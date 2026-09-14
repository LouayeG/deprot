//! # deprot-netmon
//!
//! Runtime network monitoring: run a command (typically a dependency install/build — `npm install`,
//! `pip install`, `cargo build`) and watch every outbound TCP connection its process tree makes.
//! A package that phones home during installation, probes the cloud metadata service for credentials,
//! or opens a connection to a public host it has no business talking to is exactly how modern
//! supply-chain attacks (compromised `postinstall` scripts, malicious build steps) exfiltrate.
//!
//! This is a *dynamic* complement to deprot's static analysis — the thing a "dependency rot" tool
//! isn't expected to have, and something most dependency tooling doesn't do locally, keyless.
//!
//! Implemented on Linux via `/proc` (no root, no packet capture, no external crates). On other
//! platforms [`watch`] returns an error.

mod classify;
#[cfg(target_os = "linux")]
mod proc;

pub use classify::Category;

use deprot_core::Severity;
use serde::Serialize;
use std::net::IpAddr;

/// One observed connection made by the monitored process tree.
#[derive(Debug, Clone, Serialize)]
pub struct NetFinding {
    /// PID that owned the socket.
    pub pid: u32,
    /// Process command name (e.g. `node`, `python3`).
    pub process: String,
    /// Remote IP address.
    pub remote_ip: String,
    /// Remote port.
    pub remote_port: u16,
    /// `"established"` or `"connecting"`.
    pub state: &'static str,
    /// Stable rule id (e.g. `cloud-metadata-connection`).
    pub rule: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Severity of the connection category.
    pub severity: Severity,
}

/// The result of a monitored run.
#[derive(Debug, Clone, Serialize)]
pub struct WatchReport {
    /// The command that was run.
    pub command: Vec<String>,
    /// The child's exit code, if it exited normally.
    pub exit_code: Option<i32>,
    /// Every noteworthy connection (loopback is excluded), worst-first.
    pub findings: Vec<NetFinding>,
    /// How many distinct connections were observed in total (including loopback).
    pub total_observed: usize,
}

impl WatchReport {
    /// The highest severity among reported findings, if any.
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

fn state_label(state: u8) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        if state == proc::SYN_SENT {
            return "connecting";
        }
    }
    let _ = state;
    "established"
}

/// Run `command` under network monitoring, returning what it connected to. `poll_interval_ms`
/// controls how often the connection table is sampled (smaller = catches shorter-lived connections
/// at higher CPU cost); 50–100ms is a good default.
#[cfg(target_os = "linux")]
pub fn watch(command: &[String], poll_interval_ms: u64) -> std::io::Result<WatchReport> {
    use std::collections::HashSet;
    use std::process::Command;
    use std::time::Duration;

    let (program, args) = command
        .split_first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty command"))?;

    let mut child = Command::new(program).args(args).spawn()?;
    let pid = child.id();

    // Deduplicated observations: (pid, ip, port) -> (process, state, category).
    let mut seen: HashSet<(u32, IpAddr, u16)> = HashSet::new();
    let mut records: Vec<(u32, String, IpAddr, u16, u8, Category)> = Vec::new();

    let sample = |seen: &mut HashSet<(u32, IpAddr, u16)>,
                  records: &mut Vec<(u32, String, IpAddr, u16, u8, Category)>| {
        let tree = proc::process_tree(pid);
        let inode_pid = proc::socket_inodes(&tree);
        for c in proc::connections() {
            let Some(&owner) = inode_pid.get(&c.inode) else {
                continue;
            };
            if seen.insert((owner, c.ip, c.port)) {
                let cat = classify::classify(c.ip);
                records.push((owner, proc::comm(owner), c.ip, c.port, c.state, cat));
            }
        }
    };

    // Poll until the child exits, then take one final sample to catch late connections.
    let exit_code = loop {
        sample(&mut seen, &mut records);
        match child.try_wait()? {
            Some(status) => break status.code(),
            None => std::thread::sleep(Duration::from_millis(poll_interval_ms.max(1))),
        }
    };
    sample(&mut seen, &mut records);

    Ok(build_report(command.to_vec(), exit_code, records))
}

/// Non-Linux stub: runtime monitoring needs `/proc`.
#[cfg(not(target_os = "linux"))]
pub fn watch(_command: &[String], _poll_interval_ms: u64) -> std::io::Result<WatchReport> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "runtime network monitoring is currently supported on Linux only",
    ))
}

/// Turn raw observations into a sorted report (loopback excluded, worst-first).
fn build_report(
    command: Vec<String>,
    exit_code: Option<i32>,
    records: Vec<(u32, String, IpAddr, u16, u8, Category)>,
) -> WatchReport {
    let total_observed = records.len();
    let mut findings: Vec<NetFinding> = records
        .into_iter()
        .filter(|(_, _, _, _, _, cat)| *cat != Category::Loopback)
        .map(|(pid, process, ip, port, state, cat)| NetFinding {
            pid,
            process,
            remote_ip: ip.to_string(),
            remote_port: port,
            state: state_label(state),
            rule: cat.rule(),
            description: cat.describe(),
            severity: cat.severity(),
        })
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.remote_ip.cmp(&b.remote_ip))
            .then(a.remote_port.cmp(&b.remote_port))
    });
    WatchReport {
        command,
        exit_code,
        findings,
        total_observed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn report_excludes_loopback_and_sorts_worst_first() {
        let records = vec![
            (
                10,
                "node".into(),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8080,
                proc_established(),
                Category::Loopback,
            ),
            (
                11,
                "node".into(),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                443,
                proc_established(),
                Category::External,
            ),
            (
                12,
                "curl".into(),
                IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
                80,
                proc_established(),
                Category::CloudMetadata,
            ),
        ];
        let r = build_report(vec!["npm".into(), "install".into()], Some(0), records);
        assert_eq!(r.total_observed, 3);
        assert_eq!(r.findings.len(), 2, "loopback dropped");
        assert_eq!(
            r.findings[0].rule, "cloud-metadata-connection",
            "worst first"
        );
        assert_eq!(r.worst(), Some(Severity::Critical));
    }

    fn proc_established() -> u8 {
        1
    }
}
