//! Linux `/proc` scanning: attribute open TCP sockets to a process tree.
//!
//! We only report connections made by the monitored command (its process and descendants), so a
//! noisy machine doesn't drown the signal. That means matching socket inodes owned by those PIDs
//! (`/proc/<pid>/fd`) against the connection table (`/proc/net/tcp[6]`).

use crate::classify::{parse_v4, parse_v6};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::IpAddr;

/// A live socket owned by the monitored tree.
pub struct Conn {
    pub inode: u64,
    pub ip: IpAddr,
    pub port: u16,
    pub state: u8,
}

/// TCP states we care about: a completed connection or a connect() in flight (which reveals intent
/// even if the peer never answers — e.g. a dead C2).
pub const ESTABLISHED: u8 = 0x01;
pub const SYN_SENT: u8 = 0x02;

/// The monitored PID plus every descendant currently alive.
pub fn process_tree(root: u32) -> HashSet<u32> {
    // child_ppid[pid] = ppid, built from a single /proc scan.
    let mut ppid_of: HashMap<u32, u32> = HashMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(ppid) = read_ppid(pid) {
                ppid_of.insert(pid, ppid);
            }
        }
    }
    // BFS down from root.
    let mut tree = HashSet::new();
    tree.insert(root);
    let mut queue = VecDeque::from([root]);
    while let Some(cur) = queue.pop_front() {
        for (&pid, &ppid) in &ppid_of {
            if ppid == cur && tree.insert(pid) {
                queue.push_back(pid);
            }
        }
    }
    tree
}

/// Parse the parent PID from `/proc/<pid>/stat` (field 4, after the possibly-parenthesized comm).
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm can contain spaces/parens; skip to the last ')' then take the fields after it.
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?; // field 3
    fields.next()?.parse().ok() // field 4 = ppid
}

/// The process command name (`/proc/<pid>/comm`), best-effort.
pub fn comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Map socket inode -> owning PID for every PID in `pids`.
pub fn socket_inodes(pids: &HashSet<u32>) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    for &pid in pids {
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if let Some(inode) = target
                    .to_str()
                    .and_then(|s| s.strip_prefix("socket:["))
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

/// All connections of interest from `/proc/net/tcp` and `/proc/net/tcp6`.
pub fn connections() -> Vec<Conn> {
    let mut out = Vec::new();
    collect("/proc/net/tcp", false, &mut out);
    collect("/proc/net/tcp6", true, &mut out);
    out
}

fn collect(path: &str, v6: bool, out: &mut Vec<Conn>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // 1=local 2=rem_address 3=state ... 9=inode
        if f.len() < 10 {
            continue;
        }
        let state = u8::from_str_radix(f[3], 16).unwrap_or(0);
        if state != ESTABLISHED && state != SYN_SENT {
            continue;
        }
        let parsed = if v6 { parse_v6(f[2]) } else { parse_v4(f[2]) };
        let Some((ip, port)) = parsed else {
            continue;
        };
        if port == 0 || ip.is_unspecified() {
            continue;
        }
        let Ok(inode) = f[9].parse::<u64>() else {
            continue;
        };
        out.push(Conn {
            inode,
            ip,
            port,
            state,
        });
    }
}
