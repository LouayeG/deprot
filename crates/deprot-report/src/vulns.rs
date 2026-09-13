//! The vuln-first view (`--vulns`): a per-advisory audit rather than a per-package grade. Every
//! known advisory affecting an analyzed package becomes one row, sorted worst-first, showing the
//! CVE id, severity, the installed version, and the version to upgrade to.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use deprot_core::{Severity, Vuln};
use owo_colors::OwoColorize;
use serde::Serialize;

/// One advisory affecting one analyzed package — the unit of the vuln-first report.
pub struct VulnFinding {
    /// Package name.
    pub package: String,
    /// The installed/analyzed version the advisory applies to.
    pub version: String,
    /// Ecosystem label.
    pub ecosystem: String,
    /// The advisory itself.
    pub vuln: Vuln,
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

fn sev_color(s: Severity) -> Color {
    match s {
        Severity::Critical => Color::Red,
        Severity::High => Color::DarkRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::DarkGrey,
    }
}

/// Worst-first ordering: severity desc, then CVSS desc, then package name.
fn sort_findings(findings: &mut [&VulnFinding]) {
    findings.sort_by(|a, b| {
        b.vuln
            .severity()
            .cmp(&a.vuln.severity())
            .then(
                b.vuln
                    .cvss
                    .unwrap_or(0.0)
                    .partial_cmp(&a.vuln.cvss.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.package.cmp(&b.package))
    });
}

/// Render the advisories as a worst-first table.
pub fn vuln_table(findings: &[VulnFinding]) -> String {
    let mut order: Vec<&VulnFinding> = findings.iter().collect();
    sort_findings(&mut order);

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("SEVERITY"),
            Cell::new("CVSS"),
            Cell::new("ADVISORY"),
            Cell::new("PACKAGE"),
            Cell::new("INSTALLED"),
            Cell::new("FIXED"),
            Cell::new("TITLE"),
        ]);

    for f in order {
        let sev = f.vuln.severity();
        let cvss = f
            .vuln
            .cvss
            .map(|c| format!("{c:.1}"))
            .unwrap_or_else(|| "—".to_string());
        let fixed = f
            .vuln
            .fixed_version
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let title = f.vuln.title.clone().unwrap_or_default();
        let title = if title.len() > 48 {
            format!("{}…", &title[..47])
        } else {
            title
        };
        table.add_row(vec![
            Cell::new(sev_label(sev)).fg(sev_color(sev)),
            Cell::new(cvss),
            Cell::new(&f.vuln.id),
            Cell::new(&f.package),
            Cell::new(&f.version),
            Cell::new(fixed),
            Cell::new(title),
        ]);
    }
    table.to_string()
}

/// The colored one-line summary under the vuln table.
pub fn vuln_summary(findings: &[VulnFinding]) -> String {
    let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
    for f in findings {
        match f.vuln.severity() {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
        }
    }
    let fixable = findings.iter().filter(|f| f.vuln.is_fixable()).count();
    let pkgs: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.package.as_str()).collect();

    if findings.is_empty() {
        return format!("{} no known advisories 🎉", "✓".green().bold());
    }
    format!(
        "{} advisories across {} package(s) — {} {}  {} {}  {} {}  {} {}   ({} fixable by upgrade)",
        findings.len(),
        pkgs.len(),
        crit.to_string().red().bold(),
        "critical".red(),
        high.to_string().red().bold(),
        "high".red(),
        med.to_string().yellow().bold(),
        "medium".yellow(),
        low.to_string().dimmed(),
        "low".dimmed(),
        fixable.to_string().green().bold(),
    )
}

#[derive(Serialize)]
struct VulnOut {
    severity: &'static str,
    cvss: Option<f64>,
    id: String,
    aliases: Vec<String>,
    package: String,
    ecosystem: String,
    installed: String,
    fixed: Option<String>,
    fixable: bool,
    title: Option<String>,
    reference: Option<String>,
}

#[derive(Serialize)]
struct VulnSummaryOut {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    fixable: usize,
    packages: usize,
}

#[derive(Serialize)]
struct VulnReport {
    tool: &'static str,
    version: &'static str,
    summary: VulnSummaryOut,
    vulnerabilities: Vec<VulnOut>,
}

/// Serialize the advisories into a stable, vuln-first JSON report.
pub fn vuln_json(findings: &[VulnFinding]) -> String {
    let mut order: Vec<&VulnFinding> = findings.iter().collect();
    sort_findings(&mut order);

    let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
    for f in findings {
        match f.vuln.severity() {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
        }
    }
    let pkgs: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.package.as_str()).collect();

    let vulnerabilities: Vec<VulnOut> = order
        .iter()
        .map(|f| VulnOut {
            severity: sev_label(f.vuln.severity()),
            cvss: f.vuln.cvss,
            id: f.vuln.id.clone(),
            aliases: f.vuln.aliases.clone(),
            package: f.package.clone(),
            ecosystem: f.ecosystem.clone(),
            installed: f.version.clone(),
            fixed: f.vuln.fixed_version.clone(),
            fixable: f.vuln.is_fixable(),
            title: f.vuln.title.clone(),
            reference: f.vuln.reference.clone(),
        })
        .collect();

    let report = VulnReport {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        summary: VulnSummaryOut {
            total: findings.len(),
            critical: crit,
            high,
            medium: med,
            low,
            fixable: findings.iter().filter(|f| f.vuln.is_fixable()).count(),
            packages: pkgs.len(),
        },
        vulnerabilities,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

/// A representative `security-severity` number (what GitHub code scanning color-codes on): the CVSS
/// score when known, else a bucket midpoint from the severity label.
fn security_severity(f: &VulnFinding) -> f64 {
    f.vuln.cvss.unwrap_or(match f.vuln.severity() {
        Severity::Critical => 9.0,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.0,
    })
}

/// Serialize the advisories into a SARIF 2.1.0 log — one result per (package, advisory), with a
/// `security-severity` property so GitHub code scanning ranks them. Vuln-first: RISKY→error etc.
pub fn vuln_sarif(findings: &[VulnFinding]) -> String {
    use serde_json::{json, Map, Value};

    let mut order: Vec<&VulnFinding> = findings.iter().collect();
    sort_findings(&mut order);

    let mut rules: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let mut results: Vec<Value> = Vec::new();

    for f in &order {
        let sev = f.vuln.severity();
        let level = match sev {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        };
        let sec = format!("{:.1}", security_severity(f));
        let title = f.vuln.title.clone().unwrap_or_else(|| f.vuln.id.clone());
        let fix = f
            .vuln
            .fixed_version
            .as_deref()
            .map(|v| format!("; fix: upgrade to {v}"))
            .unwrap_or_else(|| "; no fixed version published".to_string());

        rules.entry(f.vuln.id.clone()).or_insert_with(|| {
            let mut rule = Map::new();
            rule.insert("id".into(), json!(f.vuln.id));
            rule.insert("name".into(), json!("KnownVulnerability"));
            rule.insert("shortDescription".into(), json!({ "text": title }));
            if let Some(url) = &f.vuln.reference {
                rule.insert("helpUri".into(), json!(url));
            }
            rule.insert(
                "properties".into(),
                json!({ "security-severity": sec, "tags": ["security", "vulnerability"] }),
            );
            Value::Object(rule)
        });

        results.push(json!({
            "ruleId": f.vuln.id,
            "level": level,
            "message": { "text": format!(
                "{}@{} — {} [{} {}]{}",
                f.package, f.version, title, sev_label(sev), sec, fix
            )},
            "properties": { "security-severity": sec },
            "locations": [{
                "logicalLocations": [{ "name": f.package, "kind": "package" }]
            }]
        }));
    }

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "deprot",
                "informationUri": "https://github.com/LouayeG/deprot",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}
