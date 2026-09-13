//! Rendering for the GitHub Actions workflow scanner (`--workflows`): a worst-first table, a
//! severity-bucketed summary, stable JSON, and SARIF with physical file locations.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use deprot_actions::ActionFinding;
use deprot_core::Severity;
use owo_colors::OwoColorize;
use serde::Serialize;

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

fn sort_findings(f: &mut [&ActionFinding]) {
    f.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.path.cmp(&b.path))
            .then(a.line.cmp(&b.line))
    });
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let head: String = s.chars().take(max - 1).collect();
        format!("{head}…")
    } else {
        s.to_string()
    }
}

/// Render workflow findings as a worst-first table.
pub fn workflow_table(findings: &[ActionFinding]) -> String {
    let mut order: Vec<&ActionFinding> = findings.iter().collect();
    sort_findings(&mut order);

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("SEVERITY"),
            Cell::new("RULE"),
            Cell::new("LOCATION"),
            Cell::new("DETAIL"),
        ]);
    for f in order {
        table.add_row(vec![
            Cell::new(sev_label(f.severity)).fg(sev_color(f.severity)),
            Cell::new(f.rule),
            Cell::new(format!("{}:{}", f.path, f.line)),
            Cell::new(truncate(&f.detail, 52)),
        ]);
    }
    table.to_string()
}

/// The colored one-line summary under the table.
pub fn workflow_summary(findings: &[ActionFinding]) -> String {
    if findings.is_empty() {
        return format!(
            "{} no workflow-security issues found 🎉",
            "✓".green().bold()
        );
    }
    let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
        }
    }
    let files: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.path.as_str()).collect();
    format!(
        "{} workflow issue(s) across {} file(s) — {} {}  {} {}  {} {}  {} {}",
        findings.len(),
        files.len(),
        crit.to_string().red().bold(),
        "critical".red(),
        high.to_string().red().bold(),
        "high".red(),
        med.to_string().yellow().bold(),
        "medium".yellow(),
        low.to_string().dimmed(),
        "low".dimmed(),
    )
}

#[derive(Serialize)]
struct SummaryOut {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    files: usize,
}

#[derive(Serialize)]
struct Report<'a> {
    tool: &'static str,
    version: &'static str,
    summary: SummaryOut,
    findings: &'a [ActionFinding],
}

/// Serialize workflow findings to a stable JSON report.
pub fn workflow_json(findings: &[ActionFinding]) -> String {
    let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
        }
    }
    let files: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.path.as_str()).collect();
    let report = Report {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        summary: SummaryOut {
            total: findings.len(),
            critical: crit,
            high,
            medium: med,
            low,
            files: files.len(),
        },
        findings,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

/// Serialize workflow findings to SARIF 2.1.0 with physical file locations for GitHub code scanning.
pub fn workflow_sarif(findings: &[ActionFinding]) -> String {
    use serde_json::{json, Map, Value};

    let mut rules: std::collections::BTreeMap<&str, Value> = std::collections::BTreeMap::new();
    let mut results: Vec<Value> = Vec::new();

    for f in findings {
        let level = match f.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        };
        rules.entry(f.rule).or_insert_with(|| {
            let mut rule = Map::new();
            rule.insert("id".into(), json!(f.rule));
            rule.insert("name".into(), json!("WorkflowSecurity"));
            rule.insert("shortDescription".into(), json!({ "text": f.description }));
            rule.insert("properties".into(), json!({ "tags": ["security", "ci"] }));
            Value::Object(rule)
        });
        results.push(json!({
            "ruleId": f.rule,
            "level": level,
            "message": { "text": format!("{}: {}", f.description, f.detail) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": f.path },
                    "region": { "startLine": f.line.max(1) }
                }
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
