//! Rendering for the secret scanner (`--secrets`): a worst-first table, a severity-bucketed
//! summary, stable JSON, and SARIF with real file locations for GitHub code scanning.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use deprot_core::Severity;
use deprot_secrets::SecretFinding;
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

fn sort_findings(f: &mut [&SecretFinding]) {
    f.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.path.cmp(&b.path))
            .then(a.line.cmp(&b.line))
    });
}

/// Render found secrets as a worst-first table.
pub fn secret_table(findings: &[SecretFinding]) -> String {
    let mut order: Vec<&SecretFinding> = findings.iter().collect();
    sort_findings(&mut order);

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("SEVERITY"),
            Cell::new("RULE"),
            Cell::new("LOCATION"),
            Cell::new("SECRET"),
        ]);
    for f in order {
        table.add_row(vec![
            Cell::new(sev_label(f.severity)).fg(sev_color(f.severity)),
            Cell::new(f.rule),
            Cell::new(format!("{}:{}", f.path, f.line)),
            Cell::new(&f.preview),
        ]);
    }
    table.to_string()
}

/// The colored one-line summary under the table.
pub fn secret_summary(findings: &[SecretFinding]) -> String {
    if findings.is_empty() {
        return format!("{} no hardcoded secrets found 🎉", "✓".green().bold());
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
        "{} potential secret(s) across {} file(s) — {} {}  {} {}  {} {}  {} {}",
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
struct SecretSummaryOut {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    files: usize,
}

#[derive(Serialize)]
struct SecretReport<'a> {
    tool: &'static str,
    version: &'static str,
    summary: SecretSummaryOut,
    secrets: &'a [SecretFinding],
}

/// Serialize found secrets to a stable JSON report (previews are already redacted).
pub fn secret_json(findings: &[SecretFinding]) -> String {
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
    let report = SecretReport {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        summary: SecretSummaryOut {
            total: findings.len(),
            critical: crit,
            high,
            medium: med,
            low,
            files: files.len(),
        },
        secrets: findings,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

/// Serialize found secrets to SARIF 2.1.0 with physical file locations, so each appears as an
/// alert on the exact line in GitHub code scanning.
pub fn secret_sarif(findings: &[SecretFinding]) -> String {
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
            rule.insert("name".into(), json!("HardcodedSecret"));
            rule.insert("shortDescription".into(), json!({ "text": f.description }));
            rule.insert(
                "properties".into(),
                json!({ "tags": ["security", "secret"] }),
            );
            Value::Object(rule)
        });
        results.push(json!({
            "ruleId": f.rule,
            "level": level,
            "message": { "text": format!("{} ({})", f.description, f.preview) },
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
