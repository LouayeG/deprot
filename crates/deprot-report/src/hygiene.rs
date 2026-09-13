//! Rendering for the repository hygiene audit (`--hygiene`): a per-check pass/fail table, a scored
//! summary with a letter grade, and stable JSON.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use deprot_core::Severity;
use deprot_hygiene::HygieneReport;
use owo_colors::OwoColorize;
use serde::Serialize;

/// Letter grade for a 0–100 posture score (mirrors the dependency-grade thresholds).
fn grade(score: u8) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
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

/// Render every check as a pass/fail row (failures colored by severity).
pub fn hygiene_table(report: &HygieneReport) -> String {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![Cell::new(""), Cell::new("CHECK"), Cell::new("DETAIL")]);
    // Failures first (worst severity first), then passing checks in declared order.
    let mut rows: Vec<&_> = report.checks.iter().collect();
    rows.sort_by_key(|c| c.passed); // false (0) before true (1)
    for c in rows {
        // For failures show the remediation; for passes the title is self-explanatory.
        let (status, detail) = if c.passed {
            (Cell::new("✓ pass").fg(Color::Green), String::new())
        } else {
            (
                Cell::new("✗ fail").fg(sev_color(c.severity)),
                c.detail.clone(),
            )
        };
        table.add_row(vec![status, Cell::new(c.title), Cell::new(detail)]);
    }
    table.to_string()
}

/// The scored one-line summary under the table.
pub fn hygiene_summary(report: &HygieneReport) -> String {
    let passed = report.checks.iter().filter(|c| c.passed).count();
    let total = report.checks.len();
    let g = grade(report.score);
    let colored = match g {
        "A" | "B" => format!("{}/100 (grade {g})", report.score)
            .green()
            .to_string(),
        "C" | "D" => format!("{}/100 (grade {g})", report.score)
            .yellow()
            .to_string(),
        _ => format!("{}/100 (grade {g})", report.score)
            .red()
            .to_string(),
    };
    format!(
        "{} posture {} — {passed}/{total} checks passed",
        "hygiene:".bold(),
        colored,
    )
}

#[derive(Serialize)]
struct HygieneOut<'a> {
    tool: &'static str,
    version: &'static str,
    score: u8,
    grade: &'static str,
    passed: usize,
    total: usize,
    checks: &'a [deprot_hygiene::HygieneCheck],
}

/// Serialize the hygiene report to stable JSON.
pub fn hygiene_json(report: &HygieneReport) -> String {
    let out = HygieneOut {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        score: report.score,
        grade: grade(report.score),
        passed: report.checks.iter().filter(|c| c.passed).count(),
        total: report.checks.len(),
        checks: &report.checks,
    };
    serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
}
