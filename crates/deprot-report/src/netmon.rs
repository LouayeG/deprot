//! Rendering for the runtime network monitor (`--watch`): a worst-first connection table, a colored
//! summary, and stable JSON.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use deprot_core::Severity;
use deprot_netmon::WatchReport;
use owo_colors::OwoColorize;

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

/// Render observed connections as a worst-first table.
pub fn netmon_table(report: &WatchReport) -> String {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("SEVERITY"),
            Cell::new("PROCESS"),
            Cell::new("REMOTE"),
            Cell::new("STATE"),
            Cell::new("CATEGORY"),
        ]);
    for f in &report.findings {
        table.add_row(vec![
            Cell::new(sev_label(f.severity)).fg(sev_color(f.severity)),
            Cell::new(format!("{} ({})", f.process, f.pid)),
            Cell::new(format!("{}:{}", f.remote_ip, f.remote_port)),
            Cell::new(f.state),
            Cell::new(f.rule),
        ]);
    }
    table.to_string()
}

/// The colored one-line summary under the table.
pub fn netmon_summary(report: &WatchReport) -> String {
    if report.findings.is_empty() {
        return format!(
            "{} no external or metadata connections during `{}` 🎉",
            "✓".green().bold(),
            report.command.join(" ")
        );
    }
    let (mut crit, mut med, mut low) = (0, 0, 0);
    for f in &report.findings {
        match f.severity {
            Severity::Critical | Severity::High => crit += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
        }
    }
    format!(
        "{} connection(s) flagged during `{}` — {} {}  {} {}  {} {}",
        report.findings.len(),
        report.command.join(" "),
        crit.to_string().red().bold(),
        "metadata/critical".red(),
        med.to_string().yellow().bold(),
        "external".yellow(),
        low.to_string().dimmed(),
        "private".dimmed(),
    )
}

/// Serialize the watch report to stable JSON.
pub fn netmon_json(report: &WatchReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}
