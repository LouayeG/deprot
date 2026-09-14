//! Rendering for the reachability audit (`--reach`): a table of used / unused / dev dependencies
//! (unused first — the actionable ones), a summary, and stable JSON.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use deprot_reach::{DepUsage, Reach};
use owo_colors::OwoColorize;
use serde::Serialize;

fn reach_rank(r: Reach) -> u8 {
    match r {
        Reach::Unused => 0,
        Reach::Used => 1,
        Reach::Dev => 2,
        Reach::Unscanned => 3,
    }
}

fn reach_cell(r: Reach) -> Cell {
    match r {
        Reach::Used => Cell::new("used").fg(Color::Green),
        Reach::Unused => Cell::new("UNUSED").fg(Color::Yellow),
        Reach::Dev => Cell::new("dev").fg(Color::DarkGrey),
        Reach::Unscanned => Cell::new("unscanned").fg(Color::DarkGrey),
    }
}

/// Render the reachability of every dependency, unused-first.
pub fn reach_table(usages: &[DepUsage]) -> String {
    let mut order: Vec<&DepUsage> = usages.iter().collect();
    order.sort_by(|a, b| {
        reach_rank(a.reach)
            .cmp(&reach_rank(b.reach))
            .then(a.name.cmp(&b.name))
    });

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("REACH"),
            Cell::new("PACKAGE"),
            Cell::new("ORIGIN"),
            Cell::new("IMPORTED IN"),
        ]);
    for u in order {
        table.add_row(vec![
            reach_cell(u.reach),
            Cell::new(&u.name),
            Cell::new(if u.direct { "runtime" } else { "dev" }),
            Cell::new(u.evidence.clone().unwrap_or_else(|| "—".to_string())),
        ]);
    }
    table.to_string()
}

/// The colored one-line summary.
pub fn reach_summary(usages: &[DepUsage]) -> String {
    let used = usages.iter().filter(|u| u.reach == Reach::Used).count();
    let unused = usages.iter().filter(|u| u.reach == Reach::Unused).count();
    let dev = usages.iter().filter(|u| u.reach == Reach::Dev).count();
    let unscanned = usages
        .iter()
        .filter(|u| u.reach == Reach::Unscanned)
        .count();
    let mut s = format!(
        "{} {} {}  {} {}  {} {}",
        "reachability:".bold(),
        used.to_string().green().bold(),
        "used".green(),
        unused.to_string().yellow().bold(),
        "unused (removal candidates)".yellow(),
        dev.to_string().dimmed(),
        "dev".dimmed(),
    );
    if unscanned > 0 {
        // Be explicit that some ecosystems have no import scanner yet, rather than implying "used".
        s.push_str(&format!(
            "  {} {}",
            unscanned.to_string().dimmed(),
            "unscanned (no import scanner for this ecosystem yet)".dimmed(),
        ));
    }
    s
}

#[derive(Serialize)]
struct SummaryOut {
    total: usize,
    used: usize,
    unused: usize,
    dev: usize,
    unscanned: usize,
}

#[derive(Serialize)]
struct Report<'a> {
    tool: &'static str,
    version: &'static str,
    summary: SummaryOut,
    dependencies: &'a [DepUsage],
}

/// Serialize the reachability report to stable JSON.
pub fn reach_json(usages: &[DepUsage]) -> String {
    let report = Report {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        summary: SummaryOut {
            total: usages.len(),
            used: usages.iter().filter(|u| u.reach == Reach::Used).count(),
            unused: usages.iter().filter(|u| u.reach == Reach::Unused).count(),
            dev: usages.iter().filter(|u| u.reach == Reach::Dev).count(),
            unscanned: usages
                .iter()
                .filter(|u| u.reach == Reach::Unscanned)
                .count(),
        },
        dependencies: usages,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
