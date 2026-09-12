//! Human-facing terminal output: the sorted results table and the summary banner.

use crate::Row;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use deprot_core::{Grade, Tier};
use owo_colors::OwoColorize;

/// Color used for a tier, shared by the table cells and the banner.
fn tier_color(tier: Tier) -> Color {
    match tier {
        Tier::Ok => Color::Green,
        Tier::Caution => Color::Yellow,
        Tier::Risky => Color::Red,
    }
}

fn grade_color(grade: Grade) -> Color {
    match grade {
        Grade::A => Color::Green,
        Grade::B => Color::Cyan,
        Grade::C => Color::Yellow,
        Grade::D => Color::DarkYellow,
        Grade::F => Color::Red,
    }
}

/// Render the results as a table, worst rows first. Returns the table as a string so callers
/// control where it goes.
pub fn table(rows: &[Row]) -> String {
    let mut sorted: Vec<&Row> = rows.iter().collect();
    // Worst first: by tier (risky > caution > ok), then ascending score.
    sorted.sort_by(|a, b| {
        b.score
            .tier
            .cmp(&a.score.tier)
            .then(a.score.value.cmp(&b.score.value))
    });

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("PACKAGE"),
            Cell::new("VERSION"),
            Cell::new("SCORE"),
            Cell::new("GRADE"),
            Cell::new("VERDICT"),
            Cell::new("TOP REASON"),
        ]);

    for row in sorted {
        let s = &row.score;
        let version = row
            .analyzed_version
            .clone()
            .unwrap_or_else(|| "?".to_string());
        let reason = top_reason(row);

        table.add_row(vec![
            Cell::new(&row.dependency.name),
            Cell::new(version),
            Cell::new(format!("{:>3}", s.value)),
            Cell::new(s.grade.as_str()).fg(grade_color(s.grade)),
            Cell::new(s.tier.as_str().to_uppercase()).fg(tier_color(s.tier)),
            Cell::new(reason),
        ]);
    }

    table.to_string()
}

/// The single most important line to show for a row: a forced reason if present, else the
/// lowest-scoring signal's detail, else a collection error.
fn top_reason(row: &Row) -> String {
    if let Some(err) = &row.error {
        return format!("lookup failed: {err}");
    }
    if let Some(first) = row.score.forced_reasons.first() {
        return first.clone();
    }
    row.score
        .signals
        .iter()
        .filter(|s| s.score < 0.75)
        .min_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
        .map(|s| s.detail.clone())
        .unwrap_or_else(|| "healthy".to_string())
}

/// The colored one-line summary banner printed under the table.
pub fn summary_banner(rows: &[Row]) -> String {
    let mut ok = 0;
    let mut caution = 0;
    let mut risky = 0;
    for r in rows {
        match r.score.tier {
            Tier::Ok => ok += 1,
            Tier::Caution => caution += 1,
            Tier::Risky => risky += 1,
        }
    }
    let total = rows.len();
    format!(
        "{total} dependencies analyzed — {} {}  {} {}  {} {}",
        risky.to_string().red().bold(),
        "risky".red(),
        caution.to_string().yellow().bold(),
        "caution".yellow(),
        ok.to_string().green().bold(),
        "ok".green(),
    )
}
