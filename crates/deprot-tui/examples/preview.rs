//! Renders the TUI once to plain text with fixture data — a quick way to eyeball the layout
//! without a real terminal. Run: `cargo run -p deprot-tui --example preview`.

use deprot_core::{score, Dependency, Ecosystem, Facts};
use deprot_report::Row;

fn row(name: &str, version: &str, days_old: i64, releases: u32, deprecated: bool) -> Row {
    let now = chrono::Utc::now();
    let facts = Facts {
        latest_published: Some(now - chrono::Duration::days(days_old)),
        releases_last_year: Some(releases),
        licenses: vec!["MIT".into()],
        scorecard_overall: Some(6.0),
        deprecated,
        deprecated_reason: deprecated.then(|| "no longer maintained".to_string()),
        ..Default::default()
    };
    Row {
        analyzed_version: Some(version.into()),
        score: score(&facts, now),
        dependency: Dependency {
            name: name.into(),
            requested: None,
            ecosystem: Ecosystem::Npm,
            direct: true,
        },
        error: None,
        source: None,
    }
}

fn main() {
    let rows = vec![
        row("request", "2.88.2", 2400, 0, true),
        row("left-pad", "1.3.0", 3000, 0, true),
        row("chalk", "6.0.0", 40, 1, false),
        row("lodash", "4.18.1", 60, 3, false),
        row("express", "5.2.1", 20, 9, false),
    ];
    print!("{}", deprot_tui::render_to_text(rows, 92, 22));
}
