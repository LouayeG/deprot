//! The `--explain` view: a full, human-readable breakdown of why one dependency got its score.

use crate::Row;
use deprot_core::Tier;
use owo_colors::OwoColorize;

/// Render a detailed explanation for a single scored dependency.
pub fn explain(row: &Row) -> String {
    let s = &row.score;
    let mut out = String::new();

    let header = format!(
        "{} {}  —  score {}/100  grade {}  [{}]",
        row.dependency.name.bold(),
        row.analyzed_version.as_deref().unwrap_or("?").dimmed(),
        s.value,
        s.grade.as_str(),
        s.tier.as_str().to_uppercase(),
    );
    out.push_str(&match s.tier {
        Tier::Ok => header.green().to_string(),
        Tier::Caution => header.yellow().to_string(),
        Tier::Risky => header.red().to_string(),
    });
    out.push('\n');

    if let Some(err) = &row.error {
        out.push_str(&format!(
            "  {} {}\n",
            "!".red(),
            format!("lookup failed: {err}").red()
        ));
        return out;
    }

    if !s.forced_reasons.is_empty() {
        out.push_str(&format!("\n  {}\n", "Forced RISKY because:".red().bold()));
        for r in &s.forced_reasons {
            out.push_str(&format!("    {} {}\n", "•".red(), r));
        }
    }

    out.push_str(&format!("\n  {}\n", "Signals:".bold()));
    if s.signals.is_empty() {
        out.push_str("    (no data collected)\n");
    }
    for sig in &s.signals {
        // A compact 10-cell bar visualising the subscore.
        let filled = (sig.score * 10.0).round() as usize;
        let bar: String = "█".repeat(filled) + &"░".repeat(10usize.saturating_sub(filled));
        let colored_bar = if sig.score >= 0.75 {
            bar.green().to_string()
        } else if sig.score >= 0.4 {
            bar.yellow().to_string()
        } else {
            bar.red().to_string()
        };
        out.push_str(&format!(
            "    {:<16} {} {:>4.0}%  (w{})  {}\n",
            sig.name,
            colored_bar,
            sig.score * 100.0,
            sig.weight,
            sig.detail.dimmed(),
        ));
    }

    out
}
