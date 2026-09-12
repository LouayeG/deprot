//! Rendering for transitive-tree analysis (`--tree`): a per-node table that includes blast radius
//! and direct/transitive origin, a headline "highest-leverage fix", and matching JSON.

use deprot_core::{Ecosystem, Score, Tier};
use owo_colors::OwoColorize;
use serde::Serialize;

/// One resolved graph node, scored, with its blast radius.
pub struct TreeRow {
    /// Package name.
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Ecosystem.
    pub ecosystem: Ecosystem,
    /// Direct dependency of the project (vs. transitive).
    pub direct: bool,
    /// Number of other packages that transitively depend on this one.
    pub blast: usize,
    /// Health score.
    pub score: Score,
    /// Whether registry data was found (false = local/workspace/unknown package).
    pub has_data: bool,
    /// Collection error, if any.
    pub error: Option<String>,
}

impl TreeRow {
    /// Leverage = risk × reach: how much project risk a fix here would remove. Only meaningful for
    /// packages with data that aren't already OK.
    fn leverage(&self) -> u64 {
        if !self.has_data || self.score.tier == Tier::Ok {
            return 0;
        }
        (100u64.saturating_sub(self.score.value as u64)) * (self.blast as u64 + 1)
    }
}

/// The color for a tier (kept local so this module is self-contained).
fn tier_color(tier: Tier) -> comfy_table::Color {
    match tier {
        Tier::Ok => comfy_table::Color::Green,
        Tier::Caution => comfy_table::Color::Yellow,
        Tier::Risky => comfy_table::Color::Red,
    }
}

/// Render the resolved tree, worst (and highest-reach) first.
pub fn tree_table(rows: &[TreeRow]) -> String {
    use comfy_table::{Cell, ContentArrangement, Table};

    let mut order: Vec<&TreeRow> = rows.iter().collect();
    order.sort_by(|a, b| {
        b.score
            .tier
            .cmp(&a.score.tier)
            .then(b.blast.cmp(&a.blast))
            .then(a.score.value.cmp(&b.score.value))
    });

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("PACKAGE"),
            Cell::new("VERSION"),
            Cell::new("ORIGIN"),
            Cell::new("BLAST"),
            Cell::new("SCORE"),
            Cell::new("GRADE"),
            Cell::new("VERDICT"),
        ]);

    for r in order {
        if !r.has_data {
            table.add_row(vec![
                Cell::new(&r.name),
                Cell::new(&r.version),
                Cell::new(if r.direct { "direct" } else { "transitive" }),
                Cell::new(r.blast.to_string()),
                Cell::new("—"),
                Cell::new("—"),
                Cell::new("local/unknown"),
            ]);
            continue;
        }
        table.add_row(vec![
            Cell::new(&r.name),
            Cell::new(&r.version),
            Cell::new(if r.direct { "direct" } else { "transitive" }),
            Cell::new(r.blast.to_string()),
            Cell::new(format!("{:>3}", r.score.value)),
            Cell::new(r.score.grade.as_str()),
            Cell::new(r.score.tier.as_str().to_uppercase()).fg(tier_color(r.score.tier)),
        ]);
    }
    table.to_string()
}

/// The colored summary + highest-leverage recommendation printed under the tree table.
pub fn tree_summary(rows: &[TreeRow]) -> String {
    let (mut ok, mut caution, mut risky) = (0, 0, 0);
    for r in rows {
        if !r.has_data {
            continue;
        }
        match r.score.tier {
            Tier::Ok => ok += 1,
            Tier::Caution => caution += 1,
            Tier::Risky => risky += 1,
        }
    }
    let direct = rows.iter().filter(|r| r.direct).count();
    let mut out = format!(
        "{} packages in the resolved tree ({} direct) — {} {}  {} {}  {} {}",
        rows.len(),
        direct,
        risky.to_string().red().bold(),
        "risky".red(),
        caution.to_string().yellow().bold(),
        "caution".yellow(),
        ok.to_string().green().bold(),
        "ok".green(),
    );

    if let Some(top) = rows
        .iter()
        .filter(|r| r.leverage() > 0)
        .max_by_key(|r| r.leverage())
    {
        out.push_str(&format!(
            "\n{} upgrade or replace {} — grade {}, {} dependent(s): the single biggest risk reduction.",
            "★ highest-leverage fix:".bold(),
            top.name.bold(),
            top.score.grade.as_str(),
            top.blast,
        ));
    }
    out
}

#[derive(Serialize)]
struct TreeRowOut {
    name: String,
    version: String,
    ecosystem: String,
    origin: &'static str,
    blast_radius: usize,
    score: Option<u8>,
    grade: Option<String>,
    tier: Option<String>,
    leverage: u64,
    error: Option<String>,
}

#[derive(Serialize)]
struct TreeReport {
    tool: &'static str,
    version: &'static str,
    total: usize,
    direct: usize,
    dependencies: Vec<TreeRowOut>,
}

/// Serialize the resolved tree to the stable JSON report.
pub fn tree_to_json(rows: &[TreeRow]) -> String {
    let out = TreeReport {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        total: rows.len(),
        direct: rows.iter().filter(|r| r.direct).count(),
        dependencies: rows
            .iter()
            .map(|r| TreeRowOut {
                name: r.name.clone(),
                version: r.version.clone(),
                ecosystem: r.ecosystem.label().to_string(),
                origin: if r.direct { "direct" } else { "transitive" },
                blast_radius: r.blast,
                score: r.has_data.then_some(r.score.value),
                grade: r.has_data.then(|| r.score.grade.as_str().to_string()),
                tier: r.has_data.then(|| r.score.tier.as_str().to_string()),
                leverage: r.leverage(),
                error: r.error.clone(),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
}
