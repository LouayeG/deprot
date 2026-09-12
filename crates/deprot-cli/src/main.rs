//! `deprot` — grade your dependencies for rot & supply-chain risk.
//!
//! This binary is the thin wiring layer: parse a manifest ([`deprot_manifest`]), collect facts
//! from public data sources ([`deprot_collect`]), score them with the pure engine
//! ([`deprot_core`]), and render the result ([`deprot_report`]). All the interesting logic lives
//! in those crates; `main` just orchestrates and owns the CLI surface + exit codes.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::Parser;
use deprot_collect::{Collector, CollectorConfig};
use deprot_core::Tier;
use deprot_report::{explain, summary_banner, table, to_json, Row};
use owo_colors::OwoColorize;
use std::path::PathBuf;

/// Default cache lifetime: a day is plenty fresh for maintenance/advisory data.
const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Parser)]
#[command(
    name = "deprot",
    version,
    about = "Grade your dependencies for rot & supply-chain risk — local, no keys, no cloud",
    long_about = None,
)]
struct Cli {
    /// Project directory or manifest file to analyze (defaults to the current directory).
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Emit machine-readable JSON instead of the table.
    #[arg(long)]
    json: bool,

    /// Show a full signal breakdown. Optionally filter to package names containing this string.
    #[arg(long, value_name = "PACKAGE", num_args = 0..=1, default_missing_value = "")]
    explain: Option<String>,

    /// Exit non-zero if any dependency is at or worse than this tier (ok | caution | risky).
    #[arg(long, value_name = "TIER")]
    fail_on: Option<String>,

    /// Only analyze direct (production) dependencies, skipping dev/peer deps.
    #[arg(long)]
    prod_only: bool,

    /// Ignore the on-disk cache for reads and writes.
    #[arg(long)]
    no_cache: bool,

    /// Refetch everything, ignoring cached facts (the cache is still refreshed).
    #[arg(long)]
    refresh: bool,

    /// Maximum number of concurrent lookups.
    #[arg(long, default_value_t = 12)]
    concurrency: usize,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {e:#}", "error:".red().bold());
        std::process::exit(2);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Validate --fail-on early so a typo fails before we hit the network.
    let fail_on = match &cli.fail_on {
        Some(t) => Some(Tier::parse(t).ok_or_else(|| {
            anyhow!("invalid --fail-on value '{t}' (expected: ok, caution, or risky)")
        })?),
        None => None,
    };

    // 1. Parse the manifest.
    let detected = deprot_manifest::detect(&cli.path)
        .with_context(|| format!("resolving target {}", cli.path.display()))?;
    let mut deps = detected.dependencies;
    if cli.prod_only {
        deps.retain(|d| d.direct);
    }

    if deps.is_empty() {
        eprintln!("no dependencies found in {}", detected.path.display());
        return Ok(());
    }

    eprintln!(
        "{} {} {} dependencies from {} ...",
        "deprot".bold(),
        "analyzing".dimmed(),
        deps.len(),
        detected.path.display(),
    );

    // 2. Collect facts from public sources (concurrent, cached).
    let config = CollectorConfig {
        concurrency: cli.concurrency.max(1),
        cache_ttl_secs: if cli.refresh {
            0
        } else {
            DEFAULT_CACHE_TTL_SECS
        },
        cache_enabled: !cli.no_cache,
    };
    let collector = Collector::new(config)?;
    let collected = collector.collect_all(&deps).await;

    // 3. Score (pure) and build render rows.
    let now = Utc::now();
    let rows: Vec<Row> = collected
        .into_iter()
        .map(|c| Row {
            analyzed_version: c.facts.analyzed_version.clone(),
            score: deprot_core::score(&c.facts, now),
            dependency: c.dependency,
            error: c.error,
        })
        .collect();

    // 4. Render.
    if cli.json {
        println!("{}", to_json(&rows));
    } else if let Some(filter) = &cli.explain {
        let mut shown = 0;
        for row in &rows {
            if filter.is_empty() || row.dependency.name.contains(filter.as_str()) {
                println!("{}", explain(row));
                shown += 1;
            }
        }
        if shown == 0 {
            eprintln!("no analyzed dependency matched '{filter}'");
        }
    } else {
        println!("{}", table(&rows));
        println!();
        println!("{}", summary_banner(&rows));
    }

    // 5. CI gate.
    if let Some(threshold) = fail_on {
        let worst = rows.iter().map(|r| r.score.tier).max().unwrap_or(Tier::Ok);
        if worst >= threshold {
            std::process::exit(1);
        }
    }

    Ok(())
}
