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
use deprot_report::{
    explain, summary_banner, table, to_json, tree_summary, tree_table, tree_to_json, Row, TreeRow,
};
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

    /// Analyze the full resolved dependency tree from a lockfile (transitive deps + blast radius),
    /// not just the direct dependencies in the manifest.
    #[arg(long)]
    tree: bool,

    /// Browse results in an interactive terminal UI (arrow keys to navigate, live details).
    #[arg(long)]
    tui: bool,

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

    /// Path to a policy file (defaults to `.deprot.toml` in the project directory if present).
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Ignore any `.deprot.toml` policy file.
    #[arg(long)]
    no_policy: bool,

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

    // Transitive-tree mode analyzes the resolved lockfile instead of the manifest.
    if cli.tree {
        return run_tree(&cli, fail_on).await;
    }

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

    // 3. Score (pure) and build render rows. Facts are kept alongside for policy evaluation.
    let now = Utc::now();
    let facts: Vec<deprot_core::Facts> = collected.iter().map(|c| c.facts.clone()).collect();
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
    if cli.tui {
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            return Err(anyhow!(
                "--tui requires an interactive terminal; omit it for table output or use --json"
            ));
        }
        deprot_tui::run(rows)?;
        // The interactive UI is for exploration; skip the CI gate when it's used.
        return Ok(());
    } else if cli.json {
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

    // 5. Policy evaluation (`.deprot.toml`), if present.
    let policy_dir = detected
        .path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut policy_failed = false;
    if !cli.no_policy {
        if let Some(policy) = deprot_policy::Policy::load(policy_dir, cli.policy.as_deref())? {
            let subjects: Vec<deprot_policy::Subject> = rows
                .iter()
                .zip(&facts)
                .map(|(row, f)| deprot_policy::Subject {
                    name: &row.dependency.name,
                    facts: f,
                    score: &row.score,
                })
                .collect();
            let violations = policy.evaluate(&subjects, Utc::now().date_naive());
            print_violations(&violations);
            policy_failed = !violations.is_empty();
        }
    }

    // 6. CI gate: fail on the tier threshold or any policy violation.
    let tier_failed = fail_on
        .map(|threshold| rows.iter().map(|r| r.score.tier).max().unwrap_or(Tier::Ok) >= threshold)
        .unwrap_or(false);
    if tier_failed || policy_failed {
        std::process::exit(1);
    }

    Ok(())
}

/// Print policy violations to stderr (so JSON stdout stays clean), grouped and colored.
fn print_violations(violations: &[deprot_policy::Violation]) {
    if violations.is_empty() {
        return;
    }
    eprintln!();
    eprintln!(
        "{} {} policy violation(s):",
        "✗".red().bold(),
        violations.len()
    );
    for v in violations {
        eprintln!(
            "  {} {} — {} [{}]",
            "•".red(),
            v.package.bold(),
            v.detail,
            v.rule.dimmed()
        );
    }
}

/// Transitive-tree analysis: resolve the lockfile, score every node at its exact version, compute
/// blast radius, and report the tree plus the highest-leverage fix.
async fn run_tree(cli: &Cli, fail_on: Option<Tier>) -> Result<()> {
    let resolved = deprot_manifest::detect_lockfile(&cli.path)
        .with_context(|| format!("resolving lockfile at {}", cli.path.display()))?;
    if resolved.graph.is_empty() {
        eprintln!("no dependencies in {}", resolved.path.display());
        return Ok(());
    }

    eprintln!(
        "{} {} {} packages (resolved tree) from {} ...",
        "deprot".bold(),
        "analyzing".dimmed(),
        resolved.graph.len(),
        resolved.path.display(),
    );

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
    let gfacts = collector.collect_graph(&resolved.graph).await;
    let radii = resolved.graph.blast_radii();
    let now = Utc::now();

    let rows: Vec<TreeRow> = gfacts
        .into_iter()
        .map(|gf| {
            let node = &resolved.graph.nodes()[gf.index];
            TreeRow {
                name: node.name.clone(),
                version: node.version.clone(),
                ecosystem: node.ecosystem,
                direct: node.direct,
                blast: radii[gf.index],
                has_data: gf.facts.analyzed_version.is_some(),
                score: deprot_core::score(&gf.facts, now),
                error: gf.error,
            }
        })
        .collect();

    if cli.json {
        println!("{}", tree_to_json(&rows));
    } else {
        println!("{}", tree_table(&rows));
        println!();
        println!("{}", tree_summary(&rows));
    }

    if let Some(threshold) = fail_on {
        let worst = rows
            .iter()
            .filter(|r| r.has_data)
            .map(|r| r.score.tier)
            .max()
            .unwrap_or(Tier::Ok);
        if worst >= threshold {
            std::process::exit(1);
        }
    }
    Ok(())
}
