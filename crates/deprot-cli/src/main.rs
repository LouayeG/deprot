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
    explain, summary_banner, table, to_json, to_json_packages, tree_summary, tree_table,
    tree_to_json, vuln_json, vuln_summary, vuln_table, Row, TreeRow, VulnFinding,
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

    /// Recursively discover and analyze every manifest under the directory (monorepo mode):
    /// package.json, Cargo.toml and go.mod across subprojects, each reported in its own section.
    #[arg(long)]
    recursive: bool,

    /// Vulnerability audit (vuln-first): list every known advisory affecting your packages — CVE
    /// id, severity, and the fixed version to upgrade to — from OSV merged with GitHub advisories.
    /// Scans the resolved lockfile tree when present, else the manifest. Exits non-zero if any
    /// advisory is found.
    #[arg(long)]
    vulns: bool,

    /// Analyze the packages actually installed on disk — the project's node_modules and the active
    /// Python environment — at their exact installed versions, instead of the manifest. Catches
    /// drift from the lockfile and packages installed by hand.
    #[arg(long)]
    installed: bool,

    /// Also scan machine-wide installs: the global npm root (`npm root -g`) and pipx. Combine with
    /// --installed, or use alone to audit only global tooling.
    #[arg(long)]
    global: bool,

    /// Compare the target against a baseline lockfile (PR mode): show added/removed/changed
    /// dependencies and the net change in project risk.
    #[arg(long, value_name = "BASELINE")]
    diff: Option<PathBuf>,

    /// After a `--tree` analysis, compute a remediation plan: for each risky/caution package,
    /// check whether upgrading to the latest version would improve its grade, and print the fix.
    #[arg(long)]
    fix: bool,

    /// Browse results in an interactive terminal UI (arrow keys to navigate, live details).
    #[arg(long)]
    tui: bool,

    /// Emit machine-readable JSON instead of the table.
    #[arg(long)]
    json: bool,

    /// Emit a SARIF 2.1.0 report (for GitHub code scanning and security tooling).
    #[arg(long)]
    sarif: bool,

    /// Emit a CycloneDX 1.5 SBOM with deprot's risk assessment attached to each component.
    #[arg(long)]
    sbom: bool,

    /// Show a package's release history over time (a "time machine" of its cadence and staleness).
    #[arg(long, value_name = "PACKAGE")]
    history: Option<String>,

    /// Show a full signal breakdown. Optionally filter to package names containing this string.
    #[arg(long, value_name = "PACKAGE", num_args = 0..=1, default_missing_value = "")]
    explain: Option<String>,

    /// Exit non-zero if any dependency is at or worse than this tier (ok | caution | risky).
    #[arg(long, value_name = "TIER")]
    fail_on: Option<String>,

    /// Deep supply-chain analysis: also fetch maintainer identities and install scripts, then
    /// report maintainer capture-risk (concentration) and code-on-install packages. Adds one
    /// registry request per dependency.
    #[arg(long)]
    deep: bool,

    /// Only analyze direct (production) dependencies, skipping dev/peer deps.
    #[arg(long)]
    prod_only: bool,

    /// Ignore the on-disk cache for reads and writes.
    #[arg(long)]
    no_cache: bool,

    /// Refetch everything, ignoring cached facts (the cache is still refreshed).
    #[arg(long)]
    refresh: bool,

    /// Air-gapped mode: never touch the network; use only previously-cached data. Warm the cache
    /// with an online run first.
    #[arg(long)]
    offline: bool,

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

    // History mode shows one package's release timeline.
    if let Some(pkg) = cli.history.clone() {
        return run_history(&cli, &pkg).await;
    }

    // Diff mode compares two lockfiles.
    if let Some(baseline) = cli.diff.clone() {
        return run_diff(&cli, &baseline, fail_on).await;
    }

    // Vuln-first audit: list every advisory across the tree/manifest.
    if cli.vulns {
        return run_vulns(&cli).await;
    }

    // Installed mode analyzes the packages actually present on disk.
    if cli.installed || cli.global {
        return run_installed(&cli, fail_on).await;
    }

    // Transitive-tree mode analyzes the resolved lockfile instead of the manifest.
    if cli.tree {
        return run_tree(&cli, fail_on).await;
    }

    // Recursive/monorepo mode analyzes every manifest found under the directory.
    if cli.recursive {
        return run_recursive(&cli, fail_on).await;
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
        hint_multi_package(&cli.path, &detected.path);
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
        enrich: cli.deep,
        offline: cli.offline,
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
            source: None,
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
    } else if cli.sarif {
        println!("{}", deprot_report::to_sarif(&rows));
    } else if cli.sbom {
        println!("{}", deprot_report::to_cyclonedx(&rows));
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

    // 4b. Typosquat / dependency-confusion warnings (pure, offline).
    if !cli.json && !cli.sarif && !cli.sbom {
        let names: Vec<&str> = rows.iter().map(|r| r.dependency.name.as_str()).collect();
        let eco = detected.ecosystem;
        let suspects = deprot_core::typosquat_scan(names, eco);
        if !suspects.is_empty() {
            eprintln!();
            eprintln!("{} possible typosquat(s):", "⚠".yellow().bold());
            for s in &suspects {
                eprintln!(
                    "  {} {} looks like {} ({} edit(s) away) — verify it's the package you intend",
                    "•".yellow(),
                    s.name.bold(),
                    s.nearest.bold(),
                    s.distance
                );
            }
        }
    }

    // 4c. Deep supply-chain analysis (maintainer capture-risk + install scripts).
    if cli.deep && !cli.json && !cli.sarif && !cli.sbom {
        print_deep(&rows, &facts);
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

/// When a single-manifest analysis comes up empty but the directory holds manifests in
/// subdirectories, point the user at `--recursive` instead of leaving them at a dead end.
fn hint_multi_package(target: &std::path::Path, already: &std::path::Path) {
    if !target.is_dir() {
        return;
    }
    let others: Vec<String> =
        deprot_manifest::discover(target, deprot_manifest::DEFAULT_DISCOVER_DEPTH)
            .into_iter()
            .filter(|m| m != already)
            .map(|m| m.strip_prefix(target).unwrap_or(&m).display().to_string())
            .collect();
    if others.is_empty() {
        return;
    }
    let shown = others
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let more = if others.len() > 5 {
        format!(" (+{} more)", others.len() - 5)
    } else {
        String::new()
    };
    eprintln!(
        "{} found manifest(s) in subdirectories: {shown}{more}",
        "hint:".cyan().bold()
    );
    eprintln!(
        "      this looks like a multi-package repo — run {} to analyze them all.",
        format!("deprot --recursive {}", target.display()).bold()
    );
}

/// Vuln-first audit: gather every known advisory across the resolved tree (preferred) or the
/// manifest, render them worst-first, and exit non-zero if any are found.
async fn run_vulns(cli: &Cli) -> Result<()> {
    let collector = collector_from(cli, false)?;
    let mut findings: Vec<VulnFinding> = Vec::new();

    // Prefer the resolved lockfile tree — that's where most advisories hide (transitive deps).
    if let Ok(resolved) = deprot_manifest::detect_lockfile(&cli.path) {
        eprintln!(
            "{} {} {} packages (resolved tree) from {} for advisories ...",
            "deprot".bold(),
            "auditing".dimmed(),
            resolved.graph.len(),
            resolved.path.display(),
        );
        for gf in collector.collect_graph(&resolved.graph).await {
            let node = &resolved.graph.nodes()[gf.index];
            for v in gf.facts.vulns {
                findings.push(VulnFinding {
                    package: node.name.clone(),
                    version: node.version.clone(),
                    ecosystem: node.ecosystem.label().to_string(),
                    vuln: v,
                });
            }
        }
    } else {
        let detected = deprot_manifest::detect(&cli.path)
            .with_context(|| format!("resolving target {}", cli.path.display()))?;
        eprintln!(
            "{} {} {} dependencies from {} for advisories ...",
            "deprot".bold(),
            "auditing".dimmed(),
            detected.dependencies.len(),
            detected.path.display(),
        );
        for c in collector.collect_all(&detected.dependencies).await {
            let version = c
                .facts
                .analyzed_version
                .clone()
                .unwrap_or_else(|| "?".into());
            let (name, eco) = (c.dependency.name, c.dependency.ecosystem);
            for v in c.facts.vulns {
                findings.push(VulnFinding {
                    package: name.clone(),
                    version: version.clone(),
                    ecosystem: eco.label().to_string(),
                    vuln: v,
                });
            }
        }
    }

    if cli.json {
        println!("{}", vuln_json(&findings));
    } else {
        if !findings.is_empty() {
            println!("{}", vuln_table(&findings));
            println!();
        }
        println!("{}", vuln_summary(&findings));
    }

    // Vuln-first convention: a clean tree exits 0, any advisory exits non-zero.
    if !findings.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// Build a collector from the CLI's cache/offline/concurrency flags.
fn collector_from(cli: &Cli, enrich: bool) -> Result<Collector> {
    Collector::new(CollectorConfig {
        concurrency: cli.concurrency.max(1),
        cache_ttl_secs: if cli.refresh {
            0
        } else {
            DEFAULT_CACHE_TTL_SECS
        },
        cache_enabled: !cli.no_cache,
        enrich,
        offline: cli.offline,
    })
}

/// Collect facts for a set of manifest dependencies and score them into render rows, tagging each
/// with its originating subproject (`source`) for the multi-package view.
async fn collect_and_score(
    collector: &Collector,
    deps: &[deprot_core::Dependency],
    now: chrono::DateTime<Utc>,
    source: Option<&str>,
) -> Vec<Row> {
    collector
        .collect_all(deps)
        .await
        .into_iter()
        .map(|c| Row {
            analyzed_version: c.facts.analyzed_version.clone(),
            score: deprot_core::score(&c.facts, now),
            dependency: c.dependency,
            error: c.error,
            source: source.map(str::to_string),
        })
        .collect()
}

/// Recursive/monorepo mode: discover every manifest under the target directory, analyze each in its
/// own section, and gate on the worst verdict across all of them.
async fn run_recursive(cli: &Cli, fail_on: Option<Tier>) -> Result<()> {
    let manifests = deprot_manifest::discover(&cli.path, deprot_manifest::DEFAULT_DISCOVER_DEPTH);

    // Parse each manifest, keeping the ones that actually declare dependencies.
    let mut detecteds: Vec<deprot_manifest::Detected> = Vec::new();
    for m in &manifests {
        match deprot_manifest::detect(m) {
            Ok(d) if !d.dependencies.is_empty() => detecteds.push(d),
            Ok(_) => {} // empty manifest (e.g. an empty root package.json) — nothing to grade
            Err(e) => eprintln!("{} skipping {}: {e:#}", "warning:".yellow(), m.display()),
        }
    }
    if detecteds.is_empty() {
        return Err(anyhow!(
            "no dependencies found under {} (scanned {} manifest(s))",
            cli.path.display(),
            manifests.len()
        ));
    }

    eprintln!(
        "{} {} {} package(s) under {} ...",
        "deprot".bold(),
        "analyzing".dimmed(),
        detecteds.len(),
        cli.path.display(),
    );

    let collector = collector_from(cli, false)?;
    let now = Utc::now();

    let mut worst = Tier::Ok;
    let mut packages: Vec<(String, String, Vec<Row>)> = Vec::new();

    for d in &detecteds {
        let mut deps = d.dependencies.clone();
        if cli.prod_only {
            deps.retain(|x| x.direct);
        }
        if deps.is_empty() {
            continue;
        }

        // Short subproject label (the manifest's directory, relative to the target) used to tag and
        // group rows in the merged TUI view; e.g. `frontend`, `backend`, `.` for the repo root.
        let group = d
            .path
            .parent()
            .and_then(|p| p.strip_prefix(&cli.path).ok())
            .map(|p| p.to_string_lossy().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| ".".to_string());

        let rows = collect_and_score(&collector, &deps, now, Some(&group)).await;
        worst = worst.max(rows.iter().map(|r| r.score.tier).max().unwrap_or(Tier::Ok));

        let label = d
            .path
            .strip_prefix(&cli.path)
            .unwrap_or(&d.path)
            .display()
            .to_string();
        packages.push((label, d.ecosystem.label().to_string(), rows));
    }

    // Interactive mode: merge every subproject's dependencies into one browsable list (each row
    // carries its `source`, so the TUI can label and filter by subproject). Like the single-manifest
    // --tui, this is for exploration, so it skips the CI gate.
    if cli.tui {
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            return Err(anyhow!(
                "--tui requires an interactive terminal; omit it for table output or use --json"
            ));
        }
        let all: Vec<Row> = packages.into_iter().flat_map(|(_, _, rows)| rows).collect();
        deprot_tui::run(all)?;
        return Ok(());
    }

    if cli.json {
        println!("{}", to_json_packages(&packages));
    } else {
        for (label, eco, rows) in &packages {
            println!("{} {} ({})", "▌".cyan().bold(), label.bold(), eco);
            println!("{}", table(rows));
            println!("{}", summary_banner(rows));
            println!();
        }
    }

    if let Some(threshold) = fail_on {
        if worst >= threshold {
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Time-machine: print a package's release history — a per-year cadence histogram, the longest
/// gap between releases, and its current staleness. The ecosystem is taken from the target path's
/// manifest.
async fn run_history(cli: &Cli, pkg: &str) -> Result<()> {
    let ecosystem = deprot_manifest::detect(&cli.path)
        .map(|d| d.ecosystem)
        .or_else(|_| deprot_manifest::detect_lockfile(&cli.path).map(|r| r.ecosystem))
        .unwrap_or(deprot_core::Ecosystem::Npm);

    let config = CollectorConfig {
        concurrency: 1,
        cache_ttl_secs: if cli.refresh {
            0
        } else {
            DEFAULT_CACHE_TTL_SECS
        },
        cache_enabled: !cli.no_cache,
        enrich: false,
        offline: cli.offline,
    };
    let collector = Collector::new(config)?;
    let timeline = collector.history(ecosystem, pkg).await?;

    if timeline.is_empty() {
        eprintln!(
            "no release history found for {pkg} on {}",
            ecosystem.label()
        );
        return Ok(());
    }

    let first = timeline.first().unwrap();
    let last = timeline.last().unwrap();
    let now = Utc::now();

    println!(
        "{} — {} releases on {} ({} → {})",
        pkg.bold(),
        timeline.len(),
        ecosystem.label(),
        first.1.format("%Y-%m-%d"),
        last.1.format("%Y-%m-%d"),
    );

    // Per-year release histogram.
    use std::collections::BTreeMap;
    let mut per_year: BTreeMap<i32, usize> = BTreeMap::new();
    for (_, d) in &timeline {
        *per_year
            .entry(d.format("%Y").to_string().parse().unwrap_or(0))
            .or_default() += 1;
    }
    let max = per_year.values().copied().max().unwrap_or(1);
    println!("\n{}", "releases per year".bold());
    for (year, count) in &per_year {
        let bar = "█".repeat((*count * 24 / max).max(1));
        println!("  {year}  {} {count}", bar.cyan());
    }

    // Longest gap between consecutive releases.
    let mut longest_gap = 0i64;
    let mut gap_at = None;
    for w in timeline.windows(2) {
        let gap = (w[1].1 - w[0].1).num_days();
        if gap > longest_gap {
            longest_gap = gap;
            gap_at = Some((w[0].clone(), w[1].clone()));
        }
    }
    if let Some((a, b)) = gap_at {
        println!(
            "\n{} {} days between {} ({}) and {} ({})",
            "longest gap:".bold(),
            longest_gap,
            a.0,
            a.1.format("%Y-%m-%d"),
            b.0,
            b.1.format("%Y-%m-%d"),
        );
    }
    let staleness = (now - last.1).num_days();
    let staleness_str = format!(
        "current staleness: {staleness} days since {} ({})",
        last.0,
        last.1.format("%Y-%m-%d")
    );
    println!(
        "{}",
        if staleness > 365 {
            staleness_str.red().to_string()
        } else {
            staleness_str.green().to_string()
        }
    );
    Ok(())
}

/// Resolve a lockfile at `path`, collect + score every node, and return `(mean_score, map)` where
/// the map is `name -> (version, tier, value)`.
async fn scored_lockfile(
    collector: &Collector,
    path: &std::path::Path,
) -> Result<(u8, std::collections::BTreeMap<String, (String, Tier, u8)>)> {
    let resolved = deprot_manifest::detect_lockfile(path)
        .with_context(|| format!("resolving lockfile at {}", path.display()))?;
    let gfacts = collector.collect_graph(&resolved.graph).await;
    let now = Utc::now();
    let mut map = std::collections::BTreeMap::new();
    let mut sum = 0u32;
    let mut n = 0u32;
    for gf in gfacts {
        let node = &resolved.graph.nodes()[gf.index];
        if gf.facts.analyzed_version.is_none() {
            continue; // skip local/workspace/unknown
        }
        let score = deprot_core::score(&gf.facts, now);
        sum += score.value as u32;
        n += 1;
        map.insert(
            node.name.clone(),
            (node.version.clone(), score.tier, score.value),
        );
    }
    let mean = sum.checked_div(n).unwrap_or(0) as u8;
    Ok((mean, map))
}

/// PR mode: diff the resolved tree of `cli.path` against a `baseline` lockfile.
async fn run_diff(cli: &Cli, baseline: &std::path::Path, fail_on: Option<Tier>) -> Result<()> {
    let config = CollectorConfig {
        concurrency: cli.concurrency.max(1),
        cache_ttl_secs: if cli.refresh {
            0
        } else {
            DEFAULT_CACHE_TTL_SECS
        },
        cache_enabled: !cli.no_cache,
        enrich: false,
        offline: cli.offline,
    };
    let collector = Collector::new(config)?;

    eprintln!(
        "{} {} {} → {} ...",
        "deprot".bold(),
        "diffing".dimmed(),
        baseline.display(),
        cli.path.display()
    );
    let (base_mean, base) = scored_lockfile(&collector, baseline).await?;
    let (new_mean, new) = scored_lockfile(&collector, &cli.path).await?;

    let verdict = |t: Tier| match t {
        Tier::Ok => "OK".green().to_string(),
        Tier::Caution => "CAUTION".yellow().to_string(),
        Tier::Risky => "RISKY".red().to_string(),
    };

    let mut added_risky = false;

    let added: Vec<_> = new.iter().filter(|(k, _)| !base.contains_key(*k)).collect();
    let removed: Vec<_> = base.iter().filter(|(k, _)| !new.contains_key(*k)).collect();
    let changed: Vec<_> = new
        .iter()
        .filter_map(|(k, nv)| base.get(k).filter(|bv| bv.0 != nv.0).map(|bv| (k, bv, nv)))
        .collect();

    println!("{}", "Dependency diff".bold());
    println!("\n{} ({})", "added".bold(), added.len());
    for (name, (ver, tier, _)) in &added {
        if *tier == Tier::Risky {
            added_risky = true;
        }
        println!("  {} {name} {ver}  [{}]", "+".green(), verdict(*tier));
    }
    println!("\n{} ({})", "removed".bold(), removed.len());
    for (name, (ver, _, _)) in &removed {
        println!("  {} {name} {ver}", "-".red());
    }
    println!("\n{} ({})", "version-changed".bold(), changed.len());
    for (name, bv, nv) in &changed {
        println!(
            "  {} {name} {} → {}  [{}]",
            "~".yellow(),
            bv.0,
            nv.0,
            verdict(nv.1)
        );
    }

    let delta = new_mean as i32 - base_mean as i32;
    let sign = if delta >= 0 { "+" } else { "" };
    let delta_str = format!("{sign}{delta}");
    println!(
        "\n{} {base_mean} → {new_mean}  ({})",
        "project health:".bold(),
        if delta >= 0 {
            delta_str.green().to_string()
        } else {
            delta_str.red().to_string()
        }
    );

    // In PR mode, --fail-on gates on newly-added dependencies at/above the threshold.
    if let Some(threshold) = fail_on {
        let worst_added = added.iter().map(|(_, v)| v.1).max().unwrap_or(Tier::Ok);
        if worst_added >= threshold {
            std::process::exit(1);
        }
    } else if added_risky {
        // Sensible default: a PR that introduces a RISKY dependency fails.
        std::process::exit(1);
    }
    Ok(())
}

/// Print the deep-analysis section: install-script (code-on-install) packages and maintainer
/// capture-risk concentration across the analyzed set.
fn print_deep(rows: &[Row], facts: &[deprot_core::Facts]) {
    // #4 — install scripts.
    let with_scripts: Vec<&str> = rows
        .iter()
        .zip(facts)
        .filter(|(_, f)| f.has_install_script)
        .map(|(r, _)| r.dependency.name.as_str())
        .collect();
    if !with_scripts.is_empty() {
        eprintln!();
        eprintln!(
            "{} {} package(s) run code on install (pre/post-install scripts):",
            "⚠".yellow().bold(),
            with_scripts.len()
        );
        for name in &with_scripts {
            eprintln!("  {} {}", "•".yellow(), name.bold());
        }
    }

    // #1 — maintainer capture-risk.
    let entries: Vec<(&str, &[String])> = rows
        .iter()
        .zip(facts)
        .map(|(r, f)| (r.dependency.name.as_str(), f.maintainers.as_slice()))
        .collect();
    let reaches = deprot_core::capture_risk(entries.iter().map(|(n, m)| (*n, *m)));
    let total = rows.len();
    let top = deprot_core::top_share(&reaches, total);
    let concentrated: Vec<_> = reaches.iter().filter(|r| r.count() > 1).take(8).collect();
    if !concentrated.is_empty() {
        eprintln!();
        eprintln!(
            "{} maintainer capture-risk — top identity controls {:.0}% of your dependencies:",
            "⚠".yellow().bold(),
            top * 100.0
        );
        for r in concentrated {
            eprintln!(
                "  {} {} — {} package(s): {}",
                "•".yellow(),
                r.identity.bold(),
                r.count(),
                r.packages.join(", ")
            );
        }
    }
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
        hint_multi_package(&cli.path, &resolved.path);
        return Ok(());
    }

    eprintln!(
        "{} {} {} packages (resolved tree) from {} ...",
        "deprot".bold(),
        "analyzing".dimmed(),
        resolved.graph.len(),
        resolved.path.display(),
    );

    analyze_graph(cli, &resolved.graph, fail_on).await
}

/// Installed mode: scan packages present on disk (node_modules + the active Python environment, and
/// with `--global` the global npm root + pipx) and analyze them at their exact installed versions
/// through the same resolved-graph pipeline as `--tree`.
async fn run_installed(cli: &Cli, fail_on: Option<Tier>) -> Result<()> {
    let opts = deprot_manifest::InstalledOptions {
        local: cli.installed,
        global: cli.global,
    };
    let scan = deprot_manifest::scan_installed(&cli.path, opts)
        .with_context(|| format!("scanning installed packages under {}", cli.path.display()))?;

    if scan.graph.is_empty() {
        return Err(anyhow!(
            "no installed packages found (looked in {}/node_modules and the active Python environment{}) \
             — is anything installed?",
            cli.path.display(),
            if cli.global { ", plus global npm/pipx" } else { "" }
        ));
    }

    eprintln!(
        "{} {} {} installed packages [{}] ...",
        "deprot".bold(),
        "analyzing".dimmed(),
        scan.graph.len(),
        scan.sources.join(", "),
    );

    analyze_graph(cli, &scan.graph, fail_on).await
}

/// Shared resolved-graph analysis for `--tree` and `--installed`: collect facts at each node's exact
/// version, score, render the tree table/JSON, optionally print a fix plan, and apply the CI gate.
async fn analyze_graph(
    cli: &Cli,
    graph: &deprot_core::DepGraph,
    fail_on: Option<Tier>,
) -> Result<()> {
    let config = CollectorConfig {
        concurrency: cli.concurrency.max(1),
        cache_ttl_secs: if cli.refresh {
            0
        } else {
            DEFAULT_CACHE_TTL_SECS
        },
        cache_enabled: !cli.no_cache,
        enrich: false,
        offline: cli.offline,
    };
    let collector = Collector::new(config)?;
    let gfacts = collector.collect_graph(graph).await;
    let radii = graph.blast_radii();
    let now = Utc::now();

    let rows: Vec<TreeRow> = gfacts
        .into_iter()
        .map(|gf| {
            let node = &graph.nodes()[gf.index];
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

    if cli.fix {
        print_fix_plan(&collector, &rows, now).await;
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

/// Remediation solver: for each risky/caution package, check whether the latest version scores
/// better than the locked one, and print the upgrade that helps most (highest reach first).
async fn print_fix_plan(collector: &Collector, rows: &[TreeRow], now: chrono::DateTime<Utc>) {
    use deprot_core::{Dependency, Tier};

    // Candidates: not-OK, with data. Prioritize by tier then blast radius, cap the work.
    let mut candidates: Vec<&TreeRow> = rows
        .iter()
        .filter(|r| r.has_data && r.score.tier != Tier::Ok)
        .collect();
    candidates.sort_by(|a, b| b.score.tier.cmp(&a.score.tier).then(b.blast.cmp(&a.blast)));
    candidates.truncate(20);

    let mut plan: Vec<String> = Vec::new();
    for r in candidates {
        let dep = Dependency {
            name: r.name.clone(),
            requested: None,
            ecosystem: r.ecosystem,
            direct: r.direct,
        };
        let latest = collector.collect_one(&dep).await;
        let Some(latest_ver) = latest.facts.analyzed_version.clone() else {
            continue;
        };
        if latest_ver == r.version {
            continue; // already on latest
        }
        let latest_score = deprot_core::score(&latest.facts, now);
        // Recommend when the tier improves or the score jumps meaningfully.
        let improves = latest_score.tier < r.score.tier || latest_score.value >= r.score.value + 10;
        if improves {
            let cmd = match r.ecosystem {
                deprot_core::Ecosystem::Npm => format!("npm install {}@{}", r.name, latest_ver),
                deprot_core::Ecosystem::Cargo => format!("cargo update -p {}", r.name),
                deprot_core::Ecosystem::PyPI => {
                    format!("pip install -U {}=={}", r.name, latest_ver)
                }
                deprot_core::Ecosystem::Go => format!("go get {}@{}", r.name, latest_ver),
            };
            plan.push(format!(
                "  {} {} {} → {}  (grade {}→{})   {}",
                "•".green(),
                r.name.bold(),
                r.version,
                latest_ver,
                r.score.grade.as_str(),
                latest_score.grade.as_str(),
                cmd.dimmed(),
            ));
        }
    }

    println!();
    if plan.is_empty() {
        println!(
            "{} no upgrade improves a risky/caution package — issues are in the latest versions too.",
            "fix plan:".bold()
        );
    } else {
        println!(
            "{} {} upgrade(s) would improve your risk:",
            "fix plan:".bold(),
            plan.len()
        );
        for line in plan {
            println!("{line}");
        }
    }
}
