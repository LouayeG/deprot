//! Stable JSON output for CI and scripting (`--json`).
//!
//! The shape is deliberately flat and explicit rather than a serde dump of internal types, so the
//! output is a documented contract that survives internal refactors.

use crate::Row;
use serde::Serialize;

#[derive(Serialize)]
struct SignalOut {
    name: &'static str,
    score: f64,
    weight: f64,
    detail: String,
}

#[derive(Serialize)]
struct RowOut {
    name: String,
    ecosystem: String,
    requested: Option<String>,
    analyzed_version: Option<String>,
    direct: bool,
    score: u8,
    grade: String,
    tier: String,
    forced_reasons: Vec<String>,
    signals: Vec<SignalOut>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Summary {
    total: usize,
    ok: usize,
    caution: usize,
    risky: usize,
}

#[derive(Serialize)]
struct Report {
    tool: &'static str,
    version: &'static str,
    summary: Summary,
    dependencies: Vec<RowOut>,
}

#[derive(Serialize)]
struct PackageReport {
    /// The manifest this package's dependencies came from (e.g. `frontend/package.json`).
    source: String,
    ecosystem: String,
    summary: Summary,
    dependencies: Vec<RowOut>,
}

#[derive(Serialize)]
struct MultiReport {
    tool: &'static str,
    version: &'static str,
    summary: Summary,
    packages: Vec<PackageReport>,
}

/// Tally tier counts and map each row to its serializable form.
fn body(rows: &[Row]) -> (Summary, Vec<RowOut>) {
    let mut summary = Summary {
        total: rows.len(),
        ok: 0,
        caution: 0,
        risky: 0,
    };
    let deps: Vec<RowOut> = rows
        .iter()
        .map(|r| {
            match r.score.tier {
                deprot_core::Tier::Ok => summary.ok += 1,
                deprot_core::Tier::Caution => summary.caution += 1,
                deprot_core::Tier::Risky => summary.risky += 1,
            }
            RowOut {
                name: r.dependency.name.clone(),
                ecosystem: r.dependency.ecosystem.label().to_string(),
                requested: r.dependency.requested.clone(),
                analyzed_version: r.analyzed_version.clone(),
                direct: r.dependency.direct,
                score: r.score.value,
                grade: r.score.grade.as_str().to_string(),
                tier: r.score.tier.as_str().to_string(),
                forced_reasons: r.score.forced_reasons.clone(),
                signals: r
                    .score
                    .signals
                    .iter()
                    .map(|s| SignalOut {
                        name: s.name,
                        score: (s.score * 1000.0).round() / 1000.0,
                        weight: s.weight,
                        detail: s.detail.clone(),
                    })
                    .collect(),
                error: r.error.clone(),
            }
        })
        .collect();
    (summary, deps)
}

/// Serialize scored rows into the stable deprot JSON report (pretty-printed).
pub fn to_json(rows: &[Row]) -> String {
    let (summary, dependencies) = body(rows);
    let report = Report {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        summary,
        dependencies,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

/// Serialize a multi-package (monorepo) analysis: one section per discovered manifest, plus a
/// project-wide summary. Each package is `(source_label, ecosystem_label, rows)`.
pub fn to_json_packages(packages: &[(String, String, Vec<Row>)]) -> String {
    let mut total = Summary {
        total: 0,
        ok: 0,
        caution: 0,
        risky: 0,
    };
    let pkgs: Vec<PackageReport> = packages
        .iter()
        .map(|(source, ecosystem, rows)| {
            let (summary, dependencies) = body(rows);
            total.total += summary.total;
            total.ok += summary.ok;
            total.caution += summary.caution;
            total.risky += summary.risky;
            PackageReport {
                source: source.clone(),
                ecosystem: ecosystem.clone(),
                summary,
                dependencies,
            }
        })
        .collect();

    let report = MultiReport {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        summary: total,
        packages: pkgs,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
