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

/// Serialize scored rows into the stable deprot JSON report (pretty-printed).
pub fn to_json(rows: &[Row]) -> String {
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

    let report = Report {
        tool: "deprot",
        version: env!("CARGO_PKG_VERSION"),
        summary,
        dependencies: deps,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
