//! SARIF 2.1.0 export (`--sarif`) so deprot results can flow into GitHub code scanning and other
//! security tooling. Each dependency that isn't OK becomes a result; RISKY maps to `error`,
//! CAUTION to `warning`.

use crate::Row;
use deprot_core::Tier;
use serde_json::{json, Value};

/// Serialize scored rows into a SARIF 2.1.0 log.
pub fn to_sarif(rows: &[Row]) -> String {
    let results: Vec<Value> = rows
        .iter()
        .filter(|r| r.score.tier != Tier::Ok)
        .map(|r| {
            let level = match r.score.tier {
                Tier::Risky => "error",
                Tier::Caution => "warning",
                Tier::Ok => "note",
            };
            let reason = r.score.forced_reasons.first().cloned().unwrap_or_else(|| {
                format!(
                    "score {}/100 (grade {})",
                    r.score.value,
                    r.score.grade.as_str()
                )
            });
            json!({
                "ruleId": format!("deprot/{}", r.score.tier.as_str()),
                "level": level,
                "message": {
                    "text": format!(
                        "{} {} — {} [grade {}, score {}]",
                        r.dependency.name,
                        r.analyzed_version.as_deref().unwrap_or("?"),
                        reason,
                        r.score.grade.as_str(),
                        r.score.value
                    )
                },
                "locations": [{
                    "logicalLocations": [{
                        "name": r.dependency.name,
                        "kind": "package"
                    }]
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "deprot",
                    "informationUri": "https://github.com/LouayeG/deprot",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": [
                        { "id": "deprot/risky", "name": "RiskyDependency",
                          "shortDescription": { "text": "Dependency is a supply-chain risk" } },
                        { "id": "deprot/caution", "name": "CautionDependency",
                          "shortDescription": { "text": "Dependency warrants caution" } }
                    ]
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}
