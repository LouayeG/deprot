//! CycloneDX 1.5 SBOM export (`--sbom`) with deprot's risk assessment attached to each component,
//! so deprot plugs into the wider SBOM/security toolchain instead of being an island.

use crate::Row;
use serde_json::{json, Value};

/// Serialize scored rows into a CycloneDX 1.5 BOM, annotating each component with deprot's score,
/// grade, and verdict as `properties`.
pub fn to_cyclonedx(rows: &[Row]) -> String {
    let components: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut props = vec![
                json!({ "name": "deprot:score", "value": r.score.value.to_string() }),
                json!({ "name": "deprot:grade", "value": r.score.grade.as_str() }),
                json!({ "name": "deprot:verdict", "value": r.score.tier.as_str() }),
            ];
            if let Some(v) = r.dependency.requested.as_ref() {
                props.push(json!({ "name": "deprot:requested", "value": v }));
            }
            json!({
                "type": "library",
                "name": r.dependency.name,
                "version": r.analyzed_version.as_deref().unwrap_or("unknown"),
                "purl": purl(r),
                "properties": props
            })
        })
        .collect();

    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{ "vendor": "deprot", "name": "deprot", "version": env!("CARGO_PKG_VERSION") }]
        },
        "components": components
    });
    serde_json::to_string_pretty(&bom).unwrap_or_else(|_| "{}".to_string())
}

/// A package URL (purl) for the component, per the ecosystem.
fn purl(r: &Row) -> String {
    use deprot_core::Ecosystem;
    let v = r.analyzed_version.as_deref().unwrap_or("");
    match r.dependency.ecosystem {
        Ecosystem::Npm => format!("pkg:npm/{}@{}", r.dependency.name, v),
        Ecosystem::Cargo => format!("pkg:cargo/{}@{}", r.dependency.name, v),
        Ecosystem::PyPI => format!("pkg:pypi/{}@{}", r.dependency.name, v),
    }
}
