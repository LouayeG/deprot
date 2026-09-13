//! Client for the [OSV.dev](https://osv.dev) API — the Open Source Vulnerabilities database.
//!
//! OSV is the authoritative, keyless, cross-ecosystem source for vulnerability data. Where deps.dev
//! gives us advisory *keys* plus a CVSS number, OSV gives us the full per-advisory picture: CVE
//! aliases, affected version ranges with the **fixed version**, references, and a CVSS vector we can
//! score ourselves. deprot uses OSV as the primary vuln source and *merges* in any advisory deps.dev
//! knew about that OSV didn't — a strict superset of either source alone.

use deprot_core::{Ecosystem, Facts, Vuln};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

const QUERY_URL: &str = "https://api.osv.dev/v1/query";

/// OSV's ecosystem identifier for a deprot [`Ecosystem`] (note: not the same strings as deps.dev).
fn osv_ecosystem(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::Cargo => "crates.io",
        Ecosystem::PyPI => "PyPI",
        Ecosystem::Go => "Go",
    }
}

// ---- wire types (only the fields deprot consumes) ----

#[derive(Deserialize)]
struct QueryResp {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    severity: Vec<SeverityEntry>,
    #[serde(default)]
    database_specific: Option<DatabaseSpecific>,
}

#[derive(Deserialize)]
struct Affected {
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Deserialize)]
struct Range {
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Deserialize)]
struct Reference {
    #[serde(rename = "type", default)]
    ref_type: String,
    url: String,
}

#[derive(Deserialize)]
struct SeverityEntry {
    #[serde(rename = "type", default)]
    sev_type: String,
    #[serde(default)]
    score: String,
}

#[derive(Deserialize)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

/// Query OSV for the advisories affecting `name`@`version` in `eco`, and **merge** them into
/// `facts.vulns` (OSV entries first, then any deps.dev advisory OSV didn't already cover). Networked
/// and best-effort: on any error the existing deps.dev vulns are left untouched.
pub async fn merge(http: &Client, eco: Ecosystem, name: &str, facts: &mut Facts) {
    let Some(version) = facts.analyzed_version.clone() else {
        return; // nothing resolved to query
    };
    let osv = match query(http, eco, name, &version).await {
        Some(v) if !v.is_empty() => dedup_by_id(v),
        _ => return, // no OSV data (or a failed lookup): keep whatever deps.dev found
    };

    // Everything OSV already identifies, by any id/alias, so we don't list a deps.dev duplicate.
    let mut known: HashSet<String> = HashSet::new();
    for v in &osv {
        known.insert(v.id.clone());
        known.extend(v.aliases.iter().cloned());
    }

    let mut merged = osv;
    for v in std::mem::take(&mut facts.vulns) {
        let dup = known.contains(&v.id) || v.aliases.iter().any(|a| known.contains(a));
        if !dup {
            merged.push(v);
        }
    }
    facts.vulns = merged;
}

/// Collapse advisories that resolve to the same primary id — e.g. two OSV/GHSA records that share a
/// CVE — keeping the highest CVSS, the smallest published fix, and the union of aliases. Preserves
/// first-seen order.
fn dedup_by_id(vulns: Vec<Vuln>) -> Vec<Vuln> {
    use std::collections::HashMap;
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, Vuln> = HashMap::new();
    for v in vulns {
        match map.get_mut(&v.id) {
            None => {
                order.push(v.id.clone());
                map.insert(v.id.clone(), v);
            }
            Some(existing) => {
                if v.cvss.unwrap_or(0.0) > existing.cvss.unwrap_or(0.0) {
                    existing.cvss = v.cvss;
                    if v.title.is_some() {
                        existing.title = v.title;
                    }
                }
                if existing.severity_label.is_none() {
                    existing.severity_label = v.severity_label;
                }
                existing.fixed_version = min_fix(existing.fixed_version.take(), v.fixed_version);
                for a in v.aliases {
                    if !existing.aliases.contains(&a) {
                        existing.aliases.push(a);
                    }
                }
            }
        }
    }
    order.into_iter().filter_map(|id| map.remove(&id)).collect()
}

/// The smaller of two fixed versions (the more conservative real fix), semver-aware.
fn min_fix(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => match (parse_ver(&a), parse_ver(&b)) {
            (Some(va), Some(vb)) => Some(if va <= vb { a } else { b }),
            _ => Some(a),
        },
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

async fn query(http: &Client, eco: Ecosystem, name: &str, version: &str) -> Option<Vec<Vuln>> {
    let body = serde_json::json!({
        "version": version,
        "package": { "name": name, "ecosystem": osv_ecosystem(eco) },
    });
    let resp = http.post(QUERY_URL).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: QueryResp = resp.json().await.ok()?;
    Some(
        parsed
            .vulns
            .into_iter()
            .map(|v| convert(v, version))
            .collect(),
    )
}

/// Turn an OSV record into deprot's [`Vuln`], preferring a CVE id for display and computing a CVSS
/// base score from the vector when present.
fn convert(v: OsvVuln, current_version: &str) -> Vuln {
    // Prefer a CVE alias as the primary id; keep every other identifier (including the OSV id) as an
    // alias so cross-referencing still works.
    let cve = v.aliases.iter().find(|a| a.starts_with("CVE-")).cloned();
    let (id, mut aliases) = match cve {
        Some(cve) => {
            let mut rest: Vec<String> = v.aliases.iter().filter(|a| **a != cve).cloned().collect();
            rest.push(v.id.clone());
            (cve, rest)
        }
        None => (v.id.clone(), v.aliases.clone()),
    };
    aliases.retain(|a| *a != id);
    aliases.sort();
    aliases.dedup();

    let cvss = v
        .severity
        .iter()
        .filter(|s| s.sev_type.starts_with("CVSS_V3"))
        .filter_map(|s| cvss3_base_score(&s.score))
        .fold(None, |acc: Option<f64>, x| {
            Some(acc.map_or(x, |a| a.max(x)))
        });

    let severity_label = v.database_specific.and_then(|d| d.severity);

    let fixed_version = pick_fixed(&v.affected, current_version);

    let reference = v
        .references
        .iter()
        .find(|r| r.ref_type == "ADVISORY")
        .or_else(|| v.references.first())
        .map(|r| r.url.clone());

    let title = v.summary.or_else(|| {
        v.details
            .map(|d| d.lines().next().unwrap_or_default().to_string())
    });

    Vuln {
        id,
        cvss,
        title,
        aliases,
        fixed_version,
        reference,
        severity_label,
    }
}

/// Parse a version, tolerating a leading `v` (Go modules) so semver comparison still works.
fn parse_ver(s: &str) -> Option<semver::Version> {
    semver::Version::parse(s.trim_start_matches('v')).ok()
}

/// Choose the fixed version to recommend: the smallest published fix strictly greater than the
/// installed version (so a 4.x user isn't told to "fix" by downgrading to a 3.x patch). Falls back
/// to the first fixed version when versions aren't semver-comparable.
fn pick_fixed(affected: &[Affected], current: &str) -> Option<String> {
    let fixed: Vec<String> = affected
        .iter()
        .flat_map(|a| a.ranges.iter())
        .flat_map(|r| r.events.iter())
        .filter_map(|e| e.fixed.clone())
        .collect();
    if fixed.is_empty() {
        return None;
    }
    if let Some(cur) = parse_ver(current) {
        let best = fixed
            .iter()
            .filter_map(|f| parse_ver(f).map(|v| (v, f)))
            .filter(|(v, _)| *v > cur)
            .min_by(|(a, _), (b, _)| a.cmp(b));
        if let Some((_, f)) = best {
            return Some(f.clone());
        }
    }
    Some(fixed[0].clone())
}

/// Compute the CVSS v3.0/3.1 **base score** from a vector string like
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Returns `None` if required metrics are missing.
fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut m = std::collections::HashMap::new();
    for part in vector.split('/') {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k, v);
        }
    }
    let scope_changed = *m.get("S")? == "C";
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*m.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |v: &str| -> Option<f64> {
        match v {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let c = cia(m.get("C")?)?;
    let i = cia(m.get("I")?)?;
    let a = cia(m.get("A")?)?;

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // CVSS "roundup": round up to one decimal place.
    Some((base * 10.0).ceil() / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_critical_vector_scores_correctly() {
        // Classic 9.8 critical (network, no auth, full impact).
        let s = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((s - 9.8).abs() < 0.05, "got {s}");
    }

    #[test]
    fn cvss_medium_vector_scores_correctly() {
        // CVE-style 6.1 (scope changed, low impacts) — reflected XSS shape.
        let s = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        assert!((s - 6.1).abs() < 0.05, "got {s}");
    }

    #[test]
    fn cvss_missing_metric_is_none() {
        assert!(cvss3_base_score("CVSS:3.1/AV:N/AC:L").is_none());
    }

    #[test]
    fn pick_fixed_prefers_smallest_fix_above_current() {
        let affected = vec![Affected {
            ranges: vec![Range {
                events: vec![
                    Event {
                        fixed: Some("3.0.0".into()),
                    },
                    Event {
                        fixed: Some("4.17.20".into()),
                    },
                ],
            }],
        }];
        // A 4.x user should be told 4.17.20, not the older 3.0.0 line.
        assert_eq!(pick_fixed(&affected, "4.17.15").as_deref(), Some("4.17.20"));
    }

    #[test]
    fn pick_fixed_handles_go_v_prefix() {
        let affected = vec![Affected {
            ranges: vec![Range {
                events: vec![Event {
                    fixed: Some("v1.2.4".into()),
                }],
            }],
        }];
        assert_eq!(pick_fixed(&affected, "v1.2.0").as_deref(), Some("v1.2.4"));
    }
}
