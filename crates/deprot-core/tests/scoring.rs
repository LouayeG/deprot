//! Behavioural tests for the pure scoring engine. Because [`deprot_core::score`] takes an
//! explicit `now`, every case is fully deterministic — no clock, no network.

use chrono::{TimeZone, Utc};
use deprot_core::{score, Facts, Grade, Tier, Vuln};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

/// A fresh, well-maintained, permissively-licensed package with no advisories should grade well.
#[test]
fn healthy_package_scores_high() {
    let facts = Facts {
        latest_published: Some(now() - chrono::Duration::days(20)),
        releases_last_year: Some(12),
        total_versions: Some(80),
        licenses: vec!["MIT".into()],
        scorecard_overall: Some(9.0),
        top_contributor_share: Some(0.4),
        ..Default::default()
    };
    let s = score(&facts, now());
    assert!(s.value >= 90, "expected A-grade, got {}", s.value);
    assert_eq!(s.grade, Grade::A);
    assert_eq!(s.tier, Tier::Ok);
    assert!(s.forced_reasons.is_empty());
}

/// Deprecation must force RISKY no matter how good the other signals look.
#[test]
fn deprecation_forces_risky() {
    let facts = Facts {
        latest_published: Some(now() - chrono::Duration::days(5)),
        releases_last_year: Some(20),
        licenses: vec!["MIT".into()],
        scorecard_overall: Some(9.5),
        deprecated: true,
        deprecated_reason: Some("use foo instead".into()),
        ..Default::default()
    };
    let s = score(&facts, now());
    assert_eq!(s.tier, Tier::Risky);
    assert!(s.forced_reasons.iter().any(|r| r.contains("deprecated")));
}

/// An unfixed high/critical advisory forces RISKY.
#[test]
fn high_severity_vuln_forces_risky() {
    let facts = Facts {
        latest_published: Some(now() - chrono::Duration::days(10)),
        releases_last_year: Some(8),
        licenses: vec!["MIT".into()],
        vulns: vec![Vuln {
            id: "GHSA-xxxx".into(),
            cvss: Some(9.1),
            title: Some("rce".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let s = score(&facts, now());
    assert_eq!(s.tier, Tier::Risky);
    assert!(s.forced_reasons.iter().any(|r| r.contains("GHSA-xxxx")));
}

/// An archived upstream repository forces RISKY.
#[test]
fn archived_forces_risky() {
    let facts = Facts {
        latest_published: Some(now() - chrono::Duration::days(30)),
        releases_last_year: Some(3),
        licenses: vec!["MIT".into()],
        archived: true,
        ..Default::default()
    };
    let s = score(&facts, now());
    assert_eq!(s.tier, Tier::Risky);
}

/// A long-abandoned package (no release in years) should tank the staleness signal.
#[test]
fn stale_package_scores_low() {
    let facts = Facts {
        latest_published: Some(now() - chrono::Duration::days(1200)),
        releases_last_year: Some(0),
        licenses: vec!["MIT".into()],
        ..Default::default()
    };
    let s = score(&facts, now());
    assert!(s.value < 80, "stale pkg should not be OK, got {}", s.value);
}

/// With no facts at all — an unknown/typosquatted name, a 404, or a failed lookup — the package is
/// unassessed and must NOT read as healthy. It's forced RISKY with an explanatory reason, and the
/// free "no known advisories" credit is withheld.
#[test]
fn no_data_is_flagged_not_healthy() {
    let facts = Facts::default();
    let s = score(&facts, now());
    assert_eq!(
        s.tier,
        Tier::Risky,
        "unresolved package must not pass, got {}",
        s.value
    );
    assert!(s
        .forced_reasons
        .iter()
        .any(|r| r.contains("no registry data")));
    // The bogus positive vulnerability signal is gone when there's no data.
    assert!(s.signals.iter().all(|sig| sig.name != "vulnerabilities"));
}

/// Same input, same output — the property the whole replay/testing story rests on.
#[test]
fn scoring_is_deterministic() {
    let facts = Facts {
        latest_published: Some(now() - chrono::Duration::days(100)),
        releases_last_year: Some(5),
        licenses: vec!["Apache-2.0".into()],
        scorecard_overall: Some(7.0),
        ..Default::default()
    };
    let a = score(&facts, now());
    let b = score(&facts, now());
    assert_eq!(a.value, b.value);
    assert_eq!(a.tier, b.tier);
    assert_eq!(a.signals, b.signals);
}
