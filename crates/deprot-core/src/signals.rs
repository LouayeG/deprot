//! Individual health signals.
//!
//! Each signal reduces some slice of [`Facts`] to a normalized subscore in `0.0..=1.0` (1.0 =
//! healthy) plus a human-readable explanation. A signal that cannot be computed from the
//! available facts returns `None` and is simply left out of the weighted average, so a missing
//! data source lowers confidence rather than unfairly tanking a grade.

use crate::facts::{Facts, Severity};
use chrono::{DateTime, Utc};

/// One scored dimension of dependency health.
#[derive(Debug, Clone, PartialEq)]
pub struct Signal {
    /// Stable short name, e.g. `"staleness"`.
    pub name: &'static str,
    /// Normalized subscore, `0.0` (worst) ..= `1.0` (best).
    pub score: f64,
    /// Relative weight in the aggregate. Only the weights of *present* signals count.
    pub weight: f64,
    /// One-line explanation of why this subscore was assigned (powers `--explain`).
    pub detail: String,
}

impl Signal {
    fn new(name: &'static str, score: f64, weight: f64, detail: impl Into<String>) -> Self {
        Signal {
            name,
            score: score.clamp(0.0, 1.0),
            weight,
            detail: detail.into(),
        }
    }
}

/// Linear interpolation of `x` from the range `[lo, hi]` onto `[0, 1]`, clamped. When `hi < lo`
/// the mapping is inverted (larger `x` → smaller output), which is how "more days is worse" style
/// signals are expressed.
fn ramp(x: f64, lo: f64, hi: f64) -> f64 {
    if (hi - lo).abs() < f64::EPSILON {
        return if x >= lo { 1.0 } else { 0.0 };
    }
    ((x - lo) / (hi - lo)).clamp(0.0, 1.0)
}

/// Staleness: how long since the most recent release. Fresh (<90d) is perfect; it decays to a
/// floor as the package approaches ~2 years without a release.
pub fn staleness(facts: &Facts, now: DateTime<Utc>) -> Option<Signal> {
    let last = facts.latest_published?;
    let days = (now - last).num_days().max(0) as f64;
    // 90d -> 1.0, 730d (~2y) -> 0.0
    let score = 1.0 - ramp(days, 90.0, 730.0);
    let detail = format!("last release {} days ago", days as i64);
    Some(Signal::new("staleness", score, 2.0, detail))
}

/// Release cadence: how many releases shipped in the trailing year. Zero is a strong rot signal;
/// four or more reads as an actively iterating project.
pub fn cadence(facts: &Facts) -> Option<Signal> {
    let n = facts.releases_last_year?;
    let score = ramp(n as f64, 0.0, 4.0);
    let detail = format!("{n} release(s) in the last 12 months");
    Some(Signal::new("cadence", score, 1.0, detail))
}

/// Deprecation: a registry-level deprecation is a near-fatal health signal.
pub fn deprecation(facts: &Facts) -> Option<Signal> {
    if !facts.deprecated {
        return None;
    }
    let detail = facts
        .deprecated_reason
        .clone()
        .filter(|r| !r.is_empty())
        .map(|r| format!("deprecated: {r}"))
        .unwrap_or_else(|| "package is deprecated".to_string());
    Some(Signal::new("deprecation", 0.0, 4.0, detail))
}

/// Known vulnerabilities: driven by the single worst advisory affecting the analyzed version.
pub fn vulnerabilities(facts: &Facts) -> Option<Signal> {
    if facts.vulns.is_empty() {
        // Absence of *known* vulns is a (mild) positive signal we can assert.
        return Some(Signal::new(
            "vulnerabilities",
            1.0,
            2.0,
            "no known advisories".to_string(),
        ));
    }
    let worst = facts
        .vulns
        .iter()
        .max_by(|a, b| a.severity().cmp(&b.severity()))
        .expect("non-empty checked above");
    let score = match worst.severity() {
        Severity::Critical => 0.0,
        Severity::High => 0.15,
        Severity::Medium => 0.5,
        Severity::Low => 0.75,
    };
    let detail = format!(
        "{} known advisory(ies); worst {} ({})",
        facts.vulns.len(),
        worst.id,
        match worst.severity() {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    );
    Some(Signal::new("vulnerabilities", score, 3.0, detail))
}

/// License hygiene: a recognized permissive license is best; a copyleft or unusual-but-known
/// license is fine-with-caveats; a missing or unknown license is a compliance risk.
pub fn license(facts: &Facts) -> Option<Signal> {
    if facts.licenses.is_empty() {
        return Some(Signal::new(
            "license",
            0.3,
            1.0,
            "no license declared".to_string(),
        ));
    }
    let permissive = [
        "MIT",
        "APACHE-2.0",
        "BSD-2-CLAUSE",
        "BSD-3-CLAUSE",
        "ISC",
        "0BSD",
        "UNLICENSE",
    ];
    let copyleft = ["GPL", "LGPL", "AGPL", "MPL"];
    let joined = facts.licenses.join(", ");
    // Break SPDX expressions ("Apache-2.0 OR MIT", "(MIT AND BSD-3-Clause)") into individual
    // identifier tokens so a compound-but-permissive license is still recognized as permissive.
    let tokens: Vec<String> = facts
        .licenses
        .iter()
        .flat_map(|l| {
            l.to_uppercase()
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
                .filter(|t| !t.is_empty() && *t != "OR" && *t != "AND" && *t != "WITH")
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    let is_permissive = tokens.iter().any(|t| permissive.contains(&t.as_str()));
    let is_copyleft = tokens
        .iter()
        .any(|t| copyleft.iter().any(|c| t.contains(c)));
    let (score, note) = if is_permissive {
        (1.0, "permissive")
    } else if is_copyleft {
        (0.6, "copyleft — review obligations")
    } else {
        (0.5, "non-standard — review terms")
    };
    Some(Signal::new(
        "license",
        score,
        1.0,
        format!("{joined} ({note})"),
    ))
}

/// OpenSSF Scorecard: upstream engineering hygiene (CI, review, signed releases, ...). Prefers
/// the aggregate score, falling back to the "Maintained" check when only that is present.
pub fn scorecard(facts: &Facts) -> Option<Signal> {
    let (val, which) = match (facts.scorecard_overall, facts.scorecard_maintained) {
        (Some(o), _) => (o, "overall"),
        (None, Some(m)) => (m, "maintained"),
        (None, None) => return None,
    };
    let score = (val / 10.0).clamp(0.0, 1.0);
    Some(Signal::new(
        "scorecard",
        score,
        1.5,
        format!("OpenSSF Scorecard {which} {val:.1}/10"),
    ))
}

/// Bus factor / capture risk: how concentrated authorship is. A project where one author owns
/// almost all recent commits is fragile and a takeover-friendly target.
pub fn bus_factor(facts: &Facts) -> Option<Signal> {
    let share = facts.top_contributor_share?;
    // 50% share -> 1.0 (healthy spread), 95%+ -> ~0.0 (single point of failure)
    let score = 1.0 - ramp(share, 0.5, 0.95);
    Some(Signal::new(
        "bus_factor",
        score,
        1.5,
        format!(
            "top contributor authored {:.0}% of recent commits",
            share * 100.0
        ),
    ))
}

/// Archived upstream repository: development has stopped.
pub fn archived(facts: &Facts) -> Option<Signal> {
    if !facts.archived {
        return None;
    }
    Some(Signal::new(
        "archived",
        0.0,
        3.0,
        "source repository is archived".to_string(),
    ))
}

/// Compute every applicable signal for a set of facts, in display order.
pub fn all(facts: &Facts, now: DateTime<Utc>) -> Vec<Signal> {
    [
        deprecation(facts),
        archived(facts),
        vulnerabilities(facts),
        staleness(facts, now),
        cadence(facts),
        scorecard(facts),
        bus_factor(facts),
        license(facts),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_with_licenses(l: &[&str]) -> Facts {
        Facts {
            licenses: l.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn spdx_or_expression_is_permissive() {
        let sig = license(&facts_with_licenses(&["Apache-2.0 OR MIT"])).unwrap();
        assert_eq!(sig.score, 1.0, "{}", sig.detail);
    }

    #[test]
    fn copyleft_is_penalized() {
        let sig = license(&facts_with_licenses(&["GPL-3.0-only"])).unwrap();
        assert!(sig.score < 0.75);
    }

    #[test]
    fn missing_license_is_low() {
        let sig = license(&facts_with_licenses(&[])).unwrap();
        assert!(sig.score <= 0.3);
    }
}
