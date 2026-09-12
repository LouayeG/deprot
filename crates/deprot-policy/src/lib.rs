//! # deprot-policy
//!
//! Policy-as-code for deprot. A project drops a `.deprot.toml` in its repo declaring the rules its
//! dependencies must satisfy — banned licenses, a minimum score, a maximum age, an OpenSSF floor,
//! outright-banned packages — plus **waivers** (time-boxed exceptions with a reason). deprot then
//! reports every [`Violation`] and a CI run can gate on them.
//!
//! This is what turns deprot from an ad-hoc audit into an enforceable, reviewable team standard —
//! and it's the thing `npm audit` / `cargo audit` fundamentally lack. Evaluation is pure and
//! offline: it reads only the [`Facts`]/[`Score`] deprot already computed.
//!
//! ```toml
//! # .deprot.toml
//! min_score = 60
//! max_age_days = 730
//! required_scorecard = 4.0
//!
//! [licenses]
//! deny = ["GPL-3.0", "AGPL-3.0"]
//! # allow_only = ["MIT", "Apache-2.0", "ISC"]
//!
//! [packages]
//! deny = ["request", "left-pad"]
//!
//! [[waivers]]
//! package = "lodash"
//! reason  = "risk accepted for Q1; migration tracked in JIRA-123"
//! until   = "2026-06-01"
//! ```

use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};
use deprot_core::{Facts, Score};
use serde::Deserialize;
use std::path::Path;

/// A parsed `.deprot.toml` policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Fail if a dependency scores below this (0–100).
    pub min_score: Option<u8>,
    /// Fail if the most recent release is older than this many days.
    pub max_age_days: Option<i64>,
    /// Fail if the OpenSSF Scorecard is below this (0–10).
    pub required_scorecard: Option<f64>,
    /// License rules.
    #[serde(default)]
    pub licenses: LicenseRules,
    /// Package allow/deny lists.
    #[serde(default)]
    pub packages: PackageRules,
    /// Time-boxed exceptions.
    #[serde(default)]
    pub waivers: Vec<Waiver>,
}

/// License allow/deny rules.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseRules {
    /// SPDX identifiers that are forbidden (matched against each license token).
    #[serde(default)]
    pub deny: Vec<String>,
    /// If non-empty, a dependency's license must be one of these.
    #[serde(default)]
    pub allow_only: Vec<String>,
}

/// Package allow/deny rules.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRules {
    /// Packages that are outright banned.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Packages that are always accepted regardless of other rules (e.g. vetted internal deps).
    #[serde(default)]
    pub allow: Vec<String>,
}

/// A time-boxed exception for one package.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// Package the waiver applies to.
    pub package: String,
    /// Why the risk was accepted (required by convention; kept for the audit trail).
    #[serde(default)]
    pub reason: String,
    /// Optional expiry date (`YYYY-MM-DD`); after it, the waiver no longer applies.
    pub until: Option<String>,
}

/// One dependency to evaluate against the policy.
pub struct Subject<'a> {
    /// Package name.
    pub name: &'a str,
    /// Its collected facts.
    pub facts: &'a Facts,
    /// Its computed score.
    pub score: &'a Score,
}

/// A single policy breach.
#[derive(Debug, Clone, PartialEq)]
pub struct Violation {
    /// Offending package.
    pub package: String,
    /// Short rule identifier (e.g. `min_score`, `denied_license`).
    pub rule: &'static str,
    /// Human-readable explanation.
    pub detail: String,
}

impl Policy {
    /// Load a policy from an explicit file, or auto-discover `.deprot.toml` in `dir`. Returns
    /// `Ok(None)` when no policy file exists (policy is opt-in).
    pub fn load(dir: &Path, explicit: Option<&Path>) -> Result<Option<Policy>> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => {
                let candidate = dir.join(".deprot.toml");
                if !candidate.exists() {
                    return Ok(None);
                }
                candidate
            }
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let policy: Policy =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(policy))
    }

    /// Whether `name` currently has an active (non-expired) waiver as of `today`.
    fn is_waived(&self, name: &str, today: NaiveDate) -> bool {
        self.waivers.iter().any(|w| {
            w.package == name
                && match &w.until {
                    None => true,
                    Some(d) => NaiveDate::parse_from_str(d, "%Y-%m-%d")
                        .map(|until| today <= until)
                        .unwrap_or(true), // an unparseable date fails open (waiver active)
                }
        })
    }

    /// Evaluate all subjects, returning every violation. Uses `today` for waiver expiry so it's
    /// deterministic and testable.
    pub fn evaluate(&self, subjects: &[Subject], today: NaiveDate) -> Vec<Violation> {
        let mut out = Vec::new();
        for s in subjects {
            // Explicit allow-list wins over everything.
            if self.packages.allow.iter().any(|p| p == s.name) {
                continue;
            }
            // Active waivers suppress all violations for the package.
            if self.is_waived(s.name, today) {
                continue;
            }

            if self.packages.deny.iter().any(|p| p == s.name) {
                out.push(Violation {
                    package: s.name.to_string(),
                    rule: "banned_package",
                    detail: "package is on the policy deny list".into(),
                });
            }

            if let Some(min) = self.min_score {
                if s.score.value < min {
                    out.push(Violation {
                        package: s.name.to_string(),
                        rule: "min_score",
                        detail: format!("score {} is below the required {min}", s.score.value),
                    });
                }
            }

            if let Some(max_age) = self.max_age_days {
                if let Some(published) = s.facts.latest_published {
                    let age = (Utc::now() - published).num_days();
                    if age > max_age {
                        out.push(Violation {
                            package: s.name.to_string(),
                            rule: "max_age",
                            detail: format!(
                                "last release {age} days ago exceeds limit of {max_age}"
                            ),
                        });
                    }
                }
            }

            if let Some(req) = self.required_scorecard {
                if let Some(sc) = s.facts.scorecard_overall {
                    if sc < req {
                        out.push(Violation {
                            package: s.name.to_string(),
                            rule: "required_scorecard",
                            detail: format!(
                                "OpenSSF Scorecard {sc:.1} is below the required {req:.1}"
                            ),
                        });
                    }
                }
            }

            out.extend(self.license_violations(s));
        }
        out
    }

    fn license_violations(&self, s: &Subject) -> Vec<Violation> {
        let mut out = Vec::new();
        let tokens: Vec<String> = s
            .facts
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

        for denied in &self.licenses.deny {
            let d = denied.to_uppercase();
            // Prefix match so `GPL-3.0` catches SPDX ids like `GPL-3.0-only`.
            if tokens.iter().any(|t| t.starts_with(&d)) {
                out.push(Violation {
                    package: s.name.to_string(),
                    rule: "denied_license",
                    detail: format!("license {denied} is denied by policy"),
                });
            }
        }

        if !self.licenses.allow_only.is_empty() && !s.facts.licenses.is_empty() {
            let allowed: Vec<String> = self
                .licenses
                .allow_only
                .iter()
                .map(|l| l.to_uppercase())
                .collect();
            if !tokens
                .iter()
                .any(|t| allowed.iter().any(|a| t.starts_with(a)))
            {
                out.push(Violation {
                    package: s.name.to_string(),
                    rule: "license_not_allowed",
                    detail: format!(
                        "license {} is not in the allow list",
                        s.facts.licenses.join(", ")
                    ),
                });
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use deprot_core::{score, Facts};

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()
    }

    fn facts(licenses: &[&str], scorecard: Option<f64>) -> Facts {
        Facts {
            latest_published: Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap()),
            releases_last_year: Some(0),
            licenses: licenses.iter().map(|s| s.to_string()).collect(),
            scorecard_overall: scorecard,
            ..Default::default()
        }
    }

    fn subject<'a>(name: &'a str, f: &'a Facts, sc: &'a Score) -> Subject<'a> {
        Subject {
            name,
            facts: f,
            score: sc,
        }
    }

    #[test]
    fn denied_license_is_flagged() {
        let policy = Policy {
            licenses: LicenseRules {
                deny: vec!["GPL-3.0".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let f = facts(&["GPL-3.0-only"], None);
        let sc = score(&f, Utc::now());
        let v = policy.evaluate(&[subject("x", &f, &sc)], today());
        assert!(v.iter().any(|v| v.rule == "denied_license"));
    }

    #[test]
    fn allow_only_flags_outsiders() {
        let policy = Policy {
            licenses: LicenseRules {
                allow_only: vec!["MIT".into(), "Apache-2.0".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let f = facts(&["MPL-2.0"], None);
        let sc = score(&f, Utc::now());
        let v = policy.evaluate(&[subject("x", &f, &sc)], today());
        assert!(v.iter().any(|v| v.rule == "license_not_allowed"));
    }

    #[test]
    fn banned_package_is_flagged_but_waiver_suppresses() {
        let policy = Policy {
            packages: PackageRules {
                deny: vec!["request".into()],
                ..Default::default()
            },
            waivers: vec![Waiver {
                package: "request".into(),
                reason: "migrating".into(),
                until: Some("2026-06-01".into()),
            }],
            ..Default::default()
        };
        let f = facts(&["MIT"], None);
        let sc = score(&f, Utc::now());
        // Waiver active on 2026-01-01 → suppressed.
        assert!(policy
            .evaluate(&[subject("request", &f, &sc)], today())
            .is_empty());
        // Waiver expired by 2026-07-01 → violation returns.
        let later = NaiveDate::from_ymd_opt(2026, 7, 1).unwrap();
        assert!(!policy
            .evaluate(&[subject("request", &f, &sc)], later)
            .is_empty());
    }

    #[test]
    fn allow_list_overrides_all_rules() {
        let policy = Policy {
            min_score: Some(100),
            packages: PackageRules {
                allow: vec!["internal-thing".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let f = facts(&["MIT"], Some(1.0));
        let sc = score(&f, Utc::now());
        assert!(policy
            .evaluate(&[subject("internal-thing", &f, &sc)], today())
            .is_empty());
    }

    #[test]
    fn required_scorecard_floor() {
        let policy = Policy {
            required_scorecard: Some(6.0),
            ..Default::default()
        };
        let f = facts(&["MIT"], Some(3.0));
        let sc = score(&f, Utc::now());
        let v = policy.evaluate(&[subject("x", &f, &sc)], today());
        assert!(v.iter().any(|v| v.rule == "required_scorecard"));
    }
}
