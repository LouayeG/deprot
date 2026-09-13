//! Aggregation: turn a set of [`Signal`]s into a final [`Score`] — a 0–100 value, a letter
//! [`Grade`], and a [`Tier`] verdict.
//!
//! The base value is a weight-normalized average of whatever signals were computable. On top of
//! that, a few conditions **force** the verdict to `Risky` regardless of the average, because they
//! represent facts a good average should never wash out: an unfixed high/critical vulnerability, a
//! registry deprecation, or an archived upstream.

use crate::facts::{Facts, Severity};
use crate::signals::{self, Signal};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Letter grade derived from the 0–100 score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    fn from_value(v: u8) -> Grade {
        match v {
            90..=100 => Grade::A,
            75..=89 => Grade::B,
            60..=74 => Grade::C,
            40..=59 => Grade::D,
            _ => Grade::F,
        }
    }

    /// Single-character label.
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }
}

/// The headline verdict tier. This is what `--fail-on` gates against and what the summary banner
/// reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Ok,
    Caution,
    Risky,
}

impl Tier {
    /// Lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Ok => "ok",
            Tier::Caution => "caution",
            Tier::Risky => "risky",
        }
    }

    /// Parse from a CLI string (`ok` / `caution` / `risky`).
    pub fn parse(s: &str) -> Option<Tier> {
        match s.trim().to_lowercase().as_str() {
            "ok" => Some(Tier::Ok),
            "caution" => Some(Tier::Caution),
            "risky" => Some(Tier::Risky),
            _ => None,
        }
    }
}

/// The full result of scoring one dependency.
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    /// 0–100 health value.
    pub value: u8,
    /// Letter grade derived from `value`.
    pub grade: Grade,
    /// Headline verdict (may be forced worse than `value` alone implies).
    pub tier: Tier,
    /// The signals that produced this score, in display order.
    pub signals: Vec<Signal>,
    /// Human-readable reasons the tier was *forced* (empty when the tier follows the value).
    pub forced_reasons: Vec<String>,
}

/// Score value thresholds for the (unforced) tier mapping.
const CAUTION_BELOW: u8 = 80;
const RISKY_BELOW: u8 = 55;

/// Score one dependency from its [`Facts`] at reference time `now`.
///
/// Pure and deterministic: no I/O, no ambient clock. Pass the same inputs, get the same output —
/// which is exactly what the engine's unit tests and replay fixtures rely on.
pub fn score(facts: &Facts, now: DateTime<Utc>) -> Score {
    let signals = signals::all(facts, now);

    let total_weight: f64 = signals.iter().map(|s| s.weight).sum();
    let value = if total_weight <= 0.0 {
        50 // no signals at all: neutral, not a false "perfect"
    } else {
        let weighted: f64 = signals.iter().map(|s| s.score * s.weight).sum();
        (weighted / total_weight * 100.0).round() as u8
    };

    // Base tier from the value.
    let mut tier = if value < RISKY_BELOW {
        Tier::Risky
    } else if value < CAUTION_BELOW {
        Tier::Caution
    } else {
        Tier::Ok
    };

    // Forced escalations — facts that must not be averaged away.
    let mut forced_reasons = Vec::new();
    // A package we could not resolve at all (unknown/typosquatted name, a registry 404, or a
    // failed lookup) must never be presented as healthy: absence of data is not absence of risk.
    // Force RISKY with an explicit reason so a CI gate (`--fail-on risky`) surfaces it instead of
    // the remaining default signals averaging into a reassuring grade.
    if facts.is_unresolved() {
        forced_reasons
            .push("no registry data — package unknown or lookup failed; risk not assessable".to_string());
    }
    if facts.deprecated {
        forced_reasons.push("package is deprecated".to_string());
    }
    if facts.archived {
        forced_reasons.push("source repository is archived".to_string());
    }
    if let Some(v) = facts.vulns.iter().find(|v| v.severity() >= Severity::High) {
        forced_reasons.push(format!("unresolved high/critical advisory {}", v.id));
    }
    if !forced_reasons.is_empty() {
        tier = Tier::Risky;
    }

    Score {
        value,
        grade: Grade::from_value(value),
        tier,
        signals,
        forced_reasons,
    }
}
