//! Input types for the scoring engine.
//!
//! [`Dependency`] is *what to look at* (produced by a manifest parser); [`Facts`] is *everything
//! we learned about it* (produced by a collector). The scoring engine in [`crate::score`] reads
//! only [`Facts`] — it never knows which ecosystem or data source produced them, which is what
//! keeps deprot ecosystem-agnostic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A package ecosystem. New ecosystems are added here and wired up with a manifest + collector
/// adapter; the scoring engine does not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    PyPI,
    Go,
}

impl Ecosystem {
    /// The identifier deps.dev uses for this ecosystem (their "system" path segment).
    pub fn deps_dev_system(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "cargo",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Go => "go",
        }
    }

    /// Human-facing label.
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Go => "Go",
        }
    }
}

/// A single dependency to analyze, as extracted from a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// Registry name of the package (e.g. `lodash`, `serde`).
    pub name: String,
    /// The version requirement as written in the manifest (e.g. `^4.17.0`), if any.
    pub requested: Option<String>,
    /// Which ecosystem this dependency belongs to.
    pub ecosystem: Ecosystem,
    /// Whether this is a direct dependency (vs. transitive / dev-only).
    pub direct: bool,
}

/// A known vulnerability affecting the analyzed version.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Vuln {
    /// Primary advisory identifier — a CVE id when one exists, otherwise the GHSA/OSV id.
    pub id: String,
    /// CVSS base score (0.0–10.0), if published or computable from a CVSS vector.
    pub cvss: Option<f64>,
    /// Short human-readable title / summary.
    pub title: Option<String>,
    /// Other identifiers for the same advisory (CVE / GHSA / OSV / RUSTSEC …), for cross-reference.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The first version that fixes this advisory for the analyzed package, if known — what a user
    /// should upgrade to. `None` means no fixed version is published yet.
    #[serde(default)]
    pub fixed_version: Option<String>,
    /// A primary reference URL (the advisory page), if available.
    #[serde(default)]
    pub reference: Option<String>,
    /// Database severity label (e.g. `CRITICAL`, `HIGH`) used when no numeric CVSS is available.
    #[serde(default)]
    pub severity_label: Option<String>,
}

impl Vuln {
    /// Severity bucket. Prefers the numeric CVSS score, falls back to a database severity label,
    /// and treats a completely unscored-but-real advisory as `Medium` so it's never silently
    /// ignored.
    pub fn severity(&self) -> Severity {
        if let Some(s) = self.cvss {
            return if s >= 9.0 {
                Severity::Critical
            } else if s >= 7.0 {
                Severity::High
            } else if s >= 4.0 {
                Severity::Medium
            } else {
                Severity::Low
            };
        }
        match self.severity_label.as_deref().map(str::to_ascii_uppercase) {
            Some(l) if l == "CRITICAL" => Severity::Critical,
            Some(l) if l == "HIGH" => Severity::High,
            Some(l) if l == "MODERATE" || l == "MEDIUM" => Severity::Medium,
            Some(l) if l == "LOW" => Severity::Low,
            _ => Severity::Medium,
        }
    }

    /// Whether a fixed version is published (i.e. the advisory is actionable by upgrading).
    pub fn is_fixable(&self) -> bool {
        self.fixed_version.is_some()
    }
}

/// Coarse severity bucket for a [`Vuln`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Everything deprot learned about one dependency. Populated by the collector from public data
/// sources; all fields are optional so the engine degrades gracefully when a source is
/// unavailable (e.g. no auth, offline, or the package has no linked repository).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Facts {
    /// The concrete version these facts describe (the version deprot chose to analyze).
    pub analyzed_version: Option<String>,
    /// When the most recent release was published (drives the staleness signal).
    pub latest_published: Option<DateTime<Utc>>,
    /// Number of releases published in the trailing 12 months (drives the cadence signal).
    pub releases_last_year: Option<u32>,
    /// Total number of published versions ever.
    pub total_versions: Option<u32>,
    /// The registry has marked this version (or package) deprecated.
    pub deprecated: bool,
    /// Reason string attached to the deprecation, if any.
    pub deprecated_reason: Option<String>,
    /// The source repository is archived (read-only / abandoned upstream).
    pub archived: bool,
    /// SPDX-ish license identifiers reported for the analyzed version.
    pub licenses: Vec<String>,
    /// Known vulnerabilities affecting the analyzed version.
    pub vulns: Vec<Vuln>,
    /// Canonical source repository (e.g. `github.com/lodash/lodash`), if known.
    pub repo: Option<String>,
    /// Repository star count, if known.
    pub stars: Option<u64>,
    /// Open issue count, if known.
    pub open_issues: Option<u64>,
    /// OpenSSF Scorecard "Maintained" check (0–10), if available.
    pub scorecard_maintained: Option<f64>,
    /// OpenSSF Scorecard aggregate score (0–10), if available.
    pub scorecard_overall: Option<f64>,
    /// Fraction (0.0–1.0) of recent commits authored by the single most active contributor.
    /// High concentration = high bus-factor / capture risk. Optional (needs a GitHub token).
    pub top_contributor_share: Option<f64>,
    /// Registry maintainer/owner identities (email or login). Populated only in `--deep` mode.
    #[serde(default)]
    pub maintainers: Vec<String>,
    /// The package runs an install/pre/post-install script (npm) — a code-execution vector.
    #[serde(default)]
    pub has_install_script: bool,
}

impl Facts {
    /// Whether the collector obtained **no** registry data for this package — an unknown or
    /// typosquatted name, a registry 404, or a failed/offline lookup. The collector always sets
    /// `total_versions` (and usually `latest_published`) the moment it reaches the registry, so
    /// both being absent means we never got a usable response.
    ///
    /// Scoring uses this to avoid presenting an *unassessed* package as healthy: absence of data
    /// is not absence of risk.
    pub fn is_unresolved(&self) -> bool {
        self.total_versions.is_none() && self.latest_published.is_none()
    }
}
