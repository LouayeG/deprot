//! # deprot-report
//!
//! Renders scored dependencies for humans and machines. [`terminal`] produces the color-coded
//! table and summary banner shown in a normal run; [`explain`] produces the per-dependency signal
//! breakdown for `--explain`; [`json`] produces stable machine output for CI.
//!
//! Rendering is kept separate from scoring so the same [`Row`] data can be presented three ways
//! without the engine knowing anything about presentation.

mod actions;
mod explain;
mod hygiene;
mod json;
mod malware;
mod netmon;
mod reach;
mod sarif;
mod sbom;
mod secrets;
mod terminal;
mod tree;
mod vulns;

use deprot_core::{Dependency, Score};

pub use actions::{workflow_json, workflow_sarif, workflow_summary, workflow_table};
pub use explain::explain;
pub use hygiene::{hygiene_json, hygiene_summary, hygiene_table};
pub use json::{to_json, to_json_packages};
pub use malware::{malware_json, malware_sarif, malware_summary, malware_table};
pub use netmon::{netmon_json, netmon_summary, netmon_table};
pub use reach::{reach_json, reach_summary, reach_table};
pub use sarif::to_sarif;
pub use sbom::to_cyclonedx;
pub use secrets::{secret_json, secret_sarif, secret_summary, secret_table};
pub use terminal::{summary_banner, table};
pub use tree::{tree_summary, tree_table, tree_to_json, TreeRow};
pub use vulns::{vuln_json, vuln_sarif, vuln_summary, vuln_table, VulnFinding};

/// A scored dependency ready to render: the dependency, the facts-derived score, and any error
/// that occurred while collecting its facts.
pub struct Row {
    /// The dependency described by this row.
    pub dependency: Dependency,
    /// The concrete version that was analyzed (from the collected facts), if known.
    pub analyzed_version: Option<String>,
    /// Its computed score.
    pub score: Score,
    /// Present when fact collection failed (the score is then low-confidence).
    pub error: Option<String>,
    /// The subproject this dependency came from in multi-package (`--recursive`) mode, e.g.
    /// `frontend` — `None` for a single-manifest analysis. Lets the TUI group and label a merged
    /// monorepo view.
    pub source: Option<String>,
}
