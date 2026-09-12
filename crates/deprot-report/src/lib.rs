//! # deprot-report
//!
//! Renders scored dependencies for humans and machines. [`terminal`] produces the color-coded
//! table and summary banner shown in a normal run; [`explain`] produces the per-dependency signal
//! breakdown for `--explain`; [`json`] produces stable machine output for CI.
//!
//! Rendering is kept separate from scoring so the same [`Row`] data can be presented three ways
//! without the engine knowing anything about presentation.

mod explain;
mod json;
mod terminal;

use deprot_core::{Dependency, Score};

pub use explain::explain;
pub use json::to_json;
pub use terminal::{summary_banner, table};

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
}
