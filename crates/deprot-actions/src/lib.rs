//! # deprot-actions
//!
//! GitHub Actions **workflow security** analysis: detect CI supply-chain footguns — template
//! injection, pwn-requests, unpinned/mutable action refs, excessive `GITHUB_TOKEN` permissions,
//! and `curl | bash` — in a repo's `.github/workflows`.
//!
//! The analyzer ([`analyze_workflow`]) is pure and line-oriented (exact line numbers, no YAML
//! dependency); the walker ([`scan_path`]) is the only part that touches disk.

mod detect;
mod walk;

pub use detect::{analyze_workflow, ActionFinding};
pub use walk::scan_path;
