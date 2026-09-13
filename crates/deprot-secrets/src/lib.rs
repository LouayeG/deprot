//! # deprot-secrets
//!
//! Hardcoded-secret detection: scan a project's own source for leaked credentials — API keys,
//! tokens, and private keys — with high-precision format rules plus entropy analysis, aggressive
//! false-positive suppression, and always-redacted output.
//!
//! The detection engine ([`scan_content`]) is pure and deterministic; the file walker
//! ([`scan_path`]) is the only part that touches disk.

mod detect;
mod walk;

pub use detect::{scan_content, SecretFinding};
pub use walk::scan_path;
