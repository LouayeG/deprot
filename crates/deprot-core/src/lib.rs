//! # deprot-core
//!
//! The **pure, zero-I/O** heart of deprot. Everything here is deterministic: given the same
//! [`Facts`] and the same reference time, [`score`] always returns the same [`Score`]. That is
//! what makes the scoring engine fully unit-testable and replayable from cached fixtures — no
//! network, no clock, no filesystem reach into this crate.
//!
//! The data pipeline is: an ecosystem manifest yields [`Dependency`] values, the collector turns
//! each one into [`Facts`], and this crate turns [`Facts`] into a [`Score`] (a 0–100 value, a
//! letter [`Grade`], a [`Tier`] verdict, and the list of [`Signal`]s that explain it).

mod facts;
mod score;
mod signals;

pub use facts::{Dependency, Ecosystem, Facts, Vuln};
pub use score::{score, Grade, Score, Tier};
pub use signals::Signal;
