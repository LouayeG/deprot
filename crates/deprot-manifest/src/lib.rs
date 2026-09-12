//! # deprot-manifest
//!
//! Turns a project manifest on disk into a normalized list of [`Dependency`] values for the rest
//! of the pipeline. Each ecosystem implements the [`Manifest`] trait; [`detect`] sniffs a path (a
//! file or a directory) and dispatches to the right parser, so the CLI can just say "analyze
//! here" without the user naming the ecosystem.

use anyhow::{anyhow, Context, Result};
use deprot_core::{Dependency, Ecosystem};
use std::path::{Path, PathBuf};

mod npm;

pub use npm::NpmManifest;

/// A parser for one ecosystem's manifest format.
pub trait Manifest {
    /// The ecosystem this parser produces dependencies for.
    fn ecosystem(&self) -> Ecosystem;
    /// Parse raw manifest text into dependencies.
    fn parse(&self, contents: &str) -> Result<Vec<Dependency>>;
}

/// The candidate manifest filenames deprot knows how to read, in detection priority order.
const CANDIDATES: &[(&str, Ecosystem)] = &[
    ("package.json", Ecosystem::Npm),
    // Additional ecosystems (Cargo.toml, requirements.txt, ...) are registered here as their
    // adapters land.
];

/// The result of resolving a target path: which file was read and what it contained.
pub struct Detected {
    /// Absolute-ish path to the manifest that was parsed.
    pub path: PathBuf,
    /// Ecosystem the manifest belongs to.
    pub ecosystem: Ecosystem,
    /// Parsed dependencies.
    pub dependencies: Vec<Dependency>,
}

/// Resolve a target `path` (a manifest file, or a directory containing one) into parsed
/// dependencies. When `path` is a directory the first known manifest found there wins.
pub fn detect(path: &Path) -> Result<Detected> {
    let manifest_path = if path.is_dir() {
        CANDIDATES
            .iter()
            .map(|(name, _)| path.join(name))
            .find(|p| p.exists())
            .ok_or_else(|| {
                anyhow!(
                    "no supported manifest found in {} (looked for: {})",
                    path.display(),
                    CANDIDATES
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?
    } else {
        path.to_path_buf()
    };

    let parser = parser_for(&manifest_path)
        .ok_or_else(|| anyhow!("unsupported manifest: {}", manifest_path.display()))?;

    let contents = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let dependencies = parser
        .parse(&contents)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;

    Ok(Detected {
        path: manifest_path,
        ecosystem: parser.ecosystem(),
        dependencies,
    })
}

/// Pick a parser for a concrete manifest file based on its filename.
fn parser_for(path: &Path) -> Option<Box<dyn Manifest>> {
    let name = path.file_name()?.to_str()?;
    match name {
        "package.json" => Some(Box::new(NpmManifest)),
        _ => None,
    }
}
