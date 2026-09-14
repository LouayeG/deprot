//! # deprot-manifest
//!
//! Turns a project manifest on disk into a normalized list of [`Dependency`] values for the rest
//! of the pipeline. Each ecosystem implements the [`Manifest`] trait; [`detect`] sniffs a path (a
//! file or a directory) and dispatches to the right parser, so the CLI can just say "analyze
//! here" without the user naming the ecosystem.

use anyhow::{anyhow, Context, Result};
use deprot_core::{Dependency, Ecosystem};
use std::path::{Path, PathBuf};

mod cargo;
mod go;
mod installed;
mod lockfile;
mod maven;
mod npm;
mod nuget;
mod php;
mod ruby;

pub use cargo::CargoManifest;
pub use go::GoManifest;
pub use installed::{scan_installed, InstalledOptions, InstalledScan};
pub use lockfile::{detect_lockfile, ResolvedGraph};
pub use maven::MavenManifest;
pub use npm::NpmManifest;
pub use nuget::NuGetManifest;
pub use php::PhpManifest;
pub use ruby::RubyManifest;

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
    ("Cargo.toml", Ecosystem::Cargo),
    ("go.mod", Ecosystem::Go),
    ("Gemfile", Ecosystem::Ruby),
    ("composer.json", Ecosystem::Php),
    ("pom.xml", Ecosystem::Maven),
    ("packages.config", Ecosystem::NuGet),
    // NuGet `.csproj` files have project-specific names and are matched by extension separately.
    // Additional ecosystems (requirements.txt, ...) are registered here as their adapters land.
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
            .or_else(|| find_csproj(path))
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
        "package.json" => return Some(Box::new(NpmManifest)),
        "Cargo.toml" => return Some(Box::new(CargoManifest)),
        "go.mod" => return Some(Box::new(GoManifest)),
        "Gemfile" => return Some(Box::new(RubyManifest)),
        "composer.json" => return Some(Box::new(PhpManifest)),
        "pom.xml" => return Some(Box::new(MavenManifest)),
        "packages.config" => return Some(Box::new(NuGetManifest)),
        _ => {}
    }
    // SDK-style NuGet project files carry a project-specific `<name>.csproj`.
    if path.extension().and_then(|e| e.to_str()) == Some("csproj") {
        return Some(Box::new(NuGetManifest));
    }
    None
}

/// The first `.csproj` file in `dir`, if any (name-sorted for determinism).
fn find_csproj(dir: &Path) -> Option<PathBuf> {
    let mut hits: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("csproj"))
        .collect();
    hits.sort();
    hits.into_iter().next()
}

/// Default recursion depth for [`discover`]. Deep enough for `packages/<name>/` monorepo layouts,
/// shallow enough to stay fast (dependency/build directories are skipped regardless).
pub const DEFAULT_DISCOVER_DEPTH: usize = 6;

/// Directories never descended into during recursive discovery — dependency stores, build output,
/// and VCS/editor metadata. (Dot-directories are skipped separately.)
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    "venv",
    "__pycache__",
    "coverage",
];

/// Recursively find every supported manifest under `root` (bounded to `max_depth`), skipping
/// dependency and build directories and not following symlinks. If `root` is itself a manifest file
/// it's returned directly. Results are sorted for stable ordering.
///
/// This is what powers multi-package / monorepo analysis: one repo often holds a `frontend/`
/// (`package.json`), a `backend/` (`go.mod`), and more, none of which a single top-level `detect`
/// would find.
pub fn discover(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        if parser_for(root).is_some() {
            out.push(root.to_path_buf());
        }
        return out;
    }
    discover_walk(root, 0, max_depth, &mut out);
    out.sort();
    out
}

fn discover_walk(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
    for (name, _) in CANDIDATES {
        let p = dir.join(name);
        if p.is_file() {
            out.push(p);
        }
    }
    if let Some(csproj) = find_csproj(dir) {
        out.push(csproj);
    }
    if depth >= max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue; // don't follow symlinks (loops / escaping the tree)
        }
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
            continue;
        }
        discover_walk(&p, depth + 1, max_depth, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_finds_nested_manifests_and_skips_dependency_dirs() {
        let root =
            std::env::temp_dir().join(format!("deprot_disc_{}_{}", std::process::id(), line!()));
        let write = |rel: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "{}").unwrap();
        };
        write("package.json"); // empty root manifest
        write("frontend/package.json");
        write("backend/go.mod");
        write("packages/lib/Cargo.toml");
        write("node_modules/foo/package.json"); // must be skipped
        write("frontend/node_modules/bar/package.json"); // must be skipped

        let found = discover(&root, DEFAULT_DISCOVER_DEPTH);
        let _ = std::fs::remove_dir_all(&root);

        let rels: Vec<String> = found
            .iter()
            .map(|p| {
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert!(rels.contains(&"package.json".to_string()));
        assert!(rels.contains(&"frontend/package.json".to_string()));
        assert!(rels.contains(&"backend/go.mod".to_string()));
        assert!(rels.contains(&"packages/lib/Cargo.toml".to_string()));
        assert!(
            !rels.iter().any(|r| r.contains("node_modules")),
            "node_modules must be skipped, got {rels:?}"
        );
        assert_eq!(rels.len(), 4);
    }

    #[test]
    fn discover_on_a_file_returns_it() {
        let root = std::env::temp_dir().join(format!("deprot_disc_file_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let f = root.join("go.mod");
        std::fs::write(&f, "module x\n").unwrap();
        let found = discover(&f, DEFAULT_DISCOVER_DEPTH);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(found, vec![f]);
    }
}
