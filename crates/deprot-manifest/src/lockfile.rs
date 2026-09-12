//! Lockfile parsers that build a fully-resolved [`DepGraph`] — the exact tree, at exact versions,
//! with edges — so deprot can analyze transitive dependencies and compute blast radius.
//!
//! Supported: Cargo's `Cargo.lock` and npm's `package-lock.json` (lockfileVersion 2/3). Direct
//! dependencies are identified from the accompanying manifest when available.

use anyhow::{anyhow, Context, Result};
use deprot_core::{DepGraph, DepNode, Ecosystem};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// A resolved lockfile plus where it was found.
pub struct ResolvedGraph {
    /// Path to the lockfile that was parsed.
    pub path: PathBuf,
    /// Ecosystem of the lockfile.
    pub ecosystem: Ecosystem,
    /// The resolved dependency graph.
    pub graph: DepGraph,
}

/// Lockfile filenames deprot understands, in detection priority order.
const LOCKFILES: &[(&str, Ecosystem)] = &[
    ("Cargo.lock", Ecosystem::Cargo),
    ("package-lock.json", Ecosystem::Npm),
];

/// Resolve a target path (a lockfile, or a directory containing one) into a dependency graph.
pub fn detect_lockfile(path: &Path) -> Result<ResolvedGraph> {
    let lock_path = if path.is_dir() {
        LOCKFILES
            .iter()
            .map(|(name, _)| path.join(name))
            .find(|p| p.exists())
            .ok_or_else(|| {
                anyhow!(
                    "no supported lockfile found in {} (looked for: {})",
                    path.display(),
                    LOCKFILES
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?
    } else {
        path.to_path_buf()
    };

    let name = lock_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let contents = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;

    let (ecosystem, graph) = match recognize(name, &contents) {
        Some(Ecosystem::Cargo) => (
            Ecosystem::Cargo,
            parse_cargo_lock(&contents, direct_names(&lock_path, Ecosystem::Cargo))
                .context("parsing Cargo lockfile")?,
        ),
        Some(Ecosystem::Npm) => (
            Ecosystem::Npm,
            parse_npm_lock(&contents).context("parsing npm lockfile")?,
        ),
        _ => return Err(anyhow!("unrecognized lockfile: {}", lock_path.display())),
    };

    Ok(ResolvedGraph {
        path: lock_path,
        ecosystem,
        graph,
    })
}

/// Read the sibling manifest (if present) to learn which packages are *direct* dependencies —
/// Cargo.lock itself doesn't distinguish them.
fn direct_names(lock_path: &Path, eco: Ecosystem) -> BTreeSet<String> {
    let manifest = match eco {
        Ecosystem::Cargo => "Cargo.toml",
        _ => return BTreeSet::new(),
    };
    let Some(dir) = lock_path.parent() else {
        return BTreeSet::new();
    };
    let Ok(text) = std::fs::read_to_string(dir.join(manifest)) else {
        return BTreeSet::new();
    };
    match crate::parser_for(&dir.join(manifest)) {
        Some(p) => p
            .parse(&text)
            .map(|deps| deps.into_iter().map(|d| d.name).collect())
            .unwrap_or_default(),
        None => BTreeSet::new(),
    }
}

/// Identify a lockfile's ecosystem by filename, falling back to sniffing its contents (so a
/// baseline copied to an arbitrary name, e.g. for `--diff`, still resolves).
fn recognize(name: &str, contents: &str) -> Option<Ecosystem> {
    match name {
        "Cargo.lock" => return Some(Ecosystem::Cargo),
        "package-lock.json" => return Some(Ecosystem::Npm),
        _ => {}
    }
    let trimmed = contents.trim_start();
    if trimmed.starts_with('{') && contents.contains("lockfileVersion") {
        Some(Ecosystem::Npm)
    } else if contents.contains("[[package]]") {
        Some(Ecosystem::Cargo)
    } else {
        None
    }
}

// ---- Cargo.lock ----

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default, rename = "package")]
    packages: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    source: Option<String>,
}

/// Parse `Cargo.lock`. Only registry packages (those with a `source`) are analyzable via
/// crates.io; path/workspace members (no `source`) are kept as nodes for graph structure but are
/// marked so the collector can skip them.
fn parse_cargo_lock(contents: &str, direct: BTreeSet<String>) -> Result<DepGraph> {
    let lock: CargoLock = toml::from_str(contents)?;
    let mut graph = DepGraph::new();

    // Index nodes by name and by "name version" so dependency strings resolve unambiguously.
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_name_version: HashMap<(String, String), usize> = HashMap::new();

    for pkg in &lock.packages {
        // Registry crates have a source; local/workspace members don't and aren't on crates.io.
        let is_registry = pkg
            .source
            .as_deref()
            .map(|s| s.contains("registry"))
            .unwrap_or(false);
        let idx = graph.add_node(DepNode {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            ecosystem: Ecosystem::Cargo,
            // A workspace member (no registry source) is a "direct" root of the tree; registry
            // crates are direct only if the manifest lists them.
            direct: !is_registry || direct.contains(&pkg.name),
        });
        by_name.entry(pkg.name.clone()).or_default().push(idx);
        by_name_version.insert((pkg.name.clone(), pkg.version.clone()), idx);
    }

    for (i, pkg) in lock.packages.iter().enumerate() {
        for dep in &pkg.dependencies {
            // A dependency string is "name" or "name version".
            let mut parts = dep.splitn(2, ' ');
            let dname = parts.next().unwrap_or_default();
            let dver = parts.next();
            let target = match dver {
                Some(v) => by_name_version
                    .get(&(dname.to_string(), v.to_string()))
                    .copied(),
                None => by_name.get(dname).and_then(|v| v.first().copied()),
            };
            if let Some(t) = target {
                graph.add_edge(i, t);
            }
        }
    }

    Ok(graph)
}

// ---- package-lock.json (v2/v3) ----

#[derive(Deserialize)]
struct NpmLock {
    #[serde(default)]
    packages: BTreeMap<String, NpmPackage>,
}

#[derive(Deserialize)]
struct NpmPackage {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev: bool,
}

/// Parse `package-lock.json` v2/v3. The `packages` map is keyed by install path; the `""` entry is
/// the project root (its dependency maps mark the direct deps). Edges are resolved by package
/// name (nearest-node_modules resolution is approximated to top-level), which is exact enough for
/// blast-radius counting.
fn parse_npm_lock(contents: &str) -> Result<DepGraph> {
    let lock: NpmLock = serde_json::from_str(contents)?;
    let mut graph = DepGraph::new();

    // Direct deps = the root entry's dependency maps.
    let mut direct: BTreeSet<String> = BTreeSet::new();
    if let Some(root) = lock.packages.get("") {
        direct.extend(root.dependencies.keys().cloned());
        direct.extend(root.optional_dependencies.keys().cloned());
        direct.extend(root.dev_dependencies.keys().cloned());
    }

    // One node per non-root package entry; index by bare package name.
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for (path, pkg) in &lock.packages {
        if path.is_empty() {
            continue; // the root project itself is not a dependency
        }
        let name = npm_name_from_path(path);
        let idx = graph.add_node(DepNode {
            name: name.clone(),
            version: pkg.version.clone().unwrap_or_else(|| "?".into()),
            ecosystem: Ecosystem::Npm,
            direct: direct.contains(&name) && !pkg.dev,
        });
        by_name.entry(name.clone()).or_insert(idx);
    }

    // Edges: link each package to the (top-level) node of each name it depends on.
    for (path, pkg) in &lock.packages {
        if path.is_empty() {
            continue;
        }
        let from_name = npm_name_from_path(path);
        let Some(&from) = by_name.get(&from_name) else {
            continue;
        };
        for dep_name in pkg
            .dependencies
            .keys()
            .chain(pkg.optional_dependencies.keys())
        {
            if let Some(&to) = by_name.get(dep_name) {
                graph.add_edge(from, to);
            }
        }
    }

    Ok(graph)
}

/// Extract the package name from a `node_modules/...` lock path, handling nesting and scopes.
fn npm_name_from_path(path: &str) -> String {
    // e.g. "node_modules/a/node_modules/@scope/b" -> "@scope/b"
    let tail = path.rsplit("node_modules/").next().unwrap_or(path);
    tail.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock_builds_graph_with_edges() {
        let lock = r#"
            [[package]]
            name = "app"
            version = "0.1.0"

            [[package]]
            name = "serde"
            version = "1.0.0"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            dependencies = ["serde_derive"]

            [[package]]
            name = "serde_derive"
            version = "1.0.0"
            source = "registry+https://github.com/rust-lang/crates.io-index"
        "#;
        let mut direct = BTreeSet::new();
        direct.insert("serde".to_string());
        let g = parse_cargo_lock(lock, direct).unwrap();
        assert_eq!(g.len(), 3);
        let radii = g.blast_radii();
        // serde_derive is depended on by serde (1); app (workspace member) has no dependents.
        let idx = |name: &str| g.nodes().iter().position(|n| n.name == name).unwrap();
        assert_eq!(radii[idx("serde_derive")], 1);
        assert!(g.nodes()[idx("app")].direct, "workspace member is a root");
        assert!(g.nodes()[idx("serde")].direct, "listed in manifest");
    }

    #[test]
    fn npm_lock_builds_graph() {
        let lock = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "express": "^4" } },
                "node_modules/express": { "version": "4.18.2", "dependencies": { "accepts": "^1" } },
                "node_modules/accepts": { "version": "1.3.8" }
            }
        }"#;
        let g = parse_npm_lock(lock).unwrap();
        assert_eq!(g.len(), 2);
        let idx = |name: &str| g.nodes().iter().position(|n| n.name == name).unwrap();
        assert!(g.nodes()[idx("express")].direct);
        assert!(!g.nodes()[idx("accepts")].direct);
        assert_eq!(g.blast_radii()[idx("accepts")], 1);
    }
}
