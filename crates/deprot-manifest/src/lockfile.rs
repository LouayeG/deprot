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
    ("composer.lock", Ecosystem::Php),
    ("Gemfile.lock", Ecosystem::Ruby),
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
        Some(Ecosystem::Php) => (
            Ecosystem::Php,
            parse_composer_lock(&contents, direct_names(&lock_path, Ecosystem::Php))
                .context("parsing composer lockfile")?,
        ),
        Some(Ecosystem::Ruby) => (
            Ecosystem::Ruby,
            parse_gemfile_lock(&contents).context("parsing Gemfile lockfile")?,
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
        Ecosystem::Php => "composer.json",
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
        "composer.lock" => return Some(Ecosystem::Php),
        "Gemfile.lock" => return Some(Ecosystem::Ruby),
        _ => {}
    }
    let trimmed = contents.trim_start();
    if trimmed.starts_with('{') && contents.contains("lockfileVersion") {
        Some(Ecosystem::Npm)
    } else if trimmed.starts_with('{') && contents.contains("\"packages\"") {
        Some(Ecosystem::Php)
    } else if contents.contains("[[package]]") {
        Some(Ecosystem::Cargo)
    } else if contents.contains("GEM\n") && contents.contains("specs:") {
        Some(Ecosystem::Ruby)
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
    #[serde(rename = "lockfileVersion", default)]
    lockfile_version: u32,
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

    // v1 lockfiles have no `packages` map, so they'd parse into an empty graph and silently report
    // "no dependencies". Fail loudly with an actionable message instead. (An empty v2/v3 lockfile —
    // a project with zero dependencies — is legitimate and still returns an empty graph.)
    if lock.packages.is_empty() && lock.lockfile_version < 2 {
        return Err(anyhow!(
            "package-lock.json lockfileVersion {} is unsupported (deprot needs v2 or v3); \
             regenerate it with npm 7+ via `rm package-lock.json && npm install`",
            lock.lockfile_version
        ));
    }

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

// ---- composer.lock (PHP / Packagist) ----

#[derive(Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<ComposerPackage>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Vec<ComposerPackage>,
}

#[derive(Deserialize)]
struct ComposerPackage {
    name: String,
    version: String,
    #[serde(default)]
    require: BTreeMap<String, String>,
}

/// Whether a composer requirement is a platform / pseudo package (not a real Packagist node).
fn composer_is_platform(name: &str) -> bool {
    name == "php"
        || name == "composer"
        || name.starts_with("ext-")
        || name.starts_with("lib-")
        || name.starts_with("php-")
        || name.starts_with("composer-")
        || !name.contains('/') // real Packagist ids are always vendor/package
}

/// Parse `composer.lock`. `direct` (from `composer.json`) marks top-level requires; everything in
/// `packages-dev` is treated as a dev dependency. Versions keep any leading `v`. Edges come from each
/// package's `require` map (platform requirements excluded).
fn parse_composer_lock(contents: &str, direct: BTreeSet<String>) -> Result<DepGraph> {
    let lock: ComposerLock = serde_json::from_str(contents)?;
    let mut graph = DepGraph::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();

    let mut all: Vec<(ComposerPackage, bool)> = Vec::new();
    for p in lock.packages {
        let is_direct = direct.contains(&p.name);
        all.push((p, is_direct));
    }
    for p in lock.packages_dev {
        all.push((p, false)); // dev deps are never "direct" runtime deps
    }

    for (p, is_direct) in &all {
        let idx = graph.add_node(DepNode {
            name: p.name.clone(),
            version: p.version.trim_start_matches('v').to_string(),
            ecosystem: Ecosystem::Php,
            direct: *is_direct,
        });
        by_name.entry(p.name.clone()).or_insert(idx);
    }

    for (p, _) in &all {
        let Some(&from) = by_name.get(&p.name) else {
            continue;
        };
        for dep_name in p.require.keys() {
            if composer_is_platform(dep_name) {
                continue;
            }
            if let Some(&to) = by_name.get(dep_name) {
                graph.add_edge(from, to);
            }
        }
    }

    Ok(graph)
}

// ---- Gemfile.lock (Ruby / RubyGems) ----

/// Parse bundler's `Gemfile.lock`. The `GEM > specs:` section lists every resolved gem
/// (`name (version)`) and, indented under it, its runtime dependencies; the `DEPENDENCIES` section
/// lists the direct (top-level) gems. Blast-radius edges are built from the spec dependency lines.
fn parse_gemfile_lock(contents: &str) -> Result<DepGraph> {
    let mut graph = DepGraph::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    // (spec_name -> its listed dependency names)
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut direct: BTreeSet<String> = BTreeSet::new();

    let mut section = ""; // "specs" | "deps" | ""
    let mut current_spec: Option<String> = None;

    for raw in contents.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();

        // Section headers sit at column 0 (or `  specs:` at indent 2 inside GEM).
        if indent == 0 {
            section = match trimmed {
                "DEPENDENCIES" => "deps",
                "GEM" | "GIT" | "PATH" => "gem",
                _ => "",
            };
            current_spec = None;
            continue;
        }

        match section {
            "gem" => {
                if trimmed == "specs:" {
                    section = "specs";
                }
            }
            "specs" => {
                // 4-space indent: a resolved gem `name (version)`. 6-space: its dependency.
                if indent <= 4 {
                    if let Some((name, version)) = parse_spec_line(trimmed) {
                        let idx = *by_name.entry(name.clone()).or_insert_with(|| {
                            graph.add_node(DepNode {
                                name: name.clone(),
                                version,
                                ecosystem: Ecosystem::Ruby,
                                direct: false,
                            })
                        });
                        let _ = idx;
                        current_spec = Some(name);
                    }
                } else if let Some(spec) = &current_spec {
                    // Dependency line: `name (constraint)` — keep just the name.
                    let dep = trimmed.split_whitespace().next().unwrap_or("").to_string();
                    if !dep.is_empty() {
                        edges.push((spec.clone(), dep));
                    }
                }
            }
            "deps" => {
                let name = trimmed
                    .trim_end_matches('!')
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    direct.insert(name);
                }
            }
            _ => {}
        }
    }

    // Apply direct flags now that DEPENDENCIES is known.
    for name in &direct {
        if let Some(&idx) = by_name.get(name) {
            graph.nodes_mut()[idx].direct = true;
        }
    }
    for (from, to) in edges {
        if let (Some(&f), Some(&t)) = (by_name.get(&from), by_name.get(&to)) {
            graph.add_edge(f, t);
        }
    }

    Ok(graph)
}

/// Parse a `name (version)` spec line into its parts.
fn parse_spec_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(" (")?;
    let version = rest.trim_end_matches(')').trim().to_string();
    // Platform-suffixed versions like `1.2.3-x86_64-linux` -> keep the semver head.
    let version = version.split('-').next().unwrap_or(&version).to_string();
    Some((name.trim().to_string(), version))
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

    #[test]
    fn npm_lockfile_v1_is_rejected() {
        let lock = r#"{
            "lockfileVersion": 1,
            "dependencies": { "express": { "version": "4.18.2" } }
        }"#;
        let err = parse_npm_lock(lock).unwrap_err().to_string();
        assert!(err.contains("lockfileVersion 1"), "{err}");
    }

    #[test]
    fn empty_v3_lockfile_is_ok() {
        let lock = r#"{ "lockfileVersion": 3, "packages": {} }"#;
        let g = parse_npm_lock(lock).unwrap();
        assert!(g.is_empty());
    }

    #[test]
    fn composer_lock_builds_graph_with_edges_and_dev() {
        let lock = r#"{
            "packages": [
                {"name": "monolog/monolog", "version": "3.5.0",
                 "require": {"php": ">=8.1", "psr/log": "^3.0"}},
                {"name": "psr/log", "version": "3.0.0", "require": {"php": ">=8.0"}}
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "10.5.0", "require": {}}
            ]
        }"#;
        let mut direct = BTreeSet::new();
        direct.insert("monolog/monolog".to_string());
        let g = parse_composer_lock(lock, direct).unwrap();
        assert_eq!(g.len(), 3);
        let idx = |name: &str| g.nodes().iter().position(|n| n.name == name).unwrap();
        assert!(g.nodes()[idx("monolog/monolog")].direct);
        assert!(!g.nodes()[idx("psr/log")].direct, "transitive");
        assert!(!g.nodes()[idx("phpunit/phpunit")].direct, "dev");
        // monolog -> psr/log gives psr/log a blast radius of 1 (platform `php` is ignored).
        assert_eq!(g.blast_radii()[idx("psr/log")], 1);
    }

    #[test]
    fn gemfile_lock_builds_graph_with_direct_and_edges() {
        let lock = r#"GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      rack (~> 2.0)
    rack (2.2.4)
    nokogiri (1.15.0-x86_64-linux)

PLATFORMS
  ruby

DEPENDENCIES
  actionpack (~> 7.0)
  nokogiri!

BUNDLED WITH
   2.4.10
"#;
        let g = parse_gemfile_lock(lock).unwrap();
        assert_eq!(g.len(), 3);
        let idx = |name: &str| g.nodes().iter().position(|n| n.name == name).unwrap();
        assert!(
            g.nodes()[idx("actionpack")].direct,
            "listed in DEPENDENCIES"
        );
        assert!(g.nodes()[idx("nokogiri")].direct, "`!` suffix still direct");
        assert!(!g.nodes()[idx("rack")].direct, "transitive only");
        assert_eq!(
            g.nodes()[idx("nokogiri")].version,
            "1.15.0",
            "platform suffix stripped"
        );
        assert_eq!(
            g.blast_radii()[idx("rack")],
            1,
            "actionpack depends on rack"
        );
    }
}
