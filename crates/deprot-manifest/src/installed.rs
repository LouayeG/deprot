//! Installed-package scanning: discover the packages actually present *on disk* and resolve them
//! into a [`DepGraph`] at their exact installed versions — as opposed to the versions a manifest
//! *declares* or a lockfile *pins*. This catches drift (an installed version that no longer matches
//! the lockfile), extraneous packages installed by hand, and whole ecosystems that have no lockfile
//! parser yet (Python).
//!
//! Three sources are supported:
//! - **npm `node_modules`** — the project's install tree (and nested `node_modules`), read from each
//!   package's `package.json`.
//! - **the active Python environment** — every installed distribution reported by the interpreter's
//!   `importlib.metadata` (i.e. what `pip list` would show for the current venv/system Python).
//! - **global installs** — the global npm root (`npm root -g`) and `pipx`.
//!
//! "Direct" here means *top-level*: a package that nothing else in the scanned set depends on. It's
//! derived from the resolved graph, so it needs no manifest.

use anyhow::{Context, Result};
use deprot_core::{DepGraph, DepNode, Ecosystem};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The result of an installed scan: the resolved graph plus a human label per source that
/// contributed (for the "analyzing …" line).
pub struct InstalledScan {
    /// Resolved graph of installed packages at their exact versions.
    pub graph: DepGraph,
    /// One label per contributing source, e.g. `"node_modules (142)"`.
    pub sources: Vec<String>,
}

/// Which installed sources to scan.
#[derive(Clone, Copy)]
pub struct InstalledOptions {
    /// Project-local installs: `<path>/node_modules` and the active Python environment.
    pub local: bool,
    /// Machine-wide installs: the global npm root and `pipx`.
    pub global: bool,
}

/// Scan installed packages under `path` (and, if requested, machine-wide) into a resolved graph.
pub fn scan_installed(path: &Path, opts: InstalledOptions) -> Result<InstalledScan> {
    let mut b = GraphBuilder::default();
    let mut sources = Vec::new();

    let record = |b: &GraphBuilder, before: usize, label: &str, sources: &mut Vec<String>| {
        let added = b.nodes.len() - before;
        if added > 0 {
            sources.push(format!("{label} ({added})"));
        }
    };

    if opts.local {
        let nm = path.join("node_modules");
        if nm.is_dir() {
            let before = b.nodes.len();
            NpmWalker::new(&mut b).walk(&nm);
            record(&b, before, "node_modules", &mut sources);
        }
        if let Some(py) = python_exe() {
            let before = b.nodes.len();
            let _ = scan_python(&py, &mut b);
            record(&b, before, "python env", &mut sources);
        }
    }

    if opts.global {
        if let Some(root) = npm_global_root() {
            let before = b.nodes.len();
            NpmWalker::new(&mut b).walk(&root);
            record(&b, before, "npm -g", &mut sources);
        }
        let before = b.nodes.len();
        let _ = scan_pipx(&mut b);
        record(&b, before, "pipx", &mut sources);
    }

    Ok(InstalledScan {
        graph: b.build(),
        sources,
    })
}

// ---- graph assembly ----

/// Accumulates nodes (deduplicated by ecosystem+name+version) and unresolved edges, then resolves
/// edges by canonical name and infers "direct" (top-level = nothing depends on it).
#[derive(Default)]
struct GraphBuilder {
    nodes: Vec<DepNode>,
    by_nv: HashMap<(Ecosystem, String, String), usize>,
    by_name: HashMap<(Ecosystem, String), usize>,
    /// `(from_index, ecosystem, raw_dependency_name)` — resolved to a target index in `build`.
    pending: Vec<(usize, Ecosystem, String)>,
}

impl GraphBuilder {
    /// Add a package (deduped) and queue edges to each of its dependency names.
    fn add(&mut self, name: String, version: String, eco: Ecosystem, deps: Vec<String>) {
        let nv = (eco, name.clone(), version.clone());
        let idx = *self.by_nv.entry(nv).or_insert_with(|| {
            let i = self.nodes.len();
            self.nodes.push(DepNode {
                name: name.clone(),
                version,
                ecosystem: eco,
                direct: false,
            });
            self.by_name.entry((eco, canon(eco, &name))).or_insert(i);
            i
        });
        for d in deps {
            self.pending.push((idx, eco, d));
        }
    }

    fn build(self) -> DepGraph {
        let n = self.nodes.len();
        let mut edges: Vec<(usize, usize)> = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        let mut indeg = vec![0usize; n];
        for (from, eco, dep) in &self.pending {
            if let Some(&to) = self.by_name.get(&(*eco, canon(*eco, dep))) {
                if *from != to && seen.insert((*from, to)) {
                    edges.push((*from, to));
                    indeg[to] += 1;
                }
            }
        }
        let mut g = DepGraph::new();
        for (i, mut node) in self.nodes.into_iter().enumerate() {
            // Top-level install: nothing else in the scanned set depends on it.
            node.direct = indeg[i] == 0;
            g.add_node(node);
        }
        for (from, to) in edges {
            g.add_edge(from, to);
        }
        g
    }
}

/// Canonical name for edge matching. PyPI names are PEP 503-normalized (lowercase, runs of `-_.`
/// collapse to a single `-`); npm names are just lowercased.
fn canon(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::PyPI => {
            let mut out = String::with_capacity(name.len());
            let mut prev_sep = false;
            for c in name.to_lowercase().chars() {
                if c == '-' || c == '_' || c == '.' {
                    if !prev_sep {
                        out.push('-');
                        prev_sep = true;
                    }
                } else {
                    out.push(c);
                    prev_sep = false;
                }
            }
            out
        }
        _ => name.to_lowercase(),
    }
}

// ---- npm node_modules ----

#[derive(Deserialize)]
struct NpmPkgJson {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: std::collections::BTreeMap<String, String>,
}

/// Recursively reads packages out of a `node_modules` tree, guarding against symlink loops
/// (pnpm-style layouts) via a visited set of canonicalized directories.
struct NpmWalker<'a> {
    b: &'a mut GraphBuilder,
    visited: HashSet<PathBuf>,
}

impl<'a> NpmWalker<'a> {
    fn new(b: &'a mut GraphBuilder) -> Self {
        NpmWalker {
            b,
            visited: HashSet::new(),
        }
    }

    fn walk(&mut self, nm: &Path) {
        let key = std::fs::canonicalize(nm).unwrap_or_else(|_| nm.to_path_buf());
        if !self.visited.insert(key) {
            return;
        }
        let Ok(entries) = std::fs::read_dir(nm) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue; // .bin, .cache, .package-lock.json, …
            }
            if name.starts_with('@') {
                // scope directory: its children are the packages
                if let Ok(scoped) = std::fs::read_dir(&p) {
                    for se in scoped.flatten() {
                        if se.path().is_dir() {
                            self.read_pkg(&se.path());
                        }
                    }
                }
            } else {
                self.read_pkg(&p);
            }
        }
    }

    fn read_pkg(&mut self, dir: &Path) {
        if let Ok(text) = std::fs::read_to_string(dir.join("package.json")) {
            if let Ok(doc) = serde_json::from_str::<NpmPkgJson>(&text) {
                if let Some(name) = doc.name {
                    let version = doc.version.unwrap_or_else(|| "?".into());
                    let mut deps: Vec<String> = doc.dependencies.into_keys().collect();
                    deps.extend(doc.optional_dependencies.into_keys());
                    self.b.add(name, version, Ecosystem::Npm, deps);
                }
            }
        }
        let nested = dir.join("node_modules");
        if nested.is_dir() {
            self.walk(&nested);
        }
    }
}

/// The global npm `node_modules` root (`npm root -g`), if npm is installed.
fn npm_global_root() -> Option<PathBuf> {
    let out = Command::new("npm").args(["root", "-g"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    dir.is_dir().then_some(dir)
}

// ---- Python ----

/// Enumerate installed distributions via the interpreter's own `importlib.metadata`, so we see
/// exactly what that environment can import.
const PY_SNIPPET: &str = "\
import json, importlib.metadata as m
out = []
for d in m.distributions():
    try:
        name = d.metadata['Name']
    except Exception:
        name = None
    if not name:
        continue
    try:
        reqs = list(d.requires or [])
    except Exception:
        reqs = []
    out.append({'name': name, 'version': d.version or '?', 'requires': reqs})
print(json.dumps(out))
";

#[derive(Deserialize, Default)]
struct PyDist {
    name: String,
    version: String,
    #[serde(default)]
    requires: Vec<String>,
}

/// The Python interpreter to inspect: the active virtualenv if one is set, else `python3`/`python`.
fn python_exe() -> Option<String> {
    if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
        for sub in [["bin", "python"], ["Scripts", "python.exe"]] {
            let cand = Path::new(&venv).join(sub[0]).join(sub[1]);
            if cand.exists() {
                return Some(cand.to_string_lossy().into_owned());
            }
        }
    }
    for exe in ["python3", "python"] {
        let ok = Command::new(exe)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(exe.to_string());
        }
    }
    None
}

fn scan_python(python: &str, b: &mut GraphBuilder) -> Result<usize> {
    let out = Command::new(python)
        .args(["-c", PY_SNIPPET])
        .output()
        .with_context(|| format!("running {python}"))?;
    if !out.status.success() {
        return Ok(0);
    }
    let dists: Vec<PyDist> = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let before = b.nodes.len();
    for d in dists {
        let deps: Vec<String> = d
            .requires
            .iter()
            .filter_map(|r| parse_req_name(r))
            .collect();
        b.add(d.name, d.version, Ecosystem::PyPI, deps);
    }
    Ok(b.nodes.len() - before)
}

/// Extract the bare package name from a PEP 508 requirement string, dropping any version specifier,
/// extras, or environment marker: `"urllib3 (>=1.21.1) ; extra == 'x'"` -> `"urllib3"`.
fn parse_req_name(req: &str) -> Option<String> {
    let s = req.trim_start();
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .unwrap_or(s.len());
    let name = &s[..end];
    (!name.is_empty()).then(|| name.to_string())
}

// ---- pipx ----

#[derive(Deserialize, Default)]
struct PipxList {
    #[serde(default)]
    venvs: std::collections::BTreeMap<String, PipxVenv>,
}

#[derive(Deserialize)]
struct PipxVenv {
    metadata: PipxMeta,
}

#[derive(Deserialize)]
struct PipxMeta {
    main_package: Option<PipxPkg>,
}

#[derive(Deserialize)]
struct PipxPkg {
    package: Option<String>,
    package_version: Option<String>,
}

fn scan_pipx(b: &mut GraphBuilder) -> Result<usize> {
    let out = match Command::new("pipx").args(["list", "--json"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Ok(0),
    };
    let list: PipxList = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let before = b.nodes.len();
    for venv in list.venvs.into_values() {
        if let Some(mp) = venv.metadata.main_package {
            if let Some(name) = mp.package {
                b.add(
                    name,
                    mp.package_version.unwrap_or_else(|| "?".into()),
                    Ecosystem::PyPI,
                    vec![],
                );
            }
        }
    }
    Ok(b.nodes.len() - before)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requirement_names() {
        assert_eq!(
            parse_req_name("urllib3 (>=1.21.1,<3)").as_deref(),
            Some("urllib3")
        );
        assert_eq!(
            parse_req_name("PySocks>=1.5.6 ; extra == 'socks'").as_deref(),
            Some("PySocks")
        );
        assert_eq!(parse_req_name("requests").as_deref(), Some("requests"));
        assert_eq!(parse_req_name(""), None);
    }

    #[test]
    fn pep503_canonicalization() {
        assert_eq!(
            canon(Ecosystem::PyPI, "Flask_SQLAlchemy"),
            "flask-sqlalchemy"
        );
        assert_eq!(canon(Ecosystem::PyPI, "zope.interface"), "zope-interface");
        assert_eq!(canon(Ecosystem::Npm, "Lodash"), "lodash");
    }

    #[test]
    fn resolves_edges_and_infers_top_level() {
        let mut b = GraphBuilder::default();
        // express -> accepts ; accepts is a leaf.
        b.add(
            "express".into(),
            "4.18.2".into(),
            Ecosystem::Npm,
            vec!["accepts".into()],
        );
        b.add("accepts".into(), "1.3.8".into(), Ecosystem::Npm, vec![]);
        // A PyPI dist whose requirement name is normalized differently than declared.
        b.add(
            "Flask".into(),
            "3.0.0".into(),
            Ecosystem::PyPI,
            vec!["flask_sqlalchemy".into()],
        );
        b.add(
            "Flask-SQLAlchemy".into(),
            "3.1.1".into(),
            Ecosystem::PyPI,
            vec![],
        );
        let g = b.build();
        let idx = |n: &str| g.nodes().iter().position(|x| x.name == n).unwrap();
        assert_eq!(g.blast_radii()[idx("accepts")], 1);
        assert_eq!(
            g.blast_radii()[idx("Flask-SQLAlchemy")],
            1,
            "PEP503 edge should match"
        );
        assert!(
            g.nodes()[idx("express")].direct,
            "nothing depends on express"
        );
        assert!(!g.nodes()[idx("accepts")].direct);
        assert!(g.nodes()[idx("Flask")].direct);
    }

    #[test]
    fn npm_walker_reads_versions_scopes_and_nesting() {
        let tmp =
            std::env::temp_dir().join(format!("deprot_nm_{}_{}", std::process::id(), line!()));
        let nm = tmp.join("node_modules");
        let write = |dir: PathBuf, json: &str| {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("package.json"), json).unwrap();
        };
        write(
            nm.join("express"),
            r#"{"name":"express","version":"4.18.2","dependencies":{"accepts":"^1"}}"#,
        );
        write(
            nm.join("accepts"),
            r#"{"name":"accepts","version":"1.3.8"}"#,
        );
        write(
            nm.join("@scope").join("thing"),
            r#"{"name":"@scope/thing","version":"1.0.0"}"#,
        );
        // A nested (non-hoisted) install of a second version.
        write(
            nm.join("express").join("node_modules").join("accepts"),
            r#"{"name":"accepts","version":"2.0.0"}"#,
        );

        let mut b = GraphBuilder::default();
        NpmWalker::new(&mut b).walk(&nm);
        let g = b.build();
        let _ = std::fs::remove_dir_all(&tmp);

        // express, accepts@1.3.8, accepts@2.0.0, @scope/thing
        assert_eq!(g.len(), 4);
        let express = g.nodes().iter().position(|x| x.name == "express").unwrap();
        assert_eq!(g.nodes()[express].version, "4.18.2");
        assert!(g.nodes().iter().any(|x| x.name == "@scope/thing"));
        assert_eq!(
            g.nodes().iter().filter(|x| x.name == "accepts").count(),
            2,
            "both installed versions are captured"
        );
    }
}
