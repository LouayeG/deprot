//! # deprot-reach
//!
//! Dependency **reachability**: does your source actually *import* each declared dependency? deprot
//! goes finer than a runtime-vs-build split — it classifies every dependency as:
//!
//! - **used** — imported somewhere in the source (reachable),
//! - **unused** — a *runtime* dependency that is never imported (dead weight and needless attack
//!   surface — a removal candidate),
//! - **dev** — a dev/build/peer dependency (tools run via config/CLI, not imported), reported but not
//!   flagged as unused.
//!
//! Detection is heuristic and per-ecosystem (import specifiers for npm, module paths for Go, path
//! roots for Rust) and biased toward *not* wrongly calling something unused. The engine is pure;
//! [`scan_imports`] is the only part that touches disk.

use deprot_core::{Dependency, Ecosystem};
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

/// Reachability verdict for one dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// Imported somewhere in the source.
    Used,
    /// A runtime dependency never imported — a removal candidate.
    Unused,
    /// A dev/build/peer dependency (not evaluated for "unused").
    Dev,
    /// This ecosystem has no source-import scanner yet, so reachability is unknown. Reported
    /// honestly rather than assumed used — never counted as a removal candidate.
    Unscanned,
}

/// One dependency with its reachability verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DepUsage {
    /// Package name.
    pub name: String,
    /// Ecosystem label (e.g. `npm`).
    pub ecosystem: String,
    /// Whether it's a direct/runtime dependency.
    pub direct: bool,
    /// The verdict.
    pub reach: Reach,
    /// A file where it was seen imported (when `Used`).
    pub evidence: Option<String>,
}

/// The imports discovered across a source tree, indexed per ecosystem.
#[derive(Default)]
pub struct ImportIndex {
    /// npm package specifier -> a file it appeared in.
    npm: HashMap<String, String>,
    /// Rust path roots seen (`foo` in `use foo::…` / `foo::…`).
    rust: HashSet<String>,
    /// Go import paths -> a file.
    go: Vec<(String, String)>,
}

// ---- extraction (pure) ----

fn js_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:require\(|import\(|(?:^|\s)from\s+|(?:^|\s)import\s+)['"]([^'"]+)['"]"#)
            .unwrap()
    })
}

fn rust_use_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)use\s+([a-zA-Z_][a-zA-Z0-9_]*)").unwrap())
}

fn rust_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)::").unwrap())
}

/// The package a JS module specifier belongs to (`@scope/pkg/sub` -> `@scope/pkg`, `pkg/sub` ->
/// `pkg`); `None` for a relative/absolute path.
pub fn js_package(spec: &str) -> Option<String> {
    if spec.starts_with('.') || spec.starts_with('/') {
        return None;
    }
    let parts: Vec<&str> = spec.split('/').collect();
    if spec.starts_with('@') {
        if parts.len() >= 2 {
            Some(format!("{}/{}", parts[0], parts[1]))
        } else {
            None
        }
    } else {
        parts.first().map(|s| s.to_string())
    }
}

impl ImportIndex {
    fn index_js(&mut self, file: &str, content: &str) {
        for caps in js_re().captures_iter(content) {
            if let Some(pkg) = js_package(&caps[1]) {
                self.npm.entry(pkg).or_insert_with(|| file.to_string());
            }
        }
    }

    fn index_rust(&mut self, content: &str) {
        for caps in rust_use_re().captures_iter(content) {
            self.rust.insert(caps[1].to_string());
        }
        for caps in rust_path_re().captures_iter(content) {
            self.rust.insert(caps[1].to_string());
        }
    }

    fn index_go(&mut self, file: &str, content: &str) {
        let mut in_block = false;
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("import (") {
                in_block = true;
                continue;
            }
            if in_block {
                if t == ")" {
                    in_block = false;
                    continue;
                }
                if let Some(p) = quoted(t) {
                    self.go.push((p, file.to_string()));
                }
            } else if t.starts_with("import ") {
                if let Some(p) = quoted(t) {
                    self.go.push((p, file.to_string()));
                }
            }
        }
    }
}

fn quoted(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ---- classification (pure) ----

/// Classify each dependency against the discovered imports.
pub fn classify(deps: &[Dependency], index: &ImportIndex) -> Vec<DepUsage> {
    deps.iter()
        .map(|d| {
            let base = |reach, evidence| DepUsage {
                name: d.name.clone(),
                ecosystem: d.ecosystem.label().to_string(),
                direct: d.direct,
                reach,
                evidence,
            };
            // Dev/peer/transitive deps aren't expected to be imported directly.
            if !d.direct {
                return base(Reach::Dev, None);
            }
            // `@types/*` packages are consumed by the TypeScript compiler, never imported at a call
            // site — treat them as dev/implicit rather than falsely "unused".
            if matches!(d.ecosystem, Ecosystem::Npm) && d.name.starts_with("@types/") {
                return base(Reach::Dev, None);
            }
            let usage = match d.ecosystem {
                Ecosystem::Npm => {
                    let e = index.npm.get(&d.name).cloned();
                    Some((e.is_some(), e))
                }
                Ecosystem::Cargo => {
                    // Crate path roots use underscores.
                    Some((index.rust.contains(&d.name.replace('-', "_")), None))
                }
                Ecosystem::Go => {
                    let prefix = format!("{}/", d.name);
                    let hit = index
                        .go
                        .iter()
                        .find(|(p, _)| *p == d.name || p.starts_with(&prefix));
                    Some((hit.is_some(), hit.map(|(_, f)| f.clone())))
                }
                // No source-import scanner wired for these ecosystems yet.
                Ecosystem::PyPI
                | Ecosystem::Ruby
                | Ecosystem::Php
                | Ecosystem::Maven
                | Ecosystem::NuGet => None,
            };
            match usage {
                Some((used, ev)) => base(if used { Reach::Used } else { Reach::Unused }, ev),
                None => base(Reach::Unscanned, None),
            }
        })
        .collect()
}

// ---- walker (I/O) ----

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

/// Walk `root` and index every source import into an [`ImportIndex`].
pub fn scan_imports(root: &Path) -> ImportIndex {
    let mut idx = ImportIndex::default();
    walk(root, root, &mut idx);
    idx
}

/// Convenience: scan `root` and classify `deps` in one call.
pub fn analyze(root: &Path, deps: &[Dependency]) -> Vec<DepUsage> {
    classify(deps, &scan_imports(root))
}

fn walk(root: &Path, dir: &Path, idx: &mut ImportIndex) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue;
        }
        let p = e.path();
        if p.is_dir() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(root, &p, idx);
        } else if p.is_file() {
            index_file(root, &p, idx);
        }
    }
}

fn index_file(root: &Path, path: &Path, idx: &mut ImportIndex) {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e,
        None => return,
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    match ext {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => {
            if let Ok(c) = std::fs::read_to_string(path) {
                idx.index_js(&rel, &c);
            }
        }
        "rs" => {
            if let Ok(c) = std::fs::read_to_string(path) {
                idx.index_rust(&c);
            }
        }
        "go" => {
            if let Ok(c) = std::fs::read_to_string(path) {
                idx.index_go(&rel, &c);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, eco: Ecosystem, direct: bool) -> Dependency {
        Dependency {
            name: name.into(),
            requested: None,
            ecosystem: eco,
            direct,
        }
    }

    #[test]
    fn js_package_extraction() {
        assert_eq!(js_package("lodash").as_deref(), Some("lodash"));
        assert_eq!(js_package("lodash/fp").as_deref(), Some("lodash"));
        assert_eq!(js_package("@scope/pkg/sub").as_deref(), Some("@scope/pkg"));
        assert_eq!(js_package("./local"), None);
    }

    #[test]
    fn classifies_used_unused_and_dev() {
        let mut idx = ImportIndex::default();
        idx.index_js(
            "src/app.js",
            "import _ from 'lodash';\nconst x = require('@scope/pkg');\n",
        );
        let deps = vec![
            dep("lodash", Ecosystem::Npm, true),     // imported -> used
            dep("@scope/pkg", Ecosystem::Npm, true), // imported -> used
            dep("left-pad", Ecosystem::Npm, true),   // runtime, not imported -> unused
            dep("jest", Ecosystem::Npm, false),      // dev -> dev
        ];
        let out = classify(&deps, &idx);
        let by = |n: &str| out.iter().find(|u| u.name == n).unwrap().reach;
        assert_eq!(by("lodash"), Reach::Used);
        assert_eq!(by("@scope/pkg"), Reach::Used);
        assert_eq!(by("left-pad"), Reach::Unused);
        assert_eq!(by("jest"), Reach::Dev);
    }

    #[test]
    fn types_packages_are_never_unused() {
        let idx = ImportIndex::default();
        let deps = vec![dep("@types/leaflet", Ecosystem::Npm, true)];
        // Even as a runtime dep with no imports, @types/* is dev/implicit, not unused.
        assert_eq!(classify(&deps, &idx)[0].reach, Reach::Dev);
    }

    #[test]
    fn rust_and_go_membership() {
        let mut idx = ImportIndex::default();
        idx.index_rust("use serde_json::Value;\nfn f() { anyhow::bail!(); }\n");
        idx.index_go(
            "main.go",
            "import (\n  \"github.com/gin-gonic/gin\"\n  \"fmt\"\n)\n",
        );
        let deps = vec![
            dep("serde-json", Ecosystem::Cargo, true), // `-` normalizes to `_`
            dep("anyhow", Ecosystem::Cargo, true),
            dep("unused-crate", Ecosystem::Cargo, true),
            dep("github.com/gin-gonic/gin", Ecosystem::Go, true),
            dep("github.com/unused/mod", Ecosystem::Go, true),
        ];
        let out = classify(&deps, &idx);
        let by = |n: &str| out.iter().find(|u| u.name == n).unwrap().reach;
        assert_eq!(by("serde-json"), Reach::Used);
        assert_eq!(by("anyhow"), Reach::Used);
        assert_eq!(by("unused-crate"), Reach::Unused);
        assert_eq!(by("github.com/gin-gonic/gin"), Reach::Used);
        assert_eq!(by("github.com/unused/mod"), Reach::Unused);
    }
}
