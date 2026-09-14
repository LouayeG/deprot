//! Python manifest parsers: `requirements.txt` and `pyproject.toml` (both PEP 621 `[project]` and
//! Poetry `[tool.poetry]`).
//!
//! Package names are PEP 503-normalized (lowercased, runs of `-_.` collapsed to `-`) so they resolve
//! against deps.dev / OSV. Version requirements are kept verbatim for display. `requirements.txt`
//! option lines (`-r`, `-e`, `--hash`, …), URLs/VCS installs, and environment markers are skipped.

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};
use serde::Deserialize;
use std::collections::BTreeMap;

/// PEP 503 canonical name: lowercase, collapse runs of `-`, `_`, `.` to a single `-`.
fn canon(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.trim().chars() {
        if c == '-' || c == '_' || c == '.' {
            if !prev_sep && !out.is_empty() {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out.trim_end_matches('-').to_string()
}

/// Split a PEP 508 requirement into `(name, version-spec)`. The name ends at the first character
/// that isn't part of a package name; the remainder (before any extras / marker) is the spec.
fn split_req(req: &str) -> Option<(String, Option<String>)> {
    let s = req.trim();
    if s.is_empty() {
        return None;
    }
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .unwrap_or(s.len());
    let name = &s[..end];
    if name.is_empty() {
        return None;
    }
    // Everything after the name: optional extras `[...]`, then a version spec, then an env marker.
    let mut rest = s[end..].trim_start();
    if rest.starts_with('[') {
        if let Some(i) = rest.find(']') {
            rest = rest[i + 1..].trim_start();
        }
    }
    let rest = rest.split(';').next().unwrap_or("").trim(); // drop environment marker
    let rest = rest.trim_start_matches('(').trim_end_matches(')').trim(); // PEP 508 `(>=x)`
    let spec = if rest.chars().any(|c| c.is_ascii_digit()) {
        Some(rest.to_string())
    } else {
        None
    };
    Some((canon(name), spec))
}

/// Parser for `requirements.txt`.
pub struct RequirementsManifest;

impl Manifest for RequirementsManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let mut deps = Vec::new();
        for raw in contents.lines() {
            // Strip inline comments (must be preceded by whitespace per PEP 508, but be lenient).
            let line = raw.split(" #").next().unwrap_or("").trim();
            let line = if line.starts_with('#') { "" } else { line };
            if line.is_empty() {
                continue;
            }
            // Skip pip options (-r/-e/-c/--hash/…) and direct URL / VCS installs.
            if line.starts_with('-')
                || line.contains("://")
                || line.starts_with("git+")
                || line.starts_with("file:")
            {
                continue;
            }
            if let Some((name, spec)) = split_req(line) {
                deps.push(Dependency {
                    name,
                    requested: spec,
                    ecosystem: Ecosystem::PyPI,
                    direct: true,
                });
            }
        }
        Ok(deps)
    }
}

/// Parser for `pyproject.toml` (PEP 621 and Poetry).
pub struct PyprojectManifest;

#[derive(Deserialize, Default)]
struct Pyproject {
    #[serde(default)]
    project: Option<Project>,
    #[serde(default)]
    tool: Option<Tool>,
}

#[derive(Deserialize, Default)]
struct Project {
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize, Default)]
struct Tool {
    #[serde(default)]
    poetry: Option<Poetry>,
}

#[derive(Deserialize, Default)]
struct Poetry {
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default)]
    group: BTreeMap<String, PoetryGroup>,
}

#[derive(Deserialize, Default)]
struct PoetryGroup {
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
}

impl Manifest for PyprojectManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let doc: Pyproject = toml::from_str(contents)?;
        let mut deps: Vec<Dependency> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut push = |name: String, requested: Option<String>, direct: bool| {
            if name.is_empty() || !seen.insert(name.clone()) {
                return;
            }
            deps.push(Dependency {
                name,
                requested,
                ecosystem: Ecosystem::PyPI,
                direct,
            });
        };

        // PEP 621.
        if let Some(p) = &doc.project {
            for req in &p.dependencies {
                if let Some((n, s)) = split_req(req) {
                    push(n, s, true);
                }
            }
            for reqs in p.optional_dependencies.values() {
                for req in reqs {
                    if let Some((n, s)) = split_req(req) {
                        push(n, s, false); // extras are optional, not core runtime deps
                    }
                }
            }
        }

        // Poetry.
        if let Some(poetry) = doc.tool.as_ref().and_then(|t| t.poetry.as_ref()) {
            let ver = |v: &toml::Value| v.as_str().map(str::to_string);
            for (name, v) in &poetry.dependencies {
                if name.eq_ignore_ascii_case("python") {
                    continue; // the interpreter constraint, not a package
                }
                push(canon(name), ver(v), true);
            }
            for (name, v) in &poetry.dev_dependencies {
                push(canon(name), ver(v), false);
            }
            for grp in poetry.group.values() {
                for (name, v) in &grp.dependencies {
                    push(canon(name), ver(v), false);
                }
            }
        }

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canon_normalizes_pep503() {
        assert_eq!(canon("Flask_SQLAlchemy"), "flask-sqlalchemy");
        assert_eq!(canon("zope.interface"), "zope-interface");
        assert_eq!(canon("Django"), "django");
    }

    #[test]
    fn requirements_txt_parses_and_skips_noise() {
        let txt = r#"
# a comment
Flask==2.0.1
requests>=2.25.0  # inline comment
urllib3 (>=1.21.1) ; python_version < '3.8'
uvicorn[standard]==0.23.0
-r base.txt
-e .
git+https://github.com/x/y.git#egg=y
https://example.com/pkg.whl
"#;
        let deps = RequirementsManifest.parse(txt).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["flask", "requests", "urllib3", "uvicorn"]);
        assert_eq!(deps[0].requested.as_deref(), Some("==2.0.1"));
        assert!(deps.iter().all(|d| d.direct));
    }

    #[test]
    fn pyproject_pep621() {
        let toml_src = r#"
[project]
name = "app"
dependencies = ["flask>=2.0", "requests"]
[project.optional-dependencies]
test = ["pytest>=7"]
"#;
        let deps = PyprojectManifest.parse(toml_src).unwrap();
        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert!(flask.direct);
        assert_eq!(flask.requested.as_deref(), Some(">=2.0"));
        assert!(!deps.iter().find(|d| d.name == "pytest").unwrap().direct);
    }

    #[test]
    fn pyproject_poetry() {
        let toml_src = r#"
[tool.poetry.dependencies]
python = "^3.11"
flask = "^2.0"
requests = { version = "^2.28", optional = true }
[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
"#;
        let deps = PyprojectManifest.parse(toml_src).unwrap();
        assert!(deps.iter().any(|d| d.name == "flask" && d.direct));
        assert!(deps.iter().any(|d| d.name == "requests"));
        assert!(!deps.iter().any(|d| d.name == "python"), "interpreter skipped");
        assert!(!deps.iter().find(|d| d.name == "pytest").unwrap().direct);
    }
}
