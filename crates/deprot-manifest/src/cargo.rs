//! Cargo `Cargo.toml` parser.
//!
//! Reads `[dependencies]`, `[dev-dependencies]` and `[build-dependencies]`. A dependency entry is
//! either a bare version string or a table; either way we take the crate name and version
//! requirement. Path and git dependencies (no `crates.io` presence) are skipped, since deprot can
//! only reason about published packages.

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};
use serde::Deserialize;
use std::collections::BTreeMap;
use toml::Value;

/// Parser for Rust `Cargo.toml` files.
pub struct CargoManifest;

#[derive(Deserialize, Default)]
struct CargoToml {
    #[serde(default)]
    dependencies: BTreeMap<String, Value>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, Value>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, Value>,
}

/// Extract a `(registry_name, requested)` pair from a dependency value, or `None` for a
/// path/git dependency that isn't published to crates.io.
fn resolve(name: &str, value: &Value) -> Option<(String, Option<String>)> {
    match value {
        // `serde = "1.0"`
        Value::String(req) => Some((name.to_string(), Some(req.clone()))),
        // `serde = { version = "1", package = "...", path = "...", git = "..." }`
        Value::Table(t) => {
            if t.contains_key("path") || t.contains_key("git") {
                return None; // not resolvable via crates.io
            }
            if t.get("workspace").and_then(Value::as_bool) == Some(true) {
                // Version is inherited from the workspace root; without resolving that we can't
                // reliably identify the crate, and internal members aren't on crates.io. Skip.
                return None;
            }
            // `package = "x"` renames the crate; the real registry name is `package`.
            let registry_name = t
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or(name)
                .to_string();
            let req = t.get("version").and_then(Value::as_str).map(String::from);
            Some((registry_name, req))
        }
        _ => Some((name.to_string(), None)),
    }
}

impl Manifest for CargoManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let parsed: CargoToml = toml::from_str(contents)?;
        let mut deps: BTreeMap<String, Dependency> = BTreeMap::new();

        let mut add = |name: &str, value: &Value, direct: bool| {
            if let Some((reg_name, req)) = resolve(name, value) {
                deps.entry(reg_name.clone())
                    .and_modify(|d| d.direct = d.direct || direct)
                    .or_insert(Dependency {
                        name: reg_name,
                        requested: req,
                        ecosystem: Ecosystem::Cargo,
                        direct,
                    });
            }
        };

        for (name, value) in &parsed.dependencies {
            add(name, value, true);
        }
        for (name, value) in &parsed.dev_dependencies {
            add(name, value, false);
        }
        for (name, value) in &parsed.build_dependencies {
            add(name, value, false);
        }

        Ok(deps.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_and_table_deps() {
        let toml = r#"
            [dependencies]
            serde = "1.0"
            tokio = { version = "1", features = ["full"] }

            [dev-dependencies]
            criterion = "0.5"
        "#;
        let deps = CargoManifest.parse(toml).unwrap();
        assert_eq!(deps.len(), 3);
        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.requested.as_deref(), Some("1.0"));
        assert!(serde.direct);
        let criterion = deps.iter().find(|d| d.name == "criterion").unwrap();
        assert!(!criterion.direct);
    }

    #[test]
    fn skips_path_and_git_deps() {
        let toml = r#"
            [dependencies]
            local = { path = "../local" }
            remote = { git = "https://example.com/x" }
            published = "2.0"
        "#;
        let deps = CargoManifest.parse(toml).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "published");
    }

    #[test]
    fn honors_package_rename() {
        let toml = r#"
            [dependencies]
            my-alias = { version = "1", package = "real-crate" }
        "#;
        let deps = CargoManifest.parse(toml).unwrap();
        assert_eq!(deps[0].name, "real-crate");
    }
}
