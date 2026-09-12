//! npm `package.json` parser.
//!
//! Reads the four standard dependency maps. `dependencies` and `optionalDependencies` are treated
//! as direct runtime deps; `devDependencies` and `peerDependencies` are flagged non-direct so the
//! report can distinguish "ships to production" from "build/test only".

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Parser for npm `package.json` files.
pub struct NpmManifest;

#[derive(Deserialize, Default)]
struct PackageJson {
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, String>,
}

impl Manifest for NpmManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let pkg: PackageJson = serde_json::from_str(contents)?;
        let mut deps: BTreeMap<String, Dependency> = BTreeMap::new();

        let mut add = |name: &str, req: &str, direct: bool| {
            // A name appearing in multiple maps keeps the "most direct" classification.
            deps.entry(name.to_string())
                .and_modify(|d| d.direct = d.direct || direct)
                .or_insert(Dependency {
                    name: name.to_string(),
                    requested: Some(req.to_string()),
                    ecosystem: Ecosystem::Npm,
                    direct,
                });
        };

        for (name, req) in &pkg.dependencies {
            add(name, req, true);
        }
        for (name, req) in &pkg.optional_dependencies {
            add(name, req, true);
        }
        for (name, req) in &pkg.dev_dependencies {
            add(name, req, false);
        }
        for (name, req) in &pkg.peer_dependencies {
            add(name, req, false);
        }

        Ok(deps.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_dependency_maps() {
        let json = r#"{
            "name": "demo",
            "dependencies": { "lodash": "^4.17.21", "express": "4.18.2" },
            "devDependencies": { "jest": "^29.0.0" },
            "peerDependencies": { "react": ">=18" }
        }"#;
        let deps = NpmManifest.parse(json).unwrap();
        assert_eq!(deps.len(), 4);
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.requested.as_deref(), Some("^4.17.21"));
        assert!(lodash.direct);
        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert!(!jest.direct);
    }

    #[test]
    fn empty_manifest_is_ok() {
        let deps = NpmManifest.parse(r#"{"name":"x"}"#).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn direct_wins_over_dev_for_duplicates() {
        let json = r#"{
            "dependencies": { "typescript": "^5.0.0" },
            "devDependencies": { "typescript": "^5.0.0" }
        }"#;
        let deps = NpmManifest.parse(json).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(deps[0].direct);
    }
}
