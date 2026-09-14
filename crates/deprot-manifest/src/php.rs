//! PHP `composer.json` parser.
//!
//! Reads the `require` and `require-dev` maps. Platform packages — `php` itself and the `ext-*` /
//! `lib-*` pseudo-packages — are not on Packagist and are skipped. `require-dev` entries are dev
//! dependencies (`direct = false`). Exact versions live in `composer.lock` (parsed by the lockfile
//! layer); deps.dev does not index Packagist, so PHP vulnerabilities come from OSV.

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Parser for PHP `composer.json` files.
pub struct PhpManifest;

#[derive(Deserialize, Default)]
struct ComposerJson {
    #[serde(default)]
    require: BTreeMap<String, String>,
    #[serde(default, rename = "require-dev")]
    require_dev: BTreeMap<String, String>,
}

/// A platform / pseudo package that isn't a real Packagist dependency.
fn is_platform(name: &str) -> bool {
    name == "php"
        || name.starts_with("ext-")
        || name.starts_with("lib-")
        || name.starts_with("php-")
        || name == "composer"
        || name.starts_with("composer-")
}

impl Manifest for PhpManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Php
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let doc: ComposerJson = serde_json::from_str(contents)?;
        let mut deps = Vec::new();
        let mut push = |name: String, req: String, direct: bool| {
            if is_platform(&name) {
                return;
            }
            deps.push(Dependency {
                name,
                requested: Some(req),
                ecosystem: Ecosystem::Php,
                direct,
            });
        };
        for (name, req) in doc.require {
            push(name, req, true);
        }
        for (name, req) in doc.require_dev {
            push(name, req, false);
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_require_and_skips_platform() {
        let json = r#"{
            "require": {
                "php": ">=8.1",
                "ext-json": "*",
                "monolog/monolog": "^3.0",
                "guzzlehttp/guzzle": "^7.5"
            },
            "require-dev": {
                "phpunit/phpunit": "^10.0"
            }
        }"#;
        let deps = PhpManifest.parse(json).unwrap();
        assert_eq!(deps.len(), 3, "php + ext-json skipped: {deps:?}");

        let mono = deps.iter().find(|d| d.name == "monolog/monolog").unwrap();
        assert_eq!(mono.requested.as_deref(), Some("^3.0"));
        assert!(mono.direct);

        let phpunit = deps.iter().find(|d| d.name == "phpunit/phpunit").unwrap();
        assert!(!phpunit.direct, "require-dev is not direct");
    }
}
