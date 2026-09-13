//! Go module (`go.mod`) parser.
//!
//! Reads `require` directives — both the single-line form and the parenthesized block. A dependency
//! flagged `// indirect` is transitive; everything else is a direct requirement. Module paths (e.g.
//! `github.com/gin-gonic/gin`) are used verbatim as the package name, which is exactly what deps.dev
//! expects for the `go` system. `replace`/`exclude`/`retract` directives are ignored.

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};
use std::collections::BTreeMap;

/// Parser for Go `go.mod` files.
pub struct GoManifest;

impl Manifest for GoManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let mut deps: BTreeMap<String, Dependency> = BTreeMap::new();
        let mut in_require_block = false;

        let add = |entry: &str, indirect: bool, deps: &mut BTreeMap<String, Dependency>| {
            let mut parts = entry.split_whitespace();
            let Some(path) = parts.next() else {
                return;
            };
            let version = parts.next().map(str::to_string);
            deps.entry(path.to_string())
                .and_modify(|d| d.direct = d.direct || !indirect)
                .or_insert(Dependency {
                    name: path.to_string(),
                    requested: version,
                    ecosystem: Ecosystem::Go,
                    direct: !indirect,
                });
        };

        for raw in contents.lines() {
            let indirect = raw.contains("// indirect");
            // Drop any trailing line comment before tokenizing.
            let line = raw.split("//").next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            if in_require_block {
                if line == ")" {
                    in_require_block = false;
                } else {
                    add(line, indirect, &mut deps);
                }
                continue;
            }

            if line == "require (" || line.starts_with("require (") {
                in_require_block = true;
            } else if let Some(rest) = line.strip_prefix("require ") {
                add(rest.trim(), indirect, &mut deps);
            }
            // module / go / toolchain / replace / exclude / retract: ignored.
        }

        Ok(deps.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_and_single_require_with_indirect() {
        let go_mod = r#"
module example.com/app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/sys v0.10.0 // indirect
    github.com/pkg/errors v0.9.1
)

require github.com/spf13/cobra v1.7.0
"#;
        let deps = GoManifest.parse(go_mod).unwrap();
        assert_eq!(deps.len(), 4);

        let gin = deps
            .iter()
            .find(|d| d.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin.requested.as_deref(), Some("v1.9.1"));
        assert!(gin.direct);

        let sys = deps.iter().find(|d| d.name == "golang.org/x/sys").unwrap();
        assert!(!sys.direct, "// indirect marks a transitive dep");

        let cobra = deps
            .iter()
            .find(|d| d.name == "github.com/spf13/cobra")
            .unwrap();
        assert!(cobra.direct, "single-line require is direct");
    }

    #[test]
    fn ignores_replace_and_module_directives() {
        let go_mod = r#"
module example.com/app
go 1.22
require github.com/google/uuid v1.6.0
replace github.com/google/uuid => ../local-uuid
exclude github.com/bad/mod v1.0.0
"#;
        let deps = GoManifest.parse(go_mod).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/google/uuid");
    }
}
