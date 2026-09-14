//! Maven `pom.xml` parser.
//!
//! Extracts `<dependency>` coordinates as `groupId:artifactId` names with their `<version>` (the form
//! OSV and deps.dev expect for the Maven ecosystem). Dependencies scoped `test` or `provided` are
//! treated as dev (`direct = false`). Versions given as an unresolved property placeholder
//! (`${spring.version}`) are dropped to `None` — deps.dev then resolves the default version. Uses a
//! lightweight tag scan rather than a full XML parser, which is enough for well-formed POMs.

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};
use regex::Regex;
use std::sync::OnceLock;

/// Parser for Maven `pom.xml` files.
pub struct MavenManifest;

fn dep_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<dependency>(.*?)</dependency>").expect("valid regex"))
}

fn tag_value(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    Some(block[start..end].trim().to_string())
}

impl Manifest for MavenManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let mut deps = Vec::new();
        for cap in dep_block_re().captures_iter(contents) {
            let block = &cap[1];
            let (Some(group), Some(artifact)) =
                (tag_value(block, "groupId"), tag_value(block, "artifactId"))
            else {
                continue;
            };
            let version = tag_value(block, "version").filter(|v| !v.contains("${"));
            let scope = tag_value(block, "scope").unwrap_or_default();
            let dev = matches!(scope.as_str(), "test" | "provided" | "system");
            deps.push(Dependency {
                name: format!("{group}:{artifact}"),
                requested: version,
                ecosystem: Ecosystem::Maven,
                direct: !dev,
            });
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_coordinates_scope_and_property_versions() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.2-jre</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>"#;
        let deps = MavenManifest.parse(pom).unwrap();
        assert_eq!(deps.len(), 3);

        let guava = deps
            .iter()
            .find(|d| d.name == "com.google.guava:guava")
            .unwrap();
        assert_eq!(guava.requested.as_deref(), Some("32.1.2-jre"));
        assert!(guava.direct);

        let spring = deps
            .iter()
            .find(|d| d.name == "org.springframework:spring-core")
            .unwrap();
        assert_eq!(spring.requested, None, "property version dropped");

        let junit = deps.iter().find(|d| d.name == "junit:junit").unwrap();
        assert!(!junit.direct, "test scope is dev");
    }
}
