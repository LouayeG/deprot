//! NuGet parser for `.csproj` (SDK-style `<PackageReference>`) and legacy `packages.config`.
//!
//! `<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />` and its child-element form are
//! both read, as is `<package id="..." version="..." />` from `packages.config`. Package ids are
//! used verbatim (the form OSV and deps.dev expect for the NuGet ecosystem). Versions given as an
//! MSBuild property placeholder (`$(JsonVersion)`) drop to `None`.

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};
use regex::Regex;
use std::sync::OnceLock;

/// Parser for NuGet project files (`.csproj`) and `packages.config`.
pub struct NuGetManifest;

fn package_reference_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Matches <PackageReference Include="X" Version="Y" .../> and <package id="X" version="Y" />,
        // with attributes in either order (Version optional -> resolved via deps.dev).
        Regex::new(r#"(?is)<(?:PackageReference|package)\s+([^>]*?)/?>"#).expect("valid regex")
    })
}

fn attr(attrs: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"(?i)\b{name}\s*=\s*"([^"]*)""#)).ok()?;
    re.captures(attrs).map(|c| c[1].trim().to_string())
}

impl Manifest for NuGetManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let mut deps = Vec::new();
        for cap in package_reference_re().captures_iter(contents) {
            let attrs = &cap[1];
            // `Include` (csproj) or `id` (packages.config) carries the package id.
            let Some(name) = attr(attrs, "Include").or_else(|| attr(attrs, "id")) else {
                continue;
            };
            let version = attr(attrs, "Version")
                .or_else(|| attr(attrs, "version"))
                .filter(|v| !v.contains("$("));
            deps.push(Dependency {
                name,
                requested: version,
                ecosystem: Ecosystem::NuGet,
                direct: true,
            });
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csproj_package_references() {
        let csproj = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
    <PackageReference Include="Dapper" />
  </ItemGroup>
</Project>"#;
        let deps = NuGetManifest.parse(csproj).unwrap();
        assert_eq!(deps.len(), 3);
        let json = deps.iter().find(|d| d.name == "Newtonsoft.Json").unwrap();
        assert_eq!(json.requested.as_deref(), Some("13.0.1"));
        let serilog = deps.iter().find(|d| d.name == "Serilog").unwrap();
        assert_eq!(serilog.requested, None, "MSBuild property dropped");
        let dapper = deps.iter().find(|d| d.name == "Dapper").unwrap();
        assert_eq!(dapper.requested, None, "no version -> resolved later");
    }

    #[test]
    fn parses_legacy_packages_config() {
        let cfg = r#"<?xml version="1.0"?>
<packages>
  <package id="EntityFramework" version="6.4.4" targetFramework="net48" />
  <package id="NUnit" version="3.13.3" />
</packages>"#;
        let deps = NuGetManifest.parse(cfg).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "EntityFramework")
                .unwrap()
                .requested
                .as_deref(),
            Some("6.4.4")
        );
    }
}
