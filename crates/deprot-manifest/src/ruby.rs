//! Ruby `Gemfile` parser.
//!
//! Reads `gem "name", "~> 1.2"` declarations. Gems inside a `group :development`/`:test` block (or
//! declared with `group:` set to one of those) are treated as dev dependencies (`direct = false`),
//! matching how deprot handles dev deps elsewhere. The exact resolved versions live in `Gemfile.lock`
//! (parsed by the lockfile layer); the Gemfile itself yields the requirement strings.

use crate::Manifest;
use anyhow::Result;
use deprot_core::{Dependency, Ecosystem};

/// Parser for Ruby `Gemfile` files.
pub struct RubyManifest;

impl Manifest for RubyManifest {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Ruby
    }

    fn parse(&self, contents: &str) -> Result<Vec<Dependency>> {
        let mut deps = Vec::new();
        let mut dev_group_depth: u32 = 0;

        for raw in contents.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            // Track `group :development do ... end` blocks so their gems become dev deps.
            if let Some(rest) = line.strip_prefix("group ") {
                if rest.trim_end().ends_with("do") && mentions_dev(rest) {
                    dev_group_depth += 1;
                    continue;
                }
            }
            if line == "end" && dev_group_depth > 0 {
                dev_group_depth -= 1;
                continue;
            }

            let Some(rest) = line.strip_prefix("gem ") else {
                continue;
            };
            let quoted = quoted_strings(rest);
            let Some(name) = quoted.first().cloned() else {
                continue;
            };
            // A second quoted string that carries a digit is a version requirement (not an option).
            let requested = quoted
                .get(1)
                .filter(|s| s.chars().any(|c| c.is_ascii_digit()))
                .cloned();
            // Inline `group:` on the gem line also marks a dev dependency.
            let dev = dev_group_depth > 0 || (rest.contains("group:") && mentions_dev(rest));
            deps.push(Dependency {
                name,
                requested,
                ecosystem: Ecosystem::Ruby,
                direct: !dev,
            });
        }

        Ok(deps)
    }
}

/// Whether a fragment references the development or test groups.
fn mentions_dev(s: &str) -> bool {
    s.contains(":development") || s.contains(":test")
}

/// Extract the contents of every single- or double-quoted string in a fragment, in order.
fn quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j <= bytes.len() {
                out.push(s[start..j.min(bytes.len())].to_string());
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gems_versions_and_dev_groups() {
        let gemfile = r#"
source "https://rubygems.org"

gem "rails", "~> 7.0"
gem 'puma', require: false
gem "nokogiri"

group :development, :test do
  gem "rspec-rails", "6.0.1"
end

gem "sidekiq", "7.1", group: :test
"#;
        let deps = RubyManifest.parse(gemfile).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();

        assert_eq!(get("rails").requested.as_deref(), Some("~> 7.0"));
        assert!(get("rails").direct);
        assert_eq!(
            get("puma").requested,
            None,
            "require:false is not a version"
        );
        assert!(get("puma").direct);
        assert!(!get("rspec-rails").direct, "inside dev group");
        assert_eq!(get("rspec-rails").requested.as_deref(), Some("6.0.1"));
        assert!(!get("sidekiq").direct, "inline group: :test");
    }
}
