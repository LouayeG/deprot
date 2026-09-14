//! Registry enrichment: maintainer identities and install-script detection, from the package
//! registries themselves (npm registry, crates.io). Used only in `--deep` mode because it adds a
//! request per package on top of deps.dev. No API key required.

use anyhow::Result;
use deprot_core::{Ecosystem, Facts};
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Enrich `facts` in place with maintainer identities and (npm) install-script detection.
pub async fn enrich(
    http: &Client,
    ecosystem: Ecosystem,
    name: &str,
    facts: &mut Facts,
) -> Result<()> {
    match ecosystem {
        Ecosystem::Npm => enrich_npm(http, name, facts).await,
        Ecosystem::Cargo => enrich_crates(http, name, facts).await,
        // No keyless per-package maintainer feed wired for these yet — PyPI/RubyGems require auth,
        // Go has no registry, and Packagist/Maven/NuGet enrichment is future work.
        Ecosystem::PyPI
        | Ecosystem::Go
        | Ecosystem::Ruby
        | Ecosystem::Php
        | Ecosystem::Maven
        | Ecosystem::NuGet => Ok(()),
    }
}

#[derive(Deserialize)]
struct NpmDoc {
    #[serde(default)]
    maintainers: Vec<NpmPerson>,
    #[serde(rename = "dist-tags", default)]
    dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    versions: BTreeMap<String, NpmVersionDoc>,
}

#[derive(Deserialize)]
struct NpmPerson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
}

#[derive(Deserialize)]
struct NpmVersionDoc {
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

async fn enrich_npm(http: &Client, name: &str, facts: &mut Facts) -> Result<()> {
    let url = format!("https://registry.npmjs.org/{}", urlencode(name));
    let resp = http.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(());
    }
    let doc: NpmDoc = resp.json().await?;

    facts.maintainers = doc
        .maintainers
        .iter()
        .map(|m| {
            if !m.email.is_empty() {
                m.email.clone()
            } else {
                m.name.clone()
            }
        })
        .filter(|s| !s.is_empty())
        .collect();

    // Install scripts on the "latest" version (or the version we analyzed) = a code-exec vector.
    let target = facts
        .analyzed_version
        .clone()
        .or_else(|| doc.dist_tags.get("latest").cloned());
    if let Some(v) = target {
        if let Some(vd) = doc.versions.get(&v) {
            facts.has_install_script = vd
                .scripts
                .keys()
                .any(|k| matches!(k.as_str(), "preinstall" | "install" | "postinstall"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct CratesOwners {
    #[serde(default)]
    users: Vec<CratesUser>,
}

#[derive(Deserialize)]
struct CratesUser {
    #[serde(default)]
    login: String,
}

async fn enrich_crates(http: &Client, name: &str, facts: &mut Facts) -> Result<()> {
    let url = format!("https://crates.io/api/v1/crates/{}/owners", urlencode(name));
    let resp = http.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(());
    }
    let owners: CratesOwners = resp.json().await?;
    facts.maintainers = owners
        .users
        .into_iter()
        .map(|u| u.login)
        .filter(|s| !s.is_empty())
        .collect();
    Ok(())
}

/// Percent-encode a path segment (scoped npm names contain `@` and `/`).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
