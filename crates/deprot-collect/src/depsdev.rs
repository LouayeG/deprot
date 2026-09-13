//! Client for the [deps.dev](https://deps.dev) v3 API — Google's Open Source Insights service.
//!
//! deps.dev is the workhorse behind deprot: a single, unauthenticated, rate-limit-friendly API
//! that aggregates release metadata, licenses, security advisories, linked source repositories,
//! and OpenSSF Scorecard results across npm, crates.io, PyPI and more. No key required.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use deprot_core::{Facts, Vuln};
use reqwest::Client;
use serde::Deserialize;

const BASE: &str = "https://api.deps.dev/v3";

/// Thin async client over the deps.dev v3 API.
#[derive(Clone)]
pub struct DepsDev {
    http: Client,
}

// ---- wire types (only the fields deprot consumes) ----

#[derive(Deserialize)]
struct PackageResp {
    #[serde(default)]
    versions: Vec<VersionEntry>,
}

#[derive(Deserialize)]
struct VersionEntry {
    #[serde(rename = "versionKey")]
    version_key: VersionKey,
    #[serde(rename = "publishedAt")]
    published_at: Option<DateTime<Utc>>,
    #[serde(rename = "isDefault", default)]
    is_default: bool,
}

#[derive(Deserialize)]
struct VersionKey {
    version: String,
}

#[derive(Deserialize)]
struct VersionResp {
    #[serde(default)]
    licenses: Vec<String>,
    #[serde(rename = "advisoryKeys", default)]
    advisory_keys: Vec<AdvisoryKey>,
    #[serde(rename = "isDeprecated", default)]
    is_deprecated: bool,
    #[serde(rename = "deprecatedReason", default)]
    deprecated_reason: String,
    #[serde(rename = "relatedProjects", default)]
    related_projects: Vec<RelatedProject>,
}

#[derive(Deserialize)]
struct AdvisoryKey {
    id: String,
}

#[derive(Deserialize)]
struct RelatedProject {
    #[serde(rename = "projectKey")]
    project_key: ProjectKey,
    #[serde(rename = "relationType", default)]
    relation_type: String,
}

#[derive(Deserialize)]
struct ProjectKey {
    id: String,
}

#[derive(Deserialize)]
struct AdvisoryResp {
    title: Option<String>,
    #[serde(rename = "cvss3Score")]
    cvss3_score: Option<f64>,
}

#[derive(Deserialize)]
struct ProjectResp {
    #[serde(rename = "openIssuesCount")]
    open_issues_count: Option<u64>,
    #[serde(rename = "starsCount")]
    stars_count: Option<u64>,
    scorecard: Option<Scorecard>,
}

#[derive(Deserialize)]
struct Scorecard {
    #[serde(rename = "overallScore")]
    overall_score: Option<f64>,
    #[serde(default)]
    checks: Vec<ScorecardCheck>,
}

#[derive(Deserialize)]
struct ScorecardCheck {
    name: String,
    score: Option<f64>,
}

impl DepsDev {
    /// Build a client sharing the given HTTP handle (so connection pooling is shared).
    pub fn new(http: Client) -> Self {
        DepsDev { http }
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<Option<T>> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp
            .error_for_status()
            .with_context(|| format!("GET {url}"))?;
        Ok(Some(
            resp.json::<T>()
                .await
                .with_context(|| format!("decoding {url}"))?,
        ))
    }

    /// Fetch the full release timeline `(version, published_at)` for a package, oldest first.
    pub async fn version_timeline(
        &self,
        system: &str,
        name: &str,
    ) -> Result<Vec<(String, DateTime<Utc>)>> {
        let enc = urlencode(name);
        let pkg: Option<PackageResp> = self
            .get_json(&format!("{BASE}/systems/{system}/packages/{enc}"))
            .await?;
        let mut out: Vec<(String, DateTime<Utc>)> = pkg
            .map(|p| {
                p.versions
                    .into_iter()
                    .filter_map(|e| e.published_at.map(|d| (e.version_key.version, d)))
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by_key(|(_, d)| *d);
        Ok(out)
    }

    /// Collect everything deprot knows about one package into [`Facts`].
    ///
    /// Strategy: fetch the package's version list (staleness, cadence, which version is default),
    /// then a specific version's detail (licenses, advisories, linked repo), then enrich with
    /// advisory severities and — if a source repo is linked — its OpenSSF Scorecard and repo stats.
    /// When `pin` is `Some`, that exact version is analyzed (used for lockfile-resolved trees);
    /// otherwise the registry default (else newest) version is used.
    pub async fn collect(
        &self,
        system: &str,
        name: &str,
        pin: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Facts> {
        let mut facts = Facts::default();
        let enc = urlencode(name);

        // 1. Version list.
        let pkg: Option<PackageResp> = self
            .get_json(&format!("{BASE}/systems/{system}/packages/{enc}"))
            .await?;
        let Some(pkg) = pkg else {
            // Unknown package (e.g. a local/workspace crate): return empty facts.
            return Ok(facts);
        };

        facts.total_versions = Some(pkg.versions.len() as u32);
        facts.latest_published = pkg.versions.iter().filter_map(|v| v.published_at).max();
        let year_ago = now - Duration::days(365);
        facts.releases_last_year = Some(
            pkg.versions
                .iter()
                .filter(|v| v.published_at.map(|p| p >= year_ago).unwrap_or(false))
                .count() as u32,
        );

        // Choose the version to analyze: the pinned one if given, else the registry's default,
        // else the newest by date.
        let chosen = pin.map(|p| p.to_string()).or_else(|| {
            pkg.versions
                .iter()
                .find(|v| v.is_default)
                .or_else(|| {
                    pkg.versions
                        .iter()
                        .max_by_key(|v| v.published_at.unwrap_or(DateTime::<Utc>::MIN_UTC))
                })
                .map(|v| v.version_key.version.clone())
        });

        let Some(version) = chosen else {
            return Ok(facts);
        };
        facts.analyzed_version = Some(version.clone());

        // 2. Version detail.
        let venc = urlencode(&version);
        if let Some(vr) = self
            .get_json::<VersionResp>(&format!(
                "{BASE}/systems/{system}/packages/{enc}/versions/{venc}"
            ))
            .await?
        {
            facts.licenses = vr.licenses;
            facts.deprecated = vr.is_deprecated;
            if !vr.deprecated_reason.is_empty() {
                facts.deprecated_reason = Some(vr.deprecated_reason);
            }
            facts.repo = pick_repo(&vr.related_projects);

            // 3. Advisory severities.
            for key in &vr.advisory_keys {
                if let Some(adv) = self
                    .get_json::<AdvisoryResp>(&format!("{BASE}/advisories/{}", urlencode(&key.id)))
                    .await?
                {
                    facts.vulns.push(Vuln {
                        id: key.id.clone(),
                        cvss: adv.cvss3_score,
                        title: adv.title,
                        reference: Some(format!("https://osv.dev/vulnerability/{}", key.id)),
                        ..Default::default()
                    });
                } else {
                    facts.vulns.push(Vuln {
                        id: key.id.clone(),
                        reference: Some(format!("https://osv.dev/vulnerability/{}", key.id)),
                        ..Default::default()
                    });
                }
            }
        }

        // 4. Source-repo enrichment (Scorecard + stats).
        if let Some(repo) = facts.repo.clone() {
            if let Some(proj) = self
                .get_json::<ProjectResp>(&format!("{BASE}/projects/{}", urlencode(&repo)))
                .await?
            {
                facts.stars = proj.stars_count;
                facts.open_issues = proj.open_issues_count;
                if let Some(sc) = proj.scorecard {
                    facts.scorecard_overall = sc.overall_score;
                    facts.scorecard_maintained = sc
                        .checks
                        .iter()
                        .find(|c| c.name == "Maintained")
                        .and_then(|c| c.score);
                }
            }
        }

        Ok(facts)
    }
}

/// Pick the best source-repo id from a version's related projects, preferring the declared
/// SOURCE_REPO relation but accepting any linked project as a fallback.
fn pick_repo(related: &[RelatedProject]) -> Option<String> {
    related
        .iter()
        .find(|r| r.relation_type == "SOURCE_REPO")
        .or_else(|| related.first())
        .map(|r| r.project_key.id.clone())
}

/// Percent-encode a path segment. deps.dev wants scoped npm names (`@scope/pkg`) and project ids
/// (`github.com/owner/repo`) encoded so their `@` and `/` don't break the path.
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
