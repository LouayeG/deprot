//! # deprot-collect
//!
//! The I/O layer: turns [`Dependency`] values into [`Facts`] by querying public data sources
//! (currently [deps.dev](https://deps.dev)). This is the only crate that touches the network.
//! Results are cached on disk ([`cache`]) and fetched with bounded concurrency so a large
//! manifest resolves quickly without flooding the API.
//!
//! Nothing here requires an API key. Every source deprot uses is free and public.

mod cache;
mod depsdev;
mod osv;
mod registry;

use chrono::Utc;
use deprot_core::{DepGraph, Dependency, Ecosystem, Facts};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;

pub use cache::Cache;

/// Runtime configuration for a collection pass.
#[derive(Clone)]
pub struct CollectorConfig {
    /// Maximum number of dependencies fetched concurrently.
    pub concurrency: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether the on-disk cache is used at all.
    pub cache_enabled: bool,
    /// Whether to enrich facts with registry data (maintainers + install scripts). Off by default
    /// because it adds a request per package.
    pub enrich: bool,
    /// Air-gapped mode: never touch the network; serve only from the on-disk cache.
    pub offline: bool,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        CollectorConfig {
            concurrency: 12,
            cache_ttl_secs: 24 * 60 * 60,
            cache_enabled: true,
            enrich: false,
            offline: false,
        }
    }
}

/// One dependency paired with the facts collected about it (or the error that prevented it).
pub struct Collected {
    /// The dependency that was analyzed.
    pub dependency: Dependency,
    /// Facts gathered from public sources. On a fetch error this falls back to
    /// [`Facts::default`] and `error` is set, so a single flaky lookup never aborts the run.
    pub facts: Facts,
    /// Set when collection failed and `facts` is a default placeholder.
    pub error: Option<String>,
}

/// Collects facts for dependencies from public data sources.
pub struct Collector {
    depsdev: depsdev::DepsDev,
    http: Client,
    cache: Arc<Cache>,
    config: CollectorConfig,
}

impl Collector {
    /// Build a collector with the given config.
    pub fn new(config: CollectorConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "deprot/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/LouayeG/deprot)"
            ))
            .timeout(Duration::from_secs(20))
            .build()?;
        let cache = Cache::open(config.cache_ttl_secs, config.cache_enabled);
        Ok(Collector {
            depsdev: depsdev::DepsDev::new(http.clone()),
            http,
            cache: Arc::new(cache),
            config,
        })
    }

    /// Collect facts for one package name at an optional pinned version, consulting the cache
    /// first. Returns just the facts (plus any error string).
    async fn fetch(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        pin: Option<&str>,
    ) -> (Facts, Option<String>) {
        let system = system_for(ecosystem);
        // Enriched facts are a superset, so they get a distinct cache namespace.
        let suffix = if self.config.enrich { "+deep" } else { "" };
        let base = match pin {
            Some(v) => format!("{name}@{v}{suffix}"),
            None => format!("{name}{suffix}"),
        };
        let ckey = cache::key(system, &base);
        if let Some(facts) = self.cache.get(&ckey) {
            return (facts, None);
        }
        // Air-gapped: never hit the network. A cache miss is reported, not fetched.
        if self.config.offline {
            return (
                Facts::default(),
                Some(format!("offline: no cached data for {name}")),
            );
        }
        match self.depsdev.collect(system, name, pin, Utc::now()).await {
            Ok(mut facts) => {
                // OSV is the primary vulnerability source (per-CVE aliases + fixed versions),
                // merged with any advisory deps.dev already found. Best-effort.
                osv::merge(&self.http, ecosystem, name, &mut facts).await;
                if self.config.enrich {
                    // Registry enrichment is best-effort; failures leave facts as-is.
                    let _ = registry::enrich(&self.http, ecosystem, name, &mut facts).await;
                }
                self.cache.put(&ckey, &facts);
                (facts, None)
            }
            Err(e) => (Facts::default(), Some(e.to_string())),
        }
    }

    /// Collect facts for a single dependency (analyzing its default/latest version).
    pub async fn collect_one(&self, dep: &Dependency) -> Collected {
        let (facts, error) = self.fetch(dep.ecosystem, &dep.name, None).await;
        Collected {
            dependency: dep.clone(),
            facts,
            error,
        }
    }

    /// Collect facts for many dependencies with bounded concurrency. Output order is not
    /// guaranteed to match input order; callers sort by score for display.
    pub async fn collect_all(&self, deps: &[Dependency]) -> Vec<Collected> {
        stream::iter(deps.iter())
            .map(|dep| self.collect_one(dep))
            .buffer_unordered(self.config.concurrency)
            .collect()
            .await
    }

    /// Collect facts for every node of a resolved dependency graph, at each node's *exact* locked
    /// version. Returns facts indexed to match `graph.nodes()`.
    pub async fn collect_graph(&self, graph: &DepGraph) -> Vec<GraphFacts> {
        let results = stream::iter(graph.nodes().iter().enumerate())
            .map(|(idx, node)| async move {
                let (facts, error) = self
                    .fetch(node.ecosystem, &node.name, Some(&node.version))
                    .await;
                GraphFacts {
                    index: idx,
                    facts,
                    error,
                }
            })
            .buffer_unordered(self.config.concurrency)
            .collect::<Vec<_>>()
            .await;
        let mut sorted = results;
        sorted.sort_by_key(|g| g.index);
        sorted
    }
}

impl Collector {
    /// Fetch a package's release timeline `(version, published_at)`, oldest first.
    pub async fn history(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> anyhow::Result<Vec<(String, chrono::DateTime<Utc>)>> {
        self.depsdev
            .version_timeline(system_for(ecosystem), name)
            .await
    }
}

/// Facts collected for one node of a dependency graph.
pub struct GraphFacts {
    /// Index into `graph.nodes()`.
    pub index: usize,
    /// Facts gathered for the node's exact version.
    pub facts: Facts,
    /// Set when collection failed.
    pub error: Option<String>,
}

/// Map a core [`Ecosystem`] to the deps.dev system identifier.
fn system_for(eco: Ecosystem) -> &'static str {
    eco.deps_dev_system()
}
