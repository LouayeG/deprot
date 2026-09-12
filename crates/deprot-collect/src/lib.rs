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

use chrono::Utc;
use deprot_core::{Dependency, Ecosystem, Facts};
use futures::stream::{self, StreamExt};
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
}

impl Default for CollectorConfig {
    fn default() -> Self {
        CollectorConfig {
            concurrency: 12,
            cache_ttl_secs: 24 * 60 * 60,
            cache_enabled: true,
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
    cache: Arc<Cache>,
    config: CollectorConfig,
}

impl Collector {
    /// Build a collector with the given config.
    pub fn new(config: CollectorConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("deprot/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(20))
            .build()?;
        let cache = Cache::open(config.cache_ttl_secs, config.cache_enabled);
        Ok(Collector {
            depsdev: depsdev::DepsDev::new(http),
            cache: Arc::new(cache),
            config,
        })
    }

    /// Collect facts for a single dependency, consulting the cache first.
    pub async fn collect_one(&self, dep: &Dependency) -> Collected {
        let system = system_for(dep.ecosystem);
        let ckey = cache::key(system, &dep.name);

        if let Some(facts) = self.cache.get(&ckey) {
            return Collected {
                dependency: dep.clone(),
                facts,
                error: None,
            };
        }

        match self.depsdev.collect(system, &dep.name, Utc::now()).await {
            Ok(facts) => {
                self.cache.put(&ckey, &facts);
                Collected {
                    dependency: dep.clone(),
                    facts,
                    error: None,
                }
            }
            Err(e) => Collected {
                dependency: dep.clone(),
                facts: Facts::default(),
                error: Some(e.to_string()),
            },
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
}

/// Map a core [`Ecosystem`] to the deps.dev system identifier.
fn system_for(eco: Ecosystem) -> &'static str {
    eco.deps_dev_system()
}
