//! A tiny TTL'd on-disk cache for collected [`Facts`].
//!
//! Re-running deprot on the same project should be instant and should not hammer public APIs, so
//! each dependency's facts are cached as JSON under the OS cache directory and reused until they
//! age out. The cache is a pure convenience layer: a corrupt or missing entry is simply a miss.

use deprot_core::Facts;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct Entry {
    stored_at: u64,
    facts: Facts,
}

/// Handle to the on-disk cache directory.
pub struct Cache {
    dir: Option<PathBuf>,
    ttl_secs: u64,
    enabled: bool,
}

impl Cache {
    /// Open the cache with a given TTL. When `enabled` is false every read misses and every write
    /// is a no-op (used for `--no-cache`).
    pub fn open(ttl_secs: u64, enabled: bool) -> Self {
        let dir = directories::ProjectDirs::from("io", "deprot", "deprot").map(|d| {
            let p = d.cache_dir().join("facts");
            let _ = std::fs::create_dir_all(&p);
            p
        });
        Cache {
            dir,
            ttl_secs,
            enabled,
        }
    }

    fn path_for(&self, key: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(format!("{key}.json")))
    }

    /// Fetch fresh facts for `key`, or `None` on miss / stale / disabled.
    pub fn get(&self, key: &str) -> Option<Facts> {
        if !self.enabled {
            return None;
        }
        let path = self.path_for(key)?;
        let raw = std::fs::read_to_string(path).ok()?;
        let entry: Entry = serde_json::from_str(&raw).ok()?;
        if now_secs().saturating_sub(entry.stored_at) > self.ttl_secs {
            return None;
        }
        Some(entry.facts)
    }

    /// Store facts for `key`. Failures are ignored — the cache never breaks a run.
    pub fn put(&self, key: &str, facts: &Facts) {
        if !self.enabled {
            return;
        }
        let Some(path) = self.path_for(key) else {
            return;
        };
        let entry = Entry {
            stored_at: now_secs(),
            facts: facts.clone(),
        };
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = std::fs::write(path, json);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a filesystem-safe cache key from ecosystem + package name.
pub fn key(system: &str, name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{system}__{safe}")
}
