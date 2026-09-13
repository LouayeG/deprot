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
///
/// A readable, sanitized prefix is kept for debuggability, but the key is disambiguated with a
/// stable hash of the *raw* name. Sanitizing alone is lossy — distinct packages collapse to the
/// same string (`@scope/pkg`, `scope-pkg` and `scope.pkg` all become `_scope_pkg`), which for npm
/// (where those are different packages) would serve one package's cached facts for another.
pub fn key(system: &str, name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(60)
        .collect();
    format!("{system}__{safe}_{:016x}", fnv1a(name))
}

/// FNV-1a 64-bit: a tiny, dependency-free hash that is stable across runs and Rust releases.
/// (`std`'s `DefaultHasher` is unsuitable here because its output may change between Rust versions,
/// which would silently orphan every persisted cache entry.)
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::key;

    #[test]
    fn distinct_names_do_not_collide() {
        // These all sanitize to the same lossy string but are different npm packages.
        let a = key("npm", "@scope/pkg");
        let b = key("npm", "scope-pkg");
        let c = key("npm", "scope.pkg");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn key_is_stable() {
        assert_eq!(key("cargo", "serde@1.0.0"), key("cargo", "serde@1.0.0"));
    }
}
