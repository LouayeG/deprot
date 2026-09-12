//! Maintainer capture-risk analysis.
//!
//! Given the maintainer identities of every dependency, this computes how concentrated your
//! supply chain is: which single identity controls the most packages, and what share of your
//! dependencies would be exposed if that one account were compromised. This is deprot's take on
//! the `xz`-style "one maintainer, many packages" risk — a pure aggregation over collected data.

use std::collections::BTreeMap;

/// A maintainer and the packages they control within the analyzed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintainerReach {
    /// Maintainer identity (email or login).
    pub identity: String,
    /// Packages in the analyzed set this identity maintains.
    pub packages: Vec<String>,
}

impl MaintainerReach {
    /// Number of packages controlled.
    pub fn count(&self) -> usize {
        self.packages.len()
    }
}

/// Aggregate maintainer reach across `(package, maintainers)` pairs, most-reaching first.
pub fn capture_risk<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [String])>,
) -> Vec<MaintainerReach> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (pkg, maintainers) in entries {
        for m in maintainers {
            let e = map.entry(m.clone()).or_default();
            if !e.iter().any(|p| p == pkg) {
                e.push(pkg.to_string());
            }
        }
    }
    let mut out: Vec<MaintainerReach> = map
        .into_iter()
        .map(|(identity, mut packages)| {
            packages.sort();
            MaintainerReach { identity, packages }
        })
        .collect();
    // Most packages first; ties broken alphabetically for determinism.
    out.sort_by(|a, b| b.count().cmp(&a.count()).then(a.identity.cmp(&b.identity)));
    out
}

/// The share (0.0–1.0) of `total_packages` controlled by the single most-reaching maintainer.
pub fn top_share(reaches: &[MaintainerReach], total_packages: usize) -> f64 {
    if total_packages == 0 {
        return 0.0;
    }
    reaches
        .first()
        .map(|r| r.count() as f64 / total_packages as f64)
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_and_ranks_by_reach() {
        let a = vec!["alice@x".to_string()];
        let ab = vec!["alice@x".to_string(), "bob@y".to_string()];
        let entries: Vec<(&str, &[String])> = vec![
            ("pkg1", a.as_slice()),
            ("pkg2", ab.as_slice()),
            ("pkg3", a.as_slice()),
        ];
        let reaches = capture_risk(entries);
        assert_eq!(reaches[0].identity, "alice@x");
        assert_eq!(reaches[0].count(), 3);
        assert!((top_share(&reaches, 3) - 1.0).abs() < 1e-9);
    }
}
