//! Typosquat / dependency-confusion detection.
//!
//! A pure check: each dependency name is compared by edit distance against a bundled list of very
//! popular packages. A name that is 1–2 edits away from a popular package — but is not itself that
//! package — is a classic typosquat (`lodahs` for `lodash`, `expres` for `express`). No network,
//! deterministic, testable.

use crate::facts::Ecosystem;

/// A dependency name that looks like a typo of a popular package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspect {
    /// The suspicious dependency name.
    pub name: String,
    /// The popular package it closely resembles.
    pub nearest: String,
    /// Edit distance between them.
    pub distance: usize,
}

/// Popular npm packages (abbreviated but representative).
const POPULAR_NPM: &[&str] = &[
    "react",
    "lodash",
    "express",
    "chalk",
    "axios",
    "webpack",
    "commander",
    "request",
    "moment",
    "debug",
    "async",
    "bluebird",
    "underscore",
    "jquery",
    "typescript",
    "eslint",
    "prettier",
    "vue",
    "angular",
    "next",
    "dotenv",
    "uuid",
    "cors",
    "body-parser",
    "mongoose",
    "redux",
    "jest",
    "mocha",
    "yargs",
    "glob",
    "semver",
    "colors",
    "node-fetch",
    "ws",
    "socket.io",
    "rxjs",
];

/// Popular crates.io crates (abbreviated but representative).
const POPULAR_CARGO: &[&str] = &[
    "serde",
    "tokio",
    "rand",
    "log",
    "clap",
    "anyhow",
    "thiserror",
    "regex",
    "syn",
    "quote",
    "libc",
    "reqwest",
    "hyper",
    "futures",
    "chrono",
    "itertools",
    "bytes",
    "tracing",
    "async-trait",
    "rayon",
    "base64",
    "url",
    "uuid",
    "once_cell",
    "lazy_static",
    "bitflags",
    "cfg-if",
    "proc-macro2",
    "serde_json",
];

/// Popular PyPI packages (abbreviated but representative).
const POPULAR_PYPI: &[&str] = &[
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "pytest",
    "pillow",
    "scipy",
    "boto3",
    "urllib3",
    "click",
    "jinja2",
    "setuptools",
    "wheel",
    "six",
    "certifi",
    "idna",
    "cryptography",
];

fn popular_for(eco: Ecosystem) -> &'static [&'static str] {
    match eco {
        Ecosystem::Npm => POPULAR_NPM,
        Ecosystem::Cargo => POPULAR_CARGO,
        Ecosystem::PyPI => POPULAR_PYPI,
    }
}

/// Levenshtein edit distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Scan dependency names for likely typosquats of popular packages in the same ecosystem.
pub fn scan<'a>(names: impl IntoIterator<Item = &'a str>, ecosystem: Ecosystem) -> Vec<Suspect> {
    let popular = popular_for(ecosystem);
    let mut out = Vec::new();
    for name in names {
        let lname = name.to_lowercase();
        // A name that IS popular is fine.
        if popular.iter().any(|p| *p == lname) {
            continue;
        }
        // Find the closest popular package.
        if let Some((nearest, dist)) = popular
            .iter()
            .map(|p| (*p, edit_distance(&lname, p)))
            .min_by_key(|(_, d)| *d)
        {
            // 1–2 edits from a popular name, and long enough that a small edit is meaningful.
            if (1..=2).contains(&dist) && lname.len() >= 4 {
                out.push(Suspect {
                    name: name.to_string(),
                    nearest: nearest.to_string(),
                    distance: dist,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_close_typosquats() {
        let s = scan(["lodahs", "expres", "reqwests"], Ecosystem::Npm);
        assert!(s
            .iter()
            .any(|x| x.name == "lodahs" && x.nearest == "lodash"));
        assert!(s
            .iter()
            .any(|x| x.name == "expres" && x.nearest == "express"));
    }

    #[test]
    fn does_not_flag_exact_popular_names() {
        assert!(scan(["lodash", "express", "react"], Ecosystem::Npm).is_empty());
    }

    #[test]
    fn does_not_flag_unrelated_names() {
        // A genuinely different, distant name should not trip the 1–2 edit window.
        assert!(scan(["my-company-internal-widget"], Ecosystem::Npm).is_empty());
    }

    #[test]
    fn cargo_ecosystem_uses_crate_list() {
        let s = scan(["tokjo", "serde"], Ecosystem::Cargo);
        assert!(s.iter().any(|x| x.name == "tokjo" && x.nearest == "tokio"));
        // "serde" is itself popular → not flagged.
        assert!(!s.iter().any(|x| x.name == "serde"));
    }
}
