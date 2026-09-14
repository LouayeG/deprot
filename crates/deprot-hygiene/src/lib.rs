//! # deprot-hygiene
//!
//! A local, keyless repository **security-posture** audit — deprot's take on the project-hygiene
//! side of a supply-chain review, without needing the GitHub API. It grades a repo against current
//! best practices: a security policy, a committed lockfile, a `.gitignore` that actually covers
//! secrets, no credential files checked in, automated dependency updates, CI, CODEOWNERS, and more.
//!
//! Everything is derived from files on disk (and `git ls-files` when available, to only flag
//! *tracked* credential files). Deterministic and easy to test by pointing [`analyze`] at a
//! directory.

use deprot_core::Severity;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// One posture check and its result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HygieneCheck {
    /// Stable id, e.g. `security-policy`.
    pub id: &'static str,
    /// Short human-readable title.
    pub title: &'static str,
    /// Whether the repo satisfies the check.
    pub passed: bool,
    /// Severity of the gap when `passed` is false.
    pub severity: Severity,
    /// What was found, or remediation advice.
    pub detail: String,
}

/// The full hygiene report: every check plus a weighted 0–100 posture score.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HygieneReport {
    /// All checks, in display order.
    pub checks: Vec<HygieneCheck>,
    /// Weighted posture score (0–100): share of severity-weighted checks that passed.
    pub score: u8,
}

impl HygieneReport {
    /// The failing checks, worst-first.
    pub fn failures(&self) -> Vec<&HygieneCheck> {
        let mut f: Vec<&HygieneCheck> = self.checks.iter().filter(|c| !c.passed).collect();
        f.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(b.id)));
        f
    }
}

/// Severity weight for scoring — failing an important check hurts the score more.
fn weight(s: Severity) -> u32 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

/// Run every hygiene check against the repository at `root`.
pub fn analyze(root: &Path) -> HygieneReport {
    let tracked = git_tracked(root);
    let mut checks = Vec::new();

    let exists = |names: &[&str]| names.iter().any(|n| root.join(n).exists());

    // 1. Security policy.
    checks.push(check(
        "security-policy",
        "Security policy (SECURITY.md)",
        exists(&["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]),
        Severity::Medium,
        "add a SECURITY.md describing how to report vulnerabilities",
    ));

    // 2. License.
    checks.push(check(
        "license",
        "License file",
        exists(&[
            "LICENSE",
            "LICENSE.md",
            "LICENSE.txt",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "COPYING",
        ]),
        Severity::Low,
        "add a LICENSE so downstream users know their rights",
    ));

    // 3. README.
    checks.push(check(
        "readme",
        "README",
        exists(&["README.md", "README", "README.rst", "readme.md"]),
        Severity::Low,
        "add a README",
    ));

    // 4. .gitignore + does it cover secrets?
    let gitignore = root.join(".gitignore");
    if gitignore.is_file() {
        let body = std::fs::read_to_string(&gitignore).unwrap_or_default();
        let covers = [".env", "*.pem", "*.key", "id_rsa", "credentials"]
            .iter()
            .any(|p| body.contains(p));
        checks.push(check(
            "gitignore-covers-secrets",
            ".gitignore covers secret patterns",
            covers,
            Severity::Low,
            "add secret patterns to .gitignore (.env, *.pem, *.key, id_rsa, credentials)",
        ));
    } else {
        checks.push(check(
            "gitignore",
            ".gitignore present",
            false,
            Severity::Medium,
            "add a .gitignore to avoid committing build output and secrets",
        ));
    }

    // 5. Lockfile committed (only when a manifest exists).
    if let Some((ok, detail)) = lockfile_status(root) {
        checks.push(check(
            "lockfile-committed",
            "Dependency lockfile committed",
            ok,
            Severity::Medium,
            &detail,
        ));
    }

    // 6. No credential files committed.
    let (clean, where_) = no_committed_secrets(root, tracked.as_ref());
    checks.push(check(
        "no-committed-secrets",
        "No credential files committed",
        clean,
        Severity::High,
        &if clean {
            "no tracked .env / key / credential files".to_string()
        } else {
            format!("remove and rotate committed credential file(s): {where_}")
        },
    ));

    // 7. Automated dependency updates.
    checks.push(check(
        "dependency-automation",
        "Automated dependency updates",
        exists(&[
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
            "renovate.json",
            ".renovaterc",
            ".renovaterc.json",
            ".github/renovate.json",
        ]),
        Severity::Low,
        "enable automated dependency-update PRs to keep dependencies current",
    ));

    // 8. CI configured.
    checks.push(check(
        "ci-configured",
        "Continuous integration configured",
        has_ci(root),
        Severity::Low,
        "add a CI workflow to build/test on every change",
    ));

    // 9. CODEOWNERS.
    checks.push(check(
        "codeowners",
        "CODEOWNERS defined",
        exists(&["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]),
        Severity::Low,
        "add a CODEOWNERS file to require review from responsible owners",
    ));

    let total: u32 = checks.iter().map(|c| weight(c.severity)).sum();
    let passed: u32 = checks
        .iter()
        .filter(|c| c.passed)
        .map(|c| weight(c.severity))
        .sum();
    let score = if total == 0 {
        100
    } else {
        ((passed as f64 / total as f64) * 100.0).round() as u8
    };

    HygieneReport { checks, score }
}

fn check(
    id: &'static str,
    title: &'static str,
    passed: bool,
    severity: Severity,
    detail: &str,
) -> HygieneCheck {
    HygieneCheck {
        id,
        title,
        passed,
        severity,
        detail: detail.to_string(),
    }
}

/// The set of git-tracked file paths (relative), or `None` if this isn't a git repo / git is absent.
fn git_tracked(root: &Path) -> Option<HashSet<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect(),
    )
}

fn has_ci(root: &Path) -> bool {
    let wf = root.join(".github").join("workflows");
    let github_ci = std::fs::read_dir(&wf)
        .map(|mut e| e.any(|f| f.map(|f| is_yaml(&f.path())).unwrap_or(false)))
        .unwrap_or(false);
    github_ci
        || ["/.gitlab-ci.yml", "/.circleci/config.yml", "/.travis.yml"]
            .iter()
            .any(|p| root.join(p.trim_start_matches('/')).exists())
}

fn is_yaml(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

/// `Some((committed, detail))` when the repo has a manifest whose lockfile we can check; `None` when
/// there's no manifest to reason about.
fn lockfile_status(root: &Path) -> Option<(bool, String)> {
    let has = |n: &str| root.join(n).exists();
    let mut expected: Vec<(&str, bool)> = Vec::new(); // (ecosystem label, lock present)

    if has("package.json") {
        expected.push((
            "npm",
            [
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
                "npm-shrinkwrap.json",
            ]
            .iter()
            .any(|l| has(l)),
        ));
    }
    if has("Cargo.toml") {
        expected.push(("cargo", has("Cargo.lock")));
    }
    if has("go.mod") {
        expected.push(("go", has("go.sum")));
    }
    if has("pyproject.toml") {
        expected.push((
            "python",
            ["poetry.lock", "pdm.lock", "uv.lock", "Pipfile.lock"]
                .iter()
                .any(|l| has(l)),
        ));
    }
    if has("Pipfile") {
        expected.push(("pipenv", has("Pipfile.lock")));
    }

    if expected.is_empty() {
        return None;
    }
    let missing: Vec<&str> = expected
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(e, _)| *e)
        .collect();
    if missing.is_empty() {
        Some((
            true,
            "lockfile present for reproducible installs".to_string(),
        ))
    } else {
        Some((
            false,
            format!("commit a lockfile for: {}", missing.join(", ")),
        ))
    }
}

/// Whether a file basename is a credential/secret file that should never be committed.
fn is_sensitive_name(name: &str) -> bool {
    // .env and its variants, but allow templates/examples.
    if name.starts_with(".env")
        && !name.ends_with(".example")
        && !name.ends_with(".sample")
        && !name.ends_with(".template")
        && !name.ends_with(".dist")
    {
        return true;
    }
    if matches!(
        name,
        "id_rsa"
            | "id_dsa"
            | "id_ecdsa"
            | "id_ed25519"
            | "credentials"
            | "credentials.json"
            | "secrets.json"
    ) {
        return true;
    }
    matches!(
        name.rsplit('.').next(),
        Some("pfx") | Some("p12") | Some("keystore") | Some("jks")
    )
}

/// `(clean, where)` — whether the repo has no committed credential files (and, if not, which).
fn no_committed_secrets(root: &Path, tracked: Option<&HashSet<String>>) -> (bool, String) {
    let mut hits: Vec<String> = Vec::new();

    let basename = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();

    match tracked {
        Some(files) => {
            for f in files {
                let name = basename(f);
                if is_sensitive_name(&name) || is_tokened_rc(&name, &root.join(f)) {
                    hits.push(f.clone());
                }
            }
        }
        None => {
            // No git: shallow scan of the root directory only.
            if let Ok(entries) = std::fs::read_dir(root) {
                for e in entries.flatten() {
                    if e.path().is_file() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if is_sensitive_name(&name) || is_tokened_rc(&name, &e.path()) {
                            hits.push(name);
                        }
                    }
                }
            }
        }
    }

    hits.sort();
    hits.dedup();
    if hits.is_empty() {
        (true, String::new())
    } else {
        (false, hits.join(", "))
    }
}

/// Whether `.npmrc` / `.pypirc` actually carries an auth token (mere registry config is fine).
fn is_tokened_rc(name: &str, path: &Path) -> bool {
    if name != ".npmrc" && name != ".pypirc" {
        return false;
    }
    let body = std::fs::read_to_string(path).unwrap_or_default();
    body.contains("_authToken")
        || body.contains("_auth=")
        || body.contains(":_password")
        || body.contains("password")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "deprot_hyg_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn passed(r: &HygieneReport, id: &str) -> bool {
        r.checks
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.passed)
            .unwrap()
    }

    #[test]
    fn bare_repo_scores_low_and_lists_gaps() {
        let d = tmp();
        let r = analyze(&d);
        let _ = std::fs::remove_dir_all(&d);
        assert!(r.score < 40, "bare repo should score low, got {}", r.score);
        assert!(!passed(&r, "security-policy"));
        assert!(!passed(&r, "gitignore")); // no .gitignore
    }

    #[test]
    fn well_kept_repo_scores_high() {
        let d = tmp();
        let w = |n: &str, b: &str| {
            let p = d.join(n);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b).unwrap();
        };
        w("SECURITY.md", "report to security@x");
        w("LICENSE", "MIT");
        w("README.md", "hi");
        w(".gitignore", "node_modules/\n.env\n*.key\n");
        w("package.json", "{}");
        w("package-lock.json", "{}");
        w(".github/dependabot.yml", "version: 2");
        w(".github/workflows/ci.yml", "on: push");
        w(".github/CODEOWNERS", "* @me");
        let r = analyze(&d);
        let _ = std::fs::remove_dir_all(&d);
        assert!(
            r.score >= 90,
            "kept repo should score high, got {} ({:?})",
            r.score,
            r.failures()
        );
        assert!(passed(&r, "lockfile-committed"));
        assert!(passed(&r, "no-committed-secrets"));
    }

    #[test]
    fn committed_env_file_is_flagged_but_example_is_not() {
        let d = tmp();
        std::fs::write(d.join(".env"), "SECRET=abc").unwrap();
        std::fs::write(d.join(".env.example"), "SECRET=").unwrap();
        let r = analyze(&d);
        let _ = std::fs::remove_dir_all(&d);
        let c = r
            .checks
            .iter()
            .find(|c| c.id == "no-committed-secrets")
            .unwrap();
        assert!(!c.passed, "a committed .env must fail");
        assert!(c.detail.contains(".env"));
        assert!(
            !c.detail.contains(".env.example"),
            "example files are allowed"
        );
    }

    #[test]
    fn missing_lockfile_is_flagged() {
        let d = tmp();
        std::fs::write(d.join("package.json"), "{}").unwrap();
        let r = analyze(&d);
        let _ = std::fs::remove_dir_all(&d);
        assert!(!passed(&r, "lockfile-committed"));
    }
}
