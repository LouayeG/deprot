//! The pure secret-detection engine: `content -> findings`. No I/O, deterministic, and easy to
//! unit-test. Two tiers of detection:
//!
//! 1. **Format-specific rules** — high-precision regexes for the exact shapes of real credentials
//!    (AWS keys, GitHub/GitLab/Slack tokens, Stripe/Google/OpenAI/Anthropic keys, PEM private keys …).
//!    These fire with high confidence.
//! 2. **Generic high-entropy assignment** — a `secret = "…"`-style assignment whose value has high
//!    Shannon entropy, to catch credentials we don't have a named pattern for.
//!
//! Both tiers run through aggressive false-positive suppression (placeholders, env-var references,
//! obvious test/example values) and every match is **redacted** — the raw secret never leaves this
//! crate.

use deprot_core::Severity;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

/// One detected secret. The `preview` is always redacted; the raw value is never retained.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecretFinding {
    /// Stable rule id, e.g. `aws-access-key-id`.
    pub rule: &'static str,
    /// Human-readable description of what was found.
    pub description: &'static str,
    /// Severity of the exposure.
    pub severity: Severity,
    /// Repo-relative (or given) path — filled by the file walker; empty for [`scan_content`].
    pub path: String,
    /// 1-based line number.
    pub line: usize,
    /// Redacted preview of the match (e.g. `ghp_ab…yz`).
    pub preview: String,
    /// Shannon entropy of the matched value, when relevant (generic tier).
    pub entropy: Option<f64>,
}

/// Inline suppression marker: a line containing this is never flagged (mirrors the widely-used
/// `pragma: allowlist secret`, but namespaced to deprot).
const ALLOW_MARKER: &str = "deprot:allow-secret";

struct Rule {
    id: &'static str,
    desc: &'static str,
    severity: Severity,
    re: Regex,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |id, desc, severity, pat: &str| Rule {
            id,
            desc,
            severity,
            re: Regex::new(pat).expect("valid secret regex"),
        };
        vec![
            r(
                "private-key",
                "Cryptographic private key",
                Severity::Critical,
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            ),
            r(
                "aws-access-key-id",
                "AWS Access Key ID",
                Severity::High,
                r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b",
            ),
            r(
                "github-token",
                "GitHub token",
                Severity::High,
                r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
            ),
            r(
                "github-fine-grained-pat",
                "GitHub fine-grained PAT",
                Severity::High,
                r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
            ),
            r(
                "gitlab-pat",
                "GitLab personal access token",
                Severity::High,
                r"\bglpat-[0-9A-Za-z_\-]{20}\b",
            ),
            r(
                "slack-token",
                "Slack token",
                Severity::High,
                r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b",
            ),
            r(
                "slack-webhook",
                "Slack incoming webhook",
                Severity::Medium,
                r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{16,}",
            ),
            r(
                "stripe-secret-key",
                "Stripe live secret key",
                Severity::High,
                r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b",
            ),
            r(
                "google-api-key",
                "Google API key",
                Severity::High,
                r"\bAIza[0-9A-Za-z_\-]{35}\b",
            ),
            r(
                "openai-key",
                "OpenAI API key",
                Severity::High,
                r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            ),
            r(
                "anthropic-key",
                "Anthropic API key",
                Severity::High,
                r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
            ),
            r(
                "npm-token",
                "npm access token",
                Severity::High,
                r"\bnpm_[0-9A-Za-z]{36}\b",
            ),
            r(
                "pypi-token",
                "PyPI upload token",
                Severity::High,
                r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
            ),
            r(
                "sendgrid-key",
                "SendGrid API key",
                Severity::High,
                r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b",
            ),
            r(
                "twilio-key",
                "Twilio API key",
                Severity::Medium,
                r"\bSK[0-9a-fA-F]{32}\b",
            ),
            r(
                "jwt",
                "JSON Web Token",
                Severity::Low,
                r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            ),
        ]
    })
}

/// The generic `keyword = "high-entropy-value"` matcher.
fn generic_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:secret|token|passwd|password|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key)"?\s*[:=]\s*["']([A-Za-z0-9+/_\-]{16,})["']"#,
        )
        .expect("valid generic secret regex")
    })
}

/// Entropy threshold (bits/char) above which a generic value is treated as a likely secret.
const ENTROPY_THRESHOLD: f64 = 3.5;

/// Scan a single file's `content`, returning redacted findings. `path` is attached to each finding
/// (pass `""` when scanning a bare string).
pub fn scan_content(path: &str, content: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.contains(ALLOW_MARKER) {
            continue;
        }
        // Skip absurdly long lines (minified bundles): expensive and noise-prone.
        if line.len() > 2000 {
            continue;
        }
        let line_no = i + 1;
        let mut matched_here = false;

        for rule in rules() {
            if let Some(m) = rule.re.find(line) {
                let value = m.as_str();
                if is_placeholder(value) {
                    continue;
                }
                matched_here = true;
                out.push(SecretFinding {
                    rule: rule.id,
                    description: rule.desc,
                    severity: rule.severity,
                    path: path.to_string(),
                    line: line_no,
                    preview: redact(value),
                    entropy: None,
                });
            }
        }

        // Generic tier only if a named rule didn't already claim this line.
        if !matched_here {
            if let Some(caps) = generic_rule().captures(line) {
                let value = &caps[1];
                let ent = shannon_entropy(value);
                if ent >= ENTROPY_THRESHOLD && !is_placeholder(value) {
                    out.push(SecretFinding {
                        rule: "generic-high-entropy",
                        description: "High-entropy secret assignment",
                        severity: Severity::Medium,
                        path: path.to_string(),
                        line: line_no,
                        preview: redact(value),
                        entropy: Some((ent * 100.0).round() / 100.0),
                    });
                }
            }
        }
    }
    out
}

/// Whether a matched value is an obvious non-secret: a placeholder, an env-var reference, or a
/// well-known documentation/example credential.
fn is_placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "example",
        "xxxx",
        "changeme",
        "placeholder",
        "your_",
        "yourkey",
        "your-key",
        "dummy",
        "redacted",
        "insertkey",
        "test-key",
        "sample",
        "faketoken",
        "notreal",
        "0000000000",
        "1234567890",
        "aaaaaaaa",
    ];
    if NEEDLES.iter().any(|n| l.contains(n)) {
        return true;
    }
    // Env-var / interpolation references, not literals.
    if v.contains("${") || v.contains("{{") || v.contains("process.env") || v.contains("os.environ")
    {
        return true;
    }
    // AWS's canonical documentation key.
    if v == "AKIAIOSFODNN7EXAMPLE" {
        return true;
    }
    // A single repeated character (padding / masking).
    let bytes = v.as_bytes();
    bytes.len() > 3 && bytes.iter().all(|&b| b == bytes[0])
}

/// Redact a secret to `<first4>…<last4>` (or fully masked when short), so the raw value never
/// appears in output.
fn redact(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() <= 10 {
        let head = chars.first().map(|c| c.to_string()).unwrap_or_default();
        return format!("{head}{}", "*".repeat(chars.len().saturating_sub(1)));
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// Shannon entropy (bits per character) of a string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let len = s.chars().count() as f64;
    -counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_github_and_private_key() {
        let src = "\
            let aws = \"AKIAZ3XYQ7R8T2WV5N1P\";\n\
            const gh = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEF0189';\n\
            -----BEGIN RSA PRIVATE KEY-----\n";
        let f = scan_content("x.js", src);
        assert!(f
            .iter()
            .any(|x| x.rule == "aws-access-key-id" && x.line == 1));
        assert!(f.iter().any(|x| x.rule == "github-token" && x.line == 2));
        assert!(f
            .iter()
            .any(|x| x.rule == "private-key" && x.severity == Severity::Critical));
        // never leak the raw secret
        assert!(f.iter().all(|x| !x.preview.contains("Z3XYQ7R8T2WV5N1P")));
    }

    #[test]
    fn ignores_placeholders_and_env_refs() {
        let src = "\
            aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n\
            token = \"${GITHUB_TOKEN}\"\n\
            api_key = \"your_api_key_here\"\n";
        assert!(scan_content("c.env", src).is_empty());
    }

    #[test]
    fn inline_allow_marker_suppresses() {
        let src = "secret = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' // deprot:allow-secret\n";
        assert!(scan_content("x.js", src).is_empty());
    }

    #[test]
    fn generic_high_entropy_assignment_flagged() {
        // A random-looking value assigned to a secret-ish name.
        let src = "API_SECRET = \"gH7xQ2vLpZ9wR4tK1nB8mD6sF3jY0aC\"\n";
        let f = scan_content("c.py", src);
        assert!(f.iter().any(|x| x.rule == "generic-high-entropy"));
    }

    #[test]
    fn low_entropy_generic_is_ignored() {
        let src = "password = \"aaaaaaaaaaaaaaaaaaaa\"\n";
        assert!(scan_content("c.py", src).is_empty());
    }

    #[test]
    fn redaction_hides_the_secret() {
        assert_eq!(redact("ghp_abcdefghijklmnop"), "ghp_…mnop");
    }
}
