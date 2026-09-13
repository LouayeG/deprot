//! The GitHub Actions workflow analyzer: `workflow yaml -> findings`. Pure, deterministic, line-
//! oriented (so every finding has an exact line number), and dependency-light. It implements the
//! high-impact, current audits for CI supply-chain attacks:
//!
//! - **`template-injection`** — untrusted `${{ github.event.* }}` / `github.head_ref` interpolated
//!   into a `run:` shell step (the classic Actions RCE).
//! - **`pwn-request`** — an elevated trigger (`pull_request_target` / `workflow_run`) that checks out
//!   attacker-controlled PR code (`ref: …head.sha` / `head.ref`) with secrets in scope.
//! - **`unpinned-action` / `mutable-ref-action`** — a `uses:` not pinned to a full commit SHA (tags
//!   are movable; `@main`/`@master` is worst).
//! - **`broad-permissions`** — `permissions: write-all`.
//! - **`missing-permissions`** — no explicit `permissions:` block (default token may be over-privileged).
//! - **`dangerous-trigger`** — use of `pull_request_target` / `workflow_run` at all.
//! - **`curl-pipe-shell`** — piping a remote download straight into a shell.

use deprot_core::Severity;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

/// One workflow-security finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ActionFinding {
    /// Stable rule id, e.g. `template-injection`.
    pub rule: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Severity of the issue.
    pub severity: Severity,
    /// Repo-relative path (filled by the walker; empty for [`analyze_workflow`] callers).
    pub path: String,
    /// 1-based line number.
    pub line: usize,
    /// Specific offending context (the action ref, the expression, …).
    pub detail: String,
}

fn re(pat: &str) -> Regex {
    Regex::new(pat).expect("valid workflow regex")
}

fn uses_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"(?:^|\s|-)uses:\s*([^\s#]+)"))
}

/// Untrusted `${{ … }}` expression whose leaf is an attacker-influenced field.
fn injection_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        re(r"\$\{\{[^}]*(?:github\.head_ref|github\.event\.[A-Za-z0-9_.\*\[\]]*(?:title|body|message|name|email|label|page_name|ref))[^}]*\}\}")
    })
}

/// A `ref:` that checks out attacker-controlled PR code.
fn untrusted_ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        re(r"ref:\s*\$\{\{[^}]*(?:head\.sha|head\.ref|head_ref|pull_request\.head)[^}]*\}\}")
    })
}

/// A remote download piped straight into a shell interpreter.
fn curl_pipe_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:[a-z]*sh)\b"))
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// True if `s` is a full 40-hex git commit SHA (the only truly pinned action ref).
fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The inline content after a `run:` key (`Some("")` for a block scalar like `run: |`), else `None`.
fn run_inline(trimmed: &str) -> Option<&str> {
    let t = trimmed.strip_prefix("- ").unwrap_or(trimmed);
    t.strip_prefix("run:").map(|r| r.trim())
}

/// Analyze one workflow file's `content`, attaching `path` to each finding.
pub fn analyze_workflow(path: &str, content: &str) -> Vec<ActionFinding> {
    let mut out = Vec::new();
    let push = |out: &mut Vec<ActionFinding>, rule, description, severity, line, detail: String| {
        out.push(ActionFinding {
            rule,
            description,
            severity,
            path: path.to_string(),
            line,
            detail,
        });
    };

    let elevated = content.contains("pull_request_target") || content.contains("workflow_run");
    let has_permissions = content.contains("permissions:");

    // `run:` block tracking so injection/curl checks only fire inside shell steps.
    let mut run_indent: Option<usize> = None;

    for (i, raw) in content.lines().enumerate() {
        let line_no = i + 1;
        let indent = indent_of(raw);
        let trimmed = raw.trim_start();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Close the current run block on dedent to or past the `run:` key.
        if let Some(base) = run_indent {
            if indent <= base {
                run_indent = None;
            }
        }

        // --- uses: pinning (not inside a run script) ---
        if run_indent.is_none() {
            if let Some(c) = uses_re().captures(raw) {
                let val = c[1].trim_matches(|ch| ch == '"' || ch == '\'');
                let is_local = val.starts_with("./") || val.starts_with('.');
                let docker_pinned = val.starts_with("docker://") && val.contains("@sha256:");
                if !is_local && !docker_pinned {
                    if let Some((action, rref)) = val.rsplit_once('@') {
                        if !is_commit_sha(rref) {
                            let first_party =
                                action.starts_with("actions/") || action.starts_with("github/");
                            if matches!(rref, "main" | "master" | "HEAD") {
                                push(
                                    &mut out,
                                    "mutable-ref-action",
                                    "Action pinned to a movable branch (not a commit SHA)",
                                    Severity::High,
                                    line_no,
                                    val.to_string(),
                                );
                            } else {
                                let sev = if first_party {
                                    Severity::Low
                                } else {
                                    Severity::Medium
                                };
                                push(
                                    &mut out,
                                    "unpinned-action",
                                    "Action not pinned to a full commit SHA (tag can be moved)",
                                    sev,
                                    line_no,
                                    val.to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }

        // --- run: detection + in-run checks ---
        let inline = run_inline(trimmed);
        if let Some(content_after) = inline {
            run_indent = Some(indent);
            scan_run_line(&mut out, path, line_no, content_after);
        } else if run_indent.is_some() {
            scan_run_line(&mut out, path, line_no, trimmed);
        }

        // --- permissions: write-all ---
        if trimmed.replace(' ', "").contains("permissions:write-all") {
            push(
                &mut out,
                "broad-permissions",
                "Workflow grants the GITHUB_TOKEN write-all permissions",
                Severity::High,
                line_no,
                trimmed.to_string(),
            );
        }

        // --- pwn-request: untrusted checkout under an elevated trigger ---
        if elevated && untrusted_ref_re().is_match(raw) {
            push(
                &mut out,
                "pwn-request",
                "Elevated trigger checks out untrusted PR code with secrets in scope",
                Severity::Critical,
                line_no,
                trimmed.to_string(),
            );
        }
    }

    // --- file-level findings ---
    if elevated {
        let line = content
            .lines()
            .position(|l| l.contains("pull_request_target") || l.contains("workflow_run"))
            .map(|p| p + 1)
            .unwrap_or(1);
        push(
            &mut out,
            "dangerous-trigger",
            "Uses pull_request_target / workflow_run (runs with secrets in an elevated context)",
            Severity::Medium,
            line,
            "elevated trigger".to_string(),
        );
    }
    if !has_permissions {
        push(
            &mut out,
            "missing-permissions",
            "No explicit permissions block; the default GITHUB_TOKEN may be over-privileged",
            Severity::Low,
            1,
            "add a least-privilege `permissions:` block".to_string(),
        );
    }

    out
}

fn scan_run_line(out: &mut Vec<ActionFinding>, path: &str, line_no: usize, text: &str) {
    if let Some(m) = injection_re().find(text) {
        out.push(ActionFinding {
            rule: "template-injection",
            description: "Untrusted ${{ … }} expression interpolated into a shell step (RCE risk)",
            severity: Severity::High,
            path: path.to_string(),
            line: line_no,
            detail: m.as_str().to_string(),
        });
    }
    if curl_pipe_re().is_match(text) {
        out.push(ActionFinding {
            rule: "curl-pipe-shell",
            description: "Remote script piped directly into a shell (unverified code execution)",
            severity: Severity::Medium,
            path: path.to_string(),
            line: line_no,
            detail: text.trim().to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(f: &[ActionFinding]) -> Vec<&str> {
        f.iter().map(|x| x.rule).collect()
    }

    #[test]
    fn flags_unpinned_and_mutable_but_not_sha() {
        let wf = "\
jobs:\n  b:\n    permissions: read-all\n    steps:\n\
      - uses: actions/checkout@v4\n\
      - uses: some/third-party@v1\n\
      - uses: evil/action@main\n\
      - uses: pinned/action@abcdef0123456789abcdef0123456789abcdef01\n";
        let f = analyze_workflow("ci.yml", wf);
        let first = f
            .iter()
            .find(|x| x.detail == "actions/checkout@v4")
            .unwrap();
        assert_eq!(first.rule, "unpinned-action");
        assert_eq!(first.severity, Severity::Low, "first-party is lower risk");
        assert!(f.iter().any(|x| x.rule == "unpinned-action"
            && x.detail == "some/third-party@v1"
            && x.severity == Severity::Medium));
        assert!(f
            .iter()
            .any(|x| x.rule == "mutable-ref-action" && x.severity == Severity::High));
        assert!(
            !f.iter().any(|x| x.detail.contains("pinned/action")),
            "SHA-pinned is fine"
        );
    }

    #[test]
    fn flags_template_injection_only_in_run() {
        let wf = "\
jobs:\n  b:\n    permissions: read-all\n    steps:\n\
      - run: echo \"${{ github.event.pull_request.title }}\"\n\
      - uses: x/y@1111111111111111111111111111111111111111\n\
        with:\n          title: ${{ github.event.issue.title }}\n";
        let f = analyze_workflow("ci.yml", wf);
        // The run step is flagged...
        let inj: Vec<_> = f
            .iter()
            .filter(|x| x.rule == "template-injection")
            .collect();
        assert_eq!(inj.len(), 1, "only the run step, not the with: input");
        assert_eq!(inj[0].line, 5);
    }

    #[test]
    fn flags_pwn_request() {
        let wf = "\
on: pull_request_target\npermissions: read-all\njobs:\n  b:\n    steps:\n\
      - uses: actions/checkout@1111111111111111111111111111111111111111\n\
        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
        let f = analyze_workflow("ci.yml", wf);
        assert!(f
            .iter()
            .any(|x| x.rule == "pwn-request" && x.severity == Severity::Critical));
        assert!(rules(&f).contains(&"dangerous-trigger"));
    }

    #[test]
    fn flags_broad_and_missing_permissions() {
        let wf = "jobs:\n  b:\n    permissions: write-all\n    steps: []\n";
        let f = analyze_workflow("ci.yml", wf);
        assert!(f
            .iter()
            .any(|x| x.rule == "broad-permissions" && x.severity == Severity::High));
        // has_permissions is true here, so no missing-permissions
        assert!(!rules(&f).contains(&"missing-permissions"));

        let wf2 = "jobs:\n  b:\n    steps:\n      - run: echo hi\n";
        let f2 = analyze_workflow("ci.yml", wf2);
        assert!(f2.iter().any(|x| x.rule == "missing-permissions"));
    }

    #[test]
    fn flags_curl_pipe_shell() {
        let wf = "jobs:\n  b:\n    permissions: read-all\n    steps:\n      - run: curl https://x.sh | sudo bash\n";
        let f = analyze_workflow("ci.yml", wf);
        assert!(f.iter().any(|x| x.rule == "curl-pipe-shell"));
    }

    #[test]
    fn clean_workflow_has_no_findings() {
        let wf = "\
on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n\
      - uses: actions/checkout@1111111111111111111111111111111111111111\n\
      - run: echo \"${{ github.sha }}\"\n";
        let f = analyze_workflow("ci.yml", wf);
        assert!(f.is_empty(), "expected clean, got {f:?}");
    }
}
