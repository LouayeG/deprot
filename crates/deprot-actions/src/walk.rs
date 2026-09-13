//! The workflow file walker: find `.github/workflows/*.yml|*.yaml` under a project root (or accept a
//! single workflow file / a workflows directory directly) and run the analyzer on each.

use crate::detect::{analyze_workflow, ActionFinding};
use std::fs;
use std::path::Path;

fn is_workflow(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

/// Analyze the GitHub Actions workflows under `root`. `root` may be a project directory (its
/// `.github/workflows` is scanned), a `workflows` directory, or a single workflow file. Finding
/// paths are relative to `root`.
pub fn scan_path(root: &Path) -> Vec<ActionFinding> {
    let mut out = Vec::new();

    if root.is_file() {
        analyze_file(root, root, &mut out);
        return out;
    }

    // Prefer the canonical location; otherwise treat `root` itself as the directory of workflows.
    let wf = root.join(".github").join("workflows");
    let dir = if wf.is_dir() { wf } else { root.to_path_buf() };

    let Ok(entries) = fs::read_dir(&dir) else {
        return out;
    };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_workflow(p))
        .collect();
    files.sort();
    for f in &files {
        analyze_file(root, f, &mut out);
    }
    out
}

fn analyze_file(root: &Path, path: &Path, out: &mut Vec<ActionFinding>) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    out.extend(analyze_workflow(&rel, &content));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_github_workflows_dir() {
        let root =
            std::env::temp_dir().join(format!("deprot_wf_{}_{}", std::process::id(), line!()));
        let dir = root.join(".github").join("workflows");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("ci.yml"),
            "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: some/action@v1\n",
        )
        .unwrap();

        let found = scan_path(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(found
            .iter()
            .any(|f| f.rule == "unpinned-action" && f.path == ".github/workflows/ci.yml"));
    }
}
