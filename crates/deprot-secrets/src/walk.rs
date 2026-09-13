//! The file walker: the only part of the crate that touches disk. Recursively scans a directory for
//! source files and runs [`scan_content`] on each, skipping dependency/build directories, binary and
//! asset files, oversized files, and lockfiles (hash-heavy, noise-prone).

use crate::detect::{scan_content, SecretFinding};
use std::fs;
use std::path::Path;

/// Directories never descended into (dot-directories are skipped separately).
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    "venv",
    "__pycache__",
    "coverage",
];

/// Files never read: binary/asset extensions and hash-heavy lockfiles.
const SKIP_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "svg", "pdf", "zip", "gz", "tgz", "tar", "bz2",
    "7z", "mp4", "mp3", "mov", "woff", "woff2", "ttf", "eot", "otf", "wasm", "exe", "dll", "so",
    "dylib", "a", "o", "class", "jar", "bin", "pyc", "map",
];

const SKIP_FILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
    "go.sum",
];

/// Files larger than this are skipped (minified bundles, data blobs).
const MAX_FILE_BYTES: u64 = 1_000_000;

/// Recursively scan `root` (a directory or a single file) for hardcoded secrets. Paths on findings
/// are relative to `root`.
pub fn scan_path(root: &Path) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    if root.is_file() {
        let base = root.parent().unwrap_or(root);
        scan_file(base, root, &mut out);
    } else {
        walk(root, root, &mut out);
    }
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<SecretFinding>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue; // don't follow symlinks
        }
        let p = e.path();
        if p.is_dir() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(root, &p, out);
        } else if p.is_file() {
            scan_file(root, &p, out);
        }
    }
}

fn scan_file(root: &Path, path: &Path, out: &mut Vec<SecretFinding>) {
    if should_skip_file(path) {
        return;
    }
    if fs::metadata(path)
        .map(|m| m.len() > MAX_FILE_BYTES)
        .unwrap_or(true)
    {
        return;
    }
    // read_to_string fails on non-UTF-8, which conveniently skips binary files.
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    out.extend(scan_content(&rel, &content));
}

fn should_skip_file(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if SKIP_FILES.contains(&name) {
            return true;
        }
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => SKIP_EXT.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_tree_skipping_deps_and_binaries() {
        let root =
            std::env::temp_dir().join(format!("deprot_sec_{}_{}", std::process::id(), line!()));
        let write = |rel: &str, body: &str| {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        };
        write(
            "src/config.js",
            "const key = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEF0189';\n",
        );
        write(
            "node_modules/pkg/leak.js",
            "const k = 'ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ0189';\n",
        );
        write("README.md", "no secrets here\n");

        let mut found = scan_path(&root);
        let _ = fs::remove_dir_all(&root);
        found.sort_by(|a, b| a.path.cmp(&b.path));

        assert_eq!(found.len(), 1, "only src/config.js should match: {found:?}");
        assert_eq!(found[0].path, "src/config.js");
        assert_eq!(found[0].rule, "github-token");
    }

    #[test]
    fn scan_single_file() {
        let root = std::env::temp_dir().join(format!("deprot_sec_one_{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let f = root.join("secrets.env");
        fs::write(&f, "AWS=AKIAZ3XYQ7R8T2WV5N1P\n").unwrap();
        let found = scan_path(&f);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "secrets.env");
    }
}
