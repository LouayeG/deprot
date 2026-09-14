//! End-to-end tests that drive the actual `deprot` binary. These exercise the offline scanners only,
//! so they're deterministic and need no network — asserting the exit-code contract and output shape
//! that CI and users depend on.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_deprot"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("deprot_e2e_{}_{}", std::process::id(), tag));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn version_and_help_exit_zero() {
    assert!(bin().arg("--version").output().unwrap().status.success());
    assert!(bin().arg("--help").output().unwrap().status.success());
}

#[test]
fn malware_flags_dropper_and_exits_nonzero() {
    let dir = tmpdir("mal");
    fs::write(dir.join("evil.js"), "eval(atob('ZWNobyBoaQ=='))\n").unwrap();

    let out = bin()
        .arg("--malware")
        .arg("--json")
        .arg(&dir)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(out.status.code(), Some(1), "a critical finding must exit 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("obfuscated-eval"),
        "json should name the rule: {stdout}"
    );
    assert!(
        stdout.contains("\"confidence\""),
        "json should carry confidence"
    );
}

#[test]
fn malware_clean_tree_exits_zero() {
    let dir = tmpdir("clean");
    fs::write(dir.join("ok.js"), "export const add = (a, b) => a + b;\n").unwrap();

    let out = bin().arg("--malware").arg(&dir).output().unwrap();
    let _ = fs::remove_dir_all(&dir);
    assert!(out.status.success(), "a clean tree must exit 0");
}

#[test]
fn unsupported_target_errors() {
    let dir = tmpdir("empty");
    // No supported manifest here -> detect() fails -> exit code 2 (error).
    let out = bin().arg(&dir).output().unwrap();
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unresolvable target should exit 2"
    );
}
