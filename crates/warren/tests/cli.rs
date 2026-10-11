//! Runs the built `warren` binary the way an operator would.

use std::process::Command;

fn warren(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_warren"))
        .args(args)
        .output()
        .expect("run warren")
}

#[test]
fn version_succeeds() {
    let out = warren(&["--version"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert_eq!(stdout.trim(), concat!("warren ", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_succeeds() {
    let out = warren(&["--help"]);
    assert!(out.status.success());
}

#[test]
fn bare_invocation_prints_help_and_fails() {
    let out = warren(&[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("Usage:"), "{stderr}");
}

#[cfg(feature = "relay")]
#[test]
fn unimplemented_role_fails_with_a_reason() {
    let out = warren(&["relay"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("not implemented yet"), "{stderr}");
}
