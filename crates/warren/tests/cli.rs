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
fn relay_without_credentials_fails_with_usage() {
    let out = warren(&["relay"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("--cert"), "{stderr}");
}

#[cfg(feature = "connector")]
#[test]
fn connector_with_missing_files_fails_with_a_reason() {
    let out = warren(&[
        "connector",
        "--group",
        "homelab",
        "--relay",
        "relay.example.test@127.0.0.1:443",
        "--cert",
        "/nonexistent/c.pem",
        "--key",
        "/nonexistent/c.key",
        "--trust-bundle",
        "/nonexistent",
        "--bundle",
        "/nonexistent/bundle.json",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("bundle.json"), "{stderr}");
}
