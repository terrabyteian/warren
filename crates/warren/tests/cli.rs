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

#[cfg(feature = "control-plane")]
#[test]
fn policy_check_compiles_the_documented_examples() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/examples/policy");
    let out = warren(&["policy", "check", dir]);
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(out.status.success(), "{stderr}");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        stdout.contains("@id(\"observability/engineers-view-grafana\")"),
        "{stdout}"
    );
    // The documented rule that lists posture with browser draws a warning.
    assert!(stderr.contains("warning"), "{stderr}");
}

#[cfg(feature = "control-plane")]
#[test]
fn policy_check_reports_problems_by_file_and_line() {
    let dir = std::env::temp_dir().join(format!("warren-cli-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(
        dir.join("bad.yaml"),
        "apiVersion: warren.dev/v1alpha1\nkind: App\nmetadata:\n  name: Bad\n",
    )
    .expect("write");
    let out = warren(&["policy", "check", dir.to_str().expect("utf-8 path")]);
    std::fs::remove_dir_all(&dir).ok();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("bad.yaml:4: error"), "{stderr}");
}

#[cfg(feature = "control-plane")]
#[test]
fn control_plane_and_admin_fail_with_a_reason() {
    let out = warren(&["control-plane", "--config", "/nonexistent/warren.yaml"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("/nonexistent/warren.yaml"), "{stderr}");

    let out = warren(&[
        "admin",
        "--socket",
        "/nonexistent/admin.sock",
        "users",
        "list",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("admin socket"), "{stderr}");
}
