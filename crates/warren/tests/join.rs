//! `warren relay --join-token` and `warren connector --join-token` join a
//! running control plane with tokens `warren admin join-token create`
//! mints, and keep a certificate chain the data path's own checks accept.

#![cfg(all(feature = "control-plane", feature = "relay", feature = "connector"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use warren_control::ControlPlane;
use warren_control::config::Config;
use warren_core::cert::{self, CertSpec};
use warren_core::identity::NodeRole;
use warren_core::keys::{SigningKey, hex, random_bytes};
use warren_core::pki::{self, Issuer, TrustBundle};

const TRUST_DOMAIN: &str = "example.test";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "warren-join-{}",
            hex(&random_bytes::<6>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn warren(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_warren"));
    cmd.args(args);
    cmd
}

/// Mints a token with the admin CLI and returns it.
fn mint(socket: &Path, args: &[&str]) -> String {
    let socket = socket.to_str().unwrap();
    let mut all = vec!["admin", "--socket", socket, "join-token", "create"];
    all.extend_from_slice(args);
    let out = warren(&all).output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let start = stdout.find("warren-join-v1.").expect("a join token");
    let rest = &stdout[start..];
    rest[..rest.find('"').unwrap()].to_owned()
}

/// Runs a node with `args` until its join has left a certificate in
/// `state`, then stops it.
fn join_with(args: &[&str], state: &Path) {
    let mut child = warren(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !state.join("cert.pem").exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
            panic!("the node exited ({status}) before joining: {err}");
        }
        assert!(Instant::now() < deadline, "no join within 30 seconds");
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The joined node's leaf, verified the way nodes verify each other.
fn joined(state: &Path, server_use: bool) -> pki::NodeIdentity {
    let trust = TrustBundle::load_dir(TRUST_DOMAIN, &state.join("trust")).unwrap();
    let chain = pki::load_chain(&state.join("cert.pem")).unwrap();
    trust
        .verify_chain(
            &chain[0],
            Issuer::Infrastructure,
            server_use,
            pki::unix_time(std::time::SystemTime::now()),
        )
        .unwrap();
    pki::check_infra_profile(&chain[0], TRUST_DOMAIN).unwrap()
}

#[test]
fn relays_and_connectors_join_with_minted_tokens() {
    let dir = TempDir::new();
    let path = |p: &str| dir.0.join(p);
    // An IdP CA file, so the control plane starts without reading the
    // system store; nothing here signs in.
    let key = SigningKey::generate().unwrap();
    let spki = cert::p256_spki(key.public_key().point());
    let idp_ca = cert::issue(
        &CertSpec::ca("unused IdP CA"),
        &spki,
        &cert::name(Some("unused IdP CA")),
        &cert::spki_key_id(&spki).unwrap(),
        |tbs| key.sign_der(tbs),
    )
    .unwrap();
    std::fs::write(
        path("idp-ca.pem"),
        warren_core::base64::pem("CERTIFICATE", &idp_ca),
    )
    .unwrap();
    std::fs::create_dir_all(path("policy")).unwrap();
    std::fs::write(
        path("policy/groups.yaml"),
        "apiVersion: warren.dev/v1alpha1\nkind: ConnectorGroup\nmetadata: { name: homelab }\nspec:\n  destinations:\n    cidrs: [\"10.20.0.0/16\"]\n",
    )
    .unwrap();
    let bundle = path("bundle.json");
    std::fs::write(
        &bundle,
        format!(r#"{{"version":1,"trustDomain":"{TRUST_DOMAIN}"}}"#),
    )
    .unwrap();
    let port = free_port();
    let config = Config::parse(&format!(
        "trustDomain: {TRUST_DOMAIN}\n\
         publicUrl: https://localhost:{port}\n\
         listen: 127.0.0.1:{port}\n\
         dataDir: {data}\n\
         policyDir: {policy}\n\
         idp:\n  issuer: https://idp.example.test\n  clientId: warren\n  caFile: {ca}\n",
        data = path("data").display(),
        policy = path("policy").display(),
        ca = path("idp-ca.pem").display(),
    ))
    .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let cp = runtime.block_on(ControlPlane::start(config)).unwrap();
    let root = cp.app().authority.root.der.clone();
    let socket = cp.admin_socket.clone();
    let bundle = bundle.to_str().unwrap();

    let token = mint(
        &socket,
        &[
            "--role",
            "relay",
            "--name",
            "relay-1",
            "--dns-name",
            "relay1.example.test",
        ],
    );
    let relay_state = path("relay");
    join_with(
        &[
            "relay",
            "--join-token",
            &token,
            "--state-dir",
            relay_state.to_str().unwrap(),
            "--bundle",
            bundle,
            "--listen",
            "127.0.0.1:0",
            "--no-tcp",
        ],
        &relay_state,
    );
    let relay = joined(&relay_state, true);
    assert_eq!(relay.role, NodeRole::Relay);
    assert_eq!(relay.dns_names, ["relay1.example.test"]);
    let trust = TrustBundle::load_dir(TRUST_DOMAIN, &relay_state.join("trust")).unwrap();
    assert_eq!(trust.root.as_ref(), root.as_slice());

    let token = mint(
        &socket,
        &[
            "--role",
            "connector",
            "--group",
            "homelab",
            "--name",
            "lab-1",
        ],
    );
    let connector_state = path("connector");
    join_with(
        &[
            "connector",
            "--group",
            "homelab",
            "--relay",
            "relay1.example.test@127.0.0.1:9",
            "--join-token",
            &token,
            "--state-dir",
            connector_state.to_str().unwrap(),
            "--bundle",
            bundle,
        ],
        &connector_state,
    );
    let connector = joined(&connector_state, false);
    assert_eq!(
        connector.role,
        NodeRole::Connector {
            group: "homelab".into()
        }
    );
    assert_ne!(connector.id, relay.id);

    // A spent token admits nobody else.
    let again = path("again");
    let out = warren(&[
        "connector",
        "--group",
        "homelab",
        "--relay",
        "relay1.example.test@127.0.0.1:9",
        "--join-token",
        &token,
        "--state-dir",
        again.to_str().unwrap(),
        "--bundle",
        bundle,
    ])
    .output()
    .unwrap();
    assert!(!out.status.success());
    assert!(!again.join("cert.pem").exists());
    runtime.block_on(cp.shutdown());
}
