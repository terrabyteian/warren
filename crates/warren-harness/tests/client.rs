//! The client core end to end, in one process: sign in through the
//! control plane and a test IdP with a scripted browser, enroll the device
//! and wait for approval, get a certificate, then run the engine through a
//! relay and a connector that joined the same control plane, and reach an
//! app, see a block with its reason, and see an address outside every app
//! refused at once.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::Method;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use warren_client::control::{Account, OrgTrust};
use warren_client::device::KeyStorage;
use warren_client::engine::{Engine, EngineOptions, Event, NetworkSettings, Platform};
use warren_client::signin::{SignInOptions, sign_in};
use warren_client::state::Store;
use warren_connector::{Connector, ConnectorConfig};
use warren_control::ControlPlane;
use warren_control::config::Config;
use warren_control::web::Client;
use warren_core::audit::{AuditSink, NodeInfo};
use warren_core::bundle::{Bundle, IpNet, NodeState};
use warren_core::join::{JoinToken, NodeKey, sha256_hex};
use warren_core::packet;
use warren_core::quic::TransportTuning;
use warren_harness::deploy::{StaticResolver, UserspaceUdp, udp_echo};
use warren_harness::idp::{IdpUser, TestIdp};
use warren_masque::session::{RelayAddress, TransportMode};
use warren_relay::{Relay, RelayConfig};

const GROUPS: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: ConnectorGroup
metadata: { name: homelab }
spec:
  destinations:
    cidrs: ["10.77.0.0/24"]
  clientNames: ["*.lab.test"]
"#;

const APPS: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: echo }
spec:
  connectorGroup: homelab
  destinations:
    - cidr: 10.77.0.10/32
      ports: [7]
      protocol: udp
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: billing }
spec:
  connectorGroup: homelab
  discoverable: true
  destinations:
    - cidr: 10.77.0.30/32
      protocol: any
"#;

const POLICY: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata: { name: lab }
spec:
  rules:
    - name: eng-echo
      who: { groups: [eng] }
      what: { apps: [echo] }
---
apiVersion: warren.dev/v1alpha1
kind: AccessRequestPolicy
metadata: { name: billing-requests }
spec:
  who: { groups: [eng] }
  what: { apps: [billing] }
  approval:
    approvers: { groups: [finance] }
  maxDuration: 1h
"#;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "warren-{name}-{}",
        warren_core::keys::hex(&warren_core::keys::random_bytes::<6>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The browser: follows the sign-in redirects through the control plane
/// and the IdP, and finally calls the client's loopback listener.
async fn browse(start: String, roots: String) {
    let client = Client::new(Client::roots_from_pem(&roots).unwrap(), None).unwrap();
    let mut url = start;
    for _ in 0..5 {
        if let Some(rest) = url.strip_prefix("http://127.0.0.1:") {
            let (port, path) = rest.split_once('/').unwrap();
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap()))
                .await
                .unwrap();
            s.write_all(format!("GET /{path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut page = String::new();
            let _ = s.read_to_string(&mut page).await;
            assert!(page.contains("Signed in to warren"), "{page}");
            return;
        }
        let reply = client.request(Method::GET, &url, &[], None).await.unwrap();
        assert_eq!(
            reply.status,
            http::StatusCode::FOUND,
            "{url}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        url = reply.headers["location"].to_str().unwrap().to_owned();
    }
    panic!("too many redirects");
}

/// The platform: records settings and the packets the engine delivers.
#[derive(Debug)]
struct Recorder {
    settings: Mutex<Vec<NetworkSettings>>,
    delivered: mpsc::UnboundedSender<Vec<u8>>,
}

impl Platform for Recorder {
    fn deliver(&self, packet: &[u8]) {
        let _ = self.delivered.send(packet.to_vec());
    }

    fn apply(&self, s: &NetworkSettings) -> Result<Vec<String>, String> {
        self.settings.lock().unwrap().push(s.clone());
        Ok(Vec::new())
    }
}

async fn next_event(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(10), events.recv())
        .await
        .expect("an event in time")
        .expect("events open")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_in_enroll_and_reach_an_app_through_the_engine() {
    let dir = temp("client-e2e");
    let idp = TestIdp::start(
        "127.0.0.1:0".parse().unwrap(),
        "localhost",
        "warren",
        Some("s3cret"),
        IdpUser {
            sub: "00u-ada".into(),
            email: "ada@example.com".into(),
            groups: vec!["eng".into()],
            amr: vec!["pwd".into(), "mfa".into()],
        },
    )
    .await
    .unwrap();
    write(&dir.join("idp-ca.pem"), &idp.ca_pem);
    write(&dir.join("idp-secret"), "s3cret\n");
    write(&dir.join("policy/groups.yaml"), GROUPS);
    write(&dir.join("policy/apps.yaml"), APPS);
    write(&dir.join("policy/lab.yaml"), POLICY);
    let port = free_port();
    let config = Config::parse(&format!(
        "trustDomain: lab.test\n\
         publicUrl: https://localhost:{port}\n\
         listen: 127.0.0.1:{port}\n\
         dataDir: {d}/data\n\
         policyDir: {d}/policy\n\
         idp:\n  issuer: {issuer}\n  clientId: warren\n  clientSecretFile: {d}/idp-secret\n  caFile: {d}/idp-ca.pem\n\
         devices:\n  approval: manual\n\
         audit:\n  file: {d}/audit.jsonl\n",
        d = dir.display(),
        issuer = idp.issuer,
    ))
    .unwrap();
    let cp = ControlPlane::start(config).await.unwrap();
    let org = format!("https://localhost:{port}");
    let bundle_pem = cp.app().authority.trust_bundle();
    let root = {
        use rustls::pki_types::pem::PemObject;
        rustls::pki_types::CertificateDer::pem_slice_iter(bundle_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
    };
    let fingerprint = sha256_hex(&root);

    // Sign in, pinning the deployment root as an MDM profile would.
    let store = Store::open(&dir.join("client")).unwrap();
    let roots = format!("{bundle_pem}{}", idp.ca_pem);
    let opts = SignInOptions {
        org_url: org.clone(),
        trust: OrgTrust::Pinned(fingerprint.clone()),
        key_storage: Some(KeyStorage::File),
        fresh: false,
        timeout: Duration::from_secs(30),
    };
    let signed = sign_in(&store, opts.clone(), |url| {
        tokio::spawn(browse(url.to_owned(), roots.clone()));
    })
    .await
    .unwrap();
    assert_eq!(
        signed.account.profile.user.email.as_deref(),
        Some("ada@example.com")
    );
    assert_eq!(signed.device.status, "pending");
    assert_eq!(
        signed.pending.as_ref().unwrap().reason,
        "device_not_approved"
    );
    assert!(signed.certificate.is_none());
    let device = signed.device.id.clone();
    let user = signed.account.profile.user.id.clone();

    // A pinned root that is not the deployment's is refused before any
    // credential is sent.
    let mut wrong = opts.clone();
    wrong.trust = OrgTrust::Pinned("00".repeat(32));
    let err = sign_in(&Store::open(&dir.join("other")).unwrap(), wrong, |_| {})
        .await
        .unwrap_err();
    assert!(err.contains("pinned"), "{err}");

    // The engine says why it cannot start while the device waits.
    let recorder = Arc::new(Recorder {
        settings: Mutex::new(Vec::new()),
        delivered: mpsc::unbounded_channel().0,
    });
    let err = Engine::start(
        Account::load(&store).unwrap(),
        recorder.clone(),
        EngineOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.reason, "device_not_approved");
    assert!(err.message.contains(&device), "{}", err.message);

    // The admin approves the device; relay and connector join.
    let admin = |method: &'static str, path: String, body: Option<String>| {
        let socket = cp.admin_socket.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                warren_control::admin_request(&socket, method, &path, body).unwrap()
            })
            .await
            .unwrap()
        }
    };
    let (status, _) = admin("POST", format!("/v1/admin/devices/{device}/approve"), None).await;
    assert_eq!(status, 200);
    let mint = |role: &str, group: Option<&str>, name: &str, dns: &[&str]| {
        json!({ "role": role, "group": group, "name": name, "dns_names": dns }).to_string()
    };
    let (_, relay_token) = admin(
        "POST",
        "/v1/admin/join-tokens".into(),
        Some(mint("relay", None, "relay-1", &["relay.lab.test"])),
    )
    .await;
    let (_, conn_token) = admin(
        "POST",
        "/v1/admin/join-tokens".into(),
        Some(mint("connector", Some("homelab"), "lab-1", &[])),
    )
    .await;
    let token = |text: &str| {
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        JoinToken::parse(
            v["token"].as_str().unwrap(),
            warren_core::clock::now_secs().unsigned_abs(),
        )
        .unwrap()
    };
    let relay_joined =
        warren_masque::join::join(&token(&relay_token), &NodeKey::generate().unwrap())
            .await
            .unwrap();
    let conn_joined = warren_masque::join::join(&token(&conn_token), &NodeKey::generate().unwrap())
        .await
        .unwrap();

    // Until relays and connectors consume the control plane's bundles,
    // they load the same policy statically, naming the enrolled user and
    // device.
    let node_bundle = json!({
        "version": 1,
        "trustDomain": "lab.test",
        "connectorGroups": [{
            "name": "homelab",
            "destinations": { "cidrs": ["10.77.0.0/24"] },
            "clientNames": ["*.lab.test"]
        }],
        "apps": [
            { "name": "echo", "connectorGroup": "homelab",
              "destinations": [{ "cidr": "10.77.0.10/32", "ports": [7], "protocol": "udp" }] },
            { "name": "billing", "connectorGroup": "homelab", "discoverable": true,
              "destinations": [{ "cidr": "10.77.0.30/32", "protocol": "any" }] }
        ],
        "users": [{ "id": user, "groups": ["eng"] }],
        "devices": [{ "id": device, "approved": true }],
        "rules": [{ "id": "lab/eng-echo", "who": { "groups": ["eng"] }, "what": { "apps": ["echo"] } }]
    });
    let compiled = serde_json::from_value::<Bundle>(node_bundle)
        .unwrap()
        .compile()
        .unwrap();
    let state = NodeState::new(compiled);
    let relay = Relay::start(RelayConfig {
        listen_quic: "127.0.0.1:0".parse().unwrap(),
        listen_tcp: Some("127.0.0.1:0".parse().unwrap()),
        credentials: relay_joined.credentials,
        trust: Arc::new(relay_joined.trust),
        state: state.clone(),
        name: "relay-1".into(),
        peer_prefix: None,
        max_splices_per_client: 64,
        bind_rollover: warren_core::params::BIND_ROLLOVER,
        tuning: TransportTuning::default(),
    })
    .await
    .unwrap();
    let relay_addr = RelayAddress {
        name: "relay.lab.test".into(),
        quic: relay.quic_addr(),
        tcp: relay.tcp_addr().unwrap(),
    };
    let echo = udp_echo().await;
    let targets: HashMap<SocketAddr, SocketAddr> = [
        ("10.77.0.10:7".parse().unwrap(), echo),
        ("10.77.0.30:7".parse().unwrap(), echo),
    ]
    .into_iter()
    .collect();
    let (_backend, io) = UserspaceUdp::start(targets);
    let connector = Connector::start(
        ConnectorConfig {
            group: "homelab".into(),
            relays: vec![relay_addr.clone()],
            transport: TransportMode::QuicOnly,
            credentials: conn_joined.credentials,
            trust: Arc::new(conn_joined.trust),
            policy: Arc::new(warren_core::policy::StaticPolicy::new(state.clone())),
            state,
            audit: AuditSink::discard(NodeInfo {
                role: "connector".into(),
                name: "connector/homelab/lab-1".into(),
            }),
            resolver: Arc::new(StaticResolver::default()),
            synthetic_pools: Vec::new(),
            tunnel_mtu: warren_core::params::TUNNEL_MTU,
            tuning: TransportTuning::default(),
        },
        io,
    )
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while relay.metrics().attachments.get() < 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "connector never attached"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The engine gets a certificate and the entitlements, routes exactly
    // the entitled apps, and connects.
    let (tx, mut delivered) = mpsc::unbounded_channel();
    let recorder = Arc::new(Recorder {
        settings: Mutex::new(Vec::new()),
        delivered: tx,
    });
    let engine = Engine::start(
        Account::load(&store).unwrap(),
        recorder.clone(),
        EngineOptions {
            transport: TransportMode::QuicOnly,
            relays: Some(vec![relay_addr]),
            ..EngineOptions::default()
        },
    )
    .await
    .unwrap();
    let mut events = engine.subscribe();
    match next_event(&mut events).await {
        Event::Connected { group, relay, .. } => {
            assert_eq!(group, "homelab");
            assert_eq!(relay, "relay.lab.test");
        }
        other => panic!("expected a connection, got {other:?}"),
    }
    let settings = recorder.settings.lock().unwrap()[0].clone();
    let routes: Vec<String> = settings.routes.iter().map(ToString::to_string).collect();
    assert_eq!(routes, ["10.77.0.10/32", "10.77.0.30/32"]);
    let v4 = settings
        .addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .unwrap();
    let status = engine.status();
    assert_eq!(status.groups[0].state, "connected");
    assert_eq!(status.apps.len(), 2);
    assert!(status.certificate.is_some());

    // The app answers through the tunnel.
    let src = SocketAddr::new(v4, 40_000);
    engine.send(&packet::udp(src, "10.77.0.10:7".parse().unwrap(), b"hello"));
    let reply = tokio::time::timeout(Duration::from_secs(5), delivered.recv())
        .await
        .unwrap()
        .unwrap();
    let p = packet::parse(&reply).unwrap();
    assert_eq!(packet::udp_payload(&reply, &p).unwrap(), b"hello");

    // Renewal: a new certificate for the same key, which the live session
    // moves to without reconnecting.
    let before = engine.status().certificate.unwrap();
    engine.renew_now();
    loop {
        match next_event(&mut events).await {
            Event::Renewed { not_after } => {
                assert!(not_after >= before.not_after);
                break;
            }
            Event::Problem { message, .. } => panic!("renewal failed: {message}"),
            _ => continue,
        }
    }
    // Wait for the outer path to move to the renewed certificate, then
    // check the session still carries traffic.
    tokio::time::sleep(Duration::from_millis(500)).await;
    engine.send(&packet::udp(src, "10.77.0.10:7".parse().unwrap(), b"again"));
    let reply = tokio::time::timeout(Duration::from_secs(5), delivered.recv())
        .await
        .unwrap()
        .unwrap();
    let p = packet::parse(&reply).unwrap();
    assert_eq!(packet::udp_payload(&reply, &p).unwrap(), b"again");
    assert_eq!(engine.status().groups[0].state, "connected");

    // Signing in again while the engine runs: its next renewal, even one
    // right after the last, uses the new session.
    let again = sign_in(&store, opts.clone(), |url| {
        tokio::spawn(browse(url.to_owned(), roots.clone()));
    })
    .await
    .unwrap();
    assert!(again.reused_key);
    let session = again.account.profile.session.clone();
    assert_ne!(session.id, signed.account.profile.session.id);
    engine.renew_now();
    loop {
        match next_event(&mut events).await {
            Event::Renewed { .. } => break,
            Event::Problem { message, .. } => panic!("renewal failed: {message}"),
            _ => continue,
        }
    }
    let renewed = store.certificate().unwrap().unwrap();
    let id = warren_core::pki::check_client_profile(&renewed.chain[0], "lab.test").unwrap();
    assert_eq!(id.identity.session_id, session.id);
    assert_eq!(engine.status().session_expires_at, session.expires_at);

    // A requestable app is blocked by the connector, with its reason.
    engine.send(&packet::udp(src, "10.77.0.30:7".parse().unwrap(), b"pay"));
    loop {
        match next_event(&mut events).await {
            Event::Blocked {
                reason, app, flow, ..
            } => {
                assert_eq!(reason, "request_access");
                assert_eq!(app.as_deref(), Some("billing"));
                assert_eq!(flow, "udp 10.77.0.30:7");
                break;
            }
            Event::Notice { .. } | Event::PathChanged { .. } => continue,
            other => panic!("expected a block, got {other:?}"),
        }
    }

    // An address outside every app is refused locally, at once.
    let stray: IpNet = "10.99.0.0/24".parse().unwrap();
    engine.send(&packet::udp(src, SocketAddr::new(stray.addr, 53), b"stray"));
    loop {
        match next_event(&mut events).await {
            Event::Blocked { reason, .. } => {
                assert_eq!(reason, "not_an_app");
                break;
            }
            Event::Notice { .. } | Event::PathChanged { .. } => continue,
            other => panic!("expected a local refusal, got {other:?}"),
        }
    }
    loop {
        let answer = tokio::time::timeout(Duration::from_secs(5), delivered.recv())
            .await
            .unwrap()
            .unwrap();
        let a = packet::parse(&answer).unwrap();
        if a.dst == v4 && a.is_icmp_error() {
            break;
        }
    }

    engine.stop().await;
    drop(connector);
    let _ = std::fs::remove_dir_all(&dir);
}
