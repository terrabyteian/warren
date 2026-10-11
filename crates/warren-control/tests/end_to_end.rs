//! The control plane end to end: sign in through an OIDC provider, enroll
//! and approve a device, get a user+device certificate, receive
//! entitlements, join relays and connectors, verify signed bundles, and
//! watch revocations reach a stub connector within the 10-second deadline
//! (G9).

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::{Method, StatusCode};
use serde_json::{Value, json};
use support::{IdpUser, RunningIdp, StubNode, TempDir, TestClient, free_port, pem_certs, write};
use tokio::sync::mpsc;
use warren_control::config::Config;
use warren_control::{ControlPlane, admin_request, audit};
use warren_core::cert;
use warren_core::clock;
use warren_core::events::{EventBody, Line};
use warren_core::identity::{AUTH_TIME_UNKNOWN, NodeRole, TrustClass};
use warren_core::join::{JoinToken, sha256_hex};
use warren_core::keys::SigningKey;
use warren_core::params::REVOCATION_DEADLINE;
use warren_core::pki;
use warren_core::policy_bundle::{Bundle, View};

const GROUP: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: ConnectorGroup
metadata: { name: homelab }
spec:
  destinations:
    domains: ["*.lab.example.com"]
    cidrs: ["10.20.0.0/16"]
  clientNames: ["*.lab.example.com"]
"#;

const APPS: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: App
metadata:
  name: grafana
  labels: { team: observability }
spec:
  connectorGroup: homelab
  destinations:
    - host: grafana.lab.example.com
      ports: [443]
      protocol: tcp
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: billing }
spec:
  connectorGroup: homelab
  destinations:
    - host: billing.lab.example.com
      ports: [443]
      protocol: tcp
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: lab-network }
spec:
  connectorGroup: homelab
  destinations:
    - cidr: 10.20.0.0/24
      protocol: icmp
"#;

const POLICY: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata: { name: base }
spec:
  rules:
    - name: engineers-grafana
      who: { groups: [engineering] }
      what: { apps: [grafana, lab-network] }
      when:
        auth: { maxAge: 12h, mfa: true }
    - name: finance-billing
      who: { groups: [finance] }
      what: { apps: [billing] }
"#;

struct Deployment {
    dir: TempDir,
    idp: RunningIdp,
    cp: ControlPlane,
    audit: Arc<Mutex<Vec<u8>>>,
    base: String,
    bundle: String,
}

impl Deployment {
    async fn start(approval: &str) -> Deployment {
        let dir = TempDir::new("e2e");
        let idp = RunningIdp::start(IdpUser {
            sub: "00u-ada".into(),
            email: "Ada@Example.com".into(),
            groups: vec!["engineering".into()],
            amr: vec!["pwd".into(), "mfa".into()],
        })
        .await;
        write(&dir.path().join("policy/groups.yaml"), GROUP);
        write(&dir.path().join("policy/apps.yaml"), APPS);
        write(&dir.path().join("policy/base.yaml"), POLICY);
        write(&dir.path().join("idp-ca.pem"), &idp.pki.ca_pem);
        write(&dir.path().join("idp-secret"), "s3cret\n");
        let port = free_port();
        let config_text = format!(
            "trustDomain: example.test\n\
             publicUrl: https://localhost:{port}\n\
             listen: 127.0.0.1:{port}\n\
             dataDir: {data}\n\
             policyDir: {dir}/policy\n\
             idp:\n  issuer: {issuer}\n  clientId: warren\n  clientSecretFile: {dir}/idp-secret\n  caFile: {dir}/idp-ca.pem\n\
             devices:\n  approval: {approval}\n\
             certificates:\n  clientLifetime: 4h\n",
            data = dir.path().join("data").display(),
            dir = dir.path().display(),
            issuer = idp.idp.issuer,
        );
        let config = Config::parse(&config_text).unwrap();
        let audit = Arc::new(Mutex::new(Vec::new()));
        let cp = ControlPlane::start_with_audit(config, Some(audit::Sink::memory(audit.clone())))
            .await
            .unwrap();
        let bundle = cp.app().authority.trust_bundle();
        Deployment {
            base: format!("https://localhost:{port}"),
            dir,
            idp,
            cp,
            audit,
            bundle,
        }
    }

    fn client(&self) -> TestClient {
        TestClient::new(&self.base, &self.bundle, &self.idp.pki.ca_pem)
    }

    /// Calls the admin socket the way `warren admin` does.
    async fn admin(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let socket = self.cp.admin_socket.clone();
        let method = method.to_owned();
        let path = path.to_owned();
        let (status, text) = tokio::task::spawn_blocking(move || {
            admin_request(&socket, &method, &path, body.map(|b| b.to_string())).unwrap()
        })
        .await
        .unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    fn audit_records(&self) -> Vec<Value> {
        let text = String::from_utf8(self.audit.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Mints a join token, as `warren admin join-token create` does.
    async fn mint(
        &self,
        role: &str,
        group: Option<&str>,
        name: &str,
        dns: &[&str],
    ) -> (u16, Value) {
        self.admin(
            "POST",
            "/v1/admin/join-tokens",
            Some(json!({ "role": role, "group": group, "name": name, "dns_names": dns })),
        )
        .await
    }

    async fn join(&self, role: &str, group: Option<&str>, name: &str, dns: &[&str]) -> StubNode {
        let (status, body) = self.mint(role, group, name, dns).await;
        assert_eq!(status, 201, "{body}");
        let token = body["token"].as_str().unwrap();
        // The token pins the root CA and names where nodes join.
        let parsed = JoinToken::parse(token, clock::now_secs().unsigned_abs()).unwrap();
        let root = pem_certs(&self.bundle).remove(0);
        assert_eq!(parsed.root, sha256_hex(&root));
        assert_eq!(format!("https://{}", parsed.cp), self.base);
        StubNode::join(&self.base, token).await.unwrap()
    }
}

/// Fetches the connector bundle until one newer than `held` satisfies
/// `want`, failing after the revocation deadline.
async fn wait_for_bundle(
    node: &StubNode,
    key: &warren_core::keys::PublicKey,
    held: u64,
    want: impl Fn(&Bundle) -> bool,
) -> Bundle {
    let deadline = Instant::now() + REVOCATION_DEADLINE;
    loop {
        let jws = String::from_utf8(node.get("/v1/node/bundle").await.body.to_vec()).unwrap();
        let bundle =
            Bundle::verify(&jws, key, "example.test", View::Connector, Some(held)).unwrap();
        if want(&bundle) {
            return bundle;
        }
        assert!(
            Instant::now() < deadline,
            "no matching bundle within the deadline"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn next_event(
    rx: &mut mpsc::UnboundedReceiver<support::Received>,
    want: impl Fn(&EventBody) -> bool,
) -> (support::Received, warren_core::events::Event) {
    let deadline = Instant::now() + REVOCATION_DEADLINE;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let received = tokio::time::timeout(left, rx.recv())
            .await
            .expect("the event did not arrive within the revocation deadline")
            .expect("the event stream ended");
        if let Line::Event(e) = &received.line
            && want(&e.body)
        {
            let e = e.clone();
            return (received, e);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_in_enroll_certify_and_revoke() {
    let d = Deployment::start("manual").await;

    // Discovery hands out the trust bundle and endpoints.
    let mut client = d.client();
    let discovery: warren_core::api::Discovery =
        client.get("/.well-known/warren").await.json().unwrap();
    assert_eq!(discovery.trust_domain, "example.test");
    assert_eq!(discovery.trust_bundle, d.bundle);
    assert_eq!(
        discovery.authorize_endpoint,
        format!("{}/v1/auth/authorize", d.base)
    );

    // Sign in through the IdP; the session is bound to the device key.
    let session = client.sign_in().await;
    assert_eq!(session.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(session.user.groups, ["engineering"]);
    assert!(session.mfa);
    assert!(session.token.starts_with("wst_"));

    // A one-time code works once.
    let q = d.client().browser_sign_in().await;
    let mut other = d.client();
    assert_eq!(
        other.exchange(&q["code"], &q["verifier"]).await.status,
        StatusCode::OK
    );
    let replay = other.exchange(&q["code"], &q["verifier"]).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    let problem: Value = serde_json::from_slice(&replay.body).unwrap();
    assert_eq!(problem["reason"], "invalid_grant");
    // A wrong PKCE verifier fails too.
    let q = d.client().browser_sign_in().await;
    assert_eq!(
        other.exchange(&q["code"], &"x".repeat(43)).await.status,
        StatusCode::BAD_REQUEST
    );

    // Enroll: the device waits for an admin.
    let (status, device) = client.enroll().await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(device["status"], "pending");
    assert_eq!(device["tunnel_v4"], "100.96.0.1");
    let device_id = device["id"].as_str().unwrap().to_owned();

    // No certificate until it is approved, and the refusal says why.
    let (status, problem) = client.certificate().await.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["reason"], "device_not_approved");
    assert!(problem["detail"].as_str().unwrap().contains("approve"));

    // A CSR from another key is refused: the session is bound to this key.
    let mut stranger = d.client();
    stranger.session = client.session.clone();
    let (status, problem) = stranger.certificate().await.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["reason"], "key_mismatch");

    // Disabling and re-enabling a pending device never skips approval, and
    // a disabled device cannot be approved directly.
    let device_admin = |action: &str| format!("/v1/admin/devices/{device_id}/{action}");
    d.admin("POST", &device_admin("disable"), None).await;
    let (status, _) = d.admin("POST", &device_admin("approve"), None).await;
    assert_eq!(status, 409);
    d.admin("POST", &device_admin("enable"), None).await;
    assert_eq!(client.device().await.status, "pending");

    let (status, body) = d
        .admin(
            "POST",
            &format!("/v1/admin/devices/{device_id}/approve"),
            None,
        )
        .await;
    assert_eq!((status, body["changed"].clone()), (200, json!(true)));
    assert_eq!(client.device().await.status, "approved");

    // The certificate follows the profile.
    let asked = clock::now_secs();
    let issued = client.certificate().await.unwrap();
    let answered = clock::now_secs();
    let chain = pem_certs(&issued.certificate_chain);
    assert_eq!(chain.len(), 2);
    let app = d.cp.app();
    assert_eq!(chain[1], app.authority.client.der);
    // It chains to the root through the client CA only, and passes the
    // profile connectors check (empty subject, critical SAN, clientAuth
    // only, the identity extension).
    let leaf = rustls::pki_types::CertificateDer::from(chain[0].clone());
    let at = pki::unix_time(std::time::SystemTime::now());
    let bundle = &app.authority.bundle;
    bundle
        .verify_chain(&leaf, pki::Issuer::Client, false, at)
        .unwrap();
    assert!(
        bundle
            .verify_chain(&leaf, pki::Issuer::Infrastructure, false, at)
            .is_err()
    );
    let profile = pki::check_client_profile(&chain[0], "example.test").unwrap();
    assert_eq!(
        profile.spki,
        cert::p256_spki(client.key.public_key().point())
    );
    let cert = pki::parse_cert(&chain[0]).unwrap();
    assert!(cert.not_after - cert.not_before <= 4 * 3600 + 120);
    assert!(cert.not_after - clock::now_secs() <= 4 * 3600);
    // Half-life counts from issuance, not from the backdated notBefore.
    assert!(cert.not_before < asked);
    assert!(
        (asked + cert.not_after) / 2 <= issued.renew_at
            && issued.renew_at <= (answered + cert.not_after) / 2,
        "{} not half-way from issuance to {}",
        issued.renew_at,
        cert.not_after
    );
    let user_id = session.user.id.clone();
    assert_eq!((&profile.user, &profile.device), (&user_id, &device_id));
    let identity = &profile.identity;
    assert_eq!(identity.session_id, session.session_id);
    assert!(identity.mfa);
    assert_eq!(identity.auth_time, session.auth_time as u64);
    assert_eq!(identity.trust_class, TrustClass::DeviceReported);
    assert_eq!(identity.tunnel_v4.to_string(), "100.96.0.1");

    // Entitlements name only what Ada may reach.
    let ent = client.entitlements().await;
    let names: Vec<&str> = ent.apps.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["grafana", "lab-network"]);
    assert!(ent.apps.iter().all(|a| a.access == "allowed"));
    assert!(!serde_json::to_string(&ent).unwrap().contains("billing"));
    assert_eq!(ent.dns_suffixes, ["grafana.lab.example.com"]);

    // The admin socket is private to the control plane's user.
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&d.cp.admin_socket)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // No node may be issued the control plane's own name.
    let (status, refused) = d.mint("relay", None, "impostor", &["localhost"]).await;
    assert_eq!(
        (status, refused["reason"].clone()),
        (409, json!("name_reserved"))
    );

    // A relay and a connector join; each token works once.
    let relay = d
        .join("relay", None, "relay-1", &["relay1.example.test"])
        .await;
    let connector = d.join("connector", Some("homelab"), "lab-1", &[]).await;
    assert_eq!(
        connector.role,
        NodeRole::Connector {
            group: "homelab".into()
        }
    );
    // The chain verifies as main's nodes verify it: through the
    // infrastructure CA, for both TLS roles, in the infrastructure profile.
    let node_leaf = rustls::pki_types::CertificateDer::from(connector.chain[0].clone());
    let at = pki::unix_time(std::time::SystemTime::now());
    for server_use in [false, true] {
        connector
            .trust
            .verify_chain(&node_leaf, pki::Issuer::Infrastructure, server_use, at)
            .unwrap();
    }
    let node_uri = format!("warren://example.test/connector/homelab/{}", connector.id);
    assert_eq!(
        pki::parse_cert(&connector.chain[0])
            .unwrap()
            .subject_alt_names()
            .unwrap()
            .uris,
        std::slice::from_ref(&node_uri)
    );
    let (_, token) = d.mint("connector", Some("homelab"), "lab-2", &[]).await;
    let token = token["token"].as_str().unwrap();
    StubNode::join(&d.base, token).await.unwrap();
    let reused = StubNode::join(&d.base, token).await.err().unwrap();
    assert!(reused.contains("(401)"), "{reused}");
    // Entitlements now list the relay.
    let ent = client.entitlements().await;
    assert_eq!(ent.relays.len(), 1);
    assert_eq!(ent.relays[0].dns_names, ["relay1.example.test"]);

    // Node endpoints refuse clients without an infrastructure certificate.
    assert_eq!(
        client.get("/v1/node/bundle").await.status,
        StatusCode::UNAUTHORIZED
    );

    // Bundles verify with the policy key from the join, per view.
    let policy_key = connector.policy_key.to_key().unwrap();
    let reply = connector.get("/v1/node/bundle").await;
    assert_eq!(reply.status, StatusCode::OK);
    let jws = String::from_utf8(reply.body.to_vec()).unwrap();
    let bundle = Bundle::verify(&jws, &policy_key, "example.test", View::Connector, None).unwrap();
    let policy = bundle.policy.as_ref().unwrap();
    assert!(policy.policies.contains("@id(\"base/engineers-grafana\")"));
    assert!(
        bundle
            .devices
            .iter()
            .any(|dv| dv.id == device_id && dv.users == [user_id.clone()])
    );
    assert!(
        bundle
            .entities
            .as_ref()
            .unwrap()
            .to_string()
            .contains(&user_id)
    );
    assert!(bundle.keys.contains_key("posture"));
    let relay_jws = String::from_utf8(relay.get("/v1/node/bundle").await.body.to_vec()).unwrap();
    let relay_bundle =
        Bundle::verify(&relay_jws, &policy_key, "example.test", View::Relay, None).unwrap();
    assert!(
        relay_bundle.policy.is_none()
            && relay_bundle.entities.is_none()
            && relay_bundle.devices.is_empty()
    );
    assert_eq!(relay_bundle.version, bundle.version);
    assert!(
        Bundle::verify(
            &relay_jws,
            &policy_key,
            "example.test",
            View::Connector,
            None
        )
        .is_err()
    );

    // The connector holds the revocation stream from now on.
    let mut events = connector.events(None).await;
    let first = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    let Line::Snapshot(snapshot) = first.line else {
        panic!(
            "a fresh stream starts with a snapshot, got {:?}",
            first.line
        )
    };
    assert!(snapshot.revocations.users.is_empty());
    // Heartbeats keep an idle stream alive.
    let heartbeat = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if matches!(events.recv().await.unwrap().line, Line::Heartbeat { .. }) {
                return;
            }
        }
    })
    .await;
    assert!(
        heartbeat.is_ok(),
        "no heartbeat within three heartbeat intervals"
    );

    // Disabling the user reaches the connector within the deadline.
    let started = Instant::now();
    let (status, _) = d
        .admin("POST", "/v1/admin/users/ada@example.com/disable", None)
        .await;
    assert_eq!(status, 200);
    let (received, event) = next_event(
        &mut events,
        |b| matches!(b, EventBody::UserDisabled { user_id: u } if *u == user_id),
    )
    .await;
    let commit_to_receipt = received.at_ms - event.committed_at_ms;
    assert!(received.at.duration_since(started) < REVOCATION_DEADLINE);
    assert!(
        (0..REVOCATION_DEADLINE.as_millis() as i64).contains(&commit_to_receipt),
        "{commit_to_receipt} ms"
    );
    eprintln!("user_disabled: commit to receipt {commit_to_receipt} ms");
    assert_eq!(
        connector.ack(event.seq, received.at_ms, 1).await.status,
        StatusCode::OK
    );

    // The disabled user can do nothing on link D, and the reason is clear.
    let (status, problem) = client.certificate().await.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["reason"], "user_disabled");
    // A bundle that drops the user follows.
    let newer = wait_for_bundle(&connector, &policy_key, bundle.version, |b| {
        b.revocations.users.contains(&user_id)
    })
    .await;
    assert!(
        !newer
            .entities
            .as_ref()
            .unwrap()
            .to_string()
            .contains(&user_id)
    );

    // Device disable, session revoke and certificate revoke all push.
    let started = Instant::now();
    d.admin(
        "POST",
        &format!("/v1/admin/devices/{device_id}/disable"),
        None,
    )
    .await;
    let (received, event) = next_event(&mut events, |b| matches!(b, EventBody::DeviceDisabled { device_id: x, revoked: false } if *x == device_id)).await;
    assert!(received.at.duration_since(started) < REVOCATION_DEADLINE);
    assert_eq!(
        connector.ack(event.seq, received.at_ms, 0).await.status,
        StatusCode::OK
    );
    let (_, sessions) = d
        .admin("GET", &format!("/v1/admin/users/{user_id}/sessions"), None)
        .await;
    let session_id = sessions[0]["id"].as_str().unwrap().to_owned();
    d.admin(
        "POST",
        &format!("/v1/admin/sessions/{session_id}/revoke"),
        None,
    )
    .await;
    let (received, event) = next_event(
        &mut events,
        |b| matches!(b, EventBody::SessionRevoked { session_id: x } if *x == session_id),
    )
    .await;
    assert_eq!(
        connector.ack(event.seq, received.at_ms, 0).await.status,
        StatusCode::OK
    );
    d.admin(
        "POST",
        &format!("/v1/admin/certificates/{}/revoke", issued.serial),
        None,
    )
    .await;
    let (_, event) = next_event(
        &mut events,
        |b| matches!(b, EventBody::CertificateRevoked { serial, .. } if *serial == issued.serial),
    )
    .await;
    let EventBody::CertificateRevoked { not_after, .. } = event.body else {
        unreachable!()
    };
    assert_eq!(not_after, issued.not_after);

    // A policy change ships as a new bundle and says so on the stream.
    write(
        &d.dir.path().join("policy/base.yaml"),
        &POLICY.replace(
            "what: { apps: [grafana, lab-network] }",
            "what: { apps: [grafana] }",
        ),
    );
    let (status, status_body) = d.admin("POST", "/v1/admin/policy/reload", None).await;
    assert_eq!(status, 200, "{status_body}");
    let (_, event) = next_event(
        &mut events,
        |b| matches!(b, EventBody::BundleUpdated { digest, .. } if *digest != policy.digest),
    )
    .await;
    let EventBody::BundleUpdated { version, digest } = event.body else {
        unreachable!()
    };
    let changed = wait_for_bundle(&connector, &policy_key, newer.version, |b| {
        b.version >= version
    })
    .await;
    assert_eq!(changed.policy.as_ref().unwrap().digest, digest);
    assert!(!changed.policy.unwrap().policies.contains("lab-network"));

    // A broken policy is refused and the previous one stays in force.
    write(
        &d.dir.path().join("policy/broken.yaml"),
        "apiVersion: warren.dev/v1alpha1\nkind: App\nmetadata: { name: Bad }\n",
    );
    let (status, body) = d.admin("POST", "/v1/admin/policy/reload", None).await;
    assert_eq!(status, 422);
    assert!(
        body["errors"][0]
            .as_str()
            .unwrap()
            .contains("broken.yaml:3"),
        "{body}"
    );
    let (_, now_status) = d.admin("GET", "/v1/admin/policy", None).await;
    assert_eq!(now_status["digest"], json!(digest));

    // Revoking a node pushes an event and closes its own stream.
    let mut relay_events = relay.events(None).await;
    relay_events.recv().await.unwrap();
    d.admin(
        "POST",
        &format!("/v1/admin/nodes/{}/revoke", relay.id),
        None,
    )
    .await;
    let (_, event) = next_event(&mut events, |b| matches!(b, EventBody::NodeRevoked { .. })).await;
    assert_eq!(
        connector
            .ack(event.seq, clock::now_millis(), 0)
            .await
            .status,
        StatusCode::OK
    );
    let closed = tokio::time::timeout(REVOCATION_DEADLINE, async {
        while relay_events.recv().await.is_some() {}
    })
    .await;
    assert!(closed.is_ok(), "the revoked relay's stream stayed open");
    assert_eq!(
        relay.get("/v1/node/bundle").await.status,
        StatusCode::FORBIDDEN
    );
    let refused = d
        .audit_records()
        .into_iter()
        .find(|r| r["message"] == "relay or connector refused: this node has been revoked")
        .expect("the revoked relay's refusal is audited");
    assert_eq!(refused["status"], "Failure");
    assert!(
        refused["unmapped"]["certificate_uris"][0]
            .as_str()
            .unwrap()
            .contains(&relay.id)
    );

    // A node resuming from a retained sequence number gets what it missed.
    let mut resumed = connector.events(Some(event.seq - 1)).await;
    let (_, again) = next_event(&mut resumed, |b| matches!(b, EventBody::NodeRevoked { .. })).await;
    assert_eq!(again.seq, event.seq);

    // The revoked relay's certificate is in the revocation state by serial,
    // and reusing its name does not drop the node's revocation.
    let relay_serial = relay.serial.clone();
    let after_revoke = wait_for_bundle(&connector, &policy_key, changed.version, |b| {
        b.revocations
            .certificates
            .iter()
            .any(|c| c.serial == relay_serial)
            && b.revocations.nodes.contains(&relay.id)
    })
    .await;
    let reused = d
        .join("relay", None, "relay-1", &["relay1.example.test"])
        .await;
    let kept = wait_for_bundle(&connector, &policy_key, after_revoke.version, |b| {
        b.nodes.iter().any(|n| n.id == reused.id)
    })
    .await;
    assert!(kept.revocations.nodes.contains(&relay.id));

    // Revoking a node's certificate by serial closes that node's stream.
    let lab4 = d.join("connector", Some("homelab"), "lab-4", &[]).await;
    let mut lab4_events = lab4.events(None).await;
    lab4_events.recv().await.unwrap();
    d.admin(
        "POST",
        &format!("/v1/admin/certificates/{}/revoke", lab4.serial),
        None,
    )
    .await;
    let closed = tokio::time::timeout(REVOCATION_DEADLINE, async {
        while lab4_events.recv().await.is_some() {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "a stream outlived the revocation of its certificate"
    );

    // The commit-to-cut metric counts the acknowledgements.
    let (_, latency) = d.admin("GET", "/v1/admin/revocation-latency", None).await;
    assert!(
        latency["commit_to_cut"]["count"].as_u64().unwrap() >= 4,
        "{latency}"
    );
    assert_eq!(latency["commit_to_cut"]["over_deadline"], 0);
    assert_eq!(latency["deadline_ms"], 10_000);

    // Decision logs from the connector reach the audit sink, stamped with
    // the node that sent them.
    let record = json!({ "class_uid": 3005, "time": clock::now_millis(), "activity_id": 1, "message": "flow allowed", "metadata": { "log_provider": "someone else" } });
    let reply = connector
        .post(
            "/v1/node/audit",
            "application/x-ndjson",
            format!("{record}\n").into_bytes(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    let reply = connector
        .post(
            "/v1/node/audit",
            "application/x-ndjson",
            b"{\"class_uid\":1}\n".to_vec(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let records = d.audit_records();
    let decision = records
        .iter()
        .find(|r| r["message"] == "flow allowed")
        .unwrap();
    assert_eq!(decision["metadata"]["log_provider"], node_uri);
    // The control plane audited its own decisions too.
    for message in [
        "signed in at the IdP",
        "device enrolled",
        "device approved",
        "user+device certificate issued",
        "user disabled",
        "node joined with a join token",
        "policy loaded",
        "policy rejected; the previous policy stays in force",
    ] {
        assert!(
            records.iter().any(|r| r["message"] == message),
            "no audit record {message:?}"
        );
    }
    assert!(
        records
            .iter()
            .all(|r| r["class_uid"].is_u64() && r["time"].is_i64())
    );

    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_approval_and_disabled_sign_in() {
    let d = Deployment::start("automatic").await;
    let mut client = d.client();
    client.sign_in().await;
    let (status, device) = client.enroll().await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(device["status"], "approved");
    assert_eq!(device["api_base"], format!("{}/v1", d.base));
    assert!(client.certificate().await.is_ok());
    // Enrolling the same key again binds, it does not duplicate.
    let (status, again) = client.enroll().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["id"], device["id"]);
    // An approved device that is disabled and enabled is approved again.
    let id = device["id"].as_str().unwrap();
    d.admin("POST", &format!("/v1/admin/devices/{id}/disable"), None)
        .await;
    assert_eq!(client.device().await.status, "disabled");
    d.admin("POST", &format!("/v1/admin/devices/{id}/enable"), None)
        .await;
    assert_eq!(client.device().await.status, "approved");

    // A disabled user is refused at sign-in with a reason for the app.
    d.admin("POST", "/v1/admin/users/00u-ada/disable", None)
        .await;
    let back = d.client().browser_sign_in().await;
    assert_eq!(back["error"], "access_denied");
    assert!(back["error_description"].contains("disabled"));
    assert!(!back.contains_key("code"));

    // A finance user signs in; their groups decide their entitlements.
    *d.idp.idp.user.lock().unwrap() = IdpUser {
        sub: "00u-fin".into(),
        email: "fin@example.com".into(),
        groups: vec!["finance".into()],
        amr: vec!["pwd".into()],
    };
    let mut fin = d.client();
    let session = fin.sign_in().await;
    assert!(!session.mfa);
    let names: Vec<String> = fin
        .entitlements()
        .await
        .apps
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert_eq!(names, ["billing"]);
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_enrollments_and_certificates_are_audited() {
    let d = Deployment::start("automatic").await;
    let mut client = d.client();
    client.sign_in().await;
    let (_, device) = client.enroll().await;
    let device_id = device["id"].as_str().unwrap().to_owned();
    let (status, _) = client.enroll().await;
    assert_eq!(status, StatusCode::OK);
    let message = |m: &str| d.audit_records().into_iter().find(|r| r["message"] == m);
    assert!(message("device enrolled again by the same user").is_some());

    // A certificate request on a revoked session is refused and audited.
    let (_, sessions) = d
        .admin("GET", "/v1/admin/users/00u-ada/sessions", None)
        .await;
    let session_id = sessions[0]["id"].as_str().unwrap().to_owned();
    d.admin(
        "POST",
        &format!("/v1/admin/sessions/{session_id}/revoke"),
        None,
    )
    .await;
    let (status, problem) = client.certificate().await.unwrap_err();
    assert_eq!(
        (status, problem["reason"].clone()),
        (StatusCode::UNAUTHORIZED, json!("revoked"))
    );
    let refused = message("certificate refused: revoked").expect("refusal audited");
    assert_eq!(refused["status"], "Failure");
    assert_eq!(refused["actor"]["user"]["uid"], sessions[0]["user_id"]);

    // A revoked device is refused, audited, and gains no users.
    client.sign_in().await;
    d.admin(
        "POST",
        &format!("/v1/admin/devices/{device_id}/revoke"),
        None,
    )
    .await;
    let (status, problem) = client.enroll().await;
    assert_eq!(
        (status, problem["reason"].clone()),
        (StatusCode::FORBIDDEN, json!("device_revoked"))
    );
    assert!(message("device refused: device_revoked").is_some());
    *d.idp.idp.user.lock().unwrap() = IdpUser {
        sub: "00u-fin".into(),
        email: "fin@example.com".into(),
        groups: vec!["finance".into()],
        amr: vec!["pwd".into()],
    };
    let mut other = d.client();
    other.key = SigningKey::from_pkcs8(&client.key.to_pkcs8().unwrap()).unwrap();
    other.sign_in().await;
    let (status, _) = other.enroll().await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, devices) = d.admin("GET", "/v1/admin/devices", None).await;
    let users = &devices.as_array().unwrap()[0]["users"];
    assert_eq!(users.as_array().unwrap().len(), 1, "{devices}");
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_in_asks_for_and_records_freshness() {
    let d = Deployment::start("automatic").await;
    // The policy's shortest auth.maxAge (12h) is asked of the IdP, and
    // prompt=login only when the client asks to sign in again.
    let mut client = d.client();
    let session = client.sign_in().await;
    let first = d.idp.idp.authorize_requests.lock().unwrap()[0].clone();
    assert_eq!(first.get("max_age").map(String::as_str), Some("43200"));
    assert_eq!(first.get("prompt"), None);
    let now = clock::now_secs();
    assert!((now - 10..=now).contains(&session.auth_time));
    let back = client.browser_sign_in_with(&[("prompt", "login")]).await;
    assert!(back.contains_key("code"));
    let again = d.idp.idp.authorize_requests.lock().unwrap()[1].clone();
    assert_eq!(again.get("prompt").map(String::as_str), Some("login"));
    let back = client
        .http
        .request(
            Method::GET,
            &format!(
                "{}/v1/auth/authorize?redirect_uri=http://127.0.0.1:9/cb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=s&prompt=none",
                d.base
            ),
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(back.status, StatusCode::BAD_REQUEST);

    // An IdP that leaves auth_time out: freshness is unknown, never the
    // token's issue time, and the certificate says so.
    *d.idp.idp.omit_auth_time.lock().unwrap() = true;
    let mut unsure = d.client();
    let session = unsure.sign_in().await;
    assert_eq!(session.auth_time, AUTH_TIME_UNKNOWN as i64);
    unsure.enroll().await;
    let issued = unsure.certificate().await.unwrap();
    let chain = pem_certs(&issued.certificate_chain);
    let identity = pki::check_client_profile(&chain[0], "example.test")
        .unwrap()
        .identity;
    assert_eq!(identity.auth_time, AUTH_TIME_UNKNOWN);
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_in_refuses_unsafe_requests() {
    let d = Deployment::start("manual").await;
    let client = d.client();
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    for (redirect, method) in [
        ("https://evil.example.com/cb", "S256"),
        ("http://localhost:1234/cb", "S256"),
        ("http://127.0.0.1:1234/cb", "plain"),
    ] {
        let url = format!(
            "{}/v1/auth/authorize?redirect_uri={}&code_challenge={challenge}&code_challenge_method={method}&state=s",
            d.base,
            form_urlencoded::byte_serialize(redirect.as_bytes()).collect::<String>()
        );
        let reply = client
            .http
            .request(Method::GET, &url, &[], None)
            .await
            .unwrap();
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{redirect} {method}");
        assert!(reply.headers.get("location").is_none());
    }
    // A forged or replayed callback is refused without a redirect.
    let reply = client
        .http
        .request(
            Method::GET,
            &format!("{}/v1/auth/callback?state=forged&code=x", d.base),
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(*d.idp.idp.token_requests.lock().unwrap(), 0);
    // Unauthenticated link D calls get a reason, not a timeout.
    let reply = client.get("/v1/entitlements").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    let problem: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(problem["reason"], "unauthenticated");
    // Every listed route is handled: none answers "no endpoint".
    for (method, path) in warren_control::api::ROUTES {
        let reply = client
            .http
            .request(
                method.parse().unwrap(),
                &format!("{}{path}", d.base),
                &[],
                None,
            )
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&reply.body);
        assert!(!body.contains("no endpoint"), "{method} {path}: {body}");
    }
    for (method, path) in warren_control::admin::ROUTES {
        let path = path.replace(['{', '}'], "");
        let (status, body) = d.admin(method, &path, None).await;
        assert!(
            !body.to_string().contains("no admin endpoint"),
            "{method} {path}: {status} {body}"
        );
    }

    // An unsupported protocol version is refused, naming the one spoken.
    let reply = client
        .http
        .request(
            Method::GET,
            &format!("{}/.well-known/warren", d.base),
            &[("warren-protocol", "9")],
            None,
        )
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let problem: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(problem["reason"], "unsupported_protocol");
    assert!(problem["detail"].as_str().unwrap().contains("protocol 1"));
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_survives_a_restart() {
    let d = Deployment::start("automatic").await;
    let mut client = d.client();
    client.sign_in().await;
    client.enroll().await;
    let root = d.cp.app().authority.root.der.clone();
    let version =
        d.cp.app()
            .store
            .latest_bundle()
            .await
            .unwrap()
            .unwrap()
            .version;
    let config = d.cp.app().config.clone();
    let Deployment { cp, dir, idp, .. } = d;
    cp.shutdown().await;
    let cp = ControlPlane::start_with_audit(
        config.clone(),
        Some(audit::Sink::memory(Arc::new(Mutex::new(Vec::new())))),
    )
    .await
    .unwrap();
    // Same CA, same users and devices, bundle versions keep increasing.
    assert_eq!(cp.app().authority.root.der, root);
    assert_eq!(cp.app().store.devices().await.unwrap().len(), 1);
    assert!(
        cp.app()
            .store
            .latest_bundle()
            .await
            .unwrap()
            .unwrap()
            .version
            > version
    );
    assert!(client.certificate().await.is_ok());
    cp.shutdown().await;

    // A different key-encryption key cannot open the keys.
    std::fs::write(
        &config.kek_file,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .unwrap();
    let err = ControlPlane::start(config).await.err().unwrap();
    assert!(err.to_string().contains("key-encryption key"), "{err}");
    drop((dir, idp));
}
