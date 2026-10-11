//! Certificate chains and profiles (docs/protocol.md section 10) against
//! the verifiers every link uses.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use warren_core::identity::NodeRole;
use warren_core::pki::{CertError, ClientIdentity, NodeIdentity, PeerIdentity, oid};
use warren_core::tls::{
    self, AcceptClients, ExpectServer, NoRevocations, NodeRoleMatch, RevocationCheck,
};
use warren_harness::pki::{CertSpec, ClientCert, Issuer, KeyPair, TestPki, issue};

fn users_only() -> AcceptClients {
    AcceptClients {
        users: true,
        nodes: vec![],
    }
}

fn verify_client_leaf(
    pki: &TestPki,
    leaf: &[u8],
    accept: &AcceptClients,
) -> Result<PeerIdentity, CertError> {
    tls::verify_client(
        &pki.bundle(),
        accept,
        &NoRevocations,
        &leaf.to_vec().into(),
        tls::now(),
    )
}

fn alice() -> ClientCert {
    ClientCert::new("alice", "mac-1", "100.96.0.2", "fd00:96::2")
}

#[test]
fn conforming_client_certificate_verifies() {
    let pki = TestPki::new("example.test");
    let creds = pki.client(&alice());
    let id = verify_client_leaf(&pki, &creds.chain[0], &users_only()).unwrap();
    let PeerIdentity::Client(c) = id else {
        panic!("expected a client")
    };
    assert_eq!(c.user, "alice");
    assert_eq!(c.device, "mac-1");
    assert_eq!(c.identity.tunnel_v4.to_string(), "100.96.0.2");
    assert!(c.identity.mfa);
    assert_eq!(c.serial.len(), 32);
}

#[test]
fn issuing_cas_are_not_interchangeable() {
    let pki = TestPki::new("example.test");
    // A client-profile certificate from the infrastructure CA.
    let key = KeyPair::generate();
    let infra = Issuer {
        key: &pki.infra_ca.key,
        name: pki.infra_ca.name.clone(),
    };
    let leaf = issue(&pki.client_spec(&alice()), &key, Some(&infra));
    assert!(verify_client_leaf(&pki, &leaf, &users_only()).is_err());
    // A leaf straight from the root.
    let root = Issuer {
        key: &pki.root.key,
        name: pki.root.name.clone(),
    };
    let leaf = issue(&pki.client_spec(&alice()), &key, Some(&root));
    assert!(verify_client_leaf(&pki, &leaf, &users_only()).is_err());
    // A connector certificate where a user is required, and vice versa.
    let conn = pki.connector("homelab", "c1");
    assert!(verify_client_leaf(&pki, &conn.chain[0], &users_only()).is_err());
    let nodes = AcceptClients {
        users: false,
        nodes: vec![NodeRoleMatch::AnyConnector],
    };
    assert!(matches!(
        verify_client_leaf(&pki, &conn.chain[0], &nodes).unwrap(),
        PeerIdentity::Node(NodeIdentity {
            role: NodeRole::Connector { .. },
            ..
        })
    ));
    let user = pki.client(&alice());
    assert!(verify_client_leaf(&pki, &user.chain[0], &nodes).is_err());
    // A relay certificate is not a connector.
    let relay = pki.relay("r1", &["relay.example.test"]);
    assert!(verify_client_leaf(&pki, &relay.chain[0], &nodes).is_err());
}

#[test]
fn another_deployment_is_not_trusted() {
    let ours = TestPki::new("example.test");
    let theirs = TestPki::new("example.test");
    let creds = theirs.client(&alice());
    assert!(verify_client_leaf(&ours, &creds.chain[0], &users_only()).is_err());
}

/// A change that breaks the client certificate profile.
type Mutation = Box<dyn Fn(&mut CertSpec)>;

#[test]
fn profile_violations_are_rejected() {
    let pki = TestPki::new("example.test");
    let base = pki.client_spec(&alice());
    let mutations: Vec<(&str, Mutation)> = vec![
        (
            "lifetime over 4 h",
            Box::new(|s| s.not_after = s.not_before + 5 * 3600),
        ),
        ("SAN not critical", Box::new(|s| s.san_critical = false)),
        (
            "extra DNS SAN",
            Box::new(|s| s.san_dns = vec!["x.example.test".into()]),
        ),
        (
            "no device URI",
            Box::new(|s| {
                s.san_uris.pop();
            }),
        ),
        (
            "two users",
            Box::new(|s| s.san_uris[1] = "warren://example.test/user/bob".into()),
        ),
        (
            "foreign trust domain",
            Box::new(|s| s.san_uris[0] = "warren://other.test/user/alice".into()),
        ),
        (
            "serverAuth too",
            Box::new(|s| s.eku.push(oid::SERVER_AUTH.to_vec())),
        ),
        ("no EKU", Box::new(|s| s.eku.clear())),
        (
            "keyUsage not critical",
            Box::new(|s| s.key_usage = Some((0x80, false))),
        ),
        (
            "keyCertSign",
            Box::new(|s| s.key_usage = Some((0x84, true))),
        ),
        ("no basicConstraints", Box::new(|s| s.ca = None)),
        ("no key identifiers", Box::new(|s| s.key_ids = false)),
        (
            "subject not empty",
            Box::new(|s| s.subject_cn = Some("alice".into())),
        ),
        ("short serial", Box::new(|s| s.serial = vec![1, 2, 3])),
        ("no identity extension", Box::new(|s| s.extra.clear())),
        (
            "critical identity extension",
            Box::new(|s| s.extra[0].1 = true),
        ),
        (
            "CRL pointer",
            Box::new(|s| {
                s.extra
                    .push((oid::CRL_DP.to_vec(), false, vec![0x30, 0x00]))
            }),
        ),
        (
            "expired",
            Box::new(|s| {
                s.not_before -= 7200;
                s.not_after = s.not_before + 3600;
            }),
        ),
    ];
    for (what, mutate) in mutations {
        let mut spec = base.clone();
        mutate(&mut spec);
        let creds = pki.issue_client(&spec);
        let result = verify_client_leaf(&pki, &creds.chain[0], &users_only());
        assert!(result.is_err(), "accepted a certificate with {what}: {result:?}");
    }
}

#[test]
fn server_verification_checks_names_and_groups() {
    let pki = TestPki::new("example.test");
    let bundle = pki.bundle();
    let relay = pki.relay("r1", &["relay.example.test"]);
    let name = ServerName::try_from("relay.example.test").unwrap();
    let other = ServerName::try_from("evil.example.test").unwrap();
    let ok = tls::verify_server(
        &bundle,
        &ExpectServer::Relay,
        &NoRevocations,
        &relay.chain[0],
        &name,
        tls::now(),
    );
    assert!(ok.is_ok());
    assert!(
        tls::verify_server(
            &bundle,
            &ExpectServer::Relay,
            &NoRevocations,
            &relay.chain[0],
            &other,
            tls::now()
        )
        .is_err()
    );

    let conn = pki.connector("homelab", "c1");
    let inner = ServerName::try_from("homelab.connectors.warren.invalid").unwrap();
    let homelab = ExpectServer::Connector {
        group: "homelab".into(),
    };
    let office = ExpectServer::Connector {
        group: "office".into(),
    };
    assert!(
        tls::verify_server(
            &bundle,
            &homelab,
            &NoRevocations,
            &conn.chain[0],
            &inner,
            tls::now()
        )
        .is_ok()
    );
    assert!(
        tls::verify_server(
            &bundle,
            &office,
            &NoRevocations,
            &conn.chain[0],
            &inner,
            tls::now()
        )
        .is_err()
    );
    // A relay cannot stand in for a connector, nor a connector for a relay.
    assert!(
        tls::verify_server(
            &bundle,
            &homelab,
            &NoRevocations,
            &relay.chain[0],
            &inner,
            tls::now()
        )
        .is_err()
    );
    assert!(
        tls::verify_server(
            &bundle,
            &ExpectServer::Relay,
            &NoRevocations,
            &conn.chain[0],
            &name,
            tls::now()
        )
        .is_err()
    );
    // Client certificates never serve.
    let user = pki.client(&alice());
    assert!(
        tls::verify_server(
            &bundle,
            &homelab,
            &NoRevocations,
            &user.chain[0],
            &inner,
            tls::now()
        )
        .is_err()
    );
}

#[derive(Debug)]
struct RevokeDevice(&'static str);

impl RevocationCheck for RevokeDevice {
    fn check_client(&self, id: &ClientIdentity) -> Result<(), CertError> {
        if id.device == self.0 {
            return Err(CertError::Revoked(format!("device {}", id.device)));
        }
        Ok(())
    }
    fn check_node(&self, _: &NodeIdentity) -> Result<(), CertError> {
        Ok(())
    }
}

#[test]
fn revocation_state_is_consulted() {
    let pki = TestPki::new("example.test");
    let creds = pki.client(&alice());
    let revoked: Arc<dyn RevocationCheck> = Arc::new(RevokeDevice("mac-1"));
    let err = tls::verify_client(
        &pki.bundle(),
        &users_only(),
        revoked.as_ref(),
        &creds.chain[0],
        tls::now(),
    );
    assert!(matches!(err, Err(CertError::Revoked(_))));
}
