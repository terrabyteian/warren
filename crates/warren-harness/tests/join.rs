//! Joining a deployment with single-use tokens, then running on the
//! credentials the join produced.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use warren_core::audit::{AuditSink, NodeInfo};
use warren_core::bundle::NodeState;
use warren_core::identity::NodeRole;
use warren_core::join::{JoinToken, NodeKey};
use warren_core::quic::TransportTuning;
use warren_core::{packet, params};
use warren_harness::deploy::{StaticResolver, UserspaceUdp, alice, compile, test_bundle, udp_echo};
use warren_harness::join::JoinServer;
use warren_harness::pki::TestPki;
use warren_masque::join::join;
use warren_masque::session::{RelayAddress, TransportMode};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tokens_are_single_use_scoped_and_pinned() {
    let pki = Arc::new(TestPki::new("lab.test"));
    let cp = JoinServer::start(pki.clone(), "localhost").await.unwrap();

    let relay_token = cp.mint(None, &["relay.lab.test"]);
    let key = NodeKey::generate().unwrap();
    let joined = join(&relay_token, &key).await.expect("relay joins");
    assert_eq!(joined.identity.role, NodeRole::Relay);
    assert_eq!(joined.identity.dns_names, ["relay.lab.test"]);
    assert_eq!(joined.trust.trust_domain, "lab.test");

    // Single use.
    let again = join(&relay_token, &NodeKey::generate().unwrap())
        .await
        .unwrap_err();
    assert!(again.0.contains("409"), "{again}");

    // Scoped to a connector group.
    let conn = join(
        &cp.mint(Some("homelab"), &[]),
        &NodeKey::generate().unwrap(),
    )
    .await
    .expect("connector joins");
    assert_eq!(
        conn.identity.role,
        NodeRole::Connector {
            group: "homelab".into()
        }
    );

    // A token pinning another root never talks to this control plane.
    let mut wrong = cp.mint(None, &["relay.lab.test"]);
    wrong.root = "00".repeat(32);
    let e = join(&wrong, &NodeKey::generate().unwrap())
        .await
        .unwrap_err();
    assert!(e.0.contains("pinned"), "{e}");

    // Tampered secrets are refused.
    let mut forged = cp.mint(None, &["relay.lab.test"]);
    forged.secret = warren_core::base64::encode_url(&[1u8; 32]);
    assert!(join(&forged, &NodeKey::generate().unwrap()).await.is_err());

    // Tokens are checked locally too.
    let encoded = relay_token.encode();
    assert!(JoinToken::parse(&encoded, relay_token.exp + 1).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joined_nodes_carry_traffic() {
    let pki = Arc::new(TestPki::new("lab.test"));
    let cp = JoinServer::start(pki.clone(), "localhost").await.unwrap();
    let relay_joined = join(
        &cp.mint(None, &["relay.lab.test"]),
        &NodeKey::generate().unwrap(),
    )
    .await
    .unwrap();
    let conn_joined = join(
        &cp.mint(Some("homelab"), &[]),
        &NodeKey::generate().unwrap(),
    )
    .await
    .unwrap();
    let trust = Arc::new(relay_joined.trust);
    let state = NodeState::new(compile(&test_bundle(1)));
    let relay = warren_relay::Relay::start(warren_relay::RelayConfig {
        listen_quic: "127.0.0.1:0".parse().unwrap(),
        listen_tcp: None,
        credentials: relay_joined.credentials,
        trust: trust.clone(),
        state: state.clone(),
        name: "warren-relay-joined".into(),
        peer_prefix: None,
        max_splices_per_client: 8,
        tuning: TransportTuning::default(),
    })
    .await
    .unwrap();
    let relay_addr = RelayAddress {
        name: "relay.lab.test".into(),
        quic: relay.quic_addr(),
        tcp: "127.0.0.1:9".parse().unwrap(),
    };
    let echo = udp_echo().await;
    let targets: HashMap<SocketAddr, SocketAddr> = [("10.77.0.10:7".parse().unwrap(), echo)]
        .into_iter()
        .collect();
    let (_backend, io) = UserspaceUdp::start(targets);
    let _connector = warren_connector::Connector::start(
        warren_connector::ConnectorConfig {
            group: "homelab".into(),
            relays: vec![relay_addr.clone()],
            transport: TransportMode::QuicOnly,
            credentials: conn_joined.credentials,
            trust: Arc::new(conn_joined.trust),
            state,
            audit: AuditSink::discard(NodeInfo {
                role: "connector".into(),
                name: "connector/homelab/joined".into(),
            }),
            resolver: Arc::new(StaticResolver::default()),
            synthetic_pools: vec![params::SYNTHETIC_POOL_V4.parse().unwrap()],
            tunnel_mtu: params::TUNNEL_MTU,
            tuning: TransportTuning::default(),
        },
        io,
    )
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while relay.metrics().attachments.get() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the joined connector never attached"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut t = warren_client::connect(warren_client::ClientConfig {
        group: "homelab".into(),
        relays: vec![relay_addr],
        transport: TransportMode::QuicOnly,
        credentials: pki.client(&alice()),
        trust,
        tunnel_mtu: params::TUNNEL_MTU,
        fallback_delay: params::FALLBACK_DELAY,
        tuning: TransportTuning::default(),
    })
    .await
    .unwrap();
    let v4 = t
        .info()
        .addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .unwrap();
    let src = SocketAddr::new(v4, 45_000);
    t.send(&packet::udp(
        src,
        "10.77.0.10:7".parse().unwrap(),
        b"joined",
    ));
    let reply = tokio::time::timeout(Duration::from_secs(5), t.recv())
        .await
        .unwrap()
        .unwrap();
    let p = packet::parse(&reply).unwrap();
    assert_eq!(packet::udp_payload(&reply, &p).unwrap(), b"joined");
}
