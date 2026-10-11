//! In-process deployments: a relay, a connector and clients in one
//! process, on loopback, with a test PKI. Kernel forwarding needs root, so
//! these use [`UserspaceUdp`], a test backend that answers ICMP echo itself
//! and relays UDP to sockets on loopback. Kernel-mode tests run the real
//! binaries in network namespaces (scripts/e2e-kernel.sh).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use warren_client::ClientConfig;
use warren_connector::{Backend, Connector, ConnectorConfig, Forwarder, Resolver};
use warren_core::audit::{AuditSink, NodeInfo};
use warren_core::bundle::{Bundle, IpNet, NodeState, proto};
use warren_core::packet;
use warren_core::params;
use warren_core::pki::TrustBundle;
use warren_core::quic::TransportTuning;
use warren_masque::session::{RelayAddress, TransportMode};
use warren_relay::{Relay, RelayConfig};

use crate::pki::{ClientCert, TestPki};

/// The trust domain of test deployments.
pub const TRUST_DOMAIN: &str = "lab.test";
/// The relay's DNS name.
pub const RELAY_NAME: &str = "relay.lab.test";
/// The connector group.
pub const GROUP: &str = "homelab";

/// A test bundle: the `homelab` group, apps on 10.77.0.0/24 and
/// fd77:7761::/64, a user `alice` in `eng` on approved device `mac-1`, and
/// rules letting `eng` reach the echo apps and names.
pub fn test_bundle(version: u64) -> Value {
    serde_json::json!({
        "version": version,
        "trustDomain": TRUST_DOMAIN,
        "connectorGroups": [{
            "name": GROUP,
            "destinations": { "cidrs": ["10.77.0.0/24", "fd77:7761::/64"], "domains": ["*.lab.test", "echo.internal.test"] },
            "clientNames": ["*.lab.test"]
        }],
        "apps": [
            { "name": "echo-udp", "connectorGroup": GROUP,
              "destinations": [{ "cidr": "10.77.0.10/32", "ports": [7], "protocol": "udp" },
                               { "cidr": "fd77:7761::10/128", "ports": [7], "protocol": "udp" },
                               { "cidr": "10.77.0.10/32", "protocol": "icmp" }] },
            { "name": "echo-tcp", "connectorGroup": GROUP,
              "destinations": [{ "cidr": "10.77.0.10/32", "ports": ["7"], "protocol": "tcp" },
                               { "cidr": "fd77:7761::10/128", "ports": ["7"], "protocol": "tcp" }] },
            { "name": "secret", "connectorGroup": GROUP,
              "destinations": [{ "cidr": "10.77.0.20/32", "protocol": "any" }] },
            { "name": "billing", "connectorGroup": GROUP, "discoverable": true,
              "destinations": [{ "cidr": "10.77.0.30/32", "protocol": "any" }] },
            { "name": "grafana", "connectorGroup": GROUP,
              "destinations": [{ "host": "grafana.lab.test", "target": "echo.internal.test", "ports": [7], "protocol": "udp" }] },
            { "name": "lab-web", "connectorGroup": GROUP,
              "destinations": [{ "host": "*.lab.test", "target": null, "ports": [7], "protocol": "udp" }] },
            { "name": "pusher", "connectorGroup": GROUP, "serverInitiatedFlows": true,
              "destinations": [{ "cidr": "10.77.0.40/32", "protocol": "udp" }] }
        ],
        "users": [
            { "id": "alice", "groups": ["eng"] },
            { "id": "bob", "groups": ["contractors"] }
        ],
        "devices": [
            { "id": "mac-1", "approved": true },
            { "id": "mac-2", "approved": true },
            { "id": "unapproved-mac", "approved": false }
        ],
        "rules": [
            { "id": "lab/eng-echo", "who": { "groups": ["eng"] }, "what": { "apps": ["echo-udp", "echo-tcp", "grafana", "pusher"] } },
            { "id": "lab/eng-web-fresh", "who": { "groups": ["eng"] }, "what": { "apps": ["lab-web"] },
              "when": { "auth": { "maxAge": "12h", "mfa": true } } },
            { "id": "lab/contractors", "who": { "groups": ["contractors"] }, "what": { "apps": ["echo-udp"] } }
        ]
    })
}

/// Compiles a bundle value.
pub fn compile(v: &Value) -> warren_core::bundle::CompiledBundle {
    serde_json::from_value::<Bundle>(v.clone())
        .expect("bundle parses")
        .compile()
        .expect("bundle compiles")
}

/// A userspace test backend: answers ICMP echo for any destination,
/// relays UDP to loopback sockets per a destination map, and drops TCP.
#[derive(Debug)]
pub struct UserspaceUdp {
    targets: HashMap<SocketAddr, SocketAddr>,
    returns: mpsc::Sender<Bytes>,
    flows: Mutex<HashMap<(SocketAddr, SocketAddr), Arc<std::net::UdpSocket>>>,
    /// Every packet forwarded, for assertions.
    pub seen: Mutex<Vec<Vec<u8>>>,
}

impl UserspaceUdp {
    /// Creates the backend; `targets` maps app addresses to loopback
    /// sockets.
    pub fn start(targets: HashMap<SocketAddr, SocketAddr>) -> (Arc<UserspaceUdp>, Backend) {
        let (returns, rx) = mpsc::channel(4096);
        let fwd = Arc::new(UserspaceUdp {
            targets,
            returns,
            flows: Mutex::new(HashMap::new()),
            seen: Mutex::new(Vec::new()),
        });
        let backend = Backend {
            forwarder: fwd.clone(),
            returns: rx,
        };
        (fwd, backend)
    }

    /// Injects a packet as if it came from the private network.
    pub fn inject(&self, packet: Vec<u8>) {
        let _ = self.returns.try_send(Bytes::from(packet));
    }
}

impl Forwarder for UserspaceUdp {
    fn send(&self, pkt: &[u8]) {
        self.seen.lock().expect("seen lock").push(pkt.to_vec());
        let Ok(p) = packet::parse(pkt) else { return };
        match p.protocol {
            proto::ICMP | proto::ICMPV6
                if p.is_icmp_echo() && matches!(p.icmp, Some((8 | 128, _))) =>
            {
                let payload = &pkt[p.l4 + 8..p.len];
                let seq = u16::from_be_bytes([pkt[p.l4 + 6], pkt[p.l4 + 7]]);
                let reply = packet::icmp_echo(p.dst, p.src, true, p.src_port, seq, payload);
                let _ = self.returns.try_send(Bytes::from(reply));
            }
            proto::UDP => {
                let (client, app) = (p.src_sock(), p.dst_sock());
                let Some(target) = self.targets.get(&app).copied() else {
                    return;
                };
                let payload = packet::udp_payload(pkt, &p).unwrap_or_default().to_vec();
                let existing = self
                    .flows
                    .lock()
                    .expect("flows lock")
                    .get(&(client, app))
                    .cloned();
                let returns = self.returns.clone();
                let sock = match existing {
                    Some(s) => s,
                    None => {
                        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
                        s.set_nonblocking(true).expect("nonblocking");
                        let reader = UdpSocket::from_std(s.try_clone().expect("clone"))
                            .expect("tokio socket");
                        let s = Arc::new(s);
                        self.flows
                            .lock()
                            .expect("flows lock")
                            .insert((client, app), s.clone());
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65_536];
                            while let Ok((n, _)) = reader.recv_from(&mut buf).await {
                                let back = packet::udp(app, client, &buf[..n]);
                                if returns.send(Bytes::from(back)).await.is_err() {
                                    return;
                                }
                            }
                        });
                        s
                    }
                };
                let _ = sock.send_to(&payload, target);
            }
            _ => {}
        }
    }
}

/// A static resolver for name apps.
#[derive(Debug, Default)]
pub struct StaticResolver(pub HashMap<String, Vec<IpAddr>>);

impl Resolver for StaticResolver {
    fn resolve(
        &self,
        name: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>
    {
        let found = self.0.get(&name).cloned();
        Box::pin(async move {
            found.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such name"))
        })
    }
}

/// Starts a UDP echo server on loopback.
pub async fn udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// Options for an in-process deployment.
#[derive(Debug, Clone)]
pub struct Options {
    /// Whether the relay listens for the HTTP/2 fallback.
    pub relay_tcp: bool,
    /// The bundle.
    pub bundle: Value,
    /// Carrier for the connector's attachment.
    pub connector_transport: TransportMode,
    /// Connector transport tuning (link B).
    pub connector_tuning: TransportTuning,
    /// How many relays (the connector attaches to all of them).
    pub relays: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            relay_tcp: true,
            bundle: test_bundle(1),
            connector_transport: TransportMode::QuicOnly,
            connector_tuning: TransportTuning::default(),
            relays: 1,
        }
    }
}

/// A running in-process deployment.
#[derive(Debug)]
pub struct Deployment {
    /// The PKI.
    pub pki: TestPki,
    /// The trust bundle.
    pub trust: Arc<TrustBundle>,
    /// The relays.
    pub relays: Vec<Relay>,
    /// The connector.
    pub connector: Connector,
    /// The test backend.
    pub backend: Arc<UserspaceUdp>,
    /// Audit records the connector wrote.
    pub audit: std::sync::mpsc::Receiver<Value>,
    /// Where the UDP echo app really listens.
    pub echo: SocketAddr,
}

impl Deployment {
    /// Starts a relay and a connector, and waits until the connector is
    /// attached.
    pub async fn start(opts: Options) -> Deployment {
        let pki = TestPki::new(TRUST_DOMAIN);
        let trust = Arc::new(pki.bundle());
        let state = NodeState::new(compile(&opts.bundle));
        let mut relays = Vec::new();
        for i in 0..opts.relays.max(1) {
            let relay = Relay::start(RelayConfig {
                listen_quic: "127.0.0.1:0".parse().expect("valid"),
                listen_tcp: opts
                    .relay_tcp
                    .then(|| "127.0.0.1:0".parse().expect("valid")),
                credentials: pki.relay(&format!("r{i}"), &[RELAY_NAME]),
                trust: trust.clone(),
                state: state.clone(),
                name: format!("warren-relay-r{i}"),
                peer_prefix: None,
                max_splices_per_client: 64,
                tuning: TransportTuning::default(),
            })
            .await
            .expect("relay starts");
            relays.push(relay);
        }
        let echo = udp_echo().await;
        let targets: HashMap<SocketAddr, SocketAddr> = [
            ("10.77.0.10:7".parse().expect("valid"), echo),
            ("[fd77:7761::10]:7".parse().expect("valid"), echo),
            ("10.77.0.20:7".parse().expect("valid"), echo),
            ("10.77.0.30:7".parse().expect("valid"), echo),
        ]
        .into_iter()
        .collect();
        let (backend, io) = UserspaceUdp::start(targets);
        let (audit, records) = AuditSink::collect(NodeInfo {
            role: "connector".into(),
            name: format!("connector/{GROUP}/c1"),
        });
        let resolver = StaticResolver(
            [
                (
                    "echo.internal.test".to_owned(),
                    vec!["10.77.0.10".parse().expect("valid")],
                ),
                (
                    "wiki.lab.test".to_owned(),
                    vec!["10.77.0.10".parse().expect("valid")],
                ),
                (
                    "outside.lab.test".to_owned(),
                    vec!["192.0.2.1".parse().expect("valid")],
                ),
            ]
            .into_iter()
            .collect(),
        );
        let connector = Connector::start(
            ConnectorConfig {
                group: GROUP.into(),
                relays: relays.iter().map(relay_address).collect(),
                transport: opts.connector_transport,
                credentials: pki.connector(GROUP, "c1"),
                trust: trust.clone(),
                state,
                audit,
                resolver: Arc::new(resolver),
                synthetic_pools: vec![
                    params::SYNTHETIC_POOL_V4.parse::<IpNet>().expect("valid"),
                    params::SYNTHETIC_POOL_V6.parse::<IpNet>().expect("valid"),
                ],
                tunnel_mtu: params::TUNNEL_MTU,
                tuning: opts.connector_tuning,
            },
            io,
        )
        .expect("connector starts");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while relays.iter().any(|r| r.metrics().attachments.get() == 0) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "connector never attached"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Deployment {
            pki,
            trust,
            relays,
            connector,
            backend,
            audit: records,
            echo,
        }
    }

    /// A client configuration for `cert`.
    pub fn client(&self, cert: &ClientCert, transport: TransportMode) -> ClientConfig {
        ClientConfig {
            group: GROUP.into(),
            relays: self.relays.iter().map(relay_address).collect(),
            transport,
            credentials: self.pki.client(cert),
            trust: self.trust.clone(),
            tunnel_mtu: params::TUNNEL_MTU,
            fallback_delay: params::FALLBACK_DELAY,
            tuning: TransportTuning::default(),
        }
    }

    /// The first relay.
    pub fn relay(&self) -> &Relay {
        &self.relays[0]
    }

    /// Audit records written so far.
    pub fn audit_records(&self) -> Vec<Value> {
        self.audit.try_iter().collect()
    }
}

/// The relay's address for clients and connectors.
pub fn relay_address(relay: &Relay) -> RelayAddress {
    RelayAddress {
        name: RELAY_NAME.into(),
        quic: relay.quic_addr(),
        tcp: relay
            .tcp_addr()
            .unwrap_or_else(|| "127.0.0.1:9".parse().expect("valid")),
    }
}

/// Alice on mac-1.
pub fn alice() -> ClientCert {
    ClientCert::new("alice", "mac-1", "100.96.0.2", "fd00:7761:7272:6e00::2")
}
