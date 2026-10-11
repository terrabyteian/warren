//! The client core linked by the native platform shells.
//!
//! It dials a relay (QUIC first, HTTP/2 raced behind it), asks it to splice
//! a CONNECT-UDP stream to the connector group, runs the inner, mutually
//! authenticated QUIC session over that stream, and opens CONNECT-IP inside
//! it (docs/protocol.md sections 4, 5 and 8). The shell moves IP packets in
//! and out; the core answers what must be answered at the client ingress
//! (oversized packets, MSS) and reports every block with its reason (G12).
//! When the outer path breaks, the core re-dials and the inner session
//! migrates instead of restarting.
//!
//! This crate is a data-path build: it must never link control-plane,
//! console or Kubernetes crates, which `scripts/check-closure.sh` enforces.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustls::pki_types::CertificateDer;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};
use warren_core::params;
use warren_core::pki::{self, ClientIdentity, TrustBundle};
use warren_core::quic::{self, Layer, TransportTuning};
use warren_core::tls::{self, Credentials, ExpectServer, NoRevocations, WarrenServerVerifier};
use warren_core::vsock::{self, Inbound, PacketSink, VirtualSocket};
use warren_masque::capsule::{
    AddressEntry, Capsule, CertRefresh, FlowDenied, IpRange, NameBind, Notice, split_context,
};
use warren_masque::connect::{self, Refusal};
use warren_masque::h3::H3Connection;
use warren_masque::session::{self as carrier, OpenError, OuterConn, RelayAddress, TransportMode};
use warren_masque::tunnel::{CarrierKind, TunnelSender};

/// The exporter label a certificate refresh signs (docs/protocol.md 5).
pub const REFRESH_EXPORTER_LABEL: &[u8] = b"EXPORTER-warren-cert-refresh";

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The connector group to reach.
    pub group: String,
    /// Relays in order of preference.
    pub relays: Vec<RelayAddress>,
    /// Carrier selection.
    pub transport: TransportMode,
    /// The user+device certificate and key.
    pub credentials: Credentials,
    /// The deployment trust bundle.
    pub trust: Arc<TrustBundle>,
    /// The tunnel MTU (never below the 1280-byte floor).
    pub tunnel_mtu: u16,
    /// How long QUIC gets before HTTP/2 is raced.
    pub fallback_delay: Duration,
    /// Transport overrides for tests.
    pub tuning: TransportTuning,
}

/// Why the tunnel could not be set up, phrased for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The configured tunnel MTU is below the floor.
    MtuFloor(String),
    /// No relay could be reached on any carrier.
    Unreachable(String),
    /// The relay refused the splice.
    Refused {
        /// RFC 9209 error type.
        error: String,
        /// Human-readable details.
        details: String,
    },
    /// The inner session to the connector failed.
    Session(String),
    /// The client's own credentials are unusable.
    Credentials(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::MtuFloor(m) => write!(f, "tunnel MTU below the 1280-byte floor: {m}"),
            ConnectError::Unreachable(m) => write!(f, "cannot reach a relay: {m}"),
            ConnectError::Refused { error, details } => {
                write!(f, "relay refused ({error}): {details}")
            }
            ConnectError::Session(m) => write!(f, "connector session failed: {m}"),
            ConnectError::Credentials(m) => write!(f, "credentials: {m}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Something the user should hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A flow was denied by the connector.
    Denied(FlowDenied),
    /// The connector or relay sent a notice.
    Notice(Notice),
    /// The outer path changed (carrier or relay).
    PathChanged {
        /// The new carrier.
        carrier: CarrierKind,
        /// The relay.
        relay: String,
    },
    /// The session ended.
    Closed(String),
}

/// A name bind was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRejected {
    /// Reason code.
    pub reason: String,
    /// Human-readable message.
    pub message: String,
}

/// Facts about the established tunnel.
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Addresses the connector assigned.
    pub addresses: Vec<IpAddr>,
    /// Routes it advertised (hints only).
    pub routes: Vec<IpRange>,
    /// The tunnel MTU.
    pub tunnel_mtu: u16,
    /// The verified identity.
    pub identity: ClientIdentity,
}

/// Counters for diagnostics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathStats {
    /// Outer carrier.
    pub carrier: Option<CarrierKind>,
    /// Inner QUIC packets carried in DATAGRAM capsules on the outer stream.
    pub outer_capsule_fallbacks: u64,
    /// IP packets carried in DATAGRAM capsules on the CONNECT-IP stream.
    pub inner_capsule_fallbacks: u64,
    /// Current inner datagram limit.
    pub inner_max_datagram: Option<usize>,
}

impl PathStats {
    /// Whether the path is too small for full-size packets in datagrams,
    /// so some travel reliably on a stream instead (docs/protocol.md 9).
    pub fn constrained(&self) -> bool {
        self.outer_capsule_fallbacks > 0 || self.inner_capsule_fallbacks > 0
    }
}

/// The outer path the inner session currently rides on.
#[derive(Debug, Default)]
struct OuterPath {
    tx: RwLock<Option<TunnelSender>>,
}

impl PacketSink for OuterPath {
    fn send_to(&self, _dst: SocketAddr, packet: &[u8]) {
        if let Some(tx) = self.tx.read().expect("path lock").as_ref() {
            let _ = tx.send_datagram(0, packet);
        }
    }
}

/// The virtual address the inner session believes the connector has.
const CONNECTOR_VIRTUAL: &str = "[fd00:7761:7272:6e02::1]:443";

/// An established tunnel.
#[derive(Debug)]
pub struct Tunnel {
    info: TunnelInfo,
    tx: TunnelSender,
    packets: mpsc::Receiver<Bytes>,
    local: mpsc::Sender<Bytes>,
    events: Option<mpsc::Receiver<ClientEvent>>,
    binds: Arc<Mutex<HashMap<IpAddr, oneshot::Sender<Result<(), BindRejected>>>>>,
    inner: quinn::Connection,
    outer: Arc<OuterPath>,
    carrier: watch::Receiver<Option<CarrierKind>>,
    _endpoint: quinn::Endpoint,
    shutdown: watch::Sender<bool>,
}

impl Tunnel {
    /// Facts about the tunnel.
    pub fn info(&self) -> &TunnelInfo {
        &self.info
    }

    /// Takes the event stream.
    pub fn events(&mut self) -> mpsc::Receiver<ClientEvent> {
        self.events.take().unwrap_or_else(|| mpsc::channel(1).1)
    }

    /// A handle for sending packets from another task.
    pub fn sender(&self) -> PacketSender {
        PacketSender {
            tx: self.tx.clone(),
            local: self.local.clone(),
            mtu: self.info.tunnel_mtu,
        }
    }

    /// Sends an IP packet from the device into the tunnel.
    pub fn send(&self, packet: &[u8]) {
        self.sender().send(packet);
    }

    /// The next IP packet for the device.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.packets.recv().await
    }

    /// Path diagnostics.
    pub fn stats(&self) -> PathStats {
        let outer = self.outer.tx.read().expect("path lock");
        PathStats {
            carrier: *self.carrier.borrow(),
            outer_capsule_fallbacks: outer
                .as_ref()
                .map_or(0, |t| t.stats().capsule_fallbacks.load(Ordering::Relaxed)),
            inner_capsule_fallbacks: self.tx.stats().capsule_fallbacks.load(Ordering::Relaxed),
            inner_max_datagram: self.inner.max_datagram_size(),
        }
    }

    /// Binds a synthetic address to a name and the app the client believes
    /// owns it (docs/protocol.md section 6).
    pub async fn bind_name(
        &self,
        address: IpAddr,
        name: &str,
        app: &str,
    ) -> Result<(), BindRejected> {
        let (done, wait) = oneshot::channel();
        self.binds.lock().expect("binds lock").insert(address, done);
        let capsule = Capsule::NameBind(NameBind {
            address,
            name: name.into(),
            app: app.into(),
        });
        let lost = BindRejected {
            reason: "session_closed".into(),
            message: "The tunnel closed before the name was bound.".into(),
        };
        if self.tx.send_capsule(&capsule).await.is_err() {
            return Err(lost);
        }
        match tokio::time::timeout(Duration::from_secs(5), wait).await {
            Ok(Ok(r)) => r,
            _ => Err(lost),
        }
    }

    /// Hands the connector a renewed certificate, signing the session's
    /// exporter value with the device key so it is bound to this session.
    pub async fn refresh_certificate(
        &self,
        chain: &[CertificateDer<'static>],
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<(), String> {
        let mut exporter = [0u8; 32];
        self.inner
            .export_keying_material(&mut exporter, REFRESH_EXPORTER_LABEL, b"")
            .map_err(|_| "keying material export failed".to_owned())?;
        let signature = sign(&exporter)?;
        let capsule = Capsule::CertRefresh(CertRefresh {
            chain: chain.iter().map(|c| Bytes::copy_from_slice(c)).collect(),
            signature: Bytes::from(signature),
        });
        self.tx
            .send_capsule(&capsule)
            .await
            .map_err(|_| "tunnel closed".to_owned())
    }

    /// Closes the tunnel.
    pub fn close(&self) {
        let _ = self.shutdown.send(true);
        self.inner
            .close(quinn::VarInt::from_u32(0x100), b"client closed");
    }
}

/// Sends packets into a tunnel from any task.
#[derive(Debug, Clone)]
pub struct PacketSender {
    tx: TunnelSender,
    local: mpsc::Sender<Bytes>,
    mtu: u16,
}

impl PacketSender {
    /// Sends an IP packet. Packets over the tunnel MTU are answered with
    /// ICMP fragmentation-needed or packet-too-big, never dropped silently;
    /// TCP SYNs have their MSS clamped to fit.
    pub fn send(&self, packet: &[u8]) {
        let Ok(p) = warren_core::packet::parse(packet) else {
            return;
        };
        if p.len > usize::from(self.mtu) {
            if let Some(frags) = warren_core::packet::fragment_v4(packet, &p, self.mtu) {
                for f in frags {
                    let _ = self.tx.send_datagram(0, &f);
                }
            } else if let Some(err) = warren_core::packet::icmp_error(
                packet,
                &p,
                warren_core::packet::IcmpError::TooBig(self.mtu),
                p.dst,
            ) {
                let _ = self.local.try_send(Bytes::from(err));
            }
            return;
        }
        if p.protocol == warren_core::bundle::proto::TCP
            && p.tcp_flags & warren_core::packet::tcp::SYN != 0
        {
            let mut b = packet.to_vec();
            warren_core::packet::clamp_mss(
                &mut b,
                &p,
                warren_core::packet::mss_for(self.mtu, p.src.is_ipv4()),
            );
            let _ = self.tx.send_datagram(0, &b);
            return;
        }
        let _ = self.tx.send_datagram(0, packet);
    }
}

fn map_refusal(r: Refusal) -> ConnectError {
    let details = match r.error {
        "destination_unavailable" => format!("{} (no connector for this app is online)", r.details),
        "http_request_denied" | "destination_ip_prohibited" => {
            format!("{} (not permitted)", r.details)
        }
        "connection_limit_reached" => {
            format!("{} (too many connections from this device)", r.details)
        }
        _ => r.details,
    };
    ConnectError::Refused {
        error: r.error.to_owned(),
        details,
    }
}

struct Outer {
    tx: TunnelSender,
    rx: warren_masque::tunnel::TunnelReceiver,
    conn: OuterConn,
    relay: String,
}

async fn dial_outer(
    config: &ClientConfig,
    endpoint: &quinn::Endpoint,
    quic_config: &quinn::ClientConfig,
    h2_tls: &Arc<rustls::ClientConfig>,
) -> Result<Outer, ConnectError> {
    let mut errors = Vec::new();
    let mut refusal = None;
    for relay in &config.relays {
        let conn = match carrier::dial(
            config.transport,
            endpoint,
            relay,
            quic_config.clone(),
            h2_tls.clone(),
            config.fallback_delay,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                errors.push(e.to_string());
                continue;
            }
        };
        let limit = 1 + usize::from(params::QUIC_MIN_UDP_PAYLOAD);
        match conn
            .open_tunnel(&connect::udp_to_group(&relay.name, &config.group), limit)
            .await
        {
            Ok((_, tx, rx)) => {
                return Ok(Outer {
                    tx,
                    rx,
                    conn,
                    relay: relay.name.clone(),
                });
            }
            Err(OpenError::Refused(r)) => {
                conn.close("refused");
                // A refusal is an answer, not a transport failure; another
                // relay may still have a replica attached.
                refusal = Some(map_refusal(r));
            }
            Err(e) => {
                conn.close("failed");
                errors.push(e.to_string());
            }
        }
    }
    Err(refusal.unwrap_or_else(|| ConnectError::Unreachable(errors.join("; "))))
}

/// Sets up the tunnel.
pub async fn connect(config: ClientConfig) -> Result<Tunnel, ConnectError> {
    if config.tunnel_mtu < params::TUNNEL_MTU_FLOOR {
        return Err(ConnectError::MtuFloor(format!(
            "configured {} bytes; RFC 9484 requires at least {}",
            config.tunnel_mtu,
            params::TUNNEL_MTU_FLOOR
        )));
    }
    let leaf = config
        .credentials
        .chain
        .first()
        .ok_or_else(|| ConnectError::Credentials("empty certificate chain".into()))?;
    let identity = pki::check_client_profile(leaf, &config.trust.trust_domain)
        .map_err(|e| ConnectError::Credentials(e.to_string()))?;

    // Outer layer.
    let relay_verifier = Arc::new(WarrenServerVerifier::new(
        config.trust.clone(),
        ExpectServer::Relay,
        Arc::new(NoRevocations),
    ));
    let outer_quic_tls =
        tls::client_config(&config.credentials, relay_verifier.clone(), tls::ALPN_H3)
            .map_err(|e| ConnectError::Credentials(e.to_string()))?;
    let h2_tls = Arc::new(
        tls::client_config(&config.credentials, relay_verifier, tls::ALPN_H2)
            .map_err(|e| ConnectError::Credentials(e.to_string()))?,
    );
    let outer_quic = quic::client_config(outer_quic_tls, Layer::Outer, config.tuning);
    let bind: SocketAddr = match config.relays.first().map(|r| r.quic) {
        Some(SocketAddr::V6(_)) => "[::]:0".parse().expect("valid"),
        _ => "0.0.0.0:0".parse().expect("valid"),
    };
    let outer_endpoint = quinn::Endpoint::new(
        quic::endpoint_config(Layer::Outer),
        None,
        std::net::UdpSocket::bind(bind).map_err(|e| ConnectError::Unreachable(e.to_string()))?,
        quinn::default_runtime()
            .ok_or_else(|| ConnectError::Unreachable("no async runtime".into()))?,
    )
    .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
    let outer = dial_outer(&config, &outer_endpoint, &outer_quic, &h2_tls).await?;
    info!(relay = %outer.relay, carrier = ?outer.conn.carrier(), "spliced through relay");

    // Inner session over the outer stream.
    let path = Arc::new(OuterPath::default());
    *path.tx.write().expect("path lock") = Some(outer.tx.clone());
    let (socket, inbound) = VirtualSocket::new(
        "[fd00:7761:7272:6e02::2]:443".parse().expect("valid"),
        path.clone(),
    );
    let inner_endpoint = vsock::endpoint(quic::endpoint_config(Layer::Inner), None, socket)
        .map_err(|e| ConnectError::Session(e.to_string()))?;
    let connector_addr: SocketAddr = CONNECTOR_VIRTUAL.parse().expect("valid");
    let (carrier_tx, carrier_rx) = watch::channel(Some(outer.conn.carrier()));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (events_tx, events_rx) = mpsc::channel(256);
    tokio::spawn(supervise_outer(
        config.clone(),
        outer,
        path.clone(),
        inbound,
        connector_addr,
        outer_endpoint.clone(),
        outer_quic,
        h2_tls,
        carrier_tx,
        events_tx.clone(),
        shutdown_rx,
    ));

    let inner_verifier = Arc::new(WarrenServerVerifier::new(
        config.trust.clone(),
        ExpectServer::Connector {
            group: config.group.clone(),
        },
        Arc::new(NoRevocations),
    ));
    let inner_tls = tls::client_config(&config.credentials, inner_verifier, tls::ALPN_H3)
        .map_err(|e| ConnectError::Credentials(e.to_string()))?;
    let inner_config = quic::client_config(inner_tls, Layer::Inner, TransportTuning::default());
    let target = connect::group_target(&config.group);
    let inner = inner_endpoint
        .connect_with(inner_config, connector_addr, &target)
        .map_err(|e| ConnectError::Session(e.to_string()))?
        .await
        .map_err(|e| ConnectError::Session(format!("handshake with the connector: {e}")))?;
    let h3 = H3Connection::new(inner.clone(), false)
        .await
        .map_err(|e| ConnectError::Session(e.to_string()))?;
    // The inner session must carry datagrams; without them the floor
    // cannot be met efficiently and the profile requires them.
    h3.require_masque()
        .await
        .map_err(|e| ConnectError::Session(e.to_string()))?;
    let limit = 1 + usize::from(config.tunnel_mtu);
    let (_, tx, mut rx) = match OuterConn::H3(h3.clone())
        .open_tunnel(&connect::ip(&config.group), limit)
        .await
    {
        Ok(t) => t,
        Err(OpenError::Refused(r)) => return Err(map_refusal(r)),
        Err(e) => return Err(ConnectError::Session(e.to_string())),
    };

    // Addresses: exactly the certificate's.
    let id = &identity.identity;
    let request = vec![
        AddressEntry {
            request_id: 1,
            addr: IpAddr::V4(id.tunnel_v4),
            prefix_len: 32,
        },
        AddressEntry {
            request_id: 2,
            addr: IpAddr::V6(id.tunnel_v6),
            prefix_len: 128,
        },
    ];
    tx.send_capsule(&Capsule::AddressRequest(request))
        .await
        .map_err(|_| ConnectError::Session("tunnel closed".into()))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut addresses, mut routes) = (None, None);
    while addresses.is_none() || routes.is_none() {
        let wait = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(wait, rx.capsules.recv()).await {
            Ok(Some(Capsule::AddressAssign(a))) => {
                let got: Vec<IpAddr> = a
                    .iter()
                    .filter(|e| !e.addr.is_unspecified())
                    .map(|e| e.addr)
                    .collect();
                if got.is_empty() {
                    return Err(ConnectError::Session(
                        "the connector assigned no addresses".into(),
                    ));
                }
                addresses = Some(got);
            }
            Ok(Some(Capsule::RouteAdvertisement(r))) => routes = Some(r),
            Ok(Some(Capsule::Notice(n))) => {
                return Err(ConnectError::Session(format!(
                    "{}: {}",
                    n.reason, n.message
                )));
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ConnectError::Session(
                    "the connector closed the tunnel".into(),
                ));
            }
            Err(_) => {
                return Err(ConnectError::Session(
                    "no address assignment from the connector".into(),
                ));
            }
        }
    }

    let (packets_tx, packets) = mpsc::channel(4096);
    let binds: Arc<Mutex<HashMap<IpAddr, oneshot::Sender<Result<(), BindRejected>>>>> =
        Arc::default();
    {
        let binds = binds.clone();
        let packets_tx = packets_tx.clone();
        let events_tx = events_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    d = rx.datagrams.recv() => {
                        let Some(d) = d else { break };
                        if let Some((0, pkt)) = split_context(&d) {
                            let _ = packets_tx.try_send(pkt);
                        }
                    }
                    c = rx.capsules.recv() => match c {
                        None => break,
                        Some(Capsule::FlowDenied(d)) => {
                            info!(reason = %d.reason, message = %d.message, "flow denied");
                            let _ = events_tx.try_send(ClientEvent::Denied(d));
                        }
                        Some(Capsule::Notice(n)) => {
                            info!(reason = %n.reason, message = %n.message, "notice");
                            let _ = events_tx.try_send(ClientEvent::Notice(n));
                        }
                        Some(Capsule::NameBound(b)) => {
                            if let Some(done) = binds.lock().expect("binds lock").remove(&b.address) {
                                let _ = done.send(if b.accepted {
                                    Ok(())
                                } else {
                                    Err(BindRejected { reason: b.reason, message: b.message })
                                });
                            }
                        }
                        Some(_) => {}
                    }
                }
            }
            let reason = rx
                .closed
                .borrow()
                .clone()
                .unwrap_or_else(|| "closed".into());
            let _ = events_tx.try_send(ClientEvent::Closed(reason));
        });
    }

    Ok(Tunnel {
        info: TunnelInfo {
            addresses: addresses.unwrap_or_default(),
            routes: routes.unwrap_or_default(),
            tunnel_mtu: config.tunnel_mtu,
            identity,
        },
        tx,
        packets,
        local: packets_tx,
        events: Some(events_rx),
        binds,
        inner,
        outer: path,
        carrier: carrier_rx,
        _endpoint: inner_endpoint,
        shutdown,
    })
}

/// Feeds the inner session from the current outer stream and re-dials when
/// it breaks; the inner session then migrates to the new path.
#[allow(clippy::too_many_arguments)]
async fn supervise_outer(
    config: ClientConfig,
    mut outer: Outer,
    path: Arc<OuterPath>,
    inbound: Inbound,
    connector: SocketAddr,
    endpoint: quinn::Endpoint,
    quic_config: quinn::ClientConfig,
    h2_tls: Arc<rustls::ClientConfig>,
    carrier: watch::Sender<Option<CarrierKind>>,
    events: mpsc::Sender<ClientEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        loop {
            tokio::select! {
                d = outer.rx.datagrams.recv() => {
                    let Some(d) = d else { break };
                    if let Some((0, pkt)) = split_context(&d) {
                        inbound.deliver(connector, pkt);
                    }
                }
                c = outer.rx.capsules.recv() => {
                    if c.is_none() { break }
                }
                _ = shutdown.changed() => {
                    outer.conn.close("client closed");
                    return;
                }
            }
        }
        debug!(relay = %outer.relay, "outer path lost");
        outer.conn.close("path lost");
        *path.tx.write().expect("path lock") = None;
        carrier.send_replace(None);
        let mut backoff = Duration::from_millis(50);
        outer = loop {
            if *shutdown.borrow() {
                return;
            }
            match dial_outer(&config, &endpoint, &quic_config, &h2_tls).await {
                Ok(o) => break o,
                Err(e) => {
                    warn!(error = %e, "re-dial failed");
                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        _ = shutdown.changed() => return,
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        };
        info!(relay = %outer.relay, carrier = ?outer.conn.carrier(), "outer path re-established; migrating");
        *path.tx.write().expect("path lock") = Some(outer.tx.clone());
        carrier.send_replace(Some(outer.conn.carrier()));
        let _ = events.try_send(ClientEvent::PathChanged {
            carrier: outer.conn.carrier(),
            relay: outer.relay.clone(),
        });
    }
}
