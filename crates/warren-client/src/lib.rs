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
//! Around the tunnel, the client core holds everything a native shell
//! shares: signing in and enrolling ([`signin`]), the device key in the
//! Secure Enclave ([`device`]), the control-plane calls of link D
//! ([`control`]), the state kept between runs ([`state`]), relay choice
//! ([`relays`]), and the engine that keeps one tunnel per connector group
//! and routes only internal apps into them ([`engine`]).
//!
//! This crate is a data-path build: it must never link control-plane,
//! console or Kubernetes crates, which `scripts/check-closure.sh` enforces.

#[cfg(target_os = "macos")]
mod apple;
pub mod control;
pub mod device;
pub mod engine;
pub mod relays;
pub mod signin;
pub mod state;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};
use warren_core::params;
use warren_core::pki::{self, ClientIdentity, TrustBundle};
use warren_core::quic::{self, Layer, TransportTuning};
use warren_core::tls::{
    self, DeviceCredentials, ExpectServer, NoRevocations, WarrenServerVerifier,
};
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
    /// The user+device certificate and the device key, which may live in
    /// hardware.
    pub credentials: DeviceCredentials,
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
    /// The relay rejected this device's certificate as revoked or expired.
    Rejected(String),
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
            ConnectError::Rejected(m) => write!(f, "access revoked or certificate expired: {m}"),
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

/// Name binds waiting for the connector's answer.
type PendingBinds = Arc<Mutex<HashMap<IpAddr, oneshot::Sender<Result<(), BindRejected>>>>>;

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
    /// The relay the session was set up through.
    pub relay: String,
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
    binds: PendingBinds,
    inner: quinn::Connection,
    outer: Arc<OuterPath>,
    carrier: watch::Receiver<Option<CarrierKind>>,
    _endpoint: quinn::Endpoint,
    shutdown: Arc<watch::Sender<bool>>,
    renew: watch::Sender<Option<DeviceCredentials>>,
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

    /// Moves the tunnel to a renewed certificate: the connector gets it in
    /// a `WARREN_CERT_REFRESH` capsule, signed with the device key over the
    /// session's exporter value so it is bound to this session, and the
    /// outer path is re-established with it before the old certificate
    /// expires (docs/protocol.md sections 4.3 and 5). `sign` signs with the
    /// device key, which may live in hardware.
    pub async fn refresh_certificate(
        &self,
        credentials: impl Into<DeviceCredentials>,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<(), String> {
        let credentials = credentials.into();
        let mut exporter = [0u8; 32];
        self.inner
            .export_keying_material(&mut exporter, REFRESH_EXPORTER_LABEL, b"")
            .map_err(|_| "keying material export failed".to_owned())?;
        let signature = sign(&exporter)?;
        let capsule = Capsule::CertRefresh(CertRefresh {
            chain: credentials
                .chain()
                .iter()
                .map(|c| Bytes::copy_from_slice(c))
                .collect(),
            signature: Bytes::from(signature),
        });
        self.tx
            .send_capsule(&capsule)
            .await
            .map_err(|_| "tunnel closed".to_owned())?;
        self.renew.send_replace(Some(credentials));
        Ok(())
    }

    /// Closes the tunnel.
    pub fn close(&self) {
        self.closer().close();
    }

    /// A handle that closes the tunnel from anywhere.
    pub fn closer(&self) -> TunnelCloser {
        TunnelCloser {
            inner: self.inner.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

/// Closes a tunnel, for example from another task than the one moving its
/// packets.
#[derive(Debug, Clone)]
pub struct TunnelCloser {
    inner: quinn::Connection,
    shutdown: Arc<watch::Sender<bool>>,
}

impl TunnelCloser {
    /// Closes the inner session and the outer path.
    pub fn close(&self) {
        self.inner
            .close(quinn::VarInt::from_u32(0x100), b"client closed");
        let _ = self.shutdown.send(true);
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
    /// Position in the relay list, so a re-dial starts with the next one.
    index: usize,
}

async fn dial_outer(
    config: &ClientConfig,
    endpoint: &quinn::Endpoint,
    quic_config: &quinn::ClientConfig,
    h2_tls: &Arc<rustls::ClientConfig>,
    first: usize,
    connector: Option<&str>,
) -> Result<Outer, ConnectError> {
    let mut errors = Vec::new();
    let mut refusal = None;
    let mut rejected = false;
    let n = config.relays.len();
    for i in 0..n {
        let index = (first + i) % n;
        let relay = &config.relays[index];
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
                rejected |= e.credentials_rejected;
                errors.push(e.to_string());
                continue;
            }
        };
        let limit = 1 + usize::from(params::QUIC_MIN_UDP_PAYLOAD);
        let mut head = connect::udp_to_group(&relay.name, &config.group);
        if let Some(id) = connector {
            head.headers
                .push((connect::WARREN_CONNECTOR.into(), id.to_owned()));
        }
        match conn.open_tunnel(&head, limit).await {
            Ok((_, tx, rx)) => {
                return Ok(Outer {
                    tx,
                    rx,
                    conn,
                    relay: relay.name.clone(),
                    index,
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
    if rejected {
        return Err(ConnectError::Rejected(errors.join("; ")));
    }
    Err(refusal.unwrap_or_else(|| ConnectError::Unreachable(errors.join("; "))))
}

/// The node ID in the connector certificate the inner session verified,
/// which re-dials name so the relay keeps the session on that replica
/// (docs/protocol.md section 4.3).
fn connector_id(inner: &Mutex<Option<quinn::Connection>>, trust_domain: &str) -> Option<String> {
    let conn = inner.lock().expect("inner lock").clone()?;
    let certs = carrier::peer_certificates(&conn);
    pki::check_infra_profile(certs.first()?, trust_domain)
        .ok()
        .map(|n| n.id)
}

/// Dials a new outer path in its own task, so the current one keeps
/// carrying the inner session meanwhile.
fn spawn_dial(
    config: &ClientConfig,
    endpoint: &quinn::Endpoint,
    configs: &OuterConfigs,
    first: usize,
    connector: Option<String>,
) -> tokio::task::JoinHandle<Result<Outer, ConnectError>> {
    let (config, endpoint) = (config.clone(), endpoint.clone());
    let (quic, h2) = (configs.quic.clone(), configs.h2.clone());
    tokio::spawn(async move {
        dial_outer(&config, &endpoint, &quic, &h2, first, connector.as_deref()).await
    })
}

/// TLS and QUIC configurations for dialling relays with a credential.
struct OuterConfigs {
    quic: quinn::ClientConfig,
    h2: Arc<rustls::ClientConfig>,
}

fn outer_configs(
    config: &ClientConfig,
    creds: &DeviceCredentials,
) -> Result<OuterConfigs, ConnectError> {
    let verifier = Arc::new(WarrenServerVerifier::new(
        config.trust.clone(),
        ExpectServer::Relay,
        Arc::new(NoRevocations),
    ));
    let quic_tls = tls::device_client_config(creds, verifier.clone(), tls::ALPN_H3)
        .map_err(|e| ConnectError::Credentials(e.to_string()))?;
    let h2 = tls::device_client_config(creds, verifier, tls::ALPN_H2)
        .map_err(|e| ConnectError::Credentials(e.to_string()))?;
    Ok(OuterConfigs {
        quic: quic::client_config(quic_tls, Layer::Outer, config.tuning),
        h2: Arc::new(h2),
    })
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
        .chain()
        .first()
        .ok_or_else(|| ConnectError::Credentials("empty certificate chain".into()))?;
    let identity = pki::check_client_profile(leaf, &config.trust.trust_domain)
        .map_err(|e| ConnectError::Credentials(e.to_string()))?;

    // Outer layer.
    let configs = outer_configs(&config, &config.credentials)?;
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
    let outer = dial_outer(
        &config,
        &outer_endpoint,
        &configs.quic,
        &configs.h2,
        0,
        None,
    )
    .await?;
    info!(relay = %outer.relay, carrier = ?outer.conn.carrier(), "spliced through relay");
    let relay = outer.relay.clone();

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
    let shutdown = Arc::new(shutdown);
    let inner_slot: Arc<Mutex<Option<quinn::Connection>>> = Arc::default();
    let (events_tx, events_rx) = mpsc::channel(256);
    let (renew, renew_rx) = watch::channel(None);
    tokio::spawn(supervise_outer(
        config.clone(),
        outer,
        path.clone(),
        inbound,
        connector_addr,
        outer_endpoint.clone(),
        configs,
        carrier_tx,
        events_tx.clone(),
        shutdown_rx,
        inner_slot.clone(),
        renew_rx,
    ));

    let inner_verifier = Arc::new(WarrenServerVerifier::new(
        config.trust.clone(),
        ExpectServer::Connector {
            group: config.group.clone(),
        },
        Arc::new(NoRevocations),
    ));
    let inner_tls = tls::device_client_config(&config.credentials, inner_verifier, tls::ALPN_H3)
        .map_err(|e| ConnectError::Credentials(e.to_string()))?;
    let inner_config = quic::client_config(inner_tls, Layer::Inner, TransportTuning::default());
    let target = connect::group_target(&config.group);
    let inner = inner_endpoint
        .connect_with(inner_config, connector_addr, &target)
        .map_err(|e| ConnectError::Session(e.to_string()))?
        .await
        .map_err(|e| ConnectError::Session(format!("handshake with the connector: {e}")))?;
    *inner_slot.lock().expect("inner lock") = Some(inner.clone());
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
    let binds: PendingBinds = Arc::default();
    {
        let binds = binds.clone();
        let packets_tx = packets_tx.clone();
        let events_tx = events_tx.clone();
        let shutdown = shutdown.clone();
        let inner = inner.clone();
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
            // The session is over: close it and drop the outer path too.
            inner.close(quinn::VarInt::from_u32(0x100), b"session ended");
            let _ = shutdown.send(true);
        });
    }

    Ok(Tunnel {
        info: TunnelInfo {
            addresses: addresses.unwrap_or_default(),
            routes: routes.unwrap_or_default(),
            tunnel_mtu: config.tunnel_mtu,
            identity,
            relay,
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
        renew,
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
    mut configs: OuterConfigs,
    carrier: watch::Sender<Option<CarrierKind>>,
    events: mpsc::Sender<ClientEvent>,
    mut shutdown: watch::Receiver<bool>,
    inner: Arc<Mutex<Option<quinn::Connection>>>,
    mut renew: watch::Receiver<Option<DeviceCredentials>>,
) {
    let end = |why: String| {
        info!(reason = %why, "tunnel ended");
        if let Some(c) = inner.lock().expect("inner lock").take() {
            c.close(quinn::VarInt::from_u32(0x10b), why.as_bytes());
        }
        let _ = events.try_send(ClientEvent::Closed(why));
    };
    let switch = |outer: &mut Outer, fresh: Outer, why: &str| {
        *path.tx.write().expect("path lock") = Some(fresh.tx.clone());
        carrier.send_replace(Some(fresh.conn.carrier()));
        let _ = events.try_send(ClientEvent::PathChanged {
            carrier: fresh.conn.carrier(),
            relay: fresh.relay.clone(),
        });
        let old = std::mem::replace(outer, fresh);
        old.conn.close(why);
    };
    let trust_domain = config.trust.trust_domain.clone();
    // Whether `configs` hold renewed credentials the current outer path was
    // not dialled with.
    let mut stale = false;
    let mut renewal: Option<tokio::task::JoinHandle<Result<Outer, ConnectError>>> = None;
    let mut retry: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    let mut retry_backoff = Duration::from_secs(1);
    let mut renew_open = true;
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
                r = renew.changed(), if renew_open => {
                    if r.is_err() {
                        renew_open = false;
                        continue;
                    }
                    let creds = renew.borrow_and_update().clone();
                    let Some(creds) = creds else { continue };
                    // A renewed certificate: open a new outer connection with
                    // it before the old one's certificate expires, and move
                    // the inner session over (docs/protocol.md section 4.3).
                    match outer_configs(&config, &creds) {
                        Ok(c) => configs = c,
                        Err(e) => {
                            warn!(error = %e, "renewed credentials are unusable");
                            continue;
                        }
                    }
                    stale = true;
                    retry = None;
                    retry_backoff = Duration::from_secs(1);
                    if let Some(h) = renewal.take() {
                        h.abort();
                    }
                    let id = connector_id(&inner, &trust_domain);
                    renewal = Some(spawn_dial(&config, &endpoint, &configs, outer.index, id));
                }
                res = async { renewal.as_mut().expect("renewal pending").await }, if renewal.is_some() => {
                    renewal = None;
                    match res {
                        Ok(Ok(fresh)) => {
                            info!(relay = %fresh.relay, "outer path renewed with the new certificate; migrating");
                            switch(&mut outer, fresh, "renewed");
                            stale = false;
                        }
                        Ok(Err(e)) => {
                            warn!(error = %e, retry = ?retry_backoff, "could not renew the outer path; keeping the current one");
                            retry = Some(Box::pin(tokio::time::sleep(retry_backoff)));
                            retry_backoff = (retry_backoff * 2).min(Duration::from_secs(30));
                        }
                        Err(_) => {}
                    }
                }
                () = async { retry.as_mut().expect("retry pending").await }, if retry.is_some() => {
                    retry = None;
                    let id = connector_id(&inner, &trust_domain);
                    renewal = Some(spawn_dial(&config, &endpoint, &configs, outer.index, id));
                }
                _ = shutdown.changed() => {
                    if let Some(h) = renewal.take() {
                        h.abort();
                    }
                    outer.conn.close("client closed");
                    return;
                }
            }
        }
        if let Some(h) = renewal.take() {
            h.abort();
        }
        retry = None;
        debug!(relay = %outer.relay, "outer path lost");
        // A relay that cut us for revocation will not take us back, nor will
        // one whose certificate expired unless renewed credentials are held.
        if let OuterConn::H3(h3) = &outer.conn
            && let Some(quinn::ConnectionError::ApplicationClosed(close)) = h3.quic().close_reason()
            && (&close.reason[..] == b"revoked"
                || (&close.reason[..] == b"certificate expired" && !stale))
        {
            end(format!(
                "the relay closed the connection: {}",
                String::from_utf8_lossy(&close.reason)
            ));
            return;
        }
        outer.conn.close("path lost");
        *path.tx.write().expect("path lock") = None;
        carrier.send_replace(None);
        let mut backoff = Duration::from_millis(50);
        let fresh = loop {
            if *shutdown.borrow() {
                return;
            }
            // Start with the next relay: the one that just failed is the
            // least likely to work.
            let next = (outer.index + 1) % config.relays.len().max(1);
            let id = connector_id(&inner, &trust_domain);
            match dial_outer(
                &config,
                &endpoint,
                &configs.quic,
                &configs.h2,
                next,
                id.as_deref(),
            )
            .await
            {
                Ok(o) => break o,
                Err(ConnectError::Rejected(e)) => {
                    end(format!("access revoked or certificate expired: {e}"));
                    return;
                }
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
        info!(relay = %fresh.relay, carrier = ?fresh.conn.carrier(), "outer path re-established; migrating");
        switch(&mut outer, fresh, "path lost");
        stale = false;
    }
}
