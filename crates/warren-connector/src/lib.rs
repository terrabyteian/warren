//! The connector role.
//!
//! Dials out to every relay in its relay set and attaches with a bound
//! CONNECT-UDP request, so it needs no inbound port (G6). Clients reach it
//! through those attachments: each spliced client is a virtual peer on a
//! bind stream, and the connector's inner QUIC endpoint runs over all of
//! them. It terminates each inner, mutually authenticated session, accepts
//! one CONNECT-IP request on it, and admits every flow against the
//! invariants and policy (G1, G7) before forwarding it (kernel mode: TUN
//! plus NAT). Every decision and every flow is audited (G13).

mod forward;
mod session;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};
use warren_core::audit::AuditSink;
use warren_core::bundle::{CompiledBundle, IpNet, NodeState};
use warren_core::metrics::{Counter, Gauge, Registry};
use warren_core::params;
use warren_core::pki::{PeerIdentity, TrustBundle};
use warren_core::quic::{self, Layer, TransportTuning};
use warren_core::tls::{
    self, AcceptClients, Credentials, ExpectServer, RevocationCheck, WarrenClientVerifier,
    WarrenServerVerifier,
};
use warren_core::vsock::{self, Inbound, PacketSink, VirtualSocket};
use warren_masque::capsule::{Capsule, split_context};
use warren_masque::connect::{self, Refusal};
use warren_masque::h3::H3Connection;
use warren_masque::http::ResponseHead;
use warren_masque::session::{self as carrier, Incoming, OuterConn, RelayAddress, TransportMode};
use warren_masque::tunnel::{TunnelReceiver, TunnelSender};

#[cfg(target_os = "linux")]
pub use forward::kernel;
pub use forward::{Backend, Forwarder};
pub use session::{Resolver, SystemResolver};

/// One-line description of the role, shown by `warren connector --help`.
pub const ABOUT: &str = "Run a connector that enforces policy and reaches private apps";

/// Connector configuration.
#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    /// The connector group this replica serves (must match its certificate).
    pub group: String,
    /// The relays to attach to.
    pub relays: Vec<RelayAddress>,
    /// Which carriers to use for attachments.
    pub transport: TransportMode,
    /// The connector's infrastructure certificate and key.
    pub credentials: Credentials,
    /// The deployment trust bundle.
    pub trust: Arc<TrustBundle>,
    /// The node bundle: entities, scopes, revocations (and, for the static
    /// decision point, rules).
    pub state: Arc<NodeState>,
    /// The policy decision point every flow that passes the invariants is
    /// put to: [`warren_core::policy::StaticPolicy`] over the bundle until
    /// the control plane's compiled policy is available.
    pub policy: Arc<dyn warren_core::policy::PolicyDecisionPoint>,
    /// Where audit records go.
    pub audit: AuditSink,
    /// Name resolution for name apps.
    pub resolver: Arc<dyn Resolver>,
    /// Synthetic pools clients answer names from, advertised as routes.
    pub synthetic_pools: Vec<IpNet>,
    /// The tunnel MTU (at least the 1280-byte floor).
    pub tunnel_mtu: u16,
    /// Transport overrides for tests.
    pub tuning: TransportTuning,
}

/// Connector metrics.
#[derive(Debug, Clone)]
pub struct ConnectorMetrics {
    /// The registry they are exposed through.
    pub registry: Registry,
    /// Live relay attachments.
    pub attachments: Gauge,
    /// Live inner sessions.
    pub sessions: Gauge,
    /// Inner sessions accepted.
    pub sessions_total: Counter,
    /// Flows admitted.
    pub flows_allowed: Counter,
    /// Flows denied.
    pub flows_denied: Counter,
    /// Live flows.
    pub flows: Gauge,
    /// Packets forwarded to the private network.
    pub packets_out: Counter,
    /// Packets returned to clients.
    pub packets_in: Counter,
    /// Packets dropped (spoofed source, malformed, no flow).
    pub dropped: Counter,
    /// Packets sent as DATAGRAM capsules because they did not fit a frame.
    pub capsule_fallbacks: Counter,
}

impl ConnectorMetrics {
    fn new() -> ConnectorMetrics {
        let r = Registry::default();
        ConnectorMetrics {
            attachments: r.gauge("warren_connector_attachments", "Relay attachments live"),
            sessions: r.gauge("warren_connector_sessions", "Inner sessions live"),
            sessions_total: r.counter("warren_connector_sessions_total", "Inner sessions accepted"),
            flows_allowed: r.counter("warren_connector_flows_allowed_total", "Flows admitted"),
            flows_denied: r.counter("warren_connector_flows_denied_total", "Flows denied"),
            flows: r.gauge("warren_connector_flows", "Flows live"),
            packets_out: r.counter(
                "warren_connector_packets_out_total",
                "Packets forwarded to private networks",
            ),
            packets_in: r.counter(
                "warren_connector_packets_in_total",
                "Packets returned to clients",
            ),
            dropped: r.counter("warren_connector_packets_dropped_total", "Packets dropped"),
            capsule_fallbacks: r.counter(
                "warren_connector_capsule_fallbacks_total",
                "Packets carried in DATAGRAM capsules because they did not fit a frame",
            ),
            registry: r,
        }
    }
}

/// A bind stream's virtual peers.
#[derive(Debug)]
struct Attachment {
    tx: TunnelSender,
    relay: String,
}

/// Maps virtual peer addresses to the bind stream and context that reach
/// them, for the inner endpoint's outgoing packets.
#[derive(Debug, Default)]
struct PeerTable {
    peers: RwLock<HashMap<SocketAddr, (Arc<Attachment>, u64)>>,
    /// Relay-observed public addresses, by virtual peer.
    observed: RwLock<HashMap<SocketAddr, SocketAddr>>,
}

impl PacketSink for PeerTable {
    fn send_to(&self, dst: SocketAddr, packet: &[u8]) {
        let entry = self.peers.read().expect("peers lock").get(&dst).cloned();
        if let Some((a, ctx)) = entry {
            let _ = a.tx.send_datagram(ctx, packet);
        }
    }
}

/// Routes return traffic to the session owning a device address.
#[derive(Debug, Default)]
pub(crate) struct Routes {
    by_addr: RwLock<HashMap<IpAddr, (u64, mpsc::Sender<session::Event>)>>,
}

impl Routes {
    pub(crate) fn insert(&self, addr: IpAddr, session: u64, tx: mpsc::Sender<session::Event>) {
        self.by_addr
            .write()
            .expect("routes lock")
            .insert(addr, (session, tx));
    }

    pub(crate) fn remove(&self, addr: IpAddr, session: u64) {
        let mut m = self.by_addr.write().expect("routes lock");
        if m.get(&addr).is_some_and(|(s, _)| *s == session) {
            m.remove(&addr);
        }
    }

    fn get(&self, addr: &IpAddr) -> Option<mpsc::Sender<session::Event>> {
        self.by_addr
            .read()
            .expect("routes lock")
            .get(addr)
            .map(|(_, tx)| tx.clone())
    }

    fn all(&self) -> Vec<mpsc::Sender<session::Event>> {
        let mut seen = std::collections::HashSet::new();
        self.by_addr
            .read()
            .expect("routes lock")
            .values()
            .filter(|(id, _)| seen.insert(*id))
            .map(|(_, tx)| tx.clone())
            .collect()
    }
}

pub(crate) struct Shared {
    pub(crate) config: ConnectorConfig,
    pub(crate) forwarder: Arc<dyn Forwarder>,
    pub(crate) routes: Routes,
    pub(crate) metrics: ConnectorMetrics,
    peers: Arc<PeerTable>,
    pub(crate) next_id: AtomicU64,
    draining: watch::Sender<bool>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("group", &self.config.group)
            .finish_non_exhaustive()
    }
}

impl Shared {
    pub(crate) fn observed(&self, peer: SocketAddr) -> Option<SocketAddr> {
        self.peers
            .observed
            .read()
            .expect("observed lock")
            .get(&peer)
            .copied()
    }
}

/// A running connector.
#[derive(Debug)]
pub struct Connector {
    shared: Arc<Shared>,
    endpoint: quinn::Endpoint,
    shutdown: watch::Sender<bool>,
}

impl Connector {
    /// Starts the connector on a forwarding backend: attaches to every
    /// relay and serves inner sessions.
    pub fn start(config: ConnectorConfig, backend: Backend) -> std::io::Result<Connector> {
        if config.tunnel_mtu < params::TUNNEL_MTU_FLOOR {
            return Err(std::io::Error::other(format!(
                "tunnel MTU {} is below the {}-byte floor",
                config.tunnel_mtu,
                params::TUNNEL_MTU_FLOOR
            )));
        }
        let peers = Arc::new(PeerTable::default());
        let virtual_local: SocketAddr = "[fd00::1]:443".parse().expect("valid address");
        let (socket, inbound) = VirtualSocket::new(virtual_local, peers.clone());

        let verifier = Arc::new(WarrenClientVerifier::new(
            config.trust.clone(),
            AcceptClients {
                users: true,
                nodes: vec![],
            },
            config.state.clone() as Arc<dyn RevocationCheck>,
        ));
        let inner_tls = tls::server_config(&config.credentials, verifier, &[tls::ALPN_H3])
            .map_err(std::io::Error::other)?;
        let server = quic::server_config(inner_tls, Layer::Inner, config.tuning);
        let endpoint = vsock::endpoint(quic::endpoint_config(Layer::Inner), Some(server), socket)?;

        let (shutdown, shutdown_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            forwarder: backend.forwarder,
            routes: Routes::default(),
            metrics: ConnectorMetrics::new(),
            peers,
            next_id: AtomicU64::new(1),
            draining: watch::channel(false).0,
            config,
        });
        for relay in shared.config.relays.clone() {
            tokio::spawn(attach_loop(
                shared.clone(),
                relay,
                inbound.clone(),
                shutdown_rx.clone(),
            ));
        }
        tokio::spawn(serve_inner(
            shared.clone(),
            endpoint.clone(),
            shutdown_rx.clone(),
        ));
        tokio::spawn(dispatch_returns(shared.clone(), backend.returns));
        tokio::spawn(sweep(shared.clone(), shutdown_rx));
        info!(group = %shared.config.group, relays = shared.config.relays.len(), "connector started");
        Ok(Connector {
            shared,
            endpoint,
            shutdown,
        })
    }

    /// Metrics.
    pub fn metrics(&self) -> &ConnectorMetrics {
        &self.shared.metrics
    }

    /// Replaces the node bundle and re-evaluates every live session and
    /// flow against it, cutting what it no longer allows.
    pub fn reload(&self, bundle: CompiledBundle) -> Result<(), String> {
        self.shared
            .config
            .state
            .replace(bundle)
            .map_err(|e| e.to_string())?;
        for tx in self.shared.routes.all() {
            let _ = tx.try_send(session::Event::Reevaluate);
        }
        Ok(())
    }

    /// Starts draining: relays stop sending new clients, existing sessions
    /// are told and given up to `timeout` to finish.
    pub async fn drain(&self, timeout: Duration) {
        self.shared.draining.send_replace(true);
        for tx in self.shared.routes.all() {
            let _ = tx.try_send(session::Event::Draining);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        while self.shared.metrics.sessions.get() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Stops everything.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        self.endpoint
            .close(quinn::VarInt::from_u32(0x100), b"connector shutting down");
    }
}

async fn attach_loop(
    shared: Arc<Shared>,
    relay: RelayAddress,
    inbound: Inbound,
    mut shutdown: watch::Receiver<bool>,
) {
    let c = &shared.config;
    let verifier = Arc::new(WarrenServerVerifier::new(
        c.trust.clone(),
        ExpectServer::Relay,
        c.state.clone() as Arc<dyn RevocationCheck>,
    ));
    let quic_tls = match tls::client_config(&c.credentials, verifier.clone(), tls::ALPN_H3) {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "invalid connector credentials");
            return;
        }
    };
    let h2_tls = match tls::client_config(&c.credentials, verifier, tls::ALPN_H2) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            warn!(error = %e, "invalid connector credentials");
            return;
        }
    };
    let quic_config = quic::client_config(quic_tls, Layer::Outer, c.tuning);
    let bind_addr: SocketAddr = if relay.quic.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid")
    } else {
        "[::]:0".parse().expect("valid")
    };
    let endpoint = match quinn::Endpoint::new(
        quic::endpoint_config(Layer::Outer),
        None,
        match std::net::UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "cannot bind a UDP socket");
                return;
            }
        },
        quinn::default_runtime().expect("tokio runtime"),
    ) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "cannot start a QUIC endpoint");
            return;
        }
    };
    let mut backoff = Duration::from_millis(100);
    loop {
        if *shutdown.borrow() {
            return;
        }
        let dialled = carrier::dial(
            c.transport,
            &endpoint,
            &relay,
            quic_config.clone(),
            h2_tls.clone(),
            params::FALLBACK_DELAY,
        )
        .await;
        match dialled {
            Ok(conn) => {
                backoff = Duration::from_millis(100);
                let reason = attach_once(&shared, &relay, &conn, &inbound, &mut shutdown).await;
                conn.close("detached");
                info!(relay = %relay.name, reason = %reason, "attachment ended");
                if *shutdown.borrow() {
                    return;
                }
                // Re-attach at once (docs/protocol.md section 4.2).
                continue;
            }
            Err(e) => warn!(relay = %relay.name, error = %e, "cannot reach relay"),
        }
        let jitter = Duration::from_millis(u64::from(rand_u16() % 250));
        tokio::select! {
            () = tokio::time::sleep(backoff + jitter) => {}
            _ = shutdown.changed() => return,
        }
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    let _ = rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut b);
    u16::from_ne_bytes(b)
}

async fn attach_once(
    shared: &Arc<Shared>,
    relay: &RelayAddress,
    conn: &OuterConn,
    inbound: &Inbound,
    shutdown: &mut watch::Receiver<bool>,
) -> String {
    let head = connect::udp_bind(&relay.name);
    let limit = warren_masque::varint::len(params::MAX_BIND_CONTEXT_ID)
        + usize::from(params::QUIC_MIN_UDP_PAYLOAD);
    let (resp, tx, mut rx) = match conn.open_tunnel(&head, limit).await {
        Ok(t) => t,
        Err(e) => return format!("bind refused: {e}"),
    };
    if resp.header(connect::CONNECT_UDP_BIND) != Some("?1") {
        return "relay does not support bound CONNECT-UDP".into();
    }
    let attachment = Arc::new(Attachment {
        tx,
        relay: relay.name.clone(),
    });
    shared.metrics.attachments.inc();
    info!(relay = %relay.name, carrier = ?conn.carrier(), "attached");
    let mut mine: HashMap<u64, SocketAddr> = HashMap::new();
    // Datagrams for contexts announced but not yet processed are held
    // briefly instead of dropped.
    let mut pending: HashMap<u64, Vec<Bytes>> = HashMap::new();
    let mut draining = shared.draining.subscribe();
    let reason = loop {
        tokio::select! {
            d = rx.datagrams.recv() => {
                let Some(d) = d else { break closed_reason(&rx) };
                let Some((ctx, payload)) = split_context(&d) else { continue };
                match mine.get(&ctx) {
                    Some(peer) => inbound.deliver(*peer, payload),
                    None if ctx % 2 == 1 && pending.len() < 64 => {
                        let q = pending.entry(ctx).or_default();
                        if q.len() < 16 {
                            q.push(payload);
                        }
                    }
                    None => {}
                }
            }
            c = rx.capsules.recv() => {
                let Some(c) = c else { break closed_reason(&rx) };
                match c {
                    Capsule::CompressionAssign { context_id, target: Some(peer) } if context_id % 2 == 1 => {
                        let fresh = !mine.contains_key(&context_id) && {
                            let mut peers = shared.peers.peers.write().expect("peers lock");
                            let fresh = !peers.contains_key(&peer);
                            if fresh {
                                peers.insert(peer, (attachment.clone(), context_id));
                            }
                            fresh
                        };
                        if !fresh {
                            let _ = attachment.tx.send_capsule(&Capsule::CompressionClose(context_id)).await;
                            continue;
                        }
                        mine.insert(context_id, peer);
                        let _ = attachment.tx.send_capsule(&Capsule::CompressionAck(context_id)).await;
                        for p in pending.remove(&context_id).unwrap_or_default() {
                            inbound.deliver(peer, p);
                        }
                    }
                    Capsule::CompressionAssign { context_id, .. } => {
                        // Uncompressed contexts and even IDs are not part of
                        // warren's profile.
                        let _ = attachment.tx.send_capsule(&Capsule::CompressionClose(context_id)).await;
                    }
                    Capsule::CompressionClose(ctx) => {
                        pending.remove(&ctx);
                        if let Some(peer) = mine.remove(&ctx) {
                            shared.peers.peers.write().expect("peers lock").remove(&peer);
                            shared.peers.observed.write().expect("observed lock").remove(&peer);
                        }
                    }
                    Capsule::PeerInfo(info) => {
                        if let Some(peer) = mine.get(&info.context_id) {
                            shared.peers.observed.write().expect("observed lock").insert(*peer, info.observed);
                        }
                    }
                    Capsule::Notice(n) => debug!(relay = %relay.name, reason = %n.reason, "relay notice"),
                    _ => {}
                }
            }
            () = async { let _ = draining.wait_for(|d| *d).await; } => {
                if let OuterConn::H3(h3) = conn {
                    let _ = h3.send_goaway().await;
                }
                // Keep serving existing peers until the session drain ends.
                let _ = shutdown.wait_for(|s| *s).await;
                break "drained".into();
            }
            _ = shutdown.changed() => break "shutdown".into(),
        }
    };
    {
        let mut peers = shared.peers.peers.write().expect("peers lock");
        let mut observed = shared.peers.observed.write().expect("observed lock");
        for peer in mine.values() {
            peers.remove(peer);
            observed.remove(peer);
        }
    }
    shared.metrics.attachments.dec();
    debug!(relay = %attachment.relay, "attachment state cleared");
    reason
}

fn closed_reason(rx: &TunnelReceiver) -> String {
    rx.closed
        .borrow()
        .clone()
        .unwrap_or_else(|| "bind stream closed".into())
}

async fn serve_inner(
    shared: Arc<Shared>,
    endpoint: quinn::Endpoint,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let incoming = tokio::select! {
            i = endpoint.accept() => i,
            _ = shutdown.changed() => return,
        };
        let Some(incoming) = incoming else { return };
        let shared = shared.clone();
        tokio::spawn(async move {
            let peer_addr = incoming.remote_address();
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    debug!(error = %e, "inner handshake failed");
                    return;
                }
            };
            let certs = carrier::peer_certificates(&conn);
            let c = &shared.config;
            let identity = certs.first().and_then(|leaf| {
                tls::verify_client(
                    &c.trust,
                    &AcceptClients {
                        users: true,
                        nodes: vec![],
                    },
                    c.state.as_ref(),
                    leaf,
                    tls::now(),
                )
                .ok()
            });
            let Some(PeerIdentity::Client(client)) = identity else {
                conn.close(quinn::VarInt::from_u32(0x102), b"unidentified client");
                return;
            };
            let h3 = match H3Connection::new(conn.clone(), true).await {
                Ok(h) => h,
                Err(e) => {
                    debug!(error = %e, "inner HTTP/3 setup failed");
                    return;
                }
            };
            // One CONNECT-IP per inner session.
            let accepted = h3.accept_request().await;
            let (head, stream) = match accepted {
                Ok(Some(r)) => r,
                _ => {
                    h3.close(warren_masque::h3::code::NO_ERROR, "no request");
                    return;
                }
            };
            if let Err(refusal) = connect::parse_connector_request(&head, &c.group) {
                Incoming::H3(stream)
                    .refuse(&refusal, &format!("warren-connector-{}", c.group))
                    .await;
                h3.close(warren_masque::h3::code::NO_ERROR, "refused");
                return;
            }
            if *shared.draining.borrow() {
                let r = Refusal::new(503, "destination_unavailable", "connector is draining");
                Incoming::H3(stream)
                    .refuse(&r, &format!("warren-connector-{}", c.group))
                    .await;
                h3.close(warren_masque::h3::code::NO_ERROR, "draining");
                return;
            }
            let limit = 1 + usize::from(c.tunnel_mtu);
            let (tx, rx) = match Incoming::H3(stream)
                .accept(&ResponseHead::new(200), limit)
                .await
            {
                Ok(t) => t,
                Err(_) => return,
            };
            session::run(shared.clone(), client, conn.clone(), peer_addr, tx, rx).await;
            h3.close(warren_masque::h3::code::NO_ERROR, "session ended");
        });
    }
}

async fn dispatch_returns(shared: Arc<Shared>, mut returns: mpsc::Receiver<Bytes>) {
    while let Some(packet) = returns.recv().await {
        let dst = match warren_core::packet::parse(&packet) {
            Ok(p) => p.dst,
            Err(_) => {
                shared.metrics.dropped.inc();
                continue;
            }
        };
        match shared.routes.get(&dst) {
            Some(tx) => {
                if tx.try_send(session::Event::Return(packet)).is_err() {
                    shared.metrics.dropped.inc();
                }
            }
            None => shared.metrics.dropped.inc(),
        }
    }
}

async fn sweep(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                for tx in shared.routes.all() {
                    let _ = tx.try_send(session::Event::Tick);
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}
