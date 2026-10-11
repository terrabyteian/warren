//! The relay role.
//!
//! A stateless rendezvous that clients and connectors both dial out to
//! (docs/protocol.md section 4). Connectors attach with a bound CONNECT-UDP
//! request; clients send CONNECT-UDP naming a connector group; the relay
//! splices each client stream to one attached replica of that group,
//! announcing the client as a virtual peer on the replica's bind stream, and
//! forwards datagram payloads byte for byte. It never forwards anywhere
//! else (G8), never sees inside the inner session (G5), and keeps no state
//! that outlives its connections.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tracing::{debug, info};
use warren_core::bundle::{CompiledBundle, NodeState};
use warren_core::identity::NodeRole;
use warren_core::metrics::{Counter, Gauge, Registry};
use warren_core::params;
use warren_core::pki::{ClientIdentity, NodeIdentity, PeerIdentity, TrustBundle};
use warren_core::quic::{self, Layer, TransportTuning};
use warren_core::tls::{
    self, AcceptClients, Credentials, NodeRoleMatch, RevocationCheck, WarrenClientVerifier,
};
use warren_masque::capsule::{Capsule, NOTICE_BIND_ROLLOVER, Notice, PeerInfo, split_context};
use warren_masque::connect::{self, CONNECT_UDP_BIND, PROXY_PUBLIC_ADDRESS, Refusal, Request};
use warren_masque::h2::H2Server;
use warren_masque::h3::H3Connection;
use warren_masque::http::{RequestHead, ResponseHead};
use warren_masque::session::{Incoming, peer_certificates};
use warren_masque::tunnel::{TunnelReceiver, TunnelSender};

/// One-line description of the role, shown by `warren relay --help`.
pub const ABOUT: &str = "Run a relay that clients and connectors dial out to";

/// Relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// UDP address for QUIC.
    pub listen_quic: SocketAddr,
    /// TCP address for the HTTP/2 fallback; `None` disables it.
    pub listen_tcp: Option<SocketAddr>,
    /// The relay's infrastructure certificate and key.
    pub credentials: Credentials,
    /// The deployment trust bundle.
    pub trust: Arc<TrustBundle>,
    /// The node bundle (revocations, connector groups).
    pub state: Arc<NodeState>,
    /// Name used in `Proxy-Status` and logs.
    pub name: String,
    /// Virtual peer addresses come from this /64 (`RELAY_PEER_PREFIX`);
    /// `None` picks a random IPv6 ULA prefix.
    pub peer_prefix: Option<Ipv6Addr>,
    /// Concurrent splices allowed per client device (`RELAY_LIMITS`).
    pub max_splices_per_client: usize,
    /// Context ID at which a bind stream rolls over (`BIND_ROLLOVER`).
    pub bind_rollover: u64,
    /// Transport overrides for tests.
    pub tuning: TransportTuning,
}

/// Relay metrics.
#[derive(Debug, Clone)]
pub struct RelayMetrics {
    /// The registry they are exposed through.
    pub registry: Registry,
    /// Outer connections accepted.
    pub connections: Counter,
    /// Connector attachments currently live: outer connections carrying at
    /// least one bind stream.
    pub attachments: Gauge,
    /// Bind streams currently live.
    pub bind_streams: Gauge,
    /// Client splices currently live.
    pub splices: Gauge,
    /// Client splices established.
    pub splices_total: Counter,
    /// Requests refused.
    pub refusals: Counter,
    /// Datagrams forwarded client to connector.
    pub to_connector: Counter,
    /// Datagrams forwarded connector to client.
    pub to_client: Counter,
    /// Bytes forwarded in both directions.
    pub bytes: Counter,
    /// Datagrams dropped (oversized for the next hop, unknown context, or
    /// congested).
    pub dropped: Counter,
    /// Outer connections closed by revocation or certificate expiry.
    pub cut: Counter,
    /// Bind streams rolled over to a fresh one.
    pub rollovers: Counter,
    /// Rolled-over bind streams closed after their last context ended.
    pub retired: Counter,
}

impl RelayMetrics {
    fn new() -> RelayMetrics {
        let r = Registry::default();
        RelayMetrics {
            connections: r.counter(
                "warren_relay_connections_total",
                "Outer connections accepted",
            ),
            attachments: r.gauge("warren_relay_attachments", "Connector attachments live"),
            bind_streams: r.gauge("warren_relay_bind_streams", "Bind streams live"),
            splices: r.gauge("warren_relay_splices", "Client splices live"),
            splices_total: r.counter("warren_relay_splices_total", "Client splices established"),
            refusals: r.counter("warren_relay_refusals_total", "CONNECT requests refused"),
            to_connector: r.counter(
                "warren_relay_datagrams_to_connector_total",
                "Datagrams forwarded to connectors",
            ),
            to_client: r.counter(
                "warren_relay_datagrams_to_client_total",
                "Datagrams forwarded to clients",
            ),
            bytes: r.counter("warren_relay_bytes_total", "Payload bytes forwarded"),
            dropped: r.counter("warren_relay_datagrams_dropped_total", "Datagrams dropped"),
            cut: r.counter(
                "warren_relay_connections_cut_total",
                "Connections closed by revocation or expiry",
            ),
            rollovers: r.counter(
                "warren_relay_bind_rollovers_total",
                "Bind streams rolled over to a fresh one",
            ),
            retired: r.counter(
                "warren_relay_bind_streams_retired_total",
                "Rolled-over bind streams closed after their last context ended",
            ),
            registry: r,
        }
    }
}

/// An attached connector replica.
#[derive(Debug)]
struct Attachment {
    id: u64,
    node: String,
    /// The connector's node ID, which clients name to keep their inner
    /// session on this replica.
    node_id: String,
    tx: TunnelSender,
    contexts: Mutex<Contexts>,
    draining: AtomicBool,
    /// The context ID at which this stream asks for a fresh one.
    rollover: u64,
    /// Notified when a rolled-over stream's last context ends, so the bind
    /// stream closes; the connector's fresh stream carries on.
    retire: Notify,
    /// Set once the bind stream is gone.
    gone: watch::Sender<bool>,
}

#[derive(Debug, Default)]
struct Contexts {
    /// The next context ID to assign; IDs are never reused on a stream.
    next: u64,
    /// Contexts assigned and not yet released: the stream's load.
    open: usize,
    /// Rolled over: a fresh stream of the connector replaced this one, which
    /// takes no new contexts.
    rolled: bool,
    live: HashMap<u64, TunnelSender>,
}

impl Attachment {
    /// Assigns the next odd context ID (RFC 9298), unless the stream has
    /// rolled over or spent its IDs.
    fn assign(&self) -> Option<u64> {
        let mut c = self.contexts.lock().expect("contexts lock");
        if c.rolled || c.next > params::MAX_BIND_CONTEXT_ID {
            return None;
        }
        let ctx = c.next;
        c.next += 2;
        c.open += 1;
        Some(ctx)
    }

    /// Whether the stream is past its rollover point, so the connector
    /// should open a fresh one.
    fn past_rollover(&self) -> bool {
        self.contexts.lock().expect("contexts lock").next > self.rollover
    }

    /// Rolls the stream over once a fresh stream of its connector is
    /// attached, if it is past its rollover point; it then retires when its
    /// last context ends. Returns whether it rolled over now.
    fn roll_over(&self) -> bool {
        let mut c = self.contexts.lock().expect("contexts lock");
        if c.rolled || c.next <= self.rollover {
            return false;
        }
        c.rolled = true;
        if c.open == 0 {
            self.retire.notify_one();
        }
        true
    }

    /// Ends a context assigned by [`Attachment::assign`].
    fn release(&self, ctx: u64) {
        let mut c = self.contexts.lock().expect("contexts lock");
        c.live.remove(&ctx);
        c.open -= 1;
        if c.rolled && c.open == 0 {
            self.retire.notify_one();
        }
    }

    /// Contexts open on the stream.
    fn load(&self) -> usize {
        self.contexts.lock().expect("contexts lock").open
    }

    /// How the stream ranks for a new client of its replica, lowest first:
    /// streams before their rollover point, then by load; `None` if it
    /// cannot take one.
    fn rank(&self) -> Option<(bool, usize)> {
        let c = self.contexts.lock().expect("contexts lock");
        (!c.rolled && c.next <= params::MAX_BIND_CONTEXT_ID)
            .then_some((c.next > self.rollover, c.open))
    }
}

#[derive(Debug, Default)]
struct Registry_ {
    groups: HashMap<String, Vec<Arc<Attachment>>>,
}

/// A live outer connection, kept so revocations can cut it.
struct Live {
    peer: PeerIdentity,
    close: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Shared {
    config: RelayConfig,
    prefix: Ipv6Addr,
    registry: Mutex<Registry_>,
    next_id: AtomicU64,
    per_client: Mutex<HashMap<String, usize>>,
    live: Mutex<HashMap<u64, Live>>,
    metrics: RelayMetrics,
    accept: AcceptClients,
}

/// A running relay.
#[derive(Debug)]
pub struct Relay {
    shared: Arc<Shared>,
    endpoint: quinn::Endpoint,
    quic_addr: SocketAddr,
    tcp_addr: Option<SocketAddr>,
    shutdown: watch::Sender<bool>,
}

fn random_ula() -> Ipv6Addr {
    let mut b = [0u8; 16];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut b[1..8])
        .expect("CSPRNG");
    b[0] = 0xfd;
    for x in &mut b[8..] {
        *x = 0;
    }
    Ipv6Addr::from(b)
}

impl Relay {
    /// Binds the listeners and starts serving.
    pub async fn start(config: RelayConfig) -> std::io::Result<Relay> {
        let accept = AcceptClients {
            users: true,
            nodes: vec![NodeRoleMatch::AnyConnector],
        };
        let verifier = Arc::new(WarrenClientVerifier::new(
            config.trust.clone(),
            accept.clone(),
            config.state.clone() as Arc<dyn RevocationCheck>,
        ));
        let quic_tls = tls::server_config(&config.credentials, verifier.clone(), &[tls::ALPN_H3])
            .map_err(std::io::Error::other)?;
        let server = quic::server_config(quic_tls, Layer::Outer, config.tuning);
        let endpoint = quinn::Endpoint::new(
            quic::endpoint_config(Layer::Outer),
            Some(server),
            std::net::UdpSocket::bind(config.listen_quic)?,
            quinn::default_runtime().ok_or_else(|| std::io::Error::other("no runtime"))?,
        )?;
        let quic_addr = endpoint.local_addr()?;
        let prefix = config.peer_prefix.unwrap_or_else(random_ula);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            prefix,
            registry: Mutex::new(Registry_::default()),
            next_id: AtomicU64::new(1),
            per_client: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            metrics: RelayMetrics::new(),
            accept,
            config,
        });

        let tcp_addr = match shared.config.listen_tcp {
            Some(addr) => {
                let listener = TcpListener::bind(addr).await?;
                let local = listener.local_addr()?;
                let h2_tls =
                    tls::server_config(&shared.config.credentials, verifier, &[tls::ALPN_H2])
                        .map_err(std::io::Error::other)?;
                let acceptor = warren_masque::tokio_rustls::TlsAcceptor::from(Arc::new(h2_tls));
                tokio::spawn(serve_tcp(
                    shared.clone(),
                    listener,
                    acceptor,
                    shutdown_rx.clone(),
                ));
                Some(local)
            }
            None => None,
        };
        tokio::spawn(serve_quic(shared.clone(), endpoint.clone(), shutdown_rx));
        info!(quic = %quic_addr, tcp = ?tcp_addr, prefix = %prefix, name = %shared.config.name, "relay listening");
        Ok(Relay {
            shared,
            endpoint,
            quic_addr,
            tcp_addr,
            shutdown,
        })
    }

    /// The QUIC address.
    pub fn quic_addr(&self) -> SocketAddr {
        self.quic_addr
    }

    /// The HTTP/2 fallback address.
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    /// Metrics.
    pub fn metrics(&self) -> &RelayMetrics {
        &self.shared.metrics
    }

    /// Replaces the node bundle and cuts every connection it no longer
    /// permits.
    pub fn reload(&self, bundle: CompiledBundle) -> Result<usize, String> {
        self.shared
            .config
            .state
            .replace(bundle)
            .map_err(|e| e.to_string())?;
        Ok(self.shared.enforce_revocations())
    }

    /// Stops accepting and closes every connection.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        self.endpoint
            .close(quinn::VarInt::from_u32(0x100), b"relay shutting down");
    }
}

impl Shared {
    fn revoked(&self, peer: &PeerIdentity) -> bool {
        let state = &self.config.state;
        match peer {
            PeerIdentity::Client(c) => state.check_client(c).is_err(),
            PeerIdentity::Node(n) => state.check_node(n).is_err(),
        }
    }

    fn enforce_revocations(&self) -> usize {
        let live = self.live.lock().expect("live lock");
        let mut cut = 0;
        for l in live.values() {
            if self.revoked(&l.peer) {
                (l.close)();
                cut += 1;
            }
        }
        self.metrics.cut.add(cut as u64);
        if cut > 0 {
            info!(cut, "closed connections no longer permitted by the bundle");
        }
        cut
    }

    /// Tracks a connection so revocations can cut it. The bundle is checked
    /// again once tracked, so a reload that ran after the peer was
    /// identified but before it was tracked still covers it; `None` means
    /// the peer is no longer permitted.
    fn track(&self, peer: PeerIdentity, close: Box<dyn Fn() + Send + Sync>) -> Option<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut live = self.live.lock().expect("live lock");
        if self.revoked(&peer) {
            return None;
        }
        live.insert(id, Live { peer, close });
        Some(id)
    }

    fn untrack(&self, id: u64) {
        self.live.lock().expect("live lock").remove(&id);
    }

    fn identify(
        &self,
        certs: &[rustls::pki_types::CertificateDer<'static>],
    ) -> Option<PeerIdentity> {
        let leaf = certs.first()?;
        tls::verify_client(
            &self.config.trust,
            &self.accept,
            self.config.state.as_ref(),
            leaf,
            tls::now(),
        )
        .ok()
    }

    fn virtual_peer(&self, attachment: u64, context: u64) -> SocketAddr {
        let base = u128::from(self.prefix) & !((1u128 << 64) - 1);
        let host = (u128::from(attachment as u32) << 16) | u128::from(context as u16);
        SocketAddr::new(Ipv6Addr::from(base | host).into(), 443)
    }
}

fn not_after(peer: &PeerIdentity) -> SystemTime {
    match peer {
        PeerIdentity::Client(c) => c.not_after,
        PeerIdentity::Node(n) => n.not_after,
    }
}

fn describe(peer: &PeerIdentity) -> String {
    match peer {
        PeerIdentity::Client(c) => format!("user {} on device {}", c.user, c.device),
        PeerIdentity::Node(n) => format!("{} {}", n.role, n.id),
    }
}

async fn serve_quic(
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
            let remote = incoming.remote_address();
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    debug!(%remote, error = %e, "QUIC handshake failed");
                    return;
                }
            };
            shared.metrics.connections.inc();
            let Some(peer) = shared.identify(&peer_certificates(&conn)) else {
                conn.close(quinn::VarInt::from_u32(0x102), b"unidentified peer");
                return;
            };
            let closer = {
                let conn = conn.clone();
                Box::new(move || conn.close(quinn::VarInt::from_u32(0x10b), b"revoked"))
            };
            let Some(live) = shared.track(peer.clone(), closer) else {
                shared.metrics.cut.inc();
                conn.close(quinn::VarInt::from_u32(0x10b), b"revoked");
                return;
            };
            let h3 = match H3Connection::new(conn.clone(), true).await {
                Ok(h) => h,
                Err(e) => {
                    debug!(%remote, error = %e, "HTTP/3 setup failed");
                    shared.untrack(live);
                    return;
                }
            };
            // A connection never outlives the certificate that
            // authenticated it (docs/protocol.md section 4.3).
            let expiry = {
                let conn = conn.clone();
                let shared = shared.clone();
                let until = not_after(&peer);
                tokio::spawn(async move {
                    let wait = until.duration_since(SystemTime::now()).unwrap_or_default();
                    tokio::time::sleep(wait).await;
                    shared.metrics.cut.inc();
                    conn.close(quinn::VarInt::from_u32(0x10b), b"certificate expired");
                })
            };
            debug!(%remote, peer = %describe(&peer), "outer connection");
            let binds = Arc::new(AtomicUsize::new(0));
            loop {
                match h3.accept_request().await {
                    Ok(Some((head, stream))) => {
                        let shared = shared.clone();
                        let peer = peer.clone();
                        let binds = binds.clone();
                        tokio::spawn(async move {
                            handle(shared, peer, remote, head, Incoming::H3(stream), binds).await;
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!(%remote, error = %e, "outer connection ended");
                        break;
                    }
                }
            }
            expiry.abort();
            shared.untrack(live);
            h3.close(warren_masque::h3::code::NO_ERROR, "done");
        });
    }
}

async fn serve_tcp(
    shared: Arc<Shared>,
    listener: TcpListener,
    acceptor: warren_masque::tokio_rustls::TlsAcceptor,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = shutdown.changed() => return,
        };
        let Ok((tcp, remote)) = accepted else {
            continue;
        };
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_tcp_conn(shared, tcp, remote, acceptor).await {
                debug!(%remote, error = %e, "HTTP/2 connection ended");
            }
        });
    }
}

async fn serve_tcp_conn(
    shared: Arc<Shared>,
    tcp: TcpStream,
    remote: SocketAddr,
    acceptor: warren_masque::tokio_rustls::TlsAcceptor,
) -> Result<(), String> {
    tcp.set_nodelay(true).map_err(|e| e.to_string())?;
    let tls = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    shared.metrics.connections.inc();
    let certs: Vec<_> = tls
        .get_ref()
        .1
        .peer_certificates()
        .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
        .unwrap_or_default();
    let peer = shared.identify(&certs).ok_or("unidentified peer")?;
    let (cut_tx, mut cut_rx) = watch::channel(false);
    let Some(live) = shared.track(
        peer.clone(),
        Box::new(move || {
            let _ = cut_tx.send(true);
        }),
    ) else {
        shared.metrics.cut.inc();
        return Err("revoked".into());
    };
    let served = serve_h2(&shared, tls, &peer, remote, &mut cut_rx).await;
    shared.untrack(live);
    served
}

async fn serve_h2(
    shared: &Arc<Shared>,
    tls: warren_masque::tokio_rustls::server::TlsStream<TcpStream>,
    peer: &PeerIdentity,
    remote: SocketAddr,
    cut_rx: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    let mut h2 = tokio::select! {
        h = tokio::time::timeout(Duration::from_secs(10), H2Server::handshake(tls)) => h
            .map_err(|_| "HTTP/2 handshake timed out".to_owned())?
            .map_err(|e| e.to_string())?,
        _ = cut_rx.changed() => return Ok(()),
    };
    let until = not_after(peer);
    let expiry = tokio::time::sleep(until.duration_since(SystemTime::now()).unwrap_or_default());
    tokio::pin!(expiry);
    let binds = Arc::new(AtomicUsize::new(0));
    loop {
        tokio::select! {
            next = h2.accept() => match next {
                Some(Ok(req)) => {
                    let shared = shared.clone();
                    let peer = peer.clone();
                    let binds = binds.clone();
                    let head = req.head.clone();
                    tokio::spawn(async move {
                        handle(shared, peer, remote, head, Incoming::H2(req), binds).await;
                    });
                }
                Some(Err(e)) => return Err(e.to_string()),
                None => return Ok(()),
            },
            _ = cut_rx.changed() => return Ok(()),
            () = &mut expiry => {
                shared.metrics.cut.inc();
                return Ok(());
            }
        }
    }
}

async fn handle(
    shared: Arc<Shared>,
    peer: PeerIdentity,
    remote: SocketAddr,
    head: RequestHead,
    incoming: Incoming,
    binds: Arc<AtomicUsize>,
) {
    let name = shared.config.name.clone();
    let request = match connect::parse_relay_request(&head) {
        Ok(r) => r,
        Err(refusal) => {
            shared.metrics.refusals.inc();
            incoming.refuse(&refusal, &name).await;
            return;
        }
    };
    match (request, &peer) {
        (Request::UdpToGroup { group }, PeerIdentity::Client(client)) => {
            let connector = head.header(connect::WARREN_CONNECTOR).map(str::to_owned);
            splice(shared, client.clone(), remote, group, connector, incoming).await;
        }
        (Request::UdpBind, PeerIdentity::Node(node)) => {
            if let NodeRole::Connector { group } = &node.role {
                let group = group.clone();
                attach(shared, node.clone(), group, incoming, &binds).await;
            } else {
                shared.metrics.refusals.inc();
                incoming
                    .refuse(
                        &Refusal::new(403, "http_request_denied", "only connectors may bind"),
                        &name,
                    )
                    .await;
            }
        }
        _ => {
            shared.metrics.refusals.inc();
            let refusal = Refusal::new(
                403,
                "http_request_denied",
                "this identity may not make this request",
            );
            incoming.refuse(&refusal, &name).await;
        }
    }
}

/// Deliver limits: the inner session's packets are never larger than the
/// QUIC minimum unless path MTU discovery proved more, so these sizes must
/// always arrive, as frames or capsules (docs/protocol.md section 9).
fn deliver_limit(context: u64) -> usize {
    warren_masque::varint::len(context) + usize::from(params::QUIC_MIN_UDP_PAYLOAD)
}

/// Serves a bind stream; `binds` counts the bind streams on its outer
/// connection, which is one attachment however many it carries.
async fn attach(
    shared: Arc<Shared>,
    node: NodeIdentity,
    group: String,
    incoming: Incoming,
    binds: &AtomicUsize,
) {
    let resp = ResponseHead::new(200)
        .with(CONNECT_UDP_BIND, "?1")
        .with(PROXY_PUBLIC_ADDRESS, format!("\"[{}]:443\"", shared.prefix));
    let (tx, mut rx) = match incoming
        .accept(&resp, deliver_limit(params::MAX_BIND_CONTEXT_ID))
        .await
    {
        Ok(t) => t,
        Err(e) => {
            debug!(error = %e, "bind accept failed");
            return;
        }
    };
    let attachment = Arc::new(Attachment {
        id: shared.next_id.fetch_add(1, Ordering::Relaxed),
        node: format!("{}/{}", node.role, node.id),
        node_id: node.id.clone(),
        tx,
        contexts: Mutex::new(Contexts {
            next: 1,
            open: 0,
            rolled: false,
            live: HashMap::new(),
        }),
        draining: AtomicBool::new(false),
        rollover: shared.config.bind_rollover,
        retire: Notify::new(),
        gone: watch::channel(false).0,
    });
    {
        let mut registry = shared.registry.lock().expect("registry lock");
        let streams = registry.groups.entry(group.clone()).or_default();
        for a in streams.iter().filter(|a| a.node_id == attachment.node_id) {
            if a.roll_over() {
                info!(connector = %a.node, attachment = a.id, "bind stream rolled over");
                shared.metrics.rollovers.inc();
            }
        }
        streams.push(attachment.clone());
    }
    if binds.fetch_add(1, Ordering::SeqCst) == 0 {
        shared.metrics.attachments.inc();
    }
    shared.metrics.bind_streams.inc();
    info!(connector = %attachment.node, group = %group, attachment = attachment.id, "connector attached");

    serve_bind(&shared, &attachment, &mut rx).await;

    shared
        .registry
        .lock()
        .expect("registry lock")
        .groups
        .entry(group)
        .or_default()
        .retain(|a| a.id != attachment.id);
    shared.metrics.bind_streams.dec();
    if binds.fetch_sub(1, Ordering::SeqCst) == 1 {
        shared.metrics.attachments.dec();
    }
    // The replica is gone: end its clients' streams so they re-establish
    // on another replica (docs/design.md section 11).
    attachment.gone.send_replace(true);
    attachment
        .contexts
        .lock()
        .expect("contexts lock")
        .live
        .clear();
    info!(connector = %attachment.node, "connector detached");
}

async fn serve_bind(shared: &Shared, a: &Attachment, rx: &mut TunnelReceiver) {
    loop {
        tokio::select! {
            d = rx.datagrams.recv() => {
                let Some(d) = d else { return };
                let Some((ctx, payload)) = split_context(&d) else { continue };
                let client = a.contexts.lock().expect("contexts lock").live.get(&ctx).cloned();
                match client {
                    Some(c) => {
                        shared.metrics.to_client.inc();
                        shared.metrics.bytes.add(payload.len() as u64);
                        if c.send_datagram(0, &payload).is_err() {
                            shared.metrics.dropped.inc();
                        }
                    }
                    None => shared.metrics.dropped.inc(),
                }
            }
            c = rx.capsules.recv() => {
                let Some(c) = c else { return };
                match c {
                    Capsule::CompressionAck(_) => {}
                    Capsule::CompressionClose(ctx) => {
                        // The connector closed the context: end that client.
                        a.contexts.lock().expect("contexts lock").live.remove(&ctx);
                    }
                    Capsule::CompressionAssign { context_id, .. } => {
                        // Only the relay registers peers on a bind stream.
                        let _ = a.tx.send_capsule(&Capsule::CompressionClose(context_id)).await;
                    }
                    Capsule::Notice(n) if n.reason == "draining" => {
                        info!(connector = %a.node, "connector draining");
                        a.draining.store(true, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            () = a.retire.notified() => {
                info!(connector = %a.node, attachment = a.id, "rolled-over bind stream drained; closing it");
                shared.metrics.retired.inc();
                return;
            }
        }
    }
}

/// Picks the bind stream for a client and assigns it a context ID.
fn pick_replica(
    shared: &Shared,
    group: &str,
    connector: Option<&str>,
) -> Option<(Arc<Attachment>, u64)> {
    let registry = shared.registry.lock().expect("registry lock");
    let candidates = registry.groups.get(group)?;
    let streams = |id: &str| -> Vec<&Arc<Attachment>> {
        candidates.iter().filter(|a| a.node_id == id).collect()
    };
    let best_stream = |id: &str, eligible: &dyn Fn(&Attachment) -> bool| {
        streams(id)
            .into_iter()
            .filter(|a| eligible(a))
            .filter_map(|a| a.rank().map(|rank| (rank, a)))
            .min_by_key(|(rank, _)| *rank)
            .map(|(_, a)| a)
    };
    // The replica holding the client's inner session, on any of its
    // streams here, and never another replica while it has one; otherwise
    // REPLICA_SELECTION: the replica with the fewest open contexts over all
    // its streams, among those with a stream not draining that can take the
    // client. Within the replica, a stream before its rollover point first.
    let a = match connector.filter(|id| candidates.iter().any(|a| a.node_id == *id)) {
        Some(id) => best_stream(id, &|_| true),
        None => {
            let mut replicas: Vec<&str> = Vec::new();
            for a in candidates {
                if !replicas.contains(&a.node_id.as_str()) {
                    replicas.push(&a.node_id);
                }
            }
            replicas
                .into_iter()
                .filter_map(|id| {
                    let stream = best_stream(id, &|a| !a.draining.load(Ordering::Relaxed))?;
                    let load: usize = streams(id).iter().map(|a| a.load()).sum();
                    Some((load, stream))
                })
                .min_by_key(|(load, _)| *load)
                .map(|(_, a)| a)
        }
    }?
    .clone();
    let ctx = a.assign()?;
    Some((a, ctx))
}

async fn splice(
    shared: Arc<Shared>,
    client: ClientIdentity,
    remote: SocketAddr,
    group: String,
    connector: Option<String>,
    incoming: Incoming,
) {
    let name = shared.config.name.clone();
    let bundle = shared.config.state.get();
    if bundle.groups.get(&group).is_some_and(|g| !g.enabled) {
        shared.metrics.refusals.inc();
        let r = Refusal::new(
            403,
            "http_request_denied",
            format!("connector group {group} is disabled"),
        );
        incoming.refuse(&r, &name).await;
        return;
    }
    let key = format!("{}/{}", client.user, client.device);
    let within_limit = {
        let mut per = shared.per_client.lock().expect("limits lock");
        let n = per.entry(key.clone()).or_default();
        let ok = *n < shared.config.max_splices_per_client;
        if ok {
            *n += 1;
        }
        ok
    };
    if !within_limit {
        shared.metrics.refusals.inc();
        let r = Refusal::new(
            429,
            "connection_limit_reached",
            "too many tunnels from this device",
        );
        incoming.refuse(&r, &name).await;
        return;
    }
    let release = || {
        let mut per = shared.per_client.lock().expect("limits lock");
        if let Some(n) = per.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per.remove(&key);
            }
        }
    };
    let Some((attachment, ctx)) = pick_replica(&shared, &group, connector.as_deref()) else {
        release();
        shared.metrics.refusals.inc();
        let r = Refusal::new(
            503,
            "destination_unavailable",
            format!("no connector of group {group} attached to this relay can take this client"),
        );
        incoming.refuse(&r, &name).await;
        return;
    };
    let peer = shared.virtual_peer(attachment.id, ctx);
    // Announce the virtual peer before answering the client, so the
    // connector usually knows it before the first datagram arrives.
    let announced = attachment
        .tx
        .send_capsule(&Capsule::CompressionAssign {
            context_id: ctx,
            target: Some(peer),
        })
        .await
        .is_ok()
        && attachment
            .tx
            .send_capsule(&Capsule::PeerInfo(PeerInfo {
                context_id: ctx,
                observed: remote,
            }))
            .await
            .is_ok();
    if !announced {
        attachment.release(ctx);
        release();
        let r = Refusal::new(
            503,
            "destination_unavailable",
            "the connector replica went away",
        );
        incoming.refuse(&r, &name).await;
        return;
    }
    // Asked on every assignment past the rollover point, until a fresh
    // stream of the connector takes over.
    if attachment.past_rollover() {
        debug!(connector = %attachment.node, attachment = attachment.id, "bind stream past its rollover point");
        let _ = attachment
            .tx
            .send_capsule(&Capsule::Notice(Notice {
                reason: NOTICE_BIND_ROLLOVER.into(),
                message: "open a fresh bind stream".into(),
            }))
            .await;
    }
    let (client_tx, mut client_rx) = match incoming
        .accept(&ResponseHead::new(200), deliver_limit(0))
        .await
    {
        Ok(t) => t,
        Err(_) => {
            let _ = attachment
                .tx
                .send_capsule(&Capsule::CompressionClose(ctx))
                .await;
            attachment.release(ctx);
            release();
            return;
        }
    };
    attachment
        .contexts
        .lock()
        .expect("contexts lock")
        .live
        .insert(ctx, client_tx);
    shared.metrics.splices.inc();
    shared.metrics.splices_total.inc();
    debug!(user = %client.user, device = %client.device, group = %group, connector = %attachment.node, context = ctx, "spliced");

    // Client to connector. The client may only use context 0.
    let mut gone = attachment.gone.subscribe();
    loop {
        tokio::select! {
            d = client_rx.datagrams.recv() => {
                let Some(d) = d else { break };
                match split_context(&d) {
                    Some((0, payload)) => {
                        shared.metrics.to_connector.inc();
                        shared.metrics.bytes.add(payload.len() as u64);
                        if attachment.tx.send_datagram(ctx, &payload).is_err() {
                            shared.metrics.dropped.inc();
                        }
                    }
                    _ => shared.metrics.dropped.inc(),
                }
            }
            c = client_rx.capsules.recv() => {
                if c.is_none() { break }
            }
            _ = gone.wait_for(|g| *g) => break,
        }
    }
    let _ = attachment
        .tx
        .send_capsule(&Capsule::CompressionClose(ctx))
        .await;
    attachment.release(ctx);
    shared.metrics.splices.dec();
    release();
}
