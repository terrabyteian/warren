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
use tokio::sync::watch;
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
use warren_masque::capsule::{Capsule, PeerInfo, split_context};
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
    /// Connector attachments currently live.
    pub attachments: Gauge,
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
            registry: r,
        }
    }
}

/// An attached connector replica.
#[derive(Debug)]
struct Attachment {
    id: u64,
    node: String,
    tx: TunnelSender,
    contexts: Mutex<Contexts>,
    draining: AtomicBool,
    load: AtomicUsize,
    /// Set once the bind stream is gone.
    gone: watch::Sender<bool>,
}

#[derive(Debug, Default)]
struct Contexts {
    /// The next context ID to assign; IDs are never reused on a stream.
    next: u64,
    live: HashMap<u64, TunnelSender>,
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
    fn enforce_revocations(&self) -> usize {
        let state = &self.config.state;
        let live = self.live.lock().expect("live lock");
        let mut cut = 0;
        for l in live.values() {
            let revoked = match &l.peer {
                PeerIdentity::Client(c) => state.check_client(c).is_err(),
                PeerIdentity::Node(n) => state.check_node(n).is_err(),
            };
            if revoked {
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

    fn track(&self, peer: PeerIdentity, close: Box<dyn Fn() + Send + Sync>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.live
            .lock()
            .expect("live lock")
            .insert(id, Live { peer, close });
        id
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
            let h3 = match H3Connection::new(conn.clone(), true).await {
                Ok(h) => h,
                Err(e) => {
                    debug!(%remote, error = %e, "HTTP/3 setup failed");
                    return;
                }
            };
            let closer = {
                let conn = conn.clone();
                Box::new(move || conn.close(quinn::VarInt::from_u32(0x10b), b"revoked"))
            };
            let live = shared.track(peer.clone(), closer);
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
            let goaway = h3.goaway();
            loop {
                match h3.accept_request().await {
                    Ok(Some((head, stream))) => {
                        let shared = shared.clone();
                        let peer = peer.clone();
                        let goaway = goaway.clone();
                        tokio::spawn(async move {
                            handle(
                                shared,
                                peer,
                                remote,
                                head,
                                Incoming::H3(stream),
                                Some(goaway),
                            )
                            .await;
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
    let mut h2 = H2Server::handshake(tls).await.map_err(|e| e.to_string())?;
    let (cut_tx, mut cut_rx) = watch::channel(false);
    let live = shared.track(
        peer.clone(),
        Box::new(move || {
            let _ = cut_tx.send(true);
        }),
    );
    let until = not_after(&peer);
    let expiry = tokio::time::sleep(until.duration_since(SystemTime::now()).unwrap_or_default());
    tokio::pin!(expiry);
    loop {
        tokio::select! {
            next = h2.accept() => match next {
                Some(Ok(req)) => {
                    let shared = shared.clone();
                    let peer = peer.clone();
                    let head = req.head.clone();
                    tokio::spawn(async move {
                        handle(shared, peer, remote, head, Incoming::H2(req), None).await;
                    });
                }
                Some(Err(e)) => {
                    shared.untrack(live);
                    return Err(e.to_string());
                }
                None => break,
            },
            _ = cut_rx.changed() => break,
            () = &mut expiry => {
                shared.metrics.cut.inc();
                break;
            }
        }
    }
    shared.untrack(live);
    Ok(())
}

async fn handle(
    shared: Arc<Shared>,
    peer: PeerIdentity,
    remote: SocketAddr,
    head: RequestHead,
    incoming: Incoming,
    goaway: Option<watch::Receiver<Option<u64>>>,
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
            splice(shared, client.clone(), remote, group, incoming).await;
        }
        (Request::UdpBind, PeerIdentity::Node(node)) => {
            if let NodeRole::Connector { group } = &node.role {
                let group = group.clone();
                attach(shared, node.clone(), group, incoming, goaway).await;
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

async fn attach(
    shared: Arc<Shared>,
    node: NodeIdentity,
    group: String,
    incoming: Incoming,
    goaway: Option<watch::Receiver<Option<u64>>>,
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
        tx,
        contexts: Mutex::new(Contexts {
            next: 1,
            live: HashMap::new(),
        }),
        draining: AtomicBool::new(false),
        load: AtomicUsize::new(0),
        gone: watch::channel(false).0,
    });
    shared
        .registry
        .lock()
        .expect("registry lock")
        .groups
        .entry(group.clone())
        .or_default()
        .push(attachment.clone());
    shared.metrics.attachments.inc();
    info!(connector = %attachment.node, group = %group, attachment = attachment.id, "connector attached");

    if let Some(mut goaway) = goaway {
        let a = attachment.clone();
        tokio::spawn(async move {
            if goaway.wait_for(Option::is_some).await.is_ok() {
                info!(connector = %a.node, "connector draining");
                a.draining.store(true, Ordering::Relaxed);
            }
        });
    }

    serve_bind(&shared, &attachment, &mut rx).await;

    shared
        .registry
        .lock()
        .expect("registry lock")
        .groups
        .entry(group)
        .or_default()
        .retain(|a| a.id != attachment.id);
    shared.metrics.attachments.dec();
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
                    _ => {}
                }
            }
        }
    }
}

fn pick_replica(shared: &Shared, group: &str) -> Option<(Arc<Attachment>, u64)> {
    let registry = shared.registry.lock().expect("registry lock");
    let candidates = registry.groups.get(group)?;
    // REPLICA_SELECTION: least loaded among those not draining with a free
    // context ID.
    let mut best: Option<&Arc<Attachment>> = None;
    for a in candidates {
        if a.draining.load(Ordering::Relaxed) {
            continue;
        }
        let next = a.contexts.lock().expect("contexts lock").next;
        if next > params::MAX_BIND_CONTEXT_ID {
            continue;
        }
        if best.is_none_or(|b| a.load.load(Ordering::Relaxed) < b.load.load(Ordering::Relaxed)) {
            best = Some(a);
        }
    }
    let a = best?.clone();
    let ctx = {
        let mut c = a.contexts.lock().expect("contexts lock");
        let ctx = c.next;
        // Relays allocate odd context IDs (RFC 9298).
        c.next += 2;
        ctx
    };
    Some((a, ctx))
}

async fn splice(
    shared: Arc<Shared>,
    client: ClientIdentity,
    remote: SocketAddr,
    group: String,
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
    let Some((attachment, ctx)) = pick_replica(&shared, &group) else {
        release();
        shared.metrics.refusals.inc();
        let r = Refusal::new(
            503,
            "destination_unavailable",
            format!("no connector of group {group} is attached to this relay"),
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
        release();
        let r = Refusal::new(
            503,
            "destination_unavailable",
            "the connector replica went away",
        );
        incoming.refuse(&r, &name).await;
        return;
    }
    let (client_tx, mut client_rx) = match incoming
        .accept(&ResponseHead::new(200), deliver_limit(0))
        .await
    {
        Ok(t) => t,
        Err(_) => {
            release();
            let _ = attachment
                .tx
                .send_capsule(&Capsule::CompressionClose(ctx))
                .await;
            return;
        }
    };
    attachment
        .contexts
        .lock()
        .expect("contexts lock")
        .live
        .insert(ctx, client_tx);
    attachment.load.fetch_add(1, Ordering::Relaxed);
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
    attachment
        .contexts
        .lock()
        .expect("contexts lock")
        .live
        .remove(&ctx);
    attachment.load.fetch_sub(1, Ordering::Relaxed);
    let _ = attachment
        .tx
        .send_capsule(&Capsule::CompressionClose(ctx))
        .await;
    shared.metrics.splices.dec();
    release();
}
