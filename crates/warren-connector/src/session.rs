//! One inner session: a client's CONNECT-IP stream, its addresses and name
//! bindings, and every flow it starts (docs/protocol.md sections 5 to 7).
//!
//! A session is a single task that owns all of its state; packets from the
//! client, return packets from the private network, timer ticks and policy
//! changes all arrive as events, so admission needs no locks.

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info};
use warren_core::audit::{self, DecisionRecord, FlowRecord, Subject};
use warren_core::bundle::{CompiledApp, CompiledBundle, DestKind, normalize_name, proto};
use warren_core::packet::{self, IcmpError, Parsed, Side, tcp};
use warren_core::pki::{self, ClientIdentity};
use warren_core::policy::{Decision, FlowRequest, PolicyDecisionPoint, Reason, Via};
use warren_core::tls::{self, AcceptClients, RevocationCheck};
use warren_masque::capsule::{
    AddressEntry, Capsule, CertRefresh, FlowDenied, FlowTuple, IpRange, NameBind, NameBound,
    Notice, split_context,
};
use warren_masque::tunnel::{TunnelReceiver, TunnelSender};

use crate::Shared;

/// Resolves names for name apps inside the private network.
pub trait Resolver: Send + Sync + Debug + 'static {
    /// Every address `name` resolves to.
    fn resolve(
        &self,
        name: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>;
}

/// The system resolver.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(
        &self,
        name: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name.as_str(), 0)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// Events a session handles.
#[derive(Debug)]
pub(crate) enum Event {
    /// A packet from the private network for this client.
    Return(Bytes),
    /// Once a second: expire idle flows.
    Tick,
    /// The bundle changed: re-evaluate every flow.
    Reevaluate,
    /// The connector is draining.
    Draining,
    /// A name resolution finished.
    Resolved {
        synthetic: IpAddr,
        result: Result<Vec<IpAddr>, String>,
    },
}

/// How long a resolution is reused for new flows.
const RESOLVE_TTL: Duration = Duration::from_secs(30);
/// Bound on packets held while a name resolves (`FIRST_PACKET_QUEUE`).
const FIRST_PACKET_QUEUE: usize = 64 * 1024;
/// How long a TCP flow lingers after both FINs.
const TCP_LINGER: Duration = Duration::from_secs(5);
/// Exporter label for certificate refresh signatures.
pub const REFRESH_EXPORTER_LABEL: &[u8] = b"EXPORTER-warren-cert-refresh";

#[derive(Debug)]
struct Binding {
    name: String,
    app: String,
    /// The connector-side target: an address, or a name to resolve.
    target: Result<IpAddr, String>,
    resolved: Option<(Vec<IpAddr>, Instant)>,
    resolving: bool,
    held: Vec<Bytes>,
    held_bytes: usize,
}

type FlowKey = (u8, SocketAddr, SocketAddr);

/// What a decision record is about, beyond the packet.
#[derive(Debug, Clone, Copy)]
struct About<'a> {
    app: Option<&'a str>,
    hostname: Option<&'a str>,
    translated: Option<SocketAddr>,
    server_initiated: bool,
}

#[derive(Debug)]
struct Flow {
    id: String,
    app: String,
    hostname: Option<String>,
    /// The destination as the client addresses it (synthetic for names).
    client_dst: SocketAddr,
    server_initiated: bool,
    start: SystemTime,
    last: Instant,
    bytes_out: u64,
    bytes_in: u64,
    packets_out: u64,
    packets_in: u64,
    fin_out: bool,
    fin_in: bool,
    closed_at: Option<Instant>,
    client_next_seq: u32,
    server_next_seq: u32,
}

struct Session {
    shared: Arc<Shared>,
    id: u64,
    client: ClientIdentity,
    conn: quinn::Connection,
    peer: SocketAddr,
    tx: TunnelSender,
    events: mpsc::Sender<Event>,
    policy: Arc<dyn PolicyDecisionPoint>,
    assigned: Vec<IpAddr>,
    binds: HashMap<IpAddr, Binding>,
    flows: HashMap<FlowKey, Flow>,
    by_client: HashMap<FlowKey, FlowKey>,
    frags_out: HashMap<(IpAddr, IpAddr, u8, u32), (FlowKey, Instant)>,
    expires: SystemTime,
    reported_fallbacks: u64,
}

/// Runs a session until the stream, the connection or the certificate
/// ends.
pub(crate) async fn run(
    shared: Arc<Shared>,
    client: ClientIdentity,
    conn: quinn::Connection,
    peer: SocketAddr,
    tx: TunnelSender,
    mut rx: TunnelReceiver,
) {
    let (events, mut events_rx) = mpsc::channel(4096);
    let id = shared
        .next_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let policy = shared.config.policy.clone();
    let mut s = Session {
        expires: client.not_after,
        shared,
        id,
        client,
        conn,
        peer,
        tx,
        events,
        policy,
        assigned: Vec::new(),
        binds: HashMap::new(),
        flows: HashMap::new(),
        by_client: HashMap::new(),
        frags_out: HashMap::new(),
        reported_fallbacks: 0,
    };
    s.shared.metrics.sessions.inc();
    s.shared.metrics.sessions_total.inc();
    info!(
        user = %s.client.user,
        device = %s.client.device,
        session = s.id,
        relay_observed = ?s.shared.observed(s.peer),
        "inner session started"
    );
    let end = loop {
        let expiry = tokio::time::sleep(
            s.expires
                .duration_since(SystemTime::now())
                .unwrap_or_default(),
        );
        tokio::select! {
            d = rx.datagrams.recv() => {
                let Some(d) = d else { break "stream closed" };
                match split_context(&d) {
                    Some((0, pkt)) => s.outbound(pkt),
                    _ => s.shared.metrics.dropped.inc(),
                }
            }
            c = rx.capsules.recv() => {
                let Some(c) = c else { break "stream closed" };
                if let Some(reason) = s.capsule(c).await {
                    break reason;
                }
            }
            e = events_rx.recv() => {
                let Some(e) = e else { break "connector stopped" };
                if let Some(reason) = s.event(e).await {
                    break reason;
                }
            }
            () = expiry => {
                s.notice("certificate_expired", "Your session certificate expired; reconnecting with a renewed one.").await;
                break "certificate expired";
            }
            _ = s.conn.closed() => break "connection closed",
        }
    };
    for addr in &s.assigned {
        s.shared.routes.remove(*addr, s.id);
    }
    let keys: Vec<FlowKey> = s.flows.keys().copied().collect();
    for k in keys {
        s.end_flow(k, "session_closed");
    }
    s.shared.metrics.sessions.dec();
    info!(user = %s.client.user, device = %s.client.device, session = s.id, reason = end, "inner session ended");
    if matches!(end, "revoked" | "certificate expired") {
        // Give the notice a moment to reach the client before the close
        // discards anything still in flight.
        let _ = tokio::time::timeout(Duration::from_millis(250), s.conn.closed()).await;
    }
    s.conn.close(quinn::VarInt::from_u32(0x100), end.as_bytes());
}

fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

impl Session {
    fn bundle(&self) -> Arc<CompiledBundle> {
        self.shared.config.state.get()
    }

    fn subject(&self) -> Subject<'_> {
        Subject {
            user: &self.client.user,
            device: &self.client.device,
            session: &self.client.identity.session_id,
        }
    }

    async fn notice(&self, reason: &str, message: &str) {
        let _ = self
            .tx
            .send_capsule(&Capsule::Notice(Notice {
                reason: reason.into(),
                message: message.into(),
            }))
            .await;
    }

    async fn event(&mut self, e: Event) -> Option<&'static str> {
        match e {
            Event::Return(pkt) => self.inbound(pkt),
            Event::Tick => self.tick(),
            Event::Reevaluate => return self.reevaluate().await,
            Event::Draining => {
                self.notice(
                    "draining",
                    "This connector is restarting; your connection moves to another one.",
                )
                .await;
            }
            Event::Resolved { synthetic, result } => self.resolved(synthetic, result),
        }
        None
    }

    // ----- capsules -----

    async fn capsule(&mut self, c: Capsule) -> Option<&'static str> {
        match c {
            Capsule::AddressRequest(entries) => self.address_request(entries).await,
            Capsule::NameBind(b) => self.name_bind(b).await,
            Capsule::CertRefresh(r) => {
                if let Err(e) = self.cert_refresh(r) {
                    info!(user = %self.client.user, error = %e, "certificate refresh rejected");
                    self.notice(
                        "certificate_refresh_failed",
                        "Your renewed certificate was not accepted.",
                    )
                    .await;
                }
            }
            Capsule::Posture(_) => debug!(
                "posture statement received; posture enforcement arrives with the control plane"
            ),
            Capsule::Datagram(_) => {}
            other => debug!(kind = other.kind(), "ignoring capsule"),
        }
        None
    }

    async fn address_request(&mut self, entries: Vec<AddressEntry>) {
        let ours = self.client.identity.tunnel_addresses();
        let mut assigned = Vec::new();
        for e in entries {
            let want = ours
                .iter()
                .copied()
                .find(|a| same_family(*a, e.addr) && (e.addr == *a || e.addr.is_unspecified()));
            let full = if e.addr.is_ipv4() { 32 } else { 128 };
            match want {
                // Exactly the certificate's addresses (docs/protocol.md 5).
                Some(a) if e.prefix_len == full || e.addr.is_unspecified() => {
                    assigned.push(AddressEntry {
                        request_id: e.request_id,
                        addr: a,
                        prefix_len: full,
                    });
                    if !self.assigned.contains(&a) {
                        self.assigned.push(a);
                        self.shared.routes.insert(a, self.id, self.events.clone());
                    }
                }
                _ => assigned.push(AddressEntry {
                    request_id: e.request_id,
                    addr: if e.addr.is_ipv4() {
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                    } else {
                        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                    },
                    prefix_len: full,
                }),
            }
        }
        let _ = self
            .tx
            .send_capsule(&Capsule::AddressAssign(assigned))
            .await;
        let routes = self.routes();
        let _ = self
            .tx
            .send_capsule(&Capsule::RouteAdvertisement(routes))
            .await;
    }

    /// Route hints: CIDR destinations of the apps this user could reach
    /// through this group, and the synthetic pools for name apps. Routes are
    /// never authorization.
    fn routes(&self) -> Vec<IpRange> {
        let bundle = self.bundle();
        let groups = bundle.user_groups(&self.client.user);
        let mut ranges: Vec<(bool, u128, u128)> = Vec::new();
        let mut names = false;
        for app in bundle
            .apps
            .values()
            .filter(|a| a.group == self.shared.config.group)
        {
            let visible = app.discoverable
                || bundle.rules.iter().any(|r| {
                    !r.deny
                        && (r.users.contains(&self.client.user)
                            || groups.iter().any(|g| r.groups.contains(g)))
                        && (r.apps.contains(&app.name)
                            || r.labels.as_ref().is_some_and(|l| {
                                l.iter().all(|(k, v)| app.labels.get(k) == Some(v))
                            }))
                });
            if !visible {
                continue;
            }
            for d in &app.destinations {
                match &d.kind {
                    DestKind::Cidr(net) => {
                        let (a, b) = net.range();
                        ranges.push((net.addr.is_ipv6(), ip_u128(a), ip_u128(b)));
                    }
                    DestKind::Name { .. } => names = true,
                }
            }
        }
        if names {
            for pool in &self.shared.config.synthetic_pools {
                let (a, b) = pool.range();
                ranges.push((pool.addr.is_ipv6(), ip_u128(a), ip_u128(b)));
            }
        }
        // RFC 9484 wants ranges ordered and non-overlapping.
        ranges.sort();
        let mut merged: Vec<(bool, u128, u128)> = Vec::new();
        for r in ranges {
            match merged.last_mut() {
                Some(m) if m.0 == r.0 && r.1 <= m.2.saturating_add(1) => m.2 = m.2.max(r.2),
                _ => merged.push(r),
            }
        }
        merged
            .into_iter()
            .map(|(v6, a, b)| IpRange {
                start: u128_ip(v6, a),
                end: u128_ip(v6, b),
                protocol: 0,
            })
            .collect()
    }

    async fn name_bind(&mut self, b: NameBind) {
        let bundle = self.bundle();
        let group = &self.shared.config.group;
        let name = normalize_name(&b.name);
        let decision_id = audit::new_id();
        let owner = name.as_deref().and_then(|n| bundle.owning_app(n));
        let in_pool = self
            .shared
            .config
            .synthetic_pools
            .iter()
            .any(|p| p.contains(b.address));
        let accepted = match (&name, owner) {
            (Some(n), Some(app)) => {
                app.name == b.app
                    && app.group == *group
                    && in_pool
                    && bundle
                        .groups
                        .get(group)
                        .is_some_and(|g| g.client_names.iter().any(|p| p.matches(n)))
            }
            _ => false,
        };
        let message = format!("{} isn't part of any app you can reach.", b.name);
        let target = owner
            .zip(name.as_deref())
            .and_then(|(app, n)| target_for(app, n));
        let dst = SocketAddr::new(b.address, 0);
        let src = SocketAddr::new(
            self.assigned
                .iter()
                .copied()
                .find(|a| same_family(*a, b.address))
                .unwrap_or(b.address),
            0,
        );
        let rules: Vec<String> = Vec::new();
        self.shared.config.audit.decision(&DecisionRecord {
            id: &decision_id,
            subject: self.subject(),
            app: Some(&b.app),
            hostname: Some(&b.name),
            protocol: 0,
            src,
            dst,
            translated_dst: None,
            allowed: accepted,
            reason: (!accepted).then_some(Reason::NameNotInApp.code()),
            message: if accepted { "" } else { &message },
            rules: &rules,
            failed_condition: None,
            policy_version: bundle.version,
            server_initiated: false,
        });
        let reply = match (accepted, name, target) {
            (true, Some(n), Some(target)) => {
                self.binds.insert(
                    b.address,
                    Binding {
                        name: n,
                        app: b.app.clone(),
                        target,
                        resolved: None,
                        resolving: false,
                        held: Vec::new(),
                        held_bytes: 0,
                    },
                );
                // Resolve now so the first packet does not wait.
                self.start_resolve(b.address);
                NameBound {
                    address: b.address,
                    accepted: true,
                    reason: String::new(),
                    message: String::new(),
                }
            }
            _ => {
                self.binds.remove(&b.address);
                NameBound {
                    address: b.address,
                    accepted: false,
                    reason: Reason::NameNotInApp.code().into(),
                    message,
                }
            }
        };
        let _ = self.tx.send_capsule(&Capsule::NameBound(reply)).await;
    }

    fn start_resolve(&mut self, synthetic: IpAddr) {
        let Some(b) = self.binds.get_mut(&synthetic) else {
            return;
        };
        if b.resolving {
            return;
        }
        let name = match &b.target {
            Ok(ip) => {
                b.resolved = Some((vec![*ip], Instant::now()));
                return;
            }
            Err(name) => name.clone(),
        };
        b.resolving = true;
        let resolver = self.shared.config.resolver.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let result =
                match tokio::time::timeout(Duration::from_secs(5), resolver.resolve(name)).await {
                    Ok(Ok(a)) => Ok(a),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err("resolution timed out".into()),
                };
            let _ = events.send(Event::Resolved { synthetic, result }).await;
        });
    }

    fn resolved(&mut self, synthetic: IpAddr, result: Result<Vec<IpAddr>, String>) {
        let Some(b) = self.binds.get_mut(&synthetic) else {
            return;
        };
        b.resolving = false;
        let addrs = match result {
            Ok(a) => a,
            Err(e) => {
                debug!(name = %b.name, error = %e, "resolution failed");
                Vec::new()
            }
        };
        b.resolved = Some((addrs, Instant::now()));
        let held = std::mem::take(&mut b.held);
        b.held_bytes = 0;
        for pkt in held {
            self.outbound(pkt);
        }
    }

    fn cert_refresh(&mut self, r: CertRefresh) -> Result<(), String> {
        let leaf = r.chain.first().ok_or("empty chain")?;
        let leaf = rustls::pki_types::CertificateDer::from(leaf.to_vec());
        let c = &self.shared.config;
        let id = match tls::verify_client(
            &c.trust,
            &AcceptClients {
                users: true,
                nodes: vec![],
            },
            c.state.as_ref() as &dyn RevocationCheck,
            &leaf,
            tls::now(),
        )
        .map_err(|e| e.to_string())?
        {
            pki::PeerIdentity::Client(id) => id,
            pki::PeerIdentity::Node(_) => return Err("not a client certificate".into()),
        };
        if id.user != self.client.user
            || id.device != self.client.device
            || id.spki != self.client.spki
        {
            return Err("the renewed certificate names another user, device or key".into());
        }
        let mut exporter = [0u8; 32];
        self.conn
            .export_keying_material(&mut exporter, REFRESH_EXPORTER_LABEL, b"")
            .map_err(|_| "keying material export failed")?;
        verify_device_signature(&id.spki, &exporter, &r.signature)?;
        info!(user = %id.user, device = %id.device, "session certificate refreshed");
        self.expires = id.not_after;
        self.client = id;
        Ok(())
    }

    // ----- client to network -----

    fn outbound(&mut self, pkt: Bytes) {
        let mut buf = pkt.to_vec();
        let Ok(p) = packet::parse(&buf) else {
            self.shared.metrics.dropped.inc();
            return;
        };
        // RFC 9484: only assigned source addresses.
        if !self.assigned.contains(&p.src) {
            self.shared.metrics.dropped.inc();
            return;
        }
        if let Some((frag_id, false)) = p.fragment {
            let key = (p.src, p.dst, p.protocol, frag_id);
            match self.frags_out.get(&key).map(|(k, _)| *k) {
                Some(fk) if self.flows.contains_key(&fk) => {
                    let real = fk.2.ip();
                    if real != p.dst
                        && packet::rewrite_addr(&mut buf, &p, Side::Destination, real).is_err()
                    {
                        return;
                    }
                    self.forward(&buf);
                }
                _ => self.shared.metrics.dropped.inc(),
            }
            return;
        }
        if p.is_icmp_error() {
            // Errors about server-initiated flows go back as they came.
            if let Some((q, _)) = packet::quoted(&buf, &p) {
                let key = (q.protocol, q.dst_sock(), q.src_sock());
                if self.flows.get(&key).is_some_and(|f| f.server_initiated) {
                    self.forward(&buf);
                    return;
                }
            }
            self.shared.metrics.dropped.inc();
            return;
        }
        let client_key = (p.protocol, p.src_sock(), p.dst_sock());
        if let Some(fk) = self.by_client.get(&client_key).copied() {
            self.forward_existing(fk, buf, &p);
            return;
        }
        self.admit(buf, &p);
    }

    fn forward(&self, pkt: &[u8]) {
        self.shared.metrics.packets_out.inc();
        self.shared.forwarder.send(pkt);
    }

    fn forward_existing(&mut self, fk: FlowKey, mut buf: Vec<u8>, p: &Parsed) {
        let real = fk.2.ip();
        if real != p.dst && packet::rewrite_addr(&mut buf, p, Side::Destination, real).is_err() {
            return;
        }
        let mtu = self.shared.config.tunnel_mtu;
        packet::clamp_mss(&mut buf, p, packet::mss_for(mtu, p.src.is_ipv4()));
        if let Some(f) = self.flows.get_mut(&fk) {
            f.last = Instant::now();
            f.bytes_out += p.len as u64;
            f.packets_out += 1;
            track_tcp(f, &buf, p, true);
        }
        if let Some((id, true)) = p.fragment {
            self.frags_out
                .insert((p.src, p.dst, p.protocol, id), (fk, Instant::now()));
        }
        self.forward(&buf);
    }

    /// Admits the first packet of a new client flow.
    fn admit(&mut self, buf: Vec<u8>, p: &Parsed) {
        let starts_flow = match p.protocol {
            proto::TCP => p.tcp_flags & tcp::SYN != 0 && p.tcp_flags & tcp::ACK == 0,
            proto::ICMP | proto::ICMPV6 => matches!(p.icmp, Some((8, _)) | Some((128, _))),
            _ => true,
        };
        if !starts_flow {
            // Not the start of a flow and no flow exists: fail fast.
            if let Some(rst) = packet::tcp_reset(&buf, p) {
                let _ = self.tx.send_datagram(0, &rst);
            }
            self.shared.metrics.dropped.inc();
            return;
        }
        let bundle = self.bundle();
        let group = self.shared.config.group.clone();

        // Name apps: the destination is a bound synthetic address.
        if let Some(b) = self.binds.get_mut(&p.dst) {
            let fresh = b
                .resolved
                .as_ref()
                .is_some_and(|(_, at)| at.elapsed() < RESOLVE_TTL);
            if !fresh {
                // Hold the packet until the name resolves.
                if b.held_bytes + buf.len() <= FIRST_PACKET_QUEUE {
                    b.held_bytes += buf.len();
                    b.held.push(Bytes::from(buf));
                }
                self.start_resolve(p.dst);
                return;
            }
            let (name, app_name) = (b.name.clone(), b.app.clone());
            let addrs = b
                .resolved
                .as_ref()
                .map(|(a, _)| a.clone())
                .unwrap_or_default();
            let g = bundle.groups.get(&group);
            let real = addrs
                .into_iter()
                .find(|a| same_family(*a, p.dst) && g.is_some_and(|g| g.address_in_scope(*a)));
            let app = bundle.apps.get(&app_name).cloned();
            let Some(real) = real else {
                let d = Decision::deny(
                    Reason::OutOfScope,
                    format!("{name} doesn't resolve to an address this connector may reach."),
                    bundle.version,
                );
                self.deny(&buf, p, app.as_ref(), Some(&name), None, &d);
                return;
            };
            let real_dst = SocketAddr::new(real, p.dst_port);
            let d = self.decide(
                &bundle,
                app.as_ref(),
                Some(&name),
                p.protocol,
                real_dst,
                false,
            );
            if d.allowed {
                self.open_flow(
                    buf,
                    p,
                    app.as_ref().map(|a| a.name.clone()).unwrap_or_default(),
                    Some(name),
                    real_dst,
                    &d,
                );
            } else {
                self.deny(&buf, p, app.as_ref(), Some(&name), Some(real_dst), &d);
            }
            return;
        }

        // An unbound synthetic address stands for nothing.
        if self
            .shared
            .config
            .synthetic_pools
            .iter()
            .any(|n| n.contains(p.dst))
        {
            let d = Decision::deny(
                Reason::OutOfScope,
                "This address isn't bound to any app; resolve the app's name again.",
                bundle.version,
            );
            self.deny(&buf, p, None, None, None, &d);
            return;
        }

        // CIDR and IP apps keep real addresses.
        let app = cidr_app(&bundle, &group, p);
        let real_dst = p.dst_sock();
        let d = self.decide(&bundle, app, None, p.protocol, real_dst, false);
        if d.allowed {
            let name = app.map(|a| a.name.clone()).unwrap_or_default();
            self.open_flow(buf, p, name, None, real_dst, &d);
        } else {
            let app = app.cloned();
            self.deny(&buf, p, app.as_ref(), None, None, &d);
        }
    }

    /// The invariants no rule can override (G1), then policy.
    fn decide(
        &self,
        bundle: &CompiledBundle,
        app: Option<&CompiledApp>,
        hostname: Option<&str>,
        protocol: u8,
        real_dst: SocketAddr,
        server_initiated: bool,
    ) -> Decision {
        let v = bundle.version;
        if let Some(why) = bundle.client_revocation(&self.client) {
            return Decision::deny(
                Reason::Revoked,
                format!("Your access was revoked ({why})."),
                v,
            );
        }
        if !bundle.device_approved(&self.client.device) {
            return Decision::deny(
                Reason::DeviceNotApproved,
                "This device is not approved yet. Ask an administrator to approve it.",
                v,
            );
        }
        let group = &self.shared.config.group;
        let Some(app) = app.filter(|a| a.group == *group) else {
            return Decision::deny(
                Reason::OutOfScope,
                format!(
                    "{} isn't part of any app you can reach.",
                    hostname.map_or(real_dst.ip().to_string(), str::to_owned)
                ),
                v,
            );
        };
        // Flows start at the client unless the app opts in; a server's
        // source port is ephemeral, so only its address and protocol must
        // belong to the app.
        if server_initiated && !app.server_initiated_flows {
            return Decision::deny(
                Reason::ServerInitiatedBlocked,
                format!("{} may not open connections to your device.", app.name),
                v,
            );
        }
        let port = real_dst.port();
        let admits = app.destinations.iter().any(|d| {
            (if server_initiated {
                d.protocol.matches(protocol)
            } else {
                d.admits(protocol, port)
            }) && match (&d.kind, hostname) {
                (DestKind::Name { host, .. }, Some(h)) => host.matches(h),
                (DestKind::Cidr(net), None) => net.contains(real_dst.ip()),
                _ => false,
            }
        });
        if !admits {
            return Decision::deny(
                Reason::OutOfScope,
                format!("{} doesn't allow this port or protocol.", app.name),
                v,
            );
        }
        if !bundle
            .groups
            .get(group)
            .is_some_and(|g| g.address_in_scope(real_dst.ip()))
        {
            return Decision::deny(
                Reason::OutOfScope,
                format!("{} is outside this connector's scope.", app.name),
                v,
            );
        }
        self.policy.decide(&FlowRequest {
            client: &self.client,
            app,
            protocol,
            dst: real_dst,
            via: Via::Client,
            now: SystemTime::now(),
        })
    }

    fn record(&self, id: &str, p: &Parsed, about: About<'_>, d: &Decision) {
        let About {
            app,
            hostname,
            translated,
            server_initiated,
        } = about;
        self.shared.config.audit.decision(&DecisionRecord {
            id,
            subject: self.subject(),
            app,
            hostname,
            protocol: p.protocol,
            src: if server_initiated {
                p.dst_sock()
            } else {
                p.src_sock()
            },
            dst: if server_initiated {
                p.src_sock()
            } else {
                p.dst_sock()
            },
            translated_dst: translated,
            allowed: d.allowed,
            reason: d.reason.map(Reason::code),
            message: &d.message,
            rules: &d.rules,
            failed_condition: d.failed_condition.as_deref(),
            policy_version: d.policy_version,
            server_initiated,
        });
    }

    fn open_flow(
        &mut self,
        mut buf: Vec<u8>,
        p: &Parsed,
        app: String,
        hostname: Option<String>,
        real_dst: SocketAddr,
        d: &Decision,
    ) {
        let fk: FlowKey = (p.protocol, p.src_sock(), real_dst);
        if self.flows.contains_key(&fk) {
            // Another synthetic address already maps this exact tuple.
            let d = Decision::deny(
                Reason::OutOfScope,
                "This connection collides with another one; retry.",
                d.policy_version,
            );
            let app_ref = self.bundle().apps.get(&app).cloned();
            self.deny(
                &buf,
                p,
                app_ref.as_ref(),
                hostname.as_deref(),
                Some(real_dst),
                &d,
            );
            return;
        }
        let id = audit::new_id();
        let translated = (real_dst != p.dst_sock()).then_some(real_dst);
        self.record(
            &id,
            p,
            About {
                app: Some(&app),
                hostname: hostname.as_deref(),
                translated,
                server_initiated: false,
            },
            d,
        );
        self.shared.metrics.flows_allowed.inc();
        self.shared.metrics.flows.inc();
        self.flows.insert(
            fk,
            Flow {
                id,
                app,
                hostname,
                client_dst: p.dst_sock(),
                server_initiated: false,
                start: SystemTime::now(),
                last: Instant::now(),
                bytes_out: 0,
                bytes_in: 0,
                packets_out: 0,
                packets_in: 0,
                fin_out: false,
                fin_in: false,
                closed_at: None,
                client_next_seq: 0,
                server_next_seq: 0,
            },
        );
        self.by_client
            .insert((p.protocol, p.src_sock(), p.dst_sock()), fk);
        let _ = &mut buf;
        self.forward_existing(fk, buf, p);
    }

    fn deny(
        &mut self,
        buf: &[u8],
        p: &Parsed,
        app: Option<&CompiledApp>,
        hostname: Option<&str>,
        translated: Option<SocketAddr>,
        d: &Decision,
    ) {
        let id = audit::new_id();
        self.record(
            &id,
            p,
            About {
                app: app.map(|a| a.name.as_str()),
                hostname,
                translated,
                server_initiated: false,
            },
            d,
        );
        self.shared.metrics.flows_denied.inc();
        // Fail fast: a reset for TCP, administratively prohibited for the
        // rest (docs/protocol.md section 7).
        let reply = packet::tcp_reset(buf, p)
            .or_else(|| packet::icmp_error(buf, p, IcmpError::AdminProhibited, p.dst));
        if let Some(r) = reply {
            let _ = self.tx.send_datagram(0, &r);
        }
        let capsule = Capsule::FlowDenied(FlowDenied {
            flow: FlowTuple {
                protocol: p.protocol,
                src: p.src_sock(),
                dst: p.dst_sock(),
            },
            decision_id: id,
            reason: d.reason.unwrap_or(Reason::NoRule).code().into(),
            message: d.message.clone(),
            remediation: d.remediation.clone(),
        });
        let _ = self.tx.try_send_capsule(&capsule);
    }

    // ----- network to client -----

    fn inbound(&mut self, pkt: Bytes) {
        let mut buf = pkt.to_vec();
        let Ok(p) = packet::parse(&buf) else {
            self.shared.metrics.dropped.inc();
            return;
        };
        if p.fragment.is_some_and(|(_, first)| !first) {
            // Return fragments: the kernel reassembles before NAT, so these
            // only arrive for flows it already matched.
            self.deliver(buf, &p);
            return;
        }
        if p.is_icmp_error() {
            self.inbound_icmp_error(buf, &p);
            return;
        }
        let fk: FlowKey = (p.protocol, p.dst_sock(), p.src_sock());
        if let Some(f) = self.flows.get_mut(&fk) {
            f.last = Instant::now();
            f.bytes_in += p.len as u64;
            f.packets_in += 1;
            track_tcp(f, &buf, &p, false);
            let client_dst = f.client_dst;
            if client_dst.ip() != p.src
                && packet::rewrite_addr(&mut buf, &p, Side::Source, client_dst.ip()).is_err()
            {
                return;
            }
            let Ok(p2) = packet::parse(&buf) else { return };
            let mtu = self.shared.config.tunnel_mtu;
            packet::clamp_mss(&mut buf, &p2, packet::mss_for(mtu, p2.src.is_ipv4()));
            self.deliver(buf, &p2);
            return;
        }
        self.server_initiated(buf, &p);
    }

    fn inbound_icmp_error(&mut self, mut buf: Vec<u8>, p: &Parsed) {
        let Some((q, _)) = packet::quoted(&buf, p) else {
            return;
        };
        let fk: FlowKey = (q.protocol, q.src_sock(), q.dst_sock());
        let Some(f) = self.flows.get(&fk) else {
            self.shared.metrics.dropped.inc();
            return;
        };
        let synthetic = f.client_dst.ip();
        if synthetic != q.dst && packet::rewrite_icmp_error(&mut buf, p, q.dst, synthetic).is_err()
        {
            return;
        }
        if let Ok(p2) = packet::parse(&buf) {
            self.deliver(buf, &p2);
        }
    }

    /// Sends a packet to the client, answering oversized ones at this
    /// ingress (docs/protocol.md section 9).
    fn deliver(&mut self, buf: Vec<u8>, p: &Parsed) {
        let mtu = self.shared.config.tunnel_mtu;
        if p.len > usize::from(mtu) {
            if let Some(frags) = packet::fragment_v4(&buf, p, mtu) {
                for f in frags {
                    self.send_client(&f);
                }
            } else if let Some(err) = packet::icmp_error(&buf, p, IcmpError::TooBig(mtu), p.dst) {
                self.shared.forwarder.send(&err);
            }
            return;
        }
        self.send_client(&buf);
    }

    fn send_client(&self, pkt: &[u8]) {
        self.shared.metrics.packets_in.inc();
        if self.tx.send_datagram(0, pkt).is_err() {
            self.shared.metrics.dropped.inc();
        }
    }

    fn server_initiated(&mut self, buf: Vec<u8>, p: &Parsed) {
        let starts_flow = match p.protocol {
            proto::TCP => p.tcp_flags & tcp::SYN != 0 && p.tcp_flags & tcp::ACK == 0,
            proto::ICMP | proto::ICMPV6 => matches!(p.icmp, Some((8, _)) | Some((128, _))),
            _ => true,
        };
        if !starts_flow {
            self.shared.metrics.dropped.inc();
            return;
        }
        let bundle = self.bundle();
        let group = self.shared.config.group.clone();
        // The server's own address and port identify the app.
        let mut probe = *p;
        probe.dst = p.src;
        probe.dst_port = p.src_port;
        let app = cidr_app(&bundle, &group, &probe).cloned();
        let remote = p.src_sock();
        let d = self.decide(&bundle, app.as_ref(), None, p.protocol, remote, true);
        let id = audit::new_id();
        self.record(
            &id,
            p,
            About {
                app: app.as_ref().map(|a| a.name.as_str()),
                hostname: None,
                translated: None,
                server_initiated: true,
            },
            &d,
        );
        if !d.allowed {
            self.shared.metrics.flows_denied.inc();
            // Refuse toward the server; the client never sees the flow.
            let reply = packet::tcp_reset(&buf, p)
                .or_else(|| packet::icmp_error(&buf, p, IcmpError::AdminProhibited, p.dst));
            if let Some(r) = reply {
                self.shared.forwarder.send(&r);
            }
            return;
        }
        self.shared.metrics.flows_allowed.inc();
        self.shared.metrics.flows.inc();
        let fk: FlowKey = (p.protocol, p.dst_sock(), remote);
        self.flows.insert(
            fk,
            Flow {
                id,
                app: app.map(|a| a.name).unwrap_or_default(),
                hostname: None,
                client_dst: remote,
                server_initiated: true,
                start: SystemTime::now(),
                last: Instant::now(),
                bytes_out: 0,
                bytes_in: p.len as u64,
                packets_out: 0,
                packets_in: 1,
                fin_out: false,
                fin_in: false,
                closed_at: None,
                client_next_seq: 0,
                server_next_seq: 0,
            },
        );
        self.by_client.insert(fk, fk);
        self.deliver(buf, p);
    }

    // ----- lifecycle -----

    fn tick(&mut self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        for (k, f) in &self.flows {
            let idle = now.duration_since(f.last);
            let limit = match k.0 {
                proto::TCP => warren_core::params::FLOW_IDLE_TCP,
                proto::UDP => warren_core::params::FLOW_IDLE_UDP,
                _ => warren_core::params::FLOW_IDLE_ICMP,
            };
            let closed = f
                .closed_at
                .is_some_and(|t| now.duration_since(t) >= TCP_LINGER);
            if idle >= limit || closed {
                expired.push((*k, if closed { "closed" } else { "idle" }));
            }
        }
        for (k, why) in expired {
            self.end_flow(k, why);
        }
        self.frags_out
            .retain(|_, (_, at)| now.duration_since(*at) < Duration::from_secs(30));
        let fb = self
            .tx
            .stats()
            .capsule_fallbacks
            .load(std::sync::atomic::Ordering::Relaxed);
        self.shared
            .metrics
            .capsule_fallbacks
            .add(fb - self.reported_fallbacks);
        self.reported_fallbacks = fb;
    }

    fn end_flow(&mut self, k: FlowKey, reason: &str) {
        let Some(f) = self.flows.remove(&k) else {
            return;
        };
        self.by_client.retain(|_, v| *v != k);
        self.shared.metrics.flows.dec();
        self.shared.config.audit.flow(&FlowRecord {
            id: &f.id,
            subject: self.subject(),
            app: &f.app,
            protocol: k.0,
            src: k.1,
            dst: k.2,
            start: f.start,
            end: SystemTime::now(),
            bytes_out: f.bytes_out,
            bytes_in: f.bytes_in,
            packets_out: f.packets_out,
            packets_in: f.packets_in,
            end_reason: reason,
        });
    }

    /// Re-evaluates every flow after a bundle change; cuts the ones no
    /// longer allowed, and the whole session if the client is revoked.
    async fn reevaluate(&mut self) -> Option<&'static str> {
        let bundle = self.bundle();
        if let Some(why) = bundle.client_revocation(&self.client) {
            info!(user = %self.client.user, device = %self.client.device, reason = %why, "session revoked");
            let cut: Vec<FlowKey> = self.flows.keys().copied().collect();
            for k in cut {
                self.teardown(k, "revoked");
            }
            self.notice("revoked", "Your access was revoked.").await;
            return Some("revoked");
        }
        let group = self.shared.config.group.clone();
        // A name stays bound only while its app still owns it here; the
        // client binds again when it next resolves the name.
        let owns = |name: &str, app: &str| {
            bundle
                .owning_app(name)
                .is_some_and(|a| a.name == app && a.group == group)
        };
        self.binds.retain(|_, b| owns(&b.name, &b.app));
        let mut cut = Vec::new();
        for (k, f) in &self.flows {
            if f.hostname.as_deref().is_some_and(|h| !owns(h, &f.app)) {
                cut.push(*k);
                continue;
            }
            let app = bundle.apps.get(&f.app);
            let mut probe_dst = k.2;
            if f.server_initiated {
                probe_dst = f.client_dst;
            }
            let d = self.decide(
                &bundle,
                app.filter(|a| a.group == group),
                f.hostname.as_deref(),
                k.0,
                probe_dst,
                f.server_initiated,
            );
            if !d.allowed {
                cut.push(*k);
            }
        }
        for k in cut {
            self.teardown(k, "policy");
        }
        None
    }

    /// Ends a flow now: TCP gets resets toward both ends.
    fn teardown(&mut self, k: FlowKey, reason: &str) {
        if let Some(f) = self.flows.get(&k)
            && k.0 == proto::TCP
        {
            let to_client = rst_packet(f.client_dst, k.1, f.server_next_seq);
            let to_server = rst_packet(k.1, k.2, f.client_next_seq);
            let _ = self.tx.send_datagram(0, &to_client);
            self.shared.forwarder.send(&to_server);
        }
        self.end_flow(k, reason);
    }
}

fn rst_packet(src: SocketAddr, dst: SocketAddr, seq: u32) -> Vec<u8> {
    let mut seg = vec![0u8; 20];
    seg[0..2].copy_from_slice(&src.port().to_be_bytes());
    seg[2..4].copy_from_slice(&dst.port().to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = tcp::RST;
    packet::build(src.ip(), dst.ip(), proto::TCP, seg, Some(16))
}

fn track_tcp(f: &mut Flow, buf: &[u8], p: &Parsed, outbound: bool) {
    if p.protocol != proto::TCP || p.l4 == 0 {
        return;
    }
    let seq = u32::from_be_bytes([buf[p.l4 + 4], buf[p.l4 + 5], buf[p.l4 + 6], buf[p.l4 + 7]]);
    let off = usize::from(buf[p.l4 + 12] >> 4) * 4;
    let len = p.len.saturating_sub(p.l4 + off) as u32
        + u32::from(p.tcp_flags & tcp::SYN != 0)
        + u32::from(p.tcp_flags & tcp::FIN != 0);
    let next = seq.wrapping_add(len);
    if outbound {
        f.client_next_seq = next;
        f.fin_out |= p.tcp_flags & tcp::FIN != 0;
    } else {
        f.server_next_seq = next;
        f.fin_in |= p.tcp_flags & tcp::FIN != 0;
    }
    if p.tcp_flags & tcp::RST != 0 || (f.fin_out && f.fin_in) {
        f.closed_at.get_or_insert_with(Instant::now);
    }
}

/// The app that owns a real destination in this group: the most specific
/// CIDR destination admitting the protocol and port; failing that, any app
/// whose CIDR contains the address (so the deny names it).
fn cidr_app<'a>(bundle: &'a CompiledBundle, group: &str, p: &Parsed) -> Option<&'a CompiledApp> {
    let mut best: Option<(&CompiledApp, u8, bool)> = None;
    for app in bundle.apps.values().filter(|a| a.group == group) {
        for d in &app.destinations {
            if let DestKind::Cidr(net) = &d.kind
                && net.contains(p.dst)
            {
                let admits = d.admits(p.protocol, p.dst_port);
                let better = match best {
                    None => true,
                    Some((_, len, ok)) => (admits, net.len) > (ok, len),
                };
                if better {
                    best = Some((app, net.len, admits));
                }
            }
        }
    }
    best.map(|(a, _, _)| a)
}

/// The connector-side target for a name: the matching exact host's target,
/// or the name itself.
fn target_for(app: &CompiledApp, name: &str) -> Option<Result<IpAddr, String>> {
    let mut best: Option<(&warren_core::bundle::DomainPattern, &Option<String>)> = None;
    for d in &app.destinations {
        if let DestKind::Name { host, target } = &d.kind
            && host.matches(name)
            && best
                .is_none_or(|(b, _)| matches!(b, warren_core::bundle::DomainPattern::Wildcard(_)))
        {
            best = Some((host, target));
        }
    }
    let (_, target) = best?;
    Some(match target {
        Some(t) => t.parse::<IpAddr>().map_err(|_| t.clone()),
        None => Err(name.to_owned()),
    })
}

fn ip_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

fn u128_ip(v6: bool, v: u128) -> IpAddr {
    if v6 {
        IpAddr::V6(v.into())
    } else {
        IpAddr::V4((v as u32).into())
    }
}

/// Verifies an ECDSA P-256 SHA-256 signature by the key in `spki`.
pub fn verify_device_signature(
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use warren_core::der::{Reader, tag};
    let mut outer = Reader::new(spki);
    let mut seq = Reader::new(outer.read(tag::SEQUENCE).map_err(|e| e.to_string())?);
    seq.read(tag::SEQUENCE).map_err(|e| e.to_string())?;
    let bits = seq.read(tag::BIT_STRING).map_err(|e| e.to_string())?;
    let key = bits.get(1..).ok_or("empty key")?;
    let algs = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
    let alg = algs
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == rustls::SignatureScheme::ECDSA_NISTP256_SHA256)
        .and_then(|(_, a)| a.first())
        .ok_or("ECDSA P-256 is unavailable")?;
    alg.verify_signature(key, message, signature)
        .map_err(|_| "the refresh signature does not verify".to_owned())
}
