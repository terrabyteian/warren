//! The tunnel engine every native shell runs: the command-line client on a
//! utun interface, and the menu-bar app's packet tunnel provider.
//!
//! Given a signed-in [`Account`], the engine keeps a certificate (renewed
//! at half-life, G4), learns the user's entitlements, routes exactly the
//! ranges of the apps the user may reach or request (G14), and keeps one
//! tunnel per connector group open through the lowest-latency relay. The
//! shell hands it the packets the system routed into the tunnel and gets
//! back the packets to deliver, the network settings to apply, and events
//! to show: every block arrives with its reason (G12), and a packet for a
//! group that is still connecting is held briefly instead of dropped
//! (`FIRST_PACKET_HOLD`). The client never enforces anything; connectors
//! do (G7).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, broadcast, watch};
use warren_core::api::Entitlements;
use warren_core::bundle::{IpNet, proto};
use warren_core::clock;
use warren_core::packet::{self, IcmpError, Parsed};
use warren_core::params;
use warren_core::pki::{self, TrustBundle};
use warren_core::quic::TransportTuning;
use warren_core::tls::DeviceCredentials;
use warren_masque::capsule::FlowDenied;
use warren_masque::session::{RelayAddress, TransportMode};
use warren_masque::tunnel::CarrierKind;

use crate::control::{Account, ApiError, Endpoint};
use crate::device::DeviceKey;
use crate::relays;
use crate::state::{CertificateTimes, StoredCertificate};
use crate::{ClientConfig, ClientEvent, ConnectError, PacketSender};

/// How long a first packet waits for its group's session
/// (`FIRST_PACKET_HOLD`).
pub const FIRST_PACKET_HOLD: Duration = Duration::from_secs(2);
/// How many bytes wait per group (`FIRST_PACKET_QUEUE`).
pub const FIRST_PACKET_QUEUE: usize = 64 * 1024;
/// How often entitlements are refreshed.
pub const ENTITLEMENTS_INTERVAL: Duration = Duration::from_secs(60);
/// How long the same block is not reported again.
const BLOCK_REPEAT: Duration = Duration::from_secs(30);
/// How many recent events status keeps.
const RECENT: usize = 20;

/// What the engine needs from the system it runs on.
pub trait Platform: Send + Sync + 'static {
    /// Hands an IP packet from the tunnel to the system's network stack.
    fn deliver(&self, packet: &[u8]);
    /// Applies the tunnel's network settings. Called once at start and
    /// whenever the routes change; `settings` is always the full set.
    /// Returns warnings about routes the system would not take (a local
    /// network that already routes the range, for example); an error means
    /// the tunnel cannot work at all.
    fn apply(&self, settings: &NetworkSettings) -> Result<Vec<String>, String>;
}

/// The tunnel's addresses, MTU and routes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// The device's tunnel addresses (from its certificate).
    pub addresses: Vec<IpAddr>,
    /// The tunnel MTU.
    pub mtu: u16,
    /// Every range routed into the tunnel: internal apps only.
    pub routes: Vec<IpNet>,
    /// App ranges left out, and why.
    pub skipped: Vec<SkippedRoute>,
}

/// An app range the engine did not route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedRoute {
    /// The range.
    pub range: String,
    /// The app.
    pub app: String,
    /// Why.
    pub why: String,
}

/// Engine settings.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Carrier selection.
    pub transport: TransportMode,
    /// The tunnel MTU (never below the 1280-byte floor).
    pub tunnel_mtu: u16,
    /// How long QUIC gets before HTTP/2 is raced.
    pub fallback_delay: Duration,
    /// How often entitlements are refreshed.
    pub entitlements_interval: Duration,
    /// The port relays listen on.
    pub relay_port: u16,
    /// Relays to dial instead of the entitlements' list (tests).
    pub relays: Option<Vec<RelayAddress>>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            transport: TransportMode::Auto,
            tunnel_mtu: params::TUNNEL_MTU,
            fallback_delay: params::FALLBACK_DELAY,
            entitlements_interval: ENTITLEMENTS_INTERVAL,
            relay_port: 443,
            relays: None,
        }
    }
}

/// Something the user should hear about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A connector group's tunnel is up.
    Connected {
        /// The connector group.
        group: String,
        /// The relay.
        relay: String,
        /// `QUIC` or `HTTP/2`.
        carrier: String,
    },
    /// A tunnel moved to another relay or carrier.
    PathChanged {
        /// The connector group.
        group: String,
        /// The relay.
        relay: String,
        /// `QUIC` or `HTTP/2`.
        carrier: String,
    },
    /// A tunnel is down; the engine keeps trying.
    Disconnected {
        /// The connector group.
        group: String,
        /// Why, for people.
        reason: String,
    },
    /// A flow was refused, by its connector or because its tunnel is down.
    Blocked {
        /// The flow, for example `tcp 10.77.0.20:7`.
        flow: String,
        /// The app it belongs to, when known.
        app: Option<String>,
        /// The reason code.
        reason: String,
        /// What happened, for people.
        message: String,
        /// What to do about it, possibly empty.
        remediation: String,
    },
    /// A connector or relay said something.
    Notice {
        /// The connector group.
        group: String,
        /// The reason code.
        reason: String,
        /// The message.
        message: String,
    },
    /// The certificate was renewed.
    Renewed {
        /// Its new end of validity, Unix seconds.
        not_after: i64,
    },
    /// The routes changed with the entitlements.
    RoutesChanged {
        /// Apps the user may reach or request.
        apps: usize,
        /// Ranges routed into the tunnel.
        routes: usize,
    },
    /// Something needs the user's attention.
    Problem {
        /// The reason code.
        reason: String,
        /// What happened and what to do, for people.
        message: String,
    },
}

/// `QUIC` or `HTTP/2`.
pub fn carrier_name(c: CarrierKind) -> &'static str {
    match c {
        CarrierKind::Http3 => "QUIC",
        CarrierKind::Http2 => "HTTP/2",
    }
}

impl Event {
    /// The event as one line for people.
    pub fn message(&self) -> String {
        match self {
            Event::Connected {
                group,
                relay,
                carrier,
            } => format!("connected to {group} through {relay} over {carrier}"),
            Event::PathChanged {
                group,
                relay,
                carrier,
            } => format!("{group}: now through {relay} over {carrier}"),
            Event::Disconnected { group, reason } => {
                format!("{group}: not connected: {reason}; retrying")
            }
            Event::Blocked {
                flow,
                app,
                reason,
                message,
                remediation,
            } => {
                let app = app
                    .as_deref()
                    .map(|a| format!(" ({a})"))
                    .unwrap_or_default();
                let fix = if remediation.is_empty() {
                    String::new()
                } else {
                    format!(" {remediation}")
                };
                format!("blocked {flow}{app}: {message}{fix} [{reason}]")
            }
            Event::Notice {
                group,
                reason,
                message,
            } => format!("{group}: {message} [{reason}]"),
            Event::Renewed { not_after } => {
                format!(
                    "certificate renewed; valid until {}",
                    clock::rfc3339(*not_after)
                )
            }
            Event::RoutesChanged { apps, routes } => {
                format!("entitlements updated: {apps} apps, {routes} routes")
            }
            Event::Problem { message, .. } => message.clone(),
        }
    }
}

/// A connector group's tunnel, as status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStatus {
    /// The connector group.
    pub name: String,
    /// `connecting`, `connected` or `down`.
    pub state: String,
    /// The relay, when connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// The carrier, when connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    /// Why it is down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Since when, Unix seconds.
    pub since: i64,
}

/// An app, as status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStatus {
    /// The app's name.
    pub name: String,
    /// `allowed` or `requestable`.
    pub access: String,
    /// Its connector group.
    pub group: String,
    /// Its destinations, as `range protocol ports`.
    pub destinations: Vec<String>,
}

/// One recent event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recent {
    /// When, Unix seconds.
    pub at: i64,
    /// What, for people.
    pub message: String,
}

/// The engine's state, for `warren status` and the menu.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// The organization URL.
    pub org: String,
    /// The signed-in user (email, or ID).
    pub user: String,
    /// The device ID.
    pub device: String,
    /// The device's approval status.
    pub device_status: String,
    /// Where the device key lives.
    pub key_storage: String,
    /// When the sign-in session ends, Unix seconds.
    pub session_expires_at: i64,
    /// The current certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateTimes>,
    /// The network settings in force.
    pub network: NetworkSettings,
    /// The tunnels.
    pub groups: Vec<GroupStatus>,
    /// The apps.
    pub apps: Vec<AppStatus>,
    /// Recent events, oldest first.
    pub recent: Vec<Recent>,
}

impl Status {
    /// Status from what the account and store know, without an engine.
    pub fn offline(account: &Account) -> Status {
        let store = account.store();
        let p = &account.profile;
        let entitlements = store.entitlements().ok().flatten();
        Status {
            org: p.org_url.clone(),
            user: p.user.email.clone().unwrap_or_else(|| p.user.id.clone()),
            device: p.device.as_ref().map(|d| d.id.clone()).unwrap_or_default(),
            device_status: p
                .device
                .as_ref()
                .map(|d| d.status.clone())
                .unwrap_or_else(|| "not enrolled".into()),
            key_storage: account.key.storage().describe().into(),
            session_expires_at: p.session.expires_at,
            certificate: store.certificate().ok().flatten().map(|c| c.times),
            network: NetworkSettings::default(),
            groups: Vec::new(),
            apps: entitlements.as_ref().map(apps_status).unwrap_or_default(),
            recent: Vec::new(),
        }
    }
}

fn apps_status(e: &Entitlements) -> Vec<AppStatus> {
    e.apps
        .iter()
        .map(|a| AppStatus {
            name: a.name.clone(),
            access: a.access.clone(),
            group: a.connector_group.clone(),
            destinations: a
                .destinations
                .iter()
                .map(|d| {
                    let target = d
                        .cidr
                        .clone()
                        .or_else(|| d.host.clone())
                        .unwrap_or_default();
                    let ports = if d.ports.is_empty() {
                        String::new()
                    } else {
                        let list: Vec<String> = d
                            .ports
                            .iter()
                            .map(|p| {
                                if p.from == p.to {
                                    p.from.to_string()
                                } else {
                                    format!("{}-{}", p.from, p.to)
                                }
                            })
                            .collect();
                        format!(" {}", list.join(","))
                    };
                    format!("{target} {}{ports}", d.protocol)
                })
                .collect(),
        })
        .collect()
}

/// A routed range and the app and group it belongs to.
#[derive(Debug, Clone)]
struct Route {
    net: IpNet,
    app: String,
    group: String,
}

/// The routes in force, most specific first.
#[derive(Debug, Default)]
struct Plan {
    routes: Vec<Route>,
    settings: NetworkSettings,
    entitlements: Option<Entitlements>,
}

impl Plan {
    fn lookup(&self, ip: IpAddr) -> Option<&Route> {
        self.routes.iter().find(|r| r.net.contains(ip))
    }

    fn groups(&self) -> Vec<String> {
        let mut g: Vec<String> = self.routes.iter().map(|r| r.group.clone()).collect();
        g.sort();
        g.dedup();
        g
    }
}

/// Whether a range is too broad to be an internal app: anything wider
/// than a /8. warren tunnels internal apps only, never a default route or
/// the halves of one (G14).
pub fn too_broad(net: &IpNet) -> bool {
    net.len < 8
}

/// Builds the routes for `e`: every CIDR destination of every app the
/// user may reach or request, except ranges that would capture the path
/// to a relay or the control plane, and never a default route.
fn plan(e: &Entitlements, addresses: Vec<IpAddr>, mtu: u16, protected: &[IpAddr]) -> Plan {
    let mut routes = Vec::new();
    let mut skipped = Vec::new();
    for app in &e.apps {
        for d in &app.destinations {
            let Some(cidr) = &d.cidr else { continue };
            let Ok(net) = cidr.parse::<IpNet>() else {
                continue;
            };
            let why = if too_broad(&net) {
                Some("warren routes internal apps only, never a range this wide".to_owned())
            } else {
                protected
                    .iter()
                    .find(|ip| net.contains(**ip))
                    .map(|ip| format!("it contains {ip}, which warren itself must reach directly"))
            };
            if let Some(why) = why {
                skipped.push(SkippedRoute {
                    range: net.to_string(),
                    app: app.name.clone(),
                    why,
                });
                continue;
            }
            routes.push(Route {
                net,
                app: app.name.clone(),
                group: app.connector_group.clone(),
            });
        }
    }
    routes.sort_by_key(|r| std::cmp::Reverse(r.net.len));
    let mut nets: Vec<IpNet> = routes.iter().map(|r| r.net).collect();
    nets.sort_by_key(|n| (n.addr.is_ipv6(), n.addr, n.len));
    nets.dedup();
    Plan {
        settings: NetworkSettings {
            addresses,
            mtu,
            routes: nets,
            skipped,
        },
        routes,
        entitlements: Some(e.clone()),
    }
}

#[derive(Debug)]
enum GroupState {
    Connecting,
    Up {
        sender: PacketSender,
        relay: String,
        carrier: CarrierKind,
    },
    Down(String),
}

/// Packets waiting for a group's session.
#[derive(Debug, Default)]
struct Hold {
    packets: VecDeque<(Instant, Vec<u8>)>,
    bytes: usize,
}

#[derive(Debug)]
struct Group {
    name: String,
    state: Mutex<(GroupState, i64)>,
    hold: Mutex<Hold>,
    stop: watch::Sender<bool>,
}

impl Group {
    fn set(&self, s: GroupState) {
        *self.state.lock().expect("group lock") = (s, clock::now_secs());
    }

    fn status(&self) -> GroupStatus {
        let st = self.state.lock().expect("group lock");
        let (state, relay, carrier, reason) = match &st.0 {
            GroupState::Connecting => ("connecting", None, None, None),
            GroupState::Up { relay, carrier, .. } => (
                "connected",
                Some(relay.clone()),
                Some(carrier_name(*carrier).to_owned()),
                None,
            ),
            GroupState::Down(r) => ("down", None, None, Some(r.clone())),
        };
        GroupStatus {
            name: self.name.clone(),
            state: state.into(),
            relay,
            carrier,
            reason,
            since: st.1,
        }
    }
}

struct Shared {
    platform: Arc<dyn Platform>,
    options: EngineOptions,
    account: tokio::sync::Mutex<Account>,
    key: Arc<DeviceKey>,
    trust: Arc<TrustBundle>,
    addresses: Vec<IpAddr>,
    cert: watch::Sender<Arc<StoredCertificate>>,
    plan: RwLock<Arc<Plan>>,
    groups: Mutex<HashMap<String, Arc<Group>>>,
    relays: RwLock<Vec<RelayAddress>>,
    protected: RwLock<Vec<IpAddr>>,
    events: broadcast::Sender<Event>,
    recent: Mutex<VecDeque<Recent>>,
    reported: Mutex<HashMap<String, Instant>>,
    renew_now: Notify,
    shutdown: watch::Sender<bool>,
    static_status: Mutex<Status>,
}

impl Shared {
    fn emit(&self, e: Event) {
        let mut recent = self.recent.lock().expect("recent lock");
        if recent.len() == RECENT {
            recent.pop_front();
        }
        recent.push_back(Recent {
            at: clock::now_secs(),
            message: e.message(),
        });
        drop(recent);
        let _ = self.events.send(e);
    }

    /// Reports a block once per `BLOCK_REPEAT` for the same flow target
    /// and reason, so a retrying app produces one clear message.
    fn report_block(&self, key: String, e: Event) {
        let now = Instant::now();
        let mut seen = self.reported.lock().expect("reported lock");
        seen.retain(|_, t| now.duration_since(*t) < BLOCK_REPEAT);
        if seen.contains_key(&key) {
            return;
        }
        seen.insert(key, now);
        drop(seen);
        self.emit(e);
    }

    fn app_for(&self, ip: IpAddr) -> Option<String> {
        let plan = self.plan.read().expect("plan lock").clone();
        plan.lookup(ip).map(|r| r.app.clone())
    }

    fn denied(&self, d: FlowDenied) {
        let flow = flow_text(d.flow.protocol, d.flow.dst);
        let key = format!("{}|{}", d.reason, flow);
        self.report_block(
            key,
            Event::Blocked {
                app: self.app_for(d.flow.dst.ip()),
                flow,
                reason: d.reason,
                message: d.message,
                remediation: d.remediation,
            },
        );
    }

    /// Answers a packet the engine cannot carry, so the application fails
    /// at once instead of timing out (G12), and says why.
    fn refuse(&self, raw: &[u8], p: &Parsed, app: Option<String>, reason: &str, message: &str) {
        let answer = if p.protocol == proto::TCP {
            (p.tcp_flags & packet::tcp::RST == 0)
                .then(|| packet::tcp_reset(raw, p))
                .flatten()
        } else if p.is_icmp_error() {
            None
        } else {
            packet::icmp_error(raw, p, IcmpError::AdminProhibited, p.dst)
        };
        if let Some(a) = answer {
            self.platform.deliver(&a);
        }
        let flow = flow_text(p.protocol, p.dst_sock());
        self.report_block(
            format!("{reason}|{flow}"),
            Event::Blocked {
                flow,
                app,
                reason: reason.into(),
                message: message.into(),
                remediation: String::new(),
            },
        );
    }

    fn credentials(&self, cert: &StoredCertificate) -> DeviceCredentials {
        DeviceCredentials::External {
            chain: cert.chain.clone(),
            signer: self.key.tls_signer(),
        }
    }

    /// Picks up a session a later sign-in saved; returns whether it did.
    fn reload_session(&self, account: &mut Account) -> bool {
        if !account.reload_session() {
            return false;
        }
        let p = &account.profile;
        let mut s = self.static_status.lock().expect("status lock");
        s.user = p.user.email.clone().unwrap_or_else(|| p.user.id.clone());
        s.session_expires_at = p.session.expires_at;
        true
    }

    fn stopping(&self) -> bool {
        *self.shutdown.borrow()
    }
}

fn flow_text(protocol: u8, dst: SocketAddr) -> String {
    match protocol {
        proto::TCP => format!("tcp {dst}"),
        proto::UDP => format!("udp {dst}"),
        proto::ICMP | proto::ICMPV6 => format!("icmp {}", dst.ip()),
        p => format!("protocol {p} {}", dst.ip()),
    }
}

/// A running engine.
pub struct Engine {
    shared: Arc<Shared>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    first_events: Mutex<Option<broadcast::Receiver<Event>>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

/// Why the engine cannot start, for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError {
    /// A reason code: `device_not_approved`, `reauth_required`,
    /// `unreachable` and the like.
    pub reason: String,
    /// What happened and what to do.
    pub message: String,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StartError {}

fn start_error(e: &ApiError, device: &str) -> StartError {
    let message = match e.reason.as_str() {
        "device_not_approved" => format!(
            "{} Ask an administrator to approve device {device}, then run warren up again.",
            e.detail
        ),
        _ if e.needs_sign_in() => format!("{} Run warren login to sign in again.", e.detail),
        _ => e.detail.clone(),
    };
    StartError {
        reason: e.reason.clone(),
        message,
    }
}

/// The control plane's and the organization URL's addresses, which routes
/// must never capture.
async fn control_plane_addresses(account: &Account) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let urls = [
        Some(account.profile.org_url.clone()),
        account.profile.api_base.clone(),
    ];
    for url in urls.into_iter().flatten() {
        if let Ok(e) = Endpoint::parse(&url)
            && let Ok(addrs) = tokio::net::lookup_host((e.host.as_str(), e.port)).await
        {
            out.extend(addrs.map(|a| a.ip()));
        }
    }
    out
}

impl Engine {
    /// Starts the engine: gets a usable certificate and the entitlements,
    /// applies the network settings, and starts one tunnel per connector
    /// group.
    pub async fn start(
        mut account: Account,
        platform: Arc<dyn Platform>,
        options: EngineOptions,
    ) -> Result<Engine, StartError> {
        if options.tunnel_mtu < params::TUNNEL_MTU_FLOOR {
            return Err(StartError {
                reason: "mtu_floor".into(),
                message: format!(
                    "the tunnel MTU must be at least {} bytes",
                    params::TUNNEL_MTU_FLOOR
                ),
            });
        }
        let device = account
            .profile
            .device
            .as_ref()
            .map(|d| d.id.clone())
            .unwrap_or_default();
        let now = clock::now_secs();
        let stored = account.store().certificate().ok().flatten();
        let cert = match stored {
            Some(c) if c.times.renew_at > now => c,
            stale => match account.issue_certificate().await {
                Ok(c) => c,
                // During a control-plane outage a certificate that is still
                // valid keeps working until it expires (G10).
                Err(e) if e.status == 0 => match stale {
                    Some(c) if c.times.not_after > now + 60 => c,
                    _ => return Err(start_error(&e, &device)),
                },
                Err(e) => return Err(start_error(&e, &device)),
            },
        };
        let leaf = cert.chain.first().ok_or_else(|| StartError {
            reason: "bad_certificate".into(),
            message: "the stored certificate is empty".into(),
        })?;
        let id = pki::check_client_profile(leaf, &account.trust.trust_domain).map_err(|e| {
            StartError {
                reason: "bad_certificate".into(),
                message: format!("the stored certificate is unusable: {e}"),
            }
        })?;
        let addresses = vec![
            IpAddr::V4(id.identity.tunnel_v4),
            IpAddr::V6(id.identity.tunnel_v6),
        ];
        let entitlements = match account.entitlements().await {
            Ok(e) => e,
            Err(e) if e.status == 0 => account
                .store()
                .entitlements()
                .ok()
                .flatten()
                .ok_or_else(|| start_error(&e, &device))?,
            Err(e) => return Err(start_error(&e, &device)),
        };
        let protected = control_plane_addresses(&account).await;
        let mut status = Status::offline(&account);
        status.certificate = Some(cert.times);
        let (cert_tx, _) = watch::channel(Arc::new(cert));
        let (events, first_events) = broadcast::channel(256);
        let (shutdown, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            platform,
            key: account.key.clone(),
            trust: account.trust.clone(),
            options,
            account: tokio::sync::Mutex::new(account),
            addresses,
            cert: cert_tx,
            plan: RwLock::new(Arc::new(Plan::default())),
            groups: Mutex::new(HashMap::new()),
            relays: RwLock::new(Vec::new()),
            protected: RwLock::new(protected),
            events,
            recent: Mutex::new(VecDeque::new()),
            reported: Mutex::new(HashMap::new()),
            renew_now: Notify::new(),
            shutdown,
            static_status: Mutex::new(status),
        });
        apply_entitlements(&shared, entitlements, true)
            .await
            .map_err(|message| StartError {
                reason: "network_settings".into(),
                message,
            })?;
        let tasks = vec![
            tokio::spawn(renew_loop(shared.clone())),
            tokio::spawn(entitlements_loop(shared.clone())),
        ];
        Ok(Engine {
            shared,
            tasks: Mutex::new(tasks),
            first_events: Mutex::new(Some(first_events)),
        })
    }

    /// Takes a packet the system routed into the tunnel.
    pub fn send(&self, raw: &[u8]) {
        let Ok(p) = packet::parse(raw) else { return };
        let plan = self.shared.plan.read().expect("plan lock").clone();
        let Some(route) = plan.lookup(p.dst) else {
            // The system still routed it here after the routes changed.
            self.shared.refuse(
                raw,
                &p,
                None,
                "not_an_app",
                "this address is not part of any app you may reach",
            );
            return;
        };
        let group = self
            .shared
            .groups
            .lock()
            .expect("groups lock")
            .get(&route.group)
            .cloned();
        let Some(group) = group else {
            self.shared.refuse(
                raw,
                &p,
                Some(route.app.clone()),
                "unreachable",
                "warren is not connected to this app's connector group",
            );
            return;
        };
        let st = group.state.lock().expect("group lock");
        match &st.0 {
            GroupState::Up { sender, .. } => sender.send(raw),
            GroupState::Connecting => {
                // Queue while still holding the state: the session marks
                // itself up under this lock before it flushes the queue,
                // so a packet is either flushed or sent, never stranded.
                let mut hold = group.hold.lock().expect("hold lock");
                expire(&self.shared, &mut hold);
                if hold.bytes + raw.len() <= FIRST_PACKET_QUEUE {
                    hold.bytes += raw.len();
                    hold.packets.push_back((Instant::now(), raw.to_vec()));
                } else {
                    drop(hold);
                    self.shared.refuse(
                        raw,
                        &p,
                        Some(route.app.clone()),
                        "connecting",
                        "warren is still connecting to this app's connector",
                    );
                }
            }
            GroupState::Down(reason) => {
                let message = format!("warren cannot reach this app's connector: {reason}");
                drop(st);
                self.shared
                    .refuse(raw, &p, Some(route.app.clone()), "unreachable", &message);
            }
        }
    }

    /// Renews the certificate now instead of at half-life, with the
    /// latest saved sign-in, as after a fresh one; the tunnels move to the
    /// new certificate without reconnecting.
    pub fn renew_now(&self) {
        self.shared.renew_now.notify_one();
    }

    /// Events: the first call gets every event since the engine started,
    /// later calls those from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.first_events
            .lock()
            .expect("events lock")
            .take()
            .unwrap_or_else(|| self.shared.events.subscribe())
    }

    /// The engine's state.
    pub fn status(&self) -> Status {
        let mut s = self
            .shared
            .static_status
            .lock()
            .expect("status lock")
            .clone();
        let plan = self.shared.plan.read().expect("plan lock").clone();
        s.network = plan.settings.clone();
        if let Some(e) = &plan.entitlements {
            s.apps = apps_status(e);
        }
        s.certificate = Some(self.shared.cert.borrow().times);
        let mut groups: Vec<GroupStatus> = self
            .shared
            .groups
            .lock()
            .expect("groups lock")
            .values()
            .map(|g| g.status())
            .collect();
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        s.groups = groups;
        s.recent = self
            .shared
            .recent
            .lock()
            .expect("recent lock")
            .iter()
            .cloned()
            .collect();
        s
    }

    /// Closes every tunnel and stops.
    pub async fn stop(&self) {
        self.shared.shutdown.send_replace(true);
        let groups: Vec<Arc<Group>> = self
            .shared
            .groups
            .lock()
            .expect("groups lock")
            .drain()
            .map(|(_, g)| g)
            .collect();
        for g in &groups {
            g.stop.send_replace(true);
        }
        for t in self.tasks.lock().expect("tasks lock").drain(..) {
            t.abort();
        }
        // Give the tunnels a moment to tell their connectors.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Drops held packets older than `FIRST_PACKET_HOLD`, answering each.
fn expire(shared: &Shared, hold: &mut Hold) {
    while let Some((t, _)) = hold.packets.front() {
        if t.elapsed() < FIRST_PACKET_HOLD {
            break;
        }
        let (_, raw) = hold.packets.pop_front().expect("non-empty");
        hold.bytes -= raw.len();
        if let Ok(p) = packet::parse(&raw) {
            shared.refuse(
                &raw,
                &p,
                shared.app_for(p.dst),
                "connecting",
                "warren is still connecting to this app's connector",
            );
        }
    }
}

/// Answers every held packet: the session did not come up.
fn fail_held(shared: &Shared, group: &Group, reason: &str) {
    let held: Vec<Vec<u8>> = {
        let mut hold = group.hold.lock().expect("hold lock");
        hold.bytes = 0;
        hold.packets.drain(..).map(|(_, p)| p).collect()
    };
    for raw in held {
        if let Ok(p) = packet::parse(&raw) {
            let message = format!("warren cannot reach this app's connector: {reason}");
            shared.refuse(&raw, &p, shared.app_for(p.dst), "unreachable", &message);
        }
    }
}

/// Applies new entitlements: routes, relays, and the set of groups.
async fn apply_entitlements(
    shared: &Arc<Shared>,
    e: Entitlements,
    first: bool,
) -> Result<(), String> {
    let relays = match &shared.options.relays {
        Some(r) => r.clone(),
        None => {
            let resolved = relays::resolve(&e.relays, shared.options.relay_port).await;
            relays::rank(resolved)
                .await
                .into_iter()
                .map(|r| r.address)
                .collect()
        }
    };
    let mut protected = shared.protected.read().expect("protected lock").clone();
    protected.extend(relays.iter().map(|r| r.quic.ip()));
    let new = plan(
        &e,
        shared.addresses.clone(),
        shared.options.tunnel_mtu,
        &protected,
    );
    let old = shared.plan.read().expect("plan lock").clone();
    let changed = old.settings != new.settings;
    if first || changed {
        for w in shared.platform.apply(&new.settings)? {
            shared.emit(Event::Problem {
                reason: "route_failed".into(),
                message: w,
            });
        }
        for s in &new.settings.skipped {
            shared.emit(Event::Problem {
                reason: "route_skipped".into(),
                message: format!("not routing {} for {}: {}", s.range, s.app, s.why),
            });
        }
    }
    *shared.relays.write().expect("relays lock") = relays;
    let groups = new.groups();
    let apps = e.apps.len();
    let routes = new.settings.routes.len();
    *shared.plan.write().expect("plan lock") = Arc::new(new);
    if !first && changed {
        shared.emit(Event::RoutesChanged { apps, routes });
    }
    // Start tunnels for new groups and stop those no app needs any more.
    let mut current = shared.groups.lock().expect("groups lock");
    current.retain(|name, g| {
        let keep = groups.contains(name);
        if !keep {
            g.stop.send_replace(true);
        }
        keep
    });
    for name in groups {
        if current.contains_key(&name) || shared.stopping() {
            continue;
        }
        let (stop, stop_rx) = watch::channel(false);
        let g = Arc::new(Group {
            name: name.clone(),
            state: Mutex::new((GroupState::Connecting, clock::now_secs())),
            hold: Mutex::new(Hold::default()),
            stop,
        });
        current.insert(name, g.clone());
        tokio::spawn(run_group(shared.clone(), g, stop_rx));
    }
    Ok(())
}

async fn run_group(shared: Arc<Shared>, group: Arc<Group>, mut stop: watch::Receiver<bool>) {
    let mut backoff = Duration::from_millis(500);
    let mut last_report: Option<String> = None;
    loop {
        if *stop.borrow() || shared.stopping() {
            return;
        }
        group.set(GroupState::Connecting);
        let cert = shared.cert.borrow().clone();
        let relays = shared.relays.read().expect("relays lock").clone();
        let outcome = if cert.times.not_after <= clock::now_secs() {
            shared.renew_now.notify_one();
            Err("the certificate has expired and is not renewed yet".to_owned())
        } else if relays.is_empty() {
            Err("no relay is available; the deployment lists none this device can reach".into())
        } else {
            let config = ClientConfig {
                group: group.name.clone(),
                relays,
                transport: shared.options.transport,
                credentials: shared.credentials(&cert),
                trust: shared.trust.clone(),
                tunnel_mtu: shared.options.tunnel_mtu,
                fallback_delay: shared.options.fallback_delay,
                tuning: TransportTuning::default(),
            };
            let connect = crate::connect(config);
            tokio::pin!(connect);
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    r = &mut connect => break r.map_err(|e| {
                        if matches!(e, ConnectError::Rejected(_)) {
                            shared.renew_now.notify_one();
                        }
                        e.to_string()
                    }),
                    _ = tick.tick() => {
                        let mut hold = group.hold.lock().expect("hold lock");
                        expire(&shared, &mut hold);
                    }
                    _ = stop.changed() => {
                        group.set(GroupState::Down("stopped".into()));
                        return;
                    }
                }
            }
        };
        let reason = match outcome {
            Ok(tunnel) => {
                backoff = Duration::from_millis(500);
                last_report = None;
                carry(&shared, &group, tunnel, &mut stop).await
            }
            Err(e) => e,
        };
        if *stop.borrow() || shared.stopping() {
            group.set(GroupState::Down("stopped".into()));
            return;
        }
        group.set(GroupState::Down(reason.clone()));
        fail_held(&shared, &group, &reason);
        if last_report.as_deref() != Some(reason.as_str()) {
            shared.emit(Event::Disconnected {
                group: group.name.clone(),
                reason: reason.clone(),
            });
            last_report = Some(reason);
        }
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            _ = stop.changed() => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// Moves packets for one live tunnel until it ends; returns why it ended.
async fn carry(
    shared: &Arc<Shared>,
    group: &Group,
    mut tunnel: crate::Tunnel,
    stop: &mut watch::Receiver<bool>,
) -> String {
    let carrier = tunnel.stats().carrier.unwrap_or(CarrierKind::Http3);
    let relay = tunnel.info().relay.clone();
    let sender = tunnel.sender();
    group.set(GroupState::Up {
        sender: sender.clone(),
        relay: relay.clone(),
        carrier,
    });
    let held: Vec<Vec<u8>> = {
        let mut hold = group.hold.lock().expect("hold lock");
        hold.bytes = 0;
        hold.packets.drain(..).map(|(_, p)| p).collect()
    };
    for p in held {
        sender.send(&p);
    }
    shared.emit(Event::Connected {
        group: group.name.clone(),
        relay,
        carrier: carrier_name(carrier).into(),
    });
    let mut events = tunnel.events();
    let mut certs = shared.cert.subscribe();
    certs.mark_unchanged();
    let reason = loop {
        tokio::select! {
            p = tunnel.recv() => match p {
                Some(p) => shared.platform.deliver(&p),
                None => break "the tunnel closed".to_owned(),
            },
            e = events.recv() => match e {
                Some(ClientEvent::Denied(d)) => shared.denied(d),
                Some(ClientEvent::Notice(n)) => shared.emit(Event::Notice {
                    group: group.name.clone(),
                    reason: n.reason,
                    message: n.message,
                }),
                Some(ClientEvent::PathChanged { carrier, relay }) => {
                    group.set(GroupState::Up { sender: sender.clone(), relay: relay.clone(), carrier });
                    shared.emit(Event::PathChanged {
                        group: group.name.clone(),
                        relay,
                        carrier: carrier_name(carrier).into(),
                    });
                }
                Some(ClientEvent::Closed(r)) => break r,
                None => break "the tunnel closed".to_owned(),
            },
            r = certs.changed() => {
                if r.is_err() {
                    break "stopped".to_owned();
                }
                let cert = certs.borrow_and_update().clone();
                let key = shared.key.clone();
                if let Err(e) = tunnel
                    .refresh_certificate(shared.credentials(&cert), |exporter| key.sign_der(exporter))
                    .await
                {
                    shared.emit(Event::Problem {
                        reason: "refresh_failed".into(),
                        message: format!("{}: could not move the tunnel to the renewed certificate: {e}", group.name),
                    });
                }
            }
            _ = stop.changed() => break "stopped".to_owned(),
        }
    };
    tunnel.close();
    if reason.contains("revoked") || reason.contains("certificate") {
        shared.renew_now.notify_one();
    }
    reason
}

fn renewal_problem(e: &ApiError, not_after: i64) -> Event {
    let ends = clock::rfc3339(not_after);
    let message = if e.needs_sign_in() {
        format!(
            "{} Run warren login to sign in again; access ends at {ends} otherwise.",
            e.detail
        )
    } else if e.status == 0 {
        format!(
            "cannot renew the certificate: {}. Access continues until {ends}.",
            e.detail
        )
    } else {
        format!(
            "the control plane refused to renew the certificate: {} Access ends at {ends}.",
            e.detail
        )
    };
    Event::Problem {
        reason: e.reason.clone(),
        message,
    }
}

async fn renew_loop(shared: Arc<Shared>) {
    let mut failures: u32 = 0;
    let mut last_renewal: Option<Instant> = None;
    let mut renewed_session = shared.account.lock().await.profile.session.id.clone();
    let mut shutdown = shared.shutdown.subscribe();
    loop {
        let times = shared.cert.borrow().times;
        let wait = if failures == 0 {
            Duration::from_secs((times.renew_at - clock::now_secs()).max(0).unsigned_abs())
        } else {
            Duration::from_secs(30 * 2u64.pow(failures.min(4)))
        };
        let notified = tokio::select! {
            () = tokio::time::sleep(wait) => false,
            () = shared.renew_now.notified() => true,
            _ = shutdown.changed() => return,
        };
        let mut account = shared.account.lock().await;
        shared.reload_session(&mut account);
        let session = account.profile.session.id.clone();
        // Something was refused: renew, but not over and over, unless a
        // new sign-in is there to renew with.
        if notified
            && session == renewed_session
            && last_renewal.is_some_and(|t| t.elapsed() < Duration::from_secs(60))
        {
            continue;
        }
        let result = account.issue_certificate().await;
        drop(account);
        match result {
            Ok(c) => {
                failures = 0;
                last_renewal = Some(Instant::now());
                renewed_session = session;
                let not_after = c.times.not_after;
                shared
                    .static_status
                    .lock()
                    .expect("status lock")
                    .certificate = Some(c.times);
                shared.cert.send_replace(Arc::new(c));
                shared.emit(Event::Renewed { not_after });
            }
            Err(e) => {
                failures += 1;
                shared.emit(renewal_problem(&e, times.not_after));
            }
        }
    }
}

async fn entitlements_loop(shared: Arc<Shared>) {
    let mut shutdown = shared.shutdown.subscribe();
    let mut told_sign_in = false;
    loop {
        tokio::select! {
            () = tokio::time::sleep(shared.options.entitlements_interval) => {}
            _ = shutdown.changed() => return,
        }
        let mut account = shared.account.lock().await;
        if shared.reload_session(&mut account) {
            shared.renew_now.notify_one();
        }
        let result = account.entitlements().await;
        drop(account);
        match result {
            Ok(e) => {
                told_sign_in = false;
                let same = shared
                    .plan
                    .read()
                    .expect("plan lock")
                    .entitlements
                    .as_ref()
                    .is_some_and(|old| *old == e);
                if !same && let Err(err) = apply_entitlements(&shared, e, false).await {
                    shared.emit(Event::Problem {
                        reason: "network_settings".into(),
                        message: format!("cannot apply the new routes: {err}"),
                    });
                }
            }
            Err(e) if e.needs_sign_in() && !told_sign_in => {
                told_sign_in = true;
                shared.emit(Event::Problem {
                    reason: e.reason.clone(),
                    message: format!("{} Run warren login to sign in again.", e.detail),
                });
            }
            // An unreachable control plane changes nothing: the tunnels
            // keep their routes until the certificate ends (G10).
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warren_core::api::{EntitledApp, EntitledDestination};

    fn app(name: &str, group: &str, cidrs: &[&str]) -> EntitledApp {
        EntitledApp {
            name: name.into(),
            access: "allowed".into(),
            connector_group: group.into(),
            destinations: cidrs
                .iter()
                .map(|c| EntitledDestination {
                    host: None,
                    cidr: Some((*c).into()),
                    protocol: "tcp".into(),
                    ports: Vec::new(),
                })
                .chain(std::iter::once(EntitledDestination {
                    host: Some("grafana.lab.example.com".into()),
                    cidr: None,
                    protocol: "tcp".into(),
                    ports: Vec::new(),
                }))
                .collect(),
        }
    }

    #[test]
    fn plans_route_app_ranges_only_and_most_specific_first() {
        let e = Entitlements {
            version: 1,
            apps: vec![
                app("lab", "homelab", &["10.20.0.0/16"]),
                app("db", "prod", &["10.20.5.0/24", "fd00:20::/64"]),
                app("everything", "prod", &["0.0.0.0/0"]),
                app("relay-net", "homelab", &["192.0.2.0/24"]),
            ],
            dns_suffixes: Vec::new(),
            relays: Vec::new(),
        };
        let addrs: Vec<IpAddr> = vec!["100.96.0.2".parse().unwrap()];
        let p = plan(&e, addrs.clone(), 1280, &["192.0.2.10".parse().unwrap()]);
        assert_eq!(p.settings.addresses, addrs);
        let routes: Vec<String> = p.settings.routes.iter().map(ToString::to_string).collect();
        assert_eq!(routes, ["10.20.0.0/16", "10.20.5.0/24", "fd00:20::/64"]);
        assert_eq!(
            p.lookup("10.20.5.9".parse().unwrap()).unwrap().group,
            "prod"
        );
        assert_eq!(p.lookup("10.20.6.9".parse().unwrap()).unwrap().app, "lab");
        assert!(p.lookup("8.8.8.8".parse().unwrap()).is_none());
        let skipped: Vec<&str> = p.settings.skipped.iter().map(|s| s.app.as_str()).collect();
        assert_eq!(skipped, ["everything", "relay-net"]);
        assert_eq!(p.groups(), ["homelab", "prod"]);
    }

    #[test]
    fn events_read_as_sentences() {
        let e = Event::Blocked {
            flow: "tcp 10.77.0.20:7".into(),
            app: Some("secret".into()),
            reason: "no_rule".into(),
            message: "No rule gives you access to secret.".into(),
            remediation: "Ask for access.".into(),
        };
        assert_eq!(
            e.message(),
            "blocked tcp 10.77.0.20:7 (secret): No rule gives you access to secret. Ask for access. [no_rule]"
        );
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["event"], "blocked");
        assert_eq!(
            Event::Connected {
                group: "homelab".into(),
                relay: "relay.example.com".into(),
                carrier: "QUIC".into()
            }
            .message(),
            "connected to homelab through relay.example.com over QUIC"
        );
    }
}
