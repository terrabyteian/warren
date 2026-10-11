//! The node bundle: what a relay or connector knows about the deployment.
//!
//! In production this arrives as the control plane's signed, versioned
//! policy bundle (docs/protocol.md section 11.2) plus the revocation stream
//! (section 12). Until that feed exists, nodes load the same content from a
//! static JSON file, in the shapes of docs/policy.md. Bundle versions only
//! increase: a reload with an older version is rejected.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Deserialize;

use crate::identity::{NodeRole, valid_id};
use crate::pki::{CertError, ClientIdentity, NodeIdentity};
use crate::tls::RevocationCheck;

/// A bundle could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError(pub String);

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bundle: {}", self.0)
    }
}

impl std::error::Error for BundleError {}

fn err<T>(msg: impl Into<String>) -> Result<T, BundleError> {
    Err(BundleError(msg.into()))
}

/// The static bundle file.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    /// Monotonic version.
    pub version: u64,
    /// The deployment's trust domain.
    pub trust_domain: String,
    /// Connector groups and their scopes.
    #[serde(default)]
    pub connector_groups: Vec<ConnectorGroup>,
    /// Apps.
    #[serde(default)]
    pub apps: Vec<App>,
    /// Users and their IdP groups.
    #[serde(default)]
    pub users: Vec<User>,
    /// Devices and their approval.
    #[serde(default)]
    pub devices: Vec<Device>,
    /// Access rules.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Revocation state.
    #[serde(default)]
    pub revoked: Revoked,
}

/// A connector group (docs/policy.md section 2).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorGroup {
    /// Name.
    pub name: String,
    /// Whether relays accept its connectors and route to it.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// What its apps may point at.
    #[serde(default)]
    pub destinations: Destinations,
    /// Names clients may use for its apps.
    #[serde(default)]
    pub client_names: Vec<String>,
}

fn yes() -> bool {
    true
}

/// A destination scope.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Destinations {
    /// Exact or `*.` wildcard domains.
    #[serde(default)]
    pub domains: Vec<String>,
    /// CIDR ranges.
    #[serde(default)]
    pub cidrs: Vec<String>,
}

/// An app (docs/policy.md section 3).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct App {
    /// Name.
    pub name: String,
    /// The group that serves it.
    pub connector_group: String,
    /// Labels for selectors.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Destinations.
    pub destinations: Vec<AppDestination>,
    /// Whether servers may open flows toward clients.
    #[serde(default)]
    pub server_initiated_flows: bool,
    /// Whether users who may request it can see it.
    #[serde(default)]
    pub discoverable: bool,
}

/// One destination of an app.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppDestination {
    /// A client-facing host name, exact or `*.` wildcard.
    #[serde(default)]
    pub host: Option<String>,
    /// For an exact host: the name or address the connector reaches.
    #[serde(default)]
    pub target: Option<String>,
    /// An IP address or CIDR range.
    #[serde(default)]
    pub cidr: Option<String>,
    /// Ports or port ranges; empty means every port.
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// `tcp`, `udp`, `icmp` or `any`.
    pub protocol: String,
}

/// A port or `low-high` range, as a number or a string.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    /// A single port.
    Number(u16),
    /// `"22"` or `"8000-8100"`.
    Text(String),
}

/// A user.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct User {
    /// The user ID in certificates.
    pub id: String,
    /// IdP groups.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Disabled users have no access.
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// A device.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Device {
    /// The device ID in certificates.
    pub id: String,
    /// Whether the device is approved.
    pub approved: bool,
}

/// An access rule (docs/policy.md section 5).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    /// `<policy>/<rule>`.
    pub id: String,
    /// `allow` (default) or `deny`.
    #[serde(default = "allow")]
    pub effect: String,
    /// Who.
    pub who: Who,
    /// What.
    pub what: What,
    /// Conditions.
    #[serde(default)]
    pub when: When,
}

fn allow() -> String {
    "allow".into()
}

/// Rule subjects.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Who {
    /// User IDs.
    #[serde(default)]
    pub users: Vec<String>,
    /// IdP groups.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Rule objects.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct What {
    /// App names.
    #[serde(default)]
    pub apps: Vec<String>,
    /// Label selector.
    #[serde(default)]
    pub app_selector: Option<AppSelector>,
}

/// A label selector.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppSelector {
    /// Labels that must all match.
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

/// Rule conditions supported by the static enforcement point. Posture,
/// schedule and network conditions arrive with the control plane's
/// compiled policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct When {
    /// Authentication freshness.
    #[serde(default)]
    pub auth: Option<AuthCondition>,
}

/// `when.auth`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthCondition {
    /// Maximum age of the IdP sign-in, like `12h`.
    #[serde(default)]
    pub max_age: Option<String>,
    /// Whether MFA is required.
    #[serde(default)]
    pub mfa: bool,
}

/// Revocation state.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revoked {
    /// Disabled users.
    #[serde(default)]
    pub users: Vec<String>,
    /// Disabled or revoked devices.
    #[serde(default)]
    pub devices: Vec<String>,
    /// Revoked sign-in sessions.
    #[serde(default)]
    pub sessions: Vec<String>,
    /// Revoked certificate serials, hex.
    #[serde(default)]
    pub serials: Vec<String>,
    /// Revoked infrastructure nodes, as `relay/<id>` or
    /// `connector/<group>/<id>`.
    #[serde(default)]
    pub nodes: Vec<String>,
}

/// An IP prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length.
    pub len: u8,
}

impl IpNet {
    /// Whether `ip` is inside.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }

    /// Whether `other` lies entirely inside.
    pub fn covers(&self, other: &IpNet) -> bool {
        other.len >= self.len && self.contains(other.addr)
    }

    /// First and last address.
    pub fn range(&self) -> (IpAddr, IpAddr) {
        match self.addr {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                let start = u32::from(a) & mask;
                (IpAddr::V4(start.into()), IpAddr::V4((start | !mask).into()))
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                let start = u128::from(a) & mask;
                (IpAddr::V6(start.into()), IpAddr::V6((start | !mask).into()))
            }
        }
    }
}

impl FromStr for IpNet {
    type Err = BundleError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| BundleError(format!("invalid address {s:?}")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            Some(l) => l
                .parse::<u8>()
                .ok()
                .filter(|l| *l <= max)
                .ok_or_else(|| BundleError(format!("invalid prefix length in {s:?}")))?,
            None => max,
        };
        let net = IpNet { addr, len };
        if net.range().0 != addr {
            return err(format!("{s:?} has host bits set"));
        }
        Ok(net)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// An exact name or a `*.` wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomainPattern {
    /// Matches one name.
    Exact(String),
    /// `*.suffix`: matches names with one or more labels before `.suffix`.
    Wildcard(String),
}

/// Normalizes a DNS name: lowercase, no trailing dot; `None` if invalid.
pub fn normalize_name(name: &str) -> Option<String> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    ok.then_some(n)
}

impl FromStr for DomainPattern {
    type Err = BundleError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.strip_prefix("*.") {
            Some(rest) => normalize_name(rest)
                .map(DomainPattern::Wildcard)
                .ok_or_else(|| BundleError(format!("invalid wildcard {s:?}"))),
            None => normalize_name(s)
                .map(DomainPattern::Exact)
                .ok_or_else(|| BundleError(format!("invalid name {s:?}"))),
        }
    }
}

impl DomainPattern {
    /// Whether a normalized name matches.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            DomainPattern::Exact(n) => n == name,
            DomainPattern::Wildcard(suffix) => name
                .strip_suffix(suffix.as_str())
                .is_some_and(|head| head.len() > 1 && head.ends_with('.')),
        }
    }

    /// Whether every name this pattern matches is also matched by `outer`.
    pub fn within(&self, outer: &DomainPattern) -> bool {
        match (self, outer) {
            (DomainPattern::Exact(n), o) => o.matches(n),
            (DomainPattern::Wildcard(s), DomainPattern::Wildcard(o)) => {
                s == o || DomainPattern::Wildcard(o.clone()).matches(s)
            }
            (DomainPattern::Wildcard(_), DomainPattern::Exact(_)) => false,
        }
    }

    /// Specificity for ownership: exact names beat wildcards, longer
    /// wildcards beat shorter ones.
    fn specificity(&self) -> (u8, usize) {
        match self {
            DomainPattern::Exact(n) => (1, n.len()),
            DomainPattern::Wildcard(s) => (0, s.len()),
        }
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainPattern::Exact(n) => f.write_str(n),
            DomainPattern::Wildcard(s) => write!(f, "*.{s}"),
        }
    }
}

/// IP protocol numbers.
pub mod proto {
    /// ICMP.
    pub const ICMP: u8 = 1;
    /// TCP.
    pub const TCP: u8 = 6;
    /// UDP.
    pub const UDP: u8 = 17;
    /// ICMPv6.
    pub const ICMPV6: u8 = 58;
}

/// A protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoMatch {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP or ICMPv6.
    Icmp,
    /// Anything.
    Any,
}

impl ProtoMatch {
    /// Whether an IP protocol number matches.
    pub fn matches(self, p: u8) -> bool {
        match self {
            ProtoMatch::Tcp => p == proto::TCP,
            ProtoMatch::Udp => p == proto::UDP,
            ProtoMatch::Icmp => p == proto::ICMP || p == proto::ICMPV6,
            ProtoMatch::Any => true,
        }
    }

    /// The RFC 9484 route protocol number (0 for any).
    pub fn route_protocol(self) -> u8 {
        match self {
            ProtoMatch::Tcp => proto::TCP,
            ProtoMatch::Udp => proto::UDP,
            ProtoMatch::Icmp | ProtoMatch::Any => 0,
        }
    }
}

/// Where a destination points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestKind {
    /// A client-facing name; the connector resolves `target`.
    Name {
        /// The client-facing pattern.
        host: DomainPattern,
        /// What the connector reaches: an exact name or an address; `None`
        /// means the client-facing name itself.
        target: Option<String>,
    },
    /// Real addresses.
    Cidr(IpNet),
}

/// A compiled app destination.
#[derive(Debug, Clone)]
pub struct CompiledDest {
    /// Name or addresses.
    pub kind: DestKind,
    /// Inclusive port ranges; empty means any.
    pub ports: Vec<(u16, u16)>,
    /// Protocol.
    pub protocol: ProtoMatch,
}

impl CompiledDest {
    /// Whether a protocol and port match.
    pub fn admits(&self, protocol: u8, port: u16) -> bool {
        self.protocol.matches(protocol)
            && (self.ports.is_empty()
                || matches!(protocol, proto::ICMP | proto::ICMPV6)
                || self
                    .ports
                    .iter()
                    .any(|(lo, hi)| (*lo..=*hi).contains(&port)))
    }
}

/// A compiled app.
#[derive(Debug, Clone)]
pub struct CompiledApp {
    /// Name.
    pub name: String,
    /// Connector group.
    pub group: String,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// Destinations.
    pub destinations: Vec<CompiledDest>,
    /// Whether server-initiated flows are allowed.
    pub server_initiated_flows: bool,
    /// Whether it may be requested.
    pub discoverable: bool,
}

/// A compiled connector group.
#[derive(Debug, Clone)]
pub struct CompiledGroup {
    /// Enabled.
    pub enabled: bool,
    /// Destination CIDRs.
    pub dest_cidrs: Vec<IpNet>,
    /// Destination domains.
    pub dest_domains: Vec<DomainPattern>,
    /// Client-facing name scope.
    pub client_names: Vec<DomainPattern>,
}

impl CompiledGroup {
    /// Whether an address is inside the destination scope.
    pub fn address_in_scope(&self, ip: IpAddr) -> bool {
        self.dest_cidrs.iter().any(|n| n.contains(ip))
    }

    /// Whether a name is inside the destination scope.
    pub fn name_in_scope(&self, name: &str) -> bool {
        self.dest_domains.iter().any(|d| d.matches(name))
    }
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// `<policy>/<rule>`.
    pub id: String,
    /// Deny rules win.
    pub deny: bool,
    /// Users.
    pub users: HashSet<String>,
    /// Groups.
    pub groups: HashSet<String>,
    /// Apps by name.
    pub apps: HashSet<String>,
    /// Apps by labels.
    pub labels: Option<BTreeMap<String, String>>,
    /// Maximum authentication age.
    pub auth_max_age: Option<Duration>,
    /// Whether MFA is required.
    pub mfa: bool,
}

/// A validated, indexed bundle.
#[derive(Debug, Clone)]
pub struct CompiledBundle {
    /// Version.
    pub version: u64,
    /// Trust domain.
    pub trust_domain: String,
    /// Groups by name.
    pub groups: HashMap<String, CompiledGroup>,
    /// Apps by name.
    pub apps: BTreeMap<String, CompiledApp>,
    /// Users by ID.
    pub users: HashMap<String, User>,
    /// Device approval by ID.
    pub devices: HashMap<String, bool>,
    /// Rules in order.
    pub rules: Vec<CompiledRule>,
    revoked_users: HashSet<String>,
    revoked_devices: HashSet<String>,
    revoked_sessions: HashSet<String>,
    revoked_serials: HashSet<String>,
    revoked_nodes: HashSet<String>,
}

/// Parses a duration like `90s`, `5m`, `12h` or `1d`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = n.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        "d" => n.checked_mul(86_400)?,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

fn parse_ports(specs: &[PortSpec]) -> Result<Vec<(u16, u16)>, BundleError> {
    specs
        .iter()
        .map(|p| match p {
            PortSpec::Number(n) if *n > 0 => Ok((*n, *n)),
            PortSpec::Text(t) => {
                let (lo, hi) = t.split_once('-').unwrap_or((t, t));
                match (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                    (Ok(lo), Ok(hi)) if lo > 0 && lo <= hi => Ok((lo, hi)),
                    _ => err(format!("invalid port {t:?}")),
                }
            }
            PortSpec::Number(_) => err("port 0 is not a port"),
        })
        .collect()
}

impl Bundle {
    /// Loads and compiles a bundle file.
    pub fn load(path: &Path) -> Result<CompiledBundle, BundleError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| BundleError(format!("{}: {e}", path.display())))?;
        let raw: Bundle = serde_json::from_str(&text)
            .map_err(|e| BundleError(format!("{}: {e}", path.display())))?;
        raw.compile()
    }

    /// Validates and indexes the bundle.
    pub fn compile(self) -> Result<CompiledBundle, BundleError> {
        if !crate::identity::valid_trust_domain(&self.trust_domain) {
            return err(format!("invalid trust domain {:?}", self.trust_domain));
        }
        let mut groups = HashMap::new();
        for g in &self.connector_groups {
            if !valid_id(&g.name) {
                return err(format!("invalid group name {:?}", g.name));
            }
            let compiled = CompiledGroup {
                enabled: g.enabled,
                dest_cidrs: g
                    .destinations
                    .cidrs
                    .iter()
                    .map(|c| c.parse())
                    .collect::<Result<_, _>>()?,
                dest_domains: g
                    .destinations
                    .domains
                    .iter()
                    .map(|d| d.parse())
                    .collect::<Result<_, _>>()?,
                client_names: g
                    .client_names
                    .iter()
                    .map(|d| d.parse())
                    .collect::<Result<_, _>>()?,
            };
            if groups.insert(g.name.clone(), compiled).is_some() {
                return err(format!("duplicate group {}", g.name));
            }
        }
        let mut apps = BTreeMap::new();
        let mut claimed: Vec<(DomainPattern, String)> = Vec::new();
        for a in &self.apps {
            if !valid_id(&a.name) {
                return err(format!("invalid app name {:?}", a.name));
            }
            let Some(group) = groups.get(&a.connector_group) else {
                return err(format!(
                    "app {} names unknown group {}",
                    a.name, a.connector_group
                ));
            };
            let mut destinations = Vec::new();
            for d in &a.destinations {
                let protocol = match d.protocol.as_str() {
                    "tcp" => ProtoMatch::Tcp,
                    "udp" => ProtoMatch::Udp,
                    "icmp" => ProtoMatch::Icmp,
                    "any" => ProtoMatch::Any,
                    p => return err(format!("app {}: unknown protocol {p:?}", a.name)),
                };
                let kind = match (&d.host, &d.cidr) {
                    (Some(h), None) => {
                        let host: DomainPattern = h.parse()?;
                        if !group.client_names.iter().any(|s| host.within(s)) {
                            return err(format!(
                                "app {}: host {host} is outside the group's client names",
                                a.name
                            ));
                        }
                        let target = match (&host, &d.target) {
                            (DomainPattern::Wildcard(_), Some(_)) => {
                                return err(format!(
                                    "app {}: a wildcard host cannot set a target",
                                    a.name
                                ));
                            }
                            (_, Some(t)) => Some(check_target(t, group, &a.name)?),
                            (DomainPattern::Exact(n), None) => {
                                if !group.name_in_scope(n) {
                                    return err(format!(
                                        "app {}: {n} is outside the group's destinations",
                                        a.name
                                    ));
                                }
                                None
                            }
                            (DomainPattern::Wildcard(_), None) => {
                                if !group.dest_domains.iter().any(|s| host.within(s)) {
                                    return err(format!(
                                        "app {}: {host} is outside the group's destinations",
                                        a.name
                                    ));
                                }
                                None
                            }
                        };
                        if let Some((_, owner)) =
                            claimed.iter().find(|(p, o)| *p == host && *o != a.name)
                        {
                            return err(format!(
                                "app {}: host {host} is already claimed by {owner}",
                                a.name
                            ));
                        }
                        claimed.push((host.clone(), a.name.clone()));
                        DestKind::Name { host, target }
                    }
                    (None, Some(c)) => {
                        let net: IpNet = c.parse()?;
                        if !group.dest_cidrs.iter().any(|g| g.covers(&net)) {
                            return err(format!(
                                "app {}: {net} is outside the group's destinations",
                                a.name
                            ));
                        }
                        DestKind::Cidr(net)
                    }
                    _ => {
                        return err(format!(
                            "app {}: each destination needs exactly one of host and cidr",
                            a.name
                        ));
                    }
                };
                destinations.push(CompiledDest {
                    kind,
                    ports: parse_ports(&d.ports)?,
                    protocol,
                });
            }
            let app = CompiledApp {
                name: a.name.clone(),
                group: a.connector_group.clone(),
                labels: a.labels.clone(),
                destinations,
                server_initiated_flows: a.server_initiated_flows,
                discoverable: a.discoverable,
            };
            if apps.insert(a.name.clone(), app).is_some() {
                return err(format!("duplicate app {}", a.name));
            }
        }
        let mut rules = Vec::new();
        for r in &self.rules {
            let deny = match r.effect.as_str() {
                "allow" => false,
                "deny" => true,
                e => return err(format!("rule {}: unknown effect {e:?}", r.id)),
            };
            if r.who.users.is_empty() && r.who.groups.is_empty() {
                return err(format!(
                    "rule {}: who needs users or groups; there is no implicit everyone",
                    r.id
                ));
            }
            if let Some(unknown) = r.what.apps.iter().find(|a| !apps.contains_key(*a)) {
                return err(format!("rule {}: unknown app {unknown}", r.id));
            }
            if r.what
                .app_selector
                .as_ref()
                .is_some_and(|s| s.match_labels.is_empty())
            {
                return err(format!(
                    "rule {}: appSelector needs matchLabels; an empty selector would match every app",
                    r.id
                ));
            }
            if deny && r.when.auth.is_some() {
                return err(format!(
                    "rule {}: a deny rule cannot have when conditions; it always applies",
                    r.id
                ));
            }
            let auth = r.when.auth.clone().unwrap_or_default();
            let auth_max_age =
                match &auth.max_age {
                    Some(s) => Some(parse_duration(s).ok_or_else(|| {
                        BundleError(format!("rule {}: invalid maxAge {s:?}", r.id))
                    })?),
                    None => None,
                };
            rules.push(CompiledRule {
                id: r.id.clone(),
                deny,
                users: r.who.users.iter().cloned().collect(),
                groups: r.who.groups.iter().cloned().collect(),
                apps: r.what.apps.iter().cloned().collect(),
                labels: r.what.app_selector.as_ref().map(|s| s.match_labels.clone()),
                auth_max_age,
                mfa: auth.mfa,
            });
        }
        let mut revoked_serials = HashSet::new();
        for s in &self.revoked.serials {
            if s.is_empty() || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
                return err(format!(
                    "revoked serial {s:?} must be plain hex digits, without separators"
                ));
            }
            let digits = s.trim_start_matches('0').to_ascii_lowercase();
            revoked_serials.insert(if digits.len() % 2 == 1 {
                format!("0{digits}")
            } else {
                digits
            });
        }
        Ok(CompiledBundle {
            version: self.version,
            trust_domain: self.trust_domain,
            groups,
            apps,
            users: self.users.into_iter().map(|u| (u.id.clone(), u)).collect(),
            devices: self
                .devices
                .into_iter()
                .map(|d| (d.id, d.approved))
                .collect(),
            rules,
            revoked_users: self.revoked.users.into_iter().collect(),
            revoked_devices: self.revoked.devices.into_iter().collect(),
            revoked_sessions: self.revoked.sessions.into_iter().collect(),
            revoked_serials,
            revoked_nodes: self.revoked.nodes.into_iter().collect(),
        })
    }
}

fn check_target(t: &str, group: &CompiledGroup, app: &str) -> Result<String, BundleError> {
    if let Ok(ip) = t.parse::<IpAddr>() {
        if !group.address_in_scope(ip) {
            return err(format!(
                "app {app}: target {ip} is outside the group's destinations"
            ));
        }
        return Ok(ip.to_string());
    }
    let name =
        normalize_name(t).ok_or_else(|| BundleError(format!("app {app}: invalid target {t:?}")))?;
    if !group.name_in_scope(&name) {
        return err(format!(
            "app {app}: target {name} is outside the group's destinations"
        ));
    }
    Ok(name)
}

impl CompiledBundle {
    /// The app that owns a client-facing name across the deployment: an
    /// exact host first, otherwise the most specific matching wildcard.
    pub fn owning_app(&self, name: &str) -> Option<&CompiledApp> {
        let mut best: Option<(&CompiledApp, (u8, usize))> = None;
        for app in self.apps.values() {
            for d in &app.destinations {
                if let DestKind::Name { host, .. } = &d.kind
                    && host.matches(name)
                {
                    let s = host.specificity();
                    if best.is_none_or(|(_, b)| s > b) {
                        best = Some((app, s));
                    }
                }
            }
        }
        best.map(|(a, _)| a)
    }

    /// The groups a user belongs to.
    pub fn user_groups(&self, user: &str) -> &[String] {
        self.users
            .get(user)
            .map(|u| u.groups.as_slice())
            .unwrap_or(&[])
    }

    /// Whether a device is approved.
    pub fn device_approved(&self, device: &str) -> bool {
        self.devices.get(device).copied().unwrap_or(false)
    }

    /// Why a client is revoked, if it is.
    pub fn client_revocation(&self, id: &ClientIdentity) -> Option<String> {
        if self.revoked_users.contains(&id.user)
            || self.users.get(&id.user).is_some_and(|u| !u.enabled)
        {
            return Some(format!("user {} is disabled", id.user));
        }
        if self.revoked_devices.contains(&id.device) {
            return Some(format!("device {} is revoked", id.device));
        }
        if self.revoked_sessions.contains(&id.identity.session_id) {
            return Some("the sign-in session is revoked".into());
        }
        if self.revoked_serials.contains(&id.serial) {
            return Some("the certificate is revoked".into());
        }
        None
    }

    /// Why a node is revoked or disabled, if it is.
    pub fn node_revocation(&self, id: &NodeIdentity) -> Option<String> {
        let key = format!("{}/{}", id.role, id.id);
        if self.revoked_nodes.contains(&key) || self.revoked_serials.contains(&id.serial) {
            return Some(format!("node {key} is revoked"));
        }
        if let NodeRole::Connector { group } = &id.role {
            match self.groups.get(group) {
                Some(g) if g.enabled => {}
                Some(_) => return Some(format!("connector group {group} is disabled")),
                None => return Some(format!("connector group {group} is unknown")),
            }
        }
        None
    }
}

/// The current bundle, shared and swappable on reload.
#[derive(Debug)]
pub struct NodeState {
    current: RwLock<Arc<CompiledBundle>>,
}

impl NodeState {
    /// Wraps a compiled bundle.
    pub fn new(bundle: CompiledBundle) -> Arc<NodeState> {
        Arc::new(NodeState {
            current: RwLock::new(Arc::new(bundle)),
        })
    }

    /// The current bundle.
    pub fn get(&self) -> Arc<CompiledBundle> {
        self.current.read().expect("bundle lock").clone()
    }

    /// Replaces the bundle; versions only increase.
    pub fn replace(&self, bundle: CompiledBundle) -> Result<(), BundleError> {
        let mut cur = self.current.write().expect("bundle lock");
        if bundle.version < cur.version {
            return err(format!(
                "bundle version {} is older than the current {}",
                bundle.version, cur.version
            ));
        }
        if bundle.trust_domain != cur.trust_domain {
            return err("a bundle cannot change the trust domain");
        }
        *cur = Arc::new(bundle);
        Ok(())
    }
}

impl RevocationCheck for NodeState {
    fn check_client(&self, id: &ClientIdentity) -> Result<(), CertError> {
        match self.get().client_revocation(id) {
            Some(why) => Err(CertError::Revoked(why)),
            None => Ok(()),
        }
    }

    fn check_node(&self, id: &NodeIdentity) -> Result<(), CertError> {
        match self.get().node_revocation(id) {
            Some(why) => Err(CertError::Revoked(why)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(apps: &str) -> Result<CompiledBundle, BundleError> {
        bundle_with(apps, "")
    }

    fn bundle_with(apps: &str, extra: &str) -> Result<CompiledBundle, BundleError> {
        let text = format!(
            r#"{{
              "version": 1,
              "trustDomain": "example.test",
              "connectorGroups": [{{
                "name": "homelab",
                "destinations": {{ "domains": ["*.lab.example.com", "nas.example.internal"], "cidrs": ["10.20.0.0/16", "fd00:20::/48"] }},
                "clientNames": ["*.lab.example.com", "*.access.example.com"]
              }}],
              "apps": {apps}{extra}
            }}"#
        );
        serde_json::from_str::<Bundle>(&text).unwrap().compile()
    }

    #[test]
    fn owning_app_prefers_exact_then_longest_wildcard() {
        let b = bundle(
            r#"[
              {"name": "lab-web", "connectorGroup": "homelab",
               "destinations": [{"host": "*.lab.example.com", "ports": [80, 443], "protocol": "tcp"}]},
              {"name": "grafana", "connectorGroup": "homelab",
               "destinations": [{"host": "grafana.lab.example.com", "ports": ["443"], "protocol": "tcp"}]},
              {"name": "deep", "connectorGroup": "homelab",
               "destinations": [{"host": "*.deep.lab.example.com", "protocol": "any"}]}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            b.owning_app("grafana.lab.example.com").unwrap().name,
            "grafana"
        );
        assert_eq!(
            b.owning_app("wiki.lab.example.com").unwrap().name,
            "lab-web"
        );
        assert_eq!(b.owning_app("x.deep.lab.example.com").unwrap().name, "deep");
        assert!(b.owning_app("lab.example.com").is_none());
        assert!(b.owning_app("other.example.com").is_none());
    }

    #[test]
    fn scopes_and_conflicts_are_enforced() {
        let bad = [
            r#"[{"name": "a", "connectorGroup": "homelab", "destinations": [{"cidr": "10.30.0.0/24", "protocol": "tcp"}]}]"#,
            r#"[{"name": "a", "connectorGroup": "homelab", "destinations": [{"host": "x.other.com", "protocol": "tcp"}]}]"#,
            r#"[{"name": "a", "connectorGroup": "homelab", "destinations": [{"host": "x.access.example.com", "target": "1.1.1.1", "protocol": "tcp"}]}]"#,
            r#"[{"name": "a", "connectorGroup": "homelab", "destinations": [{"host": "x.access.example.com", "protocol": "tcp"}]}]"#,
            r#"[{"name": "a", "connectorGroup": "nope", "destinations": [{"cidr": "10.20.0.0/24", "protocol": "tcp"}]}]"#,
            r#"[{"name": "a", "connectorGroup": "homelab", "destinations": [{"cidr": "10.20.0.1/24", "protocol": "tcp"}]}]"#,
            r#"[{"name": "a", "connectorGroup": "homelab", "destinations": [{"cidr": "10.20.0.0/24", "ports": ["9-1"], "protocol": "tcp"}]}]"#,
            r#"[{"name": "a", "connectorGroup": "homelab", "destinations": [{"host": "g.lab.example.com", "protocol": "tcp"}]},
                {"name": "b", "connectorGroup": "homelab", "destinations": [{"host": "g.lab.example.com", "protocol": "tcp"}]}]"#,
        ];
        for apps in bad {
            assert!(bundle(apps).is_err(), "{apps}");
        }
        let ok = r#"[{"name": "nas", "connectorGroup": "homelab",
            "destinations": [{"host": "files.access.example.com", "target": "nas.example.internal", "protocol": "tcp"},
                             {"cidr": "fd00:20::/64", "protocol": "icmp"}]}]"#;
        assert!(bundle(ok).is_ok());
    }

    #[test]
    fn empty_selectors_and_conditional_denies_are_rejected() {
        let apps = r#"[{"name": "grafana", "connectorGroup": "homelab", "labels": {"env": "prod"},
            "destinations": [{"host": "grafana.lab.example.com", "protocol": "tcp"}]}]"#;
        let rules = |r: &str| bundle_with(apps, &format!(r#", "rules": [{r}]"#));
        for bad in [
            r#"{"id": "p/a", "who": {"groups": ["eng"]}, "what": {"appSelector": {"matchLabels": {}}}}"#,
            r#"{"id": "p/a", "who": {"groups": ["eng"]}, "what": {"appSelector": {}}}"#,
            r#"{"id": "p/d", "effect": "deny", "who": {"groups": ["eng"]}, "what": {"apps": ["grafana"]},
                "when": {"auth": {"mfa": true}}}"#,
        ] {
            assert!(rules(bad).is_err(), "{bad}");
        }
        for ok in [
            r#"{"id": "p/a", "who": {"groups": ["eng"]}, "what": {"appSelector": {"matchLabels": {"env": "prod"}}},
                "when": {"auth": {"mfa": true}}}"#,
            r#"{"id": "p/d", "effect": "deny", "who": {"groups": ["eng"]}, "what": {"apps": ["grafana"]}}"#,
        ] {
            assert!(rules(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn revoked_serials_match_certificate_rendering() {
        let serials = |s: &str| bundle_with("[]", &format!(r#", "revoked": {{"serials": [{s}]}}"#));
        let b = serials(r#""008A01FF", "4B0c", "0abc", "000c""#).unwrap();
        for s in ["8a01ff", "4b0c", "0abc", "0c"] {
            assert!(b.revoked_serials.contains(s), "{s}");
        }
        for bad in [r#""00:8a:01""#, r#""""#, r#""0x8a01""#, r#""8a 01""#] {
            assert!(serials(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nets_and_patterns() {
        let n: IpNet = "10.20.0.0/16".parse().unwrap();
        assert!(n.contains("10.20.255.1".parse().unwrap()));
        assert!(!n.contains("10.21.0.1".parse().unwrap()));
        assert!(!n.contains("fd00::1".parse().unwrap()));
        assert!(n.covers(&"10.20.4.0/24".parse().unwrap()));
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        let w: DomainPattern = "*.svc.cluster.local".parse().unwrap();
        assert!(w.matches("grafana.observability.svc.cluster.local"));
        assert!(!w.matches("svc.cluster.local"));
        assert!(!w.matches("xsvc.cluster.local"));
        assert_eq!(parse_duration("12h"), Some(Duration::from_secs(43_200)));
        assert_eq!(parse_duration("h"), None);
    }
}
