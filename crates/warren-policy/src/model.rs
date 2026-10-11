//! The policy surface's objects (docs/policy.md sections 1 to 6), read from
//! YAML documents with every problem reported against its file and line.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use warren_core::identity::is_valid_name;
use warren_core::policy_bundle::PortRange;

use crate::names::{Cidr, DomainPattern};
use crate::yaml::{self, Node, Value};

/// The API version every object must declare. The group name is
/// provisional until v1.0.
pub const API_VERSION: &str = "warren.dev/v1alpha1";

/// How serious a diagnostic is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The policy set is rejected.
    Error,
    /// The policy set compiles, but something is probably not what the
    /// author meant.
    Warning,
}

/// A problem found while reading or compiling policy, located at the file
/// and line that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Error or warning.
    pub severity: Severity,
    /// The file, relative to the policy directory.
    pub file: String,
    /// 1-based line.
    pub line: usize,
    /// What is wrong, in words.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{}:{}: {level}: {}", self.file, self.line, self.message)
    }
}

/// Where an object or rule was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The file, relative to the policy directory.
    pub file: String,
    /// 1-based line.
    pub line: usize,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// Every object's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// The object's name, unique within its kind.
    pub name: String,
    /// Its labels.
    pub labels: BTreeMap<String, String>,
    /// Where it was written.
    pub source: Source,
}

/// A `ConnectorGroup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorGroup {
    /// Metadata.
    pub meta: Meta,
    /// Domains its apps may target.
    pub destination_domains: Vec<DomainPattern>,
    /// Address ranges its apps may target.
    pub destination_cidrs: Vec<Cidr>,
    /// Names clients may use for its apps.
    pub client_names: Vec<DomainPattern>,
    /// The relays its connectors attach to; `None` for every relay.
    pub relays: Option<Vec<String>>,
}

/// A transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP and ICMPv6.
    Icmp,
    /// Any protocol.
    Any,
}

impl Protocol {
    /// The protocol's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Any => "any",
        }
    }
}

/// What a connector reaches for an exact host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A name the connector resolves.
    Name(String),
    /// An address.
    Addr(IpAddr),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Name(n) => f.write_str(n),
            Target::Addr(a) => write!(f, "{a}"),
        }
    }
}

/// Where an app destination points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationKind {
    /// A client-facing host name, with an optional separate target.
    Host {
        /// The client-facing name.
        host: DomainPattern,
        /// What the connector reaches, if not the host itself.
        target: Option<Target>,
    },
    /// An address range, used as-is end to end.
    Cidr(Cidr),
}

/// One destination of an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Host or range.
    pub kind: DestinationKind,
    /// Protocol.
    pub protocol: Protocol,
    /// Port ranges; empty means every port.
    pub ports: Vec<PortRange>,
    /// 1-based line.
    pub line: usize,
}

/// An app's clientless (browser) access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clientless {
    /// The client-facing host of the URL users open.
    pub url_host: DomainPattern,
    /// The URL users open.
    pub url: String,
    /// The host of the URL the connector forwards to.
    pub upstream_host: String,
    /// The URL the connector forwards to.
    pub upstream: String,
    /// 1-based line.
    pub line: usize,
}

/// An `App`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    /// Metadata.
    pub meta: Meta,
    /// The connector group serving it.
    pub connector_group: String,
    /// Its destinations.
    pub destinations: Vec<Destination>,
    /// Visible to users who may request it.
    pub discoverable: bool,
    /// Whether servers may open flows toward clients.
    pub server_initiated_flows: bool,
    /// Clientless access, if enabled.
    pub clientless: Option<Clientless>,
}

/// One posture check's signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// Disk encryption (FileVault).
    DiskEncryption,
    /// The firewall is on.
    Firewall,
    /// The OS version is at least this, encoded as `major * 10000 + minor *
    /// 100 + patch`.
    OsVersion(i64),
    /// Screen lock is on, with at most this many seconds of idle time if
    /// given.
    ScreenLock(Option<i64>),
    /// The device is enrolled in MDM.
    MdmEnrolled,
    /// The named security agent is running.
    SecurityAgent(String),
}

impl Signal {
    /// The signal's name in the schema.
    pub fn name(&self) -> &'static str {
        match self {
            Signal::DiskEncryption => "diskEncryption",
            Signal::Firewall => "firewall",
            Signal::OsVersion(_) => "osVersion",
            Signal::ScreenLock(_) => "screenLock",
            Signal::MdmEnrolled => "mdmEnrolled",
            Signal::SecurityAgent(_) => "securityAgent",
        }
    }
}

/// One check of a posture profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// The signal and its threshold.
    pub signal: Signal,
    /// The minimum trust class, 1 to 3.
    pub min_trust: u8,
    /// Text shown to the user when the check blocks them.
    pub remediation: Option<String>,
    /// 1-based line.
    pub line: usize,
}

/// A `PostureProfile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureProfile {
    /// Metadata.
    pub meta: Meta,
    /// The platform: `macos` in v1.
    pub platform: String,
    /// The checks, all of which must pass.
    pub checks: Vec<Check>,
}

/// Who a rule is about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Who {
    /// IdP subject identifiers or email addresses.
    pub users: Vec<String>,
    /// IdP groups.
    pub groups: Vec<String>,
}

/// What a rule is about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct What {
    /// Apps by name.
    pub apps: Vec<String>,
    /// Apps whose labels include all of these.
    pub match_labels: BTreeMap<String, String>,
    /// 1-based line.
    pub line: usize,
}

/// Authentication freshness.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Auth {
    /// Longest time since the IdP sign-in, seconds.
    pub max_age: Option<i64>,
    /// Whether that sign-in must have used MFA.
    pub mfa: bool,
}

/// How a session reaches the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The device tunnel.
    Client,
    /// Clientless, in a browser.
    Browser,
}

/// A weekly time window, in minutes since Sunday 00:00 in the schedule's
/// time zone: `from` inclusive, `to` exclusive, possibly wrapping past
/// Saturday midnight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeekRange {
    /// Start minute.
    pub from: i64,
    /// End minute.
    pub to: i64,
}

/// A schedule condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    /// An IANA time zone name, or `UTC`.
    pub timezone: String,
    /// The allowed ranges.
    pub ranges: Vec<WeekRange>,
    /// The windows as written, for messages.
    pub text: String,
}

/// A rule's conditions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct When {
    /// Posture profiles that must all pass.
    pub posture: Vec<String>,
    /// Authentication freshness.
    pub auth: Auth,
    /// How the session may arrive; `None` when not written.
    pub via: Option<Vec<Via>>,
    /// Weekly windows.
    pub schedule: Option<Schedule>,
    /// Source networks, relay-observed.
    pub network: Vec<Cidr>,
    /// 1-based line.
    pub line: usize,
}

/// A rule of an `AccessPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The rule's name, unique within its policy.
    pub name: String,
    /// True for `effect: deny`.
    pub deny: bool,
    /// Who.
    pub who: Who,
    /// What.
    pub what: What,
    /// Conditions.
    pub when: When,
    /// 1-based line.
    pub line: usize,
}

/// An `AccessPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPolicy {
    /// Metadata.
    pub meta: Meta,
    /// Its rules.
    pub rules: Vec<Rule>,
}

/// An `AccessRequestPolicy`: just-in-time access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequestPolicy {
    /// Metadata.
    pub meta: Meta,
    /// Who may request.
    pub who: Who,
    /// What they may request.
    pub what: What,
    /// Who approves.
    pub approvers: Who,
    /// How many approvals a request needs.
    pub min_approvals: u32,
    /// Conditions under which requests are approved without a human.
    pub automatic: Option<When>,
    /// Whether a request must give a reason.
    pub require_reason: bool,
    /// Longest grant, seconds.
    pub max_duration: i64,
    /// Default grant, seconds.
    pub default_duration: i64,
    /// Conditions that must hold to request and for the whole grant.
    pub when: When,
}

/// Every object read from a policy directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Objects {
    /// Connector groups.
    pub groups: Vec<ConnectorGroup>,
    /// Apps.
    pub apps: Vec<App>,
    /// Posture profiles.
    pub profiles: Vec<PostureProfile>,
    /// Access policies.
    pub policies: Vec<AccessPolicy>,
    /// Access request policies.
    pub request_policies: Vec<AccessRequestPolicy>,
}

/// Reads every `.yaml` and `.yml` file under `dir`, recursively, in sorted
/// path order. File names in diagnostics and sources are relative to `dir`.
pub fn load_dir(dir: &Path) -> Result<(Objects, Vec<Diagnostic>), std::io::Error> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    files.sort();
    let mut objects = Objects::default();
    let mut diags = Vec::new();
    for (rel, path) in files {
        let text = std::fs::read_to_string(&path)?;
        parse_file(&rel, &text, &mut objects, &mut diags);
    }
    Ok((objects, diags))
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, std::path::PathBuf)>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        if entry.file_type()?.is_dir() {
            collect_files(root, &path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml")
        ) {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

/// Reads the objects in one YAML file into `out`.
pub fn parse_file(file: &str, text: &str, out: &mut Objects, diags: &mut Vec<Diagnostic>) {
    let mut ctx = Ctx { file, diags };
    let docs = match yaml::parse_documents(text) {
        Ok(docs) => docs,
        Err(e) => {
            ctx.error(e.line, format!("YAML: {}", e.message));
            return;
        }
    };
    for doc in &docs {
        parse_object(&mut ctx, doc, out);
    }
}

struct Ctx<'a> {
    file: &'a str,
    diags: &'a mut Vec<Diagnostic>,
}

type Fields<'n> = BTreeMap<&'n str, &'n Node>;

impl Ctx<'_> {
    fn push(&mut self, severity: Severity, line: usize, message: String) {
        self.diags.push(Diagnostic {
            severity,
            file: self.file.to_owned(),
            line,
            message,
        });
    }

    fn error(&mut self, line: usize, message: impl Into<String>) {
        self.push(Severity::Error, line, message.into());
    }

    fn warn(&mut self, line: usize, message: impl Into<String>) {
        self.push(Severity::Warning, line, message.into());
    }

    fn source(&self, line: usize) -> Source {
        Source {
            file: self.file.to_owned(),
            line,
        }
    }

    /// The fields of a mapping, refusing keys outside `allowed`.
    fn fields<'n>(&mut self, node: &'n Node, what: &str, allowed: &[&str]) -> Option<Fields<'n>> {
        let Value::Map(entries) = &node.value else {
            self.error(
                node.line,
                format!("{what} must be a mapping, not {}", node.kind()),
            );
            return None;
        };
        let mut out = BTreeMap::new();
        for (key, value) in entries {
            if allowed.contains(&key.as_str()) {
                out.insert(key.as_str(), value);
            } else {
                self.error(
                    value.line,
                    format!(
                        "unknown field {key:?} in {what}; expected one of: {}",
                        allowed.join(", ")
                    ),
                );
            }
        }
        Some(out)
    }

    fn string(&mut self, node: &Node, what: &str) -> Option<String> {
        match &node.value {
            Value::Scalar { text, .. } if !node.is_null() => Some(text.clone()),
            _ => {
                self.error(
                    node.line,
                    format!("{what} must be a string, not {}", node.kind()),
                );
                None
            }
        }
    }

    fn name(&mut self, node: &Node, what: &str) -> Option<String> {
        let s = self.string(node, what)?;
        if is_valid_name(&s) {
            Some(s)
        } else {
            self.error(
                node.line,
                format!(
                    "{what} {s:?} must be 1 to 63 lowercase letters, digits and '-', \
                     starting and ending with a letter or digit"
                ),
            );
            None
        }
    }

    fn boolean(&mut self, node: &Node, what: &str) -> Option<bool> {
        match &node.value {
            Value::Scalar { text, plain: true } if text == "true" => Some(true),
            Value::Scalar { text, plain: true } if text == "false" => Some(false),
            _ => {
                self.error(node.line, format!("{what} must be true or false"));
                None
            }
        }
    }

    fn integer(&mut self, node: &Node, what: &str) -> Option<i64> {
        match &node.value {
            Value::Scalar { text, plain: true } => match text.parse::<i64>() {
                Ok(n) => Some(n),
                Err(_) => {
                    self.error(node.line, format!("{what} must be a whole number"));
                    None
                }
            },
            _ => {
                self.error(node.line, format!("{what} must be a whole number"));
                None
            }
        }
    }

    fn list<'n>(&mut self, node: &'n Node, what: &str) -> Option<&'n [Node]> {
        match &node.value {
            Value::Seq(items) => Some(items),
            _ => {
                self.error(
                    node.line,
                    format!("{what} must be a list, not {}", node.kind()),
                );
                None
            }
        }
    }

    fn strings(&mut self, node: &Node, what: &str) -> Vec<(String, usize)> {
        let Some(items) = self.list(node, what) else {
            return Vec::new();
        };
        items
            .iter()
            .filter_map(|item| self.string(item, what).map(|s| (s, item.line)))
            .collect()
    }

    fn duration(&mut self, node: &Node, what: &str) -> Option<i64> {
        let text = self.string(node, what)?;
        match parse_duration(&text) {
            Some(secs) if secs > 0 => Some(secs),
            _ => {
                self.error(
                    node.line,
                    format!("{what} {text:?} must be a duration such as 90s, 5m, 12h or 1h30m"),
                );
                None
            }
        }
    }
}

/// Parses a duration such as `90s`, `5m`, `12h`, `1h30m` or `7d` into
/// seconds.
pub fn parse_duration(text: &str) -> Option<i64> {
    let mut total: i64 = 0;
    let mut digits = String::new();
    let mut any = false;
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => return None,
        };
        let n: i64 = digits.parse().ok()?;
        total = total.checked_add(n.checked_mul(unit)?)?;
        digits.clear();
        any = true;
    }
    if !digits.is_empty() || !any {
        return None;
    }
    Some(total)
}

fn parse_object(ctx: &mut Ctx<'_>, doc: &Node, out: &mut Objects) {
    let Some(f) = ctx.fields(
        doc,
        "an object",
        &["apiVersion", "kind", "metadata", "spec"],
    ) else {
        return;
    };
    match f.get("apiVersion") {
        Some(v) => {
            if let Some(api) = ctx.string(v, "apiVersion")
                && api != API_VERSION
            {
                ctx.error(
                    v.line,
                    format!("apiVersion must be {API_VERSION}, not {api:?}"),
                );
                return;
            }
        }
        None => {
            ctx.error(
                doc.line,
                format!("missing apiVersion (expected {API_VERSION})"),
            );
            return;
        }
    }
    let Some(kind) = f.get("kind").and_then(|k| ctx.string(k, "kind")) else {
        ctx.error(doc.line, "missing kind");
        return;
    };
    let Some(meta) = f.get("metadata").and_then(|m| parse_meta(ctx, m)) else {
        if !f.contains_key("metadata") {
            ctx.error(doc.line, "missing metadata");
        }
        return;
    };
    let empty = Node {
        value: Value::Map(Vec::new()),
        line: doc.line,
    };
    let spec = f.get("spec").copied().unwrap_or(&empty);
    match kind.as_str() {
        "ConnectorGroup" => {
            if let Some(g) = parse_group(ctx, meta, spec) {
                out.groups.push(g);
            }
        }
        "App" => {
            if let Some(a) = parse_app(ctx, meta, spec) {
                out.apps.push(a);
            }
        }
        "PostureProfile" => {
            if let Some(p) = parse_profile(ctx, meta, spec) {
                out.profiles.push(p);
            }
        }
        "AccessPolicy" => {
            if let Some(p) = parse_access_policy(ctx, meta, spec) {
                out.policies.push(p);
            }
        }
        "AccessRequestPolicy" => {
            if let Some(p) = parse_request_policy(ctx, meta, spec) {
                out.request_policies.push(p);
            }
        }
        other => ctx.error(
            doc.line,
            format!(
                "unknown kind {other:?}; expected ConnectorGroup, App, PostureProfile, \
                 AccessPolicy or AccessRequestPolicy"
            ),
        ),
    }
}

fn valid_label(key: &str, value: &str) -> bool {
    let key_ok = !key.is_empty()
        && key.len() <= 253
        && key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'/'));
    let value_ok = value.len() <= 63
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'));
    key_ok && value_ok
}

fn parse_meta(ctx: &mut Ctx<'_>, node: &Node) -> Option<Meta> {
    let f = ctx.fields(node, "metadata", &["name", "labels"])?;
    let name = match f.get("name") {
        Some(n) => ctx.name(n, "metadata.name")?,
        None => {
            ctx.error(node.line, "metadata.name is required");
            return None;
        }
    };
    let mut labels = BTreeMap::new();
    if let Some(l) = f.get("labels") {
        if let Value::Map(entries) = &l.value {
            for (key, value) in entries {
                let Some(value_text) = ctx.string(value, "a label value") else {
                    continue;
                };
                if valid_label(key, &value_text) {
                    labels.insert(key.clone(), value_text);
                } else {
                    ctx.error(
                        value.line,
                        format!(
                            "label {key}={value_text} must use letters, digits, '-', '_' and '.' \
                             (and '/' in keys), with values of at most 63 characters"
                        ),
                    );
                }
            }
        } else if !l.is_null() {
            ctx.error(l.line, "metadata.labels must be a mapping");
        }
    }
    Some(Meta {
        name,
        labels,
        source: ctx.source(node.line),
    })
}

fn domains(ctx: &mut Ctx<'_>, node: &Node, what: &str) -> Vec<DomainPattern> {
    ctx.strings(node, what)
        .into_iter()
        .filter_map(|(s, line)| match DomainPattern::parse(&s) {
            Ok(d) => Some(d),
            Err(e) => {
                ctx.error(line, e);
                None
            }
        })
        .collect()
}

fn cidrs(ctx: &mut Ctx<'_>, node: &Node, what: &str) -> Vec<Cidr> {
    ctx.strings(node, what)
        .into_iter()
        .filter_map(|(s, line)| match Cidr::parse(&s) {
            Ok(c) => Some(c),
            Err(e) => {
                ctx.error(line, e);
                None
            }
        })
        .collect()
}

fn parse_group(ctx: &mut Ctx<'_>, meta: Meta, spec: &Node) -> Option<ConnectorGroup> {
    let f = ctx.fields(
        spec,
        "ConnectorGroup spec",
        &["destinations", "clientNames", "relays"],
    )?;
    let mut group = ConnectorGroup {
        meta,
        destination_domains: Vec::new(),
        destination_cidrs: Vec::new(),
        client_names: Vec::new(),
        relays: None,
    };
    if let Some(d) = f.get("destinations")
        && let Some(df) = ctx.fields(d, "destinations", &["domains", "cidrs"])
    {
        if let Some(n) = df.get("domains") {
            group.destination_domains = domains(ctx, n, "destinations.domains");
        }
        if let Some(n) = df.get("cidrs") {
            group.destination_cidrs = cidrs(ctx, n, "destinations.cidrs");
        }
    }
    if let Some(n) = f.get("clientNames") {
        group.client_names = domains(ctx, n, "clientNames");
    }
    if let Some(r) = f.get("relays") {
        match &r.value {
            Value::Scalar { text, .. } if text == "all" => {}
            Value::Seq(_) => {
                let names = ctx.strings(r, "relays");
                group.relays = Some(names.into_iter().map(|(s, _)| s).collect());
            }
            _ => ctx.error(r.line, "relays must be \"all\" or a list of relay names"),
        }
    }
    Some(group)
}

fn parse_ports(ctx: &mut Ctx<'_>, node: &Node) -> Vec<PortRange> {
    let Some(items) = ctx.list(node, "ports") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let Value::Scalar { text, .. } = &item.value else {
            ctx.error(
                item.line,
                "a port must be a number or a range such as \"8000-8100\"",
            );
            continue;
        };
        let parse = |s: &str| s.trim().parse::<u16>().ok().filter(|p| *p > 0);
        let range = match text.split_once('-') {
            Some((a, b)) => parse(a).zip(parse(b)).filter(|(a, b)| a <= b),
            None => parse(text).map(|p| (p, p)),
        };
        match range {
            Some((from, to)) => out.push(PortRange { from, to }),
            None => ctx.error(
                item.line,
                format!("{text:?} is not a port (1 to 65535) or an ascending port range"),
            ),
        }
    }
    out
}

fn parse_destination(ctx: &mut Ctx<'_>, node: &Node) -> Option<Destination> {
    let f = ctx.fields(
        node,
        "a destination",
        &["host", "target", "cidr", "ports", "protocol"],
    )?;
    let protocol = match f.get("protocol") {
        Some(p) => match ctx.string(p, "protocol")?.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            "any" => Protocol::Any,
            other => {
                ctx.error(
                    p.line,
                    format!("protocol {other:?} must be tcp, udp, icmp or any"),
                );
                return None;
            }
        },
        None => {
            ctx.error(
                node.line,
                "a destination needs a protocol: tcp, udp, icmp or any",
            );
            return None;
        }
    };
    let ports = match f.get("ports") {
        Some(p) if matches!(protocol, Protocol::Icmp | Protocol::Any) => {
            ctx.error(
                p.line,
                format!("ports cannot be set for protocol {}", protocol.as_str()),
            );
            Vec::new()
        }
        Some(p) => parse_ports(ctx, p),
        None => {
            if matches!(protocol, Protocol::Tcp | Protocol::Udp) {
                ctx.warn(
                    node.line,
                    format!(
                        "no ports listed, so every {} port is reachable",
                        protocol.as_str()
                    ),
                );
            }
            Vec::new()
        }
    };
    let kind = match (f.get("host"), f.get("cidr")) {
        (Some(h), None) => {
            let text = ctx.string(h, "host")?;
            let host = match DomainPattern::parse(&text) {
                Ok(d) => d,
                Err(e) => {
                    ctx.error(h.line, e);
                    return None;
                }
            };
            let target = match f.get("target") {
                None => None,
                Some(t) => {
                    let text = ctx.string(t, "target")?;
                    if matches!(host, DomainPattern::Wildcard(_)) {
                        ctx.error(t.line, "only an exact host can set a separate target");
                        return None;
                    }
                    if let Ok(addr) = text.parse::<IpAddr>() {
                        Some(Target::Addr(addr))
                    } else {
                        match DomainPattern::parse(&text) {
                            Ok(DomainPattern::Exact(name)) => Some(Target::Name(name)),
                            _ => {
                                ctx.error(
                                    t.line,
                                    format!("target {text:?} must be a host name or an address"),
                                );
                                return None;
                            }
                        }
                    }
                }
            };
            DestinationKind::Host { host, target }
        }
        (None, Some(c)) => {
            if let Some(t) = f.get("target") {
                ctx.error(t.line, "target applies only to host destinations");
            }
            let text = ctx.string(c, "cidr")?;
            match Cidr::parse(&text) {
                Ok(c) => DestinationKind::Cidr(c),
                Err(e) => {
                    ctx.error(c.line, e);
                    return None;
                }
            }
        }
        _ => {
            ctx.error(node.line, "a destination has exactly one of host or cidr");
            return None;
        }
    };
    Some(Destination {
        kind,
        protocol,
        ports,
        line: node.line,
    })
}

fn url_host(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.parse::<u16>().is_ok() => h,
        _ => authority,
    };
    Some((host.to_ascii_lowercase(), authority.to_owned()))
}

fn parse_app(ctx: &mut Ctx<'_>, meta: Meta, spec: &Node) -> Option<App> {
    let f = ctx.fields(
        spec,
        "App spec",
        &[
            "connectorGroup",
            "destinations",
            "discoverable",
            "clientless",
            "serverInitiatedFlows",
            "kubernetes",
        ],
    )?;
    if let Some(k) = f.get("kubernetes") {
        ctx.error(
            k.line,
            "Kubernetes API apps arrive with the Kubernetes broker in milestone M2",
        );
        return None;
    }
    let connector_group = match f.get("connectorGroup") {
        Some(g) => ctx.name(g, "connectorGroup")?,
        None => {
            ctx.error(spec.line, "an App needs a connectorGroup");
            return None;
        }
    };
    let mut destinations = Vec::new();
    match f.get("destinations") {
        Some(d) => {
            if let Some(items) = ctx.list(d, "destinations") {
                destinations.extend(items.iter().filter_map(|i| parse_destination(ctx, i)));
            }
        }
        None => ctx.error(spec.line, "an App needs at least one destination"),
    }
    let discoverable = f
        .get("discoverable")
        .and_then(|d| ctx.boolean(d, "discoverable"))
        .unwrap_or(false);
    let server_initiated_flows = f
        .get("serverInitiatedFlows")
        .and_then(|d| ctx.boolean(d, "serverInitiatedFlows"))
        .unwrap_or(false);
    let clientless = match f.get("clientless") {
        None => None,
        Some(c) => {
            let cf = ctx.fields(c, "clientless", &["url", "upstream"])?;
            let (Some(url_node), Some(up_node)) = (cf.get("url"), cf.get("upstream")) else {
                ctx.error(c.line, "clientless needs both url and upstream");
                return None;
            };
            let url = ctx.string(url_node, "clientless.url")?;
            let upstream = ctx.string(up_node, "clientless.upstream")?;
            let Some((host, _)) = url_host(&url).filter(|_| url.starts_with("https://")) else {
                ctx.error(url_node.line, "clientless.url must be an https:// URL");
                return None;
            };
            let url_host_pattern = match DomainPattern::parse(&host) {
                Ok(d @ DomainPattern::Exact(_)) => d,
                _ => {
                    ctx.error(url_node.line, "clientless.url must name an exact host");
                    return None;
                }
            };
            let Some((upstream_host, _)) = url_host(&upstream) else {
                ctx.error(
                    up_node.line,
                    "clientless.upstream must be an http:// or https:// URL",
                );
                return None;
            };
            Some(Clientless {
                url_host: url_host_pattern,
                url,
                upstream_host,
                upstream,
                line: c.line,
            })
        }
    };
    Some(App {
        meta,
        connector_group,
        destinations,
        discoverable,
        server_initiated_flows,
        clientless,
    })
}

fn trust_class(ctx: &mut Ctx<'_>, node: &Node) -> Option<u8> {
    match ctx.string(node, "minTrust")?.as_str() {
        "device-reported" => Some(1),
        "server-verified" => Some(2),
        "hardware-attested" => Some(3),
        other => {
            ctx.error(
                node.line,
                format!(
                    "minTrust {other:?} must be device-reported, server-verified or hardware-attested"
                ),
            );
            None
        }
    }
}

fn parse_os_version(text: &str) -> Option<i64> {
    let mut parts = text.split('.');
    let mut out = 0;
    for scale in [10_000, 100, 1] {
        let part = match parts.next() {
            Some(p) => p.parse::<i64>().ok().filter(|n| (0..100).contains(n))?,
            None if scale != 10_000 => 0,
            None => return None,
        };
        out += part * scale;
    }
    parts.next().is_none().then_some(out)
}

fn parse_check(ctx: &mut Ctx<'_>, node: &Node) -> Option<Check> {
    let f = ctx.fields(
        node,
        "a posture check",
        &[
            "signal",
            "minTrust",
            "remediation",
            "minimum",
            "maxIdle",
            "name",
        ],
    )?;
    let Some(signal_node) = f.get("signal") else {
        ctx.error(node.line, "a posture check needs a signal");
        return None;
    };
    let signal_name = ctx.string(signal_node, "signal")?;
    let allowed_extra: &[&str] = match signal_name.as_str() {
        "osVersion" => &["minimum"],
        "screenLock" => &["maxIdle"],
        "securityAgent" => &["name"],
        _ => &[],
    };
    for key in ["minimum", "maxIdle", "name"] {
        if let Some(n) = f.get(key)
            && !allowed_extra.contains(&key)
        {
            ctx.error(
                n.line,
                format!("{key} does not apply to signal {signal_name}"),
            );
        }
    }
    let signal = match signal_name.as_str() {
        "diskEncryption" => Signal::DiskEncryption,
        "firewall" => Signal::Firewall,
        "osVersion" => {
            let Some(m) = f.get("minimum") else {
                ctx.error(node.line, "osVersion needs a minimum, such as \"15.4\"");
                return None;
            };
            let text = ctx.string(m, "minimum")?;
            match parse_os_version(&text) {
                Some(v) => Signal::OsVersion(v),
                None => {
                    ctx.error(
                        m.line,
                        format!("minimum {text:?} must be a version such as 15.4 or 15.4.1"),
                    );
                    return None;
                }
            }
        }
        "screenLock" => Signal::ScreenLock(match f.get("maxIdle") {
            Some(m) => Some(ctx.duration(m, "maxIdle")?),
            None => None,
        }),
        "mdmEnrolled" => Signal::MdmEnrolled,
        "securityAgent" => {
            let Some(n) = f.get("name") else {
                ctx.error(
                    node.line,
                    "securityAgent needs the name of a configured integration",
                );
                return None;
            };
            Signal::SecurityAgent(ctx.string(n, "name")?)
        }
        other => {
            ctx.error(
                signal_node.line,
                format!(
                    "unknown signal {other:?}; expected diskEncryption, firewall, osVersion, \
                     screenLock, mdmEnrolled or securityAgent"
                ),
            );
            return None;
        }
    };
    let default_trust = match signal {
        Signal::MdmEnrolled | Signal::SecurityAgent(_) => 2,
        _ => 1,
    };
    let min_trust = match f.get("minTrust") {
        Some(t) => trust_class(ctx, t)?,
        None => default_trust,
    };
    let remediation = match f.get("remediation") {
        Some(r) => Some(ctx.string(r, "remediation")?),
        None => None,
    };
    Some(Check {
        signal,
        min_trust,
        remediation,
        line: node.line,
    })
}

fn parse_profile(ctx: &mut Ctx<'_>, meta: Meta, spec: &Node) -> Option<PostureProfile> {
    let f = ctx.fields(spec, "PostureProfile spec", &["platform", "checks"])?;
    let platform = match f.get("platform") {
        Some(p) => ctx.string(p, "platform")?,
        None => {
            ctx.error(spec.line, "a PostureProfile needs a platform (macos)");
            return None;
        }
    };
    if platform != "macos" {
        ctx.error(
            spec.line,
            format!("platform {platform:?} is not supported; v1 supports macos"),
        );
        return None;
    }
    let mut checks = Vec::new();
    if let Some(c) = f.get("checks")
        && let Some(items) = ctx.list(c, "checks")
    {
        checks.extend(items.iter().filter_map(|i| parse_check(ctx, i)));
    }
    if checks.is_empty() {
        ctx.error(spec.line, "a PostureProfile needs at least one check");
        return None;
    }
    Some(PostureProfile {
        meta,
        platform,
        checks,
    })
}

fn parse_who(ctx: &mut Ctx<'_>, node: &Node, what: &str) -> Option<Who> {
    let f = ctx.fields(node, what, &["users", "groups"])?;
    let mut who = Who::default();
    if let Some(u) = f.get("users") {
        who.users = ctx
            .strings(u, "users")
            .into_iter()
            .map(|(s, _)| s)
            .collect();
    }
    if let Some(g) = f.get("groups") {
        who.groups = ctx
            .strings(g, "groups")
            .into_iter()
            .map(|(s, _)| s)
            .collect();
    }
    if who.users.is_empty() && who.groups.is_empty() {
        ctx.error(
            node.line,
            format!("{what} needs users or groups; there is no implicit \"everyone\""),
        );
        return None;
    }
    Some(who)
}

fn parse_what(ctx: &mut Ctx<'_>, node: &Node) -> Option<What> {
    let f = ctx.fields(node, "what", &["apps", "appSelector"])?;
    let mut what = What {
        line: node.line,
        ..What::default()
    };
    if let Some(a) = f.get("apps") {
        for (name, line) in ctx.strings(a, "apps") {
            if is_valid_name(&name) {
                what.apps.push(name);
            } else {
                ctx.error(line, format!("{name:?} is not a valid app name"));
            }
        }
    }
    if let Some(s) = f.get("appSelector") {
        let sf = ctx.fields(s, "appSelector", &["matchLabels"])?;
        if let Some(m) = sf.get("matchLabels") {
            match &m.value {
                Value::Map(entries) if !entries.is_empty() => {
                    for (k, v) in entries {
                        if let Some(v) = ctx.string(v, "a label value") {
                            what.match_labels.insert(k.clone(), v);
                        }
                    }
                }
                _ => ctx.error(m.line, "matchLabels must be a non-empty mapping"),
            }
        } else {
            ctx.error(s.line, "appSelector needs matchLabels");
        }
    }
    if what.apps.is_empty() && what.match_labels.is_empty() {
        ctx.error(node.line, "what needs apps or an appSelector");
        return None;
    }
    Some(what)
}

fn parse_time_of_day(text: &str) -> Option<i64> {
    let (h, m) = text.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
    if (h == 24 && m == 0) || (h < 24 && m < 60) {
        Some(h * 60 + m)
    } else {
        None
    }
}

const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn valid_timezone(tz: &str) -> bool {
    !tz.is_empty()
        && tz.len() <= 64
        && tz.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'+'))
        })
}

fn parse_schedule(ctx: &mut Ctx<'_>, node: &Node) -> Option<Schedule> {
    let f = ctx.fields(node, "schedule", &["timezone", "windows"])?;
    let timezone = match f.get("timezone") {
        Some(t) => ctx.string(t, "timezone")?,
        None => {
            ctx.error(
                node.line,
                "schedule needs a timezone, such as UTC or Europe/Berlin",
            );
            return None;
        }
    };
    if !valid_timezone(&timezone) {
        ctx.error(node.line, format!("{timezone:?} is not a time zone name"));
        return None;
    }
    let Some(windows) = f.get("windows").and_then(|w| ctx.list(w, "windows")) else {
        ctx.error(node.line, "schedule needs windows");
        return None;
    };
    let mut ranges = Vec::new();
    let mut texts = Vec::new();
    for w in windows {
        let wf = ctx.fields(w, "a window", &["days", "from", "to"])?;
        let days: Vec<(String, usize)> = match wf.get("days") {
            Some(d) => ctx.strings(d, "days"),
            None => {
                ctx.error(w.line, "a window needs days");
                return None;
            }
        };
        let (Some(from_n), Some(to_n)) = (wf.get("from"), wf.get("to")) else {
            ctx.error(
                w.line,
                "a window needs from and to, such as \"08:00\" and \"19:00\"",
            );
            return None;
        };
        let from_text = ctx.string(from_n, "from")?;
        let to_text = ctx.string(to_n, "to")?;
        let (Some(from), Some(to)) = (parse_time_of_day(&from_text), parse_time_of_day(&to_text))
        else {
            ctx.error(w.line, "from and to must be times of day such as \"08:00\"");
            return None;
        };
        if from == to || from == 1440 {
            ctx.error(w.line, "a window must not be empty");
            return None;
        }
        let mut indexes = Vec::new();
        for (day, line) in days {
            let Some(index) = WEEKDAYS.iter().position(|d| *d == day) else {
                ctx.error(
                    line,
                    format!("{day:?} is not a day; use mon, tue, wed, thu, fri, sat or sun"),
                );
                return None;
            };
            if indexes.contains(&index) {
                ctx.error(line, format!("{day} is listed twice"));
                return None;
            }
            indexes.push(index);
            let start = index as i64 * 1440;
            if to > from {
                ranges.push(WeekRange {
                    from: start + from,
                    to: start + to,
                });
            } else {
                // Overnight: run to midnight, then continue the next day.
                ranges.push(WeekRange {
                    from: start + from,
                    to: start + 1440,
                });
                let next = (index as i64 + 1) % 7 * 1440;
                ranges.push(WeekRange {
                    from: next,
                    to: next + to,
                });
            }
        }
        texts.push(format!("{} {from_text}-{to_text}", day_list(&indexes)));
    }
    Some(Schedule {
        text: format!("{} {timezone}", texts.join("; ")),
        timezone,
        ranges,
    })
}

/// Days for messages, Monday first, with runs of three or more collapsed:
/// "Mon-Fri", "Sat,Sun", "Mon,Wed".
fn day_list(indexes: &[usize]) -> String {
    const NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let mut monday_first: Vec<usize> = indexes.iter().map(|i| (i + 6) % 7).collect();
    monday_first.sort_unstable();
    let name = |i: usize| NAMES[(i + 1) % 7];
    let mut parts = Vec::new();
    let mut i = 0;
    while i < monday_first.len() {
        let mut j = i;
        while j + 1 < monday_first.len() && monday_first[j + 1] == monday_first[j] + 1 {
            j += 1;
        }
        if j - i >= 2 {
            parts.push(format!(
                "{}-{}",
                name(monday_first[i]),
                name(monday_first[j])
            ));
        } else {
            parts.extend((i..=j).map(|k| name(monday_first[k]).to_owned()));
        }
        i = j + 1;
    }
    parts.join(",")
}

fn parse_when(ctx: &mut Ctx<'_>, node: &Node, allow_via: bool) -> Option<When> {
    let allowed: &[&str] = if allow_via {
        &["posture", "auth", "via", "schedule", "network"]
    } else {
        &["posture", "auth", "schedule", "network"]
    };
    let f = ctx.fields(node, "when", allowed)?;
    let mut when = When {
        line: node.line,
        ..When::default()
    };
    if let Some(p) = f.get("posture") {
        when.posture = ctx
            .strings(p, "posture")
            .into_iter()
            .map(|(s, _)| s)
            .collect();
    }
    if let Some(a) = f.get("auth") {
        let af = ctx.fields(a, "auth", &["maxAge", "mfa"])?;
        if let Some(m) = af.get("maxAge") {
            when.auth.max_age = Some(ctx.duration(m, "maxAge")?);
        }
        if let Some(m) = af.get("mfa") {
            when.auth.mfa = ctx.boolean(m, "mfa")?;
        }
    }
    if let Some(v) = f.get("via") {
        let mut via = Vec::new();
        for (s, line) in ctx.strings(v, "via") {
            match s.as_str() {
                "client" => via.push(Via::Client),
                "browser" => via.push(Via::Browser),
                other => ctx.error(line, format!("via {other:?} must be client or browser")),
            }
        }
        via.dedup();
        if via.is_empty() {
            ctx.error(v.line, "via needs client, browser or both");
            return None;
        }
        when.via = Some(via);
    }
    if let Some(s) = f.get("schedule") {
        when.schedule = Some(parse_schedule(ctx, s)?);
    }
    if let Some(n) = f.get("network") {
        let nf = ctx.fields(n, "network", &["sourceCidrs"])?;
        if let Some(c) = nf.get("sourceCidrs") {
            when.network = cidrs(ctx, c, "sourceCidrs");
        }
        if when.network.is_empty() {
            ctx.error(n.line, "network needs sourceCidrs");
            return None;
        }
    }
    Some(when)
}

fn parse_rule(ctx: &mut Ctx<'_>, node: &Node) -> Option<Rule> {
    let f = ctx.fields(node, "a rule", &["name", "effect", "who", "what", "when"])?;
    let name = match f.get("name") {
        Some(n) => ctx.name(n, "rule name")?,
        None => {
            ctx.error(node.line, "a rule needs a name");
            return None;
        }
    };
    let deny = match f.get("effect") {
        None => false,
        Some(e) => match ctx.string(e, "effect")?.as_str() {
            "allow" => false,
            "deny" => true,
            other => {
                ctx.error(e.line, format!("effect {other:?} must be allow or deny"));
                return None;
            }
        },
    };
    let who = match f.get("who") {
        Some(w) => parse_who(ctx, w, "who")?,
        None => {
            ctx.error(node.line, "a rule needs who");
            return None;
        }
    };
    let what = match f.get("what") {
        Some(w) => parse_what(ctx, w)?,
        None => {
            ctx.error(node.line, "a rule needs what");
            return None;
        }
    };
    let when = match f.get("when") {
        Some(w) => parse_when(ctx, w, true)?,
        None => When {
            line: node.line,
            ..When::default()
        },
    };
    Some(Rule {
        name,
        deny,
        who,
        what,
        when,
        line: node.line,
    })
}

fn parse_access_policy(ctx: &mut Ctx<'_>, meta: Meta, spec: &Node) -> Option<AccessPolicy> {
    let f = ctx.fields(spec, "AccessPolicy spec", &["rules"])?;
    let Some(items) = f.get("rules").and_then(|r| ctx.list(r, "rules")) else {
        ctx.error(spec.line, "an AccessPolicy needs rules");
        return None;
    };
    let mut rules: Vec<Rule> = Vec::new();
    for item in items {
        if let Some(rule) = parse_rule(ctx, item) {
            if rules.iter().any(|r| r.name == rule.name) {
                ctx.error(
                    rule.line,
                    format!("rule {} is defined twice in {}", rule.name, meta.name),
                );
                continue;
            }
            rules.push(rule);
        }
    }
    Some(AccessPolicy { meta, rules })
}

fn parse_request_policy(ctx: &mut Ctx<'_>, meta: Meta, spec: &Node) -> Option<AccessRequestPolicy> {
    let f = ctx.fields(
        spec,
        "AccessRequestPolicy spec",
        &[
            "who",
            "what",
            "approval",
            "requireReason",
            "maxDuration",
            "defaultDuration",
            "when",
        ],
    )?;
    let who = match f.get("who") {
        Some(w) => parse_who(ctx, w, "who")?,
        None => {
            ctx.error(spec.line, "an AccessRequestPolicy needs who");
            return None;
        }
    };
    let what = match f.get("what") {
        Some(w) => parse_what(ctx, w)?,
        None => {
            ctx.error(spec.line, "an AccessRequestPolicy needs what");
            return None;
        }
    };
    let Some(approval) = f.get("approval") else {
        ctx.error(spec.line, "an AccessRequestPolicy needs approval");
        return None;
    };
    let af = ctx.fields(
        approval,
        "approval",
        &["approvers", "minApprovals", "automatic"],
    )?;
    let approvers = match af.get("approvers") {
        Some(a) => parse_who(ctx, a, "approvers")?,
        None => {
            ctx.error(approval.line, "approval needs approvers");
            return None;
        }
    };
    let min_approvals = match af.get("minApprovals") {
        Some(m) => match ctx.integer(m, "minApprovals")? {
            n @ 1..=100 => n as u32,
            _ => {
                ctx.error(m.line, "minApprovals must be between 1 and 100");
                return None;
            }
        },
        None => 1,
    };
    let automatic = match af.get("automatic") {
        None => None,
        Some(a) => {
            let auto = ctx.fields(a, "automatic", &["when"])?;
            match auto.get("when") {
                Some(w) => Some(parse_when(ctx, w, false)?),
                None => {
                    ctx.error(a.line, "automatic needs when");
                    return None;
                }
            }
        }
    };
    let require_reason = match f.get("requireReason") {
        Some(r) => ctx.boolean(r, "requireReason")?,
        None => true,
    };
    let max_duration = match f.get("maxDuration") {
        Some(d) => ctx.duration(d, "maxDuration")?,
        None => {
            ctx.error(spec.line, "an AccessRequestPolicy needs maxDuration");
            return None;
        }
    };
    let default_duration = match f.get("defaultDuration") {
        Some(d) => ctx.duration(d, "defaultDuration")?,
        None => max_duration,
    };
    if default_duration > max_duration {
        ctx.error(spec.line, "defaultDuration is longer than maxDuration");
        return None;
    }
    let when = match f.get("when") {
        Some(w) => parse_when(ctx, w, false)?,
        None => When {
            line: spec.line,
            ..When::default()
        },
    };
    Some(AccessRequestPolicy {
        meta,
        who,
        what,
        approvers,
        min_approvals,
        automatic,
        require_reason,
        max_duration,
        default_duration,
        when,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> (Objects, Vec<Diagnostic>) {
        let mut objects = Objects::default();
        let mut diags = Vec::new();
        parse_file("test.yaml", text, &mut objects, &mut diags);
        (objects, diags)
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("1h30m"), Some(5400));
        assert_eq!(parse_duration("12h"), Some(43_200));
        assert_eq!(parse_duration("7d"), Some(604_800));
        for bad in ["", "h", "12", "1x", "-1h", "1.5h"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }

    #[test]
    fn os_versions() {
        assert_eq!(parse_os_version("15.4"), Some(150_400));
        assert_eq!(parse_os_version("15.4.1"), Some(150_401));
        assert_eq!(parse_os_version("15"), Some(150_000));
        assert_eq!(parse_os_version("15.4.1.2"), None);
        assert_eq!(parse_os_version("15.100"), None);
    }

    #[test]
    fn schedule_windows_become_week_ranges() {
        let (objects, diags) = parse(
            r#"
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata: { name: p }
spec:
  rules:
    - name: r
      who: { groups: [g] }
      what: { apps: [a] }
      when:
        schedule:
          timezone: Europe/Berlin
          windows:
            - { days: [mon], from: "08:00", to: "19:00" }
            - { days: [sat], from: "22:00", to: "02:00" }
"#,
        );
        assert!(diags.is_empty(), "{diags:?}");
        let schedule = objects.policies[0].rules[0].when.schedule.clone().unwrap();
        assert_eq!(
            schedule.ranges,
            vec![
                WeekRange {
                    from: 1920,
                    to: 2580
                },
                WeekRange {
                    from: 6 * 1440 + 1320,
                    to: 7 * 1440
                },
                WeekRange { from: 0, to: 120 },
            ]
        );
        assert_eq!(
            schedule.text,
            "Mon 08:00-19:00; Sat 22:00-02:00 Europe/Berlin"
        );
    }

    #[test]
    fn errors_point_at_lines() {
        let (_, diags) = parse(
            "apiVersion: warren.dev/v1alpha1\nkind: App\nmetadata:\n  name: Grafana\nspec: {}\n",
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, 4);
        assert!(diags[0].message.contains("metadata.name"));

        let (_, diags) = parse(
            "apiVersion: warren.dev/v1alpha1\nkind: App\nmetadata: {name: a}\nspec:\n  connectorGroup: g\n  destinations:\n    - host: a.example.com\n      protocol: tcp\n      colour: blue\n",
        );
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1, "{diags:?}");
        assert_eq!(errors[0].line, 9);
        assert!(errors[0].message.contains("colour"));
        assert!(
            diags
                .iter()
                .any(|d| d.severity == Severity::Warning && d.line == 7)
        );
    }

    #[test]
    fn wrong_api_version_and_kind() {
        let (_, diags) = parse("apiVersion: v1\nkind: App\nmetadata: {name: a}\n");
        assert!(diags[0].message.contains("apiVersion"));
        let (_, diags) =
            parse("apiVersion: warren.dev/v1alpha1\nkind: Gadget\nmetadata: {name: a}\n");
        assert!(diags[0].message.contains("unknown kind"));
    }
}
