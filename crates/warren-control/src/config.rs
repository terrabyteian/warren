//! The control plane's configuration file.
//!
//! One YAML document, read with the same strict reader as policy, so
//! mistakes are reported with their line. Values that are bounded by a
//! guarantee (certificate lifetime, clock skew) are refused beyond the bound.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use warren_core::identity::valid_trust_domain;
use warren_core::params::{CLIENT_CERT_LIFETIME, CLOCK_SKEW_ALLOWANCE};
use warren_policy::model::parse_duration;
use warren_policy::names::{Cidr, is_host_name};
use warren_policy::yaml::{self, Node, Value};

use crate::Error;
use crate::web::{ListenOptions, is_internal_name};

/// How new devices are approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// Every enrolled device is approved at once.
    Automatic,
    /// An admin approves each device.
    Manual,
}

/// Which kind of identity provider `idp` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpKind {
    /// Any OpenID Connect provider, found through discovery.
    Oidc,
    /// Google, with its issuer and endpoints preset. Google ID tokens carry
    /// no groups, so Google users get theirs from warren's own groups.
    Google,
}

/// Where an IdP's endpoints are, when they are preset rather than found
/// through discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// The authorization endpoint.
    pub authorization: String,
    /// The token endpoint.
    pub token: String,
    /// The JWKS URI.
    pub jwks: String,
}

/// Google's OpenID Connect issuer.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Idp {
    /// What kind of provider this is.
    pub kind: IdpKind,
    /// How the sign-in page names the provider.
    pub display_name: String,
    /// The OIDC issuer URL; discovery is fetched from
    /// `{issuer}/.well-known/openid-configuration` unless `endpoints` are
    /// preset.
    pub issuer: String,
    /// Other spellings of the issuer an ID token's `iss` may use (Google
    /// also issues tokens as `accounts.google.com`).
    pub issuer_aliases: Vec<String>,
    /// Preset endpoints; discovery is skipped when these are set.
    pub endpoints: Option<Endpoints>,
    /// The client ID registered for warren.
    pub client_id: String,
    /// A file holding the client secret, for confidential clients. Without
    /// one warren is a public client and relies on PKCE alone.
    pub client_secret_file: Option<PathBuf>,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// The ID-token claim that lists the user's groups.
    pub groups_claim: String,
    /// A PEM file of CA certificates to trust for the IdP instead of the
    /// operating system's trust store, for a privately signed IdP.
    pub ca_file: Option<PathBuf>,
    /// `amr` values that mean the sign-in used multi-factor authentication.
    pub mfa_amr_values: Vec<String>,
    /// `acr` values that mean the sign-in used multi-factor authentication.
    pub mfa_acr_values: Vec<String>,
    /// Google: only accounts of this Workspace domain (the `hd` claim) may
    /// sign in, besides `allowed_emails`.
    pub hosted_domain: Option<String>,
    /// Google: these verified emails may sign in, besides accounts of
    /// `hosted_domain`.
    pub allowed_emails: Vec<String>,
}

impl Idp {
    /// Whether an ID token's `iss` names this provider.
    pub fn issued_by(&self, iss: &str) -> bool {
        let iss = iss.trim_end_matches('/');
        iss == self.issuer || self.issuer_aliases.iter().any(|a| a == iss)
    }
}

/// The first admin, created from a mounted secret on the first start that
/// finds no built-in accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapAdmin {
    /// The username.
    pub username: String,
    /// A file holding the initial password.
    pub password_file: PathBuf,
    /// The admin's email, if any.
    pub email: Option<String>,
    /// Local groups the admin joins.
    pub groups: Vec<String>,
}

/// Built-in accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAccounts {
    /// Whether built-in accounts can sign in and be created.
    pub enabled: bool,
    /// The first admin, if one is to be created.
    pub bootstrap_admin: Option<BootstrapAdmin>,
    /// Failed sign-ins one source address may make per 15 minutes before
    /// it is refused for the rest of them; 0 turns the limit off.
    pub max_failures_per_source: u32,
}

/// A certificate the operator supplies for the public host, from WebPKI or
/// the operator's own CA, so browsers trust the sign-in pages. Reloaded
/// when the files change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    /// The PEM certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// The unencrypted PEM private key: PKCS#8 (`PRIVATE KEY`), SEC1
    /// (`EC PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`).
    pub key_file: PathBuf,
}

/// Who may use the web console's admin pages, and how recently they must
/// have signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Console {
    /// Admins by IdP email (compared without case), IdP subject,
    /// `local:<username>` for a built-in account, or warren user ID.
    pub admin_users: Vec<String>,
    /// Admins by IdP group.
    pub admin_groups: Vec<String>,
    /// How long a console sign-in lasts.
    pub session_lifetime: Duration,
    /// How recently an admin must have authenticated at the IdP to make a
    /// change: approve or revoke a device, disable or enable a user.
    pub change_max_age: Duration,
}

impl Default for Console {
    fn default() -> Console {
        Console {
            admin_users: Vec::new(),
            admin_groups: Vec::new(),
            session_lifetime: Duration::from_secs(12 * 3600),
            change_max_age: Duration::from_secs(3600),
        }
    }
}

/// The longest console sign-in a deployment may configure.
const CONSOLE_SESSION_BOUND: Duration = Duration::from_secs(86_400);

/// The control plane's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The deployment's trust domain, used in every identity URI.
    pub trust_domain: String,
    /// The organization URL clients are given, `https://host[:port]`.
    pub public_url: String,
    /// The host of `public_url`, reserved so no app can claim it.
    pub public_host: String,
    /// More DNS names for the control plane's own certificate, from the
    /// infrastructure CA. With `tls` set these are the names relays and
    /// connectors use, since the public host presents the operator's
    /// certificate.
    pub dns_names: Vec<String>,
    /// The operator's certificate for the public host; without one the
    /// public host presents the control plane's own certificate.
    pub tls: Option<TlsFiles>,
    /// Where the HTTPS API listens.
    pub listen: SocketAddr,
    /// Per-source limits and trusted proxies for the HTTPS listener.
    pub connections: ListenOptions,
    /// Where the local admin API listens: a Unix socket, created mode 0600.
    pub admin_socket: PathBuf,
    /// Where state lives.
    pub data_dir: PathBuf,
    /// The SQLite database file.
    pub database: PathBuf,
    /// The key-encryption key file, created on first start if missing.
    pub kek_file: PathBuf,
    /// The policy directory.
    pub policy_dir: PathBuf,
    /// The identity provider, if there is one.
    pub idp: Option<Idp>,
    /// Built-in accounts.
    pub local_accounts: LocalAccounts,
    /// Exact redirect URIs accepted at sign-in besides loopback ones.
    pub redirect_uris: Vec<String>,
    /// `SESSION_MAX_LIFETIME`: time between browser sign-ins.
    pub session_max_lifetime: Duration,
    /// How devices are approved.
    pub device_approval: Approval,
    /// `DEVICE_POOL_V4`.
    pub device_pool_v4: Cidr,
    /// `DEVICE_POOL_V6`.
    pub device_pool_v6: Cidr,
    /// `CLIENT_CERT_LIFETIME`, at most 4 hours.
    pub client_cert_lifetime: Duration,
    /// `CLOCK_SKEW_ALLOWANCE`, at most 2 minutes.
    pub clock_skew: Duration,
    /// The audit log file; standard output when absent.
    pub audit_file: Option<PathBuf>,
    /// More names no app may claim, such as relay host names.
    pub reserved_names: Vec<String>,
    /// The web console.
    pub console: Console,
}

/// The longest sign-in session a deployment may configure.
const SESSION_MAX_LIFETIME_BOUND: Duration = Duration::from_secs(90 * 86_400);

const KEYS: &[&str] = &[
    "trustDomain",
    "publicUrl",
    "dnsNames",
    "tls",
    "listen",
    "connections",
    "adminSocket",
    "dataDir",
    "database",
    "keyEncryptionKeyFile",
    "policyDir",
    "idp",
    "localAccounts",
    "signIn",
    "devices",
    "certificates",
    "audit",
    "reservedNames",
    "console",
];

struct Reader {
    errors: Vec<String>,
}

impl Reader {
    fn err(&mut self, node: &Node, msg: impl std::fmt::Display) {
        self.errors.push(format!("line {}: {msg}", node.line));
    }

    fn map<'n>(
        &mut self,
        node: &'n Node,
        what: &str,
        allowed: &[&str],
    ) -> Vec<(&'n str, &'n Node)> {
        let Value::Map(entries) = &node.value else {
            self.err(node, format!("{what} must be a mapping"));
            return Vec::new();
        };
        let mut out = Vec::new();
        for (k, v) in entries {
            if allowed.contains(&k.as_str()) {
                out.push((k.as_str(), v));
            } else {
                self.err(
                    v,
                    format!(
                        "unknown setting {k:?} in {what}; expected one of: {}",
                        allowed.join(", ")
                    ),
                );
            }
        }
        out
    }

    fn string(&mut self, node: &Node, what: &str) -> Option<String> {
        match &node.value {
            Value::Scalar { text, .. } if !node.is_null() => Some(text.clone()),
            _ => {
                self.err(node, format!("{what} must be a string"));
                None
            }
        }
    }

    fn strings(&mut self, node: &Node, what: &str) -> Vec<String> {
        match &node.value {
            Value::Seq(items) => items.iter().filter_map(|i| self.string(i, what)).collect(),
            _ => {
                self.err(node, format!("{what} must be a list"));
                Vec::new()
            }
        }
    }

    /// Exact host names: lowercase DNS names, no wildcards, no trailing dot.
    fn host_names(&mut self, node: &Node, what: &str) -> Vec<String> {
        let names = self.strings(node, what);
        names
            .into_iter()
            .filter(|n| {
                let ok = is_host_name(n);
                if !ok {
                    self.err(
                        node,
                        format!("{what} entry {n:?} must be a lowercase host name"),
                    );
                }
                ok
            })
            .collect()
    }

    fn duration(&mut self, node: &Node, what: &str) -> Option<Duration> {
        let text = self.string(node, what)?;
        match parse_duration(&text) {
            Some(s) if s > 0 => Some(Duration::from_secs(s as u64)),
            _ => {
                self.err(
                    node,
                    format!("{what} {text:?} must be a duration such as 4h or 2m"),
                );
                None
            }
        }
    }
}

fn get<'n>(fields: &[(&str, &'n Node)], key: &str) -> Option<&'n Node> {
    fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Splits an `https://host[:port]` URL into its host, refusing anything
/// with a path, query or user info.
pub fn https_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.parse::<u16>().is_ok() => h,
        Some(_) => return None,
        None => authority,
    };
    let host = host.to_ascii_lowercase();
    (is_host_name(&host) || host.parse::<std::net::IpAddr>().is_ok()).then_some(host)
}

/// The host of any `https://` URL, path or not: what the IdP's issuer
/// (often `https://host/realms/x` or `https://host/oauth2/default`) puts
/// on the network.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.parse::<u16>().is_ok() => h,
        _ => authority,
    };
    let host = host.to_ascii_lowercase();
    is_host_name(&host).then_some(host)
}

impl Config {
    /// Reads and checks a configuration file.
    pub fn load(path: &Path) -> Result<Config, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Config::parse(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }

    /// Parses configuration text. Relative paths are kept as written.
    pub fn parse(text: &str) -> Result<Config, String> {
        let docs = yaml::parse_documents(text).map_err(|e| e.to_string())?;
        let [doc] = docs.as_slice() else {
            return Err("the configuration must be exactly one YAML document".into());
        };
        let mut r = Reader { errors: Vec::new() };
        let f = r.map(doc, "the configuration", KEYS);
        let required = |r: &mut Reader, key: &str| -> Option<String> {
            match get(&f, key) {
                Some(n) => r.string(n, key),
                None => {
                    r.errors.push(format!("{key} is required"));
                    None
                }
            }
        };
        let trust_domain = required(&mut r, "trustDomain").unwrap_or_default();
        if !trust_domain.is_empty() && !valid_trust_domain(&trust_domain) {
            r.errors.push(format!(
                "trustDomain {trust_domain:?} must be a lowercase DNS name"
            ));
        }
        let public_url = required(&mut r, "publicUrl")
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_owned();
        let public_host = https_host(&public_url).unwrap_or_default();
        if !public_url.is_empty() && public_host.is_empty() {
            r.errors.push(format!(
                "publicUrl {public_url:?} must be https://host[:port] with no path"
            ));
        }
        let dns_names = get(&f, "dnsNames")
            .map(|n| r.host_names(n, "dnsNames"))
            .unwrap_or_default();
        let mut tls = None;
        if let Some(n) = get(&f, "tls") {
            let tf = r.map(n, "tls", &["certFile", "keyFile"]);
            let cert_file = get(&tf, "certFile").and_then(|p| r.string(p, "tls.certFile"));
            let key_file = get(&tf, "keyFile").and_then(|p| r.string(p, "tls.keyFile"));
            match (cert_file, key_file) {
                (Some(cert_file), Some(key_file)) => {
                    tls = Some(TlsFiles {
                        cert_file: cert_file.into(),
                        key_file: key_file.into(),
                    })
                }
                _ => r.err(n, "tls needs both certFile and keyFile"),
            }
            if !dns_names.iter().any(|d| *d != public_host) {
                r.err(
                    n,
                    "tls gives publicUrl's host the operator's certificate, so dnsNames needs another name, where relays and connectors reach the control plane under its own certificate",
                );
            }
        }
        let data_dir = PathBuf::from(
            get(&f, "dataDir")
                .and_then(|n| r.string(n, "dataDir"))
                .unwrap_or_else(|| "/var/lib/warren".into()),
        );
        let path_or = |r: &mut Reader, key: &str, default: PathBuf| -> PathBuf {
            get(&f, key)
                .and_then(|n| r.string(n, key))
                .map(PathBuf::from)
                .unwrap_or(default)
        };
        let listen_text = get(&f, "listen")
            .and_then(|n| r.string(n, "listen"))
            .unwrap_or_else(|| "[::]:443".into());
        let listen = listen_text.parse().unwrap_or_else(|_| {
            r.errors.push(format!(
                "listen {listen_text:?} must be an address and port"
            ));
            SocketAddr::from(([0, 0, 0, 0], 0))
        });
        let mut connections = ListenOptions::default();
        if let Some(n) = get(&f, "connections") {
            let cf = r.map(n, "connections", &["maxPerSource", "trustedProxies"]);
            if let Some(m) = get(&cf, "maxPerSource") {
                match r.string(m, "maxPerSource").map(|t| t.parse::<usize>()) {
                    Some(Ok(limit)) => connections.max_per_source = limit,
                    Some(Err(_)) => {
                        r.err(m, "maxPerSource must be a whole number; 0 means no limit")
                    }
                    None => {}
                }
            }
            if let Some(p) = get(&cf, "trustedProxies") {
                for text in r.strings(p, "trustedProxies") {
                    match Cidr::parse(&text) {
                        Ok(c) => connections.trusted_proxies.push(c),
                        Err(e) => r.err(p, format!("trustedProxies entry {text:?}: {e}")),
                    }
                }
            }
        }
        let admin_socket = path_or(&mut r, "adminSocket", data_dir.join("admin.sock"));
        let database = path_or(&mut r, "database", data_dir.join("warren.db"));
        let kek_file = path_or(&mut r, "keyEncryptionKeyFile", data_dir.join("kek"));
        let policy_dir = PathBuf::from(required(&mut r, "policyDir").unwrap_or_default());

        let idp = get(&f, "idp").map(|n| parse_idp(&mut r, n));
        let mut local_accounts = LocalAccounts {
            enabled: true,
            bootstrap_admin: None,
            max_failures_per_source: crate::accounts::SOURCE_FAILURE_LIMIT,
        };
        if let Some(n) = get(&f, "localAccounts") {
            parse_local_accounts(&mut r, n, &mut local_accounts);
        }
        if idp.is_none() && !local_accounts.enabled {
            r.errors.push(
                "with no idp, localAccounts must stay enabled, or nobody could sign in".into(),
            );
        }

        let mut redirect_uris = Vec::new();
        let mut session_max_lifetime = Duration::from_secs(7 * 86_400);
        if let Some(n) = get(&f, "signIn") {
            let sf = r.map(n, "signIn", &["redirectUris", "sessionMaxLifetime"]);
            if let Some(u) = get(&sf, "redirectUris") {
                redirect_uris = r.strings(u, "redirectUris");
            }
            if let Some(d) =
                get(&sf, "sessionMaxLifetime").and_then(|d| r.duration(d, "sessionMaxLifetime"))
            {
                if d > SESSION_MAX_LIFETIME_BOUND {
                    r.err(n, "sessionMaxLifetime may be at most 90d");
                } else {
                    session_max_lifetime = d;
                }
            }
        }

        let mut device_approval = Approval::Manual;
        let mut device_pool_v4 = Cidr::parse("100.96.0.0/16").map_err(|e| e.to_string())?;
        let mut device_pool_v6 =
            Cidr::parse("fd77:6172:7265:6e00::/64").map_err(|e| e.to_string())?;
        if let Some(n) = get(&f, "devices") {
            let df = r.map(n, "devices", &["approval", "poolV4", "poolV6"]);
            if let Some(a) = get(&df, "approval") {
                match r.string(a, "approval").as_deref() {
                    Some("automatic") => device_approval = Approval::Automatic,
                    Some("manual") => device_approval = Approval::Manual,
                    Some(other) => {
                        r.err(a, format!("approval {other:?} must be automatic or manual"))
                    }
                    None => {}
                }
            }
            for (key, slot, v4) in [
                ("poolV4", &mut device_pool_v4, true),
                ("poolV6", &mut device_pool_v6, false),
            ] {
                if let Some(p) = get(&df, key)
                    && let Some(text) = r.string(p, key)
                {
                    match Cidr::parse(&text) {
                        Ok(c) if c.is_ipv4() == v4 && c.prefix() <= if v4 { 30 } else { 126 } => {
                            *slot = c
                        }
                        Ok(_) => r.err(
                            p,
                            format!("{key} must be a larger IPv{} range", if v4 { 4 } else { 6 }),
                        ),
                        Err(e) => r.err(p, e),
                    }
                }
            }
        }

        let mut client_cert_lifetime = CLIENT_CERT_LIFETIME;
        let mut clock_skew = CLOCK_SKEW_ALLOWANCE;
        if let Some(n) = get(&f, "certificates") {
            let cf = r.map(n, "certificates", &["clientLifetime", "clockSkewAllowance"]);
            if let Some(d) =
                get(&cf, "clientLifetime").and_then(|d| r.duration(d, "clientLifetime"))
            {
                if d > CLIENT_CERT_LIFETIME {
                    r.err(n, "clientLifetime may be at most 4h (G4)");
                } else if d < Duration::from_secs(300) {
                    r.err(n, "clientLifetime must be at least 5m");
                } else {
                    client_cert_lifetime = d;
                }
            }
            if let Some(d) =
                get(&cf, "clockSkewAllowance").and_then(|d| r.duration(d, "clockSkewAllowance"))
            {
                if d > CLOCK_SKEW_ALLOWANCE {
                    r.err(n, "clockSkewAllowance may be at most 2m");
                } else {
                    clock_skew = d;
                }
            }
        }

        let mut audit_file = None;
        if let Some(n) = get(&f, "audit") {
            let af = r.map(n, "audit", &["file"]);
            audit_file = get(&af, "file")
                .and_then(|p| r.string(p, "audit.file"))
                .map(PathBuf::from);
        }
        let reserved_names = get(&f, "reservedNames")
            .map(|n| r.host_names(n, "reservedNames"))
            .unwrap_or_default();

        let console = get(&f, "console")
            .map(|n| parse_console(&mut r, n))
            .unwrap_or_default();

        if !r.errors.is_empty() {
            return Err(r.errors.join("; "));
        }
        let idp = match idp {
            Some(Some(idp)) => Some(idp),
            Some(None) => return Err("idp is invalid".into()),
            None => None,
        };
        Ok(Config {
            trust_domain,
            public_url,
            public_host,
            dns_names,
            tls,
            listen,
            connections,
            admin_socket,
            data_dir,
            database,
            kek_file,
            policy_dir,
            idp,
            local_accounts,
            redirect_uris,
            session_max_lifetime,
            device_approval,
            device_pool_v4,
            device_pool_v6,
            client_cert_lifetime,
            clock_skew,
            audit_file,
            reserved_names,
            console,
        })
    }

    /// Resolves relative paths against `base`, the configuration file's
    /// directory.
    pub fn resolve_paths(&mut self, base: &Path) {
        for p in [
            &mut self.admin_socket,
            &mut self.data_dir,
            &mut self.database,
            &mut self.kek_file,
            &mut self.policy_dir,
        ] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        let idp_files = self
            .idp
            .iter_mut()
            .flat_map(|i| [&mut i.client_secret_file, &mut i.ca_file]);
        for p in idp_files
            .chain([&mut self.audit_file])
            .flatten()
            .chain(
                self.local_accounts
                    .bootstrap_admin
                    .iter_mut()
                    .map(|b| &mut b.password_file),
            )
            .chain(
                self.tls
                    .iter_mut()
                    .flat_map(|t| [&mut t.cert_file, &mut t.key_file]),
            )
        {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
    }

    /// Where enrolled clients, relays and connectors reach the control
    /// plane, always under its own certificate, as `host:port`: the host of
    /// `public_url`, or with an operator certificate on it the first
    /// internal name, and `public_url`'s port either way. Join tokens carry
    /// it as `cp`.
    pub fn internal_endpoint(&self) -> String {
        let host = match (&self.tls, self.internal_names().first()) {
            (Some(_), Some(name)) => name.clone(),
            _ => self.public_host.clone(),
        };
        let authority = self.public_url.trim_start_matches("https://");
        let port = authority
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(443);
        format!("{host}:{port}")
    }

    /// [`Config::internal_endpoint`] as an `https://` URL.
    pub fn internal_url(&self) -> String {
        let endpoint = self.internal_endpoint();
        format!(
            "https://{}",
            endpoint.strip_suffix(":443").unwrap_or(&endpoint)
        )
    }

    /// The names in `dns_names` other than `public_host`, which always get
    /// the control plane's own certificate.
    pub fn internal_names(&self) -> Vec<String> {
        self.dns_names
            .iter()
            .filter(|n| **n != self.public_host)
            .cloned()
            .collect()
    }

    /// Whether a connection that asked for `server_name` was given the
    /// control plane's own certificate, which the trust bundle verifies,
    /// rather than the operator's.
    pub fn presents_own_certificate(&self, server_name: Option<&str>) -> bool {
        self.tls.is_none() || is_internal_name(&self.internal_names(), server_name)
    }

    /// The control plane's own names, which no app may claim: its host, its
    /// extra DNS names, the IdP's host and any configured reserved names.
    pub fn reserved(&self) -> Vec<String> {
        let mut names = vec![self.public_host.clone()];
        names.extend(self.dns_names.iter().cloned());
        names.extend(self.idp.as_ref().and_then(|i| url_host(&i.issuer)));
        names.extend(self.reserved_names.iter().cloned());
        names
    }
}

fn parse_console(r: &mut Reader, node: &Node) -> Console {
    let mut console = Console::default();
    let f = r.map(
        node,
        "console",
        &["admins", "sessionLifetime", "changeMaxAge"],
    );
    if let Some(a) = get(&f, "admins") {
        let af = r.map(a, "console.admins", &["users", "groups"]);
        if let Some(u) = get(&af, "users") {
            console.admin_users = r.strings(u, "console.admins.users");
        }
        if let Some(g) = get(&af, "groups") {
            console.admin_groups = r.strings(g, "console.admins.groups");
        }
    }
    if let Some(d) =
        get(&f, "sessionLifetime").and_then(|d| r.duration(d, "console.sessionLifetime"))
    {
        if d > CONSOLE_SESSION_BOUND {
            r.err(node, "console.sessionLifetime may be at most 24h");
        } else {
            console.session_lifetime = d;
        }
    }
    if let Some(d) = get(&f, "changeMaxAge").and_then(|d| r.duration(d, "console.changeMaxAge")) {
        if d > console.session_lifetime {
            r.err(
                node,
                "console.changeMaxAge may be at most console.sessionLifetime",
            );
        } else {
            console.change_max_age = d;
        }
    }
    console
}

fn parse_idp(r: &mut Reader, node: &Node) -> Option<Idp> {
    let f = r.map(
        node,
        "idp",
        &[
            "type",
            "displayName",
            "issuer",
            "clientId",
            "clientSecretFile",
            "scopes",
            "groupsClaim",
            "caFile",
            "mfaAmrValues",
            "mfaAcrValues",
            "hostedDomain",
            "allowedEmails",
        ],
    );
    let kind = match get(&f, "type")
        .and_then(|n| r.string(n, "idp.type"))
        .as_deref()
    {
        None | Some("oidc") => IdpKind::Oidc,
        Some("google") => IdpKind::Google,
        Some(other) => {
            r.err(node, format!("idp.type {other:?} must be oidc or google"));
            return None;
        }
    };
    let client_id = get(&f, "clientId").and_then(|n| r.string(n, "idp.clientId"));
    let client_secret_file = get(&f, "clientSecretFile")
        .and_then(|n| r.string(n, "idp.clientSecretFile"))
        .map(PathBuf::from);
    let display_name = get(&f, "displayName").and_then(|n| r.string(n, "idp.displayName"));
    if kind == IdpKind::Google {
        for key in [
            "issuer",
            "scopes",
            "groupsClaim",
            "caFile",
            "mfaAmrValues",
            "mfaAcrValues",
        ] {
            if let Some(n) = get(&f, key) {
                r.err(
                    n,
                    format!("idp.{key} is preset for type google and cannot be set"),
                );
            }
        }
        let (Some(client_id), Some(client_secret_file)) = (client_id, client_secret_file) else {
            r.err(
                node,
                "idp type google needs clientId and clientSecretFile, from the OAuth client created in the Google Cloud console",
            );
            return None;
        };
        let hosted_domain = get(&f, "hostedDomain")
            .and_then(|n| r.string(n, "idp.hostedDomain"))
            .map(|d| d.to_ascii_lowercase());
        if let Some(d) = &hosted_domain
            && !is_host_name(d)
        {
            r.err(
                node,
                format!("idp.hostedDomain {d:?} must be a domain name such as example.com"),
            );
        }
        let allowed_emails: Vec<String> = get(&f, "allowedEmails")
            .map(|n| r.strings(n, "idp.allowedEmails"))
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.to_ascii_lowercase())
            .collect();
        if let Some(bad) = allowed_emails.iter().find(|e| !e.contains('@')) {
            r.err(
                node,
                format!("idp.allowedEmails entry {bad:?} is not an email address"),
            );
        }
        return Some(Idp {
            kind,
            display_name: display_name.unwrap_or_else(|| "Google".into()),
            issuer: GOOGLE_ISSUER.into(),
            issuer_aliases: vec!["accounts.google.com".into()],
            endpoints: Some(Endpoints {
                authorization: "https://accounts.google.com/o/oauth2/v2/auth".into(),
                token: "https://oauth2.googleapis.com/token".into(),
                jwks: "https://www.googleapis.com/oauth2/v3/certs".into(),
            }),
            client_id,
            client_secret_file: Some(client_secret_file),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            groups_claim: String::new(),
            ca_file: None,
            mfa_amr_values: Vec::new(),
            mfa_acr_values: Vec::new(),
            hosted_domain,
            allowed_emails,
        });
    }
    for key in ["hostedDomain", "allowedEmails"] {
        if let Some(n) = get(&f, key) {
            r.err(n, format!("idp.{key} applies only to type google"));
        }
    }
    let issuer = get(&f, "issuer").and_then(|n| r.string(n, "idp.issuer"));
    let (Some(issuer), Some(client_id)) = (issuer, client_id) else {
        r.err(node, "idp needs issuer and clientId");
        return None;
    };
    if !issuer.starts_with("https://") {
        r.err(node, "idp.issuer must be an https:// URL");
        return None;
    }
    let scopes = get(&f, "scopes")
        .map(|n| r.strings(n, "idp.scopes"))
        .unwrap_or_else(|| {
            vec![
                "openid".into(),
                "email".into(),
                "profile".into(),
                "groups".into(),
            ]
        });
    if !scopes.iter().any(|s| s == "openid") {
        r.err(node, "idp.scopes must include openid");
    }
    Some(Idp {
        kind,
        display_name: display_name.unwrap_or_else(|| "your identity provider".into()),
        issuer: issuer.trim_end_matches('/').to_owned(),
        issuer_aliases: Vec::new(),
        endpoints: None,
        client_id,
        client_secret_file,
        scopes,
        groups_claim: get(&f, "groupsClaim")
            .and_then(|n| r.string(n, "idp.groupsClaim"))
            .unwrap_or_else(|| "groups".into()),
        ca_file: get(&f, "caFile")
            .and_then(|n| r.string(n, "idp.caFile"))
            .map(PathBuf::from),
        mfa_amr_values: get(&f, "mfaAmrValues")
            .map(|n| r.strings(n, "idp.mfaAmrValues"))
            .unwrap_or_else(|| vec!["mfa".into()]),
        mfa_acr_values: get(&f, "mfaAcrValues")
            .map(|n| r.strings(n, "idp.mfaAcrValues"))
            .unwrap_or_default(),
        hosted_domain: None,
        allowed_emails: Vec::new(),
    })
}

fn parse_local_accounts(r: &mut Reader, node: &Node, out: &mut LocalAccounts) {
    let f = r.map(
        node,
        "localAccounts",
        &["enabled", "bootstrapAdmin", "maxFailuresPerSource"],
    );
    if let Some(n) = get(&f, "maxFailuresPerSource") {
        match r
            .string(n, "localAccounts.maxFailuresPerSource")
            .map(|t| t.parse::<u32>())
        {
            Some(Ok(limit)) => out.max_failures_per_source = limit,
            Some(Err(_)) => r.err(
                n,
                "localAccounts.maxFailuresPerSource must be a whole number; 0 means no limit",
            ),
            None => {}
        }
    }
    if let Some(n) = get(&f, "enabled") {
        match r.string(n, "localAccounts.enabled").as_deref() {
            Some("true") => out.enabled = true,
            Some("false") => out.enabled = false,
            Some(other) => r.err(
                n,
                format!("localAccounts.enabled {other:?} must be true or false"),
            ),
            None => {}
        }
    }
    let Some(n) = get(&f, "bootstrapAdmin") else {
        return;
    };
    let bf = r.map(
        n,
        "localAccounts.bootstrapAdmin",
        &["username", "passwordFile", "email", "groups"],
    );
    let username = get(&bf, "username")
        .and_then(|u| r.string(u, "bootstrapAdmin.username"))
        .unwrap_or_else(|| "admin".into());
    if !warren_core::identity::valid_id(&username) {
        r.err(
            n,
            format!(
                "bootstrapAdmin.username {username:?} must be 1 to 63 lowercase letters, digits and '-'"
            ),
        );
    }
    let Some(password_file) =
        get(&bf, "passwordFile").and_then(|p| r.string(p, "bootstrapAdmin.passwordFile"))
    else {
        r.err(
            n,
            "localAccounts.bootstrapAdmin needs passwordFile, a mounted secret holding the first password",
        );
        return;
    };
    let email = get(&bf, "email")
        .and_then(|e| r.string(e, "bootstrapAdmin.email"))
        .map(|e| e.to_ascii_lowercase());
    let groups = get(&bf, "groups")
        .map(|g| r.strings(g, "bootstrapAdmin.groups"))
        .unwrap_or_else(|| vec!["admins".into()]);
    if let Some(bad) = groups.iter().find(|g| !warren_core::identity::valid_id(g)) {
        r.err(
            n,
            format!("bootstrapAdmin.groups entry {bad:?} must be a local group name"),
        );
    }
    if !out.enabled {
        r.err(
            n,
            "localAccounts.bootstrapAdmin needs localAccounts enabled",
        );
    }
    out.bootstrap_admin = Some(BootstrapAdmin {
        username,
        password_file: password_file.into(),
        email,
        groups,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "trustDomain: example.com\npublicUrl: https://warren.example.com\npolicyDir: policy\nidp:\n  issuer: https://idp.example.com/\n  clientId: warren\n";

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.public_host, "warren.example.com");
        let idp = c.idp.as_ref().unwrap();
        assert_eq!(idp.issuer, "https://idp.example.com");
        assert_eq!(idp.kind, IdpKind::Oidc);
        assert!(idp.endpoints.is_none());
        assert!(c.local_accounts.enabled);
        assert!(c.local_accounts.bootstrap_admin.is_none());
        assert_eq!(c.client_cert_lifetime, CLIENT_CERT_LIFETIME);
        assert_eq!(c.device_approval, Approval::Manual);
        assert_eq!(c.database, PathBuf::from("/var/lib/warren/warren.db"));
        assert_eq!(c.reserved(), ["warren.example.com", "idp.example.com"]);
    }

    #[test]
    fn connection_limits_and_trusted_proxies() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.connections, ListenOptions::default());
        assert_eq!(c.connections.max_per_source, 64);
        let c = Config::parse(&format!(
            "{MINIMAL}connections:\n  maxPerSource: 0\n  trustedProxies: [10.0.0.0/8, \"fd00::1\"]\n"
        ))
        .unwrap();
        assert_eq!(c.connections.max_per_source, 0);
        assert_eq!(c.connections.trusted_proxies.len(), 2);
        let e = Config::parse(&format!("{MINIMAL}connections:\n  maxPerSource: -1\n")).unwrap_err();
        assert!(e.contains("maxPerSource"), "{e}");
        let e = Config::parse(&format!(
            "{MINIMAL}connections:\n  trustedProxies: [10.0.0.1/8]\n"
        ))
        .unwrap_err();
        assert!(e.contains("trustedProxies"), "{e}");
    }

    #[test]
    fn bounds_are_enforced() {
        let e =
            Config::parse(&format!("{MINIMAL}certificates:\n  clientLifetime: 5h\n")).unwrap_err();
        assert!(e.contains("at most 4h"), "{e}");
        let e = Config::parse(&format!(
            "{MINIMAL}certificates:\n  clockSkewAllowance: 3m\n"
        ))
        .unwrap_err();
        assert!(e.contains("at most 2m"), "{e}");
        let ok = Config::parse(&format!("{MINIMAL}certificates:\n  clientLifetime: 1h\n")).unwrap();
        assert_eq!(ok.client_cert_lifetime, Duration::from_secs(3600));
    }

    #[test]
    fn mistakes_are_reported_with_lines() {
        let e = Config::parse(&format!("{MINIMAL}colour: blue\n")).unwrap_err();
        assert!(e.contains("line 7") && e.contains("colour"), "{e}");
        let e = Config::parse(&MINIMAL.replace("https://warren", "http://warren")).unwrap_err();
        assert!(e.contains("publicUrl"), "{e}");
        assert!(Config::parse(&MINIMAL.replace("trustDomain: example.com\n", "")).is_err());
    }

    #[test]
    fn issuers_with_paths_reserve_their_host() {
        let c = Config::parse(&MINIMAL.replace(
            "https://idp.example.com/",
            "https://login.example.com/realms/corp",
        ))
        .unwrap();
        assert!(c.reserved().contains(&"login.example.com".to_owned()));
        assert_eq!(
            url_host("https://a.example.com:8443/x?y").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(url_host("https://u@a.example.com/"), None);
    }

    #[test]
    fn names_and_lifetimes_are_checked() {
        let e = Config::parse(&format!("{MINIMAL}dnsNames: [\"*.example.com\"]\n")).unwrap_err();
        assert!(e.contains("dnsNames"), "{e}");
        let e = Config::parse(&format!("{MINIMAL}reservedNames: [cp.example.com.]\n")).unwrap_err();
        assert!(e.contains("reservedNames"), "{e}");
        let e =
            Config::parse(&format!("{MINIMAL}signIn:\n  sessionMaxLifetime: 1000d\n")).unwrap_err();
        assert!(e.contains("90d"), "{e}");
    }

    #[test]
    fn operator_certificates_need_both_files_and_an_internal_name() {
        let tls = "tls:\n  certFile: tls/cert.pem\n  keyFile: /etc/warren/key.pem\n";
        let mut c = Config::parse(&format!(
            "{MINIMAL}dnsNames: [nodes.warren.example.com]\n{tls}"
        ))
        .unwrap();
        c.resolve_paths(Path::new("/srv/warren"));
        assert_eq!(
            c.tls,
            Some(TlsFiles {
                cert_file: "/srv/warren/tls/cert.pem".into(),
                key_file: "/etc/warren/key.pem".into(),
            })
        );
        assert_eq!(c.internal_url(), "https://nodes.warren.example.com");
        assert!(c.presents_own_certificate(Some("Nodes.Warren.Example.com")));
        assert!(!c.presents_own_certificate(Some("warren.example.com")));
        assert!(!c.presents_own_certificate(None));
        let plain = Config::parse(MINIMAL).unwrap();
        assert_eq!(plain.tls, None);
        assert_eq!(plain.internal_url(), "https://warren.example.com");
        assert_eq!(plain.internal_endpoint(), "warren.example.com:443");
        assert!(plain.presents_own_certificate(Some("warren.example.com")));

        // The host is compared and given out lowercase, whatever case the
        // operator wrote it in; the port carries over.
        let mixed = Config::parse(&MINIMAL.replace(
            "https://warren.example.com",
            "https://Warren.Example.com:8443",
        ))
        .unwrap();
        assert_eq!(mixed.internal_endpoint(), "warren.example.com:8443");
        assert_eq!(mixed.internal_url(), "https://warren.example.com:8443");
        let mut mixed_tls = Config::parse(&format!(
            "{}dnsNames: [nodes.warren.example.com]\n{tls}",
            MINIMAL.replace(
                "https://warren.example.com",
                "https://Warren.Example.com:8443"
            )
        ))
        .unwrap();
        mixed_tls.resolve_paths(Path::new("/srv/warren"));
        assert_eq!(
            mixed_tls.internal_endpoint(),
            "nodes.warren.example.com:8443"
        );
        assert_eq!(
            mixed_tls.internal_url(),
            "https://nodes.warren.example.com:8443"
        );

        let e = Config::parse(&format!(
            "{MINIMAL}dnsNames: [nodes.warren.example.com]\ntls:\n  certFile: cert.pem\n"
        ))
        .unwrap_err();
        assert!(
            e.contains("line 9") && e.contains("both certFile and keyFile"),
            "{e}"
        );
        let e = Config::parse(&format!(
            "{MINIMAL}dnsNames: [nodes.warren.example.com]\ntls:\n  keyFile: key.pem\n"
        ))
        .unwrap_err();
        assert!(e.contains("both certFile and keyFile"), "{e}");
        let e =
            Config::parse(&format!("{MINIMAL}tls:\n  certFile: c\n  keyFile: k\n")).unwrap_err();
        assert!(e.contains("dnsNames"), "{e}");
        let e = Config::parse(&format!(
            "{MINIMAL}dnsNames: [warren.example.com]\ntls:\n  certFile: c\n  keyFile: k\n"
        ))
        .unwrap_err();
        assert!(e.contains("dnsNames"), "{e}");
        let e = Config::parse(&format!(
            "{MINIMAL}dnsNames: [nodes.warren.example.com]\ntls:\n  certFile: c\n  keyFile: k\n  chain: x\n"
        ))
        .unwrap_err();
        assert!(e.contains("chain"), "{e}");
    }

    #[test]
    fn console_settings() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.console, Console::default());
        let c = Config::parse(&format!(
            "{MINIMAL}console:\n  admins:\n    users: [ada@example.com]\n    groups: [warren-admins]\n  sessionLifetime: 8h\n  changeMaxAge: 30m\n"
        ))
        .unwrap();
        assert_eq!(c.console.admin_users, ["ada@example.com"]);
        assert_eq!(c.console.admin_groups, ["warren-admins"]);
        assert_eq!(c.console.session_lifetime, Duration::from_secs(8 * 3600));
        assert_eq!(c.console.change_max_age, Duration::from_secs(1800));
        for (bad, why) in [
            ("console:\n  requireMfa: false\n", "requireMfa"),
            ("console:\n  sessionLifetime: 2d\n", "24h"),
            ("console:\n  changeMaxAge: 13h\n", "changeMaxAge"),
            ("console:\n  admins:\n    roles: [x]\n", "roles"),
        ] {
            let e = Config::parse(&format!("{MINIMAL}{bad}")).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }

    #[test]
    fn the_google_preset() {
        let base =
            "trustDomain: example.com\npublicUrl: https://warren.example.com\npolicyDir: policy\n";
        let mut c = Config::parse(&format!(
            "{base}idp:\n  type: google\n  clientId: 123.apps.googleusercontent.com\n  clientSecretFile: google-secret\n  hostedDomain: Example.com\n  allowedEmails: [Contractor@Gmail.com]\n"
        ))
        .unwrap();
        c.resolve_paths(Path::new("/etc/warren"));
        let idp = c.idp.as_ref().unwrap();
        assert_eq!(idp.kind, IdpKind::Google);
        assert_eq!(idp.issuer, GOOGLE_ISSUER);
        assert!(idp.issued_by("accounts.google.com"));
        assert!(idp.issued_by("https://accounts.google.com"));
        assert!(!idp.issued_by("https://accounts.google.com.evil.example"));
        let endpoints = idp.endpoints.as_ref().unwrap();
        assert!(
            endpoints
                .authorization
                .starts_with("https://accounts.google.com/")
        );
        assert_eq!(idp.scopes, ["openid", "email", "profile"]);
        assert_eq!(idp.hosted_domain.as_deref(), Some("example.com"));
        assert_eq!(idp.allowed_emails, ["contractor@gmail.com"]);
        assert_eq!(
            idp.client_secret_file.as_deref(),
            Some(Path::new("/etc/warren/google-secret"))
        );
        assert_eq!(idp.display_name, "Google");

        // A client secret is required, and the preset cannot be changed.
        let e = Config::parse(&format!("{base}idp:\n  type: google\n  clientId: x\n")).unwrap_err();
        assert!(e.contains("clientSecretFile"), "{e}");
        let e = Config::parse(&format!(
            "{base}idp:\n  type: google\n  clientId: x\n  clientSecretFile: s\n  issuer: https://evil.example\n"
        ))
        .unwrap_err();
        assert!(e.contains("preset"), "{e}");
        let e = Config::parse(&format!(
            "{base}idp:\n  issuer: https://idp.example.com\n  clientId: x\n  hostedDomain: example.com\n"
        ))
        .unwrap_err();
        assert!(e.contains("only to type google"), "{e}");
        let e = Config::parse(&format!("{base}idp:\n  type: saml\n")).unwrap_err();
        assert!(e.contains("oidc or google"), "{e}");
    }

    #[test]
    fn local_accounts_and_the_bootstrap_admin() {
        let base =
            "trustDomain: example.com\npublicUrl: https://warren.example.com\npolicyDir: policy\n";
        // Built-in accounts alone are enough to sign in.
        let c = Config::parse(base).unwrap();
        assert!(c.idp.is_none());
        assert!(c.local_accounts.enabled);
        assert_eq!(c.local_accounts.max_failures_per_source, 20);
        assert_eq!(c.reserved(), ["warren.example.com"]);
        for (value, limit) in [("0", 0), ("200", 200)] {
            let c = Config::parse(&format!(
                "{base}localAccounts:\n  maxFailuresPerSource: {value}\n"
            ))
            .unwrap();
            assert_eq!(c.local_accounts.max_failures_per_source, limit);
        }
        let e = Config::parse(&format!(
            "{base}localAccounts:\n  maxFailuresPerSource: -1\n"
        ))
        .unwrap_err();
        assert!(e.contains("maxFailuresPerSource"), "{e}");
        let e = Config::parse(&format!("{base}localAccounts:\n  enabled: false\n")).unwrap_err();
        assert!(e.contains("nobody could sign in"), "{e}");

        let mut c = Config::parse(&format!(
            "{base}localAccounts:\n  bootstrapAdmin:\n    passwordFile: secrets/admin-password\n"
        ))
        .unwrap();
        c.resolve_paths(Path::new("/etc/warren"));
        let admin = c.local_accounts.bootstrap_admin.unwrap();
        assert_eq!(admin.username, "admin");
        assert_eq!(admin.groups, ["admins"]);
        assert_eq!(
            admin.password_file,
            PathBuf::from("/etc/warren/secrets/admin-password")
        );
        let e = Config::parse(&format!(
            "{base}localAccounts:\n  bootstrapAdmin:\n    username: Admin\n    passwordFile: p\n"
        ))
        .unwrap_err();
        assert!(e.contains("bootstrapAdmin.username"), "{e}");
        let e = Config::parse(&format!(
            "{base}localAccounts:\n  bootstrapAdmin:\n    username: root\n"
        ))
        .unwrap_err();
        assert!(e.contains("passwordFile"), "{e}");
        let e = Config::parse(&format!(
            "{MINIMAL}localAccounts:\n  enabled: false\n  bootstrapAdmin:\n    passwordFile: p\n"
        ))
        .unwrap_err();
        assert!(e.contains("needs localAccounts enabled"), "{e}");
    }

    #[test]
    fn https_hosts() {
        assert_eq!(
            https_host("https://a.example.com:8443").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(
            https_host("https://127.0.0.1:8443").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(https_host("https://a.example.com/x"), None);
        assert_eq!(https_host("http://a.example.com"), None);
        assert_eq!(https_host("https://u@a.example.com"), None);
    }
}
