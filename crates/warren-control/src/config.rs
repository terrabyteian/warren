//! The control plane's configuration file.
//!
//! One YAML document, read with the same strict reader as policy, so
//! mistakes are reported with their line. Values that are bounded by a
//! guarantee (certificate lifetime, clock skew) are refused beyond the bound.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use warren_core::identity::is_valid_trust_domain;
use warren_core::params::{CLIENT_CERT_LIFETIME, CLOCK_SKEW_ALLOWANCE};
use warren_policy::model::parse_duration;
use warren_policy::names::{Cidr, is_host_name};
use warren_policy::yaml::{self, Node, Value};

use crate::Error;

/// How new devices are approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// Every enrolled device is approved at once.
    Automatic,
    /// An admin approves each device.
    Manual,
}

/// The identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Idp {
    /// The OIDC issuer URL; discovery is fetched from
    /// `{issuer}/.well-known/openid-configuration`.
    pub issuer: String,
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
}

/// The control plane's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The deployment's trust domain, used in every identity URI.
    pub trust_domain: String,
    /// The organization URL clients are given, `https://host[:port]`.
    pub public_url: String,
    /// The host of `public_url`, reserved so no app can claim it.
    pub public_host: String,
    /// More DNS names for the control plane's certificate.
    pub dns_names: Vec<String>,
    /// Where the HTTPS API listens.
    pub listen: SocketAddr,
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
    /// The identity provider.
    pub idp: Idp,
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
}

const KEYS: &[&str] = &[
    "trustDomain",
    "publicUrl",
    "dnsNames",
    "listen",
    "adminSocket",
    "dataDir",
    "database",
    "keyEncryptionKeyFile",
    "policyDir",
    "idp",
    "signIn",
    "devices",
    "certificates",
    "audit",
    "reservedNames",
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
        if !trust_domain.is_empty() && !is_valid_trust_domain(&trust_domain) {
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
            .map(|n| r.strings(n, "dnsNames"))
            .unwrap_or_default();
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
        let admin_socket = path_or(&mut r, "adminSocket", data_dir.join("admin.sock"));
        let database = path_or(&mut r, "database", data_dir.join("warren.db"));
        let kek_file = path_or(&mut r, "keyEncryptionKeyFile", data_dir.join("kek"));
        let policy_dir = PathBuf::from(required(&mut r, "policyDir").unwrap_or_default());

        let idp = match get(&f, "idp") {
            Some(n) => parse_idp(&mut r, n),
            None => {
                r.errors.push("idp is required".into());
                None
            }
        };

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
                session_max_lifetime = d;
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
            .map(|n| r.strings(n, "reservedNames"))
            .unwrap_or_default();

        if !r.errors.is_empty() {
            return Err(r.errors.join("; "));
        }
        let idp = idp.ok_or("idp is invalid")?;
        Ok(Config {
            trust_domain,
            public_url,
            public_host,
            dns_names,
            listen,
            admin_socket,
            data_dir,
            database,
            kek_file,
            policy_dir,
            idp,
            redirect_uris,
            session_max_lifetime,
            device_approval,
            device_pool_v4,
            device_pool_v6,
            client_cert_lifetime,
            clock_skew,
            audit_file,
            reserved_names,
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
        for p in [
            &mut self.idp.client_secret_file,
            &mut self.idp.ca_file,
            &mut self.audit_file,
        ]
        .into_iter()
        .flatten()
        {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
    }

    /// The control plane's own names, which no app may claim: its host, its
    /// extra DNS names, the IdP's host and any configured reserved names.
    pub fn reserved(&self) -> Vec<String> {
        let mut names = vec![self.public_host.clone()];
        names.extend(self.dns_names.iter().cloned());
        names.extend(https_host(&self.idp.issuer));
        names.extend(self.reserved_names.iter().cloned());
        names
    }
}

fn parse_idp(r: &mut Reader, node: &Node) -> Option<Idp> {
    let f = r.map(
        node,
        "idp",
        &[
            "issuer",
            "clientId",
            "clientSecretFile",
            "scopes",
            "groupsClaim",
            "caFile",
            "mfaAmrValues",
            "mfaAcrValues",
        ],
    );
    let issuer = get(&f, "issuer").and_then(|n| r.string(n, "idp.issuer"));
    let client_id = get(&f, "clientId").and_then(|n| r.string(n, "idp.clientId"));
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
        issuer: issuer.trim_end_matches('/').to_owned(),
        client_id,
        client_secret_file: get(&f, "clientSecretFile")
            .and_then(|n| r.string(n, "idp.clientSecretFile"))
            .map(PathBuf::from),
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "trustDomain: example.com\npublicUrl: https://warren.example.com\npolicyDir: policy\nidp:\n  issuer: https://idp.example.com/\n  clientId: warren\n";

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.public_host, "warren.example.com");
        assert_eq!(c.idp.issuer, "https://idp.example.com");
        assert_eq!(c.client_cert_lifetime, CLIENT_CERT_LIFETIME);
        assert_eq!(c.device_approval, Approval::Manual);
        assert_eq!(c.database, PathBuf::from("/var/lib/warren/warren.db"));
        assert_eq!(c.reserved(), ["warren.example.com", "idp.example.com"]);
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
