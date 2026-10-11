//! warren identities: the `warren://` URIs in certificate SANs, the warren
//! identity extension of user+device certificates, and the names of things
//! in a deployment (docs/protocol.md section 10).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::der::{self, Reader, tag};

/// `WARREN_OID_ARC`: a UUID-based arc (ITU-T X.667, `2.25.n`), which needs
/// no registration. The UUID is 49308b39-041c-46e4-b975-76e84488b505.
pub const WARREN_OID_ARC: [u128; 3] = [2, 25, 97_285_697_713_720_826_090_513_308_506_181_383_429];

/// The warren identity extension: `WARREN_OID_ARC.1`.
pub fn identity_extension_oid() -> Vec<u8> {
    let mut arcs = WARREN_OID_ARC.to_vec();
    arcs.push(1);
    der::oid_value(&arcs)
}

/// A device's enrollment trust class (docs/design.md section 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustClass {
    /// Observed by the client.
    DeviceReported = 1,
    /// Confirmed by an integration such as an MDM.
    ServerVerified = 2,
    /// Backed by a hardware attestation chain.
    HardwareAttested = 3,
}

impl TrustClass {
    /// The class with this `trustClass` value, if any.
    pub fn from_u64(v: u64) -> Option<TrustClass> {
        match v {
            1 => Some(TrustClass::DeviceReported),
            2 => Some(TrustClass::ServerVerified),
            3 => Some(TrustClass::HardwareAttested),
            _ => None,
        }
    }

    /// The name used in policy and audit.
    pub fn as_str(self) -> &'static str {
        match self {
            TrustClass::DeviceReported => "device-reported",
            TrustClass::ServerVerified => "server-verified",
            TrustClass::HardwareAttested => "hardware-attested",
        }
    }
}

/// The contents of the warren identity extension.
///
/// ```text
/// WarrenIdentity ::= SEQUENCE {
///   version          INTEGER (1),
///   sessionId        UTF8String,
///   authTime         INTEGER,      -- IdP authentication, Unix seconds
///   mfa              BOOLEAN,      -- from the IdP's amr/acr
///   trustClass       ENUMERATED { deviceReported(1), serverVerified(2),
///                                 hardwareAttested(3) },
///   tunnelAddresses  SEQUENCE OF OCTET STRING  -- 4 or 16 octets each
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarrenIdentity {
    /// The sign-in session the certificate was issued under.
    pub session_id: String,
    /// When the user last authenticated at the IdP, Unix seconds.
    pub auth_time: u64,
    /// Whether that authentication used MFA.
    pub mfa: bool,
    /// The device's enrollment trust class.
    pub trust_class: TrustClass,
    /// The device's IPv4 tunnel address.
    pub tunnel_v4: Ipv4Addr,
    /// The device's IPv6 tunnel address.
    pub tunnel_v6: Ipv6Addr,
}

/// An identity encoding or naming error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityError(pub String);

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IdentityError {}

impl From<der::DerError> for IdentityError {
    fn from(e: der::DerError) -> Self {
        IdentityError(e.to_string())
    }
}

impl WarrenIdentity {
    /// Encodes the extension value.
    pub fn to_der(&self) -> Vec<u8> {
        let addrs = der::sequence(&[
            &der::tlv(tag::OCTET_STRING, &self.tunnel_v4.octets()),
            &der::tlv(tag::OCTET_STRING, &self.tunnel_v6.octets()),
        ]);
        der::sequence(&[
            &der::uint(tag::INTEGER, 1),
            &der::tlv(tag::UTF8_STRING, self.session_id.as_bytes()),
            &der::uint(tag::INTEGER, self.auth_time),
            &der::boolean(self.mfa),
            &der::uint(tag::ENUMERATED, self.trust_class as u64),
            &addrs,
        ])
    }

    /// Decodes the extension value. Exactly one IPv4 and one IPv6 tunnel
    /// address are required.
    pub fn from_der(value: &[u8]) -> Result<WarrenIdentity, IdentityError> {
        let mut outer = Reader::new(value);
        let mut r = Reader::new(outer.read(tag::SEQUENCE)?);
        outer.finish()?;
        if r.read_u64(tag::INTEGER)? != 1 {
            return Err(IdentityError(
                "unsupported identity extension version".into(),
            ));
        }
        let session_id = std::str::from_utf8(r.read(tag::UTF8_STRING)?)
            .map_err(|_| IdentityError("session ID is not UTF-8".into()))?
            .to_owned();
        if session_id.is_empty() || session_id.len() > 128 {
            return Err(IdentityError("session ID length out of range".into()));
        }
        let auth_time = r.read_u64(tag::INTEGER)?;
        let mfa = r.read_bool()?;
        let trust_class = TrustClass::from_u64(r.read_u64(tag::ENUMERATED)?)
            .ok_or_else(|| IdentityError("unknown trust class".into()))?;
        let mut addrs = Reader::new(r.read(tag::SEQUENCE)?);
        let (mut v4, mut v6) = (None, None);
        while !addrs.is_empty() {
            match addrs.read(tag::OCTET_STRING)? {
                b if b.len() == 4 && v4.is_none() => {
                    v4 = Some(Ipv4Addr::from(
                        <[u8; 4]>::try_from(b).expect("length checked"),
                    ));
                }
                b if b.len() == 16 && v6.is_none() => {
                    v6 = Some(Ipv6Addr::from(
                        <[u8; 16]>::try_from(b).expect("length checked"),
                    ));
                }
                _ => return Err(IdentityError("invalid or repeated tunnel address".into())),
            }
        }
        // Later versions may append fields; they are ignored.
        let (Some(tunnel_v4), Some(tunnel_v6)) = (v4, v6) else {
            return Err(IdentityError(
                "an IPv4 and an IPv6 tunnel address are required".into(),
            ));
        };
        Ok(WarrenIdentity {
            session_id,
            auth_time,
            mfa,
            trust_class,
            tunnel_v4,
            tunnel_v6,
        })
    }

    /// The tunnel addresses.
    pub fn tunnel_addresses(&self) -> [IpAddr; 2] {
        [IpAddr::V4(self.tunnel_v4), IpAddr::V6(self.tunnel_v6)]
    }
}

/// A role an infrastructure certificate names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeRole {
    /// A relay.
    Relay,
    /// A connector in a connector group.
    Connector {
        /// The connector group.
        group: String,
    },
    /// The control plane.
    ControlPlane,
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeRole::Relay => f.write_str("relay"),
            NodeRole::Connector { group } => write!(f, "connector/{group}"),
            NodeRole::ControlPlane => f.write_str("control-plane"),
        }
    }
}

/// A parsed `warren://{td}/...` URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WarrenUri {
    /// `warren://{td}/user/{id}`.
    User {
        /// Trust domain.
        td: String,
        /// User ID.
        id: String,
    },
    /// `warren://{td}/device/{id}`.
    Device {
        /// Trust domain.
        td: String,
        /// Device ID.
        id: String,
    },
    /// `warren://{td}/relay/{id}`, `warren://{td}/connector/{group}/{id}` or
    /// `warren://{td}/control-plane/{id}`.
    Node {
        /// Trust domain.
        td: String,
        /// Role.
        role: NodeRole,
        /// Node ID.
        id: String,
    },
}

/// Whether `s` is a valid identifier segment: 1 to 128 characters from
/// `[A-Za-z0-9._-]`.
pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `s` is a valid trust domain: a lowercase DNS-style name.
pub fn valid_trust_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

impl WarrenUri {
    /// Parses a URI; `None` if it is not a well-formed warren URI.
    pub fn parse(uri: &str) -> Option<WarrenUri> {
        let rest = uri.strip_prefix("warren://")?;
        let mut parts = rest.split('/');
        let td = parts.next()?.to_owned();
        if !valid_trust_domain(&td) {
            return None;
        }
        let kind = parts.next()?;
        let a = parts.next()?;
        let b = parts.next();
        let parsed = match (kind, b) {
            ("user", None) => WarrenUri::User { td, id: a.into() },
            ("device", None) => WarrenUri::Device { td, id: a.into() },
            ("relay", None) => WarrenUri::Node {
                td,
                role: NodeRole::Relay,
                id: a.into(),
            },
            ("control-plane", None) => WarrenUri::Node {
                td,
                role: NodeRole::ControlPlane,
                id: a.into(),
            },
            ("connector", Some(id)) if valid_id(a) => WarrenUri::Node {
                td,
                role: NodeRole::Connector { group: a.into() },
                id: id.into(),
            },
            _ => return None,
        };
        if parts.next().is_some() {
            return None;
        }
        let id = match &parsed {
            WarrenUri::User { id, .. }
            | WarrenUri::Device { id, .. }
            | WarrenUri::Node { id, .. } => id,
        };
        valid_id(id).then_some(parsed)
    }

    /// The trust domain.
    pub fn trust_domain(&self) -> &str {
        match self {
            WarrenUri::User { td, .. }
            | WarrenUri::Device { td, .. }
            | WarrenUri::Node { td, .. } => td,
        }
    }
}

impl fmt::Display for WarrenUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WarrenUri::User { td, id } => write!(f, "warren://{td}/user/{id}"),
            WarrenUri::Device { td, id } => write!(f, "warren://{td}/device/{id}"),
            WarrenUri::Node { td, role, id } => write!(f, "warren://{td}/{role}/{id}"),
        }
    }
}

/// A malformed name or identity URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameError(pub String);

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NameError {}

/// Whether `s` is a valid object name: 1 to 63 characters of lowercase
/// letters, digits and `-`, starting and ending with a letter or digit (a DNS
/// label). Policy objects, connector groups, nodes, users and devices are all
/// named this way, so a name can sit in a URI path segment or a Cedar entity
/// ID without escaping.
pub fn is_valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// Whether `s` is a valid trust domain: a lowercase DNS name of at most 253
/// characters whose labels are valid names.
pub fn is_valid_trust_domain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.split('.').all(is_valid_name)
}

/// The role of an infrastructure node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The control plane.
    ControlPlane,
    /// A relay.
    Relay,
    /// A connector.
    Connector,
}

impl Role {
    /// The role's name as it appears in URIs and APIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::ControlPlane => "control-plane",
            Role::Relay => "relay",
            Role::Connector => "connector",
        }
    }

    /// Parses a role name.
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "control-plane" => Some(Role::ControlPlane),
            "relay" => Some(Role::Relay),
            "connector" => Some(Role::Connector),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An identity named by a `warren://{td}/...` URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
    /// `warren://{td}/user/{id}`
    User(String),
    /// `warren://{td}/device/{id}`
    Device(String),
    /// `warren://{td}/relay/{id}` or `warren://{td}/control-plane/{id}`
    Node {
        /// Relay or control plane.
        role: Role,
        /// The node's ID.
        id: String,
    },
    /// `warren://{td}/connector/{group}/{id}`
    Connector {
        /// The connector group.
        group: String,
        /// The connector replica's ID.
        id: String,
    },
}

impl Principal {
    /// The URI for this principal in trust domain `td`.
    pub fn to_uri(&self, td: &str) -> String {
        match self {
            Principal::User(id) => format!("warren://{td}/user/{id}"),
            Principal::Device(id) => format!("warren://{td}/device/{id}"),
            Principal::Node { role, id } => format!("warren://{td}/{role}/{id}"),
            Principal::Connector { group, id } => format!("warren://{td}/connector/{group}/{id}"),
        }
    }

    /// Parses a URI, returning its trust domain and principal. Every name in
    /// it must be valid.
    pub fn parse_uri(uri: &str) -> Result<(String, Principal), NameError> {
        let bad = || NameError(format!("not a warren identity URI: {uri}"));
        let rest = uri.strip_prefix("warren://").ok_or_else(bad)?;
        let parts: Vec<&str> = rest.split('/').collect();
        let td = parts[0];
        if !is_valid_trust_domain(td) || !parts[1..].iter().all(|p| is_valid_name(p)) {
            return Err(bad());
        }
        let principal = match parts[1..] {
            ["user", id] => Principal::User(id.into()),
            ["device", id] => Principal::Device(id.into()),
            ["relay", id] => Principal::Node {
                role: Role::Relay,
                id: id.into(),
            },
            ["control-plane", id] => Principal::Node {
                role: Role::ControlPlane,
                id: id.into(),
            },
            ["connector", group, id] => Principal::Connector {
                group: group.into(),
                id: id.into(),
            },
            _ => return Err(bad()),
        };
        Ok((td.into(), principal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_extension_round_trips() {
        let id = WarrenIdentity {
            session_id: "s-123".into(),
            auth_time: 1_791_720_000,
            mfa: true,
            trust_class: TrustClass::HardwareAttested,
            tunnel_v4: "100.96.0.2".parse().unwrap(),
            tunnel_v6: "fd00:77::2".parse().unwrap(),
        };
        assert_eq!(WarrenIdentity::from_der(&id.to_der()).unwrap(), id);
    }

    #[test]
    fn identity_extension_requires_both_addresses() {
        let v4_only = der::sequence(&[
            &der::uint(tag::INTEGER, 1),
            &der::tlv(tag::UTF8_STRING, b"s"),
            &der::uint(tag::INTEGER, 1),
            &der::boolean(false),
            &der::uint(tag::ENUMERATED, 1),
            &der::sequence(&[&der::tlv(tag::OCTET_STRING, &[100, 96, 0, 2])]),
        ]);
        assert!(WarrenIdentity::from_der(&v4_only).is_err());
        assert!(WarrenIdentity::from_der(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn uris() {
        let cases = [
            "warren://example.test/user/alice",
            "warren://example.test/device/mac-01",
            "warren://example.test/relay/r1",
            "warren://example.test/connector/homelab/c1",
            "warren://example.test/control-plane/cp",
        ];
        for c in cases {
            let u = WarrenUri::parse(c).unwrap_or_else(|| panic!("{c}"));
            assert_eq!(u.to_string(), c);
            assert_eq!(u.trust_domain(), "example.test");
        }
        let bad = [
            "https://example.test/user/alice",
            "warren://Example.test/user/alice",
            "warren://example.test/user/",
            "warren://example.test/user/a/b",
            "warren://example.test/connector/homelab",
            "warren://example.test/admin/x",
            "warren://example.test/user/al ice",
            "warren://-bad.test/user/a",
        ];
        for b in bad {
            assert!(WarrenUri::parse(b).is_none(), "{b}");
        }
    }

    #[test]
    fn oid_arc_is_stable() {
        let oid = identity_extension_oid();
        assert_eq!(oid[0], 105);
        assert_eq!(*oid.last().unwrap(), 1);
    }

    #[test]
    fn names() {
        for ok in ["a", "grafana", "lab-web", "u-0123abcd", &"x".repeat(63)] {
            assert!(is_valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "Grafana",
            "a_b",
            "a.b",
            "é",
            &"x".repeat(64),
        ] {
            assert!(!is_valid_name(bad), "{bad}");
        }
        assert!(is_valid_trust_domain("example.com"));
        assert!(!is_valid_trust_domain("example..com"));
        assert!(!is_valid_trust_domain("Example.com"));
    }

    #[test]
    fn uris_round_trip() {
        let all = [
            Principal::User("u-1".into()),
            Principal::Device("d-1".into()),
            Principal::Node {
                role: Role::Relay,
                id: "r-1".into(),
            },
            Principal::Node {
                role: Role::ControlPlane,
                id: "cp".into(),
            },
            Principal::Connector {
                group: "homelab".into(),
                id: "c-1".into(),
            },
        ];
        for p in all {
            let uri = p.to_uri("example.com");
            assert_eq!(
                Principal::parse_uri(&uri).unwrap(),
                ("example.com".into(), p)
            );
        }
    }

    #[test]
    fn malformed_uris_are_rejected() {
        for bad in [
            "https://example.com/user/u-1",
            "warren://example.com/user",
            "warren://example.com/user/u-1/x",
            "warren://example.com/user/U-1",
            "warren://example.com/connector/g",
            "warren://example.com/admin/x",
            "warren:///user/u-1",
            "warren://example.com/user/u-1?x=1",
        ] {
            assert!(Principal::parse_uri(bad).is_err(), "{bad}");
        }
    }
}
