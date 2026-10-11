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

/// `authTime` when the IdP did not report when the user authenticated:
/// freshness is unknown, and the sign-in counts as older than any
/// `auth.maxAge`, so freshness-gated rules ask the user to sign in again.
pub const AUTH_TIME_UNKNOWN: u64 = 0;

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

/// Whether `s` is a valid name or identifier: 1 to 63 characters of
/// lowercase letters, digits and `-`, starting and ending with a letter or
/// digit (a DNS label). Users, devices, nodes, connector groups and policy
/// objects are all named this way, so a name sits in a URI path segment, a
/// certificate or a Cedar entity ID without escaping, and two spellings of
/// one name cannot differ only in case.
pub fn valid_id(s: &str) -> bool {
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
pub fn valid_trust_domain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.split('.').all(valid_id)
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
    fn names_are_lowercase_dns_labels() {
        for ok in ["a", "grafana", "lab-web", "u-0123abcd", &"x".repeat(63)] {
            assert!(valid_id(ok), "{ok}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "Grafana",
            "a_b",
            "a.b",
            "\u{e9}",
            &"x".repeat(64),
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
        assert!(valid_trust_domain("example.com"));
        assert!(!valid_trust_domain("example..com"));
        assert!(!valid_trust_domain("Example.com"));
        assert!(!valid_trust_domain("a-.example.com"));
    }
}
