//! The extended CONNECT requests warren sends and accepts
//! (docs/protocol.md sections 4, 5 and 13), and refusals carrying a
//! `Proxy-Status` (RFC 9209).

use crate::http::{RequestHead, ResponseHead};

/// The header carrying the warren protocol version.
pub const WARREN_PROTOCOL: &str = "warren-protocol";
/// RFC 9297 `Capsule-Protocol`.
pub const CAPSULE_PROTOCOL: &str = "capsule-protocol";
/// The bound-UDP extension's request and response header.
pub const CONNECT_UDP_BIND: &str = "connect-udp-bind";
/// The bound-UDP extension's response header naming the proxy's address.
pub const PROXY_PUBLIC_ADDRESS: &str = "proxy-public-address";
/// RFC 9209.
pub const PROXY_STATUS: &str = "proxy-status";

/// The current protocol version and the oldest one accepted.
pub const PROTOCOL_VERSION: u32 = 1;
/// Oldest accepted version (`VERSION_SKEW`: current and previous).
pub const PROTOCOL_VERSION_MIN: u32 = 1;

/// The suffix of connector-group targets.
pub const GROUP_TARGET_SUFFIX: &str = ".connectors.warren.invalid";

/// The inner session's TLS server name and `:authority` for a group.
pub fn group_target(group: &str) -> String {
    format!("{group}{GROUP_TARGET_SUFFIX}")
}

fn base(authority: &str, protocol: &str, path: String) -> RequestHead {
    RequestHead {
        method: "CONNECT".into(),
        scheme: Some("https".into()),
        authority: Some(authority.into()),
        path: Some(path),
        protocol: Some(protocol.into()),
        headers: vec![
            (CAPSULE_PROTOCOL.into(), "?1".into()),
            (WARREN_PROTOCOL.into(), PROTOCOL_VERSION.to_string()),
        ],
    }
}

/// A client's CONNECT-UDP toward a connector group (link A).
pub fn udp_to_group(relay_authority: &str, group: &str) -> RequestHead {
    base(
        relay_authority,
        "connect-udp",
        format!("/.well-known/masque/udp/{}/443/", group_target(group)),
    )
}

/// A connector's bound CONNECT-UDP (link B).
pub fn udp_bind(relay_authority: &str) -> RequestHead {
    let mut h = base(
        relay_authority,
        "connect-udp",
        "/.well-known/masque/udp/%2A/%2A/".into(),
    );
    h.headers.push((CONNECT_UDP_BIND.into(), "?1".into()));
    h
}

/// The client's CONNECT-IP on the inner session (link C).
pub fn ip(group: &str) -> RequestHead {
    base(
        &group_target(group),
        "connect-ip",
        "/.well-known/masque/ip/*/*/".into(),
    )
}

/// What an accepted request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// CONNECT-UDP to a connector group.
    UdpToGroup {
        /// The group.
        group: String,
    },
    /// Bound CONNECT-UDP from a connector.
    UdpBind,
    /// CONNECT-IP.
    Ip,
}

/// A refusal: an HTTP status and a `Proxy-Status` error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// HTTP status code.
    pub status: u16,
    /// RFC 9209 error type.
    pub error: &'static str,
    /// Human-readable details.
    pub details: String,
}

impl Refusal {
    /// A refusal.
    pub fn new(status: u16, error: &'static str, details: impl Into<String>) -> Refusal {
        Refusal {
            status,
            error,
            details: details.into(),
        }
    }

    /// The response carrying it.
    pub fn response(&self, proxy: &str) -> ResponseHead {
        let details: String = self
            .details
            .chars()
            .filter(|c| (' '..='~').contains(c))
            .flat_map(|c| match c {
                '"' | '\\' => vec!['\\', c],
                c => vec![c],
            })
            .collect();
        ResponseHead::new(self.status).with(
            PROXY_STATUS,
            format!("{proxy}; error={}; details=\"{details}\"", self.error),
        )
    }

    /// Reads a refusal back from a response.
    pub fn from_response(head: &ResponseHead) -> Refusal {
        let mut r = Refusal::new(
            head.status,
            "http_request_error",
            format!("status {}", head.status),
        );
        let Some(ps) = head.header(PROXY_STATUS) else {
            return r;
        };
        for param in ps.split(';').skip(1).map(str::trim) {
            if let Some(e) = param.strip_prefix("error=") {
                r.error = known_error(e);
            } else if let Some(d) = param.strip_prefix("details=") {
                let d = d.trim_matches('"');
                let mut out = String::new();
                let mut chars = d.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        if let Some(n) = chars.next() {
                            out.push(n);
                        }
                    } else {
                        out.push(c);
                    }
                }
                r.details = out;
            }
        }
        r
    }
}

const ERRORS: [&str; 12] = [
    "destination_unavailable",
    "destination_not_found",
    "destination_ip_prohibited",
    "connection_refused",
    "connection_terminated",
    "connection_limit_reached",
    "tls_certificate_error",
    "http_request_error",
    "http_request_denied",
    "proxy_internal_error",
    "proxy_configuration_error",
    "proxy_loop_detected",
];

fn known_error(e: &str) -> &'static str {
    ERRORS
        .iter()
        .find(|k| **k == e)
        .copied()
        .unwrap_or("proxy_internal_error")
}

fn header<'a>(h: &'a RequestHead, name: &str) -> Option<&'a str> {
    h.header(name)
}

fn bad(details: impl Into<String>) -> Refusal {
    Refusal::new(400, "http_request_error", details)
}

/// Checks the common parts of a warren CONNECT request: method, scheme,
/// Capsule-Protocol and the protocol version.
fn check_common(h: &RequestHead) -> Result<(), Refusal> {
    if h.method != "CONNECT" || h.scheme.as_deref() != Some("https") {
        return Err(bad("expected an extended CONNECT over https"));
    }
    if header(h, CAPSULE_PROTOCOL) != Some("?1") {
        return Err(bad("Capsule-Protocol: ?1 is required"));
    }
    let version = header(h, WARREN_PROTOCOL).and_then(|v| v.trim().parse::<u32>().ok());
    match version {
        Some(v) if (PROTOCOL_VERSION_MIN..=PROTOCOL_VERSION).contains(&v) => Ok(()),
        _ => Err(bad(format!(
            "unsupported warren protocol version; supported: {PROTOCOL_VERSION_MIN}-{PROTOCOL_VERSION}"
        ))),
    }
}

fn is_star(s: &str) -> bool {
    s == "*" || s.eq_ignore_ascii_case("%2a")
}

/// Parses a request a relay receives.
pub fn parse_relay_request(h: &RequestHead) -> Result<Request, Refusal> {
    check_common(h)?;
    if h.protocol.as_deref() != Some("connect-udp") {
        return Err(bad("relays accept only connect-udp"));
    }
    let path = h.path.as_deref().unwrap_or_default();
    let rest = path
        .strip_prefix("/.well-known/masque/udp/")
        .ok_or_else(|| bad("unexpected CONNECT-UDP path"))?;
    let parts: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
    let [host, port] = parts[..] else {
        return Err(bad("unexpected CONNECT-UDP path"));
    };
    if !path.ends_with('/') {
        return Err(bad("unexpected CONNECT-UDP path"));
    }
    if is_star(host) && is_star(port) {
        if header(h, CONNECT_UDP_BIND) != Some("?1") {
            return Err(bad("a wildcard target requires Connect-UDP-Bind: ?1"));
        }
        return Ok(Request::UdpBind);
    }
    if is_star(host) || is_star(port) {
        return Err(bad(
            "target host and port must both be wildcards or neither",
        ));
    }
    // There is no egress besides connector groups: anything else is refused
    // (docs/protocol.md section 4.3, G8).
    let group = host
        .strip_suffix(GROUP_TARGET_SUFFIX)
        .filter(|g| warren_core::identity::valid_id(g))
        .ok_or_else(|| {
            Refusal::new(
                403,
                "destination_ip_prohibited",
                "relays forward only to connector groups",
            )
        })?;
    if port != "443" {
        return Err(Refusal::new(
            403,
            "destination_ip_prohibited",
            "connector groups are reached on port 443",
        ));
    }
    Ok(Request::UdpToGroup {
        group: group.to_owned(),
    })
}

/// Parses the CONNECT-IP request a connector receives on an inner session.
pub fn parse_connector_request(h: &RequestHead, group: &str) -> Result<Request, Refusal> {
    check_common(h)?;
    if h.protocol.as_deref() != Some("connect-ip") {
        return Err(bad("connectors accept only connect-ip"));
    }
    if h.authority.as_deref() != Some(group_target(group).as_str()) {
        return Err(Refusal::new(
            421,
            "destination_not_found",
            "this connector serves another group",
        ));
    }
    let path = h.path.as_deref().unwrap_or_default();
    let rest = path
        .strip_prefix("/.well-known/masque/ip/")
        .ok_or_else(|| bad("unexpected CONNECT-IP path"))?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts[..] {
        [t, p, ""] if is_star(t) && is_star(p) => Ok(Request::Ip),
        _ => Err(bad("CONNECT-IP is not scoped by target; use */*")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse() {
        assert_eq!(
            parse_relay_request(&udp_to_group("relay.example.test", "homelab")),
            Ok(Request::UdpToGroup {
                group: "homelab".into()
            })
        );
        assert_eq!(
            parse_relay_request(&udp_bind("relay.example.test")),
            Ok(Request::UdpBind)
        );
        assert_eq!(
            parse_connector_request(&ip("homelab"), "homelab"),
            Ok(Request::Ip)
        );
        assert_eq!(
            parse_connector_request(&ip("homelab"), "office")
                .unwrap_err()
                .status,
            421
        );
    }

    #[test]
    fn relays_are_not_open_proxies() {
        let mut h = udp_to_group("relay.example.test", "homelab");
        h.path = Some("/.well-known/masque/udp/10.0.0.1/53/".into());
        assert_eq!(parse_relay_request(&h).unwrap_err().status, 403);
        h.path = Some("/.well-known/masque/udp/homelab.connectors.warren.invalid/53/".into());
        assert_eq!(parse_relay_request(&h).unwrap_err().status, 403);
        h.path = Some("/.well-known/masque/udp/%2A/443/".into());
        assert_eq!(parse_relay_request(&h).unwrap_err().status, 400);
        let mut bind = udp_bind("relay.example.test");
        bind.headers.retain(|(n, _)| n != CONNECT_UDP_BIND);
        assert_eq!(parse_relay_request(&bind).unwrap_err().status, 400);
    }

    #[test]
    fn versions_and_capsule_protocol_are_required() {
        let mut h = udp_to_group("r", "g");
        h.headers.retain(|(n, _)| n != WARREN_PROTOCOL);
        assert!(parse_relay_request(&h).is_err());
        let mut h = udp_to_group("r", "g");
        h.headers[1].1 = "99".into();
        let r = parse_relay_request(&h).unwrap_err();
        assert!(r.details.contains("supported: 1-1"), "{}", r.details);
        let mut h = udp_to_group("r", "g");
        h.headers.retain(|(n, _)| n != CAPSULE_PROTOCOL);
        assert!(parse_relay_request(&h).is_err());
    }

    #[test]
    fn proxy_status_round_trips() {
        let r = Refusal::new(
            503,
            "destination_unavailable",
            "no replica of \"homelab\" is attached",
        );
        let back = Refusal::from_response(&r.response("warren-relay"));
        assert_eq!(back, r);
    }
}
