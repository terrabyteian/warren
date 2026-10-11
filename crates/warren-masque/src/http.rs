//! Request and response heads shared by the HTTP/3 and HTTP/2 carriers.

/// The head of an HTTP request: pseudo-header fields and header fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestHead {
    /// `:method`.
    pub method: String,
    /// `:scheme`.
    pub scheme: Option<String>,
    /// `:authority`.
    pub authority: Option<String>,
    /// `:path`.
    pub path: Option<String>,
    /// `:protocol` (extended CONNECT, RFC 8441 and RFC 9220).
    pub protocol: Option<String>,
    /// Header fields, names lowercase.
    pub headers: Vec<(String, String)>,
}

/// The head of an HTTP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseHead {
    /// `:status`.
    pub status: u16,
    /// Header fields, names lowercase.
    pub headers: Vec<(String, String)>,
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// A malformed message (H3_MESSAGE_ERROR, or a stream error in HTTP/2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageError(pub String);

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed HTTP message: {}", self.0)
    }
}

impl std::error::Error for MessageError {}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.!#$%&'*+^`|~".contains(&b)
        })
}

fn valid_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
        && !value.starts_with([' ', '\t'])
        && !value.ends_with([' ', '\t'])
}

/// Connection-specific fields that HTTP/2 and HTTP/3 forbid.
const CONNECTION_SPECIFIC: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

fn check_regular(name: &str, value: &str) -> Result<(), MessageError> {
    if !valid_name(name) {
        return Err(MessageError(format!("invalid field name {name:?}")));
    }
    if !valid_value(value) {
        return Err(MessageError(format!("invalid value for {name}")));
    }
    if CONNECTION_SPECIFIC.contains(&name) || (name == "te" && value != "trailers") {
        return Err(MessageError(format!("connection-specific field {name}")));
    }
    Ok(())
}

impl RequestHead {
    /// A header value by name.
    pub fn header(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// Field lines in wire order: pseudo-headers first.
    pub fn to_fields(&self) -> Vec<(&str, &str)> {
        let mut f = vec![(":method", self.method.as_str())];
        if let Some(p) = &self.protocol {
            f.push((":protocol", p));
        }
        if let Some(s) = &self.scheme {
            f.push((":scheme", s));
        }
        if let Some(a) = &self.authority {
            f.push((":authority", a));
        }
        if let Some(p) = &self.path {
            f.push((":path", p));
        }
        f.extend(self.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())));
        f
    }

    /// Builds and validates a request head from decoded field lines.
    pub fn from_fields(fields: Vec<(String, String)>) -> Result<RequestHead, MessageError> {
        let mut head = RequestHead::default();
        let mut method = None;
        let mut seen_regular = false;
        for (name, value) in fields {
            if let Some(pseudo) = name.strip_prefix(':') {
                if seen_regular {
                    return Err(MessageError("pseudo-header after a header field".into()));
                }
                let slot = match pseudo {
                    "method" => &mut method,
                    "scheme" => &mut head.scheme,
                    "authority" => &mut head.authority,
                    "path" => &mut head.path,
                    "protocol" => &mut head.protocol,
                    _ => return Err(MessageError(format!("unknown pseudo-header {name}"))),
                };
                if slot.replace(value).is_some() {
                    return Err(MessageError(format!("duplicate pseudo-header {name}")));
                }
            } else {
                seen_regular = true;
                check_regular(&name, &value)?;
                head.headers.push((name, value));
            }
        }
        head.method = method.ok_or_else(|| MessageError("missing :method".into()))?;
        if head.method == "CONNECT" {
            if head.protocol.is_some() {
                // Extended CONNECT: all of :scheme, :authority and :path.
                if head.scheme.is_none() || head.authority.is_none() || head.path.is_none() {
                    return Err(MessageError(
                        "extended CONNECT needs scheme, authority and path".into(),
                    ));
                }
            } else if head.authority.is_none() || head.scheme.is_some() || head.path.is_some() {
                return Err(MessageError("malformed CONNECT".into()));
            }
        } else if head.protocol.is_some() {
            return Err(MessageError(":protocol outside CONNECT".into()));
        } else if head.scheme.is_none() || head.path.as_deref().is_none_or(str::is_empty) {
            return Err(MessageError("missing :scheme or :path".into()));
        }
        Ok(head)
    }
}

impl ResponseHead {
    /// A response with a status and no fields.
    pub fn new(status: u16) -> ResponseHead {
        ResponseHead {
            status,
            headers: Vec::new(),
        }
    }

    /// Adds a header field.
    pub fn with(mut self, name: &str, value: impl Into<String>) -> ResponseHead {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// A header value by name.
    pub fn header(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// Field lines in wire order.
    pub fn to_fields(&self) -> (String, Vec<(&str, &str)>) {
        let status = self.status.to_string();
        let fields = self
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        (status, fields)
    }

    /// Builds and validates a response head from decoded field lines.
    pub fn from_fields(fields: Vec<(String, String)>) -> Result<ResponseHead, MessageError> {
        let mut status = None;
        let mut headers = Vec::new();
        for (name, value) in fields {
            if name == ":status" {
                if !headers.is_empty() || status.is_some() {
                    return Err(MessageError("misplaced :status".into()));
                }
                let code: u16 = value
                    .parse()
                    .ok()
                    .filter(|c| (100..=599).contains(c))
                    .ok_or_else(|| MessageError("invalid :status".into()))?;
                status = Some(code);
            } else if name.starts_with(':') {
                return Err(MessageError(format!("pseudo-header {name} in a response")));
            } else {
                check_regular(&name, &value)?;
                headers.push((name, value));
            }
        }
        Ok(ResponseHead {
            status: status.ok_or_else(|| MessageError("missing :status".into()))?,
            headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(f: &[(&str, &str)]) -> Vec<(String, String)> {
        f.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn extended_connect_round_trips() {
        let head = RequestHead {
            method: "CONNECT".into(),
            scheme: Some("https".into()),
            authority: Some("relay.example.com".into()),
            path: Some("/.well-known/masque/udp/g.connectors.warren.invalid/443/".into()),
            protocol: Some("connect-udp".into()),
            headers: vec![("capsule-protocol".into(), "?1".into())],
        };
        let wire: Vec<(String, String)> = head
            .to_fields()
            .into_iter()
            .map(|(n, v)| (n.to_owned(), v.to_owned()))
            .collect();
        assert_eq!(RequestHead::from_fields(wire).unwrap(), head);
        assert_eq!(head.header("Capsule-Protocol"), Some("?1"));
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let bad = [
            fields(&[(":scheme", "https")]),
            fields(&[(":method", "CONNECT"), (":protocol", "connect-ip")]),
            fields(&[(":method", "GET"), (":scheme", "https")]),
            fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                ("x", "1"),
                (":authority", "a"),
            ]),
            fields(&[
                (":method", "GET"),
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
            ]),
            fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                ("Upper", "1"),
            ]),
            fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                ("connection", "close"),
            ]),
            fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                ("x", "a\nb"),
            ]),
            fields(&[(":method", "GET"), (":foo", "x")]),
            fields(&[
                (":method", "GET"),
                (":protocol", "x"),
                (":scheme", "https"),
                (":path", "/"),
            ]),
        ];
        for f in bad {
            assert!(RequestHead::from_fields(f.clone()).is_err(), "{f:?}");
        }
    }

    #[test]
    fn responses() {
        let r =
            ResponseHead::from_fields(fields(&[(":status", "200"), ("connect-udp-bind", "?1")]))
                .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("connect-udp-bind"), Some("?1"));
        assert!(ResponseHead::from_fields(fields(&[(":status", "99")])).is_err());
        assert!(ResponseHead::from_fields(fields(&[("x", "1")])).is_err());
        assert!(ResponseHead::from_fields(fields(&[(":status", "200"), (":path", "/")])).is_err());
    }
}
