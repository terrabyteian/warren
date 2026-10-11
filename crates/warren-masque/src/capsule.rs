//! The Capsule Protocol (RFC 9297, section 3) and every capsule warren uses:
//! the HTTP Datagram capsule, the CONNECT-IP capsules (RFC 9484), the bound
//! UDP compression capsules (draft-ietf-masque-connect-udp-listen, revision
//! [`BIND_DRAFT_REVISION`]) and warren's own capsules (docs/protocol.md,
//! sections 4.3, 5, 6 and 7).
//!
//! Unknown capsule types decode to [`Capsule::Unknown`] and callers ignore
//! them (RFC 9297). Malformed known capsules are errors, which the caller
//! treats as a Capsule Protocol error and aborts the request stream.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::varint;

/// The pinned revision of draft-ietf-masque-connect-udp-listen.
pub const BIND_DRAFT_REVISION: u32 = 16;

/// Capsule type codepoints.
pub mod kind {
    /// HTTP Datagram carried on the stream (RFC 9297).
    pub const DATAGRAM: u64 = 0x00;
    /// CONNECT-IP address assignment (RFC 9484).
    pub const ADDRESS_ASSIGN: u64 = 0x01;
    /// CONNECT-IP address request (RFC 9484).
    pub const ADDRESS_REQUEST: u64 = 0x02;
    /// CONNECT-IP route advertisement (RFC 9484).
    pub const ROUTE_ADVERTISEMENT: u64 = 0x03;
    /// Bound UDP context registration.
    pub const COMPRESSION_ASSIGN: u64 = 0x11;
    /// Bound UDP context registration accepted.
    pub const COMPRESSION_ACK: u64 = 0x12;
    /// Bound UDP context rejected or closed.
    pub const COMPRESSION_CLOSE: u64 = 0x13;
    /// `WARREN_NAME_BIND`: binds a synthetic address to a name and app.
    pub const WARREN_NAME_BIND: u64 = 0x3a72_6e10;
    /// `WARREN_NAME_BOUND`: the connector's answer to a name bind.
    pub const WARREN_NAME_BOUND: u64 = 0x3a72_6e11;
    /// `WARREN_FLOW_DENIED`: a flow was denied, with its reason.
    pub const WARREN_FLOW_DENIED: u64 = 0x3a72_6e12;
    /// `WARREN_POSTURE`: a signed posture statement for the connector.
    pub const WARREN_POSTURE: u64 = 0x3a72_6e13;
    /// `WARREN_CERT_REFRESH`: a renewed certificate bound to the session.
    pub const WARREN_CERT_REFRESH: u64 = 0x3a72_6e14;
    /// `WARREN_NOTICE`: a user-facing notice before a session closes.
    pub const WARREN_NOTICE: u64 = 0x3a72_6e15;
    /// `WARREN_PEER_INFO`: the client's relay-observed public address.
    pub const WARREN_PEER_INFO: u64 = 0x3a72_6e16;

    /// Whether `t` is a reserved (GREASE) capsule type, `0x29 * N + 0x17`.
    pub fn is_grease(t: u64) -> bool {
        t >= 0x17 && (t - 0x17).is_multiple_of(0x29)
    }
}

/// Upper bound on a single capsule's payload; larger capsules abort the
/// stream. The largest legitimate capsule is a certificate refresh.
pub const MAX_CAPSULE_PAYLOAD: usize = 64 * 1024;

/// A Capsule Protocol error: the request stream must be aborted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleError(pub String);

impl fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed capsule: {}", self.0)
    }
}

impl std::error::Error for CapsuleError {}

fn err<T>(msg: impl Into<String>) -> Result<T, CapsuleError> {
    Err(CapsuleError(msg.into()))
}

/// A capsule as it appears on the wire: a type and an opaque payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCapsule {
    /// Capsule type.
    pub kind: u64,
    /// Capsule value.
    pub payload: Bytes,
}

impl RawCapsule {
    /// Appends the encoded capsule to `out`.
    pub fn encode_into(&self, out: &mut BytesMut) {
        varint::put(out, self.kind);
        varint::put(out, self.payload.len() as u64);
        out.extend_from_slice(&self.payload);
    }

    /// Encoded length.
    pub fn encoded_len(&self) -> usize {
        varint::len(self.kind) + varint::len(self.payload.len() as u64) + self.payload.len()
    }
}

/// Incremental capsule parser over a byte stream.
#[derive(Debug, Default)]
pub struct CapsuleReader {
    buf: BytesMut,
}

impl CapsuleReader {
    /// Creates an empty reader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds stream bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns the next complete capsule, if any.
    pub fn next_capsule(&mut self) -> Result<Option<RawCapsule>, CapsuleError> {
        let mut peek = &self.buf[..];
        let Some(kind) = varint::get(&mut peek) else {
            return Ok(None);
        };
        let Some(len) = varint::get(&mut peek) else {
            return Ok(None);
        };
        if len > MAX_CAPSULE_PAYLOAD as u64 {
            return err(format!("capsule of {len} bytes exceeds the limit"));
        }
        let len = len as usize;
        if peek.len() < len {
            return Ok(None);
        }
        let header = self.buf.len() - peek.len();
        self.buf.advance(header);
        let payload = self.buf.split_to(len).freeze();
        Ok(Some(RawCapsule { kind, payload }))
    }

    /// Whether a partial capsule is buffered (an error at end of stream).
    pub fn has_partial(&self) -> bool {
        !self.buf.is_empty()
    }
}

/// An address or prefix in an ADDRESS_ASSIGN or ADDRESS_REQUEST capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressEntry {
    /// Request identifier (zero for unprompted assignments).
    pub request_id: u64,
    /// Address (all zeros when a request was not assigned).
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub prefix_len: u8,
}

/// One range in a ROUTE_ADVERTISEMENT capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    /// Inclusive start.
    pub start: IpAddr,
    /// Inclusive end.
    pub end: IpAddr,
    /// IP protocol number, or 0 for any.
    pub protocol: u8,
}

/// The 5-tuple a flow is identified by (ICMP uses the echo identifier as
/// both ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    /// IP protocol number.
    pub protocol: u8,
    /// Source address and port.
    pub src: SocketAddr,
    /// Destination address and port.
    pub dst: SocketAddr,
}

/// `WARREN_NAME_BIND`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameBind {
    /// Synthetic address the client answered for `name`.
    pub address: IpAddr,
    /// Client-facing name.
    pub name: String,
    /// The app the client believes owns the name.
    pub app: String,
}

/// `WARREN_NAME_BOUND`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameBound {
    /// The synthetic address from the bind.
    pub address: IpAddr,
    /// Whether the bind was accepted.
    pub accepted: bool,
    /// Reason code when rejected (for example `name_not_in_app`).
    pub reason: String,
    /// Human-readable message when rejected.
    pub message: String,
}

/// `WARREN_FLOW_DENIED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDenied {
    /// The denied flow, as the client sent it.
    pub flow: FlowTuple,
    /// Decision identifier, matching the connector's audit record.
    pub decision_id: String,
    /// Reason code (docs/protocol.md section 7).
    pub reason: String,
    /// Human-readable message.
    pub message: String,
    /// What the user can do about it, possibly empty.
    pub remediation: String,
}

/// `WARREN_CERT_REFRESH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRefresh {
    /// The renewed certificate chain, leaf first, DER.
    pub chain: Vec<Bytes>,
    /// Device-key signature over the session's refresh exporter value.
    pub signature: Bytes,
}

/// `WARREN_NOTICE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// Reason code (for example `revoked` or `draining`).
    pub reason: String,
    /// Human-readable message.
    pub message: String,
}

/// `WARREN_PEER_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    /// The bind context the information is about.
    pub context_id: u64,
    /// The client's public address as the relay observed it.
    pub observed: SocketAddr,
}

/// A decoded capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    /// DATAGRAM: an HTTP Datagram payload (context ID first).
    Datagram(Bytes),
    /// ADDRESS_ASSIGN.
    AddressAssign(Vec<AddressEntry>),
    /// ADDRESS_REQUEST.
    AddressRequest(Vec<AddressEntry>),
    /// ROUTE_ADVERTISEMENT.
    RouteAdvertisement(Vec<IpRange>),
    /// COMPRESSION_ASSIGN; `target` is `None` for the uncompressed context.
    CompressionAssign {
        /// The context being registered.
        context_id: u64,
        /// The peer address it stands for.
        target: Option<SocketAddr>,
    },
    /// COMPRESSION_ACK.
    CompressionAck(u64),
    /// COMPRESSION_CLOSE.
    CompressionClose(u64),
    /// `WARREN_NAME_BIND`.
    NameBind(NameBind),
    /// `WARREN_NAME_BOUND`.
    NameBound(NameBound),
    /// `WARREN_FLOW_DENIED`.
    FlowDenied(FlowDenied),
    /// `WARREN_POSTURE`: an opaque signed statement.
    Posture(Bytes),
    /// `WARREN_CERT_REFRESH`.
    CertRefresh(CertRefresh),
    /// `WARREN_NOTICE`.
    Notice(Notice),
    /// `WARREN_PEER_INFO`.
    PeerInfo(PeerInfo),
    /// Any other type; ignored by receivers.
    Unknown(RawCapsule),
}

const MAX_TEXT: usize = 4096;

fn put_ip(out: &mut BytesMut, addr: IpAddr) {
    match addr {
        IpAddr::V4(a) => {
            out.put_u8(4);
            out.put_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.put_u8(6);
            out.put_slice(&a.octets());
        }
    }
}

fn get_ip(buf: &mut Bytes) -> Result<IpAddr, CapsuleError> {
    if buf.is_empty() {
        return err("missing IP version");
    }
    match buf.get_u8() {
        4 if buf.len() >= 4 => {
            let mut o = [0u8; 4];
            buf.copy_to_slice(&mut o);
            Ok(IpAddr::V4(Ipv4Addr::from(o)))
        }
        6 if buf.len() >= 16 => {
            let mut o = [0u8; 16];
            buf.copy_to_slice(&mut o);
            Ok(IpAddr::V6(Ipv6Addr::from(o)))
        }
        4 | 6 => err("truncated IP address"),
        v => err(format!("invalid IP version {v}")),
    }
}

fn get_same_family(buf: &mut Bytes, v6: bool) -> Result<IpAddr, CapsuleError> {
    if v6 {
        if buf.len() < 16 {
            return err("truncated IPv6 address");
        }
        let mut o = [0u8; 16];
        buf.copy_to_slice(&mut o);
        Ok(IpAddr::V6(Ipv6Addr::from(o)))
    } else {
        if buf.len() < 4 {
            return err("truncated IPv4 address");
        }
        let mut o = [0u8; 4];
        buf.copy_to_slice(&mut o);
        Ok(IpAddr::V4(Ipv4Addr::from(o)))
    }
}

fn put_socket(out: &mut BytesMut, addr: SocketAddr) {
    put_ip(out, addr.ip());
    out.put_u16(addr.port());
}

fn get_socket(buf: &mut Bytes) -> Result<SocketAddr, CapsuleError> {
    let ip = get_ip(buf)?;
    if buf.len() < 2 {
        return err("truncated port");
    }
    Ok(SocketAddr::new(ip, buf.get_u16()))
}

fn get_varint(buf: &mut Bytes) -> Result<u64, CapsuleError> {
    varint::get(buf).ok_or_else(|| CapsuleError("truncated varint".into()))
}

fn put_bytes(out: &mut BytesMut, b: &[u8]) {
    varint::put(out, b.len() as u64);
    out.put_slice(b);
}

fn get_bytes(buf: &mut Bytes, max: usize) -> Result<Bytes, CapsuleError> {
    let n = get_varint(buf)?;
    if n > max as u64 || n > buf.len() as u64 {
        return err("length field out of range");
    }
    Ok(buf.split_to(n as usize))
}

fn get_text(buf: &mut Bytes) -> Result<String, CapsuleError> {
    let b = get_bytes(buf, MAX_TEXT)?;
    String::from_utf8(b.to_vec()).map_err(|_| CapsuleError("text is not UTF-8".into()))
}

fn max_prefix(addr: &IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn put_entries(out: &mut BytesMut, entries: &[AddressEntry]) {
    for e in entries {
        varint::put(out, e.request_id);
        put_ip(out, e.addr);
        out.put_u8(e.prefix_len);
    }
}

fn get_entries(mut buf: Bytes) -> Result<Vec<AddressEntry>, CapsuleError> {
    let mut entries = Vec::new();
    while !buf.is_empty() {
        let request_id = get_varint(&mut buf)?;
        let addr = get_ip(&mut buf)?;
        if buf.is_empty() {
            return err("missing prefix length");
        }
        let prefix_len = buf.get_u8();
        if prefix_len > max_prefix(&addr) {
            return err("prefix length exceeds the address length");
        }
        entries.push(AddressEntry {
            request_id,
            addr,
            prefix_len,
        });
    }
    Ok(entries)
}

impl Capsule {
    /// The capsule's type codepoint.
    pub fn kind(&self) -> u64 {
        match self {
            Capsule::Datagram(_) => kind::DATAGRAM,
            Capsule::AddressAssign(_) => kind::ADDRESS_ASSIGN,
            Capsule::AddressRequest(_) => kind::ADDRESS_REQUEST,
            Capsule::RouteAdvertisement(_) => kind::ROUTE_ADVERTISEMENT,
            Capsule::CompressionAssign { .. } => kind::COMPRESSION_ASSIGN,
            Capsule::CompressionAck(_) => kind::COMPRESSION_ACK,
            Capsule::CompressionClose(_) => kind::COMPRESSION_CLOSE,
            Capsule::NameBind(_) => kind::WARREN_NAME_BIND,
            Capsule::NameBound(_) => kind::WARREN_NAME_BOUND,
            Capsule::FlowDenied(_) => kind::WARREN_FLOW_DENIED,
            Capsule::Posture(_) => kind::WARREN_POSTURE,
            Capsule::CertRefresh(_) => kind::WARREN_CERT_REFRESH,
            Capsule::Notice(_) => kind::WARREN_NOTICE,
            Capsule::PeerInfo(_) => kind::WARREN_PEER_INFO,
            Capsule::Unknown(raw) => raw.kind,
        }
    }

    /// Encodes the capsule's payload.
    pub fn payload(&self) -> Bytes {
        let mut out = BytesMut::new();
        match self {
            Capsule::Datagram(b) | Capsule::Posture(b) => return b.clone(),
            Capsule::Unknown(raw) => return raw.payload.clone(),
            Capsule::AddressAssign(e) | Capsule::AddressRequest(e) => put_entries(&mut out, e),
            Capsule::RouteAdvertisement(ranges) => {
                for r in ranges {
                    put_ip(&mut out, r.start);
                    match r.end {
                        IpAddr::V4(a) => out.put_slice(&a.octets()),
                        IpAddr::V6(a) => out.put_slice(&a.octets()),
                    }
                    out.put_u8(r.protocol);
                }
            }
            Capsule::CompressionAssign { context_id, target } => {
                varint::put(&mut out, *context_id);
                match target {
                    None => out.put_u8(0),
                    Some(t) => put_socket(&mut out, *t),
                }
            }
            Capsule::CompressionAck(c) | Capsule::CompressionClose(c) => varint::put(&mut out, *c),
            Capsule::NameBind(b) => {
                put_ip(&mut out, b.address);
                put_bytes(&mut out, b.name.as_bytes());
                put_bytes(&mut out, b.app.as_bytes());
            }
            Capsule::NameBound(b) => {
                put_ip(&mut out, b.address);
                out.put_u8(u8::from(!b.accepted));
                put_bytes(&mut out, b.reason.as_bytes());
                put_bytes(&mut out, b.message.as_bytes());
            }
            Capsule::FlowDenied(d) => {
                out.put_u8(d.flow.protocol);
                put_socket(&mut out, d.flow.src);
                put_socket(&mut out, d.flow.dst);
                put_bytes(&mut out, d.decision_id.as_bytes());
                put_bytes(&mut out, d.reason.as_bytes());
                put_bytes(&mut out, d.message.as_bytes());
                put_bytes(&mut out, d.remediation.as_bytes());
            }
            Capsule::CertRefresh(r) => {
                varint::put(&mut out, r.chain.len() as u64);
                for c in &r.chain {
                    put_bytes(&mut out, c);
                }
                put_bytes(&mut out, &r.signature);
            }
            Capsule::Notice(n) => {
                put_bytes(&mut out, n.reason.as_bytes());
                put_bytes(&mut out, n.message.as_bytes());
            }
            Capsule::PeerInfo(p) => {
                varint::put(&mut out, p.context_id);
                put_socket(&mut out, p.observed);
            }
        }
        out.freeze()
    }

    /// Encodes the whole capsule.
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::new();
        self.encode_into(&mut out);
        out.freeze()
    }

    /// Appends the whole encoded capsule to `out`.
    pub fn encode_into(&self, out: &mut BytesMut) {
        RawCapsule {
            kind: self.kind(),
            payload: self.payload(),
        }
        .encode_into(out);
    }

    /// Decodes a raw capsule. Trailing bytes after a warren capsule's known
    /// fields are ignored, so later versions can append fields.
    pub fn decode(raw: RawCapsule) -> Result<Capsule, CapsuleError> {
        let mut b = raw.payload.clone();
        let capsule = match raw.kind {
            kind::DATAGRAM => Capsule::Datagram(b),
            kind::ADDRESS_ASSIGN => Capsule::AddressAssign(get_entries(b)?),
            kind::ADDRESS_REQUEST => {
                let entries = get_entries(b)?;
                if entries.is_empty() || entries.iter().any(|e| e.request_id == 0) {
                    return err("ADDRESS_REQUEST needs entries with non-zero request IDs");
                }
                Capsule::AddressRequest(entries)
            }
            kind::ROUTE_ADVERTISEMENT => {
                let mut ranges: Vec<IpRange> = Vec::new();
                while !b.is_empty() {
                    let start = get_ip(&mut b)?;
                    let end = get_same_family(&mut b, start.is_ipv6())?;
                    if b.is_empty() {
                        return err("missing IP protocol");
                    }
                    let protocol = b.get_u8();
                    if start > end {
                        return err("route range start after end");
                    }
                    let range = IpRange {
                        start,
                        end,
                        protocol,
                    };
                    if let Some(prev) = ranges.last() {
                        let order = (u8::from(prev.start.is_ipv6()), prev.protocol)
                            .cmp(&(u8::from(range.start.is_ipv6()), range.protocol));
                        if order.is_gt() || (order.is_eq() && prev.end >= range.start) {
                            return err("route ranges are not ordered");
                        }
                    }
                    ranges.push(range);
                }
                Capsule::RouteAdvertisement(ranges)
            }
            kind::COMPRESSION_ASSIGN => {
                let context_id = get_varint(&mut b)?;
                if context_id == 0 {
                    return err("COMPRESSION_ASSIGN with context ID 0");
                }
                if b.is_empty() {
                    return err("missing IP version");
                }
                let target = if b[0] == 0 {
                    b.advance(1);
                    None
                } else {
                    Some(get_socket(&mut b)?)
                };
                Capsule::CompressionAssign { context_id, target }
            }
            kind::COMPRESSION_ACK | kind::COMPRESSION_CLOSE => {
                let c = get_varint(&mut b)?;
                if c == 0 {
                    return err("compression capsule with context ID 0");
                }
                if raw.kind == kind::COMPRESSION_ACK {
                    Capsule::CompressionAck(c)
                } else {
                    Capsule::CompressionClose(c)
                }
            }
            kind::WARREN_NAME_BIND => Capsule::NameBind(NameBind {
                address: get_ip(&mut b)?,
                name: get_text(&mut b)?,
                app: get_text(&mut b)?,
            }),
            kind::WARREN_NAME_BOUND => {
                let address = get_ip(&mut b)?;
                if b.is_empty() {
                    return err("missing result");
                }
                let accepted = b.get_u8() == 0;
                Capsule::NameBound(NameBound {
                    address,
                    accepted,
                    reason: get_text(&mut b)?,
                    message: get_text(&mut b)?,
                })
            }
            kind::WARREN_FLOW_DENIED => {
                if b.is_empty() {
                    return err("missing protocol");
                }
                let protocol = b.get_u8();
                let src = get_socket(&mut b)?;
                let dst = get_socket(&mut b)?;
                Capsule::FlowDenied(FlowDenied {
                    flow: FlowTuple { protocol, src, dst },
                    decision_id: get_text(&mut b)?,
                    reason: get_text(&mut b)?,
                    message: get_text(&mut b)?,
                    remediation: get_text(&mut b)?,
                })
            }
            kind::WARREN_POSTURE => Capsule::Posture(b),
            kind::WARREN_CERT_REFRESH => {
                let n = get_varint(&mut b)?;
                if n == 0 || n > 4 {
                    return err("certificate chain length out of range");
                }
                let mut chain = Vec::new();
                for _ in 0..n {
                    chain.push(get_bytes(&mut b, MAX_CAPSULE_PAYLOAD)?);
                }
                Capsule::CertRefresh(CertRefresh {
                    chain,
                    signature: get_bytes(&mut b, 512)?,
                })
            }
            kind::WARREN_NOTICE => Capsule::Notice(Notice {
                reason: get_text(&mut b)?,
                message: get_text(&mut b)?,
            }),
            kind::WARREN_PEER_INFO => Capsule::PeerInfo(PeerInfo {
                context_id: get_varint(&mut b)?,
                observed: get_socket(&mut b)?,
            }),
            _ => Capsule::Unknown(raw),
        };
        Ok(capsule)
    }
}

/// Splits an HTTP Datagram payload into its context ID and the rest.
pub fn split_context(payload: &Bytes) -> Option<(u64, Bytes)> {
    let (ctx, n) = varint::peek(payload)?;
    Some((ctx, payload.slice(n..)))
}

/// Builds an HTTP Datagram payload from a context ID and data.
pub fn with_context(context_id: u64, data: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(varint::len(context_id) + data.len());
    varint::put(&mut out, context_id);
    out.put_slice(data);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(c: Capsule) {
        let wire = c.encode();
        let mut r = CapsuleReader::new();
        // Feed byte by byte to exercise partial reads.
        let mut out = None;
        for (i, b) in wire.iter().enumerate() {
            r.push(&[*b]);
            if let Some(raw) = r.next_capsule().unwrap() {
                assert_eq!(i, wire.len() - 1, "capsule completed early");
                out = Some(raw);
            }
        }
        let raw = out.expect("complete capsule");
        assert!(!r.has_partial());
        assert_eq!(Capsule::decode(raw).unwrap(), c);
    }

    #[test]
    fn every_capsule_round_trips() {
        let v4: IpAddr = "100.96.0.2".parse().unwrap();
        let v6: IpAddr = "fd00:77::2".parse().unwrap();
        round_trip(Capsule::Datagram(Bytes::from_static(b"\x00hello")));
        round_trip(Capsule::AddressRequest(vec![
            AddressEntry {
                request_id: 1,
                addr: v4,
                prefix_len: 32,
            },
            AddressEntry {
                request_id: 2,
                addr: v6,
                prefix_len: 128,
            },
        ]));
        round_trip(Capsule::AddressAssign(vec![]));
        round_trip(Capsule::RouteAdvertisement(vec![
            IpRange {
                start: "10.0.0.0".parse().unwrap(),
                end: "10.0.0.255".parse().unwrap(),
                protocol: 0,
            },
            IpRange {
                start: "10.0.1.0".parse().unwrap(),
                end: "10.0.1.255".parse().unwrap(),
                protocol: 0,
            },
            IpRange {
                start: "fd00::".parse().unwrap(),
                end: "fd00::ff".parse().unwrap(),
                protocol: 6,
            },
        ]));
        round_trip(Capsule::CompressionAssign {
            context_id: 3,
            target: Some("[fd12::1]:443".parse().unwrap()),
        });
        round_trip(Capsule::CompressionAssign {
            context_id: 2,
            target: None,
        });
        round_trip(Capsule::CompressionAck(3));
        round_trip(Capsule::CompressionClose(16_383));
        round_trip(Capsule::NameBind(NameBind {
            address: "100.80.0.5".parse().unwrap(),
            name: "grafana.lab.example.com".into(),
            app: "grafana".into(),
        }));
        round_trip(Capsule::NameBound(NameBound {
            address: "100.80.0.5".parse().unwrap(),
            accepted: false,
            reason: "name_not_in_app".into(),
            message: "nope".into(),
        }));
        round_trip(Capsule::FlowDenied(FlowDenied {
            flow: FlowTuple {
                protocol: 6,
                src: "100.96.0.2:50000".parse().unwrap(),
                dst: "10.20.0.5:22".parse().unwrap(),
            },
            decision_id: "d-1".into(),
            reason: "no_rule".into(),
            message: "No policy allows you to reach lab-network.".into(),
            remediation: String::new(),
        }));
        round_trip(Capsule::Posture(Bytes::from_static(b"statement")));
        round_trip(Capsule::CertRefresh(CertRefresh {
            chain: vec![Bytes::from_static(b"leaf"), Bytes::from_static(b"ca")],
            signature: Bytes::from_static(b"sig"),
        }));
        round_trip(Capsule::Notice(Notice {
            reason: "draining".into(),
            message: "connector restarting".into(),
        }));
        round_trip(Capsule::PeerInfo(PeerInfo {
            context_id: 5,
            observed: "203.0.113.9:61000".parse().unwrap(),
        }));
        round_trip(Capsule::Unknown(RawCapsule {
            kind: 0x29 * 7 + 0x17,
            payload: Bytes::from_static(b"grease"),
        }));
    }

    #[test]
    fn malformed_capsules_are_errors() {
        let bad = [
            (kind::ADDRESS_REQUEST, &b""[..]),
            (kind::ADDRESS_REQUEST, &[0, 4, 1, 2, 3, 4, 32][..]),
            (kind::ADDRESS_ASSIGN, &[1, 4, 1, 2, 3, 4, 33][..]),
            (kind::ADDRESS_ASSIGN, &[1, 5, 1, 2, 3, 4, 32][..]),
            (kind::COMPRESSION_ASSIGN, &[0, 0][..]),
            (kind::COMPRESSION_ACK, &[0][..]),
            (
                kind::ROUTE_ADVERTISEMENT,
                &[4, 10, 0, 0, 9, 10, 0, 0, 1, 0][..],
            ),
            (kind::WARREN_NAME_BIND, &[4, 1, 2, 3][..]),
        ];
        for (k, p) in bad {
            let raw = RawCapsule {
                kind: k,
                payload: Bytes::copy_from_slice(p),
            };
            assert!(Capsule::decode(raw).is_err(), "type {k:#x} {p:?}");
        }
    }

    #[test]
    fn oversized_capsules_are_rejected_before_buffering() {
        let mut r = CapsuleReader::new();
        let mut hdr = BytesMut::new();
        varint::put(&mut hdr, kind::DATAGRAM);
        varint::put(&mut hdr, (MAX_CAPSULE_PAYLOAD + 1) as u64);
        r.push(&hdr);
        assert!(r.next_capsule().is_err());
    }

    #[test]
    fn grease_detection() {
        assert!(kind::is_grease(0x17));
        assert!(kind::is_grease(0x17 + 0x29 * 1000));
        for k in [
            kind::WARREN_NAME_BIND,
            kind::WARREN_NAME_BOUND,
            kind::WARREN_FLOW_DENIED,
            kind::WARREN_POSTURE,
            kind::WARREN_CERT_REFRESH,
            kind::WARREN_NOTICE,
            kind::WARREN_PEER_INFO,
        ] {
            assert!(!kind::is_grease(k));
            assert_eq!(varint::len(k), 4);
        }
    }

    #[test]
    fn datagram_context_helpers() {
        let d = with_context(16_383, b"abc");
        assert_eq!(d.len(), 5);
        assert_eq!(
            split_context(&d),
            Some((16_383, Bytes::from_static(b"abc")))
        );
    }
}
