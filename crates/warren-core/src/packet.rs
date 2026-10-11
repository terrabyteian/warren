//! IP packet handling for the tunnel: parsing the fields flow admission
//! needs, rewriting addresses for synthetic names with incremental checksum
//! updates (RFC 1624), clamping TCP MSS, and building the replies that make
//! applications fail fast (TCP reset, ICMP unreachable, packet too big).
//!
//! This is packet plumbing, not cryptography; it never interprets payloads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::bundle::proto;

/// A packet that cannot be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError(pub &'static str);

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "packet: {}", self.0)
    }
}

impl std::error::Error for PacketError {}

/// TCP flags.
pub mod tcp {
    /// FIN.
    pub const FIN: u8 = 0x01;
    /// SYN.
    pub const SYN: u8 = 0x02;
    /// RST.
    pub const RST: u8 = 0x04;
    /// ACK.
    pub const ACK: u8 = 0x10;
}

/// The facts about a packet that admission and forwarding use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Upper-layer protocol.
    pub protocol: u8,
    /// Offset of the upper-layer header (0 for non-first fragments).
    pub l4: usize,
    /// Total packet length from the IP header.
    pub len: usize,
    /// Source port, or the ICMP echo identifier.
    pub src_port: u16,
    /// Destination port, or the ICMP echo identifier.
    pub dst_port: u16,
    /// TCP flags.
    pub tcp_flags: u8,
    /// ICMP type and code.
    pub icmp: Option<(u8, u8)>,
    /// Fragment state: `None` when unfragmented, otherwise the fragment
    /// identification and whether this is the first fragment.
    pub fragment: Option<(u32, bool)>,
    /// IPv4 Don't Fragment (always true for IPv6, which never fragments in
    /// transit).
    pub dont_fragment: bool,
}

impl Parsed {
    /// Source as a socket address (port or echo identifier).
    pub fn src_sock(&self) -> SocketAddr {
        SocketAddr::new(self.src, self.src_port)
    }

    /// Destination as a socket address.
    pub fn dst_sock(&self) -> SocketAddr {
        SocketAddr::new(self.dst, self.dst_port)
    }

    /// Whether this ICMP message is an echo request or reply, which forms a
    /// flow, rather than an error about another packet.
    pub fn is_icmp_echo(&self) -> bool {
        matches!(
            (self.protocol, self.icmp),
            (proto::ICMP, Some((0 | 8, _))) | (proto::ICMPV6, Some((128 | 129, _)))
        )
    }

    /// Whether this is an ICMP error that quotes another packet.
    pub fn is_icmp_error(&self) -> bool {
        matches!(
            (self.protocol, self.icmp),
            (proto::ICMP, Some((3 | 11 | 12, _))) | (proto::ICMPV6, Some((1..=4, _)))
        )
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Parses an IPv4 or IPv6 packet.
pub fn parse(b: &[u8]) -> Result<Parsed, PacketError> {
    parse_headers(b, false)
}

/// Parses headers; a `quote` (the packet inside an ICMP error, as short as
/// the IP header plus 8 bytes) needs only the TCP or UDP ports and never
/// sets `tcp_flags`.
fn parse_headers(b: &[u8], quote: bool) -> Result<Parsed, PacketError> {
    let version = b.first().ok_or(PacketError("empty packet"))? >> 4;
    let (src, dst, protocol, l4, len, fragment, dont_fragment) = match version {
        4 => {
            if b.len() < 20 {
                return Err(PacketError("short IPv4 header"));
            }
            let ihl = usize::from(b[0] & 0x0f) * 4;
            let len = usize::from(be16(b, 2));
            if ihl < 20 || len < ihl || len > b.len() {
                return Err(PacketError("bad IPv4 lengths"));
            }
            let flags_frag = be16(b, 6);
            let offset = flags_frag & 0x1fff;
            let more = flags_frag & 0x2000 != 0;
            let fragment = (offset != 0 || more).then_some((u32::from(be16(b, 4)), offset == 0));
            let src = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
            let l4 = if offset == 0 { ihl } else { 0 };
            (src, dst, b[9], l4, len, fragment, flags_frag & 0x4000 != 0)
        }
        6 => {
            if b.len() < 40 {
                return Err(PacketError("short IPv6 header"));
            }
            let len = 40 + usize::from(be16(b, 4));
            if len > b.len() {
                return Err(PacketError("bad IPv6 length"));
            }
            let src = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&b[8..24]).expect("16 bytes"),
            ));
            let dst = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&b[24..40]).expect("16 bytes"),
            ));
            let mut next = b[6];
            let mut at = 40;
            let mut fragment = None;
            // Walk extension headers to the upper layer.
            loop {
                match next {
                    0 | 43 | 60 => {
                        if at + 8 > len {
                            return Err(PacketError("truncated extension header"));
                        }
                        let hlen = (usize::from(b[at + 1]) + 1) * 8;
                        next = b[at];
                        at += hlen;
                    }
                    44 => {
                        if at + 8 > len {
                            return Err(PacketError("truncated fragment header"));
                        }
                        let off = be16(b, at + 2) >> 3;
                        let id = u32::from_be_bytes([b[at + 4], b[at + 5], b[at + 6], b[at + 7]]);
                        fragment = Some((id, off == 0));
                        next = b[at];
                        at += 8;
                        if off != 0 {
                            at = 0;
                            break;
                        }
                    }
                    _ => break,
                }
            }
            (src, dst, next, at, len, fragment, true)
        }
        _ => return Err(PacketError("not IPv4 or IPv6")),
    };
    let mut p = Parsed {
        src,
        dst,
        protocol,
        l4,
        len,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        icmp: None,
        fragment,
        dont_fragment,
    };
    if l4 == 0 {
        return Ok(p);
    }
    let need = match protocol {
        proto::TCP | proto::UDP if quote => 4,
        proto::TCP => 20,
        proto::UDP => 8,
        proto::ICMP | proto::ICMPV6 => 8,
        _ => 0,
    };
    if l4 + need > len {
        // Includes a first fragment too short to carry the upper-layer
        // header, which could not be admitted on its ports.
        return Err(PacketError("truncated upper-layer header"));
    }
    match protocol {
        proto::TCP => {
            p.src_port = be16(b, l4);
            p.dst_port = be16(b, l4 + 2);
            if !quote {
                p.tcp_flags = b[l4 + 13];
            }
        }
        proto::UDP => {
            p.src_port = be16(b, l4);
            p.dst_port = be16(b, l4 + 2);
        }
        proto::ICMP | proto::ICMPV6 => {
            p.icmp = Some((b[l4], b[l4 + 1]));
            if p.is_icmp_echo() {
                let id = be16(b, l4 + 4);
                p.src_port = id;
                p.dst_port = id;
            }
        }
        _ => {}
    }
    Ok(p)
}

/// The Internet checksum of `data` (RFC 1071), folded and complemented.
pub fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_header_sum(src: IpAddr, dst: IpAddr, protocol: u8, len: usize) -> u32 {
    let mut sum = 0u32;
    let mut add = |b: &[u8]| {
        for c in b.chunks(2) {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
    };
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            add(&s.octets());
            add(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            add(&s.octets());
            add(&d.octets());
        }
        _ => {}
    }
    sum + u32::from(protocol) + len as u32
}

/// Incrementally updates a checksum field at `at` for `old` replaced by
/// `new` (RFC 1624, equation 3).
fn adjust(b: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
    let mut sum = u32::from(!be16(b, at));
    for c in old.chunks(2) {
        sum += u32::from(!u16::from_be_bytes([c[0], c[1]]));
    }
    for c in new.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let v = !(sum as u16);
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// Which address to rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The source address.
    Source,
    /// The destination address.
    Destination,
}

/// Replaces the source or destination address, updating the IPv4 header
/// checksum and the TCP, UDP or ICMPv6 checksum. The new address must be of
/// the same family.
pub fn rewrite_addr(b: &mut [u8], p: &Parsed, side: Side, new: IpAddr) -> Result<(), PacketError> {
    let (old, at) = match (side, p.src) {
        (Side::Source, IpAddr::V4(_)) => (p.src, 12),
        (Side::Destination, IpAddr::V4(_)) => (p.dst, 16),
        (Side::Source, IpAddr::V6(_)) => (p.src, 8),
        (Side::Destination, IpAddr::V6(_)) => (p.dst, 24),
    };
    if old.is_ipv4() != new.is_ipv4() {
        return Err(PacketError("address family mismatch"));
    }
    let (old_b, new_b) = (octets(old), octets(new));
    b[at..at + old_b.len()].copy_from_slice(&new_b);
    if old.is_ipv4() {
        adjust(b, 10, &old_b, &new_b);
    }
    if p.l4 == 0 {
        return Ok(());
    }
    let ck = match p.protocol {
        proto::TCP => Some(p.l4 + 16),
        // A zero UDP checksum over IPv4 means "none" and stays zero.
        proto::UDP if !(old.is_ipv4() && be16(b, p.l4 + 6) == 0) => Some(p.l4 + 6),
        proto::ICMPV6 => Some(p.l4 + 2),
        _ => None,
    };
    if let Some(ck) = ck {
        adjust(b, ck, &old_b, &new_b);
        if p.protocol == proto::UDP && be16(b, ck) == 0 {
            b[ck..ck + 2].copy_from_slice(&0xffffu16.to_be_bytes());
        }
    }
    Ok(())
}

/// Clamps the MSS option of a TCP SYN to `max`. Returns whether it changed.
pub fn clamp_mss(b: &mut [u8], p: &Parsed, max: u16) -> bool {
    if p.protocol != proto::TCP || p.l4 == 0 || p.tcp_flags & tcp::SYN == 0 {
        return false;
    }
    let off = usize::from(b[p.l4 + 12] >> 4) * 4;
    let end = (p.l4 + off).min(p.len);
    let mut i = p.l4 + 20;
    while i < end {
        match b[i] {
            0 => break,
            1 => i += 1,
            kind => {
                if i + 1 >= end {
                    break;
                }
                let olen = usize::from(b[i + 1]);
                if olen < 2 || i + olen > end {
                    break;
                }
                if kind == 2 && olen == 4 {
                    let mss = be16(b, i + 2);
                    if mss > max {
                        let old = mss.to_be_bytes();
                        b[i + 2..i + 4].copy_from_slice(&max.to_be_bytes());
                        adjust(b, p.l4 + 16, &old, &max.to_be_bytes());
                        return true;
                    }
                    return false;
                }
                i += olen;
            }
        }
    }
    false
}

/// The largest TCP MSS that fits `mtu` for the packet's family.
pub fn mss_for(mtu: u16, ipv4: bool) -> u16 {
    if ipv4 { mtu - 40 } else { mtu - 60 }
}

fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: usize) -> Vec<u8> {
    let total = (20 + payload_len) as u16;
    let mut h = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0];
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let ck = checksum(&h, 0);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

fn ipv6_header(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload_len: usize) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&(payload_len as u16).to_be_bytes());
    h.push(next);
    h.push(64);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h
}

/// Builds an IP packet from `src` to `dst` around an upper-layer segment
/// whose checksum field is at `ck` (relative), computing that checksum.
pub fn build(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    mut segment: Vec<u8>,
    ck: Option<usize>,
) -> Vec<u8> {
    if let Some(at) = ck {
        segment[at..at + 2].copy_from_slice(&[0, 0]);
        let pseudo = match (protocol, src) {
            (proto::ICMP, _) => 0,
            _ => pseudo_header_sum(src, dst, protocol, segment.len()),
        };
        let mut v = checksum(&segment, pseudo);
        if protocol == proto::UDP && v == 0 {
            v = 0xffff;
        }
        segment[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    let mut out = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ipv4_header(s, d, protocol, segment.len()),
        (IpAddr::V6(s), IpAddr::V6(d)) => ipv6_header(s, d, protocol, segment.len()),
        _ => panic!("mixed address families"),
    };
    out.extend_from_slice(&segment);
    out
}

/// Builds a UDP packet.
pub fn udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend_from_slice(&src.port().to_be_bytes());
    seg.extend_from_slice(&dst.port().to_be_bytes());
    seg.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    build(src.ip(), dst.ip(), proto::UDP, seg, Some(6))
}

/// Builds an ICMP or ICMPv6 echo request or reply.
pub fn icmp_echo(
    src: IpAddr,
    dst: IpAddr,
    reply: bool,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (protocol, ty) = match (src.is_ipv4(), reply) {
        (true, false) => (proto::ICMP, 8),
        (true, true) => (proto::ICMP, 0),
        (false, false) => (proto::ICMPV6, 128),
        (false, true) => (proto::ICMPV6, 129),
    };
    let mut seg = vec![ty, 0, 0, 0];
    seg.extend_from_slice(&id.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(payload);
    build(src, dst, protocol, seg, Some(2))
}

/// The upper-layer payload of a parsed UDP packet.
pub fn udp_payload<'a>(b: &'a [u8], p: &Parsed) -> Option<&'a [u8]> {
    (p.protocol == proto::UDP && p.l4 != 0).then(|| &b[p.l4 + 8..p.len])
}

/// A TCP reset answering `b` (a segment from the client), sent as if from
/// its destination, so the application fails at once.
pub fn tcp_reset(b: &[u8], p: &Parsed) -> Option<Vec<u8>> {
    if p.protocol != proto::TCP || p.l4 == 0 || p.tcp_flags & tcp::RST != 0 {
        return None;
    }
    let seq = u32::from_be_bytes(b[p.l4 + 4..p.l4 + 8].try_into().ok()?);
    let ack = u32::from_be_bytes(b[p.l4 + 8..p.l4 + 12].try_into().ok()?);
    let off = usize::from(b[p.l4 + 12] >> 4) * 4;
    let data_len = p.len.saturating_sub(p.l4 + off) as u32;
    let mut seg = vec![0u8; 20];
    seg[0..2].copy_from_slice(&p.dst_port.to_be_bytes());
    seg[2..4].copy_from_slice(&p.src_port.to_be_bytes());
    let (rseq, rack, flags) = if p.tcp_flags & tcp::ACK != 0 {
        (ack, 0, tcp::RST)
    } else {
        let syn_fin =
            u32::from(p.tcp_flags & tcp::SYN != 0) + u32::from(p.tcp_flags & tcp::FIN != 0);
        (0, seq.wrapping_add(data_len + syn_fin), tcp::RST | tcp::ACK)
    };
    seg[4..8].copy_from_slice(&rseq.to_be_bytes());
    seg[8..12].copy_from_slice(&rack.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = flags;
    Some(build(p.dst, p.src, proto::TCP, seg, Some(16)))
}

/// An ICMP error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    /// Destination unreachable, administratively prohibited.
    AdminProhibited,
    /// Fragmentation needed (IPv4) or packet too big (IPv6), with the MTU.
    TooBig(u16),
}

/// An ICMP or ICMPv6 error about `b`, sent from `from` to the packet's
/// source. Errors are never sent about ICMP errors or non-first fragments.
pub fn icmp_error(b: &[u8], p: &Parsed, kind: IcmpError, from: IpAddr) -> Option<Vec<u8>> {
    if p.is_icmp_error() || p.fragment.is_some_and(|(_, first)| !first) {
        return None;
    }
    if from.is_ipv4() != p.src.is_ipv4() {
        return None;
    }
    let ipv4 = p.src.is_ipv4();
    // Quote as much of the packet as the minimum MTU allows.
    let quote_max = if ipv4 { 576 - 28 } else { 1280 - 48 };
    let quote = &b[..p.len.min(quote_max)];
    let (protocol, ty, code, rest): (u8, u8, u8, [u8; 4]) = match (ipv4, kind) {
        (true, IcmpError::AdminProhibited) => (proto::ICMP, 3, 13, [0; 4]),
        (true, IcmpError::TooBig(mtu)) => {
            let m = mtu.to_be_bytes();
            (proto::ICMP, 3, 4, [0, 0, m[0], m[1]])
        }
        (false, IcmpError::AdminProhibited) => (proto::ICMPV6, 1, 1, [0; 4]),
        (false, IcmpError::TooBig(mtu)) => (proto::ICMPV6, 2, 0, u32::from(mtu).to_be_bytes()),
    };
    let mut seg = vec![ty, code, 0, 0];
    seg.extend_from_slice(&rest);
    seg.extend_from_slice(quote);
    Some(build(from, p.src, protocol, seg, Some(2)))
}

/// The flow tuple quoted inside an ICMP error, as the quoted packet's
/// source and destination: the packet the error is about.
pub fn quoted(b: &[u8], p: &Parsed) -> Option<(Parsed, usize)> {
    if !p.is_icmp_error() || p.l4 == 0 {
        return None;
    }
    let at = p.l4 + 8;
    let inner = &b[at..p.len];
    // The quote is usually truncated; parse its headers only.
    let mut tmp = inner.to_vec();
    match tmp.first()? >> 4 {
        4 if tmp.len() >= 20 => {
            let ihl = usize::from(tmp[0] & 0x0f) * 4;
            let fake = (tmp.len().max(ihl)) as u16;
            tmp[2..4].copy_from_slice(&fake.to_be_bytes());
        }
        6 if tmp.len() >= 40 => {
            let fake = (tmp.len() - 40) as u16;
            tmp[4..6].copy_from_slice(&fake.to_be_bytes());
        }
        _ => return None,
    }
    let q = parse_headers(&tmp, true).ok()?;
    Some((q, at))
}

/// Rewrites an address inside the packet quoted by an ICMP error and the
/// outer source, keeping every checksum valid: used to translate errors
/// about name-app flows back to the synthetic address the client used.
pub fn rewrite_icmp_error(
    b: &mut [u8],
    p: &Parsed,
    real: IpAddr,
    synthetic: IpAddr,
) -> Result<(), PacketError> {
    let (q, at) = quoted(b, p).ok_or(PacketError("not an ICMP error"))?;
    if q.dst != real || real.is_ipv4() != synthetic.is_ipv4() {
        return Err(PacketError("quoted packet does not match"));
    }
    let (old, new) = (octets(real), octets(synthetic));
    let ck = p.l4 + 2;
    // Quoted destination address.
    let addr_at = at + if real.is_ipv4() { 16 } else { 24 };
    b[addr_at..addr_at + old.len()].copy_from_slice(&new);
    adjust(b, ck, &old, &new);
    // Checksums inside the quote change too, and each change is itself
    // covered by the ICMP checksum: the quoted IPv4 header checksum, and the
    // quoted TCP or UDP checksum when the quote reaches it.
    let quoted_end = p.len;
    let fix_inner = |b: &mut [u8], field: usize| {
        if field + 2 > quoted_end {
            return;
        }
        let before = [b[field], b[field + 1]];
        if q.protocol == crate::bundle::proto::UDP && before == [0, 0] {
            return;
        }
        adjust(b, field, &old, &new);
        let after = [b[field], b[field + 1]];
        adjust(b, ck, &before, &after);
    };
    if real.is_ipv4() {
        fix_inner(b, at + 10);
    }
    if q.l4 != 0 {
        match q.protocol {
            crate::bundle::proto::UDP => fix_inner(b, at + q.l4 + 6),
            crate::bundle::proto::TCP => fix_inner(b, at + q.l4 + 16),
            _ => {}
        }
    }
    // ICMPv6 checksums cover the outer addresses; ICMPv4 ones do not.
    if p.src == real {
        let p_outer = *p;
        rewrite_addr(b, &p_outer, Side::Source, synthetic)?;
    }
    Ok(())
}

/// Splits an IPv4 packet without Don't Fragment into fragments that fit
/// `mtu` (RFC 791). Returns `None` for IPv6, DF packets, or packets that
/// already fit.
pub fn fragment_v4(b: &[u8], p: &Parsed, mtu: u16) -> Option<Vec<Vec<u8>>> {
    if !p.src.is_ipv4() || p.dont_fragment || p.len <= usize::from(mtu) {
        return None;
    }
    let ihl = usize::from(b[0] & 0x0f) * 4;
    let flags_frag = be16(b, 6);
    let base_offset = usize::from(flags_frag & 0x1fff) * 8;
    let more_after = flags_frag & 0x2000 != 0;
    let step = (usize::from(mtu) - ihl) & !7;
    if step == 0 {
        return None;
    }
    let payload = &b[ihl..p.len];
    let mut out = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        let end = (at + step).min(payload.len());
        let last = end == payload.len();
        let mut f = Vec::with_capacity(ihl + end - at);
        f.extend_from_slice(&b[..ihl]);
        f.extend_from_slice(&payload[at..end]);
        let total = f.len() as u16;
        f[2..4].copy_from_slice(&total.to_be_bytes());
        let off = ((base_offset + at) / 8) as u16;
        let mf = if !last || more_after { 0x2000 } else { 0 };
        f[6..8].copy_from_slice(&(off | mf).to_be_bytes());
        f[10..12].copy_from_slice(&[0, 0]);
        let ck = checksum(&f[..ihl], 0);
        f[10..12].copy_from_slice(&ck.to_be_bytes());
        out.push(f);
        at = end;
    }
    Some(out)
}

/// Verifies a packet's IP and upper-layer checksums (for tests).
pub fn checksums_valid(b: &[u8]) -> bool {
    let Ok(p) = parse(b) else { return false };
    if p.src.is_ipv4() {
        let ihl = usize::from(b[0] & 0x0f) * 4;
        if checksum(&b[..ihl], 0) != 0 {
            return false;
        }
    }
    if p.l4 == 0 {
        return true;
    }
    let seg = &b[p.l4..p.len];
    let pseudo = match p.protocol {
        proto::ICMP => 0,
        proto::UDP if p.src.is_ipv4() && be16(b, p.l4 + 6) == 0 => return true,
        _ => pseudo_header_sum(p.src, p.dst, p.protocol, seg.len()),
    };
    matches!(
        p.protocol,
        proto::TCP | proto::UDP | proto::ICMP | proto::ICMPV6
    ) && checksum(seg, pseudo) == 0
        || !matches!(
            p.protocol,
            proto::TCP | proto::UDP | proto::ICMP | proto::ICMPV6
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_syn(src: SocketAddr, dst: SocketAddr, mss: u16) -> Vec<u8> {
        let mut seg = vec![0u8; 24];
        seg[0..2].copy_from_slice(&src.port().to_be_bytes());
        seg[2..4].copy_from_slice(&dst.port().to_be_bytes());
        seg[4..8].copy_from_slice(&1000u32.to_be_bytes());
        seg[12] = 6 << 4;
        seg[13] = tcp::SYN;
        seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
        seg[20..24].copy_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
        build(src.ip(), dst.ip(), proto::TCP, seg, Some(16))
    }

    #[test]
    fn udp_round_trip_and_checksums() {
        for (s, d) in [
            ("100.96.0.2:5000", "10.20.0.5:53"),
            ("[fd00::2]:5000", "[fd00:20::5]:53"),
        ] {
            let (s, d): (SocketAddr, SocketAddr) = (s.parse().unwrap(), d.parse().unwrap());
            let pkt = udp(s, d, b"hello");
            assert!(checksums_valid(&pkt));
            let p = parse(&pkt).unwrap();
            assert_eq!((p.src_sock(), p.dst_sock(), p.protocol), (s, d, proto::UDP));
            assert_eq!(udp_payload(&pkt, &p), Some(&b"hello"[..]));
        }
    }

    #[test]
    fn rewriting_keeps_checksums_valid() {
        let cases = [
            ("100.96.0.2:40000", "100.80.0.7:443", "10.20.0.5"),
            ("[fd00::2]:40000", "[fd00:80::7]:443", "fd00:20::5"),
        ];
        for (s, d, real) in cases {
            let (s, d): (SocketAddr, SocketAddr) = (s.parse().unwrap(), d.parse().unwrap());
            let real: IpAddr = real.parse().unwrap();
            for mut pkt in [
                tcp_syn(s, d, 1460),
                udp(s, d, b"x"),
                icmp_echo(s.ip(), d.ip(), false, 7, 1, b"ping"),
            ] {
                let p = parse(&pkt).unwrap();
                rewrite_addr(&mut pkt, &p, Side::Destination, real).unwrap();
                assert!(checksums_valid(&pkt), "{p:?}");
                assert_eq!(parse(&pkt).unwrap().dst, real);
                let p = parse(&pkt).unwrap();
                rewrite_addr(
                    &mut pkt,
                    &p,
                    Side::Source,
                    "100.96.0.9".parse::<IpAddr>().unwrap(),
                )
                .map(|()| assert!(s.is_ipv4()))
                .unwrap_or_else(|_| assert!(s.is_ipv6()));
            }
        }
    }

    #[test]
    fn mss_is_clamped() {
        let mut pkt = tcp_syn(
            "100.96.0.2:40000".parse().unwrap(),
            "10.0.0.1:22".parse().unwrap(),
            1460,
        );
        let p = parse(&pkt).unwrap();
        assert!(clamp_mss(&mut pkt, &p, mss_for(1280, true)));
        assert!(checksums_valid(&pkt));
        assert_eq!(be16(&pkt, 20 + 22), 1240);
        let p = parse(&pkt).unwrap();
        assert!(!clamp_mss(&mut pkt, &p, 1300));
    }

    #[test]
    fn resets_and_icmp_errors() {
        let s: SocketAddr = "100.96.0.2:40000".parse().unwrap();
        let d: SocketAddr = "10.0.0.1:22".parse().unwrap();
        let syn = tcp_syn(s, d, 1460);
        let p = parse(&syn).unwrap();
        let rst = tcp_reset(&syn, &p).unwrap();
        assert!(checksums_valid(&rst));
        let r = parse(&rst).unwrap();
        assert_eq!((r.src_sock(), r.dst_sock()), (d, s));
        assert_eq!(r.tcp_flags, tcp::RST | tcp::ACK);
        assert_eq!(u32::from_be_bytes(rst[28..32].try_into().unwrap()), 1001);

        for (s, d) in [
            ("100.96.0.2:5000", "10.0.0.1:53"),
            ("[fd00::2]:5000", "[fd00:20::1]:53"),
        ] {
            let (s, d): (SocketAddr, SocketAddr) = (s.parse().unwrap(), d.parse().unwrap());
            let pkt = udp(s, d, &[0u8; 1400]);
            let p = parse(&pkt).unwrap();
            for kind in [IcmpError::AdminProhibited, IcmpError::TooBig(1280)] {
                let e = icmp_error(&pkt, &p, kind, d.ip()).unwrap();
                assert!(checksums_valid(&e));
                assert!(e.len() <= 1280);
                let ep = parse(&e).unwrap();
                assert!(ep.is_icmp_error());
                assert_eq!(ep.dst, s.ip());
                let (q, _) = quoted(&e, &ep).unwrap();
                assert_eq!((q.src_sock(), q.dst_sock()), (s, d));
                // Never an error about an error.
                assert!(icmp_error(&e, &ep, kind, d.ip()).is_none());
            }
        }
    }

    #[test]
    fn icmp_errors_translate_back_to_synthetic_addresses() {
        for (client, real, synthetic) in [
            ("100.96.0.2:5000", "10.20.0.5:53", "100.80.0.7"),
            ("[fd00::2]:5000", "[fd00:20::5]:53", "fd00:80::7"),
        ] {
            let (client, real): (SocketAddr, SocketAddr) =
                (client.parse().unwrap(), real.parse().unwrap());
            let synthetic: IpAddr = synthetic.parse().unwrap();
            // The client's packet after translation to the real address.
            let sent = udp(client, real, b"query");
            let p = parse(&sent).unwrap();
            let mut err = icmp_error(&sent, &p, IcmpError::AdminProhibited, real.ip()).unwrap();
            let ep = parse(&err).unwrap();
            rewrite_icmp_error(&mut err, &ep, real.ip(), synthetic).unwrap();
            assert!(checksums_valid(&err));
            let ep = parse(&err).unwrap();
            assert_eq!(ep.src, synthetic);
            let (q, _) = quoted(&err, &ep).unwrap();
            assert_eq!(q.dst, synthetic);
        }
    }

    #[test]
    fn minimal_quotes_of_tcp_packets_are_understood() {
        for (client, real, synthetic, header) in [
            ("100.96.0.2:40000", "10.20.0.5:443", "100.80.0.7", 20),
            ("[fd00::2]:40000", "[fd00:20::5]:443", "fd00:80::7", 40),
        ] {
            let (client, real): (SocketAddr, SocketAddr) =
                (client.parse().unwrap(), real.parse().unwrap());
            let synthetic: IpAddr = synthetic.parse().unwrap();
            let syn = tcp_syn(client, real, 1460);
            let mut p = parse(&syn).unwrap();
            // An error quoting only the IP header and 8 bytes (RFC 792).
            p.len = header + 8;
            let mut err = icmp_error(&syn, &p, IcmpError::TooBig(1280), real.ip()).unwrap();
            let ep = parse(&err).unwrap();
            let (q, _) = quoted(&err, &ep).unwrap();
            assert_eq!(
                (q.protocol, q.src_sock(), q.dst_sock()),
                (proto::TCP, client, real)
            );
            rewrite_icmp_error(&mut err, &ep, real.ip(), synthetic).unwrap();
            assert!(checksums_valid(&err));
            let ep = parse(&err).unwrap();
            let (q, _) = quoted(&err, &ep).unwrap();
            assert_eq!(q.dst_sock(), SocketAddr::new(synthetic, real.port()));
        }
    }

    #[test]
    fn ipv4_fragmentation() {
        let s: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let d: SocketAddr = "100.96.0.2:5000".parse().unwrap();
        let mut pkt = udp(s, d, &[7u8; 2000]);
        pkt[6] &= !0x40;
        let ck = checksum(
            &{
                let mut h = pkt[..20].to_vec();
                h[10] = 0;
                h[11] = 0;
                h
            },
            0,
        );
        pkt[10..12].copy_from_slice(&ck.to_be_bytes());
        let p = parse(&pkt).unwrap();
        let frags = fragment_v4(&pkt, &p, 1280).unwrap();
        assert_eq!(frags.len(), 2);
        assert!(
            frags
                .iter()
                .all(|f| f.len() <= 1280 && checksum(&f[..20], 0) == 0)
        );
        let payload: Vec<u8> = frags.iter().flat_map(|f| f[20..].to_vec()).collect();
        assert_eq!(payload, pkt[20..]);
        assert_eq!(parse(&frags[1]).unwrap().fragment.map(|f| f.1), Some(false));
        // DF packets are not fragmented.
        let df = udp(s, d, &[7u8; 2000]);
        assert!(fragment_v4(&df, &parse(&df).unwrap(), 1280).is_none());
    }

    #[test]
    fn fragments_and_malformed_packets() {
        let s: SocketAddr = "100.96.0.2:5000".parse().unwrap();
        let mut pkt = udp(s, "10.0.0.1:53".parse().unwrap(), &[1u8; 100]);
        // Non-first fragment: offset 8 (64 bytes).
        pkt[6..8].copy_from_slice(&0x0008u16.to_be_bytes());
        let p = parse(&pkt).unwrap();
        assert_eq!(p.l4, 0);
        assert_eq!(p.fragment.map(|f| f.1), Some(false));
        assert!(parse(&[0x45, 0, 0]).is_err());
        assert!(parse(&[0x75; 40]).is_err());
        let mut short = udp(s, "10.0.0.1:53".parse().unwrap(), b"x");
        short[2..4].copy_from_slice(&500u16.to_be_bytes());
        assert!(parse(&short).is_err());
    }
}
