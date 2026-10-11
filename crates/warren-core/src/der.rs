//! A minimal DER reader and writer (ITU-T X.690) for the certificate fields
//! warren checks and the structures it encodes. It is not a general ASN.1
//! library: it handles single-byte tags and definite lengths only, which is
//! all DER uses in X.509. Certificates are parsed only after their signature
//! chain has been verified by webpki.

use std::fmt;

/// Universal and context tags used by warren.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// ENUMERATED.
    pub const ENUMERATED: u8 = 0x0a;
    /// UTF8String.
    pub const UTF8_STRING: u8 = 0x0c;
    /// UTCTime.
    pub const UTC_TIME: u8 = 0x17;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// SEQUENCE.
    pub const SEQUENCE: u8 = 0x30;
    /// SET.
    pub const SET: u8 = 0x31;

    /// A constructed context-specific tag, `[n]`.
    pub const fn context(n: u8) -> u8 {
        0xa0 | n
    }

    /// A primitive context-specific tag, `[n] IMPLICIT`.
    pub const fn context_primitive(n: u8) -> u8 {
        0x80 | n
    }
}

/// A DER decoding error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerError(pub &'static str);

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DER: {}", self.0)
    }
}

impl std::error::Error for DerError {}

/// Reads TLVs from a byte slice.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Reads from `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The tag of the next element.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads the next element's tag and value.
    pub fn read_any(&mut self) -> Result<(u8, &'a [u8]), DerError> {
        let (&t, rest) = self.data.split_first().ok_or(DerError("truncated tag"))?;
        if t & 0x1f == 0x1f {
            return Err(DerError("multi-byte tags are not supported"));
        }
        let (&first, mut rest) = rest.split_first().ok_or(DerError("truncated length"))?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(DerError("invalid length"));
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = (len << 8) | usize::from(b);
            }
            // DER requires the shortest length encoding.
            if len < 0x80 || rest[0] == 0 {
                return Err(DerError("non-minimal length"));
            }
            rest = &rest[n..];
            len
        };
        if rest.len() < len {
            return Err(DerError("truncated value"));
        }
        let (value, rest) = rest.split_at(len);
        self.data = rest;
        Ok((t, value))
    }

    /// Reads an element that must have tag `t`, returning the whole encoded
    /// element and its value.
    pub fn read_element(&mut self, t: u8) -> Result<(&'a [u8], &'a [u8]), DerError> {
        let start = self.data;
        let value = self.read(t)?;
        let used = start.len() - self.data.len();
        Ok((&start[..used], value))
    }

    /// Reads an element that must have tag `t`.
    pub fn read(&mut self, t: u8) -> Result<&'a [u8], DerError> {
        match self.read_any()? {
            (got, v) if got == t => Ok(v),
            _ => Err(DerError("unexpected tag")),
        }
    }

    /// Reads an element with tag `t` if it is next.
    pub fn read_optional(&mut self, t: u8) -> Result<Option<&'a [u8]>, DerError> {
        if self.peek_tag() == Some(t) {
            self.read(t).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads a BOOLEAN.
    pub fn read_bool(&mut self) -> Result<bool, DerError> {
        match self.read(tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DerError("invalid BOOLEAN")),
        }
    }

    /// Reads a non-negative INTEGER (or ENUMERATED with `t`) that fits a u64.
    pub fn read_u64(&mut self, t: u8) -> Result<u64, DerError> {
        let v = self.read(t)?;
        let v = match v {
            [] => return Err(DerError("empty INTEGER")),
            [0x00, rest @ ..] if !rest.is_empty() && rest[0] & 0x80 == 0 => {
                return Err(DerError("non-minimal INTEGER"));
            }
            [0x00, rest @ ..] => rest,
            [b, ..] if b & 0x80 != 0 => return Err(DerError("negative INTEGER")),
            v => v,
        };
        if v.len() > 8 {
            return Err(DerError("INTEGER too large"));
        }
        Ok(v.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// Requires that everything has been consumed.
    pub fn finish(&self) -> Result<(), DerError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(DerError("trailing data"))
        }
    }
}

/// Encodes one TLV.
pub fn tlv(t: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(t);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(value);
    out
}

/// Encodes a SEQUENCE of already-encoded elements.
pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

/// Encodes a non-negative INTEGER (or ENUMERATED with `t`).
pub fn uint(t: u8, v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let skip = bytes
        .iter()
        .take_while(|b| **b == 0)
        .count()
        .min(bytes.len() - 1);
    let mut body = Vec::with_capacity(9);
    if bytes[skip] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(&bytes[skip..]);
    tlv(t, &body)
}

/// Encodes a BOOLEAN.
pub fn boolean(b: bool) -> Vec<u8> {
    tlv(tag::BOOLEAN, &[if b { 0xff } else { 0x00 }])
}

/// Encodes an OBJECT IDENTIFIER from its arcs. Arcs may exceed 64 bits, as
/// in UUID-based OIDs (`2.25.n`).
pub fn oid(arcs: &[u128]) -> Vec<u8> {
    tlv(tag::OID, &oid_value(arcs))
}

/// The content octets of an OBJECT IDENTIFIER.
///
/// # Panics
///
/// Panics if fewer than two arcs are given or the first two are invalid.
pub fn oid_value(arcs: &[u128]) -> Vec<u8> {
    assert!(arcs.len() >= 2 && arcs[0] <= 2 && (arcs[0] == 2 || arcs[1] < 40));
    let mut out = Vec::new();
    let mut put = |mut v: u128| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        tmp.reverse();
        out.extend_from_slice(&tmp);
    };
    put(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        put(a);
    }
    out
}

/// Seconds since the Unix epoch for a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn digits(s: &[u8]) -> Result<u32, DerError> {
    s.iter().try_fold(0u32, |acc, &b| {
        if b.is_ascii_digit() {
            Ok(acc * 10 + u32::from(b - b'0'))
        } else {
            Err(DerError("invalid time digit"))
        }
    })
}

/// Parses a UTCTime or GeneralizedTime value (`Z` form, as RFC 5280
/// requires) to seconds since the Unix epoch.
pub fn parse_time(t: u8, v: &[u8]) -> Result<i64, DerError> {
    let (year, rest) = match (t, v.len()) {
        (tag::UTC_TIME, 13) => {
            let yy = digits(&v[..2])? as i64;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..])
        }
        (tag::GENERALIZED_TIME, 15) => (digits(&v[..4])? as i64, &v[4..]),
        _ => return Err(DerError("invalid time")),
    };
    if rest[10] != b'Z' {
        return Err(DerError("time is not UTC"));
    }
    let (mo, d, h, mi, s) = (
        digits(&rest[0..2])?,
        digits(&rest[2..4])?,
        digits(&rest[4..6])?,
        digits(&rest[6..8])?,
        digits(&rest[8..10])?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return Err(DerError("time out of range"));
    }
    Ok(days_from_civil(year, mo, d) * 86_400
        + i64::from(h) * 3600
        + i64::from(mi) * 60
        + i64::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_round_trip() {
        for len in [0usize, 1, 127, 128, 255, 256, 65_535, 70_000] {
            let value = vec![7u8; len];
            let enc = tlv(tag::OCTET_STRING, &value);
            let mut r = Reader::new(&enc);
            assert_eq!(r.read(tag::OCTET_STRING).unwrap(), &value[..]);
            r.finish().unwrap();
        }
    }

    #[test]
    fn rejects_non_der_lengths() {
        // Indefinite, long form for a short length, and leading zero.
        assert!(Reader::new(&[0x04, 0x80]).read_any().is_err());
        assert!(
            Reader::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5])
                .read_any()
                .is_err()
        );
        assert!(Reader::new(&[0x04, 0x82, 0x00, 0x80]).read_any().is_err());
        assert!(Reader::new(&[0x04, 0x05, 1]).read_any().is_err());
        assert!(Reader::new(&[0x1f, 0x01, 0x00]).read_any().is_err());
    }

    #[test]
    fn integers() {
        for v in [0u64, 1, 127, 128, 255, 256, u64::MAX] {
            let enc = uint(tag::INTEGER, v);
            assert_eq!(Reader::new(&enc).read_u64(tag::INTEGER).unwrap(), v);
        }
        assert_eq!(uint(tag::INTEGER, 128), [0x02, 0x02, 0x00, 0x80]);
        assert!(
            Reader::new(&[0x02, 0x01, 0x80])
                .read_u64(tag::INTEGER)
                .is_err()
        );
        assert!(
            Reader::new(&[0x02, 0x02, 0x00, 0x01])
                .read_u64(tag::INTEGER)
                .is_err()
        );
    }

    #[test]
    fn oids() {
        // 1.2.840.10045.3.1.7 (prime256v1).
        assert_eq!(
            oid_value(&[1, 2, 840, 10045, 3, 1, 7]),
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        );
        // 2.25 UUID arcs encode beyond 64 bits.
        let v = oid_value(&[2, 25, u128::MAX]);
        assert_eq!(v[0], 105);
        assert_eq!(v.len(), 1 + 19);
    }

    #[test]
    fn times() {
        assert_eq!(parse_time(tag::UTC_TIME, b"700101000000Z").unwrap(), 0);
        assert_eq!(
            parse_time(tag::GENERALIZED_TIME, b"20261011120000Z").unwrap(),
            1_791_720_000
        );
        assert_eq!(
            parse_time(tag::UTC_TIME, b"491231235959Z").unwrap(),
            2_524_607_999
        );
        assert!(parse_time(tag::UTC_TIME, b"700101000000+").is_err());
        assert!(parse_time(tag::UTC_TIME, b"701301000000Z").is_err());
    }
}
