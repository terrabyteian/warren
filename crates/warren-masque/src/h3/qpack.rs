//! A QPACK (RFC 9204) codec without a dynamic table.
//!
//! warren advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and
//! `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, so a conforming peer never refers to
//! a dynamic table entry and every field section has a Required Insert Count
//! of zero. That removes the encoder and decoder streams and all of their
//! state. The decoder still accepts every static-table and literal
//! representation, with or without Huffman coding; the encoder uses static
//! references and plain literals.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::huffman_table::HUFFMAN_CODES;
use super::static_table::STATIC_TABLE;

/// One header field.
pub type Field = (String, String);

/// A field section could not be decoded (QPACK_DECOMPRESSION_FAILED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QPACK decoding failed: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

/// Upper bound on a decoded field section, matching the
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` warren advertises.
pub const MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;

fn encode_int(out: &mut Vec<u8>, flags: u8, prefix_bits: u8, mut value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    value -= max;
    while value >= 128 {
        out.push((value % 128) as u8 | 0x80);
        value /= 128;
    }
    out.push(value as u8);
}

fn decode_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<u64, DecodeError> {
    let first = *buf.get(*pos).ok_or(DecodeError("truncated integer"))?;
    *pos += 1;
    let max = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & max;
    if value < max {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or(DecodeError("truncated integer"))?;
        *pos += 1;
        if shift > 56 {
            return Err(DecodeError("integer overflow"));
        }
        value += u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

fn encode_string(out: &mut Vec<u8>, flags: u8, prefix_bits: u8, s: &[u8]) {
    // Plain literal: the Huffman bit, just above the prefix, stays clear.
    encode_int(out, flags, prefix_bits, s.len() as u64);
    out.extend_from_slice(s);
}

fn decode_string(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<String, DecodeError> {
    let first = *buf.get(*pos).ok_or(DecodeError("truncated string"))?;
    let huffman = first & (1 << prefix_bits) != 0;
    let len = decode_int(buf, pos, prefix_bits)?;
    if len > MAX_FIELD_SECTION_SIZE {
        return Err(DecodeError("string too long"));
    }
    let end = pos
        .checked_add(len as usize)
        .filter(|e| *e <= buf.len())
        .ok_or(DecodeError("truncated string"))?;
    let raw = &buf[*pos..end];
    *pos = end;
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| DecodeError("field is not UTF-8"))
}

fn huffman_lookup() -> &'static HashMap<(u8, u32), u16> {
    static TABLE: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
    TABLE.get_or_init(|| {
        HUFFMAN_CODES
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((len, code), sym as u16))
            .collect()
    })
}

/// Decodes a Huffman-coded string (RFC 7541, section 5.2).
pub fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let table = huffman_lookup();
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let (mut code, mut len) = (0u32, 0u8);
    for byte in input {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len >= 5
                && let Some(&sym) = table.get(&(len, code))
            {
                if sym == 256 {
                    return Err(DecodeError("EOS in Huffman string"));
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            }
            if len > 30 {
                return Err(DecodeError("invalid Huffman code"));
            }
        }
    }
    // Padding: at most 7 bits, all ones (the most significant bits of EOS).
    if len > 7 || code != (1u32 << len) - 1 {
        return Err(DecodeError("invalid Huffman padding"));
    }
    Ok(out)
}

/// Huffman-encodes a string; used to test the decoder against peers that
/// compress.
pub fn huffman_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u64, 0u32);
    for &b in input {
        let (code, len) = HUFFMAN_CODES[usize::from(b)];
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (8 - bits)) as u8) | (0xff >> bits));
    }
    out
}

/// Encodes a field section with Required Insert Count zero.
pub fn encode(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0, 0];
    for (name, value) in fields {
        let exact = STATIC_TABLE
            .iter()
            .position(|(n, v)| n == name && v == value);
        if let Some(i) = exact {
            // Indexed field line, static table: 1 T=1 index(6).
            encode_int(&mut out, 0xc0, 6, i as u64);
            continue;
        }
        if let Some(i) = STATIC_TABLE.iter().position(|(n, _)| n == name) {
            // Literal with name reference, static table: 01 N=0 T=1 index(4).
            encode_int(&mut out, 0x50, 4, i as u64);
            encode_string(&mut out, 0x00, 7, value.as_bytes());
        } else {
            // Literal with literal name: 001 N=0 H=0 length(3).
            encode_string(&mut out, 0x20, 3, name.as_bytes());
            encode_string(&mut out, 0x00, 7, value.as_bytes());
        }
    }
    out
}

fn static_entry(index: u64) -> Result<(&'static str, &'static str), DecodeError> {
    STATIC_TABLE
        .get(index as usize)
        .copied()
        .ok_or(DecodeError("static index out of range"))
}

/// Decodes a field section. Any reference to the dynamic table is an error,
/// because warren's settings forbid one.
pub fn decode(buf: &[u8]) -> Result<Vec<Field>, DecodeError> {
    let mut pos = 0;
    let required_insert_count = decode_int(buf, &mut pos, 8)?;
    if required_insert_count != 0 {
        return Err(DecodeError("dynamic table reference"));
    }
    // Sign bit and Delta Base; meaningless without a dynamic table.
    decode_int(buf, &mut pos, 7)?;
    let mut fields = Vec::new();
    let mut size = 0u64;
    while pos < buf.len() {
        let b = buf[pos];
        let field = if b & 0x80 != 0 {
            // Indexed field line.
            if b & 0x40 == 0 {
                return Err(DecodeError("dynamic table reference"));
            }
            let (n, v) = static_entry(decode_int(buf, &mut pos, 6)?)?;
            (n.to_owned(), v.to_owned())
        } else if b & 0x40 != 0 {
            // Literal field line with name reference.
            if b & 0x10 == 0 {
                return Err(DecodeError("dynamic table reference"));
            }
            let (n, _) = static_entry(decode_int(buf, &mut pos, 4)?)?;
            (n.to_owned(), decode_string(buf, &mut pos, 7)?)
        } else if b & 0x20 != 0 {
            // Literal field line with literal name.
            let name = decode_string(buf, &mut pos, 3)?;
            (name, decode_string(buf, &mut pos, 7)?)
        } else {
            // Post-base forms refer to the dynamic table.
            return Err(DecodeError("dynamic table reference"));
        };
        size += (field.0.len() + field.1.len() + 32) as u64;
        if size > MAX_FIELD_SECTION_SIZE {
            return Err(DecodeError("field section too large"));
        }
        fields.push(field);
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_huffman_examples() {
        // RFC 7541, appendix C.4.1 to C.4.3.
        let cases: [(&str, &str); 3] = [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-value", "25a849e95bb8e8b4bf"),
        ];
        for (plain, hex) in cases {
            let wire: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(huffman_decode(&wire).unwrap(), plain.as_bytes());
            assert_eq!(huffman_encode(plain.as_bytes()), wire);
        }
    }

    #[test]
    fn huffman_rejects_bad_padding_and_eos() {
        // "a" is 00011 (5 bits); padding with zeros is invalid.
        assert!(huffman_decode(&[0b0001_1000]).is_err());
        assert_eq!(huffman_decode(&[0b0001_1111]).unwrap(), b"a");
        // A full byte of padding is too long.
        assert!(huffman_decode(&[0b0001_1111, 0xff]).is_err());
        // EOS spelled out is an error.
        assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn every_byte_round_trips_through_huffman() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(huffman_decode(&huffman_encode(&all)).unwrap(), all);
    }

    #[test]
    fn static_table_spot_checks() {
        assert_eq!(STATIC_TABLE[15], (":method", "CONNECT"));
        assert_eq!(STATIC_TABLE[23], (":scheme", "https"));
        assert_eq!(STATIC_TABLE[25], (":status", "200"));
        assert_eq!(
            STATIC_TABLE[52],
            ("content-type", "text/html; charset=utf-8")
        );
        assert_eq!(STATIC_TABLE[98], ("x-frame-options", "sameorigin"));
    }

    #[test]
    fn field_sections_round_trip() {
        let fields = [
            (":method", "CONNECT"),
            (":protocol", "connect-ip"),
            (":scheme", "https"),
            (":authority", "homelab.connectors.warren.invalid"),
            (":path", "/.well-known/masque/ip/*/*/"),
            ("capsule-protocol", "?1"),
            ("warren-protocol", "1"),
            (":status", "200"),
            (
                "a-very-long-custom-header-name-for-the-prefix",
                &"x".repeat(300),
            ),
        ];
        let wire = encode(&fields);
        let decoded = decode(&wire).unwrap();
        let expect: Vec<Field> = fields
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(decoded, expect);
    }

    #[test]
    fn decodes_huffman_literals_from_other_encoders() {
        // Literal with literal name, both Huffman coded: 001 N=0 H=1 len(3).
        let name = huffman_encode(b"warren-protocol");
        let value = huffman_encode(b"1");
        let mut wire = vec![0, 0];
        encode_int(&mut wire, 0x28, 3, name.len() as u64);
        wire.extend_from_slice(&name);
        encode_int(&mut wire, 0x80, 7, value.len() as u64);
        wire.extend_from_slice(&value);
        assert_eq!(
            decode(&wire).unwrap(),
            vec![("warren-protocol".to_string(), "1".to_string())]
        );
    }

    #[test]
    fn dynamic_references_are_rejected() {
        assert!(decode(&[1, 0]).is_err()); // Required Insert Count 1
        assert!(decode(&[0, 0, 0x80]).is_err()); // indexed, dynamic
        assert!(decode(&[0, 0, 0x40, 0]).is_err()); // name ref, dynamic
        assert!(decode(&[0, 0, 0x10]).is_err()); // post-base indexed
        assert!(decode(&[0, 0, 0x00]).is_err()); // post-base name ref
        assert!(decode(&[0, 0, 0xff, 0x7f]).is_err()); // static index out of range
    }

    #[test]
    fn prefix_integers() {
        // RFC 7541, appendix C.1.
        let mut out = Vec::new();
        encode_int(&mut out, 0, 5, 10);
        assert_eq!(out, [10]);
        out.clear();
        encode_int(&mut out, 0, 5, 1337);
        assert_eq!(out, [31, 154, 10]);
        let mut pos = 0;
        assert_eq!(decode_int(&out, &mut pos, 5).unwrap(), 1337);
        assert_eq!(pos, 3);
    }
}
