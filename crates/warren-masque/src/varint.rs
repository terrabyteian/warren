//! QUIC variable-length integers (RFC 9000, section 16), shared by HTTP/3
//! frames, capsules and HTTP Datagram prefixes.

use bytes::{Buf, BufMut};

/// The largest value a variable-length integer can carry.
pub const MAX: u64 = (1 << 62) - 1;

/// Encoded length in bytes of `v`.
///
/// # Panics
///
/// Panics if `v` exceeds [`MAX`].
pub fn len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ if v <= MAX => 8,
        _ => panic!("varint out of range: {v}"),
    }
}

/// Appends `v` in its shortest encoding.
///
/// # Panics
///
/// Panics if `v` exceeds [`MAX`].
pub fn put(out: &mut impl BufMut, v: u64) {
    match len(v) {
        1 => out.put_u8(v as u8),
        2 => out.put_u16(0x4000 | v as u16),
        4 => out.put_u32(0x8000_0000 | v as u32),
        _ => out.put_u64(0xc000_0000_0000_0000 | v),
    }
}

/// Reads one variable-length integer, or returns `None` (consuming nothing)
/// when `buf` holds only part of one.
pub fn get(buf: &mut impl Buf) -> Option<u64> {
    let first = *buf.chunk().first()?;
    let n = 1usize << (first >> 6);
    if buf.remaining() < n {
        return None;
    }
    let v = match n {
        1 => u64::from(buf.get_u8()),
        2 => u64::from(buf.get_u16() & 0x3fff),
        4 => u64::from(buf.get_u32() & 0x3fff_ffff),
        _ => buf.get_u64() & 0x3fff_ffff_ffff_ffff,
    };
    Some(v)
}

/// Reads a variable-length integer from the front of a byte slice, returning
/// the value and the number of bytes it used.
pub fn peek(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut b = bytes;
    let v = get(&mut b)?;
    Some((v, bytes.len() - b.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_examples_round_trip() {
        // RFC 9000, appendix A.1.
        let cases: [(&[u8], u64); 4] = [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (wire, value) in cases {
            assert_eq!(peek(wire), Some((value, wire.len())));
            let mut out = Vec::new();
            put(&mut out, value);
            assert_eq!(out, wire);
        }
        // A non-minimal encoding still decodes.
        assert_eq!(peek(&[0x40, 0x25]), Some((37, 2)));
    }

    #[test]
    fn partial_input_consumes_nothing() {
        let mut b: &[u8] = &[0x9d, 0x7f];
        assert_eq!(get(&mut b), None);
        assert_eq!(b.len(), 2);
        assert_eq!(peek(&[]), None);
    }

    #[test]
    fn boundaries() {
        for v in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, MAX] {
            let mut out = Vec::new();
            put(&mut out, v);
            assert_eq!(out.len(), len(v));
            assert_eq!(peek(&out), Some((v, out.len())));
        }
    }
}
