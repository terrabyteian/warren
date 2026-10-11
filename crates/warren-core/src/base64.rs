//! Base64 (RFC 4648) for PEM files, join tokens and the join exchange.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_with(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(alphabet[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn decode_with(text: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut lookup = [0xffu8; 256];
    for (i, c) in alphabet.iter().enumerate() {
        lookup[usize::from(*c)] = i as u8;
    }
    let bytes: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let trimmed = bytes
        .strip_suffix(b"==")
        .or_else(|| bytes.strip_suffix(b"="))
        .unwrap_or(&bytes);
    if trimmed.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    for chunk in trimmed.chunks(4) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            let v = lookup[usize::from(*b)];
            if v == 0xff {
                return None;
            }
            n |= u32::from(v) << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

/// Standard alphabet with padding.
pub fn encode(data: &[u8]) -> String {
    encode_with(data, STANDARD, true)
}

/// Decodes the standard alphabet, padding optional, whitespace ignored.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    decode_with(text, STANDARD)
}

/// URL-safe alphabet without padding.
pub fn encode_url(data: &[u8]) -> String {
    encode_with(data, URL_SAFE, false)
}

/// Decodes the URL-safe alphabet.
pub fn decode_url(text: &str) -> Option<Vec<u8>> {
    decode_with(text, URL_SAFE)
}

/// PEM-encodes DER with a label.
pub fn pem(label: &str, der: &[u8]) -> String {
    let b64 = encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in cases {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
            assert_eq!(
                decode_url(&encode_url(plain.as_bytes())).unwrap(),
                plain.as_bytes()
            );
        }
        assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
        assert!(decode("Zm9v!").is_none());
        assert!(decode("Z").is_none());
    }
}
