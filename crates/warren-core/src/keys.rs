//! ECDSA P-256 keys: the device key profile, every infrastructure key and the
//! control plane's signing keys (docs/protocol.md sections 3 and 10).
//!
//! All operations go through aws-lc-rs; nothing here implements cryptography.

use std::fmt;

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, UnparsedPublicKey,
};
use zeroize::Zeroizing;

/// A key or signature operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(pub &'static str);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for KeyError {}

/// An ECDSA P-256 public key, held as its uncompressed SEC 1 point
/// (`0x04 || x || y`, 65 bytes).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 65]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex(&self.key_id()))
    }
}

impl PublicKey {
    /// A key from its uncompressed point. The point is checked to be on the
    /// curve.
    pub fn from_point(point: &[u8]) -> Result<PublicKey, KeyError> {
        let bytes: [u8; 65] = point
            .try_into()
            .map_err(|_| KeyError("a P-256 public key is a 65-byte uncompressed point"))?;
        if bytes[0] != 0x04 {
            return Err(KeyError("only uncompressed P-256 points are accepted"));
        }
        // aws-lc-rs validates the point when a key is parsed for
        // verification; do that once here so every PublicKey is usable.
        aws_lc_rs::signature::ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, bytes)
            .map_err(|_| KeyError("the point is not on the P-256 curve"))?;
        Ok(PublicKey(bytes))
    }

    /// A key from the x and y coordinates (32 bytes each, as in a JWK).
    pub fn from_coordinates(x: &[u8], y: &[u8]) -> Result<PublicKey, KeyError> {
        if x.len() != 32 || y.len() != 32 {
            return Err(KeyError("P-256 coordinates are 32 bytes each"));
        }
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(y);
        PublicKey::from_point(&point)
    }

    /// The uncompressed point.
    pub fn point(&self) -> &[u8; 65] {
        &self.0
    }

    /// The x coordinate.
    pub fn x(&self) -> &[u8] {
        &self.0[1..33]
    }

    /// The y coordinate.
    pub fn y(&self) -> &[u8] {
        &self.0[33..]
    }

    /// Verifies a DER (X9.62 `ECDSA-Sig-Value`) signature over `message`
    /// with SHA-256, as X.509 and PKCS#10 use.
    pub fn verify_der(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.0[..])
            .verify(message, signature)
            .map_err(|_| KeyError("signature verification failed"))
    }

    /// Verifies a fixed-length (`r || s`, 64 bytes) signature over `message`
    /// with SHA-256, as JWS ES256 uses.
    pub fn verify_fixed(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.0[..])
            .verify(message, signature)
            .map_err(|_| KeyError("signature verification failed"))
    }

    /// The key identifier: the leftmost 160 bits of the SHA-256 digest of
    /// the point (RFC 7093 section 2, method 1). Used for the Subject and
    /// Authority Key Identifier extensions.
    pub fn key_id(&self) -> [u8; 20] {
        let d = digest::digest(&digest::SHA256, &self.0);
        let mut id = [0u8; 20];
        id.copy_from_slice(&d.as_ref()[..20]);
        id
    }
}

/// An ECDSA P-256 private key held in memory, able to sign in both the DER
/// and the fixed-length encodings.
pub struct SigningKey {
    der: EcdsaKeyPair,
    fixed: EcdsaKeyPair,
    public: PublicKey,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({:?})", self.public)
    }
}

impl SigningKey {
    /// Generates a new key from the system's CSPRNG.
    pub fn generate() -> Result<SigningKey, KeyError> {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .map_err(|_| KeyError("key generation failed"))?;
        let pkcs8 = pair
            .to_pkcs8v1()
            .map_err(|_| KeyError("key serialization failed"))?;
        SigningKey::from_pkcs8(pkcs8.as_ref())
    }

    /// Loads a key from PKCS#8 (RFC 5208) DER.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<SigningKey, KeyError> {
        let der = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
            .map_err(|_| KeyError("not a P-256 PKCS#8 private key"))?;
        let fixed = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| KeyError("not a P-256 PKCS#8 private key"))?;
        let public = PublicKey::from_point(der.public_key().as_ref())?;
        Ok(SigningKey { der, fixed, public })
    }

    /// The private key as PKCS#8 DER, for storage under the deployment's
    /// key-encryption key. The buffer is wiped when dropped.
    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        Ok(Zeroizing::new(
            self.der
                .to_pkcs8v1()
                .map_err(|_| KeyError("key serialization failed"))?
                .as_ref()
                .to_vec(),
        ))
    }

    /// The public half.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Signs `message` with SHA-256, DER-encoded signature.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.der
            .sign(&SystemRandom::new(), message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| KeyError("signing failed"))
    }

    /// Signs `message` with SHA-256, fixed-length `r || s` signature.
    pub fn sign_fixed(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.fixed
            .sign(&SystemRandom::new(), message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| KeyError("signing failed"))
    }
}

/// Fills a buffer from the system's CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], KeyError> {
    let mut out = [0u8; N];
    aws_lc_rs::rand::fill(&mut out).map_err(|_| KeyError("the system CSPRNG failed"))?;
    Ok(out)
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Parses lowercase or uppercase hexadecimal.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_in_both_encodings() {
        let key = SigningKey::generate().unwrap();
        let der = key.sign_der(b"hello").unwrap();
        let fixed = key.sign_fixed(b"hello").unwrap();
        assert_eq!(fixed.len(), 64);
        key.public_key().verify_der(b"hello", &der).unwrap();
        key.public_key().verify_fixed(b"hello", &fixed).unwrap();
        assert!(key.public_key().verify_der(b"hellO", &der).is_err());
        assert!(key.public_key().verify_fixed(b"hello", &der).is_err());
    }

    #[test]
    fn pkcs8_round_trips() {
        let key = SigningKey::generate().unwrap();
        let again = SigningKey::from_pkcs8(&key.to_pkcs8().unwrap()).unwrap();
        assert_eq!(key.public_key(), again.public_key());
    }

    #[test]
    fn points_off_the_curve_are_rejected() {
        let key = SigningKey::generate().unwrap();
        let mut point = *key.public_key().point();
        assert!(PublicKey::from_point(&point).is_ok());
        point[64] ^= 1;
        assert!(PublicKey::from_point(&point).is_err());
        assert!(PublicKey::from_point(&point[..64]).is_err());
        let mut compressed = *key.public_key().point();
        compressed[0] = 0x02;
        assert!(PublicKey::from_point(&compressed).is_err());
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0x00, 0xab, 0x7f]), "00ab7f");
        assert_eq!(unhex("00AB7f"), Some(vec![0x00, 0xab, 0x7f]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }
}
