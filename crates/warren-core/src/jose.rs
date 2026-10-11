//! The small part of JOSE warren uses: base64url, P-256 JSON Web Keys
//! (RFC 7517, RFC 7518 section 6.2), their thumbprints (RFC 7638), and JWS
//! compact serialization with ES256 (RFC 7515).
//!
//! Policy bundles, posture statements and session requests are JWS objects
//! signed with ES256, so one verifier serves them all. Signatures come from
//! aws-lc-rs through [`crate::keys`].

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::keys::{PublicKey, SigningKey, sha256};

/// A JOSE object was malformed or did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoseError(pub String);

impl fmt::Display for JoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JoseError {}

fn err(msg: impl Into<String>) -> JoseError {
    JoseError(msg.into())
}

/// base64url without padding (RFC 7515 section 2).
pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url without padding. Padding, other alphabets and
/// non-canonical trailing bits are rejected.
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, JoseError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| err("invalid base64url"))
}

/// A P-256 public key as a JSON Web Key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: always `EC`.
    pub kty: String,
    /// Curve: always `P-256`.
    pub crv: String,
    /// The x coordinate, base64url.
    pub x: String,
    /// The y coordinate, base64url.
    pub y: String,
    /// Key ID, when the key is named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl Jwk {
    /// The JWK of a P-256 public key, with its thumbprint as key ID.
    pub fn from_key(key: &PublicKey) -> Jwk {
        let mut jwk = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: b64url(key.x()),
            y: b64url(key.y()),
            kid: None,
        };
        jwk.kid = Some(jwk.thumbprint());
        jwk
    }

    /// The public key, with the point checked to be on the curve.
    pub fn to_key(&self) -> Result<PublicKey, JoseError> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(err("only EC P-256 keys are accepted"));
        }
        PublicKey::from_coordinates(&b64url_decode(&self.x)?, &b64url_decode(&self.y)?)
            .map_err(|e| err(e.0))
    }

    /// The RFC 7638 thumbprint: base64url SHA-256 of the required members
    /// in lexicographic order.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            self.crv, self.kty, self.x, self.y
        );
        b64url(&sha256(canonical.as_bytes()))
    }
}

/// The protected header warren writes and accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Always `ES256`.
    pub alg: String,
    /// The object's type, which names what the payload is, so a signature
    /// over one kind of object can never be passed off as another.
    pub typ: String,
    /// The signing key's ID, when the verifier knows the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// The signing key itself, when the signature proves possession of a key
    /// the verifier does not know yet (a device key at sign-in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// Critical extensions. warren defines none, so any present member makes
    /// the object invalid (RFC 7515 section 4.1.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
}

/// Signs `payload` as a JWS compact serialization with ES256.
pub fn sign(header: &Header, payload: &[u8], key: &SigningKey) -> Result<String, JoseError> {
    if header.alg != "ES256" {
        return Err(err("only ES256 is supported"));
    }
    let header_json = serde_json::to_vec(header).map_err(|e| err(e.to_string()))?;
    let signing_input = format!("{}.{}", b64url(&header_json), b64url(payload));
    let signature = key
        .sign_fixed(signing_input.as_bytes())
        .map_err(|e| err(e.0))?;
    Ok(format!("{signing_input}.{}", b64url(&signature)))
}

/// A JWS whose structure has been checked but whose signature has not.
#[derive(Debug, Clone)]
pub struct Unverified {
    /// The protected header.
    pub header: Header,
    signing_input: String,
    signature: Vec<u8>,
    payload: Vec<u8>,
}

impl Unverified {
    /// Splits and decodes a compact JWS, and checks that it is ES256, has
    /// the expected `typ`, and uses no critical extensions.
    pub fn parse(jws: &str, typ: &str) -> Result<Unverified, JoseError> {
        let mut parts = jws.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(err("a compact JWS has exactly three parts"));
        };
        let header: Header =
            serde_json::from_slice(&b64url_decode(h)?).map_err(|_| err("malformed JWS header"))?;
        if header.alg != "ES256" {
            return Err(err("only ES256 is accepted"));
        }
        if header.typ != typ {
            return Err(err(format!("expected a {typ} object, got {}", header.typ)));
        }
        if header.crit.is_some() {
            return Err(err("critical JWS header extensions are not supported"));
        }
        Ok(Unverified {
            header,
            signing_input: format!("{h}.{p}"),
            signature: b64url_decode(s)?,
            payload: b64url_decode(p)?,
        })
    }

    /// Verifies the signature with `key` and returns the payload.
    pub fn verify(self, key: &PublicKey) -> Result<Vec<u8>, JoseError> {
        key.verify_fixed(self.signing_input.as_bytes(), &self.signature)
            .map_err(|_| err("JWS signature does not verify"))?;
        Ok(self.payload)
    }

    /// Verifies the signature with the key embedded in the header's `jwk`
    /// member and returns that key and the payload. Use only where the
    /// signature proves possession of a key the verifier binds afterwards.
    pub fn verify_embedded(self) -> Result<(PublicKey, Vec<u8>), JoseError> {
        let key = self
            .header
            .jwk
            .as_ref()
            .ok_or_else(|| err("the JWS header carries no jwk"))?
            .to_key()?;
        let payload = self.verify(&key)?;
        Ok((key, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(typ: &str) -> Header {
        Header {
            alg: "ES256".into(),
            typ: typ.into(),
            kid: None,
            jwk: None,
            crit: None,
        }
    }

    #[test]
    fn sign_and_verify() {
        let key = SigningKey::generate().unwrap();
        let jws = sign(&header("test+jws"), b"{\"a\":1}", &key).unwrap();
        let payload = Unverified::parse(&jws, "test+jws")
            .unwrap()
            .verify(key.public_key())
            .unwrap();
        assert_eq!(payload, b"{\"a\":1}");
    }

    #[test]
    fn wrong_key_type_or_tampering_fails() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let jws = sign(&header("a+jws"), b"payload", &key).unwrap();
        assert!(
            Unverified::parse(&jws, "a+jws")
                .unwrap()
                .verify(other.public_key())
                .is_err()
        );
        assert!(Unverified::parse(&jws, "b+jws").is_err());
        let mut parts: Vec<&str> = jws.split('.').collect();
        let forged = b64url(b"PAYLOAD");
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert!(
            Unverified::parse(&tampered, "a+jws")
                .unwrap()
                .verify(key.public_key())
                .is_err()
        );
        assert!(Unverified::parse(&format!("{jws}.x"), "a+jws").is_err());
    }

    #[test]
    fn other_algorithms_and_critical_headers_are_refused() {
        let none = format!(
            "{}.{}.",
            b64url(br#"{"alg":"none","typ":"a+jws"}"#),
            b64url(b"x")
        );
        assert!(Unverified::parse(&none, "a+jws").is_err());
        let crit = format!(
            "{}.{}.{}",
            b64url(br#"{"alg":"ES256","typ":"a+jws","crit":["exp"]}"#),
            b64url(b"x"),
            b64url(&[0; 64])
        );
        assert!(Unverified::parse(&crit, "a+jws").is_err());
    }

    #[test]
    fn embedded_key_proves_possession() {
        let key = SigningKey::generate().unwrap();
        let mut h = header("req+jws");
        h.jwk = Some(Jwk::from_key(key.public_key()));
        let jws = sign(&h, b"hi", &key).unwrap();
        let (found, payload) = Unverified::parse(&jws, "req+jws")
            .unwrap()
            .verify_embedded()
            .unwrap();
        assert_eq!(found, *key.public_key());
        assert_eq!(payload, b"hi");

        // A header naming one key but signed by another fails.
        let other = SigningKey::generate().unwrap();
        let jws = sign(&h, b"hi", &other).unwrap();
        assert!(
            Unverified::parse(&jws, "req+jws")
                .unwrap()
                .verify_embedded()
                .is_err()
        );
    }

    #[test]
    fn thumbprint_matches_rfc_7638_construction() {
        let key = SigningKey::generate().unwrap();
        let jwk = Jwk::from_key(key.public_key());
        assert_eq!(jwk.to_key().unwrap(), *key.public_key());
        let expected = b64url(&sha256(
            format!(
                "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                jwk.x, jwk.y
            )
            .as_bytes(),
        ));
        assert_eq!(jwk.thumbprint(), expected);
        assert_eq!(jwk.kid.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn base64url_is_strict() {
        assert_eq!(b64url_decode("AQID").unwrap(), vec![1, 2, 3]);
        assert!(b64url_decode("AQID=").is_err());
        assert!(b64url_decode("AQ+D").is_err());
        assert!(b64url_decode("AR").is_err());
    }
}
