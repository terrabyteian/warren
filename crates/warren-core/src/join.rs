//! Joining a deployment (docs/protocol.md section 10.3): the join token, a
//! key generated on the node that never leaves it, and the signed request
//! (PKCS#10, RFC 2986) the node exchanges for its first certificate.
//!
//! A token carries what a new node needs to reach the control plane
//! safely before it has a trust bundle: the control plane's address and
//! the SHA-256 of the deployment root CA certificate, which the node pins
//! for that one exchange. The control plane enforces the rest: tokens are
//! single-use, expire after `JOIN_TOKEN_LIFETIME`, and are scoped to one
//! role (and one connector group).

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair as _};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};

use crate::cert;
use crate::der::{self, Reader, tag};
use crate::identity::{NodeRole, valid_id, valid_trust_domain};
use crate::pki::oid;
use crate::{base64, params};

/// The prefix of an encoded join token.
pub const TOKEN_PREFIX: &str = "warren-join-v1.";

/// The control plane's join endpoint path.
pub const JOIN_PATH: &str = "/v1/join";

const ECDSA_WITH_SHA256: &[u128] = &[1, 2, 840, 10045, 4, 3, 2];

/// A join failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinError(pub String);

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "join: {}", self.0)
    }
}

impl std::error::Error for JoinError {}

fn err<T>(msg: impl Into<String>) -> Result<T, JoinError> {
    Err(JoinError(msg.into()))
}

/// A join token's contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinToken {
    /// Trust domain.
    pub td: String,
    /// The control plane's join endpoint, `host:port`.
    pub cp: String,
    /// `relay` or `connector`.
    pub role: String,
    /// The connector group, for connector tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// SHA-256 of the root CA certificate (DER), lowercase hex.
    pub root: String,
    /// Token identifier.
    pub id: String,
    /// The secret, base64url.
    pub secret: String,
    /// Expiry, Unix seconds.
    pub exp: u64,
}

impl JoinToken {
    /// Encodes the token for an operator to copy.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("token serializes");
        format!("{TOKEN_PREFIX}{}", base64::encode_url(&json))
    }

    /// Parses and checks a token: well formed, in scope, and not expired on
    /// this node's clock.
    pub fn parse(text: &str, now_unix: u64) -> Result<JoinToken, JoinError> {
        let Some(body) = text.trim().strip_prefix(TOKEN_PREFIX) else {
            return err("not a warren join token");
        };
        let json =
            base64::decode_url(body).ok_or_else(|| JoinError("token is not base64url".into()))?;
        let t: JoinToken = serde_json::from_slice(&json)
            .map_err(|e| JoinError(format!("malformed token: {e}")))?;
        if !valid_trust_domain(&t.td) || !valid_id(&t.id) {
            return err("token names an invalid trust domain or ID");
        }
        match (t.role.as_str(), &t.group) {
            ("relay", None) => {}
            ("connector", Some(g)) if valid_id(g) => {}
            _ => return err("token must be for a relay, or for a connector in one group"),
        }
        if t.root.len() != 64 || !t.root.bytes().all(|b| b.is_ascii_hexdigit()) {
            return err("token's root fingerprint is not a SHA-256");
        }
        if base64::decode_url(&t.secret).is_none_or(|s| s.len() < 16) {
            return err("token's secret is too short");
        }
        if t.exp <= now_unix {
            return err("token has expired");
        }
        if t.exp
            > now_unix
                + params::JOIN_TOKEN_LIFETIME.as_secs()
                + params::CLOCK_SKEW_ALLOWANCE.as_secs()
        {
            return err("token outlives the join token lifetime");
        }
        Ok(t)
    }

    /// The role the token joins as.
    pub fn node_role(&self) -> NodeRole {
        match &self.group {
            Some(group) => NodeRole::Connector {
                group: group.clone(),
            },
            None => NodeRole::Relay,
        }
    }
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A node's ECDSA P-256 key, generated where it is used.
pub struct NodeKey {
    pkcs8: Vec<u8>,
    pair: EcdsaKeyPair,
}

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeKey(P-256)")
    }
}

impl NodeKey {
    /// Generates a key.
    pub fn generate() -> Result<NodeKey, JoinError> {
        let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)
            .map_err(|_| JoinError("key generation failed".into()))?
            .as_ref()
            .to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(alg, &pkcs8)
            .map_err(|_| JoinError("key parse failed".into()))?;
        Ok(NodeKey { pkcs8, pair })
    }

    /// The SubjectPublicKeyInfo, DER.
    pub fn spki(&self) -> Vec<u8> {
        cert::p256_spki(self.pair.public_key().as_ref())
    }

    /// A certificate request signed by this key, with an empty subject: the
    /// control plane assigns the node's identity from the token.
    pub fn certificate_request(&self) -> Result<Vec<u8>, JoinError> {
        certificate_request(&self.spki(), |info| {
            self.pair
                .sign(&SystemRandom::new(), info)
                .map(|sig| sig.as_ref().to_vec())
                .map_err(|_| JoinError("signing failed".into()))
        })
    }

    /// The private key.
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()))
    }

    /// The private key as PEM.
    pub fn private_key_pem(&self) -> String {
        base64::pem("PRIVATE KEY", &self.pkcs8)
    }
}

/// A certificate request (PKCS#10, RFC 2986) for the key in `spki`, with an
/// empty subject and no attributes. `sign` returns that key's ECDSA P-256
/// SHA-256 signature over the request info, DER, so a key held in hardware
/// signs without leaving its store.
pub fn certificate_request<E>(
    spki: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, E> {
    let info = der::sequence(&[
        &der::uint(tag::INTEGER, 0),
        &der::sequence(&[]),
        spki,
        &der::tlv(tag::context(0), &[]),
    ]);
    let mut bits = vec![0u8];
    bits.extend_from_slice(&sign(&info)?);
    Ok(der::sequence(&[
        &info,
        &der::sequence(&[&der::oid(ECDSA_WITH_SHA256)]),
        &der::tlv(tag::BIT_STRING, &bits),
    ]))
}

/// Checks a certificate request's self-signature and returns its
/// SubjectPublicKeyInfo (the issuer's side of the exchange).
pub fn verify_certificate_request(csr: &[u8]) -> Result<Vec<u8>, JoinError> {
    let bad = |e: der::DerError| JoinError(format!("certificate request: {e}"));
    let mut outer = Reader::new(csr);
    let mut req = Reader::new(outer.read(tag::SEQUENCE).map_err(bad)?);
    outer.finish().map_err(bad)?;
    let (info_full, info) = req.read_element(tag::SEQUENCE).map_err(bad)?;
    let mut alg = Reader::new(req.read(tag::SEQUENCE).map_err(bad)?);
    if alg.read(tag::OID).map_err(bad)? != der::oid_value(ECDSA_WITH_SHA256) {
        return err("certificate requests must be signed with ECDSA P-256 SHA-256");
    }
    let sig = req.read(tag::BIT_STRING).map_err(bad)?;
    let mut info_r = Reader::new(info);
    if info_r.read_u64(tag::INTEGER).map_err(bad)? != 0 {
        return err("unsupported certificate request version");
    }
    info_r.read(tag::SEQUENCE).map_err(bad)?;
    let (spki_full, spki) = info_r.read_element(tag::SEQUENCE).map_err(bad)?;
    let mut spki_r = Reader::new(spki);
    let mut key_alg = Reader::new(spki_r.read(tag::SEQUENCE).map_err(bad)?);
    if key_alg.read(tag::OID).map_err(bad)? != oid::EC_PUBLIC_KEY
        || key_alg.read(tag::OID).map_err(bad)? != oid::P256
    {
        return err("node keys must be ECDSA P-256");
    }
    let point = spki_r.read(tag::BIT_STRING).map_err(bad)?;
    let (point, sig) = (
        point.get(1..).unwrap_or_default(),
        sig.get(1..).unwrap_or_default(),
    );
    aws_lc_rs::signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
        .verify(info_full, sig)
        .map_err(|_| JoinError("certificate request signature does not verify".into()))?;
    Ok(spki_full.to_vec())
}

/// The join request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinRequest {
    /// The join token.
    pub token: String,
    /// The certificate request, base64 DER.
    pub csr: String,
}

/// The trust bundle in the join response, base64 DER certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleJson {
    /// Root CA.
    pub root: String,
    /// Client CAs.
    pub client_cas: Vec<String>,
    /// Infrastructure CAs.
    pub infra_cas: Vec<String>,
}

/// The join response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinResponse {
    /// The node's certificate chain, leaf first, base64 DER.
    pub chain: Vec<String>,
    /// The deployment trust bundle.
    pub trust_bundle: BundleJson,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(exp: u64) -> JoinToken {
        JoinToken {
            td: "lab.test".into(),
            cp: "cp.lab.test:443".into(),
            role: "connector".into(),
            group: Some("homelab".into()),
            root: "ab".repeat(32),
            id: "t1".into(),
            secret: base64::encode_url(&[7u8; 32]),
            exp,
        }
    }

    #[test]
    fn tokens_round_trip_and_are_checked() {
        let now = 1_000_000;
        let t = token(now + 600);
        assert_eq!(JoinToken::parse(&t.encode(), now).unwrap(), t);
        assert_eq!(
            t.node_role(),
            NodeRole::Connector {
                group: "homelab".into()
            }
        );
        assert!(
            JoinToken::parse(&token(now - 1).encode(), now).is_err(),
            "expired"
        );
        assert!(
            JoinToken::parse(&token(now + 86_400).encode(), now).is_err(),
            "too long-lived"
        );
        let mut relay_with_group = token(now + 600);
        relay_with_group.role = "relay".into();
        assert!(JoinToken::parse(&relay_with_group.encode(), now).is_err());
        let mut weak = token(now + 600);
        weak.secret = "AAAA".into();
        assert!(JoinToken::parse(&weak.encode(), now).is_err());
        assert!(JoinToken::parse("not-a-token", now).is_err());
    }

    #[test]
    fn certificate_requests_are_signed_by_the_node_key() {
        let key = NodeKey::generate().unwrap();
        let csr = key.certificate_request().unwrap();
        assert_eq!(verify_certificate_request(&csr).unwrap(), key.spki());
        let mut tampered = csr.clone();
        let n = tampered.len();
        tampered[n / 2] ^= 1;
        assert!(verify_certificate_request(&tampered).is_err());
    }
}
