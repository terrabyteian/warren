//! Building certificates in the profiles of docs/protocol.md section 10,
//! with the DER writer in [`crate::der`]. The issuer's signature comes from
//! the caller, so a key can sign wherever it lives (in memory, a KMS, a
//! hardware token). The control plane issues with this; tests use it to
//! mint certificates that break the profile on purpose, which is why it
//! checks nothing itself: issuers decide what they sign.

use crate::clock;
use crate::der::{self, Reader, tag};
use crate::pki::oid;

const ECDSA_WITH_SHA256: &[u128] = &[1, 2, 840, 10045, 4, 3, 2];
const COMMON_NAME: &[u128] = &[2, 5, 4, 3];

/// Everything that goes into a certificate.
#[derive(Debug, Clone)]
pub struct CertSpec {
    /// Serial number content octets: a positive INTEGER, minimally encoded.
    pub serial: Vec<u8>,
    /// Subject common name; `None` for an empty subject.
    pub subject_cn: Option<String>,
    /// notBefore, Unix seconds.
    pub not_before: i64,
    /// notAfter, Unix seconds.
    pub not_after: i64,
    /// basicConstraints: `None` to omit, `Some(ca)` otherwise.
    pub ca: Option<bool>,
    /// basicConstraints pathLenConstraint, for CAs.
    pub path_len: Option<u8>,
    /// keyUsage first octet and criticality.
    pub key_usage: Option<(u8, bool)>,
    /// extKeyUsage OIDs (content octets); empty to omit.
    pub eku: Vec<Vec<u8>>,
    /// SAN URIs.
    pub san_uris: Vec<String>,
    /// SAN DNS names.
    pub san_dns: Vec<String>,
    /// SAN criticality.
    pub san_critical: bool,
    /// Whether to include subject and authority key identifiers.
    pub key_ids: bool,
    /// Further extensions: OID content octets, criticality, value.
    pub extra: Vec<(Vec<u8>, bool, Vec<u8>)>,
}

/// A random serial number: 16 bytes from the CSPRNG, positive, with at
/// least 120 random bits.
pub fn random_serial() -> Vec<u8> {
    let mut s = [0u8; 16];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut s)
        .expect("CSPRNG");
    s[0] = (s[0] & 0x7f) | 0x40;
    s.to_vec()
}

impl CertSpec {
    /// A CA certificate valid for ten years from an hour ago.
    pub fn ca(cn: &str) -> CertSpec {
        let now = clock::now_secs();
        CertSpec {
            serial: random_serial(),
            subject_cn: Some(cn.into()),
            not_before: now - 3600,
            not_after: now + 10 * 365 * 86_400,
            ca: Some(true),
            path_len: None,
            key_usage: Some((0x06, true)),
            eku: Vec::new(),
            san_uris: Vec::new(),
            san_dns: Vec::new(),
            san_critical: false,
            key_ids: true,
            extra: Vec::new(),
        }
    }

    /// A leaf with the given lifetime starting now (backdated a minute):
    /// empty subject, critical digitalSignature, CA:FALSE.
    pub fn leaf(lifetime_secs: i64) -> CertSpec {
        let now = clock::now_secs();
        CertSpec {
            serial: random_serial(),
            subject_cn: None,
            not_before: now - 60,
            not_after: now - 60 + lifetime_secs,
            ca: Some(false),
            path_len: None,
            key_usage: Some((0x80, true)),
            eku: Vec::new(),
            san_uris: Vec::new(),
            san_dns: Vec::new(),
            san_critical: true,
            key_ids: true,
            extra: Vec::new(),
        }
    }
}

/// A Name: a single common name, or the empty sequence.
pub fn name(cn: Option<&str>) -> Vec<u8> {
    match cn {
        None => der::sequence(&[]),
        Some(cn) => {
            let atv = der::sequence(&[
                &der::oid(COMMON_NAME),
                &der::tlv(tag::UTF8_STRING, cn.as_bytes()),
            ]);
            der::sequence(&[&der::tlv(tag::SET, &atv)])
        }
    }
}

fn extension(oid_value: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![der::tlv(tag::OID, oid_value)];
    if critical {
        parts.push(der::boolean(true));
    }
    parts.push(der::tlv(tag::OCTET_STRING, value));
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    der::sequence(&refs)
}

/// The SubjectPublicKeyInfo of a P-256 key, DER, from its uncompressed
/// point.
pub fn p256_spki(point: &[u8]) -> Vec<u8> {
    let alg = der::sequence(&[
        &der::tlv(tag::OID, oid::EC_PUBLIC_KEY),
        &der::tlv(tag::OID, oid::P256),
    ]);
    let mut bits = vec![0u8];
    bits.extend_from_slice(point);
    der::sequence(&[&alg, &der::tlv(tag::BIT_STRING, &bits)])
}

/// The public key bits of a SubjectPublicKeyInfo (for EC keys, the point).
pub fn spki_key_bits(spki: &[u8]) -> Result<&[u8], der::DerError> {
    let mut outer = Reader::new(spki);
    let mut seq = Reader::new(outer.read(tag::SEQUENCE)?);
    outer.finish()?;
    seq.read(tag::SEQUENCE)?;
    let bits = seq.read(tag::BIT_STRING)?;
    seq.finish()?;
    match bits {
        [0, key @ ..] if !key.is_empty() => Ok(key),
        _ => Err(der::DerError("public key BIT STRING with unused bits")),
    }
}

/// The key identifier of a SubjectPublicKeyInfo: the leftmost 160 bits of
/// the SHA-256 of its public key bits (RFC 7093 section 2, method 1).
pub fn spki_key_id(spki: &[u8]) -> Result<Vec<u8>, der::DerError> {
    let bits = spki_key_bits(spki)?;
    Ok(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bits).as_ref()[..20].to_vec())
}

/// Builds and signs a certificate for `subject_spki`. The issuer is named
/// by `issuer_name` (a whole Name element) and `issuer_key_id`; `sign`
/// returns the issuer's ECDSA P-256 SHA-256 signature over the
/// TBSCertificate, DER. For a self-signed certificate, pass the subject's
/// own name and key identifier.
pub fn issue<E>(
    spec: &CertSpec,
    subject_spki: &[u8],
    issuer_name: &[u8],
    issuer_key_id: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, E> {
    let subject = name(spec.subject_cn.as_deref());
    let mut exts = Vec::new();
    if let Some(ca) = spec.ca {
        let bc = match (ca, spec.path_len) {
            (false, _) => der::sequence(&[]),
            (true, None) => der::sequence(&[&der::boolean(true)]),
            (true, Some(n)) => {
                der::sequence(&[&der::boolean(true), &der::uint(tag::INTEGER, u64::from(n))])
            }
        };
        exts.push(extension(oid::BASIC_CONSTRAINTS, true, &bc));
    }
    if let Some((bits, critical)) = spec.key_usage {
        let unused = bits.trailing_zeros().min(7) as u8;
        exts.push(extension(
            oid::KEY_USAGE,
            critical,
            &der::tlv(tag::BIT_STRING, &[unused, bits]),
        ));
    }
    if !spec.eku.is_empty() {
        let oids: Vec<Vec<u8>> = spec.eku.iter().map(|o| der::tlv(tag::OID, o)).collect();
        let refs: Vec<&[u8]> = oids.iter().map(Vec::as_slice).collect();
        exts.push(extension(oid::EXT_KEY_USAGE, false, &der::sequence(&refs)));
    }
    if !spec.san_uris.is_empty() || !spec.san_dns.is_empty() {
        let mut names: Vec<Vec<u8>> = spec
            .san_uris
            .iter()
            .map(|u| der::tlv(tag::context_primitive(6), u.as_bytes()))
            .collect();
        names.extend(
            spec.san_dns
                .iter()
                .map(|d| der::tlv(tag::context_primitive(2), d.as_bytes())),
        );
        let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
        exts.push(extension(
            oid::SAN,
            spec.san_critical,
            &der::sequence(&refs),
        ));
    }
    if spec.key_ids {
        let ski = spki_key_id(subject_spki).unwrap_or_default();
        exts.push(extension(
            oid::SKI,
            false,
            &der::tlv(tag::OCTET_STRING, &ski),
        ));
        let aki = der::sequence(&[&der::tlv(tag::context_primitive(0), issuer_key_id)]);
        exts.push(extension(oid::AKI, false, &aki));
    }
    for (o, critical, value) in &spec.extra {
        exts.push(extension(o, *critical, value));
    }
    let ext_refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    let sig_alg = der::sequence(&[&der::oid(ECDSA_WITH_SHA256)]);
    let version = der::tlv(tag::context(0), &der::uint(tag::INTEGER, 2));
    let validity = der::sequence(&[
        &clock::der_time(spec.not_before),
        &clock::der_time(spec.not_after),
    ]);
    let extensions = der::tlv(tag::context(3), &der::sequence(&ext_refs));
    let tbs = der::sequence(&[
        &version,
        &der::tlv(tag::INTEGER, &spec.serial),
        &sig_alg,
        issuer_name,
        &validity,
        &subject,
        subject_spki,
        &extensions,
    ]);
    let mut sig = vec![0u8];
    sig.extend_from_slice(&sign(&tbs)?);
    Ok(der::sequence(&[
        &tbs,
        &sig_alg,
        &der::tlv(tag::BIT_STRING, &sig),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use crate::pki;

    #[test]
    fn issued_certificates_parse_with_their_fields() {
        let ca_key = SigningKey::generate().unwrap();
        let ca_spki = p256_spki(ca_key.public_key().point());
        let mut ca_spec = CertSpec::ca("test CA");
        ca_spec.path_len = Some(0);
        let ca_name = name(Some("test CA"));
        let ca_id = spki_key_id(&ca_spki).unwrap();
        let ca = issue(&ca_spec, &ca_spki, &ca_name, &ca_id, |tbs| {
            ca_key.sign_der(tbs)
        })
        .unwrap();
        let parsed = pki::parse_cert(&ca).unwrap();
        assert_eq!(parsed.spki, ca_spki);
        assert_eq!(der::tlv(tag::SEQUENCE, parsed.subject), ca_name);

        let leaf_key = SigningKey::generate().unwrap();
        let leaf_spki = p256_spki(leaf_key.public_key().point());
        let mut spec = CertSpec::leaf(3600);
        spec.san_uris = vec!["warren://example.test/relay/r-1".into()];
        spec.san_dns = vec!["relay.example.test".into()];
        let leaf = issue(&spec, &leaf_spki, &ca_name, &ca_id, |tbs| {
            ca_key.sign_der(tbs)
        })
        .unwrap();
        let parsed = pki::parse_cert(&leaf).unwrap();
        assert_eq!(parsed.serial, spec.serial);
        assert_eq!(
            (parsed.not_before, parsed.not_after),
            (spec.not_before, spec.not_after)
        );
        let names = parsed.subject_alt_names().unwrap();
        assert_eq!(names.uris, spec.san_uris);
        assert_eq!(names.dns, spec.san_dns);
        assert!(names.critical);
        assert_eq!(
            spki_key_bits(&leaf_spki).unwrap(),
            leaf_key.public_key().point()
        );
    }
}
