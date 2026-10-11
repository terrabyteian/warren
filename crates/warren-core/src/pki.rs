//! The deployment trust bundle, chain verification, and the certificate
//! profiles of docs/protocol.md section 10.
//!
//! Chains are verified with webpki against the deployment root, using only
//! the bundle's own issuing CAs as intermediates, so a certificate from one
//! issuing CA is never accepted where the other is required. Profile checks
//! then parse the verified leaf.

use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, UnixTime};

use crate::der::{self, Reader, tag};
use crate::identity::{self, NodeRole, WarrenIdentity, WarrenUri};
use crate::params;

/// A certificate failed verification or its profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    /// The chain does not verify to the deployment root through the right
    /// issuing CA, or is outside its validity window.
    Chain(String),
    /// The certificate verifies but violates the warren profile.
    Profile(String),
    /// The certificate, its user, device, session or node is revoked or
    /// disabled.
    Revoked(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Chain(e) => write!(f, "certificate chain: {e}"),
            CertError::Profile(e) => write!(f, "certificate profile: {e}"),
            CertError::Revoked(e) => write!(f, "revoked: {e}"),
        }
    }
}

impl std::error::Error for CertError {}

fn profile<T>(msg: impl Into<String>) -> Result<T, CertError> {
    Err(CertError::Profile(msg.into()))
}

/// Which issuing CA a certificate must chain through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issuer {
    /// The client CA (user+device certificates).
    Client,
    /// The infrastructure CA (control plane, relays, connectors).
    Infrastructure,
}

/// The deployment trust bundle: the root and both issuing CAs.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    /// The trust domain `{td}` in warren URIs.
    pub trust_domain: String,
    /// Root CA certificate.
    pub root: CertificateDer<'static>,
    /// Client CA certificates (more than one during rotation).
    pub client_cas: Vec<CertificateDer<'static>>,
    /// Infrastructure CA certificates.
    pub infra_cas: Vec<CertificateDer<'static>>,
}

/// File names inside a trust bundle directory.
pub const ROOT_CA_FILE: &str = "root-ca.pem";
/// Client CA file name.
pub const CLIENT_CA_FILE: &str = "client-ca.pem";
/// Infrastructure CA file name.
pub const INFRA_CA_FILE: &str = "infra-ca.pem";

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, CertError> {
    CertificateDer::pem_file_iter(path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| CertError::Chain(format!("{}: {e}", path.display())))
}

/// Loads a PEM certificate chain, leaf first.
pub fn load_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, CertError> {
    let chain = read_certs(path)?;
    if chain.is_empty() {
        return Err(CertError::Chain(format!(
            "{}: no certificates",
            path.display()
        )));
    }
    Ok(chain)
}

impl TrustBundle {
    /// Loads a bundle from a directory holding `root-ca.pem`,
    /// `client-ca.pem` and `infra-ca.pem`.
    pub fn load_dir(trust_domain: &str, dir: &Path) -> Result<TrustBundle, CertError> {
        let mut root = read_certs(&dir.join(ROOT_CA_FILE))?;
        if root.len() != 1 {
            return Err(CertError::Chain(format!(
                "{ROOT_CA_FILE} must hold exactly one certificate"
            )));
        }
        TrustBundle::new(
            trust_domain,
            root.remove(0),
            read_certs(&dir.join(CLIENT_CA_FILE))?,
            read_certs(&dir.join(INFRA_CA_FILE))?,
        )
    }

    /// Builds a bundle and checks it: a valid trust domain, at least one CA
    /// of each kind, and the two kinds disjoint.
    pub fn new(
        trust_domain: &str,
        root: CertificateDer<'static>,
        client_cas: Vec<CertificateDer<'static>>,
        infra_cas: Vec<CertificateDer<'static>>,
    ) -> Result<TrustBundle, CertError> {
        if !identity::valid_trust_domain(trust_domain) {
            return Err(CertError::Chain(format!(
                "invalid trust domain {trust_domain:?}"
            )));
        }
        if client_cas.is_empty() || infra_cas.is_empty() {
            return Err(CertError::Chain(
                "the bundle needs a client CA and an infrastructure CA".into(),
            ));
        }
        if client_cas.iter().any(|c| infra_cas.contains(c))
            || client_cas.contains(&root)
            || infra_cas.contains(&root)
        {
            return Err(CertError::Chain(
                "issuing CAs must be distinct from each other and the root".into(),
            ));
        }
        Ok(TrustBundle {
            trust_domain: trust_domain.to_owned(),
            root,
            client_cas,
            infra_cas,
        })
    }

    /// Verifies `leaf` to the root through exactly one CA of `issuer`'s
    /// kind, for TLS client or server use. Peer-supplied intermediates are
    /// ignored; only the bundle's CAs can complete a path.
    pub fn verify_chain(
        &self,
        leaf: &CertificateDer<'_>,
        issuer: Issuer,
        server_use: bool,
        now: UnixTime,
    ) -> Result<(), CertError> {
        let anchor = webpki::anchor_from_trusted_cert(&self.root)
            .map_err(|e| CertError::Chain(format!("root: {e}")))?;
        let intermediates = match issuer {
            Issuer::Client => &self.client_cas,
            Issuer::Infrastructure => &self.infra_cas,
        };
        let ee =
            webpki::EndEntityCert::try_from(leaf).map_err(|e| CertError::Chain(e.to_string()))?;
        let algs = rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .all;
        let usage = if server_use {
            webpki::KeyUsage::server_auth()
        } else {
            webpki::KeyUsage::client_auth()
        };
        let anchors = [anchor];
        let path = ee
            .verify_for_usage(algs, &anchors, intermediates, now, usage, None, None)
            .map_err(|e| CertError::Chain(e.to_string()))?;
        if path.intermediate_certificates().count() != 1 {
            return Err(CertError::Chain(
                "the chain must pass through exactly one issuing CA".into(),
            ));
        }
        Ok(())
    }
}

/// An X.509 extension.
#[derive(Debug, Clone, Copy)]
pub struct Extension<'a> {
    /// OID content octets.
    pub oid: &'a [u8],
    /// Critical flag.
    pub critical: bool,
    /// The extnValue content.
    pub value: &'a [u8],
}

/// The fields of a certificate warren's profiles look at.
#[derive(Debug, Clone)]
pub struct ParsedCert<'a> {
    /// X.509 version number (2 means v3).
    pub version: u64,
    /// Serial number content octets.
    pub serial: &'a [u8],
    /// Subject Name content (empty for an empty subject).
    pub subject: &'a [u8],
    /// notBefore, Unix seconds.
    pub not_before: i64,
    /// notAfter, Unix seconds.
    pub not_after: i64,
    /// The full SubjectPublicKeyInfo element, DER.
    pub spki: &'a [u8],
    /// Public key algorithm OID.
    pub key_algorithm: &'a [u8],
    /// Named curve OID for EC keys.
    pub key_curve: Option<&'a [u8]>,
    /// Extensions.
    pub extensions: Vec<Extension<'a>>,
}

/// OIDs (content octets).
pub mod oid {
    /// subjectAltName.
    pub const SAN: &[u8] = &[0x55, 0x1d, 0x11];
    /// keyUsage.
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// extKeyUsage.
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// basicConstraints.
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// authorityKeyIdentifier.
    pub const AKI: &[u8] = &[0x55, 0x1d, 0x23];
    /// subjectKeyIdentifier.
    pub const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
    /// cRLDistributionPoints.
    pub const CRL_DP: &[u8] = &[0x55, 0x1d, 0x1f];
    /// authorityInfoAccess.
    pub const AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
    /// id-kp-serverAuth.
    pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// id-kp-clientAuth.
    pub const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    /// id-ecPublicKey.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1 (P-256).
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// id-Ed25519.
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
}

/// Parses the fields of a DER certificate.
pub fn parse_cert(der_bytes: &[u8]) -> Result<ParsedCert<'_>, CertError> {
    let bad = |e: der::DerError| CertError::Profile(format!("unparseable certificate: {e}"));
    let mut outer = Reader::new(der_bytes);
    let mut cert = Reader::new(outer.read(tag::SEQUENCE).map_err(bad)?);
    let mut tbs = Reader::new(cert.read(tag::SEQUENCE).map_err(bad)?);
    let version = match tbs.read_optional(tag::context(0)).map_err(bad)? {
        Some(v) => Reader::new(v).read_u64(tag::INTEGER).map_err(bad)?,
        None => 0,
    };
    let serial = tbs.read(tag::INTEGER).map_err(bad)?;
    tbs.read(tag::SEQUENCE).map_err(bad)?; // signature algorithm
    tbs.read(tag::SEQUENCE).map_err(bad)?; // issuer
    let mut validity = Reader::new(tbs.read(tag::SEQUENCE).map_err(bad)?);
    let (t1, v1) = validity.read_any().map_err(bad)?;
    let (t2, v2) = validity.read_any().map_err(bad)?;
    let not_before = der::parse_time(t1, v1).map_err(bad)?;
    let not_after = der::parse_time(t2, v2).map_err(bad)?;
    let subject = tbs.read(tag::SEQUENCE).map_err(bad)?;
    let (spki, spki_value) = tbs.read_element(tag::SEQUENCE).map_err(bad)?;
    let mut spki_r = Reader::new(spki_value);
    let mut alg = Reader::new(spki_r.read(tag::SEQUENCE).map_err(bad)?);
    let key_algorithm = alg.read(tag::OID).map_err(bad)?;
    let key_curve = alg.read_optional(tag::OID).map_err(bad)?;
    tbs.read_optional(tag::context_primitive(1)).map_err(bad)?;
    tbs.read_optional(tag::context_primitive(2)).map_err(bad)?;
    let mut extensions = Vec::new();
    if let Some(exts) = tbs.read_optional(tag::context(3)).map_err(bad)? {
        let mut seq = Reader::new(exts);
        let mut list = Reader::new(seq.read(tag::SEQUENCE).map_err(bad)?);
        while !list.is_empty() {
            let mut e = Reader::new(list.read(tag::SEQUENCE).map_err(bad)?);
            let oid = e.read(tag::OID).map_err(bad)?;
            let critical = if e.peek_tag() == Some(tag::BOOLEAN) {
                e.read_bool().map_err(bad)?
            } else {
                false
            };
            let value = e.read(tag::OCTET_STRING).map_err(bad)?;
            if extensions.iter().any(|x: &Extension<'_>| x.oid == oid) {
                return profile("duplicate extension");
            }
            extensions.push(Extension {
                oid,
                critical,
                value,
            });
        }
    }
    Ok(ParsedCert {
        version,
        serial,
        subject,
        not_before,
        not_after,
        spki,
        key_algorithm,
        key_curve,
        extensions,
    })
}

impl ParsedCert<'_> {
    /// An extension by OID.
    pub fn extension(&self, oid: &[u8]) -> Option<&Extension<'_>> {
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// URIs and DNS names in the SAN, and whether it was critical.
    pub fn subject_alt_names(
        &self,
    ) -> Result<(Vec<String>, Vec<String>, Vec<IpAddr>, bool), CertError> {
        let Some(ext) = self.extension(oid::SAN) else {
            return profile("missing subjectAltName");
        };
        let bad = |e: der::DerError| CertError::Profile(format!("subjectAltName: {e}"));
        let mut outer = Reader::new(ext.value);
        let mut names = Reader::new(outer.read(tag::SEQUENCE).map_err(bad)?);
        let (mut uris, mut dns, mut ips) = (Vec::new(), Vec::new(), Vec::new());
        while !names.is_empty() {
            let (t, v) = names.read_any().map_err(bad)?;
            let text = || {
                std::str::from_utf8(v)
                    .map(str::to_owned)
                    .map_err(|_| CertError::Profile("non-ASCII name".into()))
            };
            match t {
                t if t == tag::context_primitive(6) => uris.push(text()?),
                t if t == tag::context_primitive(2) => dns.push(text()?),
                t if t == tag::context_primitive(7) => match v.len() {
                    4 => ips.push(IpAddr::from(
                        <[u8; 4]>::try_from(v).expect("length checked"),
                    )),
                    16 => ips.push(IpAddr::from(
                        <[u8; 16]>::try_from(v).expect("length checked"),
                    )),
                    _ => return profile("invalid IP address SAN"),
                },
                _ => return profile("unsupported subjectAltName type"),
            }
        }
        Ok((uris, dns, ips, ext.critical))
    }

    /// The extended key usage OIDs.
    pub fn extended_key_usages(&self) -> Result<Vec<&[u8]>, CertError> {
        let Some(ext) = self.extension(oid::EXT_KEY_USAGE) else {
            return Ok(Vec::new());
        };
        let bad = |e: der::DerError| CertError::Profile(format!("extKeyUsage: {e}"));
        let mut outer = Reader::new(ext.value);
        let mut seq = Reader::new(outer.read(tag::SEQUENCE).map_err(bad)?);
        let mut out = Vec::new();
        while !seq.is_empty() {
            out.push(seq.read(tag::OID).map_err(bad)?);
        }
        Ok(out)
    }

    /// The first octet of the keyUsage bits and whether it was critical.
    fn key_usage(&self) -> Result<Option<(u8, bool)>, CertError> {
        let Some(ext) = self.extension(oid::KEY_USAGE) else {
            return Ok(None);
        };
        let mut r = Reader::new(ext.value);
        let bits = r
            .read(tag::BIT_STRING)
            .map_err(|e| CertError::Profile(format!("keyUsage: {e}")))?;
        let first = bits.get(1).copied().unwrap_or(0);
        // Any bits beyond the first octet (encipherOnly, decipherOnly) count.
        let extra = bits.iter().skip(2).any(|b| *b != 0);
        Ok(Some((if extra { 0xff } else { first }, ext.critical)))
    }

    /// Whether basicConstraints says CA:TRUE.
    fn is_ca(&self) -> Result<Option<bool>, CertError> {
        let Some(ext) = self.extension(oid::BASIC_CONSTRAINTS) else {
            return Ok(None);
        };
        let bad = |e: der::DerError| CertError::Profile(format!("basicConstraints: {e}"));
        let mut outer = Reader::new(ext.value);
        let mut seq = Reader::new(outer.read(tag::SEQUENCE).map_err(bad)?);
        if seq.peek_tag() == Some(tag::BOOLEAN) {
            return seq.read_bool().map(Some).map_err(bad);
        }
        Ok(Some(false))
    }

    /// notAfter as a system time.
    pub fn not_after_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.not_after.max(0) as u64)
    }
}

/// A verified user+device identity, from a client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Trust domain.
    pub trust_domain: String,
    /// User ID.
    pub user: String,
    /// Device ID.
    pub device: String,
    /// Certificate serial number, hex.
    pub serial: String,
    /// notAfter.
    pub not_after: SystemTime,
    /// The warren identity extension.
    pub identity: WarrenIdentity,
    /// The SubjectPublicKeyInfo, DER: the device key.
    pub spki: Vec<u8>,
}

/// A verified infrastructure identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// Trust domain.
    pub trust_domain: String,
    /// Role.
    pub role: NodeRole,
    /// Node ID.
    pub id: String,
    /// Certificate serial number, hex.
    pub serial: String,
    /// notAfter.
    pub not_after: SystemTime,
    /// DNS names the node listens on.
    pub dns_names: Vec<String>,
}

/// Either kind of verified peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentity {
    /// A user on a device.
    Client(ClientIdentity),
    /// A relay, connector or control plane.
    Node(NodeIdentity),
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Checks a verified leaf against the user+device certificate profile
/// (docs/protocol.md section 10.2).
pub fn check_client_profile(leaf: &[u8], trust_domain: &str) -> Result<ClientIdentity, CertError> {
    let c = parse_cert(leaf)?;
    if c.version != 2 {
        return profile("not an X.509 v3 certificate");
    }
    let serial = c.serial.strip_prefix(&[0]).unwrap_or(c.serial);
    if serial.len() < 8 {
        return profile("serial number shorter than 64 bits");
    }
    if !c.subject.is_empty() {
        return profile("subject must be empty");
    }
    if c.key_algorithm != oid::EC_PUBLIC_KEY || c.key_curve != Some(oid::P256) {
        return profile("device key must be ECDSA P-256");
    }
    let lifetime = c.not_after - c.not_before;
    let max = (params::CLIENT_CERT_LIFETIME + params::CLOCK_SKEW_ALLOWANCE).as_secs() as i64;
    if lifetime <= 0 || lifetime > max {
        return profile("validity exceeds the 4-hour lifetime plus clock skew");
    }
    let (uris, dns, ips, critical) = c.subject_alt_names()?;
    if !critical {
        return profile("subjectAltName must be critical");
    }
    if !dns.is_empty() || !ips.is_empty() || uris.len() != 2 {
        return profile("subjectAltName must hold exactly one user and one device URI");
    }
    let (mut user, mut device) = (None, None);
    for u in &uris {
        match WarrenUri::parse(u) {
            Some(WarrenUri::User { td, id }) if td == trust_domain && user.is_none() => {
                user = Some(id)
            }
            Some(WarrenUri::Device { td, id }) if td == trust_domain && device.is_none() => {
                device = Some(id)
            }
            _ => return profile(format!("unexpected SAN URI {u}")),
        }
    }
    let (Some(user), Some(device)) = (user, device) else {
        return profile("subjectAltName must hold a user and a device URI");
    };
    match c.key_usage()? {
        Some((bits, true)) if bits & 0x80 != 0 && bits & 0x06 == 0 && bits != 0xff => {}
        _ => return profile("keyUsage must be critical digitalSignature"),
    }
    if c.extended_key_usages()? != [oid::CLIENT_AUTH] {
        return profile("extKeyUsage must be clientAuth only");
    }
    if c.is_ca()? != Some(false) {
        return profile("basicConstraints must be present with CA:FALSE");
    }
    if c.extension(oid::AKI).is_none() || c.extension(oid::SKI).is_none() {
        return profile("authority and subject key identifiers are required");
    }
    if c.extension(oid::CRL_DP).is_some() || c.extension(oid::AIA).is_some() {
        return profile("revocation pointers are not allowed; revocation is pushed");
    }
    let id_oid = identity::identity_extension_oid();
    let Some(ext) = c.extension(&id_oid) else {
        return profile("missing warren identity extension");
    };
    if ext.critical {
        return profile("the warren identity extension must be non-critical");
    }
    let identity = WarrenIdentity::from_der(ext.value)
        .map_err(|e| CertError::Profile(format!("identity extension: {e}")))?;
    Ok(ClientIdentity {
        trust_domain: trust_domain.to_owned(),
        user,
        device,
        serial: hex(serial),
        not_after: c.not_after_time(),
        identity,
        spki: c.spki.to_vec(),
    })
}

/// Checks a verified leaf against the infrastructure profile
/// (docs/protocol.md section 10.3).
pub fn check_infra_profile(leaf: &[u8], trust_domain: &str) -> Result<NodeIdentity, CertError> {
    let c = parse_cert(leaf)?;
    if c.version != 2 {
        return profile("not an X.509 v3 certificate");
    }
    let key_ok = (c.key_algorithm == oid::EC_PUBLIC_KEY && c.key_curve == Some(oid::P256))
        || (c.key_algorithm == oid::ED25519 && c.key_curve.is_none());
    if !key_ok {
        return profile("infrastructure keys must be ECDSA P-256 or Ed25519");
    }
    if c.is_ca()? == Some(true) {
        return profile("a CA certificate cannot identify a node");
    }
    let (uris, dns, _ips, _) = c.subject_alt_names()?;
    let mut node = None;
    for u in &uris {
        match WarrenUri::parse(u) {
            Some(WarrenUri::Node { td, role, id }) if td == trust_domain && node.is_none() => {
                node = Some((role, id))
            }
            _ => return profile(format!("unexpected SAN URI {u}")),
        }
    }
    let Some((role, id)) = node else {
        return profile("subjectAltName must hold one warren node URI");
    };
    Ok(NodeIdentity {
        trust_domain: trust_domain.to_owned(),
        role,
        id,
        serial: hex(c.serial.strip_prefix(&[0]).unwrap_or(c.serial)),
        not_after: c.not_after_time(),
        dns_names: dns,
    })
}

/// Converts a system time for webpki.
pub fn unix_time(t: SystemTime) -> UnixTime {
    UnixTime::since_unix_epoch(t.duration_since(UNIX_EPOCH).unwrap_or_default())
}
