//! A test PKI: a deployment root, client and infrastructure issuing CAs,
//! and certificates for relays, connectors and user+device clients, in the
//! profile of docs/protocol.md section 10. The control plane issues real
//! certificates; this exists so the data path can be tested on its own.
//!
//! Certificates are built here with warren-core's DER writer and signed
//! with aws-lc-rs, so tests can also mint certificates that break the
//! profile on purpose.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use warren_core::der::{self, tag};
use warren_core::identity::{self, WarrenIdentity};
use warren_core::pki::{TrustBundle, oid};
use warren_core::tls::Credentials;

const ECDSA_WITH_SHA256: &[u128] = &[1, 2, 840, 10045, 4, 3, 2];
const COMMON_NAME: &[u128] = &[2, 5, 4, 3];

/// An ECDSA P-256 key pair.
pub struct KeyPair {
    pkcs8: Vec<u8>,
    pair: EcdsaKeyPair,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyPair(P-256)")
    }
}

impl KeyPair {
    /// Generates a key.
    pub fn generate() -> KeyPair {
        let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &SystemRandom::new())
            .expect("key generation")
            .as_ref()
            .to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(alg, &pkcs8).expect("own key parses");
        KeyPair { pkcs8, pair }
    }

    /// The SubjectPublicKeyInfo, DER.
    pub fn spki(&self) -> Vec<u8> {
        let alg = der::sequence(&[
            &der::tlv(tag::OID, oid::EC_PUBLIC_KEY),
            &der::tlv(tag::OID, oid::P256),
        ]);
        let mut bits = vec![0u8];
        bits.extend_from_slice(self.pair.public_key().as_ref());
        der::sequence(&[&alg, &der::tlv(tag::BIT_STRING, &bits)])
    }

    /// Signs with ECDSA P-256 SHA-256, DER signature.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&SystemRandom::new(), msg)
            .expect("signing")
            .as_ref()
            .to_vec()
    }

    /// The private key, PKCS#8.
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()))
    }

    /// The private key as PEM.
    pub fn private_key_pem(&self) -> String {
        pem("PRIVATE KEY", &self.pkcs8)
    }

    fn key_id(&self) -> Vec<u8> {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, self.pair.public_key().as_ref())
            .as_ref()[..20]
            .to_vec()
    }
}

/// Everything that goes into a certificate; tests change fields to break
/// the profile.
#[derive(Debug, Clone)]
pub struct CertSpec {
    /// Serial number content octets.
    pub serial: Vec<u8>,
    /// Subject common name; `None` for an empty subject.
    pub subject_cn: Option<String>,
    /// notBefore, Unix seconds.
    pub not_before: i64,
    /// notAfter, Unix seconds.
    pub not_after: i64,
    /// basicConstraints: `None` to omit, `Some(ca)` otherwise.
    pub ca: Option<bool>,
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

/// Seconds since the Unix epoch now.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

fn random_serial() -> Vec<u8> {
    let mut s = [0u8; 16];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut s)
        .expect("CSPRNG");
    s[0] &= 0x7f;
    s[0] |= 0x40;
    s.to_vec()
}

impl CertSpec {
    /// A CA certificate valid for ten years.
    pub fn ca(cn: &str) -> CertSpec {
        let now = unix_now();
        CertSpec {
            serial: random_serial(),
            subject_cn: Some(cn.into()),
            not_before: now - 3600,
            not_after: now + 10 * 365 * 86_400,
            ca: Some(true),
            key_usage: Some((0x06, true)),
            eku: Vec::new(),
            san_uris: Vec::new(),
            san_dns: Vec::new(),
            san_critical: false,
            key_ids: true,
            extra: Vec::new(),
        }
    }

    /// A leaf with the given lifetime starting now (backdated a minute).
    pub fn leaf(lifetime_secs: i64) -> CertSpec {
        let now = unix_now();
        CertSpec {
            serial: random_serial(),
            subject_cn: None,
            not_before: now - 60,
            not_after: now - 60 + lifetime_secs,
            ca: Some(false),
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

fn name(cn: Option<&str>) -> Vec<u8> {
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

fn time(secs: i64) -> Vec<u8> {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let (h, mi, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    if (1950..2050).contains(&y) {
        let v = format!("{:02}{m:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100);
        der::tlv(tag::UTC_TIME, v.as_bytes())
    } else {
        let v = format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z");
        der::tlv(tag::GENERALIZED_TIME, v.as_bytes())
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

/// An issuer: its key, subject name and key identifier.
#[derive(Debug)]
pub struct Issuer<'a> {
    /// Signing key.
    pub key: &'a KeyPair,
    /// Subject name of the issuer certificate, DER.
    pub name: Vec<u8>,
}

/// Builds and signs a certificate. `issuer` `None` means self-signed.
pub fn issue(spec: &CertSpec, subject_key: &KeyPair, issuer: Option<&Issuer<'_>>) -> Vec<u8> {
    let subject = name(spec.subject_cn.as_deref());
    let (issuer_key, issuer_name) = match issuer {
        Some(i) => (i.key, i.name.clone()),
        None => (subject_key, subject.clone()),
    };
    let mut exts = Vec::new();
    if let Some(ca) = spec.ca {
        let bc = if ca {
            der::sequence(&[&der::boolean(true)])
        } else {
            der::sequence(&[])
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
        exts.push(extension(
            oid::SKI,
            false,
            &der::tlv(tag::OCTET_STRING, &subject_key.key_id()),
        ));
        let aki = der::sequence(&[&der::tlv(tag::context_primitive(0), &issuer_key.key_id())]);
        exts.push(extension(oid::AKI, false, &aki));
    }
    for (o, critical, value) in &spec.extra {
        exts.push(extension(o, *critical, value));
    }
    let ext_refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    let sig_alg = der::sequence(&[&der::oid(ECDSA_WITH_SHA256)]);
    let version = der::tlv(tag::context(0), &der::uint(tag::INTEGER, 2));
    let validity = der::sequence(&[&time(spec.not_before), &time(spec.not_after)]);
    let extensions = der::tlv(tag::context(3), &der::sequence(&ext_refs));
    let tbs = der::sequence(&[
        &version,
        &der::tlv(tag::INTEGER, &spec.serial),
        &sig_alg,
        &issuer_name,
        &validity,
        &subject,
        &subject_key.spki(),
        &extensions,
    ]);
    let mut sig = vec![0u8];
    sig.extend_from_slice(&issuer_key.sign(&tbs));
    der::sequence(&[&tbs, &sig_alg, &der::tlv(tag::BIT_STRING, &sig)])
}

/// A CA: key, certificate and subject name.
#[derive(Debug)]
pub struct Ca {
    /// Key.
    pub key: KeyPair,
    /// Certificate, DER.
    pub cert: Vec<u8>,
    /// Subject name, DER.
    pub name: Vec<u8>,
}

impl Ca {
    fn issuer(&self) -> Issuer<'_> {
        Issuer {
            key: &self.key,
            name: self.name.clone(),
        }
    }
}

/// A full test deployment PKI.
#[derive(Debug)]
pub struct TestPki {
    /// Trust domain.
    pub trust_domain: String,
    /// Root CA.
    pub root: Ca,
    /// Client issuing CA.
    pub client_ca: Ca,
    /// Infrastructure issuing CA.
    pub infra_ca: Ca,
}

/// Options for a user+device certificate.
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// User ID.
    pub user: String,
    /// Device ID.
    pub device: String,
    /// The identity extension.
    pub identity: WarrenIdentity,
    /// Lifetime in seconds (the profile allows at most 4 hours).
    pub lifetime_secs: i64,
}

impl ClientCert {
    /// A client certificate for `user` on `device` with the given tunnel
    /// addresses, MFA used, authenticated now.
    pub fn new(user: &str, device: &str, v4: &str, v6: &str) -> ClientCert {
        ClientCert {
            user: user.into(),
            device: device.into(),
            identity: WarrenIdentity {
                session_id: format!("session-{user}-{device}"),
                auth_time: unix_now() as u64,
                mfa: true,
                trust_class: identity::TrustClass::DeviceReported,
                tunnel_v4: v4.parse().expect("IPv4 tunnel address"),
                tunnel_v6: v6.parse().expect("IPv6 tunnel address"),
            },
            lifetime_secs: 4 * 3600,
        }
    }
}

impl TestPki {
    /// Creates a root and both issuing CAs.
    pub fn new(trust_domain: &str) -> TestPki {
        let make = |cn: &str, parent: Option<&Ca>| {
            let key = KeyPair::generate();
            let spec = CertSpec::ca(cn);
            let cert = issue(&spec, &key, parent.map(Ca::issuer).as_ref());
            Ca {
                key,
                cert,
                name: name(Some(cn)),
            }
        };
        let root = make(&format!("{trust_domain} root CA"), None);
        let client_ca = make(&format!("{trust_domain} client CA"), Some(&root));
        let infra_ca = make(&format!("{trust_domain} infrastructure CA"), Some(&root));
        TestPki {
            trust_domain: trust_domain.into(),
            root,
            client_ca,
            infra_ca,
        }
    }

    /// The trust bundle clients and nodes verify against.
    pub fn bundle(&self) -> TrustBundle {
        TrustBundle::new(
            &self.trust_domain,
            CertificateDer::from(self.root.cert.clone()),
            vec![CertificateDer::from(self.client_ca.cert.clone())],
            vec![CertificateDer::from(self.infra_ca.cert.clone())],
        )
        .expect("test bundle is valid")
    }

    fn credentials(leaf: Vec<u8>, ca: &Ca, key: &KeyPair) -> Credentials {
        Credentials {
            chain: vec![
                CertificateDer::from(leaf),
                CertificateDer::from(ca.cert.clone()),
            ],
            key: key.private_key(),
        }
    }

    /// An infrastructure leaf spec for `uri`, with both EKUs.
    pub fn infra_spec(&self, uri: &str, dns: &[&str]) -> CertSpec {
        let mut spec = CertSpec::leaf(24 * 3600);
        spec.san_critical = false;
        spec.san_uris = vec![uri.to_owned()];
        spec.san_dns = dns.iter().map(|d| (*d).to_owned()).collect();
        spec.eku = vec![oid::SERVER_AUTH.to_vec(), oid::CLIENT_AUTH.to_vec()];
        spec
    }

    /// Issues an infrastructure certificate from a spec.
    pub fn issue_infra(&self, spec: &CertSpec) -> Credentials {
        let key = KeyPair::generate();
        let leaf = issue(spec, &key, Some(&self.infra_ca.issuer()));
        Self::credentials(leaf, &self.infra_ca, &key)
    }

    /// A relay certificate listening on `dns` names.
    pub fn relay(&self, id: &str, dns: &[&str]) -> Credentials {
        let uri = format!("warren://{}/relay/{id}", self.trust_domain);
        self.issue_infra(&self.infra_spec(&uri, dns))
    }

    /// A connector certificate in `group`.
    pub fn connector(&self, group: &str, id: &str) -> Credentials {
        let uri = format!("warren://{}/connector/{group}/{id}", self.trust_domain);
        self.issue_infra(&self.infra_spec(&uri, &[]))
    }

    /// The spec of a conforming user+device certificate.
    pub fn client_spec(&self, c: &ClientCert) -> CertSpec {
        let mut spec = CertSpec::leaf(c.lifetime_secs);
        spec.san_uris = vec![
            format!("warren://{}/user/{}", self.trust_domain, c.user),
            format!("warren://{}/device/{}", self.trust_domain, c.device),
        ];
        spec.eku = vec![oid::CLIENT_AUTH.to_vec()];
        spec.extra = vec![(
            identity::identity_extension_oid(),
            false,
            c.identity.to_der(),
        )];
        spec
    }

    /// Issues a client certificate from a spec with a new device key.
    pub fn issue_client(&self, spec: &CertSpec) -> Credentials {
        let key = KeyPair::generate();
        self.issue_client_with_key(spec, &key)
    }

    /// Issues a client certificate from a spec for an existing device key.
    pub fn issue_client_with_key(&self, spec: &CertSpec, key: &KeyPair) -> Credentials {
        let leaf = issue(spec, key, Some(&self.client_ca.issuer()));
        Self::credentials(leaf, &self.client_ca, key)
    }

    /// A conforming user+device certificate.
    pub fn client(&self, c: &ClientCert) -> Credentials {
        self.issue_client(&self.client_spec(c))
    }

    /// Writes the trust bundle as `root-ca.pem`, `client-ca.pem` and
    /// `infra-ca.pem` into `dir`.
    pub fn write_bundle(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(
            dir.join(warren_core::pki::ROOT_CA_FILE),
            pem("CERTIFICATE", &self.root.cert),
        )?;
        std::fs::write(
            dir.join(warren_core::pki::CLIENT_CA_FILE),
            pem("CERTIFICATE", &self.client_ca.cert),
        )?;
        std::fs::write(
            dir.join(warren_core::pki::INFRA_CA_FILE),
            pem("CERTIFICATE", &self.infra_ca.cert),
        )
    }
}

/// Writes credentials as `<name>.pem` (chain) and `<name>.key` (PKCS#8).
pub fn write_credentials(dir: &Path, name: &str, creds: &Credentials) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let chain: String = creds.chain.iter().map(|c| pem("CERTIFICATE", c)).collect();
    std::fs::write(dir.join(format!("{name}.pem")), chain)?;
    let PrivateKeyDer::Pkcs8(k) = &creds.key else {
        return Err(std::io::Error::other("expected a PKCS#8 key"));
    };
    let path = dir.join(format!("{name}.key"));
    std::fs::write(&path, pem("PRIVATE KEY", k.secret_pkcs8_der()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// PEM-encodes DER.
pub fn pem(label: &str, der_bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der_bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                b64.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
