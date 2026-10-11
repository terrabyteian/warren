//! The certificate profile in code (docs/protocol.md section 10): X.509
//! certificates, PKCS#10 requests and the warren identity extension.
//!
//! warren writes its certificates with this module rather than a general
//! certificate library for one reason: the identity extension lives under
//! `WARREN_OID_ARC`, a UUID-derived arc (`2.25.<uuid>`, ITU-T X.667) whose
//! second component is a 128-bit integer, and the general libraries only
//! encode object identifiers with 64-bit components. The encoder covers
//! exactly the profile and nothing more; DER comes from yasna and every
//! signature from aws-lc-rs, so no cryptography is implemented here. Path
//! validation of received certificates is not done here either: it belongs
//! to rustls and webpki, and [`Certificate::parse`] only reads fields from a
//! certificate that has already been validated (or that the caller issued).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use yasna::models::ObjectIdentifier;
use yasna::{ASN1Error, ASN1ErrorKind, BERReader, DERWriter, Tag};

use crate::clock;
use crate::keys::{KeyError, PublicKey};

/// `WARREN_OID_ARC` (docs/protocol.md section 14): the UUID-derived object
/// identifier arc under which warren defines its own identifiers.
pub const WARREN_OID_ARC: &str = "2.25.210934735780206524032646251764184590960";

/// The object identifier of the warren identity extension,
/// `WARREN_OID_ARC.1`.
pub const IDENTITY_EXTENSION_OID: &str = "2.25.210934735780206524032646251764184590960.1";

/// DER of [`IDENTITY_EXTENSION_OID`], tag and length included.
const IDENTITY_EXTENSION_OID_DER: &[u8] = &[
    0x06, 0x15, 0x69, 0x82, 0xbd, 0xb0, 0xc6, 0xda, 0xb8, 0xb1, 0xb2, 0x9b, 0x93, 0x9c, 0xdf, 0xf3,
    0xff, 0xb0, 0x8d, 0xc4, 0xd4, 0x70, 0x01,
];

const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const OID_SUBJECT_KEY_ID: &[u64] = &[2, 5, 29, 14];
const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
const OID_AUTHORITY_KEY_ID: &[u64] = &[2, 5, 29, 35];
const OID_EXT_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
const OID_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
const OID_CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];

/// A certificate or request could not be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Error(pub String);

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for X509Error {}

impl From<KeyError> for X509Error {
    fn from(e: KeyError) -> Self {
        X509Error(e.0.to_owned())
    }
}

impl From<ASN1Error> for X509Error {
    fn from(e: ASN1Error) -> Self {
        X509Error(format!("malformed DER: {e}"))
    }
}

fn err(msg: impl Into<String>) -> X509Error {
    X509Error(msg.into())
}

fn oid(components: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(components)
}

fn oid_der(components: &[u64]) -> Vec<u8> {
    yasna::construct_der(|w| w.write_oid(&oid(components)))
}

/// DER of a P-256 SubjectPublicKeyInfo.
pub fn spki_der(key: &PublicKey) -> Vec<u8> {
    yasna::construct_der(|w| write_spki(w, key))
}

fn write_spki(w: DERWriter, key: &PublicKey) {
    w.write_sequence(|w| {
        w.next().write_sequence(|w| {
            w.next().write_oid(&oid(OID_EC_PUBLIC_KEY));
            w.next().write_oid(&oid(OID_PRIME256V1));
        });
        w.next().write_bitvec_bytes(key.point(), 65 * 8);
    });
}

fn read_spki(r: BERReader) -> Result<PublicKey, ASN1Error> {
    let point = r.read_sequence(|r| {
        r.next().read_sequence(|r| {
            let alg = r.next().read_oid()?;
            let curve = r.next().read_oid()?;
            if alg != oid(OID_EC_PUBLIC_KEY) || curve != oid(OID_PRIME256V1) {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            Ok(())
        })?;
        let (bytes, bits) = r.next().read_bitvec_bytes()?;
        if bits != bytes.len() * 8 {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        Ok(bytes)
    })?;
    PublicKey::from_point(&point).map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))
}

/// Parses a DER SubjectPublicKeyInfo holding a P-256 key.
pub fn parse_spki(der: &[u8]) -> Result<PublicKey, X509Error> {
    yasna::parse_der(der, read_spki).map_err(|_| err("not a P-256 SubjectPublicKeyInfo"))
}

fn write_ecdsa_sha256(w: DERWriter) {
    // RFC 5758 section 3.2: the parameters field MUST be absent.
    w.write_sequence(|w| w.next().write_oid(&oid(OID_ECDSA_SHA256)));
}

fn read_ecdsa_sha256(r: BERReader) -> Result<(), ASN1Error> {
    r.read_sequence(|r| {
        if r.next().read_oid()? != oid(OID_ECDSA_SHA256) {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        Ok(())
    })
}

/// A distinguished name with a single common name, for CA subjects.
pub fn common_name(cn: &str) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_set(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid(OID_COMMON_NAME));
                    w.next().write_utf8_string(cn);
                });
            });
        });
    })
}

/// The empty distinguished name used by every leaf certificate: identity is
/// in the subject alternative name (docs/protocol.md section 10.2).
pub const EMPTY_NAME: &[u8] = &[0x30, 0x00];

/// What a certificate may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// A certificate authority that may sign certificates, with the
    /// largest number of intermediate CAs allowed below it.
    Ca {
        /// The basic-constraints path length.
        path_len: u8,
    },
    /// An end-entity certificate with the listed extended key usages.
    Leaf {
        /// id-kp-serverAuth: may authenticate a TLS server.
        server_auth: bool,
        /// id-kp-clientAuth: may authenticate a TLS client.
        client_auth: bool,
    },
}

/// `authTime` when the IdP did not report when the user authenticated:
/// freshness is unknown, and the sign-in counts as older than any
/// `auth.maxAge`, so freshness-gated rules ask the user to sign in again.
pub const AUTH_TIME_UNKNOWN: i64 = 0;

/// The warren identity extension carried by user+device certificates
/// (docs/protocol.md section 10.2).
///
/// ```text
/// WarrenIdentity ::= SEQUENCE {
///   version     INTEGER,             -- 1
///   sessionId   UTF8String,
///   authTime    INTEGER,             -- IdP authentication time, Unix seconds;
///                                    -- 0 when the IdP did not report it
///   mfa         BOOLEAN,             -- the sign-in used multi-factor authentication
///   trustClass  INTEGER (1..3),      -- device enrollment trust class
///   tunnelV4    OCTET STRING (SIZE (4)),
///   tunnelV6    OCTET STRING (SIZE (16)),
///   ...                              -- later versions append fields
/// }
/// ```
///
/// Trust classes use the scale of posture signals: 1 device-reported,
/// 2 server-verified, 3 hardware-attested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The sign-in session the certificate belongs to.
    pub session_id: String,
    /// When the user last authenticated at the IdP, in Unix seconds, or
    /// [`AUTH_TIME_UNKNOWN`].
    pub auth_time: i64,
    /// Whether that authentication used multi-factor authentication.
    pub mfa: bool,
    /// The device's enrollment trust class, 1 to 3.
    pub trust_class: u8,
    /// The device's IPv4 tunnel address.
    pub tunnel_v4: Ipv4Addr,
    /// The device's IPv6 tunnel address.
    pub tunnel_v6: Ipv6Addr,
}

const IDENTITY_VERSION: u64 = 1;

impl Identity {
    /// The DER encoding of the extension value.
    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u64(IDENTITY_VERSION);
                w.next().write_utf8_string(&self.session_id);
                w.next().write_i64(self.auth_time);
                w.next().write_bool(self.mfa);
                w.next().write_u8(self.trust_class);
                w.next().write_bytes(&self.tunnel_v4.octets());
                w.next().write_bytes(&self.tunnel_v6.octets());
            })
        })
    }

    /// Decodes the extension value. Fields appended by later versions are
    /// skipped.
    pub fn from_der(der: &[u8]) -> Result<Identity, X509Error> {
        yasna::parse_der(der, |r| {
            r.read_sequence(|r| {
                let version = r.next().read_u64()?;
                if version < IDENTITY_VERSION {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                let session_id = r.next().read_utf8string()?;
                let auth_time = r.next().read_i64()?;
                let mfa = r.next().read_bool()?;
                let trust_class = r.next().read_u8()?;
                let v4: [u8; 4] = r
                    .next()
                    .read_bytes()?
                    .try_into()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                let v6: [u8; 16] = r
                    .next()
                    .read_bytes()?
                    .try_into()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                while r.read_optional(|r| r.read_der())?.is_some() {}
                Ok(Identity {
                    session_id,
                    auth_time,
                    mfa,
                    trust_class,
                    tunnel_v4: Ipv4Addr::from(v4),
                    tunnel_v6: Ipv6Addr::from(v6),
                })
            })
        })
        .map_err(|_| err("malformed warren identity extension"))
        .and_then(|id| {
            if (1..=3).contains(&id.trust_class) {
                Ok(id)
            } else {
                Err(err("identity extension trust class out of range"))
            }
        })
    }
}

/// Everything that goes into one certificate.
#[derive(Debug, Clone)]
pub struct CertificateSpec<'a> {
    /// The serial number: at least 64 bits from a CSPRNG. It is encoded as a
    /// positive integer.
    pub serial: [u8; 16],
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// The subject name, DER: [`EMPTY_NAME`] for leaves, a
    /// [`common_name`] for CAs.
    pub subject: Vec<u8>,
    /// The certified key.
    pub public_key: &'a PublicKey,
    /// CA or leaf, and the leaf's extended key usages.
    pub usage: Usage,
    /// URI subject alternative names.
    pub uris: Vec<String>,
    /// DNS subject alternative names.
    pub dns_names: Vec<String>,
    /// The warren identity extension, for user+device certificates.
    pub identity: Option<Identity>,
}

/// The CA that signs a certificate: its subject name and key identifier,
/// taken from its own certificate (or from the spec, for a self-signed
/// root).
#[derive(Debug, Clone)]
pub struct IssuerInfo {
    /// The issuer's subject name, DER.
    pub name: Vec<u8>,
    /// The issuer's key identifier.
    pub key_id: [u8; 20],
}

/// Builds and signs a certificate. `sign` receives the DER of the
/// TBSCertificate and returns an ECDSA P-256 SHA-256 signature, DER-encoded;
/// it is where the issuing key (in memory, in a KMS, in hardware) is used.
pub fn build_certificate(
    spec: &CertificateSpec<'_>,
    issuer: &IssuerInfo,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, KeyError>,
) -> Result<Vec<u8>, X509Error> {
    if spec.not_after <= spec.not_before {
        return Err(err("certificate validity ends before it starts"));
    }
    if spec.serial.iter().all(|b| *b == 0) {
        return Err(err("serial number must not be zero"));
    }
    let leaf = matches!(spec.usage, Usage::Leaf { .. });
    if leaf && spec.subject != EMPTY_NAME {
        return Err(err("leaf certificates carry an empty subject"));
    }
    if leaf && spec.uris.is_empty() && spec.dns_names.is_empty() {
        return Err(err("a leaf certificate needs a subject alternative name"));
    }
    if !spec
        .uris
        .iter()
        .chain(&spec.dns_names)
        .all(|s| s.is_ascii())
    {
        return Err(err("subject alternative names must be ASCII"));
    }
    if let Usage::Leaf {
        server_auth: false,
        client_auth: false,
    } = spec.usage
    {
        return Err(err(
            "a leaf certificate needs at least one extended key usage",
        ));
    }
    if let Some(id) = &spec.identity
        && !(1..=3).contains(&id.trust_class)
    {
        return Err(err("identity extension trust class out of range"));
    }
    if ![spec.not_before, spec.not_after]
        .iter()
        .all(|t| (1950..=9999).contains(&clock::Civil::from_unix(*t).year))
    {
        return Err(err("certificate validity must fall between 1950 and 9999"));
    }
    let tbs = tbs_der(spec, issuer);
    let signature = sign(&tbs)?;
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&tbs);
            write_ecdsa_sha256(w.next());
            w.next().write_bitvec_bytes(&signature, signature.len() * 8);
        })
    }))
}

fn tbs_der(spec: &CertificateSpec<'_>, issuer: &IssuerInfo) -> Vec<u8> {
    let key_id = spec.public_key.key_id();
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            // version: v3
            w.next().write_tagged(Tag::context(0), |w| w.write_u8(2));
            w.next().write_bigint_bytes(&spec.serial, true);
            write_ecdsa_sha256(w.next());
            w.next().write_der(&issuer.name);
            w.next().write_sequence(|w| {
                w.next().write_der(&clock::der_time(spec.not_before));
                w.next().write_der(&clock::der_time(spec.not_after));
            });
            w.next().write_der(&spec.subject);
            write_spki(w.next(), spec.public_key);
            w.next().write_tagged(Tag::context(3), |w| {
                w.write_sequence(|w| write_extensions(w, spec, issuer, &key_id));
            });
        })
    })
}

fn write_extension(w: DERWriter, id: &[u8], critical: bool, value: Vec<u8>) {
    w.write_sequence(|w| {
        w.next().write_der(id);
        if critical {
            w.next().write_bool(true);
        }
        w.next().write_bytes(&value);
    });
}

fn write_extensions(
    w: &mut yasna::DERWriterSeq,
    spec: &CertificateSpec<'_>,
    issuer: &IssuerInfo,
    key_id: &[u8; 20],
) {
    let self_signed = issuer.key_id == *key_id;
    if !self_signed {
        write_extension(
            w.next(),
            &oid_der(OID_AUTHORITY_KEY_ID),
            false,
            yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next()
                        .write_tagged_implicit(Tag::context(0), |w| w.write_bytes(&issuer.key_id));
                })
            }),
        );
    }
    write_extension(
        w.next(),
        &oid_der(OID_SUBJECT_KEY_ID),
        false,
        yasna::construct_der(|w| w.write_bytes(key_id)),
    );
    match spec.usage {
        Usage::Ca { path_len } => {
            // keyCertSign (bit 5).
            write_extension(
                w.next(),
                &oid_der(OID_KEY_USAGE),
                true,
                yasna::construct_der(|w| w.write_bitvec_bytes(&[0x04], 6)),
            );
            write_extension(
                w.next(),
                &oid_der(OID_BASIC_CONSTRAINTS),
                true,
                yasna::construct_der(|w| {
                    w.write_sequence(|w| {
                        w.next().write_bool(true);
                        w.next().write_u8(path_len);
                    })
                }),
            );
        }
        Usage::Leaf {
            server_auth,
            client_auth,
        } => {
            // digitalSignature (bit 0).
            write_extension(
                w.next(),
                &oid_der(OID_KEY_USAGE),
                true,
                yasna::construct_der(|w| w.write_bitvec_bytes(&[0x80], 1)),
            );
            write_extension(
                w.next(),
                &oid_der(OID_EXT_KEY_USAGE),
                false,
                yasna::construct_der(|w| {
                    w.write_sequence(|w| {
                        if server_auth {
                            w.next().write_oid(&oid(OID_SERVER_AUTH));
                        }
                        if client_auth {
                            w.next().write_oid(&oid(OID_CLIENT_AUTH));
                        }
                    })
                }),
            );
            // cA defaults to FALSE, so CA:FALSE is the empty sequence.
            write_extension(
                w.next(),
                &oid_der(OID_BASIC_CONSTRAINTS),
                true,
                yasna::construct_der(|w| w.write_sequence(|_| {})),
            );
        }
    }
    if !spec.uris.is_empty() || !spec.dns_names.is_empty() {
        // RFC 5280 section 4.2.1.6: critical when the subject is empty.
        write_extension(
            w.next(),
            &oid_der(OID_SUBJECT_ALT_NAME),
            spec.subject == EMPTY_NAME,
            yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    for dns in &spec.dns_names {
                        w.next()
                            .write_tagged_implicit(Tag::context(2), |w| w.write_ia5_string(dns));
                    }
                    for uri in &spec.uris {
                        w.next()
                            .write_tagged_implicit(Tag::context(6), |w| w.write_ia5_string(uri));
                    }
                })
            }),
        );
    }
    if let Some(identity) = &spec.identity {
        write_extension(
            w.next(),
            IDENTITY_EXTENSION_OID_DER,
            false,
            identity.to_der(),
        );
    }
}

/// The fields of a certificate this profile cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The whole certificate, DER.
    pub der: Vec<u8>,
    /// The TBSCertificate, DER: what the signature covers.
    pub tbs: Vec<u8>,
    /// The signature over `tbs`, DER.
    pub signature: Vec<u8>,
    /// The serial number's magnitude, big-endian, without leading zeros.
    pub serial: Vec<u8>,
    /// The issuer name, DER.
    pub issuer: Vec<u8>,
    /// The subject name, DER.
    pub subject: Vec<u8>,
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// The certified key.
    pub public_key: PublicKey,
    /// Basic constraints: whether this is a CA.
    pub is_ca: bool,
    /// Extended key usage includes id-kp-serverAuth.
    pub server_auth: bool,
    /// Extended key usage includes id-kp-clientAuth.
    pub client_auth: bool,
    /// URI subject alternative names.
    pub uris: Vec<String>,
    /// DNS subject alternative names.
    pub dns_names: Vec<String>,
    /// Whether the subject alternative name extension is critical.
    pub san_critical: bool,
    /// The subject key identifier, if present.
    pub subject_key_id: Option<Vec<u8>>,
    /// The authority key identifier, if present.
    pub authority_key_id: Option<Vec<u8>>,
    /// The warren identity extension, if present.
    pub identity: Option<Identity>,
}

impl Certificate {
    /// Parses a certificate that uses ECDSA P-256 with SHA-256. This reads
    /// fields; it does not validate the certificate (see the module docs).
    /// Unknown critical extensions are rejected, as RFC 5280 requires.
    pub fn parse(der: &[u8]) -> Result<Certificate, X509Error> {
        let (tbs, signature) = yasna::parse_der(der, |r| {
            r.read_sequence(|r| {
                let tbs = r.next().read_der()?;
                read_ecdsa_sha256(r.next())?;
                let (sig, bits) = r.next().read_bitvec_bytes()?;
                if bits != sig.len() * 8 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                Ok((tbs, sig))
            })
        })?;
        let mut cert = yasna::parse_der(&tbs, |r| {
            r.read_sequence(|r| {
                let version = r.next().read_tagged(Tag::context(0), |r| r.read_u8())?;
                if version != 2 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                let (serial, positive) = r.next().read_bigint_bytes()?;
                if !positive {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                let first = serial.iter().position(|b| *b != 0).unwrap_or(serial.len());
                let serial = serial[first..].to_vec();
                read_ecdsa_sha256(r.next())?;
                let issuer = r.next().read_der()?;
                let (not_before, not_after) = r
                    .next()
                    .read_sequence(|r| Ok((read_time(r.next())?, read_time(r.next())?)))?;
                let subject = r.next().read_der()?;
                let public_key = read_spki(r.next())?;
                let mut cert = Certificate {
                    der: der.to_vec(),
                    tbs: Vec::new(),
                    signature: Vec::new(),
                    serial,
                    issuer,
                    subject,
                    not_before,
                    not_after,
                    public_key,
                    is_ca: false,
                    server_auth: false,
                    client_auth: false,
                    uris: Vec::new(),
                    dns_names: Vec::new(),
                    san_critical: false,
                    subject_key_id: None,
                    authority_key_id: None,
                    identity: None,
                };
                let mut seen = Vec::new();
                r.read_optional(|r| {
                    r.read_tagged(Tag::context(3), |r| {
                        r.read_sequence_of(|r| read_extension(r, &mut cert, &mut seen))
                    })
                })?;
                Ok(cert)
            })
        })?;
        cert.tbs = tbs;
        cert.signature = signature;
        Ok(cert)
    }

    /// Checks the signature against the issuer's key.
    pub fn verify_signature(&self, issuer: &PublicKey) -> Result<(), X509Error> {
        issuer
            .verify_der(&self.tbs, &self.signature)
            .map_err(|_| err("certificate signature does not verify"))
    }

    /// The serial number as lowercase hex, the form revocation state uses.
    pub fn serial_hex(&self) -> String {
        crate::keys::hex(&self.serial)
    }
}

fn read_time(r: BERReader) -> Result<i64, ASN1Error> {
    let value = r.read_tagged_der()?;
    let tag = match value.tag() {
        t if t == yasna::tags::TAG_UTCTIME => 0x17,
        t if t == yasna::tags::TAG_GENERALIZEDTIME => 0x18,
        _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
    };
    clock::parse_der_time(tag, value.value()).ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))
}

fn read_extension(
    r: BERReader,
    cert: &mut Certificate,
    seen: &mut Vec<Vec<u8>>,
) -> Result<(), ASN1Error> {
    r.read_sequence(|r| {
        let id = r.next().read_der()?;
        let critical = r.read_default(false, |r| r.read_bool())?;
        let value = r.next().read_bytes()?;
        let invalid = || ASN1Error::new(ASN1ErrorKind::Invalid);
        // RFC 5280 section 4.2: at most one instance of each extension.
        if seen.contains(&id) {
            return Err(invalid());
        }
        seen.push(id.clone());
        if id == oid_der(OID_BASIC_CONSTRAINTS) {
            cert.is_ca = yasna::parse_der(&value, |r| {
                r.read_sequence(|r| {
                    let ca = r.read_default(false, |r| r.read_bool())?;
                    r.read_optional(|r| r.read_u64())?;
                    Ok(ca)
                })
            })?;
        } else if id == oid_der(OID_EXT_KEY_USAGE) {
            yasna::parse_der(&value, |r| {
                r.read_sequence_of(|r| {
                    let usage = r.read_oid()?;
                    if usage == oid(OID_SERVER_AUTH) {
                        cert.server_auth = true;
                    } else if usage == oid(OID_CLIENT_AUTH) {
                        cert.client_auth = true;
                    }
                    Ok(())
                })
            })?;
        } else if id == oid_der(OID_SUBJECT_ALT_NAME) {
            cert.san_critical = critical;
            yasna::parse_der(&value, |r| {
                r.read_sequence_of(|r| {
                    let name = r.read_tagged_der()?;
                    let named = name.tag() == Tag::context(6) || name.tag() == Tag::context(2);
                    if named && name.pcbit() != yasna::PCBit::Primitive {
                        return Err(invalid());
                    }
                    let text = || {
                        std::str::from_utf8(name.value())
                            .ok()
                            .filter(|s| s.is_ascii())
                            .map(str::to_owned)
                            .ok_or_else(invalid)
                    };
                    if name.tag() == Tag::context(6) {
                        cert.uris.push(text()?);
                    } else if name.tag() == Tag::context(2) {
                        cert.dns_names.push(text()?);
                    }
                    Ok(())
                })
            })?;
        } else if id == oid_der(OID_SUBJECT_KEY_ID) {
            cert.subject_key_id = Some(yasna::parse_der(&value, |r| r.read_bytes())?);
        } else if id == oid_der(OID_AUTHORITY_KEY_ID) {
            cert.authority_key_id = yasna::parse_der(&value, |r| {
                r.read_sequence(|r| {
                    let id = r.read_optional(|r| {
                        r.read_tagged_implicit(Tag::context(0), |r| r.read_bytes())
                    })?;
                    while r.read_optional(|r| r.read_der())?.is_some() {}
                    Ok(id)
                })
            })?;
        } else if id == IDENTITY_EXTENSION_OID_DER {
            cert.identity = Some(Identity::from_der(&value).map_err(|_| invalid())?);
        } else if id == oid_der(OID_KEY_USAGE) {
            // Read for well-formedness; the profile's key usage is checked by
            // the TLS stack during path validation.
            yasna::parse_der(&value, |r| r.read_bitvec_bytes())?;
        } else if critical {
            return Err(invalid());
        }
        Ok(())
    })
}

/// Builds a PKCS#10 certificate request (RFC 2986) for a P-256 key with an
/// empty subject and no attributes. `sign` signs the
/// CertificationRequestInfo with that key (DER-encoded ECDSA signature), so
/// a hardware-held key can sign without leaving its key store.
pub fn build_csr(
    key: &PublicKey,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, KeyError>,
) -> Result<Vec<u8>, X509Error> {
    let info = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            w.next().write_der(EMPTY_NAME);
            write_spki(w.next(), key);
            w.next()
                .write_tagged_implicit(Tag::context(0), |w| w.write_set(|_| {}));
        })
    });
    let signature = sign(&info)?;
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&info);
            write_ecdsa_sha256(w.next());
            w.next().write_bitvec_bytes(&signature, signature.len() * 8);
        })
    }))
}

/// Parses a PKCS#10 request for a P-256 key and verifies its signature, which
/// proves the requester holds the private key. Returns the key. The subject
/// and any attributes are ignored: the control plane decides every field of
/// the certificate it issues.
pub fn verify_csr(der: &[u8]) -> Result<PublicKey, X509Error> {
    let (info, signature) = yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            let info = r.next().read_der()?;
            read_ecdsa_sha256(r.next())?;
            let (sig, bits) = r.next().read_bitvec_bytes()?;
            if bits != sig.len() * 8 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            Ok((info, sig))
        })
    })
    .map_err(|_| err("not a PKCS#10 request signed with ECDSA P-256 SHA-256"))?;
    let key = yasna::parse_der(&info, |r| {
        r.read_sequence(|r| {
            if r.next().read_u8()? != 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            r.next().read_der()?;
            let key = read_spki(r.next())?;
            r.next().read_tagged_implicit(Tag::context(0), |r| {
                r.read_set_of(|r| r.read_der().map(drop))
            })?;
            Ok(key)
        })
    })
    .map_err(|_| err("the request does not carry a P-256 key"))?;
    key.verify_der(&info, &signature)
        .map_err(|_| err("the request is not signed by the key it carries"))?;
    Ok(key)
}

/// PEM-encodes DER under a label such as `CERTIFICATE`.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        // base64 output is ASCII, so every chunk is valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Decodes every PEM block with the given label, in order.
pub fn pem_decode(label: &str, text: &str) -> Result<Vec<Vec<u8>>, X509Error> {
    use base64::Engine;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let stop = after
            .find(&end)
            .ok_or_else(|| err(format!("unterminated PEM {label} block")))?;
        let body: String = after[..stop].split_whitespace().collect();
        out.push(
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|_| err(format!("invalid base64 in PEM {label} block")))?,
        );
        rest = &after[stop + end.len()..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    fn oid_text_to_der(text: &str) -> Vec<u8> {
        // Arbitrary-precision base-128 encoding, for checking the constant.
        let parts: Vec<u128> = text.split('.').map(|p| p.parse().unwrap()).collect();
        let mut body = Vec::new();
        let mut arcs = vec![parts[0] * 40 + parts[1]];
        arcs.extend_from_slice(&parts[2..]);
        for mut arc in arcs {
            let mut chunk = vec![(arc & 0x7f) as u8];
            arc >>= 7;
            while arc > 0 {
                chunk.push((arc & 0x7f) as u8 | 0x80);
                arc >>= 7;
            }
            chunk.reverse();
            body.extend(chunk);
        }
        let mut out = vec![0x06, body.len() as u8];
        out.extend(body);
        out
    }

    #[test]
    fn identity_oid_constant_matches_its_dotted_form() {
        assert_eq!(
            oid_text_to_der(IDENTITY_EXTENSION_OID),
            IDENTITY_EXTENSION_OID_DER
        );
        assert!(IDENTITY_EXTENSION_OID.starts_with(WARREN_OID_ARC));
        assert_eq!(oid_text_to_der("2.5.29.17"), oid_der(OID_SUBJECT_ALT_NAME));
    }

    fn identity() -> Identity {
        Identity {
            session_id: "s-0123".into(),
            auth_time: 1_791_715_800,
            mfa: true,
            trust_class: 1,
            tunnel_v4: "100.96.0.7".parse().unwrap(),
            tunnel_v6: "fd77:6172:7265:6e00::7".parse().unwrap(),
        }
    }

    #[test]
    fn identity_round_trips_and_tolerates_appended_fields() {
        let id = identity();
        assert_eq!(Identity::from_der(&id.to_der()).unwrap(), id);
        // A later version with one more field still decodes.
        let extended = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u64(2);
                w.next().write_utf8_string(&id.session_id);
                w.next().write_i64(id.auth_time);
                w.next().write_bool(id.mfa);
                w.next().write_u8(id.trust_class);
                w.next().write_bytes(&id.tunnel_v4.octets());
                w.next().write_bytes(&id.tunnel_v6.octets());
                w.next().write_utf8_string("future");
            })
        });
        assert_eq!(Identity::from_der(&extended).unwrap(), id);
        let mut bad = id.clone();
        bad.trust_class = 4;
        assert!(Identity::from_der(&bad.to_der()).is_err());
    }

    struct Ca {
        key: SigningKey,
        cert: Certificate,
    }

    fn root() -> Ca {
        let key = SigningKey::generate().unwrap();
        let name = common_name("warren root CA test");
        let spec = CertificateSpec {
            serial: [7; 16],
            not_before: 1_791_000_000,
            not_after: 1_791_000_000 + 86_400 * 365,
            subject: name.clone(),
            public_key: key.public_key(),
            usage: Usage::Ca { path_len: 1 },
            uris: vec![],
            dns_names: vec![],
            identity: None,
        };
        let issuer = IssuerInfo {
            name,
            key_id: key.public_key().key_id(),
        };
        let der = build_certificate(&spec, &issuer, |tbs| key.sign_der(tbs)).unwrap();
        Ca {
            cert: Certificate::parse(&der).unwrap(),
            key,
        }
    }

    #[test]
    fn a_self_signed_root_has_the_ca_profile() {
        let ca = root();
        ca.cert.verify_signature(ca.key.public_key()).unwrap();
        assert!(ca.cert.is_ca);
        assert_eq!(ca.cert.subject, ca.cert.issuer);
        assert_eq!(ca.cert.authority_key_id, None);
        assert_eq!(
            ca.cert.subject_key_id.as_deref(),
            Some(&ca.key.public_key().key_id()[..])
        );
        assert_eq!(ca.cert.serial, vec![7; 16]);
    }

    #[test]
    fn a_client_certificate_has_the_user_device_profile() {
        let ca = root();
        let device = SigningKey::generate().unwrap();
        let spec = CertificateSpec {
            serial: [0x80; 16],
            not_before: 1_791_715_680,
            not_after: 1_791_715_800 + 4 * 3600,
            subject: EMPTY_NAME.to_vec(),
            public_key: device.public_key(),
            usage: Usage::Leaf {
                server_auth: false,
                client_auth: true,
            },
            uris: vec![
                "warren://example.com/user/u-1".into(),
                "warren://example.com/device/d-1".into(),
            ],
            dns_names: vec![],
            identity: Some(identity()),
        };
        let issuer = IssuerInfo {
            name: ca.cert.subject.clone(),
            key_id: ca.key.public_key().key_id(),
        };
        let der = build_certificate(&spec, &issuer, |tbs| ca.key.sign_der(tbs)).unwrap();
        let cert = Certificate::parse(&der).unwrap();
        cert.verify_signature(ca.key.public_key()).unwrap();
        assert!(cert.verify_signature(device.public_key()).is_err());
        assert!(!cert.is_ca && cert.client_auth && !cert.server_auth);
        assert!(cert.san_critical);
        assert_eq!(cert.subject, EMPTY_NAME);
        assert_eq!(cert.issuer, ca.cert.subject);
        assert_eq!(cert.uris, spec.uris);
        assert_eq!(cert.identity, Some(identity()));
        assert_eq!(cert.public_key, *device.public_key());
        assert_eq!(cert.not_before, spec.not_before);
        assert_eq!(cert.not_after, spec.not_after);
        // A serial with the top bit set is still a positive integer.
        assert_eq!(cert.serial, vec![0x80; 16]);
        assert_eq!(
            cert.authority_key_id.as_deref(),
            Some(&ca.key.public_key().key_id()[..])
        );
    }

    #[test]
    fn leaves_need_an_empty_subject_and_a_name() {
        let ca = root();
        let key = SigningKey::generate().unwrap();
        let issuer = IssuerInfo {
            name: ca.cert.subject.clone(),
            key_id: ca.key.public_key().key_id(),
        };
        let mut spec = CertificateSpec {
            serial: [1; 16],
            not_before: 1,
            not_after: 2,
            subject: common_name("nope"),
            public_key: key.public_key(),
            usage: Usage::Leaf {
                server_auth: true,
                client_auth: false,
            },
            uris: vec![],
            dns_names: vec!["relay.example.com".into()],
            identity: None,
        };
        assert!(build_certificate(&spec, &issuer, |t| ca.key.sign_der(t)).is_err());
        spec.subject = EMPTY_NAME.to_vec();
        spec.dns_names.clear();
        assert!(build_certificate(&spec, &issuer, |t| ca.key.sign_der(t)).is_err());
        spec.dns_names.push("relay.example.com".into());
        spec.not_after = 1;
        assert!(build_certificate(&spec, &issuer, |t| ca.key.sign_der(t)).is_err());
    }

    #[test]
    fn the_builder_refuses_what_the_profile_forbids() {
        let ca = root();
        let key = SigningKey::generate().unwrap();
        let issuer = IssuerInfo {
            name: ca.cert.subject.clone(),
            key_id: ca.key.public_key().key_id(),
        };
        let good = CertificateSpec {
            serial: [1; 16],
            not_before: 1_791_000_000,
            not_after: 1_791_003_600,
            subject: EMPTY_NAME.to_vec(),
            public_key: key.public_key(),
            usage: Usage::Leaf {
                server_auth: false,
                client_auth: true,
            },
            uris: vec!["warren://example.com/user/u-1".into()],
            dns_names: vec![],
            identity: Some(identity()),
        };
        let sign = |t: &[u8]| ca.key.sign_der(t);
        assert!(build_certificate(&good, &issuer, sign).is_ok());
        let mut no_usage = good.clone();
        no_usage.usage = Usage::Leaf {
            server_auth: false,
            client_auth: false,
        };
        assert!(build_certificate(&no_usage, &issuer, sign).is_err());
        let mut bad_class = good.clone();
        if let Some(id) = bad_class.identity.as_mut() {
            id.trust_class = 4;
        }
        assert!(build_certificate(&bad_class, &issuer, sign).is_err());
        let mut far = good.clone();
        far.not_after = 400_000_000_000;
        assert!(build_certificate(&far, &issuer, sign).is_err());
    }

    /// A copy of `cert` with its extensions replaced by `extensions`
    /// (each a DER Extension), signed again by `key`.
    fn with_extensions(cert: &Certificate, key: &SigningKey, extensions: &[Vec<u8>]) -> Vec<u8> {
        let fields = yasna::parse_der(&cert.tbs, |r| {
            r.read_sequence(|r| {
                let fields: Vec<Vec<u8>> = (0..7)
                    .map(|_| r.next().read_der())
                    .collect::<Result<_, _>>()?;
                r.next().read_der()?;
                Ok(fields)
            })
        })
        .unwrap();
        let tbs = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                for f in &fields {
                    w.next().write_der(f);
                }
                w.next().write_tagged(Tag::context(3), |w| {
                    w.write_sequence(|w| {
                        for e in extensions {
                            w.next().write_der(e);
                        }
                    })
                });
            })
        });
        let sig = key.sign_der(&tbs).unwrap();
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_der(&tbs);
                write_ecdsa_sha256(w.next());
                w.next().write_bitvec_bytes(&sig, sig.len() * 8);
            })
        })
    }

    #[test]
    fn the_parser_refuses_repeated_extensions_and_constructed_names() {
        let ca = root();
        let ski = yasna::construct_der(|w| {
            write_extension(
                w,
                &oid_der(OID_SUBJECT_KEY_ID),
                false,
                yasna::construct_der(|w| w.write_bytes(&[1, 2, 3])),
            )
        });
        let once = with_extensions(&ca.cert, &ca.key, std::slice::from_ref(&ski));
        assert!(Certificate::parse(&once).is_ok());
        let twice = with_extensions(&ca.cert, &ca.key, &[ski.clone(), ski]);
        assert!(Certificate::parse(&twice).is_err());

        let san = |constructed: bool| {
            let value = yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    if constructed {
                        w.next()
                            .write_tagged(Tag::context(6), |w| w.write_ia5_string("x"));
                    } else {
                        w.next()
                            .write_tagged_implicit(Tag::context(6), |w| w.write_ia5_string("x"));
                    }
                })
            });
            yasna::construct_der(|w| {
                write_extension(w, &oid_der(OID_SUBJECT_ALT_NAME), false, value)
            })
        };
        let primitive = with_extensions(&ca.cert, &ca.key, &[san(false)]);
        assert_eq!(Certificate::parse(&primitive).unwrap().uris, ["x"]);
        let constructed = with_extensions(&ca.cert, &ca.key, &[san(true)]);
        assert!(Certificate::parse(&constructed).is_err());
    }

    #[test]
    fn csr_round_trip_proves_possession() {
        let key = SigningKey::generate().unwrap();
        let csr = build_csr(key.public_key(), |info| key.sign_der(info)).unwrap();
        assert_eq!(verify_csr(&csr).unwrap(), *key.public_key());

        let other = SigningKey::generate().unwrap();
        let forged = build_csr(key.public_key(), |info| other.sign_der(info)).unwrap();
        assert!(verify_csr(&forged).is_err());

        let mut flipped = csr.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(verify_csr(&flipped).is_err());
        let mut trailing = csr;
        trailing.push(0);
        assert!(verify_csr(&trailing).is_err());
    }

    #[test]
    fn pem_round_trips() {
        let blobs = [vec![1u8; 100], vec![2u8; 3]];
        let text: String = blobs.iter().map(|b| pem_encode("CERTIFICATE", b)).collect();
        assert!(text.lines().all(|l| l.len() <= 64));
        assert_eq!(pem_decode("CERTIFICATE", &text).unwrap(), blobs.to_vec());
        assert!(pem_decode("CERTIFICATE", "-----BEGIN CERTIFICATE-----\nAAAA").is_err());
    }
}
