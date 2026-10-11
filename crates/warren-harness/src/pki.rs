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
use warren_core::cert;
pub use warren_core::cert::{CertSpec, name};
use warren_core::identity::{self, WarrenIdentity};
use warren_core::pki::{TrustBundle, oid};
use warren_core::tls::Credentials;

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
        cert::p256_spki(self.pair.public_key().as_ref())
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

    /// The key identifier: the leftmost 160 bits of the SHA-256 of the
    /// public key.
    pub fn key_id(&self) -> Vec<u8> {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, self.pair.public_key().as_ref())
            .as_ref()[..20]
            .to_vec()
    }
}

/// Seconds since the Unix epoch now.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
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
    let own = Issuer {
        key: subject_key,
        name: name(spec.subject_cn.as_deref()),
    };
    issue_for(spec, &subject_key.spki(), issuer.unwrap_or(&own))
}

/// Builds and signs a certificate for a public key (from a certificate
/// request, say) whose private key this process never sees.
pub fn issue_for(spec: &CertSpec, subject_spki: &[u8], issuer: &Issuer<'_>) -> Vec<u8> {
    cert::issue(
        spec,
        subject_spki,
        &issuer.name,
        &issuer.key.key_id(),
        |tbs| Ok::<_, std::convert::Infallible>(issuer.key.sign(tbs)),
    )
    .unwrap_or_else(|e| match e {})
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

    /// A control-plane certificate listening on `dns` names; its chain
    /// includes the root, so a node can pin it while joining.
    pub fn control_plane(&self, id: &str, dns: &[&str]) -> Credentials {
        let uri = format!("warren://{}/control-plane/{id}", self.trust_domain);
        let mut creds = self.issue_infra(&self.infra_spec(&uri, dns));
        creds
            .chain
            .push(CertificateDer::from(self.root.cert.clone()));
        creds
    }

    /// Issues an infrastructure certificate for a public key.
    pub fn issue_infra_for(&self, spec: &CertSpec, spki: &[u8]) -> Vec<CertificateDer<'static>> {
        let leaf = issue_for(spec, spki, &self.infra_ca.issuer());
        vec![
            CertificateDer::from(leaf),
            CertificateDer::from(self.infra_ca.cert.clone()),
        ]
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
    warren_core::base64::pem(label, der_bytes)
}
