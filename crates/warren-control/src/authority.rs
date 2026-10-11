//! The control plane's keys: the deployment's certificate authorities and
//! signing keys, sealed at rest under the key-encryption key (docs/design.md
//! section 12, docs/protocol.md section 10).
//!
//! The hierarchy is a root CA and two issuing CAs under it, the client CA
//! (user+device certificates) and the infrastructure CA (control plane,
//! relays, connectors), so a certificate from one can never stand in for the
//! other. Bundles, posture statements and clientless session assertions are
//! each signed with their own key.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use warren_core::base64::pem;
use warren_core::cert::{self, CertSpec};
use warren_core::clock;
use warren_core::der;
use warren_core::identity::{self, NodeRole, WarrenIdentity, WarrenUri};
use warren_core::jose::Jwk;
use warren_core::keys::{SigningKey, hex, random_bytes};
use warren_core::params;
use warren_core::pki::{self, TrustBundle, oid};
use zeroize::Zeroizing;

use crate::Error;
use crate::store::Store;

/// The deployment key-encryption key. CA and signing keys are stored only
/// sealed under it (AES-256-GCM, with the key's role as associated data, so
/// a sealed key cannot be swapped into another role).
pub struct Kek(RandomizedNonceKey);

impl Kek {
    /// Loads the key from `path`, creating it (mode 0600) if the file does
    /// not exist. The file holds 32 random bytes as base64.
    pub fn load_or_create(path: &Path) -> Result<Kek, Error> {
        let io = |e: std::io::Error| Error::Config(format!("{}: {e}", path.display()));
        let text = match std::fs::read_to_string(path) {
            Ok(text) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(path)
                        && meta.permissions().mode() & 0o077 != 0
                    {
                        crate::log::warn(
                            "keys",
                            &format!(
                                "{} is readable by other users; restrict it to its owner (mode 0600)",
                                path.display()
                            ),
                        );
                    }
                }
                Zeroizing::new(text)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key: Zeroizing<[u8; 32]> =
                    Zeroizing::new(random_bytes().map_err(|e| Error::Internal(e.to_string()))?);
                let text = Zeroizing::new(STANDARD.encode(*key));
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).map_err(io)?;
                }
                let mut file = create_private(path).map_err(io)?;
                file.write_all(text.as_bytes()).map_err(io)?;
                file.sync_all().map_err(io)?;
                text
            }
            Err(e) => return Err(io(e)),
        };
        let bytes = Zeroizing::new(
            STANDARD
                .decode(text.trim())
                .map_err(|_| Error::Config(format!("{}: not base64", path.display())))?,
        );
        if bytes.len() != 32 {
            return Err(Error::Config(format!(
                "{}: the key-encryption key must be 32 bytes",
                path.display()
            )));
        }
        RandomizedNonceKey::new(&AES_256_GCM, &bytes)
            .map(Kek)
            .map_err(|_| Error::Internal("cannot load the key-encryption key".into()))
    }

    fn aad(name: &str) -> String {
        format!("warren-sealed-key:{name}")
    }

    /// Seals `plaintext` for the key role `name`: base64 of nonce, then
    /// ciphertext and tag.
    pub fn seal(&self, name: &str, plaintext: &[u8]) -> Result<String, Error> {
        let mut buf = plaintext.to_vec();
        let nonce = self
            .0
            .seal_in_place_append_tag(Aad::from(Self::aad(name).as_bytes()), &mut buf)
            .map_err(|_| Error::Internal("sealing failed".into()))?;
        let mut out = nonce.as_ref().to_vec();
        out.extend_from_slice(&buf);
        Ok(STANDARD.encode(out))
    }

    /// Opens a sealed value for the key role `name`.
    pub fn open(&self, name: &str, sealed: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let bad = || {
            Error::Config(format!(
                "cannot unseal {name}: the key-encryption key does not match this database"
            ))
        };
        let mut data = Zeroizing::new(STANDARD.decode(sealed).map_err(|_| bad())?);
        if data.len() < 12 + 16 {
            return Err(bad());
        }
        let nonce = Nonce::try_assume_unique_for_key(&data[..12]).map_err(|_| bad())?;
        let mut body = Zeroizing::new(data[12..].to_vec());
        data.fill(0);
        let plain = self
            .0
            .open_in_place(nonce, Aad::from(Self::aad(name).as_bytes()), &mut body)
            .map_err(|_| bad())?;
        Ok(Zeroizing::new(plain.to_vec()))
    }
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// A certificate authority: its key and certificate.
pub struct Ca {
    name: String,
    key: SigningKey,
    /// The CA certificate, DER.
    pub der: Vec<u8>,
    /// Its subject Name, DER: the issuer name of everything it signs.
    subject: Vec<u8>,
    /// Its key identifier, for the authority key identifier of what it
    /// signs.
    key_id: Vec<u8>,
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
}

impl Ca {
    /// A CA from its key and certificate, which must certify that key.
    fn new(name: &str, key: SigningKey, der: Vec<u8>) -> Result<Ca, Error> {
        let bad = |e: &dyn std::fmt::Display| Error::Internal(format!("{name} certificate: {e}"));
        let parsed = pki::parse_cert(&der).map_err(|e| bad(&e))?;
        let spki = cert::p256_spki(key.public_key().point());
        if parsed.spki != spki {
            return Err(Error::Internal(format!(
                "{name} certificate does not match its key"
            )));
        }
        let subject = der::tlv(der::tag::SEQUENCE, parsed.subject);
        let (not_before, not_after) = (parsed.not_before, parsed.not_after);
        Ok(Ca {
            name: name.into(),
            key_id: cert::spki_key_id(&spki).map_err(|e| bad(&e))?,
            key,
            subject,
            not_before,
            not_after,
            der,
        })
    }
}

/// An issued leaf certificate.
#[derive(Debug, Clone)]
pub struct Issued {
    /// The certificate, DER.
    pub der: Vec<u8>,
    /// The serial, lowercase hex.
    pub serial: String,
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// When to renew: half-way from issuance to `not_after`.
    pub renew_at: i64,
}

/// Every key the control plane holds.
pub struct Authority {
    trust_domain: String,
    /// The root CA.
    pub root: Ca,
    /// The client CA.
    pub client: Ca,
    /// The infrastructure CA.
    pub infra: Ca,
    /// The trust bundle of the three, for verifying what they issued.
    pub bundle: TrustBundle,
    /// Signs policy bundles.
    pub policy_key: SigningKey,
    /// Signs posture statements.
    pub posture_key: SigningKey,
    /// Signs clientless session assertions.
    pub assertion_key: SigningKey,
}

const ROOT_LIFETIME: i64 = 10 * 365 * 86_400;
const ISSUING_LIFETIME: i64 = 5 * 365 * 86_400;
/// How long before a CA expires the control plane starts warning about it.
const CA_EXPIRY_WARNING: i64 = 90 * 86_400;

/// A leaf in the shared profile with these extended key usages and names.
fn leaf_spec(
    not_before: i64,
    not_after: i64,
    eku: &[&[u8]],
    uris: Vec<String>,
    dns_names: Vec<String>,
) -> Result<CertSpec, Error> {
    let mut spec = CertSpec::leaf_valid(not_before, not_after)
        .map_err(|_| Error::Internal("the CSPRNG failed".into()))?;
    spec.eku = eku.iter().map(|o| o.to_vec()).collect();
    spec.san_uris = uris;
    spec.san_dns = dns_names;
    Ok(spec)
}

impl Authority {
    /// Loads every key from the store, creating the hierarchy and keys on
    /// first start.
    pub async fn load_or_create(
        store: &Store,
        kek: &Kek,
        trust_domain: &str,
    ) -> Result<Authority, Error> {
        let bound = store.init_setting("trust_domain", trust_domain).await?;
        if bound != trust_domain {
            return Err(Error::Config(format!(
                "this database belongs to trust domain {bound}, not {trust_domain}"
            )));
        }
        let root = load_ca(
            store,
            kek,
            "root-ca",
            &format!("warren root CA {trust_domain}"),
            None,
        )
        .await?;
        let client = load_ca(
            store,
            kek,
            "client-ca",
            &format!("warren client CA {trust_domain}"),
            Some(&root),
        )
        .await?;
        let infra = load_ca(
            store,
            kek,
            "infrastructure-ca",
            &format!("warren infrastructure CA {trust_domain}"),
            Some(&root),
        )
        .await?;
        let bundle = TrustBundle::new(
            trust_domain,
            CertificateDer::from(root.der.clone()),
            vec![CertificateDer::from(client.der.clone())],
            vec![CertificateDer::from(infra.der.clone())],
        )
        .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(Authority {
            trust_domain: trust_domain.to_owned(),
            root,
            client,
            infra,
            bundle,
            policy_key: load_key(store, kek, "policy-signing").await?,
            posture_key: load_key(store, kek, "posture-signing").await?,
            assertion_key: load_key(store, kek, "session-assertion-signing").await?,
        })
        .inspect(Authority::warn_if_expiring)
    }

    /// Logs a warning for each CA that expires within `CA_EXPIRY_WARNING`.
    /// Nothing is issued past a CA's own expiry, so once one expires the
    /// certificates it issues stop.
    pub fn warn_if_expiring(&self) {
        let now = clock::now_secs();
        for ca in [&self.root, &self.client, &self.infra] {
            if ca.not_after - now < CA_EXPIRY_WARNING {
                crate::log::warn(
                    "keys",
                    &format!(
                        "the {} expires at {}; certificates it issues cannot outlive it, so replace it before then",
                        ca.name,
                        clock::rfc3339(ca.not_after)
                    ),
                );
            }
        }
    }

    /// The trust domain.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The deployment trust bundle, PEM: root, client CA, infrastructure CA.
    pub fn trust_bundle(&self) -> String {
        [&self.root, &self.client, &self.infra]
            .iter()
            .map(|ca| pem("CERTIFICATE", &ca.der))
            .collect()
    }

    /// The policy-signing key as a JWK, for nodes to verify bundles with.
    pub fn policy_jwk(&self) -> Jwk {
        Jwk::from_key(self.policy_key.public_key())
    }

    /// Issues a user+device certificate (docs/protocol.md section 10.2)
    /// for the key in `spki`, valid from `not_before` to `not_after`, Unix
    /// seconds.
    pub fn issue_client(
        &self,
        spki: &[u8],
        user_id: &str,
        device_id: &str,
        identity: &WarrenIdentity,
        not_before: i64,
        not_after: i64,
    ) -> Result<Issued, Error> {
        let td = self.trust_domain.clone();
        let mut spec = leaf_spec(
            not_before,
            not_after,
            &[oid::CLIENT_AUTH],
            vec![
                WarrenUri::User {
                    td: td.clone(),
                    id: user_id.into(),
                }
                .to_string(),
                WarrenUri::Device {
                    td,
                    id: device_id.into(),
                }
                .to_string(),
            ],
            Vec::new(),
        )?;
        spec.extra = vec![(identity::identity_extension_oid(), false, identity.to_der())];
        issue(&spec, spki, &self.client)
    }

    /// Issues an infrastructure certificate (docs/protocol.md section 10.3)
    /// for the key in `spki`. Connectors and relays get both server and
    /// client authentication; they listen on one link and dial out on
    /// another.
    pub fn issue_node(
        &self,
        spki: &[u8],
        role: &NodeRole,
        id: &str,
        dns_names: &[String],
        lifetime_secs: i64,
        skew_secs: i64,
    ) -> Result<Issued, Error> {
        let now = clock::now_secs();
        let uri = WarrenUri::Node {
            td: self.trust_domain.clone(),
            role: role.clone(),
            id: id.into(),
        };
        let spec = leaf_spec(
            now - skew_secs,
            now + lifetime_secs,
            &[oid::SERVER_AUTH, oid::CLIENT_AUTH],
            vec![uri.to_string()],
            dns_names.to_vec(),
        )?;
        issue(&spec, spki, &self.infra)
    }

    /// A certificate chain as PEM: the leaf, then its issuing CA.
    pub fn chain_pem(&self, leaf: &[u8], issuer: &Ca) -> String {
        pem("CERTIFICATE", leaf) + &pem("CERTIFICATE", &issuer.der)
    }
}

/// Signs a leaf with `ca`, refusing one that would be valid outside the
/// CA's own validity, which verifiers anchored at the root would reject.
fn issue(spec: &CertSpec, spki: &[u8], ca: &Ca) -> Result<Issued, Error> {
    let now = clock::now_secs();
    if now < ca.not_before || spec.not_after > ca.not_after {
        return Err(Error::Unavailable(format!(
            "the {} is valid from {} until {}, so it cannot issue a certificate valid until {}",
            ca.name,
            clock::rfc3339(ca.not_before),
            clock::rfc3339(ca.not_after),
            clock::rfc3339(spec.not_after)
        )));
    }
    if spec.not_after <= spec.not_before {
        return Err(Error::Internal(
            "certificate validity ends before it starts".into(),
        ));
    }
    let der = cert::issue(spec, spki, &ca.subject, &ca.key_id, |tbs| {
        ca.key.sign_der(tbs)
    })
    .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(Issued {
        serial: hex(&spec.serial),
        not_before: spec.not_before,
        not_after: spec.not_after,
        renew_at: params::renew_at(clock::now_secs(), spec.not_after),
        der,
    })
}

async fn load_key(store: &Store, kek: &Kek, name: &str) -> Result<SigningKey, Error> {
    if let Some((sealed, _)) = store.signing_key(name).await? {
        let pkcs8 = kek.open(name, &sealed)?;
        return SigningKey::from_pkcs8(&pkcs8).map_err(|e| Error::Internal(e.to_string()));
    }
    let key = SigningKey::generate().map_err(|e| Error::Internal(e.to_string()))?;
    let pkcs8 = key.to_pkcs8().map_err(|e| Error::Internal(e.to_string()))?;
    store
        .insert_signing_key(name, &kek.seal(name, &pkcs8)?, None)
        .await?;
    Ok(key)
}

async fn load_ca(
    store: &Store,
    kek: &Kek,
    name: &str,
    cn: &str,
    parent: Option<&Ca>,
) -> Result<Ca, Error> {
    if let Some((sealed, Some(pem))) = store.signing_key(name).await? {
        let pkcs8 = kek.open(name, &sealed)?;
        let key = SigningKey::from_pkcs8(&pkcs8).map_err(|e| Error::Internal(e.to_string()))?;
        let der = CertificateDer::pem_slice_iter(pem.as_bytes())
            .last()
            .and_then(Result::ok)
            .ok_or_else(|| Error::Internal(format!("{name} certificate is unreadable")))?;
        return Ca::new(name, key, der.to_vec());
    }
    let lifetime = match parent {
        None => ROOT_LIFETIME,
        Some(_) => ISSUING_LIFETIME,
    };
    let (ca, pkcs8) = create_ca(name, cn, parent, lifetime)?;
    store
        .insert_signing_key(
            name,
            &kek.seal(name, &pkcs8)?,
            Some(&pem("CERTIFICATE", &ca.der)),
        )
        .await?;
    Ok(ca)
}

/// A new CA valid for `lifetime` seconds, signed by `parent` or by itself,
/// with its key as PKCS#8.
fn create_ca(
    name: &str,
    cn: &str,
    parent: Option<&Ca>,
    lifetime: i64,
) -> Result<(Ca, Zeroizing<Vec<u8>>), Error> {
    let key = SigningKey::generate().map_err(|e| Error::Internal(e.to_string()))?;
    let now = clock::now_secs();
    let spki = cert::p256_spki(key.public_key().point());
    let spec = CertSpec {
        serial: cert::random_serial().map_err(|_| Error::Internal("the CSPRNG failed".into()))?,
        subject_cn: Some(cn.into()),
        not_before: now - 3600,
        not_after: now + lifetime,
        ca: Some(true),
        path_len: Some(if parent.is_none() { 1 } else { 0 }),
        key_usage: Some((0x04, true)),
        eku: Vec::new(),
        san_uris: Vec::new(),
        san_dns: Vec::new(),
        san_critical: false,
        key_ids: true,
        extra: Vec::new(),
    };
    let own_id = cert::spki_key_id(&spki).map_err(|e| Error::Internal(e.to_string()))?;
    let der = match parent {
        None => cert::issue(&spec, &spki, &cert::name(Some(cn)), &own_id, |tbs| {
            key.sign_der(tbs)
        }),
        Some(parent) => cert::issue(&spec, &spki, &parent.subject, &parent.key_id, |tbs| {
            parent.key.sign_der(tbs)
        }),
    }
    .map_err(|e| Error::Internal(e.to_string()))?;
    let pkcs8 = key.to_pkcs8().map_err(|e| Error::Internal(e.to_string()))?;
    Ok((Ca::new(name, key, der)?, pkcs8))
}

/// Device tunnel addresses for allocation index `index`: the index-th
/// address of each pool, skipping the network address.
pub fn tunnel_addresses(
    pool_v4: &warren_policy::names::Cidr,
    pool_v6: &warren_policy::names::Cidr,
    index: i64,
) -> Result<(Ipv4Addr, Ipv6Addr), Error> {
    let exhausted = || Error::Unavailable("the device address pool is exhausted".into());
    let n = u128::try_from(index).map_err(|_| exhausted())?;
    let v4 = match pool_v4.nth(n).ok_or_else(exhausted)? {
        std::net::IpAddr::V4(a) => a,
        _ => return Err(exhausted()),
    };
    // Keep the broadcast address of the IPv4 pool free as well.
    if pool_v4.nth(n + 1).is_none() {
        return Err(exhausted());
    }
    let v6 = match pool_v6.nth(n).ok_or_else(exhausted)? {
        std::net::IpAddr::V6(a) => a,
        _ => return Err(exhausted()),
    };
    Ok((v4, v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "warren-authority-{name}-{}",
            warren_core::keys::hex(&random_bytes::<6>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sealing_binds_the_role() {
        let dir = temp_dir("kek");
        let kek = Kek::load_or_create(&dir.join("kek")).unwrap();
        let sealed = kek.seal("root-ca", b"secret").unwrap();
        assert_eq!(&*kek.open("root-ca", &sealed).unwrap(), b"secret");
        assert!(kek.open("client-ca", &sealed).is_err());
        let again = Kek::load_or_create(&dir.join("kek")).unwrap();
        assert_eq!(&*again.open("root-ca", &sealed).unwrap(), b"secret");
        let other = Kek::load_or_create(&dir.join("kek2")).unwrap();
        assert!(other.open("root-ca", &sealed).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("kek"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn nothing_outlives_its_issuing_ca() {
        let root = create_ca("root-ca", "test root", None, 86_400).unwrap().0;
        let infra = create_ca("infrastructure-ca", "test infra", Some(&root), 3_600)
            .unwrap()
            .0;
        let key = SigningKey::generate().unwrap();
        let spki = cert::p256_spki(key.public_key().point());
        let spec = |not_after: i64| {
            leaf_spec(
                clock::now_secs() - 60,
                not_after,
                &[oid::SERVER_AUTH],
                vec!["warren://example.test/relay/n-1".into()],
                Vec::new(),
            )
            .unwrap()
        };
        let within = clock::now_secs() + 1_800;
        let issued = issue(&spec(within), &spki, &infra).unwrap();
        assert_eq!(issued.not_after, within);
        let past = infra.not_after + 1;
        let refused = issue(&spec(past), &spki, &infra).unwrap_err();
        assert!(
            matches!(&refused, Error::Unavailable(m) if m.contains("infrastructure-ca")),
            "{refused:?}"
        );
    }

    #[test]
    fn issued_certificates_chain_to_the_root() {
        let root = create_ca("root-ca", "test root", None, 86_400).unwrap().0;
        let client = create_ca("client-ca", "test client", Some(&root), 3_600)
            .unwrap()
            .0;
        let infra = create_ca("infrastructure-ca", "test infra", Some(&root), 3_600)
            .unwrap()
            .0;
        let bundle = TrustBundle::new(
            "example.test",
            CertificateDer::from(root.der.clone()),
            vec![CertificateDer::from(client.der.clone())],
            vec![CertificateDer::from(infra.der.clone())],
        )
        .unwrap();
        let key = SigningKey::generate().unwrap();
        let spki = cert::p256_spki(key.public_key().point());
        let now = clock::now_secs();
        let spec = leaf_spec(
            now - 60,
            now + 600,
            &[oid::SERVER_AUTH, oid::CLIENT_AUTH],
            vec!["warren://example.test/relay/n-1".into()],
            vec!["relay.example.test".into()],
        )
        .unwrap();
        let leaf = CertificateDer::from(issue(&spec, &spki, &infra).unwrap().der);
        let at = pki::unix_time(std::time::SystemTime::now());
        bundle
            .verify_chain(&leaf, pki::Issuer::Infrastructure, true, at)
            .unwrap();
        assert!(
            bundle
                .verify_chain(&leaf, pki::Issuer::Client, false, at)
                .is_err()
        );
        let id = pki::check_infra_profile(&leaf, "example.test").unwrap();
        assert_eq!((id.role, id.id.as_str()), (NodeRole::Relay, "n-1"));
    }

    #[test]
    fn address_allocation() {
        let v4 = warren_policy::names::Cidr::parse("100.96.0.0/30").unwrap();
        let v6 = warren_policy::names::Cidr::parse("fd77::/64").unwrap();
        let (a, b) = tunnel_addresses(&v4, &v6, 1).unwrap();
        assert_eq!(a.to_string(), "100.96.0.1");
        assert_eq!(b.to_string(), "fd77::1");
        assert!(tunnel_addresses(&v4, &v6, 2).is_ok());
        assert!(tunnel_addresses(&v4, &v6, 3).is_err());
    }
}
