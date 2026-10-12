//! The device key (docs/design.md section 7.2): the P-256 key that binds
//! sign-in sessions and certificates to this device.
//!
//! On a Mac with a Secure Enclave the key is generated in the enclave and
//! never leaves it (G3); the client keeps only the enclave-wrapped blob,
//! which no other device can use. Without an enclave (an older Mac or a
//! virtual machine) the key is a software key: its PKCS#8 form is sealed
//! with AES-256-GCM in a file only the user can read, under a key kept in
//! the user's login keychain, so neither the file nor the keychain item is
//! enough alone. Elsewhere (Linux, for tests) the key is a PKCS#8 file only
//! the user can read. Enrollment reports which kind it is, and a software
//! key is recorded as such: it does not meet G3, since malware running as
//! the user can read it (docs/threat-model.md, T10).

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use rustls::SignatureScheme;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::sign::{Signer, SigningKey as TlsSigningKey};
use serde::{Deserialize, Serialize};
use warren_core::cert;
use warren_core::jose::{self, Header, Jwk};
use warren_core::keys::{PublicKey, SigningKey};

use crate::state::{self, write_private};

/// Where a device key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyStorage {
    /// Generated in and held by the Secure Enclave.
    SecureEnclave,
    /// A software key sealed in a file, under a key in the login keychain.
    Keychain,
    /// A software key in a file only the user can read.
    File,
}

impl KeyStorage {
    /// The `key_storage` value enrollment reports: `secure-enclave`, or
    /// `software` for every software key.
    pub fn wire(self) -> &'static str {
        match self {
            KeyStorage::SecureEnclave => "secure-enclave",
            KeyStorage::Keychain | KeyStorage::File => "software",
        }
    }

    /// A short description for people.
    pub fn describe(self) -> &'static str {
        match self {
            KeyStorage::SecureEnclave => "Secure Enclave (hardware-bound)",
            KeyStorage::Keychain => "software key, sealed under the login keychain",
            KeyStorage::File => "software key in a file",
        }
    }
}

/// What the client records about its key next to the key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyRecord {
    storage: KeyStorage,
    /// The public key, as a base64url uncompressed point.
    public_key: String,
    /// The login keychain item holding the sealing key, for keychain keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keychain_account: Option<String>,
}

const RECORD: &str = "device-key.json";
const ENCLAVE_BLOB: &str = "device-key.enclave";
const SEALED: &str = "device-key.sealed";
const PKCS8: &str = "device-key.pk8";
/// The keychain service the sealing keys are stored under.
pub const KEYCHAIN_SERVICE: &str = "dev.warren.device-key";
/// What a sealed software key is bound to (AES-GCM associated data).
#[cfg(target_os = "macos")]
const SEAL_LABEL: &[u8] = b"warren-device-key-v1";

enum Inner {
    #[cfg(target_os = "macos")]
    Enclave(crate::apple::SecureEnclaveKey),
    Software(SigningKey),
}

/// The device key.
pub struct DeviceKey {
    inner: Inner,
    storage: KeyStorage,
    public: PublicKey,
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({:?}, {:?})", self.storage, self.public)
    }
}

impl DeviceKey {
    /// Creates a key in `dir`: in the Secure Enclave when there is one,
    /// unless `want` names another storage, which then must work.
    /// Returns the key and, when the enclave was wanted but unavailable,
    /// why it could not be used.
    pub fn create(
        dir: &Path,
        want: Option<KeyStorage>,
    ) -> Result<(DeviceKey, Option<String>), String> {
        let mut fallback = None;
        let storage = match want {
            Some(s) => s,
            None => match create_enclave(dir) {
                Ok(key) => return Ok((key, None)),
                Err(e) => {
                    fallback = Some(e);
                    default_software()
                }
            },
        };
        let key = match storage {
            KeyStorage::SecureEnclave => create_enclave(dir)?,
            KeyStorage::Keychain => create_keychain(dir)?,
            KeyStorage::File => create_file(dir)?,
        };
        Ok((key, fallback))
    }

    /// Loads the key recorded in `dir`.
    pub fn load(dir: &Path) -> Result<DeviceKey, String> {
        let record: KeyRecord = state::read_json(&dir.join(RECORD))?
            .ok_or_else(|| "no device key yet; sign in first with `warren login`".to_owned())?;
        let key = match record.storage {
            KeyStorage::SecureEnclave => load_enclave(dir)?,
            KeyStorage::Keychain => load_keychain(dir, &record)?,
            KeyStorage::File => load_file(dir)?,
        };
        if jose::b64url(key.public.point()) != record.public_key {
            return Err(format!(
                "the device key in {} does not match its record",
                dir.display()
            ));
        }
        Ok(key)
    }

    /// Whether `dir` holds a device key.
    pub fn exists(dir: &Path) -> bool {
        dir.join(RECORD).exists()
    }

    /// Deletes the key in `dir` and its keychain item.
    pub fn delete(dir: &Path) -> Result<(), String> {
        let record: Option<KeyRecord> = state::read_json(&dir.join(RECORD)).ok().flatten();
        #[cfg(target_os = "macos")]
        if let Some(account) = record.as_ref().and_then(|r| r.keychain_account.as_deref()) {
            crate::apple::keychain::delete(KEYCHAIN_SERVICE, account)?;
        }
        #[cfg(not(target_os = "macos"))]
        let _ = record;
        for f in [RECORD, ENCLAVE_BLOB, SEALED, PKCS8] {
            match std::fs::remove_file(dir.join(f)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", dir.join(f).display())),
            }
        }
        Ok(())
    }

    /// Where the key lives.
    pub fn storage(&self) -> KeyStorage {
        self.storage
    }

    /// The public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The SubjectPublicKeyInfo, DER.
    pub fn spki(&self) -> Vec<u8> {
        cert::p256_spki(self.public.point())
    }

    /// Signs with ECDSA P-256 and SHA-256; the signature is DER.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        match &self.inner {
            #[cfg(target_os = "macos")]
            Inner::Enclave(k) => k.sign_der(message),
            Inner::Software(k) => k.sign_der(message).map_err(|e| e.to_string()),
        }
    }

    /// Signs with ECDSA P-256 and SHA-256; the signature is `r || s`.
    pub fn sign_fixed(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        match &self.inner {
            #[cfg(target_os = "macos")]
            Inner::Enclave(_) => {
                let der = self.sign_der(message)?;
                Ok(warren_core::keys::der_signature_to_fixed(&der)
                    .map_err(|e| e.to_string())?
                    .to_vec())
            }
            Inner::Software(k) => k.sign_fixed(message).map_err(|e| e.to_string()),
        }
    }

    /// A certificate request (PKCS#10) for this key, signed by it.
    pub fn certificate_request(&self) -> Result<Vec<u8>, String> {
        warren_core::join::certificate_request(&self.spki(), |info| self.sign_der(info))
    }

    /// A JWS of `typ` over `payload`, signed by this key with the key
    /// itself in the header, proving possession to a verifier that does
    /// not know it yet.
    pub fn jws(&self, typ: &str, payload: &[u8]) -> Result<String, String> {
        let header = Header {
            alg: "ES256".into(),
            typ: typ.into(),
            kid: None,
            jwk: Some(Jwk::from_key(&self.public)),
            crit: None,
        };
        jose::sign_with(&header, payload, |input| self.sign_fixed(input)).map_err(|e| e.to_string())
    }

    /// The key as a TLS signer, for client authentication on every link.
    pub fn tls_signer(self: &Arc<Self>) -> Arc<dyn TlsSigningKey> {
        Arc::new(TlsKey {
            key: self.clone(),
            spki: self.spki(),
        })
    }
}

#[cfg(target_os = "macos")]
fn default_software() -> KeyStorage {
    KeyStorage::Keychain
}

#[cfg(not(target_os = "macos"))]
fn default_software() -> KeyStorage {
    KeyStorage::File
}

fn record(dir: &Path, key: &DeviceKey, account: Option<String>) -> Result<(), String> {
    let r = KeyRecord {
        storage: key.storage,
        public_key: jose::b64url(key.public.point()),
        keychain_account: account,
    };
    let text = serde_json::to_vec_pretty(&r).map_err(|e| e.to_string())?;
    write_private(&dir.join(RECORD), &text)
}

#[cfg(target_os = "macos")]
fn create_enclave(dir: &Path) -> Result<DeviceKey, String> {
    let (key, blob) = crate::apple::SecureEnclaveKey::generate()
        .map_err(|e| format!("the Secure Enclave is not available: {e}"))?;
    let public = PublicKey::from_point(key.public_point()).map_err(|e| e.to_string())?;
    write_private(&dir.join(ENCLAVE_BLOB), &blob)?;
    let key = DeviceKey {
        inner: Inner::Enclave(key),
        storage: KeyStorage::SecureEnclave,
        public,
    };
    record(dir, &key, None)?;
    Ok(key)
}

#[cfg(not(target_os = "macos"))]
fn create_enclave(_: &Path) -> Result<DeviceKey, String> {
    Err("there is no Secure Enclave on this platform".into())
}

#[cfg(target_os = "macos")]
fn load_enclave(dir: &Path) -> Result<DeviceKey, String> {
    let path = dir.join(ENCLAVE_BLOB);
    let blob = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = crate::apple::SecureEnclaveKey::load(&blob)
        .map_err(|e| format!("the Secure Enclave refused this device's key: {e}"))?;
    let public = PublicKey::from_point(key.public_point()).map_err(|e| e.to_string())?;
    Ok(DeviceKey {
        inner: Inner::Enclave(key),
        storage: KeyStorage::SecureEnclave,
        public,
    })
}

#[cfg(not(target_os = "macos"))]
fn load_enclave(_: &Path) -> Result<DeviceKey, String> {
    Err("this key lives in a Secure Enclave, which this platform does not have".into())
}

fn software(key: SigningKey, storage: KeyStorage) -> DeviceKey {
    DeviceKey {
        public: key.public_key().clone(),
        inner: Inner::Software(key),
        storage,
    }
}

#[cfg(target_os = "macos")]
fn create_keychain(dir: &Path) -> Result<DeviceKey, String> {
    use warren_core::keys;
    let key = SigningKey::generate().map_err(|e| e.to_string())?;
    let secret = zeroize::Zeroizing::new(keys::random_bytes::<32>().map_err(|e| e.to_string())?);
    let sealed = keys::SealingKey::new(&secret)
        .and_then(|s| s.seal(SEAL_LABEL, &key.to_pkcs8()?))
        .map_err(|e| e.to_string())?;
    let account = keys::hex(&keys::random_bytes::<16>().map_err(|e| e.to_string())?);
    crate::apple::keychain::set(
        KEYCHAIN_SERVICE,
        &account,
        "warren device key (sealing key)",
        &secret[..],
    )?;
    write_private(&dir.join(SEALED), &sealed)?;
    let key = software(key, KeyStorage::Keychain);
    record(dir, &key, Some(account))?;
    Ok(key)
}

#[cfg(not(target_os = "macos"))]
fn create_keychain(_: &Path) -> Result<DeviceKey, String> {
    Err("the login keychain exists only on macOS".into())
}

#[cfg(target_os = "macos")]
fn load_keychain(dir: &Path, record: &KeyRecord) -> Result<DeviceKey, String> {
    use warren_core::keys;
    let account = record
        .keychain_account
        .as_deref()
        .ok_or("the device key record names no keychain item")?;
    let secret = zeroize::Zeroizing::new(
        crate::apple::keychain::get(KEYCHAIN_SERVICE, account)?
            .ok_or("the device key's sealing key is missing from the login keychain")?,
    );
    let secret: &[u8; 32] = secret[..]
        .try_into()
        .map_err(|_| "the sealing key in the login keychain is malformed")?;
    let path = dir.join(SEALED);
    let sealed = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pkcs8 = keys::SealingKey::new(secret)
        .and_then(|s| s.open(SEAL_LABEL, &sealed))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let key = SigningKey::from_pkcs8(&pkcs8).map_err(|e| e.to_string())?;
    Ok(software(key, KeyStorage::Keychain))
}

#[cfg(not(target_os = "macos"))]
fn load_keychain(_: &Path, _: &KeyRecord) -> Result<DeviceKey, String> {
    Err("this key is sealed under the macOS login keychain".into())
}

fn create_file(dir: &Path) -> Result<DeviceKey, String> {
    let key = SigningKey::generate().map_err(|e| e.to_string())?;
    write_private(
        &dir.join(PKCS8),
        &key.to_pkcs8().map_err(|e| e.to_string())?,
    )?;
    let key = software(key, KeyStorage::File);
    record(dir, &key, None)?;
    Ok(key)
}

fn load_file(dir: &Path) -> Result<DeviceKey, String> {
    let path = dir.join(PKCS8);
    state::check_private(&path)?;
    let pkcs8 = zeroize::Zeroizing::new(
        std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?,
    );
    let key = SigningKey::from_pkcs8(&pkcs8).map_err(|e| e.to_string())?;
    Ok(software(key, KeyStorage::File))
}

/// The device key as rustls sees it.
#[derive(Debug)]
struct TlsKey {
    key: Arc<DeviceKey>,
    spki: Vec<u8>,
}

impl TlsSigningKey for TlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(TlsSign(self.key.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct TlsSign(Arc<DeviceKey>);

impl Signer for TlsSign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.sign_der(message).map_err(rustls::Error::General)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warren_core::keys;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "warren-device-{name}-{}",
            keys::hex(&keys::random_bytes::<6>().unwrap())
        ));
        state::create_private_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn file_keys_round_trip_and_sign() {
        let dir = temp("file");
        let (key, fallback) = DeviceKey::create(&dir, Some(KeyStorage::File)).unwrap();
        assert!(fallback.is_none());
        assert_eq!(key.storage().wire(), "software");
        let again = DeviceKey::load(&dir).unwrap();
        assert_eq!(key.public_key(), again.public_key());
        let sig = again.sign_der(b"msg").unwrap();
        key.public_key().verify_der(b"msg", &sig).unwrap();
        let fixed = again.sign_fixed(b"msg").unwrap();
        key.public_key().verify_fixed(b"msg", &fixed).unwrap();
        let csr = key.certificate_request().unwrap();
        assert_eq!(
            warren_core::join::verify_certificate_request(&csr).unwrap(),
            key.spki()
        );
        let jws = key.jws("test+jws", b"{}").unwrap();
        let (k, payload) = jose::Unverified::parse(&jws, "test+jws")
            .unwrap()
            .verify_embedded()
            .unwrap();
        assert_eq!(&k, key.public_key());
        assert_eq!(payload, b"{}");
        DeviceKey::delete(&dir).unwrap();
        assert!(!DeviceKey::exists(&dir));
        assert!(DeviceKey::load(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn file_keys_others_can_read_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("perm");
        DeviceKey::create(&dir, Some(KeyStorage::File)).unwrap();
        std::fs::set_permissions(dir.join(PKCS8), std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = DeviceKey::load(&dir).unwrap_err();
        assert!(err.contains("other users"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_swapped_key_is_refused() {
        let dir = temp("swap");
        DeviceKey::create(&dir, Some(KeyStorage::File)).unwrap();
        let other = SigningKey::generate().unwrap();
        write_private(&dir.join(PKCS8), &other.to_pkcs8().unwrap()).unwrap();
        assert!(
            DeviceKey::load(&dir)
                .unwrap_err()
                .contains("does not match")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_names() {
        assert_eq!(KeyStorage::SecureEnclave.wire(), "secure-enclave");
        assert_eq!(KeyStorage::Keychain.wire(), "software");
    }

    /// Exercises the real Secure Enclave and login keychain; run on a Mac
    /// with `cargo test -p warren-client -- --ignored`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "uses this Mac's Secure Enclave and login keychain"]
    fn hardware_and_keychain_keys() {
        for storage in [KeyStorage::SecureEnclave, KeyStorage::Keychain] {
            let dir = temp("hw");
            let (key, _) = DeviceKey::create(&dir, Some(storage)).unwrap();
            let again = DeviceKey::load(&dir).unwrap();
            assert_eq!(again.storage(), storage);
            let sig = again.sign_der(b"msg").unwrap();
            key.public_key().verify_der(b"msg", &sig).unwrap();
            let fixed = again.sign_fixed(b"msg").unwrap();
            key.public_key().verify_fixed(b"msg", &fixed).unwrap();
            DeviceKey::delete(&dir).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
