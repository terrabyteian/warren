//! What the client keeps between runs, in one directory only the user can
//! read (mode 0700): the organization and its trust bundle, the sign-in
//! session, the enrolled device, the device key, the current certificate
//! and the last entitlements. There is nothing for the user to edit.
//!
//! The default directory is `~/Library/Application Support/warren` on
//! macOS and `$XDG_CONFIG_HOME/warren` (or `~/.config/warren`) elsewhere;
//! `WARREN_HOME` overrides it.

use std::path::{Path, PathBuf};

use rustls::pki_types::CertificateDer;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use warren_core::api::{Entitlements, UserInfo};
use warren_core::pki::{self, TrustBundle};

/// The client's state directory.
pub fn default_home() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("WARREN_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or("HOME is not set; set WARREN_HOME to choose where warren keeps its state")?;
    if cfg!(target_os = "macos") {
        return Ok(home.join("Library/Application Support/warren"));
    }
    Ok(std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map_or_else(|| home.join(".config"), PathBuf::from)
        .join("warren"))
}

/// Creates `dir` (and its parents) and makes it private to the user.
pub fn create_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Fails if other users could read `path`.
pub fn check_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{} is readable by other users; restrict it to its owner (chmod 600) or sign in again",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Writes `data` to `path` atomically, readable only by the user.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let fail = |e: std::io::Error| format!("{}: {e}", path.display());
    let name = path
        .file_name()
        .ok_or_else(|| format!("{}: not a file path", path.display()))?;
    let nonce = warren_core::keys::random_bytes::<6>().map_err(|e| e.to_string())?;
    let mut staging = std::ffi::OsString::from(".");
    staging.push(name);
    staging.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        warren_core::keys::hex(&nonce)
    ));
    let tmp = path.with_file_name(staging);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(fail)?;
    let written = file
        .write_all(data)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.map_err(fail)
}

/// Reads JSON from `path`; `None` if the file does not exist.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    write_private(path, &text)
}

/// The sign-in session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    /// The session ID.
    pub id: String,
    /// The bearer token for link D calls.
    pub token: String,
    /// When the session ends, Unix seconds.
    pub expires_at: i64,
    /// When the user authenticated at the IdP, Unix seconds (0: unknown).
    pub auth_time: i64,
    /// Whether that authentication used MFA.
    pub mfa: bool,
}

/// The enrolled device, as the control plane last described it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceState {
    /// The device ID.
    pub id: String,
    /// `pending`, `approved`, `disabled` or `revoked`.
    pub status: String,
    /// The IPv4 tunnel address.
    pub tunnel_v4: String,
    /// The IPv6 tunnel address.
    pub tunnel_v6: String,
    /// The enrollment trust class.
    pub trust_class: u8,
}

/// Everything sign-in established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The organization URL, `https://host[:port]`.
    pub org_url: String,
    /// The deployment's trust domain.
    pub trust_domain: String,
    /// The pinned root fingerprint (lowercase hex SHA-256), when sign-in
    /// verified the organization URL against one instead of the system's
    /// trust store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Discovery's API base, for sign-in and enrollment.
    pub signin_api_base: String,
    /// Where enrolled calls go, verified against the trust bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,
    /// The signed-in user.
    pub user: UserInfo,
    /// The session.
    pub session: SessionState,
    /// The enrolled device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceState>,
}

/// The current certificate's facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateTimes {
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// When to renew, Unix seconds.
    pub renew_at: i64,
}

/// The current user+device certificate.
#[derive(Debug, Clone)]
pub struct StoredCertificate {
    /// The chain, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// Its serial number, lowercase hex.
    pub serial: String,
    /// When it is valid and when to renew it.
    pub times: CertificateTimes,
}

#[derive(Serialize, Deserialize)]
struct CertificateRecord {
    serial: String,
    #[serde(flatten)]
    times: CertificateTimes,
}

const PROFILE: &str = "profile.json";
const TRUST: &str = "trust";
const CERT_PEM: &str = "certificate.pem";
const CERT_JSON: &str = "certificate.json";
const ENTITLEMENTS: &str = "entitlements.json";
/// The control socket a running `warren up` listens on.
pub const CONTROL_SOCKET: &str = "up.sock";

/// The state directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// The store in `dir`, which is created private to the user.
    pub fn open(dir: &Path) -> Result<Store, String> {
        create_private_dir(dir)?;
        Ok(Store {
            dir: dir.to_owned(),
        })
    }

    /// The store in `dir` if it exists, without creating anything.
    pub fn existing(dir: &Path) -> Option<Store> {
        dir.is_dir().then(|| Store {
            dir: dir.to_owned(),
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The control socket path.
    pub fn control_socket(&self) -> PathBuf {
        self.dir.join(CONTROL_SOCKET)
    }

    /// The profile, if signed in.
    pub fn profile(&self) -> Result<Option<Profile>, String> {
        let path = self.dir.join(PROFILE);
        if path.exists() {
            check_private(&path)?;
        }
        read_json(&path)
    }

    /// Saves the profile.
    pub fn save_profile(&self, p: &Profile) -> Result<(), String> {
        write_json(&self.dir.join(PROFILE), p)
    }

    /// The trust bundle for `trust_domain`.
    pub fn trust(&self, trust_domain: &str) -> Result<TrustBundle, String> {
        TrustBundle::load_dir(trust_domain, &self.dir.join(TRUST)).map_err(|e| e.to_string())
    }

    /// Saves the trust bundle.
    pub fn save_trust(&self, trust: &TrustBundle) -> Result<(), String> {
        let dir = self.dir.join(TRUST);
        create_private_dir(&dir)?;
        let pem = |certs: &[CertificateDer<'_>]| -> String {
            certs
                .iter()
                .map(|c| warren_core::base64::pem("CERTIFICATE", c))
                .collect()
        };
        write_private(
            &dir.join(pki::ROOT_CA_FILE),
            pem(std::slice::from_ref(&trust.root)).as_bytes(),
        )?;
        write_private(
            &dir.join(pki::CLIENT_CA_FILE),
            pem(&trust.client_cas).as_bytes(),
        )?;
        write_private(
            &dir.join(pki::INFRA_CA_FILE),
            pem(&trust.infra_cas).as_bytes(),
        )
    }

    /// The current certificate, if there is one.
    pub fn certificate(&self) -> Result<Option<StoredCertificate>, String> {
        let Some(record) = read_json::<CertificateRecord>(&self.dir.join(CERT_JSON))? else {
            return Ok(None);
        };
        let path = self.dir.join(CERT_PEM);
        if !path.exists() {
            return Ok(None);
        }
        let chain = pki::load_chain(&path).map_err(|e| e.to_string())?;
        Ok(Some(StoredCertificate {
            chain,
            serial: record.serial,
            times: record.times,
        }))
    }

    /// Saves the current certificate.
    pub fn save_certificate(&self, c: &StoredCertificate) -> Result<(), String> {
        let pem: String = c
            .chain
            .iter()
            .map(|d| warren_core::base64::pem("CERTIFICATE", d))
            .collect();
        write_private(&self.dir.join(CERT_PEM), pem.as_bytes())?;
        write_json(
            &self.dir.join(CERT_JSON),
            &CertificateRecord {
                serial: c.serial.clone(),
                times: c.times,
            },
        )
    }

    /// Forgets the certificate.
    pub fn clear_certificate(&self) {
        let _ = std::fs::remove_file(self.dir.join(CERT_JSON));
        let _ = std::fs::remove_file(self.dir.join(CERT_PEM));
    }

    /// The last entitlements fetched.
    pub fn entitlements(&self) -> Result<Option<Entitlements>, String> {
        read_json(&self.dir.join(ENTITLEMENTS))
    }

    /// Saves the entitlements.
    pub fn save_entitlements(&self, e: &Entitlements) -> Result<(), String> {
        write_json(&self.dir.join(ENTITLEMENTS), e)
    }

    /// Removes everything sign-in left, the device key included.
    pub fn clear(&self) -> Result<(), String> {
        crate::device::DeviceKey::delete(&self.dir)?;
        self.clear_certificate();
        for f in [PROFILE, ENTITLEMENTS] {
            let _ = std::fs::remove_file(self.dir.join(f));
        }
        let _ = std::fs::remove_dir_all(self.dir.join(TRUST));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_private_and_atomic() {
        let dir = std::env::temp_dir().join(format!(
            "warren-state-{}",
            warren_core::keys::hex(&warren_core::keys::random_bytes::<6>().unwrap())
        ));
        let store = Store::open(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        assert!(store.profile().unwrap().is_none());
        let p = Profile {
            org_url: "https://warren.example.com".into(),
            trust_domain: "example.com".into(),
            pin: None,
            signin_api_base: "https://warren.example.com/v1".into(),
            api_base: Some("https://nodes.warren.example.com/v1".into()),
            user: UserInfo {
                id: "u-1".into(),
                email: Some("ada@example.com".into()),
                groups: vec!["eng".into()],
            },
            session: SessionState {
                id: "s-1".into(),
                token: "wst_x".into(),
                expires_at: 1,
                auth_time: 0,
                mfa: false,
            },
            device: None,
        };
        store.save_profile(&p).unwrap();
        assert_eq!(store.profile().unwrap(), Some(p));
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [PROFILE]);
        check_private(&dir.join(PROFILE)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_writers_to_sibling_files_do_not_collide() {
        let dir = std::env::temp_dir().join(format!(
            "warren-state-{}",
            warren_core::keys::hex(&warren_core::keys::random_bytes::<6>().unwrap())
        ));
        create_private_dir(&dir).unwrap();
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|s| {
            for (i, file) in ["certificate.pem", "certificate.json"]
                .iter()
                .cycle()
                .take(4)
                .enumerate()
            {
                let (dir, barrier) = (&dir, &barrier);
                s.spawn(move || {
                    barrier.wait();
                    for n in 0..200 {
                        write_private(&dir.join(file), format!("{i}-{n}").as_bytes()).unwrap();
                    }
                });
            }
        });
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["certificate.json", "certificate.pem"]);
        for f in &names {
            check_private(&dir.join(f)).unwrap();
            let text = std::fs::read_to_string(dir.join(f)).unwrap();
            assert!(text.ends_with("-199"), "{f}: {text}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
