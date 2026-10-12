//! The control plane role.
//!
//! Identity: built-in accounts with mandatory MFA and brokering with the
//! organization's IdP; device registration and approval, certificate
//! issuance, policy compilation and distribution, revocation push, audit,
//! and the admin API that serves the console.
//!
//! [`ControlPlane::start`] runs everything on the current tokio runtime;
//! [`run`] is the blocking entry point behind `warren control-plane`.

pub mod accounts;
pub mod admin;
pub mod api;
pub mod app;
pub mod audit;
pub mod authority;
pub mod config;
pub mod console;
pub mod log;
pub mod oidc;
mod signin;
pub mod store;
mod stream;
pub mod web;

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use warren_core::cert;
use warren_core::clock;
use warren_core::identity::NodeRole;
use warren_core::keys::{SigningKey, sha256};
use warren_core::params::INFRA_CERT_LIFETIME;

use crate::app::App;
use crate::audit::{Activity, Actor};
use crate::authority::{Authority, Kek};
use crate::config::IdpKind;
use crate::config::{Config, TlsFiles};
use crate::store::Store;
use crate::web::ServerCert;

/// One-line description of the role, shown by `warren control-plane --help`.
pub const ABOUT: &str =
    "Run the control plane: identity, devices, certificates, policy, revocation";

/// A control-plane error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The configuration is wrong.
    Config(String),
    /// The database failed.
    Store(String),
    /// TLS setup failed.
    Tls(String),
    /// The IdP failed or answered with something unacceptable.
    Idp(String),
    /// A request was malformed.
    BadRequest(String),
    /// A request conflicts with existing state.
    Conflict(String),
    /// Something needed is unavailable.
    Unavailable(String),
    /// A bug or an unexpected failure.
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(e) => write!(f, "configuration: {e}"),
            Error::Store(e) => write!(f, "database: {e}"),
            Error::Tls(e) => write!(f, "TLS: {e}"),
            Error::Idp(e) => write!(f, "identity provider: {e}"),
            Error::BadRequest(e) => write!(f, "bad request: {e}"),
            Error::Conflict(e) => write!(f, "conflict: {e}"),
            Error::Unavailable(e) => write!(f, "unavailable: {e}"),
            Error::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// A running control plane.
pub struct ControlPlane {
    /// Where the HTTPS API listens.
    pub addr: SocketAddr,
    /// The admin socket.
    pub admin_socket: PathBuf,
    admin_socket_id: Option<(u64, u64)>,
    app: Arc<App>,
    certificates: Arc<Certificates>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

/// How long revocation events are kept for nodes to resume from.
const EVENT_RETENTION: Duration = Duration::from_secs(7 * 86_400);

/// How often the operator's certificate files are checked for changes.
const CERT_FILE_POLL: Duration = Duration::from_secs(30);

/// The listener's certificates, and the operator's files behind the one for
/// the public host.
struct Certificates {
    server: Arc<ServerCert>,
    operator: Option<TlsFiles>,
    /// A digest of the operator's files as last read.
    seen: Mutex<[u8; 32]>,
}

impl Certificates {
    /// Reads the operator's files and, if they changed since they were last
    /// read, presents the certificate they hold. Returns whether it did; a
    /// change that does not load leaves the current certificate in place.
    fn reload(&self) -> Result<bool, Error> {
        let Some(files) = &self.operator else {
            return Ok(false);
        };
        let read = |path: &Path| {
            std::fs::read_to_string(path)
                .map(zeroize::Zeroizing::new)
                .map_err(|e| Error::Tls(format!("{}: {e}", path.display())))
        };
        let (cert, key) = (read(&files.cert_file)?, read(&files.key_file)?);
        let digest = sha256(&[sha256(cert.as_bytes()), sha256(key.as_bytes())].concat());
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| Error::Internal("certificate state poisoned".into()))?;
            if *seen == digest {
                return Ok(false);
            }
            *seen = digest;
        }
        self.server.set_operator(&cert, &key).map_err(|e| {
            Error::Tls(format!(
                "{} and {}: {e}",
                files.cert_file.display(),
                files.key_file.display()
            ))
        })?;
        Ok(true)
    }
}

fn issue_own_cert(
    app_authority: &Authority,
    config: &Config,
    id: &str,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), Error> {
    let key = SigningKey::generate().map_err(|e| Error::Internal(e.to_string()))?;
    let mut names = vec![config.public_host.clone()];
    names.extend(config.dns_names.iter().cloned());
    names.dedup();
    let issued = app_authority.issue_node(
        &cert::p256_spki(key.public_key().point()),
        &NodeRole::ControlPlane,
        id,
        &names,
        INFRA_CERT_LIFETIME.as_secs() as i64,
        config.clock_skew.as_secs() as i64,
    )?;
    let pkcs8 = key.to_pkcs8().map_err(|e| Error::Internal(e.to_string()))?;
    // The root rides along so a joining node can find the root its token
    // pins (docs/protocol.md section 10.3).
    Ok((
        vec![
            issued.der,
            app_authority.infra.der.clone(),
            app_authority.root.der.clone(),
        ],
        pkcs8.to_vec(),
    ))
}

impl ControlPlane {
    /// Starts the control plane on the current tokio runtime: opens the
    /// database, loads or creates the keys, compiles policy (refusing to
    /// start on a policy that does not compile), publishes a bundle, and
    /// starts the HTTPS and admin listeners.
    pub async fn start(config: Config) -> Result<ControlPlane, Error> {
        ControlPlane::start_with_audit(config, None).await
    }

    /// Like [`ControlPlane::start`], writing audit records to `sink` instead
    /// of the configured destination.
    pub async fn start_with_audit(
        config: Config,
        sink: Option<audit::Sink>,
    ) -> Result<ControlPlane, Error> {
        if config.public_host.parse::<std::net::IpAddr>().is_ok() {
            return Err(Error::Config("publicUrl must use a DNS name".into()));
        }
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| Error::Config(format!("{}: {e}", config.data_dir.display())))?;
        let kek = Kek::load_or_create(&config.kek_file)?;
        let store = Store::open(&config.database).await?;
        let authority = Authority::load_or_create(&store, &kek, &config.trust_domain).await?;
        let idp = config
            .idp
            .as_ref()
            .map(|i| oidc::Provider::new(i, config.clock_skew))
            .transpose()?;
        warn_about_idp(&config);
        let sink = match (sink, &config.audit_file) {
            (Some(sink), _) => sink,
            (None, Some(path)) => audit::Sink::file(path)?,
            (None, None) => audit::Sink::stdout(),
        };
        let id = store
            .init_setting("control_plane_id", &store::new_id("cp")?)
            .await?;
        let (latest, _) = store.event_bounds().await?;
        let app = Arc::new(App::new(
            config, store, authority, kek, idp, sink, id, latest,
        ));
        bootstrap_admin(&app).await?;
        ControlPlane::serve(app).await
    }

    async fn serve(app: Arc<App>) -> Result<ControlPlane, Error> {
        let config = &app.config;
        if let Err(errors) = app.load_policy(&Actor::System).await {
            return Err(Error::Config(format!(
                "the policy in {} does not compile:\n{}",
                config.policy_dir.display(),
                errors.join("\n")
            )));
        }
        app.publish().await?;

        let (chain, pkcs8) = issue_own_cert(&app.authority, config, &app.id)?;
        let certificates = Arc::new(Certificates {
            server: Arc::new(ServerCert::new(chain, &pkcs8, config.internal_names())?),
            operator: config.tls.clone(),
            seen: Mutex::new([0; 32]),
        });
        if config.tls.is_some() {
            certificates
                .reload()
                .map_err(|e| Error::Config(e.to_string()))?;
            let nodes: Vec<String> = app
                .store
                .nodes()
                .await?
                .into_iter()
                .filter(|n| n.revoked_at.is_none())
                .map(|n| format!("{} {}", n.role, n.name))
                .collect();
            if !nodes.is_empty() {
                log::warn(
                    "tls",
                    &format!(
                        "{} now presents the operator's certificate, which relays and connectors do not accept; any of these that still use it must be pointed at {} to keep receiving bundles and revocations: {}",
                        config.public_url,
                        config.internal_url(),
                        nodes.join(", ")
                    ),
                );
            }
        } else {
            log::warn(
                "tls",
                "no tls.certFile and tls.keyFile are configured, so the HTTPS listener presents a certificate from the deployment's private CA; browsers will not trust it, and browser sign-in will show a certificate error until they are set",
            );
        }
        let tls = web::server_config(
            certificates.server.clone(),
            &[
                app.authority.client.der.clone(),
                app.authority.infra.der.clone(),
            ],
        )?;
        let listener = tokio::net::TcpListener::bind(config.listen)
            .await
            .map_err(|e| Error::Config(format!("cannot listen on {}: {e}", config.listen)))?;
        let addr = listener
            .local_addr()
            .map_err(|e| Error::Internal(e.to_string()))?;
        let (shutdown, rx) = watch::channel(false);
        let mut tasks = Vec::new();
        tasks.push(tokio::spawn(web::serve_tls(
            listener,
            tls,
            Arc::new(api::Api(app.clone())),
            config.connections.clone(),
            rx.clone(),
        )));

        let admin_socket = config.admin_socket.clone();
        #[cfg(unix)]
        {
            let unix = bind_admin_socket(&admin_socket)?;
            tasks.push(tokio::spawn(web::serve_unix(
                unix,
                Arc::new(admin::Admin(app.clone())),
                rx.clone(),
            )));
        }

        tasks.push(tokio::spawn(app.clone().publisher()));
        // Renew the control plane's own certificate at half-life, reload the
        // operator's when its files change, and prune the event log.
        let maintenance = app.clone();
        let certs = certificates.clone();
        tasks.push(tokio::spawn(async move {
            let half = INFRA_CERT_LIFETIME / 2;
            let mut renew = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
            let mut poll = tokio::time::interval_at(
                tokio::time::Instant::now() + CERT_FILE_POLL,
                CERT_FILE_POLL,
            );
            let mut prune = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = renew.tick() => {
                        maintenance.authority.warn_if_expiring();
                        match issue_own_cert(&maintenance.authority, &maintenance.config, &maintenance.id)
                            .and_then(|(chain, key)| certs.server.replace(chain, &key))
                        {
                            Ok(()) => log::info("tls", "renewed the control plane's certificate"),
                            Err(e) => log::error("tls", &format!("cannot renew the control plane's certificate: {e}")),
                        }
                    }
                    _ = poll.tick() => log_reload(certs.reload()),
                    _ = prune.tick() => {
                        let before = clock::now_millis() - EVENT_RETENTION.as_millis() as i64;
                        if let Err(e) = maintenance.store.prune_events(before).await {
                            log::error("events", &format!("cannot prune events: {e}"));
                        }
                        if let Err(e) = maintenance.store.prune_auth().await {
                            log::error("sign-in", &format!("cannot prune expired sign-ins: {e}"));
                        }
                    }
                }
            }
        }));
        log::info_with(
            "control-plane",
            "listening",
            &[
                ("address", &addr.to_string()),
                ("admin_socket", &admin_socket.display().to_string()),
                ("trust_domain", &app.config.trust_domain),
            ],
        );
        Ok(ControlPlane {
            addr,
            #[cfg(unix)]
            admin_socket_id: file_id(&admin_socket),
            #[cfg(not(unix))]
            admin_socket_id: None,
            admin_socket,
            app,
            certificates,
            shutdown,
            tasks,
        })
    }

    /// The shared state.
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    /// Rereads the operator's certificate files (`tls.certFile` and
    /// `tls.keyFile`) now, as the control plane does every 30 seconds and on
    /// SIGHUP. Returns whether a new certificate is being presented; files
    /// that do not load leave the current one in place.
    pub fn reload_certificate(&self) -> Result<bool, Error> {
        self.certificates.reload()
    }

    /// Stops listening and closes the database.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
        // Remove the socket only if it is still the one this instance made.
        #[cfg(unix)]
        if self.admin_socket_id.is_some() && file_id(&self.admin_socket) == self.admin_socket_id {
            let _ = std::fs::remove_file(&self.admin_socket);
        }
        self.app.store.close().await;
    }
}

/// Points out IdP setups that work but are probably not what was meant.
fn warn_about_idp(config: &Config) {
    let Some(idp) = config.idp.as_ref().filter(|i| i.kind == IdpKind::Google) else {
        return;
    };
    if idp.hosted_domain.is_none() && idp.allowed_emails.is_empty() {
        log::warn(
            "idp",
            "idp type google has no hostedDomain or allowedEmails, so any Google account with a verified email can sign in and enroll devices; such users reach nothing unless policy names them",
        );
    }
    let host = &config.public_host;
    if [
        ".local",
        ".lan",
        ".internal",
        ".home.arpa",
        ".localdomain",
        ".test",
    ]
    .iter()
    .any(|suffix| host.ends_with(suffix))
    {
        log::warn(
            "idp",
            &format!(
                "Google accepts redirect URIs only on a public top-level domain or localhost, so {host} will be refused; give publicUrl a name under a public domain (it need not be reachable from the internet)"
            ),
        );
    }
}

/// Creates the first admin from the mounted password file, once: on the
/// first start that finds no built-in account. Later starts never read the
/// file again, so deleting the admin never brings it back.
async fn bootstrap_admin(app: &App) -> Result<(), Error> {
    let Some(admin) = &app.config.local_accounts.bootstrap_admin else {
        return Ok(());
    };
    if app.store.setting("bootstrap_admin").await?.is_some() {
        return Ok(());
    }
    if app.store.has_local_accounts().await? {
        app.store.init_setting("bootstrap_admin", "skipped").await?;
        log::info(
            "accounts",
            "built-in accounts already exist, so no bootstrap admin was created; the password file is not read",
        );
        return Ok(());
    }
    let path = &admin.password_file;
    let text =
        zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!("bootstrap admin password {}: {e}", path.display()))
        })?);
    let password = zeroize::Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_owned());
    accounts::check_new_password(&password, &admin.username)
        .map_err(|e| Error::Config(format!("bootstrap admin password {}: {e}", path.display())))?;
    let hash = app.hash_password(password).await?;
    let user = app
        .store
        .create_local_user(
            &admin.username,
            admin.email.as_deref(),
            None,
            &admin.groups,
            Some(&hash),
            None,
        )
        .await?;
    app.store.init_setting("bootstrap_admin", &user.id).await?;
    let mut r = audit::record(
        Activity::AccountCreate,
        true,
        &Actor::System,
        "bootstrap admin created from the mounted password file",
    );
    r.insert(
        "user".into(),
        serde_json::json!({ "uid": user.id, "name": admin.username, "groups": admin.groups }),
    );
    app.audit(r);
    log::info_with(
        "accounts",
        "created the bootstrap admin; it sets up an authenticator app at first sign-in, and the password file is no longer read",
        &[
            ("username", &admin.username),
            ("password_file", &path.display().to_string()),
        ],
    );
    Ok(())
}

fn log_reload(result: Result<bool, Error>) {
    match result {
        Ok(true) => log::info("tls", "presenting the new certificate from tls.certFile"),
        Ok(false) => {}
        Err(e) => log::error(
            "tls",
            &format!("cannot load the new certificate; the previous one stays in use: {e}"),
        ),
    }
}

/// Makes way for the admin socket at `path`: nothing there is fine, a stale
/// socket is removed, and anything else is refused, whether a file that is
/// not a socket (a misconfigured path must never delete data) or a socket
/// another control plane is still answering on.
#[cfg(unix)]
fn clear_stale_socket(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::FileTypeExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::Config(format!("{}: {e}", path.display()))),
    };
    if !meta.file_type().is_socket() {
        return Err(Error::Config(format!(
            "{} exists and is not a socket; adminSocket must name a path the control plane owns",
            path.display()
        )));
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(Error::Config(format!(
            "another control plane is already serving {}",
            path.display()
        )));
    }
    std::fs::remove_file(path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

/// The identity of the file at `path`, to recognize our own socket later.
#[cfg(unix)]
fn file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Creates the admin socket so that nobody but the control plane's own user
/// can ever connect to it: it is bound inside a fresh directory only that
/// user can enter, restricted to mode 0600, and only then moved into place.
#[cfg(unix)]
fn bind_admin_socket(path: &Path) -> Result<tokio::net::UnixListener, Error> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let err = |e: std::io::Error| Error::Config(format!("{}: {e}", path.display()));
    let dir = path
        .parent()
        .ok_or_else(|| Error::Config(format!("{}: no parent directory", path.display())))?;
    std::fs::create_dir_all(dir).map_err(err)?;
    clear_stale_socket(path)?;
    let staging = dir.join(format!(
        ".a{}",
        warren_core::keys::hex(
            &warren_core::keys::random_bytes::<3>().map_err(|e| Error::Internal(e.to_string()))?
        )
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(err)?;
    // Short names: socket paths are limited to about 100 bytes, and the
    // staged path is no longer than the final one.
    let staged = staging.join("s");
    let result = (|| {
        let listener = tokio::net::UnixListener::bind(&staged).map_err(err)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).map_err(err)?;
        std::fs::rename(&staged, path).map_err(err)?;
        Ok(listener)
    })();
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_dir(&staging);
    result
}

/// Runs the control plane with the configuration at `config_path` until
/// SIGINT or SIGTERM. SIGHUP reloads policy and the operator's certificate.
pub fn run(config_path: &Path) -> Result<(), Error> {
    let mut config = Config::load(config_path)?;
    if let Some(dir) = config_path.parent() {
        config.resolve_paths(dir);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Internal(e.to_string()))?;
    runtime.block_on(async move {
        let cp = ControlPlane::start(config).await?;
        wait_for_signals(&cp).await;
        log::info("control-plane", "shutting down");
        cp.shutdown().await;
        Ok(())
    })
}

#[cfg(unix)]
async fn wait_for_signals(cp: &ControlPlane) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    loop {
        tokio::select! {
            _ = term.recv() => return,
            _ = int.recv() => return,
            _ = hup.recv() => {
                log_reload(cp.reload_certificate());
                match cp.app.load_policy(&Actor::System).await {
                    Ok(_) => log::info("policy", "policy reloaded"),
                    Err(errors) => log::error("policy", &format!("policy rejected; the previous policy stays in force: {}", errors.join("; "))),
                }
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signals(_cp: &ControlPlane) {
    let _ = tokio::signal::ctrl_c().await;
}

/// Sends one admin request over the local socket (`warren admin`).
#[cfg(unix)]
pub fn admin_request(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<String>,
) -> Result<(u16, String), Error> {
    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|e| Error::BadRequest(e.to_string()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Internal(e.to_string()))?;
    runtime.block_on(admin::request(socket, method, path, body))
}

/// Sends one admin request over the local socket (`warren admin`). The
/// admin socket is a Unix socket, so other platforms have no admin API yet.
#[cfg(not(unix))]
pub fn admin_request(
    _socket: &Path,
    _method: &str,
    _path: &str,
    _body: Option<String>,
) -> Result<(u16, String), Error> {
    Err(Error::Unavailable(
        "the admin socket needs a Unix platform".into(),
    ))
}

/// Compiles a policy directory and returns the compiled Cedar policy set,
/// or every diagnostic (`warren policy check`). Warnings are returned with
/// the compiled set.
pub fn check_policy(dir: &Path, reserved: &[String]) -> Result<(String, Vec<String>), Vec<String>> {
    let (objects, diags) =
        warren_policy::model::load_dir(dir).map_err(|e| vec![format!("{}: {e}", dir.display())])?;
    let compiled = warren_policy::compile::compile(objects, diags, reserved)
        .map_err(|d| d.iter().map(|d| d.to_string()).collect::<Vec<_>>())?;
    Ok((
        compiled.policy.policies.clone(),
        compiled.warnings.iter().map(|w| w.to_string()).collect(),
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::clear_stale_socket;

    #[test]
    fn only_stale_sockets_are_cleared() {
        let dir = std::env::temp_dir().join(format!(
            "warren-sock-{}",
            warren_core::keys::hex(&warren_core::keys::random_bytes::<4>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Nothing there.
        assert!(clear_stale_socket(&dir.join("none")).is_ok());
        // A regular file is never deleted.
        let file = dir.join("data");
        std::fs::write(&file, b"keep me").unwrap();
        assert!(clear_stale_socket(&file).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
        // A live socket belongs to someone else.
        let live = dir.join("live");
        let listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
        assert!(clear_stale_socket(&live).is_err());
        // Once nobody listens it is stale, and goes.
        drop(listener);
        assert!(clear_stale_socket(&live).is_ok());
        assert!(!live.exists());
        std::fs::remove_dir_all(dir).ok();
    }
}
