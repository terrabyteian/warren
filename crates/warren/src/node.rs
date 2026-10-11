//! What the relay and connector roles share: loading credentials and the
//! node bundle, logging, metrics, and signals.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::ArgMatches;
use warren_core::bundle::{Bundle, CompiledBundle, NodeState};
use warren_core::join::{JoinToken, NodeKey};
use warren_core::metrics::Registry;
use warren_core::pki::{self, TrustBundle};
use warren_core::tls::Credentials;

/// Everything a node loads at start.
pub struct NodeSetup {
    pub credentials: Credentials,
    pub trust: Arc<TrustBundle>,
    pub state: Arc<NodeState>,
    pub bundle_path: PathBuf,
}

fn path(m: &ArgMatches, name: &str) -> PathBuf {
    PathBuf::from(m.get_one::<String>(name).expect("required argument"))
}

/// Joins with a token into `dir`, unless an earlier join left credentials
/// there; returns the certificate, key and trust bundle paths.
fn join_into(
    token: &str,
    dir: &Path,
    trust_domain: &str,
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let (cert, key, trust) = (dir.join("cert.pem"), dir.join("key.pem"), dir.join("trust"));
    if cert.exists() && key.exists() && trust.exists() {
        tracing::info!(dir = %dir.display(), "using credentials from an earlier join");
        return Ok((cert, key, trust));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token = JoinToken::parse(token, now).map_err(|e| e.to_string())?;
    if token.td != trust_domain {
        return Err(format!(
            "the token joins {}, the bundle is for {trust_domain}",
            token.td
        ));
    }
    let node_key = NodeKey::generate().map_err(|e| e.to_string())?;
    let joined = runtime()?
        .block_on(warren_masque::join::join(&token, &node_key))
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&trust).map_err(|e| format!("{}: {e}", trust.display()))?;
    let pem = |certs: &[rustls::pki_types::CertificateDer<'_>]| -> String {
        certs
            .iter()
            .map(|c| warren_core::base64::pem("CERTIFICATE", c))
            .collect()
    };
    let write = |p: &Path, text: String| {
        std::fs::write(p, text).map_err(|e| format!("{}: {e}", p.display()))
    };
    write(
        &trust.join(pki::ROOT_CA_FILE),
        pem(std::slice::from_ref(&joined.trust.root)),
    )?;
    write(
        &trust.join(pki::CLIENT_CA_FILE),
        pem(&joined.trust.client_cas),
    )?;
    write(
        &trust.join(pki::INFRA_CA_FILE),
        pem(&joined.trust.infra_cas),
    )?;
    write(&key, node_key.private_key_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    // The certificate last: its presence marks a completed join.
    write(&cert, pem(&joined.credentials.chain))?;
    tracing::info!(role = %joined.identity.role, id = %joined.identity.id, "joined the deployment");
    Ok((cert, key, trust))
}

/// Loads credentials (joining first if asked to), the trust bundle and the
/// node bundle, and starts logging.
pub fn setup(m: &ArgMatches) -> Result<NodeSetup, String> {
    warren_core::logging::init(
        m.get_one::<String>("log-level")
            .map_or("info", String::as_str),
    );
    let bundle_path = path(m, "bundle");
    let bundle = Bundle::load(&bundle_path).map_err(|e| e.to_string())?;
    let (cert, key, trust_dir) = match m.get_one::<String>("join-token") {
        Some(token) => join_into(token, &path(m, "state-dir"), &bundle.trust_domain)?,
        None => (path(m, "cert"), path(m, "key"), path(m, "trust-bundle")),
    };
    let trust =
        TrustBundle::load_dir(&bundle.trust_domain, &trust_dir).map_err(|e| e.to_string())?;
    let credentials = Credentials::load(&cert, &key)?;
    Ok(NodeSetup {
        credentials,
        trust: Arc::new(trust),
        state: NodeState::new(bundle),
        bundle_path,
    })
}

/// Reloads the node bundle from disk.
pub fn reload(path: &std::path::Path) -> Result<CompiledBundle, String> {
    Bundle::load(path).map_err(|e| e.to_string())
}

/// Serves metrics if asked to.
pub async fn serve_metrics(m: &ArgMatches, registry: Registry) -> Result<(), String> {
    if let Some(addr) = m.get_one::<String>("metrics") {
        let addr: SocketAddr = addr.parse().map_err(|e| format!("--metrics {addr}: {e}"))?;
        let listener = warren_core::metrics::bind(addr)
            .await
            .map_err(|e| format!("--metrics {addr}: {e}"))?;
        tracing::info!(%addr, "serving metrics");
        tokio::spawn(registry.serve(listener));
    }
    Ok(())
}

/// What a signal asks the node to do.
pub enum Signal {
    /// SIGHUP: reload the bundle.
    Reload,
    /// SIGTERM or SIGINT: stop.
    Stop,
}

/// Waits for the next signal.
pub async fn next_signal() -> Signal {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut hup), Ok(mut term), Ok(mut int)) = (
            signal(SignalKind::hangup()),
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            std::future::pending::<()>().await;
            unreachable!();
        };
        tokio::select! {
            _ = hup.recv() => Signal::Reload,
            _ = term.recv() => Signal::Stop,
            _ = int.recv() => Signal::Stop,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        Signal::Stop
    }
}

/// Builds the runtime roles run on.
pub fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("warren")
        .build()
        .map_err(|e| e.to_string())
}
