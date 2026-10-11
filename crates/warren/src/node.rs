//! What the relay and connector roles share: loading credentials and the
//! node bundle, logging, metrics, and signals.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::ArgMatches;
use warren_core::bundle::{Bundle, CompiledBundle, NodeState};
use warren_core::metrics::Registry;
use warren_core::pki::TrustBundle;
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

/// Loads credentials, the trust bundle and the node bundle, and starts
/// logging.
pub fn setup(m: &ArgMatches) -> Result<NodeSetup, String> {
    warren_core::logging::init(
        m.get_one::<String>("log-level")
            .map_or("info", String::as_str),
    );
    let bundle_path = path(m, "bundle");
    let bundle = Bundle::load(&bundle_path).map_err(|e| e.to_string())?;
    let trust = TrustBundle::load_dir(&bundle.trust_domain, &path(m, "trust-bundle"))
        .map_err(|e| e.to_string())?;
    let credentials = Credentials::load(&path(m, "cert"), &path(m, "key"))?;
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
