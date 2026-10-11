//! `warren connector`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use clap::ArgMatches;
use tracing::{info, warn};
use warren_connector::{Connector, ConnectorConfig, SystemResolver};
use warren_core::audit::{AuditSink, NodeInfo};
use warren_core::bundle::IpNet;
use warren_core::params;
use warren_core::quic::TransportTuning;
use warren_masque::session::{RelayAddress, TransportMode};

use crate::node::{self, Signal};

/// Parses `NAME[@HOST:PORT]`; without an address the name is resolved on
/// port 443. QUIC and the HTTP/2 fallback share the address.
fn relay(spec: &str) -> Result<RelayAddress, String> {
    let (name, addr) = match spec.split_once('@') {
        Some((n, a)) => (n, a.to_owned()),
        None => (spec, format!("{spec}:443")),
    };
    let addr: SocketAddr = addr
        .to_socket_addrs()
        .map_err(|e| format!("--relay {spec}: {e}"))?
        .next()
        .ok_or_else(|| format!("--relay {spec}: no address"))?;
    Ok(RelayAddress {
        name: name.to_owned(),
        quic: addr,
        tcp: addr,
    })
}

fn pools(m: &ArgMatches, name: &str, defaults: [&str; 2]) -> Result<Vec<IpNet>, String> {
    match m.get_many::<String>(name) {
        Some(v) => v
            .map(|p| p.parse::<IpNet>().map_err(|e| format!("--{name} {p}: {e}")))
            .collect(),
        None => Ok(defaults
            .iter()
            .map(|d| d.parse().expect("valid default pool"))
            .collect()),
    }
}

pub fn run(m: &ArgMatches) -> Result<(), String> {
    let runtime = node::runtime()?;
    let mut signals = node::Signals::new(&runtime)?;
    let setup = node::setup(m)?;
    signals.listen_for_stop(&runtime)?;
    let group = m.get_one::<String>("group").expect("required").clone();
    let leaf = setup
        .credentials
        .chain
        .first()
        .ok_or("empty certificate chain")?;
    let me = warren_core::pki::check_infra_profile(leaf, &setup.trust.trust_domain)
        .map_err(|e| e.to_string())?;
    match &me.role {
        warren_core::identity::NodeRole::Connector { group: g } if *g == group => {}
        other => {
            return Err(format!(
                "the certificate names {other}, not a connector in group {group}"
            ));
        }
    }
    let relays = m
        .get_many::<String>("relay")
        .expect("required")
        .map(|s| relay(s))
        .collect::<Result<Vec<_>, _>>()?;
    let transport = match m.get_one::<String>("transport").map(String::as_str) {
        Some("quic") => TransportMode::QuicOnly,
        Some("h2") => TransportMode::Http2Only,
        _ => TransportMode::Auto,
    };
    let device_pools = pools(
        m,
        "device-pool",
        [params::DEVICE_POOL_V4, params::DEVICE_POOL_V6],
    )?;
    let synthetic_pools = pools(
        m,
        "synthetic-pool",
        [params::SYNTHETIC_POOL_V4, params::SYNTHETIC_POOL_V6],
    )?;
    let tunnel_mtu = *m.get_one::<u16>("tunnel-mtu").expect("defaulted");
    let node_info = NodeInfo {
        role: "connector".into(),
        name: format!("connector/{group}/{}", me.id),
    };
    let audit = AuditSink::new(
        node_info,
        m.get_one::<String>("audit").map(std::path::Path::new),
    )
    .map_err(|e| format!("--audit: {e}"))?;
    let drain = Duration::from_secs(*m.get_one::<u64>("drain-timeout").expect("defaulted"));
    let config = ConnectorConfig {
        group,
        relays,
        transport,
        credentials: setup.credentials,
        trust: setup.trust,
        policy: Arc::new(warren_core::policy::StaticPolicy::new(setup.state.clone())),
        state: setup.state,
        audit,
        resolver: Arc::new(SystemResolver),
        synthetic_pools,
        tunnel_mtu,
        tuning: TransportTuning::default(),
    };
    let bundle_path = setup.bundle_path;
    let tun_name = m.get_one::<String>("tun-name").expect("defaulted").clone();
    let masquerade = m.get_one::<String>("nat").map(String::as_str) == Some("masquerade");
    runtime.block_on(async move {
        let backend = kernel_backend(&tun_name, tunnel_mtu, device_pools.clone(), masquerade)?;
        let connector = Connector::start(config, backend).map_err(|e| e.to_string())?;
        node::serve_metrics(m, connector.metrics().registry.clone()).await?;
        loop {
            match signals.next().await {
                Signal::Reload => {
                    match node::reload(&bundle_path).and_then(|b| connector.reload(b)) {
                        Ok(()) => info!("bundle reloaded; live flows re-evaluated"),
                        Err(e) => {
                            warn!(error = %e, "bundle reload failed; keeping the current bundle")
                        }
                    }
                }
                Signal::Stop => {
                    info!(timeout = ?drain, "connector draining");
                    let stop = async { while let Signal::Reload = signals.next().await {} };
                    tokio::select! {
                        () = connector.drain(drain) => {}
                        () = stop => info!("stopping without waiting"),
                    }
                    connector.shutdown();
                    stop_kernel(&tun_name, tunnel_mtu, device_pools, masquerade);
                    return Ok(());
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn kernel_options(
    tun: &str,
    mtu: u16,
    pools: Vec<IpNet>,
    masquerade: bool,
) -> warren_connector::kernel::KernelOptions {
    warren_connector::kernel::KernelOptions {
        tun_name: tun.to_owned(),
        mtu,
        device_pools: pools,
        masquerade,
    }
}

#[cfg(target_os = "linux")]
fn kernel_backend(
    tun: &str,
    mtu: u16,
    pools: Vec<IpNet>,
    masquerade: bool,
) -> Result<warren_connector::Backend, String> {
    warren_connector::kernel::start(&kernel_options(tun, mtu, pools, masquerade))
        .map_err(|e| format!("kernel forwarding (needs Linux and CAP_NET_ADMIN): {e}"))
}

#[cfg(target_os = "linux")]
fn stop_kernel(tun: &str, mtu: u16, pools: Vec<IpNet>, masquerade: bool) {
    warren_connector::kernel::stop(&kernel_options(tun, mtu, pools, masquerade));
}

#[cfg(not(target_os = "linux"))]
fn kernel_backend(
    _: &str,
    _: u16,
    _: Vec<IpNet>,
    _: bool,
) -> Result<warren_connector::Backend, String> {
    Err("kernel forwarding mode needs Linux (TUN and NAT); the userspace mode comes later".into())
}

#[cfg(not(target_os = "linux"))]
fn stop_kernel(_: &str, _: u16, _: Vec<IpNet>, _: bool) {}
