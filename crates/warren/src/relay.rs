//! `warren relay`.

use std::net::{Ipv6Addr, SocketAddr};

use clap::ArgMatches;
use tracing::{info, warn};
use warren_core::quic::TransportTuning;
use warren_relay::{Relay, RelayConfig};

use crate::node::{self, Signal};

pub fn run(m: &ArgMatches) -> Result<(), String> {
    let runtime = node::runtime()?;
    let mut signals = node::Signals::new(&runtime)?;
    let setup = node::setup(m)?;
    let listen: SocketAddr = parse(m, "listen")?;
    let listen_tcp = if m.get_flag("no-tcp") {
        None
    } else {
        Some(match m.get_one::<String>("listen-tcp") {
            Some(a) => a.parse().map_err(|e| format!("--listen-tcp {a}: {e}"))?,
            None => listen,
        })
    };
    let peer_prefix = match m.get_one::<String>("peer-prefix") {
        Some(p) => Some(
            p.parse::<Ipv6Addr>()
                .map_err(|e| format!("--peer-prefix {p}: {e}"))?,
        ),
        None => None,
    };
    let leaf = setup
        .credentials
        .chain
        .first()
        .ok_or("empty certificate chain")?;
    let me = warren_core::pki::check_infra_profile(leaf, &setup.trust.trust_domain)
        .map_err(|e| e.to_string())?;
    if me.role != warren_core::identity::NodeRole::Relay {
        return Err(format!("the certificate names a {}, not a relay", me.role));
    }
    let config = RelayConfig {
        listen_quic: listen,
        listen_tcp,
        credentials: setup.credentials,
        trust: setup.trust,
        state: setup.state,
        name: format!("warren-relay-{}", me.id),
        peer_prefix,
        max_splices_per_client: *m
            .get_one::<usize>("max-splices-per-client")
            .expect("defaulted"),
        tuning: TransportTuning::default(),
    };
    let bundle_path = setup.bundle_path;
    runtime.block_on(async move {
        let relay = Relay::start(config).await.map_err(|e| e.to_string())?;
        node::serve_metrics(m, relay.metrics().registry.clone()).await?;
        loop {
            match signals.next().await {
                Signal::Reload => match node::reload(&bundle_path).and_then(|b| relay.reload(b)) {
                    Ok(cut) => info!(cut, "bundle reloaded"),
                    Err(e) => warn!(error = %e, "bundle reload failed; keeping the current bundle"),
                },
                Signal::Stop => {
                    info!("relay stopping");
                    relay.shutdown();
                    return Ok(());
                }
            }
        }
    })
}

fn parse(m: &ArgMatches, name: &str) -> Result<SocketAddr, String> {
    let v = m.get_one::<String>(name).expect("defaulted");
    v.parse().map_err(|e| format!("--{name} {v}: {e}"))
}
