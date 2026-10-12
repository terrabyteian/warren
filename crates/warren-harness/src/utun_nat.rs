//! A macOS stand-in for the connector's kernel forwarding, for end-to-end
//! tests of the macOS client on one Mac (scripts/e2e-macos.sh). Admitted
//! packets go into a utun interface with both addresses translated: each
//! app address to a local address of that interface, so the Mac's own TCP
//! and UDP stacks serve the stand-in apps, and each client's tunnel address
//! to a peer address behind the interface, so the answers come back through
//! it and are translated back. Translating both ends keeps the Mac from
//! short-circuiting traffic between the client's tunnel addresses and the
//! apps, which all live on the same machine. IPv4 only; needs root. Never
//! shipped.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::mpsc;
use warren_connector::{Backend, Forwarder};
use warren_core::bundle::IpNet;
use warren_core::packet::{self, Side};
use warren_core::utun::{self, Utun};

/// Client tunnel addresses and the peer addresses standing in for them.
#[derive(Debug)]
struct Peers {
    pool: IpNet,
    next: u32,
    by_client: HashMap<Ipv4Addr, Ipv4Addr>,
    by_peer: HashMap<Ipv4Addr, Ipv4Addr>,
}

impl Peers {
    fn peer_for(&mut self, client: Ipv4Addr) -> Option<Ipv4Addr> {
        if let Some(p) = self.by_client.get(&client) {
            return Some(*p);
        }
        let IpAddr::V4(base) = self.pool.addr else {
            return None;
        };
        let p = Ipv4Addr::from(u32::from(base).checked_add(self.next)?);
        if !self.pool.contains(IpAddr::V4(p)) {
            return None;
        }
        self.next += 1;
        self.by_client.insert(client, p);
        self.by_peer.insert(p, client);
        Some(p)
    }
}

#[derive(Debug)]
struct NatForwarder {
    utun: Arc<Utun>,
    apps: HashMap<Ipv4Addr, Ipv4Addr>,
    peers: Arc<Mutex<Peers>>,
}

impl Forwarder for NatForwarder {
    fn send(&self, raw: &[u8]) {
        let Ok(p) = packet::parse(raw) else { return };
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (p.src, p.dst) else {
            return;
        };
        let Some(local) = self.apps.get(&dst).copied() else {
            return;
        };
        let Some(peer) = self.peers.lock().expect("peers lock").peer_for(src) else {
            return;
        };
        let mut b = raw.to_vec();
        if packet::rewrite_addr(&mut b, &p, Side::Destination, IpAddr::V4(local)).is_err() {
            return;
        }
        let Ok(p2) = packet::parse(&b) else { return };
        if packet::rewrite_addr(&mut b, &p2, Side::Source, IpAddr::V4(peer)).is_err() {
            return;
        }
        if let Err(e) = self.utun.send(&b) {
            eprintln!("utun write failed: {e}");
        }
    }
}

/// Starts the backend: `apps` maps each app address to the local address
/// that serves it, and `peers` is the range client addresses are mapped
/// into. Must run inside a tokio runtime.
pub fn start(apps: Vec<(Ipv4Addr, Ipv4Addr)>, peers: IpNet) -> std::io::Result<Backend> {
    let handle = utun::open()?;
    let name = handle.name().to_owned();
    for (_, local) in &apps {
        utun::configure(&name, 1500, Some(*local), None)?;
    }
    utun::add_route(&name, &peers)?;
    let utun = Arc::new(handle.into_async()?);
    let reverse: HashMap<Ipv4Addr, Ipv4Addr> = apps.iter().map(|(a, l)| (*l, *a)).collect();
    let peers = Arc::new(Mutex::new(Peers {
        pool: peers,
        next: 2,
        by_client: HashMap::new(),
        by_peer: HashMap::new(),
    }));
    let (tx, returns) = mpsc::channel(4096);
    {
        let (utun, peers) = (utun.clone(), peers.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let n = match utun.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("utun read failed: {e}");
                        return;
                    }
                };
                let raw = &buf[..n];
                let Ok(p) = packet::parse(raw) else { continue };
                let (IpAddr::V4(src), IpAddr::V4(dst)) = (p.src, p.dst) else {
                    continue;
                };
                let (Some(app), Some(client)) = (
                    reverse.get(&src).copied(),
                    peers.lock().expect("peers lock").by_peer.get(&dst).copied(),
                ) else {
                    continue;
                };
                let mut b = raw.to_vec();
                if packet::rewrite_addr(&mut b, &p, Side::Source, IpAddr::V4(app)).is_err() {
                    continue;
                }
                let Ok(p2) = packet::parse(&b) else { continue };
                if packet::rewrite_addr(&mut b, &p2, Side::Destination, IpAddr::V4(client)).is_err()
                {
                    continue;
                }
                if tx.send(Bytes::from(b)).await.is_err() {
                    return;
                }
            }
        });
    }
    Ok(Backend {
        forwarder: Arc::new(NatForwarder {
            utun,
            apps: apps.into_iter().collect(),
            peers,
        }),
        returns,
    })
}
