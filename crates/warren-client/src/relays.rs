//! Relay choice (docs/design.md section 5.2): the client measures every
//! relay it may use and dials the lowest-latency one first, keeping the
//! rest, in order, for when that relay is lost.
//!
//! The measurement is a TCP connection to the relay's port 443, which the
//! HTTP/2 fallback listens on: one round trip, no credentials, and no
//! state left on the relay.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use warren_core::api::Relay;
use warren_masque::session::RelayAddress;

/// How long a relay gets to answer the probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// A relay, where it is, and how long it took to answer.
#[derive(Debug, Clone)]
pub struct Ranked {
    /// The relay's dial address.
    pub address: RelayAddress,
    /// The probe's round trip, or `None` if it did not answer.
    pub rtt: Option<Duration>,
}

/// Resolves every relay's first name that resolves, on `port`.
pub async fn resolve(relays: &[Relay], port: u16) -> Vec<RelayAddress> {
    let mut out = Vec::new();
    for r in relays {
        for name in &r.dns_names {
            let Ok(mut addrs) = tokio::net::lookup_host((name.as_str(), port)).await else {
                continue;
            };
            // Prefer IPv4 where both exist: the device's network more
            // often routes it, and the probe below catches the rest.
            let all: Vec<SocketAddr> = addrs.by_ref().collect();
            if let Some(addr) = all.iter().find(|a| a.is_ipv4()).or(all.first()) {
                out.push(RelayAddress {
                    name: name.clone(),
                    quic: *addr,
                    tcp: *addr,
                });
                break;
            }
        }
    }
    out
}

/// Probes every relay at once and orders them: answering relays by round
/// trip, then the rest in their original order (UDP may still reach a
/// relay whose TCP port is blocked).
pub async fn rank(relays: Vec<RelayAddress>) -> Vec<Ranked> {
    let probes = relays.into_iter().map(|address| async move {
        let start = Instant::now();
        let ok = matches!(
            tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(address.tcp)).await,
            Ok(Ok(_))
        );
        Ranked {
            rtt: ok.then(|| start.elapsed()),
            address,
        }
    });
    let mut ranked = Vec::new();
    for p in probes.map(tokio::spawn).collect::<Vec<_>>() {
        if let Ok(r) = p.await {
            ranked.push(r);
        }
    }
    // A stable sort keeps the original order among relays that did not
    // answer.
    ranked.sort_by_key(|r| r.rtt.unwrap_or(Duration::MAX));
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn answering_relays_come_first() {
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        // A port nothing listens on: refused at once.
        let down_addr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let relay = |name: &str, addr: SocketAddr| RelayAddress {
            name: name.into(),
            quic: addr,
            tcp: addr,
        };
        let ranked = rank(vec![relay("down", down_addr), relay("up", up_addr)]).await;
        assert_eq!(ranked[0].address.name, "up");
        assert!(ranked[0].rtt.is_some());
        assert_eq!(ranked[1].address.name, "down");
        assert!(ranked[1].rtt.is_none());
    }

    #[tokio::test]
    async fn relays_resolve_by_their_first_working_name() {
        let relays = vec![Relay {
            id: "r-1".into(),
            name: "relay-1".into(),
            dns_names: vec!["no-such-host.invalid".into(), "localhost".into()],
        }];
        let addrs = resolve(&relays, 4443).await;
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].name, "localhost");
        assert_eq!(addrs[0].quic.port(), 4443);
    }
}
