//! The benchmark suite: connection setup time, round-trip latency and
//! throughput through a relay, against a TLS-over-TCP baseline.
//!
//! Two shapes share these measurements. The in-process suite runs a relay,
//! a connector with the userspace test backend and clients on loopback, so
//! it runs anywhere without privileges. The kernel suite
//! (scripts/bench-kernel.sh) runs the real binaries in network namespaces
//! with TUN devices on both ends and measures ordinary TCP through them.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Latency samples.
#[derive(Debug, Clone, Default)]
pub struct Samples(pub Vec<Duration>);

impl Samples {
    fn pct(&self, p: f64) -> f64 {
        if self.0.is_empty() {
            return f64::NAN;
        }
        let mut v: Vec<f64> = self.0.iter().map(|d| d.as_secs_f64() * 1e3).collect();
        v.sort_by(f64::total_cmp);
        let i = ((v.len() - 1) as f64 * p).round() as usize;
        v[i]
    }

    /// Summary in milliseconds.
    pub fn summary(&self) -> Value {
        json!({
            "n": self.0.len(),
            "p50_ms": round3(self.pct(0.5)),
            "p90_ms": round3(self.pct(0.9)),
            "p99_ms": round3(self.pct(0.99)),
        })
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Ping-pongs `size`-byte messages over an established echo stream.
pub async fn stream_rtt<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    n: usize,
    size: usize,
) -> std::io::Result<Samples> {
    let msg = vec![0x42u8; size];
    let mut back = vec![0u8; size];
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        s.write_all(&msg).await?;
        s.flush().await?;
        s.read_exact(&mut back).await?;
        out.push(t.elapsed());
    }
    Ok(Samples(out))
}

/// Writes for `secs` seconds into a sink stream and returns Mbit/s, as
/// confirmed by the sink's byte count.
pub async fn stream_throughput<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    secs: f64,
) -> std::io::Result<f64> {
    let chunk = vec![0x17u8; 128 * 1024];
    let start = Instant::now();
    let limit = Duration::from_secs_f64(secs);
    while start.elapsed() < limit {
        s.write_all(&chunk).await?;
    }
    s.shutdown().await?;
    let mut count = [0u8; 8];
    s.read_exact(&mut count).await?;
    let elapsed = start.elapsed().as_secs_f64();
    Ok(u64::from_be_bytes(count) as f64 * 8.0 / elapsed / 1e6)
}

/// Times TCP connects.
pub async fn tcp_connects(addr: SocketAddr, n: usize) -> std::io::Result<Samples> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        let s = TcpStream::connect(addr).await?;
        out.push(t.elapsed());
        drop(s);
    }
    Ok(Samples(out))
}

/// Plain TCP measurements against an echo and a sink address.
pub async fn tcp_suite(echo: SocketAddr, sink: SocketAddr, secs: f64) -> std::io::Result<Value> {
    let connect = tcp_connects(echo, 50).await?;
    let mut s = TcpStream::connect(echo).await?;
    s.set_nodelay(true)?;
    let rtt = stream_rtt(&mut s, 2000, 64).await?;
    let sink = TcpStream::connect(sink).await?;
    let mbps = stream_throughput(sink, secs).await?;
    Ok(json!({
        "connect": connect.summary(),
        "rtt_64b": rtt.summary(),
        "throughput_mbps": round3(mbps),
    }))
}

fn tls_client(ca: &rustls::pki_types::CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("valid CA");
    Arc::new(
        rustls::ClientConfig::builder_with_provider(warren_core::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn tls_connect(
    addr: SocketAddr,
    name: &str,
    config: &Arc<rustls::ClientConfig>,
    mode: u8,
) -> std::io::Result<warren_masque::tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let server_name =
        rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(std::io::Error::other)?;
    let mut tls = warren_masque::tokio_rustls::TlsConnector::from(config.clone())
        .connect(server_name, tcp)
        .await?;
    tls.write_all(&[mode]).await?;
    Ok(tls)
}

/// The TLS-over-TCP baseline: handshake time, round trips and throughput
/// against a [`crate::serve::tls_server`].
pub async fn tls_suite(
    addr: SocketAddr,
    name: &str,
    ca: &rustls::pki_types::CertificateDer<'static>,
    secs: f64,
) -> std::io::Result<Value> {
    let config = tls_client(ca);
    let mut handshakes = Vec::new();
    for _ in 0..50 {
        let t = Instant::now();
        let mut s = tls_connect(addr, name, &config, b'e').await?;
        // The handshake is done once the server can answer.
        s.write_all(b"x").await?;
        s.flush().await?;
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await?;
        handshakes.push(t.elapsed());
    }
    let mut s = tls_connect(addr, name, &config, b'e').await?;
    let rtt = stream_rtt(&mut s, 2000, 64).await?;
    let sink = tls_connect(addr, name, &config, b's').await?;
    let mbps = stream_throughput(sink, secs).await?;
    Ok(json!({
        "connect": Samples(handshakes).summary(),
        "rtt_64b": rtt.summary(),
        "throughput_mbps": round3(mbps),
    }))
}

/// The in-process suite.
pub mod inprocess {
    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};
    use warren_core::packet;
    use warren_masque::session::TransportMode;

    use super::{Samples, round3};
    use crate::deploy::{Deployment, Options, alice};

    async fn udp_rtt(t: &mut warren_client::Tunnel, n: usize) -> Samples {
        let src = SocketAddr::new(v4(t), 50_000);
        let dst: SocketAddr = "10.77.0.10:7".parse().expect("valid");
        let mut out = Vec::with_capacity(n);
        let mut msg = [0u8; 64];
        for i in 0..n {
            msg[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let pkt = packet::udp(src, dst, &msg);
            let at = Instant::now();
            t.send(&pkt);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while let Ok(Some(reply)) = tokio::time::timeout_at(deadline, t.recv()).await {
                if packet::parse(&reply).is_ok_and(|p| {
                    p.dst_sock() == src && packet::udp_payload(&reply, &p) == Some(&msg[..])
                }) {
                    out.push(at.elapsed());
                    break;
                }
            }
        }
        Samples(out)
    }

    fn v4(t: &warren_client::Tunnel) -> IpAddr {
        t.info()
            .addresses
            .iter()
            .copied()
            .find(IpAddr::is_ipv4)
            .expect("IPv4")
    }

    /// Echoed goodput with a window of packets in flight.
    async fn udp_throughput(t: &mut warren_client::Tunnel, secs: f64) -> (f64, f64) {
        let sender = t.sender();
        let src = SocketAddr::new(v4(t), 50_001);
        let dst: SocketAddr = "10.77.0.10:7".parse().expect("valid");
        let pkt = packet::udp(src, dst, &[0x33; 1252]);
        let window = 256;
        for _ in 0..window {
            sender.send(&pkt);
        }
        let start = Instant::now();
        let limit = Duration::from_secs_f64(secs);
        let (mut got, mut sent) = (0u64, window as u64);
        while start.elapsed() < limit {
            match tokio::time::timeout(Duration::from_millis(200), t.recv()).await {
                Ok(Some(reply)) if packet::parse(&reply).is_ok_and(|p| p.dst_sock() == src) => {
                    got += 1;
                    sender.send(&pkt);
                    sent += 1;
                }
                Ok(Some(_)) => {}
                // A lost packet: refill the window.
                _ => {
                    sender.send(&pkt);
                    sent += 1;
                }
            }
        }
        let elapsed = start.elapsed().as_secs_f64();
        let mbps = got as f64 * pkt.len() as f64 * 8.0 / elapsed / 1e6;
        (round3(mbps), round3(got as f64 / sent as f64))
    }

    /// Runs the suite and returns its results.
    pub async fn run(secs: f64) -> Value {
        let d = Deployment::start(Options {
            record_packets: false,
            ..Options::default()
        })
        .await;
        let mut setups = Vec::new();
        for _ in 0..20 {
            let t0 = Instant::now();
            let t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
                .await
                .expect("tunnel");
            setups.push(t0.elapsed());
            t.close();
        }
        let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
            .await
            .expect("tunnel");
        let rtt = udp_rtt(&mut t, 2000).await;
        let (mbps, delivered) = udp_throughput(&mut t, secs).await;

        // The same echo app reached directly over loopback UDP.
        let direct = {
            let s = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind");
            s.connect(d.echo).await.expect("connect");
            let mut out = Vec::new();
            let mut msg = [0u8; 64];
            let mut buf = [0u8; 2048];
            for i in 0..2000u64 {
                msg[..8].copy_from_slice(&i.to_be_bytes());
                let at = Instant::now();
                s.send(&msg).await.expect("send");
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, s.recv(&mut buf)).await {
                    if buf[..n] == msg {
                        out.push(at.elapsed());
                        break;
                    }
                }
            }
            Samples(out)
        };

        // TLS over TCP on loopback, the baseline.
        let pki = crate::pki::TestPki::new("bench.test");
        let creds = pki.relay("tls", &["tls.bench.test"]);
        let tls_addr = crate::serve::tls_server("127.0.0.1:0".parse().expect("valid"), creds)
            .await
            .expect("TLS server");
        // The server presents its leaf and the infrastructure CA; the
        // client trusts the root.
        let root = rustls::pki_types::CertificateDer::from(pki.root.cert.clone());
        let tls = super::tls_suite(tls_addr, "tls.bench.test", &root, secs)
            .await
            .unwrap_or_else(|e| json!({ "error": e.to_string() }));
        json!({
            "suite": "in-process",
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "warren": {
                "tunnel_setup": Samples(setups).summary(),
                "rtt_udp_64b": rtt.summary(),
                "throughput_udp_1280b_mbps": mbps,
                "delivered_fraction": delivered,
            },
            "direct_udp": { "rtt_udp_64b": direct.summary() },
            "tls_over_tcp": tls,
        })
    }
}
