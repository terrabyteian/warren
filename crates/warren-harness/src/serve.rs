//! Stand-in private apps for tests and benchmarks: TCP and UDP echo, a TCP
//! sink that counts bytes, and a TLS-over-TCP echo and sink for the
//! baseline.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Echoes every TCP connection back to itself.
pub async fn tcp_echo(addr: SocketAddr) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let _ = s.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Ok(local)
}

/// Reads and discards everything; answers each connection's end with the
/// byte count, as eight big-endian bytes.
pub async fn tcp_sink(addr: SocketAddr) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(sink_one(s));
        }
    });
    Ok(local)
}

async fn sink_one<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n as u64,
        }
    }
    let _ = s.write_all(&total.to_be_bytes()).await;
    let _ = s.shutdown().await;
}

/// Echoes UDP datagrams.
pub async fn udp_echo(addr: SocketAddr) -> std::io::Result<SocketAddr> {
    let sock = UdpSocket::bind(addr).await?;
    let local = sock.local_addr()?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    Ok(local)
}

/// A TLS 1.3 server (rustls on aws-lc-rs, warren's provider) whose
/// connections echo when the first byte is `e` and sink otherwise.
pub async fn tls_server(
    addr: SocketAddr,
    creds: warren_core::tls::Credentials,
) -> std::io::Result<SocketAddr> {
    let config = rustls::ServerConfig::builder_with_provider(warren_core::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(std::io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(creds.chain, creds.key)
        .map_err(std::io::Error::other)?;
    let acceptor = warren_masque::tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let _ = s.set_nodelay(true);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(s).await else {
                    return;
                };
                let mut mode = [0u8; 1];
                if tls.read_exact(&mut mode).await.is_err() {
                    return;
                }
                if mode[0] == b'e' {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if tls.write_all(&buf[..n]).await.is_err()
                                    || tls.flush().await.is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    sink_one(tls).await;
                }
            });
        }
    });
    Ok(local)
}
