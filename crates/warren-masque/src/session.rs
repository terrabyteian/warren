//! Carrier-independent connection handling: dialling a relay over QUIC
//! with the HTTP/2 fallback raced behind it (docs/protocol.md section 8),
//! opening tunnels on an outer connection, and answering requests on either
//! carrier.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;

use crate::connect::Refusal;
use crate::h2::{H2Client, H2Error, H2Request};
use crate::h3::{H3Connection, H3Error, RequestStream};
use crate::http::{RequestHead, ResponseHead};
use crate::tunnel::{self, CarrierKind, TunnelReceiver, TunnelSender};

/// An outer connection to a relay.
#[derive(Debug, Clone)]
pub enum OuterConn {
    /// HTTP/3 over QUIC.
    H3(Arc<H3Connection>),
    /// HTTP/2 over TLS over TCP.
    H2(H2Client),
}

/// Why opening a tunnel failed.
#[derive(Debug)]
pub enum OpenError {
    /// The peer answered with a non-2xx status.
    Refused(Refusal),
    /// The carrier failed.
    Carrier(String),
    /// The HTTP/3 connection ran out of quarter stream IDs; dial again.
    StreamLimit,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Refused(r) => write!(f, "refused ({} {}): {}", r.status, r.error, r.details),
            OpenError::Carrier(e) => write!(f, "{e}"),
            OpenError::StreamLimit => write!(f, "stream budget exhausted"),
        }
    }
}

impl std::error::Error for OpenError {}

/// A tunnel opened on an outer connection, with the response head.
pub type Opened = (ResponseHead, TunnelSender, TunnelReceiver);

impl OuterConn {
    /// The carrier.
    pub fn carrier(&self) -> CarrierKind {
        match self {
            OuterConn::H3(_) => CarrierKind::Http3,
            OuterConn::H2(_) => CarrierKind::Http2,
        }
    }

    /// Sends an extended CONNECT and starts a tunnel on a 2xx answer.
    pub async fn open_tunnel(
        &self,
        head: &RequestHead,
        deliver_limit: usize,
    ) -> Result<Opened, OpenError> {
        match self {
            OuterConn::H3(conn) => {
                let (resp, stream) = conn.send_request(head).await.map_err(|e| match e {
                    H3Error::StreamLimit => OpenError::StreamLimit,
                    e => OpenError::Carrier(e.to_string()),
                })?;
                if !(200..300).contains(&resp.status) {
                    return Err(OpenError::Refused(Refusal::from_response(&resp)));
                }
                let (tx, rx) = tunnel::from_h3(stream, deliver_limit);
                Ok((resp, tx, rx))
            }
            OuterConn::H2(client) => {
                let mut client = client.clone();
                let (resp, send, recv) = client
                    .send_request(head)
                    .await
                    .map_err(|e| OpenError::Carrier(e.to_string()))?;
                if !(200..300).contains(&resp.status) {
                    return Err(OpenError::Refused(Refusal::from_response(&resp)));
                }
                let (tx, rx) = tunnel::from_h2(send, recv);
                Ok((resp, tx, rx))
            }
        }
    }

    /// Closes the connection.
    pub fn close(&self, reason: &str) {
        if let OuterConn::H3(c) = self {
            c.close(crate::h3::code::NO_ERROR, reason);
        }
    }
}

/// A request waiting for an answer, on either carrier.
#[derive(Debug)]
pub enum Incoming {
    /// On an HTTP/3 connection.
    H3(RequestStream),
    /// On an HTTP/2 connection.
    H2(H2Request),
}

impl Incoming {
    /// Answers with a refusal and drops the request.
    pub async fn refuse(self, refusal: &Refusal, proxy: &str) {
        let resp = refusal.response(proxy);
        match self {
            Incoming::H3(mut s) => {
                if s.respond(&resp).await.is_ok() {
                    let _ = s.send.finish();
                }
            }
            Incoming::H2(mut r) => {
                let _ = r.respond(&resp, true);
            }
        }
    }

    /// Answers 2xx with `resp` and starts the tunnel.
    pub async fn accept(
        self,
        resp: &ResponseHead,
        deliver_limit: usize,
    ) -> Result<(TunnelSender, TunnelReceiver), String> {
        match self {
            Incoming::H3(mut s) => {
                s.respond(resp).await.map_err(|e| e.to_string())?;
                Ok(tunnel::from_h3(s, deliver_limit))
            }
            Incoming::H2(mut r) => {
                let send = r.respond(resp, false).map_err(|e| e.to_string())?;
                Ok(tunnel::from_h2(send, r.recv))
            }
        }
    }
}

/// How to reach a relay.
#[derive(Debug, Clone)]
pub struct RelayAddress {
    /// The relay's DNS name: TLS server name and `:authority`.
    pub name: String,
    /// The UDP address for QUIC.
    pub quic: SocketAddr,
    /// The TCP address for the HTTP/2 fallback.
    pub tcp: SocketAddr,
}

/// Which carriers a dial may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// QUIC first, HTTP/2 raced after the fallback delay.
    Auto,
    /// QUIC only.
    QuicOnly,
    /// HTTP/2 only.
    Http2Only,
}

/// A dial error.
#[derive(Debug)]
pub struct DialError {
    /// What went wrong.
    pub message: String,
    /// The relay rejected this client's certificate as revoked or expired:
    /// retrying with the same credentials cannot succeed.
    pub credentials_rejected: bool,
}

impl DialError {
    fn new(message: impl Into<String>) -> DialError {
        DialError {
            message: message.into(),
            credentials_rejected: false,
        }
    }
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// TLS alerts that mean the peer rejected our certificate for good.
const ALERT_CERTIFICATE_REVOKED: u8 = 0x2c;
const ALERT_CERTIFICATE_EXPIRED: u8 = 0x2d;

fn quic_rejected(e: &quinn::ConnectionError) -> bool {
    match e {
        quinn::ConnectionError::ConnectionClosed(c) => {
            c.error_code == quinn::TransportErrorCode::crypto(ALERT_CERTIFICATE_REVOKED)
                || c.error_code == quinn::TransportErrorCode::crypto(ALERT_CERTIFICATE_EXPIRED)
        }
        _ => false,
    }
}

fn tls_rejected(e: &std::io::Error) -> bool {
    matches!(
        e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(
            rustls::AlertDescription::CertificateRevoked
                | rustls::AlertDescription::CertificateExpired
        ))
    )
}

impl std::error::Error for DialError {}

/// How long a QUIC handshake may take before the dial gives up.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Dials over QUIC and starts HTTP/3, checking the peer supports MASQUE.
pub async fn dial_quic(
    endpoint: &quinn::Endpoint,
    relay: &RelayAddress,
    config: quinn::ClientConfig,
) -> Result<(Arc<H3Connection>, Vec<CertificateDer<'static>>), DialError> {
    let connecting = endpoint
        .connect_with(config, relay.quic, &relay.name)
        .map_err(|e| DialError::new(format!("QUIC connect: {e}")))?;
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .map_err(|_| DialError::new(format!("QUIC handshake with {} timed out", relay.name)))?
        .map_err(|e| DialError {
            message: format!("QUIC handshake with {}: {e}", relay.name),
            credentials_rejected: quic_rejected(&e),
        })?;
    let certs = peer_certificates(&conn);
    // TLS 1.3 servers check the client certificate after the client has
    // finished its handshake, so a rejection can surface here.
    let h3_error = |e: H3Error| DialError {
        credentials_rejected: matches!(&e, H3Error::Connection(c) if quic_rejected(c)),
        message: e.to_string(),
    };
    let h3 = H3Connection::new(conn, false).await.map_err(h3_error)?;
    if let Err(e) = h3.require_masque().await {
        h3.close(crate::h3::code::SETTINGS_ERROR, "MASQUE unsupported");
        return Err(h3_error(e));
    }
    Ok((h3, certs))
}

/// The peer's certificate chain on a QUIC connection.
pub fn peer_certificates(conn: &quinn::Connection) -> Vec<CertificateDer<'static>> {
    conn.peer_identity()
        .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
        .map(|b| *b)
        .unwrap_or_default()
}

/// Dials over TLS on TCP and starts HTTP/2.
pub async fn dial_h2(
    relay: &RelayAddress,
    tls: Arc<rustls::ClientConfig>,
) -> Result<H2Client, DialError> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(relay.tcp))
        .await
        .map_err(|_| DialError::new(format!("TCP connect to {} timed out", relay.tcp)))?
        .map_err(|e| DialError::new(format!("TCP connect to {}: {e}", relay.tcp)))?;
    let name =
        ServerName::try_from(relay.name.clone()).map_err(|e| DialError::new(e.to_string()))?;
    let (client, _) = H2Client::connect(tcp, tls, name).await.map_err(|e| match e {
        H2Error::Io(io) if tls_rejected(&io) => DialError {
            message: format!("TLS to {}: {io}", relay.name),
            credentials_rejected: true,
        },
        H2Error::Http2(e) if e.get_io().is_some_and(tls_rejected) => DialError {
            message: format!("HTTP/2 to {}: {e}", relay.name),
            credentials_rejected: true,
        },
        H2Error::Io(io) if io.kind() == std::io::ErrorKind::InvalidData => {
            // rustls reports certificate failures as invalid data; a pinned
            // trust bundle failing on a reachable relay usually means the
            // network intercepts TLS (docs/protocol.md section 8).
            DialError::new(format!(
                "TLS to {} failed certificate verification (is the network intercepting TLS?): {io}",
                relay.name
            ))
        }
        e => DialError::new(format!("HTTP/2 to {}: {e}", relay.name)),
    })?;
    Ok(client)
}

fn combine(quic: DialError, h2: DialError) -> DialError {
    DialError {
        message: format!("{quic}; {h2}"),
        credentials_rejected: quic.credentials_rejected || h2.credentials_rejected,
    }
}

/// Dials a relay: QUIC first, and HTTP/2 in parallel if no QUIC handshake
/// completes within `fallback_delay`; whichever completes first wins, with
/// QUIC preferred when both are ready.
pub async fn dial(
    mode: TransportMode,
    endpoint: &quinn::Endpoint,
    relay: &RelayAddress,
    quic_config: quinn::ClientConfig,
    h2_tls: Arc<rustls::ClientConfig>,
    fallback_delay: Duration,
) -> Result<OuterConn, DialError> {
    match mode {
        TransportMode::QuicOnly => Ok(OuterConn::H3(
            dial_quic(endpoint, relay, quic_config).await?.0,
        )),
        TransportMode::Http2Only => Ok(OuterConn::H2(dial_h2(relay, h2_tls).await?)),
        TransportMode::Auto => {
            let quic = dial_quic(endpoint, relay, quic_config);
            tokio::pin!(quic);
            let quic_err = tokio::select! {
                biased;
                r = &mut quic => match r {
                    Ok((c, _)) => return Ok(OuterConn::H3(c)),
                    Err(e) => Some(e),
                },
                () = tokio::time::sleep(fallback_delay) => None,
            };
            let h2 = dial_h2(relay, h2_tls);
            tokio::pin!(h2);
            if let Some(qe) = quic_err {
                return h2.await.map(OuterConn::H2).map_err(|he| combine(qe, he));
            }
            let mut h2_err = None;
            loop {
                tokio::select! {
                    biased;
                    r = &mut quic => match r {
                        Ok((c, _)) => return Ok(OuterConn::H3(c)),
                        Err(qe) => {
                            return match h2_err {
                                Some(he) => Err(combine(qe, he)),
                                None => h2.await.map(OuterConn::H2).map_err(|he| combine(qe, he)),
                            };
                        }
                    },
                    r = &mut h2, if h2_err.is_none() => match r {
                        Ok(c) => return Ok(OuterConn::H2(c)),
                        Err(he) => h2_err = Some(he),
                    },
                }
            }
        }
    }
}
