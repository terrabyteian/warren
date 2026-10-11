//! The HTTP/2 fallback carrier (docs/protocol.md section 8): extended
//! CONNECT (RFC 8441) over TLS 1.3 on TCP, with every HTTP Datagram carried
//! in a DATAGRAM capsule on the request stream.

use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpStream;

use crate::http::{RequestHead, ResponseHead};

/// The TLS stream an HTTP/2 client runs on.
pub type ClientTls = tokio_rustls::client::TlsStream<TcpStream>;
/// The TLS stream an HTTP/2 server runs on.
pub type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;

/// An HTTP/2 carrier error.
#[derive(Debug)]
pub enum H2Error {
    /// The TCP or TLS layer failed.
    Io(std::io::Error),
    /// The HTTP/2 layer failed.
    Http2(h2::Error),
    /// The peer did not enable extended CONNECT.
    NoExtendedConnect,
    /// A malformed request or response.
    Message(String),
}

impl std::fmt::Display for H2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H2Error::Io(e) => write!(f, "TLS over TCP: {e}"),
            H2Error::Http2(e) => write!(f, "HTTP/2: {e}"),
            H2Error::NoExtendedConnect => write!(f, "peer did not enable extended CONNECT"),
            H2Error::Message(e) => write!(f, "malformed message: {e}"),
        }
    }
}

impl std::error::Error for H2Error {}

impl From<h2::Error> for H2Error {
    fn from(e: h2::Error) -> Self {
        H2Error::Http2(e)
    }
}

impl From<std::io::Error> for H2Error {
    fn from(e: std::io::Error) -> Self {
        H2Error::Io(e)
    }
}

/// Flow-control window for each tunnel stream and the connection. Tunnels
/// carry packets, so the windows are sized for throughput, not for a single
/// request body.
const WINDOW: u32 = 4 * 1024 * 1024;

/// An HTTP/2 client connection that can open extended CONNECT streams.
#[derive(Debug, Clone)]
pub struct H2Client {
    send_request: h2::client::SendRequest<Bytes>,
}

impl H2Client {
    /// Performs the TLS and HTTP/2 handshakes and waits for the server's
    /// SETTINGS to enable extended CONNECT.
    pub async fn connect(
        tcp: TcpStream,
        tls: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<(H2Client, ClientTlsInfo), H2Error> {
        tcp.set_nodelay(true)?;
        let tls = tokio_rustls::TlsConnector::from(tls)
            .connect(server_name, tcp)
            .await?;
        let info = ClientTlsInfo {
            peer_certificates: tls
                .get_ref()
                .1
                .peer_certificates()
                .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
                .unwrap_or_default(),
        };
        let (send_request, connection) = h2::client::Builder::new()
            .initial_window_size(WINDOW)
            .initial_connection_window_size(WINDOW)
            .handshake::<_, Bytes>(tls)
            .await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(error = %e, "HTTP/2 connection ended");
            }
        });
        let mut send_request = send_request.ready().await?;
        // h2 sends nothing until told, and exposes no event for the peer's
        // SETTINGS; poll briefly for extended CONNECT to be enabled.
        let deadline = tokio::time::Instant::now() + crate::h3::SETTINGS_TIMEOUT;
        while !send_request.is_extended_connect_protocol_enabled() {
            if tokio::time::Instant::now() >= deadline {
                return Err(H2Error::NoExtendedConnect);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
            send_request = send_request.ready().await?;
        }
        Ok((H2Client { send_request }, info))
    }

    /// Sends an extended CONNECT request and waits for the response.
    pub async fn send_request(
        &mut self,
        head: &RequestHead,
    ) -> Result<(ResponseHead, h2::SendStream<Bytes>, h2::RecvStream), H2Error> {
        let uri = format!(
            "{}://{}{}",
            head.scheme.as_deref().unwrap_or("https"),
            head.authority.as_deref().unwrap_or_default(),
            head.path.as_deref().unwrap_or("/"),
        );
        let mut builder = ::http::Request::builder()
            .method(head.method.as_str())
            .uri(uri);
        for (n, v) in &head.headers {
            builder = builder.header(n.as_str(), v.as_str());
        }
        if let Some(p) = &head.protocol {
            builder = builder.extension(h2::ext::Protocol::from(p.as_str()));
        }
        let request = builder
            .body(())
            .map_err(|e| H2Error::Message(e.to_string()))?;
        let mut ready = self.send_request.clone().ready().await?;
        let (response, send) = ready.send_request(request, false)?;
        let response = response.await?;
        let (parts, recv) = response.into_parts();
        let head = ResponseHead {
            status: parts.status.as_u16(),
            headers: header_pairs(&parts.headers)?,
        };
        Ok((head, send, recv))
    }
}

/// What the client learned from the TLS handshake.
#[derive(Debug, Clone)]
pub struct ClientTlsInfo {
    /// The server's certificate chain.
    pub peer_certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
}

fn header_pairs(map: &::http::HeaderMap) -> Result<Vec<(String, String)>, H2Error> {
    map.iter()
        .map(|(n, v)| {
            let v = v
                .to_str()
                .map_err(|_| H2Error::Message(format!("non-ASCII value for {n}")))?;
            Ok((n.as_str().to_owned(), v.to_owned()))
        })
        .collect()
}

/// An accepted HTTP/2 server connection.
pub struct H2Server {
    conn: h2::server::Connection<ServerTls, Bytes>,
}

impl std::fmt::Debug for H2Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Server").finish_non_exhaustive()
    }
}

/// A request accepted on an HTTP/2 server connection.
pub struct H2Request {
    /// The request head.
    pub head: RequestHead,
    /// The request body (the tunnel's incoming capsules).
    pub recv: h2::RecvStream,
    /// Where to send the response.
    pub respond: h2::server::SendResponse<Bytes>,
}

impl std::fmt::Debug for H2Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Request")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

impl H2Request {
    /// Sends the response head; for a 2xx the returned stream carries the
    /// tunnel's outgoing capsules.
    pub fn respond(
        &mut self,
        head: &ResponseHead,
        end: bool,
    ) -> Result<h2::SendStream<Bytes>, H2Error> {
        let mut builder = ::http::Response::builder().status(head.status);
        for (n, v) in &head.headers {
            builder = builder.header(n.as_str(), v.as_str());
        }
        let response = builder
            .body(())
            .map_err(|e| H2Error::Message(e.to_string()))?;
        Ok(self.respond.send_response(response, end)?)
    }
}

impl H2Server {
    /// Performs the HTTP/2 handshake on an accepted TLS stream, enabling
    /// extended CONNECT.
    pub async fn handshake(tls: ServerTls) -> Result<H2Server, H2Error> {
        let mut builder = h2::server::Builder::new();
        builder
            .enable_connect_protocol()
            .initial_window_size(WINDOW)
            .initial_connection_window_size(WINDOW);
        let conn = builder.handshake(tls).await?;
        Ok(H2Server { conn })
    }

    /// Accepts the next request; `None` when the connection ends. The
    /// connection only makes progress while this is being polled, so callers
    /// keep calling it from one task and hand requests to others.
    pub async fn accept(&mut self) -> Option<Result<H2Request, H2Error>> {
        let (request, respond) = match self.conn.accept().await? {
            Ok(r) => r,
            Err(e) => return Some(Err(e.into())),
        };
        let (parts, recv) = request.into_parts();
        let headers = match header_pairs(&parts.headers) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };
        let head = RequestHead {
            method: parts.method.as_str().to_owned(),
            scheme: parts.uri.scheme_str().map(str::to_owned),
            authority: parts.uri.authority().map(|a| a.as_str().to_owned()),
            path: parts.uri.path_and_query().map(|p| p.as_str().to_owned()),
            protocol: parts
                .extensions
                .get::<h2::ext::Protocol>()
                .map(|p| p.as_str().to_owned()),
            headers,
        };
        Some(Ok(H2Request {
            head,
            recv,
            respond,
        }))
    }

    /// Starts a graceful shutdown (GOAWAY).
    pub fn graceful_shutdown(&mut self) {
        self.conn.graceful_shutdown();
    }
}

/// Writes all of `data` to an HTTP/2 stream, waiting for flow-control
/// capacity.
pub async fn send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<(), H2Error> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let granted = match poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Err(e.into()),
            None => return Err(H2Error::Message("stream closed".into())),
        };
        if granted == 0 {
            continue;
        }
        let chunk = data.split_to(granted.min(data.len()));
        send.send_data(chunk, false)?;
    }
    Ok(())
}

/// Reads the next body chunk and returns its flow-control credit at once.
pub async fn recv_chunk(recv: &mut h2::RecvStream) -> Result<Option<Bytes>, H2Error> {
    match recv.data().await {
        None => Ok(None),
        Some(Err(e)) => Err(e.into()),
        Some(Ok(b)) => {
            let _ = recv.flow_control().release_capacity(b.len());
            Ok(Some(b))
        }
    }
}
