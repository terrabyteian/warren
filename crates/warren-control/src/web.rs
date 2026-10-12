//! HTTP plumbing: the TLS listener, the local admin socket, a minimal HTTPS
//! client, and helpers for JSON bodies and RFC 9457 problems.
//!
//! TLS is rustls on aws-lc-rs, TLS 1.3 only, no 0-RTT (G16,
//! docs/protocol.md section 3).

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue, LOCATION};
use http::{Request, Response, StatusCode};
use http_body::{Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::RootCertStore;
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use warren_core::api::Problem;
use warren_core::params::{PROTOCOL_HEADER, PROTOCOL_VERSION};
use warren_policy::names::Cidr;

use crate::Error;

/// A response body: fixed or streaming.
pub type Body = BoxBody<Bytes, Infallible>;

/// The largest request body any endpoint reads, unless it says otherwise.
pub const MAX_BODY: usize = 1 << 20;

/// A fixed body.
pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).boxed()
}

fn with_protocol(mut resp: Response<Body>) -> Response<Body> {
    resp.headers_mut().insert(
        PROTOCOL_HEADER,
        HeaderValue::from_str(&PROTOCOL_VERSION.to_string())
            .unwrap_or(HeaderValue::from_static("1")),
    );
    resp.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    resp
}

/// A JSON response.
pub fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    match serde_json::to_vec(value) {
        Ok(bytes) => {
            let mut resp = Response::new(full(bytes));
            *resp.status_mut() = status;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            with_protocol(resp)
        }
        Err(_) => problem(&ApiError::internal()),
    }
}

/// A body of another content type.
pub fn body(
    status: StatusCode,
    content_type: &'static str,
    bytes: impl Into<Bytes>,
) -> Response<Body> {
    let mut resp = Response::new(full(bytes));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    with_protocol(resp)
}

/// A streaming body fed through a channel.
pub fn stream(content_type: &'static str, rx: mpsc::Receiver<Bytes>) -> Response<Body> {
    let mut resp = Response::new(ChannelBody(rx).boxed());
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    with_protocol(resp)
}

/// A 302 redirect.
pub fn redirect(location: &str) -> Response<Body> {
    redirect_with(StatusCode::FOUND, location)
}

/// A 303 redirect, after a form is posted.
pub fn see_other(location: &str) -> Response<Body> {
    redirect_with(StatusCode::SEE_OTHER, location)
}

fn redirect_with(status: StatusCode, location: &str) -> Response<Body> {
    let mut resp = Response::new(full(Bytes::new()));
    *resp.status_mut() = status;
    match HeaderValue::from_str(location) {
        Ok(v) => {
            resp.headers_mut().insert(LOCATION, v);
            with_protocol(resp)
        }
        Err(_) => problem(&ApiError::internal()),
    }
}

/// Escapes text for HTML.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A plain HTML page with a title and one paragraph, for the browser during
/// sign-in. Both strings are escaped.
pub fn page(status: StatusCode, title: &str, text: &str) -> Response<Body> {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>{}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
        escape_html(title),
        escape_html(title),
        escape_html(text)
    );
    let mut resp = body(status, "text/html; charset=utf-8", html);
    resp.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'"),
    );
    resp
}

/// An error an endpoint returns, as an RFC 9457 problem with a stable
/// reason code and a human-readable detail (G12).
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable reason code.
    pub reason: &'static str,
    /// What happened and what to do.
    pub detail: String,
}

impl ApiError {
    /// A new error.
    pub fn new(status: StatusCode, reason: &'static str, detail: impl Into<String>) -> ApiError {
        ApiError {
            status,
            reason,
            detail: detail.into(),
        }
    }

    /// 400 with reason `bad_request`.
    pub fn bad_request(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_request", detail)
    }

    /// 401 with reason `unauthenticated`.
    pub fn unauthenticated(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated", detail)
    }

    /// 404 with reason `not_found`.
    pub fn not_found(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, "not_found", detail)
    }

    /// 500 with no internal detail.
    pub fn internal() -> ApiError {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "The control plane hit an internal error; the operator's logs have the details.",
        )
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> ApiError {
        match e {
            Error::BadRequest(d) => ApiError::bad_request(d),
            Error::Conflict(d) => ApiError::new(StatusCode::CONFLICT, "conflict", d),
            Error::Unavailable(d) => {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", d)
            }
            Error::Idp(d) => {
                crate::log::error("idp", &d);
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "idp_error",
                    "The identity provider could not complete the sign-in. Try again; if it keeps failing, tell your administrator.",
                )
            }
            other => {
                crate::log::error("internal", &other.to_string());
                ApiError::internal()
            }
        }
    }
}

fn title(status: StatusCode) -> String {
    status.canonical_reason().unwrap_or("Error").to_owned()
}

/// The response for an error.
pub fn problem(e: &ApiError) -> Response<Body> {
    let p = Problem {
        status: e.status.as_u16(),
        reason: e.reason.into(),
        title: title(e.status),
        detail: e.detail.clone(),
    };
    let mut resp = Response::new(full(serde_json::to_vec(&p).unwrap_or_default()));
    *resp.status_mut() = e.status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    with_protocol(resp)
}

/// How long a client may take to send a request body.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// Reads a whole request body, up to `limit` bytes and within
/// `BODY_TIMEOUT`.
pub async fn read_body(req: Request<Incoming>, limit: usize) -> Result<Bytes, ApiError> {
    let collected =
        tokio::time::timeout(BODY_TIMEOUT, Limited::new(req.into_body(), limit).collect())
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "request_timeout",
                    "The request body took too long to arrive.",
                )
            })?;
    collected.map(|c| c.to_bytes()).map_err(|e| {
        if e.downcast_ref::<http_body_util::LengthLimitError>()
            .is_some()
        {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                format!("request bodies are limited to {limit} bytes"),
            )
        } else {
            ApiError::bad_request("the request body could not be read")
        }
    })
}

/// Reads a JSON request body.
pub async fn read_json<T: DeserializeOwned>(req: Request<Incoming>) -> Result<T, ApiError> {
    let bytes = read_body(req, MAX_BODY).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON body: {e}")))
}

/// The query parameters of a request; a repeated parameter is an error,
/// since sign-in parameters must be unambiguous.
pub fn query<B>(req: &Request<B>) -> Result<Vec<(String, String)>, ApiError> {
    let pairs: Vec<(String, String)> =
        form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    for (i, (k, _)) in pairs.iter().enumerate() {
        if pairs[..i].iter().any(|(other, _)| other == k) {
            return Err(ApiError::bad_request(format!("parameter {k} is repeated")));
        }
    }
    Ok(pairs)
}

/// Looks up a query parameter.
pub fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Checks the `Warren-Protocol` header when present.
pub fn check_protocol<B>(req: &Request<B>) -> Result<(), ApiError> {
    match req.headers().get(PROTOCOL_HEADER) {
        None => Ok(()),
        Some(v)
            if v.to_str().ok().and_then(|v| v.parse::<u32>().ok()) == Some(PROTOCOL_VERSION) =>
        {
            Ok(())
        }
        Some(_) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_protocol",
            format!("this control plane speaks warren protocol {PROTOCOL_VERSION}"),
        )),
    }
}

struct ChannelBody(mpsc::Receiver<Bytes>);

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|b| b.map(|b| Ok(Frame::data(b))))
    }
}

/// The certificates a TLS client presented, already verified by rustls to
/// chain to one of the deployment's issuing CAs, with proof of the key.
#[derive(Debug, Default)]
pub struct Peer {
    /// The chain, leaf first; empty when the client presented none.
    pub certificates: Vec<CertificateDer<'static>>,
    /// The client's address: the source a trusted proxy reported, or the
    /// connection's own.
    pub addr: Option<SocketAddr>,
    /// The name the client asked for in TLS (SNI).
    pub server_name: Option<String>,
}

/// Whether `server_name` is one of `internal_names`, where the control plane
/// always presents its own certificate.
pub fn is_internal_name(internal_names: &[String], server_name: Option<&str>) -> bool {
    server_name.is_some_and(|name| internal_names.iter().any(|n| n.eq_ignore_ascii_case(name)))
}

/// Something that answers requests.
pub trait Handler: Send + Sync + 'static {
    /// Answers one request.
    fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: Arc<Peer>,
    ) -> impl Future<Output = Response<Body>> + Send;
}

/// The control plane's server certificates: its own, from the
/// infrastructure CA, and optionally one the operator supplies for the
/// public host. Both are replaceable while running, so they can be renewed
/// without restarting.
#[derive(Debug)]
pub struct ServerCert {
    own: RwLock<Arc<CertifiedKey>>,
    operator: RwLock<Option<Arc<CertifiedKey>>>,
    internal_names: Vec<String>,
}

impl ServerCert {
    /// The control plane's own certificate chain and PKCS#8 key, presented
    /// for every name until an operator certificate is set, and for
    /// `internal_names` always.
    pub fn new(
        chain: Vec<Vec<u8>>,
        pkcs8: &[u8],
        internal_names: Vec<String>,
    ) -> Result<ServerCert, Error> {
        Ok(ServerCert {
            own: RwLock::new(Arc::new(certified_key(
                chain,
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
            )?)),
            operator: RwLock::new(None),
            internal_names,
        })
    }

    /// Replaces the control plane's own certificate.
    pub fn replace(&self, chain: Vec<Vec<u8>>, pkcs8: &[u8]) -> Result<(), Error> {
        let key = Arc::new(certified_key(
            chain,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
        )?);
        if let Ok(mut slot) = self.own.write() {
            *slot = key;
        }
        Ok(())
    }

    /// Sets the operator's certificate, presented for every name but the
    /// internal ones: a PEM chain, leaf first, and an unencrypted PEM key
    /// (`PRIVATE KEY`, `EC PRIVATE KEY` or `RSA PRIVATE KEY`) that must
    /// match the leaf.
    pub fn set_operator(&self, chain_pem: &str, key_pem: &str) -> Result<(), Error> {
        let pem = |e: rustls::pki_types::pem::Error| Error::Tls(format!("PEM: {e}"));
        let chain: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
            .map(|c| c.map(|c| c.to_vec()))
            .collect::<Result<_, _>>()
            .map_err(pem)?;
        if chain.is_empty() {
            return Err(Error::Tls(
                "no CERTIFICATE block in the certificate file".into(),
            ));
        }
        let mut keys = Vec::new();
        for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(key_pem.as_bytes()) {
            match section.map_err(pem)? {
                (SectionKind::PrivateKey, der) => keys.push(PrivateKeyDer::Pkcs8(der.into())),
                (SectionKind::EcPrivateKey, der) => keys.push(PrivateKeyDer::Sec1(der.into())),
                (SectionKind::RsaPrivateKey, der) => keys.push(PrivateKeyDer::Pkcs1(der.into())),
                _ => {}
            }
        }
        let [key] = <[_; 1]>::try_from(keys).map_err(|_| {
            Error::Tls(
                "the key file must hold exactly one unencrypted PRIVATE KEY, EC PRIVATE KEY or RSA PRIVATE KEY block".into(),
            )
        })?;
        let certified = certified_key(chain, key)?;
        certified
            .keys_match()
            .map_err(|e| Error::Tls(format!("the key does not match the certificate: {e}")))?;
        if let Ok(mut slot) = self.operator.write() {
            *slot = Some(Arc::new(certified));
        }
        Ok(())
    }
}

fn certified_key(chain: Vec<Vec<u8>>, key: PrivateKeyDer<'static>) -> Result<CertifiedKey, Error> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(CertifiedKey::new(
        chain.into_iter().map(CertificateDer::from).collect(),
        key,
    ))
}

impl ResolvesServerCert for ServerCert {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !is_internal_name(&self.internal_names, hello.server_name())
            && let Ok(operator) = self.operator.read()
            && let Some(key) = operator.as_ref()
        {
            return Some(key.clone());
        }
        self.own.read().ok().map(|k| k.clone())
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The listener's TLS configuration: TLS 1.3 only, ALPN `h2` and
/// `http/1.1`, and an optional client certificate that must chain to one of
/// `client_anchors` (the client CA and the infrastructure CA).
pub fn server_config(
    cert: Arc<ServerCert>,
    client_anchors: &[Vec<u8>],
) -> Result<Arc<rustls::ServerConfig>, Error> {
    let mut roots = RootCertStore::empty();
    for der in client_anchors {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| Error::Tls(e.to_string()))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
        .allow_unauthenticated()
        .build()
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(cert);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    // No session resumption: every connection presents its certificate
    // afresh, so a session never outlives the certificate behind it
    // (docs/protocol.md section 3).
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The most connections the HTTPS listener holds at once. Beyond it new
/// connections are closed at once, so slow or idle clients cannot exhaust
/// the process's file descriptors.
const MAX_CONNECTIONS: usize = 4096;

/// The default for [`ListenOptions::max_per_source`].
pub const MAX_CONNECTIONS_PER_SOURCE: usize = 64;

/// How the HTTPS listener treats sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenOptions {
    /// The most connections one source (an IPv4 address, or an IPv6 /64)
    /// holds before they authenticate. Beyond it the source's new
    /// connections are closed at once, so no single source can take every
    /// slot of [`MAX_CONNECTIONS`]. A connection that presents a client
    /// certificate the listener verifies stops counting. 0 means no limit.
    pub max_per_source: usize,
    /// Load balancers and proxies whose connections start with a PROXY
    /// protocol version 2 header naming the real source. Connections from
    /// them must carry one; nobody else's are read for one.
    pub trusted_proxies: Vec<Cidr>,
}

impl Default for ListenOptions {
    fn default() -> ListenOptions {
        ListenOptions {
            max_per_source: MAX_CONNECTIONS_PER_SOURCE,
            trusted_proxies: Vec::new(),
        }
    }
}

/// The PROXY protocol version 2 signature.
const PROXY_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// The source a PROXY protocol version 2 header names, given its fixed
/// 16-byte start and the `len` bytes after it, for a connection from
/// `proxy`. Only `LOCAL` (the proxy's own connection, such as a health
/// check) and `PROXY` over TCP on IPv4 or IPv6 are accepted.
fn proxy_source(head: &[u8; 16], body: &[u8], proxy: SocketAddr) -> Option<SocketAddr> {
    if head[..12] != PROXY_SIGNATURE
        || usize::from(u16::from_be_bytes([head[14], head[15]])) != body.len()
    {
        return None;
    }
    match (head[12], head[13]) {
        (0x20, _) => Some(proxy),
        (0x21, 0x11) if body.len() >= 12 => {
            let ip: [u8; 4] = body[..4].try_into().ok()?;
            let port = u16::from_be_bytes([body[8], body[9]]);
            Some(SocketAddr::from((ip, port)))
        }
        (0x21, 0x21) if body.len() >= 36 => {
            let ip: [u8; 16] = body[..16].try_into().ok()?;
            let port = u16::from_be_bytes([body[32], body[33]]);
            Some(SocketAddr::from((ip, port)))
        }
        _ => None,
    }
}

/// Reads the PROXY protocol version 2 header a trusted proxy sends first,
/// and returns the source it names.
async fn read_proxy_header(tcp: &mut TcpStream, proxy: SocketAddr) -> Option<SocketAddr> {
    use tokio::io::AsyncReadExt;
    let mut head = [0u8; 16];
    tcp.read_exact(&mut head).await.ok()?;
    if head[..12] != PROXY_SIGNATURE {
        return None;
    }
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([head[14], head[15]]))];
    tcp.read_exact(&mut body).await.ok()?;
    proxy_source(&head, &body, proxy)
}

/// The most requests one HTTP/2 connection may have in progress at once.
const MAX_CONCURRENT_STREAMS: u32 = 32;

/// How long a connection may stay open with no request in progress. A
/// request counts until its response body is finished, so event streams
/// keep their connection.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the accept loops pause after a failed accept (such as running
/// out of file descriptors) before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The requests a connection has in progress, from the moment each arrives
/// until its response body is finished or dropped.
#[derive(Clone)]
struct Activity(Arc<watch::Sender<usize>>);

impl Activity {
    fn new() -> Activity {
        Activity(Arc::new(watch::channel(0).0))
    }

    fn begin(&self) -> InFlight {
        self.0.send_modify(|n| *n += 1);
        InFlight(self.0.clone())
    }

    /// Resolves once there has been no request in progress for
    /// [`IDLE_TIMEOUT`].
    async fn idle(&self) {
        let mut rx = self.0.subscribe();
        loop {
            let _ = rx.wait_for(|n| *n == 0).await;
            tokio::select! {
                _ = tokio::time::sleep(IDLE_TIMEOUT) => {
                    if *rx.borrow_and_update() == 0 {
                        return;
                    }
                }
                _ = rx.changed() => {}
            }
        }
    }
}

struct InFlight(Arc<watch::Sender<usize>>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// A response body that keeps its request counted as in progress.
struct Tracked {
    body: Body,
    _in_flight: InFlight,
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// Open connections per source, for [`MAX_CONNECTIONS_PER_SOURCE`].
#[derive(Clone, Default)]
struct Sources(Arc<Mutex<HashMap<IpAddr, usize>>>);

struct SourceSlot(Sources, IpAddr);

impl Sources {
    fn acquire(&self, addr: IpAddr, limit: usize) -> Option<SourceSlot> {
        let source = match addr.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !(u128::MAX >> 64))),
            v4 => v4,
        };
        let mut open = self.0.lock().ok()?;
        let n = open.entry(source).or_default();
        if *n >= limit {
            return None;
        }
        *n += 1;
        Some(SourceSlot(self.clone(), source))
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        if let Ok(mut open) = (self.0).0.lock()
            && let Some(n) = open.get_mut(&self.1)
        {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.1);
            }
        }
    }
}

/// Drives `conn` until it ends, or until it has been idle for
/// [`IDLE_TIMEOUT`]; then shuts it down gracefully, giving it
/// [`HANDSHAKE_TIMEOUT`] to finish.
async fn close_when_idle<C: Future>(
    conn: C,
    activity: &Activity,
    shutdown: impl FnOnce(Pin<&mut C>),
) {
    let mut conn = std::pin::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => return,
        _ = activity.idle() => shutdown(conn.as_mut()),
    }
    let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn).await;
}

/// Serves one TLS connection with the protocol ALPN chose: HTTP/2 with a
/// bounded number of concurrent streams and keep-alive pings that drop dead
/// peers, or HTTP/1.1 with a deadline for each request's headers. Either is
/// closed once idle. No protocol sniffing, so nothing waits unbounded
/// before the first request.
async fn serve_connection<S>(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    service: S,
    activity: Activity,
) where
    S: hyper::service::Service<Request<Incoming>, Response = Response<Body>, Error = Infallible>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = TokioIo::new(tls);
    if h2 {
        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .keep_alive_timeout(Duration::from_secs(20))
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS);
        close_when_idle(builder.serve_connection(io, service), &activity, |c| {
            c.graceful_shutdown()
        })
        .await;
    } else {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(10));
        close_when_idle(builder.serve_connection(io, service), &activity, |c| {
            c.graceful_shutdown()
        })
        .await;
    }
}

/// Serves HTTPS on `listener` until `shutdown` turns true.
pub async fn serve_tls<H: Handler>(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    handler: Arc<H>,
    options: ListenOptions,
    mut shutdown: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(config);
    let mut connections = tokio::task::JoinSet::new();
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let sources = Sources::default();
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = shutdown.changed() => break,
        };
        let Ok((mut tcp, addr)) = accepted else {
            tokio::time::sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            // At capacity: close this one rather than queue it.
            drop(tcp);
            continue;
        };
        let proxied = options
            .trusted_proxies
            .iter()
            .any(|p| p.contains(addr.ip().to_canonical()));
        let count = {
            let sources = sources.clone();
            let limit = options.max_per_source;
            move |ip: IpAddr| match limit {
                0 => Some(None),
                limit => sources.acquire(ip, limit).map(Some),
            }
        };
        // A direct connection is counted here, in the order connections
        // arrive, so a source over its cap has its newest connection closed
        // at once; a proxied one once its header names the source.
        let mut counted = None;
        if !proxied {
            let Some(c) = count(addr.ip()) else {
                drop(tcp);
                continue;
            };
            counted = c;
        }
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        connections.spawn(async move {
            let _slot = slot;
            let authenticate = async {
                let (source, counted) = if proxied {
                    let source = read_proxy_header(&mut tcp, addr).await?;
                    (source, count(source.ip())?)
                } else {
                    let mut first = [0u8; 12];
                    if tcp.peek(&mut first).await.ok()? == first.len() && first == PROXY_SIGNATURE {
                        crate::log::warn_with(
                            "listener",
                            "a connection started with a PROXY protocol header from a source address not in connections.trustedProxies; list that address there only if it is the load balancer's own address, otherwise turn PROXY protocol off at the load balancer",
                            &[("source", &addr.to_string())],
                        );
                        return None;
                    }
                    (addr, counted)
                };
                let tls = acceptor.accept(tcp).await.ok()?;
                Some((source, counted, tls))
            };
            let Ok(Some((source, mut counted, tls))) =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, authenticate).await
            else {
                return;
            };
            let certificates: Vec<CertificateDer<'static>> = tls
                .get_ref()
                .1
                .peer_certificates()
                .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
                .unwrap_or_default();
            if !certificates.is_empty() {
                counted = None;
            }
            let _counted = counted;
            let peer = Arc::new(Peer {
                certificates,
                addr: Some(source),
                server_name: tls.get_ref().1.server_name().map(str::to_owned),
            });
            let activity = Activity::new();
            let requests = activity.clone();
            let service = hyper::service::service_fn(move |req| {
                let handler = handler.clone();
                let peer = peer.clone();
                let in_flight = requests.begin();
                async move {
                    let resp = handler.handle(req, peer).await;
                    Ok::<_, Infallible>(resp.map(|body| {
                        Tracked {
                            body,
                            _in_flight: in_flight,
                        }
                        .boxed()
                    }))
                }
            });
            serve_connection(tls, service, activity).await;
        });
        while connections.try_join_next().is_some() {}
    }
}

/// Serves plain HTTP/1.1 on a Unix socket until `shutdown` turns true.
#[cfg(unix)]
pub async fn serve_unix<H: Handler>(
    listener: tokio::net::UnixListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = shutdown.changed() => break,
        };
        let Ok((stream, _)) = accepted else {
            tokio::time::sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let handler = handler.clone();
        connections.spawn(async move {
            let peer = Arc::new(Peer::default());
            let service = hyper::service::service_fn(move |req| {
                let handler = handler.clone();
                let peer = peer.clone();
                async move { Ok::<_, Infallible>(handler.handle(req, peer).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        while connections.try_join_next().is_some() {}
    }
}

/// A minimal HTTPS client: one connection per request, TLS 1.3, HTTP/1.1.
/// Used for the IdP and by tests; nothing here keeps state between calls.
#[derive(Clone)]
pub struct Client {
    config: Arc<rustls::ClientConfig>,
}

/// A response read in full.
#[derive(Debug, Clone)]
pub struct Reply {
    /// Status.
    pub status: StatusCode,
    /// Headers.
    pub headers: http::HeaderMap,
    /// Body.
    pub body: Bytes,
}

impl Reply {
    /// The body as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::BadRequest(format!("invalid JSON in response: {e}")))
    }
}

const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE: usize = 4 << 20;

impl Client {
    /// A client trusting `roots`, presenting `identity` (a chain and a
    /// PKCS#8 key) when given.
    pub fn new(
        roots: RootCertStore,
        identity: Option<(Vec<Vec<u8>>, &[u8])>,
    ) -> Result<Client, Error> {
        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Tls(e.to_string()))?
            .with_root_certificates(roots);
        let config = match identity {
            None => builder.with_no_client_auth(),
            Some((chain, pkcs8)) => builder
                .with_client_auth_cert(
                    chain.into_iter().map(CertificateDer::from).collect(),
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
                )
                .map_err(|e| Error::Tls(e.to_string()))?,
        };
        Ok(Client {
            config: Arc::new(config),
        })
    }

    /// Roots from PEM text.
    pub fn roots_from_pem(pem: &str) -> Result<RootCertStore, Error> {
        let mut roots = RootCertStore::empty();
        let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Tls(format!("PEM: {e}")))?;
        if certs.is_empty() {
            return Err(Error::Tls("no certificates in PEM".into()));
        }
        for der in certs {
            roots.add(der).map_err(|e| Error::Tls(e.to_string()))?;
        }
        Ok(roots)
    }

    /// The operating system's trust store.
    pub fn native_roots() -> Result<RootCertStore, Error> {
        let found = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(found.certs);
        if added == 0 {
            return Err(Error::Tls(
                "no trusted CA certificates found in the operating system's store".into(),
            ));
        }
        Ok(roots)
    }

    async fn connect(
        &self,
        url: &str,
    ) -> Result<
        (
            hyper::client::conn::http1::SendRequest<Full<Bytes>>,
            String,
            String,
        ),
        Error,
    > {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| Error::BadRequest(format!("only https:// URLs are fetched: {url}")))?;
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        let bad_port = || Error::BadRequest(format!("bad port in {url}"));
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            // An IPv6 literal, with an optional port after the bracket.
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| Error::BadRequest(format!("bad host in {url}")))?;
            match after.strip_prefix(':') {
                Some(p) => (host, p.parse::<u16>().map_err(|_| bad_port())?),
                None if after.is_empty() => (host, 443),
                None => return Err(bad_port()),
            }
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad_port())?),
                None => (authority, 443),
            }
        };
        let host = host.to_owned();
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| Error::BadRequest(format!("bad host in {url}")))?;
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| Error::Unavailable(format!("{url}: {e}")))?;
        let tls = TlsConnector::from(self.config.clone())
            .connect(server_name, tcp)
            .await
            .map_err(|e| Error::Tls(format!("{url}: {e}")))?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| Error::Unavailable(format!("{url}: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok((sender, authority.to_owned(), path))
    }

    /// Sends a request and returns the response with its body unread.
    pub async fn send(
        &self,
        method: http::Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Bytes>,
    ) -> Result<Response<Incoming>, Error> {
        let (mut sender, authority, path) = tokio::time::timeout(CLIENT_TIMEOUT, self.connect(url))
            .await
            .map_err(|_| Error::Unavailable(format!("{url}: timed out")))??;
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, authority);
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(PROTOCOL_HEADER))
        {
            req = req.header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string());
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|e| Error::BadRequest(e.to_string()))?;
        tokio::time::timeout(CLIENT_TIMEOUT, sender.send_request(req))
            .await
            .map_err(|_| Error::Unavailable(format!("{url}: timed out")))?
            .map_err(|e| Error::Unavailable(format!("{url}: {e}")))
    }

    /// Sends a request and reads the whole response.
    pub async fn request(
        &self,
        method: http::Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Bytes>,
    ) -> Result<Reply, Error> {
        let resp = self.send(method, url, headers, body).await?;
        let (parts, incoming) = resp.into_parts();
        let body = tokio::time::timeout(
            CLIENT_TIMEOUT,
            Limited::new(incoming, MAX_RESPONSE).collect(),
        )
        .await
        .map_err(|_| Error::Unavailable(format!("{url}: timed out reading the response")))?
        .map_err(|e| Error::Unavailable(format!("{url}: {e}")))?
        .to_bytes();
        Ok(Reply {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            escape_html("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn proxy_headers_are_read_strictly() {
        let proxy: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let head = |cmd: u8, fam: u8, len: u16| {
            let mut h = [0u8; 16];
            h[..12].copy_from_slice(&PROXY_SIGNATURE);
            h[12] = cmd;
            h[13] = fam;
            h[14..].copy_from_slice(&len.to_be_bytes());
            h
        };
        let v4 = [203, 0, 113, 7, 10, 0, 0, 1, 0x15, 0xb3, 1, 187];
        assert_eq!(
            proxy_source(&head(0x21, 0x11, 12), &v4, proxy),
            Some("203.0.113.7:5555".parse().unwrap())
        );
        let mut v6 = [0u8; 36];
        v6[..16].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        v6[32..34].copy_from_slice(&5555u16.to_be_bytes());
        assert_eq!(
            proxy_source(&head(0x21, 0x21, 36), &v6, proxy),
            Some("[2001:db8::7]:5555".parse().unwrap())
        );
        // TLVs after the addresses are allowed.
        let mut with_tlv = v4.to_vec();
        with_tlv.extend([0x04, 0, 1, 0]);
        assert!(proxy_source(&head(0x21, 0x11, 16), &with_tlv, proxy).is_some());
        assert_eq!(proxy_source(&head(0x20, 0x00, 0), &[], proxy), Some(proxy));
        // Wrong signature, version or command, UDP, UNIX, UNSPEC, or too
        // short a body for the family: refused.
        let mut bad = head(0x21, 0x11, 12);
        bad[0] = b'P';
        assert_eq!(proxy_source(&bad, &v4, proxy), None);
        for (cmd, fam) in [
            (0x11, 0x11),
            (0x22, 0x11),
            (0x21, 0x12),
            (0x21, 0x31),
            (0x21, 0x00),
        ] {
            assert_eq!(proxy_source(&head(cmd, fam, 12), &v4, proxy), None);
        }
        assert_eq!(proxy_source(&head(0x21, 0x21, 12), &v4, proxy), None);
        assert_eq!(proxy_source(&head(0x21, 0x11, 13), &v4, proxy), None);
    }

    #[test]
    fn repeated_query_parameters_are_refused() {
        let req = Request::builder().uri("/x?a=1&b=2").body(()).unwrap();
        assert_eq!(param(&query(&req).unwrap(), "b"), Some("2"));
        let req = Request::builder().uri("/x?a=1&a=2").body(()).unwrap();
        assert!(query(&req).is_err());
    }
}
