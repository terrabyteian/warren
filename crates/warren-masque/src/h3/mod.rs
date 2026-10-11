//! warren's minimal HTTP/3 (RFC 9114) over quinn.
//!
//! It implements exactly what MASQUE needs: SETTINGS on the control stream,
//! request streams carrying one HEADERS exchange followed by DATA frames,
//! HTTP Datagrams (RFC 9297) demultiplexed by quarter stream ID, and GOAWAY.
//! There is no server push and no QPACK dynamic table (see [`qpack`]). The
//! published `h3` crate cannot express `:protocol = connect-ip`, which the
//! inner session needs, so warren carries this subset itself as
//! docs/design.md section 14 allows.

pub mod frame;
mod huffman_table;
pub mod qpack;
mod static_table;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, watch};

use self::frame::{FrameEvent, FrameReader, Settings, setting, ty};
use crate::http::{RequestHead, ResponseHead};
use crate::varint;

/// HTTP/3 and HTTP Datagram error codes.
pub mod code {
    /// H3_NO_ERROR.
    pub const NO_ERROR: u64 = 0x100;
    /// H3_GENERAL_PROTOCOL_ERROR.
    pub const GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    /// H3_INTERNAL_ERROR.
    pub const INTERNAL_ERROR: u64 = 0x102;
    /// H3_STREAM_CREATION_ERROR.
    pub const STREAM_CREATION_ERROR: u64 = 0x103;
    /// H3_CLOSED_CRITICAL_STREAM.
    pub const CLOSED_CRITICAL_STREAM: u64 = 0x104;
    /// H3_FRAME_UNEXPECTED.
    pub const FRAME_UNEXPECTED: u64 = 0x105;
    /// H3_FRAME_ERROR.
    pub const FRAME_ERROR: u64 = 0x106;
    /// H3_EXCESSIVE_LOAD.
    pub const EXCESSIVE_LOAD: u64 = 0x107;
    /// H3_ID_ERROR.
    pub const ID_ERROR: u64 = 0x108;
    /// H3_SETTINGS_ERROR.
    pub const SETTINGS_ERROR: u64 = 0x109;
    /// H3_MISSING_SETTINGS.
    pub const MISSING_SETTINGS: u64 = 0x10a;
    /// H3_REQUEST_REJECTED.
    pub const REQUEST_REJECTED: u64 = 0x10b;
    /// H3_REQUEST_CANCELLED.
    pub const REQUEST_CANCELLED: u64 = 0x10c;
    /// H3_MESSAGE_ERROR.
    pub const MESSAGE_ERROR: u64 = 0x10e;
    /// H3_CONNECT_ERROR.
    pub const CONNECT_ERROR: u64 = 0x10f;
    /// QPACK_DECOMPRESSION_FAILED.
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
    /// H3_DATAGRAM_ERROR (RFC 9297).
    pub const DATAGRAM_ERROR: u64 = 0x33;
}

/// Unidirectional stream types.
mod stream_type {
    pub const CONTROL: u64 = 0x00;
    pub const PUSH: u64 = 0x01;
    pub const QPACK_ENCODER: u64 = 0x02;
    pub const QPACK_DECODER: u64 = 0x03;
}

/// Request streams must keep quarter stream IDs within a 2-byte varint
/// (docs/protocol.md section 9); past this an endpoint opens a new
/// connection.
pub const MAX_QUARTER_STREAM_ID: u64 = 16_383;

/// How long to wait for the peer's SETTINGS.
pub const SETTINGS_TIMEOUT: Duration = Duration::from_secs(10);

/// An HTTP/3 error.
#[derive(Debug, Clone)]
pub enum H3Error {
    /// A connection error this endpoint detected; the connection is closed
    /// with `code`.
    Protocol {
        /// HTTP/3 error code.
        code: u64,
        /// Diagnostic text.
        reason: String,
    },
    /// The QUIC connection failed or was closed.
    Connection(quinn::ConnectionError),
    /// Reading a stream failed.
    Read(String),
    /// Writing a stream failed.
    Write(String),
    /// A malformed request or response (a stream error).
    Message(String),
    /// The peer's settings lack what MASQUE needs.
    Settings(String),
    /// The connection has used up its quarter stream IDs.
    StreamLimit,
}

impl H3Error {
    pub(crate) fn protocol(code: u64, reason: &str) -> H3Error {
        H3Error::Protocol {
            code,
            reason: reason.to_owned(),
        }
    }
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Error::Protocol { code, reason } => write!(f, "HTTP/3 error {code:#x}: {reason}"),
            H3Error::Connection(e) => write!(f, "QUIC connection: {e}"),
            H3Error::Read(e) => write!(f, "stream read: {e}"),
            H3Error::Write(e) => write!(f, "stream write: {e}"),
            H3Error::Message(e) => write!(f, "malformed message: {e}"),
            H3Error::Settings(e) => write!(f, "peer settings: {e}"),
            H3Error::StreamLimit => write!(f, "quarter stream ID budget exhausted"),
        }
    }
}

impl std::error::Error for H3Error {}

impl From<quinn::ConnectionError> for H3Error {
    fn from(e: quinn::ConnectionError) -> Self {
        H3Error::Connection(e)
    }
}

/// Why a datagram was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramSendError {
    /// Larger than the path currently carries in a DATAGRAM frame.
    TooLarge,
    /// The peer does not accept datagrams.
    Unsupported,
    /// The connection is closed.
    Closed,
}

/// The settings warren sends on every HTTP/3 connection.
pub fn local_settings() -> Settings {
    Settings {
        entries: vec![
            (setting::QPACK_MAX_TABLE_CAPACITY, 0),
            (setting::QPACK_BLOCKED_STREAMS, 0),
            (
                setting::MAX_FIELD_SECTION_SIZE,
                qpack::MAX_FIELD_SECTION_SIZE,
            ),
            (setting::ENABLE_CONNECT_PROTOCOL, 1),
            (setting::H3_DATAGRAM, 1),
            // A reserved setting keeps the extension point exercised
            // (RFC 9114, 7.2.4.1; docs/protocol.md section 13).
            (0x1f * 0x5752 + 0x21, 0),
        ],
    }
}

/// One HTTP/3 connection over a QUIC connection.
#[derive(Debug)]
pub struct H3Connection {
    quic: quinn::Connection,
    is_server: bool,
    settings: watch::Receiver<Option<Arc<Settings>>>,
    goaway: watch::Receiver<Option<u64>>,
    routes: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
    control: tokio::sync::Mutex<quinn::SendStream>,
}

impl H3Connection {
    /// Starts HTTP/3 on an established QUIC connection: opens the control
    /// stream with SETTINGS and starts serving the peer's streams and
    /// datagrams.
    pub async fn new(quic: quinn::Connection, is_server: bool) -> Result<Arc<Self>, H3Error> {
        let mut control = quic.open_uni().await?;
        let mut out = BytesMut::new();
        varint::put(&mut out, stream_type::CONTROL);
        out.extend_from_slice(&frame::encode(ty::SETTINGS, &local_settings().encode()));
        control
            .write_all(&out)
            .await
            .map_err(|e| H3Error::Write(e.to_string()))?;

        let (settings_tx, settings) = watch::channel(None);
        let (goaway_tx, goaway) = watch::channel(None);
        let conn = Arc::new(H3Connection {
            quic,
            is_server,
            settings,
            goaway,
            routes: Mutex::new(HashMap::new()),
            control: tokio::sync::Mutex::new(control),
        });
        tokio::spawn(accept_uni_streams(conn.clone(), settings_tx, goaway_tx));
        tokio::spawn(read_datagrams(Arc::downgrade(&conn), conn.quic.clone()));
        Ok(conn)
    }

    /// The QUIC connection.
    pub fn quic(&self) -> &quinn::Connection {
        &self.quic
    }

    /// Waits for the peer's SETTINGS.
    pub async fn peer_settings(&self) -> Result<Arc<Settings>, H3Error> {
        let mut rx = self.settings.clone();
        let wait = rx.wait_for(Option::is_some);
        match tokio::time::timeout(SETTINGS_TIMEOUT, wait).await {
            Ok(Ok(s)) => Ok(s.clone().expect("checked by wait_for")),
            Ok(Err(_)) => Err(self
                .quic
                .close_reason()
                .map(H3Error::Connection)
                .unwrap_or_else(|| H3Error::Settings("connection closed before SETTINGS".into()))),
            Err(_) => Err(H3Error::Settings("no SETTINGS from the peer".into())),
        }
    }

    /// Waits for the peer's SETTINGS and checks that it supports extended
    /// CONNECT and HTTP Datagrams, as docs/protocol.md section 4.1 requires.
    pub async fn require_masque(&self) -> Result<(), H3Error> {
        if !self.peer_settings().await?.supports_masque() {
            return Err(H3Error::Settings(
                "peer lacks SETTINGS_ENABLE_CONNECT_PROTOCOL or SETTINGS_H3_DATAGRAM".into(),
            ));
        }
        if self.quic.max_datagram_size().is_none() {
            return Err(H3Error::Settings(
                "peer does not accept QUIC datagrams".into(),
            ));
        }
        Ok(())
    }

    /// The peer's GOAWAY, once received.
    pub fn goaway(&self) -> watch::Receiver<Option<u64>> {
        self.goaway.clone()
    }

    /// Sends GOAWAY: no new requests on this connection.
    pub async fn send_goaway(&self) -> Result<(), H3Error> {
        // Servers name the first stream they will not process; warren has
        // no push, so clients send push ID 0.
        let id = if self.is_server {
            (MAX_QUARTER_STREAM_ID + 1) * 4
        } else {
            0
        };
        let mut payload = BytesMut::new();
        varint::put(&mut payload, id);
        let mut control = self.control.lock().await;
        control
            .write_all(&frame::encode(ty::GOAWAY, &payload))
            .await
            .map_err(|e| H3Error::Write(e.to_string()))
    }

    /// Closes the connection with an HTTP/3 error code.
    pub fn close(&self, code: u64, reason: &str) {
        self.quic.close(
            quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::from_u32(0x102)),
            reason.as_bytes(),
        );
    }

    /// Opens a request stream and sends `head`; returns the final response.
    pub async fn send_request(
        self: &Arc<Self>,
        head: &RequestHead,
    ) -> Result<(ResponseHead, RequestStream), H3Error> {
        let (mut send, recv) = self.quic.open_bi().await?;
        if stream_id(&send) / 4 > MAX_QUARTER_STREAM_ID {
            let _ = send.reset(quinn::VarInt::from_u32(code::REQUEST_CANCELLED as u32));
            return Err(H3Error::StreamLimit);
        }
        let block = qpack::encode(&head.to_fields());
        send.write_all(&frame::encode(ty::HEADERS, &block))
            .await
            .map_err(|e| H3Error::Write(e.to_string()))?;
        let mut stream = RequestStream {
            id: stream_id(&send),
            send,
            recv: FrameReader::new(recv),
            conn: self.clone(),
        };
        loop {
            let fields = stream.read_headers().await?;
            let response = ResponseHead::from_fields(fields).map_err(|e| H3Error::Message(e.0))?;
            // Interim responses are skipped; the final one follows.
            if response.status >= 200 {
                return Ok((response, stream));
            }
        }
    }

    /// Accepts the next request stream, or `None` once the peer closes the
    /// connection cleanly.
    pub async fn accept_request(
        self: &Arc<Self>,
    ) -> Result<Option<(RequestHead, RequestStream)>, H3Error> {
        loop {
            let (send, recv) = match self.quic.accept_bi().await {
                Ok(s) => s,
                Err(
                    quinn::ConnectionError::ApplicationClosed(_)
                    | quinn::ConnectionError::LocallyClosed,
                ) => {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            };
            let mut stream = RequestStream {
                id: stream_id(&send),
                send,
                recv: FrameReader::new(recv),
                conn: self.clone(),
            };
            if stream.id / 4 > MAX_QUARTER_STREAM_ID {
                stream.reject(code::REQUEST_REJECTED);
                continue;
            }
            let fields = match stream.read_headers().await {
                Ok(f) => f,
                Err(H3Error::Message(_)) => {
                    stream.reject(code::MESSAGE_ERROR);
                    continue;
                }
                Err(e @ H3Error::Protocol { .. }) => {
                    self.fail(&e);
                    return Err(e);
                }
                Err(_) => continue,
            };
            match RequestHead::from_fields(fields) {
                Ok(head) => return Ok(Some((head, stream))),
                Err(_) => stream.reject(code::MESSAGE_ERROR),
            }
        }
    }

    /// Routes HTTP Datagrams for a request stream to `tx`.
    pub fn register_datagrams(&self, stream_id: u64, tx: mpsc::Sender<Bytes>) {
        self.routes
            .lock()
            .expect("routes lock")
            .insert(stream_id, tx);
    }

    /// Stops routing datagrams for a request stream.
    pub fn unregister_datagrams(&self, stream_id: u64) {
        self.routes.lock().expect("routes lock").remove(&stream_id);
    }

    /// Largest HTTP Datagram payload (context ID and data) that currently
    /// fits a DATAGRAM frame for `stream_id`.
    pub fn max_datagram_payload(&self, stream_id: u64) -> Option<usize> {
        let max = self.quic.max_datagram_size()?;
        max.checked_sub(varint::len(stream_id / 4))
    }

    /// Sends an HTTP Datagram for a request stream: the quarter stream ID,
    /// the context ID and the payload, built in one buffer.
    pub fn send_datagram(
        &self,
        stream_id: u64,
        context: u64,
        payload: &[u8],
    ) -> Result<(), DatagramSendError> {
        let qsid = stream_id / 4;
        let mut out =
            BytesMut::with_capacity(varint::len(qsid) + varint::len(context) + payload.len());
        varint::put(&mut out, qsid);
        varint::put(&mut out, context);
        out.extend_from_slice(payload);
        match self.quic.send_datagram(out.freeze()) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => Err(DatagramSendError::TooLarge),
            Err(
                quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled,
            ) => Err(DatagramSendError::Unsupported),
            Err(quinn::SendDatagramError::ConnectionLost(_)) => Err(DatagramSendError::Closed),
        }
    }

    fn fail(&self, e: &H3Error) {
        if let H3Error::Protocol { code, reason } = e {
            tracing::debug!(code = *code, reason = %reason, "closing HTTP/3 connection");
            self.close(*code, reason);
        }
    }
}

fn stream_id(send: &quinn::SendStream) -> u64 {
    // Client-initiated bidirectional streams are 4n; quinn numbers them n.
    send.id().index() * 4
}

/// A request stream: one HEADERS exchange, then DATA frames.
#[derive(Debug)]
pub struct RequestStream {
    /// The QUIC stream ID.
    pub id: u64,
    /// Send half.
    pub send: quinn::SendStream,
    /// Receive half.
    pub recv: FrameReader,
    conn: Arc<H3Connection>,
}

impl RequestStream {
    /// The connection the stream belongs to.
    pub fn connection(&self) -> &Arc<H3Connection> {
        &self.conn
    }

    /// Splits the stream into its ID, halves and connection.
    pub fn into_parts(self) -> (u64, quinn::SendStream, FrameReader, Arc<H3Connection>) {
        (self.id, self.send, self.recv, self.conn)
    }

    async fn read_headers(&mut self) -> Result<Vec<(String, String)>, H3Error> {
        loop {
            match self.recv.next().await? {
                None => return Err(H3Error::Message("stream ended before HEADERS".into())),
                Some(FrameEvent::Frame {
                    ty: ty::HEADERS,
                    payload,
                }) => {
                    return qpack::decode(&payload).map_err(|e| H3Error::Protocol {
                        code: code::QPACK_DECOMPRESSION_FAILED,
                        reason: e.to_string(),
                    });
                }
                Some(FrameEvent::Frame { ty: t, .. }) if !is_known_request_frame(t) => continue,
                Some(_) => {
                    return Err(H3Error::protocol(
                        code::FRAME_UNEXPECTED,
                        "expected HEADERS",
                    ));
                }
            }
        }
    }

    /// Sends the response head (server side).
    pub async fn respond(&mut self, head: &ResponseHead) -> Result<(), H3Error> {
        let (status, rest) = head.to_fields();
        let mut fields = vec![(":status", status.as_str())];
        fields.extend(rest);
        let block = qpack::encode(&fields);
        self.send
            .write_all(&frame::encode(ty::HEADERS, &block))
            .await
            .map_err(|e| H3Error::Write(e.to_string()))
    }

    /// Rejects the request by resetting both directions.
    pub fn reject(&mut self, code: u64) {
        let c = quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::from_u32(0x102));
        let _ = self.send.reset(c);
        let _ = self.recv.stream_mut().stop(c);
    }
}

fn is_known_request_frame(t: u64) -> bool {
    matches!(
        t,
        ty::DATA
            | ty::HEADERS
            | ty::CANCEL_PUSH
            | ty::SETTINGS
            | ty::PUSH_PROMISE
            | ty::GOAWAY
            | ty::MAX_PUSH_ID
    ) || ty::is_http2_reserved(t)
}

/// Reads DATA payload from a request stream's receive half, skipping
/// unknown frames; `None` at end of stream or trailers.
pub async fn recv_data(recv: &mut FrameReader) -> Result<Option<Bytes>, H3Error> {
    loop {
        match recv.next().await? {
            None => return Ok(None),
            Some(FrameEvent::Data(b)) => return Ok(Some(b)),
            // Trailers end the message; nothing follows them.
            Some(FrameEvent::Frame {
                ty: ty::HEADERS, ..
            }) => return Ok(None),
            Some(FrameEvent::Frame { ty: t, .. }) if !is_known_request_frame(t) => continue,
            Some(FrameEvent::Frame { .. }) => {
                return Err(H3Error::protocol(
                    code::FRAME_UNEXPECTED,
                    "unexpected frame on a request stream",
                ));
            }
        }
    }
}

/// Writes `data` as one DATA frame.
pub async fn send_data(send: &mut quinn::SendStream, data: &[u8]) -> Result<(), H3Error> {
    send.write_all(&frame::encode(ty::DATA, data))
        .await
        .map_err(|e| H3Error::Write(e.to_string()))
}

async fn accept_uni_streams(
    conn: Arc<H3Connection>,
    settings_tx: watch::Sender<Option<Arc<Settings>>>,
    goaway_tx: watch::Sender<Option<u64>>,
) {
    let settings_tx = Arc::new(settings_tx);
    let goaway_tx = Arc::new(goaway_tx);
    let control_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    loop {
        let Ok(mut recv) = conn.quic.accept_uni().await else {
            return;
        };
        let conn = conn.clone();
        let (settings_tx, goaway_tx, control_seen) =
            (settings_tx.clone(), goaway_tx.clone(), control_seen.clone());
        tokio::spawn(async move {
            let mut prefix = BytesMut::new();
            let kind = loop {
                if let Some((v, n)) = varint::peek(&prefix) {
                    let _ = prefix.split_to(n);
                    break v;
                }
                match recv.read_chunk(8, true).await {
                    Ok(Some(c)) => prefix.extend_from_slice(&c.bytes),
                    _ => return,
                }
            };
            match kind {
                stream_type::CONTROL => {
                    if control_seen.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        conn.fail(&H3Error::protocol(
                            code::STREAM_CREATION_ERROR,
                            "second control stream",
                        ));
                        return;
                    }
                    let reader = FrameReader::with_prefix(recv, prefix.freeze());
                    if let Err(e) =
                        serve_control(reader, &settings_tx, &goaway_tx, conn.is_server).await
                    {
                        conn.fail(&e);
                    }
                }
                stream_type::PUSH => {
                    // warren never sends MAX_PUSH_ID, so no push is allowed.
                    conn.fail(&H3Error::protocol(code::ID_ERROR, "unexpected push stream"));
                }
                stream_type::QPACK_ENCODER | stream_type::QPACK_DECODER => {
                    // With no dynamic table these carry nothing that matters;
                    // keep reading so the peer is never blocked by flow control.
                    while let Ok(Some(_)) = recv.read_chunk(4096, true).await {}
                }
                _ => {
                    let _ = recv.stop(quinn::VarInt::from_u32(code::STREAM_CREATION_ERROR as u32));
                }
            }
        });
    }
}

async fn serve_control(
    mut reader: FrameReader,
    settings_tx: &watch::Sender<Option<Arc<Settings>>>,
    goaway_tx: &watch::Sender<Option<u64>>,
    is_server: bool,
) -> Result<(), H3Error> {
    let first = reader.next().await?;
    match first {
        Some(FrameEvent::Frame {
            ty: ty::SETTINGS,
            payload,
        }) => {
            let settings = Settings::decode(payload)?;
            settings_tx.send_replace(Some(Arc::new(settings)));
        }
        None => {
            return Err(H3Error::protocol(
                code::CLOSED_CRITICAL_STREAM,
                "control stream closed",
            ));
        }
        Some(_) => {
            return Err(H3Error::protocol(
                code::MISSING_SETTINGS,
                "first control frame is not SETTINGS",
            ));
        }
    }
    loop {
        match reader.next().await? {
            None => {
                return Err(H3Error::protocol(
                    code::CLOSED_CRITICAL_STREAM,
                    "control stream closed",
                ));
            }
            Some(FrameEvent::Frame {
                ty: ty::GOAWAY,
                mut payload,
            }) => {
                let id = varint::get(&mut payload)
                    .ok_or_else(|| H3Error::protocol(code::FRAME_ERROR, "truncated GOAWAY"))?;
                let previous = *goaway_tx.borrow();
                if previous.is_some_and(|p| id > p) {
                    return Err(H3Error::protocol(
                        code::ID_ERROR,
                        "GOAWAY identifier increased",
                    ));
                }
                goaway_tx.send_replace(Some(id));
            }
            Some(FrameEvent::Frame {
                ty: ty::MAX_PUSH_ID,
                ..
            }) if is_server => {}
            Some(FrameEvent::Frame {
                ty: ty::CANCEL_PUSH,
                ..
            }) => {}
            Some(FrameEvent::Frame { ty: t, .. }) if !is_known_request_frame(t) => {}
            Some(_) => {
                return Err(H3Error::protocol(
                    code::FRAME_UNEXPECTED,
                    "unexpected frame on the control stream",
                ));
            }
        }
    }
}

async fn read_datagrams(conn: std::sync::Weak<H3Connection>, quic: quinn::Connection) {
    while let Ok(datagram) = quic.read_datagram().await {
        let Some((qsid, n)) = varint::peek(&datagram) else {
            // RFC 9297: a datagram without a quarter stream ID is an error.
            quic.close(
                quinn::VarInt::from_u32(code::DATAGRAM_ERROR as u32),
                b"datagram without quarter stream ID",
            );
            return;
        };
        let Some(conn) = conn.upgrade() else { return };
        let route = conn
            .routes
            .lock()
            .expect("routes lock")
            .get(&(qsid * 4))
            .cloned();
        // Datagrams for unknown or congested streams are dropped, as an
        // unreliable path would.
        if let Some(tx) = route {
            let _ = tx.try_send(datagram.slice(n..));
        }
    }
}
