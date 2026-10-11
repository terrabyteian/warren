//! A tunnel: one extended-CONNECT request stream carrying the Capsule
//! Protocol plus its HTTP Datagrams, over either carrier.
//!
//! Over HTTP/3, datagrams travel in QUIC DATAGRAM frames when they fit and
//! in DATAGRAM capsules on the stream when they do not but must still be
//! delivered (the "no silent drops" rule of docs/protocol.md section 9). Over
//! HTTP/2 every datagram is a DATAGRAM capsule. Receivers see one stream of
//! datagrams either way.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, watch};

use crate::capsule::{Capsule, CapsuleReader, RawCapsule, kind};
use crate::h3::{self, DatagramSendError, H3Connection, RequestStream};
use crate::{h2 as carrier_h2, varint};

/// Queue depth for received datagrams before newer ones are dropped.
const DATAGRAM_QUEUE: usize = 1024;
/// Queue depth for capsules waiting to be written.
const CAPSULE_QUEUE: usize = 1024;

/// Which carrier a tunnel runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    /// HTTP/3 over QUIC.
    Http3,
    /// HTTP/2 over TLS over TCP (the fallback).
    Http2,
}

#[derive(Debug)]
enum Carrier {
    H3 {
        conn: Arc<H3Connection>,
        stream_id: u64,
    },
    H2,
}

/// Counters a tunnel keeps about how its datagrams travelled.
#[derive(Debug, Default)]
pub struct TunnelStats {
    /// Datagrams sent in QUIC DATAGRAM frames.
    pub frames_sent: AtomicU64,
    /// Datagrams sent as DATAGRAM capsules because they did not fit a frame
    /// (always zero over HTTP/2, where capsules are the only way).
    pub capsule_fallbacks: AtomicU64,
    /// Datagrams dropped because they exceeded the delivery limit.
    pub dropped_too_large: AtomicU64,
    /// Datagrams dropped because the send queue was full.
    pub dropped_congested: AtomicU64,
}

#[derive(Debug)]
struct SenderShared {
    carrier: Carrier,
    capsules: mpsc::Sender<Bytes>,
    /// Datagram payloads (context ID included) up to this size are always
    /// delivered, by capsule if no frame fits; larger ones that do not fit a
    /// frame are dropped like an over-MTU packet.
    deliver_limit: AtomicU64,
    stats: TunnelStats,
}

/// The sending half of a tunnel. Cloning shares it.
#[derive(Debug, Clone)]
pub struct TunnelSender {
    shared: Arc<SenderShared>,
}

/// Why a send failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The datagram exceeds the path and the delivery limit; it was dropped.
    TooLarge,
    /// The tunnel is closed.
    Closed,
}

impl TunnelSender {
    /// The carrier this tunnel runs on.
    pub fn carrier(&self) -> CarrierKind {
        match self.shared.carrier {
            Carrier::H3 { .. } => CarrierKind::Http3,
            Carrier::H2 => CarrierKind::Http2,
        }
    }

    /// Delivery statistics.
    pub fn stats(&self) -> &TunnelStats {
        &self.shared.stats
    }

    /// Sets the delivery limit (see [`TunnelSender::send_datagram`]).
    pub fn set_deliver_limit(&self, limit: usize) {
        self.shared
            .deliver_limit
            .store(limit as u64, Ordering::Relaxed);
    }

    /// Largest datagram payload that currently fits a DATAGRAM frame, or
    /// `None` over HTTP/2.
    pub fn max_frame_payload(&self) -> Option<usize> {
        match &self.shared.carrier {
            Carrier::H3 { conn, stream_id } => conn.max_datagram_payload(*stream_id),
            Carrier::H2 => None,
        }
    }

    /// Sends one HTTP Datagram: `context` and `payload`.
    ///
    /// Over HTTP/3 it goes in a DATAGRAM frame if it fits; otherwise, if it
    /// is within the delivery limit, in a DATAGRAM capsule on the stream;
    /// otherwise it is dropped with [`SendError::TooLarge`]. Over HTTP/2 it
    /// is always a capsule.
    pub fn send_datagram(&self, context: u64, payload: &[u8]) -> Result<(), SendError> {
        let stats = &self.shared.stats;
        let len = varint::len(context) + payload.len();
        if let Carrier::H3 { conn, stream_id } = &self.shared.carrier {
            match conn.send_datagram(*stream_id, context, payload) {
                Ok(()) => {
                    stats.frames_sent.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(DatagramSendError::Closed) => return Err(SendError::Closed),
                Err(DatagramSendError::TooLarge | DatagramSendError::Unsupported) => {
                    if len as u64 > self.shared.deliver_limit.load(Ordering::Relaxed) {
                        stats.dropped_too_large.fetch_add(1, Ordering::Relaxed);
                        return Err(SendError::TooLarge);
                    }
                    stats.capsule_fallbacks.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let mut out = BytesMut::with_capacity(len + 6);
        varint::put(&mut out, kind::DATAGRAM);
        varint::put(&mut out, len as u64);
        varint::put(&mut out, context);
        out.extend_from_slice(payload);
        match self.shared.capsules.try_send(out.freeze()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                stats.dropped_congested.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(SendError::Closed),
        }
    }

    /// Sends a capsule; capsules are delivered reliably and in order.
    pub async fn send_capsule(&self, capsule: &Capsule) -> Result<(), SendError> {
        self.shared
            .capsules
            .send(capsule.encode())
            .await
            .map_err(|_| SendError::Closed)
    }

    /// Queues a capsule without waiting; fails if the queue is full or the
    /// tunnel is closed.
    pub fn try_send_capsule(&self, capsule: &Capsule) -> Result<(), SendError> {
        self.shared
            .capsules
            .try_send(capsule.encode())
            .map_err(|_| SendError::Closed)
    }

    /// Whether the tunnel's writer has stopped.
    pub fn is_closed(&self) -> bool {
        self.shared.capsules.is_closed()
    }

    /// Sends a GREASE capsule, which receivers must ignore (docs/protocol.md
    /// section 13).
    pub async fn send_grease(&self) -> Result<(), SendError> {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::from(d.subsec_nanos() % 1000))
            .unwrap_or(1);
        let capsule = Capsule::Unknown(RawCapsule {
            kind: 0x29 * (n + 1) + 0x17,
            payload: Bytes::new(),
        });
        self.send_capsule(&capsule).await
    }
}

/// The receiving half of a tunnel.
#[derive(Debug)]
pub struct TunnelReceiver {
    /// HTTP Datagram payloads (context ID first), from frames and capsules.
    pub datagrams: mpsc::Receiver<Bytes>,
    /// Every other capsule, decoded; GREASE and unknown types are filtered.
    pub capsules: mpsc::Receiver<Capsule>,
    /// Set once the stream ends, with the reason.
    pub closed: watch::Receiver<Option<String>>,
}

/// Starts a tunnel on an HTTP/3 request stream whose 2xx response has been
/// sent or received. `deliver_limit` is the largest datagram payload that
/// must reach the peer even when it does not fit a DATAGRAM frame.
pub fn from_h3(stream: RequestStream, deliver_limit: usize) -> (TunnelSender, TunnelReceiver) {
    let (stream_id, mut send, mut recv, conn) = stream.into_parts();
    let (dgram_tx, datagrams) = mpsc::channel(DATAGRAM_QUEUE);
    let (capsule_tx, capsules) = mpsc::channel(CAPSULE_QUEUE);
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(CAPSULE_QUEUE);
    let (closed_tx, closed) = watch::channel(None);
    conn.register_datagrams(stream_id, dgram_tx.clone());

    tokio::spawn(async move {
        while let Some(capsule) = out_rx.recv().await {
            if h3::send_data(&mut send, &capsule).await.is_err() {
                return;
            }
        }
        let _ = send.finish();
    });

    let reader_conn = conn.clone();
    tokio::spawn(async move {
        let mut parser = CapsuleReader::new();
        let reason = loop {
            match h3::recv_data(&mut recv).await {
                Ok(Some(data)) => {
                    parser.push(&data);
                    if let Err(e) = dispatch(&mut parser, &dgram_tx, &capsule_tx).await {
                        let _ = recv.stream_mut().stop(quinn::VarInt::from_u32(
                            h3::code::GENERAL_PROTOCOL_ERROR as u32,
                        ));
                        break e;
                    }
                }
                Ok(None) if parser.has_partial() => {
                    break "stream ended inside a capsule".to_owned();
                }
                Ok(None) => break "stream closed by peer".to_owned(),
                Err(e) => break e.to_string(),
            }
        };
        reader_conn.unregister_datagrams(stream_id);
        closed_tx.send_replace(Some(reason));
    });

    let shared = Arc::new(SenderShared {
        carrier: Carrier::H3 { conn, stream_id },
        capsules: out_tx,
        deliver_limit: AtomicU64::new(deliver_limit as u64),
        stats: TunnelStats::default(),
    });
    (
        TunnelSender { shared },
        TunnelReceiver {
            datagrams,
            capsules,
            closed,
        },
    )
}

/// Starts a tunnel on an HTTP/2 request stream whose 2xx response has been
/// sent or received.
pub fn from_h2(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
) -> (TunnelSender, TunnelReceiver) {
    let (dgram_tx, datagrams) = mpsc::channel(DATAGRAM_QUEUE);
    let (capsule_tx, capsules) = mpsc::channel(CAPSULE_QUEUE);
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(CAPSULE_QUEUE);
    let (closed_tx, closed) = watch::channel(None);

    tokio::spawn(async move {
        while let Some(first) = out_rx.recv().await {
            // Coalesce whatever is queued into one DATA frame.
            let mut batch = BytesMut::from(&first[..]);
            while batch.len() < 16 * 1024 {
                match out_rx.try_recv() {
                    Ok(more) => batch.extend_from_slice(&more),
                    Err(_) => break,
                }
            }
            if carrier_h2::send_all(&mut send, batch.freeze())
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });

    tokio::spawn(async move {
        let mut parser = CapsuleReader::new();
        let reason = loop {
            match carrier_h2::recv_chunk(&mut recv).await {
                Ok(Some(data)) => {
                    parser.push(&data);
                    if let Err(e) = dispatch(&mut parser, &dgram_tx, &capsule_tx).await {
                        break e;
                    }
                }
                Ok(None) if parser.has_partial() => {
                    break "stream ended inside a capsule".to_owned();
                }
                Ok(None) => break "stream closed by peer".to_owned(),
                Err(e) => break e.to_string(),
            }
        };
        closed_tx.send_replace(Some(reason));
    });

    let shared = Arc::new(SenderShared {
        carrier: Carrier::H2,
        capsules: out_tx,
        deliver_limit: AtomicU64::new(u64::MAX),
        stats: TunnelStats::default(),
    });
    (
        TunnelSender { shared },
        TunnelReceiver {
            datagrams,
            capsules,
            closed,
        },
    )
}

/// Hands every complete capsule to its queue; datagram capsules join the
/// datagram queue so receivers need not care how a datagram travelled.
async fn dispatch(
    parser: &mut CapsuleReader,
    datagrams: &mpsc::Sender<Bytes>,
    capsules: &mpsc::Sender<Capsule>,
) -> Result<(), String> {
    while let Some(raw) = parser.next_capsule().map_err(|e| e.to_string())? {
        if raw.kind == kind::DATAGRAM {
            // Stream-carried datagrams are the reliable path; wait for room
            // rather than drop them.
            if datagrams.send(raw.payload).await.is_err() {
                return Err("datagram receiver gone".into());
            }
            continue;
        }
        if kind::is_grease(raw.kind) {
            continue;
        }
        match Capsule::decode(raw).map_err(|e| e.to_string())? {
            Capsule::Unknown(_) => {}
            c => {
                if capsules.send(c).await.is_err() {
                    return Err("capsule receiver gone".into());
                }
            }
        }
    }
    Ok(())
}
