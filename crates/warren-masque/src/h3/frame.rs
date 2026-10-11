//! HTTP/3 frames (RFC 9114, section 7) and settings.

use bytes::{Buf, Bytes, BytesMut};

use super::{H3Error, code};
use crate::varint;

/// Frame types.
pub mod ty {
    /// DATA.
    pub const DATA: u64 = 0x0;
    /// HEADERS.
    pub const HEADERS: u64 = 0x1;
    /// CANCEL_PUSH.
    pub const CANCEL_PUSH: u64 = 0x3;
    /// SETTINGS.
    pub const SETTINGS: u64 = 0x4;
    /// PUSH_PROMISE.
    pub const PUSH_PROMISE: u64 = 0x5;
    /// GOAWAY.
    pub const GOAWAY: u64 = 0x7;
    /// MAX_PUSH_ID.
    pub const MAX_PUSH_ID: u64 = 0xd;

    /// Frame types reserved because HTTP/2 used them (RFC 9114, 7.2.8).
    pub fn is_http2_reserved(t: u64) -> bool {
        matches!(t, 0x2 | 0x6 | 0x8 | 0x9)
    }
}

/// Setting identifiers.
pub mod setting {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204).
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114).
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x6;
    /// SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204).
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x7;
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220).
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
    /// SETTINGS_H3_DATAGRAM (RFC 9297).
    pub const H3_DATAGRAM: u64 = 0x33;
}

/// A peer's SETTINGS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// Every setting the peer sent, in order.
    pub entries: Vec<(u64, u64)>,
}

impl Settings {
    /// The value of a setting, if present.
    pub fn get(&self, id: u64) -> Option<u64> {
        self.entries.iter().find(|(i, _)| *i == id).map(|(_, v)| *v)
    }

    /// Whether the peer enabled extended CONNECT and HTTP Datagrams.
    pub fn supports_masque(&self) -> bool {
        self.get(setting::ENABLE_CONNECT_PROTOCOL) == Some(1)
            && self.get(setting::H3_DATAGRAM) == Some(1)
    }

    /// Encodes as a SETTINGS frame payload.
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::new();
        for (id, v) in &self.entries {
            varint::put(&mut out, *id);
            varint::put(&mut out, *v);
        }
        out.freeze()
    }

    /// Decodes a SETTINGS frame payload.
    pub fn decode(mut payload: Bytes) -> Result<Settings, H3Error> {
        let mut entries: Vec<(u64, u64)> = Vec::new();
        while payload.has_remaining() {
            let (Some(id), Some(v)) = (varint::get(&mut payload), varint::get(&mut payload)) else {
                return Err(H3Error::protocol(code::FRAME_ERROR, "truncated SETTINGS"));
            };
            // HTTP/2 setting identifiers are reserved (RFC 9114, 7.2.4.1).
            if matches!(id, 0x0 | 0x2 | 0x3 | 0x4 | 0x5) {
                return Err(H3Error::protocol(code::SETTINGS_ERROR, "HTTP/2 setting"));
            }
            if entries.iter().any(|(i, _)| *i == id) {
                return Err(H3Error::protocol(code::SETTINGS_ERROR, "duplicate setting"));
            }
            if matches!(id, setting::ENABLE_CONNECT_PROTOCOL | setting::H3_DATAGRAM) && v > 1 {
                return Err(H3Error::protocol(
                    code::SETTINGS_ERROR,
                    "boolean setting above 1",
                ));
            }
            entries.push((id, v));
        }
        Ok(Settings { entries })
    }
}

/// Encodes a frame: type, length, payload.
pub fn encode(frame_type: u64, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(
        varint::len(frame_type) + varint::len(payload.len() as u64) + payload.len(),
    );
    varint::put(&mut out, frame_type);
    varint::put(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out.freeze()
}

/// One event from a stream of frames.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameEvent {
    /// A piece of a DATA frame's payload; DATA frames are streamed, never
    /// buffered whole.
    Data(Bytes),
    /// A complete non-DATA frame.
    Frame {
        /// Frame type.
        ty: u64,
        /// Frame payload.
        payload: Bytes,
    },
}

/// Largest non-DATA frame accepted.
pub const MAX_FRAME: u64 = 64 * 1024;

/// Reads frames from a QUIC receive stream.
#[derive(Debug)]
pub struct FrameReader {
    recv: quinn::RecvStream,
    buf: BytesMut,
    data_remaining: u64,
}

impl FrameReader {
    /// Wraps a receive stream.
    pub fn new(recv: quinn::RecvStream) -> Self {
        Self {
            recv,
            buf: BytesMut::new(),
            data_remaining: 0,
        }
    }

    /// Wraps a receive stream whose first bytes were already read.
    pub fn with_prefix(recv: quinn::RecvStream, prefix: Bytes) -> Self {
        Self {
            recv,
            buf: BytesMut::from(&prefix[..]),
            data_remaining: 0,
        }
    }

    /// The underlying stream, for STOP_SENDING.
    pub fn stream_mut(&mut self) -> &mut quinn::RecvStream {
        &mut self.recv
    }

    /// Reads more bytes into the buffer; `false` at end of stream.
    async fn fill(&mut self) -> Result<bool, H3Error> {
        match self.recv.read_chunk(64 * 1024, true).await {
            Ok(Some(chunk)) => {
                self.buf.extend_from_slice(&chunk.bytes);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => Err(H3Error::Read(e.to_string())),
        }
    }

    /// Returns the next event, or `None` at a clean end of stream.
    pub async fn next(&mut self) -> Result<Option<FrameEvent>, H3Error> {
        loop {
            if self.data_remaining > 0 {
                if self.buf.is_empty() && !self.fill().await? {
                    return Err(H3Error::protocol(
                        code::FRAME_ERROR,
                        "stream ended inside DATA",
                    ));
                }
                let n = (self.buf.len() as u64).min(self.data_remaining) as usize;
                self.data_remaining -= n as u64;
                return Ok(Some(FrameEvent::Data(self.buf.split_to(n).freeze())));
            }
            let mut peek = &self.buf[..];
            let header = match (varint::get(&mut peek), varint::get(&mut peek)) {
                (Some(t), Some(l)) => Some((t, l, self.buf.len() - peek.len())),
                _ => None,
            };
            let Some((frame_type, len, header_len)) = header else {
                if !self.fill().await? {
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(H3Error::protocol(
                        code::FRAME_ERROR,
                        "truncated frame header",
                    ));
                }
                continue;
            };
            if frame_type == ty::DATA {
                self.buf.advance(header_len);
                self.data_remaining = len;
                continue;
            }
            if len > MAX_FRAME {
                return Err(H3Error::protocol(code::EXCESSIVE_LOAD, "frame too large"));
            }
            let total = header_len + len as usize;
            while self.buf.len() < total {
                if !self.fill().await? {
                    return Err(H3Error::protocol(code::FRAME_ERROR, "truncated frame"));
                }
            }
            self.buf.advance(header_len);
            let payload = self.buf.split_to(len as usize).freeze();
            return Ok(Some(FrameEvent::Frame {
                ty: frame_type,
                payload,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_validation() {
        let s = Settings {
            entries: vec![
                (setting::QPACK_MAX_TABLE_CAPACITY, 0),
                (setting::ENABLE_CONNECT_PROTOCOL, 1),
                (setting::H3_DATAGRAM, 1),
                (0x1f * 3 + 0x21, 7),
            ],
        };
        let decoded = Settings::decode(s.encode()).unwrap();
        assert_eq!(decoded, s);
        assert!(decoded.supports_masque());

        let dup = Settings {
            entries: vec![(setting::H3_DATAGRAM, 1), (setting::H3_DATAGRAM, 1)],
        };
        assert!(Settings::decode(dup.encode()).is_err());
        let h2 = Settings {
            entries: vec![(0x2, 0)],
        };
        assert!(Settings::decode(h2.encode()).is_err());
        let bad_bool = Settings {
            entries: vec![(setting::H3_DATAGRAM, 2)],
        };
        assert!(Settings::decode(bad_bool.encode()).is_err());
        assert!(Settings::decode(Bytes::from_static(&[0x33])).is_err());
    }

    #[test]
    fn frame_encoding() {
        assert_eq!(&encode(ty::DATA, b"ab")[..], &[0x00, 0x02, b'a', b'b']);
        assert_eq!(&encode(ty::GOAWAY, &[0x04])[..], &[0x07, 0x01, 0x04]);
    }
}
