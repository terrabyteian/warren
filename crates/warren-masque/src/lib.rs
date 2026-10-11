//! warren's own MASQUE layer.
//!
//! CONNECT-UDP (RFC 9298), its bound-UDP extension, and CONNECT-IP
//! (RFC 9484) over a minimal HTTP/3 (RFC 9114), the HTTP Datagram and
//! Capsule Protocol (RFC 9297), and the HTTP/2 fallback carrying the same
//! capsules over TCP, as profiled in `docs/protocol.md`.

pub mod capsule;
pub mod connect;
pub mod h2;
pub mod h3;
pub mod http;
pub mod join;
pub mod session;
pub mod tunnel;
pub mod varint;

/// TLS over TCP for the HTTP/2 carrier, re-exported for role crates.
pub use tokio_rustls;
