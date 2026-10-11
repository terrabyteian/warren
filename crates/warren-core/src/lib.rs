//! The shared core of warren's data path.
//!
//! One implementation of the TLS and QUIC configuration (rustls on
//! aws-lc-rs, nothing else), certificate profiles and device identity, the
//! virtual socket that carries the inner session, packet handling, the
//! tunnel device, audit records and the policy enforcement interface, used
//! by the client, the relay and the connector alike. See `docs/design.md`
//! and `docs/protocol.md`.

pub mod audit;
pub mod base64;
pub mod bundle;
pub mod der;
pub mod identity;
pub mod join;
pub mod logging;
pub mod metrics;
pub mod packet;
pub mod params;
pub mod pki;
pub mod policy;
pub mod quic;
pub mod tls;
#[cfg(target_os = "linux")]
pub mod tun;
pub mod vsock;
