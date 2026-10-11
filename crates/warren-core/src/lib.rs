//! The shared core of warren's data path.
//!
//! One implementation of the TLS and QUIC configuration (rustls on
//! aws-lc-rs, nothing else), certificate profiles and device identity, the
//! virtual socket that carries the inner session, packet handling, the
//! tunnel device, audit records and the policy enforcement interface, used
//! by the client, the relay and the connector alike. See `docs/design.md`
//! and `docs/protocol.md`.
//!
//! It also holds what every role shares with the control plane: the
//! certificate profile ([`pki`], [`identity`], and [`cert`] to issue it), the
//! join exchange ([`join`]), the keys and JOSE objects that sign policy
//! ([`keys`], [`jose`]), and the control-channel messages of links D and E
//! ([`api`], [`policy_bundle`], [`events`]).

pub mod api;
pub mod audit;
pub mod base64;
pub mod bundle;
pub mod cert;
pub mod clock;
pub mod der;
pub mod events;
pub mod identity;
pub mod join;
pub mod jose;
pub mod keys;
pub mod logging;
pub mod metrics;
pub mod packet;
pub mod params;
pub mod pki;
pub mod policy;
pub mod policy_bundle;
pub mod quic;
pub mod tls;
#[cfg(target_os = "linux")]
pub mod tun;
pub mod vsock;
