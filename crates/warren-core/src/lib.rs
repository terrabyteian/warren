//! The shared core of warren's data path.
//!
//! One implementation of the tunnel engine, the TLS and QUIC configuration
//! (rustls on aws-lc-rs, nothing else), device identity and the policy
//! enforcement point, used by the client, the relay and the connector alike.
//! See `docs/design.md` and `docs/protocol.md`.
//!
//! Placeholder: milestone M1 fills this crate.
