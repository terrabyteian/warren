//! The relay role.
//!
//! A stateless rendezvous that clients and connectors both dial out to. It
//! splices CONNECT-UDP sessions between them and only ever sees ciphertext of
//! the end-to-end sessions it carries.
//!
//! Placeholder: milestone M1 fills this crate.

/// One-line description of the role, shown by `warren relay --help`.
pub const ABOUT: &str = "Run a relay that clients and connectors dial out to";
