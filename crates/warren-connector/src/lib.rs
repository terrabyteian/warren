//! The connector role.
//!
//! Terminates end-to-end sessions from clients, enforces policy on every new
//! connection, and forwards admitted traffic to the private destinations it
//! has been scoped to.
//!
//! Placeholder: milestone M1 fills this crate.

/// One-line description of the role, shown by `warren connector --help`.
pub const ABOUT: &str = "Run a connector that enforces policy and reaches private apps";
