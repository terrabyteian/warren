//! The policy surface and its compilation to Cedar.
//!
//! Parses the declarative schema (config directory or CRDs) described in
//! `docs/policy.md`, validates it, and compiles it to a Cedar policy set that
//! the connector enforces and the console explains.
//!
//! [`names`] holds the host-name and address-range rules that both the
//! compiler and enforcement points apply. Reading YAML and compiling to
//! Cedar sit behind the `compiler` feature, which the control plane enables
//! and data-path builds do not.

pub mod names;

#[cfg(feature = "compiler")]
pub mod compile;
#[cfg(feature = "compiler")]
pub mod model;
#[cfg(feature = "compiler")]
pub mod yaml;
