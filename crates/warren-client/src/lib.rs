//! The client core linked by the native platform shells.
//!
//! The macOS shell (Swift, NetworkExtension system extension) comes first;
//! Windows and Linux shells follow. This crate is a data-path build: it must
//! never link control-plane, console or Kubernetes crates, which
//! `scripts/check-closure.sh` enforces.
//!
//! Placeholder: milestone M1 fills this crate.
