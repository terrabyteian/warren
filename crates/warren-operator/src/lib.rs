//! The Kubernetes operator.
//!
//! Deploys and scales connectors, publishes annotated Services and app CRDs,
//! and syncs policy CRDs to the control plane. It becomes its own binary in
//! milestone M2 and is never linked into the `warren` binary or any data-path
//! build, so the Kubernetes client crates stay out of the data path.
//!
//! Placeholder: milestone M2 fills this crate.
