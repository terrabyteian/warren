//! The web console served by the control plane.
//!
//! Server-rendered pages with hand-written JavaScript and CSS and no npm
//! toolchain. Kept out of every data-path build. This crate only renders:
//! the control plane gathers what each page shows into the plain data in
//! [`view`], checks who may see it, and serves the result. Every value is
//! escaped on the way into the markup ([`html`]).

pub mod html;
pub mod pages;
pub mod view;

/// The console's stylesheet.
pub const CSS: &str = include_str!("../assets/console.css");

/// The console's script: progressive enhancement only; every page works
/// without it.
pub const JS: &str = include_str!("../assets/console.js");

/// A digest of the assets (FNV-1a), so their URLs change when they do.
pub const ASSET_VERSION: u64 = {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let parts = [CSS.as_bytes(), JS.as_bytes()];
    let mut p = 0;
    while p < parts.len() {
        let bytes = parts[p];
        let mut i = 0;
        while i < bytes.len() {
            hash ^= bytes[i] as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            i += 1;
        }
        p += 1;
    }
    hash
};
