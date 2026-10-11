//! Named parameters from docs/protocol.md section 14 that the data path
//! uses. Fixed bounds are guarantees (docs/design.md section 4); the rest are
//! initial defaults that benchmarks may change.

use std::time::Duration;

/// Maximum user+device certificate lifetime (fixed bound).
pub const CLIENT_CERT_LIFETIME: Duration = Duration::from_secs(4 * 3600);

/// Maximum clock-skew allowance (fixed bound; deployments may only lower it).
pub const CLOCK_SKEW_ALLOWANCE: Duration = Duration::from_secs(120);

/// The tunnel MTU floor: RFC 9484's IPv6 minimum (fixed).
pub const TUNNEL_MTU_FLOOR: u16 = 1280;

/// Initial tunnel MTU.
pub const TUNNEL_MTU: u16 = 1280;

/// Largest tunnel MTU used once the inner session has proven it.
pub const TUNNEL_MTU_MAX: u16 = 1380;

/// The smallest UDP payload QUIC requires of a path (RFC 9000, 14.1); the
/// inner session's packets are never smaller than this guarantee.
pub const QUIC_MIN_UDP_PAYLOAD: u16 = 1200;

/// UDP payload of a 1280-byte IPv6 path (1280 - 40 - 8), the outer layer's
/// guaranteed minimum (docs/protocol.md section 9).
pub const OUTER_MIN_UDP_PAYLOAD: u16 = 1232;

/// Upper bound for path MTU discovery on outer connections (an IPv4
/// Ethernet path: 1500 - 20 - 8).
pub const OUTER_MTU_DISCOVERY_MAX: u16 = 1472;

/// Upper bound for path MTU discovery on the inner session: the outer
/// maximum less outer overhead.
pub const INNER_MTU_DISCOVERY_MAX: u16 = 1440;

/// Connection ID length on outer connections (links A and B): at most 4
/// bytes, so the outer overhead stays within the MTU budget.
pub const OUTER_CID_LEN: usize = 4;

/// Connection ID length on the inner session (link C).
pub const INNER_CID_LEN: usize = 8;

/// Largest compressed context ID on a bind stream: 2-byte varints only.
pub const MAX_BIND_CONTEXT_ID: u64 = 16_383;

/// How long a QUIC handshake gets before HTTP/2 is raced alongside it.
pub const FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// Idle time that ends a UDP flow.
pub const FLOW_IDLE_UDP: Duration = Duration::from_secs(60);

/// Idle time that ends an ICMP flow.
pub const FLOW_IDLE_ICMP: Duration = Duration::from_secs(10);

/// Idle time that ends a TCP flow that never closed cleanly. The profile
/// leaves TCP idle time open; this bounds memory without cutting ordinary
/// long-lived connections that send keepalives.
pub const FLOW_IDLE_TCP: Duration = Duration::from_secs(2 * 3600);

/// Longest a draining connector keeps existing streams.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(300);

/// The current warren protocol version, carried in `Warren-Protocol`.
pub const PROTOCOL_VERSION: u32 = 1;

/// The oldest protocol version each role still accepts (`VERSION_SKEW`:
/// current and previous).
pub const PROTOCOL_VERSION_MIN: u32 = 1;

/// The `.invalid` suffix of connector-group targets (RFC 6761), so a target
/// can never resolve in DNS.
pub const CONNECTOR_TARGET_SUFFIX: &str = ".connectors.warren.invalid";

/// QUIC idle timeout on every connection; keepalives keep healthy
/// connections well inside it.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// QUIC keepalive interval.
pub const KEEPALIVE: Duration = Duration::from_secs(10);

/// Default `DEVICE_POOL_V4` (a deployment setting): device tunnel
/// addresses.
pub const DEVICE_POOL_V4: &str = "100.96.0.0/16";

/// Default `DEVICE_POOL_V6` (a deployment setting).
pub const DEVICE_POOL_V6: &str = "fd00:7761:7272:6e00::/64";

/// Default `SYNTHETIC_POOL_V4` (a deployment setting): addresses clients
/// answer for names.
pub const SYNTHETIC_POOL_V4: &str = "100.80.0.0/16";

/// Default `SYNTHETIC_POOL_V6` (a deployment setting).
pub const SYNTHETIC_POOL_V6: &str = "fd00:7761:7272:6e01::/64";
