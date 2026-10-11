//! QUIC configuration for the outer connections (links A and B) and the
//! inner session (link C), following the MTU budget of docs/protocol.md
//! section 9.

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{EndpointConfig, MtuDiscoveryConfig, TransportConfig, VarInt};

use crate::params;

/// Which layer a QUIC connection belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Client or connector to relay.
    Outer,
    /// Client to connector, carried inside the outer layer.
    Inner,
}

/// Overrides for tests and diagnostics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransportTuning {
    /// Pin the outer path MTU (UDP payload) and disable discovery, to
    /// emulate a constrained path.
    pub fixed_outer_mtu: Option<u16>,
}

/// Transport parameters for a layer.
pub fn transport(layer: Layer, tuning: TransportTuning) -> TransportConfig {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        params::IDLE_TIMEOUT
            .try_into()
            .expect("idle timeout fits a QUIC varint"),
    ));
    t.keep_alive_interval(Some(params::KEEPALIVE));
    // Datagrams carry the tunnel; give them generous buffers.
    t.datagram_receive_buffer_size(Some(4 << 20));
    t.datagram_send_buffer_size(4 << 20);
    t.min_mtu(params::QUIC_MIN_UDP_PAYLOAD);
    match layer {
        Layer::Outer => {
            // Request streams are few (one per tunnel); uni streams carry
            // HTTP/3 control and QPACK streams.
            t.max_concurrent_bidi_streams(VarInt::from_u32(256));
            t.max_concurrent_uni_streams(VarInt::from_u32(8));
            match tuning.fixed_outer_mtu {
                Some(mtu) => {
                    t.initial_mtu(mtu);
                    t.min_mtu(mtu.min(params::QUIC_MIN_UDP_PAYLOAD));
                    t.mtu_discovery_config(None);
                }
                None => {
                    // Every IPv6-capable path carries 1232 bytes of UDP
                    // payload; start there and discover upward.
                    t.initial_mtu(params::OUTER_MIN_UDP_PAYLOAD);
                    let mut d = MtuDiscoveryConfig::default();
                    d.upper_bound(params::OUTER_MTU_DISCOVERY_MAX);
                    t.mtu_discovery_config(Some(d));
                }
            }
        }
        Layer::Inner => {
            t.max_concurrent_bidi_streams(VarInt::from_u32(16));
            t.max_concurrent_uni_streams(VarInt::from_u32(8));
            // The inner session starts at the QUIC minimum, which the outer
            // layer always delivers, and discovers the end-to-end path.
            t.initial_mtu(params::QUIC_MIN_UDP_PAYLOAD);
            let mut d = MtuDiscoveryConfig::default();
            d.upper_bound(params::INNER_MTU_DISCOVERY_MAX);
            t.mtu_discovery_config(Some(d));
        }
    }
    t
}

/// Endpoint configuration with the layer's connection ID length.
pub fn endpoint_config(layer: Layer) -> EndpointConfig {
    let len = match layer {
        Layer::Outer => params::OUTER_CID_LEN,
        Layer::Inner => params::INNER_CID_LEN,
    };
    let mut c = EndpointConfig::default();
    c.cid_generator(move || Box::new(RandomCid(len)));
    c
}

/// Random connection IDs of a fixed length from the aws-lc-rs CSPRNG.
#[derive(Debug)]
struct RandomCid(usize);

impl quinn::ConnectionIdGenerator for RandomCid {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut b = [0u8; 20];
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(&mut b[..self.0])
            .expect("the system CSPRNG works");
        quinn::ConnectionId::new(&b[..self.0])
    }

    fn cid_len(&self) -> usize {
        self.0
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }
}

/// A QUIC client configuration.
pub fn client_config(
    tls: rustls::ClientConfig,
    layer: Layer,
    tuning: TransportTuning,
) -> quinn::ClientConfig {
    let crypto =
        QuicClientConfig::try_from(tls).expect("warren's provider has TLS13_AES_128_GCM_SHA256");
    let mut c = quinn::ClientConfig::new(Arc::new(crypto));
    c.transport_config(Arc::new(transport(layer, tuning)));
    c
}

/// A QUIC server configuration.
pub fn server_config(
    tls: rustls::ServerConfig,
    layer: Layer,
    tuning: TransportTuning,
) -> quinn::ServerConfig {
    let crypto =
        QuicServerConfig::try_from(tls).expect("warren's provider has TLS13_AES_128_GCM_SHA256");
    let mut c = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    c.transport_config(Arc::new(transport(layer, tuning)));
    // Clients migrate between networks and relays (docs/protocol.md 5).
    c.migration(true);
    c
}
