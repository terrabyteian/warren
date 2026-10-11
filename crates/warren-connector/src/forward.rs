//! Forwarding backends. A backend moves admitted packets into the private
//! network and brings return packets back; it never makes policy decisions
//! (docs/design.md section 10). Kernel mode writes packets to a TUN device
//! and lets the kernel route them, masquerading the device addresses.

use std::fmt::Debug;

use bytes::Bytes;
use tokio::sync::mpsc;

/// Sends admitted packets toward the private network.
pub trait Forwarder: Send + Sync + Debug + 'static {
    /// Forwards one IP packet; may drop it under congestion.
    fn send(&self, packet: &[u8]);
}

/// A started backend: where to send packets, and the return packets.
#[derive(Debug)]
pub struct Backend {
    /// Outbound side.
    pub forwarder: std::sync::Arc<dyn Forwarder>,
    /// Return packets, from the private network toward clients.
    pub returns: mpsc::Receiver<Bytes>,
}

/// Kernel mode: a TUN device plus kernel routing and NAT (Linux, needs
/// `CAP_NET_ADMIN`).
#[cfg(target_os = "linux")]
pub mod kernel {
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::sync::mpsc;
    use warren_core::bundle::IpNet;
    use warren_core::tun::{self, Tun};

    use super::{Backend, Forwarder};

    /// Kernel-mode options.
    #[derive(Debug, Clone)]
    pub struct KernelOptions {
        /// TUN interface name.
        pub tun_name: String,
        /// Its MTU: the tunnel MTU, so the kernel itself answers oversized
        /// return traffic.
        pub mtu: u16,
        /// Device pools, routed into the TUN for return traffic.
        pub device_pools: Vec<IpNet>,
        /// Whether to install warren's masquerade table.
        pub masquerade: bool,
    }

    #[derive(Debug)]
    struct TunForwarder(Arc<Tun>);

    impl Forwarder for TunForwarder {
        fn send(&self, packet: &[u8]) {
            if let Err(e) = self.0.send(packet) {
                tracing::warn!(error = %e, "TUN write failed");
            }
        }
    }

    /// Opens and configures the TUN device and NAT.
    pub fn start(opts: &KernelOptions) -> std::io::Result<Backend> {
        let tun = Arc::new(Tun::create(&opts.tun_name)?);
        tun::configure(tun.name(), opts.mtu, &[], &opts.device_pools)?;
        if opts.masquerade {
            tun::enable_nat(tun.name(), &opts.device_pools)?;
        }
        let (tx, returns) = mpsc::channel(4096);
        let reader = tun.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                match reader.recv(&mut buf).await {
                    Ok(n) => {
                        if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "TUN read failed");
                        return;
                    }
                }
            }
        });
        tracing::info!(tun = %tun.name(), mtu = opts.mtu, masquerade = opts.masquerade, "kernel forwarding ready");
        Ok(Backend {
            forwarder: Arc::new(TunForwarder(tun)),
            returns,
        })
    }

    /// Removes the NAT table on shutdown.
    pub fn stop(opts: &KernelOptions) {
        if opts.masquerade {
            tun::disable_nat();
        }
    }
}
