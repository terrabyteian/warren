//! A virtual UDP socket that lets a quinn endpoint run over HTTP Datagrams:
//! the inner session (link C) is QUIC carried by CONNECT-UDP tunnels instead
//! of a kernel socket.
//!
//! Outgoing packets go to a [`PacketSink`], which maps the destination
//! address to a tunnel. Incoming packets are queued with the address they
//! came from. The socket never fragments, so quinn runs path MTU discovery
//! over it: a sink drops packets that exceed what its tunnel can deliver,
//! exactly as a network path drops an oversized probe.

use std::fmt::Debug;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

/// Where a virtual socket's outgoing packets go.
pub trait PacketSink: Send + Sync + Debug + 'static {
    /// Sends one packet towards `dst`. Packets that cannot be delivered are
    /// dropped silently, like UDP on a congested or constrained path.
    fn send_to(&self, dst: SocketAddr, packet: &[u8]);
}

/// The receiving queue of a virtual socket.
#[derive(Debug, Clone)]
pub struct Inbound {
    tx: mpsc::Sender<(SocketAddr, Bytes)>,
}

impl Inbound {
    /// Delivers a packet from `src`; dropped if the queue is full.
    pub fn deliver(&self, src: SocketAddr, packet: Bytes) {
        let _ = self.tx.try_send((src, packet));
    }
}

/// A UDP socket made of tunnels.
#[derive(Debug)]
pub struct VirtualSocket {
    local: SocketAddr,
    rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    sink: Arc<dyn PacketSink>,
}

/// Inbound queue depth.
const QUEUE: usize = 2048;

impl VirtualSocket {
    /// Creates a socket with a nominal local address.
    pub fn new(local: SocketAddr, sink: Arc<dyn PacketSink>) -> (Arc<VirtualSocket>, Inbound) {
        let (tx, rx) = mpsc::channel(QUEUE);
        (
            Arc::new(VirtualSocket {
                local,
                rx: Mutex::new(rx),
                sink,
            }),
            Inbound { tx },
        )
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for VirtualSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        match transmit.segment_size {
            Some(size) if size < transmit.contents.len() => {
                for segment in transmit.contents.chunks(size) {
                    self.sink.send_to(transmit.destination, segment);
                }
            }
            _ => self.sink.send_to(transmit.destination, transmit.contents),
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().expect("virtual socket lock");
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let next = if n == 0 {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(p)) => p,
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "tunnel closed",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match rx.try_recv() {
                    Ok(p) => p,
                    Err(_) => break,
                }
            };
            let (src, packet) = next;
            let buf = &mut bufs[n];
            if packet.len() > buf.len() {
                continue;
            }
            buf[..packet.len()].copy_from_slice(&packet);
            meta[n] = RecvMeta {
                addr: src,
                len: packet.len(),
                stride: packet.len(),
                ecn: None,
                dst_ip: Some(self.local.ip()),
            };
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// Starts a quinn endpoint on a virtual socket.
pub fn endpoint(
    config: quinn::EndpointConfig,
    server: Option<quinn::ServerConfig>,
    socket: Arc<VirtualSocket>,
) -> io::Result<quinn::Endpoint> {
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime for the inner endpoint"))?;
    quinn::Endpoint::new_with_abstract_socket(config, server, socket, runtime)
}
