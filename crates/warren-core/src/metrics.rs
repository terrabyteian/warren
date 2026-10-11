//! Node metrics: named counters and gauges, served in the Prometheus text
//! format on `/metrics` by a deliberately tiny HTTP/1.1 responder, with
//! `/healthz` for liveness.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug)]
struct Metric {
    name: &'static str,
    help: &'static str,
    gauge: bool,
    value: Arc<AtomicU64>,
}

/// A set of metrics.
#[derive(Debug, Default, Clone)]
pub struct Registry {
    metrics: Arc<Mutex<Vec<Metric>>>,
}

/// A monotonically increasing counter.
#[derive(Debug, Clone)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    /// Adds one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n`.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// The current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A value that goes up and down.
#[derive(Debug, Clone)]
pub struct Gauge(Arc<AtomicU64>);

impl Gauge {
    /// Adds one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Subtracts one.
    pub fn dec(&self) {
        let _ = self
            .0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// The current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Registry {
    fn register(&self, name: &'static str, help: &'static str, gauge: bool) -> Arc<AtomicU64> {
        let value = Arc::new(AtomicU64::new(0));
        self.metrics.lock().expect("metrics lock").push(Metric {
            name,
            help,
            gauge,
            value: value.clone(),
        });
        value
    }

    /// Registers a counter.
    pub fn counter(&self, name: &'static str, help: &'static str) -> Counter {
        Counter(self.register(name, help, false))
    }

    /// Registers a gauge.
    pub fn gauge(&self, name: &'static str, help: &'static str) -> Gauge {
        Gauge(self.register(name, help, true))
    }

    /// Renders the Prometheus text format.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for m in self.metrics.lock().expect("metrics lock").iter() {
            let kind = if m.gauge { "gauge" } else { "counter" };
            let _ = writeln!(out, "# HELP {} {}", m.name, m.help);
            let _ = writeln!(out, "# TYPE {} {kind}", m.name);
            let _ = writeln!(out, "{} {}", m.name, m.value.load(Ordering::Relaxed));
        }
        out
    }

    /// Serves `/metrics` and `/healthz` on `addr` until the task is dropped.
    pub async fn serve(self, listener: TcpListener) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let registry = self.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
                let line = String::from_utf8_lossy(&buf[..n]);
                let path = line.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = match path {
                    "/metrics" => ("200 OK", registry.render()),
                    "/healthz" => ("200 OK", "ok\n".to_owned()),
                    _ => ("404 Not Found", "not found\n".to_owned()),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    }
}

/// Binds the metrics listener.
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}
