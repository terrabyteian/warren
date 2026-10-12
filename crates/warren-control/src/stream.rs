//! The revocation push channel's server side (docs/protocol.md section 12):
//! one long-lived response per node, carrying events in sequence order,
//! heartbeats while idle, and a snapshot when a node resumes from further
//! back than the log retains.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use tokio::sync::mpsc;
use warren_core::clock;
use warren_core::events::{Line, Snapshot};
use warren_core::params::EVENT_HEARTBEAT_INTERVAL;

use crate::app::App;
use crate::store::Node;
use crate::web::{self, Body};

/// The content type of the stream: one JSON object per line.
pub const CONTENT_TYPE: &str = "application/x-ndjson";

/// The certificate a node opened its stream with.
pub struct StreamCert {
    /// Its serial, lowercase hex.
    pub serial: String,
    /// When it expires, Unix seconds.
    pub not_after: i64,
}

/// Opens a stream for `node`, resuming after sequence number `after` when
/// given. The stream ends when the node is revoked, or when the certificate
/// it authenticated with is revoked or expires.
pub fn open(app: Arc<App>, node: Node, after: Option<u64>, cert: StreamCert) -> Response<Body> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        if let Err(e) = run(app, node, after, cert, tx).await {
            crate::log::warn("events", &format!("event stream ended: {e}"));
        }
    });
    web::stream(CONTENT_TYPE, rx)
}

async fn send(tx: &mpsc::Sender<Bytes>, line: &Line) -> Result<(), crate::Error> {
    let mut text = line.to_json();
    text.push('\n');
    tx.send(Bytes::from(text))
        .await
        .map_err(|_| crate::Error::Unavailable("the node disconnected".into()))
}

async fn snapshot(app: &App, seq: u64) -> Result<Line, crate::Error> {
    let bundle = app.store.latest_bundle().await?;
    Ok(Line::Snapshot(Snapshot {
        seq,
        revocations: app.store.revocations().await?,
        bundle_version: bundle.as_ref().map(|b| b.version).unwrap_or(0),
        bundle_digest: bundle.map(|b| b.digest).unwrap_or_default(),
    }))
}

async fn run(
    app: Arc<App>,
    node: Node,
    after: Option<u64>,
    cert: StreamCert,
    tx: mpsc::Sender<Bytes>,
) -> Result<(), crate::Error> {
    let not_after = cert.not_after;
    // The node counts as connected while this stream is open.
    let _presence = app.presence.connect(&node.id);
    let mut changes = app.subscribe();
    let (latest, oldest) = app.store.event_bounds().await?;
    let mut last = match after {
        // Everything after `a` is still retained: replay it.
        Some(a) if a <= latest && a + 1 >= oldest => a,
        // A fresh node, a gap, or a sequence number from the future: start
        // from a full snapshot.
        _ => {
            send(&tx, &snapshot(&app, latest).await?).await?;
            latest
        }
    };
    loop {
        loop {
            let events = app.store.events_after(last, 256).await?;
            if events.is_empty() {
                break;
            }
            if events.iter().zip(last + 1..).any(|(e, seq)| e.seq != seq) {
                // Events the node needs were pruned between reading the
                // bounds and reading the log: never skip them silently.
                let (latest, _) = app.store.event_bounds().await?;
                send(&tx, &snapshot(&app, latest).await?).await?;
                last = latest;
                continue;
            }
            for event in events {
                last = event.seq;
                send(&tx, &Line::Event(event)).await?;
            }
        }
        if app
            .store
            .node(&node.id)
            .await?
            .is_none_or(|n| n.revoked_at.is_some())
            || app.store.certificate_revoked(&cert.serial).await?
        {
            return Ok(());
        }
        let now = clock::now_secs();
        if now >= not_after {
            return Ok(());
        }
        let until_expiry = Duration::from_secs((not_after - now) as u64);
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
            }
            _ = tokio::time::sleep(EVENT_HEARTBEAT_INTERVAL) => {
                send(&tx, &Line::Heartbeat { seq: last, time_ms: clock::now_millis() }).await?;
            }
            _ = tokio::time::sleep(until_expiry) => return Ok(()),
            _ = tx.closed() => return Ok(()),
        }
    }
}
