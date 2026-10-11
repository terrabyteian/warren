//! Audit records (G13): one OCSF-shaped JSON record per access decision,
//! allow or deny, and one per flow when it ends (docs/design.md section
//! 7.7). Records are OCSF Network Activity (class 4001) events; warren's own
//! facts (app, reason code, rules, policy version) sit under
//! `unmapped.warren`. User-controlled values are always structured fields,
//! never interpolated into text (T16).

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

/// The OCSF schema version the records follow.
pub const OCSF_VERSION: &str = "1.3.0";

/// OCSF Network Activity activity IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// A flow or bind was admitted.
    Open = 1,
    /// A flow ended.
    Close = 2,
    /// A flow was torn down.
    Reset = 3,
    /// A flow or bind was refused.
    Refuse = 5,
}

impl Activity {
    fn name(self) -> &'static str {
        match self {
            Activity::Open => "Open",
            Activity::Close => "Close",
            Activity::Reset => "Reset",
            Activity::Refuse => "Refuse",
        }
    }
}

/// Generates a decision or flow identifier.
pub fn new_id() -> String {
    let mut b = [0u8; 12];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut b)
        .expect("the system CSPRNG works");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Milliseconds since the Unix epoch.
pub fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// Who and where a record is about.
#[derive(Debug, Clone)]
pub struct Subject<'a> {
    /// User ID.
    pub user: &'a str,
    /// Device ID.
    pub device: &'a str,
    /// Sign-in session.
    pub session: &'a str,
}

/// An access decision to record.
#[derive(Debug, Clone)]
pub struct DecisionRecord<'a> {
    /// Decision ID, shared with the client's deny capsule.
    pub id: &'a str,
    /// Who.
    pub subject: Subject<'a>,
    /// The app, if one was identified.
    pub app: Option<&'a str>,
    /// The client-facing name, for name apps.
    pub hostname: Option<&'a str>,
    /// IP protocol.
    pub protocol: u8,
    /// Source (the device's tunnel address).
    pub src: SocketAddr,
    /// Destination as the client addressed it.
    pub dst: SocketAddr,
    /// Real destination after name translation, if different.
    pub translated_dst: Option<SocketAddr>,
    /// Allowed or denied.
    pub allowed: bool,
    /// Reason code for denies.
    pub reason: Option<&'a str>,
    /// User-facing message.
    pub message: &'a str,
    /// Rules that determined it.
    pub rules: &'a [String],
    /// First failed condition.
    pub failed_condition: Option<&'a str>,
    /// Policy version.
    pub policy_version: u64,
    /// Whether the server opened the flow.
    pub server_initiated: bool,
}

/// A finished flow to record.
#[derive(Debug, Clone)]
pub struct FlowRecord<'a> {
    /// Flow ID (the admitting decision's ID).
    pub id: &'a str,
    /// Who.
    pub subject: Subject<'a>,
    /// The app.
    pub app: &'a str,
    /// IP protocol.
    pub protocol: u8,
    /// Source.
    pub src: SocketAddr,
    /// Real destination.
    pub dst: SocketAddr,
    /// When it started.
    pub start: SystemTime,
    /// When it ended.
    pub end: SystemTime,
    /// Bytes client to server.
    pub bytes_out: u64,
    /// Bytes server to client.
    pub bytes_in: u64,
    /// Packets client to server.
    pub packets_out: u64,
    /// Packets server to client.
    pub packets_in: u64,
    /// Why it ended (`idle`, `fin`, `rst`, `revoked`, `session_closed`).
    pub end_reason: &'a str,
}

fn protocol_name(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "other",
    }
}

fn endpoint(a: SocketAddr) -> Value {
    json!({ "ip": a.ip().to_string(), "port": a.port() })
}

fn envelope(activity: Activity, time: SystemTime, node: &NodeInfo, uid: &str, log: &str) -> Value {
    json!({
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": activity as u8,
        "activity_name": activity.name(),
        "type_uid": 400_100 + activity as u32,
        "severity_id": 1,
        "time": millis(time),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": uid,
            "log_name": log,
            "product": {
                "name": "warren",
                "vendor_name": "warren",
                "version": env!("CARGO_PKG_VERSION"),
                "feature": { "name": node.role },
            },
        },
        "observer": { "name": node.name, "type": node.role },
    })
}

/// The node writing records.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Role, such as `connector`.
    pub role: String,
    /// Node name, such as `connector/homelab/c1`.
    pub name: String,
}

/// Builds a decision record.
pub fn decision(node: &NodeInfo, r: &DecisionRecord<'_>) -> Value {
    let activity = if r.allowed {
        Activity::Open
    } else {
        Activity::Refuse
    };
    let mut v = envelope(activity, SystemTime::now(), node, r.id, "decision");
    let mut dst = endpoint(r.dst);
    if let Some(h) = r.hostname {
        dst["hostname"] = json!(h);
    }
    let fields = json!({
        "action_id": if r.allowed { 1 } else { 2 },
        "action": if r.allowed { "Allowed" } else { "Denied" },
        "disposition_id": if r.allowed { 1 } else { 2 },
        "disposition": if r.allowed { "Allowed" } else { "Blocked" },
        "status_id": if r.allowed { 1 } else { 2 },
        "status": if r.allowed { "Success" } else { "Failure" },
        "status_code": r.reason,
        "status_detail": if r.message.is_empty() { None } else { Some(r.message) },
        "actor": {
            "user": { "uid": r.subject.user },
            "session": { "uid": r.subject.session },
        },
        "device": { "uid": r.subject.device },
        "src_endpoint": endpoint(r.src),
        "dst_endpoint": dst,
        "connection_info": {
            "protocol_num": r.protocol,
            "protocol_name": protocol_name(r.protocol),
            "direction_id": if r.server_initiated { 1 } else { 2 },
            "direction": if r.server_initiated { "Inbound" } else { "Outbound" },
            "uid": r.id,
        },
        "policy": {
            "uid": r.rules.first(),
            "version": r.policy_version.to_string(),
        },
        "unmapped": { "warren": {
            "decision_id": r.id,
            "app": r.app,
            "reason": r.reason,
            "rules": r.rules,
            "failed_condition": r.failed_condition,
            "policy_version": r.policy_version,
            "translated_dst": r.translated_dst.map(endpoint),
        }},
    });
    merge(&mut v, fields);
    v
}

/// Builds a flow record.
pub fn flow(node: &NodeInfo, r: &FlowRecord<'_>) -> Value {
    let mut v = envelope(Activity::Close, r.end, node, r.id, "flow");
    let fields = json!({
        "start_time": millis(r.start),
        "end_time": millis(r.end),
        "duration": millis(r.end).saturating_sub(millis(r.start)),
        "actor": { "user": { "uid": r.subject.user }, "session": { "uid": r.subject.session } },
        "device": { "uid": r.subject.device },
        "src_endpoint": endpoint(r.src),
        "dst_endpoint": endpoint(r.dst),
        "connection_info": {
            "protocol_num": r.protocol,
            "protocol_name": protocol_name(r.protocol),
            "uid": r.id,
        },
        "traffic": {
            "bytes_out": r.bytes_out,
            "bytes_in": r.bytes_in,
            "bytes": r.bytes_out + r.bytes_in,
            "packets_out": r.packets_out,
            "packets_in": r.packets_in,
            "packets": r.packets_out + r.packets_in,
        },
        "unmapped": { "warren": { "app": r.app, "end_reason": r.end_reason } },
    });
    merge(&mut v, fields);
    v
}

fn merge(into: &mut Value, from: Value) {
    if let (Value::Object(a), Value::Object(b)) = (into, from) {
        for (k, v) in b {
            if !v.is_null() {
                a.insert(k, v);
            }
        }
    }
}

/// Where records go.
#[derive(Debug, Clone)]
pub struct AuditSink {
    tx: Option<mpsc::Sender<Value>>,
    node: NodeInfo,
}

impl AuditSink {
    /// Writes JSON lines to stdout, or appends them to `path`. A dedicated
    /// thread does the writing so the data path never blocks on it.
    pub fn new(node: NodeInfo, path: Option<&Path>) -> std::io::Result<AuditSink> {
        let mut out: Box<dyn Write + Send> = match path {
            Some(p) => Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)?,
            ),
            None => Box::new(std::io::stdout()),
        };
        let (tx, rx) = mpsc::channel::<Value>();
        std::thread::Builder::new()
            .name("warren-audit".into())
            .spawn(move || {
                for record in rx {
                    let mut line = record.to_string();
                    line.push('\n');
                    if out
                        .write_all(line.as_bytes())
                        .and_then(|()| out.flush())
                        .is_err()
                    {
                        tracing::error!("audit sink write failed");
                    }
                }
            })?;
        Ok(AuditSink { tx: Some(tx), node })
    }

    /// A sink that collects records in memory, for tests.
    pub fn collect(node: NodeInfo) -> (AuditSink, mpsc::Receiver<Value>) {
        let (tx, rx) = mpsc::channel();
        (AuditSink { tx: Some(tx), node }, rx)
    }

    /// A sink that discards records.
    pub fn discard(node: NodeInfo) -> AuditSink {
        AuditSink { tx: None, node }
    }

    /// The node identity in records.
    pub fn node(&self) -> &NodeInfo {
        &self.node
    }

    /// Records a decision.
    pub fn decision(&self, r: &DecisionRecord<'_>) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(decision(&self.node, r));
        }
    }

    /// Records a finished flow.
    pub fn flow(&self, r: &FlowRecord<'_>) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(flow(&self.node, r));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_records_are_ocsf_shaped() {
        let node = NodeInfo {
            role: "connector".into(),
            name: "connector/homelab/c1".into(),
        };
        let rules = vec!["lab/engineers".to_string()];
        let v = decision(
            &node,
            &DecisionRecord {
                id: "abc",
                subject: Subject {
                    user: "alice",
                    device: "mac-1",
                    session: "s1",
                },
                app: Some("grafana"),
                hostname: Some("grafana.lab.example.com"),
                protocol: 6,
                src: "100.96.0.2:50000".parse().unwrap(),
                dst: "100.80.0.5:443".parse().unwrap(),
                translated_dst: Some("10.20.0.5:443".parse().unwrap()),
                allowed: false,
                reason: Some("no_rule"),
                message: "No policy allows you to reach grafana.",
                rules: &rules,
                failed_condition: None,
                policy_version: 7,
                server_initiated: false,
            },
        );
        assert_eq!(v["class_uid"], 4001);
        assert_eq!(v["activity_id"], 5);
        assert_eq!(v["type_uid"], 400_105);
        assert_eq!(v["action"], "Denied");
        assert_eq!(v["status_code"], "no_rule");
        assert_eq!(v["actor"]["user"]["uid"], "alice");
        assert_eq!(v["dst_endpoint"]["hostname"], "grafana.lab.example.com");
        assert_eq!(v["unmapped"]["warren"]["policy_version"], 7);
        assert_eq!(v["unmapped"]["warren"]["translated_dst"]["ip"], "10.20.0.5");
        assert_eq!(v["metadata"]["product"]["name"], "warren");
    }
}
