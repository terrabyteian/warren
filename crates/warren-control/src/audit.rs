//! Audit records: OCSF-shaped JSON, one record per line, to standard output
//! or a file (docs/design.md section 7.7).
//!
//! The control plane writes a record for every decision it makes itself
//! (sign-ins, device enrollment and approval, certificate issuance, policy
//! changes, node joins, revocations) and passes on the access-decision and
//! flow records connectors send it, after checking their shape and stamping
//! which node reported them.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde_json::{Map, Value, json};
use warren_core::clock;

use crate::Error;

/// The OCSF schema version the records follow.
pub const OCSF_VERSION: &str = "1.3.0";

/// Where audit records go.
pub struct Sink {
    out: Mutex<Box<dyn Write + Send>>,
}

impl Sink {
    /// Standard output.
    pub fn stdout() -> Sink {
        Sink {
            out: Mutex::new(Box::new(std::io::stdout())),
        }
    }

    /// A file, appended to and created mode 0600 if missing.
    pub fn file(path: &Path) -> Result<Sink, Error> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| Error::Config(format!("audit file {}: {e}", path.display())))?;
        Ok(Sink {
            out: Mutex::new(Box::new(file)),
        })
    }

    /// A sink writing into memory, for tests.
    pub fn memory(buffer: std::sync::Arc<Mutex<Vec<u8>>>) -> Sink {
        struct Shared(std::sync::Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if let Ok(mut b) = self.0.lock() {
                    b.extend_from_slice(data);
                }
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        Sink {
            out: Mutex::new(Box::new(Shared(buffer))),
        }
    }

    /// Writes one record as a line. Failing to write audit is reported on
    /// the operational log; it never blocks the decision being recorded.
    pub fn write(&self, record: &Value) {
        let line = record.to_string();
        match self.out.lock() {
            Ok(mut out) => {
                if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
                    crate::log::error("audit", "cannot write an audit record");
                }
            }
            Err(_) => crate::log::error("audit", "audit sink is unavailable"),
        }
    }
}

/// OCSF event classes the control plane emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Account Change (3001).
    AccountChange,
    /// Authentication (3002).
    Authentication,
    /// Entity Management (3004).
    EntityManagement,
}

impl Class {
    fn uid(self) -> u32 {
        match self {
            Class::AccountChange => 3001,
            Class::Authentication => 3002,
            Class::EntityManagement => 3004,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Class::AccountChange => "Account Change",
            Class::Authentication => "Authentication",
            Class::EntityManagement => "Entity Management",
        }
    }
}

/// OCSF activities, with their IDs within their class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// Authentication: Logon.
    Logon,
    /// Account Change: Enable.
    Enable,
    /// Account Change: Disable.
    Disable,
    /// Entity Management: Create.
    Create,
    /// Entity Management: Update.
    Update,
    /// Entity Management: Delete.
    Delete,
    /// Entity Management: Enroll.
    Enroll,
    /// Entity Management: Unenroll.
    Unenroll,
    /// Entity Management: Activate.
    Activate,
    /// Entity Management: Suspend.
    Suspend,
}

impl Activity {
    fn class(self) -> Class {
        match self {
            Activity::Logon => Class::Authentication,
            Activity::Enable | Activity::Disable => Class::AccountChange,
            _ => Class::EntityManagement,
        }
    }

    fn id_and_name(self) -> (u32, &'static str) {
        match self {
            Activity::Logon => (1, "Logon"),
            Activity::Enable => (2, "Enable"),
            Activity::Disable => (5, "Disable"),
            Activity::Create => (1, "Create"),
            Activity::Update => (3, "Update"),
            Activity::Delete => (4, "Delete"),
            Activity::Enroll => (6, "Enroll"),
            Activity::Unenroll => (7, "Unenroll"),
            Activity::Activate => (10, "Activate"),
            Activity::Suspend => (12, "Suspend"),
        }
    }
}

/// Who did something.
#[derive(Debug, Clone)]
pub enum Actor {
    /// The control plane itself (automatic approval, expiry).
    System,
    /// An admin through the local admin API.
    LocalAdmin,
    /// A user.
    User {
        /// User ID.
        id: String,
        /// Email, if known.
        email: String,
    },
    /// A relay or connector.
    Node {
        /// Node ID.
        id: String,
    },
    /// An unauthenticated party, by address.
    Anonymous,
}

impl Actor {
    fn to_value(&self) -> Value {
        match self {
            Actor::System => json!({ "app_name": "warren control plane" }),
            Actor::LocalAdmin => json!({ "app_name": "warren admin API (local socket)" }),
            Actor::User { id, email } => json!({ "user": { "uid": id, "email_addr": email } }),
            Actor::Node { id } => json!({ "app_name": "warren node", "app_uid": id }),
            Actor::Anonymous => json!({ "app_name": "unauthenticated" }),
        }
    }
}

/// Builds one control-plane record.
pub fn record(
    activity: Activity,
    success: bool,
    actor: &Actor,
    message: &str,
) -> Map<String, Value> {
    let class = activity.class();
    let (activity_id, activity_name) = activity.id_and_name();
    let mut r = Map::new();
    r.insert("class_uid".into(), class.uid().into());
    r.insert("class_name".into(), class.name().into());
    r.insert("category_uid".into(), 3.into());
    r.insert(
        "category_name".into(),
        "Identity & Access Management".into(),
    );
    r.insert("activity_id".into(), activity_id.into());
    r.insert("activity_name".into(), activity_name.into());
    r.insert("type_uid".into(), (class.uid() * 100 + activity_id).into());
    r.insert("time".into(), clock::now_millis().into());
    r.insert("severity_id".into(), 1.into());
    r.insert("status_id".into(), if success { 1 } else { 2 }.into());
    r.insert(
        "status".into(),
        if success { "Success" } else { "Failure" }.into(),
    );
    r.insert("message".into(), message.into());
    r.insert(
        "metadata".into(),
        json!({
            "version": OCSF_VERSION,
            "product": { "name": "warren", "vendor_name": "warren", "version": env!("CARGO_PKG_VERSION") },
            "log_name": "control-plane",
        }),
    );
    r.insert("actor".into(), actor.to_value());
    r
}

/// The OCSF entity object for something the control plane manages.
pub fn entity(kind: &str, uid: &str) -> Value {
    json!({ "type": kind, "uid": uid })
}

/// The largest single record accepted from a node.
pub const MAX_RECORD: usize = 64 << 10;

/// Checks and stamps the records a node sends (newline-delimited JSON).
/// Every line must be a JSON object with an integer `class_uid` and an
/// integer `time`; on any error nothing is accepted and the error names the
/// line. The control plane overwrites `metadata.log_provider` with the
/// reporting node, `metadata.log_name` with its role (`relay` or
/// `connector`), and sets `metadata.logged_time`, so a node can neither
/// claim another node's records nor pass its own off as the control
/// plane's.
pub fn accept_node_records(body: &[u8], reporter: &str, role: &str) -> Result<Vec<Value>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "audit records must be UTF-8".to_owned())?;
    let now = clock::now_millis();
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_RECORD {
            return Err(format!(
                "line {}: record larger than {MAX_RECORD} bytes",
                i + 1
            ));
        }
        let mut value: Value =
            serde_json::from_str(line).map_err(|e| format!("line {}: not JSON: {e}", i + 1))?;
        let Some(obj) = value.as_object_mut() else {
            return Err(format!("line {}: a record must be a JSON object", i + 1));
        };
        if !obj.get("class_uid").is_some_and(Value::is_u64)
            || !obj.get("time").is_some_and(Value::is_i64)
        {
            return Err(format!(
                "line {}: a record needs integer class_uid and time",
                i + 1
            ));
        }
        let metadata = obj
            .entry("metadata")
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(metadata) = metadata.as_object_mut() else {
            return Err(format!("line {}: metadata must be an object", i + 1));
        };
        metadata.insert("log_provider".into(), reporter.into());
        metadata.insert("log_name".into(), role.into());
        metadata.insert("logged_time".into(), now.into());
        out.push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_have_the_ocsf_shape() {
        let r = record(Activity::Enroll, true, &Actor::System, "device enrolled");
        assert_eq!(r["class_uid"], 3004);
        assert_eq!(r["type_uid"], 300_406);
        assert_eq!(r["status_id"], 1);
        assert_eq!(r["metadata"]["version"], OCSF_VERSION);
        let r = record(Activity::Disable, false, &Actor::LocalAdmin, "x");
        assert_eq!(r["type_uid"], 300_105);
        assert_eq!(r["status"], "Failure");
    }

    #[test]
    fn node_records_are_checked_and_stamped() {
        let body = b"{\"class_uid\":4001,\"time\":5,\"metadata\":{\"log_provider\":\"forged\"}}\n\n{\"class_uid\":3005,\"time\":6}\n";
        let records =
            accept_node_records(body, "warren://example.com/connector/g/n-1", "connector").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0]["metadata"]["log_provider"],
            "warren://example.com/connector/g/n-1"
        );
        assert!(records[1]["metadata"]["logged_time"].is_i64());
        for bad in [
            &b"[1]"[..],
            b"{\"time\":1}",
            b"{\"class_uid\":\"x\",\"time\":1}",
            b"nope",
            b"{\"class_uid\":1,\"time\":1,\"metadata\":3}",
        ] {
            assert!(
                accept_node_records(bad, "x", "connector").is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let err =
            accept_node_records(b"{\"class_uid\":1,\"time\":1}\n{}", "x", "connector").unwrap_err();
        assert!(err.starts_with("line 2"), "{err}");
    }
}
