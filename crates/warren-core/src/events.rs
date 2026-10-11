//! The revocation push channel (docs/protocol.md section 12).
//!
//! Each relay and connector holds one long-lived `GET /v1/node/events`
//! response from the control plane. The body is a stream of JSON lines
//! (newline-delimited JSON, one [`Line`] per line): events in sequence order,
//! a heartbeat at least every `EVENT_HEARTBEAT_INTERVAL`, and a snapshot
//! when the node asks to resume from a sequence number the control plane no
//! longer retains. Nodes acknowledge each event with `POST
//! /v1/node/events/ack`, saying when it took effect and how many
//! connections it cut.

use serde::{Deserialize, Serialize};

use crate::policy_bundle::Revocations;

/// One line of the event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// An event to apply.
    Event(Event),
    /// The stream is alive; `seq` is the last sequence number sent on it,
    /// which is the latest committed one once the stream has caught up.
    Heartbeat {
        /// The last sequence number sent.
        seq: u64,
        /// The control plane's clock, Unix milliseconds.
        time_ms: i64,
    },
    /// The full revocation state and the current bundle, sent instead of
    /// events the control plane no longer retains. The node replaces its
    /// revocation state, fetches the bundle if it is newer than its own, and
    /// continues from `seq`.
    Snapshot(Snapshot),
    /// A line of a type this build does not know. Nodes log it and refresh
    /// their bundle; they never ignore it silently (section 12, item 8).
    Unknown {
        /// The sequence number, if the line had one.
        seq: Option<u64>,
        /// The line's `type`.
        kind: String,
    },
}

/// A committed event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The deployment-wide, strictly increasing sequence number.
    pub seq: u64,
    /// When the control plane committed the change, Unix milliseconds; the
    /// start of the revocation deadline.
    pub committed_at_ms: i64,
    /// What happened.
    #[serde(flatten)]
    pub body: EventBody,
}

/// What an event says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventBody {
    /// A user was disabled: cut every session of theirs.
    UserDisabled {
        /// The user.
        user_id: String,
    },
    /// A device was disabled (reversibly) or revoked (permanently): cut
    /// every session from it.
    DeviceDisabled {
        /// The device.
        device_id: String,
        /// True when the device can never be re-enabled.
        revoked: bool,
    },
    /// A sign-in session was revoked: cut every connection authenticated by
    /// a certificate of that session.
    SessionRevoked {
        /// The session.
        session_id: String,
    },
    /// One certificate was revoked.
    CertificateRevoked {
        /// The serial number, lowercase hex.
        serial: String,
        /// When it expires anyway, Unix seconds; nodes keep it until then.
        not_after: i64,
    },
    /// A relay or connector was revoked: close its connections.
    NodeRevoked {
        /// The node.
        node_id: String,
    },
    /// The user must sign in again before their sessions continue.
    ReauthRequired {
        /// The user.
        user_id: String,
    },
    /// A new bundle is available. It may remove access (re-evaluate every
    /// live flow against it) or add access; either way, fetch it.
    BundleUpdated {
        /// The new version.
        version: u64,
        /// The digest of its compiled policy set.
        digest: String,
    },
}

impl EventBody {
    /// The event's `type` string.
    pub fn kind(&self) -> &'static str {
        match self {
            EventBody::UserDisabled { .. } => "user_disabled",
            EventBody::DeviceDisabled { .. } => "device_disabled",
            EventBody::SessionRevoked { .. } => "session_revoked",
            EventBody::CertificateRevoked { .. } => "certificate_revoked",
            EventBody::NodeRevoked { .. } => "node_revoked",
            EventBody::ReauthRequired { .. } => "reauth_required",
            EventBody::BundleUpdated { .. } => "bundle_updated",
        }
    }
}

/// A full revocation snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The sequence number the snapshot is current as of.
    pub seq: u64,
    /// The full revocation state.
    pub revocations: Revocations,
    /// The current bundle version.
    pub bundle_version: u64,
    /// The current bundle's policy digest.
    pub bundle_digest: String,
}

impl Line {
    /// Encodes the line as JSON, without the trailing newline.
    pub fn to_json(&self) -> String {
        let value = match self {
            Line::Event(e) => serde_json::to_value(e),
            Line::Heartbeat { seq, time_ms } => Ok(serde_json::json!({
                "type": "heartbeat",
                "seq": seq,
                "time_ms": time_ms,
            })),
            Line::Snapshot(s) => serde_json::to_value(s).map(|mut v| {
                if let Some(o) = v.as_object_mut() {
                    o.insert("type".into(), "snapshot".into());
                }
                v
            }),
            Line::Unknown { seq, kind } => Ok(serde_json::json!({ "type": kind, "seq": seq })),
        };
        value.map(|v| v.to_string()).unwrap_or_default()
    }

    /// Decodes one line. Lines of an unknown type decode to
    /// [`Line::Unknown`]; lines that are not JSON objects with a string
    /// `type`, or known types with missing fields, are errors.
    pub fn parse(text: &str) -> Result<Line, String> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("event line is not JSON: {e}"))?;
        let kind = value
            .get("type")
            .and_then(|t| t.as_str())
            .ok_or("event line has no type")?
            .to_owned();
        let bad = |e: serde_json::Error| format!("malformed {kind} line: {e}");
        match kind.as_str() {
            "heartbeat" => {
                #[derive(Deserialize)]
                struct Heartbeat {
                    seq: u64,
                    time_ms: i64,
                }
                let h: Heartbeat = serde_json::from_value(value).map_err(bad)?;
                Ok(Line::Heartbeat {
                    seq: h.seq,
                    time_ms: h.time_ms,
                })
            }
            "snapshot" => Ok(Line::Snapshot(serde_json::from_value(value).map_err(bad)?)),
            "user_disabled"
            | "device_disabled"
            | "session_revoked"
            | "certificate_revoked"
            | "node_revoked"
            | "reauth_required"
            | "bundle_updated" => Ok(Line::Event(serde_json::from_value(value).map_err(bad)?)),
            _ => Ok(Line::Unknown {
                seq: value.get("seq").and_then(|s| s.as_u64()),
                kind,
            }),
        }
    }
}

/// A node's acknowledgement that an event took effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// The event's sequence number.
    pub seq: u64,
    /// When the node finished applying it, Unix milliseconds on the node's
    /// clock.
    pub applied_at_ms: i64,
    /// How many connections or flows it cut.
    pub connections_cut: u64,
}

/// The body of `POST /v1/node/events/ack`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckRequest {
    /// One entry per applied event.
    pub acks: Vec<Ack>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_round_trip() {
        let lines = [
            Line::Event(Event {
                seq: 7,
                committed_at_ms: 1_791_715_800_000,
                body: EventBody::UserDisabled {
                    user_id: "u-1".into(),
                },
            }),
            Line::Event(Event {
                seq: 8,
                committed_at_ms: 1,
                body: EventBody::BundleUpdated {
                    version: 3,
                    digest: "sha256:00".into(),
                },
            }),
            Line::Heartbeat { seq: 8, time_ms: 2 },
            Line::Snapshot(Snapshot {
                seq: 8,
                revocations: Revocations::default(),
                bundle_version: 3,
                bundle_digest: "sha256:00".into(),
            }),
        ];
        for line in lines {
            let text = line.to_json();
            assert!(!text.contains('\n'));
            assert_eq!(Line::parse(&text).unwrap(), line);
        }
        let event = Line::Event(Event {
            seq: 7,
            committed_at_ms: 5,
            body: EventBody::UserDisabled {
                user_id: "u-1".into(),
            },
        });
        let value: serde_json::Value = serde_json::from_str(&event.to_json()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "type": "user_disabled",
                "seq": 7,
                "committed_at_ms": 5,
                "user_id": "u-1",
            })
        );
    }

    #[test]
    fn unknown_and_malformed_lines() {
        assert_eq!(
            Line::parse(r#"{"type":"grant_expired","seq":9,"grant_id":"g"}"#).unwrap(),
            Line::Unknown {
                seq: Some(9),
                kind: "grant_expired".into()
            }
        );
        assert!(Line::parse(r#"{"type":"user_disabled","seq":1}"#).is_err());
        assert!(Line::parse(r#"{"seq":1}"#).is_err());
        assert!(Line::parse("not json").is_err());
    }
}
