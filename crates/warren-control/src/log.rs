//! Operational logs: one JSON object per line on standard error. Values
//! from users and peers are always fields, never spliced into the message
//! format, so a log line cannot be forged from outside (threat model T16).
//! Audit records are separate; see [`crate::audit`].

use std::io::Write;

use warren_core::clock;

fn write(level: &str, component: &str, message: &str, fields: &[(&str, &str)]) {
    let mut line = serde_json::Map::new();
    line.insert("time".into(), clock::rfc3339(clock::now_secs()).into());
    line.insert("level".into(), level.into());
    line.insert("component".into(), component.into());
    line.insert("message".into(), message.into());
    for (k, v) in fields {
        line.insert((*k).into(), (*v).into());
    }
    let text = serde_json::Value::Object(line).to_string();
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{text}");
}

/// An informational line.
pub fn info(component: &str, message: &str) {
    write("info", component, message, &[]);
}

/// An informational line with fields.
pub fn info_with(component: &str, message: &str, fields: &[(&str, &str)]) {
    write("info", component, message, fields);
}

/// A warning.
pub fn warn(component: &str, message: &str) {
    write("warn", component, message, &[]);
}

/// A warning with fields.
pub fn warn_with(component: &str, message: &str, fields: &[(&str, &str)]) {
    write("warn", component, message, fields);
}

/// An error.
pub fn error(component: &str, message: &str) {
    write("error", component, message, &[]);
}
