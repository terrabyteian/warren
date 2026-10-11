//! Structured logs: JSON lines on stderr, one object per event, so they can
//! be shipped and queried like the audit records on stdout.

use tracing::Level;

/// Starts JSON logging at `level` (`error`, `warn`, `info`, `debug` or
/// `trace`). Logs from dependencies are capped at `warn` unless the level is
/// `trace`.
pub fn init(level: &str) {
    let level: Level = level.parse().unwrap_or(Level::INFO);
    let deps = if level == Level::TRACE {
        Level::TRACE
    } else {
        Level::WARN
    };
    let filter = tracing_subscriber::filter::Targets::new()
        .with_default(deps)
        .with_target("warren", level)
        .with_target("warren_core", level)
        .with_target("warren_masque", level)
        .with_target("warren_relay", level)
        .with_target("warren_connector", level)
        .with_target("warren_client", level)
        .with_target("warren_harness", level);
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(std::io::stderr),
        )
        .with(filter)
        .try_init();
}
