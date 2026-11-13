//! The daemon's log subscriber.

use tracing::{Level, Subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, registry};

/// The log subscriber: plain text without timestamps (journald stamps them).
///
/// Filtered by `spec`, the `RUST_LOG` value: a `Targets` list (`info`,
/// `info,lanforge_dns=debug`). Without one, or with one that does not parse
/// (`lanforge_dns=loud`), `info`. A list without a bare level shows only the targets it names,
/// so a malformed value that still parses as a target (`foo =`) silences the rest. No
/// span/field filters: they need `EnvFilter`'s regex engine.
#[must_use]
pub fn subscriber(spec: Option<&str>) -> impl Subscriber + Send + Sync {
    let filter = spec
        .and_then(|s| s.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    // `registry` + layer, not `fmt()`: the `fmt()` builder carries its own INFO ceiling, which a
    // filter layered on top can only lower.
    registry().with(fmt::layer().without_time()).with(filter)
}

#[cfg(test)]
mod tests {
    use super::subscriber;
    use tracing::subscriber::with_default;
    use tracing::{Level, enabled};

    /// Which of the given levels are enabled for target `lanforge_dns::x` and `lanforge_core::y`.
    fn enabled_for(spec: Option<&str>) -> [(bool, bool); 3] {
        with_default(subscriber(spec), || {
            [Level::TRACE, Level::DEBUG, Level::INFO].map(|level| {
                (
                    match level {
                        Level::TRACE => enabled!(target: "lanforge_dns::x", Level::TRACE),
                        Level::DEBUG => enabled!(target: "lanforge_dns::x", Level::DEBUG),
                        _ => enabled!(target: "lanforge_dns::x", Level::INFO),
                    },
                    match level {
                        Level::TRACE => enabled!(target: "lanforge_core::y", Level::TRACE),
                        Level::DEBUG => enabled!(target: "lanforge_core::y", Level::DEBUG),
                        _ => enabled!(target: "lanforge_core::y", Level::INFO),
                    },
                )
            })
        })
    }

    #[test]
    fn rust_log_levels_reach_the_subscriber() {
        // [trace, debug, info] × (lanforge_dns, lanforge_core)
        assert_eq!(enabled_for(Some("trace")), [(true, true); 3]);
        assert_eq!(
            enabled_for(Some("debug")),
            [(false, false), (true, true), (true, true)]
        );
        assert_eq!(
            enabled_for(Some("info,lanforge_dns=debug")),
            [(false, false), (true, false), (true, true)]
        );
        for default in [None, Some("info"), Some("lanforge_dns=loud")] {
            assert_eq!(
                enabled_for(default),
                [(false, false), (false, false), (true, true)],
                "{default:?}"
            );
        }
    }
}
