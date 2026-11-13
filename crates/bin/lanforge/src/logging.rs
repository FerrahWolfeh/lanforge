//! The daemon's log subscriber.

use std::sync::Arc;

use lanforge_core::logging::LogLevels;
use lanforge_types::logging::{LogFilter, LogLevel};
use tracing::{Level, Subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, registry, reload};

/// The log subscriber and the [`LogLevels`] that change its filter at runtime: plain text
/// without timestamps (journald stamps them).
///
/// `rust_log` is the `RUST_LOG` value, a [`LogFilter`] (`info`, `debug`, `debug-all`,
/// `info,lanforge_dns=debug`). Without one, `info`; one that does not parse is reported in
/// the third value, to be logged once the subscriber is installed, and `info` is used.
#[must_use]
pub fn subscriber(
    rust_log: Option<&str>,
) -> (
    impl Subscriber + Send + Sync,
    Arc<LogLevels>,
    Option<String>,
) {
    let (boot, error) = match rust_log.map(str::parse::<LogFilter>) {
        None => (None, None),
        Some(Ok(filter)) => (Some(filter), None),
        Some(Err(e)) => (
            None,
            Some(format!("RUST_LOG is not a log filter ({e}); using info")),
        ),
    };
    let (filter, handle) = reload::Layer::new(targets(&boot.clone().unwrap_or_default()));
    let levels = LogLevels::new(boot, move |filter| {
        // Fails only once the subscriber is gone (shutdown).
        let _ = handle.reload(targets(filter));
    });
    // `registry` + layer, not `fmt()`: the `fmt()` builder carries its own INFO ceiling, which a
    // filter layered on top can only lower.
    let subscriber = registry().with(fmt::layer().without_time()).with(filter);
    (subscriber, Arc::new(levels), error)
}

/// `filter` as `tracing` targets: the most specific matching target wins, so an override
/// beats lanforge's level, which beats the libraries' default.
fn targets(filter: &LogFilter) -> Targets {
    Targets::new()
        .with_default(level(filter.library_level()))
        .with_target(LogFilter::OWN_TARGET, level(filter.level))
        .with_targets(
            filter
                .targets
                .iter()
                .map(|t| (t.target.to_string(), level(t.level))),
        )
}

const fn level(level: LogLevel) -> Level {
    match level {
        LogLevel::Error => Level::ERROR,
        LogLevel::Warn => Level::WARN,
        LogLevel::Info => Level::INFO,
        LogLevel::Debug => Level::DEBUG,
        LogLevel::Trace => Level::TRACE,
    }
}

#[cfg(test)]
mod tests {
    use super::subscriber;
    use lanforge_core::logging::LogLevels;
    use tracing::subscriber::with_default;
    use tracing::{Level, enabled};

    /// The most verbose level enabled for a lanforge module, one of its submodules, and a
    /// library, under `subscriber` — re-read after `change` ran.
    fn most_verbose(rust_log: Option<&str>, change: impl FnOnce(&LogLevels)) -> [Option<Level>; 3] {
        let (sub, levels, _) = subscriber(rust_log);
        with_default(sub, || {
            change(&levels);
            macro_rules! max {
                ($target:literal) => {
                    if enabled!(target: $target, Level::TRACE) {
                        Some(Level::TRACE)
                    } else if enabled!(target: $target, Level::DEBUG) {
                        Some(Level::DEBUG)
                    } else if enabled!(target: $target, Level::INFO) {
                        Some(Level::INFO)
                    } else if enabled!(target: $target, Level::WARN) {
                        Some(Level::WARN)
                    } else if enabled!(target: $target, Level::ERROR) {
                        Some(Level::ERROR)
                    } else {
                        None
                    }
                };
            }
            [
                max!("lanforge_core::y"),
                max!("lanforge_dns::resolver"),
                max!("hyper::proto"),
            ]
        })
    }

    const T: Option<Level> = Some(Level::TRACE);
    const D: Option<Level> = Some(Level::DEBUG);
    const I: Option<Level> = Some(Level::INFO);
    const W: Option<Level> = Some(Level::WARN);

    #[test]
    fn rust_log_sets_the_boot_filter() {
        let none = |_: &_| {};
        assert_eq!(most_verbose(None, none), [I, I, I]);
        assert_eq!(most_verbose(Some("info"), none), [I, I, I]);
        // A bare level is lanforge's; `-all` reaches libraries.
        assert_eq!(most_verbose(Some("debug"), none), [D, D, I]);
        assert_eq!(most_verbose(Some("debug-all"), none), [D, D, D]);
        assert_eq!(most_verbose(Some("trace-all"), none), [T, T, T]);
        assert_eq!(most_verbose(Some("warn"), none), [W, W, W]);
        // The most specific target wins, in both directions.
        assert_eq!(
            most_verbose(Some("info,lanforge_dns=debug"), none),
            [I, D, I]
        );
        assert_eq!(
            most_verbose(Some("debug,lanforge_dns=warn"), none),
            [D, W, I]
        );
        // Garbage no longer silences everything: it falls back to info.
        for bad in ["foo =", "lanforge_dns=loud", ""] {
            assert_eq!(most_verbose(Some(bad), none), [I, I, I], "{bad:?}");
        }
    }

    #[test]
    fn a_change_at_runtime_reaches_the_subscriber() {
        let saved = most_verbose(Some("info"), |l| {
            l.save(Some("debug,lanforge_dns=trace".parse().expect("filter")));
        });
        assert_eq!(saved, [D, T, I]);
        let reset = most_verbose(Some("warn"), |l| {
            l.save(Some("debug-all".parse().expect("filter")));
            l.save(None);
        });
        assert_eq!(reset, [W, W, W]);
    }

    #[test]
    fn rust_log_errors_are_reported() {
        assert!(subscriber(Some("loud")).2.is_some());
        assert!(subscriber(Some("debug")).2.is_none());
        assert!(subscriber(None).2.is_none());
    }
}
