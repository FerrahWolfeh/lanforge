//! The daemon's log filter at runtime.
//!
//! What `RUST_LOG` set at boot, a filter saved through the API, and one set for a limited time
//! on top of either. The subscriber itself lives in the binary; it hands [`LogLevels`] the
//! function that swaps its filter.

use std::sync::{Arc, Weak};
use std::time::Duration;

use lanforge_types::logging::{LogFilter, LogLevelStatus, LogSource};
use parking_lot::Mutex;
use tokio::time::{Instant, sleep};
use tracing::info;

type Apply = Box<dyn Fn(&LogFilter) + Send + Sync>;

struct Temporary {
    filter: LogFilter,
    until: Instant,
    /// Which `set_for` armed it: a timer whose filter was since replaced does nothing.
    generation: u64,
}

struct Levels {
    boot: LogFilter,
    boot_source: LogSource,
    saved: Option<LogFilter>,
    temporary: Option<Temporary>,
    generation: u64,
}

impl Levels {
    const fn active(&self) -> (&LogFilter, LogSource) {
        if let Some(t) = &self.temporary {
            (&t.filter, LogSource::Temporary)
        } else if let Some(s) = &self.saved {
            (s, LogSource::Saved)
        } else {
            (&self.boot, self.boot_source)
        }
    }
}

/// The daemon's log filter. Shared through the context (`get_shared::<LogLevels>()`).
pub struct LogLevels {
    levels: Mutex<Levels>,
    apply: Apply,
}

impl LogLevels {
    /// `boot` is the filter `RUST_LOG` gave (`None`: unset, `info`); `apply` swaps the
    /// subscriber's filter and is called with every change, under the lock, so calls never
    /// reorder.
    #[must_use]
    pub fn new(
        boot: Option<LogFilter>,
        apply: impl Fn(&LogFilter) + Send + Sync + 'static,
    ) -> Self {
        let boot_source = if boot.is_some() {
            LogSource::Env
        } else {
            LogSource::Default
        };
        Self {
            levels: Mutex::new(Levels {
                boot: boot.unwrap_or_default(),
                boot_source,
                saved: None,
                temporary: None,
                generation: 0,
            }),
            apply: Box::new(apply),
        }
    }

    #[must_use]
    pub fn status(&self) -> LogLevelStatus {
        let levels = self.levels.lock();
        let (active, source) = levels.active();
        LogLevelStatus {
            active: active.clone(),
            source,
            saved: levels.saved.clone(),
            boot: levels.boot.clone(),
            expires_in_secs: levels
                .temporary
                .as_ref()
                .map(|t| t.until.saturating_duration_since(Instant::now()).as_secs()),
        }
    }

    /// The filter saved before this run (read from redb at boot). Does not log: nothing changed
    /// from the operator's point of view.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the lock is held while applying, so concurrent changes reach the subscriber in order"
    )]
    pub fn restore(&self, saved: Option<LogFilter>) {
        let mut levels = self.levels.lock();
        levels.saved = saved;
        let (active, _) = levels.active();
        (self.apply)(active);
    }

    /// Saves `filter` (`None`: back to `RUST_LOG`), ending any temporary filter. The caller
    /// persists it.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the lock is held while applying, so concurrent changes reach the subscriber in order"
    )]
    pub fn save(&self, filter: Option<LogFilter>) {
        let mut levels = self.levels.lock();
        levels.temporary = None;
        levels.generation += 1;
        levels.saved = filter;
        self.switch(&levels, "saved");
    }

    /// Sets `filter` for `duration`, then returns to the saved filter (or `RUST_LOG`).
    pub fn set_for(self: &Arc<Self>, filter: LogFilter, duration: Duration) {
        let mut levels = self.levels.lock();
        levels.generation += 1;
        let generation = levels.generation;
        levels.temporary = Some(Temporary {
            filter,
            until: Instant::now() + duration,
            generation,
        });
        self.switch(&levels, &format!("for {}s", duration.as_secs()));
        drop(levels);

        let this: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            sleep(duration).await;
            if let Some(this) = this.upgrade() {
                this.expire(generation);
            }
        });
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the lock is held while applying, so concurrent changes reach the subscriber in order"
    )]
    fn expire(&self, generation: u64) {
        let mut levels = self.levels.lock();
        if levels
            .temporary
            .as_ref()
            .is_some_and(|t| t.generation == generation)
        {
            levels.temporary = None;
            self.switch(&levels, "temporary filter ended");
        }
    }

    /// Applies the active filter, logging the change first: under the old filter, so the line
    /// shows even when the new one is quieter.
    fn switch(&self, levels: &Levels, why: &str) {
        let (active, source) = levels.active();
        info!(filter = %active, ?source, "Log filter changed ({why})");
        (self.apply)(active);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use lanforge_types::logging::{LogFilter, LogSource};
    use parking_lot::Mutex;
    use tokio::time::sleep;

    use super::LogLevels;

    fn f(s: &str) -> LogFilter {
        s.parse().expect("filter")
    }

    /// Levels whose `apply` records every filter it was given.
    fn levels(boot: Option<&str>) -> (Arc<LogLevels>, Arc<Mutex<Vec<String>>>) {
        let applied = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&applied);
        let levels = LogLevels::new(boot.map(f), move |filter| {
            sink.lock().push(filter.to_string());
        });
        (Arc::new(levels), applied)
    }

    #[test]
    fn boot_filter_comes_from_rust_log_or_defaults_to_info() {
        let (l, _) = levels(None);
        let s = l.status();
        assert_eq!(
            (s.active, s.source),
            (LogFilter::info(), LogSource::Default)
        );
        let (l, _) = levels(Some("debug"));
        let s = l.status();
        assert_eq!((s.active, s.source), (f("debug"), LogSource::Env));
    }

    #[test]
    fn a_saved_filter_wins_over_rust_log_until_it_is_cleared() {
        let (l, applied) = levels(Some("warn"));
        l.restore(Some(f("debug")));
        assert_eq!(l.status().source, LogSource::Saved);
        l.save(Some(f("info,lanforge_dns=debug")));
        assert_eq!(l.status().active, f("info,lanforge_dns=debug"));
        l.save(None);
        let s = l.status();
        assert_eq!(
            (s.active, s.source, s.saved),
            (f("warn"), LogSource::Env, None)
        );
        assert_eq!(
            *applied.lock(),
            ["debug", "info,lanforge_dns=debug", "warn"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_temporary_filter_ends_on_time_and_returns_to_the_saved_one() {
        let (l, applied) = levels(None);
        l.restore(Some(f("debug")));
        l.set_for(f("trace"), Duration::from_secs(600));
        let s = l.status();
        assert_eq!(
            (s.active.clone(), s.source),
            (f("trace"), LogSource::Temporary)
        );
        assert_eq!(s.saved, Some(f("debug")));
        assert_eq!(s.expires_in_secs, Some(600));

        sleep(Duration::from_secs(599)).await;
        assert_eq!(l.status().source, LogSource::Temporary);
        sleep(Duration::from_secs(2)).await;
        let s = l.status();
        assert_eq!(
            (s.active, s.source, s.expires_in_secs),
            (f("debug"), LogSource::Saved, None)
        );
        assert_eq!(*applied.lock(), ["debug", "trace", "debug"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_replaced_temporary_filter_keeps_its_own_deadline() {
        let (l, _) = levels(None);
        l.set_for(f("debug"), Duration::from_secs(60));
        l.set_for(f("debug-all"), Duration::from_secs(600));
        // The first timer fires and must not end the second filter.
        sleep(Duration::from_secs(120)).await;
        assert_eq!(l.status().active, f("debug-all"));
        sleep(Duration::from_secs(600)).await;
        assert_eq!(l.status().source, LogSource::Default);
    }

    #[tokio::test(start_paused = true)]
    async fn saving_ends_a_temporary_filter() {
        let (l, _) = levels(None);
        l.set_for(f("trace"), Duration::from_secs(600));
        l.save(Some(f("debug")));
        let s = l.status();
        assert_eq!(
            (s.active, s.source, s.expires_in_secs),
            (f("debug"), LogSource::Saved, None)
        );
        sleep(Duration::from_secs(700)).await;
        assert_eq!(l.status().active, f("debug"));
    }
}
