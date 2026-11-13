//! What the daemon logs: a [`LogFilter`], set from `RUST_LOG` at boot and changed at runtime
//! through the API (saved in redb, or for a limited time).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A log verbosity, from the quietest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub const ALL: [Self; 5] = [
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|l| l.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unknown log level `{s}` (error, warn, info, debug, trace)"))
    }
}

/// One `target=level` override: `target` is a module path (`lanforge_dns`,
/// `lanforge_dhcp::v4`) and covers everything below it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogTarget {
    pub target: Box<str>,
    pub level: LogLevel,
}

/// What the daemon logs, written as a comma-separated list:
///
/// - `debug`: lanforge's own modules at that level; libraries (hyper, rustls, redb, ...) at
///   `info`, or quieter if the level is (`warn`: everything at `warn`);
/// - `debug-all`: everything at that level, libraries included;
/// - `lanforge_dns=trace`: one module path and everything below it, overriding the above.
///
/// `info,lanforge_dns=debug` is lanforge at `info` and its DNS at `debug`. A list without a
/// bare level keeps `info` for the rest. Levels and `-all` are case-insensitive, targets are
/// lowercase module paths, and each target appears once.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct LogFilter {
    /// Level of lanforge's own modules.
    pub level: LogLevel,
    /// Whether `level` also applies to libraries (`-all`).
    pub all: bool,
    /// Per-module overrides, in the order written.
    pub targets: Vec<LogTarget>,
}

impl LogFilter {
    /// The module path prefix of every lanforge crate (`lanforge_dns`, `lanforged`, ...).
    pub const OWN_TARGET: &'static str = "lanforge";
    /// More overrides than any real use needs; bounds what a request can make us parse.
    pub const MAX_TARGETS: usize = 32;

    /// `info` for everything: the default.
    #[must_use]
    pub const fn info() -> Self {
        Self {
            level: LogLevel::Info,
            all: false,
            targets: Vec::new(),
        }
    }

    /// The level of modules outside lanforge (and outside every override).
    #[must_use]
    pub fn library_level(&self) -> LogLevel {
        if self.all {
            self.level
        } else {
            self.level.min(LogLevel::Info)
        }
    }

    /// The most verbose level anything is logged at.
    #[must_use]
    pub fn max_level(&self) -> LogLevel {
        self.targets
            .iter()
            .map(|t| t.level)
            .fold(self.level, LogLevel::max)
    }

    fn valid_target(t: &str) -> bool {
        !t.is_empty()
            && t.split("::").all(|seg| {
                !seg.is_empty()
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
    }
}

impl Default for LogFilter {
    fn default() -> Self {
        Self::info()
    }
}

impl FromStr for LogFilter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut base: Option<(LogLevel, bool)> = None;
        let mut targets: Vec<LogTarget> = Vec::new();
        for item in s.split(',').map(str::trim) {
            if item.is_empty() {
                return Err(format!("empty item in log filter `{s}`"));
            }
            if let Some((target, level)) = item.split_once('=') {
                let target = target.trim();
                if !Self::valid_target(target) {
                    return Err(format!(
                        "`{target}` is not a module path (lowercase, `::`-separated)"
                    ));
                }
                if targets.iter().any(|t| &*t.target == target) {
                    return Err(format!("`{target}` appears twice"));
                }
                if targets.len() == Self::MAX_TARGETS {
                    return Err(format!("more than {} targets", Self::MAX_TARGETS));
                }
                targets.push(LogTarget {
                    target: target.into(),
                    level: level.trim().parse()?,
                });
            } else {
                if base.is_some() {
                    return Err(format!("more than one bare level in `{s}`"));
                }
                let (level, all) = match item.len().checked_sub(4) {
                    Some(i)
                        if item.is_char_boundary(i) && item[i..].eq_ignore_ascii_case("-all") =>
                    {
                        (&item[..i], true)
                    }
                    _ => (item, false),
                };
                base = Some((level.parse()?, all));
            }
        }
        let (level, all) = base.unwrap_or((LogLevel::Info, false));
        Ok(Self {
            level,
            // `info-all` is `info`: one spelling per filter.
            all: all && level != LogLevel::Info,
            targets,
        })
    }
}

impl fmt::Display for LogFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.level.as_str())?;
        if self.all {
            f.write_str("-all")?;
        }
        for t in &self.targets {
            write!(f, ",{}={}", t.target, t.level)?;
        }
        Ok(())
    }
}

impl From<LogFilter> for String {
    fn from(filter: LogFilter) -> Self {
        filter.to_string()
    }
}

impl TryFrom<String> for LogFilter {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::{LogFilter, LogLevel};

    fn parse(s: &str) -> LogFilter {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn a_bare_level_is_for_lanforge_and_all_widens_it_to_libraries() {
        let debug = parse("debug");
        assert_eq!(
            (debug.level, debug.library_level()),
            (LogLevel::Debug, LogLevel::Info)
        );
        let all = parse("debug-all");
        assert_eq!(
            (all.level, all.library_level()),
            (LogLevel::Debug, LogLevel::Debug)
        );
        let trace = parse("TRACE-All");
        assert_eq!(
            (trace.level, trace.library_level()),
            (LogLevel::Trace, LogLevel::Trace)
        );
        // Quieter than info is quieter for everyone.
        assert_eq!(parse("warn").library_level(), LogLevel::Warn);
        assert_eq!(parse("info-all"), parse("info"));
    }

    #[test]
    fn targets_override_and_default_to_info_without_a_bare_level() {
        let f = parse(" lanforge_dns = trace , warn ");
        assert_eq!(f.level, LogLevel::Warn);
        assert_eq!(&*f.targets[0].target, "lanforge_dns");
        assert_eq!(f.targets[0].level, LogLevel::Trace);
        assert_eq!(f.max_level(), LogLevel::Trace);

        let f = parse("lanforge_dhcp::v4=debug");
        assert_eq!(f.level, LogLevel::Info);
        assert_eq!(f.max_level(), LogLevel::Debug);
    }

    #[test]
    fn display_is_canonical_and_round_trips() {
        for (input, shown) in [
            ("info", "info"),
            ("info-all", "info"),
            ("Debug-ALL", "debug-all"),
            ("lanforge_dns=debug", "info,lanforge_dns=debug"),
            ("lanforge_dns=debug,trace", "trace,lanforge_dns=debug"),
        ] {
            let f = parse(input);
            assert_eq!(f.to_string(), shown, "{input}");
            assert_eq!(parse(shown), f, "{input}");
        }
    }

    #[test]
    fn malformed_filters_are_refused() {
        for bad in [
            "",
            "loud",
            "debug,",
            ",debug",
            "debug,trace",
            "foo =",
            "=debug",
            "lanforge_dns=loud",
            "Lanforge_dns=debug",
            "lanforge dns=debug",
            "lanforge_dns::=debug",
            "lanforge-dns=debug",
            "a=debug,a=trace",
            "lanforge_dns=debug=trace",
            "all",
            "-all",
            "debugall",
        ] {
            assert!(bad.parse::<LogFilter>().is_err(), "{bad:?}");
        }
        let many: Vec<String> = (0..=LogFilter::MAX_TARGETS)
            .map(|i| format!("t{i}=debug"))
            .collect();
        assert!(many.join(",").parse::<LogFilter>().is_err());
    }

    #[test]
    fn serialized_as_its_text() {
        let f = parse("debug,lanforge_dns=trace");
        let json = serde_json::to_string(&f).expect("json");
        assert_eq!(json, r#""debug,lanforge_dns=trace""#);
        assert_eq!(serde_json::from_str::<LogFilter>(&json).expect("back"), f);
        assert!(serde_json::from_str::<LogFilter>(r#""loud""#).is_err());
    }
}
