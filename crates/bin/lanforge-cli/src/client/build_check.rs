//! Warns once per run when the daemon was built from another commit than this CLI.

use std::sync::Once;

use chrono::{DateTime, Local};
use colored::Colorize;
use lanforge_types::build::{BuildInfo, BuildOrder};

static CHECKED: Once = Once::new();

/// This CLI's build.
#[must_use]
pub fn cli_build() -> BuildInfo {
    BuildInfo::parse(env!("LANFORGE_BUILD")).unwrap_or_else(|| BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
    })
}

/// Compares the daemon's build token (`None` when it sent none) with this CLI's, the first
/// time only; prints a warning on stderr when they differ.
pub fn check_daemon_build(daemon: Option<&str>) {
    CHECKED.call_once(|| {
        if let Some(msg) = mismatch(&cli_build(), daemon) {
            eprintln!("{} {msg}", "⚠".yellow().bold());
        }
    });
}

/// The warning for a daemon build `daemon` seen from `cli`; `None` when they match.
fn mismatch(cli: &BuildInfo, daemon: Option<&str>) -> Option<String> {
    let Some(daemon) = daemon.and_then(BuildInfo::parse) else {
        return Some(format!(
            "the daemon reports no build: it predates this CLI ({})",
            describe(cli)
        ));
    };
    let relation = match cli.order_of(&daemon) {
        BuildOrder::Same => return None,
        BuildOrder::Older => "older than",
        BuildOrder::Newer => "newer than",
        BuildOrder::Different => "different from",
    };
    Some(format!(
        "the daemon runs a build {relation} this CLI: daemon {}, CLI {}",
        describe(&daemon),
        describe(cli)
    ))
}

/// `0.40.0 (74ea33b0e126, 2026-11-03 12:44, local changes)`, commit time in local time.
pub fn describe(build: &BuildInfo) -> String {
    let Some(commit) = &build.commit else {
        return build.version.clone();
    };
    let when = i64::try_from(commit.time)
        .ok()
        .and_then(|t| DateTime::from_timestamp(t, 0))
        .map_or_else(String::new, |t| {
            format!(", {}", t.with_timezone(&Local).format("%Y-%m-%d %H:%M"))
        });
    let dirty = if commit.dirty { ", local changes" } else { "" };
    format!("{} ({}{when}{dirty})", build.version, commit.hash)
}

#[cfg(test)]
mod tests {
    use super::mismatch;
    use lanforge_types::build::BuildInfo;

    fn build(token: &str) -> BuildInfo {
        BuildInfo::parse(token).unwrap()
    }

    #[test]
    fn the_same_build_says_nothing() {
        let cli = build("0.40.0+aaaa.200");
        assert_eq!(mismatch(&cli, Some("0.40.0+aaaa.200")), None);
    }

    #[test]
    fn a_different_build_is_named_with_its_side() {
        let cli = build("0.40.0+aaaa.1762160000");
        let msg = mismatch(&cli, Some("0.40.1+bbbb.1762170000")).unwrap();
        assert!(msg.contains("newer than"), "{msg}");
        assert!(msg.contains("daemon 0.40.1 (bbbb, 2025-11-0"), "{msg}");
        let msg = mismatch(&cli, Some("0.40.0+aaaa.1762160000.dirty")).unwrap();
        assert!(msg.contains("different from"), "{msg}");
        assert!(msg.contains("local changes"), "{msg}");
    }

    #[test]
    fn a_daemon_without_a_build_predates_the_check() {
        let cli = build("0.40.0+aaaa.200");
        for daemon in [None, Some("garbage")] {
            let msg = mismatch(&cli, daemon).unwrap();
            assert!(msg.contains("predates"), "{msg}");
        }
    }
}
