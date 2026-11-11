#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions and setup"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! `NO_COLOR` follows <https://no-color.org>: any non-empty value turns colours off, and it never
//! stops a command (it was a clap `bool` env that refused the usual `NO_COLOR=1`).

use std::process::Command;

/// Runs a command that fails on the socket (no daemon) and returns its stderr. No saved login
/// is reachable: on a dev PC the CLI would otherwise log into the real router by itself.
fn stderr_with(no_color: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_lanforge"))
        .args(["-s", "/nonexistent/lanforge.sock", "status"])
        .env("NO_COLOR", no_color)
        .env("HOME", "/nonexistent")
        .env("XDG_DATA_HOME", "/nonexistent")
        .env_remove("LANFORGE_REMOTE_URL")
        .env_remove("LANFORGE_TOKEN")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn no_color_one_does_not_stop_the_cli() {
    for value in ["1", "yes", "true", ""] {
        let err = stderr_with(value);
        assert!(!err.contains("--no-color"), "NO_COLOR={value:?}: {err}");
    }
}

/// The error report is plain too.
#[test]
fn no_color_set_leaves_no_ansi_codes() {
    let err = stderr_with("1");
    assert!(err.contains("error"), "{err:?}");
    assert!(!err.contains('\u{1b}'), "{err:?}");
}

/// A failed command prints one `error:` line and exits 1: no `Location:` of the CLI source and no
/// backtrace hint, which made a daemon refusal look like a crash.
#[test]
fn an_error_is_one_line_and_exit_code_one() {
    let out = Command::new(env!("CARGO_BIN_EXE_lanforge"))
        .args(["-s", "/nonexistent/lanforge.sock", "status"])
        .env("NO_COLOR", "1")
        .env("HOME", "/nonexistent")
        .env("XDG_DATA_HOME", "/nonexistent")
        .env_remove("LANFORGE_REMOTE_URL")
        .env_remove("LANFORGE_TOKEN")
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(
        err.starts_with("error: Failed to connect to daemon"),
        "{err}"
    );
    assert!(
        !err.contains("Location") && !err.contains("Backtrace"),
        "{err}"
    );
}
