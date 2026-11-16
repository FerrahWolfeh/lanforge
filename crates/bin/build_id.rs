//! Build script shared by the daemon and the CLI (`build = "../build_id.rs"`): sets
//! `LANFORGE_BUILD` to the build token read by `lanforge_types::build::BuildInfo`,
//! `<version>+<commit>.<commit time>.<webui>[.dirty]`, or just the version without git. On glibc
//! Linux it also links the binaries with packed relative relocations (see `main`).

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The web UI version from `web/package.json` (`0.0.0` when missing), read without a JSON
/// parser: the first `"version": "..."` line.
fn web_version(root: &Path) -> String {
    let Ok(text) = fs::read_to_string(root.join("web/package.json")) else {
        return "0.0.0".into();
    };
    for line in text.lines() {
        if let Some((_, rest)) = line.split_once("\"version\"")
            && let Some((_, after_colon)) = rest.split_once(':')
            && let Some((_, after_quote)) = after_colon.split_once('"')
            && let Some((ver, _)) = after_quote.split_once('"')
            && !ver.is_empty()
        {
            return ver.to_string();
        }
    }
    "0.0.0".into()
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let root = Path::new(&manifest).join("../../..");
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();

    // Rerun on a commit, checkout or stage (git files), and on any source edit (dirty flag).
    for path in ["HEAD", "index", "packed-refs"] {
        if let Some(p) = git(&root, &["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={}", root.join(p).display());
        }
    }
    if let Some(head_ref) = git(&root, &["symbolic-ref", "-q", "HEAD"])
        && let Some(p) = git(&root, &["rev-parse", "--git-path", &head_ref])
    {
        println!("cargo:rerun-if-changed={}", root.join(p).display());
    }
    for path in [
        "crates",
        "web/src",
        "web/package.json",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }

    let webui = web_version(&root);
    let token = match git(&root, &["log", "-1", "--format=%h %ct", "--abbrev=12"])
        .as_deref()
        .and_then(|line| line.split_once(' '))
    {
        Some((hash, time)) => {
            // Tracked files only: scratch files lying around do not change the build.
            let dirty = git(&root, &["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|s| !s.is_empty());
            let suffix = if dirty { ".dirty" } else { "" };
            format!("{version}+{hash}.{time}.{webui}{suffix}")
        }
        None => version,
    };
    println!("cargo:rustc-env=LANFORGE_BUILD={token}");

    // Packed relative relocations (DT_RELR): the PIE daemon's `.rela.dyn` shrinks from ~720 KiB
    // to ~10 KiB, ASLR kept. Needs glibc >= 2.36 at run time (an older loader refuses to start
    // the binary instead of misloading it) and binutils >= 2.38 or lld to link. Here and not in
    // `.cargo/config.toml`, where any `RUSTFLAGS` in the environment would silently drop it.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "linux" && target_env == "gnu" {
        println!("cargo:rustc-link-arg-bins=-Wl,-z,pack-relative-relocs");
    }
}
