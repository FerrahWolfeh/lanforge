//! Build script shared by the daemon and the CLI (`build = "../build_id.rs"`): sets
//! `LANFORGE_BUILD` to the build token read by `lanforge_types::build::BuildInfo`,
//! `<version>+<commit>.<commit time>[.dirty]`, or just the version without git.

use std::env;
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
    for path in ["crates", "web/src", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }

    let token = match git(&root, &["log", "-1", "--format=%h %ct", "--abbrev=12"]) {
        Some(line) => match line.split_once(' ') {
            Some((hash, time)) => {
                // Tracked files only: scratch files lying around do not change the build.
                let dirty = git(&root, &["status", "--porcelain", "--untracked-files=no"])
                    .is_some_and(|s| !s.is_empty());
                let suffix = if dirty { ".dirty" } else { "" };
                format!("{version}+{hash}.{time}{suffix}")
            }
            None => version,
        },
        None => version,
    };
    println!("cargo:rustc-env=LANFORGE_BUILD={token}");
}
