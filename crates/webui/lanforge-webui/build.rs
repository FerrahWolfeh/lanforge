use std::env;
use std::fmt::Write as _;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use flate2::Compression;
use flate2::write::GzEncoder;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let manifest_path = Path::new(&manifest_dir);
    let web_dir = manifest_path.join("../../../web");
    let build_dir = web_dir.join("build");
    let index_html = build_dir.join("index.html");

    // Track environment variables
    println!("cargo:rerun-if-env-changed=LANFORGE_SKIP_WEB_BUILD");
    println!("cargo:rerun-if-env-changed=LANFORGE_FORCE_WEB_BUILD");

    // Track web files for incremental builds
    let watch_targets = [
        "src",
        "static",
        "package.json",
        "pnpm-lock.yaml",
        "svelte.config.js",
        "vite.config.ts",
        "tsconfig.json",
        "components.json",
    ];

    for target in &watch_targets {
        let p = web_dir.join(target);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }

    if !web_dir.exists() {
        println!(
            "cargo:warning=Web directory not found at {}",
            web_dir.display()
        );
    }

    let is_cross = is_cross_compiling();
    let skip_build = env::var("LANFORGE_SKIP_WEB_BUILD")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_build = env::var("LANFORGE_FORCE_WEB_BUILD")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if is_cross || skip_build {
        if index_html.exists() {
            println!(
                "cargo:warning=Using pre-built WebUI assets from web/build (cross-compilation or web build skipped)."
            );
        } else {
            println!(
                "cargo:warning=WebUI assets missing at {} during cross-compilation! Creating placeholder index.html. Run 'pnpm --prefix web build' on your host to embed the real WebUI.",
                index_html.display()
            );
            create_placeholder(&build_dir, &index_html);
        }
        pack_assets(&build_dir);
        return;
    }

    #[cfg(feature = "auto-build")]
    {
        if web_dir.exists() {
            let is_outdated = force_build || is_webui_outdated(&web_dir, &index_html);

            if is_outdated {
                let build_succeeded = run_frontend_build(&web_dir);
                if !build_succeeded && !index_html.exists() {
                    println!(
                        "cargo:warning=Could not build WebUI and {} is missing. Creating placeholder.",
                        index_html.display()
                    );
                    create_placeholder(&build_dir, &index_html);
                }
            }
        }
    }

    // Guarantee that web/build and index.html exist so there is something to embed.
    if !index_html.exists() {
        create_placeholder(&build_dir, &index_html);
    }
    pack_assets(&build_dir);
}

/// Packs `web/build` into `OUT_DIR`: every file gzip-compressed at the best level (kept as is
/// when that does not shrink it, e.g. woff2), plus `assets.rs`, the sorted table `lib.rs`
/// includes. Compressing here instead of per request keeps a compressor out of the daemon.
fn pack_assets(build_dir: &Path) {
    println!("cargo:rerun-if-changed={}", build_dir.display());
    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR for build scripts"));
    let mut files = Vec::new();
    collect_files(build_dir, build_dir, &mut files);
    files.sort();

    let mut table = String::from("&[\n");
    for (i, rel) in files.iter().enumerate() {
        let src = build_dir.join(rel);
        let raw = fs::read(&src).unwrap_or_else(|e| panic!("read {}: {e}", src.display()));
        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&raw).expect("gzip into a Vec cannot fail");
        let gz = enc.finish().expect("gzip into a Vec cannot fail");
        let gzip = gz.len() < raw.len();
        let blob = out.join(format!("asset{i}"));
        fs::write(&blob, if gzip { &gz } else { &raw })
            .unwrap_or_else(|e| panic!("write {}: {e}", blob.display()));

        // Changes whenever the content does; stable for one toolchain (fixed SipHash keys).
        let mut hasher = DefaultHasher::new();
        raw.hash(&mut hasher);
        let etag = format!("\"{:016x}\"", hasher.finish());
        writeln!(
            table,
            "    Asset {{ path: {rel:?}, mime: {:?}, etag: {etag:?}, gzip: {gzip}, data: include_bytes!({:?}) }},",
            mime(rel),
            blob.to_string_lossy(),
        )
        .expect("write to a String cannot fail");
    }
    table.push(']');
    fs::write(out.join("assets.rs"), table).expect("write assets.rs");
}

/// Every file under `dir`, as a `/`-separated path relative to `root`.
fn collect_files(root: &Path, dir: &Path, files: &mut Vec<String>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else {
            let rel = path.strip_prefix(root).expect("walked from root");
            let parts: Vec<_> = rel.iter().map(|p| p.to_string_lossy()).collect();
            files.push(parts.join("/"));
        }
    }
}

/// The `Content-Type` of a web UI file, by extension.
fn mime(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript",
        Some("css") => "text/css",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        _ => "application/octet-stream",
    }
}

fn is_cross_compiling() -> bool {
    let target = env::var("TARGET").ok();
    let host = env::var("HOST").ok();

    if target.is_some() && host.is_some() && target != host {
        return true;
    }

    if env::var("CROSS_RUNNER").is_ok()
        || env::var("CROSS_TARGET").is_ok()
        || Path::new("/cross").exists()
    {
        return true;
    }

    false
}

fn get_latest_mtime_in_dir(dir: &Path) -> Option<SystemTime> {
    if !dir.is_dir() {
        return None;
    }
    let mut latest: Option<SystemTime> = None;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if name.starts_with('.') || name == "node_modules" || name == "build" {
                continue;
            }
            if path.is_dir() {
                if let Some(sub_latest) = get_latest_mtime_in_dir(&path) {
                    latest = Some(latest.map_or(sub_latest, |l| l.max(sub_latest)));
                }
            } else if let Ok(meta) = entry.metadata()
                && let Ok(mtime) = meta.modified()
            {
                latest = Some(latest.map_or(mtime, |l| l.max(mtime)));
            }
        }
    }
    latest
}

fn is_webui_outdated(web_dir: &Path, index_html: &Path) -> bool {
    if !index_html.exists() || !web_dir.join("build/_app").exists() {
        return true;
    }

    let index_mtime = match fs::metadata(index_html).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return true,
    };

    let config_files = [
        "package.json",
        "pnpm-lock.yaml",
        "svelte.config.js",
        "vite.config.ts",
        "tsconfig.json",
        "components.json",
    ];

    for file in &config_files {
        let p = web_dir.join(file);
        if let Ok(meta) = fs::metadata(&p)
            && let Ok(mtime) = meta.modified()
            && mtime > index_mtime
        {
            return true;
        }
    }

    let src_dirs = ["src", "static"];
    for dir in &src_dirs {
        let p = web_dir.join(dir);
        if let Some(latest) = get_latest_mtime_in_dir(&p)
            && latest > index_mtime
        {
            return true;
        }
    }

    false
}

fn run_frontend_build(web_dir: &Path) -> bool {
    // Try pnpm first
    if Command::new("pnpm")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        println!("cargo:warning=Building WebUI assets with pnpm...");
        let status = Command::new("pnpm")
            .args(["--prefix", &web_dir.to_string_lossy(), "build"])
            .status();

        if matches!(status, Ok(s) if s.success()) {
            println!("cargo:warning=WebUI built successfully with pnpm.");
            return true;
        }
        println!("cargo:warning=pnpm build failed or returned non-zero status.");
    }

    // Fallback to npm if pnpm was not found or failed
    if Command::new("npm")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        println!("cargo:warning=Attempting WebUI build with npm...");
        let status = Command::new("npm")
            .args(["--prefix", &web_dir.to_string_lossy(), "run", "build"])
            .status();

        if matches!(status, Ok(s) if s.success()) {
            println!("cargo:warning=WebUI built successfully with npm.");
            return true;
        }
        println!("cargo:warning=npm build failed or returned non-zero status.");
    }

    false
}

fn create_placeholder(build_dir: &Path, index_html: &Path) {
    if !index_html.exists() {
        println!("cargo:warning=Creating placeholder index.html in web/build...");
        if let Err(e) = fs::create_dir_all(build_dir) {
            println!("cargo:warning=Failed to create web/build directory: {e}");
        }
        let placeholder = "<!DOCTYPE html><html><head><title>Lanforge</title></head><body><h1>Lanforge WebUI</h1><p>WebUI static assets have not been built yet. Run <code>pnpm --prefix web build</code> on your host.</p></body></html>";
        if let Err(e) = fs::write(index_html, placeholder) {
            println!("cargo:warning=Failed to write placeholder index.html: {e}");
        }
    }
}
