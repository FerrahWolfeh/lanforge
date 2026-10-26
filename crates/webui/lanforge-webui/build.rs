use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

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

    // Guarantee that web/build and index.html exist so RustEmbed macro can compile
    if !index_html.exists() {
        create_placeholder(&build_dir, &index_html);
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
        println!("cargo:warning=Creating placeholder index.html in web/build for RustEmbed...");
        if let Err(e) = fs::create_dir_all(build_dir) {
            println!("cargo:warning=Failed to create web/build directory: {e}");
        }
        let placeholder = "<!DOCTYPE html><html><head><title>Lanforge</title></head><body><h1>Lanforge WebUI</h1><p>WebUI static assets have not been built yet. Run <code>pnpm --prefix web build</code> on your host.</p></body></html>";
        if let Err(e) = fs::write(index_html, placeholder) {
            println!("cargo:warning=Failed to write placeholder index.html: {e}");
        }
    }
}
