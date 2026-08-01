use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let web_dir_rel = "../../../web";
    let build_dir_rel = "../../../web/build";
    let index_html_rel = "../../../web/build/index.html";

    // Rerun triggers for cargo incremental build tracking
    let watched_paths = [
        format!("{web_dir_rel}/src"),
        format!("{web_dir_rel}/static"),
        format!("{web_dir_rel}/package.json"),
        format!("{web_dir_rel}/pnpm-lock.yaml"),
        format!("{web_dir_rel}/svelte.config.js"),
        format!("{web_dir_rel}/vite.config.ts"),
    ];

    for path in &watched_paths {
        println!("cargo:rerun-if-changed={path}");
    }

    let web_dir = Path::new(web_dir_rel);
    let build_dir = Path::new(build_dir_rel);
    let index_html = Path::new(index_html_rel);

    if !web_dir.exists() {
        println!("cargo:warning=Web directory not found at {web_dir_rel}");
    }

    let is_cross_compile = env::var("TARGET").ok() != env::var("HOST").ok()
        || env::var("CROSS_RUNNER").is_ok()
        || env::var("LANFORGE_SKIP_WEB_BUILD")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

    #[cfg(feature = "auto-build")]
    {
        if web_dir.exists() {
            if is_cross_compile && index_html.exists() {
                println!(
                    "cargo:warning=Cross-compilation detected or web build skipped; using existing web/build assets."
                );
            } else {
                let mut build_success = false;

                // Try pnpm first
                if Command::new("pnpm")
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
                {
                    println!("cargo:warning=Building WebUI assets with pnpm...");
                    let status = Command::new("pnpm")
                        .args(["--prefix", web_dir_rel, "build"])
                        .status();

                    if matches!(status, Ok(s) if s.success()) {
                        println!("cargo:warning=WebUI built successfully with pnpm.");
                        build_success = true;
                    } else {
                        println!("cargo:warning=pnpm build failed or returned non-zero status.");
                    }
                }

                // Fallback to npm if pnpm was not found or failed
                if !build_success
                    && Command::new("npm")
                        .arg("--version")
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                {
                    println!("cargo:warning=Attempting WebUI build with npm...");
                    let status = Command::new("npm")
                        .args(["--prefix", web_dir_rel, "run", "build"])
                        .status();

                    if matches!(status, Ok(s) if s.success()) {
                        println!("cargo:warning=WebUI built successfully with npm.");
                        build_success = true;
                    } else {
                        println!("cargo:warning=npm build failed or returned non-zero status.");
                    }
                }

                if !build_success {
                    if index_html.exists() {
                        println!(
                            "cargo:warning=WebUI build command failed; falling back to existing web/build assets."
                        );
                    } else {
                        println!(
                            "cargo:warning=Could not build WebUI assets and web/build/index.html is missing."
                        );
                    }
                }
            }
        }
    }

    // Guarantee that web/build and index.html exist so RustEmbed macro can compile
    if !index_html.exists() {
        println!("cargo:warning=Creating placeholder index.html in web/build for RustEmbed...");
        if let Err(e) = fs::create_dir_all(build_dir) {
            println!("cargo:warning=Failed to create web/build directory: {e}");
        }
        let placeholder = "<!DOCTYPE html><html><head><title>Lanforge</title></head><body><h1>Lanforge WebUI</h1><p>WebUI static assets have not been built yet. Run <code>pnpm --prefix web build</code>.</p></body></html>";
        if let Err(e) = fs::write(index_html, placeholder) {
            println!("cargo:warning=Failed to write placeholder index.html: {e}");
        }
    }
}
