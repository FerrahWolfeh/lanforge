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

    #[cfg(feature = "auto-build")]
    {
        if web_dir.exists() {
            // Check if pnpm is installed
            let pnpm_check = Command::new("pnpm").arg("--version").output();

            match pnpm_check {
                Ok(output) if output.status.success() => {
                    println!("cargo:warning=Building WebUI assets with pnpm...");
                    let status = Command::new("pnpm")
                        .args(["--prefix", web_dir_rel, "build"])
                        .status();

                    match status {
                        Ok(s) if s.success() => {
                            println!("cargo:warning=WebUI built successfully.");
                        }
                        Ok(s) => {
                            println!("cargo:warning=pnpm build exited with status: {s}");
                        }
                        Err(e) => {
                            println!("cargo:warning=Failed to execute pnpm build: {e}");
                        }
                    }
                }
                _ => {
                    if index_html.exists() {
                        println!(
                            "cargo:warning=pnpm not found in PATH; using existing web/build static assets."
                        );
                    } else {
                        println!("cargo:warning=pnpm not found in PATH and web/build is missing.");
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
