#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../../web/build"]
pub struct WebUiAssets;

impl WebUiAssets {
    /// Retrieve embedded file content and guessed MIME type for a given path.
    /// Falls back to `index.html` if the exact file path is not found (SPA routing fallback).
    #[must_use]
    pub fn get_file_or_fallback(path: &str) -> Option<(mime_guess::Mime, rust_embed::EmbeddedFile)> {
        let clean_path = path.trim_start_matches('/');
        let target_path = if clean_path.is_empty() { "index.html" } else { clean_path };

        Self::get(target_path)
            .map(|content| (mime_guess::from_path(target_path).first_or_octet_stream(), content))
            .or_else(|| {
                Self::get("index.html").map(|fallback_content| {
                    (
                        mime_guess::from_path("index.html").first_or_octet_stream(),
                        fallback_content,
                    )
                })
            })
    }
}
