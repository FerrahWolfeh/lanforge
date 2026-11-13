#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::borrow::Cow;
use std::io::Read;

use flate2::read::GzDecoder;

/// One file of the web UI build, embedded by `build.rs`.
#[derive(Debug)]
pub struct Asset {
    /// Path relative to `web/build`, `/`-separated (`_app/immutable/...`).
    pub path: &'static str,
    pub mime: &'static str,
    /// Strong validator of the file's content, quotes included.
    pub etag: &'static str,
    /// Whether `data` is gzip-compressed; files that do not shrink (woff2) are stored as is.
    pub gzip: bool,
    pub data: &'static [u8],
}

/// Sorted by `path`.
static ASSETS: &[Asset] = include!(concat!(env!("OUT_DIR"), "/assets.rs"));

impl Asset {
    /// The file at `path` (a leading `/` is ignored), or `index.html` for a path that names
    /// none (SPA routing).
    #[must_use]
    pub fn get_or_index(path: &str) -> Option<&'static Self> {
        let path = path.trim_start_matches('/');
        let path = if path.is_empty() { "index.html" } else { path };
        Self::get(path).or_else(|| Self::get("index.html"))
    }

    fn get(path: &str) -> Option<&'static Self> {
        ASSETS
            .binary_search_by(|a| a.path.cmp(path))
            .ok()
            .map(|i| &ASSETS[i])
    }

    /// The file's original bytes, for a client that does not take gzip: decompressed (an
    /// allocation, on this rare path only) when stored compressed.
    #[must_use]
    pub fn identity(&self) -> Cow<'static, [u8]> {
        if !self.gzip {
            return Cow::Borrowed(self.data);
        }
        let mut out = Vec::with_capacity(self.data.len() * 4);
        GzDecoder::new(self.data)
            .read_to_end(&mut out)
            .expect("build.rs wrote a valid gzip stream");
        Cow::Owned(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{ASSETS, Asset};
    use std::fs;
    use std::path::Path;

    #[test]
    fn every_file_of_the_build_comes_back_byte_for_byte() {
        let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../web/build");
        assert!(!ASSETS.is_empty());
        for asset in ASSETS {
            let raw = fs::read(build.join(asset.path)).expect("embedded file exists");
            assert_eq!(asset.identity().as_ref(), raw.as_slice(), "{}", asset.path);
        }
    }

    #[test]
    fn table_is_sorted_for_binary_search() {
        assert!(ASSETS.windows(2).all(|w| w[0].path < w[1].path));
    }

    #[test]
    fn unknown_paths_fall_back_to_index() {
        let index = Asset::get_or_index("/").expect("index.html");
        assert_eq!(index.path, "index.html");
        assert_eq!(index.mime, "text/html; charset=utf-8");
        let spa = Asset::get_or_index("/network/dhcp").expect("fallback");
        assert_eq!(spa.path, "index.html");
    }
}
