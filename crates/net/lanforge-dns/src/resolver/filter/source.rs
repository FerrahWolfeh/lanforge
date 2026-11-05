use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION};
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use lanforge_types::network::dns::adblock::AdblockSourceFormat;
use lanforge_types::network::dns::adblock::syntax::RuleAction;

use crate::error::DnsError;
use crate::resolver::filter::engine::{build_fst_map, encode_val, reverse_domain_key};
use crate::resolver::filter::manifest::SourceManifestEntry;

const MAX_BODY_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

pub type AdblockHttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Builds an HTTP/HTTPS client configured for downloading adblock filter sources.
#[must_use]
pub fn build_adblock_http_client() -> AdblockHttpClient {
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build(https)
}

/// Formats an error and its entire underlying cause chain for diagnostics.
pub fn format_error_chain(err: &impl std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut cur = err.source();
    while let Some(cause) = cur {
        msg.push_str(&format!(": {cause}"));
        cur = cause.source();
    }
    msg
}

pub enum SourceFetchResult {
    NotModified,
    Fetched {
        body: Bytes,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Performs a conditional HTTP GET request using `ETag` and If-Modified-Since headers.
pub async fn fetch_source_conditional(
    client: &Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    mut url: String,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Result<SourceFetchResult, DnsError> {
    for _ in 0..5 {
        let uri: Uri = url
            .parse()
            .map_err(|e| DnsError::Generic(format!("Invalid URL: {e}")))?;

        let mut req_builder = Request::builder()
            .method(Method::GET)
            .uri(uri.clone())
            .header("User-Agent", "lanforge-dns");

        if let Some(tag) = etag {
            req_builder = req_builder.header(IF_NONE_MATCH, tag);
        }
        if let Some(lm) = last_modified {
            req_builder = req_builder.header(IF_MODIFIED_SINCE, lm);
        }

        let req = req_builder
            .body(Full::default())
            .map_err(|e| DnsError::Generic(e.to_string()))?;

        let resp = tokio::time::timeout(Duration::from_secs(120), client.request(req))
            .await
            .map_err(|_| DnsError::Generic("Request timed out (120s limit)".to_string()))?
            .map_err(|e| {
                DnsError::Generic(format!("HTTP request error: {}", format_error_chain(&e)))
            })?;

        let status = resp.status();

        if status == hyper::StatusCode::NOT_MODIFIED {
            return Ok(SourceFetchResult::NotModified);
        }

        if status.is_redirection() {
            if let Some(loc) = resp.headers().get(LOCATION) {
                let loc_str = loc
                    .to_str()
                    .map_err(|e| DnsError::Generic(format!("Invalid redirect location: {e}")))?;
                if loc_str.starts_with("http://") || loc_str.starts_with("https://") {
                    url = loc_str.to_string();
                } else if loc_str.starts_with('/') {
                    let authority = uri.authority().map_or("", |a| a.as_str());
                    let scheme = uri.scheme_str().unwrap_or("https");
                    url = format!("{scheme}://{authority}{loc_str}");
                } else {
                    url = loc_str.to_string();
                }
                continue;
            }
            return Err(DnsError::Generic(
                "Redirect without Location header".to_string(),
            ));
        }

        if !status.is_success() {
            return Err(DnsError::Generic(format!("HTTP status {status}")));
        }

        let new_etag = resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let new_last_modified = resp
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut body = resp.into_body();
        let mut body_bytes = Vec::new();

        while let Some(frame_res) = body.frame().await {
            let frame =
                frame_res.map_err(|e| DnsError::Generic(format!("Body frame error: {e}")))?;
            if let Ok(data) = frame.into_data() {
                if body_bytes.len() + data.len() > MAX_BODY_SIZE {
                    return Err(DnsError::Generic(format!(
                        "Response body exceeded limit of 64 MiB (read {} bytes)",
                        body_bytes.len() + data.len()
                    )));
                }
                body_bytes.extend_from_slice(&data);
            }
        }

        return Ok(SourceFetchResult::Fetched {
            body: Bytes::from(body_bytes),
            etag: new_etag,
            last_modified: new_last_modified,
        });
    }

    Err(DnsError::Generic("Too many redirects".to_string()))
}

/// Processes downloaded source text, writing per-source FST maps and badfilter lists.
#[allow(clippy::too_many_arguments)]
pub fn compile_source_artifacts(
    source_id: i64,
    source_idx: u16,
    url: &str,
    format: AdblockSourceFormat,
    content: &str,
    etag: Option<String>,
    last_modified: Option<String>,
    sources_dir: &Path,
) -> Result<SourceManifestEntry, DnsError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let parse_res = format.parse(content);

    let mut blocks = Vec::with_capacity(parse_res.stats.blocks as usize);
    let mut allows = Vec::with_capacity(parse_res.stats.exceptions as usize);
    let mut badfilters = HashSet::new();

    for rule in parse_res.rules {
        let Some(rev_key) = reverse_domain_key(&rule.domain) else {
            continue;
        };
        match rule.action {
            RuleAction::Block => {
                blocks.push((rev_key, encode_val(rule.flags, source_idx)));
            }
            RuleAction::Allow => {
                allows.push((rev_key, encode_val(rule.flags, source_idx)));
            }
            RuleAction::BadFilter => {
                badfilters.insert(rev_key);
            }
        }
    }

    if blocks.is_empty() && allows.is_empty() && badfilters.is_empty() {
        return Err(DnsError::Generic(format!(
            "Source '{url}' parsed into zero rules (empty content or incompatible syntax)"
        )));
    }

    // Build per-source block FST
    let block_fst_path = sources_dir.join(format!("{source_id}.block.fst"));
    build_fst_map(blocks, &block_fst_path)?;

    // Build per-source allow FST
    let allow_fst_path = sources_dir.join(format!("{source_id}.allow.fst"));
    build_fst_map(allows, &allow_fst_path)?;

    // Write badfilter file if any
    let bad_path = sources_dir.join(format!("{source_id}.bad"));
    if !badfilters.is_empty() {
        let mut f = BufWriter::new(File::create(&bad_path)?);
        for k in badfilters {
            writeln!(f, "{k}")?;
        }
        f.flush()?;
    } else if bad_path.exists() {
        let _ = std::fs::remove_file(&bad_path);
    }

    // Compute content hash of the block.fst
    let content_hash = match std::fs::read(&block_fst_path) {
        Ok(bytes) => {
            let mut h = 0xcbf29ce484222325u64;
            for &b in &bytes {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        }
        Err(_) => 0,
    };

    Ok(SourceManifestEntry {
        id: source_id,
        url: url.to_string(),
        format_configured: format,
        format_detected: parse_res.detected_format,
        etag,
        last_modified,
        last_attempt: now,
        last_success: now,
        consecutive_failures: 0,
        last_error: None,
        stats: parse_res.stats,
        unsupported_samples: parse_res.unsupported_samples,
        content_hash,
    })
}

#[cfg(test)]
mod tests {
    use lanforge_types::network::dns::adblock::AdblockUrlKind;

    use super::*;
    use crate::resolver::filter::{DiskBlocklist, ListMatches};

    fn compile(dir: &Path, id: i64, format: AdblockSourceFormat, text: &str) {
        compile_source_artifacts(id, 0, "http://test", format, text, None, None, dir).unwrap();
    }

    /// Each list answers from its own FSTs, one bit per list in load order.
    #[test]
    fn lists_are_queried_in_place_one_bit_each() {
        let dir = tempfile::tempdir().unwrap();
        compile(
            dir.path(),
            1,
            AdblockSourceFormat::Adblock,
            "||ads.example.com^\n||tracking.com^\n@@||good.tracking.com^\n",
        );
        compile(
            dir.path(),
            2,
            AdblockSourceFormat::Hosts,
            "0.0.0.0 ads.example.com\n0.0.0.0 extra.com\n",
        );
        let kinds = [
            (1, AdblockUrlKind::Blocklist),
            (2, AdblockUrlKind::Blocklist),
        ];
        let (bl, failed) = DiskBlocklist::load(dir.path(), &kinds);
        assert!(failed.is_empty());
        let m = |d: &str| bl.match_lists(d);
        assert_eq!(m("ads.example.com").block, 0b11);
        assert_eq!(m("x.ads.example.com").block, 0b01, "hosts lines are exact");
        assert_eq!(m("good.tracking.com").allow, 0b01);
        assert_eq!(m("good.tracking.com").block, 0b01);
        assert_eq!(m("extra.com").block, 0b10);
        assert_eq!(m("unlisted.com"), ListMatches::default());
        assert_eq!((bl.source_id(0), bl.source_id(1)), (1, 2));
        assert_eq!((bl.len(), bl.exceptions_len()), (4, 1));
    }

    /// Failed on the merged engine: the source kind was never read, so an allowlist URL blocked
    /// every domain it was meant to allow.
    #[test]
    fn an_allowlist_source_allows() {
        let dir = tempfile::tempdir().unwrap();
        compile(
            dir.path(),
            1,
            AdblockSourceFormat::Hosts,
            "0.0.0.0 bank.com\n",
        );
        compile(dir.path(), 2, AdblockSourceFormat::Domains, "bank.com\n");
        let kinds = [
            (1, AdblockUrlKind::Blocklist),
            (2, AdblockUrlKind::Allowlist),
        ];
        let (bl, _) = DiskBlocklist::load(dir.path(), &kinds);
        let m = bl.match_lists("bank.com");
        assert_eq!((m.block, m.allow), (0b01, 0b10));
        assert_eq!((bl.len(), bl.exceptions_len()), (1, 1));
    }

    /// A `$badfilter` in one list disables the same rule in every list; other levels still match.
    #[test]
    fn a_badfilter_disables_the_rule_in_other_lists() {
        let dir = tempfile::tempdir().unwrap();
        compile(
            dir.path(),
            1,
            AdblockSourceFormat::Adblock,
            "||ads.com^\n||x.ads.com^\n",
        );
        compile(
            dir.path(),
            2,
            AdblockSourceFormat::Adblock,
            "||x.ads.com^$badfilter\n||other.com^\n",
        );
        let kinds = [
            (1, AdblockUrlKind::Blocklist),
            (2, AdblockUrlKind::Blocklist),
        ];
        let (bl, _) = DiskBlocklist::load(dir.path(), &kinds);
        assert_eq!(
            bl.match_lists("x.ads.com").block,
            0b01,
            "still matched by ||ads.com^"
        );
        assert_eq!(bl.match_lists("ads.com").block, 0b01);
        let (only, _) = DiskBlocklist::load(dir.path(), &kinds[1..]);
        assert_eq!(only.match_lists("other.com").block, 0b01);
    }

    #[test]
    fn an_unreadable_list_is_skipped_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        compile(dir.path(), 1, AdblockSourceFormat::Hosts, "0.0.0.0 a.com\n");
        std::fs::write(dir.path().join("2.block.fst"), b"garbage").unwrap();
        let kinds = [
            (2, AdblockUrlKind::Blocklist),
            (1, AdblockUrlKind::Blocklist),
        ];
        let (bl, failed) = DiskBlocklist::load(dir.path(), &kinds);
        assert_eq!(failed, vec![2]);
        assert_eq!(bl.match_lists("a.com").block, 0b01);
        assert_eq!(bl.source_id(0), 1);
    }

    #[tokio::test]
    async fn test_adblock_http_client_scheme_support() {
        let client = build_adblock_http_client();
        // Request an HTTPS URI on loopback: even if connection is refused, it must NOT fail
        // with "invalid URL, scheme is not http".
        let uri: Uri = "https://127.0.0.1:1/hosts".parse().unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::<Bytes>::default())
            .unwrap();

        let res = client.request(req).await;
        assert!(res.is_err());
        let err_chain = format_error_chain(&res.unwrap_err());
        assert!(
            !err_chain.contains("scheme is not http"),
            "Client should not enforce http scheme on https requests: {err_chain}"
        );
    }
}
