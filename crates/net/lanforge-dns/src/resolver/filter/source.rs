use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use fst::map::OpBuilder;
use fst::{Map, MapBuilder, Streamer};
use http_body_util::{BodyExt, Full};
use hyper::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION};
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use memmap2::Mmap;

use lanforge_types::network::dns::adblock::AdblockSourceFormat;

use crate::error::DnsError;
use crate::resolver::filter::engine::{
    decode_val, encode_val, reverse_domain_key, LABEL_SEPARATOR,
};
use crate::resolver::filter::manifest::SourceManifestEntry;
use crate::resolver::filter::parse::{parse_source, MatchFlags, RuleAction};

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


/// Performs a conditional HTTP GET request using ETag and If-Modified-Since headers.
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
            .map_err(|e| DnsError::Generic(format!("HTTP request error: {}", format_error_chain(&e))))?;


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
            return Err(DnsError::Generic("Redirect without Location header".to_string()));
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
            let frame = frame_res.map_err(|e| DnsError::Generic(format!("Body frame error: {e}")))?;
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

    let parse_res = parse_source(content, format);

    let mut blocks = Vec::new();
    let mut allows = Vec::new();
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
    build_sorted_fst_map(blocks, &block_fst_path)?;

    // Build per-source allow FST
    let allow_fst_path = sources_dir.join(format!("{source_id}.allow.fst"));
    build_sorted_fst_map(allows, &allow_fst_path)?;

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

/// Builds an FST Map from a vector of (reversed_key, encoded_val) ensuring unique sorted order.
fn build_sorted_fst_map(mut entries: Vec<(String, u64)>, target_path: &Path) -> Result<(), DnsError> {
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp_file = tempfile::Builder::new()
        .prefix("src-fst-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| DnsError::Generic(format!("Failed to create source FST tempfile: {e}")))?;

    let mut writer = BufWriter::new(tmp_file);
    let mut builder = MapBuilder::new(&mut writer)
        .map_err(|e| DnsError::Generic(format!("MapBuilder creation failed: {e}")))?;

    let mut last_key: Option<String> = None;
    let mut last_val: u64 = 0;

    for (key, val) in entries {
        if let Some(prev) = &last_key {
            if prev == &key {
                let (prev_flags, prev_src) = decode_val(last_val);
                let (cur_flags, _) = decode_val(val);
                let combined = MatchFlags(prev_flags.0 | cur_flags.0);
                last_val = encode_val(combined, prev_src);
                continue;
            } else {
                builder
                    .insert(prev.as_bytes(), last_val)
                    .map_err(|e| DnsError::Generic(format!("FST insertion error: {e}")))?;
            }
        }
        last_key = Some(key);
        last_val = val;
    }

    if let Some(prev) = last_key {
        builder
            .insert(prev.as_bytes(), last_val)
            .map_err(|e| DnsError::Generic(format!("FST insertion error: {e}")))?;
    }

    builder
        .finish()
        .map_err(|e| DnsError::Generic(format!("MapBuilder finish failed: {e}")))?;

    std::io::Write::flush(&mut writer)
        .map_err(|e| DnsError::Generic(format!("MapBuilder flush failed: {e}")))?;

    let tmp_file = writer
        .into_inner()
        .map_err(|e| DnsError::Generic(format!("Buffer unwrap failed: {e}")))?;

    tmp_file
        .persist(target_path)
        .map_err(|e| DnsError::Generic(format!("Atomic persist failed: {e}")))?;

    Ok(())
}

/// Merges all source block and allow FSTs into the final `block.fst` and `allow.fst`.
/// Applies $badfilter removals, union of flags, and single-pass descendant pruning.
pub fn merge_all_sources(
    sources_dir: &Path,
    active_source_ids: &[i64],
    target_block_path: &Path,
    target_allow_path: &Path,
) -> Result<(usize, usize, usize), DnsError> {
    // 1. Collect all badfilters across all sources
    let mut global_badfilter = HashSet::new();
    for id in active_source_ids {
        let bad_path = sources_dir.join(format!("{id}.bad"));
        if bad_path.exists()
            && let Ok(file) = File::open(&bad_path)
        {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    global_badfilter.insert(trimmed.to_string());
                }
            }
        }
    }

    // 2. Open all source block FSTs
    let mut block_maps = Vec::new();
    for id in active_source_ids {
        let p = sources_dir.join(format!("{id}.block.fst"));
        if p.exists()
            && let Ok(file) = File::open(&p)
            && let Ok(mmap) = unsafe { Mmap::map(&file) }
            && let Ok(map) = Map::new(mmap)
        {
            block_maps.push(map);
        }
    }

    // 3. Open all source allow FSTs
    let mut allow_maps = Vec::new();
    for id in active_source_ids {
        let p = sources_dir.join(format!("{id}.allow.fst"));
        if p.exists()
            && let Ok(file) = File::open(&p)
            && let Ok(mmap) = unsafe { Mmap::map(&file) }
            && let Ok(map) = Map::new(mmap)
        {
            allow_maps.push(map);
        }
    }

    // 4. Merge block maps via OpBuilder::union
    let (merged_blocks, pruned_count) = merge_fst_stream(
        &block_maps,
        &global_badfilter,
        target_block_path,
        true, // apply wildcard pruning on blocks
    )?;

    // 5. Merge allow maps via OpBuilder::union
    let (merged_allows, _) = merge_fst_stream(
        &allow_maps,
        &global_badfilter,
        target_allow_path,
        false, // don't prune allow rules
    )?;

    Ok((merged_blocks, merged_allows, pruned_count))
}

fn merge_fst_stream(
    maps: &[Map<Mmap>],
    badfilters: &HashSet<String>,
    target_path: &Path,
    prune_wildcards: bool,
) -> Result<(usize, usize), DnsError> {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp_file = tempfile::Builder::new()
        .prefix("merged-fst-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| DnsError::Generic(format!("Failed to create merge tempfile: {e}")))?;

    let mut writer = BufWriter::new(tmp_file);
    let mut builder = MapBuilder::new(&mut writer)
        .map_err(|e| DnsError::Generic(format!("MapBuilder creation failed: {e}")))?;

    if maps.is_empty() {
        builder
            .finish()
            .map_err(|e| DnsError::Generic(format!("MapBuilder finish failed: {e}")))?;
        let tmp_file = writer.into_inner().map_err(|e| DnsError::Generic(e.to_string()))?;
        tmp_file.persist(target_path).map_err(|e| DnsError::Generic(e.to_string()))?;
        return Ok((0, 0));
    }

    let mut op = OpBuilder::new();
    for map in maps {
        op.push(map.stream());
    }

    let mut stream = op.union();

    let mut total_inserted = 0;
    let mut pruned_count = 0;
    let mut current_wildcard_prefix: Option<(Vec<u8>, bool)> = None;

    while let Some((key_bytes, items)) = stream.next() {
        // 1. Check if badfilter applies
        if !badfilters.is_empty()
            && let Ok(k_str) = std::str::from_utf8(key_bytes)
            && badfilters.contains(k_str)
        {
            continue;
        }

        let mut combined_flags = MatchFlags::empty();
        let mut first_src_idx = 0u16;
        let mut first = true;
        for iv in items {
            let (flags, _) = decode_val(iv.value);
            combined_flags = MatchFlags(combined_flags.0 | flags.0);
            if first || flags.is_important() {
                first_src_idx = (iv.index as u16).min(u16::MAX - 1);
                first = false;
            }
        }
        let val = encode_val(combined_flags, first_src_idx);
        let flags = combined_flags;

        // 2. Wildcard pruning
        if prune_wildcards {
            if let Some((prefix, ancestor_important)) = &current_wildcard_prefix {
                if key_bytes.starts_with(prefix) {
                    if *ancestor_important || !flags.is_important() {
                        pruned_count += 1;
                        continue;
                    }
                } else {
                    current_wildcard_prefix = None;
                }
            }

            if flags.is_subdomains() {
                let mut prefix = key_bytes.to_vec();
                prefix.push(LABEL_SEPARATOR);
                current_wildcard_prefix = Some((prefix, flags.is_important()));
            }
        }

        builder
            .insert(key_bytes, val)
            .map_err(|e| DnsError::Generic(format!("FST stream insertion error: {e}")))?;
        total_inserted += 1;
    }

    builder
        .finish()
        .map_err(|e| DnsError::Generic(format!("MapBuilder finish failed: {e}")))?;

    std::io::Write::flush(&mut writer)
        .map_err(|e| DnsError::Generic(format!("MapBuilder flush failed: {e}")))?;

    let tmp_file = writer
        .into_inner()
        .map_err(|e| DnsError::Generic(format!("Buffer unwrap failed: {e}")))?;

    tmp_file
        .persist(target_path)
        .map_err(|e| DnsError::Generic(format!("Atomic persist failed: {e}")))?;

    Ok((total_inserted, pruned_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_and_merge_sources() {
        let dir = tempfile::tempdir().unwrap();
        let sources_dir = dir.path().join("sources");
        std::fs::create_dir_all(&sources_dir).unwrap();

        let s1 = r#"
||ads.example.com^
||tracking.com^
@@||good.tracking.com^
"#;
        let s2 = r#"
0.0.0.0 ads.example.com
0.0.0.0 extra.com
||bad.tracking.com^$badfilter
"#;

        let entry1 = compile_source_artifacts(
            1,
            1,
            "http://s1.test",
            AdblockSourceFormat::Adblock,
            s1,
            None,
            None,
            &sources_dir,
        )
        .unwrap();

        let entry2 = compile_source_artifacts(
            2,
            2,
            "http://s2.test",
            AdblockSourceFormat::Hosts,
            s2,
            None,
            None,
            &sources_dir,
        )
        .unwrap();

        assert_eq!(entry1.stats.blocks, 2);
        assert_eq!(entry1.stats.exceptions, 1);
        assert_eq!(entry2.stats.blocks, 2);

        let merged_block_path = dir.path().join("block.fst");
        let merged_allow_path = dir.path().join("allow.fst");

        let (blocks, allows, _pruned) = merge_all_sources(
            &sources_dir,
            &[1, 2],
            &merged_block_path,
            &merged_allow_path,
        )
        .unwrap();

        assert_eq!(blocks, 3); // ads.example.com, tracking.com, extra.com
        assert_eq!(allows, 1); // good.tracking.com

        let block_map = Map::new(unsafe { Mmap::map(&File::open(&merged_block_path).unwrap()).unwrap() }).unwrap();
        let allow_map = Map::new(unsafe { Mmap::map(&File::open(&merged_allow_path).unwrap()).unwrap() }).unwrap();

        assert_eq!(block_map.len(), 3);
        assert_eq!(allow_map.len(), 1);
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
