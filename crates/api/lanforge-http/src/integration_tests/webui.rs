//! The embedded WebUI as the daemon serves it: files stored gzip-compressed, sent as stored to
//! a client that takes gzip (RFC 9110 §12.5.3) and decompressed for one that does not, each form
//! with its own `ETag`; already-compressed files (woff2) go out as they are.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use flate2::read::GzDecoder;
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::contract::make_state;
use crate::config::HttpConfig;
use crate::server::HttpService;

async fn router() -> Router {
    HttpService::build_router(make_state(false).await, &HttpConfig::default())
}

async fn get(
    router: &Router,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::get(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let (parts, body) = resp.into_parts();
    let body = body.collect().await.expect("body").to_bytes().to_vec();
    (parts.status, parts.headers, body)
}

fn build_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../web/build")
}

/// The first file under `web/build/_app/immutable` with extension `ext`, as a URL path.
fn some_file(ext: &str) -> Option<String> {
    fn walk(dir: &Path, ext: &str) -> Option<PathBuf> {
        for entry in fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = walk(&path, ext) {
                    return Some(found);
                }
            } else if path.extension().is_some_and(|e| e == ext) {
                return Some(path);
            }
        }
        None
    }
    let root = build_dir();
    let found = walk(&root.join("_app/immutable"), ext)?;
    Some(format!("/{}", found.strip_prefix(&root).ok()?.to_str()?))
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    GzDecoder::new(data)
        .read_to_end(&mut out)
        .expect("gzip body");
    out
}

fn header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn gzip_client_gets_the_stored_gzip_and_others_the_plain_file() {
    let router = router().await;
    let raw = fs::read(build_dir().join("index.html")).expect("index.html");

    let (status, headers, body) =
        get(&router, "/", &[("accept-encoding", "gzip, deflate, br")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, header::CONTENT_ENCODING), Some("gzip"));
    assert_eq!(header(&headers, header::VARY), Some("Accept-Encoding"));
    assert_eq!(
        header(&headers, header::CONTENT_TYPE),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(gunzip(&body), raw);
    let gzip_etag = header(&headers, header::ETAG).expect("etag").to_string();

    for accept in [
        None,
        Some("identity"),
        Some("gzip;q=0, deflate"),
        Some("br"),
    ] {
        let hdrs: Vec<_> = accept.map(|a| ("accept-encoding", a)).into_iter().collect();
        let (status, headers, body) = get(&router, "/", &hdrs).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header(&headers, header::CONTENT_ENCODING),
            None,
            "{accept:?}"
        );
        assert_eq!(header(&headers, header::VARY), Some("Accept-Encoding"));
        assert_eq!(body, raw, "{accept:?}");
        assert_ne!(
            header(&headers, header::ETAG),
            Some(gzip_etag.as_str()),
            "{accept:?}"
        );
    }

    let (_, headers, _) = get(&router, "/", &[("accept-encoding", "*")]).await;
    assert_eq!(
        header(&headers, header::CONTENT_ENCODING),
        Some("gzip"),
        "* takes gzip"
    );
}

#[tokio::test]
async fn etag_revalidates_only_the_same_representation() {
    let router = router().await;
    let Some(path) = some_file("js") else {
        return; // placeholder build without the real WebUI
    };
    let gz = [("accept-encoding", "gzip")];
    let (_, headers, _) = get(&router, &path, &gz).await;
    let etag = header(&headers, header::ETAG).expect("etag").to_string();
    assert_eq!(
        header(&headers, header::CACHE_CONTROL),
        Some("public, max-age=31536000, immutable")
    );

    let (status, headers, body) = get(&router, &path, &[gz[0], ("if-none-match", &etag)]).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(header(&headers, header::ETAG), Some(etag.as_str()));
    assert!(body.is_empty());

    // The gzip form's validator does not match the plain form.
    let (status, _, body) = get(&router, &path, &[("if-none-match", &etag)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, fs::read(build_dir().join(&path[1..])).expect("file"));
}

#[tokio::test]
async fn compressed_formats_go_out_as_they_are() {
    let router = router().await;
    let Some(path) = some_file("woff2") else {
        return;
    };
    let (status, headers, body) = get(&router, &path, &[("accept-encoding", "gzip")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, header::CONTENT_ENCODING), None);
    assert_eq!(header(&headers, header::CONTENT_TYPE), Some("font/woff2"));
    assert_eq!(body, fs::read(build_dir().join(&path[1..])).expect("file"));
}

#[tokio::test]
async fn client_side_routes_get_index_html() {
    let router = router().await;
    let (status, headers, body) = get(&router, "/network/dhcp", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, header::CONTENT_TYPE),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        body,
        fs::read(build_dir().join("index.html")).expect("index.html")
    );
}
