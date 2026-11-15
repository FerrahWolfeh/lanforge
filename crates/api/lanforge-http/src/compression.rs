//! gzip for the API's JSON answers (RFC 9110 §8.4): the lists and logs the web UI polls are
//! 5–13× smaller compressed. Streamed bodies (SSE) and answers under [`MIN_GZIP_BYTES`] go out as
//! they are.

use std::io::Write;

use axum::{
    body::{Body, HttpBody},
    extract::Request,
    http::{
        HeaderValue,
        header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, VARY},
    },
    middleware::Next,
    response::Response,
};
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt;

/// Below this the gzip header and the CPU cost outweigh the bytes saved.
const MIN_GZIP_BYTES: u64 = 1024;

/// Middleware: compresses a complete (`Content-Length`-sized) JSON body of [`MIN_GZIP_BYTES`] or
/// more for a client whose `Accept-Encoding` takes gzip. Every JSON answer carries
/// `Vary: Accept-Encoding`, since its representation depends on that header.
pub async fn gzip_json(req: Request, next: Next) -> Response {
    let wants_gzip = req
        .headers()
        .get(ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(accepts_gzip);
    let mut resp = next.run(req).await;
    let is_json = resp
        .headers()
        .get(CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/json"));
    if !is_json || resp.headers().contains_key(CONTENT_ENCODING) {
        return resp;
    }
    resp.headers_mut()
        .append(VARY, HeaderValue::from_static("accept-encoding"));
    let size = resp.body().size_hint().exact();
    if !wants_gzip || size.is_none_or(|n| n < MIN_GZIP_BYTES) {
        return resp;
    }

    let (mut parts, body) = resp.into_parts();
    // A body with an exact size is already in memory (`Json`, `String`): collecting cannot wait.
    let Ok(collected) = body.collect().await else {
        return Response::from_parts(parts, Body::empty());
    };
    let plain = collected.to_bytes();
    let mut encoder = GzEncoder::new(Vec::with_capacity(plain.len() / 4), Compression::default());
    let Ok(gzipped) = encoder.write_all(&plain).and_then(|()| encoder.finish()) else {
        return Response::from_parts(parts, Body::from(plain));
    };
    parts
        .headers
        .insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(gzipped))
}

/// Whether an `Accept-Encoding` value takes gzip (RFC 9110 §12.5.3): `gzip` (or `x-gzip`)
/// listed with a non-zero weight, or `*` with one while gzip is not listed. No header at all
/// gets the plain body: such clients (`curl` without `--compressed`) rarely decode.
pub fn accepts_gzip(value: &str) -> bool {
    let mut star = false;
    for item in value.split(',') {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or_default().trim();
        let refused = parts.any(|param| {
            let param = param.trim();
            param.get(..2).is_some_and(|k| k.eq_ignore_ascii_case("q="))
                && param[2..].trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
        });
        if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
            return !refused;
        }
        if coding == "*" {
            star = !refused;
        }
    }
    star
}
