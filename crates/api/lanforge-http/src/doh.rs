use std::borrow::Cow;
use std::net::IpAddr;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{
        HeaderMap, Method, StatusCode,
        header::CONTENT_TYPE,
    },
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lanforge_dns::{pipeline::DnsPipelineRequest, server::DnsContext};
use lanforge_dns_wire::{WireHeader, WireQuestion};
use lanforge_types::network::dns::TransportProtocol;
use serde::Deserialize;

use crate::server::AppState;

/// Query parameters for DNS-over-HTTPS (`DoH`) requests via GET.
#[derive(Debug, Deserialize)]
pub struct DnsQueryParams {
    pub dns: Option<String>,
}

/// Handler for `/dns-query` (RFC 8484 DNS Queries over HTTPS / `DoH`).
pub async fn handle_dns_query(
    State(state): State<AppState>,
    Query(params): Query<DnsQueryParams>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let query_data = if method == Method::GET {
        let Some(dns_base64) = params.dns else {
            return (StatusCode::BAD_REQUEST, "Missing dns parameter").into_response();
        };
        match URL_SAFE_NO_PAD.decode(dns_base64) {
            Ok(d) => Cow::Owned(d),
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64").into_response(),
        }
    } else {
        Cow::Borrowed(body.as_ref())
    };

    if query_data.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty query").into_response();
    }

    let Some(dns_ctx) = state
        .ctx
        .get_service_state_ref::<DnsContext>("dns::context")
    else {
        return (StatusCode::SERVICE_UNAVAILABLE, "DNS engine not ready").into_response();
    };

    let src_ip: IpAddr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    let Some(header) = WireHeader::parse(&query_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid DNS header").into_response();
    };
    let Some(question) = WireQuestion::parse(&query_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid DNS question").into_response();
    };

    let mut resp_buf = Vec::with_capacity(512);
    let filter_match = parking_lot::Mutex::new(None);
    let req = DnsPipelineRequest::new(
        &query_data,
        &header,
        &question,
        src_ip,
        TransportProtocol::Https,
        &filter_match,
    );

    match dns_ctx.pipeline.run(&dns_ctx, req, &mut resp_buf).await {
        Ok(()) => {
            if resp_buf.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                ([(CONTENT_TYPE, "application/dns-message")], resp_buf).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
