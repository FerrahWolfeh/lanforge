use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, Method, StatusCode, header::CONTENT_TYPE},
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

/// The client the DNS pipeline sees (logs, rate limits, per-device filtering). The socket
/// peer, unless it is loopback: a reverse proxy on the router itself, whose
/// `X-Forwarded-For` names the client. From anyone else that header is the client's own
/// claim, and trusting it let any client pose as another device or as the router.
fn client_ip(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    if !peer.is_loopback() {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(peer)
}

/// Handler for `/dns-query` (RFC 8484 DNS Queries over HTTPS / `DoH`).
pub async fn handle_dns_query(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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

    let Some(dns_ctx) = state.ctx.get_shared::<DnsContext>() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "DNS engine not ready").into_response();
    };

    let src_ip = client_ip(peer.ip(), &headers);

    let Some(header) = WireHeader::parse(&query_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid DNS header").into_response();
    };
    let Some(question) = WireQuestion::parse(&query_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid DNS question").into_response();
    };

    let mut resp_buf = Vec::with_capacity(512);
    let req = DnsPipelineRequest::new(
        &query_data,
        &header,
        &question,
        src_ip,
        TransportProtocol::Https,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    #[test]
    fn lan_client_cannot_claim_another_address() {
        let lan: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(client_ip(lan, &xff("127.0.0.1")), lan);
        assert_eq!(client_ip(lan, &xff("192.168.1.10")), lan);
        assert_eq!(client_ip(lan, &HeaderMap::new()), lan);
    }

    #[test]
    fn local_reverse_proxy_names_the_client() {
        let proxy: IpAddr = "::1".parse().unwrap();
        let client: IpAddr = "fd00::42".parse().unwrap();
        assert_eq!(client_ip(proxy, &xff("fd00::42, 10.0.0.1")), client);
        assert_eq!(client_ip(proxy, &xff("garbage")), proxy);
        assert_eq!(client_ip(proxy, &HeaderMap::new()), proxy);
    }
}
