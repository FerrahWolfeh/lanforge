use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::{delete, get},
};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamProtocol};
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

fn deserialize_flexible_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let trimmed = s.trim();
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inside = &trimmed[1..trimmed.len() - 1];
        if let Ok(ip) = inside.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, 53));
        }
    }
    trimmed.parse::<SocketAddr>().map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
pub struct UpstreamAddRequest {
    #[serde(deserialize_with = "deserialize_flexible_socket_addr")]
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamTestParams {
    #[serde(deserialize_with = "deserialize_flexible_socket_addr")]
    pub addr: SocketAddr,
    #[serde(default)]
    pub protocol: Option<UpstreamProtocol>,
    pub domain: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct UpstreamTestResponse {
    pub ok: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamRemoveRequest {
    #[serde(deserialize_with = "deserialize_flexible_socket_addr")]
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReverseResolverAddRequest {
    pub subnet: String,
    pub resolver_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct ReverseResolverRemoveRequest {
    pub subnet: String,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamModeRequest {
    pub mode: UpstreamMode,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/upstreams",
            get(handle_dns_upstreams)
                .post(handle_dns_upstream_add)
                .delete(handle_dns_upstream_remove),
        )
        .route("/upstreams/test", get(handle_dns_upstream_test).post(handle_dns_upstream_test))
        .route("/upstreams/clear", delete(handle_dns_upstream_clear))
        .route(
            "/upstreams/mode",
            get(handle_dns_upstream_mode_get)
                .put(handle_dns_upstream_mode_set)
                .post(handle_dns_upstream_mode_set),
        )
        .route(
            "/reverse-resolvers",
            get(handle_reverse_resolver_list)
                .post(handle_reverse_resolver_add)
                .delete(handle_reverse_resolver_remove),
        )
}

async fn handle_dns_upstream_mode_get(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_upstream_mode_get().await, DnsUpstreamMode)
}

async fn handle_dns_upstream_mode_set(
    State(state): State<AppState>,
    Json(payload): Json<UpstreamModeRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_mode_set(payload.mode).await,
        DnsUpstreamMode
    )
}

async fn handle_dns_upstreams(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_upstreams().await, DnsUpstreams)
}

async fn handle_dns_upstream_add(
    State(state): State<AppState>,
    Query(params): Query<UpstreamAddRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_add(params.addr, params.protocol, params.domain).await,
        Success => NoContent
    )
}

async fn handle_dns_upstream_remove(
    State(state): State<AppState>,
    Query(params): Query<UpstreamRemoveRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_remove(params.addr, params.protocol, params.domain).await,
        Success => NoContent
    )
}

async fn handle_dns_upstream_clear(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_clear().await,
        Success => NoContent
    )
}

async fn handle_reverse_resolver_list(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_reverse_resolver_list().await,
        DnsReverseResolvers
    )
}

async fn handle_reverse_resolver_add(
    State(state): State<AppState>,
    Query(params): Query<ReverseResolverAddRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_reverse_resolver_add(params.subnet, params.resolver_uri).await,
        Success => NoContent
    )
}

async fn handle_reverse_resolver_remove(
    State(state): State<AppState>,
    Query(params): Query<ReverseResolverRemoveRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_reverse_resolver_remove(params.subnet).await,
        Success => NoContent
    )
}

async fn handle_dns_upstream_test(
    Query(params): Query<UpstreamTestParams>,
) -> impl IntoResponse {
    let proto = params.protocol.unwrap_or(UpstreamProtocol::Udp);
    let res = test_upstream_reachability(params.addr, proto).await;
    axum::Json(res)
}

async fn test_upstream_reachability(addr: SocketAddr, proto: UpstreamProtocol) -> UpstreamTestResponse {
    let start = std::time::Instant::now();
    let query_bytes: &[u8] = &[
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x0a, b'c', b'l', b'o', b'u', b'd', b'f', b'a', b'r', b'e', 0x03, b'c', b'o', b'm', 0x00, // QNAME
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ];

    match proto {
        UpstreamProtocol::Udp => {
            let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let sock = match tokio::net::UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(e) => {
                    return UpstreamTestResponse {
                        ok: false,
                        latency_ms: 0,
                        error: Some(format!("Failed to bind local UDP socket: {e}")),
                    };
                }
            };
            if let Err(e) = sock.send_to(query_bytes, addr).await {
                return UpstreamTestResponse {
                    ok: false,
                    latency_ms: 0,
                    error: Some(format!("Failed to send UDP query: {e}")),
                };
            }
            let mut buf = [0u8; 512];
            match tokio::time::timeout(std::time::Duration::from_millis(2500), sock.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) if len >= 12 => {
                    let rcode = buf[3] & 0x0F;
                    UpstreamTestResponse {
                        ok: true,
                        latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                        error: if rcode == 0 {
                            None
                        } else {
                            Some(format!("Server replied with RCODE {rcode}"))
                        },
                    }
                }
                Ok(Ok(_)) => UpstreamTestResponse {
                    ok: false,
                    latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                    error: Some("Received truncated DNS header".into()),
                },
                Ok(Err(e)) => UpstreamTestResponse {
                    ok: false,
                    latency_ms: 0,
                    error: Some(format!("I/O error waiting for UDP response: {e}")),
                },
                Err(_) => UpstreamTestResponse {
                    ok: false,
                    latency_ms: 2500,
                    error: Some("Timed out after 2500ms (no UDP response)".into()),
                },
            }
        }
        UpstreamProtocol::Tls | UpstreamProtocol::Https | UpstreamProtocol::Quic => {
            match tokio::time::timeout(
                std::time::Duration::from_millis(2500),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(_stream)) => UpstreamTestResponse {
                    ok: true,
                    latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                    error: None,
                },
                Ok(Err(e)) => UpstreamTestResponse {
                    ok: false,
                    latency_ms: 0,
                    error: Some(format!("TCP connection failed: {e}")),
                },
                Err(_) => UpstreamTestResponse {
                    ok: false,
                    latency_ms: 2500,
                    error: Some("Timed out connecting to upstream via TCP (2500ms)".into()),
                },
            }
        }
    }
}
