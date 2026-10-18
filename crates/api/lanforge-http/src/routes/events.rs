use std::convert::Infallible;
use std::time::Duration;

use axum::{
    Router,
    extract::{Query, State},
    http::header,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use futures::stream::Stream;
use lanforge_api::api::{HttpPaginatedResponse, LogMeta};
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_types::device::state::IPv4State;
use lanforge_types::events::{
    DeviceEvent, DnsEvent, FirewallEvent, NetworkEvent, PppoeEvent, StorageEvent, SystemEvent,
    TimedEvent, TrafficEvent,
};
use lanforge_types::identifiers::MacAddr;
use serde::Deserialize;

use crate::server::AppState;

#[derive(Debug, Deserialize, Default)]
pub struct EventsQuery {
    pub filter: Option<String>,
    pub initial: Option<usize>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    #[serde(default)]
    pub follow: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_events))
        .route("/history", get(handle_events_history))
}

async fn handle_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<EventsQuery>,
) -> Response {
    let is_sse = params.follow
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/event-stream"));

    if is_sse {
        let stream = handle_events_stream(state, params.filter, params.initial);
        Sse::new(stream)
            .keep_alive(
                KeepAlive::default()
                    .interval(Duration::from_secs(15))
                    .text("keepalive"),
            )
            .into_response()
    } else {
        handle_events_history_inner(&state, &params).into_response()
    }
}

async fn handle_events_history(
    State(state): State<AppState>,
    Query(params): Query<EventsQuery>,
) -> Response {
    handle_events_history_inner(&state, &params)
}

fn handle_events_history_inner(
    state: &AppState,
    params: &EventsQuery,
) -> Response {
    let limit = params.limit.or(params.initial).unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0);

    let raw_events = state
        .log_db
        .get_history(limit + offset)
        .unwrap_or_default();

    let filtered: Vec<serde_json::Value> = raw_events
        .into_iter()
        .filter(|e| !matches!(&e.event, LanforgeEvent::Dns(_)))
        .filter(|e| matches_filter(&e.event, params.filter.as_deref()))
        .skip(offset)
        .take(limit)
        .filter_map(|e| event_to_json_value(&state.ctx, &e))
        .collect();

    let total = filtered.len();

    (
        axum::http::StatusCode::OK,
        axum::Json(HttpPaginatedResponse {
            data: filtered,
            meta: LogMeta {
                total,
                limit,
                offset,
            },
        }),
    )
        .into_response()
}

const fn matches_filter(event: &LanforgeEvent, filter: Option<&str>) -> bool {
    let Some(f) = filter else { return true };
    match event {
        LanforgeEvent::Device(dev_ev) => {
            f.eq_ignore_ascii_case("device")
                || f.eq_ignore_ascii_case("devices")
                || (f.eq_ignore_ascii_case("dhcp")
                    && matches!(
                        dev_ev,
                        DeviceEvent::LeaseRelease { .. }
                            | DeviceEvent::LeaseRenew { .. }
                            | DeviceEvent::DhcpV4Transaction { .. }
                            | DeviceEvent::DhcpV6Transaction { .. }
                            | DeviceEvent::NetworkUpdate { .. }
                    ))
        }
        LanforgeEvent::Network(_) => {
            f.eq_ignore_ascii_case("network")
                || f.eq_ignore_ascii_case("dhcp")
                || f.eq_ignore_ascii_case("ra")
        }
        LanforgeEvent::System(sys_ev) => {
            f.eq_ignore_ascii_case("system")
                || (f.eq_ignore_ascii_case("dhcp")
                    && matches!(
                        sys_ev,
                        SystemEvent::ConfigDhcpV4Changed
                            | SystemEvent::ConfigDhcpV6Changed
                            | SystemEvent::ConfigDhcpOptionsChanged
                    ))
        }
        LanforgeEvent::Storage(_) => {
            f.eq_ignore_ascii_case("storage") || f.eq_ignore_ascii_case("db")
        }
        LanforgeEvent::Pppoe(_) => f.eq_ignore_ascii_case("pppoe"),
        LanforgeEvent::Firewall(_) => f.eq_ignore_ascii_case("firewall"),
        LanforgeEvent::Traffic(_) => f.eq_ignore_ascii_case("traffic"),
        LanforgeEvent::Dns(_) => f.eq_ignore_ascii_case("dns"),
    }
}

const fn extract_mac(event: &LanforgeEvent) -> Option<MacAddr> {
    match event {
        LanforgeEvent::Device(d) => match d {
            DeviceEvent::Discovered { mac, .. }
            | DeviceEvent::NetworkUpdate { mac, .. }
            | DeviceEvent::NetworkActivity { mac, .. }
            | DeviceEvent::AdminUpdate { mac, .. }
            | DeviceEvent::Expired { mac }
            | DeviceEvent::Purged { mac }
            | DeviceEvent::LeaseRelease { mac, .. }
            | DeviceEvent::LeaseRenew { mac, .. }
            | DeviceEvent::DhcpV4Transaction { mac, .. }
            | DeviceEvent::DhcpV6Transaction { mac, .. } => Some(*mac),
            DeviceEvent::NeighborBatchSummary { .. } => None,
        },
        LanforgeEvent::Network(n) => match n {
            NetworkEvent::WolTriggered { mac, .. }
            | NetworkEvent::RsReceived { mac }
            | NetworkEvent::LeaseRenewRequested { mac, .. }
            | NetworkEvent::LeaseReleaseRequested { mac, .. } => Some(*mac),
            NetworkEvent::PrefixChanged(..)
            | NetworkEvent::InterfaceUpdated { .. }
            | NetworkEvent::RaTriggerRequested => None,
        },
        _ => None,
    }
}

fn enrich_device_info(ctx: &LanforgeContext, mac: MacAddr) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("mac".to_string(), serde_json::Value::String(mac.to_string()));

    ctx.with_state(|s| {
        if let Some(d) = s.devices.get(&mac) {
            let h = d.display_hostname();
            if h != "?" && !h.is_empty() {
                map.insert("hostname".to_string(), serde_json::Value::String(h.to_string()));
            } else if !d.dns_fallback.is_empty() {
                map.insert("hostname".to_string(), serde_json::Value::String(d.dns_fallback.clone()));
            }

            let ip = match &d.v4 {
                IPv4State::Static(ip) => Some(ip.to_string()),
                IPv4State::Dynamic(lease) => Some(lease.ip.to_string()),
                IPv4State::None => d.seen_v4.first().map(|(ip, _)| ip.to_string()),
            };
            if let Some(ip_str) = ip {
                map.insert("ip".to_string(), serde_json::Value::String(ip_str));
            }

            map.insert("class".to_string(), serde_json::Value::String(format!("{:?}", d.class)));
            map.insert("status".to_string(), serde_json::Value::String(format!("{:?}", d.status)));
            map.insert("is_static".to_string(), serde_json::Value::Bool(d.is_static()));
            if let Some(ref iface) = d.iface {
                map.insert("iface".to_string(), serde_json::Value::String(iface.clone()));
            }
        }
    });

    serde_json::Value::Object(map)
}

fn enrich_interface_info(ctx: &LanforgeContext, ifindex: u32) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("ifindex".to_string(), serde_json::Value::Number(ifindex.into()));

    let mut if_name = [0u8; libc::IF_NAMESIZE];
    let name_opt = unsafe {
        let ptr = libc::if_indextoname(ifindex, if_name.as_mut_ptr().cast());
        if ptr.is_null() {
            None
        } else {
            std::ffi::CStr::from_ptr(ptr).to_str().ok().map(String::from)
        }
    };
    if let Some(name) = name_opt {
        map.insert("name".to_string(), serde_json::Value::String(name));
    }

    let if_state = ctx.get_interface_state(ifindex);
    if let Some((v4, prefix_len)) = if_state.v4 {
        map.insert("ipv4".to_string(), serde_json::Value::String(format!("{v4}/{prefix_len}")));
    }
    if let Some(gua) = if_state.gua {
        map.insert("gua".to_string(), serde_json::Value::String(gua.to_string()));
    }
    if let Some(ula) = if_state.ula {
        map.insert("ula".to_string(), serde_json::Value::String(ula.to_string()));
    }

    serde_json::Value::Object(map)
}

const fn event_topic_and_kind(event: &LanforgeEvent) -> (&'static str, &'static str) {
    match event {
        LanforgeEvent::Device(d) => ("device", match d {
            DeviceEvent::Discovered { .. } => "Discovered",
            DeviceEvent::NetworkUpdate { .. } => "NetworkUpdate",
            DeviceEvent::NetworkActivity { .. } => "NetworkActivity",
            DeviceEvent::AdminUpdate { .. } => "AdminUpdate",
            DeviceEvent::Expired { .. } => "Expired",
            DeviceEvent::Purged { .. } => "Purged",
            DeviceEvent::LeaseRelease { .. } => "LeaseRelease",
            DeviceEvent::LeaseRenew { .. } => "LeaseRenew",
            DeviceEvent::DhcpV4Transaction { .. } => "DhcpV4Transaction",
            DeviceEvent::DhcpV6Transaction { .. } => "DhcpV6Transaction",
            DeviceEvent::NeighborBatchSummary { .. } => "NeighborBatchSummary",
        }),
        LanforgeEvent::Network(n) => ("network", match n {
            NetworkEvent::PrefixChanged(..) => "PrefixChanged",
            NetworkEvent::InterfaceUpdated { .. } => "InterfaceUpdated",
            NetworkEvent::WolTriggered { .. } => "WolTriggered",
            NetworkEvent::RsReceived { .. } => "RsReceived",
            NetworkEvent::LeaseRenewRequested { .. } => "LeaseRenewRequested",
            NetworkEvent::LeaseReleaseRequested { .. } => "LeaseReleaseRequested",
            NetworkEvent::RaTriggerRequested => "RaTriggerRequested",
        }),
        LanforgeEvent::System(s) => ("system", match s {
            SystemEvent::Shutdown => "Shutdown",
            SystemEvent::StateReady => "StateReady",
            SystemEvent::DbReady => "DbReady",
            SystemEvent::InterfaceReady => "InterfaceReady",
            SystemEvent::ServiceReady { .. } => "ServiceReady",
            SystemEvent::SystemReady => "SystemReady",
            SystemEvent::ReloadConfig => "ReloadConfig",
            SystemEvent::ConfigUpdate { .. } => "ConfigUpdate",
            SystemEvent::ServiceStatusBanner(..) => "ServiceStatusBanner",
            SystemEvent::ServiceControl { .. } => "ServiceControl",
            SystemEvent::ConfigDhcpV4Changed => "ConfigDhcpV4Changed",
            SystemEvent::ConfigDhcpV6Changed => "ConfigDhcpV6Changed",
            SystemEvent::ConfigRaChanged => "ConfigRaChanged",
            SystemEvent::ConfigTftpChanged => "ConfigTftpChanged",
            SystemEvent::ConfigDhcpOptionsChanged => "ConfigDhcpOptionsChanged",
            SystemEvent::ConfigPppoeChanged => "ConfigPppoeChanged",
        }),
        LanforgeEvent::Storage(s) => ("storage", match s {
            StorageEvent::DbVacuum => "DbVacuum",
            StorageEvent::DbLogClean => "DbLogClean",
            StorageEvent::DbPrune => "DbPrune",
            StorageEvent::DbReset => "DbReset",
            StorageEvent::DbResetCompleted => "DbResetCompleted",
            StorageEvent::TableDirty => "TableDirty",
            StorageEvent::DbWrite { .. } => "DbWrite",
        }),
        LanforgeEvent::Pppoe(p) => ("pppoe", match p {
            PppoeEvent::SessionUp(..) => "SessionUp",
            PppoeEvent::SessionDown { .. } => "SessionDown",
            PppoeEvent::Reconnecting { .. } => "Reconnecting",
            PppoeEvent::AuthFailed { .. } => "AuthFailed",
            PppoeEvent::KeepaliveWarning { .. } => "KeepaliveWarning",
            PppoeEvent::KeepaliveRestored => "KeepaliveRestored",
        }),
        LanforgeEvent::Firewall(f) => ("firewall", match f {
            FirewallEvent::PortOpenRequested(..) => "PortOpenRequested",
            FirewallEvent::PortReleaseRequested { .. } => "PortReleaseRequested",
            FirewallEvent::RulesetApplied(..) => "RulesetApplied",
            FirewallEvent::ApplyFailed { .. } => "ApplyFailed",
            FirewallEvent::RulesetFlushed => "RulesetFlushed",
            FirewallEvent::RulesetChanged => "RulesetChanged",
        }),
        LanforgeEvent::Traffic(t) => ("traffic", match &**t {
            TrafficEvent::TuningApplied { .. } => "TuningApplied",
            TrafficEvent::SqmApplied { .. } => "SqmApplied",
            TrafficEvent::SqmCleared { .. } => "SqmCleared",
            TrafficEvent::RulesetChanged => "RulesetChanged",
        }),
        LanforgeEvent::Dns(d) => ("dns", match d {
            DnsEvent::AdblockToggle { .. } => "AdblockToggle",
            DnsEvent::AdblockReload => "AdblockReload",
            DnsEvent::AdblockBlock(..) => "AdblockBlock",
            DnsEvent::AdblockAllow(..) => "AdblockAllow",
            DnsEvent::QueryBlocked { .. } => "QueryBlocked",
            DnsEvent::QueryResolved(..) => "QueryResolved",
            DnsEvent::CacheFlush => "CacheFlush",
            DnsEvent::ConfigRewritesChanged => "ConfigRewritesChanged",
            DnsEvent::ConfigAllowlistChanged => "ConfigAllowlistChanged",
            DnsEvent::ConfigAdblockChanged => "ConfigAdblockChanged",
            DnsEvent::ConfigAdblockRulesChanged => "ConfigAdblockRulesChanged",
            DnsEvent::ConfigUpstreamsChanged => "ConfigUpstreamsChanged",
            DnsEvent::ConfigUpstreamModeChanged(_) => "ConfigUpstreamModeChanged",
        }),
    }
}

fn enrich_event_details(
    ctx: &LanforgeContext,
    map: &mut serde_json::Map<String, serde_json::Value>,
    event: &LanforgeEvent,
) {
    // Enrich with device info if MAC address is present
    if let Some(mac) = extract_mac(event) {
        map.insert("device_info".to_string(), enrich_device_info(ctx, mac));
    }

    // Enrich with interface info if InterfaceUpdated
    if let LanforgeEvent::Network(NetworkEvent::InterfaceUpdated { ifindex }) = event {
        map.insert("interface_info".to_string(), enrich_interface_info(ctx, *ifindex));
    }

    // Enrich with service info if ServiceControl
    if let LanforgeEvent::System(SystemEvent::ServiceControl { id, .. }) = event {
        let mut svc_map = serde_json::Map::new();
        svc_map.insert("id".to_string(), serde_json::Value::String(id.clone()));
        let state = ctx.get_service_state(id);
        svc_map.insert("state".to_string(), serde_json::Value::String(format!("{state:?}")));
        let uptime = ctx.get_service_uptime(id);
        svc_map.insert("uptime_secs".to_string(), serde_json::Value::Number(uptime.into()));
        map.insert("service_info".to_string(), serde_json::Value::Object(svc_map));
    }
}

fn event_to_json_value(ctx: &LanforgeContext, event: &TimedEvent) -> Option<serde_json::Value> {
    let ts_millis = u64::try_from(
        event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(0);

    let (topic, kind) = event_topic_and_kind(&event.event);

    let mut val = serde_json::to_value(event).ok()?;
    if let serde_json::Value::Object(ref mut map) = val {
        map.insert(
            "topic".to_string(),
            serde_json::Value::String(topic.to_string()),
        );
        map.insert("kind".to_string(), serde_json::Value::String(kind.to_string()));
        map.insert(
            "timestamp_ms".to_string(),
            serde_json::Value::Number(ts_millis.into()),
        );

        enrich_event_details(ctx, map, &event.event);
    }
    Some(val)
}

fn handle_events_stream(
    state: AppState,
    filter: Option<String>,
    initial: Option<usize>,
) -> impl Stream<Item = Result<Event, Infallible>> + use<> {
    let mut rx = state.ctx.bus().subscribe();

    async_stream::try_stream! {
        // 1. Replay initial history from log_db if requested
        if let Some(n) = initial && n > 0 {
            let initial_limit = n.min(250);
            if let Ok(history) = state.log_db.get_history(initial_limit) {
                for ev in history {
                    if let LanforgeEvent::Dns(_) = &ev.event {
                        continue;
                    }
                    if !matches_filter(&ev.event, filter.as_deref()) {
                        continue;
                    }
                    if let Some(val) = event_to_json_value(&state.ctx, &ev)
                        && let Ok(json) = serde_json::to_string(&val)
                    {
                        yield Event::default().data(json);
                    }
                }
            }
        }

        // 2. Stream live bus events
        loop {
            let event = match rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            // Filter out DNS events (which have their own dedicated log stream)
            if let LanforgeEvent::Dns(_) = &event.event {
                continue;
            }

            if !matches_filter(&event.event, filter.as_deref()) {
                continue;
            }

            if let Some(val) = event_to_json_value(&state.ctx, &event)
                && let Ok(json) = serde_json::to_string(&val)
            {
                yield Event::default().data(json);
            }
        }
    }
}
