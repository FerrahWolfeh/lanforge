use crate::bus::{
    DeviceEvent, EventBus, EventVec, FirewallEvent, LanforgeEvent, NetworkChange, SystemEvent,
};
use crate::context::ConfigPatch;
use crate::context::LanforgeContext;
use crate::context::state::State;
use crate::error::CoreError;
use crate::service::ServiceHandle;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::firewall::{DynamicPortRequest, FirewallConfig, L4Protocol};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::system::{Cap, ServiceId, ServiceState, SystemStatus};
use lanforge_types::update::DeviceUpdate;
use std::iter;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use tokio::task::yield_now;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_core_state_concurrency_stress() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let mut write_tasks = Vec::new();
    for t_idx in 0u8..10 {
        let ctx = ctx.clone();
        write_tasks.push(tokio::spawn(async move {
            for i in 0u8..20 {
                let mac_bytes = [0x00, 0x11, 0x22, 0x33, t_idx, i];
                let mac = MacAddr(mac_bytes);
                let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
                    mac,
                    hostname: format!("host-{t_idx}-{i}"),
                });
                yield_now().await;
            }
        }));
    }

    let mut read_tasks = Vec::new();
    for _ in 0..10 {
        let ctx = ctx.clone();
        read_tasks.push(tokio::spawn(async move {
            for _ in 0..20 {
                ctx.with_state(|s| {
                    let _ = s.devices.len();
                });
                let _ = ctx.get_device(&MacAddr([0x00, 0x11, 0x22, 0x33, 0, 0]));
                yield_now().await;
            }
        }));
    }

    for t in write_tasks {
        t.await.unwrap();
    }
    for t in read_tasks {
        t.await.unwrap();
    }

    // Verify all 200 devices were added
    let count = ctx.with_state(|s| s.devices.len());
    assert_eq!(count, 200);
}

#[tokio::test]
async fn test_wait_for_service_dependency() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(Arc::clone(&bus), state, None);

    // 1. When already online, wait_for_service returns Ok(()) immediately
    ctx.set_service_state(ServiceId::Dns, ServiceState::Online);
    let res = ctx.wait_for_service(ServiceId::Dns).await;
    assert!(res.is_ok());

    // 2. When not online, it waits for ServiceReady event
    let ctx_clone = ctx.clone();
    let wait_handle = tokio::spawn(async move { ctx_clone.wait_for_service(ServiceId::Db).await });

    // Cooperative yield to let wait_handle spawn and register its listener
    yield_now().await;
    ctx.set_service_state(ServiceId::Db, ServiceState::Online);
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceReady {
        id: ServiceId::Db,
    }));

    let res = wait_handle.await.unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_wait_for_condition_shutdown_aborts() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(Arc::clone(&bus), state, None);

    // 1. If context is already terminated, wait_for_service immediately fails with Shutdown
    ctx.terminate();
    let res = ctx.wait_for_service(ServiceId::Db).await;
    assert!(matches!(res, Err(CoreError::Shutdown)));

    // 2. If waiting and shutdown is signaled on the bus, wait terminates with Shutdown
    ctx.reset_lifecycle();
    let ctx_clone = ctx.clone();
    let wait_handle = tokio::spawn(async move { ctx_clone.wait_for_service(ServiceId::Db).await });

    yield_now().await;
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

    let res = wait_handle.await.unwrap();
    assert!(matches!(res, Err(CoreError::Shutdown)));
}

#[tokio::test]
async fn test_service_handle_stream() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(Arc::clone(&bus), state, None);

    let mut handle = ctx.service_handle();

    // 1. Publish regular event
    let _ = handle.publish(LanforgeEvent::System(SystemEvent::SystemReady));
    let next = handle.next_event().await;
    assert!(matches!(
        next.unwrap().event,
        LanforgeEvent::System(SystemEvent::SystemReady)
    ));

    // 2. Shutdown terminates the stream
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let next = handle.next_event().await;
    assert!(next.is_none());
}

#[tokio::test]
async fn test_service_control_idempotency() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(Arc::clone(&bus), state, None);
    let mut rx = bus.subscribe_system();

    let ctrl = ServiceHandle::new(ServiceId::Dns, ctx.clone());
    assert_eq!(ctrl.id(), ServiceId::Dns);

    // Signal ready first time
    ctrl.ready();
    assert_eq!(ctx.get_service_state(ServiceId::Dns), ServiceState::Online);

    let mut ready_count = 0;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.event, LanforgeEvent::System(SystemEvent::ServiceReady { id }) if id == ServiceId::Dns)
        {
            ready_count += 1;
        }
    }
    assert_eq!(ready_count, 1);

    // Signal ready a second time (should be a no-op due to atomic swap)
    ctrl.ready();
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.event, LanforgeEvent::System(SystemEvent::ServiceReady { id }) if id == ServiceId::Dns)
        {
            ready_count += 1;
        }
    }
    assert_eq!(ready_count, 1, "ServiceHandle::ready must be idempotent");
}

#[tokio::test]
async fn test_dynamic_pppoe_config() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    assert!(ctx.get_pppoe_config().is_none());

    let cfg = PppoeConfig {
        username: "test_user".to_string(),
        wan_iface: "eth42".to_string(),
        ..Default::default()
    };

    ctx.update_pppoe_config(cfg);

    let retrieved = ctx.get_pppoe_config();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.username, "test_user");
    assert_eq!(retrieved.wan_iface, "eth42");
}

#[tokio::test]
async fn test_server_capabilities_matrix() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    // Set custom compiled capabilities
    ctx.set_compiled_caps(smallvec::smallvec![
        Cap::Dns,
        Cap::DhcpV4,
        Cap::DhcpV6,
        Cap::Http,
    ]);

    // Status with DNS enabled, but DHCP disabled
    ctx.set_status(SystemStatus {
        dns_enabled: true,
        dhcp_v4_enabled: false,
        dhcp_v6_enabled: false,
        http_enabled: true,
        ..Default::default()
    });

    let caps = ctx.server_capabilities();
    assert!(caps.enabled.contains(&Cap::Dns));
    assert!(caps.enabled.contains(&Cap::Http));
    assert!(!caps.enabled.contains(&Cap::DhcpV4));
    assert!(!caps.enabled.contains(&Cap::DhcpV6));
}

#[tokio::test]
async fn test_dynamic_port_registration() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(Arc::clone(&bus), state, None);
    let mut rx = bus.subscribe_firewall();

    // Register HTTP port 80
    ctx.register_service_port(DynamicPortRequest {
        service: "webui".to_string(),
        zone: "internal".to_string(),
        comment: Some("WebUI port".to_string()),
        port: 80,
        protocol: L4Protocol::Tcp,
    });

    let ev = rx.try_recv().unwrap();
    assert!(matches!(
        ev.event,
        LanforgeEvent::Firewall(FirewallEvent::PortOpenRequested(ref req)) if req.port == 80 && req.service == "webui"
    ));

    // Register same port again: must not duplicate
    ctx.register_service_port(DynamicPortRequest {
        service: "webui".to_string(),
        zone: "internal".to_string(),
        comment: Some("WebUI port".to_string()),
        port: 80,
        protocol: L4Protocol::Tcp,
    });
    assert_eq!(ctx.registered_service_ports().len(), 1);

    // Release port
    ctx.release_service_port("webui", 80, L4Protocol::Tcp);
    assert_eq!(ctx.registered_service_ports().len(), 0);

    let ev = rx.try_recv().unwrap();
    assert!(matches!(
        ev.event,
        LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested { port, .. }) if port == 80
    ));
}

#[tokio::test]
async fn test_firewall_transaction_lifecycle() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let candidate = FirewallConfig::default();

    // Stage transaction
    let report = ctx.stage_firewall_transaction(candidate);
    assert!(report.valid);
    let tx_id = report
        .tx_id
        .expect("Expected transaction ID for valid candidate");

    // Retrieve staged transaction
    let staged = ctx.get_staged_firewall_transaction();
    assert!(staged.is_some());
    let staged = staged.unwrap();
    assert_eq!(staged.tx_id, tx_id);

    // Set rollback deadline
    let deadline = Instant::now() + Duration::from_secs(60);
    ctx.set_firewall_transaction_rollback(&tx_id, deadline);
    assert_eq!(
        ctx.get_staged_firewall_transaction()
            .and_then(|tx| tx.auto_rollback_deadline),
        Some(deadline)
    );

    // Clear transaction
    let cleared = ctx.clear_staged_firewall_transaction(Some(&tx_id));
    assert!(cleared.is_some());
    assert!(ctx.get_staged_firewall_transaction().is_none());
}

/// A service's uptime runs while it serves (Online, Active, Degraded) and stops when it
/// leaves; going Online → Degraded keeps counting. Nothing ever set the start before, so
/// every banner showed uptime 0.
#[test]
fn service_uptime_follows_the_serving_states() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.set_service_state(ServiceId::Dns, ServiceState::Starting);
    assert_eq!(ctx.get_service_uptime(ServiceId::Dns), 0);

    ctx.set_service_state(ServiceId::Dns, ServiceState::Online);
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(ctx.get_service_uptime(ServiceId::Dns), 1);

    ctx.set_service_state(ServiceId::Dns, ServiceState::Degraded);
    assert_eq!(
        ctx.get_service_uptime(ServiceId::Dns),
        1,
        "degraded still serves"
    );

    ctx.set_service_state(ServiceId::Dns, ServiceState::Inactive);
    assert_eq!(ctx.get_service_uptime(ServiceId::Dns), 0);
}

/// A banner sums the counters of every socket its service registered; a stop, dormancy or
/// failure drops them, a pause keeps them (the sockets survive a pause).
#[test]
fn banner_transport_sums_the_registered_counters() {
    use lanforge_types::network::snapshot::TransportMetrics;
    use lanforge_types::system::ServiceId;

    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.register_service(ServiceId::Dns, "DNS Server", &[], None);
    let transport = |ctx: &LanforgeContext| ctx.service_banners()[0].transport;
    assert_eq!(transport(&ctx), None, "nothing registered, nothing shown");

    let (v4, v6) = (
        Arc::new(TransportMetrics::new()),
        Arc::new(TransportMetrics::new()),
    );
    v4.record_rx(100);
    v6.record_rx(60);
    v6.record_tx(80);
    ctx.set_service_transports(ServiceId::Dns, vec![v4, Arc::clone(&v6)]);
    let sum = transport(&ctx).unwrap();
    assert_eq!((sum.rx_packets, sum.rx_bytes, sum.tx_bytes), (2, 160, 80));

    v6.record_rx(40);
    assert_eq!(
        transport(&ctx).unwrap().rx_bytes,
        200,
        "live counters, not a copy"
    );

    ctx.set_service_state(ServiceId::Dns, ServiceState::Paused);
    assert!(transport(&ctx).is_some());
    ctx.set_service_state(ServiceId::Dns, ServiceState::Error);
    assert_eq!(transport(&ctx), None);
}

/// `dev:<name>` names the static host the admin called that before any device that merely
/// announces the hostname; a MAC names its device.
#[test]
fn resolve_device_prefers_the_static_hosts_name() {
    use lanforge_types::device::StaticHost;
    use lanforge_types::identifiers::DeviceIdentifier;

    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let announcer = MacAddr([2, 0, 0, 0, 0, 9]);
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac: announcer,
        hostname: "nas".to_string(),
    });
    let nas = MacAddr([2, 0, 0, 0, 5, 1]);
    let issues = ctx.apply_static_hosts(&[StaticHost {
        mac: nas,
        hostname: "NAS".to_string(),
        v4: None,
        v6: None,
        boot_file: None,
    }]);
    assert!(issues.is_empty(), "{issues:?}");

    let by_name: DeviceIdentifier = "nas".parse().unwrap();
    assert_eq!(ctx.resolve_device(&by_name), Some(nas));
    assert_eq!(ctx.resolve_device(&DeviceIdentifier::Mac(nas)), Some(nas));
    let unknown: DeviceIdentifier = "printer".parse().unwrap();
    assert_eq!(ctx.resolve_device(&unknown), None);
}

fn hint(ctx: &LanforgeContext, mac: MacAddr, name: &str) -> EventVec {
    ctx.apply_with_events(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: name.to_string(),
    })
}

fn refused_by(events: &EventVec) -> Option<MacAddr> {
    events.iter().find_map(|e| match e {
        LanforgeEvent::Device(DeviceEvent::NetworkUpdate { change, .. }) => match &**change {
            NetworkChange::HostnameRefused { holder, .. } => Some(*holder),
            _ => None,
        },
        _ => None,
    })
}

fn hostname_of(ctx: &LanforgeContext, mac: MacAddr) -> String {
    ctx.get_device(&mac)
        .map_or_else(String::new, |d| d.hostname.name.clone())
}

fn resolved(ctx: &LanforgeContext, name: &str) -> Option<MacAddr> {
    ctx.resolve_device(&name.parse().unwrap())
}

/// A port forward to `dev:<name>`, through the entry point the API and reload use.
fn forward_to(ctx: &LanforgeContext, names: &[&str]) {
    use lanforge_types::network::firewall::PortForwardRule;

    let mut fw = FirewallConfig::default();
    for (i, name) in names.iter().enumerate() {
        fw.port_forwards.push(PortForwardRule {
            comment: None,
            src_zone: "external".to_string(),
            internal_ip: format!("dev:{name}").parse().unwrap(),
            external_port: 8000 + u16::try_from(i).unwrap(),
            internal_port: 8000 + u16::try_from(i).unwrap(),
            protocol: L4Protocol::Tcp,
            enable_hairpin: false,
            family: None,
        });
    }
    let _ = ctx.apply_config(ConfigPatch::new().with_firewall(fw));
}

const SERVER: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);
const INTRUDER: MacAddr = MacAddr([2, 0, 0, 0, 0, 2]);

fn new_ctx() -> LanforgeContext {
    LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None)
}

/// A name nothing security-relevant targets keeps following whoever announces it: a phone that
/// re-randomizes its MAC keeps its name (and its adblock group).
#[test]
fn an_unbound_name_follows_its_announcer() {
    let ctx = new_ctx();
    let _ = hint(&ctx, SERVER, "pixel");
    let events = hint(&ctx, INTRUDER, "pixel");
    assert_eq!(refused_by(&events), None);
    assert_eq!(hostname_of(&ctx, INTRUDER), "pixel");
    assert_eq!(resolved(&ctx, "pixel"), Some(INTRUDER));
    assert!(ctx.name_bindings().is_empty());
}

/// Anyone on the LAN can announce any hostname. A device announcing the name a port forward
/// targets took the forward (and its IPv6 pinhole); the forward binds the name to its device
/// now, and another announcer is refused.
#[test]
fn a_forward_binds_its_name_and_refuses_other_announcers() {
    let ctx = new_ctx();
    let _ = hint(&ctx, SERVER, "servidor");
    forward_to(&ctx, &["servidor"]);
    assert_eq!(ctx.name_bindings().get("servidor"), Some(&SERVER));

    let events = hint(&ctx, INTRUDER, "Servidor");
    assert_eq!(refused_by(&events), Some(SERVER), "{events:?}");
    assert_eq!(resolved(&ctx, "servidor"), Some(SERVER));
    assert_ne!(hostname_of(&ctx, INTRUDER).to_lowercase(), "servidor");
    assert_eq!(
        ctx.read().bound_device("servidor"),
        Some(SERVER),
        "DNS path"
    );

    // DHCP renewals and mDNS announcements repeat the claim: reported once, still refused.
    assert_eq!(refused_by(&hint(&ctx, INTRUDER, "servidor")), None);
    let _ = ctx.apply(DeviceUpdate::MdnsHostnameHint {
        mac: INTRUDER,
        hostname: "servidor".to_string(),
    });
    assert_eq!(resolved(&ctx, "servidor"), Some(SERVER));
    // The holder renewing its own name is no conflict.
    assert_eq!(refused_by(&hint(&ctx, SERVER, "servidor")), None);
}

/// Mentioned before any device holds it: the first device announcing it gets it.
#[test]
fn a_name_referenced_first_binds_its_first_announcer() {
    let ctx = new_ctx();
    forward_to(&ctx, &["servidor"]);
    assert!(ctx.name_bindings().is_empty());

    let _ = hint(&ctx, SERVER, "servidor");
    assert_eq!(ctx.name_bindings().get("servidor"), Some(&SERVER));
    assert_eq!(refused_by(&hint(&ctx, INTRUDER, "servidor")), Some(SERVER));
}

/// A DNS rewrite to `dev:<name>` binds like a forward (its fallback too).
#[test]
fn a_dns_rewrite_binds_its_name() {
    use lanforge_types::network::dns::DnsRecordType;
    use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};

    let ctx = new_ctx();
    let _ = hint(&ctx, SERVER, "pixie");
    let _ = ctx.apply_config(ConfigPatch::new().with_dns_rewrites(vec![RewriteRule {
        id: None,
        domain: "*.eonteam.xyz".to_string(),
        rtype: DnsRecordType::Device,
        answer: "dev:pixie".parse::<RewriteAnswer>().unwrap(),
    }]));
    assert_eq!(ctx.name_bindings().get("pixie"), Some(&SERVER));
    assert_eq!(refused_by(&hint(&ctx, INTRUDER, "pixie")), Some(SERVER));
}

/// Dropping the last reference frees the name: it follows announcers again.
#[test]
fn dropping_the_reference_unbinds_the_name() {
    let ctx = new_ctx();
    let _ = hint(&ctx, SERVER, "servidor");
    forward_to(&ctx, &["servidor"]);
    forward_to(&ctx, &[]);
    assert!(ctx.name_bindings().is_empty());

    assert_eq!(refused_by(&hint(&ctx, INTRUDER, "servidor")), None);
    assert_eq!(resolved(&ctx, "servidor"), Some(INTRUDER));
}

/// Deleting the bound device frees the name; the forward still names it, so the next device
/// announcing it is bound (a replaced server).
#[test]
fn deleting_the_bound_device_frees_its_name() {
    let ctx = new_ctx();
    let _ = hint(&ctx, SERVER, "servidor");
    forward_to(&ctx, &["servidor"]);

    let _ = ctx.apply(DeviceUpdate::HostRemoved { mac: SERVER });
    assert!(ctx.name_bindings().is_empty());
    assert_eq!(refused_by(&hint(&ctx, INTRUDER, "servidor")), None);
    assert_eq!(ctx.name_bindings().get("servidor"), Some(&INTRUDER));
}

/// The bindings come back from redb before any announcement: a restart opens no race.
#[test]
fn restored_bindings_hold_before_any_announcement() {
    let ctx = new_ctx();
    ctx.restore_name_bindings(iter::once(("servidor".to_string(), SERVER)).collect());
    forward_to(&ctx, &["servidor"]);
    assert_eq!(refused_by(&hint(&ctx, INTRUDER, "servidor")), Some(SERVER));
}

/// The DNS fallback name (`dev:<fallback>` works too) binds like a hostname.
#[test]
fn a_bound_dns_fallback_is_refused_to_others() {
    let ctx = new_ctx();
    let _ = hint(&ctx, SERVER, "servidor");
    let fallback = ctx.get_device(&SERVER).unwrap().dns_fallback.clone();
    forward_to(&ctx, &[&fallback]);

    assert_eq!(refused_by(&hint(&ctx, INTRUDER, &fallback)), Some(SERVER));
}

/// A static host's name is pinned by `[hosts]`: never bound, and still resolved first.
#[test]
fn a_static_hosts_name_is_not_bound() {
    use lanforge_types::device::StaticHost;

    let ctx = new_ctx();
    let nas = MacAddr([2, 0, 0, 0, 5, 1]);
    let issues = ctx.apply_static_hosts(&[StaticHost {
        mac: nas,
        hostname: "nas".to_string(),
        v4: None,
        v6: None,
        boot_file: None,
    }]);
    assert!(issues.is_empty(), "{issues:?}");
    forward_to(&ctx, &["nas"]);
    assert!(ctx.name_bindings().is_empty());
    let _ = hint(&ctx, INTRUDER, "nas");
    assert_eq!(resolved(&ctx, "nas"), Some(nas));
}

/// A device dropping a name another device holds (an announcer that had it before the admin
/// made it a static host) unindexed the holder: the DNS lost the static host's name.
#[test]
fn a_device_dropping_a_shared_name_keeps_the_holder_indexed() {
    use lanforge_types::device::StaticHost;

    let ctx = new_ctx();
    let announcer = MacAddr([2, 0, 0, 0, 0, 9]);
    let _ = hint(&ctx, announcer, "nas");
    let nas = MacAddr([2, 0, 0, 0, 5, 1]);
    let issues = ctx.apply_static_hosts(&[StaticHost {
        mac: nas,
        hostname: "nas".to_string(),
        v4: None,
        v6: None,
        boot_file: None,
    }]);
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(ctx.get_by_hostname("nas").map(|d| d.mac), Some(nas));

    let _ = hint(&ctx, announcer, "tablet");
    assert_eq!(ctx.get_by_hostname("nas").map(|d| d.mac), Some(nas));
}

/// A device announcing a static host's name took the name index entry the DNS resolver reads
/// (`nas.lan` answered the announcer) while `dev:nas` still found the static host.
#[test]
fn an_announcer_never_takes_a_static_hosts_dns_name() {
    use lanforge_types::device::StaticHost;

    let ctx = new_ctx();
    let nas = MacAddr([2, 0, 0, 0, 5, 1]);
    let issues = ctx.apply_static_hosts(&[StaticHost {
        mac: nas,
        hostname: "nas".to_string(),
        v4: None,
        v6: None,
        boot_file: None,
    }]);
    assert!(issues.is_empty(), "{issues:?}");

    let _ = hint(&ctx, INTRUDER, "NAS");
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac: INTRUDER,
        ip: Ipv4Addr::new(192, 168, 1, 66),
        expires: SystemTime::now() + Duration::from_hours(1),
    });
    assert_eq!(ctx.get_by_hostname("nas").map(|d| d.mac), Some(nas));
    // A full rebuild (boot, indexing switched on) keeps it too.
    ctx.with_state_mut(State::rebuild_indices);
    assert_eq!(ctx.get_by_hostname("nas").map(|d| d.mac), Some(nas));
}
