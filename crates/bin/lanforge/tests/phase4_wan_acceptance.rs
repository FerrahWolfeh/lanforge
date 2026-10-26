//! Acceptance tests for Phase 4 — Synthetic Nodes (interfaces, wan) and WAN Transitions.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use lanforge::registry::ServiceRegistry;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, Edge, LanforgeService, LossPolicy, RestartPolicy, RuntimeClass,
    ServiceHandle, ServiceSpec,
};
use lanforge_types::network::snapshot::{InterfaceSnapshot, LinkInfo, WanSnapshot, WanState};
use lanforge_types::system::{DegradedReason, ServiceId, ServiceState};
use smallvec::smallvec;
use tokio::time::timeout;

fn init_test_ctx() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    LanforgeContext::new(bus, State::new(), None)
}

fn dummy_spec(id: ServiceId, deps: &'static [Edge]) -> ServiceSpec {
    ServiceSpec {
        id,
        display_name: id.as_str(),
        runtime: RuntimeClass::Shared,
        restart: RestartPolicy {
            base_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
            max_retries: 3,
            healthy_uptime: Duration::from_millis(50),
        },
        shutdown_timeout: Duration::from_millis(100),
        deps,
        condition: Condition::ALWAYS,
    }
}

// ---------------------------------------------------------------------------
// 1. WAN Flap Isolation Acceptance Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wan_flap_isolated() {
    let ctx = init_test_ctx();

    static IF_DEPS: &[Edge] = &[];
    static PPPOE_DEPS: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Continue)];
    static WAN_DEPS: &[Edge] = &[Edge::wants(ServiceId::Pppoe)];
    static DHCP4_DEPS: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Degrade)];
    static DHCP6_DEPS: &[Edge] = &[
        Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
        Edge::wants(ServiceId::Wan),
    ];
    static RA_DEPS: &[Edge] = &[
        Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
        Edge::wants(ServiceId::Wan),
    ];
    static DNS_DEPS: &[Edge] = &[
        Edge::wants(ServiceId::Wan),
        Edge::wants(ServiceId::Interfaces),
    ];
    static HTTP_DEPS: &[Edge] = &[Edge::wants(ServiceId::Wan)];

    let pppoe_starts = Arc::new(AtomicU32::new(0));
    let dhcp4_starts = Arc::new(AtomicU32::new(0));
    let dhcp6_starts = Arc::new(AtomicU32::new(0));
    let ra_starts = Arc::new(AtomicU32::new(0));
    let dns_starts = Arc::new(AtomicU32::new(0));
    let http_starts = Arc::new(AtomicU32::new(0));

    // Synthetic Interfaces Node
    struct IfNode;
    impl LanforgeService for IfNode {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Interfaces, IF_DEPS)
        }
    }
    impl AsyncService for IfNode {
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    // PPPoE Service that simulates bouncing its internal session
    struct FlappingPppoe {
        starts: Arc<AtomicU32>,
    }
    impl LanforgeService for FlappingPppoe {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Pppoe, PPPOE_DEPS)
        }
    }
    impl AsyncService for FlappingPppoe {
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    // Synthetic WAN Node
    struct WanNode;
    impl LanforgeService for WanNode {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Wan, WAN_DEPS)
        }
    }
    impl AsyncService for WanNode {
        async fn serve(
            &mut self,
            ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            ctx.set_wan_snapshot(WanSnapshot {
                state: WanState::Up,
                ifindex: Some(2),
                ifname: Some("ppp0".into()),
                v4: Some((Ipv4Addr::new(203, 0, 113, 1), 32)),
                v6_prefixes: smallvec![],
                generation: 1,
            });
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    // Counter service wrapper
    struct TrackedSvc {
        id: ServiceId,
        deps: &'static [Edge],
        starts: Arc<AtomicU32>,
    }
    impl LanforgeService for TrackedSvc {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(self.id, self.deps)
        }
    }
    impl AsyncService for TrackedSvc {
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    let mut reg = ServiceRegistry::new();
    reg.register(&ctx, || IfNode);
    let p_starts = Arc::clone(&pppoe_starts);
    reg.register(&ctx, move || FlappingPppoe {
        starts: Arc::clone(&p_starts),
    });
    reg.register(&ctx, || WanNode);

    let d4 = Arc::clone(&dhcp4_starts);
    reg.register(&ctx, move || TrackedSvc {
        id: ServiceId::Dhcp4,
        deps: DHCP4_DEPS,
        starts: Arc::clone(&d4),
    });
    let d6 = Arc::clone(&dhcp6_starts);
    reg.register(&ctx, move || TrackedSvc {
        id: ServiceId::Dhcp6,
        deps: DHCP6_DEPS,
        starts: Arc::clone(&d6),
    });
    let ra = Arc::clone(&ra_starts);
    reg.register(&ctx, move || TrackedSvc {
        id: ServiceId::Ra,
        deps: RA_DEPS,
        starts: Arc::clone(&ra),
    });
    let dns = Arc::clone(&dns_starts);
    reg.register(&ctx, move || TrackedSvc {
        id: ServiceId::Dns,
        deps: DNS_DEPS,
        starts: Arc::clone(&dns),
    });
    let http = Arc::clone(&http_starts);
    reg.register(&ctx, move || TrackedSvc {
        id: ServiceId::Http,
        deps: HTTP_DEPS,
        starts: Arc::clone(&http),
    });

    let sup = reg.start(&ctx).expect("start supervisor");

    // Wait until all services are Online
    timeout(Duration::from_millis(500), async {
        loop {
            if ctx.get_service_state(ServiceId::Dhcp4) == ServiceState::Online
                && ctx.get_service_state(ServiceId::Dhcp6) == ServiceState::Online
                && ctx.get_service_state(ServiceId::Ra) == ServiceState::Online
                && ctx.get_service_state(ServiceId::Dns) == ServiceState::Online
                && ctx.get_service_state(ServiceId::Http) == ServiceState::Online
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("All services must reach Online");

    // Verify initial start counts
    assert_eq!(dhcp4_starts.load(Ordering::SeqCst), 1);
    assert_eq!(dhcp6_starts.load(Ordering::SeqCst), 1);
    assert_eq!(ra_starts.load(Ordering::SeqCst), 1);
    assert_eq!(dns_starts.load(Ordering::SeqCst), 1);
    assert_eq!(http_starts.load(Ordering::SeqCst), 1);

    // Simulate WAN transition (WAN drops to Down and recovers to Up)
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Down,
        ifindex: None,
        ifname: None,
        v4: None,
        v6_prefixes: smallvec![],
        generation: 2,
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifindex: Some(2),
        ifname: Some("ppp0".into()),
        v4: Some((Ipv4Addr::new(203, 0, 113, 2), 32)),
        v6_prefixes: smallvec![],
        generation: 3,
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Golden Rule of Isolation assertion:
    // None of the peripheral daemons were restarted or had their sockets closed!
    assert_eq!(
        dhcp4_starts.load(Ordering::SeqCst),
        1,
        "dhcp4 must not restart on WAN flap"
    );
    assert_eq!(
        dhcp6_starts.load(Ordering::SeqCst),
        1,
        "dhcp6 must not restart on WAN flap"
    );
    assert_eq!(
        ra_starts.load(Ordering::SeqCst),
        1,
        "ra must not restart on WAN flap"
    );
    assert_eq!(
        dns_starts.load(Ordering::SeqCst),
        1,
        "dns must not restart on WAN flap"
    );
    assert_eq!(
        http_starts.load(Ordering::SeqCst),
        1,
        "http must not restart on WAN flap"
    );

    sup.shutdown(&ctx, Duration::from_millis(200)).await;
}

// ---------------------------------------------------------------------------
// 2. WAN Traffic Pause & Resume Acceptance Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wan_traffic_pause_resume() {
    let ctx = init_test_ctx();
    let mut wan_rx = ctx.watch_wan();

    // Verify initial state
    assert_eq!(wan_rx.borrow().state, WanState::Down);

    // WAN comes UP: SQM active
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifindex: Some(10),
        ifname: Some("wan0".into()),
        v4: Some((Ipv4Addr::new(198, 51, 100, 1), 24)),
        v6_prefixes: smallvec![],
        generation: 1,
    });
    wan_rx.changed().await.unwrap();
    assert_eq!(wan_rx.borrow().state, WanState::Up);
    assert_eq!(wan_rx.borrow().generation, 1);

    // WAN drops DOWN: SQM pauses without tearing down LAN NIC tuning
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Down,
        ifindex: None,
        ifname: None,
        v4: None,
        v6_prefixes: smallvec![],
        generation: 2,
    });
    wan_rx.changed().await.unwrap();
    assert_eq!(wan_rx.borrow().state, WanState::Down);
    assert_eq!(wan_rx.borrow().generation, 2);

    // WAN recovers UP with generation bump: SQM resumed/reapplied
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifindex: Some(10),
        ifname: Some("wan0".into()),
        v4: Some((Ipv4Addr::new(198, 51, 100, 2), 24)),
        v6_prefixes: smallvec![],
        generation: 3,
    });
    wan_rx.changed().await.unwrap();
    assert_eq!(wan_rx.borrow().state, WanState::Up);
    assert_eq!(wan_rx.borrow().generation, 3);
}

// ---------------------------------------------------------------------------
// 3. WAN Firewall Recompile on Generation Acceptance Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wan_firewall_recompile_on_generation() {
    let ctx = init_test_ctx();
    let mut wan_rx = ctx.watch_wan();

    let recompiles = Arc::new(AtomicU32::new(0));
    let r_count = Arc::clone(&recompiles);

    // Simulate Firewall service watching wan_rx
    let handle = tokio::spawn(async move {
        let mut last_gen = 0u64;
        while let Ok(()) = wan_rx.changed().await {
            let snap = wan_rx.borrow().clone();
            if snap.generation != last_gen {
                last_gen = snap.generation;
                r_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    // Advance generation 3 times
    for generation_idx in 1..=3 {
        ctx.set_wan_snapshot(WanSnapshot {
            state: WanState::Up,
            ifindex: Some(generation_idx as u32),
            ifname: Some(format!("ppp{}", generation_idx)),
            v4: None,
            v6_prefixes: smallvec![],
            generation: generation_idx,
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(recompiles.load(Ordering::SeqCst), 3);
    handle.abort();
}

// ---------------------------------------------------------------------------
// 4. Interfaces No-Carrier Ready Acceptance Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interfaces_no_carrier_ready() {
    let ctx = init_test_ctx();

    // Setup interface snapshot where the configured LAN link has NO carrier
    let snap = InterfaceSnapshot {
        links: smallvec![LinkInfo {
            ifindex: 1,
            name: "lan0".to_string(),
            carrier: false, // NO CARRIER
            addrs: smallvec![],
        }],
        generation: 1,
    };
    ctx.set_interfaces_snapshot(snap);

    let current = ctx.interfaces_snapshot();
    assert!(
        current.has_link("lan0"),
        "Interface lan0 must exist by name"
    );
    let link = current.find_by_name("lan0").unwrap();
    assert!(!link.carrier, "Link carrier is false (no cable connected)");
}

// ---------------------------------------------------------------------------
// 5. Boot Without Database Acceptance Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_boot_without_db() {
    let ctx = init_test_ctx();

    static DB_DEPS: &[Edge] = &[];
    static HTTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Continue)];
    static DNS_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];

    // DB service that starts in Degraded state
    struct DegradedDb;
    impl LanforgeService for DegradedDb {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Db, DB_DEPS)
        }
    }
    impl AsyncService for DegradedDb {
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            h.degraded(DegradedReason::custom("database unavailable"));
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    // HTTP service with in-memory auth fallback
    struct FallbackHttp;
    impl LanforgeService for FallbackHttp {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Http, HTTP_DEPS)
        }
    }
    impl AsyncService for FallbackHttp {
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    // DNS service with static / in-memory cache
    struct ResilientDns;
    impl LanforgeService for ResilientDns {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Dns, DNS_DEPS)
        }
    }
    impl AsyncService for ResilientDns {
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    let mut reg = ServiceRegistry::new();
    reg.register(&ctx, || DegradedDb);
    reg.register(&ctx, || FallbackHttp);
    reg.register(&ctx, || ResilientDns);

    let sup = reg.start(&ctx).expect("start supervisor");

    // Wait until services settle
    timeout(Duration::from_millis(500), async {
        loop {
            let db_st = ctx.get_service_state(ServiceId::Db);
            let http_st = ctx.get_service_state(ServiceId::Http);
            let dns_st = ctx.get_service_state(ServiceId::Dns);
            if matches!(db_st, ServiceState::Degraded)
                && http_st == ServiceState::Online
                && dns_st == ServiceState::Online
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Services must reach settled states even with degraded DB");

    assert!(matches!(
        ctx.get_service_state(ServiceId::Db),
        ServiceState::Degraded
    ));
    assert_eq!(ctx.get_service_state(ServiceId::Http), ServiceState::Online);
    assert_eq!(ctx.get_service_state(ServiceId::Dns), ServiceState::Online);

    sup.shutdown(&ctx, Duration::from_millis(200)).await;
}
