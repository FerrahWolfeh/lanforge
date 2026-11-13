//! Services report their state only through their handle, and the supervisor owns the
//! transitions around it (condition dormancy, exit): run the real services under the real
//! supervisor and read the state the CLI/WebUI see.

use std::sync::Arc;
use std::time::Duration;

use crate::registry::ServiceRegistry;
use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, LanforgeService, RestartPolicy, RuntimeClass, ServiceCommand,
    ServiceHandle, ServiceSpec,
};
use lanforge_nft::{NftService, RecordingNft};
use lanforge_types::network::firewall::{FirewallConfig, FirewallMode};
use lanforge_types::system::{DormantReason, ServiceId, ServiceState, StateDetail};
use tokio::time::{sleep, timeout};

/// Stands in for a synthetic node the firewall depends on (interfaces, wan).
struct Node(ServiceId);

impl LanforgeService for Node {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: self.0,
            display_name: self.0.as_str(),
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_millis(5),
                max_backoff: Duration::from_millis(20),
                max_retries: 3,
                healthy_uptime: Duration::from_millis(50),
            },
            shutdown_timeout: Duration::from_millis(100),
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }
}

impl AsyncService for Node {
    async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        h.ready();
        loop {
            if matches!(
                h.next_command().await,
                ServiceCommand::Stop | ServiceCommand::Shutdown
            ) {
                return Ok(());
            }
        }
    }
}

async fn wait_status(
    ctx: &LanforgeContext,
    id: ServiceId,
    state: ServiceState,
    detail: Option<StateDetail>,
) {
    timeout(Duration::from_secs(2), async {
        while ctx.get_service_state(id) != state || ctx.get_service_detail(id) != detail {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{id}: expected {state:?}/{detail:?}, got {:?}/{:?}",
            ctx.get_service_state(id),
            ctx.get_service_detail(id)
        )
    });
}

/// `mode = "disabled"` switches the firewall off like `enabled = false`: the supervisor stops it
/// as dormant and the table goes; `mode = "full"` starts it again. It used to keep running with
/// `Inactive` written into the context while its node said `Online`.
#[tokio::test]
async fn firewall_mode_disabled_is_dormant() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.set_target_interface_name("lan0".to_string());
    let full = FirewallConfig {
        enabled: true,
        mode: FirewallMode::Full,
        ..FirewallConfig::default()
    };
    ctx.apply_config(ConfigPatch::new().with_firewall(full.clone()));

    let kernel = RecordingNft::default();
    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, || Node(ServiceId::Interfaces));
    registry.register(&ctx, || Node(ServiceId::Wan));
    let applier = kernel.clone();
    registry.register(&ctx, move || NftService::with_applier(applier.clone()));
    let supervisor = registry.start(&ctx).expect("start supervisor");
    wait_status(&ctx, ServiceId::Nft, ServiceState::Online, None).await;
    assert!(kernel.payload().is_some(), "the ruleset is applied");

    ctx.apply_config(ConfigPatch::new().with_firewall(FirewallConfig {
        mode: FirewallMode::Disabled,
        ..full.clone()
    }));
    wait_status(
        &ctx,
        ServiceId::Nft,
        ServiceState::Inactive,
        Some(StateDetail::Dormant(DormantReason::disabled(
            "firewall.mode",
        ))),
    )
    .await;
    assert!(
        kernel.payload().is_none(),
        "a disabled firewall leaves no table"
    );

    ctx.apply_config(ConfigPatch::new().with_firewall(full));
    wait_status(&ctx, ServiceId::Nft, ServiceState::Online, None).await;
    assert!(kernel.payload().is_some(), "the ruleset is back");

    supervisor.shutdown(&ctx, Duration::from_millis(500)).await;
}
