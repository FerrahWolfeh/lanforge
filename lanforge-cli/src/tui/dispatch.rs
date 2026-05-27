use crate::cli::LanforgeClient;
use crate::tui::action::{ActionResult, PendingAction};

/// Executes the given `PendingAction` using the `LanforgeClient` and returns an `ActionResult`.
pub async fn execute_action(
    client: &LanforgeClient,
    action: PendingAction,
) -> ActionResult {
    match action {
        PendingAction::Scan => match client.scan().await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::Reload => match client.reload().await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::Shutdown => match client.shutdown().await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::DnsCacheFlush => match client.dns_cache_flush().await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::Wol { mac, .. } => match client.wol(mac.to_string()).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::Purge { mac, .. } => match client.purge(mac).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::AdblockToggle { enable } => match client.dns_adblock_set(enable, None).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::AdblockTimedDisable { duration_secs } => {
            match client.dns_adblock_set(false, Some(duration_secs)).await {
                Ok(r) => ActionResult::Success(r.message),
                Err(e) => ActionResult::Error(e.to_string()),
            }
        }
        PendingAction::AdblockReload => match client.dns_adblock_reload().await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::AdblockAllow { domain } => match client.dns_allow(domain).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::AdblockUnallow { domain } => match client.dns_unallow(domain).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::AdblockBlock { domain } => match client.dns_block(domain).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::LeaseRenew { mac, .. } => match client.lease_renew(mac, None).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
        PendingAction::LeaseRelease { mac, .. } => match client.lease_release(mac, None).await {
            Ok(r) => ActionResult::Success(r.message),
            Err(e) => ActionResult::Error(e.to_string()),
        },
    }
}
