//! `lanforge reload`: re-reads the config file and applies the file-owned sections that changed.
//!
//! Sections migrated to "files are config" (`phase-7-config-storage`) have no other source, so
//! an offline edit takes effect here without a daemon restart. An unreadable or invalid file
//! applies nothing: the running configuration stays as it is.

use lanforge_api::config_file::ConfigFile;
use lanforge_core::context::LanforgeContext;
use tracing::{info, warn};

/// Re-reads the config file and applies the file-owned sections that differ from the live ones.
pub fn reload_file_sections(ctx: &LanforgeContext) {
    let Some(path) = ctx.config_path() else {
        return;
    };
    let file = match std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|text| ConfigFile::parse(&text).map_err(|e| e.to_string()))
    {
        Ok(file) => file,
        Err(e) => {
            warn!(
                "Reload: '{}' cannot be read or parsed ({e}); nothing applied",
                path.display()
            );
            return;
        }
    };

    #[cfg(feature = "pppoe")]
    if ctx.get_pppoe_config().as_ref() != Some(&file.pppoe) {
        info!("Reload: [pppoe] changed in '{}'; applying", path.display());
        ctx.update_pppoe_config(file.pppoe);
    }
    #[cfg(feature = "traffic")]
    if ctx.get_traffic_config().as_ref() != Some(&file.traffic) {
        info!(
            "Reload: [traffic] changed in '{}'; applying",
            path.display()
        );
        ctx.update_traffic_config(file.traffic);
    }
    #[cfg(not(any(feature = "pppoe", feature = "traffic")))]
    let _ = file;
}

#[cfg(all(test, feature = "pppoe"))]
mod tests {
    use std::sync::Arc;

    use lanforge_core::bus::EventBus;
    use lanforge_core::context::state::State;

    use super::*;

    #[test]
    fn reload_applies_an_offline_pppoe_edit() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "[pppoe]\nenabled = true\nusername = \"new-user\"\n\n[pppoe.nftables]\nbypass_dns = false\n",
        )
        .unwrap();
        ctx.set_config_path(&path);

        reload_file_sections(&ctx);

        let live = ctx.get_pppoe_config().expect("applied");
        assert_eq!(live.username, "new-user");
        assert!(!live.nftables.bypass_dns, "nested fields are applied too");
    }

    #[cfg(feature = "traffic")]
    #[test]
    fn reload_applies_an_offline_traffic_edit() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "[traffic.sqm]\nenabled = true\ndownload_mbps = 700\nrtt_ms = 30\n",
        )
        .unwrap();
        ctx.set_config_path(&path);

        reload_file_sections(&ctx);

        let live = ctx.get_traffic_config().expect("applied");
        assert!(live.sqm.enabled);
        assert_eq!(live.sqm.download_mbps, 700);
        assert_eq!(live.sqm.rtt_ms, Some(30));
    }

    #[test]
    fn invalid_file_applies_nothing() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(&path, "[pppoe\nusername = \"x\"\n").unwrap();
        ctx.set_config_path(&path);
        let before = ctx.get_pppoe_config();

        reload_file_sections(&ctx);

        assert_eq!(ctx.get_pppoe_config(), before);
    }
}
