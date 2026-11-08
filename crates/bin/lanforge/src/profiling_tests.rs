use std::error::Error;
use std::fs;
use std::sync::Arc;

use hotpath::{Format, HotpathGuardBuilder};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::DeviceUpdate;
use serde_json::Value;

#[test]
fn daemon_allocator_records_core_updates() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("report.json");
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let guard = HotpathGuardBuilder::new("core_regression")
        .format(Format::Json)
        .output_path(&path)
        .functions_limit(0)
        .build();
    let mac = MacAddr([2, 0, 0, 0, 0, 1]);
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "profiled-host".to_string(),
    });
    assert!(ctx.get_by_hostname("profiled-host").is_some());
    drop(guard);
    let report: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let timing = report["functions_timing"]["data"]
        .as_array()
        .ok_or("missing timing collection")?;
    assert!(timing.iter().any(|row| {
        row["name"]
            .as_str()
            .is_some_and(|name| name.contains("apply_with_events"))
            && row["calls"].as_u64().is_some_and(|calls| calls > 0)
    }));
    #[cfg(feature = "hotpath-alloc")]
    {
        let alloc = report["functions_alloc"]["data"]
            .as_array()
            .ok_or("missing allocation collection")?;
        assert!(
            alloc.iter().any(|row| row["total"]
                .as_str()
                .is_some_and(|total| total.chars().any(|c| ('1'..='9').contains(&c)))),
            "allocator must record non-zero bytes"
        );
    }
    Ok(())
}
