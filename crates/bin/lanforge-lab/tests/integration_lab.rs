use std::sync::Arc;

use lanforge_lab::cli::args::{ModeArg, ScenarioArg};
use lanforge_lab::error::LabError;
use lanforge_lab::harness::{LabHarness, LabMode};
use lanforge_lab::netns::NetnsConfig;
use lanforge_lab::tui::app::{App, LabAction};
use lanforge_types::identifiers::MacAddr;

#[tokio::test]
async fn test_harness_direct_mode_initialization() {
    let harness = LabHarness::setup_direct().expect("Direct mode setup must succeed without root");
    assert_eq!(harness.mode(), LabMode::Direct);
}

#[tokio::test]
async fn test_harness_report_serialization() {
    let harness = LabHarness::setup_direct().unwrap();

    let mac = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let dhcp_eng = harness.dhcp();

    // Even if no server is listening, simulate_dora handles timeout cleanly without crashing
    let dora = dhcp_eng.simulate_dora(mac, Some("test-box")).await.unwrap();
    assert!(!dora.success); // No server listening on port 1067 in this unit test

    // Ensure JSON serialization works
    let json_str = serde_json::to_string_pretty(&dora).unwrap();
    assert!(json_str.contains("02:11:22:33:44:55"));
}

#[test]
fn test_root_flag_methods() {
    assert!(ModeArg::Netns.requires_root());
    assert!(!ModeArg::Direct.requires_root());
    assert!(!ModeArg::Auto.requires_root());
    assert!(!ModeArg::Interface.requires_root());

    assert!(ScenarioArg::Ra.requires_root());
    assert!(ScenarioArg::PppoeFlap.requires_root());
    assert!(!ScenarioArg::Dhcp.requires_root());
    assert!(!ScenarioArg::Dns.requires_root());
    assert!(!ScenarioArg::Discovery.requires_root());
    assert!(!ScenarioArg::Vlan.requires_root());

    assert!(LabAction::Ipv6Ra.requires_root());
    assert!(!LabAction::DhcpDora.requires_root());
    assert!(!LabAction::DnsQuery.requires_root());
    assert!(!LabAction::DiscoveryPing.requires_root());
    assert!(!LabAction::DhcpStorm.requires_root());
    assert!(!LabAction::DnsFlood.requires_root());
    assert!(!LabAction::RunSuite.requires_root());
}

#[tokio::test]
async fn test_unprivileged_execution_guards() {
    if !lanforge_lab::is_root() {
        let netns_res = LabHarness::setup_netns(NetnsConfig::default());
        assert!(matches!(netns_res, Err(LabError::RootRequired(_))));

        let harness = LabHarness::setup_direct().unwrap();
        let ra_res = harness.ra().send_rs_and_await_ra().await;
        assert!(matches!(ra_res, Err(LabError::RootRequired(_))));
    }
}

#[tokio::test]
async fn test_tui_root_action_guard() {
    let harness = Arc::new(LabHarness::setup_direct().unwrap());
    let mut app = App::new(
        harness.dhcp_target,
        harness.dns_target,
        "Direct".to_string(),
    );
    app.is_root = false;

    // Triggering root-only action when unprivileged should be blocked
    app.trigger_action(LabAction::Ipv6Ra, harness);

    assert!(app.status_message.contains("requires root"));
    let logs = app.logs.lock();
    assert!(
        logs.iter()
            .any(|l| l.contains("[GUARD]") && l.contains("requires root privileges"))
    );
}
