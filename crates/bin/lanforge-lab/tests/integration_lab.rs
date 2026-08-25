use lanforge_lab::harness::{LabHarness, LabMode};
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
