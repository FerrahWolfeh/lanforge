//! `lanforge reload` (`handle_reload`): the file-owned sections apply as the boot applies them.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use lanforge_api::api::Response;
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::network::firewall::{FirewallConfig, L4Protocol, PortForwardRule};
use lanforge_types::network::pppoe::PppoeConfig;

/// A client with in-memory storage whose config file holds `text`.
fn with_file(text: &str) -> (ClientContext, tempfile::TempDir, std::path::PathBuf) {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            config_path: "memory".to_string(),
            ..Default::default()
        })
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open_in_memory());
    let mut worker =
        lanforge_db::worker::DbWorker::new(DatabaseConfig::default(), ctx.clone(), db, log_db);
    let ctx_worker = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(lanforge_types::system::ServiceId::Db, ctx_worker.clone());
        let _ = worker.serve(&ctx_worker, &h).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, text).unwrap();
    ctx.set_config_path(&path);
    ctx.set_config_writable(true);
    let client = ClientContext {
        current_gua: None,
        uptime_secs: 100,
        ctx,
        active_clients: Arc::new(AtomicUsize::new(1)),
    };
    (client, dir, path)
}

async fn reload(client: &ClientContext) {
    // The storage worker starts on the runtime.
    while client.ctx.storage_handle().is_none() {
        tokio::task::yield_now().await;
    }
    let res = client.handle_reload().await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
}

#[tokio::test]
async fn reload_applies_an_offline_pppoe_edit() {
    let (client, _dir, _) = with_file(
        "[pppoe]\nenabled = true\nusername = \"new-user\"\n\n[pppoe.nftables]\nbypass_dns = false\n",
    );
    reload(&client).await;
    let live = client.ctx.get_pppoe_config().expect("applied");
    assert_eq!(live.username, "new-user");
    assert!(!live.nftables.bypass_dns, "nested fields are applied too");
}

#[tokio::test]
async fn reload_applies_an_offline_traffic_edit() {
    let (client, _dir, _) =
        with_file("[traffic.sqm]\nenabled = true\ndownload_mbps = 700\nrtt_ms = 30\n");
    reload(&client).await;
    let live = client.ctx.get_traffic_config().expect("applied");
    assert!(live.sqm.enabled);
    assert_eq!(live.sqm.download_mbps, 700);
    assert_eq!(live.sqm.rtt_ms, Some(30));
}

/// An offline `[dhcp]` edit applies; a pool with a wrong range is left out (no address leased
/// from it) and reported, the rest applies.
#[tokio::test]
async fn reload_applies_a_dhcp_edit_and_leaves_out_a_wrong_pool() {
    let (client, _dir, _) = with_file(
        "[dhcp.v4]\nlease = \"12h\"\nntp = []\n\n\
         [dhcp.v4.pools.lan]\nrange = \"192.168.1.100-192.168.1.200\"\n\n\
         [dhcp.v4.pools.typo]\nrange = \"192.168.1.10-192.168.1.300\"\n\n\
         [tftp]\nenabled = true\nblock_size = 1468\n",
    );
    reload(&client).await;
    let options = client.ctx.get_dhcp_options();
    assert_eq!(options.v4.lease_time, 43200);
    assert!(
        options.v4.ntp_servers.is_empty(),
        "ntp = [] advertises none"
    );
    assert!(options.tftp.enabled);
    assert_eq!(options.tftp.block_size, 1468);
    let pools = client.ctx.get_dhcp_v4_pools();
    assert_eq!(pools.len(), 1);
    assert_eq!(pools[0].name.as_deref(), Some("lan"));
    let issues = client.ctx.config_issues();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(issues[0].contains("typo"), "{issues:?}");
}

/// A broken `[pppoe]` leaves the running `PPPoE` alone (its default would disable it) and is
/// reported; the valid sections still apply.
#[tokio::test]
async fn broken_section_on_reload_keeps_running_config_and_is_reported() {
    let (client, _dir, _) = with_file("[pppoe]\nmru = \"big\"\n\n[traffic.sqm]\nenabled = true\n");
    let running = PppoeConfig {
        enabled: true,
        username: "working".into(),
        ..Default::default()
    };
    client.ctx.update_pppoe_config(running.clone());
    reload(&client).await;
    assert_eq!(client.ctx.get_pppoe_config(), Some(running));
    assert!(
        client
            .ctx
            .get_traffic_config()
            .is_some_and(|t| t.sqm.enabled)
    );
    let issues = client.ctx.config_issues();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(issues[0].starts_with("[pppoe]"), "{issues:?}");
}

/// An offline `[firewall]` edit applies; a wrong entry is left out (nothing opened for it) and
/// reported, the rest applies.
#[tokio::test]
async fn reload_applies_a_firewall_edit_and_leaves_out_a_wrong_entry() {
    let (client, _dir, _) = with_file(
        "[firewall.port_forwards.game]\nproto = \"udp\"\nport = 7777\nto = \"192.0.2.7\"\n\n\
         [firewall.port_forwards.typo]\nport = 445\nto = \"192.0.2.300\"\n",
    );
    client.ctx.update_firewall_config(FirewallConfig::default());
    reload(&client).await;
    let fw = client.ctx.get_firewall_config().unwrap();
    assert_eq!(fw.port_forwards.len(), 1);
    assert_eq!(fw.port_forwards[0].external_port, 7777);
    let issues = client.ctx.config_issues();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(issues[0].contains("typo"), "{issues:?}");
}

/// The firewall reloads as the boot runs it: with SQM on, flowtable offload stays off (CAKE
/// must see every packet) and the LAN interface joins `internal`, though the file says
/// otherwise; the file itself is not rewritten.
#[tokio::test]
async fn reload_runs_the_effective_firewall_and_leaves_the_file_alone() {
    let text = "# mine\n[traffic.sqm]\nenabled = true # keep\n\n\
                [firewall]\nflow_offload = true # mine too\n";
    let (client, _dir, path) = with_file(text);
    client.ctx.set_target_interface_name("lan0".into());
    reload(&client).await;
    let fw = client.ctx.get_firewall_config().unwrap();
    assert!(!fw.flow_offload, "offload off under SQM");
    let internal = fw.zones.iter().find(|z| z.name == "internal").unwrap();
    assert!(internal.interfaces.iter().any(|i| i == "lan0"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
}

/// A `[firewall]` that does not parse keeps the running firewall (its default would drop
/// every port forward) and is reported.
#[tokio::test]
async fn unreadable_firewall_section_keeps_the_running_firewall() {
    let (client, _dir, _) = with_file("[firewall]\nenabled = \"yes\"\n");
    let mut running = FirewallConfig::default();
    running.port_forwards.push(PortForwardRule {
        comment: Some("kept".into()),
        src_zone: "external".into(),
        internal_ip: "192.0.2.9".parse().unwrap(),
        external_port: 9999,
        internal_port: 9999,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
    });
    client.ctx.update_firewall_config(running.clone());
    reload(&client).await;
    assert_eq!(client.ctx.get_firewall_config(), Some(running));
    assert!(client.ctx.config_issues()[0].starts_with("[firewall]"));
}

#[tokio::test]
async fn invalid_file_applies_nothing() {
    let (client, _dir, _) = with_file("[pppoe\nusername = \"x\"\n");
    let before = client.ctx.get_pppoe_config();
    let res = client.handle_reload().await;
    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(client.ctx.get_pppoe_config(), before);
}

/// An offline `[ra]` edit applies with what the daemon derives (interface, DNSSL from the
/// search domains); a prefix that cannot be read is left out and reported.
#[tokio::test]
async fn reload_applies_an_ra_edit_and_leaves_out_a_wrong_prefix() {
    let (client, _dir, _) = with_file(
        "[ra]\nmtu = 1492\n\n[ra.prefixes.ula]\nprefix = \"fd00:1::/64\"\n\
         valid_lifetime = \"infinity\"\n\n[ra.prefixes.typo]\nprefix = \"fd00:zz::/64\"\n",
    );
    client.ctx.set_target_interface_name("lan0".into());
    reload(&client).await;
    let ra = client.ctx.get_ra_server_config();
    assert_eq!(ra.mtu, Some(1492));
    assert_eq!(ra.iface.as_deref(), Some("lan0"));
    assert_eq!(ra.prefixes.len(), 1);
    assert_eq!(
        ra.prefixes[0].valid_lifetime,
        lanforge_types::network::ra::PrefixLifetime::Infinity
    );
    assert_eq!(ra.dnssl[0].domains, vec!["lan".to_string()], "derived");
    let issues = client.ctx.config_issues();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(issues[0].contains("typo"), "{issues:?}");
}

/// Reloading an unchanged file keeps what the daemon derived (here the DNSSL): the lists are
/// not imported raw over the live ones.
#[tokio::test]
async fn an_unchanged_ra_reload_keeps_the_derived_lists() {
    let (client, _dir, _) = with_file(
        "[system]\nsearch_domains = [\"home.arpa\"]\n\n[ra.prefixes.gua]\nsource = \"auto_gua\"\n",
    );
    reload(&client).await;
    let first = client.ctx.get_ra_server_config();
    assert_eq!(first.dnssl[0].domains, ["home.arpa", "lan"]);
    reload(&client).await;
    assert_eq!(client.ctx.get_ra_server_config(), first);
}
