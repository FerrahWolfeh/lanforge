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

fn static_host(mac: &str, name: &str) -> lanforge_types::device::StaticHost {
    lanforge_types::device::StaticHost {
        mac: lanforge_types::identifiers::MacAddr::parse(mac).unwrap(),
        hostname: name.into(),
        v4: None,
        v6: None,
        boot_file: None,
    }
}

/// A host taken out of `[hosts]` offline becomes a discovered device on reload; the others
/// stay reserved.
#[tokio::test]
async fn reload_demotes_a_host_taken_out_of_the_file() {
    let (client, _dir, _) =
        with_file("[hosts.archie]\nmac = \"bc:fc:e7:8a:a9:73\"\nv4 = \"192.168.0.2\"\n");
    let solarium = static_host("04:d9:f5:0a:25:94", "solarium");
    let _ = client
        .ctx
        .apply_static_hosts(&[static_host("bc:fc:e7:8a:a9:73", "archie"), solarium.clone()]);
    reload(&client).await;
    let hosts = client.ctx.static_hosts();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].v4, Some("192.168.0.2".parse().unwrap()));
    let dev = client
        .ctx
        .get_device(&solarium.mac)
        .expect("the device stays");
    assert_eq!(dev.origin, lanforge_types::device::Origin::Dynamic);
}

/// An unreadable `[hosts]` keeps every static host as it is (its default, no hosts, would
/// demote them all) and is reported.
#[tokio::test]
async fn an_unreadable_hosts_section_keeps_the_static_hosts() {
    let (client, _dir, _) = with_file("[hosts.archie]\nmac = 7\n");
    let hosts = vec![static_host("bc:fc:e7:8a:a9:73", "archie")];
    let _ = client.ctx.apply_static_hosts(&hosts);
    reload(&client).await;
    assert_eq!(client.ctx.static_hosts(), hosts);
    assert!(client.ctx.config_issues()[0].starts_with("[hosts]"));
}

/// An offline `[dns]` edit applies on reload, a wrong answer is left out and reported, and the
/// file is not rewritten.
#[tokio::test]
async fn reload_applies_a_dns_edit_and_leaves_out_a_wrong_answer() {
    use lanforge_types::network::dns::upstream::UpstreamMode;

    let text = "[dns]\nupstream_mode = \"parallel\"\n\n[dns.upstreams.default]\n\
                addresses = [\"udp://9.9.9.9:53\"]\n\n[dns.reverse]\n\
                \"10.8.0.0/24\" = \"udp://10.8.0.1:53\"\n\n[dns.rewrites]\n\
                \"nas.lan\" = \"192.0.2.10\"\n\"bad.lan\" = \"pixie\"\n";
    let (client, _dir, path) = with_file(text);
    reload(&client).await;

    let ctx = &client.ctx;
    assert_eq!(ctx.get_dns_upstream_mode(), UpstreamMode::Parallel);
    assert_eq!(
        ctx.get_dns_upstreams(),
        vec!["udp://9.9.9.9:53".parse().unwrap()]
    );
    assert_eq!(ctx.all_reverse_resolvers().len(), 1);
    let rewrites = ctx.get_dns_rewrites();
    assert_eq!(rewrites.len(), 1, "{rewrites:?}");
    assert_eq!(rewrites[0].domain, "nas.lan");
    let issues = ctx.config_issues();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(issues[0].contains("\"bad.lan\""), "{issues:?}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        text,
        "file untouched"
    );
}

/// `[dns] listen` and `enabled` apply on reload only when they changed (the DNS service alone
/// restarts or goes dormant); `DoT`/`DoQ`, not in `[dns]`, stay as they run.
#[tokio::test]
async fn reload_applies_the_dns_listener_only_when_it_changed() {
    use lanforge_types::config::DnsListenConfig;
    use std::time::Duration;

    let (client, _dir, path) = with_file(
        "[dns]
listen = \"127.0.0.1:5353\"\n",
    );
    let ctx = &client.ctx;
    let dot: std::net::SocketAddr = "[::]:853".parse().unwrap();
    ctx.update_dns_listen(DnsListenConfig {
        dot_listen: Some(dot),
        dot_enabled: true,
        ..DnsListenConfig::default()
    });
    reload(&client).await;
    let live = ctx.get_dns_listen();
    assert_eq!(live.listen.to_string(), "127.0.0.1:5353");
    assert!(live.enabled);
    assert_eq!(live.dot_listen, Some(dot), "DoT is not in [dns]: kept");

    // Unchanged: the listener is not touched (no DNS restart).
    let mut sub = ctx.config_subscription::<DnsListenConfig>();
    reload(&client).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sub.next())
            .await
            .is_err(),
        "an unchanged listener must not restart DNS"
    );

    std::fs::write(
        &path,
        "[dns]\nenabled = false\nlisten = \"127.0.0.1:5353\"\n",
    )
    .unwrap();
    reload(&client).await;
    assert!(!ctx.get_dns_listen().enabled, "disabled by the file");
}

/// A `[dns]` that does not fit its type is set aside: the running DNS keeps working.
#[tokio::test]
async fn an_unreadable_dns_section_keeps_the_running_dns() {
    let (client, _dir, _) = with_file("[dns]\nupstreams = 7\n");
    let running: Vec<lanforge_types::network::dns::upstream::UpstreamTarget> =
        vec!["udp://1.1.1.1:53".parse().unwrap()];
    client.ctx.update_dns_upstreams(running.clone());
    reload(&client).await;
    assert_eq!(client.ctx.get_dns_upstreams(), running);
    assert!(client.ctx.config_issues()[0].starts_with("[dns]"));
}

/// `[adblock]` and its rules file apply on reload; a rules file that cannot be read keeps the
/// rules that run (an unread file is not an empty one).
#[cfg(feature = "adblock")]
#[tokio::test]
async fn reload_applies_adblock_and_keeps_rules_it_cannot_read() {
    let file = "[adblock]\nenabled = true\nlists = [\"l\"]\nrules = \"adblock/global.rules\"\n\n\
                [adblock.sources.l]\nurl = \"https://example.com/l\"\n";
    let (client, dir, _path) = with_file(file);
    std::fs::create_dir(dir.path().join("adblock")).unwrap();
    std::fs::write(
        dir.path().join("adblock/global.rules"),
        "@@||bank.example^\n",
    )
    .unwrap();

    reload(&client).await;
    assert!(client.ctx.get_dns_adblock().enabled);
    let urls = client.ctx.get_dns_adblock_urls();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].url, "https://example.com/l");
    assert_eq!(client.ctx.get_dns_adblock_rules(), "@@||bank.example^\n");

    std::fs::remove_file(dir.path().join("adblock/global.rules")).unwrap();
    std::fs::create_dir(dir.path().join("adblock/global.rules")).unwrap();
    let _ = client.handle_reload().await;
    assert_eq!(
        client.ctx.get_dns_adblock_rules(),
        "@@||bank.example^\n",
        "an unreadable rules file must not drop the rules"
    );
    assert!(
        client
            .ctx
            .config_issues()
            .iter()
            .any(|i| i.contains("cannot be read")),
        "{:?}",
        client.ctx.config_issues()
    );
}

/// `[system] search_domains` edited offline reaches the live site domains on reload (DNS reads
/// them in place); the site rule appends `lan`.
#[tokio::test]
async fn reload_applies_the_site_search_domains() {
    let (client, _dir, _) = with_file("[system]\nsearch_domains = [\"home.arpa\"]\n");
    reload(&client).await;
    assert_eq!(client.ctx.get_site_domains().0, ["home.arpa", "lan"]);
}
