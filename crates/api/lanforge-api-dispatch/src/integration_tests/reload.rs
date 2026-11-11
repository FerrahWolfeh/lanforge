//! `lanforge reload` (`handle_reload`): the file-owned sections apply as the boot applies them.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::timeout;

use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_db::worker::DbWorker;
use lanforge_types::device::{Origin, StaticHost};
use lanforge_types::identifiers::{DeviceIdentifier, MacAddr};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::firewall::{FirewallConfig, L4Protocol, PortForwardRule};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::PrefixLifetime;
use lanforge_types::system::ServiceId;
use tempfile::TempDir;

/// A client with in-memory storage whose config file holds `text`.
fn with_file(text: &str) -> (ClientContext, TempDir, PathBuf) {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            config_path: "memory".to_string(),
            ..Default::default()
        })
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open_in_memory());
    let mut worker = DbWorker::new(DatabaseConfig::default(), ctx.clone(), db, log_db);
    let ctx_worker = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Db, ctx_worker.clone());
        let _ = worker.serve(&ctx_worker, &h).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, text).unwrap();
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
        yield_now().await;
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

/// A hand-edited `[pppoe]` value the client cannot run on (MRU 0, no PADI) does not reach it:
/// it is reported and replaced by the default; the other keys apply, and echo 0 (off) stays.
#[tokio::test]
async fn reload_replaces_pppoe_values_the_client_cannot_run_on() {
    let (client, _dir, _) = with_file(
        "[pppoe]\nenabled = true\nusername = \"u\"\nmru = 0\ndiscovery_padi_retries = 0\nlcp_echo_interval_secs = 0\n",
    );
    reload(&client).await;
    let live = client.ctx.get_pppoe_config().expect("applied");
    let default = PppoeConfig::default();
    assert_eq!(live.username, "u");
    assert_eq!(live.mru, default.mru);
    assert_eq!(live.discovery_padi_retries, default.discovery_padi_retries);
    assert_eq!(live.lcp_echo_interval_secs, 0, "0 turns the echo off");
    let issues = client.ctx.config_issues();
    assert_eq!(issues.len(), 2, "{issues:?}");
    assert!(
        issues.iter().all(|i| i.starts_with("[pppoe]")),
        "{issues:?}"
    );
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

/// `[firewall]` asks for offload while SQM is on: the daemon runs without it (CAKE must see
/// every packet) and with the LAN interface in `internal`, while the config it serves and the
/// file keep what the admin wrote — so switching SQM off brings the offload back. The status
/// reports the offload as suspended, not disabled.
#[tokio::test]
async fn reload_keeps_the_admins_firewall_and_runs_the_effective_one() {
    let text = "# mine\n[traffic.sqm]\nenabled = true # keep\n\n\
                [firewall]\nflow_offload = true # mine too\n";
    let (client, _dir, path) = with_file(text);
    client.ctx.set_target_interface_name("lan0".into());
    reload(&client).await;

    let configured = client.ctx.get_firewall_config().unwrap();
    assert!(configured.flow_offload, "the admin's setting is kept");
    let Response::FirewallConfig(served) = client.handle_firewall_config().await else {
        panic!("firewall config");
    };
    assert!(served.flow_offload, "the WebUI edits what the file says");

    let running = client.ctx.running_firewall_config();
    assert!(!running.flow_offload, "offload off under SQM");
    let internal = running.zones.iter().find(|z| z.name == "internal").unwrap();
    assert!(internal.interfaces.iter().any(|i| i == "lan0"));

    let Response::FirewallStatus(status) = client.handle_firewall_status().await else {
        panic!("firewall status");
    };
    assert!(status.flow_offload_suspended, "suspended by SQM");
    assert!(!status.flow_offload_active);
    assert_eq!(fs::read_to_string(&path).unwrap(), text);
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
        family: None,
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
    assert_eq!(ra.prefixes[0].valid_lifetime, PrefixLifetime::Infinity);
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

fn static_host(mac: &str, name: &str) -> StaticHost {
    StaticHost {
        mac: MacAddr::parse(mac).unwrap(),
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
    assert_eq!(dev.origin, Origin::Dynamic);
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
    assert_eq!(fs::read_to_string(&path).unwrap(), text, "file untouched");
}

/// `[dns]`'s listeners (plain, `DoT`, `DoQ`), cache and `enabled` apply on reload only when
/// they changed (the DNS service alone restarts or goes dormant). The file is their source: a
/// `DoT` listener the file does not name is off.
#[tokio::test]
async fn reload_applies_the_dns_listener_only_when_it_changed() {
    use lanforge_types::config::DnsListenConfig;
    use std::time::Duration;

    let (client, _dir, path) = with_file(
        "[dns]\nlisten = \"127.0.0.1:5353\"\ndot_listen = \"[::]:853\"\n\
         cache_size = 20000\ncache_min_ttl = \"1m\"\n",
    );
    let ctx = &client.ctx;
    // The TLS identity is `[system]`'s: a reload of `[dns]` keeps it.
    ctx.update_dns_listen(DnsListenConfig {
        tls_cert: Some("/etc/lanforge/cert.pem".into()),
        ..DnsListenConfig::default()
    });
    reload(&client).await;
    let live = ctx.get_dns_listen();
    assert_eq!(live.listen.to_string(), "127.0.0.1:5353");
    assert!(live.enabled);
    assert_eq!(live.dot_listen, Some("[::]:853".parse().unwrap()));
    assert!(live.dot_enabled);
    assert!(live.doq_listen.is_none() && !live.doq_enabled);
    assert_eq!((live.cache_size, live.cache_min_ttl), (20_000, 60));
    assert_eq!(live.tls_cert.as_deref(), Some("/etc/lanforge/cert.pem"));

    // Unchanged: the listener is not touched (no DNS restart).
    let mut sub = ctx.config_subscription::<DnsListenConfig>();
    reload(&client).await;
    assert!(
        timeout(Duration::from_millis(50), sub.next())
            .await
            .is_err(),
        "an unchanged listener must not restart DNS"
    );

    fs::write(
        &path,
        "[dns]\nenabled = false\nlisten = \"127.0.0.1:5353\"\n",
    )
    .unwrap();
    reload(&client).await;
    let live = ctx.get_dns_listen();
    assert!(!live.enabled, "disabled by the file");
    assert!(
        live.dot_listen.is_none() && !live.dot_enabled,
        "DoT left the file"
    );
    assert_eq!(live.cache_size, DnsListenConfig::DEFAULT_CACHE_SIZE);
}

/// A `[dns]` change from the API/WebUI (here a rewrite) rewrites the section from the live
/// settings: the listeners and the cache it does not touch stay in the file as written.
#[tokio::test]
async fn a_dns_change_keeps_the_listeners_and_cache_in_the_file() {
    use lanforge_types::network::dns::DnsRecordType;
    use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};

    let (client, _dir, path) = with_file(
        "[dns]\ndot_listen = \"[::]:853\"\ndoq_listen = \"[::]:853\"\ncache_size = 20000\n\
         cache_min_ttl = \"1m\"\n",
    );
    reload(&client).await;
    client
        .change_dns(|dns| {
            dns.rewrites.push(RewriteRule {
                id: None,
                domain: "nas.lan".into(),
                rtype: DnsRecordType::A,
                answer: RewriteAnswer::A("192.0.2.10".parse().unwrap()),
            });
        })
        .expect("dns change");
    let written = fs::read_to_string(&path).unwrap();
    for line in [
        "dot_listen = \"[::]:853\"",
        "doq_listen = \"[::]:853\"",
        "cache_size = 20000",
        "\"nas.lan\"",
    ] {
        assert!(written.contains(line), "{line} missing:\n{written}");
    }
    assert!(written.contains("cache_min_ttl = "), "{written}");
}

/// A `[dns]` that does not fit its type is set aside: the running DNS keeps working.
#[tokio::test]
async fn an_unreadable_dns_section_keeps_the_running_dns() {
    let (client, _dir, _) = with_file("[dns]\nupstreams = 7\n");
    let running: Vec<UpstreamTarget> = vec!["udp://1.1.1.1:53".parse().unwrap()];
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
    fs::create_dir(dir.path().join("adblock")).unwrap();
    fs::write(
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

    fs::remove_file(dir.path().join("adblock/global.rules")).unwrap();
    fs::create_dir(dir.path().join("adblock/global.rules")).unwrap();
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

/// The `WebUI` loads the firewall, edits it and sends it back to be written to the file: the GET
/// must not fill an empty `external` zone with the WAN interface (the ruleset binds the active
/// WAN itself), or `wan0`/`ppp0` lands in the file as if the admin had written it.
#[tokio::test]
async fn firewall_get_serves_an_empty_external_zone_as_written() {
    let text = "[pppoe]\nenabled = true\nwan_iface = \"wan0\"\n\n\
                [firewall.zones.external]\ninput = \"drop\"\n\n\
                [firewall.zones.internal]\ninterfaces = [\"lan0\"]\ninput = \"accept\"\n";
    let (client, _dir, _path) = with_file(text);
    reload(&client).await;
    let Response::FirewallConfig(served) = client.handle_firewall_config().await else {
        panic!("firewall config");
    };
    let external = served.zones.iter().find(|z| z.name == "external").unwrap();
    assert!(external.interfaces.is_empty(), "{:?}", external.interfaces);
}

/// A reload that changes several file-owned sections applies them as one patch: one
/// `ConfigChanged` naming every changed section, so each subscriber wakes once and no service
/// sees half of the new file.
#[tokio::test]
async fn reload_applies_all_changed_sections_as_one_change() {
    use lanforge_core::bus::{LanforgeEvent, SystemEvent};
    use lanforge_types::config::DomainSet;

    let (client, _dir, _) = with_file(concat!(
        "[pppoe]\nenabled = true\nusername = \"new-user\"\n\n",
        "[traffic.sqm]\nenabled = true\ndownload_mbps = 700\n\n",
        "[dns.upstreams.default]\naddresses = [\"udp://9.9.9.9:53\"]\n",
    ));
    let mut sys = client.ctx.bus().subscribe_system();
    reload(&client).await;

    let mut changes = Vec::new();
    while let Ok(Ok(ev)) = timeout(Duration::from_millis(100), sys.recv()).await {
        if let LanforgeEvent::System(SystemEvent::ConfigChanged { sections }) = ev.event {
            changes.push(sections);
        }
    }
    assert_eq!(
        changes.len(),
        1,
        "one change for the whole reload: {changes:?}"
    );
    let want = DomainSet::PPPOE | DomainSet::TRAFFIC | DomainSet::DNS_UPSTREAMS;
    assert!(
        changes[0].contains(want),
        "all sections in it: {:?}",
        changes[0]
    );
}

/// Renaming a static host keeps everything that names it: `dev:<old>` in port forwards, DNS
/// rewrites and adblock groups becomes `dev:<new>`, in the file and in what runs.
#[tokio::test]
async fn renaming_a_host_moves_its_dev_references() {
    use lanforge_types::network::dns::adblock::RewriteAnswer;
    use lanforge_types::network::firewall::ForwardTarget;

    let text = "[hosts.nas]\nmac = \"02:00:00:00:05:01\"\nv4 = \"192.168.0.128\"\n\n\
                [firewall.port_forwards.qbt]\nport = 6881\nto = \"dev:nas\"\n\n\
                [dns.rewrites]\n\"files.lan\" = \"dev:nas\"\n\n\
                [adblock.groups.servers]\nclients = [\"dev:nas\", \"192.168.0.0/28\"]\n";
    let (client, _dir, path) = with_file(text);
    reload(&client).await;
    assert_eq!(client.ctx.static_hosts()[0].hostname, "nas");

    client
        .change_hosts(|hosts| hosts[0].hostname = "storage".to_string())
        .expect("renamed");

    let written = fs::read_to_string(&path).unwrap();
    assert!(!written.contains("dev:nas"), "{written}");
    assert_eq!(written.matches("dev:storage").count(), 3, "{written}");
    assert!(
        written.contains("192.168.0.0/28"),
        "other selectors kept: {written}"
    );

    let storage: DeviceIdentifier = "storage".parse().unwrap();
    let fw = client.ctx.get_firewall_config().expect("firewall");
    assert_eq!(
        fw.port_forwards[0].internal_ip,
        ForwardTarget::Device(storage.clone())
    );
    let rewrites = client.ctx.get_dns_rewrites();
    assert!(matches!(
        &rewrites[0].answer,
        RewriteAnswer::Device { identifier, .. } if *identifier == storage
    ));
    let clients: Vec<String> = client.ctx.get_dns_adblock_policy().groups[0]
        .clients
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(clients, ["dev:storage", "192.168.0.0/28"]);
}

/// The adblock groups and `bypass` run as the file has them after a reload, each group with
/// its own lists and its rules file; a group rules file that cannot be read keeps the group's
/// rules that run. A `WebUI` change to `[adblock]` keeps them running.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn reload_applies_adblock_groups_and_bypass() {
    let file = "[adblock]\nenabled = true\nlists = [\"g\"]\nbypass = [\"dev:notebook\"]\n\n\
                [adblock.sources.g]\nurl = \"https://example.com/g\"\n\n\
                [adblock.sources.k]\nurl = \"https://example.com/k\"\n\n\
                [adblock.groups.bradesco]\nrules = \"adblock/bradesco.rules\"\nclients = [\"dev:pixel-faiko\"]\n\n\
                [adblock.groups.kids]\nlists = [\"k\"]\nclients = [\"192.168.1.64/28\"]\n";
    let (client, dir, _path) = with_file(file);
    fs::create_dir(dir.path().join("adblock")).unwrap();
    fs::write(
        dir.path().join("adblock/bradesco.rules"),
        "@@||app-measurement.com^\n",
    )
    .unwrap();

    reload(&client).await;
    let policy = client.ctx.get_dns_adblock_policy();
    let bypass: Vec<String> = policy.bypass.iter().map(ToString::to_string).collect();
    assert_eq!(bypass, ["dev:notebook"]);
    let [bradesco, kids] = &policy.groups[..] else {
        panic!("two groups: {policy:?}");
    };
    assert_eq!(bradesco.name, "bradesco");
    assert_eq!(bradesco.rules, "@@||app-measurement.com^\n");
    assert_eq!(bradesco.clients[0].to_string(), "dev:pixel-faiko");
    assert!(bradesco.sources.is_empty());
    assert_eq!(kids.sources.len(), 1);
    assert_eq!(kids.sources[0].url, "https://example.com/k");
    // The global layer is still only `lists`.
    let urls = client.ctx.get_dns_adblock_urls();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].url, "https://example.com/g");

    fs::remove_file(dir.path().join("adblock/bradesco.rules")).unwrap();
    fs::create_dir(dir.path().join("adblock/bradesco.rules")).unwrap();
    let _ = client.handle_reload().await;
    assert_eq!(
        client.ctx.get_dns_adblock_policy().groups[0].rules,
        "@@||app-measurement.com^\n",
        "an unreadable group rules file must not drop the group's rules"
    );
    assert!(
        client
            .ctx
            .config_issues()
            .iter()
            .any(|i| i.contains("[adblock.groups.\"bradesco\"] rules")
                && i.contains("cannot be read")),
        "{:?}",
        client.ctx.config_issues()
    );

    client
        .change_adblock(|a| a.config.enabled = false)
        .expect("adblock change");
    assert_eq!(client.ctx.get_dns_adblock_policy().groups.len(), 2);
    assert_eq!(client.ctx.get_dns_adblock_policy().bypass.len(), 1);
}

/// The adblock groups API (the `WebUI`'s): create an empty group, give it rules (its own rules
/// file, named in `[adblock]`) and a list, put a device in it from the device side, move it to
/// `bypass`, delete the group. Everything lands in the files and in what runs.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn adblock_groups_are_managed_through_the_api() {
    use lanforge_api::api::Response;
    use lanforge_types::network::dns::adblock::AdblockUrlKind;
    use lanforge_types::update::DeviceUpdate;
    use std::time::SystemTime;

    let file = "[adblock]\nenabled = true\nlists = [\"g\"]\n\n\
                [adblock.sources.g]\nurl = \"https://example.com/g\"\n";
    let (client, dir, path) = with_file(file);
    reload(&client).await;
    let mac = MacAddr::parse("aa:aa:aa:aa:aa:01").unwrap();
    let _ = client.ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.17".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    let _ = client.ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "galaxy".into(),
    });
    let ok = |res: Response| assert!(matches!(res, Response::Success(_)), "{res:?}");
    let groups = || async {
        let Response::DnsAdblockGroups(g) = client.handle_dns_adblock_groups().await else {
            panic!("groups");
        };
        g
    };

    // Bad names, then an empty group (valid: members come later).
    for bad in ["", "a b", "../x"] {
        let res = client
            .handle_dns_adblock_group_create(bad.into(), Vec::new(), Vec::new())
            .await;
        assert!(matches!(res, Response::Rejected { .. }), "{bad:?}: {res:?}");
    }
    ok(client
        .handle_dns_adblock_group_create("bradesco".into(), Vec::new(), Vec::new())
        .await);
    let res = client
        .handle_dns_adblock_group_create("bradesco".into(), Vec::new(), Vec::new())
        .await;
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(
        client.ctx.get_dns_adblock_policy().groups[0].name,
        "bradesco"
    );

    // A rule of the group: its own file, named in `[adblock]`, running at once.
    ok(client
        .handle_dns_adblock_rule_add(
            "app-measurement.com".into(),
            "allow".into(),
            Some("bradesco".into()),
        )
        .await);
    let rules = fs::read_to_string(dir.path().join("adblock/bradesco.rules")).unwrap();
    assert!(rules.contains("@@||app-measurement.com^"), "{rules}");
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("rules = \"adblock/bradesco.rules\"")
    );
    assert!(
        client.ctx.get_dns_adblock_policy().groups[0]
            .rules
            .contains("@@||app-measurement.com^")
    );
    let Response::DnsAdblockRules(listed) = client
        .handle_dns_adblock_rules(Some("bradesco".into()))
        .await
    else {
        panic!("group rules");
    };
    assert_eq!(listed.rules.len(), 1);
    assert!(
        client.ctx.get_dns_adblock_rules().is_empty(),
        "global untouched"
    );
    let res = client.handle_dns_adblock_rules(Some("nope".into())).await;
    assert!(matches!(res, Response::NotFound { .. }), "{res:?}");

    // The device side: in the group by name, then bypassed instead.
    ok(client
        .handle_dns_adblock_device_set(mac, vec!["bradesco".into()], false)
        .await);
    ok(client
        .handle_dns_adblock_device_set(mac, vec!["bradesco".into()], false)
        .await);
    let g = groups().await;
    assert_eq!(g.groups[0].clients.len(), 1, "added once");
    assert_eq!(g.groups[0].clients[0].selector, "dev:galaxy");
    assert_eq!(g.groups[0].clients[0].devices[0].mac, mac);
    assert_eq!((g.groups[0].allow_rules, g.groups[0].block_rules), (1, 0));
    ok(client
        .handle_dns_adblock_device_set(mac, Vec::new(), true)
        .await);
    let g = groups().await;
    assert!(g.groups[0].clients.is_empty());
    assert_eq!(g.bypass[0].selector, "dev:galaxy");
    assert_eq!(client.ctx.get_dns_adblock_policy().bypass.len(), 1);

    // A list for the group only, then removed (a group-only source used to be "not found").
    ok(client
        .handle_dns_adblock_url_add(
            Some("kids".into()),
            "https://example.com/k".into(),
            AdblockUrlKind::Blocklist,
            None,
            Some("bradesco".into()),
        )
        .await);
    assert_eq!(groups().await.groups[0].lists, ["kids"]);
    assert_eq!(client.ctx.get_dns_adblock_urls().len(), 1, "not global");
    assert_eq!(
        client.ctx.get_dns_adblock_policy().groups[0].sources.len(),
        1
    );
    ok(client
        .handle_dns_adblock_url_remove("https://example.com/k".into())
        .await);
    assert!(groups().await.groups[0].lists.is_empty());

    // Delete: gone from `[adblock]`, and its rules file with it.
    ok(client
        .handle_dns_adblock_group_delete("bradesco".into())
        .await);
    assert!(groups().await.groups.is_empty());
    assert!(client.ctx.get_dns_adblock_policy().groups.is_empty());
    assert!(!dir.path().join("adblock/bradesco.rules").exists());
    assert!(!fs::read_to_string(&path).unwrap().contains("bradesco"));
    let res = client
        .handle_dns_adblock_group_delete("bradesco".into())
        .await;
    assert!(matches!(res, Response::NotFound { .. }), "{res:?}");
}

/// A read-only configuration keeps adblock group changes in memory: each change builds on the
/// running groups (not on the file, which does not have them), so a rule added to a group
/// survives a later change of its clients, and the listing shows what runs.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn adblock_group_changes_add_up_on_a_read_only_config() {
    use lanforge_api::api::Response;

    let (client, _dir, path) = with_file("[adblock]\nenabled = true\n");
    reload(&client).await;
    client.ctx.set_config_writable(false);
    let ok = |res: Response| assert!(matches!(res, Response::Success(_)), "{res:?}");
    ok(client
        .handle_dns_adblock_group_create("kids".into(), Vec::new(), Vec::new())
        .await);
    ok(client
        .handle_dns_adblock_rule_add("games.example".into(), "block".into(), Some("kids".into()))
        .await);
    ok(client
        .handle_dns_adblock_group_update("kids".into(), Vec::new(), vec!["10.0.0.0/24".into()])
        .await);
    ok(client
        .handle_dns_adblock_group_create("guests".into(), Vec::new(), Vec::new())
        .await);

    let policy = client.ctx.get_dns_adblock_policy();
    let names: Vec<&str> = policy.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["kids", "guests"]);
    assert!(
        policy.groups[0].rules.contains("||games.example^"),
        "{policy:?}"
    );
    assert_eq!(policy.groups[0].clients[0].to_string(), "10.0.0.0/24");
    let Response::DnsAdblockGroups(listed) = client.handle_dns_adblock_groups().await else {
        panic!("groups");
    };
    assert_eq!(listed.groups.len(), 2);
    assert_eq!(listed.groups[0].block_rules, 1);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "[adblock]\nenabled = true\n",
        "read-only: file untouched"
    );
}

/// Deleting a group removes its rules file only when nothing else names it: a file the global
/// layer or another group also uses stays, a file named by the deleted group alone goes.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn deleting_an_adblock_group_keeps_a_rules_file_still_in_use() {
    use lanforge_api::api::Response;

    let file = "[adblock]\nenabled = true\nrules = \"adblock/shared.rules\"\n\n\
                [adblock.groups.a]\nrules = \"adblock/shared.rules\"\n\n\
                [adblock.groups.b]\nrules = \"adblock/b.rules\"\n\n\
                [adblock.groups.c]\nrules = \"adblock/b.rules\"\n";
    let (client, dir, _path) = with_file(file);
    fs::create_dir_all(dir.path().join("adblock")).unwrap();
    fs::write(dir.path().join("adblock/shared.rules"), "||a.example^\n").unwrap();
    fs::write(dir.path().join("adblock/b.rules"), "||b.example^\n").unwrap();
    reload(&client).await;
    let ok = |res: Response| assert!(matches!(res, Response::Success(_)), "{res:?}");

    ok(client.handle_dns_adblock_group_delete("a".into()).await);
    assert!(
        dir.path().join("adblock/shared.rules").exists(),
        "global uses it"
    );
    ok(client.handle_dns_adblock_group_delete("b".into()).await);
    assert!(
        dir.path().join("adblock/b.rules").exists(),
        "group c uses it"
    );
    ok(client.handle_dns_adblock_group_delete("c".into()).await);
    assert!(
        !dir.path().join("adblock/b.rules").exists(),
        "nothing uses it now"
    );
    assert!(dir.path().join("adblock/shared.rules").exists());
}

/// A source only a group uses goes with the group's last use of it: deleting the group, or
/// replacing its lists, used to be refused ("not in `lists` nor in a group") and left the group
/// in place. A source the global layer or another group still uses stays.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn a_group_change_drops_the_sources_nothing_uses_any_more() {
    use lanforge_api::api::Response;

    let file = "[adblock]\nenabled = true\nlists = [\"g\"]\n\n\
                [adblock.sources.g]\nurl = \"https://example.com/g\"\n\n\
                [adblock.sources.k]\nurl = \"https://example.com/k\"\n\n\
                [adblock.sources.s]\nurl = \"https://example.com/s\"\n\n\
                [adblock.groups.kids]\nlists = [\"k\", \"s\", \"g\"]\n\n\
                [adblock.groups.teens]\nlists = [\"s\"]\n";
    let (client, _dir, path) = with_file(file);
    reload(&client).await;
    let ok = |res: Response| assert!(matches!(res, Response::Success(_)), "{res:?}");

    ok(client
        .handle_dns_adblock_group_update("teens".into(), Vec::new(), Vec::new())
        .await);
    let text = fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("[adblock.sources.s]"),
        "kids still uses s: {text}"
    );
    ok(client.handle_dns_adblock_group_delete("kids".into()).await);
    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains("[adblock.sources.k]"), "{text}");
    assert!(!text.contains("[adblock.sources.s]"), "{text}");
    assert!(
        text.contains("[adblock.sources.g]"),
        "global uses g: {text}"
    );
    assert_eq!(client.ctx.get_dns_adblock_urls().len(), 1);
    let names: Vec<String> = client
        .ctx
        .get_dns_adblock_policy()
        .groups
        .iter()
        .map(|g| g.name.clone())
        .collect();
    assert_eq!(names, ["teens"]);
}

/// The incremental adblock calls (the CLI's): a group gains and loses lists (by name or URL) and
/// clients one at a time, `bypass` likewise, a device joins and leaves groups without touching
/// the others, and block/allow/unallow/allowlist work on a group's rules file. Taking out what
/// is not there is `NotFound`, never a silent success.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn adblock_groups_change_one_member_at_a_time() {
    use lanforge_api::api::{AdblockGroupChange, Response};
    use lanforge_types::update::DeviceUpdate;
    use std::time::SystemTime;

    let file = "[adblock]\nenabled = true\nlists = [\"g\"]\n\n\
                [adblock.sources.g]\nurl = \"https://example.com/g\"\n\n\
                [adblock.sources.k]\nurl = \"https://example.com/k\"\n\n\
                [adblock.groups.kids]\nclients = [\"192.168.1.64/28\"]\n\n\
                [adblock.groups.bank]\n";
    let (client, dir, path) = with_file(file);
    reload(&client).await;
    let mac = MacAddr::parse("aa:aa:aa:aa:aa:02").unwrap();
    let _ = client.ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.18".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    let _ = client.ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "tablet".into(),
    });
    let ok = |res: Response| assert!(matches!(res, Response::Success(_)), "{res:?}");
    let not_found = |res: Response| assert!(matches!(res, Response::NotFound { .. }), "{res:?}");
    let policy = || client.ctx.get_dns_adblock_policy();
    let clients = |group: usize| -> Vec<String> {
        policy().groups[group]
            .clients
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    let change = |add_lists: &[&str], remove_lists: &[&str], add: &[&str], remove: &[&str]| {
        let v = |s: &[&str]| s.iter().map(ToString::to_string).collect();
        AdblockGroupChange {
            add_lists: v(add_lists),
            remove_lists: v(remove_lists),
            add_clients: v(add),
            remove_clients: v(remove),
        }
    };

    // A list by URL lands as its name; a client is added once; the other member stays.
    ok(client
        .handle_dns_adblock_group_change(
            "kids".into(),
            change(
                &["https://example.com/k"],
                &[],
                &["10.0.0.5", "10.0.0.5"],
                &[],
            ),
        )
        .await);
    assert_eq!(policy().groups[0].sources[0].url, "https://example.com/k");
    assert_eq!(clients(0), ["192.168.1.64/28", "10.0.0.5"]);
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("lists = [\"k\"]")
    );
    // Taking out one member keeps the rest.
    ok(client
        .handle_dns_adblock_group_change(
            "kids".into(),
            change(&[], &["k"], &[], &["192.168.1.64/28"]),
        )
        .await);
    assert!(policy().groups[0].sources.is_empty());
    assert_eq!(clients(0), ["10.0.0.5"]);
    // Not there, unknown group, bad selector, unknown list.
    not_found(
        client
            .handle_dns_adblock_group_change("kids".into(), change(&[], &[], &[], &["10.9.9.9"]))
            .await,
    );
    not_found(
        client
            .handle_dns_adblock_group_change("kids".into(), change(&[], &["g"], &[], &[]))
            .await,
    );
    not_found(
        client
            .handle_dns_adblock_group_change("nope".into(), change(&[], &[], &["10.0.0.1"], &[]))
            .await,
    );
    let res = client
        .handle_dns_adblock_group_change("kids".into(), change(&[], &[], &["dev:"], &[]))
        .await;
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    let res = client
        .handle_dns_adblock_group_change("kids".into(), change(&["missing"], &[], &[], &[]))
        .await;
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(clients(0), ["10.0.0.5"], "refused changes apply nothing");

    // bypass: add two, take one out, a missing one is NotFound.
    ok(client
        .handle_dns_adblock_bypass_change(vec!["10.0.0.7".into(), "dev:tv".into()], Vec::new())
        .await);
    ok(client
        .handle_dns_adblock_bypass_change(Vec::new(), vec!["10.0.0.7".into()])
        .await);
    let bypass: Vec<String> = policy().bypass.iter().map(ToString::to_string).collect();
    assert_eq!(bypass, ["dev:tv"]);
    not_found(
        client
            .handle_dns_adblock_bypass_change(Vec::new(), vec!["10.0.0.7".into()])
            .await,
    );

    // The device side: join one group, then the other, the first membership stays.
    ok(client
        .handle_dns_adblock_device_change(mac, vec!["kids".into()], Vec::new(), None)
        .await);
    ok(client
        .handle_dns_adblock_device_change(mac, vec!["bank".into()], Vec::new(), Some(true))
        .await);
    assert_eq!(clients(0), ["10.0.0.5", "dev:tablet"]);
    assert_eq!(clients(1), ["dev:tablet"]);
    assert!(
        policy()
            .bypass
            .iter()
            .any(|c| c.to_string() == "dev:tablet")
    );
    ok(client
        .handle_dns_adblock_device_change(mac, Vec::new(), vec!["kids".into()], Some(false))
        .await);
    assert_eq!(clients(0), ["10.0.0.5"]);
    assert_eq!(clients(1), ["dev:tablet"], "bank untouched");
    assert!(
        !policy()
            .bypass
            .iter()
            .any(|c| c.to_string() == "dev:tablet")
    );
    // Leaving a group that does not name it, an unknown group, an unknown device.
    not_found(
        client
            .handle_dns_adblock_device_change(mac, Vec::new(), vec!["kids".into()], None)
            .await,
    );
    not_found(
        client
            .handle_dns_adblock_device_change(mac, vec!["nope".into()], Vec::new(), None)
            .await,
    );
    not_found(
        client
            .handle_dns_adblock_device_change(
                MacAddr::parse("aa:aa:aa:aa:aa:99").unwrap(),
                vec!["kids".into()],
                Vec::new(),
                None,
            )
            .await,
    );

    // block/allow/unallow/allowlist on a group's rules file, the global one untouched.
    ok(client
        .handle_dns_allow("bank.example".into(), Some("bank".into()))
        .await);
    ok(client
        .handle_dns_block("ads.example".into(), Some("bank".into()))
        .await);
    let rules = fs::read_to_string(dir.path().join("adblock/bank.rules")).unwrap();
    assert!(
        rules.contains("@@||bank.example^") && rules.contains("||ads.example^"),
        "{rules}"
    );
    assert!(
        client.ctx.get_dns_adblock_rules().is_empty(),
        "global untouched"
    );
    let Response::DnsAllowlist(list) = client.handle_dns_allowlist(Some("bank".into())).await
    else {
        panic!("group allowlist");
    };
    assert_eq!(list.allowlist.len(), 1);
    assert_eq!(list.allowlist[0].domain, "bank.example");
    let Response::DnsAllowlist(global) = client.handle_dns_allowlist(None).await else {
        panic!("global allowlist");
    };
    assert!(global.allowlist.is_empty());
    not_found(client.handle_dns_allowlist(Some("nope".into())).await);
    ok(client
        .handle_dns_unallow("bank.example".into(), Some("bank".into()))
        .await);
    assert!(!policy().groups[1].rules.contains("@@||bank.example^"));
    not_found(
        client
            .handle_dns_unallow("bank.example".into(), Some("bank".into()))
            .await,
    );
}
