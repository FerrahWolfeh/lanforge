#![cfg(feature = "adblock")]
//! Per-client adblock: groups (overlays on the global layer) and `bypass`, through the DNS
//! service's `serve` with queries from different client addresses.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockGroupPolicy, AdblockPolicy, AdblockSourceFormat, AdblockUrlKind,
    BlockingMode, FilterAction, FilterOrigin,
};
use lanforge_types::network::dns::{DnsRecordType, DnsRequest, DnsResponse};
use lanforge_types::system::ServiceId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

use super::common::{
    DnsPacketBuilder, MockUpstreamServer, extract_a, init_test_context, mock_config,
    parse_response, register_test_device, wait_for_service_online,
};
use crate::config::DnsConfig;
use crate::resolver::filter::{AdBlocker, ClientLayers, DiskBlocklist};
use crate::server::service::DnsService;

/// The global list: what every client gets blocked.
const GLOBAL_LIST: &str = "||ads.example.com^\n||app-measurement.com^\n||analytics.google.com^\n";
/// The `kids` group's own list.
const KIDS_LIST: &str = "||games.example.com^\n";

/// Serves `/global.txt` and `/kids.txt`.
async fn spawn_list_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.starts_with("GET /kids.txt") {
                    KIDS_LIST
                } else {
                    GLOBAL_LIST
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

fn source(port: u16, path: &str) -> AdblockUrlEntry {
    AdblockUrlEntry {
        id: None,
        name: Some(path.to_string()),
        url: format!("http://127.0.0.1:{port}/{path}"),
        kind: AdblockUrlKind::Blocklist,
        format: AdblockSourceFormat::Adblock,
    }
}

fn group(
    name: &str,
    sources: Vec<AdblockUrlEntry>,
    rules: &str,
    clients: &[&str],
) -> AdblockGroupPolicy {
    AdblockGroupPolicy {
        name: name.to_string(),
        sources,
        rules: rules.to_string(),
        clients: clients.iter().map(|c| c.parse().unwrap()).collect(),
    }
}

const PIXEL: &str = "aa:aa:aa:aa:aa:01";
const PIXEL_NEW_MAC: &str = "aa:aa:aa:aa:aa:02";
const NOTEBOOK: &str = "bb:bb:bb:bb:bb:01";
const OTHER: &str = "cc:cc:cc:cc:cc:01";

/// The owner's case: Bradesco's app needs 4 tracker domains the global list blocks; only the
/// phone in group `bradesco` gets them. Plus a `kids` group with its own list and rule by
/// subnet, and a bypassed notebook.
fn owner_policy(port: u16) -> AdblockPolicy {
    AdblockPolicy {
        bypass: vec![format!("dev:{NOTEBOOK}").parse().unwrap()],
        groups: vec![
            group(
                "bradesco",
                Vec::new(),
                "@@||app-measurement.com^\n@@||analytics.google.com^\n",
                &["dev:pixel-faiko"],
            ),
            group(
                "kids",
                vec![source(port, "kids.txt")],
                "||extra.example.com^\n",
                &["192.168.1.64/28"],
            ),
        ],
    }
}

/// Runs the DNS service on `ctx` and answers `name` for the client at `ip`: the A record, or
/// `0.0.0.0` when blocked (`null_ip`).
struct Dns {
    handle: lanforge_transport::InertHandle<SocketAddr>,
}

impl Dns {
    async fn ask(&self, ip: &str, name: &str) -> Ipv4Addr {
        let client: SocketAddr = format!("{ip}:5353").parse().unwrap();
        let query = DnsPacketBuilder::query(name, DnsRecordType::A).build_bytes();
        self.handle.inject(query, client).await;
        let (reply, _) = self.handle.recv_reply().await.expect("a reply");
        let resp = parse_response(&reply).expect("a DNS message");
        extract_a(&resp)
            .first()
            .copied()
            .unwrap_or(Ipv4Addr::BROADCAST)
    }
}

const BLOCKED: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const ANSWER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

async fn start(ctx: &LanforgeContext, cache_dir: &Path) -> (Dns, MockUpstreamServer) {
    let names = [
        "ads.example.com",
        "app-measurement.com",
        "analytics.google.com",
        "games.example.com",
        "extra.example.com",
        "clean.example.com",
    ];
    let records: HashMap<String, Vec<IpAddr>> = names
        .iter()
        .map(|n| ((*n).to_string(), vec![IpAddr::V4(ANSWER)]))
        .collect();
    let upstream = MockUpstreamServer::spawn(records).await;
    ctx.update_dns_upstreams(vec![upstream.target()]);
    ctx.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        blocking_mode: BlockingMode::NullIp,
        ..Default::default()
    });

    let cfg = DnsConfig {
        enabled: true,
        adblock_enabled: true,
        adblock_cache_dir: Some(cache_dir.to_str().unwrap().to_string()),
        ..mock_config()
    };
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dns, ctx_service.clone());
        service.serve(&ctx_service, &h).await.expect("DNS service");
    });
    wait_for_service_online(ctx, ServiceId::Dns).await;
    (Dns { handle }, upstream)
}

/// Waits until `ip` gets `want` for `name` (the lists download in the background).
async fn wait_for(dns: &Dns, ip: &str, name: &str, want: Ipv4Addr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = dns.ask(ip, name).await;
        if got == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{ip} asking {name}: got {got}, want {want}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn groups_and_bypass_apply_per_client() {
    let port = spawn_list_server().await;
    let dir = tempfile::tempdir().unwrap();
    let ctx = init_test_context();
    ctx.update_dns_adblock_urls(vec![source(port, "global.txt")]);
    let _ = ctx.apply_config(ConfigPatch::new().with_dns_adblock_policy(owner_policy(port)));

    let mac = |m: &str| MacAddr::parse(m).unwrap();
    register_test_device(
        &ctx,
        "pixel-faiko",
        mac(PIXEL),
        Ipv4Addr::new(192, 168, 1, 50),
    );
    register_test_device(
        &ctx,
        "notebook",
        mac(NOTEBOOK),
        Ipv4Addr::new(192, 168, 1, 30),
    );
    register_test_device(&ctx, "tv", mac(OTHER), Ipv4Addr::new(192, 168, 1, 20));

    let (dns, _upstream) = start(&ctx, dir.path()).await;
    // The group's own list is downloaded too.
    wait_for(&dns, "192.168.1.70", "games.example.com", BLOCKED).await;
    wait_for(&dns, "192.168.1.20", "ads.example.com", BLOCKED).await;

    // The phone first: its allowed answer is cached, and must not reach the others.
    let pixel = "192.168.1.50";
    assert_eq!(
        dns.ask(pixel, "app-measurement.com").await,
        ANSWER,
        "group allow"
    );
    assert_eq!(
        dns.ask(pixel, "analytics.google.com").await,
        ANSWER,
        "group allow"
    );
    assert_eq!(
        dns.ask(pixel, "ads.example.com").await,
        BLOCKED,
        "global still applies"
    );
    assert_eq!(
        dns.ask(pixel, "games.example.com").await,
        ANSWER,
        "not in kids"
    );

    for other in ["192.168.1.20", "192.168.1.99"] {
        assert_eq!(
            dns.ask(other, "app-measurement.com").await,
            BLOCKED,
            "{other}"
        );
        assert_eq!(
            dns.ask(other, "analytics.google.com").await,
            BLOCKED,
            "{other}"
        );
        assert_eq!(dns.ask(other, "games.example.com").await, ANSWER, "{other}");
        assert_eq!(dns.ask(other, "extra.example.com").await, ANSWER, "{other}");
    }

    // `kids` by subnet: its list and its rule on top of the global layer.
    let kid = "192.168.1.70";
    assert_eq!(dns.ask(kid, "games.example.com").await, BLOCKED);
    assert_eq!(dns.ask(kid, "extra.example.com").await, BLOCKED);
    assert_eq!(dns.ask(kid, "app-measurement.com").await, BLOCKED);
    assert_eq!(dns.ask(kid, "clean.example.com").await, ANSWER);

    // `bypass` by MAC: nothing filtered.
    assert_eq!(dns.ask("192.168.1.30", "ads.example.com").await, ANSWER);

    // Android re-randomizes the phone's MAC: same name, still in the group.
    register_test_device(
        &ctx,
        "pixel-faiko",
        mac(PIXEL_NEW_MAC),
        Ipv4Addr::new(192, 168, 1, 51),
    );
    assert_eq!(dns.ask("192.168.1.51", "app-measurement.com").await, ANSWER);

    // `dns adblock check --client`: the verdict and the groups that client gets.
    let check = |client: Option<&str>| {
        let handle = ctx.dns_handle().expect("DNS handle");
        let client = client.map(|c| c.parse().unwrap());
        async move {
            let res = handle
                .send_request(DnsRequest::AdblockCheck {
                    domain: "app-measurement.com".into(),
                    client,
                })
                .await;
            let Ok(DnsResponse::AdblockCheck(res)) = res else {
                panic!("check: {res:?}");
            };
            res
        }
    };
    let phone = check(Some(pixel)).await;
    assert_eq!(phone.groups, ["bradesco"]);
    assert_eq!(
        phone.filter.map(|m| (m.action, m.origin)),
        Some((
            FilterAction::Allow,
            FilterOrigin::GroupAllowlist {
                group: "bradesco".into()
            }
        ))
    );
    let global = check(None).await;
    assert!(global.groups.is_empty() && !global.bypass);
    assert_eq!(global.filter.map(|m| m.action), Some(FilterAction::Block));
    let notebook = check(Some("192.168.1.30")).await;
    assert!(notebook.bypass && !notebook.matched);

    // Out of the group (a config change, applied in place): blocked again.
    let mut policy = owner_policy(port);
    policy.groups[0].clients.clear();
    let _ = ctx.apply_config(ConfigPatch::new().with_dns_adblock_policy(policy));
    wait_for(&dns, pixel, "app-measurement.com", BLOCKED).await;

    ctx.terminate();
}

/// Attribution and precedence on the filter itself: a group decides before the global layer,
/// even over a global `$important` block; of a client's groups an allow wins.
#[test]
fn a_group_overrides_the_global_layer() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = init_test_context();
    ctx.update_dns_adblock_rules("||imp.example.com^$important\n||ads.example.com^\n".into());
    let global = AdblockUrlEntry {
        id: Some(1),
        ..source(1, "global.txt")
    };
    let kids = AdblockUrlEntry {
        id: Some(2),
        ..source(1, "kids.txt")
    };
    ctx.update_dns_adblock_urls(vec![global.clone()]);
    let policy = AdblockPolicy {
        bypass: Vec::new(),
        groups: vec![
            group(
                "a",
                Vec::new(),
                "@@||imp.example.com^\n||both.example.com^\n",
                &["10.0.0.1"],
            ),
            group("b", vec![kids], "@@||both.example.com^\n", &["10.0.0.1"]),
        ],
    };
    let _ = ctx.apply_config(ConfigPatch::new().with_dns_adblock_policy(policy));

    let filter = AdBlocker::new(true);
    filter.sync_from_context(&ctx);
    // Two compiled lists: id 1 (global) blocks list.example.com, id 2 (kids) games.example.com.
    let path = |id: i64| dir.path().join(format!("{id}.block.fst"));
    drop(DiskBlocklist::build(["list.example.com".to_string()].into(), &path(1), 0).unwrap());
    drop(DiskBlocklist::build(["games.example.com".to_string()].into(), &path(2), 0).unwrap());
    let (lists, failed) = DiskBlocklist::load(
        dir.path(),
        &[
            (1, AdblockUrlKind::Blocklist),
            (2, AdblockUrlKind::Blocklist),
        ],
    );
    assert!(failed.is_empty());
    filter.replace_blocklist(lists);

    let layers = filter.client_layers(&ctx, "10.0.0.1".parse().unwrap());
    assert_eq!(
        layers,
        ClientLayers {
            bypass: false,
            groups: 0b11
        }
    );
    let verdict = |name: &str, client| filter.check(name, client).map(|m| (m.action, m.origin));

    assert_eq!(
        verdict("imp.example.com", layers),
        Some((
            FilterAction::Allow,
            FilterOrigin::GroupAllowlist { group: "a".into() }
        ))
    );
    assert_eq!(
        verdict("imp.example.com", ClientLayers::GLOBAL),
        Some((FilterAction::Block, FilterOrigin::UserRule))
    );
    assert_eq!(
        verdict("both.example.com", layers),
        Some((
            FilterAction::Allow,
            FilterOrigin::GroupAllowlist { group: "b".into() }
        ))
    );
    assert_eq!(
        verdict("games.example.com", layers),
        Some((
            FilterAction::Block,
            FilterOrigin::GroupList {
                group: "b".into(),
                source_id: 2
            }
        ))
    );
    // A group's list is not global.
    assert_eq!(verdict("games.example.com", ClientLayers::GLOBAL), None);
    assert_eq!(
        verdict("list.example.com", ClientLayers::GLOBAL),
        Some((FilterAction::Block, FilterOrigin::List { source_id: 1 }))
    );
    assert_eq!(
        verdict("ads.example.com", layers),
        Some((FilterAction::Block, FilterOrigin::UserRule))
    );
    // A client in no group, or a bypassed one.
    let nobody = filter.client_layers(&ctx, "10.0.0.2".parse().unwrap());
    assert_eq!(nobody, ClientLayers::GLOBAL);
    let bypass = ClientLayers {
        bypass: true,
        groups: 0,
    };
    assert_eq!(verdict("ads.example.com", bypass), None);
}

/// A list added while the daemon was down (here a group's) is downloaded at boot even though
/// the lists already on disk are fresh: before, a fresh cache skipped the whole download pass
/// and the new list stayed empty until the next daily refresh.
#[tokio::test(flavor = "multi_thread")]
async fn a_list_added_while_down_is_downloaded_at_boot() {
    let port = spawn_list_server().await;
    let dir = tempfile::tempdir().unwrap();

    let ctx = init_test_context();
    ctx.update_dns_adblock_urls(vec![source(port, "global.txt")]);
    let (dns, _upstream) = start(&ctx, dir.path()).await;
    wait_for(&dns, "192.168.1.20", "ads.example.com", BLOCKED).await;
    ctx.terminate();
    sleep(Duration::from_millis(200)).await;

    let ctx = init_test_context();
    ctx.update_dns_adblock_urls(vec![source(port, "global.txt")]);
    let _ = ctx.apply_config(ConfigPatch::new().with_dns_adblock_policy(owner_policy(port)));
    let (dns, _upstream) = start(&ctx, dir.path()).await;
    wait_for(&dns, "192.168.1.70", "games.example.com", BLOCKED).await;
    ctx.terminate();
}
