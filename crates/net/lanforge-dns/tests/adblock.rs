#[path = "common/mod.rs"]
mod common;

use common::{DnsPacketBuilder, init_test_context, parse_response, wait_for_service_online};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_core::service::AsyncService;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::network::dns::adblock::AdblockUrlKind;
use lanforge_types::network::dns::{DnsRecordType, DnsResponseCode};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "adblock")]
#[tokio::test(flavor = "multi_thread")]
async fn test_adblock_service_lifecycle_and_rebuild() {
    // 1. Spawn a mock HTTP server to host our blocklist
    use lanforge_types::network::dns::AdblockUrlEntry;
    use lanforge_types::network::dns::adblock::{AdblockDbConfig, BlockingMode};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Spawn task to handle HTTP requests
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n# Some comment\r\nads.example.com\r\ntracking.example.com\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let temp_dir = tempfile::tempdir().unwrap();
    let cache_dir_path = temp_dir.path().to_str().unwrap().to_string();

    let ctx = init_test_context();

    // 2. Setup Config with adblock compiled but disabled at start
    let cfg = DnsConfig {
        enabled: true,
        adblock_enabled: false,
        adblock_cache_dir: Some(cache_dir_path.clone()),
        ..common::mock_config()
    };

    // 3. Start DNS Service in inert mode
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(
            lanforge_types::system::ServiceId::Dns,
            ctx_service.clone(),
        );
        service
            .serve(&ctx_service, &h)
            .await
            .expect("Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    let client_addr: SocketAddr = "192.168.1.100:54326".parse().unwrap();
    let query_bytes = DnsPacketBuilder::query("ads.example.com", DnsRecordType::A)
        .with_id(1001)
        .build_bytes();

    // 4. Test: If disabled, it should do nothing (queries are not blocked -> ServFail without upstreams)
    handle.inject(query_bytes.clone(), client_addr).await;

    let (reply1, _) = handle.recv_reply().await.expect("Expected DNS reply");
    let response = parse_response(&reply1).expect("Valid DNS message");
    assert_eq!(
        response.header.rcode,
        DnsResponseCode::ServFail,
        "Should return ServFail if not blocked"
    );

    // 5. Test: Enabling it in the DB and trigger toggle on the fly
    let url = format!("http://127.0.0.1:{}/blocklist.txt", port);
    ctx.update_dns_adblock_urls(vec![AdblockUrlEntry {
        id: Some(1),
        name: None,
        url: url.clone(),
        kind: AdblockUrlKind::Blocklist,
        format: lanforge_types::network::dns::adblock::AdblockSourceFormat::Auto,
    }]);

    ctx.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        blocking_mode: BlockingMode::NullIp,
        ..Default::default()
    });

    // Trigger toggle and config changed signals
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
            enabled: true,
            duration_secs: None,
        }));

    // Wait for downloader to run and rebuild FST
    let mut fst_built = false;
    let fst_file_path = temp_dir.path().join("adblock").join("block.fst");
    for _ in 0..50 {
        if fst_file_path.exists() {
            fst_built = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        fst_built,
        "Adblock worker should build FST file when enabled"
    );

    // Give it a brief moment to update memory blocker with new FST
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Test: Query should now be blocked!
    handle.inject(query_bytes.clone(), client_addr).await;
    let (reply2, _) = handle.recv_reply().await.expect("Expected blocked reply");
    let response2 = parse_response(&reply2).expect("Valid DNS message");
    // Default blocking mode is NullIp, which returns 0.0.0.0 (NoError with answers)
    assert_eq!(response2.header.rcode, DnsResponseCode::NoError);
    assert!(!response2.answers.is_empty());

    // 7. Change blocking mode to Refused
    ctx.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        blocking_mode: BlockingMode::Refused,
        ..Default::default()
    });
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    let _ = ctx.bus().publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Query again, should be Refused
    handle.inject(query_bytes.clone(), client_addr).await;
    let (reply3, _) = handle.recv_reply().await.expect("Expected refused reply");
    let response3 = parse_response(&reply3).expect("Valid DNS message");
    assert_eq!(response3.header.rcode, DnsResponseCode::Refused);

    // 8. Test: Toggle off during runtime
    ctx.update_dns_adblock(AdblockDbConfig {
        enabled: false,
        ..Default::default()
    });
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
            enabled: false,
            duration_secs: None,
        }));
    let _ = ctx.bus().publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Query should not be blocked anymore
    handle.inject(query_bytes, client_addr).await;
    let (reply4, _) = handle.recv_reply().await.expect("Expected unblocked reply");
    let response4 = parse_response(&reply4).expect("Valid DNS message");
    assert_eq!(response4.header.rcode, DnsResponseCode::ServFail);

    ctx.terminate();
}
