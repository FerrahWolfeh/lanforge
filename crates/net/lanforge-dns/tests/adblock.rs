mod common;
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::adblock::AdblockUrlKind;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRecordType, DnsResponseCode,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket as TokioUdpSocket;

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

    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let ctx = LanforgeContext::new(bus, table, None);

    // 2. Setup Config with adblock compiled but disabled at start
    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1073".parse().unwrap(),
        adblock_enabled: false,
        adblock_cache_dir: Some(cache_dir_path.clone()),
        ..Default::default()
    };

    // 3. Start DNS Service
    let mut service = DnsService::new(cfg, ctx.clone());
    let ctrl = ServiceControl::new("dns-adblock-test", ctx.clone());

    ctx.set_db_ready(true);
    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        service.run(ctrl).await.expect("Service failed");
    });

    // Wait for ServiceReady
    loop {
        let event = rx.recv().await.expect("Bus closed");
        if let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = event.event
            && name == "dns-adblock-test"
        {
            break;
        }
    }

    // 4. Test: If disabled, it should do nothing (queries are not blocked)
    let client_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect("127.0.0.1:1073").await.unwrap();

    let mut query = DnsMessage::new();
    query.header.id = 1001;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("ads.example.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let query_bytes = WireEncoder::new().encode_message(&query);
    client_sock.send(&query_bytes).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for DNS response")
        .unwrap();

    let response = WireDecoder::new(&buf[..n]).decode_message().unwrap();
    assert_eq!(
        response.header.rcode,
        DnsResponseCode::ServFail,
        "Should return ServFail if not blocked"
    );

    // 5. Test: Enabling it in the DB and trigger toggle on the fly
    // Let's add blocklist URL to the DB first
    let url = format!("http://127.0.0.1:{}/blocklist.txt", port);
    ctx.update_dns_adblock_urls(vec![AdblockUrlEntry {
        id: Some(1),
        url: url.clone(),
        kind: AdblockUrlKind::Blocklist,
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
    let fst_file_path = temp_dir.path().join("blocklist.fst");
    for _ in 0..50 {
        if fst_file_path.exists() {
            fst_built = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        fst_built,
        "Adblock worker should build FST file when enabled"
    );

    // Give it a brief moment to update memory blocker with new FST
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 6. Test: Query should now be blocked!
    client_sock.send(&query_bytes).await.unwrap();
    let n2 = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let response2 = WireDecoder::new(&buf[..n2]).decode_message().unwrap();
    // Default blocking mode is NullIp, which returns 0.0.0.0
    assert_eq!(response2.header.rcode, DnsResponseCode::NoError);
    assert!(!response2.answers.is_empty());

    // Change blocking mode to Refused
    ctx.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        blocking_mode: BlockingMode::Refused,
        ..Default::default()
    });
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    let _ = ctx.bus().publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Query again, should be Refused
    client_sock.send(&query_bytes).await.unwrap();
    let n3 = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let response3 = WireDecoder::new(&buf[..n3]).decode_message().unwrap();
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Query should not be blocked anymore
    client_sock.send(&query_bytes).await.unwrap();
    let n4 = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let response4 = WireDecoder::new(&buf[..n4]).decode_message().unwrap();
    assert_eq!(response4.header.rcode, DnsResponseCode::ServFail);

    ctx.terminate();
}
