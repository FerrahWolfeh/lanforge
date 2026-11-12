//! The banner carries the serving instance's socket counters.

use crate::TftpService;
use crate::config::TftpConfig;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_types::system::{ServiceId, ServiceState};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

/// Real sockets, real `serve`: a request the server received shows in its banner, and the
/// counters go when the service stops (the old banner read a registration-time instance that
/// never bound anything).
#[tokio::test]
async fn banner_counts_the_serving_sockets() {
    let root = tempfile::tempdir().unwrap();
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.register_service(ServiceId::Tftp, "TFTP Server", &[]);
    let cfg = TftpConfig {
        enabled: true,
        listen: "127.0.0.1:0".parse().unwrap(),
        root_dir: root.path().to_path_buf(),
        block_size: 512,
        timeout: 1,
        max_retries: 1,
    };
    let mut service = TftpService::new(ctx.clone(), cfg);
    let probe = service.clone();
    let serving = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Tftp, serving.clone());
        let _ = service.serve(&serving, &h).await;
    });

    let mut bound = None;
    for _ in 0..50 {
        bound = probe.bound_addr();
        if bound.is_some() {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    let server: SocketAddr = bound.expect("TFTP bound").parse().unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"\x00\x01missing.txt\x00octet\x00", server)
        .await
        .unwrap();
    let mut buf = [0u8; 516];
    let _ = timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await;

    let transport = |ctx: &LanforgeContext| {
        ctx.service_banners()
            .into_iter()
            .find(|b| b.id == ServiceId::Tftp)
            .unwrap()
            .transport
    };
    let counters = transport(&ctx).expect("the serving instance registered its sockets");
    assert!(counters.rx_packets >= 1, "{counters:?}");
    assert!(counters.rx_bytes >= 20, "{counters:?}");

    ctx.set_service_state(ServiceId::Tftp, ServiceState::Inactive);
    assert_eq!(transport(&ctx), None);
}
