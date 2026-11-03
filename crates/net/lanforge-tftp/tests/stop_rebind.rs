//! A stopped TFTP server releases its port even with a transfer in flight.

use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_tftp::TftpService;
use lanforge_tftp::config::TftpConfig;
use lanforge_types::system::ServiceId;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Each request ran in a detached task holding a clone of the listening socket for the whole
/// transfer (retries included): after a stop the port stayed bound, and the restart failed with
/// "address in use" until the client gave up.
#[tokio::test]
async fn stop_releases_the_port_with_a_transfer_in_flight() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("boot.bin"), vec![0xAB; 4096]).unwrap();
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let cfg = TftpConfig {
        enabled: true,
        listen: "127.0.0.1:0".parse().unwrap(),
        root_dir: root.path().to_path_buf(),
        block_size: 512,
        timeout: 2,
        max_retries: 5,
    };
    let mut service = TftpService::new(ctx.clone(), cfg);
    let probe = service.clone();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(4);
    let h = ServiceHandle::with_command_channel(ServiceId::Tftp, ctx.clone(), cmd_rx);
    let serving = ctx.clone();
    let serve = tokio::spawn(async move { service.serve(&serving, &h).await });

    let mut bound = None;
    for _ in 0..50 {
        bound = probe.bound_addr();
        if bound.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let server: SocketAddr = bound.expect("TFTP bound").parse().unwrap();

    // Read request, first block received, never acknowledged: the transfer keeps retrying.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"\x00\x01boot.bin\x00octet\x00", server)
        .await
        .unwrap();
    let mut buf = [0u8; 516];
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("first block")
        .unwrap();
    assert_eq!(&buf[..4], b"\x00\x03\x00\x01", "DATA block 1 ({n} bytes)");

    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");

    let rebind = std::net::UdpSocket::bind(server);
    assert!(rebind.is_ok(), "{server} still held: {:?}", rebind.err());
}
