use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_tftp::TftpService;
use lanforge_tftp::config::TftpConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_tftp_path_traversal_prevention() {
    // 1. Create a temp root and directory structure
    let temp_dir = tempfile::tempdir().unwrap();
    let root_path = temp_dir.path().to_path_buf();

    // Create a subdirectory to be the TFTP root so we can traverse up out of it
    let tftp_root = root_path.join("tftp");
    std::fs::create_dir(&tftp_root).unwrap();

    // Create a valid file inside the root
    let valid_file_path = tftp_root.join("valid.txt");
    std::fs::write(&valid_file_path, b"Hello Inside TFTP!").unwrap();

    // Create a file outside the TFTP root (in the parent temp directory)
    let outside_file_path = root_path.join("outside.txt");
    std::fs::write(&outside_file_path, b"Secret Outside Info!").unwrap();

    // 2. Start the service
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);

    let cfg = TftpConfig {
        enabled: true,
        listen_addr: "127.0.0.1:0".into(),
        root_dir: tftp_root.clone(),
        block_size: 512,
        timeout: 1,
        max_retries: 2,
    };

    let mut service = TftpService::new(ctx.clone(), cfg);
    ctx.register_status_provider(Arc::new(service.clone()));
    let ctx_service = ctx.clone();

    tokio::spawn(async move {
        service.serve(&ctx_service).await.expect("TFTP service failed to run");
    });

    // Wait for service to bind and register port
    tokio::time::sleep(Duration::from_millis(100)).await;
    let banners = ctx.service_banners();
    let banner = banners.iter().find(|b| b.id == "tftp").unwrap();
    let listen = banner
        .stats
        .iter()
        .find(|(k, _)| k == "listen")
        .unwrap()
        .1
        .clone();
    let tftp_addr = listen.parse::<SocketAddr>().unwrap();
    println!("Bound TFTP address: {tftp_addr:?}");

    // 3. Setup client UDP socket
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // --- Part A: Verify that reading a valid file works ---
    let mut rrq_packet = Vec::new();
    rrq_packet.extend_from_slice(&1u16.to_be_bytes()); // Opcode RRQ (1)
    rrq_packet.extend_from_slice(b"valid.txt\0octet\0");
    client.send_to(&rrq_packet, tftp_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (n, server_session_addr) =
        tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("Timeout waiting for TFTP response")
            .unwrap();

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    assert_eq!(opcode, 3, "Expected DATA opcode (3) for valid file");
    let block = u16::from_be_bytes([buf[2], buf[3]]);
    assert_eq!(block, 1, "Expected block number 1");
    let file_data = &buf[4..n];
    assert_eq!(file_data, b"Hello Inside TFTP!");

    // Send ACK back to finish session cleanly (opcode 4, block 1)
    let mut ack_packet = Vec::new();
    ack_packet.extend_from_slice(&4u16.to_be_bytes());
    ack_packet.extend_from_slice(&1u16.to_be_bytes());
    client
        .send_to(&ack_packet, server_session_addr)
        .await
        .unwrap();

    // --- Part B: Verify path traversal attempt is blocked ---
    let mut traversal_packet = Vec::new();
    traversal_packet.extend_from_slice(&1u16.to_be_bytes()); // Opcode RRQ (1)
    traversal_packet.extend_from_slice(b"../outside.txt\0octet\0");
    client.send_to(&traversal_packet, tftp_addr).await.unwrap();

    let (_n2, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("Timeout waiting for TFTP traversal response")
        .unwrap();

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    assert_eq!(opcode, 5, "Expected ERROR opcode (5) for traversal attempt");
    let error_code = u16::from_be_bytes([buf[2], buf[3]]);
    assert_eq!(error_code, 2, "Expected Access Violation (2) error code");

    ctx.terminate();
}
