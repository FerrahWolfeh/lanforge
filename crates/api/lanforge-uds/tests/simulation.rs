use lanforge_api::rpc::{RpcRequest, RpcResponse};
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_uds::config::ApiConfig;
use lanforge_uds::server::ControlService;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn init_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}

#[tokio::test]
async fn dns_uds_simulation_basic() {
    let ctx = init_test_context().await;
    let socket_path = "/tmp/lanforge_test_control.sock";

    // 1. Setup config
    let api_cfg = ApiConfig {
        enabled: true,
        socket_path: socket_path.to_string(),
        tcp_port: None,
    };
    let cfg = Arc::new(api_cfg);

    // 2. Spawn UDS server control service
    let mut service = ControlService::new(cfg, ctx.clone());
    let ctrl = ServiceControl::new(lanforge_types::system::ServiceId::Uds, ctx.clone());
    let ctx_service = ctx.clone();

    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        service
            .serve(&ctx_service, &ctrl)
            .await
            .expect("Control API service failed");
    });

    // Wait for ServiceReady
    loop {
        let event = rx.recv().await.expect("Bus closed");
        if let LanforgeEvent::System(SystemEvent::ServiceReady { id }) = event.event
            && id == lanforge_types::system::ServiceId::Uds
        {
            break;
        }
    }

    // 3. Verify permissions of the socket file (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(socket_path).expect("Socket file should exist");
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o660);
    }

    // 4. Connect to socket and query
    let mut client = UnixStream::connect(socket_path)
        .await
        .expect("Failed to connect to UDS");

    let req = RpcRequest::Status {};
    let payload = postcard::to_stdvec(&req).unwrap();
    let len = payload.len() as u32;
    client.write_all(&len.to_be_bytes()).await.unwrap();
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    client.read_exact(&mut resp_buf).await.unwrap();

    let resp: RpcResponse = postcard::from_bytes(&resp_buf).unwrap();
    assert!(matches!(resp, RpcResponse::Status(_)));

    // Cleanup
    drop(client);
    ctx.terminate();
}
