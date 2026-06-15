use crate::server::handle_client;
use lanforge_api::api::EventKind;
use lanforge_api::rpc::{RpcRequest, RpcResponse};
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State as CoreState;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::events::{LanforgeEvent, StorageEvent, SystemEvent, TimedEvent};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn init_test_context() -> ClientContext {
    let bus = Arc::new(EventBus::new());
    let table = CoreState::new();
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open("sqlite::memory:").await.unwrap());
    let ctx = LanforgeContext::new(bus, table, None);

    ClientContext {
        current_gua: None,
        uptime_secs: 100,
        ctx: ctx.clone(),
        db,
        log_db,
        active_clients: ctx.active_clients(),
    }
}

#[tokio::test]
async fn test_uds_client_status_flow() {
    let client_ctx = init_test_context().await;
    let (mut client, server) = tokio::io::duplex(8192);

    let handler_task = tokio::spawn(async move {
        handle_client(server, client_ctx).await.unwrap();
    });

    // Send request
    let req = RpcRequest::Status {};
    let payload = postcard::to_stdvec(&req).unwrap();
    let len = payload.len() as u32;
    client.write_all(&len.to_be_bytes()).await.unwrap();
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    // Read response
    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    client.read_exact(&mut resp_buf).await.unwrap();

    let resp: RpcResponse = postcard::from_bytes(&resp_buf).unwrap();
    assert!(matches!(resp, RpcResponse::Status(_)));

    // Close connection
    drop(client);
    handler_task.await.unwrap();
}

#[tokio::test]
async fn test_uds_client_large_framing_protection() {
    let client_ctx = init_test_context().await;
    let (mut client, server) = tokio::io::duplex(1024);

    let handler_task = tokio::spawn(async move {
        // It should return an encoding error when framing size is exceeded
        let res = handle_client(server, client_ctx).await;
        assert!(res.is_err());
    });

    // Write a framed length that exceeds 10MB (e.g. 11MB)
    let invalid_len: u32 = 11 * 1024 * 1024;
    client.write_all(&invalid_len.to_be_bytes()).await.unwrap();
    client.flush().await.unwrap();

    handler_task.await.unwrap();
}

#[tokio::test]
async fn test_uds_log_streaming_filter() {
    let client_ctx = init_test_context().await;
    let (mut client, server) = tokio::io::duplex(8192);

    // Populate history logs using TimedEvent::new() to automatically assign timestamps
    let log1 = TimedEvent::new(LanforgeEvent::System(SystemEvent::ReloadConfig)); // matches ConfigReloaded
    let log2 = TimedEvent::new(LanforgeEvent::Storage(StorageEvent::DbVacuum)); // filtered out
    client_ctx.log_db.record_log(&log1).await.unwrap();
    client_ctx.log_db.record_log(&log2).await.unwrap();

    let client_ctx_clone = client_ctx.clone();
    let handler_task = tokio::spawn(async move {
        handle_client(server, client_ctx_clone).await.unwrap();
    });

    // Send Log request with follow=true and filter=[ConfigReloaded]
    let req = RpcRequest::Log {
        follow: true,
        n: Some(10),
        filter: Some(vec![EventKind::ConfigReloaded]),
    };
    let payload = postcard::to_stdvec(&req).unwrap();
    let len = payload.len() as u32;
    client.write_all(&len.to_be_bytes()).await.unwrap();
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    // 1. Read first response: Log(())
    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    client.read_exact(&mut resp_buf).await.unwrap();
    let resp: RpcResponse = postcard::from_bytes(&resp_buf).unwrap();
    assert!(matches!(resp, RpcResponse::Log(())));

    // 2. Read history response (should only be log1 which matches ConfigReloaded)
    client.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    client.read_exact(&mut resp_buf).await.unwrap();
    let resp: RpcResponse = postcard::from_bytes(&resp_buf).unwrap();
    if let RpcResponse::Event(e) = resp {
        assert!(matches!(
            e.event,
            LanforgeEvent::System(SystemEvent::ReloadConfig)
        ));
    } else {
        panic!("Expected RpcResponse::Event, got {:?}", resp);
    }

    // 3. Publish dynamic live events to the bus
    let live1 = TimedEvent::new(LanforgeEvent::System(SystemEvent::ReloadConfig)); // matches filter
    let live2 = TimedEvent::new(LanforgeEvent::Storage(StorageEvent::DbVacuum)); // filtered out

    let _ = client_ctx.ctx.bus().publish(live1.event.clone());
    let _ = client_ctx.ctx.bus().publish(live2.event.clone());

    // Read live response (should only receive live1)
    client.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    client.read_exact(&mut resp_buf).await.unwrap();
    let resp: RpcResponse = postcard::from_bytes(&resp_buf).unwrap();
    if let RpcResponse::Event(e) = resp {
        assert!(matches!(
            e.event,
            LanforgeEvent::System(SystemEvent::ReloadConfig)
        ));
    } else {
        panic!("Expected RpcResponse::Event, got {:?}", resp);
    }

    // Close the connection (causing EOF in client reader)
    drop(client);
    handler_task.await.unwrap();
}
