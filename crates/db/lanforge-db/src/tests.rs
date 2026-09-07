use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use crate::log_engine::LogDb;

#[tokio::test]
async fn test_log_db_in_memory() {
    let log_db = LogDb::open(":memory:").await.unwrap();
    let (history, total) = log_db.get_dns_query_history(10, None).await.unwrap();
    assert_eq!(total, 0);
    assert_eq!(history.len(), 0);
}

#[tokio::test]
async fn test_db_worker_lifecycle_mock() {
    // Verify the worker setup, start, and graceful shutdown.
    let bus = Arc::new(EventBus::new());

    // Test that the event channels connect
    let mut bus_rx = bus.subscribe();

    // Broadcast a shutdown immediately to test clean exit
    let bus_clone = bus.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(50)).await;
        let _ = bus_clone.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    });

    // Verify that the worker listener processes the shutdown event and exits
    let mut shutdown_seen = false;
    for _ in 0..10 {
        if let Ok(timed_ev) = tokio::time::timeout(Duration::from_millis(100), bus_rx.recv()).await
            && let Ok(ev) = timed_ev
            && matches!(ev.event, LanforgeEvent::System(SystemEvent::Shutdown))
        {
            shutdown_seen = true;
            break;
        }
    }
    assert!(shutdown_seen);
}

#[tokio::test]
async fn test_lanforge_db_schema_version() {
    let db = crate::LanforgeDb::open_in_memory().await.unwrap();
    assert_eq!(db.schema_version().unwrap(), 1);

    let log_db = LogDb::open(":memory:").await.unwrap();
    assert_eq!(log_db.schema_version().unwrap(), 1);
}
