use crate::log_engine::LogDb;
use lanforge_db_core::LogStore;

#[tokio::test]
async fn test_log_db_in_memory() {
    let log_db = LogDb::open(":memory:").unwrap();
    let (history, total) = log_db
        .get_dns_query_history(10, None, None, None, None, None)
        .unwrap();
    assert_eq!(total, 0);
    assert_eq!(history.len(), 0);
}

#[tokio::test]
async fn test_lanforge_db_schema_version() {
    let db = crate::LanforgeDb::open_in_memory().unwrap();
    assert_eq!(db.schema_version().unwrap(), 4);

    let log_db = LogDb::open(":memory:").unwrap();
    assert_eq!(log_db.schema_version().unwrap(), 1);
}
