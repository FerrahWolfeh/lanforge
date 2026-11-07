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

/// The runtime database lives on tmpfs to be lost on reboot, but must survive a daemon restart,
/// including one that never closes the database (crash, watchdog kill, exit with live `Arc`s):
/// with `Durability::None` only a clean close wrote the last commits to the file. A child
/// process writes and exits without closing the database (`process::exit` runs no destructor,
/// like a crash, but leaves no core dump behind); this test then reopens the same file.
#[test]
fn test_runtime_db_survives_a_daemon_crash() {
    use lanforge_types::device::Device;
    use lanforge_types::events::{LanforgeEvent, SystemEvent, TimedEvent};
    use lanforge_types::identifiers::MacAddr;
    use std::env;
    use std::path::Path;
    use std::process::{self, Command};
    use std::sync::Arc;

    const CHILD: &str = "LANFORGE_TEST_RUNTIME_DB_CHILD";
    const CHILD_EXIT: i32 = 42;
    if let Ok(path) = env::var(CHILD) {
        let log_db = LogDb::open(&path).unwrap();
        assert_eq!(log_db.path(), Some(Path::new(&path)));
        log_db
            .record_log(&TimedEvent::new(LanforgeEvent::System(
                SystemEvent::SystemReady,
            )))
            .unwrap();
        let device = Device::new(MacAddr([0x02, 0, 0, 0, 0, 0x42]));
        log_db
            .sync_runtime_devices(&[Arc::new(device)], &[])
            .unwrap();
        process::exit(CHILD_EXIT);
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("runtime.redb");
    let status = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::test_runtime_db_survives_a_daemon_crash",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(CHILD_EXIT),
        "the child exits after writing"
    );

    let path = path.to_str().unwrap();
    let log_db = LogDb::open(path).unwrap();
    assert_eq!(
        log_db.path(),
        Some(Path::new(path)),
        "reopened the same file"
    );
    assert_eq!(log_db.schema_version().unwrap(), 1);
    assert_eq!(log_db.get_history(10).unwrap().len(), 1);
    assert_eq!(log_db.load_runtime_devices().unwrap().len(), 1);
}
