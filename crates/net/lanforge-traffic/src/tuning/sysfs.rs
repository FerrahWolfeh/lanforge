use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

/// Writes a string value to a procfs/sysfs path asynchronously.
async fn write_sysfs_value(path: &Path, value: &str) -> std::io::Result<()> {
    fs::write(path, value.as_bytes()).await
}

/// Applies global kernel network sysctls (e.g. RFS socket flow entries).
pub async fn apply_global_sysctls(rps_sock_flow_entries: u32) {
    let proc_path = Path::new("/proc/sys/net/core/rps_sock_flow_entries");
    let val_str = format!("{rps_sock_flow_entries}\n");
    if let Err(e) = write_sysfs_value(proc_path, &val_str).await {
        debug!(
            path = %proc_path.display(),
            error = %e,
            "Could not set net.core.rps_sock_flow_entries (may require root privileges or container environment)"
        );
    } else {
        debug!(
            entries = rps_sock_flow_entries,
            "Configured net.core.rps_sock_flow_entries"
        );
    }
}

/// Discovers all matching queue files under `/sys/class/net/<iface>/queues/<pattern>/<filename>`.
async fn find_queue_files(iface: &str, queue_prefix: &str, target_filename: &str) -> Vec<PathBuf> {
    let queues_dir = PathBuf::from(format!("/sys/class/net/{iface}/queues"));
    let mut files = Vec::new();

    let Ok(mut dir) = fs::read_dir(&queues_dir).await else {
        return files;
    };

    while let Ok(Some(entry)) = dir.next_entry().await {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with(queue_prefix) {
            let target_file = entry.path().join(target_filename);
            if fs::metadata(&target_file).await.is_ok() {
                files.push(target_file);
            }
        }
    }
    files.sort();
    files
}

/// Applies RPS, RFS, and XPS settings on a network interface via sysfs.
pub async fn apply_interface_steering(
    iface: &str,
    cpu_mask: &str,
    rps_flow_cnt: u32,
) -> bool {
    let iface_path = PathBuf::from(format!("/sys/class/net/{iface}"));
    if fs::metadata(&iface_path).await.is_err() {
        debug!(iface = %iface, "Interface does not exist in sysfs, skipping steering tuning");
        return false;
    }

    let mask_str = format!("{cpu_mask}\n");
    let flow_cnt_str = format!("{rps_flow_cnt}\n");
    let mut tuned_any = false;

    // 1. RPS (Receive Packet Steering) - set on all rx-* queues
    let rx_rps_files = find_queue_files(iface, "rx-", "rps_cpus").await;
    for file in &rx_rps_files {
        match write_sysfs_value(file, &mask_str).await {
            Ok(()) => {
                debug!(iface = %iface, path = %file.display(), mask = %cpu_mask, "Applied RPS CPU mask");
                tuned_any = true;
            }
            Err(e) => {
                debug!(iface = %iface, path = %file.display(), error = %e, "Failed to write rps_cpus");
            }
        }
    }

    // 2. RFS (Receive Flow Steering) - set on all rx-* queues
    let rx_rfs_files = find_queue_files(iface, "rx-", "rps_flow_cnt").await;
    for file in &rx_rfs_files {
        match write_sysfs_value(file, &flow_cnt_str).await {
            Ok(()) => {
                debug!(iface = %iface, path = %file.display(), cnt = rps_flow_cnt, "Applied RFS flow count");
                tuned_any = true;
            }
            Err(e) => {
                debug!(iface = %iface, path = %file.display(), error = %e, "Failed to write rps_flow_cnt");
            }
        }
    }

    // 3. XPS (Transmit Packet Steering) - set on all tx-* queues if supported
    let tx_xps_files = find_queue_files(iface, "tx-", "xps_cpus").await;
    for file in &tx_xps_files {
        match write_sysfs_value(file, &mask_str).await {
            Ok(()) => {
                debug!(iface = %iface, path = %file.display(), mask = %cpu_mask, "Applied XPS CPU mask");
                tuned_any = true;
            }
            Err(e) => {
                // Common on single-queue hardware (Realtek RTL8111) which rejects XPS
                debug!(
                    iface = %iface,
                    path = %file.display(),
                    error = %e,
                    "XPS not supported by interface hardware (single-queue or driver constraint, skipped)"
                );
            }
        }
    }

    if tuned_any {
        info!(
            iface = %iface,
            rx_queues = rx_rps_files.len(),
            tx_queues = tx_xps_files.len(),
            cpu_mask = %cpu_mask,
            "Applied RPS/RFS packet steering optimizations"
        );
    }

    tuned_any
}
