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
    // Check if already configured to avoid write syscalls or container permissions issues
    if let Ok(current) = fs::read_to_string(proc_path).await
        && current.trim() == rps_sock_flow_entries.to_string()
    {
        debug!(
            entries = rps_sock_flow_entries,
            "net.core.rps_sock_flow_entries already configured"
        );
        return;
    }

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

/// Applies RPS, RFS, and XPS settings on a network interface via sysfs in a single directory pass.
pub async fn apply_interface_steering(iface: &str, cpu_mask: &str, rps_flow_cnt: u32) -> bool {
    let queues_dir = PathBuf::from(format!("/sys/class/net/{iface}/queues"));
    let Ok(mut dir) = fs::read_dir(&queues_dir).await else {
        debug!(iface = %iface, "Interface queues directory does not exist, skipping steering tuning");
        return false;
    };

    let mask_str = format!("{cpu_mask}\n");
    let flow_cnt_str = format!("{rps_flow_cnt}\n");
    let mut tuned_any = false;
    let mut rx_queues = 0usize;
    let mut tx_queues = 0usize;

    while let Ok(Some(entry)) = dir.next_entry().await {
        let file_name = entry.file_name();
        let name_bytes = file_name.as_encoded_bytes();

        if name_bytes.starts_with(b"rx-") {
            rx_queues += 1;
            let q_path = entry.path();

            // 1. RPS (Receive Packet Steering)
            let rps_path = q_path.join("rps_cpus");
            if write_sysfs_value(&rps_path, &mask_str).await.is_ok() {
                debug!(iface = %iface, path = %rps_path.display(), mask = %cpu_mask, "Applied RPS CPU mask");
                tuned_any = true;
            }

            // 2. RFS (Receive Flow Steering)
            let rfs_path = q_path.join("rps_flow_cnt");
            if write_sysfs_value(&rfs_path, &flow_cnt_str).await.is_ok() {
                debug!(iface = %iface, path = %rfs_path.display(), cnt = rps_flow_cnt, "Applied RFS flow count");
                tuned_any = true;
            }
        } else if name_bytes.starts_with(b"tx-") {
            tx_queues += 1;
            // 3. XPS (Transmit Packet Steering)
            let xps_path = entry.path().join("xps_cpus");
            match write_sysfs_value(&xps_path, &mask_str).await {
                Ok(()) => {
                    debug!(iface = %iface, path = %xps_path.display(), mask = %cpu_mask, "Applied XPS CPU mask");
                    tuned_any = true;
                }
                Err(e) => {
                    // Common on single-queue hardware (Realtek RTL8111) which rejects XPS
                    debug!(
                        iface = %iface,
                        path = %xps_path.display(),
                        error = %e,
                        "XPS not supported by interface hardware (single-queue or driver constraint, skipped)"
                    );
                }
            }
        }
    }

    if tuned_any {
        info!(
            iface = %iface,
            rx_queues,
            tx_queues,
            cpu_mask = %cpu_mask,
            "Applied RPS/RFS packet steering optimizations"
        );
    }

    tuned_any
}
