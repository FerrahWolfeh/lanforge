pub mod cpu;
pub mod ethtool;
pub mod sysfs;

use lanforge_types::network::NicTuningConfig;
use tracing::info;

/// Applies complete NIC tuning profile according to configuration.
pub async fn apply_tuning(cfg: &NicTuningConfig, default_ifaces: &[String]) -> Vec<String> {
    if !cfg.enabled {
        return Vec::new();
    }

    // 1. Global sysctls
    sysfs::apply_global_sysctls(cfg.rps_flow_entries).await;

    // 2. Resolve target interfaces
    let target_ifaces: Vec<String> = if cfg.interfaces.is_empty() {
        default_ifaces.to_vec()
    } else {
        cfg.interfaces.clone()
    };

    let cpu_mask = cpu::resolve_effective_cpu_mask(&cfg.cpu_mask);
    let mut tuned = Vec::new();

    for iface in &target_ifaces {
        let iface = iface.trim();
        if iface.is_empty() {
            continue;
        }

        // Apply EEE
        if cfg.disable_eee {
            ethtool::disable_eee(iface).await;
        }

        // Apply Ring Buffers
        ethtool::apply_ring_buffers(iface, &cfg.rx_ring, &cfg.tx_ring).await;

        // Apply RPS / RFS / XPS steering
        if sysfs::apply_interface_steering(iface, &cpu_mask, cfg.rps_flow_cnt).await {
            tuned.push(iface.to_string());
        }

        // Apply UDP GRO Forwarding
        if cfg.udp_gro_forwarding {
            ethtool::apply_udp_gro_forwarding(iface).await;
        }
    }

    if !tuned.is_empty() {
        info!(
            interfaces = ?tuned,
            cpu_mask = %cpu_mask,
            "NIC optimizations successfully applied"
        );
    }

    tuned
}
