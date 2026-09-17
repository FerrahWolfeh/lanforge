use tokio::process::Command;
use tracing::{debug, info};

/// Parsed maximum ring parameters from `ethtool -g`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingMaximums {
    pub rx: Option<u32>,
    pub tx: Option<u32>,
}

/// Queries pre-set maximum ring buffer sizes from `ethtool -g <iface>`.
pub async fn query_max_ring_buffers(iface: &str) -> Option<RingMaximums> {
    let output = Command::new("ethtool")
        .args(["-g", iface])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ethtool_g_output(&stdout)
}

/// Parses the output of `ethtool -g`.
#[must_use]
pub fn parse_ethtool_g_output(stdout: &str) -> Option<RingMaximums> {
    let mut in_max_section = false;
    let mut rx_max = None;
    let mut tx_max = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Pre-set maximums:") {
            in_max_section = true;
            continue;
        }
        if in_max_section && trimmed.starts_with("Current hardware settings:") {
            break;
        }
        if in_max_section {
            if let Some(val_str) = trimmed.strip_prefix("RX:") {
                let val_str = val_str.trim();
                if let Ok(num) = val_str.parse::<u32>() {
                    rx_max = Some(num);
                }
            } else if let Some(val_str) = trimmed.strip_prefix("TX:") {
                let val_str = val_str.trim();
                if let Ok(num) = val_str.parse::<u32>() {
                    tx_max = Some(num);
                }
            }
        }
    }

    if rx_max.is_some() || tx_max.is_some() {
        Some(RingMaximums { rx: rx_max, tx: tx_max })
    } else {
        None
    }
}

/// Applies ring buffer optimization (querying hardware limit if set to "auto").
pub async fn apply_ring_buffers(iface: &str, rx_ring: &str, tx_ring: &str) {
    let hardware_max = query_max_ring_buffers(iface).await;

    let target_rx = resolve_ring_size(rx_ring, hardware_max.and_then(|m| m.rx));
    let target_tx = resolve_ring_size(tx_ring, hardware_max.and_then(|m| m.tx));

    let rx_val = target_rx.unwrap_or(1024);
    let tx_val = target_tx.unwrap_or(1024);

    // Attempt target values
    if run_ethtool_ring(iface, rx_val, tx_val).await {
        info!(iface = %iface, rx = rx_val, tx = tx_val, "Configured NIC ring buffers");
        return;
    }

    // Fallback attempts if driver rejected maximum (e.g. 512 or 256)
    for fallback in [512, 256] {
        if (rx_val > fallback || tx_val > fallback)
            && run_ethtool_ring(iface, fallback, fallback).await
        {
            info!(iface = %iface, rx = fallback, tx = fallback, "Configured fallback ring buffers");
            return;
        }
    }
}

async fn run_ethtool_ring(iface: &str, rx: u32, tx: u32) -> bool {
    let res = Command::new("ethtool")
        .args(["-G", iface, "rx", &rx.to_string(), "tx", &tx.to_string()])
        .output()
        .await;

    match res {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn resolve_ring_size(cfg: &str, hw_max: Option<u32>) -> Option<u32> {
    let trimmed = cfg.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
        hw_max
    } else {
        trimmed.parse::<u32>().ok().or(hw_max)
    }
}

/// Disables Energy Efficient Ethernet (EEE) to avoid link renegotiation or 100Mbps drops.
pub async fn disable_eee(iface: &str) {
    let res = Command::new("ethtool")
        .args(["--set-eee", iface, "eee", "off"])
        .output()
        .await;

    match res {
        Ok(out) => {
            if out.status.success() {
                debug!(iface = %iface, "Disabled Energy Efficient Ethernet (EEE)");
            } else {
                debug!(
                    iface = %iface,
                    "EEE setting not supported or already disabled by driver"
                );
            }
        }
        Err(e) => {
            debug!(iface = %iface, error = %e, "Could not run ethtool to toggle EEE");
        }
    }
}

/// Enables UDP GRO forwarding (accelerates WireGuard/Tailscale/QUIC throughput).
pub async fn apply_udp_gro_forwarding(iface: &str) {
    let res = Command::new("ethtool")
        .args(["-K", iface, "rx-udp-gro-forwarding", "on", "rx-gro-list", "off"])
        .output()
        .await;

    match res {
        Ok(out) => {
            if out.status.success() {
                debug!(iface = %iface, "Enabled rx-udp-gro-forwarding");
            } else {
                debug!(
                    iface = %iface,
                    "rx-udp-gro-forwarding not supported on this kernel/driver (skipped)"
                );
            }
        }
        Err(e) => {
            debug!(iface = %iface, error = %e, "Could not run ethtool for offloads");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethtool_g_output() {
        let sample = r#"
Ring parameters for enp39s0:
Pre-set maximums:
RX:			256
RX Mini:		n/a
RX Jumbo:		n/a
TX:			256
TX push buff len:	n/a
HDS thresh:		n/a
Current hardware settings:
RX:			256
RX Mini:		n/a
RX Jumbo:		n/a
TX:			256
"#;
        let parsed = parse_ethtool_g_output(sample).unwrap();
        assert_eq!(parsed.rx, Some(256));
        assert_eq!(parsed.tx, Some(256));
    }

    #[test]
    fn test_parse_ethtool_g_output_large() {
        let sample = r#"
Ring parameters for eth0:
Pre-set maximums:
RX:			1024
TX:			1024
Current hardware settings:
RX:			512
TX:			512
"#;
        let parsed = parse_ethtool_g_output(sample).unwrap();
        assert_eq!(parsed.rx, Some(1024));
        assert_eq!(parsed.tx, Some(1024));
    }
}
