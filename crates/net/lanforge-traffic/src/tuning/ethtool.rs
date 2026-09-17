use std::path::Path;
use std::sync::OnceLock;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Resolves the absolute path to the `ethtool` binary, searching common sbin/bin locations.
fn resolve_ethtool_binary() -> &'static str {
    static ETHTOOL_PATH: OnceLock<&'static str> = OnceLock::new();
    ETHTOOL_PATH.get_or_init(|| {
        for candidate in [
            "/usr/sbin/ethtool",
            "/sbin/ethtool",
            "/usr/bin/ethtool",
            "/bin/ethtool",
        ] {
            if Path::new(candidate).exists() {
                return candidate;
            }
        }
        "ethtool"
    })
}

/// Parsed ring parameters from `ethtool -g`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RingParameters {
    pub max_rx: Option<u32>,
    pub max_tx: Option<u32>,
    pub current_rx: Option<u32>,
    pub current_tx: Option<u32>,
}

pub type RingMaximums = RingParameters;

/// Queries pre-set and current ring buffer sizes from `ethtool -g <iface>`.
pub async fn query_ring_parameters(iface: &str) -> Option<RingParameters> {
    let ethtool_bin = resolve_ethtool_binary();
    let output = Command::new(ethtool_bin)
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

pub async fn query_max_ring_buffers(iface: &str) -> Option<RingParameters> {
    query_ring_parameters(iface).await
}

/// Parses the output of `ethtool -g` for both pre-set maximums and current hardware settings.
#[must_use]
pub fn parse_ethtool_g_output(stdout: &str) -> Option<RingParameters> {
    let mut in_max_section = false;
    let mut in_current_section = false;
    let mut max_rx = None;
    let mut max_tx = None;
    let mut current_rx = None;
    let mut current_tx = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Pre-set maximums:") {
            in_max_section = true;
            in_current_section = false;
            continue;
        }
        if trimmed.starts_with("Current hardware settings:") {
            in_max_section = false;
            in_current_section = true;
            continue;
        }
        if in_max_section {
            if let Some(val_str) = trimmed.strip_prefix("RX:")
                && let Ok(num) = val_str.trim().parse::<u32>()
            {
                max_rx = Some(num);
            } else if let Some(val_str) = trimmed.strip_prefix("TX:")
                && let Ok(num) = val_str.trim().parse::<u32>()
            {
                max_tx = Some(num);
            }
        } else if in_current_section {
            if let Some(val_str) = trimmed.strip_prefix("RX:")
                && let Ok(num) = val_str.trim().parse::<u32>()
            {
                current_rx = Some(num);
            } else if let Some(val_str) = trimmed.strip_prefix("TX:")
                && let Ok(num) = val_str.trim().parse::<u32>()
            {
                current_tx = Some(num);
            }
        }
    }

    if max_rx.is_some() || max_tx.is_some() || current_rx.is_some() || current_tx.is_some() {
        Some(RingParameters {
            max_rx,
            max_tx,
            current_rx,
            current_tx,
        })
    } else {
        None
    }
}

/// Applies ring buffer optimization (querying hardware limit if set to "auto").
///
/// If the interface already has the target ring sizes configured, skips reconfiguration
/// to avoid tearing down the link / causing carrier flaps on active connections (e.g. `PPPoE`).
pub async fn apply_ring_buffers(iface: &str, rx_ring: &str, tx_ring: &str) {
    let hardware_params = query_ring_parameters(iface).await;

    let target_rx = resolve_ring_size(rx_ring, hardware_params.and_then(|m| m.max_rx));
    let target_tx = resolve_ring_size(tx_ring, hardware_params.and_then(|m| m.max_tx));

    let rx_val = target_rx.unwrap_or(1024);
    let tx_val = target_tx.unwrap_or(1024);

    // If current hardware settings already match target values, avoid resetting the NIC!
    if let Some(params) = hardware_params
        && params.current_rx == Some(rx_val)
        && params.current_tx == Some(tx_val)
    {
        debug!(
            iface = %iface,
            rx = rx_val,
            tx = tx_val,
            "NIC ring buffers already configured to target values (skipping driver reinit)"
        );
        return;
    }

    info!(
        iface = %iface,
        rx = rx_val,
        tx = tx_val,
        "Configuring NIC ring buffers (driver may briefly renegotiate link)"
    );

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
    let ethtool_bin = resolve_ethtool_binary();
    let res = Command::new(ethtool_bin)
        .args(["-G", iface, "rx", &rx.to_string(), "tx", &tx.to_string()])
        .output()
        .await;

    match res {
        Ok(out) => out.status.success(),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                warn!("ethtool binary not found. Please install ethtool ('sudo dnf install -y ethtool' on Fedora)");
            }
            false
        }
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

/// Parses the output of `ethtool --show-eee` to determine if EEE is enabled.
#[must_use]
pub fn parse_ethtool_eee_status(stdout: &str) -> Option<bool> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("EEE status:") {
            if trimmed.contains("enabled") {
                return Some(true);
            }
            if trimmed.contains("disabled") {
                return Some(false);
            }
        }
    }
    None
}

/// Queries whether EEE is currently enabled on the interface.
pub async fn is_eee_enabled(iface: &str) -> Option<bool> {
    let ethtool_bin = resolve_ethtool_binary();
    let output = Command::new(ethtool_bin)
        .args(["--show-eee", iface])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ethtool_eee_status(&stdout)
}

/// Disables Energy Efficient Ethernet (EEE) to avoid link renegotiation or 100Mbps drops.
/// Checks current state first to avoid triggering unnecessary PHY resets when already disabled.
pub async fn disable_eee(iface: &str) {
    if is_eee_enabled(iface).await == Some(false) {
        debug!(iface = %iface, "EEE is already disabled by driver/hardware");
        return;
    }

    let ethtool_bin = resolve_ethtool_binary();
    let res = Command::new(ethtool_bin)
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
            if e.kind() == std::io::ErrorKind::NotFound {
                warn!("ethtool binary not found. Please install ethtool ('sudo dnf install -y ethtool' on Fedora)");
            } else {
                debug!(iface = %iface, error = %e, "Could not run ethtool to toggle EEE");
            }
        }
    }
}

/// Enables UDP GRO forwarding (accelerates WireGuard/Tailscale/QUIC throughput).
pub async fn apply_udp_gro_forwarding(iface: &str) {
    let ethtool_bin = resolve_ethtool_binary();
    let res = Command::new(ethtool_bin)
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
        assert_eq!(parsed.max_rx, Some(256));
        assert_eq!(parsed.max_tx, Some(256));
        assert_eq!(parsed.current_rx, Some(256));
        assert_eq!(parsed.current_tx, Some(256));
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
        assert_eq!(parsed.max_rx, Some(1024));
        assert_eq!(parsed.max_tx, Some(1024));
        assert_eq!(parsed.current_rx, Some(512));
        assert_eq!(parsed.current_tx, Some(512));
    }

    #[test]
    fn test_parse_ethtool_eee_status() {
        let enabled_sample = r#"
ETHTOOL_GEEE:
	Supported EEE link modes:  1000baseT/Full
	Advertised EEE link modes:  1000baseT/Full
	Link partner advertised EEE link modes:  1000baseT/Full
	EEE status: enabled - active
	Tx LPI: 17 (us)
"#;
        assert_eq!(parse_ethtool_eee_status(enabled_sample), Some(true));

        let disabled_sample = r#"
ETHTOOL_GEEE:
	Supported EEE link modes:  1000baseT/Full
	Advertised EEE link modes:  Not reported
	Link partner advertised EEE link modes:  Not reported
	EEE status: disabled
"#;
        assert_eq!(parse_ethtool_eee_status(disabled_sample), Some(false));
    }
}
