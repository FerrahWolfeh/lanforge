use super::cake::build_cake_args;
use super::ifb::{resolve_ifb_name, setup_ifb, teardown_ifb};
use lanforge_types::network::SqmConfig;
use std::path::Path;
use std::sync::OnceLock;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Resolves the absolute path to the `tc` binary, searching common sbin/bin locations.
pub fn resolve_tc_binary() -> &'static str {
    static TC_PATH: OnceLock<&'static str> = OnceLock::new();
    TC_PATH.get_or_init(|| {
        for candidate in ["/usr/sbin/tc", "/sbin/tc", "/usr/bin/tc", "/bin/tc"] {
            if Path::new(candidate).exists() {
                return candidate;
            }
        }
        "tc"
    })
}

/// Helper to execute a `tc` command and check the result.
async fn run_tc(args: &[&str]) -> bool {
    let tc_bin = resolve_tc_binary();
    let res = Command::new(tc_bin).args(args).output().await;

    match res {
        Ok(out) => {
            if out.status.success() {
                true
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                debug!(args = ?args, stderr = %stderr.trim(), "tc command notice");
                false
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                warn!(
                    args = ?args,
                    "Traffic Control binary 'tc' not found. If running Fedora/RHEL, please install it via: 'sudo dnf install -y iproute-tc'. On Debian/Ubuntu: 'sudo apt install -y iproute2'."
                );
            } else {
                warn!(args = ?args, error = %e, "Could not execute tc binary");
            }
            false
        }
    }
}

/// Applies SQM (CAKE) on the specified WAN interface and an associated IFB device.
pub async fn apply_sqm(wan_iface: &str, cfg: &SqmConfig, is_pppoe: bool) -> Option<String> {
    if !cfg.enabled {
        return None;
    }

    info!(
        wan = %wan_iface,
        download_mbps = cfg.download_mbps,
        upload_mbps = cfg.upload_mbps,
        is_pppoe = is_pppoe,
        "Applying SQM (CAKE) traffic shaper"
    );

    // 1. Egress Shaping on WAN interface
    let egress_cake_args = build_cake_args(cfg, cfg.upload_mbps, false, is_pppoe);
    let mut egress_cmd = Vec::with_capacity(6 + egress_cake_args.len());
    egress_cmd.extend_from_slice(&["qdisc", "replace", "dev", wan_iface, "root", "cake"]);
    for arg in &egress_cake_args {
        egress_cmd.push(arg.as_str());
    }

    if run_tc(&egress_cmd).await {
        debug!(wan = %wan_iface, "Attached CAKE to WAN egress");
    } else {
        warn!(wan = %wan_iface, "Failed to apply CAKE qdisc to WAN egress");
    }

    // 2. Ingress Shaping via IFB device
    let ifb_name = resolve_ifb_name(wan_iface, &cfg.ingress_device);
    if setup_ifb(&ifb_name).await {
        // Clear any old ingress qdisc on WAN
        let _ = run_tc(&["qdisc", "del", "dev", wan_iface, "ingress"]).await;

        // Add ingress qdisc handle ffff:
        if run_tc(&[
            "qdisc", "add", "dev", wan_iface, "handle", "ffff:", "ingress",
        ])
        .await
        {
            // Add redirect filter to IFB
            let filter_args = [
                "filter", "replace", "dev", wan_iface, "parent", "ffff:", "protocol", "all",
                "prio", "10", "u32", "match", "u32", "0", "0", "flowid", "1:1", "action", "mirred",
                "egress", "redirect", "dev", &ifb_name,
            ];

            if run_tc(&filter_args).await {
                // Attach CAKE to IFB root
                let ingress_cake_args = build_cake_args(cfg, cfg.download_mbps, true, is_pppoe);
                let mut ingress_cmd = Vec::with_capacity(6 + ingress_cake_args.len());
                ingress_cmd
                    .extend_from_slice(&["qdisc", "replace", "dev", &ifb_name, "root", "cake"]);
                for arg in &ingress_cake_args {
                    ingress_cmd.push(arg.as_str());
                }

                if run_tc(&ingress_cmd).await {
                    info!(
                        wan = %wan_iface,
                        ifb = %ifb_name,
                        "Attached CAKE to Ingress IFB mirror successfully"
                    );
                    return Some(ifb_name);
                }
                warn!(ifb = %ifb_name, "Failed to attach CAKE to IFB root");
            } else {
                warn!(wan = %wan_iface, ifb = %ifb_name, "Failed to attach mirred redirect filter");
            }
        } else {
            warn!(wan = %wan_iface, "Failed to add ingress qdisc handle ffff:");
        }
    }

    None
}

/// Removes SQM qdiscs from the WAN interface and destroys the IFB device.
pub async fn clear_sqm(wan_iface: &str, configured_ifb: &str) {
    let ifb_name = resolve_ifb_name(wan_iface, configured_ifb);

    info!(wan = %wan_iface, ifb = %ifb_name, "Clearing SQM queues and IFB mirror");

    let _ = run_tc(&["qdisc", "del", "dev", wan_iface, "root"]).await;
    let _ = run_tc(&["qdisc", "del", "dev", wan_iface, "ingress"]).await;
    let _ = run_tc(&["qdisc", "del", "dev", &ifb_name, "root"]).await;

    teardown_ifb(&ifb_name).await;
}
