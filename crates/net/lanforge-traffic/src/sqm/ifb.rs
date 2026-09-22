use std::path::Path;
use std::sync::OnceLock;
use tokio::process::Command;
use tracing::{debug, warn};

/// Resolves the absolute path to the `ip` binary.
fn resolve_ip_binary() -> &'static str {
    static IP_PATH: OnceLock<&'static str> = OnceLock::new();
    IP_PATH.get_or_init(|| {
        for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
            if Path::new(candidate).exists() {
                return candidate;
            }
        }
        "ip"
    })
}

/// Resolves the absolute path to the `modprobe` binary.
fn resolve_modprobe_binary() -> &'static str {
    static MODPROBE_PATH: OnceLock<&'static str> = OnceLock::new();
    MODPROBE_PATH.get_or_init(|| {
        for candidate in [
            "/usr/sbin/modprobe",
            "/sbin/modprobe",
            "/usr/bin/modprobe",
            "/bin/modprobe",
        ] {
            if Path::new(candidate).exists() {
                return candidate;
            }
        }
        "modprobe"
    })
}

/// Derives a clean, standard Linux IFB device name (max 15 characters).
#[must_use]
pub fn resolve_ifb_name(iface: &str, configured: &str) -> String {
    let trimmed = configured.trim();
    if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("auto") {
        return trimmed.to_string();
    }

    let mut candidate = format!("ifb4{iface}");
    if let Some((idx, _)) = candidate.char_indices().nth(15) {
        candidate.truncate(idx);
    }
    candidate
}

/// Prepares and activates an IFB interface for ingress queue redirection.
pub async fn setup_ifb(ifb_name: &str) -> bool {
    let modprobe_bin = resolve_modprobe_binary();
    let ip_bin = resolve_ip_binary();

    // 1. Ensure kernel module is loaded
    let _ = Command::new(modprobe_bin)
        .args(["ifb", "numifbs=0"])
        .output()
        .await;

    // 2. Create the virtual IFB link (idempotent; ignores EEXIST)
    let add_res = Command::new(ip_bin)
        .args(["link", "add", "name", ifb_name, "type", "ifb"])
        .output()
        .await;

    if let Ok(out) = add_res
        && !out.status.success()
    {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.contains("File exists") {
            warn!(
                ifb = %ifb_name,
                stderr = %stderr.trim(),
                "Failed to create virtual IFB link (ensure 'ifb' kernel module is loaded: 'sudo modprobe ifb')"
            );
        }
    }

    // 3. Bring IFB interface UP
    let up_res = Command::new(ip_bin)
        .args(["link", "set", "dev", ifb_name, "up"])
        .output()
        .await;

    match up_res {
        Ok(out) => {
            if out.status.success() {
                debug!(ifb = %ifb_name, "IFB device is UP");
                true
            } else {
                warn!(
                    ifb = %ifb_name,
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "Failed to bring IFB device UP"
                );
                false
            }
        }
        Err(e) => {
            warn!(ifb = %ifb_name, error = %e, "Could not execute ip command to raise IFB");
            false
        }
    }
}

/// Tears down and deletes an IFB interface.
pub async fn teardown_ifb(ifb_name: &str) {
    let ip_bin = resolve_ip_binary();

    let _ = Command::new(ip_bin)
        .args(["link", "set", "dev", ifb_name, "down"])
        .output()
        .await;

    let _ = Command::new(ip_bin)
        .args(["link", "del", "dev", ifb_name])
        .output()
        .await;

    debug!(ifb = %ifb_name, "Removed IFB device");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_ifb_name() {
        assert_eq!(resolve_ifb_name("ppp0", "auto"), "ifb4ppp0");
        assert_eq!(resolve_ifb_name("wan0", ""), "ifb4wan0");
        assert_eq!(resolve_ifb_name("eth1", "custom-ifb"), "custom-ifb");
        assert_eq!(resolve_ifb_name("verylonginterfacename", "auto").len(), 15);
    }
}
