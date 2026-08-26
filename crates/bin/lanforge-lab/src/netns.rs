use std::process::Command;
use tracing::{debug, info, warn};

use crate::error::LabError;

/// Configuration and state for a managed network namespace pair.
#[derive(Debug, Clone)]
pub struct NetnsConfig {
    pub netns_name: String,
    pub host_iface: String,
    pub client_iface: String,
    pub host_ipv4: String,
    pub client_ipv4: String,
}

impl Default for NetnsConfig {
    fn default() -> Self {
        Self {
            netns_name: "lf-lab-ns".to_string(),
            host_iface: "veth-lf-host".to_string(),
            client_iface: "veth-lf-cli".to_string(),
            host_ipv4: "192.168.100.1/24".to_string(),
            client_ipv4: "192.168.100.2/24".to_string(),
        }
    }
}

/// Linux Network Namespace Manager.
///
/// Creates isolated `veth` pairs and configures network namespaces for realistic
/// L2/L3 testing. Automatically cleans up on `Drop` if configured.
pub struct NetnsManager {
    cfg: NetnsConfig,
    active: bool,
    auto_cleanup: bool,
}

impl NetnsManager {
    /// Creates a new `NetnsManager` without bringing it up yet.
    #[must_use]
    pub const fn new(cfg: NetnsConfig, auto_cleanup: bool) -> Self {
        Self {
            cfg,
            active: false,
            auto_cleanup,
        }
    }

    /// Checks if the current process has `root/CAP_NET_ADMIN` privileges.
    #[must_use]
    pub fn has_privileges() -> bool {
        crate::is_root()
    }

    /// Sets up the virtual network namespace and veth pair.
    pub fn setup(&mut self) -> Result<(), LabError> {
        if !Self::has_privileges() {
            return Err(LabError::RootRequired(
                "Kernel Network Namespace (netns) mode requires root privileges (sudo / CAP_NET_ADMIN).".to_string(),
            ));
        }

        info!(
            "Netns: Creating namespace '{}' with veth pair ({} <-> {})...",
            self.cfg.netns_name, self.cfg.host_iface, self.cfg.client_iface
        );

        // 1. Cleanup any stale namespace or interface
        self.cleanup_quiet();

        // 2. Create netns and veth pair
        Self::run_cmd("ip", &["netns", "add", &self.cfg.netns_name])?;
        Self::run_cmd(
            "ip",
            &[
                "link",
                "add",
                &self.cfg.host_iface,
                "type",
                "veth",
                "peer",
                "name",
                &self.cfg.client_iface,
            ],
        )?;

        // 3. Move client interface into namespace
        Self::run_cmd(
            "ip",
            &[
                "link",
                "set",
                &self.cfg.client_iface,
                "netns",
                &self.cfg.netns_name,
            ],
        )?;

        // 4. Configure host interface
        Self::run_cmd(
            "ip",
            &["addr", "add", &self.cfg.host_ipv4, "dev", &self.cfg.host_iface],
        )?;
        Self::run_cmd("ip", &["link", "set", &self.cfg.host_iface, "up"])?;

        // 5. Configure client namespace loopback and link
        Self::run_cmd_in_netns(&self.cfg.netns_name, "ip", &["link", "set", "lo", "up"])?;
        Self::run_cmd_in_netns(
            &self.cfg.netns_name,
            "ip",
            &["link", "set", &self.cfg.client_iface, "up"],
        )?;

        self.active = true;
        info!(
            "Netns: Virtual lab environment ready on '{}' (Host: {})",
            self.cfg.host_iface, self.cfg.host_ipv4
        );
        Ok(())
    }

    /// Destroys the veth interfaces and namespace.
    pub fn teardown(&mut self) -> Result<(), LabError> {
        if !self.active {
            return Ok(());
        }

        debug!("Netns: Tearing down virtual lab environment...");
        self.cleanup_quiet();
        self.active = false;
        info!("Netns: Virtual lab environment cleaned up");
        Ok(())
    }

    fn cleanup_quiet(&self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.cfg.host_iface])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.cfg.netns_name])
            .output();
    }

    fn run_cmd(prog: &str, args: &[&str]) -> Result<(), LabError> {
        let output = Command::new(prog)
            .args(args)
            .output()
            .map_err(|e| LabError::Netns(format!("Failed to execute {prog}: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(LabError::Netns(format!(
                "{prog} {} failed: {stderr}",
                args.join(" ")
            )));
        }
        Ok(())
    }

    fn run_cmd_in_netns(netns: &str, prog: &str, args: &[&str]) -> Result<(), LabError> {
        let mut full_args = vec!["netns", "exec", netns, prog];
        full_args.extend_from_slice(args);

        let output = Command::new("ip")
            .args(&full_args)
            .output()
            .map_err(|e| LabError::Netns(format!("Failed to exec in netns {netns}: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(LabError::Netns(format!(
                "ip netns exec {netns} {prog} failed: {stderr}"
            )));
        }
        Ok(())
    }

    #[must_use]
    pub const fn config(&self) -> &NetnsConfig {
        &self.cfg
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for NetnsManager {
    fn drop(&mut self) {
        if self.active && self.auto_cleanup && let Err(e) = self.teardown() {
            warn!("Netns drop cleanup error: {e}");
        }
    }
}
