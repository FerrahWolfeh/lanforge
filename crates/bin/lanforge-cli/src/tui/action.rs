use lanforge_api::api::HostConfigEntry;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::adblock::{AdblockUrlKind, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::system::ServiceAction;

/// A pending action waiting for confirmation.
#[derive(Debug, Clone)]
pub enum PendingAction {
    // System

    Reload,
    Shutdown,
    DnsCacheFlush,

    // Device
    Wol {
        mac: MacAddr,
        hostname: String,
    },
    Purge {
        mac: MacAddr,
        hostname: String,
    },

    // Adblock
    AdblockToggle {
        enable: bool,
    },
    AdblockTimedDisable {
        duration_secs: u64,
    },
    AdblockReload,
    AdblockAllow {
        domain: String,
    },
    AdblockUnallow {
        domain: String,
    },
    AdblockBlock {
        domain: String,
    },

    // DHCP
    LeaseRenew {
        mac: MacAddr,
        hostname: String,
    },
    LeaseRelease {
        mac: MacAddr,
        hostname: String,
    },

    // DNS Rewrites
    DnsRewriteAdd {
        rule: RewriteRule,
    },
    DnsRewriteRemove {
        id: i64,
        domain: String,
    },

    // Hosts Management
    HostAdd {
        entry: HostConfigEntry,
    },
    HostRemove {
        mac: MacAddr,
        hostname: String,
    },

    // Upstreams Management
    DnsUpstreamAdd {
        target: UpstreamTarget,
    },
    DnsUpstreamRemove {
        target: UpstreamTarget,
    },

    // Adblock Sources Management
    AdblockSourceAdd {
        url: String,
        kind: AdblockUrlKind,
    },
    AdblockSourceRemove {
        url: String,
    },

    // Services Control
    ServiceControl {
        id: String,
        name: String,
        action: ServiceAction,
    },
}

/// Result of an async action, delivered back to the TUI via `AppEvent`.
#[derive(Debug, Clone)]
pub enum ActionResult {
    Success(String),
    Error(String),
}

impl PendingAction {
    #[must_use]
    pub const fn title(&self) -> &'static str {
        match self {

            Self::Reload => "Reload Daemon",
            Self::Shutdown => "Shutdown Daemon",
            Self::DnsCacheFlush => "Flush DNS Cache",
            Self::Wol { .. } => "Wake on LAN",
            Self::Purge { .. } => "Purge Device",
            Self::AdblockToggle { enable: true } => "Enable Adblock",
            Self::AdblockToggle { enable: false } => "Disable Adblock",
            Self::AdblockTimedDisable { .. } => "Temporarily Disable Adblock",
            Self::AdblockReload => "Reload Adblock Rules",
            Self::AdblockAllow { .. } => "Allow Domain",
            Self::AdblockUnallow { .. } => "Remove Domain from Allowlist",
            Self::AdblockBlock { .. } => "Block Domain",
            Self::LeaseRenew { .. } => "Renew DHCP Lease",
            Self::LeaseRelease { .. } => "Release DHCP Lease",
            Self::DnsRewriteAdd { .. } => "Add DNS Rewrite Rule",
            Self::DnsRewriteRemove { .. } => "Remove DNS Rewrite Rule",
            Self::HostAdd { .. } => "Save Host Configuration",
            Self::HostRemove { .. } => "Remove Host Configuration",
            Self::DnsUpstreamAdd { .. } => "Add DNS Upstream",
            Self::DnsUpstreamRemove { .. } => "Remove DNS Upstream",
            Self::AdblockSourceAdd { .. } => "Add Adblock Source",
            Self::AdblockSourceRemove { .. } => "Remove Adblock Source",
            Self::ServiceControl { action, .. } => match action {
                ServiceAction::Start => "Start Service",
                ServiceAction::Stop => "Stop Service",
                ServiceAction::Restart => "Restart Service",
            },
        }
    }

    #[must_use]
    pub fn description(&self) -> String {
        match self {

            Self::Reload => "Reload configuration files and restart local services.".to_string(),
            Self::Shutdown => "Stop the Lanforge daemon. DNS/DHCP services will become inactive.".to_string(),
            Self::DnsCacheFlush => "Clear all cached DNS queries from the local resolver.".to_string(),
            Self::Wol { hostname, mac } => format!("Send a Wake-on-LAN magic packet to {hostname} ({mac})."),
            Self::Purge { hostname, mac } => format!("Remove {hostname} ({mac}) from local cache and persistence database completely."),
            Self::AdblockToggle { enable: true } => "Enable network-wide ad blocking resolver rules.".to_string(),
            Self::AdblockToggle { enable: false } => "Disable ad blocking. Unblocked domains will resolve immediately.".to_string(),
            Self::AdblockTimedDisable { duration_secs } => format!("Disable ad blocking for the next {duration_secs} seconds."),
            Self::AdblockReload => "Reload all adblock blocklists and allowlists from sources and disk.".to_string(),
            Self::AdblockAllow { domain } => format!("Add {domain} to the allowlist (takes precedence over blocklists)."),
            Self::AdblockUnallow { domain } => format!("Remove {domain} from the allowed domains list."),
            Self::AdblockBlock { domain } => format!("Add {domain} to the custom blocklist."),
            Self::LeaseRenew { hostname, mac } => format!("Force the daemon to extend/renew the DHCP lease for {hostname} ({mac})."),
            Self::LeaseRelease { hostname, mac } => format!("Release the active DHCP lease for {hostname} ({mac}). The device may lose connectivity."),
            Self::DnsRewriteAdd { rule } => format!("Add DNS rewrite rule for {} to resolve as {}.", rule.domain, rule.answer),
            Self::DnsRewriteRemove { domain, .. } => format!("Remove DNS rewrite rule for {domain}."),
            Self::HostAdd { entry } => format!("Save static host configuration for {} ({}).", entry.hostname, entry.mac),
            Self::HostRemove { mac, hostname } => format!("Remove static host configuration for {hostname} ({mac}). The device will return to dynamic configuration state."),
            Self::DnsUpstreamAdd { target } => format!("Add DNS upstream resolver {} using protocol {}.", target.addr, target.protocol),
            Self::DnsUpstreamRemove { target } => format!("Remove DNS upstream resolver {} using protocol {}?", target.addr, target.protocol),
            Self::AdblockSourceAdd { url, .. } => format!("Add adblock blocklist source URL: {url}."),
            Self::AdblockSourceRemove { url } => format!("Remove adblock blocklist source URL: {url}?"),
            Self::ServiceControl { id, name, action } => match action {
                ServiceAction::Start => format!("Start background service {name} ({id})."),
                ServiceAction::Stop => format!("Stop background service {name} ({id}). This will release resources and may affect connected devices."),
                ServiceAction::Restart => format!("Restart background service {name} ({id}). This will re-initialize the service."),
            },
        }
    }

    #[must_use]
    pub const fn is_destructive(&self) -> bool {
        matches!(
            self,
            Self::Shutdown
                | Self::Purge { .. }
                | Self::LeaseRelease { .. }
                | Self::DnsRewriteRemove { .. }
                | Self::HostRemove { .. }
                | Self::DnsUpstreamRemove { .. }
                | Self::AdblockSourceRemove { .. }
                | Self::ServiceControl {
                    action: lanforge_types::system::ServiceAction::Stop
                        | lanforge_types::system::ServiceAction::Restart,
                    ..
                }
        )
    }
}
