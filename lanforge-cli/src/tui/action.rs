use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::adblock::RewriteRule;

/// A pending action waiting for confirmation.
#[derive(Debug, Clone)]
pub enum PendingAction {
    // System
    Scan,
    Reload,
    Shutdown,
    DnsCacheFlush,

    // Device
    Wol { mac: MacAddr, hostname: String },
    Purge { mac: MacAddr, hostname: String },

    // Adblock
    AdblockToggle { enable: bool },
    AdblockTimedDisable { duration_secs: u64 },
    AdblockReload,
    AdblockAllow { domain: String },
    AdblockUnallow { domain: String },
    AdblockBlock { domain: String },

    // DHCP
    LeaseRenew { mac: MacAddr, hostname: String },
    LeaseRelease { mac: MacAddr, hostname: String },

    // DNS Rewrites
    DnsRewriteAdd { rule: RewriteRule },
    DnsRewriteRemove { id: i64, domain: String },
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
            Self::Scan => "Scan Network",
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
        }
    }

    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Scan => "Trigger a background ARP/ICMP ping sweep on configured interfaces to discover active devices.".to_string(),
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
        )
    }
}
