use lanforge_core::context::state::State;
use lanforge_types::identifiers::MacAddr;
use std::net::IpAddr;

pub mod adblock;
pub mod cache;
pub mod filter;
pub mod query;
pub mod reverse;
pub mod rewrite;
pub mod stats;

pub(crate) fn resolve_mac_hostname(state: &State, mac: MacAddr) -> Option<String> {
    if let Some(d) = state.devices.get(&mac) {
        let name = d.display_hostname();
        if name != "?" && !name.is_empty() {
            return Some(name.to_string());
        }
        if !d.dns_fallback.is_empty() {
            return Some(d.dns_fallback.clone());
        }
    }
    None
}

pub(crate) fn resolve_ip_identity(state: &State, ip: IpAddr) -> (Option<MacAddr>, Option<String>) {
    let mac = state.get_mac_by_ip(ip);
    let hostname = mac.and_then(|m| resolve_mac_hostname(state, m));
    (mac, hostname)
}
