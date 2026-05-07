use mac_oui::Oui;
use std::sync::OnceLock;

static OUI_DB: OnceLock<Oui> = OnceLock::new();

/// Resolves a MAC address to a vendor name using the local OUI database.
///
/// This database is large (~70MB) and is only loaded into memory when
/// this function is first called. Since the CLI is short-lived, this
/// one-time memory spike is acceptable.
pub fn resolve_vendor(mac: &str) -> Option<String> {
    let db = OUI_DB.get_or_init(|| Oui::default().expect("Failed to load OUI database"));
    db.lookup_by_mac(mac)
        .ok()
        .flatten()
        .map(|entry| entry.company_name.clone())
}
