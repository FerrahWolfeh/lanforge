use crate::identifiers::MacAddr;
use mac_oui::Oui;
use std::sync::OnceLock;

static OUI_DB: OnceLock<Oui> = OnceLock::new();

/// Resolves the vendor name for a given MAC address using the bundled OUI database.
///
/// # Panics
///
/// Panics if the bundled OUI database cannot be loaded (e.g. internal crate failure).
pub fn resolve_vendor(mac: &MacAddr) -> Option<String> {
    let db = OUI_DB.get_or_init(|| {
        // Since we enabled 'with-db' feature, we can use the inbuilt database
        Oui::default().expect("Failed to load bundled OUI database")
    });

    db.lookup_by_mac(&mac.to_string())
        .ok()
        .flatten()
        .map(|entry| entry.company_name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_resolve_apple() {
        let mac = MacAddr::from_str("00:00:0c:00:00:00").unwrap();
        let vendor = resolve_vendor(&mac);
        assert!(vendor.is_some());
        assert!(vendor.unwrap().to_lowercase().contains("cisco"));
    }

    #[test]
    fn test_resolve_raspberry() {
        // Raspberry Pi Trading Ltd
        let mac = MacAddr::from_str("b8:27:eb:00:00:00").unwrap();
        let vendor = resolve_vendor(&mac);
        assert!(vendor.is_some());
        assert!(vendor.unwrap().to_lowercase().contains("raspberry"));
    }
}
