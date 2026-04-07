use std::{fmt, sync::Arc};

use lanforge_core::{device::Device, identifiers::MacAddr};

/// Device identity — "Who am I?" (WTFAI) representation.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// Device's MAC address.
    pub mac: MacAddr,
    /// Device's hostname (if any).
    pub hostname: Option<String>,
    /// Device's vendor class (if any).
    pub vendor_class: Option<String>,
}

impl DeviceIdentity {
    #[must_use]
    pub const fn new(mac: MacAddr, hostname: Option<String>, vendor_class: Option<String>) -> Self {
        Self {
            mac,
            hostname,
            vendor_class,
        }
    }

    /// Resolves the identity using packet-provided information and an optional device snapshot.
    #[must_use]
    pub fn resolve(
        mac: MacAddr,
        packet_hostname: Option<String>,
        packet_vendor: Option<String>,
        device: Option<Arc<Device>>,
    ) -> Self {
        let mut identity = Self::new(mac, packet_hostname, packet_vendor);

        if let Some(dev) = device {
            // If the packet didn't provide a hostname but the table has one
            // (e.g., static or previously learned), use the table's version.
            if identity.hostname.is_none() && !dev.hostname.name.is_empty() {
                identity.hostname = Some(dev.hostname.name.clone());
            }
        }

        identity
    }
}

impl fmt::Display for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.hostname, &self.vendor_class) {
            (Some(h), Some(v)) => write!(f, "\"{h}\" ({v}) [{}]", self.mac),
            (Some(h), None) => write!(f, "\"{h}\" [{}]", self.mac),
            (None, Some(v)) => write!(f, "({v}) [{}]", self.mac),
            (None, None) => write!(f, "[{}]", self.mac),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_display() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let id1 = DeviceIdentity::new(
            mac,
            Some("my-phone".to_string()),
            Some("Android".to_string()),
        );
        assert_eq!(
            id1.to_string(),
            "\"my-phone\" (Android) [aa:bb:cc:dd:ee:ff]"
        );

        let id2 = DeviceIdentity::new(mac, Some("my-phone".to_string()), None);
        assert_eq!(id2.to_string(), "\"my-phone\" [aa:bb:cc:dd:ee:ff]");

        let id3 = DeviceIdentity::new(mac, None, Some("Apple".to_string()));
        assert_eq!(id3.to_string(), "(Apple) [aa:bb:cc:dd:ee:ff]");

        let id4 = DeviceIdentity::new(mac, None, None);
        assert_eq!(id4.to_string(), "[aa:bb:cc:dd:ee:ff]");
    }
}
