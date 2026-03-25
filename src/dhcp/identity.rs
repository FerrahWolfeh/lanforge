use crate::{device::MacAddr, state::DeviceTable};
use std::fmt;

/// Identidade " Who TF am I?" (WTFAI) de um dispositivo.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub mac: MacAddr,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
}

impl DeviceIdentity {
    pub const fn new(mac: MacAddr, hostname: Option<String>, vendor_class: Option<String>) -> Self {
        Self {
            mac,
            hostname,
            vendor_class,
        }
    }

    /// Resolve a identidade usando informações do pacote e da tabela de dispositivos.
    pub fn resolve(
        mac: MacAddr,
        packet_hostname: Option<String>,
        packet_vendor: Option<String>,
        table: Option<&DeviceTable>,
    ) -> Self {
        let mut identity = Self::new(mac, packet_hostname, packet_vendor);

        if let Some(t) = table
            && let Some(dev) = t.devices.get(&mac)
        {
            // Se o pacote não trouxe hostname mas a tabela tem (ex: estático ou aprendido antes), usamos o da tabela
            if identity.hostname.is_none() && !dev.hostname.is_empty() {
                identity.hostname = Some(dev.hostname.clone());
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
