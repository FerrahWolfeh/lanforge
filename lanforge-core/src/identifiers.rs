use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Representa um DHCP Unique Identifier (DUID)
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Duid {
    #[serde(serialize_with = "serialize_duid")]
    pub bytes: Vec<u8>,
}

fn serialize_duid<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(
        &bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<String>>()
            .join(":"),
    )
}

impl Duid {
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Retorna os bytes puros do DUID
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Retorna o tipo do DUID como string legível — útil para logs de diagnóstico.
    pub fn duid_type(&self) -> &'static str {
        if self.bytes.len() < 2 {
            return "unknown (too short)";
        }
        match u16::from_be_bytes([self.bytes[0], self.bytes[1]]) {
            1 => "DUID-LLT (contains MAC)",
            2 => "DUID-EN (no MAC — enterprise number)",
            3 => "DUID-LL (contains MAC)",
            4 => "DUID-UUID (no MAC)",
            _ => "DUID-unknown",
        }
    }

    /// Tenta extrair um MAC (Link-Layer Address) a partir do DUID, se for do tipo LL ou LLT.
    /// Retorna None se não for possível extrair com segurança.
    #[allow(clippy::match_same_arms)]
    pub fn extract_mac(&self) -> Option<MacAddr> {
        if self.bytes.len() < 2 {
            return None;
        }

        let duid_type = u16::from_be_bytes([self.bytes[0], self.bytes[1]]);

        match duid_type {
            // DUID-LLT (Link-Layer Address Plus Time)
            1 => {
                // type(2) + htype(2) + time(4) + lladdr(6+)
                if self.bytes.len() >= 14 {
                    return MacAddr::from_slice(&self.bytes[8..14]);
                }
            }
            // DUID-EN (Enterprise Number)
            2 => {
                // type(2) + enterprise(4) + identifier(variable)
                // Cannot reliably extract MAC
            }
            // DUID-LL (Link-Layer Address)
            3 => {
                // type(2) + htype(2) + lladdr(6+)
                if self.bytes.len() >= 10 {
                    return MacAddr::from_slice(&self.bytes[4..10]);
                }
            }
            _ => {}
        }
        None
    }

    /// Gera um DUID-LL (Link-Layer) válido de 10 bytes usando o MAC da interface.
    /// Formato: Type (0x0003) + Hardware Type (0x0001 para Ethernet) + MAC (6 bytes)
    pub fn generate_ll_from_mac(mac: [u8; 6]) -> Self {
        let mut bytes = vec![0x00, 0x03, 0x00, 0x01];
        bytes.extend_from_slice(&mac);
        Self::new(bytes)
    }
}

impl fmt::Debug for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: String = self
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        write!(f, "Duid({hex})")
    }
}

impl fmt::Display for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: String = self
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        write!(f, "{hex}")
    }
}

// ---------------------------------------------------------------------------
// MacAddr
// ---------------------------------------------------------------------------

/// Endereço MAC de 6 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(
    #[serde(serialize_with = "serialize_mac", deserialize_with = "deserialize_mac")] pub [u8; 6],
);

fn deserialize_mac<'de, D>(deserializer: D) -> Result<[u8; 6], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    MacAddr::parse(&s)
        .map(|m| m.0)
        .ok_or_else(|| serde::de::Error::custom(format!("Invalid MAC address: {}", s)))
}

fn serialize_mac<S>(mac: &[u8; 6], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

impl MacAddr {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).ok()?;
        }
        Some(Self(bytes))
    }

    pub const fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 6 {
            let mut arr = [0u8; 6];
            // arr.copy_from_slice(bytes); // not const
            arr[0] = bytes[0];
            arr[1] = bytes[1];
            arr[2] = bytes[2];
            arr[3] = bytes[3];
            arr[4] = bytes[4];
            arr[5] = bytes[5];
            Some(Self(arr))
        } else {
            None
        }
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(arr: [u8; 6]) -> Self {
        Self(arr)
    }
}

impl FromStr for MacAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("Invalid MAC address: {}", s))
    }
}

impl AsRef<[u8; 6]> for MacAddr {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}
