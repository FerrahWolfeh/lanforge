use crate::device::MacAddr;
use serde::{Deserialize, Serialize};
use std::fmt;

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
