use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Status geral do sistema
    Status,
    /// Lista completa de dispositivos gerenciados
    Devices {
        filter: Option<String>,
        format: Option<String>,
    },
    /// Solicita ao daemon que recarregue configurações
    Reload,
    /// Monitora mudanças de estado ao vivo
    Watch,
    /// Mostra todos os eventos do bus
    Log {
        follow: bool,
    },
    /// Força execução de um scan
    Scan,
    /// Encerramento do serviço
    Shutdown,
    /// Gerenciamento de hosts customizados
    HostAdd {
        mac: Option<String>,
        hostname: Option<String>,
        v4: Option<String>,
        v6_suffix: Option<String>,
    },
    HostSet {
        mac: String,
        field: String,
        value: String,
    },
    HostRemove {
        mac: String,
    },
    HostList,
    LeaseRenew {
        mac: String,
    },
    LeaseRelease {
        mac: String,
    },
    DbVacuum,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Status(Box<StatusResponse>),
    Devices(DevicesResponse),
    Error { error: String },
    Success(SimpleSuccess),
    Event(crate::bus::LanforgeEvent),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleSuccess {
    pub message: String,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct Interfaces {
    pub lan: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceEntry>,
    pub meta: DevicesMeta,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub mac: String,
    pub hostname: String,
    pub origin: String,
    pub online: bool,
    pub last_seen: String,
    pub duid: Option<String>,
    pub v4: Option<LeaseInfo>,
    pub v6: Option<LeaseInfo>,
    pub slaac: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub ip: String,
    pub expires: String,
    pub reserved: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DevicesMeta {
    pub total: usize,
    pub online: usize,
    pub last_scan_secs_ago: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub uptime_secs: u64,
    pub version: String,
    pub services: ServicesStatus,
    pub db: DbStatus,
    pub network: NetworkStatus,
    pub devices: DevicesStats,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServicesStatus {
    pub ra: ServiceRa,
    pub dhcp_v4: ServiceDhcpV4,
    pub dhcp_v6: ServiceDhcpV6,
    pub dns: ServiceDns,
    pub slaac: ServiceSlaac,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceRa {
    pub state: String,
    pub uptime_secs: u64,
    pub gua: Option<String>,
    pub ula: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDhcpV4 {
    pub state: String,
    pub uptime_secs: u64,
    pub leases_active: usize,
    pub pool_free: usize,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDhcpV6 {
    pub state: String,
    pub uptime_secs: u64,
    pub leases_active: usize,
    pub pool_free: usize,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDns {
    pub state: String,
    pub uptime_secs: u64,
    pub upstream: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceSlaac {
    pub state: String,
    pub uptime_secs: u64,
    pub addrs_tracked: usize,
    pub last_scan_secs_ago: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DbStatus {
    pub path: String,
    pub size_bytes: u64,
    pub last_flush_secs_ago: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct NetworkStatus {
    pub lan_iface: String,
    pub wan_iface: String,
    pub gua: Option<String>,
    pub ula: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DevicesStats {
    pub total: usize,
    pub online: usize,
    pub static_toml: usize,
    pub managed_cli: usize,
    pub dynamic: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization() {
        let cmd = Command::Status;
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(json, r#"{"command":"status"}"#);

        let cmd = Command::Devices {
            filter: Some("arch".to_string()),
            format: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(
            json,
            r#"{"command":"devices","filter":"arch","format":null}"#
        );
    }
}
