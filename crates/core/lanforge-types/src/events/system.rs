use serde::{Deserialize, Serialize};

use crate::system::{ServiceAction, ServiceBanner};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SystemEvent {
    Shutdown,
    StateReady,
    DbReady,
    InterfaceReady,
    ServiceReady { name: String },
    SystemReady,
    ReloadConfig,
    ConfigUpdate { password_hash: String },
    ServiceStatusBanner(ServiceBanner),
    ServiceControl { id: String, action: ServiceAction },
    ConfigDhcpV4Changed,
    ConfigDhcpV6Changed,
    ConfigRaChanged,
}
