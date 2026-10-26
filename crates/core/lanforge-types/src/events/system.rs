use serde::{Deserialize, Serialize};

use crate::config::DomainSet;
use crate::system::{ServiceAction, ServiceBanner, ServiceId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SystemEvent {
    Shutdown,
    StateReady,
    DbReady,
    InterfaceReady,
    ServiceReady {
        id: ServiceId,
    },
    SystemReady,
    ReloadConfig,
    ConfigChanged {
        sections: DomainSet,
    },
    ConfigUpdate {
        password_hash: String,
    },
    ServiceStatusBanner(Box<ServiceBanner>),
    ServiceControl {
        id: ServiceId,
        action: ServiceAction,
    },
    ConfigDhcpV4Changed,
    ConfigDhcpV6Changed,
    ConfigRaChanged,
    ConfigTftpChanged,
    ConfigDhcpOptionsChanged,
    ConfigPppoeChanged,
}
