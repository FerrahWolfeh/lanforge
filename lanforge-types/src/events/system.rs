use serde::{Deserialize, Serialize};

use crate::system::ServiceBanner;

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
}
