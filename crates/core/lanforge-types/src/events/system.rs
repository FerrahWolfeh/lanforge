use serde::{Deserialize, Serialize};

use crate::config::DomainSet;
use crate::system::{ServiceAction, ServiceId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SystemEvent {
    Shutdown,
    ServiceReady {
        id: ServiceId,
    },
    SystemReady,
    /// Configuration sections changed (the only config notification: services read config
    /// through their subscriptions; this is for logs and observers).
    ConfigChanged {
        sections: DomainSet,
    },
    ConfigUpdate {
        password_hash: String,
    },
    ServiceControl {
        id: ServiceId,
        action: ServiceAction,
    },
}
