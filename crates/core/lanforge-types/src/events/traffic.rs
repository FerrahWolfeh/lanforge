use serde::{Deserialize, Serialize};

/// Events emitted by the traffic management and SQM subsystems.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TrafficEvent {
    /// NIC hardware and sysfs tuning parameters successfully applied.
    TuningApplied {
        interfaces: Vec<String>,
        cpu_mask: String,
    },
    /// SQM (CAKE) queues attached to egress/ingress interfaces.
    SqmApplied {
        interface: String,
        ingress_device: Option<String>,
        download_mbps: u32,
        upload_mbps: u32,
    },
    /// SQM queues removed/cleaned up from interface.
    SqmCleared { interface: String },
    /// Traffic management or SQM configuration updated in-place.
    RulesetChanged,
}
