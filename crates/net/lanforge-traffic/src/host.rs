//! What the traffic service does to the machine: NIC tuning, `tc` SQM queues, counters.
//!
//! Injected like a transport: [`KernelTraffic`] in production, [`InertTraffic`] in rootless
//! tests. The service itself holds no simulation branches.

use std::future::{Future, ready};

use lanforge_types::network::traffic::TrafficTelemetryResponse;
use lanforge_types::network::{NicTuningConfig, SqmConfig};

use crate::collector::collect_traffic_telemetry;
use crate::sqm::{apply_sqm, clear_sqm};
use crate::tuning::apply_tuning;

/// The host side of NIC tuning and SQM.
pub trait TrafficHost: Clone + Send + Sync + 'static {
    /// Tunes `ifaces` (RPS/XPS, ring sizes, offloads); returns the interfaces that were tuned.
    fn apply_tuning(
        &self,
        cfg: &NicTuningConfig,
        ifaces: &[String],
    ) -> impl Future<Output = Vec<String>> + Send;

    /// Shapes `wan` with CAKE; returns the ingress (IFB) device when one is used.
    fn apply_sqm(
        &self,
        wan: &str,
        cfg: &SqmConfig,
        is_pppoe: bool,
    ) -> impl Future<Output = Option<String>> + Send;

    /// Removes the queues from `wan` and its ingress device.
    fn clear_sqm(&self, wan: &str, ingress_device: &str) -> impl Future<Output = ()> + Send;

    /// Current counters of the shaped interfaces.
    fn telemetry(
        &self,
        wan: Option<&str>,
        ifb: Option<&str>,
    ) -> impl Future<Output = TrafficTelemetryResponse> + Send;
}

/// The real host: sysfs, ethtool and `tc`.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelTraffic;

impl TrafficHost for KernelTraffic {
    async fn apply_tuning(&self, cfg: &NicTuningConfig, ifaces: &[String]) -> Vec<String> {
        apply_tuning(cfg, ifaces).await
    }

    async fn apply_sqm(&self, wan: &str, cfg: &SqmConfig, is_pppoe: bool) -> Option<String> {
        apply_sqm(wan, cfg, is_pppoe).await
    }

    async fn clear_sqm(&self, wan: &str, ingress_device: &str) {
        clear_sqm(wan, ingress_device).await;
    }

    async fn telemetry(&self, wan: Option<&str>, ifb: Option<&str>) -> TrafficTelemetryResponse {
        collect_traffic_telemetry(wan, ifb).await
    }
}

/// Touches nothing: every interface counts as tuned, SQM reports its ingress device
/// (`ifb4lanforge` unless configured), counters stay at zero.
#[cfg(any(test, feature = "inert"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct InertTraffic;

#[cfg(any(test, feature = "inert"))]
impl TrafficHost for InertTraffic {
    fn apply_tuning(
        &self,
        _cfg: &NicTuningConfig,
        ifaces: &[String],
    ) -> impl Future<Output = Vec<String>> + Send {
        ready(ifaces.to_vec())
    }

    fn apply_sqm(
        &self,
        _wan: &str,
        cfg: &SqmConfig,
        _is_pppoe: bool,
    ) -> impl Future<Output = Option<String>> + Send {
        let dev = cfg.ingress_device.trim();
        ready(Some(
            if dev.is_empty() { "ifb4lanforge" } else { dev }.to_string(),
        ))
    }

    fn clear_sqm(&self, _wan: &str, _ingress_device: &str) -> impl Future<Output = ()> + Send {
        ready(())
    }

    fn telemetry(
        &self,
        _wan: Option<&str>,
        _ifb: Option<&str>,
    ) -> impl Future<Output = TrafficTelemetryResponse> + Send {
        ready(TrafficTelemetryResponse::default())
    }
}
