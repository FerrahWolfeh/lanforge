//! Firewall dynamic ports and transaction staging/rollback coordination.

use std::time::{Instant, SystemTime};

use lanforge_types::events::FirewallEvent;
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallTransactionState, FirewallValidationReport,
    L4Protocol, validate_firewall_candidate,
};

use crate::bus::LanforgeEvent;
use crate::context::LanforgeContext;

impl LanforgeContext {
    /// Registers a dynamic port requirement for an internal service (e.g. HTTP `WebUI`, DNS, DHCP).
    ///
    /// Stores the port in context and broadcasts a `FirewallEvent::PortOpenRequested` on the bus.
    pub fn register_service_port(&self, request: DynamicPortRequest) {
        let added = {
            let mut ports = self.inner.runtime.firewall_ports.write();
            if ports.iter().any(|p| {
                p.service == request.service
                    && p.port == request.port
                    && p.protocol == request.protocol
            }) {
                false
            } else {
                ports.push(request.clone());
                true
            }
        };
        if added {
            let _ =
                self.inner
                    .bus
                    .publish(LanforgeEvent::Firewall(FirewallEvent::PortOpenRequested(
                        Box::new(request),
                    )));
        }
    }

    /// Releases a previously registered dynamic port requirement.
    pub fn release_service_port(&self, service: &str, port: u16, protocol: L4Protocol) {
        let removed = {
            let mut ports = self.inner.runtime.firewall_ports.write();
            let initial = ports.len();
            ports.retain(|p| !(p.service == service && p.port == port && p.protocol == protocol));
            ports.len() != initial
        };
        if removed {
            let _ = self.inner.bus.publish(LanforgeEvent::Firewall(
                FirewallEvent::PortReleaseRequested {
                    service: service.to_string(),
                    port,
                    protocol,
                },
            ));
        }
    }

    /// Returns all registered dynamic service ports.
    #[must_use]
    pub fn registered_service_ports(&self) -> Vec<DynamicPortRequest> {
        self.inner.runtime.firewall_ports.read().clone()
    }

    /// Evaluates a candidate firewall configuration, runs pre-flight sanity checks,
    /// and stages it as an active pending transaction if valid.
    #[must_use]
    pub fn stage_firewall_transaction(
        &self,
        candidate: FirewallConfig,
    ) -> FirewallValidationReport {
        let current = self.get_firewall_config().unwrap_or_default();
        let dynamic_ports = self.registered_service_ports();

        let report = validate_firewall_candidate(&candidate, &current, &dynamic_ports, || {
            let id = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            format!("tx-{id:x}")
        });

        if let Some(ref tx_id) = report.tx_id {
            let now = Instant::now();
            let mut tx_lock = self.inner.runtime.firewall_tx.write();
            *tx_lock = Some(FirewallTransactionState {
                tx_id: tx_id.clone(),
                candidate_config: candidate,
                previous_config: Some(current),
                created_at: now,
                expires_at: now + std::time::Duration::from_secs(300),
                auto_rollback_deadline: None,
            });
        }

        report
    }

    /// Retrieves the staged firewall transaction if not expired.
    #[must_use]
    pub fn get_staged_firewall_transaction(&self) -> Option<FirewallTransactionState> {
        let mut tx_lock = self.inner.runtime.firewall_tx.write();
        if let Some(ref tx) = *tx_lock
            && Instant::now() > tx.expires_at
        {
            *tx_lock = None;
            return None;
        }
        tx_lock.clone()
    }

    /// Sets an auto-rollback deadline for the active staged transaction.
    #[must_use]
    pub fn set_firewall_transaction_rollback(&self, tx_id: &str, deadline: Instant) -> bool {
        let mut tx_lock = self.inner.runtime.firewall_tx.write();
        if let Some(ref mut tx) = *tx_lock
            && tx.tx_id == tx_id
        {
            tx.auto_rollback_deadline = Some(deadline);
            return true;
        }
        drop(tx_lock);
        false
    }

    /// Clears the staged firewall transaction.
    #[must_use]
    pub fn clear_staged_firewall_transaction(
        &self,
        tx_id: Option<&str>,
    ) -> Option<FirewallTransactionState> {
        let mut tx_lock = self.inner.runtime.firewall_tx.write();
        if let Some(ref tx) = *tx_lock
            && (tx_id.is_none() || tx_id == Some(tx.tx_id.as_str()))
        {
            return tx_lock.take();
        }
        None
    }
}
