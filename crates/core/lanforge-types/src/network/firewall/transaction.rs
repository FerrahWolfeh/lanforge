use super::FirewallConfig;
use std::time::Instant;

/// Internal state of an in-flight staged firewall transaction.
#[derive(Debug, Clone)]
pub struct FirewallTransactionState {
    pub tx_id: String,
    pub candidate_config: FirewallConfig,
    pub previous_config: Option<FirewallConfig>,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub auto_rollback_deadline: Option<Instant>,
}
