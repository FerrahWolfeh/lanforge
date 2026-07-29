pub use lanforge_types::network::pppoe::{AuthMethod, PppoeConfig};

/// Decoupled credentials handle, ready for DB integration.
#[derive(Debug, Clone)]
pub struct PppoeCredentials {
    pub username: String,
    pub password: String,
    pub auth: AuthMethod,
}
