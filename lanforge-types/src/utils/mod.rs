pub mod network;
pub mod serde;

pub use network::{compute_eui64_ip, ip_matches_prefix, is_slaac_iid, mac_from_eui64_link_local};
