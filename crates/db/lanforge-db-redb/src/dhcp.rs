//! DhcpConfigStore, RaConfigStore, and PppoeConfigStore implementations for `RedbDatabase`.

use crate::RedbDatabase;
use lanforge_db_core::{
    config_keys::*, DbError, DhcpConfigStore, PppoeConfigStore, RaConfigStore, TrafficConfigStore,
};
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::TrafficConfig;
use std::net::Ipv6Addr;

impl DhcpConfigStore for RedbDatabase {
    fn load_dhcp_v4_pools(&self) -> Result<Vec<Dhcpv4Pool>, DbError> {
        Ok(self.get(DHCP_V4_POOLS)?.unwrap_or_default())
    }

    fn save_dhcp_v4_pools(&self, pools: &[Dhcpv4Pool]) -> Result<(), DbError> {
        self.put(DHCP_V4_POOLS, &pools.to_vec())
    }

    fn load_dhcp_v6_pools(&self) -> Result<Vec<Dhcpv6Pool>, DbError> {
        Ok(self.get(DHCP_V6_POOLS)?.unwrap_or_default())
    }

    fn save_dhcp_v6_pools(&self, pools: &[Dhcpv6Pool]) -> Result<(), DbError> {
        self.put(DHCP_V6_POOLS, &pools.to_vec())
    }

    fn load_dhcp_options(&self) -> Result<Option<DhcpOptionsConfig>, DbError> {
        self.get(DHCP_OPTIONS)
    }

    fn save_dhcp_options(&self, options: &DhcpOptionsConfig) -> Result<(), DbError> {
        self.put(DHCP_OPTIONS, options)
    }
}

impl RaConfigStore for RedbDatabase {
    fn load_ra_prefixes(&self) -> Result<Vec<RAPrefix>, DbError> {
        Ok(self.get(RA_PREFIXES)?.unwrap_or_default())
    }

    fn save_ra_prefixes(&self, prefixes: &[RAPrefix]) -> Result<(), DbError> {
        self.put(RA_PREFIXES, &prefixes.to_vec())
    }

    fn load_ra_rdnss(&self) -> Result<Vec<RdnssConfig>, DbError> {
        Ok(self.get(RA_RDNSS)?.unwrap_or_default())
    }

    fn save_ra_rdnss(&self, rdnss: &[RdnssConfig]) -> Result<(), DbError> {
        self.put(RA_RDNSS, &rdnss.to_vec())
    }

    fn load_ra_dnssl(&self) -> Result<Vec<DnsslConfig>, DbError> {
        Ok(self.get(RA_DNSSL)?.unwrap_or_default())
    }

    fn save_ra_dnssl(&self, dnssl: &[DnsslConfig]) -> Result<(), DbError> {
        self.put(RA_DNSSL, &dnssl.to_vec())
    }

    fn load_last_gua_prefix(&self) -> Result<Option<Ipv6Addr>, DbError> {
        self.get(LAST_GUA_PREFIX)
    }

    fn save_last_gua_prefix(&self, prefix: Option<Ipv6Addr>) -> Result<(), DbError> {
        if let Some(p) = prefix {
            self.put(LAST_GUA_PREFIX, &p)
        } else {
            self.write(|tx| tx.remove(LAST_GUA_PREFIX))
        }
    }
}

impl PppoeConfigStore for RedbDatabase {
    fn load_pppoe_config(&self) -> Result<Option<PppoeConfig>, DbError> {
        self.get(PPPOE)
    }

    fn save_pppoe_config(&self, cfg: &PppoeConfig) -> Result<(), DbError> {
        self.put(PPPOE, cfg)
    }
}

impl TrafficConfigStore for RedbDatabase {
    fn load_traffic_config(&self) -> Result<Option<TrafficConfig>, DbError> {
        self.get(TRAFFIC)
    }

    fn save_traffic_config(&self, cfg: &TrafficConfig) -> Result<(), DbError> {
        self.put(TRAFFIC, cfg)
    }
}
