//! `LanforgeDb` facade for PostgreSQL.

use std::sync::Arc;
use std::time::SystemTime;

use lanforge_core::context::PersistenceSnapshot;
use lanforge_core::context::state::State;
use lanforge_db_core::{
    AdblockStore, ApiTokenEntry, ApiTokenStore, BoxFuture, DbError, DeviceStore, DhcpConfigStore,
    DnsStore, DnsUpstreamEntry, DnsUpstreamStore, PppoeConfigStore, RaConfigStore, UserEntry,
    UserStore, delegate_db_call,
};
use lanforge_db_postgres::PostgresDatabase;
use lanforge_types::auth::ApiScopes;
use lanforge_types::device::{Device, LeaseAction};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockUrlKind, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::{DnsReverseResolver, IpSubnet};

pub mod types {
    pub use lanforge_db_core::{
        ApiTokenEntry as ApiTokenRow, DnsUpstreamEntry as DnsUpstreamRow, UserEntry as UserRow,
    };
}

pub use lanforge_types::device::LeaseHistoryEntry;

use lanforge_types::device::LeaseKind;
use lanforge_types::network::dns::adblock::{BlockingMode, RewriteAnswer};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

pub struct MockDbState {
    pub devices: RwLock<HashMap<MacAddr, Device>>,
    pub dns_rewrites: RwLock<Vec<RewriteRule>>,
    pub dns_allowlist: RwLock<HashSet<String>>,
    pub dns_reverse_resolvers: RwLock<Vec<DnsReverseResolver>>,
    pub adblock_config: RwLock<AdblockDbConfig>,
    pub adblock_urls: RwLock<Vec<(i64, String, AdblockUrlKind)>>,
    pub api_tokens: RwLock<Vec<ApiTokenEntry>>,
    pub dns_upstreams: RwLock<Vec<DnsUpstreamEntry>>,
    pub lease_history: RwLock<Vec<(MacAddr, LeaseHistoryEntry)>>,
    pub dhcp_v4_pools: RwLock<Vec<Dhcpv4Pool>>,
    pub dhcp_v6_pools: RwLock<Vec<Dhcpv6Pool>>,
    pub dhcp_options: RwLock<Option<DhcpOptionsConfig>>,
    pub ra_prefixes: RwLock<Vec<RAPrefix>>,
    pub ra_rdnss: RwLock<Vec<RdnssConfig>>,
    pub ra_dnssl: RwLock<Vec<DnsslConfig>>,
    pub last_gua_prefix: RwLock<Option<std::net::Ipv6Addr>>,
    pub pppoe_config: RwLock<Option<PppoeConfig>>,
    pub users: RwLock<Vec<UserEntry>>,
}

impl Default for MockDbState {
    fn default() -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            dns_rewrites: RwLock::new(Vec::new()),
            dns_allowlist: RwLock::new(HashSet::new()),
            dns_reverse_resolvers: RwLock::new(Vec::new()),
            adblock_config: RwLock::new(AdblockDbConfig::default()),
            adblock_urls: RwLock::new(Vec::new()),
            api_tokens: RwLock::new(Vec::new()),
            dns_upstreams: RwLock::new(Vec::new()),
            lease_history: RwLock::new(Vec::new()),
            dhcp_v4_pools: RwLock::new(Vec::new()),
            dhcp_v6_pools: RwLock::new(Vec::new()),
            dhcp_options: RwLock::new(None),
            ra_prefixes: RwLock::new(Vec::new()),
            ra_rdnss: RwLock::new(Vec::new()),
            ra_dnssl: RwLock::new(Vec::new()),
            last_gua_prefix: RwLock::new(None),
            pppoe_config: RwLock::new(None),
            users: RwLock::new(Vec::new()),
        }
    }
}

pub enum DbEngine {
    Postgres(Arc<PostgresDatabase>),
    Mock(Arc<MockDbState>),
}

pub struct LanforgeDb {
    inner: DbEngine,
}

impl LanforgeDb {
    /// Opens the PostgreSQL database pool.
    pub async fn open(cfg: &crate::config::DatabaseConfig) -> Result<Self, DbError> {
        if cfg.url.starts_with("sqlite:")
            || cfg.url.starts_with("mock:")
            || cfg.url.contains(":memory:")
        {
            return Ok(Self {
                inner: DbEngine::Mock(Arc::new(MockDbState::default())),
            });
        }
        let db = PostgresDatabase::open(&cfg.url, cfg.max_connections, cfg.min_connections).await?;
        Ok(Self {
            inner: DbEngine::Postgres(Arc::new(db)),
        })
    }

    /// Backwards compatibility method (returning error for sqlite in-memory).
    pub async fn open_in_memory() -> Result<Self, DbError> {
        Ok(Self {
            inner: DbEngine::Mock(Arc::new(MockDbState::default())),
        })
    }

    // --- DeviceStore ---

    pub async fn save_table(&self, table: &State) -> Result<(), DbError> {
        delegate_db_call!(self, save_table(table), mock => {
            let mut dev_map = mock.devices.write();
            dev_map.clear();
            for device in table.devices() {
                dev_map.insert(device.mac, device.as_ref().clone());
            }
            Ok(())
        })
    }

    pub async fn save_snapshot(&self, snapshot: &PersistenceSnapshot) -> Result<(), DbError> {
        delegate_db_call!(self, save_snapshot(snapshot), mock => {
            let mut dev_map = mock.devices.write();
            dev_map.clear();
            for device in snapshot.devices.values() {
                dev_map.insert(device.mac, device.as_ref().clone());
            }
            Ok(())
        })
    }

    pub async fn upsert_device(&self, device: &Device) -> Result<(), DbError> {
        delegate_db_call!(self, upsert_device(device), mock => {
            mock.devices.write().insert(device.mac, device.clone());
            Ok(())
        })
    }

    pub async fn upsert_base_device_only(&self, device: &Device) -> Result<(), DbError> {
        delegate_db_call!(self, upsert_base_device_only(device), mock => {
            mock.devices.write().insert(device.mac, device.clone());
            Ok(())
        })
    }

    pub async fn delete_devices(&self, macs: &[MacAddr]) -> Result<(), DbError> {
        delegate_db_call!(self, delete_devices(macs), mock => {
            let mut dev_map = mock.devices.write();
            for mac in macs {
                dev_map.remove(mac);
            }
            Ok(())
        })
    }

    pub async fn find_mac_by_hostname(&self, hostname: &str) -> Result<Option<MacAddr>, DbError> {
        delegate_db_call!(self, find_mac_by_hostname(hostname), mock => {
            let dev_map = mock.devices.read();
            let mac = dev_map
                .values()
                .find(|d| d.hostname.name == hostname)
                .map(|d| d.mac);
            Ok(mac)
        })
    }

    pub async fn load_table(&self) -> Result<State, DbError> {
        delegate_db_call!(self, load_table(), mock => {
            let mut state = State::new();
            for (mac, device) in mock.devices.read().iter() {
                state.insert_device(*mac, device.clone());
            }
            Ok(state)
        })
    }

    pub async fn load_all_devices(&self) -> Result<Vec<Device>, DbError> {
        delegate_db_call!(self, load_all_devices(), mock => {
            let dev_map = mock.devices.read();
            Ok(dev_map.values().cloned().collect())
        })
    }

    pub async fn remove_device(&self, mac: MacAddr) -> Result<(), DbError> {
        delegate_db_call!(self, remove_device(mac), mock => {
            mock.devices.write().remove(&mac);
            Ok(())
        })
    }

    pub async fn vacuum(&self) -> Result<(), DbError> {
        delegate_db_call!(self, vacuum(), _mock => Ok(()))
    }

    pub async fn prune_zombies(&self) -> Result<usize, DbError> {
        delegate_db_call!(self, prune_zombies(), _mock => Ok(0))
    }

    pub async fn reset(&self) -> Result<(), DbError> {
        delegate_db_call!(self, reset(), mock => {
            mock.devices.write().clear();
            mock.dns_rewrites.write().clear();
            mock.dns_allowlist.write().clear();
            mock.dns_reverse_resolvers.write().clear();
            *mock.adblock_config.write() = AdblockDbConfig::default();
            mock.adblock_urls.write().clear();
            mock.api_tokens.write().clear();
            mock.dns_upstreams.write().clear();
            mock.lease_history.write().clear();
            mock.dhcp_v4_pools.write().clear();
            mock.dhcp_v6_pools.write().clear();
            mock.ra_prefixes.write().clear();
            mock.ra_rdnss.write().clear();
            mock.ra_dnssl.write().clear();
            Ok(())
        })
    }

    pub async fn record_lease_event(
        &self,
        mac: MacAddr,
        ip: &str,
        lease_type: &str,
        action: LeaseAction,
    ) -> Result<(), DbError> {
        delegate_db_call!(self, record_lease_event(mac, ip, lease_type, action), mock => {
            let mut history = mock.lease_history.write();
            let ip_parsed = ip
                .parse::<IpAddr>()
                .map_err(|e| DbError::Validation(format!("Invalid IP: {e}")))?;
            let lease_type_parsed = lease_type
                .parse::<LeaseKind>()
                .map_err(DbError::Validation)?;
            history.push((
                mac,
                LeaseHistoryEntry {
                    ip: ip_parsed,
                    lease_type: lease_type_parsed,
                    action,
                    timestamp: SystemTime::now(),
                },
            ));
            Ok(())
        })
    }

    pub async fn get_lease_history(&self, mac: MacAddr) -> Result<Vec<LeaseHistoryEntry>, DbError> {
        delegate_db_call!(self, get_lease_history(mac), mock => {
            let history = mock.lease_history.read();
            let mut filtered: Vec<LeaseHistoryEntry> = history
                .iter()
                .filter(|(m, _)| *m == mac)
                .map(|(_, entry)| entry.clone())
                .collect();
            filtered.reverse(); // newest first
            filtered.truncate(100);
            Ok(filtered)
        })
    }

    // --- DnsStore ---

    pub async fn load_dns_rewrites(&self) -> Result<Vec<RewriteRule>, DbError> {
        delegate_db_call!(self, load_dns_rewrites(), mock => {
            let mut rewrites = mock.dns_rewrites.read().clone();
            rewrites.sort_by(|a, b| a.domain.cmp(&b.domain));
            Ok(rewrites)
        })
    }

    pub async fn upsert_dns_rewrite(
        &self,
        domain: &str,
        rtype: DnsRecordType,
        answer: &str,
    ) -> Result<(), DbError> {
        delegate_db_call!(self, upsert_dns_rewrite(domain, rtype, answer), mock => {
            let mut rewrites = mock.dns_rewrites.write();
            if let Some(pos) = rewrites
                .iter()
                .position(|r| r.domain == domain && r.rtype == rtype)
            {
                if let Ok(ans) = RewriteAnswer::from_str(answer) {
                    rewrites[pos].answer = ans;
                }
            } else {
                let id = rewrites.len() as i64 + 1;
                if let Ok(ans) = RewriteAnswer::from_str(answer) {
                    rewrites.push(RewriteRule {
                        id: Some(id),
                        domain: domain.to_string(),
                        rtype,
                        answer: ans,
                    });
                }
            }
            Ok(())
        })
    }

    pub async fn delete_dns_rewrite_by_id(&self, id: i64) -> Result<(), DbError> {
        delegate_db_call!(self, delete_dns_rewrite_by_id(id), mock => {
            let mut rewrites = mock.dns_rewrites.write();
            rewrites.retain(|r| r.id != Some(id));
            Ok(())
        })
    }

    pub async fn clear_dns_rewrites(&self) -> Result<(), DbError> {
        delegate_db_call!(self, clear_dns_rewrites(), mock => {
            mock.dns_rewrites.write().clear();
            Ok(())
        })
    }

    pub async fn load_dns_allowlist(&self) -> Result<Vec<(i64, String)>, DbError> {
        delegate_db_call!(self, load_dns_allowlist(), mock => {
            let mut list: Vec<(i64, String)> = mock
                .dns_allowlist
                .read()
                .iter()
                .enumerate()
                .map(|(i, domain)| (i as i64 + 1, domain.clone()))
                .collect();
            list.sort_by(|a, b| a.1.cmp(&b.1));
            Ok(list)
        })
    }

    pub async fn add_dns_allowlist(&self, domain: &str) -> Result<(), DbError> {
        delegate_db_call!(self, add_dns_allowlist(domain), mock => {
            mock.dns_allowlist.write().insert(domain.to_string());
            Ok(())
        })
    }

    pub async fn remove_dns_allowlist(&self, domain: &str) -> Result<(), DbError> {
        delegate_db_call!(self, remove_dns_allowlist(domain), mock => {
            mock.dns_allowlist.write().remove(domain);
            Ok(())
        })
    }

    pub async fn clear_dns_allowlist(&self) -> Result<(), DbError> {
        delegate_db_call!(self, clear_dns_allowlist(), mock => {
            mock.dns_allowlist.write().clear();
            Ok(())
        })
    }

    pub async fn load_dns_reverse_resolvers(&self) -> Result<Vec<DnsReverseResolver>, DbError> {
        delegate_db_call!(self, load_dns_reverse_resolvers(), mock => Ok(mock.dns_reverse_resolvers.read().clone()))
    }

    pub async fn add_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
        resolver: &UpstreamTarget,
    ) -> Result<(), DbError> {
        delegate_db_call!(self, add_dns_reverse_resolver(subnet, resolver), mock => {
            let mut resolvers = mock.dns_reverse_resolvers.write();
            if let Some(pos) = resolvers.iter().position(|r| r.subnet == *subnet) {
                resolvers[pos].resolver = resolver.clone();
            } else {
                resolvers.push(DnsReverseResolver {
                    subnet: *subnet,
                    resolver: resolver.clone(),
                });
            }
            Ok(())
        })
    }

    pub async fn remove_dns_reverse_resolver(&self, subnet: &IpSubnet) -> Result<(), DbError> {
        delegate_db_call!(self, remove_dns_reverse_resolver(subnet), mock => {
            let mut resolvers = mock.dns_reverse_resolvers.write();
            resolvers.retain(|r| r.subnet != *subnet);
            Ok(())
        })
    }

    pub async fn clear_dns_reverse_resolvers(&self) -> Result<(), DbError> {
        delegate_db_call!(self, clear_dns_reverse_resolvers(), mock => {
            mock.dns_reverse_resolvers.write().clear();
            Ok(())
        })
    }

    // --- AdblockStore ---

    pub async fn load_adblock_config(&self) -> Result<AdblockDbConfig, DbError> {
        delegate_db_call!(self, load_adblock_config(), mock => Ok(mock.adblock_config.read().clone()))
    }

    pub async fn save_adblock_config(&self, cfg: &AdblockDbConfig) -> Result<(), DbError> {
        delegate_db_call!(self, save_adblock_config(cfg), mock => {
            *mock.adblock_config.write() = cfg.clone();
            Ok(())
        })
    }

    // Legacy adblock set config helper
    pub async fn set_adblock_config_value(&self, key: &str, value: &str) -> Result<(), DbError> {
        delegate_db_call!(self, set_adblock_config_value(key, value), mock => {
            let mut cfg = mock.adblock_config.write();
            match key {
                "enabled" => cfg.enabled = value == "true",
                "blocking_mode" => {
                    if let Ok(m) = BlockingMode::from_str(value) {
                        cfg.blocking_mode = m;
                    }
                }
                "blocking_ip_v4" => {
                    if value.is_empty() || value == "none" || value == "null" {
                        cfg.blocking_ip_v4 = None;
                    } else if let Ok(ip) = value.parse() {
                        cfg.blocking_ip_v4 = Some(ip);
                    }
                }
                "blocking_ip_v6" => {
                    if value.is_empty() || value == "none" || value == "null" {
                        cfg.blocking_ip_v6 = None;
                    } else if let Ok(ip) = value.parse() {
                        cfg.blocking_ip_v6 = Some(ip);
                    }
                }
                "refresh_hours" => {
                    if let Ok(h) = value.parse() {
                        cfg.refresh_hours = h;
                    }
                }
                "refresh_at_night" => cfg.refresh_at_night = value == "true",
                _ => {}
            }
            Ok(())
        })
    }

    pub async fn load_adblock_urls(&self) -> Result<Vec<(i64, String, AdblockUrlKind)>, DbError> {
        delegate_db_call!(self, load_adblock_urls(), mock => Ok(mock.adblock_urls.read().clone()))
    }

    pub async fn add_adblock_url(&self, url: &str, kind: AdblockUrlKind) -> Result<(), DbError> {
        delegate_db_call!(self, add_adblock_url(url, kind), mock => {
            let mut urls = mock.adblock_urls.write();
            if let Some(pos) = urls.iter().position(|u| u.1 == url) {
                urls[pos].2 = kind;
            } else {
                let id = urls.len() as i64 + 1;
                urls.push((id, url.to_string(), kind));
            }
            Ok(())
        })
    }

    pub async fn remove_adblock_url(&self, url: &str) -> Result<(), DbError> {
        delegate_db_call!(self, remove_adblock_url(url), mock => {
            let mut urls = mock.adblock_urls.write();
            urls.retain(|u| u.1 != url);
            Ok(())
        })
    }

    pub async fn clear_adblock_urls(&self) -> Result<(), DbError> {
        delegate_db_call!(self, clear_adblock_urls(), mock => {
            mock.adblock_urls.write().clear();
            Ok(())
        })
    }

    pub async fn load_adblock_sources(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, bool)>, DbError> {
        delegate_db_call!(self, load_adblock_sources(), mock => {
            Ok(mock
                .adblock_urls
                .read()
                .iter()
                .map(|(id, url, kind)| (*id, url.clone(), *kind, true))
                .collect())
        })
    }

    pub async fn add_adblock_source(
        &self,
        url: &str,
        kind: AdblockUrlKind,
    ) -> Result<i64, DbError> {
        delegate_db_call!(self, add_adblock_source(url, kind), mock => {
            let mut urls = mock.adblock_urls.write();
            let id = urls.len() as i64 + 1;
            urls.push((id, url.to_string(), kind));
            Ok(id)
        })
    }

    pub async fn remove_adblock_source(&self, id: i64) -> Result<(), DbError> {
        delegate_db_call!(self, remove_adblock_source(id), mock => {
            let mut urls = mock.adblock_urls.write();
            urls.retain(|u| u.0 != id);
            Ok(())
        })
    }

    pub async fn update_adblock_source_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> Result<(), DbError> {
        delegate_db_call!(self, update_adblock_source_status(id, enabled), mock => {
            Ok(())
        })
    }

    pub async fn clear_adblock_sources(&self) -> Result<(), DbError> {
        delegate_db_call!(self, clear_adblock_sources(), mock => {
            mock.adblock_urls.write().clear();
            Ok(())
        })
    }

    pub async fn load_adblock_rules(&self) -> Result<Vec<(i64, String, String, bool)>, DbError> {
        delegate_db_call!(self, load_adblock_rules(), mock => Ok(Vec::new()))
    }

    pub async fn add_adblock_rule(&self, domain: &str, action: &str) -> Result<i64, DbError> {
        delegate_db_call!(self, add_adblock_rule(domain, action), mock => Ok(1))
    }

    pub async fn remove_adblock_rule(&self, id: i64) -> Result<(), DbError> {
        delegate_db_call!(self, remove_adblock_rule(id), mock => Ok(()))
    }

    pub async fn update_adblock_rule_status(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        delegate_db_call!(self, update_adblock_rule_status(id, enabled), mock => Ok(()))
    }

    pub async fn clear_adblock_rules(&self) -> Result<(), DbError> {
        delegate_db_call!(self, clear_adblock_rules(), mock => Ok(()))
    }

    // --- ApiTokenStore ---

    pub async fn store_api_token(
        &self,
        token: &str,
        name: &str,
        scopes: &ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<i64, DbError> {
        match &self.inner {
            DbEngine::Postgres(db) => {
                db.store_api_token(token, name, scopes, expires_at, now)
                    .await
            }
            DbEngine::Mock(mock) => {
                let mut tokens = mock.api_tokens.write();
                let id = tokens.len() as i64 + 1;
                tokens.push(ApiTokenEntry {
                    id,
                    token: token.to_string(),
                    name: name.to_string(),
                    created_at: now,
                    last_used: None,
                    scopes: scopes
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    expires_at,
                });
                Ok(id)
            }
        }
    }

    pub async fn validate_api_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Option<(String, ApiScopes)>, DbError> {
        match &self.inner {
            DbEngine::Postgres(db) => db.validate_api_token(token, now).await,
            DbEngine::Mock(mock) => {
                let mut tokens = mock.api_tokens.write();
                if let Some(pos) = tokens.iter().position(|t| t.token == token) {
                    let mut t = tokens[pos].clone();
                    if let Some(exp) = t.expires_at
                        && now > exp
                    {
                        return Ok(None);
                    }
                    t.last_used = Some(now);
                    tokens[pos] = t.clone();
                    let scopes = t.scopes.split(',').filter_map(|s| s.parse().ok()).collect();
                    Ok(Some((t.name, scopes)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub async fn delete_api_token(&self, token: &str) -> Result<(), DbError> {
        delegate_db_call!(self, delete_api_token(token), mock => {
            let mut tokens = mock.api_tokens.write();
            tokens.retain(|t| t.token != token);
            Ok(())
        })
    }

    pub async fn delete_api_token_by_id_or_name(&self, id_or_name: &str) -> Result<(), DbError> {
        delegate_db_call!(self, delete_api_token_by_id_or_name(id_or_name), mock => {
            let mut tokens = mock.api_tokens.write();
            if let Ok(id) = id_or_name.parse::<i64>() {
                tokens.retain(|t| t.id != id);
            } else {
                tokens.retain(|t| t.name != id_or_name);
            }
            Ok(())
        })
    }

    pub async fn load_api_tokens(&self) -> Result<Vec<ApiTokenEntry>, DbError> {
        delegate_db_call!(self, load_api_tokens(), mock => {
            let mut tokens = mock.api_tokens.read().clone();
            tokens.sort_by_key(|b| std::cmp::Reverse(b.created_at));
            Ok(tokens)
        })
    }

    pub async fn get_api_token_info(
        &self,
        id_or_name: &str,
    ) -> Result<Option<(String, ApiScopes, Option<i64>)>, DbError> {
        delegate_db_call!(self, get_api_token_info(id_or_name), mock => {
            let tokens = mock.api_tokens.read();
            let found = if let Ok(id) = id_or_name.parse::<i64>() {
                tokens.iter().find(|t| t.id == id).cloned()
            } else {
                tokens.iter().find(|t| t.name == id_or_name).cloned()
            };
            if let Some(t) = found {
                let scopes = t.scopes.split(',').filter_map(|s| s.parse().ok()).collect();
                Ok(Some((t.name, scopes, t.expires_at)))
            } else {
                Ok(None)
            }
        })
    }

    // --- DnsUpstreamStore ---

    pub async fn load_dns_upstreams(&self) -> Result<Vec<DnsUpstreamEntry>, DbError> {
        delegate_db_call!(self, load_dns_upstreams(), mock => {
            let mut upstreams = mock.dns_upstreams.read().clone();
            upstreams.sort_by_key(|u| u.id);
            Ok(upstreams)
        })
    }

    pub async fn add_dns_upstream(
        &self,
        addr: &str,
        protocol: &str,
        domain: Option<&str>,
    ) -> Result<i64, DbError> {
        delegate_db_call!(self, add_dns_upstream(addr, protocol, domain), mock => {
            let mut upstreams = mock.dns_upstreams.write();
            if let Some(pos) = upstreams
                .iter()
                .position(|u| u.addr == addr && u.protocol == protocol)
            {
                upstreams[pos].domain = domain.map(|d| d.to_string());
                Ok(upstreams[pos].id)
            } else {
                let id = upstreams.len() as i64 + 1;
                upstreams.push(DnsUpstreamEntry {
                    id,
                    addr: addr.to_string(),
                    protocol: protocol.to_string(),
                    domain: domain.map(|d| d.to_string()),
                });
                Ok(id)
            }
        })
    }

    pub async fn remove_dns_upstream(&self, addr: &str, protocol: &str) -> Result<(), DbError> {
        delegate_db_call!(self, remove_dns_upstream(addr, protocol), mock => {
            let mut upstreams = mock.dns_upstreams.write();
            upstreams.retain(|u| !(u.addr == addr && u.protocol == protocol));
            Ok(())
        })
    }

    pub async fn clear_dns_upstreams(&self) -> Result<(), DbError> {
        delegate_db_call!(self, clear_dns_upstreams(), mock => {
            mock.dns_upstreams.write().clear();
            Ok(())
        })
    }

    // --- DhcpConfigStore ---

    pub async fn load_dhcp_v4_pools(&self) -> Result<Vec<Dhcpv4Pool>, DbError> {
        delegate_db_call!(self, load_dhcp_v4_pools(), mock => Ok(mock.dhcp_v4_pools.read().clone()))
    }

    pub async fn save_dhcp_v4_pools(&self, pools: &[Dhcpv4Pool]) -> Result<(), DbError> {
        delegate_db_call!(self, save_dhcp_v4_pools(pools), mock => {
            *mock.dhcp_v4_pools.write() = pools.to_vec();
            Ok(())
        })
    }

    pub async fn load_dhcp_v6_pools(&self) -> Result<Vec<Dhcpv6Pool>, DbError> {
        delegate_db_call!(self, load_dhcp_v6_pools(), mock => Ok(mock.dhcp_v6_pools.read().clone()))
    }

    pub async fn save_dhcp_v6_pools(&self, pools: &[Dhcpv6Pool]) -> Result<(), DbError> {
        delegate_db_call!(self, save_dhcp_v6_pools(pools), mock => {
            *mock.dhcp_v6_pools.write() = pools.to_vec();
            Ok(())
        })
    }

    pub async fn load_dhcp_options(&self) -> Result<Option<DhcpOptionsConfig>, DbError> {
        delegate_db_call!(self, load_dhcp_options(), mock => Ok(mock.dhcp_options.read().clone()))
    }

    pub async fn save_dhcp_options(&self, options: &DhcpOptionsConfig) -> Result<(), DbError> {
        delegate_db_call!(self, save_dhcp_options(options), mock => {
            *mock.dhcp_options.write() = Some(options.clone());
            Ok(())
        })
    }

    // --- RaConfigStore ---

    pub async fn load_ra_prefixes(&self) -> Result<Vec<RAPrefix>, DbError> {
        delegate_db_call!(self, load_ra_prefixes(), mock => Ok(mock.ra_prefixes.read().clone()))
    }

    pub async fn save_ra_prefixes(&self, prefixes: &[RAPrefix]) -> Result<(), DbError> {
        delegate_db_call!(self, save_ra_prefixes(prefixes), mock => {
            *mock.ra_prefixes.write() = prefixes.to_vec();
            Ok(())
        })
    }

    pub async fn load_ra_rdnss(&self) -> Result<Vec<RdnssConfig>, DbError> {
        delegate_db_call!(self, load_ra_rdnss(), mock => Ok(mock.ra_rdnss.read().clone()))
    }

    pub async fn save_ra_rdnss(&self, rdnss: &[RdnssConfig]) -> Result<(), DbError> {
        delegate_db_call!(self, save_ra_rdnss(rdnss), mock => {
            *mock.ra_rdnss.write() = rdnss.to_vec();
            Ok(())
        })
    }

    pub async fn load_ra_dnssl(&self) -> Result<Vec<DnsslConfig>, DbError> {
        delegate_db_call!(self, load_ra_dnssl(), mock => Ok(mock.ra_dnssl.read().clone()))
    }

    pub async fn save_ra_dnssl(&self, dnssl: &[DnsslConfig]) -> Result<(), DbError> {
        delegate_db_call!(self, save_ra_dnssl(dnssl), mock => {
            *mock.ra_dnssl.write() = dnssl.to_vec();
            Ok(())
        })
    }

    pub async fn load_last_gua_prefix(&self) -> Result<Option<std::net::Ipv6Addr>, DbError> {
        delegate_db_call!(self, load_last_gua_prefix(), mock => Ok(*mock.last_gua_prefix.read()))
    }

    pub async fn save_last_gua_prefix(
        &self,
        prefix: Option<std::net::Ipv6Addr>,
    ) -> Result<(), DbError> {
        delegate_db_call!(self, save_last_gua_prefix(prefix), mock => {
            *mock.last_gua_prefix.write() = prefix;
            Ok(())
        })
    }

    // --- PppoeConfigStore ---

    pub async fn load_pppoe_config(&self) -> Result<Option<PppoeConfig>, DbError> {
        delegate_db_call!(self, load_pppoe_config(), mock => Ok(mock.pppoe_config.read().clone()))
    }

    pub async fn save_pppoe_config(&self, cfg: &PppoeConfig) -> Result<(), DbError> {
        delegate_db_call!(self, save_pppoe_config(cfg), mock => {
            *mock.pppoe_config.write() = Some(cfg.clone());
            Ok(())
        })
    }

    // --- UserStore ---

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        now: i64,
    ) -> Result<UserEntry, DbError> {
        delegate_db_call!(
            self,
            create_user(username, password_hash, role, now),
            mock => {
                let mut users = mock.users.write();
                if users.iter().any(|u| u.username == username) {
                    return Err(DbError::Validation(format!("User {username} already exists")));
                }
                let id = users.len() as i64 + 1;
                let entry = UserEntry {
                    id,
                    username: username.to_string(),
                    password_hash: password_hash.to_string(),
                    role: role.to_string(),
                    created_at: now,
                    updated_at: now,
                    last_login: None,
                };
                users.push(entry.clone());
                Ok(entry)
            }
        )
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<UserEntry>, DbError> {
        delegate_db_call!(
            self,
            get_user_by_username(username),
            mock => {
                Ok(mock.users.read().iter().find(|u| u.username == username).cloned())
            }
        )
    }

    pub async fn get_user_by_id(&self, id: i64) -> Result<Option<UserEntry>, DbError> {
        delegate_db_call!(
            self,
            get_user_by_id(id),
            mock => {
                Ok(mock.users.read().iter().find(|u| u.id == id).cloned())
            }
        )
    }

    pub async fn list_users(&self) -> Result<Vec<UserEntry>, DbError> {
        delegate_db_call!(
            self,
            list_users(),
            mock => {
                Ok(mock.users.read().clone())
            }
        )
    }

    pub async fn update_user_password(
        &self,
        username: &str,
        new_hash: &str,
        now: i64,
    ) -> Result<(), DbError> {
        delegate_db_call!(
            self,
            update_user_password(username, new_hash, now),
            mock => {
                let mut users = mock.users.write();
                if let Some(user) = users.iter_mut().find(|u| u.username == username) {
                    user.password_hash = new_hash.to_string();
                    user.updated_at = now;
                    Ok(())
                } else {
                    Err(DbError::NotFound(format!("User {username} not found")))
                }
            }
        )
    }

    pub async fn update_user_role(
        &self,
        username: &str,
        new_role: &str,
        now: i64,
    ) -> Result<(), DbError> {
        delegate_db_call!(
            self,
            update_user_role(username, new_role, now),
            mock => {
                let mut users = mock.users.write();
                if let Some(user) = users.iter_mut().find(|u| u.username == username) {
                    user.role = new_role.to_string();
                    user.updated_at = now;
                    Ok(())
                } else {
                    Err(DbError::NotFound(format!("User {username} not found")))
                }
            }
        )
    }

    pub async fn update_user_last_login(&self, username: &str, now: i64) -> Result<(), DbError> {
        delegate_db_call!(
            self,
            update_user_last_login(username, now),
            mock => {
                let mut users = mock.users.write();
                if let Some(user) = users.iter_mut().find(|u| u.username == username) {
                    user.last_login = Some(now);
                }
                Ok(())
            }
        )
    }

    pub async fn delete_user(&self, username: &str) -> Result<(), DbError> {
        delegate_db_call!(
            self,
            delete_user(username),
            mock => {
                let mut users = mock.users.write();
                users.retain(|u| u.username != username);
                Ok(())
            }
        )
    }

    pub async fn count_users(&self) -> Result<i64, DbError> {
        delegate_db_call!(
            self,
            count_users(),
            mock => {
                Ok(mock.users.read().len() as i64)
            }
        )
    }
}

impl DeviceStore for LanforgeDb {
    fn load_all_devices(&self) -> BoxFuture<'_, Result<Vec<Device>, DbError>> {
        Box::pin(async move { self.load_all_devices().await })
    }

    fn upsert_device<'a>(&'a self, device: &'a Device) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.upsert_device(device).await })
    }

    fn upsert_base_device_only<'a>(
        &'a self,
        device: &'a Device,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.upsert_base_device_only(device).await })
    }

    fn delete_devices<'a>(&'a self, macs: &'a [MacAddr]) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.delete_devices(macs).await })
    }

    fn find_mac_by_hostname<'a>(
        &'a self,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<Option<MacAddr>, DbError>> {
        Box::pin(async move { self.find_mac_by_hostname(hostname).await })
    }

    fn remove_device(&self, mac: MacAddr) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.remove_device(mac).await })
    }

    fn vacuum(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.vacuum().await })
    }

    fn prune_zombies(&self) -> BoxFuture<'_, Result<usize, DbError>> {
        Box::pin(async move { self.prune_zombies().await })
    }

    fn reset(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.reset().await })
    }

    fn record_lease_event<'a>(
        &'a self,
        mac: MacAddr,
        ip: &'a str,
        lease_type: &'a str,
        action: LeaseAction,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.record_lease_event(mac, ip, lease_type, action).await })
    }

    fn get_lease_history(
        &self,
        mac: MacAddr,
    ) -> BoxFuture<'_, Result<Vec<LeaseHistoryEntry>, DbError>> {
        Box::pin(async move { self.get_lease_history(mac).await })
    }
}

impl DnsStore for LanforgeDb {
    fn load_dns_rewrites(&self) -> BoxFuture<'_, Result<Vec<RewriteRule>, DbError>> {
        Box::pin(async move { self.load_dns_rewrites().await })
    }

    fn upsert_dns_rewrite<'a>(
        &'a self,
        domain: &'a str,
        rtype: DnsRecordType,
        answer: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.upsert_dns_rewrite(domain, rtype, answer).await })
    }

    fn delete_dns_rewrite_by_id(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.delete_dns_rewrite_by_id(id).await })
    }

    fn clear_dns_rewrites(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_dns_rewrites().await })
    }

    fn load_dns_allowlist(&self) -> BoxFuture<'_, Result<Vec<(i64, String)>, DbError>> {
        Box::pin(async move { self.load_dns_allowlist().await })
    }

    fn add_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.add_dns_allowlist(domain).await })
    }

    fn remove_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.remove_dns_allowlist(domain).await })
    }

    fn clear_dns_allowlist(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_dns_allowlist().await })
    }

    fn load_dns_reverse_resolvers(
        &self,
    ) -> BoxFuture<'_, Result<Vec<DnsReverseResolver>, DbError>> {
        Box::pin(async move { self.load_dns_reverse_resolvers().await })
    }

    fn add_dns_reverse_resolver<'a>(
        &'a self,
        subnet: &'a IpSubnet,
        resolver: &'a UpstreamTarget,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.add_dns_reverse_resolver(subnet, resolver).await })
    }

    fn remove_dns_reverse_resolver<'a>(
        &'a self,
        subnet: &'a IpSubnet,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.remove_dns_reverse_resolver(subnet).await })
    }

    fn clear_dns_reverse_resolvers(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_dns_reverse_resolvers().await })
    }
}

impl AdblockStore for LanforgeDb {
    fn load_adblock_config(&self) -> BoxFuture<'_, Result<AdblockDbConfig, DbError>> {
        Box::pin(async move { self.load_adblock_config().await })
    }

    fn save_adblock_config<'a>(
        &'a self,
        cfg: &'a AdblockDbConfig,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_adblock_config(cfg).await })
    }

    fn set_adblock_config_value<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.set_adblock_config_value(key, value).await })
    }

    fn load_adblock_urls(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind)>, DbError>> {
        Box::pin(async move { self.load_adblock_urls().await })
    }

    fn add_adblock_url<'a>(
        &'a self,
        url: &'a str,
        kind: AdblockUrlKind,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.add_adblock_url(url, kind).await })
    }

    fn remove_adblock_url<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.remove_adblock_url(url).await })
    }

    fn clear_adblock_urls(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_adblock_urls().await })
    }

    fn load_adblock_sources(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind, bool)>, DbError>> {
        Box::pin(async move { self.load_adblock_sources().await })
    }

    fn add_adblock_source<'a>(
        &'a self,
        url: &'a str,
        kind: AdblockUrlKind,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move { self.add_adblock_source(url, kind).await })
    }

    fn remove_adblock_source(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.remove_adblock_source(id).await })
    }

    fn update_adblock_source_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.update_adblock_source_status(id, enabled).await })
    }

    fn clear_adblock_sources(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_adblock_sources().await })
    }

    fn load_adblock_rules(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, String, bool)>, DbError>> {
        Box::pin(async move { self.load_adblock_rules().await })
    }

    fn add_adblock_rule<'a>(
        &'a self,
        domain: &'a str,
        action: &'a str,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move { self.add_adblock_rule(domain, action).await })
    }

    fn remove_adblock_rule(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.remove_adblock_rule(id).await })
    }

    fn update_adblock_rule_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.update_adblock_rule_status(id, enabled).await })
    }

    fn clear_adblock_rules(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_adblock_rules().await })
    }
}

impl ApiTokenStore for LanforgeDb {
    fn store_api_token<'a>(
        &'a self,
        token: &'a str,
        name: &'a str,
        scopes: &'a ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move {
            self.store_api_token(token, name, scopes, expires_at, now)
                .await
        })
    }

    fn validate_api_token<'a>(
        &'a self,
        token: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes)>, DbError>> {
        Box::pin(async move { self.validate_api_token(token, now).await })
    }

    fn delete_api_token<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.delete_api_token(token).await })
    }

    fn delete_api_token_by_id_or_name<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.delete_api_token_by_id_or_name(id_or_name).await })
    }

    fn load_api_tokens(&self) -> BoxFuture<'_, Result<Vec<ApiTokenEntry>, DbError>> {
        Box::pin(async move { self.load_api_tokens().await })
    }

    fn get_api_token_info<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes, Option<i64>)>, DbError>> {
        Box::pin(async move { self.get_api_token_info(id_or_name).await })
    }
}

impl DnsUpstreamStore for LanforgeDb {
    fn load_dns_upstreams(&self) -> BoxFuture<'_, Result<Vec<DnsUpstreamEntry>, DbError>> {
        Box::pin(async move { self.load_dns_upstreams().await })
    }

    fn add_dns_upstream<'a>(
        &'a self,
        addr: &'a str,
        protocol: &'a str,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move { self.add_dns_upstream(addr, protocol, domain).await })
    }

    fn remove_dns_upstream<'a>(
        &'a self,
        addr: &'a str,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.remove_dns_upstream(addr, protocol).await })
    }

    fn clear_dns_upstreams(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_dns_upstreams().await })
    }
}

impl DhcpConfigStore for LanforgeDb {
    fn load_dhcp_v4_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv4Pool>, DbError>> {
        Box::pin(async move { self.load_dhcp_v4_pools().await })
    }

    fn save_dhcp_v4_pools<'a>(
        &'a self,
        pools: &'a [Dhcpv4Pool],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_dhcp_v4_pools(pools).await })
    }

    fn load_dhcp_v6_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv6Pool>, DbError>> {
        Box::pin(async move { self.load_dhcp_v6_pools().await })
    }

    fn save_dhcp_v6_pools<'a>(
        &'a self,
        pools: &'a [Dhcpv6Pool],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_dhcp_v6_pools(pools).await })
    }

    fn load_dhcp_options(&self) -> BoxFuture<'_, Result<Option<DhcpOptionsConfig>, DbError>> {
        Box::pin(async move { self.load_dhcp_options().await })
    }

    fn save_dhcp_options<'a>(
        &'a self,
        options: &'a DhcpOptionsConfig,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_dhcp_options(options).await })
    }
}

impl RaConfigStore for LanforgeDb {
    fn load_ra_prefixes(&self) -> BoxFuture<'_, Result<Vec<RAPrefix>, DbError>> {
        Box::pin(async move { self.load_ra_prefixes().await })
    }

    fn save_ra_prefixes<'a>(
        &'a self,
        prefixes: &'a [RAPrefix],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_ra_prefixes(prefixes).await })
    }

    fn load_ra_rdnss(&self) -> BoxFuture<'_, Result<Vec<RdnssConfig>, DbError>> {
        Box::pin(async move { self.load_ra_rdnss().await })
    }

    fn save_ra_rdnss<'a>(&'a self, rdnss: &'a [RdnssConfig]) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_ra_rdnss(rdnss).await })
    }

    fn load_ra_dnssl(&self) -> BoxFuture<'_, Result<Vec<DnsslConfig>, DbError>> {
        Box::pin(async move { self.load_ra_dnssl().await })
    }

    fn save_ra_dnssl<'a>(&'a self, dnssl: &'a [DnsslConfig]) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_ra_dnssl(dnssl).await })
    }

    fn load_last_gua_prefix(&self) -> BoxFuture<'_, Result<Option<std::net::Ipv6Addr>, DbError>> {
        Box::pin(async move { self.load_last_gua_prefix().await })
    }

    fn save_last_gua_prefix(
        &self,
        prefix: Option<std::net::Ipv6Addr>,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.save_last_gua_prefix(prefix).await })
    }
}

impl PppoeConfigStore for LanforgeDb {
    fn load_pppoe_config(&self) -> BoxFuture<'_, Result<Option<PppoeConfig>, DbError>> {
        Box::pin(async move { self.load_pppoe_config().await })
    }

    fn save_pppoe_config<'a>(&'a self, cfg: &'a PppoeConfig) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.save_pppoe_config(cfg).await })
    }
}

impl UserStore for LanforgeDb {
    fn create_user<'a>(
        &'a self,
        username: &'a str,
        password_hash: &'a str,
        role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<UserEntry, DbError>> {
        Box::pin(async move { self.create_user(username, password_hash, role, now).await })
    }

    fn get_user_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> BoxFuture<'a, Result<Option<UserEntry>, DbError>> {
        Box::pin(async move { self.get_user_by_username(username).await })
    }

    fn get_user_by_id(&self, id: i64) -> BoxFuture<'_, Result<Option<UserEntry>, DbError>> {
        Box::pin(async move { self.get_user_by_id(id).await })
    }

    fn list_users(&self) -> BoxFuture<'_, Result<Vec<UserEntry>, DbError>> {
        Box::pin(async move { self.list_users().await })
    }

    fn update_user_password<'a>(
        &'a self,
        username: &'a str,
        new_hash: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.update_user_password(username, new_hash, now).await })
    }

    fn update_user_role<'a>(
        &'a self,
        username: &'a str,
        new_role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.update_user_role(username, new_role, now).await })
    }

    fn update_user_last_login<'a>(
        &'a self,
        username: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.update_user_last_login(username, now).await })
    }

    fn delete_user<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.delete_user(username).await })
    }

    fn count_users(&self) -> BoxFuture<'_, Result<i64, DbError>> {
        Box::pin(async move { self.count_users().await })
    }
}
