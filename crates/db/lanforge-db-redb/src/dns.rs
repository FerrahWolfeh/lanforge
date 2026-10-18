use std::net::SocketAddr;

use crate::RedbDatabase;
use crate::tables::{
    TABLE_ADBLOCK_RULES, TABLE_ADBLOCK_URLS, TABLE_CONFIG, TABLE_DNS_ALLOWLIST, TABLE_DNS_REWRITES,
    TABLE_DNS_UPSTREAMS,
};
use lanforge_db_core::{
    AdblockStore, DbError, DnsStore, DnsUpstreamEntry, DnsUpstreamStore,
};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockSourceFormat, AdblockUrlKind, RewriteAnswer,
    RewriteRule,
};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::{DnsReverseResolver, IpSubnet};
use redb::{ReadableDatabase, ReadableTable};

impl DnsStore for RedbDatabase {
    fn load_dns_rewrites(&self) -> Result<Vec<RewriteRule>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_DNS_REWRITES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut rules = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let rule: RewriteRule = serde_json::from_slice(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            rules.push(rule);
        }
        rules.sort_by_key(|r| r.id.unwrap_or(0));
        Ok(rules)
    }

    fn upsert_dns_rewrite(
        &self,
        domain: &str,
        rtype: DnsRecordType,
        answer: &RewriteAnswer,
    ) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let table = write_txn
                .open_table(TABLE_DNS_REWRITES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let mut existing_id = None;
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (id, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let r: RewriteRule = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if r.domain.eq_ignore_ascii_case(domain) && r.rtype == rtype {
                    existing_id = Some(id.value());
                    break;
                }
            }

            drop(table);

            let id = match existing_id {
                Some(id) => id,
                None => Self::next_id_in_txn(&write_txn, "dns_rewrites")?,
            };

            let rule = RewriteRule {
                id: Some(id),
                domain: domain.to_string(),
                rtype,
                answer: answer.clone(),
            };

            let bytes = serde_json::to_vec(&rule)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let mut table = write_txn
                .open_table(TABLE_DNS_REWRITES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(id, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn delete_dns_rewrite_by_id(&self, id: i64) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DNS_REWRITES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let _ = table.remove(id);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn clear_dns_rewrites(&self) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let _ = write_txn.delete_table(TABLE_DNS_REWRITES);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_dns_allowlist(&self) -> Result<Vec<(i64, String)>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_DNS_ALLOWLIST) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut list = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (domain, id) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            list.push((id.value(), domain.value().to_string()));
        }
        list.sort_by_key(|(id, _)| *id);
        Ok(list)
    }

    fn add_dns_allowlist(&self, domain: &str) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let id = Self::next_id_in_txn(&write_txn, "dns_allowlist")?;
            let mut table = write_txn
                .open_table(TABLE_DNS_ALLOWLIST)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(domain, id)
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn remove_dns_allowlist(&self, domain: &str) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DNS_ALLOWLIST)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let _ = table.remove(domain);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn clear_dns_allowlist(&self) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let _ = write_txn.delete_table(TABLE_DNS_ALLOWLIST);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_dns_reverse_resolvers(&self) -> Result<Vec<DnsReverseResolver>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("dns_reverse_resolvers").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let res: Vec<DnsReverseResolver> = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(res)
            }
            None => Ok(Vec::new()),
        }
    }

    fn add_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
        resolver: &UpstreamTarget,
    ) -> Result<(), DbError> {
        let mut resolvers = self.load_dns_reverse_resolvers()?;
        resolvers.retain(|r| r.subnet != *subnet);
        resolvers.push(DnsReverseResolver {
            subnet: *subnet,
            resolver: resolver.clone(),
        });

        let bytes = serde_json::to_vec(&resolvers)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("dns_reverse_resolvers", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn remove_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
    ) -> Result<(), DbError> {
        let mut resolvers = self.load_dns_reverse_resolvers()?;
        resolvers.retain(|r| r.subnet != *subnet);

        let bytes = serde_json::to_vec(&resolvers)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("dns_reverse_resolvers", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn clear_dns_reverse_resolvers(&self) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let _ = table.remove("dns_reverse_resolvers");
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum StoredSourceTuple {
    V2(String, AdblockUrlKind, bool, AdblockSourceFormat),
    V1(String, AdblockUrlKind, bool),
}

impl StoredSourceTuple {
    fn into_parts(self) -> (String, AdblockUrlKind, bool, AdblockSourceFormat) {
        match self {
            Self::V2(url, kind, enabled, format) => (url, kind, enabled, format),
            Self::V1(url, kind, enabled) => (url, kind, enabled, AdblockSourceFormat::Auto),
        }
    }
}

impl AdblockStore for RedbDatabase {
    fn load_adblock_config(&self) -> Result<AdblockDbConfig, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(AdblockDbConfig::default()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("adblock_config").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let cfg: AdblockDbConfig = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(cfg)
            }
            None => Ok(AdblockDbConfig::default()),
        }
    }

    fn save_adblock_config(
        &self,
        config: &AdblockDbConfig,
    ) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(config)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("adblock_config", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn set_adblock_config_value(
        &self,
        key: &str,
        value: &str,
    ) -> Result<(), DbError> {
        let mut cfg = self.load_adblock_config()?;
        match key {
            "enabled" => cfg.enabled = value == "true",
            "blocking_mode" => {
                if let Ok(mode) = value.parse() {
                    cfg.blocking_mode = mode;
                }
            }
            "blocking_ip_v4" => {
                cfg.blocking_ip_v4 = if value.is_empty() || value == "none" || value == "null" {
                    None
                } else {
                    Some(value.parse().map_err(|e| DbError::Validation(format!("Invalid IPv4: {e}")))?)
                };
            }
            "blocking_ip_v6" => {
                cfg.blocking_ip_v6 = if value.is_empty() || value == "none" || value == "null" {
                    None
                } else {
                    Some(value.parse().map_err(|e| DbError::Validation(format!("Invalid IPv6: {e}")))?)
                };
            }
            "refresh_time" => {
                if let Ok(tod) = value.parse() {
                    cfg.refresh_time = tod;
                }
            }
            _ => {}
        }
        self.save_adblock_config(&cfg)?;
        Ok(())
    }

    fn load_adblock_urls(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, AdblockSourceFormat)>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_ADBLOCK_URLS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut urls = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (id, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let (url, kind, _, format) = serde_json::from_slice::<StoredSourceTuple>(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?
                .into_parts();
            urls.push((id.value(), url, kind, format));
        }
        urls.sort_by_key(|(id, _, _, _)| *id);
        Ok(urls)
    }

    fn add_adblock_url(
        &self,
        url: &str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let id = Self::next_id_in_txn(&write_txn, "adblock_urls")?;
            let bytes = serde_json::to_vec(&(url, kind, true, format))
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let mut table = write_txn
                .open_table(TABLE_ADBLOCK_URLS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(id, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn remove_adblock_url(&self, url: &str) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = match write_txn.open_table(TABLE_ADBLOCK_URLS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let target_id = {
                let mut found = None;
                for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                    let (id, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                    let (u, _, _): (String, AdblockUrlKind, bool) = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    if u == url {
                        found = Some(id.value());
                        break;
                    }
                }
                found
            };

            if let Some(id) = target_id {
                let _ = table.remove(id);
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn clear_adblock_urls(&self) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let _ = write_txn.delete_table(TABLE_ADBLOCK_URLS);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_adblock_sources(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, bool, AdblockSourceFormat)>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_ADBLOCK_URLS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut urls = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (id, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let (url, kind, enabled, format) = serde_json::from_slice::<StoredSourceTuple>(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?
                .into_parts();
            urls.push((id.value(), url, kind, enabled, format));
        }
        urls.sort_by_key(|(id, _, _, _, _)| *id);
        Ok(urls)
    }

    fn add_adblock_source(
        &self,
        url: &str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> Result<i64, DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let id = {
            let id = Self::next_id_in_txn(&write_txn, "adblock_urls")?;
            let bytes = serde_json::to_vec(&(url, kind, true, format))
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let mut table = write_txn
                .open_table(TABLE_ADBLOCK_URLS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(id, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
            id
        };
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(id)
    }

    fn remove_adblock_source(&self, id: i64) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_ADBLOCK_URLS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let _ = table.remove(id);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn update_adblock_source_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_ADBLOCK_URLS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let updated = {
                if let Some(val) = table.get(id).map_err(|e| DbError::Backend(e.to_string()))? {
                    let (url, kind, _): (String, AdblockUrlKind, bool) =
                        serde_json::from_slice(val.value())
                            .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    Some((url, kind, enabled))
                } else {
                    None
                }
            };

            if let Some(entry) = updated {
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                table
                    .insert(id, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn clear_adblock_sources(&self) -> Result<(), DbError> {
        self.clear_adblock_urls()
    }

    fn load_adblock_rules(
        &self,
    ) -> Result<Vec<(i64, String, AdblockRuleAction, bool)>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_ADBLOCK_RULES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut rules = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (id, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let (domain, action, enabled): (String, AdblockRuleAction, bool) =
                serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            rules.push((id.value(), domain, action, enabled));
        }
        rules.sort_by_key(|(id, _, _, _)| *id);
        Ok(rules)
    }

    fn add_adblock_rule(
        &self,
        domain: &str,
        action: AdblockRuleAction,
    ) -> Result<i64, DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let id = {
            let id = Self::next_id_in_txn(&write_txn, "adblock_rules")?;
            let bytes = serde_json::to_vec(&(domain, action, true))
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let mut table = write_txn
                .open_table(TABLE_ADBLOCK_RULES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(id, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
            id
        };
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(id)
    }

    fn remove_adblock_rule(&self, id: i64) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_ADBLOCK_RULES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let _ = table.remove(id);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn update_adblock_rule_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_ADBLOCK_RULES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let updated = {
                if let Some(val) = table.get(id).map_err(|e| DbError::Backend(e.to_string()))? {
                    let (domain, action, _): (String, AdblockRuleAction, bool) =
                        serde_json::from_slice(val.value())
                            .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    Some((domain, action, enabled))
                } else {
                    None
                }
            };

            if let Some(entry) = updated {
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

                table
                    .insert(id, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn clear_adblock_rules(&self) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let _ = write_txn.delete_table(TABLE_ADBLOCK_RULES);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl DnsUpstreamStore for RedbDatabase {
    fn load_dns_upstreams(&self) -> Result<Vec<DnsUpstreamEntry>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_DNS_UPSTREAMS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut upstreams = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let entry: DnsUpstreamEntry = serde_json::from_slice(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            upstreams.push(entry);
        }
        upstreams.sort_by_key(|u| u.id);
        Ok(upstreams)
    }

    fn add_dns_upstream(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&str>,
    ) -> Result<i64, DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let id = {
            let id = Self::next_id_in_txn(&write_txn, "dns_upstreams")?;
            let entry = DnsUpstreamEntry {
                id,
                addr,
                protocol,
                domain: domain.map(ToString::to_string),
            };

            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let mut table = write_txn
                .open_table(TABLE_DNS_UPSTREAMS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(id, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
            id
        };
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(id)
    }

    fn remove_dns_upstream(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&str>,
    ) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = match write_txn.open_table(TABLE_DNS_UPSTREAMS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let target_id = {
                let mut found = None;
                for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                    let (id, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                    let entry: DnsUpstreamEntry = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    let domain_match = match domain {
                        Some(d) => entry.domain.as_deref() == Some(d),
                        None => true,
                    };
                    if entry.addr == addr && entry.protocol == protocol && domain_match {
                        found = Some(id.value());
                        break;
                    }
                }
                found
            };

            if let Some(id) = target_id {
                let _ = table.remove(id);
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn clear_dns_upstreams(&self) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let _ = write_txn.delete_table(TABLE_DNS_UPSTREAMS);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_dns_upstream_mode(&self) -> Result<Option<UpstreamMode>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("dns_upstream_mode").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let mode_str = std::str::from_utf8(val.value())
                    .map_err(|e| DbError::Backend(format!("UTF-8 decode error: {e}")))?;
                let mode: UpstreamMode = mode_str
                    .parse()
                    .map_err(|e| DbError::Backend(format!("Invalid mode: {e}")))?;
                Ok(Some(mode))
            }
            None => Ok(None),
        }
    }

    fn save_dns_upstream_mode(&self, mode: UpstreamMode) -> Result<(), DbError> {
        let mode_str = mode.to_string();
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("dns_upstream_mode", mode_str.as_bytes())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}
