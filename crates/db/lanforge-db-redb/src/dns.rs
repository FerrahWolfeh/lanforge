//! DnsStore, AdblockStore, and DnsUpstreamStore implementations for `RedbDatabase`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::RedbDatabase;
use lanforge_db_core::{
    AdblockStore, ConfigKey, DbError, DnsStore, DnsUpstreamEntry, DnsUpstreamStore, config_keys::*,
};
use lanforge_types::identifiers::DeviceIdentifier;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockRuleEntry, AdblockSourceFormat, AdblockUrlKind,
    RewriteAnswer, RewriteRule,
};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::dns::{AdblockUrlEntry, DnsRecordType};
use lanforge_types::network::{DnsReverseResolver, IpSubnet};

/// `DNS_REWRITES` as stored before SRV rewrites were removed. postcard encodes enum variants by
/// index, so one stored `Service` answer would make the whole list undecodable: rules are read in
/// this shape and SRV answers are dropped. Goes away with the redb DNS keys (config-storage step 5).
const STORED_DNS_REWRITES: ConfigKey<Vec<StoredRewriteRule>> = ConfigKey::new(DNS_REWRITES.name());

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRewriteRule {
    id: Option<i64>,
    domain: String,
    rtype: DnsRecordType,
    answer: StoredRewriteAnswer,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum StoredRewriteAnswer {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Device {
        identifier: DeviceIdentifier,
        fallback: Option<Box<Self>>,
    },
    Service {
        service: StoredSrvService,
        protocol: StoredSrvProtocol,
        device: DeviceIdentifier,
        port: u16,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
enum StoredSrvService {
    Http,
    Https,
    Ssh,
    Ftp,
    Minecraft,
    Plex,
    Jellyfin,
    Ldap,
    Custom(String),
}

#[derive(serde::Serialize, serde::Deserialize)]
enum StoredSrvProtocol {
    Tcp,
    Udp,
}

impl StoredRewriteAnswer {
    /// The answer without SRV: `None` for an SRV answer, an SRV fallback is dropped.
    fn into_answer(self) -> Option<RewriteAnswer> {
        match self {
            Self::A(ip) => Some(RewriteAnswer::A(ip)),
            Self::Aaaa(ip) => Some(RewriteAnswer::Aaaa(ip)),
            Self::Cname(host) => Some(RewriteAnswer::Cname(host)),
            Self::Device {
                identifier,
                fallback,
            } => Some(RewriteAnswer::Device {
                identifier,
                fallback: fallback.and_then(|fb| fb.into_answer()).map(Box::new),
            }),
            Self::Service { .. } => None,
        }
    }
}

impl DnsStore for RedbDatabase {
    fn load_dns_rewrites(&self) -> Result<Vec<RewriteRule>, DbError> {
        let stored = self.get(STORED_DNS_REWRITES)?.unwrap_or_default();
        Ok(stored
            .into_iter()
            .filter_map(|rule| {
                let Some(answer) = rule.answer.into_answer() else {
                    tracing::warn!(domain = %rule.domain, "dropping a stored SRV DNS rewrite: SRV rewrites are no longer supported");
                    return None;
                };
                Some(RewriteRule {
                    id: rule.id,
                    domain: rule.domain,
                    rtype: rule.rtype,
                    answer,
                })
            })
            .collect())
    }

    fn upsert_dns_rewrite(
        &self,
        domain: &str,
        rtype: DnsRecordType,
        answer: &RewriteAnswer,
    ) -> Result<(), DbError> {
        let mut list = self.load_dns_rewrites()?;
        if let Some(existing) = list
            .iter_mut()
            .find(|r| r.domain.eq_ignore_ascii_case(domain) && r.rtype == rtype)
        {
            existing.answer = answer.clone();
        } else {
            let max_id = list.iter().filter_map(|r| r.id).max().unwrap_or(0);
            list.push(RewriteRule {
                id: Some(max_id + 1),
                domain: domain.to_string(),
                rtype,
                answer: answer.clone(),
            });
        }
        self.put(DNS_REWRITES, &list)
    }

    fn delete_dns_rewrite_by_id(&self, id: i64) -> Result<(), DbError> {
        let mut list = self.load_dns_rewrites()?;
        list.retain(|r| r.id != Some(id));
        self.put(DNS_REWRITES, &list)
    }

    fn clear_dns_rewrites(&self) -> Result<(), DbError> {
        self.put(DNS_REWRITES, &Vec::new())
    }

    fn load_dns_allowlist(&self) -> Result<Vec<(i64, String)>, DbError> {
        let list = self.get(DNS_ALLOWLIST)?.unwrap_or_default();
        Ok(list
            .into_iter()
            .enumerate()
            .map(|(i, d)| (i as i64 + 1, d))
            .collect())
    }

    fn add_dns_allowlist(&self, domain: &str) -> Result<(), DbError> {
        let mut list = self.get(DNS_ALLOWLIST)?.unwrap_or_default();
        if !list.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
            list.push(domain.to_string());
            self.put(DNS_ALLOWLIST, &list)?;
        }
        Ok(())
    }

    fn remove_dns_allowlist(&self, domain: &str) -> Result<(), DbError> {
        let mut list = self.get(DNS_ALLOWLIST)?.unwrap_or_default();
        list.retain(|d| !d.eq_ignore_ascii_case(domain));
        self.put(DNS_ALLOWLIST, &list)
    }

    fn clear_dns_allowlist(&self) -> Result<(), DbError> {
        self.put(DNS_ALLOWLIST, &Vec::new())
    }

    fn load_dns_reverse_resolvers(&self) -> Result<Vec<DnsReverseResolver>, DbError> {
        Ok(self.get(DNS_REVERSE_RESOLVERS)?.unwrap_or_default())
    }

    fn add_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
        resolver: &UpstreamTarget,
    ) -> Result<(), DbError> {
        let mut list = self.load_dns_reverse_resolvers()?;
        list.retain(|r| r.subnet != *subnet);
        list.push(DnsReverseResolver {
            subnet: *subnet,
            resolver: resolver.clone(),
        });
        self.put(DNS_REVERSE_RESOLVERS, &list)
    }

    fn remove_dns_reverse_resolver(&self, subnet: &IpSubnet) -> Result<(), DbError> {
        let mut list = self.load_dns_reverse_resolvers()?;
        list.retain(|r| r.subnet != *subnet);
        self.put(DNS_REVERSE_RESOLVERS, &list)
    }

    fn clear_dns_reverse_resolvers(&self) -> Result<(), DbError> {
        self.put(DNS_REVERSE_RESOLVERS, &Vec::new())
    }
}

impl AdblockStore for RedbDatabase {
    fn load_adblock_config(&self) -> Result<AdblockDbConfig, DbError> {
        Ok(self.get(ADBLOCK_CONFIG)?.unwrap_or_default())
    }

    fn save_adblock_config(&self, cfg: &AdblockDbConfig) -> Result<(), DbError> {
        self.put(ADBLOCK_CONFIG, cfg)
    }

    fn set_adblock_config_value(&self, key: &str, value: &str) -> Result<(), DbError> {
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
                    Some(
                        value
                            .parse()
                            .map_err(|e| DbError::Validation(format!("Invalid IPv4: {e}")))?,
                    )
                };
            }
            "blocking_ip_v6" => {
                cfg.blocking_ip_v6 = if value.is_empty() || value == "none" || value == "null" {
                    None
                } else {
                    Some(
                        value
                            .parse()
                            .map_err(|e| DbError::Validation(format!("Invalid IPv6: {e}")))?,
                    )
                };
            }
            "refresh_time" => {
                if let Ok(time) = value.parse() {
                    cfg.refresh_time = time;
                }
            }
            _ => {}
        }
        self.save_adblock_config(&cfg)
    }

    fn load_adblock_urls(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, AdblockSourceFormat)>, DbError> {
        let list = self.get(ADBLOCK_URLS)?.unwrap_or_default();
        Ok(list
            .into_iter()
            .enumerate()
            .map(|(i, u)| (u.id.unwrap_or(i as i64 + 1), u.url, u.kind, u.format))
            .collect())
    }

    fn add_adblock_url(
        &self,
        url: &str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> Result<(), DbError> {
        let mut list = self.get(ADBLOCK_URLS)?.unwrap_or_default();
        if !list.iter().any(|u| u.url == url) {
            let mut entry = AdblockUrlEntry {
                id: None,
                name: None,
                url: url.to_string(),
                kind,
                format,
            };
            entry.id = Some(entry.source_id());
            list.push(entry);
            self.put(ADBLOCK_URLS, &list)?;
        }
        Ok(())
    }

    fn remove_adblock_url(&self, url: &str) -> Result<(), DbError> {
        let mut list = self.get(ADBLOCK_URLS)?.unwrap_or_default();
        list.retain(|u| u.url != url);
        self.put(ADBLOCK_URLS, &list)
    }

    fn clear_adblock_urls(&self) -> Result<(), DbError> {
        self.put(ADBLOCK_URLS, &Vec::new())
    }

    fn load_adblock_sources(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, bool, AdblockSourceFormat)>, DbError> {
        let list = self.get(ADBLOCK_URLS)?.unwrap_or_default();
        Ok(list
            .into_iter()
            .enumerate()
            .map(|(i, u)| (u.id.unwrap_or(i as i64 + 1), u.url, u.kind, true, u.format))
            .collect())
    }

    fn add_adblock_source(
        &self,
        url: &str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> Result<i64, DbError> {
        let mut list = self.get(ADBLOCK_URLS)?.unwrap_or_default();
        let mut entry = AdblockUrlEntry {
            id: None,
            name: None,
            url: url.to_string(),
            kind,
            format,
        };
        let id = entry.source_id();
        entry.id = Some(id);
        if !list.iter().any(|u| u.url == url) {
            list.push(entry);
            self.put(ADBLOCK_URLS, &list)?;
        }
        Ok(id)
    }

    fn remove_adblock_source(&self, id: i64) -> Result<(), DbError> {
        let mut list = self.get(ADBLOCK_URLS)?.unwrap_or_default();
        list.retain(|u| u.id != Some(id));
        self.put(ADBLOCK_URLS, &list)
    }

    fn update_adblock_source_status(&self, _id: i64, _enabled: bool) -> Result<(), DbError> {
        Ok(())
    }

    fn clear_adblock_sources(&self) -> Result<(), DbError> {
        self.clear_adblock_urls()
    }

    fn load_adblock_rules(&self) -> Result<Vec<(i64, String, AdblockRuleAction, bool)>, DbError> {
        let list = self.get(ADBLOCK_RULES)?.unwrap_or_default();
        Ok(list
            .into_iter()
            .enumerate()
            .map(|(i, r)| (r.id.unwrap_or(i as i64 + 1), r.domain, r.action, r.enabled))
            .collect())
    }

    fn add_adblock_rule(&self, domain: &str, action: AdblockRuleAction) -> Result<i64, DbError> {
        let mut list = self.get(ADBLOCK_RULES)?.unwrap_or_default();
        let mut entry = AdblockRuleEntry {
            id: None,
            name: None,
            domain: domain.to_string(),
            action,
            enabled: true,
        };
        let id = entry.deterministic_id();
        entry.id = Some(id);
        list.push(entry);
        self.put(ADBLOCK_RULES, &list)?;
        Ok(id)
    }

    fn remove_adblock_rule(&self, id: i64) -> Result<(), DbError> {
        let mut list = self.get(ADBLOCK_RULES)?.unwrap_or_default();
        list.retain(|r| r.id != Some(id));
        self.put(ADBLOCK_RULES, &list)
    }

    fn update_adblock_rule_status(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        let mut list = self.get(ADBLOCK_RULES)?.unwrap_or_default();
        if let Some(r) = list.iter_mut().find(|r| r.id == Some(id)) {
            r.enabled = enabled;
            self.put(ADBLOCK_RULES, &list)?;
        }
        Ok(())
    }

    fn clear_adblock_rules(&self) -> Result<(), DbError> {
        self.put(ADBLOCK_RULES, &Vec::new())
    }
}

impl DnsUpstreamStore for RedbDatabase {
    fn load_dns_upstreams(&self) -> Result<Vec<DnsUpstreamEntry>, DbError> {
        Ok(self.get(DNS_UPSTREAMS)?.unwrap_or_default())
    }

    fn add_dns_upstream(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&str>,
    ) -> Result<i64, DbError> {
        let mut list = self.load_dns_upstreams()?;
        let mut entry = DnsUpstreamEntry {
            id: 0,
            name: None,
            addr,
            protocol,
            domain: domain.map(String::from),
        };
        let id = entry.deterministic_id();
        entry.id = id;
        list.push(entry);
        self.put(DNS_UPSTREAMS, &list)?;
        Ok(id)
    }

    fn remove_dns_upstream(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&str>,
    ) -> Result<(), DbError> {
        let mut list = self.load_dns_upstreams()?;
        list.retain(|e| {
            !(e.addr == addr && e.protocol == protocol && e.domain.as_deref() == domain)
        });
        self.put(DNS_UPSTREAMS, &list)
    }

    fn clear_dns_upstreams(&self) -> Result<(), DbError> {
        self.put(DNS_UPSTREAMS, &Vec::new())
    }

    fn load_dns_upstream_mode(&self) -> Result<Option<UpstreamMode>, DbError> {
        self.get(DNS_UPSTREAM_MODE)
    }

    fn save_dns_upstream_mode(&self, mode: UpstreamMode) -> Result<(), DbError> {
        self.put(DNS_UPSTREAM_MODE, &mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A list stored by a binary that still had SRV rewrites decodes, minus the SRV entries.
    #[test]
    fn stored_srv_rewrites_are_dropped_not_fatal() {
        let db = RedbDatabase::open_temp().unwrap();
        let nas = || DeviceIdentifier::Name("nas".to_string());
        let stored = vec![
            StoredRewriteRule {
                id: Some(1),
                domain: "_http._tcp.nas.lan".to_string(),
                rtype: DnsRecordType::SRV,
                answer: StoredRewriteAnswer::Service {
                    service: StoredSrvService::Custom("my-app".to_string()),
                    protocol: StoredSrvProtocol::Udp,
                    device: nas(),
                    port: 5000,
                },
            },
            StoredRewriteRule {
                id: Some(2),
                domain: "nas.lan".to_string(),
                rtype: DnsRecordType::Device,
                answer: StoredRewriteAnswer::Device {
                    identifier: nas(),
                    fallback: Some(Box::new(StoredRewriteAnswer::A(Ipv4Addr::new(
                        192, 0, 2, 9,
                    )))),
                },
            },
            StoredRewriteRule {
                id: Some(3),
                domain: "alias.lan".to_string(),
                rtype: DnsRecordType::CNAME,
                answer: StoredRewriteAnswer::Cname("nas.lan".to_string()),
            },
        ];
        db.put(STORED_DNS_REWRITES, &stored).unwrap();

        let loaded = db.load_dns_rewrites().unwrap();
        assert_eq!(
            loaded,
            vec![
                RewriteRule {
                    id: Some(2),
                    domain: "nas.lan".to_string(),
                    rtype: DnsRecordType::Device,
                    answer: RewriteAnswer::Device {
                        identifier: nas(),
                        fallback: Some(Box::new(RewriteAnswer::A(Ipv4Addr::new(192, 0, 2, 9)))),
                    },
                },
                RewriteRule {
                    id: Some(3),
                    domain: "alias.lan".to_string(),
                    rtype: DnsRecordType::CNAME,
                    answer: RewriteAnswer::Cname("nas.lan".to_string()),
                },
            ]
        );
    }

    /// Today's `RewriteRule` still encodes the same bytes the stored shape reads.
    #[test]
    fn current_rewrites_roundtrip_through_the_stored_shape() {
        let db = RedbDatabase::open_temp().unwrap();
        db.upsert_dns_rewrite(
            "nas.lan",
            DnsRecordType::A,
            &RewriteAnswer::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .unwrap();
        db.upsert_dns_rewrite(
            "v6.lan",
            DnsRecordType::AAAA,
            &RewriteAnswer::Aaaa(Ipv6Addr::LOCALHOST),
        )
        .unwrap();
        let loaded = db.load_dns_rewrites().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].answer, RewriteAnswer::Aaaa(Ipv6Addr::LOCALHOST));
    }
}
