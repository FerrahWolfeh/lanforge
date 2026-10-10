use crate::ClientContext;
use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, ImportResult, ImportSection, Response, SystemConfigExport,
    SystemConfigImportResponse,
};
use lanforge_types::network::dns::adblock::AdblockDbConfig;

impl ClientContext {
    pub async fn handle_system_config_export(&self) -> Response {
        // 1. Hosts
        let hosts = if let Response::Hosts(res) = self.handle_hosts().await {
            res.hosts
        } else {
            Vec::new()
        };

        // 2. DNS Rewrites
        let dns_rewrites = if let Response::DnsRewrites(res) = self.handle_dns_rewrites().await {
            res.rewrites
        } else {
            Vec::new()
        };

        // 3. DNS Upstreams
        let dns_upstreams = self
            .ctx
            .get_dns_upstreams()
            .into_iter()
            .map(|row| DnsUpstreamConfig {
                addr: row.addr,
                protocol: row.protocol,
                domain: row.domain,
            })
            .collect();

        // 4. Adblock Config
        let dns_adblock_config = self.ctx.get_dns_adblock();

        // 5. Adblock URLs
        let dns_adblock_urls = self.ctx.get_dns_adblock_urls();

        // 6. DNS Allowlist
        let dns_allowlist = self
            .ctx
            .get_dns_allowlist()
            .into_iter()
            .enumerate()
            .map(|(id, domain)| AllowlistEntry {
                id: id as i64 + 1,
                domain,
            })
            .collect();

        // 6b. DNS Adblock Rules
        let dns_adblock_rules = Some(self.ctx.get_dns_adblock_rules());

        // 7. API Tokens
        let api_tokens = if let Some(storage) = self.ctx.storage_handle() {
            match storage
                .send_query(lanforge_types::storage::StorageQuery::LoadApiTokens)
                .await
            {
                Ok(lanforge_types::storage::StorageQueryResult::ApiTokens(tokens)) => Some(
                    tokens
                        .into_iter()
                        .map(|t| lanforge_api::api::ExportedApiToken {
                            token: t.token,
                            name: t.name,
                            created_at: t.created_at,
                            last_used: t.last_used,
                            scopes: t.scopes,
                            expires_at: t.expires_at,
                        })
                        .collect(),
                ),
                _ => None,
            }
        } else {
            None
        };

        // 8. Dynamic Configs (pools, prefixes, pppoe, options, reverse resolvers)
        let dhcp_v4_pools = Some(self.ctx.get_dhcp_v4_pools());
        let dhcp_v6_pools = Some(self.ctx.get_dhcp_v6_pools());
        let ra_prefixes = Some(self.ctx.get_ra_prefixes());
        let ra_rdnss = Some(self.ctx.get_ra_rdnss());
        let ra_dnssl = Some(self.ctx.get_ra_dnssl());
        let pppoe_config = self.ctx.get_pppoe_config().map(Box::new);
        let dhcp_options = Some(Box::new(self.ctx.get_dhcp_options()));
        let dns_reverse_resolvers = Some(self.ctx.with_state(|s| s.reverse_resolvers.clone()));

        Response::SystemConfig(Box::new(SystemConfigExport {
            hosts,
            dns_rewrites,
            dns_upstreams,
            dns_adblock_config,
            dns_adblock_urls,
            dns_allowlist,
            dns_adblock_rules,
            api_tokens,
            dhcp_v4_pools,
            dhcp_v6_pools,
            ra_prefixes,
            ra_rdnss,
            ra_dnssl,
            pppoe_config,
            dhcp_options,
            dns_reverse_resolvers,
            overwrite: false,
        }))
    }

    pub async fn handle_system_config_import(&self, config: SystemConfigExport) -> Response {
        let SystemConfigExport {
            hosts,
            dns_rewrites,
            dns_upstreams,
            dns_adblock_config,
            dns_adblock_urls,
            dns_allowlist,
            dns_adblock_rules,
            api_tokens,
            dhcp_v4_pools,
            dhcp_v6_pools,
            ra_prefixes,
            ra_rdnss,
            ra_dnssl,
            pppoe_config,
            dhcp_options,
            dns_reverse_resolvers,
            overwrite,
        } = config;

        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let mut dhcp_v4_dirty = overwrite;
        let mut dhcp_v6_dirty = overwrite;
        let mut ra_dirty = overwrite;

        let mut total_success = true;
        let mut results = Vec::new();

        if overwrite {
            // Clear existing static hosts
            let static_macs = self.ctx.with_state(|state| {
                state
                    .devices
                    .values()
                    .filter(|dev| dev.origin != lanforge_types::device::Origin::Dynamic)
                    .map(|dev| dev.mac)
                    .collect::<Vec<_>>()
            });
            for mac in static_macs {
                let _ = self
                    .ctx
                    .apply(lanforge_types::update::DeviceUpdate::Remove(mac));
            }

            // Clear DNS rewrites, upstreams, adblock URLs, allowlist
            if let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::ClearDnsRewrites)
                .await
            {
                total_success = false;
                results.push(ImportResult {
                    section: ImportSection::DnsRewrites,
                    success: false,
                    count: 0,
                    error: Some(format!("Failed to clear DNS rewrites: {e}")),
                });
            } else {
                self.ctx.update_dns_rewrites(Vec::new());
            }
            if let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::ClearDnsUpstreams)
                .await
            {
                total_success = false;
                results.push(ImportResult {
                    section: ImportSection::DnsUpstreams,
                    success: false,
                    count: 0,
                    error: Some(format!("Failed to clear DNS upstreams: {e}")),
                });
            } else {
                self.ctx.update_dns_upstreams(Vec::new());
            }
            if let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::ClearAdblockUrls)
                .await
            {
                total_success = false;
                results.push(ImportResult {
                    section: ImportSection::DnsAdblockUrls,
                    success: false,
                    count: 0,
                    error: Some(format!("Failed to clear Adblock URLs: {e}")),
                });
            } else {
                self.ctx.update_dns_adblock_urls(Vec::new());
            }
            if let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::ClearDnsAllowlist)
                .await
            {
                total_success = false;
                results.push(ImportResult {
                    section: ImportSection::DnsAllowlist,
                    success: false,
                    count: 0,
                    error: Some(format!("Failed to clear DNS allowlist: {e}")),
                });
            } else {
                self.ctx.update_dns_allowlist(Vec::new());
            }

            if let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::ClearAdblockRules)
                .await
            {
                total_success = false;
                results.push(ImportResult {
                    section: ImportSection::DnsAdblockRules,
                    success: false,
                    count: 0,
                    error: Some(format!("Failed to clear Adblock rules: {e}")),
                });
            } else {
                self.ctx.update_dns_adblock_rules(Vec::new());
            }

            // Clear API Tokens
            if let Ok(lanforge_types::storage::StorageQueryResult::ApiTokens(existing_tokens)) = storage
                .send_query(lanforge_types::storage::StorageQuery::LoadApiTokens)
                .await
            {
                for token in existing_tokens {
                    let _ = storage
                        .send_query(lanforge_types::storage::StorageQuery::DeleteApiToken(
                            token.token,
                        ))
                        .await;
                }
            }

            // Clear Dynamic Configs by overwriting with empty lists
            self.ctx.update_dhcp_v4_pools(Vec::new());
            self.ctx.update_dhcp_v6_pools(Vec::new());
            self.ctx.update_ra_config(Vec::new(), Vec::new(), Vec::new());
            let _ = storage
                .send_query(lanforge_types::storage::StorageQuery::ClearReverseResolvers)
                .await;
        }

        // 1. Import hosts
        let mut hosts_count = 0;
        let mut hosts_success = true;
        let mut hosts_err = None;
        for entry in hosts {
            match self.handle_host_add(entry).await {
                Response::Success(_) => hosts_count += 1,
                Response::Error { error } => {
                    hosts_success = false;
                    hosts_err = Some(error);
                }
                _ => {}
            }
        }
        if !hosts_success {
            total_success = false;
        }
        results.push(ImportResult {
            section: ImportSection::Hosts,
            success: hosts_success,
            count: hosts_count,
            error: hosts_err,
        });

        // 2. Import DNS rewrites
        let mut rewrites_count = 0;
        let mut rewrites_success = true;
        let mut rewrites_err = None;
        for rule in dns_rewrites {
            match self.handle_dns_rewrite_add(rule).await {
                Response::Success(_) => rewrites_count += 1,
                Response::Error { error } => {
                    rewrites_success = false;
                    rewrites_err = Some(error);
                }
                _ => {}
            }
        }
        if !rewrites_success {
            total_success = false;
        }
        results.push(ImportResult {
            section: ImportSection::DnsRewrites,
            success: rewrites_success,
            count: rewrites_count,
            error: rewrites_err,
        });

        // 3. Import DNS upstreams
        let mut upstream_count = 0;
        let mut upstreams_success = true;
        let mut upstreams_err = None;
        for u in dns_upstreams {
            match self
                .handle_dns_upstream_add(u.addr, u.protocol, u.domain)
                .await
            {
                Response::Success(_) => upstream_count += 1,
                Response::Error { error } => {
                    upstreams_success = false;
                    upstreams_err = Some(error);
                }
                _ => {}
            }
        }
        if !upstreams_success {
            total_success = false;
        }
        results.push(ImportResult {
            section: ImportSection::DnsUpstreams,
            success: upstreams_success,
            count: upstream_count,
            error: upstreams_err,
        });

        // 4. Import Adblock Config
        let AdblockDbConfig {
            enabled,
            blocking_mode,
            blocking_ip_v4,
            blocking_ip_v6,
            refresh_time,
        } = dns_adblock_config;

        let mut adblock_cfg_success = true;
        let mut adblock_cfg_err = None;
        if let Err(e) = storage
            .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                key: "enabled".into(),
                value: if enabled { "true".into() } else { "false".into() },
            })
            .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set enabled: {e}"));
        }
        if adblock_cfg_success
            && let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                    key: "blocking_mode".into(),
                    value: blocking_mode.to_string(),
                })
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set blocking_mode: {e}"));
        }
        if adblock_cfg_success
            && let Some(ip) = blocking_ip_v4
            && let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                    key: "blocking_ip_v4".into(),
                    value: ip.to_string(),
                })
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set blocking_ip_v4: {e}"));
        }
        if adblock_cfg_success
            && let Some(ip) = blocking_ip_v6
            && let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                    key: "blocking_ip_v6".into(),
                    value: ip.to_string(),
                })
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set blocking_ip_v6: {e}"));
        }
        if adblock_cfg_success
            && let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                    key: "refresh_time".into(),
                    value: refresh_time.to_string(),
                })
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set refresh_time: {e}"));
        }
        if !adblock_cfg_success {
            total_success = false;
        }
        results.push(ImportResult {
            section: ImportSection::DnsAdblockConfig,
            success: adblock_cfg_success,
            count: if adblock_cfg_success { 1 } else { 0 },
            error: adblock_cfg_err,
        });

        // 5. Import Adblock URLs
        let mut url_count = 0;
        let mut url_success = true;
        let mut url_err = None;
        for u in dns_adblock_urls {
            match self.handle_dns_adblock_url_add(u.url, u.kind, Some(u.format)).await {
                Response::Success(_) => url_count += 1,
                Response::Error { error } => {
                    url_success = false;
                    url_err = Some(error);
                }
                _ => {}
            }
        }
        if !url_success {
            total_success = false;
        }
        results.push(ImportResult {
            section: ImportSection::DnsAdblockUrls,
            success: url_success,
            count: url_count,
            error: url_err,
        });

        // 6. Import DNS allowlist
        let mut allow_count = 0;
        let mut allow_success = true;
        let mut allow_err = None;
        for a in dns_allowlist {
            match self.handle_dns_allow(a.domain).await {
                Response::Success(_) => allow_count += 1,
                Response::Error { error } => {
                    allow_success = false;
                    allow_err = Some(error);
                }
                _ => {}
            }
        }
        if !allow_success {
            total_success = false;
        }
        results.push(ImportResult {
            section: ImportSection::DnsAllowlist,
            success: allow_success,
            count: allow_count,
            error: allow_err,
        });

        // 6b. Import Adblock Rules
        if let Some(rules) = dns_adblock_rules {
            let mut rules_count = 0;
            let mut rules_success = true;
            let mut rules_err = None;
            for r in rules {
                match storage
                    .send_query(lanforge_types::storage::StorageQuery::AddAdblockRule {
                        domain: r.domain,
                        action: r.action,
                    })
                    .await
                {
                    Ok(lanforge_types::storage::StorageQueryResult::Id(id)) => {
                        if !r.enabled {
                            let _ = storage
                                .send_query(
                                    lanforge_types::storage::StorageQuery::UpdateAdblockRuleStatus {
                                        id,
                                        enabled: false,
                                    },
                                )
                                .await;
                        }
                        rules_count += 1;
                    }
                    Ok(_) => {
                        rules_count += 1;
                    }
                    Err(e) => {
                        rules_success = false;
                        rules_err = Some(e);
                    }
                }
            }
            if !rules_success {
                total_success = false;
            }
            results.push(ImportResult {
                section: ImportSection::DnsAdblockRules,
                success: rules_success,
                count: rules_count,
                error: rules_err,
            });
        }

        // 7. Import API Tokens
        if let Some(tokens) = api_tokens {
            let mut imported_tokens = 0;
            let mut tokens_success = true;
            let mut tokens_err = None;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            for t in tokens {
                if let Err(e) = storage
                    .send_query(lanforge_types::storage::StorageQuery::StoreApiToken {
                        token: t.token,
                        name: t.name,
                        scopes: t.scopes,
                        expires_at: t.expires_at,
                        now,
                    })
                    .await
                {
                    tokens_success = false;
                    tokens_err = Some(e);
                } else {
                    imported_tokens += 1;
                }
            }
            if !tokens_success {
                total_success = false;
            }
            results.push(ImportResult {
                section: ImportSection::ApiTokens,
                success: tokens_success,
                count: imported_tokens,
                error: tokens_err,
            });
        }

        // 8. Import Dynamic Configs
        if let Some(ref pools) = dhcp_v4_pools {
            self.ctx.update_dhcp_v4_pools(pools.clone());
            dhcp_v4_dirty = false;
            results.push(ImportResult {
                section: ImportSection::DhcpV4Pools,
                success: true,
                count: pools.len(),
                error: None,
            });
        }
        if let Some(ref pools) = dhcp_v6_pools {
            self.ctx.update_dhcp_v6_pools(pools.clone());
            dhcp_v6_dirty = false;
            results.push(ImportResult {
                section: ImportSection::DhcpV6Pools,
                success: true,
                count: pools.len(),
                error: None,
            });
        }
        if ra_prefixes.is_some() || ra_rdnss.is_some() || ra_dnssl.is_some() {
            let prefixes = ra_prefixes.clone().unwrap_or_else(|| self.ctx.get_ra_prefixes());
            let rdnss = ra_rdnss.clone().unwrap_or_else(|| self.ctx.get_ra_rdnss());
            let dnssl = ra_dnssl.clone().unwrap_or_else(|| self.ctx.get_ra_dnssl());
            self.ctx.update_ra_config(prefixes.clone(), rdnss.clone(), dnssl.clone());
            ra_dirty = false;

            if let Some(ref p) = ra_prefixes {
                results.push(ImportResult {
                    section: ImportSection::RaPrefixes,
                    success: true,
                    count: p.len(),
                    error: None,
                });
            }
            if let Some(ref r) = ra_rdnss {
                results.push(ImportResult {
                    section: ImportSection::RaRdnss,
                    success: true,
                    count: r.len(),
                    error: None,
                });
            }
            if let Some(ref d) = ra_dnssl {
                results.push(ImportResult {
                    section: ImportSection::RaDnssl,
                    success: true,
                    count: d.len(),
                    error: None,
                });
            }
        }
        if let Some(pppoe_cfg) = pppoe_config {
            self.ctx.update_pppoe_config(*pppoe_cfg);
            results.push(ImportResult {
                section: ImportSection::PppoeConfig,
                success: true,
                count: 1,
                error: None,
            });
        }

        if let Some(opts) = dhcp_options {
            self.ctx.update_dhcp_options(*opts);
            results.push(ImportResult {
                section: ImportSection::DhcpOptions,
                success: true,
                count: 1,
                error: None,
            });
        }

        if let Some(resolvers) = dns_reverse_resolvers {
            let mut res_count = 0;
            let mut res_success = true;
            let mut res_err = None;
            for r in resolvers {
                if let Err(e) = storage
                    .send_query(lanforge_types::storage::StorageQuery::AddReverseResolver {
                        subnet: r.subnet,
                        resolver: r.resolver,
                    })
                    .await
                {
                    res_success = false;
                    res_err = Some(e);
                } else {
                    res_count += 1;
                }
            }
            if !res_success {
                total_success = false;
            }
            results.push(ImportResult {
                section: ImportSection::DnsReverseResolvers,
                success: res_success,
                count: res_count,
                error: res_err,
            });
        }

        if dhcp_v4_dirty {
            self.ctx.update_dhcp_v4_pools(Vec::new());
        }
        if dhcp_v6_dirty {
            self.ctx.update_dhcp_v6_pools(Vec::new());
        }
        if ra_dirty {
            self.ctx.update_ra_config(Vec::new(), Vec::new(), Vec::new());
        }

        Response::SystemConfigImport(SystemConfigImportResponse {
            results,
            total_success,
        })
    }
}
