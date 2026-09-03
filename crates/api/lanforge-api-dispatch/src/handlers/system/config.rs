use crate::ClientContext;
use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, ImportResult, ImportSection, Response, SystemConfigExport,
    SystemConfigImportResponse,
};
use lanforge_types::network::dns::AdblockUrlEntry;
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
        let dns_upstreams = match self.db.load_dns_upstreams().await {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|row| {
                    let addr = row.addr.parse().ok()?;
                    let protocol = row.protocol.parse().ok()?;
                    Some(DnsUpstreamConfig {
                        addr,
                        protocol,
                        domain: row.domain,
                    })
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // 4. Adblock Config
        let dns_adblock_config = self.db.load_adblock_config().await.unwrap_or_default();

        // 5. Adblock URLs
        let dns_adblock_urls = match self.db.load_adblock_urls().await {
            Ok(rows) => rows
                .into_iter()
                .map(|(id, url, kind)| AdblockUrlEntry {
                    id: Some(id),
                    url,
                    kind,
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // 6. DNS Allowlist
        let dns_allowlist = match self.db.load_dns_allowlist().await {
            Ok(rows) => rows
                .into_iter()
                .map(|(id, domain)| AllowlistEntry { id, domain })
                .collect(),
            Err(_) => Vec::new(),
        };

        // 7. API Tokens
        let api_tokens = match self.db.load_api_tokens().await {
            Ok(tokens) => Some(
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
            Err(_) => None,
        };

        // 8. Dynamic Configs (pools, prefixes, pppoe, options, reverse resolvers)
        let dhcp_v4_pools = self.db.load_dhcp_v4_pools().await.ok();
        let dhcp_v6_pools = self.db.load_dhcp_v6_pools().await.ok();
        let ra_prefixes = self.db.load_ra_prefixes().await.ok();
        let ra_rdnss = self.db.load_ra_rdnss().await.ok();
        let ra_dnssl = self.db.load_ra_dnssl().await.ok();
        let pppoe_config = self.db.load_pppoe_config().await.ok().flatten();
        let dhcp_options = self.db.load_dhcp_options().await.ok().flatten();
        let dns_reverse_resolvers = self.db.load_dns_reverse_resolvers().await.ok();

        Response::SystemConfig(Box::new(SystemConfigExport {
            hosts,
            dns_rewrites,
            dns_upstreams,
            dns_adblock_config,
            dns_adblock_urls,
            dns_allowlist,
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
            if let Err(e) = self.db.clear_dns_rewrites().await {
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
            if let Err(e) = self.db.clear_dns_upstreams().await {
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
            if let Err(e) = self.db.clear_adblock_urls().await {
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
            if let Err(e) = self.db.clear_dns_allowlist().await {
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

            // Clear API Tokens
            if let Ok(existing_tokens) = self.db.load_api_tokens().await {
                for token in existing_tokens {
                    let _ = self.db.delete_api_token(&token.token).await;
                }
            }

            // Clear Dynamic Configs by overwriting with empty lists
            let _ = self.db.save_dhcp_v4_pools(&[]).await;
            let _ = self.db.save_dhcp_v6_pools(&[]).await;
            let _ = self.db.save_ra_prefixes(&[]).await;
            let _ = self.db.save_ra_rdnss(&[]).await;
            let _ = self.db.save_ra_dnssl(&[]).await;
            let _ = self.db.clear_dns_reverse_resolvers().await;
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
            refresh_hours,
            refresh_at_night,
        } = dns_adblock_config;

        let mut adblock_cfg_success = true;
        let mut adblock_cfg_err = None;
        if let Err(e) = self
            .db
            .set_adblock_config_value("enabled", if enabled { "true" } else { "false" })
            .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set enabled: {e}"));
        }
        if adblock_cfg_success
            && let Err(e) = self
                .db
                .set_adblock_config_value("blocking_mode", &blocking_mode.to_string())
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set blocking_mode: {e}"));
        }
        if adblock_cfg_success
            && let Some(ip) = blocking_ip_v4
            && let Err(e) = self
                .db
                .set_adblock_config_value("blocking_ip_v4", &ip.to_string())
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set blocking_ip_v4: {e}"));
        }
        if adblock_cfg_success
            && let Some(ip) = blocking_ip_v6
            && let Err(e) = self
                .db
                .set_adblock_config_value("blocking_ip_v6", &ip.to_string())
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set blocking_ip_v6: {e}"));
        }
        if adblock_cfg_success
            && let Err(e) = self
                .db
                .set_adblock_config_value("refresh_hours", &refresh_hours.to_string())
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set refresh_hours: {e}"));
        }
        if adblock_cfg_success
            && let Err(e) = self
                .db
                .set_adblock_config_value(
                    "refresh_at_night",
                    if refresh_at_night { "true" } else { "false" },
                )
                .await
        {
            adblock_cfg_success = false;
            adblock_cfg_err = Some(format!("Failed to set refresh_at_night: {e}"));
        }
        if adblock_cfg_success {
            if let Ok(cfg) = self.db.load_adblock_config().await {
                self.ctx.update_dns_adblock(cfg);
            }
        } else {
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
            match self.handle_dns_adblock_url_add(u.url, u.kind).await {
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
                let scopes: lanforge_types::auth::ApiScopes =
                    t.scopes.split(',').filter_map(|s| s.parse().ok()).collect();
                if let Err(e) = self
                    .db
                    .store_api_token(&t.token, &t.name, &scopes, t.expires_at, now)
                    .await
                {
                    tokens_success = false;
                    tokens_err = Some(e.to_string());
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
        if let Some(pools) = dhcp_v4_pools {
            let mut pools_success = true;
            let mut pools_err = None;
            let count = pools.len();
            if let Err(e) = self.db.save_dhcp_v4_pools(&pools).await {
                pools_success = false;
                total_success = false;
                pools_err = Some(e.to_string());
            } else {
                dhcp_v4_dirty = true;
            }
            results.push(ImportResult {
                section: ImportSection::DhcpV4Pools,
                success: pools_success,
                count: if pools_success { count } else { 0 },
                error: pools_err,
            });
        }
        if let Some(pools) = dhcp_v6_pools {
            let mut pools_success = true;
            let mut pools_err = None;
            let count = pools.len();
            if let Err(e) = self.db.save_dhcp_v6_pools(&pools).await {
                pools_success = false;
                total_success = false;
                pools_err = Some(e.to_string());
            } else {
                dhcp_v6_dirty = true;
            }
            results.push(ImportResult {
                section: ImportSection::DhcpV6Pools,
                success: pools_success,
                count: if pools_success { count } else { 0 },
                error: pools_err,
            });
        }
        if let Some(prefixes) = ra_prefixes {
            let mut ra_pref_success = true;
            let mut ra_pref_err = None;
            let count = prefixes.len();
            if let Err(e) = self.db.save_ra_prefixes(&prefixes).await {
                ra_pref_success = false;
                total_success = false;
                ra_pref_err = Some(e.to_string());
            } else {
                ra_dirty = true;
            }
            results.push(ImportResult {
                section: ImportSection::RaPrefixes,
                success: ra_pref_success,
                count: if ra_pref_success { count } else { 0 },
                error: ra_pref_err,
            });
        }
        if let Some(rdnss) = ra_rdnss {
            let mut rdnss_success = true;
            let mut rdnss_err = None;
            let count = rdnss.len();
            if let Err(e) = self.db.save_ra_rdnss(&rdnss).await {
                rdnss_success = false;
                total_success = false;
                rdnss_err = Some(e.to_string());
            } else {
                ra_dirty = true;
            }
            results.push(ImportResult {
                section: ImportSection::RaRdnss,
                success: rdnss_success,
                count: if rdnss_success { count } else { 0 },
                error: rdnss_err,
            });
        }
        if let Some(dnssl) = ra_dnssl {
            let mut dnssl_success = true;
            let mut dnssl_err = None;
            let count = dnssl.len();
            if let Err(e) = self.db.save_ra_dnssl(&dnssl).await {
                dnssl_success = false;
                total_success = false;
                dnssl_err = Some(e.to_string());
            } else {
                ra_dirty = true;
            }
            results.push(ImportResult {
                section: ImportSection::RaDnssl,
                success: dnssl_success,
                count: if dnssl_success { count } else { 0 },
                error: dnssl_err,
            });
        }
        if let Some(pppoe_cfg) = pppoe_config {
            let mut pppoe_success = true;
            let mut pppoe_err = None;
            if let Err(e) = self.db.save_pppoe_config(&pppoe_cfg).await {
                pppoe_success = false;
                total_success = false;
                pppoe_err = Some(e.to_string());
            }
            results.push(ImportResult {
                section: ImportSection::PppoeConfig,
                success: pppoe_success,
                count: if pppoe_success { 1 } else { 0 },
                error: pppoe_err,
            });
        }

        if let Some(opts) = dhcp_options {
            let mut opts_success = true;
            let mut opts_err = None;
            if let Err(e) = self.db.save_dhcp_options(&opts).await {
                opts_success = false;
                total_success = false;
                opts_err = Some(e.to_string());
            } else {
                self.ctx.update_dhcp_options(opts);
            }
            results.push(ImportResult {
                section: ImportSection::DhcpOptions,
                success: opts_success,
                count: if opts_success { 1 } else { 0 },
                error: opts_err,
            });
        }

        if let Some(resolvers) = dns_reverse_resolvers {
            let mut res_count = 0;
            let mut res_success = true;
            let mut res_err = None;
            for r in resolvers {
                if let Err(e) = self
                    .db
                    .add_dns_reverse_resolver(&r.subnet, &r.resolver)
                    .await
                {
                    res_success = false;
                    res_err = Some(e.to_string());
                } else {
                    let _ =
                        self.ctx
                            .apply(lanforge_types::update::DeviceUpdate::AddReverseResolver {
                                resolver: r,
                            });
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

        if dhcp_v4_dirty && let Ok(pools) = self.db.load_dhcp_v4_pools().await {
            self.ctx.update_dhcp_v4_pools(pools);
        }
        if dhcp_v6_dirty && let Ok(pools) = self.db.load_dhcp_v6_pools().await {
            self.ctx.update_dhcp_v6_pools(pools);
        }
        if ra_dirty
            && let (Ok(prefixes), Ok(rdnss), Ok(dnssl)) = (
                self.db.load_ra_prefixes().await,
                self.db.load_ra_rdnss().await,
                self.db.load_ra_dnssl().await,
            )
        {
            self.ctx.update_ra_config(prefixes, rdnss, dnssl);
        }

        if self.db.is_in_memory() {
            let _ = self.flush_static_config_to_toml().await;
        }

        Response::SystemConfigImport(SystemConfigImportResponse {
            results,
            total_success,
        })
    }
}
