use crate::ClientContext;
use lanforge_api::api::{
    DnsUpstreamConfig, ImportResult, ImportSection, Response, SystemConfigExport,
    SystemConfigImportResponse,
};
use lanforge_api::config_file::NamedUpstream;
use lanforge_db_core::Stores;
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::rules_file::RulesFile;
use lanforge_types::network::dns::adblock::{AdblockRuleAction, AdblockRuleEntry};
use lanforge_types::network::dns::upstream::UpstreamTarget;

use crate::handlers::dns::adblock::with_rule_only;
use crate::handlers::dns::rewrite::upsert_rewrite;
use crate::handlers::system::config_write::ChangeError;

/// The import result of a section that `outcome` wrote (`count` entries) or refused.
fn import_result(
    section: ImportSection,
    count: usize,
    outcome: &Result<(), ChangeError>,
) -> ImportResult {
    match outcome {
        Ok(()) => ImportResult {
            section,
            success: true,
            count,
            error: None,
        },
        Err(e) => ImportResult {
            section,
            success: false,
            count: 0,
            error: Some(e.to_string()),
        },
    }
}

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

        // 3. DNS Upstreams, under their `[dns.upstreams]` group names
        let dns_upstreams = self
            .live_dns_settings()
            .upstreams
            .into_iter()
            .map(|up| DnsUpstreamConfig {
                name: Some(up.name),
                addr: up.target.addr,
                protocol: up.target.protocol,
                domain: up.target.domain,
            })
            .collect();

        // 4. Adblock Config
        let dns_adblock_config = self.ctx.get_dns_adblock();

        // 5. Adblock URLs
        let dns_adblock_urls = self.ctx.get_dns_adblock_urls();

        // 6. Manual adblock rules, the allowlist among them (`@@||x^`): the rules file's rules,
        // each as written.
        let dns_allowlist = Vec::new();
        let dns_adblock_rules = Some(
            self.ctx
                .with_config(|c| RulesFile::new(&c.dns_adblock_rules.0).rule_entries()),
        );

        // 7. API Tokens
        let api_tokens = if let Some(storage) = self.ctx.storage_handle() {
            match storage.call(|s: &Stores| s.auth().load_api_tokens()).await {
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
        let firewall_config = self.ctx.get_firewall_config().map(Box::new);
        let traffic_config = self.ctx.get_traffic_config().map(Box::new);
        let system_iface = self.ctx.target_interface_name();

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
            firewall_config,
            traffic_config,
            system_iface,
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
            firewall_config,
            traffic_config,
            system_iface,
            overwrite,
        } = config;

        if let Some(iface) = system_iface
            && !iface.is_empty()
        {
            self.ctx.set_target_interface_name(iface);
        }

        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let mut total_success = true;
        let mut results = Vec::new();

        if overwrite {
            // Clear API Tokens
            if let Ok(existing_tokens) = storage.call(|s: &Stores| s.auth().load_api_tokens()).await
            {
                for token in existing_tokens {
                    let tok = token.token;
                    let _ = storage
                        .call(move |s: &Stores| s.auth().delete_api_token(&tok))
                        .await;
                }
            }
        }

        // 1. Import hosts. File-owned: imported only if they reach `[hosts]`; overwrite makes
        // the static hosts not imported discovered devices again (their history stays).
        if overwrite || !hosts.is_empty() {
            let outcome = self.import_hosts(hosts, overwrite);
            if outcome.is_err() {
                total_success = false;
            }
            results.push(match outcome {
                Ok(count) => ImportResult {
                    section: ImportSection::Hosts,
                    success: true,
                    count,
                    error: None,
                },
                Err(e) => ImportResult {
                    section: ImportSection::Hosts,
                    success: false,
                    count: 0,
                    error: Some(e.to_string()),
                },
            });
        }

        // 2. DNS rewrites, upstreams and reverse resolvers. File-owned: imported only if they
        // reach `[dns]`, in one write; overwrite replaces the lists.
        let mut dns_sections = vec![
            (ImportSection::DnsRewrites, dns_rewrites.len()),
            (ImportSection::DnsUpstreams, dns_upstreams.len()),
        ];
        if let Some(ref resolvers) = dns_reverse_resolvers {
            dns_sections.push((ImportSection::DnsReverseResolvers, resolvers.len()));
        }
        let dns_outcome = if overwrite
            || !dns_rewrites.is_empty()
            || !dns_upstreams.is_empty()
            || dns_reverse_resolvers.is_some()
        {
            self.change_dns(|dns| {
                if overwrite {
                    dns.rewrites.clear();
                    dns.upstreams.clear();
                    dns.reverse.clear();
                }
                for rule in dns_rewrites {
                    upsert_rewrite(&mut dns.rewrites, rule);
                }
                for up in dns_upstreams {
                    let known = dns.upstreams.iter().any(|u| {
                        u.target.addr == up.addr
                            && u.target.protocol == up.protocol
                            && u.target.domain == up.domain
                    });
                    if !known {
                        dns.upstreams.push(NamedUpstream {
                            name: up
                                .name
                                .or_else(|| up.domain.clone())
                                .unwrap_or_else(|| "default".to_string()),
                            target: UpstreamTarget {
                                addr: up.addr,
                                protocol: up.protocol,
                                hostname: None,
                                domain: up.domain,
                            },
                        });
                    }
                }
                for r in dns_reverse_resolvers.unwrap_or_default() {
                    dns.reverse.retain(|known| known.subnet != r.subnet);
                    dns.reverse.push(r);
                }
            })
            .map(|_| ())
        } else {
            Ok(())
        };
        if dns_outcome.is_err() {
            total_success = false;
        }
        for (section, count) in dns_sections {
            results.push(match &dns_outcome {
                Ok(()) => ImportResult {
                    section,
                    success: true,
                    count,
                    error: None,
                },
                Err(e) => ImportResult {
                    section,
                    success: false,
                    count: 0,
                    error: Some(e.to_string()),
                },
            });
        }

        // 4-6. Adblock settings and sources, then the manual rules (allowlist included). File-owned:
        // imported only if they reach `[adblock]` / the rules file; overwrite replaces them.
        let url_count = dns_adblock_urls.len();
        let adblock_outcome = if overwrite
            || !dns_adblock_urls.is_empty()
            || dns_adblock_config != self.ctx.get_dns_adblock()
        {
            self.change_adblock(|a| {
                if overwrite {
                    a.sources.clear();
                    a.lists.clear();
                    for group in &mut a.groups {
                        group.lists.clear();
                    }
                }
                a.config = dns_adblock_config;
                for u in dns_adblock_urls {
                    let name = match a.sources.iter().find(|s| s.url == u.url) {
                        Some(known) => known.name.clone().unwrap_or_default(),
                        None => {
                            let name = lanforge_crypto::stable_id_or_hash(
                                u.name.as_deref(),
                                u.url.as_bytes(),
                                "src",
                            );
                            a.sources.push(AdblockUrlEntry {
                                id: None,
                                name: Some(name.clone()),
                                ..u
                            });
                            name
                        }
                    };
                    if !a.lists.contains(&name) {
                        a.lists.push(name);
                    }
                }
            })
            .map(|_| ())
        } else {
            Ok(())
        };
        for (section, count) in [
            (ImportSection::DnsAdblockConfig, 1),
            (ImportSection::DnsAdblockUrls, url_count),
        ] {
            results.push(import_result(section, count, &adblock_outcome));
        }

        let rules = dns_adblock_rules.unwrap_or_default();
        let (allow_count, rules_count) = (dns_allowlist.len(), rules.len());
        let rules_outcome = if overwrite || allow_count > 0 || rules_count > 0 {
            self.change_adblock_rules(|live| {
                let mut text = if overwrite {
                    String::new()
                } else {
                    live.to_string()
                };
                let lines =
                    dns_allowlist
                        .iter()
                        .map(|a| {
                            (
                                AdblockRuleEntry::rule_line(&a.domain, AdblockRuleAction::Allow),
                                true,
                            )
                        })
                        .chain(rules.iter().map(|r| {
                            (AdblockRuleEntry::rule_line(&r.domain, r.action), r.enabled)
                        }));
                for (line, enabled) in lines {
                    if let Some(new) = with_rule_only(&text, &line)? {
                        text = new;
                    }
                    if !enabled
                        && let Some(new) = RulesFile::new(&text)
                            .with_rule_enabled(RulesFile::rule_id(&line), false)
                    {
                        text = new;
                    }
                }
                Ok((text != live).then_some(text))
            })
            .map(|_| ())
        } else {
            Ok(())
        };
        for (section, count) in [
            (ImportSection::DnsAllowlist, allow_count),
            (ImportSection::DnsAdblockRules, rules_count),
        ] {
            results.push(import_result(section, count, &rules_outcome));
        }
        if adblock_outcome.is_err() || rules_outcome.is_err() {
            total_success = false;
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
                let tok = t.token.clone();
                let nm = t.name.clone();
                let sc = t.scopes.clone();
                if let Err(e) = storage
                    .call(move |s: &Stores| -> Result<(), lanforge_db_core::DbError> {
                        s.auth()
                            .store_api_token(&tok, &nm, &sc, t.expires_at, now)
                            .map(|_| ())
                    })
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
        let mut patch = lanforge_core::context::ConfigPatch::new();

        // File-owned: imported only if it reaches the config file. Overwrite clears the lists
        // the import does not carry.
        let ra_prefixes = ra_prefixes.or_else(|| overwrite.then(Vec::new));
        let ra_rdnss = ra_rdnss.or_else(|| overwrite.then(Vec::new));
        let ra_dnssl = ra_dnssl.or_else(|| overwrite.then(Vec::new));
        if ra_prefixes.is_some() || ra_rdnss.is_some() || ra_dnssl.is_some() {
            let sections = [
                (
                    ImportSection::RaPrefixes,
                    ra_prefixes.as_ref().map(Vec::len),
                ),
                (ImportSection::RaRdnss, ra_rdnss.as_ref().map(Vec::len)),
                (ImportSection::RaDnssl, ra_dnssl.as_ref().map(Vec::len)),
            ];
            let outcome = self.change_ra(|ra| {
                if let Some(prefixes) = ra_prefixes {
                    ra.prefixes = prefixes;
                }
                if let Some(rdnss) = ra_rdnss {
                    ra.rdnss = rdnss;
                }
                if let Some(dnssl) = ra_dnssl {
                    ra.dnssl = dnssl;
                }
            });
            for (section, count) in sections {
                let Some(count) = count else { continue };
                results.push(match &outcome {
                    Ok(_) => ImportResult {
                        section,
                        success: true,
                        count,
                        error: None,
                    },
                    Err(e) => ImportResult {
                        section,
                        success: false,
                        count: 0,
                        error: Some(e.to_string()),
                    },
                });
            }
        }
        if let Some(pppoe_cfg) = pppoe_config {
            // File-owned: imported only if it reaches the config file.
            match self
                .persist_config_sections(lanforge_api::config_file::SectionSet::PPPOE, |file| {
                    file.pppoe = (*pppoe_cfg).clone()
                }) {
                Ok(_) => {
                    patch = patch.with_pppoe(*pppoe_cfg);
                    results.push(ImportResult {
                        section: ImportSection::PppoeConfig,
                        success: true,
                        count: 1,
                        error: None,
                    });
                }
                Err(e) => results.push(ImportResult {
                    section: ImportSection::PppoeConfig,
                    success: false,
                    count: 0,
                    error: Some(e.to_string()),
                }),
            }
        }

        // File-owned: imported only if it reaches the config file. Overwrite clears the pools
        // the import does not carry.
        let dhcp_v4_pools = dhcp_v4_pools.or_else(|| overwrite.then(Vec::new));
        let dhcp_v6_pools = dhcp_v6_pools.or_else(|| overwrite.then(Vec::new));
        if dhcp_options.is_some() || dhcp_v4_pools.is_some() || dhcp_v6_pools.is_some() {
            let sections = [
                (ImportSection::DhcpOptions, dhcp_options.as_ref().map(|_| 1)),
                (
                    ImportSection::DhcpV4Pools,
                    dhcp_v4_pools.as_ref().map(Vec::len),
                ),
                (
                    ImportSection::DhcpV6Pools,
                    dhcp_v6_pools.as_ref().map(Vec::len),
                ),
            ];
            let outcome = self.change_dhcp(|dhcp| {
                if let Some(opts) = dhcp_options {
                    dhcp.options = *opts;
                }
                if let Some(pools) = dhcp_v4_pools {
                    dhcp.v4_pools = pools;
                }
                if let Some(pools) = dhcp_v6_pools {
                    dhcp.v6_pools = pools;
                }
            });
            for (section, count) in sections {
                let Some(count) = count else { continue };
                results.push(match &outcome {
                    Ok(_) => ImportResult {
                        section,
                        success: true,
                        count,
                        error: None,
                    },
                    Err(e) => ImportResult {
                        section,
                        success: false,
                        count: 0,
                        error: Some(e.to_string()),
                    },
                });
            }
        }

        if let Some(fw) = firewall_config {
            // File-owned: imported only if it reaches the config file.
            if let Err(e) = self.persist_firewall(&fw) {
                results.push(ImportResult {
                    section: ImportSection::FirewallConfig,
                    success: false,
                    count: 0,
                    error: Some(e.to_string()),
                });
                total_success = false;
            } else {
                patch = patch.with_firewall(*fw);
                results.push(ImportResult {
                    section: ImportSection::FirewallConfig,
                    success: true,
                    count: 1,
                    error: None,
                });
            }
        }

        if let Some(tr) = traffic_config {
            // File-owned: imported only if it reaches the config file.
            match self
                .persist_config_sections(lanforge_api::config_file::SectionSet::TRAFFIC, |file| {
                    file.traffic = (*tr).clone()
                }) {
                Ok(_) => {
                    patch = patch.with_traffic(*tr);
                    results.push(ImportResult {
                        section: ImportSection::TrafficConfig,
                        success: true,
                        count: 1,
                        error: None,
                    });
                }
                Err(e) => results.push(ImportResult {
                    section: ImportSection::TrafficConfig,
                    success: false,
                    count: 0,
                    error: Some(e.to_string()),
                }),
            }
        }

        let _ = self.ctx.apply_config(patch);

        // Flush live config and snapshot to disk immediately before replying
        let _ = self.flush_now().await;

        Response::SystemConfigImport(SystemConfigImportResponse {
            results,
            total_success,
        })
    }
}
