use crate::ClientContext;
#[cfg(not(feature = "adblock"))]
use lanforge_api::api::Response;
#[cfg(feature = "adblock")]
use lanforge_api::api::{
    DnsAdblockRulesResponse, DnsAdblockStatusResponse, DnsAdblockUrlsResponse, Response,
    SimpleSuccess,
};

#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};

#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockRuleAction;
use lanforge_types::network::dns::adblock::{
    AdblockSourceFormat, AdblockUrlKind, BlockingMode, TimeOfDay,
};
use std::net::{Ipv4Addr, Ipv6Addr};

impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Response {
        if duration_secs.is_none() {
            let mut cfg = self.ctx.get_dns_adblock();
            cfg.enabled = enabled;
            self.ctx.update_dns_adblock(cfg);
        }

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
                enabled,
                duration_secs,
            }));

        Response::Success(SimpleSuccess {
            message: if enabled {
                "DNS Adblock enabled".to_string()
            } else if let Some(d) = duration_secs {
                format!("DNS Adblock disabled for {d} seconds")
            } else {
                "DNS Adblock disabled permanently in database".to_string()
            },
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_set(
        &self,
        _enabled: bool,
        _duration_secs: Option<u64>,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockReload));
        Response::Success(SimpleSuccess {
            message: "Adblock reload triggered".to_string(),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_reload(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_status(&self) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(lanforge_types::network::dns::DnsResponse::AdblockStatus(res)) = handle
                .send_request(lanforge_types::network::dns::DnsRequest::AdblockStatus)
                .await
        {
            return Response::DnsAdblockStatus(Box::new(DnsAdblockStatusResponse {
                enabled: res.enabled,
                disabled_until: res.disabled_until,
                remaining_secs: res.remaining_secs,
                blocklist_size: res.blocklist_size,
                allowlist_size: res.allowlist_size,
                blocking_mode: res.blocking_mode,
                blocking_ip_v4: res.blocking_ip_v4,
                blocking_ip_v6: res.blocking_ip_v6,
                exceptions_size: res.exceptions_size,
                last_update: res.last_update,
                next_update: res.next_update,
                sources_ok: res.sources_ok,
                sources_failing: res.sources_failing,
            }));
        }

        Response::Error {
            error: "DNS service or adblock not available".into(),
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_status(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_sources(&self) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(lanforge_types::network::dns::DnsResponse::AdblockSources(res)) = handle
                .send_request(lanforge_types::network::dns::DnsRequest::AdblockSources)
                .await
        {
            return Response::DnsAdblockSources(res);
        }
        Response::DnsAdblockSources(lanforge_types::network::dns::DnsAdblockSourcesResponse::default())
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_sources(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_check(&self, domain: String) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(lanforge_types::network::dns::DnsResponse::AdblockCheck(res)) = handle
                .send_request(lanforge_types::network::dns::DnsRequest::AdblockCheck {
                    domain: domain.clone(),
                })
                .await
        {
            return Response::AdblockCheck(Box::new(res));
        }
        Response::AdblockCheck(Box::new(lanforge_types::network::dns::AdblockCheckResponse {
            domain,
            matched: false,
            filter: None,
            source_matches: Vec::new(),
        }))
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_check(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_add(
        &self,
        url: String,
        kind: AdblockUrlKind,
        format: Option<AdblockSourceFormat>,
    ) -> Response {
        let mut urls = self.ctx.get_dns_adblock_urls();
        if !urls.iter().any(|u| u.url == url) {
            let next_id = urls.iter().filter_map(|u| u.id).max().unwrap_or(0) + 1;
            urls.push(lanforge_types::network::dns::AdblockUrlEntry {
                id: Some(next_id),
                url: url.clone(),
                kind,
                format: format.unwrap_or_default(),
            });
            self.ctx.update_dns_adblock_urls(urls);
        }
        Response::Success(SimpleSuccess {
            message: format!("Adblock {kind} URL added: {url}"),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_add(
        &self,
        _url: String,
        _kind: AdblockUrlKind,
        _format: Option<AdblockSourceFormat>,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_remove(&self, url: String) -> Response {
        let mut urls = self.ctx.get_dns_adblock_urls();
        let len_before = urls.len();
        urls.retain(|u| u.url != url);
        if urls.len() == len_before {
            return Response::Error {
                error: format!("URL '{url}' not found"),
            };
        }
        self.ctx.update_dns_adblock_urls(urls);
        Response::Success(SimpleSuccess {
            message: format!("Adblock URL removed: {url}"),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_remove(&self, _url: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_list(&self) -> Response {
        let urls = self.ctx.get_dns_adblock_urls();
        Response::DnsAdblockUrls(DnsAdblockUrlsResponse { urls })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_list(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_config_set(
        &self,
        blocking_mode: Option<BlockingMode>,
        blocking_ip_v4: Option<Ipv4Addr>,
        blocking_ip_v6: Option<Ipv6Addr>,
        refresh_time: Option<TimeOfDay>,
    ) -> Response {
        let mut cfg = self.ctx.get_dns_adblock();
        if let Some(mode) = blocking_mode {
            cfg.blocking_mode = mode;
        }
        if let Some(ip) = blocking_ip_v4 {
            cfg.blocking_ip_v4 = Some(ip);
        }
        if let Some(ip) = blocking_ip_v6 {
            cfg.blocking_ip_v6 = Some(ip);
        }
        if let Some(time) = refresh_time {
            cfg.refresh_time = time;
        }
        self.ctx.update_dns_adblock(cfg);

        Response::Success(SimpleSuccess {
            message: "DNS Adblock configuration updated".to_string(),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_config_set(
        &self,
        _blocking_mode: Option<BlockingMode>,
        _blocking_ip_v4: Option<Ipv4Addr>,
        _blocking_ip_v6: Option<Ipv6Addr>,
        _refresh_time: Option<TimeOfDay>,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_rules(&self) -> Response {
        let rules = self.ctx.get_dns_adblock_rules();
        Response::DnsAdblockRules(DnsAdblockRulesResponse { rules })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_rules(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_rule_add(&self, domain: String, action: String) -> Response {
        let rule_action = match action.parse::<AdblockRuleAction>() {
            Ok(a) => a,
            Err(e) => return Response::Error { error: e },
        };
        let mut rules = self.ctx.get_dns_adblock_rules();
        let id = if let Some(existing) = rules.iter_mut().find(|r| r.domain.eq_ignore_ascii_case(&domain)) {
            existing.action = rule_action;
            existing.enabled = true;
            existing.id.unwrap_or(1)
        } else {
            let next_id = rules.iter().filter_map(|r| r.id).max().unwrap_or(0) + 1;
            rules.push(lanforge_types::network::dns::adblock::AdblockRuleEntry {
                id: Some(next_id),
                domain: domain.clone(),
                action: rule_action,
                enabled: true,
            });
            next_id
        };
        self.ctx.update_dns_adblock_rules(rules);
        Response::Success(SimpleSuccess {
            message: format!(
                "Adblock rule added for domain '{domain}' with action '{action}' (id: {id})"
            ),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_rule_add(&self, _domain: String, _action: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_rule_remove(&self, id: i64) -> Response {
        let mut rules = self.ctx.get_dns_adblock_rules();
        let len_before = rules.len();
        rules.retain(|r| r.id != Some(id));
        if rules.len() == len_before {
            return Response::Error {
                error: format!("Adblock rule with ID {id} not found"),
            };
        }
        self.ctx.update_dns_adblock_rules(rules);
        Response::Success(SimpleSuccess {
            message: format!("Adblock rule {id} removed"),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_rule_remove(&self, _id: i64) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_rule_status(&self, id: i64, enabled: bool) -> Response {
        let mut rules = self.ctx.get_dns_adblock_rules();
        if let Some(rule) = rules.iter_mut().find(|r| r.id == Some(id)) {
            rule.enabled = enabled;
            self.ctx.update_dns_adblock_rules(rules);
            Response::Success(SimpleSuccess {
                message: format!("Adblock rule {id} status updated to enabled={enabled}"),
            })
        } else {
            Response::Error {
                error: format!("Adblock rule with ID {id} not found"),
            }
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_rule_status(&self, _id: i64, _enabled: bool) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }
}
