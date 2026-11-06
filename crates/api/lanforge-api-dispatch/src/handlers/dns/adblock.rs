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
use crate::handlers::dns::rewrite::dns_reply;
use crate::handlers::system::config_write::ChangeError;
#[cfg(feature = "adblock")]
use crate::handlers::system::config_write::Persisted;
use lanforge_types::network::dns::adblock::rules_file::RulesFile;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::rules_file::RulesImport;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::{AdblockRuleAction, AdblockRuleEntry};
use lanforge_types::network::dns::adblock::{
    AdblockSourceFormat, AdblockUrlKind, BlockingMode, TimeOfDay,
};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::{
    AdblockCheckResponse, AdblockUrlEntry, DnsAdblockSourcesResponse, DnsRequest, DnsResponse,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// The rules text with `line` active and its opposite (the same rule with `@@` added or
/// removed) gone: a domain is blocked or allowed, not both. `None` when nothing changes.
pub(crate) fn with_rule_only(text: &str, line: &str) -> Result<Option<String>, ChangeError> {
    let opposite = line
        .strip_prefix("@@")
        .map_or_else(|| format!("@@{line}"), str::to_string);
    let without = RulesFile::new(text).without_rule(RulesFile::rule_id(&opposite));
    match RulesFile::new(without.as_deref().unwrap_or(text)).with_rule(line) {
        Ok(Some(new)) => Ok(Some(new)),
        Ok(None) => Ok(without),
        Err(issue) => Err(ChangeError::Rejected(format!("\"{line}\": {issue}"))),
    }
}

impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Response {
        // A timed pause lives in memory only (the event); an enable or a permanent disable is
        // `[adblock] enabled`.
        let persisted = if duration_secs.is_none() {
            match self.change_adblock(|a| a.config.enabled = enabled) {
                Ok(p) => Some(p),
                Err(e) => return e.into(),
            }
        } else {
            None
        };

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
                enabled,
                duration_secs,
            }));

        let what = if enabled {
            "DNS Adblock enabled".to_string()
        } else if let Some(d) = duration_secs {
            format!("DNS Adblock disabled for {d} seconds")
        } else {
            "DNS Adblock disabled".to_string()
        };
        match persisted {
            Some(p) => dns_reply(Ok(p), what),
            None => Response::Success(SimpleSuccess { message: what }),
        }
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
            && let Ok(DnsResponse::AdblockStatus(res)) =
                handle.send_request(DnsRequest::AdblockStatus).await
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
                refresh_time: res.refresh_time,
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
            && let Ok(DnsResponse::AdblockSources(res)) =
                handle.send_request(DnsRequest::AdblockSources).await
        {
            return Response::DnsAdblockSources(res);
        }
        Response::DnsAdblockSources(DnsAdblockSourcesResponse::default())
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
            && let Ok(DnsResponse::AdblockCheck(res)) = handle
                .send_request(DnsRequest::AdblockCheck {
                    domain: domain.clone(),
                })
                .await
        {
            return Response::AdblockCheck(Box::new(res));
        }
        Response::AdblockCheck(Box::new(AdblockCheckResponse {
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
        name: Option<String>,
        url: String,
        kind: AdblockUrlKind,
        format: Option<AdblockSourceFormat>,
    ) -> Response {
        let what = format!("Adblock {kind} URL added: {url}");
        dns_reply(
            self.change_adblock(|a| {
                let name = match a.sources.iter().find(|s| s.url == url) {
                    Some(known) => known.name.clone().unwrap_or_default(),
                    None => {
                        let name = lanforge_crypto::stable_id_or_hash(
                            name.as_deref(),
                            url.as_bytes(),
                            "src",
                        );
                        a.sources.push(AdblockUrlEntry {
                            id: None,
                            name: Some(name.clone()),
                            url: url.clone(),
                            kind,
                            format: format.unwrap_or_default(),
                        });
                        name
                    }
                };
                if !a.lists.contains(&name) {
                    a.lists.push(name);
                }
            }),
            what,
        )
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_add(
        &self,
        _name: Option<String>,
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
        if !self.ctx.get_dns_adblock_urls().iter().any(|u| u.url == url) {
            return Response::Error {
                error: format!("URL '{url}' not found"),
            };
        }
        dns_reply(
            self.change_adblock(|a| {
                let names: Vec<String> = a
                    .sources
                    .iter()
                    .filter(|s| s.url == url)
                    .filter_map(|s| s.name.clone())
                    .collect();
                a.sources.retain(|s| s.url != url);
                a.lists.retain(|n| !names.contains(n));
                for group in &mut a.groups {
                    group.lists.retain(|n| !names.contains(n));
                }
            }),
            format!("Adblock URL removed: {url}"),
        )
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
        dns_reply(
            self.change_adblock(|a| {
                let cfg = &mut a.config;
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
            }),
            "DNS Adblock configuration updated".to_string(),
        )
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
        let rules = self
            .ctx
            .with_config(|c| RulesFile::new(&c.dns_adblock_rules.0).rule_entries());
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
        match action.parse::<AdblockRuleAction>() {
            Ok(action) => self.add_adblock_rule(&domain, action),
            Err(error) => Response::Rejected { error },
        }
    }

    /// Blocks or allows `domain` (a bare name or a rule as written) in the rules file, replacing
    /// its opposite rule. The one write path of the block/allow/rule-add calls; a block announces
    /// `AdblockBlock` to watchers.
    #[cfg(feature = "adblock")]
    pub(crate) fn add_adblock_rule(&self, domain: &str, action: AdblockRuleAction) -> Response {
        let line = AdblockRuleEntry::rule_line(domain, action);
        let reply = dns_reply(
            self.change_adblock_rules(|text| with_rule_only(text, &line)),
            format!("Adblock rule added: {line}"),
        );
        if matches!(reply, Response::Success(_)) && !action.is_allow() {
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Dns(DnsEvent::AdblockBlock(
                    domain.to_string(),
                )));
        }
        reply
    }

    /// Adds every rule of a pasted list (`action` for bare names) in one rules-file write and one
    /// engine reload; rejected lines are reported, never fatal.
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_rules_import(&self, text: String, action: String) -> Response {
        let action = match action.parse::<AdblockRuleAction>() {
            Ok(a) => a,
            Err(error) => return Response::Rejected { error },
        };
        let mut report = RulesImport::default();
        let persisted = self.change_adblock_rules(|live| {
            let (new, outcome) = RulesFile::new(live).with_rules_imported(&text, action);
            report = outcome;
            Ok(new)
        });
        match persisted {
            Ok(persisted) => {
                report.saved = matches!(persisted, Persisted::File);
                Response::DnsAdblockRulesImport(Box::new(report))
            }
            Err(e) => e.into(),
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_rules_import(
        &self,
        _text: String,
        _action: String,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
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
        dns_reply(
            self.change_adblock_rules(|text| {
                RulesFile::new(text)
                    .without_rule(id)
                    .map(Some)
                    .ok_or_else(|| {
                        ChangeError::NotFound(format!("Adblock rule with ID {id} not found"))
                    })
            }),
            format!("Adblock rule {id} removed"),
        )
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
        dns_reply(
            self.change_adblock_rules(|text| {
                let file = RulesFile::new(text);
                if !file.rule_entries().iter().any(|r| r.id == Some(id)) {
                    return Err(ChangeError::NotFound(format!(
                        "Adblock rule with ID {id} not found"
                    )));
                }
                Ok(file.with_rule_enabled(id, enabled))
            }),
            format!("Adblock rule {id} status updated to enabled={enabled}"),
        )
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_rule_status(&self, _id: i64, _enabled: bool) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }
}
