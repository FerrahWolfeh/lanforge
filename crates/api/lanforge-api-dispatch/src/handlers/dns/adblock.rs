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
use tracing::error;

#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockRuleAction;
use lanforge_types::network::dns::adblock::{
    AdblockSourceFormat, AdblockUrlKind, BlockingMode, TimeOfDay,
};
#[cfg(feature = "adblock")]
use lanforge_db_core::Stores;
use std::net::{Ipv4Addr, Ipv6Addr};

impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Response {
        if duration_secs.is_none() {
            // Persistent change
            let val = if enabled { "true" } else { "false" };
            if let Some(storage) = self.ctx.storage_handle()
                && let Err(e) = storage
                    .call(move |s: &Stores| s.db().set_adblock_config_value("enabled", val))
                    .await
            {
                error!("❌ API: Failed to persist adblock enabled status: {e}");
            }
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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let u_clone = url.clone();
        let fmt = format.unwrap_or_default();
        match storage
            .call(move |s: &Stores| s.db().add_adblock_url(&u_clone, kind, fmt))
            .await
        {
            Ok(_) => {
                if let Ok(urls) = storage.call(|s: &Stores| s.db().load_adblock_urls()).await {
                    self.ctx.update_dns_adblock_urls(
                        urls.into_iter()
                            .map(|(id, url, kind, format)| {
                                lanforge_types::network::dns::AdblockUrlEntry {
                                    id: Some(id),
                                    url,
                                    kind,
                                    format,
                                }
                            })
                            .collect(),
                    );
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock {kind} URL added: {url}"),
                })
            }
            Err(e) => Response::Error { error: e.to_string() },
        }
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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let u_clone = url.clone();
        match storage
            .call(move |s: &Stores| s.db().remove_adblock_url(&u_clone))
            .await
        {
            Ok(()) => {
                if let Ok(urls) = storage.call(|s: &Stores| s.db().load_adblock_urls()).await {
                    self.ctx.update_dns_adblock_urls(
                        urls.into_iter()
                            .map(|(id, url, kind, format)| {
                                lanforge_types::network::dns::AdblockUrlEntry {
                                    id: Some(id),
                                    url,
                                    kind,
                                    format,
                                }
                            })
                            .collect(),
                    );
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock URL removed: {url}"),
                })
            }
            Err(e) => Response::Error { error: e.to_string() },
        }
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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        if let Some(mode) = blocking_mode
            && let Err(e) = storage
                .call(move |s: &Stores| {
                    s.db().set_adblock_config_value("blocking_mode", &mode.to_string())
                })
                .await
        {
            return Response::Error {
                error: format!("Failed to update blocking_mode: {e}"),
            };
        }
        if let Some(ip) = blocking_ip_v4
            && let Err(e) = storage
                .call(move |s: &Stores| {
                    s.db().set_adblock_config_value("blocking_ip_v4", &ip.to_string())
                })
                .await
        {
            return Response::Error {
                error: format!("Failed to update blocking_ip_v4: {e}"),
            };
        }
        if let Some(ip) = blocking_ip_v6
            && let Err(e) = storage
                .call(move |s: &Stores| {
                    s.db().set_adblock_config_value("blocking_ip_v6", &ip.to_string())
                })
                .await
        {
            return Response::Error {
                error: format!("Failed to update blocking_ip_v6: {e}"),
            };
        }
        if let Some(time) = refresh_time
            && let Err(e) = storage
                .call(move |s: &Stores| {
                    s.db().set_adblock_config_value("refresh_time", &time.to_string())
                })
                .await
        {
            return Response::Error {
                error: format!("Failed to update refresh_time: {e}"),
            };
        }
        if let Ok(cfg) = storage.call(|s: &Stores| s.db().load_adblock_config()).await {
            self.ctx.update_dns_adblock(cfg);
        }

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));

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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let d_clone = domain.clone();
        match storage
            .call(move |s: &Stores| s.db().add_adblock_rule(&d_clone, rule_action))
            .await
        {
            Ok(id) => {
                if let Ok(rules) = storage.call(|s: &Stores| s.db().load_adblock_rules()).await {
                    self.ctx.update_dns_adblock_rules(
                        rules
                            .into_iter()
                            .map(|(id, domain, action, enabled)| {
                                lanforge_types::network::dns::adblock::AdblockRuleEntry {
                                    id: Some(id),
                                    domain,
                                    action,
                                    enabled,
                                }
                            })
                            .collect(),
                    );
                }
                Response::Success(SimpleSuccess {
                    message: format!(
                        "Adblock rule added for domain '{domain}' with action '{action}' (id: {id})"
                    ),
                })
            }
            Err(e) => Response::Error { error: e.to_string() },
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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .call(move |s: &Stores| s.db().remove_adblock_rule(id))
            .await
        {
            Ok(()) => {
                if let Ok(rules) = storage.call(|s: &Stores| s.db().load_adblock_rules()).await {
                    self.ctx.update_dns_adblock_rules(
                        rules
                            .into_iter()
                            .map(|(id, domain, action, enabled)| {
                                lanforge_types::network::dns::adblock::AdblockRuleEntry {
                                    id: Some(id),
                                    domain,
                                    action,
                                    enabled,
                                }
                            })
                            .collect(),
                    );
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock rule {id} removed"),
                })
            }
            Err(e) => Response::Error { error: e.to_string() },
        }
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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .call(move |s: &Stores| s.db().update_adblock_rule_status(id, enabled))
            .await
        {
            Ok(()) => {
                if let Ok(rules) = storage.call(|s: &Stores| s.db().load_adblock_rules()).await {
                    self.ctx.update_dns_adblock_rules(
                        rules
                            .into_iter()
                            .map(|(id, domain, action, enabled)| {
                                lanforge_types::network::dns::adblock::AdblockRuleEntry {
                                    id: Some(id),
                                    domain,
                                    action,
                                    enabled,
                                }
                            })
                            .collect(),
                    );
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock rule {id} status updated to enabled={enabled}"),
                })
            }
            Err(e) => Response::Error { error: e.to_string() },
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
