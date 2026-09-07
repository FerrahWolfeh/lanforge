use crate::ClientContext;
#[cfg(not(feature = "adblock"))]
use lanforge_api::api::Response;
#[cfg(feature = "adblock")]
use lanforge_api::api::{
    AdblockRuleEntry, AdblockUrlEntry, DnsAdblockRulesResponse, DnsAdblockStatusResponse,
    DnsAdblockUrlsResponse, Response, SimpleSuccess,
};

#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use tracing::error;

#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockRuleAction;
use lanforge_types::network::dns::adblock::{AdblockUrlKind, BlockingMode};
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
            match self.db.set_adblock_config_value("enabled", val).await {
                Ok(()) => {
                    if let Ok(cfg) = self.db.load_adblock_config().await {
                        self.ctx.update_dns_adblock(cfg);
                    }
                }
                Err(e) => {
                    error!("❌ API: Failed to persist adblock enabled status: {e}");
                }
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
            return Response::DnsAdblockStatus(DnsAdblockStatusResponse {
                enabled: res.enabled,
                disabled_until: res.disabled_until,
                remaining_secs: res.remaining_secs,
                blocklist_size: res.blocklist_size,
                allowlist_size: res.allowlist_size,
                blocking_mode: res.blocking_mode,
                blocking_ip_v4: res.blocking_ip_v4,
                blocking_ip_v6: res.blocking_ip_v6,
            });
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
    pub async fn handle_dns_adblock_url_add(&self, url: String, kind: AdblockUrlKind) -> Response {
        match self.db.add_adblock_url(&url, kind).await {
            Ok(()) => {
                if let Ok(urls) = self.db.load_adblock_urls().await {
                    let entries = urls
                        .into_iter()
                        .map(|(id, url, kind)| AdblockUrlEntry {
                            id: Some(id),
                            url,
                            kind,
                        })
                        .collect();
                    self.ctx.update_dns_adblock_urls(entries);
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock {kind} URL added: {url}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_add(
        &self,
        _url: String,
        _kind: AdblockUrlKind,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_remove(&self, url: String) -> Response {
        match self.db.remove_adblock_url(&url).await {
            Ok(()) => {
                if let Ok(urls) = self.db.load_adblock_urls().await {
                    let entries = urls
                        .into_iter()
                        .map(|(id, url, kind)| AdblockUrlEntry {
                            id: Some(id),
                            url,
                            kind,
                        })
                        .collect();
                    self.ctx.update_dns_adblock_urls(entries);
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock URL removed: {url}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
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
        match self.db.load_adblock_urls().await {
            Ok(urls) => Response::DnsAdblockUrls(DnsAdblockUrlsResponse {
                urls: urls
                    .into_iter()
                    .map(|(id, url, kind)| AdblockUrlEntry {
                        id: Some(id),
                        url,
                        kind,
                    })
                    .collect(),
            }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
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
    ) -> Response {
        let mut updated = false;
        if let Some(mode) = blocking_mode {
            if let Err(e) = self
                .db
                .set_adblock_config_value("blocking_mode", &mode.to_string())
                .await
            {
                return Response::Error {
                    error: format!("Failed to update blocking_mode: {e}"),
                };
            }
            updated = true;
        }
        if let Some(ip) = blocking_ip_v4 {
            if let Err(e) = self
                .db
                .set_adblock_config_value("blocking_ip_v4", &ip.to_string())
                .await
            {
                return Response::Error {
                    error: format!("Failed to update blocking_ip_v4: {e}"),
                };
            }
            updated = true;
        }
        if let Some(ip) = blocking_ip_v6 {
            if let Err(e) = self
                .db
                .set_adblock_config_value("blocking_ip_v6", &ip.to_string())
                .await
            {
                return Response::Error {
                    error: format!("Failed to update blocking_ip_v6: {e}"),
                };
            }
            updated = true;
        }

        if updated && let Ok(cfg) = self.db.load_adblock_config().await {
            self.ctx.update_dns_adblock(cfg);
        }

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
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_rules(&self) -> Response {
        match self.db.load_adblock_rules().await {
            Ok(rows) => {
                let rules = rows
                    .into_iter()
                    .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                        id: Some(id),
                        domain,
                        action,
                        enabled,
                    })
                    .collect();
                Response::DnsAdblockRules(DnsAdblockRulesResponse { rules })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
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
        match self.db.add_adblock_rule(&domain, rule_action).await {
            Ok(id) => {
                if let Ok(rows) = self.db.load_adblock_rules().await {
                    let rules = rows
                        .into_iter()
                        .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                            id: Some(id),
                            domain,
                            action,
                            enabled,
                        })
                        .collect();
                    self.ctx.update_dns_adblock_rules(rules);
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock rule added for domain '{domain}' with action '{action}' (id: {id})"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
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
        match self.db.remove_adblock_rule(id).await {
            Ok(()) => {
                if let Ok(rows) = self.db.load_adblock_rules().await {
                    let rules = rows
                        .into_iter()
                        .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                            id: Some(id),
                            domain,
                            action,
                            enabled,
                        })
                        .collect();
                    self.ctx.update_dns_adblock_rules(rules);
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock rule {id} removed"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
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
        match self.db.update_adblock_rule_status(id, enabled).await {
            Ok(()) => {
                if let Ok(rows) = self.db.load_adblock_rules().await {
                    let rules = rows
                        .into_iter()
                        .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                            id: Some(id),
                            domain,
                            action,
                            enabled,
                        })
                        .collect();
                    self.ctx.update_dns_adblock_rules(rules);
                }
                Response::Success(SimpleSuccess {
                    message: format!("Adblock rule {id} status updated to enabled={enabled}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
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
