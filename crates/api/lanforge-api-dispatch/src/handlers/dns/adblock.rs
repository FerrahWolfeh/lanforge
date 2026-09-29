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
            if let Some(storage) = self.ctx.storage_handle()
                && let Err(e) = storage
                    .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                        key: "enabled".into(),
                        value: val.into(),
                    })
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
    pub async fn handle_dns_adblock_url_add(&self, url: String, kind: AdblockUrlKind) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .send_query(lanforge_types::storage::StorageQuery::AddAdblockUrl {
                url: url.clone(),
                kind,
            })
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("Adblock {kind} URL added: {url}"),
            }),
            Err(e) => Response::Error { error: e },
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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .send_query(lanforge_types::storage::StorageQuery::RemoveAdblockUrl(
                url.clone(),
            ))
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("Adblock URL removed: {url}"),
            }),
            Err(e) => Response::Error { error: e },
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
    ) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        if let Some(mode) = blocking_mode
            && let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                    key: "blocking_mode".into(),
                    value: mode.to_string(),
                })
                .await
        {
            return Response::Error {
                error: format!("Failed to update blocking_mode: {e}"),
            };
        }
        if let Some(ip) = blocking_ip_v4
            && let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                    key: "blocking_ip_v4".into(),
                    value: ip.to_string(),
                })
                .await
        {
            return Response::Error {
                error: format!("Failed to update blocking_ip_v4: {e}"),
            };
        }
        if let Some(ip) = blocking_ip_v6
            && let Err(e) = storage
                .send_query(lanforge_types::storage::StorageQuery::SetAdblockConfigValue {
                    key: "blocking_ip_v6".into(),
                    value: ip.to_string(),
                })
                .await
        {
            return Response::Error {
                error: format!("Failed to update blocking_ip_v6: {e}"),
            };
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

        match storage
            .send_query(lanforge_types::storage::StorageQuery::AddAdblockRule {
                domain: domain.clone(),
                action: rule_action,
            })
            .await
        {
            Ok(lanforge_types::storage::StorageQueryResult::Id(id)) => {
                Response::Success(SimpleSuccess {
                    message: format!(
                        "Adblock rule added for domain '{domain}' with action '{action}' (id: {id})"
                    ),
                })
            }
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("Adblock rule added for domain '{domain}' with action '{action}'"),
            }),
            Err(e) => Response::Error { error: e },
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
            .send_query(lanforge_types::storage::StorageQuery::RemoveAdblockRule(id))
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("Adblock rule {id} removed"),
            }),
            Err(e) => Response::Error { error: e },
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
            .send_query(
                lanforge_types::storage::StorageQuery::UpdateAdblockRuleStatus { id, enabled },
            )
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("Adblock rule {id} status updated to enabled={enabled}"),
            }),
            Err(e) => Response::Error { error: e },
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
