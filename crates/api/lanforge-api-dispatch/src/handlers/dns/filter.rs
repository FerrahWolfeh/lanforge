use crate::ClientContext;
use lanforge_api::api::AllowlistEntry;
#[cfg(not(feature = "adblock"))]
use lanforge_api::api::{DnsAllowlistResponse, Response};
#[cfg(feature = "adblock")]
use lanforge_api::api::{DnsAllowlistResponse, Response, SimpleSuccess};
#[cfg(feature = "adblock")]
use lanforge_db_core::Stores;

#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockRuleAction;

impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_block(&self, domain: String) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let d_clone = domain.clone();
        match storage
            .call(move |s: &Stores| {
                s.db().add_adblock_rule(&d_clone, AdblockRuleAction::Block)
            })
            .await
        {
            Ok(_) => {
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
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::AdblockBlock(domain.clone())));
                Response::Success(SimpleSuccess {
                    message: format!("Domain '{domain}' blocked in adblock rules"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_block(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_allow(&self, domain: String) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let d_clone = domain.clone();
        match storage
            .call(move |s: &Stores| s.db().add_dns_allowlist(&d_clone))
            .await
        {
            Ok(()) => {
                if let Ok(rows) = storage.call(|s: &Stores| s.db().load_dns_allowlist()).await {
                    self.ctx.update_dns_allowlist(rows.into_iter().map(|(_, d)| d).collect());
                }
                Response::Success(SimpleSuccess {
                    message: format!("Domain '{domain}' added to DNS allowlist"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_allow(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_unallow(&self, domain: String) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let d_clone = domain.clone();
        match storage
            .call(move |s: &Stores| s.db().remove_dns_allowlist(&d_clone))
            .await
        {
            Ok(()) => {
                if let Ok(rows) = storage.call(|s: &Stores| s.db().load_dns_allowlist()).await {
                    self.ctx.update_dns_allowlist(rows.into_iter().map(|(_, d)| d).collect());
                }
                Response::Success(SimpleSuccess {
                    message: format!("Domain '{domain}' removed from DNS allowlist"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_unallow(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    pub async fn handle_dns_allowlist(&self) -> Response {
        let allowlist = self
            .ctx
            .get_dns_allowlist()
            .into_iter()
            .enumerate()
            .map(|(id, domain)| AllowlistEntry {
                id: id as i64 + 1,
                domain,
            })
            .collect();
        Response::DnsAllowlist(DnsAllowlistResponse { allowlist })
    }
}
