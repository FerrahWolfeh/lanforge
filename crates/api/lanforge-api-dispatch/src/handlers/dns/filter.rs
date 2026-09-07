use crate::ClientContext;
use lanforge_api::api::AllowlistEntry;
#[cfg(not(feature = "adblock"))]
use lanforge_api::api::{DnsAllowlistResponse, Response};
#[cfg(feature = "adblock")]
use lanforge_api::api::{DnsAllowlistResponse, Response, SimpleSuccess};

#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockRuleAction;

impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_block(&self, domain: String) -> Response {
        match self.db.add_adblock_rule(&domain, AdblockRuleAction::Block).await {
            Ok(_) => {
                if let Ok(rows) = self.db.load_adblock_rules().await {
                    let rules = rows
                        .into_iter()
                        .map(|(id, domain, action, enabled)| {
                            lanforge_types::network::dns::adblock::AdblockRuleEntry {
                                id: Some(id),
                                domain,
                                action,
                                enabled,
                            }
                        })
                        .collect();
                    self.ctx.update_dns_adblock_rules(rules);
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
        match self.db.add_dns_allowlist(&domain).await {
            Ok(()) => {
                let allowlist = self.db.load_dns_allowlist().await.map_or_else(
                    |_| Vec::new(),
                    |list| list.into_iter().map(|(_, d)| d).collect(),
                );
                self.ctx.update_dns_allowlist(allowlist);
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
        match self.db.remove_dns_allowlist(&domain).await {
            Ok(()) => {
                let allowlist = self.db.load_dns_allowlist().await.map_or_else(
                    |_| Vec::new(),
                    |list| list.into_iter().map(|(_, d)| d).collect(),
                );
                self.ctx.update_dns_allowlist(allowlist);
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
        match self.db.load_dns_allowlist().await {
            Ok(allowlist) => Response::DnsAllowlist(DnsAllowlistResponse {
                allowlist: allowlist
                    .into_iter()
                    .map(|(id, domain)| AllowlistEntry { id, domain })
                    .collect(),
            }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }
}
