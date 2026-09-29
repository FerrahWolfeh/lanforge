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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .send_query(lanforge_types::storage::StorageQuery::AddAdblockRule {
                domain: domain.clone(),
                action: AdblockRuleAction::Block,
            })
            .await
        {
            Ok(_) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::AdblockBlock(domain.clone())));
                Response::Success(SimpleSuccess {
                    message: format!("Domain '{domain}' blocked in adblock rules"),
                })
            }
            Err(e) => Response::Error {
                error: e,
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

        match storage
            .send_query(lanforge_types::storage::StorageQuery::AddDnsAllowlist(
                domain.clone(),
            ))
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("Domain '{domain}' added to DNS allowlist"),
            }),
            Err(e) => Response::Error {
                error: e,
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

        match storage
            .send_query(lanforge_types::storage::StorageQuery::RemoveDnsAllowlist(
                domain.clone(),
            ))
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("Domain '{domain}' removed from DNS allowlist"),
            }),
            Err(e) => Response::Error {
                error: e,
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
