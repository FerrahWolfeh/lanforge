use crate::ClientContext;
#[cfg(not(feature = "adblock"))]
use lanforge_api::api::{DnsAllowlistResponse, Response};
#[cfg(feature = "adblock")]
use lanforge_api::api::{DnsAllowlistResponse, Response, SimpleSuccess};

#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::DnsRecordType;

impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_block(&self, domain: String) -> Response {
        match self
            .db
            .upsert_dns_rewrite(&domain, DnsRecordType::A, "0.0.0.0")
            .await
        {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
                Response::Success(SimpleSuccess {
                    message: format!(
                        "Domain '{domain}' blocked persistently via rewrite to 0.0.0.0"
                    ),
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
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
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
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
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
                    .map(|(id, domain)| lanforge_api::api::AllowlistEntry { id, domain })
                    .collect(),
            }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }
}
