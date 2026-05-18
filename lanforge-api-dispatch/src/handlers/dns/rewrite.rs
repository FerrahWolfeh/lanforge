use crate::ClientContext;
use lanforge_api::api::{DnsRewritesResponse, Response, SimpleSuccess};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_types::network::dns::adblock::RewriteRule;

impl ClientContext {
    pub async fn handle_dns_rewrite_add(&self, rule: RewriteRule) -> Response {
        match self
            .db
            .upsert_dns_rewrite(&rule.domain, rule.rtype, &rule.answer.to_string())
            .await
        {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
                Response::Success(SimpleSuccess {
                    message: format!(
                        "DNS rewrite added: {} ({}) -> {}",
                        rule.domain, rule.rtype, rule.answer
                    ),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    pub async fn handle_dns_rewrite_remove(&self, id: i64) -> Response {
        match self.db.delete_dns_rewrite_by_id(id).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
                Response::Success(SimpleSuccess {
                    message: format!("DNS rewrite with ID {id} removed"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    pub async fn handle_dns_rewrites(&self) -> Response {
        match self.db.load_dns_rewrites().await {
            Ok(rewrites) => Response::DnsRewrites(DnsRewritesResponse { rewrites }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    pub async fn handle_dns_rewrite_clear(&self) -> Response {
        match self.db.clear_dns_rewrites().await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
                Response::Success(SimpleSuccess {
                    message: "All DNS rewrites cleared".to_string(),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    pub async fn handle_dns_rewrite_import(&self, rules: Vec<RewriteRule>) -> Response {
        let mut count = 0;
        for rule in rules {
            if let Response::Success(_) = self.handle_dns_rewrite_add(rule).await {
                count += 1;
            }
        }
        Response::Success(SimpleSuccess {
            message: format!("Successfully imported {count} DNS rewrites"),
        })
    }

    pub async fn handle_dns_rewrite_export(&self) -> Response {
        self.handle_dns_rewrites().await
    }
}
