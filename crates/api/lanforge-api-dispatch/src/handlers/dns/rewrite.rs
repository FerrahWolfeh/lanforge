use crate::ClientContext;
use lanforge_api::api::{DnsRewritesResponse, Response, SimpleSuccess};
use lanforge_types::network::dns::adblock::RewriteRule;

impl ClientContext {
    pub async fn handle_dns_rewrite_add(&self, rule: RewriteRule) -> Response {
        match self.add_dns_rewrite_internal(&rule).await {
            Ok(()) => {
                if let Err(e) = self.reload_dns_rewrites_to_context().await {
                    return Response::Error { error: e };
                }
                Response::Success(SimpleSuccess {
                    message: format!(
                        "DNS rewrite added: {} ({}) -> {}",
                        rule.domain, rule.rtype, rule.answer
                    ),
                })
            }
            Err(e) => Response::Error { error: e },
        }
    }

    pub async fn handle_dns_rewrite_remove(&self, id: i64) -> Response {
        match self.db.delete_dns_rewrite_by_id(id).await {
            Ok(()) => {
                if let Err(e) = self.reload_dns_rewrites_to_context().await {
                    return Response::Error { error: e };
                }
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
                if let Err(e) = self.reload_dns_rewrites_to_context().await {
                    return Response::Error { error: e };
                }
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
            if self.add_dns_rewrite_internal(&rule).await.is_ok() {
                count += 1;
            }
        }
        let _ = self.reload_dns_rewrites_to_context().await;
        Response::Success(SimpleSuccess {
            message: format!("Successfully imported {count} DNS rewrites"),
        })
    }

    pub async fn handle_dns_rewrite_export(&self) -> Response {
        self.handle_dns_rewrites().await
    }

    async fn add_dns_rewrite_internal(&self, rule: &RewriteRule) -> Result<(), String> {
        self.db
            .upsert_dns_rewrite(&rule.domain, rule.rtype, &rule.answer.to_string())
            .await
            .map_err(|e| e.to_string())
    }

    async fn reload_dns_rewrites_to_context(&self) -> Result<(), String> {
        let rewrites = self
            .db
            .load_dns_rewrites()
            .await
            .map_err(|e| e.to_string())?;
        self.ctx.update_dns_rewrites(rewrites);
        Ok(())
    }
}
