use crate::ClientContext;
use lanforge_api::api::{DnsRewritesResponse, Response, SimpleSuccess};
use lanforge_db_core::Stores;
use lanforge_types::network::dns::adblock::RewriteRule;

impl ClientContext {
    pub async fn handle_dns_rewrite_add(&self, rule: RewriteRule) -> Response {
        match self.add_dns_rewrite_internal(&rule).await {
            Ok(()) => Response::Success(SimpleSuccess {
                message: format!(
                    "DNS rewrite added: {} ({}) -> {}",
                    rule.domain, rule.rtype, rule.answer
                ),
            }),
            Err(e) => Response::Error { error: e },
        }
    }

    pub async fn handle_dns_rewrite_remove(&self, id: i64) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .call(move |s: &Stores| s.db().delete_dns_rewrite_by_id(id))
            .await
        {
            Ok(()) => {
                if let Ok(rows) = storage.call(|s: &Stores| s.db().load_dns_rewrites()).await {
                    self.ctx.update_dns_rewrites(rows);
                }
                Response::Success(SimpleSuccess {
                    message: format!("DNS rewrite with ID {id} removed"),
                })
            }
            Err(e) => Response::Error { error: e.to_string() },
        }
    }

    pub async fn handle_dns_rewrites(&self) -> Response {
        let rewrites = self.ctx.get_dns_rewrites();
        Response::DnsRewrites(DnsRewritesResponse { rewrites })
    }

    pub async fn handle_dns_rewrite_clear(&self) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .call(|s: &Stores| s.db().clear_dns_rewrites())
            .await
        {
            Ok(()) => {
                self.ctx.update_dns_rewrites(Vec::new());
                Response::Success(SimpleSuccess {
                    message: "All DNS rewrites cleared".to_string(),
                })
            }
            Err(e) => Response::Error { error: e.to_string() },
        }
    }

    pub async fn handle_dns_rewrite_import(&self, rules: Vec<RewriteRule>) -> Response {
        let mut count = 0;
        for rule in rules {
            if self.add_dns_rewrite_internal(&rule).await.is_ok() {
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

    async fn add_dns_rewrite_internal(&self, rule: &RewriteRule) -> Result<(), String> {
        let storage = self
            .ctx
            .storage_handle()
            .ok_or_else(|| "Storage service not available".to_string())?;
        let domain = rule.domain.clone();
        let rtype = rule.rtype;
        let answer = rule.answer.clone();
        storage
            .call(move |s: &Stores| s.db().upsert_dns_rewrite(&domain, rtype, &answer))
            .await
            .map_err(|e| e.to_string())?;

        if let Ok(rows) = storage.call(|s: &Stores| s.db().load_dns_rewrites()).await {
            self.ctx.update_dns_rewrites(rows);
        }
        Ok(())
    }
}
