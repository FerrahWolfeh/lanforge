use crate::ClientContext;
use lanforge_api::api::{DnsRewritesResponse, Response, SimpleSuccess};
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
            .send_query(lanforge_types::storage::StorageQuery::DeleteDnsRewrite(id))
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("DNS rewrite with ID {id} removed"),
            }),
            Err(e) => Response::Error { error: e },
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
            .send_query(lanforge_types::storage::StorageQuery::ClearDnsRewrites)
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: "All DNS rewrites cleared".to_string(),
            }),
            Err(e) => Response::Error { error: e },
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
        storage
            .send_query(lanforge_types::storage::StorageQuery::UpsertDnsRewrite {
                domain: rule.domain.clone(),
                rtype: rule.rtype,
                answer: rule.answer.clone(),
            })
            .await
            .map(|_| ())
    }
}
