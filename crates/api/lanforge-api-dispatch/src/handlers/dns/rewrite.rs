use crate::ClientContext;
use crate::handlers::system::toml_sync::Persisted;
use lanforge_api::api::{DnsRewritesResponse, Response, SimpleSuccess};
use lanforge_types::network::dns::adblock::RewriteRule;

/// The reply to a DNS change that `[dns]` took (`what` done), kept in memory only, or refused.
pub(crate) fn dns_reply(result: Result<Persisted, String>, what: String) -> Response {
    match result {
        Ok(Persisted::File) => Response::Success(SimpleSuccess { message: what }),
        Ok(Persisted::MemoryOnly) => Response::Success(SimpleSuccess {
            message: format!(
                "{what} (in memory only, not saved: the configuration file is read-only or not set)"
            ),
        }),
        Err(error) => Response::Error { error },
    }
}

/// Adds `rule`, or gives the rule of the same domain and type its answer.
pub(crate) fn upsert_rewrite(rewrites: &mut Vec<RewriteRule>, rule: RewriteRule) {
    if let Some(existing) = rewrites
        .iter_mut()
        .find(|r| r.domain.eq_ignore_ascii_case(&rule.domain) && r.rtype == rule.rtype)
    {
        existing.answer = rule.answer;
    } else {
        rewrites.push(rule);
    }
}

impl ClientContext {
    pub async fn handle_dns_rewrite_add(&self, rule: RewriteRule) -> Response {
        let what = format!(
            "DNS rewrite added: {} ({}) -> {}",
            rule.domain, rule.rtype, rule.answer
        );
        dns_reply(
            self.change_dns(|dns| upsert_rewrite(&mut dns.rewrites, rule)),
            what,
        )
    }

    pub async fn handle_dns_rewrite_remove(&self, id: i64) -> Response {
        if !self
            .ctx
            .get_dns_rewrites()
            .iter()
            .any(|r| r.effective_id() == id)
        {
            return Response::Error {
                error: format!("DNS rewrite with ID {id} not found"),
            };
        }
        dns_reply(
            self.change_dns(|dns| dns.rewrites.retain(|r| r.effective_id() != id)),
            format!("DNS rewrite with ID {id} removed"),
        )
    }

    pub async fn handle_dns_rewrites(&self) -> Response {
        let mut rewrites = self.ctx.get_dns_rewrites();
        for r in &mut rewrites {
            if r.id.is_none() {
                r.id = Some(r.effective_id());
            }
        }
        Response::DnsRewrites(DnsRewritesResponse { rewrites })
    }

    pub async fn handle_dns_rewrite_clear(&self) -> Response {
        dns_reply(
            self.change_dns(|dns| dns.rewrites.clear()),
            "All DNS rewrites cleared".to_string(),
        )
    }

    pub async fn handle_dns_rewrite_import(&self, rules: Vec<RewriteRule>) -> Response {
        let count = rules.len();
        dns_reply(
            self.change_dns(|dns| {
                for rule in rules {
                    upsert_rewrite(&mut dns.rewrites, rule);
                }
            }),
            format!("Successfully imported {count} DNS rewrites"),
        )
    }

    pub async fn handle_dns_rewrite_export(&self) -> Response {
        self.handle_dns_rewrites().await
    }
}
