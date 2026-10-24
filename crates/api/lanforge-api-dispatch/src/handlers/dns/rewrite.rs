use crate::ClientContext;
use lanforge_api::api::{DnsRewritesResponse, Response, SimpleSuccess};
use lanforge_types::network::dns::adblock::RewriteRule;

impl ClientContext {
    pub async fn handle_dns_rewrite_add(&self, rule: RewriteRule) -> Response {
        let mut rewrites = self.ctx.get_dns_rewrites();
        if let Some(existing) = rewrites
            .iter_mut()
            .find(|r| r.domain.eq_ignore_ascii_case(&rule.domain) && r.rtype == rule.rtype)
        {
            existing.answer = rule.answer.clone();
        } else {
            let next_id = rewrites.iter().filter_map(|r| r.id).max().unwrap_or(0) + 1;
            let mut new_rule = rule.clone();
            new_rule.id = Some(next_id);
            rewrites.push(new_rule);
        }
        self.ctx.update_dns_rewrites(rewrites);

        Response::Success(SimpleSuccess {
            message: format!(
                "DNS rewrite added: {} ({}) -> {}",
                rule.domain, rule.rtype, rule.answer
            ),
        })
    }

    pub async fn handle_dns_rewrite_remove(&self, id: i64) -> Response {
        let mut rewrites = self.ctx.get_dns_rewrites();
        let len_before = rewrites.len();
        rewrites.retain(|r| r.id != Some(id));
        if rewrites.len() != len_before {
            self.ctx.update_dns_rewrites(rewrites);
        }
        Response::Success(SimpleSuccess {
            message: format!("DNS rewrite with ID {id} removed"),
        })
    }

    pub async fn handle_dns_rewrites(&self) -> Response {
        let rewrites = self.ctx.get_dns_rewrites();
        Response::DnsRewrites(DnsRewritesResponse { rewrites })
    }

    pub async fn handle_dns_rewrite_clear(&self) -> Response {
        self.ctx.update_dns_rewrites(Vec::new());
        Response::Success(SimpleSuccess {
            message: "All DNS rewrites cleared".to_string(),
        })
    }

    pub async fn handle_dns_rewrite_import(&self, rules: Vec<RewriteRule>) -> Response {
        let mut rewrites = self.ctx.get_dns_rewrites();
        let mut count = 0;
        for rule in rules {
            if let Some(existing) = rewrites
                .iter_mut()
                .find(|r| r.domain.eq_ignore_ascii_case(&rule.domain) && r.rtype == rule.rtype)
            {
                existing.answer = rule.answer;
            } else {
                let next_id = rewrites.iter().filter_map(|r| r.id).max().unwrap_or(0) + 1;
                let mut new_rule = rule;
                new_rule.id = Some(next_id);
                rewrites.push(new_rule);
            }
            count += 1;
        }
        self.ctx.update_dns_rewrites(rewrites);
        Response::Success(SimpleSuccess {
            message: format!("Successfully imported {count} DNS rewrites"),
        })
    }

    pub async fn handle_dns_rewrite_export(&self) -> Response {
        self.handle_dns_rewrites().await
    }
}
