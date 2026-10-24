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
        let mut rules = self.ctx.get_dns_adblock_rules();
        if let Some(existing) = rules.iter_mut().find(|r| r.domain.eq_ignore_ascii_case(&domain)) {
            existing.action = AdblockRuleAction::Block;
            existing.enabled = true;
        } else {
            let mut entry = lanforge_types::network::dns::adblock::AdblockRuleEntry {
                id: None,
                name: Some(lanforge_crypto::slugify(&domain)),
                domain: domain.clone(),
                action: AdblockRuleAction::Block,
                enabled: true,
            };
            entry.id = Some(entry.deterministic_id());
            rules.push(entry);
        }
        self.ctx.update_dns_adblock_rules(rules);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockBlock(domain.clone())));
        Response::Success(SimpleSuccess {
            message: format!("Domain '{domain}' blocked in adblock rules"),
        })
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
        let mut list = self.ctx.get_dns_allowlist();
        if !list.iter().any(|d| d.eq_ignore_ascii_case(&domain)) {
            list.push(domain.clone());
            self.ctx.update_dns_allowlist(list);
        }
        Response::Success(SimpleSuccess {
            message: format!("Domain '{domain}' added to DNS allowlist"),
        })
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
        let mut list = self.ctx.get_dns_allowlist();
        let len_before = list.len();
        list.retain(|d| !d.eq_ignore_ascii_case(&domain));
        if list.len() == len_before {
            return Response::Error {
                error: format!("Domain '{domain}' not found in allowlist"),
            };
        }
        self.ctx.update_dns_allowlist(list);
        Response::Success(SimpleSuccess {
            message: format!("Domain '{domain}' removed from DNS allowlist"),
        })
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
