use crate::ClientContext;
use lanforge_api::api::{AllowlistEntry, DnsAllowlistResponse, Response};

#[cfg(feature = "adblock")]
use crate::handlers::dns::adblock::with_rule_only;
#[cfg(feature = "adblock")]
use crate::handlers::dns::rewrite::dns_reply;
use crate::handlers::system::toml_sync::ChangeError;
#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::rules_file::RulesFile;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::{AdblockRuleAction, AdblockRuleEntry};

// The allowlist is the allow rules (`@@||x^`) of the global rules file; blocking or allowing a
// domain replaces its opposite rule.
impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_block(&self, domain: String) -> Response {
        let line = AdblockRuleEntry::rule_line(&domain, AdblockRuleAction::Block);
        let reply = dns_reply(
            self.change_adblock_rules(|text| with_rule_only(text, &line)),
            format!("Domain '{domain}' blocked in adblock rules"),
        );
        if matches!(reply, Response::Success(_)) {
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Dns(DnsEvent::AdblockBlock(domain)));
        }
        reply
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
        let line = AdblockRuleEntry::rule_line(&domain, AdblockRuleAction::Allow);
        dns_reply(
            self.change_adblock_rules(|text| with_rule_only(text, &line)),
            format!("Domain '{domain}' added to DNS allowlist"),
        )
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
        let id = RulesFile::rule_id(&AdblockRuleEntry::rule_line(
            &domain,
            AdblockRuleAction::Allow,
        ));
        dns_reply(
            self.change_adblock_rules(|text| {
                RulesFile::new(text)
                    .without_rule(id)
                    .map(Some)
                    .ok_or_else(|| {
                        ChangeError::NotFound(format!("Domain '{domain}' not found in allowlist"))
                    })
            }),
            format!("Domain '{domain}' removed from DNS allowlist"),
        )
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_unallow(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    /// The enabled allow rules, a `@@||x^` one shown as its domain.
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_allowlist(&self) -> Response {
        let allowlist = self.ctx.with_config(|c| {
            RulesFile::new(&c.dns_adblock_rules.0)
                .rule_entries()
                .into_iter()
                .filter(|r| r.enabled && r.is_allow())
                .map(|r| AllowlistEntry {
                    id: r.effective_id(),
                    domain: r
                        .domain
                        .strip_prefix("@@||")
                        .and_then(|d| d.strip_suffix('^'))
                        .map_or_else(|| r.domain.clone(), str::to_string),
                })
                .collect()
        });
        Response::DnsAllowlist(DnsAllowlistResponse { allowlist })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_allowlist(&self) -> Response {
        let allowlist: Vec<AllowlistEntry> = Vec::new();
        Response::DnsAllowlist(DnsAllowlistResponse { allowlist })
    }
}
