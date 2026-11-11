use crate::ClientContext;
use lanforge_api::api::{AllowlistEntry, DnsAllowlistResponse, Response};

#[cfg(feature = "adblock")]
use crate::handlers::dns::rewrite::dns_reply;
#[cfg(feature = "adblock")]
use crate::handlers::system::config_write::ChangeError;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::rules_file::RulesFile;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::{AdblockRuleAction, AdblockRuleEntry};

// The allowlist is the allow rules (`@@||x^`) of the global rules file; blocking or allowing a
// domain replaces its opposite rule.
impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_block(&self, domain: String) -> Response {
        self.add_adblock_rule(&domain, AdblockRuleAction::Block, None)
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
        self.add_adblock_rule(&domain, AdblockRuleAction::Allow, None)
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
            self.change_adblock_rules(None, |text| {
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
