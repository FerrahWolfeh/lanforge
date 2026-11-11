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

// The allowlist is the allow rules (`@@||x^`) of a rules file (the global one, or a group's with
// `group`); blocking or allowing a domain replaces its opposite rule.
impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_block(&self, domain: String, group: Option<String>) -> Response {
        self.add_adblock_rule(&domain, AdblockRuleAction::Block, group.as_deref())
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_block(&self, _domain: String, _group: Option<String>) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_allow(&self, domain: String, group: Option<String>) -> Response {
        self.add_adblock_rule(&domain, AdblockRuleAction::Allow, group.as_deref())
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_allow(&self, _domain: String, _group: Option<String>) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_unallow(&self, domain: String, group: Option<String>) -> Response {
        let id = RulesFile::rule_id(&AdblockRuleEntry::rule_line(
            &domain,
            AdblockRuleAction::Allow,
        ));
        dns_reply(
            self.change_adblock_rules(group.as_deref(), |text| {
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
    pub async fn handle_dns_unallow(&self, _domain: String, _group: Option<String>) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    /// The enabled allow rules of the global rules file (or `group`'s), a `@@||x^` one shown as
    /// its domain.
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_allowlist(&self, group: Option<String>) -> Response {
        let allowlist = self.ctx.with_config(|c| {
            let text = match group.as_deref() {
                None => &c.dns_adblock_rules.0,
                Some(name) => {
                    &c.dns_adblock_policy
                        .groups
                        .iter()
                        .find(|g| g.name == name)?
                        .rules
                }
            };
            let entries = RulesFile::new(text)
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
                .collect();
            Some(entries)
        });
        match allowlist {
            Some(allowlist) => Response::DnsAllowlist(DnsAllowlistResponse { allowlist }),
            None => Response::NotFound {
                error: format!("adblock group \"{}\"", group.unwrap_or_default()),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_allowlist(&self, _group: Option<String>) -> Response {
        let allowlist: Vec<AllowlistEntry> = Vec::new();
        Response::DnsAllowlist(DnsAllowlistResponse { allowlist })
    }
}
