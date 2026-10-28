#![cfg(feature = "adblock")]
//! The manual layer decides what the stored allowlist and rules decided before they were read
//! through the rules-file parser (item f2a): same decisions, same attribution.

use std::sync::Arc;

use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::resolver::filter::AdBlocker;
use lanforge_types::network::dns::adblock::{AdblockRuleAction, AdblockRuleEntry, FilterAction};

fn rule(domain: &str, action: AdblockRuleAction, enabled: bool) -> AdblockRuleEntry {
    AdblockRuleEntry {
        id: None,
        name: None,
        domain: domain.into(),
        action,
        enabled,
    }
}

/// Every decision as `name -> action (rule)`, one line per query.
fn decisions(filter: &AdBlocker, queries: &[&str]) -> String {
    queries
        .iter()
        .map(|q| match filter.check_domain(q) {
            None => format!("{q} -> none\n"),
            Some(m) => format!(
                "{q} -> {} {:?} rule={:?} important={}\n",
                if m.action == FilterAction::Block {
                    "block"
                } else {
                    "allow"
                },
                m.origin,
                m.rule,
                m.important
            ),
        })
        .collect()
}

#[test]
fn stored_rules_decide_as_before() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    // The owner's 4 Bradesco allows, plus every stored spelling the WebUI/CLI could produce.
    ctx.update_dns_allowlist(vec![
        "app-measurement.com".into(),
        "www.googletagmanager.com".into(),
        "js-cdn.dynatrace.com".into(),
        "analytics.google.com".into(),
        "@@||allow-syntax.com^".into(),
        "Upper.Example.com".into(),
    ]);
    ctx.update_dns_adblock_rules(vec![
        rule("ads.example.com", AdblockRuleAction::Block, true),
        rule("||wild.example.com^", AdblockRuleAction::Block, true),
        rule("|pipe.example.com^", AdblockRuleAction::Block, true),
        rule("*.star.example.com", AdblockRuleAction::Block, true),
        rule("mod.example.com$important", AdblockRuleAction::Block, true),
        rule(
            "client.example.com$client=10.0.0.1",
            AdblockRuleAction::Block,
            true,
        ),
        rule("off.example.com", AdblockRuleAction::Block, false),
        rule("ok.ads.example.com", AdblockRuleAction::Allow, true),
        rule("google.com", AdblockRuleAction::Block, true),
        rule("trailing.example.com.", AdblockRuleAction::Block, true),
    ]);
    let filter = AdBlocker::new(true);
    filter.sync_from_context(&ctx);

    let queries = [
        "app-measurement.com",
        "x.app-measurement.com",
        "www.googletagmanager.com",
        "googletagmanager.com",
        "js-cdn.dynatrace.com",
        "analytics.google.com",
        "google.com",
        "mail.google.com",
        "allow-syntax.com",
        "a.allow-syntax.com",
        "upper.example.com",
        "ads.example.com",
        "a.b.ads.example.com",
        "ok.ads.example.com",
        "x.ok.ads.example.com",
        "wild.example.com",
        "x.wild.example.com",
        "pipe.example.com",
        "x.pipe.example.com",
        "star.example.com",
        "x.star.example.com",
        "mod.example.com",
        "client.example.com",
        "off.example.com",
        "trailing.example.com",
        "example.com",
        "unrelated.org",
    ];
    let expected = "\
app-measurement.com -> allow UserAllowlist rule=None important=false
x.app-measurement.com -> allow UserAllowlist rule=Some(\"app-measurement.com\") important=false
www.googletagmanager.com -> allow UserAllowlist rule=None important=false
googletagmanager.com -> none
js-cdn.dynatrace.com -> allow UserAllowlist rule=None important=false
analytics.google.com -> allow UserAllowlist rule=None important=false
google.com -> block UserRule rule=None important=false
mail.google.com -> block UserRule rule=Some(\"google.com\") important=false
allow-syntax.com -> allow UserAllowlist rule=None important=false
a.allow-syntax.com -> allow UserAllowlist rule=Some(\"allow-syntax.com\") important=false
upper.example.com -> allow UserAllowlist rule=None important=false
ads.example.com -> block UserRule rule=None important=false
a.b.ads.example.com -> block UserRule rule=Some(\"ads.example.com\") important=false
ok.ads.example.com -> allow UserAllowlist rule=None important=false
x.ok.ads.example.com -> allow UserAllowlist rule=Some(\"ok.ads.example.com\") important=false
wild.example.com -> block UserRule rule=None important=false
x.wild.example.com -> block UserRule rule=Some(\"wild.example.com\") important=false
pipe.example.com -> block UserRule rule=None important=false
x.pipe.example.com -> block UserRule rule=Some(\"pipe.example.com\") important=false
star.example.com -> block UserRule rule=None important=false
x.star.example.com -> block UserRule rule=Some(\"star.example.com\") important=false
mod.example.com -> block UserRule rule=None important=false
client.example.com -> block UserRule rule=None important=false
off.example.com -> none
trailing.example.com -> block UserRule rule=None important=false
example.com -> none
unrelated.org -> none
";
    assert_eq!(decisions(&filter, &queries), expected);
}
