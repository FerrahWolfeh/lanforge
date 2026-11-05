#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions and setup"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
#![cfg(feature = "adblock")]
//! The manual rules file decides what the old database allowlist and rules decided (the
//! expected table below passed on the engine before item f2a; the file is what the config
//! cut-over wrote from them): same decisions, same attribution.

use std::sync::Arc;

use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::resolver::filter::AdBlocker;
use lanforge_types::network::dns::adblock::FilterAction;

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
    // The owner's 4 Bradesco allows, plus every stored spelling the WebUI/CLI could produce
    // (`@@||allow-syntax.com^`, `Upper.Example.com`, `|pipe.example.com^`, `*.star.example.com`,
    // `mod.example.com$important`, `client.example.com$client=10.0.0.1`, `trailing.example.com.`,
    // a disabled `off.example.com`), as the cut-over wrote them.
    let text = "\
@@||app-measurement.com^
@@||www.googletagmanager.com^
@@||js-cdn.dynatrace.com^
@@||analytics.google.com^
@@||allow-syntax.com^
@@||upper.example.com^
||ads.example.com^
||wild.example.com^
||pipe.example.com^
||star.example.com^
||mod.example.com^
||client.example.com^
# ||off.example.com^
@@||ok.ads.example.com^
||google.com^
||trailing.example.com^
"
    .to_string();
    // Through the context, as the daemon loads it.
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.update_dns_adblock_rules(text);
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
