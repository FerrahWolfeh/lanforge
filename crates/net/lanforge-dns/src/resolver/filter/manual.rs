//! The manual layer: the rules of the local rules files (`adblock/*.rules`), kept in memory and
//! checked before the lists. Never compiled into an FST: small, and an edit applies at once.

use std::collections::HashMap;

use lanforge_types::network::dns::adblock::FilterAction;
use lanforge_types::network::dns::adblock::rules_file::{RulesFile, RulesLineKind};
use lanforge_types::network::dns::adblock::syntax::{MatchFlags, ParsedRule, RuleAction};

/// The enabled rules of a rules file, by domain.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ManualRules {
    allow: HashMap<Box<str>, MatchFlags>,
    block: HashMap<Box<str>, MatchFlags>,
}

/// What the manual layer decides for a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualVerdict<'a> {
    pub action: FilterAction,
    /// The rule's domain: the name itself or the parent a `||x^` rule covers it from.
    pub domain: &'a str,
    pub important: bool,
}

impl ManualRules {
    /// The enabled rules of a rules file's text. Lines the file gets wrong are config issues
    /// (same reader), never rules. A `$badfilter` cancels its domain in this file.
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        let mut rules = Self::default();
        let mut cancelled: Vec<Box<str>> = Vec::new();
        RulesFile::new(text).for_each_line(|line, parsed| {
            if !matches!(line.kind, RulesLineKind::Rule { enabled: true, .. }) {
                return;
            }
            for rule in parsed {
                match rule.action {
                    RuleAction::BadFilter => cancelled.push(rule.domain.as_str().into()),
                    _ => rules.insert(rule),
                }
            }
        });
        for domain in &cancelled {
            rules.allow.remove(domain);
            rules.block.remove(domain);
        }
        rules
    }

    fn insert(&mut self, rule: &ParsedRule) {
        let map = if rule.action == RuleAction::Allow {
            &mut self.allow
        } else {
            &mut self.block
        };
        map.entry(rule.domain.as_str().into()).or_default().0 |= rule.flags.0;
    }

    #[must_use]
    pub fn block_len(&self) -> usize {
        self.block.len()
    }

    #[must_use]
    pub fn allow_len(&self) -> usize {
        self.allow.len()
    }

    /// The rule of `map` that covers `qname`, the most specific one, important first: the name
    /// itself (rules matching it), then each parent (rules matching subdomains).
    fn find<'a>(
        map: &'a HashMap<Box<str>, MatchFlags>,
        qname: &str,
    ) -> Option<(&'a str, MatchFlags)> {
        if map.is_empty() {
            return None;
        }
        let mut best: Option<(&str, MatchFlags)> = None;
        let mut consider = |hit: Option<(&'a Box<str>, &MatchFlags)>,
                            wanted: fn(MatchFlags) -> bool| {
            if let Some((domain, flags)) = hit
                && wanted(*flags)
                && best.is_none_or(|(_, b)| flags.is_important() && !b.is_important())
            {
                best = Some((domain, *flags));
            }
        };
        consider(map.get_key_value(qname), MatchFlags::is_self);
        let mut rest = qname;
        while let Some(pos) = rest.find('.') {
            rest = &rest[pos + 1..];
            if rest.is_empty() {
                break;
            }
            consider(map.get_key_value(rest), MatchFlags::is_subdomains);
        }
        best
    }

    /// The manual verdict, AdGuard precedence as for the lists: an important block wins unless
    /// an important allow also matches; otherwise an allow wins over a block.
    #[must_use]
    pub fn verdict(&self, qname: &str) -> Option<ManualVerdict<'_>> {
        let allow = Self::find(&self.allow, qname);
        let block = Self::find(&self.block, qname);
        let (action, (domain, flags)) = match (allow, block) {
            (Some(a), Some(b)) if b.1.is_important() && !a.1.is_important() => {
                (FilterAction::Block, b)
            }
            (Some(a), _) => (FilterAction::Allow, a),
            (None, Some(b)) => (FilterAction::Block, b),
            (None, None) => return None,
        };
        Some(ManualVerdict {
            action,
            domain,
            important: flags.is_important(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(rules: &ManualRules, qname: &str) -> Option<(FilterAction, String)> {
        rules
            .verdict(qname)
            .map(|v| (v.action, v.domain.to_string()))
    }

    const ALLOW: FilterAction = FilterAction::Allow;
    const BLOCK: FilterAction = FilterAction::Block;

    #[test]
    fn rule_syntax_sets_the_reach() {
        let rules = ManualRules::from_text(
            "||wild.com^\n|exact.com^\nplain.com\n0.0.0.0 hosts.com\n*.subs.com\n",
        );
        let cases = [
            ("wild.com", Some(BLOCK)),
            ("a.b.wild.com", Some(BLOCK)),
            ("exact.com", Some(BLOCK)),
            ("a.exact.com", None),
            // A plain domain is exact, as in AdGuard Home and Pi-hole.
            ("plain.com", Some(BLOCK)),
            ("a.plain.com", None),
            ("hosts.com", Some(BLOCK)),
            ("a.hosts.com", None),
            ("subs.com", None),
            ("a.subs.com", Some(BLOCK)),
            ("other.com", None),
        ];
        for (qname, want) in cases {
            assert_eq!(rules.verdict(qname).map(|v| v.action), want, "{qname}");
        }
    }

    #[test]
    fn allow_wins_over_block_unless_the_block_is_important() {
        let rules = ManualRules::from_text(
            "||ads.com^\n@@||ok.ads.com^\n||track.com^$important\n@@||track.com^\n\
             ||both.com^$important\n@@||both.com^$important\n",
        );
        assert_eq!(
            verdict(&rules, "x.ads.com"),
            Some((BLOCK, "ads.com".into()))
        );
        assert_eq!(
            verdict(&rules, "a.ok.ads.com"),
            Some((ALLOW, "ok.ads.com".into()))
        );
        assert_eq!(
            verdict(&rules, "track.com"),
            Some((BLOCK, "track.com".into()))
        );
        assert_eq!(
            verdict(&rules, "both.com"),
            Some((ALLOW, "both.com".into()))
        );
        assert!(rules.verdict("both.com").unwrap().important);
    }

    #[test]
    fn disabled_wrong_and_cancelled_lines_are_not_rules() {
        let rules = ManualRules::from_text(
            "# ||off.com^\n||client.com^$client=10.0.0.1\n192.168.1.5 nas.lan\n\
             /ads[0-9]+/\n||gone.com^\n||gone.com^$badfilter\n! comment\n\n||kept.com^\n",
        );
        for qname in ["off.com", "client.com", "nas.lan", "ads1", "gone.com"] {
            assert_eq!(rules.verdict(qname), None, "{qname}");
        }
        assert_eq!(rules.verdict("kept.com").map(|v| v.action), Some(BLOCK));
        assert_eq!((rules.block_len(), rules.allow_len()), (1, 0));
    }

    /// The owner's 4 Bradesco allows, written by the config cut-over as `@@||x^`: the domains and
    /// every subdomain are allowed, as the stored allowlist did.
    #[test]
    fn owner_bradesco_allows() {
        let rules = ManualRules::from_text(
            "@@||app-measurement.com^\n@@||www.googletagmanager.com^\n\
             @@||js-cdn.dynatrace.com^\n@@||analytics.google.com^\n",
        );
        for qname in [
            "app-measurement.com",
            "region1.app-measurement.com",
            "www.googletagmanager.com",
            "js-cdn.dynatrace.com",
            "analytics.google.com",
        ] {
            assert_eq!(
                rules.verdict(qname).map(|v| v.action),
                Some(ALLOW),
                "{qname}"
            );
        }
        for qname in ["googletagmanager.com", "dynatrace.com", "google.com"] {
            assert_eq!(rules.verdict(qname), None, "{qname}");
        }
    }
}
