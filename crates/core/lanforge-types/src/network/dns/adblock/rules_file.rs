//! Local rules files (`adblock/*.rules`): manual block (`||x^`) and allow (`@@||x^`) rules.
//!
//! One rule per line. The text is the source of truth: lines are borrowed from it, edits return the
//! new text, and comments, order and line endings are kept. A rule is disabled by commenting it out
//! (`# ||x^`).

use std::fmt::Display;

use super::syntax::{ParseStats, ParsedRule};

/// Why a rules-file line is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesLineIssue {
    /// Regex rules, or modifiers other than `$important` / `$badfilter`.
    Unsupported,
    /// A hosts line with a real address: that is a rewrite, not a block.
    HostsAddress,
    /// Not a DNS domain rule (bad domain, cosmetic filter, ...).
    Invalid,
}

impl Display for RulesLineIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "unsupported syntax (regex, or a modifier other than $important)",
            Self::HostsAddress => "hosts line with a real address: use [dns.rewrites] instead",
            Self::Invalid => "not a DNS domain rule",
        })
    }
}

/// What a rules-file line holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesLineKind {
    Blank,
    Comment,
    /// A rule, identified by the content hash of its text; `enabled = false` when commented out.
    Rule {
        id: i64,
        enabled: bool,
    },
    /// Ignored line, reported as a config issue.
    Ignored(RulesLineIssue),
}

/// One line of a rules file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesLine<'a> {
    /// 1-based line number.
    pub number: usize,
    /// The rule text without the disabling `#`; the trimmed line for other kinds.
    pub rule: &'a str,
    pub kind: RulesLineKind,
}

/// A rules file's text.
#[derive(Debug, Clone, Copy)]
pub struct RulesFile<'a> {
    text: &'a str,
}

impl<'a> RulesFile<'a> {
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self { text }
    }

    /// Content hash of a rule's text (case-insensitive), the rule id used by the API.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn rule_id(rule: &str) -> i64 {
        let mut h = 0xcbf2_9ce4_8422_2325_u64;
        for &b in rule.trim().as_bytes() {
            h ^= u64::from(b.to_ascii_lowercase());
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        (h & 0x7FFF_FFFF_FFFF_FFFF) as i64
    }

    /// Visits every line with the rules it holds (empty unless the line is a rule, enabled or not).
    /// One parse per line and one buffer per call: the engine and the API share this path.
    pub fn for_each_line(&self, mut f: impl FnMut(RulesLine<'a>, &[ParsedRule])) {
        let mut rules = Vec::new();
        let mut stats = ParseStats::default();
        let mut samples = Vec::new();
        for (idx, raw) in self.text.lines().enumerate() {
            rules.clear();
            let trimmed = raw.trim();
            let (rule, kind) = if trimmed.is_empty() {
                (trimmed, RulesLineKind::Blank)
            } else if trimmed.starts_with(['!', '[']) {
                (trimmed, RulesLineKind::Comment)
            } else if let Some(rest) = trimmed.strip_prefix('#') {
                let rest = rest.trim_start();
                if !rest.is_empty()
                    && !rest.starts_with(['#', '!'])
                    && Self::parse(rest, &mut rules, &mut stats, &mut samples).is_none()
                {
                    let id = Self::rule_id(rest);
                    (rest, RulesLineKind::Rule { id, enabled: false })
                } else {
                    rules.clear();
                    (trimmed, RulesLineKind::Comment)
                }
            } else if let Some(issue) = Self::parse(trimmed, &mut rules, &mut stats, &mut samples) {
                rules.clear();
                (trimmed, RulesLineKind::Ignored(issue))
            } else {
                let id = Self::rule_id(trimmed);
                (trimmed, RulesLineKind::Rule { id, enabled: true })
            };
            f(
                RulesLine {
                    number: idx + 1,
                    rule,
                    kind,
                },
                &rules,
            );
        }
    }

    /// Parses one rule into `out`; `Some(issue)` when the line is not a clean rule.
    fn parse(
        rule: &str,
        out: &mut Vec<ParsedRule>,
        stats: &mut ParseStats,
        samples: &mut Vec<String>,
    ) -> Option<RulesLineIssue> {
        *stats = ParseStats::default();
        samples.clear();
        ParsedRule::parse_rules_line(rule, out, stats, samples);
        if stats.unsupported > 0 {
            Some(RulesLineIssue::Unsupported)
        } else if stats.hosts_rewrite_as_block > 0 {
            Some(RulesLineIssue::HostsAddress)
        } else if stats.invalid > 0 || out.is_empty() {
            Some(RulesLineIssue::Invalid)
        } else {
            None
        }
    }

    /// The text with `rule` active: appended, or uncommented if present but disabled.
    /// `Ok(None)` when it is already active.
    ///
    /// # Errors
    /// The issue when `rule` is not a single clean rule.
    pub fn with_rule(&self, rule: &str) -> Result<Option<String>, RulesLineIssue> {
        let rule = rule.trim();
        if rule.is_empty() || rule.contains('\n') || rule.starts_with(['#', '!', '[']) {
            return Err(RulesLineIssue::Invalid);
        }
        if let Some(issue) = Self::parse(
            rule,
            &mut Vec::new(),
            &mut ParseStats::default(),
            &mut Vec::new(),
        ) {
            return Err(issue);
        }
        let id = Self::rule_id(rule);
        let mut state = None;
        self.for_each_line(|line, _| {
            if let RulesLineKind::Rule {
                id: line_id,
                enabled,
            } = line.kind
                && line_id == id
            {
                state = Some(state.unwrap_or(false) || enabled);
            }
        });
        Ok(match state {
            Some(true) => None,
            Some(false) => self.with_rule_enabled(id, true),
            None => {
                let mut out = String::with_capacity(self.text.len() + rule.len() + 1);
                out.push_str(self.text);
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(rule);
                out.push('\n');
                Some(out)
            }
        })
    }

    /// The text without the rule `id` (every copy, enabled or not); `None` when absent.
    #[must_use]
    pub fn without_rule(&self, id: i64) -> Option<String> {
        self.rewrite(id, None)
    }

    /// The text with the rule `id` enabled or commented out; `None` when absent or unchanged.
    #[must_use]
    pub fn with_rule_enabled(&self, id: i64, enabled: bool) -> Option<String> {
        self.rewrite(id, Some(enabled))
    }

    /// Rebuilds the text with every line of rule `id` set to `target` (`None` drops it).
    /// Returns `None` when no line changed.
    fn rewrite(&self, id: i64, target: Option<bool>) -> Option<String> {
        let mut out = String::with_capacity(self.text.len());
        let mut changed = false;
        let mut raw_lines = self.text.split_inclusive('\n');
        self.for_each_line(|line, _| {
            let raw = raw_lines.next().unwrap_or_default();
            let RulesLineKind::Rule {
                id: line_id,
                enabled,
            } = line.kind
            else {
                out.push_str(raw);
                return;
            };
            if line_id != id || target == Some(enabled) {
                out.push_str(raw);
                return;
            }
            changed = true;
            if let Some(enable) = target {
                if !enable {
                    out.push_str("# ");
                }
                out.push_str(line.rule);
                out.push_str(&raw[raw.trim_end_matches(['\r', '\n']).len()..]);
            }
        });
        changed.then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::dns::adblock::syntax::{MatchFlags, RuleAction};

    /// Kind and rules of every line.
    fn read(text: &str) -> Vec<(RulesLineKind, Vec<ParsedRule>)> {
        let mut lines = Vec::new();
        RulesFile::new(text).for_each_line(|line, rules| lines.push((line.kind, rules.to_vec())));
        lines
    }

    fn rule(domain: &str, action: RuleAction, flags: MatchFlags) -> ParsedRule {
        ParsedRule {
            domain: domain.to_owned(),
            action,
            flags,
        }
    }

    fn id(rule: &str, enabled: bool) -> RulesLineKind {
        RulesLineKind::Rule {
            id: RulesFile::rule_id(rule),
            enabled,
        }
    }

    /// The owner's 4 allowlist entries, as the cut-over writes them.
    const OWNER_GLOBAL_RULES: &str = "\
! Global manual rules (Bradesco Android app)
@@||app-measurement.com^
@@||www.googletagmanager.com^
@@||js-cdn.dynatrace.com^
@@||analytics.google.com^
";

    #[test]
    fn owner_allowlist_reads_as_four_allow_rules_with_subdomains() {
        let lines = read(OWNER_GLOBAL_RULES);
        let allow = |d: &str| vec![rule(d, RuleAction::Allow, MatchFlags::wildcard())];
        assert_eq!(
            lines,
            vec![
                (RulesLineKind::Comment, vec![]),
                (
                    id("@@||app-measurement.com^", true),
                    allow("app-measurement.com")
                ),
                (
                    id("@@||www.googletagmanager.com^", true),
                    allow("www.googletagmanager.com")
                ),
                (
                    id("@@||js-cdn.dynatrace.com^", true),
                    allow("js-cdn.dynatrace.com")
                ),
                (
                    id("@@||analytics.google.com^", true),
                    allow("analytics.google.com")
                ),
            ]
        );
    }

    #[test]
    fn each_line_is_read_in_its_own_format() {
        let text = "\
\n\
# prose comment\n\
# ||disabled.com^\n\
example.com\n\
*.sub.com\n\
0.0.0.0 a.com b.com\n\
||important.com^$important\n\
/ads[0-9]+/\n\
||client.com^$client=192.168.1.5\n\
bad!domain.com\n\
1.2.3.4 rewrite.com\n\
127.0.0.1 localhost\n\
site.com##.banner\n\
";
        let block = |d: &str, f| vec![rule(d, RuleAction::Block, f)];
        assert_eq!(
            read(text),
            vec![
                (RulesLineKind::Blank, vec![]),
                (RulesLineKind::Comment, vec![]),
                (
                    id("||disabled.com^", false),
                    block("disabled.com", MatchFlags::wildcard())
                ),
                (
                    id("example.com", true),
                    block("example.com", MatchFlags::exact())
                ),
                (
                    id("*.sub.com", true),
                    block("sub.com", MatchFlags::subdomains_only())
                ),
                (
                    id("0.0.0.0 a.com b.com", true),
                    vec![
                        rule("a.com", RuleAction::Block, MatchFlags::exact()),
                        rule("b.com", RuleAction::Block, MatchFlags::exact()),
                    ]
                ),
                (
                    id("||important.com^$important", true),
                    block("important.com", MatchFlags::wildcard().with_important())
                ),
                (RulesLineKind::Ignored(RulesLineIssue::Unsupported), vec![]),
                (RulesLineKind::Ignored(RulesLineIssue::Unsupported), vec![]),
                (RulesLineKind::Ignored(RulesLineIssue::Invalid), vec![]),
                (RulesLineKind::Ignored(RulesLineIssue::HostsAddress), vec![]),
                (RulesLineKind::Ignored(RulesLineIssue::Invalid), vec![]),
                (RulesLineKind::Ignored(RulesLineIssue::Invalid), vec![]),
            ]
        );
    }

    #[test]
    fn line_numbers_and_rule_text_point_at_the_file() {
        let mut seen = Vec::new();
        RulesFile::new("! c\n\n#   ||x.com^  \n  bad!x.com\n")
            .for_each_line(|line, _| seen.push((line.number, line.rule)));
        assert_eq!(
            seen,
            vec![(1, "! c"), (2, ""), (3, "||x.com^"), (4, "bad!x.com")]
        );
    }

    #[test]
    fn disabling_keeps_the_id_and_case_does_not_change_it() {
        assert_eq!(
            RulesFile::rule_id("||X.com^"),
            RulesFile::rule_id(" ||x.com^ ")
        );
        let file = RulesFile::new("||x.com^\n");
        let disabled = file
            .with_rule_enabled(RulesFile::rule_id("||x.com^"), false)
            .unwrap();
        assert_eq!(disabled, "# ||x.com^\n");
        assert_eq!(read(&disabled)[0].0, id("||x.com^", false));
        let enabled = RulesFile::new(&disabled)
            .with_rule_enabled(RulesFile::rule_id("||x.com^"), true)
            .unwrap();
        assert_eq!(enabled, "||x.com^\n");
        assert_eq!(
            RulesFile::new(&enabled).with_rule_enabled(RulesFile::rule_id("||x.com^"), true),
            None,
            "already enabled: unchanged"
        );
    }

    #[test]
    fn setting_the_state_a_rule_already_has_never_drops_it() {
        let id = RulesFile::rule_id("||x.com^");
        assert_eq!(
            RulesFile::new("# ||x.com^\n").with_rule_enabled(id, false),
            None
        );
        assert_eq!(
            RulesFile::new("||x.com^\n").with_rule_enabled(id, true),
            None
        );
        assert_eq!(
            RulesFile::new("||x.com^\n# ||x.com^\n")
                .with_rule_enabled(id, false)
                .as_deref(),
            Some("# ||x.com^\n# ||x.com^\n"),
            "only the copy that differs changes"
        );
    }

    #[test]
    fn adding_appends_once_and_reenables_a_disabled_copy() {
        let file = RulesFile::new("! head\n||a.com^");
        assert_eq!(
            file.with_rule(" @@||b.com^ ").unwrap().as_deref(),
            Some("! head\n||a.com^\n@@||b.com^\n")
        );
        assert_eq!(file.with_rule("||a.com^"), Ok(None));
        assert_eq!(
            RulesFile::new("# ||a.com^\r\n! tail\r\n")
                .with_rule("||a.com^")
                .unwrap()
                .as_deref(),
            Some("||a.com^\r\n! tail\r\n")
        );
        assert_eq!(
            RulesFile::new("").with_rule("x.com").unwrap().as_deref(),
            Some("x.com\n")
        );
    }

    #[test]
    fn adding_refuses_what_the_file_would_ignore() {
        let file = RulesFile::new("");
        assert_eq!(file.with_rule("/re/"), Err(RulesLineIssue::Unsupported));
        assert_eq!(
            file.with_rule("1.2.3.4 x.com"),
            Err(RulesLineIssue::HostsAddress)
        );
        assert_eq!(file.with_rule("bad!x.com"), Err(RulesLineIssue::Invalid));
        assert_eq!(file.with_rule("# ||x.com^"), Err(RulesLineIssue::Invalid));
        assert_eq!(
            file.with_rule("||a.com^\n||b.com^"),
            Err(RulesLineIssue::Invalid)
        );
        assert_eq!(file.with_rule("  "), Err(RulesLineIssue::Invalid));
    }

    #[test]
    fn removing_drops_every_copy_and_keeps_the_rest_byte_for_byte() {
        let text = "! keep me\r\n||a.com^\r\n# ||a.com^\r\n\r\n||b.com^";
        let out = RulesFile::new(text)
            .without_rule(RulesFile::rule_id("||a.com^"))
            .unwrap();
        assert_eq!(out, "! keep me\r\n\r\n||b.com^");
        assert_eq!(
            RulesFile::new(&out).without_rule(RulesFile::rule_id("||a.com^")),
            None
        );
    }
}
