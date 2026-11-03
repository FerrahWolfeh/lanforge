//! Local rules files (`adblock/*.rules`): manual block (`||x^`) and allow (`@@||x^`) rules.
//!
//! One rule per line. The text is the source of truth: lines are borrowed from it, edits return the
//! new text, and comments, order and line endings are kept. A rule is disabled by commenting it out
//! (`# ||x^`).

use std::collections::{HashMap, HashSet};
use std::fmt::Display;

use serde::{Deserialize, Serialize};

use super::syntax::{ParseStats, ParsedRule, RuleAction};
use super::{AdblockRuleAction, AdblockRuleEntry};

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

/// What a bulk import did: the file is written once with every accepted line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesImport {
    /// Rules appended, or re-enabled where they were commented out.
    pub added: usize,
    /// Rules already active, or repeated in the pasted text.
    pub unchanged: usize,
    /// Rules skipped because their opposite is already there (a pasted block never undoes an
    /// allow, nor the reverse): the existing rule is kept.
    pub conflicts: usize,
    /// Every rejected line; only the first [`RulesImport::REJECTED_SHOWN`] are listed.
    pub rejected_total: usize,
    pub rejected: Vec<RejectedRuleLine>,
    /// `false` when the change applies in memory only (the configuration is read-only or not
    /// set); set by the caller that writes the file.
    pub saved: bool,
}

/// A pasted line that is not a rule the DNS can apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedRuleLine {
    /// 1-based line of the pasted text.
    pub line: usize,
    pub text: String,
    pub reason: String,
}

impl RulesImport {
    pub const REJECTED_SHOWN: usize = 50;

    fn reject(&mut self, line: usize, text: &str, issue: RulesLineIssue) {
        self.rejected_total += 1;
        if self.rejected.len() < Self::REJECTED_SHOWN {
            self.rejected.push(RejectedRuleLine {
                line,
                text: text.to_string(),
                reason: issue.to_string(),
            });
        }
    }
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
        self.rewrite_each(|line_id| (line_id == id).then_some(target))
    }

    /// Rebuilds the text with each rule line set to `target(id)`: `None` keeps the line,
    /// `Some(None)` drops it, `Some(Some(enabled))` enables or comments it out.
    /// Returns `None` when no line changed.
    fn rewrite_each(&self, target: impl Fn(i64) -> Option<Option<bool>>) -> Option<String> {
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
            let Some(target) = target(line_id).filter(|t| *t != Some(enabled)) else {
                out.push_str(raw);
                return;
            };
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

    /// The text with every rule of `pasted` active: a bare domain becomes `||d^` (`@@||d^` when
    /// `action` allows) and a line starting with `@@` always allows. Unlike a single add, a rule
    /// whose opposite is already there (in the file or earlier in the paste) is skipped as a
    /// conflict: a pasted list never undoes an exception. Blank and comment lines are skipped;
    /// lines that are not clean rules are rejected and reported. One pass over the file, one
    /// rewrite.
    #[must_use]
    pub fn with_rules_imported(
        &self,
        pasted: &str,
        action: AdblockRuleAction,
    ) -> (Option<String>, RulesImport) {
        // Rule id -> enabled, of the file's rules and the ones the paste adds.
        let mut present: HashMap<i64, bool> = HashMap::new();
        self.for_each_line(|line, _| {
            if let RulesLineKind::Rule { id, enabled } = line.kind {
                *present.entry(id).or_default() |= enabled;
            }
        });
        let mut enable = HashSet::new();
        let mut appended = String::new();
        let mut report = RulesImport::default();
        let (mut rules, mut stats, mut samples) = (Vec::new(), ParseStats::default(), Vec::new());

        for (idx, raw) in pasted.lines().enumerate() {
            let text = raw.trim();
            if text.is_empty() || text.starts_with(['#', '!', '[']) {
                continue;
            }
            let line_action = if text.starts_with("@@") {
                AdblockRuleAction::Allow
            } else {
                action
            };
            let line = AdblockRuleEntry::rule_line(text, line_action);
            if let Some(issue) = Self::parse(&line, &mut rules, &mut stats, &mut samples) {
                report.reject(idx + 1, text, issue);
                continue;
            }
            let opposite = Self::rule_id(
                &line
                    .strip_prefix("@@")
                    .map_or_else(|| format!("@@{line}"), str::to_string),
            );
            if present.get(&opposite) == Some(&true) {
                report.conflicts += 1;
                continue;
            }
            let id = Self::rule_id(&line);
            match present.insert(id, true) {
                Some(true) => report.unchanged += 1,
                Some(false) => {
                    enable.insert(id);
                    report.added += 1;
                }
                None => {
                    appended.push_str(&line);
                    appended.push('\n');
                    report.added += 1;
                }
            }
        }

        if report.added == 0 {
            return (None, report);
        }
        let mut out = if enable.is_empty() {
            None
        } else {
            self.rewrite_each(|id| enable.contains(&id).then_some(Some(true)))
        }
        .unwrap_or_else(|| self.text.to_string());
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&appended);
        (Some(out), report)
    }

    /// The rules, enabled or not, in file order as the API lists them: the id, the rule text as
    /// written (`domain`) and its action (allow when it allows).
    #[must_use]
    pub fn rule_entries(&self) -> Vec<AdblockRuleEntry> {
        let mut entries = Vec::new();
        self.for_each_line(|line, rules| {
            if let RulesLineKind::Rule { id, enabled } = line.kind {
                let allow = rules.iter().any(|r| r.action == RuleAction::Allow);
                entries.push(AdblockRuleEntry {
                    id: Some(id),
                    name: None,
                    domain: line.rule.to_string(),
                    action: if allow {
                        AdblockRuleAction::Allow
                    } else {
                        AdblockRuleAction::Block
                    },
                    enabled,
                });
            }
        });
        entries
    }

    /// The ignored lines, as config issues of the file at `at`.
    #[must_use]
    pub fn issues(&self, at: &str) -> Vec<String> {
        let mut issues = Vec::new();
        self.for_each_line(|line, _| {
            if let RulesLineKind::Ignored(issue) = line.kind {
                issues.push(format!(
                    "{at} line {}: \"{}\": {issue}; ignored",
                    line.number, line.rule
                ));
            }
        });
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::dns::adblock::syntax::MatchFlags;

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
    fn rules_are_listed_with_their_text_action_and_state() {
        let text = "! c\n@@||ok.com^\n# ||off.com^\n0.0.0.0 a.com\n/re/\n";
        let entry = |rule: &str, action, enabled| AdblockRuleEntry {
            id: Some(RulesFile::rule_id(rule)),
            name: None,
            domain: rule.into(),
            action,
            enabled,
        };
        assert_eq!(
            RulesFile::new(text).rule_entries(),
            vec![
                entry("@@||ok.com^", AdblockRuleAction::Allow, true),
                entry("||off.com^", AdblockRuleAction::Block, false),
                entry("0.0.0.0 a.com", AdblockRuleAction::Block, true),
            ]
        );
        assert_eq!(
            RulesFile::new(text).issues("adblock/global.rules"),
            vec![
                "adblock/global.rules line 5: \"/re/\": unsupported syntax (regex, or a modifier other than $important); ignored"
                    .to_string()
            ]
        );
    }

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

    /// A pasted list: comments and blanks skipped, bare names and hosts lines kept as rules,
    /// `@@` lines allow, junk rejected with its line number, repeats counted once.
    #[test]
    fn importing_a_pasted_list_writes_every_rule_once() {
        let file = "! mine\n||old.com^\n# ||off.com^\n";
        let pasted = "# Title: some list\n\n! comment\nads.example\n||track.example^\n\
                      0.0.0.0 pixel.example\n@@||cdn.example^\nADS.example.\n/re/\n\
                      ||old.com^\noff.com\n1.2.3.4 x.com\n";
        let (text, report) =
            RulesFile::new(file).with_rules_imported(pasted, AdblockRuleAction::Block);
        assert_eq!(
            text.as_deref(),
            Some(
                "! mine\n||old.com^\n||off.com^\n||ads.example^\n||track.example^\n\
                 0.0.0.0 pixel.example\n@@||cdn.example^\n"
            )
        );
        assert_eq!((report.added, report.unchanged), (5, 2));
        assert_eq!(report.rejected_total, 2);
        assert_eq!(
            report
                .rejected
                .iter()
                .map(|r| (r.line, r.text.as_str()))
                .collect::<Vec<_>>(),
            [(9, "/re/"), (12, "1.2.3.4 x.com")]
        );
    }

    /// A paste never undoes the opposite rule, in the file or earlier in the paste: the
    /// owner's Bradesco allow survives a blocklist that names the same domain.
    #[test]
    fn importing_keeps_the_opposite_rule() {
        let file = "@@||bank.example^\n# ||off.example^\n";
        let pasted = "bank.example\nshop.example\n@@shop.example\n@@off.example\n";
        let (text, report) =
            RulesFile::new(file).with_rules_imported(pasted, AdblockRuleAction::Block);
        assert_eq!(
            text.as_deref(),
            Some("@@||bank.example^\n# ||off.example^\n||shop.example^\n@@||off.example^\n")
        );
        assert_eq!(
            (report.added, report.unchanged, report.conflicts),
            (2, 0, 2)
        );
    }

    #[test]
    fn importing_what_is_already_there_changes_nothing() {
        let file = "||a.com^\n@@||b.com^";
        let (text, report) = RulesFile::new(file)
            .with_rules_imported("a.com\n@@b.com\n# x\n", AdblockRuleAction::Block);
        assert_eq!(text, None);
        assert_eq!(
            (report.added, report.unchanged, report.rejected_total),
            (0, 2, 0)
        );
    }

    #[test]
    fn importing_lists_only_the_first_rejected_lines() {
        let pasted = "bad!x\n".repeat(RulesImport::REJECTED_SHOWN + 10);
        let (text, report) =
            RulesFile::new("").with_rules_imported(&pasted, AdblockRuleAction::Block);
        assert_eq!(text, None);
        assert_eq!(report.rejected_total, RulesImport::REJECTED_SHOWN + 10);
        assert_eq!(report.rejected.len(), RulesImport::REJECTED_SHOWN);
    }
}
