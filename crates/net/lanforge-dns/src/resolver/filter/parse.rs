use std::net::IpAddr;
use std::str::FromStr;

use lanforge_types::network::dns::adblock::AdblockSourceFormat;
use serde::{Deserialize, Serialize};

/// Bitflags representing rule match behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct MatchFlags(pub u8);

impl MatchFlags {
    /// Matches the domain itself.
    pub const SELF: u8 = 1 << 0;
    /// Matches all subdomains of the domain.
    pub const SUBDOMAINS: u8 = 1 << 1;
    /// Priority override: wins over standard rules.
    pub const IMPORTANT: u8 = 1 << 2;

    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    #[must_use]
    pub const fn exact() -> Self {
        Self(Self::SELF)
    }

    #[inline]
    #[must_use]
    pub const fn wildcard() -> Self {
        Self(Self::SELF | Self::SUBDOMAINS)
    }

    #[inline]
    #[must_use]
    pub const fn subdomains_only() -> Self {
        Self(Self::SUBDOMAINS)
    }

    #[inline]
    #[must_use]
    pub const fn is_self(self) -> bool {
        (self.0 & Self::SELF) != 0
    }

    #[inline]
    #[must_use]
    pub const fn is_subdomains(self) -> bool {
        (self.0 & Self::SUBDOMAINS) != 0
    }

    #[inline]
    #[must_use]
    pub const fn is_important(self) -> bool {
        (self.0 & Self::IMPORTANT) != 0
    }

    #[inline]
    #[must_use]
    pub const fn with_important(self) -> Self {
        Self(self.0 | Self::IMPORTANT)
    }
}

/// Action to be taken on a matched rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Allow,
    BadFilter,
}

/// A parsed filtering rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParsedRule {
    pub domain: String,
    pub action: RuleAction,
    pub flags: MatchFlags,
}

/// Aggregate statistics collected during parsing of a source list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseStats {
    pub blocks: u64,
    pub exceptions: u64,
    pub important: u64,
    pub badfilter: u64,
    pub unsupported: u64,
    pub unsupported_exceptions: u64,
    pub invalid: u64,
    pub hosts_rewrite_as_block: u64,
}

/// Result of parsing a list source.
pub struct ParseResult {
    pub rules: Vec<ParsedRule>,
    pub detected_format: AdblockSourceFormat,
    pub stats: ParseStats,
    pub unsupported_samples: Vec<String>,
}

/// Detects the list format from headers and early lines.
#[must_use]
pub fn detect_format(content: &str) -> AdblockSourceFormat {
    let mut adblock_hints = 0;
    let mut hosts_hints = 0;
    let mut examined_lines = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Header metadata hints
        if trimmed.starts_with('[') || trimmed.starts_with('#') || trimmed.starts_with('!') {
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("[adblock")
                || lower.contains("syntax: adblock")
                || lower.contains("syntax: adp")
            {
                return AdblockSourceFormat::Adblock;
            }
            if lower.contains("syntax: hosts") {
                return AdblockSourceFormat::Hosts;
            }
            if lower.contains("syntax: wildcard") {
                return AdblockSourceFormat::WildcardDomains;
            }
            if lower.contains("syntax: domains") {
                return AdblockSourceFormat::Domains;
            }
            continue;
        }

        examined_lines += 1;

        if trimmed.starts_with("||") || trimmed.starts_with("@@||") {
            adblock_hints += 1;
        } else if let Some(first_word) = trimmed.split_whitespace().next()
            && IpAddr::from_str(first_word).is_ok()
        {
            hosts_hints += 1;
        }

        if examined_lines >= 500 {
            break;
        }
    }

    if adblock_hints > 0 && adblock_hints >= hosts_hints {
        AdblockSourceFormat::Adblock
    } else if hosts_hints > 0 {
        AdblockSourceFormat::Hosts
    } else {
        AdblockSourceFormat::Domains
    }
}

/// Parses a list source with the specified or detected format.
#[must_use]
pub fn parse_source(content: &str, format: AdblockSourceFormat) -> ParseResult {
    let resolved_format = match format {
        AdblockSourceFormat::Auto => detect_format(content),
        other => other,
    };

    let mut rules = Vec::new();
    let mut stats = ParseStats::default();
    let mut unsupported_samples = Vec::new();

    for line in content.lines() {
        parse_line(
            line,
            resolved_format,
            &mut rules,
            &mut stats,
            &mut unsupported_samples,
        );
    }

    ParseResult {
        rules,
        detected_format: resolved_format,
        stats,
        unsupported_samples,
    }
}

/// Parses a single line based on the source format.
pub fn parse_line(
    line: &str,
    format: AdblockSourceFormat,
    out: &mut Vec<ParsedRule>,
    stats: &mut ParseStats,
    unsupported_samples: &mut Vec<String>,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }

    // Comment lines
    if trimmed.starts_with('#') || trimmed.starts_with('!') || trimmed.starts_with("[Adblock") {
        return;
    }

    // Filter cosmetic / element-hiding rules (not DNS)
    if trimmed.contains("##")
        || trimmed.contains("#?#")
        || trimmed.contains("#$#")
        || trimmed.contains("$$")
    {
        return;
    }

    match format {
        AdblockSourceFormat::Adblock => {
            parse_adblock_line(trimmed, out, stats, unsupported_samples);
        }
        AdblockSourceFormat::Hosts => {
            parse_hosts_line(trimmed, out, stats);
        }
        AdblockSourceFormat::Domains => {
            parse_domains_line(
                trimmed,
                MatchFlags::exact(),
                out,
                stats,
                unsupported_samples,
            );
        }
        AdblockSourceFormat::WildcardDomains => {
            parse_domains_line(
                trimmed,
                MatchFlags::wildcard(),
                out,
                stats,
                unsupported_samples,
            );
        }
        AdblockSourceFormat::Auto => {
            // Auto was resolved before calling, but fallback to adblock if called directly
            parse_adblock_line(trimmed, out, stats, unsupported_samples);
        }
    }
}

/// Parses an Adblock-style rule (`||domain^`, `@@||domain^`, modifiers).
fn parse_adblock_line(
    raw: &str,
    out: &mut Vec<ParsedRule>,
    stats: &mut ParseStats,
    unsupported_samples: &mut Vec<String>,
) {
    let mut s = raw;
    let mut action = RuleAction::Block;

    // Check for exception rule (@@)
    if let Some(rest) = s.strip_prefix("@@") {
        action = RuleAction::Allow;
        s = rest;
    }

    // Check for modifiers after '$'
    let mut is_important = false;
    let mut is_badfilter = false;

    if let Some((rule_part, mod_part)) = s.split_once('$') {
        s = rule_part;
        let mut has_unsupported = false;

        for m in mod_part.split(',') {
            let m_clean = m.trim();
            if m_clean.is_empty() {
                continue;
            }
            if m_clean.eq_ignore_ascii_case("important") {
                is_important = true;
            } else if m_clean.eq_ignore_ascii_case("badfilter") {
                is_badfilter = true;
            } else {
                has_unsupported = true;
            }
        }

        if has_unsupported {
            stats.unsupported += 1;
            if action == RuleAction::Allow {
                stats.unsupported_exceptions += 1;
            }
            if unsupported_samples.len() < 20 {
                unsupported_samples.push(raw.to_string());
            }
            return;
        }
    }

    if is_badfilter {
        action = RuleAction::BadFilter;
    }

    // Determine matching flags
    let (domain_raw, flags) = if let Some(domain_part) = s.strip_prefix("||") {
        let clean = domain_part.strip_suffix('^').unwrap_or(domain_part);
        (clean, MatchFlags::wildcard())
    } else if let Some(domain_part) = s.strip_prefix('|') {
        let clean = domain_part
            .strip_suffix('|')
            .unwrap_or_else(|| domain_part.strip_suffix('^').unwrap_or(domain_part));
        (clean, MatchFlags::exact())
    } else if let Some(domain_part) = s.strip_prefix("*.") {
        let clean = domain_part.strip_suffix('^').unwrap_or(domain_part);
        (clean, MatchFlags::subdomains_only())
    } else if s.starts_with('/') && s.ends_with('/') {
        // Regex rule - unsupported in DNS FST
        stats.unsupported += 1;
        if unsupported_samples.len() < 20 {
            unsupported_samples.push(raw.to_string());
        }
        return;
    } else {
        let clean = s.strip_suffix('^').unwrap_or(s);
        (clean, MatchFlags::wildcard())
    };

    // Wildcards inside domain (e.g. `*` not at prefix) are not supported by simple FST
    if domain_raw.contains('*') {
        stats.unsupported += 1;
        if unsupported_samples.len() < 20 {
            unsupported_samples.push(raw.to_string());
        }
        return;
    }

    if let Some(domain) = sanitize_domain(domain_raw) {
        let final_flags = if is_important {
            flags.with_important()
        } else {
            flags
        };

        match action {
            RuleAction::Block => stats.blocks += 1,
            RuleAction::Allow => stats.exceptions += 1,
            RuleAction::BadFilter => stats.badfilter += 1,
        }
        if is_important {
            stats.important += 1;
        }

        out.push(ParsedRule {
            domain,
            action,
            flags: final_flags,
        });
    } else {
        stats.invalid += 1;
    }
}

/// Parses an /etc/hosts format line: `0.0.0.0 domain1 domain2 # comment`.
fn parse_hosts_line(raw: &str, out: &mut Vec<ParsedRule>, stats: &mut ParseStats) {
    // Strip trailing inline comment
    let line = if let Some((before_comment, _)) = raw.split_once('#') {
        before_comment.trim()
    } else {
        raw
    };

    let mut parts = line.split_whitespace();
    let Some(ip_str) = parts.next() else {
        return;
    };

    let Ok(ip) = IpAddr::from_str(ip_str) else {
        return;
    };

    let is_blocking_ip = match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
    };

    if !is_blocking_ip {
        stats.hosts_rewrite_as_block += 1;
    }

    for domain_raw in parts {
        if let Some(domain) = sanitize_domain(domain_raw) {
            stats.blocks += 1;
            out.push(ParsedRule {
                domain,
                action: RuleAction::Block,
                flags: MatchFlags::exact(),
            });
        } else {
            stats.invalid += 1;
        }
    }
}

/// Parses a domains-only format line.
fn parse_domains_line(
    raw: &str,
    default_flags: MatchFlags,
    out: &mut Vec<ParsedRule>,
    stats: &mut ParseStats,
    unsupported_samples: &mut Vec<String>,
) {
    // Strip trailing inline comment
    let line = if let Some((before_comment, _)) = raw.split_once('#') {
        before_comment.trim()
    } else {
        raw
    };

    if line.is_empty() {
        return;
    }

    // Check for *.domain syntax in domains list
    if let Some(sub) = line.strip_prefix("*.") {
        if let Some(domain) = sanitize_domain(sub) {
            stats.blocks += 1;
            out.push(ParsedRule {
                domain,
                action: RuleAction::Block,
                flags: MatchFlags::subdomains_only(),
            });
        } else {
            stats.invalid += 1;
        }
        return;
    }

    // If it contains adblock markers (e.g. `||`), fallback to adblock parser
    if line.starts_with("||") || line.starts_with("@@") || line.contains('^') {
        parse_adblock_line(line, out, stats, unsupported_samples);
        return;
    }

    if let Some(domain) = sanitize_domain(line) {
        stats.blocks += 1;
        out.push(ParsedRule {
            domain,
            action: RuleAction::Block,
            flags: default_flags,
        });
    } else {
        stats.invalid += 1;
    }
}

/// Normalizes and validates a domain name.
/// Returns `None` if invalid, loopback, or an IP address.
#[must_use]
pub fn sanitize_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }

    let mut label_count = 0usize;
    let mut last_label_all_digits = true;

    for label in domain.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        let mut all_digits = true;
        for &b in bytes {
            if b.is_ascii_digit() {
                continue;
            }
            if b.is_ascii_alphabetic() || b == b'-' || b == b'_' {
                all_digits = false;
            } else {
                return None;
            }
        }
        last_label_all_digits = all_digits;
        label_count += 1;
    }

    if label_count < 2 || last_label_all_digits {
        return None;
    }

    if domain.eq_ignore_ascii_case("localhost.localdomain") {
        return None;
    }

    Some(domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adblock_rules() {
        let input = r#"
! Title: Test List
||example.com^
@@||allowed.com^
||important-ad.com^$important
||bad-filter.com^$badfilter
||unsupported.com^$dnstype=AAAA
||client-only.com^$client=192.168.1.5
*.subonly.com
|exact.com^
"#;
        let res = parse_source(input, AdblockSourceFormat::Adblock);
        assert_eq!(res.detected_format, AdblockSourceFormat::Adblock);

        assert_eq!(res.stats.blocks, 4); // example.com, important-ad.com, subonly.com, exact.com
        assert_eq!(res.stats.exceptions, 1); // allowed.com
        assert_eq!(res.stats.important, 1);
        assert_eq!(res.stats.badfilter, 1);
        assert_eq!(res.stats.unsupported, 2); // dnstype, client

        let find = |d: &str| res.rules.iter().find(|r| r.domain == d).cloned();

        let ex = find("example.com").unwrap();
        assert_eq!(ex.action, RuleAction::Block);
        assert_eq!(ex.flags, MatchFlags::wildcard());

        let allow = find("allowed.com").unwrap();
        assert_eq!(allow.action, RuleAction::Allow);
        assert_eq!(allow.flags, MatchFlags::wildcard());

        let imp = find("important-ad.com").unwrap();
        assert!(imp.flags.is_important());

        let bad = find("bad-filter.com").unwrap();
        assert_eq!(bad.action, RuleAction::BadFilter);

        let sub = find("subonly.com").unwrap();
        assert_eq!(sub.flags, MatchFlags::subdomains_only());

        let exact = find("exact.com").unwrap();
        assert_eq!(exact.flags, MatchFlags::exact());
    }

    #[test]
    fn test_hosts_rules() {
        let input = r#"
# Hosts file test
127.0.0.1 localhost
0.0.0.0 ads.example.com tracking.example.com # inline comment
1.2.3.4 sinkhole.com
0.0.0.0 127.0.0.1
"#;
        let res = parse_source(input, AdblockSourceFormat::Hosts);
        assert_eq!(res.detected_format, AdblockSourceFormat::Hosts);
        assert_eq!(res.stats.blocks, 3); // ads.example.com, tracking.example.com, sinkhole.com
        assert_eq!(res.stats.hosts_rewrite_as_block, 1); // sinkhole.com

        assert!(
            res.rules
                .iter()
                .any(|r| r.domain == "ads.example.com" && r.flags == MatchFlags::exact())
        );
        assert!(
            res.rules
                .iter()
                .any(|r| r.domain == "tracking.example.com" && r.flags == MatchFlags::exact())
        );
        assert!(
            res.rules
                .iter()
                .any(|r| r.domain == "sinkhole.com" && r.flags == MatchFlags::exact())
        );
        // localhost and 127.0.0.1 should not be present
        assert!(!res.rules.iter().any(|r| r.domain == "localhost"));
        assert!(!res.rules.iter().any(|r| r.domain == "127.0.0.1"));
    }

    #[test]
    fn test_domains_and_wildcard_domains() {
        let input = r#"
# Simple domains
domain1.com
domain2.com # with comment
*.sub.domain3.com
||adblock-in-domains.com^
"#;
        let res_dom = parse_source(input, AdblockSourceFormat::Domains);
        assert_eq!(
            res_dom
                .rules
                .iter()
                .find(|r| r.domain == "domain1.com")
                .unwrap()
                .flags,
            MatchFlags::exact()
        );
        assert_eq!(
            res_dom
                .rules
                .iter()
                .find(|r| r.domain == "sub.domain3.com")
                .unwrap()
                .flags,
            MatchFlags::subdomains_only()
        );

        let res_wild = parse_source(input, AdblockSourceFormat::WildcardDomains);
        assert_eq!(
            res_wild
                .rules
                .iter()
                .find(|r| r.domain == "domain1.com")
                .unwrap()
                .flags,
            MatchFlags::wildcard()
        );
    }

    #[test]
    fn test_format_auto_detection() {
        let adblock_input = "[Adblock Plus 2.0]\n||ads.com^\n||track.com^\n";
        assert_eq!(detect_format(adblock_input), AdblockSourceFormat::Adblock);

        let hosts_input = "# Title: Hosts\n0.0.0.0 ads.com\n0.0.0.0 track.com\n";
        assert_eq!(detect_format(hosts_input), AdblockSourceFormat::Hosts);

        let domains_input = "# Just domains\nads.com\ntrack.com\n";
        assert_eq!(detect_format(domains_input), AdblockSourceFormat::Domains);
    }

    #[test]
    fn test_sanitize_domain() {
        assert_eq!(
            sanitize_domain("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            sanitize_domain("EXAMPLE.COM."),
            Some("example.com".to_string())
        );
        assert_eq!(
            sanitize_domain("sub_domain-1.example.com"),
            Some("sub_domain-1.example.com".to_string())
        );
        assert_eq!(sanitize_domain("localhost"), None);
        assert_eq!(sanitize_domain("127.0.0.1"), None);
        assert_eq!(sanitize_domain("::1"), None);
        assert_eq!(sanitize_domain("singleword"), None);
        assert_eq!(sanitize_domain("bad!char.com"), None);
    }
}
