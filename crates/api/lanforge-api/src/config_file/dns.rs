//! `[dns]`, in its own file form: the DNS server settings that live in `lanforge.toml` (listen,
//! upstreams, reverse resolvers, rewrites). The query log, cache and TTL knobs, DoT/DoQ and the
//! device visibility threshold are dynamic and stay out of the file.
//!
//! Not wired in yet: `ConfigFile.dns` is still `sections::DnsFile` until the DNS cut-over.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::{DnsRecordType, DnsReverseResolver, IpSubnet, ListenConfig};
use serde::de::Deserializer;
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use super::sections::named_tables;

const fn default_true() -> bool {
    true
}

fn default_upstream_mode() -> String {
    UpstreamMode::default().to_string()
}

/// The DNS settings `[dns]` describes, as the daemon runs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    pub enabled: bool,
    /// `None` = the daemon's built-in `[::]:53`.
    pub listen: Option<ListenConfig>,
    pub upstream_mode: UpstreamMode,
    /// In order: the order is the one the sequential mode tries.
    pub upstreams: Vec<NamedUpstream>,
    pub reverse: Vec<DnsReverseResolver>,
    /// In order: the first rule that answers a query wins.
    pub rewrites: Vec<RewriteRule>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: None,
            upstream_mode: UpstreamMode::default(),
            upstreams: Vec::new(),
            reverse: Vec::new(),
            rewrites: Vec::new(),
        }
    }
}

/// An upstream resolver and the name of the group it is listed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedUpstream {
    pub name: String,
    pub target: UpstreamTarget,
}

/// `[dns]` as written in the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// `sequential`, `parallel`, `fastest` or `roundrobin`.
    #[serde(default = "default_upstream_mode")]
    pub upstream_mode: String,
    /// `[dns.upstreams.<name>]`, in file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub upstreams: Vec<(String, DnsUpstreamFile)>,
    /// `[dns.reverse]`: `"<subnet>" = "<resolver>"`, in file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub reverse: Vec<(String, String)>,
    /// `[dns.rewrites]`: `"<domain>" = <answer> | [<answer>, ...]`, in file order.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "rewrites_in_order"
    )]
    pub rewrites: Vec<(String, DnsRewriteValue)>,
}

impl Default for DnsFile {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: None,
            upstream_mode: default_upstream_mode(),
            upstreams: Vec::new(),
            reverse: Vec::new(),
            rewrites: Vec::new(),
        }
    }
}

/// A named group of upstream resolvers. `domain` makes the whole group a conditional forwarder;
/// one address can also carry its own (`udp://10.0.0.1:53#corp`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsUpstreamFile {
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// The answers of one rewritten domain: one item, or a list tried in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRewriteValue(pub Vec<DnsRewriteItem>);

/// One answer of a rewritten domain. An entry that is neither a string nor a valid table is
/// kept as written (`Invalid`): it is reported and not served, and never fails the section.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRewriteItem {
    /// `"192.168.1.10"`, `"fd00::10"`, `"alias.lan"`, `"dev:pixie"` or `"dev:pixie|192.168.1.50"`.
    Answer(String),
    /// `{ answer = "dev:pixie", rtype = "A", fallback = ["192.168.1.50", "fd00::50"] }`.
    Detailed(DnsRewriteTable),
    Invalid(toml::Value),
}

// `toml::Value` is only `PartialEq` because of floats; a rewrite never holds a NaN.
impl Eq for DnsRewriteItem {}

/// The table form of a rewrite answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRewriteTable {
    pub answer: String,
    /// `A`, `AAAA` or `CNAME`: the only query type the rule answers. Absent: inferred from the
    /// answer (`dev:` answers both A and AAAA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtype: Option<String>,
    /// For a `dev:` answer: what to answer while the device has no address of that family —
    /// at most one IPv4 and one IPv6, or one name (CNAME).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<String>,
}

impl Serialize for DnsRewriteItem {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Answer(text) => serializer.serialize_str(text),
            Self::Detailed(table) => table.serialize(serializer),
            Self::Invalid(value) => value.serialize(serializer),
        }
    }
}

impl DnsRewriteItem {
    fn from_value(value: toml::Value) -> Self {
        match value {
            toml::Value::String(text) => Self::Answer(text),
            toml::Value::Table(_) => DnsRewriteTable::deserialize(value.clone())
                .map_or(Self::Invalid(value), Self::Detailed),
            other => Self::Invalid(other),
        }
    }
}

impl Serialize for DnsRewriteValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let [one] = self.0.as_slice() {
            return one.serialize(serializer);
        }
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for item in &self.0 {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

impl DnsRewriteValue {
    /// Whether this value can only be written as a table (`[dns.rewrites."<domain>"]`).
    fn is_tabular(&self) -> bool {
        !self.0.is_empty()
            && self.0.iter().all(|item| {
                matches!(
                    item,
                    DnsRewriteItem::Detailed(_) | DnsRewriteItem::Invalid(toml::Value::Table(_))
                )
            })
    }
}

/// A rewrite value written in table form: `"x"` as `{ answer = "x" }`.
struct Tabular<'a>(&'a DnsRewriteValue);

struct TabularItem<'a>(&'a DnsRewriteItem);

impl Serialize for TabularItem<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            DnsRewriteItem::Answer(text) => DnsRewriteTable {
                answer: text.clone(),
                rtype: None,
                fallback: Vec::new(),
            }
            .serialize(serializer),
            other => other.serialize(serializer),
        }
    }
}

impl Serialize for Tabular<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let [one] = self.0.0.as_slice() {
            return TabularItem(one).serialize(serializer);
        }
        let mut seq = serializer.serialize_seq(Some(self.0.0.len()))?;
        for item in &self.0.0 {
            seq.serialize_element(&TabularItem(item))?;
        }
        seq.end()
    }
}

/// `[dns.rewrites]` in its order, which is the order rules are tried in. The TOML writer puts
/// plain values before tables, so once one rewrite needs a table every later one is written as a
/// table too (`"x" = "a"` as `[dns.rewrites."x"] answer = "a"`), keeping the order.
mod rewrites_in_order {
    use serde::ser::{SerializeMap, Serializer};

    use super::{DnsRewriteValue, Tabular};

    pub use super::named_tables::deserialize;

    pub fn serialize<S: Serializer>(
        entries: &[(String, DnsRewriteValue)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        let mut tabular = false;
        for (domain, value) in entries {
            tabular |= value.is_tabular();
            if tabular {
                map.serialize_entry(domain, &Tabular(value))?;
            } else {
                map.serialize_entry(domain, value)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for DnsRewriteValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(match toml::Value::deserialize(deserializer)? {
            toml::Value::Array(items) => {
                items.into_iter().map(DnsRewriteItem::from_value).collect()
            }
            one => vec![DnsRewriteItem::from_value(one)],
        }))
    }
}

/// The record type a rule of this answer has when the file does not say.
const fn inferred_rtype(answer: &RewriteAnswer) -> DnsRecordType {
    match answer {
        RewriteAnswer::A(_) => DnsRecordType::A,
        RewriteAnswer::Aaaa(_) => DnsRecordType::AAAA,
        RewriteAnswer::Cname(_) => DnsRecordType::CNAME,
        RewriteAnswer::Device { .. } => DnsRecordType::Device,
    }
}

/// A host name a CNAME may point at: dot-separated labels of letters, digits, `-` and `_`.
fn is_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A static answer (IPv4, IPv6 or a name with a dot); never a device.
fn parse_static(text: &str) -> Result<RewriteAnswer, String> {
    match RewriteAnswer::from_str(text) {
        Ok(answer @ (RewriteAnswer::A(_) | RewriteAnswer::Aaaa(_))) => Ok(answer),
        Ok(RewriteAnswer::Cname(name)) if is_dns_name(&name) => Ok(RewriteAnswer::Cname(name)),
        _ => Err(format!(
            "\"{text}\" is not an IPv4 address, an IPv6 address or a host name"
        )),
    }
}

/// An answer: a static one, or `dev:<name|mac>` with an optional `|<static fallback>`.
fn parse_answer(text: &str) -> Result<RewriteAnswer, String> {
    let text = text.trim();
    let Some(device) = text.strip_prefix("dev:") else {
        return parse_static(text).map_err(|e| {
            if text.contains('.') || text.contains(':') {
                e
            } else {
                format!("{e} (a device is written \"dev:{text}\")")
            }
        });
    };
    let (id, fallback) = match device.split_once('|') {
        Some((id, fallback)) => (id, Some(fallback)),
        None => (device, None),
    };
    let identifier = id.parse().map_err(|e| format!("\"{text}\": {e}"))?;
    let fallback = match fallback {
        Some(fb) => Some(Box::new(
            parse_static(fb.trim()).map_err(|e| format!("fallback {e}"))?,
        )),
        None => None,
    };
    Ok(RewriteAnswer::Device {
        identifier,
        fallback,
    })
}

/// An upstream resolver: `[udp|tls|quic|https]://[<tls name>@]<ip>[:<port>][#<domain>]`. Without a
/// port, the protocol's own: 53 (udp), 853 (tls, quic), 443 (https).
fn parse_upstream(text: &str) -> Result<UpstreamTarget, String> {
    let text = text.trim();
    let err = match UpstreamTarget::from_str(text) {
        Ok(target) => return Ok(target),
        Err(e) => e,
    };
    let (body, domain) = text
        .split_once('#')
        .map_or((text, None), |(b, d)| (b, Some(d)));
    let (scheme, rest) = body.split_once("://").unwrap_or(("udp", body));
    if !matches!(scheme, "udp" | "tls" | "quic" | "https") {
        return Err(format!("\"{scheme}://\" is not udp, tls, quic or https"));
    }
    let (name, addr) = rest
        .rsplit_once('@')
        .map_or((None, rest), |(n, a)| (Some(n), a));
    let port = match scheme {
        "udp" => 53,
        "tls" | "quic" => 853,
        _ => 443,
    };
    let ip: IpAddr = addr
        .strip_prefix('[')
        .and_then(|a| a.strip_suffix(']'))
        .unwrap_or(addr)
        .parse()
        .map_err(|_| err.clone())?;
    let name = name.map(|n| format!("{n}@")).unwrap_or_default();
    let domain = domain.map(|d| format!("#{d}")).unwrap_or_default();
    UpstreamTarget::from_str(&format!(
        "{scheme}://{name}{}{domain}",
        SocketAddr::new(ip, port)
    ))
    .map_err(|_| err)
}

fn parse_rtype(text: &str) -> Option<DnsRecordType> {
    match text.trim().to_ascii_uppercase().as_str() {
        "A" => Some(DnsRecordType::A),
        "AAAA" => Some(DnsRecordType::AAAA),
        "CNAME" => Some(DnsRecordType::CNAME),
        _ => None,
    }
}

/// Whether a rule of type `rtype` can serve `answer`: the static answers only their own type, a
/// device A or AAAA (delimited) — and its fallback must then be of that family.
fn fits(rtype: DnsRecordType, answer: &RewriteAnswer) -> bool {
    match answer {
        RewriteAnswer::Device { fallback, .. } => {
            rtype == DnsRecordType::Device
                || (matches!(rtype, DnsRecordType::A | DnsRecordType::AAAA)
                    && fallback
                        .as_deref()
                        .is_none_or(|fb| inferred_rtype(fb) == rtype))
        }
        other => inferred_rtype(other) == rtype,
    }
}

/// The rules of one table item (one per fallback; a fallback list needs a `dev:` answer).
fn table_rules(table: &DnsRewriteTable) -> Result<Vec<(DnsRecordType, RewriteAnswer)>, String> {
    let answer = parse_answer(&table.answer)?;
    let rtype = match &table.rtype {
        None => inferred_rtype(&answer),
        Some(text) => parse_rtype(text)
            .ok_or_else(|| format!("rtype = \"{text}\" is not A, AAAA or CNAME"))?,
    };
    if table.fallback.is_empty() {
        return Ok(vec![(rtype, answer)]);
    }
    let RewriteAnswer::Device {
        identifier,
        fallback: None,
    } = answer
    else {
        return Err(if matches!(answer, RewriteAnswer::Device { .. }) {
            "a fallback written both after `|` and in `fallback`".to_string()
        } else {
            "a fallback needs a \"dev:\" answer".to_string()
        });
    };
    let mut fallbacks = Vec::with_capacity(table.fallback.len());
    for text in &table.fallback {
        let fb = parse_static(text.trim()).map_err(|e| format!("fallback {e}"))?;
        let kind = inferred_rtype(&fb);
        let clash = fallbacks.iter().any(|f: &RewriteAnswer| {
            let other = inferred_rtype(f);
            other == kind || other == DnsRecordType::CNAME || kind == DnsRecordType::CNAME
        });
        if clash {
            return Err(
                "fallback takes at most one IPv4 and one IPv6 address, or one host name"
                    .to_string(),
            );
        }
        fallbacks.push(fb);
    }
    Ok(fallbacks
        .into_iter()
        .map(|fb| {
            (
                rtype,
                RewriteAnswer::Device {
                    identifier: identifier.clone(),
                    fallback: Some(Box::new(fb)),
                },
            )
        })
        .collect())
}

fn item_rules(item: &DnsRewriteItem) -> Result<Vec<(DnsRecordType, RewriteAnswer)>, String> {
    let rules = match item {
        DnsRewriteItem::Answer(text) => {
            let answer = parse_answer(text)?;
            vec![(inferred_rtype(&answer), answer)]
        }
        DnsRewriteItem::Detailed(table) => table_rules(table)?,
        DnsRewriteItem::Invalid(toml::Value::Table(t)) => {
            let e = DnsRewriteTable::deserialize(toml::Value::Table(t.clone()))
                .err()
                .map_or_else(String::new, |e| e.message().trim().to_string());
            return Err(format!("not an answer table ({e})"));
        }
        DnsRewriteItem::Invalid(other) => {
            return Err(format!(
                "{} is not an answer (a string or a table)",
                other.type_str()
            ));
        }
    };
    for (rtype, answer) in &rules {
        if !fits(*rtype, answer) {
            return Err(format!(
                "rtype = \"{rtype}\" does not fit the answer \"{answer}\""
            ));
        }
    }
    Ok(rules)
}

/// The file item of one rule: the bare answer when its type is the inferred one.
fn rule_item(rule: &RewriteRule) -> DnsRewriteItem {
    if rule.rtype == inferred_rtype(&rule.answer) {
        DnsRewriteItem::Answer(rule.answer.to_string())
    } else {
        DnsRewriteItem::Detailed(DnsRewriteTable {
            answer: rule.answer.to_string(),
            rtype: Some(rule.rtype.to_string()),
            fallback: Vec::new(),
        })
    }
}

/// Two consecutive device rules that differ only in a fallback of each family: the table form
/// `{ answer = "dev:x", fallback = [<one>, <other>] }`.
fn fallback_pair(a: &RewriteRule, b: &RewriteRule) -> Option<DnsRewriteItem> {
    let (
        RewriteAnswer::Device {
            identifier: id_a,
            fallback: Some(fb_a),
        },
        RewriteAnswer::Device {
            identifier: id_b,
            fallback: Some(fb_b),
        },
    ) = (&a.answer, &b.answer)
    else {
        return None;
    };
    let families = (inferred_rtype(fb_a), inferred_rtype(fb_b));
    let pair = matches!(
        families,
        (DnsRecordType::A, DnsRecordType::AAAA) | (DnsRecordType::AAAA, DnsRecordType::A)
    );
    (pair && id_a == id_b && a.rtype == DnsRecordType::Device && b.rtype == DnsRecordType::Device)
        .then(|| {
            DnsRewriteItem::Detailed(DnsRewriteTable {
                answer: format!("dev:{id_a}"),
                rtype: None,
                fallback: vec![fb_a.to_string(), fb_b.to_string()],
            })
        })
}

impl fmt::Display for DnsRewriteItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Answer(text) => write!(f, "\"{text}\""),
            Self::Detailed(table) => write!(f, "{{ answer = \"{}\" }}", table.answer),
            Self::Invalid(value) => write!(f, "{value}"),
        }
    }
}

impl DnsFile {
    /// The file form of `dns`, losing nothing but the rewrite ids. Upstreams are grouped under
    /// their name (names in first-seen order, addresses in order within a name); rewrites are
    /// grouped under their domain the same way.
    #[must_use]
    pub fn from_config(dns: &DnsSettings) -> Self {
        let mut upstreams: Vec<(String, Vec<&UpstreamTarget>)> = Vec::new();
        for up in &dns.upstreams {
            match upstreams.iter_mut().find(|(n, _)| *n == up.name) {
                Some((_, targets)) => targets.push(&up.target),
                None => upstreams.push((up.name.clone(), vec![&up.target])),
            }
        }
        let upstreams = upstreams
            .into_iter()
            .map(|(name, targets)| {
                let first = targets[0].domain.clone();
                let shared = targets.iter().all(|t| t.domain == first);
                let addresses = targets
                    .iter()
                    .map(|t| {
                        if shared {
                            UpstreamTarget {
                                domain: None,
                                ..(*t).clone()
                            }
                            .to_string()
                        } else {
                            t.to_string()
                        }
                    })
                    .collect();
                let domain = if shared { first } else { None };
                (name, DnsUpstreamFile { addresses, domain })
            })
            .collect();

        let mut rewrites: Vec<(String, Vec<&RewriteRule>)> = Vec::new();
        for rule in &dns.rewrites {
            match rewrites.iter_mut().find(|(d, _)| *d == rule.domain) {
                Some((_, rules)) => rules.push(rule),
                None => rewrites.push((rule.domain.clone(), vec![rule])),
            }
        }
        let rewrites = rewrites
            .into_iter()
            .map(|(domain, rules)| {
                let mut items = Vec::with_capacity(rules.len());
                let mut i = 0;
                while i < rules.len() {
                    if let Some(pair) = rules.get(i + 1).and_then(|b| fallback_pair(rules[i], b)) {
                        items.push(pair);
                        i += 2;
                    } else {
                        items.push(rule_item(rules[i]));
                        i += 1;
                    }
                }
                (domain, DnsRewriteValue(items))
            })
            .collect();

        Self {
            enabled: dns.enabled,
            listen: dns.listen.as_ref().map(ToString::to_string),
            upstream_mode: dns.upstream_mode.to_string(),
            upstreams,
            reverse: dns
                .reverse
                .iter()
                .map(|r| (r.subnet.to_string(), r.resolver.to_string()))
                .collect(),
            rewrites,
        }
    }

    /// The DNS settings this file describes, plus one message per value it gets wrong. A wrong
    /// value is left out — an upstream, reverse resolver or rewrite answer is never guessed —
    /// and the rest of the section applies. A wrong `listen` or `upstream_mode` falls back to
    /// the default.
    #[must_use]
    pub fn to_config(&self) -> (DnsSettings, Vec<String>) {
        let mut issues = Vec::new();

        let listen = self.listen.as_deref().and_then(|text| {
            ListenConfig::from_str(text)
                .map_err(|e| {
                    issues.push(format!(
                        "[dns] listen = \"{text}\" is not valid ({e}); using \"[::]:53\""
                    ));
                })
                .ok()
        });

        let upstream_mode = UpstreamMode::from_str(&self.upstream_mode).unwrap_or_else(|_| {
            issues.push(format!(
                "[dns] upstream_mode = \"{}\" is not sequential, parallel, fastest or roundrobin; using \"sequential\"",
                self.upstream_mode
            ));
            UpstreamMode::default()
        });

        let mut upstreams = Vec::new();
        for (name, group) in &self.upstreams {
            let at = format!("[dns.upstreams.\"{name}\"]");
            for text in &group.addresses {
                let mut target = match parse_upstream(text) {
                    Ok(t) => t,
                    Err(e) => {
                        issues.push(format!(
                            "{at} address \"{text}\" is not valid ({e}); left out"
                        ));
                        continue;
                    }
                };
                match (&target.domain, &group.domain) {
                    (Some(own), Some(shared)) if own != shared => {
                        issues.push(format!(
                            "{at} address \"{text}\" names domain \"{own}\" but the group is \"{shared}\"; left out"
                        ));
                        continue;
                    }
                    (None, Some(shared)) => target.domain = Some(shared.clone()),
                    _ => {}
                }
                upstreams.push(NamedUpstream {
                    name: name.clone(),
                    target,
                });
            }
        }

        let mut reverse = Vec::with_capacity(self.reverse.len());
        for (subnet, resolver) in &self.reverse {
            let Ok(parsed_subnet) = IpSubnet::from_str(subnet.trim()) else {
                issues.push(format!(
                    "[dns.reverse] \"{subnet}\" is not a subnet (e.g. \"10.8.0.0/24\"); left out"
                ));
                continue;
            };
            match parse_upstream(resolver) {
                Ok(target) => reverse.push(DnsReverseResolver {
                    subnet: parsed_subnet,
                    resolver: target,
                }),
                Err(e) => issues.push(format!(
                    "[dns.reverse] \"{subnet}\" = \"{resolver}\" is not a resolver ({e}); left out"
                )),
            }
        }

        let mut rewrites = Vec::new();
        for (domain, value) in &self.rewrites {
            let at = format!("[dns.rewrites] \"{domain}\"");
            if domain.trim().is_empty() || domain.chars().any(char::is_whitespace) {
                issues.push(format!("{at} is not a domain; rewrite not served"));
                continue;
            }
            if value.0.is_empty() {
                issues.push(format!("{at} has no answer; rewrite not served"));
                continue;
            }
            for item in &value.0 {
                match item_rules(item) {
                    Ok(rules) => {
                        rewrites.extend(rules.into_iter().map(|(rtype, answer)| RewriteRule {
                            id: None,
                            domain: domain.clone(),
                            rtype,
                            answer,
                        }));
                    }
                    Err(e) => issues.push(format!("{at} answer {item}: {e}; not served")),
                }
            }
        }

        (
            DnsSettings {
                enabled: self.enabled,
                listen,
                upstream_mode,
                upstreams,
                reverse,
                rewrites,
            },
            issues,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Root {
        dns: DnsFile,
    }

    fn parse(text: &str) -> DnsFile {
        toml::from_str::<Root>(text)
            .unwrap_or_else(|e| panic!("{e}\n{text}"))
            .dns
    }

    fn render(file: &DnsFile) -> String {
        #[derive(Serialize)]
        struct Out<'a> {
            dns: &'a DnsFile,
        }
        toml::to_string(&Out { dns: file }).unwrap()
    }

    /// `dns` written to the file and read back, plus the issues and the text.
    fn through_file(dns: &DnsSettings) -> (DnsSettings, Vec<String>, String) {
        let text = render(&DnsFile::from_config(dns));
        let (back, issues) = parse(&text).to_config();
        (back, issues, text)
    }

    fn up(name: &str, target: &str) -> NamedUpstream {
        NamedUpstream {
            name: name.into(),
            target: target.parse().unwrap(),
        }
    }

    fn rule(domain: &str, rtype: DnsRecordType, answer: &str) -> RewriteRule {
        RewriteRule {
            id: None,
            domain: domain.into(),
            rtype,
            answer: answer.parse().unwrap(),
        }
    }

    fn owner_settings() -> DnsSettings {
        let cf = |a: &str| up("default", &format!("udp://{a}"));
        DnsSettings {
            enabled: true,
            listen: Some("[::]:53".parse().unwrap()),
            upstream_mode: UpstreamMode::Sequential,
            upstreams: vec![
                cf("1.1.1.1:53"),
                cf("1.0.0.1:53"),
                cf("[2606:4700:4700::1111]:53"),
                cf("[2606:4700:4700::1001]:53"),
            ],
            reverse: Vec::new(),
            rewrites: vec![rule("*.eonteam.xyz", DnsRecordType::Device, "dev:pixie")],
        }
    }

    /// The owner's `[dns]` in the approved file form (2026-10-28): live mode sequential, one
    /// device rewrite, no reverse resolver.
    const OWNER_FILE: &str = r#"
[dns]
enabled = true
listen = "[::]:53"
upstream_mode = "sequential"

[dns.upstreams.default]
addresses = ["udp://1.1.1.1:53", "udp://1.0.0.1:53",
             "udp://[2606:4700:4700::1111]:53", "udp://[2606:4700:4700::1001]:53"]

[dns.reverse]

[dns.rewrites]
"*.eonteam.xyz" = "dev:pixie"
"#;

    #[test]
    fn owner_file_reads_as_the_live_settings() {
        let (dns, issues) = parse(OWNER_FILE).to_config();
        assert_eq!(issues, Vec::<String>::new());
        assert_eq!(dns, owner_settings());
    }

    #[test]
    fn owner_settings_survive_the_file_exactly() {
        let (back, issues, text) = through_file(&owner_settings());
        assert_eq!(issues, Vec::<String>::new(), "{text}");
        assert_eq!(back, owner_settings(), "{text}");
        assert!(text.contains("\"*.eonteam.xyz\" = \"dev:pixie\""), "{text}");
        assert!(text.contains("upstream_mode = \"sequential\""), "{text}");
    }

    #[test]
    fn every_setting_survives_the_file_exactly() {
        let dns = DnsSettings {
            enabled: false,
            listen: Some("192.168.1.1:53, [fd00::1]:53".parse().unwrap()),
            upstream_mode: UpstreamMode::RoundRobin,
            upstreams: vec![
                up("cloudflare", "tls://one.one.one.one@1.1.1.1:853"),
                up("cloudflare", "https://[2606:4700:4700::1111]:443"),
                // the whole group forwards one domain
                up("corp", "udp://10.0.0.1:53#corp.example"),
                up("corp", "udp://10.0.0.2:53#corp.example"),
                // addresses of one group forwarding different domains
                up("mixed", "udp://10.1.0.1:53#a.example"),
                up("mixed", "quic://10.1.0.2:853"),
            ],
            reverse: vec![
                DnsReverseResolver {
                    subnet: "10.8.0.0/24".parse().unwrap(),
                    resolver: "udp://10.8.0.1:53".parse().unwrap(),
                },
                DnsReverseResolver {
                    subnet: "fd00:8::/64".parse().unwrap(),
                    resolver: "udp://[fd00:8::1]:53".parse().unwrap(),
                },
            ],
            rewrites: vec![
                rule("nas.lan", DnsRecordType::A, "192.168.1.10"),
                rule("nas.lan", DnsRecordType::AAAA, "fd00::10"),
                rule("alias.lan", DnsRecordType::CNAME, "nas.lan"),
                rule("pixie.lan", DnsRecordType::Device, "dev:pixie|192.168.1.50"),
                // fallback per family: two rules, one table entry
                rule(
                    "*.eonteam.xyz",
                    DnsRecordType::Device,
                    "dev:pixie|192.168.1.50",
                ),
                rule("*.eonteam.xyz", DnsRecordType::Device, "dev:pixie|fd00::50"),
                // delimited device
                rule(
                    "v4only.lan",
                    DnsRecordType::A,
                    "dev:aa:bb:cc:dd:ee:ff|192.168.1.60",
                ),
                rule("cname-fb.lan", DnsRecordType::Device, "dev:box|box.example"),
            ],
        };
        let (back, issues, text) = through_file(&dns);
        assert_eq!(issues, Vec::<String>::new(), "{text}");
        assert_eq!(back, dns, "{text}");
        assert!(
            text.contains("fallback = [\"192.168.1.50\", \"fd00::50\"]"),
            "{text}"
        );
    }

    #[test]
    fn defaults_survive_the_file_exactly() {
        let (back, issues, text) = through_file(&DnsSettings::default());
        assert_eq!(issues, Vec::<String>::new(), "{text}");
        assert_eq!(back, DnsSettings::default(), "{text}");
        assert_eq!(
            parse("[dns]\n").to_config(),
            (DnsSettings::default(), Vec::new())
        );
    }

    #[test]
    fn rewrite_value_forms_read_as_rules() {
        let file = parse(
            r#"
[dns.rewrites]
"one.lan" = "192.168.1.10"
"two.lan" = ["192.168.1.11", "fd00::11"]
"pixie.lan" = { answer = "dev:pixie", fallback = ["192.168.1.50", "fd00::50"] }
"v4.lan" = { answer = "dev:pixie", rtype = "a" }
"mixed.lan" = ["192.168.1.12", { answer = "dev:pixie", rtype = "AAAA" }]
"#,
        );
        let (dns, issues) = file.to_config();
        assert_eq!(issues, Vec::<String>::new());
        assert_eq!(
            dns.rewrites,
            vec![
                rule("one.lan", DnsRecordType::A, "192.168.1.10"),
                rule("two.lan", DnsRecordType::A, "192.168.1.11"),
                rule("two.lan", DnsRecordType::AAAA, "fd00::11"),
                rule("pixie.lan", DnsRecordType::Device, "dev:pixie|192.168.1.50"),
                rule("pixie.lan", DnsRecordType::Device, "dev:pixie|fd00::50"),
                rule("v4.lan", DnsRecordType::A, "dev:pixie"),
                rule("mixed.lan", DnsRecordType::A, "192.168.1.12"),
                rule("mixed.lan", DnsRecordType::AAAA, "dev:pixie"),
            ]
        );
    }

    #[test]
    fn upstream_without_a_port_takes_the_protocols_own() {
        let file = parse(
            r#"
[dns.upstreams.x]
addresses = ["1.1.1.1", "udp://[2606:4700:4700::1111]", "tls://one.one.one.one@1.1.1.1", "https://1.1.1.1#lan"]
"#,
        );
        let (dns, issues) = file.to_config();
        assert_eq!(issues, Vec::<String>::new());
        let targets: Vec<String> = dns.upstreams.iter().map(|u| u.target.to_string()).collect();
        assert_eq!(
            targets,
            [
                "udp://1.1.1.1:53",
                "udp://[2606:4700:4700::1111]:53",
                "tls://one.one.one.one@1.1.1.1:853",
                "https://1.1.1.1:443#lan",
            ]
        );
    }

    /// Every wrong value is reported and left out; nothing is guessed (the legacy reader turned
    /// a bad upstream into `1.1.1.1:53` and any bad answer into a CNAME), and the rest applies.
    #[test]
    fn wrong_values_are_reported_and_left_out() {
        let file = parse(
            r#"
[dns]
listen = "port 53"
upstream_mode = "random"

[dns.upstreams.default]
addresses = ["udp://9.9.9.9:53", "not-an-address", "ftp://1.1.1.1"]

[dns.upstreams.corp]
domain = "corp.example"
addresses = ["udp://10.0.0.1:53#other.example"]

[dns.reverse]
"10.8.0.0/33" = "udp://10.8.0.1:53"
"10.9.0.0/24" = "nowhere"

[dns.rewrites]
"ok.lan" = "192.168.1.10"
"srv.lan" = "srv:http:tcp:nas:8096"
"bare.lan" = "pixie"
"badname.lan" = "a b.lan"
"tail.lan" = "dev:pixie|192.0.2.9|fd00::9"
"devfb.lan" = "dev:pixie|dev:other"
"txt.lan" = { answer = "192.168.1.10", rtype = "TXT" }
"mismatch.lan" = { answer = "192.168.1.10", rtype = "AAAA" }
"cname-dev.lan" = { answer = "dev:pixie", rtype = "CNAME" }
"famfb.lan" = { answer = "dev:pixie", rtype = "A", fallback = ["fd00::9"] }
"twofb.lan" = { answer = "dev:pixie", fallback = ["192.0.2.1", "192.0.2.2"] }
"staticfb.lan" = { answer = "192.0.2.1", fallback = ["fd00::1"] }
"both.lan" = { answer = "dev:pixie|192.0.2.1", fallback = ["fd00::1"] }
"old.lan" = { target = "dev:pixie", rtype = "DEVICE" }
"number.lan" = 5
"empty.lan" = []
"partial.lan" = ["192.168.1.20", "nope"]
"#,
        );
        let (dns, issues) = file.to_config();
        assert_eq!(dns.listen, None);
        assert_eq!(dns.upstream_mode, UpstreamMode::Sequential);
        assert_eq!(dns.upstreams, vec![up("default", "udp://9.9.9.9:53")]);
        assert_eq!(dns.reverse, Vec::new());
        assert_eq!(
            dns.rewrites,
            vec![
                rule("ok.lan", DnsRecordType::A, "192.168.1.10"),
                rule("partial.lan", DnsRecordType::A, "192.168.1.20"),
            ]
        );
        let expected_keys = [
            "listen = \"port 53\"",
            "upstream_mode = \"random\"",
            "\"not-an-address\"",
            "names domain \"other.example\"",
            "\"10.8.0.0/33\" is not a subnet",
            "\"10.9.0.0/24\" = \"nowhere\"",
            "\"srv.lan\"",
            "\"bare.lan\" answer \"pixie\": \"pixie\" is not an IPv4 address, an IPv6 address or a host name (a device is written \"dev:pixie\")",
            "\"badname.lan\"",
            "\"tail.lan\"",
            "\"devfb.lan\"",
            "\"txt.lan\"",
            "\"mismatch.lan\"",
            "\"cname-dev.lan\"",
            "\"famfb.lan\"",
            "\"twofb.lan\"",
            "\"staticfb.lan\"",
            "\"both.lan\"",
            "\"old.lan\" answer { target = \"dev:pixie\", rtype = \"DEVICE\" }: not an answer table (unknown field `target`",
            "\"ftp://1.1.1.1\" is not valid (\"ftp://\" is not udp, tls, quic or https)",
            "\"number.lan\" answer 5: integer is not an answer",
            "\"empty.lan\" has no answer",
            "\"partial.lan\" answer \"nope\"",
        ];
        for key in expected_keys {
            assert!(
                issues.iter().any(|i| i.contains(key)),
                "no issue with {key:?} in {issues:#?}"
            );
        }
        assert_eq!(issues.len(), expected_keys.len(), "{issues:#?}");
    }

    /// An entry the reader does not understand is written back as it was, not dropped.
    #[test]
    fn a_wrong_rewrite_is_written_back_as_it_was() {
        let file = parse(
            r#"
[dns.rewrites]
"old.lan" = { target = "dev:pixie", rtype = "DEVICE" }
"#,
        );
        assert_eq!(parse(&render(&file)), file);
    }
}
