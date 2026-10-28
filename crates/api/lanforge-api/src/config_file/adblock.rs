//! `[adblock]`, in its own file form: the filter settings, the list sources, the global layer
//! (`lists` + the `rules` file every client gets) and the per-client overlays (`groups`,
//! `bypass`). A source is active by being named in `lists` or in a group; there is no
//! per-source `enabled`. Manual rules live in line files (`adblock/*.rules`), not here.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path};
use std::str::FromStr;

use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockSourceFormat, AdblockUrlKind, BlockingMode, ClientSelector, TimeOfDay,
};
use serde::{Deserialize, Serialize};

use super::sections::named_tables;

/// Lists one client can have: the engine keeps one bit per list in a `u64`.
pub const MAX_LISTS: usize = 64;

fn default_blocking_mode() -> String {
    BlockingMode::default().to_string()
}

fn default_refresh_time() -> String {
    TimeOfDay::DEFAULT.to_string()
}

/// The adblock settings `[adblock]` describes, as the daemon runs them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdblockSettings {
    pub config: AdblockDbConfig,
    /// `[adblock.sources.<name>]` in file order; `name` is always set and `id` never (the id is
    /// derived from the URL, which names the compiled list on disk).
    pub sources: Vec<AdblockUrlEntry>,
    /// The global layer: the names of the sources every client gets, in order.
    pub lists: Vec<String>,
    /// The global rules file, relative to the directory of `lanforge.toml`.
    pub rules: Option<String>,
    /// Clients that are never filtered.
    pub bypass: Vec<ClientSelector>,
    pub groups: Vec<AdblockGroup>,
}

/// An overlay on the global layer for some clients: it adds lists and rules, never removes any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdblockGroup {
    pub name: String,
    pub lists: Vec<String>,
    pub rules: Option<String>,
    pub clients: Vec<ClientSelector>,
}

impl AdblockSettings {
    /// The sources of the global layer, in `lists` order.
    pub fn global_sources(&self) -> impl Iterator<Item = &AdblockUrlEntry> {
        self.lists.iter().filter_map(|name| {
            self.sources
                .iter()
                .find(|s| s.name.as_deref() == Some(name))
        })
    }
}

/// `[adblock]` as written in the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdblockFile {
    #[serde(default)]
    pub enabled: bool,
    /// `nxdomain`, `null_ip`, `custom_ip` or `refused`.
    #[serde(default = "default_blocking_mode")]
    pub blocking_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ip_v4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ip_v6: Option<String>,
    /// `HH:MM`, local time of the daily list update.
    #[serde(default = "default_refresh_time")]
    pub refresh_time: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bypass: Vec<String>,
    /// `[adblock.sources.<name>]`, in file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub sources: Vec<(String, AdblockSourceFile)>,
    /// `[adblock.groups.<name>]`, in file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub groups: Vec<(String, AdblockGroupFile)>,
}

impl Default for AdblockFile {
    fn default() -> Self {
        Self {
            enabled: false,
            blocking_mode: default_blocking_mode(),
            blocking_ip_v4: None,
            blocking_ip_v6: None,
            refresh_time: default_refresh_time(),
            lists: Vec::new(),
            rules: None,
            bypass: Vec::new(),
            sources: Vec::new(),
            groups: Vec::new(),
        }
    }
}

/// A downloaded list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdblockSourceFile {
    pub url: String,
    /// `adblock`, `hosts`, `domains` or `wildcard_domains`; absent = detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// `blocklist` (absent) or `allowlist`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// `[adblock.groups.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdblockGroupFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,
    #[serde(default)]
    pub clients: Vec<String>,
}

/// A rules file path: relative to the config directory, never leaving it.
fn rules_path(at: &str, text: Option<&String>, issues: &mut Vec<String>) -> Option<String> {
    let text = text?;
    let inside = !text.trim().is_empty()
        && Path::new(text)
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if inside {
        Some(text.clone())
    } else {
        issues.push(format!(
            "{at} rules = \"{text}\" is not a path inside the config directory (e.g. \"adblock/global.rules\"); no rules read"
        ));
        None
    }
}

fn selectors(
    at: &str,
    key: &str,
    texts: &[String],
    issues: &mut Vec<String>,
) -> Vec<ClientSelector> {
    texts
        .iter()
        .filter_map(|text| {
            ClientSelector::from_str(text)
                .map_err(|e| issues.push(format!("{at} {key} \"{text}\": {e}; left out")))
                .ok()
        })
        .collect()
}

impl AdblockFile {
    /// The file form of `adblock`, losing nothing (source ids are derived from the URL).
    #[must_use]
    pub fn from_config(adblock: &AdblockSettings) -> Self {
        let cfg = &adblock.config;
        Self {
            enabled: cfg.enabled,
            blocking_mode: cfg.blocking_mode.to_string(),
            blocking_ip_v4: cfg.blocking_ip_v4.map(|ip| ip.to_string()),
            blocking_ip_v6: cfg.blocking_ip_v6.map(|ip| ip.to_string()),
            refresh_time: cfg.refresh_time.to_string(),
            lists: adblock.lists.clone(),
            rules: adblock.rules.clone(),
            bypass: adblock.bypass.iter().map(ToString::to_string).collect(),
            sources: adblock
                .sources
                .iter()
                .map(|s| {
                    let name = lanforge_crypto::stable_id_or_hash(
                        s.name.as_deref(),
                        s.url.as_bytes(),
                        "src",
                    );
                    let file = AdblockSourceFile {
                        url: s.url.clone(),
                        format: (s.format != AdblockSourceFormat::Auto)
                            .then(|| s.format.to_string()),
                        kind: (s.kind != AdblockUrlKind::Blocklist).then(|| s.kind.to_string()),
                    };
                    (name, file)
                })
                .collect(),
            groups: adblock
                .groups
                .iter()
                .map(|g| {
                    let file = AdblockGroupFile {
                        lists: g.lists.clone(),
                        rules: g.rules.clone(),
                        clients: g.clients.iter().map(ToString::to_string).collect(),
                    };
                    (g.name.clone(), file)
                })
                .collect(),
        }
    }

    /// The adblock settings this file describes, plus one message per value it gets wrong. A
    /// wrong source, list name or client is left out — never guessed — and the rest applies; a
    /// wrong `blocking_mode` or `refresh_time` falls back to the default.
    #[must_use]
    pub fn to_config(&self) -> (AdblockSettings, Vec<String>) {
        let mut issues = Vec::new();

        let blocking_mode = BlockingMode::from_str(&self.blocking_mode).unwrap_or_else(|_| {
            issues.push(format!(
                "[adblock] blocking_mode = \"{}\" is not nxdomain, null_ip, custom_ip or refused; using \"nxdomain\"",
                self.blocking_mode
            ));
            BlockingMode::default()
        });
        let blocking_ip_v4 = self.blocking_ip_v4.as_deref().and_then(|text| {
            Ipv4Addr::from_str(text.trim())
                .map_err(|_| {
                    issues.push(format!(
                        "[adblock] blocking_ip_v4 = \"{text}\" is not an IPv4 address; left out"
                    ));
                })
                .ok()
        });
        let blocking_ip_v6 = self.blocking_ip_v6.as_deref().and_then(|text| {
            Ipv6Addr::from_str(text.trim())
                .map_err(|_| {
                    issues.push(format!(
                        "[adblock] blocking_ip_v6 = \"{text}\" is not an IPv6 address; left out"
                    ));
                })
                .ok()
        });
        let refresh_time = TimeOfDay::from_str(&self.refresh_time).unwrap_or_else(|_| {
            issues.push(format!(
                "[adblock] refresh_time = \"{}\" is not HH:MM; using \"03:00\"",
                self.refresh_time
            ));
            TimeOfDay::DEFAULT
        });

        let mut sources: Vec<AdblockUrlEntry> = Vec::with_capacity(self.sources.len());
        for (name, file) in &self.sources {
            let at = format!("[adblock.sources.\"{name}\"]");
            let url = file.url.trim();
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("https://") || lower.starts_with("http://")) || url.len() < 9 {
                issues.push(format!(
                    "{at} url = \"{}\" is not an http(s) URL; source left out",
                    file.url
                ));
                continue;
            }
            if let Some(other) = sources.iter().find(|s| s.url == url) {
                issues.push(format!(
                    "{at} has the same url as \"{}\"; source left out",
                    other.name.as_deref().unwrap_or_default()
                ));
                continue;
            }
            let format = match file.format.as_deref().map(AdblockSourceFormat::from_str) {
                None => AdblockSourceFormat::Auto,
                Some(Ok(format)) => format,
                Some(Err(_)) => {
                    issues.push(format!(
                        "{at} format = \"{}\" is not adblock, hosts, domains or wildcard_domains; source left out",
                        file.format.as_deref().unwrap_or_default()
                    ));
                    continue;
                }
            };
            let kind = match file.kind.as_deref().map(AdblockUrlKind::from_str) {
                None => AdblockUrlKind::Blocklist,
                Some(Ok(kind)) => kind,
                Some(Err(_)) => {
                    issues.push(format!(
                        "{at} kind = \"{}\" is not blocklist or allowlist; source left out",
                        file.kind.as_deref().unwrap_or_default()
                    ));
                    continue;
                }
            };
            sources.push(AdblockUrlEntry {
                id: None,
                name: Some(name.clone()),
                url: url.to_string(),
                kind,
                format,
            });
        }

        // Names a layer may use: known sources, once each, at most MAX_LISTS per client.
        let known = |at: &str, names: &[String], taken: usize, issues: &mut Vec<String>| {
            let mut out: Vec<String> = Vec::with_capacity(names.len());
            for name in names {
                if !sources
                    .iter()
                    .any(|s| s.name.as_deref() == Some(name.as_str()))
                {
                    issues.push(format!("{at} lists \"{name}\" is not a source; left out"));
                } else if out.contains(name) {
                    issues.push(format!("{at} lists \"{name}\" is listed twice; left out"));
                } else if taken + out.len() >= MAX_LISTS {
                    issues.push(format!(
                        "{at} lists \"{name}\": more than {MAX_LISTS} lists for one client; left out"
                    ));
                } else {
                    out.push(name.clone());
                }
            }
            out
        };

        let lists = known("[adblock]", &self.lists, 0, &mut issues);
        let rules = rules_path("[adblock]", self.rules.as_ref(), &mut issues);
        let bypass = selectors("[adblock]", "bypass", &self.bypass, &mut issues);

        let mut groups = Vec::with_capacity(self.groups.len());
        for (name, file) in &self.groups {
            let at = format!("[adblock.groups.\"{name}\"]");
            let own: Vec<String> = file
                .lists
                .iter()
                .filter(|n| !lists.contains(n))
                .cloned()
                .collect();
            if own.len() < file.lists.len() {
                issues.push(format!(
                    "{at} lists repeats lists of the global layer; those are left out (every client has them)"
                ));
            }
            let group_lists = known(&at, &own, lists.len(), &mut issues);
            let clients = selectors(&at, "clients", &file.clients, &mut issues);
            if clients.is_empty() {
                issues.push(format!("{at} has no clients; it applies to nobody"));
            }
            groups.push(AdblockGroup {
                name: name.clone(),
                lists: group_lists,
                rules: rules_path(&at, file.rules.as_ref(), &mut issues),
                clients,
            });
        }

        for source in &sources {
            let name = source.name.as_deref().unwrap_or_default();
            let used = lists.iter().any(|n| n == name)
                || groups.iter().any(|g| g.lists.iter().any(|n| n == name));
            if !used {
                issues.push(format!(
                    "[adblock.sources.\"{name}\"] is not in `lists` nor in a group; not downloaded"
                ));
            }
        }

        (
            AdblockSettings {
                config: AdblockDbConfig {
                    enabled: self.enabled,
                    blocking_mode,
                    blocking_ip_v4,
                    blocking_ip_v6,
                    refresh_time,
                },
                sources,
                lists,
                rules,
                bypass,
                groups,
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
        adblock: AdblockFile,
    }

    fn parse(text: &str) -> AdblockFile {
        toml::from_str::<Root>(text)
            .unwrap_or_else(|e| panic!("{e}\n{text}"))
            .adblock
    }

    fn render(file: &AdblockFile) -> String {
        #[derive(Serialize)]
        struct Out<'a> {
            adblock: &'a AdblockFile,
        }
        toml::to_string(&Out { adblock: file }).unwrap()
    }

    fn source(name: &str, url: &str) -> AdblockUrlEntry {
        AdblockUrlEntry {
            id: None,
            name: Some(name.into()),
            url: url.into(),
            kind: AdblockUrlKind::Blocklist,
            format: AdblockSourceFormat::Auto,
        }
    }

    const STEVENBLACK: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

    /// The owner's `[adblock]` in the approved file form (2026-10-28): one hosts list, the
    /// Bradesco allows in the global rules file.
    const OWNER_FILE: &str = r#"
[adblock]
enabled = true
blocking_mode = "nxdomain"
refresh_time = "03:00"
lists = ["src-7cc6f305"]
rules = "adblock/global.rules"

[adblock.sources.src-7cc6f305]
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
format = "hosts"
"#;

    fn owner_settings() -> AdblockSettings {
        AdblockSettings {
            config: AdblockDbConfig {
                enabled: true,
                ..AdblockDbConfig::default()
            },
            sources: vec![AdblockUrlEntry {
                format: AdblockSourceFormat::Hosts,
                ..source("src-7cc6f305", STEVENBLACK)
            }],
            lists: vec!["src-7cc6f305".into()],
            rules: Some("adblock/global.rules".into()),
            bypass: Vec::new(),
            groups: Vec::new(),
        }
    }

    #[test]
    fn owner_file_reads_as_the_live_settings() {
        let (adblock, issues) = parse(OWNER_FILE).to_config();
        assert_eq!(issues, Vec::<String>::new());
        assert_eq!(adblock, owner_settings());
    }

    /// The compiled list on the owner's box is `1023162918584372960.block.fst`: the file keeps no
    /// id, so the one derived from the URL must be that one or the first boot downloads again.
    #[test]
    fn owner_source_keeps_the_id_of_its_compiled_list() {
        let (adblock, _) = parse(OWNER_FILE).to_config();
        let ids: Vec<i64> = adblock
            .global_sources()
            .map(AdblockUrlEntry::source_id)
            .collect();
        assert_eq!(ids, vec![1_023_162_918_584_372_960]);
    }

    #[test]
    fn owner_settings_survive_the_file_exactly() {
        let text = render(&AdblockFile::from_config(&owner_settings()));
        assert_eq!(parse(&text), parse(OWNER_FILE));
        let (back, issues) = parse(&text).to_config();
        assert_eq!(issues, Vec::<String>::new());
        assert_eq!(back, owner_settings());
    }

    #[test]
    fn every_field_survives_the_file() {
        let adblock = AdblockSettings {
            config: AdblockDbConfig {
                enabled: true,
                blocking_mode: BlockingMode::CustomIp,
                blocking_ip_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                blocking_ip_v6: Some("2001:db8::1".parse().unwrap()),
                refresh_time: TimeOfDay::new(4, 30).unwrap(),
            },
            sources: vec![
                // File order, not name order.
                source("zeta", "https://example.com/z.txt"),
                AdblockUrlEntry {
                    kind: AdblockUrlKind::Allowlist,
                    format: AdblockSourceFormat::Adblock,
                    ..source("allow", "https://example.com/allow.txt")
                },
                AdblockUrlEntry {
                    format: AdblockSourceFormat::WildcardDomains,
                    ..source("nsfw", "http://example.com/nsfw.txt")
                },
            ],
            lists: vec!["zeta".into(), "allow".into()],
            rules: Some("adblock/global.rules".into()),
            bypass: vec!["dev:notebook-trabalho".parse().unwrap()],
            groups: vec![
                AdblockGroup {
                    name: "kids".into(),
                    lists: vec!["nsfw".into()],
                    rules: None,
                    clients: vec![
                        "192.168.1.64/28".parse().unwrap(),
                        "dev:aa:bb:cc:dd:ee:ff".parse().unwrap(),
                        "dev:galaxy-tab".parse().unwrap(),
                        "fd00::64".parse().unwrap(),
                    ],
                },
                AdblockGroup {
                    name: "bradesco".into(),
                    lists: Vec::new(),
                    rules: Some("adblock/bradesco.rules".into()),
                    clients: vec!["dev:pixel-faiko".parse().unwrap()],
                },
            ],
        };
        let text = render(&AdblockFile::from_config(&adblock));
        let (back, issues) = parse(&text).to_config();
        assert_eq!(issues, Vec::<String>::new(), "{text}");
        assert_eq!(back, adblock, "{text}");
        assert!(
            text.contains("\"fd00::64\""),
            "a host is written bare:\n{text}"
        );
    }

    #[test]
    fn global_sources_follow_lists_not_the_source_order() {
        let (adblock, _) = parse(
            r#"
[adblock]
lists = ["b", "a"]
[adblock.sources.a]
url = "https://example.com/a"
[adblock.sources.b]
url = "https://example.com/b"
"#,
        )
        .to_config();
        let urls: Vec<&str> = adblock.global_sources().map(|s| s.url.as_str()).collect();
        assert_eq!(urls, vec!["https://example.com/b", "https://example.com/a"]);
    }

    #[test]
    fn wrong_entries_are_left_out_and_reported() {
        let (adblock, issues) = parse(
            r#"
[adblock]
enabled = true
blocking_mode = "sinkhole"
blocking_ip_v4 = "fd00::1"
blocking_ip_v6 = "nope"
refresh_time = "25:00"
lists = ["ok", "missing", "ok", "ftp", "badkind", "badfmt", "dup"]
rules = "../etc/shadow"
bypass = ["dev:", "10.0.0.0/33", "192.168.1.9"]

[adblock.sources.ok]
url = "https://example.com/ok"
[adblock.sources.ftp]
url = "ftp://example.com/list"
[adblock.sources.badkind]
url = "https://example.com/k"
kind = "denylist"
[adblock.sources.badfmt]
url = "https://example.com/f"
format = "regex"
[adblock.sources.dup]
url = "https://example.com/ok"
[adblock.sources.unused]
url = "https://example.com/unused"

[adblock.groups.kids]
lists = ["ok", "unknown"]
rules = "/etc/lanforge/kids.rules"
clients = ["dev:galaxy tab"]
"#,
        )
        .to_config();
        assert_eq!(adblock.config.blocking_mode, BlockingMode::NxDomain);
        assert_eq!(adblock.config.blocking_ip_v4, None);
        assert_eq!(adblock.config.blocking_ip_v6, None);
        assert_eq!(adblock.config.refresh_time, TimeOfDay::DEFAULT);
        assert_eq!(
            adblock.sources,
            vec![
                source("ok", "https://example.com/ok"),
                source("unused", "https://example.com/unused")
            ]
        );
        assert_eq!(adblock.lists, vec!["ok".to_string()]);
        assert_eq!(adblock.rules, None);
        assert_eq!(adblock.bypass, vec!["192.168.1.9".parse().unwrap()]);
        assert_eq!(
            adblock.groups,
            vec![AdblockGroup {
                name: "kids".into(),
                lists: Vec::new(),
                rules: None,
                clients: Vec::new(),
            }]
        );
        let expected = [
            "blocking_mode = \"sinkhole\"",
            "blocking_ip_v4 = \"fd00::1\"",
            "blocking_ip_v6 = \"nope\"",
            "refresh_time = \"25:00\"",
            "[adblock.sources.\"ftp\"] url",
            "[adblock.sources.\"badkind\"] kind = \"denylist\"",
            "[adblock.sources.\"badfmt\"] format = \"regex\"",
            "[adblock.sources.\"dup\"] has the same url as \"ok\"",
            "[adblock] lists \"missing\" is not a source",
            "[adblock] lists \"ok\" is listed twice",
            "[adblock] lists \"ftp\" is not a source",
            "[adblock] lists \"badkind\" is not a source",
            "[adblock] lists \"badfmt\" is not a source",
            "[adblock] lists \"dup\" is not a source",
            "[adblock] rules = \"../etc/shadow\"",
            "[adblock] bypass \"dev:\"",
            "[adblock] bypass \"10.0.0.0/33\"",
            "[adblock.groups.\"kids\"] lists repeats lists of the global layer",
            "[adblock.groups.\"kids\"] lists \"unknown\" is not a source",
            "[adblock.groups.\"kids\"] clients \"dev:galaxy tab\"",
            "[adblock.groups.\"kids\"] has no clients",
            "[adblock.groups.\"kids\"] rules = \"/etc/lanforge/kids.rules\"",
            "[adblock.sources.\"unused\"] is not in `lists` nor in a group; not downloaded",
        ];
        for key in expected {
            assert!(
                issues.iter().any(|i| i.contains(key)),
                "no issue with {key:?} in {issues:#?}"
            );
        }
        assert_eq!(issues.len(), expected.len(), "{issues:#?}");
    }

    #[test]
    fn a_client_gets_at_most_64_lists() {
        let mut text = String::from("[adblock]\nlists = [");
        for i in 0..=MAX_LISTS {
            text.push_str(&format!("\"l{i}\", "));
        }
        text.push_str("]\n");
        for i in 0..=MAX_LISTS {
            text.push_str(&format!(
                "[adblock.sources.l{i}]\nurl = \"https://example.com/{i}\"\n"
            ));
        }
        text.push_str("[adblock.groups.g]\nlists = [\"l64\"]\nclients = [\"10.0.0.1\"]\n");
        let (adblock, issues) = parse(&text).to_config();
        assert_eq!(adblock.lists.len(), MAX_LISTS);
        assert_eq!(adblock.groups[0].lists, Vec::<String>::new());
        assert_eq!(
            issues,
            vec![
                format!(
                    "[adblock] lists \"l64\": more than {MAX_LISTS} lists for one client; left out"
                ),
                format!(
                    "[adblock.groups.\"g\"] lists \"l64\": more than {MAX_LISTS} lists for one client; left out"
                ),
                "[adblock.sources.\"l64\"] is not in `lists` nor in a group; not downloaded"
                    .to_string(),
            ]
        );
    }

    /// The form the hash sync wrote (`allowlist`, `[adblock.rules."<domain>"]`, per-source
    /// `enabled`) is not this form: the cut-over must write `[adblock]` before it is read.
    #[test]
    fn the_old_file_form_does_not_parse() {
        for old in [
            "[adblock]\nallowlist = [\"x.com\"]\n",
            "[adblock.rules.\"x.com\"]\naction = \"block\"\n",
            "[adblock.sources.s]\nurl = \"https://example.com\"\nenabled = true\n",
        ] {
            assert!(toml::from_str::<Root>(old).is_err(), "{old}");
        }
    }
}
