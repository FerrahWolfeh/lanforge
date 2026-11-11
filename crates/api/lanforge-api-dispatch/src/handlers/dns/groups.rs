//! Adblock groups and `bypass` (`[adblock.groups.*]`, `[adblock] bypass`): list, create, edit,
//! delete, and a device's memberships. Every write goes through `change_adblock` (file, then
//! live), so a group change is a config change like any other.

use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;

use lanforge_api::api::{
    AdblockClientDevice, AdblockClientEntry, AdblockGroupChange, AdblockGroupEntry,
    DnsAdblockGroupsResponse, Response,
};
use lanforge_api::config_file::AdblockGroup;
use lanforge_core::context::state::State;
use lanforge_types::identifiers::{DeviceIdentifier, MacAddr};
use lanforge_types::network::dns::adblock::ClientSelector;
use lanforge_types::network::dns::adblock::rules_file::RulesFile;

use crate::ClientContext;
use crate::handlers::dns::rewrite::dns_reply;
use crate::handlers::system::config_write::Persisted;

/// Client selectors as the API receives them; the first one that does not parse is the error.
fn parse_clients(texts: &[String]) -> Result<Vec<ClientSelector>, String> {
    texts
        .iter()
        .map(|text| ClientSelector::from_str(text).map_err(|e| format!("client \"{text}\": {e}")))
        .collect()
}

/// `selector` with the devices it names now.
fn client_entry(state: &State, selector: &ClientSelector) -> AdblockClientEntry {
    let devices = if selector.needs_device() {
        state
            .devices
            .iter()
            .filter(|(mac, device)| {
                selector.matches(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(**mac), Some(device))
            })
            .map(|(mac, device)| AdblockClientDevice {
                mac: *mac,
                name: if device.hostname.name.is_empty() {
                    device.dns_fallback.clone()
                } else {
                    device.hostname.name.clone()
                },
            })
            .collect()
    } else {
        Vec::new()
    };
    AdblockClientEntry {
        selector: selector.to_string(),
        devices,
    }
}

impl ClientContext {
    /// The groups as `[adblock]` has them (lists, rules file, clients with the devices they
    /// name now, rule counts of what runs) and the bypassed clients.
    pub async fn handle_dns_adblock_groups(&self) -> Response {
        let adblock = self.live_adblock_settings();
        let policy = self.ctx.get_dns_adblock_policy();
        let response = self.ctx.with_state(|state| DnsAdblockGroupsResponse {
            groups: adblock
                .groups
                .iter()
                .map(|group| {
                    let rules = policy
                        .groups
                        .iter()
                        .find(|g| g.name == group.name)
                        .map(|g| RulesFile::new(&g.rules).rule_entries())
                        .unwrap_or_default();
                    let enabled = |allow: bool| {
                        rules
                            .iter()
                            .filter(|r| r.enabled && r.action.is_allow() == allow)
                            .count()
                    };
                    AdblockGroupEntry {
                        name: group.name.clone(),
                        lists: group.lists.clone(),
                        rules_file: group.rules.clone(),
                        allow_rules: enabled(true),
                        block_rules: enabled(false),
                        clients: group
                            .clients
                            .iter()
                            .map(|c| client_entry(state, c))
                            .collect(),
                    }
                })
                .collect(),
            bypass: adblock
                .bypass
                .iter()
                .map(|c| client_entry(state, c))
                .collect(),
        });
        Response::DnsAdblockGroups(Box::new(response))
    }

    /// Creates `[adblock.groups.<name>]` with these lists (source names) and clients.
    pub async fn handle_dns_adblock_group_create(
        &self,
        name: String,
        lists: Vec<String>,
        clients: Vec<String>,
    ) -> Response {
        if !AdblockGroup::is_valid_name(&name) {
            return Response::Rejected {
                error: format!(
                    "group name \"{name}\": use letters, digits, '-' and '_' (at most 64)"
                ),
            };
        }
        let clients = match parse_clients(&clients) {
            Ok(clients) => clients,
            Err(error) => return Response::Rejected { error },
        };
        if self
            .live_adblock_settings()
            .groups
            .iter()
            .any(|g| g.name == name)
        {
            return Response::Rejected {
                error: format!("adblock group \"{name}\" already exists"),
            };
        }
        dns_reply(
            self.change_adblock(|a| {
                a.groups.push(AdblockGroup {
                    name: name.clone(),
                    lists,
                    rules: None,
                    clients,
                });
            }),
            format!("Adblock group \"{name}\" created"),
        )
    }

    /// Replaces a group's lists (source names) and clients; its rules file stays.
    pub async fn handle_dns_adblock_group_update(
        &self,
        name: String,
        lists: Vec<String>,
        clients: Vec<String>,
    ) -> Response {
        let clients = match parse_clients(&clients) {
            Ok(clients) => clients,
            Err(error) => return Response::Rejected { error },
        };
        if !self
            .live_adblock_settings()
            .groups
            .iter()
            .any(|g| g.name == name)
        {
            return Response::NotFound {
                error: format!("adblock group \"{name}\""),
            };
        }
        dns_reply(
            self.change_adblock(|a| {
                if let Some(group) = a.groups.iter_mut().find(|g| g.name == name) {
                    group.lists = lists;
                    group.clients = clients;
                }
            }),
            format!("Adblock group \"{name}\" updated"),
        )
    }

    /// Removes `[adblock.groups.<name>]` and, once the file no longer names it, its rules file
    /// (unless the global layer or another group names the same file). A read-only config
    /// leaves the rules file alone.
    pub async fn handle_dns_adblock_group_delete(&self, name: String) -> Response {
        if !self
            .live_adblock_settings()
            .groups
            .iter()
            .any(|g| g.name == name)
        {
            return Response::NotFound {
                error: format!("adblock group \"{name}\""),
            };
        }
        let mut rules = None;
        let persisted = self.change_adblock(|a| {
            let Some(at) = a.groups.iter().position(|g| g.name == name) else {
                return;
            };
            let group = a.groups.remove(at);
            rules = group.rules.filter(|r| {
                a.rules.as_deref() != Some(r.as_str())
                    && !a
                        .groups
                        .iter()
                        .any(|g| g.rules.as_deref() == Some(r.as_str()))
            });
        });
        let mut what = format!("Adblock group \"{name}\" removed");
        if let (Ok(Persisted::File), Some(rules), Some(config)) =
            (&persisted, rules, self.ctx.config_path())
        {
            let path = config.parent().unwrap_or(Path::new(".")).join(&rules);
            match fs::remove_file(&path) {
                Ok(()) => what.push_str(&format!(" with its rules file {rules}")),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => what.push_str(&format!(
                    "; its rules file {} could not be removed: {e}",
                    path.display()
                )),
            }
        }
        dns_reply(persisted, what)
    }

    /// Replaces `[adblock] bypass`.
    pub async fn handle_dns_adblock_bypass_set(&self, clients: Vec<String>) -> Response {
        let clients = match parse_clients(&clients) {
            Ok(clients) => clients,
            Err(error) => return Response::Rejected { error },
        };
        dns_reply(
            self.change_adblock(|a| a.bypass = clients),
            "Adblock bypass updated".to_string(),
        )
    }

    /// Adds to and takes out of `[adblock] bypass`. Taking out a client that is not there is
    /// `NotFound` (a typo must not pass for done).
    pub async fn handle_dns_adblock_bypass_change(
        &self,
        add: Vec<String>,
        remove: Vec<String>,
    ) -> Response {
        let (add, remove) = match (parse_clients(&add), parse_clients(&remove)) {
            (Ok(add), Ok(remove)) => (add, remove),
            (Err(error), _) | (_, Err(error)) => return Response::Rejected { error },
        };
        let live = self.live_adblock_settings();
        if let Some(missing) = remove.iter().find(|c| !live.bypass.contains(c)) {
            return Response::NotFound {
                error: format!("client \"{missing}\" is not in the adblock bypass"),
            };
        }
        dns_reply(
            self.change_adblock(|a| edit_clients(&mut a.bypass, add, &remove)),
            "Adblock bypass updated".to_string(),
        )
    }

    /// Adds members to a group and takes members out of it. A list is named by its source name
    /// or URL, a client by its selector. Taking out a member the group does not have is
    /// `NotFound`; adding one it has changes nothing.
    pub async fn handle_dns_adblock_group_change(
        &self,
        name: String,
        change: AdblockGroupChange,
    ) -> Response {
        let (add_clients, remove_clients) = match (
            parse_clients(&change.add_clients),
            parse_clients(&change.remove_clients),
        ) {
            (Ok(add), Ok(remove)) => (add, remove),
            (Err(error), _) | (_, Err(error)) => return Response::Rejected { error },
        };
        let live = self.live_adblock_settings();
        let Some(group) = live.groups.iter().find(|g| g.name == name) else {
            return Response::NotFound {
                error: format!("adblock group \"{name}\""),
            };
        };
        let list_name = |text: &String| {
            live.sources
                .iter()
                .find(|s| &s.url == text)
                .and_then(|s| s.name.clone())
                .unwrap_or_else(|| text.clone())
        };
        let add_lists: Vec<String> = change.add_lists.iter().map(list_name).collect();
        let remove_lists: Vec<String> = change.remove_lists.iter().map(list_name).collect();
        let missing: Vec<String> = remove_lists
            .iter()
            .filter(|l| !group.lists.contains(l))
            .map(|l| format!("list \"{l}\""))
            .chain(
                remove_clients
                    .iter()
                    .filter(|c| !group.clients.contains(c))
                    .map(|c| format!("client \"{c}\"")),
            )
            .collect();
        if !missing.is_empty() {
            return Response::NotFound {
                error: format!("not in adblock group \"{name}\": {}", missing.join(", ")),
            };
        }
        dns_reply(
            self.change_adblock(|a| {
                if let Some(group) = a.groups.iter_mut().find(|g| g.name == name) {
                    for list in add_lists {
                        if !group.lists.contains(&list) {
                            group.lists.push(list);
                        }
                    }
                    group.lists.retain(|l| !remove_lists.contains(l));
                    edit_clients(&mut group.clients, add_clients, &remove_clients);
                }
            }),
            format!("Adblock group \"{name}\" updated"),
        )
    }

    /// Makes the device `mac` a member of exactly `groups` and bypassed or not (the `WebUI`'s
    /// device menu). See [`Self::set_device_adblock`].
    pub async fn handle_dns_adblock_device_set(
        &self,
        mac: MacAddr,
        groups: Vec<String>,
        bypass: bool,
    ) -> Response {
        self.set_device_adblock(mac, &groups, &[], Some(bypass), true)
    }

    /// Puts the device `mac` in the groups `join`, takes it out of `leave`, and bypasses it or
    /// not (`bypass`), leaving the rest as it is. Leaving a group that does not name the device
    /// is `NotFound`: it may be in it through a subnet, which only the group can change.
    pub async fn handle_dns_adblock_device_change(
        &self,
        mac: MacAddr,
        join: Vec<String>,
        leave: Vec<String>,
        bypass: Option<bool>,
    ) -> Response {
        self.set_device_adblock(mac, &join, &leave, bypass, false)
    }

    /// The device `mac` in the groups `join`, out of the groups `leave` (with `exact`: out of
    /// every group not in `join`), bypassed per `bypass` (`None`: as it is). It is added as
    /// `dev:<name>` (it keeps matching when an Android re-randomizes its MAC), or `dev:<mac>`
    /// without a name; a `dev:` selector naming it is removed where it is no longer wanted.
    /// Subnet selectors are left alone: a device in a group through its subnet stays in it.
    fn set_device_adblock(
        &self,
        mac: MacAddr,
        join: &[String],
        leave: &[String],
        bypass: Option<bool>,
        exact: bool,
    ) -> Response {
        let Some(device) = self.ctx.get_device(&mac) else {
            return Response::NotFound {
                error: format!("device {mac}"),
            };
        };
        let selector = if device.hostname.name.is_empty() {
            ClientSelector::Device(DeviceIdentifier::Mac(mac))
        } else {
            match DeviceIdentifier::from_str(&device.hostname.name) {
                Ok(id) => ClientSelector::Device(id),
                Err(_) => ClientSelector::Device(DeviceIdentifier::Mac(mac)),
            }
        };
        let names_it = |s: &ClientSelector| {
            s.needs_device()
                && s.matches(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(mac), Some(&device))
        };
        let known = self.live_adblock_settings();
        let group = |name: &String| known.groups.iter().find(|g| &g.name == name);
        if let Some(unknown) = join.iter().chain(leave).find(|n| group(n).is_none()) {
            return Response::NotFound {
                error: format!("adblock group \"{unknown}\""),
            };
        }
        if let Some(not_in) = leave
            .iter()
            .find(|n| group(n).is_some_and(|g| !g.clients.iter().any(names_it)))
        {
            return Response::NotFound {
                error: format!(
                    "device {mac} is not in adblock group \"{not_in}\" by name (a subnet of the group may still cover it)"
                ),
            };
        }
        let set = |clients: &mut Vec<ClientSelector>, wanted: bool| {
            if wanted {
                if !clients.iter().any(names_it) {
                    clients.push(selector.clone());
                }
            } else {
                clients.retain(|s| !names_it(s));
            }
        };
        dns_reply(
            self.change_adblock(|a| {
                for group in &mut a.groups {
                    if join.contains(&group.name) {
                        set(&mut group.clients, true);
                    } else if exact || leave.contains(&group.name) {
                        set(&mut group.clients, false);
                    }
                }
                if let Some(bypass) = bypass {
                    set(&mut a.bypass, bypass);
                }
            }),
            format!("Adblock groups of {mac} updated"),
        )
    }
}

/// `clients` with `add` appended (those it lacks) and `remove` taken out.
fn edit_clients(
    clients: &mut Vec<ClientSelector>,
    add: Vec<ClientSelector>,
    remove: &[ClientSelector],
) {
    for client in add {
        if !clients.contains(&client) {
            clients.push(client);
        }
    }
    clients.retain(|c| !remove.contains(c));
}
