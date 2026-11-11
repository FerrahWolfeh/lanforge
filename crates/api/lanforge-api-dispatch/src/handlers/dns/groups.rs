//! Adblock groups and `bypass` (`[adblock.groups.*]`, `[adblock] bypass`): list, create, edit,
//! delete, and a device's memberships. Every write goes through `change_adblock` (file, then
//! live), so a group change is a config change like any other.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use lanforge_api::api::{
    AdblockClientDevice, AdblockClientEntry, AdblockGroupEntry, DnsAdblockGroupsResponse, Response,
};
use lanforge_api::config_file::AdblockGroup;
use lanforge_core::context::state::State;
use lanforge_types::identifiers::{DeviceIdentifier, MacAddr};
use lanforge_types::network::dns::adblock::ClientSelector;
use lanforge_types::network::dns::adblock::rules_file::RulesFile;

use crate::ClientContext;
use crate::handlers::dns::rewrite::dns_reply;

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

    /// Removes `[adblock.groups.<name>]`. Its rules file stays on disk.
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
        dns_reply(
            self.change_adblock(|a| a.groups.retain(|g| g.name != name)),
            format!("Adblock group \"{name}\" removed"),
        )
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

    /// Makes the device `mac` a member of exactly `groups` and bypassed or not. It is added as
    /// `dev:<name>` (it keeps matching when an Android re-randomizes its MAC), or `dev:<mac>`
    /// without a name; a `dev:` selector naming it is removed where it is no longer wanted.
    /// Subnet selectors are left alone: a device in a group through its subnet stays in it.
    pub async fn handle_dns_adblock_device_set(
        &self,
        mac: MacAddr,
        groups: Vec<String>,
        bypass: bool,
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
        let known = self.live_adblock_settings();
        if let Some(unknown) = groups
            .iter()
            .find(|name| !known.groups.iter().any(|g| &&g.name == name))
        {
            return Response::NotFound {
                error: format!("adblock group \"{unknown}\""),
            };
        }
        let names_it = |s: &ClientSelector| {
            s.needs_device()
                && s.matches(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(mac), Some(&device))
        };
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
                    set(&mut group.clients, groups.contains(&group.name));
                }
                set(&mut a.bypass, bypass);
            }),
            format!("Adblock groups of {mac} updated"),
        )
    }
}
