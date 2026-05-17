use color_eyre::eyre::{bail, Result};
use inquire::{Confirm, Select, Text};
use std::fmt::Display;

use crate::cli::LanforgeClient;
use lanforge_api::api::{
    AdblockUrlEntry, AllowlistEntry, AuthTokenEntry, DeviceEntry, HostConfigEntry, LeaseEntry,
};
use lanforge_types::network::dns::adblock::RewriteRule;

struct DeviceItem(DeviceEntry);
impl Display for DeviceItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = if self.0.hostname.is_empty() { "—" } else { &self.0.hostname };
        write!(f, "{:<20} | {:<20} | {}", self.0.mac, host, self.0.display_v4)
    }
}

struct HostItem(HostConfigEntry);
impl Display for HostItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<20} | {:<20} | {}",
            self.0.mac,
            self.0.hostname,
            self.0.v4_fixed.as_deref().unwrap_or("—")
        )
    }
}

struct LeaseItem(LeaseEntry);
impl Display for LeaseItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = if self.0.hostname.is_empty() { "—" } else { &self.0.hostname };
        write!(f, "{:<20} | {:<20} | {}", self.0.mac, host, self.0.address)
    }
}

struct TokenItem(AuthTokenEntry);
impl Display for TokenItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ID: {:<5} | Name: {}", self.0.id, self.0.name)
    }
}

struct RewriteItem(RewriteRule);
impl Display for RewriteItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<30} -> {}", self.0.domain, self.0.answer)
    }
}

struct AllowlistItem(AllowlistEntry);
impl Display for AllowlistItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ID: {:<5} | Domain: {}", self.0.id, self.0.domain)
    }
}

struct AdblockSourceItem(AdblockUrlEntry);
impl Display for AdblockSourceItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:<10}] {}", self.0.kind.to_uppercase(), self.0.url)
    }
}

pub async fn fuzzy_select_device(client: &LanforgeClient, prompt: &str) -> Result<DeviceEntry> {
    let resp = client
        .list_devices(None, None, None, None, None, None)
        .await?;
    if resp.devices.is_empty() {
        bail!("No devices found on the network.");
    }
    let items: Vec<DeviceItem> = resp.devices.into_iter().map(DeviceItem).collect();
    let selected = Select::new(prompt, items).prompt()?;
    Ok(selected.0)
}

pub async fn fuzzy_select_host(client: &LanforgeClient, prompt: &str) -> Result<HostConfigEntry> {
    let resp = client.host_list().await?;
    if resp.hosts.is_empty() {
        bail!("No configured hosts found.");
    }
    let items: Vec<HostItem> = resp.hosts.into_iter().map(HostItem).collect();
    let selected = Select::new(prompt, items).prompt()?;
    Ok(selected.0)
}

pub async fn fuzzy_select_lease(client: &LanforgeClient, prompt: &str) -> Result<LeaseEntry> {
    let resp = client.leases(false).await?;
    if resp.leases.is_empty() {
        bail!("No active DHCP leases found.");
    }
    let items: Vec<LeaseItem> = resp.leases.into_iter().map(LeaseItem).collect();
    let selected = Select::new(prompt, items).prompt()?;
    Ok(selected.0)
}

pub async fn fuzzy_select_token(client: &LanforgeClient, prompt: &str) -> Result<AuthTokenEntry> {
    let resp = client.ak_list().await?;
    if resp.tokens.is_empty() {
        bail!("No API tokens found.");
    }
    let items: Vec<TokenItem> = resp.tokens.into_iter().map(TokenItem).collect();
    let selected = Select::new(prompt, items).prompt()?;
    Ok(selected.0)
}

pub async fn fuzzy_select_rewrite(client: &LanforgeClient, prompt: &str) -> Result<RewriteRule> {
    let resp = client.dns_rewrites().await?;
    if resp.rewrites.is_empty() {
        bail!("No DNS rewrite rules found.");
    }
    let items: Vec<RewriteItem> = resp.rewrites.into_iter().map(RewriteItem).collect();
    let selected = Select::new(prompt, items).prompt()?;
    Ok(selected.0)
}

pub async fn fuzzy_select_allowlist(client: &LanforgeClient, prompt: &str) -> Result<AllowlistEntry> {
    let resp = client.dns_allowlist().await?;
    if resp.allowlist.is_empty() {
        bail!("No DNS allowlist entries found.");
    }
    let items: Vec<AllowlistItem> = resp.allowlist.into_iter().map(AllowlistItem).collect();
    let selected = Select::new(prompt, items).prompt()?;
    Ok(selected.0)
}

pub async fn fuzzy_select_adblock_source(
    client: &LanforgeClient,
    prompt: &str,
) -> Result<AdblockUrlEntry> {
    let resp = client.dns_adblock_url_list().await?;
    if resp.urls.is_empty() {
        bail!("No DNS adblock sources found.");
    }
    let items: Vec<AdblockSourceItem> = resp.urls.into_iter().map(AdblockSourceItem).collect();
    let selected = Select::new(prompt, items).prompt()?;
    Ok(selected.0)
}

pub fn prompt_text(prompt: &str, default: Option<&str>) -> Result<String> {
    let mut t = Text::new(prompt);
    if let Some(d) = default {
        t = t.with_default(d);
    }
    Ok(t.prompt()?)
}

pub fn prompt_select<T: Display + PartialEq>(prompt: &str, items: Vec<T>) -> Result<T> {
    Ok(Select::new(prompt, items).prompt()?)
}

pub fn confirm_destructive(client: &LanforgeClient, prompt: &str) -> Result<bool> {
    if client.yes {
        return Ok(true);
    }
    Ok(Confirm::new(prompt).with_default(false).prompt()?)
}

pub fn confirm_wipe(client: &LanforgeClient) -> Result<bool> {
    if client.yes {
        return Ok(true);
    }
    let first = Confirm::new("Are you absolutely sure you want to reset the database?")
        .with_default(false)
        .prompt()?;
    if !first {
        return Ok(false);
    }
    let second = Text::new("Type 'wipe' to confirm reset:").prompt()?;
    Ok(second == "wipe")
}
