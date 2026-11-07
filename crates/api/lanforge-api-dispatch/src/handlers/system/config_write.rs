use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};

use lanforge_api::api::Response;
use lanforge_api::config_file::{
    AdblockFile, AdblockSettings, ConfigFile, DhcpSettings, DnsFile, DnsSettings, FirewallFile,
    NamedUpstream, RaFile, SectionSet, persist_sections, write_toml_atomically,
};
use lanforge_core::context::ConfigPatch;
use lanforge_crypto::stable_id_or_hash;
use lanforge_types::device::{Origin, StaticHost};
use lanforge_types::identifiers::DeviceIdentifier;
use lanforge_types::network::DnsReverseResolver;
use lanforge_types::network::dns::adblock::{ClientSelector, RewriteAnswer};
use lanforge_types::network::firewall::{FirewallConfig, ForwardTarget};
use lanforge_types::network::ra::RaServerConfig;

use crate::ClientContext;

/// Why a configuration change was not made: nothing was written nor applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeError {
    /// The value is refused (the file form cannot hold it, a conflict): the caller's to fix.
    Rejected(String),
    /// The item the change names does not exist.
    NotFound(String),
    /// The configuration file could not be written: the server's failure.
    Failed(String),
}

impl ChangeError {
    /// The reason, for the user.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Rejected(e) | Self::NotFound(e) | Self::Failed(e) => e,
        }
    }

    /// The API reply, its reason prefixed with `context` ("DNS configuration not saved", ...).
    /// A failure to write is logged: it is the server's, not the user's.
    #[must_use]
    pub fn response_in(self, context: &str) -> Response {
        let error = format!("{context}: {}", self.reason());
        match self {
            Self::Rejected(_) => Response::Rejected { error },
            Self::NotFound(_) => Response::NotFound { error },
            Self::Failed(_) => {
                tracing::error!("{error}");
                Response::Error { error }
            }
        }
    }
}

impl fmt::Display for ChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl From<ChangeError> for Response {
    fn from(e: ChangeError) -> Self {
        match e {
            ChangeError::Rejected(error) => Self::Rejected { error },
            ChangeError::NotFound(error) => Self::NotFound { error },
            ChangeError::Failed(error) => {
                tracing::error!("configuration not saved: {error}");
                Self::Error { error }
            }
        }
    }
}

/// Whether a config change reached the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persisted {
    /// Written to the config file.
    File,
    /// The config file is read-only (or unknown): the change lives in memory only.
    MemoryOnly,
}

impl Persisted {
    /// The success message for a change of `what`.
    #[must_use]
    pub fn message(self, what: &str) -> String {
        match self {
            Self::File => format!("{what} updated successfully"),
            Self::MemoryOnly => format!(
                "{what} updated in memory only, not saved: the configuration file is read-only or not set"
            ),
        }
    }
}

impl ClientContext {
    /// Writes the `sections` set by `fill` into the config file (file-owned sections, see
    /// `phase-7-config-storage`). Call it **before** applying the change in memory: an error
    /// means nothing was written and the change must be rejected.
    pub fn persist_config_sections(
        &self,
        sections: SectionSet,
        fill: impl FnOnce(&mut ConfigFile),
    ) -> Result<Persisted, ChangeError> {
        if !self.ctx.is_config_writable() {
            return Ok(Persisted::MemoryOnly);
        }
        let Some(path) = self.ctx.config_path() else {
            return Ok(Persisted::MemoryOnly);
        };
        let mut cfg = ConfigFile::default();
        fill(&mut cfg);
        let _file_guard = self.ctx.config_file_lock();
        persist_sections(&path, &cfg, sections)
            .map(|()| Persisted::File)
            .map_err(|e| ChangeError::Failed(format!("cannot write {}: {e}", path.display())))
    }

    /// Writes `fw` to `[firewall]` (see [`Self::persist_config_sections`]). Zones are keyed by
    /// name in the file, so a zone defined twice cannot be written and is refused.
    pub fn persist_firewall(&self, fw: &FirewallConfig) -> Result<Persisted, ChangeError> {
        let mut seen = HashSet::new();
        if let Some(dup) = fw.zones.iter().find(|z| !seen.insert(z.name.as_str())) {
            return Err(ChangeError::Rejected(format!(
                "zone '{}' is defined twice",
                dup.name
            )));
        }
        self.persist_config_sections(SectionSet::FIREWALL, |file| {
            file.firewall = FirewallFile::from_config(fw);
        })
    }

    /// Changes the DHCP options and/or pools: `change` edits the live settings, the result is
    /// written to `[dhcp]` and `[tftp]` (see [`Self::persist_config_sections`]) and then
    /// applied as the file now holds it (unnamed pools are named, repeated names made unique).
    /// A value the file form cannot hold (a pool whose first address is past its last, ...) is
    /// refused: nothing written, nothing applied.
    pub fn change_dhcp(
        &self,
        change: impl FnOnce(&mut DhcpSettings),
    ) -> Result<Persisted, ChangeError> {
        let _serial = self.ctx.config_change_lock();
        let live = DhcpSettings {
            options: self.ctx.get_dhcp_options(),
            v4_pools: self.ctx.get_dhcp_v4_pools(),
            v6_pools: self.ctx.get_dhcp_v6_pools(),
        };
        let mut wanted = live.clone();
        change(&mut wanted);
        let mut file = ConfigFile::default();
        file.set_dhcp_settings(&wanted);
        let (dhcp, issues) = file.dhcp_settings();
        if !issues.is_empty() {
            return Err(ChangeError::Rejected(issues.join("; ")));
        }
        let persisted = self.persist_config_sections(SectionSet::DHCP | SectionSet::TFTP, |f| {
            f.dhcp = file.dhcp;
            f.tftp = file.tftp;
        })?;
        let mut patch = ConfigPatch::new();
        if dhcp.options != live.options {
            patch = patch.with_dhcp_options(dhcp.options);
        }
        if dhcp.v4_pools != live.v4_pools {
            patch = patch.with_dhcp_v4_pools(dhcp.v4_pools);
        }
        if dhcp.v6_pools != live.v6_pools {
            patch = patch.with_dhcp_v6_pools(dhcp.v6_pools);
        }
        let _ = self.ctx.apply_config(patch);
        Ok(persisted)
    }

    /// Changes the RA configuration: `change` edits the live one, the result is written to
    /// `[ra]` (see [`Self::persist_config_sections`]) and then applied as the file now holds it.
    /// The LAN interface the daemon fills in is not written (the file follows `[system] iface`).
    /// A value the file form cannot hold (a prefix address that is not IPv6, ...) is refused:
    /// nothing written, nothing applied.
    pub fn change_ra(
        &self,
        change: impl FnOnce(&mut RaServerConfig),
    ) -> Result<Persisted, ChangeError> {
        let _serial = self.ctx.config_change_lock();
        let mut wanted = self.ctx.get_ra_server_config();
        change(&mut wanted);
        let lan_iface = self.ctx.target_interface_name();
        if wanted.iface.is_some() && wanted.iface == lan_iface {
            wanted.iface = None;
        }
        let file = RaFile::from_config(&wanted);
        let (mut ra, issues) = file.to_config();
        if !issues.is_empty() {
            return Err(ChangeError::Rejected(issues.join("; ")));
        }
        let persisted = self.persist_config_sections(SectionSet::RA, |f| f.ra = file)?;
        if ra.iface.is_none() {
            ra.iface = lan_iface;
        }
        let _ = self.ctx.apply_config(ConfigPatch::new().with_ra(ra));
        Ok(persisted)
    }

    /// Changes the static hosts: `change` edits the live ones (`ctx.static_hosts`), the result is
    /// written to `[hosts]` (see [`Self::persist_config_sections`]) and the device table is made
    /// to follow it (`apply_static_hosts`: a host left out becomes a discovered device again).
    /// A host the file form cannot hold, or the router itself, is refused: nothing written,
    /// nothing applied.
    pub fn change_hosts(
        &self,
        change: impl FnOnce(&mut Vec<StaticHost>),
    ) -> Result<Persisted, ChangeError> {
        let _serial = self.ctx.config_change_lock();
        let mut wanted = self.ctx.static_hosts();
        change(&mut wanted);
        if let Some(router) = wanted.iter().find(|h| {
            self.ctx
                .get_device(&h.mac)
                .is_some_and(|d| d.origin == Origin::System)
        }) {
            return Err(ChangeError::Rejected(format!(
                "{} is this router; not a static host",
                router.mac
            )));
        }
        let mut file = ConfigFile::default();
        file.set_static_hosts(&wanted);
        let (hosts, issues) = file.static_hosts();
        if !issues.is_empty() {
            return Err(ChangeError::Rejected(issues.join("; ")));
        }

        // A renamed host keeps what names it: `dev:<old name>` in port forwards, DNS rewrites
        // and adblock selectors becomes `dev:<new name>`, written with the hosts and applied
        // with them.
        let renames = renamed_hosts(&self.ctx.static_hosts(), &hosts);
        let mut sections = SectionSet::HOSTS;
        let mut firewall = self.ctx.get_firewall_config();
        let mut dns = None;
        let mut adblock = None;
        if !renames.is_empty() {
            if let Some(fw) = firewall.as_mut()
                && rename_all(
                    &renames,
                    fw.port_forwards.iter_mut().map(|pf| &mut pf.internal_ip),
                    ForwardTarget::rename_device,
                )
            {
                sections |= SectionSet::FIREWALL;
            }
            let mut live_dns = self.live_dns_settings();
            if rename_all(
                &renames,
                live_dns.rewrites.iter_mut().map(|r| &mut r.answer),
                RewriteAnswer::rename_device,
            ) {
                sections |= SectionSet::DNS;
                dns = Some(live_dns);
            }
            let mut live_adblock = self.live_adblock_settings();
            let selectors = live_adblock.bypass.iter_mut().chain(
                live_adblock
                    .groups
                    .iter_mut()
                    .flat_map(|g| g.clients.iter_mut()),
            );
            if rename_all(&renames, selectors, ClientSelector::rename_device) {
                sections |= SectionSet::ADBLOCK;
                adblock = Some(live_adblock);
            }
        }
        let firewall = firewall.filter(|_| sections.contains(SectionSet::FIREWALL));

        let persisted = self.persist_config_sections(sections, |f| {
            f.hosts = file.hosts;
            if let Some(fw) = &firewall {
                f.firewall = FirewallFile::from_config(fw);
            }
            if let Some(dns) = &dns {
                f.dns = DnsFile::from_config(dns);
            }
            if let Some(adblock) = &adblock {
                f.adblock = AdblockFile::from_config(adblock);
            }
        })?;
        let _ = self.ctx.apply_static_hosts(&hosts);
        let mut patch = ConfigPatch::new();
        if let Some(fw) = firewall {
            patch = patch.with_firewall(fw);
        }
        if let Some(dns) = dns {
            patch = self.dns_settings_patch(patch, dns);
        }
        let _ = self.ctx.apply_config(patch);
        Ok(persisted)
    }

    /// The DNS settings running now, as `[dns]` holds them: upstreams, mode, rewrites and
    /// reverse resolvers are the live ones; the listener and the upstream group names are not
    /// kept in memory and come from the file (an upstream it does not name is named after the
    /// domain it forwards, else `default`).
    pub(crate) fn live_dns_settings(&self) -> DnsSettings {
        let file = self
            .ctx
            .config_path()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| ConfigFile::parse_lenient(&text).ok())
            .map(|(cfg, _)| cfg.dns.to_config().0)
            .unwrap_or_default();
        let upstreams = self
            .ctx
            .get_dns_upstreams()
            .into_iter()
            .map(|target| NamedUpstream {
                name: file
                    .upstreams
                    .iter()
                    .find(|u| u.target == target)
                    .map(|u| u.name.clone())
                    .or_else(|| target.domain.clone())
                    .unwrap_or_else(|| "default".to_string()),
                target,
            })
            .collect();
        DnsSettings {
            enabled: file.enabled,
            listen: file.listen,
            upstream_mode: self.ctx.get_dns_upstream_mode(),
            upstreams,
            reverse: self.ctx.all_reverse_resolvers(),
            rewrites: self.ctx.get_dns_rewrites(),
        }
    }

    /// Changes the DNS settings: `change` edits the live ones, the result is written to `[dns]`
    /// (see [`Self::persist_config_sections`]) and then applied as the file now holds it. A value
    /// the file form cannot hold (a rewrite whose type does not fit its answer, ...) is refused:
    /// nothing written, nothing applied.
    pub fn change_dns(
        &self,
        change: impl FnOnce(&mut DnsSettings),
    ) -> Result<Persisted, ChangeError> {
        let _serial = self.ctx.config_change_lock();
        let mut wanted = self.live_dns_settings();
        change(&mut wanted);
        let file = DnsFile::from_config(&wanted);
        let (dns, issues) = file.to_config();
        if !issues.is_empty() {
            return Err(ChangeError::Rejected(issues.join("; ")));
        }
        let persisted = self.persist_config_sections(SectionSet::DNS, |f| f.dns = file)?;
        self.apply_dns_settings(dns);
        Ok(persisted)
    }

    /// Applies the parts of `dns` that differ from the live settings. The listener is bound at
    /// start-up and is not changed here.
    pub fn apply_dns_settings(&self, dns: DnsSettings) {
        let reverse = dns.reverse.clone();
        let _ = self
            .ctx
            .apply_config(self.dns_settings_patch(ConfigPatch::new(), dns));
        self.sync_reverse_resolvers(reverse);
    }

    /// `patch` plus the upstreams, mode and rewrites of `dns` that differ from the live ones.
    /// The reverse resolvers are not part of it: see [`Self::sync_reverse_resolvers`].
    pub(crate) fn dns_settings_patch(
        &self,
        mut patch: ConfigPatch,
        dns: DnsSettings,
    ) -> ConfigPatch {
        let upstreams: Vec<_> = dns.upstreams.into_iter().map(|u| u.target).collect();
        if self.ctx.get_dns_upstreams() != upstreams {
            patch = patch.with_dns_upstreams(upstreams);
        }
        if self.ctx.get_dns_upstream_mode() != dns.upstream_mode {
            patch = patch.with_dns_upstream_mode(dns.upstream_mode);
        }
        if self.ctx.get_dns_rewrites() != dns.rewrites {
            patch = patch.with_dns_rewrites(dns.rewrites);
        }
        patch
    }

    /// The reverse resolvers live in the device state and the config store at once;
    /// `set_reverse_resolvers` keeps both.
    pub(crate) fn sync_reverse_resolvers(&self, reverse: Vec<DnsReverseResolver>) {
        if self.ctx.all_reverse_resolvers() != reverse {
            self.ctx.set_reverse_resolvers(reverse);
        }
    }

    /// The adblock settings running now, as `[adblock]` holds them: the filter settings and the
    /// global layer (its sources, in order) are the live ones; the groups, `bypass`, the rules
    /// path and the sources no layer uses are not kept in memory and come from the file.
    pub(crate) fn live_adblock_settings(&self) -> AdblockSettings {
        let mut adblock = self
            .ctx
            .config_path()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| ConfigFile::parse_lenient(&text).ok())
            .map(|(cfg, _)| cfg.adblock.to_config().0)
            .unwrap_or_default();
        let mut sources: Vec<_> = self
            .ctx
            .get_dns_adblock_urls()
            .into_iter()
            .map(|mut s| {
                s.id = None;
                s.name = Some(stable_id_or_hash(
                    s.name.as_deref(),
                    s.url.as_bytes(),
                    "src",
                ));
                s
            })
            .collect();
        adblock.lists = sources.iter().filter_map(|s| s.name.clone()).collect();
        for unused in mem::take(&mut adblock.sources) {
            if !sources
                .iter()
                .any(|s| s.url == unused.url || s.name == unused.name)
            {
                sources.push(unused);
            }
        }
        adblock.sources = sources;
        adblock.config = self.ctx.get_dns_adblock();
        adblock
    }

    /// Changes the adblock settings: `change` edits the live ones, the result is written to
    /// `[adblock]` (see [`Self::persist_config_sections`]) and then applied as the file now holds
    /// it. A value the file form refuses (a source without an http(s) URL, a list name that is
    /// not a source, ...) is refused: nothing written, nothing applied. Issues the file already
    /// had (a hand-written source no layer uses) do not block an unrelated change.
    pub fn change_adblock(
        &self,
        change: impl FnOnce(&mut AdblockSettings),
    ) -> Result<Persisted, ChangeError> {
        let _serial = self.ctx.config_change_lock();
        let live = self.live_adblock_settings();
        let (_, known) = AdblockFile::from_config(&live).to_config();
        let mut wanted = live;
        change(&mut wanted);
        let file = AdblockFile::from_config(&wanted);
        let (adblock, issues) = file.to_config();
        let new: Vec<String> = issues.into_iter().filter(|i| !known.contains(i)).collect();
        if !new.is_empty() {
            return Err(ChangeError::Rejected(new.join("; ")));
        }
        let persisted = self.persist_config_sections(SectionSet::ADBLOCK, |f| f.adblock = file)?;
        self.apply_adblock_settings(&adblock);
        Ok(persisted)
    }

    /// Applies the filter settings and the global layer's sources of `adblock` that differ from
    /// the live ones. The rules file is applied by [`Self::change_adblock_rules`] / the reload.
    pub fn apply_adblock_settings(&self, adblock: &AdblockSettings) {
        let _ = self
            .ctx
            .apply_config(self.adblock_settings_patch(ConfigPatch::new(), adblock));
    }

    /// `patch` plus the filter settings and global sources of `adblock` that differ from the
    /// live ones.
    pub(crate) fn adblock_settings_patch(
        &self,
        mut patch: ConfigPatch,
        adblock: &AdblockSettings,
    ) -> ConfigPatch {
        let sources: Vec<_> = adblock.global_sources().cloned().collect();
        if self.ctx.get_dns_adblock() != adblock.config {
            patch = patch.with_dns_adblock(adblock.config.clone());
        }
        if self.ctx.get_dns_adblock_urls() != sources {
            patch = patch.with_dns_adblock_urls(sources);
        }
        patch
    }

    /// Changes the global adblock rules file: `change` gets the live text and returns the new
    /// one, or `None` when nothing changes. The file `[adblock] rules` names is written before
    /// the text applies; without one, `adblock/global.rules` is created and named in
    /// `[adblock]`. A read-only config applies in memory only.
    pub fn change_adblock_rules(
        &self,
        change: impl FnOnce(&str) -> Result<Option<String>, ChangeError>,
    ) -> Result<Persisted, ChangeError> {
        let _serial = self.ctx.config_change_lock();
        let live = self.ctx.get_dns_adblock_rules();
        let Some(text) = change(&live)? else {
            return Ok(Persisted::File);
        };
        let persisted = match self.ctx.config_path() {
            Some(path) if self.ctx.is_config_writable() => {
                let mut adblock = self.live_adblock_settings();
                let named = adblock.rules.is_some();
                if !named {
                    adblock.rules = Some(AdblockSettings::DEFAULT_RULES.to_string());
                }
                let rules_path = adblock.rules_path(&path).unwrap_or_default();
                if let Some(dir) = rules_path.parent() {
                    fs::create_dir_all(dir).map_err(|e| {
                        ChangeError::Failed(format!("cannot create {}: {e}", dir.display()))
                    })?;
                }
                write_toml_atomically(&rules_path, &text).map_err(|e| {
                    ChangeError::Failed(format!("cannot write {}: {e}", rules_path.display()))
                })?;
                if !named {
                    let file = AdblockFile::from_config(&adblock);
                    self.persist_config_sections(SectionSet::ADBLOCK, |f| f.adblock = file)?;
                }
                Persisted::File
            }
            _ => Persisted::MemoryOnly,
        };
        let _ = self
            .ctx
            .apply_config(ConfigPatch::new().with_dns_adblock_rules(text));
        Ok(persisted)
    }

    /// The configuration file as it is on disk: every section lives in it (the adblock rules
    /// have their own file), so it is the whole configuration.
    pub fn export_system_config_toml(&self) -> Result<String, String> {
        let path = self
            .resolve_config_path()
            .ok_or_else(|| "no configuration file".to_string())?;
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    }

    /// Resolves the candidate configuration file path for writes.
    #[must_use]
    pub fn resolve_config_path(&self) -> Option<PathBuf> {
        if let Some(p) = self.ctx.config_path() {
            if let Some(parent) = p.parent() {
                if parent.as_os_str().is_empty() || parent.exists() {
                    return Some(p);
                }
            } else {
                return Some(p);
            }
        }

        let candidates = ["/etc/lanforge/lanforge.toml", "lanforge.toml"];
        for c in candidates {
            let p = Path::new(c);
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }
        None
    }
}

/// `(old name, new name)` of every static host whose name changed (same MAC) to one a `dev:`
/// reference can hold.
fn renamed_hosts(before: &[StaticHost], after: &[StaticHost]) -> Vec<(String, DeviceIdentifier)> {
    before
        .iter()
        .filter_map(|old| {
            let new = after.iter().find(|h| h.mac == old.mac)?;
            if old.hostname.is_empty() || new.hostname.eq_ignore_ascii_case(&old.hostname) {
                return None;
            }
            match new.hostname.parse::<DeviceIdentifier>() {
                Ok(id @ DeviceIdentifier::Name(_)) => Some((old.hostname.clone(), id)),
                _ => None,
            }
        })
        .collect()
}

/// Applies every rename to every reference; whether any changed.
fn rename_all<'a, T: 'a>(
    renames: &[(String, DeviceIdentifier)],
    refs: impl Iterator<Item = &'a mut T>,
    rename: impl Fn(&mut T, &str, &DeviceIdentifier) -> bool,
) -> bool {
    let mut changed = false;
    for item in refs {
        for (old, new) in renames {
            changed |= rename(item, old, new);
        }
    }
    changed
}
