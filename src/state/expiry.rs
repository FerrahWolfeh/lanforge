//! Manutenção periódica e índices de alta performance para o DNS.

use std::net::IpAddr;
use std::time::SystemTime;

use tracing::debug;

use crate::device::{IPv4State, IPv6State};

use super::DeviceTable;

impl DeviceTable {
    /// Remove leases expirados e devices dinâmicos inativos.
    /// Retorna `true` se houve mudança — dispara `DeviceTableDirty`.
    pub fn expire_stale(&mut self) -> bool {
        let now = SystemTime::now();
        let max_age = std::time::Duration::from_secs(7 * 24 * 3600);
        let ndp_max_age = std::time::Duration::from_secs(24 * 3600);
        let mut changed = false;

        let initial_ndp_len = self.ndp_cache.len();
        self.ndp_cache
            .retain(|_, (_, ts)| ts.elapsed().unwrap_or(std::time::Duration::ZERO) <= ndp_max_age);
        if self.ndp_cache.len() != initial_ndp_len {
            changed = true;
        }

        // Limpa leases órfãos expirados
        let initial_orphaned_len = self.orphaned_v6.len();
        self.orphaned_v6.retain(|_, (_, _, expires)| *expires > now);
        if self.orphaned_v6.len() != initial_orphaned_len {
            changed = true;
        }

        let macs: Vec<_> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut remove_device = false;
            if let Some(dev) = self.devices.get_mut(&mac) {
                // V4 expiration
                if let IPv4State::Dynamic(lease) = &dev.v4
                    && lease.expires < now
                {
                    dev.v4 = IPv4State::None;
                    changed = true;
                }
                // V6 expiration
                let initial_v6_len = dev.v6.len();
                dev.v6.retain(|state| match state {
                    IPv6State::Dynamic(lease) => lease.expires > now,
                    _ => true,
                });
                if dev.v6.len() != initial_v6_len {
                    changed = true;
                }

                let initial_prefixes_len = dev.v6_prefixes.len();
                dev.v6_prefixes.retain(|p| p.expires > now);
                if dev.v6_prefixes.len() != initial_prefixes_len {
                    changed = true;
                }

                if !dev.is_static()
                    && matches!(dev.v4, IPv4State::None)
                    && dev.v6.is_empty()
                    && dev.v6_prefixes.is_empty()
                    && dev.last_seen.elapsed().unwrap_or(std::time::Duration::ZERO) > max_age
                {
                    remove_device = true;
                }
            }

            if remove_device {
                if let Some(dev) = self.devices.remove(&mac)
                    && let Some(duid) = dev.duid
                {
                    self.duid_index.remove(&duid);
                }
                changed = true;
                debug!("[state] Removed stale dynamic device {}", mac);
            }
        }

        if changed {
            self.rebuild_dns_indices();
        }

        changed
    }

    // -----------------------------------------------------------------------
    // Índices de Alta Performance para o DNS (Hot Path)
    // -----------------------------------------------------------------------

    /// Reconstrói os índices O(1) do DNS do zero.
    /// Isso garante que não teremos IPs ou Hostnames fantasmas presos no cache
    /// após expirações de lease ou rotações de SLAAC.
    pub(crate) fn rebuild_dns_indices(&mut self) {
        self.name_index.clear();
        self.ip_index.clear();

        for (&mac, device) in &self.devices {
            let _static_entry = self.static_entries.get(&mac);

            // 1. Indexa o hostname explícito (sempre em minúsculas)
            if !device.hostname.is_empty() {
                self.name_index
                    .insert(device.hostname.to_ascii_lowercase(), mac);
            }

            // 2. Indexa o fallback obrigatório (host-<mac>)
            let fallback =
                format!("host-{}", mac.to_string().replace(':', "")).to_ascii_lowercase();
            self.name_index.insert(fallback, mac);

            // 3. Indexa IPv4 (Dinâmico e Estático)
            if let Some(ip) = device.v4.ip() {
                self.ip_index.insert(IpAddr::V4(ip), mac);
            }

            // 4. Indexa IPv6 (Dinâmico DHCPv6, SLAAC e Estático Full)
            for state in &device.v6 {
                if let Some(ip) = state.ip() {
                    self.ip_index.insert(IpAddr::V6(ip), mac);
                }
            }

            // Nota: IPs com sufixos estáticos (ex: ::10) compostos com ULA/GUA
            // não estão sendo indexados aqui porque dependem da `DnsConfig` (o prefixo real da rede).
        }

        self.name_index.shrink_to_fit();
        self.ip_index.shrink_to_fit();

        debug!(
            "[state] Índices DNS reconstruídos: {} nomes, {} IPs",
            self.name_index.len(),
            self.ip_index.len()
        );
    }
}
