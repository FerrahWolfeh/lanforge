use crate::ClientContext;
use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, Response, SimpleSuccess, SystemConfigExport,
};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::AdblockDbConfig;

impl ClientContext {
    pub async fn handle_system_config_export(&self) -> Response {
        // 1. Hosts
        let hosts = if let Response::Hosts(res) = self.handle_hosts().await {
            res.hosts
        } else {
            Vec::new()
        };

        // 2. DNS Rewrites
        let dns_rewrites = if let Response::DnsRewrites(res) = self.handle_dns_rewrites().await {
            res.rewrites
        } else {
            Vec::new()
        };

        // 3. DNS Upstreams
        let dns_upstreams = match self.db.load_dns_upstreams().await {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|row| {
                    let addr = row.addr.parse().ok()?;
                    let protocol = row.protocol.parse().ok()?;
                    Some(DnsUpstreamConfig {
                        addr,
                        protocol,
                        domain: row.domain,
                    })
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // 4. Adblock Config
        let dns_adblock_config = self.db.load_adblock_config().await.unwrap_or_default();

        // 5. Adblock URLs
        let dns_adblock_urls = match self.db.load_adblock_urls().await {
            Ok(rows) => rows
                .into_iter()
                .map(|(id, url, kind)| AdblockUrlEntry {
                    id: Some(id),
                    url,
                    kind,
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // 6. DNS Allowlist
        let dns_allowlist = match self.db.load_dns_allowlist().await {
            Ok(rows) => rows
                .into_iter()
                .map(|(id, domain)| AllowlistEntry { id, domain })
                .collect(),
            Err(_) => Vec::new(),
        };

        Response::SystemConfig(Box::new(SystemConfigExport {
            hosts,
            dns_rewrites,
            dns_upstreams,
            dns_adblock_config,
            dns_adblock_urls,
            dns_allowlist,
            overwrite: false,
        }))
    }

    pub async fn handle_system_config_import(&self, config: SystemConfigExport) -> Response {
        let SystemConfigExport {
            hosts,
            dns_rewrites,
            dns_upstreams,
            dns_adblock_config,
            dns_adblock_urls,
            dns_allowlist,
            overwrite,
        } = config;

        let mut total_success = true;
        let mut messages = Vec::new();

        if overwrite {
            // Clear existing static hosts
            let devices = self.ctx.all_devices();
            for dev in &devices {
                if dev.origin != lanforge_types::device::Origin::Dynamic {
                    let _ = self
                        .ctx
                        .apply(lanforge_types::update::DeviceUpdate::Remove(dev.mac));
                }
            }

            // Clear DNS rewrites, upstreams, adblock URLs, allowlist
            if let Err(e) = self.db.clear_dns_rewrites().await {
                total_success = false;
                messages.push(format!("Failed to clear DNS rewrites: {e}"));
            }
            if let Err(e) = self.db.clear_dns_upstreams().await {
                total_success = false;
                messages.push(format!("Failed to clear DNS upstreams: {e}"));
            }
            if let Err(e) = self.db.clear_adblock_urls().await {
                total_success = false;
                messages.push(format!("Failed to clear Adblock URLs: {e}"));
            }
            if let Err(e) = self.db.clear_dns_allowlist().await {
                total_success = false;
                messages.push(format!("Failed to clear DNS allowlist: {e}"));
            }
        }

        // 1. Import hosts
        let res = self.handle_host_import(hosts).await;
        if let Response::Success(s) = res {
            messages.push(s.message);
        } else if let Response::Error { error } = res {
            total_success = false;
            messages.push(format!("Host import error: {error}"));
        }

        // 2. Import DNS rewrites
        let res = self.handle_dns_rewrite_import(dns_rewrites).await;
        if let Response::Success(s) = res {
            messages.push(s.message);
        } else if let Response::Error { error } = res {
            total_success = false;
            messages.push(format!("DNS rewrite import error: {error}"));
        }

        // 3. Import DNS upstreams
        let mut upstream_count = 0;
        for u in dns_upstreams {
            let res = self
                .handle_dns_upstream_add(u.addr, u.protocol, u.domain)
                .await;
            if let Response::Success(_) = res {
                upstream_count += 1;
            } else if let Response::Error { error } = res {
                total_success = false;
                messages.push(format!("Upstream import error: {error}"));
            }
        }
        messages.push(format!(
            "Successfully imported {upstream_count} DNS upstreams"
        ));

        // 4. Import Adblock Config
        let AdblockDbConfig {
            enabled,
            blocking_mode,
            blocking_ip_v4,
            blocking_ip_v6,
            refresh_hours,
            refresh_at_night,
        } = dns_adblock_config;

        let mut adblock_cfg_success = true;
        if let Err(e) = self
            .db
            .set_adblock_config_value("enabled", if enabled { "true" } else { "false" })
            .await
        {
            adblock_cfg_success = false;
            total_success = false;
            messages.push(format!("Adblock config import error: {e}"));
        }
        if let Err(e) = self
            .db
            .set_adblock_config_value("blocking_mode", &blocking_mode.to_string())
            .await
        {
            adblock_cfg_success = false;
            total_success = false;
            messages.push(format!("Adblock config import error: {e}"));
        }
        if let Some(ip) = blocking_ip_v4
            && let Err(e) = self
                .db
                .set_adblock_config_value("blocking_ip_v4", &ip.to_string())
                .await
        {
            adblock_cfg_success = false;
            total_success = false;
            messages.push(format!("Adblock config import error: {e}"));
        }
        if let Some(ip) = blocking_ip_v6
            && let Err(e) = self
                .db
                .set_adblock_config_value("blocking_ip_v6", &ip.to_string())
                .await
        {
            adblock_cfg_success = false;
            total_success = false;
            messages.push(format!("Adblock config import error: {e}"));
        }
        if let Err(e) = self
            .db
            .set_adblock_config_value("refresh_hours", &refresh_hours.to_string())
            .await
        {
            adblock_cfg_success = false;
            total_success = false;
            messages.push(format!("Adblock config import error: {e}"));
        }
        if let Err(e) = self
            .db
            .set_adblock_config_value(
                "refresh_at_night",
                if refresh_at_night { "true" } else { "false" },
            )
            .await
        {
            adblock_cfg_success = false;
            total_success = false;
            messages.push(format!("Adblock config import error: {e}"));
        }
        if adblock_cfg_success {
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
            messages.push("Successfully imported Adblock configuration".to_string());
        }

        // 5. Import Adblock URLs
        let mut url_count = 0;
        for u in dns_adblock_urls {
            let res = self.handle_dns_adblock_url_add(u.url, u.kind).await;

            if let Response::Success(_) = res {
                url_count += 1;
            } else if let Response::Error { error } = res {
                total_success = false;
                messages.push(format!("Adblock URL import error: {error}"));
            }
        }
        messages.push(format!("Successfully imported {url_count} Adblock URLs"));

        // 6. Import DNS allowlist
        let mut allow_count = 0;
        for a in dns_allowlist {
            let res = self.handle_dns_allow(a.domain).await;
            if let Response::Success(_) = res {
                allow_count += 1;
            } else if let Response::Error { error } = res {
                total_success = false;
                messages.push(format!("Allowlist import error: {error}"));
            }
        }
        messages.push(format!(
            "Successfully imported {allow_count} DNS allowlist entries"
        ));

        if total_success {
            Response::Success(SimpleSuccess {
                message: messages.join("; "),
            })
        } else {
            Response::Error {
                error: messages.join("; "),
            }
        }
    }
}
