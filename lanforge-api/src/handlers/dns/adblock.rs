use crate::api::{AdblockUrlEntry, DnsAdblockStatusResponse, DnsAdblockUrlsResponse, Response, SimpleSuccess};
use crate::server::ClientContext;
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_dns::server::DnsContext;
use std::sync::atomic::Ordering;
use tracing::error;

#[cfg(feature = "adblock")]
use lanforge_core::config::AdblockUrlKind;
#[cfg(feature = "adblock")]
use std::str::FromStr;

impl ClientContext {
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Response {
        if duration_secs.is_none() {
            // Persistent change
            let val = if enabled { "true" } else { "false" };
            if let Err(e) = self.db.set_adblock_config_value("enabled", val).await {
                error!("❌ API: Failed to persist adblock enabled status: {e}");
            }
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
        }

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
                enabled,
                duration_secs,
            }));

        Response::Success(SimpleSuccess {
            message: if enabled {
                "DNS Adblock enabled".to_string()
            } else if let Some(d) = duration_secs {
                format!("DNS Adblock disabled for {d} seconds")
            } else {
                "DNS Adblock disabled permanently in database".to_string()
            },
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_set(
        &self,
        _enabled: bool,
        _duration_secs: Option<u64>,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockReload));
        Response::Success(SimpleSuccess {
            message: "Adblock reload triggered".to_string(),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_reload(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_status(&self) -> Response {
        let Some(dns_ctx_any) = self.ctx.get_dns_context() else {
            return Response::Error {
                error: "DNS service not initialized".into(),
            };
        };
        let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>() else {
            return Response::Error {
                error: "Invalid DNS context".into(),
            };
        };
        let Some(adblocker) = &dns_ctx.filter else {
            return Response::Error {
                error: "Adblocker is not enabled in this build".into(),
            };
        };

        Response::DnsAdblockStatus(DnsAdblockStatusResponse {
            enabled: adblocker.is_enabled(),
            disabled_until: {
                let until = adblocker.timer.disabled_until.load(Ordering::Relaxed);
                if until == 0 { None } else { Some(until) }
            },
            remaining_secs: adblocker.timer.remaining_secs(),
            blocklist_size: adblocker.blocklist_size(),
            allowlist_size: adblocker.allowlist_size(),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_status(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_add(&self, url: String, kind: String) -> Response {
        let kind_enum = AdblockUrlKind::from_str(&kind).unwrap_or(AdblockUrlKind::Blocklist);
        match self.db.add_adblock_url(&url, kind_enum).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
                Response::Success(SimpleSuccess {
                    message: format!("Adblock {kind} URL added: {url}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_add(&self, _url: String, _kind: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_remove(&self, url: String) -> Response {
        match self.db.remove_adblock_url(&url).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
                Response::Success(SimpleSuccess {
                    message: format!("Adblock URL removed: {url}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_remove(&self, _url: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_list(&self) -> Response {
        match self.db.load_adblock_urls().await {
            Ok(urls) => Response::DnsAdblockUrls(DnsAdblockUrlsResponse {
                urls: urls
                    .into_iter()
                    .map(|(id, url, kind)| AdblockUrlEntry {
                        id: Some(id),
                        url,
                        kind: kind.to_string(),
                    })
                    .collect(),
            }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_list(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }
}
