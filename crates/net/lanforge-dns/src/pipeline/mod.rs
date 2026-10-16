pub mod middleware;

use lanforge_dns_wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_types::device::TransientOrigin;
use lanforge_types::network::dns::TransportProtocol;
use lanforge_types::network::dns::{DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, FilterMatch};
use lanforge_types::network::{Hostname, HostnameOrigin};
use lanforge_types::update::{DeviceUpdate, TransientHostUpdate};

use crate::error::DnsError;
use crate::resolver::recursive::UpstreamManager;
use crate::server::DnsContext;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

/// Represents a DNS query request passing through the pipeline.
#[derive(Clone)]
pub struct DnsPipelineRequest<'a> {
    pub data: &'a [u8],
    pub header: &'a WireHeader<'a>,
    pub question: &'a WireQuestion<'a>,
    pub src_ip: IpAddr,
    pub protocol: TransportProtocol,
    pub domain: Arc<str>,
    pub filter_match: &'a parking_lot::Mutex<Option<Box<FilterMatch>>>,
}

impl<'a> DnsPipelineRequest<'a> {
    pub fn new(
        data: &'a [u8],
        header: &'a WireHeader<'a>,
        question: &'a WireQuestion<'a>,
        src_ip: IpAddr,
        protocol: TransportProtocol,
        filter_match: &'a parking_lot::Mutex<Option<Box<FilterMatch>>>,
    ) -> Self {
        let domain = question.to_domain_lowercase_arc();
        Self {
            data,
            header,
            question,
            src_ip: src_ip.to_canonical(),
            protocol,
            domain,
            filter_match,
        }
    }
}

pub trait Middleware: Send + Sync {
    fn run_sync(
        &self,
        _ctx: &DnsContext,
        _req: &DnsPipelineRequest<'_>,
        _resp: &mut Vec<u8>,
    ) -> Option<Result<bool, DnsError>> {
        None
    }

    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        req: DnsPipelineRequest<'a>,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>>;
}

#[derive(Default)]
pub struct Pipeline {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    pub fn push<M: Middleware + 'static>(&mut self, m: M) {
        self.middlewares.push(Box::new(m));
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn run(
        &self,
        ctx: &DnsContext,
        req: DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<(), DnsError> {
        ctx.stats.inc_requests();
        ctx.stats.inc_protocol(req.protocol);

        // Trigger reverse DNS lookup in the background if the client IP is configured
        handle_reverse_dns_trigger(ctx, req.src_ip);

        for m in &self.middlewares {
            if let Some(res) = m.run_sync(ctx, &req, resp) {
                if res? {
                    return Ok(());
                }
                continue;
            }
            if m.run(ctx, req.clone(), resp).await? {
                return Ok(());
            }
        }
        Ok(())
    }
}

fn classify_transient_origin(ip: IpAddr) -> TransientOrigin {
    match ip {
        IpAddr::V4(v4) => {
            // 100.64.0.0/10 (Tailscale CGNAT space: 100.64.0.0 - 100.127.255.255)
            if (u32::from(v4) & 0xFFC0_0000) == 0x6440_0000 {
                TransientOrigin::Tailscale
            } else {
                TransientOrigin::LocalPtr
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // fd7a:115c:a1e0::/48 (Tailscale IPv6 ULA)
            if octets[0..6] == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0] {
                TransientOrigin::Tailscale
            } else {
                TransientOrigin::LocalPtr
            }
        }
    }
}

fn handle_reverse_dns_trigger(ctx: &DnsContext, client_ip: IpAddr) {
    if let Some(resolver) = ctx.local.ctx.find_reverse_resolver(client_ip)
        && ctx.local.ctx.get_transient_host(&client_ip).is_none()
    {
        let should_resolve = {
            let mut resolving = ctx.resolving_ips.lock();
            if resolving.contains(&client_ip) {
                false
            } else {
                resolving.insert(client_ip);
                true
            }
        };

        if should_resolve {
            let ctx_core = ctx.local.ctx.clone();
            let reverse_managers = ctx.reverse_managers.clone();
            let resolving_ips = ctx.resolving_ips.clone();
            let cache = ctx.cache.clone();

            tokio::spawn(async move {
                resolve_reverse_ptr_background(
                    ctx_core,
                    reverse_managers,
                    resolving_ips,
                    cache,
                    client_ip,
                    resolver,
                )
                .await;
            });
        }
    }
}

async fn resolve_reverse_ptr_background(
    ctx_core: lanforge_core::context::LanforgeContext,
    reverse_managers: Arc<
        parking_lot::RwLock<
            std::collections::HashMap<
                lanforge_types::network::dns::upstream::UpstreamTarget,
                Arc<UpstreamManager>,
            >,
        >,
    >,
    resolving_ips: Arc<parking_lot::Mutex<std::collections::HashSet<IpAddr>>>,
    cache: Arc<crate::resolver::recursive::DnsCache>,
    ip: IpAddr,
    resolver: lanforge_types::network::dns::upstream::UpstreamTarget,
) {
    // 1. Get or create UpstreamManager
    let mgr = {
        let read_guard = reverse_managers.read();
        read_guard.get(&resolver).cloned()
    };

    let mgr = match mgr {
        Some(m) => m,
        None => {
            let new_mgr = match UpstreamManager::new(&resolver, cache).await {
                Ok(new_mgr) => new_mgr,
                Err(e) => {
                    tracing::error!(
                        "❌ DNS: Failed to initialize reverse resolver UpstreamManager for {}: {}",
                        resolver.addr,
                        e
                    );
                    resolving_ips.lock().remove(&ip);
                    return;
                }
            };
            let mut write_guard = reverse_managers.write();
            if let Some(m) = write_guard.get(&resolver) {
                m.clone()
            } else {
                write_guard.insert(resolver.clone(), new_mgr.clone());
                new_mgr
            }
        }
    };

    // 2. Perform reverse PTR query
    let arpa_name = crate::utils::ip_to_arpa(ip);
    let mut query = DnsMessage::new();
    query.header.rd = true;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: std::sync::Arc::from(arpa_name),
        qtype: DnsRecordType::PTR,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let wire_query = encoder.encode_message(&query);

    match mgr.forward(&wire_query).await {
        Ok((resp_bytes, _cached, _blocked)) => {
            let mut decoder = WireDecoder::new(&resp_bytes);
            if let Some(msg) = decoder.decode_message() {
                let mut resolved_name = None;
                for ans in msg.answers {
                    if let DnsRData::PTR(ptr_name) = ans.rdata {
                        resolved_name = Some(ptr_name.to_string());
                        break;
                    }
                }

                if let Some(name) = resolved_name {
                    // Normalize the hostname: strip trailing dot if present
                    let name = name.strip_suffix('.').unwrap_or(&name).to_string();
                    if !name.is_empty() {
                        let origin = classify_transient_origin(ip);
                        let hostname = Hostname {
                            name,
                            origin: HostnameOrigin::Static,
                        };
                        let update = DeviceUpdate::TransientHostResolved(Box::new(
                            TransientHostUpdate {
                                ip,
                                hostname: hostname.clone(),
                                origin,
                            },
                        ));
                        if ctx_core.apply(update) {
                            tracing::info!(
                                "✅ DNS: Resolved transient host {} -> {}",
                                ip,
                                hostname.name
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "DNS: Reverse resolution failed for {} via resolver {}: {:?}",
                ip,
                resolver.addr,
                e
            );
        }
    }

    resolving_ips.lock().remove(&ip);
}
