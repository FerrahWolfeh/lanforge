pub mod middleware;

use lanforge_core::types::network::dns::TransportProtocol;

use crate::error::DnsError;
use crate::server::DnsContext;
use crate::wire::{WireHeader, WireQuestion};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// Represents a DNS query request passing through the pipeline.
#[derive(Clone, Copy)]
pub struct DnsPipelineRequest<'a> {
    pub data: &'a [u8],
    pub header: &'a WireHeader<'a>,
    pub question: &'a WireQuestion<'a>,
    pub src_ip: IpAddr,
    pub protocol: TransportProtocol,
}

impl<'a> DnsPipelineRequest<'a> {
    pub fn new(
        data: &'a [u8],
        header: &'a WireHeader<'a>,
        question: &'a WireQuestion<'a>,
        src_ip: IpAddr,
        protocol: TransportProtocol,
    ) -> Self {
        Self {
            data,
            header,
            question,
            src_ip,
            protocol,
        }
    }
}

pub trait Middleware: Send + Sync {
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

    pub async fn run(
        &self,
        ctx: &DnsContext,
        req: DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<(), DnsError> {
        ctx.stats.inc_requests();
        ctx.stats.inc_protocol(req.protocol);

        for m in &self.middlewares {
            if m.run(ctx, req, resp).await? {
                return Ok(());
            }
        }
        Ok(())
    }
}
