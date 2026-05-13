pub mod middleware;

use crate::error::DnsError;
use crate::server::DnsContext;
use crate::wire::{WireHeader, WireQuestion};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

pub trait Middleware: Send + Sync {
    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        data: &'a [u8],
        header: &'a WireHeader,
        question: &'a WireQuestion<'a>,
        src_ip: IpAddr,
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
        data: &[u8],
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
        src_ip: IpAddr,
        resp: &mut Vec<u8>,
    ) -> Result<(), DnsError> {
        ctx.stats.inc_requests();
        for m in &self.middlewares {
            if m.run(ctx, data, header, question, src_ip, resp).await? {
                return Ok(());
            }
        }
        Ok(())
    }
}
