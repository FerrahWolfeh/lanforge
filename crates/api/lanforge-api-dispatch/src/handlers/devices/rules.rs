use crate::ClientContext;
use lanforge_api::api::{DevicePortForward, DeviceRulesResponse, RefusedName, Response};
use lanforge_core::context::LanforgeContext;
use lanforge_types::identifiers::{DeviceIdentifier, MacAddr};
use lanforge_types::network::dns::adblock::RewriteAnswer;
use lanforge_types::network::firewall::ForwardTarget;
use std::net::IpAddr;

/// Whether a rewrite answer gives `mac`'s address or names it, following a fallback only where
/// the DNS would.
fn answers_device(ctx: &LanforgeContext, mac: MacAddr, answer: &RewriteAnswer) -> bool {
    match answer {
        RewriteAnswer::A(ip) => ctx.get_mac_by_ip(IpAddr::V4(*ip)) == Some(mac),
        RewriteAnswer::Aaaa(ip) => ctx.get_mac_by_ip(IpAddr::V6(*ip)) == Some(mac),
        RewriteAnswer::Cname(_) => false,
        // The DNS answers with the fallback only when the reference names no device.
        RewriteAnswer::Device {
            identifier,
            fallback,
        } => match ctx.resolve_device(identifier) {
            Some(target) => target == mac,
            None => fallback
                .as_deref()
                .is_some_and(|fb| answers_device(ctx, mac, fb)),
        },
    }
}

impl ClientContext {
    /// What the daemon itself resolves to one device: where forwards land now, the forwards and
    /// rewrites that reach it (a `dev:` reference through `resolve_device`, a fixed address
    /// through the address index) and its name bindings.
    pub async fn handle_device_rules(&self, mac: MacAddr) -> Response {
        let ctx = &self.ctx;
        if ctx.get_device(&mac).is_none() {
            return Response::NotFound {
                error: format!("Device {mac} not found"),
            };
        }
        let addrs = ctx
            .forward_addresses(&DeviceIdentifier::Mac(mac))
            .unwrap_or_default();
        let port_forwards = ctx
            .get_firewall_config()
            .map(|fw| fw.port_forwards)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .filter_map(|(index, rule)| {
                let by_device = match &rule.internal_ip {
                    ForwardTarget::Device(id) => {
                        (ctx.resolve_device(id) == Some(mac)).then_some(true)
                    }
                    ForwardTarget::Ip(ip) => (ctx.get_mac_by_ip(*ip) == Some(mac)).then_some(false),
                }?;
                Some(DevicePortForward {
                    index,
                    rule,
                    by_device,
                })
            })
            .collect();
        let rewrites = ctx
            .get_dns_rewrites()
            .into_iter()
            .filter(|r| answers_device(ctx, mac, &r.answer))
            .map(|mut r| {
                if r.id.is_none() {
                    r.id = Some(r.effective_id());
                }
                r
            })
            .collect();
        let bound_names = ctx
            .name_bindings()
            .into_iter()
            .filter(|(_, bound)| *bound == mac)
            .map(|(name, _)| name)
            .collect();
        Response::DeviceRules(Box::new(DeviceRulesResponse {
            forward_v4: addrs.v4,
            forward_v6: addrs.v6,
            port_forwards,
            rewrites,
            bound_names,
            refused_name: ctx
                .refused_name(mac)
                .map(|(name, owner)| RefusedName { name, owner }),
        }))
    }
}
