use super::rewrite::dns_reply;
use crate::ClientContext;
use lanforge_api::api::{DnsReverseResolversResponse, Response};
use lanforge_types::network::{DnsReverseResolver, IpSubnet, dns::upstream::UpstreamTarget};

impl ClientContext {
    pub async fn handle_dns_reverse_resolver_add(
        &self,
        subnet_str: String,
        resolver_str: String,
    ) -> Response {
        let subnet = match subnet_str.parse::<IpSubnet>() {
            Ok(s) => s,
            Err(e) => {
                return Response::Error {
                    error: format!("Invalid subnet: {e}"),
                };
            }
        };
        let resolver = match resolver_str.parse::<UpstreamTarget>() {
            Ok(r) if r.host_name().is_some() => {
                return Response::Rejected {
                    error: "A reverse resolver needs an IP address, not a host name".into(),
                };
            }
            Ok(r) => r,
            Err(e) => {
                return Response::Error {
                    error: format!("Invalid resolver URI: {e}"),
                };
            }
        };

        dns_reply(
            self.change_dns(|dns| {
                dns.reverse.retain(|r| r.subnet != subnet);
                dns.reverse.push(DnsReverseResolver { subnet, resolver });
            }),
            "Reverse resolver added successfully".to_string(),
        )
    }

    pub async fn handle_dns_reverse_resolver_remove(&self, subnet_str: String) -> Response {
        let subnet = match subnet_str.parse::<IpSubnet>() {
            Ok(s) => s,
            Err(e) => {
                return Response::Error {
                    error: format!("Invalid subnet: {e}"),
                };
            }
        };

        dns_reply(
            self.change_dns(|dns| dns.reverse.retain(|r| r.subnet != subnet)),
            "Reverse resolver removed successfully".to_string(),
        )
    }

    pub async fn handle_dns_reverse_resolver_list(&self) -> Response {
        let resolvers = self.ctx.all_reverse_resolvers();
        Response::DnsReverseResolvers(DnsReverseResolversResponse { resolvers })
    }
}
