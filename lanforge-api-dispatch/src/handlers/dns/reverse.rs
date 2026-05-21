use crate::ClientContext;
use lanforge_api::api::{DnsReverseResolversResponse, Response, SimpleSuccess};
use lanforge_types::{
    network::{DnsReverseResolver, IpSubnet, dns::upstream::UpstreamTarget},
    update::DeviceUpdate,
};

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
            Ok(r) => r,
            Err(e) => {
                return Response::Error {
                    error: format!("Invalid resolver URI: {e}"),
                };
            }
        };

        if let Err(e) = self.db.add_dns_reverse_resolver(&subnet, &resolver).await {
            return Response::Error {
                error: e.to_string(),
            };
        }

        let _ = self.ctx.apply(DeviceUpdate::AddReverseResolver {
            resolver: DnsReverseResolver { subnet, resolver },
        });

        Response::Success(SimpleSuccess {
            message: "Reverse resolver added successfully".to_string(),
        })
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

        if let Err(e) = self.db.remove_dns_reverse_resolver(&subnet).await {
            return Response::Error {
                error: e.to_string(),
            };
        }

        let _ = self
            .ctx
            .apply(DeviceUpdate::RemoveReverseResolver { subnet });

        Response::Success(SimpleSuccess {
            message: "Reverse resolver removed successfully".to_string(),
        })
    }

    pub async fn handle_dns_reverse_resolver_list(&self) -> Response {
        let resolvers = self.ctx.all_reverse_resolvers();
        Response::DnsReverseResolvers(DnsReverseResolversResponse { resolvers })
    }
}
