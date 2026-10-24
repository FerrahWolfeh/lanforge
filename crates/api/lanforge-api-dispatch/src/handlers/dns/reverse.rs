use crate::ClientContext;
use lanforge_api::api::{DnsReverseResolversResponse, Response, SimpleSuccess};
use lanforge_db_core::Stores;
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
            Ok(r) => r,
            Err(e) => {
                return Response::Error {
                    error: format!("Invalid resolver URI: {e}"),
                };
            }
        };

        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let r_clone = resolver.clone();
        if let Err(e) = storage
            .call(move |s: &Stores| s.db().add_dns_reverse_resolver(&subnet, &r_clone))
            .await
        {
            return Response::Error { error: e.to_string() };
        }

        self.ctx.add_reverse_resolver(DnsReverseResolver { subnet, resolver });

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

        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        if let Err(e) = storage
            .call(move |s: &Stores| s.db().remove_dns_reverse_resolver(&subnet))
            .await
        {
            return Response::Error { error: e.to_string() };
        }

        self.ctx.remove_reverse_resolver(subnet);

        Response::Success(SimpleSuccess {
            message: "Reverse resolver removed successfully".to_string(),
        })
    }

    pub async fn handle_dns_reverse_resolver_list(&self) -> Response {
        let resolvers = self.ctx.all_reverse_resolvers();
        Response::DnsReverseResolvers(DnsReverseResolversResponse { resolvers })
    }
}
