use crate::ClientContext;
use lanforge_api::api::{DnsReverseResolversResponse, Response, SimpleSuccess};
use lanforge_types::network::{IpSubnet, dns::upstream::UpstreamTarget};

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

        if let Err(e) = storage
            .send_query(lanforge_types::storage::StorageQuery::AddReverseResolver {
                subnet,
                resolver,
            })
            .await
        {
            return Response::Error { error: e };
        }

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
            .send_query(lanforge_types::storage::StorageQuery::RemoveReverseResolver(
                subnet,
            ))
            .await
        {
            return Response::Error { error: e };
        }

        Response::Success(SimpleSuccess {
            message: "Reverse resolver removed successfully".to_string(),
        })
    }

    pub async fn handle_dns_reverse_resolver_list(&self) -> Response {
        let resolvers = self.ctx.all_reverse_resolvers();
        Response::DnsReverseResolvers(DnsReverseResolversResponse { resolvers })
    }
}
