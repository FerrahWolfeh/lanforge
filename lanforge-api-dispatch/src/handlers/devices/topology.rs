use super::super::format_iso8601;
use lanforge_api::api::{Response, TopologyEntry, TopologyResponse};
use crate::ClientContext;

impl ClientContext {
    pub async fn handle_topology(&self) -> Response {
        let mut entries = Vec::new();

        for dev in self.ctx.all_devices() {
            if let Some(topo) = &dev.topology {
                entries.push(TopologyEntry {
                    mac: dev.mac.to_string(),
                    hostname: dev.display_hostname().to_string(),
                    parent_mac: topo.parent_mac.map(|m| m.to_string()),
                    port: topo.port.clone(),
                    local_ifindex: topo.local_ifindex,
                    last_updated: format_iso8601(topo.last_updated),
                });
            }
        }

        Response::Topology(TopologyResponse { entries })
    }
}
