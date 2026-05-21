use std::time::UNIX_EPOCH;

use crate::ClientContext;
use lanforge_api::api::{Response, TopologyEntry, TopologyResponse};

impl ClientContext {
    pub async fn handle_topology(&self) -> Response {
        let mut entries = Vec::new();

        for dev in self.ctx.all_devices() {
            if let Some(topo) = &dev.topology {
                entries.push(TopologyEntry {
                    mac: dev.mac,
                    hostname: dev.display_hostname().to_string(),
                    parent_mac: topo.parent_mac,
                    port: topo.port.clone(),
                    local_ifindex: topo.local_ifindex,
                    last_updated: topo
                        .last_updated
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                });
            }
        }

        Response::Topology(TopologyResponse { entries })
    }
}
