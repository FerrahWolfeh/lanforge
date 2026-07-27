use lanforge_types::system::{Cap, ServerCapabilities};
use smallvec::SmallVec;

pub struct CompiledCaps;

impl CompiledCaps {
    /// Detects and returns the compiled and runtime enabled server capabilities.
    #[must_use]
    pub fn detect() -> ServerCapabilities {
        let mut compiled = SmallVec::new();
        let mut enabled = SmallVec::new();

        // Core compiled features
        compiled.push(Cap::Dns);
        compiled.push(Cap::UpstreamUdpTcp);
        compiled.push(Cap::UpstreamDoT);
        compiled.push(Cap::UpstreamDoQ);
        compiled.push(Cap::UpstreamDoH);
        compiled.push(Cap::DohDownstream);
        compiled.push(Cap::DhcpV4);
        compiled.push(Cap::DhcpV6);
        compiled.push(Cap::Ra);
        compiled.push(Cap::NdpDiscovery);
        compiled.push(Cap::MdnsProbe);
        compiled.push(Cap::Uds);
        compiled.push(Cap::Http);
        compiled.push(Cap::Zstd);
        compiled.push(Cap::Sqlite);
        compiled.push(Cap::Postgresql);
        compiled.push(Cap::Pppoe);

        // Enabled features (simulated/detected runtime configuration)
        enabled.push(Cap::Dns);
        enabled.push(Cap::UpstreamDoT);
        enabled.push(Cap::DhcpV4);
        enabled.push(Cap::Ra);
        enabled.push(Cap::Uds);
        enabled.push(Cap::Http);
        enabled.push(Cap::Sqlite);

        ServerCapabilities { compiled, enabled }
    }
}
