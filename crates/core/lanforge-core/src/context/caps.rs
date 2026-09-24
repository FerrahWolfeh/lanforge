use lanforge_types::system::{Cap, ServerCapabilities};
use smallvec::SmallVec;

pub struct CompiledCaps;

impl CompiledCaps {
    /// Returns the baseline list of compiled capabilities known to the system.
    #[must_use]
    pub fn detect_default_compiled() -> SmallVec<[Cap; 32]> {
        let mut compiled = SmallVec::new();
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
        compiled.push(Cap::Storage);
        compiled.push(Cap::Pppoe);
        compiled.push(Cap::Tftp);
        compiled.push(Cap::Firewall);
        compiled.push(Cap::Traffic);
        compiled.push(Cap::Adblock);
        compiled.push(Cap::Webui);
        compiled
    }

    /// Detects and returns a fallback `ServerCapabilities` snapshot.
    #[must_use]
    pub fn detect() -> ServerCapabilities {
        let compiled = Self::detect_default_compiled();
        let enabled = compiled.clone();
        ServerCapabilities { compiled, enabled }
    }
}
