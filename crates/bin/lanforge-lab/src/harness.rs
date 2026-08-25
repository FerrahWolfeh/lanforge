use std::net::{Ipv4Addr, SocketAddr};

use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::DnsRecordType;

use crate::engine::{DhcpEngine, DiscoveryEngine, DnsEngine, RaEngine};
use crate::error::LabError;
use crate::netns::{NetnsConfig, NetnsManager};
use crate::report::SuiteReport;

/// Operating mode of the Lab Harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabMode {
    /// Direct mode: Unprivileged socket communication (e.g. localhost ports, zero sudo).
    Direct,
    /// Full Netns mode: Kernel network namespaces and veth pairs (requires `root/CAP_NET_ADMIN`).
    Netns,
    /// Interface mode: Targeting a pre-existing host interface.
    Interface,
}

/// Central orchestrator and harness for Lanforge laboratory testing.
pub struct LabHarness {
    pub mode: LabMode,
    pub dhcp_target: SocketAddr,
    pub dns_target: SocketAddr,
    pub iface: Option<String>,
    pub netns_mgr: Option<NetnsManager>,
}

impl LabHarness {
    /// Automatically selects the best available mode: Netns if root, otherwise Direct.
    pub fn auto() -> Result<Self, LabError> {
        if NetnsManager::has_privileges() {
            Self::setup_netns(NetnsConfig::default())
        } else {
            Self::setup_direct()
        }
    }

    /// Sets up the harness in Direct / Unprivileged mode (no root or sudo needed).
    pub fn setup_direct() -> Result<Self, LabError> {
        Ok(Self {
            mode: LabMode::Direct,
            dhcp_target: "127.0.0.1:1067".parse().unwrap(),
            dns_target: "127.0.0.1:1053".parse().unwrap(),
            iface: None,
            netns_mgr: None,
        })
    }

    /// Sets up the harness targeting specific server socket endpoints.
    #[must_use]
    pub const fn with_endpoints(
        mut self,
        dhcp_target: SocketAddr,
        dns_target: SocketAddr,
    ) -> Self {
        self.dhcp_target = dhcp_target;
        self.dns_target = dns_target;
        self
    }

    /// Sets up the harness in full Kernel Network Namespace mode (requires sudo / root).
    pub fn setup_netns(cfg: NetnsConfig) -> Result<Self, LabError> {
        let mut mgr = NetnsManager::new(cfg, true);
        mgr.setup()?;

        let host_iface = mgr.config().host_iface.clone();
        let dhcp_target = SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)),
            67,
        );
        let dns_target = SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)),
            53,
        );

        Ok(Self {
            mode: LabMode::Netns,
            dhcp_target,
            dns_target,
            iface: Some(host_iface),
            netns_mgr: Some(mgr),
        })
    }

    /// Sets up the harness targeting an existing host interface.
    #[must_use]
    pub fn targeting_interface(iface: &str, dhcp_port: u16, dns_port: u16) -> Self {
        Self {
            mode: LabMode::Interface,
            dhcp_target: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)),
                dhcp_port,
            ),
            dns_target: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)),
                dns_port,
            ),
            iface: Some(iface.to_string()),
            netns_mgr: None,
        }
    }

    /// Returns the active operating mode.
    #[must_use]
    pub const fn mode(&self) -> LabMode {
        self.mode
    }

    /// Accessor for the DHCP simulation engine.
    #[must_use]
    pub const fn dhcp(&self) -> DhcpEngine {
        DhcpEngine::new(self.dhcp_target)
    }

    /// Accessor for the DNS simulation engine.
    #[must_use]
    pub const fn dns(&self) -> DnsEngine {
        DnsEngine::new(self.dns_target)
    }

    /// Accessor for the Router Advertisement engine.
    #[must_use]
    pub fn ra(&self) -> RaEngine {
        RaEngine::new(self.iface.clone())
    }

    /// Accessor for the Discovery and mDNS engine.
    #[must_use]
    pub const fn discovery(&self) -> DiscoveryEngine {
        DiscoveryEngine
    }

    /// Executes the full end-to-end regression test suite.
    pub async fn run_full_suite(&self) -> Result<SuiteReport, LabError> {
        let mac = MacAddr([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

        // 1. Test DHCP DORA
        let dora_res = self.dhcp().simulate_dora(mac, Some("lab-suite-device")).await.ok();
        let dhcp_dora_passed = dora_res.as_ref().is_some_and(|r| r.success);

        // 2. Test Local DNS resolution
        let mut dns_results = Vec::new();
        let q_local = self.dns().query("lanforge.lan", DnsRecordType::A).await.ok();
        let dns_local_passed = q_local.as_ref().is_some_and(|r| r.rcode == "NoError");
        if let Some(r) = q_local {
            dns_results.push(r);
        }

        // 3. Test Adblock DNS query
        let q_adblock = self.dns().query("doubleclick.net", DnsRecordType::A).await.ok();
        let dns_adblock_passed = q_adblock.as_ref().is_some_and(|r| r.is_blocked || r.answers.contains(&"0.0.0.0".to_string()));
        if let Some(r) = q_adblock {
            dns_results.push(r);
        }

        // 4. Test Upstream / Public DNS query
        let q_upstream = self.dns().query("google.com", DnsRecordType::A).await.ok();
        let dns_upstream_passed = q_upstream.as_ref().is_some_and(|r| r.rcode == "NoError" && !r.answers.is_empty());
        if let Some(r) = q_upstream {
            dns_results.push(r);
        }

        let all_passed = dhcp_dora_passed && dns_local_passed && dns_adblock_passed && dns_upstream_passed;

        Ok(SuiteReport {
            dhcp_dora_passed,
            dhcp_result: dora_res,
            dns_local_passed,
            dns_adblock_passed,
            dns_upstream_passed,
            dns_results,
            all_passed,
        })
    }
}
