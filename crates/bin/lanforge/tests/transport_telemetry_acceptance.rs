use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_dhcp::v4::io::Dhcpv4Transport;
use lanforge_dhcp::v6::io::Dhcpv6Transport;
use lanforge_dhcp::{Dhcpv4Config, Dhcpv4Service, Dhcpv6Config, Dhcpv6Service};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_pppoe::{PppoeConfig, PppoeService};
use lanforge_ra::{RaConfig, RaService};
use lanforge_tftp::{TftpConfig, TftpService};
use lanforge_transport::{Icmp6Transport, PppoeTransport, UdpTransport};

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    (ctx, bus)
}

#[tokio::test]
async fn test_transport_telemetry_in_service_banners() {
    let (ctx, _bus) = create_test_context();

    // 1. DHCPv4 Service Banner Transport Telemetry
    {
        let (handle, transport) = Dhcpv4Transport::inert();
        handle
            .inject(vec![1, 2, 3, 4], SocketAddr::from(([127, 0, 0, 1], 68)))
            .await;
        let mut buf = [0u8; 64];
        let (n, _src) = transport.recv(&mut buf).await.unwrap();
        assert_eq!(n, 4);

        let service =
            Dhcpv4Service::with_transport(Dhcpv4Config::default(), ctx.clone(), transport);
        let banner = service.banner(&ctx);
        let t = banner
            .transport
            .expect("DHCPv4 must surface transport telemetry in banner");
        assert_eq!(t.rx_packets, 1);
        assert_eq!(t.rx_bytes, 4);
    }

    // 2. DHCPv6 Service Banner Transport Telemetry
    {
        let (handle, transport) = Dhcpv6Transport::inert();
        handle
            .inject(
                vec![10, 20, 30],
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 546)),
            )
            .await;
        let mut buf = [0u8; 64];
        let (n, _src) = transport.recv(&mut buf).await.unwrap();
        assert_eq!(n, 3);

        let service =
            Dhcpv6Service::with_transport(Dhcpv6Config::default(), ctx.clone(), transport);
        let banner = service.banner(&ctx);
        let t = banner
            .transport
            .expect("DHCPv6 must surface transport telemetry in banner");
        assert_eq!(t.rx_packets, 1);
        assert_eq!(t.rx_bytes, 3);
    }

    // 3. IPv6 RA Service Banner Transport Telemetry
    {
        let (handle, transport) = Icmp6Transport::inert();
        handle
            .inject(
                vec![0x85, 0x00, 0x00, 0x00],
                SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0),
            )
            .await;
        let mut buf = [0u8; 64];
        let (n, _src) = transport.recv(&mut buf).await.unwrap();
        assert_eq!(n, 4);

        let service = RaService::with_transport(RaConfig::default(), ctx.clone(), transport);
        let banner = service.banner(&ctx);
        let t = banner
            .transport
            .expect("RA must surface transport telemetry in banner");
        assert_eq!(t.rx_packets, 1);
        assert_eq!(t.rx_bytes, 4);
    }

    // 4. DNS Service Banner Transport Telemetry
    {
        let (udp_handle, udp_transport) = UdpTransport::inert();
        udp_handle
            .inject(
                vec![1, 2, 3, 4, 5, 6, 7],
                SocketAddr::from(([127, 0, 0, 1], 10053)),
            )
            .await;
        let mut buf = [0u8; 64];
        let (n, _src) = udp_transport.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 7);

        let service = DnsService::with_transport(DnsConfig::default(), ctx.clone(), udp_transport);
        let banner = service.banner(&ctx);
        let t = banner
            .transport
            .expect("DNS must surface transport telemetry in banner");
        assert_eq!(t.rx_packets, 1);
        assert_eq!(t.rx_bytes, 7);
    }

    // 5. PPPoE Service Banner Transport Telemetry
    {
        let (handle, transport) = PppoeTransport::inert();
        handle.inject_discovery(vec![1, 2, 3, 4, 5, 6, 7, 8]).await;
        let mut buf = [0u8; 64];
        let n = transport.recv_discovery(&mut buf).await.unwrap();
        assert_eq!(n, 8);

        let service = PppoeService::with_transport(PppoeConfig::default(), ctx.clone(), transport);
        let banner = service.banner(&ctx);
        let t = banner
            .transport
            .expect("PPPoE must surface transport telemetry in banner");
        assert_eq!(t.rx_packets, 1);
        assert_eq!(t.rx_bytes, 8);
    }

    // 6. TFTP Service Banner Transport Telemetry
    {
        let (handle, transport) = UdpTransport::inert();
        handle
            .inject(
                vec![0x00, 0x01, b't', b'e', b's', b't', 0x00],
                SocketAddr::from(([127, 0, 0, 1], 50069)),
            )
            .await;
        let mut buf = [0u8; 64];
        let (n, _src) = transport.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 7);

        let service =
            TftpService::with_transports(ctx.clone(), TftpConfig::default(), vec![transport]);
        let banner = service.banner(&ctx);
        let t = banner
            .transport
            .expect("TFTP must surface transport telemetry in banner");
        assert_eq!(t.rx_packets, 1);
        assert_eq!(t.rx_bytes, 7);
    }
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
}

#[test]
fn test_zero_mock_architecture_grep_guard() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("Failed to locate workspace root")
        .to_path_buf();

    let net_crates = [
        "lanforge-dhcp",
        "lanforge-ra",
        "lanforge-dns",
        "lanforge-pppoe",
        "lanforge-tftp",
        "lanforge-discovery",
        "lanforge-wol",
    ];

    let mut violations = Vec::new();

    for crate_name in &net_crates {
        let crate_src = workspace_root
            .join("crates/net")
            .join(crate_name)
            .join("src");
        let mut files = Vec::new();
        collect_rs_files(&crate_src, &mut files);

        for file in files {
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            for (line_no, line) in content.lines().enumerate() {
                // Disallow inert: bool in service field declarations
                if line.trim().starts_with("inert: bool")
                    || line.trim().starts_with("pub inert: bool")
                    || line.trim().starts_with("pub(crate) inert: bool")
                {
                    violations.push(format!(
                        "{}:{}: Found forbidden 'inert: bool' field",
                        file.display(),
                        line_no + 1
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Zero-mock architecture violations found:\n{}",
        violations.join("\n")
    );
}
