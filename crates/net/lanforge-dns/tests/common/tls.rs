//! Fixtures for the encrypted listeners: a self-signed `localhost` certificate and a running
//! DNS service with `DoT`/`DoQ` on loopback ports. Included with `#[path]` by the test files
//! that need it, next to `mod common`.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns_wire::WireHeader;
use lanforge_types::DnsListenConfig;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::ListenConfig;
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::system::ServiceId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::common::{
    DnsPacketBuilder, init_test_context, mock_config, register_test_device, wait_for_service_online,
};

/// The address the test device `nas.lan` resolves to.
pub const NAS_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

pub struct SelfSigned {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: rustls::pki_types::CertificateDer<'static>,
}

#[must_use]
pub fn self_signed() -> SelfSigned {
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed certificate");
    SelfSigned {
        cert_pem: certified.cert.pem(),
        key_pem: certified.signing_key.serialize_pem(),
        cert_der: certified.cert.der().clone(),
    }
}

/// A rustls client config that trusts only `cert`.
#[must_use]
pub fn client_config(cert: &SelfSigned, alpn: &[u8]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert_der.clone()).expect("trust test cert");
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !alpn.is_empty() {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    config
}

/// A free loopback port for both TCP and UDP.
#[must_use]
pub fn free_port() -> u16 {
    loop {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .expect("ephemeral port");
        if std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

pub struct RunningDns {
    pub ctx: LanforgeContext,
    pub dot: SocketAddr,
    pub doq: SocketAddr,
    pub cmd_tx: mpsc::Sender<ServiceCommand>,
    pub serve: JoinHandle<Result<(), CoreError>>,
}

impl RunningDns {
    /// Starts DNS with plain DNS, `DoT` and `DoQ` on fresh loopback ports and a device `nas`.
    pub async fn start(cert: &SelfSigned) -> Self {
        let ctx = init_test_context();
        register_test_device(&ctx, "nas", MacAddr([2, 0, 0, 0, 0, 0x50]), NAS_IP);
        let dot = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let doq = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        ctx.update_dns_listen(DnsListenConfig {
            enabled: true,
            listen: ListenConfig::Single(SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))),
            dot_listen: Some(dot),
            dot_enabled: true,
            doq_listen: Some(doq),
            doq_enabled: true,
            tls_cert: Some(cert.cert_pem.clone()),
            tls_key: Some(cert.key_pem.clone()),
        });
        let cfg = DnsConfig {
            enabled: true,
            ..mock_config()
        };
        let mut service = DnsService::new(cfg, ctx.clone());
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
        let ctx_serve = ctx.clone();
        let serve = tokio::spawn(async move { service.serve(&ctx_serve, &h).await });
        wait_for_service_online(&ctx, ServiceId::Dns).await;
        // Let the listeners bind.
        tokio::time::sleep(Duration::from_millis(100)).await;
        Self {
            ctx,
            dot,
            doq,
            cmd_tx,
            serve,
        }
    }

    /// Sends `Stop` and waits for `serve` to return.
    pub async fn stop(self) {
        self.cmd_tx
            .send(ServiceCommand::Stop)
            .await
            .expect("service alive");
        tokio::time::timeout(Duration::from_secs(2), self.serve)
            .await
            .expect("serve must return on Stop")
            .expect("join")
            .expect("serve ok");
    }
}

/// An `A nas.lan` query with the given Message ID.
#[must_use]
pub fn nas_query(id: u16) -> Vec<u8> {
    let mut query = DnsPacketBuilder::query("nas.lan", DnsRecordType::A).build_bytes();
    WireHeader::patch_id(&mut query, id);
    query
}
