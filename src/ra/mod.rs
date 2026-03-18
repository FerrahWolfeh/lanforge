//! Serviço de Router Advertisement (RFC 4861 + RFC 8106).
//!
//! Implementação genérica e RFC-compliant do protocolo NDP/RA.
//! Projetada para rodar em hardware limitado (Raspberry Pi 4B).
//!
//! # RFCs implementadas
//! - RFC 4861  — Neighbor Discovery for IPv6 (RA/RS completo)
//! - RFC 8106  — RA Options for DNS Configuration (RDNSS + DNSSL)
//! - RFC 4191  — Default Router Preferences (flag de prioridade)
//! - RFC 3775  — AdvRouterAddr flag no Prefix Information

pub mod config;
pub mod packet;

pub use config::*;
pub use packet::{build_ra_packet, icmpv6_checksum};

use crate::bus::{EventBus, LanforgeEvent};

use anyhow::{Context, Result, anyhow};
use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use rand::{RngExt, rng};
use rtnetlink::Handle;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tokio::time::{Duration, sleep};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constantes RFC 4861 §6.2.1 e §10
// ---------------------------------------------------------------------------

/// Intervalo máximo entre os primeiros RAs no startup (§6.2.6).
/// Garante que clientes recém-conectados não esperem MaxRtrAdvInterval inteiro.
const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);

/// Quantidade de RAs iniciais enviados com intervalo reduzido (§6.2.6).
const MAX_INITIAL_RTR_ADVERTISEMENTS: u8 = 3;

/// Intervalo mínimo entre RAs multicast consecutivos (§6.2.4).
/// Protege contra tempestade de RAs quando vários clientes solicitam simultaneamente.
const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);

/// Atraso máximo aleatório antes de responder a um RS (§6.2.6), em ms.
const MAX_RA_DELAY_TIME_MS: u64 = 500;

const ICMPV6_TYPE_RS: u8 = 133;

// ---------------------------------------------------------------------------
// Estado de runtime — controla temporização RFC-compliant
// ---------------------------------------------------------------------------

pub(crate) struct RaState {
    /// Quantos RAs iniciais já foram enviados (controla fase de startup).
    initial_sent: u8,
    /// Instante do último RA multicast enviado (aplica MIN_DELAY_BETWEEN_RAS).
    last_multicast_ra: Option<Instant>,
    /// Rate limiting por destino unicast: instante do último RA enviado para cada IP.
    unicast_rl: HashMap<Ipv6Addr, Instant>,
    /// Último GUA detectado — para publicar PrefixChanged apenas quando muda.
    last_gua: Option<Ipv6Addr>,
}

impl RaState {
    pub(crate) fn new() -> Self {
        RaState {
            initial_sent: 0,
            last_multicast_ra: None,
            unicast_rl: HashMap::new(),
            last_gua: None,
        }
    }

    /// Sorteia o intervalo para o próximo RA periódico (RFC 4861 §6.2.4).
    ///
    /// Durante o startup: intervalos curtos (até MAX_INITIAL_RTR_ADVERT_INTERVAL)
    /// para convergência rápida. Depois: aleatório uniforme em [Min, Max].
    fn next_interval(&self, cfg: &RaConfig) -> Duration {
        let mut rng = rand::rng();
        if self.initial_sent < MAX_INITIAL_RTR_ADVERTISEMENTS {
            let ms = rng.random_range(0..MAX_INITIAL_RTR_ADVERT_INTERVAL.as_millis() as u64);
            Duration::from_millis(ms)
        } else {
            let min_ms = cfg.effective_min_interval().as_millis() as u64;
            let max_ms = cfg.max_interval.as_millis() as u64;
            Duration::from_millis(rng.random_range(min_ms..=max_ms))
        }
    }

    pub(crate) fn can_multicast_now(&self) -> bool {
        self.last_multicast_ra
            .is_none_or(|t| t.elapsed() >= MIN_DELAY_BETWEEN_RAS)
    }

    pub(crate) fn can_unicast_now(&self, dst: &Ipv6Addr) -> bool {
        self.unicast_rl
            .get(dst)
            .is_none_or(|t| t.elapsed() >= MIN_DELAY_BETWEEN_RAS)
    }

    pub(crate) fn record_multicast(&mut self) {
        self.last_multicast_ra = Some(Instant::now());
        self.initial_sent = self.initial_sent.saturating_add(1);
    }

    pub(crate) fn record_unicast(&mut self, dst: Ipv6Addr) {
        self.unicast_rl.insert(dst, Instant::now());
    }
}

pub(crate) struct RaContext<'a> {
    pub(crate) async_fd: &'a AsyncFd<Socket>,
    pub(crate) cfg: &'a RaConfig,
    pub(crate) handle: &'a Handle,
    pub(crate) mac: &'a [u8; 6],
    pub(crate) iface_index: u32,
    pub(crate) bus: &'a EventBus,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Task principal do serviço de RA. Invocar via `tokio::spawn`.
///
/// Encerra com `Err` apenas em falhas irrecuperáveis (permissão negada, interface
/// não encontrada etc.). O chamador deve reiniciar com backoff.
pub async fn ra_service(cfg: RaConfig, bus: Arc<EventBus>) -> Result<()> {
    cfg.validate()?;

    info!(
        "Iniciando na interface '{}' (M={}, O={}, MaxInterval={}s, RouterLifetime={}s)",
        cfg.iface,
        cfg.managed as u8,
        cfg.other_config as u8,
        cfg.max_interval.as_secs(),
        cfg.effective_router_lifetime().as_secs(),
    );

    let (connection, handle, _) =
        rtnetlink::new_connection().context("Netlink connection para RA")?;
    tokio::spawn(connection);

    let iface_index = get_iface_index(&cfg.iface)?;
    let mac = get_iface_mac(&cfg.iface)?;

    info!(
        "ifindex={iface_index}, MAC={}",
        mac.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    );

    let socket = create_ra_socket(&cfg.iface, iface_index)?;
    let async_fd = AsyncFd::new(socket)?;
    let mut state = RaState::new();

    let ctx = RaContext {
        async_fd: &async_fd,
        cfg: &cfg,
        handle: &handle,
        mac: &mac,
        iface_index,
        bus: &bus,
    };

    // RA imediato no startup — clientes já ativos recebem configuração sem esperar
    do_multicast_ra(&ctx, &mut state).await;

    loop {
        let next = state.next_interval(&cfg);
        debug!("Próximo RA periódico em {:.1}s", next.as_secs_f64());

        tokio::select! {
            // ── RA periódico ──────────────────────────────────────────────
            _ = sleep(next) => {
                do_multicast_ra(&ctx, &mut state).await;
            }

            // ── Router Solicitation recebido ──────────────────────────────
            guard = async_fd.readable() => {
                let mut guard = guard?;
                let mut buf = [0u8; 1500];

                match guard.try_io(|fd| {
                    let buf_uninit = unsafe {
                        &mut *(std::ptr::from_mut::<[u8]>(&mut buf)
                            as *mut [std::mem::MaybeUninit<u8>])
                    };
                    fd.get_ref().recv_from(buf_uninit)
                }) {
                    Ok(Ok((n, src_sa))) if n > 0 => {
                        let data = &buf[..n];

                        // ICMP6_FILTER já rejeita no kernel; checagem secundária aqui
                        if data.first() != Some(&ICMPV6_TYPE_RS) {
                            continue;
                        }

                        let rs_src = src_sa.as_socket_ipv6().map(|s| *s.ip());
                        debug!("RS recebido de {rs_src:?}");

                        handle_rs(&ctx, rs_src, &mut state).await;
                    }
                    Ok(Ok(_))  => {}
                    Ok(Err(e)) => warn!("Erro de leitura no socket: {e}"),
                    Err(_)     => {}  // WouldBlock — AsyncFd reseta automaticamente
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lógica de resposta a RS (RFC 4861 §6.2.6)
// ---------------------------------------------------------------------------

async fn handle_rs(ctx: &RaContext<'_>, rs_src: Option<Ipv6Addr>, state: &mut RaState) {
    // Atraso aleatório 0–500ms antes de responder (RFC 4861 §6.2.6).
    // Evita que múltiplos roteadores respondam ao mesmo RS no mesmo instante.
    let delay_ms = rng().random_range(0..MAX_RA_DELAY_TIME_MS);
    sleep(Duration::from_millis(delay_ms)).await;

    // Destino: unicast para o solicitante (se tem endereço válido) ou multicast
    let dst = rs_src.filter(|ip| !ip.is_unspecified());

    match dst {
        Some(unicast_dst) if state.can_unicast_now(&unicast_dst) => {
            match send_ra(ctx, Some(unicast_dst), state).await {
                Ok(()) => {
                    debug!("RA unicast -> {unicast_dst}");
                    state.record_unicast(unicast_dst);
                }
                Err(e) => warn!("Erro RA unicast: {e:?}"),
            }
        }
        None if state.can_multicast_now() => {
            // Solicitante com endereço ::  → resposta multicast
            do_multicast_ra(ctx, state).await;
        }
        _ => {
            // Rate limit ativo — RFC 4861 §6.2.6 permite descartar silenciosamente
            debug!("RS descartado: rate limit MIN_DELAY_BETWEEN_RAS ativo");
        }
    }
}

async fn do_multicast_ra(ctx: &RaContext<'_>, state: &mut RaState) {
    match send_ra(ctx, None, state).await {
        Ok(()) => {
            debug!("RA multicast -> ff02::1");
            state.record_multicast();
        }
        Err(e) => warn!("Erro RA multicast: {e:?}"),
    }
}

/// Constrói, assina (checksum) e envia um RA.
/// `unicast_dst = None` → multicast `ff02::1` (all-nodes).
async fn send_ra(
    ctx: &RaContext<'_>,
    unicast_dst: Option<Ipv6Addr>,
    state: &mut RaState,
) -> Result<()> {
    // Endereços são relidos a cada envio: GUA pode mudar quando o ISP renova
    // a delegação de prefixo via DHCPv6-PD, sem necessidade de reiniciar o serviço
    let src_ll = get_link_local_addr(ctx.handle, ctx.iface_index)
        .await
        .context("sem endereço link-local na interface")?;
    let gua = get_gua_prefix(ctx.handle, ctx.iface_index).await?;

    // Publica PrefixChanged no EventBus se o GUA mudou
    if gua != state.last_gua {
        info!("GUA prefix changed: {:?} -> {:?}", state.last_gua, gua);
        state.last_gua = gua;
        ctx.bus.publish(LanforgeEvent::PrefixChanged { gua });
    }

    let dst_ip: Ipv6Addr = unicast_dst.unwrap_or_else(|| "ff02::1".parse().unwrap());
    // scope_id obrigatório para destinos link-scoped (multicast e link-local)
    let dst_sa = SockAddr::from(SocketAddrV6::new(dst_ip, 0, 0, ctx.iface_index));

    let mut pkt = build_ra_packet(ctx.cfg, ctx.mac, gua.as_ref());

    // Checksum calculado sobre o pseudo-header IPv6 + payload
    let csum = icmpv6_checksum(&src_ll, &dst_ip, &pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = (csum & 0xFF) as u8;

    ctx.async_fd
        .get_ref()
        .send_to(&pkt, &dst_sa)
        .context("ICMPv6 send_to")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Configuração do socket ICMPv6 raw
// ---------------------------------------------------------------------------

fn create_ra_socket(iface: &str, iface_index: u32) -> Result<Socket> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .context("Falha ao criar socket ICMPv6 raw — necessário CAP_NET_RAW")?;

    // Vincula à interface LAN — mesmo em hosts multi-homed, tráfego fica contido
    sock.bind_device(Some(iface.as_bytes()))
        .with_context(|| format!("SO_BINDTODEVICE({iface})"))?;

    // RFC 4861 §6.1.2: receptores DEVEM descartar RAs com hop limit != 255
    sock.set_multicast_hops_v6(255)
        .context("IPV6_MULTICAST_HOPS=255")?;
    set_sockopt_int(&sock, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, 255)
        .context("IPV6_UNICAST_HOPS=255")?;

    // Inscreve em ff02::2 (all-routers) para receber Router Solicitations.
    // O kernel não repassa multicast de um grupo se o socket não estiver inscrito.
    let ff02_2: Ipv6Addr = "ff02::2".parse().unwrap();
    sock.join_multicast_v6(&ff02_2, iface_index)
        .context("join_multicast_v6(ff02::2)")?;

    // ICMP6_FILTER: rejeita no kernel todos os tipos ICMPv6 exceto RS (133).
    // No RPi4 isso reduz context switches e uso de CPU em redes com muito tráfego NDP.
    set_icmp6_filter_rs_only(&sock).context("ICMP6_FILTER")?;

    sock.set_nonblocking(true).context("O_NONBLOCK")?;

    info!("Socket ICMPv6 raw OK — filtro ICMP6_FILTER ativo (apenas RS), inscrito em ff02::2");
    Ok(sock)
}

/// Configura ICMP6_FILTER para aceitar apenas RS (tipo 133), bloquear todo o resto.
///
/// O filtro é um bitmask de 256 bits (32 bytes) processado no kernel antes de
/// acordar o processo. Fundamental no RPi4 onde cada wakeup desnecessário
/// custa comparativamente mais que em x86.
fn set_icmp6_filter_rs_only(sock: &Socket) -> io::Result<()> {
    // Todos bits = 1 → bloqueia tudo (ICMP6_FILTER_SETBLOCKALL)
    let mut filter = [0xFFu8; 32];
    // Limpa o bit do tipo RS → deixa passar (ICMP6_FILTER_SETPASS(133))
    let t = ICMPV6_TYPE_RS as usize;
    filter[t / 8] &= !(1u8 << (t % 8));
    // ICMP6_FILTER = 1 (linux/icmpv6.h — not exposed by libc crate)
    const ICMP6_FILTER: libc::c_int = 1;
    set_sockopt_raw(sock, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filter)
}

// ---------------------------------------------------------------------------
// Wrappers de setsockopt não expostos pelo socket2 0.5
// ---------------------------------------------------------------------------

fn set_sockopt_int(
    sock: &Socket,
    level: libc::c_int,
    opt: libc::c_int,
    val: i32,
) -> io::Result<()> {
    let v = val as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            &v as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_sockopt_raw(
    sock: &Socket,
    level: libc::c_int,
    opt: libc::c_int,
    data: &[u8],
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            data.as_ptr() as *const libc::c_void,
            data.len() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// Helpers de interface (sysfs — leitura direta sem syscall extra)
// ---------------------------------------------------------------------------

fn get_iface_index(iface: &str) -> Result<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("ifindex de '{iface}'"))?
        .trim()
        .parse::<u32>()
        .context("parse ifindex")
}

fn get_iface_mac(iface: &str) -> Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("MAC de '{iface}'"))?;
    let bytes: Vec<u8> = s
        .trim()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).map_err(|e| anyhow!("{e}")))
        .collect::<Result<_>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("MAC deve ter 6 bytes"))
}

// ---------------------------------------------------------------------------
// Detecção de endereços via rtnetlink (reutiliza Handle existente)
// ---------------------------------------------------------------------------

/// Retorna o endereço link-local (fe80::/10) da interface.
/// Obrigatório como endereço fonte de todo RA (RFC 4861 §4.2).
async fn get_link_local_addr(handle: &Handle, iface_index: u32) -> Result<Ipv6Addr> {
    let mut stream = handle.address().get().execute();
    while let Some(msg) = stream.try_next().await? {
        if msg.header.index != iface_index {
            continue;
        }
        if let Some(addr) = extract_ipv6(&msg) {
            let o = addr.octets();
            if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
                return Ok(addr);
            }
        }
    }
    Err(anyhow!(
        "Sem endereço link-local na interface índice {iface_index}"
    ))
}

/// Detecta o prefixo GUA /64 da interface e retorna com bits de host zerados.
///
/// GUA (2000::/3): primeiro byte em [0x20, 0x3F].
/// O endereço na interface (ex: `2a01:x:y:z::1`) é mascarado para obter `2a01:x:y:z::`.
/// Retorna `None` se não houver GUA atribuído (ISP sem IPv6 ou delegação pendente).
async fn get_gua_prefix(handle: &Handle, iface_index: u32) -> Result<Option<Ipv6Addr>> {
    let mut stream = handle.address().get().execute();
    while let Some(msg) = stream.try_next().await? {
        if msg.header.index != iface_index {
            continue;
        }
        if let Some(addr) = extract_ipv6(&msg) {
            let o = addr.octets();
            if (0x20..=0x3F).contains(&o[0]) {
                let mut masked = o;
                masked[8..].fill(0);
                return Ok(Some(Ipv6Addr::from(masked)));
            }
        }
    }
    Ok(None)
}

fn extract_ipv6(msg: &netlink_packet_route::address::AddressMessage) -> Option<Ipv6Addr> {
    msg.attributes.iter().find_map(|a| {
        if let AddressAttribute::Address(IpAddr::V6(v6)) = a {
            Some(*v6)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn state_rate_limits_multicast_and_unicast() {
        let mut state = RaState::new();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();

        // Inicialmente, tudo liberado
        assert!(state.can_multicast_now());
        assert!(state.can_unicast_now(&ip));

        // Após registrar um envio, deve bloquear pelo MIN_DELAY_BETWEEN_RAS (3s)
        state.record_multicast();
        assert!(
            !state.can_multicast_now(),
            "Multicast deve sofrer rate limit"
        );

        state.record_unicast(ip);
        assert!(
            !state.can_unicast_now(&ip),
            "Unicast deve sofrer rate limit"
        );

        // Um IP diferente não deve ser afetado pelo rate limit do primeiro
        let ip2: Ipv6Addr = "fe80::2".parse().unwrap();
        assert!(state.can_unicast_now(&ip2));
    }

    #[test]
    fn state_startup_phase_uses_short_intervals() {
        let cfg = RaConfig {
            max_interval: Duration::from_secs(100),
            ..Default::default()
        };
        let mut state = RaState::new();

        // Os 3 primeiros RAs devem ter um intervalo curto (<= 16s)
        for _ in 0..3 {
            let interval = state.next_interval(&cfg);
            assert!(
                interval <= MAX_INITIAL_RTR_ADVERT_INTERVAL,
                "Intervalo de startup muito longo: {:?}",
                interval
            );
            state.record_multicast();
        }

        // Do 4º em diante, deve entrar no regime normal [Min, Max]
        // Min = 0.33 * Max = 33s. Max = 100s.
        let normal_interval = state.next_interval(&cfg);
        assert!(
            normal_interval >= Duration::from_secs(33)
                && normal_interval <= Duration::from_secs(100),
            "Intervalo normal fora dos limites: {:?}",
            normal_interval
        );
    }
}
