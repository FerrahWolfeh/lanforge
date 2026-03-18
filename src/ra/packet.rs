//! Construção e checksum de pacotes Router Advertisement (RFC 4861 §4.2).

use super::config::*;
use std::net::Ipv6Addr;

pub const ICMPV6_TYPE_RA: u8 = 134;

// ---------------------------------------------------------------------------
// Montagem do pacote RA (RFC 4861 §4.2)
// ---------------------------------------------------------------------------

pub fn build_ra_packet(cfg: &RaConfig, mac: &[u8; 6], gua_prefix: Option<&Ipv6Addr>) -> Vec<u8> {
    let mut p = Vec::with_capacity(256);

    // ── Cabeçalho ICMPv6 ─────────────────────────────────────────────────
    p.push(ICMPV6_TYPE_RA);
    p.push(0u8); // code = 0
    p.extend([0u8; 2]); // checksum placeholder

    // ── Campos fixos do RA ────────────────────────────────────────────────
    p.push(cfg.hop_limit);

    // Byte de flags (RFC 4861 §4.2 + RFC 4191 §2.1):
    //   bit 7 (0x80): M — Managed Address Configuration
    //   bit 6 (0x40): O — Other Configuration
    //   bits 3–4:     Prf — Default Router Preference
    let flags: u8 = if cfg.managed { 0x80 } else { 0 }
        | if cfg.other_config { 0x40 } else { 0 }
        | cfg.priority.bits();
    p.push(flags);

    let rl = cfg.effective_router_lifetime().as_secs().min(9000) as u16;
    p.extend(rl.to_be_bytes());
    p.extend(0u32.to_be_bytes()); // reachable_time  (0 = não especificado)
    p.extend(0u32.to_be_bytes()); // retrans_timer   (0 = não especificado)

    // ── Opção 1: Source Link-Layer Address (RFC 4861 §4.6.1) ─────────────
    // Obrigatório em RAs multicast; permite que clientes atualizem o cache NDP.
    p.push(1u8); // type
    p.push(1u8); // length = 1 × 8 bytes
    p.extend_from_slice(mac);

    // ── Opção 5: MTU (RFC 4861 §4.6.4) ───────────────────────────────────
    // Anuncia MTU quando a WAN tem valor menor que 1500 (ex: PPPoE = 1492).
    // Sem esta opção, clientes assumem 1500 e podem ter fragmentação silenciosa.
    if let Some(mtu) = cfg.mtu {
        p.push(5u8); // type
        p.push(1u8); // length = 8 bytes
        p.extend([0u8; 2]); // reserved
        p.extend(mtu.to_be_bytes());
    }

    // ── Opção 3: Prefix Information (RFC 4861 §4.6.2) ────────────────────
    for pc in &cfg.prefixes {
        let addr = match &pc.source {
            PrefixSource::Static(a) => Some(*a),
            PrefixSource::AutoGua => gua_prefix.copied(),
        };
        if let Some(addr) = addr {
            push_prefix_option(&mut p, &addr, pc);
        }
    }

    // ── Opção 25: RDNSS (RFC 8106 §3.1) ─────────────────────────────────
    let rdnss_lt = |rd: &RdnssConfig| -> u32 {
        rd.lifetime
            .unwrap_or_else(|| cfg.max_interval * 2)
            .as_secs() as u32
    };

    for rdnss in &cfg.rdnss {
        if rdnss.servers.is_empty() {
            continue;
        }
        let n = rdnss.servers.len();
        p.push(25u8);
        // length em unidades de 8B: 1 (cabeçalho de 8B) + 2 por servidor (16B cada)
        p.push((1 + 2 * n) as u8);
        p.extend([0u8; 2]); // reserved
        p.extend(rdnss_lt(rdnss).to_be_bytes());
        for srv in &rdnss.servers {
            p.extend_from_slice(&srv.octets());
        }
    }

    // ── Opção 31: DNSSL (RFC 8106 §3.2) ─────────────────────────────────
    let dnssl_lt = |ds: &DnsslConfig| -> u32 {
        ds.lifetime
            .unwrap_or_else(|| cfg.max_interval * 2)
            .as_secs() as u32
    };

    for dnssl in &cfg.dnssl {
        if dnssl.domains.is_empty() {
            continue;
        }
        let encoded = encode_dns_wire(&dnssl.domains);
        // Tamanho total da opção: 8 bytes de cabeçalho + dados, arredondado para cima (múltiplo de 8)
        let total = 8 + encoded.len();
        let padded = (total + 7) & !7;
        p.push(31u8);
        p.push((padded / 8) as u8);
        p.extend([0u8; 2]); // reserved
        p.extend(dnssl_lt(dnssl).to_be_bytes());
        p.extend_from_slice(&encoded);
        p.resize(p.len() + (padded - total), 0u8); // padding de zeros
    }

    p
}

/// Serializa a opção Prefix Information (tipo 3, 32 bytes — RFC 4861 §4.6.2).
pub fn push_prefix_option(p: &mut Vec<u8>, addr: &Ipv6Addr, cfg: &PrefixConfig) {
    p.push(3u8); // type
    p.push(4u8); // length = 4 × 8 = 32 bytes
    p.push(cfg.prefix_len);

    // Flags:
    //   bit 7 (L): on-link
    //   bit 6 (A): autonomous (SLAAC)
    //   bit 5 (R): router address (RFC 3775)
    let flags: u8 = if cfg.on_link { 0x80 } else { 0 }
        | if cfg.autonomous { 0x40 } else { 0 }
        | if cfg.router_addr { 0x20 } else { 0 };
    p.push(flags);

    p.extend(cfg.valid_lifetime.as_u32().to_be_bytes());
    p.extend(cfg.preferred_lifetime.as_u32().to_be_bytes());
    p.extend([0u8; 4]); // reserved

    // Zera os bits de host conforme prefix_len — geralmente /64 = zera 8 bytes finais
    let mut octets = addr.octets();
    let host_bytes = ((128 - cfg.prefix_len) / 8) as usize;
    for i in (16 - host_bytes)..16 {
        octets[i] = 0;
    }
    p.extend_from_slice(&octets);
}

/// Codifica domínios no formato DNS wire (RFC 1035 §3.1) para uso na opção DNSSL.
/// Ex: ["home.arpa"] → b"\x04home\x04arpa\x00"
pub fn encode_dns_wire(domains: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for domain in domains {
        for label in domain.trim_end_matches('.').split('.') {
            let b = label.as_bytes();
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        }
        out.push(0u8); // terminador de domínio
    }
    out
}

// ---------------------------------------------------------------------------
// Checksum ICMPv6 — RFC 4443 §2.3
// ---------------------------------------------------------------------------

/// Calcula o checksum ICMPv6 incluindo o pseudo-header IPv6.
///
/// Diferente do ICMP v4, o checksum cobre um pseudo-header que inclui os
/// endereços IPv6 src/dst, o comprimento do payload e next-header=58.
/// Receptores que detectam checksum incorreto descartam o pacote silenciosamente.
pub fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, payload: &[u8]) -> u16 {
    let mut acc = 0u32;

    for chunk in src.octets().chunks(2) {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    let len = payload.len() as u32;
    acc += len >> 16;
    acc += len & 0xFFFF;
    acc += 58u32; // next-header = ICMPv6

    let mut iter = payload.chunks_exact(2);
    for chunk in iter.by_ref() {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [tail] = iter.remainder() {
        acc += (*tail as u32) << 8; // padding de zero à direita
    }

    // Dobramento one's complement
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

// ---------------------------------------------------------------------------
// Testes unitários
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn checksum_self_validates() {
        // Recalcular o checksum sobre um pacote com checksum preenchido deve dar 0
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1".parse().unwrap();
        let mut pkt = vec![
            134u8, 0, 0, 0, // type, code, csum=0
            64, 0, 0x07, 0x08, // hop, flags, lifetime=1800
            0, 0, 0, 0, // reachable_time
            0, 0, 0, 0, // retrans_timer
        ];
        let csum = icmpv6_checksum(&src, &dst, &pkt);
        assert_ne!(csum, 0, "checksum não pode ser zero em pacote não-trivial");
        pkt[2] = (csum >> 8) as u8;
        pkt[3] = (csum & 0xFF) as u8;
        assert_eq!(
            icmpv6_checksum(&src, &dst, &pkt),
            0,
            "checksum preenchido deve verificar a zero"
        );
    }

    #[test]
    fn checksum_odd_length_payload() {
        // Pacotes com número ímpar de bytes devem ter padding correto
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1".parse().unwrap();
        let mut pkt = vec![134u8, 0, 0, 0, 64, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF];
        let csum = icmpv6_checksum(&src, &dst, &pkt);
        pkt[2] = (csum >> 8) as u8;
        pkt[3] = (csum & 0xFF) as u8;
        assert_eq!(icmpv6_checksum(&src, &dst, &pkt), 0);
    }

    #[test]
    fn config_validation_passes_defaults() {
        assert!(RaConfig::default().validate().is_ok());
    }

    #[test]
    fn config_validation_max_interval_bounds() {
        let mut cfg = RaConfig::default();
        cfg.max_interval = Duration::from_secs(3); // abaixo de 4s
        assert!(cfg.validate().is_err());
        cfg.max_interval = Duration::from_secs(1801); // acima de 1800s
        assert!(cfg.validate().is_err());
        cfg.max_interval = Duration::from_secs(200);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validation_router_lifetime() {
        let mut cfg = RaConfig {
            max_interval: Duration::from_secs(100),
            ..Default::default()
        };
        // lifetime < max_interval → inválido
        cfg.router_lifetime = Some(Duration::from_secs(50));
        assert!(cfg.validate().is_err());
        // 0 sempre é válido
        cfg.router_lifetime = Some(Duration::from_secs(0));
        assert!(cfg.validate().is_ok());
        // acima de 9000 → inválido
        cfg.router_lifetime = Some(Duration::from_secs(9001));
        assert!(cfg.validate().is_err());
        // None → calculado como 3 × max_interval = 300s → válido
        cfg.router_lifetime = None;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn prefix_masking_zeros_host_bits() {
        let addr: Ipv6Addr = "2001:db8:cafe:1::abcd:ef01".parse().unwrap();
        let expected: Ipv6Addr = "2001:db8:cafe:1::".parse().unwrap();
        let mut p = Vec::new();
        push_prefix_option(&mut p, &addr, &PrefixConfig::gua_dynamic());
        // bytes 16..32 = prefixo mascarado na opção (offset 4 = type+len+plen+flags)
        let prefix_bytes: [u8; 16] = p[16..32].try_into().unwrap();
        assert_eq!(Ipv6Addr::from(prefix_bytes), expected);
    }

    #[test]
    fn dns_wire_encoding() {
        assert_eq!(
            encode_dns_wire(&["home.arpa".to_string()]),
            b"\x04home\x04arpa\x00"
        );
        assert_eq!(
            encode_dns_wire(&["a.b.c".to_string()]),
            b"\x01a\x01b\x01c\x00"
        );
    }

    #[test]
    fn build_packet_structure() {
        let cfg = RaConfig {
            managed: true,
            other_config: true,
            max_interval: Duration::from_secs(100),
            prefixes: vec![PrefixConfig::ula("fd97:f00d:cafe:3731::")],
            rdnss: vec![RdnssConfig::new(vec![
                "fd97:f00d:cafe:3731::1".parse().unwrap(),
            ])],
            ..Default::default()
        };
        let mac = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        let pkt = build_ra_packet(&cfg, &mac, None);

        assert_eq!(pkt[0], ICMPV6_TYPE_RA, "tipo ICMPv6 deve ser 134");
        assert_eq!(pkt[1], 0, "code deve ser 0");
        assert_eq!(pkt[5], 0b_1100_0000, "flags M=1, O=1");
        // Tamanho mínimo: 4+12 (hdr+fixo) + 8 (SLLA) + 32 (prefix) + 24 (RDNSS 1 srv) = 80
        assert!(
            pkt.len() >= 80,
            "pacote menor que esperado: {} bytes",
            pkt.len()
        );
    }

    #[test]
    fn ra_state_rate_limiting() {
        use super::super::RaState;
        let mut state = RaState::new();
        // Sem envios anteriores, sempre pode enviar
        assert!(state.can_multicast_now());
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(state.can_unicast_now(&ip));

        // Após registrar envio, deve respeitar rate limit
        state.record_multicast();
        assert!(
            !state.can_multicast_now(),
            "deve respeitar MIN_DELAY_BETWEEN_RAS"
        );
        state.record_unicast(ip);
        assert!(!state.can_unicast_now(&ip));
    }
}
