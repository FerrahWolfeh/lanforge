use hickory_proto::rr::Name;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parseador de ARPA otimizado sem alocação de Vec ou manipulação reversa pesada.
pub fn parse_arpa(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.');

    if let Some(v4_part) = name.strip_suffix(".in-addr.arpa") {
        let mut parts = v4_part.split('.');
        // Lendo do fim para o começo diretamente do iterador
        let d: u8 = parts.next()?.parse().ok()?;
        let c: u8 = parts.next()?.parse().ok()?;
        let b: u8 = parts.next()?.parse().ok()?;
        let a: u8 = parts.next()?.parse().ok()?;
        return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }

    if let Some(v6_part) = name.strip_suffix(".ip6.arpa") {
        let parts: Vec<&str> = v6_part.split('.').collect();
        if parts.len() == 32 {
            let mut hex = String::with_capacity(39);
            for (i, p) in parts.into_iter().rev().enumerate() {
                hex.push_str(p);
                if i % 4 == 3 && i != 31 {
                    hex.push(':');
                }
            }
            if let Ok(ipv6) = hex.parse::<Ipv6Addr>() {
                return Some(IpAddr::V6(ipv6));
            }
        }
    }
    None
}

pub fn combine_prefix_suffix(prefix_segs: &[u16], suffix: &str) -> Option<Ipv6Addr> {
    let clean_suffix = suffix.strip_prefix("::").unwrap_or(suffix);
    let suffix_ip: Ipv6Addr = format!("::{clean_suffix}").parse().ok()?;
    let suf_segs = suffix_ip.segments();

    Some(Ipv6Addr::new(
        prefix_segs[0],
        prefix_segs[1],
        prefix_segs[2],
        prefix_segs[3],
        suf_segs[4],
        suf_segs[5],
        suf_segs[6],
        suf_segs[7],
    ))
}

/// Extrai o hostname local diretamente dos labels do pacote DNS bruto.
/// Custo de alocação: 0 bytes.
pub fn extract_local_hostname<'a>(qname: &'a Name, search_labels: &[Vec<u8>]) -> Option<&'a str> {
    let mut iter = qname.iter();

    // 1. O primeiro label é sempre o alvo (ex: "node-12" de "node-12.lanforge.local")
    let host_bytes = iter.next()?;

    // 2. Valida se o resto da query bate exatamente com o seu domínio de busca
    for expected_label in search_labels {
        let actual_label = iter.next()?;

        // Comparação de bytes ignorando case (muito mais rápido que mexer com UTF-8 strings)
        if !actual_label.eq_ignore_ascii_case(expected_label) {
            return None;
        }
    }

    // 3. Se a query tiver mais labels (ex: sub.node-12.lanforge.local), rejeita
    if iter.next().is_some() {
        return None;
    }

    // 4. Tudo certo. Converte os bytes do hostname para &str e devolve
    std::str::from_utf8(host_bytes).ok()
}

/// Verifica se a string já é minúscula.
/// Em 99% das queries LAN, não fazemos NENHUMA alocação (retorna Borrowed).
/// Só aloca memória no heap (Owned) se algum dispositivo maluco mandar letras maiúsculas.
pub fn fast_lowercase(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}
