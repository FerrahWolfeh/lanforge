use hickory_proto::rr::Name;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

/// Parseador de ARPA otimizado que opera diretamente sobre os labels de um Name, evitando alocações.
pub fn parse_arpa(name: &Name) -> Option<IpAddr> {
    let mut labels = name.iter().rev();

    // 1. Verifica sufixo (in-addr.arpa ou ip6.arpa)
    let first = labels.next()?;
    if first.eq_ignore_ascii_case(b"arpa") {
        let second = labels.next()?;
        if second.eq_ignore_ascii_case(b"in-addr") {
            // IPv4: d.c.b.a.in-addr.arpa
            let a_str = from_utf8(labels.next()?).ok()?; // a quick check to see if at least the first block of the ipv4 is a readable number in utf-8
            let a: u8 = a_str.parse().ok()?;
            let b: u8 = from_utf8(labels.next()?).ok()?.parse().ok()?;
            let c: u8 = from_utf8(labels.next()?).ok()?.parse().ok()?;
            let d: u8 = from_utf8(labels.next()?).ok()?.parse().ok()?;
            return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
        } else if second.eq_ignore_ascii_case(b"ip6") {
            // IPv6: 32 nibbles reversos
            let mut segments = [0u16; 8];
            for i in 0..32 {
                let label = labels.next()?;
                if label.len() != 1 {
                    return None;
                }
                let nibble = u8::from_str_radix(from_utf8(label).ok()?, 16).ok()?;
                let seg_idx = i / 4;

                // O primeiro nibble de um grupo de 4 recebe o maior shift (12)
                let shift = 12 - ((i % 4) * 4);
                segments[seg_idx] |= (nibble as u16) << shift;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(segments)));
        }
    }

    None
}

pub fn combine_prefix_suffix(
    prefix_segs: &[u16],
    suffix: &crate::device::Ipv6AddrOrSuffix,
) -> Option<Ipv6Addr> {
    match suffix {
        crate::device::Ipv6AddrOrSuffix::Full(ip) => Some(*ip),
        crate::device::Ipv6AddrOrSuffix::Suffix(s) => Some(Ipv6Addr::new(
            prefix_segs[0],
            prefix_segs[1],
            prefix_segs[2],
            prefix_segs[3],
            u16::from_be_bytes([s[0], s[1]]),
            u16::from_be_bytes([s[2], s[3]]),
            u16::from_be_bytes([s[4], s[5]]),
            u16::from_be_bytes([s[6], s[7]]),
        )),
    }
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
