use hickory_proto::rr::Name;
use lanforge_core::device::Ipv6AddrOrSuffix;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dns::wire::WireLabelIter;

/// Parseador de ARPA otimizado que opera diretamente sobre os labels de um Name, evitando alocações.
pub fn parse_arpa(name: &Name) -> Option<IpAddr> {
    let labels = name.iter().rev();

    byte_parse_arpa(labels)
}

/// Parseia um octeto decimal diretamente de bytes, sem UTF-8.
/// Rejeita strings vazias, > 3 chars, não-dígitos, e valores > 255.
#[inline(always)]
fn parse_octet(label: &[u8]) -> Option<u8> {
    if label.is_empty() || label.len() > 3 {
        return None;
    }
    let mut val: u16 = 0;
    for &b in label {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val * 10 + (b - b'0') as u16;
    }
    if val > 255 { None } else { Some(val as u8) }
}

/// Parseia um único nibble hex (0-9, a-f, A-F) de um label de 1 byte.
#[inline(always)]
fn parse_nibble(label: &[u8]) -> Option<u8> {
    match label {
        [b] => match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        },
        _ => None, // label vazio ou multi-byte: inválido
    }
}

#[inline]
fn byte_parse_arpa<'a>(mut labels: impl Iterator<Item = &'a [u8]>) -> Option<IpAddr> {
    if !labels.next()?.eq_ignore_ascii_case(b"arpa") {
        return None;
    }

    let second = labels.next()?;

    if second.eq_ignore_ascii_case(b"in-addr") {
        let [a, b, c, d] = std::array::from_fn(|_| labels.next());
        return Some(IpAddr::V4(Ipv4Addr::new(
            parse_octet(a?)?,
            parse_octet(b?)?,
            parse_octet(c?)?,
            parse_octet(d?)?,
        )));
    }

    if second.eq_ignore_ascii_case(b"ip6") {
        let mut segments = [0u16; 8];
        for i in 0..32_usize {
            let nibble = parse_nibble(labels.next()?)?;
            segments[i / 4] |= (nibble as u16) << (12 - (i % 4) * 4);
        }
        return Some(IpAddr::V6(Ipv6Addr::from(segments)));
    }

    None
}

pub fn combine_prefix_suffix(prefix_segs: &[u16], suffix: &Ipv6AddrOrSuffix) -> Option<Ipv6Addr> {
    match suffix {
        Ipv6AddrOrSuffix::Full(ip) => Some(*ip),
        Ipv6AddrOrSuffix::Suffix(s) => Some(Ipv6Addr::new(
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

/// Extrai o hostname local diretamente dos labels de um iterador wire, sem alocações.
pub fn extract_local_hostname_wire<'a>(
    labels: &mut crate::dns::wire::WireLabelIter<'a>,
    search_labels: &[Vec<u8>],
) -> Option<&'a str> {
    // 1. O primeiro label é o alvo
    let host_bytes = labels.next()?;

    // 2. Valida o resto da query
    for expected in search_labels {
        let actual = labels.next()?;
        if !actual.eq_ignore_ascii_case(expected) {
            return None;
        }
    }

    // 3. Rejeita subdomínios excedentes
    if labels.next().is_some() {
        return None;
    }

    std::str::from_utf8(host_bytes).ok()
}

pub fn parse_arpa_wire(labels: WireLabelIter<'_>) -> Option<IpAddr> {
    // IPv6: 32 nibbles + "ip6" + "arpa" = 34 labels max
    let mut parts: [&[u8]; 34] = [b""; 34];
    let mut count = 0;

    for l in labels {
        if count < parts.len() {
            parts[count] = l;
            count += 1;
        }
    }

    // Itera só os slots preenchidos, em ordem reversa
    byte_parse_arpa(parts[..count].iter().copied().rev())
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
