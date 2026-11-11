//! The host's own upstream resolvers, the last fallback for the `DHCPv4` DNS option.

use std::fs;
use std::net::Ipv4Addr;

/// systemd-resolved lists the real upstreams here; `/etc/resolv.conf` may only name its stub.
const RESOLV_FILES: [&str; 2] = ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"];

/// The IPv4 upstreams the host resolves through, from the first file that names any. Loopback
/// stubs and `own` (this server, whose DNS is off when this is asked) are not upstreams.
pub fn host_resolvers(own: Ipv4Addr) -> Vec<Ipv4Addr> {
    RESOLV_FILES
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|text| nameservers(&text, own))
        .find(|servers| !servers.is_empty())
        .unwrap_or_default()
}

/// The usable IPv4 `nameserver` entries of a resolv.conf (resolv.conf(5)).
fn nameservers(text: &str, own: Ipv4Addr) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver"))
                .then(|| words.next())
                .flatten()
        })
        .filter_map(|addr| addr.parse::<Ipv4Addr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified() && *ip != own)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_ipv4_upstreams_and_drops_stubs_ipv6_and_this_server() {
        let own = Ipv4Addr::new(192, 168, 3, 1);
        let text = "# managed by systemd-resolved\n\
                    nameserver 127.0.0.53\n\
                    nameserver 192.168.3.1\n\
                    nameserver 2804:14d::1\n\
                    nameserver 200.175.5.139\n\
                    nameserver\t1.1.1.1 # comment\n\
                    search lan\n\
                    options edns0\n";
        assert_eq!(
            nameservers(text, own),
            vec![Ipv4Addr::new(200, 175, 5, 139), Ipv4Addr::new(1, 1, 1, 1)]
        );
    }

    #[test]
    fn a_stub_only_file_names_no_upstream() {
        assert_eq!(
            nameservers("nameserver 127.0.0.53\n", Ipv4Addr::UNSPECIFIED),
            Vec::<Ipv4Addr>::new()
        );
    }
}
