use lanforge_types::network::{SqmConfig, SqmDiffserv, SqmOverhead};

/// Generates arguments for the CAKE qdisc.
#[must_use]
pub fn build_cake_args(
    cfg: &SqmConfig,
    bandwidth_mbps: u32,
    is_ingress: bool,
    is_pppoe: bool,
) -> Vec<String> {
    let mut args = Vec::new();

    // Bandwidth
    if bandwidth_mbps > 0 {
        args.push("bandwidth".to_string());
        args.push(format!("{bandwidth_mbps}mbit"));
    } else {
        args.push("unlimited".to_string());
    }

    // Diffserv profile
    match cfg.diffserv {
        SqmDiffserv::Diffserv4 => args.push("diffserv4".to_string()),
        SqmDiffserv::Diffserv3 => args.push("diffserv3".to_string()),
        SqmDiffserv::Besteffort => args.push("besteffort".to_string()),
    }

    // Per-host fairness (nat keyword enables conntrack lookups)
    if cfg.per_host_isolation {
        args.push("nat".to_string());
    }

    // Wash untrusted DSCP markings on ingress
    if is_ingress {
        args.push("wash".to_string());
        args.push("ingress".to_string());
    }

    // RTT parameter if custom
    if let Some(rtt) = cfg.rtt_ms {
        args.push("rtt".to_string());
        args.push(format!("{rtt}ms"));
    }

    // Overhead compensation
    let effective_overhead = match cfg.overhead {
        SqmOverhead::Auto => {
            if is_pppoe {
                SqmOverhead::Pppoe
            } else {
                SqmOverhead::Ethernet
            }
        }
        other => other,
    };

    // tc's `overhead N` sets the value and keywords such as `ethernet` add to it: the old
    // `overhead 34 ethernet` became 72 on the owner's box. Spell the totals out instead.
    match effective_overhead {
        // CAKE on the PPP link sees bare IP packets: Ethernet on the wire (preamble 8 + header
        // 14 + FCS 4 + inter-frame gap 12 = 38) plus PPPoE 6 + PPP protocol 2.
        SqmOverhead::Pppoe => {
            args.extend(["overhead", "46", "mpu", "84", "noatm"].map(String::from));
        }
        // An Ethernet WAN: `ethernet` is overhead 38 mpu 84 noatm.
        SqmOverhead::Ethernet => {
            args.push("ethernet".to_string());
        }
        SqmOverhead::Docsis => {
            args.push("docsis".to_string());
        }
        SqmOverhead::None | SqmOverhead::Auto => {}
    }

    // Custom raw arguments if provided
    if let Some(ref raw) = cfg.raw_cake_args {
        for token in raw.split_whitespace() {
            args.push(token.to_string());
        }
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cake_args_egress_pppoe() {
        let cfg = SqmConfig {
            enabled: true,
            interface: "auto".into(),
            download_mbps: 500,
            upload_mbps: 250,
            overhead: SqmOverhead::Auto,
            diffserv: SqmDiffserv::Diffserv4,
            per_host_isolation: true,
            rtt_ms: None,
            ingress_device: "auto".into(),
            raw_cake_args: None,
        };

        let args = build_cake_args(&cfg, cfg.upload_mbps, false, true);
        assert_eq!(
            args,
            vec![
                "bandwidth",
                "250mbit",
                "diffserv4",
                "nat",
                "overhead",
                "46",
                "mpu",
                "84",
                "noatm"
            ]
        );
    }

    #[test]
    fn test_build_cake_args_ingress() {
        let cfg = SqmConfig {
            enabled: true,
            interface: "wan0".into(),
            download_mbps: 100,
            upload_mbps: 50,
            overhead: SqmOverhead::Ethernet,
            diffserv: SqmDiffserv::Diffserv4,
            per_host_isolation: true,
            rtt_ms: Some(20),
            ingress_device: "auto".into(),
            raw_cake_args: None,
        };

        let args = build_cake_args(&cfg, cfg.download_mbps, true, false);
        assert!(args.contains(&"wash".to_string()));
        assert!(args.contains(&"ingress".to_string()));
        assert!(args.contains(&"rtt".to_string()));
        assert!(args.contains(&"20ms".to_string()));
        assert!(args.contains(&"ethernet".to_string()));
        assert!(
            !args.contains(&"overhead".to_string()),
            "`overhead N ethernet` adds the two: {args:?}"
        );
    }
}
