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

    match effective_overhead {
        SqmOverhead::Pppoe => {
            args.push("overhead".to_string());
            args.push("34".to_string());
            args.push("ethernet".to_string());
        }
        SqmOverhead::Ethernet => {
            args.push("overhead".to_string());
            args.push("18".to_string());
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
                "bandwidth", "250mbit",
                "diffserv4",
                "nat",
                "overhead", "34", "ethernet"
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
        assert!(args.contains(&"overhead".to_string()));
        assert!(args.contains(&"18".to_string()));
    }
}
