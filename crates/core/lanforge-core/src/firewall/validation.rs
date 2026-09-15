use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallPolicy, FirewallValidationReport, L4Protocol,
};
use std::collections::{HashMap, HashSet};

fn protocols_overlap(a: L4Protocol, b: L4Protocol) -> bool {
    a == L4Protocol::Both || b == L4Protocol::Both || a == b
}

/// Runs comprehensive pre-flight sanity and conflict checks on a candidate firewall configuration.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn validate_firewall_candidate(
    candidate: &FirewallConfig,
    current: &FirewallConfig,
    dynamic_ports: &[DynamicPortRequest],
    tx_id_generator: impl FnOnce() -> String,
) -> FirewallValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut diff_summary = Vec::new();

    // 1. Zone Name Uniqueness & Interface Overlap Check
    let mut zone_names = HashSet::new();
    let mut assigned_interfaces: HashMap<String, String> = HashMap::new();

    for zone in &candidate.zones {
        if !zone_names.insert(&zone.name) {
            errors.push(format!(
                "Duplicate zone name '{}': all zone names must be unique",
                zone.name
            ));
        }

        for iface in &zone.interfaces {
            if let Some(existing_zone) = assigned_interfaces.get(iface) {
                errors.push(format!(
                    "Interface overlap: interface '{iface}' is assigned to both zone '{existing_zone}' and zone '{}'",
                    zone.name
                ));
            } else {
                assigned_interfaces.insert(iface.clone(), zone.name.clone());
            }
        }
    }

    // 2. Inter-Zone Forwarding Integrity
    for fwd in &candidate.forwardings {
        if !zone_names.contains(&fwd.from) {
            errors.push(format!(
                "Invalid forwarding source: zone '{}' does not exist in candidate configuration",
                fwd.from
            ));
        }
        if !zone_names.contains(&fwd.to) {
            errors.push(format!(
                "Invalid forwarding destination: zone '{}' does not exist in candidate configuration",
                fwd.to
            ));
        }
    }

    // 3. Port Forwarding (DNAT) Collisions & Validation
    for (idx, rule) in candidate.port_forwards.iter().enumerate() {
        if !zone_names.contains(&rule.src_zone) {
            errors.push(format!(
                "Invalid port forward source zone: zone '{}' does not exist",
                rule.src_zone
            ));
        }

        if rule.external_port == 0 {
            errors.push(format!(
                "Invalid external port 0 in port forwarding rule #{}",
                idx + 1
            ));
        }

        if rule.internal_port == 0 {
            errors.push(format!(
                "Invalid internal port 0 in port forwarding rule #{}",
                idx + 1
            ));
        }

        if rule.internal_ip.is_unspecified() {
            errors.push(format!(
                "Port forward #{} has unspecified target IP ({})",
                idx + 1,
                rule.internal_ip
            ));
        }

        // Collision check against subsequent port forward rules
        for other in &candidate.port_forwards[idx + 1..] {
            if rule.external_port == other.external_port
                && protocols_overlap(rule.protocol, other.protocol)
            {
                errors.push(format!(
                    "Port forward collision: external port {} ({}) is mapped multiple times",
                    rule.external_port,
                    rule.protocol.as_str()
                ));
            }
        }

        // Collision check against active host dynamic service ports (e.g. WebUI, DNS)
        for dyn_port in dynamic_ports {
            if rule.external_port == dyn_port.port
                && protocols_overlap(rule.protocol, dyn_port.protocol)
                && rule.src_zone == dyn_port.zone
            {
                warnings.push(format!(
                    "Port forward external port {} ({}) shadows local host service '{}'",
                    rule.external_port,
                    rule.protocol.as_str(),
                    dyn_port.service
                ));
            }
        }
    }

    // 4. Host Open Ports Validity within Zones
    for zone in &candidate.zones {
        for (i, p1) in zone.open_ports.iter().enumerate() {
            if p1.port == 0 {
                errors.push(format!("Zone '{}' has invalid open port 0", zone.name));
            }
            for p2 in &zone.open_ports[i + 1..] {
                if p1.port == p2.port && protocols_overlap(p1.protocol, p2.protocol) {
                    warnings.push(format!(
                        "Zone '{}' has duplicate open port definition for port {} ({})",
                        zone.name,
                        p1.port,
                        p1.protocol.as_str()
                    ));
                }
            }
        }
    }

    // 5. Anti-Lockout Guard
    // If an administrative zone (e.g. "internal" or "trusted") has input policy Drop or Reject,
    // ensure either SSH (22) or the WebUI port is open.
    for zone in &candidate.zones {
        if (zone.name == "internal" || zone.name == "trusted")
            && (zone.input_policy == FirewallPolicy::Drop
                || zone.input_policy == FirewallPolicy::Reject)
        {
            let has_ssh = zone.open_ports.iter().any(|p| {
                p.port == 22 && (p.protocol == L4Protocol::Tcp || p.protocol == L4Protocol::Both)
            });

            let has_webui = dynamic_ports.iter().any(|dp| {
                dp.service.contains("webui")
                    || dp.service.contains("http")
                    || zone.open_ports.iter().any(|p| {
                        p.port == dp.port
                            && (p.protocol == L4Protocol::Tcp || p.protocol == L4Protocol::Both)
                    })
            }) || zone.open_ports.iter().any(|p| {
                (p.port == 8080 || p.port == 443 || p.port == 80)
                    && (p.protocol == L4Protocol::Tcp || p.protocol == L4Protocol::Both)
            });

            if !has_ssh && !has_webui {
                errors.push(format!(
                    "Anti-lockout guard: zone '{}' has input policy {:?}, but neither SSH (port 22) nor WebUI access is permitted. Applying this would lock out administrative access.",
                    zone.name, zone.input_policy
                ));
            }
        }
    }

    // 6. Diff Computation
    compute_diff(candidate, current, &mut diff_summary);

    let valid = errors.is_empty();
    let tx_id = if valid {
        Some(tx_id_generator())
    } else {
        None
    };

    FirewallValidationReport {
        valid,
        tx_id,
        diff_summary,
        warnings,
        errors,
    }
}

#[allow(clippy::too_many_lines)]
fn compute_diff(candidate: &FirewallConfig, current: &FirewallConfig, diff: &mut Vec<String>) {
    if candidate.enabled != current.enabled {
        diff.push(format!(
            "~ Firewall master toggle: {} -> {}",
            current.enabled, candidate.enabled
        ));
    }
    if candidate.flow_offload != current.flow_offload {
        diff.push(format!(
            "~ Flowtable offload: {} -> {}",
            current.flow_offload, candidate.flow_offload
        ));
    }
    if candidate.bypass_dns != current.bypass_dns {
        diff.push(format!(
            "~ DNS bypass: {} -> {}",
            current.bypass_dns, candidate.bypass_dns
        ));
    }
    if candidate.default_input_policy != current.default_input_policy {
        diff.push(format!(
            "~ Default input policy: {:?} -> {:?}",
            current.default_input_policy, candidate.default_input_policy
        ));
    }
    if candidate.default_forward_policy != current.default_forward_policy {
        diff.push(format!(
            "~ Default forward policy: {:?} -> {:?}",
            current.default_forward_policy, candidate.default_forward_policy
        ));
    }

    // Zones
    let curr_zones: HashMap<&str, _> = current.zones.iter().map(|z| (z.name.as_str(), z)).collect();
    let cand_zones: HashMap<&str, _> = candidate.zones.iter().map(|z| (z.name.as_str(), z)).collect();

    for (name, z) in &cand_zones {
        if let Some(curr_z) = curr_zones.get(name) {
            if z.input_policy != curr_z.input_policy {
                diff.push(format!(
                    "~ Zone '{name}' input policy: {:?} -> {:?}",
                    curr_z.input_policy, z.input_policy
                ));
            }
            if z.forward_policy != curr_z.forward_policy {
                diff.push(format!(
                    "~ Zone '{name}' forward policy: {:?} -> {:?}",
                    curr_z.forward_policy, z.forward_policy
                ));
            }
            if z.interfaces != curr_z.interfaces {
                diff.push(format!(
                    "~ Zone '{name}' interfaces: {:?} -> {:?}",
                    curr_z.interfaces, z.interfaces
                ));
            }
            if z.masquerade != curr_z.masquerade {
                diff.push(format!(
                    "~ Zone '{name}' masquerade: {} -> {}",
                    curr_z.masquerade, z.masquerade
                ));
            }

            // Open ports diff
            for p in &z.open_ports {
                if !curr_z.open_ports.contains(p) {
                    diff.push(format!(
                        "+ Zone '{name}' open port: {}/{}",
                        p.port,
                        p.protocol.as_str()
                    ));
                }
            }
            for p in &curr_z.open_ports {
                if !z.open_ports.contains(p) {
                    diff.push(format!(
                        "- Zone '{name}' open port: {}/{}",
                        p.port,
                        p.protocol.as_str()
                    ));
                }
            }
        } else {
            diff.push(format!(
                "+ Added zone '{name}' (input: {:?}, forward: {:?})",
                z.input_policy, z.forward_policy
            ));
        }
    }

    for name in curr_zones.keys() {
        if !cand_zones.contains_key(name) {
            diff.push(format!("- Removed zone '{name}'"));
        }
    }

    // Forwardings
    for f in &candidate.forwardings {
        if !current.forwardings.contains(f) {
            diff.push(format!("+ Inter-zone forwarding: {} -> {}", f.from, f.to));
        }
    }
    for f in &current.forwardings {
        if !candidate.forwardings.contains(f) {
            diff.push(format!("- Inter-zone forwarding: {} -> {}", f.from, f.to));
        }
    }

    // Port forwards
    for pf in &candidate.port_forwards {
        if !current.port_forwards.contains(pf) {
            diff.push(format!(
                "+ Port forward: {} port {} -> {}:{}",
                pf.protocol.as_str(),
                pf.external_port,
                pf.internal_ip,
                pf.internal_port
            ));
        }
    }
    for pf in &current.port_forwards {
        if !candidate.port_forwards.contains(pf) {
            diff.push(format!(
                "- Port forward: {} port {} -> {}:{}",
                pf.protocol.as_str(),
                pf.external_port,
                pf.internal_ip,
                pf.internal_port
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_types::network::firewall::PortForwardRule;
    use std::net::Ipv4Addr;

    #[test]
    fn test_validation_detects_port_forward_collision() {
        let current = FirewallConfig::default();
        let mut candidate = current.clone();

        candidate.port_forwards.push(PortForwardRule {
            comment: Some("Rule 1".into()),
            src_zone: "external".into(),
            internal_ip: Ipv4Addr::new(192, 168, 1, 50).into(),
            external_port: 8443,
            internal_port: 8443,
            protocol: L4Protocol::Tcp,
            enable_hairpin: true,
        });

        candidate.port_forwards.push(PortForwardRule {
            comment: Some("Rule 2 colliding".into()),
            src_zone: "external".into(),
            internal_ip: Ipv4Addr::new(192, 168, 1, 60).into(),
            external_port: 8443,
            internal_port: 8443,
            protocol: L4Protocol::Tcp,
            enable_hairpin: true,
        });

        let report = validate_firewall_candidate(&candidate, &current, &[], || "tx-test".into());
        assert!(!report.valid);
        assert!(report.tx_id.is_none());
        assert!(report.errors.iter().any(|e| e.contains("Port forward collision")));
    }

    #[test]
    fn test_validation_detects_interface_overlap() {
        let current = FirewallConfig::default();
        let mut candidate = current.clone();

        candidate.zones[0].interfaces = vec!["eth0".into()];
        candidate.zones[1].interfaces = vec!["eth0".into()];

        let report = validate_firewall_candidate(&candidate, &current, &[], || "tx-test".into());
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.contains("Interface overlap")));
    }

    #[test]
    fn test_validation_detects_lockout_risk() {
        let current = FirewallConfig::default();
        let mut candidate = current.clone();

        // Find internal zone, set input policy to Drop and clear open ports (remove SSH and WebUI)
        let internal = candidate.zones.iter_mut().find(|z| z.name == "internal").unwrap();
        internal.input_policy = FirewallPolicy::Drop;
        internal.open_ports.clear();

        let report = validate_firewall_candidate(&candidate, &current, &[], || "tx-test".into());
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.contains("Anti-lockout guard")));
    }

    #[test]
    fn test_validation_accepts_valid_config_and_computes_diff() {
        let current = FirewallConfig::default();
        let mut candidate = current.clone();

        candidate.flow_offload = false;
        candidate.port_forwards.push(PortForwardRule {
            comment: Some("Plex".into()),
            src_zone: "external".into(),
            internal_ip: Ipv4Addr::new(192, 168, 1, 100).into(),
            external_port: 32400,
            internal_port: 32400,
            protocol: L4Protocol::Tcp,
            enable_hairpin: true,
        });

        let report = validate_firewall_candidate(&candidate, &current, &[], || "tx-valid-123".into());
        assert!(report.valid);
        assert_eq!(report.tx_id.as_deref(), Some("tx-valid-123"));
        assert!(report.errors.is_empty());
        assert!(report.diff_summary.iter().any(|d| d.contains("Flowtable offload: true -> false")));
        assert!(report.diff_summary.iter().any(|d| d.contains("32400")));
    }
}

