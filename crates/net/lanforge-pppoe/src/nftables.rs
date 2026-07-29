use std::borrow::Cow;

use lanforge_types::network::pppoe::PppoeNftablesConfig;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, RT, RTKey, TcpOption},
    helper::{self, NftablesError},
    schema::{Chain, FlowTable, NfListObject, Rule, Table},
    stmt::{Flow, Mangle, Match, Operator, Return, SetOp, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use tracing::{info, warn};

/// Resolves the effective table name, falling back to `"lanforge"` if unset.
fn table_name(cfg: &PppoeNftablesConfig) -> String {
    let t = cfg.table_name.trim();
    if t.is_empty() {
        "lanforge".into()
    } else {
        t.into()
    }
}

/// Builds a `Nftables` batch representing the router performance tuning ruleset.
#[allow(clippy::too_many_lines)]
fn build_ruleset(
    cfg: &PppoeNftablesConfig,
    ppp_iface: &str,
    lan_ifaces: &[String],
) -> nftables::schema::Nftables<'static> {
    let table: String = table_name(cfg);
    let chain_name = "forward";
    let flowtable_name = "f";

    let mut batch = Batch::new();

    // 1. Table
    batch.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: table.clone().into(),
        handle: None,
    }));

    // 2. Flowtable (if flow offload is enabled)
    if cfg.flow_offload {
        let mut devices: Vec<String> = Vec::new();
        if !ppp_iface.is_empty() {
            devices.push(ppp_iface.to_string());
        }
        for lan in lan_ifaces {
            if !lan.is_empty() && !devices.contains(lan) {
                devices.push(lan.clone());
            }
        }
        let dev: Vec<Cow<'static, str>> =
            devices.into_iter().map(std::convert::Into::into).collect();

        batch.add(NfListObject::FlowTable(FlowTable {
            family: NfFamily::INet,
            table: table.clone().into(),
            name: flowtable_name.into(),
            handle: None,
            hook: Some(NfHook::Ingress),
            prio: Some(0),
            dev: Some(dev.into()),
        }));
    }

    // 3. Forward chain
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: table.clone().into(),
        name: chain_name.into(),
        newname: None,
        handle: None,
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Forward),
        prio: Some(-10),
        dev: None,
        policy: Some(NfChainPolicy::Accept),
    }));

    // 4. Rules
    let add_rule = |stmts: Vec<Statement<'static>>| -> NfListObject<'static> {
        NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: table.clone().into(),
            chain: chain_name.into(),
            expr: stmts.into(),
            handle: None,
            index: None,
            comment: None,
        })
    };

    // DNS bypass (prevent flowtable socket buffer errors)
    if cfg.bypass_dns {
        for (proto, port_field) in [
            ("udp", "sport"),
            ("udp", "dport"),
            ("tcp", "sport"),
            ("tcp", "dport"),
        ] {
            batch.add(add_rule(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(
                        nftables::expr::Payload::PayloadField(nftables::expr::PayloadField {
                            protocol: proto.into(),
                            field: port_field.into(),
                        }),
                    )),
                    right: Expression::Number(53),
                    op: Operator::EQ,
                }),
                Statement::Return(Some(Return {})),
            ]));
        }
    }

    // VoWiFi / IPSec / IKEv2 bypass
    if cfg.bypass_vowifi {
        // UDP ports 500 and 4500
        for port in [500u32, 4500u32] {
            for field in ["sport", "dport"] {
                batch.add(add_rule(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(
                            nftables::expr::Payload::PayloadField(nftables::expr::PayloadField {
                                protocol: "udp".into(),
                                field: field.into(),
                            }),
                        )),
                        right: Expression::Number(port),
                        op: Operator::EQ,
                    }),
                    Statement::Return(Some(Return {})),
                ]));
            }
        }
        // ESP protocol bypass: meta l4proto esp return
        batch.add(add_rule(vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::String("esp".into()),
                op: Operator::EQ,
            }),
            Statement::Return(Some(Return {})),
        ]));
    }

    // Fast path flow offloading: ip/ip6 protocol { tcp, udp } flow add @f
    if cfg.flow_offload {
        let flowtable_ref = format!("@{flowtable_name}");
        let flow_stmt = Statement::Flow(Flow {
            op: SetOp::Add,
            flowtable: flowtable_ref.into(),
        });

        // IPv4: ip protocol { tcp, udp }
        batch.add(add_rule(vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(
                    nftables::expr::Payload::PayloadField(nftables::expr::PayloadField {
                        protocol: "ip".into(),
                        field: "protocol".into(),
                    }),
                )),
                right: Expression::Named(NamedExpression::Set(vec![
                    nftables::expr::SetItem::Element(Expression::String("tcp".into())),
                    nftables::expr::SetItem::Element(Expression::String("udp".into())),
                ])),
                op: Operator::EQ,
            }),
            flow_stmt.clone(),
        ]));

        // IPv6: ip6 nexthdr { tcp, udp }
        batch.add(add_rule(vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(
                    nftables::expr::Payload::PayloadField(nftables::expr::PayloadField {
                        protocol: "ip6".into(),
                        field: "nexthdr".into(),
                    }),
                )),
                right: Expression::Named(NamedExpression::Set(vec![
                    nftables::expr::SetItem::Element(Expression::String("tcp".into())),
                    nftables::expr::SetItem::Element(Expression::String("udp".into())),
                ])),
                op: Operator::EQ,
            }),
            flow_stmt,
        ]));
    }

    // TCP MSS clamping: tcp flags syn tcp option maxseg size set rt mtu
    if cfg.mss_clamping {
        batch.add(add_rule(vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(
                    nftables::expr::Payload::PayloadField(nftables::expr::PayloadField {
                        protocol: "tcp".into(),
                        field: "flags".into(),
                    }),
                )),
                right: Expression::String("syn".into()),
                op: Operator::IN,
            }),
            Statement::Mangle(Mangle {
                key: Expression::Named(NamedExpression::TcpOption(TcpOption {
                    name: "maxseg".into(),
                    field: Some("size".into()),
                })),
                value: Expression::Named(NamedExpression::RT(RT {
                    key: RTKey::MTU,
                    family: None,
                })),
            }),
        ]));
    }

    batch.to_nftables()
}

/// Applies the router tuning ruleset via the nftables crate's JSON API.
pub async fn apply_nftables_tuning(
    cfg: &PppoeNftablesConfig,
    ppp_iface: &str,
    lan_ifaces: &[String],
) -> Result<(), String> {
    if !cfg.enabled {
        info!("nftables performance tuning is disabled in configuration");
        return Ok(());
    }

    let ruleset = build_ruleset(cfg, ppp_iface, lan_ifaces);
    let table = table_name(cfg);
    let iface = ppp_iface.to_string();

    tokio::task::spawn_blocking(move || helper::apply_ruleset(&ruleset))
        .await
        .map_err(|e| format!("nftables apply task panicked: {e}"))?
        .map_err(|e| format!("nftables apply failed: {e}"))?;

    // Apply custom rules file separately, since raw nft text cannot be expressed
    // through the JSON API.
    if let Some(ref path_str) = cfg.custom_rules_file
        && !path_str.trim().is_empty()
    {
        if std::path::Path::new(path_str).exists() {
            let path = path_str.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let result = std::process::Command::new("nft")
                    .args(["-f", &path])
                    .output();
                match result {
                    Ok(out) if out.status.success() => Ok(()),
                    Ok(out) => Err(format!(
                        "nft -f {path}: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(format!("nft not found: {e}")),
                }
            })
            .await
            .map_err(|e| format!("custom rules task panicked: {e}"))?
            {
                warn!(error = %e, "Failed to apply custom nftables rules file");
            }
        } else {
            warn!(
                custom_file = path_str.as_str(),
                "Custom nftables rules file not found"
            );
        }
    }

    info!(
        table,
        interface = iface,
        "Successfully applied nftables router tuning rules"
    );
    Ok(())
}

/// Removes the lanforge nftables table cleanly.
pub async fn cleanup_nftables_tuning(table_name: &str) {
    let table: String = {
        let t = table_name.trim();
        if t.is_empty() {
            "lanforge".into()
        } else {
            t.into()
        }
    };

    let mut batch = Batch::new();
    batch.delete(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: table.clone().into(),
        handle: None,
    }));
    let ruleset = batch.to_nftables();

    let result = tokio::task::spawn_blocking(move || helper::apply_ruleset(&ruleset)).await;
    match result {
        Ok(Ok(())) => {
            info!(table, "Flushed and removed nftables tuning table");
        }
        Ok(Err(NftablesError::NftFailed { .. })) => {
            // Table may not exist or was already removed; ignore silently.
        }
        Ok(Err(NftablesError::NftExecution { inner, .. }))
            if inner.kind() == std::io::ErrorKind::NotFound => {}
        Ok(Err(e)) => {
            warn!(table, error = %e, "Failed to delete nftables tuning table");
        }
        Err(e) => {
            warn!(table, error = %e, "nftables cleanup task panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ruleset_default() {
        let cfg = PppoeNftablesConfig::default();
        let lan_ifaces = vec!["end0".to_string(), "br0".to_string()];
        let ruleset = build_ruleset(&cfg, "ppp0", &lan_ifaces);
        let json = serde_json::to_string(&ruleset).unwrap();

        assert!(json.contains("\"lanforge\""));
        // Flow table devices
        assert!(json.contains("ppp0"));
        assert!(json.contains("end0"));
        // DNS bypass
        assert!(json.contains("\"sport\""));
        assert!(json.contains("53"));
        // VoWiFi bypass (esp protocol)
        assert!(json.contains("\"esp\""));
        // Flow offload
        assert!(json.contains("\"@f\""));
        // MSS clamping
        assert!(json.contains("\"maxseg\""));
        assert!(json.contains("mtu"));
    }

    #[test]
    fn test_build_ruleset_disabled_offload() {
        let cfg = PppoeNftablesConfig {
            flow_offload: false,
            ..Default::default()
        };
        let ruleset = build_ruleset(&cfg, "ppp0", &[]);
        let json = serde_json::to_string(&ruleset).unwrap();

        assert!(!json.contains("flowtable"));
        assert!(!json.contains("\"@f\""));
        // MSS clamping still present
        assert!(json.contains("\"maxseg\""));
    }

    #[test]
    fn test_build_ruleset_minimal() {
        let cfg = PppoeNftablesConfig {
            enabled: true,
            flow_offload: false,
            mss_clamping: false,
            bypass_dns: false,
            bypass_vowifi: false,
            ..PppoeNftablesConfig::default()
        };
        let ruleset = build_ruleset(&cfg, "ppp0", &[]);
        let json = serde_json::to_string(&ruleset).unwrap();

        // Only table + chain, no rules beyond those
        assert!(json.contains("\"lanforge\""));
        assert!(json.contains("\"forward\""));
        assert!(!json.contains("53"));
        assert!(!json.contains("\"esp\""));
        assert!(!json.contains("\"@f\""));
        assert!(!json.contains("\"maxseg\""));
    }

    #[test]
    fn test_cleanup_batch_structure() {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: "lanforge".into(),
            handle: None,
        }));
        let ruleset = batch.to_nftables();
        let json = serde_json::to_string(&ruleset).unwrap();
        assert!(json.contains("\"delete\""));
        assert!(json.contains("\"lanforge\""));
    }
}
