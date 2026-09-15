use lanforge_types::network::firewall::{DynamicPortRequest, FirewallConfig, FirewallPolicy};
use nftables::batch::Batch;
use nftables::expr::{
    Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, TcpOption,
};
use nftables::schema::{Chain, FlowTable, NfListObject, Nftables, Rule, Table};
use nftables::stmt::{Mangle, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use std::borrow::Cow;

/// Builder that compiles a high-level `FirewallConfig` into an atomic `nftables` batch.
pub struct RulesetBuilder<'a> {
    cfg: &'a FirewallConfig,
    active_wan: Option<&'a str>,
    dynamic_ports: &'a [DynamicPortRequest],
}

impl<'a> RulesetBuilder<'a> {
    #[must_use]
    pub fn new(cfg: &'a FirewallConfig) -> Self {
        Self {
            cfg,
            active_wan: None,
            dynamic_ports: &[],
        }
    }

    #[must_use]
    pub fn with_active_wan(mut self, wan: Option<&'a str>) -> Self {
        self.active_wan = wan;
        self
    }

    #[must_use]
    pub fn with_dynamic_ports(mut self, ports: &'a [DynamicPortRequest]) -> Self {
        self.dynamic_ports = ports;
        self
    }

    /// Resolves effective table name (default: "lanforge").
    #[must_use]
    pub fn table_name(&self) -> &str {
        let t = self.cfg.table_name.trim();
        if t.is_empty() {
            "lanforge"
        } else {
            t
        }
    }

    /// Resolves all active interfaces associated with a zone name.
    #[must_use]
    pub fn resolve_zone_interfaces(&self, zone_name: &str) -> Vec<String> {
        let mut ifaces = Vec::new();
        for zone in &self.cfg.zones {
            if zone.name == zone_name {
                ifaces.extend(zone.interfaces.clone());
                // Auto-bind active WAN interface to external zone
                if (zone.name == "external" || zone.name == "wan")
                    && let Some(wan) = self.active_wan
                    && !ifaces.contains(&wan.to_string())
                {
                    ifaces.push(wan.to_string());
                }
            }
        }
        ifaces
    }

    /// Compiles the complete declarative ruleset.
    #[must_use]
    pub fn build(&self) -> Nftables<'static> {
        let table = self.table_name().to_string();
        let mut batch = Batch::new();

        // 1. Table
        batch.add(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: table.clone().into(),
            handle: None,
        }));

        if !self.cfg.enabled {
            return batch.to_nftables();
        }

        // 2. Flowtable (if flow offload is enabled and WAN or LAN interfaces exist)
        let mut flow_devices: Vec<String> = Vec::new();
        if let Some(wan) = self.active_wan
            && (wan.starts_with("ppp") || wan.is_empty())
        {
            flow_devices.push(wan.to_string());
        }
        for zone in &self.cfg.zones {
            if zone.name != "external" && zone.name != "wan" {
                for iface in &zone.interfaces {
                    if !iface.is_empty() && !flow_devices.contains(iface) {
                        flow_devices.push(iface.clone());
                    }
                }
            }
        }

        let flowtable_name = "f";
        if self.cfg.flow_offload && !flow_devices.is_empty() {
            let dev: Vec<Cow<'static, str>> =
                flow_devices.into_iter().map(Into::into).collect();

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

        // Helper closures to build rules
        let add_rule = |target_chain: &str, stmts: Vec<Statement<'static>>| -> NfListObject<'static> {
            NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: table.clone().into(),
                chain: target_chain.to_string().into(),
                expr: stmts.into(),
                handle: None,
                index: None,
                comment: None,
            })
        };

        // 3. Chain INPUT (Host protection)
        let input_policy = match self.cfg.default_input_policy {
            FirewallPolicy::Accept => NfChainPolicy::Accept,
            FirewallPolicy::Drop | FirewallPolicy::Reject => NfChainPolicy::Drop,
        };

        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: table.clone().into(),
            name: "input".into(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Input),
            prio: Some(0),
            dev: None,
            policy: Some(input_policy),
        }));

        // Rule: lo accept
        batch.add(add_rule("input", vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::Iifname,
                })),
                right: Expression::String("lo".into()),
                op: Operator::EQ,
            }),
            Statement::Return(None),
        ]));

        // Rule: ct state established,related accept
        batch.add(add_rule("input", vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::Iifname,
                })),
                right: Expression::String("lo".into()),
                op: Operator::NEQ,
            }),
        ]));

        // 4. Chain FORWARD (Gateway routing)
        let forward_policy = match self.cfg.default_forward_policy {
            FirewallPolicy::Accept => NfChainPolicy::Accept,
            FirewallPolicy::Drop | FirewallPolicy::Reject => NfChainPolicy::Drop,
        };

        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: table.clone().into(),
            name: "forward".into(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Forward),
            prio: Some(0),
            dev: None,
            policy: Some(forward_policy),
        }));

        // TCP MSS clamping
        for target_chain in ["forward", "output"] {
            if target_chain == "output" {
                batch.add(NfListObject::Chain(Chain {
                    family: NfFamily::INet,
                    table: table.clone().into(),
                    name: "output".into(),
                    newname: None,
                    handle: None,
                    _type: Some(NfChainType::Filter),
                    hook: Some(NfHook::Output),
                    prio: Some(-10),
                    dev: None,
                    policy: Some(NfChainPolicy::Accept),
                }));
            }

            // IPv4 MSS 1452
            batch.add(add_rule(target_chain, vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "ip".into(),
                            field: "protocol".into(),
                        },
                    ))),
                    right: Expression::String("tcp".into()),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "tcp".into(),
                            field: "flags".into(),
                        },
                    ))),
                    right: Expression::String("syn".into()),
                    op: Operator::IN,
                }),
                Statement::Mangle(Mangle {
                    key: Expression::Named(NamedExpression::TcpOption(TcpOption {
                        name: "maxseg".into(),
                        field: Some("size".into()),
                    })),
                    value: Expression::Number(1452),
                }),
            ]));

            // IPv6 MSS 1432
            batch.add(add_rule(target_chain, vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "ip6".into(),
                            field: "nexthdr".into(),
                        },
                    ))),
                    right: Expression::String("tcp".into()),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "tcp".into(),
                            field: "flags".into(),
                        },
                    ))),
                    right: Expression::String("syn".into()),
                    op: Operator::IN,
                }),
                Statement::Mangle(Mangle {
                    key: Expression::Named(NamedExpression::TcpOption(TcpOption {
                        name: "maxseg".into(),
                        field: Some("size".into()),
                    })),
                    value: Expression::Number(1432),
                }),
            ]));
        }

        // 5. Chain POSTROUTING (NAT / Masquerade)
        let external_ifaces = self.resolve_zone_interfaces("external");
        if !external_ifaces.is_empty() {
            batch.add(NfListObject::Chain(Chain {
                family: NfFamily::INet,
                table: table.clone().into(),
                name: "postrouting".into(),
                newname: None,
                handle: None,
                _type: Some(NfChainType::NAT),
                hook: Some(NfHook::Postrouting),
                prio: Some(100),
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            }));

            for ext in &external_ifaces {
                batch.add(add_rule("postrouting", vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Nfproto,
                        })),
                        right: Expression::String("ipv4".into()),
                        op: Operator::EQ,
                    }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Oifname,
                        })),
                        right: Expression::String(ext.clone().into()),
                        op: Operator::EQ,
                    }),
                    Statement::Masquerade(None),
                ]));
            }
        }

        batch.to_nftables()
    }
}
