use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallPolicy, HostPortRule, L4Protocol, PortForwardRule,
};
use nftables::batch::Batch;
use nftables::expr::{
    CT, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, TcpOption,
};
use nftables::schema::{Chain, FlowTable, FlushObject, NfCmd, NfListObject, Nftables, Rule, Table};
use nftables::stmt::{Flow, Limit, Mangle, Match, NATFamily, Operator, SetOp, Statement, NAT};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use std::borrow::Cow;
use std::net::IpAddr;

/// Builder that compiles a high-level `FirewallConfig` into an atomic `nftables` batch.
pub struct RulesetBuilder<'a> {
    cfg: &'a FirewallConfig,
    active_wan: Option<&'a str>,
    primary_lan: Option<&'a str>,
    dynamic_ports: &'a [DynamicPortRequest],
}

impl<'a> RulesetBuilder<'a> {
    #[must_use]
    pub const fn new(cfg: &'a FirewallConfig) -> Self {
        Self {
            cfg,
            active_wan: None,
            primary_lan: None,
            dynamic_ports: &[],
        }
    }

    #[must_use]
    pub const fn with_active_wan(mut self, wan: Option<&'a str>) -> Self {
        self.active_wan = wan;
        self
    }

    #[must_use]
    pub const fn with_primary_lan(mut self, lan: Option<&'a str>) -> Self {
        self.primary_lan = lan;
        self
    }

    #[must_use]
    pub const fn with_dynamic_ports(mut self, ports: &'a [DynamicPortRequest]) -> Self {
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
                // Auto-bind primary LAN interface to internal zone
                if (zone.name == "internal" || zone.name == "lan")
                    && let Some(lan) = self.primary_lan
                    && !ifaces.contains(&lan.to_string())
                {
                    ifaces.push(lan.to_string());
                }
            }
        }
        ifaces
    }

    /// Resolves all internal (non-external) interfaces across configured zones.
    #[must_use]
    pub fn resolve_internal_interfaces(&self) -> Vec<String> {
        let mut ifaces = Vec::new();
        for zone in &self.cfg.zones {
            if zone.name != "external" && zone.name != "wan" {
                for iface in self.resolve_zone_interfaces(&zone.name) {
                    if !iface.is_empty() && !ifaces.contains(&iface) {
                        ifaces.push(iface);
                    }
                }
            }
        }
        if let Some(lan) = self.primary_lan
            && !lan.is_empty()
            && !ifaces.contains(&lan.to_string())
        {
            ifaces.push(lan.to_string());
        }
        ifaces
    }

    /// Compiles the complete declarative ruleset.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn build(&self) -> Nftables<'static> {
        let table = self.table_name().to_string();
        let mut batch = Batch::new();

        // 1. Table: Add if not exists, then flush all previous chains/rules in table
        batch.add(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: table.clone().into(),
            handle: None,
        }));
        batch.add_cmd(NfCmd::Flush(FlushObject::Table(Table {
            family: NfFamily::INet,
            name: table.clone().into(),
            handle: None,
        })));

        if !self.cfg.enabled {
            return batch.to_nftables();
        }

        // 2. Flowtable (if flow offload is enabled and WAN or LAN interfaces exist)
        let mut flow_devices: Vec<String> = Vec::new();
        if let Some(wan) = self.active_wan
            && !wan.is_empty()
            && !flow_devices.contains(&wan.to_string())
        {
            flow_devices.push(wan.to_string());
        }
        for iface in self.resolve_internal_interfaces() {
            if !flow_devices.contains(&iface) {
                flow_devices.push(iface);
            }
        }

        let flowtable_name = "f";
        let has_flowtable = self.cfg.flow_offload && !flow_devices.is_empty();
        if has_flowtable {
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
        batch.add(add_rule(
            "input",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Iifname,
                    })),
                    right: Expression::String("lo".into()),
                    op: Operator::EQ,
                }),
                Statement::Accept(None),
            ],
        ));

        // Rule: ct state established,related accept
        batch.add(add_rule(
            "input",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(CT {
                        key: "state".into(),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::List(vec![
                        Expression::String("established".into()),
                        Expression::String("related".into()),
                    ]),
                    op: Operator::IN,
                }),
                Statement::Accept(None),
            ],
        ));

        // Rule: ct state invalid drop
        batch.add(add_rule(
            "input",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(CT {
                        key: "state".into(),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::String("invalid".into()),
                    op: Operator::EQ,
                }),
                Statement::Drop(None),
            ],
        ));

        // Rule: ICMP rate-limited echo-request (10/sec)
        batch.add(add_rule(
            "input",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "ip".into(),
                            field: "protocol".into(),
                        },
                    ))),
                    right: Expression::String("icmp".into()),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "icmp".into(),
                            field: "type".into(),
                        },
                    ))),
                    right: Expression::String("echo-request".into()),
                    op: Operator::EQ,
                }),
                Statement::Limit(Limit {
                    rate: 10,
                    rate_unit: Some("packets".into()),
                    per: Some("second".into()),
                    burst: Some(5),
                    burst_unit: None,
                    inv: None,
                }),
                Statement::Accept(None),
            ],
        ));

        // Rule: ICMPv6 rate-limited echo-request (20/sec)
        batch.add(add_rule(
            "input",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "ip6".into(),
                            field: "nexthdr".into(),
                        },
                    ))),
                    right: Expression::String("icmpv6".into()),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "icmpv6".into(),
                            field: "type".into(),
                        },
                    ))),
                    right: Expression::String("echo-request".into()),
                    op: Operator::EQ,
                }),
                Statement::Limit(Limit {
                    rate: 20,
                    rate_unit: Some("packets".into()),
                    per: Some("second".into()),
                    burst: Some(10),
                    burst_unit: None,
                    inv: None,
                }),
                Statement::Accept(None),
            ],
        ));

        // Rule: RFC 4890 Essential ICMPv6 types (ND, Packet Too Big, etc.)
        for icmpv6_type in [
            "destination-unreachable",
            "packet-too-big",
            "time-exceeded",
            "parameter-problem",
            "nd-router-solicit",
            "nd-router-advert",
            "nd-neighbor-solicit",
            "nd-neighbor-advert",
        ] {
            batch.add(add_rule(
                "input",
                vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: "ip6".into(),
                                field: "nexthdr".into(),
                            },
                        ))),
                        right: Expression::String("icmpv6".into()),
                        op: Operator::EQ,
                    }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: "icmpv6".into(),
                                field: "type".into(),
                            },
                        ))),
                        right: Expression::String(icmpv6_type.into()),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ],
            ));
        }

        // Rule: Bypass DNS (UDP/TCP 53) directly to router host
        if self.cfg.bypass_dns {
            for proto in ["udp", "tcp"] {
                batch.add(add_rule(
                    "input",
                    vec![
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                                PayloadField {
                                    protocol: proto.into(),
                                    field: "dport".into(),
                                },
                            ))),
                            right: Expression::Number(53),
                            op: Operator::EQ,
                        }),
                        Statement::Accept(None),
                    ],
                ));
            }
        }

        // Rule: Bypass VoWiFi (IKEv2 / IPsec ports 500, 4500)
        if self.cfg.bypass_vowifi {
            for port in [500, 4500] {
                batch.add(add_rule(
                    "input",
                    vec![
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                                PayloadField {
                                    protocol: "udp".into(),
                                    field: "dport".into(),
                                },
                            ))),
                            right: Expression::Number(port),
                            op: Operator::EQ,
                        }),
                        Statement::Accept(None),
                    ],
                ));
            }
        }

        // Host port rules: static from zone configuration
        for zone in &self.cfg.zones {
            let ifaces = self.resolve_zone_interfaces(&zone.name);
            for iface in &ifaces {
                for rule in &zone.open_ports {
                    Self::add_port_rule(&mut batch, &table, "input", iface, rule);
                }

                // Dynamic ports registered for this zone
                for dyn_port in self.dynamic_ports {
                    if dyn_port.zone == zone.name {
                        let rule = HostPortRule {
                            comment: dyn_port.comment.clone(),
                            port: dyn_port.port,
                            protocol: dyn_port.protocol,
                        };
                        Self::add_port_rule(&mut batch, &table, "input", iface, &rule);
                    }
                }

                // Zone-level ingress policy overrides
                match zone.input_policy {
                    FirewallPolicy::Accept => {
                        batch.add(add_rule(
                            "input",
                            vec![
                                Statement::Match(Match {
                                    left: Expression::Named(NamedExpression::Meta(Meta {
                                        key: MetaKey::Iifname,
                                    })),
                                    right: Expression::String(iface.clone().into()),
                                    op: Operator::EQ,
                                }),
                                Statement::Accept(None),
                            ],
                        ));
                    }
                    FirewallPolicy::Drop => {
                        batch.add(add_rule(
                            "input",
                            vec![
                                Statement::Match(Match {
                                    left: Expression::Named(NamedExpression::Meta(Meta {
                                        key: MetaKey::Iifname,
                                    })),
                                    right: Expression::String(iface.clone().into()),
                                    op: Operator::EQ,
                                }),
                                Statement::Drop(None),
                            ],
                        ));
                    }
                    FirewallPolicy::Reject => {
                        batch.add(add_rule(
                            "input",
                            vec![
                                Statement::Match(Match {
                                    left: Expression::Named(NamedExpression::Meta(Meta {
                                        key: MetaKey::Iifname,
                                    })),
                                    right: Expression::String(iface.clone().into()),
                                    op: Operator::EQ,
                                }),
                                Statement::Reject(None),
                            ],
                        ));
                    }
                }
            }
        }

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

        // Rule: ct state established,related accept
        batch.add(add_rule(
            "forward",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(CT {
                        key: "state".into(),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::List(vec![
                        Expression::String("established".into()),
                        Expression::String("related".into()),
                    ]),
                    op: Operator::IN,
                }),
                Statement::Accept(None),
            ],
        ));

        // Rule: ct state invalid drop
        batch.add(add_rule(
            "forward",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(CT {
                        key: "state".into(),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::String("invalid".into()),
                    op: Operator::EQ,
                }),
                Statement::Drop(None),
            ],
        ));

        // Rule: ct status dnat accept (Podman / Netavark & Port Forward reflection)
        batch.add(add_rule(
            "forward",
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(CT {
                        key: "status".into(),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::String("dnat".into()),
                    op: Operator::IN,
                }),
                Statement::Accept(None),
            ],
        ));

        // Flowtable offload in forward chain
        if has_flowtable {
            for proto in ["tcp", "udp"] {
                batch.add(add_rule(
                    "forward",
                    vec![
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Meta(Meta {
                                key: MetaKey::L4proto,
                            })),
                            right: Expression::String(proto.into()),
                            op: Operator::EQ,
                        }),
                        Statement::Flow(Flow {
                            op: SetOp::Add,
                            flowtable: format!("@{flowtable_name}").into(),
                        }),
                    ],
                ));
            }
        }

        // VoWiFi Forward bypass
        if self.cfg.bypass_vowifi {
            for port in [500, 4500] {
                batch.add(add_rule(
                    "forward",
                    vec![
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                                PayloadField {
                                    protocol: "udp".into(),
                                    field: "dport".into(),
                                },
                            ))),
                            right: Expression::Number(port),
                            op: Operator::EQ,
                        }),
                        Statement::Accept(None),
                    ],
                ));
            }
        }

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

        // Inter-zone forwarding matrix
        for fwd in &self.cfg.forwardings {
            let src_ifaces = self.resolve_zone_interfaces(&fwd.from);
            let dst_ifaces = self.resolve_zone_interfaces(&fwd.to);
            for src in &src_ifaces {
                for dst in &dst_ifaces {
                    batch.add(add_rule(
                        "forward",
                        vec![
                            Statement::Match(Match {
                                left: Expression::Named(NamedExpression::Meta(Meta {
                                    key: MetaKey::Iifname,
                                })),
                                right: Expression::String(src.clone().into()),
                                op: Operator::EQ,
                            }),
                            Statement::Match(Match {
                                left: Expression::Named(NamedExpression::Meta(Meta {
                                    key: MetaKey::Oifname,
                                })),
                                right: Expression::String(dst.clone().into()),
                                op: Operator::EQ,
                            }),
                            Statement::Accept(None),
                        ],
                    ));
                }
            }
        }

        // Intra-zone forwarding (when zone forward_policy is Accept)
        for zone in &self.cfg.zones {
            if zone.forward_policy == FirewallPolicy::Accept {
                let ifaces = self.resolve_zone_interfaces(&zone.name);
                for src in &ifaces {
                    for dst in &ifaces {
                        if src != dst {
                            batch.add(add_rule(
                                "forward",
                                vec![
                                    Statement::Match(Match {
                                        left: Expression::Named(NamedExpression::Meta(Meta {
                                            key: MetaKey::Iifname,
                                        })),
                                        right: Expression::String(src.clone().into()),
                                        op: Operator::EQ,
                                    }),
                                    Statement::Match(Match {
                                        left: Expression::Named(NamedExpression::Meta(Meta {
                                            key: MetaKey::Oifname,
                                        })),
                                        right: Expression::String(dst.clone().into()),
                                        op: Operator::EQ,
                                    }),
                                    Statement::Accept(None),
                                ],
                            ));
                        }
                    }
                }
            }
        }

        // 5. NAT Chains: PREROUTING & POSTROUTING
        let has_port_forwards = !self.cfg.port_forwards.is_empty();
        let external_ifaces = self.resolve_zone_interfaces("external");
        let internal_ifaces = self.resolve_internal_interfaces();

        if has_port_forwards {
            batch.add(NfListObject::Chain(Chain {
                family: NfFamily::INet,
                table: table.clone().into(),
                name: "prerouting".into(),
                newname: None,
                handle: None,
                _type: Some(NfChainType::NAT),
                hook: Some(NfHook::Prerouting),
                prio: Some(-100),
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            }));

            for pf in &self.cfg.port_forwards {
                let src_ifaces = self.resolve_zone_interfaces(&pf.src_zone);
                let protos = match pf.protocol {
                    L4Protocol::Tcp => vec!["tcp"],
                    L4Protocol::Udp => vec!["udp"],
                    L4Protocol::Both => vec!["tcp", "udp"],
                };

                for iface in &src_ifaces {
                    for proto in &protos {
                        Self::add_dnat_rule(&mut batch, &table, iface, proto, pf);
                    }
                }

                // Hairpin NAT: internal clients requesting external port
                if pf.enable_hairpin {
                    for int_iface in &internal_ifaces {
                        for proto in &protos {
                            Self::add_dnat_rule(&mut batch, &table, int_iface, proto, pf);
                        }
                    }
                }
            }
        }

        // Chain POSTROUTING (NAT Masquerade & Hairpin NAT)
        let has_hairpin = self.cfg.port_forwards.iter().any(|p| p.enable_hairpin);
        let has_masquerade = !external_ifaces.is_empty()
            || self.cfg.zones.iter().any(|z| z.masquerade);

        if has_masquerade || has_hairpin {
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

            // WAN IPv4 Masquerade
            for ext in &external_ifaces {
                batch.add(add_rule(
                    "postrouting",
                    vec![
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
                    ],
                ));
            }

            // Zones with explicit masquerade enabled
            for zone in &self.cfg.zones {
                if zone.masquerade && zone.name != "external" && zone.name != "wan" {
                    for iface in &zone.interfaces {
                        batch.add(add_rule(
                            "postrouting",
                            vec![
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
                                    right: Expression::String(iface.clone().into()),
                                    op: Operator::EQ,
                                }),
                                Statement::Masquerade(None),
                            ],
                        ));
                    }
                }
            }

            // Hairpin NAT Masquerade
            if has_hairpin {
                for int_iface in &internal_ifaces {
                    batch.add(add_rule(
                        "postrouting",
                        vec![
                            Statement::Match(Match {
                                left: Expression::Named(NamedExpression::Meta(Meta {
                                    key: MetaKey::Iifname,
                                })),
                                right: Expression::String(int_iface.clone().into()),
                                op: Operator::EQ,
                            }),
                            Statement::Match(Match {
                                left: Expression::Named(NamedExpression::Meta(Meta {
                                    key: MetaKey::Oifname,
                                })),
                                right: Expression::String(int_iface.clone().into()),
                                op: Operator::EQ,
                            }),
                            Statement::Match(Match {
                                left: Expression::Named(NamedExpression::CT(CT {
                                    key: "status".into(),
                                    family: None,
                                    dir: None,
                                })),
                                right: Expression::String("dnat".into()),
                                op: Operator::IN,
                            }),
                            Statement::Masquerade(None),
                        ],
                    ));
                }
            }
        }

        batch.to_nftables()
    }

    fn add_port_rule(
        batch: &mut Batch<'static>,
        table: &str,
        chain: &str,
        iface: &str,
        rule: &HostPortRule,
    ) {
        let protos = match rule.protocol {
            L4Protocol::Tcp => vec!["tcp"],
            L4Protocol::Udp => vec!["udp"],
            L4Protocol::Both => vec!["tcp", "udp"],
        };

        for proto in protos {
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: table.to_string().into(),
                chain: chain.to_string().into(),
                expr: vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Iifname,
                        })),
                        right: Expression::String(iface.to_string().into()),
                        op: Operator::EQ,
                    }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: proto.into(),
                                field: "dport".into(),
                            },
                        ))),
                        right: Expression::Number(u32::from(rule.port)),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]
                .into(),
                handle: None,
                index: None,
                comment: rule.comment.as_ref().map(|c| c.clone().into()),
            }));
        }
    }

    fn add_dnat_rule(
        batch: &mut Batch<'static>,
        table: &str,
        iface: &str,
        proto: &'static str,
        rule: &PortForwardRule,
    ) {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: table.to_string().into(),
            chain: "prerouting".into(),
            expr: vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Iifname,
                    })),
                    right: Expression::String(iface.to_string().into()),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: proto.into(),
                            field: "dport".into(),
                        },
                    ))),
                    right: Expression::Number(u32::from(rule.external_port)),
                    op: Operator::EQ,
                }),
                Statement::DNAT(Some(NAT {
                    addr: Some(Expression::String(rule.internal_ip.to_string().into())),
                    family: match rule.internal_ip {
                        IpAddr::V4(_) => Some(NATFamily::IP),
                        IpAddr::V6(_) => Some(NATFamily::IP6),
                    },
                    port: Some(Expression::Number(u32::from(rule.internal_port))),
                    flags: None,
                })),
            ]
            .into(),
            handle: None,
            index: None,
            comment: rule.comment.as_ref().map(|c| c.clone().into()),
        }));
    }
}
