use super::*;

/// Install nftables rules to DROP outgoing TCP RSTs from interface-NAT
/// (SNAT) addresses. These addresses are owned by the userspace
/// dataplane; the kernel has no sockets for them and should never emit
/// RSTs.
pub(super) fn install_kernel_rst_suppression(state: &ForwardingState) {
    use nftables::batch::Batch;
    use nftables::expr::{BinaryOperation, Expression, NamedExpression, Payload, PayloadField};
    use nftables::schema::{Chain, NfListObject, Rule, Table};
    use nftables::stmt::{Counter, Match, Operator, Statement};
    use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

    let v4_addrs: Vec<String> = state
        .interface_nat_v4
        .keys()
        .map(|ip| ip.to_string())
        .collect();
    let v6_addrs: Vec<String> = state
        .interface_nat_v6
        .keys()
        .map(|ip| ip.to_string())
        .collect();

    let table_name = "bpfrx_dp_rst";
    let chain_name = "output";

    {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: table_name.into(),
            handle: None,
        }));
        let _ = nftables::helper::apply_ruleset(&batch.to_nftables());
    }

    if v4_addrs.is_empty() && v6_addrs.is_empty() {
        return;
    }

    let mut batch = Batch::new();
    batch.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: table_name.into(),
        handle: None,
    }));
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: table_name.into(),
        name: chain_name.into(),
        newname: None,
        handle: None,
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Output),
        prio: Some(0),
        dev: None,
        policy: Some(NfChainPolicy::Accept),
    }));

    let rst_drop_rule = |proto: &'static str, addr: &str| -> Vec<Statement<'static>> {
        vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                    PayloadField {
                        protocol: proto.into(),
                        field: "saddr".into(),
                    },
                ))),
                right: Expression::String(addr.to_string().into()),
                op: Operator::EQ,
            }),
            Statement::Match(Match {
                left: Expression::BinaryOperation(Box::new(BinaryOperation::AND(
                    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "tcp".into(),
                            field: "flags".into(),
                        },
                    ))),
                    Expression::Number(4),
                ))),
                right: Expression::Number(0),
                op: Operator::NEQ,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Drop(None),
        ]
    };

    for addr in &v4_addrs {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: table_name.into(),
            chain: chain_name.into(),
            expr: rst_drop_rule("ip", addr).into(),
            handle: None,
            index: None,
            comment: None,
        }));
    }
    for addr in &v6_addrs {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: table_name.into(),
            chain: chain_name.into(),
            expr: rst_drop_rule("ip6", addr).into(),
            handle: None,
            index: None,
            comment: None,
        }));
    }

    match nftables::helper::apply_ruleset(&batch.to_nftables()) {
        Ok(()) => {
            eprintln!(
                "RST_SUPPRESS: installed nftables rules for {} v4 + {} v6 SNAT addresses",
                v4_addrs.len(),
                v6_addrs.len()
            );
        }
        Err(err) => {
            eprintln!("RST_SUPPRESS: failed to apply nftables rules: {err}");
        }
    }
}

/// Remove the nftables RST suppression table on shutdown.
pub(crate) fn remove_kernel_rst_suppression() {
    use nftables::batch::Batch;
    use nftables::schema::{NfListObject, Table};
    use nftables::types::NfFamily;

    let mut batch = Batch::new();
    batch.delete(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: "bpfrx_dp_rst".into(),
        handle: None,
    }));
    let _ = nftables::helper::apply_ruleset(&batch.to_nftables());
}

pub(super) fn nat_translated_local_exclusions(
    snapshot: &ConfigSnapshot,
) -> (FastSet<Ipv4Addr>, FastSet<Ipv6Addr>) {
    let mut excluded_v4 = FastSet::default();
    let mut excluded_v6 = FastSet::default();
    let mut to_zones = FastSet::default();
    for rule in &snapshot.source_nat_rules {
        if rule.interface_mode && !rule.off && !rule.to_zone.is_empty() {
            to_zones.insert(rule.to_zone.clone());
        }
    }
    if to_zones.is_empty() {
        return (excluded_v4, excluded_v6);
    }
    for iface in &snapshot.interfaces {
        if iface.zone.is_empty() || !to_zones.contains(&iface.zone) {
            continue;
        }
        if let Some(v4) = pick_interface_v4(iface) {
            excluded_v4.insert(v4);
        }
        if let Some(v6) = pick_interface_v6(iface) {
            excluded_v6.insert(v6);
        }
    }
    (excluded_v4, excluded_v6)
}
