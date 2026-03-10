use crate::SourceNATRuleSnapshot;
use crate::prefix::{PrefixV4, PrefixV6};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
}

impl NatDecision {
    pub(crate) fn reverse(self, original_src: IpAddr, original_dst: IpAddr) -> Self {
        Self {
            rewrite_src: self.rewrite_dst.map(|_| original_dst),
            rewrite_dst: self.rewrite_src.map(|_| original_src),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SourceNatRule {
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    pub(crate) interface_mode: bool,
    pub(crate) off: bool,
}

impl SourceNatRule {
    fn matches(&self, from_zone: &str, to_zone: &str, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        if !self.from_zone.is_empty() && self.from_zone != from_zone {
            return false;
        }
        if !self.to_zone.is_empty() && self.to_zone != to_zone {
            return false;
        }
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                nets_match_v4(&self.source_v4, src) && nets_match_v4(&self.destination_v4, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                nets_match_v6(&self.source_v6, src) && nets_match_v6(&self.destination_v6, dst)
            }
            _ => false,
        }
    }
}

pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    let mut out = Vec::with_capacity(snaps.len());
    for snap in snaps {
        let mut rule = SourceNatRule {
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            interface_mode: snap.interface_mode,
            off: snap.off,
            ..SourceNatRule::default()
        };
        for prefix in &snap.source_addresses {
            match prefix.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => rule.source_v4.push(PrefixV4::from_net(net)),
                Ok(IpNet::V6(net)) => rule.source_v6.push(PrefixV6::from_net(net)),
                Err(_) => {}
            }
        }
        for prefix in &snap.destination_addresses {
            match prefix.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => rule.destination_v4.push(PrefixV4::from_net(net)),
                Ok(IpNet::V6(net)) => rule.destination_v6.push(PrefixV6::from_net(net)),
                Err(_) => {}
            }
        }
        out.push(rule);
    }
    out
}

pub(crate) fn match_source_nat(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> Option<NatDecision> {
    for rule in rules {
        if !rule.matches(from_zone, to_zone, src_ip, dst_ip) {
            continue;
        }
        if rule.off {
            return Some(NatDecision::default());
        }
        if rule.interface_mode {
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            return Some(NatDecision {
                rewrite_src,
                rewrite_dst: None,
            });
        }
        return Some(NatDecision::default());
    }
    None
}

fn nets_match_v4(nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

fn nets_match_v6(nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_source_nat_matches_v4_rule() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }]);
        let decision = match_source_nat(
            &rules,
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        );
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("172.16.80.8".parse().expect("snat")),
                rewrite_dst: None,
            })
        );
    }

    #[test]
    fn interface_source_nat_matches_v6_rule() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "snat6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["::/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }]);
        let decision = match_source_nat(
            &rules,
            "lan",
            "wan",
            "2001:559:8585:ef00::100".parse().expect("src"),
            "2001:559:8585:80::200".parse().expect("dst"),
            None,
            Some("2001:559:8585:80::8".parse().expect("egress")),
        );
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
                rewrite_dst: None,
            })
        );
    }

    #[test]
    fn off_rule_short_circuits_translation() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "no-nat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.61.0/24".to_string()],
            off: true,
            ..SourceNATRuleSnapshot::default()
        }]);
        assert_eq!(
            match_source_nat(
                &rules,
                "lan",
                "wan",
                "10.0.61.102".parse().expect("src"),
                "172.16.80.200".parse().expect("dst"),
                Some("172.16.80.8".parse().expect("egress")),
                None,
            ),
            Some(NatDecision::default())
        );
    }

    #[test]
    fn reverse_decision_turns_snat_into_reply_dnat() {
        let decision = NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
        };
        assert_eq!(
            decision.reverse(
                "10.0.61.102".parse().expect("orig src"),
                "172.16.80.200".parse().expect("orig dst"),
            ),
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some("10.0.61.102".parse().expect("orig src")),
            }
        );
    }
}
