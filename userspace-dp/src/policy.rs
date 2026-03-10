use crate::PolicyRuleSnapshot;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyAction {
    Permit,
    Deny,
    Reject,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Deny
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PolicyRule {
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) source_v4: Vec<Ipv4Net>,
    pub(crate) source_v6: Vec<Ipv6Net>,
    pub(crate) destination_v4: Vec<Ipv4Net>,
    pub(crate) destination_v6: Vec<Ipv6Net>,
    pub(crate) applications: Vec<String>,
    pub(crate) action: PolicyAction,
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    pub(crate) rules: Vec<PolicyRule>,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            rules: Vec::new(),
        }
    }
}

pub(crate) fn parse_policy_state(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
) -> PolicyState {
    let mut state = PolicyState {
        default_action: parse_action(default_policy),
        rules: Vec::with_capacity(rules.len()),
    };
    for snap in rules {
        let mut rule = PolicyRule {
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            applications: snap.applications.clone(),
            action: parse_action(&snap.action),
            ..PolicyRule::default()
        };
        for prefix in &snap.source_addresses {
            parse_address(prefix, &mut rule.source_v4, &mut rule.source_v6);
        }
        for prefix in &snap.destination_addresses {
            parse_address(prefix, &mut rule.destination_v4, &mut rule.destination_v6);
        }
        state.rules.push(rule);
    }
    state
}

pub(crate) fn evaluate_policy(
    state: &PolicyState,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> PolicyAction {
    for rule in &state.rules {
        if !rule.from_zone.is_empty() && rule.from_zone != from_zone {
            continue;
        }
        if !rule.to_zone.is_empty() && rule.to_zone != to_zone {
            continue;
        }
        if !applications_match(&rule.applications) {
            continue;
        }
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst))
                if nets_match_v4(&rule.source_v4, src)
                    && nets_match_v4(&rule.destination_v4, dst) =>
            {
                return rule.action;
            }
            (IpAddr::V6(src), IpAddr::V6(dst))
                if nets_match_v6(&rule.source_v6, src)
                    && nets_match_v6(&rule.destination_v6, dst) =>
            {
                return rule.action;
            }
            _ => {}
        }
    }
    state.default_action
}

fn parse_action(action: &str) -> PolicyAction {
    match action {
        "permit" => PolicyAction::Permit,
        "reject" => PolicyAction::Reject,
        _ => PolicyAction::Deny,
    }
}

fn parse_address(prefix: &str, out_v4: &mut Vec<Ipv4Net>, out_v6: &mut Vec<Ipv6Net>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => out_v4.push(net),
        Ok(IpNet::V6(net)) => out_v6.push(net),
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(Ipv4Net::new(ip, 32).expect("v4 /32"));
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(Ipv6Net::new(ip, 128).expect("v6 /128"));
            }
        }
    }
}

fn applications_match(applications: &[String]) -> bool {
    applications.is_empty()
        || applications
            .iter()
            .all(|app| app.is_empty() || app == "any")
}

fn nets_match_v4(nets: &[Ipv4Net], ip: Ipv4Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(&ip))
}

fn nets_match_v6(nets: &[Ipv6Net], ip: Ipv6Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_matches_zone_pair() {
        let state = parse_policy_state(
            "deny",
            &[PolicyRuleSnapshot {
                name: "allow-all".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
            }],
        );
        assert_eq!(
            evaluate_policy(
                &state,
                "lan",
                "wan",
                "10.0.61.100".parse().expect("src"),
                "172.16.80.200".parse().expect("dst"),
            ),
            PolicyAction::Permit
        );
    }

    #[test]
    fn default_deny_applies_without_match() {
        let state = parse_policy_state("deny", &[]);
        assert_eq!(
            evaluate_policy(
                &state,
                "lan",
                "wan",
                "10.0.61.100".parse().expect("src"),
                "172.16.80.200".parse().expect("dst"),
            ),
            PolicyAction::Deny
        );
    }

    #[test]
    fn cidr_matches_ipv6() {
        let state = parse_policy_state(
            "deny",
            &[PolicyRuleSnapshot {
                name: "allow-v6".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["2001:559:8585:ef00::/64".to_string()],
                destination_addresses: vec!["2001:559:8585:80::/64".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
            }],
        );
        assert_eq!(
            evaluate_policy(
                &state,
                "lan",
                "wan",
                "2001:559:8585:ef00::100".parse().expect("src"),
                "2001:559:8585:80::200".parse().expect("dst"),
            ),
            PolicyAction::Permit
        );
    }
}
