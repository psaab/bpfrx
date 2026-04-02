use crate::prefix::{PrefixV4, PrefixV6};
use crate::{PolicyApplicationSnapshot, PolicyRuleSnapshot};
use ipnet::IpNet;
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const PROTO_GRE: u8 = 47;
const PROTO_OSPF: u8 = 89;
const PROTO_IPIP: u8 = 4;

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

#[derive(Debug)]
pub(crate) struct PolicyRule {
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    pub(crate) applications: Vec<ApplicationMatch>,
    /// Precompiled application matcher (protocol-indexed, exact-port sets).
    compiled_apps: CompiledApplications,
    pub(crate) action: PolicyAction,
    pub(crate) hit_count: AtomicU64,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            from_zone: String::new(),
            to_zone: String::new(),
            source_v4: Vec::new(),
            source_v6: Vec::new(),
            destination_v4: Vec::new(),
            destination_v6: Vec::new(),
            applications: Vec::new(),
            compiled_apps: CompiledApplications {
                match_any: true,
                by_protocol: FxHashMap::default(),
            },
            action: PolicyAction::Deny,
            hit_count: AtomicU64::new(0),
        }
    }
}

impl Clone for PolicyRule {
    fn clone(&self) -> Self {
        Self {
            from_zone: self.from_zone.clone(),
            to_zone: self.to_zone.clone(),
            source_v4: self.source_v4.clone(),
            source_v6: self.source_v6.clone(),
            destination_v4: self.destination_v4.clone(),
            destination_v6: self.destination_v6.clone(),
            applications: self.applications.clone(),
            compiled_apps: self.compiled_apps.clone(),
            action: self.action,
            hit_count: AtomicU64::new(self.hit_count.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRange {
    pub(crate) low: u16,
    pub(crate) high: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationMatch {
    pub(crate) protocol: u8,
    pub(crate) source_ports: Vec<PortRange>,
    pub(crate) destination_ports: Vec<PortRange>,
}

/// Pre-indexed application matcher: groups terms by protocol for O(1) lookup.
/// For exact single-port rules (the common case), stores them in a set
/// for O(1) hit instead of linear range scan.
#[derive(Clone, Debug)]
struct CompiledApplications {
    /// If true, matches any protocol/port (application "any").
    match_any: bool,
    /// Grouped by protocol for fast lookup. Key = protocol number.
    by_protocol: FxHashMap<u8, ProtoTerms>,
}

#[derive(Clone, Debug, Default)]
struct ProtoTerms {
    /// Exact destination port set (single-port terms compiled for O(1) lookup).
    exact_dst_ports: rustc_hash::FxHashSet<u16>,
    /// Port range terms that need linear scan (multi-port ranges).
    range_terms: Vec<(Vec<PortRange>, Vec<PortRange>)>, // (src_ranges, dst_ranges)
}

impl CompiledApplications {
    fn from_matches(apps: &[ApplicationMatch]) -> Self {
        if apps.is_empty() {
            return Self {
                match_any: true,
                by_protocol: FxHashMap::default(),
            };
        }
        let mut by_protocol: FxHashMap<u8, ProtoTerms> = FxHashMap::default();
        for app in apps {
            let entry = by_protocol.entry(app.protocol).or_default();
            // Optimise the common case: single exact dst port, no src port restriction.
            if app.source_ports.is_empty()
                && app.destination_ports.len() == 1
                && app.destination_ports[0].low == app.destination_ports[0].high
            {
                entry.exact_dst_ports.insert(app.destination_ports[0].low);
            } else {
                entry
                    .range_terms
                    .push((app.source_ports.clone(), app.destination_ports.clone()));
            }
        }
        Self {
            match_any: false,
            by_protocol,
        }
    }

    #[inline]
    fn matches(&self, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        if self.match_any {
            return true;
        }
        let Some(terms) = self.by_protocol.get(&protocol) else {
            return false;
        };
        // Fast path: check exact dst port set first (O(1)).
        if terms.exact_dst_ports.contains(&dst_port) {
            return true;
        }
        // Slow path: check range terms.
        terms.range_terms.iter().any(|(src_ranges, dst_ranges)| {
            port_ranges_match(src_ranges, src_port) && port_ranges_match(dst_ranges, dst_port)
        })
    }
}

/// Zone-pair key for the policy index.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ZonePairKey {
    from: String,
    to: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    /// All rules in original order (kept for hit-counter reporting).
    pub(crate) rules: Vec<PolicyRule>,
    /// Zone-pair index: maps (from_zone, to_zone) → indices into `rules`.
    /// Avoids scanning unrelated zone-pairs during evaluation.
    zone_pair_index: FxHashMap<ZonePairKey, Vec<usize>>,
    /// Indices of global rules (from_zone = "junos-global").
    global_indices: Vec<usize>,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            rules: Vec::new(),
            zone_pair_index: FxHashMap::default(),
            global_indices: Vec::new(),
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
        zone_pair_index: FxHashMap::default(),
        global_indices: Vec::new(),
    };
    for snap in rules {
        let mut rule = PolicyRule {
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            action: parse_action(&snap.action),
            ..PolicyRule::default()
        };
        for prefix in &snap.source_addresses {
            parse_address(prefix, &mut rule.source_v4, &mut rule.source_v6);
        }
        for prefix in &snap.destination_addresses {
            parse_address(prefix, &mut rule.destination_v4, &mut rule.destination_v6);
        }
        rule.applications = parse_applications(&snap.application_terms);
        rule.compiled_apps = CompiledApplications::from_matches(&rule.applications);
        let idx = state.rules.len();
        let is_global = rule.from_zone == "junos-global" || rule.to_zone == "junos-global";
        state.rules.push(rule);

        if is_global {
            state.global_indices.push(idx);
        } else {
            let key = ZonePairKey {
                from: snap.from_zone.clone(),
                to: snap.to_zone.clone(),
            };
            state.zone_pair_index.entry(key).or_default().push(idx);
        }
    }
    state
}

pub(crate) fn evaluate_policy(
    state: &PolicyState,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> PolicyAction {
    // Phase 2 optimisation: look up only the rules for this zone-pair
    // instead of scanning all rules. Global rules are checked afterward.
    // The ZonePairKey allocation is acceptable because evaluate_policy
    // only runs on session miss (new flows), not on the hot path.
    let key = ZonePairKey {
        from: from_zone.to_string(),
        to: to_zone.to_string(),
    };
    if let Some(indices) = state.zone_pair_index.get(&key) {
        for &idx in indices {
            if let Some(action) = try_match_rule(
                &state.rules[idx],
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            ) {
                return action;
            }
        }
    }
    // Global policies (junos-global) apply to any zone-pair.
    for &idx in &state.global_indices {
        if let Some(action) = try_match_rule(
            &state.rules[idx],
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
        ) {
            return action;
        }
    }
    state.default_action
}

/// Try to match a single policy rule against packet fields.
/// Returns the rule's action if all criteria match, None otherwise.
#[inline]
fn try_match_rule(
    rule: &PolicyRule,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> Option<PolicyAction> {
    if !rule.compiled_apps.matches(protocol, src_port, dst_port) {
        return None;
    }
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst))
            if nets_match_v4(&rule.source_v4, src) && nets_match_v4(&rule.destination_v4, dst) =>
        {
            rule.hit_count.fetch_add(1, Ordering::Relaxed);
            Some(rule.action)
        }
        (IpAddr::V6(src), IpAddr::V6(dst))
            if nets_match_v6(&rule.source_v6, src) && nets_match_v6(&rule.destination_v6, dst) =>
        {
            rule.hit_count.fetch_add(1, Ordering::Relaxed);
            Some(rule.action)
        }
        _ => None,
    }
}

fn parse_action(action: &str) -> PolicyAction {
    match action {
        "permit" => PolicyAction::Permit,
        "reject" => PolicyAction::Reject,
        _ => PolicyAction::Deny,
    }
}

fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => out_v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => out_v6.push(PrefixV6::from_net(net)),
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
            }
        }
    }
}

fn parse_applications(terms: &[PolicyApplicationSnapshot]) -> Vec<ApplicationMatch> {
    let mut out = Vec::with_capacity(terms.len());
    for term in terms {
        let Some(protocol) = parse_protocol(&term.protocol) else {
            continue;
        };
        let Some(source_ports) = parse_port_spec(&term.source_port) else {
            continue;
        };
        let Some(destination_ports) = parse_port_spec(&term.destination_port) else {
            continue;
        };
        out.push(ApplicationMatch {
            protocol,
            source_ports,
            destination_ports,
        });
    }
    out
}

fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        _ => protocol.parse::<u8>().ok(),
    }
}

fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() {
        return Some(Vec::new());
    }
    let normalized = match spec {
        "http" => "80",
        "https" => "443",
        "ssh" => "22",
        "telnet" => "23",
        "ftp" => "21",
        "ftp-data" => "20",
        "smtp" => "25",
        "dns" => "53",
        "pop3" => "110",
        "imap" => "143",
        "snmp" => "161",
        "ntp" => "123",
        "bgp" => "179",
        "ldap" => "389",
        "syslog" => "514",
        other => other,
    };
    if let Some((low, high)) = normalized.split_once('-') {
        let low = low.parse::<u16>().ok()?;
        let high = high.parse::<u16>().ok()?;
        if low == 0 || low > high {
            return None;
        }
        return Some(vec![PortRange { low, high }]);
    }
    let port = normalized.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
        low: port,
        high: port,
    }])
}

fn port_ranges_match(ranges: &[PortRange], port: u16) -> bool {
    ranges.is_empty()
        || ranges
            .iter()
            .any(|range| port >= range.low && port <= range.high)
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
                application_terms: Vec::new(),
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
                PROTO_TCP,
                12345,
                5201,
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
                PROTO_TCP,
                12345,
                5201,
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
                application_terms: Vec::new(),
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
                PROTO_TCP,
                12345,
                5201,
            ),
            PolicyAction::Permit
        );
    }

    #[test]
    fn named_application_matches_protocol_and_port() {
        let state = parse_policy_state(
            "deny",
            &[PolicyRuleSnapshot {
                name: "allow-http".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["junos-http".to_string()],
                application_terms: vec![PolicyApplicationSnapshot {
                    name: "junos-http".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "80".to_string(),
                }],
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
                PROTO_TCP,
                40000,
                80,
            ),
            PolicyAction::Permit
        );
        assert_eq!(
            evaluate_policy(
                &state,
                "lan",
                "wan",
                "10.0.61.100".parse().expect("src"),
                "172.16.80.200".parse().expect("dst"),
                PROTO_TCP,
                40000,
                443,
            ),
            PolicyAction::Deny
        );
    }

    #[test]
    fn application_set_matches_any_expanded_term() {
        let state = parse_policy_state(
            "deny",
            &[PolicyRuleSnapshot {
                name: "allow-web".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["web".to_string()],
                application_terms: vec![
                    PolicyApplicationSnapshot {
                        name: "junos-http".to_string(),
                        protocol: "tcp".to_string(),
                        source_port: String::new(),
                        destination_port: "80".to_string(),
                    },
                    PolicyApplicationSnapshot {
                        name: "junos-https".to_string(),
                        protocol: "tcp".to_string(),
                        source_port: String::new(),
                        destination_port: "443".to_string(),
                    },
                ],
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
                PROTO_TCP,
                40000,
                443,
            ),
            PolicyAction::Permit
        );
    }

    #[test]
    fn global_policy_matches_any_zone_pair() {
        let state = parse_policy_state(
            "deny",
            &[PolicyRuleSnapshot {
                name: "global-allow".to_string(),
                from_zone: "junos-global".to_string(),
                to_zone: "junos-global".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "permit".to_string(),
            }],
        );
        // Should match any zone pair
        assert_eq!(
            evaluate_policy(
                &state,
                "trust",
                "untrust",
                "10.0.0.1".parse().expect("src"),
                "8.8.8.8".parse().expect("dst"),
                PROTO_TCP,
                12345,
                443,
            ),
            PolicyAction::Permit
        );
        assert_eq!(
            evaluate_policy(
                &state,
                "dmz",
                "wan",
                "192.168.1.1".parse().expect("src"),
                "1.1.1.1".parse().expect("dst"),
                PROTO_UDP,
                5555,
                53,
            ),
            PolicyAction::Permit
        );
    }

    #[test]
    fn global_policy_evaluated_after_zone_specific() {
        let state = parse_policy_state(
            "deny",
            &[
                PolicyRuleSnapshot {
                    name: "deny-trust-to-untrust".to_string(),
                    from_zone: "trust".to_string(),
                    to_zone: "untrust".to_string(),
                    source_addresses: vec!["any".to_string()],
                    destination_addresses: vec!["any".to_string()],
                    applications: vec!["any".to_string()],
                    application_terms: Vec::new(),
                    action: "deny".to_string(),
                },
                PolicyRuleSnapshot {
                    name: "global-allow".to_string(),
                    from_zone: "junos-global".to_string(),
                    to_zone: "junos-global".to_string(),
                    source_addresses: vec!["any".to_string()],
                    destination_addresses: vec!["any".to_string()],
                    applications: vec!["any".to_string()],
                    application_terms: Vec::new(),
                    action: "permit".to_string(),
                },
            ],
        );
        // Zone-specific deny should take precedence (evaluated first)
        assert_eq!(
            evaluate_policy(
                &state,
                "trust",
                "untrust",
                "10.0.0.1".parse().expect("src"),
                "8.8.8.8".parse().expect("dst"),
                PROTO_TCP,
                12345,
                80,
            ),
            PolicyAction::Deny
        );
        // Different zone pair should hit the global permit
        assert_eq!(
            evaluate_policy(
                &state,
                "dmz",
                "wan",
                "10.0.0.1".parse().expect("src"),
                "8.8.8.8".parse().expect("dst"),
                PROTO_TCP,
                12345,
                80,
            ),
            PolicyAction::Permit
        );
    }
}
