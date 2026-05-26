// Source NAT (SNAT) rules + matching + lookup.
//
// Owns rule parsing from snapshots, the address/port-pool match
// pipeline, and the public release/rollback entry points that
// drive the allocator. Pool ownership / persistent lease state
// machine lives in the sibling allocator.rs.

use super::allocator::{
    PersistentSourceKey, PoolAddressFamily, PortAllocator, TranslatedTuple, NS_PER_SEC,
};
use super::NatDecision;
use crate::prefix::{PrefixV4, PrefixV6};
use crate::SourceNATRuleSnapshot;
use ipnet::IpNet;
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS: i64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatLookup {
    NoMatch,
    Matched(NatDecision),
    Unavailable(SourceNatFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceNatFailure {
    pub(crate) rule_name: String,
    pub(crate) pool_name: String,
    pub(crate) reason: SourceNatFailureReason,
}

impl SourceNatFailure {
    fn for_rule(rule: &SourceNatRule, reason: SourceNatFailureReason) -> Self {
        Self {
            rule_name: rule.name.clone(),
            pool_name: rule.pool_name.clone(),
            reason,
        }
    }

    pub(crate) fn exception_reason(&self) -> &'static str {
        self.reason.exception_reason()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatFailureReason {
    MissingPool,
    EmptyPool,
    InvalidPool,
    InvalidPortRange,
    WrongAddressFamily,
    AllocatorExhausted,
}

impl SourceNatFailureReason {
    fn exception_reason(self) -> &'static str {
        match self {
            Self::MissingPool => "source_nat_pool_missing",
            Self::EmptyPool => "source_nat_pool_empty",
            Self::InvalidPool => "source_nat_pool_invalid",
            Self::InvalidPortRange => "source_nat_pool_invalid_port_range",
            Self::WrongAddressFamily => "source_nat_pool_wrong_family",
            Self::AllocatorExhausted => "source_nat_pool_exhausted",
        }
    }
}

fn source_nat_failure_reason_from_snapshot(reason: &str) -> SourceNatFailureReason {
    match reason {
        "missing_pool" => SourceNatFailureReason::MissingPool,
        "empty_pool" => SourceNatFailureReason::EmptyPool,
        "invalid_port_range" => SourceNatFailureReason::InvalidPortRange,
        "invalid_pool" => SourceNatFailureReason::InvalidPool,
        "wrong_address_family" => SourceNatFailureReason::WrongAddressFamily,
        "allocator_exhausted" => SourceNatFailureReason::AllocatorExhausted,
        _ => SourceNatFailureReason::InvalidPool,
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SourceNatFlowKey {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
}

impl SourceNatFlowKey {
    pub(super) fn persistent_source_key(self) -> PersistentSourceKey {
        PersistentSourceKey {
            protocol: self.protocol,
            src_ip: self.src_ip,
            src_port: self.src_port,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SourceNatRule {
    pub(crate) name: String,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    pub(crate) interface_mode: bool,
    pub(crate) off: bool,
    pub(crate) pool_name: String,
    pub(crate) pool_mode: bool,
    pub(crate) pool_failure: Option<SourceNatFailureReason>,
    pub(crate) address_persistent: bool,
    pub(crate) persistent_nat: bool,
    pub(crate) persistent_nat_permit_any_remote_host: bool,
    pub(crate) persistent_nat_inactivity_timeout_secs: i64,
    pub(crate) persistent_nat_timeout_ns: u64,
    pub(crate) pool_addresses_v4: Vec<Ipv4Addr>,
    pub(crate) pool_addresses_v6: Vec<Ipv6Addr>,
    pub(crate) pool_allocator: PortAllocator,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SourceNatPoolAllocatorKey {
    pool_name: String,
    pool_addresses_v4: Vec<Ipv4Addr>,
    pool_addresses_v6: Vec<Ipv6Addr>,
    port_low: u16,
    port_high: u16,
}

impl SourceNatRule {
    fn allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
        let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
        (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
            SourceNatPoolAllocatorKey {
                pool_name: self.pool_name.clone(),
                pool_addresses_v4: self.pool_addresses_v4.clone(),
                pool_addresses_v6: self.pool_addresses_v6.clone(),
                port_low: self.pool_allocator.port_low,
                port_high: self.pool_allocator.port_high,
            }
        })
    }
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    parse_source_nat_rules_with_previous(snaps, None)
}

pub(crate) fn parse_source_nat_rules_with_previous(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
) -> Vec<SourceNatRule> {
    // Persistent SNAT allocator state is helper-local runtime state. A
    // compatible in-process refresh may reuse the previous allocator below,
    // but a helper cold start passes `None` here and intentionally resets live
    // tuple ownership, persistent leases, and allocator counters instead of
    // replaying unproven translated tuple ownership.
    let mut out = Vec::with_capacity(snaps.len());
    let mut previous_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    if let Some(prev_rules) = previous {
        for prev in prev_rules {
            if let Some(key) = prev.allocator_key() {
                previous_allocators
                    .entry(key)
                    .or_insert_with(|| prev.pool_allocator.clone());
            }
        }
    }
    let mut pool_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    for snap in snaps {
        let timeout_secs = if snap.persistent_nat_inactivity_timeout > 0 {
            snap.persistent_nat_inactivity_timeout
        } else {
            DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS
        };
        let mut rule = SourceNatRule {
            name: snap.name.clone(),
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            interface_mode: snap.interface_mode,
            off: snap.off,
            pool_name: snap.pool_name.clone(),
            pool_mode: !snap.pool_name.is_empty() || !snap.pool_addresses.is_empty(),
            address_persistent: snap.address_persistent,
            persistent_nat: snap.persistent_nat,
            persistent_nat_permit_any_remote_host: snap.persistent_nat_permit_any_remote_host,
            persistent_nat_inactivity_timeout_secs: timeout_secs,
            persistent_nat_timeout_ns: (timeout_secs as u64).saturating_mul(NS_PER_SEC),
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
        // Parse pool addresses and port range for pool-mode SNAT.
        let mut invalid_pool_address = false;
        for addr_str in &snap.pool_addresses {
            // Pool addresses may be bare IPs or /32 CIDRs — strip the mask.
            let ip_str = addr_str.split('/').next().unwrap_or(addr_str);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => rule.pool_addresses_v4.push(v4),
                    IpAddr::V6(v6) => rule.pool_addresses_v6.push(v6),
                }
            } else {
                invalid_pool_address = true;
            }
        }
        let total_pool = rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len();
        let port_low = if snap.port_low > 0 {
            snap.port_low
        } else {
            1024
        };
        let port_high = if snap.port_high > 0 {
            snap.port_high
        } else {
            65535
        };
        if snap.pool_unusable {
            rule.pool_failure = Some(source_nat_failure_reason_from_snapshot(
                &snap.pool_unusable_reason,
            ));
        } else if rule.pool_mode && invalid_pool_address {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPool);
        } else if rule.pool_mode && total_pool == 0 {
            rule.pool_failure = Some(if snap.pool_addresses.is_empty() {
                SourceNatFailureReason::EmptyPool
            } else {
                SourceNatFailureReason::MissingPool
            });
        } else if rule.pool_mode && port_low > port_high {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPortRange);
        }
        if total_pool > 0 {
            rule.pool_allocator = PortAllocator::new(total_pool, port_low, port_high);
        }
        if let Some(key) = rule.allocator_key() {
            if let Some(existing) = pool_allocators.get(&key) {
                rule.pool_allocator = existing.clone();
            } else {
                let allocator = previous_allocators
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| rule.pool_allocator.clone());
                rule.pool_allocator = allocator.clone();
                pool_allocators.insert(key, allocator);
            }
        }
        out.push(rule);
    }
    out
}

#[allow(dead_code)]
fn source_nat_runtime_compatible(new_rule: &SourceNatRule, old_rule: &SourceNatRule) -> bool {
    new_rule.name == old_rule.name
        && new_rule.pool_name == old_rule.pool_name
        && new_rule.pool_mode == old_rule.pool_mode
        && new_rule.pool_failure == old_rule.pool_failure
        && new_rule.address_persistent == old_rule.address_persistent
        && new_rule.persistent_nat == old_rule.persistent_nat
        && new_rule.persistent_nat_permit_any_remote_host
            == old_rule.persistent_nat_permit_any_remote_host
        && new_rule.persistent_nat_inactivity_timeout_secs
            == old_rule.persistent_nat_inactivity_timeout_secs
        && new_rule.pool_addresses_v4 == old_rule.pool_addresses_v4
        && new_rule.pool_addresses_v6 == old_rule.pool_addresses_v6
        && new_rule.pool_allocator.port_low == old_rule.pool_allocator.port_low
        && new_rule.pool_allocator.port_high == old_rule.pool_allocator.port_high
}

pub(crate) fn release_source_nat_allocation(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_source_nat_allocation_with_mode(rules, key, nat, is_reverse, now_ns, false);
}

pub(crate) fn rollback_source_nat_allocation(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_source_nat_allocation_with_mode(rules, key, nat, is_reverse, now_ns, true);
}

fn release_source_nat_allocation_with_mode(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    rollback: bool,
) {
    if is_reverse {
        return;
    }
    let Some(rewrite_src) = nat.rewrite_src else {
        return;
    };
    let Some(rewrite_src_port) = nat.rewrite_src_port else {
        return;
    };
    let translated = TranslatedTuple {
        ip: rewrite_src,
        port: rewrite_src_port,
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
    for rule in rules {
        if !rule.pool_mode {
            continue;
        }
        let released = if rollback {
            rule.pool_allocator.rollback_flow(flow, translated, now_ns)
        } else {
            rule.pool_allocator.release_flow(flow, translated, now_ns)
        };
        if released {
            break;
        }
    }
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
    match match_source_nat_result(
        rules, from_zone, to_zone, src_ip, dst_ip, egress_v4, egress_v6,
    ) {
        SourceNatLookup::Matched(decision) => Some(decision),
        SourceNatLookup::NoMatch | SourceNatLookup::Unavailable(_) => None,
    }
}

pub(crate) fn match_source_nat_result(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> SourceNatLookup {
    match_source_nat_result_for_tuple(
        rules, from_zone, to_zone, src_ip, dst_ip, 0, 0, 0, egress_v4, egress_v6, 0,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn match_source_nat_result_for_tuple(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
    now_ns: u64,
) -> SourceNatLookup {
    let flow = SourceNatFlowKey {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    };
    for rule in rules {
        if !rule.matches(from_zone, to_zone, src_ip, dst_ip) {
            continue;
        }
        if rule.off {
            return SourceNatLookup::Matched(NatDecision::default());
        }
        if rule.interface_mode {
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            return SourceNatLookup::Matched(NatDecision {
                rewrite_src,
                rewrite_dst: None,
                ..NatDecision::default()
            });
        }
        if rule.pool_mode {
            if let Some(reason) = rule.pool_failure {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(rule, reason));
            }
        } else {
            continue;
        }
        // Pool-mode SNAT: pick address by source-IP hash when
        // address-persistent is enabled, otherwise round-robin by family.
        let tupleless_lookup = protocol == 0 && src_port == 0 && dst_port == 0;
        match src_ip {
            IpAddr::V4(_) if !rule.pool_addresses_v4.is_empty() => {
                if tupleless_lookup {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        0,
                        rule.pool_addresses_v4.len(),
                        rule.address_persistent,
                    );
                    let pool_addr = rule.pool_addresses_v4[addr_idx];
                    let port = match rule.pool_allocator.try_next_port(addr_idx) {
                        Ok(port) => port,
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    };
                    return SourceNatLookup::Matched(NatDecision {
                        rewrite_src: Some(IpAddr::V4(pool_addr)),
                        rewrite_dst: None,
                        rewrite_src_port: Some(port),
                        rewrite_dst_port: None,
                        ..NatDecision::default()
                    });
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V4(&rule.pool_addresses_v4),
                    0,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            IpAddr::V6(_) if !rule.pool_addresses_v6.is_empty() => {
                let v6_offset = rule.pool_addresses_v4.len();
                if tupleless_lookup {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        v6_offset,
                        rule.pool_addresses_v6.len(),
                        rule.address_persistent,
                    );
                    let v6_idx = addr_idx - v6_offset;
                    let pool_addr = rule.pool_addresses_v6[v6_idx];
                    let port = match rule.pool_allocator.try_next_port(addr_idx) {
                        Ok(port) => port,
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    };
                    return SourceNatLookup::Matched(NatDecision {
                        rewrite_src: Some(IpAddr::V6(pool_addr)),
                        rewrite_dst: None,
                        rewrite_src_port: Some(port),
                        rewrite_dst_port: None,
                        ..NatDecision::default()
                    });
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V6(&rule.pool_addresses_v6),
                    v6_offset,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            _ => {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::WrongAddressFamily,
                ));
            }
        }
    }
    SourceNatLookup::NoMatch
}

fn nets_match_v4(nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

fn nets_match_v6(nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}
