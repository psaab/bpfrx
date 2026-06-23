// Source NAT (SNAT) rules + matching + lookup.
//
// Owns rule parsing from snapshots, the address/port-pool match
// pipeline, and the public release/rollback entry points that
// drive the allocator. Pool ownership / persistent lease state
// machine lives in the sibling allocator.rs.

use super::allocator::{
    NS_PER_SEC, PersistentSourceKey, PoolAddressFamily, PortAllocator, TranslatedTuple,
};
use super::{NatCounterStore, NatDecision, NatRuleCounter};
use crate::SourceNATRuleSnapshot;
use crate::prefix::{PrefixV4, PrefixV6};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

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
    /// #1852: a non-first IP fragment reached a port-translating
    /// (pool-mode) source-NAT rule. It has no L4 ports — allocating a
    /// mapping from its garbage payload "ports" would leak a pool port
    /// per fragment and corrupt payload. Without datapath reassembly the
    /// fragment cannot be correctly port-mapped, so it is dropped.
    NonFirstFragment,
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
            Self::NonFirstFragment => "source_nat_non_first_fragment",
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
    /// #2398: whether the rule carried a `match source-address` constraint at
    /// all (snapshot source list non-empty), independent of how many entries
    /// parsed. `false` = unscoped source -> match any source (unchanged
    /// behavior). `true` but BOTH `source_v4`/`source_v6` empty (every
    /// configured prefix failed to parse) => match NOTHING (fail closed), never
    /// the pre-#2398 collapse-to-match-any fail-open broadening.
    pub(crate) source_constrained: bool,
    /// #2398: whether the rule carried a `match destination-address`
    /// constraint at all. Same fail-closed semantics as `source_constrained`,
    /// for the destination match set.
    pub(crate) destination_constrained: bool,
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
    /// #2218: per-rule translation hit counter, shared from the
    /// coordinator's `NatCounterStore`. `None` when the rule carries no
    /// per-rule counter (`counter_id == 0`). Captured at build time; the
    /// cold-path commit site clones the `Arc` and calls `.add(len)` once
    /// per committed translated forward flow.
    pub(crate) hit_counter: Option<Arc<NatRuleCounter>>,
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
                nets_match_v4(self.source_constrained, &self.source_v4, src)
                    && nets_match_v4(self.destination_constrained, &self.destination_v4, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                nets_match_v6(self.source_constrained, &self.source_v6, src)
                    && nets_match_v6(self.destination_constrained, &self.destination_v6, dst)
            }
            _ => false,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    parse_source_nat_rules_with_previous(snaps, None, &NatCounterStore::default())
}

pub(crate) fn parse_source_nat_rules_with_previous(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
    nat_counters: &NatCounterStore,
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
            // #2218: resolve the per-rule hit counter (None for counter_id 0).
            hit_counter: nat_counters.rule_counter(snap.counter_id),
            ..SourceNatRule::default()
        };
        // #2398: record whether each match set was scoped at all (snapshot list
        // non-empty), independent of how many prefixes parse. These flags drive
        // the fail-closed distinction in `nets_match_*`: a rule that WAS scoped
        // but whose configured prefixes ALL fail to parse must match NOTHING,
        // not collapse to match-any (the pre-#2398 fail-open broadening). An
        // unscoped (empty) set keeps "match any" (anti-over-restrict).
        rule.source_constrained = !snap.source_addresses.is_empty();
        rule.destination_constrained = !snap.destination_addresses.is_empty();
        // #2398: parse each match prefix as a CIDR, falling back to a bare host
        // IP -> /32 (v4) or /128 (v6). Junos carries source/destination-address
        // verbatim and the Go compiler does NOT normalize it, so a bare host
        // reaches the wire with no `/prefix`; `IpNet::from_str` REQUIRES
        // `addr/prefix` and rejects a bare IP. Without the fallback a bare-host
        // match would skip its only entry, leave the list empty, and (pre-#2398)
        // silently match ANY address — the exact fail-open this fix closes (and
        // the same bare-IP live bug fixed for DNAT in #2394).
        for prefix in &snap.source_addresses {
            parse_match_prefix(prefix, &mut rule.source_v4, &mut rule.source_v6);
        }
        for prefix in &snap.destination_addresses {
            parse_match_prefix(prefix, &mut rule.destination_v4, &mut rule.destination_v6);
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
    let mut counter = None;
    match_source_nat_result_for_tuple(
        rules,
        from_zone,
        to_zone,
        src_ip,
        dst_ip,
        0,
        0,
        0,
        egress_v4,
        egress_v6,
        0,
        false,
        &mut counter,
    )
}

/// #2218: same as `match_source_nat_result_for_tuple` but the matched
/// rule's per-rule hit counter (if any) is written to `matched_counter`.
/// The `SourceNatLookup` enum stays wire-/Eq-frozen (it is destructured
/// and `matches!`-compared in many tests and over no wire), so the counter
/// rides out via this out-parameter rather than a new enum payload — the
/// least-invasive shape. The cold-path commit site clones the captured
/// `Arc` and increments it once per committed translated flow.
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
    // #1852: when true, gate port-translating (pool-mode) allocation —
    // a non-first fragment has no L4 ports. Interface-mode (address-only)
    // and `off`/static rules are unaffected.
    non_first_fragment: bool,
    matched_counter: &mut Option<Arc<NatRuleCounter>>,
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
            // An `off` rule applies no translation — leave matched_counter
            // unset so no hit is counted for a no-op match.
            return SourceNatLookup::Matched(NatDecision::default());
        }
        *matched_counter = rule.hit_counter.clone();
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
            // This rule matched the zone/addresses but is neither
            // interface-mode nor pool-mode — it applies no translation, so
            // clear the tentatively-captured counter and try the next rule.
            *matched_counter = None;
            continue;
        }
        // #1852: pool-mode SNAT translates the L4 port. A non-first
        // fragment carries no L4 header at the post-IP offset (its
        // "ports" are payload), so allocating a mapping here would both
        // leak a pool port per fragment and write the allocated port into
        // payload bytes. Without datapath reassembly the fragment cannot
        // be correctly port-mapped — drop it (the caller records the
        // exception). Interface-mode SNAT (address-only) already returned
        // above, so it and static NAT keep working on fragments.
        if non_first_fragment {
            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                rule,
                SourceNatFailureReason::NonFirstFragment,
            ));
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

/// #2398: parse one match prefix into the family-appropriate prefix vec. A CIDR
/// (`10.0.0.0/24`) is parsed directly; a bare host IP (`10.0.0.5`) — which
/// `IpNet::from_str` rejects — falls back to a /32 (v4) or /128 (v6). A prefix
/// that parses as neither is dropped (it narrows the match rather than widening
/// it); the `*_constrained` flag, set from the snapshot list being non-empty,
/// makes an all-malformed set fail closed in `nets_match_*`.
fn parse_match_prefix(prefix: &str, v4: &mut Vec<PrefixV4>, v6: &mut Vec<PrefixV6>) {
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => v6.push(PrefixV6::from_net(net)),
        Err(_) => match prefix.parse::<IpAddr>() {
            Ok(IpAddr::V4(addr)) => {
                if let Ok(net) = Ipv4Net::new(addr, 32) {
                    v4.push(PrefixV4::from_net(net));
                }
            }
            Ok(IpAddr::V6(addr)) => {
                if let Ok(net) = Ipv6Net::new(addr, 128) {
                    v6.push(PrefixV6::from_net(net));
                }
            }
            Err(_) => {}
        },
    }
}

/// #2398: match a v4 IP against a rule's match set.
///
/// - `constrained == false` (unscoped match set): match any IP (unchanged).
/// - `constrained == true` but `nets` empty (every configured prefix failed to
///   parse): match NOTHING — fail closed, never the pre-#2398 collapse to
///   match-any fail-open broadening.
/// - otherwise: the IP must fall in one of the parsed prefixes.
fn nets_match_v4(constrained: bool, nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return false;
    }
    nets.iter().any(|net| net.contains(ip))
}

/// #2398: match a v6 IP against a rule's match set. See `nets_match_v4`.
fn nets_match_v6(constrained: bool, nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return false;
    }
    nets.iter().any(|net| net.contains(ip))
}
