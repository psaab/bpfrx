// Filter evaluation (non-TX-selection) extracted from engine.rs by #1546.
// Bodies byte-identical with the pre-split versions; `term_matches*` calls
// now go through `super::matching::*` (same crate, `#[inline(always)]`
// preserved on the callees).
//
// Module responsibility: input/output filter evaluation against a packet,
// including lo0 host-bound filter, per-interface input filter, per-interface
// output filter, the non-routing-instance variants (filter PBR rejects),
// the log-match diagnostic, and the routing-instance overrides. Also holds
// the precheck `interface_filter_affects_route_lookup` because it is paired
// with `evaluate_interface_filter_routing_instance_event_counted` at the
// only external call site (afxdp/forwarding/mod.rs:929/:936).

use super::super::*;
use super::matching::{term_matches, term_matches_v4, term_matches_v6};

/// Evaluate a named filter against a packet flow. First matching term wins.
/// If no term matches, the implicit action is Accept.
pub(crate) fn evaluate_filter(
    state: &FilterState,
    filter_key: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_filter_counted(
        state, filter_key, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_filter_counted(
    state: &FilterState,
    filter_key: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let Some(filter) = state.filters.get(filter_key) else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

#[inline]
pub(super) fn evaluate_filter_ref_counted(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        _ => FilterResult::default(),
    }
}

#[inline]
fn evaluate_filter_ref_counted_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return FilterResult {
            action: term.action.clone(),
            dscp_rewrite: term.dscp_rewrite,
            policer_name: term.policer_name.clone(),
            routing_instance: term.routing_instance.clone(),
            forwarding_class: term.forwarding_class.clone(),
            log: term.log,
            log_match: filter_log_match(filter, term),
        };
    }
    FilterResult::default()
}

#[inline]
fn evaluate_filter_ref_counted_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return FilterResult {
            action: term.action.clone(),
            dscp_rewrite: term.dscp_rewrite,
            policer_name: term.policer_name.clone(),
            routing_instance: term.routing_instance.clone(),
            forwarding_class: term.forwarding_class.clone(),
            log: term.log,
            log_match: filter_log_match(filter, term),
        };
    }
    FilterResult::default()
}

#[inline]
fn evaluate_filter_ref_non_routing_counted(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_non_routing_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_non_routing_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        _ => FilterResult::default(),
    }
}

#[inline]
fn evaluate_filter_ref_non_routing_counted_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if !term.routing_instance.is_empty() {
            return FilterResult::default();
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return FilterResult {
            action: term.action,
            dscp_rewrite: term.dscp_rewrite,
            policer_name: term.policer_name.clone(),
            routing_instance: String::new(),
            forwarding_class: term.forwarding_class.clone(),
            log: term.log,
            log_match: filter_log_match(filter, term),
        };
    }
    FilterResult::default()
}

#[inline]
fn evaluate_filter_ref_non_routing_counted_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if !term.routing_instance.is_empty() {
            return FilterResult::default();
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return FilterResult {
            action: term.action,
            dscp_rewrite: term.dscp_rewrite,
            policer_name: term.policer_name.clone(),
            routing_instance: String::new(),
            forwarding_class: term.forwarding_class.clone(),
            log: term.log,
            log_match: filter_log_match(filter, term),
        };
    }
    FilterResult::default()
}

#[inline]
pub(super) fn filter_log_match(filter: &Filter, term: &FilterTerm) -> Option<FilterLogMatch> {
    term.log.then_some(FilterLogMatch {
        filter_id: filter.id,
        term_id: term.id,
        action: term.action,
    })
}

#[inline]
fn evaluate_filter_ref_routing_instance_counted_v4<'a>(
    filter: &'a Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        let routing_instance =
            (!term.routing_instance.is_empty()).then_some(term.routing_instance.as_str())?;
        return Some(FilterRoutingInstanceResult {
            routing_instance,
            log: term.log,
            action: term.action,
            filter_id: filter.id,
            term_id: term.id,
        });
    }
    None
}

#[inline]
fn evaluate_filter_ref_routing_instance_counted_v6<'a>(
    filter: &'a Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        let routing_instance =
            (!term.routing_instance.is_empty()).then_some(term.routing_instance.as_str())?;
        return Some(FilterRoutingInstanceResult {
            routing_instance,
            log: term.log,
            action: term.action,
            filter_id: filter.id,
            term_id: term.id,
        });
    }
    None
}

/// Evaluate the lo0 (host-bound) filter for a given address family.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn evaluate_lo0_filter(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_lo0_filter_counted(
        state, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_lo0_filter_counted(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let filter = if is_v6 {
        state.lo0_filter_v6_fast.as_deref()
    } else {
        state.lo0_filter_v4_fast.as_deref()
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

pub(crate) fn evaluate_lo0_filter_log_match(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> Option<FilterLogMatch> {
    let filter = if is_v6 {
        state.lo0_filter_v6_fast.as_deref()
    } else {
        state.lo0_filter_v4_fast.as_deref()
    }?;
    evaluate_filter_ref_log_match(
        filter, src_ip, dst_ip, protocol, src_port, dst_port, dscp, false,
    )
}

/// Evaluate the per-interface input filter for a given address family.
pub(crate) fn evaluate_interface_filter(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_interface_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_interface_filter_counted(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

pub(crate) fn evaluate_interface_filter_non_routing_counted(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_non_routing_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

pub(crate) fn evaluate_interface_filter_log_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    skip_routing_instance: bool,
) -> Option<FilterLogMatch> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    }?;
    evaluate_filter_ref_log_match(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        skip_routing_instance,
    )
}

pub(crate) fn evaluate_interface_filter_routing_instance_counted<'a>(
    state: &'a FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> Option<&'a str> {
    evaluate_interface_filter_routing_instance_event_counted(
        state,
        ifindex,
        is_v6,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
    .map(|result| result.routing_instance)
}

pub(crate) fn evaluate_interface_filter_routing_instance_event_counted<'a>(
    state: &'a FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return None;
    };
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_routing_instance_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_routing_instance_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        _ => None,
    }
}

fn evaluate_filter_ref_log_match(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    skip_routing_instance: bool,
) -> Option<FilterLogMatch> {
    if !filter.has_log_terms {
        return None;
    }
    let first_matching_term = filter
        .terms
        .iter()
        .find(|term| term_matches(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp))?;
    if skip_routing_instance && !first_matching_term.routing_instance.is_empty() {
        return None;
    }
    filter_log_match(filter, first_matching_term)
}

/// Evaluate the per-interface output filter for a given address family.
pub(crate) fn evaluate_interface_output_filter(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_interface_output_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_interface_output_filter_counted(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let filter = if is_v6 {
        state
            .iface_filter_out_v6_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    } else {
        state
            .iface_filter_out_v4_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

/// Whether the per-interface input filter for the given family carries terms
/// that override the route lookup with a routing-instance pointer. This is
/// the precheck paired with `evaluate_interface_filter_routing_instance_event_counted`
/// at the only external call site (afxdp/forwarding/mod.rs:929 + :936); it
/// lives next to the routing-instance evaluator rather than in
/// cache_sensitive.rs because it is not a cache-coherency predicate.
pub(crate) fn interface_filter_affects_route_lookup(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state
            .iface_filter_v6_affects_route_lookup
            .contains(&ifindex)
    } else {
        state
            .iface_filter_v4_affects_route_lookup
            .contains(&ifindex)
    }
}
