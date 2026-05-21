// Per-packet filter evaluation engine extracted from filter.rs (#1049 P2 structural split).
// Pure relocation — bodies are byte-for-byte identical; only the
// enclosing module and visibility paths change.

use super::*;

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
fn evaluate_filter_ref_counted(
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
pub(crate) fn evaluate_filter_ref_tx_selection_counted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
        None,
    )
}

pub(crate) fn evaluate_filter_ref_tx_selection_runtime_counted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
    now_ns: u64,
) -> TxSelectionFilterResult<'a> {
    evaluate_filter_ref_tx_selection_runtime(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
        Some(now_ns),
    )
}

#[inline]
fn evaluate_filter_ref_tx_selection_runtime<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
    now_ns: Option<u64>,
) -> TxSelectionFilterResult<'a> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_tx_selection_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
            now_ns,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_tx_selection_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
            now_ns,
        ),
        _ => TxSelectionFilterResult::default(),
    }
}

pub(crate) fn evaluate_filter_ref_tx_selection_cached(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_tx_selection_cached_v4(
            filter, src, dst, protocol, src_port, dst_port, dscp,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_tx_selection_cached_v6(
            filter, src, dst, protocol, src_port, dst_port, dscp,
        ),
        _ => CachedTxSelectionFilterResult::default(),
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
fn evaluate_filter_ref_tx_selection_counted_v4<'a>(
    filter: &'a Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
    now_ns: Option<u64>,
) -> TxSelectionFilterResult<'a> {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        let policer_action = apply_term_three_color_policer(term, now_ns, packet_bytes);
        return TxSelectionFilterResult {
            action: term.action,
            forwarding_class: (!term.forwarding_class.is_empty())
                .then_some(term.forwarding_class.as_ref()),
            dscp_rewrite: policer_action.dscp_rewrite.or(term.dscp_rewrite),
            policer_drop: policer_action.drop,
            log_match: filter_log_match(filter, term),
        };
    }
    TxSelectionFilterResult::default()
}

#[inline]
fn evaluate_filter_ref_tx_selection_counted_v6<'a>(
    filter: &'a Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
    now_ns: Option<u64>,
) -> TxSelectionFilterResult<'a> {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        let policer_action = apply_term_three_color_policer(term, now_ns, packet_bytes);
        return TxSelectionFilterResult {
            action: term.action,
            forwarding_class: (!term.forwarding_class.is_empty())
                .then_some(term.forwarding_class.as_ref()),
            dscp_rewrite: policer_action.dscp_rewrite.or(term.dscp_rewrite),
            policer_drop: policer_action.drop,
            log_match: filter_log_match(filter, term),
        };
    }
    TxSelectionFilterResult::default()
}

#[inline]
fn apply_term_three_color_policer(
    term: &FilterTerm,
    now_ns: Option<u64>,
    packet_bytes: u64,
) -> ThreeColorPolicerAction {
    let Some(runtime) = term.three_color_policer.as_ref() else {
        return ThreeColorPolicerAction::default();
    };
    let Some(now_ns) = now_ns else {
        return ThreeColorPolicerAction::default();
    };
    let decision = runtime.meter(now_ns, packet_bytes, PacketColor::Green);
    ThreeColorPolicerAction {
        dscp_rewrite: decision.dscp_rewrite,
        drop: decision.drop,
    }
}

pub(crate) fn apply_cached_three_color_policers(
    policers: &CachedThreeColorPolicers,
    now_ns: u64,
    packet_bytes: u64,
) -> ThreeColorPolicerAction {
    let mut action = ThreeColorPolicerAction::default();
    policers.for_each(|policer| {
        let decision = policer.meter(now_ns, packet_bytes, PacketColor::Green);
        action.dscp_rewrite = action.dscp_rewrite.or(decision.dscp_rewrite);
        action.drop |= decision.drop;
    });
    action
}

fn evaluate_filter_ref_tx_selection_cached_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        return CachedTxSelectionFilterResult {
            action: term.action,
            forwarding_class: (!term.forwarding_class.is_empty())
                .then(|| term.forwarding_class.clone()),
            dscp_rewrite: term.dscp_rewrite,
            counter: term.has_count.then(|| term.counter.clone()),
            three_color_policers: CachedThreeColorPolicers::from_option(
                term.three_color_policer.clone(),
            ),
            log_match: filter_log_match(filter, term),
        };
    }
    CachedTxSelectionFilterResult::default()
}

fn evaluate_filter_ref_tx_selection_cached_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        return CachedTxSelectionFilterResult {
            action: term.action,
            forwarding_class: (!term.forwarding_class.is_empty())
                .then(|| term.forwarding_class.clone()),
            dscp_rewrite: term.dscp_rewrite,
            counter: term.has_count.then(|| term.counter.clone()),
            three_color_policers: CachedThreeColorPolicers::from_option(
                term.three_color_policer.clone(),
            ),
            log_match: filter_log_match(filter, term),
        };
    }
    CachedTxSelectionFilterResult::default()
}

#[inline]
fn filter_log_match(filter: &Filter, term: &FilterTerm) -> Option<FilterLogMatch> {
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

pub(crate) fn evaluate_interface_filter_tx_selection_counted<'a>(
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
) -> TxSelectionFilterResult<'a> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return TxSelectionFilterResult::default();
    };
    evaluate_filter_ref_tx_selection_counted(
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

pub(crate) fn evaluate_interface_output_filter_tx_selection_counted<'a>(
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
) -> TxSelectionFilterResult<'a> {
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
        return TxSelectionFilterResult::default();
    };
    evaluate_filter_ref_tx_selection_counted(
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

pub(crate) fn interface_filter_affects_tx_selection(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state
            .iface_filter_v6_affects_tx_selection
            .contains(&ifindex)
    } else {
        state
            .iface_filter_v4_affects_tx_selection
            .contains(&ifindex)
    }
}

pub(crate) fn filter_state_has_input_three_color_policer(state: &FilterState, is_v6: bool) -> bool {
    if is_v6 {
        state.has_input_three_color_policer_v6
    } else {
        state.has_input_three_color_policer_v4
    }
}

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

pub(crate) fn interface_input_filter_has_dscp_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state.iface_filter_v6_has_dscp_match.contains(&ifindex)
    } else {
        state.iface_filter_v4_has_dscp_match.contains(&ifindex)
    }
}

pub(crate) fn interface_output_filter_needs_tx_eval(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state.iface_filter_out_v6_needs_tx_eval.contains(&ifindex)
    } else {
        state.iface_filter_out_v4_needs_tx_eval.contains(&ifindex)
    }
}

pub(crate) fn interface_output_filter_has_dscp_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    let filter = if is_v6 {
        state.iface_filter_out_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_out_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|filter| filter.has_dscp_match_terms)
}

fn three_color_policer_semantics_match(
    old: &Option<Arc<ThreeColorPolicerRuntime>>,
    new: &Option<Arc<ThreeColorPolicerRuntime>>,
) -> bool {
    match (old.as_ref(), new.as_ref()) {
        (None, None) => true,
        (Some(old), Some(new)) => Arc::ptr_eq(old, new) || old.same_runtime_shape_as(new),
        _ => false,
    }
}

fn filter_term_semantics_match(old: &FilterTerm, new: &FilterTerm) -> bool {
    old.name == new.name
        && old.source_v4 == new.source_v4
        && old.source_v6 == new.source_v6
        && old.dest_v4 == new.dest_v4
        && old.dest_v6 == new.dest_v6
        && old.protocol_bitmap == new.protocol_bitmap
        && old.protocol_match_enabled == new.protocol_match_enabled
        && old.source_ports == new.source_ports
        && old.dest_ports == new.dest_ports
        && old.dscp_bitmap == new.dscp_bitmap
        && old.dscp_match_enabled == new.dscp_match_enabled
        && old.action == new.action
        && old.count == new.count
        && old.has_count == new.has_count
        && old.log == new.log
        && old.policer_name == new.policer_name
        && three_color_policer_semantics_match(&old.three_color_policer, &new.three_color_policer)
        && old.routing_instance == new.routing_instance
        && old.forwarding_class == new.forwarding_class
        && old.dscp_rewrite == new.dscp_rewrite
}

fn dscp_sensitive_filter_semantics_match(old: &Filter, new: &Filter) -> bool {
    old.name == new.name
        && old.family == new.family
        && old.affects_tx_selection == new.affects_tx_selection
        && old.affects_route_lookup == new.affects_route_lookup
        && old.has_counter_terms == new.has_counter_terms
        && old.has_log_terms == new.has_log_terms
        && old.has_terminal_action_terms == new.has_terminal_action_terms
        && old.has_dscp_match_terms == new.has_dscp_match_terms
        && old.has_three_color_policer_terms == new.has_three_color_policer_terms
        && old.terms.len() == new.terms.len()
        && old
            .terms
            .iter()
            .zip(new.terms.iter())
            .all(|(old, new)| filter_term_semantics_match(old, new))
}

fn input_dscp_filter_family_changed(
    old_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
    new_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
) -> bool {
    old_filters
        .iter()
        .filter(|(_, filter)| filter.has_dscp_match_terms)
        .any(|(ifindex, old)| {
            new_filters
                .get(ifindex)
                .is_none_or(|new| !dscp_sensitive_filter_semantics_match(old, new))
        })
        || new_filters
            .iter()
            .filter(|(_, filter)| filter.has_dscp_match_terms)
            .any(|(ifindex, new)| {
                old_filters
                    .get(ifindex)
                    .is_none_or(|old| !dscp_sensitive_filter_semantics_match(old, new))
            })
}

pub(crate) fn input_dscp_filter_families_changed(
    old: &FilterState,
    new: &FilterState,
) -> (bool, bool) {
    (
        input_dscp_filter_family_changed(&old.iface_filter_v4_fast, &new.iface_filter_v4_fast),
        input_dscp_filter_family_changed(&old.iface_filter_v6_fast, &new.iface_filter_v6_fast),
    )
}

#[inline]
pub(crate) fn filter_state_has_input_tx_selection(state: &FilterState, is_v6: bool) -> bool {
    if is_v6 {
        state.has_input_tx_selection_v6
    } else {
        state.has_input_tx_selection_v4
    }
}

#[inline]
pub(crate) fn filter_state_has_output_tx_selection(state: &FilterState, is_v6: bool) -> bool {
    if is_v6 {
        state.has_output_tx_selection_v6
    } else {
        state.has_output_tx_selection_v4
    }
}

/// Check whether a single filter term matches the given packet fields.
/// All specified criteria must match (AND logic). Empty criteria = match any.
#[inline(always)]
fn term_matches(
    term: &FilterTerm,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> bool {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            term_matches_v4(term, src, dst, protocol, src_port, dst_port, dscp)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            term_matches_v6(term, src, dst, protocol, src_port, dst_port, dscp)
        }
        _ => false,
    }
}

#[inline(always)]
fn term_matches_v4(
    term: &FilterTerm,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> bool {
    if term.protocol_match_enabled
        && (term.protocol_bitmap[(protocol / 64) as usize] & (1u64 << (protocol % 64))) == 0
    {
        return false;
    }
    if !term.source_v4.is_empty() && !term.source_v4.iter().any(|net| net.contains(src_ip)) {
        return false;
    }
    if !term.dest_v4.is_empty() && !term.dest_v4.iter().any(|net| net.contains(dst_ip)) {
        return false;
    }
    if !term.source_ports.matches(src_port) {
        return false;
    }
    if !term.dest_ports.matches(dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    true
}

#[inline(always)]
fn term_matches_v6(
    term: &FilterTerm,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> bool {
    if term.protocol_match_enabled
        && (term.protocol_bitmap[(protocol / 64) as usize] & (1u64 << (protocol % 64))) == 0
    {
        return false;
    }
    if !term.source_v6.is_empty() && !term.source_v6.iter().any(|net| net.contains(src_ip)) {
        return false;
    }
    if !term.dest_v6.is_empty() && !term.dest_v6.iter().any(|net| net.contains(dst_ip)) {
        return false;
    }
    if !term.source_ports.matches(src_port) {
        return false;
    }
    if !term.dest_ports.matches(dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    true
}
