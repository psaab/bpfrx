// Cache-sensitive evaluation + DSCP-sensitive comparison helpers extracted
// from engine.rs by #1546. Bodies byte-identical with the pre-split versions;
// `term_matches*` invocations route through `super::matching::*`.
//
// Module responsibility: the cached/snapshot TX-selection rebuild path
// (used by the flow-cache hit fast path) and the family-level structural
// equality predicates that decide when cached filter decisions must be
// invalidated. Co-located so a future contributor touching DSCP semantics
// must update both the comparison helpers and the rebuild path in the
// same file — directly addresses the original #1546 motivation about
// desynchronized cache predicates.

use super::super::*;
use super::matching::{term_matches_v4, term_matches_v6};

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
            log_match: cached_log_match(filter, term),
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
            log_match: cached_log_match(filter, term),
        };
    }
    CachedTxSelectionFilterResult::default()
}

#[inline]
fn cached_log_match(filter: &Filter, term: &FilterTerm) -> Option<FilterLogMatch> {
    term.log.then_some(FilterLogMatch {
        filter_id: filter.id,
        term_id: term.id,
        action: term.action,
    })
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
