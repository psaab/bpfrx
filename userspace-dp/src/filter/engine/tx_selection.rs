// TX-selection evaluation extracted from engine.rs by #1546.
// Bodies byte-identical with the pre-split versions; `term_matches*`
// invocations go through `super::matching::*` and policer application
// through `super::policer::apply_term_three_color_policer`.
//
// Hot path on the userspace-dp dataplane:
//   evaluate_filter_ref_tx_selection_counted_v{4,6}
//     -> term_matches_v{4,6}                (super::matching, inline(always))
//     -> apply_term_three_color_policer     (super::policer, inline)
//     -> TxSelectionFilterResult::default() | construct return
//
// `policer_action.dscp_rewrite.or(term.dscp_rewrite)` precedence is
// preserved exactly — policer-imposed rewrite wins over the term's
// configured rewrite.

use super::super::*;
use super::eval::filter_log_match;
use super::matching::{term_matches_v4, term_matches_v6};
use super::policer::apply_term_three_color_policer;

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
