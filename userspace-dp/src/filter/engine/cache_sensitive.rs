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
use super::eval::filter_log_match;
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
        if !term_matches_v4(
            term,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            dscp,
            TermMatchExtra::default(),
        ) {
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
        if !term_matches_v6(
            term,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            dscp,
            TermMatchExtra::default(),
        ) {
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
        // #2400: the *_constrained flags change match semantics (fail-closed vs
        // match-any) WITHOUT changing the parsed vecs/matcher in the
        // unscoped<->all-malformed transition (both leave empty vecs /
        // PortMatcher::Any), so they MUST be compared here or a flow-cache
        // rebuild would keep stale match-any decisions.
        && old.source_addr_constrained == new.source_addr_constrained
        && old.dest_addr_constrained == new.dest_addr_constrained
        // #2506: the except inversion flips the address decision without
        // changing the parsed prefix vecs, so it must be compared here too — a
        // snapshot toggling `except` on/off otherwise keeps stale decisions.
        && old.source_except == new.source_except
        && old.dest_except == new.dest_except
        && old.protocol_bitmap == new.protocol_bitmap
        && old.protocol_match_enabled == new.protocol_match_enabled
        && old.source_ports == new.source_ports
        && old.dest_ports == new.dest_ports
        && old.source_port_constrained == new.source_port_constrained
        && old.dest_port_constrained == new.dest_port_constrained
        && old.dscp_bitmap == new.dscp_bitmap
        && old.dscp_match_enabled == new.dscp_match_enabled
        && old.tcp_flags_mask == new.tcp_flags_mask
        && old.is_fragment == new.is_fragment
        && old.icmp_type == new.icmp_type
        && old.icmp_code == new.icmp_code
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
        && old.has_per_packet_l4_match_terms == new.has_per_packet_l4_match_terms
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

// ---------------------------------------------------------------------------
// #2362 per-packet L4 match (tcp-flags / is-fragment / icmp-type / icmp-code).
// These vary per packet within a 5-tuple flow exactly like DSCP, so they get
// the same cache-coherency treatment: a flow-cache decline (flow_cache.rs), a
// per-packet re-evaluation on session hit (poll_descriptor/filter.rs), and a
// config-rotation purge (worker/loop_body) when the per-packet-L4 filter set
// changes. The structural equality test reuses dscp_sensitive_filter_semantics_match
// (which now also compares the per-packet term fields).
// ---------------------------------------------------------------------------

fn input_per_packet_l4_filter_family_changed(
    old_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
    new_filters: &rustc_hash::FxHashMap<i32, Arc<Filter>>,
) -> bool {
    old_filters
        .iter()
        .filter(|(_, filter)| filter.has_per_packet_l4_match_terms)
        .any(|(ifindex, old)| {
            new_filters
                .get(ifindex)
                .is_none_or(|new| !dscp_sensitive_filter_semantics_match(old, new))
        })
        || new_filters
            .iter()
            .filter(|(_, filter)| filter.has_per_packet_l4_match_terms)
            .any(|(ifindex, new)| {
                old_filters
                    .get(ifindex)
                    .is_none_or(|old| !dscp_sensitive_filter_semantics_match(old, new))
            })
}

pub(crate) fn input_per_packet_l4_filter_families_changed(
    old: &FilterState,
    new: &FilterState,
) -> (bool, bool) {
    (
        input_per_packet_l4_filter_family_changed(
            &old.iface_filter_v4_fast,
            &new.iface_filter_v4_fast,
        ),
        input_per_packet_l4_filter_family_changed(
            &old.iface_filter_v6_fast,
            &new.iface_filter_v6_fast,
        ),
    )
}

pub(crate) fn interface_input_filter_has_per_packet_l4_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state
            .iface_filter_v6_has_per_packet_l4_match
            .contains(&ifindex)
    } else {
        state
            .iface_filter_v4_has_per_packet_l4_match
            .contains(&ifindex)
    }
}

pub(crate) fn interface_output_filter_has_per_packet_l4_match(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    let filter = if is_v6 {
        state.iface_filter_out_v6_fast.get(&ifindex)
    } else {
        state.iface_filter_out_v4_fast.get(&ifindex)
    };
    filter.is_some_and(|filter| filter.has_per_packet_l4_match_terms)
}

#[cfg(test)]
mod cache_sensitive_2400_tests {
    use super::super::super::*;

    // Compile a single-term filter from one snapshot and return its sole term.
    fn term_from(snap: FirewallTermSnapshot) -> FilterTerm {
        let state = parse_filter_state(
            &[FirewallFilterSnapshot {
                name: "f".into(),
                family: "inet".into(),
                terms: vec![snap],
            }],
            &[],
            &[],
            "",
            "",
        )
        .expect("filter state compiles");
        state
            .filters
            .get("inet:f")
            .expect("filter compiled")
            .terms
            .first()
            .expect("one term")
            .clone()
    }

    /// #2400 (hostile reviewer MINOR): the unscoped <-> all-malformed ADDRESS
    /// flip changes match semantics (match-any vs fail-closed) WITHOUT changing
    /// any parsed vec/matcher — both leave `source_v4`/`source_v6` empty. The
    /// ONLY difference is `source_addr_constrained`. `filter_term_semantics_match`
    /// MUST report them as NOT equal so a flow-cache rebuild invalidates the
    /// stale match-any verdict. REVERT (dropping the `*_constrained` comparisons
    /// from `filter_term_semantics_match`) makes this assert FAIL.
    #[test]
    fn unscoped_vs_all_malformed_source_address_is_not_cache_equal() {
        let unscoped = term_from(FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            ..Default::default()
        });
        let all_malformed = term_from(FirewallTermSnapshot {
            name: "t".into(),
            source_addresses: vec!["not-an-ip".into()],
            action: "discard".into(),
            ..Default::default()
        });
        // Precondition: the parsed match state is otherwise identical — the only
        // distinguishing bit is the constrained flag.
        assert!(unscoped.source_v4.is_empty() && unscoped.source_v6.is_empty());
        assert!(all_malformed.source_v4.is_empty() && all_malformed.source_v6.is_empty());
        assert!(!unscoped.source_addr_constrained);
        assert!(all_malformed.source_addr_constrained);

        assert!(
            !super::filter_term_semantics_match(&unscoped, &all_malformed),
            "unscoped vs all-malformed address must NOT be cache-equal \
             (the *_constrained flip must invalidate cached verdicts)"
        );
        // A term compared with itself stays equal (no spurious invalidation).
        assert!(super::filter_term_semantics_match(&unscoped, &unscoped));
        assert!(super::filter_term_semantics_match(&all_malformed, &all_malformed));
    }

    /// Same flip for the PORT match set: unscoped (PortMatcher::Any,
    /// unconstrained) vs all-malformed (PortMatcher::Any, constrained) — the
    /// matcher is byte-identical, only `source_port_constrained` differs.
    #[test]
    fn unscoped_vs_all_malformed_source_port_is_not_cache_equal() {
        let unscoped = term_from(FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            ..Default::default()
        });
        let all_malformed = term_from(FirewallTermSnapshot {
            name: "t".into(),
            source_ports: vec!["70000".into()], // out of range -> no parsed range
            action: "discard".into(),
            ..Default::default()
        });
        assert_eq!(unscoped.source_ports, PortMatcher::Any);
        assert_eq!(all_malformed.source_ports, PortMatcher::Any);
        assert!(!unscoped.source_port_constrained);
        assert!(all_malformed.source_port_constrained);

        assert!(
            !super::filter_term_semantics_match(&unscoped, &all_malformed),
            "unscoped vs all-malformed port must NOT be cache-equal"
        );
    }
}
