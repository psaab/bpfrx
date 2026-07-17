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
    // #2544: accumulate modifiers across fall-through terms; return on the first
    // terminating matched term. See merge_matched_cached_modifiers.
    let mut acc = CachedTxSelectionFilterResult::default();
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
        merge_matched_cached_modifiers(&mut acc, filter, term);
        if !term.continue_term {
            acc.action = term.action;
            return acc;
        }
    }
    acc
}

/// #2544: merge a matched term's modifiers into the cached TX-selection result.
/// Used for both fall-through and terminating matches. Latest matched term wins
/// for forwarding-class, dscp-rewrite, and log; three-color policers AND
/// `then count` term counters accumulate so a counter/policer on every matched
/// term still records on the cached rebuild path. The action is set only by the
/// caller for a terminating term.
///
/// #2573: `counters` accumulates EVERY matched `then count` term (deduped by
/// counter identity), not just the last. With #2544 fall-through a single packet
/// can match multiple `then count` terms; the old single-Arc slot kept only the
/// last, so the earlier fall-through count terms were silently under-counted on
/// the cached replay path while the uncached full-eval path counted each.
#[inline]
fn merge_matched_cached_modifiers(
    acc: &mut CachedTxSelectionFilterResult,
    filter: &Filter,
    term: &FilterTerm,
) {
    if !term.forwarding_class.is_empty() {
        acc.forwarding_class = Some(term.forwarding_class.clone());
    }
    if term.dscp_rewrite.is_some() {
        acc.dscp_rewrite = term.dscp_rewrite;
    }
    if term.has_count {
        acc.counters.push(term.counter.clone());
    }
    acc.three_color_policers
        .extend(CachedThreeColorPolicers::from_option(
            term.three_color_policer.clone(),
        ));
    if let Some(lm) = filter_log_match(filter, term) {
        acc.log_match = Some(lm);
    }
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
    // #2544: see evaluate_filter_ref_tx_selection_cached_v4.
    let mut acc = CachedTxSelectionFilterResult::default();
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
        merge_matched_cached_modifiers(&mut acc, filter, term);
        if !term.continue_term {
            acc.action = term.action;
            return acc;
        }
    }
    acc
}

/// #3777: capture the interface INPUT filter `then count` term handles matched
/// by an established (cacheable) flow's 5-tuple, for replay on every flow-cache
/// HIT. Output/TX `then count` terms are already replayed on the cached path
/// (#2573 via [`evaluate_filter_ref_tx_selection_cached`]); INPUT `then count`
/// terms were not, so an interface input filter with `then count` reported only
/// the seed (first) packet of an N-packet cacheable flow.
///
/// The walk mirrors the `Always`-policy walk of
/// `evaluate_filter_ref_non_routing_counted` (the non-PBR / session-HIT
/// per-packet counter): it captures every matched non-routing `then count` term
/// up to AND INCLUDING the terminal action term, and DEFERS at a matched
/// routing-instance (PBR) term — returning the counters accumulated before it —
/// so the PBR term's counter stays owned by the routing-instance evaluator
/// (which counts it on the session-miss packet). This preserves the #2620
/// `NonRoutingCountPolicy` count-ownership split on the cached path (a naive
/// "capture every matched term" walk would double/under-count a filter that
/// mixes routing-affecting and count terms).
///
/// This only COLLECTS `Arc<FilterTermCounter>` handles; it never calls
/// `record_filter_counter`. The seed packet is counted by the cold path, so the
/// capture must not re-count. Cache-declined DSCP / per-packet-L4 input filters
/// never reach a cached flow, so the matched set is stable for the flow's
/// lifetime and `TermMatchExtra::default()` suffices (matching
/// `evaluate_filter_ref_tx_selection_cached`).
pub(crate) fn evaluate_interface_input_filter_counters_cached(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedFilterCounters {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return CachedFilterCounters::default();
    };
    // Common case: no `then count` term on this input filter — skip the walk.
    if !filter.has_counter_terms {
        return CachedFilterCounters::default();
    }
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            capture_input_filter_counters_v4(filter, src, dst, protocol, src_port, dst_port, dscp)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            capture_input_filter_counters_v6(filter, src, dst, protocol, src_port, dst_port, dscp)
        }
        _ => CachedFilterCounters::default(),
    }
}

#[inline]
fn capture_input_filter_counters_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedFilterCounters {
    let mut counters = CachedFilterCounters::default();
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
        // A matched routing-instance (PBR) term defers to the routing-instance
        // evaluator — mirror evaluate_filter_ref_non_routing_counted's early
        // return so the PBR term's count is not re-attributed to the cached
        // input replay (#2620 ownership).
        if !term.routing_instance.is_empty() {
            return counters;
        }
        if term.has_count {
            counters.push(term.counter.clone());
        }
        if !term.continue_term {
            return counters;
        }
    }
    counters
}

#[inline]
fn capture_input_filter_counters_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedFilterCounters {
    let mut counters = CachedFilterCounters::default();
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
        if !term.routing_instance.is_empty() {
            return counters;
        }
        if term.has_count {
            counters.push(term.counter.clone());
        }
        if !term.continue_term {
            return counters;
        }
    }
    counters
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
    // #5293: derive this change-detector from an EXHAUSTIVE destructure of the
    // FilterTerm with NO `..` rest pattern. Every field is bound either to a
    // name (and compared against `old` below) or explicitly to `_` (a field
    // that is deliberately NOT part of match semantics). Adding a new field to
    // FilterTerm therefore FAILS TO COMPILE here until the author classifies it
    // — making it impossible to silently omit a match-relevant field from the
    // per-worker session-purge change detector, the way the six `flex_*` fields
    // were omitted originally.
    //
    // The bug this closes: the flexible-match-range fields (#3077, #3232) were
    // absent from the comparison, so a filter/PBR rotation that changed ONLY a
    // flex value/mask/offset/length/enable/match-start compared EQUAL here. The
    // worker then skipped its per-packet-L4 session purge, and an established
    // session kept its stale (pre-rotation) routing-instance / forwarding
    // decision until timeout — a cross-VRF policy-coherency failure (stranded
    // reachability / egress / zone-path / NAT), not merely stale telemetry.
    //
    // Fields intentionally EXCLUDED from match semantics (bound to `_`):
    //   id      — synthetic per-term identity, never a match/action criterion.
    //   counter — runtime hit-counter Arc (shared handle), not config state.
    let FilterTerm {
        id: _,
        name,
        source_v4,
        source_v6,
        dest_v4,
        dest_v6,
        // #2400: the *_constrained flags change match semantics (fail-closed vs
        // match-any) WITHOUT changing the parsed vecs/matcher in the
        // unscoped<->all-malformed transition (both leave empty vecs /
        // PortMatcher::Any), so they MUST be compared or a flow-cache rebuild
        // would keep stale match-any decisions.
        source_addr_constrained,
        dest_addr_constrained,
        // #2506: the except inversion flips the address decision without
        // changing the parsed prefix vecs, so it must be compared too — a
        // snapshot toggling `except` on/off otherwise keeps stale decisions.
        source_except,
        dest_except,
        protocol_bitmap,
        protocol_match_enabled,
        source_ports,
        dest_ports,
        source_port_constrained,
        dest_port_constrained,
        // #2622: the port-except inversion flips the port decision without
        // changing the parsed port matcher, so it must be compared too — a
        // snapshot toggling `*-port-except` on/off otherwise keeps stale
        // flow-cache decisions (sibling of source_except/dest_except above).
        source_port_except,
        dest_port_except,
        dscp_bitmap,
        dscp_match_enabled,
        tcp_flags_mask,
        tcp_flags_forbidden,
        is_fragment,
        icmp_type_bitmap,
        icmp_type_match_enabled,
        icmp_code_bitmap,
        icmp_code_match_enabled,
        // #5293: flexible-match-range (#3077, #3232). All six fields change
        // WHICH packets the term matches (byte-offset window, value/mask,
        // enable, and the L3/L4 base), yet none are part of the 5-tuple
        // SessionKey — so a rotation touching any of them must invalidate
        // cached per-session decisions here.
        flex_enabled,
        flex_offset,
        flex_length,
        flex_value,
        flex_mask,
        flex_match_start,
        action,
        // #2544: continue_term flips a matched term between terminate-here and
        // apply-modifiers-and-fall-through WITHOUT changing the parsed match
        // vecs, so toggling `then next term` on/off must rebuild flow-cache
        // decisions — compare it here.
        continue_term,
        count,
        has_count,
        log,
        policer_name,
        three_color_policer,
        routing_instance,
        forwarding_class,
        dscp_rewrite,
        counter: _,
    } = new;

    old.name == *name
        && old.source_v4 == *source_v4
        && old.source_v6 == *source_v6
        && old.dest_v4 == *dest_v4
        && old.dest_v6 == *dest_v6
        && old.source_addr_constrained == *source_addr_constrained
        && old.dest_addr_constrained == *dest_addr_constrained
        && old.source_except == *source_except
        && old.dest_except == *dest_except
        && old.protocol_bitmap == *protocol_bitmap
        && old.protocol_match_enabled == *protocol_match_enabled
        && old.source_ports == *source_ports
        && old.dest_ports == *dest_ports
        && old.source_port_constrained == *source_port_constrained
        && old.dest_port_constrained == *dest_port_constrained
        && old.source_port_except == *source_port_except
        && old.dest_port_except == *dest_port_except
        && old.dscp_bitmap == *dscp_bitmap
        && old.dscp_match_enabled == *dscp_match_enabled
        && old.tcp_flags_mask == *tcp_flags_mask
        && old.tcp_flags_forbidden == *tcp_flags_forbidden
        && old.is_fragment == *is_fragment
        && old.icmp_type_bitmap == *icmp_type_bitmap
        && old.icmp_type_match_enabled == *icmp_type_match_enabled
        && old.icmp_code_bitmap == *icmp_code_bitmap
        && old.icmp_code_match_enabled == *icmp_code_match_enabled
        && old.flex_enabled == *flex_enabled
        && old.flex_offset == *flex_offset
        && old.flex_length == *flex_length
        && old.flex_value == *flex_value
        && old.flex_mask == *flex_mask
        && old.flex_match_start == *flex_match_start
        && old.action == *action
        && old.continue_term == *continue_term
        && old.count == *count
        && old.has_count == *has_count
        && old.log == *log
        && old.policer_name == *policer_name
        && three_color_policer_semantics_match(&old.three_color_policer, three_color_policer)
        && old.routing_instance == *routing_instance
        && old.forwarding_class == *forwarding_class
        && old.dscp_rewrite == *dscp_rewrite
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

    /// #5293: the six flexible-match-range fields (`flex_enabled`,
    /// `flex_offset`, `flex_length`, `flex_value`, `flex_mask`,
    /// `flex_match_start`) change WHICH packets a term matches but are NOT part
    /// of the 5-tuple SessionKey. A filter/PBR rotation that touches ONLY a flex
    /// field must be reported as NOT cache-equal so the per-worker session purge
    /// runs — otherwise an established session strands on its stale (pre-
    /// rotation) routing-instance / forwarding decision until timeout.
    ///
    /// Each case clones one compiled base term and mutates exactly ONE flex
    /// field, so the ONLY distinguishing bit is that field. REVERT (dropping the
    /// `flex_*` comparisons from `filter_term_semantics_match`) makes every
    /// "changed flex field" assertion FAIL — the comparator would wrongly return
    /// `true` (equal) and skip the purge.
    #[test]
    fn flex_field_change_is_not_cache_equal() {
        let base = term_from(FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            ..Default::default()
        });

        // Control: a term compared with an untouched clone stays cache-equal
        // (no spurious invalidation for a no-op rotation).
        let identical = base.clone();
        assert!(
            super::filter_term_semantics_match(&base, &identical),
            "an identical term must be cache-equal (no spurious purge)"
        );

        // Each mutated clone differs from `base` in EXACTLY one flex field.
        let mut flex_enabled = base.clone();
        flex_enabled.flex_enabled = !base.flex_enabled;

        let mut flex_offset = base.clone();
        flex_offset.flex_offset = base.flex_offset.wrapping_add(1);

        let mut flex_length = base.clone();
        flex_length.flex_length = base.flex_length.wrapping_add(1);

        let mut flex_value = base.clone();
        flex_value.flex_value = base.flex_value ^ 0xA5A5_A5A5;

        let mut flex_mask = base.clone();
        flex_mask.flex_mask = base.flex_mask ^ 0xA5A5_A5A5;

        let mut flex_match_start = base.clone();
        // Pick a variant strictly different from the base's (default Layer3).
        flex_match_start.flex_match_start = match base.flex_match_start {
            FlexMatchStart::Layer3 => FlexMatchStart::Layer4,
            _ => FlexMatchStart::Layer3,
        };

        for (label, mutated) in [
            ("flex_enabled", &flex_enabled),
            ("flex_offset", &flex_offset),
            ("flex_length", &flex_length),
            ("flex_value", &flex_value),
            ("flex_mask", &flex_mask),
            ("flex_match_start", &flex_match_start),
        ] {
            assert!(
                !super::filter_term_semantics_match(&base, mutated),
                "a change to `{label}` must NOT be cache-equal (the rotation \
                 purge must run so sessions do not strand on stale decisions)"
            );
        }
    }
}
