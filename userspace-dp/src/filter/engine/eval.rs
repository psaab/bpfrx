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
    extra: TermMatchExtra,
) -> FilterResult {
    evaluate_filter_counted(
        state, filter_key, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0,
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
    extra: TermMatchExtra,
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
        extra,
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
    extra: TermMatchExtra,
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
            extra,
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
            extra,
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
    extra: TermMatchExtra,
    packet_bytes: u64,
) -> FilterResult {
    // #2544: accumulate modifiers across fall-through terms. A matched
    // fall-through term (continue_term) applies its modifiers and continues; a
    // matched terminating term applies its action+modifiers and returns. If no
    // term terminates, the accumulated modifiers ride the default Accept.
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        merge_matched_modifiers(&mut acc, filter, term);
        if !term.continue_term {
            acc.action = term.action;
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2616: the RT_FLOW log action must report the verdict the packet actually
/// received, not the placeholder Accept a fall-through (`then { log; next term; }`)
/// logging term carries in its `action` field. The accumulated `log_match`
/// tracks the latest matched logging term's identity (filter_id/term_id), but
/// its action is the term's own — which is the Accept placeholder for a
/// fall-through term. Before the result leaves the evaluator, rewrite the
/// log_match action to the final `acc.action` so a `log; next term` ahead of a
/// terminal `discard`/`reject` logs DENY, not permit. For a terminating logging
/// term `term.action == acc.action` already, so this is a no-op there.
#[inline]
fn normalize_log_match_action(acc: &mut FilterResult) {
    if let Some(lm) = acc.log_match.as_mut() {
        lm.action = acc.action;
    }
}

/// #2544: merge a matched term's modifiers into the running result. Used by both
/// the fall-through and terminating cases: count/policer side effects are
/// recorded by the caller; here we carry the term's dscp-rewrite, policer name,
/// routing-instance, forwarding-class, and log signal forward. Latest matched
/// term wins for each scalar modifier (Junos applies modifiers as terms are
/// traversed); `log` is OR'd so any matched term with `then log` lights it. The
/// log_match diagnostic tracks the latest matched logging term. The action is
/// NOT set here — the caller sets it only for a terminating term, and
/// `normalize_log_match_action` (#2616) rewrites the stored log_match action to
/// the final verdict before the result is returned.
#[inline]
fn merge_matched_modifiers(acc: &mut FilterResult, filter: &Filter, term: &FilterTerm) {
    if term.dscp_rewrite.is_some() {
        acc.dscp_rewrite = term.dscp_rewrite;
    }
    if !term.policer_name.is_empty() {
        acc.policer_name = term.policer_name.clone();
    }
    if !term.routing_instance.is_empty() {
        acc.routing_instance = term.routing_instance.clone();
    }
    if !term.forwarding_class.is_empty() {
        acc.forwarding_class = term.forwarding_class.clone();
    }
    if term.log {
        acc.log = true;
    }
    if let Some(lm) = filter_log_match(filter, term) {
        acc.log_match = Some(lm);
    }
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
    extra: TermMatchExtra,
    packet_bytes: u64,
) -> FilterResult {
    // #2544: see evaluate_filter_ref_counted_v4 — accumulate fall-through
    // modifiers; return on the first terminating matched term.
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        merge_matched_modifiers(&mut acc, filter, term);
        if !term.continue_term {
            acc.action = term.action;
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2620: counter ownership policy for the non-routing input-filter evaluator.
///
/// The session-miss path runs this precheck for the verdict AND — only on its
/// Accept/defer exit (`poll_descriptor/mod.rs` does `continue` on a non-Accept
/// verdict, never reaching the routing evaluator) — the routing-instance
/// evaluator (`evaluate_interface_filter_routing_instance_event_counted`, via
/// `ingress_route_table_override`), which counts every matched term itself.
/// So WHO owns the count depends on the per-packet exit, not just on whether
/// the filter has a routing-instance term:
///
/// * `Always` — this precheck is the SOLE counter for the packet. Used when no
///   routing-instance term exists in the filter (the routing evaluator returns
///   early at the `affects_route_lookup` guard and counts nothing) AND on the
///   DSCP/L4-sensitive SESSION-HIT re-eval path (`evaluate_dscp_sensitive_input_filter_on_session_hit`),
///   which never invokes the routing evaluator. Counts every matched `then
///   count` term on every exit — bit-identical to pre-#2620 behavior.
/// * `OnlyTerminalNonAccept` — used on the session-MISS path when the filter IS
///   route-lookup-affecting. The routing evaluator runs and counts on the
///   Accept/defer exit, so this precheck must NOT count there (else the
///   fall-through `then count` ahead of the routing-instance term double-counts,
///   the #2620 bug). But on a terminal `discard`/`reject` exit BEFORE the
///   routing-instance term the poll path `continue`s and the routing evaluator
///   never runs — so this precheck IS the sole counter on that exit and must
///   count every matched `then count` term up to and including the terminal one
///   (else those terms under-count to zero, the regression the coarse boolean
///   gate introduced).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NonRoutingCountPolicy {
    Always,
    OnlyTerminalNonAccept,
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
    extra: TermMatchExtra,
    packet_bytes: u64,
    count_policy: NonRoutingCountPolicy,
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
            extra,
            packet_bytes,
            count_policy,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_non_routing_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            extra,
            packet_bytes,
            count_policy,
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
    extra: TermMatchExtra,
    packet_bytes: u64,
    count_policy: NonRoutingCountPolicy,
) -> FilterResult {
    // #2544: accumulate fall-through modifiers (count/log/fc/dscp). A matched
    // term that points at a routing-instance defers to the routing-instance
    // evaluator (returns default here, unchanged); such a term is never a
    // fall-through (continue_term is false when routing_instance is set).
    //
    // #2620: counting follows `count_policy` (see NonRoutingCountPolicy). Under
    // `Always` every matched `then count` term records inline. Under
    // `OnlyTerminalNonAccept` we do NOT count during the walk — the routing
    // evaluator owns the count on the Accept/defer exit — and instead replay the
    // count over the matched terms ONLY when this evaluator reaches a terminal
    // `discard`/`reject` (the exit on which the poll path `continue`s and the
    // routing evaluator never runs), so those fall-through counters are recorded
    // exactly once and never drop to zero.
    let always_count = count_policy == NonRoutingCountPolicy::Always;
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if !term.routing_instance.is_empty() {
            return FilterResult::default();
        }
        if always_count && term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        merge_matched_modifiers(&mut acc, filter, term);
        // This loop variant never carries a routing-instance through the
        // result (it defers to the routing-instance evaluator); keep that.
        acc.routing_instance = String::new();
        if !term.continue_term {
            acc.action = term.action;
            if !always_count && term.action != FilterAction::Accept {
                count_matched_non_routing_terms_v4(
                    filter,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    dscp,
                    extra,
                    packet_bytes,
                    term,
                );
            }
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2620: replay the matched-term walk under `OnlyTerminalNonAccept` once the
/// caller has resolved that the verdict is a terminal `discard`/`reject`,
/// recording each matched `then count` term up to AND INCLUDING `terminal`
/// exactly once. The routing evaluator never runs on this exit, so this
/// evaluator is the sole counter. Walk order is identical to the main loop so
/// the recorded set matches.
#[inline]
#[allow(clippy::too_many_arguments)]
fn count_matched_non_routing_terms_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra,
    packet_bytes: u64,
    terminal: &FilterTerm,
) {
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        // A routing-instance term would have made the main loop return default
        // before reaching the terminal; it can never precede `terminal` here.
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        if std::ptr::eq(term, terminal) {
            return;
        }
    }
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
    extra: TermMatchExtra,
    packet_bytes: u64,
    count_policy: NonRoutingCountPolicy,
) -> FilterResult {
    // #2544/#2620: see evaluate_filter_ref_non_routing_counted_v4.
    let always_count = count_policy == NonRoutingCountPolicy::Always;
    let mut acc = FilterResult::default();
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if !term.routing_instance.is_empty() {
            return FilterResult::default();
        }
        if always_count && term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        merge_matched_modifiers(&mut acc, filter, term);
        acc.routing_instance = String::new();
        if !term.continue_term {
            acc.action = term.action;
            if !always_count && term.action != FilterAction::Accept {
                count_matched_non_routing_terms_v6(
                    filter,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    dscp,
                    extra,
                    packet_bytes,
                    term,
                );
            }
            normalize_log_match_action(&mut acc);
            return acc;
        }
    }
    normalize_log_match_action(&mut acc);
    acc
}

/// #2620: v6 counterpart of `count_matched_non_routing_terms_v4`.
#[inline]
#[allow(clippy::too_many_arguments)]
fn count_matched_non_routing_terms_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra,
    packet_bytes: u64,
    terminal: &FilterTerm,
) {
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        if std::ptr::eq(term, terminal) {
            return;
        }
    }
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
    extra: TermMatchExtra,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    let mut acc_log: Option<FilterLogMatch> = None;
    for term in &filter.terms {
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        // #2544: a matched fall-through term (no terminating action, no
        // routing-instance) applies its count modifier above and must NOT halt
        // the search for a routing-instance term — keep scanning. A matched
        // TERMINATING term without a routing-instance still halts (returns None
        // via the `?` below): once a packet is accepted/discarded there is no
        // routing-instance override to find.
        // #2619: capture a fall-through `then log` term's log_match before we
        // continue past it — the PBR path previously dropped these. Latest
        // matched logging term wins, mirroring the full evaluator.
        if term.continue_term {
            if let Some(lm) = filter_log_match(filter, term) {
                acc_log = Some(lm);
            }
            continue;
        }
        let routing_instance =
            (!term.routing_instance.is_empty()).then_some(term.routing_instance.as_str())?;
        // The routing-instance term itself may also carry `then log`; latest
        // matched wins so it supersedes any earlier fall-through log.
        if let Some(lm) = filter_log_match(filter, term) {
            acc_log = Some(lm);
        }
        // #2616: the routing-instance term is terminating on the PBR path; stamp
        // its action onto the accumulated log_match so a fall-through log ahead
        // of it reports the verdict the packet actually receives.
        if let Some(lm) = acc_log.as_mut() {
            lm.action = term.action;
        }
        return Some(FilterRoutingInstanceResult {
            routing_instance,
            log: term.log,
            action: term.action,
            filter_id: filter.id,
            term_id: term.id,
            log_match: acc_log,
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
    extra: TermMatchExtra,
    packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> {
    let mut acc_log: Option<FilterLogMatch> = None;
    for term in &filter.terms {
        if !term_matches_v6(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        // #2544: see the v4 variant — a matched fall-through term keeps scanning.
        // #2619: capture its log_match before continuing (latest wins).
        if term.continue_term {
            if let Some(lm) = filter_log_match(filter, term) {
                acc_log = Some(lm);
            }
            continue;
        }
        let routing_instance =
            (!term.routing_instance.is_empty()).then_some(term.routing_instance.as_str())?;
        if let Some(lm) = filter_log_match(filter, term) {
            acc_log = Some(lm);
        }
        // #2616: stamp the routing-instance term's verdict onto the log_match.
        if let Some(lm) = acc_log.as_mut() {
            lm.action = term.action;
        }
        return Some(FilterRoutingInstanceResult {
            routing_instance,
            log: term.log,
            action: term.action,
            filter_id: filter.id,
            term_id: term.id,
            log_match: acc_log,
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
    extra: TermMatchExtra,
) -> FilterResult {
    evaluate_lo0_filter_counted(
        state, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0,
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
    extra: TermMatchExtra,
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
        extra,
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
    extra: TermMatchExtra,
) -> Option<FilterLogMatch> {
    let filter = if is_v6 {
        state.lo0_filter_v6_fast.as_deref()
    } else {
        state.lo0_filter_v4_fast.as_deref()
    }?;
    evaluate_filter_ref_log_match(
        filter, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, false,
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
    extra: TermMatchExtra,
) -> FilterResult {
    evaluate_interface_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0,
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
    extra: TermMatchExtra,
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
        extra,
        packet_bytes,
    )
}

/// Evaluate the per-interface input filter for the session-miss / session-hit
/// decision, deferring any routing-instance (PBR) term to the routing-instance
/// evaluator. `count_policy` selects who owns the per-packet count — see
/// [`NonRoutingCountPolicy`] (#2620). The caller picks:
///
/// * `OnlyTerminalNonAccept` on the session-MISS path when the filter is
///   route-lookup-affecting (the routing evaluator runs on the Accept exit and
///   counts there; this evaluator counts only on the terminal discard/reject
///   exit the routing evaluator can't reach), and
/// * `Always` otherwise — a plain non-PBR filter, or the DSCP/L4 session-HIT
///   re-eval, where this evaluator is the SOLE counter.
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
    extra: TermMatchExtra,
    packet_bytes: u64,
    count_policy: NonRoutingCountPolicy,
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
        extra,
        packet_bytes,
        count_policy,
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
    extra: TermMatchExtra,
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
        extra,
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
    extra: TermMatchExtra,
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
        extra,
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
    extra: TermMatchExtra,
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
            extra,
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
            extra,
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
    extra: TermMatchExtra,
    skip_routing_instance: bool,
) -> Option<FilterLogMatch> {
    if !filter.has_log_terms {
        return None;
    }
    // #2544: a matched fall-through term (`then next term` / modifier-only) with
    // `then log` fires its log even though evaluation continues to later terms.
    // #2618: this log-only helper must share the FULL evaluator's
    // latest-matched-logging-term semantics — it previously returned on the
    // FIRST matched logging fall-through term, so two `log; next term` terms made
    // the cached input-filter log point at a different term than live evaluation.
    // Walk all terms: a matched logging fall-through term records its log_match
    // and keeps scanning (latest wins); a matched fall-through term without `log`
    // is skipped; the first matched TERMINATING term ends the scan, recording its
    // own log_match (when it has `log`) and resolving the final verdict.
    //
    // #2616: the recorded log action must follow the FINAL verdict, not the
    // Accept placeholder a fall-through logging term carries — track the terminal
    // action and stamp it onto the accumulated log_match before returning so a
    // `log; next term` ahead of a terminal discard/reject logs DENY, not permit.
    let mut acc_log: Option<FilterLogMatch> = None;
    let mut final_action = FilterAction::Accept;
    for term in &filter.terms {
        if !term_matches(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.continue_term {
            if let Some(lm) = filter_log_match(filter, term) {
                acc_log = Some(lm);
            }
            continue;
        }
        if skip_routing_instance && !term.routing_instance.is_empty() {
            // The route-lookup-affecting PBR term is handled by the
            // routing-instance evaluator; its log is not emitted on this path.
            // Any earlier fall-through log_match still carries the verdict the
            // packet receives here (default Accept on the non-PBR path).
            break;
        }
        final_action = term.action;
        if let Some(lm) = filter_log_match(filter, term) {
            acc_log = Some(lm);
        }
        break;
    }
    if let Some(lm) = acc_log.as_mut() {
        lm.action = final_action;
    }
    acc_log
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
    extra: TermMatchExtra,
) -> FilterResult {
    evaluate_interface_output_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra, 0,
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
    extra: TermMatchExtra,
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
        extra,
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
