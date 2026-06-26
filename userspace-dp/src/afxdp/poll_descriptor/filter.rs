// #1697 cold-path extraction: interface-input-filter evaluation +
// filter-log emission, lifted out of poll_descriptor/mod.rs.
//
// Inline policy is per-function (NOT blanket #[inline(never)]) so the
// cheap common-case guards stay folded into the hot/warm caller while
// only the rare/heavy bodies are forced out of line:
//
//   - filter_log_ingress_zone_id / filter_log_egress_zone_id: trivial
//     leaf helpers, #[inline] — called from both inline and cold
//     callers; let rustc place them.
//   - emit_cached_input_filter_log / emit_cached_output_filter_log are
//     called UNCONDITIONALLY from stage_flow_cache_hit (#[inline(always)],
//     the established-flow fast path). They stay #[inline] so the
//     `None` filter-log guard folds into the fast path: in the common
//     no-filter-logging case the hot path is a load + branch with NO
//     call and NO 96-byte UserspaceDpMeta copy. The rare non-None tail
//     of the output emitter is split into a #[cold] #[inline(never)]
//     callee (emit_cached_output_filter_log_tail); the input emitter's
//     non-None tail is already just a call to the cold
//     emit_input_filter_log_match.
//   - evaluate_dscp_sensitive_input_filter_on_session_hit runs per
//     packet on the session-hit path for DSCP-sensitive-filter configs
//     (flow_cache.rs:285 does not cache those). It stays #[inline] so
//     the cheap interface_input_filter_has_dscp_match guard folds in
//     and returns None with no call when no DSCP filter is configured.
//     The post-guard body calls the cold evaluate_non_pbr_input_filter.
//   - evaluate_non_pbr_input_filter / _log_only,
//     emit_input_filter_log_match, apply_lo0_filter_action are the
//     rare/exception bodies: #[cold] #[inline(never)] for .text.unlikely
//     placement away from the hot loop's cache lines.
//
// Bodies are behavior-identical to their previous location in mod.rs.
// The only deltas are: the inline attributes (#[inline] ->
// #[cold] #[inline(never)] on the cold leaves), pub(super) visibility,
// the emit_cached_output_filter_log tail split, and rustfmt
// re-collapsing the now-shorter emit_input_filter_log_match call in
// emit_cached_input_filter_log onto one line (the call previously sat
// in a wider context that forced a multiline layout). No logic,
// side-effect ordering, counter increments, or allocation sites change.

use super::*;
use crate::afxdp::frame::term_match_extra_from_frame;
use crate::filter::TermMatchExtra;

#[inline]
pub(super) fn filter_log_ingress_zone_id(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    ingress_logical_ifindex: i32,
) -> u16 {
    ingress_zone_override
        .filter(|id| forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&ingress_logical_ifindex)
                .copied()
        })
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&(meta.ingress_ifindex as i32))
                .copied()
        })
        .unwrap_or(0)
}

#[inline]
pub(super) fn filter_log_egress_zone_id(forwarding: &ForwardingState, egress_ifindex: i32) -> u16 {
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|egress| egress.zone_id)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NonPbrInputFilterEval {
    pub(super) action: crate::filter::FilterAction,
    pub(super) cached_log: Option<CachedInputFilterLog>,
}

#[cold]
#[inline(never)]
pub(super) fn evaluate_non_pbr_input_filter(
    forwarding: &ForwardingState,
    extra: TermMatchExtra<'_>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    routing_eval_follows: bool,
) -> NonPbrInputFilterEval {
    let Some(flow) = flow else {
        return NonPbrInputFilterEval {
            action: crate::filter::FilterAction::Accept,
            cached_log: None,
        };
    };
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    // #2620: pick the counter-ownership policy. `routing_eval_follows` is true
    // ONLY on the session-MISS path, where the caller proceeds to
    // `ingress_route_table_override` after an Accept verdict from this precheck.
    // When that path is taken AND the filter is route-lookup-affecting, the
    // routing-instance evaluator runs on the Accept/defer exit and counts the
    // same terms — so this precheck must count only on the terminal
    // discard/reject exit the routing evaluator can't reach (the poll path
    // `continue`s on a non-Accept verdict, never calling the routing
    // evaluator). `OnlyTerminalNonAccept` avoids BOTH the #2620 double-count
    // (count in both evaluators on Accept) AND the under-count regression
    // (count in neither on a discard/reject ahead of the routing-instance
    // term). Otherwise — a non-PBR-affecting filter, or the session-HIT re-eval
    // (`routing_eval_follows == false`, which never invokes the routing
    // evaluator) — this evaluator is the SOLE per-packet counter: `Always`
    // (pre-#2620 behavior).
    let count_policy = if routing_eval_follows
        && crate::filter::interface_filter_affects_route_lookup(
            &forwarding.filter_state,
            ingress_ifindex,
            is_v6,
        ) {
        crate::filter::NonRoutingCountPolicy::OnlyTerminalNonAccept
    } else {
        crate::filter::NonRoutingCountPolicy::Always
    };
    let result = crate::filter::evaluate_interface_filter_non_routing_counted(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        meta.pkt_len as u64,
        count_policy,
    );
    let ingress_zone_id =
        filter_log_ingress_zone_id(forwarding, meta, ingress_zone_override, ingress_ifindex);
    NonPbrInputFilterEval {
        action: result.action,
        cached_log: result.log_match.map(|log_match| CachedInputFilterLog {
            log_match,
            ingress_zone_id,
        }),
    }
}

#[cold]
#[inline(never)]
pub(super) fn evaluate_non_pbr_input_filter_log_only(
    forwarding: &ForwardingState,
    extra: TermMatchExtra<'_>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> Option<CachedInputFilterLog> {
    let Some(flow) = flow else {
        return None;
    };
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let log_match = crate::filter::evaluate_interface_filter_log_match(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        true,
    )?;
    Some(CachedInputFilterLog {
        log_match,
        ingress_zone_id: filter_log_ingress_zone_id(
            forwarding,
            meta,
            ingress_zone_override,
            ingress_ifindex,
        ),
    })
}

#[inline]
pub(super) fn evaluate_dscp_sensitive_input_filter_on_session_hit(
    forwarding: &ForwardingState,
    frame: &[u8],
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> Option<NonPbrInputFilterEval> {
    let flow = flow?;
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    // #2362: re-evaluate on a session hit whenever the interface input filter
    // carries EITHER a DSCP match term OR a per-packet L4 match term
    // (tcp-flags / is-fragment / icmp-type / icmp-code). Both classes vary per
    // packet within a flow, so the first-packet decision must not be replayed.
    // The extra-build stays AFTER this gate so the common no-such-filter case
    // pays only two FxHashSet lookups (this function is #[inline] on the hot
    // session-hit path).
    if !crate::filter::interface_input_filter_has_dscp_match(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    ) && !crate::filter::interface_input_filter_has_per_packet_l4_match(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    ) {
        return None;
    }
    let extra = term_match_extra_from_frame(frame, meta);
    // #2620: the session-HIT re-eval is the SOLE counter for this packet — it
    // never calls `ingress_route_table_override`/the routing evaluator. Pass
    // `routing_eval_follows = false` so it counts on every exit (per-packet,
    // pre-#2620 behavior), even when the filter is route-lookup-affecting.
    Some(evaluate_non_pbr_input_filter(
        forwarding,
        extra,
        Some(flow),
        meta,
        ingress_zone_override,
        false,
    ))
}

#[cold]
#[inline(never)]
pub(super) fn emit_input_filter_log_match(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_log: CachedInputFilterLog,
    now_ns: u64,
) {
    emit_filter_log_event(
        event_stream,
        flow,
        meta,
        cached_log.ingress_zone_id,
        0,
        cached_log.log_match.filter_id,
        cached_log.log_match.term_id,
        cached_log.log_match.action,
        FilterLogSource::Input,
        // #2520: resolve the AppID via the hot-path app_catalog.lookup so the
        // filter-log RT_FLOW record carries the application, not UNKNOWN.
        resolve_flow_app_id(&forwarding.app_catalog, flow),
        now_ns,
    );
}

#[inline]
pub(super) fn emit_cached_input_filter_log(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_descriptor: &RewriteDescriptor,
    now_ns: u64,
) {
    let Some(cached_log) = cached_descriptor.input_filter_log else {
        return;
    };
    emit_input_filter_log_match(forwarding, event_stream, flow, meta, cached_log, now_ns);
}

#[inline]
pub(super) fn emit_cached_output_filter_log(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_decision: SessionDecision,
    cached_descriptor: &RewriteDescriptor,
    cached_metadata: &SessionMetadata,
    now_ns: u64,
) {
    let Some(log_match) = cached_descriptor.tx_selection.filter_log else {
        return;
    };
    emit_cached_output_filter_log_tail(
        forwarding,
        event_stream,
        flow,
        meta,
        cached_decision,
        cached_metadata,
        log_match,
        now_ns,
    );
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn emit_cached_output_filter_log_tail(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_decision: SessionDecision,
    cached_metadata: &SessionMetadata,
    log_match: crate::filter::FilterLogMatch,
    now_ns: u64,
) {
    emit_filter_log_event(
        event_stream,
        flow,
        meta,
        cached_metadata.ingress_zone,
        filter_log_egress_zone_id(forwarding, cached_decision.resolution.egress_ifindex),
        log_match.filter_id,
        log_match.term_id,
        log_match.action,
        FilterLogSource::CachedOutput,
        // #2520: AppID via the hot-path app_catalog.lookup.
        resolve_flow_app_id(&forwarding.app_catalog, flow),
        now_ns,
    );
}

/// Evaluate the lo0 (host-bound) firewall filter and emit any matched filter
/// log. Returns the matched terminal `FilterAction` (#2521): the caller maps
/// `Accept` → deliver, `Discard` → silent drop, `Reject` → silent drop PLUS a
/// synthesized active reply (TCP RST / ICMP unreachable). Previously this
/// returned a bare `bool` (drop vs deliver), collapsing `Reject` into a silent
/// `Discard` — the parity gap #2521 closes for control-plane / host-bound
/// filters.
#[cold]
#[inline(never)]
pub(super) fn apply_lo0_filter_action(
    forwarding: &ForwardingState,
    extra: TermMatchExtra<'_>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_ns: u64,
) -> crate::filter::FilterAction {
    let Some(flow) = flow else {
        return crate::filter::FilterAction::Accept;
    };
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let result = crate::filter::evaluate_lo0_filter_counted(
        &forwarding.filter_state,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        meta.pkt_len as u64,
    );
    if let Some(log_match) = result.log_match {
        emit_filter_log_event(
            event_stream,
            flow,
            meta,
            filter_log_ingress_zone_id(
                forwarding,
                meta,
                ingress_zone_override,
                meta.ingress_ifindex as i32,
            ),
            0,
            log_match.filter_id,
            log_match.term_id,
            log_match.action,
            FilterLogSource::Lo0,
            // #2520: AppID via the hot-path app_catalog.lookup.
            resolve_flow_app_id(&forwarding.app_catalog, flow),
            now_ns,
        );
    }
    result.action
}
