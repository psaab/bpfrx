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

/// #3485: host-inbound zone admission MUST gate the lo0 (host-bound) firewall
/// filter on the local-delivery path. `host-inbound-traffic` is the first-line
/// zone control for router self-traffic; a packet it denies is a SILENT drop
/// (Junos posture) and must NOT incur the lo0 filter's active side-effects: the
/// term counter bump (`record_filter_counter`), the filter-log event, and — in
/// the caller — the synthesized TCP RST / ICMP-unreachable reject reply plus the
/// host-bound session teardown. Before #3485 `apply_lo0_filter_action` ran FIRST
/// (codex-review-118 M1), so a service host-inbound would have silently denied
/// still triggered the lo0 reject / RST / teardown / counter / log.
///
/// This helper runs the host-inbound gate FIRST; only an ADMITTED packet pays
/// the lo0 evaluation. It returns:
///   - `None`         => host-inbound DENIED. The lo0 filter was NOT evaluated
///                       (no counter, no log). The caller drops the packet
///                       silently (no reject reply) and tears down any cached
///                       host-bound session.
///   - `Some(action)` => host-inbound ADMITTED. `action` is the lo0 verdict the
///                       caller handles exactly as before: `Accept` => deliver;
///                       `Discard` => silent drop; `Reject` => drop + reject
///                       reply.
///
/// Both LocalDelivery call sites (session-HIT and session-MISS) route through
/// this single helper, which keeps the gate ordering unit-testable (vs two
/// inline blocks that only the un-callable poll loop could exercise). See
/// `lo0_gate_tests` for the RED-on-revert coverage. `host_inbound_zone` is the
/// admission zone (the session metadata's recorded ingress zone on the HIT path,
/// the resolved `from_zone_id` on the MISS path); `lo0_ingress_zone_override` is
/// the lo0 filter-log ingress-zone hint, preserved per-path unchanged.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn host_inbound_gated_lo0_action(
    forwarding: &ForwardingState,
    logical_ingress_ifindex: i32,
    host_inbound_zone: u16,
    dst_port: u16,
    is_v6: bool,
    icmp_first_l4_byte: u8,
    extra: TermMatchExtra<'_>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    lo0_ingress_zone_override: Option<u16>,
    now_ns: u64,
) -> Option<crate::filter::FilterAction> {
    // Host-inbound gate FIRST — a denied packet is a fail-closed silent drop
    // with NO lo0 side-effects (#3485). #3362: keyed by ingress interface so a
    // per-interface host-inbound override governs the check where one exists,
    // falling back to the from-zone set otherwise. #3609: the override map
    // (`ifindex_host_inbound`) is keyed by the LOGICAL unit ifindex
    // (`forwarding_build/interfaces.rs`), so the caller passes the resolved
    // logical ingress ifindex — NOT the raw physical `meta.ingress_ifindex` —
    // exactly as the sibling input-filter / zone-pair / CoS sites do
    // (`resolve_ingress_logical_ifindex`). Passing the physical bind port would
    // miss a VLAN sub-interface's override and silently fall back to the zone
    // set (the #3609 bug).
    if !crate::afxdp::forwarding::host_inbound_admits_iface(
        forwarding,
        logical_ingress_ifindex,
        host_inbound_zone,
        meta.protocol,
        dst_port,
        is_v6,
        icmp_first_l4_byte,
    ) {
        return None;
    }
    // Only an admitted packet pays the lo0 evaluation (counter + log).
    Some(apply_lo0_filter_action(
        forwarding,
        extra,
        event_stream,
        Some(flow),
        meta,
        lo0_ingress_zone_override,
        now_ns,
    ))
}

/// #3485: regression tests for the host-inbound-before-lo0 ordering on the
/// local-delivery path. They drive `host_inbound_gated_lo0_action` directly —
/// the single helper both the session-HIT and session-MISS call sites route
/// through — so they pin the ordering the un-callable poll loop enforces.
#[cfg(test)]
mod lo0_gate_tests {
    use super::*;
    use crate::filter::FilterAction;
    use crate::ip_proto::PROTO_TCP;
    use crate::session::SessionKey;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    // A configured host-inbound zone with an empty admit set denies TCP/443.
    const DENY_ZONE: u16 = 1;
    // A zone absent from the table => admit-all default (pre-#3070 behaviour).
    const ADMIT_ZONE: u16 = 2;

    /// ForwardingState whose lo0 v4 filter is a single COUNTING REJECT term
    /// matching TCP/443, with `DENY_ZONE` present-but-empty in the host-inbound
    /// table (denies) and `ADMIT_ZONE` absent (admit-all).
    fn forwarding_with_lo0_reject() -> ForwardingState {
        let mut fw = ForwardingState::default();
        fw.filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "protect-re".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "deny-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    count: "lo0-web".into(),
                    action: "reject".into(),
                    ..Default::default()
                }],
            }],
            &[],
            &[],
            "protect-re",
            "",
        )
        .expect("filter state compiles");
        // Present-but-empty => the zone IS configured and admits nothing, so a
        // TCP/443 host-bound packet is denied (Junos posture).
        fw.zone_host_inbound
            .insert(DENY_ZONE, crate::afxdp::types::ZoneHostInbound::default());
        fw
    }

    /// Packets recorded by the single lo0 term's counter. In `#[cfg(test)]`
    /// `record_filter_counter` updates this atomic immediately, so a non-zero
    /// value proves the lo0 filter actually evaluated the packet.
    fn lo0_term_packets(fw: &ForwardingState) -> u64 {
        fw.filter_state
            .lo0_filter_v4_fast
            .as_ref()
            .expect("lo0 v4 filter present")
            .terms[0]
            .counter
            .packets
            .load(Ordering::Relaxed)
    }

    fn tcp_443_flow_and_meta() -> (SessionFlow, UserspaceDpMeta) {
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let meta = UserspaceDpMeta {
            protocol: PROTO_TCP,
            addr_family: libc::AF_INET as u8,
            l3_offset: 14,
            l4_offset: 34,
            tcp_flags: 0x02,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: src,
                dst_ip: dst,
                src_port: 40000,
                dst_port: 443,
            },
        };
        (flow, meta)
    }

    fn extra() -> TermMatchExtra<'static> {
        TermMatchExtra {
            tcp_flags: 0x02,
            l4_present: true,
            ..Default::default()
        }
    }

    /// A host-inbound-DENIED packet must return `None` (caller drops silently,
    /// no reject reply / no session teardown) AND must NOT evaluate the lo0
    /// filter — its counter stays 0. Reverting the reorder (lo0 first) bumps the
    /// counter to 1 on the denied packet, turning this RED.
    #[test]
    fn host_inbound_deny_skips_lo0_side_effects() {
        let fw = forwarding_with_lo0_reject();
        let (flow, meta) = tcp_443_flow_and_meta();

        let action = host_inbound_gated_lo0_action(
            &fw,
            meta.ingress_ifindex as i32,
            DENY_ZONE,
            443,
            false,
            0,
            extra(),
            None,
            &flow,
            meta,
            Some(DENY_ZONE),
            1_000,
        );
        assert_eq!(action, None, "host-inbound deny must short-circuit with None");
        assert_eq!(
            lo0_term_packets(&fw),
            0,
            "lo0 filter must NOT run on a host-inbound-denied packet (#3485)",
        );
    }

    /// A host-inbound-ADMITTED packet preserves the prior behaviour exactly:
    /// the lo0 filter evaluates, returns `Reject`, and its counter bumps.
    #[test]
    fn host_inbound_admit_runs_lo0() {
        let fw = forwarding_with_lo0_reject();
        let (flow, meta) = tcp_443_flow_and_meta();

        let action = host_inbound_gated_lo0_action(
            &fw,
            meta.ingress_ifindex as i32,
            ADMIT_ZONE,
            443,
            false,
            0,
            extra(),
            None,
            &flow,
            meta,
            Some(ADMIT_ZONE),
            1_000,
        );
        assert_eq!(
            action,
            Some(FilterAction::Reject),
            "admitted packet runs the lo0 reject term",
        );
        assert_eq!(
            lo0_term_packets(&fw),
            1,
            "lo0 filter must run + count on an admitted packet",
        );
    }

    /// #3609 (M10): a host-bound packet on a VLAN LOGICAL sub-interface must get
    /// its per-interface host-inbound override. The override map
    /// (`ifindex_host_inbound`) is keyed by the LOGICAL unit ifindex
    /// (`forwarding_build::interfaces`), NOT the raw physical bind port carried
    /// in `meta.ingress_ifindex`. `host_inbound_gated_lo0_action` therefore takes
    /// the caller-resolved logical ingress ifindex (as the sibling input-filter /
    /// zone-pair / CoS sites already do) and must honour it.
    ///
    /// Setup: the LOGICAL unit carries a present-but-empty override (deny-all,
    /// the #3362 fail-closed shape); the physical bind port has NO override; the
    /// from-zone is admit-all (absent from `zone_host_inbound`). A TCP/443
    /// host-bound packet arrives on the physical port (`meta.ingress_ifindex =
    /// PHYS`) with the resolved LOGICAL ifindex threaded in. The logical override
    /// governs → DENY (`None`), and the lo0 filter never runs.
    ///
    /// Fail-on-revert: pass the raw physical `meta.ingress_ifindex` instead of
    /// the resolved logical ifindex (the pre-#3609 bug at filter.rs:452-454) and
    /// the lookup misses the override, falls back to the admit-all zone, the lo0
    /// reject term runs, and this returns `Some(Reject)` with the counter bumped
    /// to 1 — RED on BOTH assertions.
    #[test]
    fn host_inbound_override_keyed_by_logical_vlan_ifindex() {
        const PHYS_IFINDEX: u32 = 11;
        const LOGICAL_IFINDEX: i32 = 3011;

        let mut fw = forwarding_with_lo0_reject();
        // The LOGICAL VLAN unit's per-interface override admits nothing
        // (present-but-empty => deny-all). Keyed by the logical unit ifindex,
        // exactly as `forwarding_build::interfaces` populates it.
        fw.ifindex_host_inbound
            .insert(LOGICAL_IFINDEX, crate::afxdp::types::ZoneHostInbound::default());

        let (flow, mut meta) = tcp_443_flow_and_meta();
        // The frame arrives on the PHYSICAL bind port; the physical ifindex has
        // NO override, so a raw-physical lookup would fall back to the zone.
        meta.ingress_ifindex = PHYS_IFINDEX;

        // ADMIT_ZONE is absent from zone_host_inbound (admit-all) — the zone
        // fallback WOULD admit, so only the logical override can deny here.
        let action = host_inbound_gated_lo0_action(
            &fw,
            LOGICAL_IFINDEX,
            ADMIT_ZONE,
            443,
            false,
            0,
            extra(),
            None,
            &flow,
            meta,
            Some(ADMIT_ZONE),
            1_000,
        );
        assert_eq!(
            action, None,
            "VLAN logical-interface host-inbound override (deny-all) must govern \
             and deny TCP/443 — #3609",
        );
        assert_eq!(
            lo0_term_packets(&fw),
            0,
            "lo0 filter must NOT run when the logical override denies (#3609)",
        );
    }
}
