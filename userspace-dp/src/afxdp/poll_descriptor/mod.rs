// Hot-path inner loop extracted from afxdp.rs (#1054). The body is
// byte-for-byte identical to its previous location; this PR only
// changes the enclosing module so afxdp.rs drops below the
// modularity-discipline LOC threshold. `use super::*;` brings every
// type, constant, and helper from afxdp.rs into scope, including
// the sibling submodules (parser, rst, sharded_neighbor, etc.)
// that the extracted fn references.
//
// #1327 Step 1 (Phase 1.5 follow-up to #946): converted from flat
// poll_descriptor.rs to a directory module. The flow-cache fast path
// extraction (`flow_cache_hit::stage_flow_cache_hit`) and the
// per-descriptor RX telemetry helper (`rx_telemetry::record_rx_descriptor_telemetry`)
// live as sibling modules. The post-flow-cache slow path (stages 12+)
// stays inline — see docs/pr/1327-poll-descriptor-stages/plan.md for
// the architectural verdict that further extraction is blocked by
// mutable-locals coupling.

mod cookie_reply;
mod filter;
mod flow_cache_hit;
mod nat_exception;
mod reject_reply;
mod rx_telemetry;

use flow_cache_hit::{FlowCacheOutcome, stage_flow_cache_hit};
use rx_telemetry::record_rx_descriptor_telemetry;

use super::poll_stages::{
    FabricIngressOutcome, ScreenCheckOutcome, StageOutcome, SynCookieAckOutcome,
    stage_classify_fabric_ingress, stage_ipsec_passthrough_check, stage_link_layer_classify,
    stage_native_gre_decap, stage_parse_flow_and_learn, stage_screen_check,
    stage_screen_syn_cookie_ack_on_session_miss,
};
use super::*;
use crate::policy::evaluate_policy_result_with_len;

use cookie_reply::{SynCookieReply, enqueue_syn_cookie_reply};
use nat_exception::{record_source_nat_failure, source_nat_decision_for_flow};
use reject_reply::{enqueue_deny_reply, enqueue_filter_reject_reply};

use filter::{
    apply_lo0_filter_action, emit_input_filter_log_match,
    evaluate_dscp_sensitive_input_filter_on_session_hit, evaluate_non_pbr_input_filter,
    evaluate_non_pbr_input_filter_log_only,
};

// Per-batch packet processing lifted from `poll_binding` (#678).
//
// Runs `binding.xsk.rx.receive(available)` + the descriptor while-let +
// `received.release(); drop(received);` as its own compilation unit so
// it surfaces under its own symbol in `perf top`.
//
// #946 Phase 1 (commit ea8fa4e6) extracted seven per-packet
// sub-stages out of the while-let body into named helpers in
// `afxdp/poll_stages.rs`. The helpers are all `#[inline]` so the
// extracted bodies stay in the caller's CGU and the call/return
// overhead is amortized to zero — the refactor is pure
// code-motion at the IR level (modulo what rustc's inliner picks
// up; the explicit hint matches other hot-path extractions in
// this repo).
//
// `area` raw-pointer contract (#1826, applies to every
// `unsafe { &*area }` reborrow in this function): the caller
// (worker/lifecycle.rs `process_binding_rx`) casts `area` from a
// `&MmapArea` borrowed out of `binding.umem`'s `Rc<WorkerUmemInner>`
// allocation. The pointee outlives this call — nothing on the poll
// path drops or replaces `binding.umem`, and the only
// `&mut WorkerUmemInner` escape hatch (`WorkerUmem::umem_mut` via
// `Rc::get_mut`) runs solely at bind time, never while a worker is
// polling — so each shared reborrow is valid and cannot alias a
// mutable reference. The raw pointer only decouples the immutable
// UMEM-area borrow from the `&mut BindingWorker` borrow.
/// #1769/#1912: per-key rate-limited enqueue of the shared neighbor
/// resolver. Both the neg-cache fast-fail branch and the #1912 tunnel
/// outer-hop branch use the identical throttle-check / `ifindex_to_name`
/// clone / `enqueue` / cap-clear / `insert` sequence keyed by
/// `(ifindex, next_hop)` — factored here so the throttle window, the cap
/// constant, and the clear-vs-evict policy live in ONE place (Copilot
/// #1912 r1 Medium). Returns true iff it actually enqueued (i.e. was not
/// throttled and the iface had a name). Cold-path only.
#[inline]
fn try_enqueue_resolver(
    resolver: &NeighborResolver,
    throttle: &mut FastMap<(i32, IpAddr), u64>,
    ifindex_to_name: &FastMap<i32, String>,
    key: (i32, IpAddr),
    now_ns: u64,
) -> bool {
    // Cheap (i32, IpAddr) map check runs before any clone.
    let throttled = matches!(
        throttle.get(&key),
        Some(&t) if now_ns.saturating_sub(t) < RESOLVER_ENQUEUE_THROTTLE_NS
    );
    if throttled {
        return false;
    }
    let Some(name) = ifindex_to_name.get(&key.0) else {
        return false;
    };
    resolver.enqueue(key.0, key.1, name.clone());
    // Bound the throttle map like the negative cache: a /24 scan touches
    // <=254 keys, so clear wholesale past the cap (best-effort — losing
    // throttle for a few keys only risks one extra clone).
    if throttle.len() >= MAX_NEG_NEIGH_CACHE && !throttle.contains_key(&key) {
        throttle.clear();
    }
    throttle.insert(key, now_ns);
    true
}

/// #2134: per-IP session-limit enforcement at the NEW-FLOW decision.
///
/// Junos `limit-session source-ip-based <n>` / `destination-ip-based <n>`
/// caps the concurrent locally-admitted sessions a single source /
/// destination IP may hold. The decision MUST fire exactly once per new
/// flow, before that flow's own session exists — NOT in the per-packet
/// screen stage, which runs on every data packet of every flow and would
/// re-check an established flow's own counted session and self-drop it at
/// the limit boundary (#2134 r2 BLOCKER).
///
/// This is a read-only query on the per-worker `SessionTable` count
/// (maintained at the install/remove sinks + HA promote/demote), so it
/// preserves the #2128 leak-fix (closed by #2159) by construction: an IP
/// that never installs a session never gets a map entry. Returns the
/// screen-drop reason if the new flow must
/// be rejected, or `None` to proceed to install. Cold path (session
/// miss only); the profile lookup short-circuits on the common
/// no-`limit-session` zone.
#[inline]
fn new_flow_session_limit_drop(
    forwarding: &ForwardingState,
    sessions: &SessionTable,
    from_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<&'static str> {
    // `screen_profiles` is keyed by zone NAME. An empty/absent zone or a
    // zone with no `limit-session` configured short-circuits with no cost
    // beyond the map probe.
    let profile = forwarding.screen_profiles.get(from_zone)?;
    if profile.session_limit_src > 0
        && sessions.session_limit_src_count(src_ip) >= profile.session_limit_src
    {
        return Some("session-limit-src");
    }
    if profile.session_limit_dst > 0
        && sessions.session_limit_dst_count(dst_ip) >= profile.session_limit_dst
    {
        return Some("session-limit-dst");
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(super) fn poll_binding_process_descriptor(
    binding: &mut BindingWorker,
    binding_index: usize,
    area: *const MmapArea,
    available: u32,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    _worker_id: u32,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) {
    let mut received = binding.xsk.rx.receive(available);
    binding.scratch.scratch_recycle.clear();
    binding.scratch.scratch_forwards.clear();
    binding.scratch.scratch_rst_teardowns.clear();
    while let Some(desc) = received.read() {
        record_rx_descriptor_telemetry(desc, area, telemetry, worker_ctx);
        let mut recycle_now = true;
        // SAFETY: per the `area` contract in this function's header
        // comment — pointee outlives the call, never aliased mutably.
        if let Some(meta) = try_parse_metadata(unsafe { &*area }, desc) {
            telemetry.counters.metadata_packets += 1;
            let disposition = classify_metadata(meta, validation);
            if disposition == PacketDisposition::Valid {
                telemetry.counters.validated_packets += 1;
                telemetry.counters.validated_bytes += desc.len as u64;
                // SAFETY: per the `area` contract in this function's
                // header comment.
                let Some(raw_frame) =
                    unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                else {
                    binding.scratch.scratch_recycle.push(desc.addr);
                    continue;
                };
                // #946 Phase 1 stage 5: ARP / NDP link-layer
                // classification. ARP frames recycle without
                // transiting; NDP NA learns and falls through.
                if let StageOutcome::RecycleAndContinue =
                    stage_link_layer_classify(raw_frame, meta, worker_ctx)
                {
                    binding.scratch.scratch_recycle.push(desc.addr);
                    continue;
                }
                // #946 Phase 1 stage 6: native GRE decap. Caller
                // binds the active slice locally; helper does NOT
                // return the slice (would be self-referential).
                // `owned_packet_frame` MUST be `mut` — deferred
                // stage-12+ code at lines below calls `.take()`.
                let (mut meta, mut owned_packet_frame) =
                    stage_native_gre_decap(raw_frame, meta, worker_ctx.forwarding);
                let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
                // #946 Phase 1 stage 7+8: parse session flow and
                // learn the source-side dynamic neighbor.
                // `learn_from_live_frame` MUST be
                // `owned_packet_frame.is_none()` — preserves the
                // GRE guard at the original line 113 (neighbor
                // learning uses the live UMEM Ethernet frame so
                // the source MAC is the outer host's, not the
                // GRE tunnel egress).
                let flow = stage_parse_flow_and_learn(
                    // SAFETY: per the `area` contract in this
                    // function's header comment.
                    unsafe { &*area },
                    desc,
                    packet_frame,
                    meta,
                    owned_packet_frame.is_none(),
                    &mut binding.last_learned_neighbor,
                    worker_ctx,
                );
                // #946 Phase 1 stage 9: fabric-ingress
                // classification. Mutates meta.meta_flags. MUST
                // run before screen/IPsec/flow-cache because they
                // read meta.meta_flags downstream.
                let FabricIngressOutcome {
                    ingress_zone_override,
                    packet_fabric_ingress,
                } = stage_classify_fabric_ingress(packet_frame, &mut meta, worker_ctx);
                // #946 Phase 1 stage 10: screen / IDS slow-path.
                // Caller still owns the recycle push (matches
                // original code's pattern).
                match stage_screen_check(
                    flow.as_ref(),
                    packet_frame,
                    meta,
                    ingress_zone_override,
                    now_secs,
                    screen,
                    telemetry.counters,
                    worker_ctx,
                ) {
                    StageOutcome::RecycleAndContinue => {
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                    StageOutcome::Continue(ScreenCheckOutcome::Pass) => {}
                    StageOutcome::Continue(ScreenCheckOutcome::SynCookieChallenge(challenge)) => {
                        enqueue_syn_cookie_reply(
                            &mut binding.tx_pipeline,
                            worker_ctx.forwarding,
                            binding.ifindex,
                            packet_frame,
                            meta,
                            flow.as_ref(),
                            SynCookieReply::SynAck(challenge),
                            telemetry.counters,
                        );
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                }
                // #946 Phase 1 stage 11: IPsec passthrough. ESP
                // (proto 50) and IKE (UDP 500/4500) reinject via
                // the slow-path TUN; recycle the UMEM frame.
                if let StageOutcome::RecycleAndContinue = stage_ipsec_passthrough_check(
                    flow.as_ref(),
                    packet_frame,
                    meta,
                    &binding.live,
                    worker_ctx,
                ) {
                    binding.scratch.scratch_recycle.push(desc.addr);
                    continue;
                }
                // ── Flow cache fast path (#1327 Step 1) ────────────────
                // Extracted to poll_descriptor/flow_cache_hit.rs. The
                // helper owns ALL recycle/forward pushes on Consumed;
                // caller MUST `continue` without touching desc.addr.
                // The original L477 `packet_frame` binding's NLL
                // lifetime ends at the previous line (last use was
                // inside stage_ipsec_passthrough_check); it is rebound
                // below the helper call for the slow-path code.
                if FlowCacheEntry::packet_eligible(meta)
                    && let Some(flow) = flow.as_ref()
                {
                    match stage_flow_cache_hit(
                        &mut binding.flow,
                        &mut binding.tx_pipeline,
                        &mut binding.tx_counters,
                        &mut binding.scratch,
                        &mut binding.mirror_sample_counter,
                        &binding.live,
                        binding.slot,
                        binding_index,
                        desc,
                        area,
                        raw_frame,
                        &mut owned_packet_frame,
                        meta,
                        flow,
                        packet_fabric_ingress,
                        validation,
                        sessions,
                        now_ns,
                        now_secs,
                        worker_ctx,
                        telemetry,
                    ) {
                        FlowCacheOutcome::Consumed => continue,
                        FlowCacheOutcome::FallThrough => {}
                    }
                }
                // Re-bind packet_frame for slow-path code below
                // (original L477 binding's NLL lifetime ended before
                // the helper call above).
                let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
                // ── End flow cache fast path ─────────────────────────
                let mut debug = flow
                    .as_ref()
                    .map(|flow| ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow));
                let mut session_ingress_zone: Option<u16> = None;
                let mut flow_cache_owner_rg_id = 0i32;
                let mut apply_nat_on_fabric = false;
                // #1861 §5.4: true when a session install was attempted
                // for this packet's decision and refused (max_sessions).
                // Gates the flow-cache population below — caching a
                // sessionless decision would suppress the per-packet
                // reply repair (and, on the new-flow path, persist a
                // rolled-back SNAT tuple) until cache invalidation.
                let mut flow_cache_install_failed = false;
                // #2218: the matched pre-routing DNAT/static-DNAT rule's
                // per-rule hit counter, hoisted to the outer (post-resolution)
                // scope so BOTH the inner miss-block install sites (LocalMiss,
                // ForwardCandidate) and the later MissingNeighbor seed path
                // can increment it once on a committed translated flow. Set
                // inside the session-miss block below; stays None on a
                // session hit (the established fast path applies no new
                // translation, so it is never counted again).
                let mut pre_routing_dnat_counter: Option<
                    std::sync::Arc<crate::nat::NatRuleCounter>,
                > = None;
                let mut decision = if let Some(flow) = flow.as_ref() {
                    if let Some(resolved) = resolve_flow_session_decision(
                        sessions,
                        binding.bpf_maps.session_map_fd,
                        worker_ctx.shared_sessions,
                        worker_ctx.shared_nat_sessions,
                        worker_ctx.shared_forward_wire_sessions,
                        &worker_ctx.shared_owner_rg_indexes,
                        worker_ctx.peer_worker_commands,
                        worker_ctx.forwarding,
                        worker_ctx.ha_state,
                        worker_ctx.dynamic_neighbors,
                        flow,
                        now_ns,
                        now_secs,
                        meta.protocol,
                        meta.tcp_flags,
                        meta.ingress_ifindex as i32,
                        packet_fabric_ingress,
                        ha_startup_grace_until_secs,
                    ) {
                        telemetry.counters.session_hits += 1;
                        telemetry.dbg.session_hit += 1;
                        flow_cache_install_failed = resolved.install_failed;
                        if resolved.created {
                            telemetry.counters.session_creates += 1;
                            telemetry.dbg.session_create += 1;
                            // Mirror new session to BPF conntrack map for
                            // `show security flow session` zone/interface display.
                            // #2008 M5: resolve the application id from the
                            // 5-tuple so the conntrack entry carries app_id.
                            let app_id = worker_ctx.forwarding.app_catalog.lookup(
                                flow.forward_key.protocol,
                                flow.forward_key.src_port,
                                flow.forward_key.dst_port,
                            );
                            publish_bpf_conntrack_entry(
                                conntrack_v4_fd,
                                conntrack_v6_fd,
                                &flow.forward_key,
                                resolved.decision,
                                &resolved.metadata,
                                &worker_ctx.forwarding.zone_name_to_id,
                                worker_ctx.forwarding.alg_disable_flags,
                                app_id,
                            );
                        }
                        // Log first N session hits from WAN (return path)
                        if cfg!(feature = "debug-log")
                            && meta.ingress_ifindex == 6
                            && telemetry.dbg.wan_return_hits < 5
                        {
                            telemetry.dbg.wan_return_hits += 1;
                            debug_log!(
                                "DBG WAN_RETURN_HIT[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} nat=({:?},{:?}) rev={}",
                                telemetry.dbg.wan_return_hits,
                                flow.src_ip,
                                flow.forward_key.src_port,
                                flow.dst_ip,
                                flow.forward_key.dst_port,
                                meta.protocol,
                                meta.tcp_flags,
                                resolved.decision.nat.rewrite_src,
                                resolved.decision.nat.rewrite_dst,
                                resolved.metadata.is_reverse,
                            );
                        }
                        if let Some(debug) = debug.as_mut() {
                            debug.from_zone = Some(resolved.metadata.ingress_zone);
                            debug.to_zone = Some(resolved.metadata.egress_zone);
                        }
                        session_ingress_zone = Some(resolved.metadata.ingress_zone);
                        flow_cache_owner_rg_id = resolved.metadata.owner_rg_id;
                        apply_nat_on_fabric = true;
                        if let Some(input_filter_eval) =
                            evaluate_dscp_sensitive_input_filter_on_session_hit(
                                worker_ctx.forwarding,
                                packet_frame,
                                Some(flow),
                                meta,
                                Some(resolved.metadata.ingress_zone),
                            )
                        {
                            if let Some(cached_log) = input_filter_eval.cached_log {
                                emit_input_filter_log_match(
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    flow,
                                    meta,
                                    cached_log,
                                    now_ns,
                                );
                            }
                            if input_filter_eval.action != crate::filter::FilterAction::Accept {
                                // #2521: a filter `then reject` synthesizes a
                                // TCP RST / ICMP unreachable back toward the
                                // source (same machinery as policy reject);
                                // `discard` stays a silent drop. The reply is
                                // enqueued before the recycle, while flow /
                                // packet_frame are in scope.
                                if input_filter_eval.action
                                    == crate::filter::FilterAction::Reject
                                {
                                    enqueue_filter_reject_reply(
                                        &mut binding.tx_pipeline,
                                        worker_ctx.forwarding,
                                        binding.ifindex,
                                        packet_frame,
                                        meta,
                                        flow,
                                        telemetry.counters,
                                    );
                                }
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                        }
                        let lo0_action = if resolved.decision.resolution.disposition
                            == ForwardingDisposition::LocalDelivery
                        {
                            apply_lo0_filter_action(
                                worker_ctx.forwarding,
                                crate::afxdp::frame::term_match_extra_from_frame(
                                    packet_frame,
                                    meta,
                                ),
                                worker_ctx.event_stream,
                                Some(flow),
                                meta,
                                Some(resolved.metadata.ingress_zone),
                                now_ns,
                            )
                        } else {
                            crate::filter::FilterAction::Accept
                        };
                        if lo0_action != crate::filter::FilterAction::Accept {
                            // #2521: a lo0 `then reject` synthesizes a TCP RST /
                            // ICMP unreachable toward the source before the
                            // host-bound session is torn down; `discard` stays
                            // a silent drop.
                            if lo0_action == crate::filter::FilterAction::Reject {
                                enqueue_filter_reject_reply(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    flow,
                                    telemetry.counters,
                                );
                            }
                            delete_terminal_filtered_session(
                                sessions,
                                binding.bpf_maps.session_map_fd,
                                conntrack_v4_fd,
                                conntrack_v6_fd,
                                worker_ctx.shared_sessions,
                                worker_ctx.shared_nat_sessions,
                                worker_ctx.shared_forward_wire_sessions,
                                &worker_ctx.shared_owner_rg_indexes,
                                worker_ctx.peer_worker_commands,
                                &resolved.key,
                                resolved.decision,
                                &resolved.metadata,
                                resolved.origin,
                            );
                            telemetry.dbg.local += 1;
                            telemetry.dbg.policy_deny += 1;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // #3070: host-inbound-traffic enforcement on the
                        // session-HIT local-delivery path. Re-checked on every
                        // hit (mirroring the lo0 re-check above) so a
                        // host-inbound config change is enforced on an already
                        // established host-bound session WITHOUT an explicit
                        // purge: if the tightened set no longer admits the
                        // service, the session is torn down here and the packet
                        // dropped. The ingress zone is the session metadata's
                        // recorded ingress_zone.
                        if resolved.decision.resolution.disposition
                            == ForwardingDisposition::LocalDelivery
                            && !host_inbound_admits(
                                worker_ctx.forwarding,
                                resolved.metadata.ingress_zone,
                                meta.protocol,
                                resolved.key.dst_port,
                                matches!(flow.dst_ip, IpAddr::V6(_)),
                            )
                        {
                            delete_terminal_filtered_session(
                                sessions,
                                binding.bpf_maps.session_map_fd,
                                conntrack_v4_fd,
                                conntrack_v6_fd,
                                worker_ctx.shared_sessions,
                                worker_ctx.shared_nat_sessions,
                                worker_ctx.shared_forward_wire_sessions,
                                &worker_ctx.shared_owner_rg_indexes,
                                worker_ctx.peer_worker_commands,
                                &resolved.key,
                                resolved.decision,
                                &resolved.metadata,
                                resolved.origin,
                            );
                            telemetry.dbg.local += 1;
                            telemetry.dbg.policy_deny += 1;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // TTL/hop-limit check on session-hit path: generate
                        // ICMP Time Exceeded for packets that would expire
                        // after decrement. The session-miss path handles this
                        // in build_local_time_exceeded_request(); the session-
                        // hit path previously silently dropped these packets
                        // (the rewrite functions return None for TTL<=1).
                        if matches!(
                            resolved.decision.resolution.disposition,
                            ForwardingDisposition::ForwardCandidate
                        ) {
                            // #1145: reuse line-50 raw_frame bind.
                            let local_icmp_te = build_local_time_exceeded_request(
                                raw_frame,
                                desc,
                                meta,
                                &worker_ctx.ident,
                                flow,
                                worker_ctx.forwarding,
                                worker_ctx.dynamic_neighbors,
                                worker_ctx.ha_state,
                                now_secs,
                                telemetry.counters,
                            );
                            if let Some(request) = local_icmp_te {
                                binding.scratch.scratch_forwards.push(request);
                                // Don't recycle: the TE response references
                                // the original frame via desc.addr on the request.
                                // The continue skips recycle_now handling.
                                continue;
                            }
                        }
                        resolved.decision
                    } else {
                        telemetry.counters.session_misses += 1;
                        telemetry.dbg.session_miss += 1;
                        match stage_screen_syn_cookie_ack_on_session_miss(
                            Some(flow),
                            packet_frame,
                            meta,
                            ingress_zone_override,
                            now_secs,
                            screen,
                            telemetry.counters,
                            worker_ctx,
                        ) {
                            StageOutcome::RecycleAndContinue => {
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            StageOutcome::Continue(SynCookieAckOutcome::Pass) => {}
                            StageOutcome::Continue(SynCookieAckOutcome::Validated) => {
                                enqueue_syn_cookie_reply(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    Some(flow),
                                    SynCookieReply::AckRst,
                                    telemetry.counters,
                                );
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                        }
                        let resolution_target =
                            parse_packet_destination_from_frame(packet_frame, meta)
                                .unwrap_or(flow.dst_ip);
                        // Cluster peer return fast path:
                        // a packet arriving from zone-encoded fabric ingress has already
                        // been policy/NAT-validated by the active owner. Allow the inactive
                        // peer to hand it to the resolved local egress zone instead of
                        // treating it as a brand-new flow. Keep pure TCP SYN excluded so
                        // brand-new connects still require local session ownership.
                        if let Some((fabric_return_decision, fabric_return_metadata)) =
                            cluster_peer_return_fast_path(
                                worker_ctx.forwarding,
                                worker_ctx.dynamic_neighbors,
                                packet_frame,
                                meta,
                                ingress_zone_override,
                                resolution_target,
                            )
                        {
                            let ingress_ident = BindingIdentity {
                                slot: binding.slot,
                                queue_id: binding.queue_id,
                                worker_id: binding.worker_id,
                                interface: binding.interface.clone(),
                                ifindex: binding.ifindex,
                            };
                            if let Some(mut request) = build_live_forward_request_from_frame(
                                worker_ctx.binding_lookup,
                                binding_index,
                                &ingress_ident,
                                desc,
                                packet_frame,
                                meta,
                                &fabric_return_decision,
                                worker_ctx.forwarding,
                                Some(flow),
                                None,
                                false,
                                now_ns,
                                worker_ctx.event_stream,
                                None,
                                None,
                            ) {
                                request.frame = owned_packet_frame
                                    .take()
                                    .map(PendingForwardFrame::Owned)
                                    .unwrap_or(PendingForwardFrame::Live);
                                if sessions.install_with_protocol_with_origin(
                                    flow.forward_key.clone(),
                                    fabric_return_decision,
                                    fabric_return_metadata,
                                    SessionOrigin::ReverseFlow,
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                ) {
                                    // #1789: a failed publish leaves the
                                    // shim without this key (NO_SESSION
                                    // degraded path). Count it; one
                                    // Relaxed fetch_add on the rare error
                                    // branch only.
                                    if publish_live_session_entry(
                                        binding.bpf_maps.session_map_fd,
                                        &flow.forward_key,
                                        NatDecision::default(),
                                        true,
                                    )
                                    .is_err()
                                    {
                                        binding
                                            .live
                                            .session_publish_errors
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                binding.scratch.scratch_forwards.push(request);
                                continue;
                            }
                        }

                        // --- DNAT pre-routing ---
                        // Check DNAT table first (port-based DNAT), then
                        // fall back to static NAT DNAT (IP-only 1:1).
                        // The translated destination affects FIB lookup.
                        // #919: ingress_zone_override is now Option<u16>;
                        // DNAT/static NAT lookups still take zone names,
                        // so resolve ID→name lazily on this miss path.
                        let ingress_zone_name = ingress_zone_override
                            .and_then(|id| {
                                worker_ctx
                                    .forwarding
                                    .zone_id_to_name
                                    .get(&id)
                                    .map(|s| s.as_str())
                            })
                            .or_else(|| {
                                // #921: ifindex → u16 → name (slow path; DNAT/static-NAT
                                // takes &str names).
                                worker_ctx
                                    .forwarding
                                    .ifindex_to_zone_id
                                    .get(&(meta.ingress_ifindex as i32))
                                    .and_then(|id| worker_ctx.forwarding.zone_id_to_name.get(id))
                                    .map(|s| s.as_str())
                            })
                            .unwrap_or("");
                        let dnat_decision = if !worker_ctx.forwarding.dnat_table.is_empty() {
                            worker_ctx.forwarding.dnat_table.lookup_with_counter(
                                meta.protocol,
                                flow.forward_key.src_ip,
                                resolution_target,
                                flow.forward_key.dst_port,
                                ingress_zone_name,
                            )
                        } else {
                            None
                        };
                        let static_dnat_decision = if dnat_decision.is_none() {
                            worker_ctx.forwarding.static_nat.match_dnat_with_counter(
                                resolution_target,
                                flow.forward_key.dst_port,
                                ingress_zone_name,
                            )
                        } else {
                            None
                        };
                        // #2218: DNAT/static-DNAT now yields
                        // (NatDecision, Option<Arc<NatRuleCounter>>). Split
                        // the counter off — the decision flows unchanged into
                        // `decision`/`effective_resolution_target` below; the
                        // counter is recorded into the outer-scoped
                        // `pre_routing_dnat_counter` and incremented only at a
                        // committed session install (here or the later
                        // MissingNeighbor seed path).
                        let pre_routing_dnat = match dnat_decision.or(static_dnat_decision) {
                            Some((decision, counter)) => {
                                pre_routing_dnat_counter = counter;
                                Some(decision)
                            }
                            None => None,
                        };

                        // --- NPTv6 inbound pre-routing ---
                        // If dst matches an external NPTv6 prefix, translate the
                        // destination to the internal prefix. This is stateless
                        // prefix translation (RFC 6296) -- no L4 checksum update.
                        let nptv6_inbound = if pre_routing_dnat.is_none() {
                            if let IpAddr::V6(mut dst_v6) = resolution_target {
                                if worker_ctx.forwarding.nptv6.translate_inbound(&mut dst_v6) {
                                    Some(dst_v6)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        // --- NAT64 pre-routing ---
                        // If dst is IPv6 matching a NAT64 prefix, extract IPv4
                        // dest and allocate an IPv4 SNAT address. Route lookup
                        // must use the IPv4 destination.
                        //
                        // #2291: tri-state lookup. The pre-fix code collapsed
                        // "prefix matched but no source pool" into "no match"
                        // (a bare Option whose None meant both), so a matched-
                        // but-unallocatable destination fell through to IPv6
                        // route lookup on the SYNTHETIC NAT64 address — a
                        // fail-OPEN that could leak it upstream on a default
                        // IPv6 route. Now MatchUnavailable fails CLOSED (drop +
                        // counter); only NoPrefixMatch continues IPv6 routing.
                        let nat64_match = if pre_routing_dnat.is_none() && nptv6_inbound.is_none() {
                            if let IpAddr::V6(dst_v6) = resolution_target {
                                match worker_ctx.forwarding.nat64.classify_ipv6_dest(dst_v6) {
                                    crate::nat64::Nat64Match::NoPrefixMatch => None,
                                    crate::nat64::Nat64Match::MatchReady {
                                        prefix_idx,
                                        dst_v4,
                                        snat_v4,
                                        dst_v6,
                                    } => Some((prefix_idx, dst_v4, snat_v4, dst_v6)),
                                    crate::nat64::Nat64Match::MatchUnavailable => {
                                        // Fail closed: a NAT64 prefix matched
                                        // but the source pool is empty/exhausted.
                                        // Drop rather than route the synthetic
                                        // IPv6 destination as ordinary IPv6.
                                        telemetry.counters.nat64_no_source_pool += 1;
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        let effective_resolution_target =
                            if let Some((_, dst_v4, _, _)) = &nat64_match {
                                IpAddr::V4(*dst_v4)
                            } else if let Some(internal_dst) = nptv6_inbound {
                                IpAddr::V6(internal_dst)
                            } else {
                                match &pre_routing_dnat {
                                    Some(d) => d.rewrite_dst.unwrap_or(resolution_target),
                                    None => resolution_target,
                                }
                            };
                        // #2345: Junos evaluates the inbound security policy
                        // against the POST-translation destination tuple. For
                        // the SAME-FAMILY destination translations that happen
                        // BEFORE the route/zone lookup — DNAT, static-DNAT, and
                        // inbound NPTv6 — the policy must match on the translated
                        // (real/internal) destination address + port, in the
                        // zone derived from that translated destination, NOT the
                        // original public/virtual destination. The egress zone
                        // (`to_zone_id`) is already derived from
                        // `effective_resolution_target`, so the zone is correct;
                        // these bindings carry the translated address + port into
                        // the policy-match call so the address/port match also
                        // runs on the post-translation tuple. Only port-based
                        // DNAT carries a destination-port rewrite; static-DNAT
                        // and NPTv6 preserve the L4 port, so the original port
                        // flows through for those.
                        //
                        // NAT64 is DELIBERATELY EXCLUDED here. NAT64 is a
                        // cross-family translation: the translated destination is
                        // IPv4 while the flow source stays IPv6. xpf's policy
                        // matcher (`policy.rs` `evaluate_policy`) requires the
                        // source and destination to be the SAME family — a mixed
                        // (V6 src, V4 dst) tuple matches no rule and falls to
                        // default-deny. Feeding the extracted IPv4 destination
                        // here would therefore break ALL NAT64 connectivity, not
                        // fix it. NAT64 keeps its historical behavior (policy
                        // matched on the synthetic IPv6 destination, the only
                        // same-family tuple available at this site). Making NAT64
                        // policy match the real IPv4 server is a larger,
                        // separate design change (cross-family policy matching);
                        // see `docs/next-features/twice-nat.md` and #2345.
                        let policy_dst_ip = if nat64_match.is_some() {
                            flow.dst_ip
                        } else {
                            effective_resolution_target
                        };
                        let policy_dst_port = pre_routing_dnat
                            .as_ref()
                            .and_then(|d| d.rewrite_dst_port)
                            .unwrap_or(flow.forward_key.dst_port);
                        // #2620: session-MISS path — an Accept verdict here
                        // proceeds to ingress_route_table_override (the routing
                        // evaluator), so pass routing_eval_follows = true. The
                        // precheck then counts only on the terminal
                        // discard/reject exit (the routing evaluator owns the
                        // Accept/defer exit count).
                        let input_filter_eval = evaluate_non_pbr_input_filter(
                            worker_ctx.forwarding,
                            crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta),
                            Some(flow),
                            meta,
                            ingress_zone_override,
                            true,
                        );
                        // #2617: emit the matched input-filter `then log` event
                        // on THIS (session-miss / first) packet, regardless of
                        // the term's terminal action. Previously the emit fired
                        // only inside the `action != Accept` branch below and at
                        // the ForwardCandidate session-install success site
                        // (~L1850); the install emit was removed in this fix in
                        // favour of this single early site. The old layout left
                        // two accept-path gaps:
                        //
                        //   - LocalDelivery (host-bound) accepted flows never
                        //     reached the install emit, so an accepted `then log`
                        //     never fired on the miss packet.
                        //   - A ForwardCandidate flow whose session install was
                        //     refused (max-sessions admission) dropped via
                        //     `continue` BEFORE the install emit, losing the
                        //     audit record entirely for a cache-declined /
                        //     short-lived permitted flow.
                        //
                        // Emitting once here — before the action branch — gives
                        // exactly-once miss-packet semantics across every accept
                        // exit (forward, local-delivery, install-refused) and is
                        // bit-identical to the non-accept path's prior immediate
                        // emit. The log_match comes from the SAME counted
                        // evaluation at ~L838, so emitting it does not re-count
                        // the filter hit. The flow-cache descriptor populated
                        // later (~L2615) stores the log via
                        // evaluate_non_pbr_input_filter_log_only (the
                        // non-counting variant) for cache-hit replay on
                        // SUBSEQUENT packets; the miss packet does not take the
                        // cache-hit path, so the same packet is never
                        // double-logged.
                        if let Some(cached_log) = input_filter_eval.cached_log {
                            emit_input_filter_log_match(
                                worker_ctx.forwarding,
                                worker_ctx.event_stream,
                                flow,
                                meta,
                                cached_log,
                                now_ns,
                            );
                        }
                        if input_filter_eval.action != crate::filter::FilterAction::Accept {
                            // #2521: filter `then reject` synthesizes an active
                            // reply (TCP RST / ICMP unreachable) like policy
                            // reject; `discard` remains a silent drop.
                            if input_filter_eval.action == crate::filter::FilterAction::Reject {
                                enqueue_filter_reject_reply(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    flow,
                                    telemetry.counters,
                                );
                            }
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        let route_table_override = ingress_route_table_override(
                            worker_ctx.forwarding,
                            packet_frame,
                            meta,
                            flow,
                            ingress_zone_override,
                            worker_ctx.event_stream,
                            now_ns,
                        );

                        let resolution = if should_block_tunnel_interface_nat_session_miss(
                            worker_ctx.forwarding,
                            effective_resolution_target,
                            meta.protocol,
                        ) {
                            no_route_resolution(Some(effective_resolution_target))
                        } else {
                            ingress_interface_local_resolution_on_session_miss(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
                                meta.ingress_vlan_id,
                                effective_resolution_target,
                                meta.protocol,
                            )
                            .or_else(|| {
                                interface_nat_local_resolution_on_session_miss(
                                    worker_ctx.forwarding,
                                    effective_resolution_target,
                                    meta.protocol,
                                )
                            })
                            .unwrap_or_else(|| {
                                enforce_ha_resolution_snapshot(
                                    worker_ctx.forwarding,
                                    worker_ctx.ha_state,
                                    now_secs,
                                    lookup_forwarding_resolution_in_table_with_dynamic(
                                        worker_ctx.forwarding,
                                        worker_ctx.dynamic_neighbors,
                                        effective_resolution_target,
                                        route_table_override.as_deref(),
                                    ),
                                )
                            })
                        };
                        let fabric_ingress = packet_fabric_ingress;
                        let resolution = prefer_local_forward_candidate_for_fabric_ingress(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            worker_ctx.dynamic_neighbors,
                            now_secs,
                            fabric_ingress,
                            effective_resolution_target,
                            resolution,
                        );
                        let nptv6_nat = nptv6_inbound.map(|internal_dst| NatDecision {
                            rewrite_src: None,
                            rewrite_dst: Some(IpAddr::V6(internal_dst)),
                            nat64: false,
                            nptv6: true,
                            ..NatDecision::default()
                        });
                        let mut decision = SessionDecision {
                            resolution,
                            nat: nptv6_nat.or(pre_routing_dnat).unwrap_or_default(),
                        };
                        // #919/#922: zero-allocation zone-pair resolution
                        // direct from u16 IDs — no String materialisation
                        // on the per-flow miss path.
                        //
                        // #3021: resolve the LOGICAL ingress ifindex first.
                        // `ifindex_to_zone_id` is keyed by the logical unit
                        // ifindex (forwarding_build/interfaces.rs:76); a VLAN
                        // subinterface's physical bind ifindex maps only to its
                        // parent's FIRST-subinterface zone, so the raw physical
                        // index would evaluate the wrong zone-pair policy on a
                        // parent carrying multiple VLAN units in distinct zones.
                        // Mirrors filter.rs / cos_classify.rs; non-VLAN ports
                        // resolve physical == logical (unchanged).
                        let ingress_logical = resolve_ingress_logical_ifindex(
                            worker_ctx.forwarding,
                            meta.ingress_ifindex as i32,
                            meta.ingress_vlan_id,
                        )
                        .unwrap_or(meta.ingress_ifindex as i32);
                        let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                            worker_ctx.forwarding,
                            ingress_logical,
                            ingress_zone_override,
                            resolution.egress_ifindex,
                        );
                        // Borrow zone names as &str for string-typed downstream
                        // callers (static_nat, match_source_nat_for_flow, debug
                        // log). No clone — the borrow lives only inside this
                        // miss-path block while `worker_ctx.forwarding` is held.
                        let from_zone: &str = worker_ctx
                            .forwarding
                            .zone_id_to_name
                            .get(&from_zone_id)
                            .map(|s| s.as_str())
                            .unwrap_or("");
                        let to_zone: &str = worker_ctx
                            .forwarding
                            .zone_id_to_name
                            .get(&to_zone_id)
                            .map(|s| s.as_str())
                            .unwrap_or("");
                        let is_trust_flow = meta.ingress_ifindex == 5
                            || from_zone == "lan"
                            || matches!(flow.src_ip, IpAddr::V4(ip) if ip.octets()[0] == 10);
                        // #2210 + #2209: port-scan / IP-sweep screen
                        // detection at the new-flow / session-MISS
                        // decision. Running it HERE (not on the per-packet
                        // pre-session stage) is what fixes the #2210
                        // false positives: an established flow's packets
                        // are session HITS and never reach this point, so
                        // mid-stream ACKs/data no longer inflate the sweep
                        // counter. port-scan keeps its TCP-initial-SYN
                        // gate; IP-sweep counts the new flow on any
                        // protocol. State is per-`(from_zone_id, src_ip)`
                        // and bounded (see `screen/scan.rs`). The reason
                        // is `port-scan` / `ip-sweep`; emit + recycle in
                        // the shared block below.
                        // #2227 MINOR-5: parse the screen 5-tuple ONCE on
                        // this cold new-flow path. It feeds both the
                        // scan/sweep check below and the drop-event tuple
                        // if a drop fires. If the L3 header is unparseable
                        // (#2146 Err), fall back to a meta+flow info so the
                        // scan/sweep tuple and any drop event still carry
                        // the offending 5-tuple.
                        let l3_off = if meta.ingress_vlan_present != 0 {
                            18
                        } else {
                            14
                        };
                        let screen_pkt = extract_screen_info(
                            packet_frame,
                            meta.addr_family,
                            meta.protocol,
                            meta.tcp_flags,
                            meta.pkt_len,
                            flow.src_ip,
                            flow.dst_ip,
                            flow.forward_key.src_port,
                            flow.forward_key.dst_port,
                            l3_off,
                        )
                        .unwrap_or_else(|_| screen_parse_error_info(&meta, flow));
                        let new_flow_screen_reason = screen
                            .scan_sweep_drop_on_new_flow(
                                from_zone,
                                from_zone_id,
                                &screen_pkt,
                                now_secs,
                            )
                            // #2134: per-IP session-limit enforcement at the
                            // new-flow decision. This dominates BOTH counted
                            // install sites below (LocalMiss host-inbound and
                            // ForwardFlow transit), fires exactly once per new
                            // flow before its session exists, and reads the
                            // SessionTable count read-only (so an over-limit /
                            // rejected IP never gets a phantom map entry —
                            // #2128). Keys on the pre-NAT original src/dst
                            // (`flow.src_ip`/`flow.dst_ip`), matching Junos
                            // per-source-IP semantics and the screen stage's
                            // own tuple. Evaluated only if scan/sweep did not
                            // already decide a drop.
                            .or_else(|| {
                                new_flow_session_limit_drop(
                                    worker_ctx.forwarding,
                                    sessions,
                                    from_zone,
                                    flow.src_ip,
                                    flow.dst_ip,
                                )
                            });
                        // #2234: surface a rare (logarithmic) operator alarm
                        // when the scan/sweep source table is saturated and
                        // the detector is displacing stale sources to stay
                        // able to track a fresh real scanner. This is NOT a
                        // drop — the packet still forwards — so it uses the
                        // ALARM emitter (RT_FLOW action PERMIT), which rides
                        // the screen event frame with a dedicated
                        // `scan-table-pressure` reason WITHOUT inflating the
                        // drop/deny counters. It fires at most a handful of
                        // times under a sustained flood (never per-flow), and
                        // is checked here on the cold session-miss path only
                        // (the same path that performs the eviction), so the
                        // hot established-flow path pays nothing.
                        if screen.take_scan_table_pressure_event() {
                            emit_screen_alarm_event(
                                worker_ctx.event_stream,
                                &screen_pkt,
                                meta,
                                from_zone_id,
                                "scan-table-pressure",
                                event_now_ns_from_secs(now_secs),
                            );
                        }
                        if let Some(reason) = new_flow_screen_reason {
                            // The screen verdict is already decided; reuse
                            // the single parse above for the drop event's
                            // 5-tuple.
                            emit_screen_drop_event(
                                worker_ctx.event_stream,
                                &screen_pkt,
                                meta,
                                from_zone_id,
                                reason,
                                event_now_ns_from_secs(now_secs),
                            );
                            telemetry.counters.touched = true;
                            telemetry.counters.screen_drops += 1;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        decision.resolution = finalize_new_flow_ha_resolution(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            now_secs,
                            decision.resolution,
                            packet_fabric_ingress,
                            meta.ingress_ifindex as i32,
                            from_zone_id,
                            ha_startup_grace_until_secs,
                        );
                        // Debug: log session miss with flow details (throttled)
                        if cfg!(feature = "debug-log") {
                            if telemetry.dbg.session_miss <= 10 || is_trust_flow {
                                eprintln!(
                                    "DBG SESS_MISS[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} ingress_if={} disp={:?} egress_if={} neigh={:?} zone={}->{}",
                                    telemetry.dbg.session_miss,
                                    flow.src_ip,
                                    flow.forward_key.src_port,
                                    flow.dst_ip,
                                    flow.forward_key.dst_port,
                                    meta.protocol,
                                    meta.tcp_flags,
                                    meta.ingress_ifindex,
                                    resolution.disposition,
                                    resolution.egress_ifindex,
                                    resolution.neighbor_mac.map(|m| format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        m[0], m[1], m[2], m[3], m[4], m[5]
                                    )),
                                    from_zone,
                                    to_zone,
                                );
                                // If from WAN (if6), dump what session key was tried
                                if meta.ingress_ifindex == 6 {
                                    eprintln!(
                                        "DBG SESS_MISS_KEY: af={} proto={} key={}:{}->{}:{} bpf_entries={} local_sessions={}",
                                        flow.forward_key.addr_family,
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_ip,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_ip,
                                        flow.forward_key.dst_port,
                                        count_bpf_session_entries(binding.bpf_maps.session_map_fd),
                                        sessions.len(),
                                    );
                                    // Dump all local sessions to compare
                                    if telemetry.dbg.session_miss <= 3 {
                                        let mut sess_dump = String::new();
                                        let mut count = 0;
                                        sessions.iter_with_origin(|key, decision, metadata, origin| {
                                            if count < 30 {
                                                use std::fmt::Write;
                                                let _ = write!(sess_dump,
                                                    "\n  LOCAL_SESS: af={} proto={} {}:{}->{}:{} nat=({:?},{:?}) rev={} synced={} origin={}",
                                                    key.addr_family, key.protocol,
                                                    key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                                                    decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                                    metadata.is_reverse, origin.is_peer_synced(), origin.as_str(),
                                                );
                                                count += 1;
                                            }
                                        });
                                        if !sess_dump.is_empty() {
                                            eprintln!("DBG SESS_MISS_DUMP:{sess_dump}");
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(debug) = debug.as_mut() {
                            debug.from_zone = Some(from_zone_id);
                            debug.to_zone = Some(to_zone_id);
                        }
                        // Compute embedded ICMP error flag early so we can skip
                        // the BPF session map publish for ICMP errors. Publishing
                        // them as PASS_TO_KERNEL causes subsequent ICMP errors to
                        // bypass the userspace embedded ICMP NAT reversal.
                        let is_embedded_icmp_error = if worker_ctx.forwarding.allow_embedded_icmp
                            && matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
                        {
                            // #1145: reuse line-50 raw_frame bind.
                            raw_frame
                                .get(meta.l4_offset as usize)
                                .copied()
                                .map(|icmp_type| is_icmp_error(meta.protocol, icmp_type))
                                .unwrap_or(false)
                        } else {
                            false
                        };
                        let lo0_action = if resolution.disposition
                            == ForwardingDisposition::LocalDelivery
                        {
                            apply_lo0_filter_action(
                                worker_ctx.forwarding,
                                crate::afxdp::frame::term_match_extra_from_frame(
                                    packet_frame,
                                    meta,
                                ),
                                worker_ctx.event_stream,
                                Some(flow),
                                meta,
                                ingress_zone_override,
                                now_ns,
                            )
                        } else {
                            crate::filter::FilterAction::Accept
                        };
                        if lo0_action != crate::filter::FilterAction::Accept {
                            // #2521: lo0 `then reject` synthesizes an active
                            // reply (TCP RST / ICMP unreachable); `discard`
                            // stays a silent drop.
                            if lo0_action == crate::filter::FilterAction::Reject {
                                enqueue_filter_reject_reply(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    flow,
                                    telemetry.counters,
                                );
                            }
                            telemetry.dbg.local += 1;
                            telemetry.dbg.policy_deny += 1;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // #3070: host-inbound-traffic enforcement on the
                        // session-MISS local-delivery path. A host-bound packet
                        // (destined to a firewall-local interface IP) whose
                        // system-service / protocol is not in the INGRESS
                        // zone's host-inbound set is denied (silent drop, Junos
                        // posture) and never cached. A zone with no host-inbound
                        // stanza admits everything (admit-all default), so
                        // existing configs are unaffected. Gated on
                        // LocalDelivery so transit traffic never pays for it.
                        if resolution.disposition == ForwardingDisposition::LocalDelivery
                            && !host_inbound_admits(
                                worker_ctx.forwarding,
                                from_zone_id,
                                meta.protocol,
                                flow.forward_key.dst_port,
                                matches!(flow.dst_ip, IpAddr::V6(_)),
                            )
                        {
                            telemetry.dbg.local += 1;
                            telemetry.dbg.policy_deny += 1;
                            telemetry.counters.touched = true;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        if resolution.disposition == ForwardingDisposition::LocalDelivery
                            && !is_embedded_icmp_error
                            && should_cache_local_delivery_session_on_miss(
                                worker_ctx.forwarding,
                                effective_resolution_target,
                                resolution,
                                meta.protocol,
                                meta.tcp_flags,
                            )
                        {
                            let local_metadata = SessionMetadata {
                                ingress_zone: from_zone_id,
                                egress_zone: to_zone_id,
                                owner_rg_id: 0,
                                fabric_ingress: false,
                                is_reverse: false,
                                // Keep firewall-local sessions in the helper only for HA
                                // state. Publish only the exact observed key back into the
                                // BPF session map so subsequent established packets bypass
                                // userspace and return directly to the kernel.
                                nat64_reverse: None,
                                // #2508: firewall-local (host-destined) sessions are
                                // not policy-forwarded, so they carry no per-policy
                                // `then log` selection.
                                log_session_init: false,
                                log_session_close: false,
                                // #3056: host-local sessions are not policy-forwarded,
                                // so they carry no admitting policy ID.
                                policy_id: 0,
                            };
                            if install_helper_local_session_on_miss(
                                sessions,
                                binding.bpf_maps.session_map_fd,
                                worker_ctx.shared_sessions,
                                worker_ctx.shared_nat_sessions,
                                worker_ctx.shared_forward_wire_sessions,
                                &worker_ctx.shared_owner_rg_indexes,
                                &flow.forward_key,
                                decision,
                                local_metadata.clone(),
                                SessionOrigin::LocalMiss,
                                now_ns,
                                meta.protocol,
                                meta.tcp_flags,
                            ) {
                                telemetry.counters.session_creates += 1;
                                telemetry.dbg.session_create += 1;
                                // #2218: a DNAT/static-DNAT to a firewall-
                                // local service commits its translation
                                // here. No SNAT is applied on the local-
                                // delivery path, so only the pre-routing
                                // DNAT counter is bumped, once.
                                if let Some(c) = pre_routing_dnat_counter.as_ref() {
                                    c.add(desc.len as u64);
                                }
                                // #2008 M5: stamp the resolved application id.
                                let app_id = worker_ctx.forwarding.app_catalog.lookup(
                                    flow.forward_key.protocol,
                                    flow.forward_key.src_port,
                                    flow.forward_key.dst_port,
                                );
                                publish_bpf_conntrack_entry(
                                    conntrack_v4_fd,
                                    conntrack_v6_fd,
                                    &flow.forward_key,
                                    decision,
                                    &local_metadata,
                                    &worker_ctx.forwarding.zone_name_to_id,
                                    worker_ctx.forwarding.alg_disable_flags,
                                    app_id,
                                );
                            }
                        }
                        if is_embedded_icmp_error {
                            #[cfg(feature = "debug-log")]
                            let icmpv6_trace = meta.protocol == PROTO_ICMPV6
                                && ICMPV6_EMBED_LOGGED.fetch_add(1, Ordering::Relaxed) < 32;
                            if let Some(icmp_match) = try_embedded_icmp_nat_match(
                                // SAFETY: per the `area` contract in
                                // this function's header comment.
                                unsafe { &*area },
                                desc,
                                meta,
                                sessions,
                                worker_ctx.forwarding,
                                worker_ctx.dynamic_neighbors,
                                worker_ctx.shared_sessions,
                                worker_ctx.shared_nat_sessions,
                                worker_ctx.shared_forward_wire_sessions,
                                now_ns,
                            ) {
                                #[cfg(feature = "debug-log")]
                                if icmpv6_trace {
                                    debug_log!(
                                        "ICMPV6_EMBED: match orig_src={} orig_port={} nat={:?} resolution={:?} egress_if={} tx_if={} neigh={:?}",
                                        icmp_match.original_src,
                                        icmp_match.original_src_port,
                                        icmp_match.nat,
                                        icmp_match.resolution.disposition,
                                        icmp_match.resolution.egress_ifindex,
                                        icmp_match.resolution.tx_ifindex,
                                        icmp_match.resolution.neighbor_mac,
                                    );
                                }
                                if icmp_match.nat.rewrite_src.is_some() {
                                    let icmp_resolution = finalize_embedded_icmp_resolution(
                                        worker_ctx.forwarding,
                                        worker_ctx.ha_state,
                                        now_secs,
                                        meta.ingress_ifindex as i32,
                                        &icmp_match,
                                    );
                                    // #1145: reuse line-50 raw_frame bind.
                                    let rewritten = match meta.addr_family as i32 {
                                        libc::AF_INET => build_nat_reversed_icmp_error_v4(
                                            raw_frame,
                                            meta,
                                            &icmp_match,
                                        ),
                                        libc::AF_INET6 => build_nat_reversed_icmp_error_v6(
                                            raw_frame,
                                            meta,
                                            &icmp_match,
                                        ),
                                        _ => None,
                                    };
                                    if let Some(rewritten_frame) = rewritten {
                                        let icmp_decision = SessionDecision {
                                            resolution: icmp_resolution,
                                            nat: NatDecision::default(),
                                        };
                                        let target_ifindex =
                                            if icmp_decision.resolution.tx_ifindex > 0 {
                                                icmp_decision.resolution.tx_ifindex
                                            } else {
                                                resolve_tx_binding_ifindex(
                                                    worker_ctx.forwarding,
                                                    icmp_decision.resolution.egress_ifindex,
                                                )
                                            };
                                        let cos = resolve_cos_tx_selection_at(
                                            worker_ctx.forwarding,
                                            icmp_decision.resolution.egress_ifindex,
                                            meta,
                                            Some(&flow.forward_key),
                                            // #2362 fold B: generated ICMP error
                                            // reply — meta-only extra (tcp_flags
                                            // authoritative; no per-packet frame
                                            // re-read for this synthesized frame).
                                            crate::afxdp::frame::term_match_extra_from_meta(
                                                meta.into(),
                                            ),
                                            now_ns,
                                        );
                                        if !cos.drop {
                                            binding.scratch.scratch_forwards.push(
                                                PendingForwardRequest {
                                                    target_ifindex,
                                                    target_binding_index: worker_ctx
                                                        .binding_lookup
                                                        .target_index(
                                                            binding_index,
                                                            worker_ctx.ident.ifindex,
                                                            worker_ctx.ident.queue_id,
                                                            target_ifindex,
                                                        ),
                                                    ingress_queue_id: worker_ctx.ident.queue_id,
                                                    desc,
                                                    frame: PendingForwardFrame::Prebuilt(
                                                        rewritten_frame,
                                                    ),
                                                    meta: meta.into(),
                                                    decision: icmp_decision,
                                                    apply_nat_on_fabric: false,
                                                    expected_ports: None,
                                                    flow_key: Some(flow.forward_key.clone()),
                                                    nat64_reverse: None,
                                                    cos_queue_id: cos.queue_id,
                                                    dscp_rewrite: cos.dscp_rewrite,
                                                    cos_tx_selection_resolved: true,
                                                    // #2362 fold B: resolved
                                                    // above; deferred recompute
                                                    // not taken.
                                                    filter_match_extra:
                                                        crate::filter::TermMatchExtra::default(),
                                                },
                                            );
                                            recycle_now = false;
                                        }
                                        #[cfg(feature = "debug-log")]
                                        if icmpv6_trace {
                                            debug_log!(
                                                "ICMPV6_EMBED: queued resolution={:?} egress_if={} tx_if={} target_if={}",
                                                icmp_decision.resolution.disposition,
                                                icmp_decision.resolution.egress_ifindex,
                                                icmp_decision.resolution.tx_ifindex,
                                                target_ifindex,
                                            );
                                        }
                                    } else {
                                        #[cfg(feature = "debug-log")]
                                        if icmpv6_trace {
                                            debug_log!(
                                                "ICMPV6_EMBED: build_none resolution={:?} egress_if={} tx_if={} neigh={:?}",
                                                icmp_resolution.disposition,
                                                icmp_resolution.egress_ifindex,
                                                icmp_resolution.tx_ifindex,
                                                icmp_resolution.neighbor_mac,
                                            );
                                        }
                                    }
                                } else {
                                    #[cfg(feature = "debug-log")]
                                    if icmpv6_trace {
                                        debug_log!(
                                            "ICMPV6_EMBED: no_rewrite nat={:?}",
                                            icmp_match.nat
                                        );
                                    }
                                }
                            } else {
                                #[cfg(feature = "debug-log")]
                                if icmpv6_trace {
                                    debug_log!(
                                        "ICMPV6_EMBED: no_match outer={}:{} -> {}:{} ingress_if={} from_zone={} to_zone={}",
                                        flow.src_ip,
                                        flow.forward_key.src_port,
                                        flow.dst_ip,
                                        flow.forward_key.dst_port,
                                        meta.ingress_ifindex,
                                        from_zone,
                                        to_zone,
                                    );
                                }
                            }
                            // Permit without policy check or session install.
                            // If NAT reversal was applied, the prebuilt frame
                            // is already queued. If not, fall through to slow-path.
                        } else if decision.resolution.disposition
                            == ForwardingDisposition::ForwardCandidate
                        {
                            let owner_rg_id =
                                owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                            flow_cache_owner_rg_id = owner_rg_id;
                            // #850: allow-dns-reply admits sessionless DNS replies
                            // through policy (not around it). Always evaluate policy;
                            // the session-install step below is skipped only when
                            // the knob matches AND no NAT is required (to avoid
                            // orphan NAT state without a session anchor).
                            //
                            // #1620: cold-path latency histogram pre-eval gate.
                            // Per plan v4 §4.4: open a scoped &mut binding.cold_path
                            // borrow that ENDS before evaluate_policy_*, so no
                            // mutable cold_path borrow overlaps the policy call.
                            let (cp_sample_tag, cp_t_in) = {
                                let cp = &mut binding.cold_path;
                                cp.sample_phase = cp.sample_phase.wrapping_add(1);
                                let tag = (cp.sample_phase & worker_ctx.cold_path_sample_mask) == 0;
                                let t = if tag {
                                    crate::afxdp::cold_path_hist::sample_tsc_start()
                                } else {
                                    0
                                };
                                (tag, t)
                            };
                            // #2345: match on the POST-translation destination
                            // tuple (translated dst addr + port) in the
                            // translated-dst zone. `policy_dst_ip` /
                            // `policy_dst_port` collapse to the original dst when
                            // no inbound destination translation applies.
                            let policy_result = evaluate_policy_result_with_len(
                                &worker_ctx.forwarding.policy,
                                from_zone_id,
                                to_zone_id,
                                flow.src_ip,
                                policy_dst_ip,
                                flow.forward_key.protocol,
                                flow.forward_key.src_port,
                                policy_dst_port,
                                desc.len as u64,
                            );
                            // #1620: cold-path latency histogram post-eval record.
                            // q32-skip + wrapper_underflow_count per plan v4 §4.4.
                            if cp_sample_tag {
                                let t_out = crate::afxdp::cold_path_hist::sample_tsc_end();
                                let q32 = binding.cold_path.ns_per_tsc_q32;
                                if q32 != 0 {
                                    let delta_tsc = t_out.saturating_sub(cp_t_in);
                                    let raw_ns = ((delta_tsc as u128 * q32 as u128) >> 32) as u64;
                                    let baseline = binding.cold_path.wrapper_ns_baseline;
                                    let delta_ns = if raw_ns < baseline {
                                        binding.cold_path.wrapper_underflow_count = binding
                                            .cold_path
                                            .wrapper_underflow_count
                                            .saturating_add(1);
                                        0
                                    } else {
                                        raw_ns - baseline
                                    };
                                    // #1635: direct slot map lookup;
                                    // skip the sample on a miss
                                    // (capacity exhausted or zone-id
                                    // ≥ 65).
                                    if let Some(slot) = crate::afxdp::cold_path_hist::lookup_slot(
                                        &worker_ctx.forwarding.cold_path_slot_map,
                                        from_zone_id,
                                        to_zone_id,
                                    ) {
                                        binding.cold_path.record_sample(
                                            slot,
                                            from_zone_id,
                                            to_zone_id,
                                            delta_ns,
                                        );
                                    }
                                }
                            }
                            if let PolicyAction::Permit = policy_result.action {
                                // NAT64: cross-family translation takes
                                // priority over same-family SNAT.
                                let mut source_nat_release_key = None;
                                // #2218: the matched SNAT/static-SNAT rule's
                                // per-rule hit counter, captured from the
                                // decision helper; incremented once at the
                                // committed forward install below.
                                let mut source_nat_counter: Option<
                                    std::sync::Arc<crate::nat::NatRuleCounter>,
                                > = None;
                                // #1852: gate pool-mode SNAT allocation
                                // for a non-first fragment (no L4 ports —
                                // allocating leaks a pool port + corrupts
                                // payload). Computed from the ingress
                                // frame at the L3 offset.
                                let snat_non_first_fragment = {
                                    let l3 = meta.l3_offset as usize;
                                    l3 <= packet_frame.len()
                                        && is_non_first_fragment(
                                            &packet_frame[l3..],
                                            meta.addr_family,
                                        )
                                };
                                let nat64_info = if let Some((_, dst_v4, snat_v4, orig_dst_v6)) =
                                    nat64_match
                                {
                                    decision.nat = Nat64State::forward_decision(snat_v4, dst_v4);
                                    Some(Nat64ReverseInfo {
                                        orig_src_v6: match flow.src_ip {
                                            IpAddr::V6(v6) => v6,
                                            _ => std::net::Ipv6Addr::UNSPECIFIED,
                                        },
                                        orig_dst_v6: orig_dst_v6,
                                    })
                                } else {
                                    // Check NPTv6 outbound, then static NAT SNAT, then interface SNAT.
                                    // Use merge() to combine with any pre-routing DNAT
                                    // decision rather than overwriting it.
                                    let nat_match_flow =
                                        flow.with_destination(effective_resolution_target);
                                    if decision.nat.rewrite_dst.is_none() {
                                        // Try NPTv6 outbound: if src matches an internal prefix,
                                        // translate to external prefix (stateless, no L4 csum update).
                                        let nptv6_snat =
                                            if let IpAddr::V6(mut src_v6) = nat_match_flow.src_ip {
                                                if worker_ctx
                                                    .forwarding
                                                    .nptv6
                                                    .translate_outbound(&mut src_v6)
                                                {
                                                    Some(NatDecision {
                                                        rewrite_src: Some(IpAddr::V6(src_v6)),
                                                        rewrite_dst: None,
                                                        nat64: false,
                                                        nptv6: true,
                                                        ..NatDecision::default()
                                                    })
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            };
                                        // #2218: capture the matched SNAT
                                        // rule's counter via the out-param.
                                        // NPTv6 has no per-rule NAT counter,
                                        // so the helper is only called (and
                                        // the out-param only set) on the
                                        // non-NPTv6 arm.
                                        let mut snat_match_counter = None;
                                        match nptv6_snat.map(Ok).unwrap_or_else(|| {
                                            source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                &from_zone,
                                                &to_zone,
                                                decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                                now_ns,
                                                snat_non_first_fragment,
                                                &mut snat_match_counter,
                                            )
                                        }) {
                                            Ok(snat_decision) => {
                                                decision.nat = snat_decision;
                                                source_nat_release_key =
                                                    Some(nat_match_flow.forward_key.clone());
                                                source_nat_counter = snat_match_counter;
                                            }
                                            Err(failure) => {
                                                record_source_nat_failure(
                                                    telemetry,
                                                    worker_ctx,
                                                    meta,
                                                    flow,
                                                    from_zone_id,
                                                    to_zone_id,
                                                    desc.len,
                                                    &failure,
                                                );
                                                binding.scratch.scratch_recycle.push(desc.addr);
                                                continue;
                                            }
                                        }
                                    } else {
                                        let mut snat_match_counter = None;
                                        match source_nat_decision_for_flow(
                                            worker_ctx.forwarding,
                                            &from_zone,
                                            &to_zone,
                                            decision.resolution.egress_ifindex,
                                            &nat_match_flow,
                                            now_ns,
                                            snat_non_first_fragment,
                                            &mut snat_match_counter,
                                        ) {
                                            Ok(snat_decision) => {
                                                decision.nat = decision.nat.merge(snat_decision);
                                                source_nat_release_key =
                                                    Some(nat_match_flow.forward_key.clone());
                                                source_nat_counter = snat_match_counter;
                                            }
                                            Err(failure) => {
                                                record_source_nat_failure(
                                                    telemetry,
                                                    worker_ctx,
                                                    meta,
                                                    flow,
                                                    from_zone_id,
                                                    to_zone_id,
                                                    desc.len,
                                                    &failure,
                                                );
                                                binding.scratch.scratch_recycle.push(desc.addr);
                                                continue;
                                            }
                                        }
                                    }
                                    None
                                };
                                // #1145: reuse line-50 raw_frame bind.
                                let local_icmp_te = build_local_time_exceeded_request(
                                    raw_frame,
                                    desc,
                                    meta,
                                    &worker_ctx.ident,
                                    flow,
                                    worker_ctx.forwarding,
                                    worker_ctx.dynamic_neighbors,
                                    worker_ctx.ha_state,
                                    now_secs,
                                    telemetry.counters,
                                );
                                if let Some(request) = local_icmp_te {
                                    if let Some(release_key) = source_nat_release_key.as_ref() {
                                        rollback_source_nat_allocation(
                                            &worker_ctx.forwarding.source_nat_rules,
                                            release_key,
                                            decision.nat,
                                            false,
                                            now_ns,
                                        );
                                    }
                                    binding.scratch.scratch_forwards.push(request);
                                    recycle_now = false;
                                } else {
                                    let mut created = 0u64;
                                    // #850: DNS-reply fast-path skips session install
                                    // when no NAT is required.  If NAT is required, fall
                                    // through to normal session install so NAT state is
                                    // anchored for GC.
                                    let dns_fastpath_admit =
                                        allow_unsolicited_dns_reply(worker_ctx.forwarding, flow)
                                            && decision.nat.rewrite_src.is_none()
                                            && decision.nat.rewrite_dst.is_none()
                                            && !decision.nat.nat64
                                            && !decision.nat.nptv6;
                                    let track_in_userspace = decision.resolution.disposition
                                        != ForwardingDisposition::LocalDelivery
                                        && !dns_fastpath_admit;
                                    let install_local_reverse =
                                        should_install_local_reverse_session(
                                            decision,
                                            fabric_ingress,
                                        );
                                    // #1861 §5.2: transaction boundary for the
                                    // forward+reverse install pair. The table is
                                    // per-worker single-threaded, so a passing
                                    // preflight makes both installs below
                                    // infallible within this descriptor
                                    // iteration. On refusal: roll back the SNAT
                                    // allocation (same call shape as the old
                                    // failure arm), count, and DROP the trigger
                                    // packet (Junos parity: session-creation
                                    // failure ⇒ packet dropped) — skipping the
                                    // reverse install, the forwarding block,
                                    // and the flow-cache population.
                                    // `needed == 0` is the tracking-not-required
                                    // case (DNS fast-path, LocalDelivery): no
                                    // install is attempted and nothing changes.
                                    let needed_sessions = usize::from(track_in_userspace)
                                        + usize::from(track_in_userspace && install_local_reverse);
                                    if needed_sessions > 0 && !sessions.can_admit(needed_sessions) {
                                        sessions.note_admission_refused();
                                        rollback_source_nat_allocation(
                                            &worker_ctx.forwarding.source_nat_rules,
                                            source_nat_release_key
                                                .as_ref()
                                                .unwrap_or(&flow.forward_key),
                                            decision.nat,
                                            false,
                                            now_ns,
                                        );
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                    let forward_metadata = SessionMetadata {
                                        ingress_zone: from_zone_id,
                                        egress_zone: to_zone_id,
                                        owner_rg_id,
                                        fabric_ingress,
                                        is_reverse: false,
                                        nat64_reverse: nat64_info,
                                        // #2508: stamp the admitting policy's
                                        // per-policy RT_FLOW SYSLOG log selection.
                                        log_session_init: policy_result.log_session_init,
                                        log_session_close: policy_result.log_session_close,
                                        // #3056: stamp the admitting policy's ID so
                                        // the live-session BPF-compat publish and the
                                        // SESSION_CREATE RT_FLOW record reference the
                                        // policy that admitted the flow (was the `0`
                                        // sentinel → first-configured-policy misattribution).
                                        policy_id: policy_result.policy_id,
                                    };
                                    let forward_installed = track_in_userspace
                                        && sessions.install_with_protocol_with_origin(
                                            flow.forward_key.clone(),
                                            decision,
                                            forward_metadata.clone(),
                                            SessionOrigin::ForwardFlow,
                                            now_ns,
                                            meta.protocol,
                                            meta.tcp_flags,
                                        );
                                    if track_in_userspace && !forward_installed {
                                        // #1861 §5.2 residual: impossible by
                                        // construction after a passing
                                        // can_admit (cap is the only install
                                        // failure mode; nothing mutates the
                                        // table mid-iteration). Debug: loud.
                                        // Release (#1855 contract): count,
                                        // roll back, drop — never half-commit.
                                        debug_assert!(
                                            false,
                                            "forward install failed after can_admit preflight"
                                        );
                                        sessions.note_install_partial();
                                        rollback_source_nat_allocation(
                                            &worker_ctx.forwarding.source_nat_rules,
                                            source_nat_release_key
                                                .as_ref()
                                                .unwrap_or(&flow.forward_key),
                                            decision.nat,
                                            false,
                                            now_ns,
                                        );
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                    if forward_installed {
                                        created += 1;
                                        // #2218: count the per-rule NAT
                                        // translation hit ONCE per committed
                                        // translated forward flow. This is
                                        // the cold-path success point — past
                                        // every rollback door (ICMP-TE
                                        // bounce, max_sessions refusal,
                                        // install-partial), so a rolled-back
                                        // SNAT allocation is never counted.
                                        // DNAT/static-DNAT and SNAT/static-
                                        // SNAT counters are independent Arcs;
                                        // a DNAT+SNAT flow bumps both.
                                        let nat_hit_len = desc.len as u64;
                                        if let Some(c) = pre_routing_dnat_counter.as_ref() {
                                            c.add(nat_hit_len);
                                        }
                                        if let Some(c) = source_nat_counter.as_ref() {
                                            c.add(nat_hit_len);
                                        }
                                        let forward_entry = SyncedSessionEntry {
                                            key: flow.forward_key.clone(),
                                            decision,
                                            metadata: forward_metadata,
                                            origin: SessionOrigin::ForwardFlow,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                            // Local forward-flow learn (#2170): no peer gen.
                                            generation: 0,
                                        };
                                        // #1789: count failed publishes so
                                        // map-at-capacity / stale-fd
                                        // failures are visible in release
                                        // builds (was `let _ =`).
                                        if publish_live_session_entry(
                                            binding.bpf_maps.session_map_fd,
                                            &flow.forward_key,
                                            decision.nat,
                                            false,
                                        )
                                        .is_err()
                                        {
                                            binding
                                                .live
                                                .session_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        publish_shared_session(
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            &forward_entry,
                                        );
                                        // Populate BPF dnat_table for embedded ICMP NAT reversal.
                                        // Without this, mtr/traceroute intermediate hops are invisible.
                                        // #2244: a failed map publish silently loses the reverse
                                        // record — count it so map pressure is operator-visible.
                                        if !publish_dnat_table_entry(
                                            &worker_ctx.dnat_fds,
                                            &flow.forward_key,
                                            decision.nat,
                                        ) {
                                            binding
                                                .live
                                                .dnat_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        replicate_session_upsert(
                                            worker_ctx.peer_worker_commands,
                                            &forward_entry,
                                        );
                                        // #2617: the input-filter `then log`
                                        // emit moved to the single early site at
                                        // the accept fall-through (~L876), so it
                                        // now fires once per miss packet across
                                        // every accept exit (forward,
                                        // local-delivery, install-refused). The
                                        // former per-install emit here would
                                        // double-log a successfully installed
                                        // ForwardCandidate flow once the early
                                        // site is in place.
                                    } else {
                                        // #1861: only reachable when
                                        // track_in_userspace == false (a true
                                        // install failure now drops above) —
                                        // no session anchors the NAT state, so
                                        // release any allocation. No-op for the
                                        // DNS fast-path (its guard requires no
                                        // NAT).
                                        rollback_source_nat_allocation(
                                            &worker_ctx.forwarding.source_nat_rules,
                                            source_nat_release_key
                                                .as_ref()
                                                .unwrap_or(&flow.forward_key),
                                            decision.nat,
                                            false,
                                            now_ns,
                                        );
                                    }
                                    let reverse_resolution = reverse_resolution_for_session(
                                        worker_ctx.forwarding,
                                        worker_ctx.ha_state,
                                        worker_ctx.dynamic_neighbors,
                                        flow.src_ip,
                                        from_zone_id,
                                        fabric_ingress,
                                        now_secs,
                                        false,
                                    );
                                    // Install the reverse entry even if the initial reply-side
                                    // resolution is not immediately usable. On live traffic the
                                    // first server reply can arrive before the reverse neighbor
                                    // state has converged on every worker, and dropping the reverse
                                    // entry creation turns that race into a hard policy miss. The
                                    // hit path re-resolves on demand and can fall back to the
                                    // cached decision when neighbor convergence is still in flight.
                                    let reverse_decision = SessionDecision {
                                        resolution: reverse_resolution,
                                        nat: decision.nat.reverse(
                                            flow.src_ip,
                                            flow.dst_ip,
                                            flow.forward_key.src_port,
                                            flow.forward_key.dst_port,
                                        ),
                                    };
                                    // For NAT64: the reverse key is IPv4 (different AF
                                    // from the forward IPv6 key). The reply arrives as
                                    // IPv4: src=dst_v4, dst=snat_v4.
                                    let (reverse_key, reverse_protocol) = if nat64_info.is_some() {
                                        let nat = decision.nat;
                                        let dst_v4 = match nat.rewrite_dst {
                                            Some(IpAddr::V4(v4)) => v4,
                                            _ => Ipv4Addr::UNSPECIFIED,
                                        };
                                        let snat_v4 = match nat.rewrite_src {
                                            Some(IpAddr::V4(v4)) => v4,
                                            _ => Ipv4Addr::UNSPECIFIED,
                                        };
                                        // Map protocol: ICMPv6→ICMP for the reverse key.
                                        let rev_proto = match meta.protocol {
                                            PROTO_ICMPV6 => PROTO_ICMP,
                                            p => p,
                                        };
                                        let (src_port, dst_port) =
                                            if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
                                                (
                                                    flow.forward_key.src_port,
                                                    flow.forward_key.dst_port,
                                                )
                                            } else {
                                                (
                                                    flow.forward_key.dst_port,
                                                    flow.forward_key.src_port,
                                                )
                                            };
                                        (
                                            SessionKey {
                                                addr_family: libc::AF_INET as u8,
                                                protocol: rev_proto,
                                                src_ip: IpAddr::V4(dst_v4),
                                                dst_ip: IpAddr::V4(snat_v4),
                                                src_port,
                                                dst_port,
                                            },
                                            rev_proto,
                                        )
                                    } else {
                                        (flow.reverse_key_with_nat(decision.nat), meta.protocol)
                                    };
                                    let _ = reverse_protocol; // used below for install
                                    let reverse_metadata = SessionMetadata {
                                        ingress_zone: to_zone_id,
                                        egress_zone: from_zone_id,
                                        owner_rg_id,
                                        fabric_ingress,
                                        is_reverse: true,
                                        nat64_reverse: nat64_info,
                                        // #2508: mirror the admitting policy's log
                                        // selection onto the reverse entry so the
                                        // close delta carries a consistent gate
                                        // regardless of which entry expires it.
                                        log_session_init: policy_result.log_session_init,
                                        log_session_close: policy_result.log_session_close,
                                        // #3056: mirror the admitting policy ID onto
                                        // the reverse companion so a row keyed on the
                                        // reverse tuple attributes the same policy.
                                        policy_id: policy_result.policy_id,
                                    };
                                    // #1861 §5.2: the reverse install is gated on
                                    // forward_installed (was track_in_userspace —
                                    // a forward failure used to fall through and
                                    // still attempt the reverse, the latent
                                    // half-open-reverse hazard). At this point
                                    // track_in_userspace ⇒ forward_installed
                                    // (the residual arm above drops otherwise),
                                    // so this gate is explicit, not a behavior
                                    // fork.
                                    let reverse_installed = forward_installed
                                        && install_local_reverse
                                        && sessions.install_with_protocol_with_origin(
                                            reverse_key.clone(),
                                            reverse_decision,
                                            reverse_metadata.clone(),
                                            SessionOrigin::ReverseFlow,
                                            now_ns,
                                            meta.protocol,
                                            meta.tcp_flags,
                                        );
                                    if forward_installed
                                        && install_local_reverse
                                        && !reverse_installed
                                    {
                                        // #1861 §5.2 residual (reverse half):
                                        // impossible after a passing can_admit
                                        // for needed_sessions == 2. Release
                                        // (#1855 contract): keep the committed
                                        // forward (the reply repair services
                                        // inbound), count, and suppress the
                                        // flow-cache entry so the partially-
                                        // installed flow is re-evaluated per
                                        // packet instead of being persisted.
                                        debug_assert!(
                                            false,
                                            "reverse install failed after can_admit preflight"
                                        );
                                        sessions.note_install_partial();
                                        flow_cache_install_failed = true;
                                    }
                                    if reverse_installed {
                                        // #1789: count failed reverse-key
                                        // publishes (was `let _ =`; the
                                        // debug-only verify below re-reads
                                        // the map and cannot see the Err).
                                        if publish_live_session_key(
                                            binding.bpf_maps.session_map_fd,
                                            &reverse_key,
                                        )
                                        .is_err()
                                        {
                                            binding
                                                .live
                                                .session_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        // Verify session keys and log creations (debug-only: BPF syscalls)
                                        if cfg!(feature = "debug-log") {
                                            if verify_session_key_in_bpf(
                                                binding.bpf_maps.session_map_fd,
                                                &reverse_key,
                                            ) {
                                                SESSION_PUBLISH_VERIFY_OK
                                                    .fetch_add(1, Ordering::Relaxed);
                                            } else {
                                                SESSION_PUBLISH_VERIFY_FAIL
                                                    .fetch_add(1, Ordering::Relaxed);
                                                debug_log!(
                                                    "SESS_VERIFY_FAIL: reverse key NOT found after publish! \
                                                             af={} proto={} {}:{} -> {}:{} (map_fd={})",
                                                    reverse_key.addr_family,
                                                    reverse_key.protocol,
                                                    reverse_key.src_ip,
                                                    reverse_key.src_port,
                                                    reverse_key.dst_ip,
                                                    reverse_key.dst_port,
                                                    binding.bpf_maps.session_map_fd,
                                                );
                                            }
                                            if !verify_session_key_in_bpf(
                                                binding.bpf_maps.session_map_fd,
                                                &flow.forward_key,
                                            ) {
                                                debug_log!(
                                                    "SESS_VERIFY_FAIL: forward key NOT found! \
                                                             af={} proto={} {}:{} -> {}:{}",
                                                    flow.forward_key.addr_family,
                                                    flow.forward_key.protocol,
                                                    flow.forward_key.src_ip,
                                                    flow.forward_key.src_port,
                                                    flow.forward_key.dst_ip,
                                                    flow.forward_key.dst_port,
                                                );
                                            }
                                            let logged = SESSION_CREATIONS_LOGGED
                                                .fetch_add(1, Ordering::Relaxed);
                                            if logged < 10 {
                                                debug_log!(
                                                    "SESS_CREATE[{}]: FWD af={} proto={} {}:{} -> {}:{} \
                                                             | REV af={} proto={} {}:{} -> {}:{} \
                                                             | NAT src={:?} dst={:?} \
                                                             | map_fd={} bpf_entries={}",
                                                    logged,
                                                    flow.forward_key.addr_family,
                                                    flow.forward_key.protocol,
                                                    flow.forward_key.src_ip,
                                                    flow.forward_key.src_port,
                                                    flow.forward_key.dst_ip,
                                                    flow.forward_key.dst_port,
                                                    reverse_key.addr_family,
                                                    reverse_key.protocol,
                                                    reverse_key.src_ip,
                                                    reverse_key.src_port,
                                                    reverse_key.dst_ip,
                                                    reverse_key.dst_port,
                                                    decision.nat.rewrite_src,
                                                    decision.nat.rewrite_dst,
                                                    binding.bpf_maps.session_map_fd,
                                                    count_bpf_session_entries(
                                                        binding.bpf_maps.session_map_fd
                                                    ),
                                                );
                                                dump_bpf_session_entries(
                                                    binding.bpf_maps.session_map_fd,
                                                    20,
                                                );
                                            }
                                        }
                                        created += 1;
                                        let reverse_entry = SyncedSessionEntry {
                                            key: reverse_key,
                                            decision: reverse_decision,
                                            metadata: reverse_metadata,
                                            origin: SessionOrigin::ReverseFlow,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                            // Local reverse-flow learn (#2170): no peer gen.
                                            generation: 0,
                                        };
                                        publish_shared_session(
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            &reverse_entry,
                                        );
                                        replicate_session_upsert(
                                            worker_ctx.peer_worker_commands,
                                            &reverse_entry,
                                        );
                                    }
                                    if created > 0 {
                                        telemetry.counters.session_creates += created;
                                        telemetry.dbg.session_create += created;
                                    }
                                }
                            } else {
                                emit_policy_deny_event(
                                    worker_ctx.event_stream,
                                    flow,
                                    meta,
                                    from_zone_id,
                                    to_zone_id,
                                    owner_rg_id,
                                    policy_result.policy_id,
                                    policy_result.action,
                                    // #2520: resolve the AppID with the same
                                    // app_catalog.lookup the session-create hot
                                    // path runs, so the deny RT_FLOW record
                                    // carries the application, not UNKNOWN.
                                    resolve_flow_app_id(&worker_ctx.forwarding.app_catalog, flow),
                                    now_ns,
                                );
                                telemetry.dbg.policy_deny += 1;
                                if cfg!(feature = "debug-log")
                                    && (telemetry.dbg.policy_deny <= 3 || is_trust_flow)
                                {
                                    debug_log!(
                                        "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
                                        telemetry.dbg.policy_deny,
                                        flow.src_ip,
                                        flow.forward_key.src_port,
                                        flow.dst_ip,
                                        flow.forward_key.dst_port,
                                        meta.protocol,
                                        from_zone,
                                        to_zone,
                                        meta.ingress_ifindex,
                                        resolution.egress_ifindex,
                                    );
                                }
                                // #2089/#3071: `reject` actively rejects —
                                // synthesize a TCP RST (TCP) or ICMP
                                // unreachable (admin-prohibited; other
                                // protocols) back toward the source. Plain
                                // `deny` is a silent drop UNLESS the flow is
                                // TCP and the ingress (from) zone has Junos
                                // `tcp-rst`, in which case a TCP RST is sent.
                                // The reply is enqueued here before the
                                // disposition fall-through, while flow /
                                // action / from_zone_id / packet_frame are in
                                // scope.
                                enqueue_deny_reply(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    flow,
                                    telemetry.counters,
                                    matches!(policy_result.action, PolicyAction::Reject),
                                    from_zone_id,
                                );
                                decision.resolution.disposition =
                                    ForwardingDisposition::PolicyDenied;
                            }
                        } else if decision.resolution.disposition
                            == ForwardingDisposition::HAInactive
                            && !packet_fabric_ingress
                        {
                            let owner_rg_id =
                                owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                            if owner_rg_id > 0 {
                                flow_cache_owner_rg_id = owner_rg_id;
                            }
                            // New flow to inactive RG: fabric-redirect to the peer
                            // that owns the egress RG.  Use from_zone_arc directly
                            // (always in scope) rather than going through the debug
                            // struct which may not have been populated.
                            // #919/#922: ID-keyed redirect — no name lookup.
                            if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
                                worker_ctx.forwarding,
                                from_zone_id,
                            )
                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                            {
                                decision.resolution = redirect;
                            }
                        }
                        decision
                    }
                } else {
                    let non_flow_resolution = enforce_ha_resolution_snapshot(
                        worker_ctx.forwarding,
                        worker_ctx.ha_state,
                        now_secs,
                        resolve_forwarding(
                            // SAFETY: per the `area` contract in this
                            // function's header comment.
                            unsafe { &*area },
                            desc,
                            meta,
                            worker_ctx.forwarding,
                            worker_ctx.dynamic_neighbors,
                        ),
                    );
                    // For non-flow packets (no L4 ports), also attempt fabric
                    // redirect when the egress RG is inactive.
                    let final_resolution = if non_flow_resolution.disposition
                        == ForwardingDisposition::HAInactive
                        && !packet_fabric_ingress
                    {
                        resolve_fabric_redirect(worker_ctx.forwarding)
                            .unwrap_or(non_flow_resolution)
                    } else {
                        non_flow_resolution
                    };
                    SessionDecision {
                        resolution: final_resolution,
                        nat: NatDecision::default(),
                    }
                };
                // Safety net: convert any remaining HAInactive to fabric
                // redirect. Session-hit and new-flow paths each attempt
                // fabric redirect internally, but demoted sessions that
                // arrive via DNAT/interface-NAT XDP shim paths can slip
                // through with HAInactive when the inner conversion found
                // no fabric link at the time. Anti-loop: never redirect
                // packets that arrived on the fabric interface itself.
                // Only redirect when the egress maps to a known RG.
                // HAInactive with unknown ownership (rg=0) means unresolved
                // — those should NOT be fabric-redirected.
                let egress_rg = owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                if decision.resolution.disposition == ForwardingDisposition::HAInactive
                    && egress_rg > 0
                    && !packet_fabric_ingress
                {
                    if flow_cache_owner_rg_id <= 0 {
                        flow_cache_owner_rg_id = egress_rg;
                    }
                    // #919: prefer the cached u16 zone ID; fall back to
                    // looking up the ifindex's zone name and translating
                    // to an ID. resolve_zone_encoded_fabric_redirect_by_id
                    // skips the name round-trip.
                    // #921: direct ifindex → u16 (was a two-hop
                    // name round-trip).
                    let zone_id = session_ingress_zone.or_else(|| {
                        worker_ctx
                            .forwarding
                            .ifindex_to_zone_id
                            .get(&(meta.ingress_ifindex as i32))
                            .copied()
                    });
                    if let Some(redirect) = zone_id
                        .and_then(|id| {
                            resolve_zone_encoded_fabric_redirect_by_id(worker_ctx.forwarding, id)
                        })
                        .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                    {
                        decision.resolution = redirect;
                    }
                }
                if matches!(
                    decision.resolution.disposition,
                    ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
                ) {
                    telemetry.dbg.forward += 1;
                    // #2501: account this slow-path forwarded packet against
                    // its session. The flow-cache fast path accounts every
                    // packet of an established flow; this chokepoint covers
                    // the packets that reach the full forward-build — the
                    // first packet(s) of a flow before the cache warms, and
                    // any non-cacheable flow (NAT64/NPTv6). `account_packet`
                    // derives the direction from the resolved entry and folds
                    // it onto the canonical forward entry; a packet whose
                    // session does not yet exist (the very first SYN, accounted
                    // on its install pass via the cache or this site once the
                    // session lands) is a no-op miss.
                    if let Some(flow) = flow.as_ref() {
                        sessions.account_packet(&flow.forward_key, meta.pkt_len as u64);
                    }
                    // Direction-specific tracking
                    let ingress_if = meta.ingress_ifindex as i32;
                    let egress_if = decision.resolution.egress_ifindex;
                    if ingress_if == 5 {
                        telemetry.dbg.rx_from_trust += 1;
                        telemetry.dbg.fwd_trust_to_wan += 1;
                    } else if ingress_if == 6 {
                        telemetry.dbg.rx_from_wan += 1;
                        telemetry.dbg.fwd_wan_to_trust += 1;
                    }
                    // NAT decision tracking
                    if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some() {
                        telemetry.dbg.nat_applied_snat += 1;
                        telemetry.dbg.nat_applied_dnat += 1;
                    } else if decision.nat.rewrite_src.is_some() {
                        telemetry.dbg.nat_applied_snat += 1;
                    } else if decision.nat.rewrite_dst.is_some() {
                        telemetry.dbg.nat_applied_dnat += 1;
                    } else {
                        telemetry.dbg.nat_applied_none += 1;
                    }
                    // Log NAT details for first few forward-candidate packets
                    if cfg!(feature = "debug-log") {
                        if telemetry.dbg.forward <= 10 {
                            let flow_str = flow
                                .as_ref()
                                .map(|f| {
                                    format!(
                                        "{}:{} -> {}:{}",
                                        f.src_ip,
                                        f.forward_key.src_port,
                                        f.dst_ip,
                                        f.forward_key.dst_port
                                    )
                                })
                                .unwrap_or_else(|| "no-flow".into());
                            let nat_str = format!(
                                "snat={:?} dnat={:?}",
                                decision.nat.rewrite_src, decision.nat.rewrite_dst,
                            );
                            eprintln!(
                                "DBG FWD_DECISION[{}]: ingress_if={} egress_if={} {} {} proto={}",
                                telemetry.dbg.forward,
                                ingress_if,
                                egress_if,
                                flow_str,
                                nat_str,
                                meta.protocol,
                            );
                        }
                    }
                    // TCP flag tracking on forwarded frames
                    if cfg!(feature = "debug-log") {
                        if meta.protocol == 6 {
                            // Compare meta.tcp_flags from BPF shim with raw frame TCP flags.
                            // #1145: reuse line-50 raw_frame bind instead of re-slicing.
                            let raw_tcp_info = extract_tcp_flags_and_window(raw_frame);
                            let raw_flags = raw_tcp_info.map(|(f, _)| f);
                            let raw_window = raw_tcp_info.map(|(_, w)| w);
                            // Log first 20 forwarded TCP packets: compare meta vs raw
                            if telemetry.dbg.forward <= 20 {
                                let flow_str = flow
                                    .as_ref()
                                    .map(|f| {
                                        format!(
                                            "{}:{} -> {}:{}",
                                            f.src_ip,
                                            f.forward_key.src_port,
                                            f.dst_ip,
                                            f.forward_key.dst_port
                                        )
                                    })
                                    .unwrap_or_else(|| "no-flow".into());
                                eprintln!(
                                    "FWD_TCP_CMP[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} l4_off={} {}",
                                    telemetry.dbg.forward,
                                    meta.tcp_flags,
                                    raw_flags
                                        .map(|f| format!("0x{:02x}", f))
                                        .unwrap_or_else(|| "NONE".into()),
                                    raw_window
                                        .map(|w| format!("{}", w))
                                        .unwrap_or_else(|| "NONE".into()),
                                    desc.len,
                                    meta.l4_offset,
                                    flow_str,
                                );
                                // Hex dump bytes around TCP flags position in raw frame.
                                // #1145: reuse line-50 raw_frame bind (no Option wrapper).
                                let l4 = meta.l4_offset as usize;
                                if raw_frame.len() > l4 + 20 {
                                    let tcp_hdr: String = raw_frame[l4..l4 + 20]
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    eprintln!(
                                        "FWD_TCP_HDR[{}]: offset={} {}",
                                        telemetry.dbg.forward, l4, tcp_hdr
                                    );
                                }
                            }
                            if crate::tcp_flags::has_rst(meta.tcp_flags) {
                                // RST
                                telemetry.dbg.fwd_tcp_rst += 1;
                                if telemetry.dbg.fwd_tcp_rst <= 5 {
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "FWD_TCP_RST_DETECT[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} fwd#={} {}",
                                        telemetry.dbg.fwd_tcp_rst,
                                        meta.tcp_flags,
                                        raw_flags
                                            .map(|f| format!("0x{:02x}", f))
                                            .unwrap_or_else(|| "NONE".into()),
                                        raw_window
                                            .map(|w| format!("{}", w))
                                            .unwrap_or_else(|| "NONE".into()),
                                        desc.len,
                                        telemetry.dbg.forward,
                                        flow_str,
                                    );
                                    // Hex dump TCP header when RST detected.
                                    // #1145: reuse line-50 raw_frame bind.
                                    let l4 = meta.l4_offset as usize;
                                    if raw_frame.len() > l4 + 20 {
                                        let tcp_hdr: String = raw_frame[l4..l4 + 20]
                                            .iter()
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        eprintln!(
                                            "FWD_TCP_RST_HDR[{}]: meta_off={} raw_off={} {}",
                                            telemetry.dbg.fwd_tcp_rst,
                                            l4,
                                            frame_l3_offset(raw_frame).unwrap_or(0),
                                            tcp_hdr
                                        );
                                    }
                                }
                            }
                            if crate::tcp_flags::has_fin(meta.tcp_flags) {
                                // FIN
                                telemetry.dbg.fwd_tcp_fin += 1;
                                if telemetry.dbg.fwd_tcp_fin <= 5 {
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "FWD_TCP_FIN[{}]: ingress_if={} {} tcp_flags=0x{:02x}",
                                        telemetry.dbg.fwd_tcp_fin,
                                        meta.ingress_ifindex,
                                        flow_str,
                                        meta.tcp_flags,
                                    );
                                }
                            }
                            // Detect zero-window in TCP frames by inspecting raw packet
                            if let Some(win) = raw_window {
                                if win == 0 {
                                    telemetry.dbg.fwd_tcp_zero_window += 1;
                                    if telemetry.dbg.fwd_tcp_zero_window <= 10 {
                                        let flow_str = flow
                                            .as_ref()
                                            .map(|f| {
                                                format!(
                                                    "{}:{} -> {}:{}",
                                                    f.src_ip,
                                                    f.forward_key.src_port,
                                                    f.dst_ip,
                                                    f.forward_key.dst_port
                                                )
                                            })
                                            .unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_ZERO_WIN[{}]: ingress_if={} {} meta_flags=0x{:02x} raw_flags={}",
                                            telemetry.dbg.fwd_tcp_zero_window,
                                            meta.ingress_ifindex,
                                            flow_str,
                                            meta.tcp_flags,
                                            raw_flags
                                                .map(|f| format!("0x{:02x}", f))
                                                .unwrap_or_else(|| "NONE".into()),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    if should_teardown_tcp_rst(meta, flow.as_ref())
                        && let Some(flow) = flow.as_ref()
                    {
                        binding
                            .scratch
                            .scratch_rst_teardowns
                            .push((flow.forward_key.clone(), decision.nat));
                    }
                    telemetry.counters.forward_candidate_packets += 1;
                    if decision.nat.rewrite_src.is_some() {
                        telemetry.counters.snat_packets += 1;
                    }
                    if decision.nat.rewrite_dst.is_some() {
                        telemetry.counters.dnat_packets += 1;
                    }
                    // #2161: count every NAT64-translated forwarded packet
                    // here, the single forward-candidate site reached by
                    // both directions of a NAT64 flow (v6->v4 forward and
                    // v4->v6 reverse — both carry `decision.nat.nat64`).
                    // NAT64 flows are non-cacheable (FlowCacheEntry::
                    // should_cache excludes nat64), so the flow-cache-hit
                    // fast path never serves them and this is the only site
                    // that needs to count. Forward NAT64 also sets
                    // rewrite_src/rewrite_dst, so it is additionally counted
                    // as SNAT+DNAT above — the NAT64 counter is a distinct,
                    // additive translation tally, not a replacement.
                    if decision.nat.nat64 {
                        telemetry.counters.nat64_translations += 1;
                    }
                    if let Some(mut request) = build_live_forward_request_from_frame(
                        worker_ctx.binding_lookup,
                        binding_index,
                        &worker_ctx.ident,
                        desc,
                        packet_frame,
                        meta,
                        &decision,
                        worker_ctx.forwarding,
                        flow.as_ref(),
                        session_ingress_zone,
                        apply_nat_on_fabric,
                        now_ns,
                        worker_ctx.event_stream,
                        None,
                        None,
                    ) {
                        // #2362: capture the per-packet L4 match inputs from the
                        // frame BEFORE `owned_packet_frame.take()` below moves the
                        // backing buffer out — the flow-cache log-only evaluation
                        // further down would otherwise borrow `packet_frame`
                        // after the take. TermMatchExtra is a small Copy value
                        // holding no borrow.
                        let filter_match_extra =
                            crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta);
                        request.frame = owned_packet_frame
                            .take()
                            .map(PendingForwardFrame::Owned)
                            .unwrap_or(PendingForwardFrame::Live);
                        telemetry.dbg.tx += 1; // track forward requests queued
                        if cfg!(feature = "debug-log") {
                            if telemetry.dbg.tx <= 5 {
                                let dst_mac_str = decision
                                    .resolution
                                    .neighbor_mac
                                    .map(|m| {
                                        format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )
                                    })
                                    .unwrap_or_else(|| "NONE".into());
                                let src_mac_str = decision
                                    .resolution
                                    .src_mac
                                    .map(|m| {
                                        format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )
                                    })
                                    .unwrap_or_else(|| "NONE".into());
                                let flow_str = flow
                                    .as_ref()
                                    .map(|f| {
                                        format!(
                                            "{}:{} -> {}:{}",
                                            f.src_ip,
                                            f.forward_key.src_port,
                                            f.dst_ip,
                                            f.forward_key.dst_port
                                        )
                                    })
                                    .unwrap_or_else(|| "no-flow".into());
                                eprintln!(
                                    "DBG FWD_REQ: target_if={} egress_if={} tx_if={} len={} proto={} vlan={} dst_mac={} src_mac={} flow={}",
                                    request.target_ifindex,
                                    decision.resolution.egress_ifindex,
                                    decision.resolution.tx_ifindex,
                                    desc.len,
                                    meta.protocol,
                                    decision.resolution.tx_vlan_id,
                                    dst_mac_str,
                                    src_mac_str,
                                    flow_str,
                                );
                            }
                        }
                        let request_target_binding_index = request.target_binding_index;
                        binding.scratch.scratch_forwards.push(request);
                        recycle_now = false;
                        // ── Flow cache population ────────────────────
                        // Cache ForwardCandidate decisions for established
                        // TCP/UDP flows. Skip NAT64/NPTv6 (non-cacheable).
                        // #1861 §5.4: never cache a decision whose backing
                        // session install was attempted and refused
                        // (flow_cache_install_failed) — a cached
                        // sessionless decision would suppress the
                        // per-packet reply repair until cache
                        // invalidation. "No install required" paths
                        // (DNS fast-path, fabric-return) keep the flag
                        // false and cache as before.
                        if !flow_cache_install_failed
                            && let Some(flow) = flow.as_ref()
                            && let Some(entry) = FlowCacheEntry::from_forward_decision(
                                flow,
                                meta,
                                validation,
                                decision,
                                flow_cache_owner_rg_id,
                                session_ingress_zone,
                                request_target_binding_index,
                                evaluate_non_pbr_input_filter_log_only(
                                    worker_ctx.forwarding,
                                    filter_match_extra,
                                    Some(flow),
                                    meta,
                                    ingress_zone_override,
                                ),
                                worker_ctx.forwarding,
                                worker_ctx.ha_state,
                                apply_nat_on_fabric,
                                &worker_ctx.rg_epochs,
                            )
                        {
                            binding.flow.flow_cache.insert(entry);
                        }
                        // ── End flow cache population ────────────────
                    } else {
                        telemetry.dbg.build_fail += 1;
                        if cfg!(feature = "debug-log") {
                            if telemetry.dbg.build_fail <= 3 {
                                eprintln!(
                                    "DBG FWD_BUILD_NONE: egress_if={} tx_if={} neigh={:?} src_mac={:?} len={} proto={}",
                                    decision.resolution.egress_ifindex,
                                    decision.resolution.tx_ifindex,
                                    decision.resolution.neighbor_mac.map(|m| format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        m[0], m[1], m[2], m[3], m[4], m[5]
                                    )),
                                    decision.resolution.src_mac.map(|m| format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        m[0], m[1], m[2], m[3], m[4], m[5]
                                    )),
                                    desc.len,
                                    meta.protocol,
                                );
                            }
                        }
                    }
                } else {
                    // Debug: count non-forward dispositions
                    match decision.resolution.disposition {
                        ForwardingDisposition::LocalDelivery => {
                            telemetry.dbg.local += 1;
                            // Host-bound traffic (NDP, ICMP echo, BGP,
                            // GRE-to-self inner packets, etc.) is
                            // delivered by the SINGLE decap-aware
                            // reinject chokepoint at the end of this
                            // leg (`maybe_reinject_slow_path_from_frame`
                            // over `packet_frame`). #1885: this arm used
                            // to ALSO call the desc-based
                            // `maybe_reinject_slow_path` here, pairing
                            // the ORIGINAL UMEM frame (the VLAN-tagged
                            // GRE OUTER frame on a tagged underlay) with
                            // the post-decap INNER meta
                            // (`stage_native_gre_decap` rebinds `meta`
                            // but `desc` still points at the un-decapped
                            // frame) — the slice landed 4 bytes early on
                            // tagged ingress (TUN write EINVAL: payload
                            // started with the dot1q TCI tail instead of
                            // the IP version nibble) and delivered the
                            // still-encapsulated OUTER packet on
                            // untagged ingress. It was ALSO a duplicate
                            // enqueue for non-decapped local packets
                            // (both calls pass the same disposition
                            // filter). The first delivered packet
                            // creates a BPF session map entry so
                            // subsequent packets bypass userspace
                            // entirely.
                            recycle_now = true;
                        }
                        ForwardingDisposition::NoRoute => {
                            telemetry.dbg.no_route += 1;
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.no_route <= 3 {
                                    if let Some(flow) = flow.as_ref() {
                                        eprintln!(
                                            "DBG NO_ROUTE: {}:{} -> {}:{} proto={} ingress_if={}",
                                            flow.src_ip,
                                            flow.forward_key.src_port,
                                            flow.dst_ip,
                                            flow.forward_key.dst_port,
                                            meta.protocol,
                                            meta.ingress_ifindex,
                                        );
                                    }
                                }
                            }
                        }
                        ForwardingDisposition::MissingNeighbor => {
                            telemetry.dbg.missing_neigh += 1;
                            // #919/#922: zero-allocation ID-native zone
                            // resolution. Computed at the TOP of the arm so
                            // the #1913 policy gate below can run BEFORE the
                            // negative-cache fast-fail / resolver enqueue.
                            //
                            // #3021: resolve the LOGICAL ingress ifindex first
                            // (see the ForwardCandidate arm above) so a VLAN
                            // subinterface evaluates its OWN ingress zone, not
                            // the parent's first-subinterface zone.
                            let ingress_logical = resolve_ingress_logical_ifindex(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
                                meta.ingress_vlan_id,
                            )
                            .unwrap_or(meta.ingress_ifindex as i32);
                            let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                worker_ctx.forwarding,
                                ingress_logical,
                                ingress_zone_override,
                                decision.resolution.egress_ifindex,
                            );
                            // Borrow zone names as &str (no clone) for the
                            // string-typed downstream NAT helpers.
                            let from_zone: &str = worker_ctx
                                .forwarding
                                .zone_id_to_name
                                .get(&from_zone_id)
                                .map(|s| s.as_str())
                                .unwrap_or("");
                            let to_zone: &str = worker_ctx
                                .forwarding
                                .zone_id_to_name
                                .get(&to_zone_id)
                                .map(|s| s.as_str())
                                .unwrap_or("");
                            // #1913 (Codex r2/r3): evaluate policy for the
                            // MissingNeighbor cold path BEFORE any forwarding
                            // OR neighbor-resolution side-effect. The
                            // MissingNeighbor arm has its OWN policy
                            // evaluation (the main deny→PolicyDenied
                            // conversion lives only in the ForwardCandidate
                            // branch). A DENY must exit here so a denied flow
                            // never enqueues the shared resolver / fires a
                            // kernel ARP/NDP probe (network traffic for a
                            // flow policy says to drop, repeated per packet
                            // since denied frames are not buffered), never
                            // runs the negative-cache fast-fail, never seeds
                            // a session, never buffers in pending_neigh, and
                            // never reaches the slow-path reinject gate.
                            // `MissingNeighbor` is slow-path-eligible, so
                            // without this conversion a denied unresolved-
                            // neighbor cold-path packet was forwarded by the
                            // kernel FIB (a zone-policy bypass). The cold-path
                            // histogram samples this eval (session-install
                            // slow path).
                            if let Some(flow) = flow.as_ref() {
                                let (cp_sample_tag, cp_t_in) = {
                                    let cp = &mut binding.cold_path;
                                    cp.sample_phase = cp.sample_phase.wrapping_add(1);
                                    let tag =
                                        (cp.sample_phase & worker_ctx.cold_path_sample_mask) == 0;
                                    let t = if tag {
                                        crate::afxdp::cold_path_hist::sample_tsc_start()
                                    } else {
                                        0
                                    };
                                    (tag, t)
                                };
                                // #2345: MissingNeighbor cold path must match
                                // the SAME post-translation destination tuple as
                                // the ForwardCandidate path above so a denied
                                // (or permitted) verdict is identical whether or
                                // not the next-hop neighbor is already resolved.
                                // The session-miss block's `effective_resolution_target`
                                // is out of scope here, so reconstruct the
                                // post-translation dst tuple from the merged
                                // `decision.nat`:
                                //   - DNAT / static-DNAT / inbound NPTv6 each
                                //     populate `decision.nat.rewrite_dst` (set at
                                //     the decision build as `nptv6_nat.or(
                                //     pre_routing_dnat)`), so the translated
                                //     internal dst is used; only port-based DNAT
                                //     also sets `rewrite_dst_port`.
                                //   - NAT64 populates NEITHER `nptv6_nat` NOR
                                //     `pre_routing_dnat`, so `decision.nat
                                //     .rewrite_dst` is None here and the tuple
                                //     falls back to `flow.dst_ip` (the synthetic
                                //     IPv6 dst). That is the INTENDED NAT64
                                //     exclusion — cross-family policy matching is
                                //     not supported (see the long comment at the
                                //     ForwardCandidate policy-tuple binding), and
                                //     this fallback keeps the MissingNeighbor
                                //     verdict identical to the ForwardCandidate
                                //     path for NAT64.
                                // Both halves fall back to the original dst/port
                                // when no inbound destination translation applies.
                                let policy_dst_ip = decision.nat.rewrite_dst.unwrap_or(flow.dst_ip);
                                let policy_dst_port = decision
                                    .nat
                                    .rewrite_dst_port
                                    .unwrap_or(flow.forward_key.dst_port);
                                let policy_result = evaluate_policy_result_with_len(
                                    &worker_ctx.forwarding.policy,
                                    from_zone_id,
                                    to_zone_id,
                                    flow.src_ip,
                                    policy_dst_ip,
                                    flow.forward_key.protocol,
                                    flow.forward_key.src_port,
                                    policy_dst_port,
                                    desc.len as u64,
                                );
                                if cp_sample_tag {
                                    let t_out = crate::afxdp::cold_path_hist::sample_tsc_end();
                                    let q32 = binding.cold_path.ns_per_tsc_q32;
                                    if q32 != 0 {
                                        let delta_tsc = t_out.saturating_sub(cp_t_in);
                                        let raw_ns =
                                            ((delta_tsc as u128 * q32 as u128) >> 32) as u64;
                                        let baseline = binding.cold_path.wrapper_ns_baseline;
                                        let delta_ns = if raw_ns < baseline {
                                            binding.cold_path.wrapper_underflow_count = binding
                                                .cold_path
                                                .wrapper_underflow_count
                                                .saturating_add(1);
                                            0
                                        } else {
                                            raw_ns - baseline
                                        };
                                        if let Some(slot) =
                                            crate::afxdp::cold_path_hist::lookup_slot(
                                                &worker_ctx.forwarding.cold_path_slot_map,
                                                from_zone_id,
                                                to_zone_id,
                                            )
                                        {
                                            binding.cold_path.record_sample(
                                                slot,
                                                from_zone_id,
                                                to_zone_id,
                                                delta_ns,
                                            );
                                        }
                                    }
                                }
                                if !matches!(policy_result.action, PolicyAction::Permit) {
                                    let owner_rg_id = owner_rg_for_resolution(
                                        worker_ctx.forwarding,
                                        decision.resolution,
                                    );
                                    emit_policy_deny_event(
                                        worker_ctx.event_stream,
                                        flow,
                                        meta,
                                        from_zone_id,
                                        to_zone_id,
                                        owner_rg_id,
                                        policy_result.policy_id,
                                        policy_result.action,
                                        // #2520: AppID via the hot-path lookup.
                                        resolve_flow_app_id(
                                            &worker_ctx.forwarding.app_catalog,
                                            flow,
                                        ),
                                        now_ns,
                                    );
                                    telemetry.dbg.policy_deny += 1;
                                    // #2089/#3071: `reject` actively rejects
                                    // (TCP RST / ICMP unreachable); plain
                                    // `deny` stays a silent drop UNLESS the
                                    // flow is TCP and the ingress (from) zone
                                    // has Junos `tcp-rst`, in which case a TCP
                                    // RST is sent. Enqueue before the
                                    // disposition record + recycle.
                                    enqueue_deny_reply(
                                        &mut binding.tx_pipeline,
                                        worker_ctx.forwarding,
                                        binding.ifindex,
                                        packet_frame,
                                        meta,
                                        flow,
                                        telemetry.counters,
                                        matches!(policy_result.action, PolicyAction::Reject),
                                        from_zone_id,
                                    );
                                    decision.resolution.disposition =
                                        ForwardingDisposition::PolicyDenied;
                                    record_forwarding_disposition(
                                        &worker_ctx.ident,
                                        DispositionCounters::Hot(telemetry.counters),
                                        decision.resolution,
                                        desc.len as u32,
                                        Some(meta),
                                        debug.as_ref(),
                                        worker_ctx.recent_exceptions,
                                        worker_ctx.last_resolution,
                                        worker_ctx.forwarding,
                                    );
                                    binding.scratch.scratch_recycle.push(desc.addr);
                                    continue;
                                }
                            }
                            // No flow tuple (e.g. non-first fragment) skips
                            // the early policy gate and falls through to the
                            // negative-cache / probe / reinject path,
                            // preserving the pre-#1913 behavior —
                            // `MissingNeighbor` for a flowless packet was
                            // always slow-path-eligible.
                            // #1651 B3: dead-host fast-fail gate. Runs at
                            // the very top of the MissingNeighbor arm,
                            // BEFORE the kernel probe, session seed, and
                            // pending_neigh buffer, so a dead host never
                            // consumes a queue slot, fires a probe, or
                            // creates a MissingNeighborSeed session.
                            //
                            // Resolved-neighbor-wins (RTM_NEWNEIGH
                            // invalidation): check static then dynamic
                            // neighbors FIRST (same order as
                            // retry_pending_neigh / lookup_neighbor_entry).
                            // If the dst is now resolved, drop any stale
                            // negative entry and fall through to normal
                            // forwarding. Otherwise, if it is still
                            // negatively cached + un-expired, recycle the
                            // frame immediately.
                            // #1912: key the OUTER-hop neighbor
                            // resolution side-effects (ARP/NDP probe,
                            // #1769 resolver enqueue, neg-cache,
                            // resolved-wins, already-probing dedup) by the
                            // OUTER transport's L3 egress ifindex, not the
                            // tunnel logical ifindex. For a non-tunnel
                            // resolution this equals
                            // decision.resolution.egress_ifindex so the
                            // path is byte-identical; for a tunnel-marked
                            // decision (next_hop = outer hop) it is the
                            // outer transport egress where the outer
                            // neighbor is actually keyed (a VLAN outer
                            // transport keys on the L3 subif, not the VLAN
                            // parent / tx_ifindex). Computed once per cold
                            // packet on this arm.
                            let neigh_if = outer_neighbor_ifindex(
                                worker_ctx.forwarding,
                                Some(worker_ctx.dynamic_neighbors),
                                &decision.resolution,
                            );
                            if let Some(next_hop) = decision.resolution.next_hop {
                                let neg_key = (neigh_if, next_hop);
                                // neg_neigh_gate runs the resolved-wins
                                // probe (static neighbors THEN dynamic,
                                // same order as retry_pending_neigh /
                                // lookup_neighbor_entry) and the TTL check.
                                // Returns true ⇒ fast-fail this packet.
                                let fast_fail = neg_neigh_gate(
                                    &mut binding.neg_neigh_cache,
                                    &neg_key,
                                    now_ns,
                                    || {
                                        worker_ctx.forwarding.neighbors.contains_key(&neg_key)
                                            || worker_ctx.dynamic_neighbors.get(&neg_key).is_some()
                                    },
                                );
                                if fast_fail {
                                    telemetry.dbg.neg_neigh_fast_fail += 1;
                                    // #1782: promote the debug counter to a
                                    // real per-binding atomic so the
                                    // cold-start capture can read it from
                                    // Prometheus. Single Relaxed fetch_add
                                    // on the existing discard path — no new
                                    // hot-path work, no behavior change.
                                    binding
                                        .live
                                        .neg_neigh_fast_fail
                                        .fetch_add(1, Ordering::Relaxed);
                                    // #1769: the negative gate suppresses
                                    // the probe + buffer below, so a dst
                                    // that lost its dynamic entry (transient
                                    // FAILED/DELNEIGH or a dropped good
                                    // RTM_NEWNEIGH) would blackhole for the
                                    // full 3s TTL with nothing nudging it
                                    // back. Route it through the shared
                                    // resolver: a single-key RTM_GETNEIGH
                                    // off the hot path caches a confirmed
                                    // REACHABLE/PERMANENT lladdr (epoch-
                                    // guarded) or probes to force kernel
                                    // revalidation on a DELAY/STALE one.
                                    // Per-key rate-limited in the resolver
                                    // thread, so a SYN storm fires at most
                                    // one GET/probe per key per window. The
                                    // hot path only pays a non-blocking
                                    // try_send here (not per-packet — this
                                    // arm fires only on the negative fast-
                                    // fail).
                                    // Per-key rate-limited (the resolver
                                    // coalesces per-key anyway) so a
                                    // dead-host SYN storm does NOT clone +
                                    // try_send per fast-failed packet. See
                                    // try_enqueue_resolver.
                                    if let Some(resolver) = worker_ctx.neighbor_resolver {
                                        try_enqueue_resolver(
                                            resolver,
                                            &mut binding.resolver_enqueue_throttle,
                                            &worker_ctx.forwarding.ifindex_to_name,
                                            neg_key,
                                            now_ns,
                                        );
                                    }
                                    // Fresh RX descriptor → recycle via
                                    // scratch_recycle + continue, matching
                                    // the source-NAT-failure discard
                                    // pattern. The continue skips the
                                    // recycle_now epilogue and the
                                    // session-seed/buffer below.
                                    binding.scratch.scratch_recycle.push(desc.addr);
                                    continue;
                                }
                            }
                            // Send ARP/NDP solicitation via RAW socket (not XSK)
                            // so the reply goes through the kernel's normal RX
                            // path (cpumap_or_pass), bypassing XSK fill ring issues.
                            // Also reinject original packet to slow-path for kernel
                            // to forward once the neighbor is resolved.
                            // Trigger ARP/NDP resolution via kernel netlink.
                            // Adding an INCOMPLETE neighbor entry makes the
                            // kernel send its own ARP/NDP solicitation through
                            // the normal stack, which correctly handles VLAN
                            // tagging and TX offload. The netlink monitor then
                            // picks up the resolved entry instantly.
                            if let Some(next_hop) = decision.resolution.next_hop {
                                // #1912: tunnel-marked decisions are NEVER
                                // buffered in pending_neigh (R-E), and the
                                // per-hop neg-cache arms only on a
                                // pending_neigh timeout (neighbor_dispatch.rs
                                // neg_neigh_record), so for an unresolved
                                // OUTER hop the top-of-arm neg fast-fail can
                                // never arm and suppress this block. The
                                // outer-hop probe + resolver are therefore
                                // gated by the per-(neigh_if, next_hop)
                                // resolver_enqueue_throttle window below.
                                //
                                // outer_if_distinct: true only when this is a
                                // tunnel decision whose outer transport
                                // RESOLVED to a real L3 egress distinct from
                                // the tunnel logical ifindex. If
                                // outer_neighbor_ifindex fell back to
                                // egress_ifindex (endpoint vanished / outer
                                // egress <= 0 — unreachable within the
                                // single-threaded worker loop, but explicit),
                                // neigh_if == egress_ifindex == tunnel logical;
                                // probing / RTM_GETNEIGH on the GRE logical
                                // iface is the useless pre-#1912 behavior, so
                                // skip it (Copilot #1912 r1 Low).
                                let tunnel_marked = decision.resolution.tunnel_endpoint_id != 0;
                                let outer_if_distinct = tunnel_marked
                                    && neigh_if > 0
                                    && neigh_if != decision.resolution.egress_ifindex;
                                let throttle_key = (neigh_if, next_hop);
                                // For a tunnel decision, gate BOTH the kernel
                                // ARP probe AND the resolver enqueue behind
                                // ONE throttle window so a SYN flood to a
                                // flushed outer hop fires at most one
                                // probe + enqueue per outer key per window
                                // (else trigger_kernel_arp_probe — a raw
                                // socket open/setsockopt/sendto/close — would
                                // run per packet; AGY #1912 r1 High).
                                let tunnel_throttled = outer_if_distinct
                                    && matches!(
                                        binding
                                            .resolver_enqueue_throttle
                                            .get(&throttle_key),
                                        Some(&t) if now_ns.saturating_sub(t)
                                            < RESOLVER_ENQUEUE_THROTTLE_NS
                                    );
                                // Only spawn ping if we don't already have a
                                // pending probe for this (ifindex, hop).
                                // #1771 §2.2: pending_neigh is keyed by
                                // (egress_ifindex, next_hop), so the
                                // "already probing this hop" dedup is a
                                // direct contains_key (was an O(n) iter scan).
                                // #1912: dedup + iface lookup on the OUTER
                                // L3 egress (neigh_if), not the tunnel
                                // logical ifindex. For a non-tunnel flow
                                // neigh_if == egress_ifindex so the dedup is
                                // byte-identical; for a tunnel flow
                                // pending_neigh never holds the key (R-E), so
                                // the per-window throttle is the probe-storm
                                // bound instead.
                                let already_probing =
                                    binding.pending_neigh.contains_key(&(neigh_if, next_hop));
                                // Suppress the probe for a tunnel decision
                                // with NO distinct outer egress: neigh_if
                                // would be the tunnel logical ifindex and the
                                // probe would bind to the GRE iface (no ARP —
                                // the useless pre-#1912 behavior). For a
                                // non-tunnel flow tunnel_marked is false so
                                // this never suppresses (byte-identical).
                                let tunnel_without_outer = tunnel_marked && !outer_if_distinct;
                                if !already_probing && !tunnel_throttled && !tunnel_without_outer {
                                    let iface_name = worker_ctx
                                        .forwarding
                                        .ifindex_to_name
                                        .get(&neigh_if)
                                        .cloned();
                                    if let Some(name) = iface_name {
                                        // Fast path: ICMP socket triggers kernel ARP
                                        // in microseconds (no fork/exec).
                                        trigger_kernel_arp_probe(&name, neigh_if, next_hop);
                                    }
                                }
                                // #1912: for a tunnel-marked MissingNeighbor
                                // with a DISTINCT resolved outer egress (e.g.
                                // GRE outer hop), ALSO drive the #1769
                                // resolver on the OUTER L3 egress, not only on
                                // the neg-cache fast-fail. A freshly-flushed
                                // outer hop has no negative entry, so without
                                // this only the one-shot kernel ARP probe
                                // fires; the resolver hardens the STALE/DELAY
                                // outer-entry case via RTM_GETNEIGH. The frame
                                // is STILL NOT buffered (R-E), so no
                                // plaintext-leak window opens. try_enqueue_-
                                // resolver re-reads the SAME throttle entry
                                // and bumps it once, so the probe above and
                                // this enqueue share one window per key.
                                if outer_if_distinct && !tunnel_throttled {
                                    if let Some(resolver) = worker_ctx.neighbor_resolver {
                                        try_enqueue_resolver(
                                            resolver,
                                            &mut binding.resolver_enqueue_throttle,
                                            &worker_ctx.forwarding.ifindex_to_name,
                                            throttle_key,
                                            now_ns,
                                        );
                                    } else {
                                        // No resolver (probe-only build): bump
                                        // the throttle directly so the probe
                                        // above is still rate-limited to one
                                        // per window. Bounded like the neg
                                        // cache.
                                        let throttle = &mut binding.resolver_enqueue_throttle;
                                        if throttle.len() >= MAX_NEG_NEIGH_CACHE
                                            && !throttle.contains_key(&throttle_key)
                                        {
                                            throttle.clear();
                                        }
                                        throttle.insert(throttle_key, now_ns);
                                    }
                                }
                            }
                            // Create the session NOW so the SYN-ACK (reverse
                            // direction) finds the forward NAT match and creates
                            // a reverse session. Without this, the SYN-ACK hits
                            // session miss → policy deny (no rule for WAN→LAN).
                            let mut pending_decision = decision;
                            let mut source_nat_release_key = None;
                            // #2218: matched SNAT/static-SNAT rule counter
                            // for the seeded translated flow; incremented at
                            // the committed seed install below.
                            let mut source_nat_counter: Option<
                                std::sync::Arc<crate::nat::NatRuleCounter>,
                            > = None;
                            // #1861 §5.3: true when the seed install was
                            // ATTEMPTED and refused (max_sessions). Gates
                            // the pending-neighbor buffering below: a
                            // refused seed's SNAT allocation was rolled
                            // back, so replaying the buffered frame after
                            // neighbor resolution would forward it on an
                            // unreserved NAT tuple with no session. Flow-
                            // less packets (no install attempted) keep
                            // buffering as before.
                            let mut seed_install_refused = false;
                            if let Some(flow) = flow.as_ref() {
                                // #1913 (Codex r2): policy was already
                                // evaluated (and any DENY dropped+recycled)
                                // above, BEFORE the kernel ARP probe. Only a
                                // permitted flow reaches here, so the SNAT
                                // allocation runs unconditionally for the
                                // permitted MissingNeighbor flow. The
                                // cold-path histogram sample is taken at the
                                // early eval site above.
                                {
                                    let nat_match_flow = flow.with_destination(
                                        pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
                                    );
                                    // #1852: gate pool-mode SNAT allocation
                                    // for a non-first fragment (no L4 ports).
                                    let snat_non_first_fragment = {
                                        let l3 = meta.l3_offset as usize;
                                        l3 <= packet_frame.len()
                                            && is_non_first_fragment(
                                                &packet_frame[l3..],
                                                meta.addr_family,
                                            )
                                    };
                                    if pending_decision.nat.rewrite_dst.is_none() {
                                        let mut snat_match_counter = None;
                                        match source_nat_decision_for_flow(
                                            worker_ctx.forwarding,
                                            &from_zone,
                                            &to_zone,
                                            pending_decision.resolution.egress_ifindex,
                                            &nat_match_flow,
                                            now_ns,
                                            snat_non_first_fragment,
                                            &mut snat_match_counter,
                                        ) {
                                            Ok(snat_decision) => {
                                                pending_decision.nat = snat_decision;
                                                source_nat_release_key =
                                                    Some(nat_match_flow.forward_key.clone());
                                                source_nat_counter = snat_match_counter;
                                            }
                                            Err(failure) => {
                                                record_source_nat_failure(
                                                    telemetry,
                                                    worker_ctx,
                                                    meta,
                                                    flow,
                                                    from_zone_id,
                                                    to_zone_id,
                                                    desc.len,
                                                    &failure,
                                                );
                                                binding.scratch.scratch_recycle.push(desc.addr);
                                                continue;
                                            }
                                        }
                                    } else {
                                        let mut snat_match_counter = None;
                                        match source_nat_decision_for_flow(
                                            worker_ctx.forwarding,
                                            &from_zone,
                                            &to_zone,
                                            pending_decision.resolution.egress_ifindex,
                                            &nat_match_flow,
                                            now_ns,
                                            snat_non_first_fragment,
                                            &mut snat_match_counter,
                                        ) {
                                            Ok(snat_decision) => {
                                                pending_decision.nat =
                                                    pending_decision.nat.merge(snat_decision);
                                                source_nat_release_key =
                                                    Some(nat_match_flow.forward_key.clone());
                                                source_nat_counter = snat_match_counter;
                                            }
                                            Err(failure) => {
                                                record_source_nat_failure(
                                                    telemetry,
                                                    worker_ctx,
                                                    meta,
                                                    flow,
                                                    from_zone_id,
                                                    to_zone_id,
                                                    desc.len,
                                                    &failure,
                                                );
                                                binding.scratch.scratch_recycle.push(desc.addr);
                                                continue;
                                            }
                                        }
                                    }
                                }
                                let sess_meta = build_missing_neighbor_session_metadata(
                                    worker_ctx.forwarding,
                                    from_zone_id,
                                    to_zone_id,
                                    packet_fabric_ingress,
                                    pending_decision,
                                );
                                let pending_installed = sessions.install_with_protocol_with_origin(
                                    flow.forward_key.clone(),
                                    pending_decision,
                                    sess_meta.clone(),
                                    SessionOrigin::MissingNeighborSeed,
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                );
                                if pending_installed {
                                    // #2218: the seed install is the
                                    // committed translation for this
                                    // missing-neighbor flow (a refused seed
                                    // takes the else-arm below and rolls the
                                    // SNAT allocation back, so it is never
                                    // counted). Count the DNAT and SNAT
                                    // per-rule hits once each.
                                    let nat_hit_len = desc.len as u64;
                                    if let Some(c) = pre_routing_dnat_counter.as_ref() {
                                        c.add(nat_hit_len);
                                    }
                                    if let Some(c) = source_nat_counter.as_ref() {
                                        c.add(nat_hit_len);
                                    }
                                    let entry = SyncedSessionEntry {
                                        key: flow.forward_key.clone(),
                                        decision: pending_decision,
                                        metadata: sess_meta,
                                        origin: SessionOrigin::MissingNeighborSeed,
                                        protocol: meta.protocol,
                                        tcp_flags: meta.tcp_flags,
                                        // Local missing-neighbor seed (#2170): no peer gen.
                                        generation: 0,
                                    };
                                    publish_shared_session(
                                        worker_ctx.shared_sessions,
                                        worker_ctx.shared_nat_sessions,
                                        worker_ctx.shared_forward_wire_sessions,
                                        &worker_ctx.shared_owner_rg_indexes,
                                        &entry,
                                    );
                                    // #1789: count a failed publish
                                    // (shim misses the key -> NO_SESSION
                                    // degraded path for the seeded flow).
                                    if publish_session_map_entry_for_session(
                                        binding.bpf_maps.session_map_fd,
                                        &flow.forward_key,
                                        pending_decision,
                                        &entry.metadata,
                                    )
                                    .is_err()
                                    {
                                        binding
                                            .live
                                            .session_publish_errors
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    // #2008 M5: stamp the resolved app id.
                                    let app_id = worker_ctx.forwarding.app_catalog.lookup(
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_port,
                                    );
                                    publish_bpf_conntrack_entry(
                                        conntrack_v4_fd,
                                        conntrack_v6_fd,
                                        &flow.forward_key,
                                        pending_decision,
                                        &entry.metadata,
                                        &worker_ctx.forwarding.zone_name_to_id,
                                        worker_ctx.forwarding.alg_disable_flags,
                                        app_id,
                                    );
                                    // #2244: count failed reverse-NAT publishes so
                                    // map-pressure loss is operator-visible.
                                    if !publish_dnat_table_entry(
                                        &worker_ctx.dnat_fds,
                                        &flow.forward_key,
                                        pending_decision.nat,
                                    ) {
                                        binding
                                            .live
                                            .dnat_publish_errors
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    telemetry.counters.session_creates += 1;
                                } else {
                                    // #1861 §5.3: at-cap seed refusal. The
                                    // single-entry install IS the
                                    // transaction here (no pair); the
                                    // refusal is counted by the table's
                                    // create_drops (exported since #1861 —
                                    // admission_refused stays preflight-
                                    // only). Roll back the SNAT allocation
                                    // and drop the frame instead of
                                    // buffering it for replay.
                                    seed_install_refused = true;
                                    rollback_source_nat_allocation(
                                        &worker_ctx.forwarding.source_nat_rules,
                                        source_nat_release_key
                                            .as_ref()
                                            .unwrap_or(&flow.forward_key),
                                        pending_decision.nat,
                                        false,
                                        now_ns,
                                    );
                                }
                            }
                            // Buffer the packet. The ICMP probe resolves ARP
                            // in ~1ms. The retry loop below re-forwards the
                            // buffered packet once the neighbor resolves via the
                            // netlink monitor. The session was already created
                            // above so the SYN-ACK reverse path works too.
                            // Total latency: ~2ms (ARP + netlink + retry).
                            //
                            // NOTE: we do NOT reinject to slow-path here because
                            // kernel ARP resolution via XDP_PASS breaks VLAN demux
                            // in zero-copy mode (mlx5). The ICMP probe + netlink
                            // monitor + buffer-retry path bypasses this issue.
                            // #1771 §2.2: buffer one representative packet
                            // per (egress_ifindex, next_hop). Keep the
                            // OLDEST (it drives the probe/dwell clock):
                            // a duplicate for an already-buffered hop is
                            // dropped+recycled (recycle_now stays true),
                            // pinning ≤1 UMEM frame per unresolved hop.
                            // A packet with no next_hop cannot be keyed or
                            // resolved (the retry sweep needs next_hop to
                            // look up a MAC), so it is not buffered —
                            // recycled instead of held until timeout.
                            // #1861 §5.3: a refused seed is recycled, not
                            // buffered (see seed_install_refused above) —
                            // the kernel ARP probe already fired, and the
                            // next packet retries the install once the
                            // table has room, converging with the #1771
                            // duplicate-drop semantics.
                            // #1873 R-E: tunnel-marked decisions are
                            // NEVER admitted to pending_neigh. The retry
                            // path TXes buffered frames via in-place
                            // MAC/VLAN rewrite with no encapsulation, so
                            // a buffered tunnel inner packet would go out
                            // PLAINTEXT on the physical wire when the
                            // outer neighbor resolves (AGY plan r2,
                            // verified). The kernel ARP/ICMP probe above
                            // already fired, and the post-match
                            // maybe_reinject_slow_path_from_frame call
                            // routes this frame into the R-C tunnel gate
                            // (counted drop) — the #1769 resolver keeps
                            // driving the outer next-hop, and the flow
                            // recovers via retransmission once resolved.
                            // #1902 (sibling of #1885): a GRE-DECAPPED
                            // packet is NEVER admitted to pending_neigh.
                            // `desc` still references the un-decapped
                            // OUTER UMEM frame while `meta`/the decision
                            // describe the synthetic INNER frame in
                            // `owned_packet_frame`; the retry path's
                            // rewrite_forwarded_frame_in_place(pkt.desc,
                            // pkt.meta, ..) would MAC/NAT/TTL-rewrite the
                            // still-encapsulated outer packet at inner
                            // offsets and TX it toward the inner next-hop
                            // — a corrupt transmit, not a drop. The
                            // kernel ARP/ICMP probe above already fired,
                            // the trailing decap-aware
                            // maybe_reinject_slow_path_from_frame
                            // chokepoint (#1901) still hands the
                            // correctly-paired INNER packet to the kernel
                            // slow path, and the #1769 resolver +
                            // retransmission recover the flow once the
                            // neighbor resolves. Counted per binding so
                            // the live gate is observable
                            // (xpf_userspace_pending_neigh_decap_drops_total).
                            if !seed_install_refused
                                && pending_decision.resolution.tunnel_endpoint_id == 0
                                && pending_decision.resolution.next_hop.is_some()
                                && owned_packet_frame.is_some()
                            {
                                binding
                                    .live
                                    .pending_neigh_decap_drops
                                    .fetch_add(1, Ordering::Relaxed);
                            } else if !seed_install_refused
                                && pending_decision.resolution.tunnel_endpoint_id == 0
                                && let Some(hop) = pending_decision.resolution.next_hop
                            {
                                let pending_key = (pending_decision.resolution.egress_ifindex, hop);
                                // #1782: split the buffer-admission test so
                                // the capture can tell WHY a sibling was not
                                // buffered. The DuplicateDrop branch is the
                                // H5 sibling drop (key already pending — the
                                // first packet drove the kernel probe); the
                                // CapacityDrop branch is a distinct
                                // condition, counted SEPARATELY (#2375) in
                                // pending_neigh_capacity_drops. #1771
                                // §2.4: the decision is the pure
                                // `pending_neigh_admission` helper so
                                // invariant N1's "at most one buffered
                                // packet per key" half is unit-tested;
                                // behavior is unchanged — an insert happens
                                // iff the key is absent AND there is room,
                                // otherwise `recycle_now` stays true and
                                // the frame is recycled.
                                let admission = pending_neigh_admission(
                                    binding.pending_neigh.contains_key(&pending_key),
                                    binding.pending_neigh.len(),
                                );
                                // #2375: record the drop counters via the
                                // extracted helper so both the duplicate and
                                // the capacity case are a unit-tested
                                // side-effect (the test fails if either
                                // increment is removed). Buffer is a no-op
                                // here — the buffering insert stays inline
                                // below.
                                record_pending_neigh_admission_drop(&binding.live, admission);
                                match admission {
                                    PendingNeighAdmission::DuplicateDrop => {}
                                    PendingNeighAdmission::Buffer => {
                                        // #2357: when this buffered packet is
                                        // later flushed by retry_pending_neigh,
                                        // its stored flow_key drives
                                        // resolve_cos_tx_selection_at (egress
                                        // queue / DSCP / output-filter). A
                                        // non-first IP fragment carries no L4
                                        // header, so refuse to synthesize a
                                        // ported tuple from metadata for it —
                                        // store `None` so the flush selects the
                                        // interface default queue with no
                                        // port-filter eval. `flow` is already
                                        // `None` for a fragment (#2344); the
                                        // gate only suppresses the meta
                                        // fallback, leaving legitimate flowless
                                        // TCP/UDP packets (real L4 header) their
                                        // meta-derived ports. `raw_frame` is the
                                        // UMEM slice for `desc`; this branch is
                                        // only reached when
                                        // `owned_packet_frame.is_none()`, so it
                                        // describes the packet `meta` refers to.
                                        let pending_flow_key = flow
                                            .as_ref()
                                            .map(|flow| flow.forward_key.clone())
                                            .or_else(|| {
                                                if frame_is_non_first_fragment(raw_frame, meta) {
                                                    None
                                                } else {
                                                    parse_session_flow_from_meta(meta)
                                                        .map(|flow| flow.forward_key)
                                                }
                                            });
                                        binding.pending_neigh.insert(
                                            pending_key,
                                            PendingNeighPacket {
                                                addr: desc.addr,
                                                desc,
                                                meta,
                                                decision: pending_decision,
                                                flow_key: pending_flow_key,
                                                queued_ns: now_ns,
                                                probe_attempts: 0,
                                            },
                                        );
                                        recycle_now = false;
                                    }
                                    PendingNeighAdmission::CapacityDrop => {
                                        // #2375: a NEW distinct hop refused
                                        // because pending_neigh is at
                                        // MAX_PENDING_NEIGH (distinct-hop
                                        // neighbor exhaustion — the
                                        // scan/upstream-outage failure mode).
                                        // The counter increment is the helper
                                        // call above; the frame is recycled
                                        // exactly like the duplicate branch
                                        // (recycle_now stays true).
                                    }
                                }
                            }
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.missing_neigh <= 3 {
                                    if let Some(flow) = flow.as_ref() {
                                        eprintln!(
                                            "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
                                            "SOLICIT+SLOW",
                                            flow.src_ip,
                                            flow.forward_key.src_port,
                                            flow.dst_ip,
                                            flow.forward_key.dst_port,
                                            meta.protocol,
                                            pending_decision.resolution.egress_ifindex,
                                            pending_decision.resolution.next_hop,
                                        );
                                    }
                                }
                            }
                        }
                        ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
                        ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
                        _ => telemetry.dbg.disposition_other += 1,
                    }
                    record_forwarding_disposition(
                        &worker_ctx.ident,
                        DispositionCounters::Hot(telemetry.counters),
                        decision.resolution,
                        desc.len as u32,
                        Some(meta),
                        debug.as_ref(),
                        worker_ctx.recent_exceptions,
                        worker_ctx.last_resolution,
                        worker_ctx.forwarding,
                    );
                    // #1913: gate the trailing reinjection with the
                    // shared allow-list. Without this, PolicyDenied /
                    // HAInactive / DiscardRoute frames were handed to
                    // the kernel FIB unfiltered (a zone-policy DENY
                    // silently bypassed on the cold path). When the
                    // predicate rejects the disposition the frame is
                    // already counted by record_forwarding_disposition
                    // above and recycled by the recycle_now epilogue
                    // below — no leak, no double-count.
                    if decision.resolution.disposition.is_slow_path_eligible() {
                        maybe_reinject_slow_path_from_frame(
                            &worker_ctx.ident,
                            &binding.live,
                            worker_ctx.slow_path,
                            worker_ctx.local_tunnel_deliveries,
                            packet_frame,
                            meta,
                            decision,
                            worker_ctx.recent_exceptions,
                            "slow_path",
                            worker_ctx.forwarding,
                        );
                    }
                }
            } else {
                record_disposition(
                    &worker_ctx.ident,
                    &binding.live,
                    DispositionCounters::Hot(telemetry.counters),
                    disposition,
                    desc.len as u32,
                    Some(meta),
                    worker_ctx.recent_exceptions,
                    worker_ctx.forwarding,
                );
            }
        } else {
            telemetry.dbg.metadata_err += 1;
            binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
            record_exception(
                worker_ctx.recent_exceptions,
                &worker_ctx.ident,
                "metadata_parse",
                desc.len as u32,
                None,
                None,
                worker_ctx.forwarding,
            );
        }
        if recycle_now {
            binding.scratch.scratch_recycle.push(desc.addr);
        }
    }
    received.release();
    drop(received);
}

#[cfg(test)]
mod try_enqueue_resolver_tests {
    use super::*;
    use crate::afxdp::neighbor_resolver::{NeighborResolver, ResolveItem, ResolverCounters};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;

    fn make_resolver() -> (NeighborResolver, mpsc::Receiver<ResolveItem>) {
        let (tx, rx) = mpsc::sync_channel::<ResolveItem>(8);
        let resolver = NeighborResolver::new(
            tx,
            Arc::new(ResolverCounters::default()),
            Arc::new(AtomicU64::new(0)),
            Arc::new(crate::afxdp::neighbor_latency::NeighborLatencyHist::default()),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        (resolver, rx)
    }

    #[test]
    fn try_enqueue_resolver_throttles_within_window_and_bounds_map() {
        let (resolver, rx) = make_resolver();
        let mut throttle: FastMap<(i32, IpAddr), u64> = FastMap::default();
        let mut names: FastMap<i32, String> = FastMap::default();
        names.insert(12, "ge-0-0-2.80".to_string());
        let key = (12, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));

        // First call enqueues and records the throttle entry.
        assert!(try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000
        ));
        assert_eq!(rx.try_recv().expect("first enqueue").ifindex, 12);
        assert!(throttle.contains_key(&key));

        // Second call within RESOLVER_ENQUEUE_THROTTLE_NS is throttled: no
        // enqueue (storm bound — at most one per key per window).
        assert!(!try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000 + RESOLVER_ENQUEUE_THROTTLE_NS - 1
        ));
        assert!(rx.try_recv().is_err(), "throttled call must not enqueue");

        // After the window elapses, it enqueues again.
        assert!(try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000 + RESOLVER_ENQUEUE_THROTTLE_NS
        ));
        assert_eq!(rx.try_recv().expect("post-window enqueue").ifindex, 12);
    }

    #[test]
    fn try_enqueue_resolver_skips_when_iface_has_no_name() {
        let (resolver, rx) = make_resolver();
        let mut throttle: FastMap<(i32, IpAddr), u64> = FastMap::default();
        let names: FastMap<i32, String> = FastMap::default(); // empty
        let key = (362, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
        // No name for the ifindex ⇒ no enqueue, no throttle entry.
        assert!(!try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000
        ));
        assert!(rx.try_recv().is_err());
        assert!(throttle.is_empty());
    }
}

/// #2134: unit tests for the new-flow session-limit enforcement decision.
/// These drive `new_flow_session_limit_drop` directly against a real
/// `SessionTable` count, so they FAIL if the check is reverted to a
/// never-drop no-op (the #2134 bug) — the under/at/over-limit boundary
/// and the unconfigured-zone short-circuit are all pinned.
#[cfg(test)]
mod new_flow_session_limit_tests {
    use super::*;
    use crate::screen::ScreenProfile;
    use crate::session::{SessionMetadata, SessionOrigin};
    use std::net::{IpAddr, Ipv4Addr};

    fn forwarding_with_limit(zone: &str, src_limit: u32, dst_limit: u32) -> ForwardingState {
        let mut fw = ForwardingState::default();
        let mut profile = ScreenProfile::default();
        profile.session_limit_src = src_limit;
        profile.session_limit_dst = dst_limit;
        fw.screen_profiles.insert(zone.to_string(), profile);
        fw
    }

    fn counted_key(src: IpAddr, dst: IpAddr, src_port: u16) -> crate::session::SessionKey {
        crate::session::SessionKey {
            addr_family: 2,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port: 443,
        }
    }

    fn meta() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
        }
    }

    fn decision() -> crate::session::SessionDecision {
        crate::session::SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: crate::nat::NatDecision::default(),
        }
    }

    /// Install `n` distinct counted forward flows (distinct src ports) for
    /// the same (src, dst). `port_base` lets callers add MORE without
    /// re-installing already-present keys (which would net via the
    /// idempotent pre-clear).
    fn install_n(table: &mut SessionTable, src: IpAddr, dst: IpAddr, port_base: u16, n: u32) {
        for i in 0..n {
            assert!(table.install_with_protocol_with_origin(
                counted_key(src, dst, port_base + i as u16),
                decision(),
                meta(),
                SessionOrigin::ForwardFlow,
                1_000_000_000,
                crate::ip_proto::PROTO_TCP,
                0x10,
            ));
        }
    }

    #[test]
    fn under_limit_passes_at_and_over_limit_drops_src() {
        let fw = forwarding_with_limit("untrust", 3, 0);
        let mut table = SessionTable::new();
        table.set_session_limit_active(true);
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        // 0 sessions: under limit -> pass (None).
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            None
        );
        // 2 sessions (under 3): still pass.
        install_n(&mut table, src, dst, 40000, 2);
        assert_eq!(table.session_limit_src_count(src), 2);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            None
        );
        // 3 sessions (== limit): the next new flow MUST drop.
        install_n(&mut table, src, dst, 40002, 1); // distinct port -> count 3
        assert_eq!(table.session_limit_src_count(src), 3);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            Some("session-limit-src"),
            "at/over the limit, a new flow must be dropped"
        );
    }

    #[test]
    fn over_limit_drops_dst() {
        let fw = forwarding_with_limit("untrust", 0, 2);
        let mut table = SessionTable::new();
        table.set_session_limit_active(true);
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        install_n(&mut table, src, dst, 40000, 2);
        assert_eq!(table.session_limit_dst_count(dst), 2);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            Some("session-limit-dst")
        );
    }

    #[test]
    fn unconfigured_zone_never_drops() {
        // Zone present but no limit configured.
        let fw = forwarding_with_limit("untrust", 0, 0);
        let mut table = SessionTable::new();
        table.set_session_limit_active(true);
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 52));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        install_n(&mut table, src, dst, 40000, 50);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            None,
            "no limit configured -> never drop"
        );
        // Unknown zone name -> short-circuit None.
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "nonexistent", src, dst),
            None
        );
    }

    #[test]
    fn read_only_check_never_creates_phantom_entry() {
        // #2128: checking an IP that never installed a session must not
        // populate the count maps.
        let fw = forwarding_with_limit("untrust", 5, 5);
        let table = SessionTable::new();
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
        for _ in 0..1000 {
            assert_eq!(
                new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
                None
            );
        }
        assert_eq!(table.session_limit_src_map_len(), 0);
        assert_eq!(table.session_limit_dst_map_len(), 0);
    }
}
