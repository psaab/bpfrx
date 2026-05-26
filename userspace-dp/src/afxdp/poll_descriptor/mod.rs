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

mod flow_cache_hit;
mod rx_telemetry;

use flow_cache_hit::{FlowCacheOutcome, stage_flow_cache_hit};
use rx_telemetry::record_rx_descriptor_telemetry;

use super::poll_stages::{
    FabricIngressOutcome, ScreenCheckOutcome, StageOutcome, SynCookieAckOutcome,
    stage_classify_fabric_ingress, stage_ipsec_passthrough_check, stage_link_layer_classify,
    stage_native_gre_decap, stage_parse_flow_and_learn, stage_screen_check,
    stage_screen_syn_cookie_ack_on_session_miss,
};
use super::worker::WorkerTxPipeline;
use super::*;
use crate::policy::{evaluate_policy_result_with_len, evaluate_policy_with_len};
use crate::screen::SynCookieChallenge;

const SYN_COOKIE_REPLY_PENDING_RESERVE: usize = TX_BATCH_SIZE;

enum SynCookieReply {
    SynAck(SynCookieChallenge),
    AckRst,
}

#[inline]
fn source_nat_decision_for_flow(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
    now_ns: u64,
) -> Result<NatDecision, SourceNatFailure> {
    if let Some(decision) = forwarding.static_nat.match_snat(flow.src_ip, from_zone) {
        return Ok(decision);
    }
    match match_source_nat_for_flow_result_at(
        forwarding,
        from_zone,
        to_zone,
        egress_ifindex,
        flow,
        now_ns,
    ) {
        SourceNatLookup::Matched(decision) => Ok(decision),
        SourceNatLookup::NoMatch => Ok(NatDecision::default()),
        SourceNatLookup::Unavailable(failure) => Err(failure),
    }
}

#[inline]
fn record_source_nat_failure(
    telemetry: &mut TelemetryContext,
    worker_ctx: &WorkerContext,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    from_zone_id: u16,
    to_zone_id: u16,
    packet_length: u32,
    failure: &SourceNatFailure,
) {
    telemetry.counters.touched = true;
    telemetry.counters.exception_packets += 1;
    let mut debug = ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow);
    debug.from_zone = Some(from_zone_id);
    debug.to_zone = Some(to_zone_id);
    record_source_nat_exception(
        worker_ctx.recent_exceptions,
        &worker_ctx.ident,
        packet_length,
        Some(meta),
        Some(&debug),
        worker_ctx.forwarding,
        failure,
    );
}

#[inline]
fn filter_log_ingress_zone_id(
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
fn filter_log_egress_zone_id(forwarding: &ForwardingState, egress_ifindex: i32) -> u16 {
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|egress| egress.zone_id)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug)]
struct NonPbrInputFilterEval {
    action: crate::filter::FilterAction,
    cached_log: Option<CachedInputFilterLog>,
}

#[inline]
fn evaluate_non_pbr_input_filter(
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
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
        meta.pkt_len as u64,
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

#[inline]
fn evaluate_non_pbr_input_filter_log_only(
    forwarding: &ForwardingState,
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
fn evaluate_dscp_sensitive_input_filter_on_session_hit(
    forwarding: &ForwardingState,
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
    if !crate::filter::interface_input_filter_has_dscp_match(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    ) {
        return None;
    }
    Some(evaluate_non_pbr_input_filter(
        forwarding,
        Some(flow),
        meta,
        ingress_zone_override,
    ))
}

#[inline]
fn syn_cookie_reply_budget_available(tx_pipeline: &WorkerTxPipeline) -> bool {
    let max_pending = tx_pipeline.max_pending_tx;
    if max_pending == 0 {
        return false;
    }
    if tx_pipeline.free_tx_frames.len() <= SYN_COOKIE_REPLY_PENDING_RESERVE {
        return false;
    }
    let reserve = SYN_COOKIE_REPLY_PENDING_RESERVE.min(max_pending);
    let admitted = tx_pipeline
        .pending_tx_local
        .len()
        .saturating_add(tx_pipeline.pending_tx_prepared.len());
    admitted < max_pending.saturating_sub(reserve)
}

#[inline]
fn enqueue_syn_cookie_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    reply: SynCookieReply,
    counters: &mut BatchCounters,
) -> bool {
    if !syn_cookie_reply_budget_available(tx_pipeline) {
        counters.touched = true;
        counters.syn_cookie_reply_budget_drops += 1;
        return false;
    }

    let (bytes, sent_counter): (Option<Vec<u8>>, fn(&mut BatchCounters)) = match reply {
        SynCookieReply::SynAck(challenge) => (
            build_syn_cookie_syn_ack_frame(packet_frame, challenge.cookie_isn, challenge.peer_mss),
            |counters| counters.syn_cookie_syn_ack_sent += 1,
        ),
        SynCookieReply::AckRst => (build_syn_cookie_ack_rst_frame(packet_frame), |counters| {
            counters.syn_cookie_ack_rst_sent += 1
        }),
    };
    let Some(bytes) = bytes else {
        return false;
    };

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: flow.map(|flow| flow.forward_key.clone()),
        egress_ifindex: ifindex,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
    });
    counters.touched = true;
    sent_counter(counters);
    true
}

#[inline]
fn emit_input_filter_log_match(
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
        now_ns,
    );
}

#[inline]
fn emit_cached_input_filter_log(
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_descriptor: &RewriteDescriptor,
    now_ns: u64,
) {
    let Some(cached_log) = cached_descriptor.input_filter_log else {
        return;
    };
    emit_input_filter_log_match(
        event_stream,
        flow,
        meta,
        cached_log,
        now_ns,
    );
}

#[inline]
fn emit_cached_output_filter_log(
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
        now_ns,
    );
}

#[inline]
fn apply_lo0_filter_action(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_ns: u64,
) -> bool {
    let Some(flow) = flow else {
        return false;
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
            now_ns,
        );
    }
    !matches!(result.action, crate::filter::FilterAction::Accept)
}

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
            if let Some(meta) = try_parse_metadata(unsafe { &*area }, desc) {
                telemetry.counters.metadata_packets += 1;
                let disposition = classify_metadata(meta, validation);
                if disposition == PacketDisposition::Valid {
                    telemetry.counters.validated_packets += 1;
                    telemetry.counters.validated_bytes += desc.len as u64;
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
                            if resolved.created {
                                telemetry.counters.session_creates += 1;
                                telemetry.dbg.session_create += 1;
                                // Mirror new session to BPF conntrack map for
                                // `show security flow session` zone/interface display.
                                publish_bpf_conntrack_entry(
                                    conntrack_v4_fd,
                                    conntrack_v6_fd,
                                    &flow.forward_key,
                                    resolved.decision,
                                    &resolved.metadata,
                                    &worker_ctx.forwarding.zone_name_to_id,
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
                                    Some(flow),
                                    meta,
                                    Some(resolved.metadata.ingress_zone),
                                )
                            {
                                if let Some(cached_log) = input_filter_eval.cached_log {
                                    emit_input_filter_log_match(
                                        worker_ctx.event_stream,
                                        flow,
                                        meta,
                                        cached_log,
                                        now_ns,
                                    );
                                }
                                if input_filter_eval.action
                                    != crate::filter::FilterAction::Accept
                                {
                                    binding.scratch.scratch_recycle.push(desc.addr);
                                    continue;
                                }
                            }
                            if resolved.decision.resolution.disposition
                                == ForwardingDisposition::LocalDelivery
                                && apply_lo0_filter_action(
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    Some(flow),
                                    meta,
                                    Some(resolved.metadata.ingress_zone),
                                    now_ns,
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
                                        let _ = publish_live_session_entry(
                                            binding.bpf_maps.session_map_fd,
                                            &flow.forward_key,
                                            NatDecision::default(),
                                            true,
                                        );
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
                                    worker_ctx.forwarding.zone_id_to_name.get(&id).map(|s| s.as_str())
                                })
                                .or_else(|| {
                                    // #921: ifindex → u16 → name (slow path; DNAT/static-NAT
                                    // takes &str names).
                                    worker_ctx.forwarding
                                        .ifindex_to_zone_id
                                        .get(&(meta.ingress_ifindex as i32))
                                        .and_then(|id| worker_ctx.forwarding.zone_id_to_name.get(id))
                                        .map(|s| s.as_str())
                                })
                                .unwrap_or("");
                            let dnat_decision = if !worker_ctx.forwarding.dnat_table.is_empty() {
                                worker_ctx.forwarding.dnat_table.lookup(
                                    meta.protocol,
                                    resolution_target,
                                    flow.forward_key.dst_port,
                                    ingress_zone_name,
                                )
                            } else {
                                None
                            };
                            let static_dnat_decision = if dnat_decision.is_none() {
                                worker_ctx.forwarding
                                    .static_nat
                                    .match_dnat(resolution_target, ingress_zone_name)
                            } else {
                                None
                            };
                            let pre_routing_dnat = dnat_decision.or(static_dnat_decision);

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
                            let nat64_match =
                                if pre_routing_dnat.is_none() && nptv6_inbound.is_none() {
                                    if let IpAddr::V6(dst_v6) = resolution_target {
                                        worker_ctx.forwarding.nat64.match_ipv6_dest(dst_v6).and_then(
                                            |(idx, dst_v4)| {
                                                let snat_v4 =
                                                    worker_ctx.forwarding.nat64.allocate_v4_source(idx)?;
                                                Some((idx, dst_v4, snat_v4, dst_v6))
                                            },
                                        )
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
                            let input_filter_eval = evaluate_non_pbr_input_filter(
                                worker_ctx.forwarding,
                                Some(flow),
                                meta,
                                ingress_zone_override,
                            );
                            if input_filter_eval.action != crate::filter::FilterAction::Accept {
                                if let Some(cached_log) = input_filter_eval.cached_log {
                                    emit_input_filter_log_match(
                                        worker_ctx.event_stream,
                                        flow,
                                        meta,
                                        cached_log,
                                        now_ns,
                                    );
                                }
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            let route_table_override = ingress_route_table_override(
                                worker_ctx.forwarding,
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
                            let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
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
                            if resolution.disposition == ForwardingDisposition::LocalDelivery
                                && apply_lo0_filter_action(
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    Some(flow),
                                    meta,
                                    ingress_zone_override,
                                    now_ns,
                                )
                            {
                                telemetry.dbg.local += 1;
                                telemetry.dbg.policy_deny += 1;
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
                                    publish_bpf_conntrack_entry(
                                        conntrack_v4_fd,
                                        conntrack_v6_fd,
                                        &flow.forward_key,
                                        decision,
                                        &local_metadata,
                                        &worker_ctx.forwarding.zone_name_to_id,
                                    );
                                }
                            }
                            if is_embedded_icmp_error {
                                #[cfg(feature = "debug-log")]
                                let icmpv6_trace = meta.protocol == PROTO_ICMPV6
                                    && ICMPV6_EMBED_LOGGED.fetch_add(1, Ordering::Relaxed) < 32;
                                if let Some(icmp_match) = try_embedded_icmp_nat_match(
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
                                                now_ns,
                                            );
                                            if !cos.drop {
                                                binding.scratch.scratch_forwards.push(PendingForwardRequest {
                                                    target_ifindex,
                                                    target_binding_index: worker_ctx.binding_lookup.target_index(
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
                                                });
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
                                let policy_result = evaluate_policy_result_with_len(
                                    &worker_ctx.forwarding.policy,
                                    from_zone_id,
                                    to_zone_id,
                                    flow.src_ip,
                                    flow.dst_ip,
                                    flow.forward_key.protocol,
                                    flow.forward_key.src_port,
                                    flow.forward_key.dst_port,
                                    desc.len as u64,
                                );
                                if let PolicyAction::Permit = policy_result.action {
                                    // NAT64: cross-family translation takes
                                    // priority over same-family SNAT.
                                    let mut source_nat_release_key = None;
                                    let nat64_info = if let Some((
                                        _,
                                        dst_v4,
                                        snat_v4,
                                        orig_dst_v6,
                                    )) = nat64_match
                                    {
                                        decision.nat =
                                            Nat64State::forward_decision(snat_v4, dst_v4);
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
                                            let nptv6_snat = if let IpAddr::V6(mut src_v6) =
                                                nat_match_flow.src_ip
                                            {
                                                if worker_ctx.forwarding.nptv6.translate_outbound(&mut src_v6)
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
                                            match nptv6_snat.map(Ok).unwrap_or_else(|| {
                                                source_nat_decision_for_flow(
                                                    worker_ctx.forwarding,
                                                    &from_zone,
                                                    &to_zone,
                                                    decision.resolution.egress_ifindex,
                                                    &nat_match_flow,
                                                    now_ns,
                                                )
                                            }) {
                                                Ok(snat_decision) => {
                                                    decision.nat = snat_decision;
                                                    source_nat_release_key =
                                                        Some(nat_match_flow.forward_key.clone());
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
                                            match source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                &from_zone,
                                                &to_zone,
                                                decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                                now_ns,
                                            ) {
                                                Ok(snat_decision) => {
                                                    decision.nat = decision.nat.merge(snat_decision);
                                                    source_nat_release_key =
                                                        Some(nat_match_flow.forward_key.clone());
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
                                        let forward_metadata = SessionMetadata {
                                            ingress_zone: from_zone_id,
                                            egress_zone: to_zone_id,
                                            owner_rg_id,
                                            fabric_ingress,
                                            is_reverse: false,
                                            nat64_reverse: nat64_info,
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
                                        if forward_installed {
                                            created += 1;
                                            let forward_entry = SyncedSessionEntry {
                                                key: flow.forward_key.clone(),
                                                decision,
                                                metadata: forward_metadata,
                                                origin: SessionOrigin::ForwardFlow,
                                                protocol: meta.protocol,
                                                tcp_flags: meta.tcp_flags,
                                            };
                                            let _ = publish_live_session_entry(
                                                binding.bpf_maps.session_map_fd,
                                                &flow.forward_key,
                                                decision.nat,
                                                false,
                                            );
                                            publish_shared_session(
                                                worker_ctx.shared_sessions,
                                                worker_ctx.shared_nat_sessions,
                                                worker_ctx.shared_forward_wire_sessions,
                                                &worker_ctx.shared_owner_rg_indexes,
                                                &forward_entry,
                                            );
                                            // Populate BPF dnat_table for embedded ICMP NAT reversal.
                                            // Without this, mtr/traceroute intermediate hops are invisible.
                                            publish_dnat_table_entry(
                                                &worker_ctx.dnat_fds,
                                                &flow.forward_key,
                                                decision.nat,
                                            );
                                            replicate_session_upsert(
                                                worker_ctx.peer_worker_commands,
                                                &forward_entry,
                                            );
                                            if let Some(cached_log) =
                                                input_filter_eval.cached_log
                                            {
                                                emit_input_filter_log_match(
                                                    worker_ctx.event_stream,
                                                    flow,
                                                    meta,
                                                    cached_log,
                                                    now_ns,
                                                );
                                            }
                                        } else {
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
                                        let (reverse_key, reverse_protocol) = if nat64_info
                                            .is_some()
                                        {
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
                                            let (src_port, dst_port) = if matches!(
                                                meta.protocol,
                                                PROTO_ICMP | PROTO_ICMPV6
                                            ) {
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
                                        };
                                        if track_in_userspace
                                            && install_local_reverse
                                            && sessions.install_with_protocol_with_origin(
                                                reverse_key.clone(),
                                                reverse_decision,
                                                reverse_metadata.clone(),
                                                SessionOrigin::ReverseFlow,
                                                now_ns,
                                                meta.protocol,
                                                meta.tcp_flags,
                                            )
                                        {
                                            let _ = publish_live_session_key(
                                                binding.bpf_maps.session_map_fd,
                                                &reverse_key,
                                            );
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
                            resolve_fabric_redirect(worker_ctx.forwarding).unwrap_or(non_flow_resolution)
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
                                resolve_zone_encoded_fabric_redirect_by_id(
                                    worker_ctx.forwarding,
                                    id,
                                )
                            })
                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                        {
                            decision.resolution = redirect;
                        }
                    }
                    if matches!(
                        decision.resolution.disposition,
                        ForwardingDisposition::ForwardCandidate
                            | ForwardingDisposition::FabricRedirect
                    ) {
                        telemetry.dbg.forward += 1;
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
                        if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some()
                        {
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
                                if (meta.tcp_flags & 0x04) != 0 {
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
                                if (meta.tcp_flags & 0x01) != 0 {
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
                                .scratch.scratch_rst_teardowns
                                .push((flow.forward_key.clone(), decision.nat));
                        }
                        telemetry.counters.forward_candidate_packets += 1;
                        if decision.nat.rewrite_src.is_some() {
                            telemetry.counters.snat_packets += 1;
                        }
                        if decision.nat.rewrite_dst.is_some() {
                            telemetry.counters.dnat_packets += 1;
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
                            if let Some(flow) = flow.as_ref()
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
                                // Reinject to slow-path TUN so the kernel
                                // processes host-bound traffic (NDP, ICMP echo,
                                // BGP, etc.).  The first packet creates a BPF
                                // session map entry so subsequent packets bypass
                                // userspace entirely.
                                maybe_reinject_slow_path(
                                    worker_ctx.ident,
                                    &binding.live,
                                    worker_ctx.slow_path.as_deref(),
                                    worker_ctx.local_tunnel_deliveries,
                                    unsafe { &*area },
                                    desc,
                                    meta,
                                    decision,
                                    worker_ctx.recent_exceptions,
                                    worker_ctx.forwarding,
                                );
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
                                // #919/#922: zero-allocation ID-native resolution.
                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                    worker_ctx.forwarding,
                                    meta.ingress_ifindex as i32,
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
                                    // Only spawn ping if we don't already have a
                                    // pending probe for this (ifindex, hop).
                                    let already_probing = binding.pending_neigh.iter().any(|p| {
                                        p.decision.resolution.egress_ifindex
                                            == decision.resolution.egress_ifindex
                                            && p.decision.resolution.next_hop == Some(next_hop)
                                    });
                                    if !already_probing {
                                        let iface_name = worker_ctx.forwarding
                                            .ifindex_to_name
                                            .get(&decision.resolution.egress_ifindex)
                                            .cloned();
                                        if let Some(name) = iface_name {
                                            // Fast path: ICMP socket triggers kernel ARP
                                            // in microseconds (no fork/exec).
                                            trigger_kernel_arp_probe(&name, next_hop);
                                        }
                                    }
                                }
                                // Create the session NOW so the SYN-ACK (reverse
                                // direction) finds the forward NAT match and creates
                                // a reverse session. Without this, the SYN-ACK hits
                                // session miss → policy deny (no rule for WAN→LAN).
                                let mut pending_decision = decision;
                                let mut source_nat_release_key = None;
                                if let Some(flow) = flow.as_ref() {
                                    if let PolicyAction::Permit = evaluate_policy_with_len(
                                        &worker_ctx.forwarding.policy,
                                        from_zone_id,
                                        to_zone_id,
                                        flow.src_ip,
                                        flow.dst_ip,
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_port,
                                        desc.len as u64,
                                    ) {
                                        let nat_match_flow = flow.with_destination(
                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
                                        );
                                        if pending_decision.nat.rewrite_dst.is_none() {
                                            match source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                &from_zone,
                                                &to_zone,
                                                pending_decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                                now_ns,
                                            ) {
                                                Ok(snat_decision) => {
                                                    pending_decision.nat = snat_decision;
                                                    source_nat_release_key =
                                                        Some(nat_match_flow.forward_key.clone());
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
                                            match source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                &from_zone,
                                                &to_zone,
                                                pending_decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                                now_ns,
                                            ) {
                                                Ok(snat_decision) => {
                                                    pending_decision.nat =
                                                        pending_decision.nat.merge(snat_decision);
                                                    source_nat_release_key =
                                                        Some(nat_match_flow.forward_key.clone());
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
                                    let pending_installed =
                                        sessions.install_with_protocol_with_origin(
                                            flow.forward_key.clone(),
                                            pending_decision,
                                            sess_meta.clone(),
                                            SessionOrigin::MissingNeighborSeed,
                                            now_ns,
                                            meta.protocol,
                                            meta.tcp_flags,
                                        );
                                    if pending_installed {
                                        let entry = SyncedSessionEntry {
                                            key: flow.forward_key.clone(),
                                            decision: pending_decision,
                                            metadata: sess_meta,
                                            origin: SessionOrigin::MissingNeighborSeed,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                        };
                                        publish_shared_session(
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            &entry,
                                        );
                                        let _ = publish_session_map_entry_for_session(
                                            binding.bpf_maps.session_map_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                        );
                                        publish_bpf_conntrack_entry(
                                            conntrack_v4_fd,
                                            conntrack_v6_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                            &worker_ctx.forwarding.zone_name_to_id,
                                        );
                                        publish_dnat_table_entry(
                                            &worker_ctx.dnat_fds,
                                            &flow.forward_key,
                                            pending_decision.nat,
                                        );
                                        telemetry.counters.session_creates += 1;
                                    } else {
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
                                if binding.pending_neigh.len() < MAX_PENDING_NEIGH {
                                    let pending_flow_key = flow
                                        .as_ref()
                                        .map(|flow| flow.forward_key.clone())
                                        .or_else(|| {
                                            parse_session_flow_from_meta(meta)
                                                .map(|flow| flow.forward_key)
                                        });
                                    binding.pending_neigh.push_back(PendingNeighPacket {
                                        addr: desc.addr,
                                        desc,
                                        meta,
                                        decision: pending_decision,
                                        flow_key: pending_flow_key,
                                        queued_ns: now_ns,
                                        probe_attempts: 0,
                                    });
                                    recycle_now = false;
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
mod syn_cookie_reply_tests {
    use super::*;

    fn dummy_tx_request() -> TxRequest {
        TxRequest {
            bytes: Vec::new(),
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: 0,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
        }
    }

    fn tx_pipeline(
        max_pending_tx: usize,
        free_frames: usize,
        pending_local: usize,
    ) -> WorkerTxPipeline {
        let mut pipeline = WorkerTxPipeline {
            free_tx_frames: (0..free_frames as u64).collect(),
            pending_tx_prepared: VecDeque::new(),
            pending_tx_local: VecDeque::new(),
            max_pending_tx,
            outstanding_tx: 0,
            pending_fill_frames: VecDeque::new(),
            in_flight_prepared_recycles: FastMap::default(),
            tx_submit_ns: Vec::new().into_boxed_slice(),
        };
        for _ in 0..pending_local {
            pipeline.pending_tx_local.push_back(dummy_tx_request());
        }
        pipeline
    }

    fn tcp_v4_syn_frame() -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
        let src_ip = std::net::Ipv4Addr::new(192, 0, 2, 10);
        let dst_ip = std::net::Ipv4Addr::new(198, 51, 100, 20);
        let src_port = 49152u16;
        let dst_port = 443u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6,
            0x08, 0x00,
        ]);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x2c, 0x12, 0x34,
            0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x60, TCP_FLAG_SYN, 0xfa, 0xf0, // data offset / flags / window
            0x00, 0x00, 0x00, 0x00, // checksum + urgent
            0x02, 0x04, 0x05, 0xb4, // MSS 1460
        ]);
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&src_ip.octets());
        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&dst_ip.octets());
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 58,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            flow_src_addr: src_addr,
            flow_dst_addr: dst_addr,
            flow_src_port: src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: std::net::IpAddr::V4(src_ip),
            dst_ip: std::net::IpAddr::V4(dst_ip),
            src_port,
            dst_port,
        };
        let flow = SessionFlow {
            src_ip: std::net::IpAddr::V4(src_ip),
            dst_ip: std::net::IpAddr::V4(dst_ip),
            forward_key: key,
        };
        (frame, meta, flow)
    }

    #[test]
    fn syn_cookie_reply_budget_preserves_tx_batch_reserve() {
        let limit = SYN_COOKIE_REPLY_PENDING_RESERVE * 2;

        assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
            0,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            0,
        )));
        assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
            limit,
            SYN_COOKIE_REPLY_PENDING_RESERVE,
            0,
        )));
        assert!(syn_cookie_reply_budget_available(&tx_pipeline(
            limit,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            SYN_COOKIE_REPLY_PENDING_RESERVE - 1,
        )));
        assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
            limit,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            SYN_COOKIE_REPLY_PENDING_RESERVE,
        )));
    }

    #[test]
    fn syn_cookie_reply_enqueues_host_generated_frame_without_transit_policy_metadata() {
        let (frame, meta, flow) = tcp_v4_syn_frame();
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            0,
        );
        let mut counters = BatchCounters::default();

        assert!(enqueue_syn_cookie_reply(
            &mut pipeline,
            5,
            &frame,
            meta,
            Some(&flow),
            SynCookieReply::SynAck(SynCookieChallenge {
                cookie_isn: 0xaabb_ccdd,
                peer_mss: 1460,
            }),
            &mut counters,
        ));

        let req = pipeline
            .pending_tx_local
            .pop_front()
            .expect("SYN-cookie reply request");
        assert_eq!(req.egress_ifindex, 5);
        assert_eq!(req.cos_queue_id, None);
        assert_eq!(req.dscp_rewrite, None);
        assert!(!req.mirror_clone);
        assert_eq!(req.flow_key, Some(flow.forward_key));
        assert_eq!(counters.syn_cookie_syn_ack_sent, 1);
        assert_eq!(counters.syn_cookie_reply_budget_drops, 0);
    }
}
