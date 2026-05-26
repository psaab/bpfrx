// #1327 Step 1: stage_flow_cache_hit extracted from the inline body
// of poll_binding_process_descriptor (formerly lines 563-894 of the
// flat poll_descriptor.rs). The flow-cache fast path is the single
// largest self-contained `continue`-terminated block in the function
// and the only stage that's cleanly liftable without touching the
// order-coupled stage-12+ slow path. See
// docs/pr/1327-poll-descriptor-stages/plan.md for the architectural
// verdict on remaining stages.
//
// HOT PATH discipline:
//   - `#[inline(always)]` mandated by the plan (and by Codex
//     round-2 review). The 280-LOC body has a single call site;
//     LLVM produces the same IR as the original inline code. The
//     `cargo asm` spot-check in the test plan confirms no `call`
//     edge to this helper is emitted in optimised builds.
//   - Zero new per-packet allocations: every `cached_*` binding
//     is a borrow into the existing flow-cache Cache entry, never
//     a clone. The two heap interactions in the body are the
//     existing `owned_packet_frame.take()` and the
//     `PendingForwardRequest` build — both pre-existing.
//   - All `scratch_recycle.push` and `scratch_forwards.push`
//     sites run inside this helper. On `FlowCacheOutcome::Consumed`
//     the caller MUST `continue` without touching `desc.addr`
//     again.
//
// Recycle-exit map (verbatim translation of the original 3
// `continue` sites in the source):
//   - Drop path (cached descriptor `.drop` or policer `.drop`):
//     `scratch_recycle.push(desc.addr)` then `return Consumed`.
//   - TTL/hop-limit exceeded → local ICMP TE: `scratch_forwards.push(request)`
//     then `return Consumed` (frame returned via pending_fill_frames
//     later; MUST NOT recycle now — matches the original comment
//     at the line-653 site).
//   - Final fall-out: conditional `scratch_recycle.push(desc.addr)`
//     based on helper-local `recycle_now`, then `return Consumed`.

use std::sync::Arc;

use super::worker::{WorkerFlowCacheState, WorkerScratch, WorkerTxCounters, WorkerTxPipeline};
use super::*;

/// Outcome of the flow-cache fast-path stage.
///
/// The helper owns `desc.addr` disposition on `Consumed` — the
/// caller must `continue` without touching the descriptor.
///
/// On `FallThrough`, the helper performed no terminal side effect
/// (it may have invalidated a stale cache slot, but it did not
/// push to `scratch_recycle` or `scratch_forwards`); the caller
/// continues to the slow-path session resolution code with
/// `owned_packet_frame` and the descriptor untouched.
pub(super) enum FlowCacheOutcome {
    /// Cache hit. Helper performed any necessary
    /// `scratch_recycle.push` / `scratch_forwards.push`. Caller
    /// MUST `continue` without touching `desc.addr` again.
    Consumed,
    /// Cache miss or HA-invalid cached slot. Caller falls through
    /// to slow-path session resolution.
    FallThrough,
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_flow_cache_hit(
    flow_state: &mut WorkerFlowCacheState,
    tx_pipeline: &mut WorkerTxPipeline,
    tx_counters: &mut WorkerTxCounters,
    scratch: &mut WorkerScratch,
    mirror_sample_counter: &mut u64,
    live: &Arc<BindingLiveState>,
    binding_slot: u32,
    binding_index: usize,
    desc: XdpDesc,
    area: *const MmapArea,
    raw_frame: &[u8],
    owned_packet_frame: &mut Option<Vec<u8>>,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    packet_fabric_ingress: bool,
    validation: ValidationState,
    sessions: &mut SessionTable,
    now_ns: u64,
    now_secs: u64,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) -> FlowCacheOutcome {
    // Re-derive packet_frame locally (matches L477 of the caller's
    // pre-flow-cache code). The shared borrow lives only inside
    // this helper; NLL releases it before the take() at the
    // fallback-forward branch.
    let packet_frame: &[u8] = owned_packet_frame.as_deref().unwrap_or(raw_frame);

    if let Some(cached) = flow_state.flow_cache.lookup_counted(
        &flow.forward_key,
        FlowCacheLookup::for_packet(meta, validation),
        now_secs,
        &worker_ctx.rg_epochs,
        meta.pkt_len,
    ) {
        if !cached_flow_decision_valid(
            worker_ctx.forwarding,
            worker_ctx.ha_state,
            worker_ctx.dynamic_neighbors,
            now_secs,
            cached.stamp.owner_rg_id,
            packet_fabric_ingress,
            resolution_target_for_session(flow, cached.decision),
            cached.decision.resolution,
        ) {
            flow_state
                .flow_cache
                .invalidate_slot(&flow.forward_key, meta.ingress_ifindex as i32);
            // Fall through to slow path for full HA resolution → fabric redirect.
            return FlowCacheOutcome::FallThrough;
        }
        let cached_decision = cached.decision;
        let cached_descriptor = &cached.descriptor;
        let cached_metadata = &cached.metadata;
        if let Some(counter) = cached_descriptor.tx_selection.filter_counter.as_ref() {
            crate::filter::record_filter_counter(counter, meta.pkt_len as u64);
        }
        let policer_action = crate::filter::apply_cached_three_color_policers(
            &cached_descriptor.tx_selection.three_color_policers,
            now_ns,
            meta.pkt_len as u64,
        );
        emit_cached_input_filter_log(
            worker_ctx.event_stream,
            flow,
            meta,
            cached_descriptor,
            now_ns,
        );
        emit_cached_output_filter_log(
            worker_ctx.forwarding,
            worker_ctx.event_stream,
            flow,
            meta,
            cached_decision,
            cached_descriptor,
            cached_metadata,
            now_ns,
        );
        if cached_descriptor.tx_selection.drop || policer_action.drop {
            scratch.scratch_recycle.push(desc.addr);
            return FlowCacheOutcome::Consumed;
        }
        let cached_queue_id = cached_descriptor.tx_selection.queue_id;
        let cached_dscp_rewrite = policer_action
            .dscp_rewrite
            .or(cached_descriptor.tx_selection.dscp_rewrite);
        // Amortize session timestamp touch — every 64 cache hits.
        flow_state.flow_cache_session_touch += 1;
        if flow_state.flow_cache_session_touch & 63 == 0 {
            sessions.touch(&flow.forward_key, now_ns);
        }
        let mut recycle_now = true;
        if matches!(
            cached_decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        ) {
            // TTL/hop-limit check on flow cache hit path:
            // generate ICMP Time Exceeded for packets that
            // would expire after decrement.
            // #1145: reuse the line-50 raw_frame bind
            // instead of re-slicing for the same packet.
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
                scratch.scratch_forwards.push(request);
                // Don't recycle here — enqueue_pending_forwards
                // returns the frame via pending_fill_frames
                // when processing the prebuilt TE response.
                return FlowCacheOutcome::Consumed;
            }
            telemetry.counters.forward_candidate_packets += 1;
            if cached_decision.nat.rewrite_src.is_some() {
                telemetry.counters.snat_packets += 1;
            }
            if cached_decision.nat.rewrite_dst.is_some() {
                telemetry.counters.dnat_packets += 1;
            }
            // ── Inline in-place rewrite fast path ──
            // Skip PendingForwardRequest + enqueue_pending_forwards entirely.
            // Resolve target binding, rewrite frame in UMEM, push PreparedTxRequest.
            let target_ifindex = if cached_decision.resolution.tx_ifindex > 0 {
                cached_decision.resolution.tx_ifindex
            } else {
                resolve_tx_binding_ifindex(
                    worker_ctx.forwarding,
                    cached_decision.resolution.egress_ifindex,
                )
            };
            let expected_ports = authoritative_forward_ports(packet_frame, meta, Some(flow));
            let target_bi = cached_descriptor.target_binding_index.or_else(|| {
                if cached_decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                    worker_ctx.binding_lookup.fabric_target_index(
                        target_ifindex,
                        fabric_queue_hash(Some(flow), expected_ports, meta),
                    )
                } else {
                    worker_ctx.binding_lookup.target_index(
                        binding_index,
                        worker_ctx.ident.ifindex,
                        worker_ctx.ident.queue_id,
                        target_ifindex,
                    )
                }
            });
            // Check if target is same binding (hairpin) or same-UMEM.
            // For simplicity, only do in-place fast path when target == self.
            let is_self_target = target_bi == Some(binding_index);
            if is_self_target && owned_packet_frame.is_none() {
                let ingress_slot = binding_slot;
                let flow_key = flow.forward_key.clone();
                let mirror_config = resolve_mirror_config(
                    worker_ctx.forwarding,
                    meta.ingress_ifindex as i32,
                    meta.ingress_vlan_id,
                );
                let mut mirror_next_counter = None;
                let mut mirror_admission = mirror_config.and_then(|config| {
                    let admission = admit_mirror_clone_to_live(
                        worker_ctx.mirror_targets,
                        resolve_tx_binding_ifindex(
                            worker_ctx.forwarding,
                            config.output_ifindex,
                        ),
                        worker_ctx.ident.queue_id,
                        packet_frame.len(),
                    );
                    match admission {
                        Ok(admission) => {
                            let mut next_counter = *mirror_sample_counter;
                            if mirror_sample_allows(config.rate, &mut next_counter) {
                                mirror_next_counter = Some(next_counter);
                                Some((config, Ok(admission)))
                            } else {
                                mirror_next_counter = Some(next_counter);
                                None
                            }
                        }
                        Err(result) => Some((config, Err(result))),
                    }
                });
                let mirror_frame_len = packet_frame.len();
                let mut mirror_frame = mirror_admission
                    .as_ref()
                    .and_then(|(_, admission)| admission.as_ref().ok())
                    .map(|_| packet_frame.to_vec());
                // Try descriptor-based straight-line rewrite first (no branches
                // for AF, NAT type, or checksum recomputation). Falls back to
                // generic rewrite on port mismatch, NAT64, or NPTv6.
                let rewrite_result = apply_rewrite_descriptor(
                    unsafe { &*area },
                    desc,
                    meta,
                    &cached_descriptor,
                    expected_ports,
                )
                .or_else(|| {
                    rewrite_forwarded_frame_in_place(
                        unsafe { &*area },
                        desc,
                        meta,
                        &cached_decision,
                        cached_descriptor.apply_nat_on_fabric,
                        expected_ports,
                    )
                });
                if let Some(rewrite_result) = rewrite_result {
                    if let Some(next_counter) = mirror_next_counter {
                        *mirror_sample_counter = next_counter;
                    }
                    if let Some((mirror_config, admission)) = mirror_admission.take() {
                        let result = match admission {
                            Ok(admission) => {
                                if let Some(mirror_frame) = mirror_frame.take() {
                                    let cos_queue_id = mirror_cos_queue_id(
                                        worker_ctx.forwarding,
                                        mirror_config.output_ifindex,
                                        meta.into(),
                                        Some(&flow_key),
                                    );
                                    enqueue_admitted_mirror_clone_to_live(
                                        admission,
                                        mirror_config,
                                        mirror_frame,
                                        meta.into(),
                                        Some(&flow_key),
                                        cos_queue_id,
                                    )
                                } else {
                                    MirrorCloneResult::NoFrame
                                }
                            }
                            Err(result) => result,
                        };
                        record_mirror_clone_result(live, result, mirror_frame_len);
                    }
                    tx_pipeline.pending_tx_prepared.push_back(PreparedTxRequest {
                        offset: rewrite_result.offset,
                        len: rewrite_result.len,
                        recycle: PreparedTxRecycle::fill_on_slot(
                            ingress_slot,
                            rewrite_result.offset,
                            desc.addr,
                        ),
                        expected_ports,
                        expected_addr_family: meta.addr_family,
                        expected_protocol: meta.protocol,
                        flow_key: Some(flow_key),
                        egress_ifindex: cached_decision.resolution.egress_ifindex,
                        cos_queue_id: cached_queue_id,
                        dscp_rewrite: cached_dscp_rewrite,
                        mirror_clone: false,
                    });
                    tx_counters.pending_in_place_tx_packets += 1;
                    tx_counters.record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
                    telemetry.dbg.forward += 1;
                    telemetry.dbg.tx += 1;
                    recycle_now = false;
                }
            }
            // Fallback: use PendingForwardRequest path for cross-binding or failure.
            if recycle_now {
                let cached_precomputed_tx_selection = CachedTxSelectionDescriptor {
                    queue_id: cached_queue_id,
                    dscp_rewrite: cached_dscp_rewrite,
                    drop: cached_descriptor.tx_selection.drop,
                    ..CachedTxSelectionDescriptor::default()
                };
                if let Some(mut request) = build_live_forward_request_from_frame(
                    worker_ctx.binding_lookup,
                    binding_index,
                    worker_ctx.ident,
                    desc,
                    packet_frame,
                    meta,
                    &cached_decision,
                    worker_ctx.forwarding,
                    Some(flow),
                    Some(cached_metadata.ingress_zone),
                    cached_descriptor.apply_nat_on_fabric,
                    now_ns,
                    worker_ctx.event_stream,
                    Some(PendingForwardHints {
                        expected_ports,
                        target_binding_index: target_bi,
                    }),
                    Some(&cached_precomputed_tx_selection),
                ) {
                    request.frame = owned_packet_frame
                        .take()
                        .map(PendingForwardFrame::Owned)
                        .unwrap_or(PendingForwardFrame::Live);
                    telemetry.dbg.forward += 1;
                    telemetry.dbg.tx += 1;
                    scratch.scratch_forwards.push(request);
                    recycle_now = false;
                }
            }
        }
        if recycle_now {
            scratch.scratch_recycle.push(desc.addr);
        }
        return FlowCacheOutcome::Consumed;
    }
    FlowCacheOutcome::FallThrough
}
