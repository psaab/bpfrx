// Dispatch module (#1443). Pure code-motion split of the original
// 1474-LOC `dispatch.rs` into cohesive submodules:
//
// - `cos`             — Phase 1 (CoS TX-selection resolve) +
//                       the COS fast-path helpers
//                       (cos_queue_fast_path_for_request,
//                        cos_owner_live_for_request,
//                        request_runs_under_shared_exact_policy,
//                        enqueue_local_request_to_target_or_owner).
// - `shared_recycle`  — Phase 10 + cross-tick recycle routing
//                       (apply_shared_recycles*,
//                        resolve_tx_binding_ifindex,
//                        and the slot-resolution helpers).
// - `slow_path`       — handle_forward_build_failure,
//                       maybe_reinject_slow_path*,
//                       extract_l3_packet* family. All marked
//                       #[cold] #[inline(never)] per AGY round-2
//                       finding D.
//
// The orchestrator (`enqueue_pending_forwards`) and Phase 8
// (try_inplace_rewrite_or_build) intentionally stay in `mod.rs` for
// this PR — Phase 8 body extraction is deferred to a follow-up so
// reviewers can compare the in-tree control flow against current
// master without a body-shape diff. See plan.md §"Out of scope".
//
// External callers reach the re-exported symbols via the
// `use self::tx::dispatch::*;` glob at `afxdp/mod.rs:140`. The
// re-export block below preserves every `pub(in crate::afxdp)`
// symbol verbatim.

use super::*;

use super::tcp_segmentation::segment_forwarded_tcp_frames_into_prepared;

mod cos;
mod shared_recycle;
mod slow_path;

use cos::{
    cos_owner_live_for_request, enqueue_local_request_to_target_or_owner,
    pending_forward_needs_cos_tx_selection, request_runs_under_shared_exact_policy,
    resolve_pending_forward_cos_tx_selection,
};
pub(in crate::afxdp) use shared_recycle::{
    apply_shared_recycles, apply_shared_recycles_to_bindings, resolve_tx_binding_ifindex,
};
// Test-only access to internal shared_recycle helpers from
// dispatch_tests.rs (which is `mod tests` under this `mod.rs`).
#[cfg(test)]
use shared_recycle::{
    record_shared_recycle_unknown_slot_drops, shared_recycle_target_index,
    shared_recycle_target_index_for_split,
};
pub(in crate::afxdp) use slow_path::{
    extract_l3_packet_with_nat, handle_forward_build_failure, maybe_reinject_slow_path,
    maybe_reinject_slow_path_from_frame,
};
// pub(in crate::afxdp::tx) was previously pub(super) on the
// extract_l3_packet[_from_frame] family; the re-export keeps the
// pre-split sibling-tx/ visibility verbatim.
pub(in crate::afxdp::tx) use slow_path::{extract_l3_packet, extract_l3_packet_from_frame};

// #2208: test-only fault injection for the oversized-frame control flow.
// A built copy-path frame larger than `tx_frame_capacity()` (4096) cannot
// be produced from a single in-UMEM ingress frame in a unit test (the
// frame itself is capped at one UMEM frame), so this thread-local lets the
// dispatch tests force the oversized branch to prove it recycles the
// ingress descriptor (the pre-fix bare `continue;` leaked it). It is
// `#[cfg(test)]` only and DCEs out of release builds — the hot path keeps
// the bare `cp_len > tx_frame_capacity()` comparison with zero added cost.
#[cfg(test)]
thread_local! {
    static FORCE_OVERSIZED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[inline(always)]
fn copy_frame_is_oversized(cp_len: usize) -> bool {
    #[cfg(test)]
    if FORCE_OVERSIZED.with(|c| c.get()) {
        return true;
    }
    cp_len > tx_frame_capacity()
}

#[inline]
fn recycle_ingress_frame(ingress_binding: &mut BindingWorker, source_offset: u64, now_ns: u64) {
    ingress_binding
        .tx_pipeline
        .pending_fill_frames
        .push_back(source_offset);
    if ingress_binding.tx_pipeline.pending_fill_frames.len() >= FILL_BATCH_SIZE {
        let _ = drain_pending_fill(ingress_binding, now_ns);
    }
}

pub(in crate::afxdp) fn enqueue_pending_forwards(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    post_recycles: &mut Vec<(u32, u64)>,
    now_ns: u64,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    ingress_live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    counters: &mut BatchCounters,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) {
    if pending_forwards.is_empty() {
        return;
    }
    let ingress_area = ingress_binding.umem.area() as *const MmapArea;
    let tx_selection_enabled_v4 = forwarding.tx_selection_enabled_v4;
    let tx_selection_enabled_v6 = forwarding.tx_selection_enabled_v6;
    post_recycles.clear();
    // Walk the scratch vector in place. Moving large PendingForwardRequest
    // values through the iterator path was still forcing per-request memcpy
    // traffic before any forwarding work started.
    for request in pending_forwards.iter_mut() {
        let source_offset = request.desc.addr;
        let ingress_slot = ingress_binding.slot;
        if pending_forward_needs_cos_tx_selection(
            request,
            tx_selection_enabled_v4,
            tx_selection_enabled_v6,
        ) {
            let cos = resolve_pending_forward_cos_tx_selection(forwarding, &request, now_ns);
            if cos.drop {
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            }
            request.cos_queue_id = cos.queue_id;
            request.dscp_rewrite = cos.dscp_rewrite;
            request.cos_tx_selection_resolved = true;
        }
        let target_binding_index = request.target_binding_index.or_else(|| {
            binding_lookup.target_index(
                ingress_index,
                ingress_binding.ifindex,
                request.ingress_queue_id,
                request.target_ifindex,
            )
        });

        // Fast path: prebuilt frame (e.g. ICMP error NAT reversal).
        // The frame is already fully rewritten — just enqueue for TX.
        if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
            // #1946: a Prebuilt frame (e.g. an embedded-ICMP NAT-reversed
            // error) can carry a FabricRedirect resolution
            // (`finalize_embedded_icmp_resolution`). When that frame is
            // unsendable to the peer — no fabric XSK binding, or the
            // local enqueue fails — drop it fail-closed AND count it on
            // `fabric_redirect_unsendable_drops`, the same observability
            // invariant as the desc-frame no-binding / build-failure
            // paths. (Non-FabricRedirect Prebuilt drops keep their prior
            // silent recycle+continue.)
            let prebuilt_is_fabric_redirect = request.decision.resolution.disposition
                == ForwardingDisposition::FabricRedirect;
            let Some(target_binding) = resolve_pending_forward_target_binding(
                left,
                ingress_index,
                ingress_binding,
                request.ingress_queue_id,
                right,
                binding_lookup,
                target_binding_index,
                request.target_ifindex,
            ) else {
                if prebuilt_is_fabric_redirect {
                    ingress_live
                        .fabric_redirect_unsendable_drops
                        .fetch_add(1, Ordering::Relaxed);
                    record_exception(
                        recent_exceptions,
                        ingress_ident,
                        "fabric_redirect_no_binding",
                        request.desc.len,
                        Some(request.meta.into()),
                        None,
                        forwarding,
                    );
                }
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            };
            let frame_len = prebuilt.len();
            let req = TxRequest {
                bytes: core::mem::take(prebuilt),
                expected_ports: None,
                expected_addr_family: request.meta.addr_family,
                expected_protocol: request.meta.protocol,
                flow_key: request.flow_key.clone(),
                egress_ifindex: request.decision.resolution.egress_ifindex,
                cos_queue_id: request.cos_queue_id,
                dscp_rewrite: request.dscp_rewrite,
                mirror_clone: false,
                enqueue_ns: 0,
            };
            if enqueue_local_request_to_target_or_owner(target_binding, req).is_err() {
                if prebuilt_is_fabric_redirect {
                    ingress_live
                        .fabric_redirect_unsendable_drops
                        .fetch_add(1, Ordering::Relaxed);
                    record_exception(
                        recent_exceptions,
                        ingress_ident,
                        "fabric_redirect_build_failed",
                        request.desc.len,
                        Some(request.meta.into()),
                        None,
                        forwarding,
                    );
                }
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            }
            dbg.enqueue_ok += 1;
            dbg.enqueue_copy += 1;
            target_binding.tx_counters.pending_copy_tx_packets += 1;
            dbg.tx_bytes_total += frame_len as u64;
            if (frame_len as u32) > dbg.tx_max_frame {
                dbg.tx_max_frame = frame_len as u32;
            }
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            continue;
        }

        // Read source frame directly from ingress UMEM — no heap copy needed.
        // The frame is safe to read: RX ring released but frame not yet returned
        // to fill ring (that happens after this function completes).
        let source_frame = match &request.frame {
            PendingForwardFrame::Owned(frame) => frame.as_slice(),
            PendingForwardFrame::Live => {
                if let Some(frame) = (unsafe { &*ingress_area })
                    .slice(request.desc.addr as usize, request.desc.len as usize)
                {
                    frame
                } else {
                    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                    continue;
                }
            }
            PendingForwardFrame::Prebuilt(_) => unreachable!(),
        };
        if let Some(result) = enqueue_sampled_mirror_clone(
            left,
            ingress_index,
            ingress_binding,
            right,
            binding_lookup,
            mirror_targets,
            forwarding,
            request.meta.ingress_ifindex as i32,
            request.meta.ingress_vlan_id,
            request.ingress_queue_id,
            source_frame,
            request.meta,
            request.flow_key.as_ref(),
        ) {
            record_mirror_clone_result(&ingress_binding.live, result, source_frame.len());
        }
        let expected_ports = request.expected_ports;
        let ingress_umem_ptr = ingress_binding.umem.allocation_ptr();
        let Some(target_binding) = resolve_pending_forward_target_binding(
            left,
            ingress_index,
            ingress_binding,
            request.ingress_queue_id,
            right,
            binding_lookup,
            target_binding_index,
            request.target_ifindex,
        ) else {
            // No XSK binding for the target interface.  Normally fabric
            // parents have bindings; this is a safety-net fallback in case
            // the binding is not yet ready or bind() failed.
            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                // #1946: a FabricRedirect with no XSK binding on the
                // fabric parent is a rare safety net (bind not ready /
                // bind() failed). The frame is a cross-chassis L2 redirect
                // destined for the peer's pipeline, NOT a kernel-FIB-
                // routable packet — reinjecting it to the local kernel
                // slow path is a wrong-path / conntrack-poison hazard (the
                // pre-#1946 PendingForwardFrame::Owned branch did exactly
                // that, while the Live branch was silently dropped by the
                // filtered maybe_reinject_slow_path wrapper). Drop BOTH
                // frame kinds identically, fail-closed, and count (cf. the
                // #1873 R-C tunnel_encap_unresolved_drops gate). We touch
                // neither frame, so the Owned (GRE-decapped copy) vs Live
                // (raw in-UMEM) representation difference is irrelevant.
                ingress_live
                    .fabric_redirect_unsendable_drops
                    .fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    ingress_ident,
                    "fabric_redirect_no_binding",
                    request.desc.len,
                    Some(request.meta.into()),
                    None,
                    forwarding,
                );
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            }
            dbg.no_egress_binding += 1;
            if cfg!(feature = "debug-log") && dbg.no_egress_binding <= 3 {
                debug_log!(
                    "DBG NO_EGRESS_BINDING: target_ifindex={} ingress_if={} ingress_q={}",
                    request.target_ifindex,
                    ingress_ident.ifindex,
                    request.ingress_queue_id,
                );
            }
            record_exception(
                recent_exceptions,
                ingress_ident,
                "missing_egress_binding",
                request.desc.len,
                None,
                None,
                forwarding,
            );
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            continue;
        };
        let mut build_failed = false;
        let mut fallback_to_slow_path = false;
        let mut copied_source_frame = false;
        let mut retained_source_frame = false;
        // #2301: a locally-generated ICMP Frag-Needed / Packet-Too-Big to
        // send back out the ingress interface when the forwarded frame
        // exceeds the egress MTU and the TCP-segmentation path did not
        // handle it. Built inside the `target_binding` borrow (it needs
        // only `source_frame`/`meta`/`ingress_ident`/`forwarding`) and
        // enqueued onto `ingress_binding` in the finalizer once that
        // borrow ends. `mtu_signalled` suppresses the oversized build.
        let mut ptb_reply: Option<Vec<u8>> = None;
        let mut mtu_signalled = false;
        let mut flow_key = request.flow_key.take();
        {
            let tcp_segmentation_needed = forwarded_tcp_may_need_segmentation(
                source_frame,
                request.meta,
                &request.decision,
                forwarding,
            );
            if tcp_segmentation_needed {
                if let Some((segments, bytes, max_frame)) =
                    segment_forwarded_tcp_frames_into_prepared(
                        target_binding,
                        source_frame,
                        request.meta,
                        &request.decision,
                        forwarding,
                        request.apply_nat_on_fabric,
                        expected_ports,
                        flow_key.clone(),
                        request.cos_queue_id,
                        request.dscp_rewrite,
                        now_ns,
                        post_recycles,
                        worker_id,
                        worker_commands_by_id,
                    )
                {
                    dbg.enqueue_ok += segments as u64;
                    dbg.enqueue_direct += segments as u64;
                    target_binding.tx_counters.pending_direct_tx_packets += segments as u64;
                    dbg.tx_bytes_total += bytes;
                    if max_frame > dbg.tx_max_frame {
                        dbg.tx_max_frame = max_frame;
                    }
                    copied_source_frame = true;
                    if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                        );
                    }
                } else if let Some(segmented) = segment_forwarded_tcp_frames_from_frame(
                    source_frame,
                    request.meta,
                    &request.decision,
                    forwarding,
                    request.apply_nat_on_fabric,
                    expected_ports,
                ) {
                    for frame in segmented {
                        if cfg!(feature = "debug-log") {
                            if let Some(reason) = forward_tuple_mismatch_reason(
                                live_frame_ports_from_meta_bytes(source_frame, request.meta),
                                expected_ports,
                                live_frame_ports_bytes(
                                    &frame,
                                    request.meta.addr_family,
                                    request.meta.protocol,
                                ),
                            ) {
                                record_exception(
                                    recent_exceptions,
                                    ingress_ident,
                                    &reason,
                                    frame.len() as u32,
                                    Some(request.meta.into()),
                                    None,
                                    forwarding,
                                );
                                build_failed = true;
                                break;
                            }
                        }
                        let seg_frame_len = frame.len();
                        target_binding
                            .tx_pipeline
                            .pending_tx_local
                            .push_back(TxRequest {
                                bytes: frame,
                                expected_ports,
                                expected_addr_family: request.meta.addr_family,
                                expected_protocol: request.meta.protocol,
                                flow_key: flow_key.clone(),
                                egress_ifindex: request.decision.resolution.egress_ifindex,
                                cos_queue_id: request.cos_queue_id,
                                dscp_rewrite: request.dscp_rewrite,
                                mirror_clone: false,
                                enqueue_ns: 0,
                            });
                        bound_pending_tx_local(target_binding);
                        dbg.enqueue_ok += 1;
                        dbg.enqueue_copy += 1;
                        target_binding.tx_counters.pending_copy_tx_packets += 1;
                        dbg.tx_bytes_total += seg_frame_len as u64;
                        if (seg_frame_len as u32) > dbg.tx_max_frame {
                            dbg.tx_max_frame = seg_frame_len as u32;
                        }
                    }
                    copied_source_frame = true;
                    if target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                        );
                    }
                }
            }
            // Track when segmentation was needed but both builders returned None.
            if count_forwarded_tcp_segmentation_miss_if_needed(
                dbg,
                copied_source_frame,
                tcp_segmentation_needed,
            ) {
                thread_local! {
                    static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                SEG_MISS_LOG.with(|cap| {
                    record_forwarded_tcp_segmentation_miss(
                        cap,
                        recent_exceptions,
                        ingress_ident,
                        source_frame,
                        request,
                        forwarding,
                    );
                });
            }
            if !copied_source_frame {
                // NAT64: header size changes prevent in-place rewrite.
                // Always use copy path with NAT64-specific frame builder.
                let is_nat64 = request.decision.nat.nat64;
                let uses_native_tunnel = request.decision.resolution.tunnel_endpoint_id != 0;

                // #2301 + #2330: the PMTUD decision for forwarded frames the
                // TCP segmentation path did not handle (non-TCP, TCP
                // seg-miss, non-segmentable TCP).
                //
                // #2301 handled ONLY plain forwards (size-preserving), where
                // the egress MTU compared against the SOURCE frame is exact.
                // #2330 closes the gap for the size-CHANGING paths (NAT64,
                // native GRE, WireGuard): there the on-wire frame grows
                // (encap) or its header shrinks/grows (NAT64), so a
                // source-frame-vs-egress comparison is wrong. Instead we
                // derive the INNER-source MTU (the largest inner IP packet
                // whose TRANSFORMED frame fits the egress/transport MTU) from
                // the #2300/#2331 SSOT helpers (`native_gre_inner_mtu` /
                // `wg::mss::wg_inner_mtu` / the NAT64 v6<->v4 header delta)
                // and compare the SAME inner `source_frame` against THAT.
                //
                // In all three transformed cases `source_frame` IS the
                // pre-encap / pre-translation inner packet and
                // `request.meta.addr_family` is the inner family, so the
                // existing `build_frag_needed_v4` / `build_packet_too_big_v6`
                // builders already target the correct inner source — they
                // just carry the inner MTU instead of the egress MTU. The
                // generated PTB then routes through `classify_generated_reply`
                // (#2328) at the finalizer below, exactly like the plain
                // path. When `mtu` is 0 (no MTU resolvable / unknown tunnel
                // kind) `forwarded_egress_mtu_decision` returns `Forward`
                // (fail-open) and the transformed frame falls through to its
                // normal build (and, for GRE/WG oversize, the #2331 encap
                // drop guard). This CLOSES the signal #2331 deferred here: an
                // oversized GRE/WG inner now yields a PTB instead of a silent
                // `GRE_ENCAP_DF_OVERSIZE_DROPS` / `encap_mtu_drops`.
                {
                    let egress_mtu = forwarded_egress_mtu(&request.decision, forwarding);
                    // #2845: derive the inner destination so the WG PTB picks
                    // the SAME peer (and thus the SAME underlay MTU) the encap
                    // path will. `source_frame` IS the pre-encap inner packet
                    // and `request.meta.addr_family` its family. Only the WG arm
                    // of `post_transform_inner_mtu` consumes this; cheap enough
                    // to always derive.
                    let inner_dst = frame_l3_offset(source_frame)
                        .or_else(|| match request.meta.l3_offset {
                            14 | 18 => Some(request.meta.l3_offset as usize),
                            _ => None,
                        })
                        .and_then(|l3| source_frame.get(l3..))
                        .and_then(|pkt| {
                            crate::afxdp::gre::inner_dst_ip(pkt, request.meta.addr_family)
                        });
                    let mtu = if is_nat64 || uses_native_tunnel {
                        post_transform_inner_mtu(
                            &request.decision,
                            forwarding,
                            is_nat64,
                            request.meta.addr_family,
                            egress_mtu,
                            inner_dst,
                        )
                    } else {
                        egress_mtu
                    };
                    let ptb_meta: UserspaceDpMeta = request.meta.into();
                    let l3 = frame_l3_offset(source_frame).or_else(|| {
                        match request.meta.l3_offset {
                            14 | 18 => Some(request.meta.l3_offset as usize),
                            _ => None,
                        }
                    });
                    if let Some(l3) = l3 {
                        if let EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } =
                            forwarded_egress_mtu_decision(
                                source_frame,
                                l3,
                                request.meta.addr_family,
                                mtu,
                            )
                        {
                            // RFC 792 / RFC 4443 suppression: never reply to
                            // a non-first fragment or an inbound ICMP error.
                            // #2472: AND a per-reason token-bucket rate limit —
                            // an oversized-DF / IPv6 flood would otherwise emit
                            // one PTB per trigger packet, unbounded (CPU/TX
                            // amplification + reflection). On bucket-empty the
                            // PTB is suppressed (the `PacketTooBig` rate-limited
                            // counter is bumped inside `allow_generated_error`);
                            // the oversized original is still dropped below
                            // (`mtu_signalled`), so this never falls through to
                            // forward the MTU-violating frame.
                            if !ptb_reply_suppressed(source_frame, ptb_meta, l3, forwarding)
                                && allow_generated_error(GeneratedErrorReason::PacketTooBig)
                            {
                                ptb_reply = match request.meta.addr_family as i32 {
                                    libc::AF_INET => build_frag_needed_v4(
                                        source_frame,
                                        ptb_meta,
                                        ingress_ident.ifindex,
                                        forwarding,
                                        next_hop_mtu,
                                    ),
                                    libc::AF_INET6 => build_packet_too_big_v6(
                                        source_frame,
                                        ptb_meta,
                                        ingress_ident.ifindex,
                                        forwarding,
                                        next_hop_mtu as u32,
                                    ),
                                    _ => None,
                                };
                            }
                            // Drop the oversized original regardless of
                            // whether the PTB could be built (a suppressed
                            // or unbuildable PTB must not fall through to
                            // forward the MTU-violating frame). `ptb_reply`
                            // being None here is the fail-closed silent drop.
                            mtu_signalled = true;
                            record_exception(
                                recent_exceptions,
                                ingress_ident,
                                "egress_mtu_exceeded",
                                source_frame.len() as u32,
                                Some(request.meta.into()),
                                None,
                                forwarding,
                            );
                        }
                    }
                }
                // Skip the oversized-frame build/forward entirely when an
                // egress-MTU PTB was signalled; the finalizer enqueues
                // `ptb_reply` (if any) and recycles the ingress descriptor.
                if !mtu_signalled {
                // #1598 secondary fix: gate on `shared_exact` policy
                // (not on `shared_queue_lease.is_some()`), see the
                // doc comment on `request_runs_under_shared_exact_policy`
                // in dispatch/cos.rs. Non-exact uncapped queues now
                // qualify for the local in-place rewrite path.
                let owner_matches_target = request_runs_under_shared_exact_policy(
                    &target_binding.cos.cos_fast_interfaces,
                    request.decision.resolution.egress_ifindex,
                    request.cos_queue_id,
                ) || cos_owner_live_for_request(
                    &target_binding.cos.cos_fast_interfaces,
                    request.decision.resolution.egress_ifindex,
                    request.cos_queue_id,
                )
                .as_ref()
                .is_none_or(|live| Arc::ptr_eq(live, &target_binding.live));

                /*
                 * In-place TX optimization: rewrite the ingress frame directly in UMEM
                 * and submit it to the target binding's TX ring without copying.
                 * This is valid whenever ingress and egress bindings share the same
                 * UMEM allocation. That includes same-binding hairpin and the narrow
                 * shared-UMEM groups.
                 */
                let can_rewrite_in_place = target_binding.umem.allocation_ptr() == ingress_umem_ptr
                    && !is_nat64
                    && !uses_native_tunnel
                    && owner_matches_target
                    && matches!(request.frame, PendingForwardFrame::Live);
                if can_rewrite_in_place {
                    match rewrite_forwarded_frame_in_place(
                        unsafe { &*ingress_area },
                        request.desc,
                        request.meta,
                        &request.decision,
                        request.apply_nat_on_fabric,
                        expected_ports,
                    ) {
                        Some(rewrite_result) => {
                            target_binding.tx_pipeline.pending_tx_prepared.push_back(
                                PreparedTxRequest {
                                    offset: rewrite_result.offset,
                                    len: rewrite_result.len,
                                    recycle: PreparedTxRecycle::fill_on_slot(
                                        ingress_slot,
                                        rewrite_result.offset,
                                        source_offset,
                                    ),
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                    mirror_clone: false,
                                    enqueue_ns: 0,
                                },
                            );
                            bound_pending_tx_prepared(target_binding, Some(post_recycles));
                            target_binding.tx_counters.pending_in_place_tx_packets += 1;
                            target_binding
                                .tx_counters
                                .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
                            dbg.enqueue_ok += 1;
                            dbg.enqueue_inplace += 1;
                            dbg.tx_bytes_total += rewrite_result.len as u64;
                            if rewrite_result.len > dbg.tx_max_frame {
                                dbg.tx_max_frame = rewrite_result.len;
                            }
                            retained_source_frame = true;
                        }
                        None => match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
                                forwarding.nat64.no_v6_frag_header,
                            )
                        } else {
                            build_forwarded_frame_from_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                request.apply_nat_on_fabric,
                                expected_ports,
                            )
                        } {
                            Some(frame) => {
                                if cfg!(feature = "debug-log") {
                                    if let Some(reason) = forward_tuple_mismatch_reason(
                                        live_frame_ports_from_meta_bytes(
                                            source_frame,
                                            request.meta,
                                        ),
                                        expected_ports,
                                        live_frame_ports_bytes(
                                            &frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                    ) {
                                        record_exception(
                                            recent_exceptions,
                                            ingress_ident,
                                            &reason,
                                            frame.len() as u32,
                                            Some(request.meta.into()),
                                            None,
                                            forwarding,
                                        );
                                        // Don't continue — the frame was built successfully,
                                        // forward it anyway. Mismatch is diagnostic only.
                                    }
                                }
                                let cp1_len = frame.len();
                                if copy_frame_is_oversized(cp1_len) {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp1_len as u32,
                                        Some(request.meta.into()),
                                        None,
                                        forwarding,
                                    );
                                    // #2208: an oversized built frame is
                                    // undeliverable. Fall through to the
                                    // finalizer so the ingress descriptor is
                                    // recycled to the fill ring (the bare
                                    // `continue;` here leaked it). Do NOT set
                                    // fallback_to_slow_path — reinjecting an
                                    // already-oversized frame to the kernel
                                    // slow path is pointless; matching the
                                    // direct-TX oversized branch above, we
                                    // drop-and-recycle.
                                    build_failed = true;
                                } else {
                                    let req = TxRequest {
                                        bytes: frame,
                                        expected_ports,
                                        expected_addr_family: request.meta.addr_family,
                                        expected_protocol: request.meta.protocol,
                                        flow_key: flow_key.take(),
                                        egress_ifindex: request.decision.resolution.egress_ifindex,
                                        cos_queue_id: request.cos_queue_id,
                                        dscp_rewrite: request.dscp_rewrite,
                                        mirror_clone: false,
                                        enqueue_ns: 0,
                                    };
                                    if enqueue_local_request_to_target_or_owner(target_binding, req)
                                        .is_err()
                                    {
                                        // #2208: a full cross-binding CoS-owner
                                        // queue (TX congestion) returns Err and
                                        // drops the TxRequest. Set the
                                        // build-failure flags and FALL THROUGH
                                        // to the finalizer — the old bare
                                        // `continue;` skipped both
                                        // handle_forward_build_failure (no
                                        // slow-path reinject, contradicting the
                                        // flags) AND recycle_ingress_frame
                                        // (leaking the ingress descriptor). The
                                        // finalizer reinjects from source_frame,
                                        // so the dropped req is irrelevant.
                                        build_failed = true;
                                        fallback_to_slow_path = true;
                                    } else {
                                        dbg.enqueue_ok += 1;
                                        dbg.enqueue_copy += 1;
                                        target_binding.tx_counters.pending_copy_tx_packets += 1;
                                        dbg.tx_bytes_total += cp1_len as u64;
                                        if (cp1_len as u32) > dbg.tx_max_frame {
                                            dbg.tx_max_frame = cp1_len as u32;
                                        }
                                    }
                                }
                            }
                            None => {
                                build_failed = true;
                                fallback_to_slow_path = true;
                            }
                        },
                    }
                } else {
                    enum DirectTxFallbackReason {
                        NoFreeTxFrame,
                        BuildReturnedNone,
                        DisallowedByRewriteMode,
                    }
                    // Direct TX build: write the forwarded frame directly into
                    // the target binding's UMEM TX frame, eliminating the
                    // intermediate Vec allocation and one memcpy.
                    // NAT64 cannot use direct TX (header size changes), so
                    // it falls through to the copy path below.
                    let mut direct_tx_offset =
                        target_binding.tx_pipeline.free_tx_frames.pop_front();
                    if direct_tx_offset.is_none()
                        && (target_binding.tx_pipeline.outstanding_tx > 0
                            || !target_binding.tx_pipeline.pending_tx_prepared.is_empty()
                            || !target_binding.tx_pipeline.pending_tx_local.is_empty())
                    {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                        );
                        direct_tx_offset = target_binding.tx_pipeline.free_tx_frames.pop_front();
                    }
                    let mut direct_tx_fallback_reason = None;
                    let direct_built = if is_nat64 || uses_native_tunnel {
                        // NAT64 can't use direct TX — return the frame if we popped one.
                        if let Some(off) = direct_tx_offset {
                            target_binding.tx_pipeline.free_tx_frames.push_front(off);
                        }
                        direct_tx_fallback_reason =
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
                        false
                    } else if !owner_matches_target {
                        if let Some(off) = direct_tx_offset {
                            target_binding.tx_pipeline.free_tx_frames.push_front(off);
                        }
                        // A prepared/direct frame on a non-owner binding would be
                        // cloned back into a local Vec during CoS owner redirection.
                        // Skip that waste and fall back to the single-copy local path.
                        direct_tx_fallback_reason =
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
                        false
                    } else if let Some(tx_offset) = direct_tx_offset {
                        let target_area = target_binding.umem.area();
                        // Prefetch target frame to warm cache before copy.
                        #[cfg(target_arch = "x86_64")]
                        if let Some(pf) = target_area.slice(tx_offset as usize, 64) {
                            unsafe {
                                core::arch::x86_64::_mm_prefetch(
                                    pf.as_ptr() as *const i8,
                                    core::arch::x86_64::_MM_HINT_T0,
                                );
                            }
                        }
                        let written = unsafe {
                            target_area.slice_mut_unchecked(tx_offset as usize, tx_frame_capacity())
                        }
                        .and_then(|out| {
                            build_forwarded_frame_into_from_frame(
                                out,
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                request.apply_nat_on_fabric,
                                expected_ports,
                            )
                        });
                        if let Some(written) = written {
                            // Debug-only: validate built frame ports match expected.
                            // enforce_expected_ports() in build_forwarded_frame_into_from_frame
                            // already ensures correctness; this catches builder bugs.
                            if cfg!(feature = "debug-log") {
                                let built_ports = unsafe {
                                    target_area.slice_mut_unchecked(tx_offset as usize, written)
                                }
                                .and_then(|f| {
                                    live_frame_ports_bytes(
                                        f,
                                        request.meta.addr_family,
                                        request.meta.protocol,
                                    )
                                });
                                if let Some(reason) = forward_tuple_mismatch_reason(
                                    live_frame_ports_from_meta_bytes(source_frame, request.meta),
                                    expected_ports,
                                    built_ports,
                                ) {
                                    target_binding
                                        .tx_pipeline
                                        .free_tx_frames
                                        .push_front(tx_offset);
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        &reason,
                                        written as u32,
                                        Some(request.meta.into()),
                                        None,
                                        forwarding,
                                    );
                                    build_failed = true;
                                }
                            }
                            if build_failed {
                                target_binding
                                    .tx_pipeline
                                    .free_tx_frames
                                    .push_front(tx_offset);
                                true
                            } else if written > tx_frame_capacity() {
                                target_binding
                                    .tx_pipeline
                                    .free_tx_frames
                                    .push_front(tx_offset);
                                record_exception(
                                    recent_exceptions,
                                    ingress_ident,
                                    "oversized_forward_frame",
                                    written as u32,
                                    Some(request.meta.into()),
                                    None,
                                    forwarding,
                                );
                                true
                            } else {
                                target_binding.tx_pipeline.pending_tx_prepared.push_back(
                                    PreparedTxRequest {
                                        offset: tx_offset,
                                        len: written as u32,
                                        recycle: PreparedTxRecycle::FreeTxFrame,
                                        expected_ports,
                                        expected_addr_family: request.meta.addr_family,
                                        expected_protocol: request.meta.protocol,
                                        flow_key: flow_key.take(),
                                        egress_ifindex: request.decision.resolution.egress_ifindex,
                                        cos_queue_id: request.cos_queue_id,
                                        dscp_rewrite: request.dscp_rewrite,
                                        mirror_clone: false,
                                        enqueue_ns: 0,
                                    },
                                );
                                bound_pending_tx_prepared(target_binding, Some(post_recycles));
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_direct += 1;
                                target_binding.tx_counters.pending_direct_tx_packets += 1;
                                dbg.tx_bytes_total += written as u64;
                                if (written as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = written as u32;
                                }
                                true
                            }
                        } else {
                            target_binding
                                .tx_pipeline
                                .free_tx_frames
                                .push_front(tx_offset);
                            direct_tx_fallback_reason =
                                Some(DirectTxFallbackReason::BuildReturnedNone);
                            false
                        }
                    } else {
                        direct_tx_fallback_reason = Some(DirectTxFallbackReason::NoFreeTxFrame);
                        false
                    };
                    // Fallback: Vec copy path when direct build unavailable.
                    if !direct_built {
                        match direct_tx_fallback_reason {
                            Some(DirectTxFallbackReason::NoFreeTxFrame) => {
                                target_binding
                                    .tx_counters
                                    .pending_direct_tx_no_frame_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::BuildReturnedNone) => {
                                target_binding
                                    .tx_counters
                                    .pending_direct_tx_build_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode) => {
                                target_binding
                                    .tx_counters
                                    .pending_direct_tx_disallowed_fallback_packets += 1;
                            }
                            None => {}
                        }
                        match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
                                forwarding.nat64.no_v6_frag_header,
                            )
                        } else {
                            build_forwarded_frame_from_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                request.apply_nat_on_fabric,
                                expected_ports,
                            )
                        } {
                            Some(frame) => {
                                if cfg!(feature = "debug-log") {
                                    if let Some(reason) = forward_tuple_mismatch_reason(
                                        live_frame_ports_from_meta_bytes(
                                            source_frame,
                                            request.meta,
                                        ),
                                        expected_ports,
                                        live_frame_ports_bytes(
                                            &frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                    ) {
                                        record_exception(
                                            recent_exceptions,
                                            ingress_ident,
                                            &reason,
                                            frame.len() as u32,
                                            Some(request.meta.into()),
                                            None,
                                            forwarding,
                                        );
                                        // Don't continue — the frame was built successfully,
                                        // forward it anyway. Mismatch is diagnostic only.
                                    }
                                }
                                let cp2_len = frame.len();
                                if copy_frame_is_oversized(cp2_len) {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp2_len as u32,
                                        Some(request.meta.into()),
                                        None,
                                        forwarding,
                                    );
                                    // #2208: oversized fallback-copy frame —
                                    // undeliverable. Fall through to the
                                    // finalizer (recycle the ingress
                                    // descriptor); the bare `continue;` here
                                    // leaked it. Drop-and-recycle, no slow-path
                                    // reinject (the frame is already oversized).
                                    build_failed = true;
                                } else {
                                    let req = TxRequest {
                                        bytes: frame,
                                        expected_ports,
                                        expected_addr_family: request.meta.addr_family,
                                        expected_protocol: request.meta.protocol,
                                        flow_key: flow_key.take(),
                                        egress_ifindex: request.decision.resolution.egress_ifindex,
                                        cos_queue_id: request.cos_queue_id,
                                        dscp_rewrite: request.dscp_rewrite,
                                        mirror_clone: false,
                                        enqueue_ns: 0,
                                    };
                                    if enqueue_local_request_to_target_or_owner(target_binding, req)
                                        .is_err()
                                    {
                                        // #2208: cross-binding CoS-owner queue
                                        // full (TX congestion). Set the
                                        // build-failure flags and FALL THROUGH
                                        // to the finalizer instead of the old
                                        // bare `continue;`, which skipped both
                                        // handle_forward_build_failure (the
                                        // slow-path reinject the flags request)
                                        // AND recycle_ingress_frame (leaking the
                                        // ingress descriptor under congestion).
                                        build_failed = true;
                                        fallback_to_slow_path = true;
                                    } else {
                                        dbg.enqueue_ok += 1;
                                        dbg.enqueue_copy += 1;
                                        target_binding.tx_counters.pending_copy_tx_packets += 1;
                                        dbg.tx_bytes_total += cp2_len as u64;
                                        if (cp2_len as u32) > dbg.tx_max_frame {
                                            dbg.tx_max_frame = cp2_len as u32;
                                        }
                                    }
                                }
                            }
                            None => {
                                build_failed = true;
                                fallback_to_slow_path = true;
                            }
                        }
                    }
                }
                } // close `if !mtu_signalled` (#2301 egress-MTU PTB)
            }
            if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE
                || target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE
            {
                let _ = drain_pending_tx_local_owner(
                    target_binding,
                    now_ns,
                    post_recycles,
                    forwarding,
                    worker_id,
                    worker_commands_by_id,
                );
            }
        }
        if !post_recycles.is_empty() {
            apply_shared_recycles(
                left,
                ingress_index,
                ingress_binding,
                right,
                binding_lookup,
                post_recycles,
            );
        }
        // #2301: enqueue the egress-MTU PTB back out the ingress interface
        // now that the `target_binding` borrow has ended. The reply is L2-
        // reflected (dst = inbound src), so it leaves via `ingress_binding`.
        // The oversized original is dropped: `mtu_signalled` left
        // `retained_source_frame` false, so the recycle below returns its
        // descriptor to the fill ring. A None `ptb_reply` (suppressed or
        // unbuildable) is the fail-closed silent drop.
        if let Some(ptb_bytes) = ptb_reply.take() {
            // #2328: classify the GENERATED egress-MTU PTB / Frag-Needed reply
            // by its OWN egress 5-tuple + egress interface, exactly like the
            // ICMP/ICMPv6 Time Exceeded (#2238), policy-`reject`, and
            // SYN-cookie generators. The PTB is L2-reflected back out the
            // ingress interface, so `ingress_ident.ifindex` IS the egress (the
            // same interface used for the enqueue below). Pre-#2328 the PTB
            // enqueued an UNCLASSIFIED TxRequest (`cos_queue_id: None,
            // dscp_rewrite: None`), so an output firewall filter terminal
            // `discard`/`reject` keyed on the generated ICMP tuple never fired
            // and CoS forwarding-class / DSCP rewrite were skipped. A parse
            // failure of our own built bytes fails CLOSED (drop + dedicated
            // parse-error counter, §6.2) rather than leaking past the filter.
            let verdict =
                classify_generated_reply(forwarding, ingress_ident.ifindex, &ptb_bytes, now_ns);
            if verdict.drop {
                counters.touched = true;
                if verdict.parse_error {
                    counters.generated_reply_classify_parse_errors += 1;
                } else {
                    counters.ptb_output_filter_drops += 1;
                }
                // Fail-closed: the oversized original is already dropped
                // (`mtu_signalled`); dropping the PTB here leaves no frame to
                // leak past the egress output filter.
            } else {
                let ptb_len = ptb_bytes.len();
                ingress_binding
                    .tx_pipeline
                    .pending_tx_local
                    .push_back(TxRequest {
                        bytes: ptb_bytes,
                        expected_ports: None,
                        expected_addr_family: request.meta.addr_family,
                        expected_protocol: request.meta.protocol,
                        flow_key: None,
                        egress_ifindex: ingress_ident.ifindex,
                        cos_queue_id: verdict.cos_queue_id,
                        dscp_rewrite: verdict.dscp_rewrite,
                        mirror_clone: false,
                        enqueue_ns: 0,
                    });
                bound_pending_tx_local(ingress_binding);
                dbg.enqueue_ok += 1;
                dbg.enqueue_copy += 1;
                ingress_binding.tx_counters.pending_copy_tx_packets += 1;
                dbg.tx_bytes_total += ptb_len as u64;
                if (ptb_len as u32) > dbg.tx_max_frame {
                    dbg.tx_max_frame = ptb_len as u32;
                }
            }
        }
        if build_failed {
            handle_forward_build_failure(
                ingress_ident,
                ingress_live,
                slow_path,
                local_tunnel_deliveries,
                recent_exceptions,
                dbg,
                request.target_ifindex,
                request.desc.len,
                source_frame,
                request.meta,
                request.decision,
                fallback_to_slow_path,
                forwarding,
            );
            if !retained_source_frame {
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            }
            continue;
        }
        if !retained_source_frame {
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
        }
    }
    while !ingress_binding.tx_pipeline.pending_fill_frames.is_empty() {
        let pending_before = ingress_binding.tx_pipeline.pending_fill_frames.len();
        let _ = drain_pending_fill(ingress_binding, now_ns);
        if ingress_binding.tx_pipeline.pending_fill_frames.len() >= pending_before {
            break;
        }
    }
    update_binding_debug_state(ingress_binding);
    pending_forwards.clear();
}

fn resolve_pending_forward_target_binding<'a>(
    left: &'a mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &'a mut BindingWorker,
    ingress_queue_id: u32,
    right: &'a mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    target_binding_index: Option<usize>,
    target_ifindex: i32,
) -> Option<&'a mut BindingWorker> {
    if let Some(target_index) = target_binding_index {
        return binding_by_index_mut(left, ingress_index, ingress_binding, right, target_index);
    }
    find_target_binding_mut(
        left,
        ingress_index,
        ingress_binding,
        ingress_queue_id,
        right,
        binding_lookup,
        target_ifindex,
    )
}

#[inline(always)]
fn count_forwarded_tcp_segmentation_miss_if_needed(
    dbg: &mut DebugPollCounters,
    copied_source_frame: bool,
    tcp_segmentation_needed: bool,
) -> bool {
    if copied_source_frame || !tcp_segmentation_needed {
        return false;
    }
    dbg.seg_needed_but_none += 1;
    true
}

/// Surface a genuine TCP segmentation miss to operators, rate-capped per
/// worker thread.
///
/// #1282: when segmentation is needed but both frame builders return
/// `None`, the dispatcher falls back to forwarding the original oversized
/// frame, which the NIC/switch/peer then drops — black-holing the flow.
/// The `dbg.seg_needed_but_none` counter that records this is
/// `pub(in crate::afxdp)` and is never exported to Go/CLI, so it is not an
/// operator-visible signal. We record a first-class `tcp_segmentation_miss`
/// exception so the event shows up under `Recent exceptions` in `show
/// chassis cluster data-plane statistics` even in release builds.
///
/// The recording is rate-capped via the caller-owned `cap` cell (20 per
/// worker thread) so a pathological per-packet seg-miss cannot spin the
/// `recent_exceptions` mutex on the hot path. The `DBG SEG_MISS` packet-
/// shape print is `debug-log`-only, matching the sibling debug prints in
/// this file; it DCEs out of release builds.
#[inline(always)]
fn record_forwarded_tcp_segmentation_miss(
    cap: &std::cell::Cell<u32>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    ingress_ident: &BindingIdentity,
    source_frame: &[u8],
    request: &PendingForwardRequest,
    forwarding: &ForwardingState,
) {
    let n = cap.get();
    if n >= 20 {
        return;
    }
    cap.set(n + 1);
    record_exception(
        recent_exceptions,
        ingress_ident,
        "tcp_segmentation_miss",
        source_frame.len() as u32,
        Some(request.meta.into()),
        None,
        forwarding,
    );
    if cfg!(feature = "debug-log") {
        let egress_mtu = forwarding
            .egress
            .get(&request.decision.resolution.egress_ifindex)
            .or_else(|| {
                forwarding
                    .egress
                    .get(&request.decision.resolution.tx_ifindex)
            })
            .map(|e| e.mtu);
        eprintln!(
            "DBG SEG_MISS[{}]: frame_len={} proto={} egress_if={} tx_if={} egress_mtu={:?} \
             target_if={} src_frame_bytes={}",
            n,
            source_frame.len(),
            request.meta.protocol,
            request.decision.resolution.egress_ifindex,
            request.decision.resolution.tx_ifindex,
            egress_mtu,
            request.target_ifindex,
            source_frame.len(),
        );
    }
}

/// Resolve the egress interface MTU for a forwarding decision, preferring
/// the egress ifindex and falling back to the tx ifindex (the same lookup
/// `forwarded_tcp_may_need_segmentation` performs). Returns `0` when no
/// egress entry is known, which the MTU decision treats as "no MTU known →
/// forward unchanged".
#[inline(always)]
fn forwarded_egress_mtu(decision: &SessionDecision, forwarding: &ForwardingState) -> usize {
    forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or(0)
}

#[inline(always)]
fn forwarded_tcp_may_need_segmentation(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> bool {
    let meta = meta.into();
    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
        return false;
    }
    let mtu = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default()
        .max(1280);
    // Prefer the actual Ethernet header in the frame. Metadata can lag
    // behind VLAN normalization; a VLAN frame with 18 bytes of L2 and a
    // 1500-byte L3 payload is 1518 bytes total, and treating stale
    // `l3_offset=14` as authoritative falsely flags it as needing TCP
    // segmentation. The segmentation builders already re-derive L3 from
    // the frame, so keep this predicate aligned with them.
    let l3 = frame_l3_offset(frame).or_else(|| match meta.l3_offset {
        14 | 18 => Some(meta.l3_offset as usize),
        _ => None,
    });
    let Some(l3) = l3 else {
        return false;
    };
    if l3 >= frame.len() {
        return false;
    }
    // #1852: a non-first IP fragment has no TCP header at the post-IP
    // offset — never segment it. `meta.protocol == PROTO_TCP` is true for
    // a non-first fragment of a TCP datagram (the shim reads the protocol
    // from the IP header / v6 fragment next-header), so without this gate
    // a large non-first fragment would enter the segmentation builders,
    // which parse payload bytes as a TCP header and run NAT/checksum at
    // the fake offset. Route it to the normal forwarding path instead.
    if is_non_first_fragment(&frame[l3..], meta.addr_family) {
        return false;
    }
    frame.len().saturating_sub(l3) > mtu
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;
