use super::*;

#[inline]
fn recycle_ingress_frame(
    ingress_binding: &mut BindingWorker,
    source_offset: u64,
    now_ns: u64,
    fill_drain_pending: &mut bool,
) {
    ingress_binding.pending_fill_frames.push_back(source_offset);
    *fill_drain_pending = true;
    if ingress_binding.pending_fill_frames.len() >= FILL_BATCH_SIZE {
        let _ = drain_pending_fill(ingress_binding, now_ns);
        *fill_drain_pending = false;
    }
}

pub(super) fn enqueue_pending_forwards(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    post_recycles: &mut Vec<(u32, u64)>,
    now_ns: u64,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    ingress_live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
) {
    if pending_forwards.is_empty() {
        return;
    }
    let ingress_area = ingress_binding.umem.area() as *const MmapArea;
    let mut fill_drain_pending = false;
    let tx_selection_enabled_v4 = forwarding.tx_selection_enabled_v4;
    let tx_selection_enabled_v6 = forwarding.tx_selection_enabled_v6;
    post_recycles.clear();
    // Walk the scratch vector in place. Moving large PendingForwardRequest
    // values through the iterator path was still forcing per-request memcpy
    // traffic before any forwarding work started.
    for request in pending_forwards.iter_mut() {
        let source_offset = request.desc.addr;
        let ingress_slot = ingress_binding.slot;
        let tx_selection_enabled = if request.meta.addr_family as i32 == libc::AF_INET6 {
            tx_selection_enabled_v6
        } else {
            tx_selection_enabled_v4
        };
        if tx_selection_enabled && request.cos_queue_id.is_none() && request.dscp_rewrite.is_none()
        {
            let cos = resolve_pending_forward_cos_tx_selection(forwarding, &request);
            request.cos_queue_id = cos.queue_id;
            request.dscp_rewrite = cos.dscp_rewrite;
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
        if let PendingForwardFrame::Prebuilt(prebuilt) = core::mem::take(&mut request.frame) {
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
                recycle_ingress_frame(
                    ingress_binding,
                    source_offset,
                    now_ns,
                    &mut fill_drain_pending,
                );
                continue;
            };
            let frame_len = prebuilt.len();
            target_binding.pending_tx_local.push_back(TxRequest {
                bytes: prebuilt,
                expected_ports: None,
                expected_addr_family: request.meta.addr_family,
                expected_protocol: request.meta.protocol,
                flow_key: None,
                egress_ifindex: request.decision.resolution.egress_ifindex,
                cos_queue_id: request.cos_queue_id,
                dscp_rewrite: request.dscp_rewrite,
            });
            bound_pending_tx_local(target_binding);
            dbg.enqueue_ok += 1;
            dbg.enqueue_copy += 1;
            target_binding.pending_copy_tx_packets += 1;
            dbg.tx_bytes_total += frame_len as u64;
            if (frame_len as u32) > dbg.tx_max_frame {
                dbg.tx_max_frame = frame_len as u32;
            }
            recycle_ingress_frame(
                ingress_binding,
                source_offset,
                now_ns,
                &mut fill_drain_pending,
            );
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
                    recycle_ingress_frame(
                        ingress_binding,
                        source_offset,
                        now_ns,
                        &mut fill_drain_pending,
                    );
                    continue;
                }
            }
            PendingForwardFrame::Prebuilt(_) => unreachable!(),
        };
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
                if matches!(request.frame, PendingForwardFrame::Owned(_)) {
                    maybe_reinject_slow_path_from_frame(
                        ingress_ident,
                        ingress_live,
                        slow_path,
                        local_tunnel_deliveries,
                        source_frame,
                        request.meta,
                        request.decision,
                        recent_exceptions,
                        "slow_path",
                    );
                } else {
                    maybe_reinject_slow_path(
                        ingress_ident,
                        ingress_live,
                        slow_path,
                        local_tunnel_deliveries,
                        unsafe { &*ingress_area },
                        request.desc,
                        request.meta,
                        request.decision,
                        recent_exceptions,
                    );
                }
                recycle_ingress_frame(
                    ingress_binding,
                    source_offset,
                    now_ns,
                    &mut fill_drain_pending,
                );
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
            );
            recycle_ingress_frame(
                ingress_binding,
                source_offset,
                now_ns,
                &mut fill_drain_pending,
            );
            continue;
        };
        let mut build_failed = false;
        let mut fallback_to_slow_path = false;
        let mut copied_source_frame = false;
        let mut retained_source_frame = false;
        let mut flow_key = request.flow_key.take();
        {
            if forwarded_tcp_may_need_segmentation(
                source_frame,
                request.meta,
                &request.decision,
                forwarding,
            ) {
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
                        cos_owner_worker_by_queue,
                    )
                {
                    dbg.enqueue_ok += segments as u64;
                    dbg.enqueue_direct += segments as u64;
                    target_binding.pending_direct_tx_packets += segments as u64;
                    dbg.tx_bytes_total += bytes;
                    if max_frame > dbg.tx_max_frame {
                        dbg.tx_max_frame = max_frame;
                    }
                    copied_source_frame = true;
                    if target_binding.pending_tx_prepared.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                            cos_owner_worker_by_queue,
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
                                );
                                build_failed = true;
                                break;
                            }
                        }
                        let seg_frame_len = frame.len();
                        target_binding.pending_tx_local.push_back(TxRequest {
                            bytes: frame,
                            expected_ports,
                            expected_addr_family: request.meta.addr_family,
                            expected_protocol: request.meta.protocol,
                            flow_key: flow_key.clone(),
                            egress_ifindex: request.decision.resolution.egress_ifindex,
                            cos_queue_id: request.cos_queue_id,
                            dscp_rewrite: request.dscp_rewrite,
                        });
                        bound_pending_tx_local(target_binding);
                        dbg.enqueue_ok += 1;
                        dbg.enqueue_copy += 1;
                        target_binding.pending_copy_tx_packets += 1;
                        dbg.tx_bytes_total += seg_frame_len as u64;
                        if (seg_frame_len as u32) > dbg.tx_max_frame {
                            dbg.tx_max_frame = seg_frame_len as u32;
                        }
                    }
                    copied_source_frame = true;
                    if target_binding.pending_tx_local.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                            cos_owner_worker_by_queue,
                        );
                    }
                }
            }
            // Track when segmentation was needed but returned None
            if !copied_source_frame && source_frame.len() > 1514 {
                dbg.seg_needed_but_none += 1;
                thread_local! {
                    static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                SEG_MISS_LOG.with(|c| {
                    let n = c.get();
                    if n < 20 {
                        c.set(n + 1);
                        let egress_mtu = forwarding
                            .egress
                            .get(&request.decision.resolution.egress_ifindex)
                            .or_else(|| forwarding.egress.get(&request.decision.resolution.tx_ifindex))
                            .map(|e| e.mtu);
                        eprintln!("DBG SEG_MISS[{}]: frame_len={} proto={} egress_if={} tx_if={} egress_mtu={:?} \
                             target_if={} src_frame_bytes={}",
                            n, source_frame.len(), request.meta.protocol,
                            request.decision.resolution.egress_ifindex,
                            request.decision.resolution.tx_ifindex,
                            egress_mtu, request.target_ifindex,
                            source_frame.len(),
                        );
                    }
                });
            }
            if !copied_source_frame {
                // NAT64: header size changes prevent in-place rewrite.
                // Always use copy path with NAT64-specific frame builder.
                let is_nat64 = request.decision.nat.nat64;
                let uses_native_tunnel = request.decision.resolution.tunnel_endpoint_id != 0;

                /*
                 * In-place TX optimization: rewrite the ingress frame directly in UMEM
                 * and submit it to the target binding's TX ring without copying.
                 * This is valid whenever ingress and egress bindings share the same
                 * UMEM allocation. That includes same-binding hairpin and the narrow
                 * same-device shared-UMEM prototype.
                 */
                let can_rewrite_in_place = target_binding.umem.allocation_ptr() == ingress_umem_ptr
                    && !is_nat64
                    && !uses_native_tunnel
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
                        Some(frame_len) => {
                            target_binding
                                .pending_tx_prepared
                                .push_back(PreparedTxRequest {
                                    offset: source_offset,
                                    len: frame_len,
                                    recycle: PreparedTxRecycle::FillOnSlot(ingress_slot),
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                });
                            bound_pending_tx_prepared(target_binding);
                            target_binding.pending_in_place_tx_packets += 1;
                            dbg.enqueue_ok += 1;
                            dbg.enqueue_inplace += 1;
                            dbg.tx_bytes_total += frame_len as u64;
                            if frame_len > dbg.tx_max_frame {
                                dbg.tx_max_frame = frame_len;
                            }
                            retained_source_frame = true;
                        }
                        None => match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
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
                                        );
                                        // Don't continue — the frame was built successfully,
                                        // forward it anyway. Mismatch is diagnostic only.
                                    }
                                }
                                let cp1_len = frame.len();
                                if cp1_len > tx_frame_capacity() {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp1_len as u32,
                                        Some(request.meta.into()),
                                        None,
                                    );
                                    continue;
                                }
                                target_binding.pending_tx_local.push_back(TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                });
                                bound_pending_tx_local(target_binding);
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_copy += 1;
                                target_binding.pending_copy_tx_packets += 1;
                                dbg.tx_bytes_total += cp1_len as u64;
                                if (cp1_len as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = cp1_len as u32;
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
                    let mut direct_tx_offset = target_binding.free_tx_frames.pop_front();
                    if direct_tx_offset.is_none()
                        && (target_binding.outstanding_tx > 0
                            || !target_binding.pending_tx_prepared.is_empty()
                            || !target_binding.pending_tx_local.is_empty())
                    {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                            cos_owner_worker_by_queue,
                        );
                        direct_tx_offset = target_binding.free_tx_frames.pop_front();
                    }
                    let mut direct_tx_fallback_reason = None;
                    let direct_built = if is_nat64 || uses_native_tunnel {
                        // NAT64 can't use direct TX — return the frame if we popped one.
                        if let Some(off) = direct_tx_offset {
                            target_binding.free_tx_frames.push_front(off);
                        }
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
                                    target_binding.free_tx_frames.push_front(tx_offset);
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        &reason,
                                        written as u32,
                                        Some(request.meta.into()),
                                        None,
                                    );
                                    build_failed = true;
                                }
                            }
                            if build_failed {
                                target_binding.free_tx_frames.push_front(tx_offset);
                                true
                            } else if written > tx_frame_capacity() {
                                target_binding.free_tx_frames.push_front(tx_offset);
                                record_exception(
                                    recent_exceptions,
                                    ingress_ident,
                                    "oversized_forward_frame",
                                    written as u32,
                                    Some(request.meta.into()),
                                    None,
                                );
                                true
                            } else {
                                target_binding
                                    .pending_tx_prepared
                                    .push_back(PreparedTxRequest {
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
                                    });
                                bound_pending_tx_prepared(target_binding);
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_direct += 1;
                                target_binding.pending_direct_tx_packets += 1;
                                dbg.tx_bytes_total += written as u64;
                                if (written as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = written as u32;
                                }
                                true
                            }
                        } else {
                            target_binding.free_tx_frames.push_front(tx_offset);
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
                                target_binding.pending_direct_tx_no_frame_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::BuildReturnedNone) => {
                                target_binding.pending_direct_tx_build_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode) => {
                                target_binding.pending_direct_tx_disallowed_fallback_packets += 1;
                            }
                            None => {}
                        }
                        match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
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
                                        );
                                        // Don't continue — the frame was built successfully,
                                        // forward it anyway. Mismatch is diagnostic only.
                                    }
                                }
                                let cp2_len = frame.len();
                                if cp2_len > tx_frame_capacity() {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp2_len as u32,
                                        Some(request.meta.into()),
                                        None,
                                    );
                                    continue;
                                }
                                target_binding.pending_tx_local.push_back(TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                });
                                bound_pending_tx_local(target_binding);
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_copy += 1;
                                target_binding.pending_copy_tx_packets += 1;
                                dbg.tx_bytes_total += cp2_len as u64;
                                if (cp2_len as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = cp2_len as u32;
                                }
                            }
                            None => {
                                build_failed = true;
                                fallback_to_slow_path = true;
                            }
                        }
                    }
                }
            }
            if target_binding.pending_tx_prepared.len() >= TX_BATCH_SIZE
                || target_binding.pending_tx_local.len() >= TX_BATCH_SIZE
            {
                let _ = drain_pending_tx_local_owner(
                    target_binding,
                    now_ns,
                    post_recycles,
                    forwarding,
                    worker_id,
                    worker_commands_by_id,
                    cos_owner_worker_by_queue,
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
            );
            if !retained_source_frame {
                recycle_ingress_frame(
                    ingress_binding,
                    source_offset,
                    now_ns,
                    &mut fill_drain_pending,
                );
            }
            continue;
        }
        if !retained_source_frame {
            recycle_ingress_frame(
                ingress_binding,
                source_offset,
                now_ns,
                &mut fill_drain_pending,
            );
        }
    }
    if fill_drain_pending && !ingress_binding.pending_fill_frames.is_empty() {
        let _ = drain_pending_fill(ingress_binding, now_ns);
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

pub(super) fn handle_forward_build_failure(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    _target_ifindex: i32,
    packet_length: u32,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    fallback_to_slow_path: bool,
) {
    let meta = meta.into();
    dbg.build_fail += 1;
    #[cfg(feature = "debug-log")]
    if dbg.build_fail <= 3 {
        debug_log!(
            "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
            _target_ifindex,
            packet_length,
            fallback_to_slow_path,
        );
    }
    record_exception(
        recent_exceptions,
        binding,
        "forward_build_failed",
        packet_length,
        Some(meta),
        None,
    );
    if fallback_to_slow_path {
        maybe_reinject_slow_path_from_frame(
            binding,
            live,
            slow_path,
            local_tunnel_deliveries,
            frame,
            meta,
            decision,
            recent_exceptions,
            "forward_build_slow_path",
        );
    }
}

pub(super) fn apply_shared_recycles(
    left: &mut [BindingWorker],
    current_index: usize,
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if shared_recycles.is_empty() {
        return;
    }
    for (slot, offset) in shared_recycles.drain(..) {
        if let Some(target_index) = binding_lookup.slot_index(slot)
            && let Some(binding) =
                binding_by_index_mut(left, current_index, current, right, target_index)
        {
            binding.pending_fill_frames.push_back(offset);
            continue;
        }
        current.pending_fill_frames.push_back(offset);
    }
}

pub(super) fn resolve_tx_binding_ifindex(forwarding: &ForwardingState, egress_ifindex: i32) -> i32 {
    if let Some(fabric) = forwarding
        .fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex == egress_ifindex)
    {
        return fabric.parent_ifindex;
    }
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.bind_ifindex)
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(egress_ifindex)
}

fn resolve_pending_forward_cos_tx_selection(
    forwarding: &ForwardingState,
    request: &PendingForwardRequest,
) -> CoSTxSelection {
    resolve_cos_tx_selection(
        forwarding,
        request.decision.resolution.egress_ifindex,
        request.meta,
        request.flow_key.as_ref(),
    )
}

pub(super) fn maybe_reinject_slow_path(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    area: &MmapArea,
    desc: XdpDesc,
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    let meta = meta.into();
    if !matches!(
        decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
            | ForwardingDisposition::NoRoute
            | ForwardingDisposition::MissingNeighbor
            | ForwardingDisposition::NextTableUnsupported
    ) {
        return;
    }
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_extract_failed",
            desc.len as u32,
            Some(meta),
            None,
        );
        return;
    };
    maybe_reinject_slow_path_from_frame(
        binding,
        live,
        slow_path,
        local_tunnel_deliveries,
        frame,
        meta,
        decision,
        recent_exceptions,
        "slow_path",
    );
}

pub(super) fn maybe_reinject_slow_path_from_frame(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    reason: &str,
) {
    let meta = meta.into();
    let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_prepare_failed",
            frame.len() as u32,
            Some(meta),
            None,
        );
        return;
    };
    let packet_len = packet.len() as u64;
    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
        && decision.resolution.local_ifindex > 0
    {
        local_tunnel_deliveries
            .load()
            .get(&decision.resolution.local_ifindex)
            .cloned()
    } else {
        None
    };
    if let Some(delivery) = tunnel_delivery {
        match delivery.try_send(packet) {
            Ok(()) => {
                live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_queue_full",
                    frame.len() as u32,
                    Some(meta),
                    None,
                );
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_unavailable",
                    frame.len() as u32,
                    Some(meta),
                    None,
                );
            }
        }
        return;
    }
    let selected_path = slow_path.cloned();
    let Some(slow_path) = selected_path else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_unavailable",
            frame.len() as u32,
            Some(meta),
            None,
        );
        return;
    };
    match slow_path.enqueue(packet) {
        Ok(EnqueueOutcome::Accepted) => {
            live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
        }
        Ok(EnqueueOutcome::RateLimited) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.slow_path_rate_limited.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_rate_limited"),
                frame.len() as u32,
                Some(meta),
                None,
            );
        }
        Ok(EnqueueOutcome::QueueFull) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_queue_full"),
                frame.len() as u32,
                Some(meta),
                None,
            );
        }
        Err(err) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.set_error(err);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_enqueue_failed"),
                frame.len() as u32,
                Some(meta),
                None,
            );
        }
    }
}

#[allow(dead_code)]
pub(super) fn extract_l3_packet(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    extract_l3_packet_from_frame(frame, meta)
}

pub(super) fn extract_l3_packet_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let l3 = meta.l3_offset as usize;
    if l3 >= frame.len() {
        return None;
    }
    Some(frame[l3..].to_vec())
}

pub(super) fn extract_l3_packet_with_nat(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    nat: NatDecision,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let mut packet = extract_l3_packet_from_frame(frame, meta)?;
    match meta.addr_family as i32 {
        libc::AF_INET => apply_nat_ipv4(&mut packet, meta.protocol, nat)?,
        libc::AF_INET6 => apply_nat_ipv6(&mut packet, meta.protocol, nat)?,
        _ => return None,
    }
    Some(packet)
}

fn segment_forwarded_tcp_frames_into_prepared(
    target_binding: &mut BindingWorker,
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
    flow_key: Option<SessionKey>,
    cos_queue_id: Option<u8>,
    dscp_rewrite: Option<u8>,
    now_ns: u64,
    post_recycles: &mut Vec<(u32, u64)>,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
) -> Option<(u32, u64, u32)> {
    let meta = meta.into();
    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
        return None;
    }
    let mtu = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default()
        .max(1280);
    if mtu == 0 {
        return None;
    }
    let l3 = frame_l3_offset(frame)?;
    if l3 >= frame.len() {
        return None;
    }
    let payload = &frame[l3..];
    if payload.len() <= mtu {
        return None;
    }
    let frame_l4 = frame_l4_offset(frame, meta.addr_family)?;
    let tcp_offset = frame_l4.checked_sub(l3)?;
    let (ip_header_len, tcp_offset) = match meta.addr_family as i32 {
        libc::AF_INET => {
            if payload.len() < 20 {
                return None;
            }
            let ihl = ((payload[0] & 0x0f) as usize) * 4;
            if ihl < 20 || payload.len() < ihl + 20 {
                return None;
            }
            (ihl, ihl)
        }
        libc::AF_INET6 => {
            let ip_header_len = tcp_offset;
            if ip_header_len < 40 || payload.len() < ip_header_len + 20 {
                return None;
            }
            (ip_header_len, ip_header_len)
        }
        _ => return None,
    };
    let tcp_header_len = ((payload.get(tcp_offset + 12)? >> 4) as usize) * 4;
    if tcp_header_len < 20 || payload.len() < tcp_offset + tcp_header_len {
        return None;
    }
    let tcp_flags = *payload.get(tcp_offset + 13)?;
    if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) != 0 {
        return None;
    }
    let segment_payload_max = mtu.checked_sub(ip_header_len + tcp_header_len)?;
    if segment_payload_max == 0 {
        return None;
    }
    let data = payload.get(tcp_offset + tcp_header_len..)?;
    if data.len() <= segment_payload_max {
        return None;
    }

    let segment_count = data.len().div_ceil(segment_payload_max);
    if target_binding.free_tx_frames.len() < segment_count
        && (target_binding.outstanding_tx > 0
            || !target_binding.pending_tx_prepared.is_empty()
            || !target_binding.pending_tx_local.is_empty())
    {
        let _ = drain_pending_tx_local_owner(
            target_binding,
            now_ns,
            post_recycles,
            forwarding,
            worker_id,
            worker_commands_by_id,
            cos_owner_worker_by_queue,
        );
    }
    if target_binding.free_tx_frames.len() < segment_count {
        return None;
    }

    let dst_mac = decision.resolution.neighbor_mac?;
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                apply_nat_on_fabric,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let original_seq = u32::from_be_bytes([
        *payload.get(tcp_offset + 4)?,
        *payload.get(tcp_offset + 5)?,
        *payload.get(tcp_offset + 6)?,
        *payload.get(tcp_offset + 7)?,
    ]);
    let enforced_ports = expected_ports.or(live_frame_ports_from_meta_bytes(frame, meta));
    let tcp_header = payload.get(tcp_offset..tcp_offset + tcp_header_len)?;
    let ip_header = payload.get(..ip_header_len)?;
    let mut prepared: Vec<PreparedTxRequest> = Vec::with_capacity(segment_count);
    let mut total_bytes = 0u64;
    let mut max_frame = 0u32;
    let mut data_offset = 0usize;
    while data_offset < data.len() {
        let chunk_len = (data.len() - data_offset).min(segment_payload_max);
        let is_last = data_offset + chunk_len == data.len();
        let total_ip_len = ip_header_len + tcp_header_len + chunk_len;
        let frame_len = eth_len + total_ip_len;
        if frame_len > tx_frame_capacity() {
            for req in prepared.drain(..).rev() {
                target_binding.free_tx_frames.push_front(req.offset);
            }
            return None;
        }
        let Some(tx_offset) = target_binding.free_tx_frames.pop_front() else {
            for req in prepared.drain(..).rev() {
                target_binding.free_tx_frames.push_front(req.offset);
            }
            return None;
        };
        let Some(frame_out) = (unsafe {
            target_binding
                .umem
                .area()
                .slice_mut_unchecked(tx_offset as usize, frame_len)
        }) else {
            target_binding.free_tx_frames.push_front(tx_offset);
            for req in prepared.drain(..).rev() {
                target_binding.free_tx_frames.push_front(req.offset);
            }
            return None;
        };

        let built = (|| -> Option<()> {
            write_eth_header_slice(
                frame_out.get_mut(..eth_len)?,
                dst_mac,
                src_mac,
                vlan_id,
                ether_type,
            )?;
            {
                let packet = frame_out.get_mut(eth_len..)?;
                packet.get_mut(..ip_header_len)?.copy_from_slice(ip_header);
                packet
                    .get_mut(ip_header_len..ip_header_len + tcp_header_len)?
                    .copy_from_slice(tcp_header);
                packet
                    .get_mut(ip_header_len + tcp_header_len..total_ip_len)?
                    .copy_from_slice(data.get(data_offset..data_offset + chunk_len)?);

                let tcp = packet.get_mut(tcp_offset..)?;
                let seq = original_seq.wrapping_add(data_offset as u32);
                tcp.get_mut(4..8)?.copy_from_slice(&seq.to_be_bytes());
                if !is_last {
                    tcp[13] &= !TCP_FLAG_PSH;
                }
            }

            match meta.addr_family as i32 {
                libc::AF_INET => {
                    {
                        let packet = frame_out.get_mut(eth_len..)?;
                        packet
                            .get_mut(2..4)?
                            .copy_from_slice(&(total_ip_len as u16).to_be_bytes());
                        if packet[8] <= 1 {
                            return None;
                        }
                        if apply_nat {
                            apply_nat_ipv4(packet, meta.protocol, decision.nat)?;
                        }
                        if (meta.meta_flags & 0x80) == 0 {
                            packet[8] -= 1;
                        }
                    }
                    let _ = enforce_expected_ports(
                        frame_out,
                        meta.addr_family,
                        meta.protocol,
                        enforced_ports,
                    )?;
                    let packet = frame_out.get_mut(eth_len..)?;
                    packet.get_mut(10..12)?.copy_from_slice(&[0, 0]);
                    let ip_sum = checksum16(packet.get(..ip_header_len)?);
                    packet
                        .get_mut(10..12)?
                        .copy_from_slice(&ip_sum.to_be_bytes());
                    recompute_l4_checksum_ipv4(packet, ip_header_len, meta.protocol, false)?;
                }
                libc::AF_INET6 => {
                    {
                        let packet = frame_out.get_mut(eth_len..)?;
                        packet
                            .get_mut(4..6)?
                            .copy_from_slice(&((tcp_header_len + chunk_len) as u16).to_be_bytes());
                        if (meta.meta_flags & 0x80) == 0 && packet[7] <= 1 {
                            return None;
                        }
                        if apply_nat {
                            apply_nat_ipv6(packet, meta.protocol, decision.nat)?;
                        }
                        if (meta.meta_flags & 0x80) == 0 {
                            packet[7] -= 1;
                        }
                    }
                    let _ = enforce_expected_ports(
                        frame_out,
                        meta.addr_family,
                        meta.protocol,
                        enforced_ports,
                    )?;
                    let packet = frame_out.get_mut(eth_len..)?;
                    recompute_l4_checksum_ipv6(packet, meta.protocol)?;
                }
                _ => return None,
            }
            Some(())
        })();
        if built.is_none() {
            target_binding.free_tx_frames.push_front(tx_offset);
            for req in prepared.drain(..).rev() {
                target_binding.free_tx_frames.push_front(req.offset);
            }
            return None;
        }

        prepared.push(PreparedTxRequest {
            offset: tx_offset,
            len: frame_len as u32,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports,
            expected_addr_family: meta.addr_family,
            expected_protocol: meta.protocol,
            flow_key: flow_key.clone(),
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id,
            dscp_rewrite,
        });
        total_bytes += frame_len as u64;
        max_frame = max_frame.max(frame_len as u32);
        data_offset += chunk_len;
    }

    for req in prepared {
        target_binding.pending_tx_prepared.push_back(req);
    }
    bound_pending_tx_prepared(target_binding);
    Some((segment_count as u32, total_bytes, max_frame))
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
    if mtu == 0 {
        return false;
    }
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => match frame_l3_offset(frame) {
            Some(offset) => offset,
            None => return false,
        },
    };
    l3 < frame.len() && frame.len().saturating_sub(l3) > mtu
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_forwarding_with_egress_mtu(mtu: usize) -> ForwardingState {
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu,
                src_mac: [0; 6],
                zone: "wan".into(),
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );
        forwarding
    }

    fn test_decision() -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 80,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 80,
            },
            nat: NatDecision::default(),
        }
    }

    #[test]
    fn forwarded_tcp_may_need_segmentation_skips_mtu_sized_frame() {
        let forwarding = test_forwarding_with_egress_mtu(1500);
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            l3_offset: 14,
            ..UserspaceDpMeta::default()
        };
        let frame = vec![0u8; 14 + 1500];
        assert!(!forwarded_tcp_may_need_segmentation(
            &frame,
            meta,
            &test_decision(),
            &forwarding,
        ));
    }

    #[test]
    fn forwarded_tcp_may_need_segmentation_flags_oversized_frame() {
        let forwarding = test_forwarding_with_egress_mtu(1500);
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            l3_offset: 14,
            ..UserspaceDpMeta::default()
        };
        let frame = vec![0u8; 14 + 1600];
        assert!(forwarded_tcp_may_need_segmentation(
            &frame,
            meta,
            &test_decision(),
            &forwarding,
        ));
    }
}
