use super::*;

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn authoritative_forward_ports(
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let flow_ports = flow.and_then(|flow| {
        if flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0 {
            Some((flow.forward_key.src_port, flow.forward_key.dst_port))
        } else {
            None
        }
    });
    let meta_ports = if meta.flow_src_port != 0 && meta.flow_dst_port != 0 {
        Some((meta.flow_src_port, meta.flow_dst_port))
    } else {
        None
    };
    let frame_ports = live_frame_ports_bytes(frame, meta.addr_family, meta.protocol);
    flow_ports.or(frame_ports).or(meta_ports)
}

#[allow(dead_code)]
pub(super) fn live_frame_ports(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    live_frame_ports_bytes(frame, meta.addr_family, meta.protocol)
}

pub(super) fn live_frame_ports_bytes(
    frame: &[u8],
    addr_family: u8,
    protocol: u8,
) -> Option<(u16, u16)> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let l4 = frame_l4_offset(frame, addr_family)?;
    parse_flow_ports(frame, l4, protocol)
}

pub(super) fn forward_tuple_mismatch_reason(
    source_ports: Option<(u16, u16)>,
    expected_ports: Option<(u16, u16)>,
    built_ports: Option<(u16, u16)>,
) -> Option<String> {
    let expected = expected_ports.or(source_ports)?;
    let built = built_ports?;
    if built == expected {
        return None;
    }
    let source = source_ports.unwrap_or((0, 0));
    Some(format!(
        "forward_tuple_mismatch:src={}:{} expected={}:{} built={}:{}",
        source.0, source.1, expected.0, expected.1, built.0, built.1
    ))
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
) {
    let ingress_area = ingress_binding.umem.area() as *const MmapArea;
    post_recycles.clear();
    for request in pending_forwards.drain(..) {
        let source_offset = request.source_offset;
        let ingress_slot = ingress_binding.slot;

        // Fast path: prebuilt frame (e.g. ICMP error NAT reversal).
        // The frame is already fully rewritten — just enqueue for TX.
        if let Some(prebuilt) = request.prebuilt_frame {
            let Some(target_binding) = resolve_pending_forward_target_binding(
                left,
                ingress_index,
                ingress_binding,
                request.ingress_queue_id,
                right,
                binding_lookup,
                request.target_binding_index,
                request.target_ifindex,
            ) else {
                ingress_binding.pending_fill_frames.push_back(source_offset);
                continue;
            };
            let frame_len = prebuilt.len();
            target_binding.pending_tx_local.push_back(TxRequest {
                bytes: prebuilt,
                expected_ports: None,
                expected_addr_family: request.meta.addr_family,
                expected_protocol: request.meta.protocol,
                flow_key: None,
            });
            bound_pending_tx_local(target_binding);
            dbg.enqueue_ok += 1;
            dbg.enqueue_copy += 1;
            target_binding.pending_copy_tx_packets += 1;
            dbg.tx_bytes_total += frame_len as u64;
            if (frame_len as u32) > dbg.tx_max_frame {
                dbg.tx_max_frame = frame_len as u32;
            }
            ingress_binding.pending_fill_frames.push_back(source_offset);
            continue;
        }

        // Read source frame directly from ingress UMEM — no heap copy needed.
        // The frame is safe to read: RX ring released but frame not yet returned
        // to fill ring (that happens after this function completes).
        let owned_source_frame = request.source_frame.as_deref();
        let source_frame = if let Some(frame) = owned_source_frame {
            frame
        } else if let Some(frame) = (unsafe { &*ingress_area })
            .slice(request.source_offset as usize, request.desc.len as usize)
        {
            frame
        } else {
            ingress_binding.pending_fill_frames.push_back(source_offset);
            continue;
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
            request.target_binding_index,
            request.target_ifindex,
        ) else {
            // No XSK binding for the target interface.  Normally fabric
            // parents have bindings; this is a safety-net fallback in case
            // the binding is not yet ready or bind() failed.
            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                if request.source_frame.is_some() {
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
                ingress_binding.pending_fill_frames.push_back(source_offset);
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
            ingress_binding.pending_fill_frames.push_back(source_offset);
            continue;
        };
        post_recycles.clear();
        let mut build_failed = false;
        let mut fallback_to_slow_path = false;
        let mut copied_source_frame = false;
        let mut retained_source_frame = false;
        {
            if let Some((segments, bytes, max_frame)) = segment_forwarded_tcp_frames_into_prepared(
                target_binding,
                source_frame,
                request.meta,
                &request.decision,
                forwarding,
                request.apply_nat_on_fabric,
                expected_ports,
                request.flow_key.clone(),
                now_ns,
                post_recycles,
            ) {
                dbg.enqueue_ok += segments as u64;
                dbg.enqueue_direct += segments as u64;
                target_binding.pending_direct_tx_packets += segments as u64;
                dbg.tx_bytes_total += bytes;
                if max_frame > dbg.tx_max_frame {
                    dbg.tx_max_frame = max_frame;
                }
                copied_source_frame = true;
                if target_binding.pending_tx_prepared.len() >= TX_BATCH_SIZE {
                    let _ = drain_pending_tx(target_binding, now_ns, post_recycles);
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
                            live_frame_ports_bytes(
                                source_frame,
                                request.meta.addr_family,
                                request.meta.protocol,
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
                                Some(request.meta),
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
                        flow_key: request.flow_key.clone(),
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
                    let _ = drain_pending_tx(target_binding, now_ns, post_recycles);
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
                    && request.source_frame.is_none();
                if can_rewrite_in_place {
                    match rewrite_forwarded_frame_in_place(
                        unsafe { &*ingress_area },
                        request.desc,
                        request.meta,
                        &request.decision,
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
                                    flow_key: request.flow_key.clone(),
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
                                        live_frame_ports_bytes(
                                            source_frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
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
                                            Some(request.meta),
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
                                        Some(request.meta),
                                        None,
                                    );
                                    continue;
                                }
                                target_binding.pending_tx_local.push_back(TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: request.flow_key.clone(),
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
                        let _ = drain_pending_tx(target_binding, now_ns, post_recycles);
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
                                    live_frame_ports_bytes(
                                        source_frame,
                                        request.meta.addr_family,
                                        request.meta.protocol,
                                    ),
                                    expected_ports,
                                    built_ports,
                                ) {
                                    target_binding.free_tx_frames.push_front(tx_offset);
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        &reason,
                                        written as u32,
                                        Some(request.meta),
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
                                    Some(request.meta),
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
                                        flow_key: request.flow_key.clone(),
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
                                        live_frame_ports_bytes(
                                            source_frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
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
                                            Some(request.meta),
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
                                        Some(request.meta),
                                        None,
                                    );
                                    continue;
                                }
                                target_binding.pending_tx_local.push_back(TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: request.flow_key.clone(),
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
                let _ = drain_pending_tx(target_binding, now_ns, post_recycles);
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
        update_binding_debug_state(ingress_binding);
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
                ingress_binding.pending_fill_frames.push_back(source_offset);
            }
            continue;
        }
        if !retained_source_frame {
            ingress_binding.pending_fill_frames.push_back(source_offset);
        }
        // Always drain fill immediately — no watermark delay. In copy mode,
        // the kernel queues packets in the socket buffer when the fill ring
        // is low, causing latency spikes that stall TCP.
        if !ingress_binding.pending_fill_frames.is_empty() {
            let _ = drain_pending_fill(ingress_binding, now_ns);
        }
        update_binding_debug_state(ingress_binding);
    }
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
    meta: UserspaceDpMeta,
    decision: SessionDecision,
    fallback_to_slow_path: bool,
) {
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

pub(super) fn maybe_reinject_slow_path(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
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
    meta: UserspaceDpMeta,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    reason: &str,
) {
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

pub(super) fn extract_l3_packet_from_frame(frame: &[u8], meta: UserspaceDpMeta) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    if l3 >= frame.len() {
        return None;
    }
    Some(frame[l3..].to_vec())
}

pub(super) fn extract_l3_packet_with_nat(
    frame: &[u8],
    meta: UserspaceDpMeta,
    nat: NatDecision,
) -> Option<Vec<u8>> {
    let mut packet = extract_l3_packet_from_frame(frame, meta)?;
    match meta.addr_family as i32 {
        libc::AF_INET => apply_nat_ipv4(&mut packet, meta.protocol, nat)?,
        libc::AF_INET6 => apply_nat_ipv6(&mut packet, meta.protocol, nat)?,
        _ => return None,
    }
    Some(packet)
}

pub(super) fn parse_session_flow_from_bytes(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    // Fast path: for TCP/UDP with complete metadata tuple, use meta directly
    // without parsing the frame. This avoids extra L3/L4 parsing for the
    // common established-flow case.
    if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
        && let Some(meta_flow) = parse_session_flow_from_meta(meta)
        && metadata_tuple_complete(meta, &meta_flow)
    {
        return Some(meta_flow);
    }

    let frame_flow = if matches!(meta.addr_family as i32, libc::AF_INET) {
        parse_ipv4_session_flow_from_frame(frame, meta)
    } else {
        parse_session_flow_from_frame(frame, meta)
    };

    if let Some(meta_flow) = parse_session_flow_from_meta(meta)
        && metadata_tuple_complete(meta, &meta_flow)
    {
        if let Some(ref frame_flow) = frame_flow {
            if frame_flow.src_ip == meta_flow.src_ip && frame_flow.dst_ip == meta_flow.dst_ip {
                return Some(meta_flow);
            }
            return Some(frame_flow.clone());
        }
        return Some(meta_flow);
    }

    if let Some(flow) = frame_flow {
        return Some(flow);
    }

    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 12],
                frame[l3 + 13],
                frame[l3 + 14],
                frame[l3 + 15],
            ));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

pub(super) fn parse_session_flow(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_session_flow_from_bytes(frame, meta)
}

/// Check if a frame contains a TCP RST flag. Returns (is_rst, summary) for logging.
pub(super) fn frame_has_tcp_rst(frame: &[u8]) -> bool {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return false,
    };
    let ip = match frame.get(l3..) {
        Some(ip) if ip.len() >= 20 => ip,
        _ => return false,
    };
    let (protocol, l4_offset) = match ip[0] >> 4 {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 if ip.len() >= 40 => (ip[6], 40usize),
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match ip.get(l4_offset..) {
        Some(t) if t.len() >= 14 => t,
        _ => return false,
    };
    // TCP flags at offset 13: RST = 0x04
    (tcp[13] & 0x04) != 0
}

/// Extract TCP flags and window from raw frame, auto-detecting L3 from Ethernet header.
/// Returns (tcp_flags, tcp_window) or None.
pub(super) fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)> {
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    Some((flags, window))
}

/// Extract TCP window size from raw frame data.
/// Returns None if not a TCP frame or if frame is too short.
#[allow(dead_code)]
pub(super) fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16> {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return None,
    };
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match addr_family as i32 {
        libc::AF_INET => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        libc::AF_INET6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    // TCP window is at offset 14-15 (big-endian)
    Some(u16::from_be_bytes([tcp[14], tcp[15]]))
}

pub(super) fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        return Some(18);
    }
    Some(14)
}

/// Decode an Ethernet frame into a human-readable summary showing IP src/dst,
/// TCP/UDP ports, TCP flags, and checksums. For debugging packet forwarding.
pub(super) fn decode_frame_summary(frame: &[u8]) -> String {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return String::new(),
    };
    let ip = &frame[l3..];
    if ip.len() < 20 {
        return String::new();
    }
    let version = ip[0] >> 4;
    if version == 4 {
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let total_len = u16::from_be_bytes([ip[2], ip[3]]);
        let protocol = ip[9];
        let ip_csum = u16::from_be_bytes([ip[10], ip[11]]);
        let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let ttl = ip[8];
        if matches!(protocol, PROTO_TCP | PROTO_UDP) && ip.len() >= ihl + 8 {
            let l4 = &ip[ihl..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if protocol == PROTO_TCP && ip.len() >= ihl + 20 {
                let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
                let flags = l4[13];
                let tcp_csum = u16::from_be_bytes([l4[16], l4[17]]);
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv4 {}:{} -> {}:{} TCP [{flag_str}] seq={seq} ack={ack} ttl={ttl} ip_csum={ip_csum:#06x} tcp_csum={tcp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else if protocol == PROTO_UDP {
                let udp_csum = u16::from_be_bytes([l4[6], l4[7]]);
                format!(
                    "IPv4 {}:{} -> {}:{} UDP ttl={ttl} ip_csum={ip_csum:#06x} udp_csum={udp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else {
                format!(
                    "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                    src, dst
                )
            }
        } else {
            format!(
                "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                src, dst
            )
        }
    } else if version == 6 && ip.len() >= 40 {
        let payload_len = u16::from_be_bytes([ip[4], ip[5]]);
        let next_header = ip[6];
        let hop_limit = ip[7];
        let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap_or([0; 16]));
        let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap_or([0; 16]));
        if matches!(next_header, PROTO_TCP | PROTO_UDP) && ip.len() >= 48 {
            let l4 = &ip[40..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if next_header == PROTO_TCP && ip.len() >= 60 {
                let flags = l4[13];
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} TCP [{flag_str}] hop={hop_limit} pl={payload_len}"
                )
            } else {
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} proto={next_header} hop={hop_limit} pl={payload_len}"
                )
            }
        } else {
            format!("IPv6 [{src}] -> [{dst}] proto={next_header} hop={hop_limit} pl={payload_len}")
        }
    } else {
        String::new()
    }
}

pub(super) fn tcp_flags_str(flags: u8) -> String {
    let mut s = String::with_capacity(12);
    if flags & 0x02 != 0 {
        s.push_str("SYN ");
    }
    if flags & 0x10 != 0 {
        s.push_str("ACK ");
    }
    if flags & 0x01 != 0 {
        s.push_str("FIN ");
    }
    if flags & 0x04 != 0 {
        s.push_str("RST ");
    }
    if flags & 0x08 != 0 {
        s.push_str("PSH ");
    }
    if flags & 0x20 != 0 {
        s.push_str("URG ");
    }
    if s.ends_with(' ') {
        s.truncate(s.len() - 1);
    }
    if s.is_empty() {
        s.push_str("none");
    }
    s
}

pub(super) fn frame_l4_offset(frame: &[u8], addr_family: u8) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    match addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 {
                return None;
            }
            let ihl = usize::from(frame[l3] & 0x0f) * 4;
            if ihl < 20 || frame.len() < l3 + ihl {
                return None;
            }
            Some(l3 + ihl)
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 {
                return None;
            }
            let mut protocol = *frame.get(l3 + 6)?;
            let mut offset = l3 + 40;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = frame.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            Some(offset)
        }
        _ => None,
    }
}

pub(super) fn packet_rel_l4_offset(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some(ihl)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40usize;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = packet.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            Some(offset)
        }
        _ => None,
    }
}

/// Like `packet_rel_l4_offset` but also returns the final L4 protocol
/// after walking IPv6 extension headers. For IPv4, returns the protocol
/// byte from the IP header. Needed for GRE inner packet parsing where
/// the initial next-header (packet[6]) may be an extension header, not
/// the actual L4 protocol.
pub(super) fn packet_rel_l4_offset_and_protocol(
    packet: &[u8],
    addr_family: u8,
) -> Option<(usize, u8)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some((ihl, packet[9]))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40usize;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = packet.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some((offset, protocol)),
                }
            }
            Some((offset, protocol))
        }
        _ => None,
    }
}

pub(super) fn metadata_tuple_complete(meta: UserspaceDpMeta, flow: &SessionFlow) -> bool {
    if flow.src_ip.is_unspecified() || flow.dst_ip.is_unspecified() {
        return false;
    }
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0,
        _ => true,
    }
}

pub(super) fn parse_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    match meta.addr_family as i32 {
        libc::AF_INET => parse_ipv4_session_flow_from_frame(frame, meta),
        libc::AF_INET6 => {
            let l3 = frame_l3_offset(frame)?;
            let l4 = frame_l4_offset(frame, meta.addr_family)?;
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

pub(super) fn parse_session_flow_from_meta(meta: UserspaceDpMeta) -> Option<SessionFlow> {
    let (src_ip, dst_ip) = match meta.addr_family as i32 {
        libc::AF_INET => {
            let src = meta.flow_src_addr.get(..4)?;
            let dst = meta.flow_dst_addr.get(..4)?;
            (
                IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
            )
        }
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr)),
            IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr)),
        ),
        _ => return None,
    };
    if src_ip.is_unspecified() || dst_ip.is_unspecified() {
        return None;
    }
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip,
            dst_ip,
            src_port: meta.flow_src_port,
            dst_port: meta.flow_dst_port,
        },
    })
}

pub(super) fn parse_ipv4_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let mut l3 = 14usize;
    if frame.len() < l3 {
        return None;
    }
    let mut eth_proto = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < l3 + 4 {
            return None;
        }
        eth_proto = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
        l3 += 4;
    }
    if eth_proto != 0x0800 || frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let protocol = frame[l3 + 9];
    let l4 = l3 + ihl;
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 12],
        frame[l3 + 13],
        frame[l3 + 14],
        frame[l3 + 15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 16],
        frame[l3 + 17],
        frame[l3 + 18],
        frame[l3 + 19],
    ));
    let (src_port, dst_port) = parse_flow_ports(frame, l4, protocol)?;
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
    })
}

pub(super) fn parse_flow_ports(frame: &[u8], l4: usize, protocol: u8) -> Option<(u16, u16)> {
    match protocol {
        PROTO_TCP | PROTO_UDP => {
            let bytes = frame.get(l4..l4 + 4)?;
            Some((
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let bytes = frame.get(l4 + 4..l4 + 6)?;
            let ident = u16::from_be_bytes([bytes[0], bytes[1]]);
            Some((ident, 0))
        }
        _ => None,
    }
}

pub(super) fn parse_zone_encoded_fabric_ingress(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<String> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_zone_encoded_fabric_ingress_from_frame(frame, meta, forwarding)
}

pub(super) fn parse_zone_encoded_fabric_ingress_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<String> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    if frame.len() < 12 {
        return None;
    }
    if frame[6] != 0x02
        || frame[7] != 0xbf
        || frame[8] != 0x72
        || frame[9] != FABRIC_ZONE_MAC_MAGIC
        || frame[10] != 0x00
    {
        return None;
    }
    forwarding.zone_id_to_name.get(&(frame[11] as u16)).cloned()
}

pub(super) fn parse_packet_destination_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

pub(super) fn build_injected_packet(
    req: &InjectPacketRequest,
    dst: IpAddr,
    resolution: ForwardingResolution,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let dst_mac = resolution
        .neighbor_mac
        .ok_or_else(|| "missing neighbor MAC".to_string())?;
    match dst {
        IpAddr::V4(dst_v4) => build_injected_ipv4(req, dst_mac, dst_v4, egress),
        IpAddr::V6(dst_v6) => build_injected_ipv6(req, dst_mac, dst_v6, egress),
    }
}

/// Build a forwarded frame for NAT64 packets. NAT64 changes the IP address
/// family so the frame size changes (IPv6→IPv4 shrinks by 20, IPv4→IPv6 grows
/// by 20). This always uses a copy path — in-place rewrite is not possible.
pub(super) fn build_nat64_forwarded_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    nat64_reverse: Option<&Nat64ReverseInfo>,
) -> Option<Vec<u8>> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;

    match meta.addr_family as i32 {
        libc::AF_INET6 => {
            // Forward direction: IPv6 → IPv4.
            let snat_v4 = match decision.nat.rewrite_src {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            let dst_v4 = match decision.nat.rewrite_dst {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            crate::nat64::build_nat64_v6_to_v4_frame(
                frame, snat_v4, dst_v4, dst_mac, src_mac, vlan_id,
            )
        }
        libc::AF_INET => {
            // Reverse direction: IPv4 → IPv6 (reply from server).
            let info = nat64_reverse?;
            // Reply: src_v6 = original dst (NAT64 prefix + server), dst_v6 = original client
            crate::nat64::build_nat64_v4_to_v6_frame(
                frame,
                info.orig_dst_v6,
                info.orig_src_v6,
                dst_mac,
                src_mac,
                vlan_id,
            )
        }
        _ => None,
    }
}

pub(super) fn build_forwarded_frame_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; frame.len().saturating_add(4)];
    let written = build_forwarded_frame_into_from_frame(
        &mut out,
        frame,
        meta,
        decision,
        forwarding,
        apply_nat_on_fabric,
        expected_ports,
    )?;
    out.truncate(written);
    if decision.resolution.tunnel_endpoint_id != 0 {
        return encapsulate_native_gre_frame(&out, meta, decision, forwarding);
    }
    Some(out)
}

pub(super) fn segment_forwarded_tcp_frames_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    if meta.protocol != PROTO_TCP {
        return None;
    }
    let mtu = if decision.resolution.tunnel_endpoint_id != 0 {
        native_gre_inner_mtu(forwarding, decision)
    } else {
        forwarding
            .egress
            .get(&decision.resolution.egress_ifindex)
            .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
            .map(|egress| egress.mtu)
            .unwrap_or_default()
    }
    .max(1280);
    if mtu == 0 {
        return None;
    }
    let Some(l3) = frame_l3_offset(frame) else {
        return None;
    };
    if l3 >= frame.len() {
        return None;
    }
    let payload = &frame[l3..];
    if payload.len() <= mtu {
        return None;
    }
    let Some(frame_l4) = frame_l4_offset(frame, meta.addr_family) else {
        return None;
    };
    let Some(tcp_offset) = frame_l4.checked_sub(l3) else {
        return None;
    };
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
    let Some(segment_payload_max) = mtu.checked_sub(ip_header_len + tcp_header_len) else {
        return None;
    };
    if segment_payload_max == 0 {
        return None;
    }
    let Some(data) = payload.get(tcp_offset + tcp_header_len..) else {
        return None;
    };
    if data.len() <= segment_payload_max {
        return None;
    }

    let Some(dst_mac) = decision.resolution.neighbor_mac else {
        return None;
    };
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
    let enforced_ports = expected_ports.or(live_frame_ports_bytes(
        frame,
        meta.addr_family,
        meta.protocol,
    ));
    let Some(tcp_header) = payload.get(tcp_offset..tcp_offset + tcp_header_len) else {
        return None;
    };
    let Some(ip_header) = payload.get(..ip_header_len) else {
        return None;
    };
    let mut out = Vec::with_capacity((data.len() / segment_payload_max) + 1);
    let mut data_offset = 0usize;
    while data_offset < data.len() {
        let chunk_len = (data.len() - data_offset).min(segment_payload_max);
        let is_last = data_offset + chunk_len == data.len();
        let total_ip_len = ip_header_len + tcp_header_len + chunk_len;
        let mut frame_out = vec![0u8; eth_len + total_ip_len];
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
                    &mut frame_out,
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
                    &mut frame_out,
                    meta.addr_family,
                    meta.protocol,
                    enforced_ports,
                )?;
                let packet = frame_out.get_mut(eth_len..)?;
                recompute_l4_checksum_ipv6(packet, meta.protocol)?;
            }
            _ => return None,
        }
        if decision.resolution.tunnel_endpoint_id != 0 {
            out.push(encapsulate_native_gre_frame(
                &frame_out, meta, decision, forwarding,
            )?);
        } else {
            out.push(frame_out);
        }
        data_offset += chunk_len;
    }
    Some(out)
}

fn segment_forwarded_tcp_frames_into_prepared(
    target_binding: &mut BindingWorker,
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
    flow_key: Option<SessionKey>,
    now_ns: u64,
    post_recycles: &mut Vec<(u32, u64)>,
) -> Option<(u32, u64, u32)> {
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
        let _ = drain_pending_tx(target_binding, now_ns, post_recycles);
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
    let enforced_ports = expected_ports.or(live_frame_ports_bytes(
        frame,
        meta.addr_family,
        meta.protocol,
    ));
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

pub(super) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let enforced_ports = expected_ports;
    // Use meta L3 offset when it's a valid Ethernet header size (14 or 18),
    // otherwise re-derive from the frame's ethertype.
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    if l3 >= frame.len() {
        return None;
    }
    let raw_payload = &frame[l3..];
    // Trim Ethernet padding: use ip_total_len so we don't carry trailing
    // pad bytes (small frames padded to 60/64 by hardware).
    let payload = if raw_payload.len() >= 4 {
        let ip_version = raw_payload[0] >> 4;
        if ip_version == 4 {
            let ip_total_len = u16::from_be_bytes([raw_payload[2], raw_payload[3]]) as usize;
            if ip_total_len > 0 && ip_total_len < raw_payload.len() {
                &raw_payload[..ip_total_len]
            } else {
                raw_payload
            }
        } else if ip_version == 6 && raw_payload.len() >= 40 {
            let ipv6_payload_len = u16::from_be_bytes([raw_payload[4], raw_payload[5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < raw_payload.len() {
                &raw_payload[..ip6_total]
            } else {
                raw_payload
            }
        } else {
            raw_payload
        }
    } else {
        raw_payload
    };
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
    let frame_len = eth_len + payload.len();
    if frame_len > out.len() {
        return None;
    }
    write_eth_header_slice(
        out.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    let payload_out = out.get_mut(eth_len..frame_len)?;
    // SAFETY: source (payload) and destination (payload_out) are distinct
    // buffers — payload is from the ingress UMEM, payload_out is in the
    // egress UMEM. Lengths are equal because both span eth_len..frame_len.
    debug_assert_eq!(payload_out.len(), payload.len());
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), payload_out.as_mut_ptr(), payload.len());
    }
    let out = &mut out[..frame_len];
    let force_tunnel_l4_recompute = decision.resolution.tunnel_endpoint_id != 0;
    let tunnel_tcp_mss = native_gre_tcp_mss(forwarding, decision, meta.addr_family);
    let ip_start = eth_len;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if out.len() < ip_start + 20 {
                return None;
            }
            let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
            if ihl < 20 || out.len() < ip_start + ihl {
                return None;
            }
            if (meta.meta_flags & 0x80) == 0 && out[ip_start + 8] <= 1 {
                return None;
            }
            let old_src = Ipv4Addr::new(
                out[ip_start + 12],
                out[ip_start + 13],
                out[ip_start + 14],
                out[ip_start + 15],
            );
            let old_dst = Ipv4Addr::new(
                out[ip_start + 16],
                out[ip_start + 17],
                out[ip_start + 18],
                out[ip_start + 19],
            );
            let old_ttl = out[ip_start + 8];
            // IHL already computed above — use directly instead of re-parsing.
            let rel_l4 = ihl;
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv4(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            let skip_ttl = (meta.meta_flags & 0x80) != 0;
            if !skip_ttl {
                out[ip_start + 8] -= 1;
            }
            let enforced = enforce_expected_ports_at(
                out,
                ip_start,
                ip_start + rel_l4,
                meta.addr_family,
                meta.protocol,
                enforced_ports,
            )
            .unwrap_or(false);
            adjust_ipv4_header_checksum(
                &mut out[ip_start..ip_start + ihl],
                old_src,
                old_dst,
                old_ttl,
            )?;
            if tunnel_tcp_mss > 0 {
                let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
            }
            if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
                recompute_l4_checksum_ipv4(&mut out[ip_start..], ihl, meta.protocol, true)?;
            }
        }
        libc::AF_INET6 => {
            if out.len() < ip_start + 40 {
                return None;
            }
            if (meta.meta_flags & 0x80) == 0 && out[ip_start + 7] <= 1 {
                return None;
            }
            // Use meta-derived L4 offset when valid (>= 40 for IPv6 base header,
            // avoids walking extension headers). Fall back to parsing otherwise.
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&out[ip_start..], meta.addr_family)?
            };
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv6(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            if (meta.meta_flags & 0x80) == 0 {
                out[ip_start + 7] -= 1;
            }
            let enforced = enforce_expected_ports_at(
                out,
                ip_start,
                ip_start + rel_l4,
                meta.addr_family,
                meta.protocol,
                enforced_ports,
            )
            .unwrap_or(false);
            if tunnel_tcp_mss > 0 {
                let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
            }
            if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
                recompute_l4_checksum_ipv6(&mut out[ip_start..], meta.protocol)?;
            }
        }
        _ => return None,
    }
    // Debug: dump first N built frames' Ethernet + IP headers to see post-NAT on wire
    if cfg!(feature = "debug-log") {
        thread_local! {
            static BUILD_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        BUILD_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 30 {
                c.set(n + 1);
                let pkt_detail = decode_frame_summary(out);
                eprintln!(
                    "DBG BUILT_ETH[{}]: vlan={} frame_len={} proto={} {}",
                    n, vlan_id, frame_len, meta.protocol, pkt_detail,
                );
                // For the first 3 frames, also dump the full IP+TCP header hex
                if n < 3 {
                    let dump_len = frame_len.min(out.len()).min(eth_len + 60);
                    let hex: String = out[..dump_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("DBG BUILT_HEX[{n}]: {hex}");
                }
            }
        });
    }
    // Checksum verification: recompute from scratch and compare to incremental update.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&out[..frame_len]);
    }

    // RST corruption check: detect if frame building introduced a TCP RST
    // that wasn't in the source frame.
    if cfg!(feature = "debug-log") {
        let out_has_rst = frame_has_tcp_rst(&out[..frame_len]);
        let in_has_rst = frame_has_tcp_rst(frame);
        if out_has_rst && !in_has_rst {
            thread_local! {
                static BUILD_RST_CORRUPT_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            }
            BUILD_RST_CORRUPT_COUNT.with(|c| {
                let n = c.get();
                if n < 20 {
                    c.set(n + 1);
                    let in_summary = decode_frame_summary(frame);
                    let out_summary = decode_frame_summary(&out[..frame_len]);
                    eprintln!(
                        "RST_CORRUPT BUILD[{}]: frame build INTRODUCED RST! in=[{}] out=[{}]",
                        n, in_summary, out_summary,
                    );
                    let in_hex_len = frame.len().min(80);
                    let in_hex: String = frame[..in_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let out_hex_len = frame_len.min(out.len()).min(80);
                    let out_hex: String = out[..out_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("RST_CORRUPT IN_HEX[{n}]: {in_hex}");
                    eprintln!("RST_CORRUPT OUT_HEX[{n}]: {out_hex}");
                }
            });
        }
    }
    Some(frame_len)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_forwarded_frame(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_forwarded_frame_from_frame(frame, meta, decision, forwarding, false, expected_ports)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn segment_forwarded_tcp_frames(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    segment_forwarded_tcp_frames_from_frame(
        frame,
        meta,
        decision,
        forwarding,
        false,
        expected_ports,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_forwarded_frame_into(
    out: &mut [u8],
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_forwarded_frame_into_from_frame(
        out,
        frame,
        meta,
        decision,
        forwarding,
        false,
        expected_ports,
    )
}

pub(super) fn rewrite_forwarded_frame_in_place(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    expected_ports: Option<(u16, u16)>,
) -> Option<u32> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let enforced_ports = expected_ports;
    let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, UMEM_FRAME_SIZE as usize)? };
    let current_len = desc.len as usize;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(&frame[..current_len])?,
    };
    if l3 >= current_len {
        return None;
    }
    let mut payload_len = current_len.checked_sub(l3)?;
    // Trim Ethernet padding: use ip_total_len when available so we don't
    // carry trailing pad bytes (small frames padded to 60/64 by hardware).
    if payload_len >= 4 {
        let ip_version = frame[l3] >> 4;
        if ip_version == 4 {
            let ip_total_len = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]) as usize;
            if ip_total_len > 0 && ip_total_len < payload_len {
                payload_len = ip_total_len;
            }
        } else if ip_version == 6 && payload_len >= 40 {
            let ipv6_payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < payload_len {
                payload_len = ip6_total;
            }
        }
    }
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                false,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18usize } else { 14usize };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let frame_len = eth_len.checked_add(payload_len)?;
    if frame_len > frame.len() {
        return None;
    }
    if eth_len != l3 {
        frame.copy_within(l3..l3 + payload_len, eth_len);
    }
    write_eth_header_slice(
        frame.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    let packet = &mut frame[..frame_len];
    let ip_start = eth_len;
    // Fabric-ingress packets already had TTL decremented by the sending peer.
    let skip_ttl = (meta.meta_flags & 0x80) != 0;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < ip_start + 20 {
                return None;
            }
            let ihl = ((packet[ip_start] & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ip_start + ihl {
                return None;
            }
            if !skip_ttl && packet[ip_start + 8] <= 1 {
                return None;
            }
            let old_src = Ipv4Addr::new(
                packet[ip_start + 12],
                packet[ip_start + 13],
                packet[ip_start + 14],
                packet[ip_start + 15],
            );
            let old_dst = Ipv4Addr::new(
                packet[ip_start + 16],
                packet[ip_start + 17],
                packet[ip_start + 18],
                packet[ip_start + 19],
            );
            let old_ttl = packet[ip_start + 8];
            let rel_l4 = ihl;
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv4(&mut packet[ip_start..], meta.protocol, decision.nat)?;
            }
            if !skip_ttl {
                packet[ip_start + 8] -= 1;
            }
            adjust_ipv4_header_checksum(
                &mut packet[ip_start..ip_start + ihl],
                old_src,
                old_dst,
                old_ttl,
            )?;
            let enforced =
                enforce_expected_ports(packet, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv4(&mut packet[ip_start..], ihl, meta.protocol, true)?;
            }
        }
        libc::AF_INET6 => {
            if packet.len() < ip_start + 40 {
                return None;
            }
            if !skip_ttl && packet[ip_start + 7] <= 1 {
                return None;
            }
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&packet[ip_start..], meta.addr_family)?
            };
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv6(&mut packet[ip_start..], meta.protocol, decision.nat)?;
            }
            if !skip_ttl {
                packet[ip_start + 7] -= 1;
            }
            let enforced =
                enforce_expected_ports(packet, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv6(&mut packet[ip_start..], meta.protocol)?;
            }
        }
        _ => return None,
    }
    // Debug: dump first N in-place rewritten frames' Ethernet headers
    #[cfg(feature = "debug-log")]
    {
        thread_local! {
            static INPLACE_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        INPLACE_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 10 {
                c.set(n + 1);
                let hdr_len = eth_len.min(packet.len()).min(22);
                let hdr_hex: String = packet[..hdr_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                let ip_info = if meta.addr_family as i32 == libc::AF_INET && packet.len() >= ip_start + 20 {
                    format!("src={}.{}.{}.{} dst={}.{}.{}.{}",
                        packet[ip_start+12], packet[ip_start+13], packet[ip_start+14], packet[ip_start+15],
                        packet[ip_start+16], packet[ip_start+17], packet[ip_start+18], packet[ip_start+19])
                } else if meta.addr_family as i32 == libc::AF_INET6 && packet.len() >= ip_start + 40 {
                    let s = &packet[ip_start+8..ip_start+24];
                    let d = &packet[ip_start+24..ip_start+40];
                    format!("src={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x} dst={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],s[12],s[13],s[14],s[15],
                        d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15])
                } else {
                    "unknown-af".to_string()
                };
                debug_log!("DBG INPLACE_ETH[{}]: eth=[{}] vlan={} frame_len={} proto={} {}",
                    n, hdr_hex, vlan_id, frame_len, meta.protocol, ip_info,
                );
            }
        });
    }
    // Checksum verification for in-place path.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(frame_len as u32)
}

/// Straight-line frame rewrite using a precomputed `RewriteDescriptor`.
///
/// Eliminates per-packet branches for address family, VLAN presence, NAT type,
/// and checksum recomputation — all decisions are baked into the descriptor at
/// session / flow-cache insertion time.
///
/// Returns the new frame length on success, or `None` if the frame is corrupt,
/// too short, or has a port mismatch (caller falls back to generic rewrite).
///
/// **Scope**: IPv4/IPv6 TCP and UDP only (flow cache gates on ACK-only TCP + UDP).
/// Does NOT handle: ICMP identifier repair, NAT64 (header-size change), NPTv6
/// (checksum-neutral — no L4 csum adjust needed, but address rewrite differs).
#[inline]
pub(super) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &super::RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<u32> {
    // NAT64 and NPTv6 use the generic path — they need special handling.
    if rd.nat64 || rd.nptv6 {
        return None;
    }

    let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, UMEM_FRAME_SIZE as usize)? };
    let current_len = desc.len as usize;

    // L3 offset: trust XDP shim metadata when it's a standard value.
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(&frame[..current_len])?,
    };
    if l3 >= current_len {
        return None;
    }

    // Trim Ethernet padding using IP total length.
    let mut payload_len = current_len.checked_sub(l3)?;
    if payload_len >= 4 {
        let ip_version = frame[l3] >> 4;
        if ip_version == 4 {
            let ip_total_len = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]) as usize;
            if ip_total_len > 0 && ip_total_len < payload_len {
                payload_len = ip_total_len;
            }
        } else if ip_version == 6 && payload_len >= 40 {
            let ipv6_payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < payload_len {
                payload_len = ip6_total;
            }
        }
    }

    // Target Ethernet header length (14 = no VLAN, 18 = 802.1Q).
    let eth_len = if rd.tx_vlan_id > 0 { 18usize } else { 14usize };
    let frame_len = eth_len.checked_add(payload_len)?;
    if frame_len > frame.len() {
        return None;
    }

    // Shift payload if L3 offset changes (adding/removing VLAN tag).
    if eth_len != l3 {
        frame.copy_within(l3..l3 + payload_len, eth_len);
    }

    // Write Ethernet header — precomputed MACs, VLAN, ether_type.
    write_eth_header_slice(
        frame.get_mut(..eth_len)?,
        rd.dst_mac,
        rd.src_mac,
        rd.tx_vlan_id,
        rd.ether_type,
    )?;

    let packet = &mut frame[..frame_len];
    let ip = eth_len;
    let skip_ttl = (meta.meta_flags & 0x80) != 0;

    match rd.ether_type {
        0x0800 => {
            // ── IPv4 straight-line rewrite ──
            if packet.len() < ip + 20 {
                return None;
            }
            let ihl = ((packet[ip] & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ip + ihl {
                return None;
            }
            if !skip_ttl && packet[ip + 8] <= 1 {
                return None; // TTL expired
            }
            let l4 = ip + ihl;

            // Port validation (DMA race guard).
            // If ports don't match, fall back to generic path for repair.
            if let Some((exp_src, exp_dst)) = expected_ports {
                if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
                    let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
                    let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
                    if cur_src != exp_src || cur_dst != exp_dst {
                        return None;
                    }
                }
            }

            // NAT: direct byte writes for IP addresses.
            if let Some(IpAddr::V4(new_src)) = rd.rewrite_src_ip {
                packet[ip + 12..ip + 16].copy_from_slice(&new_src.octets());
            }
            if let Some(IpAddr::V4(new_dst)) = rd.rewrite_dst_ip {
                packet[ip + 16..ip + 20].copy_from_slice(&new_dst.octets());
            }

            // NAT: direct byte writes for L4 ports.
            if let Some(new_sport) = rd.rewrite_src_port {
                if packet.len() >= l4 + 2 {
                    packet[l4..l4 + 2].copy_from_slice(&new_sport.to_be_bytes());
                }
            }
            if let Some(new_dport) = rd.rewrite_dst_port {
                if packet.len() >= l4 + 4 {
                    packet[l4 + 2..l4 + 4].copy_from_slice(&new_dport.to_be_bytes());
                }
            }

            // TTL decrement (skip for fabric-ingress — peer already decremented).
            if !skip_ttl {
                packet[ip + 8] -= 1;
            }

            // IP header checksum: precomputed NAT delta + TTL-1 delta.
            let old_csum = u16::from_be_bytes([packet[ip + 10], packet[ip + 11]]);
            let mut sum = (!old_csum as u32) & 0xffff;
            sum += rd.ip_csum_delta as u32;
            if !skip_ttl {
                // TTL-1 delta is always 0xFEFF in one's complement arithmetic
                sum += 0xFEFF;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let new_csum = !(sum as u16);
            packet[ip + 10..ip + 12].copy_from_slice(&new_csum.to_be_bytes());

            // L4 checksum: precomputed delta covers IP + port changes.
            if rd.l4_csum_delta != 0 {
                let l4_csum_off = match meta.protocol {
                    PROTO_TCP => l4 + 16,
                    PROTO_UDP => l4 + 6,
                    _ => 0,
                };
                if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
                    let old_l4_csum =
                        u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
                    // Skip UDP checksum update if zero (no checksum, RFC 768).
                    if meta.protocol != PROTO_UDP || old_l4_csum != 0 {
                        let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                        l4sum += rd.l4_csum_delta as u32;
                        while (l4sum >> 16) != 0 {
                            l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                        }
                        let new_l4 = !(l4sum as u16);
                        // UDP: 0x0000 means "no checksum" — use 0xFFFF (RFC 768).
                        let final_csum = if meta.protocol == PROTO_UDP && new_l4 == 0 {
                            0xFFFFu16
                        } else {
                            new_l4
                        };
                        packet[l4_csum_off..l4_csum_off + 2]
                            .copy_from_slice(&final_csum.to_be_bytes());
                    }
                }
            }
        }
        0x86dd => {
            // ── IPv6 straight-line rewrite ──
            // No IP header checksum; only L4 pseudo-header changes matter.
            if packet.len() < ip + 40 {
                return None;
            }
            if !skip_ttl && packet[ip + 7] <= 1 {
                return None; // Hop limit expired
            }

            // L4 offset from metadata or by parsing extension headers.
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&packet[ip..], meta.addr_family)?
            };
            let l4 = ip + rel_l4;

            // Port validation (DMA race guard).
            if let Some((exp_src, exp_dst)) = expected_ports {
                if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
                    let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
                    let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
                    if cur_src != exp_src || cur_dst != exp_dst {
                        return None;
                    }
                }
            }

            // NAT: direct byte writes for IPv6 addresses.
            if let Some(IpAddr::V6(new_src)) = rd.rewrite_src_ip {
                packet[ip + 8..ip + 24].copy_from_slice(&new_src.octets());
            }
            if let Some(IpAddr::V6(new_dst)) = rd.rewrite_dst_ip {
                packet[ip + 24..ip + 40].copy_from_slice(&new_dst.octets());
            }

            // NAT: direct byte writes for L4 ports.
            if let Some(new_sport) = rd.rewrite_src_port {
                if packet.len() >= l4 + 2 {
                    packet[l4..l4 + 2].copy_from_slice(&new_sport.to_be_bytes());
                }
            }
            if let Some(new_dport) = rd.rewrite_dst_port {
                if packet.len() >= l4 + 4 {
                    packet[l4 + 2..l4 + 4].copy_from_slice(&new_dport.to_be_bytes());
                }
            }

            // Hop limit decrement (skip for fabric-ingress).
            if !skip_ttl {
                packet[ip + 7] -= 1;
            }

            // L4 checksum: precomputed delta covers IPv6 address + port changes.
            if rd.l4_csum_delta != 0 {
                let l4_csum_off = match meta.protocol {
                    PROTO_TCP => l4 + 16,
                    PROTO_UDP => l4 + 6,
                    PROTO_ICMPV6 => l4 + 2,
                    _ => 0,
                };
                if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
                    let old_l4_csum =
                        u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
                    let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                    l4sum += rd.l4_csum_delta as u32;
                    while (l4sum >> 16) != 0 {
                        l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                    }
                    let new_l4 = !(l4sum as u16);
                    // IPv6 UDP must have non-zero checksum; use 0xFFFF for all.
                    let final_csum = if new_l4 == 0 { 0xFFFFu16 } else { new_l4 };
                    packet[l4_csum_off..l4_csum_off + 2].copy_from_slice(&final_csum.to_be_bytes());
                }
            }
        }
        _ => return None,
    }

    // Checksum verification for descriptor path (debug only).
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(frame_len as u32)
}

pub(super) fn apply_nat_ipv4(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 20 {
        return None;
    }
    let old_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let old_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    // --- IP address rewriting ---
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        packet.get_mut(12..16)?.copy_from_slice(&new_src.octets());
        adjust_l4_checksum_ipv4_src(packet, ihl, protocol, old_src, new_src)?;
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        packet.get_mut(16..20)?.copy_from_slice(&new_dst.octets());
        adjust_l4_checksum_ipv4_dst(packet, ihl, protocol, old_dst, new_dst)?;
    } else if new_src.is_some() || new_dst.is_some() {
        if let Some(ip) = new_src {
            packet.get_mut(12..16)?.copy_from_slice(&ip.octets());
        }
        if let Some(ip) = new_dst {
            packet.get_mut(16..20)?.copy_from_slice(&ip.octets());
        }
        let new_src = new_src.unwrap_or(old_src);
        let new_dst = new_dst.unwrap_or(old_dst);
        match protocol {
            PROTO_TCP => {
                adjust_l4_checksum_ipv4(packet, ihl, protocol, old_src, new_src, old_dst, new_dst)?
            }
            PROTO_UDP => {
                let checksum_offset = ihl.checked_add(6)?;
                let keep_zero = packet
                    .get(checksum_offset..checksum_offset + 2)
                    .map(|bytes| bytes == [0, 0])
                    .unwrap_or(false);
                if !keep_zero {
                    adjust_l4_checksum_ipv4(
                        packet, ihl, protocol, old_src, new_src, old_dst, new_dst,
                    )?;
                }
            }
            _ => {}
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    apply_nat_port_rewrite(packet, ihl, protocol, nat)?;

    Some(())
}

pub(super) fn apply_nat_ipv6(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 40 {
        return None;
    }
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip.octets()),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip.octets()),
        _ => None,
    });

    // NPTv6 (RFC 6296): prefix translation is checksum-neutral by design --
    // the adjustment word preserves the ones-complement sum of the full address.
    // Skip L4 checksum updates entirely for NPTv6 rewrites.
    let skip_l4_csum = nat.nptv6;
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        packet.get_mut(8..24)?.copy_from_slice(&new_src);
        if !skip_l4_csum {
            let new_src_words = ipv6_words_from_octets(new_src);
            adjust_l4_checksum_ipv6_words(packet, protocol, &old_src_words, &new_src_words)?;
        }
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        packet.get_mut(24..40)?.copy_from_slice(&new_dst);
        if !skip_l4_csum {
            let new_dst_words = ipv6_words_from_octets(new_dst);
            adjust_l4_checksum_ipv6_words(packet, protocol, &old_dst_words, &new_dst_words)?;
        }
    } else if new_src.is_some() || new_dst.is_some() {
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        if let Some(ip) = new_src {
            packet.get_mut(8..24)?.copy_from_slice(&ip);
        }
        if let Some(ip) = new_dst {
            packet.get_mut(24..40)?.copy_from_slice(&ip);
        }
        if !skip_l4_csum {
            let new_src_words = new_src.map(ipv6_words_from_octets).unwrap_or(old_src_words);
            let new_dst_words = new_dst.map(ipv6_words_from_octets).unwrap_or(old_dst_words);
            match protocol {
                PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => {
                    adjust_l4_checksum_ipv6_words(
                        packet,
                        protocol,
                        &old_src_words,
                        &new_src_words,
                    )?;
                    adjust_l4_checksum_ipv6_words(
                        packet,
                        protocol,
                        &old_dst_words,
                        &new_dst_words,
                    )?;
                }
                _ => {}
            }
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    // IPv6 header is always 40 bytes (no IHL).
    apply_nat_port_rewrite(packet, 40, protocol, nat)?;

    Some(())
}

/// Rewrite L4 source/destination ports and incrementally update the L4 checksum.
/// Port rewriting MUST happen AFTER IP address rewriting to avoid double-counting
/// in the checksum. Skips ICMP (no ports).
pub(super) fn apply_nat_port_rewrite(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    nat: NatDecision,
) -> Option<()> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(());
    }
    if packet.len() < l4_offset + 4 {
        return Some(());
    }

    if let Some(new_src_port) = nat.rewrite_src_port {
        let port_offset = l4_offset; // TCP/UDP src port at offset +0
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_src_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_src_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_src_port)?;
        }
    }

    if let Some(new_dst_port) = nat.rewrite_dst_port {
        let port_offset = l4_offset + 2; // TCP/UDP dst port at offset +2
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_dst_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_dst_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_dst_port)?;
        }
    }

    Some(())
}

/// Incremental L4 checksum update for a single 16-bit port change.
pub(super) fn adjust_l4_checksum_port(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    old_port: u16,
    new_port: u16,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => l4_offset.checked_add(16)?,
        PROTO_UDP => l4_offset.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    // Skip UDP IPv4 checksum update when checksum is 0 (optional for IPv4 UDP)
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let mut updated = checksum16_adjust(current, &[old_port], &[new_port]);
    if matches!(protocol, PROTO_UDP) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(super) fn enforce_expected_ports(
    frame: &mut [u8],
    addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    let l3 = frame_l3_offset(frame)?;
    let l4 = frame_l4_offset(frame, addr_family)?;
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    let packet = frame.get_mut(l3..)?;
    let rel_l4 = l4.checked_sub(l3)?;
    if current_src != expected_src {
        packet
            .get_mut(rel_l4..rel_l4 + 2)?
            .copy_from_slice(&expected_src.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        packet
            .get_mut(rel_l4 + 2..rel_l4 + 4)?
            .copy_from_slice(&expected_dst.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_dst, expected_dst)?;
    }
    Some(true)
}

/// Like enforce_expected_ports, but takes pre-computed L3/L4 offsets to avoid
/// redundant header parsing in the hot path.
#[inline]
pub(super) fn enforce_expected_ports_at(
    frame: &mut [u8],
    l3: usize,
    l4: usize,
    _addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    let packet = frame.get_mut(l3..)?;
    let rel_l4 = l4.checked_sub(l3)?;
    if current_src != expected_src {
        packet
            .get_mut(rel_l4..rel_l4 + 2)?
            .copy_from_slice(&expected_src.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        packet
            .get_mut(rel_l4 + 2..rel_l4 + 4)?
            .copy_from_slice(&expected_dst.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_dst, expected_dst)?;
    }
    Some(true)
}

pub(super) fn restore_l4_tuple_from_meta(
    packet: &mut [u8],
    meta: UserspaceDpMeta,
    rel_l4: usize,
) -> Option<bool> {
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => Some(false),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let ident = packet.get_mut(rel_l4 + 4..rel_l4 + 6)?;
            let expected = meta.flow_src_port.to_be_bytes();
            let repaired = *ident != expected;
            if repaired {
                ident.copy_from_slice(&expected);
            }
            Some(repaired)
        }
        _ => Some(false),
    }
}

pub(super) fn build_injected_ipv4(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v4
        .ok_or_else(|| "egress interface has no IPv4 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 20 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 20 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x0800);

    let total_len = (20 + 8 + payload_len) as u16;
    let ip_start = frame.len();
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        1,
        0,
        0,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    let ip_sum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10] = (ip_sum >> 8) as u8;
    frame[ip_start + 11] = ip_sum as u8;

    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0, 0]);
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

pub(super) fn build_injected_ipv6(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    dst_ip: Ipv6Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v6
        .ok_or_else(|| "egress interface has no IPv6 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 40 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 40 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x86dd);
    let plen = (8 + payload_len) as u16;
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        58,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0, 0]);
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

pub(super) fn write_eth_header(
    buf: &mut Vec<u8>,
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    if vlan_id > 0 {
        buf.extend_from_slice(&0x8100u16.to_be_bytes());
        buf.extend_from_slice(&(vlan_id & 0x0fff).to_be_bytes());
    }
    buf.extend_from_slice(&ether_type.to_be_bytes());
}

pub(super) fn write_eth_header_slice(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    if buf.len() < eth_len {
        return None;
    }
    let ether_type_bytes = ether_type.to_be_bytes();
    // SAFETY: buf.len() >= eth_len is guaranteed by the guard above.
    // eth_len is 14 (no VLAN) or 18 (VLAN), so all writes are in-bounds.
    debug_assert!(buf.len() >= eth_len);
    unsafe {
        let ptr = buf.as_mut_ptr();
        core::ptr::copy_nonoverlapping(dst.as_ptr(), ptr, 6);
        core::ptr::copy_nonoverlapping(src.as_ptr(), ptr.add(6), 6);
        if vlan_id > 0 {
            core::ptr::copy_nonoverlapping(0x8100u16.to_be_bytes().as_ptr(), ptr.add(12), 2);
            core::ptr::copy_nonoverlapping(
                (vlan_id & 0x0fff).to_be_bytes().as_ptr(),
                ptr.add(14),
                2,
            );
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(16), 2);
        } else {
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(12), 2);
        }
    }
    Some(())
}

pub(super) fn checksum16(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn checksum16_add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        sum += (*last as u32) << 8;
    }
    sum
}

pub(super) fn checksum16_finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn checksum16_adjust(checksum: u16, old_words: &[u16], new_words: &[u16]) -> u16 {
    let mut sum = (!checksum as u32) & 0xffff;
    for word in old_words {
        sum += (!u32::from(*word)) & 0xffff;
    }
    for word in new_words {
        sum += u32::from(*word);
    }
    checksum16_finish(sum)
}

pub(super) fn ipv4_words(ip: Ipv4Addr) -> [u16; 2] {
    let octets = ip.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
}

#[allow(dead_code)]
pub(super) fn ipv6_words(ip: Ipv6Addr) -> [u16; 8] {
    ipv6_words_from_octets(ip.octets())
}

pub(super) fn ipv6_words_from_octets(octets: [u8; 16]) -> [u16; 8] {
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
        u16::from_be_bytes([octets[4], octets[5]]),
        u16::from_be_bytes([octets[6], octets[7]]),
        u16::from_be_bytes([octets[8], octets[9]]),
        u16::from_be_bytes([octets[10], octets[11]]),
        u16::from_be_bytes([octets[12], octets[13]]),
        u16::from_be_bytes([octets[14], octets[15]]),
    ]
}

pub(super) fn ipv6_words_from_slice(bytes: &[u8]) -> Option<[u16; 8]> {
    let octets: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
    Some(ipv6_words_from_octets(octets))
}

pub(super) fn adjust_ipv4_header_checksum(
    packet: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    old_ttl: u8,
) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    let current = u16::from_be_bytes([packet[10], packet[11]]);
    let new_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let new_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let old_ttl_word = u16::from_be_bytes([old_ttl, packet[9]]);
    let new_ttl_word = u16::from_be_bytes([packet[8], packet[9]]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    updated = checksum16_adjust(updated, &[old_ttl_word], &[new_ttl_word]);
    packet
        .get_mut(10..12)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(super) fn checksum16_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &(payload.len() as u32).to_be_bytes());
    sum = checksum16_add_bytes(sum, &[0, 0, 0, next_header]);
    sum = checksum16_add_bytes(sum, payload);
    checksum16_finish(sum)
}

pub(super) fn checksum16_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &[0, protocol]);
    sum = checksum16_add_bytes(sum, &(payload.len() as u16).to_be_bytes());
    sum = checksum16_add_bytes(sum, payload);
    checksum16_finish(sum)
}

pub(super) fn adjust_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    if matches!(protocol, PROTO_UDP) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[allow(dead_code)]
pub(super) fn adjust_l4_checksum_ipv6(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP => 40usize.checked_add(6)?,
        PROTO_ICMPV6 => 40usize.checked_add(2)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv6_words(old_src), &ipv6_words(new_src));
    updated = checksum16_adjust(updated, &ipv6_words(old_dst), &ipv6_words(new_dst));
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(super) fn adjust_l4_checksum_ipv4_src(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_src),
        &ipv4_words(new_src),
    )
}

pub(super) fn adjust_l4_checksum_ipv4_dst(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_dst),
        &ipv4_words(new_dst),
    )
}

pub(super) fn adjust_l4_checksum_ipv4_words(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let updated = checksum16_adjust(current, old_words, new_words);
    let updated = if matches!(protocol, PROTO_UDP) && updated == 0 {
        0xffff
    } else {
        updated
    };
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[allow(dead_code)]
pub(super) fn adjust_l4_checksum_ipv6_src(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_src), &ipv6_words(new_src))
}

#[allow(dead_code)]
pub(super) fn adjust_l4_checksum_ipv6_dst(
    packet: &mut [u8],
    protocol: u8,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_dst), &ipv6_words(new_dst))
}

pub(super) fn adjust_l4_checksum_ipv6_words(
    packet: &mut [u8],
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP => 40usize.checked_add(6)?,
        PROTO_ICMPV6 => 40usize.checked_add(2)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, old_words, new_words);
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(super) fn recompute_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    zero_offset: bool,
) -> Option<()> {
    let segment = packet.get(ihl..)?;
    match protocol {
        PROTO_TCP => {
            if segment.len() < 20 {
                return None;
            }
            packet.get_mut(ihl + 16..ihl + 18)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            packet
                .get_mut(ihl + 16..ihl + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if segment.len() < 8 {
                return None;
            }
            packet.get_mut(ihl + 6..ihl + 8)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            let sum = if zero_offset && sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(ihl + 6..ihl + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

pub(super) fn recompute_l4_checksum_ipv6(packet: &mut [u8], protocol: u8) -> Option<()> {
    let payload = packet.get(40..)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    match protocol {
        PROTO_TCP => {
            if payload.len() < 20 {
                return None;
            }
            packet.get_mut(40 + 16..40 + 18)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_TCP, packet.get(40..)?);
            packet
                .get_mut(40 + 16..40 + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if payload.len() < 8 {
                return None;
            }
            packet.get_mut(40 + 6..40 + 8)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_UDP, packet.get(40..)?);
            let sum = if sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(40 + 6..40 + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if payload.len() < 4 {
                return None;
            }
            packet.get_mut(40 + 2..40 + 4)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_ICMPV6, packet.get(40..)?);
            packet
                .get_mut(40 + 2..40 + 4)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

/// Verify IP + TCP/UDP checksums on a fully-built forwarded frame.
/// Returns (ip_ok, l4_ok). Logs mismatches for the first N frames.
pub(super) static CSUM_VERIFIED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(super) static CSUM_BAD_IP_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(super) static CSUM_BAD_L4_TOTAL: AtomicU64 = AtomicU64::new(0);

pub(super) fn verify_built_frame_checksums(frame: &[u8]) -> (bool, bool) {
    let l3 = match frame_l3_offset(frame) {
        Some(o) => o,
        None => return (true, true),
    };
    let packet = match frame.get(l3..) {
        Some(p) if p.len() >= 20 => p,
        _ => return (true, true),
    };
    // Only handle IPv4 TCP for now (main traffic under test).
    if (packet[0] >> 4) != 4 {
        return (true, true);
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return (true, true);
    }
    let protocol = packet[9];
    // --- IP header checksum verification ---
    let ip_header = match packet.get(..ihl) {
        Some(h) => h,
        None => return (true, true),
    };
    let ip_csum_in_frame = u16::from_be_bytes([ip_header[10], ip_header[11]]);
    // Compute from scratch: zero out checksum field, compute, compare.
    let mut ip_scratch = [0u8; 60]; // max IHL = 60
    let scratch = &mut ip_scratch[..ihl];
    scratch.copy_from_slice(ip_header);
    scratch[10] = 0;
    scratch[11] = 0;
    let expected_ip_csum = checksum16(scratch);
    let ip_ok = ip_csum_in_frame == expected_ip_csum;

    // --- IP total length consistency ---
    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let actual_l3_len = packet.len();
    if ip_total_len != actual_l3_len {
        thread_local! {
            static IP_LEN_MISMATCH_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        IP_LEN_MISMATCH_LOG.with(|c| {
            let n = c.get();
            if n < 20 {
                c.set(n + 1);
                #[cfg(feature = "debug-log")]
                {
                    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    debug_log!(
                        "IP_LEN_MISMATCH[{}]: ip_total_len={} actual_l3_len={} frame_len={} l3={} src={} dst={} proto={}",
                        n, ip_total_len, actual_l3_len, frame.len(), l3, src, dst, protocol,
                    );
                }
            }
        });
    }

    // --- L4 checksum verification (TCP or UDP) ---
    // Use ip_total_len to bound the L4 segment — Ethernet padding bytes beyond
    // ip_total_len must NOT be included in the checksum pseudo-header or payload.
    let l4_len = if ip_total_len > ihl {
        ip_total_len - ihl
    } else {
        0
    };
    let l4_ok = if protocol == PROTO_TCP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 20 => s,
            _ => return (ip_ok, true),
        };
        let tcp_csum_in_frame = u16::from_be_bytes([segment[16], segment[17]]);
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        // Build pseudo-header + TCP with checksum zeroed.
        let mut pseudo = Vec::with_capacity(12 + segment.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(PROTO_TCP);
        pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(segment);
        // Zero the checksum field in pseudo buffer (offset 12 + 16 = 28..30).
        let csum_off = 12 + 16;
        if pseudo.len() > csum_off + 1 {
            pseudo[csum_off] = 0;
            pseudo[csum_off + 1] = 0;
        }
        let expected_tcp_csum = checksum16(&pseudo);
        tcp_csum_in_frame == expected_tcp_csum
    } else if protocol == PROTO_UDP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 8 => s,
            _ => return (ip_ok, true),
        };
        let udp_csum_in_frame = u16::from_be_bytes([segment[6], segment[7]]);
        if udp_csum_in_frame == 0 {
            true // zero = no checksum
        } else {
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let mut pseudo = Vec::with_capacity(12 + segment.len());
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.push(0);
            pseudo.push(PROTO_UDP);
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(segment);
            let csum_off = 12 + 6;
            if pseudo.len() > csum_off + 1 {
                pseudo[csum_off] = 0;
                pseudo[csum_off + 1] = 0;
            }
            let expected_udp_csum = checksum16(&pseudo);
            let expected_udp_csum = if expected_udp_csum == 0 {
                0xffff
            } else {
                expected_udp_csum
            };
            udp_csum_in_frame == expected_udp_csum
        }
    } else {
        true
    };

    CSUM_VERIFIED_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !ip_ok {
        CSUM_BAD_IP_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if !l4_ok {
        CSUM_BAD_L4_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    thread_local! {
        static CSUM_VERIFY_COUNT: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
    }
    if !ip_ok || !l4_ok {
        CSUM_VERIFY_COUNT.with(|c| {
            let (total_bad, logged) = c.get();
            c.set((total_bad + 1, logged));
            if logged < 30 {
                c.set((total_bad + 1, logged + 1));
                let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                eprintln!("CSUM_BAD[{}]: ip_ok={} l4_ok={} proto={} ip_in={:#06x} ip_exp={:#06x} \
                     src={} dst={} frame_len={} l3={} ihl={}",
                    total_bad, ip_ok, l4_ok, protocol,
                    ip_csum_in_frame, expected_ip_csum,
                    src, dst, frame.len(), l3, ihl,
                );
                if !l4_ok && protocol == PROTO_TCP {
                    let segment = &packet[ihl..];
                    let tcp_csum = u16::from_be_bytes([segment[16], segment[17]]);
                    let tcp_src = u16::from_be_bytes([segment[0], segment[1]]);
                    let tcp_dst = u16::from_be_bytes([segment[2], segment[3]]);
                    // Recompute to show expected
                    let mut pseudo = Vec::with_capacity(12 + segment.len());
                    pseudo.extend_from_slice(&src.octets());
                    pseudo.extend_from_slice(&dst.octets());
                    pseudo.push(0);
                    pseudo.push(PROTO_TCP);
                    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
                    pseudo.extend_from_slice(segment);
                    pseudo[12 + 16] = 0;
                    pseudo[12 + 17] = 0;
                    let expected = checksum16(&pseudo);
                    eprintln!("CSUM_BAD_TCP[{}]: sport={} dport={} csum_in={:#06x} csum_exp={:#06x} seg_len={}",
                        total_bad, tcp_src, tcp_dst, tcp_csum, expected, segment.len(),
                    );
                    // Hex dump of first 60 bytes of frame for deep debug
                    if logged < 5 {
                        let hex_len = frame.len().min(80);
                        let hex: String = frame[..hex_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        eprintln!("CSUM_BAD_HEX[{}]: {}", total_bad, hex);
                    }
                }
            }
        });
    }
    (ip_ok, l4_ok)
}

pub(super) fn try_parse_metadata(area: &MmapArea, desc: XdpDesc) -> Option<UserspaceDpMeta> {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    if (desc.addr as usize) < meta_len {
        return None;
    }
    let meta_offset = (desc.addr as usize).checked_sub(meta_len)?;
    let bytes = area.slice(meta_offset, meta_len)?;
    let meta = unsafe { *(bytes.as_ptr() as *const UserspaceDpMeta) };
    if meta.magic != USERSPACE_META_MAGIC || meta.version != USERSPACE_META_VERSION {
        return None;
    }
    if meta.length as usize != meta_len {
        return None;
    }
    Some(meta)
}

/// Build an ICMPv6 Neighbor Solicitation frame (86 bytes).
/// Uses solicited-node multicast destination (ff02::1:ffXX:XXXX).
pub(super) fn build_ndp_neighbor_solicitation(
    src_mac: [u8; 6],
    src_ip: Ipv6Addr,
    target_ip: Ipv6Addr,
) -> Vec<u8> {
    let target_bytes = target_ip.octets();
    // Solicited-node multicast: ff02::1:ff00:0000 | last 24 bits of target
    let sol_node: [u8; 16] = [
        0xff,
        0x02,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x01,
        0xff,
        target_bytes[13],
        target_bytes[14],
        target_bytes[15],
    ];
    // Multicast MAC: 33:33:XX:XX:XX:XX (last 4 bytes of multicast IP)
    let dst_mac = [
        0x33,
        0x33,
        sol_node[12],
        sol_node[13],
        sol_node[14],
        sol_node[15],
    ];

    let mut frame = Vec::with_capacity(86);
    // Ethernet header (14 bytes)
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x86, 0xdd]); // ethertype: IPv6

    // IPv6 header (40 bytes)
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6, TC=0, flow=0
    frame.extend_from_slice(&[0x00, 0x20]); // payload length = 32 (NS + option)
    frame.push(58); // next header: ICMPv6
    frame.push(255); // hop limit
    frame.extend_from_slice(&src_ip.octets()); // source
    frame.extend_from_slice(&sol_node); // destination (solicited-node multicast)

    // ICMPv6 Neighbor Solicitation (32 bytes)
    // type=135, code=0, checksum placeholder, reserved(4), target(16), option(8)
    let icmpv6_start = frame.len();
    frame.push(135); // type: NS
    frame.push(0); // code
    frame.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
    frame.extend_from_slice(&target_bytes); // target address
    // Source link-layer address option (8 bytes)
    frame.push(1); // option type: source link-layer address
    frame.push(1); // option length: 1 (in units of 8 bytes)
    frame.extend_from_slice(&src_mac);

    // Compute ICMPv6 checksum using the existing helper.
    // checksum16_ipv6 expects the ICMPv6 body with the checksum field zeroed.
    let sol_node_addr = Ipv6Addr::from(sol_node);
    let csum = checksum16_ipv6(src_ip, sol_node_addr, 58, &frame[icmpv6_start..]);
    frame[icmpv6_start + 2] = (csum >> 8) as u8;
    frame[icmpv6_start + 3] = (csum & 0xff) as u8;

    frame
}

/// Build a 42-byte ARP request frame.
pub(super) fn build_arp_request(
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    // Ethernet header
    frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst: broadcast
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x08, 0x06]); // ethertype: ARP
    // ARP header
    frame.extend_from_slice(&[0x00, 0x01]); // hardware type: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // protocol type: IPv4
    frame.push(6); // hardware size
    frame.push(4); // protocol size
    frame.extend_from_slice(&[0x00, 0x01]); // opcode: request
    // Sender
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&src_ip.octets());
    // Target
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // target MAC: unknown
    frame.extend_from_slice(&target_ip.octets());
    frame
}
