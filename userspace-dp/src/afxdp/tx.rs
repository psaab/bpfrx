use super::*;

pub(super) fn reap_tx_completions(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> u32 {
    if binding.outstanding_tx == 0 {
        return 0;
    }
    let available = binding.device.available();
    if available == 0 {
        return 0;
    }
    let mut reaped = 0u32;
    binding.scratch_completed_offsets.clear();
    let mut completed = binding.device.complete(available);
    while let Some(offset) = completed.read() {
        binding.scratch_completed_offsets.push(offset);
        reaped += 1;
    }
    completed.release();
    drop(completed);
    for i in 0..binding.scratch_completed_offsets.len() {
        let offset = binding.scratch_completed_offsets[i];
        recycle_completed_tx_offset(binding, shared_recycles, offset);
    }
    binding.outstanding_tx = binding.outstanding_tx.saturating_sub(reaped);
    binding.dbg_completions_reaped += reaped as u64;
    binding
        .live
        .tx_completions
        .fetch_add(reaped as u64, Ordering::Relaxed);
    update_binding_debug_state(binding);
    reaped
}

pub(super) fn drain_pending_fill(binding: &mut BindingWorker, now_ns: u64) -> bool {
    if binding.pending_fill_frames.is_empty() {
        return false;
    }
    let batch_size = binding.pending_fill_frames.len().min(FILL_BATCH_SIZE);
    binding.scratch_fill.clear();
    while binding.scratch_fill.len() < batch_size {
        let Some(offset) = binding.pending_fill_frames.pop_front() else {
            break;
        };
        // Poison the frame before submitting to fill ring — the kernel should
        // overwrite this with real packet data on RX. If we ever read back the
        // poison pattern in the RX path, it means the kernel recycled a
        // descriptor without writing packet data (stale/uninit frame).
        if cfg!(feature = "debug-log") {
            if let Some(frame) =
                unsafe { binding.umem.area().slice_mut_unchecked(offset as usize, 8) }
            {
                frame.copy_from_slice(&0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes());
            }
        }
        binding.scratch_fill.push(offset);
    }
    if binding.scratch_fill.is_empty() {
        return false;
    }
    let inserted = {
        let mut fill = binding.device.fill(binding.scratch_fill.len() as u32);
        let inserted = fill.insert(binding.scratch_fill.iter().copied());
        fill.commit();
        inserted
    };
    if inserted == 0 {
        binding.dbg_fill_failed += binding.scratch_fill.len() as u64;
        for offset in binding.scratch_fill.drain(..).rev() {
            binding.pending_fill_frames.push_front(offset);
        }
        return false;
    }
    binding.dbg_fill_submitted += inserted as u64;
    if inserted < binding.scratch_fill.len() as u32 {
        binding.dbg_fill_failed += (binding.scratch_fill.len() as u32 - inserted) as u64;
        for offset in binding.scratch_fill.drain(inserted as usize..).rev() {
            binding.pending_fill_frames.push_front(offset);
        }
    }
    binding.scratch_fill.clear();
    // Only wake NAPI when the kernel signals it needs fill ring entries,
    // or as a safety net every FILL_WAKE_SAFETY_INTERVAL_NS to prevent
    // lost-wakeup stalls from the race between commit() and needs_wakeup.
    // Without the needs_wakeup gate, every drain triggers a sendto() syscall
    // (142K/sec at line rate), spending ~20% CPU in syscall entry/exit.
    if binding.device.needs_wakeup()
        || now_ns.saturating_sub(binding.last_rx_wake_ns) >= FILL_WAKE_SAFETY_INTERVAL_NS
    {
        maybe_wake_rx(binding, true, now_ns);
    }
    update_binding_debug_state(binding);
    true
}

pub(super) fn maybe_wake_rx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    // After submitting fill ring entries, we must kick NAPI so the driver
    // consumes them and posts new RX WQEs. Without this, mlx5 increments
    // rx_xsk_buff_alloc_err and silently drops all incoming packets.
    //
    // poll(POLLIN) triggers xsk_poll → ndo_xsk_wakeup(XDP_WAKEUP_RX),
    // which makes the driver consume fill ring entries and post WQEs.
    // sendto() only triggers XDP_WAKEUP_TX (TX kick), NOT RX fill ring
    // processing — using sendto() for RX wake was the root cause of
    // fill ring starvation on idle interfaces with zero-copy mlx5.
    if !force {
        binding.empty_rx_polls = binding.empty_rx_polls.saturating_add(1);
        if binding.empty_rx_polls < RX_WAKE_IDLE_POLLS {
            return;
        }
        if now_ns.saturating_sub(binding.last_rx_wake_ns) < RX_WAKE_MIN_INTERVAL_NS {
            return;
        }
    }
    let fd = binding.device.as_raw_fd();
    // Use poll(POLLIN) for RX wakeup — triggers XDP_WAKEUP_RX.
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    if rc >= 0 {
        binding.dbg_rx_wake_sendto_ok += 1;
    } else {
        binding.dbg_rx_wake_sendto_err += 1;
        binding.dbg_rx_wake_sendto_errno = unsafe { *libc::__errno_location() };
    }
    // Also sendto for TX completions (needed for copy mode and TX kick).
    unsafe {
        libc::sendto(
            fd,
            core::ptr::null_mut(),
            0,
            libc::MSG_DONTWAIT,
            core::ptr::null_mut(),
            0,
        );
    }
    binding.dbg_rx_wakeups += 1;
    binding.live.rx_wakeups.fetch_add(1, Ordering::Relaxed);
    binding.last_rx_wake_ns = now_ns;
    binding.empty_rx_polls = 0;
}

pub(super) fn pending_tx_capacity(ring_entries: u32) -> usize {
    (ring_entries as usize)
        .saturating_mul(PENDING_TX_LIMIT_MULTIPLIER)
        .max(TX_BATCH_SIZE.saturating_mul(2))
}

pub(super) fn bound_pending_tx_local(binding: &mut BindingWorker) {
    while binding.pending_tx_local.len() > binding.max_pending_tx {
        if binding.pending_tx_local.pop_front().is_some() {
            binding.dbg_pending_overflow += 1;
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: dedicated drop-reason counter. Subset of tx_errors.
            binding
                .live
                .pending_tx_local_overflow_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(format!(
                "pending TX local overflow on slot {}",
                binding.slot
            ));
        }
    }
}

pub(super) fn bound_pending_tx_prepared(binding: &mut BindingWorker) {
    let limit = binding.max_pending_tx;
    while binding.pending_tx_prepared.len() > limit {
        if let Some(req) = binding.pending_tx_prepared.pop_front() {
            binding.dbg_pending_overflow += 1;
            recycle_prepared_immediately(binding, &req);
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: same drop category — prepared vs local FIFO is an
            // internal distinction irrelevant to the operator.
            binding
                .live
                .pending_tx_local_overflow_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(format!(
                "pending TX prepared overflow on slot {}",
                binding.slot
            ));
        }
    }
}

pub(super) fn drain_pending_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    _cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    _cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    if !binding_has_pending_tx_work(binding) {
        return false;
    }
    let mut did_work = reap_tx_completions(binding, shared_recycles) > 0;
    // In copy mode, the kernel needs sendto() to process TX ring entries.
    // If outstanding entries remain after reaping (kernel didn't finish in
    // the previous kick), re-kick now so they don't stall forever.
    if binding.outstanding_tx > 0
        && binding.pending_tx_prepared.is_empty()
        && binding.pending_tx_local.is_empty()
    {
        maybe_wake_tx(binding, false, now_ns);
    }
    ingest_cos_pending_tx(
        binding,
        forwarding,
        now_ns,
        worker_id,
        worker_commands_by_id,
    );
    // Only continue this loop while shaped service is making real forward
    // progress. A retrying CoS batch (for example, no free TX frame on the
    // owner binding) must yield back to the worker loop so other bindings can
    // run and completions/recycles can free resources.
    while drain_shaped_tx(binding, now_ns, shared_recycles) {
        did_work = true;
    }
    while !binding.pending_tx_prepared.is_empty() {
        match transmit_prepared_batch(binding, now_ns) {
            Ok((packets, bytes)) => {
                if packets == 0 {
                    break;
                }
                did_work = true;
                binding
                    .live
                    .tx_packets
                    .fetch_add(packets, Ordering::Relaxed);
                binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            Err(TxError::Retry(err)) => {
                binding.live.set_error(err);
                return true;
            }
            Err(TxError::Drop(err)) => {
                binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                // #710: frame-level submit error (capacity / slice /
                // other `TxError::Drop`). Subset of tx_errors.
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(1, Ordering::Relaxed);
                binding.live.set_error(err);
            }
        }
    }
    if binding.pending_tx_local.is_empty() && binding.live.pending_tx_empty() {
        update_binding_debug_state(binding);
        return did_work || binding_has_pending_tx_work(binding);
    }
    let mut pending = take_pending_tx_requests(binding);
    if pending.is_empty() {
        return did_work || binding_has_pending_tx_work(binding);
    }
    let mut retry = VecDeque::new();
    while let Some(req) = pending.pop_front() {
        retry.push_back(req);
        if retry.len() >= TX_BATCH_SIZE || binding.free_tx_frames.is_empty() || pending.is_empty() {
            match transmit_batch(binding, &mut retry, now_ns, shared_recycles) {
                Ok((packets, bytes)) => {
                    if packets > 0 {
                        did_work = true;
                        binding
                            .live
                            .tx_packets
                            .fetch_add(packets, Ordering::Relaxed);
                        binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                    }
                }
                Err(TxError::Retry(err)) => {
                    binding.live.set_error(err);
                    retry.append(&mut pending);
                    break;
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                }
            }
        }
    }
    if !retry.is_empty() {
        restore_pending_tx_requests(binding, retry);
    }
    update_binding_debug_state(binding);
    did_work || binding_has_pending_tx_work(binding)
}

pub(super) enum TxError {
    Retry(String),
    Drop(String),
}

#[derive(Clone, Copy)]
enum CoSServicePhase {
    Guarantee,
    Surplus,
}

enum CoSBatch {
    Local {
        queue_idx: usize,
        phase: CoSServicePhase,
        batch_bytes: u64,
        items: VecDeque<TxRequest>,
    },
    Prepared {
        queue_idx: usize,
        phase: CoSServicePhase,
        batch_bytes: u64,
        items: VecDeque<PreparedTxRequest>,
    },
}

#[derive(Clone, Copy)]
enum ExactCoSQueueKind {
    Local,
    Prepared,
}

#[derive(Clone, Copy)]
struct ExactCoSQueueSelection {
    queue_idx: usize,
    secondary_budget: u64,
    kind: ExactCoSQueueKind,
}

enum ExactCoSScratchBuild {
    Ready,
    Drop { error: String, dropped_bytes: u64 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CoSTxSelection {
    pub(super) queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
}

fn map_cached_forwarding_class_queue(
    iface: &CoSInterfaceConfig,
    forwarding_class: Option<&Arc<str>>,
) -> Option<u8> {
    forwarding_class.and_then(|class| iface.queue_by_forwarding_class.get(class.as_ref()).copied())
}

pub(super) fn resolve_cached_cos_tx_selection(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: UserspaceDpMeta,
    flow_key: Option<&SessionKey>,
) -> CachedTxSelectionDescriptor {
    let iface = forwarding.cos.interfaces.get(&egress_ifindex);
    let Some(flow_key) = flow_key else {
        return CachedTxSelectionDescriptor {
            queue_id: iface.map(|iface| iface.default_queue),
            dscp_rewrite: None,
            filter_counter: None,
        };
    };

    let is_v6 = meta.addr_family as i32 == libc::AF_INET6;
    let has_output_tx_eval = crate::filter::interface_output_filter_needs_tx_eval(
        &forwarding.filter_state,
        egress_ifindex,
        is_v6,
    );
    let has_input_tx_selection =
        crate::filter::filter_state_has_input_tx_selection(&forwarding.filter_state, is_v6);
    if iface.is_none() && !has_output_tx_eval && !has_input_tx_selection {
        return CachedTxSelectionDescriptor::default();
    }
    let output_filter = if has_output_tx_eval {
        if is_v6 {
            forwarding
                .filter_state
                .iface_filter_out_v6_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        } else {
            forwarding
                .filter_state
                .iface_filter_out_v4_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        }
    } else {
        None
    };
    let output_result = output_filter
        .filter(|filter| filter.affects_tx_selection || filter.has_counter_terms)
        .map(|filter| {
            crate::filter::evaluate_filter_ref_tx_selection_cached(
                filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
            )
        })
        .unwrap_or_default();

    let mut effective_dscp_rewrite = output_result.dscp_rewrite;
    let mut forwarding_class = output_result.forwarding_class.clone();
    let mut filter_counter = output_result.counter.clone();

    if output_filter.is_none() && has_input_tx_selection {
        let ingress_ifindex = resolve_ingress_logical_ifindex(
            forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        let ingress_filter = if is_v6 {
            forwarding
                .filter_state
                .iface_filter_v6_fast
                .get(&ingress_ifindex)
                .map(Arc::as_ref)
        } else {
            forwarding
                .filter_state
                .iface_filter_v4_fast
                .get(&ingress_ifindex)
                .map(Arc::as_ref)
        };
        if let Some(ingress_filter) = ingress_filter.filter(|filter| filter.affects_tx_selection) {
            let ingress_result = crate::filter::evaluate_filter_ref_tx_selection_cached(
                ingress_filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
            );
            effective_dscp_rewrite = effective_dscp_rewrite.or(ingress_result.dscp_rewrite);
            forwarding_class = ingress_result.forwarding_class;
            filter_counter = ingress_result.counter;
        }
    }

    let queue_id = iface.and_then(|iface| {
        map_cached_forwarding_class_queue(iface, forwarding_class.as_ref())
            .or_else(|| resolve_cos_dscp_classifier_queue_id(iface, meta.dscp))
            .or_else(|| {
                resolve_cos_ieee8021_classifier_queue_id(
                    iface,
                    meta.ingress_pcp,
                    meta.ingress_vlan_present != 0,
                )
            })
            .or(Some(iface.default_queue))
    });

    CachedTxSelectionDescriptor {
        queue_id,
        dscp_rewrite: effective_dscp_rewrite,
        filter_counter,
    }
}

fn binding_has_pending_tx_work(binding: &BindingWorker) -> bool {
    binding.outstanding_tx > 0
        || !binding.pending_tx_prepared.is_empty()
        || !binding.pending_tx_local.is_empty()
        || !binding.live.pending_tx_empty()
        || binding.cos_nonempty_interfaces > 0
}

pub(super) fn drain_pending_tx_local_owner(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    drain_pending_tx(
        binding,
        now_ns,
        shared_recycles,
        forwarding,
        worker_id,
        worker_commands_by_id,
        cos_owner_worker_by_queue,
        cos_owner_live_by_queue,
    )
}

fn ingest_cos_pending_tx(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) {
    if forwarding.cos.interfaces.is_empty() {
        return;
    }

    if !binding.pending_tx_prepared.is_empty() {
        let mut pending = core::mem::take(&mut binding.pending_tx_prepared);
        process_pending_queue_in_place(&mut pending, |req| {
            let req = match redirect_prepared_cos_request_to_owner(
                binding,
                req,
                worker_id,
                worker_commands_by_id,
            ) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            };
            let req = match redirect_prepared_cos_request_to_owner_binding(binding, req) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            };
            match enqueue_prepared_into_cos(binding, forwarding, req, now_ns) {
                Ok(()) => Ok(()),
                Err(req) => Err(req),
            }
        });
        binding.pending_tx_prepared = pending;
    }

    let mut pending = core::mem::take(&mut binding.pending_tx_local);
    binding.live.take_pending_tx_into(&mut pending);
    process_pending_queue_in_place(&mut pending, |req| {
        let req = match redirect_local_cos_request_to_owner(
            &binding.cos_fast_interfaces,
            req,
            worker_id,
            worker_commands_by_id,
        ) {
            Ok(()) => return Ok(()),
            Err(req) => req,
        };
        let req = match redirect_local_cos_request_to_owner_binding(
            &binding.live,
            &binding.cos_fast_interfaces,
            req,
        ) {
            Ok(()) => return Ok(()),
            Err(req) => req,
        };
        match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
            Ok(()) => Ok(()),
            Err(req) => Err(req),
        }
    });
    binding.pending_tx_local = pending;
    bound_pending_tx_local(binding);
}

#[inline]
fn cos_fast_interface<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
) -> Option<&'a WorkerCoSInterfaceFastPath> {
    cos_fast_interfaces.get(&egress_ifindex)
}

#[inline]
fn cos_fast_queue<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<(&'a WorkerCoSInterfaceFastPath, &'a WorkerCoSQueueFastPath)> {
    let iface = cos_fast_interface(cos_fast_interfaces, egress_ifindex)?;
    let queue = iface.queue_fast_path(requested_queue_id)?;
    Some((iface, queue))
}

fn redirect_local_cos_request_to_owner(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    req: TxRequest,
    current_worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> Result<(), TxRequest> {
    let Some((iface_fast, queue_fast)) =
        cos_fast_queue(cos_fast_interfaces, req.egress_ifindex, req.cos_queue_id)
    else {
        return Err(req);
    };
    if queue_fast.shared_exact && iface_fast.tx_owner_live.is_some() {
        return Err(req);
    }
    let owner_worker_id = queue_fast.owner_worker_id;
    if owner_worker_id == current_worker_id {
        return Err(req);
    }
    if let Some(owner_live) = queue_fast.owner_live.as_ref() {
        return owner_live.enqueue_tx_owned(req);
    }
    let Some(commands) = worker_commands_by_id.get(&owner_worker_id) else {
        return Err(req);
    };
    if let Ok(mut pending) = commands.lock() {
        pending.push_back(WorkerCommand::EnqueueShapedLocal(req));
        return Ok(());
    }
    Err(req)
}

fn redirect_local_cos_request_to_owner_binding(
    current_live: &Arc<BindingLiveState>,
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    req: TxRequest,
) -> Result<(), TxRequest> {
    // Caller ordering matters: shared exact queues that already have a local TX
    // path were filtered out in redirect_local_cos_request_to_owner().
    let Some(iface_fast) = cos_fast_interface(cos_fast_interfaces, req.egress_ifindex) else {
        return Err(req);
    };
    let Some(owner_live) = iface_fast.tx_owner_live.as_ref() else {
        return Err(req);
    };
    if Arc::ptr_eq(owner_live, current_live) {
        return Err(req);
    }
    owner_live.enqueue_tx_owned(req)
}

#[inline]
fn prepared_cos_request_stays_on_current_tx_binding(
    binding_ifindex: i32,
    iface_fast: &WorkerCoSInterfaceFastPath,
    queue_fast: &WorkerCoSQueueFastPath,
) -> bool {
    binding_ifindex == iface_fast.tx_ifindex && queue_fast.shared_exact
}

fn redirect_prepared_cos_request_to_owner(
    binding: &mut BindingWorker,
    req: PreparedTxRequest,
    current_worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> Result<(), PreparedTxRequest> {
    let Some((iface_fast, queue_fast)) = cos_fast_queue(
        &binding.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    ) else {
        return Err(req);
    };
    if queue_fast.shared_exact && iface_fast.tx_owner_live.is_some() {
        return Err(req);
    }
    let owner_worker_id = queue_fast.owner_worker_id;
    if owner_worker_id == current_worker_id {
        return Err(req);
    }
    let Some(frame) = binding
        .umem
        .area()
        .slice(req.offset as usize, req.len as usize)
        .map(|frame| frame.to_vec())
    else {
        return Err(req);
    };
    let local_req = TxRequest {
        bytes: frame,
        expected_ports: req.expected_ports,
        expected_addr_family: req.expected_addr_family,
        expected_protocol: req.expected_protocol,
        flow_key: req.flow_key.clone(),
        egress_ifindex: req.egress_ifindex,
        cos_queue_id: req.cos_queue_id,
        dscp_rewrite: req.dscp_rewrite,
    };
    if redirect_local_cos_request_to_owner(
        &binding.cos_fast_interfaces,
        local_req,
        current_worker_id,
        worker_commands_by_id,
    )
    .is_ok()
    {
        recycle_prepared_immediately(binding, &req);
        return Ok(());
    }
    Err(req)
}

fn redirect_prepared_cos_request_to_owner_binding(
    binding: &mut BindingWorker,
    req: PreparedTxRequest,
) -> Result<(), PreparedTxRequest> {
    let Some((iface_fast, queue_fast)) = cos_fast_queue(
        &binding.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    ) else {
        return Err(req);
    };
    // Keep shared exact traffic on the current binding when it already sits on
    // the resolved TX path; redirecting it sideways would force a copy back
    // into local TX instead of preserving the prepared path.
    if prepared_cos_request_stays_on_current_tx_binding(binding.ifindex, iface_fast, queue_fast) {
        return Err(req);
    }
    let Some(owner_live) = iface_fast.tx_owner_live.as_ref() else {
        return Err(req);
    };
    if Arc::ptr_eq(owner_live, &binding.live) {
        return Err(req);
    }
    let Some(frame) = binding
        .umem
        .area()
        .slice(req.offset as usize, req.len as usize)
        .map(|frame| frame.to_vec())
    else {
        return Err(req);
    };
    let local_req = TxRequest {
        bytes: frame,
        expected_ports: req.expected_ports,
        expected_addr_family: req.expected_addr_family,
        expected_protocol: req.expected_protocol,
        flow_key: req.flow_key.clone(),
        egress_ifindex: req.egress_ifindex,
        cos_queue_id: req.cos_queue_id,
        dscp_rewrite: req.dscp_rewrite,
    };
    if owner_live.enqueue_tx(local_req).is_ok() {
        recycle_prepared_immediately(binding, &req);
        return Ok(());
    }
    Err(req)
}

fn drain_shaped_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    if binding.cos_nonempty_interfaces == 0 || binding.cos_interface_order.is_empty() {
        return false;
    }
    let start = binding.cos_interface_rr % binding.cos_interface_order.len();
    for offset in 0..binding.cos_interface_order.len() {
        let root_ifindex =
            binding.cos_interface_order[(start + offset) % binding.cos_interface_order.len()];
        let Some(root) = binding.cos_interfaces.get(&root_ifindex) else {
            continue;
        };
        if root.nonempty_queues == 0 {
            continue;
        }
        if !prime_cos_root_for_service(binding, root_ifindex, now_ns) {
            continue;
        }
        if let Some(progress) =
            service_exact_guarantee_queue_direct(binding, root_ifindex, now_ns, shared_recycles)
        {
            binding.cos_interface_rr = (start + offset + 1) % binding.cos_interface_order.len();
            return progress;
        }
        let Some(batch) = build_nonexact_cos_batch(binding, root_ifindex, now_ns) else {
            continue;
        };
        binding.cos_interface_rr = (start + offset + 1) % binding.cos_interface_order.len();
        return submit_cos_batch(binding, root_ifindex, batch, now_ns, shared_recycles);
    }
    false
}

fn prime_cos_root_for_service(binding: &mut BindingWorker, root_ifindex: i32, now_ns: u64) -> bool {
    let shared_root_lease = binding
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.clone());
    let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
        return false;
    };
    advance_cos_timer_wheel(root, now_ns);
    if let Some(shared_root_lease) = shared_root_lease.as_ref() {
        maybe_top_up_cos_root_lease(root, shared_root_lease, now_ns);
    }
    true
}

fn build_nonexact_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
) -> Option<CoSBatch> {
    let selected = {
        let root = binding.cos_interfaces.get_mut(&root_ifindex)?;
        select_nonexact_cos_guarantee_batch(root, now_ns)
            .or_else(|| select_cos_surplus_batch(root, now_ns))
    };
    if selected.is_some() {
        refresh_cos_interface_activity(binding, root_ifindex);
    }
    selected
}

fn service_exact_guarantee_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<bool> {
    let queue_fast_path = binding
        .cos_fast_interfaces
        .get(&root_ifindex)?
        .queue_fast_path
        .as_slice();
    let selection = {
        let root = binding.cos_interfaces.get_mut(&root_ifindex)?;
        select_exact_cos_guarantee_queue_with_fast_path(root, queue_fast_path, now_ns)?
    };

    let progress = match selection.kind {
        ExactCoSQueueKind::Local => service_exact_local_queue_direct(
            binding,
            root_ifindex,
            selection.queue_idx,
            selection.secondary_budget,
            now_ns,
            shared_recycles,
        ),
        ExactCoSQueueKind::Prepared => service_exact_prepared_queue_direct(
            binding,
            root_ifindex,
            selection.queue_idx,
            selection.secondary_budget,
            now_ns,
        ),
    };
    Some(progress)
}

#[cfg(test)]
fn select_cos_guarantee_batch(root: &mut CoSInterfaceRuntime, now_ns: u64) -> Option<CoSBatch> {
    select_cos_guarantee_batch_with_fast_path(root, &[], now_ns)
}

// Legacy single-pass guarantee selector that walks both classes in one
// iteration. The production path in `drain_shaped_tx` no longer calls this
// (it uses the two specialized selectors for strict-priority exact-over-
// nonexact service); `select_cos_guarantee_batch_with_fast_path` is retained
// solely for unit-test coverage of the batch-build mechanics and is
// compiled out of non-test builds along with its `legacy_guarantee_rr`
// cursor. Uses its own cursor so test harnesses that call this do not
// corrupt the production `exact_guarantee_rr` / `nonexact_guarantee_rr`
// cursors and vice versa.
#[cfg(test)]
fn select_cos_guarantee_batch_with_fast_path(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
) -> Option<CoSBatch> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.legacy_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue) || !queue.runnable {
            continue;
        }
        if queue.exact {
            maybe_top_up_cos_queue_lease(
                queue,
                queue_fast_path
                    .get(queue_idx)
                    .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
                now_ns,
            );
        } else {
            refill_cos_tokens(
                &mut queue.tokens,
                queue.transmit_rate_bytes,
                queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
                &mut queue.last_refill_ns,
                now_ns,
            );
        }
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                queue.exact,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.tokens < head_len {
            if queue.exact {
                if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                    root.tokens,
                    root.shaping_rate_bytes,
                    queue.tokens,
                    queue.transmit_rate_bytes,
                    head_len,
                    now_ns,
                    true,
                ) {
                    count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                    park_cos_queue(root, queue_idx, wake_tick);
                }
            }
            continue;
        }
        root.legacy_guarantee_rr = (start + offset + 1) % queue_count;
        let guarantee_budget = queue
            .tokens
            .min(cos_guarantee_quantum_bytes(queue))
            .max(head_len);
        if let Some(batch) = build_cos_batch_from_queue(
            queue,
            queue_idx,
            root.tokens,
            guarantee_budget,
            CoSServicePhase::Guarantee,
        ) {
            return Some(batch);
        }
    }
    None
}

// Selects the next exact-class guarantee queue for service. Rotates
// independently of the non-exact pass via `exact_guarantee_rr` — the two
// classes are scheduled with strict-priority exact-over-nonexact and
// class-independent RR within each class.
fn select_exact_cos_guarantee_queue_with_fast_path(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
) -> Option<ExactCoSQueueSelection> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.exact_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue) || !queue.runnable || !queue.exact {
            continue;
        }
        maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        root.exact_guarantee_rr = (start + offset + 1) % queue_count;
        let secondary_budget = queue
            .tokens
            .min(cos_guarantee_quantum_bytes(queue))
            .max(head_len);
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget,
            kind,
        });
    }
    None
}

// Selects the next non-exact guarantee queue for service. Rotates
// independently of the exact pass via `nonexact_guarantee_rr` — a service
// event on an exact queue does not advance this cursor, so non-exact RR
// order is stable across bursts of exact-queue activity.
fn select_nonexact_cos_guarantee_batch(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
) -> Option<CoSBatch> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.nonexact_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue) || !queue.runnable || queue.exact {
            continue;
        }
        refill_cos_tokens(
            &mut queue.tokens,
            queue.transmit_rate_bytes,
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            &mut queue.last_refill_ns,
            now_ns,
        );
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                false,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.tokens < head_len {
            continue;
        }
        root.nonexact_guarantee_rr = (start + offset + 1) % queue_count;
        let guarantee_budget = queue
            .tokens
            .min(cos_guarantee_quantum_bytes(queue))
            .max(head_len);
        if let Some(batch) = build_cos_batch_from_queue(
            queue,
            queue_idx,
            root.tokens,
            guarantee_budget,
            CoSServicePhase::Guarantee,
        ) {
            return Some(batch);
        }
    }
    None
}

fn select_cos_surplus_batch(root: &mut CoSInterfaceRuntime, now_ns: u64) -> Option<CoSBatch> {
    for priority in 0..COS_PRIORITY_LEVELS {
        let indices_len = root.queue_indices_by_priority[priority].len();
        if indices_len == 0 {
            continue;
        }
        let start = root.rr_index_by_priority[priority] % indices_len;
        for offset in 0..indices_len {
            let queue_idx =
                root.queue_indices_by_priority[priority][(start + offset) % indices_len];
            let queue = &mut root.queues[queue_idx];
            if cos_queue_is_empty(queue) || !queue.runnable || queue.exact {
                continue;
            }
            let Some(head) = cos_queue_front(queue) else {
                continue;
            };
            let head_len = cos_item_len(head);
            if root.tokens < head_len {
                if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                    root.tokens,
                    root.shaping_rate_bytes,
                    queue.tokens,
                    queue.transmit_rate_bytes,
                    head_len,
                    now_ns,
                    false,
                ) {
                    count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                    park_cos_queue(root, queue_idx, wake_tick);
                }
                continue;
            }
            if queue.surplus_deficit < head_len {
                queue.surplus_deficit = queue
                    .surplus_deficit
                    .saturating_add(cos_surplus_quantum_bytes(queue));
                if queue.surplus_deficit < head_len {
                    continue;
                }
            }
            root.rr_index_by_priority[priority] = (start + offset + 1) % indices_len;
            if let Some(batch) = build_cos_batch_from_queue(
                queue,
                queue_idx,
                root.tokens,
                queue.surplus_deficit,
                CoSServicePhase::Surplus,
            ) {
                return Some(batch);
            }
        }
    }
    None
}

fn service_exact_local_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    let flow_fair = binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| queue.flow_fair)
        .unwrap_or(false);
    if flow_fair {
        return service_exact_local_queue_direct_flow_fair(
            binding,
            root_ifindex,
            queue_idx,
            secondary_budget,
            now_ns,
            shared_recycles,
        );
    }
    if binding.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_exact_local_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_local_fifo_items_to_scratch(
            queue,
            &mut binding.free_tx_frames,
            &mut binding.scratch_exact_local_tx,
            binding.umem.area(),
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            release_exact_local_scratch_frames(
                &mut binding.free_tx_frames,
                &mut binding.scratch_exact_local_tx,
            );
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_exact_local_tx.is_empty() {
        maybe_wake_tx(binding, true, now_ns);
        binding
            .live
            .set_error("no free TX frame available".to_string());
        return false;
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_exact_local_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_exact_local_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);

    if inserted == 0 {
        let dropped = binding.scratch_exact_local_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        release_exact_local_scratch_frames(
            &mut binding.free_tx_frames,
            &mut binding.scratch_exact_local_tx,
        );
        refresh_cos_interface_activity(binding, root_ifindex);
        binding.live.set_error("tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.free_tx_frames,
        &mut binding.scratch_exact_local_tx,
        inserted as usize,
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

fn service_exact_local_queue_direct_flow_fair(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    if binding.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_local_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_local_items_to_scratch_flow_fair(
            queue,
            &mut binding.free_tx_frames,
            &mut binding.scratch_local_tx,
            binding.umem.area(),
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            restore_exact_local_scratch_to_queue_head_flow_fair(
                binding
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx)),
                &mut binding.free_tx_frames,
                &mut binding.scratch_local_tx,
            );
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_local_tx.is_empty() {
        maybe_wake_tx(binding, true, now_ns);
        binding
            .live
            .set_error("no free TX frame available".to_string());
        return false;
    }

    let mut writer = binding.tx.transmit(binding.scratch_local_tx.len() as u32);
    let inserted = writer.insert(
        binding
            .scratch_local_tx
            .iter()
            .map(|(offset, req)| XdpDesc {
                addr: *offset,
                len: req.bytes.len() as u32,
                options: 0,
            }),
    );
    writer.commit();
    drop(writer);

    if inserted == 0 {
        let dropped = binding.scratch_local_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        restore_exact_local_scratch_to_queue_head_flow_fair(
            binding
                .cos_interfaces
                .get_mut(&root_ifindex)
                .and_then(|root| root.queues.get_mut(queue_idx)),
            &mut binding.free_tx_frames,
            &mut binding.scratch_local_tx,
        );
        refresh_cos_interface_activity(binding, root_ifindex);
        binding.live.set_error("tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_local_scratch_submission_flow_fair(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.free_tx_frames,
        &mut binding.scratch_local_tx,
        inserted as usize,
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

fn service_exact_prepared_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
) -> bool {
    let flow_fair = binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| queue.flow_fair)
        .unwrap_or(false);
    if flow_fair {
        return service_exact_prepared_queue_direct_flow_fair(
            binding,
            root_ifindex,
            queue_idx,
            secondary_budget,
            now_ns,
        );
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_exact_prepared_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_prepared_fifo_items_to_scratch(
            queue,
            &mut binding.scratch_exact_prepared_tx,
            binding.umem.area(),
            &mut binding.free_tx_frames,
            &mut binding.pending_fill_frames,
            binding.slot,
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            release_exact_prepared_scratch(&mut binding.scratch_exact_prepared_tx);
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_exact_prepared_tx.is_empty() {
        return false;
    }

    if cfg!(feature = "debug-log") {
        for req in &binding.scratch_exact_prepared_tx {
            if let Some(frame_data) = binding
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
            {
                if frame_has_tcp_rst(frame_data) {
                    binding.dbg_tx_tcp_rst += 1;
                }
            }
        }
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_exact_prepared_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_exact_prepared_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);

    if inserted == 0 {
        let dropped = binding.scratch_exact_prepared_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        release_exact_prepared_scratch(&mut binding.scratch_exact_prepared_tx);
        refresh_cos_interface_activity(binding, root_ifindex);
        binding
            .live
            .set_error("prepared tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.scratch_exact_prepared_tx,
        &mut binding.in_flight_prepared_recycles,
        inserted as usize,
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

fn service_exact_prepared_queue_direct_flow_fair(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
) -> bool {
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_prepared_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut binding.scratch_prepared_tx,
            binding.umem.area(),
            &mut binding.free_tx_frames,
            &mut binding.pending_fill_frames,
            binding.slot,
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            restore_exact_prepared_scratch_to_queue_head_flow_fair(
                binding
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx)),
                &mut binding.scratch_prepared_tx,
            );
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_prepared_tx.is_empty() {
        return false;
    }

    if cfg!(feature = "debug-log") {
        for req in &binding.scratch_prepared_tx {
            if let Some(frame_data) = binding
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
            {
                if frame_has_tcp_rst(frame_data) {
                    binding.dbg_tx_tcp_rst += 1;
                }
            }
        }
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_prepared_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_prepared_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);

    if inserted == 0 {
        let dropped = binding.scratch_prepared_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        restore_exact_prepared_scratch_to_queue_head_flow_fair(
            binding
                .cos_interfaces
                .get_mut(&root_ifindex)
                .and_then(|root| root.queues.get_mut(queue_idx)),
            &mut binding.scratch_prepared_tx,
        );
        refresh_cos_interface_activity(binding, root_ifindex);
        binding
            .live
            .set_error("prepared tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_prepared_scratch_submission_flow_fair(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.scratch_prepared_tx,
        &mut binding.in_flight_prepared_recycles,
        inserted as usize,
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

fn drain_exact_local_fifo_items_to_scratch(
    queue: &mut CoSQueueRuntime,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
    area: &MmapArea,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    debug_assert!(!queue.flow_fair);
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut index = 0usize;
    while scratch_local_tx.len() < TX_BATCH_SIZE {
        if free_tx_frames.is_empty() {
            break;
        }
        let mut drop_error: Option<(String, u64)> = None;
        let mut built = false;
        {
            let Some(front) = queue.items.get(index) else {
                break;
            };
            let CoSPendingTxItem::Local(req) = front else {
                break;
            };
            let len = req.bytes.len() as u64;
            if remaining_root < len || remaining_secondary < len {
                break;
            }
            if req.bytes.len() > tx_frame_capacity() {
                drop_error = Some((
                    format!(
                        "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                        req.bytes.len(),
                        tx_frame_capacity()
                    ),
                    len,
                ));
            } else {
                let Some(offset) = free_tx_frames.pop_front() else {
                    break;
                };
                if let Some(frame) =
                    unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) }
                {
                    frame.copy_from_slice(&req.bytes);
                    if let Some(dscp_rewrite) = req.dscp_rewrite.or(queue_dscp_rewrite) {
                        let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                    }
                    scratch_local_tx.push(ExactLocalScratchTxRequest {
                        offset,
                        len: req.bytes.len() as u32,
                    });
                    remaining_root = remaining_root.saturating_sub(len);
                    remaining_secondary = remaining_secondary.saturating_sub(len);
                    built = true;
                } else {
                    free_tx_frames.push_front(offset);
                    drop_error = Some((
                        format!(
                            "tx frame slice out of range: offset={offset} len={}",
                            req.bytes.len()
                        ),
                        len,
                    ));
                }
            }
        }
        if let Some((error, fallback_dropped_bytes)) = drop_error {
            // Error path only: remove the specific malformed item we just
            // examined. VecDeque::remove(index) is O(N), but this only runs for
            // oversized/out-of-range frames, never on the steady-state hot path.
            let dropped_bytes = match queue.items.remove(index) {
                Some(CoSPendingTxItem::Local(req)) => req.bytes.len() as u64,
                Some(CoSPendingTxItem::Prepared(_)) | None => fallback_dropped_bytes,
            };
            return ExactCoSScratchBuild::Drop {
                error,
                dropped_bytes,
            };
        }
        if !built {
            break;
        }
        index += 1;
    }

    ExactCoSScratchBuild::Ready
}

fn drain_exact_local_items_to_scratch_flow_fair(
    queue: &mut CoSQueueRuntime,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
    area: &MmapArea,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    while scratch_local_tx.len() < TX_BATCH_SIZE {
        if free_tx_frames.is_empty() {
            break;
        }
        let Some(front) = cos_queue_front(queue) else {
            break;
        };
        let len = match front {
            CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
            CoSPendingTxItem::Prepared(_) => break,
        };
        if remaining_root < len || remaining_secondary < len {
            break;
        }
        let Some(CoSPendingTxItem::Local(mut req)) = cos_queue_pop_front(queue) else {
            break;
        };
        remaining_root = remaining_root.saturating_sub(len);
        remaining_secondary = remaining_secondary.saturating_sub(len);

        if let Some(dscp_rewrite) = queue_dscp_rewrite {
            req.dscp_rewrite = req.dscp_rewrite.or(Some(dscp_rewrite));
        }
        if let Some(dscp_rewrite) = req.dscp_rewrite {
            let _ = apply_dscp_rewrite_to_frame(&mut req.bytes, dscp_rewrite);
        }
        if req.bytes.len() > tx_frame_capacity() {
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                    req.bytes.len(),
                    tx_frame_capacity()
                ),
                dropped_bytes: len,
            };
        }
        let Some(offset) = free_tx_frames.pop_front() else {
            cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
            break;
        };
        let Some(frame) = (unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) })
        else {
            free_tx_frames.push_front(offset);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "tx frame slice out of range: offset={offset} len={}",
                    req.bytes.len()
                ),
                dropped_bytes: len,
            };
        };
        frame.copy_from_slice(&req.bytes);
        scratch_local_tx.push((offset, req));
    }

    ExactCoSScratchBuild::Ready
}

fn drain_exact_prepared_fifo_items_to_scratch(
    queue: &mut CoSQueueRuntime,
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    debug_assert!(!queue.flow_fair);
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut index = 0usize;

    while scratch_prepared_tx.len() < TX_BATCH_SIZE {
        let mut drop_error: Option<(String, u64)> = None;
        let mut built = false;
        {
            let Some(front) = queue.items.get(index) else {
                break;
            };
            let CoSPendingTxItem::Prepared(req) = front else {
                break;
            };
            let len = req.len as u64;
            if remaining_root < len || remaining_secondary < len {
                break;
            }
            if req.len as usize > tx_frame_capacity() {
                drop_error = Some((
                    format!(
                        "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                        req.len,
                        tx_frame_capacity()
                    ),
                    len,
                ));
            } else {
                let valid = if let Some(dscp_rewrite) = req.dscp_rewrite.or(queue_dscp_rewrite) {
                    match unsafe { area.slice_mut_unchecked(req.offset as usize, req.len as usize) }
                    {
                        Some(frame) => {
                            let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                            true
                        }
                        None => false,
                    }
                } else {
                    area.slice(req.offset as usize, req.len as usize).is_some()
                };
                if !valid {
                    drop_error = Some((
                        format!(
                            "prepared tx frame slice out of range: offset={} len={}",
                            req.offset, req.len
                        ),
                        len,
                    ));
                } else {
                    scratch_prepared_tx.push(ExactPreparedScratchTxRequest {
                        offset: req.offset,
                        len: req.len,
                    });
                    remaining_root = remaining_root.saturating_sub(len);
                    remaining_secondary = remaining_secondary.saturating_sub(len);
                    built = true;
                }
            }
        }
        if let Some((error, fallback_dropped_bytes)) = drop_error {
            let dropped_bytes = match queue.items.remove(index) {
                Some(CoSPendingTxItem::Prepared(req)) => {
                    recycle_cancelled_prepared_offset(
                        free_tx_frames,
                        pending_fill_frames,
                        slot,
                        req.recycle,
                        req.offset,
                    );
                    req.len as u64
                }
                Some(CoSPendingTxItem::Local(_)) | None => fallback_dropped_bytes,
            };
            return ExactCoSScratchBuild::Drop {
                error,
                dropped_bytes,
            };
        }
        if !built {
            break;
        }
        index += 1;
    }

    ExactCoSScratchBuild::Ready
}

fn drain_exact_prepared_items_to_scratch_flow_fair(
    queue: &mut CoSQueueRuntime,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;

    while scratch_prepared_tx.len() < TX_BATCH_SIZE {
        let Some(front) = cos_queue_front(queue) else {
            break;
        };
        let len = match front {
            CoSPendingTxItem::Prepared(req) => req.len as u64,
            CoSPendingTxItem::Local(_) => break,
        };
        if remaining_root < len || remaining_secondary < len {
            break;
        }
        let Some(CoSPendingTxItem::Prepared(mut req)) = cos_queue_pop_front(queue) else {
            break;
        };
        remaining_root = remaining_root.saturating_sub(len);
        remaining_secondary = remaining_secondary.saturating_sub(len);

        if let Some(dscp_rewrite) = queue_dscp_rewrite {
            req.dscp_rewrite = req.dscp_rewrite.or(Some(dscp_rewrite));
        }
        if req.len as usize > tx_frame_capacity() {
            recycle_cancelled_prepared_offset(
                free_tx_frames,
                pending_fill_frames,
                slot,
                req.recycle,
                req.offset,
            );
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                    req.len,
                    tx_frame_capacity()
                ),
                dropped_bytes: len,
            };
        }
        let valid = if let Some(dscp_rewrite) = req.dscp_rewrite {
            match unsafe { area.slice_mut_unchecked(req.offset as usize, req.len as usize) } {
                Some(frame) => {
                    let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                    true
                }
                None => false,
            }
        } else {
            area.slice(req.offset as usize, req.len as usize).is_some()
        };
        if !valid {
            recycle_cancelled_prepared_offset(
                free_tx_frames,
                pending_fill_frames,
                slot,
                req.recycle,
                req.offset,
            );
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "prepared tx frame slice out of range: offset={} len={}",
                    req.offset, req.len
                ),
                dropped_bytes: len,
            };
        }
        scratch_prepared_tx.push(req);
    }

    ExactCoSScratchBuild::Ready
}

fn release_exact_local_scratch_frames(
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
) {
    while let Some(req) = scratch_local_tx.pop() {
        free_tx_frames.push_front(req.offset);
    }
}

fn restore_exact_local_scratch_to_queue_head_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
) {
    let Some(queue) = queue else {
        scratch_local_tx.clear();
        return;
    };
    while let Some((offset, req)) = scratch_local_tx.pop() {
        free_tx_frames.push_front(offset);
        cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
    }
}

fn release_exact_prepared_scratch(scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>) {
    scratch_prepared_tx.clear();
}

fn restore_exact_prepared_scratch_to_queue_head_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return;
    };
    while let Some(req) = scratch_prepared_tx.pop() {
        cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
    }
}

fn settle_exact_local_fifo_submission(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        release_exact_local_scratch_frames(free_tx_frames, scratch_local_tx);
        return (0, 0);
    };
    let sent = inserted.min(scratch_local_tx.len());
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    for _ in 0..sent {
        match queue.items.pop_front() {
            Some(CoSPendingTxItem::Local(req)) => {
                sent_packets += 1;
                sent_bytes += req.bytes.len() as u64;
            }
            Some(item) => {
                queue.items.push_front(item);
                break;
            }
            None => break,
        }
    }
    for req in scratch_local_tx.drain(sent..).rev() {
        free_tx_frames.push_front(req.offset);
    }
    scratch_local_tx.clear();
    (sent_packets, sent_bytes)
}

fn settle_exact_local_scratch_submission_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_local_tx.clear();
        return (0, 0);
    };
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    while let Some((offset, req)) = scratch_local_tx.pop() {
        if scratch_local_tx.len() >= inserted {
            free_tx_frames.push_front(offset);
            cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
        } else {
            sent_packets += 1;
            sent_bytes += req.bytes.len() as u64;
        }
    }
    (sent_packets, sent_bytes)
}

fn settle_exact_prepared_fifo_submission(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return (0, 0);
    };
    let sent = inserted.min(scratch_prepared_tx.len());
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    for _ in 0..sent {
        match queue.items.pop_front() {
            Some(CoSPendingTxItem::Prepared(req)) => {
                remember_prepared_recycle(in_flight_prepared_recycles, &req);
                sent_packets += 1;
                sent_bytes += req.len as u64;
            }
            Some(item) => {
                queue.items.push_front(item);
                break;
            }
            None => break,
        }
    }
    scratch_prepared_tx.clear();
    (sent_packets, sent_bytes)
}

fn settle_exact_prepared_scratch_submission_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return (0, 0);
    };
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    while let Some(req) = scratch_prepared_tx.pop() {
        if scratch_prepared_tx.len() >= inserted {
            cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
        } else {
            remember_prepared_recycle(in_flight_prepared_recycles, &req);
            sent_packets += 1;
            sent_bytes += req.len as u64;
        }
    }
    (sent_packets, sent_bytes)
}

fn subtract_direct_cos_queue_bytes(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    dropped_bytes: u64,
) {
    if dropped_bytes == 0 {
        refresh_cos_interface_activity(binding, root_ifindex);
        return;
    }
    if let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) {
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.queued_bytes = queue.queued_bytes.saturating_sub(dropped_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn apply_direct_exact_send_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    sent_packets: u64,
    sent_bytes: u64,
) {
    if let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) {
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.queued_bytes = queue.queued_bytes.saturating_sub(sent_bytes);
            queue.tokens = queue.tokens.saturating_sub(sent_bytes);
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    if let Some(shared_queue_lease) = binding
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
        .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
    {
        shared_queue_lease.consume(sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
    if sent_packets > 0 {
        binding
            .live
            .tx_packets
            .fetch_add(sent_packets, Ordering::Relaxed);
        binding
            .live
            .tx_bytes
            .fetch_add(sent_bytes, Ordering::Relaxed);
    }
}

fn build_cos_batch_from_queue(
    queue: &mut CoSQueueRuntime,
    queue_idx: usize,
    root_budget: u64,
    secondary_budget: u64,
    phase: CoSServicePhase,
) -> Option<CoSBatch> {
    let head = cos_queue_front(queue)?;
    match head {
        CoSPendingTxItem::Local(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = cos_queue_front(queue) else {
                    break;
                };
                let len = cos_item_len(front);
                if !matches!(front, CoSPendingTxItem::Local(_))
                    || remaining_root < len
                    || remaining_secondary < len
                {
                    break;
                }
                remaining_root = remaining_root.saturating_sub(len);
                remaining_secondary = remaining_secondary.saturating_sub(len);
                match cos_queue_pop_front(queue) {
                    Some(CoSPendingTxItem::Local(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        items.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if items.is_empty() {
                None
            } else {
                Some(CoSBatch::Local {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items,
                })
            }
        }
        CoSPendingTxItem::Prepared(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = cos_queue_front(queue) else {
                    break;
                };
                let len = cos_item_len(front);
                if !matches!(front, CoSPendingTxItem::Prepared(_))
                    || remaining_root < len
                    || remaining_secondary < len
                {
                    break;
                }
                remaining_root = remaining_root.saturating_sub(len);
                remaining_secondary = remaining_secondary.saturating_sub(len);
                match cos_queue_pop_front(queue) {
                    Some(CoSPendingTxItem::Prepared(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        items.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if items.is_empty() {
                None
            } else {
                Some(CoSBatch::Prepared {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items,
                })
            }
        }
    }
}

fn submit_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    batch: CoSBatch,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    match batch {
        CoSBatch::Local {
            queue_idx,
            phase,
            batch_bytes,
            mut items,
        } => {
            assign_local_dscp_rewrite(
                &mut items,
                cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
            );
            match transmit_batch(binding, &mut items, now_ns, shared_recycles) {
                Ok((packets, bytes)) => {
                    apply_cos_send_result(
                        binding,
                        root_ifindex,
                        queue_idx,
                        phase,
                        batch_bytes,
                        bytes,
                        items,
                    );
                    if packets > 0 {
                        binding
                            .live
                            .tx_packets
                            .fetch_add(packets, Ordering::Relaxed);
                        binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                    }
                    cos_batch_tx_made_progress(Ok((packets, bytes)))
                }
                Err(TxError::Retry(err)) => {
                    binding.live.set_error(err);
                    restore_cos_local_items(binding, root_ifindex, queue_idx, batch_bytes, items);
                    cos_batch_tx_made_progress(Err(TxError::Retry(String::new())))
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    // #710: frame-level submit drop during CoS batch
                    // transmit; items are restored to the queue head,
                    // so this counts the submit-attempt failure, not a
                    // lost packet. Subset of tx_errors.
                    binding
                        .live
                        .tx_submit_error_drops
                        .fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                    restore_cos_local_items(binding, root_ifindex, queue_idx, batch_bytes, items);
                    cos_batch_tx_made_progress(Err(TxError::Drop(String::new())))
                }
            }
        }
        CoSBatch::Prepared {
            queue_idx,
            phase,
            batch_bytes,
            mut items,
        } => {
            assign_prepared_dscp_rewrite(
                &mut items,
                cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
            );
            match transmit_prepared_queue(binding, &mut items, now_ns) {
                Ok((packets, bytes)) => {
                    apply_cos_prepared_result(
                        binding,
                        root_ifindex,
                        queue_idx,
                        phase,
                        batch_bytes,
                        bytes,
                        items,
                    );
                    if packets > 0 {
                        binding
                            .live
                            .tx_packets
                            .fetch_add(packets, Ordering::Relaxed);
                        binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                    }
                    cos_batch_tx_made_progress(Ok((packets, bytes)))
                }
                Err(TxError::Retry(err)) => {
                    binding.live.set_error(err);
                    restore_cos_prepared_items(
                        binding,
                        root_ifindex,
                        queue_idx,
                        batch_bytes,
                        items,
                    );
                    cos_batch_tx_made_progress(Err(TxError::Retry(String::new())))
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding
                        .live
                        .tx_submit_error_drops
                        .fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                    restore_cos_prepared_items(
                        binding,
                        root_ifindex,
                        queue_idx,
                        batch_bytes,
                        items,
                    );
                    cos_batch_tx_made_progress(Err(TxError::Drop(String::new())))
                }
            }
        }
    }
}

fn cos_batch_tx_made_progress(result: Result<(u64, u64), TxError>) -> bool {
    matches!(result, Ok((packets, bytes)) if packets > 0 || bytes > 0)
}

const COS_TIMER_WHEEL_TICK_NS: u64 = 50_000;
const COS_MIN_BURST_BYTES: u64 = 64 * 1500;
const COS_GUARANTEE_VISIT_NS: u64 = 200_000;
const COS_GUARANTEE_QUANTUM_MIN_BYTES: u64 = 1500;
const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 512 * 1024;
/// Minimum per-flow admission share. Sized so TCP fast-retransmit can
/// trigger reliably on a single-packet drop:
/// - 3 dupacks to trigger fast-retransmit (Linux `tcp_reordering = 3`)
/// - headroom for in-flight reordering up to ~13 MTU-sized packets
/// - 16 MTU-sized (1500 B) packets total = 24 KB
/// Below this, a single drop produces < 3 dupacks before cwnd is drained,
/// forcing an RTO with cwnd reset to 1 MSS and starting the oscillation
/// observed in #704 / #707 at high flow counts on low-rate exact queues.
/// 1500 matches the default MTU and is a conservative proxy for TCP
/// payload size; actual MSS (1460 v4 / 1440 v6) is smaller, so 16 × 1500
/// is a safe over-count of the "packets needed for fast-retransmit".
const COS_FLOW_FAIR_MIN_SHARE_BYTES: u64 = 16 * 1500;

// Compile-time pin so the floor cannot silently drift below the
// fast-retransmit-safe threshold on a rebase/refactor. Parallels the
// `const _: () = assert!` invariants in `types.rs`. Lives here (at the
// constant) rather than in `tests/` so `cargo build` enforces it, not
// just `cargo test`.
const _: () = assert!(COS_FLOW_FAIR_MIN_SHARE_BYTES >= 16 * 1500);
const COS_SURPLUS_ROUND_QUANTUM_BYTES: u64 = 1500;
const COS_TIMER_WHEEL_L0_HORIZON_TICKS: u64 = COS_TIMER_WHEEL_L0_SLOTS as u64;

/// ECN CE-marking threshold as a fraction of `buffer_limit`. At 50%
/// the scheduler signals TCP to back off well before the aggregate
/// cap trips, so ECN-negotiated flows converge on their fair share
/// with smooth cwnd dynamics instead of the drop->RTO->cwnd=1MSS
/// oscillation documented in #718's live data.
const COS_ECN_MARK_THRESHOLD_NUM: u64 = 1;
const COS_ECN_MARK_THRESHOLD_DEN: u64 = 2;

// Guard against a refactor flipping the fraction. A threshold >= 1
// would never fire (queue is capped at buffer_limit) and a zero
// denominator would divide-by-zero at admission time.
const _: () = assert!(COS_ECN_MARK_THRESHOLD_NUM < COS_ECN_MARK_THRESHOLD_DEN);
const _: () = assert!(COS_ECN_MARK_THRESHOLD_DEN > 0);

/// ECN codepoint masks (low 2 bits of IPv4 TOS / IPv6 tclass).
const ECN_MASK: u8 = 0b0000_0011;
const ECN_NOT_ECT: u8 = 0b0000_0000;
const ECN_ECT_0: u8 = 0b0000_0010;
const ECN_ECT_1: u8 = 0b0000_0001;
const ECN_CE: u8 = 0b0000_0011;

/// Offset of the L3 header inside a TxRequest's `bytes` buffer. TxRequest
/// construction sites always wrap the frame with a 14-byte Ethernet
/// header (6 dst MAC + 6 src MAC + 2 ethertype) so L3 starts at byte 14.
const TX_L3_OFFSET: usize = 14;

/// Mark the IPv4 packet at `l3_offset` within `bytes` as ECN CE if it
/// is already ECT(0) or ECT(1). Updates the IP header checksum
/// incrementally (RFC 1624). Returns true iff the packet was marked.
/// Never modifies a NOT-ECT packet (protects non-ECN flows per RFC
/// 3168 section 6.1.1.1).
#[inline]
fn mark_ecn_ce_ipv4(bytes: &mut [u8], l3_offset: usize) -> bool {
    // Need the full 20-byte base IPv4 header (through the checksum field).
    // Short buffers are returned false rather than panicking — this path
    // runs per admission on the hot path and cannot trust upstream
    // length validation to have covered every corner.
    let end = l3_offset.saturating_add(20);
    if bytes.len() < end {
        return false;
    }
    let tos_idx = l3_offset + 1;
    let old_tos = bytes[tos_idx];
    let ecn = old_tos & ECN_MASK;
    // Branchless: only ECT(0) and ECT(1) cross to CE; NOT-ECT and CE
    // are left unchanged. A non-ECT packet returning false routes into
    // the existing admission drop path unchanged.
    if ecn != ECN_ECT_0 && ecn != ECN_ECT_1 {
        return false;
    }
    let new_tos = (old_tos & !ECN_MASK) | ECN_CE;
    bytes[tos_idx] = new_tos;

    // RFC 1624 incremental checksum update for a single byte change to
    // the TOS field (16-bit word = [version/IHL, TOS]). The header
    // checksum sits at l3_offset+10..l3_offset+12 in network byte order.
    //
    //   HC' = ~(~HC + ~m + m')
    //
    // where m and m' are the 16-bit words at the mutated position. The
    // version/IHL byte is unchanged so it cancels inside `old_word` /
    // `new_word` — but keeping it in the word avoids a conditional on
    // which half of the 16-bit word we touched.
    let ihl = bytes[l3_offset];
    let old_word = ((ihl as u32) << 8) | old_tos as u32;
    let new_word = ((ihl as u32) << 8) | new_tos as u32;
    let csum_idx = l3_offset + 10;
    let old_csum = ((bytes[csum_idx] as u32) << 8) | bytes[csum_idx + 1] as u32;
    // ~HC + ~m + m' in 32-bit arithmetic, then fold carries.
    let mut sum = (!old_csum & 0xffff) + (!old_word & 0xffff) + new_word;
    // Fold any carries out of the low 16 bits. Two folds are sufficient
    // for the three 16-bit addends above (max ~3 * 0xffff fits in 18
    // bits, one fold collapses to 17 bits, second to 16 bits).
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let new_csum = (!sum) & 0xffff;
    bytes[csum_idx] = (new_csum >> 8) as u8;
    bytes[csum_idx + 1] = (new_csum & 0xff) as u8;
    true
}

/// Mark the IPv6 packet at `l3_offset` within `bytes` as ECN CE if it
/// is already ECT(0) or ECT(1). IPv6 has no header checksum so no
/// incremental update is needed. Returns true iff the packet was marked.
#[inline]
fn mark_ecn_ce_ipv6(bytes: &mut [u8], l3_offset: usize) -> bool {
    // tclass spans the low nibble of byte[l3_offset] and the high
    // nibble of byte[l3_offset+1]. We need both bytes in range.
    let end = l3_offset.saturating_add(2);
    if bytes.len() < end {
        return false;
    }
    // Version/tclass-high byte: [vvvv tttt]. ECN bits are the low 2
    // bits of tclass, which sit in the high nibble of byte[l3_offset+1]
    // as bits 5..4. Extract with a simple shift-mask.
    let b1 = bytes[l3_offset + 1];
    let ecn = (b1 >> 4) & ECN_MASK;
    if ecn != ECN_ECT_0 && ecn != ECN_ECT_1 {
        return false;
    }
    // Clear the old ECN bits (bits 5..4 of byte[l3_offset+1]) and OR in
    // CE shifted into place.
    let cleared = b1 & !(ECN_MASK << 4);
    bytes[l3_offset + 1] = cleared | (ECN_CE << 4);
    true
}

/// Dispatch ECN marking based on the L3 protocol family stamped on
/// the TxRequest. Returns true iff the packet was marked.
#[inline]
fn maybe_mark_ecn_ce(req: &mut TxRequest) -> bool {
    match req.expected_addr_family as i32 {
        libc::AF_INET => mark_ecn_ce_ipv4(&mut req.bytes, TX_L3_OFFSET),
        libc::AF_INET6 => mark_ecn_ce_ipv6(&mut req.bytes, TX_L3_OFFSET),
        _ => false,
    }
}

/// Core ECN admission decision, factored out so tests can drive it
/// without spinning up a full `BindingWorker` while still exercising
/// the exact code path that `enqueue_cos_item` uses. Mutates both the
/// item (CE bits + incremental IP checksum) and the queue's
/// `admission_ecn_marked` counter.
///
/// Returns whether the packet was marked. The caller is still
/// responsible for the subsequent drop-vs-admit decision: a
/// marked packet is ALSO admitted; a non-ECT packet above threshold
/// falls through unchanged and drops via the existing buffer/share
/// caps.
#[inline]
fn apply_cos_admission_ecn_policy(
    queue: &mut CoSQueueRuntime,
    buffer_limit: u64,
    flow_share_exceeded: bool,
    buffer_exceeded: bool,
    item: &mut CoSPendingTxItem,
) -> bool {
    // Integer division by the compile-time-asserted nonzero
    // `COS_ECN_MARK_THRESHOLD_DEN` is one saturating_mul + one divide
    // on the hot path.
    let ecn_threshold = buffer_limit
        .saturating_mul(COS_ECN_MARK_THRESHOLD_NUM)
        / COS_ECN_MARK_THRESHOLD_DEN.max(1);
    if queue.queued_bytes <= ecn_threshold || flow_share_exceeded || buffer_exceeded {
        return false;
    }
    if let CoSPendingTxItem::Local(req) = item {
        if maybe_mark_ecn_ce(req) {
            queue.drop_counters.admission_ecn_marked = queue
                .drop_counters
                .admission_ecn_marked
                .wrapping_add(1);
            return true;
        }
    }
    // TODO(#718-followup): Prepared variant marks the packet via umem
    // slice_mut, needs separate plumbing. Return false for now so the
    // packet falls through to the existing admission path unchanged.
    false
}

fn maybe_top_up_cos_root_lease(
    root: &mut CoSInterfaceRuntime,
    shared_root_lease: &SharedCoSRootLease,
    now_ns: u64,
) {
    // Ensure the target is at least tx_frame_capacity() so that a maximum-sized frame
    // can always become eligible.  shared_root_lease already sizes max_total_leased using
    // lease_bytes.max(tx_frame_capacity()), so the shared pool can always satisfy this.
    let lease_bytes = shared_root_lease
        .lease_bytes()
        .max(tx_frame_capacity() as u64)
        .min(root.burst_bytes.max(COS_MIN_BURST_BYTES));
    if root.tokens >= lease_bytes {
        return;
    }
    let grant = shared_root_lease.acquire(now_ns, lease_bytes.saturating_sub(root.tokens));
    root.tokens = root
        .tokens
        .saturating_add(grant)
        .min(root.burst_bytes.max(COS_MIN_BURST_BYTES));
}

fn maybe_top_up_cos_queue_lease(
    queue: &mut CoSQueueRuntime,
    shared_queue_lease: Option<&Arc<SharedCoSQueueLease>>,
    now_ns: u64,
) {
    if queue.exact {
        let Some(shared_queue_lease) = shared_queue_lease else {
            return;
        };
        let lease_bytes = shared_queue_lease
            .lease_bytes()
            .max(tx_frame_capacity() as u64)
            .min(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
        if queue.tokens >= lease_bytes {
            return;
        }
        let grant = shared_queue_lease.acquire(now_ns, lease_bytes.saturating_sub(queue.tokens));
        queue.tokens = queue
            .tokens
            .saturating_add(grant)
            .min(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
        queue.last_refill_ns = now_ns;
        return;
    }
    let Some(shared_queue_lease) = shared_queue_lease else {
        refill_cos_tokens(
            &mut queue.tokens,
            queue.transmit_rate_bytes,
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            &mut queue.last_refill_ns,
            now_ns,
        );
        return;
    };
    let lease_bytes = shared_queue_lease
        .lease_bytes()
        .max(tx_frame_capacity() as u64)
        .min(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
    if queue.tokens >= lease_bytes {
        return;
    }
    let grant = shared_queue_lease.acquire(now_ns, lease_bytes.saturating_sub(queue.tokens));
    queue.tokens = queue
        .tokens
        .saturating_add(grant)
        .min(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
    queue.last_refill_ns = now_ns;
}

fn refill_cos_tokens(
    tokens: &mut u64,
    rate_bytes_per_sec: u64,
    burst_bytes: u64,
    last_refill_ns: &mut u64,
    now_ns: u64,
) {
    if burst_bytes == 0 {
        return;
    }
    if *last_refill_ns == 0 {
        *tokens = burst_bytes;
        *last_refill_ns = now_ns;
        return;
    }
    if now_ns <= *last_refill_ns || rate_bytes_per_sec == 0 {
        return;
    }
    let elapsed_ns = now_ns - *last_refill_ns;
    let added = ((elapsed_ns as u128) * (rate_bytes_per_sec as u128) / 1_000_000_000u128) as u64;
    if added == 0 {
        return;
    }
    *tokens = tokens.saturating_add(added).min(burst_bytes);
    *last_refill_ns = now_ns;
}

fn cos_tick_for_ns(now_ns: u64) -> u64 {
    now_ns / COS_TIMER_WHEEL_TICK_NS
}

fn cos_timer_wheel_level_and_slot(current_tick: u64, wake_tick: u64) -> (u8, usize) {
    if wake_tick.saturating_sub(current_tick) < COS_TIMER_WHEEL_L0_HORIZON_TICKS {
        (0, (wake_tick % COS_TIMER_WHEEL_L0_SLOTS as u64) as usize)
    } else {
        (
            1,
            ((wake_tick / COS_TIMER_WHEEL_L0_SLOTS as u64) % COS_TIMER_WHEEL_L1_SLOTS as u64)
                as usize,
        )
    }
}

fn cos_refill_ns_until(tokens: u64, need: u64, rate_bytes_per_sec: u64) -> Option<u64> {
    if tokens >= need {
        return Some(0);
    }
    if rate_bytes_per_sec == 0 {
        return None;
    }
    let deficit = need.saturating_sub(tokens) as u128;
    let rate = rate_bytes_per_sec as u128;
    Some(deficit.saturating_mul(1_000_000_000u128).div_ceil(rate) as u64)
}

fn cos_surplus_quantum_bytes(queue: &CoSQueueRuntime) -> u64 {
    COS_SURPLUS_ROUND_QUANTUM_BYTES.saturating_mul(u64::from(queue.surplus_weight.max(1)))
}

fn cos_guarantee_quantum_bytes(queue: &CoSQueueRuntime) -> u64 {
    let bytes_for_visit = ((queue.transmit_rate_bytes as u128) * (COS_GUARANTEE_VISIT_NS as u128)
        / 1_000_000_000u128) as u64;
    bytes_for_visit.clamp(
        COS_GUARANTEE_QUANTUM_MIN_BYTES,
        COS_GUARANTEE_QUANTUM_MAX_BYTES,
    )
}

#[inline(always)]
fn mix_cos_flow_bucket(seed: &mut u64, value: u64) {
    *seed ^= value
        .wrapping_add(0x9e3779b97f4a7c15)
        .wrapping_add(*seed << 6)
        .wrapping_add(*seed >> 2);
}

/// Draw a fresh per-queue hash salt from the kernel.
///
/// `getrandom(2)` with `flags=0` blocks only during early boot before the
/// urandom pool is initialized, which is not a path this daemon runs on
/// (xpfd starts well after systemd-random-seed). Retries on `EINTR` and
/// partial reads (the kernel is allowed to return fewer bytes than
/// requested; 8 bytes is well below any documented per-call limit so a
/// partial is pathological, but still explicitly handled rather than
/// silently degrading). If the syscall ever fails for a real reason we
/// fall through to a CLOCK_MONOTONIC + pid + stack-address-mixed
/// fallback so the daemon does not abort on queue construction. The
/// fallback is strictly weaker than `getrandom` — predictable enough
/// that it must not be the production path — but strictly stronger
/// than the zero-seed it replaces, and stays per-call-distinct because
/// each call mixes in a live clock read and the stack address of the
/// return buffer.
pub(super) fn cos_flow_hash_seed_from_os() -> u64 {
    let mut buf = [0u8; 8];
    let mut filled = 0usize;
    while filled < buf.len() {
        // SAFETY: `buf[filled..]` is a valid mutable slice of length
        // `buf.len() - filled` for the duration of the call.
        let rc = unsafe {
            libc::getrandom(
                buf.as_mut_ptr().add(filled).cast::<libc::c_void>(),
                buf.len() - filled,
                0,
            )
        };
        if rc > 0 {
            filled += rc as usize;
            continue;
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EINTR) {
                continue;
            }
        }
        // rc == 0 (should not happen for getrandom) or a real error: bail
        // to the fallback rather than spinning.
        break;
    }
    if filled == buf.len() {
        return u64::from_ne_bytes(buf);
    }

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer for `clock_gettime`.
    let now = unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            (ts.tv_sec as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add(ts.tv_nsec as u64)
        } else {
            0
        }
    };
    let pid = std::process::id() as u64;
    let stack_addr = (&buf as *const [u8; 8]) as usize as u64;
    let mut fallback = now ^ pid.wrapping_mul(0x9e3779b97f4a7c15);
    mix_cos_flow_bucket(&mut fallback, now.rotate_left(17));
    mix_cos_flow_bucket(&mut fallback, stack_addr.rotate_left(31));
    fallback
}

// #711: returns `u16` (was `u8`). With `COS_FLOW_FAIR_BUCKETS = 1024`
// the mask in `cos_flow_bucket_index` is 10 bits wide; a `u8` return
// would silently re-collapse the hash into 256 buckets and give no
// benefit from the bucket grow. Returning `u16` preserves the full
// hash width through the mask step.
#[inline(always)]
fn exact_cos_flow_bucket(queue_seed: u64, flow_key: Option<&SessionKey>) -> u16 {
    let Some(flow_key) = flow_key else {
        return 0;
    };
    let mut seed = queue_seed ^ (flow_key.protocol as u64) ^ ((flow_key.addr_family as u64) << 8);
    match flow_key.src_ip {
        IpAddr::V4(ip) => mix_cos_flow_bucket(&mut seed, u32::from(ip) as u64),
        IpAddr::V6(ip) => {
            for chunk in ip.octets().chunks_exact(8) {
                mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
            }
        }
    }
    match flow_key.dst_ip {
        IpAddr::V4(ip) => mix_cos_flow_bucket(&mut seed, u32::from(ip) as u64),
        IpAddr::V6(ip) => {
            for chunk in ip.octets().chunks_exact(8) {
                mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
            }
        }
    }
    mix_cos_flow_bucket(&mut seed, flow_key.src_port as u64);
    mix_cos_flow_bucket(&mut seed, flow_key.dst_port as u64);
    seed as u16
}

#[inline]
fn cos_item_flow_key(item: &CoSPendingTxItem) -> Option<&SessionKey> {
    match item {
        CoSPendingTxItem::Local(req) => req.flow_key.as_ref(),
        CoSPendingTxItem::Prepared(req) => req.flow_key.as_ref(),
    }
}

#[inline(always)]
fn cos_flow_bucket_index(queue_seed: u64, flow_key: Option<&SessionKey>) -> usize {
    usize::from(exact_cos_flow_bucket(queue_seed, flow_key)) & COS_FLOW_FAIR_BUCKET_MASK
}

/// Prospective distinct-flow count: current `active_flow_buckets` plus
/// one when the target bucket is currently empty (i.e. we are admitting
/// the first packet of a newly arriving flow). Both admission gates —
/// the per-flow clamp and the aggregate cap — must use this value so
/// they stay in lockstep. The original #704 bug was exactly this
/// denominator drifting: one gate bumped for the new flow, the other
/// did not, and the new flow's first packet got rejected at the
/// boundary. Keeping the formula in one place removes that class of
/// reintroduction risk.
#[inline]
fn cos_queue_prospective_active_flows(queue: &CoSQueueRuntime, flow_bucket: usize) -> u64 {
    u64::from(queue.active_flow_buckets)
        .saturating_add(u64::from(queue.flow_bucket_bytes[flow_bucket] == 0))
        .max(1)
}

#[inline]
fn cos_queue_flow_share_limit(
    queue: &CoSQueueRuntime,
    buffer_limit: u64,
    flow_bucket: usize,
) -> u64 {
    if !queue.flow_fair {
        return buffer_limit;
    }
    let prospective_active = cos_queue_prospective_active_flows(queue, flow_bucket);
    buffer_limit
        .div_ceil(prospective_active)
        .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit)
}

/// Effective buffer cap for the admission check. Grows with the
/// *prospective* distinct-flow count — same denominator that
/// `cos_queue_flow_share_limit` uses — so the aggregate admission
/// threshold never drops below `prospective_active ×
/// COS_FLOW_FAIR_MIN_SHARE_BYTES`.
///
/// Why "prospective" and not current `active_flow_buckets`: the per-
/// flow clamp already adds `+1` when the target bucket is empty, so it
/// reserves headroom for a newly arriving flow. If the aggregate cap
/// uses the *current* count it asymmetrically excludes that same new
/// flow and the first packet of every new flow can get rejected right
/// at the boundary even though the per-flow path was trying to admit
/// it. Matching the two denominators removes that off-by-one window.
///
/// Non-flow-fair queues (e.g. best-effort or pure rate-limited) bypass
/// this scaling; their admission is buffer-bound by the operator's
/// configured `buffer-size` alone.
///
/// This is a logical threshold only. The backing `VecDeque` storage is
/// dynamic, so raising the cap costs nothing until traffic actually
/// fills it. The cap is currently uncapped on the high side: at
/// `COS_FLOW_FAIR_BUCKETS = 1024` active flows it can reach `~24 MB`,
/// which on a 1 Gbps queue is `~190 ms` of queue residence time — an
/// operator-visible latency envelope concern flagged in the #716
/// review. A derived max-queue-delay clamp belongs in a follow-up
/// change alongside the queueing-budget policy discussion.
#[inline]
fn cos_flow_aware_buffer_limit(queue: &CoSQueueRuntime, flow_bucket: usize) -> u64 {
    let base = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    if !queue.flow_fair {
        return base;
    }
    let prospective_active = cos_queue_prospective_active_flows(queue, flow_bucket);
    base.max(prospective_active.saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES))
}

#[inline]
fn account_cos_queue_flow_enqueue(
    queue: &mut CoSQueueRuntime,
    flow_key: Option<&SessionKey>,
    item_len: u64,
) {
    if !queue.flow_fair || item_len == 0 {
        return;
    }
    let bucket = cos_flow_bucket_index(queue.flow_hash_seed, flow_key);
    if queue.flow_bucket_bytes[bucket] == 0 {
        queue.active_flow_buckets = queue.active_flow_buckets.saturating_add(1);
    }
    queue.flow_bucket_bytes[bucket] = queue.flow_bucket_bytes[bucket].saturating_add(item_len);
}

#[inline]
fn account_cos_queue_flow_dequeue(
    queue: &mut CoSQueueRuntime,
    flow_key: Option<&SessionKey>,
    item_len: u64,
) {
    if !queue.flow_fair || item_len == 0 {
        return;
    }
    let bucket = cos_flow_bucket_index(queue.flow_hash_seed, flow_key);
    let remaining = queue.flow_bucket_bytes[bucket].saturating_sub(item_len);
    if queue.flow_bucket_bytes[bucket] > 0 && remaining == 0 {
        queue.active_flow_buckets = queue.active_flow_buckets.saturating_sub(1);
    }
    queue.flow_bucket_bytes[bucket] = remaining;
}

#[inline]
pub(super) fn cos_queue_is_empty(queue: &CoSQueueRuntime) -> bool {
    if !queue.flow_fair {
        return queue.items.is_empty();
    }
    queue.flow_rr_buckets.is_empty()
}

#[inline]
pub(super) fn cos_queue_len(queue: &CoSQueueRuntime) -> usize {
    if !queue.flow_fair {
        return queue.items.len();
    }
    queue
        .flow_rr_buckets
        .iter()
        .map(|bucket| queue.flow_bucket_items[usize::from(bucket)].len())
        .sum()
}

#[inline]
pub(super) fn cos_queue_front(queue: &CoSQueueRuntime) -> Option<&CoSPendingTxItem> {
    if !queue.flow_fair {
        return queue.items.front();
    }
    let bucket = usize::from(queue.flow_rr_buckets.front()?);
    queue.flow_bucket_items[bucket].front()
}

#[inline]
pub(super) fn cos_queue_push_back(queue: &mut CoSQueueRuntime, item: CoSPendingTxItem) {
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    account_cos_queue_flow_enqueue(queue, flow_key, item_len);
    if !queue.flow_fair {
        queue.items.push_back(item);
        return;
    }
    let bucket = cos_flow_bucket_index(queue.flow_hash_seed, flow_key);
    let bucket_queue = &mut queue.flow_bucket_items[bucket];
    let was_empty = bucket_queue.is_empty();
    bucket_queue.push_back(item);
    if was_empty {
        queue.flow_rr_buckets.push_back(bucket as u16);
    }
}

#[inline]
pub(super) fn cos_queue_push_front(queue: &mut CoSQueueRuntime, item: CoSPendingTxItem) {
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    account_cos_queue_flow_enqueue(queue, flow_key, item_len);
    if !queue.flow_fair {
        queue.items.push_front(item);
        return;
    }
    let bucket = cos_flow_bucket_index(queue.flow_hash_seed, flow_key);
    let bucket_queue = &mut queue.flow_bucket_items[bucket];
    let was_empty = bucket_queue.is_empty();
    bucket_queue.push_front(item);
    if was_empty {
        queue.flow_rr_buckets.push_front(bucket as u16);
    }
}

#[inline]
pub(super) fn cos_queue_pop_front(queue: &mut CoSQueueRuntime) -> Option<CoSPendingTxItem> {
    let item = if !queue.flow_fair {
        queue.items.pop_front()?
    } else {
        let bucket = usize::from(queue.flow_rr_buckets.front()?);
        let item = queue.flow_bucket_items[bucket].pop_front()?;
        let active = queue
            .flow_rr_buckets
            .pop_front()
            .expect("active flow bucket must exist");
        if !queue.flow_bucket_items[bucket].is_empty() {
            queue.flow_rr_buckets.push_back(active);
        }
        item
    };
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    account_cos_queue_flow_dequeue(queue, flow_key, item_len);
    Some(item)
}

fn cos_queue_drain_all(queue: &mut CoSQueueRuntime) -> VecDeque<CoSPendingTxItem> {
    let mut items = VecDeque::new();
    while let Some(item) = cos_queue_pop_front(queue) {
        items.push_back(item);
    }
    items
}

fn cos_queue_restore_front(queue: &mut CoSQueueRuntime, mut items: VecDeque<CoSPendingTxItem>) {
    while let Some(item) = items.pop_back() {
        cos_queue_push_front(queue, item);
    }
}

fn estimate_cos_queue_wakeup_tick(
    root_tokens: u64,
    root_rate_bytes: u64,
    queue_tokens: u64,
    queue_rate_bytes: u64,
    need_bytes: u64,
    now_ns: u64,
    require_queue_tokens: bool,
) -> Option<u64> {
    let root_refill_ns = cos_refill_ns_until(root_tokens, need_bytes, root_rate_bytes)?;
    let queue_refill_ns = if require_queue_tokens {
        cos_refill_ns_until(queue_tokens, need_bytes, queue_rate_bytes)?
    } else {
        0
    };
    let wake_ns = now_ns.saturating_add(root_refill_ns.max(queue_refill_ns));
    Some(cos_tick_for_ns(wake_ns).max(cos_tick_for_ns(now_ns).saturating_add(1)))
}

fn wake_cos_queue(root: &mut CoSInterfaceRuntime, queue_idx: usize) {
    let Some(queue) = root.queues.get_mut(queue_idx) else {
        return;
    };
    if cos_queue_is_empty(queue) {
        queue.runnable = false;
        queue.parked = false;
        queue.next_wakeup_tick = 0;
        return;
    }
    if !queue.runnable {
        root.runnable_queues = root.runnable_queues.saturating_add(1);
    }
    mark_cos_queue_runnable(queue);
}

// #710: park-reason classification used at every `park_cos_queue` call
// site to attribute the wait to its upstream cause. `RootTokenStarvation`
// means the interface-level shaper token bucket was empty; the queue
// itself had work and tokens to send but the root could not admit more
// bytes this tick. `QueueTokenStarvation` means the per-queue (exact)
// token bucket was empty — the queue's own rate cap is the limiter.
// Both are "parks" rather than "drops" because the timer wheel will
// wake the queue when tokens refill; no packet is lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParkReason {
    RootTokenStarvation,
    QueueTokenStarvation,
}

// #710: count an exact-drain TX submit stall on a specific queue.
// NOT packet loss — on the exact path, `writer.insert == 0` leaves
// the FIFO items in `queue.items` or restores them (flow-fair path);
// frames that had been copied into UMEM are released back to
// `free_tx_frames`, and the items get another chance next drain tick.
// The counter signals TX-ring / completion-reap pressure, which is
// an upstream cause for the downstream effects operators chase
// (#706 mutex contention, #709 owner-worker hotspot).
//
// Non-exact transmit paths (`transmit_batch`, `transmit_prepared_queue`)
// do not carry queue identity at the submit site and do not reach
// this helper. Their frame-level failures are counted in the binding-
// level `tx_submit_error_drops` counter instead.
#[inline]
fn count_tx_ring_full_submit_stall(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    stalled_packets: u64,
) {
    if stalled_packets == 0 {
        return;
    }
    if let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) {
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.drop_counters.tx_ring_full_submit_stalls = queue
                .drop_counters
                .tx_ring_full_submit_stalls
                .wrapping_add(stalled_packets);
        }
    }
}

#[inline]
fn count_park_reason(root: &mut CoSInterfaceRuntime, queue_idx: usize, reason: ParkReason) {
    if let Some(queue) = root.queues.get_mut(queue_idx) {
        match reason {
            ParkReason::RootTokenStarvation => {
                queue.drop_counters.root_token_starvation_parks = queue
                    .drop_counters
                    .root_token_starvation_parks
                    .wrapping_add(1);
            }
            ParkReason::QueueTokenStarvation => {
                queue.drop_counters.queue_token_starvation_parks = queue
                    .drop_counters
                    .queue_token_starvation_parks
                    .wrapping_add(1);
            }
        }
    }
}

fn park_cos_queue(root: &mut CoSInterfaceRuntime, queue_idx: usize, wake_tick: u64) {
    let (level, slot) = cos_timer_wheel_level_and_slot(root.timer_wheel.current_tick, wake_tick);
    let Some(queue) = root.queues.get_mut(queue_idx) else {
        return;
    };
    if queue.runnable {
        root.runnable_queues = root.runnable_queues.saturating_sub(1);
    }
    queue.runnable = false;
    queue.parked = true;
    queue.next_wakeup_tick = wake_tick;
    queue.wheel_level = level;
    queue.wheel_slot = slot;
    if level == 0 {
        root.timer_wheel.level0[slot].push(queue_idx);
    } else {
        root.timer_wheel.level1[slot].push(queue_idx);
    }
}

fn rearm_cos_queue(root: &mut CoSInterfaceRuntime, queue_idx: usize, wake_tick: u64) {
    park_cos_queue(root, queue_idx, wake_tick);
}

fn mark_cos_queue_runnable(queue: &mut CoSQueueRuntime) {
    queue.runnable = true;
    queue.parked = false;
    queue.next_wakeup_tick = 0;
}

fn normalize_cos_queue_state(queue: &mut CoSQueueRuntime) {
    if cos_queue_is_empty(queue) {
        queue.runnable = false;
        queue.parked = false;
        queue.next_wakeup_tick = 0;
        queue.surplus_deficit = 0;
        return;
    }
    // Non-empty queues have only two valid steady states:
    // 1. parked with a wakeup tick
    // 2. runnable immediately
    // Anything else can strand backlog forever.
    if queue.parked && queue.next_wakeup_tick > 0 {
        queue.runnable = false;
        return;
    }
    mark_cos_queue_runnable(queue);
}

fn advance_cos_timer_wheel(root: &mut CoSInterfaceRuntime, now_ns: u64) {
    let now_tick = cos_tick_for_ns(now_ns);
    while root.timer_wheel.current_tick < now_tick {
        root.timer_wheel.current_tick = root.timer_wheel.current_tick.saturating_add(1);
        if root.timer_wheel.current_tick % COS_TIMER_WHEEL_L0_SLOTS as u64 == 0 {
            cascade_cos_timer_wheel_level1(root);
        }
        wake_due_cos_timer_slot(root);
    }
}

fn cascade_cos_timer_wheel_level1(root: &mut CoSInterfaceRuntime) {
    let slot = ((root.timer_wheel.current_tick / COS_TIMER_WHEEL_L0_SLOTS as u64)
        % COS_TIMER_WHEEL_L1_SLOTS as u64) as usize;
    let queued = core::mem::take(&mut root.timer_wheel.level1[slot]);
    let mut rearm = Vec::with_capacity(queued.len());
    for queue_idx in queued {
        let Some(queue) = root.queues.get(queue_idx) else {
            continue;
        };
        if !queue.parked || queue.wheel_level != 1 || queue.wheel_slot != slot {
            continue;
        }
        rearm.push((queue_idx, queue.next_wakeup_tick));
    }
    for (queue_idx, wake_tick) in rearm {
        rearm_cos_queue(root, queue_idx, wake_tick);
    }
}

fn wake_due_cos_timer_slot(root: &mut CoSInterfaceRuntime) {
    let slot = (root.timer_wheel.current_tick % COS_TIMER_WHEEL_L0_SLOTS as u64) as usize;
    let queued = core::mem::take(&mut root.timer_wheel.level0[slot]);
    let mut rearm = Vec::with_capacity(queued.len());
    let mut wake = Vec::with_capacity(queued.len());
    for queue_idx in queued {
        let Some(queue) = root.queues.get(queue_idx) else {
            continue;
        };
        if !queue.parked || queue.wheel_level != 0 || queue.wheel_slot != slot {
            continue;
        }
        if queue.next_wakeup_tick <= root.timer_wheel.current_tick {
            wake.push(queue_idx);
        } else {
            rearm.push((queue_idx, queue.next_wakeup_tick));
        }
    }
    for queue_idx in wake {
        wake_cos_queue(root, queue_idx);
    }
    for (queue_idx, wake_tick) in rearm {
        rearm_cos_queue(root, queue_idx, wake_tick);
    }
}

pub(super) fn resolve_cos_queue_id(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: impl Into<ForwardPacketMeta>,
    flow_key: Option<&SessionKey>,
) -> Option<u8> {
    resolve_cos_tx_selection(forwarding, egress_ifindex, meta, flow_key).queue_id
}

pub(super) fn resolve_cos_tx_selection(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: impl Into<ForwardPacketMeta>,
    flow_key: Option<&SessionKey>,
) -> CoSTxSelection {
    let meta = meta.into();
    let tx_selection_enabled = if meta.addr_family as i32 == libc::AF_INET6 {
        forwarding.tx_selection_enabled_v6
    } else {
        forwarding.tx_selection_enabled_v4
    };
    if !tx_selection_enabled {
        return CoSTxSelection::default();
    }
    let iface = forwarding.cos.interfaces.get(&egress_ifindex);
    let Some(flow_key) = flow_key else {
        return CoSTxSelection {
            queue_id: iface.map(|iface| iface.default_queue),
            dscp_rewrite: None,
        };
    };
    let is_v6 = meta.addr_family as i32 == libc::AF_INET6;
    let has_output_tx_eval = crate::filter::interface_output_filter_needs_tx_eval(
        &forwarding.filter_state,
        egress_ifindex,
        is_v6,
    );
    let has_input_tx_selection =
        crate::filter::filter_state_has_input_tx_selection(&forwarding.filter_state, is_v6);
    if iface.is_none() && !has_output_tx_eval && !has_input_tx_selection {
        return CoSTxSelection {
            queue_id: None,
            dscp_rewrite: None,
        };
    }
    let output_filter = if has_output_tx_eval {
        if is_v6 {
            forwarding
                .filter_state
                .iface_filter_out_v6_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        } else {
            forwarding
                .filter_state
                .iface_filter_out_v4_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        }
    } else {
        None
    };
    let has_output_filter = output_filter.is_some();
    let ingress_ifindex = if !has_output_filter && has_input_tx_selection {
        resolve_ingress_logical_ifindex(
            forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32)
    } else {
        0
    };
    let ingress_filter = if !has_output_filter && has_input_tx_selection {
        if is_v6 {
            forwarding
                .filter_state
                .iface_filter_v6_fast
                .get(&ingress_ifindex)
                .map(Arc::as_ref)
        } else {
            forwarding
                .filter_state
                .iface_filter_v4_fast
                .get(&ingress_ifindex)
                .map(Arc::as_ref)
        }
    } else {
        None
    };
    let output_result = if let Some(output_filter) =
        output_filter.filter(|filter| filter.affects_tx_selection || filter.has_counter_terms)
    {
        crate::filter::evaluate_filter_ref_tx_selection_counted(
            output_filter,
            flow_key.src_ip,
            flow_key.dst_ip,
            flow_key.protocol,
            flow_key.src_port,
            flow_key.dst_port,
            meta.dscp,
            meta.pkt_len as u64,
        )
    } else {
        crate::filter::TxSelectionFilterResult::default()
    };
    let mut effective_dscp_rewrite = output_result.dscp_rewrite;
    let mut ingress_forwarding_class = None;
    if let Some(ingress_filter) = ingress_filter.filter(|filter| filter.affects_tx_selection) {
        let ingress_result = crate::filter::evaluate_filter_ref_tx_selection_counted(
            ingress_filter,
            flow_key.src_ip,
            flow_key.dst_ip,
            flow_key.protocol,
            flow_key.src_port,
            flow_key.dst_port,
            meta.dscp,
            meta.pkt_len as u64,
        );
        effective_dscp_rewrite = effective_dscp_rewrite.or(ingress_result.dscp_rewrite);
        ingress_forwarding_class = ingress_result.forwarding_class;
    }
    let Some(iface) = iface else {
        return CoSTxSelection {
            queue_id: None,
            dscp_rewrite: effective_dscp_rewrite,
        };
    };
    if let Some(forwarding_class) = output_result.forwarding_class {
        if let Some(queue_id) = iface.queue_by_forwarding_class.get(forwarding_class) {
            return CoSTxSelection {
                queue_id: Some(*queue_id),
                dscp_rewrite: effective_dscp_rewrite,
            };
        }
    }
    if let Some(forwarding_class) = ingress_forwarding_class {
        if let Some(queue_id) = iface.queue_by_forwarding_class.get(forwarding_class) {
            return CoSTxSelection {
                queue_id: Some(*queue_id),
                dscp_rewrite: effective_dscp_rewrite,
            };
        }
    }
    if let Some(queue_id) = resolve_cos_dscp_classifier_queue_id(iface, meta.dscp) {
        return CoSTxSelection {
            queue_id: Some(queue_id),
            dscp_rewrite: effective_dscp_rewrite,
        };
    }
    if let Some(queue_id) = resolve_cos_ieee8021_classifier_queue_id(
        iface,
        meta.ingress_pcp,
        meta.ingress_vlan_present != 0,
    ) {
        return CoSTxSelection {
            queue_id: Some(queue_id),
            dscp_rewrite: effective_dscp_rewrite,
        };
    }
    CoSTxSelection {
        queue_id: Some(iface.default_queue),
        dscp_rewrite: effective_dscp_rewrite,
    }
}

fn resolve_cos_dscp_classifier_queue_id(iface: &CoSInterfaceConfig, dscp: u8) -> Option<u8> {
    let queue_id = iface.dscp_queue_by_dscp[usize::from(dscp & 0x3f)];
    (queue_id != u8::MAX).then_some(queue_id)
}

fn resolve_cos_ieee8021_classifier_queue_id(
    iface: &CoSInterfaceConfig,
    pcp: u8,
    vlan_present: bool,
) -> Option<u8> {
    if !vlan_present {
        return None;
    }
    let queue_id = iface.ieee8021_queue_by_pcp[usize::from(pcp.min(7))];
    (queue_id != u8::MAX).then_some(queue_id)
}

pub(super) fn enqueue_local_into_cos(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    req: TxRequest,
    now_ns: u64,
) -> Result<(), TxRequest> {
    let egress_ifindex = req.egress_ifindex;
    if !ensure_cos_interface_runtime(binding, forwarding, egress_ifindex, now_ns) {
        return Err(req);
    }
    if binding
        .cos_interfaces
        .get(&egress_ifindex)
        .is_some_and(|root| cos_queue_accepts_prepared(root, req.cos_queue_id))
    {
        match prepare_local_request_for_cos(binding.umem.area(), &mut binding.free_tx_frames, req) {
            Ok(prepared_req) => {
                let item_len = prepared_req.len as u64;
                match enqueue_cos_item(
                    binding,
                    egress_ifindex,
                    prepared_req.cos_queue_id,
                    item_len,
                    CoSPendingTxItem::Prepared(prepared_req),
                ) {
                    Ok(()) => return Ok(()),
                    Err(CoSPendingTxItem::Prepared(prepared_req)) => {
                        let req =
                            clone_prepared_request_for_cos(binding.umem.area(), &prepared_req)
                                .expect("prepared CoS fallback clone");
                        recycle_prepared_immediately(binding, &prepared_req);
                        let item_len = req.bytes.len() as u64;
                        return match enqueue_cos_item(
                            binding,
                            egress_ifindex,
                            req.cos_queue_id,
                            item_len,
                            CoSPendingTxItem::Local(req),
                        ) {
                            Ok(()) => Ok(()),
                            Err(CoSPendingTxItem::Local(req)) => Err(req),
                            Err(CoSPendingTxItem::Prepared(_)) => {
                                unreachable!("local request returned prepared item")
                            }
                        };
                    }
                    Err(CoSPendingTxItem::Local(_)) => {
                        unreachable!("local request prepared into prepared item")
                    }
                }
            }
            Err(req) => {
                // Fall through to the local CoS path when no TX frame is
                // available or the request cannot be materialized safely.
                let area = binding.umem.area();
                let slot = binding.slot;
                if let Some(root) = binding.cos_interfaces.get_mut(&egress_ifindex) {
                    let _ = demote_prepared_cos_queue_to_local(
                        area,
                        &mut binding.free_tx_frames,
                        &mut binding.pending_fill_frames,
                        slot,
                        root,
                        req.cos_queue_id,
                    );
                }
                let req = req;
                let item_len = req.bytes.len() as u64;
                return match enqueue_cos_item(
                    binding,
                    egress_ifindex,
                    req.cos_queue_id,
                    item_len,
                    CoSPendingTxItem::Local(req),
                ) {
                    Ok(()) => Ok(()),
                    Err(CoSPendingTxItem::Local(req)) => Err(req),
                    Err(CoSPendingTxItem::Prepared(_)) => {
                        unreachable!("local request returned prepared item")
                    }
                };
            }
        }
    }
    let item_len = req.bytes.len() as u64;
    match enqueue_cos_item(
        binding,
        egress_ifindex,
        req.cos_queue_id,
        item_len,
        CoSPendingTxItem::Local(req),
    ) {
        Ok(()) => Ok(()),
        Err(CoSPendingTxItem::Local(req)) => Err(req),
        Err(CoSPendingTxItem::Prepared(_)) => unreachable!("local request returned prepared item"),
    }
}

fn prepare_local_request_for_cos(
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    req: TxRequest,
) -> Result<PreparedTxRequest, TxRequest> {
    if req.bytes.len() > tx_frame_capacity() {
        return Err(req);
    }
    let Some(offset) = free_tx_frames.pop_front() else {
        return Err(req);
    };
    let Some(frame) = (unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) })
    else {
        free_tx_frames.push_front(offset);
        return Err(req);
    };
    frame.copy_from_slice(&req.bytes);
    Ok(PreparedTxRequest {
        offset,
        len: req.bytes.len() as u32,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: req.expected_ports,
        expected_addr_family: req.expected_addr_family,
        expected_protocol: req.expected_protocol,
        flow_key: req.flow_key,
        egress_ifindex: req.egress_ifindex,
        cos_queue_id: req.cos_queue_id,
        dscp_rewrite: req.dscp_rewrite,
    })
}

fn enqueue_prepared_into_cos(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    req: PreparedTxRequest,
    now_ns: u64,
) -> Result<(), PreparedTxRequest> {
    let egress_ifindex = req.egress_ifindex;
    if !ensure_cos_interface_runtime(binding, forwarding, egress_ifindex, now_ns) {
        return Err(req);
    }
    if binding
        .cos_interfaces
        .get(&egress_ifindex)
        .is_some_and(|root| cos_queue_accepts_prepared(root, req.cos_queue_id))
    {
        let item_len = req.len as u64;
        match enqueue_cos_item(
            binding,
            egress_ifindex,
            req.cos_queue_id,
            item_len,
            CoSPendingTxItem::Prepared(req),
        ) {
            Ok(()) => return Ok(()),
            Err(CoSPendingTxItem::Prepared(req)) => return Err(req),
            Err(CoSPendingTxItem::Local(_)) => unreachable!("prepared request returned local item"),
        }
    }

    let Some(local_req) = clone_prepared_request_for_cos(binding.umem.area(), &req) else {
        return Err(req);
    };
    // Keep prepared/direct frames in CoS while a queue stays prepared-only.
    // Once any copied local item enters that queue, later prepared frames must
    // fall back to local copies until the queue drains empty again; otherwise a
    // local head item can block behind prepared frames that are holding every
    // free TX frame on the owner binding.
    let item_len = local_req.bytes.len() as u64;
    match enqueue_cos_item(
        binding,
        egress_ifindex,
        local_req.cos_queue_id,
        item_len,
        CoSPendingTxItem::Local(local_req),
    ) {
        Ok(()) => {
            recycle_prepared_immediately(binding, &req);
            Ok(())
        }
        Err(CoSPendingTxItem::Local(_)) => Err(req),
        Err(CoSPendingTxItem::Prepared(_)) => {
            unreachable!("prepared queueing converted to local request")
        }
    }
}

fn clone_prepared_request_for_cos(area: &MmapArea, req: &PreparedTxRequest) -> Option<TxRequest> {
    let frame = area.slice(req.offset as usize, req.len as usize)?.to_vec();
    Some(TxRequest {
        bytes: frame,
        expected_ports: req.expected_ports,
        expected_addr_family: req.expected_addr_family,
        expected_protocol: req.expected_protocol,
        flow_key: req.flow_key.clone(),
        egress_ifindex: req.egress_ifindex,
        cos_queue_id: req.cos_queue_id,
        dscp_rewrite: req.dscp_rewrite,
    })
}

fn resolve_cos_queue_idx(root: &CoSInterfaceRuntime, requested_queue: Option<u8>) -> Option<usize> {
    if root.queues.is_empty() {
        return None;
    }
    if let Some(queue_id) = requested_queue {
        return root
            .queues
            .iter()
            .position(|queue| queue.queue_id == queue_id);
    }
    root.queues
        .iter()
        .position(|queue| queue.queue_id == root.default_queue)
        .or_else(|| (!root.queues.is_empty()).then_some(0))
}

fn recycle_cancelled_prepared_offset(
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    recycle: PreparedTxRecycle,
    offset: u64,
) {
    match recycle {
        PreparedTxRecycle::FreeTxFrame => free_tx_frames.push_back(offset),
        PreparedTxRecycle::FillOnSlot(fill_slot) if fill_slot == slot => {
            pending_fill_frames.push_back(offset);
        }
        PreparedTxRecycle::FillOnSlot(_) => free_tx_frames.push_back(offset),
    }
}

fn demote_prepared_cos_queue_to_local(
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    root: &mut CoSInterfaceRuntime,
    requested_queue: Option<u8>,
) -> bool {
    let Some(queue_idx) = resolve_cos_queue_idx(root, requested_queue) else {
        return false;
    };
    let Some(queue) = root.queues.get_mut(queue_idx) else {
        return false;
    };
    if !queue.exact || cos_queue_is_empty(queue) {
        return false;
    }
    let drained = cos_queue_drain_all(queue);
    let mut local_items = VecDeque::with_capacity(drained.len());
    let mut recycles = Vec::with_capacity(drained.len());
    for item in &drained {
        let CoSPendingTxItem::Prepared(req) = item else {
            cos_queue_restore_front(queue, drained);
            return false;
        };
        let Some(local_req) = clone_prepared_request_for_cos(area, req) else {
            cos_queue_restore_front(queue, drained);
            return false;
        };
        local_items.push_back(CoSPendingTxItem::Local(local_req));
        recycles.push((req.recycle, req.offset));
    }
    for item in local_items {
        cos_queue_push_back(queue, item);
    }
    for (recycle, offset) in recycles {
        recycle_cancelled_prepared_offset(
            free_tx_frames,
            pending_fill_frames,
            slot,
            recycle,
            offset,
        );
    }
    true
}

fn cos_queue_accepts_prepared(root: &CoSInterfaceRuntime, requested_queue: Option<u8>) -> bool {
    let Some(queue_idx) = resolve_cos_queue_idx(root, requested_queue) else {
        return false;
    };
    let Some(queue) = root.queues.get(queue_idx) else {
        return false;
    };
    if !queue.flow_fair {
        return !queue
            .items
            .iter()
            .any(|item| matches!(item, CoSPendingTxItem::Local(_)));
    }
    !queue.flow_rr_buckets.iter().any(|bucket| {
        queue.flow_bucket_items[usize::from(bucket)]
            .iter()
            .any(|item| matches!(item, CoSPendingTxItem::Local(_)))
    })
}

fn ensure_cos_interface_runtime(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    now_ns: u64,
) -> bool {
    if egress_ifindex <= 0 {
        return false;
    }
    let Some(config) = forwarding.cos.interfaces.get(&egress_ifindex) else {
        return false;
    };
    if !binding.cos_fast_interfaces.contains_key(&egress_ifindex) {
        return false;
    }
    if !binding.cos_interfaces.contains_key(&egress_ifindex) {
        let mut runtime = build_cos_interface_runtime(config, now_ns);
        if let Some(iface_fast) = binding.cos_fast_interfaces.get(&egress_ifindex) {
            for (queue, queue_fast) in runtime.queues.iter_mut().zip(&iface_fast.queue_fast_path) {
                queue.flow_fair = queue.exact && !queue_fast.shared_exact;
                // Draw the SFQ salt only for queues that actually use the
                // flow-fair path. Non-flow-fair queues do not consult the
                // seed (exact_cos_flow_bucket is only called from the
                // flow-fair callers), so issuing a getrandom syscall for
                // them would be wasted work. Keeping them at seed=0 also
                // preserves byte-identical legacy behavior on that path.
                if queue.flow_fair {
                    queue.flow_hash_seed = cos_flow_hash_seed_from_os();
                }
            }
        }
        binding.cos_interfaces.insert(egress_ifindex, runtime);
        binding.cos_interface_order.push(egress_ifindex);
        binding.cos_interface_order.sort_unstable();
    }
    true
}

fn build_cos_interface_runtime(config: &CoSInterfaceConfig, now_ns: u64) -> CoSInterfaceRuntime {
    let mut queue_indices_by_priority: [Vec<usize>; COS_PRIORITY_LEVELS] =
        std::array::from_fn(|_| Vec::new());
    for (idx, queue) in config.queues.iter().enumerate() {
        let priority = usize::from(queue.priority).min(COS_PRIORITY_LEVELS - 1);
        queue_indices_by_priority[priority].push(idx);
    }
    CoSInterfaceRuntime {
        shaping_rate_bytes: config.shaping_rate_bytes,
        burst_bytes: config.burst_bytes.max(COS_MIN_BURST_BYTES),
        tokens: 0,
        default_queue: config.default_queue,
        nonempty_queues: 0,
        runnable_queues: 0,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: config
            .queues
            .iter()
            .map(|queue| CoSQueueRuntime {
                queue_id: queue.queue_id,
                priority: queue.priority,
                transmit_rate_bytes: queue.transmit_rate_bytes,
                exact: queue.exact,
                flow_fair: false,
                // Zero until `ensure_cos_interface_runtime` promotes a queue
                // onto the flow-fair path and draws a real seed. On the
                // non-flow-fair path this field is never read.
                flow_hash_seed: 0,
                surplus_weight: queue.surplus_weight,
                surplus_deficit: 0,
                buffer_bytes: queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
                dscp_rewrite: queue.dscp_rewrite,
                tokens: if queue.exact {
                    0
                } else {
                    queue.buffer_bytes.max(COS_MIN_BURST_BYTES)
                },
                last_refill_ns: if queue.exact { 0 } else { now_ns },
                queued_bytes: 0,
                active_flow_buckets: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                drop_counters: CoSQueueDropCounters::default(),
            })
            .collect(),
        queue_indices_by_priority,
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: cos_tick_for_ns(now_ns),
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
        },
    }
}

fn cos_queue_dscp_rewrite(
    binding: &BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
) -> Option<u8> {
    binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .and_then(|queue| queue.dscp_rewrite)
}

fn assign_local_dscp_rewrite(items: &mut VecDeque<TxRequest>, queue_dscp_rewrite: Option<u8>) {
    if queue_dscp_rewrite.is_none() {
        return;
    }
    for req in items.iter_mut() {
        req.dscp_rewrite = req.dscp_rewrite.or(queue_dscp_rewrite);
    }
}

fn assign_prepared_dscp_rewrite(
    items: &mut VecDeque<PreparedTxRequest>,
    queue_dscp_rewrite: Option<u8>,
) {
    if queue_dscp_rewrite.is_none() {
        return;
    }
    for req in items.iter_mut() {
        req.dscp_rewrite = req.dscp_rewrite.or(queue_dscp_rewrite);
    }
}

fn enqueue_cos_item(
    binding: &mut BindingWorker,
    egress_ifindex: i32,
    requested_queue: Option<u8>,
    item_len: u64,
    mut item: CoSPendingTxItem,
) -> Result<(), CoSPendingTxItem> {
    let mut root_became_nonempty = false;
    let (accepted, queue_id, recycle) = {
        let Some(root) = binding.cos_interfaces.get_mut(&egress_ifindex) else {
            return Err(item);
        };
        let Some(mut queue_idx) = resolve_cos_queue_idx(root, requested_queue) else {
            return Err(item);
        };
        if queue_idx >= root.queues.len() {
            queue_idx = 0;
        }
        let root_was_empty = root.nonempty_queues == 0;
        let queue = &mut root.queues[queue_idx];
        // #707: aggregate cap scales with prospective-active flow count
        // so the per-flow fast-retransmit floor can be satisfied, and
        // the aggregate gate uses the same denominator as the per-flow
        // clamp — otherwise the first packet of a new flow can get
        // stuck at the boundary even when the per-flow path is trying
        // to admit it. Compute `flow_bucket` once so both gates key off
        // the same queue state snapshot.
        let flow_bucket = if queue.flow_fair {
            cos_flow_bucket_index(queue.flow_hash_seed, cos_item_flow_key(&item))
        } else {
            0
        };
        let buffer_limit = cos_flow_aware_buffer_limit(queue, flow_bucket);
        let flow_share_exceeded = if queue.flow_fair {
            queue.flow_bucket_bytes[flow_bucket].saturating_add(item_len)
                > cos_queue_flow_share_limit(queue, buffer_limit, flow_bucket)
        } else {
            false
        };
        let buffer_exceeded = queue.queued_bytes.saturating_add(item_len) > buffer_limit;
        // #718: ECN CE-mark above threshold so ECN-negotiated TCP flows
        // back off smoothly rather than tail-dropping into RTO. Non-ECT
        // packets are untouched — they fall back to the existing
        // admission drop path below. Mark only when the packet will
        // actually be admitted: a marked-and-then-dropped packet wastes
        // both the mark and the bandwidth the mark was trying to steer.
        let _ = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            flow_share_exceeded,
            buffer_exceeded,
            &mut item,
        );
        if flow_share_exceeded || buffer_exceeded {
            // #710: attribute the drop to the specific admission-path
            // reason. `flow_share_exceeded` is checked first so that
            // when both caps trip simultaneously, the root cause
            // (per-flow bucket saturation under SFQ collision / cap
            // undersizing) is counted rather than the buffer cap — the
            // buffer-cap hit is a symptom downstream of flow-share
            // admission failing to throttle the flow.
            if flow_share_exceeded {
                queue.drop_counters.admission_flow_share_drops = queue
                    .drop_counters
                    .admission_flow_share_drops
                    .wrapping_add(1);
            } else {
                queue.drop_counters.admission_buffer_drops =
                    queue.drop_counters.admission_buffer_drops.wrapping_add(1);
            }
            let recycle = match &item {
                CoSPendingTxItem::Prepared(req) => Some((req.recycle, req.offset)),
                CoSPendingTxItem::Local(_) => None,
            };
            (false, queue.queue_id, recycle)
        } else {
            let queue_was_empty = cos_queue_is_empty(queue);
            queue.queued_bytes = queue.queued_bytes.saturating_add(item_len);
            cos_queue_push_back(queue, item);
            if queue_was_empty {
                root.nonempty_queues = root.nonempty_queues.saturating_add(1);
                root_became_nonempty = root_was_empty;
            }
            if !queue.parked && !queue.runnable {
                root.runnable_queues = root.runnable_queues.saturating_add(1);
            }
            if !queue.parked {
                mark_cos_queue_runnable(queue);
            }
            (true, queue.queue_id, None)
        }
    };
    if root_became_nonempty {
        binding.cos_nonempty_interfaces = binding.cos_nonempty_interfaces.saturating_add(1);
    }
    if accepted {
        return Ok(());
    }
    if let Some((recycle, offset)) = recycle {
        match recycle {
            PreparedTxRecycle::FreeTxFrame => binding.free_tx_frames.push_back(offset),
            PreparedTxRecycle::FillOnSlot(slot) if slot == binding.slot => {
                binding.pending_fill_frames.push_back(offset);
            }
            PreparedTxRecycle::FillOnSlot(_) => binding.free_tx_frames.push_back(offset),
        }
    }
    binding.dbg_pending_overflow += 1;
    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
    binding.live.set_error(format!(
        "class-of-service queue overflow on ifindex {} queue {}",
        egress_ifindex, queue_id
    ));
    Ok(())
}

fn refresh_cos_interface_activity(binding: &mut BindingWorker, root_ifindex: i32) {
    let mut new_nonempty = 0usize;
    let mut new_runnable = 0usize;
    let mut released_queue_leases = Vec::<(usize, u64)>::new();
    let old_nonempty = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.nonempty_queues)
        .unwrap_or(0);
    if let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) {
        for (queue_idx, queue) in root.queues.iter_mut().enumerate() {
            normalize_cos_queue_state(queue);
            if cos_queue_is_empty(queue) && queue.exact && queue.tokens > 0 {
                released_queue_leases.push((queue_idx, core::mem::take(&mut queue.tokens)));
            }
            if cos_queue_is_empty(queue) {
                continue;
            }
            new_nonempty = new_nonempty.saturating_add(1);
            if queue.runnable {
                new_runnable = new_runnable.saturating_add(1);
            }
        }
        root.nonempty_queues = new_nonempty;
        root.runnable_queues = new_runnable;
    }
    if old_nonempty == 0 && new_nonempty > 0 {
        binding.cos_nonempty_interfaces = binding.cos_nonempty_interfaces.saturating_add(1);
    } else if old_nonempty > 0 && new_nonempty == 0 {
        binding.cos_nonempty_interfaces = binding.cos_nonempty_interfaces.saturating_sub(1);
        release_cos_root_lease(binding, root_ifindex);
    }
    if let Some(iface_fast) = binding.cos_fast_interfaces.get(&root_ifindex) {
        for (queue_idx, released) in released_queue_leases {
            if let Some(shared_queue_lease) = iface_fast
                .queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
            {
                shared_queue_lease.release_unused(released);
            }
        }
    }
}

fn release_cos_root_lease(binding: &mut BindingWorker, root_ifindex: i32) {
    let released = binding
        .cos_interfaces
        .get_mut(&root_ifindex)
        .map(|root| core::mem::take(&mut root.tokens))
        .unwrap_or(0);
    if released == 0 {
        return;
    }
    if let Some(shared_root_lease) = binding
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.release_unused(released);
    }
}

pub(super) fn release_all_cos_root_leases(binding: &mut BindingWorker) {
    let root_ifindexes = binding.cos_interfaces.keys().copied().collect::<Vec<_>>();
    for root_ifindex in root_ifindexes {
        release_cos_root_lease(binding, root_ifindex);
    }
}

pub(super) fn release_all_cos_queue_leases(binding: &mut BindingWorker) {
    let queue_keys = binding
        .cos_interfaces
        .iter()
        .flat_map(|(&root_ifindex, root)| {
            root.queues
                .iter()
                .enumerate()
                .filter(|(_, queue)| queue.exact && queue.tokens > 0)
                .map(move |(queue_idx, _)| (root_ifindex, queue_idx))
        })
        .collect::<Vec<_>>();
    for (root_ifindex, queue_idx) in queue_keys {
        let released = binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx))
            .map(|queue| core::mem::take(&mut queue.tokens))
            .unwrap_or(0);
        if released == 0 {
            continue;
        }
        if let Some(shared_queue_lease) = binding
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
        {
            shared_queue_lease.release_unused(released);
        }
    }
}

fn cos_item_len(item: &CoSPendingTxItem) -> u64 {
    match item {
        CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
        CoSPendingTxItem::Prepared(req) => req.len as u64,
    }
}

fn apply_cos_send_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    sent_bytes: u64,
    retry: VecDeque<TxRequest>,
) {
    let mut exact_queue_idx = None;
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            exact_queue_idx = queue.exact.then_some(queue_idx);
            let retry_bytes = restore_cos_local_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
            match phase {
                CoSServicePhase::Guarantee => {
                    queue.tokens = queue.tokens.saturating_sub(sent_bytes);
                }
                CoSServicePhase::Surplus => {
                    queue.surplus_deficit = queue.surplus_deficit.saturating_sub(sent_bytes);
                }
            }
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    if let Some(queue_idx) = exact_queue_idx {
        if let Some(shared_queue_lease) = binding
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
        {
            shared_queue_lease.consume(sent_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn apply_cos_prepared_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    sent_bytes: u64,
    retry: VecDeque<PreparedTxRequest>,
) {
    let mut exact_queue_idx = None;
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            exact_queue_idx = queue.exact.then_some(queue_idx);
            let retry_bytes = restore_cos_prepared_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
            match phase {
                CoSServicePhase::Guarantee => {
                    queue.tokens = queue.tokens.saturating_sub(sent_bytes);
                }
                CoSServicePhase::Surplus => {
                    queue.surplus_deficit = queue.surplus_deficit.saturating_sub(sent_bytes);
                }
            }
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    if let Some(queue_idx) = exact_queue_idx {
        if let Some(shared_queue_lease) = binding
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
        {
            shared_queue_lease.consume(sent_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn restore_cos_local_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    retry: VecDeque<TxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            let retry_bytes = restore_cos_local_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn restore_cos_prepared_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    retry: VecDeque<PreparedTxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            let retry_bytes = restore_cos_prepared_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn restore_cos_local_items_inner(
    queue: &mut CoSQueueRuntime,
    mut retry: VecDeque<TxRequest>,
) -> u64 {
    let mut retry_bytes = 0u64;
    while let Some(req) = retry.pop_back() {
        retry_bytes = retry_bytes.saturating_add(req.bytes.len() as u64);
        cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
    }
    if !cos_queue_is_empty(queue) {
        mark_cos_queue_runnable(queue);
    }
    retry_bytes
}

fn restore_cos_prepared_items_inner(
    queue: &mut CoSQueueRuntime,
    mut retry: VecDeque<PreparedTxRequest>,
) -> u64 {
    let mut retry_bytes = 0u64;
    while let Some(req) = retry.pop_back() {
        retry_bytes = retry_bytes.saturating_add(req.len as u64);
        cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
    }
    if !cos_queue_is_empty(queue) {
        mark_cos_queue_runnable(queue);
    }
    retry_bytes
}

fn process_pending_queue_in_place<T, F>(pending: &mut VecDeque<T>, mut f: F)
where
    F: FnMut(T) -> Result<(), T>,
{
    let initial_len = pending.len();
    for _ in 0..initial_len {
        let Some(item) = pending.pop_front() else {
            break;
        };
        if let Err(item) = f(item) {
            pending.push_back(item);
        }
    }
}

fn take_pending_tx_requests(binding: &mut BindingWorker) -> VecDeque<TxRequest> {
    // Reuse the worker-owned `pending_tx_local` buffer as the drain
    // target so the owner-worker hot path stays allocation-free. `pop`
    // from the lock-free inbox appends into the same buffer without a
    // queue-to-queue copy.
    let mut out = core::mem::take(&mut binding.pending_tx_local);
    binding.live.take_pending_tx_into(&mut out);
    out
}

fn restore_pending_tx_requests(binding: &mut BindingWorker, mut retry: VecDeque<TxRequest>) {
    retry.append(&mut binding.pending_tx_local);
    binding.pending_tx_local = retry;
    bound_pending_tx_local(binding);
}

fn apply_prepared_recycle(
    free_tx_frames: &mut VecDeque<u64>,
    shared_recycles: &mut Vec<(u32, u64)>,
    recycle: PreparedTxRecycle,
    offset: u64,
) {
    match recycle {
        PreparedTxRecycle::FreeTxFrame => free_tx_frames.push_back(offset),
        PreparedTxRecycle::FillOnSlot(slot) => shared_recycles.push((slot, offset)),
    }
}

fn recycle_completed_tx_offset(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
    offset: u64,
) {
    if let Some(recycle) = binding.in_flight_prepared_recycles.remove(&offset) {
        apply_prepared_recycle(
            &mut binding.free_tx_frames,
            shared_recycles,
            recycle,
            offset,
        );
    } else {
        binding.free_tx_frames.push_back(offset);
    }
}

pub(super) fn recycle_prepared_immediately(binding: &mut BindingWorker, req: &PreparedTxRequest) {
    recycle_cancelled_prepared_offset(
        &mut binding.free_tx_frames,
        &mut binding.pending_fill_frames,
        binding.slot,
        req.recycle,
        req.offset,
    );
}

fn remember_prepared_recycle(
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    req: &PreparedTxRequest,
) {
    if let PreparedTxRecycle::FillOnSlot(_) = req.recycle {
        in_flight_prepared_recycles.insert(req.offset, req.recycle);
    }
}

pub(super) fn transmit_batch(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<TxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() {
        return Ok((0, 0));
    }
    if binding.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let batch_size = pending
        .len()
        .min(binding.free_tx_frames.len())
        .min(TX_BATCH_SIZE);
    if batch_size == 0 {
        maybe_wake_tx(binding, true, now_ns);
        return Err(TxError::Retry("no free TX frame available".to_string()));
    }

    binding.scratch_local_tx.clear();
    while binding.scratch_local_tx.len() < batch_size {
        let Some(mut req) = pending.pop_front() else {
            break;
        };
        if let Some(dscp_rewrite) = req.dscp_rewrite {
            let _ = apply_dscp_rewrite_to_frame(&mut req.bytes, dscp_rewrite);
        }
        if req.bytes.len() > tx_frame_capacity() {
            // Unwind already-prepared entries before returning.
            for (off, r) in binding.scratch_local_tx.drain(..) {
                binding.free_tx_frames.push_back(off);
                pending.push_front(r);
            }
            return Err(TxError::Drop(format!(
                "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                req.bytes.len(),
                tx_frame_capacity()
            )));
        }
        let Some(offset) = binding.free_tx_frames.pop_front() else {
            pending.push_front(req);
            break;
        };
        let Some(frame) = (unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(offset as usize, req.bytes.len())
        }) else {
            binding.free_tx_frames.push_front(offset);
            // Unwind already-prepared entries before returning.
            for (off, r) in binding.scratch_local_tx.drain(..) {
                binding.free_tx_frames.push_back(off);
                pending.push_front(r);
            }
            return Err(TxError::Drop(format!(
                "tx frame slice out of range: offset={offset} len={}",
                req.bytes.len()
            )));
        };
        frame.copy_from_slice(&req.bytes);
        // RST detection: log when we're about to transmit a TCP RST
        if cfg!(feature = "debug-log") {
            if frame_has_tcp_rst(&req.bytes) {
                binding.dbg_tx_tcp_rst += 1;
                thread_local! {
                    static TX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                TX_RST_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 50 {
                        c.set(n + 1);
                        let summary = decode_frame_summary(&req.bytes);
                        eprintln!(
                            "RST_DETECT TX[{}]: slot={} len={} {}",
                            n,
                            binding.slot,
                            req.bytes.len(),
                            summary,
                        );
                        if n < 5 {
                            let hex_len = req.bytes.len().min(80);
                            let hex: String = req.bytes[..hex_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            eprintln!("RST_DETECT TX_HEX[{n}]: {hex}");
                        }
                    }
                });
            }
        }
        binding.scratch_local_tx.push((offset, req));
    }

    if binding.scratch_local_tx.is_empty() {
        maybe_wake_tx(binding, true, now_ns);
        return Err(TxError::Retry("no prepared TX frame available".to_string()));
    }

    let mut writer = binding.tx.transmit(binding.scratch_local_tx.len() as u32);
    let inserted = writer.insert(
        binding
            .scratch_local_tx
            .iter()
            .map(|(offset, req)| XdpDesc {
                addr: *offset,
                len: req.bytes.len() as u32,
                options: 0,
            }),
    );
    writer.commit();
    drop(writer);

    if inserted == 0 {
        binding.dbg_tx_ring_full += 1;
        maybe_wake_tx(binding, true, now_ns);
        while let Some((offset, req)) = binding.scratch_local_tx.pop() {
            binding.free_tx_frames.push_front(offset);
            pending.push_front(req);
        }
        return Err(TxError::Retry("tx ring insert failed".to_string()));
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    let mut retry_tail = Vec::new();
    for (idx, (offset, req)) in binding.scratch_local_tx.drain(..).enumerate() {
        if idx < inserted as usize {
            sent_packets += 1;
            sent_bytes += req.bytes.len() as u64;
        } else {
            binding.free_tx_frames.push_front(offset);
            retry_tail.push(req);
        }
    }
    for req in retry_tail.into_iter().rev() {
        pending.push_front(req);
    }

    // Latency-sensitive reply traffic can stall indefinitely on otherwise idle zerocopy
    // bindings unless we explicitly kick TX after committing descriptors.
    maybe_wake_tx(binding, true, now_ns);
    Ok((sent_packets, sent_bytes))
}

pub(super) fn transmit_prepared_batch(
    binding: &mut BindingWorker,
    now_ns: u64,
) -> Result<(u64, u64), TxError> {
    let mut pending = core::mem::take(&mut binding.pending_tx_prepared);
    let result = transmit_prepared_queue(binding, &mut pending, now_ns);
    binding.pending_tx_prepared = pending;
    result
}

fn transmit_prepared_queue(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() {
        return Ok((0, 0));
    }
    let batch_size = pending.len().min(TX_BATCH_SIZE);
    binding.scratch_prepared_tx.clear();
    while binding.scratch_prepared_tx.len() < batch_size {
        let Some(req) = pending.pop_front() else {
            break;
        };
        if req.len as usize > tx_frame_capacity() {
            let orphaned: Vec<_> = binding.scratch_prepared_tx.drain(..).collect();
            recycle_prepared_immediately(binding, &req);
            for r in &orphaned {
                recycle_prepared_immediately(binding, r);
            }
            // #710: each orphan is a silently-recycled packet that will
            // not reach the TX ring. The caller's post-return `+= 1`
            // covers the offender (`req`); this accounts for the
            // orphans so `tx_submit_error_drops` matches the actual
            // packet count lost on this Drop return.
            if !orphaned.is_empty() {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphaned.len() as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphaned.len() as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                req.len,
                tx_frame_capacity()
            )));
        }
        binding.scratch_prepared_tx.push(req);
    }
    if binding.scratch_prepared_tx.is_empty() {
        return Ok((0, 0));
    }
    for req in &binding.scratch_prepared_tx {
        let Some(dscp_rewrite) = req.dscp_rewrite else {
            continue;
        };
        let Some(frame) = (unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(req.offset as usize, req.len as usize)
        }) else {
            let err_offset = req.offset;
            let err_len = req.len;
            let orphaned: Vec<_> = binding.scratch_prepared_tx.drain(..).collect();
            for r in &orphaned {
                recycle_prepared_immediately(binding, r);
            }
            // #710: each orphan is a silently-recycled packet. Caller
            // will `+= 1` for the offender; this accounts for the rest.
            let orphan_count = orphaned.len();
            if orphan_count > 0 {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame slice out of range: offset={} len={}",
                err_offset, err_len
            )));
        };
        let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
    }
    for req in &binding.scratch_prepared_tx {
        if binding
            .umem
            .area()
            .slice(req.offset as usize, req.len as usize)
            .is_none()
        {
            let err_offset = req.offset;
            let err_len = req.len;
            let orphaned: Vec<_> = binding.scratch_prepared_tx.drain(..).collect();
            for r in &orphaned {
                recycle_prepared_immediately(binding, r);
            }
            // #710: same shape as the slice_mut_unchecked site above —
            // `orphaned` drains EVERY entry including the offender.
            // Caller adds 1 for the offender; we add (len-1) for the
            // rest so `tx_submit_error_drops` matches the actual count.
            let orphan_count = orphaned.len();
            if orphan_count > 0 {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame slice out of range: offset={} len={}",
                err_offset, err_len
            )));
        }
    }

    // RST detection on prepared TX path: check UMEM frames before submitting to TX ring
    if cfg!(feature = "debug-log") {
        for req in &binding.scratch_prepared_tx {
            if let Some(frame_data) = binding
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
            {
                if frame_has_tcp_rst(frame_data) {
                    binding.dbg_tx_tcp_rst += 1;
                    thread_local! {
                        static PREP_TX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                    }
                    PREP_TX_RST_LOG_COUNT.with(|c| {
                        let n = c.get();
                        if n < 50 {
                            c.set(n + 1);
                            let summary = decode_frame_summary(frame_data);
                            eprintln!(
                                "RST_DETECT PREP_TX[{}]: if={} q={} len={} {}",
                                n,
                                binding.identity().ifindex,
                                binding.identity().queue_id,
                                req.len,
                                summary,
                            );
                            if n < 5 {
                                let hex_len = (req.len as usize).min(frame_data.len()).min(80);
                                let hex: String = frame_data[..hex_len]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                eprintln!("RST_DETECT PREP_TX_HEX[{n}]: {hex}");
                            }
                        }
                    });
                }
            }
        }
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_prepared_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_prepared_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);

    if inserted == 0 {
        binding.dbg_tx_ring_full += 1;
        maybe_wake_tx(binding, true, now_ns);
        while let Some(req) = binding.scratch_prepared_tx.pop() {
            pending.push_front(req);
        }
        return Err(TxError::Retry("prepared tx ring insert failed".to_string()));
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    let mut retry_tail = Vec::new();
    for (idx, req) in binding.scratch_prepared_tx.drain(..).enumerate() {
        if idx < inserted as usize {
            remember_prepared_recycle(&mut binding.in_flight_prepared_recycles, &req);
            sent_packets += 1;
            sent_bytes += req.len as u64;
        } else {
            retry_tail.push(req);
        }
    }
    for req in retry_tail.into_iter().rev() {
        pending.push_front(req);
    }

    // Prepared cross-binding forwards need the same explicit TX kick.
    maybe_wake_tx(binding, true, now_ns);
    Ok((sent_packets, sent_bytes))
}

pub(super) fn maybe_wake_tx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    let bind_mode = XskBindMode::from_u8(binding.live.bind_mode.load(Ordering::Relaxed));
    if !bind_mode.is_zerocopy()
        || binding.tx.needs_wakeup()
        || force
        || now_ns.saturating_sub(binding.last_tx_wake_ns) >= TX_WAKE_MIN_INTERVAL_NS
    {
        // Use direct sendto() instead of binding.tx.wake() so we can capture errors.
        let fd = binding.tx.as_raw_fd();
        let rc = unsafe {
            libc::sendto(
                fd,
                core::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                core::ptr::null_mut(),
                0,
            )
        };
        binding.dbg_sendto_calls += 1;
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            // EAGAIN/EWOULDBLOCK is normal for MSG_DONTWAIT; ENOBUFS means kernel dropped.
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                binding.dbg_sendto_eagain += 1;
            } else if errno == libc::ENOBUFS {
                binding.dbg_sendto_enobufs += 1;
                if binding.dbg_sendto_enobufs <= 10 {
                    eprintln!(
                        "TX_ENOBUFS: slot={} if={} q={} outstanding_tx={} free_tx={}",
                        binding.slot,
                        binding.ifindex,
                        binding.queue_id,
                        binding.outstanding_tx,
                        binding.free_tx_frames.len(),
                    );
                }
            } else {
                binding.dbg_sendto_err += 1;
                if binding.dbg_sendto_err <= 5 {
                    eprintln!(
                        "DBG SENDTO_ERR: slot={} if={} q={} errno={} outstanding_tx={} free_tx={}",
                        binding.slot,
                        binding.ifindex,
                        binding.queue_id,
                        errno,
                        binding.outstanding_tx,
                        binding.free_tx_frames.len(),
                    );
                }
            }
        }
        binding.last_tx_wake_ns = now_ns;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
        CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot,
        CoSIEEE8021ClassifierSnapshot, CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot,
        CoSSchedulerSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    };

    fn test_queue_fast_path(
        shared_exact: bool,
        owner_worker_id: u32,
        owner_live: Option<Arc<BindingLiveState>>,
        shared_queue_lease: Option<Arc<SharedCoSQueueLease>>,
    ) -> WorkerCoSQueueFastPath {
        WorkerCoSQueueFastPath {
            shared_exact,
            owner_worker_id,
            owner_live,
            shared_queue_lease,
        }
    }

    fn test_cos_fast_interfaces(
        egress_ifindex: i32,
        tx_ifindex: i32,
        default_queue: u8,
        queue_entries: Vec<(u8, WorkerCoSQueueFastPath)>,
        tx_owner_live: Option<Arc<BindingLiveState>>,
        shared_root_lease: Option<Arc<SharedCoSRootLease>>,
    ) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
        let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
        let mut queue_fast_path = Vec::with_capacity(queue_entries.len());
        for (idx, (queue_id, queue)) in queue_entries.into_iter().enumerate() {
            queue_index_by_id[usize::from(queue_id)] = idx as u16;
            queue_fast_path.push(queue);
        }
        let default_queue_index = match queue_index_by_id[usize::from(default_queue)] {
            COS_FAST_QUEUE_INDEX_MISS => panic!("missing default queue {default_queue}"),
            idx => idx as usize,
        };
        let mut interfaces = FastMap::default();
        interfaces.insert(
            egress_ifindex,
            WorkerCoSInterfaceFastPath {
                tx_ifindex,
                default_queue_index,
                queue_index_by_id,
                tx_owner_live,
                shared_root_lease,
                queue_fast_path,
            },
        );
        interfaces
    }

    #[test]
    fn process_pending_queue_in_place_preserves_failed_item_order() {
        let mut pending = VecDeque::from([1u8, 2, 3, 4]);

        process_pending_queue_in_place(&mut pending, |item| match item {
            1 | 3 => Ok(()),
            other => Err(other),
        });

        assert_eq!(pending.into_iter().collect::<Vec<_>>(), vec![2, 4]);
    }

    #[test]
    fn cos_batch_tx_made_progress_requires_real_send_progress() {
        assert!(!cos_batch_tx_made_progress(Ok((0, 0))));
        assert!(cos_batch_tx_made_progress(Ok((1, 0))));
        assert!(cos_batch_tx_made_progress(Ok((0, 1500))));
    }

    #[test]
    fn cos_batch_tx_made_progress_yields_on_retry_and_drop() {
        assert!(!cos_batch_tx_made_progress(Err(TxError::Retry(
            "no free TX frame available".to_string()
        ))));
        assert!(!cos_batch_tx_made_progress(Err(TxError::Drop(
            "tx ring insert failed".to_string()
        ))));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_pushes_worker_command() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            None,
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        let pending = commands.lock().unwrap();
        assert_eq!(pending.len(), 1);
        match pending.front() {
            Some(WorkerCommand::EnqueueShapedLocal(req)) => {
                assert_eq!(req.egress_ifindex, 80);
                assert_eq!(req.cos_queue_id, Some(4));
            }
            other => panic!("unexpected command queued: {other:?}"),
        }
    }

    #[test]
    fn redirect_local_cos_request_to_owner_uses_interface_default_queue_owner_when_unset() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(5, test_queue_fast_path(false, 7, None, None))],
            None,
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: None,
            dscp_rewrite: None,
        };

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        let pending = commands.lock().unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn redirect_local_cos_request_to_owner_rejects_explicit_queue_miss() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(5, test_queue_fast_path(false, 7, None, None))],
            None,
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_err());
        assert!(commands.lock().unwrap().is_empty());
    }

    #[test]
    fn resolve_cos_queue_idx_rejects_explicit_queue_miss() {
        let root = test_cos_runtime_with_queues(
            10_000_000,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );

        assert_eq!(resolve_cos_queue_idx(&root, Some(4)), None);
        assert_eq!(resolve_cos_queue_idx(&root, None), Some(0));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_keeps_exact_queue_on_eligible_worker() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let tx_owner_live = Arc::new(BindingLiveState::new());
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(
                    true,
                    7,
                    None,
                    Some(Arc::new(SharedCoSQueueLease::new(
                        1_000_000,
                        COS_MIN_BURST_BYTES,
                        2,
                    ))),
                ),
            )],
            Some(tx_owner_live),
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_err());
        assert!(commands.lock().unwrap().is_empty());
    }

    #[test]
    fn shared_cos_root_lease_bounds_total_outstanding_credit() {
        let lease = SharedCoSRootLease::new(400_000_000, 256 * 1024, 2);
        let lease_bytes = lease.lease_bytes();

        let first = lease.acquire(1, lease_bytes);
        let second = lease.acquire(1, lease_bytes);
        let third = lease.acquire(1, lease_bytes);

        assert_eq!(first, lease_bytes);
        assert_eq!(second, lease_bytes);
        assert_eq!(third, 0);

        lease.release_unused(lease_bytes);
        let fourth = lease.acquire(1, lease_bytes);
        assert_eq!(fourth, lease_bytes);
    }

    #[test]
    fn shared_cos_queue_lease_bounds_total_outstanding_credit() {
        let lease = SharedCoSQueueLease::new(10_000_000, 128 * 1024, 2);
        let request = 2500;

        let first = lease.acquire(1, request);
        let second = lease.acquire(1, request);
        let third = lease.acquire(1, request);
        let fourth = lease.acquire(1, request);
        let fifth = lease.acquire(1, 1);

        assert_eq!(first, request);
        assert_eq!(second, request);
        assert_eq!(third, request);
        assert_eq!(
            first + second + third + fourth,
            (tx_frame_capacity() as u64) * 2
        );
        assert_eq!(fifth, 0);

        lease.release_unused(request);
        let sixth = lease.acquire(1, request);
        assert_eq!(sixth, request);
    }

    #[test]
    fn maybe_top_up_cos_root_lease_unblocks_large_frame_exceeding_lease_bytes() {
        // Pick a shaping rate low enough that lease_bytes() floors to COS_ROOT_LEASE_MIN_BYTES
        // (1500) and stays below tx_frame_capacity() (4096).  At 50 Mbps / 256 KB burst / 1 shard
        // the raw target lease is rate*TARGET_US/1e6 = 1250 bytes, which floors up to 1500.
        // Without the .max(tx_frame_capacity()) fix in maybe_top_up_cos_root_lease, root.tokens
        // could never exceed 1500 and any frame with len > 1500 would deadlock the CoS queue.
        let rate_bytes = 50_000_000u64 / 8;
        let lease = Arc::new(SharedCoSRootLease::new(rate_bytes, 256 * 1024, 1));
        assert!(
            lease.lease_bytes() < tx_frame_capacity() as u64,
            "precondition: lease_bytes must be below tx_frame_capacity for this regression"
        );

        let mut root = test_cos_runtime_with_queues(
            rate_bytes,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: rate_bytes,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let frame_len = tx_frame_capacity();
        root.queues[0].tokens = 64 * 1024;
        root.queues[0].runnable = true;
        root.queues[0].items.push_back(test_cos_item(frame_len));
        root.queues[0].queued_bytes = frame_len as u64;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        maybe_top_up_cos_root_lease(&mut root, &lease, 1_000_000_000);

        assert!(
            root.tokens >= frame_len as u64,
            "root tokens ({}) must cover frame len ({}) after lease top-up",
            root.tokens,
            frame_len
        );
        let batch = select_cos_guarantee_batch(&mut root, 1_000_000_000);
        assert!(
            batch.is_some(),
            "large frame must be dequeued after lease top-up"
        );
    }

    #[test]
    fn maybe_top_up_cos_queue_lease_unblocks_local_exact_queue_without_tokens() {
        let mut root = test_cos_runtime_with_queues(
            400_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 400_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 1500;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;
        let shared_queue_lease = Arc::new(SharedCoSQueueLease::new(
            400_000_000 / 8,
            COS_MIN_BURST_BYTES,
            2,
        ));
        let queue_fast_path = vec![test_queue_fast_path(
            true,
            0,
            None,
            Some(shared_queue_lease.clone()),
        )];

        maybe_top_up_cos_queue_lease(
            &mut root.queues[0],
            Some(&shared_queue_lease),
            1_000_000_000,
        );

        assert!(
            root.queues[0].tokens >= 1500,
            "shared exact queue lease must replenish local queue tokens"
        );
        assert!(
            select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000,)
                .is_some()
        );
    }

    #[test]
    fn exact_queue_without_shared_lease_does_not_locally_refill() {
        let mut root = test_cos_runtime_with_queues(
            400_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 1500;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;
        let queue_fast_path = vec![test_queue_fast_path(true, 0, None, None)];

        let batch =
            select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000);

        assert!(
            batch.is_none(),
            "exact queues must not locally refill when the shared queue lease is unavailable"
        );
        assert_eq!(root.queues[0].tokens, 0);
        assert_eq!(root.queues[0].last_refill_ns, 0);
    }

    #[test]
    fn build_cos_interface_runtime_starts_exact_queue_with_zero_local_tokens() {
        let runtime = build_cos_interface_runtime(
            &CoSInterfaceConfig {
                shaping_rate_bytes: 25_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 5,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                }],
            },
            1_000_000_000,
        );

        assert_eq!(runtime.queues[0].tokens, 0);
        assert_eq!(runtime.queues[0].last_refill_ns, 0);
    }

    #[test]
    fn redirect_local_cos_request_to_owner_binding_pushes_owner_live_queue() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            Some(owner_live.clone()),
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected =
            redirect_local_cos_request_to_owner_binding(&current_live, &cos_fast_interfaces, req);

        assert!(redirected.is_ok());
        let mut queued = VecDeque::new();
        owner_live.take_pending_tx_into(&mut queued);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
        let mut current_queued = VecDeque::new();
        current_live.take_pending_tx_into(&mut current_queued);
        assert!(current_queued.is_empty());
    }

    #[test]
    fn redirect_local_exact_cos_request_to_owner_binding_pushes_owner_live_queue() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(
                    true,
                    7,
                    None,
                    Some(Arc::new(SharedCoSQueueLease::new(
                        1_000_000,
                        COS_MIN_BURST_BYTES,
                        2,
                    ))),
                ),
            )],
            Some(owner_live.clone()),
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected =
            redirect_local_cos_request_to_owner_binding(&current_live, &cos_fast_interfaces, req);

        assert!(redirected.is_ok());
        let mut queued = VecDeque::new();
        owner_live.take_pending_tx_into(&mut queued);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
        let mut current_queued = VecDeque::new();
        current_live.take_pending_tx_into(&mut current_queued);
        assert!(current_queued.is_empty());
    }

    #[test]
    fn prepared_cos_request_stays_on_current_tx_binding_for_exact_queue() {
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(
                5,
                test_queue_fast_path(
                    true,
                    7,
                    None,
                    Some(Arc::new(SharedCoSQueueLease::new(
                        1_000_000,
                        COS_MIN_BURST_BYTES,
                        2,
                    ))),
                ),
            )],
            Some(Arc::new(BindingLiveState::new())),
            None,
        );
        let iface_fast = cos_fast_interfaces.get(&80).unwrap();
        let queue_fast = iface_fast.queue_fast_path(Some(5)).unwrap();

        assert!(prepared_cos_request_stays_on_current_tx_binding(
            12, iface_fast, queue_fast,
        ));
        assert!(!prepared_cos_request_stays_on_current_tx_binding(
            13, iface_fast, queue_fast,
        ));
    }

    #[test]
    fn prepared_cos_request_stays_on_current_tx_binding_only_for_exact_queue() {
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(5, test_queue_fast_path(false, 7, None, None))],
            Some(Arc::new(BindingLiveState::new())),
            None,
        );
        let iface_fast = cos_fast_interfaces.get(&80).unwrap();
        let queue_fast = iface_fast.queue_fast_path(Some(5)).unwrap();

        assert!(!prepared_cos_request_stays_on_current_tx_binding(
            12, iface_fast, queue_fast,
        ));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_uses_owner_live_queue_when_available() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let owner_live = Arc::new(BindingLiveState::new());
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(false, 7, Some(owner_live.clone()), None),
            )],
            None,
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        assert!(commands.lock().unwrap().is_empty());
        let mut queued = VecDeque::new();
        owner_live.take_pending_tx_into(&mut queued);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
        assert_eq!(queued.front().map(|req| req.cos_queue_id), Some(Some(4)));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_redirects_low_rate_exact_queue() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(
                    false,
                    7,
                    None,
                    Some(Arc::new(SharedCoSQueueLease::new(
                        1_000_000_000 / 8,
                        COS_MIN_BURST_BYTES,
                        4,
                    ))),
                ),
            )],
            Some(Arc::new(BindingLiveState::new())),
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        let pending = commands.lock().unwrap();
        assert_eq!(pending.len(), 1);
        match pending.front() {
            Some(WorkerCommand::EnqueueShapedLocal(req)) => {
                assert_eq!(req.egress_ifindex, 80);
                assert_eq!(req.cos_queue_id, Some(4));
            }
            other => panic!("unexpected command queued: {other:?}"),
        }
    }

    #[test]
    fn apply_prepared_recycle_routes_fill_and_free_explicitly() {
        let mut free_tx_frames = VecDeque::new();
        let mut shared_recycles = Vec::new();

        apply_prepared_recycle(
            &mut free_tx_frames,
            &mut shared_recycles,
            PreparedTxRecycle::FreeTxFrame,
            41,
        );
        apply_prepared_recycle(
            &mut free_tx_frames,
            &mut shared_recycles,
            PreparedTxRecycle::FillOnSlot(7),
            42,
        );

        assert_eq!(free_tx_frames, VecDeque::from(vec![41]));
        assert_eq!(shared_recycles, vec![(7, 42)]);
    }

    #[test]
    fn remember_prepared_recycle_tracks_only_shared_fill_recycles() {
        let mut in_flight_prepared_recycles = FastMap::default();

        remember_prepared_recycle(
            &mut in_flight_prepared_recycles,
            &PreparedTxRequest {
                offset: 41,
                len: 64,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 0,
                cos_queue_id: None,
                dscp_rewrite: None,
            },
        );
        remember_prepared_recycle(
            &mut in_flight_prepared_recycles,
            &PreparedTxRequest {
                offset: 42,
                len: 64,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 0,
                cos_queue_id: None,
                dscp_rewrite: None,
            },
        );

        assert_eq!(in_flight_prepared_recycles.len(), 1);
        assert_eq!(
            in_flight_prepared_recycles.get(&42),
            Some(&PreparedTxRecycle::FillOnSlot(7))
        );
        assert!(!in_flight_prepared_recycles.contains_key(&41));
    }

    #[test]
    fn clone_prepared_request_for_cos_returns_local_copy_with_metadata() {
        let mut area = MmapArea::new(4096).expect("mmap");
        let payload = [0xde, 0xad, 0xbe, 0xef];
        area.slice_mut(128, payload.len())
            .expect("slice")
            .copy_from_slice(&payload);
        let req = PreparedTxRequest {
            offset: 128,
            len: payload.len() as u32,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: Some((1111, 2222)),
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                src_port: 1111,
                dst_port: 2222,
            }),
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: Some(46),
        };

        let local = clone_prepared_request_for_cos(&area, &req).expect("local copy");

        assert_eq!(local.bytes, payload);
        assert_eq!(local.expected_ports, Some((1111, 2222)));
        assert_eq!(local.expected_addr_family, libc::AF_INET6 as u8);
        assert_eq!(local.expected_protocol, PROTO_TCP);
        assert_eq!(local.egress_ifindex, 80);
        assert_eq!(local.cos_queue_id, Some(4));
        assert_eq!(local.dscp_rewrite, Some(46));
        assert_eq!(
            local
                .flow_key
                .as_ref()
                .map(|key| (key.src_port, key.dst_port)),
            Some((1111, 2222))
        );
    }

    #[test]
    fn clone_prepared_request_for_cos_rejects_out_of_range_offset() {
        let area = MmapArea::new(256).expect("mmap");
        let req = PreparedTxRequest {
            offset: 1024,
            len: 64,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        assert!(clone_prepared_request_for_cos(&area, &req).is_none());
    }

    #[test]
    fn prepare_local_request_for_cos_materializes_prepared_frame() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut free_tx_frames = VecDeque::from([128]);
        let req = TxRequest {
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
            expected_ports: Some((1111, 2222)),
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                src_port: 1111,
                dst_port: 2222,
            }),
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: Some(46),
        };

        let prepared =
            prepare_local_request_for_cos(&area, &mut free_tx_frames, req).expect("prepared");

        assert_eq!(prepared.offset, 128);
        assert_eq!(prepared.len, 4);
        assert_eq!(prepared.recycle, PreparedTxRecycle::FreeTxFrame);
        assert_eq!(prepared.expected_ports, Some((1111, 2222)));
        assert_eq!(prepared.egress_ifindex, 80);
        assert_eq!(prepared.cos_queue_id, Some(5));
        assert_eq!(prepared.dscp_rewrite, Some(46));
        assert!(free_tx_frames.is_empty());
        assert_eq!(area.slice(128, 4).expect("slice"), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn prepare_local_request_for_cos_falls_back_when_no_free_tx_frame_exists() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut free_tx_frames = VecDeque::new();
        let req = TxRequest {
            bytes: vec![1, 2, 3, 4],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
        };

        let req = match prepare_local_request_for_cos(&area, &mut free_tx_frames, req) {
            Ok(_) => panic!("must fall back to local"),
            Err(req) => req,
        };

        assert_eq!(req.bytes, [1, 2, 3, 4]);
        assert!(free_tx_frames.is_empty());
    }

    #[test]
    fn cos_queue_accepts_prepared_when_queue_is_prepared_only() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        assert!(cos_queue_accepts_prepared(&root, Some(5)));
    }

    #[test]
    fn cos_queue_rejects_prepared_once_local_items_enter_queue() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![0; 1500],
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        assert!(!cos_queue_accepts_prepared(&root, Some(5)));
    }

    #[test]
    fn demote_prepared_cos_queue_to_local_recycles_frames_and_blocks_prepared_appends() {
        let area = MmapArea::new(4096).expect("mmap");
        unsafe { area.slice_mut_unchecked(64, 4) }
            .expect("frame")
            .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        unsafe { area.slice_mut_unchecked(128, 4) }
            .expect("frame")
            .copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: Some((1111, 5202)),
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 4,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: Some((1112, 5202)),
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::from([512]);
        let mut pending_fill_frames = VecDeque::new();
        assert!(demote_prepared_cos_queue_to_local(
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            &mut root,
            Some(5),
        ));

        let items = root.queues[0]
            .items
            .iter()
            .map(|item| match item {
                CoSPendingTxItem::Local(req) => req.bytes.clone(),
                CoSPendingTxItem::Prepared(_) => panic!("prepared item should be demoted"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            items,
            vec![vec![0xde, 0xad, 0xbe, 0xef], vec![0xca, 0xfe, 0xba, 0xbe]]
        );
        assert_eq!(free_tx_frames, VecDeque::from([512, 64]));
        assert_eq!(pending_fill_frames, VecDeque::from([128]));
        assert!(!cos_queue_accepts_prepared(&root, Some(5)));
    }

    #[test]
    fn demote_prepared_cos_queue_to_local_skips_non_exact_queue() {
        let area = MmapArea::new(4096).expect("mmap");
        unsafe { area.slice_mut_unchecked(64, 4) }
            .expect("frame")
            .copy_from_slice(&[1, 2, 3, 4]);

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();
        assert!(!demote_prepared_cos_queue_to_local(
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            &mut root,
            Some(5),
        ));
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(_))
        ));
        assert!(free_tx_frames.is_empty());
        assert!(pending_fill_frames.is_empty());
    }

    #[test]
    fn drain_exact_local_fifo_items_to_scratch_keeps_queue_until_commit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1, 2, 3, 4],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![5, 6, 7, 8],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 256,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::from([64, 128, 192]);
        let mut scratch_local_tx = Vec::new();

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_local_tx.len(), 2);
        assert_eq!(free_tx_frames, VecDeque::from([192]));
        assert_eq!(area.slice(64, 4).expect("first frame"), &[1, 2, 3, 4]);
        assert_eq!(area.slice(128, 4).expect("second frame"), &[5, 6, 7, 8]);
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(_))
        ));
        assert!(matches!(
            root.queues[0].items.get(2),
            Some(CoSPendingTxItem::Prepared(_))
        ));
    }

    #[test]
    fn release_exact_local_scratch_frames_preserves_queue_after_failed_submit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![2],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let mut free_tx_frames = VecDeque::from([64, 128]);
        let mut scratch_local_tx = Vec::new();

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        release_exact_local_scratch_frames(&mut free_tx_frames, &mut scratch_local_tx);
        assert!(scratch_local_tx.is_empty());
        assert_eq!(free_tx_frames, VecDeque::from([64, 128]));
        assert_eq!(root.queues[0].items.len(), 2);
        match root.queues[0].items.pop_front().expect("first queued") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![1]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
        }
        match root.queues[0].items.pop_front().expect("second queued") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
        }
    }

    #[test]
    fn settle_exact_local_fifo_submission_pops_only_committed_prefix() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![2],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![3],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let mut free_tx_frames = VecDeque::new();
        let mut scratch_local_tx = vec![
            ExactLocalScratchTxRequest { offset: 64, len: 1 },
            ExactLocalScratchTxRequest {
                offset: 128,
                len: 1,
            },
            ExactLocalScratchTxRequest {
                offset: 192,
                len: 1,
            },
        ];

        let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_tx_frames,
            &mut scratch_local_tx,
            1,
        );

        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert!(scratch_local_tx.is_empty());
        assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
        assert_eq!(root.queues[0].items.len(), 2);
        match root.queues[0].items.pop_front().expect("first restored") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
        }
        match root.queues[0].items.pop_front().expect("second restored") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![3]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
        }
    }

    #[test]
    fn exact_local_fifo_boundary_survives_partial_commit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![2],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 256,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::from([64, 128, 192]);
        let mut scratch_local_tx = Vec::new();

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_local_tx.len(), 2);

        let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_tx_frames,
            &mut scratch_local_tx,
            1,
        );
        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
        ));

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_local_tx.len(), 1);
        assert_eq!(scratch_local_tx[0].offset, 128);
        assert_eq!(free_tx_frames, VecDeque::from([192]));
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
        ));
    }

    #[test]
    fn drain_exact_prepared_items_to_scratch_recycles_dropped_prepared_frame() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: (tx_frame_capacity() + 1) as u32,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut scratch_prepared_tx = Vec::new();
        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );

        match build {
            ExactCoSScratchBuild::Drop { dropped_bytes, .. } => {
                assert_eq!(dropped_bytes, (tx_frame_capacity() + 1) as u64);
            }
            ExactCoSScratchBuild::Ready => panic!("oversized prepared frame must drop"),
        }
        assert!(scratch_prepared_tx.is_empty());
        assert!(free_tx_frames.is_empty());
        assert_eq!(pending_fill_frames, VecDeque::from([64]));
        assert!(root.queues[0].items.is_empty());
    }

    #[test]
    fn release_exact_prepared_scratch_preserves_queue_after_failed_submit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let frame = unsafe { area.slice_mut_unchecked(64, 4) }.expect("frame");
        frame.copy_from_slice(&[1, 2, 3, 4]);
        let mut scratch_prepared_tx = Vec::new();
        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        release_exact_prepared_scratch(&mut scratch_prepared_tx);
        assert!(scratch_prepared_tx.is_empty());
        assert_eq!(root.queues[0].items.len(), 1);
        match root.queues[0].items.front().expect("queued prepared") {
            CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 64),
            CoSPendingTxItem::Local(_) => panic!("unexpected local item"),
        }
    }

    #[test]
    fn settle_exact_prepared_fifo_submission_pops_only_committed_prefix() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 192,
                len: 1,
                recycle: PreparedTxRecycle::FillOnSlot(9),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let mut scratch_prepared_tx = vec![
            ExactPreparedScratchTxRequest { offset: 64, len: 1 },
            ExactPreparedScratchTxRequest {
                offset: 128,
                len: 1,
            },
            ExactPreparedScratchTxRequest {
                offset: 192,
                len: 1,
            },
        ];
        let mut in_flight_prepared_recycles = FastMap::default();

        let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
            Some(&mut root.queues[0]),
            &mut scratch_prepared_tx,
            &mut in_flight_prepared_recycles,
            1,
        );

        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert!(scratch_prepared_tx.is_empty());
        assert_eq!(
            in_flight_prepared_recycles.get(&64),
            Some(&PreparedTxRecycle::FillOnSlot(7))
        );
        assert!(!in_flight_prepared_recycles.contains_key(&128));
        assert!(!in_flight_prepared_recycles.contains_key(&192));
        assert_eq!(root.queues[0].items.len(), 2);
        match root.queues[0].items.pop_front().expect("first restored") {
            CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 128),
            CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
        }
        match root.queues[0].items.pop_front().expect("second restored") {
            CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 192),
            CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
        }
    }

    #[test]
    fn exact_prepared_fifo_boundary_survives_partial_commit() {
        let area = MmapArea::new(4096).expect("mmap");
        unsafe { area.slice_mut_unchecked(64, 1) }
            .expect("prepared frame 1")
            .copy_from_slice(&[1]);
        unsafe { area.slice_mut_unchecked(128, 1) }
            .expect("prepared frame 2")
            .copy_from_slice(&[2]);

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![9],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut scratch_prepared_tx = Vec::new();
        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_prepared_tx.len(), 2);

        let mut in_flight_prepared_recycles = FastMap::default();
        let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
            Some(&mut root.queues[0]),
            &mut scratch_prepared_tx,
            &mut in_flight_prepared_recycles,
            1,
        );
        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
        ));

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_prepared_tx.len(), 1);
        assert_eq!(scratch_prepared_tx[0].offset, 128);
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
        ));
    }

    #[test]
    fn resolve_cos_queue_id_prefers_egress_output_filter_forwarding_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    filter_output_v4: "wan-classify".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![
                FirewallFilterSnapshot {
                    name: "cos-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "best-effort".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "wan-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "expedited-forwarding".into(),
                        ..Default::default()
                    }],
                },
            ],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(1));
    }

    #[test]
    fn resolve_cached_cos_tx_selection_prefers_egress_output_filter_and_keeps_counter() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    filter_output_v4: "wan-classify".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![
                FirewallFilterSnapshot {
                    name: "cos-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "best-effort".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "wan-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        count: "wan-hits".into(),
                        forwarding_class: "expedited-forwarding".into(),
                        ..Default::default()
                    }],
                },
            ],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let cached = resolve_cached_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(cached.queue_id, Some(1));
        assert_eq!(cached.dscp_rewrite, None);
        assert!(cached.filter_counter.is_some());
    }

    #[test]
    fn resolve_cos_queue_id_uses_ingress_input_filter_when_no_output_filter_exists() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(1));
    }

    #[test]
    fn resolve_cached_cos_tx_selection_uses_ingress_input_filter_when_no_output_exists() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "lan-hits".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let cached = resolve_cached_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(cached.queue_id, Some(1));
        assert_eq!(cached.dscp_rewrite, None);
        assert!(cached.filter_counter.is_some());
    }

    #[test]
    fn resolve_cached_cos_tx_selection_keeps_counter_only_output_filter_hits() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-count".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "wan-count".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "count-only".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "wan-hits".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let cached = resolve_cached_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(cached.queue_id, Some(0));
        assert_eq!(cached.dscp_rewrite, None);
        assert!(cached.filter_counter.is_some());
    }

    #[test]
    fn resolve_cos_tx_selection_counts_counter_only_output_filter_hits() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-count".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "wan-count".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "count-only".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "wan-hits".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                pkt_len: 1514,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(0));
        assert_eq!(selection.dscp_rewrite, None);

        let filter = forwarding
            .filter_state
            .filters
            .get("inet:wan-count")
            .expect("inet output filter");
        let term = filter.terms.first().expect("first term");
        assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
        assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1514);
    }

    #[test]
    fn resolve_cos_tx_selection_uses_ingress_filter_dscp_rewrite_when_no_output_filter_exists() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    dscp_rewrite: Some(0),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 46,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(1));
        assert_eq!(selection.dscp_rewrite, Some(0));
    }

    #[test]
    fn resolve_cos_tx_selection_skips_ingress_filter_without_tx_selection_effects() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "sfmix-pbr".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "sfmix-pbr".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "sfmix-route".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "tx-duplicate".into(),
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                pkt_len: 1500,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(7));
        assert_eq!(selection.dscp_rewrite, None);
        let filter = forwarding
            .filter_state
            .filters
            .get("inet:sfmix-pbr")
            .expect("filter");
        assert_eq!(
            filter.terms[0]
                .counter
                .packets
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn resolve_cos_tx_selection_returns_none_when_no_cos_or_tx_selection_filters_exist() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "sfmix-pbr".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "sfmix-pbr".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "sfmix-route".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "tx-duplicate".into(),
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                pkt_len: 1500,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, None);
        assert_eq!(selection.dscp_rewrite, None);
        let filter = forwarding
            .filter_state
            .filters
            .get("inet:sfmix-pbr")
            .expect("filter");
        assert_eq!(
            filter.terms[0]
                .counter
                .packets
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn resolve_cos_queue_id_falls_back_to_default_queue_without_filter_match() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                ..Default::default()
            },
            None,
        );

        assert_eq!(queue_id, Some(7));
    }

    #[test]
    fn resolve_cos_queue_id_uses_dscp_classifier_when_filters_do_not_set_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                cos_dscp_classifier: "wan-classifier".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "voice".into(),
                        queue: 5,
                    },
                ],
                dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                    name: "wan-classifier".into(),
                    entries: vec![CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![46],
                    }],
                }],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "voice".into(),
                            scheduler: "voice-sched".into(),
                        },
                    ],
                }],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "voice-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 46,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(5));
    }

    #[test]
    fn resolve_cos_queue_id_uses_ieee8021_classifier_when_filters_do_not_set_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                cos_ieee8021_classifier: "wan-pcp".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "voice".into(),
                        queue: 5,
                    },
                ],
                ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                    name: "wan-pcp".into(),
                    entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        code_points: vec![5],
                    }],
                }],
                dscp_rewrite_rules: vec![],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "voice".into(),
                            scheduler: "voice-sched".into(),
                        },
                    ],
                }],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "voice-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_vlan_id: 100,
                ingress_pcp: 5,
                ingress_vlan_present: 1,
                addr_family: libc::AF_INET as u8,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(5));
    }

    #[test]
    fn resolve_cos_queue_id_does_not_use_ieee8021_classifier_for_untagged_packets() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                cos_ieee8021_classifier: "wan-pcp".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "bulk".into(),
                        queue: 3,
                    },
                ],
                ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                    name: "wan-pcp".into(),
                    entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        loss_priority: "low".into(),
                        code_points: vec![0],
                    }],
                }],
                dscp_rewrite_rules: vec![],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "bulk".into(),
                            scheduler: "bulk-sched".into(),
                        },
                    ],
                }],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "bulk-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_pcp: 0,
                ingress_vlan_present: 0,
                addr_family: libc::AF_INET as u8,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(0));
    }

    // Note on invariant change (replaces the pre-a15a6120 "defaults to iface default" behavior):
    // The original shape of this test asserted that an output filter with NO tx-side effect (no
    // forwarding_class, no counter) would still shadow the ingress input filter's classification
    // and leave egress at the interface default queue.  Commit a15a6120 changed the gating so the
    // output filter is skipped entirely when it has neither forwarding_class, dscp_rewrite, nor
    // counter terms — matching Junos semantics, where a classify-only output filter that does not
    // classify does not clobber upstream classification.  The new invariant asserted below: when
    // the output filter has no tx-side effect, ingress input-filter classification is preserved.
    #[test]
    fn resolve_cos_queue_id_preserves_ingress_classification_when_output_filter_has_no_forwarding_class()
     {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    filter_output_v4: "wan-classify".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![
                FirewallFilterSnapshot {
                    name: "cos-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "expedited-forwarding".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "wan-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "allow".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        ..Default::default()
                    }],
                },
            ],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 7,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 10_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 10_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 128_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        // cos-classify on reth1.0 maps expedited-forwarding -> queue 1.  The output filter
        // wan-classify on reth0.0 has no tx-side effect (no forwarding_class, no dscp_rewrite,
        // no counter), so post-a15a6120 it is bypassed and the ingress classification is
        // preserved.  Pre-a15a6120 this was expected to fall through to the iface default queue
        // (best-effort = 7); that contract no longer holds and is captured by this test.
        assert_eq!(queue_id, Some(1));
    }

    #[test]
    fn resolve_cos_tx_selection_preserves_output_filter_dscp_rewrite_without_forwarding_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-rewrite".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "wan-rewrite".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "rewrite".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    dscp_rewrite: Some(46),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(7));
        assert_eq!(selection.dscp_rewrite, Some(46));
    }

    #[test]
    fn assign_local_dscp_rewrite_preserves_existing_filter_rewrite() {
        let mut items = VecDeque::from([
            TxRequest {
                bytes: vec![0; 64],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 42,
                cos_queue_id: Some(0),
                dscp_rewrite: None,
            },
            TxRequest {
                bytes: vec![0; 64],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 42,
                cos_queue_id: Some(0),
                dscp_rewrite: Some(0),
            },
        ]);

        assign_local_dscp_rewrite(&mut items, Some(46));

        assert_eq!(items[0].dscp_rewrite, Some(46));
        assert_eq!(items[1].dscp_rewrite, Some(0));
    }

    fn test_cos_interface_runtime(now_ns: u64) -> CoSInterfaceRuntime {
        build_cos_interface_runtime(
            &CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: COS_MIN_BURST_BYTES,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                }],
            },
            now_ns,
        )
    }

    fn test_cos_runtime_with_exact(exact: bool) -> CoSInterfaceRuntime {
        test_cos_runtime_with_queues(
            1_000_000,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 500_000,
                exact,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        )
    }

    fn test_cos_runtime_with_queues(
        shaping_rate_bytes: u64,
        queues: Vec<CoSQueueConfig>,
    ) -> CoSInterfaceRuntime {
        build_cos_interface_runtime(
            &CoSInterfaceConfig {
                shaping_rate_bytes,
                burst_bytes: COS_MIN_BURST_BYTES,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues,
            },
            0,
        )
    }

    fn test_cos_item(len: usize) -> CoSPendingTxItem {
        CoSPendingTxItem::Local(TxRequest {
            bytes: vec![0; len],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        })
    }

    fn test_flow_cos_item(src_port: u16, len: usize) -> CoSPendingTxItem {
        CoSPendingTxItem::Local(TxRequest {
            bytes: vec![0; len],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(test_session_key(src_port, 5201)),
            egress_ifindex: 42,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        })
    }

    fn test_flow_prepared_cos_item(src_port: u16, len: u32, offset: u64) -> CoSPendingTxItem {
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset,
            len,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(test_session_key(src_port, 5201)),
            egress_ifindex: 42,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        })
    }

    fn test_session_key(src_port: u16, dst_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, (src_port & 0xff) as u8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port,
            dst_port,
        }
    }

    #[test]
    fn flow_fair_exact_queue_limits_dominant_flow_share() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        let flow_a = test_session_key(1111, 5201);
        let flow_b = test_session_key(1112, 5201);
        let bucket_a = cos_flow_bucket_index(queue.flow_hash_seed, Some(&flow_a));
        let bucket_b = cos_flow_bucket_index(queue.flow_hash_seed, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b);

        assert_eq!(
            cos_queue_flow_share_limit(queue, buffer_limit, bucket_a),
            buffer_limit
        );
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 64 * 1024);
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 32 * 1024);
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 96 * 1024);

        account_cos_queue_flow_enqueue(queue, Some(&flow_b), 16 * 1024);
        assert_eq!(queue.active_flow_buckets, 2);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 16 * 1024);

        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, bucket_a);
        assert_eq!(share_cap, buffer_limit / 2);
        assert!(queue.flow_bucket_bytes[bucket_a].saturating_add(16 * 1024) > share_cap);

        account_cos_queue_flow_dequeue(queue, Some(&flow_b), 16 * 1024);
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 0);
    }

    #[test]
    fn cos_flow_aware_buffer_limit_scales_with_prospective_active_flow_count() {
        // #707 + #716 review: at the 1 Gbps/16-flow workload a fixed
        // 125 KB buffer divided across 16 flows gives each flow a 7.8
        // KB share, below the TCP fast-retransmit floor of 16 MSS =
        // 24 KB. The flow-aware buffer limit grows the aggregate cap
        // so the per-flow floor can be honoured. "Prospective" count
        // means the same denominator the per-flow clamp uses: current
        // `active_flow_buckets + (target bucket empty ? 1 : 0)`, so
        // the two gates never disagree about whether a new flow's
        // first packet has room.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB — the admission-boundary math must
                // use the same units as the live system.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Base floor wins when prospective flow count × min share is
        // small. `flow_bucket = 0` is empty → prospective_active += 1.
        queue.active_flow_buckets = 0;
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "zero active (+1 prospective) flows must stay at the operator-configured base"
        );
        queue.active_flow_buckets = 2;
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "3 prospective × 24 KB = 72 KB stays below the 125 KB configured base, so base wins"
        );

        // Flow-aware floor wins past the break-even point. Now mark 16
        // buckets populated so prospective = 16 (target bucket already
        // non-empty).
        queue.active_flow_buckets = 16;
        for bucket in 0..16 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            16 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "16 × 24 KB = 384 KB exceeds the 125 KB base and becomes the cap"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_matches_share_limit_at_new_flow_boundary() {
        // #716 review: the aggregate cap and the per-flow clamp must
        // use the SAME denominator. Before the review fix the
        // aggregate cap used the current `active_flow_buckets` while
        // the per-flow clamp used `active + (target bucket empty ? 1 :
        // 0)`, so the first packet of a newly arriving flow could
        // pass the per-flow gate and fail the aggregate one right at
        // the boundary. This test drives the queue to the *actual*
        // admission boundary so the assertion exercises the old
        // failure mode rather than trivial 0-bytes arithmetic.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB — the admission-boundary math must
                // use the same units as the live system.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // 15 active flows filled to 24 KB each. Target bucket empty →
        // prospective_active = 16. Both caps must key off 16, not 15.
        queue.active_flow_buckets = 15;
        for bucket in 0..15 {
            queue.flow_bucket_bytes[bucket] = COS_FLOW_FAIR_MIN_SHARE_BYTES;
        }
        // Aggregate queued equals the pre-fix aggregate cap exactly —
        // this is the value that made the bug observable: under the
        // old formula the aggregate cap was `15 × min-share` and the
        // check `queued + 1500 > cap` tripped; under the fix the cap
        // is `16 × min-share` and the packet fits.
        queue.queued_bytes = 15 * COS_FLOW_FAIR_MIN_SHARE_BYTES;

        let new_flow_bucket = 100;
        assert_eq!(queue.flow_bucket_bytes[new_flow_bucket], 0);

        let buffer_limit = cos_flow_aware_buffer_limit(queue, new_flow_bucket);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, new_flow_bucket);

        // Fixed caps: aggregate = 16 × min-share, per-flow = min-share.
        assert_eq!(buffer_limit, 16 * COS_FLOW_FAIR_MIN_SHARE_BYTES);
        assert_eq!(share_cap, COS_FLOW_FAIR_MIN_SHARE_BYTES);

        // Per-flow gate: new bucket is empty, so +1500 is well below cap.
        assert!(
            queue.flow_bucket_bytes[new_flow_bucket].saturating_add(1500) <= share_cap,
            "per-flow share must admit the new flow's first packet"
        );

        // Aggregate gate: queued is at the pre-fix cap. Fix makes
        // +1500 still fit; without the fix this was a drop.
        assert!(
            queue.queued_bytes.saturating_add(1500) <= buffer_limit,
            "aggregate cap must admit the new flow's first packet at the near-cap boundary \
             (queued_bytes = {}, +1500 must fit within buffer_limit = {})",
            queue.queued_bytes,
            buffer_limit,
        );

        // Counter-factual: prove the pre-fix formula (non-prospective)
        // would have rejected the same packet. Guards against a future
        // refactor silently reverting to `active_flow_buckets` without
        // the `+1` bump.
        let non_prospective_cap = u64::from(queue.active_flow_buckets)
            .max(1)
            .saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES)
            .max(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
        assert!(
            queue.queued_bytes.saturating_add(1500) > non_prospective_cap,
            "without prospective-active, the same queued state would reject the new flow \
             (queued_bytes + 1500 = {}, non-prospective cap = {})",
            queue.queued_bytes + 1500,
            non_prospective_cap,
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_respects_non_flow_fair_queues() {
        // Pure rate-limited (non-flow-fair) queues must keep the
        // operator's configured buffer. The flow-aware scaling only
        // applies when SFQ-style per-flow accounting is active.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = false;
        queue.active_flow_buckets = 64; // should be ignored

        // `flow_bucket` argument is irrelevant when flow_fair=false; use 0.
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "flow_fair=false must bypass the flow-count multiplier"
        );
    }

    #[test]
    fn cos_queue_flow_share_limit_never_drops_below_fast_retransmit_floor() {
        // At 16 flows with a 125 KB buffer, the naive arithmetic share
        // is 7.8 KB — a single packet drop yields < 3 dupacks, forcing
        // RTO. The clamp to `COS_FLOW_FAIR_MIN_SHARE_BYTES` must hold
        // the per-flow cap at 24 KB no matter the denominator.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB — the admission-boundary math must
                // use the same units as the live system.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Simulate 16 distinct populated flow buckets.
        queue.active_flow_buckets = 16;
        for bucket in 0..16 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }

        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        assert_eq!(
            buffer_limit,
            16 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "flow-aware cap must expand to accommodate 16 × min-share"
        );

        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        assert!(
            share >= COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "per-flow cap ({share}) must stay ≥ {COS_FLOW_FAIR_MIN_SHARE_BYTES} (16 MTU-sized packets)"
        );
        assert_eq!(
            share, COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "with buffer_limit == active × min-share, per-flow cap equals the floor"
        );
    }

    #[test]
    fn cos_queue_push_and_pop_track_flow_bucket_bytes() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let req_a = TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(test_session_key(1111, 5201)),
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        let req_b = TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(test_session_key(1112, 5201)),
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        let bucket_a = cos_flow_bucket_index(queue.flow_hash_seed, req_a.flow_key.as_ref());
        let bucket_b = cos_flow_bucket_index(queue.flow_hash_seed, req_b.flow_key.as_ref());
        assert_ne!(bucket_a, bucket_b);

        cos_queue_push_back(queue, CoSPendingTxItem::Local(req_a));
        cos_queue_push_back(queue, CoSPendingTxItem::Local(req_b));
        assert_eq!(queue.active_flow_buckets, 2);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 1500);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 1500);

        let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) else {
            panic!("expected first queued local request");
        };
        assert_eq!(req.flow_key.as_ref().map(|flow| flow.src_port), Some(1111));
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 1500);
    }

    #[test]
    fn flow_fair_queue_round_robins_distinct_local_flows() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1112, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1113, 1500));

        let mut order = Vec::new();
        while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
            order.push(req.flow_key.expect("flow key").src_port);
        }

        assert_eq!(order, vec![1111, 1112, 1113, 1111]);
        assert_eq!(queue.active_flow_buckets, 0);
        assert!(queue.flow_rr_buckets.is_empty());
    }

    #[test]
    fn flow_fair_queue_round_robins_distinct_prepared_flows() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        cos_queue_push_back(queue, test_flow_prepared_cos_item(1111, 1500, 64));
        cos_queue_push_back(queue, test_flow_prepared_cos_item(1111, 1500, 128));
        cos_queue_push_back(queue, test_flow_prepared_cos_item(1112, 1500, 192));

        let mut order = Vec::new();
        while let Some(CoSPendingTxItem::Prepared(req)) = cos_queue_pop_front(queue) {
            order.push(req.flow_key.expect("flow key").src_port);
        }

        assert_eq!(order, vec![1111, 1112, 1111]);
        assert_eq!(queue.active_flow_buckets, 0);
        assert!(queue.flow_rr_buckets.is_empty());
    }

    #[test]
    fn exact_cos_flow_bucket_is_stable_for_same_seed_and_flow() {
        // Required property (#693): determinism inside one runtime instance.
        // Enqueue/dequeue bucket accounting would break if the same flow key
        // hashed to different buckets between push and pop. One random seed
        // drawn from the OS, same 5-tuple in, same bucket out, every time.
        let flow = test_session_key(9000, 5201);
        let seed = cos_flow_hash_seed_from_os();
        let first = cos_flow_bucket_index(seed, Some(&flow));
        for _ in 0..4096 {
            assert_eq!(first, cos_flow_bucket_index(seed, Some(&flow)));
        }
    }

    #[test]
    fn exact_cos_flow_bucket_diverges_across_seeds_for_same_flow() {
        // Required property (#693): the bucket mapping is not an externally-
        // probeable pure function of the 5-tuple. Two queues with different
        // seeds must be able to send the same flow into different buckets.
        // A deterministic hash would make this test a tautology that always
        // fails, so we scan seeds until we find a divergence; with a 64-bucket
        // output, collision rate is ~1/64 per seed pair, so 8192 attempts is
        // well below any reasonable flake tolerance (collision probability
        // ≈ (1/64)^8192 if the hash were uniform).
        let flow = test_session_key(9000, 5201);
        let reference = cos_flow_bucket_index(0, Some(&flow));
        let mut saw_divergence = false;
        for seed in 1u64..8192u64 {
            if cos_flow_bucket_index(seed, Some(&flow)) != reference {
                saw_divergence = true;
                break;
            }
        }
        assert!(
            saw_divergence,
            "hash must diverge across seeds; seed is not being mixed into the bucket function"
        );
    }

    #[test]
    fn exact_cos_flow_bucket_preserves_legacy_behavior_at_zero_seed() {
        // Required property (#693): preserve existing behavior for queues
        // with a zero seed. The pre-seed hash initialized `seed = protocol ^
        // (addr_family << 8)`; the seeded hash initializes `seed = queue_seed
        // ^ protocol ^ (addr_family << 8)`. At `queue_seed = 0` the two are
        // byte-identical. Pin this so a future refactor that reorders the
        // mix cannot silently change the bucket mapping under zero seed.
        let flow_v4 = test_session_key(1111, 5201);
        let mut flow_v6 = test_session_key(2222, 5201);
        flow_v6.src_ip = IpAddr::V6("2001:db8::1".parse().unwrap());
        flow_v6.dst_ip = IpAddr::V6("2001:db8::2".parse().unwrap());
        flow_v6.addr_family = libc::AF_INET6 as u8;
        let b_v4 = cos_flow_bucket_index(0, Some(&flow_v4));
        let b_v6 = cos_flow_bucket_index(0, Some(&flow_v6));
        // #711: hash-mix regression pins, updated for the bucket-count
        // grow from 64 → 1024. The hash function itself is unchanged
        // at seed=0; the values moved only because the mask widened
        // from 6 bits (0x3F) to 10 bits (0x3FF). Under the previous
        // 6-bit mask these values were 26 (v4) and 4 (v6); the
        // low 10 bits of the same hash output give the new pins below.
        // A refactor that reorders the mix or adds a term still fails
        // here and becomes an explicit decision. Update baselines only
        // after live re-validation of 5201 fairness on the loss HA
        // cluster.
        // Sanity: low 6 bits of the new pins equal the old pins
        // (26 and 4 respectively), confirming the mask-widening
        // interpretation above.
        assert_eq!(b_v4 & 0x3F, 26);
        assert_eq!(b_v6 & 0x3F, 4);
        assert_eq!(b_v4, 410);
        assert_eq!(b_v6, 260);
    }

    #[test]
    fn exact_cos_flow_bucket_handles_missing_flow_key() {
        // An item without a flow_key (e.g. a non-TCP/UDP frame, or a
        // pre-session packet) must still produce a valid bucket. Pick
        // bucket 0 deterministically so these items share one SFQ lane
        // rather than splaying across the ring and inflating
        // active_flow_buckets.
        assert_eq!(cos_flow_bucket_index(0, None), 0);
        assert_eq!(cos_flow_bucket_index(0x1234_5678_9abc_def0, None), 0);
    }

    #[test]
    fn exact_cos_flow_bucket_distribution_at_1024_keeps_collisions_below_budget() {
        // #711 correctness pin. The whole point of growing buckets
        // 64 → 1024 is collision reduction. A hash-mix regression can
        // produce acceptable distribution on one seed while clustering
        // badly under others; a single-seed test is too easy to
        // accidentally satisfy. Exercise multiple deterministic seeds
        // and mix v4/v6 tuples so the guarantee covers a realistic
        // traffic shape.
        //
        // Theoretical baseline for 64 uniform flows into 1024 buckets:
        // E[colliding pairs] ≈ 64·63/(2·1024) ≈ 1.97 — so ~62-63
        // distinct buckets on average. A budget of 58/64 per seed is
        // ~2 sigma conservative under a uniform-hash null hypothesis;
        // if this test fires, the hash function has become materially
        // non-uniform and the fairness guarantee is silently gone.
        use std::collections::BTreeSet;

        let seeds: [u64; 3] = [0, 0xA5A5_0000_C3C3_FFFF, 0x0123_4567_89AB_CDEF];
        for &seed in &seeds {
            let mut buckets = BTreeSet::new();
            for i in 0..64u16 {
                let mut flow = test_session_key(10_000 + i, 5201);
                // Alternate between v4 and v6 tuples so the test
                // exercises both address-family branches of the hash.
                if i & 1 == 1 {
                    flow.addr_family = libc::AF_INET6 as u8;
                    let v6 = format!("2001:db8::{i:x}")
                        .parse::<std::net::Ipv6Addr>()
                        .expect("v6 literal");
                    flow.src_ip = IpAddr::V6(v6);
                    flow.dst_ip = IpAddr::V6(
                        "2001:db8::5201"
                            .parse::<std::net::Ipv6Addr>()
                            .expect("v6 literal"),
                    );
                }
                buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
            }
            assert!(
                buckets.len() >= 58,
                "seed={:#x}: 64 flows landed in only {} distinct buckets — \
                 hash distribution regressed",
                seed,
                buckets.len()
            );
            assert!(
                buckets.iter().all(|&b| b < COS_FLOW_FAIR_BUCKETS),
                "bucket index out of range after mask: seed={seed:#x}"
            );
        }
    }

    #[test]
    fn build_cos_interface_runtime_leaves_flow_hash_seed_zero_until_promotion() {
        // The seed is drawn in `ensure_cos_interface_runtime`, not in
        // `build_cos_interface_runtime`. Pin this so a refactor that
        // accidentally moves the getrandom call into the builder is
        // caught: builder-time seeding would burn a syscall per non-
        // flow-fair queue and would also drift the struct doc invariant
        // that non-flow-fair queues keep seed=0.
        let root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        for queue in &root.queues {
            assert!(!queue.flow_fair);
            assert_eq!(queue.flow_hash_seed, 0);
        }
    }

    #[test]
    fn cos_flow_hash_seed_from_os_draws_nonzero_entropy() {
        // Regression guard for the degenerate "seed is always 0" case.
        // Does NOT distinguish getrandom(2) from the fallback path — either
        // source is acceptable to satisfy the not-all-zero invariant. The
        // fallback path's own quality is exercised indirectly by the
        // diverges-across-seeds test; here we only catch "seeding is wired
        // up end-to-end and produces non-zero output most of the time". A
        // single zero draw is possible, just astronomically unlikely for
        // four independent draws, so four-trial not-all-zero is a safe
        // floor.
        let mut any_nonzero = false;
        for _ in 0..4 {
            if cos_flow_hash_seed_from_os() != 0 {
                any_nonzero = true;
                break;
            }
        }
        assert!(any_nonzero, "seed source returned 0 on four draws in a row");
    }

    #[test]
    fn estimate_cos_queue_wakeup_tick_uses_token_deficits() {
        let mut root = test_cos_interface_runtime(0);
        root.tokens = 0;
        root.queues[0].tokens = 0;

        let wake_tick = estimate_cos_queue_wakeup_tick(
            root.tokens,
            root.shaping_rate_bytes,
            root.queues[0].tokens,
            root.queues[0].transmit_rate_bytes,
            1500,
            0,
            true,
        )
        .expect("wake tick");

        assert_eq!(wake_tick, 30);
    }

    #[test]
    fn estimate_cos_queue_wakeup_tick_ignores_queue_deficit_for_surplus() {
        let mut root = test_cos_interface_runtime(0);
        root.tokens = 0;
        root.queues[0].tokens = 0;

        let wake_tick = estimate_cos_queue_wakeup_tick(
            root.tokens,
            root.shaping_rate_bytes,
            root.queues[0].tokens,
            root.queues[0].transmit_rate_bytes,
            1500,
            0,
            false,
        )
        .expect("wake tick");

        assert_eq!(wake_tick, 30);
    }

    #[test]
    fn surplus_phase_selects_non_exact_queue_without_guarantee_tokens() {
        let mut root = test_cos_runtime_with_exact(false);
        root.tokens = 1500;
        root.queues[0].last_refill_ns = 1;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        let batch = select_cos_surplus_batch(&mut root, 1);

        assert!(matches!(
            batch,
            Some(CoSBatch::Local {
                phase: CoSServicePhase::Surplus,
                ..
            })
        ));
    }

    #[test]
    fn surplus_phase_skips_exact_queue_without_guarantee_tokens() {
        let mut root = test_cos_runtime_with_exact(true);
        root.tokens = 1500;
        root.queues[0].last_refill_ns = 1;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        assert!(select_cos_surplus_batch(&mut root, 1).is_none());
    }

    #[test]
    fn guarantee_phase_parks_non_exact_queue_on_root_only_wakeup() {
        let mut root = test_cos_runtime_with_exact(false);
        root.tokens = 0;
        root.queues[0].last_refill_ns = 1;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        assert!(root.queues[0].parked);
        assert_eq!(root.queues[0].next_wakeup_tick, 30);
    }

    #[test]
    fn guarantee_phase_limits_service_to_visit_quantum() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 64 * 1024;
        root.queues[0].tokens = 64 * 1024;
        root.queues[0].runnable = true;
        for _ in 0..4 {
            root.queues[0].items.push_back(test_cos_item(1500));
        }
        root.queues[0].queued_bytes = 4 * 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
        match batch {
            CoSBatch::Local { items, .. } => assert_eq!(items.len(), 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(root.queues[0].items.len(), 3);
    }

    #[test]
    fn guarantee_phase_allows_larger_high_rate_visit_quantum() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000u64 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000u64 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 256 * 1024,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 256 * 1024;
        root.queues[0].tokens = 256 * 1024;
        root.queues[0].runnable = true;
        for _ in 0..200 {
            root.queues[0].items.push_back(test_cos_item(1500));
        }
        root.queues[0].queued_bytes = 200 * 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
        match batch {
            CoSBatch::Local { items, .. } => assert_eq!(items.len(), 166),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(root.queues[0].items.len(), 34);
    }

    #[test]
    fn guarantee_phase_rotates_between_backlogged_queues() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        root.tokens = 64 * 1024;
        for queue in &mut root.queues {
            queue.tokens = 64 * 1024;
            queue.runnable = true;
            queue.items.push_back(test_cos_item(1500));
            queue.items.push_back(test_cos_item(1500));
            queue.queued_bytes = 2 * 1500;
        }
        root.nonempty_queues = 2;
        root.runnable_queues = 2;

        let first = select_cos_guarantee_batch(&mut root, 1).expect("first guarantee batch");
        let second = select_cos_guarantee_batch(&mut root, 1).expect("second guarantee batch");

        match first {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 0),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        match second {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
    }

    fn test_mixed_class_root_with_primed_queues() -> CoSInterfaceRuntime {
        // Four queues on the same iface: two exact (queue_id 0, 2),
        // two non-exact (queue_id 1, 3). Per-queue rate is set low
        // enough that `cos_guarantee_quantum_bytes` clamps to the
        // minimum (1500 bytes). That means the non-exact batch-build
        // path (`select_nonexact_cos_guarantee_batch`) dequeues exactly
        // one 1500-byte item per call, while the exact fast-path
        // selector (`select_exact_cos_guarantee_queue_with_fast_path`)
        // only picks a queue and advances its cursor — it does not
        // dequeue. Eight primed items per queue keeps backlog available
        // across every rotation round below without any test having to
        // push additional items.
        //
        // Shared by the #689 split-cursor regression tests.
        let slow_rate = 1_000_000 / 8; // 1 Mbps → quantum clamps to MIN
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "exact-0".into(),
                    priority: 5,
                    transmit_rate_bytes: slow_rate,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "nonexact-1".into(),
                    priority: 5,
                    transmit_rate_bytes: slow_rate,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 2,
                    forwarding_class: "exact-2".into(),
                    priority: 5,
                    transmit_rate_bytes: slow_rate,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 3,
                    forwarding_class: "nonexact-3".into(),
                    priority: 5,
                    transmit_rate_bytes: slow_rate,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        root.tokens = 1024 * 1024;
        for queue in &mut root.queues {
            queue.tokens = 64 * 1024;
            queue.runnable = true;
            // Eight items per queue covers the longest rotation test below
            // without any queue draining to empty.
            for _ in 0..8 {
                queue.items.push_back(test_cos_item(1500));
            }
            queue.queued_bytes = 8 * 1500;
        }
        root.nonempty_queues = 4;
        root.runnable_queues = 4;
        root
    }

    #[test]
    fn exact_and_nonexact_guarantee_rr_cursors_advance_independently() {
        // #689 regression. Prior to the cursor split, serving an exact
        // queue advanced the shared `guarantee_rr` and could cause the
        // non-exact pass to skip a waiting queue on its next run. Pin
        // that the exact pass does not touch `nonexact_guarantee_rr`
        // and vice versa.
        let mut root = test_mixed_class_root_with_primed_queues();
        assert_eq!(root.exact_guarantee_rr, 0);
        assert_eq!(root.nonexact_guarantee_rr, 0);

        // Serving an exact queue must not disturb the non-exact cursor.
        let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
            .expect("exact queue selection");
        assert_eq!(selection.queue_idx, 0);
        assert_eq!(
            root.exact_guarantee_rr, 1,
            "exact cursor must advance past the served queue"
        );
        assert_eq!(
            root.nonexact_guarantee_rr, 0,
            "serving an exact queue must not advance the non-exact cursor"
        );

        // Serving a non-exact queue must not disturb the exact cursor.
        let batch =
            select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact queue batch");
        match batch {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(
            root.exact_guarantee_rr, 1,
            "non-exact service must not advance the exact cursor"
        );
        assert_eq!(
            root.nonexact_guarantee_rr, 2,
            "non-exact cursor must advance past the served queue"
        );
    }

    #[test]
    fn exact_guarantee_rr_walks_exact_queues_in_order_independent_of_nonexact() {
        // Exact queues must rotate exact-0 -> exact-2 -> exact-0 -> exact-2
        // regardless of non-exact activity between calls. #689 before-fix
        // behavior under the shared cursor was: exact-0 served (rr=1),
        // then a non-exact service would bump rr past exact-2's position,
        // so the next exact call would skip exact-2 and loop back to
        // exact-0. This test pins that the split cursor rotates exact
        // queues deterministically without regard for non-exact service.
        // Helper primes eight 1500-byte items and sets `queued_bytes`
        // to match; no additional priming needed here. Only bump
        // queue.tokens on the exact queues to make sure they never hit
        // token-starvation during the four interleaved rounds below —
        // the exact selector does not refill exact-queue tokens itself
        // (that is done by the shared-lease path), so this test bypasses
        // that machinery by handing the queues a large local budget.
        let mut root = test_mixed_class_root_with_primed_queues();
        for queue in &mut root.queues {
            if queue.exact {
                queue.tokens = 128 * 1024;
            }
        }

        let mut exact_order = Vec::new();
        for _ in 0..4 {
            // Interleave a non-exact service between exact calls; the exact
            // rotation must not notice.
            let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
                .expect("exact queue");
            exact_order.push(selection.queue_idx);
            // Service a non-exact queue to simulate concurrent class activity;
            // ignore the result.
            let _ = select_nonexact_cos_guarantee_batch(&mut root, 1);
        }
        assert_eq!(exact_order, vec![0, 2, 0, 2]);
    }

    #[test]
    fn nonexact_guarantee_rr_walks_nonexact_queues_in_order_independent_of_exact() {
        // Symmetric to the exact test: non-exact rotation is 1 -> 3 -> 1 -> 3
        // regardless of exact-queue activity between calls. Helper primes
        // eight 1500-byte items per queue with `queued_bytes` already
        // consistent; no additional priming needed.
        let mut root = test_mixed_class_root_with_primed_queues();

        let mut nonexact_order = Vec::new();
        for _ in 0..4 {
            let batch = select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact batch");
            let queue_idx = match batch {
                CoSBatch::Local { queue_idx, .. } => queue_idx,
                CoSBatch::Prepared { queue_idx, .. } => queue_idx,
            };
            nonexact_order.push(queue_idx);
            // Interleave an exact service; must not disturb non-exact rotation.
            let _ = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
        }
        assert_eq!(nonexact_order, vec![1, 3, 1, 3]);
    }

    #[test]
    fn legacy_guarantee_rr_does_not_advance_class_cursors() {
        // The entire reason `legacy_guarantee_rr` exists as a third cursor
        // (instead of the legacy unified selector reusing one of the
        // production cursors) is to keep the legacy walk isolated from the
        // production exact/nonexact rotation state. Pin that contract:
        // a call through the legacy selector must advance only its own
        // cursor, never the two production cursors.
        let mut root = test_mixed_class_root_with_primed_queues();
        let batch = select_cos_guarantee_batch(&mut root, 1).expect("legacy guarantee batch");
        // Served something, so `legacy_guarantee_rr` advanced.
        match batch {
            CoSBatch::Local { queue_idx, .. } => {
                assert_eq!(queue_idx, 0, "legacy walk starts at index 0");
            }
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(root.legacy_guarantee_rr, 1);
        // Production cursors untouched — this is the isolation guarantee
        // that justifies the extra field over reusing either production
        // cursor for the legacy walk.
        assert_eq!(
            root.exact_guarantee_rr, 0,
            "legacy selector must not advance exact production cursor"
        );
        assert_eq!(
            root.nonexact_guarantee_rr, 0,
            "legacy selector must not advance nonexact production cursor"
        );
    }

    #[test]
    fn guarantee_rr_cursors_start_at_zero_after_runtime_build() {
        // Pin the invariant that a fresh runtime starts with both cursors
        // at 0. `build_cos_interface_runtime` is the one production init
        // site; any refactor that accidentally leaves a cursor uninitialized
        // or drops one of the fields fails here.
        let root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "q0".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        assert_eq!(root.exact_guarantee_rr, 0);
        assert_eq!(root.nonexact_guarantee_rr, 0);
        assert_eq!(root.legacy_guarantee_rr, 0);
    }

    // ---------------------------------------------------------------------
    // #698 — per-worker exact-drain micro-bench
    //
    // Purpose: establish an in-tree, reproducible measurement of the
    // userspace drain-path cost per packet. The value of
    // `COS_SHARED_EXACT_COS_SHARED_EXACT_MIN_RATE_BYTES` (2.5 Gbps) is cited in commit
    // history as "the single-worker sustained exact throughput ceiling";
    // before this harness existed there was no checked-in data supporting
    // that number.
    //
    // Scope (what this measures):
    //   - `drain_exact_local_fifo_items_to_scratch`
    //       VecDeque indexed read, pattern match, free-frame pop, UMEM
    //       `slice_mut_unchecked` + `copy_from_slice` (the 1500-byte
    //       memcpy that dominates `memmove` in the live profile),
    //       scratch Vec push, running root/secondary budget decrement.
    //   - `settle_exact_local_fifo_submission`
    //       queue.items.pop_front per sent packet, scratch Vec pop.
    //   - Re-prime between iterations — simulates a steady inflow of
    //       new items from the upstream CoS enqueue path.
    //
    // Scope (what this does NOT measure):
    //   - TX ring insert + commit (no XDP socket in unit tests; this
    //     is a ring-buffer write + release store on the producer index,
    //     ~20 ns combined on x86-64, amortized away at TX_BATCH_SIZE).
    //   - The `sendto()` syscall used for kernel TX wakeup (amortized
    //     over TX_BATCH_SIZE = 256 packets, ~2–4 ns per packet).
    //   - Completion ring reap (`reap_tx_completions`) — ~20–50 ns per
    //     completion, mostly ring-buffer read + VecDeque push-back.
    //   - All non-drain per-worker cost: RX, forwarding, NAT, session
    //     lookup, conntrack. Measured in the live cluster profile, not
    //     here. Those costs dominate in production and are the real
    //     gate on per-worker aggregate throughput.
    //
    // What this tells us about the MIN constant:
    //   - If drain-path Gbps is >> 2.5 Gbps, the constant is NOT gated
    //     by drain speed. MIN reflects "what's left after RX + forward
    //     + NAT consume 80%+ of the per-worker budget" — consistent
    //     with the PR #680 collapse shape where the drain loop couldn't
    //     absorb aggregate line-rate because of *other* per-packet work.
    //   - If drain-path Gbps is < 2.5 Gbps, MIN is provably too high
    //     and must drop. (Unlikely — drain is tightly bounded by a
    //     1500-byte memcpy and a few VecDeque ops.)
    //
    // Running (release is mandatory — debug build numbers are not
    // meaningful for this baseline):
    //   cargo test --release --manifest-path userspace-dp/Cargo.toml \
    //       cos_exact_drain_throughput_micro_bench -- --ignored --nocapture
    //
    // The bench reports two separate timings:
    //   - "drain+settle (measured)" — the inner loop only. Setup work
    //     (VecDeque priming, packet cloning, free-frame pool rebuild)
    //     is excluded.
    //   - "setup (per batch, unmeasured)" — setup cost printed for
    //     reference so future changes to the setup path are visible.
    //
    // Hardware and noise: numbers depend on the box's core frequency
    // and L1/L2 cache state. Run on quiet hardware; the published
    // baseline in this commit's message was captured under those
    // conditions. A repeat run after a refactor should stay within
    // ~15% of the baseline on the same host — larger deltas warrant
    // investigation. A single development-host measurement does NOT
    // validate the MIN constant on other deployment hardware; it only
    // rules out the inner drain loop as the limiter on this host.
    // ---------------------------------------------------------------------
    #[test]
    #[ignore]
    fn cos_exact_drain_throughput_micro_bench() {
        use std::time::Instant;

        // Single source of truth — `worker::COS_SHARED_EXACT_MIN_RATE_BYTES`
        // is `pub(super)` so the bench asserts against the production
        // constant directly rather than carrying a mirror that could drift.
        use super::super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;
        const PACKET_LEN: usize = 1500;
        const BATCHES: usize = 10_000;
        // Each drain call takes TX_BATCH_SIZE items. Prime enough items
        // for one batch; after each iteration we repopulate the queue
        // and free-frame pool so the measurement reflects steady state,
        // not a cold-start transient.
        const ITEMS_PER_BATCH: usize = TX_BATCH_SIZE;

        // UMEM: 2 MB is the hugepage-aligned minimum in MmapArea. That
        // fits TX_BATCH_SIZE * 4096 = 1 MB of frame slots with headroom.
        let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 4 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        root.tokens = u64::MAX;
        root.queues[0].tokens = u64::MAX;
        root.queues[0].runnable = true;

        let packet_bytes = vec![0xABu8; PACKET_LEN];
        let mut scratch = Vec::with_capacity(ITEMS_PER_BATCH);
        let mut free_frames: VecDeque<u64> =
            (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();

        // Prime: one full batch of items. Each iteration below drains
        // them all and then re-primes both the items and the free frames
        // to the same initial state.
        let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
            queue.items.clear();
            queue.queued_bytes = 0;
            for _ in 0..ITEMS_PER_BATCH {
                queue.items.push_back(CoSPendingTxItem::Local(TxRequest {
                    bytes: packet.to_vec(),
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: 80,
                    cos_queue_id: Some(5),
                    dscp_rewrite: None,
                }));
                queue.queued_bytes += packet.len() as u64;
            }
        };

        // Warmup: 1000 batches to settle caches and branch predictors.
        for _ in 0..1000 {
            prime_queue(&mut root.queues[0], &packet_bytes);
            scratch.clear();
            free_frames = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
            let build = drain_exact_local_fifo_items_to_scratch(
                &mut root.queues[0],
                &mut free_frames,
                &mut scratch,
                &area,
                u64::MAX,
                u64::MAX,
                None,
            );
            assert!(matches!(build, ExactCoSScratchBuild::Ready));
            let inserted = scratch.len();
            settle_exact_local_fifo_submission(
                Some(&mut root.queues[0]),
                &mut free_frames,
                &mut scratch,
                inserted,
            );
        }

        // Measurement. Setup (priming, packet cloning, free-frame pool
        // rebuild) happens outside the `iter_start.elapsed()` window so
        // the reported ns/packet reflects only drain+settle. Setup cost
        // is separately accumulated and printed for reference.
        use std::time::Duration;
        let mut measured = Duration::ZERO;
        let mut setup_time = Duration::ZERO;
        let mut total_packets = 0u64;
        let mut total_bytes = 0u64;
        for _ in 0..BATCHES {
            let setup_start = Instant::now();
            prime_queue(&mut root.queues[0], &packet_bytes);
            scratch.clear();
            free_frames.clear();
            free_frames.extend((0..ITEMS_PER_BATCH as u64).map(|i| i * 4096));
            setup_time += setup_start.elapsed();

            let iter_start = Instant::now();
            let build = drain_exact_local_fifo_items_to_scratch(
                &mut root.queues[0],
                &mut free_frames,
                &mut scratch,
                &area,
                u64::MAX,
                u64::MAX,
                None,
            );
            let inserted = scratch.len();
            let (sent_pkts, sent_bytes) = settle_exact_local_fifo_submission(
                Some(&mut root.queues[0]),
                &mut free_frames,
                &mut scratch,
                inserted,
            );
            measured += iter_start.elapsed();

            assert!(matches!(build, ExactCoSScratchBuild::Ready));
            total_packets += sent_pkts;
            total_bytes += sent_bytes;
        }

        let ns_per_packet = measured.as_nanos() as f64 / total_packets as f64;
        let mpps = total_packets as f64 / measured.as_secs_f64() / 1.0e6;
        let gbps = (total_bytes as f64 * 8.0) / measured.as_secs_f64() / 1.0e9;
        let setup_ns_per_packet = setup_time.as_nanos() as f64 / total_packets as f64;

        eprintln!(
            "\n=== #698 exact-drain userspace micro-bench ===\n\
             packet len              : {} B\n\
             batches                 : {}\n\
             packets per batch       : {}\n\
             total packets           : {}\n\
             total bytes             : {} ({:.2} MB)\n\
             drain+settle (measured) : {:?}\n\
             setup (per batch, unmeasured): {:?}\n\
             ns/packet (drain+settle): {:.2}\n\
             ns/packet (setup only)  : {:.2}\n\
             throughput (pps)        : {:.3} Mpps\n\
             throughput (line rate)  : {:.3} Gbps\n\
             min-constant gate       : {:.3} Gbps (COS_SHARED_EXACT_MIN_RATE_BYTES)\n\
             verdict (this host)     : {}\n\
             scope note              : userspace drain path only; excludes TX\n\
                                       ring insert/commit, kernel wakeup, and\n\
                                       completion ring reap. Single-host number\n\
                                       only — does not validate MIN on other\n\
                                       deployment hardware.\n\
             ================================================\n",
            PACKET_LEN,
            BATCHES,
            ITEMS_PER_BATCH,
            total_packets,
            total_bytes,
            total_bytes as f64 / (1024.0 * 1024.0),
            measured,
            setup_time,
            ns_per_packet,
            setup_ns_per_packet,
            mpps,
            gbps,
            (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9,
            if gbps > (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9 {
                "drain alone exceeds MIN on this host — rules out drain as \
                 the immediate limiter here"
            } else {
                "drain alone below MIN on this host — constant is TOO HIGH, \
                 lower it and re-validate live"
            },
        );

        assert!(
            total_packets as usize == BATCHES * ITEMS_PER_BATCH,
            "every batch must fully drain: {} != {}",
            total_packets,
            BATCHES * ITEMS_PER_BATCH
        );
    }

    #[test]
    fn surplus_phase_prefers_higher_priority_queue() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "bulk".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "voice".into(),
                    priority: 0,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        root.tokens = 64 * 1024;
        for queue in &mut root.queues {
            queue.last_refill_ns = 1;
            queue.tokens = 0;
            queue.runnable = true;
            queue.items.push_back(test_cos_item(1500));
            queue.queued_bytes = 1500;
        }
        root.nonempty_queues = 2;
        root.runnable_queues = 2;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        let batch = select_cos_surplus_batch(&mut root, 1).expect("surplus batch");
        match batch {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
    }

    #[test]
    fn surplus_phase_applies_weighted_same_priority_sharing() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "small".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "large".into(),
                    priority: 5,
                    transmit_rate_bytes: 4_000_000,
                    exact: false,
                    surplus_weight: 4,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        root.tokens = 64 * 1024;
        for queue in &mut root.queues {
            queue.last_refill_ns = 1;
            queue.tokens = 0;
            queue.runnable = true;
            for _ in 0..8 {
                queue.items.push_back(test_cos_item(1500));
            }
            queue.queued_bytes = 8 * 1500;
        }
        root.nonempty_queues = 2;
        root.runnable_queues = 2;

        let first = select_cos_surplus_batch(&mut root, 1).expect("first surplus batch");
        let second = select_cos_surplus_batch(&mut root, 1).expect("second surplus batch");

        match first {
            CoSBatch::Local {
                queue_idx, items, ..
            } => {
                assert_eq!(queue_idx, 0);
                assert_eq!(items.len(), 1);
            }
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        match second {
            CoSBatch::Local {
                queue_idx, items, ..
            } => {
                assert_eq!(queue_idx, 1);
                assert_eq!(items.len(), 4);
            }
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
    }

    #[test]
    fn timer_wheel_wakes_short_parked_queue() {
        let mut root = test_cos_interface_runtime(0);
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        park_cos_queue(&mut root, 0, 5);

        assert!(root.queues[0].parked);
        assert!(!root.queues[0].runnable);
        assert_eq!(root.runnable_queues, 0);

        advance_cos_timer_wheel(&mut root, 4 * COS_TIMER_WHEEL_TICK_NS);
        assert!(root.queues[0].parked);
        assert!(!root.queues[0].runnable);

        advance_cos_timer_wheel(&mut root, 5 * COS_TIMER_WHEEL_TICK_NS);
        assert!(!root.queues[0].parked);
        assert!(root.queues[0].runnable);
        assert_eq!(root.runnable_queues, 1);
    }

    #[test]
    fn timer_wheel_cascades_long_parked_queue() {
        let mut root = test_cos_interface_runtime(0);
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let wake_tick = COS_TIMER_WHEEL_L0_SLOTS as u64 + 10;
        park_cos_queue(&mut root, 0, wake_tick);

        assert_eq!(root.queues[0].wheel_level, 1);
        assert!(root.queues[0].parked);

        advance_cos_timer_wheel(&mut root, (wake_tick - 1) * COS_TIMER_WHEEL_TICK_NS);
        assert!(root.queues[0].parked);
        assert!(!root.queues[0].runnable);

        advance_cos_timer_wheel(&mut root, wake_tick * COS_TIMER_WHEEL_TICK_NS);
        assert!(!root.queues[0].parked);
        assert!(root.queues[0].runnable);
        assert_eq!(root.runnable_queues, 1);
    }

    #[test]
    fn normalize_cos_queue_state_repairs_nonempty_unparked_queue_to_runnable() {
        let mut queue = CoSQueueRuntime {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            exact: true,
            flow_fair: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 1500,
            active_flow_buckets: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::from([test_cos_item(1500)]),
            drop_counters: CoSQueueDropCounters::default(),
        };

        normalize_cos_queue_state(&mut queue);

        assert!(queue.runnable);
        assert!(!queue.parked);
        assert_eq!(queue.next_wakeup_tick, 0);
    }

    #[test]
    fn restore_cos_local_items_marks_queue_runnable_after_retry() {
        let mut queue = CoSQueueRuntime {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            exact: true,
            flow_fair: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            drop_counters: CoSQueueDropCounters::default(),
        };
        let retry = VecDeque::from([TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
        }]);

        let retry_bytes = restore_cos_local_items_inner(&mut queue, retry);

        assert_eq!(queue.items.len(), 1);
        assert_eq!(retry_bytes, 1500);
        assert!(queue.runnable);
        assert!(!queue.parked);
    }

    #[test]
    fn restore_cos_prepared_items_marks_queue_runnable_after_retry() {
        let mut queue = CoSQueueRuntime {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            exact: true,
            flow_fair: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            drop_counters: CoSQueueDropCounters::default(),
        };
        let retry = VecDeque::from([PreparedTxRequest {
            offset: 64,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
        }]);

        let retry_bytes = restore_cos_prepared_items_inner(&mut queue, retry);

        assert_eq!(queue.items.len(), 1);
        assert_eq!(retry_bytes, 1500);
        assert!(queue.runnable);
        assert!(!queue.parked);
    }

    // ---------------------------------------------------------------------
    // #710 drop-reason counter tests. Each test drives the exact code
    // path that should tick the named counter, and asserts:
    //   (a) the expected counter advances by the expected amount
    //   (b) no other counter on the same queue advances
    // Byte-precise so a future refactor that accidentally re-attributes a
    // drop to the wrong reason is caught on CI.
    // ---------------------------------------------------------------------

    fn snapshot_counters(queue: &CoSQueueRuntime) -> CoSQueueDropCounters {
        queue.drop_counters
    }

    #[test]
    fn park_counter_root_token_starvation_ticks_only_its_reason() {
        let mut root = test_cos_runtime_with_exact(true);
        root.tokens = 0;
        root.queues[0].tokens = 0;
        root.queues[0].runnable = true;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let before = snapshot_counters(&root.queues[0]);
        // Drive a selector that will park on root-token starvation.
        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        let after = snapshot_counters(&root.queues[0]);

        assert_eq!(
            after.root_token_starvation_parks,
            before.root_token_starvation_parks + 1,
            "root-token park counter must advance by 1"
        );
        assert_eq!(
            after.queue_token_starvation_parks,
            before.queue_token_starvation_parks
        );
        assert_eq!(
            after.admission_flow_share_drops,
            before.admission_flow_share_drops
        );
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
        assert_eq!(
            after.tx_ring_full_submit_stalls,
            before.tx_ring_full_submit_stalls
        );
    }

    #[test]
    fn park_counter_queue_token_starvation_ticks_only_its_reason_on_exact() {
        let mut root = test_cos_runtime_with_exact(true);
        // Root has headroom; per-queue tokens do not. Forces the
        // queue-token park branch on the exact selector.
        root.tokens = 1_000_000;
        root.queues[0].tokens = 0;
        root.queues[0].last_refill_ns = 1; // skip the first-refill init path
        root.queues[0].runnable = true;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let before = snapshot_counters(&root.queues[0]);
        let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
        assert!(
            selection.is_none(),
            "exact selector must park, not return a queue"
        );
        let after = snapshot_counters(&root.queues[0]);

        assert_eq!(
            after.queue_token_starvation_parks,
            before.queue_token_starvation_parks + 1,
            "queue-token park counter must advance by 1"
        );
        assert_eq!(
            after.root_token_starvation_parks,
            before.root_token_starvation_parks
        );
        assert_eq!(
            after.admission_flow_share_drops,
            before.admission_flow_share_drops
        );
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
        assert_eq!(
            after.tx_ring_full_submit_stalls,
            before.tx_ring_full_submit_stalls
        );
    }

    #[test]
    fn count_park_reason_helper_advances_exact_counter() {
        // Low-level test of the helper itself — paranoia pin against a
        // refactor that accidentally writes to the wrong field.
        let mut root = test_cos_runtime_with_exact(true);
        let before = snapshot_counters(&root.queues[0]);

        count_park_reason(&mut root, 0, ParkReason::RootTokenStarvation);
        let mid = snapshot_counters(&root.queues[0]);
        assert_eq!(
            mid.root_token_starvation_parks,
            before.root_token_starvation_parks + 1
        );
        assert_eq!(
            mid.queue_token_starvation_parks,
            before.queue_token_starvation_parks
        );

        count_park_reason(&mut root, 0, ParkReason::QueueTokenStarvation);
        let after = snapshot_counters(&root.queues[0]);
        assert_eq!(
            after.queue_token_starvation_parks,
            before.queue_token_starvation_parks + 1
        );
        assert_eq!(
            after.root_token_starvation_parks,
            mid.root_token_starvation_parks
        );

        // Out-of-range queue_idx is a no-op, not a panic.
        count_park_reason(&mut root, 999, ParkReason::RootTokenStarvation);
        assert_eq!(
            snapshot_counters(&root.queues[0]).root_token_starvation_parks,
            after.root_token_starvation_parks
        );
    }

    // ---------------------------------------------------------------------
    // #718 ECN CE-marking. The markers are the load-bearing helpers;
    // the admission-path tests exercise `apply_cos_admission_ecn_policy`
    // which is what `enqueue_cos_item` calls in-line. Keep the marker
    // tests byte-precise so a future refactor that flips an endian /
    // offset / masks a different bit fails loudly.
    // ---------------------------------------------------------------------

    /// Build a minimal IPv4 packet (Ethernet + IPv4 header, no
    /// payload) with the given `tos` byte and a valid IP checksum.
    /// 34-byte total so `l3_offset = 14` lands on the IPv4 version/IHL
    /// byte. Returns the buffer for mutation.
    fn build_ipv4_test_packet(tos: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 34];
        // Ethernet header: dst + src MAC (12 bytes of zeros is fine
        // for a checksum-only test), ethertype = IPv4 (0x0800).
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        // IPv4 header, l3_offset = 14:
        //   byte 0: version (4) + IHL (5) = 0x45
        //   byte 1: TOS
        //   bytes 2..3: total length (20)
        //   bytes 4..5: id
        //   bytes 6..7: flags + frag offset
        //   byte 8: TTL (64)
        //   byte 9: protocol (TCP=6)
        //   bytes 10..11: header checksum (placeholder)
        //   bytes 12..15: src IP 10.0.0.1
        //   bytes 16..19: dst IP 10.0.0.2
        pkt[14] = 0x45;
        pkt[15] = tos;
        pkt[16] = 0;
        pkt[17] = 20;
        pkt[22] = 64;
        pkt[23] = 6;
        pkt[26] = 10;
        pkt[27] = 0;
        pkt[28] = 0;
        pkt[29] = 1;
        pkt[30] = 10;
        pkt[31] = 0;
        pkt[32] = 0;
        pkt[33] = 2;
        let csum = compute_ipv4_header_checksum(&pkt[14..34]);
        pkt[24] = (csum >> 8) as u8;
        pkt[25] = (csum & 0xff) as u8;
        pkt
    }

    /// Compute the IPv4 header checksum over the given header bytes.
    /// Used by tests to independently verify that the incremental
    /// update in `mark_ecn_ce_ipv4` produced the same value a
    /// from-scratch computation would.
    fn compute_ipv4_header_checksum(header: &[u8]) -> u16 {
        assert_eq!(header.len(), 20, "test fixture must be a 20-byte header");
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            if i == 10 {
                // Skip the checksum field itself.
                continue;
            }
            sum += ((header[i] as u32) << 8) | header[i + 1] as u32;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        (!sum & 0xffff) as u16
    }

    fn ipv4_tos(pkt: &[u8]) -> u8 {
        pkt[15]
    }

    fn ipv4_checksum(pkt: &[u8]) -> u16 {
        ((pkt[24] as u16) << 8) | pkt[25] as u16
    }

    #[test]
    fn mark_ecn_ce_ipv4_converts_ect0_to_ce_and_updates_checksum() {
        // ECT(0) = 0b10 in the low 2 bits of the TOS byte. Pick a
        // non-zero DSCP (0x28 = CS5 = expedited forwarding) to verify
        // the upper 6 bits survive the mark. TOS before = 0xa2.
        let tos = (0x28u8 << 2) | ECN_ECT_0;
        let mut pkt = build_ipv4_test_packet(tos);
        assert_eq!(ipv4_tos(&pkt), 0xa2);
        let csum_before = ipv4_checksum(&pkt);

        assert!(mark_ecn_ce_ipv4(&mut pkt, 14));

        // Low 2 bits now CE, upper 6 bits (DSCP) unchanged.
        assert_eq!(ipv4_tos(&pkt) & ECN_MASK, ECN_CE);
        assert_eq!(ipv4_tos(&pkt) >> 2, 0x28);
        // Checksum must differ from the before-state (ECN flipped one
        // bit in the low byte) AND be valid from scratch.
        assert_ne!(
            ipv4_checksum(&pkt),
            csum_before,
            "ECN bit flip must change the IP checksum",
        );
        assert_eq!(
            ipv4_checksum(&pkt),
            compute_ipv4_header_checksum(&pkt[14..34]),
            "incremental checksum must match a from-scratch recompute",
        );
    }

    #[test]
    fn mark_ecn_ce_ipv4_converts_ect1_to_ce_and_updates_checksum() {
        // ECT(1) = 0b01. DSCP = 0, so TOS starts at 0x01 — stresses
        // the case where the high nibble is zero and only the low
        // bits mutate.
        let tos = ECN_ECT_1;
        let mut pkt = build_ipv4_test_packet(tos);

        assert!(mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(ipv4_tos(&pkt), ECN_CE);
        assert_eq!(
            ipv4_checksum(&pkt),
            compute_ipv4_header_checksum(&pkt[14..34]),
        );
    }

    #[test]
    fn mark_ecn_ce_ipv4_leaves_not_ect_untouched() {
        // NOT-ECT packet must be left entirely alone — RFC 3168 6.1.1.1
        // forbids forcing ECN on flows that did not negotiate it.
        let tos = 0xb8; // DSCP 46 (EF), ECN = 00
        let mut pkt = build_ipv4_test_packet(tos);
        let before = pkt.clone();

        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(pkt, before, "NOT-ECT packet must be byte-identical");
    }

    #[test]
    fn mark_ecn_ce_ipv4_leaves_ce_untouched() {
        // CE already — idempotent: function reports "not marked" but
        // also doesn't re-write the checksum, so bytes stay identical.
        let tos = 0xb8 | ECN_CE;
        let mut pkt = build_ipv4_test_packet(tos);
        let before = pkt.clone();

        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(pkt, before, "CE packet must be byte-identical");
    }

    #[test]
    fn mark_ecn_ce_ipv4_rejects_short_buffer() {
        // Buffer too short to hold a full 20-byte IPv4 header starting
        // at l3_offset=14 (only 33 bytes — one short). Must return
        // false and not panic.
        let mut pkt = vec![0u8; 33];
        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));

        // Also exercise the case where `l3_offset` itself pushes past
        // the buffer end.
        let mut pkt = vec![0u8; 16];
        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
    }

    /// Build a minimal IPv6 packet (Ethernet + IPv6 header, no
    /// payload) with the given full tclass byte. Returns the buffer
    /// for mutation.
    fn build_ipv6_test_packet(tclass: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 54];
        pkt[12] = 0x86;
        pkt[13] = 0xdd;
        // IPv6 header, l3_offset = 14:
        //   version/tclass high nibble in byte 0 (version=6 -> 0x60
        //   in the high nibble; tclass high nibble in the low nibble)
        //   tclass low nibble + flow label high nibble in byte 1
        pkt[14] = 0x60 | ((tclass >> 4) & 0x0f);
        pkt[15] = ((tclass & 0x0f) << 4) | 0x00;
        // Payload length = 0, next header = TCP, hop limit = 64.
        pkt[20] = 6;
        pkt[21] = 64;
        pkt
    }

    fn ipv6_tclass(pkt: &[u8]) -> u8 {
        ((pkt[14] & 0x0f) << 4) | ((pkt[15] >> 4) & 0x0f)
    }

    #[test]
    fn mark_ecn_ce_ipv6_converts_ect0_to_ce() {
        // DSCP 46 (EF) + ECT(0) → full tclass 0xba.
        let tclass = (0x2eu8 << 2) | ECN_ECT_0;
        let mut pkt = build_ipv6_test_packet(tclass);
        assert_eq!(ipv6_tclass(&pkt), 0xba);
        // Preserve flow label / version bits for the round-trip check.
        let version_nibble_before = pkt[14] & 0xf0;
        let flow_label_low_before = pkt[15] & 0x0f;

        assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(ipv6_tclass(&pkt) & ECN_MASK, ECN_CE);
        assert_eq!(ipv6_tclass(&pkt) >> 2, 0x2e);
        // Version + flow-label bits must not drift.
        assert_eq!(pkt[14] & 0xf0, version_nibble_before);
        assert_eq!(pkt[15] & 0x0f, flow_label_low_before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_converts_ect1_to_ce() {
        let tclass = ECN_ECT_1;
        let mut pkt = build_ipv6_test_packet(tclass);
        assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(ipv6_tclass(&pkt), ECN_CE);
    }

    #[test]
    fn mark_ecn_ce_ipv6_leaves_not_ect_untouched() {
        let tclass = 0xb8; // DSCP 46, ECN 00
        let mut pkt = build_ipv6_test_packet(tclass);
        let before = pkt.clone();
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(pkt, before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_leaves_ce_untouched() {
        let tclass = 0xb8 | ECN_CE;
        let mut pkt = build_ipv6_test_packet(tclass);
        let before = pkt.clone();
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(pkt, before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_rejects_short_buffer() {
        let mut pkt = vec![0u8; 15];
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
    }

    #[test]
    fn maybe_mark_ecn_ce_dispatches_by_addr_family() {
        // IPv4 dispatch: ECT(0) → CE.
        let tos = ECN_ECT_0;
        let bytes = build_ipv4_test_packet(tos);
        let mut req = TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(maybe_mark_ecn_ce(&mut req));
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE);

        // IPv6 dispatch: ECT(1) → CE.
        let tclass = ECN_ECT_1;
        let bytes = build_ipv6_test_packet(tclass);
        let mut req = TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(maybe_mark_ecn_ce(&mut req));
        assert_eq!(ipv6_tclass(&req.bytes), ECN_CE);

        // Unknown address family: no-op (and no panic).
        let mut req = TxRequest {
            bytes: vec![0u8; 64],
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(!maybe_mark_ecn_ce(&mut req));
    }

    /// Helper: build a `CoSPendingTxItem::Local` with an IPv4 test
    /// packet carrying the given TOS byte. Default flow key routes it
    /// into queue 0 of `test_cos_runtime_with_exact`.
    fn test_local_ipv4_item(tos: u8) -> CoSPendingTxItem {
        CoSPendingTxItem::Local(TxRequest {
            bytes: build_ipv4_test_packet(tos),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        })
    }

    #[test]
    fn admission_ecn_marked_counter_increments_when_marking_above_threshold() {
        // Drive the queue to >50% of buffer_limit with an ECT(0) packet
        // incoming. The mark must fire; the counter must advance by
        // exactly one; no drop counters advance; the packet is "admitted"
        // (we run the decision in isolation, so we just assert `marked`).
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        // Half + 1 byte — strictly above the 50% threshold.
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let marked = apply_cos_admission_ecn_policy(queue, buffer_limit, false, false, &mut item);

        assert!(marked);
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
            "ECN counter must advance by 1",
        );
        assert_eq!(after.admission_flow_share_drops, before.admission_flow_share_drops);
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
        // Packet bytes now carry CE.
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE);
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_does_not_mark_below_threshold() {
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        // Exactly at threshold — `>` comparison must not fire.
        queue.queued_bytes = buffer_limit / 2;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let marked = apply_cos_admission_ecn_policy(queue, buffer_limit, false, false, &mut item);

        assert!(!marked, "at-threshold must not mark");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        // Packet bytes unchanged.
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_does_not_mark_non_ect_packets() {
        // Queue above threshold, but packet is NOT-ECT. Mark must not
        // fire and counter must not advance — RFC 3168 compliance.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_NOT_ECT);
        let marked = apply_cos_admission_ecn_policy(queue, buffer_limit, false, false, &mut item);

        assert!(!marked);
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_NOT_ECT);
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_does_not_mark_when_drop_is_imminent() {
        // Queue above threshold AND flow-share/buffer exceeded: don't
        // burn the mark on a packet that's about to be dropped.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_ECT_0);
        // Signal that the caller already decided this packet will drop.
        let marked = apply_cos_admission_ecn_policy(queue, buffer_limit, true, false, &mut item);
        assert!(!marked, "flow_share_exceeded path must skip marking");
        let after_share = snapshot_counters(queue);
        assert_eq!(after_share.admission_ecn_marked, before.admission_ecn_marked);

        let marked = apply_cos_admission_ecn_policy(queue, buffer_limit, false, true, &mut item);
        assert!(!marked, "buffer_exceeded path must skip marking");
        let after_buf = snapshot_counters(queue);
        assert_eq!(after_buf.admission_ecn_marked, before.admission_ecn_marked);

        // Packet bytes unchanged through both calls.
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_does_not_mark_prepared_variant() {
        // Prepared variant is the TODO(#718-followup) path. Exercised
        // here so a future implementer sees an explicit pin when they
        // land the umem-slice marking work.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut item = test_flow_prepared_cos_item(1111, 1500, 0);
        let marked = apply_cos_admission_ecn_policy(queue, buffer_limit, false, false, &mut item);
        assert!(!marked);
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    }
}
