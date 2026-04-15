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
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
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
        cos_owner_worker_by_queue,
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
                binding.live.set_error(err);
            }
        }
    }
    let mut pending = take_pending_tx_requests(binding);
    if pending.is_empty() {
        return did_work || !binding.pending_tx_prepared.is_empty();
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
    did_work
        || !binding.pending_tx_prepared.is_empty()
        || !binding.pending_tx_local.is_empty()
        || !binding.live.pending_tx_empty()
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
        items: VecDeque<TxRequest>,
    },
    Prepared {
        queue_idx: usize,
        phase: CoSServicePhase,
        items: VecDeque<PreparedTxRequest>,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CoSTxSelection {
    pub(super) queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
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
) -> bool {
    drain_pending_tx(
        binding,
        now_ns,
        shared_recycles,
        forwarding,
        worker_id,
        worker_commands_by_id,
        cos_owner_worker_by_queue,
    )
}

fn ingest_cos_pending_tx(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
) {
    if forwarding.cos.interfaces.is_empty() {
        return;
    }

    if !binding.pending_tx_prepared.is_empty() {
        let mut kept = VecDeque::with_capacity(binding.pending_tx_prepared.len());
        while let Some(req) = binding.pending_tx_prepared.pop_front() {
            let req = match redirect_prepared_cos_request_to_owner(
                binding,
                forwarding,
                req,
                worker_id,
                worker_commands_by_id,
                cos_owner_worker_by_queue,
            ) {
                Ok(()) => continue,
                Err(req) => req,
            };
            let req = match redirect_prepared_cos_request_to_owner_binding(binding, forwarding, req)
            {
                Ok(()) => continue,
                Err(req) => req,
            };
            match enqueue_prepared_into_cos(binding, forwarding, req, now_ns) {
                Ok(()) => {}
                Err(req) => kept.push_back(req),
            }
        }
        binding.pending_tx_prepared = kept;
    }

    let local = core::mem::take(&mut binding.pending_tx_local);
    let shared = binding.live.take_pending_tx();
    let mut pending = merge_pending_tx_requests(local, shared);
    let mut kept = VecDeque::with_capacity(pending.len());
    while let Some(req) = pending.pop_front() {
        let req = match redirect_local_cos_request_to_owner(
            forwarding,
            req,
            worker_id,
            worker_commands_by_id,
            cos_owner_worker_by_queue,
        ) {
            Ok(()) => continue,
            Err(req) => req,
        };
        let req = match redirect_local_cos_request_to_owner_binding(
            &binding.live,
            &binding.cos_owner_live_by_tx_ifindex,
            forwarding,
            req,
        ) {
            Ok(()) => continue,
            Err(req) => req,
        };
        match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
            Ok(()) => {}
            Err(req) => kept.push_back(req),
        }
    }
    binding.pending_tx_local = kept;
    bound_pending_tx_local(binding);
}

fn effective_cos_queue_id(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<u8> {
    requested_queue_id.or_else(|| {
        forwarding
            .cos
            .interfaces
            .get(&egress_ifindex)
            .map(|iface| iface.default_queue)
    })
}

fn cos_owner_worker_for_cos_queue(
    forwarding: &ForwardingState,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
    current_worker_id: u32,
) -> u32 {
    effective_cos_queue_id(forwarding, egress_ifindex, requested_queue_id)
        .and_then(|queue_id| {
            cos_owner_worker_by_queue
                .get(&(egress_ifindex, queue_id))
                .copied()
        })
        .unwrap_or(current_worker_id)
}

fn redirect_local_cos_request_to_owner(
    forwarding: &ForwardingState,
    req: TxRequest,
    current_worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
) -> Result<(), TxRequest> {
    let owner_worker_id = cos_owner_worker_for_cos_queue(
        forwarding,
        cos_owner_worker_by_queue,
        req.egress_ifindex,
        req.cos_queue_id,
        current_worker_id,
    );
    if owner_worker_id == current_worker_id {
        return Err(req);
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
    owner_live_by_tx_ifindex: &BTreeMap<i32, Arc<BindingLiveState>>,
    forwarding: &ForwardingState,
    req: TxRequest,
) -> Result<(), TxRequest> {
    let tx_ifindex = resolve_tx_binding_ifindex(forwarding, req.egress_ifindex);
    let Some(owner_live) = owner_live_by_tx_ifindex.get(&tx_ifindex) else {
        return Err(req);
    };
    if Arc::ptr_eq(owner_live, current_live) {
        return Err(req);
    }
    owner_live.enqueue_tx_owned(req)
}

fn redirect_prepared_cos_request_to_owner(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    req: PreparedTxRequest,
    current_worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
) -> Result<(), PreparedTxRequest> {
    let owner_worker_id = cos_owner_worker_for_cos_queue(
        forwarding,
        cos_owner_worker_by_queue,
        req.egress_ifindex,
        req.cos_queue_id,
        current_worker_id,
    );
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
        forwarding,
        local_req,
        current_worker_id,
        worker_commands_by_id,
        cos_owner_worker_by_queue,
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
    forwarding: &ForwardingState,
    req: PreparedTxRequest,
) -> Result<(), PreparedTxRequest> {
    let tx_ifindex = resolve_tx_binding_ifindex(forwarding, req.egress_ifindex);
    let Some(owner_live) = binding.cos_owner_live_by_tx_ifindex.get(&tx_ifindex) else {
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
        let Some(batch) = build_cos_batch(binding, root_ifindex, now_ns) else {
            continue;
        };
        binding.cos_interface_rr = (start + offset + 1) % binding.cos_interface_order.len();
        return submit_cos_batch(binding, root_ifindex, batch, now_ns, shared_recycles);
    }
    false
}

fn build_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
) -> Option<CoSBatch> {
    let shared_root_lease = binding.cos_shared_root_leases.get(&root_ifindex).cloned();
    let selected = {
        let root = binding.cos_interfaces.get_mut(&root_ifindex)?;
        advance_cos_timer_wheel(root, now_ns);
        if let Some(shared_root_lease) = shared_root_lease.as_ref() {
            maybe_top_up_cos_root_lease(root, shared_root_lease, now_ns);
        }
        select_cos_guarantee_batch(root, now_ns).or_else(|| select_cos_surplus_batch(root, now_ns))
    };
    if selected.is_some() {
        refresh_cos_interface_activity(binding, root_ifindex);
    }
    selected
}

fn select_cos_guarantee_batch(root: &mut CoSInterfaceRuntime, now_ns: u64) -> Option<CoSBatch> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if queue.items.is_empty() || !queue.runnable {
            continue;
        }
        refill_cos_tokens(
            &mut queue.tokens,
            queue.transmit_rate_bytes,
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            &mut queue.last_refill_ns,
            now_ns,
        );
        let Some(head) = queue.items.front() else {
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
                    park_cos_queue(root, queue_idx, wake_tick);
                }
            }
            continue;
        }
        root.guarantee_rr = (start + offset + 1) % queue_count;
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
            if queue.items.is_empty() || !queue.runnable || queue.exact {
                continue;
            }
            let Some(head) = queue.items.front() else {
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

fn build_cos_batch_from_queue(
    queue: &mut CoSQueueRuntime,
    queue_idx: usize,
    root_budget: u64,
    secondary_budget: u64,
    phase: CoSServicePhase,
) -> Option<CoSBatch> {
    let head = queue.items.front()?;
    match head {
        CoSPendingTxItem::Local(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = queue.items.front() else {
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
                match queue.items.pop_front() {
                    Some(CoSPendingTxItem::Local(req)) => items.push_back(req),
                    Some(other) => {
                        queue.items.push_front(other);
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
                    items,
                })
            }
        }
        CoSPendingTxItem::Prepared(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = queue.items.front() else {
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
                match queue.items.pop_front() {
                    Some(CoSPendingTxItem::Prepared(req)) => items.push_back(req),
                    Some(other) => {
                        queue.items.push_front(other);
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
            mut items,
        } => {
            assign_local_dscp_rewrite(
                &mut items,
                cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
            );
            match transmit_batch(binding, &mut items, now_ns, shared_recycles) {
                Ok((packets, bytes)) => {
                    apply_cos_send_result(binding, root_ifindex, queue_idx, phase, bytes, items);
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
                    restore_cos_local_items(binding, root_ifindex, queue_idx, items);
                    cos_batch_tx_made_progress(Err(TxError::Retry(String::new())))
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                    restore_cos_local_items(binding, root_ifindex, queue_idx, items);
                    cos_batch_tx_made_progress(Err(TxError::Drop(String::new())))
                }
            }
        }
        CoSBatch::Prepared {
            queue_idx,
            phase,
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
                    restore_cos_prepared_items(binding, root_ifindex, queue_idx, items);
                    cos_batch_tx_made_progress(Err(TxError::Retry(String::new())))
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                    restore_cos_prepared_items(binding, root_ifindex, queue_idx, items);
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
const COS_GUARANTEE_VISIT_NS: u64 = 100_000;
const COS_GUARANTEE_QUANTUM_MIN_BYTES: u64 = 1500;
const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 32 * 1024;
const COS_SURPLUS_ROUND_QUANTUM_BYTES: u64 = 1500;
const COS_TIMER_WHEEL_L0_HORIZON_TICKS: u64 = COS_TIMER_WHEEL_L0_SLOTS as u64;

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
    if queue.items.is_empty() {
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
    if queue.items.is_empty() {
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
    meta: UserspaceDpMeta,
    flow_key: Option<&SessionKey>,
) -> Option<u8> {
    resolve_cos_tx_selection(forwarding, egress_ifindex, meta, flow_key).queue_id
}

pub(super) fn resolve_cos_tx_selection(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: UserspaceDpMeta,
    flow_key: Option<&SessionKey>,
) -> CoSTxSelection {
    let iface = forwarding.cos.interfaces.get(&egress_ifindex);
    let Some(flow_key) = flow_key else {
        return CoSTxSelection {
            queue_id: iface.map(|iface| iface.default_queue),
            dscp_rewrite: None,
        };
    };
    let is_v6 = meta.addr_family as i32 == libc::AF_INET6;
    let has_output_filter = if is_v6 {
        forwarding
            .filter_state
            .iface_filter_out_v6
            .contains_key(&egress_ifindex)
    } else {
        forwarding
            .filter_state
            .iface_filter_out_v4
            .contains_key(&egress_ifindex)
    };
    let output_result = if has_output_filter {
        crate::filter::evaluate_interface_output_filter_counted(
            &forwarding.filter_state,
            egress_ifindex,
            is_v6,
            flow_key.src_ip,
            flow_key.dst_ip,
            flow_key.protocol,
            flow_key.src_port,
            flow_key.dst_port,
            meta.dscp,
            meta.pkt_len as u64,
        )
    } else {
        crate::filter::FilterResult::default()
    };
    let mut effective_dscp_rewrite = output_result.dscp_rewrite;
    let mut ingress_forwarding_class = Arc::<str>::from("");
    if !has_output_filter {
        let ingress_ifindex = resolve_ingress_logical_ifindex(
            forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        let ingress_result = crate::filter::evaluate_interface_filter_counted(
            &forwarding.filter_state,
            ingress_ifindex,
            is_v6,
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
    if !output_result.forwarding_class.is_empty() {
        if let Some(queue_id) = iface
            .queue_by_forwarding_class
            .get(output_result.forwarding_class.as_ref())
        {
            return CoSTxSelection {
                queue_id: Some(*queue_id),
                dscp_rewrite: effective_dscp_rewrite,
            };
        }
    }
    if !ingress_forwarding_class.is_empty() {
        if let Some(queue_id) = iface
            .queue_by_forwarding_class
            .get(ingress_forwarding_class.as_ref())
        {
            return CoSTxSelection {
                queue_id: Some(*queue_id),
                dscp_rewrite: effective_dscp_rewrite,
            };
        }
    }
    if let Some(queue_id) = resolve_cos_dscp_classifier_queue_id(forwarding, iface, meta.dscp) {
        return CoSTxSelection {
            queue_id: Some(queue_id),
            dscp_rewrite: effective_dscp_rewrite,
        };
    }
    if let Some(queue_id) = resolve_cos_ieee8021_classifier_queue_id(
        forwarding,
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

fn resolve_cos_dscp_classifier_queue_id(
    forwarding: &ForwardingState,
    iface: &CoSInterfaceConfig,
    dscp: u8,
) -> Option<u8> {
    if iface.dscp_classifier.is_empty() {
        return None;
    }
    forwarding
        .cos
        .dscp_classifiers
        .get(&iface.dscp_classifier)
        .and_then(|classifier| classifier.queue_by_dscp.get(&dscp).copied())
}

fn resolve_cos_ieee8021_classifier_queue_id(
    forwarding: &ForwardingState,
    iface: &CoSInterfaceConfig,
    pcp: u8,
    vlan_present: bool,
) -> Option<u8> {
    if iface.ieee8021_classifier.is_empty() || !vlan_present {
        return None;
    }
    forwarding
        .cos
        .ieee8021_classifiers
        .get(&iface.ieee8021_classifier)
        .and_then(|classifier| classifier.queue_by_pcp.get(&pcp).copied())
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
    let Some(local_req) = clone_prepared_request_for_cos(binding.umem.area(), &req) else {
        return Err(req);
    };
    // Once shaped traffic is queued behind the CoS scheduler, it must not keep holding
    // owner TX frames. Otherwise a local item can reach the head of the same queue while
    // all free frames are trapped inside queued prepared items, leading to a persistent
    // "no free TX frame available" livelock.
    recycle_prepared_immediately(binding, &req);
    let item_len = local_req.bytes.len() as u64;
    match enqueue_cos_item(
        binding,
        egress_ifindex,
        local_req.cos_queue_id,
        item_len,
        CoSPendingTxItem::Local(local_req),
    ) {
        Ok(()) => Ok(()),
        Err(CoSPendingTxItem::Local(_)) => Ok(()),
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
    if !binding.cos_interfaces.contains_key(&egress_ifindex) {
        binding
            .cos_interfaces
            .insert(egress_ifindex, build_cos_interface_runtime(config, now_ns));
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
        guarantee_rr: 0,
        queues: config
            .queues
            .iter()
            .map(|queue| CoSQueueRuntime {
                queue_id: queue.queue_id,
                priority: queue.priority,
                transmit_rate_bytes: queue.transmit_rate_bytes,
                exact: queue.exact,
                surplus_weight: queue.surplus_weight,
                surplus_deficit: 0,
                buffer_bytes: queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
                dscp_rewrite: queue.dscp_rewrite,
                tokens: queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
                last_refill_ns: now_ns,
                queued_bytes: 0,
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
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
    item: CoSPendingTxItem,
) -> Result<(), CoSPendingTxItem> {
    let mut root_became_nonempty = false;
    let (accepted, queue_id, recycle) = {
        let Some(root) = binding.cos_interfaces.get_mut(&egress_ifindex) else {
            return Err(item);
        };
        if root.queues.is_empty() {
            return Err(item);
        }
        let target_queue = requested_queue.unwrap_or(root.default_queue);
        let default_queue = root.default_queue;
        let mut queue_idx = root
            .queues
            .iter()
            .position(|queue| queue.queue_id == target_queue)
            .or_else(|| {
                root.queues
                    .iter()
                    .position(|queue| queue.queue_id == default_queue)
            })
            .unwrap_or(0);
        if queue_idx >= root.queues.len() {
            queue_idx = 0;
        }
        let root_was_empty = root.nonempty_queues == 0;
        let queue = &mut root.queues[queue_idx];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        if queue.queued_bytes.saturating_add(item_len) > buffer_limit {
            let recycle = match &item {
                CoSPendingTxItem::Prepared(req) => Some((req.recycle, req.offset)),
                CoSPendingTxItem::Local(_) => None,
            };
            (false, queue.queue_id, recycle)
        } else {
            let queue_was_empty = queue.items.is_empty();
            queue.queued_bytes = queue.queued_bytes.saturating_add(item_len);
            queue.items.push_back(item);
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
    let old_nonempty = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.nonempty_queues)
        .unwrap_or(0);
    if let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) {
        for queue in &mut root.queues {
            normalize_cos_queue_state(queue);
            if queue.items.is_empty() {
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
    if let Some(shared_root_lease) = binding.cos_shared_root_leases.get(&root_ifindex) {
        shared_root_lease.release_unused(released);
    }
}

pub(super) fn release_all_cos_root_leases(binding: &mut BindingWorker) {
    let root_ifindexes = binding.cos_interfaces.keys().copied().collect::<Vec<_>>();
    for root_ifindex in root_ifindexes {
        release_cos_root_lease(binding, root_ifindex);
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
    sent_bytes: u64,
    retry: VecDeque<TxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            restore_cos_local_items_inner(queue, retry);
            queue.queued_bytes = recompute_cos_queue_bytes(&queue.items);
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
    if let Some(shared_root_lease) = binding.cos_shared_root_leases.get(&root_ifindex) {
        shared_root_lease.consume(sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn apply_cos_prepared_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    sent_bytes: u64,
    retry: VecDeque<PreparedTxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            restore_cos_prepared_items_inner(queue, retry);
            queue.queued_bytes = recompute_cos_queue_bytes(&queue.items);
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
    if let Some(shared_root_lease) = binding.cos_shared_root_leases.get(&root_ifindex) {
        shared_root_lease.consume(sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn restore_cos_local_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    retry: VecDeque<TxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            restore_cos_local_items_inner(queue, retry);
            queue.queued_bytes = recompute_cos_queue_bytes(&queue.items);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn restore_cos_prepared_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    retry: VecDeque<PreparedTxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            restore_cos_prepared_items_inner(queue, retry);
            queue.queued_bytes = recompute_cos_queue_bytes(&queue.items);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn restore_cos_local_items_inner(queue: &mut CoSQueueRuntime, mut retry: VecDeque<TxRequest>) {
    while let Some(req) = retry.pop_back() {
        queue.items.push_front(CoSPendingTxItem::Local(req));
    }
    if !queue.items.is_empty() {
        mark_cos_queue_runnable(queue);
    }
}

fn restore_cos_prepared_items_inner(
    queue: &mut CoSQueueRuntime,
    mut retry: VecDeque<PreparedTxRequest>,
) {
    while let Some(req) = retry.pop_back() {
        queue.items.push_front(CoSPendingTxItem::Prepared(req));
    }
    if !queue.items.is_empty() {
        mark_cos_queue_runnable(queue);
    }
}

fn recompute_cos_queue_bytes(queue: &VecDeque<CoSPendingTxItem>) -> u64 {
    queue.iter().map(cos_item_len).sum()
}

fn merge_pending_tx_requests(
    mut local: VecDeque<TxRequest>,
    mut shared: VecDeque<TxRequest>,
) -> VecDeque<TxRequest> {
    if local.is_empty() {
        return shared;
    }
    if !shared.is_empty() {
        local.append(&mut shared);
    }
    local
}

fn take_pending_tx_requests(binding: &mut BindingWorker) -> VecDeque<TxRequest> {
    let local = core::mem::take(&mut binding.pending_tx_local);
    let shared = binding.live.take_pending_tx();
    merge_pending_tx_requests(local, shared)
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

fn recycle_prepared_immediately(binding: &mut BindingWorker, req: &PreparedTxRequest) {
    recycle_cancelled_prepared(binding, req);
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

    #[test]
    fn merge_pending_tx_requests_appends_shared_after_local() {
        let local = VecDeque::from(vec![
            TxRequest {
                bytes: vec![1],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 0,
                cos_queue_id: None,
                dscp_rewrite: None,
            },
            TxRequest {
                bytes: vec![2],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 0,
                cos_queue_id: None,
                dscp_rewrite: None,
            },
        ]);
        let shared = VecDeque::from(vec![TxRequest {
            bytes: vec![3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
        }]);

        let merged = merge_pending_tx_requests(local, shared);
        let bytes: Vec<Vec<u8>> = merged.into_iter().map(|req| req.bytes).collect();
        assert_eq!(bytes, vec![vec![1], vec![2], vec![3]]);
    }

    #[test]
    fn merge_pending_tx_requests_uses_shared_when_local_empty() {
        let shared = VecDeque::from(vec![TxRequest {
            bytes: vec![9],
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_UDP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
        }]);

        let merged = merge_pending_tx_requests(VecDeque::new(), shared);
        let bytes: Vec<Vec<u8>> = merged.into_iter().map(|req| req.bytes).collect();
        assert_eq!(bytes, vec![vec![9]]);
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
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: COS_MIN_BURST_BYTES,
                default_queue: 4,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                queue_by_forwarding_class: FastMap::default(),
                queues: Vec::new(),
            },
        );
        let cos_owner_worker_by_queue = BTreeMap::from([((80, 4), 7)]);
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
            &forwarding,
            req,
            2,
            &worker_commands_by_id,
            &cos_owner_worker_by_queue,
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
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: COS_MIN_BURST_BYTES,
                default_queue: 5,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                queue_by_forwarding_class: FastMap::default(),
                queues: Vec::new(),
            },
        );
        let cos_owner_worker_by_queue = BTreeMap::from([((80, 5), 7)]);
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
            &forwarding,
            req,
            2,
            &worker_commands_by_id,
            &cos_owner_worker_by_queue,
        );

        assert!(redirected.is_ok());
        let pending = commands.lock().unwrap();
        assert_eq!(pending.len(), 1);
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
    fn maybe_top_up_cos_root_lease_unblocks_large_frame_exceeding_lease_bytes() {
        // At 400 Mbps / 256 KB burst / 1 shard, lease_bytes() == 1500, which is less than
        // tx_frame_capacity() == 4096.  Without the .max(tx_frame_capacity()) fix, root.tokens
        // could never exceed 1500 and any frame with len > 1500 would deadlock the CoS queue.
        let lease = Arc::new(SharedCoSRootLease::new(400_000_000, 256 * 1024, 1));
        assert!(
            lease.lease_bytes() < tx_frame_capacity() as u64,
            "precondition: lease_bytes must be below tx_frame_capacity for this regression"
        );

        let mut root = test_cos_runtime_with_queues(
            400_000_000,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 400_000_000,
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
    fn redirect_local_cos_request_to_owner_binding_pushes_owner_live_queue() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let owner_live_by_tx_ifindex = BTreeMap::from([(12, owner_live.clone())]);
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0; 6],
                zone: "wan".to_string(),
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
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

        let redirected = redirect_local_cos_request_to_owner_binding(
            &current_live,
            &owner_live_by_tx_ifindex,
            &forwarding,
            req,
        );

        assert!(redirected.is_ok());
        let queued = owner_live.take_pending_tx();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
        assert!(current_live.take_pending_tx().is_empty());
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
            local.flow_key.as_ref().map(|key| (key.src_port, key.dst_port)),
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

    #[test]
    fn resolve_cos_queue_id_defaults_when_output_filter_has_no_forwarding_class() {
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

        assert_eq!(queue_id, Some(7));
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
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 1500,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::from([test_cos_item(1500)]),
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
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
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

        restore_cos_local_items_inner(&mut queue, retry);

        assert_eq!(queue.items.len(), 1);
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
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
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

        restore_cos_prepared_items_inner(&mut queue, retry);

        assert_eq!(queue.items.len(), 1);
        assert!(queue.runnable);
        assert!(!queue.parked);
    }
}
