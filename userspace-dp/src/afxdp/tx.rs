use super::*;

/// #812 Codex round-1 MED + Rust round-1 MED-2: replaced the former
/// `canonical_submit_stamp` in-band mapping of `ts == 0 → sentinel`
/// with an early-return in `stamp_submits`. The sentinel is
/// `u64::MAX` (see `umem.rs::TX_SIDECAR_UNSTAMPED`); a legitimate
/// monotonic timestamp cannot reach it (~585 years at ns granularity).
/// Previously, the Rust reviewer flagged the `ts == 0` branch as
/// in-band signalling on a u64. We now skip all sidecar writes on
/// clock failure rather than overwriting fresh data with the sentinel
/// — safe because `record_tx_completions_with_stamp` resets each
/// slot to `TX_SIDECAR_UNSTAMPED` on reap, so a frame whose sidecar
/// did NOT receive a stamp in the current cycle is already in the
/// correct "skip at reap time" state.

/// #812: stamp the submit-timestamp sidecar for the accepted prefix
/// of the current TX batch. Called ONCE per `writer.commit()` at each
/// of the six submit sites (plan §3.1 table) with the scratch
/// offsets. Only the first `inserted` offsets are stamped; the retry
/// tail (`scratch[inserted..]`) MUST NOT be stamped because those
/// descriptors return to `free_tx_frames` and would otherwise produce
/// phantom completions bucketed against a stale submit time.
///
/// Codex round-1 HIGH #1: call sites MUST invoke this AFTER
/// `writer.commit()` (and `drop(writer)`). Pre-commit stamping
/// attributed a scheduler preemption window between `insert` and ring
/// submission to the kernel-visible submit→completion latency, which
/// is exactly backwards. Post-commit stamping reflects the moment the
/// ring producer actually became kernel-visible.
///
/// Single-writer: the owner worker is the only thread that touches
/// this sidecar (see plan §3.3 file citations: `WorkerUmem` is `Rc`
/// at `umem.rs:16-18`, `free_tx_frames` is plain `VecDeque` at
/// `worker.rs:16`). Plain slice-indexed store — no atomic, no grow.
#[inline]
pub(super) fn stamp_submits<I>(sidecar: &mut [u64], offsets: I, ts_submit: u64)
where
    I: Iterator<Item = u64>,
{
    // #812 Codex round-1 MED + Rust round-1 MED-2: clock-failure gate.
    // `monotonic_nanos()` returns 0 on `clock_gettime` failure
    // (`neighbor.rs:8-10`). On failure we do NOT overwrite sidecar
    // slots with a sentinel — we return without touching any slot.
    // `record_tx_completions_with_stamp` resets each slot to
    // `TX_SIDECAR_UNSTAMPED` on reap, so a slot that skipped its
    // stamp this cycle already reads as "unstamped" at reap time and
    // the sample is correctly dropped. This removes the previous
    // in-band mapping of `ts == 0 → TX_SIDECAR_UNSTAMPED`.
    //
    // The sentinel itself stays at `u64::MAX` — a legitimate
    // monotonic timestamp cannot reach it (~585 years uptime at ns
    // granularity), so there is no value collision between a
    // genuine-but-small stamp and "unstamped".
    if ts_submit == 0 {
        return;
    }
    for offset in offsets {
        let idx = (offset >> UMEM_FRAME_SHIFT) as usize;
        // #812 Rust round-1 HIGH-1: under `shared_umem = true` (mlx5
        // special case), frames drawn from the shared pool CAN have
        // offsets whose `offset >> UMEM_FRAME_SHIFT` exceeds THIS
        // binding's `total_frames`. Silent-drop is the correct
        // behaviour: the out-of-range frame belongs to a different
        // binding's sidecar, and that binding's owner is responsible
        // for stamping its own slots. Writing into this sidecar at a
        // bounded-out-of-range index would overflow OR (after a
        // resize up) corrupt an unrelated slot — `get_mut` returns
        // None on out-of-range, which keeps the hot path sound.
        // Pinned by the `tx_latency_hist_shared_umem_oob_offset_*`
        // tests below.
        //
        // `debug_assert!` is deliberately NOT used here: tests drive
        // this path directly and we want release-parity semantics
        // (silent drop) to be the PRIMARY pin, not a test-only panic.
        if let Some(slot) = sidecar.get_mut(idx) {
            *slot = ts_submit;
        }
    }
}

/// #812 test hook / decomposition aid: the pure per-offset fold from
/// `reap_tx_completions`. Takes the sidecar slice, the list of
/// completed offsets, and an injected `ts_completion` (so tests can
/// drive deterministic deltas), plus the owner-profile atomic set.
/// Same shape the live reap path runs — batched aggregation into
/// local counters followed by at most N_buckets `fetch_add`s — so
/// unit pins here exercise the production algorithm, not a test-only
/// fake.
///
/// Returns `(count, sum_ns)` for callers that want to assert on the
/// per-batch delta directly (rather than reading back the atomics
/// afterward).
/// #825: record a single `sendto` kick-latency sample into the owner
/// atomics. Mirrors the shape of `record_tx_completions_with_stamp`
/// but without the sidecar fold (the kick site stamps the bracket
/// directly, no submit/completion indirection). Called once per TX
/// kick on the hot path from `maybe_wake_tx` after the sentinel
/// check; `#[inline]` to elide the call overhead.
///
/// Single-writer: the owner worker is the only thread that calls
/// this for a given binding. Readers (`BindingLiveState::snapshot()`)
/// see the atomics via `Relaxed`; bounded-read-skew semantics per
/// plan §4 (K_skew inherited from #812 as a conservative upper
/// bound — kicks occur strictly less frequently than completions).
#[inline]
pub(super) fn record_kick_latency(owner: &OwnerProfileOwnerWrites, delta_ns: u64) {
    let bucket = bucket_index_for_ns(delta_ns);
    owner.tx_kick_latency_hist[bucket].fetch_add(1, Ordering::Relaxed);
    owner.tx_kick_latency_count.fetch_add(1, Ordering::Relaxed);
    owner
        .tx_kick_latency_sum_ns
        .fetch_add(delta_ns, Ordering::Relaxed);
}

#[inline]
pub(super) fn record_tx_completions_with_stamp(
    sidecar: &mut [u64],
    completed_offsets: &[u64],
    ts_completion: u64,
    owner: &OwnerProfileOwnerWrites,
) -> (u64, u64) {
    let mut hist_fire_count = 0u64;
    let mut hist_fire_sum_ns = 0u64;
    let mut hist_fire_per_bucket = [0u64; TX_SUBMIT_LAT_BUCKETS];
    for &offset in completed_offsets {
        let slot_idx = (offset >> UMEM_FRAME_SHIFT) as usize;
        let ts_submit = match sidecar.get_mut(slot_idx) {
            Some(slot) => {
                let v = *slot;
                *slot = TX_SIDECAR_UNSTAMPED;
                v
            }
            None => TX_SIDECAR_UNSTAMPED,
        };
        if ts_submit != TX_SIDECAR_UNSTAMPED && ts_completion >= ts_submit {
            let delta_ns = ts_completion - ts_submit;
            let bucket = bucket_index_for_ns(delta_ns);
            hist_fire_per_bucket[bucket] = hist_fire_per_bucket[bucket].saturating_add(1);
            hist_fire_count = hist_fire_count.saturating_add(1);
            hist_fire_sum_ns = hist_fire_sum_ns.saturating_add(delta_ns);
        }
    }
    for (b, add) in hist_fire_per_bucket.iter().enumerate() {
        if *add != 0 {
            owner.tx_submit_latency_hist[b].fetch_add(*add, Ordering::Relaxed);
        }
    }
    if hist_fire_count != 0 {
        owner
            .tx_submit_latency_count
            .fetch_add(hist_fire_count, Ordering::Relaxed);
        owner
            .tx_submit_latency_sum_ns
            .fetch_add(hist_fire_sum_ns, Ordering::Relaxed);
    }
    (hist_fire_count, hist_fire_sum_ns)
}

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
    // #812: completion stamp — single fresh `monotonic_nanos()` for
    // the entire reap batch (plan §3.1 completion-ts site). Amortised
    // one VDSO call per reap (worst-case ~15 ns / TX_BATCH_SIZE-packet
    // batch = ~0.23 ns/pkt at the post-#920 batch of 64;
    // ~15 ns/pkt on the `reaped == 1` partial-batch worst case —
    // same shape as the submit-stamp cost analysis in plan §3.4).
    let ts_completion = monotonic_nanos();
    // #812: delegate the per-offset fold to the shared helper so
    // tests exercising `record_tx_completions_with_stamp` cover the
    // exact production algorithm — NOT a test-only fake. See unit
    // pins under `#[cfg(test)]` below.
    record_tx_completions_with_stamp(
        &mut binding.tx_submit_ns,
        &binding.scratch_completed_offsets,
        ts_completion,
        &binding.live.owner_profile_owner,
    );
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
            // #804: bound-pending FIFO overflow — distinct from the CoS
            // queue admission overflow counter. Keep this attribution
            // precise so operators can tell which path is dropping.
            binding.dbg_bound_pending_overflow += 1;
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
            // #804: bound-pending FIFO overflow (prepared side). Same
            // semantic bucket as `bound_pending_tx_local` — internal
            // prepared/local distinction is irrelevant to operators.
            binding.dbg_bound_pending_overflow += 1;
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
    // First ingest pass — same structure as pre-#760. Moves
    // pending_tx_local + inbox items into CoS queues where
    // possible. Items that can't be CoS-enqueued (no CoS config
    // for the egress, or cos_queue_id=None) stay in
    // pending_tx_local and flow through the backup paths below —
    // that's the expected non-CoS fast path and MUST stay fast.
    ingest_cos_pending_tx(
        binding,
        forwarding,
        now_ns,
        worker_id,
        worker_commands_by_id,
    );
    // Original #751 drain loop: service shaped queues until noop.
    // Each shaped drain attributes latency + invocations to the
    // specific queue via drain_shaped_tx's returned queue ref.
    loop {
        let start_ns = monotonic_nanos();
        let serviced = drain_shaped_tx(binding, now_ns, shared_recycles);
        if let Some(serviced) = serviced.as_ref() {
            let delta = monotonic_nanos().saturating_sub(start_ns);
            let bucket = bucket_index_for_ns(delta);
            if let Some(root) = binding.cos_interfaces.get(&serviced.root_ifindex) {
                if let Some(queue) = root.queues.get(serviced.queue_idx) {
                    if queue.queue_id == serviced.queue_id {
                        queue.owner_profile.drain_latency_hist[bucket]
                            .fetch_add(1, Ordering::Relaxed);
                        queue
                            .owner_profile
                            .drain_invocations
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            did_work = true;
        } else {
            binding
                .live
                .owner_profile_owner
                .drain_noop_invocations
                .fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
    // #760: bounded re-ingest → drain_shaped_tx loop, but ONLY
    // while the MPSC inbox has late peer arrivals AND CoS is
    // configured on some egress. For non-CoS traffic
    // (forwarding.cos.interfaces empty, or pending_tx_local
    // items all have cos_queue_id=None), the first ingest is
    // sufficient and re-ingesting does nothing useful — items
    // in pending_tx_local that Err'd out of the first pass will
    // Err the same way on every subsequent pass. The quiesce
    // guard below is inbox-only because that is the only place
    // peer workers can push new work after the first ingest.
    //
    // Perf note: without the inbox-only guard, a 25 Gbps non-CoS
    // flow burns all 4 budget iterations per drain_pending_tx
    // call because pending_tx_local never empties — observed as
    // a severe throughput regression (25 Gbps → 3 Gbps). The
    // inbox-only guard keeps the non-CoS fast path at exactly
    // the pre-#760 cost.
    if !forwarding.cos.interfaces.is_empty() {
        const REINGEST_BUDGET: usize = 4;
        for _ in 0..REINGEST_BUDGET {
            if binding.live.pending_tx_empty() {
                break;
            }
            ingest_cos_pending_tx_with_provenance(
                binding,
                forwarding,
                now_ns,
                worker_id,
                worker_commands_by_id,
                false,
            );
            let mut serviced_in_inner = false;
            loop {
                let start_ns = monotonic_nanos();
                let serviced = drain_shaped_tx(binding, now_ns, shared_recycles);
                if let Some(serviced) = serviced.as_ref() {
                    let delta = monotonic_nanos().saturating_sub(start_ns);
                    let bucket = bucket_index_for_ns(delta);
                    if let Some(root) = binding.cos_interfaces.get(&serviced.root_ifindex) {
                        if let Some(queue) = root.queues.get(serviced.queue_idx) {
                            if queue.queue_id == serviced.queue_id {
                                queue.owner_profile.drain_latency_hist[bucket]
                                    .fetch_add(1, Ordering::Relaxed);
                                queue
                                    .owner_profile
                                    .drain_invocations
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    did_work = true;
                    serviced_in_inner = true;
                } else {
                    break;
                }
            }
            if !serviced_in_inner {
                break;
            }
        }
    }
    // #760: drop CoS-bound items that reached this backup path
    // instead of transmitting them unshaped. Fast-exit when no
    // CoS is configured (no possible cos_queue_id.is_some() on
    // any item) — keeps the non-CoS hot path allocation-free.
    if !forwarding.cos.interfaces.is_empty() {
        drop_cos_bound_prepared_leftovers(binding);
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
                // #760 instrumentation: these bytes went out via
                // the post-CoS backup path in drain_pending_tx —
                // they did NOT pass through any queue's token gate.
                // Non-zero here is the direct fingerprint of the
                // cap bypass we're hunting.
                binding
                    .live
                    .owner_profile_owner
                    .post_drain_backup_bytes
                    .fetch_add(bytes, Ordering::Relaxed);
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
    // #760: drop any CoS-bound items. Fast-exit if no CoS is
    // configured at all — saves the O(n) scan + reallocation on
    // the non-CoS hot path.
    if !forwarding.cos.interfaces.is_empty() {
        drop_cos_bound_local_leftovers(binding, forwarding, now_ns, &mut pending);
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
                        // #760 instrumentation: bytes that left via
                        // the fallback transmit_batch WITHOUT going
                        // through any CoS queue's token gate. See
                        // the post_drain_backup_bytes field comment
                        // for why this is the #760 smoking gun.
                        binding
                            .live
                            .owner_profile_owner
                            .post_drain_backup_bytes
                            .fetch_add(bytes, Ordering::Relaxed);
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

/// #760: drop any prepared TX requests whose `cos_queue_id` is
/// `Some(_)` — these items should have been admitted to a CoS
/// queue via `ingest_cos_pending_tx`, and transmitting them
/// through the post-CoS backup path bypasses the shaper. The
/// UMEM frame slot each request holds is recycled immediately so
/// the free-frame allocator stays in balance. A non-zero drop
/// count here indicates a cross-worker routing failure
/// (redirect-to-owner returned Err AND local-enqueue returned
/// Err), which is the narrow failure mode the re-ingest + drop
/// pair is designed to defend against.
fn drop_cos_bound_prepared_leftovers(binding: &mut BindingWorker) {
    if binding.pending_tx_prepared.is_empty() {
        return;
    }
    // #784 Codex review: the earlier head-peek fast-exit was a
    // correctness bug. `take_pending_tx_into` / inbox drain can
    // interleave non-CoS items (head) with CoS-bound items
    // (tail). If the head is non-CoS and we return early, later
    // CoS-bound items escape to the unshaped transmit_batch
    // path, bypassing the CoS cap. Scan the full deque always.
    //
    // Scan in-place. pop_front until empty; CoS-bound items are
    // dropped (+ recycled), non-CoS items are rotated back to
    // the tail. O(n) but only runs when a leftover exists AFTER
    // the bounded ingest-drain loop exited with residue, not
    // per-frame.
    let mut dropped = 0u64;
    let mut dropped_bytes = 0u64;
    let original_len = binding.pending_tx_prepared.len();
    for _ in 0..original_len {
        let Some(req) = binding.pending_tx_prepared.pop_front() else {
            break;
        };
        if req.cos_queue_id.is_some() {
            dropped = dropped.saturating_add(1);
            dropped_bytes = dropped_bytes.saturating_add(req.len as u64);
            recycle_prepared_immediately(binding, &req);
        } else {
            binding.pending_tx_prepared.push_back(req);
        }
    }
    if dropped > 0 {
        binding
            .live
            .tx_errors
            .fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drops
            .fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drop_bytes
            .fetch_add(dropped_bytes, Ordering::Relaxed);
    }
}

/// #760: symmetric to `drop_cos_bound_prepared_leftovers` but for
/// local (non-prepared) TxRequests. `TxRequest::bytes` is a
/// Vec<u8> owned by the request — dropping the request frees the
/// buffer, so no explicit recycle is needed here.
/// #784 rewrite: give CoS-bound items one final chance to route
/// into their queue before dropping. The previous revision
/// dropped unconditionally, which was correct for items that had
/// failed ingest's full three-step cascade — BUT items pulled
/// from the MPSC redirect inbox at `take_pending_tx_requests`
/// (after the bounded ingest-drain loop exited) had never been
/// attempted for ingest at all. On iperf3 -P 12 against a 1 Gbps
/// cap with owner-local-exact queue 4, peer workers continuously
/// push packets to the owner binding's inbox. The budget-loop
/// exits while packets are still arriving; `take_pending_tx_requests`
/// then pulls them; the drop filter killed them wholesale. That
/// produced the reported bimodal fairness: flows whose packets
/// happened to land on the owner worker's own RX got through;
/// flows that crossed workers got dropped here.
///
/// The fix: attempt `enqueue_local_into_cos` here. If it succeeds,
/// the item joins its queue and traverses the normal shaped path
/// on the next drain. If it fails (the genuine cross-worker
/// routing failure case this function was originally designed for),
/// drop as before so the #760 CoS cap bypass stays closed.
/// #784 pure-function scan: for each item in `pending`, classify
/// by `cos_queue_id`. Non-CoS items are preserved (rotated back
/// to tail). CoS-bound items get one last rescue attempt via
/// `try_rescue`; if that returns Err, the item is dropped (not
/// re-enqueued) and counted. Returns `(dropped_count, dropped_bytes)`.
///
/// **CRITICAL INVARIANT** (pinned by
/// `partition_cos_bound_local_scans_mixed_head_deque` below): the
/// scan walks the ENTIRE deque, not just the head. An earlier
/// head-peek fast-exit was a correctness bug: items pulled from
/// the redirect inbox via `take_pending_tx_requests` can
/// interleave non-CoS and CoS-bound; exiting early on a non-CoS
/// head lets later CoS-bound items escape to the unshaped
/// `transmit_batch` backup path, bypassing the CoS cap.
/// Adversarial reviewers MUST reject any PR that re-introduces
/// an early-exit on head inspection.
fn partition_cos_bound_local_with_rescue<F>(
    pending: &mut VecDeque<TxRequest>,
    mut try_rescue: F,
) -> (u64, u64)
where
    F: FnMut(TxRequest) -> Result<(), TxRequest>,
{
    let mut dropped = 0u64;
    let mut dropped_bytes = 0u64;
    let original_len = pending.len();
    for _ in 0..original_len {
        let Some(req) = pending.pop_front() else { break };
        if req.cos_queue_id.is_some() {
            let bytes_len = req.bytes.len() as u64;
            match try_rescue(req) {
                Ok(()) => { /* rescued — do not drop */ }
                Err(_req) => {
                    dropped = dropped.saturating_add(1);
                    dropped_bytes = dropped_bytes.saturating_add(bytes_len);
                }
            }
        } else {
            pending.push_back(req);
        }
    }
    (dropped, dropped_bytes)
}

fn drop_cos_bound_local_leftovers(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    pending: &mut VecDeque<TxRequest>,
) {
    // Delegate the scan to the pure helper so the mixed-head
    // invariant (Codex review on #784) is unit-testable without
    // constructing a full BindingWorker.
    let (dropped, dropped_bytes) = partition_cos_bound_local_with_rescue(
        pending,
        |req| match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
            Ok(()) => Ok(()),
            Err(req) => Err(req),
        },
    );
    if dropped > 0 {
        binding
            .live
            .tx_errors
            .fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drops
            .fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drop_bytes
            .fetch_add(dropped_bytes, Ordering::Relaxed);
    }
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
    ingest_cos_pending_tx_with_provenance(
        binding,
        forwarding,
        now_ns,
        worker_id,
        worker_commands_by_id,
        true,
    );
}

/// #760: same as `ingest_cos_pending_tx` but skips the
/// `owner_pps` / `peer_pps` attribution. `drain_pending_tx` calls
/// ingest once at the top (attribution ON) and then again after
/// the shaped-drain loop exits (attribution OFF). The second pass
/// drains items that peers pushed to the MPSC inbox DURING the
/// shaped drain; counting those as `owner_pps` would corrupt the
/// provenance telemetry because items left over in
/// `pending_tx_local` from the first pass get indistinguishably
/// mixed with fresh inbox arrivals on the second pass. Per Codex
/// adversarial review (PR #773): "The second pass reclassifies
/// peer requests as owner-local; inflates owner_pps, deflates
/// peer_pps — exactly the wrong signal for diagnosing owner
/// hotspots."
fn ingest_cos_pending_tx_with_provenance(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    count_pps: bool,
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
    // #709: the split between owner-local and peer-redirected packets.
    // `pending` starts with this worker's own locally-produced requests
    // (this worker drove RX on this binding). `take_pending_tx_into`
    // then APPENDS the MPSC inbox — every item appended was pushed by
    // a peer worker that redirected a TxRequest at this binding as
    // owner. Count the split here, before
    // `process_pending_queue_in_place` mixes them with outbound
    // re-redirects.
    //
    // For non-owner bindings the MPSC inbox is empty (peers never push
    // to a binding they do not own), so `peer` naturally stays at 0.
    //
    // #760: `count_pps` is false on re-ingest passes — items already
    // in `pending_tx_local` at that point were left over from the
    // first pass (Err returns), and re-classifying them as owner-
    // local would double-count or mis-attribute them.
    let owner_local_count = pending.len() as u64;
    binding.live.take_pending_tx_into(&mut pending);
    let peer_count = (pending.len() as u64).saturating_sub(owner_local_count);
    if count_pps && owner_local_count > 0 {
        binding
            .live
            .owner_profile_owner
            .owner_pps
            .fetch_add(owner_local_count, Ordering::Relaxed);
    }
    if count_pps && peer_count > 0 {
        binding
            .live
            .owner_profile_peer
            .peer_pps
            .fetch_add(peer_count, Ordering::Relaxed);
    }
    // #780 fast path: memoize the routing decision per
    // (egress_ifindex, cos_queue_id) across the batch. iperf-style
    // workloads push ~all items in a batch to the same queue, so
    // this hits >99%. Saves 2-3 FastMap lookups per item on the
    // hot path (profile: 1.96% CPU in this function at line rate).
    //
    // Semantic correctness: this mirrors the pre-#780 cascade of
    //   Step 1: redirect_local_cos_request_to_owner
    //   Step 2: redirect_local_cos_request_to_owner_binding
    //   Step 3: enqueue_local_into_cos (Err→item stays in pending)
    // exactly. Step 1 bails (Err) on:
    //   - queue not in iface, OR
    //   - shared_exact AND tx_owner_live is Some, OR
    //   - owner_worker_id == current_worker_id
    // Step 2 (only reached when Step 1 bailed) ignores the queue
    // and checks iface-level tx_owner_live; routes if set AND not
    // ptr_eq(tx_owner_live, &binding.live).
    //
    // Codex adversarial review (PR #782 round 1) flagged that
    // collapsing both steps lost the "queue_fast=None but Step 2
    // would still route via iface" path, and the "same owner
    // worker but not owner binding" path. This rewrite evaluates
    // Step 1 and Step 2 independently on the cached lookup and
    // picks whichever routes, falling through to EnqueueLocal
    // only when both bail — matching the prior cascade.
    // Codex adversarial review (PR #782 round 2) flagged that the
    // earlier rewrite lost the cascade's failure fallthrough: when
    // Step 1's enqueue returned Err, the OLD code walked to Step 2,
    // then Step 3. The previous PR revision returned Err after the
    // first step's failure. Restore exact fallthrough semantics by
    // caching BOTH Step 1 and Step 2 options on the decision, then
    // dispatching Step 1 → Step 2 → Step 3 with failure fallthrough
    // at each boundary.
    let mut cached_key: Option<(i32, Option<u8>)> = None;
    let mut cached_decision: Option<LocalRoutingDecision> = None;
    process_pending_queue_in_place(&mut pending, |req| {
        let key = (req.egress_ifindex, req.cos_queue_id);
        if cached_key != Some(key) {
            cached_key = Some(key);
            let iface_fast_opt = binding.cos_fast_interfaces.get(&req.egress_ifindex);
            cached_decision = Some(resolve_local_routing_decision(
                iface_fast_opt,
                req.cos_queue_id,
                worker_id,
                &binding.live,
            ));
        }
        let decision = cached_decision.as_ref().expect("decision cached above");
        // Try Step 1 first (if present). `enqueue_tx_owned` does
        // not currently return Err in any observed path (see
        // umem.rs #710/#706 tests — drop-newest returns Ok), but
        // the Result signature MUST be honored for
        // cascade-equivalence.
        let req = match &decision.step1 {
            Some(Step1Action::Arc(arc)) => match arc.enqueue_tx_owned(req) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            },
            Some(Step1Action::Command(owner_worker_id)) => {
                if let Some(commands) = worker_commands_by_id.get(owner_worker_id) {
                    if let Ok(mut pending) = commands.lock() {
                        pending.push_back(WorkerCommand::EnqueueShapedLocal(req));
                        return Ok(());
                    } else {
                        // Pointer-equal poisoned mutex is
                        // unrecoverable; fall through to Step 2/3
                        // for best-effort rather than dropping.
                        // process_pending_queue_in_place will
                        // either route via Step 2 or retain in
                        // pending_tx_local for the next cycle.
                        req
                    }
                } else {
                    req
                }
            }
            None => req,
        };
        // Fallthrough to Step 2 (if present).
        let req = match &decision.step2 {
            Some(arc) => match arc.enqueue_tx_owned(req) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            },
            None => req,
        };
        // Fallthrough to Step 3 (EnqueueLocal).
        match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
            Ok(()) => Ok(()),
            Err(req) => Err(req),
        }
    });
    binding.pending_tx_local = pending;
    bound_pending_tx_local(binding);
}

/// #780: Step 1 action variants. Mirrors the action taken inside
/// `redirect_local_cos_request_to_owner` after the bail checks
/// have been passed.
#[derive(Clone)]
enum Step1Action {
    /// The owner worker's owner_live arc is directly addressable
    /// (fast path).
    Arc(Arc<BindingLiveState>),
    /// Fall back to the per-worker command channel (slow path).
    Command(u32),
}

/// #780: routing-decision cache value. Carries BOTH Step 1 and
/// Step 2 options so the dispatch in `ingest_cos_pending_tx_with_provenance`
/// can fall through Step 1 → Step 2 → Step 3 (EnqueueLocal) on
/// Err at each boundary — exact cascade semantics of the
/// pre-#780 three-function chain. Codex review round 2 flagged
/// the previous revision's lack of fallthrough as a HIGH
/// semantic regression.
#[derive(Clone)]
struct LocalRoutingDecision {
    /// `None` when Step 1 bails (queue absent, shared_exact-with-
    /// owner, or owner_worker_id == current_worker_id). Present
    /// when Step 1 would route.
    step1: Option<Step1Action>,
    /// `None` when Step 2 bails (iface absent, no tx_owner_live,
    /// or ptr_eq(tx_owner_live, current_live)). Present when
    /// Step 2 would route.
    step2: Option<Arc<BindingLiveState>>,
}

/// #780: resolve the routing decision for a (iface, queue) pair.
/// Preserves the exact pre-#780 cascade semantics. Moved out of
/// the closure so it can be unit-tested independently. Carries
/// BOTH step options in the returned decision so dispatch can
/// walk the same fallthrough as the original cascade when an
/// earlier step's enqueue returns Err.
fn resolve_local_routing_decision(
    iface_fast_opt: Option<&WorkerCoSInterfaceFastPath>,
    cos_queue_id: Option<u8>,
    current_worker_id: u32,
    current_live: &Arc<BindingLiveState>,
) -> LocalRoutingDecision {
    let mut step1: Option<Step1Action> = None;
    let mut step2: Option<Arc<BindingLiveState>> = None;
    if let Some(iface_fast) = iface_fast_opt {
        // Step 1 (mirrors redirect_local_cos_request_to_owner):
        if let Some(queue_fast) = iface_fast.queue_fast_path(cos_queue_id) {
            let step1_bail = (queue_fast.shared_exact && iface_fast.tx_owner_live.is_some())
                || queue_fast.owner_worker_id == current_worker_id;
            if !step1_bail {
                step1 = Some(match queue_fast.owner_live.as_ref() {
                    Some(arc) => Step1Action::Arc(arc.clone()),
                    None => Step1Action::Command(queue_fast.owner_worker_id),
                });
            }
        }
        // Step 2 (mirrors redirect_local_cos_request_to_owner_binding):
        // ALWAYS evaluated — the old cascade ran Step 2 after Step 1
        // returned Err, so Step 2 is reachable whether or not Step 1
        // also routes. We cache both here; the dispatch loop walks
        // Step 1 first, falling through to Step 2 on Err.
        if let Some(owner_live) = iface_fast.tx_owner_live.as_ref() {
            if !Arc::ptr_eq(owner_live, current_live) {
                step2 = Some(owner_live.clone());
            }
        }
    }
    LocalRoutingDecision { step1, step2 }
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

/// #751: one drain pass through the binding's CoS interfaces. Returns
/// the (root_ifindex, queue_idx, queue_id) that was actually serviced
/// so the caller can attribute the drain latency to the specific
/// queue's per-queue atomics without walking the queues vec a second
/// time.
///
/// `queue_idx` is the stable position within `root.queues` captured
/// at selection time. The drain path mutates queue state (tokens,
/// queued_bytes) but does not reorder or reshape `root.queues`
/// within a single drain pass, so using the idx for direct indexed
/// access is safe and avoids the O(#queues) linear scan by
/// `queue_id` that the first revision of this PR used (Copilot
/// review, tx.rs:262).
///
/// `queue_id` is retained as a stable 8-bit identifier for the
/// snapshot and telemetry paths which key on id, not idx.
pub(super) struct DrainedQueueRef {
    pub(super) root_ifindex: i32,
    pub(super) queue_idx: usize,
    pub(super) queue_id: u8,
}

fn drain_shaped_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<DrainedQueueRef> {
    if binding.cos_nonempty_interfaces == 0 || binding.cos_interface_order.is_empty() {
        return None;
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
        if let Some(serviced) = service_exact_guarantee_queue_direct_with_info(
            binding,
            root_ifindex,
            now_ns,
            shared_recycles,
        ) {
            binding.cos_interface_rr = (start + offset + 1) % binding.cos_interface_order.len();
            return serviced;
        }
        let Some(batch) = build_nonexact_cos_batch(binding, root_ifindex, now_ns) else {
            continue;
        };
        // #751: capture both queue_idx (stable Vec position) and
        // queue_id (stable u8 identifier) BEFORE submit_cos_batch
        // takes ownership of the batch. Pre-Copilot-review this
        // resolved only queue_id and the outer loop did a linear
        // scan by id; now we carry the idx through for direct
        // indexed access.
        let located = cos_batch_queue_ref(binding, root_ifindex, &batch);
        binding.cos_interface_rr = (start + offset + 1) % binding.cos_interface_order.len();
        if submit_cos_batch(binding, root_ifindex, batch, now_ns, shared_recycles) {
            return located.map(|(queue_idx, queue_id)| DrainedQueueRef {
                root_ifindex,
                queue_idx,
                queue_id,
            });
        }
        return None;
    }
    None
}

fn cos_batch_queue_ref(
    binding: &BindingWorker,
    root_ifindex: i32,
    batch: &CoSBatch,
) -> Option<(usize, u8)> {
    let queue_idx = match batch {
        CoSBatch::Local { queue_idx, .. } | CoSBatch::Prepared { queue_idx, .. } => *queue_idx,
    };
    binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| (queue_idx, queue.queue_id))
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
    service_exact_guarantee_queue_direct_with_info(
        binding,
        root_ifindex,
        now_ns,
        shared_recycles,
    )
    .map(|slot| slot.is_some())
}

/// #751: variant that additionally reports which queue was actually
/// serviced so the caller can attribute per-queue drain latency.
/// Returns:
///   * `Some(Some(ref))` — exact-guarantee selection fired, batch
///     service progressed on `ref`.
///   * `Some(None)` — exact-guarantee selection fired but the service
///     call made no progress (batch build declined / TX ring refused).
///   * `None` — no exact-guarantee selection; caller falls through
///     to the non-exact path.
fn service_exact_guarantee_queue_direct_with_info(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<Option<DrainedQueueRef>> {
    let queue_fast_path = binding
        .cos_fast_interfaces
        .get(&root_ifindex)?
        .queue_fast_path
        .as_slice();
    let selection = {
        let root = binding.cos_interfaces.get_mut(&root_ifindex)?;
        select_exact_cos_guarantee_queue_with_fast_path(root, queue_fast_path, now_ns)?
    };

    let queue_id = binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(selection.queue_idx))
        .map(|queue| queue.queue_id);

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

    Some(if progress {
        queue_id.map(|queue_id| DrainedQueueRef {
            root_ifindex,
            queue_idx: selection.queue_idx,
            queue_id,
        })
    } else {
        None
    })
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
            // #760 instrumentation: record the per-queue observation
            // that the interface shaper held it back. Written
            // regardless of whether the wakeup-tick estimator
            // succeeds in parking it, because "gate fired" is the
            // signal we care about, not "queue successfully
            // scheduled". Same Relaxed reasoning as drain_invocations.
            queue
                .owner_profile
                .drain_park_root_tokens
                .fetch_add(1, Ordering::Relaxed);
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
            // #760 instrumentation: the per-queue token gate held
            // this queue back. A queue that sustains throughput
            // above its configured rate with this counter near zero
            // is direct evidence the gate never fired.
            queue
                .owner_profile
                .drain_park_queue_tokens
                .fetch_add(1, Ordering::Relaxed);
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
    // #812 Codex round-1 HIGH #1: sample the submit stamp AFTER
    // `writer.commit()` so a scheduler preemption between `insert`
    // and the ring submit does NOT inflate the measured latency.
    // Pre-commit stamping attributed the preemption window to the
    // kernel (submit→completion), which is exactly the opposite of
    // what we want to observe. A reused caller `now_ns` would still
    // leak up to ~1 ms of worker-loop staleness, so we take a fresh
    // `monotonic_nanos()` here rather than re-using one from the
    // outer scope. Only the accepted prefix (`.take(inserted as
    // usize)`) is stamped — the retry tail returns to
    // `free_tx_frames` and MUST NOT be stamped.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_exact_local_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

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
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — see plan
    // §3.1 submit-site table (this is the
    // service_exact_local_queue_direct_flow_fair variant). Stamping
    // post-commit prevents a preemption window between `insert` and
    // ring submit from being attributed to submit→completion latency.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_local_tx
            .iter()
            .take(inserted as usize)
            .map(|(offset, _)| *offset),
        ts_submit,
    );

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
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the service_exact_prepared_queue_direct
    // variant). Post-commit stamping ensures the measurement reflects
    // the moment the ring submission actually landed in the kernel,
    // not the moment before a potential preemption window.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_exact_prepared_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

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
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the
    // service_exact_prepared_queue_direct_flow_fair variant). See the
    // exact_local variant above for the preemption-window rationale.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_prepared_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

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
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // clear the pop-snapshot stack at batch start. The bound
    // "at most TX_BATCH_SIZE snapshots live at once" (see
    // `CoSQueueRuntime::pop_snapshot_stack` doc) relies on each
    // batch drain starting from an empty stack; committed
    // submissions leave stale snapshots until some later event
    // (push_back or another rollback) happens to clear them.
    // Without this clear, drain-all teardown paths and
    // successful-commit chains can grow the stack unbounded.
    queue.pop_snapshot_stack.clear();
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
            // #913: clean up the orphan snapshot for this dropped
            // item. The matching pop pushed a snapshot; on Drop
            // we abandon the item, so the snapshot would
            // otherwise sit at the top of the stack and trip a
            // bucket-mismatch panic when the subsequent
            // restore_front push_fronts a different surviving
            // item. Codex code review (HIGH): also clamp
            // remaining snapshots' pre_pop_queue_vtime so
            // survivor restores preserve this dropped item's
            // committed vtime advance — see helper docstring.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
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
            // #913: same orphan-snapshot cleanup as above (slice
            // failure path).
            cos_queue_clear_orphan_snapshot_after_drop(queue);
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
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // clear the pop-snapshot stack at batch start. See the
    // matching comment in `drain_exact_local_items_to_scratch_flow_fair`
    // for the rationale — committed-submit chains or drain-all
    // teardowns can otherwise leave stale snapshots that violate
    // the documented TX_BATCH_SIZE bound.
    queue.pop_snapshot_stack.clear();
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
            // #913: orphan snapshot cleanup with vtime preservation.
            // See helper docstring; same as local-builder
            // capacity-fail site.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
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
            // #913: orphan snapshot cleanup with vtime preservation
            // (slice failure path). See helper docstring.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
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
            // #760 instrumentation: record the exact-owner-local
            // send at the same place the token bucket decrements.
            // Divide by a scrape window to get an observed per-queue
            // drain rate and compare against
            // `queue.transmit_rate_bytes` to detect a cap bypass.
            queue
                .owner_profile
                .drain_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
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
        // #760 instrumentation, exact-owner-local path. Paired with
        // tx_bytes unconditionally — if the per-queue drain_sent_bytes
        // above (guarded by `if let Some(queue)`) ever undercounts
        // this, the gap is an `apply_*` early-return / queue-miss.
        binding
            .live
            .owner_profile_owner
            .drain_sent_bytes_shaped_unconditional
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
                        // #760 instrumentation, non-exact / shared-exact
                        // Local path. See umem.rs field comment.
                        binding
                            .live
                            .owner_profile_owner
                            .drain_sent_bytes_shaped_unconditional
                            .fetch_add(bytes, Ordering::Relaxed);
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
                        // #760 instrumentation, Prepared path (the
                        // in-place-rewrite hot path). See umem.rs
                        // field comment.
                        binding
                            .live
                            .owner_profile_owner
                            .drain_sent_bytes_shaped_unconditional
                            .fetch_add(bytes, Ordering::Relaxed);
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

/// Hard upper bound on per-flow fair queue residence time. Without
/// this, `cos_flow_aware_buffer_limit` can scale the aggregate cap
/// to `COS_FLOW_FAIR_BUCKETS × COS_FLOW_FAIR_MIN_SHARE_BYTES`
/// (~24 MB at max), which on a 1 Gbps queue is ~190 ms of queueing
/// — far outside the scheduler's predictable regime. 5 ms is ~5×
/// BDP at 1 Gbps cluster RTT and keeps the tail bounded while
/// leaving generous room for bulk TCP. Tracked in #717.
const COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS: u64 = 5_000_000;

// Compile-time sanity: must be at least 1 ms. Below that TCP has
// no room to grow cwnd past a handful of packets.
const _: () = assert!(COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS >= 1_000_000);
const COS_SURPLUS_ROUND_QUANTUM_BYTES: u64 = 1500;
const COS_TIMER_WHEEL_L0_HORIZON_TICKS: u64 = COS_TIMER_WHEEL_L0_SLOTS as u64;

/// ECN CE-marking threshold as a fraction of the relevant cap.
/// Applied to both the aggregate `buffer_limit` and the per-flow
/// `share_cap` in `apply_cos_admission_ecn_policy`.
///
/// History:
///   1/2 (initial) — marks never fired under the 16-flow / 1 Gbps
///     workload; per-flow buckets averaged ~36% of share_cap.
///   1/5 (#728)    — one-order-of-magnitude earlier marking to give
///     ECN-negotiated TCP room to halve cwnd smoothly.
///   1/3 (#754)    — 1/5 over-marked on a single-flow / low-rate
///     exact queue. Live trace on loss:xpf-userspace-fw0:
///       * 1 Gbps queue: 971K ECN marks vs. 1766 flow_share drops
///       * single iperf3 -P 1 -t 30: bimodal 1.44 Gbps spikes and
///         hard stalls to 0 bps, 78K retrans, avg 820 Mbps
///     Raising to 1/3 backs the marker off to 33% of share_cap so
///     TCP cubic has more headroom before mark pressure collapses
///     cwnd. Still fires before hard-drop, still lets ECN do its
///     job on elephant flows.
///
/// This is a tuning knob against live counter telemetry, not a
/// first-principles derivation. If `admission_ecn_marked` stays
/// pathologically low under load despite ECT traffic, lower further;
/// if marks fire so often that throughput drops (ECN double-backoff),
/// raise. Observe via `show class-of-service interface`. Longer-term
/// a rate-aware threshold (#747) replaces this single ratio with a
/// signal that scales with configured drain rate rather than buffer
/// depth alone.
const COS_ECN_MARK_THRESHOLD_NUM: u64 = 1;
const COS_ECN_MARK_THRESHOLD_DEN: u64 = 3;

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

/// Size of a bare Ethernet header (6 dst MAC + 6 src MAC + 2 ethertype).
const ETH_HDR_LEN: usize = 14;
/// Size of a single 802.1Q / 802.1ad VLAN tag (TPID + TCI).
const VLAN_TAG_LEN: usize = 4;

/// Parsed L3 discriminator + offset from a forwarded Ethernet frame.
/// Carries both pieces together so the ECN mark path dispatches off the
/// bytes it actually parsed, not the `expected_addr_family` sideband —
/// a malformed frame whose sideband says AF_INET but whose ethertype
/// says something else must not get its "TOS byte" stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EthernetL3 {
    Ipv4(usize),
    Ipv6(usize),
}

/// Parse the outer Ethernet header, transparently walk a single 802.1Q
/// / 802.1ad VLAN tag, and report the L3 family + header offset. The
/// CoS admission path sees frames post-forward-build, so VLAN tags
/// from tagged subinterfaces (e.g. `reth0 unit 80`) are already
/// present. Callers use the returned family to dispatch to the
/// matching ECN marker and the offset to locate the TOS / tclass byte.
///
/// Returns `None` for:
/// - buffers shorter than the parse requires (no slice-out-of-bounds
///   panic on the hot path),
/// - non-IP ethertypes (including ARP, MPLS, and the tail of a QinQ
///   stack) — we refuse to guess rather than stamp a byte that is not
///   a TOS / tclass byte,
/// - nested VLAN tags (QinQ / 802.1ad-over-Q) — not implemented yet;
///   adding support means one more 4-byte hop plus recursive inner-
///   ethertype inspection. The single-tag path covers the only lab
///   fixture we currently exercise.
///
/// Historically this helper just returned an offset, and dispatch was
/// based on `expected_addr_family`. The gap that exposed was: if the
/// sideband said AF_INET but the frame was ARP-inside-VLAN, we would
/// still compute offset = 18 and stamp byte 19 inside the ARP body.
/// Returning the parsed family here closes that drift permanently —
/// the marker cannot disagree with the wire bytes it is mutating.
#[inline]
fn ethernet_l3(bytes: &[u8]) -> Option<EthernetL3> {
    if bytes.len() < ETH_HDR_LEN {
        return None;
    }
    let outer = u16::from_be_bytes([bytes[12], bytes[13]]);
    match outer {
        0x0800 => Some(EthernetL3::Ipv4(ETH_HDR_LEN)),
        0x86DD => Some(EthernetL3::Ipv6(ETH_HDR_LEN)),
        // 802.1Q / 802.1ad single VLAN tag. The inner ethertype lives
        // 4 bytes after the outer one; if that inner ethertype is
        // *itself* a VLAN TPID we have a QinQ stack that we do not
        // support yet — reject it rather than stamping into an inner
        // tag.
        0x8100 | 0x88A8 => {
            let inner_off = ETH_HDR_LEN + VLAN_TAG_LEN;
            if bytes.len() < inner_off + 2 {
                return None;
            }
            let inner = u16::from_be_bytes([bytes[inner_off - 2], bytes[inner_off - 1]]);
            match inner {
                0x0800 => Some(EthernetL3::Ipv4(inner_off)),
                0x86DD => Some(EthernetL3::Ipv6(inner_off)),
                // QinQ or unknown inner — refuse to guess.
                _ => None,
            }
        }
        _ => None,
    }
}

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
    // Dispatch off the parsed Ethernet header, not the sideband
    // `expected_addr_family`. The sideband is populated at RX time and
    // can drift for injected or re-queued frames whose wire bytes got
    // rewritten (e.g. NAT64, tunnel transit). Trusting the parse keeps
    // the marker from stamping the wrong protocol body on any frame
    // where the two disagree.
    match ethernet_l3(&req.bytes) {
        Some(EthernetL3::Ipv4(l3_offset)) => mark_ecn_ce_ipv4(&mut req.bytes, l3_offset),
        Some(EthernetL3::Ipv6(l3_offset)) => mark_ecn_ce_ipv6(&mut req.bytes, l3_offset),
        None => false,
    }
}

/// Mark a prepared (zero-copy) TX frame as ECN CE in place inside the
/// UMEM. Only fires on ECT(0)/ECT(1) per RFC 3168 §6.1.1.1. Returns
/// true iff the packet was marked. Out-of-range offset/len pairs
/// (e.g. a PreparedTxRequest that somehow escaped bounds checks)
/// return false without panicking — the caller falls through into
/// the existing admission path unchanged.
///
/// This is the Prepared-variant counterpart to `maybe_mark_ecn_ce`;
/// #718 / #722 originally only handled the Local variant, leaving
/// the XSK-RX→XSK-TX zero-copy hot path (iperf3, NAT'd flows) with
/// the marker dormant. See `docs/cos-validation-notes.md` for the
/// counter-reading methodology.
///
/// # Safety
///
/// The caller must hold exclusive access to the frame at
/// `[req.offset, req.offset + req.len)` within `umem`. On the CoS
/// admission path this is guaranteed: admission runs *before* the
/// frame is enqueued into the CoS queue, let alone submitted to the
/// XSK TX ring, so the worker that built the frame is still the sole
/// owner. Callers that invoke this outside of the admission gate
/// must provide the same guarantee.
#[inline]
fn maybe_mark_ecn_ce_prepared(req: &PreparedTxRequest, umem: &MmapArea) -> bool {
    let offset = req.offset as usize;
    let len = req.len as usize;
    // SAFETY: see function-level doc. The admission path owns the
    // frame until `cos_queue_push_back` takes it, which is strictly
    // after this call. Out-of-range slices return None (handled
    // below) rather than producing a dangling reference.
    let Some(bytes) = (unsafe { umem.slice_mut_unchecked(offset, len) }) else {
        return false;
    };
    // Same rationale as `maybe_mark_ecn_ce`: dispatch off the parsed
    // wire bytes, not `expected_addr_family`. See that helper's
    // comment for the drift scenarios this protects against.
    match ethernet_l3(bytes) {
        Some(EthernetL3::Ipv4(l3_offset)) => mark_ecn_ce_ipv4(bytes, l3_offset),
        Some(EthernetL3::Ipv6(l3_offset)) => mark_ecn_ce_ipv6(bytes, l3_offset),
        None => false,
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
///
/// Two thresholds fire the mark, whichever trips first:
///
///   * **Aggregate**: `queue.queued_bytes > buffer_limit × NUM/DEN`.
///     This is the #718 arm — it signals congestion once the entire
///     queue is past the mark fraction of its operator-configured
///     buffer, independent of per-flow accounting.
///   * **Per-flow**: `queue.flow_bucket_bytes[flow_bucket] >
///     share_cap × NUM/DEN`, where `share_cap` is the current
///     per-flow cap from `cos_queue_flow_share_limit`. This is the
///     #722 arm. On the 16-flow / 1 Gbps exact-queue live workload
///     the aggregate queue sat at ~31% utilisation — the #718 50%
///     threshold never tripped — while per-flow buckets routinely
///     hit the 24 KB share cap and drops fired via
///     `flow_share_exceeded`. Marking off the per-flow bucket lets
///     ECN-negotiated TCP halve cwnd via ECE before the per-flow
///     cap trips the drop.
///
/// Both arms use the same `NUM/DEN` fraction. If an operator wants
/// the fraction tuned it must move in lockstep across both arms —
/// see the `admission_ecn_per_flow_threshold_matches_share_cap_denominator`
/// test for the regression pin.
///
/// Non-flow-fair queues degenerate safely:
/// `cos_queue_flow_share_limit` returns `buffer_limit` unchanged when
/// `queue.flow_fair` is false, so the per-flow threshold collapses
/// onto the aggregate one. No behaviour change on best-effort or
/// pure-rate-limited queues.
#[inline]
fn apply_cos_admission_ecn_policy(
    queue: &mut CoSQueueRuntime,
    buffer_limit: u64,
    flow_bucket: usize,
    flow_share_exceeded: bool,
    buffer_exceeded: bool,
    item: &mut CoSPendingTxItem,
    umem: &MmapArea,
) -> bool {
    // #784: ECN mark policy differs by queue kind:
    //
    // - **Flow-fair queues** (SFQ active): mark ONLY on the
    //   per-flow threshold. An aggregate-queue mark penalises
    //   every flow that happens to enqueue during a
    //   high-aggregate window — regardless of whether THAT flow
    //   is contributing to the congestion. With N flows actively
    //   sharing a queue at its rate cap, the aggregate sits above
    //   1/3 the buffer almost permanently, so the aggregate clause
    //   used to mark effectively every packet. The per-flow cwnd
    //   collapse from the marks concentrated on flows that hadn't
    //   yet filled their bucket (because their current cwnd was
    //   smaller) — a positive feedback loop producing the observed
    //   3-winner / 9-loser bimodal rate distribution on
    //   iperf3 -P 12 to a 1 Gbps cap.
    //
    // - **Non-flow-fair queues**: the aggregate IS the right
    //   signal — there's no per-flow isolation, so aggregate
    //   saturation is the only congestion indicator available.
    //
    // Adversarial review posture (required by campaign #775 /
    // issue #784): if the flow_fair branch ever grows back to
    // include the aggregate queued_bytes check, the fairness
    // regression observed in #784 (iperf3 -P 12 returning 3
    // flows at 145 Mbps with 0 retrans and 9 flows at 50-75 Mbps
    // with thousands of retrans) WILL come back.
    //
    // #722: per-flow threshold derived from the same share cap
    // the admission gate uses. `cos_queue_flow_share_limit` is
    // pure and inlined: ~5 ns on the legacy owner-local path
    // (saturating_add + max + div_ceil + clamp); ~8 ns on the
    // post-#914 shared_exact path (adds one division + multiply
    // for `bdp_floor_bytes`).
    let aggregate_ecn_threshold = buffer_limit
        .saturating_mul(COS_ECN_MARK_THRESHOLD_NUM)
        / COS_ECN_MARK_THRESHOLD_DEN.max(1);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, flow_bucket);
    let flow_ecn_threshold = share_cap
        .saturating_mul(COS_ECN_MARK_THRESHOLD_NUM)
        / COS_ECN_MARK_THRESHOLD_DEN.max(1);

    let flow_above = queue.flow_bucket_bytes[flow_bucket] > flow_ecn_threshold;
    let aggregate_above = queue.queued_bytes > aggregate_ecn_threshold;
    // Three classes:
    //   * flow_fair && !shared_exact — owner-local-exact (#784).
    //     Per-flow arm only; #784's fairness fix on 1 Gbps iperf-a
    //     depends on NOT marking on aggregate.
    //   * flow_fair && shared_exact — high-rate shared_exact
    //     (#785 Phase 3). Aggregate arm only; per-flow fairness is
    //     enforced by MQFQ virtual-finish-time ordering in the
    //     dequeue path, and per-flow ECN on top of that would
    //     double-signal on the same flow (MQFQ already depthens
    //     throttled flows' drain position; marking them too would
    //     collapse their cwnd twice).
    //   * !flow_fair — legacy best-effort / rate-limited queues.
    //     Aggregate arm; there is no per-flow accounting on that
    //     path.
    let should_mark = if queue.flow_fair && !queue.shared_exact {
        flow_above
    } else {
        aggregate_above
    };

    if !should_mark || flow_share_exceeded || buffer_exceeded {
        return false;
    }
    // Both variants share a single `admission_ecn_marked` counter: the
    // CoS counter surfaced in `show class-of-service interface` tracks
    // how often the admission policy marked a packet, independent of
    // whether that packet is Local-owned bytes or a zero-copy UMEM
    // frame. Split subcounters can be introduced later if operators
    // ask for Local-vs-Prepared attribution.
    let marked = match item {
        CoSPendingTxItem::Local(req) => maybe_mark_ecn_ce(req),
        CoSPendingTxItem::Prepared(req) => maybe_mark_ecn_ce_prepared(req, umem),
    };
    if marked {
        queue.drop_counters.admission_ecn_marked = queue
            .drop_counters
            .admission_ecn_marked
            .wrapping_add(1);
    }
    marked
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
    // Production invariant (#785 Copilot review): never return 0.
    // Zero is a valid getrandom output (probability 2^-64 per call,
    // but across a fleet of daemons × per-binding promotions it DOES
    // occur), and a zero seed turns the SFQ hash mapping into a pure
    // function of the 5-tuple — externally probeable, and identical
    // across all bindings on all nodes, which collapses SFQ bucket
    // diversity to zero. The `assert_ne!(flow_hash_seed, 0)` test
    // downstream depends on this invariant and would otherwise be
    // theoretically flaky. One in 2^64 getrandom reads gets OR'd
    // with 1 — indistinguishable from the raw entropy for any
    // downstream use.
    let nonzero = |v: u64| if v == 0 { 1 } else { v };
    if filled == buf.len() {
        return nonzero(u64::from_ne_bytes(buf));
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
    nonzero(fallback)
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

/// Per-flow BDP-equivalent floor used by `cos_queue_flow_share_limit`
/// on `shared_exact` queues (#914). Computed against the cluster's
/// post-shaper RTT envelope; intentionally larger than the
/// `cos_flow_aware_buffer_limit`'s 5 ms `delay_cap` because they
/// serve different purposes — the aggregate buffer ceiling targets
/// queue-residence latency, the per-flow floor targets TCP cwnd
/// build-up at queue rate. Project memory: cluster RTT 5-7 ms
/// post-shaper; 10 ms gives ~1.5× headroom.
const RTT_TARGET_NS: u64 = 10_000_000;

/// Burst headroom multiplier applied to the per-flow `fair_share`
/// inside `cos_queue_flow_share_limit` for shared_exact queues. Set
/// to 2 to admit short bursts up to 2× the steady-state per-flow
/// allocation without tail-drops. Only binding in the moderate-N
/// regime where it exceeds `bdp_floor` and is below `buffer_limit`;
/// at high N `bdp_floor` dominates and at low N `buffer_limit` clamps.
const SHARED_EXACT_BURST_HEADROOM: u64 = 2;

/// Per-flow BDP at the queue's rate divided across `active_flows`.
/// Used as a floor in the shared_exact rate-aware cap — TCP cwnd
/// must reach approximately one BDP for the per-flow rate to fit
/// the queue's transmit rate without tail-drops.
///
/// Truncation: result truncates to 0 when `per_flow_rate <
/// 1e9 / RTT_TARGET_NS = 100 bytes/sec`. At cluster-scale rates
/// (≥ 1 Gbps queues with ≤ 1024 flows → ≥ 122 KB/s/flow) this is
/// far from the truncation floor. On user-configured low-rate
/// queues (e.g., 64 kbps WAN class with 100+ flows) the BDP floor
/// silently degenerates to 0 and the `MIN_SHARE` (24 KB) clamp
/// becomes the effective floor. Acceptable because the MIN_SHARE
/// floor still keeps TCP recoverable via fast-retransmit.
#[inline]
fn bdp_floor_bytes(transmit_rate_bytes: u64, active_flows: u64) -> u64 {
    let per_flow_rate = transmit_rate_bytes / active_flows.max(1);
    per_flow_rate.saturating_mul(RTT_TARGET_NS) / 1_000_000_000
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
    // #914 (post-#785 Phase 3): shared_exact queues now enforce a
    // RATE-AWARE per-flow cap rather than passing through buffer_limit
    // unchanged. The previous unconditional return was correct as far
    // as it preserved TCP cwnd build-up (Attempt A had regressed
    // 22.3 → 16.3 Gbps + 25k retrans because the rate-unaware
    // `COS_FLOW_FAIR_MIN_SHARE_BYTES` floor of 24 KB was used as the
    // cap), but it allowed a single elephant to occupy the entire
    // queue buffer, starving mice in the same shared_exact class.
    //
    // The new cap = `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`:
    //
    //   - `fair_share*2` = aggregate buffer split N ways with 2×
    //     headroom for transient bursts.
    //   - `bdp_floor` = per-flow BDP at queue rate / N flows; ensures
    //     TCP cwnd can build to one BDP without tail-drops.
    //   - Clamped above by `buffer_limit` so the per-flow allocation
    //     never exceeds the aggregate; clamped below by MIN_SHARE
    //     (24 KB) for the existing guarantee.
    //
    // Behavior at low N (where bdp_floor > buffer_limit): the cap
    // clamps to buffer_limit, i.e. the formula degenerates to today's
    // behavior. This is intentional — at low N the buffer_limit
    // ceiling is the binding constraint anyway, and forcing a tighter
    // cap would regress TCP cwnd. The cap actively splits the buffer
    // only at moderate-to-high N (around N ≈ 23 flows on a 10 G
    // shared_exact queue).
    //
    // Owner-local-exact queues (low-rate, #784 workload) keep the
    // legacy aggregate/N share cap — at 1 Gbps / 12 flows the
    // 24 KB MIN floor matches TCP cwnd at 77 Mbps/flow.
    if queue.shared_exact {
        let prospective = cos_queue_prospective_active_flows(queue, flow_bucket);
        // Copilot C.2: use `div_ceil` to match the legacy owner-local
        // path below. Truncating division systematically undersizes
        // the per-flow cap by up to (prospective - 1) bytes when
        // `buffer_limit` is not divisible by `prospective`, increasing
        // boundary-condition tail-drops. The legacy path picked
        // div_ceil for that reason; shared_exact should follow.
        let fair_share = buffer_limit.div_ceil(prospective.max(1));
        let bdp = bdp_floor_bytes(queue.transmit_rate_bytes, prospective);
        return fair_share
            .saturating_mul(SHARED_EXACT_BURST_HEADROOM)
            .max(bdp)
            .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit);
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
/// fills it.
///
/// #717 latency-envelope clamp: the flow-aware expansion is bounded
/// on the high side by `delay_cap = transmit_rate_bytes ×
/// COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS / 1e9`, i.e. the number of bytes
/// the queue can drain in the max tolerated residence time. Without
/// this, at 1024 active buckets the cap reaches ~24 MB, which on a
/// 1 Gbps queue is ~190 ms of queueing — far outside the scheduler's
/// predictable regime. The clamp is applied as
/// `.min(delay_cap.max(base))`: it never shrinks below the operator's
/// explicit `buffer-size`, so an operator who asked for a deeper
/// buffer still gets it. Adds one u128 multiply + divide per admission
/// decision, not per packet.
#[inline]
fn cos_flow_aware_buffer_limit(queue: &CoSQueueRuntime, flow_bucket: usize) -> u64 {
    let base = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    if !queue.flow_fair {
        return base;
    }
    let prospective_active = cos_queue_prospective_active_flows(queue, flow_bucket);
    // u128 to keep the intermediate product safe at 10 Gbps × 5 ms
    // (plus any plausible operator-configured rate inflation).
    let delay_cap = ((queue.transmit_rate_bytes as u128)
        * (COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS as u128)
        / 1_000_000_000u128) as u64;
    base.max(prospective_active.saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES))
        .min(delay_cap.max(base))
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
        // #784 diagnostic: track the peak distinct-flow count.
        // Operators can compare this to the test's -P N count to
        // detect SFQ hash collisions under real workloads.
        if queue.active_flow_buckets > queue.active_flow_buckets_peak {
            queue.active_flow_buckets_peak = queue.active_flow_buckets;
        }
    }
    let was_idle = queue.flow_bucket_bytes[bucket] == 0;
    queue.flow_bucket_bytes[bucket] = queue.flow_bucket_bytes[bucket].saturating_add(item_len);
    // #785 Phase 3 — MQFQ head/tail finish-time update.
    //
    // When the bucket was idle before this enqueue, the HEAD
    // packet is THIS one, so both head and tail advance to
    // `max(tail, queue.vtime) + bytes` — the `max` re-anchors
    // the bucket at the current frontier (otherwise an idle bucket
    // with tail=0 would sweep past all established flows in one
    // bounded round, starving them).
    //
    // When the bucket was already active, this packet arrives at
    // the TAIL of the bucket queue — advance only the tail. The
    // head packet (and therefore head-finish) is unchanged because
    // the drain-order key for this bucket is still the previously-
    // queued packets. The new packet's finish is implicit: tail.
    //
    // Codex adversarial review flagged the original single-counter
    // design as HIGH severity: keying selection off tail-finish
    // rather than head-finish collapsed MQFQ to packet-count
    // fairness for equal-byte flows (A,A,B,B bursts instead of
    // A,B,A,B interleave).
    let new_tail = queue.flow_bucket_tail_finish_bytes[bucket]
        .max(queue.queue_vtime)
        .saturating_add(item_len);
    queue.flow_bucket_tail_finish_bytes[bucket] = new_tail;
    if was_idle {
        queue.flow_bucket_head_finish_bytes[bucket] = new_tail;
    }
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
        // #785 Phase 3 — MQFQ bucket-idle reset. When a bucket
        // drains to 0 its head/tail finish-times are stale
        // (they point at the virtual time when the LAST packet
        // finished, not the current frontier). Without reset, a
        // bucket that comes back active later would skip ahead
        // of the enqueue-side `max(tail, vtime)` anchor and starve
        // established buckets until its stale tail converges with
        // vtime. Reset both head and tail to 0 so the next
        // enqueue re-anchors at the live `queue.vtime`.
        queue.flow_bucket_head_finish_bytes[bucket] = 0;
        queue.flow_bucket_tail_finish_bytes[bucket] = 0;
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

/// #785 Phase 3 — find the flow bucket whose HEAD packet has the
/// smallest MQFQ virtual-finish-time among the currently active
/// set. The head-packet's finish (not the tail) is the correct
/// selection key: drains pop from the head, so that's the packet
/// whose ordering actually matters.
///
/// Linear scan over the active ring. Size bound: `active_flow_buckets
/// <= COS_FLOW_FAIR_BUCKETS = 1024`, typical workloads 2-16. At 12
/// active buckets this is 12 × (u64 load + compare) ≈ 20 ns — well
/// below NAPI batch pacing.
///
/// If we ever profile this as hot (e.g. with thousands of active
/// flows on a single queue), the replacement is a min-heap keyed by
/// `flow_bucket_head_finish_bytes`. For iperf3-sized workloads the
/// linear scan is cache-friendlier and simpler.
#[inline]
fn cos_queue_min_finish_bucket(queue: &CoSQueueRuntime) -> Option<u16> {
    let mut best: Option<u16> = None;
    let mut best_finish = u64::MAX;
    for bucket in queue.flow_rr_buckets.iter() {
        let finish = queue.flow_bucket_head_finish_bytes[usize::from(bucket)];
        if finish < best_finish {
            best_finish = finish;
            best = Some(bucket);
        }
    }
    best
}

#[inline]
pub(super) fn cos_queue_front(queue: &CoSQueueRuntime) -> Option<&CoSPendingTxItem> {
    if !queue.flow_fair {
        return queue.items.front();
    }
    // #785 Phase 3 — MQFQ: return the head of the bucket with the
    // smallest virtual-finish-time, not the DRR-rotation head. This
    // is the byte-rate-fair dequeue order (classical SFQ / WFQ).
    let bucket = usize::from(cos_queue_min_finish_bucket(queue)?);
    queue.flow_bucket_items[bucket].front()
}

#[inline]
pub(super) fn cos_queue_push_back(queue: &mut CoSQueueRuntime, item: CoSPendingTxItem) {
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    // #774: maintain local_item_count alongside the queue pushes
    // so cos_queue_accepts_prepared becomes O(1). `matches!` on a
    // tagged enum is a single branch; far cheaper than an O(n)
    // scan at check time.
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.local_item_count = queue.local_item_count.saturating_add(1);
    }
    // #785 Phase 3 — Codex round-3 HIGH + NEW-1: any push_back
    // invalidates every outstanding pop snapshot. A subsequent
    // push_front must re-anchor fresh rather than restoring
    // pre-pop head/tail of a bucket whose state has since changed
    // underneath us. Cleared in bulk (not per-bucket) because the
    // cost of a tiny Vec::clear is ~zero and the safety contract is
    // simpler: after any new enqueue, no rollback can use ANY
    // snapshot captured before it.
    queue.pop_snapshot_stack.clear();
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
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.local_item_count = queue.local_item_count.saturating_add(1);
    }
    if !queue.flow_fair {
        account_cos_queue_flow_enqueue(queue, flow_key, item_len);
        queue.items.push_front(item);
        return;
    }
    let bucket = cos_flow_bucket_index(queue.flow_hash_seed, flow_key);
    // #913: peek-then-pop snapshot consumption.
    //
    // Three states:
    //   1. Empty stack: legitimate (drain_all cleared it; or
    //      fresh-flow / non-Phase-3 caller). Aggregate-bytes
    //      rewind path — `vtime -= item_len` pairs with the
    //      no-snapshot pop's `vtime += bytes` for round-trip
    //      neutrality (see plan §3.7 walkthrough for
    //      drain_all→restore_front).
    //   2. Top entry's bucket matches: hot-path matched
    //      rollback. Pop and restore vtime + head/tail
    //      from snapshot (closes #913 max-based advance).
    //   3. Top entry's bucket DOES NOT match: hard contract
    //      violation. With §3.4's scratch-builder orphan
    //      cleanup in place, this is believed unreachable in
    //      current code. `assert!(false)` panics in BOTH dev
    //      and release.
    //
    //      No supervisor in this PR (#913 R4 revert): the
    //      panic propagates to the default Rust panic
    //      handler, which emits the panic message to stderr
    //      → journald and kills the worker thread. The
    //      helper process keeps running with one fewer
    //      worker; bindings served by that worker stall
    //      until the daemon is restarted via config change
    //      or operator intervention. SAME blast radius as
    //      every existing `unwrap`/`expect`/`panic!` site
    //      in `worker_loop` — #913 introduces zero
    //      incremental panic risk. Cross-cutting panic
    //      supervision (catch_unwind on helper side +
    //      parent-side restart in xpfd) tracked in #925.
    let stack_top_bucket = queue
        .pop_snapshot_stack
        .last()
        .map(|s| usize::from(s.bucket));
    let snapshot = match stack_top_bucket {
        None => None,
        Some(top) if top == bucket => queue.pop_snapshot_stack.pop(),
        Some(top) => {
            assert!(
                false,
                "pop_snapshot_stack bucket mismatch on push_front: \
                 top entry's bucket {} != target bucket {}; a \
                 caller pop+dropped an item without §3.4 cleanup, \
                 or violated the pop→push_front-same-item contract",
                top, bucket,
            );
            unreachable!()
        }
    };

    // #913: vtime restore — symmetric inverse of the §3.1 advance.
    // Matched-snapshot path: restore from snapshot for both the
    // was_empty (drained-bucket) and active-bucket branches.
    // Empty-stack path: legacy aggregate-bytes rewind paired with
    // the no-snapshot pop's `vtime += bytes`.
    match snapshot.as_ref() {
        Some(snap) => {
            queue.queue_vtime = snap.pre_pop_queue_vtime;
        }
        None => {
            queue.queue_vtime = queue.queue_vtime.saturating_sub(item_len);
        }
    }

    let was_empty = queue.flow_bucket_items[bucket].is_empty();
    if was_empty {
        // Bucket was drained by the matching pop. Snapshot (if
        // present) holds the exact pre-pop head/tail so we can
        // restore them.
        if let Some(snap) = snapshot {
            queue.flow_bucket_bytes[bucket] =
                queue.flow_bucket_bytes[bucket].saturating_add(item_len);
            queue.flow_bucket_head_finish_bytes[bucket] = snap.pre_pop_head_finish;
            queue.flow_bucket_tail_finish_bytes[bucket] = snap.pre_pop_tail_finish;
            queue.active_flow_buckets = queue.active_flow_buckets.saturating_add(1);
            if queue.active_flow_buckets > queue.active_flow_buckets_peak {
                queue.active_flow_buckets_peak = queue.active_flow_buckets;
            }
            queue.flow_bucket_items[bucket].push_front(item);
            queue.flow_rr_buckets.push_front(bucket as u16);
            return;
        }
        // No snapshot — drain_all/restore_front path or fresh-flow
        // caller. Standard idle-bucket re-anchor.
        // The aggregate-bytes vtime rewind above leaves vtime
        // correctly positioned for `max(tail, vtime) + bytes`
        // (see plan §3.7 walkthrough for the drain_all case).
        account_cos_queue_flow_enqueue(queue, flow_key, item_len);
        queue.flow_bucket_items[bucket].push_front(item);
        queue.flow_rr_buckets.push_front(bucket as u16);
        return;
    }
    // #785 Phase 3 — MQFQ push_front onto an ACTIVE bucket.
    //
    // Codex adversarial review (round-2) flagged this path as HIGH:
    // the prior revision funnelled through
    // `account_cos_queue_flow_enqueue`, which only advances `tail`
    // on an active bucket — head stayed stale at a value keyed off
    // whatever was the HEAD packet before this push_front.
    // Selection would then pick the bucket based on the STALE head
    // finish (stale because the item-queue front changed), and the
    // subsequent non-drain pop would `head += bytes(next_head)`
    // off the stale base, producing arbitrary finish values.
    //
    // Fix: push_front is only called from TX-ring-full restoration
    // paths where an item was JUST popped from this same bucket.
    // We reverse that pop's head-advance: at pop time we computed
    // `head += bytes(what_is_now_front)`. At push_front time we
    // subtract the SAME quantity to get back to the pop-time head
    // (which was the popped item's finish). The restored item
    // takes over as the new head and inherits that finish — which
    // is exactly what it had before the pop. Net effect: the
    // pop-and-restore round-trip is finish-time neutral, which is
    // what correctness on the error-retry path demands.
    //
    // #913: vtime is already restored above (snapshot path or
    // aggregate-bytes path). The active-bucket head reversal
    // here is unchanged from pre-#913 — `head -= bytes(current_head)`
    // is correct under MQFQ "drops consume virtual service"
    // semantics. Reasoning:
    //
    // - Single-pop case: push_front is the exact inverse of the
    //   most recent pop. head was advanced by bytes(current_head);
    //   subtracting reverses it.
    // - Multi-pop case with mid-Drop (e.g., pop A1, pop A2, drop A2,
    //   restore A1 while A3 is in bucket): head=4500 after pop A2.
    //   Arithmetic gives head=4500-bytes(A3=1500)=3000. Subsequent
    //   pop A1 then advances head to 3000+bytes(A3)=4500. A3 ends
    //   up at finish=4500, preserving A2's "consumed virtual
    //   service" — competing buckets between 3000 and 4500
    //   correctly drain before A3.
    //
    // (Codex code-review R8 initially flagged this as wrong with
    // recommendation to use snap.pre_pop_head_finish; R9 then
    // reversed when its own walkthrough showed the arithmetic
    // result is needed for the post-restore-pop case. Documented
    // in §3.3 of the plan.)
    let current_head_bytes = queue.flow_bucket_items[bucket]
        .front()
        .map(cos_item_len)
        .unwrap_or(0);
    queue.flow_bucket_head_finish_bytes[bucket] = queue.flow_bucket_head_finish_bytes[bucket]
        .saturating_sub(current_head_bytes);
    queue.flow_bucket_bytes[bucket] = queue.flow_bucket_bytes[bucket].saturating_add(item_len);
    queue.flow_bucket_items[bucket].push_front(item);
}

#[inline]
pub(super) fn cos_queue_pop_front(queue: &mut CoSQueueRuntime) -> Option<CoSPendingTxItem> {
    cos_queue_pop_front_inner(queue, true)
}

/// #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
/// teardown-only variant of `cos_queue_pop_front` that does NOT
/// push a rollback snapshot. Used by drain-all-items-until-empty
/// paths (`cos_queue_drain_all` and the worker teardown loop)
/// where the drained items are either discarded or restored via
/// a single reverse push_front loop that doesn't need per-pop
/// pre-state capture (nothing has mutated the bucket between
/// drain and restore in those paths).
///
/// Without this variant, a teardown of >TX_BATCH_SIZE items would
/// grow `pop_snapshot_stack` past its documented bound and trip
/// the per-pop debug_assert.
#[inline]
pub(super) fn cos_queue_pop_front_no_snapshot(
    queue: &mut CoSQueueRuntime,
) -> Option<CoSPendingTxItem> {
    cos_queue_pop_front_inner(queue, false)
}

#[inline]
fn cos_queue_pop_front_inner(
    queue: &mut CoSQueueRuntime,
    push_snapshot: bool,
) -> Option<CoSPendingTxItem> {
    let item = if !queue.flow_fair {
        queue.items.pop_front()?
    } else {
        // #785 Phase 3 — MQFQ: pop from the bucket whose head
        // packet has the smallest virtual-finish-time, not DRR
        // rotation order. The active set (`flow_rr_buckets`) is
        // still maintained on 0↔>0 transitions so the min-scan
        // only iterates the currently-active buckets (typically
        // 2-16), not all 1024.
        let bucket_u16 = cos_queue_min_finish_bucket(queue)?;
        let bucket = usize::from(bucket_u16);
        if push_snapshot {
            // #785 Phase 3 — Codex round-3 HIGH + NEW-1: snapshot
            // pre-pop bucket + vtime state BEFORE we mutate anything,
            // and push onto the per-queue LIFO stack. Every popped
            // item gets its own snapshot so a batched rollback (N
            // pops into scratch, submit a prefix, push_front the tail
            // in LIFO order) can restore exact pre-pop head/tail for
            // EVERY item — not just the most recent pop.
            //
            // Earlier revision kept a single `Option<...>`; Codex
            // NEW-1 flagged that earlier drained buckets in a
            // multi-pop rollback fell back to the
            // `max(tail, queue_vtime) + bytes` re-anchor formula,
            // which can overshoot the pre-pop head when queue_vtime
            // has advanced since the bucket's original enqueue.
            //
            // Stack capacity is preallocated to TX_BATCH_SIZE
            // (see types.rs), so this push is amortized O(1) and
            // allocation-free.
            //
            // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
            // debug_assert the stack stays within its documented bound.
            // Drain helpers clear at batch start and teardown paths
            // use `cos_queue_pop_front_no_snapshot`. If this trips
            // under dev/test, a new caller is leaking snapshots
            // and could realloc on the hot path in release builds.
            debug_assert!(
                queue.pop_snapshot_stack.len() < TX_BATCH_SIZE,
                "pop_snapshot_stack exceeded TX_BATCH_SIZE bound ({}); \
                 a caller is leaking snapshots — drain helpers must \
                 clear at batch start and teardown paths must use \
                 cos_queue_pop_front_no_snapshot",
                TX_BATCH_SIZE,
            );
            queue.pop_snapshot_stack.push(CoSQueuePopSnapshot {
                bucket: bucket_u16,
                pre_pop_head_finish: queue.flow_bucket_head_finish_bytes[bucket],
                pre_pop_tail_finish: queue.flow_bucket_tail_finish_bytes[bucket],
                pre_pop_queue_vtime: queue.queue_vtime,
            });
        }
        // #913: capture served_finish (the popped packet's finish
        // time) BEFORE pop_front + head-advance below mutate it.
        let served_finish = queue.flow_bucket_head_finish_bytes[bucket];
        let item = queue.flow_bucket_items[bucket].pop_front()?;
        // #913: branched vtime advance.
        // - push_snapshot=true (hot path / `cos_queue_pop_front`):
        //   MQFQ served-finish semantics — `vtime = max(vtime,
        //   served_finish)`. Closes #911 same-class HOL by
        //   tracking the system frontier (smallest head_finish
        //   across active buckets at pop time) instead of
        //   aggregate bytes.
        // - push_snapshot=false (`cos_queue_pop_front_no_snapshot`,
        //   used by drain_all + worker.rs:1859 teardown):
        //   legacy `vtime += bytes` retained. The
        //   `demote_prepared_cos_queue_to_local` failure-restore
        //   path (drain_all → restore_front) relies on this
        //   symmetry with push_front's `vtime -= item_len`
        //   rewind for round-trip neutrality. drain_all clears
        //   the snapshot stack at start so push_front of the
        //   restored items takes the empty-stack aggregate
        //   path. See plan §3.5 / §3.7.
        if push_snapshot {
            queue.queue_vtime = queue.queue_vtime.max(served_finish);
        } else {
            let bytes = cos_item_len(&item);
            queue.queue_vtime = queue.queue_vtime.saturating_add(bytes);
        }
        if let Some(next_head) = queue.flow_bucket_items[bucket].front() {
            // Bucket still has packets. Advance head-finish to
            // the NEW head packet's finish: head += bytes(new head).
            // This is the "fresh HOL key" for the next min-scan;
            // without it, the bucket's selection key would stay
            // frozen at the just-popped packet's finish and
            // equal-depth backlogged flows would drain in
            // `A,A,B,B` bursts (Codex HIGH on the first Phase 3
            // revision).
            let next_bytes = cos_item_len(next_head);
            queue.flow_bucket_head_finish_bytes[bucket] = queue.flow_bucket_head_finish_bytes
                [bucket]
                .saturating_add(next_bytes);
        } else {
            // Bucket drained — deregister from the active set.
            // `FlowRrRing::remove` is O(active_count), typically
            // 2-16 compares; bounded by 1024 worst case.
            queue.flow_rr_buckets.remove(bucket_u16);
        }
        item
    };
    // #774: decrement the Local counter BEFORE account_flow_dequeue
    // so that if account_flow_dequeue panics the counter isn't
    // stuck high. saturating_sub is a no-op on 0 (never should be
    // 0 when a Local item is popping, but defense-in-depth).
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.local_item_count = queue.local_item_count.saturating_sub(1);
    }
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    account_cos_queue_flow_dequeue(queue, flow_key, item_len);
    Some(item)
}

/// #913 — used by scratch-builder Drop paths to clean up the
/// orphan snapshot for an item that was popped and then dropped
/// (frame-too-big, slice-fail). The naive `pop_snapshot_stack.pop()`
/// loses the dropped item's vtime contribution: subsequent
/// survivor restores via `cos_queue_push_front` would rewind vtime
/// below the dropped item's commit, breaking MQFQ ordering.
///
/// Fix (Codex code review HIGH): after popping the orphan, clamp
/// every remaining snapshot's `pre_pop_queue_vtime` to ≥ the
/// post-drop `queue_vtime`. This preserves the "drops consume
/// virtual service" semantic: when surviving items are restored,
/// their vtime restores can't go below the dropped item's
/// committed advance.
///
/// Walkthrough: pre-batch vtime=0; pop A (head=1500) → vtime=1500;
/// pop B (head=2000) → vtime=2000; pop Z (head=3000) → vtime=3000.
/// Drop Z: z_committed_vtime=3000; pop snap_Z; clamp snap_B and
/// snap_A pre_pop_queue_vtime to max(orig, 3000)=3000. Restore B:
/// vtime=3000. Restore A: vtime=3000. Z's vtime contribution
/// preserved across the rollback.
fn cos_queue_clear_orphan_snapshot_after_drop(queue: &mut CoSQueueRuntime) {
    let Some(orphan) = queue.pop_snapshot_stack.pop() else {
        return;
    };
    // queue.queue_vtime here reflects the dropped item's pop
    // advance (already applied in cos_queue_pop_front_inner).
    // Clamp remaining snapshots to preserve it across rollback.
    let z_committed_vtime = queue.queue_vtime;
    // #927: also preserve the dropped item's bucket-frontier
    // contribution. The dropped item's served_finish equals
    // `orphan.pre_pop_head_finish` (served_finish is read from
    // `flow_bucket_head_finish_bytes[bucket]` BEFORE the
    // post-pop overwrite at the orphan's pop site, so it
    // matches the snapshot's pre_pop_head_finish capture).
    // Older same-bucket snapshots were captured before the
    // dropped item's pop, so their pre_pop_head/tail_finish
    // do not include the dropped item's frontier. When such a
    // snapshot is later restored via the `was_empty` snapshot
    // path in `cos_queue_push_front`, the bucket would be
    // re-anchored at a stale (lower) finish-time — competing
    // active buckets could be incorrectly scheduled before
    // it. Bumping to `orphan_served_finish` via .max() is
    // monotone (only raises) and never crosses a committed
    // boundary, so it is safe across all rollback orderings.
    let orphan_served_finish = orphan.pre_pop_head_finish;
    for snap in queue.pop_snapshot_stack.iter_mut() {
        if snap.pre_pop_queue_vtime < z_committed_vtime {
            snap.pre_pop_queue_vtime = z_committed_vtime;
        }
        if snap.bucket == orphan.bucket {
            snap.pre_pop_head_finish =
                snap.pre_pop_head_finish.max(orphan_served_finish);
            snap.pre_pop_tail_finish =
                snap.pre_pop_tail_finish.max(orphan_served_finish);
        }
    }
}

fn cos_queue_drain_all(queue: &mut CoSQueueRuntime) -> VecDeque<CoSPendingTxItem> {
    // #913 / Codex R3: clear stale snapshots from any prior
    // committed hot-path drain. Without this, a subsequent
    // `cos_queue_restore_front` would consume orphan snapshots
    // and apply them to the wrong items (the failure-restore
    // path in `demote_prepared_cos_queue_to_local`). The §3.7
    // round-trip-neutrality walkthrough relies on the stack
    // being EMPTY when restore_front begins.
    queue.pop_snapshot_stack.clear();
    let mut items = VecDeque::new();
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // drain-all is a teardown/reconfigure helper. Unlike the
    // hot-path batch drains (which cap at TX_BATCH_SIZE and
    // may be followed by a matching push_front rollback), this
    // path pops the entire queue without a paired rollback and
    // can visit >TX_BATCH_SIZE items. Use the no-snapshot
    // variant so we don't grow the snapshot stack past its
    // documented bound or trip the per-pop debug_assert.
    while let Some(item) = cos_queue_pop_front_no_snapshot(queue) {
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

    // #926: snapshot MQFQ frontier state BEFORE drain_all so we
    // can restore on the success path. cos_queue_drain_all uses
    // the no-snapshot pop variant (aggregate-bytes vtime advance:
    // queue_vtime += bytes per pop) which inflates queue_vtime
    // by the entire drained backlog. cos_queue_push_back then
    // re-anchors finish-times against the inflated vtime
    // (max(tail, queue_vtime) + bytes), letting any new flow Y
    // enqueued immediately after demotion jump ahead of the
    // demoted backlog — the temporal-inversion bug class #911 /
    // #913 was supposed to prevent. The failure-rollback path
    // (cos_queue_restore_front) is round-trip neutral per #913
    // §3.7 and stays correct without snapshot/restore.
    //
    // Single-worker invariant (Gemini R2): demote and pop run
    // in the same worker thread, and any in-flight pop's
    // snapshot is cleared by cos_queue_drain_all below
    // (tx.rs:4742). So no cross-batch pop_snapshot_stack
    // entries can be live at this point — restoring vtime +
    // head/tail finish-times can't race with a concurrent
    // pop's snapshot interpretation.
    //
    // Footprint: 16 KB stack memcpy of two [u64; 1024] arrays
    // already cache-resident in the queue. demote is a rare
    // TX-frame-exhaustion fallback called from
    // enqueue_local_into_cos at tx.rs:5211, not a hot-path
    // operation.
    let saved_queue_vtime = queue.queue_vtime;
    let saved_head_finish = queue.flow_bucket_head_finish_bytes;
    let saved_tail_finish = queue.flow_bucket_tail_finish_bytes;

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

    // #926: restore MQFQ frontier on the success path. Same
    // flow_keys → same cos_flow_bucket_index → same buckets,
    // so the saved per-bucket head/tail finish-times still
    // apply. Restoring queue_vtime alongside keeps the three
    // values internally consistent.
    queue.queue_vtime = saved_queue_vtime;
    queue.flow_bucket_head_finish_bytes = saved_head_finish;
    queue.flow_bucket_tail_finish_bytes = saved_tail_finish;

    true
}

/// #774: O(1) check replacing the prior O(n) scan. Profiled at
/// 3.25% CPU on the hot path at line rate before this fix.
/// `local_item_count` is maintained at every push/pop site in
/// `cos_queue_push_*` / `cos_queue_pop_front`. Single-writer
/// (owner worker), same discipline as `queued_bytes` — no atomic
/// needed.
#[inline]
fn cos_queue_accepts_prepared(root: &CoSInterfaceRuntime, requested_queue: Option<u8>) -> bool {
    let Some(queue_idx) = resolve_cos_queue_idx(root, requested_queue) else {
        return false;
    };
    let Some(queue) = root.queues.get(queue_idx) else {
        return false;
    };
    queue.local_item_count == 0
}

#[inline]
fn ensure_cos_interface_runtime(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    now_ns: u64,
) -> bool {
    if egress_ifindex <= 0 {
        return false;
    }
    // #774 fast path: if the runtime is already materialised,
    // that's the dominant case on steady state. A single
    // `contains_key` on the cos_interfaces hot map skips the two
    // forwarding.cos.interfaces + cos_fast_interfaces lookups
    // and the later-pass duplicate. Profiled at 0.9% CPU before
    // this fix.
    if binding.cos_interfaces.contains_key(&egress_ifindex) {
        return true;
    }
    let Some(config) = forwarding.cos.interfaces.get(&egress_ifindex) else {
        return false;
    };
    if !binding.cos_fast_interfaces.contains_key(&egress_ifindex) {
        return false;
    }
    {
        let mut runtime = build_cos_interface_runtime(config, now_ns);
        if let Some(iface_fast) = binding.cos_fast_interfaces.get(&egress_ifindex) {
            apply_cos_queue_flow_fair_promotion(&mut runtime, &iface_fast.queue_fast_path);
        }
        binding.cos_interfaces.insert(egress_ifindex, runtime);
        binding.cos_interface_order.push(egress_ifindex);
        binding.cos_interface_order.sort_unstable();
    }
    true
}

/// Promote every queue on a freshly-built `CoSInterfaceRuntime` onto
/// (or off) the SFQ (flow-fair) path, using the per-queue
/// `WorkerCoSQueueFastPath.shared_exact` signal as the gate. This is
/// the whole-runtime entry point — `ensure_cos_interface_runtime`
/// calls it exactly once after `build_cos_interface_runtime`. The
/// zip alignment between `runtime.queues` and
/// `iface_fast.queue_fast_path` is load-bearing: both vectors are
/// built by iterating the same `CoSInterfaceConfig.queues` slice in
/// order (`build_cos_interface_runtime` → `CoSQueueRuntime`,
/// `build_worker_cos_fast_interfaces` → `WorkerCoSQueueFastPath`),
/// so position N in one always corresponds to position N in the
/// other.  Passing both vectors through this helper — rather than
/// inlining the `zip` at the call site — lets the integration test
/// drive the exact production promotion path with hand-authored
/// fast-path state, pinning the zip + per-queue gate end-to-end.
///
/// See `promote_cos_queue_flow_fair` below for the per-queue policy
/// rationale, and the `#785` test block for the pins that guard this
/// surface against silent regressions.
#[inline]
fn apply_cos_queue_flow_fair_promotion(
    runtime: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
) {
    for (queue, queue_fast) in runtime.queues.iter_mut().zip(queue_fast_path) {
        promote_cos_queue_flow_fair(queue, queue_fast);
    }
}

/// Promote a freshly-built queue runtime onto the SFQ (flow-fair)
/// path when its configuration warrants it, and cache the
/// `shared_exact` signal onto the runtime so future work on this
/// surface can branch on it without another iface_fast lookup.
///
/// **Current policy (post-#785 Phase 3, post-#914):** `flow_fair =
/// queue.exact` for both owner-local-exact AND shared_exact. The
/// dequeue-ordering mechanism is MQFQ virtual-finish-time (#913 fixed
/// the snapshot-rollback bug). The admission-side per-flow cap on
/// shared_exact is RATE-AWARE (#914): `cos_queue_flow_share_limit`
/// returns `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`
/// rather than the rate-unaware MIN floor that regressed throughput
/// in the historical attempts described below.
///
/// **Historical retrospective (issue #785):** two earlier attempts
/// to enable SFQ on shared_exact were rolled back:
///
/// 1. Naïve flip (flow_fair=queue.exact, no admission change).
///    iperf3 -P 12 on the 25 Gbps iperf-c cap regressed from
///    22.3 Gbps / 0 retrans to 16.3 Gbps / 25 k+ retrans. Root
///    cause: the per-flow share cap (`cos_queue_flow_share_limit`
///    → floor `COS_FLOW_FAIR_MIN_SHARE_BYTES` = 24 KB) and the
///    per-flow ECN arm (`apply_cos_admission_ecn_policy`) were
///    rate-unaware; on a 25 Gbps queue with 12 flows the per-flow
///    cap collapsed to ~24 KB, far below the ~5 MB BDP a
///    2 Gbps / 20 ms TCP flow needs, so admission drops and ECN
///    marks fired on nearly every packet. **#914 fixes this** by
///    making the cap rate-aware via `bdp_floor_bytes`.
///
/// 2. SFQ + aggregate-only admission (flow_fair=queue.exact;
///    `cos_queue_flow_share_limit` returns `buffer_limit` on
///    shared_exact). Throughput preserved (22-23 Gbps) but per-flow
///    CoV went UP from ~33 % to ~40-51 % over three runs because
///    per-worker SFQ DRR cannot equalise flows that are distributed
///    unevenly across workers by NIC RSS — the dominant imbalance
///    source at P=12 / 8 workers. The DRR primitive was replaced
///    with MQFQ (#913) which uses byte-rate fairness, the
///    architecturally correct primitive for TCP under pacing.
///
/// **Contract shape:** `queue_fast: &WorkerCoSQueueFastPath` is the
/// live classifier output from `build_worker_cos_fast_interfaces`,
/// i.e. the exact same field the service path (`drain_shaped_tx`,
/// `try_drain_shared_exact`, etc.) consults. Taking the reference
/// directly rather than a loose `bool` pins the contract to the
/// same struct shape production uses: tests exercise the same
/// `WorkerCoSQueueFastPath` contract rather than an unrelated
/// standalone flag, so any future addition of fields to the
/// fast-path struct (e.g. a `min_local_flow_count` guarantee for
/// the cross-worker DRR work) is automatically visible here.
///
/// **Adversarial review posture (post-#914):** the historical
/// `!shared_exact` gate is no longer in policy — `flow_fair =
/// queue.exact` for both shared_exact and owner-local-exact. The
/// `shared_exact` shadow cached onto `CoSQueueRuntime` is now the
/// branch point used by `cos_queue_flow_share_limit` to apply the
/// rate-aware admission cap (`max(fair_share*2, bdp_floor)`)
/// instead of the legacy aggregate/N share cap. Reviewers should
/// reject PRs that re-introduce the rate-unaware MIN-floor cap on
/// shared_exact without also re-validating iperf-c P=12 ≥ 22 Gbps
/// and the same-class iperf-b mouse-latency p99 (the regressions
/// historical Attempts A and B hit).
///
/// The SFQ salt is drawn only for queues that actually use the
/// flow-fair path — non-flow-fair queues never consult the seed
/// (`exact_cos_flow_bucket` is only called from the flow-fair
/// callers). Keeping them at seed=0 also preserves byte-identical
/// legacy behavior on that path.
#[inline]
fn promote_cos_queue_flow_fair(
    queue: &mut CoSQueueRuntime,
    queue_fast: &WorkerCoSQueueFastPath,
) {
    queue.shared_exact = queue_fast.shared_exact;
    // #785 Phase 3 — flow-fair is enabled on EVERY exact queue,
    // including shared_exact. The dequeue-ordering mechanism is
    // MQFQ virtual-finish-time (byte-rate fair), not DRR round-robin
    // (packet-count fair) — which is the architecturally correct
    // primitive for per-flow fairness under TCP pacing. See
    // `docs/785-cross-worker-drr-retrospective.md` §4 for the
    // retrospective analysis, and `docs/785-perf-fairness-plan.md`
    // for the phased plan.
    //
    // Admission gates: `cos_queue_flow_share_limit` is RATE-AWARE
    // on shared_exact post-#914 — it returns
    // `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)` so the
    // per-flow cap follows BDP at queue rate / N flows rather than
    // collapsing to the rate-unaware 24 KB MIN floor that caused the
    // Attempt A regression (22.3 → 16.3 Gbps).
    // `apply_cos_admission_ecn_policy` still uses the aggregate arm
    // on shared_exact (per-flow ECN remains rate-unaware).
    queue.flow_fair = queue.exact;
    if queue.flow_fair {
        queue.flow_hash_seed = cos_flow_hash_seed_from_os();
    }
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
                // Populated by `promote_cos_queue_flow_fair` from the
                // live `WorkerCoSQueueFastPath.shared_exact` signal.
                shared_exact: false,
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
            active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
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
        // Split-borrow: `umem` sits alongside `cos_interfaces` on
        // `BindingWorker`, so we can take a shared borrow on the umem
        // field while holding `&mut binding.cos_interfaces` for the
        // admission-gate block. The Prepared-variant ECN marker
        // (#727) needs this to mutate frame bytes in the UMEM
        // in-place; the admission gate runs strictly before the
        // frame is enqueued, so nothing else in the system observes
        // the bytes concurrently. Both fields are borrowed explicitly
        // here so the borrow checker keeps us honest.
        let umem = binding.umem.area();
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
        // #718 + #722: ECN CE-mark above threshold so ECN-negotiated
        // TCP flows back off smoothly rather than tail-dropping into
        // RTO. Non-ECT packets are untouched — they fall back to the
        // existing admission drop path below. Mark only when the
        // packet will actually be admitted: a marked-and-then-dropped
        // packet wastes both the mark and the bandwidth the mark was
        // trying to steer. `flow_bucket` is the same index the
        // per-flow admission gate keyed off, so both gates see the
        // same queue snapshot.
        let _ = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            flow_bucket,
            flow_share_exceeded,
            buffer_exceeded,
            &mut item,
            umem,
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
    // #804: CoS admission overflow — NOT bound-pending. Pre-#804 this
    // site incremented `dbg_pending_overflow` which conflated it with
    // the bound-pending FIFO evict sites; the two are now tracked on
    // separate counters so operators can disambiguate CoS shaping
    // pressure from bound-pending pressure.
    binding.dbg_cos_queue_overflow += 1;
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
            // #760 instrumentation: record non-exact / surplus /
            // shared-exact sends at the same site the queue's token
            // or surplus accounting is debited. Paired with the
            // apply_direct_exact_send_result write so the sum across
            // all sites equals the bytes the CoS scheduler accounted.
            queue
                .owner_profile
                .drain_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
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
            // #760 instrumentation, the FOURTH apply_* site. This is
            // the prepared-batch path (CoSBatch::Prepared, in-place
            // rewrite — the common case for forwarded traffic). The
            // initial instrumentation commit missed this site; the
            // first 120 s iperf3 measurement showed only ~987 Mbps
            // on drain_sent_bytes while the receiver reported 1.55
            // Gbps, leaving ~563 Mbps unaccounted — all of it
            // flowing through this path. Same Relaxed semantics as
            // the other three apply_* sites.
            queue
                .owner_profile
                .drain_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
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
    // #760 / Codex review note: when `req.recycle` is
    // `FillOnSlot(fill_slot)` with `fill_slot != binding.slot`,
    // `recycle_cancelled_prepared_offset` routes the frame to THIS
    // binding's `free_tx_frames`, not the source slot's fill ring.
    // This is the same behavior as the pre-existing cancel path
    // used by `restore_cos_prepared_items` etc., and is latent in
    // practice because `FillOnSlot(other_slot)` only arises in the
    // same-device shared-UMEM prototype, which is unused on the
    // current test topologies. A proper cross-slot fill-credit
    // routing would need a `shared_recycles` channel from this
    // drop site back to the source worker; deferred until the
    // shared-UMEM prototype is activated.
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
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the post-CoS backup transmit_batch
    // variant for local requests). Post-commit stamping prevents a
    // scheduler preemption window between insert and ring submission
    // from inflating the observed latency.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_local_tx
            .iter()
            .take(inserted as usize)
            .map(|(offset, _)| *offset),
        ts_submit,
    );

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
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the transmit_prepared_queue
    // continuation variant). Post-commit stamping ensures we measure
    // kernel-visible submit time, not the pre-submit planning window.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_prepared_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

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
        // #825 plan §3.3 site 1: two fresh `monotonic_nanos()` calls
        // bracket the `sendto` syscall. `now_ns` is caller-cached —
        // stale up to `IDLE_SPIN_ITERS * spin_cost` per #812 §3.1 R1
        // — so it is NOT suitable for measuring the kick cost; we
        // need fresh stamps to measure the syscall itself. Cost per
        // kick: ~30 ns VDSO (2 × ~15 ns) + the atomic fetch_adds in
        // `record_kick_latency` (≲15 ns), well within the §7 budget.
        let kick_start = monotonic_nanos();
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
        let kick_end = monotonic_nanos();
        binding.dbg_sendto_calls += 1;
        // #825 plan §3.3 LOW-3 R1 sentinel, code-review R1 HIGH-1 hardening:
        // skip record unless (a) `kick_start != 0` AND (b) `kick_end >=
        // kick_start`. Both guards are required:
        //   - `kick_start != 0` catches the asymmetric failure mode where
        //     the first `monotonic_nanos()` call fails (returns 0) and the
        //     second succeeds — `kick_end - 0` would saturate bucket 15
        //     with a bogus-huge delta. It also drops the symmetric
        //     double-failure case (both 0) so a spurious bucket-0 record
        //     is not emitted on VDSO outage.
        //   - `kick_end >= kick_start` catches the backwards-clock /
        //     end-before-start case (wraparound in the `kick_end -
        //     kick_start` subtraction would otherwise saturate bucket
        //     15 with a bogus-huge delta). Both conditions must hold;
        //     this matches `record_tx_completions_with_stamp`'s
        //     `ts_completion >= ts_submit` precedent at :113-119.
        if kick_start != 0 && kick_end >= kick_start {
            let delta_ns = kick_end - kick_start;
            record_kick_latency(&binding.live.owner_profile_owner, delta_ns);
        }
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            // EAGAIN/EWOULDBLOCK is normal for MSG_DONTWAIT; ENOBUFS means kernel dropped.
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                binding.dbg_sendto_eagain += 1;
                // #825 plan §3.3 site 1 / §5: parallel atomic to
                // `dbg_sendto_eagain` (which is worker-local and
                // never published). Counts outer `sendto` returns
                // where `errno ∈ {EAGAIN, EWOULDBLOCK}` — the
                // "ring pushed back" signal T1 (#819 §4.1) keys
                // off. `dbg_sendto_eagain` stays in place: the
                // worker-local debug-tick log at
                // `worker.rs:~1051` continues to work.
                binding
                    .live
                    .owner_profile_owner
                    .tx_kick_retry_count
                    .fetch_add(1, Ordering::Relaxed);
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
            vtime_floor: None,
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

    /// #784 Codex review regression pin: mixed-head deque scan.
    ///
    /// The first revision of `drop_cos_bound_local_leftovers` did
    /// a head-peek fast-exit: if the deque's front item had
    /// `cos_queue_id.is_none()`, the function returned before
    /// scanning. That let CoS-bound items LATER in the deque
    /// escape to the unshaped `transmit_batch` backup path,
    /// bypassing the CoS cap — the exact #760 bypass this filter
    /// was designed to close.
    ///
    /// This test constructs a mixed-head deque
    /// `[non-cos, cos-bound, non-cos, cos-bound]` and verifies
    /// every cos-bound item is either rescued or dropped (NEVER
    /// left in the deque), while non-cos items are preserved for
    /// the downstream backup transmit path.
    ///
    /// If this test ever relaxes to allow cos-bound items in the
    /// survivor set, the #760 cap bypass returns. Adversarial
    /// reviewers MUST reject PRs that weaken this.
    #[test]
    fn partition_cos_bound_local_scans_mixed_head_deque() {
        // Build a pending deque with a NON-CoS head followed by
        // a mix of CoS-bound and non-CoS items. Codex flagged
        // the pre-refactor head-peek as HIGH severity — this is
        // the regression pin.
        let non_cos = |payload: u8| TxRequest {
            bytes: vec![payload; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 99,
            cos_queue_id: None,
            dscp_rewrite: None,
        };
        let cos_bound = |payload: u8| TxRequest {
            bytes: vec![payload; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 14,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        let mut pending: VecDeque<TxRequest> = VecDeque::from([
            non_cos(1),
            cos_bound(2),
            non_cos(3),
            cos_bound(4),
            non_cos(5),
        ]);
        // Rescue stub: always fails (returns Err) so every
        // cos-bound item falls through to drop. Verifies the
        // scan covers the WHOLE deque, not just the head.
        let (dropped, dropped_bytes) =
            partition_cos_bound_local_with_rescue(&mut pending, Err);
        assert_eq!(dropped, 2, "both cos-bound items must be dropped (scan covers tail)");
        assert_eq!(dropped_bytes, 128, "2 × 64 bytes dropped");
        // Survivors: only the 3 non-CoS items, in original order.
        let survivors: Vec<u8> = pending.iter().map(|r| r.bytes[0]).collect();
        assert_eq!(survivors, vec![1, 3, 5]);
    }

    /// #784 companion: rescue path pins. When `try_rescue` returns
    /// Ok, items are consumed (rescued) — they must NOT remain in
    /// the survivor set. Only items that actually fail rescue
    /// count toward the drop.
    #[test]
    fn partition_cos_bound_local_rescues_when_try_rescue_ok() {
        let non_cos = TxRequest {
            bytes: vec![0xAA; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 99,
            cos_queue_id: None,
            dscp_rewrite: None,
        };
        let cos_bound = TxRequest {
            bytes: vec![0xBB; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 14,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        let mut pending: VecDeque<TxRequest> = VecDeque::from([non_cos, cos_bound]);
        // Rescue always succeeds — CoS items must NOT count as drops.
        let (dropped, dropped_bytes) =
            partition_cos_bound_local_with_rescue(&mut pending, |_| Ok(()));
        assert_eq!(dropped, 0);
        assert_eq!(dropped_bytes, 0);
        // Survivor set: only the non-CoS item (rescued CoS item
        // was consumed by try_rescue closure).
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].bytes[0], 0xAA);
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

    /// #780 / Codex adversarial review: verify the decision DAG
    /// inside `resolve_local_routing_decision` exactly mirrors
    /// the pre-#780 three-step cascade across every quadrant
    /// flagged. The decision now carries BOTH Step 1 and Step 2
    /// independently so the ingest loop can fall through on Err.
    #[test]
    fn resolve_local_routing_decision_step1_routes_via_arc() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
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
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        match decision.step1 {
            Some(Step1Action::Arc(ref arc)) => {
                assert!(Arc::ptr_eq(arc, &owner_live));
            }
            _ => panic!("expected Step1 Arc"),
        }
        assert!(decision.step2.is_none());
    }

    #[test]
    fn resolve_local_routing_decision_step1_routes_via_command_when_no_arc() {
        let current_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            None,
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        match decision.step1 {
            Some(Step1Action::Command(w)) => assert_eq!(w, 7),
            _ => panic!("expected Step1 Command"),
        }
        assert!(decision.step2.is_none());
    }

    /// Codex round 2 missing-test flag: Step1Command path where
    /// iface has tx_owner_live set but queue is not shared_exact
    /// and owner_live is None. Step 1 must route via command
    /// (because queue's own owner_live is None), AND Step 2
    /// should ALSO be set so the cascade falls through on Err.
    #[test]
    fn resolve_local_routing_decision_step1_command_with_iface_tx_owner_live_populates_both_steps() {
        let current_live = Arc::new(BindingLiveState::new());
        let iface_owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            Some(iface_owner_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        match decision.step1 {
            Some(Step1Action::Command(w)) => assert_eq!(w, 7),
            _ => panic!("expected Step1 Command"),
        }
        // Step 2 must also be populated — cascade fallthrough.
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &iface_owner_live)),
            None => panic!("expected Step2 populated for cascade fallthrough"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_step2_routes_when_owner_worker_is_current() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(false, 3, Some(owner_live.clone()), None),
            )],
            Some(owner_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        // Step 1 bails (owner == current), Step 2 routes.
        assert!(decision.step1.is_none());
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
            None => panic!("expected Step2 Arc"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_step2_routes_when_shared_exact_bails_step1() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(
                    true,
                    3,
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
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        assert!(decision.step1.is_none());
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
            None => panic!("expected Step2 Arc"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_enqueue_local_when_both_bail() {
        let current_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(false, 3, Some(current_live.clone()), None),
            )],
            Some(current_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        assert!(decision.step1.is_none());
        assert!(decision.step2.is_none());
    }

    #[test]
    fn resolve_local_routing_decision_step2_routes_when_queue_absent() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            Some(owner_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(99), 3, &current_live);
        assert!(decision.step1.is_none());
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
            None => panic!("expected Step2 Arc"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_enqueue_local_when_iface_absent() {
        let current_live = Arc::new(BindingLiveState::new());
        let ifaces: FastMap<i32, WorkerCoSInterfaceFastPath> = FastMap::default();
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        assert!(decision.step1.is_none());
        assert!(decision.step2.is_none());
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
        // #774: use cos_queue_push_back so local_item_count
        // stays in sync. Previously this test poked queue.items
        // directly, which bypassed the counter maintenance.
        cos_queue_push_back(
            &mut root.queues[0],
            CoSPendingTxItem::Prepared(PreparedTxRequest {
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
            }),
        );
        cos_queue_push_back(
            &mut root.queues[0],
            CoSPendingTxItem::Local(TxRequest {
                bytes: vec![0; 1500],
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }),
        );

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

    /// #926: regression test for the success-path
    /// queue_vtime / head-finish preservation. Prepared items
    /// across multiple flows are queued, demoted to Local, and
    /// the MQFQ frontier (queue_vtime + per-bucket head/tail
    /// finish-times) MUST be unchanged. A new flow Y enqueued
    /// immediately after demotion MUST anchor at a finish-time
    /// that respects the demoted backlog's frontier — i.e. Y
    /// cannot jump ahead of the demoted backlog.
    #[test]
    fn demote_prepared_cos_queue_to_local_preserves_mqfq_frontier() {
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

        // Two distinct flows, each one Prepared item. Bucket
        // indices computed under flow_hash_seed=0 for use in
        // post-demote frontier assertions.
        let key_a = test_session_key(8001, 5201);
        let key_b = test_session_key(8002, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
        let bucket_b = cos_flow_bucket_index(0, Some(&key_b));
        assert_ne!(
            bucket_a, bucket_b,
            "test setup: ports 8001/8002 must hash to distinct buckets"
        );

        cos_queue_push_back(
            queue,
            CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: Some(key_a.clone()),
                egress_ifindex: 42,
                cos_queue_id: Some(4),
                dscp_rewrite: None,
            }),
        );
        cos_queue_push_back(
            queue,
            CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: Some(key_b.clone()),
                egress_ifindex: 42,
                cos_queue_id: Some(4),
                dscp_rewrite: None,
            }),
        );

        // Snapshot pre-demote MQFQ frontier.
        let pre_vtime = queue.queue_vtime;
        let pre_head_a = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_head_b = queue.flow_bucket_head_finish_bytes[bucket_b];
        let pre_tail_a = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_tail_b = queue.flow_bucket_tail_finish_bytes[bucket_b];
        assert!(pre_head_a > 0);
        assert!(pre_head_b > 0);

        // Demote (success path).
        let mut free_tx_frames = VecDeque::from([512]);
        let mut pending_fill_frames = VecDeque::new();
        assert!(demote_prepared_cos_queue_to_local(
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            &mut root,
            Some(4),
        ));

        let queue = &mut root.queues[0];

        // Frontier MUST be unchanged across the success path.
        assert_eq!(
            queue.queue_vtime, pre_vtime,
            "#926 regression: queue_vtime must be preserved across \
             demote success path. Pre={pre_vtime} post={}",
            queue.queue_vtime
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_head_a,
            "#926: head_finish[A] must be preserved (pre={pre_head_a})"
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], pre_head_b,
            "#926: head_finish[B] must be preserved (pre={pre_head_b})"
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_tail_a,
            "#926: tail_finish[A] must be preserved"
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], pre_tail_b,
            "#926: tail_finish[B] must be preserved"
        );

        // Items now Local. flow_fair=true stores items in
        // per-bucket VecDeques at `flow_bucket_items[bucket]`,
        // not in `queue.items`.
        let mut total_items = 0;
        for bucket in [bucket_a, bucket_b] {
            for item in queue.flow_bucket_items[bucket].iter() {
                assert!(
                    matches!(item, CoSPendingTxItem::Local(_)),
                    "demote should convert Prepared → Local"
                );
                total_items += 1;
            }
        }
        assert_eq!(total_items, 2);

        // The frontier-preservation assertions above are the
        // load-bearing test (Codex code review caught that an
        // earlier "Y does not jump ahead" assertion was
        // logically muddled — without the fix, the four
        // assert_eq calls already FAIL at the queue_vtime / head /
        // tail checks; demote_prepared without snapshot/restore
        // leaves queue_vtime=3000 and head_a=head_b=4500, all
        // mismatching the captured pre-state). The Y-anchor
        // behavior at this scenario is identical with-or-without
        // the fix (Y is small enough to anchor below A/B in
        // both cases) so it's not a useful gate.
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

    /// #914: shared_exact rate-aware cap — verify the formula
    /// `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`
    /// scales correctly with `transmit_rate_bytes` and active flows
    /// rather than collapsing to the rate-unaware MIN floor.
    #[test]
    fn flow_share_limit_shared_exact_scales_with_rate() {
        // 10 Gbps shared_exact queue at N=128 → per_flow_rate = 9.77 MB/s,
        // bdp_floor = 9.77 MB/s × 10 ms = 97.6 KB. Buffer_limit ≫ that,
        // so the cap should follow bdp_floor.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.active_flow_buckets = 128;
        for bucket in 0..128 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // bdp_floor = (1.25 GB/s / 128) × 10 ms = 97_656 bytes (rounded).
        let expected_bdp = bdp_floor_bytes(queue.transmit_rate_bytes, 128);
        assert_eq!(
            share, expected_bdp,
            "shared_exact cap should follow bdp_floor at N=128 (cap={share}, bdp={expected_bdp})"
        );
        assert!(
            share > COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "rate-aware cap ({share}) must exceed the rate-unaware MIN floor ({COS_FLOW_FAIR_MIN_SHARE_BYTES})"
        );
        assert!(
            share <= buffer_limit,
            "cap ({share}) must not exceed buffer_limit ({buffer_limit})"
        );
    }

    /// #914: at low N, `bdp_floor` exceeds `buffer_limit`; the formula
    /// must clamp to buffer_limit and degenerate to today's behavior
    /// rather than capping below per-flow BDP (which would collapse
    /// TCP cwnd).
    #[test]
    fn flow_share_limit_shared_exact_caps_at_aggregate_for_single_flow() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.active_flow_buckets = 1;
        queue.flow_bucket_bytes[0] = 1_000;
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // At N=1 the bdp_floor (~12.5 MB) is way above buffer_limit,
        // so we clamp to buffer_limit.
        assert_eq!(
            share, buffer_limit,
            "single-flow shared_exact cap must clamp to buffer_limit (no regression vs current)"
        );
    }

    /// #914 (Codex review): at moderate N where `bdp_floor` exceeds
    /// `buffer_limit` (the degeneration regime per plan §3.2), the
    /// cap must clamp to `buffer_limit` rather than below it. Pins
    /// the low-N behavior so a future regression where the formula
    /// caps below buffer_limit fails this test rather than slipping
    /// through.
    #[test]
    fn flow_share_limit_shared_exact_clamps_to_buffer_at_low_n() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        // N = 8: per-flow rate = 156 MB/s, bdp_floor = 1.56 MB,
        // far above buffer_limit (which at default base = 96 KB and
        // 8 × MIN_SHARE = 192 KB clamps to ~192 KB).
        queue.active_flow_buckets = 8;
        for bucket in 0..8 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let bdp = bdp_floor_bytes(queue.transmit_rate_bytes, 8);
        assert!(
            bdp > buffer_limit,
            "test premise: bdp_floor ({bdp}) must exceed buffer_limit ({buffer_limit}) at N=8"
        );
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        assert_eq!(
            share, buffer_limit,
            "low-N shared_exact must clamp to buffer_limit, not below"
        );
    }

    /// #914: at high N where bdp_floor < buffer_limit, the cap is
    /// active and protects mice from elephant starvation (the actual
    /// design goal).
    #[test]
    fn flow_share_limit_shared_exact_protects_against_dominant_flow() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.active_flow_buckets = 128;
        for bucket in 0..128 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // The cap must be strictly less than buffer_limit at N=128 —
        // i.e. one flow cannot fill the entire queue.
        assert!(
            share < buffer_limit,
            "rate-aware cap ({share}) must split the buffer at N=128 (buffer_limit={buffer_limit})"
        );
        // And strictly greater than buffer_limit / N (the rate-unaware
        // arithmetic share) because of the bdp_floor and 2× headroom.
        assert!(
            share >= buffer_limit / 128,
            "cap ({share}) must be at least buffer_limit/N ({})",
            buffer_limit / 128
        );
    }

    /// #914: owner-local-exact queues (NOT shared_exact) keep the
    /// legacy `buffer_limit / prospective_active` arithmetic share.
    /// Verify the new shared_exact branch does not affect them.
    #[test]
    fn flow_share_limit_owner_local_exact_unchanged() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = false; // owner-local-exact
        queue.active_flow_buckets = 12;
        for bucket in 0..12 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // Legacy formula: buffer_limit / prospective_active, clamped to
        // [MIN_SHARE, buffer_limit]. With 12 buckets and the prospective
        // +1 for empty target bucket, the divisor is 13 (or 12 if the
        // target bucket is non-empty).
        let prospective = cos_queue_prospective_active_flows(queue, 0);
        let expected = buffer_limit
            .div_ceil(prospective)
            .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit);
        assert_eq!(
            share, expected,
            "owner-local-exact cap must use the legacy aggregate/N formula"
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
    fn cos_flow_aware_buffer_limit_clamps_high_flow_count_to_max_delay() {
        // #717: at the architectural maximum of 1024 active buckets
        // the pre-clamp flow-aware expansion reaches
        // 1024 × COS_FLOW_FAIR_MIN_SHARE_BYTES ≈ 24 MB. On a 1 Gbps
        // queue that is ~190 ms of queue residence — far outside the
        // scheduler's predictable regime. The latency-envelope clamp
        // caps the aggregate at
        // `transmit_rate_bytes × COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS / 1e9`
        // so the tail stays bounded.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                // 1 Gbps → 125_000_000 bytes/s (decimal, matches
                // operator `transmit-rate 1g` semantics).
                transmit_rate_bytes: 125_000_000,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Drive to the architectural maximum: 1024 populated buckets.
        queue.active_flow_buckets = COS_FLOW_FAIR_BUCKETS as u16;
        for bucket in 0..COS_FLOW_FAIR_BUCKETS {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }

        let cap = cos_flow_aware_buffer_limit(queue, 0);

        // Expected delay cap: 125_000_000 B/s × 5 ms = 625_000 B.
        let expected_delay_cap = 625_000u64;
        assert_eq!(
            cap, expected_delay_cap,
            "flow-aware cap must be clamped to the 5 ms delay envelope, not the ~24 MB \
             unclamped expansion"
        );

        // Counter-factual: prove the pre-clamp formula would have
        // returned 24 MB. Guards against a future refactor silently
        // deleting the clamp.
        let unclamped = u64::from(queue.active_flow_buckets)
            .max(1)
            .saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES)
            .max(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
        assert_eq!(
            unclamped,
            COS_FLOW_FAIR_BUCKETS as u64 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "unclamped formula baseline: 1024 × 24 KB = ~24 MB"
        );
        assert!(
            cap < unclamped,
            "clamp must shrink the flow-aware expansion (cap = {cap}, unclamped = {unclamped})"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_honours_operator_base_above_delay_cap() {
        // #717: the clamp is `.min(delay_cap.max(base))` — if the
        // operator explicitly configured a buffer larger than
        // `delay_cap`, we honour their intent. The clamp must never
        // shrink below the operator's `buffer-size`. On a 1 Gbps queue
        // the delay cap is 625_000 B; a 100 MiB operator base is well
        // above that.
        let operator_base: u64 = 100 * 1024 * 1024;
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 125_000_000,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: operator_base,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Use a middling flow count so prospective × min-share sits
        // between delay_cap and operator_base. That exercises the
        // branch where delay_cap < base < flow-aware expansion.
        queue.active_flow_buckets = 16;
        for bucket in 0..16 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }

        let cap = cos_flow_aware_buffer_limit(queue, 0);
        assert_eq!(
            cap, operator_base,
            "operator base ({operator_base}) must survive the clamp even when it exceeds \
             delay_cap (625_000) — the clamp is .min(delay_cap.max(base))"
        );

        // Counter-factual: a naive `.min(delay_cap)` (without
        // `.max(base)`) would have clamped the operator's explicit
        // 100 MiB down to 625 KB. Pin that this is NOT what we do.
        let naive_delay_cap = 625_000u64;
        assert!(
            cap > naive_delay_cap,
            "naive delay-only clamp would shrink operator intent to {naive_delay_cap}; the \
             `.max(base)` guard must preserve {operator_base}"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_preserves_non_flow_fair_path_after_clamp() {
        // #717: the latency clamp must not leak into the non-flow-fair
        // path. Pure rate-limited queues bypass both the floor and the
        // clamp and return the raw `buffer_bytes.max(COS_MIN_BURST_BYTES)`.
        // This is the companion to
        // `cos_flow_aware_buffer_limit_respects_non_flow_fair_queues`
        // but exercises the config shape where the delay cap *would*
        // have been tighter than the operator base, to catch a future
        // refactor that moves the clamp above the `flow_fair` early
        // return.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                // 1 Gbps → delay_cap = 625 KB.
                transmit_rate_bytes: 125_000_000,
                exact: true,
                surplus_weight: 1,
                // Operator configured 10 MB — well above delay_cap.
                // If the clamp leaks into this path, the returned cap
                // would be 625 KB, not 10 MB.
                buffer_bytes: 10 * 1_000_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = false;
        queue.active_flow_buckets = 64; // should be ignored

        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "flow_fair=false must bypass both the flow-aware floor and the latency clamp"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_delay_cap_scales_linearly_with_rate() {
        // #717: pin the delay-cap formula's linearity. Same active
        // flow count and same COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS, but
        // 10 Gbps vs 1 Gbps — the delay-cap-driven return must be 10×
        // larger. Catches future refactors that accidentally clamp
        // the rate (e.g. saturating at a hardcoded byte count) or
        // swap the product for a divide.
        fn run_at_rate(rate_bytes: u64) -> u64 {
            let mut root = test_cos_runtime_with_queues(
                25_000_000_000 / 8,
                vec![CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: rate_bytes,
                    exact: true,
                    surplus_weight: 1,
                    // Small operator base so the delay cap dominates.
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                }],
            );
            let queue = &mut root.queues[0];
            queue.flow_fair = true;
            // Populate all buckets so prospective_active × min-share
            // blows past the delay cap at both rates — the clamp is
            // what's being measured.
            queue.active_flow_buckets = COS_FLOW_FAIR_BUCKETS as u16;
            for bucket in 0..COS_FLOW_FAIR_BUCKETS {
                queue.flow_bucket_bytes[bucket] = 1_000;
            }
            cos_flow_aware_buffer_limit(queue, 0)
        }

        // 1 Gbps decimal: 125_000_000 B/s × 5 ms = 625_000 B.
        let cap_1g = run_at_rate(125_000_000);
        // 10 Gbps decimal: 1_250_000_000 B/s × 5 ms = 6_250_000 B.
        let cap_10g = run_at_rate(1_250_000_000);

        assert_eq!(cap_1g, 625_000);
        assert_eq!(cap_10g, 6_250_000);
        assert_eq!(
            cap_10g,
            cap_1g * 10,
            "delay cap must scale linearly with transmit_rate_bytes \
             (1 Gbps → {cap_1g}, 10 Gbps → {cap_10g})"
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

    /// #785 Phase 3 — head-keyed MQFQ ordering with equal-byte
    /// packets. Three flows, equal 1500-byte packets, 1111 has
    /// two packets, 1112 and 1113 have one each.
    ///
    /// Post-enqueue HEAD finish times (the selection key):
    ///   bucket(1111) head=1500 tail=3000 (head unchanged when
    ///     second packet arrives at tail of active bucket)
    ///   bucket(1112) head=tail=1500
    ///   bucket(1113) head=tail=1500
    ///
    /// All heads tie at 1500. Ties broken by ring insertion
    /// order (1111 enqueued first, wins). After pop of 1111
    /// pkt1, bucket 1111 is still active; head advances to
    /// `old_head + bytes(new head packet) = 1500 + 1500 = 3000`.
    /// Now 1112 and 1113 lead at head=1500, so they drain before
    /// 1111 pkt2.
    ///
    /// For equal-byte packets, MQFQ produces the SAME service
    /// order as DRR — they're byte-rate equivalent when all
    /// packets are the same size. The MQFQ divergence from DRR
    /// shows up on mixed-size packets (see
    /// `flow_fair_queue_mqfq_bytes_rate_fair_on_mixed_packet_sizes`).
    ///
    /// This test's value is pinning the head-finish mechanism's
    /// internal correctness: head advances on non-drain pop,
    /// tail advances on enqueue, tie-break = insertion order.
    /// Codex HIGH on the first revision keyed selection off TAIL
    /// finish, which broke this equivalence and produced an
    /// A,A,B,B burst pattern.
    #[test]
    fn flow_fair_queue_pops_in_virtual_finish_order_local() {
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

        // Equal-byte packets: MQFQ order matches DRR round-robin.
        // After popping 1111 pkt1, bucket 1111's head advances to
        // 3000; 1112 and 1113 still sit at 1500 and drain next.
        assert_eq!(
            order,
            vec![1111, 1112, 1113, 1111],
            "#785 Phase 3: with equal-byte packets the head-keyed \
             MQFQ order matches DRR round-robin — both are byte-\
             rate fair on uniform packet sizes. Regression here = \
             MQFQ ordering is broken (e.g. TAIL-keyed selection \
             produces the A,A,B,B burst [1111, 1111, 1112, 1113]).",
        );
        assert_eq!(queue.active_flow_buckets, 0);
        assert!(queue.flow_rr_buckets.is_empty());
        // #913 — MQFQ served-finish semantics: vtime tracks the
        // finish time of the last served packet, not the
        // aggregate bytes drained. With pop order
        // [1111, 1112, 1113, 1111] each picking a bucket whose
        // head_finish=1500 (and the last pop seeing head_finish=
        // 3000 after head-advance), `max(0,1500,1500,1500,3000)
        // = 3000`. Pre-#913 (aggregate-bytes) would have given
        // Σbytes = 6000.
        assert_eq!(
            queue.queue_vtime, 3000,
            "vtime tracks last served packet's finish-time \
             (MQFQ served-finish), not aggregate bytes drained \
             (pre-#913 SFQ V(t))"
        );
    }

    /// #785 Phase 3 — MQFQ byte-rate fairness on MIXED packet sizes.
    /// This is where MQFQ actually diverges from DRR.
    ///
    /// Flow 1111: one 3000-byte packet (e.g. GSO-coalesced).
    /// Flow 1112: one 1500-byte packet.
    /// Flow 1113: one 1500-byte packet.
    ///
    /// DRR (packet-count fair) order: [1111, 1112, 1113] — one
    /// packet per round. Flow 1111 gets 3000 bytes drained while
    /// flows 1112/1113 get only 1500 each → NOT byte-rate fair.
    ///
    /// MQFQ (byte-rate fair) order: [1112, 1113, 1111] — 1111's
    /// finish is 3000 (byte count) while 1112/1113 sit at 1500,
    /// so 1111 drains LAST. Over 6000 bytes of drain, every flow
    /// gets exactly 1/3 = 2000 bytes of virtual time budget, not
    /// 1/3 of the packet count.
    ///
    /// This is the property that closes the #785 CoV gap under TCP
    /// pacing: a flow with smaller cwnd sends fewer/smaller packets
    /// per RTT; DRR lets the busier flow sweep its polls, while
    /// MQFQ reserves drain slots proportional to byte rate.
    #[test]
    fn flow_fair_queue_mqfq_bytes_rate_fair_on_mixed_packet_sizes() {
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

        cos_queue_push_back(queue, test_flow_cos_item(1111, 3000));
        cos_queue_push_back(queue, test_flow_cos_item(1112, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1113, 1500));

        // Head finishes: 1111=3000, 1112=1500, 1113=1500.
        // MQFQ pops smallest: 1112, then 1113 (tie-break on ring
        // insertion order), then 1111 last.
        let mut order = Vec::new();
        while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
            order.push(req.flow_key.expect("flow key").src_port);
        }

        assert_eq!(
            order,
            vec![1112, 1113, 1111],
            "#785 Phase 3: MQFQ MUST pop the larger-byte packet \
             LAST so all three flows get equal byte share over the \
             test window. DRR order [1111, 1112, 1113] is packet-\
             count fair but NOT byte-rate fair — flow 1111 gets 2× \
             the bytes of the others. Regression here collapses \
             MQFQ to DRR and re-opens the #785 CoV gap.",
        );
    }

    /// #785 Phase 3 Rust reviewer MEDIUM #3 — golden-vector table
    /// pinning MQFQ pop order across a small matrix of mixed-size
    /// inputs. Each row encodes (packet_sizes_per_flow,
    /// expected_mqfq_pop_order_by_src_port,
    /// reference_drr_pop_order_by_src_port).
    ///
    /// The DRR reference column is a static assertion of "what
    /// packet-count-fair DRR would produce" for the same input —
    /// kept as a golden vector rather than executed against a live
    /// DRR implementation (the old DRR path has been removed from
    /// this tree). The value of the table is regression-testing
    /// the tie-break rule in `cos_queue_min_finish_bucket` and
    /// locking the MQFQ-vs-DRR divergence into the test surface.
    ///
    /// Flow-to-bucket hashing depends on `flow_hash_seed=0` and
    /// the current `cos_flow_bucket_index` formula; if that hash
    /// changes, `insertion_port_order` below may need updating —
    /// test will fail with a clear "bucket collision" or
    /// "wrong port drains first" message.
    #[test]
    fn mqfq_golden_vector_pop_order_vs_drr() {
        struct GoldenRow {
            name: &'static str,
            // (src_port, bytes) tuples in push_back order.
            packets: &'static [(u16, usize)],
            // Expected MQFQ pop order (by src_port).
            mqfq_order: &'static [u16],
            // Reference DRR order (documented, not asserted against
            // live DRR).
            drr_order: &'static [u16],
        }

        const TABLE: &[GoldenRow] = &[
            // All packets same size: MQFQ and DRR produce identical
            // orderings (both are byte-rate fair on uniform sizes).
            GoldenRow {
                name: "equal-1500-two-flows",
                packets: &[(2001, 1500), (2001, 1500), (2002, 1500), (2002, 1500)],
                mqfq_order: &[2001, 2002, 2001, 2002],
                drr_order: &[2001, 2002, 2001, 2002],
            },
            // 2x size disparity, two flows. MQFQ pops the smaller
            // packet first (head=1500 vs 3000). After that pop,
            // flow B's second packet becomes its head at
            // head=1500+1500=3000 (active-bucket head advance on
            // non-drain pop). Flow A's head is still 3000. Tie on
            // head — insertion-order tie-break picks A (its bucket
            // was added to the ring first). Then B's last packet
            // drains. Order: B, A, B.
            //
            // DRR rotation would be A, B, B (larger inserted first;
            // DRR walks ring insertion order per round, not finish
            // time). Orders differ → this row proves MQFQ's
            // tie-break and non-drain-head-advance invariants
            // diverge from DRR on size-disparate traffic.
            GoldenRow {
                name: "mixed-3000-1500-two-flows",
                packets: &[(2101, 3000), (2102, 1500), (2102, 1500)],
                mqfq_order: &[2102, 2101, 2102],
                drr_order: &[2101, 2102, 2102],
            },
            // 3-way mixed: 2000 vs 1000 vs 500. MQFQ orders by
            // head finish (500, 1000, 2000) and then catches up.
            // DRR rotates insertion order (2201, 2202, 2203, ...).
            GoldenRow {
                name: "mixed-three-flows-progressive-sizes",
                packets: &[(2201, 2000), (2202, 1000), (2203, 500)],
                mqfq_order: &[2203, 2202, 2201],
                drr_order: &[2201, 2202, 2203],
            },
        ];

        for row in TABLE {
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

            for (src_port, bytes) in row.packets {
                cos_queue_push_back(queue, test_flow_cos_item(*src_port, *bytes));
            }

            let mut mqfq_order = Vec::with_capacity(row.packets.len());
            while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
                mqfq_order.push(req.flow_key.expect("flow key").src_port);
            }

            assert_eq!(
                mqfq_order, row.mqfq_order,
                "#785 Phase 3 golden vector '{}': MQFQ pop order \
                 mismatch. Expected {:?} (byte-rate fair), got \
                 {:?}. DRR reference would be {:?} — if the actual \
                 matches DRR, MQFQ has collapsed to packet-count \
                 fairness and the #785 CoV gap has reopened.",
                row.name, row.mqfq_order, mqfq_order, row.drr_order,
            );
        }

        // Separately assert that AT LEAST ONE row in the table
        // diverges MQFQ from DRR — otherwise the golden vector
        // isn't demonstrating the MQFQ advantage at all (equal-
        // size rows are expected to match; mixed-size rows are
        // the discriminating cases). A regression that collapses
        // MQFQ to DRR flips at least one mixed-size row's output
        // to the drr_order column, failing the assert_eq above.
        let any_divergent = TABLE.iter().any(|row| row.mqfq_order != row.drr_order);
        assert!(
            any_divergent,
            "#785 Phase 3 golden vector table must include at \
             least one row where MQFQ diverges from DRR; otherwise \
             the table is not demonstrating byte-rate fairness vs. \
             packet-count fairness.",
        );
    }

    /// #785 Phase 3 Rust reviewer LOW — idle-return anchor pin.
    /// Complements `mqfq_queue_vtime_advances_by_drained_bytes`
    /// and `mqfq_bucket_drain_resets_finish_time` by asserting the
    /// CONSEQUENCE of those invariants: a flow that idles while
    /// others drain must re-anchor at `queue_vtime + bytes`, NOT
    /// sweep past established flows by re-entering at 0.
    ///
    /// Without the idle re-anchor, a bursty flow that goes silent
    /// and returns would drain all its packets before the active
    /// flow got another slot (anchor=0+bytes wins every min-scan
    /// for several rounds). With it, the returning flow competes
    /// at the current frontier and interleaves correctly.
    #[test]
    fn mqfq_idle_flow_reanchors_at_frontier_not_zero() {
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

        let flow_a = test_session_key(3301, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(3302, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        // Drain flow A for 3 x 1500 = 4500 bytes. vtime reaches
        // 4500.
        for _ in 0..3 {
            cos_queue_push_back(queue, test_flow_cos_item(3301, 1500));
        }
        for _ in 0..3 {
            let _ = cos_queue_pop_front(queue);
        }
        assert_eq!(queue.queue_vtime, 4500);

        // Flow B was idle the whole time. It now returns with a
        // 1200-byte packet. It MUST anchor at queue_vtime+bytes =
        // 4500+1200 = 5700, NOT at 0+1200 = 1200.
        cos_queue_push_back(queue, test_flow_cos_item(3302, 1200));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], 5700,
            "#785 Phase 3: idle-returning bucket MUST re-anchor at \
             current queue_vtime, not 0. Anchoring at 0 lets the \
             returning flow sweep past all established flows for \
             several rounds (#785 CoV regression).",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_b], 5700);
    }

    /// #785 Phase 3 — same mixed-size byte-rate ordering on the
    /// Prepared (zero-copy) path. Both Local and Prepared variants
    /// must share MQFQ ordering; the pop path picks by finish time
    /// regardless of item kind.
    #[test]
    fn flow_fair_queue_pops_in_virtual_finish_order_prepared() {
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

        // 3000-byte packet on 1111, 1500-byte packets on 1112.
        cos_queue_push_back(queue, test_flow_prepared_cos_item(1111, 3000, 64));
        cos_queue_push_back(queue, test_flow_prepared_cos_item(1112, 1500, 192));

        let mut order = Vec::new();
        while let Some(CoSPendingTxItem::Prepared(req)) = cos_queue_pop_front(queue) {
            order.push(req.flow_key.expect("flow key").src_port);
        }

        assert_eq!(
            order,
            vec![1112, 1111],
            "Prepared-path MQFQ ordering must match Local-path: \
             smaller-finish drains first regardless of variant.",
        );
    }

    // ---------------------------------------------------------------------
    // #785 Phase 3 — MQFQ virtual-finish-time mechanism pins.
    // ---------------------------------------------------------------------

    /// Pin the enqueue-side VFT formula:
    /// `finish[b] = max(finish[b], queue.vtime) + bytes`.
    ///
    /// Three sub-properties:
    /// 1. On first packet of a newly-active bucket, finish = vtime + bytes.
    /// 2. Subsequent packets on the same bucket advance finish by bytes.
    /// 3. Different flow sizes produce proportional finish-time deltas.
    ///
    /// Regression: if the formula loses either the `max(finish, vtime)`
    /// anchor (idle bucket re-anchor) or the `+ bytes` step (cumulative
    /// byte accounting), ordering silently mis-sorts under TCP pacing.
    #[test]
    fn mqfq_enqueue_bumps_finish_time_by_byte_count() {
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
        // Simulate the queue having already drained to vtime=5000.
        queue.queue_vtime = 5000;

        let flow_a = test_session_key(1111, 5201);
        let flow_b = test_session_key(2222, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "fixture flow keys must not collide");

        // Packet 1 of flow A — bucket was idle (finish=0). Re-anchor
        // to queue.vtime (5000) then + 1500.
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 6500,
            "first packet on an idle bucket re-anchors to queue.vtime \
             + bytes (5000 + 1500 = 6500)",
        );

        // Packet 2 of flow A — already-active. finish advances by bytes.
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 8000,
            "subsequent packet on the same active bucket advances by \
             exactly bytes (6500 + 1500 = 8000)",
        );

        // Packet 1 of flow B — independent bucket, same re-anchor.
        account_cos_queue_flow_enqueue(queue, Some(&flow_b), 500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], 5500,
            "different-sized packet produces proportional finish \
             delta (5000 + 500 = 5500)",
        );
    }

    /// Pin that a bucket's finish-time is RESET to 0 when the last
    /// packet drains from it. Without this reset, a bucket that goes
    /// idle and later re-activates would inherit its stale lifetime
    /// finish-time — the enqueue-side `max(finish, vtime)` anchor
    /// would be no-op'd (finish >> vtime), letting the returning flow
    /// skip ahead of all established flows in bounded rounds.
    #[test]
    fn mqfq_bucket_drain_resets_finish_time() {
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

        let flow = test_session_key(3333, 5201);
        let bucket = cos_flow_bucket_index(0, Some(&flow));

        cos_queue_push_back(queue, test_flow_cos_item(3333, 1500));
        assert!(queue.flow_bucket_head_finish_bytes[bucket] > 0);
        assert!(queue.flow_bucket_tail_finish_bytes[bucket] > 0);

        // Drain the only packet. Bucket is now empty.
        let _ = cos_queue_pop_front(queue);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket], 0,
            "bucket drain to 0 MUST reset head-finish-time",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket], 0,
            "bucket drain to 0 MUST reset tail-finish-time so the \
             next enqueue re-anchors at queue.vtime, not the stale \
             lifetime finish",
        );
    }

    /// #913 — Pin the `queue.vtime` semantics: MQFQ served-finish.
    /// Vtime advances to track the served packet's finish time
    /// (which equals the smallest head_finish across active
    /// buckets at pop time, since MQFQ pops min-finish-first).
    /// This is the "system frontier" — re-enqueued idle buckets
    /// compare against it in `max(bucket_finish, queue_vtime) +
    /// bytes` so a returning flow starts at the current
    /// frontier, not back at 0.
    ///
    /// In this single-flow test, served_finish progresses
    /// 1500 → 3000 → 4500 (head advances by next-packet bytes
    /// after each pop). vtime = max(prev, served) tracks the
    /// progression — same numerical result as the pre-#913
    /// aggregate-bytes formulation, by coincidence in the
    /// single-flow case. The cross-flow test
    /// `mqfq_vtime_does_not_accumulate_across_flows` (below)
    /// shows where the two semantics actually diverge.
    #[test]
    fn mqfq_queue_vtime_tracks_served_finish_time() {
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

        // Three packets on one flow. After enqueue, bucket_finish
        // = 4500 (the 3rd packet's finish). But queue.vtime should
        // advance by 1500 per pop, not jump to 4500 on the first.
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));

        assert_eq!(queue.queue_vtime, 0);

        let _ = cos_queue_pop_front(queue);
        assert_eq!(
            queue.queue_vtime, 1500,
            "first pop: vtime tracks served packet's finish_time \
             (1500 = head_finish of the 1st packet)",
        );
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 3000);
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 4500);
    }

    /// #913 — Distinguishing test: vtime must NOT accumulate
    /// across flows. This test would FAIL under the pre-#913
    /// aggregate-bytes formulation and PASS under the new MQFQ
    /// served-finish formulation. It's the bug-trip that would
    /// have caught the original SFQ-V(t) implementation if it
    /// had existed at the time the original code landed.
    ///
    /// Setup: 10 distinct flows, one 1500-byte packet each. Pop
    /// one packet from each flow in MQFQ order (10 pops). Every
    /// flow's bucket has head_finish=1500 at enqueue (vtime=0).
    ///
    /// Pre-#913 (aggregate-bytes): vtime advances by 1500 per
    /// pop → final = 10 × 1500 = 15000.
    ///
    /// New (MQFQ served-finish): each pop sees served_finish=
    /// 1500 (every flow's first packet); `vtime = max(prev,
    /// 1500)` never advances past the first round → final =
    /// 1500.
    ///
    /// Why this matters for #911: under the old semantics, a
    /// mouse arriving after N rounds of elephant draining
    /// anchored at vtime + bytes = N × MTU + small ≫ active
    /// buckets' head_finish, so MQFQ served the mouse LAST.
    /// Under new semantics, vtime tracks the served frontier
    /// and the mouse interleaves with elephants.
    #[test]
    fn mqfq_vtime_does_not_accumulate_across_flows() {
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

        // Enqueue one 1500-byte packet on each of 10 distinct
        // flows. After enqueue, every bucket has head=tail=1500.
        // Copilot review: select flow IDs dynamically so the test
        // doesn't couple to a specific hash distribution. We
        // sweep candidate IDs and accept the first 10 that land
        // in distinct buckets.
        let mut buckets: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let mut accepted: Vec<u16> = Vec::with_capacity(10);
        for flow_id in 1000u16..2000u16 {
            let key = test_session_key(flow_id, 5201);
            let bucket = cos_flow_bucket_index(0, Some(&key));
            if buckets.insert(bucket) {
                accepted.push(flow_id);
                if accepted.len() == 10 {
                    break;
                }
            }
        }
        assert_eq!(
            accepted.len(),
            10,
            "test setup: 10 distinct buckets must be selectable in [1000, 2000)"
        );
        for flow_id in accepted {
            cos_queue_push_back(queue, test_flow_cos_item(flow_id, 1500));
        }
        assert_eq!(queue.queue_vtime, 0);
        assert_eq!(queue.active_flow_buckets, 10);

        // Pop all 10 items via MQFQ (min head_finish first).
        for _ in 0..10 {
            assert!(cos_queue_pop_front(queue).is_some());
        }

        assert_eq!(
            queue.queue_vtime, 1500,
            "#913 MQFQ: vtime tracks served-packet finish, \
             not aggregate bytes drained. Each pop sees the \
             same head_finish=1500 across the 10 distinct \
             flows; max(0,1500,1500,...,1500) = 1500. \
             Pre-#913 aggregate-bytes would have given \
             10 × 1500 = 15000."
        );
        assert_eq!(queue.active_flow_buckets, 0);
    }

    /// #913 — Codex code review HIGH regression. Scratch-builder
    /// Drop must preserve the dropped item's vtime contribution
    /// across multi-survivor restore, otherwise a new idle flow
    /// can jump ahead of the restored active buckets — exactly
    /// the temporal-inversion class of bug #913 was supposed to
    /// fix.
    ///
    /// Setup: 3 distinct flows X (head 1500), Y (head 2000), Z
    /// (head 3000). Pop in MQFQ order (X→Y→Z); `queue_vtime`
    /// advances 0 → 1500 → 2000 → 3000.
    ///
    /// Simulate Z dropped: invoke
    /// `cos_queue_clear_orphan_snapshot_after_drop` (the helper
    /// the four scratch-builder Drop sites call). Z's snapshot is
    /// removed and remaining (X, Y) snapshots get clamped so
    /// their `pre_pop_queue_vtime` ≥ 3000.
    ///
    /// Restore Y, then X via `cos_queue_push_front`. After both
    /// restores, `queue_vtime` MUST be ≥ 3000 (Z's commit
    /// preserved). Bucket heads/tails restored exactly.
    ///
    /// Then enqueue a new idle flow W (small bytes) and assert
    /// W's head_finish ≥ X/Y's head_finish so W cannot jump the
    /// restored active set.
    #[test]
    fn mqfq_scratch_drop_preserves_vtime_for_multi_survivor_restore() {
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

        // Distinct buckets X / Y / Z with mixed packet sizes so
        // each has a unique head_finish (avoids the "all-equal"
        // numeric-coincidence case). Copilot review: select flow
        // IDs dynamically so the test doesn't couple to a
        // specific hash distribution.
        let mut seen: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let mut picks: Vec<u16> = Vec::with_capacity(3);
        for flow_id in 7001u16..8001u16 {
            let bucket = cos_flow_bucket_index(
                0,
                Some(&test_session_key(flow_id, 5201)),
            );
            if seen.insert(bucket) {
                picks.push(flow_id);
                if picks.len() == 3 {
                    break;
                }
            }
        }
        assert_eq!(
            picks.len(),
            3,
            "test setup: 3 distinct buckets must be selectable in [7001, 8001)"
        );
        let (flow_x_id, flow_y_id, flow_z_id) = (picks[0], picks[1], picks[2]);
        cos_queue_push_back(queue, test_flow_cos_item(flow_x_id, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(flow_y_id, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(flow_z_id, 3000));
        let key_x = test_session_key(flow_x_id, 5201);
        let key_y = test_session_key(flow_y_id, 5201);
        let key_z = test_session_key(flow_z_id, 5201);
        let bucket_x = cos_flow_bucket_index(0, Some(&key_x));
        let bucket_y = cos_flow_bucket_index(0, Some(&key_y));
        let bucket_z = cos_flow_bucket_index(0, Some(&key_z));

        let pre_batch_head_x = queue.flow_bucket_head_finish_bytes[bucket_x];
        let pre_batch_head_y = queue.flow_bucket_head_finish_bytes[bucket_y];
        let pre_batch_head_z = queue.flow_bucket_head_finish_bytes[bucket_z];
        assert_eq!(pre_batch_head_x, 1500);
        assert_eq!(pre_batch_head_y, 2000);
        assert_eq!(pre_batch_head_z, 3000);

        // Pop X, Y, Z in MQFQ order.
        let popped_x = cos_queue_pop_front(queue).expect("pop X");
        let popped_y = cos_queue_pop_front(queue).expect("pop Y");
        let _popped_z = cos_queue_pop_front(queue).expect("pop Z");
        assert_eq!(
            queue.queue_vtime, 3000,
            "after X→Y→Z pops, vtime tracks served-finish frontier (max=3000)"
        );
        assert_eq!(queue.pop_snapshot_stack.len(), 3);

        // Simulate Z dropped (e.g., frame too big in scratch builder).
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);
        assert_eq!(
            queue.queue_vtime, 3000,
            "Drop preserves the committed vtime advance"
        );

        // Restore Y first (LIFO), then X.
        cos_queue_push_front(queue, popped_y);
        assert!(
            queue.queue_vtime >= 3000,
            "after Y restore, vtime must NOT regress below Z's commit \
             (got {})",
            queue.queue_vtime
        );
        cos_queue_push_front(queue, popped_x);
        assert!(
            queue.queue_vtime >= 3000,
            "after X restore, vtime must NOT regress below Z's commit \
             (got {})",
            queue.queue_vtime
        );
        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "all snapshots consumed by restore"
        );

        // X and Y bucket head_finish restored to pre-pop values.
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_x], pre_batch_head_x);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_y], pre_batch_head_y);

        // Now enqueue a new idle flow W with a small packet. Pick
        // its flow ID dynamically so its bucket is distinct from
        // the restored X and Y buckets.
        let mut flow_w_id: u16 = 0;
        for candidate in 8001u16..9001u16 {
            let bucket = cos_flow_bucket_index(
                0,
                Some(&test_session_key(candidate, 5201)),
            );
            if bucket != bucket_x && bucket != bucket_y && bucket != bucket_z {
                flow_w_id = candidate;
                break;
            }
        }
        assert_ne!(flow_w_id, 0, "test setup: distinct W bucket selectable");
        cos_queue_push_back(queue, test_flow_cos_item(flow_w_id, 100));
        let key_w = test_session_key(flow_w_id, 5201);
        let bucket_w = cos_flow_bucket_index(0, Some(&key_w));
        let w_head = queue.flow_bucket_head_finish_bytes[bucket_w];

        // CORE ASSERTION: W cannot jump ahead of the restored
        // active buckets X/Y. Pre-#913 (or pre-Drop-vtime-fix),
        // vtime would have regressed to 0 and W would anchor at
        // max(0,0)+100 = 100, jumping ahead of X (1500) and Y
        // (2000). With Drop's vtime preserved at ≥ 3000, W
        // anchors at max(0, 3000) + 100 = 3100, which is past
        // X and Y.
        assert!(
            w_head >= pre_batch_head_x,
            "Codex regression: new idle flow W (head={}) must NOT \
             jump ahead of restored bucket X (head={}) — \
             dropped Z's vtime contribution must be preserved",
            w_head, pre_batch_head_x
        );
        assert!(
            w_head >= pre_batch_head_y,
            "Codex regression: new idle flow W (head={}) must NOT \
             jump ahead of restored bucket Y (head={})",
            w_head, pre_batch_head_y
        );
    }

    /// #913 — Codex code review R8/R9 regression. Same-bucket
    /// multi-pop with intermediate Drop: under MQFQ
    /// "drops consume virtual service" semantics, the dropped
    /// item's contribution must be preserved so that surviving
    /// packets in the same bucket retain their original
    /// finish-time positions.
    ///
    /// Setup: bucket A has 3 packets [1000, 2000, 1500].
    /// Initial state at enqueue: head_A=1000, tail_A=4500.
    /// Original finish times: A1=1000, A2=3000, A3=4500.
    ///
    /// Pop A1 (1000-byte): head advances to 3000 (bytes(A2)).
    /// Pop A2 (2000-byte): head advances to 4500 (bytes(A3)).
    /// Drop A2 (frame too big). Orphan-cleanup helper pops
    /// snap_2 and clamps snap_1.pre_pop_queue_vtime.
    ///
    /// Restore A1 via push_front. Bucket has [A3] at this point
    /// (was_empty=false), so the active-bucket arithmetic runs:
    /// `head -= bytes(current_head=A3=1500) = 4500-1500 = 3000`.
    ///
    /// THIS IS CORRECT under MQFQ drops-consume semantics:
    /// head=3000 means "the bucket's frontier is at 3000 (post-
    /// A2's virtual service)." When A1 is then popped:
    /// `head += bytes(A3=1500) = 4500`. A3 ends up at finish=4500
    /// — its ORIGINAL position — preserving A2's contribution.
    /// Competing buckets with finish 3000-4500 correctly drain
    /// before A3, no scheduling inversion.
    ///
    /// (Naive alternative: restore head from snap.pre_pop_head=1000
    /// would lose A2's contribution. After pop A1: head=1000+1500=
    /// 2500; A3 ends up at 2500 instead of 4500. Competing buckets
    /// at finish 2500-4500 would unfairly drain after A3 — that's
    /// the scheduling inversion Codex R9 flagged.)
    #[test]
    fn mqfq_same_bucket_multipop_drop_preserves_dropped_item_finish() {
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

        // Single bucket A, 3 packets with mixed sizes.
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1500));
        let key_a = test_session_key(8001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&key_a));

        // Pop A1 (1000B). head_finish advances to 3000.
        let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 3000);

        // Pop A2 (2000B). head_finish advances to 4500.
        let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 4500);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);

        // Simulate A2 dropped via the scratch-builder Drop helper.
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 1);

        // Restore A1 via push_front. Active-bucket arithmetic:
        // head=4500 - bytes(A3=1500) = 3000. This is the
        // post-A2-pop value; A2's "virtual service" is preserved.
        cos_queue_push_front(queue, popped_a1);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3000,
            "post-restore head_finish should be 3000 (post-A2-pop \
             value, preserving A2's virtual-service contribution)"
        );

        // Critical Codex R9 assertion: pop A1 again, then verify
        // A3 lands at its original finish=4500, NOT 2500.
        // This is the scheduling-correctness gate — A3 must NOT
        // jump ahead of competing buckets that were originally
        // scheduled between A2's and A3's finish times.
        let _popped_a1_again = cos_queue_pop_front(queue).expect("pop A1 again");
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 4500,
            "Codex R9 regression: after dropping A2 and re-popping \
             A1, A3 must remain at its original finish=4500 (not \
             2500). Otherwise A3 jumps ahead of competing buckets \
             that were originally scheduled in the [3000, 4500) \
             window — exactly the temporal inversion #913 was \
             supposed to prevent."
        );
    }

    /// #927: drained-bucket scenario. Bucket A holds [A1=1000B,
    /// A2=2000B], bucket C holds [C=2500B]. Scratch builder pops
    /// A1+C+A2 in that order. A2's pop drains bucket A (last item).
    /// A2 is then dropped (frame too big, etc.). The orphan-cleanup
    /// helper must preserve A2's served_finish = 3000 across the
    /// restore so that A1's restored frontier is ≥ 3000. Otherwise
    /// the `was_empty` snapshot path in `cos_queue_push_front`
    /// would restore A.head=1000 (the snap_1.pre_pop_head_finish
    /// captured before A2's pop), and MQFQ would pop A1 BEFORE
    /// C — inverting their original scheduling order.
    #[test]
    fn mqfq_drained_bucket_orphan_drop_preserves_served_finish() {
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

        // Bucket A: [A1=1000, A2=2000]. Bucket C: [C=2500].
        // Two distinct flow keys so they hash to distinct buckets.
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(8002, 2500));
        let key_a = test_session_key(8001, 5201);
        let key_c = test_session_key(8002, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
        let bucket_c = cos_flow_bucket_index(0, Some(&key_c));
        assert_ne!(
            bucket_a, bucket_c,
            "test setup: ports 8001/8002 must hash to distinct buckets"
        );

        // Pre-pop frontier:
        //   A.head=1000 (A1 finish), A.tail=3000 (A2 finish).
        //   C.head=C.tail=2500.
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 1000);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 3000);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 2500);

        // Pop A1: head_finish[A] advances to 3000 (A2 finish-time).
        let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 3000);

        // Pop C: MQFQ picks min-finish-first; with A.head=3000
        // and C.head=2500, C.head < A.head so C is the next pop.
        // After pop: bucket C empty; C.head_finish reset to 0.
        let popped_c = cos_queue_pop_front(queue).expect("pop C");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 0);

        // Pop A2 (last in A): bucket A drains, A.head_finish reset
        // to 0. queue_vtime reflects all three pops.
        let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.pop_snapshot_stack.len(), 3);

        // Simulate A2 dropped (e.g., frame too big to transmit).
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);

        // Restore C via push_front: bucket C is empty so the
        // `was_empty` snapshot path applies. C.head should restore
        // to snap_C.pre_pop_head_finish = 2500.
        cos_queue_push_front(queue, popped_c);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 2500);

        // Restore A1 via push_front: bucket A is empty so the
        // `was_empty` snapshot path applies. WITHOUT #927, A.head
        // would restore to snap_1.pre_pop_head_finish = 1000 —
        // inverting MQFQ order vs C (1000 < 2500). WITH #927, the
        // orphan-cleanup helper bumped snap_1.pre_pop_head_finish
        // up to A2's served_finish = 3000, so the restored A.head
        // = 3000 > C.head = 2500 — MQFQ correctly picks C first.
        cos_queue_push_front(queue, popped_a1);
        assert!(
            queue.flow_bucket_head_finish_bytes[bucket_a]
                > queue.flow_bucket_head_finish_bytes[bucket_c],
            "#927 regression: A.head ({}) must be strictly greater than \
             C.head ({}) so MQFQ picks C first. Without the orphan-cleanup \
             same-bucket frontier bump, A.head would restore to 1000 and \
             A1 would pop before C — inverting their original schedule.",
            queue.flow_bucket_head_finish_bytes[bucket_a],
            queue.flow_bucket_head_finish_bytes[bucket_c],
        );
    }

    /// Pin that `FlowRrRing::remove` correctly de-registers a bucket
    /// from an arbitrary position. The MQFQ pop path calls this when
    /// a bucket at non-head position (determined by finish-time, not
    /// ring order) drains to empty.
    #[test]
    fn flow_rr_ring_remove_from_middle() {
        let mut ring = FlowRrRing::default();
        ring.push_back(10);
        ring.push_back(20);
        ring.push_back(30);
        ring.push_back(40);
        assert_eq!(ring.len(), 4);

        // Remove from the middle.
        assert!(ring.remove(20));
        assert_eq!(ring.len(), 3);
        let ids: Vec<u16> = ring.iter().collect();
        assert_eq!(ids, vec![10, 30, 40]);

        // Remove head-adjacent.
        assert!(ring.remove(10));
        assert_eq!(ring.len(), 2);
        let ids: Vec<u16> = ring.iter().collect();
        assert_eq!(ids, vec![30, 40]);

        // Remove missing (no-op).
        assert!(!ring.remove(999));
        assert_eq!(ring.len(), 2);

        // Remove tail.
        assert!(ring.remove(40));
        assert_eq!(ring.len(), 1);
        let ids: Vec<u16> = ring.iter().collect();
        assert_eq!(ids, vec![30]);

        // Remove last.
        assert!(ring.remove(30));
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
    }

    /// Pin that on a shared_exact flow-fair queue, the admission
    /// gates downgrade to aggregate-only — rate-unaware per-flow
    /// cap would tail-drop TCP at the 24 KB floor on a 25 Gbps
    /// queue with 12 flows. Retrospective Attempt A measured 8 Gbps
    /// throughput regression when this downgrade was absent.
    #[test]
    fn mqfq_shared_exact_admission_downgrades_to_aggregate() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.flow_hash_seed = 0;

        let target = 0usize;
        seed_sixteen_flow_buckets(queue, target, 1);
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);

        assert_eq!(
            share_cap, buffer_limit,
            "#785 Phase 3: shared_exact + flow_fair queues MUST use \
             aggregate-only admission (share_cap == buffer_limit). \
             Regression re-introduces the 24 KB per-flow floor that \
             tail-drops TCP at multi-Gbps per-flow rates.",
        );
    }

    /// #785 Phase 3 Codex round-2 HIGH: push_front onto an active
    /// bucket must be finish-time-neutral — a pop-and-restore
    /// round-trip must leave the queue in the same state it started.
    ///
    /// Without this invariant, TX-ring-full restoration paths
    /// (every flow-fair drain has one) corrupt the MQFQ selection
    /// key: push_front leaves head stale, subsequent non-drain pops
    /// advance head off the stale base, and bucket ordering drifts
    /// arbitrarily. Codex traced it with a three-packet bucket
    /// where a push_front mid-drain produced a 500-byte discrepancy
    /// on a 1500-byte packet's finish time.
    ///
    /// Round-3 extension (Codex HIGH): also pin `queue_vtime`
    /// neutrality. The prior revision advanced `queue_vtime` on
    /// pop-time but never rewound on push_front, biasing newly-
    /// active flows behind a phantom amount of drained bytes
    /// whenever TX-ring-full rolled a pop back onto the queue.
    ///
    /// Test: pop the head, observe advanced head-finish and vtime,
    /// push_front the popped item back, observe ALL of head-finish,
    /// tail-finish, bucket-bytes, AND queue_vtime returned to their
    /// pre-pop values.
    #[test]
    fn mqfq_push_front_is_finish_time_neutral_on_active_bucket() {
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

        // Enqueue three packets on one flow.
        cos_queue_push_back(queue, test_flow_cos_item(4444, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(4444, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(4444, 1500));

        let flow = test_session_key(4444, 5201);
        let bucket = cos_flow_bucket_index(0, Some(&flow));

        // Bucket state: head=1000, tail=4500.
        let pre_pop_head = queue.flow_bucket_head_finish_bytes[bucket];
        let pre_pop_tail = queue.flow_bucket_tail_finish_bytes[bucket];
        let pre_pop_bytes = queue.flow_bucket_bytes[bucket];
        let pre_pop_vtime = queue.queue_vtime;
        assert_eq!(pre_pop_head, 1000);
        assert_eq!(pre_pop_tail, 4500);
        assert_eq!(pre_pop_bytes, 4500);
        assert_eq!(pre_pop_vtime, 0);

        // Pop head (the 1000-byte packet). Head advances to 3000
        // (= pre_pop_head + bytes(new head = 2000)). vtime += 1000.
        let popped = cos_queue_pop_front(queue).expect("pop");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket], 3000);
        assert_eq!(queue.queue_vtime, 1000);

        // Push the same item back onto the front. Head-finish MUST
        // return to the pre-pop value (1000), AND queue_vtime MUST
        // return to its pre-pop value (0) — Codex round-3 HIGH.
        cos_queue_push_front(queue, popped);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket], pre_pop_head,
            "#785 Phase 3 Codex HIGH: push_front must be finish-\
             time-neutral on active buckets. Regression re-opens \
             the MQFQ ordering corruption on TX-ring-full retry.",
        );
        // Tail unchanged — we didn't add at tail.
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket], pre_pop_tail);
        assert_eq!(queue.flow_bucket_bytes[bucket], pre_pop_bytes);
        assert_eq!(
            queue.queue_vtime, pre_pop_vtime,
            "#785 Phase 3 Codex round-3 HIGH: queue_vtime must be \
             round-trip neutral on pop→push_front. Without this, \
             newly-active flows inherit an inflated vtime anchor \
             and start behind established traffic even though zero \
             bytes were actually transmitted during the rollback.",
        );
    }

    /// #785 Phase 3 Codex round-3 HIGH — companion pin for the
    /// DRAINED-bucket case (Rust reviewer MEDIUM #1). When the
    /// popped item is the SOLE packet in its bucket, the pop
    /// path's `account_cos_queue_flow_dequeue` resets head=tail=0
    /// AND the bucket deregisters from the active set. A naive
    /// push_front would hit the `was_empty` branch and re-anchor
    /// head=tail=`max(0, queue_vtime) + bytes`, which overshoots
    /// the pre-pop head by up to one packet and leaves the
    /// bucket competing at the wrong virtual-time.
    ///
    /// Fix: the last-pop snapshot records pre-pop head/tail at
    /// pop time; push_front restores them exactly when the
    /// snapshot's bucket matches.
    #[test]
    fn mqfq_push_front_is_neutral_on_drained_bucket_round_trip() {
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

        // Simulate a vtime that's already advanced (as it would
        // be mid-stream when other flows have drained), then
        // enqueue a single packet on flow A. The idle-bucket
        // re-anchor writes head=tail=max(tail=0, vtime=5000)+1500
        // = 6500.
        queue.queue_vtime = 5000;
        let flow_a = test_session_key(7777, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        cos_queue_push_back(queue, test_flow_cos_item(7777, 1500));

        let pre_pop_head = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_pop_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_pop_bytes = queue.flow_bucket_bytes[bucket_a];
        let pre_pop_vtime = queue.queue_vtime;
        let pre_pop_active = queue.active_flow_buckets;
        assert_eq!(pre_pop_head, 6500);
        assert_eq!(pre_pop_tail, 6500);
        assert_eq!(pre_pop_bytes, 1500);
        assert_eq!(pre_pop_vtime, 5000);

        // Pop the sole item. Bucket drains: head=tail=0, active
        // count -=1, vtime advances to 6500.
        let popped = cos_queue_pop_front(queue).expect("pop");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 0);
        assert_eq!(queue.queue_vtime, pre_pop_vtime + 1500);
        assert!(queue.flow_bucket_items[bucket_a].is_empty());

        // Restore it via push_front. Without the snapshot fix this
        // re-anchors to vtime+bytes = 6500+1500 = 8000 — one packet
        // past the pre-pop head of 6500. With the fix, head/tail
        // restore to 6500 exactly.
        cos_queue_push_front(queue, popped);

        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_pop_head,
            "#785 Phase 3 Codex round-3 HIGH / Rust MEDIUM #1: \
             push_front on a drained bucket must restore pre-pop \
             head exactly, not re-anchor one packet past it.",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], pre_pop_tail);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], pre_pop_bytes);
        assert_eq!(
            queue.queue_vtime, pre_pop_vtime,
            "#785 Phase 3: queue_vtime must rewind to pre-pop on \
             drained-bucket round-trip too.",
        );
        assert_eq!(queue.active_flow_buckets, pre_pop_active);
        assert_eq!(queue.flow_bucket_items[bucket_a].len(), 1);
    }

    /// #785 Phase 3 Codex round-2 NEW-1 — batched rollback on a
    /// SINGLE bucket must restore every pre-pop snapshot exactly,
    /// not just the most recent one.
    ///
    /// Scenario: N (=4) items enqueued on one flow, drained into
    /// scratch in one batch (simulating the TX-ring-full drain
    /// path), then rolled back in LIFO order via push_front.
    /// After rollback, every per-bucket field and `queue_vtime`
    /// must equal its pre-batch value.
    ///
    /// Prior revision kept a single `Option<CoSQueuePopSnapshot>`
    /// that each pop overwrote. On rollback only the FIRST
    /// push_front (matching the LAST pop) got its snapshot; all
    /// earlier restorations fell back to the idle-bucket
    /// `max(tail, queue_vtime) + bytes` re-anchor. For this
    /// single-bucket case the earlier restorations' ACTIVE branch
    /// did happen to produce the right answer (the restored item
    /// took over as the new head via `head -= bytes(front)`), BUT
    /// the drained-bucket case in the cross-bucket pin below
    /// overshoots without a per-pop stack. Both pins together
    /// cover single-bucket and multi-bucket correctness.
    #[test]
    fn mqfq_batched_rollback_restores_queue_vtime() {
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

        // Advance `queue_vtime` so that later flows anchor ahead
        // of zero (stresses the cross-bucket bug — an earlier pop
        // whose bucket drains resets head/tail to 0, then
        // `max(0, queue_vtime) + bytes` on re-enqueue overshoots
        // the pre-pop head).
        queue.queue_vtime = 3000;

        let flow_a = test_session_key(5555, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

        cos_queue_push_back(queue, test_flow_cos_item(5555, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 1200));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 800));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 1400));

        let pre_batch_head = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_batch_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_batch_bytes = queue.flow_bucket_bytes[bucket_a];
        let pre_batch_vtime = queue.queue_vtime;
        let pre_batch_active = queue.active_flow_buckets;
        let pre_batch_peak = queue.active_flow_buckets_peak;
        let pre_batch_items = queue.flow_bucket_items[bucket_a].len();
        assert_eq!(pre_batch_items, 4);

        // Drain all 4 into scratch. Stack grows to 4 snapshots.
        let mut scratch: Vec<CoSPendingTxItem> = Vec::with_capacity(4);
        while let Some(item) = cos_queue_pop_front(queue) {
            scratch.push(item);
        }
        assert_eq!(scratch.len(), 4);
        assert_eq!(
            queue.pop_snapshot_stack.len(),
            4,
            "NEW-1: every pop must push its own snapshot onto the \
             per-queue LIFO stack",
        );

        // Roll back all 4 in LIFO order (scratch.pop()). This
        // mirrors `restore_exact_local_scratch_to_queue_head_flow_fair`.
        while let Some(item) = scratch.pop() {
            cos_queue_push_front(queue, item);
        }

        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-1: snapshot stack must be fully consumed after a \
             complete rollback",
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_batch_head,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket HEAD finish exactly (single-bucket case)",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_batch_tail,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket TAIL finish exactly (single-bucket case)",
        );
        assert_eq!(
            queue.flow_bucket_bytes[bucket_a], pre_batch_bytes,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket byte count exactly",
        );
        assert_eq!(
            queue.queue_vtime, pre_batch_vtime,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             queue_vtime exactly — symmetric per-item rewind",
        );
        assert_eq!(
            queue.active_flow_buckets, pre_batch_active,
            "#785 Phase 3 NEW-1: batched rollback must leave \
             active_flow_buckets unchanged",
        );
        assert_eq!(
            queue.active_flow_buckets_peak, pre_batch_peak,
            "#785 Phase 3 NEW-1: peak counter is monotonic — \
             rollback must not bump it (no fresh high-water mark)",
        );
        assert_eq!(queue.flow_bucket_items[bucket_a].len(), pre_batch_items);
    }

    /// #785 Phase 3 Codex round-2 NEW-1 — batched rollback across
    /// MULTIPLE buckets. This is the case the prior single-
    /// `Option<CoSQueuePopSnapshot>` implementation got wrong:
    /// earlier drained buckets (i.e. not the MOST-recently-popped
    /// one) had no snapshot at rollback time and fell back to the
    /// idle re-anchor `max(tail=0, queue_vtime) + bytes`, which
    /// overshoots the pre-pop head whenever `queue_vtime` has
    /// advanced past the bucket's original enqueue point.
    ///
    /// Scenario construction:
    ///   1. Pre-advance `queue_vtime=100`; enqueue A (1500) and B
    ///      (900) at that frontier. pre-pop head[A]=1600,
    ///      head[B]=1000.
    ///   2. Force-advance `queue_vtime=5000` to simulate a long
    ///      period of other-flow drain activity between enqueue
    ///      and batch.
    ///   3. Drain both: pop B (head 1000 < 1600), then pop A.
    ///      vtime goes 5000 → 5900 → 7400. Both buckets drain,
    ///      head/tail=0.
    ///   4. Roll back LIFO. scratch.pop() returns A first, then B.
    ///
    /// With per-pop snapshots: A's restore pops snap_A from the
    /// stack and writes head[A]=1600. B's restore pops snap_B and
    /// writes head[B]=1000.
    ///
    /// Without per-pop snapshots (old single-`Option` impl):
    /// snapshot held {A, 1600, 1600} (last overwrote). A's restore
    /// uses it and succeeds. B's restore finds snapshot=None,
    /// falls through to `account_cos_queue_flow_enqueue`:
    /// head[B] = max(0, vtime_at_that_point=5000) + 900 = 5900,
    /// overshooting the pre-pop head of 1000 by 4900. THIS PIN
    /// TRIPS: without the fix the assertion on B's head-finish
    /// fails at 5900 != 1000.
    #[test]
    fn mqfq_batched_rollback_across_multiple_buckets() {
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

        // Step 1: low vtime so A and B anchor near 0.
        queue.queue_vtime = 100;

        let flow_a = test_session_key(6001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(6002, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        cos_queue_push_back(queue, test_flow_cos_item(6001, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(6002, 900));
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 1600);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_b], 1000);

        // Step 2: simulate other-flow drain activity. vtime
        // advances past both buckets' head finish times. This is
        // the condition that makes the old single-Option rollback
        // overshoot on the earlier-popped bucket.
        queue.queue_vtime = 5000;

        let pre_batch_head_a = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_batch_tail_a = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_batch_bytes_a = queue.flow_bucket_bytes[bucket_a];
        let pre_batch_head_b = queue.flow_bucket_head_finish_bytes[bucket_b];
        let pre_batch_tail_b = queue.flow_bucket_tail_finish_bytes[bucket_b];
        let pre_batch_bytes_b = queue.flow_bucket_bytes[bucket_b];
        let pre_batch_vtime = queue.queue_vtime;
        let pre_batch_active = queue.active_flow_buckets;
        let pre_batch_peak = queue.active_flow_buckets_peak;
        assert_eq!(pre_batch_head_a, 1600);
        assert_eq!(pre_batch_head_b, 1000);
        assert_eq!(pre_batch_vtime, 5000);
        assert_eq!(pre_batch_active, 2);

        // Drain both into scratch. MQFQ picks min-finish-first;
        // B's head (1400) < A's head (2000), so pop order is B
        // then A. Both buckets drain to head=tail=0.
        let mut scratch: Vec<CoSPendingTxItem> = Vec::with_capacity(2);
        while let Some(item) = cos_queue_pop_front(queue) {
            scratch.push(item);
        }
        assert_eq!(scratch.len(), 2);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_b], 0);
        assert_eq!(queue.active_flow_buckets, 0);

        // Roll back LIFO. scratch.pop() returns A (popped second)
        // first, then B. Each push_front consumes its own
        // snapshot off the stack.
        while let Some(item) = scratch.pop() {
            cos_queue_push_front(queue, item);
        }

        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-1: snapshot stack must be fully consumed after a \
             complete cross-bucket rollback",
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_batch_head_a,
            "#785 Phase 3 NEW-1: cross-bucket rollback — A's HEAD \
             must restore from A's OWN per-pop snapshot, not re- \
             anchor off the rewound vtime (that overshoots).",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_batch_tail_a,
            "#785 Phase 3 NEW-1: cross-bucket rollback — A's TAIL \
             must restore exactly.",
        );
        assert_eq!(queue.flow_bucket_bytes[bucket_a], pre_batch_bytes_a);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], pre_batch_head_b,
            "#785 Phase 3 NEW-1: cross-bucket rollback — B's HEAD \
             must restore exactly (this is the 'most recent pop' \
             case that worked with the single-snapshot impl too).",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], pre_batch_tail_b,
        );
        assert_eq!(queue.flow_bucket_bytes[bucket_b], pre_batch_bytes_b);
        assert_eq!(
            queue.queue_vtime, pre_batch_vtime,
            "#785 Phase 3 NEW-1: vtime must rewind symmetrically \
             across a cross-bucket batch rollback.",
        );
        assert_eq!(
            queue.active_flow_buckets, pre_batch_active,
            "#785 Phase 3 NEW-1: cross-bucket rollback must re- \
             activate both buckets.",
        );
        assert_eq!(queue.active_flow_buckets_peak, pre_batch_peak);
    }

    /// #785 Phase 3 Codex round-3 NEW-2 / Rust reviewer LOW —
    /// pop-snapshot stack must remain bounded by `TX_BATCH_SIZE`
    /// across a committed-only drain (no push_front rollback).
    ///
    /// Setup:
    ///   * Flow-fair queue with `TX_BATCH_SIZE + 64` items enqueued
    ///     (spread across two buckets so MQFQ selection gets
    ///     meaningful coverage).
    ///   * First "drain batch": pop TX_BATCH_SIZE items via direct
    ///     `cos_queue_pop_front`, never call push_front — this is
    ///     the committed-submit pattern where every scratch item
    ///     was accepted by the TX ring. The snapshot stack should
    ///     never exceed `TX_BATCH_SIZE` during the drain.
    ///   * Second "drain batch": drain the remaining 64 items.
    ///     Before the second batch starts, simulate the helper
    ///     contract by clearing the stack (what
    ///     `drain_exact_*_flow_fair` does at batch start). The
    ///     stack must then stay bounded through the second batch
    ///     too.
    ///
    /// Without the fix, every committed pop would leave a stale
    /// snapshot on the stack and the second batch would grow it
    /// past `TX_BATCH_SIZE` (reallocating on each push and
    /// violating the documented bound).
    ///
    /// This pin validates (1) the bound during a single batch,
    /// (2) the bound across batches once the drain-start clear
    /// runs, and (3) that no realloc grows capacity past the
    /// pre-allocated `TX_BATCH_SIZE`.
    #[test]
    fn mqfq_pop_snapshot_stack_bounded_to_tx_batch_size() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 8 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let pre_cap = queue.pop_snapshot_stack.capacity();
        assert_eq!(
            pre_cap, TX_BATCH_SIZE,
            "stack must be preallocated to TX_BATCH_SIZE",
        );

        // Enqueue TX_BATCH_SIZE + 64 items across two flows so the
        // MQFQ min-finish scan exercises real selection, not a
        // single-bucket shortcut.
        let total = TX_BATCH_SIZE + 64;
        for i in 0..total {
            let src_port = if i % 2 == 0 { 9001u16 } else { 9002u16 };
            cos_queue_push_back(queue, test_flow_cos_item(src_port, 100));
        }

        // Batch 1: committed drain — pop TX_BATCH_SIZE items and
        // DROP them (simulates the "TX ring accepted all of them"
        // path where scratch is cleared with no push_front).
        for _ in 0..TX_BATCH_SIZE {
            let popped = cos_queue_pop_front(queue);
            assert!(popped.is_some(), "queue still has items");
            assert!(
                queue.pop_snapshot_stack.len() <= TX_BATCH_SIZE,
                "NEW-2: pop_snapshot_stack must never exceed \
                 TX_BATCH_SIZE during a single drain batch",
            );
        }
        assert_eq!(
            queue.pop_snapshot_stack.len(),
            TX_BATCH_SIZE,
            "full-batch commit should leave exactly TX_BATCH_SIZE \
             snapshots (no push_front rollback consumed any)",
        );

        // Simulate what `drain_exact_*_flow_fair` does at batch
        // start: clear the stack before the next batch drains.
        // This is the fix point.
        queue.pop_snapshot_stack.clear();

        // Batch 2: drain the remaining 64 items. Stack must stay
        // bounded; without the batch-start clear this would grow
        // from TX_BATCH_SIZE → TX_BATCH_SIZE + 64 and realloc.
        for _ in 0..64 {
            let popped = cos_queue_pop_front(queue);
            assert!(popped.is_some());
            assert!(
                queue.pop_snapshot_stack.len() <= TX_BATCH_SIZE,
                "NEW-2: cross-batch drain must stay bounded after \
                 the drain-start clear",
            );
        }

        // No realloc: capacity must equal the preallocated
        // TX_BATCH_SIZE exactly. A realloc would prove the bound
        // was violated at some point.
        assert_eq!(
            queue.pop_snapshot_stack.capacity(),
            pre_cap,
            "NEW-2: stack must not realloc past TX_BATCH_SIZE",
        );
    }

    /// #785 Phase 3 Codex round-3 NEW-2 / Rust reviewer LOW —
    /// teardown/reconfigure drain path (`reset_binding_cos_runtime`
    /// style) must not grow the pop-snapshot stack past its bound
    /// and must leave the stack cleared afterwards.
    ///
    /// We exercise `cos_queue_drain_all` directly — it's the shared
    /// teardown helper used by `demote_prepared_cos_queue_to_local`
    /// and mirrors the direct-`cos_queue_pop_front_no_snapshot` loop
    /// in `reset_binding_cos_runtime`. Both paths drain all items
    /// without a matching push_front rollback.
    ///
    /// Pre-fix: drain-all pushed a snapshot per pop and never
    /// cleared them; with a queue holding > TX_BATCH_SIZE items
    /// the stack would realloc past its preallocated capacity
    /// (the documented-and-preallocated bound) and leave stale
    /// snapshots resident until the next push_back cleared them.
    ///
    /// Post-fix: drain-all uses `cos_queue_pop_front_no_snapshot`
    /// so the stack is never grown. Teardown leaves the stack at
    /// its pre-drain state (empty in this test).
    #[test]
    fn mqfq_drain_all_teardown_clears_stack() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 8 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let pre_cap = queue.pop_snapshot_stack.capacity();
        assert_eq!(pre_cap, TX_BATCH_SIZE);

        // Enqueue more items than the snapshot stack could hold
        // under the old always-push-snapshot policy.
        let total = TX_BATCH_SIZE + 300;
        for i in 0..total {
            let src_port = if i % 3 == 0 {
                9101u16
            } else if i % 3 == 1 {
                9102u16
            } else {
                9103u16
            };
            cos_queue_push_back(queue, test_flow_cos_item(src_port, 100));
        }
        // push_back clears the stack; confirm pre-condition.
        assert!(queue.pop_snapshot_stack.is_empty());

        // Drain via the teardown helper. Must NOT grow the stack
        // and must NOT trip the pop_front debug_assert on overflow.
        let drained = cos_queue_drain_all(queue);
        assert_eq!(
            drained.len(),
            total,
            "drain_all must yield every enqueued item",
        );
        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-2: teardown drain path must leave the snapshot \
             stack empty — no stale snapshots resident",
        );
        assert_eq!(
            queue.pop_snapshot_stack.capacity(),
            pre_cap,
            "NEW-2: teardown must not realloc past TX_BATCH_SIZE",
        );
    }

    /// #785 Phase 3 Codex round-2 MEDIUM — brief-idle re-entry pin.
    /// Previous pins covered the LARGE-idle case (bucket drains,
    /// lots of other traffic flows, bucket re-enqueues far in the
    /// future). This pin covers the BRIEF-idle case where a bucket
    /// drains, another bucket drains advancing vtime modestly, the
    /// first bucket re-enqueues — the `max(tail_finish, queue_vtime)
    /// + bytes` anchor formula must exercise BOTH arms of the max
    /// over the lifetime of this bucket:
    ///
    ///   * First re-enqueue after drain: tail_finish was reset to 0,
    ///     queue_vtime > 0 → max picks queue_vtime, anchor =
    ///     queue_vtime + bytes.
    ///   * Second enqueue (to now-active bucket): tail_finish >
    ///     queue_vtime, max picks tail_finish, anchor =
    ///     tail_finish + bytes.
    #[test]
    fn mqfq_brief_idle_reentry_exercises_both_max_arms() {
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

        let flow_a = test_session_key(1001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(1002, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        // Flow A: single packet. Enqueue + drain fully. Bucket A
        // goes idle with head/tail=0.
        cos_queue_push_back(queue, test_flow_cos_item(1001, 1500));
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 0);
        assert_eq!(queue.queue_vtime, 1500);

        // Flow B: one packet, drain it. Advances queue_vtime to
        // 1500 + 800 = 2300 (small amount vs. flow A's lifetime).
        cos_queue_push_back(queue, test_flow_cos_item(1002, 800));
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 2300);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_b], 0);

        // Flow A returns with a 1200-byte packet. tail_finish[A]=0,
        // queue_vtime=2300 → max picks vtime → head = tail = 2300
        // + 1200 = 3500. This is the "brief-idle" re-anchor.
        cos_queue_push_back(queue, test_flow_cos_item(1001, 1200));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3500,
            "#785 Phase 3 brief-idle re-entry: first arm of max \
             (tail_finish=0 < queue_vtime=2300) must anchor at \
             queue_vtime + bytes",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 3500);

        // Flow A appends a second 900-byte packet on its now-
        // active bucket. tail_finish=3500 > queue_vtime=2300 →
        // max picks tail_finish → tail = 3500 + 900 = 4400. Head
        // unchanged (head packet is still the first one, 3500).
        cos_queue_push_back(queue, test_flow_cos_item(1001, 900));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3500,
            "#785 Phase 3 brief-idle re-entry: active-bucket \
             enqueue must NOT alter head (head packet didn't \
             change)",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 4400,
            "#785 Phase 3 brief-idle re-entry: second arm of max \
             (tail_finish=3500 > queue_vtime=2300) must anchor at \
             tail_finish + bytes",
        );
    }

    /// Pin the overflow bound on `flow_bucket_{head,tail}_finish_bytes`
    /// by driving the ACTUAL runtime field near `u64::MAX` and
    /// exercising the real enqueue path through
    /// `cos_queue_push_back`/`account_cos_queue_flow_enqueue`.
    ///
    /// Rust reviewer MEDIUM #2 (round-2): the prior revision
    /// recomputed the wrap-interval math in the test body and
    /// asserted `years_to_wrap > 40`. That is a calculator, not a
    /// pin — a regression that narrowed the field to u32, or swapped
    /// `saturating_add` for `+`, would have left this test green
    /// because the test never touched the field. This revision:
    ///
    ///   1. Drives `queue.queue_vtime` to `u64::MAX - 10_000`.
    ///   2. Enqueues a 9000-byte packet (MTU-size upper bound).
    ///   3. Asserts the bucket's head/tail finish DID NOT wrap AND
    ///      landed at exactly `u64::MAX - 10_000 + 9_000`.
    ///   4. Enqueues again at u64::MAX-adjacent vtime and asserts
    ///      the saturating_add path keeps the field bounded.
    ///
    /// A regression that changes the accumulator type to u32,
    /// replaces `saturating_add` with `+`, or widens the per-enqueue
    /// delta (e.g. by dividing by a small weight) will fail THIS
    /// test, not a recomputed calculator.
    #[test]
    fn mqfq_finish_time_u64_has_decades_of_headroom() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Largest plausible single enqueue: MTU 9000 at weight 1.
        const MAX_SINGLE_DELTA: usize = 9_000;
        const SLACK: u64 = 10_000;
        let near_wrap = u64::MAX - SLACK;

        // Drive the runtime field near wrap by setting queue_vtime
        // (the re-anchor source for idle-bucket enqueue). The first
        // enqueue re-anchors head=tail=max(0, near_wrap)+9000 =
        // near_wrap + 9000 — well within u64 and exactly one delta
        // past queue_vtime.
        queue.queue_vtime = near_wrap;

        let flow_a = test_session_key(9999, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

        cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
        let expected_first = near_wrap + MAX_SINGLE_DELTA as u64;
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], expected_first,
            "first enqueue near u64 wrap must anchor at queue_vtime \
             + bytes; regression to u32 or non-saturating add would \
             fail here with a wrapped or truncated value",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], expected_first,
        );
        assert!(
            queue.flow_bucket_head_finish_bytes[bucket_a] > near_wrap,
            "finish time did not advance past pre-enqueue vtime — \
             type narrowed or wrap occurred",
        );

        // Second enqueue onto the ACTIVE bucket: tail advances by
        // MAX_SINGLE_DELTA, but saturating_add caps at u64::MAX.
        // With near_wrap + 2*9000 = u64::MAX - 10_000 + 18_000 =
        // u64::MAX + 8_000 — this SHOULD saturate to u64::MAX.
        cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
        let new_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        assert!(
            new_tail >= expected_first,
            "tail must monotonically advance; got {} < {}",
            new_tail,
            expected_first,
        );
        assert_eq!(
            new_tail,
            u64::MAX,
            "second enqueue must saturate at u64::MAX (input was \
             near_wrap + 2*9000 > u64::MAX); regression that replaces \
             saturating_add with `+` would panic on overflow in debug \
             builds or wrap in release builds",
        );

        // Head unchanged on active-bucket enqueue (head packet is
        // still the first one).
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], expected_first,
            "active-bucket enqueue must not alter head",
        );

        // Sanity-check the original calculator claim — 40+ years at
        // 100 Gbps — is still true. Kept alongside the real-field
        // pin above; the pin above is what would fail on regression.
        const WRAP_BYTES: u128 = 1u128 << 64;
        let bytes_per_sec: u128 = 100_000_000_000u128 / 8;
        let years_to_wrap = WRAP_BYTES / bytes_per_sec / 60 / 60 / 24 / 365;
        assert!(
            years_to_wrap > 40,
            "u64 finish-time headroom at 100 Gbps should exceed 40 \
             years of uptime, got {} years",
            years_to_wrap,
        );
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

    /// #784 regression pin: narrow-input flow distribution.
    ///
    /// The iperf3-style workload hits an SFQ bucket collision
    /// cliff that the mixed-v4/v6 distribution test above misses:
    /// 12 flows to the same (src_ip, dst_ip, dst_port, proto,
    /// addr_family) differing only in src_port (consecutive
    /// ephemeral range, all v4 TCP). Real-world iperf3 reports
    /// 3 flows at ~145 Mbps with 0 retrans and 9 flows at
    /// ~60 Mbps with thousands of retrans each — caused by
    /// multiple flows landing on the same SFQ bucket and having
    /// their flow_share caps shrunk (each bucket's share = total
    /// buffer / prospective_active_flows, halved/thirded if a
    /// bucket holds 2-3 flows).
    ///
    /// Budget: for 12 narrow-input flows in 1024 buckets under a
    /// good hash, E[colliding pairs] ≈ 12*11/(2*1024) ≈ 0.06 —
    /// essentially always 12 distinct buckets. Under the prior
    /// boost-style hash_combine, narrow inputs observably collapse
    /// to 3-6 distinct buckets across most seeds. Demand >=11
    /// distinct buckets (allowing one pair collision worst-case
    /// under uniform null).
    ///
    /// Adversarial review posture: if this test ever weakens to
    /// accept fewer distinct buckets, or drops the all-v4 shape,
    /// the iperf3 fairness regression WILL return silently.
    #[test]
    fn exact_cos_flow_bucket_distribution_narrow_inputs_all_v4() {
        use std::collections::BTreeSet;

        // Production-like ephemeral port range. Linux kernel's
        // default ephemeral range is 32768-60999; 12 consecutive
        // ports starting at 39754 matches the actual iperf3
        // capture that motivated this test.
        let ports: Vec<u16> = (39754..39754 + 12).collect();
        // Test multiple seeds so a hash-mix fix cannot pass by
        // accident on a lucky seed. Including 0 pins the
        // pre-flow-fair default.
        let seeds: [u64; 5] = [
            0,
            0xA5A5_0000_C3C3_FFFF,
            0x0123_4567_89AB_CDEF,
            0xFFFF_FFFF_FFFF_FFFF,
            0xDEAD_BEEF_CAFE_BABE,
        ];
        for &seed in &seeds {
            let mut buckets = BTreeSet::new();
            for port in &ports {
                let flow = test_session_key(*port, 5201);
                // Explicitly v4 TCP — no mixed-family shortcut.
                assert_eq!(flow.addr_family, libc::AF_INET as u8);
                buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
            }
            assert!(
                buckets.len() >= 11,
                "seed={:#x}: 12 all-v4 iperf3-style flows landed in only {} distinct \
                 buckets — SFQ fairness regression. This is the flow-spread bug from #784; \
                 if this fires, the hash function is not spreading narrow-variance inputs \
                 (identical src_ip/dst_ip/dst_port/proto/family, only src_port differs).",
                seed,
                buckets.len()
            );
        }
    }

    /// #784 companion: also pin the wider 12-flow case with
    /// non-consecutive src_ports (simulating a different
    /// ephemeral-port allocator or long-running connections
    /// from different source processes).
    #[test]
    fn exact_cos_flow_bucket_distribution_narrow_inputs_scattered_ports() {
        use std::collections::BTreeSet;
        // 12 src_ports scattered across the ephemeral range.
        let ports: [u16; 12] = [
            33000, 35719, 38112, 41003, 43517, 46281, 48907, 51214, 53841, 56118, 58792, 60999,
        ];
        let seeds: [u64; 3] = [0, 0xA5A5_0000_C3C3_FFFF, 0x0123_4567_89AB_CDEF];
        for &seed in &seeds {
            let mut buckets = BTreeSet::new();
            for port in &ports {
                let flow = test_session_key(*port, 5201);
                buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
            }
            assert!(
                buckets.len() >= 11,
                "seed={:#x}: 12 scattered all-v4 flows landed in only {} distinct \
                 buckets — SFQ hash regression on non-consecutive src_ports",
                seed,
                buckets.len()
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

        // #920: TX_BATCH_SIZE lowered 256 → 64 caps a single visit at
        // 64 items even when token budget would permit more (~166).
        // The remaining tokens stay with the queue for the next visit;
        // throughput is preserved across multiple shorter visits, with
        // the trade-off that mouse packets get an interleave point
        // every 64 packets instead of every 256.
        let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
        match batch {
            CoSBatch::Local { items, .. } => assert_eq!(items.len(), TX_BATCH_SIZE),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(root.queues[0].items.len(), 200 - TX_BATCH_SIZE);
    }

    /// #920: separate from the batch-cap test above. Asserts the
    /// rate-quantum invariant guarded by the original test name —
    /// a 10 Gbps queue gets a strictly larger byte-budget visit
    /// quantum than a 100 Mbps queue, regardless of TX_BATCH_SIZE.
    /// Guards against silent regression if `cos_guarantee_quantum_bytes`
    /// stops scaling with `transmit_rate_bytes`.
    #[test]
    fn guarantee_phase_quantum_scales_with_rate() {
        use super::cos_guarantee_quantum_bytes;
        let high_rate = test_cos_runtime_with_queues(
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
        let low_rate = test_cos_runtime_with_queues(
            100_000_000u64 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-low".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000u64 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 256 * 1024,
                dscp_rewrite: None,
            }],
        );
        let high_q = cos_guarantee_quantum_bytes(&high_rate.queues[0]);
        let low_q = cos_guarantee_quantum_bytes(&low_rate.queues[0]);
        assert!(
            high_q > low_q,
            "high-rate quantum ({high_q}) must exceed low-rate quantum ({low_q})"
        );
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
    //     over TX_BATCH_SIZE packets — ~2–4 ns per packet at the
    //     pre-#920 batch of 256; ~10–15 ns per packet at the new
    //     batch of 64).
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
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 1500,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::from([test_cos_item(1500)]),
            local_item_count: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
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
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
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
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
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

    /// Regression pin for the VLAN-tagged admission path discovered in
    /// the #727 live validation: a single 802.1Q tag (ethertype 0x8100)
    /// pushes L3 four bytes deeper. `maybe_mark_ecn_ce` must detect
    /// that via `ethernet_l3_offset` and still mark the ECN bits at
    /// the correct offset rather than stamping into the VLAN TCI.
    #[test]
    fn maybe_mark_ecn_ce_handles_single_vlan_tagged_frame() {
        // Build a standard IPv4 test packet, then splice a 4-byte VLAN
        // tag between the MAC addresses and the ethertype. The result
        // is: 6 dst + 6 src + TPID(0x8100) + TCI(VID=80, prio=5) +
        //     EthType(0x0800) + <20-byte IPv4 header>.
        let tos = ECN_ECT_0;
        let base = build_ipv4_test_packet(tos);
        let mut tagged = Vec::with_capacity(base.len() + 4);
        tagged.extend_from_slice(&base[..12]); // dst + src MAC
        tagged.extend_from_slice(&[0x81, 0x00]); // TPID
        // TCI: priority 5 << 13 | DEI 0 | VID 80.
        let tci: u16 = (5 << 13) | 80;
        tagged.extend_from_slice(&tci.to_be_bytes());
        tagged.extend_from_slice(&[0x08, 0x00]); // inner ethertype (IPv4)
        tagged.extend_from_slice(&base[14..]); // IPv4 header + payload

        // Confirm `ethernet_l3` parses IPv4 at offset 18 for this frame.
        assert_eq!(ethernet_l3(&tagged), Some(EthernetL3::Ipv4(18)));

        let mut req = TxRequest {
            bytes: tagged,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        assert!(
            maybe_mark_ecn_ce(&mut req),
            "VLAN-tagged ECT(0) frame must be marked at the VLAN-shifted L3 offset"
        );
        // TOS byte sits at l3_offset + 1 = 19 in the tagged frame.
        assert_eq!(req.bytes[19] & ECN_MASK, ECN_CE);
        // And critically: the VLAN TCI bytes must NOT have been
        // mutated — if the old hardcoded offset 14 had hit, the "ECN
        // bits" we'd have touched are inside the VLAN priority nibble
        // at byte 15, which we assert stayed intact.
        let tci_after = u16::from_be_bytes([req.bytes[14], req.bytes[15]]);
        assert_eq!(
            tci_after, tci,
            "VLAN TCI must be untouched by ECN marking"
        );
    }

    /// Counter-factual: ethertype 0 (or anything we don't understand)
    /// returns `None` from `ethernet_l3`, so marking is a no-op.
    /// Guards against a regression that defaults to offset 14 on
    /// unknown frames.
    #[test]
    fn maybe_mark_ecn_ce_rejects_unknown_ethertype() {
        let mut req = TxRequest {
            bytes: {
                let mut b = build_ipv4_test_packet(ECN_ECT_0);
                b[12] = 0x12;
                b[13] = 0x34;
                b
            },
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert_eq!(ethernet_l3(&req.bytes), None);
        assert!(!maybe_mark_ecn_ce(&mut req));
        // ECT(0) bits at the would-have-been-wrong-offset untouched.
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
    }

    /// QinQ (0x88A8 outer + 0x8100 inner) must be rejected rather than
    /// guessed at, because L3 actually lives at offset 22 on those
    /// frames and a default to 18 would stamp into the inner VLAN TCI.
    /// #728 review pin: once we've paid to parse the outer ethertype,
    /// the parse must be the source of truth.
    #[test]
    fn ethernet_l3_rejects_qinq_until_explicitly_supported() {
        let base = build_ipv4_test_packet(ECN_ECT_0);
        let mut qinq = Vec::with_capacity(base.len() + 8);
        qinq.extend_from_slice(&base[..12]); // MACs
        // Outer 802.1ad: TPID 0x88A8, TCI with an outer VID 100.
        qinq.extend_from_slice(&[0x88, 0xA8]);
        let outer_tci: u16 = 100;
        qinq.extend_from_slice(&outer_tci.to_be_bytes());
        // Inner 802.1Q: TPID 0x8100 at the "inner ethertype" position.
        qinq.extend_from_slice(&[0x81, 0x00]);
        let inner_tci: u16 = 80;
        qinq.extend_from_slice(&inner_tci.to_be_bytes());
        qinq.extend_from_slice(&[0x08, 0x00]); // IPv4 (well beyond where we care)
        qinq.extend_from_slice(&base[14..]);

        assert_eq!(
            ethernet_l3(&qinq),
            None,
            "QinQ (0x88A8 → 0x8100) must be rejected — inner VLAN tag not yet supported"
        );

        // And the marker refuses such a frame — no ECN bits are flipped.
        let mut req = TxRequest {
            bytes: qinq,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        assert!(!maybe_mark_ecn_ce(&mut req));
    }

    /// A VLAN-tagged frame whose inner ethertype is ARP / MPLS / etc.
    /// must be rejected too, matching the `refuse to guess` contract.
    /// Without this check we'd treat offset 18 as an IPv4 TOS byte and
    /// stamp the low 2 bits of whatever is there (ARP's hardware type
    /// in this case), corrupting the frame.
    #[test]
    fn ethernet_l3_rejects_vlan_tagged_non_ip_payload() {
        let base = build_ipv4_test_packet(ECN_ECT_0);
        let mut tagged = Vec::with_capacity(base.len() + 4);
        tagged.extend_from_slice(&base[..12]);
        tagged.extend_from_slice(&[0x81, 0x00]); // outer 802.1Q
        let tci: u16 = 80;
        tagged.extend_from_slice(&tci.to_be_bytes());
        tagged.extend_from_slice(&[0x08, 0x06]); // inner = ARP (0x0806)
        tagged.extend_from_slice(&base[14..]);
        assert_eq!(
            ethernet_l3(&tagged),
            None,
            "VLAN-tagged non-IP payload must not dispatch to an IP marker",
        );
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

    /// Small dummy UMEM area for admission tests that exercise the
    /// Local variant. The mark helpers never consult `umem` on the
    /// Local path (they mutate `req.bytes` directly), so any valid
    /// `MmapArea` satisfies the signature. A 4 KB mapping is cheap
    /// and enough to round up to hugepage alignment internally.
    fn test_admission_umem() -> MmapArea {
        MmapArea::new(4096).expect("mmap")
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
        let umem = test_admission_umem();
        // Non-flow-fair queue: share_cap == buffer_limit, so both
        // thresholds collapse onto the aggregate one. `flow_bucket=0`
        // is unused beyond the (constant-returning) share-limit call.
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

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
        // Exactly at the mark threshold — `>` comparison must not fire.
        // Written against the constants so retuning NUM/DEN doesn't
        // silently break this pin; at any fraction < 1, an at-threshold
        // queue must stay unmarked by the `>` comparison in
        // `apply_cos_admission_ecn_policy`.
        queue.queued_bytes =
            buffer_limit * COS_ECN_MARK_THRESHOLD_NUM / COS_ECN_MARK_THRESHOLD_DEN;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

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
        let umem = test_admission_umem();
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

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
        let umem = test_admission_umem();
        // Signal that the caller already decided this packet will drop.
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, true, false, &mut item, &umem);
        assert!(!marked, "flow_share_exceeded path must skip marking");
        let after_share = snapshot_counters(queue);
        assert_eq!(after_share.admission_ecn_marked, before.admission_ecn_marked);

        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, true, &mut item, &umem);
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

    // `admission_does_not_mark_prepared_variant` was removed in #727:
    // the Prepared variant is now handled by
    // `maybe_mark_ecn_ce_prepared`, and the positive-behaviour pins
    // for the Prepared hot path live in the
    // `admission_ecn_marks_prepared_*` tests below.

    // ---------------------------------------------------------------------
    // #722 per-flow ECN threshold. #718 landed ECN CE marking keyed off
    // aggregate queue depth. Live validation on the 16-flow / 1 Gbps
    // exact-queue workload showed the aggregate threshold never fires
    // (queue sat at ~31% vs the 50% threshold) because drops came from
    // the per-flow fair-share cap. These tests drive the per-flow arm
    // directly, recreate the live failure mode, and include a counter-
    // factual assertion that proves the pre-#722 aggregate-only formula
    // would have missed this case.
    // ---------------------------------------------------------------------

    /// Build a flow-fair exact queue shaped to match the live
    /// 16-flow / 1 Gbps / 128 KB-buffer workload that motivated #722.
    /// Picking these exact numbers means the derived thresholds
    /// (buffer_limit, share_cap, aggregate_ecn_threshold,
    /// flow_ecn_threshold) match what the scheduler sees in
    /// production, so the fixture is not just internally consistent —
    /// it is the failure mode.
    fn test_flow_fair_exact_queue_16_flows() -> CoSInterfaceRuntime {
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
        root
    }

    /// Populate 16 flow buckets on a flow-fair queue so
    /// `active_flow_buckets == 16`. Target bucket `target` is set to
    /// `target_bytes`; every other populated bucket gets 1 byte (just
    /// enough to count as active). Returns the resulting
    /// `queued_bytes` sum so the caller can reconcile the aggregate
    /// with the per-bucket picture.
    fn seed_sixteen_flow_buckets(
        queue: &mut CoSQueueRuntime,
        target: usize,
        target_bytes: u64,
    ) -> u64 {
        queue.active_flow_buckets = 16;
        let mut populated = 0usize;
        let mut bucket = 0usize;
        let mut sum = 0u64;
        while populated < 16 && bucket < queue.flow_bucket_bytes.len() {
            if bucket == target {
                queue.flow_bucket_bytes[bucket] = target_bytes;
                sum = sum.saturating_add(target_bytes);
                populated += 1;
            } else {
                queue.flow_bucket_bytes[bucket] = 1;
                sum = sum.saturating_add(1);
                populated += 1;
            }
            bucket += 1;
        }
        sum
    }

    #[test]
    fn admission_ecn_marks_when_per_flow_above_threshold_aggregate_below() {
        // Live failure mode from #722: queue sits at ~31% utilisation
        // so the aggregate 50% threshold never trips, but a dominant
        // flow's bucket is past the per-flow 50% threshold and is
        // about to be dropped by the flow-share cap.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        // buffer_limit at 16 active flows: 16 × 24 KB = 384 KB (clamped
        // by delay_cap = 625 KB on a 1 Gbps queue @ 5 ms). share_cap =
        // 384000 / 16 = 24000. At the current NUM/DEN = 1/3 (33%) per
        // #754, the thresholds are aggregate = 384000 / 3 = 128_000 and
        // per-flow = 24000 / 3 = 8_000. If NUM/DEN is retuned, both
        // derived values move together — the asserts below are written
        // against concrete numbers (not the constants) so a future
        // retune fails the pin loudly, which is the whole point.
        let target_bucket_bytes = 15_000; // > 8 000 per-flow threshold with a generous margin
        let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        queue.queued_bytes = queued_bytes;
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        assert_eq!(buffer_limit, 384_000);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
        assert_eq!(share_cap, 24_000);
        let aggregate_ecn_threshold =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let flow_ecn_threshold =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        // Concrete expected values at NUM/DEN = 1/3: aggregate =
        // 384_000 / 3 = 128_000 and per-flow = 24_000 / 3 = 8_000.
        assert_eq!(
            aggregate_ecn_threshold, 128_000,
            "aggregate threshold must remain pinned for this fixture",
        );
        assert_eq!(
            flow_ecn_threshold, 8_000,
            "per-flow threshold must remain pinned for this fixture",
        );

        // Counter-factual: reconstruct the pre-#722 aggregate-only
        // formula and assert that on this exact state it would NOT
        // fire. This is what #718 did and why it missed the live
        // workload — keep this pin live so a future refactor that
        // drops the per-flow arm fails here loudly.
        assert!(
            queue.queued_bytes <= aggregate_ecn_threshold,
            "aggregate-only formula must fall below threshold on the #722 live state",
        );
        // And the per-flow arm must be above its threshold.
        assert!(queue.flow_bucket_bytes[target] > flow_ecn_threshold);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(marked, "per-flow arm must fire when aggregate is below");
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
            "ECN counter must advance by exactly 1",
        );
        assert_eq!(
            after.admission_flow_share_drops, before.admission_flow_share_drops,
            "mark is not a drop",
        );
        assert_eq!(
            after.admission_buffer_drops, before.admission_buffer_drops,
            "mark is not a drop",
        );
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE, "CE bit must be set");
        } else {
            panic!("item must stay Local variant");
        }
    }

    /// #784: SFQ fairness regression pin. The former behavior of
    /// the aggregate-above ECN arm actively broke per-flow fairness
    /// on iperf3 -P 12 against a 1 Gbps cap (3 winners at 145 Mbps
    /// with 0 retrans, 9 losers at 50-75 Mbps with thousands of
    /// retrans each). Removing the aggregate arm restored fairness
    /// because flows that hadn't filled their bucket no longer got
    /// penalised for OTHER flows' bursts.
    ///
    /// If this test ever flips to assert `marked` is true, the
    /// aggregate arm has been reintroduced and the iperf3 fairness
    /// regression in #784 WILL come back. Do not weaken this test.
    #[test]
    fn admission_ecn_does_not_mark_when_only_aggregate_above_threshold() {
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        let target_bucket_bytes = 500; // << per-flow threshold (8 000 B at 1/3)
        let _ = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
        let aggregate_ecn_threshold =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let flow_ecn_threshold =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        queue.queued_bytes = aggregate_ecn_threshold + 1; // strictly above

        assert!(queue.queued_bytes > aggregate_ecn_threshold);
        assert!(queue.flow_bucket_bytes[target] <= flow_ecn_threshold);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(
            !marked,
            "#784: aggregate arm must NOT fire — only per-flow threshold triggers marks. \
             If this assertion ever flips, the SFQ iperf3 -P 12 fairness regression returns."
        );
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    }

    #[test]
    fn admission_ecn_does_not_mark_when_both_thresholds_below() {
        // Both below — no congestion signal. Mark must stay off and
        // the counter unchanged. Packet bytes untouched.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        let target_bucket_bytes = 500; // < 8 000 (per-flow threshold at NUM/DEN = 1/3)
        let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        queue.queued_bytes = queued_bytes; // ≪ 128 000 (aggregate threshold at 1/3)
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
        let aggregate_ecn_threshold =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let flow_ecn_threshold =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        assert!(queue.queued_bytes <= aggregate_ecn_threshold);
        assert!(queue.flow_bucket_bytes[target] <= flow_ecn_threshold);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "no threshold tripped — no mark");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(
                req.bytes[15] & ECN_MASK,
                ECN_ECT_0,
                "packet bytes must be byte-identical below threshold",
            );
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_ecn_does_not_mark_when_flow_share_already_exceeded() {
        // Per-flow above threshold BUT the caller has also decided the
        // packet will drop (flow_share_exceeded = true). Preserves the
        // #718 invariant that we don't burn marks on doomed packets —
        // a marked-then-dropped packet wastes both the mark and the
        // bandwidth the mark was trying to steer.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        let target_bucket_bytes = 15_000; // > 8 000 per-flow threshold (NUM/DEN = 1/3)
        let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        queue.queued_bytes = queued_bytes;
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            true,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "flow_share_exceeded must suppress the mark");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(
                req.bytes[15] & ECN_MASK,
                ECN_ECT_0,
                "doomed packet must not be rewritten",
            );
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_ecn_per_flow_threshold_matches_share_cap_denominator() {
        // Pin that the per-flow threshold uses the SAME
        // NUM/DEN fraction as the aggregate threshold. If a future
        // refactor changes the constants (e.g. drops the aggregate
        // arm to 33%) without updating the per-flow arm, both arms
        // drift out of lockstep and this test fails. Computed from
        // the state as `share_cap × NUM / DEN` independently — no
        // internal call into the policy function.
        //
        // #784: seed with `target_bytes > 0` so prospective_active
        // stays at 16 both in the test's computed threshold and in
        // the policy's live recompute. Earlier revision seeded
        // target=0 and set the bucket above threshold later, which
        // shifted prospective_active from 17 → 16 between compute
        // and policy call and silently passed on the aggregate arm.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        seed_sixteen_flow_buckets(queue, target, 1);
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);

        let expected_aggregate =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let expected_flow =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;

        // Ratio check: both thresholds must be exactly NUM/DEN of their
        // respective caps, i.e. `threshold × DEN == cap × NUM`. Stated
        // as multiplications so integer truncation does not mask drift.
        assert_eq!(
            expected_aggregate.saturating_mul(COS_ECN_MARK_THRESHOLD_DEN),
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM),
            "aggregate threshold must be NUM/DEN of buffer_limit",
        );
        assert_eq!(
            expected_flow.saturating_mul(COS_ECN_MARK_THRESHOLD_DEN),
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM),
            "per-flow threshold must be NUM/DEN of share_cap",
        );

        // Drive the policy at a state that trips BOTH arms and
        // verify the mark fires — proves the live code path uses
        // the same fractions we computed by hand.
        queue.queued_bytes = expected_aggregate + 1;
        queue.flow_bucket_bytes[target] = expected_flow + 1;
        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );
        assert!(marked);
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked + 1);
    }

    // ---------------------------------------------------------------------
    // #785 SFQ promotion. `ensure_cos_interface_runtime` calls
    // `apply_cos_queue_flow_fair_promotion` on a freshly-built
    // `CoSInterfaceRuntime`, which in turn calls
    // `promote_cos_queue_flow_fair` per queue.
    //
    // Current policy:
    //   * SFQ (flow-fair) runs on owner-local-exact queues only.
    //   * Shared_exact (>= `COS_SHARED_EXACT_MIN_RATE_BYTES` =
    //     2.5 Gbps) queues stay on the single-FIFO-per-worker drain.
    //   * `promote_cos_queue_flow_fair` caches the live
    //     `WorkerCoSQueueFastPath.shared_exact` bit onto the runtime
    //     as `CoSQueueRuntime.shared_exact` so the admission hot
    //     paths (or future cross-worker fairness work) can branch
    //     on it without another iface_fast lookup.
    //
    // Why shared_exact is held back: issue #785 tried two paths to
    // land SFQ on the high-rate service path. Both regressed and
    // were rolled back:
    //
    //   1. Naïve SFQ (flow_fair=queue.exact, no admission change).
    //      iperf3 -P 12 on the 25 Gbps iperf-c cap regressed from
    //      22.3 Gbps / 0 retrans to 16.3 Gbps / 25k+ retrans. Root
    //      cause: per-flow share cap + per-flow ECN arm are
    //      rate-unaware (24 KB floor); on 25 Gbps / 12 flows that
    //      is ≪ 5 MB BDP so admission drops and ECN fire on every
    //      packet.
    //
    //   2. SFQ + aggregate-only admission on shared_exact. Throughput
    //      preserved (22-23 Gbps) but per-flow CoV went UP from
    //      ~33 % to ~40-51 % over three runs. Per-worker SFQ cannot
    //      equalise flows distributed unevenly across workers by NIC
    //      RSS — which is the dominant imbalance source at P=12.
    //
    // The architecturally-correct lever is cross-worker flow
    // steering (or a single shared SFQ across workers), tracked in
    // the follow-up issue.
    //
    // Adversarial review posture (post-#914): the historical
    // `!shared_exact` gate is no longer in policy. shared_exact
    // now runs MQFQ flow-fair AND a rate-aware admission cap
    // (`max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)` —
    // see `cos_queue_flow_share_limit`). Reviewers should reject
    // PRs that re-introduce the rate-unaware MIN-floor cap on
    // shared_exact without also re-validating
    // `iperf3 -P 12 -p 5203` ≥ 22 Gbps AND per-flow CoV ≤ 20 %
    // (the regression Attempt A hit). The tests below drive the
    // full production promotion path (via
    // `apply_cos_queue_flow_fair_promotion` with hand-authored
    // `WorkerCoSQueueFastPath` vectors) so breaking the zip alignment
    // at the `ensure_cos_interface_runtime` call site — or feeding
    // the wrong `shared_exact` bit — is caught.
    // ---------------------------------------------------------------------

    /// Build a `WorkerCoSQueueFastPath` shaped like
    /// `build_worker_cos_fast_interfaces` would build it for a queue
    /// with the given `shared_exact` bit. Only the fields the
    /// promotion path consults are populated — the rest stay at the
    /// stable defaults the live builder uses when no lease or owner
    /// live state is present.
    fn test_queue_fast_path_for_promotion(shared_exact: bool) -> WorkerCoSQueueFastPath {
        WorkerCoSQueueFastPath {
            shared_exact,
            owner_worker_id: 0,
            owner_live: None,
            shared_queue_lease: None,
            vtime_floor: None,
        }
    }

    /// #785 Phase 3 — pin that a high-rate exact queue
    /// (shared_exact=true) IS promoted onto the flow-fair path AND
    /// has its `shared_exact` shadow cached. The shadow drives the
    /// admission-gate downgrade (aggregate-only) in
    /// `cos_queue_flow_share_limit` and
    /// `apply_cos_admission_ecn_policy`. The MQFQ VFT ordering in
    /// `cos_queue_pop_front` is what actually enforces per-flow
    /// fairness on this queue — the share cap + per-flow ECN arm
    /// are rate-unaware (24 KB floor) and would tail-drop TCP at
    /// 25 Gbps. Retrospective Attempt A measured 22.3 → 16.3 Gbps +
    /// 25 k retrans when the cap was enforced on shared_exact;
    /// Phase 3 replaces the cap's fairness role with VFT ordering.
    #[test]
    fn queue_flow_fair_enabled_on_shared_exact() {
        use super::super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

        let high_rate_bytes = 25_000_000_000u64 / 8;
        assert!(
            high_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES,
            "fixture must be above the shared_exact threshold or the \
             test does not exercise the regression surface",
        );

        let mut runtime = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: high_rate_bytes,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        assert!(!runtime.queues[0].flow_fair);
        assert!(!runtime.queues[0].shared_exact);

        // Drive the full ensure_cos_interface_runtime promotion loop.
        let fast_path = vec![test_queue_fast_path_for_promotion(true)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path);

        assert!(
            runtime.queues[0].flow_fair,
            "#785 Phase 3: shared_exact queue MUST be promoted onto \
             the flow-fair path so MQFQ virtual-finish-time ordering \
             runs in the dequeue path. Regression here re-opens the \
             CoV gap we just measured closed.",
        );
        assert!(
            runtime.queues[0].shared_exact,
            "#785 Phase 3: shared_exact shadow MUST be cached onto \
             the runtime so the admission gates in \
             cos_queue_flow_share_limit and \
             apply_cos_admission_ecn_policy downgrade to \
             aggregate-only. Per-flow admission gates are rate-\
             unaware (24 KB floor) and would tail-drop TCP at \
             multi-Gbps per-flow rates.",
        );
        assert_ne!(
            runtime.queues[0].flow_hash_seed, 0,
            "seed must be drawn on flow-fair promotion so MQFQ \
             bucket assignment is not an externally-probeable \
             pure function of the 5-tuple",
        );
    }

    /// Pin that a low-rate exact queue (shared_exact=false) IS
    /// promoted onto the SFQ path AND has `shared_exact=false` on
    /// its runtime. The #784 fairness fix on the 1 Gbps iperf-a
    /// queue depends on BOTH halves: flow_fair=true so DRR orders
    /// per-flow, and shared_exact=false so the per-flow share cap
    /// + per-flow ECN arm still run (at 1 Gbps / 12 flows the cap is
    /// ~24 KB which matches TCP cwnd at 77 Mbps flows cleanly).
    #[test]
    fn queue_flow_fair_enabled_on_owner_local_exact() {
        use super::super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

        let low_rate_bytes = 1_000_000_000u64 / 8;
        assert!(
            low_rate_bytes < COS_SHARED_EXACT_MIN_RATE_BYTES,
            "fixture must be below the shared_exact threshold to \
             exercise the owner-local-exact path",
        );

        let mut runtime = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: low_rate_bytes,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let fast_path = vec![test_queue_fast_path_for_promotion(false)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path);

        assert!(
            runtime.queues[0].flow_fair,
            "owner-local-exact queue MUST be promoted onto the SFQ \
             path — #784 fairness fix depends on it",
        );
        assert!(
            !runtime.queues[0].shared_exact,
            "owner-local-exact queue MUST keep shared_exact=false so \
             the per-flow share cap and per-flow ECN arm continue to \
             run — #784 depends on the per-flow cap firing at 1 Gbps",
        );
        assert_ne!(
            runtime.queues[0].flow_hash_seed, 0,
            "seed must be drawn on flow-fair promotion — otherwise \
             every binding hashes flows identically and one flow's \
             RSS bucket collides across the whole deployment",
        );
    }

    /// Pin that a non-exact (best-effort) queue is NOT promoted onto
    /// the flow-fair path. SFQ would be wasted work on these queues:
    /// there is no per-flow rate contract, so per-flow isolation is
    /// meaningless, and drawing an OS random seed for every
    /// non-exact queue on every runtime build would add a syscall
    /// per queue for zero benefit. This pin also doubles as a sanity
    /// check that the gate did not collapse to
    /// `queue.flow_fair = true` unconditionally.
    #[test]
    fn queue_flow_fair_disabled_on_non_exact() {
        let mut runtime = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 3,
                transmit_rate_bytes: 0,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );

        // Drive the production loop with shared_exact=false first,
        // then again with shared_exact=true — both MUST leave a
        // non-exact queue off the flow-fair path, because the gate's
        // LHS (`queue.exact`) fails regardless of the fast-path bit.
        let fast_path_owner_local = vec![test_queue_fast_path_for_promotion(false)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_owner_local);
        assert!(
            !runtime.queues[0].flow_fair,
            "non-exact queues must stay off the flow-fair path: SFQ \
             has no rate contract to enforce there, and draws an OS \
             random seed per queue",
        );

        let fast_path_shared = vec![test_queue_fast_path_for_promotion(true)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_shared);
        assert!(
            !runtime.queues[0].flow_fair,
            "non-exact queues must stay off the flow-fair path \
             regardless of the shared_exact signal",
        );
    }

    /// Pin that `apply_cos_queue_flow_fair_promotion` propagates the
    /// per-queue `shared_exact` bits correctly when the interface
    /// has a mix of shared_exact and owner-local-exact queues — the
    /// common production shape (a low-rate iperf-a queue next to a
    /// high-rate iperf-c queue on the same interface). Breaking the
    /// zip alignment between `runtime.queues` and
    /// `iface_fast.queue_fast_path` at the
    /// `ensure_cos_interface_runtime` call site would swap the two
    /// queues' `shared_exact` shadows and their `flow_fair` bits,
    /// silently routing both to the wrong admission branch and
    /// turning off SFQ on the iperf-a queue (re-breaking #784).
    #[test]
    fn apply_promotion_pairs_queues_with_their_fast_path_entries() {
        let mut runtime = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-c".into(),
                    priority: 5,
                    transmit_rate_bytes: 25_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
            ],
        );

        // Position 0 -> owner-local-exact; position 1 -> shared_exact.
        let fast_path = vec![
            test_queue_fast_path_for_promotion(false),
            test_queue_fast_path_for_promotion(true),
        ];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path);

        assert!(
            runtime.queues[0].flow_fair,
            "queue at position 0 (iperf-a, shared_exact=false) must \
             be on the flow-fair path — #784 fairness fix depends on it",
        );
        assert!(
            !runtime.queues[0].shared_exact,
            "queue at position 0 must get position-0's shared_exact=false",
        );
        assert!(
            runtime.queues[1].flow_fair,
            "#785 Phase 3: queue at position 1 (iperf-c, \
             shared_exact=true) must also be on the flow-fair path \
             so MQFQ VFT ordering enforces per-flow fairness. The \
             admission gates (cos_queue_flow_share_limit, \
             apply_cos_admission_ecn_policy) separately downgrade to \
             aggregate-only on shared_exact queues.",
        );
        assert!(
            runtime.queues[1].shared_exact,
            "queue at position 1 must get position-1's shared_exact=true \
             — zip misalignment would silently mis-route admission policy",
        );
    }

    // ---------------------------------------------------------------------
    // #727 Prepared-variant ECN marking. The #718 / #722 marker was
    // dormant on the XSK-RX→XSK-TX zero-copy hot path because the
    // admission policy only handled `CoSPendingTxItem::Local`. These
    // tests pin the Prepared branch byte-precisely: pre-state is
    // ECT(0/1), post-state is CE, counter bumps exactly once, and
    // the IPv4 checksum is still valid from scratch. A NOT-ECT
    // counterfactual and an out-of-range-offset counterfactual are
    // included so a regression that short-circuits either arm fails
    // loudly.
    // ---------------------------------------------------------------------

    /// Build a Prepared CoS item whose frame lives in `umem` at the
    /// given offset. Copies `packet_bytes` into the UMEM in place,
    /// then returns the `CoSPendingTxItem::Prepared` referencing
    /// those bytes. The caller is responsible for keeping `umem`
    /// alive for the duration of the item's lifetime (each test
    /// keeps both on the stack).
    fn test_prepared_item_in_umem(
        umem: &MmapArea,
        offset: u64,
        packet_bytes: &[u8],
        expected_addr_family: u8,
    ) -> CoSPendingTxItem {
        // SAFETY: in-range by construction (caller passes a valid
        // offset into a freshly-allocated MmapArea that is larger
        // than `packet_bytes`). Exclusive access holds because the
        // MmapArea is stack-local to the test.
        let dest = unsafe { umem.slice_mut_unchecked(offset as usize, packet_bytes.len()) }
            .expect("umem slice");
        dest.copy_from_slice(packet_bytes);
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset,
            len: packet_bytes.len() as u32,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        })
    }

    #[test]
    fn admission_ecn_marks_prepared_ipv4_ect0_packet_above_threshold() {
        // Pre: queue above aggregate threshold, Prepared IPv4 ECT(0)
        // packet lives at UMEM offset 0. Counter-factual pins that
        // make this robust against partial regressions:
        //   1. Before the call: TOS byte has ECN = ECT(0).
        //   2. After the call: TOS byte has ECN = CE.
        //   3. Counter bumped by exactly 1.
        //   4. IP checksum recomputed-from-scratch matches what's in
        //      the UMEM bytes.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let tos = (0x28u8 << 2) | ECN_ECT_0;
        let packet = build_ipv4_test_packet(tos);
        let umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&umem, 0, &packet, libc::AF_INET as u8);

        // Pin (1): pre-state is ECT(0).
        let pre_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();
        assert_eq!(pre_bytes[15] & ECN_MASK, ECN_ECT_0);

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(marked, "Prepared variant must be marked");
        // Pin (3): counter bumped by exactly 1.
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
            "ECN counter must advance by exactly 1",
        );
        assert_eq!(after.admission_flow_share_drops, before.admission_flow_share_drops);
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);

        // Pin (2): UMEM bytes now carry CE and preserve DSCP.
        let post_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();
        assert_eq!(post_bytes[15] & ECN_MASK, ECN_CE, "ECN bits must be CE");
        assert_eq!(post_bytes[15] >> 2, 0x28, "DSCP must survive marking");

        // Pin (4): IP checksum recomputed from scratch matches what's
        // actually sitting in UMEM. If the incremental update were
        // off-by-one or skipped a word, this would fail.
        let stored_csum = ((post_bytes[24] as u16) << 8) | post_bytes[25] as u16;
        let from_scratch = compute_ipv4_header_checksum(&post_bytes[14..34]);
        assert_eq!(
            stored_csum, from_scratch,
            "incremental IP checksum must match a from-scratch recompute",
        );
    }

    #[test]
    fn admission_ecn_marks_prepared_ipv6_ect0_packet_above_threshold() {
        // IPv6 Prepared packet at a non-zero UMEM offset. IPv6 has no
        // header checksum, so the pins are:
        //   1. Pre-state tclass has ECN = ECT(0).
        //   2. Post-state tclass has ECN = CE.
        //   3. Version + flow-label untouched.
        //   4. Counter bumped by exactly 1.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let tclass = (0x2eu8 << 2) | ECN_ECT_0;
        let packet = build_ipv6_test_packet(tclass);
        // Pick a non-zero offset to prove that `slice_mut_unchecked`
        // is honouring `req.offset` rather than always slicing from 0.
        let offset: u64 = 128;
        let umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&umem, offset, &packet, libc::AF_INET6 as u8);

        let pre_bytes = umem
            .slice(offset as usize, packet.len())
            .expect("slice readback")
            .to_vec();
        let pre_version_nibble = pre_bytes[14] & 0xf0;
        let pre_flow_label_low = pre_bytes[15] & 0x0f;
        assert_eq!(
            ((pre_bytes[14] & 0x0f) << 4) | ((pre_bytes[15] >> 4) & 0x0f),
            tclass,
        );

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(marked, "Prepared IPv6 must be marked");
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
        );

        let post_bytes = umem
            .slice(offset as usize, packet.len())
            .expect("slice readback")
            .to_vec();
        let post_tclass = ((post_bytes[14] & 0x0f) << 4) | ((post_bytes[15] >> 4) & 0x0f);
        assert_eq!(post_tclass & ECN_MASK, ECN_CE);
        assert_eq!(post_tclass >> 2, 0x2e, "DSCP must survive marking");
        assert_eq!(
            post_bytes[14] & 0xf0,
            pre_version_nibble,
            "version nibble must not drift",
        );
        assert_eq!(
            post_bytes[15] & 0x0f,
            pre_flow_label_low,
            "flow-label low nibble must not drift",
        );
    }

    #[test]
    fn admission_ecn_leaves_prepared_not_ect_packet_untouched() {
        // Queue above threshold, but the Prepared packet is NOT-ECT.
        // RFC 3168 §6.1.1.1: never mark a flow that did not negotiate
        // ECN. Counter must stay put and UMEM bytes byte-identical.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let tos = 0xb8; // DSCP 46 (EF), ECN = 00 (NOT-ECT)
        let packet = build_ipv4_test_packet(tos);
        let umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&umem, 0, &packet, libc::AF_INET as u8);
        let pre_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "NOT-ECT packet must not be marked");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        let post_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();
        assert_eq!(
            post_bytes, pre_bytes,
            "NOT-ECT packet bytes must be byte-identical",
        );
        assert_eq!(post_bytes[15] & ECN_MASK, ECN_NOT_ECT);
    }

    #[test]
    fn admission_ecn_skips_prepared_when_umem_slice_out_of_range() {
        // Constructed `PreparedTxRequest` points past the end of the
        // UMEM (`offset` > umem.len()). `slice_mut_unchecked` returns
        // None, the marker returns false, and the admission policy
        // must neither panic nor bump the counter. Guards the
        // out-of-range None-handling path — a regression that removed
        // the `let Some(...) = ... else { return false }` shape would
        // fail here without needing to catch a UB-flavoured panic.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let umem = test_admission_umem();
        // Offset deliberately past the UMEM len. `len: 1` so we do
        // not trip the internal `checked_add` overflow path — we want
        // the `end > self.len` check in `slice_mut_unchecked` to be
        // what returns None.
        let mut item = CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: u64::MAX / 2,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        });

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "out-of-range slice must not be marked");
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked, before.admission_ecn_marked,
            "counter must stay put when the slice is out of range",
        );
    }

    #[test]
    fn admission_ecn_counter_increments_for_both_local_and_prepared_in_same_queue() {
        // Drive the queue above threshold and pass ONE Local + ONE
        // Prepared, both ECT(0). The single `admission_ecn_marked`
        // counter must advance by exactly 2 — proves neither variant
        // is double-counting or under-counting, and that both paths
        // share the same counter. Counter-factual for a refactor
        // that accidentally split the counter: this test would drop
        // to +1.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let umem = test_admission_umem();

        // Local variant first.
        let mut local_item = test_local_ipv4_item(ECN_ECT_0);
        let marked_local = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut local_item,
            &umem,
        );
        assert!(marked_local, "Local variant must mark");

        // Prepared variant next.
        let packet = build_ipv4_test_packet(ECN_ECT_0);
        let mut prepared_item =
            test_prepared_item_in_umem(&umem, 0, &packet, libc::AF_INET as u8);
        let marked_prepared = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut prepared_item,
            &umem,
        );
        assert!(marked_prepared, "Prepared variant must mark");

        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 2,
            "single counter must reflect both Local and Prepared marks",
        );
    }

    /// Insert a single 802.1Q VLAN tag into an Ethernet-wrapped packet
    /// between the MAC addresses and the ethertype. Used by the
    /// VLAN-aware regression tests for both Local and Prepared paths.
    fn insert_single_vlan_tag(packet: Vec<u8>, vid: u16, priority: u8) -> Vec<u8> {
        assert!(packet.len() >= ETH_HDR_LEN, "packet must be eth-framed");
        let mut tagged = Vec::with_capacity(packet.len() + VLAN_TAG_LEN);
        tagged.extend_from_slice(&packet[..12]); // dst + src MAC
        tagged.extend_from_slice(&[0x81, 0x00]); // TPID
        let tci: u16 = ((priority as u16) << 13) | (vid & 0x0FFF);
        tagged.extend_from_slice(&tci.to_be_bytes());
        tagged.extend_from_slice(&packet[12..]); // original ethertype + payload
        tagged
    }

    /// #728 review pin: the Prepared (zero-copy) path has its own
    /// slice/offset plumbing on top of the L3-offset helper. The VLAN
    /// regression on the Local path is necessary but not sufficient —
    /// Local could stay correct while Prepared silently regressed to
    /// stamping the wrong byte. This drives a single-802.1Q ECT(0)
    /// frame through `apply_cos_admission_ecn_policy` at a *non-zero*
    /// UMEM offset and pins that:
    ///   - CE lands at `l3_offset + 1` relative to the frame start
    ///     (i.e. at `frame_offset + 19` inside the UMEM),
    ///   - the VLAN TCI bytes at frame-offset 14..16 are unchanged,
    ///   - the IPv4 header checksum still validates from scratch.
    /// A revert to a hardcoded 14 would stamp byte 15 (inside the TCI)
    /// and this test would fail on the checksum validate as well as
    /// on the TCI-untouched assertion.
    #[test]
    fn admission_ecn_marks_prepared_single_vlan_tagged_ipv4_packet() {
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;

        let packet = build_ipv4_test_packet(ECN_ECT_0);
        let vid: u16 = 80;
        let priority: u8 = 5;
        let tci: u16 = ((priority as u16) << 13) | vid;
        let tagged = insert_single_vlan_tag(packet, vid, priority);

        // Non-zero UMEM offset so we also prove offset arithmetic
        // (slice_mut_unchecked + l3_offset) composes correctly on a
        // non-head frame.
        let frame_offset: u64 = 128;
        let umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&umem, frame_offset, &tagged, libc::AF_INET as u8);

        let before = snapshot_counters(queue);
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );
        assert!(
            marked,
            "VLAN-tagged ECT(0) Prepared frame must be marked at the VLAN-shifted offset",
        );
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked + 1);

        // Read back the UMEM bytes for the frame and verify ECN = CE
        // at frame_offset + 19 (= l3_offset + 1 = 18 + 1).
        let post = umem
            .slice(frame_offset as usize, tagged.len())
            .expect("umem slice readback")
            .to_vec();
        assert_eq!(
            post[19] & ECN_MASK,
            ECN_CE,
            "CE must land at VLAN-shifted l3_offset + 1",
        );
        // VLAN TCI at bytes 14..16 must be byte-identical. A revert to
        // hardcoded offset 14 would corrupt these bytes.
        assert_eq!(
            u16::from_be_bytes([post[14], post[15]]),
            tci,
            "VLAN TCI must be untouched by ECN marking on the Prepared path",
        );
        // IP checksum recomputed from scratch over the post-mark
        // IPv4 header must equal the 16-bit value in the frame.
        let iphdr_start = 18;
        let iphdr = &post[iphdr_start..iphdr_start + 20];
        let expected_csum = compute_ipv4_header_checksum(iphdr);
        let actual_csum = u16::from_be_bytes([post[iphdr_start + 10], post[iphdr_start + 11]]);
        assert_eq!(
            actual_csum, expected_csum,
            "incremental checksum update must match a from-scratch recomputation",
        );
    }
}
