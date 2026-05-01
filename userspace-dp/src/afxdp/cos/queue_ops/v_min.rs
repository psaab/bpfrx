use super::*;

// MQFQ V_min coordination split out of queue_ops/mod.rs per #1034 P1.
// These fns coordinate the per-queue virtual-time floor (`vtime_floor`)
// across workers participating in shared-exact queues. Together they
// implement the suspension / continuation handshake that prevents
// runaway flows from monopolizing a shared-exact queue.

/// #940 — publish the committed `queue_vtime` to the V_min floor
/// slot. Called from each TX-ring commit site AFTER `settle_*`
/// returns, so the published value reflects only frames that were
/// actually inserted into the TX ring (rollbacks via
/// `cos_queue_push_front` already republished any corrected vtime
/// via the existing rollback hook in that function).
///
/// Memory ordering: libxdp's `xsk_ring_prod__submit` (called by
/// `RingTx::commit` via `bridge_xsk_ring_prod_submit` at
/// csrc/xsk_bridge.c:108-111) issues a release-store on the producer
/// head per the AF_XDP ring-buffer ABI. Our `slot.publish()` uses
/// `Ordering::Release` (types/shared_cos_lease.rs PaddedVtimeSlot::publish). On the
/// same worker thread, program order: producer commit → V_min
/// publish. Peers reading the slot via `Ordering::Acquire` thus
/// observe a vtime that reflects frames already in the TX ring.
///
/// The libxdp release-store contract is an upstream ABI assumption;
/// the worktree does NOT vendor libxdp. If libxdp is swapped or
/// downgraded, this contract MUST be re-verified.
///
/// F4 invariant: `vtime_floor` is only populated on flow_fair queues
/// (per `promote_cos_queue_flow_fair`). FIFO queues should never
/// reach the publish path. Trip loud in debug builds AND skip
/// silently in release (Gemini adversarial review): if a future
/// caller mistakenly attaches a floor to a non-flow_fair queue, the
/// debug_assert flags it during dev/test; in release we early-return
/// rather than broadcast a frozen `queue_vtime` that would mislead
/// peers' V_min calculations as garbage telemetry.
#[inline]
pub(in crate::afxdp) fn publish_committed_queue_vtime(queue: Option<&CoSQueueRuntime>) {
    let Some(queue) = queue else {
        return;
    };
    debug_assert!(
        queue.vtime_floor.is_none() || queue.flow_fair,
        "publish_committed_queue_vtime: vtime_floor set on non-flow-fair queue (queue_id={})",
        queue.queue_id,
    );
    if !queue.flow_fair {
        // Release-build escape hatch for the F4 invariant. flow_fair
        // queues are the only ones with meaningful per-pop vtime
        // advance; FIFO queues' queue_vtime stays at 0 and a publish
        // would broadcast a frozen value forever.
        return;
    }
    let Some(floor) = queue.vtime_floor.as_ref() else {
        return;
    };
    let Some(slot) = floor.slots.get(queue.worker_id as usize) else {
        return;
    };
    slot.publish(queue.queue_vtime);
}

#[inline]
fn compute_v_min_lag_threshold(queue_rate_bytes: u64, participating: u32) -> u64 {
    let participating = participating.max(1) as u64;
    let per_worker_rate = queue_rate_bytes / participating;
    let lag_bytes =
        (per_worker_rate as u128 * V_MIN_LAG_THRESHOLD_NS as u128 / 1_000_000_000u128) as u64;
    lag_bytes.max(V_MIN_MIN_LAG_BYTES)
}

/// #941 Work item D — consume one suspension slot if active. Called
/// from drain functions ONCE per drain call AFTER the
/// `free_tx_frames.is_empty()` preflight passes (so a no-progress
/// drain doesn't burn a suspension slot). Returns `true` if this
/// drain call is suspended (V_min check should be skipped for the
/// entire drain).
///
/// Memory ordering: this function is single-writer (the owning
/// worker thread). Peers don't read `v_min_suspended_remaining` —
/// it's local to this worker's `CoSQueueRuntime`.
#[inline]
pub(in crate::afxdp) fn cos_queue_v_min_consume_suspension(queue: &mut CoSQueueRuntime) -> bool {
    if queue.v_min_suspended_remaining > 0 {
        queue.v_min_suspended_remaining -= 1;
        return true;
    }
    false
}

/// #917 — V_min sync read-path: returns true if the local
/// queue_vtime is within `LAG_THRESHOLD` of the peer-min, false
/// if the local worker should throttle this queue's drain for
/// this batch. Caller increments `pop_count` before calling and
/// the helper internally skips on cadence (1-in-K) so the
/// peer-cache-line read happens at most once per K pops.
///
/// Suspension boundary (#941 Work item D): this function does NOT
/// *read* or *consume* `v_min_suspended_remaining` — that's done
/// at drain-entry by `cos_queue_v_min_consume_suspension` in the
/// wrapping drain function. This function only *arms* suspension
/// (writes to `v_min_suspended_remaining`) on the hard-cap
/// activation path below. Lifecycle:
///   - drain function consumes suspension (reads + decrements).
///   - this function arms suspension (writes max value on hard-cap).
///
/// Returns `true` (continue) on:
/// - Cadence skip (not at pop-count K boundary).
/// - No `vtime_floor` (non-shared_exact queue or floor not yet
///   allocated).
/// - No participating peers (this worker is alone — V_min sync
///   has nothing to sync against).
/// - Local vtime within LAG_THRESHOLD of V_min.
/// - Hard-cap activated (force-continue + arm suspension).
///
/// Returns `false` (throttle) if `queue_vtime > V_min + LAG` AND
/// hard-cap not yet reached.
#[inline]
pub(in crate::afxdp) fn cos_queue_v_min_continue(queue: &mut CoSQueueRuntime, pop_count: u32) -> bool {
    if pop_count != 1 && !pop_count.is_multiple_of(V_MIN_READ_CADENCE) {
        return true;
    }
    // #917 Codex Q8: V_min sync only applies to shared_exact
    // queues. Owner-local-exact queues by definition have no
    // peers; throttling them against other workers' slots
    // would falsely starve them. Even though
    // `build_shared_cos_queue_vtime_floors_reusing_existing`
    // currently allocates floors for all exact queues, this
    // gate prevents the check from firing on non-shared
    // queues. Belt-and-suspenders against future floor-
    // allocator changes.
    if !queue.shared_exact {
        return true;
    }
    let Some(floor) = queue.vtime_floor.as_ref() else {
        return true;
    };
    let mut participating = 0u32;
    let mut v_min = u64::MAX;
    for (w, slot) in floor.slots.iter().enumerate() {
        if w == queue.worker_id as usize {
            continue;
        }
        if let Some(peer_vtime) = slot.read() {
            participating += 1;
            v_min = v_min.min(peer_vtime);
        }
    }
    if participating == 0 {
        // No peers — reset hard-cap counter and continue.
        queue.consecutive_v_min_skips = 0;
        return true;
    }
    let lag = compute_v_min_lag_threshold(queue.transmit_rate_bytes, participating + 1);
    let cont = queue.queue_vtime <= v_min.saturating_add(lag);
    if cont {
        // Successful V_min check — reset the hard-cap counter so a
        // single throttled batch followed by 7 ok ones doesn't
        // accumulate.
        queue.consecutive_v_min_skips = 0;
        return true;
    }
    // #941 Work item D: hard-cap accounting. After
    // V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttle
    // decisions, force-continue AND arm suspension for the next
    // V_MIN_SUSPENSION_BATCHES drain calls. This bounds the
    // worst-case stall (N consecutive throttled batches) and recovers
    // ~99% throughput under persistent peer-vtime spread (the
    // captured #942 failure pattern).
    queue.consecutive_v_min_skips = queue.consecutive_v_min_skips.saturating_add(1);
    if queue.consecutive_v_min_skips >= V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
        queue.consecutive_v_min_skips = 0;
        queue.v_min_suspended_remaining = V_MIN_SUSPENSION_BATCHES;
        queue.v_min_hard_cap_overrides_scratch =
            queue.v_min_hard_cap_overrides_scratch.saturating_add(1);
        return true;
    }
    false
}
