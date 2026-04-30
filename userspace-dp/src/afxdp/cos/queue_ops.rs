// #956 Phase 5: queue ops + MQFQ ordering bookkeeping + V-min slot
// lifecycle, extracted from tx.rs. Provides the full queue-state
// surface that admission gates feed into and the drain scheduler
// consumes:
//
//   - Queue accessors: cos_queue_is_empty, cos_queue_len,
//     cos_queue_front, cos_queue_min_finish_bucket (file-private),
//     cos_item_len.
//   - Enqueue / dequeue: cos_queue_push_back, cos_queue_push_front,
//     cos_queue_pop_front, cos_queue_pop_front_no_snapshot,
//     cos_queue_pop_front_inner (file-private),
//     cos_queue_drain_all, cos_queue_restore_front,
//     cos_queue_clear_orphan_snapshot_after_drop.
//   - MQFQ ordering bookkeeping (Phase 3 deferred these — Gemini
//     Phase 3 round-1 finding): account_cos_queue_flow_enqueue,
//     account_cos_queue_flow_dequeue. Both are
//     pub(in crate::afxdp) with cfg-gated re-export from cos/mod.rs
//     because tx::tests still reaches them directly at 14 sites.
//   - V-min slot lifecycle: publish_committed_queue_vtime,
//     cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
//     and the file-private compute_v_min_lag_threshold helper plus
//     the V_MIN_READ_CADENCE / V_MIN_LAG_THRESHOLD_NS /
//     V_MIN_MIN_LAG_BYTES constants. The throttle-cap constants
//     V_MIN_CONSECUTIVE_SKIP_HARD_CAP and V_MIN_SUSPENSION_BATCHES
//     are pub(in crate::afxdp) with cfg-gated re-export — tx::tests
//     references them directly.
//
// 14 always-on cross-module fns get pub(in crate::afxdp); 4 items
// (account_*, V_MIN_CONSECUTIVE_SKIP_HARD_CAP, V_MIN_SUSPENSION_BATCHES)
// get pub(in crate::afxdp) with #[cfg(test)] pub(super) use
// re-export from cos/mod.rs. Per-byte hot-path fns carry #[inline]
// per the Phase 4 lesson — pub(in crate::afxdp) plus #[inline]
// preserves cross-module inlining in release builds.
//
// CoSBatch / CoSServicePhase / ExactCoSQueueKind enums and their
// consumers (select_cos_*_batch, service_exact_*_queue_direct)
// stay in tx.rs through Phase 7 (queue_service) — they live with
// the dispatch entry points, not the queue state primitives.

use std::collections::VecDeque;

use crate::afxdp::types::{
    CoSPendingTxItem, CoSQueuePopSnapshot, CoSQueueRuntime,
};
use crate::afxdp::TX_BATCH_SIZE;
use crate::session::SessionKey;

use super::flow_hash::{cos_flow_bucket_index, cos_item_flow_key};

#[inline]
pub(in crate::afxdp) fn account_cos_queue_flow_enqueue(
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
pub(in crate::afxdp) fn account_cos_queue_flow_dequeue(
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
        // #941 Work item A: bucket-empty vacate. When this worker's
        // last active bucket on a shared_exact queue empties, vacate
        // the V_min slot so peers don't see a phantom-participating
        // worker holding a stale-low value. Single-writer invariant
        // holds — only this worker writes its own slot.
        if queue.shared_exact && queue.active_flow_buckets == 0 {
            if let Some(floor) = queue.vtime_floor.as_ref() {
                if let Some(slot) = floor.slots.get(queue.worker_id as usize) {
                    slot.vacate();
                }
            }
        }
    }
    queue.flow_bucket_bytes[bucket] = remaining;
}

#[inline]
pub(in crate::afxdp) fn cos_queue_is_empty(queue: &CoSQueueRuntime) -> bool {
    if !queue.flow_fair {
        return queue.items.is_empty();
    }
    queue.flow_rr_buckets.is_empty()
}

#[inline]
pub(in crate::afxdp) fn cos_queue_len(queue: &CoSQueueRuntime) -> usize {
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
pub(in crate::afxdp) fn cos_queue_front(queue: &CoSQueueRuntime) -> Option<&CoSPendingTxItem> {
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
pub(in crate::afxdp) fn cos_queue_push_back(queue: &mut CoSQueueRuntime, item: CoSPendingTxItem) {
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
pub(in crate::afxdp) fn cos_queue_push_front(queue: &mut CoSQueueRuntime, item: CoSPendingTxItem) {
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
    // #917 Phase 3: republish the rolled-back queue_vtime so peers
    // see the restored value, not the speculative pop's advanced
    // value. Without this, a peer reading mid-rollback would see
    // an inflated V_min slot for this worker — over-throttling
    // peers until the next pop fixes it.
    if let Some(floor) = queue.vtime_floor.as_ref() {
        if let Some(slot) = floor.slots.get(queue.worker_id as usize) {
            slot.publish(queue.queue_vtime);
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
pub(in crate::afxdp) fn cos_queue_pop_front(queue: &mut CoSQueueRuntime) -> Option<CoSPendingTxItem> {
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
pub(in crate::afxdp) fn cos_queue_pop_front_no_snapshot(
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
        // #940: V_min publish moved to post-settle commit boundary.
        // See `publish_committed_queue_vtime` for details.
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
#[inline]
pub(in crate::afxdp) fn cos_queue_clear_orphan_snapshot_after_drop(queue: &mut CoSQueueRuntime) {
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

#[inline]
pub(in crate::afxdp) fn cos_queue_drain_all(queue: &mut CoSQueueRuntime) -> VecDeque<CoSPendingTxItem> {
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

#[inline]
pub(in crate::afxdp) fn cos_queue_restore_front(queue: &mut CoSQueueRuntime, mut items: VecDeque<CoSPendingTxItem>) {
    while let Some(item) = items.pop_back() {
        cos_queue_push_front(queue, item);
    }
}

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
/// `Ordering::Release` (types.rs PaddedVtimeSlot::publish). On the
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

/// #917 — V_min sync throttle decision. Plan §3.3 v2 cadence:
/// K=8 + mandatory check at drain-batch start (`pop_count == 1`).
const V_MIN_READ_CADENCE: u32 = 8;

/// #917 — per-flow drift budget that V_min sync tolerates before
/// throttling the fast worker. Plan §3.5: `per_worker_rate × 1 ms`.
const V_MIN_LAG_THRESHOLD_NS: u64 = 1_000_000;

/// Floor for the lag budget so the throttle never fires below the
/// minimum forward-progress unit (~16 MTU at 1500 B = 24 KB).
const V_MIN_MIN_LAG_BYTES: u64 = 24_000;

#[inline]
fn compute_v_min_lag_threshold(queue_rate_bytes: u64, participating: u32) -> u64 {
    let participating = participating.max(1) as u64;
    let per_worker_rate = queue_rate_bytes / participating;
    let lag_bytes =
        (per_worker_rate as u128 * V_MIN_LAG_THRESHOLD_NS as u128 / 1_000_000_000u128) as u64;
    lag_bytes.max(V_MIN_MIN_LAG_BYTES)
}

/// #941 Work item D — hard-cap escape hatch constants.
pub(in crate::afxdp) const V_MIN_CONSECUTIVE_SKIP_HARD_CAP: u32 = 8;

/// #941 Work item D — N drain calls of V_min suspension after a
/// hard-cap activation. At ~5 K successful drain invocations/sec
/// under load, N=1000 ≈ 200 ms suspension window — long enough for
/// peers to either catch up or visibly persist as out-of-band, and
/// short enough that mouse-latency budgets (#905) are unaffected.
pub(in crate::afxdp) const V_MIN_SUSPENSION_BATCHES: u32 = 1000;

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
    if pop_count != 1 && pop_count.is_multiple_of(V_MIN_READ_CADENCE) == false {
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

#[inline]
pub(in crate::afxdp) fn cos_item_len(item: &CoSPendingTxItem) -> u64 {
    match item {
        CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
        CoSPendingTxItem::Prepared(req) => req.len as u64,
    }
}

