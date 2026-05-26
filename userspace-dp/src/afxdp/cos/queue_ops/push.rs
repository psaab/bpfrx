use super::*;

// Push operations: enqueue + push-front for the CoS queue. push_back is
// the standard enqueue path; push_front is used by the worker drain loop
// when a popped item must be returned to the head of the queue (partial
// commit rollback before draining-side bookkeeping settled).
//
// #1355: cos_queue_push_front was decomposed along the snapshot-axis
// into seven #[inline] private helpers (pop_matching_snapshot,
// restore_queue_vtime, republish_worker_vtime_slot,
// push_front_drained_bucket_with_snapshot,
// push_front_drained_bucket_no_snapshot,
// mirror_lease_active_flow_increment,
// push_front_active_bucket_head_rebase). Both round-1 reviewers
// PLAN-KILL'd the earlier flow_fair() axis; the snapshot-axis
// decomposition is the round-2 PLAN-READY split. Plan doc:
// docs/pr/1355-cos-push-split/plan.md.

#[inline]
pub(in crate::afxdp) fn cos_queue_push_back(queue: &mut CoSQueueRuntime, item: CoSPendingTxItem) {
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    // #774: maintain local_item_count alongside the queue pushes
    // so cos_queue_accepts_prepared becomes O(1). `matches!` on a
    // tagged enum is a single branch; far cheaper than an O(n)
    // scan at check time.
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.hot.local_item_count = queue.hot.local_item_count.saturating_add(1);
    }
    // #785 Phase 3 — Codex round-3 HIGH + NEW-1: any push_back
    // invalidates every outstanding pop snapshot. A subsequent
    // push_front must re-anchor fresh rather than restoring
    // pre-pop head/tail of a bucket whose state has since changed
    // underneath us. Cleared in bulk (not per-bucket) because the
    // cost of a tiny Vec::clear is ~zero and the safety contract is
    // simpler: after any new enqueue, no rollback can use ANY
    // snapshot captured before it.
    if let Some(ff) = queue.flow_fair_state.as_mut() {
        ff.pop_snapshot_stack.clear();
    }
    account_cos_queue_flow_enqueue(queue, flow_key, item_len);
    if !queue.flow_fair() {
        queue.hot.items.push_back(item);
        return;
    }
    // Invariant: `flow_fair() == true` ↔ `flow_fair_state.is_some()`.
    // Set together at every promotion / demotion site (admission.rs:508,
    // tx/test_support.rs enable_/disable_test_flow_fair). A mismatch is
    // a structural bug — silently dropping the packet would leak
    // local_item_count and flow accounting; panic instead.
    let ff = queue
        .flow_fair_state
        .as_mut()
        .expect("cos_queue_push_back: flow_fair queue without flow_fair_state");
    let bucket = cos_flow_bucket_index(ff.flow_hash_seed, flow_key);
    let bucket_queue = &mut ff.flow_bucket_items[bucket];
    let was_empty = bucket_queue.is_empty();
    bucket_queue.push_back(item);
    if was_empty {
        ff.flow_rr_buckets.push_back(bucket as u16);
    }
}

/// #1355: thin outer fn — common prelude + non-flow-fair fast path
/// + bucket pre-computation, then dispatch to the flow-fair helper.
///
/// The split along the snapshot-axis lives inside
/// `push_front_flow_fair_v8`. Codex/Gemini round-1 PLAN-KILL
/// rejected the earlier flow_fair() split; round-2 accepted the
/// snapshot-axis decomposition documented in
/// docs/pr/1355-cos-push-split/plan.md.
#[inline]
pub(in crate::afxdp) fn cos_queue_push_front(queue: &mut CoSQueueRuntime, item: CoSPendingTxItem) {
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.hot.local_item_count = queue.hot.local_item_count.saturating_add(1);
    }
    if !queue.flow_fair() {
        account_cos_queue_flow_enqueue(queue, flow_key, item_len);
        queue.hot.items.push_front(item);
        return;
    }
    // #1229 Phase 6 v8: capture worker_id BEFORE the flow_fair_state
    // mutable borrow. NLL ends each `ff` borrow at its last use in
    // each early-return branch; `queue.queue_lease_v8.as_ref()`
    // (disjoint field) is then accessed without an Arc clone. See
    // accounting.rs for the same pattern; plan §v8.1.
    let worker_id = queue.v_min.worker_id as usize;
    // #1355: pre-compute the bucket index via a short `&ff` borrow
    // BEFORE `item` is moved into the flow-fair helper. `flow_key`
    // borrows into `item` (cos_item_flow_key returns
    // `Option<&SessionKey>`; SessionKey is Clone, not Copy), so the
    // bucket-index computation must complete and the borrow drop
    // BEFORE we move `item`. Only `bucket: usize` (Copy) crosses
    // the helper boundary.
    //
    // Invariant: see cos_queue_push_back for the same flow_fair/state
    // pairing. Silent drop here would also corrupt the snapshot stack.
    let bucket = {
        let ff = queue
            .flow_fair_state
            .as_ref()
            .expect("cos_queue_push_front: flow_fair queue without flow_fair_state");
        cos_flow_bucket_index(ff.flow_hash_seed, flow_key)
    };
    push_front_flow_fair_v8(queue, bucket, item_len, item, worker_id);
}

/// #1355: orchestrates the snapshot-axis state machine for the
/// flow-fair push-front path. Re-borrows `&mut flow_fair_state` in
/// two discrete blocks separated by the disjoint-field access in
/// `republish_worker_vtime_slot` (which reads `queue.v_min`). This
/// matches the NLL pattern the monolith used implicitly — v2 just
/// makes the borrow-block boundaries explicit at the helper edges.
#[inline]
fn push_front_flow_fair_v8(
    queue: &mut CoSQueueRuntime,
    bucket: usize,
    item_len: u64,
    item: CoSPendingTxItem,
    worker_id: usize,
) {
    let snapshot = {
        let ff = queue
            .flow_fair_state
            .as_mut()
            .expect("cos_queue_push_front: flow_fair queue without flow_fair_state");
        let snap = pop_matching_snapshot(ff, bucket);
        restore_queue_vtime(ff, snap.as_ref(), item_len);
        snap
    };
    // First `&mut ff` borrow ends. `republish_worker_vtime_slot`
    // re-borrows `&queue.flow_fair_state` and reads `queue.v_min`
    // (disjoint field) — same NLL pattern as the original monolith.
    republish_worker_vtime_slot(queue);
    let ff = queue
        .flow_fair_state
        .as_mut()
        .expect("cos_queue_push_front: flow_fair queue without flow_fair_state");
    let was_empty = ff.flow_bucket_items[bucket].is_empty();
    if was_empty {
        if let Some(snap) = snapshot {
            push_front_drained_bucket_with_snapshot(ff, bucket, item_len, item, snap);
            // `ff` borrow ends here (NLL: last use above).
            // #1229 Phase 6 v8: mirror to lease per-worker counter
            // on this rollback re-increment. Codex v7 review of
            // #1229 caught that omitting this leaks the asymmetry
            // until u32 wrap. Snapshot-restore path: lease mirror
            // fires unconditionally (the bucket was drained AND we
            // restored an item, so active_flow_buckets bumped from
            // 0 → 1).
            mirror_lease_active_flow_increment(queue, worker_id);
        } else {
            // No snapshot — drain_all/restore_front path or
            // fresh-flow caller. Helper returns `was_idle` (the
            // pre-mutation `flow_bucket_bytes == 0` check) so the
            // call site can gate the lease mirror.
            let was_idle = push_front_drained_bucket_no_snapshot(ff, bucket, item_len, item);
            // `ff` borrow ends here.
            // #1229 Phase 6 v8: idle-bucket-rebuild rollback path.
            // Mirror only when `was_idle` (consistent with the
            // pre-#1355 monolith's gate). Plan v2 round-2 Gemini
            // ack: branch on the pre-computed `was_idle` BEFORE
            // the lease load — harmless reorder relative to the
            // monolith's `if let Some(lease) { if was_idle ... }`
            // shape, and skips the lease load entirely for
            // non-v8 queues when `!was_idle`.
            if was_idle {
                mirror_lease_active_flow_increment(queue, worker_id);
            }
        }
        return;
    }
    // Active-bucket path: bucket is already tracked, so NO
    // active_flow_buckets bump, NO flow_rr_buckets push, NO tail
    // update, NO lease mirror (Gemini round-1 finding #2). The
    // helper preserves these by absence.
    push_front_active_bucket_head_rebase(ff, bucket, item_len, item);
}

/// #913: peek-then-pop snapshot consumption.
///
/// Three states:
///   1. Empty stack: legitimate (drain_all cleared it; or
///      fresh-flow / non-Phase-3 caller). Aggregate-bytes
///      rewind path — `vtime -= item_len` pairs with the
///      no-snapshot pop's `vtime += bytes` for round-trip
///      neutrality (see plan §3.7 walkthrough for
///      drain_all→restore_front).
///   2. Top entry's bucket matches: hot-path matched
///      rollback. Pop and restore vtime + head/tail
///      from snapshot (closes #913 max-based advance).
///   3. Top entry's bucket DOES NOT match: hard contract
///      violation. With §3.4's scratch-builder orphan
///      cleanup in place, this is believed unreachable in
///      current code. `assert!(false)` panics in BOTH dev
///      and release.
///
///      No supervisor in this PR (#913 R4 revert): the
///      panic propagates to the default Rust panic
///      handler, which emits the panic message to stderr
///      → journald and kills the worker thread. The
///      helper process keeps running with one fewer
///      worker; bindings served by that worker stall
///      until the daemon is restarted via config change
///      or operator intervention. SAME blast radius as
///      every existing `unwrap`/`expect`/`panic!` site
///      in `worker_loop` — #913 introduces zero
///      incremental panic risk. Cross-cutting panic
///      supervision (catch_unwind on helper side +
///      parent-side restart in xpfd) tracked in #925.
#[inline]
fn pop_matching_snapshot(ff: &mut FlowFairState, bucket: usize) -> Option<CoSQueuePopSnapshot> {
    let stack_top_bucket = ff.pop_snapshot_stack.last().map(|s| usize::from(s.bucket));
    match stack_top_bucket {
        None => None,
        Some(top) if top == bucket => ff.pop_snapshot_stack.pop(),
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
    }
}

/// #913: vtime restore — symmetric inverse of the §3.1 advance.
/// Matched-snapshot path: restore from snapshot for both the
/// was_empty (drained-bucket) and active-bucket branches.
/// Empty-stack path: legacy aggregate-bytes rewind paired with
/// the no-snapshot pop's `vtime += bytes`.
#[inline]
fn restore_queue_vtime(
    ff: &mut FlowFairState,
    snapshot: Option<&CoSQueuePopSnapshot>,
    item_len: u64,
) {
    match snapshot {
        Some(snap) => {
            ff.queue_vtime = snap.pre_pop_queue_vtime;
        }
        None => {
            ff.queue_vtime = ff.queue_vtime.saturating_sub(item_len);
        }
    }
}

/// #917 Phase 3: republish the rolled-back queue_vtime so peers
/// see the restored value, not the speculative pop's advanced
/// value. Without this, a peer reading mid-rollback would see
/// an inflated V_min slot for this worker — over-throttling
/// peers until the next pop fixes it.
///
/// Read-only on the `queue` so the `&mut flow_fair_state` borrow
/// in the caller can be split into two discrete blocks around
/// this call.
#[inline]
fn republish_worker_vtime_slot(queue: &CoSQueueRuntime) {
    let ff = match queue.flow_fair_state.as_ref() {
        Some(f) => f,
        None => return,
    };
    if let Some(floor) = queue.v_min.vtime_floor.as_ref() {
        if let Some(slot) = floor.slots.get(queue.v_min.worker_id as usize) {
            slot.publish(ff.queue_vtime);
        }
    }
}

/// #913: drained-bucket restore from snapshot. Bucket was drained
/// by the matching pop; snapshot holds the exact pre-pop head/tail
/// so we restore them. Caller fires the lease mirror after this
/// returns (unconditional on the snapshot path).
#[inline]
fn push_front_drained_bucket_with_snapshot(
    ff: &mut FlowFairState,
    bucket: usize,
    item_len: u64,
    item: CoSPendingTxItem,
    snap: CoSQueuePopSnapshot,
) {
    ff.flow_bucket_bytes[bucket] = ff.flow_bucket_bytes[bucket].saturating_add(item_len);
    ff.flow_bucket_head_finish_bytes[bucket] = snap.pre_pop_head_finish;
    ff.flow_bucket_tail_finish_bytes[bucket] = snap.pre_pop_tail_finish;
    ff.active_flow_buckets = ff.active_flow_buckets.saturating_add(1);
    if ff.active_flow_buckets > ff.active_flow_buckets_peak {
        ff.active_flow_buckets_peak = ff.active_flow_buckets;
    }
    ff.flow_bucket_items[bucket].push_front(item);
    ff.flow_rr_buckets.push_front(bucket as u16);
}

/// No snapshot — drain_all/restore_front path or fresh-flow caller.
/// Standard idle-bucket re-anchor. The aggregate-bytes vtime rewind
/// (in `restore_queue_vtime`) leaves vtime correctly positioned for
/// `max(tail, vtime) + bytes` (see plan §3.7 walkthrough for the
/// drain_all case).
///
/// Returns `was_idle` — the pre-mutation `flow_bucket_bytes == 0`
/// check. Caller gates the lease mirror on this return value (the
/// lease bump only fires when `was_idle`).
///
/// #1229 Phase 6 v8: `was_idle` serves as both the push-front
/// anchor flag AND the v8 lease bump gate. Captured once here
/// (before any byte mutations) to avoid a redundant re-check after
/// the active_flow_buckets increment below.
#[inline]
fn push_front_drained_bucket_no_snapshot(
    ff: &mut FlowFairState,
    bucket: usize,
    item_len: u64,
    item: CoSPendingTxItem,
) -> bool {
    let was_idle = ff.flow_bucket_bytes[bucket] == 0;
    if was_idle {
        ff.active_flow_buckets = ff.active_flow_buckets.saturating_add(1);
        if ff.active_flow_buckets > ff.active_flow_buckets_peak {
            ff.active_flow_buckets_peak = ff.active_flow_buckets;
        }
    }
    ff.flow_bucket_bytes[bucket] = ff.flow_bucket_bytes[bucket].saturating_add(item_len);
    let new_tail = ff.flow_bucket_tail_finish_bytes[bucket]
        .max(ff.queue_vtime)
        .saturating_add(item_len);
    ff.flow_bucket_tail_finish_bytes[bucket] = new_tail;
    if was_idle {
        ff.flow_bucket_head_finish_bytes[bucket] = new_tail;
    }
    ff.flow_bucket_items[bucket].push_front(item);
    ff.flow_rr_buckets.push_front(bucket as u16);
    was_idle
}

/// #1229 Phase 6 v8: mirror an `active_flow_buckets` increment to
/// the lease per-worker counter. Caller has already bumped the
/// local `active_flow_buckets` count; this hooks the v8 lease
/// per-worker slot to keep cross-worker view consistent.
#[inline]
fn mirror_lease_active_flow_increment(queue: &CoSQueueRuntime, worker_id: usize) {
    if let Some(lease) = queue.queue_lease_v8.as_ref() {
        if let Some(slot) = lease.worker_active_flow_buckets_for(worker_id) {
            slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// #785 Phase 3 — MQFQ push_front onto an ACTIVE bucket.
///
/// Codex adversarial review (round-2 of the #785 series) flagged
/// this path as HIGH: the prior revision funnelled through
/// `account_cos_queue_flow_enqueue`, which only advances `tail`
/// on an active bucket — head stayed stale at a value keyed off
/// whatever was the HEAD packet before this push_front.
/// Selection would then pick the bucket based on the STALE head
/// finish (stale because the item-queue front changed), and the
/// subsequent non-drain pop would `head += bytes(next_head)`
/// off the stale base, producing arbitrary finish values.
///
/// Fix: push_front is only called from TX-ring-full restoration
/// paths where an item was JUST popped from this same bucket.
/// We reverse that pop's head-advance: at pop time we computed
/// `head += bytes(what_is_now_front)`. At push_front time we
/// subtract the SAME quantity to get back to the pop-time head
/// (which was the popped item's finish). The restored item
/// takes over as the new head and inherits that finish — which
/// is exactly what it had before the pop. Net effect: the
/// pop-and-restore round-trip is finish-time neutral, which is
/// what correctness on the error-retry path demands.
///
/// #913: vtime is already restored above (snapshot path or
/// aggregate-bytes path). The active-bucket head reversal here
/// is unchanged from pre-#913 — `head -= bytes(current_head)`
/// is correct under MQFQ "drops consume virtual service"
/// semantics. Reasoning:
///
/// - Single-pop case: push_front is the exact inverse of the
///   most recent pop. head was advanced by bytes(current_head);
///   subtracting reverses it.
/// - Multi-pop case with mid-Drop (e.g., pop A1, pop A2, drop A2,
///   restore A1 while A3 is in bucket): head=4500 after pop A2.
///   Arithmetic gives head=4500-bytes(A3=1500)=3000. Subsequent
///   pop A1 then advances head to 3000+bytes(A3)=4500. A3 ends
///   up at finish=4500, preserving A2's "consumed virtual
///   service" — competing buckets between 3000 and 4500
///   correctly drain before A3.
///
/// (Codex code-review R8 of #785 initially flagged this as wrong
/// with recommendation to use snap.pre_pop_head_finish; R9 then
/// reversed when its own walkthrough showed the arithmetic
/// result is needed for the post-restore-pop case. Documented in
/// §3.3 of the original #785 plan.)
///
/// Invariant (Gemini round-1 finding #2 on #1355): this path does
/// NOT bump active_flow_buckets, does NOT push to flow_rr_buckets,
/// does NOT update tail finish, and does NOT mirror to the v8
/// lease. All preserved by absence — the helper simply does not
/// contain those operations.
#[inline]
fn push_front_active_bucket_head_rebase(
    ff: &mut FlowFairState,
    bucket: usize,
    item_len: u64,
    item: CoSPendingTxItem,
) {
    let current_head_bytes = ff.flow_bucket_items[bucket]
        .front()
        .map(cos_item_len)
        .unwrap_or(0);
    ff.flow_bucket_head_finish_bytes[bucket] =
        ff.flow_bucket_head_finish_bytes[bucket].saturating_sub(current_head_bytes);
    ff.flow_bucket_bytes[bucket] = ff.flow_bucket_bytes[bucket].saturating_add(item_len);
    ff.flow_bucket_items[bucket].push_front(item);
}
