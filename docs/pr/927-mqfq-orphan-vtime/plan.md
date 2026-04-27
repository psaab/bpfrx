# Plan: #927 — MQFQ drained-bucket vtime preservation

Issue: #927
Predecessor: #913 (MQFQ vtime fix; this is the deferred-NEEDS-MAJOR
follow-up Codex review-moh12hph-w5ztyx flagged)
Blocks: #917 (V_min sync runs against the corrected vtime signal)

## 1. Problem

(Full walkthrough in the issue body.)

When the scratch-builder pops multiple items from the SAME bucket
and the LAST item drains the bucket, then is DROPPED (frame too
big, etc.), the surviving earlier item's restore via
`cos_queue_push_front` takes the `was_empty` path. That path
restores `head_finish` from `snap.pre_pop_head_finish` — losing
the dropped item's "virtual service" advance (`served_finish`).
A competing active bucket can then have its scheduling inverted.

The arithmetic-based active-bucket restore (post-#913) is correct.
The drained-bucket / snapshot-restore branch is the gap.

## 2. Goal

Preserve the dropped item's served-finish in the surviving
older same-bucket snapshots, so that when those snapshots are
later popped via `was_empty` restore, `head_finish` reflects
the bytes that were dispatched (and dropped) on this bucket
between the older snapshot and the orphaned snapshot.

## 3. Approach

### 3.1 Helper internals only — no signature change (Codex R1)

v1 proposed adding `item_len: u64` so the helper could compute
`dropped_served_finish = orphan.pre_pop_head_finish + item_len`.
Codex R1 caught two issues:

- The formula over-inflates. `served_finish` for the popped
  item equals `pre_pop_head_finish` (per `tx.rs:4637-4639`,
  served_finish is read FROM `flow_bucket_head_finish_bytes`
  BEFORE the bucket head is updated). Adding `item_len` would
  bump the snapshot frontier by an extra `item_len` bytes,
  unfairly delaying any future flow that re-anchors to this
  bucket.
- The helper signature already has access to the orphan's
  `bucket` field via `CoSQueuePopSnapshot::bucket` (per
  `types.rs:1018-1042`). No caller change needed.

**Decision: pure helper-internal change.** Same signature, no
caller updates. Existing test sites at `tx.rs:11883` and
`:12025` (which Codex R1 also flagged as missing from the v1
plan) are untouched.

### 3.2 Helper body change

Inside `cos_queue_clear_orphan_snapshot_after_drop` at
`tx.rs:4718`, after popping the orphan and the existing
`pre_pop_queue_vtime` clamp loop, add a same-bucket finish-
time clamp using the orphan's served_finish:

```rust
fn cos_queue_clear_orphan_snapshot_after_drop(queue: &mut CoSQueueRuntime) {
    let Some(orphan) = queue.pop_snapshot_stack.pop() else { return };
    let z_committed_vtime = queue.queue_vtime;
    // Orphan's served_finish == its pre_pop_head_finish (the
    // bucket's head_finish at the moment we popped the dropped
    // item). #913 head/tail invariants guarantee any older
    // same-bucket snapshot's frontier was ≤ this value at the
    // time it was captured, so .max(...) only raises and never
    // crosses an already-committed boundary.
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
```

Note: merged into the existing clamp loop so the stack walks
once, not twice.

The `.max(...)` is monotone — older snapshots' finish-times
already reflect committed pops up to that snapshot's pop-time
frontier. Bumping to `orphan_served_finish` only raises them
when the dropped item's served-finish exceeds what was already
recorded. Never lowers, so no semantic regression on the
restore path.

### 3.3 Caller updates

None. The four scratch-builder Drop sites at `tx.rs:2660`,
`:2679`, `:2846`, `:2877` and the two test sites at
`tx.rs:11883`, `:12025` continue to call the helper with the
existing single `queue` argument.

### 3.4 What this is NOT

- Not a change to the active-bucket arithmetic restore path
  (#913 site at `cos_queue_push_front` ~`tx.rs:4459-4500`).
- Not a change to `was_empty` snapshot semantics — only the
  signal feeding into them.
- Not a change to per-flow accounting, bucket flags, or
  active_flow_buckets count.

## 4. Files touched

- `userspace-dp/src/afxdp/tx.rs`: helper-internal change to
  `cos_queue_clear_orphan_snapshot_after_drop` — same single-
  argument signature, just adds the same-bucket finish-time
  clamp inside the existing stack-walk loop using
  `orphan.pre_pop_head_finish` (= the dropped item's
  served_finish). No caller-site updates; no test-call-site
  updates.
- New unit test:
  `mqfq_drained_bucket_orphan_drop_preserves_served_finish` —
  exercises the scenario from the issue body's walkthrough
  (A=[A1,A2], C=[C], pop A1+C+A2, drop A2, restore C and A1,
  assert **A1.head > C.head strictly** so MQFQ pops C first.
  Codex R1: strict `>` because `cos_queue_front` uses strict
  `<` tie-break at `tx.rs:4336-4346`; equal head_finish
  leaves ordering implementation-defined.

## 5. Test strategy

- Existing #913 tests (especially
  `mqfq_same_bucket_multipop_drop_preserves_dropped_item_finish`)
  must continue to pass — they cover the same-bucket-with-
  successor case.
- New regression test for the drained-bucket scenario.
- `cargo test --release` 765+ pass.

## 6. Risks

- **Snapshot-stack walk cost.** Each orphan-cleanup now walks
  the full stack (bounded by TX_BATCH_SIZE = 64 post-#920).
  Worst case 64 comparisons + 0–2 writes per orphan. Orphan
  cleanup itself is rare (only on drop). Negligible.
- **No arithmetic overflow.** v2 reads
  `orphan.pre_pop_head_finish` directly and clamps existing
  snapshot fields with `.max(...)` — no addition, no overflow
  surface. (v1's `+ item_len` was wrong on the merits per
  §3.1; this risk no longer applies.)
- **Interaction with #926 (parallel work).** #926 changes the
  demote-path, not the orphan-cleanup. No file-line conflict
  expected; both touch `tx.rs` but in different functions.

## 7. Acceptance

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Plan reviewed by Gemini (adversarial); MERGE YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] New regression test passes.
- [ ] Full `cargo test --release` 765+ pass.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Gemini adversarial code review: MERGE YES.
- [ ] PR opened, Copilot review addressed.
- [ ] Merged.
