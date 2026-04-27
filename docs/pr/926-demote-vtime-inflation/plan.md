# Plan: #926 — demote_prepared_cos_queue_to_local vtime preservation

Issue: #926
Predecessor: #913 (MQFQ vtime fix; this is the deferred-NEEDS-MAJOR
follow-up Codex review-mogzqvpf-xojwmt flagged)
Blocks: #917 (V_min sync runs against the corrected vtime signal)

## 1. Problem

(Full walkthrough in the issue body.)

`demote_prepared_cos_queue_to_local` at `tx.rs:5303-5319`
drains a flow-fair exact queue with `cos_queue_drain_all`
(aggregate-bytes vtime advance per pop), then re-enqueues
the converted Local items via `cos_queue_push_back` on the
SUCCESS path. No bytes were transmitted, but `queue_vtime`
gets inflated by the entire drained backlog.

A new flow Y enqueued immediately after demotion can anchor
at the inflated `queue_vtime` with a smaller finish time than
the demoted backlog — recreating temporal-inversion HOL
inversion (same class as #911 / #913).

The failure-rollback path (`drain_all → restore_front`) DOES
work correctly per #913 design — that path is round-trip
neutral. The success path was never neutral and is the bug.

## 2. Goal

Preserve `queue_vtime` and `flow_bucket_*_finish_bytes` across
the success path so that no new flow can jump ahead of the
demoted backlog.

## 3. Approach

### 3.1 Decision: in-place conversion (Option 1 from issue)

The issue body proposes two options:

1. **In-place conversion**: walk `flow_bucket_items[bucket]`
   for each active bucket; replace each
   `CoSPendingTxItem::Prepared` with its `Local` equivalent.
   No drain_all, no push_back, no vtime touch. Items keep
   their position in the bucket's VecDeque.

2. **Snapshot/restore**: save `queue_vtime` +
   `flow_bucket_*_finish_bytes` + `flow_bucket_bytes` +
   `active_flow_buckets` + `active_flow_buckets_peak` before
   `cos_queue_drain_all`. Restore on success.

**Pick Option 1 (in-place).** Cleaner, single-loop, no Vec
clones, no risk of forgetting a field. The in-place path also
preserves item ORDER within the bucket — important for MQFQ
which serializes by VecDeque order within a flow's bucket.

### 3.2 Implementation sketch

```rust
fn demote_prepared_cos_queue_to_local(
    binding: &mut Binding,
    queue: &mut CoSQueueRuntime,
    forwarding: &ForwardingState,
    /* ... existing params ... */
) -> Result<(), DemoteError> {
    // 1. Iterate every active bucket in this queue.
    // 2. Walk that bucket's items VecDeque.
    // 3. For each item: convert Prepared → Local (the same
    //    conversion logic the failure-rollback path uses on
    //    re-enqueue, without the re-enqueue).
    // 4. Update tx-stat counters (Prepared count -- / Local count ++)
    //    inline as items convert. No queued_bytes change.
    // 5. queue_vtime, flow_bucket_*_finish_bytes,
    //    active_flow_buckets all left untouched.
    for (bucket_idx, items) in queue.flow_bucket_items.iter_mut().enumerate() {
        // Skip buckets that don't have Prepared items for this binding.
        for slot in items.iter_mut() {
            match slot {
                CoSPendingTxItem::Prepared(prep) => {
                    // Convert via the same path drain_all → push_back used.
                    let local = convert_prepared_to_local(prep, forwarding, binding)?;
                    *slot = CoSPendingTxItem::Local(local);
                    // Update binding-side tx counters.
                    binding.dec_prepared_count();
                    binding.inc_local_count();
                }
                CoSPendingTxItem::Local(_) => {
                    // Should not occur on this queue type, but skip safely.
                }
                _ => {}
            }
        }
    }
    Ok(())
}
```

The exact `convert_prepared_to_local` body comes from the
existing failure-rollback re-enqueue path. Refactor it into a
shared helper if not already.

### 3.3 Failure-path handling

If `convert_prepared_to_local` fails partway through (e.g.,
forwarding state changed), the queue is in a partial state:
some items Local, some still Prepared. Two options:

- **Two-pass with savepoint**: first pass validates all
  conversions are feasible; second pass commits. Prevents
  partial state but doubles iteration cost.
- **Rollback on failure**: walk the slots already converted
  and revert them to Prepared. Convert is reversible (Local
  → Prepared just unsets the precomputed wire-side state).

**Pick rollback-on-failure.** Cheaper than two-pass; matches
the existing failure semantics that `drain_all → restore_front`
already handled (drain side).

### 3.4 What this is NOT

- Not a change to `cos_queue_drain_all` or
  `cos_queue_push_back`. The failure-rollback path still uses
  them — that path is round-trip neutral and stays correct.
- Not a change to the demote function's caller contract.
  Same Result<(), DemoteError> shape, same observable
  side-effects on success and failure.
- Not a change to per-flow accounting. `queue.queued_bytes`,
  `flow_bucket_bytes[]`, `active_flow_buckets` all unchanged
  across the success path.

## 4. Files touched

- `userspace-dp/src/afxdp/tx.rs`: rewrite
  `demote_prepared_cos_queue_to_local` to use in-place
  conversion on the success path. Failure path unchanged
  (still drain_all → restore_front).
- New unit test:
  `demote_prepared_to_local_preserves_queue_vtime` —
  enqueue several Prepared items; capture pre-demote
  `queue_vtime`/finish-times; demote; assert all preserved.
- New unit test:
  `demote_prepared_to_local_no_temporal_inversion` —
  the issue body's walkthrough (Y can't jump ahead of
  demoted backlog).

## 5. Test strategy

- Existing demote-path tests (failure rollback, partial-fail
  recovery) must continue to pass.
- New regression tests for the in-place success path.
- `cargo test --release` 765+ pass.

## 6. Risks

- **Refactor scope**: extracting `convert_prepared_to_local`
  as a shared helper might force changes in the failure
  rollback re-enqueue path too. Keep the rollback path
  semantically identical — only factoring shared code.
- **Iterator invalidation**: walking `flow_bucket_items[bucket]`
  with `iter_mut` and replacing slots in-place is safe in
  Rust (no length change, no Vec mutation). Verify the
  `binding.dec_prepared_count()` / `inc_local_count()` calls
  don't reach back into `binding.flow_bucket_items` (they
  shouldn't — they update counters on the binding struct, not
  the queue runtime).
- **Interaction with #927 (parallel work)**: #927 changes
  `cos_queue_clear_orphan_snapshot_after_drop`. No file-line
  conflict expected; both in `tx.rs` but different
  functions.
- **Telemetry**: per-binding Prepared-count and Local-count
  drifts are visible via existing counters; no new telemetry
  added.

## 7. Acceptance

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Plan reviewed by Gemini (adversarial); MERGE YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] New regression tests pass.
- [ ] Full `cargo test --release` 765+ pass.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Gemini adversarial code review: MERGE YES.
- [ ] PR opened, Copilot review addressed.
- [ ] Merged.
