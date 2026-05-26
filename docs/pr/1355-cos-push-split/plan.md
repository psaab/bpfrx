# #1355 — Split 218-LOC `cos_queue_push_front` along the snapshot-axis

**Status:** PLAN-READY (v2 — after Codex task-mpn35b09-ztxsth
PLAN-NEEDS-MINOR and Gemini task-mpn35twr-zfl64q PLAN-NEEDS-MINOR;
all minors recorded in §Round-2 minor fixes below and rolled into
implementation). Re-targeted after unanimous v1 PLAN-KILL
(Codex task-mpn2tomp-5t6oam, Gemini task-mpn2u791-tq1zkx).
Both reviewers said the same thing: the `flow_fair()` config branch
is the wrong axis. The cyclomatic complexity lives in the
snapshot-state machine inside the flow-fair body. v2 re-targets the
split along that axis. v1 also got the helper signatures wrong:
`SessionKey` is `Clone` (not `Copy`), and `cos_item_flow_key`
returns `Option<&SessionKey>` (not `SessionKey`). v2 fixes both.

## v1 PLAN-KILL findings preserved verbatim

### Codex (task-mpn2tomp-5t6oam)

> 1. **The sketched helper signature is not valid pure code motion.**
>    `cos_item_flow_key` returns `Option<&SessionKey>`, and
>    `SessionKey` is `Clone`, not `Copy`. The plan says helpers take
>    `flow_key: SessionKey` and that it is `Copy`; both are false.
>    Passing a borrow into `item` plus moving `item` into the helper
>    changes the current NLL shape and likely will not compile
>    without either cloning the key or computing the bucket before
>    moving `item`. That is no longer "helper bodies move verbatim."
>
> 2. **The split axis is too weak.** The non-flow-fair path is
>    already isolated as a 4-line early return. Moving it to
>    `push_front_non_flow_fair` does not address the real review
>    pain: snapshot match/empty-stack/mismatch, drained-bucket
>    restore, idle-bucket rebuild, active-bucket head rebase, V_min
>    republish, and v8 lease mirrors.
>
> 3. **The claimed test-strength win is not real.** Private helpers
>    in push.rs will not be directly exercised by sibling tests.
>
> 4. **Perf validation is underspecified.** `#[inline]` is a hint.
>    End-to-end iperf is too coarse to catch a 1-5% hot-path
>    regression. The plan needs an explicit codegen gate.
>
> 5. **Hidden invariant list is incomplete.** Misses
>    borrowed-`flow_key`/moved-`item`, `was_empty` vs `was_idle`
>    ordering, active-bucket "no rr reinsert / no tail update /
>    no lease mirror" behavior, zero-length item behavior.

### Gemini (task-mpn2u791-tq1zkx)

> 1. The config-time `flow_fair()` branch is the wrong target.
>    Extracting two lines into a 4-argument helper adds zero net-new
>    test capability. The `flow_fair` body is **206 LOC**, not just
>    "150+". Shoving it unmodified into `push_front_flow_fair_v8`
>    fails the engineering-style >100 LOC rule. The cyclomatic
>    complexity is entirely concentrated in the snapshot vs.
>    no-snapshot logic, which v1 ignored.
>
> 2. Missing invariant: the **active-bucket path** (push.rs:219-271)
>    explicitly relies on **skipping** the `active_flow_buckets` and
>    `queue_lease_v8` increments because the bucket is already
>    actively tracked. v1 omitted this.
>
> 3. Test colocation deferral is unacceptable for a "test-win" PR.
>
> 4. Required action: **KILL.** Re-target along the snapshot-axis.

## Issue framing (v2)

`cos_queue_push_front` decomposes naturally into FIVE pieces, three
of which sit inside the flow-fair branch:

1. **Common prelude** — `cos_item_len`, `cos_item_flow_key`,
   `local_item_count` saturating add, branch on `!flow_fair()`.
   Stays in the outer fn.
2. **Non-flow-fair fast path** — `account_cos_queue_flow_enqueue` +
   `hot.items.push_front`. Stays in the outer fn — too small to
   extract per Codex/Gemini.
3. **Flow-fair snapshot resolution** — `worker_id` capture, take
   `&mut ff`, compute `bucket`, pop the snapshot stack, run the
   mismatch panic, restore `queue_vtime`, republish the v_min slot.
4. **Flow-fair drained-bucket rebuild** — `was_empty == true` arm:
   (4a) matched-snapshot restore; (4b) no-snapshot anchor.
5. **Flow-fair active-bucket head rebase** — `was_empty == false`
   arm. No rr reinsert, no tail update, no lease mirror — bucket
   is already tracked.

v2 extracts seven `#[inline]` private helpers covering (3), (4a),
(4b), the republish, the lease mirror, the snapshot pop with the
mismatch panic, and (5).

## Honest scope/value framing

Pure code motion within the flow-fair body. Algorithmic semantics
preserved byte-for-byte. The win is **reviewability + named
contracts** for the snapshot-axis branches Gemini #2 flagged as
missing:

- The active-bucket helper's "no rr reinsert / no tail update / no
  lease mirror" contract becomes explicit by absence.
- The snapshot-restore vs no-snapshot-anchor arms become named
  helpers with distinct invariants.

Codegen: `#[inline]` is a hint. v2 adds an explicit
release-mode `objdump` gate proving no direct-call edge to the
private helpers in the emitted `.so`. If the disassembly check
fails, the perf claim downgrades to "no measurable iperf
regression."

*If reviewers conclude the refactor still delivers no reviewability
win that justifies the churn, PLAN-KILL is an acceptable verdict.*

## What's already shipped / partially batched

- `cos_queue_push_back` (51 LOC) in the same file uses a much
  simpler path — no snapshot, no rollback, no rebase. Not touched.
- Sibling extractions in `queue_ops/` (`accounting.rs`, `drain.rs`,
  `pop.rs`, `v_min.rs`, `active_buckets.rs`) already split out
  from the pre-#1034 monolith. v2 follows the same convention.
- `cos_queue_pop_front_no_snapshot` in `pop.rs` is the producer
  for the snapshot stack consumed in (3). Contract unchanged.

## Concrete design

**Layout:** keep everything in `push.rs` as sibling private
helpers. Same convention as the rest of `queue_ops/`.

**Signatures (compile-checked against actual types — `SessionKey:
Clone`, `cos_item_flow_key -> Option<&SessionKey>`):**

```rust
#[inline]
pub(in crate::afxdp) fn cos_queue_push_front(
    queue: &mut CoSQueueRuntime,
    item: CoSPendingTxItem,
) {
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item); // Option<&SessionKey>
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.hot.local_item_count =
            queue.hot.local_item_count.saturating_add(1);
    }
    if !queue.flow_fair() {
        account_cos_queue_flow_enqueue(queue, flow_key, item_len);
        queue.hot.items.push_front(item);
        return;
    }
    // Codex #1: compute bucket via a short &ff borrow BEFORE item
    // is moved. bucket is usize (Copy) so it crosses the helper
    // boundary cleanly; flow_key (which borrows into item) is
    // dropped here.
    let worker_id = queue.v_min.worker_id as usize;
    let bucket = {
        let ff = queue.flow_fair_state.as_ref().expect(
            "cos_queue_push_front: flow_fair queue without \
             flow_fair_state",
        );
        cos_flow_bucket_index(ff.flow_hash_seed, flow_key)
    };
    push_front_flow_fair_v8(queue, bucket, item_len, item, worker_id);
}

#[inline]
fn push_front_flow_fair_v8(
    queue: &mut CoSQueueRuntime,
    bucket: usize,
    item_len: u64,
    item: CoSPendingTxItem,
    worker_id: usize,
) {
    let snapshot = {
        let ff = queue.flow_fair_state.as_mut().expect(
            "cos_queue_push_front: flow_fair queue without \
             flow_fair_state",
        );
        let snap = pop_matching_snapshot(ff, bucket);
        restore_queue_vtime(ff, snap.as_ref(), item_len);
        snap
    };
    // ff &mut borrow ends. v_min republish needs queue.v_min
    // (disjoint field) — same NLL pattern as the monolith.
    republish_worker_vtime_slot(queue);
    let ff = queue.flow_fair_state.as_mut().expect(
        "cos_queue_push_front: flow_fair queue without \
         flow_fair_state",
    );
    let was_empty = ff.flow_bucket_items[bucket].is_empty();
    if was_empty {
        if let Some(snap) = snapshot {
            push_front_drained_bucket_with_snapshot(
                ff, bucket, item_len, item, snap,
            );
            // ff borrow ends here (last use above).
            mirror_lease_active_flow_increment(queue, worker_id);
        } else {
            let was_idle = push_front_drained_bucket_no_snapshot(
                ff, bucket, item_len, item,
            );
            if was_idle {
                mirror_lease_active_flow_increment(queue, worker_id);
            }
        }
        return;
    }
    push_front_active_bucket_head_rebase(ff, bucket, item_len, item);
}

#[inline]
fn pop_matching_snapshot(
    ff: &mut FlowFairState,
    bucket: usize,
) -> Option<CoSQueuePopSnapshot> {
    let stack_top_bucket =
        ff.pop_snapshot_stack.last().map(|s| usize::from(s.bucket));
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

#[inline]
fn restore_queue_vtime(
    ff: &mut FlowFairState,
    snapshot: Option<&CoSQueuePopSnapshot>,
    item_len: u64,
) {
    match snapshot {
        Some(snap) => ff.queue_vtime = snap.pre_pop_queue_vtime,
        None => {
            ff.queue_vtime =
                ff.queue_vtime.saturating_sub(item_len);
        }
    }
}

#[inline]
fn republish_worker_vtime_slot(queue: &CoSQueueRuntime) {
    let ff = match queue.flow_fair_state.as_ref() {
        Some(f) => f,
        None => return,
    };
    if let Some(floor) = queue.v_min.vtime_floor.as_ref() {
        if let Some(slot) =
            floor.slots.get(queue.v_min.worker_id as usize)
        {
            slot.publish(ff.queue_vtime);
        }
    }
}

#[inline]
fn push_front_drained_bucket_with_snapshot(
    ff: &mut FlowFairState,
    bucket: usize,
    item_len: u64,
    item: CoSPendingTxItem,
    snap: CoSQueuePopSnapshot,
) {
    ff.flow_bucket_bytes[bucket] =
        ff.flow_bucket_bytes[bucket].saturating_add(item_len);
    ff.flow_bucket_head_finish_bytes[bucket] = snap.pre_pop_head_finish;
    ff.flow_bucket_tail_finish_bytes[bucket] = snap.pre_pop_tail_finish;
    ff.active_flow_buckets =
        ff.active_flow_buckets.saturating_add(1);
    if ff.active_flow_buckets > ff.active_flow_buckets_peak {
        ff.active_flow_buckets_peak = ff.active_flow_buckets;
    }
    ff.flow_bucket_items[bucket].push_front(item);
    ff.flow_rr_buckets.push_front(bucket as u16);
}

#[inline]
fn push_front_drained_bucket_no_snapshot(
    ff: &mut FlowFairState,
    bucket: usize,
    item_len: u64,
    item: CoSPendingTxItem,
) -> bool {
    let was_idle = ff.flow_bucket_bytes[bucket] == 0;
    if was_idle {
        ff.active_flow_buckets =
            ff.active_flow_buckets.saturating_add(1);
        if ff.active_flow_buckets > ff.active_flow_buckets_peak {
            ff.active_flow_buckets_peak = ff.active_flow_buckets;
        }
    }
    ff.flow_bucket_bytes[bucket] =
        ff.flow_bucket_bytes[bucket].saturating_add(item_len);
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

#[inline]
fn mirror_lease_active_flow_increment(
    queue: &CoSQueueRuntime,
    worker_id: usize,
) {
    if let Some(lease) = queue.queue_lease_v8.as_ref() {
        if let Some(slot) =
            lease.worker_active_flow_buckets_for(worker_id)
        {
            slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

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
    ff.flow_bucket_head_finish_bytes[bucket] = ff
        .flow_bucket_head_finish_bytes[bucket]
        .saturating_sub(current_head_bytes);
    ff.flow_bucket_bytes[bucket] =
        ff.flow_bucket_bytes[bucket].saturating_add(item_len);
    ff.flow_bucket_items[bucket].push_front(item);
}
```

**Borrow shape — Codex finding #1 addressed:** the bucket index is
computed via a short `&ff` borrow in the outer fn before `item` is
moved; `flow_key` (which borrows into `item`) is dropped after
`cos_flow_bucket_index` returns. The only thing crossing the helper
boundary is `bucket: usize` (Copy). Inside the flow-fair helper, the
`&mut ff` borrow is taken in two discrete blocks separated by the
disjoint-field access for `republish_worker_vtime_slot` — same NLL
pattern as the monolith, made explicit.

## Public API preservation

- `pub(in crate::afxdp) fn cos_queue_push_front(...)` — signature
  unchanged.
- `pub(in crate::afxdp) fn cos_queue_push_back(...)` — untouched.
- All 7 new helpers are module-private (`fn`, no `pub`).
- `queue_ops/mod.rs:43` re-export unchanged.

## Hidden invariants the change must preserve (complete list)

1. `cos_item_len(&item)` and `cos_item_flow_key(&item)` evaluated
   **before** `matches!(Local(_))`. Preserved in outer fn.
2. `local_item_count` saturating-add fires on **both** branches.
   Preserved in outer fn.
3. `account_cos_queue_flow_enqueue` called **only** on the
   non-flow-fair path.
4. **Bucket index computed before `item` is moved** (Codex #1).
   Outer fn computes via short `&ff` borrow.
5. `worker_id` captured **before** the `&mut ff` borrow (NLL
   discipline from push.rs:65-69).
6. `flow_fair_state` `expect` message preserved verbatim for
   operator-grep parity.
7. **v_min slot republish** fires after vtime restore, before
   bucket arms. Preserved as `republish_worker_vtime_slot`.
8. **v8 lease mirror on snapshot-restore path** —
   unconditionally bumps when `was_empty && Some(snap)`.
9. **v8 lease mirror on no-snapshot anchor path** — fires **only
   when `was_idle`** (Gemini #2). Helper returns `was_idle`;
   call site gates the mirror.
10. **Active-bucket path does NOT bump `active_flow_buckets`, NOT
    push to `flow_rr_buckets`, NOT update tail, NOT mirror lease**
    (Gemini #2). Preserved by absence in
    `push_front_active_bucket_head_rebase`.
11. **`was_empty` vs `was_idle` ordering** (Codex #5). `was_empty`
    read on the queue before any mutation; `was_idle` read on
    `flow_bucket_bytes` before byte mutation. Both helpers
    preserve read-before-mutate.
12. **Snapshot stack mismatch panic** preserved verbatim
    (`assert!(false) + unreachable!()`) inside
    `pop_matching_snapshot`. Same blast radius.
13. **No new allocation** on either branch. All helpers take
    `&mut` references, owned items, primitives, and
    `Option<&CoSQueuePopSnapshot>` / owned snapshot.
14. **`#[inline]`** on outer fn and all 7 helpers.
15. **Zero-length item behavior** (Codex #5) preserved —
    saturating math is no-op for `item_len == 0`; helpers do not
    special-case.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code motion within the flow-fair body. Outer-fn prelude preserved 1:1. Bucket pre-computation is the only new operation; ordering preserved. |
| Lifetime / borrow-checker | MED | Helper boundary forces the `{&mut ff}` - `{&queue access}` - `{&mut ff}` structure to be made explicit via re-borrows. Compile-tested by `cargo build`. |
| Performance regression | LOW-MED | `#[inline]` is a hint. v2 adds an `objdump` codegen gate. If it shows call edges, downgrade to "no measurable iperf regression" and rely on the multi-stream `-P 12 -R` smoke. |
| Architectural mismatch | LOW | v2 IS the snapshot-axis split both v1 reviewers demanded. |

## Test plan

- `cargo build` clean.
- `cargo test --release` — full suite passes.
- 5/5 flake check on the push-front-touching tests in
  `cos/queue_ops/pop_tests.rs` (e.g. line ~1230 — `pop_tests.rs`
  carries the push_front pins by name) and
  `cos/queue_ops/v_min_tests.rs:329` (republish slot test).
- `go test ./...` — 30 Go packages pass.
- **Codegen gate (Codex round-1 #4 + round-2 codegen finding):**
  use `objdump -Cd` (demangled) so Rust-mangled symbol targets
  aren't masked by the literal `<push_front_` grep, and grep the
  WHOLE `.so` for call edges to the helpers, not just the block
  scoped to `cos_queue_push_front`. The vacuous-pass scenario
  (helper inlined into _other_ callers but still emitted as a
  standalone symbol that nothing calls) is also covered by
  grepping for any `call +[0-9a-f]+ +.*push_front_(flow_fair_v8|
  drained_bucket|active_bucket|matching_snapshot|lease_active_
  flow_increment|drained_bucket_no_snapshot|drained_bucket_with_
  snapshot)` across the entire `.so`. Empty output ⇒ INLINED OK.
  Non-empty ⇒ downgrade perf claim and rely on multi-stream
  `-P 12 -R` smoke. Codex round-2 follow-up: also assert the
  searched block exists (the `awk` extraction is not vacuous)
  by sanity-checking the symbol is present in `nm -C` output
  for the `.so` before running the grep.
- Deploy on loss userspace cluster.
- **Pass A — CoS disabled:** v4 + v6 × push + reverse; multi-stream
  `-P 12 -R` reproducers. Line rate, 0 retrans on multi-stream.
- **Pass B — CoS enabled:** per-class smoke 5201-5206 × v4/v6 ×
  push/reverse = 24 cells.

## Out of scope (explicitly)

- Splitting `cos_queue_push_back` (51 LOC; under threshold).
- Migrating push tests out of `cos/queue_ops/tests.rs`. **Gemini #3
  wanted this in the same PR; v2 still defers.** Rationale: tests
  already exercise `cos_queue_push_front` through its public
  surface; helpers are private and exercised transitively. Test
  reorg is a separate concern from function decomposition.
  Reviewer escalation lever: PLAN-NEEDS-MAJOR rather than
  PLAN-KILL if test colocation is required.
- Any change to snapshot stack contract, v8 epoch handoff, or
  head-finish rebase arithmetic.

## Round-2 minor fixes folded into the implementation

Both round-2 reviewers returned PLAN-NEEDS-MINOR; the minors below
are rolled into the implementation, not deferred:

- **Codex round-2 medium — codegen gate inadequate as written.**
  Plan §Test plan now uses `objdump -Cd` (demangled) and greps the
  whole `.so` for calls to any of the seven helper names. Vacuous
  pass guarded by an `nm -C` symbol-presence assertion.
- **Codex round-2 low — test-plan names wrong file.** Plan §Test
  plan now points at `pop_tests.rs:1230` and `v_min_tests.rs:329`
  (the actual push-front-pinned tests) instead of the imagined
  `tests.rs::test_push_front_*` family.
- **Both round-2 reviewers low — panic-message Unicode parity.**
  The `pop_matching_snapshot` sketch in §Concrete design now uses
  `→` (U+2192) instead of `->`, matching `push.rs:119` byte-for-
  byte for operator-grep parity.
- **Gemini round-2 acknowledgment — `was_idle` short-circuit
  reorder.** The original code wraps `was_idle` inside the
  `if let Some(lease)` block; v2 pre-computes `was_idle` as a
  return value from `push_front_drained_bucket_no_snapshot` and
  branches on it BEFORE the lease check at the call site. This
  is harmless (potentially faster on non-v8 queues because we
  skip the lease load entirely when `!was_idle`) but is
  technically a reorder. Acknowledged; semantic identity
  preserved because the lease bump only fires when `was_idle`
  was already true under the original code path.

## Open questions for adversarial review

1. **Snapshot-axis split — right granularity?** Seven helpers
   for ~150 LOC. Coarser cut (e.g., merge 4a+4b into one
   `push_front_drained_bucket` switch on `Option<snap>`) or
   finer cut?
2. **Borrow-shape explicit re-borrow** of `&mut ff` separated by
   `republish_worker_vtime_slot`. Cleaner pattern via
   `worker_id` + cached slot ref?
3. **`#[inline]` on private fns + `objdump` codegen gate.**
   Acceptable, or should it be `cargo asm`-based?
4. **Test colocation deferral (Gemini #3).** v2 still defers
   with explicit justification. PLAN-NEEDS-MINOR vs PLAN-KILL?
5. **`pop_matching_snapshot` returning owned
   `CoSQueuePopSnapshot`** vs `Option<&CoSQueuePopSnapshot>`. v2
   picks owned because the matched-snapshot arm consumes its
   fields by value.
6. **Should `mirror_lease_active_flow_increment` hoist into
   `active_buckets.rs`?** Same pattern exists for push_back /
   accounting paths. v2 keeps it local to minimize cross-file
   churn.
