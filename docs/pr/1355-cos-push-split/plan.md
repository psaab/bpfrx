# #1355 — Split 218-LOC `cos_queue_push_front` along `flow_fair()` branch

**Status:** DRAFT v1 — pending adversarial plan review.

## Issue framing

`userspace-dp/src/afxdp/cos/queue_ops/push.rs` is 271 production LOC,
but the single function `cos_queue_push_front` (push.rs:54) is a
218-LOC body sitting on the hot per-packet CoS enqueue path. Issue
#1355 asks for a pure code-motion split along the `flow_fair()`
config-time branch, so the two paths are reviewed independently:

- Non-`flow_fair` fast path (~10 LOC).
- `flow_fair` path with v8 v_min epoch accounting, snapshot-rollback,
  disjoint-borrow lease handoff, head-finish rebase (~150+ LOC).

`docs/engineering-style.md` flags >100 LOC as a refactor cue; the
function is 2.18× the threshold and is a Tier-1 hard hit (>200 LOC).
All callers go through `pub(in crate::afxdp)` re-exports from
`queue_ops/mod.rs`, so the public boundary stays at the parent module.

## Honest scope/value framing

Pure code motion. **No** algorithmic change. Hot-path codegen is
preserved by keeping `#[inline]` on the outer fn AND the two helpers.
LLVM should lower the post-split call graph to the same instructions
as the pre-split body — verified by smoke (line rate, 0 retrans) on
the loss userspace cluster, not by IR diffing.

The win is **reviewability + tests**:

- Non-flow-fair branch and flow-fair branch can be exercised by
  separate cargo tests rather than through the union-fn.
- The 150-LOC flow-fair body (snapshot rollback, vtime restore, lease
  handoff) sits in its own helper, not entangled with the trivial
  non-flow-fair branch.

*If reviewers conclude the refactor delivers no reviewability or
test-strength win that justifies the churn, PLAN-KILL is an
acceptable verdict.*

## What's already shipped / partially batched

- `cos_queue_push_back` already lives alongside in `push.rs` (51 LOC).
  Both are `#[inline]` and cross-module-inline through the
  `pub(in crate::afxdp)` re-export at `queue_ops/mod.rs:43`.
- Sibling extractions (`accounting.rs`, `drain.rs`, `pop.rs`,
  `v_min.rs`, `active_buckets.rs`) already split out from the
  pre-#1034 monolith. This PR follows the same module/foo convention.
- Pop+push-front contract pairing is already documented at
  `push.rs:78-124` (#913 peek-then-pop snapshot consumption); the
  helper extraction MUST preserve this contract byte-for-byte.

## Concrete design

**Layout option chosen:** sibling files inside `queue_ops/` (no
`push/` sub-dir). Rationale: `queue_ops/` is already a directory of
sibling files (`pop.rs`, `drain.rs`, `accounting.rs`, etc.), and the
non-`flow_fair` branch is too small (~10 LOC) to deserve its own
file. Both helpers live in the same `push.rs` so the matched
push_back/push_front pair stays colocated.

After the split, `push.rs` contains:

```rust
#[inline]
pub(in crate::afxdp) fn cos_queue_push_front(
    queue: &mut CoSQueueRuntime,
    item: CoSPendingTxItem,
) {
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.hot.local_item_count =
            queue.hot.local_item_count.saturating_add(1);
    }
    if !queue.flow_fair() {
        push_front_non_flow_fair(queue, flow_key, item_len, item);
        return;
    }
    push_front_flow_fair_v8(queue, flow_key, item_len, item);
}

#[inline]
fn push_front_non_flow_fair(
    queue: &mut CoSQueueRuntime,
    flow_key: SessionKey,
    item_len: u64,
    item: CoSPendingTxItem,
) {
    account_cos_queue_flow_enqueue(queue, flow_key, item_len);
    queue.hot.items.push_front(item);
}

#[inline]
fn push_front_flow_fair_v8(
    queue: &mut CoSQueueRuntime,
    flow_key: SessionKey,
    item_len: u64,
    item: CoSPendingTxItem,
) {
    // <existing 150+ LOC verbatim from push.rs:65-271>
}
```

**Critical:** the helper bodies are moved verbatim. The outer fn
shape is preserved 1:1 with the original prelude:

1. `cos_item_len(&item)` (line 55).
2. `cos_item_flow_key(&item)` (line 56).
3. `local_item_count` saturating add for `Local(_)` (lines 57-59).
4. Branch on `!queue.flow_fair()`.
5. Non-flow-fair branch: `account_cos_queue_flow_enqueue` +
   `push_front` (lines 61-62).
6. Flow-fair branch: capture `worker_id`, take `&mut ff`, run the
   snapshot/rollback/lease state machine (lines 65-270).

The flow-fair helper takes ownership of `item` and re-runs the
existing `cos_item_len` / `cos_item_flow_key` for its own use? **No.**
We pass `item_len` and `flow_key` as parameters from the outer fn so
the helper does no redundant work. `item` is moved in by value.

`worker_id` capture stays *inside* the flow-fair helper because the
NLL borrow comment (`push.rs:65-69`) explicitly requires the capture
to happen before the `flow_fair_state.as_mut()` mutable borrow. The
helper boundary does not interfere — the helper has its own scope.

## Public API preservation

- `pub(in crate::afxdp) fn cos_queue_push_front(...)` — signature
  unchanged.
- `pub(in crate::afxdp) fn cos_queue_push_back(...)` — untouched.
- The two new helpers are **module-private** (`fn`, no `pub`). They
  are only callable from within `push.rs`. No re-export from
  `queue_ops/mod.rs`.

## Hidden invariants the change must preserve

1. **`cos_item_len` and `cos_item_flow_key` evaluation order** — read
   BEFORE the `matches!(Local(_))` arm. The current code reads them
   first, then mutates `local_item_count`. Preserved.
2. **`local_item_count` bump fires on BOTH branches** (flow-fair and
   non-flow-fair). The mutation lives in the outer fn before the
   `!flow_fair()` branch, so both helpers inherit it. Preserved by
   leaving the mutation in the outer fn.
3. **`account_cos_queue_flow_enqueue` is called ONLY on the
   non-flow-fair path** (line 61). The flow-fair branch does its own
   bucket-level accounting via the snapshot machinery. Preserved by
   moving the call into `push_front_non_flow_fair`.
4. **`worker_id` capture before `flow_fair_state.as_mut()`** — NLL
   discipline (push.rs:65-69) mandates this order. Preserved
   because the capture moves with the flow-fair body intact.
5. **Snapshot stack contract** — top-entry bucket mismatch panics in
   both dev and release via `assert!(false) + unreachable!()`.
   Preserved verbatim.
6. **`flow_fair_state` expect message** — current message says
   `"cos_queue_push_front: flow_fair queue without flow_fair_state"`.
   Helper retains the same message string so panics still grep with
   the same operator-facing text.
7. **v_min slot republish after vtime restore** — block at lines
   144-148 must run on every flow-fair invocation. Moves verbatim
   into the helper.
8. **v8 lease per-worker counter mirror on both rollback paths**
   (lines 171-175 and 209-215). Moves verbatim.
9. **`#[inline]`** on outer fn AND both helpers, so cross-module
   inlining at the `pub(in crate::afxdp)` boundary still folds the
   call graph flat at -O3.
10. **No new allocation** on either branch. Helpers receive `item` by
    value, `flow_key` (`SessionKey` — `Copy`), `item_len` (`u64`).

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code motion. Outer-fn prelude (cos_item_len, cos_item_flow_key, local_item_count, branch) preserved 1:1. Helper bodies moved verbatim. |
| Lifetime / borrow-checker | LOW | `worker_id` capture stays inside the flow-fair helper before the `&mut ff` borrow; the helper has its own scope so NLL discipline is identical. `item` moves by value through the helper boundary. |
| Performance regression | LOW | `#[inline]` on outer + both helpers; LLVM should produce identical machine code. Smoke gate (line rate, 0 retrans on the multi-stream `-P 12 -R` reverse reproducer) is the live verification. |
| Architectural mismatch (#946 Phase 2 / #961) | LOW | Not a pipeline change. Not a data-structure change. No cross-packet state introduced. The split is along a config-time boolean — the same dimension issue #1355 itself proposes. |

## Test plan

- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build` clean.
- `cargo test --release` — full cargo suite passes (target current
  count after rebases).
- 5/5 flake check on the most affected named test in
  `cos/queue_ops/tests.rs` (push-related — likely
  `test_push_front_rollback_*` family).
- `go test ./...` — all 30 Go packages pass.
- Deploy on loss userspace cluster.
- **Pass A — CoS disabled:** v4 + v6 × push + reverse, plus
  multi-stream `-P 12 -R` reverse reproducers. Line rate, 0 retrans
  on the multi-stream cells.
- **Pass B — CoS enabled:** per-class smoke 5201-5206 × v4/v6 ×
  push/reverse = 24 cells. Shaped classes hit shape rate cleanly.

## Out of scope (explicitly)

- Splitting the flow-fair body further (e.g.,
  `account_then_push_front_flow_fair` sub-extraction the issue body
  suggests). The flow-fair helper will still be over 100 LOC after
  this split; a second extraction can land as a follow-up PR once
  the snapshot-vs-no-snapshot decomposition is reviewed in isolation.
- Migrating push-specific tests from `cos/queue_ops/tests.rs` /
  `cos/queue_ops/pop_tests.rs` into a new `push_tests.rs` file. Test
  colocation is a separate refactor (test files >2000 LOC tracked
  elsewhere).
- Any change to the snapshot stack contract, the v8 epoch handoff,
  or the head-finish rebase arithmetic. All settled in #1229 / #913.

## Open questions for adversarial review

1. **Is splitting along `flow_fair()` the right axis?** The
   alternative is splitting by "snapshot present / absent" inside the
   flow-fair body — that's where the actual cyclomatic complexity
   lives. Is the config-time-branch split the right *first* split, or
   should we go straight for the snapshot-axis split? PLAN-KILL if the
   config-axis split adds no test-strength and the real refactor is
   the snapshot-axis one.
2. **`#[inline]` discipline + cross-module inlining.** The current
   `cos_queue_push_front` is `#[inline]` and `pub(in crate::afxdp)`.
   After the split the *helpers* are private to `push.rs`, so
   cross-module inlining doesn't apply to them — but they're called
   only from within the same crate root. Is `#[inline]` even needed
   on intra-module-private fns? Or does LLVM inline them by default
   at `-O3`?
3. **Parameter passing vs re-reading `cos_item_len`/`flow_key` in
   helpers.** Plan passes them as `u64` + `SessionKey`. If the helper
   bodies are inlined, this is free. If for some reason LLVM declines
   to inline, we pay 16 bytes of stack per helper call. Acceptable?
4. **Helper signature shape.** Should the helpers take
   `&mut CoSQueueRuntime` and pull `item_len` / `flow_key` from
   already-captured locals at the top of the helper, or should the
   outer fn pass them by value? Plan picks the latter to avoid a
   second `cos_item_len(&item)` call after `item` is moved. Right
   choice?
5. **Test colocation deferral.** The issue body explicitly says
   `push_tests.rs` does not exist and tests live in
   `pop_tests.rs` (1996 LOC). Should the test split land in this PR
   or a follow-up? Plan defers. PLAN-KILL or PLAN-NEEDS-MAJOR if
   reviewers think test colocation must land *with* the code split.
6. **Architectural mismatch / wrong-target risk.** #1355 is a
   "Refactor: <Pattern>" issue. Recent history (#946 Phase 2, #961,
   #1144) shows these can be architecturally misdirected. Is this
   refactor's *target* (push.rs single-function) right, or is the
   real review-pain elsewhere in `cos/queue_ops/` (e.g.,
   `pop_tests.rs` 1996 LOC, or the snapshot machinery split across
   `push.rs` + `drain.rs` + `accounting.rs`)?

