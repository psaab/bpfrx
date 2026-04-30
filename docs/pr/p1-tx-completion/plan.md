# P1: extract cos/tx_completion.rs from tx.rs

Plan v2 — 2026-04-30. First PR after #956's 8-phase cos/ submodule
decomposition merged at PR #983. Closes the back-edges Phase 7+8
deliberately introduced.

## v2 changelog vs v1 (from Codex round-1)

- R1-1: `mark_cos_queue_runnable` cannot be file-private (tx.rs:2080
  `enqueue_cos_item`, NOT moving). Bumped to `pub(in crate::afxdp)`.
- R1-2: `normalize_cos_queue_state` cannot be file-private — both
  `refresh_cos_interface_activity` (originally NOT moving) AND a test
  at tx.rs:10612 reach it. Now `pub(in crate::afxdp)` (see also R1-3).
- R1-3: **`refresh_cos_interface_activity` joins the move list.** All 3
  tx.rs callers (1180, 2217, 2282) are themselves in moving fns, and
  cos/queue_service.rs has 13 callers — moving it kills the largest
  remaining cos→tx back-edge in P1's scope. Net move size grows from
  18→19 fns, ~550→~600 LOC.
- R1-4: Test usages of moved items (tx.rs:10533, 10558, 10612, 10673,
  10737) require `pub(in crate::afxdp)` visibility on
  `COS_TIMER_WHEEL_TICK_NS`, `normalize_cos_queue_state`,
  `restore_cos_local_items_inner`, `restore_cos_prepared_items_inner`,
  AND a `use super::cos::{...}` line in tx.rs so the bottom-of-file
  `mod tests { use super::*; }` block resolves them.
- R1-6: Remaining cos→tx back-edges from `queue_service` and
  `cross_binding` (transmit_*, reap_tx_completions, maybe_wake_tx,
  recycle_*, refresh deferred to #984) named explicitly (see "Back-edges
  remaining" below).
- R1-7: Hot-path `#[inline]` list reconciled with current source.
- R1-8: Imports corrected — `BindingWorker` lives in `worker.rs`,
  `ParkReason` lives in `cos/queue_service.rs`,
  `std::sync::atomic::Ordering` is required.

## Goal

Move the TX-completion + timer-wheel cluster from tx.rs into
`userspace-dp/src/afxdp/cos/tx_completion.rs`. After this PR every
moving cos↔tx back-edge that #956 Phases 6/7/8 deliberately accepted is
resolved. Remaining back-edges to tx.rs are XSK-ring / worker-binding /
prepared-frame helpers, slated for #984 (afxdp/tx/ split).

## Move list (19 fns + 2 constants)

### Timer wheel cluster (~150 LOC)

| Item | Line | Visibility after move |
|---|---|---|
| `COS_TIMER_WHEEL_TICK_NS` | 1202 | `pub(in crate::afxdp)` (tests at 10533/10537/10558/10562) |
| `COS_TIMER_WHEEL_L0_HORIZON_TICKS` | 1207 | file-private |
| `cos_tick_for_ns` | 1266 | `pub(in crate::afxdp)` |
| `cos_timer_wheel_level_and_slot` | 1270 | `pub(in crate::afxdp)` |
| `wake_cos_queue` | 1292 | file-private |
| `count_tx_ring_full_submit_stall` | 1322 | `pub(in crate::afxdp)` |
| `rearm_cos_queue` | 1341 | file-private |
| `mark_cos_queue_runnable` | 1345 | `pub(in crate::afxdp)` (called by `enqueue_cos_item` tx.rs:2080) |
| `normalize_cos_queue_state` | 1351 | `pub(in crate::afxdp)` (test at 10612) |
| `advance_cos_timer_wheel` | 1370 | `pub(in crate::afxdp)` |
| `cascade_cos_timer_wheel_level1` | 1381 | file-private |
| `wake_due_cos_timer_slot` | 1400 | file-private |

### TX-completion cluster (~450 LOC)

| Item | Line | Visibility after move |
|---|---|---|
| `prime_cos_root_for_service` | 1127 | `pub(in crate::afxdp)` |
| `apply_direct_exact_send_result` | 1142 | `pub(in crate::afxdp)` |
| `refresh_cos_interface_activity` | 2114 | `pub(in crate::afxdp)` ⬅ added in v2 |
| `apply_cos_send_result` | 2159 | `pub(in crate::afxdp)` |
| `apply_cos_prepared_result` | 2220 | `pub(in crate::afxdp)` |
| `restore_cos_local_items_inner` | 2285 | `pub(in crate::afxdp)` (test at 10673) |
| `restore_cos_prepared_items_inner` | 2300 | `pub(in crate::afxdp)` (test at 10737) |

### Total

**~600 LOC** moved. After this PR, `tx.rs` size drops from 13731 → ~13130.

## Visibility rules — source-verified

`pub(in crate::afxdp)` (10 items) — required because they have callers
outside `cos/tx_completion.rs`:
- production cos/queue_service.rs callers, OR
- production tx.rs callers in non-moving fns (`mark_cos_queue_runnable`
  at tx.rs:2080), OR
- `tx::tests` callers at tx.rs:10533–10737.

File-private (5 fns + 1 const) — only callers are co-located in the
move set:
- `wake_cos_queue` (1305, 1419)
- `rearm_cos_queue` (1396, 1422)
- `cascade_cos_timer_wheel_level1` (1375)
- `wake_due_cos_timer_slot` (1377)
- `COS_TIMER_WHEEL_L0_HORIZON_TICKS`

`COS_TIMER_WHEEL_L0_SLOTS` / `_L1_SLOTS` (referenced by
`cos_timer_wheel_level_and_slot` and `cascade_cos_timer_wheel_level1`)
already live in `afxdp/types.rs` as `pub(super)` — reachable from
`cos/*` via the existing pattern.

## #[inline] adds — source-verified list

Hot-path additions for cross-module inlining (per Phase 4-8 lesson):
- `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`,
  `mark_cos_queue_runnable`, `normalize_cos_queue_state`,
  `count_tx_ring_full_submit_stall` — already short, single-purpose.
- `prime_cos_root_for_service`, `apply_direct_exact_send_result`,
  `apply_cos_send_result`, `apply_cos_prepared_result`,
  `advance_cos_timer_wheel`, `restore_cos_local_items_inner`,
  `restore_cos_prepared_items_inner` — per-batch in drain loop.
- `refresh_cos_interface_activity` — fires every per-batch helper, so
  must inline across the cos→cos boundary too.

Not inlined (off per-byte path; preserve existing attributes):
- `wake_cos_queue`, `rearm_cos_queue`,
  `cascade_cos_timer_wheel_level1`, `wake_due_cos_timer_slot`.

(Codex round-2 verifies which of these already carry `#[inline]` and
preserves them — never silently downgrades.)

## Imports for cos/tx_completion.rs (corrected, source-verified)

```rust
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::types::{
    CoSInterfaceRuntime, CoSPendingTxItem, CoSQueueRuntime,
    CoSTimerWheelRuntime, PreparedTxRequest, PreparedTxRecycle,
    TxRequest, COS_TIMER_WHEEL_L0_SLOTS, COS_TIMER_WHEEL_L1_SLOTS,
};
use crate::afxdp::worker::BindingWorker;        // worker.rs:13

use super::queue_ops::{
    cos_item_len, cos_queue_clear_orphan_snapshot_after_drop,
    cos_queue_drain_all, cos_queue_pop_front, cos_queue_push_back,
    cos_queue_push_front, cos_queue_restore_front,
    publish_committed_queue_vtime,
};
use super::queue_service::{count_park_reason, park_cos_queue, ParkReason};
//                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ queue_service.rs:2145

// Back-edges remaining to tx.rs (slated for #984 — afxdp/tx/ split):
use crate::afxdp::tx::{
    maybe_wake_tx, reap_tx_completions, recycle_cancelled_prepared_offset,
    recycle_prepared_immediately, transmit_batch, transmit_prepared_queue,
};
```

(Round-2 reviewers: verify exact import surface against the moved
function bodies; this list is the upper bound and may be trimmed.)

## cos/mod.rs additions

```rust
pub(super) mod tx_completion;

pub(in crate::afxdp) use tx_completion::{
    advance_cos_timer_wheel, apply_cos_prepared_result, apply_cos_send_result,
    apply_direct_exact_send_result, cos_tick_for_ns, cos_timer_wheel_level_and_slot,
    count_tx_ring_full_submit_stall, mark_cos_queue_runnable,
    normalize_cos_queue_state, prime_cos_root_for_service,
    refresh_cos_interface_activity, restore_cos_local_items_inner,
    restore_cos_prepared_items_inner, COS_TIMER_WHEEL_TICK_NS,
};
```

(Re-export visibility matches the items themselves: anything
`pub(in crate::afxdp)` in tx_completion.rs gets the same re-export
visibility from cos/mod.rs. File-private items are NOT re-exported.)

## tx.rs changes

- Remove the 19 fn definitions + 2 constants.
- Remove the Phase-6 visibility-bump comment block above
  `cos_tick_for_ns`.
- Add at the existing `use super::cos::{...}` block (currently at
  tx.rs:1227 / 1240):

  ```rust
  use super::cos::{
      advance_cos_timer_wheel, apply_cos_prepared_result, apply_cos_send_result,
      apply_direct_exact_send_result, cos_tick_for_ns, cos_timer_wheel_level_and_slot,
      count_tx_ring_full_submit_stall, mark_cos_queue_runnable,
      normalize_cos_queue_state, prime_cos_root_for_service,
      refresh_cos_interface_activity, restore_cos_local_items_inner,
      restore_cos_prepared_items_inner, COS_TIMER_WHEEL_TICK_NS,
  };
  ```

  This satisfies BOTH (a) production callers in non-moving tx.rs fns
  (`enqueue_cos_item` at 2080 needing `mark_cos_queue_runnable`) AND
  (b) the bottom-of-file `mod tests { use super::*; }` block at
  tx.rs:2907 reaching items via `super::*`.

## Back-edges remaining — explicit, scoped to #984

These are NOT in P1's scope. They stay because they're XSK-ring /
worker-binding / prepared-frame primitives owned by `tx::*` until the
afxdp/tx/ module split (#984). The list below is taken from the current
import block of `cos/queue_service.rs` and `cos/cross_binding.rs`:

From `cos/queue_service.rs:59` (still in source after this PR):
- `cos_queue_dscp_rewrite` (tx.rs:1966)
- `maybe_wake_tx` (tx.rs:2808)
- `reap_tx_completions`
- `recycle_cancelled_prepared_offset`
- `remember_prepared_recycle`
- `stamp_submits`
- `transmit_batch`, `transmit_prepared_queue`
- `TxError`
- guarantee/quantum constants (`COS_GUARANTEE_VISIT_NS`,
  `COS_GUARANTEE_QUANTUM_*`, `COS_SURPLUS_ROUND_QUANTUM_BYTES`)

From `cos/cross_binding.rs:30`:
- `recycle_prepared_immediately` (tx.rs:2375)

After P1: 1 fewer cos→tx import (`refresh_cos_interface_activity`
gone). The plan does NOT claim "every back-edge resolved" — only
"every back-edge introduced by Phases 6/7/8 closed."

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/tx_completion.rs`: ~650 LOC
  (~600 moved + ~50 lines header/imports/notes).
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/cos/queue_service.rs`: switch
  `refresh_cos_interface_activity` import from `super::tx::` to
  `super::tx_completion::` (or `super::` via cos/mod.rs re-export —
  reviewer preference).
- `userspace-dp/src/afxdp/tx.rs`: −600 LOC; extend the cos:: import
  block.

## Tests

No new tests required — pure structural refactor. Existing
`tx::tests` callers (tx.rs:10533, 10537, 10558, 10562, 10612, 10673,
10737) reach moved items via the cos:: re-export chain through
tx.rs's `use super::cos::{...}` line, which `mod tests { use super::*; }`
imports transitively. Same Phase 1-8 pattern.

If any test reaches an item whose `pub(in crate::afxdp)` visibility is
not enough (e.g. wants direct fn-private access), it will fail to
compile — at which point we either (a) bump the item's visibility (no
real cost), or (b) move the test to `cos/tx_completion.rs` alongside
its target. v2 expects no such test to exist.

## Risk

**Low-medium.** ~600 LOC. Hot-path concerns:

- `apply_cos_send_result` / `apply_cos_prepared_result` /
  `refresh_cos_interface_activity` fire per batch. Cross-module
  `#[inline]` preserves the inlining boundary per Phase 4-8 lesson.
- `cos_tick_for_ns` is a one-liner; cross-module move + `#[inline]`
  is free.
- Timer-wheel functions (`advance_cos_timer_wheel`,
  `cascade_*_level1`, `wake_due_*`) fire on each drain cycle but only
  hit the slow path when timer slots have queued queues. No per-byte
  overhead concern.

Atomic ordering: `apply_cos_send_result` advances queue state and
calls `publish_committed_queue_vtime` (cos/queue_ops.rs) — that fn's
Release ordering is preserved by the move (already-extracted
publish_* doesn't change). `Ordering::Release` / `Ordering::Acquire`
explicitly imported from `std::sync::atomic`.

After this PR, every `pub(in crate::afxdp)` visibility bump from
Phases 6/7/8 except those tied to XSK-ring helpers (#984 scope) is
cleaned up.

## Acceptance

- `cargo build --bins` clean (no new unused-import warnings).
- `cargo test --bins` 865/0/2 (current rolling baseline).
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (all 7 classes 5201-5207), failover (RG1
  cycled twice, ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on the cross-reviews.
- Copilot review on the PR addressed.

## After P1

Stage 2 of the long sequence: #984 — afxdp/tx/ module
(P2a stats.rs, P2b rings.rs, P2c dispatch.rs, P2d collapse tx.rs).
