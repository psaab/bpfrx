# P1: extract cos/tx_completion.rs from tx.rs

Plan v1 — 2026-04-30. First PR after #956's 8-phase cos/ submodule
decomposition merged at PR #983. Closes the back-edges Phase 7+8
deliberately introduced.

## Goal

Move the TX-completion + timer-wheel cluster from tx.rs into
`userspace-dp/src/afxdp/cos/tx_completion.rs`. After this PR every
back-edge `cos/* -> tx::*` from Phases 6/7/8 is resolved — cos/* is
fully self-contained, tx.rs is purely XSK-ring + worker-binding glue.

## Move list (18 fns + 2 constants)

### Timer wheel cluster (~150 LOC)

| Item | Line | Visibility |
|---|---|---|
| `COS_TIMER_WHEEL_TICK_NS` | 1202 | const |
| `COS_TIMER_WHEEL_L0_HORIZON_TICKS` | 1207 | const (depends on `COS_TIMER_WHEEL_L0_SLOTS` from types.rs) |
| `cos_tick_for_ns` | 1266 | `pub(in crate::afxdp)` |
| `cos_timer_wheel_level_and_slot` | 1270 | `pub(in crate::afxdp)` |
| `wake_cos_queue` | 1292 | private |
| `count_tx_ring_full_submit_stall` | 1322 | `pub(in crate::afxdp)` |
| `rearm_cos_queue` | 1341 | private |
| `mark_cos_queue_runnable` | 1345 | private |
| `normalize_cos_queue_state` | 1351 | private |
| `advance_cos_timer_wheel` | 1370 | `pub(in crate::afxdp)` |
| `cascade_cos_timer_wheel_level1` | 1381 | private |
| `wake_due_cos_timer_slot` | 1400 | private |

### TX-completion cluster (~400 LOC)

| Item | Line | Visibility |
|---|---|---|
| `prime_cos_root_for_service` | 1127 | `pub(in crate::afxdp)` |
| `apply_direct_exact_send_result` | 1142 | `pub(in crate::afxdp)` |
| `apply_cos_send_result` | 2159 | `pub(in crate::afxdp)` |
| `apply_cos_prepared_result` | 2220 | `pub(in crate::afxdp)` |
| `restore_cos_local_items_inner` | 2285 | `pub(in crate::afxdp)` |
| `restore_cos_prepared_items_inner` | 2300 | `pub(in crate::afxdp)` |

### Total
**~550 LOC** moved. After this PR, `tx.rs` size drops from 13731 → ~13180.

## Visibility

Production callers (cos/queue_service.rs and tx.rs after move):
- All 6 TX-completion fns: `pub(in crate::afxdp)` (already bumped during Phase 7).
- `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`, `count_tx_ring_full_submit_stall`,
  `advance_cos_timer_wheel`: `pub(in crate::afxdp)` (bumped during Phase 6/7).
- Internal helpers (`wake_cos_queue`, `rearm_cos_queue`, `mark_cos_queue_runnable`,
  `normalize_cos_queue_state`, `cascade_cos_timer_wheel_level1`, `wake_due_cos_timer_slot`):
  file-private after move (only co-located callers).
- Constants `COS_TIMER_WHEEL_TICK_NS`, `COS_TIMER_WHEEL_L0_HORIZON_TICKS`: file-private.

`COS_TIMER_WHEEL_L0_SLOTS` / `_L1_SLOTS` (used by `cos_timer_wheel_level_and_slot` and
`cascade_cos_timer_wheel_level1`) live in afxdp/types.rs as `pub(super)` — already
reachable from cos/* descendants via the existing pattern.

## #[inline]

Per the Phase 4-8 lesson:
- Hot-path: `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`,
  `mark_cos_queue_runnable`, `normalize_cos_queue_state`,
  `count_tx_ring_full_submit_stall` — add `#[inline]` if not already
  present.
- Per-batch (called from drain loop): `apply_cos_send_result`,
  `apply_cos_prepared_result`, `apply_direct_exact_send_result`,
  `prime_cos_root_for_service`, `advance_cos_timer_wheel` — add
  `#[inline]`.
- Off per-byte path: `wake_cos_queue`, `rearm_cos_queue`,
  `cascade_cos_timer_wheel_level1`, `wake_due_cos_timer_slot`,
  `restore_cos_*_inner` — preserve existing attributes; do not add.

(Codex round-1 verifies which fns currently carry `#[inline]` in
source — preserve those.)

## Imports for cos/tx_completion.rs (subject to verification)

```rust
use std::collections::VecDeque;

use crate::afxdp::types::{
    BindingWorker, CoSInterfaceRuntime, CoSPendingTxItem, CoSQueueRuntime,
    CoSTimerWheelRuntime, ParkReason, PreparedTxRequest, PreparedTxRecycle,
    TxRequest, COS_TIMER_WHEEL_L0_SLOTS, COS_TIMER_WHEEL_L1_SLOTS,
};
use crate::afxdp::worker::BindingWorker;

use super::queue_ops::{
    cos_item_len, cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all,
    cos_queue_pop_front, cos_queue_push_back, cos_queue_push_front,
    cos_queue_restore_front, publish_committed_queue_vtime,
};
use super::queue_service::{count_park_reason, park_cos_queue, ParkReason as ServiceParkReason};

// Back-edges remaining to tx.rs (still in tx.rs through #984's tx/ split):
use crate::afxdp::tx::{
    recycle_cancelled_prepared_offset, recycle_prepared_immediately,
    refresh_cos_interface_activity, transmit_batch, transmit_prepared_queue,
    reap_tx_completions, maybe_wake_tx,
};
```

Codex round-1 will validate the exact import surface.

## cos/mod.rs additions

```rust
pub(super) mod tx_completion;

pub(super) use tx_completion::{
    advance_cos_timer_wheel, apply_cos_prepared_result, apply_cos_send_result,
    apply_direct_exact_send_result, cos_tick_for_ns, cos_timer_wheel_level_and_slot,
    count_tx_ring_full_submit_stall, prime_cos_root_for_service,
    restore_cos_local_items_inner, restore_cos_prepared_items_inner,
};
```

(Test-touched items get cfg-gated re-exports if any; verified by Codex round-1.)

## tx.rs

- Remove the 18 fn definitions + 2 constants.
- Remove the `cos_tick_for_ns` Phase-6 visibility-bump comment block.
- Add `use super::cos::{...}` for the 10 production-callable items.
- The remaining back-edges from cos/queue_service to tx.rs (transmit_*,
  reap_tx_completions, etc) STAY because those are XSK-ring/worker-binding
  helpers slated for #984 (afxdp/tx/ split).

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/tx_completion.rs`: ~600 LOC
  (~550 moved + ~50 lines header/imports/notes).
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -550 LOC; extend cos:: imports.

## Tests

No new tests required — pure structural refactor. Existing
`tx::tests` callers reach moved items via the cos:: re-export
chain — same Phase 1-8 pattern.

## Risk

**Low-medium.** ~550 LOC. Hot-path concerns:

- `apply_cos_send_result` / `apply_cos_prepared_result` fire per
  batch (~hundreds of times per drain cycle). `#[inline]` preserves
  cross-module inlining per Phase 4-8 lesson.
- `cos_tick_for_ns` is a one-liner; cross-module move + `#[inline]`
  should be free.
- Timer-wheel functions (`advance_cos_timer_wheel`,
  `cascade_*_level1`, `wake_due_*`) fire on each drain cycle but
  only hit the slow path when timer slots have queued queues. No
  per-byte overhead concern.

Atomic ordering: `apply_cos_send_result` advances queue state and
calls `publish_committed_queue_vtime` (cos/queue_ops.rs) — that
fn's Release ordering is preserved by the move (already-extracted
publish_* doesn't change).

After this PR, every `pub(in crate::afxdp)` visibility bump in
tx.rs from Phases 6/7/8 except those tied to XSK-ring helpers (#984
scope) is cleaned up.

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
