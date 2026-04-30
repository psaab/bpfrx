# P2c: extract afxdp/tx/transmit.rs from tx/mod.rs

Plan v3 — 2026-04-30. Stage 2 step 3 of the long sequence after #992
(P2b: tx/rings.rs) merged at master `e7d66795`.

## v3 changelog vs v2 (from Codex round-2)

- Codex r2 found 2 minor doc fixes: `recycle_prepared_immediately`
  caller list now includes `worker.rs:1974` (in addition to
  cos/cross_binding.rs); LOC estimates corrected (~570→~450,
  ~580→~460, ~12320→~12440).

## v2 changelog vs v1 (from Codex round-1)

- R1-1 [BLOCKER]: `transmit_prepared_batch` visibility was wrong.
  Source `pub(super)` in `tx/transmit.rs` only reaches `tx/`, not
  `afxdp::`. The plan's facade re-export of `pub(super)` from
  `tx/mod.rs` would imply wider visibility, but you can't re-export
  more than the source. v1 also overclaimed "external caller". v2
  fixes: only known caller is at `tx/mod.rs:220` (sibling within
  `tx`); narrow facade to a private `use transmit::transmit_prepared_batch;`
  inside `tx/mod.rs` (no re-export). Source stays `pub(super)`.
- R1-2 [BLOCKER]: import block was materially wrong. Missing
  `FastMap`, `reap_tx_completions`, `tx_frame_capacity`,
  `frame_has_tcp_rst`, `decode_frame_summary`, `XdpDesc`. Had unused
  `CoSPendingTxItem`, `update_binding_debug_state`,
  `cos_queue_push_back`, `ensure_cos_interface_runtime`. v2
  reconciles to actual moved-fn bodies (verified against tx/mod.rs:1654
  / 1672 / 1691 / 1770 etc).
- R1-3 [SCOPE NARROW]: `cos_queue_dscp_rewrite` does NOT belong in
  the transmit cluster. It's not called by any of the submit fns;
  its callers are in `cos/queue_service.rs:657, 801, 962, 1103, 1985,
  2043` — i.e. the CoS-side scheduler. It belongs with the drain /
  CoS layer, not the submit-site primitives. v2 removes it from the
  move list — it stays in `tx/mod.rs` until the drain carve.
- R1-4 [MINOR]: Test section overclaimed direct pins for
  `transmit_batch` and `transmit_prepared_queue`. v2 documents the
  actual test coverage: indirect via `cos_batch_tx_made_progress`
  and `remember_prepared_recycle` direct pin.
- R1-5 [INFO]: confirmed no `#[inline]` on the moved fns today.
  v2 drops the misleading "preserve existing #[inline]" framing —
  there's nothing to preserve. The move itself is intra-crate; LLVM
  cross-module inliner handles the boundary the same way as P2a/P2b.

## Goal

Extract the **transmit + recycle** cluster (XSK TX-ring submit
primitives + per-frame recycling helpers) from `tx/mod.rs` into a
sibling `tx/transmit.rs`. The two giant drain functions and their
backpressure helpers stay for a separate later PR (P2c2 or P2d).
`cos_queue_dscp_rewrite` also stays in `tx/mod.rs` until that
later carve since it's a CoS-side helper.

## Move list (6 fns + 1 enum, ~450 LOC)

| Item | Line (post-P2b) | Source visibility (transmit.rs) | Facade re-export (tx/mod.rs) |
|---|---|---|---|
| `TxError` (enum) | 477 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::TxError;` |
| `recycle_cancelled_prepared_offset` | 1307 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::recycle_cancelled_prepared_offset;` |
| `recycle_prepared_immediately` | 1631 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::recycle_prepared_immediately;` |
| `remember_prepared_recycle` | 1653 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::remember_prepared_recycle;` |
| `transmit_batch` | 1662 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::transmit_batch;` |
| `transmit_prepared_batch` | 1833 | `pub(super)` in transmit.rs (preserved — only caller is tx/mod.rs:220, sibling-internal) | private `use transmit::transmit_prepared_batch;` in tx/mod.rs |
| `transmit_prepared_queue` | 1843 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::transmit_prepared_queue;` |

5 of 7 items have known external (cos/queue_service.rs) callers via
`crate::afxdp::tx::*`. `transmit_prepared_batch` is internal to `tx/`.
`recycle_prepared_immediately` is called from `cos/cross_binding.rs`
**and** `worker.rs:1974` (reached via `afxdp.rs:149`'s `use self::tx::*`
+ `worker.rs:1`'s `use super::*`).

## NOT in P2c scope (deferred)

- `drain_pending_tx` (line 84, ~537 LOC) and `drain_pending_tx_local_owner`
  (line 621, ~685 LOC) — the giant cross-worker dispatch fns.
- `pending_tx_capacity`, `bound_pending_tx_local`,
  `bound_pending_tx_prepared` (lines 33-83) — backpressure helpers.
- `cos_queue_dscp_rewrite` (line 1449) — CoS-side helper, not a
  submit-site primitive (per R1-3 above).
- `COS_GUARANTEE_VISIT_NS`, `COS_GUARANTEE_QUANTUM_*`,
  `COS_SURPLUS_ROUND_QUANTUM_BYTES` constants (lines 841-844).

These all go in a separate later PR — likely a `tx/drain.rs` extract
that tackles the larger ~1.2K LOC mass on its own.

## Module-structure change

```
Before P2c:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~12891 LOC)
    stats.rs     (~187 LOC)
    rings.rs     (~322 LOC)

After P2c:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~12440 LOC)
    stats.rs     (unchanged)
    rings.rs     (unchanged)
    transmit.rs  (~460 LOC)
```

`afxdp.rs:99` already points at `afxdp/tx/mod.rs`. No parent-module
changes.

Steps:
1. Create `userspace-dp/src/afxdp/tx/transmit.rs` with the moved
   fns and enum.
2. In `tx/mod.rs`, add `pub(super) mod transmit;` next to
   `pub(super) mod rings;`.
3. Add the re-export block + private `use transmit::transmit_prepared_batch;`.
4. Existing call sites stay unchanged via re-export.

## Imports for tx/transmit.rs (source-verified, v2)

Reconciled against actual moved-fn bodies:

```rust
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::frame::{
    apply_dscp_rewrite_to_frame, decode_frame_summary, frame_has_tcp_rst,
};
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::{
    FastMap, PreparedTxRecycle, PreparedTxRequest, TxRequest,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{tx_frame_capacity, TX_BATCH_SIZE};
use crate::xsk_ffi::xdp::XdpDesc;

use super::rings::{maybe_wake_tx, reap_tx_completions};
use super::stats::stamp_submits;
```

(Round-2 reviewer: re-verify on impl. The exact list may shrink if
any moved body doesn't reference one of these items; remove unused.)

## tx/mod.rs changes

- Remove the 6 fn definitions + 1 enum + their doc blocks.
- Add `pub(super) mod transmit;` next to `pub(super) mod rings;`.
- Add the `pub(in crate::afxdp) use transmit::{...}` re-export block
  for the 6 cross-afxdp-visible items.
- Add a private `use transmit::transmit_prepared_batch;` to keep the
  tx/mod.rs:220 caller resolving.
- Existing call sites within tx/mod.rs (drain_pending_tx,
  drain_pending_tx_local_owner) keep working through the re-export.

External call sites (cos/queue_service.rs and cos/cross_binding.rs
imports keep working unchanged via the same `crate::afxdp::tx::*`
paths).

## Tests

Pre-existing tests for the moved items (verified pre-impl):
- `remember_prepared_recycle`: direct unit pin in `tx/mod.rs::tests`.
- `TxError`: covered indirectly via `cos_batch_tx_made_progress` test.
- `transmit_batch`, `transmit_prepared_queue`: NO direct unit pins —
  exercised end-to-end by integration smoke + cluster failover.

The re-export from `tx/mod.rs` keeps `super::*` resolution in
`tx/mod.rs::tests` working for the indirect pins.

Round-2 reviewer: enumerate any test pin I missed.

## Risk

**Medium.** ~450 LOC across 6 fns + 1 enum. Single-writer (owner
worker) for the fns that touch BindingWorker. All atomic ops
`Ordering::Relaxed`.

Hot-path: `transmit_batch` and `transmit_prepared_queue` fire per
drain cycle. Cross-module call boundary doesn't change algorithm
shape — same XSK TX-ring `insert(...)` + `commit()` sequence.
Existing #[inline] policy unchanged (no `#[inline]` on the moved
fns today; not adding any in this PR).

Atomic ordering: same Ordering::Relaxed counters. No
publish/observe boundary moves.

## Acceptance

- `cargo build --bins` clean (no new unused-import warnings).
- `cargo test --bins` 865/0/2 (rolling baseline post-#992).
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (5201–5207), failover (RG1 cycled twice,
  ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on cross-reviews.
- Copilot review on the PR addressed.

## After P2c

P2c2 / P2d: drain_pending_tx + drain_pending_tx_local_owner +
bound_pending_tx_* + pending_tx_capacity + cos_queue_dscp_rewrite +
the 4 quantum/guarantee constants → `tx/drain.rs` (~1.4K LOC). Will
need its own multi-round plan + careful review.

P2d-final: collapse `tx/mod.rs` to a thin facade or delete if no
fns remain.
