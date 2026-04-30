# P2b: extract afxdp/tx/rings.rs from tx/mod.rs

Plan v1 — 2026-04-30. Stage 2 step 2 of the long sequence after #991
(P2a: tx/stats.rs) merged at master `290b4502`.

## Goal

Extract the XSK kernel-ring helpers (TX completion drain, fill ring
submit, RX/TX wake, TX queue bounds) from `tx/mod.rs` into a sibling
`tx/rings.rs`. This is the second carve of the `tx/` module after
P2a's `stats.rs`. Drains and transmits — the largest mass — stay for
P2c.

## Move list (8 fns, ~280 LOC)

| Item | Line | Visibility after |
|---|---|---|
| `reap_tx_completions` | 14 | `pub(in crate::afxdp)` (preserved — already cos/queue_service caller) |
| `drain_pending_fill` | 65 | `pub(super)` (preserved — worker-binding internal) |
| `maybe_wake_rx` | 126 | `pub(super)` (preserved) |
| `pending_tx_capacity` | 176 | `pub(super)` (preserved — worker.rs:332 caller) |
| `bound_pending_tx_local` | 182 | `pub(super)` (preserved) |
| `bound_pending_tx_prepared` | 203 | `pub(super)` (preserved) |
| `recycle_completed_tx_offset` | 1784 | file-private (sole caller `reap_tx_completions` at line 53) |
| `maybe_wake_tx` | 2234 | `pub(in crate::afxdp)` (preserved — cos/queue_service caller) |

Plus the doc-comment blocks above each fn.

## Why these eight together

All eight directly drive the XSK kernel rings (TX completion ring,
fill ring, TX submit ring) or compute capacities for those rings. None
touches CoS scheduling state — they read/write `BindingWorker`
ring-relevant fields (`outstanding_tx`, `pending_fill_frames`,
`pending_tx_local`, `pending_tx_prepared`, `device.fill/complete`) and
recycle frames back to `free_tx_frames` / `pending_fill_frames`.

Cohesion is high (they ARE the kernel-ring boundary). They're cleanly
separable from drain/transmit (which add CoS-scheduler logic on top of
these primitives).

## #[inline] adds — preserve existing

Source-verify on impl: `reap_tx_completions` does NOT have `#[inline]`
today (per-batch but not per-byte). Other items: spot-check before
adding. Plan is "preserve existing, do not bulk-add" — same posture
as P2a.

## Module-structure change

```
Before P2b:
  userspace-dp/src/afxdp/tx/
    mod.rs       (13157 LOC)
    stats.rs     (~180 LOC, from P2a)

After P2b:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~12880 LOC)
    stats.rs     (unchanged)
    rings.rs     (~310 LOC)
```

`afxdp.rs:99` already points at `afxdp/tx/mod.rs` after P2a. No
parent-module changes.

Steps:
1. Create `userspace-dp/src/afxdp/tx/rings.rs` with the moved helpers.
2. In `tx/mod.rs`, add `pub(super) mod rings;` next to
   `pub(super) mod stats;`.
3. Add `pub(in crate::afxdp) use rings::{reap_tx_completions, maybe_wake_tx};`
   for the externally-visible items, and
   `pub(super) use rings::{drain_pending_fill, maybe_wake_rx,
   pending_tx_capacity, bound_pending_tx_local,
   bound_pending_tx_prepared};` for the worker/sibling-visible items.
4. Existing call sites stay unchanged via re-export.

## Imports for tx/rings.rs (source-verified upper bound)

Reconciled against the moved-fn bodies (read in v2+):

```rust
use std::sync::atomic::Ordering;

use crate::afxdp::types::{
    BindingDebugState, PreparedTxRecycle, PreparedTxRequest,
    OwnerProfileOwnerWrites,
};
use crate::afxdp::umem::TX_SIDECAR_UNSTAMPED;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::neighbor::monotonic_nanos;

use super::stats::record_kick_latency;
use super::stats::record_tx_completions_with_stamp;
```

(Round-1 reviewer: verify against actual moved-fn bodies. Likely
needs additions for `FILL_BATCH_SIZE`, `FILL_WAKE_SAFETY_INTERVAL_NS`,
binding-internal types touched by drain_pending_fill / maybe_wake_*.)

## Constants needed

`FILL_BATCH_SIZE` and `FILL_WAKE_SAFETY_INTERVAL_NS` — verify location
in v2 (likely in tx/mod.rs and need pub(super) bump or move with
rings.rs).

## tx/mod.rs changes

- Remove the 8 fn definitions + their doc blocks.
- Add `pub(super) mod rings;` next to `pub(super) mod stats;`.
- Add the two re-export blocks (pub(in crate::afxdp) for external,
  pub(super) for sibling/worker).
- Existing internal call sites within tx/mod.rs (drain_pending_tx,
  transmit_*, etc. that call reap_tx_completions / maybe_wake_tx /
  drain_pending_fill / etc.) keep working through the re-export.

## Tests

No new tests required. The pre-existing tests for these fns either:
- Live in tx/mod.rs's `mod tests` block (reach via `super::*`,
  which finds the re-exported names through the re-export chain), OR
- Live in umem.rs::tests / worker.rs::tests (reach via
  `crate::afxdp::tx::...` absolute path — re-export keeps that
  resolving).

Round-1 reviewer: enumerate exact test pin locations.

## Risk

**Low-medium.** ~280 LOC across 8 pure functions. Single-writer
(owner worker). All atomic ops `Ordering::Relaxed`. The move does not
change algorithm shape — same XSK-syscall sequence (`fill.commit()`,
`device.complete()`, `bpf_tx_kick` wrapper).

Hot-path: `reap_tx_completions` and `maybe_wake_tx` fire per drain
cycle. Cross-module `#[inline]` retention works the same way as P1
+ P2a: `pub(in crate::afxdp)` + the existing `#[inline]` (where
present) propagates MIR across the new boundary, LLVM cross-module
inliner handles the rest under default release profile.

## Acceptance

- `cargo build --bins` clean (no new unused-import warnings).
- `cargo test --bins` 865/0/2 (rolling baseline post-#991).
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (5201–5207), failover (RG1 cycled twice,
  ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on cross-reviews.
- Copilot review on the PR addressed.

## After P2b

P2c: drain_pending_tx + drain_pending_tx_local_owner + transmit_batch
+ transmit_prepared_batch + transmit_prepared_queue (+ recycle_*)
into `tx/dispatch.rs` (or splits if too large for one PR). Largest
single carve in the sequence (~1.8K LOC).

P2d: collapse `tx/mod.rs` to a thin facade or delete if no fns
remain.
