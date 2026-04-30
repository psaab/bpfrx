# P2b: extract afxdp/tx/rings.rs from tx/mod.rs

Plan v3 — 2026-04-30. Stage 2 step 2 of the long sequence after #991
(P2a: tx/stats.rs) merged at master `290b4502`.

## v3 changelog vs v2 (from Codex round-2)

- R2-1 [BLOCKER]: import block was still source-inaccurate. v3
  fixes:
  - Add `std::collections::VecDeque` (apply_prepared_recycle takes
    `&mut VecDeque<u64>`).
  - Remove `PreparedTxRequest` (no moved body uses it directly —
    `recycle_prepared_immediately` is NOT a moving-body callee).
  - Remove `PENDING_TX_LIMIT_MULTIPLIER` and `TX_BATCH_SIZE` (these
    belong to the deferred `pending_tx_capacity` body, not the
    rings cluster).
  - Remove `recycle_prepared_immediately` import (the moved
    `recycle_completed_tx_offset` body calls
    `apply_prepared_recycle` only — no path goes through
    `recycle_prepared_immediately`).
- R2-2 [MINOR]: `apply_prepared_recycle` was overexposed as
  `pub(in crate::afxdp)` — that makes it reachable as
  `crate::afxdp::tx::rings::apply_prepared_recycle` everywhere in
  afxdp, even in non-test builds, when its only legitimate non-test
  caller is `recycle_completed_tx_offset` (file-private,
  co-located in rings.rs). v3 tightens to `pub(super)` in rings.rs
  (visible only to `tx/`) plus a `#[cfg(test)] use rings::apply_prepared_recycle;`
  inside `tx/mod.rs` so the existing test at `tx/mod.rs:3329` keeps
  working — same pattern as P1's cfg-test re-exports.

## v2 changelog vs v1 (from Codex round-1)

- R1-1 [BLOCKER]: `pub(super)` after the move means visible only
  within `tx/`, not within `afxdp::`. Sibling callers in
  `frame_tx.rs:62/40/54/...` and `afxdp.rs:450/483/661/507` need
  `afxdp::`-wide visibility. v2 makes the source items
  `pub(in crate::afxdp)` and re-exports from `tx/mod.rs` with a
  facade visibility (`pub(super)` from tx/mod.rs perspective ==
  `pub(in afxdp)` reach) — the Rust pattern from #983 P1.
- R1-2 [BLOCKER]: `apply_prepared_recycle` (tx/mod.rs:1772) was
  missed in v1's move list. It is the sole helper called by
  `recycle_completed_tx_offset` (the only caller is
  `recycle_completed_tx_offset` at tx/mod.rs:1790), so leaving it
  in tx/mod.rs creates a `rings -> tx/mod` back-edge. v2 adds it
  to the move set. Its direct test at tx/mod.rs:3329 keeps working
  by bumping its visibility from file-private to
  `pub(in crate::afxdp)` (accessible from `tx::tests` via the
  cos-style re-export chain, same pattern as P2a's
  `restore_cos_local_items_inner` test access).
- R1-3 [BLOCKER]: import list was source-inaccurate. v2 import
  block reconciled against actual moved-fn bodies (verified during
  impl).
- R1-4 [MINOR]: TX_BATCH_SIZE / FILL_BATCH_SIZE / FILL_WAKE_*  /
  RX_WAKE_* / TX_WAKE_* / PENDING_TX_LIMIT_* live in
  `afxdp.rs:196-242` (parent module), NOT in `tx/mod.rs`. No move
  or visibility bump needed — descendants already see them via the
  `super::` chain. v1 mischaracterized this.
- R1-5 [SCOPE NARROW]: `pending_tx_capacity`,
  `bound_pending_tx_local`, `bound_pending_tx_prepared` deferred to
  P2c with the prepared-dispatch helpers they're paired with. Their
  cohesion is queue-bound / backpressure, not XSK-ring discipline,
  and `bound_pending_tx_prepared` directly depends on the deferred
  prepared-recycle path. v2 narrows P2b to the ring-discipline
  cluster: 4 pub fns + 2 file-private helpers (~270 LOC).

## Goal

Extract the XSK kernel-ring discipline cluster (TX completion drain,
fill ring submit, RX/TX kernel wake) from `tx/mod.rs` into a sibling
`tx/rings.rs`. Drains, transmits, queue-bound helpers, and prepared
recycling all stay for P2c (the largest single carve in the
sequence).

## Move list (4 pub fns + 2 file-private helpers, ~270 LOC)

| Item | Line | Source visibility (in rings.rs) | Facade re-export visibility (from tx/mod.rs) |
|---|---|---|---|
| `reap_tx_completions` | 14 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use rings::reap_tx_completions;` |
| `drain_pending_fill` | 65 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use rings::drain_pending_fill;` |
| `maybe_wake_rx` | 126 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use rings::maybe_wake_rx;` |
| `maybe_wake_tx` | 2234 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use rings::maybe_wake_tx;` |
| `recycle_completed_tx_offset` | 1784 | file-private | not re-exported (sole caller `reap_tx_completions` moves with it) |
| `apply_prepared_recycle` | 1772 | `pub(super)` in rings.rs (visible to `tx/` only) | `#[cfg(test)] use rings::apply_prepared_recycle;` in `tx/mod.rs` (test-only re-export so the unit pin at `tx/mod.rs:3329` keeps working through `mod tests { use super::*; }`) |

## Why this exact set

- `reap_tx_completions` drives the XSK completion ring via
  `device.complete()` and feeds completed offsets to
  `record_tx_completions_with_stamp` (in stats.rs).
  `recycle_completed_tx_offset` + `apply_prepared_recycle` are the
  per-offset cleanup helpers.
- `drain_pending_fill` drives the XSK fill ring via
  `device.fill().insert(...)` and `commit()`.
- `maybe_wake_rx` and `maybe_wake_tx` are the kernel-wakeup gates
  that issue the `sendto` syscall after fill / TX submit; both check
  `needs_wakeup` and respect the per-ring rate-limit constants
  (`RX_WAKE_*`, `TX_WAKE_*`).

These six items form a self-contained kernel-ring discipline unit.
After the move, `rings.rs` has zero imports from sibling tx submodules
except `super::stats` (for `record_kick_latency` /
`record_tx_completions_with_stamp`).

## Module-structure change

```
Before P2b:
  userspace-dp/src/afxdp/tx/
    mod.rs       (13157 LOC)
    stats.rs     (~180 LOC, from P2a)

After P2b:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~12890 LOC)
    stats.rs     (unchanged)
    rings.rs     (~290 LOC)
```

`afxdp.rs:99` already points at `afxdp/tx/mod.rs` after P2a. No
parent-module changes.

Steps:
1. Create `userspace-dp/src/afxdp/tx/rings.rs` with the moved helpers.
2. In `tx/mod.rs`, add `pub(super) mod rings;` next to
   `pub(super) mod stats;`.
3. Add the re-export blocks (mixed visibility per the table).
4. Existing call sites stay unchanged via re-export.

## Imports for tx/rings.rs (source-verified upper bound, v2)

Reconciled against actual moved-fn bodies (tx/mod.rs:14-63 / 65-124 /
126-174 / 1772-1798 / 2234-2330):

```rust
use std::collections::VecDeque;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;

use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::PreparedTxRecycle;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{
    FILL_BATCH_SIZE, FILL_WAKE_SAFETY_INTERVAL_NS,
    RX_WAKE_IDLE_POLLS, RX_WAKE_MIN_INTERVAL_NS,
    TX_WAKE_MIN_INTERVAL_NS, XskBindMode,
};

use super::stats::{record_kick_latency, record_tx_completions_with_stamp};

// Sibling tx/* helpers still in tx/mod.rs (deferred to P2c):
use super::update_binding_debug_state;
```

(Round-2 reviewer: re-verify on impl. The exact list may shrink if
`recycle_completed_tx_offset` doesn't actually call
`recycle_prepared_immediately` directly — it might only go through
`apply_prepared_recycle`. Verify on the diff.)

NOT imported (verified absent from moved bodies):
- `OwnerProfileOwnerWrites` (not directly named — passed to stats fns
  through `&binding.live.owner_profile_owner`).
- `BindingDebugState` (touched only via `update_binding_debug_state`
  helper).
- `TX_SIDECAR_UNSTAMPED` (used inside stats.rs, not directly here).

## Constants — reachable as-is

`TX_BATCH_SIZE`, `FILL_BATCH_SIZE`, `FILL_WAKE_SAFETY_INTERVAL_NS`,
`RX_WAKE_IDLE_POLLS`, `RX_WAKE_MIN_INTERVAL_NS`,
`TX_WAKE_MIN_INTERVAL_NS`, `PENDING_TX_LIMIT_MULTIPLIER` all live in
`afxdp.rs:196-242` as module-private consts. Same pattern as
`UMEM_FRAME_SHIFT` from P2a — descendant modules read them via
`crate::afxdp::CONST_NAME` (no `pub` modifier required because of
Rust's "private to defining module's descendants" visibility default).

## tx/mod.rs changes

- Remove the 6 fn definitions + their doc blocks.
- Add `pub(super) mod rings;` next to `pub(super) mod stats;`.
- Add the mixed-visibility re-export block (see move table).
- Existing internal call sites within tx/mod.rs (drain_pending_tx,
  transmit_*, etc. that call reap_tx_completions / maybe_wake_tx /
  drain_pending_fill / etc.) keep working through the re-export.

External call sites (frame_tx.rs:62 calls drain_pending_fill via
`super::tx::drain_pending_fill`; afxdp.rs:507 calls maybe_wake_rx via
`tx::maybe_wake_rx`; cos/queue_service.rs imports `reap_tx_completions`
and `maybe_wake_tx` via `crate::afxdp::tx::`) keep resolving through
the re-export — same pattern as P2a's stamp_submits.

## Tests

Pre-existing tests that touch the moved fns:
- `tx/mod.rs:3329-3340` exercises `apply_prepared_recycle` directly.
  Stays in `tx/mod.rs::tests`; reaches the moved fn through the
  `pub(in crate::afxdp) use rings::apply_prepared_recycle;` re-export
  via the `mod tests { use super::*; }` resolution chain.
- The 4 pub fns (`reap_tx_completions`, `drain_pending_fill`,
  `maybe_wake_rx`, `maybe_wake_tx`) have no direct unit pins but are
  exercised end-to-end by integration smoke + cluster failover.

Round-2 reviewer: enumerate any test pin I missed.

## Risk

**Medium.** ~270 LOC across 6 functions. Single-writer (owner worker).
All atomic ops `Ordering::Relaxed`. The move does not change algorithm
shape — same XSK-syscall sequence (`fill.commit()`, `device.complete()`,
`sendto` for kernel wake).

Hot-path: `reap_tx_completions` and `maybe_wake_tx` fire per drain
cycle. Cross-module `#[inline]` retention works the same way as P1
+ P2a: `pub(in crate::afxdp)` + the existing `#[inline]` (where
present) propagates MIR across the new boundary.

Source-verify before commit: `reap_tx_completions` does NOT have
`#[inline]` today (per-batch but not per-byte). `maybe_wake_tx` does
NOT have `#[inline]` either (called once per drain cycle via cos
scheduler, same per-batch profile). Preserve as-is — adding
`#[inline]` here is premature optimization; if measured regression,
escalate.

## Acceptance

- `cargo build --bins` clean (no new unused-import warnings).
- `cargo test --bins` 865/0/2 (rolling baseline post-#991).
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (5201–5207), failover (RG1 cycled twice,
  ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on cross-reviews.
- Copilot review on the PR addressed.

## Files touched

- **MOD** `userspace-dp/src/afxdp/tx/mod.rs`: −270 LOC moved fns;
  +10 LOC for `mod rings;` + re-export block.
- **NEW** `userspace-dp/src/afxdp/tx/rings.rs`: ~290 LOC.

No other files change. `afxdp.rs` does not change. No call sites
update (re-export preserves identifiers — every existing
`crate::afxdp::tx::reap_tx_completions` etc. import resolves through
the new `pub(in crate::afxdp) use rings::...` in `tx/mod.rs`; sibling
calls via `super::tx::...` resolve through the `pub(super) use`
re-exports).

## After P2b

P2c: drain_pending_tx + drain_pending_tx_local_owner + transmit_batch
+ transmit_prepared_batch + transmit_prepared_queue + recycle_* +
bound_pending_tx_* + pending_tx_capacity + TxError +
COS_GUARANTEE_*/COS_SURPLUS_* constants → `tx/dispatch.rs` (or splits
if too large for one PR). Largest single carve in the sequence
(~1.8K LOC).

P2d: collapse `tx/mod.rs` to a thin facade or delete if no fns
remain.
