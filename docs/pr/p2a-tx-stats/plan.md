# P2a: extract afxdp/tx/stats.rs from tx.rs

Plan v1 — 2026-04-30. First PR after #990 (P1: cos/tx_completion.rs)
merged. Stage 2 of the long sequence — opens the `afxdp/tx/` module
directory split (#984 P2a..P2d).

## Goal

1. Convert `userspace-dp/src/afxdp/tx.rs` into a directory module
   `userspace-dp/src/afxdp/tx/mod.rs` (prerequisite for P2b/P2c/P2d).
2. Extract the three TX latency-histogram / sidecar helpers into
   `userspace-dp/src/afxdp/tx/stats.rs`.

This is the smallest possible first carve of `tx/`. The three helpers
are pure functions with no closures over `BindingWorker` / coordinator
state; they only touch `OwnerProfileOwnerWrites` atomic counters that
already live in `umem.rs`. Cohesion is high (they ARE the stats path),
risk is low.

## Move list (3 fns, ~110 LOC)

| Item | Line | Visibility |
|---|---|---|
| `stamp_submits<I>` | tx.rs:36-79 | `pub(in crate::afxdp)` (preserved) |
| `record_kick_latency` | tx.rs:106-113 | `pub(in crate::afxdp)` (bumped from `pub(super)`) |
| `record_tx_completions_with_stamp` | tx.rs:115-157 | `pub(in crate::afxdp)` (bumped from `pub(super)`) |

Plus the doc-comment blocks immediately above each fn (~30 lines total).

## Why these three together

- `stamp_submits` writes the per-frame submit timestamp into the
  per-binding sidecar `&mut [u64]`.
- `record_tx_completions_with_stamp` reads the sidecar at completion
  time, computes per-batch deltas, folds into bucket-local counters,
  and bumps `OwnerProfileOwnerWrites.tx_submit_latency_*`.
- `record_kick_latency` is the kick-side analogue, bumping
  `tx_kick_latency_*`.

All three are single-writer (owner worker), use `Ordering::Relaxed`
for counter updates, and are inside `#[inline]`. They share the
sidecar/sentinel discipline (`TX_SIDECAR_UNSTAMPED`,
`UMEM_FRAME_SHIFT`, `bucket_index_for_ns`) and constitute one
cohesive module.

## #[inline] preservation

All three already carry `#[inline]`. Move preserves verbatim — no
silent downgrades. Cross-module inlining works the same way as
P1 (`pub(in crate::afxdp) #[inline]` enables LLVM to inline across
the new module boundary; the same Phase 4-8 lesson applies).

## Module-structure change

The bigger structural shift in this PR:

```
Before:
  userspace-dp/src/afxdp/
    tx.rs                  (13302 LOC)

After:
  userspace-dp/src/afxdp/
    tx/
      mod.rs               (13192 LOC — what was tx.rs minus the moved 110)
      stats.rs             (~140 LOC — 110 moved + ~30 imports/header)
```

Required steps in this PR:
1. `mkdir userspace-dp/src/afxdp/tx/`.
2. `git mv userspace-dp/src/afxdp/tx.rs userspace-dp/src/afxdp/tx/mod.rs`.
3. Create `userspace-dp/src/afxdp/tx/stats.rs` with the moved helpers.
4. In `tx/mod.rs`, add `pub(super) mod stats;` + `pub(in crate::afxdp) use stats::{stamp_submits, record_kick_latency, record_tx_completions_with_stamp};`.
5. Existing import paths everywhere else in the crate (`crate::afxdp::tx::stamp_submits`, etc.) keep working unchanged because the re-export from `tx/mod.rs` makes them visible at the same path.

`afxdp/mod.rs` (or wherever `tx` is declared via `pub(super) mod tx;`)
does NOT need to change — directory modules and file modules have the
same `mod tx;` declaration.

## Imports for tx/stats.rs (source-verified)

Reconciled against the moved-fn bodies (tx.rs:36-79, 106-113, 115-157):

```rust
use std::sync::atomic::Ordering;

use crate::afxdp::umem::{
    bucket_index_for_ns, OwnerProfileOwnerWrites,
    TX_SIDECAR_UNSTAMPED, TX_SUBMIT_LAT_BUCKETS, UMEM_FRAME_SHIFT,
};
```

NOT imported (verified absent from moved bodies):
- `BindingWorker` — these fns take owner-profile slices directly.
- Anything from `cos/*` — stats path is independent of CoS scheduling.
- `monotonic_nanos` — caller-supplied timestamp, not generated here.

## tx/mod.rs changes (apart from the move + re-export)

- Remove the 3 fn definitions + their doc blocks (lines 30-157
  approximate range, but with surrounding context preserved).
- Add `pub(super) mod stats;` at the top alongside the other
  `mod` declarations.
- Add `pub(in crate::afxdp) use stats::{stamp_submits,
  record_kick_latency, record_tx_completions_with_stamp};` at the
  top alongside the existing `use super::cos::{...}` block.

Existing call sites inside tx (`reap_tx_completions` at tx.rs:159
calls `record_tx_completions_with_stamp` at tx.rs:190; `maybe_wake_tx`
calls `record_kick_latency`; `transmit_*` paths call `stamp_submits`)
keep working through the re-export — same identifier, same path
relative to the file.

External call sites (cos/queue_service.rs:65 imports `stamp_submits`
from `crate::afxdp::tx::`) keep working unchanged — the re-export
preserves the public path.

## Files touched

- **NEW** `userspace-dp/src/afxdp/tx/stats.rs`: ~140 LOC.
- **RENAME** `userspace-dp/src/afxdp/tx.rs` → `userspace-dp/src/afxdp/tx/mod.rs`.
- **MOD** `userspace-dp/src/afxdp/tx/mod.rs`: −110 LOC moved fns; +5
  LOC for the `mod stats;` + re-export.

No other files change. `afxdp/mod.rs` does not change. No call sites
update (re-export preserves identifiers).

## Tests

No new tests required — pure structural refactor. The existing tests
for the three moved fns live at `tx.rs:1449+` (`tx_kick_latency_*`,
`tx_kick_retry_*` pins) and stay in `tx/mod.rs`'s `mod tests` block;
they reach the moved fns via `super::*` (which now finds them via
the cos-style re-export chain at the top of `mod.rs`).

If the test block needs explicit access to symbols that don't
re-export through `tx/mod.rs`, add a `#[cfg(test)] use super::stats::*;`
inside the test mod. Round-1 reviewers verify whether this is needed.

## Risk

**Low.** ~110 LOC moved, all pure functions, no closures, all
`Ordering::Relaxed`, single-writer.

Hot-path concerns:
- `stamp_submits` fires once per submit batch (~hundreds of calls per
  drain cycle). Cross-module `#[inline]` preserves the per-call cost
  (a single bounded loop with `slot.get_mut`).
- `record_tx_completions_with_stamp` fires once per reap batch (also
  hundreds of calls per drain cycle). Same `#[inline]` story.
- `record_kick_latency` fires once per `sendto` kick (rarer than
  per-packet — `maybe_wake_tx` gates it).

Atomic ordering: all three use `Ordering::Relaxed` directly. No
publish/observe boundary moves. The sidecar buffer (`&mut [u64]`)
is single-writer (owner worker), so plain non-atomic writes via
`*slot = ts_submit` / `*slot = TX_SIDECAR_UNSTAMPED` remain sound
(no thread-safety guarantees changed by the move).

## Acceptance

- `cargo build --bins` clean (no new unused-import warnings).
- `cargo test --bins` 865/0/2 (current rolling baseline post-#990).
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (5201–5207), failover (RG1 cycled twice,
  ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on the cross-reviews.
- Copilot review on the PR addressed.

## After P2a

P2b: `afxdp/tx/rings.rs` — XSK ring management (~3K LOC). Largest
single carve in the sequence; will need its own multi-round plan.

P2c: `afxdp/tx/dispatch.rs` — cross-worker dispatch (~2K LOC).

P2d: collapse `afxdp/tx/mod.rs` into a thin facade (or delete it
if no fns remain).
