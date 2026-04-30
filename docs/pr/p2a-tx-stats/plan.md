# P2a: extract afxdp/tx/stats.rs from tx.rs

Plan v2 — 2026-04-30. First PR after #990 (P1: cos/tx_completion.rs)
merged. Stage 2 of the long sequence — opens the `afxdp/tx/` module
directory split (#984 P2a..P2d).

## v2 changelog vs v1 (from Codex round-1)

- R1-MA [BLOCKER]: `afxdp.rs:99` declares `tx` with
  `#[path = "afxdp/tx.rs"]`. A raw `git mv tx.rs tx/mod.rs` will not
  compile until that attribute changes to `#[path = "afxdp/tx/mod.rs"]`
  (matching the project's existing `#[path]` convention). v1's claim
  "`afxdp/mod.rs` does NOT need to change" was false — the actual file
  to update is `afxdp.rs` (which is the parent module file, not
  mod.rs). v2 adds this fix to the move steps.
- R1-MB [MINOR]: the canonical test pins for the three moved fns live
  in `umem.rs::tests` (umem.rs:950+), not `tx.rs::tests`. Tests at
  `umem.rs:965`, `1011`, etc. call
  `crate::afxdp::tx::{stamp_submits, record_tx_completions_with_stamp}`
  via the explicit absolute path, so the `tx/mod.rs` re-export is
  load-bearing for those tests too — not optional.
- R1-MC [MINOR]: visibility-bump rationale corrected. Only
  `stamp_submits` has a `cos/queue_service.rs` caller. Both
  `record_*` fns need `pub(in crate::afxdp)` because `umem::tests`
  reach them through `crate::afxdp::tx::...` (the file boundary
  changes the same as for the cos/* extraction in #956).
- Acceptance: added an explicit compile-check after the path fix so
  the directory rename is verified before the move proceeds. Added a
  note that we trust LLVM cross-module inlining (per Phase 4-8
  lesson) but do not gate this PR on a microbench.

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

Required steps in this PR (in this order):
1. **Update `userspace-dp/src/afxdp.rs:99`**: change
   `#[path = "afxdp/tx.rs"]` to `#[path = "afxdp/tx/mod.rs"]`. This
   MUST land before the rename or the build breaks.
2. `mkdir userspace-dp/src/afxdp/tx/`.
3. `git mv userspace-dp/src/afxdp/tx.rs userspace-dp/src/afxdp/tx/mod.rs`.
4. Verify compile: `cargo check --bins` clean.
5. Create `userspace-dp/src/afxdp/tx/stats.rs` with the moved helpers.
6. In `tx/mod.rs`, add `pub(super) mod stats;` + `pub(in crate::afxdp) use stats::{stamp_submits, record_kick_latency, record_tx_completions_with_stamp};` next to the existing `use super::cos::{...}` block.
7. Existing import paths everywhere else in the crate (`crate::afxdp::tx::stamp_submits`, etc., including `umem::tests` at umem.rs:965, 1011, ...) keep working unchanged because the re-export from `tx/mod.rs` makes them visible at the same path.

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

No new tests required — pure structural refactor.

The canonical pins for the three moved fns live in `umem.rs::tests`
at `umem.rs:950+` (`tx_kick_latency_*`, `tx_kick_retry_*`, sidecar
sentinel pins, and shared-UMEM OOB tests). They reach the moved fns
via the explicit absolute path `crate::afxdp::tx::{stamp_submits,
record_tx_completions_with_stamp, record_kick_latency}` — the
`tx/mod.rs` `pub(in crate::afxdp) use stats::...` re-export keeps
that path resolving after the move. **The re-export is load-bearing,
not optional.**

`tx/mod.rs::tests` (the `mod tests` block at the bottom of the
ex-tx.rs file) reaches symbols via `super::*`, which after the
re-export will pull moved-fn names into the test scope.

If on impl any test fails to resolve a symbol, add a `#[cfg(test)]
use super::stats::*;` inside the test mod or bump cos/mod.rs-style
re-exports for it. Round-2+ reviewers verify against the actual
build.

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

- After the path-attribute fix in step 1, `cargo check --bins` MUST
  pass before the rename proceeds.
- After the move + re-export (steps 2-6), `cargo build --bins` clean
  (no new unused-import warnings).
- `cargo test --bins` 865/0/2 (current rolling baseline post-#990) —
  notably exercises `umem.rs::tests` against the re-exported moved
  fns.
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (5201–5207), failover (RG1 cycled twice,
  ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on the cross-reviews.
- Copilot review on the PR addressed.

Cross-module inlining: this PR trusts LLVM's cross-module inliner
(per the Phase 4-8 lesson — `pub(in crate::afxdp) #[inline]` is
sufficient for inlining across the new boundary, not contradicted
by any prior data). We do NOT gate on a microbench in this PR. If
post-merge profiling shows a per-batch regression at the
`stamp_submits` / `record_tx_completions_with_stamp` call sites,
the fix is to add `#[inline(always)]` (escalation) rather than
back out the move.

## After P2a

P2b: `afxdp/tx/rings.rs` — XSK ring management (~3K LOC). Largest
single carve in the sequence; will need its own multi-round plan.

P2c: `afxdp/tx/dispatch.rs` — cross-worker dispatch (~2K LOC).

P2d: collapse `afxdp/tx/mod.rs` into a thin facade (or delete it
if no fns remain).
