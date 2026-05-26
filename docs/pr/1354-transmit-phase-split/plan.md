# #1354 — `tx/transmit.rs` 230-LOC `transmit_prepared_queue` phase split

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`userspace-dp/src/afxdp/tx/transmit.rs::transmit_prepared_queue()` is a
230-LOC function on the hot TX path (one call per worker tick — not
per packet). `docs/engineering-style.md` flags >100 LOC as a refactor
cue; this is a Tier-1 modularity hit at 2.3× the cap.

The issue proposes splitting the body into four phases:

1. `stage_batch_into_scratch` — pop up to `TX_BATCH_SIZE` items into
   `binding.scratch.scratch_prepared_tx`, dropping any whose `req.len`
   exceeds the UMEM frame capacity (orphan-recycle on drop).
2. (Pre-write) `apply_dscp_rewrites_to_staged` — iterate the staged
   batch and apply per-frame DSCP rewrite mutations to the UMEM frame
   slice. (The issue's sketch folds this into `write_descriptors`; in
   practice the existing code does this BEFORE descriptor write, and
   it has its own failure path that orphan-recycles the entire staged
   batch. Splitting it out as a phase preserves the existing ordering
   and the existing drop-path semantics.)
3. (Pre-write) `verify_umem_slices` — re-validate every staged frame's
   UMEM slice via the shared (read-only) accessor before reservation.
   Same orphan-recycle drop semantics as phase 2.
4. (Optional, behind `cfg!(feature = "debug-log")`)
   `log_rst_frames` — walk staged scratch and emit RST_DETECT diagnostics.
5. `reserve_and_write_descriptors` — call `xsk.tx.transmit(N)`, populate
   `XdpDesc` from staged scratch, commit, drop writer, stamp submits
   post-commit (`#812` Codex round-1 HIGH #1 invariant).
6. `finalise_kernel_kick_and_restore` — `inserted == 0` retry path
   (push everything back to `pending` front), success path (count
   sent bytes/packets, register prepared-recycle for kept entries,
   push the un-inserted tail back to `pending` front in the right
   order), then `maybe_wake_tx`.

The issue's sketch lists five helpers; the actual code has six
phases when you count the DSCP rewrite + slice re-validation as
distinct from descriptor write. We split into six to preserve
behavioural ordering 1:1 and avoid any silent merge of disjoint
failure paths.

## Honest scope/value framing

This is **pure code motion + readability**. The function is called
once per worker tick (not per packet), so even a literal function
call per phase would be invisible. The win is:

- File LOC: `tx/transmit.rs` drops below the engineering-style cue.
- Phase isolation: each phase's failure mode and drop accounting is
  separately reviewable. `transmit_prepared_queue` currently
  duplicates the orphan-recycle + tx-error-counter pattern three
  times (lines 290-316, 322-355, 358-391) with subtle differences in
  the "+= 1 vs += len-1" comments — refactoring the duplicated drop
  logic into named helpers makes those differences explicit (or
  exposes that they should be the same).
- Per-phase unit tests become possible (the issue calls this out).

If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict. The defence is "the
codebase already pays this kind of phase-split refactor cost
routinely (see #1188, #1189, #1199, #1200, #1217, #1220, #964, #959
Phases 1-11) and the gain is mechanical reviewability + modularity
discipline."

## What's already shipped / partially batched

- `tx/transmit.rs` is in a `tx/` module directory (not a flat file),
  so the new layout `transmit/{mod,stage,rewrite,verify,write,finalise}.rs`
  is a natural extension of the existing pattern (already done for
  `tx/dispatch.rs` → `tx/tcp_segmentation.rs` in #1166, and the
  decomposition pattern of #1189 supervisor split).
- `tx/transmit_tests.rs` already exists (118 LOC) and is loaded via
  `#[path = "transmit_tests.rs"] mod tests;`. The new layout should
  preserve that file's path so the existing tests continue to run
  against the helper names they currently import via `use super::*;`.
  (Concretely: keep `transmit_tests.rs` at its current path and have
  `transmit/mod.rs` continue the `#[cfg(test)] #[path = "../transmit_tests.rs"] mod tests;`
  pattern OR move the tests next to the new module.)

## Concrete design

### Layout

```
userspace-dp/src/afxdp/tx/
├── mod.rs                  (unchanged exports; switches `mod transmit;` to a directory module)
├── transmit/
│   ├── mod.rs              (re-exports the public-to-afxdp items; hosts orchestrator + helpers shared
│   │                       across phases: TxError, recycle_*_with_shared, remember_prepared_recycle,
│   │                       transmit_batch (unchanged for this PR — out of scope), transmit_prepared_batch,
│   │                       transmit_prepared_queue (now an orchestrator that calls into stage/rewrite/
│   │                       verify/write/finalise))
│   ├── stage.rs            (#[inline] stage_batch_into_scratch -> Result<(), TxError>)
│   ├── rewrite.rs          (#[inline] apply_dscp_rewrites_to_staged -> Result<(), TxError>)
│   ├── verify.rs           (#[inline] verify_umem_slices_for_staged -> Result<(), TxError>)
│   ├── write.rs            (#[inline] reserve_and_write_descriptors -> u32  // returns `inserted`)
│   └── finalise.rs         (#[inline] finalise_kernel_kick_and_restore -> (u64, u64))
└── transmit_tests.rs       (untouched path — still loaded by transmit/mod.rs)
```

The five new files keep the public symbol set in `transmit/mod.rs`
unchanged. Module siblings (`tx/cos_classify.rs`, `tx/drain.rs`,
`tx/dispatch.rs`, etc.) and external callers
(`afxdp/cos/queue_service/mod.rs`, `afxdp/mirror.rs`,
`afxdp/tx/drain.rs`) import `transmit_batch`,
`transmit_prepared_queue`, etc. through the existing
`pub(in crate::afxdp) use transmit::{...}` in `tx/mod.rs`. That
re-export keeps the import paths stable.

### Orchestrator signature (unchanged)

```rust
pub(in crate::afxdp) fn transmit_prepared_queue(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError>
```

The orchestrator body becomes ~20 LOC:

```rust
pub(in crate::afxdp) fn transmit_prepared_queue(
    binding, pending, now_ns, shared_recycles,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() { return Ok((0, 0)); }
    stage::stage_batch_into_scratch(binding, pending, shared_recycles)?;
    if binding.scratch.scratch_prepared_tx.is_empty() {
        return Ok((0, 0));
    }
    rewrite::apply_dscp_rewrites_to_staged(binding, shared_recycles)?;
    verify::verify_umem_slices_for_staged(binding, shared_recycles)?;
    if cfg!(feature = "debug-log") {
        log_rst_frames_prepared(binding);
    }
    let inserted = write::reserve_and_write_descriptors(binding);
    let (sent_bytes, sent_pkts) = finalise::finalise_prepared(
        binding, pending, now_ns, inserted,
    )?;
    Ok((sent_bytes, sent_pkts))
}
```

### Phase signatures (all `#[inline]`)

```rust
// stage.rs
#[inline]
pub(super) fn stage_batch_into_scratch(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(), TxError>;

// rewrite.rs
#[inline]
pub(super) fn apply_dscp_rewrites_to_staged(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(), TxError>;

// verify.rs
#[inline]
pub(super) fn verify_umem_slices_for_staged(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(), TxError>;

// write.rs
#[inline]
pub(super) fn reserve_and_write_descriptors(
    binding: &mut BindingWorker,
) -> u32;        // `inserted` count

// finalise.rs
#[inline]
pub(super) fn finalise_prepared(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
    inserted: u32,
) -> Result<(u64, u64), TxError>;
```

The orphan-recycle drop path is currently inline three times; we
extract a single shared private helper:

```rust
// transmit/mod.rs (private to transmit/)
#[inline]
fn drain_and_orphan_recycle_staged(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> usize;     // returns orphan count for counter math
```

This is the part where reviewers should push hardest — the three
existing call sites have subtly different "+= 1 vs += len-1"
accounting because two of them include `req` (the offender) in
`orphaned` while one does not. The phase-split exposes this; we
need to either (a) preserve the asymmetric accounting via two
helpers, or (b) prove the asymmetry is wrong and fix it. **Default
plan: preserve asymmetric accounting via two helpers.** Fixing the
asymmetry is a behavior change and out of scope for this code-motion
PR.

## Public API preservation

External callers (from grep above):

- `afxdp/mirror.rs:1312` — `transmit_batch(...)` (NOT touched this PR)
- `afxdp/cos/queue_service/mod.rs:1235` — `transmit_batch(...)`
- `afxdp/cos/queue_service/mod.rs:1333` — `transmit_prepared_queue(...)`
- `afxdp/tx/drain.rs:209` — `transmit_prepared_batch(...)`
- `afxdp/tx/drain.rs:274` — `transmit_batch(...)`

The `tx/mod.rs` re-export list stays byte-identical:

```rust
pub(in crate::afxdp) use transmit::{
    recycle_prepared_immediately_with_shared, remember_prepared_recycle, transmit_batch,
    transmit_prepared_queue,
};
use transmit::transmit_prepared_batch;
```

All four are still defined in (now) `transmit/mod.rs` and re-exported
unchanged. Call sites and import paths require zero edits.

## Hidden invariants the change must preserve

1. **Phase ordering** is the XSK ring contract: stage → DSCP rewrite
   (mutates UMEM) → slice re-verify → ring reserve (`xsk.tx.transmit(N)`)
   → write descriptors via `insert(...)` → commit writer → drop writer
   → stamp submits POST-COMMIT (#812) → outstanding_tx accounting →
   per-entry `remember_prepared_recycle` for the kept tail →
   `maybe_wake_tx`. Any reorder breaks the ring or the submit-latency
   invariant.

2. **Submit stamping is POST-commit** (#812 Codex round-1 HIGH #1
   invariant). `stamp_submits()` MUST run after `writer.commit()` and
   `drop(writer)`. The phase split keeps `reserve_and_write_descriptors`
   responsible for the whole "reserve → write → commit → drop → stamp"
   block returning `inserted` to the caller. This is the safe phase
   boundary because the orchestrator never gets a chance to drop a
   live `writer` borrow.

3. **No V_min publish** in this path (#940). The function operates
   on `pending: VecDeque<PreparedTxRequest>` directly, never touches
   a CoSQueueRuntime, never advances `queue_vtime`. The phase split
   preserves the existing comments at the current sites.

4. **Orphan-recycle drop accounting** (#710). Three current drop
   sites do orphan-recycle of the staged scratch with subtle "+= 1
   vs += len-1" differences. Preserve these byte-identical by
   choosing the helper variant carefully.

5. **No new per-tick allocations.** No new `Vec::new()`,
   `Box::new()`, `format!()`, `String::new()`, or `clone()` in the
   hot path. The existing path has zero per-tick allocations on the
   success branch (`scratch_prepared_tx` is reused; `retry_tail` is a
   `Vec` only allocated when there IS a retry tail). The phase split
   preserves this — the orchestrator passes mutable refs to scratch
   between phases, no copies.

6. **Borrow shape.** `binding.scratch.scratch_prepared_tx` is read
   then mutated then read again across phases — but never two
   concurrent mutable borrows. The phase boundaries each take
   `binding: &mut BindingWorker` (the whole struct), so the borrow
   checker handles disjoint field access via single-borrow access.

7. **`#[inline]` on every phase helper.** Each helper is called
   exactly once per orchestrator invocation, so `#[inline]` (not
   `#[inline(always)]`) lets the compiler reproduce the original
   call shape. The function isn't on the per-packet hot path, but
   we still want to give the optimiser the same shape it had pre-split.

8. **Test path preserved.** `tx/transmit_tests.rs` stays at its
   current path. `transmit/mod.rs` loads it via
   `#[path = "../transmit_tests.rs"]` so the tests still see
   `super::*` resolving to the orchestrator + helpers module.
   (Alternative: move tests into `transmit/tests.rs`. Either way
   works; pick whichever the reviewers prefer.)

## Risk assessment

| Class | Verdict | Reasoning |
|-------|---------|-----------|
| Behavioral regression | LOW | Pure code motion; phase order preserved 1:1; orphan-recycle helper preserves asymmetric accounting verbatim. |
| Lifetime / borrow-checker | LOW | All phases take `binding: &mut BindingWorker`. No nested mutable borrows of disjoint fields are needed. |
| Performance regression | LOW | Function is called once per worker tick (not per packet). `#[inline]` on each helper preserves codegen shape. Zero new allocations. |
| Architectural mismatch (#961 / #946 Phase 2 dead-end) | LOW | The phases were already commented out in the source; the file already lives in a `tx/` directory module; #1166 / #1189 / #1199 / #1200 set the pattern for this kind of split. No new architectural premise. |

## Test plan

1. `cargo build --release` clean.
2. `cargo test --release` — all 952+ Rust tests pass.
3. `cargo test --release tx::transmit` — 5/5 flake check.
4. `cargo test --release transmit_prepared_queue` — verify the
   existing `transmit_tests.rs` tests still pass.
5. `go test ./...` — 30 Go packages pass.
6. Deploy on loss userspace cluster.
7. Pass A (CoS disabled) — v4+v6 × push+reverse + 12-stream
   reverse reproducer.
8. Pass B (CoS enabled) — 24-cell per-class CoS smoke (5201-5206).

## Out of scope (explicitly)

- `transmit_batch` (the post-CoS backup path for `TxRequest`,
  separate function, separate scratch buffer). Issue body
  explicitly targets `transmit_prepared_queue`. Future issue can
  apply the same split.
- Fixing the `+= 1 vs += len-1` orphan-recycle accounting
  asymmetry. That's a behavior change deserving its own issue +
  triple-review.
- Removing the `cfg!(feature = "debug-log")` RST_DETECT blocks.
  Diagnostic code; orthogonal.
- Changes to `recycle_cancelled_prepared_offset_with_shared`,
  `recycle_prepared_immediately_with_shared`, or
  `remember_prepared_recycle`. All three stay in `transmit/mod.rs`
  unchanged.

## Open questions for adversarial review

1. **Should we keep `transmit_tests.rs` at its current path, or
   move it under `transmit/tests.rs`?** The current path makes the
   `#[path = ...]` directive a little awkward (`"../transmit_tests.rs"`).
   Moving it makes the file structure more uniform with the new
   layout. But it's churn we don't strictly need.

2. **Six phases vs five?** The issue sketch lists five. The actual
   code has a distinct DSCP-rewrite phase between stage and slice-verify,
   each with its own failure path. Should we collapse rewrite+verify
   into a single `pre_write_validate_staged` phase, or keep them
   separate to preserve the existing failure-path granularity?

3. **Orphan-recycle accounting helper — one helper or two?** The
   existing code has three call sites with two distinct accounting
   shapes: site 1 (line 290-316) does `+= orphaned.len()` because
   `orphaned` does NOT include the offender; sites 2-3 (line 322-355,
   358-391) do `+= orphan_count.saturating_sub(1)` because `orphaned`
   DOES include the offender. The plan defaults to two helpers
   preserving the asymmetry verbatim. Is this the right call, or
   should the refactor unify on one shape?

4. **`#[inline]` vs `#[inline(always)]` on each phase helper?** The
   function is called once per worker tick, not per packet. Reviewer
   guidance from #1188, #1199, #1200 was `#[inline]` (the compiler
   is free to skip it; on a per-tick call site it's harmless either
   way). The plan defaults to `#[inline]`. Is that the right knob?

5. **Architectural mismatch risk vs #961 / #946 Phase 2?** This
   refactor is a 1:1 phase split of an existing pipeline with no
   reordering and no new types. It does not match the #961
   "PacketContext that wraps a packet" / #946 Phase 2 "batched
   per-stage iteration" patterns that got killed. But reviewers
   should confirm: is there any way the per-tick batching here
   could be reorganized to batch ACROSS ticks, and if so, does
   this phase split foreclose that future direction?

6. **Should the orchestrator stay in `transmit/mod.rs` or move to
   `transmit/orchestrator.rs`?** Defaulting to `mod.rs` keeps the
   public-API surface (re-exports + shared types + orchestrator)
   together. Moving the orchestrator out would let `mod.rs` be a
   pure re-export hub. Either works; the plan defaults to `mod.rs`
   for minimum churn.
