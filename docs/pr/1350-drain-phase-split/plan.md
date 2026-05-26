## Status

DRAFT v1 — pending adversarial plan review.

## Issue framing (#1350)

`userspace-dp/src/afxdp/tx/drain.rs` is 800 LOC; the orchestrator
`drain_pending_tx()` at `drain.rs:64` is **253 LOC** with 8
parameters. `docs/engineering-style.md` puts the refactor cue at
>100 LOC and >8 params; this function is 2.5x the LOC cue and at
the param cue. Issue body proposes splitting the orchestrator
into six `drain_phase_*` helpers plus a `DrainCtx<'_>` context
struct that collapses the six immutable per-tick parameters.

## Honest scope / value framing

This is **pure code motion**. The CPU spend in the TX drain
hot path is in `transmit_prepared_batch`, `transmit_batch`,
`ingest_cos_pending_tx_with_provenance`, and `drain_shaped_tx` —
all of which stay byte-identical. The win is purely structural:

- A 253-LOC body becomes six ≤55-LOC `#[inline]` helpers, each
  with a one-paragraph contract.
- Each phase becomes independently testable from
  `tx/drain/tests.rs`, instead of every regression pin having to
  construct a full `BindingWorker` to exercise the orchestrator
  end-to-end.
- The two trailing `_cos_owner_*_by_queue` params are routed
  through `DrainCtx` and stay reserved (issue body asks the
  question; this plan keeps them rather than deletes because
  the public `drain_pending_tx_local_owner` wrapper at
  `drain.rs:524` exists precisely to forward those params from
  `worker/lifecycle.rs`. See "Open question 1").

The win is operator-readability + test-decomposition, not
cycles. **If reviewers conclude the perf-neutral churn is too
large to justify the structural cleanup, PLAN-KILL is an
acceptable verdict** — this skill explicitly invites that
outcome.

## What's already shipped / partially batched

- `tx/` is already a module directory with sibling files
  (`mod.rs`, `dispatch.rs`, `transmit.rs`, `cos_classify.rs`,
  `rings.rs`, `stats.rs`, `tcp_segmentation.rs`,
  `drain.rs`, `drain_tests.rs`, etc.). Following the
  module/foo convention, the split will move `drain.rs` into a
  `drain/` subdirectory with `mod.rs` plus `phase_*.rs` files
  per the skill's standing rule 1.
- The 4 helpers in `drain.rs` that are NOT the orchestrator
  (`bound_pending_tx_local`, `bound_pending_tx_prepared`,
  `pending_tx_capacity`, `drain_pending_tx_local_owner`, plus
  `drop_cos_bound_prepared_leftovers`,
  `drop_cos_bound_local_leftovers`,
  `partition_cos_bound_local_with_rescue`,
  `tx_request_targets_cos_interface`,
  `binding_has_pending_tx_work`, `should_enter_shaped_drain`,
  `has_queued_cos_work`, `ingest_cos_pending_tx`,
  `ingest_cos_pending_tx_with_provenance`,
  `process_pending_queue_in_place`,
  `take_pending_tx_requests`,
  `restore_pending_tx_requests`) stay where they live
  semantically. Plan keeps them all on the orchestrator side
  (`drain/mod.rs`) to avoid a parallel "where does each helper
  live" decision creeping into reviewer scope.
- `drain_tests.rs` already exists as a relocated test file
  (193 LOC) and is loaded via `#[path = ...]` from drain.rs.
  Plan preserves that exact `#[path]` load (renamed to
  `tx/drain/tests.rs`) so existing #784 regression pins keep
  firing without test churn.
- All callers (`worker/lifecycle.rs:59` and
  `worker/lifecycle.rs:90`) reach `drain_pending_tx` via the
  `pub(in crate::afxdp)` re-export at `tx/mod.rs:26`. That
  re-export is preserved verbatim.

## Concrete design

### Directory layout

```
userspace-dp/src/afxdp/tx/
├── drain/
│   ├── mod.rs              # DrainCtx, drain_pending_tx orchestrator + non-orch helpers
│   ├── phase_reap.rs       # drain_phase_reap_completions
│   ├── phase_rekick.rs     # drain_phase_maybe_rekick
│   ├── phase_ingest.rs     # drain_phase_ingest_cos
│   ├── phase_shaped.rs     # drain_phase_drain_cos (shaped-queue drain + reingest budget)
│   ├── phase_backup.rs     # drain_phase_drain_local_backup (drop_cos_bound_* + transmit_prepared_batch + transmit_batch fallback)
│   ├── phase_submit.rs     # drain_phase_submit_and_wake
│   └── tests.rs            # relocated from drain_tests.rs
```

The 5 helpers preserved alongside the orchestrator
(`bound_pending_tx_*`, `binding_has_pending_tx_work`,
`should_enter_shaped_drain`, the `ingest_cos_*` helpers, etc.)
remain in `drain/mod.rs`. Phase files are tightly scoped: each
file holds exactly one `drain_phase_*` plus any helper that is
ONLY used by that phase. Helpers shared across phases stay in
`mod.rs`.

### DrainCtx

```rust
pub(in crate::afxdp) struct DrainCtx<'a> {
    pub forwarding: &'a ForwardingState,
    pub worker_id: u32,
    pub worker_commands_by_id:
        &'a BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    pub now_ns: u64,
    pub cos_owner_worker_by_queue: &'a BTreeMap<(i32, u8), u32>,
    pub cos_owner_live_by_queue:
        &'a BTreeMap<(i32, u8), Arc<BindingLiveState>>,
}
```

Six fields rather than the four shown in the issue sketch, because
the two `_cos_owner_*_by_queue` params currently flagged unused
are routed via `DrainCtx` as future-use plumbing (see Open
question 1). All fields are immutable references or `Copy`
scalars; `DrainCtx` itself is `Copy`-cheap to pass.

DrainCtx is **stack-built once** at the top of
`drain_pending_tx` from the original 8 params. It is NOT heap
allocated; it is NOT cloned across phases (each phase takes
`ctx: DrainCtx<'_>` by value — a 48-byte register-resident
struct of references — or `&DrainCtx<'_>` if rustc prefers).
No `Box`, no `Arc`, no `Rc` introduced.

Hot-path allocation impact: zero new allocations per drain
tick (verified by constructing only `&` references and
primitives).

### Main loop transformation

`drain_pending_tx` becomes (with `#[inline]` on each phase):

```rust
pub(in crate::afxdp) fn drain_pending_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    if !binding_has_pending_tx_work(binding) {
        return false;
    }
    let ctx = DrainCtx {
        forwarding,
        worker_id,
        worker_commands_by_id,
        now_ns,
        cos_owner_worker_by_queue,
        cos_owner_live_by_queue,
    };

    let mut did_work = false;
    did_work |= drain_phase_reap_completions(binding, shared_recycles);
    drain_phase_maybe_rekick(binding, &ctx);
    drain_phase_ingest_cos(binding, &ctx, shared_recycles);
    did_work |= drain_phase_drain_cos(binding, &ctx, shared_recycles);
    // Backup phase returns either `did_work` (Ok path) or a
    // Retry sentinel that short-circuits the rest. Variant
    // returns `BackupOutcome::EarlyReturn(true)` to faithfully
    // model the existing `return true;` on TxError::Retry.
    match drain_phase_drain_local_backup(binding, &ctx, shared_recycles) {
        BackupOutcome::Continue { did_work: bw } => did_work |= bw,
        BackupOutcome::EarlyReturn(v) => return v,
    }
    drain_phase_submit_and_wake(binding, &ctx, shared_recycles, &mut did_work)
}
```

`BackupOutcome` preserves the two non-trivial early-return
points (lines 233 and 249 of the current orchestrator) without
flattening them into a fall-through that would change
observable side-effect ordering.

### Per-phase scope (LOC budget per phase ≤55)

1. **`drain_phase_reap_completions`** — wraps
   `reap_tx_completions(binding, shared_recycles) > 0`.
   Body is a one-liner; the wrapper exists so the orchestrator
   reads as six homogeneous phases. **Returns** `bool` (did_work).
   ~5 LOC.

2. **`drain_phase_maybe_rekick`** — current lines 81-86 (the
   `outstanding_tx > 0 && prepared.is_empty() && local.is_empty()`
   guard + `maybe_wake_tx(binding, false, now_ns)`).
   ~8 LOC.

3. **`drain_phase_ingest_cos`** — current lines 87-100.
   Calls `ingest_cos_pending_tx`. Side-effect identical.
   ~8 LOC.

4. **`drain_phase_drain_cos`** — current lines 101-200.
   Holds BOTH the initial shaped-drain loop (lines 109-137)
   AND the bounded re-ingest budget loop (lines 155-200).
   This is the largest phase by LOC. Reviewers should focus
   here. ~95 LOC including the inner helpers — if this exceeds
   the ≤55 cap I will split into `phase_shaped_initial` +
   `phase_shaped_reingest_budget`, but keeping them together
   keeps the shaped-drain control flow readable as one unit.
   **Will measure during implementation and report in the PR.**

5. **`drain_phase_drain_local_backup`** — current lines
   201-313. Contains:
   - `drop_cos_bound_prepared_leftovers` call
   - `transmit_prepared_batch` loop (with `TxError::Retry`
     early-return)
   - `pending_tx_local.is_empty() && pending_tx_empty()`
     short-circuit (current line 247)
   - `take_pending_tx_requests` + `drop_cos_bound_local_leftovers`
   - `transmit_batch` retry loop
   - `restore_pending_tx_requests`
   Returns `BackupOutcome` enum to model the early-returns
   without changing semantics. ~95 LOC. Same split-if-needed
   note as phase 4.

6. **`drain_phase_submit_and_wake`** — current line 314-315
   (`update_binding_debug_state` + return). Trivial.
   ~5 LOC.

### Public API preservation

Preserved verbatim (signatures and visibility):

```rust
pub(in crate::afxdp) fn pending_tx_capacity(ring_entries: u32) -> usize
pub(in crate::afxdp) fn bound_pending_tx_local(binding: &mut BindingWorker)
pub(in crate::afxdp) fn bound_pending_tx_prepared(
    binding: &mut BindingWorker,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
)
pub(in crate::afxdp) fn drain_pending_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool
pub(in crate::afxdp) fn drain_pending_tx_local_owner(/* same 8 params */) -> bool
pub(in crate::afxdp) const COS_GUARANTEE_VISIT_NS: u64 = 200_000;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MIN_BYTES: u64 = 1500;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 512 * 1024;
pub(in crate::afxdp) const COS_SURPLUS_ROUND_QUANTUM_BYTES: u64 = 1500;
```

The 8-param signature of `drain_pending_tx` stays at the public
boundary; the parameter-count refactor is **internal** (orchestrator
constructs `DrainCtx` from those 8 args and passes the ctx to
the six phases). The wrapper at
`drain_pending_tx_local_owner` is unchanged.

`tx/mod.rs:21-28` re-exports are preserved verbatim.

### Hidden invariants the change MUST preserve

1. **Phase ordering is sequenced — reordering = bug.** The six
   phases execute strictly in order:
   reap → rekick → ingest → shaped-drain → backup → submit/wake.
   Any reordering changes observable behavior (e.g., reap before
   rekick is required because reap may eliminate the very
   condition the rekick guard checks).

2. **Side-effect ordering within phases**: The shaped-drain
   phase's per-iteration sequence is start-ns → drain →
   delta-ns → bucket-attribute → did_work update. The
   re-ingest budget phase's iteration is:
   pending-empty-check → ingest-no-pps → inner-drain-loop →
   serviced-in-inner break. Both must stay byte-identical.

3. **Early-return points** (currently 2): line 233
   `return true;` on `TxError::Retry` from
   `transmit_prepared_batch`, and lines 247-254
   `update_binding_debug_state(binding); return did_work || ...`
   on empty pending. Preserved via `BackupOutcome` enum.

4. **`did_work` accumulation** must remain equivalent: the
   final return is `did_work || binding_has_pending_tx_work(binding)`.
   This is preserved by collecting `did_work` across phases
   into the orchestrator's local and computing the same OR at
   `drain_phase_submit_and_wake`.

5. **The orchestrator's `binding_has_pending_tx_work` top guard
   stays inside `drain_pending_tx`**, not pushed into a phase.
   The issue body explicitly notes this guard is "out of scope"
   and the early-exit must NOT pay any phase-call overhead.

6. **`#[inline]` on every `drain_phase_*` function**. The
   compiler will collapse most of them back to the existing
   instruction sequence at -O3; this preserves hot-path codegen.
   *Reviewers: this is the perf-neutrality contract.*

7. **`DrainCtx<'_>` is stack-built once per drain call** and
   passed by reference (`&DrainCtx<'_>`) to each phase. Codegen
   should be identical to passing the six fields directly
   under `#[inline]`. Verified by checking
   `objdump -d` for symbol presence vs inlining if reviewers
   want it (offered).

8. **No new allocations per drain tick.** Hot-path allocation
   discipline is sacrosanct per `docs/engineering-style.md`.

9. **HA sync portability**: no public type changes; binding
   state mutation patterns identical to before — HA snapshot
   sync paths are unaffected.

10. **`tx/drain/tests.rs`** must keep loading
    `partition_cos_bound_local_scans_mixed_head_deque` as the
    Codex-flagged #784 regression pin. After the move, the test
    file's `use super::*;` resolves to `drain::mod`, which
    re-exports `partition_cos_bound_local_with_rescue` and
    `tx_request_targets_cos_interface` via the same path.

### Risk assessment

| Risk class | Level | Mitigation |
|---|---|---|
| Behavioral regression | LOW | Pure code motion; phase ordering pinned in plan; existing #784 mixed-head regression test stays attached; cargo test --release before push. |
| Lifetime / borrow-checker | LOW-MED | The phase functions take `&mut BindingWorker` and `&DrainCtx<'_>`. The existing orchestrator already passes 8 params through to inner calls without conflict, so splitting it does not introduce new aliasing. The bigger risk is `shared_recycles: &mut Vec<...>` — this lives in the caller, not in DrainCtx, because some phases (`reap`, `shaped`, `backup`) need `&mut` and DrainCtx is all-immutable. Each phase signature must accept `shared_recycles: &mut Vec<(u32, u64)>` explicitly. **No anonymous `&mut` aliasing introduced.** |
| Performance regression | LOW | `#[inline]` on every phase; DrainCtx is a 48-byte stack-resident struct of references; LLVM should produce identical codegen at -O3. Smoke matrix on loss userspace cluster will pin throughput. Phase 4 (shaped-drain) is the hottest — if `#[inline]` is not enough I will mark it `#[inline(always)]`. |
| Architectural mismatch (#961/#946-Phase-2 dead-end) | LOW | Issue body proposes EXACT decomposition that already matches the function's existing comment-section boundaries (lines 87-88 "First ingest pass", 101 "Original #751 drain loop", 138-148 "#760 bounded re-ingest", 201-203 "#760: drop CoS-bound items", 247 "if empty"). The phases are not a speculative architecture, they are the existing comment headers. No #946-Phase-2 "batched iteration" or #961 PacketContext-style premise is involved. |

## Test plan

- `cargo build --release` clean from `/dev/shm/cargo`.
- `cargo test --release` — full suite (952+ tests).
- `cargo test --release tx::drain` — 5x flake check on every
  drain-prefixed test (in particular
  `partition_cos_bound_local_scans_mixed_head_deque`).
- `go test ./...` — 30 Go packages.
- Smoke on loss userspace cluster:
  - Pass A: CoS disabled. v4+v6 × push+reverse single-stream
    baseline (4 cells) + `-P 12 -R` multi-stream reproducer
    against 172.16.80.200 and 2001:559:8585:80::200 (2 cells).
  - Pass B: CoS enabled. 5201-5206 per-class × v4+v6 ×
    push+reverse (24 cells).
- Optional perf: `perf record -F 999 -p $(pgrep userspace-dp)
  -- sleep 20` under -P 12 with CoS on, before/after, to
  confirm `drain_pending_tx` percentage stayed flat.
- **Marker**: AWAITING-BATCH-MERGE (no per-PR smoke per
  standing rule 3 — comprehensive smoke batched at end of
  refactor-backlog wave).

## Out of scope (explicitly)

- The shaping algorithm inside `drain_shaped_tx` (separate
  file, separate concern).
- The wake / kick policy in `maybe_wake_tx`.
- The `binding_has_pending_tx_work` top guard.
- Deletion of the unused `_cos_owner_*_by_queue` params (see
  Open question 1 — kept until plumbing decision is final).
- Conversion of the `drop_cos_bound_*_leftovers` family to a
  phase-internal closure — kept as free functions in
  `drain/mod.rs` to preserve their unit-test surface.
- Touching `bound_pending_tx_local` /
  `bound_pending_tx_prepared` / `pending_tx_capacity`.
- Touching `worker/lifecycle.rs` callers.

## Open questions for adversarial review

1. **Should the two underscore-prefixed params be deleted now
   or kept as DrainCtx fields?** The issue body says "drop them
   or wire them" but does not pick. My current plan keeps them
   in DrainCtx (forwarded but unused inside `drain_pending_tx`)
   because `drain_pending_tx_local_owner` at `drain.rs:524` —
   which is the path `worker/lifecycle.rs` calls — already
   forwards these params from `worker/lifecycle.rs:50-51`. If
   we delete them, the wrapper signature shrinks too, and the
   caller in `worker/lifecycle.rs` has to drop the args from
   both call sites (`drain.rs:534-543`). Reviewers: is the
   simpler "delete the dead params end-to-end" the right
   call here, or is the plumbing intentional and worth
   preserving? PLAN-KILL is appropriate if either choice is
   wrong.

2. **Should phase 4 (shaped-drain) and phase 5 (backup) each
   be a single file at ~95 LOC, or should they sub-split**
   `phase_shaped_initial.rs` + `phase_shaped_reingest.rs` and
   `phase_backup_prepared.rs` + `phase_backup_local.rs`?
   Splitting smaller helps the file-LOC discipline; keeping
   them whole preserves shaped-drain control-flow readability.

3. **Is `BackupOutcome` the right shape**, or should phase 5
   return `(bool, Option<bool>)` where the Option encodes the
   early-return? The enum is a hair more explicit; the tuple
   is more idiomatic Rust. Either way the semantics must be
   that `TxError::Retry` short-circuits to `return true;`.

4. **Should `drain_phase_submit_and_wake` take `&mut did_work`
   or return `bool` and let the orchestrator OR-fold it?**
   Currently the issue's sketch has `did_work |=` semantics
   and the original function returns
   `did_work || binding_has_pending_tx_work(binding)`. The
   `&mut did_work` shape lets the phase do the final OR-fold
   internally and return the actual value; passing `bool` and
   folding in the orchestrator is more functional. Reviewers:
   call.

5. **Is the file layout `tx/drain/{mod,phase_*}.rs` correct vs
   keeping everything in a flat `tx/drain.rs` with
   `drain_phase_*` private fns?** The skill's standing rule 1
   mandates the module/foo convention; the issue body's sketch
   is just function decomposition without specifying. The
   module-dir form makes the phase boundaries visible at the
   filesystem; the flat-file form keeps blame less noisy.
   Module-dir is the chosen form. PLAN-KILL is appropriate if
   the file split is wrong.

6. **Are there any phase-ordering invariants I've missed?**
   The current orchestrator interleaves several "if CoS
   configured" fast-exits (lines 155, 205, 258). My plan
   preserves each fast-exit inside the corresponding phase
   function. Reviewers: walk lines 64-316 and confirm I have
   NOT silently combined two CoS-empty checks into one and NOT
   reordered any side effect. The drain-cos phase + backup
   phase both have their own `forwarding.cos.interfaces.is_empty()`
   guards — these are independent and must NOT be hoisted.

7. **`#[inline]` enough, or `#[inline(always)]` needed?** The
   compiler usually inlines small static-call-site functions
   at -O3 with just `#[inline]`. Adversarial reviewers should
   challenge me to prove codegen identity. If they want the
   `objdump -d` check on `drain_pending_tx`'s assembly before
   and after, I'll run it during implementation.
