## Status

DRAFT v2 — addresses Codex (task-mpn2upaq-qskyou) and Gemini
(task-mpn2vhfn-fa69ga) round-1 PLAN-NEEDS-MAJOR findings.

## Round-1 reviewer findings + resolutions

### Findings BOTH reviewers raised

**HIGH — Phase 5 `BackupOutcome` loses prior `did_work`** (Codex
finding 1, Gemini finding 3 & 4):

The v1 sketch had `drain_phase_drain_local_backup` returning
`BackupOutcome::EarlyReturn(v)` with `v` computed only from the
phase's local state. But `drain.rs:249` and `drain.rs:253` both
return `did_work || binding_has_pending_tx_work(binding)` —
where `did_work` carries reap/shaped accumulation from
`drain.rs:77`, `drain.rs:128`, and `drain.rs:190`. Phase 5
cannot construct `v` without seeing the orchestrator's
accumulated `did_work`.

Additional subtlety: `drain.rs:248` calls
`update_binding_debug_state(binding)` before the return; the
other early-exit at `drain.rs:252-253` does NOT call it. The
enum MUST preserve that side-effect distinction.

**Resolution (v2)**: `drain_phase_drain_local_backup` accepts
`did_work: &mut bool` and returns
`BackupOutcome::{Continue, EarlyReturnAfterDebugUpdate, EarlyReturnNoDebugUpdate}`.

```rust
enum BackupOutcome {
    /// Normal completion — orchestrator continues to phase 6.
    Continue,
    /// drain.rs:233 TxError::Retry path — orchestrator returns true.
    /// (did_work was already mutated to true via the `did_work |= ...`
    /// updates inside the phase; this variant just signals the return.)
    EarlyReturnRetry,
    /// drain.rs:247-249 path — pending_tx_local + pending_tx_empty
    /// AFTER transmit_prepared loop. Orchestrator calls
    /// update_binding_debug_state(binding) then returns
    /// did_work || binding_has_pending_tx_work(binding).
    EarlyReturnAfterDebugUpdate,
    /// drain.rs:251-253 path — pending was empty when popped.
    /// Orchestrator does NOT call update_binding_debug_state;
    /// returns did_work || binding_has_pending_tx_work(binding).
    EarlyReturnNoDebugUpdate,
}
```

Phase 5 mutates `*did_work` as it does work (the same `|=`
updates currently at lines 214 and 277). The orchestrator owns
the final OR-fold and the `update_binding_debug_state` call.
This preserves both the side-effect distinction at line 248 vs
252 and the cumulative `did_work` flag.

### Findings only Codex raised

**MEDIUM — Delete `_cos_owner_*_by_queue` params end-to-end**
(Codex finding 2). Gemini agreed in answer to OQ1. v2 deletes
the two params from the `drain_pending_tx` signature, from
`drain_pending_tx_local_owner`, and from the callers at
`worker/lifecycle.rs:50-51,66-67,97-98`. Also delete the
forwarding paths through `tx/dispatch.rs` and
`tx/tcp_segmentation.rs` if they pass these maps through.

**MEDIUM — Eight files is over-modularized** (Codex finding 3).
Gemini disagreed (accepted module/foo as project convention).
The skill standing rule 1 mandates the module/foo convention.
v2 keeps the module/foo layout BUT collapses the four ≤5-LOC
trivial phases (reap, rekick, ingest, submit) into a single
`phase_trivial.rs` file. The two large phases (shaped, backup)
each get their own file because they have non-trivial internal
control flow worth filesystem-level separation:

```
userspace-dp/src/afxdp/tx/
├── drain/
│   ├── mod.rs            # DrainCtx, orchestrator, BackupOutcome, helpers (~250 LOC)
│   ├── phase_trivial.rs  # reap_completions, maybe_rekick, ingest_cos, submit_and_wake (~50 LOC)
│   ├── phase_shaped.rs   # drain_phase_drain_cos + helper split_into shaped_initial + shaped_reingest_budget (~95 LOC)
│   ├── phase_backup.rs   # drain_phase_drain_local_backup + helpers (~95 LOC)
│   └── tests.rs          # relocated from drain_tests.rs
```

Five files. This compromises between Codex's
"≤3 files" push and Gemini's "8 is fine" accept, and matches
the skill's module/foo standing rule.

**MEDIUM — `#[inline]` is a hint, prove codegen** (Codex finding 4).
Resolution: during implementation I will:
1. Build with `cargo build --release` and dump
   `drain_pending_tx` via `cargo asm --rust --release
   userspace_dp::afxdp::tx::drain::drain_pending_tx`
   (or `objdump -d` on the binary) before and after the
   refactor.
2. Compare instruction counts. If the post-refactor function
   has new call edges to any `drain_phase_*` symbol, escalate
   to `#[inline(always)]` on that phase.
3. Report the comparison in the PR body before requesting
   reviewers.

**Codex specific call — split phase 4 internally**: split the
shaped-drain phase into `shaped_initial_drain` and
`shaped_reingest_budget` as private helpers inside
`phase_shaped.rs`. Orchestrator still calls one phase fn
(`drain_phase_drain_cos`); the internal split is for
readability inside that file.

**Codex specific call — split phase 5 internally**: same shape
— `backup_drain_prepared` (lines 201-246) and
`backup_drain_local` (lines 247-313) as private helpers inside
`phase_backup.rs`. Orchestrator still calls one phase fn
(`drain_phase_drain_local_backup`).

### Findings only Gemini raised

None novel; Gemini's answers to OQ1-7 either matched Codex or
left the call to me. OQ4 (submit_and_wake signature): Gemini
prefers `did_work: bool` in + bool out. v2 follows this.



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

### Directory layout (v2 — 5 files per Codex finding 3)

```
userspace-dp/src/afxdp/tx/
├── drain/
│   ├── mod.rs            # DrainCtx, BackupOutcome, drain_pending_tx orchestrator,
│   │                     # non-phase helpers (bound_pending_tx_*, partition_*,
│   │                     # ingest_cos_*, etc.) — ~400 LOC
│   ├── phase_trivial.rs  # 4 thin phases collapsed into one file:
│   │                     #   drain_phase_reap_completions
│   │                     #   drain_phase_maybe_rekick
│   │                     #   drain_phase_ingest_cos
│   │                     #   drain_phase_submit_and_wake
│   │                     # ~50 LOC total
│   ├── phase_shaped.rs   # drain_phase_drain_cos + private helpers
│   │                     # shaped_initial_drain + shaped_reingest_budget — ~110 LOC
│   ├── phase_backup.rs   # drain_phase_drain_local_backup + private helpers
│   │                     # backup_drain_prepared + backup_drain_local — ~110 LOC
│   └── tests.rs          # relocated from drain_tests.rs (193 LOC)
```

Five files, not eight. Trivial phases collapse to one
`phase_trivial.rs` per Codex finding 3 push-back; the two
LOC-heavy phases each keep their own file so the shaped/backup
control flow is filesystem-visible.

The 5+ helpers preserved alongside the orchestrator
(`bound_pending_tx_*`, `binding_has_pending_tx_work`,
`should_enter_shaped_drain`, the `ingest_cos_*` helpers,
`partition_cos_bound_local_with_rescue`,
`tx_request_targets_cos_interface`, etc.) remain in
`drain/mod.rs`. Phase files hold exactly one `drain_phase_*`
(plus the trivial four colocated) and the private helpers
used ONLY by that phase. Helpers shared across phases stay in
`mod.rs`.

### DrainCtx (v2 — four fields; unused params deleted)

```rust
pub(in crate::afxdp) struct DrainCtx<'a> {
    pub forwarding: &'a ForwardingState,
    pub worker_id: u32,
    pub worker_commands_by_id:
        &'a BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    pub now_ns: u64,
}
```

Per round-1 Codex finding 2 + Gemini answer to OQ1, the two
unused `_cos_owner_*_by_queue` params are **deleted
end-to-end** in v2:

- removed from `drain_pending_tx` signature
- removed from `drain_pending_tx_local_owner` signature
- removed from `worker/lifecycle.rs` call sites at lines
  50-51, 66-67, 97-98
- if `tx/dispatch.rs` or `tx/tcp_segmentation.rs` forward
  them through, removed there too

DrainCtx has FOUR fields, all immutable refs or `Copy`
scalars. Stack-built once at the top of `drain_pending_tx`;
not heap-allocated; not cloned across phases.

DrainCtx is **stack-built once** at the top of
`drain_pending_tx` from the original 8 params. It is NOT heap
allocated; it is NOT cloned across phases (each phase takes
`ctx: DrainCtx<'_>` by value — a 48-byte register-resident
struct of references — or `&DrainCtx<'_>` if rustc prefers).
No `Box`, no `Arc`, no `Rc` introduced.

Hot-path allocation impact: zero new allocations per drain
tick (verified by constructing only `&` references and
primitives).

### Main loop transformation (v2 — six-param signature, three-variant BackupOutcome)

`drain_pending_tx` becomes (with `#[inline]` on each phase):

```rust
pub(in crate::afxdp) fn drain_pending_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> bool {
    if !binding_has_pending_tx_work(binding) {
        return false;
    }
    let ctx = DrainCtx {
        forwarding,
        worker_id,
        worker_commands_by_id,
        now_ns,
    };

    let mut did_work = false;
    did_work |= drain_phase_reap_completions(binding, shared_recycles);
    drain_phase_maybe_rekick(binding, &ctx);
    drain_phase_ingest_cos(binding, &ctx, shared_recycles);
    did_work |= drain_phase_drain_cos(binding, &ctx, shared_recycles);

    // Phase 5 takes &mut did_work so the prepared/local
    // transmit loops can update it in place; the orchestrator
    // owns the early-return semantics so the side-effect
    // distinction at drain.rs:248 (calls update_binding_debug_state)
    // vs drain.rs:252 (does NOT) is preserved exactly.
    match drain_phase_drain_local_backup(binding, &ctx, shared_recycles, &mut did_work) {
        BackupOutcome::Continue => {}
        BackupOutcome::EarlyReturnRetry => return true,
        BackupOutcome::EarlyReturnAfterDebugUpdate => {
            update_binding_debug_state(binding);
            return did_work || binding_has_pending_tx_work(binding);
        }
        BackupOutcome::EarlyReturnNoDebugUpdate => {
            return did_work || binding_has_pending_tx_work(binding);
        }
    }
    drain_phase_submit_and_wake(binding, did_work)
}
```

The three-variant `BackupOutcome` preserves the three exit
semantics:
- `EarlyReturnRetry` → `drain.rs:233` `return true;`
- `EarlyReturnAfterDebugUpdate` → `drain.rs:247-249` (calls
  `update_binding_debug_state` first)
- `EarlyReturnNoDebugUpdate` → `drain.rs:251-253` (does NOT
  call `update_binding_debug_state` — pending was empty when
  popped, not after the transmit loop)
- `Continue` → fall through to phase 6 submit/wake.

### Per-phase scope (v2)

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
   Lives in `phase_shaped.rs`. **Codex finding 3.1 split**:
   Internally factored into two private helpers in the same
   file:
   - `shaped_initial_drain(binding, ctx, shared_recycles, did_work)`
     wraps lines 109-137 (the first while-loop).
   - `shaped_reingest_budget(binding, ctx, shared_recycles, did_work)`
     wraps lines 155-200 (the bounded re-ingest loop, including
     the `forwarding.cos.interfaces.is_empty()` guard at line
     155).
   `drain_phase_drain_cos` calls both in order. ~95 LOC total
   in `phase_shaped.rs`. The two helpers take `did_work: &mut bool`
   so the existing `did_work = true;` updates inside the loops
   preserve cumulative semantics.

5. **`drain_phase_drain_local_backup`** — current lines
   201-313. Contains:
   - `drop_cos_bound_prepared_leftovers` call (line 206)
   - `transmit_prepared_batch` loop with `TxError::Retry`
     early-return at line 233
   - `pending_tx_local.is_empty() && pending_tx_empty()`
     short-circuit (current lines 247-249, calls
     `update_binding_debug_state`)
   - `take_pending_tx_requests` (current line 251) — if pending
     is empty after that take, return without
     `update_binding_debug_state` (lines 252-253)
   - `drop_cos_bound_local_leftovers` (line 258)
   - `transmit_batch` retry loop (lines 268-310)
   - `restore_pending_tx_requests` (lines 311-313)
   Returns `BackupOutcome` with three early-return variants
   (per round-1 finding HIGH); takes `did_work: &mut bool`.
   **Codex finding 3.2 split**: Internally factored into two
   private helpers in the same file:
   - `backup_drain_prepared(binding, ctx, shared_recycles, did_work) -> Option<BackupOutcome>`
     wraps lines 201-246. Returns `Some(EarlyReturnRetry)` on
     `TxError::Retry`; otherwise `None`.
   - `backup_drain_local(binding, ctx, shared_recycles, did_work) -> BackupOutcome`
     wraps lines 247-313.
   `drain_phase_drain_local_backup` chains them, propagating
   the prepared-side early-return. ~110 LOC total in
   `phase_backup.rs`.

6. **`drain_phase_submit_and_wake`** — current line 314-315
   (`update_binding_debug_state(binding); did_work || binding_has_pending_tx_work(binding)`).
   Takes `did_work: bool`, returns `bool`. Lives in
   `phase_trivial.rs`. ~5 LOC.

### Public API changes (v2)

Preserved verbatim:

```rust
pub(in crate::afxdp) fn pending_tx_capacity(ring_entries: u32) -> usize
pub(in crate::afxdp) fn bound_pending_tx_local(binding: &mut BindingWorker)
pub(in crate::afxdp) fn bound_pending_tx_prepared(
    binding: &mut BindingWorker,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
)
pub(in crate::afxdp) const COS_GUARANTEE_VISIT_NS: u64 = 200_000;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MIN_BYTES: u64 = 1500;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 512 * 1024;
pub(in crate::afxdp) const COS_SURPLUS_ROUND_QUANTUM_BYTES: u64 = 1500;
```

**Changed** (round-1 Codex finding 2): two `_cos_owner_*_by_queue`
params dropped from BOTH signatures and from all call sites.

```rust
// Before (v1): 8 params
// After (v2):  6 params
pub(in crate::afxdp) fn drain_pending_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> bool
pub(in crate::afxdp) fn drain_pending_tx_local_owner(/* same 6 params */) -> bool
```

Caller updates required:
- `worker/lifecycle.rs:59-68` (drop 2 trailing args)
- `worker/lifecycle.rs:90-99` (drop 2 trailing args)
- The 2 trailing args at `lifecycle.rs` are still LIVE at that
  call point for OTHER calls (e.g. `drain_pending_tx_local_owner`
  is called from `tx/dispatch.rs` and `tx/tcp_segmentation.rs`
  via the worker_loop dispatch path). I will audit ALL call
  sites during implementation and drop the args end-to-end OR
  if a caller still needs them for a different fn (e.g.
  `enqueue_local_into_cos`), keep them alive in that caller's
  scope but stop forwarding them to drain.

`tx/mod.rs:21-28` re-exports preserved (still re-export the
post-trim symbols).

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

6. **`#[inline]` on every `drain_phase_*` function**, with
   `cargo asm`/`objdump` verification (per round-1 Codex
   finding 4). The compiler usually inlines small static-call-site
   fns at -O3 with just `#[inline]`. During implementation:
   - Dump `drain_pending_tx` post-refactor and confirm no
     CALL edges to any `drain_phase_*` symbol survive.
   - If any phase remains as a real call edge, escalate to
     `#[inline(always)]` on that phase.
   - Report instruction-count comparison in the PR body.
   This is the perf-neutrality contract; reviewers can demand
   the asm dump if they want to verify.

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

## Open questions — round-1 status

Round 1 (Codex task-mpn2upaq-qskyou, Gemini
task-mpn2vhfn-fa69ga) both returned PLAN-NEEDS-MAJOR; all 7
open questions resolved as follows:

1. **OQ1 (delete unused params?)** — RESOLVED: delete
   end-to-end. Codex finding 2 + Gemini OQ1 answer concurred.
2. **OQ2 (split phase 4/5?)** — RESOLVED: keep each as one
   `drain_phase_*` entry point but factor into two private
   helpers in the same file (Codex specific call). Gemini
   accepted keep-whole; the internal split is a hair more
   readable.
3. **OQ3 (BackupOutcome shape?)** — RESOLVED: three-variant
   enum + `&mut did_work` param, per Codex finding 1 / Gemini
   finding 3-4. The v1 sketch was unsafe.
4. **OQ4 (submit_and_wake signature?)** — RESOLVED: takes
   `did_work: bool` in, returns `bool` (Gemini answer).
5. **OQ5 (module-dir layout?)** — RESOLVED: keep module/foo
   per skill rule, but collapse 4 trivial phases into one
   `phase_trivial.rs`. Five files total.
6. **OQ6 (phase-ordering invariants missed?)** — Both
   reviewers confirmed: no phase-ordering invariants missed.
   Both flagged the three independent `cos.interfaces.is_empty()`
   guards at lines 155, 205, 258 as MUST NOT be hoisted —
   v2 keeps them independent in their respective phases.
7. **OQ7 (`#[inline]` vs `#[inline(always)]`?)** — Codex
   finding 4: prove via `cargo asm` / `objdump`. v2
   methodology section above incorporates this.

## Round-2 open questions for reviewers

1. **Round-1 had no quoted PLAN-KILL grounds, but BackupOutcome
   was caught as a HIGH semantic bug. v2's three-variant
   BackupOutcome with `&mut did_work` is the agreed shape —
   does either reviewer see a remaining did_work-aliasing or
   side-effect-ordering hazard in the v2 main-loop sketch
   above?**

2. **Does collapsing the 4 trivial phases into `phase_trivial.rs`
   preserve filesystem readability or does it muddy the phase
   model?** Codex pushed against 8 files; Gemini accepted 8 files.
   v2 lands at 5 — is that the right compromise?

3. **`drain_pending_tx_local_owner` at `drain.rs:524` becomes
   a no-op wrapper that just forwards the 6 remaining params
   to `drain_pending_tx`. Should it be deleted entirely (call
   sites switch to `drain_pending_tx` directly) or preserved
   for symmetry with other `*_owner` wrappers?** Currently
   it is the only call site `worker/lifecycle.rs:59` reaches.
   PR scope creep risk if deletion balloons the diff.

4. **`tx/dispatch.rs` and `tx/tcp_segmentation.rs` may forward
   the two deleted params. Reviewer pre-check: grep these
   files now and tell me whether removing the params from
   the drain signature requires a cascade through other files.**
   I will audit during implementation but a heads-up from
   either reviewer saves a round.

5. **Is the v2 inlining-verification plan (`cargo asm` +
   `#[inline(always)]` escalation if call edges remain) the
   right discipline, or is a `perf record` before/after on
   the loss userspace cluster the only sufficient evidence?**
