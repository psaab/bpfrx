# #1443 — `tx/dispatch.rs::enqueue_pending_forwards` modular phase split

**Status:** DRAFT v2 — addressing Codex + AGY round-1 PLAN-NEEDS-MAJOR
findings (both reviewers agreed plan needed major revision; neither
called PLAN-KILL).

## Round-1 findings addressed

Codex round-1 task-id `task-mpn9fpo5-h6c0nu`. AGY round-1 task-id
`adversarial-review-mpn90zjs-vntq8b`. Both verdicts captured in
`reviewer-ids.md`.

### Blocking findings (both reviewers)

1. **`copied_source_frame` invariant statement was wrong (Codex
   blocking #1).** v1 said copy-fallback/direct-TX set
   `copied_source_frame`. Reality (verified at dispatch.rs:309 +
   dispatch.rs:376): only TCP-segmentation paths set
   `copied_source_frame`. It is consumed at dispatch.rs:418 to *skip
   Phase 8 entirely* and at dispatch.rs:431 for seg-miss accounting.
   It does NOT drive the final ingress recycle. The final ingress
   recycle is gated only by `retained_source_frame` at dispatch.rs:897
   and dispatch.rs:902. Fixed in §"Hidden invariants" below.

2. **Phase 8 control-flow under-specified (Codex blocking #2).** Phase 8
   has four mid-body `continue` statements at dispatch.rs:544,
   dispatch.rs:562, dispatch.rs:822, dispatch.rs:840. Three of them
   (544, 562, 822, 840) skip `apply_shared_recycles` + skip
   `handle_forward_build_failure` + skip the final ingress recycle.
   `ControlFlow<()>` is too coarse — the helper must return a
   structured `Phase8Outcome` enum that names every continue path so
   the orchestrator can dispatch each one to its current sink.
   Concrete outcome enum is in §"Concrete design — Phase 8 outcome
   enum" below.

3. **`#[path = "dispatch_tests.rs"]` will break the test load (Codex
   blocking #3).** dispatch.rs:1473 has `#[cfg(test)] #[path =
   "dispatch_tests.rs"] mod tests;`. After moving `dispatch.rs` →
   `dispatch/mod.rs`, the `#[path]` resolves relative to the new
   module file. The plan now moves `dispatch_tests.rs` into
   `dispatch/dispatch_tests.rs` (sibling file inside the new
   directory) and updates the `#[path]` accordingly. Also corrects
   the v1 claim of "60+ tests" — `dispatch_tests.rs` has 15 tests
   (counted via `grep -c '#\[test\]'`); call sites for private
   helpers are noted explicitly below.

4. **`use self::tx::dispatch::*;` glob at afxdp/mod.rs:140 (Codex
   blocking #4).** v1 missed this. The new `dispatch/mod.rs` MUST
   either (a) re-export every `pub(in crate::afxdp)` symbol verbatim
   so the glob resolves identically, or (b) make the glob-target a
   `pub use dispatch::inner_module::*;` chain. We pick (a) — see
   §"`dispatch/mod.rs` re-export contract" below for the exact list.

5. **Phase 8 borrow shape — pass `*const MmapArea` + `ingress_umem_ptr`
   explicitly (both reviewers).** AGY caught the aliasing hazard
   (`target_binding: &mut BindingWorker` + `ingress_area: &MmapArea`
   where the second is derived via raw-pointer cast and may alias the
   first in hairpin / shared-UMEM configs). Codex caught the missing
   `ingress_umem_ptr` for the predicate at dispatch.rs:442. v2
   signature passes both as raw pointers explicitly so the unsafe
   aliasing contract stays visible. See §"Concrete design — Phase 8
   helper signature".

### Other findings (revised but not blocking)

6. **AGY: consolidate 13 submodules → 4.** Accepted. v2 layout is
   exactly 4 submodules (plus `mod.rs`): `cos.rs`, `frame.rs`,
   `slow_path.rs`, `shared_recycle.rs`. See §"Layout v2".

7. **AGY: strict `#[inline(always)]` for hot, `#[cold]` or
   `#[inline(never)]` for cold.** Partially accepted. Hot-path
   helpers get `#[inline]` (NOT `#[inline(always)]` — Codex
   explicitly endorsed refusing `#[inline(always)]` on previously-
   unmarked items). Cold helpers (`handle_forward_build_failure`,
   the slow-path reinjection family) get `#[cold]` to advise LLVM
   to push them out of the hot i-cache footprint. This compromise
   satisfies both reviewers' framing without forcing always-inline.
   See §"Hot-path inlining strategy".

8. **Codex: perf framing is parity-required, not zero-expected.**
   Accepted. v2 §"Honest scope/value framing" now says **parity
   required** — any measurable delta is a regression and a re-spin
   trigger.

9. **Codex: `const _: () = assert!(...)` size guards need
   justification or removal.** Accepted — drop the size asserts.
   They are not pure code motion. If a follow-up wants struct-size
   guarding it can ship in a separate scoped PR.

10. **Codex: `pub(super)` for `extract_l3_packet` /
    `extract_l3_packet_from_frame` changes scope when moved into
    `dispatch/slow_path.rs`.** Accepted. They were `pub(super)`
    (visible to `tx/`) and must remain so. The move uses
    `pub(in crate::afxdp::tx)` on the new module so the sibling
    visibility is preserved. AGY independently flagged the same risk.

## Issue framing

`userspace-dp/src/afxdp/tx/dispatch.rs::enqueue_pending_forwards` is a
**845-LOC body** (function spans dispatch.rs:71-915, body proper at
dispatch.rs:91-914). The file overall is **1,474 LOC** — above the
1,000-LOC cue in `docs/engineering-style.md` and well past the
100-LOC per-function cue on the body.

It is the **single fan-in point** for every cross-binding forwarded
packet plus every same-binding hairpin in the userspace dataplane.

This PR finishes the long-standing TX dispatch decomposition track:
#1166 extracted TSO, #1591 split drain (`tx/drain/`), #1586/#1354
split transmit (`tx/transmit/`). This is the FINAL big-chunk in
`tx/`.

> Closes #1443. Refs #1016 (duplicate target — earlier issue covered
> the same modularization; #1016's outstanding half "decouple
> mutation from dispatch upstream" is explicitly deferred to #946 /
> #963 follow-ups).

## Honest scope/value framing

This is **pure code motion**. Zero algorithmic change. Zero new
allocations. **Byte-output parity is required** (anything else is a
regression and a re-spin trigger). Public-API parity is required
(36 external call sites, listed in §"`dispatch/mod.rs` re-export
contract").

The win is cohesion / reviewability / future-extension headroom (the
issue cites adding new encapsulation formats or policing actions as
the next-step motivation), and a possible — speculative — L1-i
cache footprint reduction from breaking the monolithic body into
`#[inline]` hot helpers + `#[cold]` exception helpers.

Absolute-scale expectation: **parity** on the loss-userspace cluster
smoke matrix. A measurable delta in either direction is a regression
to investigate before merge.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** Both round-1 reviewers
stopped short of PLAN-KILL; the counter-argument is that #1166,
#1354/#1586, #1591 all shipped on the same framing.

## What's already shipped / partially batched

- **#1166** (PR #1199, merged 2026-05-05): extracted TSO into
  `tx/tcp_segmentation.rs`. `enqueue_pending_forwards` calls back
  into it via `segment_forwarded_tcp_frames_into_prepared`.
- **#1591 (drain split)**: `tx/drain/{mod, phase_backup, phase_shaped,
  phase_trivial}.rs` with `DrainCtx<'a>` references-only context
  struct.
- **#1586 / #1354 (transmit split)**: `tx/transmit/{mod, stage,
  rewrite, verify, write, finalise}.rs`. Confirms the directory
  convention and the `pub(super)` visibility pattern.
- **#1187 BatchCounters disposition**: `DispositionCounters` Hot/Cold
  routes — the dispatch body now records 8+ disposition-keyed
  counters which the phase split must NOT collapse.

## Enumeration of phases in `enqueue_pending_forwards`

Walking dispatch.rs:91-914 as one `for request in
pending_forwards.iter_mut()` loop. 12 phases in execution order with
verified line ranges:

| # | Phase | Lines | Mutates |
|---|---|---|---|
| 0 | Loop precondition (snapshot `ingress_area` raw pointer at dispatch.rs:94, TX-selection toggles at dispatch.rs:95-96, clear `post_recycles` at dispatch.rs:97) | 91-97 | local |
| 1 | CoS TX-selection resolve | 102-117 | `request.cos_*` fields; ingress recycle on drop |
| 2 | Target binding resolution v1 | 118-125 | local |
| 3 | Prebuilt frame fast path (`PendingForwardFrame::Prebuilt`) | 129-168 | target binding TX pipeline + counters + ingress recycle |
| 4 | Source-frame extraction (Owned / Live / Prebuilt-unreachable) | 173-186 | none |
| 5 | Mirror-clone tap | 187-203 | mirror target bindings + ingress live counters |
| 6 | Target binding resolution v2 + fabric-redirect slow-path fallback | 206-270 | dbg counters + recent_exceptions + ingress recycle |
| 7 | TCP segmentation gate + dispatch (sets `copied_source_frame=true` on success) | 277-417 | target binding TX pipeline + counters + drain trigger |
| 8 | In-place vs direct-TX vs copy-fallback. **Four mid-body `continue` exits at dispatch.rs:544 / 562 / 822 / 840.** | 418-856 | target binding TX pipeline + counters + retained_source_frame |
| 9 | Per-iteration drain trigger | 858-869 | target binding |
| 10 | `apply_shared_recycles` drain of `post_recycles` | 871-880 | left / right binding slices |
| 11 | Build-failure handling (gated by `retained_source_frame`) | 881-904 | recent_exceptions + ingress recycle |
| 12 | Loop epilogue (`drain_pending_fill`, `update_binding_debug_state`, clear `pending_forwards`) | 906-914 | ingress binding |

### Pure-mutation vs dispatch-coupled

**Pure mutation** (could be hoisted upstream in a future PR per
#1016 — NOT in this PR):
- Phase 1 (CoS resolve) — mutates `request` fields only.
- Phase 7's `segment_forwarded_tcp_frames_from_frame` branch (dispatch.rs:320-388)
  builds `Vec<u8>` segments without touching UMEM.

**Dispatch-coupled** (must run inside the same `&mut BindingWorker`
borrow window): Phases 3, 5, 6, 7-prepared-branch, 8 entirely, 9,
10, 11.

**Scope decision:** keep dispatch-coupled phases physically local to
the orchestrator's loop body. Extract only the named helpers below.
No hoisting upstream of dispatch (that's #1016's deferred half).

## Layout v2 — four submodules + mod.rs

Mirror the `tx/drain/` and `tx/transmit/` precedent. Move
`tx/dispatch.rs` → `tx/dispatch/mod.rs` and split as follows:

```
userspace-dp/src/afxdp/tx/dispatch/
├── mod.rs                       — enqueue_pending_forwards orchestrator
│                                  loop body + re-export contract + the
│                                  #[path = "dispatch_tests.rs"] mod
│                                  declaration.
├── cos.rs                       — Phase 1 CoS TX-selection resolve and
│                                  the 4 COS fast-path helpers:
│                                    cos_queue_fast_path_for_request,
│                                    cos_owner_live_for_request,
│                                    request_uses_shared_exact_queue_lease,
│                                    enqueue_local_request_to_target_or_owner,
│                                    resolve_pending_forward_cos_tx_selection,
│                                    pending_forward_needs_cos_tx_selection.
├── frame.rs                     — Phase 3 (prebuilt fast path),
│                                  Phase 4 (source-frame extraction),
│                                  Phase 7 (TCP-seg dispatch glue),
│                                  Phase 8 (in-place + direct-TX +
│                                  copy-fallback, with Phase8Outcome enum),
│                                  inline predicates
│                                  (count_forwarded_tcp_segmentation_miss_if_needed,
│                                  forwarded_tcp_may_need_segmentation),
│                                  recycle_ingress_frame,
│                                  resolve_pending_forward_target_binding.
├── slow_path.rs                 — exception / reinjection / build-fail
│                                  cold path: handle_forward_build_failure,
│                                  maybe_reinject_slow_path,
│                                  maybe_reinject_slow_path_from_frame,
│                                  extract_l3_packet                 [pub(in crate::afxdp::tx)],
│                                  extract_l3_packet_from_frame      [pub(in crate::afxdp::tx)],
│                                  extract_l3_packet_with_nat.
│                                  All cold-path helpers marked #[cold].
└── shared_recycle.rs            — Phase 10 + cross-tick recycle
                                   routing: apply_shared_recycles,
                                   apply_shared_recycles_to_bindings,
                                   route_shared_recycle_by_slot,
                                   split_binding_slot_at,
                                   shared_recycle_target_index_for_split,
                                   shared_recycle_target_index,
                                   record_shared_recycle_unknown_slot_drops,
                                   log_shared_recycle_unknown_slot_drops,
                                   resolve_tx_binding_ifindex.
```

Plus the relocated test file:

```
└── dispatch_tests.rs            — moved from tx/dispatch_tests.rs;
                                   `#[path]` resolves relative to
                                   dispatch/mod.rs verbatim.
```

`mod.rs` declares `#[cfg(test)] #[path = "dispatch_tests.rs"] mod
tests;` — verified pattern with `tx/transmit/transmit_tests.rs`.

## `dispatch/mod.rs` re-export contract

The afxdp/mod.rs:140 glob `use self::tx::dispatch::*;` means **every**
`pub(in crate::afxdp)` symbol currently in dispatch.rs MUST be
visible at the `tx::dispatch::*` glob target after the split.

Verified list of preserved `pub(in crate::afxdp)` symbols (8 total):

- `enqueue_pending_forwards` (defined in `mod.rs`)
- `handle_forward_build_failure` (re-export from `slow_path.rs`)
- `apply_shared_recycles` (re-export from `shared_recycle.rs`)
- `apply_shared_recycles_to_bindings` (re-export from
  `shared_recycle.rs`)
- `resolve_tx_binding_ifindex` (re-export from `shared_recycle.rs`)
- `maybe_reinject_slow_path` (re-export from `slow_path.rs`)
- `maybe_reinject_slow_path_from_frame` (re-export from
  `slow_path.rs`)
- `extract_l3_packet_with_nat` (re-export from `slow_path.rs`)

Plus 2 `pub(super)` (visible to `tx/`) symbols promoted to
`pub(in crate::afxdp::tx)` on the new module: `extract_l3_packet`,
`extract_l3_packet_from_frame`.

Verbatim re-export block at the top of `dispatch/mod.rs`:

```rust
mod cos;
mod frame;
mod shared_recycle;
mod slow_path;

pub(in crate::afxdp) use shared_recycle::{
    apply_shared_recycles,
    apply_shared_recycles_to_bindings,
    resolve_tx_binding_ifindex,
};
pub(in crate::afxdp) use slow_path::{
    handle_forward_build_failure,
    maybe_reinject_slow_path,
    maybe_reinject_slow_path_from_frame,
    extract_l3_packet_with_nat,
};
pub(in crate::afxdp::tx) use slow_path::{
    extract_l3_packet,
    extract_l3_packet_from_frame,
};
```

This keeps afxdp/mod.rs:140 glob resolving to the same symbol set
with the same visibility. `tx/mod.rs` and `afxdp/mod.rs` are
**untouched** by this PR.

## Concrete design — Phase 8 helper signature

Phase 8 helper takes raw pointers explicitly so the aliasing contract
is visible at the call site. **`*const MmapArea` is NOT converted to
a safe `&MmapArea` in the orchestrator before passing in.** The
helper itself does the unsafe deref under a documented single-owner-
per-binding invariant. This addresses AGY blocking #1 and Codex
blocking #5.

```rust
// frame.rs
#[inline]
pub(super) fn try_inplace_rewrite_or_build(
    target_binding: &mut BindingWorker,
    // SAFETY contract: both pointers must outlive this call. They are
    // captured at dispatch/mod.rs (at the top of the loop) BEFORE the
    // per-iteration &mut reborrows. The hairpin / shared-UMEM case
    // (target_binding.umem.allocation_ptr() == ingress_umem_ptr) is
    // handled inside the helper — no safe &MmapArea alias is
    // constructed while target_binding: &mut BindingWorker is live.
    ingress_area: *const MmapArea,
    ingress_umem_ptr: *const u8,
    ingress_slot: u32,
    source_offset: u64,
    request: &mut PendingForwardRequest,
    flow_key: &mut Option<FlowKey>,
    expected_ports: Option<L4Ports>,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    post_recycles: &mut Vec<(u32, u64)>,
    dbg: &mut DebugPollCounters,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> Phase8Outcome;
```

### Phase 8 outcome enum

Addresses Codex blocking #2: every mid-body `continue` in current
code maps to a named outcome.

```rust
// frame.rs
pub(super) enum Phase8Outcome {
    /// In-place / direct-TX / copy-fallback succeeded.
    /// retained_source_frame=true iff in-place rewrite consumed the
    /// ingress UMEM slot.
    Wrote { retained_source_frame: bool },

    /// Oversized frame path at dispatch.rs:534-545 / 812-823. Current
    /// code recycles via push_front of the popped tx_offset then
    /// `continue`s, skipping Phases 9 + 10 + 11 entirely (no build
    /// failure, no shared-recycle, no ingress recycle).
    OversizedFrame,

    /// enqueue_local_request_to_target_or_owner returned Err at
    /// dispatch.rs:557-562 / 835-840. Current code sets
    /// build_failed=true + fallback_to_slow_path=true, then
    /// `continue`s, skipping Phase 9 + 10, then runs Phase 11.
    EnqueueFailed,

    /// build_forwarded_frame_* returned None on both direct-TX and
    /// the copy fallback. Current code sets build_failed +
    /// fallback_to_slow_path, falls through to Phase 11.
    BuildReturnedNone,
}
```

Orchestrator per-iteration body becomes:

```rust
match try_inplace_rewrite_or_build(...) {
    Phase8Outcome::Wrote { retained_source_frame: r } => {
        retained_source_frame = r;
        // Fall through to Phases 9 + 10 + 11(no-fail)
    }
    Phase8Outcome::OversizedFrame => {
        continue; // matches current dispatch.rs:544 / 822 behaviour
    }
    Phase8Outcome::EnqueueFailed | Phase8Outcome::BuildReturnedNone => {
        // Match current dispatch.rs:881-900: skip 9+10, run Phase 11.
        handle_forward_build_failure(..., fallback_to_slow_path: true, ...);
        if !retained_source_frame {
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
        }
        continue;
    }
}
```

Reviewers — please verify against current dispatch.rs:534-905 that
this outcome matrix preserves every disposition.

### Phase-helper visibility

Every helper in `cos.rs`, `frame.rs`, `slow_path.rs`,
`shared_recycle.rs` that is called only from `dispatch/mod.rs` is
`pub(super)`. The visibility-leak risk is contained to the
`dispatch/` directory.

## Hot-path inlining strategy

`#[inline]` is a hint, not a guarantee. Per Codex round-1: refusing
`#[inline(always)]` on previously-unmarked items is correct. Per AGY
round-1: hot vs cold segregation is mandatory for the inline budget.
v2 compromise:

| File / helper | Marker | Rationale |
|---|---|---|
| `cos.rs` per-request helpers | `#[inline]` | Per-request hot; one caller |
| `frame.rs::try_inplace_rewrite_or_build` | `#[inline]` | Per-request hot; one caller; large body but one caller → release-build inlining reliable |
| `frame.rs::try_handle_prebuilt_frame` | `#[inline]` | Per-request; cold-ish (only ICMP error NAT reversal) |
| `frame.rs::forwarded_tcp_may_need_segmentation` | `#[inline(always)]` | Already is at dispatch.rs:1438; preserve verbatim |
| `frame.rs::count_forwarded_tcp_segmentation_miss_if_needed` | `#[inline(always)]` | Already is at dispatch.rs:1425; preserve verbatim |
| `frame.rs::recycle_ingress_frame` | `#[inline]` | Already is at dispatch.rs:60; preserve verbatim |
| `slow_path.rs::handle_forward_build_failure` | `#[cold]` | Build-failure path |
| `slow_path.rs::maybe_reinject_slow_path` | `#[cold]` | Reinjection path |
| `slow_path.rs::maybe_reinject_slow_path_from_frame` | `#[cold]` | Reinjection path |
| `slow_path.rs::extract_l3_packet*` | (no marker) | Called by both hot and cold paths; let LLVM decide |
| `shared_recycle.rs::apply_shared_recycles` | (no marker) | Called per-iteration but loops over `post_recycles` — let LLVM see the body |
| `shared_recycle.rs::resolve_tx_binding_ifindex` | (no marker) | 16+ external call sites; over-marking would conflict |

**No `#[inline(always)]` added** to anything that isn't already
`#[inline(always)]`. **`#[cold]` added** to the slow-path / build-
failure helpers — pushes them out of the hot i-cache footprint
without forcing inline on the hot helpers.

## Hidden invariants the change must preserve

Updated to reflect Codex round-1 findings:

1. **Cross-worker MPSC ordering.**
   `enqueue_local_request_to_target_or_owner` on the COS-shared
   path enqueues via `owner_live.enqueue_tx_owned(req)` — a
   `crossbeam::channel::Sender`. HA session-sync semantics rely on
   per-flow forwarding-order preservation. v2 keeps the iteration
   body linear — no reordering, no batching across iterations.
   Codex round-1: "no-batching claim is sufficient."

2. **`ingress_area` raw pointer lifetime.** dispatch.rs:94 captures
   `let ingress_area = ingress_binding.umem.area() as *const MmapArea`
   BEFORE inner `&mut ingress_binding` reborrows. v2 Phase 8 helper
   takes `*const MmapArea` directly (not a derived `&MmapArea`) —
   addresses AGY blocking #1.

3. **Recycle/retain bookkeeping (CORRECTED from v1):**
   - `copied_source_frame: bool` — set ONLY by TCP-segmentation paths
     at dispatch.rs:309 and dispatch.rs:376. Used at dispatch.rs:418
     to skip Phase 8 entirely. Used at dispatch.rs:431 for seg-miss
     accounting. Does NOT drive the final ingress recycle.
   - `retained_source_frame: bool` — set ONLY by the in-place rewrite
     branch at dispatch.rs:487. Used at dispatch.rs:897 and
     dispatch.rs:902 to skip the final ingress recycle.
   v2 keeps both flags in the orchestrator's stack frame; Phase 8
   helper returns `retained_source_frame` through
   `Phase8Outcome::Wrote { retained_source_frame }`.

4. **`post_recycles` lifecycle.** Per-call `Vec<(u32, u64)>` cleared
   at dispatch.rs:97, drained per-iteration at dispatch.rs:871-880
   via `apply_shared_recycles(left, …)`. Phase 10 MUST stay per-
   iteration — delaying lets prepared TX queues grow unbounded.

5. **`SEG_MISS_LOG` thread-local cap.** dispatch.rs:395-417 cap at
   20 with `cfg!(feature = "debug-log")` gating. v2 moves the
   thread-local into `frame.rs` but preserves the cap verbatim.

6. **`bound_pending_tx_*` push-back pairing.** Every push into
   `target_binding.tx_pipeline.pending_tx_local` MUST be followed by
   `bound_pending_tx_local(target_binding)`. Every push into
   `pending_tx_prepared` MUST be followed by
   `bound_pending_tx_prepared(target_binding, Some(post_recycles))`.

7. **`dbg.tx_max_frame` is a max-tracker, `dbg.tx_bytes_total` is a
   sum.** Verified across all 8 update sites (dispatch.rs:163-165,
   305-308, 371-374, 483-486, 567-570, 728-731, 845-848).

8. **Byte-output equivalence.** Builders unchanged:
   `build_forwarded_frame_*`, `rewrite_forwarded_frame_in_place`,
   `segment_forwarded_tcp_frames_*`.

9. **Phase 8 four `continue` paths.** dispatch.rs:544 / 562 / 822 /
   840 — each maps to a named `Phase8Outcome` variant.

10. **`#[path = "dispatch_tests.rs"]` resolution.** v2 moves the
    test file to `dispatch/dispatch_tests.rs`; `#[path]` resolves
    relative to `dispatch/mod.rs`. Verified pattern with
    `tx/transmit/transmit_tests.rs`.

11. **afxdp/mod.rs:140 glob.** `use self::tx::dispatch::*;` resolves
    to the same 8 `pub(in crate::afxdp)` symbols verbatim via the
    re-export block in `dispatch/mod.rs`.

## Risk assessment

| Class | Level | Mitigation |
|---|---|---|
| Behavioral regression | MED | Pure code motion + identical builder calls + `Phase8Outcome`-typed continue paths preserve every disposition. 15 named tests in `dispatch_tests.rs` + smoke at batch-merge end. |
| Lifetime / borrow-checker / aliasing UB | MED-HIGH | v1 signature rejected by both reviewers. v2 passes `*const MmapArea` + `ingress_umem_ptr` raw pointers explicitly. Unsafe contract documented at the helper. PLAN-KILL acceptable if reviewers see an unavoidable alias path. |
| Performance regression | LOW | `#[inline]` on per-request hot helpers + `#[cold]` on exception helpers. No new allocations. Smoke catches >2% delta. |
| Architectural mismatch | LOW | #1166, #1354/#1586, #1591 all shipped the pattern. #1016 explicitly defers the upstream-of-dispatch decouple. |
| Test-load break | LOW | v2 moves `dispatch_tests.rs` into `dispatch/` with updated `#[path]`. Verified pattern. |
| afxdp/mod.rs:140 glob break | LOW | v2 `dispatch/mod.rs` re-export block lists every symbol verbatim. |

## Test plan

1. `cargo build --release` clean (TMPDIR=/dev/shm
   CARGO_TARGET_DIR=/dev/shm/cargo).
2. `cargo test --release` — ~952 cargo tests across userspace-dp.
3. 5× flake on
   `enqueue_pending_forwards_mirrors_live_frame_and_records_counter`.
4. 5× flake on a representative direct-TX test.
5. Go `make test` — ~880 tests across 30 packages.
6. **No per-PR smoke** per Wave-5. PR posts
   `<!-- AWAITING-BATCH-MERGE -->` after 4-of-4 attestation.

## Out of scope (explicitly)

- Decoupling mutation from dispatch upstream (#1016's deferred half).
- Per-class CoS smoke (Wave-5 defers).
- Renaming `enqueue_pending_forwards` (36 external call sites).
- Removing `extract_l3_packet` (#[allow(dead_code)] removal — separate PR).
- `const _: () = assert!(...)` size guards (dropped per Codex round-1 #5).
- Hoisting `dbg.*` field updates into a struct (#1187-style refactor).

## Open questions for adversarial review v2

1. **Is `Phase8Outcome` complete?** Reviewers — re-walk
   dispatch.rs:534-580 and dispatch.rs:812-855. Does any branch
   miss the four variants?

2. **`#[cold]` vs `#[inline(never)]` on slow-path family.** v2
   picks `#[cold]`. Reviewers — does that match LLVM's hot-path
   guidance for this codebase?

3. **Is co-locating `resolve_tx_binding_ifindex` with the slot-
   resolution helpers in `shared_recycle.rs` cohesive, or should it
   live in a new `binding_resolve.rs`?**

4. **Phase 8 raw-pointer aliasing — does v2 thread the safety
   contract correctly?** Reviewers must walk the helper body before
   PLAN-READY.

5. **PLAN-KILL escape hatch (preserved from v1).** If `enqueue_pending_forwards`
   at 845 LOC is already as modular as it needs to be, PLAN-KILL is
   acceptable. Both round-1 reviewers stopped short of PLAN-KILL.
