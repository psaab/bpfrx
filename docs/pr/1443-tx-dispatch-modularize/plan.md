# #1443 — `tx/dispatch.rs::enqueue_pending_forwards` modular phase split

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY in parallel).

This PR finishes the long-standing TX dispatch decomposition track. #1166
extracted TSO out of dispatch into `tx/tcp_segmentation.rs`; #1591 split
drain (`tx/drain/`); #1586 (a.k.a. #1354) split transmit (`tx/transmit/`).
This is the FINAL big-chunk left in `tx/`: a 845-LOC body inside
`enqueue_pending_forwards` (function spans dispatch.rs:71-915, body
proper at lines 91-914) that mixes COS TX-selection resolution, target
binding resolution, TCP segmentation, in-place rewrite, direct-TX build,
copy-fallback build, drain triggers, exception reporting, and recycle
bookkeeping.

`tx/dispatch.rs` is 1,474 LOC total — already over the 1,000-LOC cue in
`docs/engineering-style.md` and well past the 100-LOC per-function cue
on the body of `enqueue_pending_forwards` itself. It is also the
highest-traffic hot path in the helper (every cross-binding forwarded
packet plus every same-binding hairpin walks this function).

> Closes #1443. Refs #1016 (duplicate target — earlier issue covered the
> same modularization; verify auto-close keyword in PR body).

## Honest scope/value framing

This is **pure code motion**. There is no algorithmic change, no
performance hypothesis being tested, no new data structure. The win is
cohesion / reviewability / future-extension headroom (the issue cites
adding new encapsulation formats or policing actions as the next-step
motivation), and a modest register-pressure reduction from breaking the
monolithic body into `#[inline]` phase helpers — the compiler can spill
phase-locals more tightly when each helper's live set is bounded.

Absolute-scale expectation: zero measurable throughput delta on the
loss-userspace cluster smoke. The whole point of the structural risk
table below is to enforce byte-output equivalence and ordering
preservation, so a measurable delta would be a regression, not a win.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** The structural / hot-path
risk on this file is real (#1183 caught a 10× regression in a
neighbouring CoS-state initialiser), and the existing code is correct.
Burning two review cycles on cosmetics is not free.

The counter-argument: #1166, #1354/#1586, and #1591 all shipped on the
same "cohesion + future headroom" framing. Closing the final TX
dispatch chunk completes the structural decomposition #946 Phase 1
started.

## What's already shipped / partially batched

- **#1166** (PR #1199, merged 2026-05-05): extracted
  `segment_forwarded_tcp_frames_into_prepared` (TSO) into
  `tx/tcp_segmentation.rs`. `enqueue_pending_forwards` calls back into
  it; the helper module is the destination of *frame* writes for
  segmented TCP.
- **#1591 (drain split)**: `tx/drain/{mod, phase_backup, phase_shaped,
  phase_trivial}.rs` with `DrainCtx<'a>` references-only struct. Sets
  the pattern for "per-tick context built once on stack, references-
  only, zero new allocations" that we will mirror for dispatch.
- **#1586 / #1354 (transmit split)**: `tx/transmit/{mod, stage, rewrite,
  verify, write, finalise}.rs`. Confirms the `module/foo.rs` directory
  convention and that `pub(super)` helpers stay private to the parent.
- **#1187 BatchCounters disposition**: `DispositionCounters` Hot/Cold
  routes were added; the dispatch body now records 8+ disposition-keyed
  counters. The phase split must NOT collapse any of them.

## Enumeration of phases in `enqueue_pending_forwards`

Walking dispatch.rs:91-914, the body is one `for request in
pending_forwards.iter_mut()` loop. The per-request work is staged.
Listed in execution order with line ranges and the exact mutation
surface each touches:

| # | Phase | Lines | Mutates |
|---|---|---|---|
| 0 | **Loop precondition** (early-out on empty, snapshot `ingress_area` pointer, snapshot TX-selection toggles, clear `post_recycles`) | 91-97 | local |
| 1 | **CoS TX-selection resolve** (`pending_forward_needs_cos_tx_selection` + `resolve_pending_forward_cos_tx_selection` + drop-on-cos-drop + write back into `request`) | 102-117 | `request.cos_queue_id`, `request.dscp_rewrite`, `request.cos_tx_selection_resolved`; ingress recycle on drop |
| 2 | **Target binding resolution v1** (compute `target_binding_index` from `request.target_binding_index` or `binding_lookup.target_index(...)`) | 118-125 | local |
| 3 | **Prebuilt frame fast path** (PendingForwardFrame::Prebuilt → resolve target, build `TxRequest` with `core::mem::take(prebuilt)`, enqueue local, bump counters, recycle ingress) | 129-168 | target_binding TX pipeline + counters + ingress recycle |
| 4 | **Source-frame extraction** (Owned: `frame.as_slice()`; Live: `(*ingress_area).slice(addr,len)` — depends on raw pointer captured before any `&mut` reborrow; Prebuilt → unreachable) | 173-186 | none (read-only) |
| 5 | **Mirror-clone tap** (`enqueue_sampled_mirror_clone` + `record_mirror_clone_result`) | 187-203 | mirror target bindings + ingress live counters |
| 6 | **Target binding resolution v2 + fabric-redirect fallback to slow path** (resolve target binding; on miss: either slow-path-from-frame for Owned or slow-path-from-area-desc for Live in FabricRedirect case, else `no_egress_binding` exception path) | 206-270 | dbg counters + recent_exceptions + ingress recycle |
| 7 | **TCP segmentation gate + dispatch** (`forwarded_tcp_may_need_segmentation` → try `segment_forwarded_tcp_frames_into_prepared` into prepared queue; on None try `segment_forwarded_tcp_frames_from_frame` for per-segment local queue path with `forward_tuple_mismatch_reason` diag; either path sets `copied_source_frame=true`; counts seg miss via `count_forwarded_tcp_segmentation_miss_if_needed`) | 277-417 | target binding TX pipeline (prepared / local) + counters + drain trigger |
| 8 | **In-place rewrite vs direct-TX vs copy-fallback decision** (`can_rewrite_in_place` predicate guarding shared-UMEM rewrite via `rewrite_forwarded_frame_in_place`; on None falls back to copy path; otherwise direct-TX build via `build_forwarded_frame_into_from_frame` into `free_tx_frames`-popped UMEM offset; on direct-TX fallback runs Vec-copy build via `build_forwarded_frame_from_frame` / `build_nat64_forwarded_frame`) | 418-856 | target binding TX pipeline (prepared / local / free_tx_frames) + tx_counters + recent_exceptions + retained_source_frame flag |
| 9 | **Per-iteration drain trigger** (`pending_tx_prepared.len() >= TX_BATCH_SIZE || pending_tx_local.len() >= TX_BATCH_SIZE` → `drain_pending_tx_local_owner`) | 858-869 | target binding |
| 10 | **Shared-recycle apply** (`apply_shared_recycles` drains `post_recycles` if non-empty) | 871-880 | left / right binding slices |
| 11 | **Build-failure handling** (`handle_forward_build_failure` + optional ingress recycle, gated by `retained_source_frame`) | 881-904 | recent_exceptions + ingress recycle |
| 12 | **Loop epilogue** (drain remaining `pending_fill_frames` on ingress, `update_binding_debug_state`, `pending_forwards.clear()`) | 906-914 | ingress binding |

Phases that are **pure mutation** (can be hoisted upstream of dispatch
later, per #1016 design question — but **NOT** in this PR):

- Phase 1 (CoS TX-selection resolve) — reads forwarding state, mutates
  `request` fields only. The only side-effect-with-borrows piece is the
  drop branch that recycles the ingress frame; the recycle is a
  function of `request.desc.addr` so even that piece could be hoisted.
- Phase 7's `segment_forwarded_tcp_frames_from_frame` builder branch
  (lines 320-388) constructs `Vec<u8>` segments without touching UMEM —
  pure mutation, only the push-back into `target_binding.tx_pipeline.
  pending_tx_local` is dispatch-coupled.

Phases that are **dispatch-coupled** (must run inside the same
`&mut BindingWorker` borrow window):

- Phase 3 (prebuilt enqueue), Phase 5 (mirror tap), Phase 6 (target
  binding resolution + fabric fallback), Phase 7's prepared-queue path,
  Phase 8 entirely (touches `free_tx_frames`, `pending_tx_prepared`,
  `pending_tx_local`, `tx_counters` on the target binding), Phase 9
  (drain trigger), Phase 10 (shared-recycle across `left`/`right`),
  Phase 11 (build-fail recycle).

**Scope decision: this PR keeps the dispatch-coupled phases physically
local to the new orchestrator and only extracts helpers that take
borrows or move payloads through them.** No hoisting upstream of
dispatch — that's a future PR gated on either #946 pipeline staging
or #963 PacketEditor (and explicitly out of scope, per #1016's status
note).

## Concrete design

### Layout: `tx/dispatch/{mod,…}.rs`

Mirror the `tx/drain/` and `tx/transmit/` layout pattern. Move
`tx/dispatch.rs` to `tx/dispatch/mod.rs` and split as follows. (Module
visibility is `pub(super)` for new helpers; `pub(in crate::afxdp)`
preserved verbatim on existing items with external callers per the
audit below.)

```
userspace-dp/src/afxdp/tx/dispatch/
├── mod.rs                       — `enqueue_pending_forwards` orchestrator
│                                  loop body + glue; re-exports preserved
│                                  pub(in crate::afxdp) helpers verbatim
├── cos_resolve.rs               — Phase 1 (CoS TX-selection resolve)
│                                  + `cos_queue_fast_path_for_request`,
│                                    `cos_owner_live_for_request`,
│                                    `request_uses_shared_exact_queue_lease`,
│                                    `enqueue_local_request_to_target_or_owner`,
│                                    `resolve_pending_forward_cos_tx_selection`,
│                                    `pending_forward_needs_cos_tx_selection`
├── target_binding.rs            — Phases 2 + 6 target binding resolve;
│                                  `resolve_pending_forward_target_binding`
├── prebuilt.rs                  — Phase 3 prebuilt-frame fast path
├── mirror_tap.rs                — Phase 5 sampled mirror clone glue
│                                  (thin wrapper — the heavy lifting is
│                                  already in `mirror::*`)
├── source_frame.rs              — Phase 4 source-frame extraction
│                                  (Owned/Live/Prebuilt match; returns
│                                  Option<&[u8]> from the captured
│                                  ingress_area ptr)
├── tcp_seg_dispatch.rs          — Phase 7 TCP segmentation gate + both
│                                  prepared and per-segment local
│                                  branches; calls back into
│                                  `tx/tcp_segmentation.rs` for the
│                                  actual segment builders (extracted
│                                  by #1166)
├── inplace_rewrite.rs           — Phase 8 in-place rewrite branch
│                                  (the can_rewrite_in_place predicate
│                                  + rewrite_forwarded_frame_in_place
│                                  wiring + counter updates)
├── direct_tx.rs                 — Phase 8 direct-TX build branch
│                                  (free_tx_frame popping, prefetch,
│                                  `build_forwarded_frame_into_from_frame`
│                                  wiring, fallback-reason counters,
│                                  copy-fallback branch via
│                                  `build_forwarded_frame_from_frame` /
│                                  `build_nat64_forwarded_frame`)
├── drain_trigger.rs             — Phase 9 (small — one inline helper)
├── shared_recycle.rs            — Phase 10 + `apply_shared_recycles`,
│                                  `apply_shared_recycles_to_bindings`,
│                                  `route_shared_recycle_by_slot`,
│                                  `split_binding_slot_at`,
│                                  `shared_recycle_target_index_for_split`,
│                                  `shared_recycle_target_index`,
│                                  `record_shared_recycle_unknown_slot_drops`,
│                                  `log_shared_recycle_unknown_slot_drops`
├── build_failure.rs             — Phase 11 `handle_forward_build_failure`
├── slow_path.rs                 — `maybe_reinject_slow_path`,
│                                  `maybe_reinject_slow_path_from_frame`,
│                                  `extract_l3_packet`,
│                                  `extract_l3_packet_from_frame`,
│                                  `extract_l3_packet_with_nat`,
│                                  `resolve_tx_binding_ifindex` (used
│                                  pervasively outside dispatch — must
│                                  stay re-exported)
└── seg_predicate.rs             — Phase 7 inline predicates:
                                   `count_forwarded_tcp_segmentation_miss_if_needed`,
                                   `forwarded_tcp_may_need_segmentation`
```

`mod.rs` re-exports verbatim every existing `pub(in crate::afxdp)`
symbol so external callers (39 grep hits across `neighbor_dispatch`,
`forward_request`, `poll_stages`, `mirror`, `worker`, `coordinator`,
`session_glue`, `session_delta`, `poll_descriptor`, `forwarding/tests`,
`worker/loop_body`, `frame/tests`, `tests.rs`) see no API surface
change.

### Phase-helper signatures (sketch)

Every phase helper is `#[inline]` and takes references / mutable
references rather than owning values. **Zero new heap allocations.**
No `Vec`, no `Box`, no `String` formatting on the hot path.

```rust
// dispatch/cos_resolve.rs
#[inline]
pub(super) fn maybe_resolve_cos_tx_selection(
    request: &mut PendingForwardRequest,
    forwarding: &ForwardingState,
    ingress_binding: &mut BindingWorker,
    tx_selection_enabled_v4: bool,
    tx_selection_enabled_v6: bool,
    source_offset: u64,
    now_ns: u64,
) -> ControlFlow<()>;
// ControlFlow::Break(()) == drop + ingress-recycle done; orchestrator continues.

// dispatch/prebuilt.rs
#[inline]
pub(super) fn try_handle_prebuilt_frame<'a>(
    request: &mut PendingForwardRequest,
    left: &'a mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &'a mut BindingWorker,
    right: &'a mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    target_binding_index: Option<usize>,
    source_offset: u64,
    now_ns: u64,
    dbg: &mut DebugPollCounters,
) -> Option<ControlFlow<()>>;
// Some(Break) == handled (prebuilt path consumed); None == not prebuilt, fall through.

// dispatch/inplace_rewrite.rs
#[inline]
pub(super) fn try_inplace_rewrite(
    target_binding: &mut BindingWorker,
    ingress_area: &MmapArea,
    ingress_slot: u32,
    source_offset: u64,
    request: &mut PendingForwardRequest,
    flow_key: &mut Option<FlowKey>,
    expected_ports: Option<L4Ports>,
    post_recycles: &mut Vec<(u32, u64)>,
    dbg: &mut DebugPollCounters,
) -> InPlaceResult;
// enum InPlaceResult { Done { retained_source_frame: true }, NoneFromRewrite, Skipped }
```

The orchestrator `mod.rs` body becomes a flat `for` loop calling the
helpers in execution order. Estimated `enqueue_pending_forwards` body
size after split: **~120-150 LOC** (within the 100-LOC cue and just
above it — acceptable for an orchestrator that explicitly lists all
phases).

### Why `ControlFlow<()>` instead of `Result<(), ()>`

`std::ops::ControlFlow` is the right type for "continue the loop / go
back to the top". It documents the early-out intent and lets each
phase document its own break semantics. `Result<(), ()>` would
overload `Err` with no payload. (Tested in #1591 drain split — Codex
asked for the same idiom there.)

### Hot-path inlining strategy per phase

| Phase | Helper count | Inline marker | Rationale |
|---|---|---|---|
| 1 CoS resolve | 1 outer + 2 inner | `#[inline]` on all | Per-request, must collapse into orchestrator |
| 2/6 target resolve | 2 (v1 lookup + v2 resolve) | `#[inline]` | Per-request |
| 3 prebuilt | 1 | `#[inline]` | Cold-ish (only ICMP error NAT reversal); inline-ok but not `#[inline(always)]` |
| 4 source-frame extract | 1 | `#[inline]` | Per-request |
| 5 mirror tap | already in mirror.rs | (no change) | Sampled — heavy lifting elsewhere |
| 7 TCP seg dispatch | 1 outer | `#[inline]` | Per-request; gates on protocol/mtu |
| 7 seg predicates | 2 | `#[inline(always)]` | Already are; preserve verbatim |
| 8 in-place | 1 outer + 1 predicate (`can_rewrite_in_place`) | `#[inline]` outer, `#[inline(always)]` predicate | Per-request hot decision |
| 8 direct-TX | 1 outer + 1 fallback-reason classifier | `#[inline]` outer | Per-request; ~200 LOC body — inline keeps it folded |
| 9 drain trigger | (inlined into orchestrator) | n/a | Two-line `if` |
| 10 shared-recycle | already `pub(in crate::afxdp)` | preserve | Not per-request hot |
| 11 build-failure | already `pub(in crate::afxdp)` | preserve | Cold |

**No `#[inline(always)]` is added** to anything that is not already
`#[inline(always)]`. `#[inline]` is a hint, not a guarantee — release
builds will inline these naturally because they have one caller each.
Forcing `inline(always)` on cold paths (build-failure, prebuilt) would
bloat the i-cache footprint of `enqueue_pending_forwards` and defeat
the point.

### Compile-time invariants

Add `const _: () = assert!(...)` near each helper that depends on a
struct layout being one specific size (e.g. `PendingForwardRequest`
size, `TxRequest` size). The #1183 incident showed a config-shape
change in CoSState can 10× a hot path; we want a build-break, not a
benchmark, when one of these types grows.

The full assertion list lands in `dispatch/mod.rs` after the helpers
are imported. (One assert per struct, not per phase — keep them
discoverable.)

## Public API preservation

The full list of preserved `pub(in crate::afxdp)` exports from
`tx/dispatch.rs` (verified by grep across the workspace, 39 external
hits):

- `enqueue_pending_forwards` (the orchestrator itself — single caller
  in `worker/lifecycle.rs:241`)
- `handle_forward_build_failure` (4 external callers: tests + 1 prod)
- `apply_shared_recycles` (4 callers: `neighbor_dispatch`, `worker/
  lifecycle` ×3)
- `apply_shared_recycles_to_bindings` (5 callers: `session_delta`,
  `worker/loop_body` ×3, one more in `worker/loop_body`)
- `resolve_tx_binding_ifindex` (16+ callers across `neighbor_dispatch`,
  `forward_request`, `mirror`, `worker/cos`, `session_glue`,
  `coordinator`, `worker`, `poll_descriptor`, `poll_descriptor/
  flow_cache_hit`, `forwarding/tests`)
- `maybe_reinject_slow_path` (3 callers: `tests.rs` ×2,
  `poll_descriptor`)
- `maybe_reinject_slow_path_from_frame` (3 callers: `poll_stages`,
  `tests.rs`, `poll_descriptor`)
- `extract_l3_packet_with_nat` (2 test callers; also internal to
  `maybe_reinject_slow_path_from_frame`)

`extract_l3_packet` and `extract_l3_packet_from_frame` are
`pub(super)` only — they stay `pub(super)` (i.e.
`pub(in crate::afxdp::tx)`) on the new module.

`tx/mod.rs` already re-exports nothing from `dispatch` (callers reach
in via the longer `tx::dispatch::*` or via the explicit per-crate
`pub(in crate::afxdp)` visibility). **`tx/mod.rs` is untouched by
this PR.**

## Hidden invariants the change must preserve

1. **Cross-worker MPSC ordering.** `enqueue_local_request_to_target_or_owner`
   on the COS-shared path enqueues via `owner_live.enqueue_tx_owned(req)`
   into a `crossbeam::channel::Sender`. HA session-sync semantics rely
   on the *enqueue order* matching the per-flow forwarding order. The
   per-request loop is single-writer (single owner worker), so order is
   preserved as long as we don't (a) batch requests across iterations,
   (b) reorder phase 1 vs phase 7-8 within an iteration, or (c) move
   the CoS-fast-path-vs-owner-redirect decision earlier than the
   target-binding resolve. **The phase split keeps the iteration body
   linear — no reordering, no batching across iterations.**

2. **`ingress_area` raw pointer lifetime.** Line 94 captures
   `let ingress_area = ingress_binding.umem.area() as *const MmapArea`
   BEFORE the inner `&mut ingress_binding` reborrows happen
   (`recycle_ingress_frame`, mirror-clone, etc.). All `unsafe { &*ingress_area }`
   dereferences inside the loop are gated on the invariant that no
   other thread can unmap the UMEM (single owner per binding). Each
   phase helper that reads the source frame via `Live` must take
   `*const MmapArea` (or `&MmapArea` derived from the captured
   pointer at the top of the helper) — **NOT** re-derive it from
   `ingress_binding.umem.area()` inside the helper, because the helper
   may already have a `&mut BindingWorker` parameter and that reborrow
   would alias.

3. **Recycle/retain bookkeeping.** Two flags drive ingress-frame
   recycle on loop exit:
   - `copied_source_frame: bool` — set when the source frame was
     consumed by a builder (TCP seg, copy-fallback, direct-TX); ingress
     frame is no longer needed.
   - `retained_source_frame: bool` — set when the in-place rewrite
     consumed the *ingress UMEM slot itself* (it's now sitting in
     `target_binding.tx_pipeline.pending_tx_prepared` with a
     `FillOnSlot` recycle policy); ingress must NOT be recycled
     because the prepared TX entry owns that offset.
   Phase 8 sets `retained_source_frame=true` exclusively. Phase 11
   guards its recycle on `!retained_source_frame`. **The phase split
   must keep these flags local to the orchestrator** — passing them
   through return values from phase helpers is fine; lifting them into
   a struct field on `BindingWorker` is NOT (it would create a
   between-iteration bleed).

4. **`post_recycles` lifecycle.** `post_recycles` is the per-call
   `Vec<(u32, u64)>` that captures cross-binding fill recycles
   generated by the in-place / TCP-seg / drain paths. It's cleared at
   the top of the call (line 97), drained inside each iteration via
   `apply_shared_recycles(left, …)` (lines 871-880), and re-drained
   from the next iteration. Phase 10 (`apply_shared_recycles`) MUST
   stay per-iteration, not lifted out to once-per-call: otherwise
   recycles from iteration N could be applied with the wrong
   `left/right` binding view (the orchestrator never splits during the
   loop, but `apply_shared_recycles` is the only place that resolves
   `(slot, offset)` → target binding via `binding_lookup`, and
   delaying it would let prepared TX queues grow unbounded between
   iterations).

5. **No `slog::Info` inside per-packet loops.** The current code uses
   `eprintln!` gated on `cfg!(feature = "debug-log")` and gated again
   on a thread-local counter capped at 20. The phase split must
   preserve these caps verbatim — moving the `SEG_MISS_LOG` thread-
   local into a helper module is fine as long as the cap is preserved.

6. **`bound_pending_tx_*` calls are not lost.** Every push-back into
   `target_binding.tx_pipeline.pending_tx_local` or `pending_tx_prepared`
   in the current body is followed by a `bound_pending_tx_local(...)`
   or `bound_pending_tx_prepared(target_binding, Some(post_recycles))`
   call. The phase split MUST preserve every one — failing to call the
   bound helper after push_back lets the FIFO overflow without the
   `pending_tx_local_overflow_drops` counter ticking.

7. **`dbg.tx_max_frame` is a `u32` max-tracker, not a sum.** Every
   per-iteration update is `if frame_len > dbg.tx_max_frame { dbg.tx_max_frame = frame_len }`.
   Don't accidentally turn it into a sum during the split. Same goes
   for `dbg.tx_bytes_total` — that one IS a sum; don't accidentally
   turn it into a max.

8. **Byte-output equivalence.** No phase helper changes the bytes
   written into `target_binding.umem` or into a `Vec<u8>` `TxRequest`.
   The builders (`build_forwarded_frame_*`, `rewrite_forwarded_frame_in_place`,
   `segment_forwarded_tcp_frames_*`) are unchanged. The only thing we
   are moving is the *control flow* that selects which builder runs.

## Risk assessment

| Class | Level | Mitigation |
|---|---|---|
| Behavioral regression | MED | Pure code motion + identical builder calls + ControlFlow-typed early-outs. Catch via byte-output snapshot tests at the dispatch_tests level + the existing 60+ named tests in `dispatch_tests.rs`. Smoke matrix on loss-userspace cluster catches dynamic regressions. (No per-PR smoke per Wave-5; smoke runs at batch-merge time per `<!-- AWAITING-BATCH-MERGE -->`.) |
| Lifetime / borrow-checker | MED-HIGH | Phase 8 has the trickiest borrow shape (mut ingress_binding + mut target_binding + mut post_recycles + immut ingress_area*). The `ingress_area as *const MmapArea` raw-pointer dance must transfer cleanly to the helper module. If the borrow checker fights the proposed signatures, the orchestrator inlines that phase rather than extracting it — i.e. we may end up with 9 helpers instead of 10, and call that good. PLAN-KILL is acceptable if reviewers can show the borrow shape forces a `_ = unsafe` lifetime extension. |
| Performance regression | LOW | `#[inline]` on every per-request helper + each helper has exactly one caller → release-build inlining is reliable. No new allocations. Compile-time struct-size asserts catch silent struct growth. Smoke matrix would catch >2% throughput delta. |
| Architectural mismatch | LOW | #1166, #1354/#1586, #1591 all shipped on the same pattern. `tx/transmit/` and `tx/drain/` are the templates. The issue body for #1443 itself proposes this decomposition. #1016 explicitly defers "decouple mutation from dispatch" to a separate PR gated on #946/#963 — this PR honours that boundary. |

## Test plan

1. `cargo build` clean (release).
2. Full `cargo test --release` — current baseline ~952 tests across
   the userspace-dp crate must remain green.
3. 5× flake check on
   `enqueue_pending_forwards_mirrors_live_frame_and_records_counter`
   plus 5× flake check on a representative direct-TX test (TBD —
   pick from `dispatch_tests.rs`).
4. Go test suite (`make test`) — 30 packages.
5. **Deploy to loss-userspace cluster is OUT OF SCOPE per Wave-5
   rules.** This PR posts `<!-- AWAITING-BATCH-MERGE -->` after 4-of-4
   review attestation; a single comprehensive smoke runs at batch
   end-of-wave.
6. (Local-only verification) `cargo bench` if a TX-dispatch bench
   exists; otherwise skip. The performance hypothesis is no-delta; if
   a measurable delta surfaces, the PR is broken regardless of sign.

Compile-time invariants asserted in the new `mod.rs`:

```rust
const _: () = assert!(core::mem::size_of::<PendingForwardRequest>() <= 256);
const _: () = assert!(core::mem::size_of::<TxRequest>() <= 256);
const _: () = assert!(core::mem::size_of::<PreparedTxRequest>() <= 128);
```

(Exact bounds TBD — read the current sizes first and assert at-or-below
current. The point is "build-breaks when a future PR grows the struct
without realising"; the bound is documentation, not minimisation.)

## Out of scope (explicitly)

- **Decoupling mutation from dispatch upstream.** That's #1016's
  remaining half; it requires a target architecture (#946 pipeline
  staging or #963 PacketEditor). Issue body for #1016 explicitly says
  "decoupling here without a target architecture would just shuffle
  code." This PR honours that.
- **Per-class CoS smoke** — Wave-5 defers per-PR smoke; one
  comprehensive smoke runs at batch end.
- **Renaming `enqueue_pending_forwards`** — the function name has 39
  external grep hits; renaming would balloon the diff.
- **Removing `extract_l3_packet`** — currently `#[allow(dead_code)]`
  and `pub(super)`. Leave it. Removing dead code rides in a separate
  scoped PR.
- **Hoisting `dbg` field updates into a `BatchCounters` struct.**
  That's a separate refactor (the field-by-field `dbg.enqueue_*`,
  `dbg.tx_*` accounting could be a struct, but that's #1187-style
  work and is out of scope here).

## Open questions for adversarial review

1. **Is `ControlFlow<()>` the right return type for early-out helpers,
   or do reviewers prefer `Option<()>` / `bool` / `Result<(), ()>`?**
   `ControlFlow` is sloggable in tests and self-documenting; the
   alternatives are shorter to write. PLAN-KILL is acceptable if
   reviewers think the type churn outweighs the clarity.

2. **Phase 8 borrow shape — does the proposed `try_inplace_rewrite`
   signature actually compile against the borrow checker, or does it
   need a second pass?** Specifically: `target_binding: &mut
   BindingWorker` + `ingress_area: &MmapArea` + `flow_key: &mut
   Option<FlowKey>` + `post_recycles: &mut Vec<(u32, u64)>` — if the
   first two reborrows alias, the helper has to take the raw
   `*const MmapArea` and re-deref inside. Reviewers please walk the
   borrow shape.

3. **Should `direct_tx.rs` and `inplace_rewrite.rs` merge into one
   `frame_writers.rs` module?** They share `can_rewrite_in_place` and
   `owner_matches_target` predicates. Pro of merge: one home for those
   predicates. Con: `direct_tx.rs` is itself ~200 LOC and merging
   would put us back near the 400-LOC cue. Plan v1 keeps them
   separate. PLAN-NEEDS-MAJOR if reviewers prefer the merge.

4. **`apply_shared_recycles_to_bindings` (the non-split variant) lives
   in `dispatch/shared_recycle.rs`. Should it instead move to
   `tx/recycle.rs` (a new sibling) since it has zero relationship to
   the per-request dispatch loop?** Plan v1 keeps it co-located — it
   shares the slot-resolution helpers with `apply_shared_recycles`,
   and a new sibling for one function is overhead. PLAN-NEEDS-MINOR
   if reviewers disagree.

5. **`slow_path.rs` carries `resolve_tx_binding_ifindex` which is
   called all over the codebase (16+ callers).** It is not actually
   slow-path-specific. Should it move to `tx/binding_resolve.rs`
   instead? Plan v1 groups it with `slow_path.rs` because both bundle
   "egress-side TX wiring" lookups. Reviewers — is the grouping wrong?

6. **#1166 already moved TSO out of `tx/dispatch.rs` and into
   `tx/tcp_segmentation.rs`.** The Phase 7 helpers proposed in
   `tcp_seg_dispatch.rs` are the *gating* logic and the *dispatch*
   into TCP seg, not the seg builders themselves. Reviewers — should
   the gating logic move INTO `tx/tcp_segmentation.rs` instead of a
   new dispatch sibling? Pro: keeps all TCP-seg concerns in one
   module. Con: `tcp_segmentation.rs` is currently 480 LOC of pure
   builders; mixing the dispatcher in dilutes its single-purpose
   shape. Plan v1 keeps them separate.

7. **PLAN-KILL escape hatch.** If reviewers conclude that
   `enqueue_pending_forwards` at 845 LOC is already as modular as it
   needs to be — that the named helpers and the linear iteration
   structure are sufficient — PLAN-KILL is acceptable. The function
   *is* long, but it is also the *single* fan-in point for every
   forwarding decision the dataplane makes per packet, and a
   "one place to read" property has value of its own. Reviewers should
   weigh the cohesion gain against the read-many-files cost.
