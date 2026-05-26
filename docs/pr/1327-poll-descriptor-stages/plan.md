# #1327 Step 1 — poll_descriptor.rs: directory split + flow-cache stage extraction (Phase 1.5)

**Status:** DRAFT v4 — addressing round-3 split verdicts: Codex
PLAN-NEEDS-MAJOR (`task-mpmvbfiy-yehdyn`) caught a real
`packet_frame`/`owned_packet_frame` borrow hazard; AGY
PLAN-READY (`review-mpmvbnc1-l7248o`) ratified the v3 split-borrow
fix.

## v3 → v4 disposition

| Round-3 finding | Disposition |
|---|---|
| **Codex MAJOR — `packet_frame` + `&mut owned_packet_frame` overlap at call site.** v3 helper takes both `packet_frame: &[u8]` (derived from `owned_packet_frame.as_deref().unwrap_or(raw_frame)` at L477) and `owned_packet_frame: &mut Option<Box<[u8]>>`. Inline code works because NLL proves `take()` only happens on `continue`-terminated paths within the same function body. Across the call boundary, the caller cannot prove that — so passing both is a borrow violation. | **APPLIED.** v4 helper does NOT take `packet_frame` as a parameter. It takes only `&mut owned_packet_frame` (plus `raw_frame: &[u8]`), and re-derives `let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);` as its first local. NLL inside the helper body works identically to the inline code. Caller does not need to rederive `packet_frame` on `FallThrough` because the original `packet_frame` binding at L477 of the caller is still valid (we never moved `owned_packet_frame` — `as_deref()` just produces a shared `&[u8]` borrow which ends before `&mut owned_packet_frame` is taken in the helper call). |
| **Codex minor — `binding_ifindex` appears unused by L548-879 block.** | **APPLIED.** v4 removes `binding_ifindex` from the signature. The audit grep confirms no `binding.ifindex` access in 548-879. |


## v2 → v3 disposition

| Round-2 finding | Disposition |
|---|---|
| **AGY critical — `&mut BindingWorker` won't compile.** The outer driver holds `let mut received = binding.xsk.rx.receive(available)` which mutably borrows `binding.xsk.rx`; passing `&mut binding` to the helper across the call boundary forces the compiler to assume the helper may touch `xsk.rx`, causing a borrow conflict. Today's inline code compiles because Rust's split-borrow analysis works *within* one function body but cannot span function call boundaries. | **APPLIED.** v3 signature passes disjoint sub-struct fields: `&mut binding.flow`, `&mut binding.tx_pipeline`, `&mut binding.tx_counters`, `&mut binding.scratch`, `&mut binding.mirror_sample_counter`, `&binding.live`, plus the scalar `binding.slot`, `binding.ifindex`. |
| **Codex — signature missing `packet_fabric_ingress: bool`.** | **APPLIED.** Added — referenced at L569 of source. |
| **Codex — call-site list incomplete: `tests.rs:3520, 3748` missing.** | **APPLIED.** Full list is now 6 test sites. |
| **Codex — stages 12+ matrix `continue` counts inaccurate.** Example: L887-1156 has 6 continues, not 2. | **APPLIED.** v3 removes specific continue counts and frames the matrix as architectural verdict only ("blocked by mutable-locals coupling"), since precise per-stage counts are off by a few. The conclusion (all blocked) is ratified by AGY round 2. |
| **Codex — test-plan checkboxes `[x]` before implementation.** | **APPLIED.** Changed to `[ ]` (required gates). |



## v1 → v2 disposition

| Round-1 finding | Disposition |
|---|---|
| **AGY #2 — recycle semantics wrong; `StageOutcome<()>` corrupts UMEM at L653 (ICMP TE) and L876 (TX fallback).** | **APPLIED.** v2 introduces a dedicated `FlowCacheOutcome` enum with `Consumed` / `FallThrough` arms. The 3-continue map (L616, L653, L876) is documented in the "Recycle-exit map" table below. |
| **AGY #10 / Codex #5 — call sites in plan are wrong.** | **APPLIED.** Real sites are `userspace-dp/src/afxdp/worker/lifecycle.rs:195`, `userspace-dp/src/afxdp/tests.rs:2793/2978/3145/3353`, and the use-import at `userspace-dp/src/afxdp/mod.rs:514`. Plan updated. |
| **Codex #2 — `#[inline]` too weak for 270-LOC helper.** | **APPLIED.** v2 mandates `#[inline(always)]` on `stage_flow_cache_hit` with a `cargo asm` post-build gate. |
| **AGY #3 / Codex #4 — PollCtx<'a> premature; aggregation churn; inconsistent with `poll_stages.rs`.** | **APPLIED.** v2 drops PollCtx from Step 1 scope. The signature stays as-is. Future steps can revisit if a coherent set of state aggregates emerges. |
| **AGY #5 / Codex #5 — stage 12+ extractability story unproven.** | **APPLIED.** v2 explicitly commits to option **(b) Step 1 is the structural ceiling** for #1327. The follow-up extraction matrix (lines 880-2915) is included in the "Stages 12+ verdict" section below: 5 candidates evaluated, all blocked. |
| **AGY #8 — `record_rx_descriptor_telemetry` placement: telemetry/rx_descriptor.rs is over-engineered.** | **APPLIED.** v2 moves it to flat `poll_descriptor/rx_telemetry.rs` (sibling of mod.rs, no nested directory). |
| **Codex #1 — perf justification "inlined and gives perf-top granularity" is contradictory.** | **APPLIED.** v2 reframes the win as **structural readability and bounded code-motion**, not a `perf top` win. The `#[inline(always)]` requirement removes the call edge entirely; per-stage profiling is a non-goal of Step 1. |
| **AGY #1 — merge-conflict risk; possibly PLAN-KILL.** | **NOTED.** Step 1's structural drop is ~12% (3292 → ~2900). If reviewers still conclude this is too small a win for the churn, PLAN-KILL remains correct. |

## Issue framing

`userspace-dp/src/afxdp/poll_descriptor.rs` is 3292 LOC. The
`poll_binding_process_descriptor` function spans lines 425-2915
(~2490 LOC). #946 Phase 1 already extracted 7 early stages into
`poll_stages.rs`; #946 Phase 2 (batched per-stage iteration) was
PLAN-KILLED. This PR sits in the gap: pure code motion of a
single self-contained `continue`-terminated block, with a
hard-stated structural ceiling.

## Honest scope/value framing

**Win:**
- `poll_descriptor/mod.rs` drops from 3292 → ~2900 LOC.
- The flow-cache fast path becomes individually reviewable in
  `flow_cache_hit.rs` (~280 LOC).
- `record_rx_descriptor_telemetry` (179 LOC) splits out to
  `poll_descriptor/rx_telemetry.rs`.

**Non-wins (explicitly):**
- No `perf top` symbol granularity (`#[inline(always)]`).
- No cycles/packet improvement.
- No path to extracting stages 12+ — see "Stages 12+ verdict".

**KILL still on the table.** If reviewers conclude a ~12%
structural LOC drop on one block + one telemetry helper is too
small to justify the merge-conflict risk on a hot path file,
KILL is correct.

## Recycle-exit map (AGY #2 fix)

The flow-cache fast path contains **3 `continue`s** (not 4 as v1
stated), verified by reading lines 614-877:

| Line | Path | Side effects before `continue` | `recycle_now` | desc disposition | Helper outcome |
|---|---|---|---|---|---|
| **616** | cached descriptor `.drop` or policer `.drop` | filter-counter record, policer eval, input/output filter logs, `scratch_recycle.push(desc.addr)` | (unread) | recycled by inline push | `Consumed` (helper already pushed) |
| **653** | TTL/hop-limit exceeded → local ICMP TE | `scratch_forwards.push(request)`, **no recycle** (comment in source: "Don't recycle here — enqueue_pending_forwards returns the frame via pending_fill_frames") | unchanged | frame returned via `pending_fill_frames` later; **must not recycle now** | `Consumed` (helper already forwarded) |
| **876** | final `continue` after the matches-block | conditionally `scratch_recycle.push(desc.addr)` based on `recycle_now`; possibly `scratch_forwards.push(request)` with `recycle_now = false` set inside | true if neither in-place TX nor fallback PendingForward succeeded | already recycled OR already forwarded | `Consumed` (helper performed the conditional push itself) |

The plan therefore introduces a 2-arm enum:

```rust
pub(super) enum FlowCacheOutcome {
    /// Cache hit fast path consumed the descriptor. The helper
    /// has already performed any necessary scratch_recycle.push
    /// and/or scratch_forwards.push. The caller MUST `continue`
    /// without touching `desc.addr` again.
    Consumed,
    /// Cache miss or HA-invalid slot. Caller falls through to the
    /// slow-path session resolution starting at line 880.
    FallThrough,
}
```

The 3-arm proposal from AGY's review collapses to **2 arms**
because all 3 terminal exits handle their own push semantics
*inside* the helper. The caller just sees `Consumed → continue`
vs `FallThrough → run slow path`. This eliminates the
double-recycle / use-after-free hazard at L653 and L876 by
design — there is no way for the caller to forget or duplicate
a push.

`recycle_now` is a local variable inside the helper for the L876
path; it is NOT exposed to the caller. The caller's
`recycle_now = true` initialisation at line 448 is for the
slow-path code below the flow-cache block, untouched by the
helper.

## Concrete design (v2)

### Directory layout

**Before:**
```
userspace-dp/src/afxdp/
  poll_descriptor.rs    3292 LOC
  poll_stages.rs        735 LOC
```

**After:**
```
userspace-dp/src/afxdp/
  poll_descriptor/
    mod.rs                  ~2900 LOC — pub(super) fn
                            poll_binding_process_descriptor; the
                            existing small helpers (L27-422); the
                            inline body with the flow-cache block
                            replaced by a `match` on the helper.
    flow_cache_hit.rs       ~280 LOC — pub(super) fn
                            stage_flow_cache_hit, FlowCacheOutcome
                            enum, #[inline(always)].
    rx_telemetry.rs         ~190 LOC — pub(super) fn
                            record_rx_descriptor_telemetry,
                            verbatim from L2948-3126.
  poll_stages.rs            735 LOC — unchanged.
```

### `stage_flow_cache_hit` signature (v3 — borrow-safe via disjoint fields)

The helper takes individual disjoint sub-struct refs, NOT a
`&mut BindingWorker`. This is mandatory because the outer driver
holds `let mut received = binding.xsk.rx.receive(available)`
which mutably borrows `binding.xsk.rx`; passing `&mut binding`
across the function call boundary breaks split-borrow analysis.

```rust
// poll_descriptor/flow_cache_hit.rs
use super::*;

pub(super) enum FlowCacheOutcome { Consumed, FallThrough }

#[inline(always)]
pub(super) fn stage_flow_cache_hit(
    // Disjoint sub-struct refs (AGY round-2 fix):
    flow_state: &mut WorkerFlowCacheState,   // .flow_cache, .flow_cache_session_touch
    tx_pipeline: &mut WorkerTxPipeline,      // .pending_tx_prepared
    tx_counters: &mut WorkerTxCounters,      // .pending_in_place_tx_packets, .record_in_place_l2_rewrite
    scratch: &mut WorkerScratch,             // .scratch_recycle, .scratch_forwards
    mirror_sample_counter: &mut u64,         // bumped per cached hit when mirroring
    live: &Arc<BindingLiveState>,            // read-only Arc handle
    binding_slot: u32,                       // scalar, by value
    // Per-descriptor context:
    binding_index: usize,
    desc: &Descriptor,
    area: *const MmapArea,
    raw_frame: &[u8],
    // NOTE: helper takes &mut Option<Box<[u8]>>, NOT a separate
    // packet_frame: &[u8]. The shared borrow `packet_frame` and
    // the mutable borrow &mut owned_packet_frame cannot coexist
    // at the call site (Codex round-3 fix). The helper re-derives
    // packet_frame as its first local from `as_deref().unwrap_or(raw_frame)`.
    owned_packet_frame: &mut Option<Box<[u8]>>,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    packet_fabric_ingress: bool,             // Codex round-2 fix; read at L569 of inline source
    validation: ValidationState,
    sessions: &mut SessionTable,
    now_ns: u64,
    now_secs: u64,
    worker_ctx: &WorkerContext<'_>,
    telemetry: &mut TelemetryContext<'_>,
) -> FlowCacheOutcome {
    // Re-derive packet_frame locally (matches L477 of the caller's
    // pre-flow-cache code). NLL keeps this shared borrow alive only
    // until the take() at L859 of the inline source, which is the
    // last lexical use before either Consumed-return or FallThrough.
    let packet_frame: &[u8] = owned_packet_frame.as_deref().unwrap_or(raw_frame);

    // Body lifted verbatim from poll_descriptor.rs:553-879
    // (the entire body of the outer `if FlowCacheEntry::packet_eligible(meta)
    // && let Some(flow) = flow.as_ref()` block, with the
    // outer-if/let already evaluated by the caller).
}
```

### Caller-side `packet_frame` lifecycle (Codex round-3 fix)

The original `packet_frame` binding at L477 of the caller is:
```rust
let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
```
This shared borrow is alive through stages 7-11 (parse_flow_and_learn,
classify_fabric_ingress, screen_check, ipsec_passthrough_check), up to
L546 (last `packet_frame` use before the flow-cache block at L548).

Between L546 (last use) and the new helper call at L548 (start of
the flow-cache block), `packet_frame` is NOT used. NLL therefore
releases the shared borrow before the helper's `&mut owned_packet_frame`
parameter is bound, so the borrow rules are satisfied.

On `FallThrough`, the caller re-binds:
```rust
match stage_flow_cache_hit(...) {
    FlowCacheOutcome::Consumed => continue,
    FlowCacheOutcome::FallThrough => {}
}
// Re-bind packet_frame for the slow-path code at L880+.
let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
```
This re-bind is mandatory because the original L477 binding's
lexical lifetime ended at L546 (NLL).

The helper takes `flow: &SessionFlow`, not `Option<&SessionFlow>`.
The `packet_eligible` + `flow.is_some()` guard stays in the
caller so the helper body has zero extra conditionals.

The exact set of `binding.*` field accesses inside the lifted
block (lines 548-879) is:

- `binding.flow.flow_cache.lookup_counted(...)` (L556)
- `binding.flow.flow_cache.invalidate_slot(...)` (L573)
- `binding.scratch.scratch_recycle.push(...)` (L615, L874)
- `binding.flow.flow_cache_session_touch` read+write (L623-624)
- `binding.scratch.scratch_forwards.push(...)` (L649, L868)
- `binding.slot` read (L702 — used as `ingress_slot`)
- `binding.mirror_sample_counter` read+write (L723, L765)
- `&binding.live` (L796)
- `binding.tx_pipeline.pending_tx_prepared.push_back(...)` (L801)
- `binding.tx_counters.pending_in_place_tx_packets += 1` (L822)
- `binding.tx_counters.record_in_place_l2_rewrite(...)` (L823-825)

`binding.bpf_maps`, `binding.xsk`, `binding.cos`, `binding.timers`,
`binding.bind_meta` are NOT accessed by this block. Confirmed by
grep on the line range.

### `owned_packet_frame` handling

The fallback `PendingForward` branch at line 859 calls
`owned_packet_frame.take()`. Helper takes
`&mut Option<Box<[u8]>>`; semantics preserved.

### Caller transformation

`poll_binding_process_descriptor` (in `mod.rs`) at lines 548-879
becomes:

```rust
// packet_frame is the inline-source L477 binding, alive from L477
// through L546 (last stage_ipsec_passthrough_check use). NLL ends
// the shared borrow here.

if FlowCacheEntry::packet_eligible(meta)
    && let Some(flow) = flow.as_ref()
{
    match stage_flow_cache_hit(
        &mut binding.flow,
        &mut binding.tx_pipeline,
        &mut binding.tx_counters,
        &mut binding.scratch,
        &mut binding.mirror_sample_counter,
        &binding.live,
        binding.slot,
        binding_index,
        desc,
        area,
        raw_frame,
        &mut owned_packet_frame,
        meta,
        flow,
        packet_fabric_ingress,
        validation,
        sessions,
        now_ns,
        now_secs,
        worker_ctx,
        telemetry,
    ) {
        FlowCacheOutcome::Consumed => continue,
        FlowCacheOutcome::FallThrough => {}
    }
}

// Re-bind packet_frame for the slow-path code at L880+.
// (The L477 binding's NLL lifetime ended at L546.)
let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
// fall through to slow-path session resolution
```

The split borrows of `binding.flow / tx_pipeline / tx_counters /
scratch / mirror_sample_counter / live / slot` are disjoint from
`binding.xsk.rx` (still held mutably by the `received` binding) —
Rust's borrow checker accepts these alongside the outer
`received.read()` call.

`binding.ifindex` was in v3's signature but is NOT accessed inside
the lifted L548-879 block; v4 removes it (Codex round-3 minor fix).

### `record_rx_descriptor_telemetry` move

Verbatim move from L2948-3126 → `poll_descriptor/rx_telemetry.rs`.
Call site at L447 imports from the new path; no signature change.

## Public API preservation

Verified call sites (6 total):
- `userspace-dp/src/afxdp/mod.rs:514` — use-import.
- `userspace-dp/src/afxdp/worker/lifecycle.rs:195` — production call.
- `userspace-dp/src/afxdp/tests.rs:2793, 2978, 3145, 3353, 3520, 3748` —
  test calls (Codex round-2 fix: added 3520 + 3748).

Signature of `pub(super) fn poll_binding_process_descriptor` is
unchanged. Visibility unchanged. Module path
`super::poll_descriptor` is unchanged from the caller's view
because `mod poll_descriptor;` with a directory module produces
the same import path as a file module.

## Hidden invariants

1. **Per-packet allocation budget: 0.** Verified by code-motion
   inspection: every `cached_*` binding is a borrow into the
   existing `Cache` entry, not a clone. No new `Vec::new()`,
   `Box::new()`, `Arc::clone()`, or `format!()` in the helper or
   the caller transformation.
2. **Side-effect ordering inside the helper:** filter-counter
   record → three-color policer → input-filter log → output-filter
   log → drop check → TTL/hop-limit check → forward. Preserved by
   verbatim lift (AGY #2 ratified ordering).
3. **`scratch_recycle` / `scratch_forwards` push ownership.**
   Helper performs all pushes inline; caller does NOT push on
   `Consumed`. AGY #2 hazard eliminated.
4. **`flow_cache_session_touch & 63 == 0` sampling.** Preserved
   verbatim.
5. **HA-validity gate.** `cached_flow_decision_valid(...)` at
   L563 runs before any side effect. Preserved verbatim.
6. **`#[inline(always)]`.** Validated by post-build `cargo asm`
   spot-check confirming no `call` edge from
   `poll_binding_process_descriptor` to
   `stage_flow_cache_hit`.
7. **`owned_packet_frame.take()` ownership.** Helper takes
   `&mut Option<Box<[u8]>>`; L859 `take()` consumes correctly.
   No double-take possible because helper returns `Consumed`
   immediately after.

## Stages 12+ verdict (Codex #5 + AGY #5)

Extraction matrix for `poll_descriptor.rs:880-2915` (architectural
verdict only — precise per-stage `continue` counts are off by a
few and not load-bearing; the conclusion is what matters):

| Candidate | Mutable locals shared with rest of body | Verdict |
|---|---|---|
| `stage_resolve_session_or_create` (~L887-L1156) | `debug`, `session_ingress_zone`, `flow_cache_owner_rg_id`, `apply_nat_on_fabric`, `decision` (initialised here, threaded through ~1700 LOC), `meta` reads, `owned_packet_frame` reads | BLOCKED — `decision` is threaded through the next ~1700 LOC; extraction needs a `DescriptorState` struct that would tangle with `&mut binding` borrows. |
| `stage_nat_preroute` (~L1100-L1300, nested in session-hit) | DNAT/static-DNAT/NPTv6/NAT64 intermediates, `effective_resolution_target` | BLOCKED — outputs not a clean tuple; intermediates threaded through later policy + FIB without a defensible interface boundary. |
| `stage_policy_evaluate` (~L1244-L1450) | `decision.nat`, log emit branches, `recycle_now` write | BLOCKED — mutates `decision.nat` in place and writes the caller's `recycle_now`. Same `DescriptorState` problem. |
| `stage_fib_neighbor_resolve` (~L1700-L2050) | `decision.resolution`, neighbor cache, MissingNeighbor enqueue | BLOCKED — MissingNeighbor side effect is the exact pattern that killed #946 Phase 2. |
| `stage_session_install` (~L2400-L2700) | `decision`, `session_ingress_zone`, conntrack publish, flow cache populate | BLOCKED — depends on outputs of all previous candidates. |

**Conclusion: Step 1 is the structural ceiling for #1327.** No
further stages are cleanly extractable without first designing a
`DescriptorState` lifetime/borrow model — a separate plan of
#946-Phase-2-class effort.

v2 explicitly commits to option **(b) Step 1 is the limit**. If
the ~12% structural drop is too small to justify the churn,
**PLAN-KILL is correct** and #1327 should be closed with this
plan as the rationale.

## Risk assessment (v2)

| Class | Level | Notes |
|---|---|---|
| Behavioural regression | **MED** | `FlowCacheOutcome` 2-arm enum eliminates the recycle-mapping hazard; verbatim lift; helper performs all pushes inline. Smoke matrix at end of wave. |
| Lifetime / borrow-checker | **LOW** | No PollCtx aggregation; helper takes the same individual refs the inline code already proves the borrow-checker accepts. |
| Performance regression | **LOW** | `#[inline(always)]` removes call edge by construction. `cargo asm` is a hard gate. |
| Architectural mismatch | **LOW** | No batched iteration (#946 Phase 2); no PollCtx; no extraction of order-coupled stages. |

## Test plan (required gates — Codex round-2 fix)

- [ ] `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release`
- [ ] `cargo test --release` — full suite
- [ ] 5× flake on `cargo test --release -- afxdp::tests::` filter
- [ ] `cargo asm` spot-check confirming no `call` edge to
      `stage_flow_cache_hit`
- [ ] `go test ./...` — 30 Go packages
- [ ] **No per-PR smoke** — Wave-1 batch-merge rule

## Out of scope (v2)

- Stages 12+ (#1327 closes after Step 1 ships)
- #946 Phase 2 batched iteration (PLAN-KILLED)
- PollCtx<'a> aggregation (deferred indefinitely)
- `poll_stages/` directory reorganisation
- Per-stage cargo unit tests
- BindingWorker sub-struct layout (#959)
- Slow-path handoff (#1318)

## Open questions for adversarial review v2

1. **`FlowCacheOutcome::Consumed` 2-arm vs AGY's 3-arm proposal.**
   v2 collapses to 2 arms by making the helper own all pushes.
   Verify this is preferable.
2. **`#[inline(always)]` on 280-LOC helper.** Single call site;
   IR size identical to current inline code. Register pressure
   regression? My read: no — same IR.
3. **`owned_packet_frame: &mut Option<Box<[u8]>>` threading.**
   Is there a cleaner shape? My read: no.
4. **Step 1 ceiling commitment.** v2 commits to option (b).
   Correct call, or PLAN-KILL on grounds of "12% drop too small
   for the churn"?
5. **`record_rx_descriptor_telemetry` placement.** Flat
   `poll_descriptor/rx_telemetry.rs` per AGY #8. Ratify.
