# #1327 Step 1 — poll_descriptor.rs: directory split + extract bounded stages (Phase 1.5)

**Status:** DRAFT v1 — pending adversarial plan review.

## Issue framing

`userspace-dp/src/afxdp/poll_descriptor.rs` has drifted from the
2343-LOC measurement in the issue body to **3292 LOC**, of which
the `poll_binding_process_descriptor` function spans lines
**425-2915 (~2490 LOC, ~10× over `docs/engineering-style.md`'s
~200-LOC threshold).** A 179-LOC sibling helper
`record_rx_descriptor_telemetry` (lines 2948-3126) sits at the
tail. Issue #1327 explicitly scopes this as the **#946 Phase 1.5
helper-extraction follow-up** — the work that #946's closure
note (`project_946_closed.md`) deferred to a future issue after
Phase 2's batched-pipeline plan was killed.

The historical Phase 1 (`poll_stages.rs`) already extracted seven
of the early stages (link-layer / GRE decap / parse-flow /
fabric-ingress / screen / IPsec / SYN-cookie ACK). Stages 12+
(flow-cache fast path, conntrack lookup, NAT pre-routing, NPTv6
inbound, NAT64 pre-routing, input/output filter eval, policy
evaluation, NAT post-routing, FIB lookup, neighbor resolution,
session install, BPF conntrack mirror, embedded-ICMP NAT, fabric
redirect safety net, slow-path handoff) remain inline and account
for ~1900 of the 2490 LOC inside the function.

## Honest scope/value framing

This is **pure code motion driven by readability and per-stage
symbol granularity in `perf top`** — not a measurable cycles-per-
packet win. The benefit:

- `poll_descriptor.rs` drops from 3292 → ~250 prod LOC (slim
  entry) + thin sibling modules per stage.
- Each stage becomes individually `#[inline]` and individually
  visible in `perf record`. Today every cycle on the packet path
  attributes to `poll_binding_process_descriptor` — there is no
  per-stage attribution available without `cargo asm` plus
  source-map hand-walking.
- Future per-stage cargo unit tests become viable. None are added
  in this PR; the issue's "test handling" section explicitly
  defers them to a follow-up.

The win is **structural, not algorithmic.** If reviewers conclude
the perf attribution + readability gain is too small to justify
the churn on a per-packet hot path, **PLAN-KILL is an acceptable
verdict**. The methodology only works if KILL stays on the table.

## What is already shipped / partially batched

- **#1054** lifted the inner-loop body byte-for-byte out of
  `afxdp.rs` into the current flat `poll_descriptor.rs`.
- **#946 Phase 1** extracted stages 5-11 into `poll_stages.rs`
  with the `StageOutcome<T>` enum, `FabricIngressOutcome`,
  `ScreenCheckOutcome`, `SynCookieAckOutcome` carriers. The
  pattern is: each stage is `#[inline] pub(super) fn` taking
  primitive references + `&WorkerContext`, returning a typed
  outcome the caller pattern-matches.
- **#946 Phase 2** (batched per-stage iteration) was **PLAN-KILLED**
  — see `project_946_phase2_plan_killed.md`. `flow_cache + session
  table + MissingNeighbor` are order-coupled and cannot be
  trivially batched. **This PR does NOT propose Phase 2.** Every
  stage helper extracted here is still called once per descriptor
  inside the existing `while let Some(desc) = received.read()`
  loop. Ordering is preserved exactly.

## Concrete design

### Directory layout (Wave-1 mandated)

Convert the flat `poll_descriptor.rs` to a module directory.
`poll_stages.rs` stays where it is for compatibility with this PR
(further reorganisation into `poll_stages/` is out of scope).

**Before (flat):**

```
userspace-dp/src/afxdp/
  poll_descriptor.rs    3292 LOC
  poll_stages.rs        735 LOC
```

**After (this PR):**

```
userspace-dp/src/afxdp/
  poll_descriptor/
    mod.rs                ~280 LOC — pub(super) fn entry, while-let driver,
                           pre-existing small helpers (source_nat_decision_for_flow,
                           record_source_nat_failure, filter_log_ingress_zone_id,
                           filter_log_egress_zone_id, evaluate_non_pbr_input_filter,
                           evaluate_non_pbr_input_filter_log_only,
                           evaluate_dscp_sensitive_input_filter_on_session_hit,
                           syn_cookie_reply_budget_available,
                           enqueue_syn_cookie_reply, emit_input_filter_log_match,
                           emit_cached_input_filter_log, emit_cached_output_filter_log,
                           apply_lo0_filter_action stay in mod.rs; they are
                           already small (<50 LOC each) and module-private)
    ctx.rs                ~80 LOC — typed `PollCtx<'a>` aggregating the
                           current 14-parameter cluster (binding, area, sessions,
                           screen, validation, now_ns, now_secs,
                           ha_startup_grace_until_secs, _worker_id,
                           conntrack_v4_fd, conntrack_v6_fd, worker_ctx, telemetry,
                           binding_index)
    flow_cache_hit.rs     ~270 LOC — stage_flow_cache_hit (extract lines
                           548-879: the entire "Flow cache fast path"
                           block, including the inline in-place rewrite
                           fast path). Returns StageOutcome<()>
                           (RecycleAndContinue | Continue). Continue means
                           "fall through to slow-path session resolution".
    telemetry/
      rx_descriptor.rs    ~190 LOC — record_rx_descriptor_telemetry (lifted
                           verbatim from poll_descriptor.rs:2948-3126; pure
                           per-descriptor bookkeeping, no packet-pipeline
                           state).
```

**Why NOT extract more stages 12+ in Step 1.**

The inline body from line 880 (post-flow-cache) through line 2915
threads ~25 mutable locals (`decision`, `debug`,
`session_ingress_zone`, `flow_cache_owner_rg_id`,
`apply_nat_on_fabric`, `meta` (mutated), `owned_packet_frame`
(taken-from), `recycle_now`, plus the various NAT/DNAT/NPTv6/NAT64
intermediates) and contains 17 of the 20 `continue` sites in the
function. Extracting any of these as `StageOutcome`-shaped helpers
requires either:

1. A wide return struct (8-15 fields) per stage — likely a code-
   readability **loss** vs the inline view, OR
2. `&mut`-borrowing the entire mutable-local cluster through a
   `&mut PollLoopState` struct, which forces every stage signature
   to take `&mut PollLoopState` and creates aliasing tension with
   `binding: &mut BindingWorker` (which is also widely written).

Reviewers should explicitly verify in plan review whether they
believe stages 12+ can be cleanly extracted *in a follow-up PR*
without falling into the #946-Phase-2 dead-end pattern. If the
answer is no, the structural LOC win caps at ~30% (3292 → ~2200).
If the answer is yes, follow-ups can carve off conntrack-lookup,
NAT-preroute, policy-eval, NAT-postroute, FIB-neighbor, and
session-install stages incrementally.

**Step 1's defensible scope** is therefore:

1. Mechanical directory split (no code change).
2. Move `record_rx_descriptor_telemetry` to a telemetry sibling
   (it has no pipeline state coupling — pure desc/area/telemetry
   inputs).
3. Extract the flow-cache fast path (the single largest
   self-contained `continue`-terminated block; 17% of the body
   in one shot; uses a small fixed set of locals that don't
   leak past the block).
4. Introduce a typed `PollCtx<'a>` that aggregates the existing
   14-param function signature so future Step-N extractions don't
   each thread 14 params again.

This is conservative on purpose. Step 1 either works mechanically
or doesn't compile — it can't introduce silent behavioural
regressions, and that's the point of a Phase 1.5 helper-extraction
PR on the hottest function in the dataplane.

### PollCtx shape

```rust
// poll_descriptor/ctx.rs
pub(super) struct PollCtx<'a> {
    pub binding: &'a mut BindingWorker,
    pub binding_index: usize,
    pub area: *const MmapArea,
    pub sessions: &'a mut SessionTable,
    pub screen: &'a mut ScreenState,
    pub validation: ValidationState,
    pub now_ns: u64,
    pub now_secs: u64,
    pub ha_startup_grace_until_secs: u64,
    pub conntrack_v4_fd: c_int,
    pub conntrack_v6_fd: c_int,
    pub worker_ctx: &'a WorkerContext<'a>,
    pub telemetry: &'a mut TelemetryContext<'a>,
}
```

`_worker_id` is dropped because the original is also `_`-prefixed
(unused). Keeping it would require carrying a placeholder through
the typed struct, which is a readability loss.

The current `poll_binding_process_descriptor` function signature
is preserved at the module boundary — it becomes a thin wrapper
that constructs a `PollCtx` and delegates. Call sites in
`worker/poll.rs` and `worker/loop.rs` are unaffected.

### stage_flow_cache_hit signature

```rust
// poll_descriptor/flow_cache_hit.rs
#[inline]
pub(super) fn stage_flow_cache_hit(
    ctx: &mut PollCtx<'_>,
    desc: &xsk::Descriptor,
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    packet_fabric_ingress: bool,
) -> StageOutcome<()> {
    // Body lifted from poll_descriptor.rs:548-879 byte-for-byte,
    // with the trailing `continue` replaced by
    // `return StageOutcome::RecycleAndContinue` and the implicit
    // "fall through to slow path" path returning
    // `StageOutcome::Continue(())`.
}
```

`#[inline]` is mandatory — this is hot-path code and the inliner
must continue to fold the helper into the caller's tight loop.
The `#[cold]` annotations on error paths inside the block are
preserved verbatim from the inline source.

Return type is `StageOutcome<()>` (the existing Phase 1 carrier)
because the flow-cache fast path has only two exits:

- HA-invalid → invalidate slot → fall through to slow path
- HA-valid → execute cached decision → recycle/continue

There is no "Continue with a value" exit from the flow-cache
block; the caller resumes with its own slow-path locals.

### record_rx_descriptor_telemetry move

Pure verbatim move from lines 2948-3126 into
`poll_descriptor/telemetry/rx_descriptor.rs`. The function takes
only `(desc, area, telemetry, worker_ctx)` — no pipeline state.
The caller's invocation at line 447 is changed only to import
from the new path.

## Public API preservation

- `pub(super) fn poll_binding_process_descriptor` — signature
  unchanged, callers unaffected.
- All internal helpers (`source_nat_decision_for_flow`,
  `evaluate_non_pbr_input_filter`, `apply_lo0_filter_action`,
  etc.) remain `fn`-private in `poll_descriptor/mod.rs`. No
  visibility expansion.
- The `SynCookieReply` enum + `SYN_COOKIE_REPLY_PENDING_RESERVE`
  const move into `mod.rs` alongside their callers
  (`enqueue_syn_cookie_reply` etc.).

## Hidden invariants the change must preserve

1. **Per-packet allocation budget: 0.** No new `Vec::new()`,
   `Box::new()`, `Arc::clone()`, or `format!()` is introduced.
   The flow-cache fast-path extraction copies the existing
   bindings verbatim — every cached_* binding is a reference
   into the existing `Cache` entry, not a clone.
2. **Side-effect ordering.** Within the flow-cache fast path:
   filter-counter record → three-color policer → input-filter
   log → output-filter log → drop check → TTL/hop-limit check →
   rewrite/forward. This order is encoded in the inline source
   and must be preserved byte-for-byte by the extraction.
3. **`scratch_recycle` / `scratch_forwards` push ordering.**
   The flow-cache block has two `scratch_recycle.push(desc.addr)`
   sites (drop path and recycle_now-tail) and one
   `scratch_forwards.push(request)` (TTL-exceeded ICMP). All
   three must continue to push into the same buffers in the
   same order.
4. **`flow_cache_session_touch` amortisation.** The `& 63 == 0`
   sampling lives inside the cached-hit branch. Extracting the
   block must not change the sampling cadence (it's incremented
   per cached hit, not per packet).
5. **`recycle_now` semantics.** The outer driver sets
   `recycle_now = true` before each descriptor. The flow-cache
   block reads it once (in the in-place-rewrite path,
   line 873-875) and then `continue`s. The extracted helper
   must continue to honour the caller's `recycle_now` state.
6. **`#[inline]` discipline.** The stage helper is `#[inline]`.
   `#[cold]` annotations inside (e.g. on slow-path error
   reporting) are preserved.
7. **HA-validity gate ordering.** `cached_flow_decision_valid(...)`
   runs *before* any side effects (counter record, log emit,
   forward). Extracting the block must not float side effects
   above the gate.
8. **`continue` → `return StageOutcome::RecycleAndContinue`
   translation.** Every `continue` site inside the lifted block
   maps to a `return RecycleAndContinue`. The caller's
   match-arm pushes `desc.addr` to `scratch_recycle` and
   `continue`s the while-let.
9. **`packet_fabric_ingress` read-only.** The flow-cache block
   reads `packet_fabric_ingress` (passed by value) but does not
   write it. The extracted signature takes it by value.
10. **`raw_frame` lifetime.** The TTL-exceeded branch calls
    `build_local_time_exceeded_request(raw_frame, ...)`. The
    `raw_frame` slice borrows from the UMEM `area`; the slice
    lifetime must outlive the helper call.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioural regression | **MED** | Hot path. Mitigated by: pure code motion of self-contained `continue`-terminated block + full smoke matrix (Pass A best-effort + Pass B per-class CoS 5201-5206, v4+v6, push+`-R`). |
| Lifetime / borrow-checker | **MED** | `PollCtx<'a>` aggregates 6 `&mut` and 4 shared refs. Rust will refuse the construction if internal aliasing breaks. Flow-cache stage takes `&mut PollCtx`, holds the borrow across `binding.scratch.*` writes and `sessions.touch()`; same pattern as today's inline code. |
| Performance regression | **MED** | `#[inline]` on the stage helper is required for the inliner to fold it back into the caller. If `cargo asm` shows the helper not inlined, the PR is held until inlining is restored. |
| Architectural mismatch (#961 / #946 P2) | **LOW** | Step 1 does NOT attempt batched per-stage iteration. The order-coupled stages 12+ remain inline. Step 1 is the conservative subset that the #946 Phase 2 kill explicitly left available. |

## Test plan

Standard Wave-1 gates:

- [x] `cargo build` clean (release).
- [x] `cargo test --release` — full suite (953+ tests).
- [x] 5/5 flake check on `cargo test --release -- afxdp::` filter.
- [x] `go test ./...` — 30 Go packages clean.
- [x] **No per-PR smoke** (Wave-1 batch-merge rule: post
  `<!-- AWAITING-BATCH-MERGE -->` after 4-of-4 reviewer
  attestation; batch smoke happens at end of wave via the
  #1477/#1530-style runbook for retirement chains).
- [x] `cargo asm` spot-check on `stage_flow_cache_hit` to
  confirm the inliner folds it into
  `poll_binding_process_descriptor`. If not inlined, hold the
  PR.

## Out of scope (explicitly)

- **Stages 12+** (conntrack lookup, NAT pre-routing, NPTv6
  inbound, NAT64 pre-routing, policy eval, NAT post-routing,
  FIB lookup, neighbor resolution, session install, BPF
  conntrack mirror, embedded-ICMP NAT, fabric redirect safety
  net, slow-path handoff). Reviewers should explicitly opine on
  whether these are extractable in a follow-up.
- **Batched per-stage iteration** (#946 Phase 2 — PLAN-KILLED).
- **`poll_stages/` directory split.** `poll_stages.rs` stays
  flat in this PR; reorganising it into a directory is a
  separate cosmetic concern.
- **Per-stage cargo unit tests.** The issue's "test handling"
  section defers them to a follow-up.
- **Touching BindingWorker sub-struct layout** (#959 follow-up
  domain).
- **Touching the slow-path handoff** (`slowpath.rs` — #1318
  domain).

## Open questions for adversarial review

Each is invitable to PLAN-KILL.

1. **Is `PollCtx<'a>` actually a win?** It aggregates 14 params
   into one struct, but if downstream stages need fields not
   covered by `PollCtx` (e.g. local mutable resolution state),
   we end up with `(ctx, &mut local_state)` again and the
   aggregation buys nothing. Should Step 1 skip `PollCtx`
   entirely and ship pure file-split + flow-cache extraction
   only?
2. **Is extracting the flow-cache fast path actually safe?**
   The block has 4 `continue` sites (lines 616, 653, 766, 876)
   and reads `recycle_now`. Reviewers should walk every
   continue site and verify the `RecycleAndContinue` mapping
   preserves exact recycle behaviour. Counter-example: if any
   path inside relies on `recycle_now` staying `true` for the
   *next* packet, the extraction breaks. (Current reading:
   `recycle_now` is re-initialised at the top of each
   descriptor — so no cross-packet state. Confirm.)
3. **Inliner pressure.** A 270-LOC `#[inline]` helper might
   exceed LLVM's inline-threshold heuristic. Should we use
   `#[inline(always)]` to force-inline, or split the helper
   internally (e.g. extract the in-place rewrite path as a
   nested `#[inline]`)?
4. **Is the directory split worth the churn?** `git blame`
   on every line moves. Reviewers can verify a clean move
   with `git log --follow -M -C poll_descriptor/mod.rs` but
   merge-conflict probability for any concurrent PR touching
   `poll_descriptor.rs` is 100%. (Mitigation: file the PR
   first, freeze poll_descriptor.rs touches until merged.)
5. **Are stages 12+ realistically extractable in follow-ups?**
   If reviewers walk the post-flow-cache body (lines 880-2915)
   and conclude the mutable-local cluster is too tangled for
   any clean extraction, then Step 1's structural ceiling is
   ~2200 LOC and the whole #1327 effort is a 30% drop, not the
   90% drop the issue body implies. Reviewers should commit to
   one of: (a) clean follow-up path exists; (b) Step 1 is the
   limit; (c) PLAN-KILL because the limit isn't worth the
   churn.
6. **Why not Wave-1's "stages 12+" subdivision from the issue
   body?** The issue body sketches conntrack_lookup.rs,
   nat_preroute.rs, policy_eval.rs, nat_postroute.rs,
   fib_neighbor.rs, session_install.rs. Step 1 ships **none**
   of these. Is that too conservative? Or is the issue body's
   sketch too optimistic about the borrow-checker survival of
   each named stage? Verdict requested.
7. **`record_rx_descriptor_telemetry` placement.** Move it to
   `poll_descriptor/telemetry/rx_descriptor.rs`, or to
   `afxdp/telemetry/rx_descriptor.rs` (alongside whatever
   telemetry module already exists)? Step 1 picks the former
   because there is no `afxdp/telemetry/` directory today; the
   issue body proposed the latter.
