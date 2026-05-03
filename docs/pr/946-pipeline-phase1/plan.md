# #946 Phase 1 — Extract Per-Packet Sub-Stages from `poll_binding_process_descriptor`

Status: **DRAFT v3 — addressing Codex round-2 PLAN-NEEDS-MAJOR**

## v3 changes (Codex round-2 findings)

Codex round 2 accepted the architectural shape but flagged 5
tactical signature defects that would break behavior preservation
once implementation began. v3 fixes each.

1. **`stage_parse_and_classify` drops side effects.** Metadata
   parse failure increments `binding.live.metadata_errors`,
   `telemetry.dbg.metadata_err`, and calls `record_exception`
   (poll_descriptor.rs:2192–2204). Non-Valid disposition calls
   `record_disposition` (line 2181) which updates live counters and
   `recent_exceptions`. v2's helper only got `telemetry`; v3 takes
   `&mut binding.live`, `worker_ctx.recent_exceptions`, the ident,
   and `worker_ctx.forwarding`. Side effects fire inside the helper.
2. **`stage_parse_flow_and_learn` cannot reproduce the GRE guard.**
   The current code learns dynamic neighbors only when
   `owned_packet_frame.is_none()` (poll_descriptor.rs:113). v3's
   helper takes an explicit `learn_from_live_frame: bool` flag, and
   the broad `&mut BindingWorker` narrows to
   `&mut binding.last_learned_neighbor`.
3. **`stage_screen_check` signature was incomplete.** Needs
   `packet_frame: &[u8]` (for `extract_screen_info`), `now_secs`
   (for `screen.check_packet`), and only `&binding.live.screen_drops`
   for the live drop counter — caller still owns the recycle push.
4. **Stage inventory still missed 3 continue sites.** v3 explicitly
   lists all 9 `continue;` sites (53, 76, 80, 183, 221, 297, 433,
   535, 604) and notes 535 (session-hit TTL ICMP-TE) and 604
   (cluster-peer-return fast path) belong to the deferred stages
   13–16. Flow-cache also has a scratch_forwards fallback at line
   397 — v3 calls this out so the future Phase 1.5 helper covers it.
5. **Main-loop sketch was not compile-realistic.** Deferred inline
   code at lines 419, 583, 1814 calls `owned_packet_frame.take()`,
   so the binding must be `mut`. v3's sketch reflects this and
   restores `let mut recycle_now = true` before the deferred body.

Open question answers from Codex round 2:
- **Q1** (split into 2 PRs?): One PR is acceptable after the
  signature fixes; 8 helpers ≈ 400–1200 LOC, in line with our
  Phase-N decompositions. Split only if churn grows beyond pure
  code motion.
- **Q2** (LinkLayerOutcome arms): collapse to `StageOutcome<()>`;
  side effects (ARP/NDP neighbor learning) stay inside the helper.
  v2 was inconsistent — said 5 arms, defined 4. v3 just uses
  `StageOutcome<()>`.
- **Q3** (fabric ingress tuple): v3 returns a small named struct
  `FabricIngressOutcome { ingress_zone_override, packet_fabric_ingress }`.
- **Q4** (fuse screen+ipsec?): no, keep them separate; different
  inputs, side effects, ordering matters.
- **Q5** (hidden invariants): documented at the bottom.

## v2 changes (Codex round-1 findings)

1. Stage inventory was incomplete. v1 missed two real stages:
   **IPsec passthrough** ([poll_descriptor.rs:188–222](../../../userspace-dp/src/afxdp/poll_descriptor.rs)) and the
   **flow-cache fast path** (line 224 onward, ~600 LOC). v2 lists
   them.
2. The "scratch_forwards is a full batch boundary" claim was
   overbroad. v2 corrects this: scratch_forwards covers only the
   pending-forward (slow-path) path; the flow-cache fast path
   bypasses it and pushes directly to `pending_tx_prepared` in the
   per-packet body.
3. v1's `stage_native_gre_decap` signature was self-referential.
   v2 returns `(updated_meta, Option<Vec<u8>>)` and the caller binds
   the active slice locally.
4. v1's two-arm `StageOutcome` was underdesigned. v2 uses
   `StageOutcome<T>` (generic) for stages where one shape fits, and
   stage-specific output types where the outcomes diverge (ARP/NDP,
   the flow-cache fast path).
5. v1 dropped the false claim that #1127 (PacketBatch SoA) is
   *required* for Phase 2 — Phase 2 can ship batched iteration via
   per-stage `Vec<StageOutput>` accumulation without a new SoA struct.
6. v1 punted on stages 10+ as "complex control flow." v2 is explicit
   that step 10 (Screen) **is** extractable and is in scope; steps
   11–15 are deferred as a **scope choice** (not a seam limitation).

## Issue framing

#946 asks for a VPP / `rte_graph` style batched pipeline where the
worker loop iterates over *batches per stage*, not stages per packet.

This Phase 1 plan does **not** ship that final architecture. Phase 1
extracts the existing per-packet body of
`poll_binding_process_descriptor` (currently 2,436 LOC, one giant
`while let Some(desc) = received.read()` loop) into named per-packet
helper functions. No batch reordering, no stage-per-batch iteration.
This is pure code-motion that establishes the seams a future
Phase 2/3 will exploit to swap to batched stages.

## What's already batched

The codebase has a **partial** per-RX-burst batch boundary, NOT a
full one:

- **Slow-path**: `binding.scratch.scratch_forwards: Vec<PendingForwardRequest>`
  accumulates forwarding decisions during the RX while-let. After the
  loop drains, `enqueue_pending_forwards` (in `tx/dispatch.rs`)
  iterates the batch and dispatches to local TX or cross-worker MPSC.
- **Per-burst housekeeping**: `binding.scratch.scratch_recycle: Vec<u64>`
  collects UMEM frame addresses to recycle, drained after the batch.
  `binding.scratch.scratch_rst_teardowns` collects RST-driven session
  teardowns, drained after the batch.
- **Flow-cache fast path** ([poll_descriptor.rs:306,369](../../../userspace-dp/src/afxdp/poll_descriptor.rs)):
  bypasses `scratch_forwards` entirely. On a flow-cache hit, the
  packet's `PreparedTxRequest` is pushed directly to
  `binding.tx_pipeline.pending_tx_prepared` from inside the per-packet
  loop. This is intentional — it skips the
  `PendingForwardRequest → enqueue_pending_forwards → PreparedTxRequest`
  conversion entirely for the hot per-flow path.

So scratch_forwards is the slow-path batch boundary; the fast path
bypasses it. Phase 1 doesn't touch either of these — it adds named
seams to the per-packet code that runs before both paths.

## All 9 continue/recycle sites in the loop body (v3)

For Phase 1 to be behavior-preserving we have to account for every
existing `continue;` in the while-let. Codex round 2 enumerated them:

| Line | Site | Recycles? | Phase 1? |
|------|------|-----------|----------|
| 53   | UMEM slice failed | yes | yes (stage 2-4) |
| 76   | ARP reply | yes | yes (stage 5) |
| 80   | ARP other | yes | yes (stage 5) |
| 183  | Screen drop | yes | yes (stage 10) |
| 221  | IPsec passthrough | yes | yes (stage 11) |
| 297  | Flow-cache TTL ICMP-TE generated | no (returned via pending_fill_frames) | NO — flow-cache stage deferred |
| 433  | Flow-cache terminal `continue;` (covers both in-place rewrite success and the scratch_forwards fallback inside the same block at line 397) | no (frame travels as TX) | NO — flow-cache deferred |
| 535  | Session-hit TTL ICMP-TE generated | no (same as 297) | NO — session-hit stage deferred |
| 604  | Cluster-peer-return fast path | no (frame travels via fabric TX) | NO — cluster-peer stage deferred |

Phase 1 covers continues at 53, 76, 80, 183, 221 — every one of these
is a recycle-and-continue (the simple StageOutcome shape). The 5
deferred continues all leave the per-packet body via TX-side paths,
not via recycle, and live in the deferred stages 12–16.

## Stage inventory (corrected v3)

The while-let body executes this sequence per descriptor:

1. `record_rx_descriptor_telemetry` — TX-side telemetry sample.
2. `try_parse_metadata` → `Option<UserspaceDpMeta>` (early return on None).
3. `classify_metadata` → `PacketDisposition` (early return on Invalid).
4. UMEM area slice for `raw_frame: &[u8]` (early return on None).
5. **ARP / NDP classification** — early-return paths (ARP recycles
   without flowing through; NDP NA learns and falls through).
6. **Native GRE decap** — replaces meta and frame slice; may produce
   an owned `Vec<u8>` for the decapped frame.
7. `parse_session_flow_from_bytes` → `Option<SessionFlow>`.
8. Dynamic-neighbor learning from the source IP (host-only).
9. **Fabric-ingress detection** — sets `meta.meta_flags |= FABRIC_INGRESS_FLAG`
   if the ingress is a fabric overlay.
10. **Screen/IDS check** (slow path, only runs when profiles
    configured).
11. **IPsec passthrough check** ([poll_descriptor.rs:188](../../../userspace-dp/src/afxdp/poll_descriptor.rs))
    — for ESP/IKE, slow-path-reinject and recycle.
12. **Flow-cache fast path** ([poll_descriptor.rs:224](../../../userspace-dp/src/afxdp/poll_descriptor.rs))
    — packet-eligible + flow lookup, validate cached decision, ICMP-TE
    on TTL=1, in-place rewrite + `pending_tx_prepared.push_back`, fall
    through on miss/invalid.
13. **Session lookup → fast-path / slow-path branch.**
14. **Slow path**: policy eval → NAT slot → forwarding lookup →
    `scratch_forwards.push`.
15. **Reverse-NAT / ICMP slow-path arms.**
16. **MissingNeighbor side queue** — build session metadata, install,
    publish, push to `pending_neigh`.

That's ~2,400 LOC of branchy per-packet code in one function.

## Phase 1 scope (explicit)

**In scope** — extract these as named functions:

- (1) `stage_record_rx_telemetry`
- (2)+(3)+(4) `stage_parse_and_classify` → `StageOutcome<ParsedFrame>`
   where `ParsedFrame` carries `meta` + `raw_frame: &'a [u8]`.
- (5) `stage_link_layer_classify` → `StageOutcome<()>` (per Codex
  round-2 answer to Q2: collapse the four ARP/NDP arms; side
  effects on `dynamic_neighbors` stay inside the helper).
- (6) `stage_native_gre_decap` → `(UserspaceDpMeta, Option<Vec<u8>>)`
  *plus* the caller binds the active slice locally (the helper does
  NOT return the slice — that would be self-referential).
- (7)+(8) `stage_parse_flow_and_learn` → `Option<SessionFlow>`,
  side-effect on `worker_ctx.dynamic_neighbors` and
  `binding.last_learned_neighbor`. The combined name makes the side
  effect explicit.
- (9) `stage_classify_fabric_ingress` — mutates `meta` in place,
  returns `bool` for `packet_fabric_ingress` (used downstream).
- (10) `stage_screen_check` → `StageOutcome<()>` (RecycleAndContinue
  on screen drop; Continue otherwise). This is the screen/IDS slow
  path that currently runs at [poll_descriptor.rs:144](../../../userspace-dp/src/afxdp/poll_descriptor.rs).
- (11) `stage_ipsec_passthrough_check` → `StageOutcome<()>` (the
  ESP/IKE branch at line 188; on hit, slow-path-reinject + recycle +
  return RecycleAndContinue; otherwise Continue).

**Explicitly deferred to a Phase 1.5 / Phase 2** — these stay inline
in the main function for now:

- (12) Flow-cache fast path — ~600 LOC with multiple early returns,
  a TTL ICMP-TE side path, and an in-place rewrite that pushes
  directly to `pending_tx_prepared`. Extracting this is genuinely
  hard because the helper would need to express six distinct
  outcomes, and the TTL/ICMP-TE arm shares state with the cached
  decision. **Scope choice**: defer to a follow-up phase that can
  focus on this single transformation.
- (13)–(16) Session lookup, slow-path policy/NAT/forwarding, fast
  path, reverse-NAT/ICMP, MissingNeighbor side queue. These are
  ~1,000+ LOC with deeply intertwined state and no obvious seams.
  **Scope choice**: each gets its own phase.

## Phase 1 stage signatures (concrete v3)

```rust
// Generic outcome for stages with a single non-recycle output.
// Used everywhere in Phase 1.
enum StageOutcome<T> {
    RecycleAndContinue,
    Continue(T),
}

// Small named struct — clearer than the (Option<u16>, bool) tuple
// used by stage 9. Caller pattern-matches on both fields.
struct FabricIngressOutcome {
    ingress_zone_override: Option<u16>,
    packet_fabric_ingress: bool,
}

// ── Stage 2-4: parse metadata, classify, slice UMEM ──────────────
//
// Side effects handled INSIDE the helper to preserve current
// behavior:
//   - Parse failure: telemetry.dbg.metadata_err += 1,
//     binding.live.metadata_errors.fetch_add, record_exception.
//   - Non-Valid disposition: record_disposition (live counters +
//     recent_exceptions).
// Returns RecycleAndContinue on either failure path; Continue on
// successful parse + classify + slice.
fn stage_parse_and_classify<'a>(
    desc: &XdpDesc,
    area: &'a MmapArea,
    validation: ValidationState,
    binding_live: &BindingLiveState,
    ident: &BindingIdentity,
    forwarding: &ForwardingState,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    telemetry: &mut TelemetryContext,
) -> StageOutcome<(UserspaceDpMeta, &'a [u8])>;

// ── Stage 5: ARP / NDP classification ─────────────────────────────
//
// All 4 cases (ARP reply learn-and-recycle, ARP request/other
// recycle, NDP NA learn-and-fall-through, plain fall-through)
// collapse to RecycleAndContinue + Continue. Neighbor-learn side
// effects are kept inside the helper — downstream code does not
// read the learned neighbor for the same packet.
fn stage_link_layer_classify(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()>;

// ── Stage 6: GRE decap ────────────────────────────────────────────
//
// Returns the (possibly-updated) meta + the optional owned decap
// frame. Caller binds the active slice locally:
//
//   let (meta, owned) = stage_native_gre_decap(raw_frame, meta, ...);
//   let packet_frame = owned.as_deref().unwrap_or(raw_frame);
//
// `owned_packet_frame: Option<Vec<u8>>` must be a `mut` binding
// because deferred stage-12+ code calls `.take()` (lines 419, 583,
// 1814).
fn stage_native_gre_decap(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> (UserspaceDpMeta, Option<Vec<u8>>);

// ── Stage 7+8: parse flow + learn dynamic neighbor ───────────────
//
// `learn_from_live_frame` MUST be true only when the active slice
// is the un-decapped raw_frame (i.e. owned_packet_frame.is_none() at
// call site). Mirrors the current GRE guard at line 113.
//
// Narrowed binding access — only takes &mut binding.last_learned_neighbor
// (not the whole BindingWorker).
fn stage_parse_flow_and_learn(
    area: &MmapArea,
    desc: &XdpDesc,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    learn_from_live_frame: bool,
    last_learned_neighbor: &mut Option<LearnedNeighborKey>,
    worker_ctx: &WorkerContext,
) -> Option<SessionFlow>;

// ── Stage 9: fabric ingress classification ────────────────────────
//
// Mutates meta in place to set FABRIC_INGRESS_FLAG when applicable.
// Returns a named struct with both outputs.
fn stage_classify_fabric_ingress(
    packet_frame: &[u8],
    meta: &mut UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> FabricIngressOutcome;

// ── Stage 10: screen / IDS slow path ──────────────────────────────
//
// Adds packet_frame and now_secs (Codex round-2 finding 3). Caller
// owns the recycle push; helper only increments
// binding.live.screen_drops on a Drop verdict.
fn stage_screen_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    screen: &mut ScreenState,
    binding_live: &BindingLiveState,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()>;

// ── Stage 11: IPsec passthrough ───────────────────────────────────
fn stage_ipsec_passthrough_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    binding_live: &BindingLiveState,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()>;
```

The main loop body becomes (compile-realistic v3):

```rust
while let Some(desc) = received.read() {
    stage_record_rx_telemetry(desc, area, telemetry, worker_ctx);
    let mut recycle_now = true;  // restored — deferred stages 12+
                                 // toggle this when packet leaves
                                 // via TX (flow-cache, session-hit
                                 // TTL, cluster-peer-return).
    let StageOutcome::Continue((mut meta, raw_frame)) = stage_parse_and_classify(
        desc,
        unsafe { &*area },
        validation,
        &binding.live,
        &worker_ctx.ident,
        worker_ctx.forwarding,
        worker_ctx.recent_exceptions,
        telemetry,
    ) else {
        binding.scratch.scratch_recycle.push(desc.addr);
        continue;
    };

    if let StageOutcome::RecycleAndContinue =
        stage_link_layer_classify(raw_frame, meta, worker_ctx)
    {
        binding.scratch.scratch_recycle.push(desc.addr);
        continue;
    }

    let (new_meta, mut owned_packet_frame) =  // mut: deferred .take() at lines 419, 583, 1814
        stage_native_gre_decap(raw_frame, meta, worker_ctx.forwarding);
    meta = new_meta;
    let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);

    let flow = stage_parse_flow_and_learn(
        unsafe { &*area },
        desc,
        packet_frame,
        meta,
        owned_packet_frame.is_none(),  // GRE guard — preserves line-113 behavior
        &mut binding.last_learned_neighbor,
        worker_ctx,
    );

    let FabricIngressOutcome { ingress_zone_override, packet_fabric_ingress } =
        stage_classify_fabric_ingress(packet_frame, &mut meta, worker_ctx);

    if let StageOutcome::RecycleAndContinue = stage_screen_check(
        flow.as_ref(),
        packet_frame,
        meta,
        ingress_zone_override,
        now_secs,
        screen,
        &binding.live,
        worker_ctx,
    ) {
        binding.scratch.scratch_recycle.push(desc.addr);
        continue;
    }

    if let StageOutcome::RecycleAndContinue = stage_ipsec_passthrough_check(
        flow.as_ref(),
        packet_frame,
        meta,
        &binding.live,
        worker_ctx,
    ) {
        binding.scratch.scratch_recycle.push(desc.addr);
        continue;
    }

    // ── Deferred stages 12-16 stay inline in this PR ────────────────
    // Flow-cache fast path, session lookup, slow-path policy/NAT/
    // forwarding, reverse-NAT/ICMP, MissingNeighbor side queue.
    // These stages can call owned_packet_frame.take() and may set
    // recycle_now = false when the packet leaves via TX.
    ...

    if recycle_now {
        binding.scratch.scratch_recycle.push(desc.addr);
    }
}
```

Note: the trailing `if recycle_now` is the ORIGINAL behavior at
[poll_descriptor.rs:2205–2207](../../../userspace-dp/src/afxdp/poll_descriptor.rs).
Phase 1 preserves it.

## Why this is safe / shippable

- **Pure code motion**: each extracted function returns the same
  values the inline code would have produced; control flow is
  preserved by the explicit StageOutcome / FabricIngressOutcome arms.
- **No state shape changes**: BindingWorker, WorkerContext, sessions,
  screen, etc. all retain their current shape and access pattern.
  Stages take `&mut` references where the original code mutated.
- **No reordering of side effects**: dynamic neighbor learning,
  telemetry counter updates, screen drops, recycle pushes, etc. all
  fire in the exact same order they do today.
- **Compiler-driven verification**: extracting a function and
  inlining its callsite is a transformation rustc verifies via type
  checking. The explicit StageOutcome arms make every early-return
  path a compile-time-checked variant.
- **Hidden ordering invariants** preserved (per Codex round 2):
  - **Metadata/disposition side effects fire BEFORE recycle.**
    `record_disposition` and `record_exception` both update
    `binding.live.*` and `recent_exceptions` before the recycle
    push. v3's stage_parse_and_classify keeps this ordering by
    firing the side effects internally before returning
    RecycleAndContinue.
  - **`validated_packets`/`validated_bytes` increment BEFORE
    raw-frame slice success** (poll_descriptor.rs:47–48 vs 49).
    v3's stage_parse_and_classify increments these between
    classify and slice.
  - **Dynamic-neighbor learning only for non-GRE-owned frames**
    (line 113 guard). v3's `learn_from_live_frame` flag passes
    `owned_packet_frame.is_none()` from the caller.
  - **`raw_frame` must stay available for deferred TTL/ICMP/debug
    paths.** Beyond the flow-cache TTL path at line 281, deferred
    code uses `raw_frame` for embedded ICMP handling at
    [poll_descriptor.rs:865](../../../userspace-dp/src/afxdp/poll_descriptor.rs)
    and [poll_descriptor.rs:963](../../../userspace-dp/src/afxdp/poll_descriptor.rs),
    and for debug TCP inspection at
    [poll_descriptor.rs:1633](../../../userspace-dp/src/afxdp/poll_descriptor.rs).
    v3's caller binds both: `let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);`
    — `raw_frame` is preserved as a separate live binding for
    deferred code that must look at the un-decapped Ethernet frame.
  - **`metadata_packets` is a batch counter, NOT a live counter.**
    `telemetry.counters.metadata_packets += 1` fires AFTER
    successful metadata parse and BEFORE classify, regardless of
    whether the disposition turns out to be Valid or not. It must
    NOT fire on parse failure, and the valid-path counters
    (validated_packets/validated_bytes) are batch counters
    (`telemetry.counters`), NOT `record_disposition(PacketDisposition::Valid)`
    live-counter calls. The Valid path's only live-counter side
    effect is via the deferred stages 12+.
  - **`meta_flags` mutation must precede screen/IPsec/flow-cache.**
    Stage 9 sets `FABRIC_INGRESS_FLAG`. Screen (10), IPsec (11),
    and the deferred flow-cache (12) all read meta after stage 9
    so they see the flag. v3's loop sketch shows the ordering
    explicitly: stage 9 → 10 → 11 → deferred 12+.
  - **ARP recycles BEFORE normal forwarding** (stages 5 → continue).
  - **NDP learns AND falls through** (StageOutcome::Continue
    after the helper updates dynamic_neighbors internally).
  - **GRE decap precedes flow/screen/fabric** (stage 6 before 7
    before 9 before 10).
  - **`owned_packet_frame` is `mut`** — deferred stage code at
    lines 419, 583, 1814 calls `.take()`. The new sketch reflects
    this.

## Test plan

- `cargo build` clean (0 new warnings).
- `cargo test --release` — full 952+ test cargo suite passes.
- Named flow-cache test 5/5 clean (flake check).
- 30 Go test packages pass.
- v4 + v6 smoke against 172.16.80.200 / 2001:559:8585:80::200 on
  loss userspace cluster (best-effort 5201, plus iperf-c 5203 for
  high-rate sanity).
- Per-class CoS smoke (best-effort, iperf-a..f) since the change
  touches the dispatch ingress path. Although Phase 1 is pure code
  motion, the per-class smoke catches inadvertent classifier or
  policer regression.

## Why a future phase is required

Phase 1 doesn't realize the L1-i locality benefit #946 cites because
each packet still walks all extracted stages before the next packet
starts. To realize the benefit, Phase 2 would need to:

1. Run stage 2 (parse_and_classify) over the entire RX burst before
   any packet enters stage 5.
2. Same for stages 5, 6, 7, 9, 10, 11.
3. Accumulate per-packet outcomes in `Vec<StageOutput>` between
   stages, drained per stage.

Phase 2 does NOT require a new `PacketBatch<N>` SoA struct (#1127);
the existing scratch_forwards-style boundary can be replicated for
each stage. A separate `PacketBatch` redesign is independent.

## Risk assessment

- **Architectural mismatch risk** (the #961 dead-end pattern):
  **LOW**. Phase 1 is pure code motion — it cannot push the codebase
  toward a wrong architecture because it doesn't introduce new
  abstractions beyond two enums (StageOutcome<T> generic and
  FabricIngressOutcome named struct). The named functions are just
  labels for existing inline code blocks.
- **Behavioral regression risk**: **LOW**. No state shape or order
  changes. The enum-based outcomes make every early-return arm
  explicit at the type level (the compiler will catch any missed
  recycle path).
- **Borrow-checker risk on stage_native_gre_decap**: addressed in
  v2 by returning `Option<Vec<u8>>` and letting the caller bind the
  slice. No self-referential return type.
- **Scope creep risk**: explicitly bounded — flow-cache fast path
  (stage 12) and stages 13–16 stay inline. They will be tackled in
  follow-up phases.

## Out of scope (explicitly)

- True batched stage iteration (Phase 2+).
- `PacketBatch<N>` SoA struct (#1127).
- `PacketEditor` builder for the rewrite half (#963).
- Decoupling control plane from data plane (#948).
- HAL abstraction (#987).
- Flow-cache fast path extraction (Phase 1.5 / 2).
- Session lookup, policy, NAT, forwarding, MissingNeighbor stages
  (Phase 2+).

## Open questions for adversarial review

1. Phase 1 extracts 8 stages and leaves stages 12–16 inline. Is this
   the right scope for one PR, or should the extraction split into
   two smaller PRs (e.g., stages 1–6 first, then 7–11)?
2. (Resolved per Codex round-2 Q2.) `LinkLayerOutcome` had 4 arms (ArpLearnAndRecycle, ArpRecycle,
   NdpLearnAndContinue, Continue). The first two collapse to "recycle"
   from the caller's perspective; only the side effects on
   dynamic_neighbors differ. Should the helper consume the side
   effect internally and the outcome reduce to RecycleAndContinue +
   Continue?
3. `stage_classify_fabric_ingress` returns `(Option<u16>, bool)`. The
   caller uses both the `ingress_zone_override` and the
   `packet_fabric_ingress` flag downstream. Should this be a struct
   with named fields instead of a tuple?
4. The plan separates stage_screen_check (10) from
   stage_ipsec_passthrough_check (11). They both have shape
   `StageOutcome<()>` and run sequentially. Is fusing them worth
   the loss of granularity?
5. Does any reviewer see a hidden invariant between stages that this
   plan would break? Specific traps to check: telemetry counter
   ordering, recycle-on-error path completeness, and meta_flags
   propagation through GRE decap → flow parse → fabric classify.
