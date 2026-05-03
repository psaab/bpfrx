# #946 Phase 2 — Batched per-stage iteration over the RX burst

Status: **KILLED v1 — Codex + Gemini both PLAN-KILL on round 1.**

## Why this plan was killed

Both Codex (task-moqfellt-385s0f) and Gemini (task-moqffrq8-0hdpe7)
independently returned **PLAN-KILL** verdicts on round 1. Both
reviewers identified the same fundamental defect: the
"harness-building for Phase 3" justification fails because
**Phase 3 is not batchable as a per-stage reorder**.

### Phase 3 unbatchability — concrete evidence

Stages 12-16 (the heavy stages where the L1-i benefit would
actually live) each carry immediate cross-packet state
dependencies:

- **Flow-cache lookup** (`afxdp/flow_cache.rs:384`,
  `flow_cache.rs:409`, `flow_cache.rs:436`) mutates LRU
  counters and can evict entries on each call. Slow-path
  miss inserts new entries at `poll_descriptor.rs:1787`.
  Packet N's lookup can evict an entry that packet N+1's
  lookup would have hit.
- **Session resolution** — `resolve_flow_session_decision`
  takes `&mut SessionTable` (`session_glue/mod.rs:954`)
  and may materialize/promote/install sessions
  (`session_glue/mod.rs:1015,1056,1084`). Packet N's session
  install is visible to packet N+1's lookup; reordering
  breaks the install-before-lookup invariant.
- **MissingNeighbor side queue** — explicitly order-coupled
  (`poll_descriptor.rs:1903,1981,2038`): probe, install seed
  session, publish maps, push to pending_neigh. Reordering
  these steps even within a single packet is unsafe; across
  packets it's much worse.

Conclusion: stages 12-16 cannot be transformed from
per-packet to per-stage iteration without losing semantics.
Phase 2's "harness for Phase 3" therefore has no successor —
the harness builds toward a Phase 3 that doesn't exist.

### Phase 2 also has direct defects

Even if Phase 3 were achievable, the Phase 2 plan has its own
defects identified by Codex:

- **Loop 5 borrow-checker conflict** — the sketch holds
  `let active = pkt.active_slice()` while calling
  `stage_classify_fabric_ingress(active, &mut pkt.meta, ...)`.
  `pkt.meta` is reborrowed mutably while a slice borrowed
  from `pkt` is still live. Fixable but the v1 sketch is
  wrong.
- **Observable reorder of IPsec reinject vs slow-path** —
  in Phase 1, an earlier packet's stage-12+ slow-path can
  enqueue to TX before a later packet's stage-11 IPsec
  reinject. In Phase 2 (per-stage), all stage-11 IPsec
  reinjections fire before Loop 8 starts. This is a real
  behavioral change in the wire-side ordering of TX events.

### Why this is the right outcome

The plan v1 explicitly invited PLAN-KILL: *"If Codex / Gemini
round-1 review concludes the harness-building value is
insufficient to justify the churn, the right move is to
**stop and reframe** — don't ship Phase 2 just because it's
'next.'"* Both reviewers exercised that escape hatch.

This matches the project's documented `feedback_difficult_path_pragmatism`
rule: "for `Refactor: <Pattern>` issues proposing large
rearchitectures, stop and report rather than ship a wrong-target
PR." #946 batched-pipeline batched-iteration falls in this class.

### Recommendation for #946 itself

The full VPP / `rte_graph` rearchitecture proposed by #946 would
require **rebuilding the dataplane around immutable-state
snapshots taken at burst boundaries** (so each per-stage iteration
can read consistent state without write-after-read hazards). That
is not a Phase-2 increment of the existing pipeline — it's a
fundamental redesign of session lookup, NAT slot allocation, FIB
caching, and the MissingNeighbor side queue.

Phase 1 (PR #1179) shipped because pure code motion has no
architectural premise to fail. The next achievable increment for
this code area is probably one of:

- **Smaller, targeted hot-path optimizations** within the
  existing per-packet structure (e.g., #779 `enqueue_pending_forwards`
  Arc<SessionKey> vs clone, #777 RX hot-path inlining).
- **Phase 1.5** — extract the stages 12-16 inline blocks into
  named helpers within the per-packet body (mirrors Phase 1's
  scope for the slow path; pure code motion).

Phase 2 batched iteration is **not** on that achievable path.

## Codex round-1 verbatim (task-moqfellt-385s0f)

[See task result for full text — key conclusions reproduced above.]

## Gemini round-1 verbatim (task-moqffrq8-0hdpe7)

[See task result for full text — key conclusions reproduced above.]

---

# Original plan v1 follows for the historical record

## Issue framing

Phase 1 (PR #1179, master commit 92e730e5) extracted seven
per-packet sub-stages out of the inline while-let body in
`poll_binding_process_descriptor` into named helpers in
`afxdp/poll_stages.rs`. Phase 1 is **pure code-motion**: each
packet still walks all stages before the next packet starts. The
L1-i locality benefit #946 cites is NOT yet realized because the
instructions for stage_X aren't kept hot across multiple packets.

Phase 2's job is to swap the per-packet loop into batched
**per-stage iteration over the RX burst** — VPP / `rte_graph`
style. Each Phase-1 stage runs once over the entire burst before
the next stage starts. The instructions for stage_X stay hot in
L1i for all N packets in the batch.

## Honest scope/value framing

Phase 2 batching of stages 5-11 alone may deliver a marginal,
hard-to-measure perf win. The reasons:

- Stages 5-11 are **short** (~20-100 LOC each). Modern
  out-of-order CPUs hide most of their L1-i pressure already.
- The big L1-i pollutors per #946 are stages 12-16 (flow cache,
  session lookup, slow-path policy/NAT/forwarding,
  reverse-NAT/ICMP, MissingNeighbor side queue) — those are
  ~1,500+ LOC and DO bloat L1i. Phase 2 explicitly does NOT
  batch those.
- Per-stage `Vec<StageOutput>` accumulator pushes/pops add
  overhead that may erase any L1-i gain on the prelude stages.

So Phase 2's primary value is **harness-building**, not perf:

- Establish the batched-iteration pattern (per-stage Vec
  accumulator, `recycle: bool` flag on per-packet state, deferred
  recycle drain).
- Verify the pattern on stages 5-11 where the data flow is
  well-understood from Phase 1 extraction.
- Provide the seam that Phase 3 (batching stages 12-16, where
  the L1-i benefit actually lives) can plug into.

If Codex / Gemini round-1 review concludes the harness-building
value is insufficient to justify the churn, the right move is to
**stop and reframe** — don't ship Phase 2 just because it's
"next."

## What's already partially batched

Same as Phase 1: `binding.scratch.scratch_forwards`,
`scratch_recycle`, `scratch_rst_teardowns` are per-RX-burst
accumulators drained after the loop. The flow-cache fast path
bypasses scratch_forwards and pushes directly to
`pending_tx_prepared` from inside the per-packet body
(poll_descriptor.rs:306, 369 — line numbers approximate, will
have shifted post-Phase-1).

Phase 2 adds new per-stage Vec accumulators **upstream** of
scratch_forwards. The existing batch boundaries are unchanged.

## Phase 2 architectural design

### `ParsedPacket` struct

A new `ParsedPacket<'a>` struct holds the per-packet state that
flows through stages 5-11:

```rust
pub(super) struct ParsedPacket<'a> {
    pub(super) desc: XdpDesc,
    pub(super) meta: UserspaceDpMeta,
    pub(super) raw_frame: &'a [u8],
    /// Owned decap frame from stage 6. `mut` because deferred
    /// stage-12+ code calls `.take()` on it.
    pub(super) owned_packet_frame: Option<Vec<u8>>,
    /// Set by stage 7+8 from the active slice
    /// (owned_packet_frame.as_deref().unwrap_or(raw_frame)).
    pub(super) flow: Option<SessionFlow>,
    /// Set by stage 9.
    pub(super) ingress_zone_override: Option<u16>,
    /// Set by stage 9.
    pub(super) packet_fabric_ingress: bool,
    /// Set to true by any stage that wants the caller to recycle
    /// the UMEM frame and skip the rest of the pipeline. The
    /// stage's side effects (ARP/NDP learn, screen drops, IPsec
    /// reinject) fire INSIDE the helper before this flag is set,
    /// matching Phase 1 behavior.
    pub(super) recycle: bool,
}
```

**Why no `packet_frame: &'a [u8]`** — that would be
self-referential against `owned_packet_frame: Option<Vec<u8>>`.
Instead, a small helper method `pkt.active_slice()` returns
`owned_packet_frame.as_deref().unwrap_or(raw_frame)`. Stages
that need the active slice call this method.

### Batch accumulator

The `BindingWorker` gains a new scratch field
`scratch_parsed: Vec<ParsedPacket<'static>>` — wait. This has a
lifetime problem: the `raw_frame: &'a [u8]` borrows from UMEM,
and the `Vec` lives across the while-let. We can't store
references with a `'static` lifetime if they actually borrow
from UMEM.

**Solutions to evaluate** (open question for review):

A. **Stack-local Vec, allocated once per RX burst.**
   `let mut parsed: Vec<ParsedPacket<'_>> = Vec::with_capacity(RX_BATCH_SIZE)`
   inside `poll_binding_process_descriptor`. Lifetime tied to
   the function scope. Simple but allocates every call (RX_BATCH_SIZE
   == 64 typically).

B. **Pre-allocated scratch on `BindingWorker.scratch`** with
   `unsafe` lifetime erasure (transmute the lifetime to `'static`
   at insert, transmute back at iterate). Avoids per-call alloc
   but unsafe.

C. **Pre-allocated scratch with raw pointer + length**, treating
   each ParsedPacket's raw_frame as a `(ptr, len)` pair instead
   of a `&[u8]`. Loses the borrow-checker guarantee that the
   slice is valid; relies on the UMEM staying alive (which it
   does for the function scope). Less unsafe than B.

D. **Don't store raw_frame in ParsedPacket at all** — recompute
   it per-stage from `desc.addr + area`. Adds a slice
   per-packet-per-stage but trivially correct.

My recommendation: **A** for the first iteration. Vec::with_capacity
of 64 elements is cheap (one malloc). The "no per-packet
allocation" rule from CLAUDE.md applies to per-PACKET allocs;
per-BURST allocations are fine and the existing scratch_forwards
already does this.

### Main-loop transformation

Pre-Phase-2 (current state, ~200 LOC):
```rust
while let Some(desc) = received.read() {
    record_rx_descriptor_telemetry(...);
    let mut recycle_now = true;
    if let Some(meta) = try_parse_metadata(...) {
        // ... stages 5-11 inline-call helpers ...
        // ... stages 12-16 inline ...
    } else { /* metadata parse failure */ }
    if recycle_now { recycle.push(desc.addr); }
}
```

Post-Phase-2 (sketch):
```rust
let mut parsed: Vec<ParsedPacket<'_>> =
    Vec::with_capacity(RX_BATCH_SIZE as usize);

// Loop 1: parse, classify, slice → ParsedPacket. Failures
// recycle directly (matching pre-Phase-2 behavior).
while let Some(desc) = received.read() {
    record_rx_descriptor_telemetry(...);
    if let Some(meta) = try_parse_metadata(...) {
        telemetry.counters.metadata_packets += 1;
        let disposition = classify_metadata(meta, validation);
        if disposition == PacketDisposition::Valid {
            telemetry.counters.validated_packets += 1;
            telemetry.counters.validated_bytes += desc.len as u64;
            if let Some(raw_frame) = unsafe { &*area }.slice(...) {
                parsed.push(ParsedPacket {
                    desc, meta, raw_frame,
                    owned_packet_frame: None,
                    flow: None,
                    ingress_zone_override: None,
                    packet_fabric_ingress: false,
                    recycle: false,
                });
            } else {
                binding.scratch.scratch_recycle.push(desc.addr);
            }
        } else {
            record_disposition(...);
            binding.scratch.scratch_recycle.push(desc.addr);
        }
    } else {
        // metadata parse failure
        record_exception(...);
        binding.scratch.scratch_recycle.push(desc.addr);
    }
}

// Loop 2 (stage 5): link-layer classify over the batch.
for pkt in parsed.iter_mut() {
    if pkt.recycle { continue; }
    if let StageOutcome::RecycleAndContinue =
        stage_link_layer_classify(pkt.raw_frame, pkt.meta, worker_ctx)
    {
        pkt.recycle = true;
    }
}

// Loop 3 (stage 6): GRE decap.
for pkt in parsed.iter_mut() {
    if pkt.recycle { continue; }
    let (new_meta, owned) =
        stage_native_gre_decap(pkt.raw_frame, pkt.meta, worker_ctx.forwarding);
    pkt.meta = new_meta;
    pkt.owned_packet_frame = owned;
}

// Loop 4 (stage 7+8): parse flow + learn neighbor.
for pkt in parsed.iter_mut() {
    if pkt.recycle { continue; }
    let active = pkt.active_slice();
    pkt.flow = stage_parse_flow_and_learn(
        unsafe { &*area },
        pkt.desc,
        active,
        pkt.meta,
        pkt.owned_packet_frame.is_none(),
        &mut binding.last_learned_neighbor,
        worker_ctx,
    );
}

// Loop 5 (stage 9): fabric ingress.
for pkt in parsed.iter_mut() {
    if pkt.recycle { continue; }
    let active = pkt.active_slice();
    let outcome = stage_classify_fabric_ingress(active, &mut pkt.meta, worker_ctx);
    pkt.ingress_zone_override = outcome.ingress_zone_override;
    pkt.packet_fabric_ingress = outcome.packet_fabric_ingress;
}

// Loop 6 (stage 10): screen check.
for pkt in parsed.iter_mut() {
    if pkt.recycle { continue; }
    let active = pkt.active_slice();
    if let StageOutcome::RecycleAndContinue = stage_screen_check(
        pkt.flow.as_ref(), active, pkt.meta, pkt.ingress_zone_override,
        now_secs, screen, &binding.live, worker_ctx,
    ) {
        pkt.recycle = true;
    }
}

// Loop 7 (stage 11): IPsec passthrough.
for pkt in parsed.iter_mut() {
    if pkt.recycle { continue; }
    let active = pkt.active_slice();
    if let StageOutcome::RecycleAndContinue = stage_ipsec_passthrough_check(
        pkt.flow.as_ref(), active, pkt.meta, &binding.live, worker_ctx,
    ) {
        pkt.recycle = true;
    }
}

// Loop 8 (deferred stages 12-16, per-packet): the entire flow-
// cache fast path, session lookup, slow-path policy/NAT/
// forwarding, reverse-NAT/ICMP, MissingNeighbor side queue.
// This is unchanged from Phase 1 — moved into a per-packet
// for-loop below the batched stages.
for pkt in parsed.iter_mut() {
    if pkt.recycle { continue; }
    let mut recycle_now = true;
    let active = pkt.active_slice();
    // ... stages 12-16 inline (lifted as-is from Phase 1) ...
    if recycle_now {
        binding.scratch.scratch_recycle.push(pkt.desc.addr);
    }
}

// Loop 9: drain recycled packets.
for pkt in parsed.iter() {
    if pkt.recycle {
        binding.scratch.scratch_recycle.push(pkt.desc.addr);
    }
}
parsed.clear();
```

### Per-stage Vec — reuse across calls?

`BindingWorker` already has a pattern for per-burst scratch
buffers (`scratch_recycle`, `scratch_forwards`,
`scratch_rst_teardowns`). The new `scratch_parsed` would slot
beside them. Reusing the Vec across calls (clear + push)
amortizes the allocation away.

But reusing means the lifetime is tied to the function call
boundary, not the Vec's storage. We need either:
- A Vec on the function stack (allocates per call).
- A Vec stored in `WorkerScratch` with manual lifetime
  management (some unsafe).

Given the per-burst pattern of existing scratch fields,
**option B** above (pre-allocated, clear+push) is the natural
fit. Need to verify lifetime sound with a small `unsafe`
block — or accept the per-call alloc for v1 and optimize later.

## Hidden invariants Phase 2 must preserve

(Same as Phase 1, plus new ones for batched iteration.)

- **Side-effect ordering inside a stage**: stage_link_layer_classify's
  ARP-learn fires before the recycle flag is set. Preserved.
- **Side-effect ordering across stages**: stage 5 fires fully
  before stage 6 starts on ANY packet. Different from Phase 1
  where stage 5 of packet N fires before stage 5 of packet N+1.
  This IS a behavioral change — previously stage 6 of packet N
  fired before stage 5 of packet N+1; now stage 5 of packet N+1
  fires first.
  - **Trap**: does any stage's side effect interact with a later
    stage's input on a DIFFERENT packet? Specifically: does ARP
    learn from packet N (stage 5) feed dynamic_neighbors which
    stage 7+8 of packet N+1 reads? **YES** — but the existing
    Phase-1 ordering already has packet N's stage 5 fire before
    packet N+1's stage 7+8, which is the same after batching
    (stage 5 batch fully drains before stage 7+8 batch starts).
    So the inter-packet interaction is preserved.
  - Other potential traps to validate: kernel ARP/NDP table
    updates (kernel-side), screen rate limiting (per-zone state),
    IPsec slow-path TUN reinject (per-packet, no inter-packet
    state).
- **Metadata parse failure / non-Valid disposition recording**
  fires from Loop 1 (per-packet record_exception /
  record_disposition path). Same ordering as pre-Phase-2.
- **`raw_frame` lifetime** — must outlive the entire batch.
  Since UMEM is mapped for the worker's lifetime and the batch
  drains before the next RX burst, this is safe. The borrow
  checker may need help (option B's unsafe transmute, or
  option A's stack-scope Vec).

## Risk assessment

- **Behavioral change risk**: MEDIUM. Per-stage iteration
  reorders cross-packet side effects (e.g., packet N's stage 6
  now fires before packet N+1's stage 5). For stages 5-11
  the analysis above suggests no interaction trap, but rounds
  of review will be hostile here.
- **Lifetime / borrow-checker risk**: MEDIUM. Storing &[u8]
  borrows in a struct held in a Vec is the classic
  self-referential-feeling pattern. May force option D
  (recompute slice per stage) which adds overhead.
- **Performance regression risk**: LOW-MEDIUM. The per-stage
  `if pkt.recycle { continue; }` branch + Vec push/pop adds
  cost. Stages 5-11 are short enough that the L1-i win may not
  cover this. Smoke must show no throughput regression on the
  loss userspace cluster.
- **Architectural mismatch risk** (#961 dead-end pattern):
  MEDIUM. The "ParsedPacket struct" pattern was tried for #961
  PacketContext and failed at plan review because the 4
  boundary types didn't fit. Phase 2's ParsedPacket has DIFFERENT
  scope (just stages 5-11, not the full pipeline) so the failure
  mode may not apply. But review must validate this.

## Test plan

- `cargo build` clean (no new warnings).
- 952+ cargo tests pass (`cargo test --release`).
- Named flow_cache test 5/5 flake check.
- 30 Go test packages pass.
- Deploy clean on loss userspace cluster.
- v4 + v6 smoke against 172.16.80.200 / 2001:559:8585:80::200,
  best-effort port 5201.
- Per-class CoS smoke on all 6 classes (5201-5206) — refactor PR
  rule from CLAUDE.md.

## Out of scope (explicitly)

- Batching stages 12-16 (Phase 3+).
- Removing stages 1-4 from the per-packet pre-loop (Phase 1 left
  them inline; Phase 2 also leaves them inline for the parse
  loop — this is the same scope choice, just with batched
  iteration after).
- Introducing `PacketBatch<N>` SoA (#1127 — independent issue).
- `PacketEditor` Builder pattern for the rewrite half (#963).

## Open questions for adversarial review

1. **Is Phase 2 worth shipping if the L1-i benefit is marginal?**
   The honest framing is "harness-building for Phase 3+" — is
   that sufficient justification, or should we wait until Phase
   3+ is concretely planned before building the harness?
2. **Lifetime / borrow-checker shape of ParsedPacket** — option
   A (per-call Vec), B (scratch with unsafe transmute), C
   (raw ptr + len), or D (recompute slice)? Default is A; what
   trade-off changes between them?
3. **Cross-packet side-effect reordering trap analysis** — the
   plan claims no interaction trap exists for stages 5-11. Is
   this complete? Specific concerns:
   - Does ARP/NDP learn from packet N affect dynamic_neighbors
     read by stage 7+8 of packet N+1?
   - Does screen rate limiting (per-zone state) get applied in
     a different order under batching?
   - Does IPsec slow-path TUN reinject from packet N affect any
     state visible to packet N+1?
4. **Should Loop 8 (stages 12-16, per-packet) live in
   `poll_descriptor.rs` or in a new `poll_slow_path.rs` sibling**
   so the batched-stages module is self-contained?
5. **Should the new ParsedPacket struct live in `poll_stages.rs`
   or in a new `poll_batch.rs`** so the existing per-packet
   stage helpers don't have to know about the batch type?
6. **Should Phase 2 include a perf measurement step** (perf stat
   on the loss cluster before/after) to confirm no regression
   AND quantify any gain? The plan currently lists smoke as the
   only perf gate.
