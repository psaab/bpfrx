# #946 Phase 1 — Extract Per-Packet Sub-Stages from `poll_binding_process_descriptor`

Status: **DRAFT — pending adversarial plan review**

## Issue framing

#946 asks for a VPP / `rte_graph` style batched pipeline where the
worker loop iterates over *batches per stage*, not stages per packet.

This Phase 1 plan does **not** ship that final architecture. Phase 1
extracts the existing per-packet body of
`poll_binding_process_descriptor` (currently 2,436 LOC, one giant
`while let Some(desc) = received.read()` loop) into a small set of
named per-packet helper functions. No batch reordering, no
stage-per-batch iteration. This is pure code-motion that establishes
the seams a future Phase 2/3 will exploit to swap to batched stages.

The final pipeline architecture (true VPP-style) requires a
`PacketBatch<N>` SoA buffer (#1127) and the `PacketEditor` builder
(#963) — those are independent issues with their own plans. Phase 1
is a precondition: without seams, the future batched extraction would
have to do all of code-motion + batching at once, which is the
"all-or-nothing risky refactor" pattern that previous attempts
(#961 PacketContext rounds 1–2) failed at.

## What's already batched

The codebase **already** has a coarse per-RX-burst batch boundary:

- `binding.scratch.scratch_forwards: Vec<PendingForwardRequest>` accumulates forwarding decisions during the RX while-let.
- After the loop drains, `enqueue_pending_forwards` (in `tx/dispatch.rs`) iterates the batch and dispatches to local TX or cross-worker MPSC.
- `binding.scratch.scratch_recycle: Vec<u64>` collects UMEM frame addresses to recycle, drained after the batch.
- `binding.scratch.scratch_rst_teardowns: Vec<...>` collects RST-driven session teardowns, drained after the batch.

This means Phase 1 is **adding seams to the per-packet path inside
the while-let** — the batch boundary itself is unchanged.

## What's NOT batched (the Phase 1 target)

Inside the while-let body, every packet goes through this sequence:

1. `record_rx_descriptor_telemetry(desc, area, telemetry, worker_ctx)`
2. `try_parse_metadata` → `Option<UserspaceDpMeta>` (early return on None)
3. `classify_metadata` → `PacketDisposition` (early return on Invalid)
4. UMEM area slice for raw frame bytes (early return on None)
5. **ARP / NDP classification** — early-return paths that recycle the
   frame and continue without flowing through the rest of the pipeline
   (ARP) or fall through (NDP NA).
6. **Native GRE decap** — replaces meta and frame-slice, may own a
   decapped frame.
7. `parse_session_flow_from_bytes` → `Option<SessionFlow>`
8. Dynamic-neighbor learning from the source IP (host-only).
9. Fabric-ingress detection + `meta.meta_flags |= FABRIC_INGRESS_FLAG`.
10. Screen/IDS check (slow path, only runs when profiles configured).
11. Session lookup → fast-path / slow-path branch.
12. Slow path: policy eval → NAT slot → forwarding lookup → push to
    `scratch_forwards`.
13. Fast path: hit existing session → push to `scratch_forwards`.
14. Reverse-NAT and ICMP slow-path arms.
15. MissingNeighbor side-queue: build session metadata, install,
    publish, push to `pending_neigh`.

That's ~2,400 LOC of branchy per-packet code in one function.

## Phase 1 scope: extract by-stage, no behavioral change

Extract into named functions, file-internal in
`afxdp/poll_descriptor.rs` or sibling files under `afxdp/poll/`:

1. **`stage_record_rx_telemetry`** — wraps step (1).  Takes a `&XdpDesc`,
   the `*const MmapArea`, telemetry, worker_ctx. Returns nothing.

2. **`stage_parse_and_classify`** — wraps steps (2)–(4). Takes the raw
   inputs, returns either `StageOutcome::RecycleAndContinue` or
   `StageOutcome::Continue { meta, raw_frame: &[u8] }`.

3. **`stage_link_layer_classify`** — wraps step (5) ARP / NDP. Returns
   `StageOutcome::RecycleAndContinue` (ARP request/reply/other) or
   `StageOutcome::Continue { learn_neighbor: Option<NeighborLearnHint> }`
   for NDP NA + IP fall-through.

4. **`stage_native_gre_decap`** — wraps step (6). Returns updated
   `meta`, optional owned decap frame, and the active frame slice
   (borrowing one of the two).

5. **`stage_parse_flow_and_learn`** — wraps steps (7)–(8). Returns
   `Option<SessionFlow>` and updates dynamic_neighbors as a side effect.

6. **`stage_classify_fabric_ingress`** — wraps step (9). Mutates `meta`
   in place.

7. Steps (10)–(15) stay in the main function for Phase 1. They have
   complex control flow (early-return arms for fast/slow path, NAT,
   ICMP, missing-neighbor side queue) that doesn't have clean seams
   yet. Phase 2 will tackle these once Phase 1 lands.

## What stays per-packet

All of (1)–(15) stay per-packet within the while-let. The only
change is that (1)–(9) become named function calls instead of inline
code. The semantic order and branching of the loop body is byte-for-byte
unchanged at the IR level (modulo whatever rustc inlines).

This means:
- No new allocations
- No new branches
- No new state
- No new types beyond `StageOutcome` (a small enum with two arms)
- No reordering of side effects

## Why this is safe / shippable

- **Pure code motion**: each extracted function returns the same
  values the inline code would have produced; control flow is
  preserved by the `StageOutcome` enum's two arms.
- **No SessionState, SessionTable, FlowCache, ScreenState mutability
  changes**: those are all in steps (10)–(15) which Phase 1 leaves
  alone.
- **No worker_ctx field shape changes**: the extracted functions take
  `worker_ctx: &WorkerContext` by reference, identical to today.
- **Compiler-driven verification**: extracting a function and
  inlining its callsite is a transformation rustc can verify via
  type-checking the function signature.
- **Smoke is the same**: v4 + v6 iperf3 against
  172.16.80.200 / 2001:559:8585:80::200 on the loss userspace cluster.
  No throughput regression expected (rustc is likely to re-inline the
  small extracted helpers anyway).

## Why a future phase is required

Phase 1 doesn't realize the L1-i locality benefit #946 cites because
each packet still walks all stages before the next packet starts. To
realize the benefit, **Phase 2** would need to:

1. Add a `PacketBatch<N>` SoA struct (or use the existing
   `scratch_forwards` shape) holding parsed-and-classified packets.
2. Run stage 2 (parse_and_classify) over the entire RX burst before
   any packet enters stage 3.
3. Run stage 3 (link_layer_classify) over the surviving packets
   before stage 4. Etc.

Phase 2 is **gated on**:
- #1127 (PacketBatch SoA struct) — cleanest concrete prerequisite.
- The existing `scratch_forwards` boundary growing to cover the
  per-packet half of the loop too (i.e., `scratch_parsed`,
  `scratch_classified`, etc.).

Phase 1 does NOT block on these. It's a pure refactor that makes
Phase 2 mechanical.

## Risk assessment

- **Architectural mismatch risk** (the #961 dead-end pattern):
  **LOW**. Phase 1 is pure code motion — it cannot push the codebase
  toward a wrong architecture because it doesn't introduce new
  abstractions. The named functions are just labels for existing
  inline code blocks.
- **Behavioral regression risk**: **LOW**. No state shape or order
  changes. The enum-based StageOutcome makes the early-return arms
  explicit at the type level (the compiler will catch any missed
  recycle path).
- **Test coverage**: existing 952-test cargo suite + 30 Go test
  packages + smoke run on the cluster.
- **Rollback**: trivially revertable (each extraction is one commit's
  code motion).

## Out of scope (explicitly)

- True batched stage iteration (Phase 2+).
- `PacketBatch<N>` SoA struct (#1127).
- `PacketEditor` builder for the rewrite half (#963).
- Decoupling control plane from data plane (#948).
- HAL abstraction (#987).

## Open questions for adversarial review

1. Is "code motion only, no behavior change" the right scope, or
   should Phase 1 also introduce the `PacketBatch<N>` struct (#1127)
   to avoid two refactors of the same code?
2. The `StageOutcome` enum — should it be one type with multiple
   arms, or should each stage have its own outcome type?
3. ARP / NDP classification at step (5) currently has 5 distinct
   branches (Reply, Request, Other, NA-with-mac, NotArp). Should
   these be flattened into a single `LinkLayerOutcome` enum, or
   should each stage have its own?
4. Step (8) "learn dynamic neighbor from packet" is a side effect on
   `worker_ctx.dynamic_neighbors` and `binding.last_learned_neighbor`.
   Should this be split into a separate stage (per the issue's
   preference for stage purity), or kept as part of
   `stage_parse_flow_and_learn` since the data flow is identical?
5. Are there hidden ordering invariants between the listed stages
   (e.g., does the screen check at step (10) implicitly depend on a
   side effect from step (5) ARP early-return)? My read is no, but
   this is the kind of trap that breaks pure code-motion refactors.
