---
status: DRAFT v1 — pending adversarial plan review
issues: #946, #947, #948, #949, #961, #963, #987, #1127, #1144, #1146, #1163, #1164, #1165, #1166, #1187, #1188, #1189
phase: Triage — codebase-reality check before any implementation
---

## 1. Why one triage doc for 17 issues

These 17 are the entire current "Refactor: <Pattern>" tail in the
open-issues backlog. They follow the same template that PLAN-KILLed
all four SIMD issues (#966/#967/#968/#969) in a unanimous 8/8 review
on 2026-05-05: "The 'Amateur' Anti-Pattern" → "The CPU Reality" →
"The Design Pattern Fix" → bullet-list of intrinsics or trait
rearrangements. Same shape also killed #946 Phase 2, #961 (twice),
#963, #1144, #747, #761.

The user-set workflow (`feedback_difficult_path_pragmatism.md`) is
explicit: for "Refactor: <Pattern>" issues, the right move is often
**not** to ship code — measure first, and if the proposed pattern's
premise doesn't match the codebase, KILL.

This single doc audits each issue's central claim against the code
on master (`dab78ef6`), then dispatches one Codex hostile review and
one Gemini Pro 3 adversarial review per issue. Verdicts converge into
PLAN-KILL or NEEDS-MAJOR per issue.

## 2. Fresh perf measurement context (master HEAD `b029e91c`, P=12 -R)

| % CPU | Symbol | Tracker |
|---:|---|---|
| 13.43 | `__memmove_evex_unaligned_erms` | #776 cross-worker frame body memcpy (already AVX-512) |
| 9.45 | `poll_binding_process_descriptor` | #777 RX hot path |
| 5.94 | bpf_prog (XDP) | XDP redirect program |
| 4.50 | `worker_loop` | xpf-userspace-dp main loop |
| 4.20 | `enqueue_pending_forwards` | #779 TX dispatch |
| 1.52 | `htab_map_hash` | #761 KILLED — BPF hash probe |
| 0.95 | `mlx5e_xsk_skb_from_cqe_linear` | #778 closed — SKB fallback |

**No symbol** in the top hotspots corresponds to any Tier D issue's
prescribed target. None of these issues address the measured cost
sources. Each proposes a refactor to a code path that doesn't appear
on the profile.

## 3. Per-issue codebase reality

### #946 — Pipeline / Chain of Responsibility Pattern (parent)

**Claim:** monolithic per-packet RX→Parse→NAT→Route→CoS→TX block,
should be VPP-style batched per-stage.

**Reality:**
- **Phase 1 SHIPPED** (`refactor/946-phase1`, PR #1179): six per-packet
  stages extracted to `userspace-dp/src/afxdp/poll_stages.rs`. This
  is the achievable scope.
- **Phase 2 PLAN-KILLED 2026-05-03** by both reviewers
  (`project_946_phase2_plan_killed.md`): batched per-stage iteration
  is structurally impossible because:
  - `flow_cache.rs:384,409,436` — lookup mutates LRU; reorder evicts
    entries the next packet would have hit.
  - `session_glue/mod.rs:954` — `resolve_flow_session_decision` takes
    `&mut SessionTable` and may install/promote sessions.
  - `poll_descriptor.rs:1903,1981,2038` — MissingNeighbor side queue
    is order-coupled.
- The "real" full VPP rearchitecture would require rebuilding session
  lookup + NAT slot allocation + FIB caching + MissingNeighbor around
  immutable snapshots. Multi-quarter, no plan, not achievable
  incrementally.

**Verdict candidate:** KILL parent. Phase 1 is the achievable scope
and it shipped. Close as "Phase 1 done, Phase 2 KILLED, parent
issue effectively complete."

### #947 — Strategy Pattern for Protocol Parsing ("decouple L2/L3/L4")

**Claim:** "Around line 890 in `userspace-dp/src/afxdp.rs`, you are
doing inline byte-shifting … in the main poll loop."

**Reality:**
- `userspace-dp/src/afxdp.rs` **does not exist**. The afxdp module
  is decomposed into ~30 files under `userspace-dp/src/afxdp/`.
- Parsing is already extracted: `parser_tests.rs`, `ethernet.rs`,
  `gre.rs`, `icmp.rs`, `tunnel.rs`, `screen.rs`, etc.
- The `poll_descriptor.rs` inner loop dispatches by `meta` fields
  produced by these parsers, not by inline byte-shifting.

**Verdict candidate:** KILL — file/symbol claim is stale; the
prescribed Strategy split has effectively shipped via #959/#964
decomposition.

### #948 — Mediator / Message Broker for Control vs Data Plane

**Claim:** "The fast-path worker loop takes raw Linux file
descriptors like `conntrack_v4_fd: c_int` as arguments. … Worker
performs syscalls on the critical path."

**Reality:**
- `conntrack_v4_fd` is passed via `bpf_map.rs::install_session_v4`
  (`bpf_map.rs:447,450`) on **session install**, not per-packet.
  Session install runs at most once per new flow.
- xpf already has the prescribed Mediator: `mpsc_inbox.rs`
  (`mpsc_inbox_tests.rs` proves correctness). Coordinator pushes
  state; workers read lock-free from inbox.
- Per-packet workers do NOT call BPF map syscalls.

**Verdict candidate:** KILL — premise factually wrong (FD is
install-time, not per-packet); prescribed pattern (mpsc) already
shipped.

### #949 — RCU / Immutable State for Fast-Path Locks

**Claim:** "You are passing `Arc<Mutex<FastMap<...>>>` directly
into the hot path (e.g., `dynamic_neighbors`, `shared_sessions`)."

**Reality:**
- `dynamic_neighbors: Arc<ShardedNeighborMap>` — **already a sharded
  lock-free structure** (`sharded_neighbor.rs`). The shard split is
  exactly what #949 prescribes.
- `shared_sessions: Arc<Mutex<FastMap<…>>>` — yes, but used only on
  session install / cross-worker session sync (slow path), not on
  per-packet read.
- Per-packet session lookups go through `flow_cache` (lock-free
  per-binding) and `SessionTable` (per-binding `&mut` access).

**Verdict candidate:** KILL — `dynamic_neighbors` already sharded;
`shared_sessions` Mutex is install-path only, not hot path.

### #961 — Extract `PacketContext` per-packet ownership state machine

**Claim:** make per-packet ownership transitions
`Live → Owned → Prepared → Recycled` explicit via a typestate.

**Reality:**
- Already once flagged as dead-end
  (`feedback_difficult_path_pragmatism.md`: "#961 PacketContext
  (2 design rounds both PLAN-NEEDS-MAJOR)").
- The codebase has 4 distinct ownership types
  (`PendingForwardRequest`, `PendingForwardFrame`,
  `PreparedTxRequest.recycle`, `PendingNeighPacket`) for **good
  reason** — different lifetimes, different downstream consumers.
- A `PacketContext<'a>` typestate would either flatten these (loses
  information) or wrap them (no behavior change, plus borrow-checker
  fight).

**Verdict candidate:** KILL — already twice plan-rejected; the
existing 4-type ownership graph is load-bearing.

### #963 — Frame Rewriting God Function — Builder/State Pattern

**Claim:** `rewrite_forwarded_frame_in_place` in `frame.rs` is a
massive God Function that should split into `Ipv4Editor`/`Ipv6Editor`.

**Reality:**
- `frame.rs` no longer exists; `frame/` is now 8 files:
  ```
  frame/byte_writes.rs       81
  frame/checksum.rs         616
  frame/inspect.rs          744
  frame/mod.rs             1707
  frame/tcp.rs              266
  frame/tcp_segmentation.rs 338
  ```
- The function still exists at `frame/mod.rs:661`, but the costly
  work (cross-UMEM body memcpy) is in
  `build_forwarded_frame_into_from_frame()` at line 262 — **already
  separately tracked as #776**.
- An `Ipv4Editor`/`Ipv6Editor` split would change zero throughput;
  the body memcpy would still dominate.

**Verdict candidate:** KILL — misdiagnoses cost (rewrite-in-place
is sub-1%; #776's body memcpy is the 13.43% figure); module already
partially decomposed.

### #987 — HAL: Decouple pipeline from AF_XDP driver

**Claim:** Define `PacketSource` / `PacketSink` traits; provide
`MockDriver` for unit testing.

**Reality:**
- xpf is integration-tested through the real cluster smoke matrix
  (`loss:xpf-userspace-fw0/fw1`), which is what catches regressions.
- A `MockDriver` would bypass UMEM lifetime invariants — the most
  bug-prone part of the AF_XDP integration. Unit tests against a
  mock would not catch UMEM frame-life bugs.
- DPDK's `rte_eth_dev` PMD abstraction is cited but xpf's cost is
  not in driver dispatch; it's in body memcpy + RX poll. The trait
  refactor would gain testability we already get from cluster smoke.

**Verdict candidate:** KILL — theoretical-only; existing cluster
smoke already validates the integration.

### #1127 — "31-Parameter God Function" → vectorized PacketBatch

**Claim:** `poll_binding_process_descriptor` takes ~31 parameters;
replace with `PacketBatch<const N: usize>` SIMD-vectorizable struct.

**Reality:**
- `poll_binding_process_descriptor` has **15 parameters** today (see
  `poll_descriptor.rs:31`), not 31. The "31-parameter" premise is
  factually wrong (likely stale from before #959 decomposition).
- The proposed `PacketBatch` data structure runs into the same
  blocker as #946 Phase 2: per-stage iteration over a batch is
  unbatchable because flow_cache mutates LRU on lookup, session table
  needs `&mut`, and MissingNeighbor is order-coupled.
- "SIMD for glue logic like clearing dispositions" is sub-1% of CPU
  even if free.

**Verdict candidate:** KILL — premise factually wrong (15, not 31)
+ batched data structure runs into #946 Phase 2's PLAN-KILL.

### #1144 — Defer Session Setup for Missing Neighbors

**Claim:** Move MissingNeighbor flow into a side-queue *before*
policy/session evaluation; perform session setup only after neighbor
resolves.

**Reality:**
- Already once flagged as dead-end
  (`feedback_difficult_path_pragmatism.md`).
- "Expensive cryptographic session setup" is a misnomer — there is
  no crypto in session install. The cost is FastMap insert + slab
  allocation, ~hundreds of nanoseconds.
- Deferring would break SYN-ACK reverse-path during ARP resolution:
  if the SYN's session isn't installed when the SYN-ACK arrives back,
  the SYN-ACK gets misclassified.

**Verdict candidate:** KILL — already plan-rejected; the deferral
breaks SYN/SYN-ACK ordering during ARP resolution.

### #1146 — Decouple Protocol Parsing from Forwarding Pipeline

**Claim:** Split `poll_descriptor` inner loop into Stage 1 (RX +
telemetry), Stage 2 (vectorized parse), Stage 3 (vectorized lookup),
Stage 4 (TX dispatch). Same staged-pipeline target as #946.

**Reality:**
- Same blocker as #946 Phase 2: per-stage batched iteration is
  structurally impossible (flow_cache LRU mutation, SessionTable
  `&mut`, MissingNeighbor order coupling).
- Phase 1 of #946 is the achievable scope and shipped (PR #1179).

**Verdict candidate:** KILL — duplicate of #946 with a different
title. Same #946 Phase 2 blockers apply.

### #1163 — Recursive String-Based Routing — `next_table` is "IPC killer"

**Claim:** `lookup_forwarding_resolution_v4` uses recursion + String
comparisons on the **hot path**. "Blowing out the call stack",
"thrashing L1-d", "stalling CPU pipeline".

**Reality:**
- `lookup_forwarding_resolution*` is called from session install
  (`session_glue/mod.rs:58,73,115`), session re-resolution
  (`session_glue/mod.rs:346,438,527,1021,1107`), and shared_ops
  (`shared_ops.rs:540,804`). **Slow-path only**, not per-packet.
- Recursion is bounded with `depth + 1` increment and explicit
  cycle break (`if next_table_name == table { break; }`).
- Per-packet path uses `flow_cache` lookup (already O(1) hash) +
  `SessionTable` lookup (O(1) by integer key). No recursion, no
  String compare.

**Verdict candidate:** KILL — "IPC killer on hot path" is wrong by
call site; recursion is in slow-path session install / re-resolution
only, with bounded depth and cycle-break.

### #1164 — JSON Serialization Tax on Control Plane Sync

**Claim:** "ConfigSnapshot/InterfaceSnapshot heavily laden with
Strings/Vecs … JSON over Unix socket between Go and Rust takes tens
to hundreds of milliseconds."

**Reality:**
- `protocol.rs` does use `serde::{Deserialize, Serialize}` with
  String/Vec fields — this is true.
- The control socket sync is a **slow path**: snapshot at startup
  + delta-style updates via `session_delta.rs`. It does NOT happen
  per-packet. The "stop-the-world coordinator stall" claim is about
  startup snapshot, not steady state.
- For a 10K-route config, JSON parse is ~tens of ms — measured one
  time, at startup. Not a hot path cost.
- FlatBuffers/Cap'n Proto migration cost is multi-week + breaks
  Go↔Rust schema versioning.

**Verdict candidate:** KILL — slow-path cost, not hot path; no
measured per-packet impact.

### #1165 — Inline `thread_local!` in dispatch.rs / poll_descriptor.rs

**Claim:** `thread_local!` access compiles to TLS lookup
(`__tls_get_addr`); inside 14.8M pps loop bloats L1-i.

**Reality:**
- `tx/dispatch.rs:368` — `thread_local! SEG_MISS_LOG` is gated by
  `if !copied_source_frame && source_frame.len() > 1514` — only
  fires on segmentation miss (rare path), rate-limited to 20 events.
- `poll_descriptor.rs:2226` — `thread_local! OVERSIZED_RX_LOG` is
  gated by `if cfg!(feature = "debug-log")` — compile-time gated,
  zero cost in release builds.
- `poll_descriptor.rs:2273` — `thread_local! RX_RST_LOG_COUNT` —
  gated by `cfg!(feature = "debug-log")`.

**Verdict candidate:** KILL — release-build hot path has zero
`thread_local!` cost; the cited sites are all debug-feature-gated
or rare-event rate-limited.

### #1166 — Software TSO 250-line inline God Function in dispatch.rs

**Claim:** `segment_forwarded_tcp_frames_into_prepared` is a 250-line
inline function in `tx/dispatch.rs` that "destroys pipeline
throughput" via cache thrashing + instruction bloat.

**Reality:**
- TCP segmentation **already extracted** to a dedicated module:
  `userspace-dp/src/afxdp/frame/tcp_segmentation.rs` (338 lines).
- `tx/dispatch.rs:1204` defines `segment_forwarded_tcp_frames_into_prepared`
  as a thin XdpDesc adapter that delegates to
  `frame/tcp_segmentation.rs::segment_forwarded_tcp_frames_from_frame`.
- The issue's prescribed fix ("dedicated software stage in
  `afxdp/frame/segmentation.rs`") **has already shipped**.

**Verdict candidate:** KILL — issue's prescribed fix already shipped;
file structure cited in the issue is stale.

### #1187 — Double-Buffered Telemetry to avoid MESI bouncing

**Claim:** `BindingLiveState`'s `AtomicU64` counters bounce cache
lines between worker core and coordinator core (different NUMA
nodes), causing MESI thrashing.

**Reality:**
- The lab cluster (`loss:xpf-userspace-fw0/fw1`) is **single-socket**
  — there is no cross-NUMA cache-line bouncing. The proposed
  optimization addresses a problem the deployment doesn't have.
- `BindingLiveState` is decomposed across sub-structs
  (`telemetry`, `scratch`, `cos`, `tx_counters`, `bpf_maps`, `timers`,
  `tx_pipeline`, `bind_meta`, `flow`, `xsk` per
  `project_959_done_phases_complete.md`). False-sharing concerns
  already partially addressed via the decomposition.
- Coordinator polls counters at 1Hz (status reporting), not in a
  tight loop. Per-second reads do not stall a 14.8M pps writer.

**Verdict candidate:** KILL — premise (cross-NUMA bouncing) doesn't
match deployment topology; decomposition into sub-structs already
shipped via #959.

### #1188 — Group disparate RCU states into single `RuntimeSnapshot`

**Claim:** `BindingWorker` / `worker_loop` "loads up to 8 separate
`ArcSwap` pointers on every iteration". Reduce to one.

**Reality:**
- **Zero `ArcSwap` loads** in `worker_loop.rs`, `poll_descriptor.rs`,
  or `poll_stages.rs` (`grep -rn "ArcSwap\|arc_swap::" ...` returns
  nothing on the per-packet path).
- ArcSwap state (forwarding, validation, HA, fabrics) is loaded
  **once per binding poll** in the binding's outer loop, not per
  packet.
- "Hundreds of millions of atomic operations per second" claim is
  factually wrong — ArcSwap loads happen at binding-poll cadence
  (~10-100 Hz), not per packet.

**Verdict candidate:** KILL — premise factually wrong; ArcSwap loads
are per-binding-poll, not per-packet.

### #1189 — Deconstruct Coordinator into domain-specific managers

**Claim:** `Coordinator` is a "3,000-line monolith"; split into
`WorkerManager`, `ConfigManager`, `NeighborManager`, `SessionManager`.

**Reality:**
- `coordinator/mod.rs` is **1959 lines**, not 3000.
- Already split into 8 files (`coordinator/{worker_manager,
  neighbor_manager, session_manager, ha_state, cos_state, inject,
  status, mod}.rs`). The manager files are mostly thin shells
  (19-30 lines each) plus the active `mod.rs`.
- Direction prescribed by the issue matches the partial
  decomposition that already exists. A full migration of the
  remaining 1959-line `mod.rs` body into the stub managers would
  be a multi-day refactor with no measured ROI.

**Verdict candidate:** NEEDS-MAJOR — direction is right but the
issue's premise (3000-line monolith) is stale. The remaining work
is "gradually move methods from mod.rs into existing manager stubs
when natural" — not a pattern-driven rearchitecture. Could close
or downgrade to "good first issue" status.

## 4. Cross-cutting failure mode

Each issue follows the same pathology as #966-969:

1. **Stale file/symbol claim** — `afxdp.rs:890` (#947), "31-parameter"
   (#1127), "frame.rs God Function" (#963 already split), "250-line
   inline TSO" (#1166 already extracted), "3000-line coordinator"
   (#1189 actually 1959 + 8 files).
2. **Hot-path claim about a slow path** — `next_table` recursion
   (#1163 install-only), JSON serialization (#1164 startup-only),
   `conntrack_v4_fd` (#948 install-only), `thread_local!` (#1165
   debug-only).
3. **Premise already disproven** — #946 Phase 2 PLAN-KILL stands
   (#1146 inherits), #961 / #1144 already plan-rejected, ArcSwap
   not on hot path (#1188).
4. **Solution already shipped** — `dynamic_neighbors` ShardedNeighborMap
   (#949), mpsc_inbox Mediator (#948), tcp_segmentation.rs (#1166),
   poll_stages.rs (#946 Phase 1), coordinator manager stubs (#1189).
5. **Single-socket lab** invalidates cross-NUMA premises (#1187).

## 5. Dispatch plan

For each of 17 issues: dispatch one Codex hostile review and one
Gemini Pro 3 adversarial review against this triage doc + the
issue's own body. Both reviewers verdict each issue independently.

Outcome rule:
- 8/8 unanimous PLAN-KILL on an issue → close with kill rationale.
- Split verdict (one KILL one not) → leave open, note disagreement.
- Both NEEDS-MAJOR → keep open without scoping work.
- Both READY → unlikely; would proceed to implementation.

Reviewer prompts dispatched in 3 batches of 5-6 issues each to keep
each review focused.

## 6. Out of scope

- Implementing any of these refactors. This triage is the entire
  scope of branch `refactor/tier-d-triage`.
- Performance work on the actually-measured hotspots (#776/#777/#779/
  #781) — those are tracked separately.

## 7. Open questions for adversarial review

1. Has any Tier D issue's central claim been mis-read here? Is there
   a code path I missed that matches the issue's prescribed target?
2. Does any issue (e.g., #1189 Coordinator decomposition or #1187
   double-buffered telemetry) actually have measurable cost that
   would justify going back to NEEDS-MAJOR rather than KILL?
3. Is there a shared structural finding across the 17 that suggests
   the issue template itself should be changed (e.g., require a
   measurement before opening)?
