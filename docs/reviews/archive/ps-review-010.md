# xpf firewall refactor audit â€” ps-review-010

## 1. Base commit reviewed

```
Repo: /home/ps/git/xpf
Branch: main
Commit: 58a002642f269cc29457945ca14f8f630add2293 (2026-07-06)
git pull --rebase: failed (network 403, proxy blocks github.com) â€“ audited existing checkout, no source mutations.
```

## 2. Output path

`/tmp/ps-review-010.md`

## 3. Duplicate suppression summary

- Prior campaign files:
  - `/tmp/fable-review-001.md`, `/tmp/fable-review-002.md` â€“ security audits, no refactor findings except note that `pkg/policymatch/` is well isolated (no refactor needed).
  - `/tmp/avo-review-002.md` through `/tmp/avo-review-007.md` â€“ security audits, no refactor findings.
  - `/tmp/ps-review-007.md` through `/tmp/ps-review-009.md` â€“ security audits with critical bugs (HA NAT pool conflict, PBR bypass, etc.), no refactor findings.
  - Total 68 prior security findings. None were refactor/modularity findings.
- Prior campaigns (per instruction) flagged these refactor-debt monoliths:
  - 1,100+ line TX drain orchestrator (`enqueue_pending_forwards` in `tx/dispatch/mod.rs`) â€“ **confirmed, Finding R1**
  - Cross-domain `SnapshotIntegrityError` / `policy.rs` dumping ground â€“ **confirmed, Finding R2**
  - ~880-line IPsec `policy.go` â€“ out of scope (Go control plane, not Rust dataplane hot path)
  - ~1,589-line HA `sync_conn.go` generation-guard state machine â€“ out of scope (Go control plane)
  - 5-file-scattered NAT compile/validate surface â€“ out of scope (Go control plane)
  - Inlined ~110-line SYN-flood enforcement in screen check function â€“ out of scope (screen, not hot path focus)
- Read `docs/engineering-style.md` â€“ hot-path discipline, no alloc, no dispatch, inlining preserved, cache locality, UMEM ownership.
- Read `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, `userspace-dp/src/policy.rs`, `userspace-dp/src/session/mod.rs`, `userspace-dp/src/afxdp/forwarding/mod.rs`, `userspace-dp/src/afxdp/tx/dispatch/mod.rs`, etc.
- Findings below are **not** restatements of prior security findings. They are new refactor/modularity findings with hot-path preservation analysis.
- Dedup notes in each finding explain why not a duplicate of prior security findings or the monoliths named above (either confirming with new decomposition detail/hot-path analysis, or identifying new monoliths).

## 4. File-size / shape inventory â€“ module checklist and coverage proof

**Rust AF_XDP dataplane hot path â€“ largest source files (excluding tests, generated):**

| File | LOC | Hot Path? | Responsibilities Fused | Rank |
|------|-----|-----------|------------------------|------|
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 5,759 | **YES** â€“ per-packet orchestrator | Session hit/miss, filter, NAT, route, screen, host-local, policy, install, telemetry, HA, flowless â€“ 15+ responsibilities | 1 |
| `userspace-dp/src/policy.rs` | 4,224 | **YES** â€“ session miss (new flow) | Policy matching, application matching, address books, AppCatalog, counters, snapshot parsing, `SnapshotIntegrityError` dumping ground | 2 |
| `userspace-dp/src/afxdp/poll_stages.rs` | 3,024 | YES â€“ poll stages | Stage definitions, batch processing â€“ moderate cohesion | 3 |
| `userspace-dp/src/afxdp/forwarding/mod.rs` | 2,671 | **YES** â€“ route lookup | FIB LPM, PBR override, local delivery, ECMP, neighbor, tunnel, table scoping â€“ 5+ responsibilities | 4 |
| `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` | 2,174 | Cold â€“ exception path | Reject reply, filter reject, policy deny, ICMP, TCP RST, rate limiting â€“ cohesive, cold | 5 |
| `userspace-dp/src/nat64.rs` | 2,047 | Warm â€“ NAT64 flows | NAT64 classification, translation, policy interaction â€“ cohesive | 6 |
| `userspace-dp/src/session/mod.rs` | 1,900 | **YES** â€“ every packet | Session table, 4 indexes, NAT demux, timer wheel, limit counting, HA sync, stats â€“ 6 responsibilities | 7 |
| `userspace-dp/src/afxdp/frame/inspect.rs` | 1,769 | YES â€“ packet parsing | Frame parsing, L4 offset, extension headers, fragment detection â€“ cohesive | 8 |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | 1,767 | **YES** â€“ worker loop | Worker loop, batch processing, HA transitions â€“ moderate cohesion | 9 |
| `userspace-dp/src/afxdp/frame/mod.rs` | 1,646 | YES â€“ frame handling | Frame lifecycle, UMEM, TX/RX â€“ cohesive | 10 |
| `userspace-dp/src/afxdp/worker/mod.rs` | 1,615 | Warm â€“ worker setup | BindingWorker god-struct (19 fields, but already sub-structured) â€“ D class | 11 |
| `userspace-dp/src/afxdp/tx/dispatch/mod.rs` | 1,423 | **YES** â€“ TX drain | TX orchestrator (1,131 LOC function), build, segmentation, WG/GRE, output filter, CoS â€“ 8+ responsibilities | 12 |
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | 2,058 | **YES** â€“ CoS selection | Queue selection waterfill (438 LOC), fast path, lease, telemetry â€“ hot/cold fusion | 13 |
| `userspace-dp/src/screen/mod.rs` | 1,479 | Warm â€“ new flows | Screen checks, SYN flood, port scan â€“ cohesive, not hot path focus | 14 |
| `userspace-dp/src/afxdp/types/forwarding.rs` | ~1,200 | Warm â€“ config | ForwardingState god-struct (55 fields), ForwardingResolution â€“ mixed hot/cold | 15 |

**Top functions by LOC:**
- `poll_binding_process_descriptor` â€“ 1,368 LOC â€“ **god-function, 15+ responsibilities**
- `enqueue_pending_forwards` â€“ 1,131 LOC â€“ **TX orchestrator, 8+ responsibilities**
- `evaluate_policy_result_l3_aware` â€“ 191 LOC â€“ hot, exemplary, keep
- `lookup_forwarding_resolution_inner_ecmp` â€“ 155 LOC â€“ fuses 5 responsibilities
- `lookup_forwarding_resolution_v4_inner` â€“ 191 LOC â€“ fuses FIB, ECMP, neighbor, tunnel
- `select_exact_cos_guarantee_queue_waterfill` â€“ 438 LOC â€“ waterfill selection, complex
- `parse_policy_state_with_counters` â€“ 557 LOC â€“ fuses validation, book building, rule parsing, index building
- `SessionTable::lookup_with_origin` â€“ ~160 LOC â€“ hot, but fuses metadata.clone() Arc and push_to_wheel

**Coverage:** Inspected all 15 files above plus `session/install.rs`, `session/lookup.rs`, `session/expire.rs`, `filter/engine/eval.rs`, `filter/engine/matching.rs`, `afxdp/poll_descriptor/filter.rs`, `afxdp/poll_descriptor/flow_cache_hit.rs`. Total ~35,000 LOC inspected. This inventory is the coverage proof.

## 5. File-by-file inspection log

### `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (5,759 LOC)
- **God-function**: `poll_binding_process_descriptor` (1,368 LOC, lines 585-1952) fuses session hit (409 LOC), session miss (721 LOC), flowless, host-local, NAT pre-routing (164 LOC), policy eval, install, telemetry, HA, debug logging.
- **Hot/cold fusion**: `cfg(feature = "debug-log")` blocks inline with `telemetry.dbg.*` increments (lines 925-943, 844, 1233, etc.). `emit_policy_deny_event`, `emit_host_inbound_deny`, `emit_pending_filter_log` called inline on drop paths â€“ event emission allocates and crosses thread boundary, must be outlined.
- **NAT pre-routing**: DNAT, static NAT, NPTv6, NAT64 logic inline (lines 1352-1515, 164 LOC) â€“ distinct responsibility, testable in isolation.
- **Host-local**: Host-inbound gate, lo0 filter, junos-host policy, flowless verdict fused in both hit and miss paths (lines 1006-1198, 193 LOC; flowless helpers 337-427, 91 LOC).
- **Session install**: BPF map publish, dnat_table publish, flow cache population inline at end of miss path â€“ transaction boundary, should be isolated.
- **Already extracted**: `flow_cache_hit.rs` (521 LOC), `filter.rs` (1,201 LOC), `rx_telemetry.rs` (220 LOC), `cookie_reply.rs`, `reject_reply.rs`, `nat_exception.rs` â€“ good precedents.
- **BindingWorker**: 19 fields but already sub-structured into `WorkerXskRings`, `WorkerTxPipeline`, etc. â€“ D class, do not split further (cache locality).
- **stage_flow_cache_hit**: 457 LOC but cohesive fast path â€“ D class, do not further split (already extracted in #1327, further split would hurt icache).

### `userspace-dp/src/policy.rs` (4,224 LOC)
- **SnapshotIntegrityError dumping ground**: 616 LOC enum (lines 16-632) with 30+ variants from policy, NAT, filter, screen â€“ cross-domain coupling.
- **PolicyState god-struct**: 83 LOC struct (lines 2139-2222) with hot fields (rules, zone indexes, books, default_counter) fused with cold metadata (concrete_zone_ids, rule_id_to_policy_id, book_id_to_idx). Hot fields accessed per session miss, cold fields only on config apply or 1s refresh. **Do NOT split hot from cold** â€“ PolicyState is Arc-swapped, splitting would add indirection and hurt cache locality during linear rule scan. Document and group fields instead.
- **CompiledApplications**: 192 LOC, `matches` hot inline, `from_matches` cold â€“ cohesive, keep with PolicyRule for locality. D class.
- **AppCatalog**: 217 LOC, directional lookup for AppID stamping â€“ cold path (session install, not per-packet), separate responsibility (telemetry, not policy decision). Safe to extract to submodule (B).
- **PolicyCounterStore**: 216 LOC, `PolicyRuleCounter` with atomic add on hot path, `Mutex` only for snapshot/reset (cold). Self-contained, extractable to submodule (A/B).
- **parse_policy_state_with_counters**: 557 LOC monolith (lines 2519-3041) fusing validation, book building, rule parsing, index building â€“ split into phase helpers (B).
- **evaluate_policy_result_l3_aware**: 191 LOC, exemplary hot path â€“ calls only `try_match_rule` and atomic counter, no logging, no alloc, no mutex. **D class, keep as is, do NOT add cold fusion.**
- **try_match_rule**: 178 LOC, hot, tightly coupled to PolicyRule layout â€“ D class, keep.

### `userspace-dp/src/session/mod.rs` (1,900 LOC) + related
- **SessionTable god-struct**: 27 fields (lines 472-589) fusing 6 responsibilities: table storage + primary index (entries, key_to_handle), NAT demux indexes (nat_reverse_index, forward_wire_index, reverse_translated_index), timer wheel (wheel, last_gc_ns), per-IP limit (session_limit_*), HA sync (deltas, owner_rg_sessions, epoch), stats. Core table + 4 indexes must stay together for locality (D), but cold HA/limit/wheel can be extracted (B).
- **SessionEntry hot/cold fusion**: 16 fields (lines 315-430). Hot per-packet: decision, metadata, last_seen_ns, expires_after_ns, closing/reset/established, counters, observed_tos/tcp_flags, wheel_tick. Cold: origin, install_epoch, created_ns, HA epochs. `metadata.clone()` in `lookup_with_origin` clones entire SessionMetadata including `Option<Arc<PolicyRuleCounter>>` â€“ **Arc clone per packet is hot-path regression** (atomic inc). Should eliminate Arc clone (A) and consider SoA split (C, risky).
- **nat_reverse_index single-value map**: P5 â€“ 1:N collisions displace earlier sessions, causing hijacking. Should be multi-map. This is a bug fix (A), then modularize NAT index operations to `session/nat_index.rs` (B).
- **Timer wheel**: Already modular (`wheel.rs` 80 LOC, `expire.rs` 514 LOC). `push_to_wheel` is `#[inline]` and throttled, calls second hash lookup â€“ acceptable. Keep (D).
- **Session limit**: `session_limit_inc/dec` simple hash inc/dec, only on install/remove (not per-packet hit). Extract to `session/limit.rs` (B), keep fns inline.
- **HA sync**: `SessionOrigin`, deltas ring, `upsert_synced_with_origin`, `standby_gate_decision` fused into table and expire loop. Extract to `session/ha.rs` (B), keep origin field in entry (1 byte).
- **lookup_with_origin**: Hottest path â€“ every packet. Fuses `metadata.clone()` Arc (cold), `push_to_wheel` second hash (warm), `opening_override_for` hash lookup (cold, only on OPENING). Should eliminate Arc clone and move opening_override check inside OPENING branch only.
- **install_with_protocol_with_origin**: Hot for new flows, fuses cold delta push (necessary for HA) â€“ keep, but delta construction clones key/metadata â€“ necessary.

### `userspace-dp/src/afxdp/forwarding/mod.rs` (2,671 LOC)
- **Monolithic route lookup**: `lookup_forwarding_resolution_inner_ecmp` (155 LOC) fuses local delivery table scoping (#3769, #3151), FIB LPM, PBR table canonicalization. `lookup_forwarding_resolution_v4_inner` (191 LOC) and v6 inner (184 LOC) fuse static vs connected choose, next-table recursion with `Vec<String> visited`, ECMP hash/select, neighbor lookup, tunnel resolve. Should split by responsibility: route.rs, local.rs, neighbor.rs, resolution.rs â€“ (B) keep in same crate for inlining.
- **PBR evaluation**: `ingress_route_table_override` (121 LOC) lives in forwarding but is a filter action â€“ should be in filter module or dedicated PBR module. Calls filter engine, enqueues reject reply, emits log. Move to `filter/pbr.rs` or `forwarding/pbr.rs` (B).
- **Flowless vs flow-backed**: `flowless_base_resolution` in poll_descriptor duplicates ordering logic (local before PBR). Extract shared `resolve_local_first` helper to `forwarding/local.rs` â€“ (C) performance-positive (prevents drift).
- **ForwardingState god-struct**: 55 fields in `afxdp/types/forwarding.rs:14-278` mixing hot FIB/neighbor/local sets with cold config metadata (policy, NAT, filter, mirrors, screen, AppID, CoS, fabrics). Cloned via ArcSwap on config commit â€“ cold fields increase clone cost and cache footprint. Split into `ForwardingHot` (routes, local, neighbors, egress) and `ForwardingCold` (policy, NAT, etc.), or document/reorder hot fields first â€“ (C) for split, (B) for documentation.
- **ForwardingResolution**: 9-field POD, cohesive egress decision â€“ D class, keep.
- **Hot vs cold fusion**: `canonical_route_table` calls `DEFAULT_V4_TABLE.to_string()` on every packet when no table override â€“ **allocates String per packet!** Should use static str. `LOCAL_DELIVERY_IFINDEX0.fetch_add` atomic inc on cold path (NAT-only) â€“ acceptable. `Vec<String> visited` for next-table recursion â€“ cold (next-table rare), but could use inline array. PBR filter call already cold. No logging in hot FIB loop â€“ good.
- **Table-scoped local delivery**: Cross-VRF protection (#3769, #3151) â€“ correct, must preserve. Connected route table-scoping (#2388) â€“ correct.

### `userspace-dp/src/afxdp/tx/dispatch/mod.rs` (1,423 LOC)
- **TX drain orchestrator**: `enqueue_pending_forwards` â€“ 1,131 LOC function (lines 125-1256) fusing build, segmentation, CoS classify, WG/GRE, output filter, DSCP, mirror, slow-path. Prior campaign flagged "1,100+ line TX drain orchestrator" â€“ **confirmed, this is it**, not `drain_pending_tx` (which is already split into phases).
- **Responsibilities fused**: TX ring management, CoS queue selection, flow fair queueing, ECN, GSO segmentation, WireGuard encryption, GRE encap, output filter, DSCP/VLAN, stats/logging, BPF updates.
- **Already split**: `tx/drain/phase_*.rs`, `tx/cos.rs`, `slow_path.rs` â€“ good precedents. Phase 8 (try_inplace_rewrite_or_build) intentionally stays in mod.rs per comment â€“ should extract.
- **Proposed decomposition**: Keep `enqueue_pending_forwards` as thin orchestrator (<150 LOC). New modules under `tx/dispatch/`: `phase_build.rs` â€“ split by encapsulation (build_plain, build_wireguard, build_gre), `phase_segment.rs` â€“ wrapper around tcp_segmentation, `phase_mirror.rs`, `phase_slow.rs` (already exists). Split cold stats/logging to `#[cold]` helpers.
- **Hot-path preservation**: TX drain is hot â€“ any split must preserve inlining (`#[inline(always)]` on build functions), no new alloc per packet (PendingForwardRequest reuses scratch Vec, TxRequest.bytes moved not cloned), no dynamic dispatch (WG/GRE selection via match on tunnel_endpoint_id, monomorphize, no trait objects), UMEM single-free invariant preserved via recycle functions, endianness conversions cohesive in gre.rs/wg/framing.rs. Verify via `cargo asm` diff, perf stat, CoS smoke/fairness gates, test-failover.
- **BindingWorker**: Already decomposed via #959 into sub-structs â€“ D class, do not split further (cache locality, `cold_path` co-located with `flow` per #1620).
- **Segmentation**: TCP GSO only, marked `#[cold]`, returns early if tunnel â€“ cohesive, keep. WG/GRE encap in build path, not segmentation â€“ correct.

### `userspace-dp/src/afxdp/cos/queue_service/mod.rs` (2,058 LOC)
- **Monolithic selection**: `select_exact_cos_guarantee_queue_waterfill` â€“ 438 LOC, fuses waterfill phase 1/2, honor refund, epoch bits. `select_exact_cos_guarantee_queue_with_lease_telemetry` â€“ 215 LOC. `drain_shaped_tx` â€“ 62 LOC orchestrator.
- **Hot/cold fusion**: `record_cos_queue_lease_acquire` (telemetry aggregation) inlined in hot path, `count_park_reason`, `park_cos_queue` with log, `ExactCoSScratchBuild::Drop` with error String â€“ cold but inlined.
- **Proposed decomposition**: New modules under `cos/queue_service/`: `select_waterfill.rs`, `select_fast.rs`, `lease.rs`. Move cold telemetry to `#[cold]` helpers. Keep `drain.rs` and `service.rs` as is (already split per #1035, #1331). Keep `mod.rs` as thin re-export (<100 LOC).
- **Hot-path preservation**: Selection functions hot, called per drain tick â€“ keep `#[inline]`, waterfill loops `#[inline(always)]`. No alloc in selection â€“ uses stack arrays and bitmasks. No vtable â€“ `CoSBatch::Local/Prepared` match static. Preserve `#[repr(align(64))]` on `CoSQueueRuntime`, `SharedCoSExactBacklog`, etc. â€“ do not reorder fields. Atomic ordering: single-writer per worker, Relaxed for queue state, Acquire/Release for lease â€“ preserve. Verify via `cargo asm` on `drain_shaped_tx`, perf on CoS fairness gate, `test-failover` for lease handoff.
- **poll_binding_process_descriptor**: 1,367 LOC RX/TX fusion â€“ D class, do NOT split further (mutable-locals coupling, icache, TX drain piggybacks on RX poll). Already extracted stages â€“ keep as is.

## 6. Findings â€“ by confidence

### High confidence

#### R1
- Title: God-function `poll_binding_process_descriptor` (1,368 LOC) fusing 15+ responsibilities â€“ split into session hit/miss, NAT pre-routing, policy eval, host-local, install stages
- Severity: Critical (maintainability, build cost, impossible to unit test branches)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ crosses per-packet fast path
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:585-1952`, `pub(super) fn poll_binding_process_descriptor` â€“ 1,368 LOC
  - Session-hit branch: lines 822-1230 (409 LOC) â€“ resolve, policy hit counter, DSCP filter, host-inbound, lo0, junos-host, TTL
  - Session-miss branch: lines 1231-1952 (721 LOC) â€“ SYN cookie, DNAT/NAT64/NPTv6, input filter, PBR, route, screen, policy, SNAT, install, BPF publish
  - NAT pre-routing block: lines 1352-1515 (164 LOC) â€“ DNAT, static NAT, NPTv6, NAT64, effective target calc
  - Host-local gate: lines 1006-1198 (193 LOC) â€“ host-inbound â†’ lo0 â†’ junos-host decision trees
  - Flowless helpers: `flowless_local_delivery_verdict:337-427` (91 LOC), `flowless_base_resolution:443-475` (33 LOC)
  - `junos_host_local_policy:247-307` (61 LOC)
  - Sibling modules already extracted: `flow_cache_hit.rs` (521 LOC), `filter.rs` (1,201 LOC), `rx_telemetry.rs` (220 LOC) â€“ good precedents
- Proposed decomposition:
  New modules under `userspace-dp/src/afxdp/poll_descriptor/`:
  - `session_hit.rs` â€“ `stage_session_hit()` â€“ session hit path, policy hit counter, DSCP filter on hit, host-inbound gated lo0, junos-host re-eval, TTL. Moves `junos_host_local_policy`, `JunosHostLocalPolicy`.
  - `session_miss.rs` â€“ `stage_session_miss()` â€“ SYN cookie, cluster peer return, NAT pre-routing call, input filter, PBR route override, route lookup, screen, policy eval, SNAT, install orchestration.
  - `nat_pre_routing.rs` â€“ `struct NatPreRoutingOutcome` with pre_routing_dnat, nptv6_inbound, nat64_match, effective_resolution_target, policy_dst_ip/port. Pure function, moves 164 LOC DNAT/NAT64/NPTv6 logic. No alloc, returns stack-only outcome.
  - `policy_eval.rs` â€“ transit policy evaluation wrapper, policy deny debug throttle, `policy_packet_icmp`. Moves cold logging predicates out of hot path.
  - `host_local.rs` â€“ host-inbound gate, lo0 filter, junos-host policy, flowless verdict. Moves `flowless_local_delivery_verdict`, `FlowlessLocalVerdict`, `flowless_base_resolution`, `host_inbound_gated_lo0_action`.
  - `flowless.rs` â€“ flowless (no-L4) transit and local delivery â€“ moves flowless helpers, keeps synthetic L3 flow handling isolated.
  - `session_install.rs` â€“ `install_session_and_publish()` â€“ session table install, BPF map publish, dnat_table publish, flow cache population. Moves ~180 LOC, isolates transaction boundary.
  - `telemetry_debug.rs` â€“ cold debug_log! wrappers, `telemetry.dbg` increments â€“ consolidate cold telemetry, mark `#[inline(never)]`.
  - `resolver_enqueue.rs` â€“ move `try_enqueue_resolver:512-539` (28 LOC) to neighbor module â€“ cold path only.
  - Seam: cut by **responsibility phase** â€“ hit vs miss vs nat vs policy vs host-local vs install â€“ not by line count. Each `stage_*` function takes `&mut PacketCtx` (grouped mutable locals) and returns `StageOutcome`, preserving mutable-locals coupling via explicit out-params (solves #1327 mutable-locals block).
- Hot-path preservation analysis:
  - **Inlining**: All new `stage_*` functions must be `#[inline(always)]` or `#[inline]` and stay within same crate (`crate::afxdp::poll_descriptor::session_hit`) so LLVM inlines across module boundaries. Do NOT move to another crate. Verify with `cargo rustc -- --emit=llvm-ir` and `objdump -d` diff â€“ hot path should be byte-identical before/after. The hot loop (session hit, flow cache hit) must show identical instructions.
  - **No new heap allocation**: `NatPreRoutingOutcome` is stack-only (enums/options of Copy types). `PacketCtx` groups existing mutable locals, no `Box`/`Vec`. `try_enqueue_resolver` already clones iface name only on cold throttled path â€“ keep.
  - **No dynamic dispatch**: Keep concrete types, no `dyn Fn`, no trait objects. Policy eval and filter eval already monomorphized â€“ preserve.
  - **Const/monomorphization**: `policy_packet_icmp` is `#[inline]` and const-folds protocol check â€“ keep. `session_miss_debug_log_allowed` is pure integer compare â€“ keep `#[inline]`.
  - **Zero-copy/UMEM**: `packet_frame`, `raw_frame`, `owned_packet_frame` lifetimes must stay as `&[u8]` borrows of UMEM area or owned `Vec<u8>` for GRE decap only. New modules must take `packet_frame: &[u8]` not owned copy. `PendingForwardFrame::Live` vs `Owned` move semantics stay in caller. The `owned_packet_frame.take()` move must remain in orchestrator.
  - **Branch/icache**: Splitting cold debug logging and event emission into `#[inline(never)]` cold functions reduces icache pressure on hot path. Hot branches (session hit, flow cache hit) should stay fall-through. Verify with `perf stat -e instructions,cache-misses` â€“ icache misses should drop, instructions per packet should stay within 1%.
  - **How to verify**: 1) `cargo test --lib afxdp::poll_descriptor` â€“ existing gates; 2) `make test` â€“ full suite; 3) `make test-failover` â€“ HA path; 4) CoS smoke â€“ `cargo test cos`; 5) Disassembly diff: `objdump -d target/.../xpf-dp | grep -A 200 poll_binding_process_descriptor` before/after â€“ must match hot loop; 6) `perf top` symbol `poll_binding_process_descriptor` must remain top with same instruction count; 7) `perf stat` cache-misses should not increase.
- Tests + gate:
  - Move with code: `debug_log_throttle_tests:5153-5203`, `try_enqueue_resolver_tests:5204-5290`, `new_flow_session_limit_tests:5291-5459`, `flowless_local_delivery_tests:5460-5759`.
  - Behavioral gates: `make test` (unit), `make test-failover` (HA), CoS smoke (`cargo test --test cos`), `cargo test --lib policy`, `cargo test --lib filter`, `cargo test --lib session`.
  - **Critical**: `flowless_local_delivery_tests` must pass â€“ Junos order (host-inbound â†’ lo0 â†’ junos-host) must be preserved.
- Why it matters:
  - **Maintainability**: Single 1,368-LOC function blocks parallel development, obscures hot vs cold, increases compile time (single CGU), prevents unit testing of NAT/policy/host-local branches in isolation.
  - **Build cost**: Every edit to any part of the forwarding path recompiles the entire 5,759-line file and all its dependencies. Splitting into smaller modules improves incremental build time dramatically.
  - **Review cost**: 1,368-LOC function is un-reviewable in a PR. Splitting by responsibility enables targeted review and reduces merge conflicts on hot path.
  - **Testability**: NAT pre-routing, host-local gating, and session install logic cannot be unit tested in isolation â€“ they are fused into the god-function. Extraction enables focused unit tests and fuzzing.
  - **Performance clarity**: Hot path (session hit, flow cache hit) fused with cold path (debug logging, event emission, error handling) â€“ obscures the performance-critical code. Splitting makes the hot path obvious and protects it from accidental cold fusion.
- Fix direction (incremental, safe to land as small PRs):
  1. **Mechanical moves first (A)**: Create `flowless.rs`, move `FlowlessLocalVerdict`, `flowless_local_delivery_verdict`, `flowless_base_resolution`, and `flowless_local_delivery_tests`. Update mod.rs with `mod flowless; use flowless::*;`. Add `#[inline]` to functions to preserve inlining. Run `cargo test flowless`, verify disassembly unchanged. PR #1.
  2. **Cold telemetry extraction (C)**: Create `telemetry_debug.rs`, move `session_miss_debug_log_allowed`, `policy_deny_debug_log_allowed`, and debug_log! bodies into `#[cold] #[inline(never)]` functions. Replace inline sites with calls to cold functions. Verify disassembly â€“ hot loop should have single conditional jump to cold section, not interleaved logging. Run `cargo test --features debug-log` and without. PR #2.
  3. **NAT pre-routing extraction (B)**: Create `nat_pre_routing.rs` with `NatPreRoutingOutcome` struct and `#[inline] pub(crate) fn nat_pre_routing(...) -> NatPreRoutingOutcome`. Move 164 LOC DNAT/NAT64/NPTv6 logic. Replace inline block with call. Add unit tests for each translation type (DNAT, NPTv6, NAT64, none). Verify no alloc via `cargo test nat` and disassembly. PR #3.
  4. **Host-local extraction (B)**: Create `host_local.rs`, move `junos_host_local_policy`, `junos_host_policy_eval`, `emit_junos_host_deny`, `emit_host_inbound_deny`, `JunosHostLocalPolicy`, flowless functions (if not already moved). Create `stage_host_local_session_hit()` and `stage_host_local_session_miss()` wrappers. Replace inline decision trees (lines 1006-1198) with calls. Keep `#[inline]` on verdict functions. Run `flowless_local_delivery_tests`, `cargo test host_inbound`, `make test-failover`. Verify Junos order preserved via existing tests. PR #4.
  5. **Session install extraction (B)**: Create `session_install.rs` with `install_session_and_publish()` â€“ session table install, BPF map publish, dnat_table publish, flow cache population. Moves ~180 LOC and deduplicates fabric return fast path vs normal miss path. Returns `Result<FlowCacheEntry, InstallError>`, caller handles `#1789` error count. Verify with `make test-failover` (HA) and BPF map unit tests. PR #5.
  6. **Event emission outlining (B)**: Annotate `emit_policy_deny_event`, `emit_host_inbound_deny`, `emit_pending_filter_log` with `#[cold] #[inline(never)]`. Verify call sites only on drop/deny branches. Check disassembly â€“ hot loop should not contain emit symbols. Run event stream integration tests. PR #6.
  7. **Major split â€“ session hit/miss (B)**: Create `session_hit.rs` and `session_miss.rs`. Define `PacketCtx` struct grouping related mutable locals (solves #1327 mutable-locals coupling). Each stage function takes `&mut PacketCtx`, `&mut BindingWorker`, etc., returns `ControlFlow` enum (Continue, Drop, Forward). Replace god-function body with calls to stages. This is the largest change, do last. Each stage can be unit tested with mock PacketCtx. Verify with full `make test`, `make test-failover`, CoS smoke, perf stat, disassembly diff. PR #7.
  8. **Verification after each PR**: Run `cargo test --lib afxdp::poll_descriptor`, `make test`, `make test-failover`, CoS smoke (`cargo test cos`), `perf stat` on loopback bench, disassembly diff of hot loop. Ensure `poll_binding_process_descriptor` remains top symbol in `perf top` with same instruction count.
- Labels: `refactor`, `hot-path`, `god-function`, `afxdp`, `dataplane`, `modularity`, `build-cost`, `x-hpc`
- Dedup note: Supersedes prior #946 Phase 1 stage extraction and #1327 flow-cache split â€“ this continues the same architectural direction but tackles the remaining monolith. The 1,368-LOC god-function was not previously broken down by responsibility phase. This finding provides the specific module decomposition and hot-path preservation analysis that prior campaigns lacked. Not a duplicate of the TX drain orchestrator (R1) â€“ this is the RX forwarding orchestrator, a different monolith.

#### R2
- Title: `SnapshotIntegrityError` dumping ground (616 LOC) mixes policy, NAT, filter, screen domains â€“ split by domain with top-level wrapper
- Severity: High (maintainability, cross-domain coupling, blocks independent domain evolution)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ cold path only (config apply), but error variants used across crates, must preserve error messages for Go control plane
- Evidence:
  - File: `userspace-dp/src/policy.rs:16-632`, `pub enum SnapshotIntegrityError` â€“ 616 LOC, 30+ variants
  - Policy variants: `DuplicateRuleId`, `UnrepresentableApplicationProtocol`, `InvalidApplicationIcmpFields`, `UnrepresentableAddress`, `UnresolvableZoneReference`, `DuplicatePolicyId`, etc.
  - NAT/NPTv6 variants: `Nptv6UnparseableRule`, `Nptv6OverlappingPrefix`
  - Filter variants: `UnrepresentableFilterProtocol`, `UnrepresentableFilterTCPFlags`, `UnrepresentableFilterIcmpType`, `UnrepresentableFilterIcmpCode`, `UnrepresentableFilterPort`, etc.
  - Screen/other: multiple cross-domain variants
  - Used by: `policy.rs:parse_policy_state_with_counters`, but also imported by NAT (`nat64.rs`, `nptv6.rs`), filter (`filter/compiler.rs`), screen (`screen/mod.rs`) parsers as a single preflight error type.
  - Results in `policy.rs` importing NAT/filter/screen concepts, and NAT/filter modules importing policy error type â€“ circular coupling.
- Proposed decomposition:
  ```
  userspace-dp/src/policy/snapshot.rs
    pub enum PolicySnapshotError {
        DuplicateRuleId { rule_id: String },
        UnrepresentableApplicationProtocol { ... },
        // ... policy-only variants
    }
    pub fn parse_policy_state_with_counters(...) -> Result<PolicyState, PolicySnapshotError>

  userspace-dp/src/nat/snapshot.rs
    pub enum NatSnapshotError {
        Nptv6UnparseableRule { ... },
        Nptv6OverlappingPrefix { ... },
        // ... NAT-only variants
    }

  userspace-dp/src/filter/snapshot.rs
    pub enum FilterSnapshotError {
        UnrepresentableFilterProtocol { ... },
        // ... filter-only variants
    }

  userspace-dp/src/snapshot.rs (or lib.rs)
    pub enum SnapshotIntegrityError {
        Policy(PolicySnapshotError),
        Nat(NatSnapshotError),
        Filter(FilterSnapshotError),
        Screen(ScreenSnapshotError),
        // ...
    }
    impl From<PolicySnapshotError> for SnapshotIntegrityError { ... }
    // Or keep single enum but split variant definitions via macro/domain modules and re-export:
    // policy/snapshot.rs defines policy variants, nat/snapshot.rs defines NAT variants, etc.,
    // then snapshot.rs assembles them into single enum with `pub use`.
  ```
  - Seam: cut by **domain responsibility** â€“ policy errors in policy module, NAT errors in NAT module, etc. Top-level wrapper preserves single error type for `apply` preflight, but domain modules own their variants.
  - Alternatively, keep single enum but move variant definitions to domain modules via `macro_rules!` or `pub use` â€“ less churn, still improves modularity.
- Hot-path preservation analysis:
  - **N/A â€“ cold path only**: `SnapshotIntegrityError` is only used during config apply (cold path), never on per-packet hot path. No inlining, alloc, or dispatch concerns for hot path.
  - **Error message preservation**: Go control plane parses error messages from Rust helper â€“ error variant names and messages must stay identical. When splitting, ensure `Display` impl produces same strings. Verify with `pkg/dataplane/userspace/` tests that check error messages.
  - **Exhaustiveness**: `match` on `SnapshotIntegrityError` in Go and Rust must be updated if variants move. Use `From` impls to keep existing match sites working, or update matches to new wrapper variants.
  - **How to verify**: 1) `cargo test --lib policy` â€“ parse failure tests; 2) `cargo test --lib nat` â€“ NAT snapshot tests; 3) `cargo test --lib filter` â€“ filter parse tests; 4) Go tests: `go test ./pkg/dataplane/userspace/ -run Snapshot` â€“ verifies error messages unchanged; 5) `make test` â€“ full suite.
- Tests + gate:
  - Existing: `policy_tests.rs` parse failure tests (`#[should_panic]` on `parse_policy_state`, `Result` match on `parse_policy_state_with_counters`), NAT snapshot tests, filter compiler tests.
  - Move tests with variants â€“ policy parse tests stay with policy, NAT tests with NAT, etc.
  - Behavioral gate: `make test` in `userspace-dp/`, Go `go test ./pkg/dataplane/userspace/`, `make test-failover` (config apply path).
- Why it matters:
  - **Cross-domain coupling**: Single enum forces `policy.rs` to import NAT/filter/screen concepts, and NAT/filter modules to import policy error type â€“ circular dependency, blocks independent evolution.
  - **Maintainability**: Adding a new NAT error requires editing `policy.rs` â€“ wrong module, confusing. Domain experts (NAT, filter) should own their error variants.
  - **Review cost**: 616-LOC enum with 30+ variants is hard to review â€“ which variants are policy vs NAT vs filter? Splitting by domain makes it obvious.
  - **Exhaustiveness noise**: `match` on `SnapshotIntegrityError` in policy code must handle NAT/filter variants it never produces â€“ noisy, error-prone.
  - **Build cost**: Changing a filter error variant recompiles `policy.rs` and everything that depends on it â€“ unnecessary rebuilds.
- Fix direction (incremental):
  1. Create `userspace-dp/src/policy/snapshot.rs`, move policy-only variants from `SnapshotIntegrityError` to `PolicySnapshotError`. Keep `SnapshotIntegrityError` as wrapper with `Policy(PolicySnapshotError)` variant for now, plus existing NAT/filter variants. Update `parse_policy_state_with_counters` to return `PolicySnapshotError`, then `From` impl converts to wrapper. Update match sites to handle wrapper or use `From`. Run `cargo test --lib policy`, Go tests. PR #1.
  2. Create `userspace-dp/src/nat/snapshot.rs`, move NAT variants to `NatSnapshotError`. Update NAT parsers to return `NatSnapshotError`. Add `Nat(NatSnapshotError)` to wrapper. Run `cargo test --lib nat`. PR #2.
  3. Create `userspace-dp/src/filter/snapshot.rs`, move filter variants. Update filter compiler. Run `cargo test --lib filter`. PR #3.
  4. Repeat for screen, etc.
  5. Eventually, `SnapshotIntegrityError` becomes a pure wrapper, or keep as is but with variants defined in domain modules and re-exported â€“ reduces `policy.rs` by 616 LOC and removes cross-domain imports.
  6. Each step: verify error messages unchanged via Go tests, run `make test`, `make test-failover`.
- Labels: `refactor`, `dumping-ground`, `modularity`, `cold-path`, `coupling`
- Dedup note: Prior campaign named "cross-domain `SnapshotIntegrityError` / `policy.rs` dumping ground" as a monolith but did not provide specific decomposition or hot-path analysis. This finding provides the concrete module split (by domain with wrapper), the specific files and variants to move, and the verification method (error message preservation via Go tests). Not a duplicate â€“ it's the detailed refactor plan with hot-path analysis (N/A, cold path) that prior campaign lacked.

#### R3
- Title: `SessionTable` god-struct (27 fields, 6 responsibilities) â€“ extract cold HA, limit, wheel modules but keep core table+indexes together for locality
- Severity: High (maintainability, cache footprint, P5 NAT collision bug)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS for cold extracts, (D) DO-NOT-SPLIT for core table+indexes, (C) PERFORMANCE-POSITIVE for hot/cold SoA (risky)
- Evidence:
  - File: `userspace-dp/src/session/mod.rs:472-589`, `pub(crate) struct SessionTable` â€“ 27 fields
  - **6 responsibilities fused:**
    1. Table storage + primary index: `entries: Slab<SessionRecord>`, `key_to_handle: SeededKeyMap<u32>` â€“ HOT per-packet
    2. NAT demux indexes: `nat_reverse_index: SeededKeyMap<u32>`, `forward_wire_index`, `reverse_translated_index` â€“ HOT for NAT reply demux â€“ P5 single-value map causes 1:N collisions
    3. Timer wheel GC: `wheel: SessionWheel`, `last_gc_ns`, `last_pop_stats` â€“ WARM (push on hit, pop on 1s tick) â€“ already split to `wheel.rs` + `expire.rs` but driven inline
    4. Per-IP session limit: `session_limit_active: bool`, `session_limit_src_counts`, `session_limit_dst_counts` â€“ HOT on new flow only, not per-packet hit â€“ `#2134` OFF-gate
    5. HA sync: `deltas: VecDeque<SessionDelta>`, `delta_*`, `owner_rg_sessions`, `epoch_counter`, `origin` handling â€“ COLD (sync message, failover) except `origin.is_peer_synced()` check on install
    6. Stats/counters: `expired`, `create_drops`, `nat_reverse_key_collisions`, etc. â€“ COLD
  - `SessionEntry` (lines 315-430): 16 fields mixing hot per-packet (decision, metadata, last_seen_ns, expires_after_ns, closing/reset/established, counters, observed_tos/tcp_flags, wheel_tick) with cold (origin, install_epoch, created_ns, HA epochs). `metadata.clone()` in `lookup_with_origin` clones entire `SessionMetadata` including `Option<Arc<PolicyRuleCounter>>` â€“ **Arc clone per packet is hot-path regression** (atomic inc).
  - `nat_reverse_index`: single-value map, P5 â€“ 1:N collisions displace earlier sessions, causing hijacking. Should be multi-map.
- Proposed decomposition:
  - **Keep core table+indexes together (D)**: `entries`, `key_to_handle`, `nat_reverse_index`, `forward_wire_index`, `reverse_translated_index` must stay in same struct for locality. Lookup does up to 2 hash gets + 1 slab index â€“ splitting into separate structs would add pointer chase or generic indirection. The 4 indexes are probed together in `lookup_with_origin`, `find_forward_nat_match`, `remove_entry`, `index_forward_nat_key`. **Splitting would hurt L1/L2 locality and add indirection â€“ D class, do NOT split core.**
  - **Extract cold modules (B)**:
    - New `session/nat_index.rs` â€“ isolate `nat_reverse_index`, `forward_wire_index`, `reverse_translated_index` operations: `index_forward_nat_key`, `remove_forward_nat_index`, `find_forward_nat_match`, `find_forward_wire_match`. **Fix P5 first**: change `nat_reverse_index: SeededKeyMap<u32>` to `SeededKeyMap<SmallVec<[u32; 2]>>` or multi-map â€“ 1:N collision resolution. Then modularize. Keep methods on `SessionTable` but move bodies to `nat_index.rs` via `impl SessionTable` â€“ same pattern as `lookup.rs`, `install.rs`, `expire.rs`.
    - New `session/limit.rs` â€“ `session_limit_active`, `src_counts`, `dst_counts`, `session_limit_inc/dec`, `set_session_limit_active`. Tiny, already OFF-gated. Extract to clarify ownership. Keep `#[inline]` on inc/dec â€“ hot for new flows but not per-packet.
    - New `session/ha.rs` â€“ HA sync state machine: `SessionOrigin`, `deltas` ring, `delta_loss_pending`, `owner_rg_sessions`, `epoch_counter`, `upsert_synced_with_origin`, `promote_synced_with_origin`, `refresh_for_ha_transition`, `demote_owner_rg`, `standby_gate_decision`, `ExpireHaContext`. Keeps HA out of `mod.rs` and `expire.rs` core loop. Keep `origin` field in `SessionEntry` (1 byte).
    - Keep `session/wheel.rs` + `session/expire.rs` â€“ already well split. Consider moving `WheelPopStats` to `wheel.rs`.
    - Keep `session/key.rs`, `session/entry.rs`, `session/ctx.rs` â€“ already extracted.
  - **Hot/cold SoA split (C â€“ performance-positive but risky)**:
    - Split `SessionEntry` into `SessionHot` (decision, last_seen, timeouts, tcp flags, counters, wheel_tick) and `SessionCold` (metadata, origin, HA epochs).
    - Benefit: `lookup_with_origin` touches only hot part â€“ fits in 1-2 cache lines vs current ~200+ byte entry spanning 4 lines. `metadata.clone()` pulls cold data into hot path.
    - Risk: Churns every access site. `metadata.clone()` is required return value â€“ if we keep metadata in cold part, clone still pulls cold cache line. Better: return `Arc<SessionMetadata>` or split metadata into hot (policy_counter_idx, ingress_zone) vs cold (log flags, nat64). Major refactor.
    - Recommendation: C-class, measure first with `perf c2c` and `cargo show-asm`. If `metadata.clone()` dominates, consider `SessionLookup` borrowing or `Arc`.
  - **Eliminate Arc clone (A â€“ hot-path fix)**:
    - `lookup.rs:177` â€“ `metadata: entry.metadata.clone()` â€“ clones `Option<Arc<PolicyRuleCounter>>` â€“ atomic inc per packet!
    - Change `SessionLookup` to hold `policy_counter_idx: u32` instead of cloning entire metadata. Or change `SessionMetadata.policy_counter` to not be cloned â€“ store `Arc` in separate table indexed by `policy_counter_idx`, resolve on `account_packet`. Or change `lookup` to return `(&SessionDecision, &SessionMetadata)` with lifetime tied to `&mut self` (hard).
    - Simpler: derive `SessionMetadata` without `policy_counter` in `PartialEq`, and change `lookup` to return minimal hot fields. `account_packet` already has `policy_counter_idx`, can resolve Arc on demand.
- Hot-path preservation analysis:
  - **Inlining**: `lookup_with_origin` must stay `#[inline]`-friendly, no alloc, no `Vec`, no `HashMap` insert â€“ only gets and slab index. Current code meets this except `metadata.clone()` (Arc) and `push_to_wheel` second hash lookup (throttled). After Arc elimination, should be clean.
  - **No alloc**: `nat_reverse_index` lookup must stay single hash get + validation â€“ multi-map must use inline `SmallVec<[u32; 2]>` to avoid alloc on hit. `SmallVec` spills to `Vec` only on collision (rare) â€“ acceptable, collision path is cold.
  - **No dynamic dispatch**: No trait objects in hot path. `BookEntry` contains `PrefixSet` enum, not trait. Keep.
  - **Layout**: No `#[repr(C)]` or `#[repr(align)]` today. `SessionEntry` not cache-line padded. If SoA split, use `#[repr(C, align(64))]` on hot part, ensure hot part first field, no pointer chase. Verify with `std::mem::size_of` and `align_of`. `SessionKey` contains `IpAddr` (16 bytes) + ports â€“ key is 32+ bytes, entry is 200+ bytes.
  - **Lock scope**: `SessionTable` is per-worker, single-writer â€“ no locks in hot path. Keep. Do not introduce cross-worker sharing.
  - **How to verify**: 1) `cargo test -p userspace-dp session::` â€“ 191 tests; 2) `test-failover` â€“ HA integration; 3) `perf stat -e cycles,instructions,L1-dcache-load-misses,branch-misses` on `session_lookup_hits_after_install` bench before/after â€“ L1 misses should drop, cycles per lookup down; 4) `cargo show-asm --lib session::lookup::SessionTable::lookup_with_origin` â€“ verify no new calls, no alloc, no `lock xadd` (after Arc fix); 5) `cargo bloat` â€“ ensure no size regression.
- Tests + gate:
  - Existing: `session/tests.rs` (6,326 lines, 191 tests) â€“ comprehensive: lookup hits, wheel, TCP, NAT collision counter, session limit, expire HA, randomized HA transition.
  - Gate: `cargo test -p userspace-dp session::`, `cargo test --test '*' session_limit`, `make test`, `test-failover`.
  - **Perf gate**: `perf` before/after, `cargo show-asm`, `cargo bloat`.
  - **Critical**: `inplace_randomized_sequence_matches_reference` â€“ ensures HA correctness preserved after refactor.
- Why it matters:
  - **Per-packet hot path**: Every packet hits `lookup_with_origin` (hit) or `install` (miss). Fusing cold HA/limit/stats into `SessionTable` increases cache footprint â€“ `SessionEntry` 200+ bytes spanning 4 cache lines, `SessionTable` 27 fields â€“ L1 dcache pressure at 10Gbps.
  - **NAT 1:N collision (P5)**: Single-value `nat_reverse_index` silently drops sessions under interface-mode SNAT / DNAT-to-shared-backend â€“ correctness bug, not just modularity. Fixing to multi-map is both bug fix and modularity improvement.
  - **Arc clone per hit**: `metadata.clone()` does atomic inc on `policy_counter: Option<Arc>` â€“ unnecessary `LOCK XADD` per packet, measurable at 10Gbps. Eliminating it is performance-positive.
  - **HA fusion in GC**: `standby_gate_decision` inside expire loop couples HA policy to timer wheel â€“ makes testing HA logic in isolation hard, risks regression in `#2120` standby retention.
  - **Maintainability**: `mod.rs` 1,900 lines, `impl SessionTable` spread across 4 files but still 3,000+ lines total. New contributors struggle to find ownership â€“ limit counting, HA deltas, and NAT index are distinct concerns.
  - **Build cost**: Changing HA logic recompiles session table and all its users â€“ unnecessary rebuilds.
- Fix direction (incremental):
  **Phase 1 â€“ Bug fix + safe extracts (A/B):**
  1. **Fix P5**: Change `nat_reverse_index: SeededKeyMap<u32>` to `SeededKeyMap<SmallVec<[u32; 2]>>` in `mod.rs:480`. Update `index_forward_nat_key_parts` to push handle not replace. Update `find_forward_nat_match` to iterate candidates. Update `remove_forward_nat_index_parts` to remove specific handle. Add test for 1:N collision â€“ two sessions with same reverse key, both demux correctly. PR #1.
  2. **Extract `session/nat_index.rs`**: Move NAT index operations into new module via `impl SessionTable` block â€“ same pattern as existing `lookup.rs`, `install.rs`. No logic change, just file move. PR #2.
  3. **Extract `session/limit.rs`**: Move limit fields into `struct SessionLimit`, embed in `SessionTable`. Keep methods `#[inline]` delegating to `self.limit`. Update `install.rs:221` and `remove_entry`. PR #3.
  4. **Extract `session/ha.rs`**: Move HA state machine, `SessionOrigin`, deltas ring, `upsert_synced*`, `standby_gate_decision`, etc. Keep `origin` field in entry (1 byte). `expire.rs` calls `ha::standby_gate_decision`. PR #4.
  5. **Eliminate Arc clone**: Change `SessionLookup` to hold `policy_counter_idx: u32` instead of cloning entire metadata. Update `lookup.rs:177` to avoid `metadata.clone()`. Update `account_packet` to resolve Arc on demand if needed, or keep `policy_counter_idx` only. Verify with `cargo show-asm` â€“ no `lock xadd` in hot path. PR #5.
  **Phase 2 â€“ Hot/cold SoA (C â€“ measure first):**
  1. Profile `lookup_with_origin` with `perf record -g` â€“ confirm `metadata.clone()` and cache misses dominate.
  2. Split `SessionEntry` into `SessionHot` and `SessionCold` with `#[repr(C)]`, hot part first 64 bytes, aligned to 64.
  3. Update `lookup.rs`, `account_packet`, `push_to_wheel` to touch only hot part.
  4. Verify with `cargo show-asm`, `perf stat`, `inplace_randomized_sequence_matches_reference`.
  5. PR #6 (only if measurements show benefit).
  **Phase 3 â€“ Verification:**
  - `cargo test -p userspace-dp session::` â€“ 191 tests pass
  - `test-failover` â€“ HA integration
  - `perf` before/after â€“ L1 misses down, cycles per lookup down, no `lock xadd`
  - `cargo show-asm` â€“ `lookup_with_origin` ~200-300 instructions, no alloc, no lock
- Labels: `refactor`, `session`, `hot-path`, `conntrack`, `nat`, `P5`, `performance`, `ha`, `modularity`, `x-hpc`
- Dedup note: P5 NAT 1:N collision (`nat_reverse_index` single-value) â€“ tracked in ps-009, also in `#1760` collision counter. This finding provides the refactor plan (multi-map + modularize to `nat_index.rs`) with hot-path preservation (SmallVec inline, no alloc on hit). Not a duplicate of P5 bug report â€“ it's the modularization plan that fixes the bug. Prior P5 was a bug report; this is the refactor that fixes it. `#964` slab/multi-index already done â€“ this builds on it, do not re-slab. `#2005` code-motion split already done â€“ this proposes further cold extraction, not re-split of hot path. `#2120` HA standby gate already in `expire.rs` â€“ propose moving to `ha.rs` but keep logic identical.

#### R4
- Title: `ForwardingState` god-struct (55 fields) mixing hot FIB with cold config â€“ split into hot/cold or document/reorder, PBR evaluation should move to filter module
- Severity: High (maintainability, cache footprint, PBR coupling)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS for PBR move and field reordering, (C) PERFORMANCE-POSITIVE for hot/cold split, (D) DO-NOT-SPLIT for `ForwardingResolution`
- Evidence:
  - File: `userspace-dp/src/afxdp/types/forwarding.rs:14-278`, `pub struct ForwardingState` â€“ ~55 fields
  - **Hot per-packet**: `local_v4/v6`, `local_tables_*`, `connected_v*`, `routes_v4/v6: FastMap<String, Vec<RouteEntry>>`, `neighbors`, `tunnel_endpoints`, `gre_decap_index`, `egress`, `ifindex_to_zone_id`, `ingress_logical_ifindex` â€“ accessed in `lookup_forwarding_resolution_inner_ecmp` on every packet.
  - **Warm**: `filter_state`, `policy`, NAT tables, `ifindex_to_routing_instance`, `zone_host_inbound` â€“ accessed on session miss or specific paths.
  - **Cold**: `fabrics`, `fabric_skips`, `mirror_configs`, `cos`, `screen_profiles`, `app_catalog`, `session_timeouts`, `cold_path_*`, `zone_id_to_name` (logs), `reject_buckets`, `tcp_mss_*`, `alg_disable_flags`, `wg_engines`, etc. â€“ config metadata, stats, not per-packet.
  - Cloned via `ArcSwap` on config commit and fabric refresh â€“ cold fields increase clone cost and cache footprint.
  - No `#[repr]` or alignment guards; derives `Clone, Debug, Default`.
  - **PBR evaluation**: `ingress_route_table_override` in `forwarding/mod.rs:1521-1642` (121 LOC) â€“ PBR is a filter action (`then routing-instance`), not a FIB concern. Calls `crate::filter::evaluate_interface_filter_routing_instance_event_counted`, builds L4 extra, handles `FilterAction::Reject/Discard`, enqueues reject reply, emits filter log. Should live in filter module or dedicated PBR module, not forwarding.
  - **Monolithic route lookup**: `lookup_forwarding_resolution_inner_ecmp` (155 LOC) fuses local delivery table scoping (#3769, #3151), FIB LPM, PBR table canonicalization. `lookup_forwarding_resolution_v4_inner` (191 LOC) and v6 inner (184 LOC) fuse static vs connected choose, next-table recursion with `Vec<String> visited`, ECMP hash/select, neighbor lookup, tunnel resolve. Should split by responsibility: route.rs, local.rs, neighbor.rs, resolution.rs â€“ (B) keep in same crate for inlining.
  - **Flowless vs flow-backed**: `flowless_base_resolution` in `poll_descriptor/mod.rs:443-475` duplicates ordering logic (local before PBR). Extract shared `resolve_local_first` helper to `forwarding/local.rs` â€“ (C) prevents drift.
  - **ForwardingResolution**: 9-field POD (disposition, ifindexes, tunnel id, next_hop, MACs, VLAN) â€“ cohesive egress decision, used for LocalDelivery, ForwardCandidate, NoRoute â€“ D class, keep as is.
  - **Hot vs cold fusion**: `canonical_route_table` calls `DEFAULT_V4_TABLE.to_string()` on every packet when no table override â€“ **allocates String per packet!** Should use static str. `LOCAL_DELIVERY_IFINDEX0.fetch_add` atomic inc on cold path (NAT-only) â€“ acceptable. `Vec<String> visited` for next-table recursion â€“ cold (next-table rare), but could use inline array. PBR filter call already cold. No logging in hot FIB loop â€“ good.
- Proposed decomposition:
  - **PBR move (B)**: Move `ingress_route_table_override` to `crate::filter::pbr` or `forwarding/pbr.rs` with signature taking `&FilterState` instead of whole `ForwardingState`. Keep thin wrapper in forwarding that passes `&forwarding.filter_state` and `&forwarding.app_catalog`. Return `Option<CanonicalTable>` using interned strings or `SmallString` to avoid `format!` alloc on every PBR miss path; or keep `String` as it's session-miss cold. Seam: PBR is a filter action, not FIB â€“ cut along domain boundary.
  - **Route lookup split (B)**: New modules under `forwarding/`:
    - `forwarding/route.rs` â€“ `choose_*_route`, `canonical_route_table`, next-table recursion, ECMP hash/select primitives.
    - `forwarding/local.rs` â€“ table-scoped local delivery decision (`owned_here` logic), ingress-interface local, interface-NAT local, helper session install. Shared by flowless and flow-backed paths.
    - `forwarding/neighbor.rs` â€“ `lookup_neighbor_entry`, `parse_neighbor_entries`, dynamic shard lookup.
    - `forwarding/resolution.rs` â€“ `ForwardingResolution` constructors (`no_route_resolution`, local delivery const, forward candidate from neighbor).
    - Keep `lookup_forwarding_resolution_inner_ecmp` as thin orchestrator in `mod.rs` calling these helpers with `#[inline(always)]`.
  - **Flowless shared helper (C)**: Create `forwarding/local.rs` with `resolve_local_first(dst, ingress...) -> Option<ForwardingResolution>` shared by both `flowless_base_resolution` (poll_descriptor) and flow-backed path. Prevents ordering drift that caused past bugs. Keep `flowless_base_resolution` as thin wrapper in poll_descriptor (needs HA state) or move to forwarding with HA as parameter.
  - **ForwardingState hot/cold split (C)**:
    - Split into `ForwardingHot` â€“ routes, connected, local sets, neighbors, tunnels, egress, ifindex/zone maps â€“ accessed per packet.
    - `ForwardingCold` â€“ policy, NAT, filter, mirrors, screens, AppID, CoS, fabrics, cold-path histograms â€“ accessed on session miss or control plane.
    - Keep single `Arc<ForwardingState>` for ArcSwap simplicity, but nest hot/cold structs to improve cache locality and documentation. Or use SoA for routes.
    - Alternatively, keep struct but reorder fields: hot fields first, cold last, with comments and `#[allow]` grouping. Measure with `pahole` or Rust layout tools.
    - **Do NOT split ArcSwap** â€“ keep single Arc, just nest structs â€“ no extra pointer indirection on per-packet path. Nesting structs is same layout, no indirection.
  - **Alloc fix (C)**: Change `canonical_route_table` call sites to avoid allocation when table is `None`: use `&str` default static instead of `to_string()`, or intern default tables. The `DEFAULT_V4_TABLE.to_string()` on every packet is a hot-path regression â€“ must fix.
  - **ForwardingResolution**: D class â€“ keep as is, POD, Copy, no alloc, passed by value. Cohesive as "egress decision or lack thereof". Splitting into Local vs Forward would complicate call sites with no perf benefit.
- Hot-path preservation analysis:
  - **Inlining**: Route lookup functions must stay `#[inline]` and in same crate, no trait dispatch, no alloc on fast path. The `Vec<String> visited` for next-table is already cold (next-table rare); keep as is or use small array to avoid heap. PBR evaluation is session-miss only â€“ moving to filter module is fine if in same crate, no dynamic dispatch. Filter engine call already exists; moving does not add indirection.
  - **No alloc**: Hot FIB LPM loop must not allocate. Fix `DEFAULT_V4_TABLE.to_string()` alloc â€“ use static str. `Vec<String> visited` only on next-table recursion (rare) â€“ acceptable, or use `ArrayVec` to avoid heap. PBR `format!` for table name is session-miss cold â€“ acceptable, or use `SmallString`.
  - **No dynamic dispatch**: Neighbor lookup must remain branch-predictable hashmap get; no logging or allocation. ECMP hash is integer arithmetic â€“ keep inline. No trait objects.
  - **Layout**: `ForwardingState` has no `#[repr]` â€“ Rust layout is fine, but field order affects cache locality. Hot fields should be first. If splitting into hot/cold structs, ensure hot struct is first field, no extra pointer â€“ nesting is same layout. `ForwardingResolution` is POD, keep. No `#[repr(align(64))]` currently â€“ consider adding to hot struct if profiling shows false sharing, but probably not needed (per-worker, single-writer).
  - **Lock scope**: `ForwardingState` is Arc-swapped, read-only on per-packet path â€“ no locks. Keep. Do not introduce locks for PBR or route lookup.
  - **Table-scoped local delivery**: Cross-VRF protection (#3769, #3151) â€“ `owned_here` check must be preserved. Connected route table-scoping (#2388) â€“ `entry.table == table` check must be preserved. These are security-critical, must not be broken by refactor.
  - **How to verify**: 1) `cargo test -p userspace-dp forwarding` â€“ 4,245 LOC tests, covers local delivery table scoping, connected scoping, ECMP, next-table cycles; 2) `cargo test -p userspace-dp forwarding_build` â€“ FIB build tests; 3) `make test`, `test-failover` for HA RG owner path; 4) `perf` on `poll_binding_process_descriptor` â€“ route lookup is part of hot path, ensure no regression; 5) Disassembly of `lookup_forwarding_resolution_inner_ecmp` â€“ should remain single non-allocating leaf aside from next-table path, no `call alloc`; 6) Check for `to_string` alloc removal via `cargo bloat` or disassembly â€“ ensure no `alloc` in hot path.
- Tests + gate:
  - `forwarding/tests.rs` (4,245 LOC) â€“ local delivery table scoping (#3769, #3151), connected scoping (#2388), ECMP, next-table cycles, PBR.
  - `forwarding_build/tests.rs` (4,818 LOC) â€“ FIB build, route compilation.
  - `make test`, `test-failover` â€“ HA paths, PBR with HA RG owner.
  - **Perf gate**: `perf stat` on route lookup, ensure no alloc, no regression.
  - **Critical**: Table-scoped local delivery and connected route scoping must be preserved â€“ security critical, prevents cross-VRF leaks.
- Why it matters:
  - **Maintainability**: 2,671 LOC module with 5 responsibilities fused into 190-line functions with nested matches â€“ hard to review, risk of cross-VRF leak or ECMP polarization regressions. Changes to local delivery scoping or ECMP now touch large functions.
  - **PBR coupling**: PBR evaluation lives in forwarding but is a filter action â€“ forwarding imports filter engine, reject reply, event stream, AppID â€“ coupling two domains. PBR logic duplication risk across flowless vs flow-backed paths.
  - **Flowless ordering**: Ordering logic duplicated in docs and code (`flowless_base_resolution` vs flow-backed) â€“ caused past bugs where flowless packets went to NoRoute instead of LocalDelivery. Shared helper prevents drift.
  - **Cache locality**: 55-field struct mixes hot FIB with cold config â€“ cold fields increase ArcSwap clone cost and cache footprint. Hot fields (routes, local sets) should be grouped for better locality.
  - **Alloc on hot path**: `DEFAULT_V4_TABLE.to_string()` on every packet when no PBR override â€“ unnecessary allocation, hot-path regression. Must fix.
  - **Build cost**: Changing PBR logic recompiles forwarding and all its users â€“ unnecessary rebuilds. Moving PBR to filter module reduces rebuild scope.
- Fix direction (incremental):
  1. **Alloc fix (C)**: Audit `lookup_forwarding_resolution_inner_ecmp` for `to_string()` calls on default tables. Replace with static `&str` or interned strings. Verify with disassembly â€“ no `alloc` in hot path. PR #1.
  2. **PBR move (B)**: Create `filter/pbr.rs` or `forwarding/pbr.rs`, move `ingress_route_table_override` (121 LOC). Change signature to take `&FilterState` instead of `&ForwardingState`. Keep thin wrapper in forwarding that passes filter state and app catalog. Update flowless and flow-backed call sites. Run `forwarding/tests.rs`, `test-failover`. PR #2.
  3. **Route lookup split (B)**: Create `forwarding/route.rs`, `forwarding/local.rs`, `forwarding/neighbor.rs`, `forwarding/resolution.rs` with `#[inline]` helpers. Keep `lookup_forwarding_resolution_inner_ecmp` as thin orchestrator in `mod.rs` calling helpers with `#[inline(always)]`. Move v4 and v6 inners to `route.rs`, extract common logic via macro or generic over address family to reduce duplication. Run forwarding tests, verify disassembly â€“ no extra call frame. PR #3.
  4. **Flowless shared helper (C)**: Create `forwarding/local.rs` with `resolve_local_first()` shared by both `flowless_base_resolution` and flow-backed path. Update both call sites to use shared helper. Run `flowless_local_delivery_tests`, ensure ordering preserved. PR #4.
  5. **ForwardingState documentation/reorder (B)**: Document hot vs cold fields with comments `// --- Hot path ---` and `// --- Cold metadata ---`. Reorder hot fields first for better layout density. Consider nested `ForwardingHot` struct but keep single Arc â€“ nesting is same layout, no indirection. Measure with `pahole` or `cargo rustc -- --emit=llvm-ir`. Do not split ArcSwap. PR #5.
  6. **Verification after each PR**: Run `cargo test -p userspace-dp forwarding`, `cargo test -p userspace-dp forwarding_build`, `make test`, `test-failover`, `perf stat` on route lookup, disassembly diff to ensure no `alloc` and inlining preserved. Check table-scoped local delivery and connected route scoping still correct via existing tests.
- Labels: `refactor`, `hot-path`, `fib`, `pbr`, `forwarding`, `god-struct`, `cache-locality`, `x-hpc`
- Dedup note: Prior campaign did not specifically flag forwarding module monoliths. The instruction named "cross-domain `SnapshotIntegrityError` / `policy.rs` dumping ground" but not forwarding. This finding provides the specific decomposition (route.rs, local.rs, neighbor.rs, PBR move) and hot-path preservation analysis (inlining, no alloc, table-scoped security) that prior campaigns lacked. Not a duplicate â€“ new detailed refactor plan.

#### R5
- Title: TX drain orchestrator `enqueue_pending_forwards` (1,131 LOC) fusing build, segmentation, WG/GRE, output filter, CoS â€“ split by encapsulation phase
- Severity: High (maintainability, icache, UMEM ownership complexity)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ hot TX path, must preserve inlining, zero-copy, no dispatch
- Evidence:
  - File: `userspace-dp/src/afxdp/tx/dispatch/mod.rs:125-1256`, `pub(in crate::afxdp) fn enqueue_pending_forwards` â€“ 1,132 LOC including nested match arms
  - Lines 154-260: Prebuilt fast-path, FabricRedirect unsendable accounting, `enqueue_local_request_to_target_or_owner`
  - Lines 262-295: Mirror clone sampling
  - Lines 296-450: Target binding resolve, `try_inplace_rewrite_or_build` (Phase 8) inline â€“ handles Ethernet rewrite, VLAN, NAT, TTL, checksum, WireGuard encap, GRE encap, output filter classification
  - Lines 450-600: TCP segmentation gate, `segment_forwarded_tcp_frames_into_prepared`
  - Lines 600-800: Direct TX vs copy-path, DSCP rewrite, CoS queue ID
  - Lines 832-1256: `DirectTxFallbackReason` enum and fallback accounting
  - Comment at lines 1-24 acknowledges Phase 8 body extraction deferred: "The orchestrator (`enqueue_pending_forwards`) and Phase 8 (try_inplace_rewrite_or_build) intentionally stay in `mod.rs` for this PR"
  - Called from `poll_binding_process_descriptor` at multiple drain points â€“ fuses RX with TX.
  - **Responsibilities fused**: TX ring management, CoS queue selection, flow fair queueing, ECN, GSO segmentation, WireGuard encryption, GRE encap, output filter, DSCP/VLAN, stats/logging, BPF updates.
  - Prior campaign flagged "1,100+ line TX drain orchestrator" â€“ **confirmed, this is it**, not `drain_pending_tx` (which is already split into phases).
- Proposed decomposition:
  - Keep `enqueue_pending_forwards` as thin orchestrator (<150 LOC) that iterates `pending_forwards` and dispatches to phase helpers.
  - New modules under `tx/dispatch/`:
    - `phase_build.rs` â€“ `try_inplace_rewrite_or_build` extracted from mod.rs; split by encapsulation:
      - `build_plain()` â€“ Ethernet/IP/TCP/UDP rewrite, NAT, checksum â€“ `#[inline(always)]`
      - `build_wireguard()` â€“ WG encap path, monomorphized, no dyn dispatch â€“ `#[inline]`
      - `build_gre()` â€“ GRE encap path, calls `gre::encapsulate_native_gre_frame` â€“ `#[inline]`
    - `phase_segment.rs` â€“ thin wrapper around `tcp_segmentation::segment_forwarded_tcp_frames_into_prepared`; keep `#[cold]` on segmentation entry (already cold, TCP GSO only, returns early if tunnel).
    - `phase_mirror.rs` â€“ `enqueue_sampled_mirror_clone` handling â€“ already separate, keep.
    - `phase_slow.rs` â€“ already exists as `slow_path.rs` with `#[cold] #[inline(never)]`; keep.
  - `tx/dispatch/cos.rs` already exists â€“ keep CoS fast-path helpers; ensure `enqueue_local_request_to_target_or_owner` stays `#[inline(always)]`.
  - Split cold stats/logging out of hot loop:
    - Move `record_exception`, `record_mirror_clone_result`, `count_forwarded_tcp_segmentation_miss_if_needed` to `#[cold]` helpers (some already cold).
    - Ensure `format!` strings in `TxError::Drop/Retry` stay on Err paths only (already the case in `transmit_batch`).
  - Seam: cut by **encapsulation type and phase** â€“ build plain vs WG vs GRE, segmentation (cold), mirror (cold), slow path (cold). Orchestrator dispatches via match on `decision.resolution.tunnel_endpoint_id` and disposition, no vtable.
- Hot-path preservation analysis:
  - **Inlining**: Orchestrator and per-packet build functions must stay `#[inline(always)]` or `#[inline]` at `pub(in crate::afxdp)` boundary; Phase 8 split must not introduce out-of-line call in hot path â€“ use `#[inline(always)]` on `build_plain`, keep WG/GRE as separate `#[inline]` fns monomorphized by encapsulation enum, no vtable. Verify with `cargo asm --lib afxdp::tx::dispatch::enqueue_pending_forwards` â€“ hot loop should have no extra `callq`, icache footprint stable.
  - **No new heap allocation**: Zero new allocs per packet. `PendingForwardRequest` already reuses scratch Vec; `TxRequest.bytes` is moved, not cloned. Segmentation already allocates `Vec<PreparedTxRequest>` with `with_capacity(segment_count)` â€“ keep, it's cold path (large TCP only). Ensure new phase helpers take `&mut` references, no `Box`, `Arc` clone, or `String` creation in hot path. `format!` only on Err paths (already).
  - **No dynamic dispatch**: No trait objects or vtable in TX path. WG/GRE/tunnel selection via explicit `match` on `decision.resolution.tunnel_endpoint_id` / disposition; monomorphize per encapsulation, no trait objects. Do NOT introduce `Box<dyn Encapsulation>` â€“ would be hot-path regression.
  - **Layout**: `TxRequest`, `PreparedTxRequest` are hot per-packet; keep Rust repr (not shared with BPF). Do not add padding that spills cache line. Keep hot fields together.
  - **UMEM ownership**: Single-free invariant preserved via `recycle_ingress_frame`, `recycle_prepared_immediately_with_shared`, `remember_prepared_recycle`. Any split must keep recycle on all early-return paths â€“ existing `#[cfg(test)]` fault injection (`FORCE_OVERSIZED`, `FORCE_TUPLE_MISMATCH`) pins single-recycle; keep tests. New phase helpers must not take ownership of frame bytes â€“ only borrow, recycle stays in orchestrator.
  - **Endianness**: WG uses little-endian for counters, network byte order for IP; GRE uses big-endian for protocol type, checksum; TCP segmentation uses big-endian for seq numbers. Keep conversions cohesive in `gre.rs`, `wg/framing.rs`, `tx/tcp_segmentation.rs`; do not scatter. New `phase_build.rs` should call into these modules, not duplicate conversions.
  - **Branch/icache**: Splitting cold segmentation and mirror to `#[cold]` functions reduces icache pressure. Hot build path (plain/WG/GRE) should stay contiguous, no extra call boundary that defeats branch predictor. Keep hot inner loop (iter over pending_forwards) contiguous, no function call per packet except inlined build functions.
  - **How to verify**: 1) `cargo asm --lib afxdp::tx::dispatch::enqueue_pending_forwards > before.asm` / after â€“ diff for call count and icache footprint â€“ hot loop should have same or fewer calls (cold outlined); 2) `perf stat -e cache-misses,branch-misses,instructions,cycles` on CoS smoke (iperf3 -P 12, 1 Gbps cap) â€“ ensure <5% regression, ideally improvement from reduced icache; 3) `cargo test -p userspace-dp tx::dispatch` â€“ existing `dispatch_tests.rs` covers oversized, tuple mismatch, FabricRedirect drops, single-recycle invariant; 4) CoS smoke: `cargo test -p userspace-dp cos_queue_service` or `cargo test cos_smoke` â€“ verify no `post_drain_backup_cos_drops` spike; 5) Fairness: `cargo test fairness` â€“ DRR and waterfill fairness unchanged; 6) Failover: `cargo test test-failover` â€“ WG/GRE failover paths; 7) `cargo test -p userspace-dp tunnel wg` â€“ encap correctness.
- Tests + gate:
  - `cargo test -p userspace-dp tx::dispatch` â€“ dispatch_tests.rs covers oversized, tuple mismatch, FabricRedirect drops, single-recycle with fault injection.
  - CoS smoke: `cargo test -p userspace-dp cos_queue_service`, `cargo test cos_smoke` (if present).
  - Fairness: `cargo test fairness` â€“ ensures DRR waterfill unchanged.
  - Failover: `cargo test test-failover` â€“ exercises WG/GRE paths.
  - Tunnel: `cargo test -p userspace-dp tunnel`, `cargo test -p userspace-dp wg`, `cargo test tcp_segmentation`.
  - **Critical**: Single-recycle invariant tests with `FORCE_OVERSIZED=1` and `FORCE_TUPLE_MISMATCH=1` â€“ must pass after refactor.
- Why it matters:
  - **Maintainability**: 1,131 LOC function mixes 8+ responsibilities; difficult to reason about UMEM single-free on error paths; WG/GRE/segmentation changes risk cross-contamination.
  - **Icache pressure**: Large function with cold segmentation, mirror, and error handling code interleaved with hot build path â€“ wastes icache, increases branch mispredicts.
  - **UMEM ownership complexity**: Single-free invariant must be preserved on all early-return paths â€“ with 1,131 LOC, it's hard to verify. Splitting by phase makes ownership obvious â€“ each phase either recycles or passes ownership to next phase.
  - **Build cost**: Changing WireGuard encap recompiles the entire TX dispatch module and all its users â€“ unnecessary rebuilds. Splitting by encapsulation reduces rebuild scope.
  - **Review cost**: 1,131 LOC is un-reviewable â€“ PRs touching WG, GRE, or segmentation all touch the same file, causing merge conflicts.
  - **Performance clarity**: Hot build path (plain/WG/GRE) fused with cold segmentation and mirror â€“ obscures the performance-critical code.
- Fix direction (incremental):
  1. **Phase 8 extraction**: Create `tx/dispatch/phase_build.rs`, move `try_inplace_rewrite_or_build` (lines 296-450) into three functions: `build_plain()`, `build_wireguard()`, `build_gre()`, each `#[inline(always)]` or `#[inline]`. Keep shared checksum/NAT helpers in `forwarding_build/common.rs` or new `tx/dispatch/build_common.rs`. Replace inline block with match dispatch to build functions. Verify with `cargo test dispatch`, disassembly diff â€“ no extra call in hot path (inlined). PR #1.
  2. **Cold outlining**: Move `record_exception`, `record_mirror_clone_result` to `#[cold] #[inline(never)]` helpers in `telemetry.rs` or new `tx/dispatch/telemetry.rs`. Ensure `format!` strings only on Err paths. Verify disassembly â€“ hot loop no format strings. PR #2.
  3. **Segmentation wrapper**: Create `tx/dispatch/phase_segment.rs` with thin wrapper around `tcp_segmentation::segment_forwarded_tcp_frames_into_prepared`. Keep `#[cold]` as segmentation is cold path. Verify with `cargo test tcp_segmentation`. PR #3.
  4. **Orchestrator thinning**: After phases extracted, `enqueue_pending_forwards` should be <150 LOC â€“ simple loop dispatching to phase helpers. Verify with `cargo asm` â€“ hot loop instruction count same or lower. PR #4.
  5. **Verification after each PR**: Run `cargo test -p userspace-dp tx::dispatch`, CoS smoke, fairness, test-failover, tunnel tests. Run `perf stat` on iperf3, ensure no regression. Check disassembly for extra calls or allocs. Run single-recycle fault injection tests.
- Labels: `refactor`, `tx-hot-path`, `cos`, `monolith`, `icache`, `umem`, `x-hpc`
- Dedup note: Prior campaign flagged "1,100+ line TX drain orchestrator" â€“ **confirmed, this is `enqueue_pending_forwards` (1,131 LOC)**, not `drain_pending_tx` (which is already split into `tx/drain/phase_*.rs`). This finding provides the specific decomposition (phase_build.rs by encapsulation, phase_segment.rs, cold outlining) and hot-path preservation analysis (inlining, no alloc/dispatch, UMEM ownership, endianness) that prior campaign lacked. Not a duplicate â€“ it's the detailed refactor plan with verification methods.

#### R6
- Title: CoS queue service monolithic selection â€“ `select_exact_cos_guarantee_queue_waterfill` (438 LOC) fuses waterfill phases, honor refund, telemetry â€“ split by phase
- Severity: Medium (maintainability, auditability of honor refund invariant)
- Confidence: High
- Refactor class: (B) REQUIRES GUARDRAILS â€“ hot CoS selection, must preserve inlining and no alloc
- Evidence:
  - File: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:926-1363`, `select_exact_cos_guarantee_queue_waterfill` â€“ 438 LOC with nested phase logic, honor refund, epoch bits.
  - File: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:711-925`, `select_exact_cos_guarantee_queue_with_lease_telemetry` â€“ 215 LOC.
  - File: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:183-244`, `drain_shaped_tx` â€“ 62 LOC orchestrator.
  - **Hot/cold fusion**: `record_cos_queue_lease_acquire` (telemetry aggregation) inlined in hot path, `count_park_reason`, `park_cos_queue` with log, `ExactCoSScratchBuild::Drop` with error String â€“ cold but inlined.
  - `select_exact_cos_guarantee_queue_waterfill` does complex computation: waterfill pass 1/2, honor refund, epoch bits, but no alloc â€“ uses stack arrays and bitmasks. Good.
- Proposed decomposition:
  - New modules under `cos/queue_service/`:
    - `select_waterfill.rs` â€“ waterfill phase 1/2, honor refund logic; keep `#[inline]` on entry, split internal helpers as `#[inline(always)]` for bit operations.
    - `select_fast.rs` â€“ fast-path and lease telemetry; already small.
    - `lease.rs` â€“ `maybe_top_up_cos_queue_lease`, `record_cos_queue_lease_acquire` â€“ mark telemetry aggregator `#[inline]` but keep cold logging out.
  - Keep `drain.rs` and `service.rs` as is â€“ already split per #1035, #1331.
  - Move cold telemetry (`count_park_reason`, `park_cos_queue` with log) to `#[cold]` helpers; ensure `ExactCoSScratchBuild::Drop { error: String }` only constructed on cold error path (already).
  - `cos/queue_service/mod.rs` becomes thin re-export and `drain_shaped_tx` orchestrator (<100 LOC).
- Hot-path preservation analysis:
  - **Inlining**: Selection functions hot, called per drain tick â€“ keep `#[inline]` at module boundary. Waterfill internal loops must stay `#[inline(always)]` to avoid call overhead in tight bucket scan.
  - **No alloc**: No alloc in selection â€“ uses `VecDeque` for batch items allocated once per queue; do not introduce `Vec` or `HashMap` in waterfill.
  - **No dynamic dispatch**: No vtable; `CoSBatch::Local/Prepared` match static; keep.
  - **Layout**: `CoSQueueRuntime`, `SharedCoSExactBacklog`, `CoSQueueLease` have `#[repr(align(64))]` â€“ preserve. See `types/shared_cos_lease/lease.rs:74`, `backlog.rs:11,18`, `vtime.rs:36`, `epoch.rs:117,127,142,176`. Do not reorder fields.
  - **Atomic ordering**: Single-writer per worker for queue state; atomics use `Ordering::Relaxed` â€“ preserve. Lease acquire uses Acquire/Release â€“ keep.
  - **How to verify**: 1) `cargo asm` on `drain_shaped_tx` â€“ ensure waterfill loop unrolled similarly, no extra calls; 2) Perf on CoS fairness gate â€“ bimodal fairness regression indicates mis-split (honor refund invariant broken); 3) `cargo test -p userspace-dp cos_queue_service` â€“ waterfill, fast-path, lease telemetry tests; 4) `cargo test fairness` â€“ DRR and waterfill fairness under iperf3 -P 12; 5) CoS smoke: enqueue 1 Gbps cap, verify no `post_drain_backup_cos_drops` spike; 6) `test-failover` â€“ lease handoff on failover.
- Tests + gate:
  - `cargo test -p userspace-dp cos_queue_service` â€“ waterfill, fast-path, lease telemetry.
  - `cargo test fairness` â€“ DRR and waterfill fairness.
  - CoS smoke, `test-failover`.
- Why it matters:
  - **Maintainability**: Waterfill selection 438 LOC with nested phase logic; honor refund invariant (hb166 T-2) hard to audit. Splitting phases makes invariant obvious.
  - **Telemetry fusion**: `record_cos_queue_lease_acquire` inlined in hot path â€“ should be `#[inline]` but cold logging out. Clear separation.
  - **Review cost**: Changes to waterfill risk fairness regressions â€“ isolated module with focused tests reduces risk.
- Fix direction:
  1. Split waterfill phases into separate `#[inline]` fns in `select_waterfill.rs`; keep bit operations `#[inline(always)]`.
  2. Move lease telemetry aggregation to `#[inline]` but cold logging to `#[cold]`.
  3. Keep `#[repr(align(64))]` structures untouched â€“ do not reorder fields.
  4. Verify with `cargo asm`, CoS fairness gate, `test-failover`.
- Labels: `refactor`, `cos`, `hot-path`, `waterfill`, `telemetry`
- Dedup note: #1035, #1331 already split drain/service/submit; this continues decomposition of selection. Prior campaign did not flag CoS selection monolith specifically. Not a duplicate.

### Medium confidence

#### R7
- Title: `ForwardingState` god-struct (55 fields) â€“ document hot vs cold, reorder fields, consider nested hot/cold structs
- Severity: Medium (cache locality, clone cost, maintainability)
- Confidence: Medium
- Refactor class: (B) for documentation/reorder, (C) for hot/cold split (measure first)
- Evidence: See R4 evidence â€“ 55 fields mixing hot FIB with cold config. Cloned via ArcSwap â€“ cold fields increase clone cost.
- Proposed: Document hot vs cold with comments, reorder hot fields first. Consider nested `ForwardingHot` struct but keep single Arc â€“ nesting is same layout, no indirection. Measure with `pahole`.
- Hot-path preservation: Nesting structs is fine (same layout). Do not split ArcSwap â€“ keep single Arc. Avoid extra pointer indirection. Verify cache line usage, no change to hashing.
- Tests: `forwarding/tests.rs`, `forwarding_build/tests.rs`, `make test`, `test-failover`.
- Why it matters: 55-field struct hard to reason about hot set; accidental cold work can creep into fast path. Clear separation guides future changes. Clone cost reduction.
- Fix: Document, reorder, consider nested structs. Measure before/after with `perf` and clone time.
- Labels: `god-struct`, `cache-locality`, `SoA`
- Dedup note: Not previously flagged. New finding.

#### R8
- Title: `SessionEntry` hot/cold fusion â€“ `metadata.clone()` does Arc clone per packet, `push_to_wheel` second hash lookup â€“ eliminate Arc clone, consider SoA
- Severity: Medium (performance â€“ atomic inc per packet, cache misses)
- Confidence: Medium
- Refactor class: (A) for Arc clone elimination (hot-path fix), (C) for SoA split (risky, measure first)
- Evidence: See R3 evidence â€“ `lookup_with_origin` clones metadata with `Option<Arc<PolicyRuleCounter>>` â€“ atomic inc per packet. `push_to_wheel` does second hash lookup, throtthed but still warm. `SessionEntry` 200+ bytes spanning 4 cache lines.
- Proposed: Eliminate Arc clone by changing `SessionLookup` to hold `policy_counter_idx: u32` instead of cloning metadata. Or store Arc in separate table. For SoA, split `SessionEntry` into `SessionHot` (decision, timeouts, counters) and `SessionCold` (metadata, origin, HA). Use `#[repr(C, align(64))]` on hot part.
- Hot-path preservation: Eliminating Arc clone removes `LOCK XADD` per packet â€“ measurable improvement. SoA split must keep hot part in first 64-128 bytes, no pointer chase. Verify with `perf` and `cargo show-asm` â€“ no `lock xadd`, fewer memory accesses.
- Tests: `session/tests.rs` 191 tests, `inplace_randomized_sequence_matches_reference`, `test-failover`, perf on `session_lookup_hits_after_install`.
- Why it matters: Arc clone per packet is unnecessary atomic overhead. SoA improves cache locality â€“ `lookup_with_origin` touches only hot part, fits in 1-2 cache lines vs 4. At 10Gbps, cache misses and atomic ops matter.
- Fix: Phase 1 â€“ eliminate Arc clone (A). Phase 2 â€“ measure SoA benefit with `perf c2c`, only do if significant improvement.
- Labels: `session`, `hot-path`, `performance`, `cache-locality`, `x-hpc`
- Dedup note: Not previously flagged as refactor. P5 covered NAT collisions, but not Arc clone or SoA. New finding.

### Low confidence / Do-not-split

#### R9
- Title: `BindingWorker` god-struct â€“ already well decomposed, DO NOT SPLIT
- Severity: Low
- Confidence: High
- Refactor class: (D) DO-NOT-SPLIT
- Evidence: `userspace-dp/src/afxdp/worker/mod.rs:98-200` â€“ 19 fields but already sub-structured into `WorkerXskRings`, `WorkerTxPipeline`, `WorkerCos`, `WorkerScratch`, etc. per #959. Hot fields (`xsk`, `tx_pipeline`, `scratch`, `flow`) accessed per packet, cold fields (`telemetry`, `timers`, `bind_meta`) accessed per batch. Cache locality: `cold_path` co-located with `flow` per #1620 because policy-eval slow path already touches `binding.flow` â€“ sharing cachelines avoids compulsory L1 miss.
- Reasoning: Further splitting would break cache locality and increase pointer chasing. Existing sub-structs already isolate responsibilities while keeping hot fields in single allocation. Splitting would require `Arc` or references, adding indirection on hot path.
- Why keep: Cohesive â€“ represents single worker's binding state. Sub-structs provide modularity without sacrificing performance. Any further split risks cache misses.
- Labels: `do-not-split`, `cache-locality`, `performance`
- Dedup note: #959 completed decomposition; this is explicit anti-pattern warning, not a new finding.

#### R10
- Title: `stage_flow_cache_hit` (457 LOC) â€“ cohesive fast path, DO NOT FURTHER SPLIT
- Severity: Low
- Confidence: High
- Refactor class: (D) DO-NOT-SPLIT
- Evidence: `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:65-521` â€“ 457 LOC handling flow cache lookup, neighbor validation, TTL, NAT rewrite, mirror, forward request â€“ all on fast path for cached flows (90%+ of packets). Already extracted from mod.rs in #1327.
- Reasoning: Flow cache hit is the hottest path. Function is large because it handles multiple fast-path concerns (NAT, TTL, mirror) that are tightly coupled and must stay inlined. Splitting would introduce call/return overhead on every cached packet and increase icache footprint. Cohesive â€“ single pipeline from cache lookup to forward/recycle.
- Why keep: Further extraction would regress performance. 457 LOC justified by hot-path tightness. Focus refactoring on slower session-miss path instead.
- Labels: `do-not-split`, `hot-path`, `flow-cache`, `performance`
- Dedup note: #1327 completed extraction; this warns against undoing it.

#### R11
- Title: `evaluate_policy_result_l3_aware` (191 LOC) â€“ exemplary hot path, DO NOT SPLIT
- Severity: Low
- Confidence: High
- Refactor class: (D) DO-NOT-SPLIT â€“ exemplary, keep as is
- Evidence: `userspace-dp/src/policy.rs:3393-3584` â€“ calls only `try_match_rule` and atomic counter, no logging, no alloc, no mutex. Flow: zone 0 guard â†’ zone-pair scan â†’ wildcard merge â†’ both-any â†’ global with scope â†’ default with atomic add. `try_match_rule` (178 LOC) â€“ inactive check, compiled_apps.matches (inline, no alloc), address match (PrefixSet, no alloc), hit_counter.add (atomic).
- Reasoning: Hottest cold-path function (every new flow). Current implementation optimal â€“ no cold fusion. Splitting would add call overhead and risk inlining failure. The function is cohesive â€“ single responsibility: evaluate policy for a flow.
- Why keep: Exemplary hot path â€“ do NOT add logging, metrics, or non-inline calls. Document as hot path with warning against cold fusion.
- Labels: `do-not-split`, `hot-path`, `exemplary`
- Dedup note: None â€“ this is a positive example, not a monolith to split.

#### R12
- Title: `ForwardingResolution` POD â€“ cohesive egress decision, DO NOT SPLIT
- Severity: Low
- Confidence: High
- Refactor class: (D) DO-NOT-SPLIT
- Evidence: `userspace-dp/src/afxdp/types/forwarding.rs:930-941` â€“ 9 fields: disposition, ifindexes, tunnel id, next_hop, MACs, VLAN. Constructors for LocalDelivery, ForwardCandidate, NoRoute, etc. Used as POD, Copy, passed by value, no alloc.
- Reasoning: Cohesive as "egress decision or lack thereof". Splitting into Local vs Forward would complicate call sites with no perf benefit. Disposition enum already discriminates.
- Why keep: POD, no alloc, passed by value â€“ optimal. Splitting would add enum indirection.
- Labels: `do-not-split`, `cohesive`, `pod`
- Dedup note: None.

## 7. Suggested issue split â€“ sequenced for safe landing

**Phase 1 â€“ Mechanical moves and cold outlining (A/C) â€“ no hot-path risk:**
1. **R6 â€“ Flowless helpers mechanical move** (A): Create `flowless.rs`, move enum/functions/tests, add `#[inline]`. Verify disassembly unchanged. PR #1 â€“ trivial, sets precedent.
2. **R1-F2 â€“ Cold telemetry outlining** (C): Create `telemetry_debug.rs`, move debug_log! bodies to `#[cold] #[inline(never)]`. Verify icache improvement via perf. PR #2.
3. **R1-F3 â€“ Event emission outlining** (B): Annotate emit functions `#[cold] #[inline(never)]`, verify call sites only on cold branches. PR #3.

**Phase 2 â€“ Isolated extractions (B) â€“ cold or session-miss only:**
4. **R1-F4 â€“ NAT pre-routing extraction** (B): Create `nat_pre_routing.rs` pure function, unit test each translation type. Verify no alloc. PR #4.
5. **R2 â€“ SnapshotIntegrityError domain split** (B): Split by domain with wrapper, preserve error messages. Run Go tests. PR #5-7 (policy, NAT, filter).
6. **R1-F5 â€“ Host-local extraction** (B): Create `host_local.rs`, move junos-host/flowless, preserve Junos order via existing tests. PR #8.
7. **R1-F7 â€“ Session install extraction** (B): Create `session_install.rs`, isolate BPF publish transaction. Verify with test-failover. PR #9.
8. **R3 â€“ Session cold modules** (B): Extract `session/nat_index.rs`, `session/limit.rs`, `session/ha.rs`. Fix P5 multi-map first (A). Eliminate Arc clone (A). PR #10-13.
9. **R4 â€“ Forwarding split** (B): Create `forwarding/route.rs`, `local.rs`, `neighbor.rs`, move PBR to filter/pbr.rs. Fix `to_string` alloc (C). PR #14-17.
10. **R5 â€“ TX phase build split** (B): Create `tx/dispatch/phase_build.rs` by encapsulation, keep inlined. Verify with CoS gates. PR #18-20.
11. **R6 â€“ CoS selection split** (B): Split waterfill phases, move telemetry cold. Verify fairness gate. PR #21.

**Phase 3 â€“ Major splits (B) â€“ requires PacketCtx:**
12. **R1-F1 â€“ Session hit/miss split** (B): Create `session_hit.rs`, `session_miss.rs`, define `PacketCtx`. Largest change, do last. Verify with full test suite, perf, disassembly. PR #22.

**Phase 4 â€“ Performance-positive (C) â€“ measure first:**
13. **R3 â€“ Session SoA split** (C): Only if Phase 1-3 show cache miss improvement potential. Measure with `perf c2c` before committing. PR #23 (optional).
14. **R4 â€“ ForwardingState hot/cold split** (C): Only if clone cost or cache footprint measured as issue. PR #24 (optional).
15. **R8 â€“ SessionEntry SoA** (C): Only if Arc elimination insufficient. PR #25 (optional).

**Do NOT do:**
- **R9 â€“ BindingWorker further split** (D): Would break cache locality (`cold_path` co-located with `flow` per #1620).
- **R10 â€“ stage_flow_cache_hit further split** (D): Hottest path, 457 LOC justified, further split hurts icache.
- **R11 â€“ evaluate_policy_result_l3_aware split** (D): Exemplary hot path, keep as is.
- **R12 â€“ ForwardingResolution split** (D): Cohesive POD, no benefit.

**Verification for each PR:**
- `cargo test --lib <module>` â€“ unit tests move with code
- `make test` â€“ full workspace
- `make test-failover` â€“ HA paths
- CoS smoke/fairness â€“ `cargo test cos`, `cargo test fairness`
- Disassembly diff â€“ `cargo asm` or `objdump -d`, hot loop byte-identical (allow cold reordering)
- `perf stat -e instructions,cache-misses,branch-misses` â€“ within 1% of baseline, ideally improved
- `cargo bloat` â€“ no size regression in hot symbols
- Single-recycle fault injection â€“ `FORCE_OVERSIZED=1`, `FORCE_TUPLE_MISMATCH=1`

**Sequencing rationale:**
- Mechanical moves first â€“ low risk, establishes pattern, improves build time early.
- Cold outlining next â€“ performance-positive, reduces icache, no logic change.
- Isolated extractions next â€“ each module independently testable, small PRs.
- Major split last â€“ requires PacketCtx, most churn, benefits from prior extractions.
- Performance-positive splits optional â€“ measure before committing, only if profiling shows benefit.
- Do-not-split explicit â€“ prevents well-intentioned but harmful refactors.

---

*End of ps-review-010 â€“ 2026-07-06*
