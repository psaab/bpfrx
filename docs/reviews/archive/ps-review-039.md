# ps-review-039 — Refactor / Modularity Audit — Monolith Detection with Hot-Path Preservation

**Base commit:** `f70146951583823a5ace87b0b11a2e58f46e8db9`
**Date:** 2026-07-08T15:51:53Z
**Output path:** `/tmp/ps-review-039.md`
**Batch files:** 10 (a1a a1b a1c a1d a1e a1f a1g a2 a3 a4)
**Focus:** Rust AF_XDP dataplane hot path (per-packet forwarding orchestrator, CoS TX drain, session table, policy/verdict) + Go control-plane monoliths (compiler, NAT, daemon, cluster, routing)

## Duplicate suppression summary


Prior refactor issues (read for dedup):
- #4404 refactor: poll_descriptor/mod.rs (5,759 LOC) — decompose god-function (1,368 LOC, 15+ resp) — ALREADY FILED
- #4407 refactor: daemon.go Daemon god-struct (150+ fields, ~3,500 LOC) + daemon_apply.go applyConfigLocked (1,148 LOC) — ALREADY FILED  
- #4408 refactor: Rust hot-path god-functions — tx/dispatch enqueue_pending_forwards (1,131 LOC) + cos/queue_service waterfill (438 LOC) — ALREADY FILED
- #4409 refactor: Rust NAT — nat/allocator.rs PortAllocator god-struct (926 LOC) + nat/source.rs (1,190) + nat/tests.rs (8,685) — ALREADY FILED
- #4421 Refactor/modularity backlog — policy.rs, nat64.rs, neighbor.rs, SnapshotIntegrityError, SessionTable, ForwardingState, flowexport, firewall-filter, rules.go — ALREADY FILED
- #4405 refactor: compiler_validate_strict.go (6,997 LOC) — CLOSED (pure code-motion done)
- Perf/HPC findings naming hot paths: per-packet forwarding orchestrator, CoS waterfill, session table hot/cold, TX drain

Hot paths that MUST NOT be disturbed (from prior perf findings):
- poll_binding_process_descriptor: per-packet orchestrator, single-recycle invariant, Junos order (host-inbound→lo0→junos-host), table-scoped local delivery, connected-route scoping
- tx/dispatch enqueue_pending_forwards: single-recycle, no-alloc, zero-copy, UMEM frame ownership
- cos/queue_service waterfill: CoS guarantee-guard (#4246), SFQ, trigger_kernel_arp_probe allocation-freedom
- session/mod.rs SessionTable + SessionEntry: hot 5-tuple lookup + NAT reverse-index (#4399 P5), per-IP limits, wheel timing, Arc clone per packet
- ForwardingState FIB lookup: hot per-packet, but construction is cold


**Coverage of prior campaigns checked:**
- /tmp/ps-review-*.md (all prior, 77 files)
- /tmp/codex-review-*.md, /tmp/agy-review-*.md, /tmp/fable-review-*.md, /tmp/opus-review-*.md
- GitHub issues #4404-#4421 refactor/modularity backlog
- Verified via `gh issue list --json number,title --limit 100` filtered for refactor/poll_desc/PortAlloc/NAT/modular keywords

## File-size / shape inventory — the module checklist

### Top Rust non-test production files (by LOC)

| File | LOC (wc -l) | Prod LOC | Largest fn | Responsibilities | Threshold |
|------|------------|----------|-----------|----------------|-----------|
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 6042 | ~4900 | poll_binding_process_descriptor 4724 | 15+ (stages 1-11, flow-cache, session-hit, session-miss, flowless, host-local, NAT pre-routing, filter, route, screen, policy, SNAT, install, telemetry, HA, debug-log) | >5000 CRITICAL — GOD-FUNCTION |
| `userspace-dp/src/afxdp/poll_stages.rs` | 3527 | ~971 prod | stage_screen_check 304 | 9 stage fns, pure code-motion extraction from poll_descriptor | Well-decomposed (D) |
| `userspace-dp/src/afxdp/forwarding/mod.rs` | 2822 | ~2822 | lookup_forwarding_resolution_inner_ecmp 192 | 68 free fns, 5 god-fns >100 LOC — FIB/NAT/fabric/tunnel fused but modular | ~3000 (B) |
| `userspace-dp/src/afxdp/coordinator/wg_control.rs` | 2280 | ~2280 | ~315, ~211 | 5 resp (socket lifecycle + control loop + handshake SM + ECN cmsg + poll) | >2000 (A) |
| `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` | 2174 | ~414 | enqueue_reject_reply 199 | TCP RST/ICMP unreach build, TX-budget, rate-limit, VLAN fix, output-filter, counters | Well-extracted cold (D) |
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | 2058 | ~2058 | select_exact_cos_guarantee_queue_waterfill 432 | Waterfill + epoch refill + clamping + Phase-1 ascend + Phase-2 descend + WRAP | >2000 (B) |
| `userspace-dp/src/session/mod.rs` | 2054 | ~2054 | — | SessionTable 25 fields (7 resp), SessionEntry 16 fields | >2000 (B god-struct) |
| `userspace-dp/src/afxdp/neighbor.rs` | 2036 | ~2036 | neigh_monitor_thread 272 | 4 resp (probe craft, netlink mgmt, monitor thread, warmer) | ~2000 (B) |
| `userspace-dp/src/afxdp/cold_path_hist.rs` | 1866 | ~950 prod | — | Histogram collection (cold path) | <2000 (D) |
| `userspace-dp/src/afxdp/frame/inspect.rs` | 1813 | ~1813 | parse_session_flow_from_bytes 141 | L2 parse, L3 parse, VLAN, IP options, 5× IPv6 EH walker duplication | ~2000 (B) |
| `userspace-dp/src/afxdp/wg/engine.rs` | 1805 | ~1805 | try_encap/try_decap on hot path | WG protocol — single resp, under threshold | (D) cohesive |
| `userspace-dp/src/afxdp/types/cos.rs` | 1786 | ~1786 | — | CoSInterfaceRuntime 28 fields (5 lifecycles), FlowFairState boxed | ~2000 (B) |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | 1776 | ~1776 | — | Worker loop body | Under threshold |
| `userspace-dp/src/afxdp/frame/mod.rs` | 1710 | ~1710 | verify_built_frame_checksums 192 debug-only | 6-resp kitchen sink: VLAN shift, NAT v4/v6, port rewrite, NAT64, inject, debug-verify | ~2000 (A) |
| `userspace-dp/src/event_stream/mod.rs` | 1693 | ~1693 | IO thread 700 | Transport + sequencing + clock + RT_FLOW | ~1700 (A if, D defer) |
| `userspace-dp/src/afxdp/worker/mod.rs` | 1625 | ~1625 | — | Worker lifecycle | Under |
| `userspace-dp/src/afxdp/frame/wg.rs` | 1561 | ~604 prod / 957 test | wg_encap_frame 253 | WG encap — test-heavy, prod clean | (D) |
| `userspace-xdp/src/lib.rs` | 1541 | ~1541 | classify_xxx GRE-inner byte-order | XDP shim | (D) |
| `userspace-dp/src/screen/mod.rs` | 1540 | ~1540 | check_packet_with_zone_id_opts 374 | 16 screen checks, 5 SYN-flood phases + ICMP/UDP flood + stateless | ~1500 (B) |
| `userspace-dp/src/afxdp/neighbor_resolver.rs` | 1512 | ~1512 | — | Neighbor netlink + rate-limit | (B) part of neighbor monolith |
| `userspace-dp/src/afxdp/event_emit.rs` | 1492 | ~1492 | — | Event emission (cold) | Under |
| `userspace-dp/src/afxdp/tx/dispatch/mod.rs` | 1486 | ~1486 | enqueue_pending_forwards 1048 | TX drain god-func: Phase 8 + PTB + seg + fabric + prebuilt + owned + live | ~1500 (B) |
| `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs` | 1460 | ~1460 | legacy lease + v8 fair-share | Legacy + v8 split pending | ~1500 (A) |
| `userspace-dp/src/nat/allocator.rs` | 1416 | ~1416 | allocate_translation_locked 114 | PortAllocatorShared: hot bitmap + cold persistent/GC/stats | ~1500 (C perf-positive) |
| `userspace-dp/src/afxdp/neighbor_dispatch.rs` | 1399 | ~1399 | — | pending_neigh + neg_neigh + dynamic-learn | (B) neighbor split |
| `userspace-dp/src/nat/source.rs` | 1389 | ~1389 | match_source_nat_result_for_tuple 336 | SNAT rule parsing + L4 match + scope + pool alloc driver — 6 resp | ~1500 (B) |
| `userspace-dp/src/afxdp/umem/mod.rs` | 1345 | ~1345 | — | UMEM lifecycle | (D) |
| `userspace-dp/src/afxdp/tx/cos_classify.rs` | 1335 | ~1335 | — | TX-selection + BA reclassify + LP + enqueue + demote + admission | ~1500 (B) |
| `userspace-dp/src/screen/scan.rs` | 1213 | ~592 prod / 621 test | ScanCore::check 61 | Generic ScanCore + thin wrappers, one-source-of-truth per #2234 | (D) clean |
| `userspace-dp/src/afxdp/poll_descriptor/filter.rs` | 1201 | ~640 | evaluate_non_pbr_input_filter 70 | Cold filter extraction | (D) clean split |
| `userspace-dp/src/protocol/binding.rs` | 1168 | ~1168 | — | Binding array construction | (A) mechanical if needed |
| `userspace-dp/src/event_stream/codec.rs` | 1165 | ~1165 | — | Event codec | Companion to mod.rs |
| `userspace-dp/src/afxdp/shared_ops.rs` | 1131 | ~1131 | — | Shared session ops | Under |
| `userspace-dp/src/nat/destination.rs` | 1088 | ~1088 | lookup_with_counter_scoped ~110 | DNAT exact+wildcard+PROTO_ANY+prefix-LPM | (D) cohesive |
| `userspace-dp/src/afxdp/cos/tx_completion.rs` | 1080 | ~1080 | — | 3 resp: completion drain + fill refill + RX/TX wake | Minor (C)/(D) |
| `userspace-dp/src/nat64.rs` | 2527 | ~2527 | translate_v6_to_v4 ~200 | NAT64 forward/reverse/EH/frag/ICMP-embed | ~2500 (defer, next feature) |

### Top Go non-test non-gen production files (by LOC)

| File | LOC | #func/#type | Smell | Action |
|------|-----|------------|-------|--------|
| `pkg/config/compiler_validate_warn.go` | 3330 | 35 funcs | Warn validators monolith, strict already split | (A) split per-domain |
| `pkg/dataplane/userspace/protocol.go` | 2979 | 72 types, 1 func | Wire-format 12 domains | (A) 12 files by domain |
| `pkg/config/compiler_nat.go` | 2529 | 37 funcs | 5 NAT types + 4 validators + 8 helpers | (A) 6 files + move validators |
| `pkg/vrrp/instance.go` | 2417 | 52 funcs/3 types | VRRP SM: state + RX + TX + GARP + VIP | (D) single coherent SM |
| `pkg/daemon/daemon_run.go` | 2329 | 9 funcs | Bootstrap + naming + run-loop + exit | (D) already #4407 |
| `pkg/config/compiler.go` | 2110 | — | 3-phase fusion (parse→validate→compile) | (A) extract phases |
| `cmd/cli/show.go` | 2100 | — | CLI show commands — not inspected | — |
| `pkg/ddns/surface_a.go` | 1957 | — | DDNS state machine (#4421 backlog) | Listed in #4421 |
| `pkg/frr/policy_render.go` | 1938 | — | FRR rendering — slightly over | Minor |
| `pkg/daemon/daemon_apply.go` | 1935 | 20 funcs | applyConfigLocked god-function 1148 | Already #4407 |
| `pkg/api/metrics_descriptors.go` | 1896 | 279 NewDesc | Prometheus descriptor monolith | (A) helper methods |
| `pkg/routing/tunnel.go` | 1877 | 3 types ~30 funcs | Tunnel lifecycle + keepalive + WG + MTU + VRF | (A) 5 responsibilities |
| `pkg/cluster/sync_conn.go` | 1858 | ~52 funcs | HA sync connection: gen-guard + fabric + bulk + sweep + delete + config + failover + barrier | (B) ordering-sensitive |
| `pkg/api/metrics_userspace.go` | 1819 | — | Userspace metrics emitter | Companion to descriptors |
| `pkg/dataplane/userspace/maps_sync.go` | 1763 | — | BPF map sync | (D) single resp |
| `pkg/dataplane/compiler.go` | 1733 | — | Compiler dispatch | (D) |
| `pkg/config/compiler_validate_strict_filter.go` | 1660 | — | Single-domain filter | (D) already per-domain split |
| `pkg/config/compiler_uniformgates.go` | 1659 | — | Uniformgates orchestrator | (D) #4406 split result |
| `pkg/grpcapi/server_diag.go` | 1602 | — | gRPC diag | Under |
| `pkg/cmdtree/tree.go` | 1548 | — | Command tree | (D) |
| `pkg/dhcprelay/relay.go` | 1545 | — | DHCP relay | Focused |
| `pkg/config/types_system.go` | 1544 | 64 type defs | System+SNMP+Login+DHCP+Services+Firewall types | (D) defer, touches 20+ consumers |

Total non-test Go in `pkg/`: ~250k LOC. Top 5 files: 3330+2979+2529+2417+2329 = 13.6k LOC in 5 files.

---

## Rankings — the monolith checklist (size × resp-count × hot-path proximity)

Ranked by (size × responsibility count × hot-path factor), hot = 3×, warm = 2×, cold = 1×:

| Rank | File | Size | Resp | Hot | Score | Notes |
|------|------|------|------|-----|-------|-------|
| 1 | poll_descriptor/mod.rs poll_binding_process_descriptor | 4724 fn | 15+ | HOT 3× | 4724×15×3=212580 | #1 monolith, #4404, per-packet |
| 2 | tx/dispatch/mod.rs enqueue_pending_forwards | 1048 fn | 8+ | HOT 3× | 1048×8×3=25152 | #4408, TX drain |
| 3 | cos/queue_service/mod.rs waterfill | 432 fn | 7 | WARM 2× | 432×7×2=6048 | #4408, TX sched |
| 4 | session/mod.rs SessionTable | 2054 file | 7 | HOT 3× | 2054×7×3=43134 | #4421, every packet lookup |
| 5 | SessionEntry | 284 but 16 fields | 2 | HOT 3× | Arc clone per packet | RPC clone cost |
| 6 | afxdp/forwarding/mod.rs | 2822 | 5 | HOT 3× | ForwardingState 65 fields | FIB lookup hot |
| 7 | ForwardingState (types/forwarding.rs) | 1054 struct | 65 fields | HOT 3× | Hot-cold field fusion | dcache waste |
| 8 | PortAllocatorShared | 800 struct | 5 | HOT 3× | Hot bitmap + cold stats/GC | Cache-line |
| 9 | nat/source.rs match_source_nat_result | 336 fn | 6 | HOT 3× | L4 classify + pool alloc | Per new-flow |
| 10 | screen/mod.rs check_packet | 374 fn | 7 | HOT 3× | 5 SYN-flood phases + flood+stateless | IDS |
| 11 | frame/inspect.rs 5× EH walker dup | 1813 | 5 | HOT 3× | Parse every packet | Code dup |
| 12 | frame/mod.rs kitchen sink | 1710 | 6 | HOT 3× | VLAN+NAT+port+prep+NAT64+verify | TX path |
| 13 | compiler_validate_warn.go | 3330 | ~12 | COLD 1× | 35 funcs, ~12 resp | Mechanical |
| 14 | protocol.go wire-format | 2979 | 12 | COLD 1× | 72 types | Mechanical |
| 15 | sync_conn.go | 1858 | 8 | COLD 1× | Gen-guard ordering | Sensitive |
| 16 | neighbor.rs | 2036 | 4 | COLD 1× | ARP/ND + netlink + monitor | GC |
| 17 | wg/engine.rs | 1805 | 1 | HOT 3× | WG encap/decap | Cohesive (D) |
| 18 | types/cos.rs CoSInterfaceRuntime | 1786 | 5 | WARM 2× | 28 fields, 3 unused WIRE-ONLY | Field split |
| 19 | compiler_nat.go | 2529 | 3 | COLD 1× | 5 NAT types + validators + helpers | Mechanical |
| 20 | tunnel.go | 1877 | 5 | COLD 1× | Tunnel + keepalive + WG MTU + VRF | Mechanical |

---

## File-by-file inspection log


### Files inspected this batch


**a1a:** 37961 chars reviewed

**a1b:** 46428 chars reviewed

**a1c:** 23099 chars reviewed

**a1d:** 21404 chars reviewed

**a1e:** 32607 chars reviewed

**a1f:** 38079 chars reviewed

**a1g:** 32142 chars reviewed

**a2:** 27175 chars reviewed

**a3:** 31847 chars reviewed

**a4:** 54711 chars reviewed

**draft:** 13022 chars reviewed

---


## Findings from a1a (/ps-review-039-a1a.md)

## File-size / shape inventory — coverage proof

| File | LOC (wc -l) | Production LOC (excl tests) | Largest production fn | One-line responsibility |
|------|-------------|-----------------------------|----------------------|------------------------|
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 6042 | ~4900 (incl helpers) | `poll_binding_process_descriptor` 4724 LOC (line 603..5326) | Per-packet orchestrator: stages 1-11 dispatch → flow-cache → session-hit → session-miss → flowless → host-local → NAT pre-routing → filter → route → screen → policy → SNAT → install → telemetry → HA → debug-log |
| `userspace-dp/src/afxdp/poll_stages.rs` | 3527 | ~971 | `stage_screen_check` 304 LOC (line 390) | Stages 5-11 pure code-motion extraction: link-layer ARP/NDP, GRE decap, flow parse + neighbor learn, fabric ingress, screen (incl flowless), SYN-cookie ACK, IPsec passthrough |
| `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` | 2174 | ~414 | `enqueue_reject_reply` 199 LOC (line 215) | Cold reject-reply synthesis: TCP RST / ICMP unreach build, TX-budget gate, per-zone rate-limit, VLAN logical-ifindex fix, output-filter classify, source-routed counters (Policy vs Filter) |
| `userspace-dp/src/afxdp/poll_descriptor/filter.rs` | 1201 | ~640 | `evaluate_non_pbr_input_filter` 70 LOC | Cold filter extraction: input filter eval (non-PBR), DSCP-sensitive re-eval on hit, lo0 host-bound filter, host-inbound-gated-lo0, filter-terminal (reply-before-log ordering), cached log replay |
| `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` | 521 | 457 | `stage_flow_cache_hit` 457 LOC | Flow-cache fast path (hottest, 90%+ packets) — neighbor check, TTL, NAT rewrite, mirror, forward |
| `userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs` | 509 | ~300 | — | SYN-cookie reply budget |
| `userspace-dp/src/afxdp/poll_descriptor/rx_telemetry.rs` | 220 | ~180 | — | RX descriptor telemetry batching |
| `userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs` | 125 | ~80 | — | Source NAT failure recording |
| `userspace-dp/src/afxdp/poll_descriptor/debug_log_throttle.rs` | 99 | 99 | — | debug-log throttle predicates (pure, #4404 inc 1) |

Total batch: 12944 LOC (all files above). Production-only for key 4 files: ~6950 LOC.

---

## Findings

### Finding 1 — `poll_binding_process_descriptor` god-function (4724 LOC, 15+ resp) — already covered by #4404, new decomposition angles

**Severity:** Critical (maintainability, build-cost, review-cost — every forwarding change recompiles 6042-line module, 39 recycle sites must stay single-free, Junos order duplicated 3×)

**Confidence:** High

**Refactor class:** (B) REQUIRES GUARDRAILS — per-packet hot path, single-recycle invariant, Junos order, VLAN logical-ifindex, no alloc, inlining preserved. Do NOT attempt mechanical split without `PacketCtx` and disassembly baseline.

**Dedup note:** #4404 filed poll_descriptor/mod.rs god-function (reported 1368 LOC at its time, 5759 total). This finding does NOT re-file that count — it provides NEW measurement (4724 LOC at f7014695, 6042 total — the 1368→4724 growth is 15+ responsibilities accreting since #4404), and NEW decomposition seams (#4404 lacked: 11 mutable-locals coupling, 39 single-recycle push sites, 3× Junos-order duplication, hot/cold `cfg(feature="debug-log")` eprintln interleaving, flowless vs session-miss local-delivery divergence). If #4404 already tracks the god-function, this finding should merge as its hot-path-preservation annex.

**Evidence:**

File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:603-5326`, 4724 LOC. Signature (line 603):

```rust
pub(super) fn poll_binding_process_descriptor(
    binding: &mut BindingWorker,
    binding_index: usize,
    area: *const MmapArea,
    available: u32,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    _worker_id: u32,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) {
```

Session-hit vs session-miss split: `let mut decision = if let Some(flow) = flow.as_ref() {` at line 866 branches to `resolve_flow_session_decision` (hit), `} else {` at ~1276 falls to `telemetry.counters.session_misses`. Hit path ~410 LOC (866-1276), miss path ~4050 LOC (1276-5326) — the miss path itself is 85% of the function.

Hot/cold fusion — debug-log eprintln interleaved inside session-miss install site (lines 2004-2062), and `telemetry.dbg.*` increments on hit path:

```rust
// mod.rs:2004-2010 — cfg(feature="debug-log") allocates String + writes to stderr
// INSIDE the session-miss path, between resolution and install:
                        // Debug: log session miss with flow details (throttled)
                        if cfg!(feature = "debug-log") {
                            if session_miss_debug_log_allowed(telemetry.dbg.session_miss) {
                                eprintln!(
                                    "DBG SESS_MISS[{}]: {}:{} -> {}:{} proto={} ...",
```

39 recycle sites (`binding.scratch.scratch_recycle.push` + `StageOutcome::RecycleAndContinue`) — single-recycle invariant must hold on every early `continue`:

```
continue points: 35, recycle pushes: 34, total recycle-related lines: 39
```

11 mutable-locals that cross hit/miss boundary (the #1327 “mutable-locals coupling” blocker):

```
flow_cache_owner_rg_id, flow_cache_policy_counter_idx, flow_cache_policy_counter,
flow_cache_install_failed, pre_routing_dnat_counter, session_ingress_zone,
apply_nat_on_fabric, debug, decision, recycle_now, received
```

NAT pre-routing block (lines 1396-1562, ~166 LOC) fuses DNAT → static-DNAT → NPTv6 → NAT64 tri-state with `pre_routing_dnat_counter` hoisting — distinct responsibility, testable in isolation.

Host-local Junos order (host-inbound → lo0 → junos-host) appears 3×:
- session-hit: 1050-1242 (`host_inbound_gated_lo0_action` + `junos_host_local_policy`)
- session-miss LocalDelivery: 2102-2222 (same pair)
- flowless: 319-409 (`flowless_local_delivery_verdict` — host-inbound → lo0 → junos-host, l4_present=false, flowless silent-drop)

**Proposed decomposition (new angles beyond #4404 generic split):**

Keep #4404's overall phase split, but add these concrete seams:

1. `poll_descriptor/session_hit.rs` — `stage_session_hit` — moves 866-1275. Takes `&mut HitCtx` (groups `session_ingress_zone`, `flow_cache_*`, `apply_nat_on_fabric`). Returns `HitOutcome::{Continue(Decision), Drop(RecycleReason), Recycle}`. Keeps `#[inline]` — same crate, LLVM inlines.

2. `poll_descriptor/session_miss/mod.rs` — orchestrates miss stages; keeps mutable-locals coupling inside one file initially (solves #1327 without `PacketCtx` churn).

3. `poll_descriptor/nat_pre_routing.rs` — `struct NatPreRoutingOutcome { pre_routing_dnat, nptv6_inbound, nat64_match, effective_resolution_target, policy_dst_ip/port, counter }` — pure fn, moves 1396-1606. Already almost pure (reads forwarding tables + flow, returns stack-only outcome). No alloc, returns `Option<Arc<…>>` counter only on DNAT hit (cold clone).

4. `poll_descriptor/host_local.rs` — dedup Junos order: single `fn host_local_delivery_gates(forwarding, flow, meta, from_zone_id, ingress_logical, ingress_zone_override, is_flowless) -> HostLocalVerdict` that encodes `host_inbound_gated_lo0_action → filter_terminal → junos_host_local_policy` in correct order. Flowless variant passes `l4_present=false`, `dst_port=0`, `reject_reply_enqueued=false`. Moves `junos_host_local_policy` (229-289), `flowless_local_delivery_verdict` (319-409), `junos_host_policy_eval` (113-133) into one module so Junos order is unit-testable once.

5. `poll_descriptor/flowless.rs` — `FlowlessLocalVerdict`, `flowless_base_resolution`, `flowless_l3_addrs` — flowless (no-L4) transit + local-delivery. Isolates non-first-fragment path (#3064, #3902) from flow path. Already `flowless_local_delivery_tests` (5743-6042) moves with it.

Seam: cut by **Junos ordering** (host-inbound → lo0 → junos-host) and **NAT phase** (pre-routing DNAT/NPTv6/NAT64 vs post-policy SNAT) — not by LOC bracket. Each stage returns `StageOutcome` or `HostLocalVerdict`, orchestrator handles recycle.

**Hot-path preservation analysis (mandatory):**

- **Single-recycle invariant** — frame freed exactly once even on drop/reject paths. Current code has 34 `scratch_recycle.push(desc.addr)` + 5 `StageOutcome::RecycleAndContinue`. Any split MUST preserve: every early `continue` pushes `desc.addr` exactly once; `owned_packet_frame.take()` move transfers UMEM ownership on forward path (lines 1359-1362) so recycle does NOT fire. Existing tests: `flowless_local_delivery_tests` (pin Junos order), `dispatch_tests.rs` `FORCE_OVERSIZED`/`FORCE_TUPLE_MISMATCH` single-recycle (TX path, same invariant family). Gate: run `cargo test --bin xpf-userspace-dp poll_descriptor::flowless_local_delivery_tests`, `cargo test session::tests::inplace_randomized_sequence_matches_reference` (HA session-sync correctness), and `cargo test tx::dispatch::dispatch_tests` with `FORCE_*` hooks.

- **Junos order** (host-inbound → lo0 → junos-host) for local delivery — must be preserved in host_local.rs. Current session-hit path (1050-1242) and session-miss LocalDelivery (2102-2222) and flowless (319-409) all implement same order with subtle differences (hit re-checks on every packet to tear down tightened host-inbound set; miss installs session; flowless silent-drops with `reject_reply_enqueued=false`). Dedup must NOT collapse hit re-check semantics into miss install semantics. Verify via `flowless_local_delivery_tests` (host_inbound_deny, lo0_reject, junos_host_permit/deny), and by grepping `host_inbound_gated_lo0_action` call sites remain 3 but route through one helper.

- **Table-scoped local delivery** (#3769/#3151 `owned_here`) and **connected-route scoping** (#2388 `entry.table==table`) — live in `forwarding/mod.rs` but called from `flowless_base_resolution` and `lookup_forwarding_resolution_in_table_with_dynamic`. Host-local extraction must NOT move `flowless_base_resolution` without preserving `ingress_interface_local_resolution_on_session_miss → interface_nat_local_resolution → table-aware FIB` ordering (the `or_else` chain). This is already tested by `forwarding/tests.rs` (table-scoped local delivery).

- **No new heap allocation** — `NatPreRoutingOutcome` is stack-only (enums/options of Copy + one `Option<Arc<NatRuleCounter>>` already cloned on DNAT hit — keep clone site identical). `HostLocalVerdict` is Copy. `PacketCtx` grouping must be `&mut` existing locals, no `Box`/`Vec`. Verify with `cargo test` + disassembly diff: `cargo show-asm poll_binding_process_descriptor` before/after should show same `alloc` calls (none on hit path, one `Vec<u8>` only on GRE decap which already allocates). `DEFAULT_V4_TABLE.to_string()` alloc on every packet when no table override is a separate bug (in forwarding, not here) — not introduced by split.

- **No new dynamic dispatch, inlining preserved** — all new `stage_*` fns must be `#[inline]` or `#[inline(always)]` and stay in `crate::afxdp::poll_descriptor::*` (same crate as `poll_binding_process_descriptor`) so LLVM inlines across module boundary. Do NOT move to another crate. `filter_terminal` and `host_inbound_gated_lo0_action` already `#[cold] #[inline(never)]` (cold path) — keep annotation.

- **Verification steps:**
  1. `cargo test --bin xpf-userspace-dp poll_descriptor` — flowless + debug_log_throttle + lo0 gate tests
  2. `cargo test --bin xpf-userspace-dp session` — 191 tests including `inplace_randomized_sequence_matches_reference`
  3. `cargo test -p userspace-dp tx::dispatch` — single-recycle invariant with `FORCE_OVERSIZED=1` / `FORCE_TUPLE_MISMATCH=1`
  4. `make test` (full workspace)
  5. Disassembly diff: `cargo rustc -- --emit=llvm-ir` on `poll_binding_process_descriptor` hot loop — byte-identical aside from cold `eprintln` outline
  6. `perf stat -e instructions,cache-misses` on loopback bench — within 1%, ideally icache misses down from cold outlining

**Tests + gate:**
- Move with code: `flowless_local_delivery_tests` (5743-6042), `debug_log_throttle_tests`, `lo0_gate_tests` (filter.rs), `filter_terminal_tests`, `reject_reply` tests
- Load-bearing: `flowless_local_delivery_tests` (Junos order), `inplace_randomized_sequence_matches_reference` (HA correctness), `FORCE_OVERSIZED`/`FORCE_TUPLE_MISMATCH` (single-recycle)
- `make test`, `make test-failover` (HA), `cargo test cos` (CoS queue service uses forwarding path)

**Why it matters:**
- 4724-LOC function is unreviewable, blocks parallel development, single CGU compile cost (every forwarding change recompiles 6042-line module). 39 recycle sites make single-recycle auditing O(n²). Junos order duplicated 3× with subtle flowless vs flow-backed divergence — past bugs (#3485 host-inbound-before-lo0, #3292 flowless fail-open) came from this duplication.
- `cfg(feature="debug-log")` eprintln with `format!` + `String::write!` + `count_bpf_session_entries` scan lives inside session-miss path — icache pollution on cold path but still in hot CGU, increases compile time and binary size.

**Fix direction (ordered, incremental, small PRs):**
1. Mechanical: move `flowless_local_delivery_verdict` + `FlowlessLocalVerdict` + `flowless_base_resolution` + `flowless_local_delivery_tests` to `poll_descriptor/flowless.rs`. `mod.rs` gets `mod flowless; use flowless::*;`. Add `#[inline]` to verdict fns. Run flowless tests, verify disassembly unchanged. PR #1 (A).
2. Cold outline: move `session_miss_debug_log_allowed` already done (#4404 inc1). Next: move `eprintln!` DBG SESS_MISS dump (2004-2062) + WAN_RETURN_HIT log (968-987) into `#[cold] #[inline(never)]` helpers in `poll_descriptor/telemetry_debug.rs`. Replace inline sites with calls. Verify hot loop no longer contains `eprintln` symbols (`nm -S`). PR #2 (C — performance-positive, icache).
3. NAT pre-routing extraction: `poll_descriptor/nat_pre_routing.rs` with `NatPreRoutingOutcome`, `#[inline] pub(crate) fn nat_pre_routing(...) -> NatPreRoutingOutcome`. Moves 1396-1562. Add unit tests for DNAT, static-DNAT, NPTv6, NAT64 tri-state, MatchUnavailable fail-closed. PR #3 (B).
4. Host-local dedup: `poll_descriptor/host_local.rs` — create `host_local_delivery_gates` that encodes Junos order once, parameterized by `is_flowless: bool` + `is_hit_recheck: bool`. Move `junos_host_local_policy`, `junos_host_policy_eval`, `emit_junos_host_deny`, `flowless_local_delivery_verdict`. Keep `#[inline]` on verdict fns, `#[cold]` on deny emit. Update 3 call sites to call helper. Run `flowless_local_delivery_tests` + `lo0_gate_tests`. PR #4 (B).
5. Session hit/miss split (largest): define `HitCtx`/`MissCtx` grouping 11 mutable locals, create `session_hit.rs` + `session_miss/mod.rs`, orchestrator <150 LOC. Do last, after prior extractions reduce coupling. Verify with full test suite + `test-failover` + disassembly. PR #5 (B).

**Labels:** `refactor`, `hot-path`, `god-function`, `modularity`, `single-recycle`, `junos-order`, `x-hpc`, `B-class`

---

### Finding 2 — `poll_stages.rs` production functions are cohesive, well-sized — DO NOT SPLIT (negative result)

**Severity:** Low (informational — confirms prior #946 Phase 1 extraction is sound, prevents well-intentioned but harmful re-split)

**Confidence:** High

**Refactor class:** (D) DO-NOT-SPLIT — production code is already decomposed into single-responsibility stage functions, all `#[inline]`, no hot/cold fusion beyond intentional screen flowless branching. Tests are the size driver (2556 of 3527 LOC), not production.

**Evidence:**

Production functions (excl `#[cfg(test)]`, lines 1-973):

| Fn | LOC | Responsibility | Hot? | Inline |
|----|-----|----------------|------|--------|
| `stage_link_layer_classify` | 142 | ARP reply/learn + NDP NA/learn + VLAN logical-ifindex, #2370, #2790, #2851, #4475 | YES (every packet, before flow-cache) | `#[inline]` |
| `stage_native_gre_decap` | 13 | GRE decap ownership transfer (`Option<Vec<u8>>`) | YES | `#[inline]` |
| `stage_parse_flow_and_learn` | 23 | `parse_session_flow_from_bytes` + source-side neighbor learn (GRE guard) | YES | `#[inline]` |
| `stage_classify_fabric_ingress` | 17 | Fabric overlay + zone-encoded ingress, mutates `meta.meta_flags` | YES | `#[inline]` |
| `flowless_l3_addrs` | 43 | L3 addr extraction for flowless screen path (#3902) | Warm (flowless only) | private `fn` |
| `stage_screen_check` | 304 | Screen profile zone resolve + `extract_screen_info` + `check_packet_with_zone_id_opts` + flowless branch + alarm-without-drop + SYN-cookie challenge | Warm (screen miss only) | `#[inline]` |
| `stage_screen_syn_cookie_ack_on_session_miss` | 113 | SYN-cookie ACK validation on session-miss | Cold (session-miss only) | `#[inline]` |
| `ipsec_passthrough_decision` | 16 | Synthetic LocalDelivery decision (local_ifindex=0 invariant #3616) | Cold | private `fn` |
| `stage_ipsec_passthrough_check` | 71 | IPsec ESP/AH/IKE passthrough + NEW IKE host-inbound gate (#4323) | Warm | `#[inline]` |

Largest production function: `stage_screen_check` 304 LOC — only one >200 LOC. It fuses flowless + flow path because screen's flowless branch must share zone resolution and `extract_screen_info` error handling (#2146 fail-closed) with flow path. Splitting would duplicate zone-resolve (logical-ifindex → zone_id → zone_name) and `l3_off` priority-tag logic (#2145) or introduce a shared helper that still needs 4 args.

Responsibilities are cleanly separated by stage:
- Stages 5-9: link → GRE → flow parse → fabric → screen — hot, must stay `#[inline]`
- Stages 10-11: screen SYN-cookie ACK + IPsec — cold/warm, but still `#[inline]` because session-miss path is cold relative to flow-cache hit (90%+ packets never reach here)

Test module: 2556 LOC (lines 974-3527) — 8 test groups (`session_miss_ack_stage_invokes_syn_cookie_runtime_validation` 187 LOC, `priority_tagged_vlan0_screen_stage_parses_l3_at_offset_18` 184 LOC, `stage_ipsec_passthrough_gates_new_ike_4323` 170 LOC, etc. plus VLAN/ARP/NDP/Owned-IP tests). Tests are large because they pin subtle invariants (VLAN logical-ifindex, priority-tagged VID-0, ARP own-IP, NDP Override, NAT-excluded WAN IP) — each test is a fail-on-revert guard for a past bug.

**Proposed decomposition:** NONE for production. Optionally split test module by concern:
- `poll_stages/tests/screen_vlan_2145.rs` — VLAN priority-tag tests
- `poll_stages/tests/neighbor_2370.rs` — ARP/NDP VLAN logical-ifindex learn tests
- `poll_stages/tests/anti_poison_2790_2851.rs` — unicast-only + own-IP gates
- `poll_stages/tests/ndp_override_4475.rs` — NDP Override honoring
- `poll_stages/tests/ipsec_3616_4323.rs` — IPsec passthrough + IKE gate

But this is low priority — test size does not affect production compile time or hot-path icache, and splitting tests risks losing the “one file, one stage” discoverability. Keep as is unless test file exceeds 4000 LOC.

**Hot-path preservation analysis:**

- **Inlining**: All stage fns `#[inline]` and in `crate::afxdp::poll_stages` (same crate as `poll_binding_process_descriptor`) — LLVM inlines across module boundary. Verified: `stage_link_layer_classify` is called in `poll_binding_process_descriptor` hot loop (line 646-651) via `if let StageOutcome::RecycleAndContinue = stage_link_layer_classify(...)` — this must remain fall-through branch-predictable. Moving stages to another crate would break inlining and add `callq` per packet. Keep in same crate.

- **No new heap allocation**: Stages take `&[u8]` packet_frame, `UserspaceDpMeta` (Copy), `&WorkerContext` — no `Vec`, `String`, `Box` on hot path. `stage_link_layer_classify`'s `learn_ifindex` closure is `||` returning `i32` — no alloc, `resolve_ingress_logical_ifindex` is `FxHashMap::get` (no alloc). `stage_screen_check` flowless path calls `flowless_l3_addrs` which returns `(IpAddr, IpAddr, bool)` — stack-only.

- **Branch/icache**: Splitting cold debug logging and event emission into `#[cold] #[inline(never)]` was already done for `emit_screen_drop_event`, `emit_screen_alarm_event` (they are `#[cold]` in `screen/`). Hot stages (link-layer, GRE, flow parse, fabric) have no cold code interleaved — good, keep.

- **How to verify do-not-split:** `cargo test --bin xpf-userspace-dp poll_stages` — 15+ tests; `cargo test --test '*'` full suite; `cargo asm` on `poll_binding_process_descriptor` — hot loop should show `stage_link_layer_classify` inlined (no `callq`), not outlined.

**Tests + gate:**
- Existing: `poll_stages::tests` — 15+ tests covering VLAN logical-ifindex, ARP/NDP learn, own-IP anti-poison, NDP Override, IPsec passthrough, priority-tagged VID-0, scan/sweep, screen parse errors.
- Behavioral gate: `cargo test --bin xpf-userspace-dp poll_stages`, `make test`, `test-failover` (VLAN, HA), `cargo test screen` (screen profile updates)

**Why it matters (negative result):**
- #946 Phase 1 deliberately extracted stages 5-11 into `poll_stages.rs` and kept them `#[inline]` so refactor is pure code-motion at IR level. Re-splitting `stage_screen_check` (304 LOC) by flowless vs flow would duplicate zone-resolve logic that already caused #2145 (priority-tagged VID-0 mis-parse) and #3022 (VLAN logical-ifindex) bugs. Keeping them together ensures fix to `l3_off` or `logical_ifindex` applies to both flowless and flow paths atomically.

**Fix direction:** No production split. Optionally split tests when file exceeds 4000 LOC. Keep `#[inline]` on all stage fns, do NOT add `#[cold]` to `stage_link_layer_classify` or `stage_parse_flow_and_learn` (hottest stages, every packet).

**Labels:** `do-not-split`, `hot-path`, `poll-stages`, `modularity`, `D-class`, `x-hpc`

**Dedup note:** Not previously flagged as monolith. #946 Phase 1 was the intentional extraction that created this file; this finding confirms the extraction is sound and warns against undoing it. Not a duplicate.

---

### Finding 3 — `reject_reply.rs` (2174 LOC) and `filter.rs` (1201 LOC) are correctly extracted cold-path modules — DO NOT FURTHER SPLIT (negative result with coupling proof)

**Severity:** Low (informational — confirms prior extractions #1697, #2089 are sound, prevents well-intentioned re-merge or over-split)

**Confidence:** High

**Refactor class:** (D) DO-NOT-SPLIT — both modules are cold/exception path, correctly isolated from hot loop, coupling is via `super::worker`, `super::cookie_reply`, `crate::afxdp::forwarding::*`, `crate::filter::*` — NOT via `poll_descriptor/mod.rs` mutable locals. Further split would fragment the reject-reply 5-stage pipeline (feasibility → budget → rate-limit → output-filter → enqueue) and the filter 3-stage ordering (host-inbound → lo0 → junos-host).

**Evidence:**

**reject_reply.rs** — 2174 LOC total, production 414 LOC (5 fns):

| Fn | LOC | Cold? | Inline | Purpose |
|----|-----|-------|--------|---------|
| `enqueue_policy_reject_reply` | 20 | `#[cold] #[inline(never)]` | no | Policy `then reject` entry |
| `enqueue_filter_reject_reply` | 20 | `#[cold] #[inline(never)]` | no | Filter `then reject` entry |
| `enqueue_deny_reply` | 35 | `#[cold] #[inline(never)]` | no | Unified deny (Reject vs zone tcp-rst) |
| `deny_reply_and_emit` | 44 | `#[cold] #[inline(never)]` | no | Reply-before-emit truthful DENY/REJECT (#3615) |
| `enqueue_reject_reply` | 199 | `#[cold] #[inline(never)]` | no | 5-stage pipeline: feasibility → budget → per-zone rate-limit → output-filter classify (VLAN logical) → enqueue |

Coupling: `use super::cookie_reply::syn_cookie_reply_budget_available; use super::worker::WorkerTxPipeline; use super::*;` — `super` here is `crate::afxdp::poll_descriptor` (the module, not `mod.rs` file), but `super::*` brings in `crate::afxdp::*` via `poll_descriptor/mod.rs`'s `use super::*;` chain. No dependency on `poll_binding_process_descriptor` mutable locals (`binding`, `sessions`, `telemetry`, `area`, `desc`). Takes `&mut WorkerTxPipeline`, `&ForwardingState`, `UserspaceDpMeta`, `&SessionFlow`, `&mut BatchCounters` — explicit, testable.

Standalone testability: `reject_reply.rs` has 14 tests (1760 LOC) driving `enqueue_policy_reject_reply` / `enqueue_filter_reject_reply` directly with `tx_pipeline(max_pending_tx, free_frames)` + `ForwardingState::default()` fixtures — no need for full worker setup. Tests pin critical invariants: budget-exhausted fail-closed, rate-limited fail-closed, output-filter drop, VLAN logical-ifindex classify (#3035), VLAN logical-ifindex source (#3976), unreplyable frame does not drain bucket (#3656 H11) nor count budget drop (H12), per-zone isolation (#3618).

**filter.rs** — 1201 LOC total, production 640 LOC (10 fns + 3 structs):

| Fn/Struct | LOC | Cold? | Purpose |
|-----------|-----|-------|---------|
| `PendingFilterLog` | 9 | — | Deferred filter-log struct (#3615) |
| `emit_pending_filter_log` | 23 | `#[inline]` | Emit deferred log with actual reply outcome |
| `filter_terminal` | 31 | `#[cold] #[inline(never)]` | Reply-before-log combining helper (testable seam) |
| `evaluate_non_pbr_input_filter` | 70 | `#[cold] #[inline(never)]` | Non-PBR input filter eval with `NonRoutingCountPolicy` (#2620 double-count avoidance) |
| `host_inbound_gated_lo0_action` | 46 | `#[cold] #[inline(never)]` | Host-inbound gate FIRST, then lo0 eval (#3485) |
| `apply_lo0_filter_action` | 44 | `#[cold] #[inline(never)]` | lo0 filter eval + deferred log return |

Coupling: `use super::*; use super::reject_reply::enqueue_filter_reject_reply; use super::worker::WorkerTxPipeline;` — takes `&ForwardingState`, `TermMatchExtra`, `&SessionFlow`, `UserspaceDpMeta`, `Option<u16>` — explicit. No `binding`, `sessions`, `area`, `desc`. Hot-path caller `evaluate_dscp_sensitive_input_filter_on_session_hit` stays `#[inline]` so cheap `interface_input_filter_has_dscp_match` guard folds into hot session-hit path with no call when no DSCP filter configured — intentional inline policy per `#1697` header comment.

Inline policy is per-function (NOT blanket `#[inline(never)]`) — the file header (lines 1-40) documents why:

```rust
// Inline policy is per-function (NOT blanket #[inline(never)]) so the
// cheap common-case guards stay folded into the hot/warm caller while
// only the rare/heavy bodies are forced out of line:
//   - filter_log_ingress_zone_id / filter_log_egress_zone_id: trivial
//     leaf helpers, #[inline] — called from both inline and cold callers
//   - emit_cached_input_filter_log / emit_cached_output_filter_log are
//     called UNCONDITIONALLY from stage_flow_cache_hit (#[inline(always)],
//     the established-flow fast path). They stay #[inline] so the
//     `None` filter-log guard folds into the fast path: in the common
//     no-filter-logging case the hot path is a load + branch with NO
//     call and NO 96-byte UserspaceDpMeta copy.
```

This is exemplary — the file already implements the hot-path preservation discipline that Finding 1 calls for in `mod.rs`.

**Proposed decomposition:** NONE. Both files are already the result of prior refactoring (#1697 filter cold-path extraction, #2089 reject-reply synthesis). Further split would fragment:

- `reject_reply.rs`'s 5-stage pipeline (`build → budget → rate-limit → output-filter → enqueue`) is linear and must stay in one function so feasibility-before-consume ordering (#3656) is obvious. Splitting budget and rate-limit into separate fns would hide H11/H12 invariants (unreplyable frame must NOT consume token nor count budget drop).

- `filter.rs`'s `host_inbound_gated_lo0_action` encodes Junos order (host-inbound FIRST → lo0) as `if !host_inbound_admits { return None; } Some(apply_lo0_filter_action(...))` — splitting host-inbound and lo0 into separate modules would lose the ordering guarantee that #3485 fixed.

The only optional move: `filter.rs`'s `lo0_gate_tests` and `filter_terminal_tests` (560 LOC) could move to `filter/lo0_gate_tests.rs` when file exceeds 1500 LOC, but not urgent — tests are colocated with the ordering they pin.

**Hot-path preservation analysis:**

- **Cold placement**: Both modules' public entry points are `#[cold] #[inline(never)]` — they live in `.text.unlikely`, away from hot loop's cache lines. Hot callers (`stage_flow_cache_hit` calling `emit_cached_input_filter_log`, session-hit calling `evaluate_dscp_sensitive_input_filter_on_session_hit`) keep their cheap guards `#[inline]` so common no-match case is load+branch with NO call. This is textbook hot/cold separation — do NOT change inline attributes.

- **No new alloc on hot path**: `evaluate_dscp_sensitive_input_filter_on_session_hit` does two `FxHashMap::contains_key` lookups (no alloc) then returns `None` in common case. `filter_terminal` allocates `Vec<u8>` for reject reply only on cold reject path — acceptable, reject is rare (policy deny / filter reject). `enqueue_reject_reply` builds reply `Vec<u8>` via `build_reject_rst_frame` / `build_reject_icmp_unreachable` — these are cold, rate-limited, budget-gated.

- **No dynamic dispatch**: All calls concrete, no trait objects.

- **Single-recycle unaffected**: Both modules are exception/side paths that return `bool` (sent?) or `Option<PendingFilterLog>` — they do NOT touch `binding.scratch.scratch_recycle`. Caller (`poll_binding_process_descriptor`) handles recycle after checking return. Verified by `filter_terminal_tests` and `reject_reply` tests — they drive `tx_pipeline` directly, no recycle needed.

- **VLAN logical-ifindex correctness**: `enqueue_reject_reply` resolves `logical_ingress_ifindex` via `resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, meta.ingress_vlan_id).unwrap_or(ingress_ifindex)` (line 267-269) so ICMP reject reply sources from sub-interface's own primary address and tags reply with sub-if VLAN ID. `host_inbound_gated_lo0_action` takes `logical_ingress_ifindex` as explicit arg (not `meta.ingress_ifindex`) so VLAN sub-interface's per-interface host-inbound override governs. Both are tested by `reject_reply_non_tcp_sources_from_logical_vlan_ifindex_3976` and `host_inbound_override_keyed_by_logical_vlan_ifindex`.

- **How to verify do-not-split**: `cargo test --bin xpf-userspace-dp poll_descriptor::filter`, `cargo test --bin xpf-userspace-dp poll_descriptor::reject_reply` — 14 + 7 tests; `cargo test --bin xpf-userspace-dp poll_stages` — full stage tests; `make test` full suite; check disassembly of `stage_flow_cache_hit` — `emit_cached_input_filter_log`'s `None` guard folded (no call), rare tail calls `#[cold]` callee.

**Tests + gate:**
- `filter.rs`: `lo0_gate_tests` (3 tests pinning #3485 + #3609), `filter_terminal_tests` (3 tests pinning #3615 truthful DENY/REJECT)
- `reject_reply.rs`: 14 tests pinning budget, rate-limit, output-filter, VLAN logical-ifindex (#3035, #3976), unreplyable frame H11/H12 (#3656), per-zone isolation (#3618), zone tcp-rst (#3071)
- Behavioral gate: `make test`, `test-failover` (HA with reject reply), `cargo test --bin xpf-userspace-dp filter`, `cargo test --bin xpf-userspace-dp reject`

**Why it matters (negative result):**
- These modules are the POSITIVE EXAMPLE of how `poll_descriptor/mod.rs`'s god-function should be decomposed. They prove the pattern: extract cold exception path to `#[cold] #[inline(never)]` helpers in sibling modules, keep cheap guards `#[inline]`, pass explicit args (no capture of `binding`/`sessions`/`area`/`desc` mutable locals), provide standalone test seam. Any proposal to re-merge them back into `mod.rs` or to further split their internal 5-stage pipeline would regress clarity and lose the fail-on-revert coverage their tests provide.

**Fix direction:** No split. Keep current module boundaries. When `reject_reply.rs` exceeds 2500 LOC (tests growing), move tests to `reject_reply/tests.rs` (mechanical, keep fixture helpers). When `filter.rs` exceeds 1500 LOC, move `lo0_gate_tests` + `filter_terminal_tests` to `filter/tests.rs`. Both are A-class mechanical moves, no logic change.

**Labels:** `do-not-split`, `cold-path`, `modularity`, `exemplary`, `D-class`

**Dedup note:** Not previously flagged as monolith — prior reviews (#1697, #2089) created these modules intentionally. This finding confirms they are correctly scoped and warns against over-splitting. Not a duplicate.

---

## Summary — issue split sequenced for safe landing

**Phase 1 already done (do not re-do):**
- `debug_log_throttle.rs` extraction (#4404 inc1) — pure, dependency-free, done
- `flow_cache_hit.rs` extraction (#1327) — hottest path, 457 LOC, do not further split
- `filter.rs` extraction (#1697) — cold input-filter + lo0 + host-inbound-gated-lo0, done, D-class keep
- `reject_reply.rs` extraction (#2089) — cold reject-reply synthesis, 5-stage pipeline, done, D-class keep
- `poll_stages.rs` extraction (#946 Phase 1) — stages 5-11, done, D-class keep

**Phase 2 — mechanical moves and cold outlining (A/C) — no hot-path risk:**
1. **Finding 1.1** Flowless mechanical move (A): `poll_descriptor/flowless.rs` — `FlowlessLocalVerdict`, `flowless_local_delivery_verdict`, `flowless_base_resolution`, `flowless_local_delivery_tests`. `mod.rs` gets `mod flowless; use flowless::*;`. Add `#[inline]`. Run `cargo test flowless`, verify disassembly unchanged. PR #1.
2. **Finding 1.2** Cold telemetry outlining (C — performance-positive): `poll_descriptor/telemetry_debug.rs` — move `eprintln!` DBG SESS_MISS dump (2004-2062) + WAN_RETURN_HIT log (968-987) into `#[cold] #[inline(never)]` helpers. Replace inline with calls. Verify disassembly — hot loop no longer contains `eprintln` symbols. PR #2.

**Phase 3 — isolated extractions (B) — cold or session-miss only, require guardrails:**
3. **Finding 1.3** NAT pre-routing extraction (B): `poll_descriptor/nat_pre_routing.rs` — `NatPreRoutingOutcome`, pure fn, 1396-1562, tri-state NAT64 (#2291), fail-closed on MatchUnavailable. Unit test each translation type. Verify no alloc. PR #3.
4. **Finding 1.4** Host-local dedup (B): `poll_descriptor/host_local.rs` — single Junos-order helper, moves `junos_host_local_policy`, `junos_host_policy_eval`, `flowless_local_delivery_verdict`, `FlowlessLocalVerdict`. Preserves Junos order (host-inbound → lo0 → junos-host) for 3 call sites (hit/miss/flowless). Run `flowless_local_delivery_tests` + `lo0_gate_tests`. PR #4.
5. **Finding 1.5** Session install transaction isolation (B): `poll_descriptor/session_install.rs` — `install_session_and_publish()` — session table install, BPF map publish, dnat_table publish, flow-cache population. Moves ~180 LOC, isolates transaction boundary, dedup fabric-return fast path vs normal miss path. Returns `Result<FlowCacheEntry, InstallError>`. Verify with `make test-failover` (HA) + `flowless_local_delivery_tests`. PR #5.

**Phase 4 — major split (B) — requires PacketCtx, do last:**
6. **Finding 1.6** Session hit/miss split (B): `poll_descriptor/session_hit.rs` + `poll_descriptor/session_miss/mod.rs` — define `HitCtx`/`MissCtx` grouping 11 mutable locals. Orchestrator `poll_binding_process_descriptor` becomes thin dispatch (<150 LOC): RX telemetry → stages 5-11 → flow-cache → `stage_session_hit` / `stage_session_miss`. Largest churn, do after prior extractions reduce coupling. Verify with full `make test`, `make test-failover`, `cargo test cos`, `perf stat`, disassembly diff. PR #6 — triple-review required (single-recycle + CoS guarantee-guard + VLAN logical-ifindex).

**Do NOT do (D-class):**
- **Finding 2** `poll_stages.rs` production further split — would duplicate zone-resolve / `l3_off` logic that already caused #2145/#3022 bugs
- **Finding 3** `reject_reply.rs` / `filter.rs` further split — would fragment 5-stage reject pipeline (H11/H12 ordering) and host-inbound→lo0 Junos order (#3485)
- `stage_flow_cache_hit` (457 LOC) further split — hottest path, 90%+ packets, already extracted in #1327, further split hurts icache
- `stage_screen_check` (304 LOC) flowless/flow split — would duplicate `logical_ifindex → zone_id` + `l3_off` priority-tag logic

**Verification for each PR:**
- `cargo test --bin xpf-userspace-dp poll_descriptor` — flowless, debug_log_throttle, lo0 gate, filter_terminal, reject_reply tests
- `cargo test --bin xpf-userspace-dp poll_stages` — 15+ stage tests (VLAN, ARP/NDP, anti-poison, NDP Override, IPsec)
- `cargo test --bin xpf-userspace-dp session` — 191 tests including `inplace_randomized_sequence_matches_reference`
- `cargo test -p userspace-dp tx::dispatch` — single-recycle with `FORCE_OVERSIZED`/`FORCE_TUPLE_MISMATCH`
- `make test` — full workspace, `make test-failover` — HA integration
- Disassembly diff: `cargo show-asm poll_binding_process_descriptor` — hot loop byte-identical (allow cold reordering), no new `callq` in hot path
- `perf stat -e instructions,cache-misses,branch-misses` — within 1% of baseline, ideally icache misses down from cold outlining
- `cargo bloat` — no size regression in hot symbols

---

*End of ps-review-039-a1a — 2026-07-08*


---

## Findings from a1b (/ps-review-039-a1b.md)

## Finding 1: tx/dispatch/mod.rs enqueue_pending_forwards — god-function remnant, Phase 8 + direct-TX + segmentation + fabric still fused

- **Severity:** High (modularity) / Low (correctness — function is correct, but reviewability is degraded)
- **Confidence:** High
- **Refactor class:** (B) — Small, safe refactor (new modules, pure code-motion, no behavioral change)
- **Dedup note:** #4408 already filed the 1,131-LOC god-function finding. This finding provides NEW decomposition detail + hot-path preservation analysis that #4408 lacked. #4408's fix direction was "outline cold segmentation + mirror paths from hot build path." This finding identifies the STILL-REMAINING Phase 8 body, the inline direct-TX fallback enum+match, the dual TCP-segmentation builder paths (prepared vs. local-copy), the triple fabric-redirect special-case repetition, and the three PendingForwardFrame variant dispatch arms — all still fused in one function body.

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/dispatch/mod.rs`
**Function:** `enqueue_pending_forwards` — lines 270..1318 — 1048 LOC function body (1486 LOC file)

Signature (10 params, plus 5 captured via `&mut`):

```rust
pub(in crate::afxdp) fn enqueue_pending_forwards(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    post_recycles: &mut Vec<(u32, u64)>,
    now_ns: u64,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    ingress_live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    counters: &mut BatchCounters,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) {
```

The #1443 split's own comment documents the deferred work:

```rust
// The orchestrator (`enqueue_pending_forwards`) and Phase 8
// (try_inplace_rewrite_or_build) intentionally stay in `mod.rs` for
// this PR — Phase 8 body extraction is deferred to a follow-up so
// reviewers can compare the in-tree control flow against current
// master without a body-shape diff. See plan.md §"Out of scope".
```

Phase 8 inline span (~650 LOC, lines ~640..1295) fuses:

1. TCP segmentation admission gate (`forwarded_tcp_may_need_segmentation`)
2. Prepared-segmentation builder (`segment_forwarded_tcp_frames_into_prepared`) + local-copy segmentation fallback (`segment_forwarded_tcp_frames_from_frame`) — dual builder paths with duplicated tuple-mismatch diagnostic + per-segment enqueue + batch-drain trigger
3. NAT64 predicate + `compute_forwarded_egress_ptb` PTB derivation
4. `request_runs_under_shared_exact_policy` / `cos_owner_live_for_request` CoS routing gate
5. In-place rewrite attempt (`rewrite_forwarded_frame_in_place` → prepared TX) — **Phase 8 proper**, the deferred extraction
6. `DirectTxFallbackReason` enum (inline, 5 variants) + direct-TX attempt (free-frame pop → prefetch → `build_forwarded_frame_into_from_frame` → tuple-mismatch check → prepared enqueue → fallback reason attribution)
7. Copy-path fallback (NAT64 + plain) with oversized-frame handling
8. Fabric-redirect no-binding/inline-prebuilt/build-failure triple special-casing (repeated 3 times: prebuilt dispatch ~line 326, live-frame dispatch ~line 452, build-failure finalizer ~line 1284)
9. Three `PendingForwardFrame` variant dispatch arms (Prebuilt at line 326, Owned at 410, Live at 412) with divergent recycling/CoS/mirror logic

Fabric-redirect pattern repeated 3x (example at line 452):

```rust
if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
    ingress_live.fabric_redirect_unsendable_drops.fetch_add(1, Ordering::Relaxed);
    record_exception(recent_exceptions, ingress_ident, "fabric_redirect_no_binding", ...);
    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
    continue;
}
```

Prebuilt vs. live/owned dispatch:

```rust
if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
    // ~80 LOC: extract frame_len, build TxRequest, enqueue, account, recycle, continue
}
// ...
let source_frame = match &request.frame {
    PendingForwardFrame::Owned(frame) => frame.as_slice(),
    PendingForwardFrame::Live => { /* UMEM slice read */ }
    PendingForwardFrame::Prebuilt(_) => unreachable!(),
};
```

### Proposed decomposition

```
tx/dispatch/mod.rs          — orchestrator loop only (~200 LOC): iter, target lookup, variant dispatch, finalizer
tx/dispatch/forward_build.rs — Phase 8: in-place rewrite → direct-TX → copy-path cascade
                              (try_inplace_or_build, DirectTxOutcome, DirectTxFallbackReason)
tx/dispatch/tcp_seg.rs       — TCP segmentation gate + dual builder dispatch
                              (try_tcp_segmentation, TcpSegOutcome)
tx/dispatch/fabric.rs        — Fabric-redirect drop helper (single site)
                              (handle_fabric_redirect_unsendable)
tx/dispatch/frame_kind.rs    — PendingForwardFrame variant helpers (optional, or inline — already small)
```

Seam: each helper takes `&mut BindingWorker` target + `&PendingForwardRequest`-equivalent + returns a small enum (`BuildOutcome::InPlace | Direct | Copy | Failed`). The orchestrator's `recycle_ingress_frame` + `apply_shared_recycles` + PTB-finalizer stay in `mod.rs` — they are loop-level concerns, not per-frame-build concerns.

Alternative seam for Phase 8: move the entire in-place→direct→copy cascade into `forward_build.rs` as:

```rust
pub(in crate::afxdp::tx::dispatch) fn build_and_enqueue_forward(
    target_binding: &mut BindingWorker,
    source_frame: &[u8],
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    // ... small param bag
) -> BuildOutcome { ... }
```

Returning `BuildOutcome { kind: BuildKind, bytes: u64, max_frame: u32 }`.

### Hot-path preservation analysis

This IS the TX hot path — per-packet at line rate on every forwarded frame.

- **No new heap allocation:** Proposed helpers take `&mut` + `&[u8]` + small `Copy` enums. No `Box`, `Vec`, `String`, or `clone`. The `DirectTxFallbackReason` enum is already stack-allocated; moving it to a submodule is code motion only. `BuildOutcome` is 2×`u64`+`u32` — fits in registers.
- **No dynamic dispatch:** All helpers are `#[inline]` fns in the same crate. No `Box<dyn Trait>`. Module boundary is free for inlining in the same crate (verified: `rustc` inlines across `mod` boundaries within a crate when `#[inline]` + single caller).
- **Zero-copy / UMEM frame ownership preserved:** The in-place rewrite path produces a `PreparedTxRecycle::FillOnSlot` that recycles the ingress frame to the fill ring. This single-recycle invariant must be preserved — the new module must NOT introduce a second recycle on any path. The proposed `forward_build.rs` returns ownership of the outcome; the orchestrator retains sole recycle responsibility for the ingress frame (same as today). Pin: existing `dispatch_tests.rs` already asserts single-recycle on every path (including the `FORCE_OVERSIZED` / `FORCE_TUPLE_MISMATCH` fault-injection tests). Those tests continue to pass without modification because the split is pure code motion.
- **Inlining preserved:** `build_and_enqueue_forward` is called from one site in the loop — `#[inline]` + `pub(in crate::afxdp::tx::dispatch)` ensures LLVM inlines it. The cold paths (`handle_forward_build_failure`, `maybe_reinject_slow_path*`) are already `#[cold] #[inline(never)]` — they stay out of the hot i-cache regardless of module location.
- **Single-recycle invariant:** The existing invariant is: every `source_offset` (ingress UMEM frame) is recycled exactly once — either via `recycle_ingress_frame` (→ `pending_fill_frames`) or via `PreparedTxRecycle::FillOnSlot` (→ cross-binding fill). Moving code must NOT add or remove a recycle call. Verification: run the existing `dispatch_tests.rs` fault-injection tests (they already enumerate oversized, tuple-mismatch, enqueue-err, fabric-no-binding paths and assert `free_tx_frames.len()` / `pending_fill_frames.len()` balance).

### Tests + gate

- Existing: `dispatch_tests.rs` (1564 LOC) — covers every recycle path, NAT64 frag drop, fabric unsendable, PTB derivation, tuple-mismatch, oversized. Must pass unchanged.
- New: no new tests needed for pure code motion. If adding `forward_build.rs`, add a unit test for `DirectTxFallbackReason → counter attribution` mapping (currently inline match at line ~1062, easy to regress when adding a new variant).
- Gate: `make test` (Go + Rust), `make test-deploy` (standalone ping), `make cluster-deploy` + `./test/incus/apply-cos-config.sh` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥ 23 Gbit/s (same as #4408 gate — this is the TX hot path).

### Why it matters

`enqueue_pending_forwards` is the single most complex function in the TX path. Every bug fix in the forward-build cascade (NAT64 frag guard #2562, PTB inner-MTU derivation #2301/#2330/#2845, fabric fail-closed #1946, direct-TX tuple mismatch #4041, owned-frame recycling #2208) added a conditional branch inside the same function body, making the next fix harder to reason about. The next feature touching this path (e.g., encap offload, GSO) will add another 100+ LOC to a function that already exceeds the 100-line / 8-param mod-threshold by 10x. Splitting Phase 8 now — while the #1443 deferred-extraction comment is fresh — keeps the function reviewable.

### Fix direction

1. Extract `DirectTxFallbackReason` + `BuildOutcome` enum + `build_and_enqueue_forward` into `tx/dispatch/forward_build.rs` (Phase 8 cascade: inplace → direct-TX → copy-path). Pure code motion, `#[inline]` helpers, same borrow shapes. Verify with `cargo test -p userspace-dp --lib afxdp::tx::dispatch::tests` + `make test-rust`.
2. Extract fabric-redirect unsendable drop helper into `tx/dispatch/fabric.rs` (de-dup 3 repeat sites → one `handle_fabric_redirect_unsendable` call). Pure code motion.
3. Extract TCP segmentation dual-builder dispatch into `tx/dispatch/tcp_seg.rs` (gate + prepared-builder + local-copy fallback + miss recording). Pure code motion.
4. Each step is a separate commit/PR — Phase 8 extraction first (largest win), fabric helper second (mechanical), TCP-seg third (independent). No behavioral change in any step — `make test` + iperf3 smoke gate on each.

### Labels

`refactor`, `modularity`, `hot-path`, `decomposition`, `dispatch`, `follow-up-to-#4408`

---

## Finding 2: tx/cos_classify.rs — 7 fused responsibilities in one 1335-LOC file (3rd-largest TX file)

- **Severity:** Medium (modularity — the file is correct but mixes admission policy, wire-format mutation, loss-priority classification, queue routing, and per-queue state machine)
- **Confidence:** High
- **Refactor class:** (B) — Small, safe refactor (new modules, pure code-motion, shared private helpers stay in same crate)

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/cos_classify.rs` — 1335 LOC (production only, 4617 LOC tests in separate file — correct shape per style guide)

7 distinct responsibilities in one `mod cos_classify`:

| Responsibility | LOC span | Distinct concept |
|---|---|---|
| TX-selection resolve — cached path | `resolve_cached_cos_tx_selection` ~line 101..330 | Flow-cache seed: filter eval + FC→queue + BA fallback, cached descriptor shape |
| TX-selection resolve — runtime path | `resolve_cos_tx_selection_internal` ~line 404..689 | Per-packet same logic + policer metering + ingress/egress filter fold |
| BA reclassification | `reclassify_cached_ba_queue` ~line 342..360 | Flow-cache HIT re-resolve from per-packet DSCP/PCP |
| Loss-priority + rewrite | `resolve_cos_loss_priority` + `resolve_cos_queue_lp_rewrite` ~line 691..757 | Per-packet loss-priority derivation + (queue, LP)→DSCP table lookup |
| Generated-reply classification | `classify_generated_reply` ~line 51..99 | ICMP PTB / Time-Exceeded / reject-reply own-tuple CoS resolve (fail-closed) |
| Local/prepared → CoS enqueue | `enqueue_local_into_cos` + `enqueue_prepared_into_cos` + `clone_prepared_request_for_cos` + `enqueue_cos_item` ~line 759..960 + ~line 1157..1331 | Materialize → admission gate (flow-share / buffer / ECN) → push |
| Demote + queue-idx helpers | `demote_prepared_cos_queue_to_local` + `resolve_cos_queue_idx` + `cos_queue_accepts_prepared` ~line 969..1143 | Prepared→local downgrade on TX-frame exhaustion, MFQ vtime snapshot/restore, queue index resolution |

`enqueue_local_into_cos` itself is a 110-LOC function fusing: TX-frame materialization (`prepare_local_request_for_cos`), prepared-enqueue attempt, fallback-to-local clone on failure, ECN policy, per-flow buffer admission, and flow-share admission — 5+ sub-steps:

```rust
pub(in crate::afxdp) fn enqueue_local_into_cos(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    req: TxRequest,
    now_ns: u64,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> Result<(), TxRequest> {
    let egress_ifindex = req.egress_ifindex;
    if !ensure_cos_interface_runtime(binding, forwarding, egress_ifindex, now_ns) {
        return Err(req);
    }
    if binding.cos.cos_interfaces.get(&egress_ifindex)
        .is_some_and(|root| cos_queue_accepts_prepared(root, req.cos_queue_id))
    {
        match prepare_local_request_for_cos(binding.umem.area(), &mut binding.tx_pipeline.free_tx_frames, req) {
            Ok(prepared_req) => {
                // ... prepared enqueue attempt → fallback to local clone on Err ...
            }
            Err(req) => {
                // ... demote + local enqueue ...
            }
        }
    }
    let item_len = req.bytes.len() as u64;
    match enqueue_cos_item(binding, egress_ifindex, req.cos_queue_id, item_len,
        CoSPendingTxItem::Local(req), now_ns, shared_recycles.as_deref_mut()) {
        Ok(()) => Ok(()),
        Err(CoSPendingTxItem::Local(req)) => Err(req),
        Err(CoSPendingTxItem::Prepared(_)) => unreachable!("local request returned prepared item"),
    }
}
```

`enqueue_cos_item` (~175 LOC) fuses 4 concerns: sojourn stamping, flow-bucket index + buffer-limit derivation, per-flow flow-share admission + aggregate buffer admission + ECN marking, and queue-push + root-nonempty/runnable bookkeeping + exact-backlog publish.

The file also carries 5 inline `resolve_cos_*_queue_id` helpers that are pure table lookups — candidates for a tiny `classifiers.rs` leaf.

### Proposed decomposition

```
tx/cos_classify/
  mod.rs              — re-exports only (~30 LOC), same pattern as tx/dispatch/mod.rs post-#1443
  tx_selection.rs     — resolve_cached_cos_tx_selection + resolve_cos_tx_selection_internal
                        + reclassify_cached_ba_queue (cached + runtime TX-selection, ~400 LOC)
  loss_priority.rs    — resolve_cos_loss_priority + resolve_cos_queue_lp_rewrite + helpers (~70 LOC)
  generated_reply.rs  — classify_generated_reply + GeneratedReplyVerdict (~50 LOC)
  enqueue.rs          — enqueue_local_into_cos + enqueue_prepared_into_cos
                        + prepare_local_request_for_cos + clone_prepared_request_for_cos (~250 LOC)
  admission.rs        — enqueue_cos_item (admission gate: flow-share / buffer / ECN / push) (~180 LOC)
  demote.rs           — demote_prepared_cos_queue_to_local + resolve_cos_queue_idx
                        + cos_queue_accepts_prepared (~160 LOC)
  classifiers.rs      — resolve_cos_dscp_classifier_queue_id + resolve_cos_ieee8021_classifier_queue_id (~25 LOC)
```

Seam: each submodule is `pub(in crate::afxdp::tx)` or `pub(in crate::afxdp)`. Shared private helpers (`resolve_cos_queue_idx`) stay `pub(super)` in the new `cos_classify` parent `mod.rs` or move to `classifiers.rs`. `enqueue_cos_item` is `pub(super)`-only (consumed by `enqueue.rs` and `demote.rs`) — its visibility does not change.

Test file (`cos_classify_tests.rs`, 4617 LOC) stays as `#[path = "cos_classify_tests.rs"] mod tests;` under the new parent `mod.rs` — no test moves needed (already separate file, correct per style guide). The `#[path]` attribute moves from `cos_classify.rs` to `cos_classify/mod.rs`.

### Hot-path preservation analysis

`enqueue_local_into_cos` / `enqueue_prepared_into_cos` / `enqueue_cos_item` ARE the CoS hot path — per-packet at line rate on every shaped flow.

- **No new heap allocation:** The split is pure code motion — same function bodies, same `VecDeque` / `MmapArea` / `BindingWorker` borrows. `CoSTxSelection` / `GeneratedReplyVerdict` are small `Copy` structs (2×Option<u8> + bool + Option<FilterLogMatch>). The one `clone_prepared_request_for_cos` `to_vec()` is already present (required to materialize a prepared frame into a local `Vec<u8>` for fallback) — not new.
- **No dynamic dispatch:** All helpers are `#[inline]` in same crate, monomorphized, single caller each. Module boundary is free for inlining.
- **Zero-copy / UMEM invariant preserved:** `prepare_local_request_for_cos` draws a free TX frame and copies into UMEM in-place — the frame is NOT double-recycled on fallback (the `recycle_prepared_immediately_with_shared` on the fallback path is the single recycle). Moving this into `enqueue.rs` does not change the borrow/ownership shape.
- **Inlining:** `resolve_cos_dscp_classifier_queue_id` / `resolve_cos_ieee8021_classifier_queue_id` are `#[inline]` table lookups (array index + `u8::MAX` sentinel check) — they MUST stay inlined (they run per-packet on every shaped flow, including the BA-reclassify hit path). The `#[inline]` attribute survives the module move (same crate, sibling submodule). `resolve_cos_loss_priority` is similarly `#[inline]` + called from two sites — same guarantee.
- **Single-recycle invariant:** `enqueue_prepared_into_cos` recycles the prepared frame on fallback-to-local success (`recycle_prepared_immediately_with_shared`), and does NOT recycle on `Err` return (caller retains ownership). This must be preserved exactly — the test `resolve_cos_queue_idx_falls_back_to_default_on_explicit_queue_miss` / demote-path tests pin the recycle accounting.

### Tests + gate

- Existing: `cos_classify_tests.rs` (4617 LOC) — covers every branch (filter FC, DSCP BA, 802.1p, BA reclassify, LP rewrite, unmaterialized-queue fallback, demote vtime snapshot/restore, `cos_queue_accepts_prepared` O(1) gate). Must pass unchanged after file move (same `mod tests` parent, no test edits).
- New: if extracting `enqueue.rs` / `admission.rs`, add a unit test for the flow-share vs. buffer drop attribution precedence (currently inline `if flow_share_exceeded` → `if buffer_exceeded` in `enqueue_cos_item` at line ~1252 — easy to swap during refactor).
- Gate: `make test` (Go+Rust), `make test-deploy`, `make cluster-deploy` + `apply-cos-config.sh` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥ 23 Gbit/s + `show class-of-service interface` targeted counters (`flow_share` / `buffer` / `ecn_marked`) move in predicted direction (CoS validation: `docs/cos-validation-notes.md`).

### Why it matters

`cos_classify.rs` is the 3rd-largest production file in `tx/` (after `dispatch/mod.rs` and `drain/mod.rs`). Every CoS admission or classifier change (BA reclassify #3778, LP rewrite #3995, demote MQFQ fix #926, ECN #718/#722, flow-share #707/#710) added a new helper or branch to the same file. The next change (e.g., WRED, per-flow DSCP rewrite) will add another 100+ LOC and risks conflicting with concurrent work on a different CoS sub-concern. Splitting now — while the file is at 1335 LOC (below the 2000 LOC hard limit but above the 1000 LOC smell threshold) — keeps review diffs small and conflict-free.

### Fix direction

1. Create `tx/cos_classify/mod.rs` + re-export shim, move `cos_classify.rs` → `cos_classify/tx_selection.rs` (first PR — largest win, mechanical rename). Update `tx/mod.rs` `mod cos_classify;` (no change needed if using `mod cos_classify;` — Rust resolves `cos_classify/mod.rs` automatically). Verify `make test-rust` passes with zero test edits (tests already in separate file).
2. Extract `generated_reply.rs` + `loss_priority.rs` + `classifiers.rs` (small leaves, independent, no cross-deps). Second PR.
3. Extract `enqueue.rs` + `admission.rs` + `demote.rs` (hot-path modules, need inline preservation check + recycle-invariant pin). Third PR — add the flow-share vs. buffer attribution precedence test before moving.

### Labels

`refactor`, `modularity`, `cos`, `file-size`, `safe-split`

---

## Finding 3: tx/transmit/*.rs — CLEAN SEPARATION (NEGATIVE FINDING)

- **Severity:** N/A (positive example)
- **Confidence:** High
- **Refactor class:** (D) — No action needed, do NOT touch
- **Dedup note:** Not previously filed. The prior A1_b2 review flagged the phase ordering (REWRITE before VERIFY) as a correctness concern (A1-R3 in ps-review-038.md), not a modularity concern.

### Evidence

**Files:**
- `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/transmit/mod.rs` — 365 LOC
- `stage.rs` — 64 LOC, single responsibility: pop up to TX_BATCH_SIZE, drop oversized
- `rewrite.rs` — 63 LOC, single responsibility: iterate staged, apply DSCP rewrite
- `verify.rs` — 58 LOC, single responsibility: re-validate UMEM slices
- `write.rs` — 60 LOC, single responsibility: reserve+write+commit+stamp (POST-COMMIT invariant preserved)
- `finalise.rs` — 56 LOC, single responsibility: post-commit accounting + retry recovery

Orchestrator is 20 LOC and documents the six-phase contract:

```rust
/// Orchestrator: walks the prepared TX queue through six phases —
/// stage → DSCP rewrite → UMEM slice re-verify → optional RST log →
/// reserve+write+commit+stamp → finalise (success accounting / retry
/// recovery / TX kick). See `transmit/{stage,rewrite,verify,write,
/// finalise}.rs` for each phase's invariants. Pure code motion of
/// the prior monolithic body (#1354); semantics, ordering, and drop
/// accounting are byte-identical to the pre-split function.
pub(in crate::afxdp) fn transmit_prepared_queue(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() {
        return Ok((0, 0));
    }
    stage::stage_batch_into_scratch(binding, pending, shared_recycles)?;
    if binding.scratch.scratch_prepared_tx.is_empty() {
        return Ok((0, 0));
    }
    rewrite::apply_dscp_rewrites_to_staged(binding, shared_recycles)?;
    verify::verify_umem_slices_for_staged(binding, shared_recycles)?;
    if cfg!(feature = "debug-log") {
        log_rst_frames_prepared(binding);
    }
    let inserted = write::reserve_and_write_descriptors(binding);
    finalise::finalise_prepared(binding, pending, now_ns, inserted)
}
```

### Why this is a NEGATIVE finding

This is the textbook example of clean modular decomposition on the hot path — exactly what `docs/engineering-style.md` "Modularity discipline" asks for. Each phase is a single-responsibility module with:

- Clear ownership of one step in a linear pipeline
- Shared error semantics (orphan-recycle + `tx_submit_error_drops` accounting) factored into `recycle_prepared_immediately_with_shared` helper (not duplicated)
- `#[inline]` on each phase function (single caller, inlining guaranteed)
- Doc comments stating the invariant + drop semantics per phase
- No shared mutable state beyond the `&mut BindingWorker` + `&mut Vec<…>` scratch buffers already threaded by the orchestrator
- Zero new allocation (all phases operate on `&mut [PreparedTxRequest]` in scratch, `&mut Vec<(u32,u64)>` for recycles)
- Post-commit stamping invariant preserved by keeping reserve+write+commit+stamp inside `write.rs` (not splittable without breaking #812 HIGH #1)

**Do NOT further split this.** The 6-phase split is the right granularity. Collapsing them would re-create a monolithic function. Splitting finer (e.g., separating `stamp_submits` from `write.rs`) would break the post-commit invariant documented in `write.rs:15-20`.

### Proposed decomposition

None — this is clean. Use as template for the dispatch/mod.rs Phase 8 extraction (Finding 1).

### Hot-path preservation analysis

- No new allocation, no dynamic dispatch, zero-copy preserved, inlining preserved, single-recycle invariant preserved — all by construction (the split IS pure code motion per #1354, verified by `make test-rust` at that PR).

### Tests + gate

- Existing: `transmit_tests.rs` (186 LOC) + `dispatch_tests.rs` (1564 LOC, covers prepared TX path indirectly). Must continue to pass.
- No new tests needed for this finding (it's a negative).

### Why it matters (as a negative)

Demonstrates that the TX path CAN be cleanly decomposed without hot-path cost. Finding 1 and Finding 2 should follow this pattern.

### Labels

`modularity`, `positive-example`, `no-action`, `template`

---

## Finding 4: tx/rings.rs — mixed ring disciplines (completion drain + fill drain + RX/TX wake) — minor

- **Severity:** Low (modularity — file is 415 LOC, below the 2000 LOC hard limit, but mixes two logically distinct XSK ring disciplines)
- **Confidence:** Medium
- **Refactor class:** (C) — Trivial refactor (new modules, pure code-motion, low risk) OR (D) — Accept as-is at current size, split only when adding new logic

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/rings.rs` — 415 LOC

Two distinct XSK ring disciplines + two wake mechanisms in one file:

| Discipline | Functions | Distinct failure mode |
|---|---|---|
| TX completion ring drain | `reap_tx_completions` (72 LOC), `recycle_completed_tx_offset`, `apply_prepared_recycle`, `record_tx_completion_ring_available*` | Completion ring stall → TX frame leak → `free_tx_frames` exhaustion |
| Fill ring drain | `drain_pending_fill` (59 LOC) | Fill ring starvation → RX stall → `rx_xsk_buff_alloc_err` on mlx5 |
| RX wake (POLLIN) | `maybe_wake_rx` (49 LOC) | RX wake missed → idle interface never receives packets |
| TX wake (sendto) | `maybe_wake_tx` (98 LOC) | TX wake missed → latency-sensitive reply stalls on idle zerocopy binding |

The completion path and fill path share only:
- `BindingWorker` (different fields: `tx_pipeline.free_tx_frames` vs `pending_fill_frames`, `scratch_completed_offsets` vs `scratch_fill`)
- `shared_recycles` routing (cross-binding fill-frame return)
- `update_binding_debug_state` (debug snapshot)

They are otherwise independent: different ring types (`complete` vs `fill`), different wake mechanisms (`poll(POLLIN)` vs `sendto`), different error paths, different telemetry counters. A change to completion drain (e.g., #812 latency sidecar, #825 kick-latency) should not require reading the fill drain code, and vice versa.

The file also carries a `#[cfg(test)]` block with two small unit tests for completion/available tracking — those belong with the completion discipline.

### Proposed decomposition (if splitting)

```
tx/rings/
  mod.rs          — re-exports (~15 LOC)
  completions.rs  — reap_tx_completions + recycle_completed_tx_offset + apply_prepared_recycle
                    + record_tx_completion_ring_available* + tests (~200 LOC)
  fill.rs         — drain_pending_fill + maybe_wake_rx (~130 LOC)
  wake.rs         — maybe_wake_tx (~100 LOC)
```

Or, more conservatively (2-file split, preserves the existing `#812` latency comment threading):

```
tx/completions.rs — completion drain + recycle + stats hooks (~220 LOC)
tx/fill.rs        — fill drain + RX wake + TX wake (~195 LOC)
```

Seam: both new modules take `&mut BindingWorker` + `&mut Vec<(u32,u64)>` + `u64 now_ns` — same as today. No new types, no new traits, no ownership changes. `tx/mod.rs` re-exports update from `pub(super) mod rings; pub(super) use rings::...` to `pub(super) mod completions; pub(super) mod fill;` (or `mod rings { pub mod completions; pub mod fill; }` keeping the `rings::` prefix for callers).

### Hot-path preservation analysis

Both `reap_tx_completions` and `drain_pending_fill` are hot-path — called once per `drain_pending_tx` tick (and `reap_tx_completions` also from `transmit_batch` on free-frame exhaustion).

- **No new heap allocation:** Pure code motion — same `&mut BindingWorker` borrows, same `Vec::clear()` + `Vec::push` on reuse buffers (`scratch_completed_offsets`, `scratch_fill`) that are already pre-allocated on `BindingWorker.scratch`.
- **No dynamic dispatch:** `#[inline]` functions in same crate, single caller each (from `drain/mod.rs` and `transmit/mod.rs`), module boundary free for inlining.
- **Zero-copy / UMEM invariant preserved:** `recycle_completed_tx_offset` routes `PreparedTxRecycle::FillOnSlot` to `shared_recycles` for cross-binding return, `FreeTxFrame` to `free_tx_frames`. This routing is unchanged by module move. The single-free invariant (frame freed exactly once via completion ring) is preserved — the `in_flight_prepared_recycles` map tracks frames until completion, then `remove(&offset)` ensures exactly-once recycle.
- **Inlining:** `reap_tx_completions` is `pub(in crate::afxdp)`, called from `drain/phase_trivial.rs` as `drain_phase_reap_completions` → `reap_tx_completions`. One level of indirection, `#[inline]` on both ensures LLVM collapses. Same for `drain_pending_fill` → `drain_phase_ingest_cos` path.
- **Single-recycle invariant:** Verified by existing `apply_prepared_recycle_routes_fill_and_free_explicitly` unit test (already in `rings.rs`, moves with `completions.rs`). No new paths introduced.

### Tests + gate

- Existing: `rings::tests::apply_prepared_recycle_routes_fill_and_free_explicitly` + `record_tx_completion_ring_available_*` (3 tests). Must pass unchanged after file move.
- New: none for pure code motion. If splitting, verify the `rings::` prefix re-export still resolves from `drain/phase_trivial.rs` / `transmit/mod.rs` / `dispatch/mod.rs` callers (compile check).
- Gate: `make test-rust` (unit), `make test-deploy` (standalone), `make cluster-deploy` + iperf3 smoke (same TX hot-path gate as Finding 1).

### Why it matters

At 415 LOC, `rings.rs` is well below the 2000 LOC hard limit and is NOT a monolith today. This finding is (C) — trivial split — or (D) — accept as-is. The reason to file it is: the next change touching EITHER completion drain OR fill drain will add code to a file that already mixes two disciplines, making the diff harder to review and increasing merge conflict surface with concurrent work on the other discipline. Splitting now costs one file-rename PR with zero behavioral change and makes future changes to each discipline independent.

If the team prefers to keep `rings.rs` as one file at current size, that is reasonable — mark this (D) and re-evaluate only if the file grows past ~600 LOC or a third discipline is added.

### Fix direction

1. Create `tx/rings/completions.rs` + `tx/rings/fill.rs` + `tx/rings/mod.rs` re-export shim, move code (pure `git mv` + `mod` declaration). Update `tx/mod.rs` re-exports. Verify `cargo test -p userspace-dp --lib` passes + `make test-rust` passes.
2. OR: accept as (D) — no action, re-evaluate when file grows past 600 LOC.

### Labels

`refactor`, `modularity`, `low-priority`, `trivial-split`, `rings`

---

## Finding 5: tx/drain/mod.rs — orchestrator + helpers + leftover filters in one 594-LOC file (minor)

- **Severity:** Low (modularity)
- **Confidence:** Medium
- **Refactor class:** (D) — Accept as-is at current size, well-structured; OR (C) — extract leftover filters into dedicated module (mechanical)
- **Dedup note:** Not previously filed. The drain phase split (#1443 follow-up) already extracted `phase_shaped.rs`, `phase_backup.rs`, `phase_trivial.rs` — this finding evaluates the remaining `mod.rs` residue.

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/drain/mod.rs` — 594 LOC

After the phase extraction, `drain/mod.rs` contains:

1. `DrainCtx` struct + 4 re-export `use super::*` + `mod phase_*` declarations (orchestrator header, ~30 LOC)
2. `pending_tx_capacity` — pure math helper (5 LOC)
3. `bound_pending_tx_local` + `bound_pending_tx_prepared` — backpressure bound helpers (50 LOC)
4. `drain_pending_tx` — 6-phase orchestrator (35 LOC — clean, delegates to phase helpers)
5. `drop_cos_bound_prepared_leftovers` — #760 CoS shaper bypass guard, prepared side (85 LOC)
6. `drop_cos_bound_local_leftovers` — #760 CoS shaper bypass guard, local side, with rescue attempt (80 LOC)
7. `tx_request_targets_cos_interface` — predicate (5 LOC)
8. `partition_cos_bound_local_with_rescue` — pure scan helper (30 LOC, `#784` mixed-head invariant)
9. `binding_has_pending_tx_work` + `should_enter_shaped_drain` + `has_queued_cos_work` — predicates (15 LOC)
10. `drain_pending_tx_local_owner` — thin wrapper (10 LOC)
11. `ingest_cos_pending_tx` + `ingest_cos_pending_tx_with_provenance` — full MPSC inbox drain + CoS routing (200 LOC)
12. `process_pending_queue_in_place` — generic queue drain helper (15 LOC)
13. `take_pending_tx_requests` + `restore_pending_tx_requests` — inbox helpers (20 LOC)

Items 5-8 (CoS leftover filters, ~200 LOC) are logically "CoS shaper bypass guards" — they protect the #760 cap bypass invariant and have their own test file (`drain/tests.rs`, 201 LOC). They could live in `drain/cos_leftover.rs`.

Items 11-13 (CoS ingest, ~235 LOC) are the MPSC inbox drain + CoS routing logic — they could be `drain/cos_ingest.rs`.

The orchestrator itself (item 4) is clean at 35 LOC and correctly delegates to phases — that is NOT the problem.

### Proposed decomposition (if splitting)

```
tx/drain/
  mod.rs              — DrainCtx + drain_pending_tx orchestrator + pending_tx_capacity (~70 LOC)
  phase_trivial.rs    — reap + rekick + ingest + submit-and-wake (existing, unchanged)
  phase_shaped.rs     — shaped drain + re-ingest budget (existing, unchanged)
  phase_backup.rs     — backup post-CoS transmit (existing, unchanged)
  cos_ingest.rs       — ingest_cos_pending_tx + ingest_cos_pending_tx_with_provenance
                        + process_pending_queue_in_place + take/restore helpers (~250 LOC)
  cos_leftover.rs     — drop_cos_bound_prepared_leftovers + drop_cos_bound_local_leftovers
                        + partition_cos_bound_local_with_rescue + tx_request_targets_cos_interface (~130 LOC)
  bounds.rs           — bound_pending_tx_local + bound_pending_tx_prepared (~50 LOC)
  predicates.rs       — binding_has_pending_tx_work + should_enter_shaped_drain + has_queued_cos_work
                        + drain_pending_tx_local_owner (~25 LOC, or fold into mod.rs — tiny)
```

Seam: `cos_ingest.rs` and `cos_leftover.rs` take `&mut BindingWorker` + `&ForwardingState` + `&mut Vec<(u32,u64)>` — same as today. No new types beyond `DrainCtx` (already in `mod.rs`). `bounds.rs` is `pub(super)` helpers used by `cos_ingest.rs` + `cos_classify.rs` + `dispatch/mod.rs` — its visibility does not change.

### Hot-path preservation analysis

`ingest_cos_pending_tx` / `drop_cos_bound_*_leftovers` are hot-path — called once per `drain_pending_tx` tick.

- **No new heap allocation:** Pure code motion. `process_pending_queue_in_place` is generic over `T` and operates on `&mut VecDeque<T>` in-place (pop_front/push_back, no alloc). `take_pending_tx_requests` reuses `binding.tx_pipeline.pending_tx_local` as the drain target (allocation-free per file comment at line 577).
- **No dynamic dispatch:** All helpers are `#[inline]` or `pub(super)` in same crate.
- **Inlining:** `partition_cos_bound_local_with_rescue` is a pure function with two closures — `#[inline]` + monomorphized per closure type, no dynamic dispatch. Moving to `cos_leftover.rs` preserves inlining (same crate, sibling module).
- **Single-recycle / correctness:** The `drop_cos_bound_prepared_leftovers` `O(n)` full-deque scan (not head-peek — #784 correctness fix) + `drop_cos_bound_local_leftovers` rescue attempt are both load-bearing for the #760 CoS cap bypass invariant. Moving them must preserve the full-scan semantics + rescue attempt. The existing `drain/tests.rs` pins `partition_cos_bound_local_scans_mixed_head_deque` — that test moves with `cos_leftover.rs` and continues to pass.

### Tests + gate

- Existing: `drain/tests.rs` (201 LOC) — `partition_cos_bound_local_scans_mixed_head_deque`, `drop_cos_bound_*` integration tests. Must pass unchanged.
- Gate: `make test-rust`, `make cluster-deploy` + iperf3 + `show class-of-service interface` (same as Finding 2 — CoS path).

### Why it matters

At 594 LOC, `drain/mod.rs` is below the 2000 LOC hard limit and its orchestrator is clean. The phase extraction (#1443 follow-up) already did the heavy lifting. This finding is (D) — accept at current size — or (C) — trivial split if the team anticipates more CoS ingest/leftover changes. The 200 LOC `ingest_cos_pending_tx_with_provenance` function (with its #780 memoization, #760 provenance tracking, and #784 mixed-head handling) is the single largest function in `drain/` and mixes MPSC inbox management with CoS routing — a future change to either concern touches a file with the other.

### Fix direction

1. If splitting: create `drain/cos_ingest.rs` + `drain/cos_leftover.rs` + `drain/bounds.rs`, move code (pure `git mv` + `mod` declaration), update `tx/mod.rs` re-exports. Verify `cargo test -p userspace-dp --lib afxdp::tx::drain::tests` passes.
2. OR: accept as (D) — no action, re-evaluate when `drain/mod.rs` grows past ~800 LOC or a new ingest/leftover concern is added.

### Labels

`refactor`, `modularity`, `low-priority`, `drain`, `future-split`

---

## Summary — Findings by Refactor Class

| # | Title | Class | Severity | LOC | New vs. Dedup |
|---|-------|-------|----------|-----|---------------|
| 1 | `dispatch/mod.rs` enqueue_pending_forwards remnant (Phase 8 + direct-TX + segmentation + fabric still fused) | (B) safe split | High (modularity) | 1048 LOC function, ~650 LOC Phase 8 still inline | NEW detail on #4408 (hot-path preservation + Phase 8 + direct-TX + fabric dedup) |
| 2 | `cos_classify.rs` 7 fused responsibilities | (B) safe split | Medium (modularity) | 1335 LOC file, 7 responsibilities | NEW (not in #4408 — #4408 covered `cos/queue_service`, not `tx/cos_classify`) |
| 3 | `transmit/*.rs` 6-phase split — CLEAN (negative) | (D) no action | N/A | 5×~60 LOC + 365 LOC orchestrator | NEW negative (prior A1_b2 review flagged phase ordering as correctness bug, not modularity) |
| 4 | `rings.rs` mixed disciplines (completion + fill + wake) | (C) trivial / (D) accept | Low | 415 LOC file | NEW |
| 5 | `drain/mod.rs` orchestrator + leftover filters + ingest | (D) accept / (C) trivial | Low | 594 LOC file, ~200 LOC leftover + ~235 LOC ingest | NEW (phase extraction already done, this evaluates residue) |

---

## Cross-Cutting Notes

### Hot-path preservation — common to all (B) findings

All proposed splits are pure code motion within the same Rust crate (`userspace-dp`). The guarantees:

- **Module boundary is free for inlining in Rust.** Same-crate `mod` boundaries do not inhibit inlining — `rustc` inlines across `mod` boundaries when `#[inline]` + single caller. The proposed new modules (`dispatch/forward_build.rs`, `dispatch/tcp_seg.rs`, `dispatch/fabric.rs`, `cos_classify/tx_selection.rs`, etc.) are siblings of the current module — same crate, same compilation unit. Verifiable by checking `cargo rustc -- --emit=llvm-ir` for `#[inline]` functions after the split — the IR should be identical (modulo symbol names) to pre-split.

- **No new heap allocation on any hot path.** Every proposed helper takes `&mut BindingWorker` + `&[u8]` + small `Copy` enums/structs. The `Vec`-returning `clone_prepared_request_for_cos` already exists and is not changed. No new `Box`, `Vec::new`, `String`, or `clone` on any hot path.

- **Zero-copy / UMEM frame ownership preserved.** The `PreparedTxRecycle` / `FillOnSlot` / `FreeTxFrame` single-recycle invariant is the most critical TX-path invariant. Every proposed split preserves the exact `push_back` / `remove` / `recycle_prepared_immediately_with_shared` call sites — no new recycle, no removed recycle, no moved recycle across error paths. Verification: run `dispatch_tests.rs` fault-injection tests (they already enumerate every recycle path and assert `free_tx_frames.len()` / `pending_fill_frames.len()` balance) + `rings::tests`.

- **Single-recycle verification method:** The existing `dispatch_tests.rs` `FORCE_OVERSIZED` / `FORCE_TUPLE_MISMATCH` / `FORCE_ENQUEUE_ERR` thread-locals drive every error path and assert single-recycle. After each split PR, run `cargo test -p userspace-dp --lib afxdp::tx::dispatch::tests` + `cargo test -p userspace-dp --lib afxdp::tx::drain::tests` + `cargo test -p userspace-dp --lib afxdp::tx::transmit::tests` — all must pass with zero test edits (pure code motion).

### Behavioral gates (applicable to all findings)

Per `docs/engineering-style.md` "Deploy + feature validation":

- `make test` (Go suite + Rust `cargo test`) — every PR, no exceptions. Rust leg needs `cargo` (~minutes). If `make test` fails on Rust side, the PR is NOT mergeable.
- `make test-deploy` (standalone VM, ping between zones) — every PR touching TX path (this IS TX path — always required).
- `make cluster-deploy` (loss userspace cluster) + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥ 23 Gbit/s — every TX-path PR (this batch IS TX path — always required). Deploy wipes CoS — re-apply before iperf3.
- `show class-of-service interface` — for Finding 2 / Finding 5 (CoS admission path) — `flow_share` / `buffer` / `ecn_marked` counters must move in predicted direction per `docs/cos-validation-notes.md`.
- `make test-failover` — if touching `fabric.rs` or `rings.rs` shared-recycle path (Finding 1 fabric helper, Finding 4 fill/completion split).
- Fairness gates: `docs/fairness-regimes.md` — per-flow CoV floor check for CoS changes.

### Dedup — full cross-reference

- **#4408** `tx/dispatch enqueue_pending_forwards (1,131 LOC) god-function` — ALREADY FILED. Finding 1 provides NEW decomposition detail (Phase 8 body, direct-TX fallback enum, dual TCP-seg builder paths, fabric-redirect triple repetition, PendingForwardFrame variant dispatch) + hot-path preservation analysis (inlining, zero-copy, single-recycle verification method) that #4408 lacked. Finding 1 does NOT re-report the god-function — it assumes #4408's filing and adds the next-level breakdown.
- **#4408** `cos/queue_service waterfill` — different file (`userspace-dp/src/afxdp/cos/queue_service/mod.rs`, not `tx/cos_classify.rs`). Finding 2 covers `tx/cos_classify.rs` — different file, different responsibility set (TX-selection + enqueue + admission + demote vs. drain-side waterfill selection). No overlap.
- **Prior A1 batch reviews** (`ps-review-038-A1_rust_dataplane_packet-b2.md`, `ps-review-038.md` A1-R1/R2/R3) — filed correctness bugs (MTU→u16 truncation, completion-ring OOB, REWRITE-before-VERIFY ordering), not modularity findings. No overlap with this audit's modularity focus.
- **#1354** `transmit` 6-phase split — already complete, verified, merged. Finding 3 is a NEGATIVE (no action) that confirms the split is exemplary. Not a duplicate.
- **#1443** `dispatch` 3-submodule split (cos, shared_recycle, slow_path) — already complete, verified, merged. Finding 1 identifies the STILL-REMAINING Phase 8 + direct-TX + fabric + frame-kind fusion that #1443 explicitly deferred ("Phase 8 body extraction is deferred to a follow-up"). Not a duplicate — it's the follow-up #1443 anticipated.



---

## Findings from a1c (/ps-review-039-a1c.md)

## Finding 1 — CoSInterfaceRuntime god-struct (mixed hot/cold, no cache isolation) — (B) Should-Fix

**Severity:** Medium
**Confidence:** High
**Refactor class:** (B) — structural debt, not blocking, should split before next waterfill change

**Evidence:**

`types/cos.rs:556-709` — `CoSInterfaceRuntime` has 28 fields mixing 5 distinct lifecycles:

```rust
pub(in crate::afxdp) struct CoSInterfaceRuntime {
    pub(in crate::afxdp) shaping_rate_bytes: u64,
    pub(in crate::afxdp) burst_bytes: u64,
    pub(in crate::afxdp) tokens: u64,                                   // (1) token bucket
    pub(in crate::afxdp) nonexact_surplus_under_exact_tokens: u64,      // (1) residual surplus bucket
    pub(in crate::afxdp) nonexact_surplus_under_exact_last_refill_ns: u64,
    pub(in crate::afxdp) default_queue: u8,                             // (2) config/routing
    pub(in crate::afxdp) nonempty_queues: usize,                         // (2) bookkeeping
    pub(in crate::afxdp) runnable_queues: usize,
    pub(in crate::afxdp) oversubscription_policy: CoSOversubscriptionPolicy, // (3) waterfill policy
    pub(in crate::afxdp) oversubscription_guarantee_fraction: f64,
    pub(in crate::afxdp) priority_low_min_share_bytes: u64,             // WIRE-SURFACE-ONLY unused
    pub(in crate::afxdp) priority_low_reserved_tokens: u64,            // UNUSED reserved
    pub(in crate::afxdp) priority_low_last_refill_ns: u64,             // UNUSED reserved
    pub(in crate::afxdp) exact_queues_by_rate_ascending: Vec<usize>,    // (3) waterfill index
    pub(in crate::afxdp) waterfill_pass1_remaining_bytes: u64,          // (3) waterfill epoch
    pub(in crate::afxdp) waterfill_phase2_cursor: usize,
    pub(in crate::afxdp) waterfill_honored_epoch_bits: u64,
    pub(in crate::afxdp) waterfill_epochs: u64,
    pub(in crate::afxdp) waterfill_phase1_budget_breaks: u64,
    pub(in crate::afxdp) waterfill_epoch_start_ns: u64,
    pub(in crate::afxdp) waterfill_epoch_wrap_pending: bool,
    pub(in crate::afxdp) exact_guarantee_rr: usize,                     // (4) RR cursors
    pub(in crate::afxdp) nonexact_guarantee_rr: usize,
    pub(in crate::afxdp) queues: Vec<CoSQueueRuntime>,                  // (2)
    pub(in crate::afxdp) queue_indices_by_priority: [Vec<usize>; 6],    // (4) surplus DRR
    pub(in crate::afxdp) rr_index_by_priority: [usize; 6],
    pub(in crate::afxdp) timer_wheel: CoSTimerWheelRuntime,             // (5) timer wheel (cold)
}
```

- No `#[repr(align(64))]` or grouping. Contrast `SharedCoSLeaseState`, `PaddedBacklogSlot`, `PackedEpochGrant`, `PaddedVtimeSlot` — all `#[repr(align(64))]` with explicit padding to avoid false-sharing. `CoSInterfaceRuntime` is single-writer (owner worker) so cross-core false-sharing is not the issue, but intra-worker cache locality is: every `select_*` walk touches `tokens`, `waterfill_*`, `queues`, `queue_indices_by_priority` — 28 fields spanning >2 cache lines with dead `priority_low_*` (3 fields, 24 bytes) in the middle of the hot struct.
- 3 WIRE-SURFACE-ONLY / UNUSED fields (`priority_low_min_share_bytes`, `priority_low_reserved_tokens`, `priority_low_last_refill_ns`) are documented as `Currently UNUSED` in the same file (lines 573-588) and confirmed by grep: only referenced in `types/cos.rs` field defs + builder copy, never read on hot path. They occupy cache-line space in a hot struct for a deferred feature.
- `CoSInterfaceRuntime` combines token bucket, waterfill epoch, RR cursors, surplus DRR indices, timer wheel, and config — 5 responsibilities. The waterfill state alone is 7 fields + 1 Vec, moved as a unit across 3 sites (`select_exact_cos_guarantee_queue_waterfill`, `refund_phase1_waterfill_honor`, `apply_phase1_waterfill_honor_refund`).
- `FlowFairState` (`types/cos.rs:922-1095`) is correctly boxed via `new_boxed` to avoid 352 KB stack frames (#1755), but `CoSInterfaceRuntime` itself is not cache-line aware — its `Vec<CoSQueueRuntime>` lives on heap but the inline struct (tokens + waterfill + RR + timer_wheel) is contiguous and hot.

Count from `types/cos.rs`:
- `CoSInterfaceConfig`: 11 fields (ok)
- `CoSInterfaceRuntime`: 28 fields (god-struct)
- `CoSQueueConfigState`: 9 fields (ok)
- `CoSQueueHotState`: 9 fields + VecDeque (ok)
- `FlowFairState`: 13 fields + huge arrays (justified, boxed)
- `VMinQueueState`: 8 fields (ok)
- `CoSQueueTelemetry`: 4 sub-structs (ok)

**Proposed decomposition:**

1. Extract waterfill epoch state into a new `CoSInterfaceWaterfillState` struct (7 fields + Vec + counters) — lives in `types/cos/waterfill.rs` or inline in `types/cos.rs` as a named sub-struct:

```rust
pub(in crate::afxdp) struct CoSInterfaceWaterfillState {
    exact_queues_by_rate_ascending: Vec<usize>,
    pass1_remaining_bytes: u64,
    phase2_cursor: usize,
    honored_epoch_bits: u64,
    epochs: u64,
    phase1_budget_breaks: u64,
    epoch_start_ns: u64,
    epoch_wrap_pending: bool,
}
```

2. Group token-bucket fields into `CoSInterfaceTokenState` (tokens, burst, shaping_rate, nonexact_surplus bucket).

3. Group RR cursors into `CoSInterfaceRrState` (exact_guarantee_rr, nonexact_guarantee_rr, queue_indices_by_priority, rr_index_by_priority).

4. Remove or `#[cfg]`-gate the 3 `priority_low_*` UNUSED fields, or move them into a `CoSInterfaceReserved` cold struct behind a feature flag so they don't pollute cache lines.

5. Add `#[repr(C)]` field ordering comment documenting hot-fields-first (tokens, waterfill, queues, RR, timer_wheel last).

This keeps `CoSInterfaceRuntime` as a façade with 5 named sub-structs, each testable in isolation and each clearing one responsibility.

**Hot-path preservation:**

- Single-writer (owner worker) — plain `u64` counters stay plain, no atomics.
- No heap alloc on TX path: `exact_queues_by_rate_ascending` already `Vec` built at promotion time; waterfill state refactor does not add allocation.
- Waterfill epoch logic unchanged — only field path prefix changes (`root.waterfill.pass1_remaining` vs `root.waterfill_pass1_remaining_bytes`).
- `priority_low_*` removal is zero-behavior: grep confirms no hot-path reads; if kept, move to cold struct at end of `CoSInterfaceRuntime` so hot prefix fits in fewer cache lines.
- QoS guarantee-guard correctness (#4246): waterfill refund + Phase-1 honor bit semantics preserved byte-for-byte; only struct nesting changes. Differential test: `cargo test --lib -- cos::queue_service::tests::waterfill` must remain green; `fused_diff_tests` proves no selection drift.

**Tests + gate:**

- Unit: existing `queue_service/tests.rs` waterfill epoch tests (6 tests pinning Phase-1/Phase-2 interaction, honored bit persistence, time-tick vs pass1==0 refill, Phase-1 refund). Must stay green.
- New: unit test that `CoSInterfaceWaterfillState::default()` matches zeroed fields of old struct (field-equivalence guard like `flow_fair_state_tests::new_boxed_matches_new`).
- CoS smoke: `make test` (Go + Rust); `loss:xpf-userspace-fw0` CoS iperf `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥23 Gbit/s, no regression; `show class-of-service interface` `waterfill_counters` move in predicted direction per `cos-validation-notes.md`.

**Why it matters:**

- Next waterfill change will touch 3 fields in a 28-field struct with no grouping — review misses spillover. The 3 UNUSED fields already misled one diagnostic (thinking `priority_low_min_share_bytes` was enforced, while the only enforcement site was never wired — #4220 honest comment).
- Cache-line efficiency: hot `select_exact_cos_guarantee_queue_waterfill` loads 7 waterfill fields + tokens on every call; moving 3 dead fields out saves one cache-line load and clarifies what's actually read.

**Fix direction:** Extract `CoSInterfaceWaterfillState`, `CoSInterfaceTokenState`, `CoSInterfaceRrState` as plain `struct`s in `types/cos.rs` (or `types/cos/interface/*.rs` if file crosses 2000 LOC after). Gate `priority_low_*` behind `#[cfg(feature="priority-low-min-share")]` or move to end/cold struct. No behavior change.

**Labels:** `refactor`, `modularity`, `cos`, `B-priority`

**Dedup note:** Not filed before. Related: #4408 (waterfill god-func) touches the waterfill *selector* function; this filing touches the waterfill *state container* (god-struct). Complementary.

---

## Finding 2 — queue_service/mod.rs waterfill selector god-function — (D) Duplicate + new angle (well-split since #1035, remaining debt tracked)

**Severity:** Low (already filed)
**Confidence:** High
**Refactor class:** (D) — already tracked as #4408, no new filing needed; confirm and add decomposition hint

**Evidence:**

`queue_service/mod.rs:925-1357` — `select_exact_cos_guarantee_queue_waterfill` measures **432 LOC** (925→1357 inclusive) inside a 2058-LOC file:

```
880  // #1614 A1: two-phase waterfill selector ...
925  fn select_exact_cos_guarantee_queue_waterfill(
926      root: &mut CoSInterfaceRuntime,
...
932      ... // Phase 1 epoch refill + raw_pass1 calc + f64→u64 fraction math + clamp
1018     // Phase 1: ascending walk
1052     for i in 0..ascending_len {
...
1226     }
1227     // Phase 2: descending walk
1238     let mut phase2_idx = root.waterfill_phase2_cursor;
...
1345     }
1346     // Genuine Phase-2 WRAP
1353     root.waterfill_pass1_remaining_bytes = 0;
1354     root.waterfill_phase2_cursor = 0;
1355     root.waterfill_epoch_wrap_pending = true;
1356     None
1357 }
```

Counted responsibilities (all in one function):

1. Epoch refill trigger (time-based `elapsed >= COS_GUARANTEE_VISIT_NS` OR `pass1 == 0`)
2. `raw_pass1` computation — two branches (shaped root `cap_per_epoch * fraction` vs transparent `quantum_sum * fraction`), with `f64::floor() as u64` truncation
3. Clamp to `COS_GUARANTEE_QUANTUM_MIN_BYTES` (AGY RISK-1 fix)
4. Honored bitset clear gating (`epoch_boundary = time_refresh || wrap_pending`)
5. Phase-1 ascending walk (lease top-up, token gates, park, telemetry, honor + bit set, budget debit)
6. Phase-2 descending walk (honored skip, lease top-up, token gates, cursor advance, telemetry)
7. Phase-2 WRAP reset (zero budget, reset cursor, arm wrap_pending)

**Measurable sub-smell:** The `f64` fraction path (lines 965-1001) is 37 LOC of float math + comments that could be unit-tested in isolation; currently covered only indirectly via end-to-end waterfill tests.

**Proposed decomposition (if/when #4408 is implemented):**

- `queue_service/waterfill_refill.rs` — `fn refill_waterfill_epoch(root, now_ns) -> bool` (returns whether epoch_boundary); own the `raw_pass1` calc + clamp + bitset clear.
- `queue_service/waterfill_phase1.rs` — `fn waterfill_phase1_ascending(root, queue_fast_path, now_ns, telemetry) -> Option<Selection>`
- `queue_service/waterfill_phase2.rs` — `fn waterfill_phase2_descending(root, ...) -> Option<Selection>`
- `select_exact_cos_guarantee_queue_waterfill` becomes ~40 LOC orchestrator: `if refill { } ; phase1.or_else(phase2).or_else(wrap)`

This mirrors the existing `#1035 P2/P3` split pattern (`drain.rs`, `service.rs`, `submit_local.rs`, `submit_prepared.rs`) that already broke 800+ LOC off `queue_service/mod.rs`.

**Hot-path preservation:** All helpers `#[inline]`, take `&mut CoSInterfaceRuntime`, no alloc, no new atomic, `f64` math stays in refill (cold-ish epoch boundary, not per-packet).

**Tests+gate:** Existing waterfill tests must stay green; add unit test for `refill_waterfill_epoch` covering transparent vs shaped root, tiny-fraction clamp, `time_refresh` vs `exhausted` vs `wrap_pending` bitset clear matrix.

**Why this filing is (D):** #4408 already filed the same 438-LOC god-func. No new GitHub issue. This note adds the `f64` fraction extraction angle and confirms the measurement (432 LOC, not 438 — drift from subsequent livelock fixes #1743 r3). Modularity discipline says split before next waterfill feature; current file is 2058 LOC (just over 2000 smell line) but was  ~3000 before #1035 split, so trending correctly.

**Labels:** `modularity`, `cos`, `D-duplicate`

**Dedup note:** #4408 `cos/queue_service waterfill (438 LOC) — ALREADY FILED`. Confirm accurate, add refill-extraction nuance.

---

## Finding 3 — shared_cos_lease cluster: backlog + vtime well-split (D-good), lease.rs still monolithic (C) — Mixed

**Severity:** Low (lease.rs trending) + None (backlog/vtime good)
**Confidence:** High
**Refactor class:** (D) for backlog/vtime/rotate/publish — well-modularized, no action; (C) for lease.rs — nice-to-have split when next v8 feature lands

**Evidence:**

**Good — backlog.rs (210 LOC) + vtime.rs (238 LOC) are exemplary:**

```rust
// backlog.rs — single struct, self-contained, no sibling reach, two repr(align(64)) inner pads
pub(in crate::afxdp) struct SharedCoSExactBacklog {
    worker_bytes: Box<[PaddedBacklogSlot]>,
    residual_budget: PaddedResidualBudget,
}
// vtime.rs — single coordination struct, self-contained, 64-byte aligned slots, sentinel clamping
pub(in crate::afxdp) struct SharedCoSQueueVtimeFloor {
    slots: Box<[PaddedVtimeSlot]>,
}
```

- Each file: one public type, 2-3 `impl` methods, no visibility widening needed (split commit message says "no visibility widening" for both). This is the template for good splits.
- Size: 210 + 238 = textbook small modules. Retain this shape.

**Trending — lease.rs (1460 LOC) still carries two disjoint lifecycles:**

- Legacy lease (lines 1-330): `SharedCoSLeaseConfig`, `SharedCoSLeaseState`, `pack/unpack`, `shared_cos_lease_acquire/release/consume`, `SharedCoSRootLease`, `SharedCoSQueueLease::new`
- v8 fair-share (lines 349-1460): `new_v8*`, `matches_config_v8`, `acquire_v8`, `acquire_v8_with_cause`, `snapshot_epoch_v8`, `try_bump_outstanding`, `tag_checked_rollback`, `equal_flow_cap_v8`, `v8_worker_claim_flow`, 6 per-worker atomic arrays

The file header itself documents the tension:

> `lease.rs` — "the `SharedCoS{Queue,Root}Lease` token bucket + the v8 per-worker fair-share acquire path"

That's two modules described as one.

**Good — rotate_epoch_v8.rs (446 LOC) + publish_equal_flow_epoch_v8.rs (247 LOC) are well-scoped:**

- Each is a single `impl SharedCoSQueueLease` method extracted via pure code-motion (PR #1588), self-contained, no heap alloc on hot path, seqlock ordering preserved. Retain.

**Good — epoch.rs (565 LOC) is mixed but tolerable:**

- Contains `V8State` + `SharedCoSEpochState` + `PackedEpochGrant` + `PaddedAtomic*` + `V8EqualFlowSuppressState` + `V8RotationScratch` + enums + constants. All are epoch-state, so one file is defensible. Cold.

**Proposed decomposition (when next v8 feature pushes lease.rs over 2000):**

- `shared_cos_lease/lease_legacy.rs` — `SharedCoSLeaseConfig`, `SharedCoSLeaseState`, `pack/unpack`, legacy `acquire/release/consume`, `SharedCoSRootLease`, `SharedCoSQueueLease::new`
- `shared_cos_lease/lease_v8.rs` — `new_v8*`, `matches_config_v8`, `acquire_v8*`, snapshot, equal-flow cap, per-worker claim
- Keep `epoch.rs` as is (or extract `V8EqualFlowSuppressState` to `equal_flow.rs` if it grows).
- Keep `backlog.rs`, `vtime.rs`, `rotate_epoch_v8.rs`, `publish_equal_flow_epoch_v8.rs` untouched — they are the positive examples.

**Hot-path preservation:**

- `acquire_v8` is on the hot path (called from `select_exact_cos_guarantee_queue_waterfill` Phase-1/Phase-2 + RR fast path). Splitting files does not change inlining — keep `#[inline(always)]` on `pack/unpack`, `#[inline]` on `acquire_v8` (already there). Module boundary is `pub(in crate::afxdp)` not `pub`, so LLVM can still inline across `mod` in same crate.
- No new heap alloc: per-worker arrays already boxed at `new_v8_with_rate_mode_and_policy` time (cold path). Split does not add alloc.

**Tests+gate:**

- Existing `shared_cos_lease_tests.rs` (2511 LOC) covers seqlock tear detection, carry, stall, equal-flow fail-open, v8 shortfall cause attribution. Must stay green.
- CoS smoke: v8 fair-share correctness — small class guaranteed under BE flood (shaped-class-held-under-BE-flood #4246 class) must hold; `loss:xpf-userspace-fw0` iperf must not regress.

**Why it matters / why (C) not (B):**

- Current `lease.rs` 1460 LOC is under the 2000 smell line but trending (was part of 2121-LOC monolith pre-#2158, now 1460 of 3258 cluster). Next v8 feature (+200 LOC) will push it over. Splitting now is premature; splitting at next feature (per "Refactor with new features, not after") is right.
- `backlog.rs` + `vtime.rs` prove the team can split well — cite them as template in review.

**Labels:** `modularity`, `cos`, `shared-lease`, `C-nice-to-have` + `D-good-example`

**Dedup note:** #2158 P2 already split the original 2121-LOC `shared_cos_lease/mod.rs` into 4 submodules — this filing acknowledges that split as exemplary for backlog/vtime, and tracks the remaining lease.rs concentration as a (C) follow-up, not a new (A)/(B).

---

## Summary

| # | Area | LOC | Finding | Class | Action |
|---|------|-----|---------|-------|--------|
| 1 | `types/cos.rs` CoSInterfaceRuntime | 28 fields, 1786 LOC file | God-struct mixing 5 lifecycles, 3 UNUSED WIRE-SURFACE-ONLY fields in hot cache lines, no sub-struct grouping | **(B)** Should-fix | Extract `WaterfillState` / `TokenState` / `RrState` sub-structs, cold-move or cfg-gate `priority_low_*` |
| 2 | `queue_service/mod.rs` waterfill selector | 432 LOC fn inside 2058 LOC file | God-function with 7 responsibilities — already filed as #4408 | **(D)** Duplicate | No new issue; add refill-extraction note to #4408 |
| 3a | `shared_cos_lease/backlog.rs` + `vtime.rs` + `rotate` + `publish` | 210/238/446/247 LOC | Cohesive, self-contained, correct `#[repr(align(64))]`, no visibility widening — positive example | **(D)** Good | No action, cite as template |
| 3b | `shared_cos_lease/lease.rs` | 1460 LOC | Legacy lease + v8 fair-share mixed in one file | **(C)** Nice-to-have | Split into `lease_legacy.rs` + `lease_v8.rs` when next v8 feature lands |
| — | `queue_ops/` prod 1893 LOC, test 6488 LOC | 3.4× test/prod | Test-dominant but expected for MQFQ CoV gate; `mod.rs` mixes min-finish selection + demotion + constants — tolerable at current size | **(D)** Good | No action; demotion helper could move to `demote.rs` if mod.rs crosses 600 LOC |
| — | `cos/tx_completion.rs` 1080 LOC | timer-wheel + TX-completion apply + prime + restore | 3 responsibilities in one file — monitor, split if new timer-wheel feature added | **(C)** Watch | No immediate action |

**Overall A1c assessment:** The CoS subsystem shows good modularity trend — `queue_service/` was split from a larger monolith (#1035 P2/P3), `shared_cos_lease/` was split from 2121 LOC single file into 7 cohesive submodules (#2158 P2), `queue_ops/` was split into 7 files (#1034 P1-P3). The remaining debt concentrates in:
- `types/cos.rs` god-struct (28 fields) — (B) should-fix before next waterfill or priority-low feature
- `queue_service/mod.rs` god-function — (D) already tracked (#4408)
- `shared_cos_lease/lease.rs` 1460 LOC legacy+v8 mix — (C) split on next v8 feature

No (A) immediate-refactor required in this batch. The codebase is not monolithic in the pejorative sense — it is mid-refactor with clear trajectory and good examples (`backlog.rs`, `vtime.rs`) to follow.

---

## Verification performed (audit only — no code change)

- `wc -l` on all 14 prod + 5 test files in batch
- `grep -n "priority_low_"` — 3 UNUSED fields confirmed no hot-path readers
- `grep -n "select_exact_cos_guarantee_queue_waterfill"` — 432 LOC measured (925-1357)
- `grep -n "SharedCoSQueueLease\|SharedCoSRootLease"` — lease.rs carries both legacy + v8
- `ls -la` on `queue_service/` (6 files), `queue_ops/` (11 files), `shared_cos_lease/` (8 files) — split shape confirmed
- No `cargo test` run (audit only)


---

## Findings from a1d (/ps-review-039-a1d.md)

## File-size / shape inventory

| File | LOC | Role | Verdict |
|------|-----|------|---------|
| `mod.rs` | 2054 | `SessionTable` struct (25 fields), `SessionEntry` (16 fields), core helpers, timeout logic, scaffolding | **God-file** — carries 7 responsibilities; submodule split delegates method impls but leaves every field in one struct |
| `install.rs` | 521 | `install_with_protocol*`, `upsert_synced*`, delete/demote, capacity preflight | Code-motion from mod.rs (#2005) — accesses `self.entries`, `self.key_to_handle`, `self.nat_*_index`, `self.owner_rg_sessions`, `self.session_limit_*`, `self.deltas`, `self.wheel` directly via child-module `super::*` visibility |
| `lookup.rs` | 411 | `lookup_with_origin`, `find_forward_nat_match`, `find_forward_wire_match*`, `resolve_reverse_translated_handle`, iteration, `take_synced_local` | Same code-motion split — reads/writes `self.entries`, `self.key_to_handle`, `self.*_index`, `self.owner_rg_sessions`; mutates `entry.last_seen_ns`, `entry.expires_after_ns`, `entry.closing`, `entry.reset`, `entry.established` under direct `&mut` slab borrow |
| `expire.rs` | 625 | `push_to_wheel`, `expire_stale_entries`, `expire_stale_entries_ha`, `standby_gate_decision`, `companion_keeps_alive`, `rebucket_alive_entry` | Same — direct field access to `self.wheel`, `self.entries`, `self.key_to_handle`, all index maps, HA context closures; `companion_keeps_alive` does a second `entry_by_key` probe per idle-crossed entry |
| `key.rs` | 232 | `SessionKey`, NAT key transforms (`forward_wire_key`, `translated_session_key`, `reverse_wire_key`, `reverse_canonical_key`, `reverse_session_key`, `reply_matches_forward_session`) | **Clean** — pure functions, no `SessionTable` coupling |
| `entry.rs` | 284 | `SessionDecision`, `SessionMetadata`, `SessionLookup`, `ForwardSessionMatch`, `SessionOrigin`, `SessionDelta`, `ExpiredSession`, `SessionCounters` | **Clean extraction** of public data types (#1047 P2); `SessionEntry` itself stays in `mod.rs` because fields are file-private |
| `ctx.rs` | 126 | `SessionInstall`, `SessionUpdate`, `ExpireHaContext` | **Clean** — context structs replacing positional 7-arg clusters (#1357) |
| `wheel.rs` | 80 | `SessionWheel`, `WheelEntry`, `bucket_for_tick`, `target_tick_for`, constants | **Clean** — power-of-two assert, `FAR_FUTURE_OFFSET`, no table coupling |
| `tests.rs` | 6994 | Unit tests (excluded from prod LOC) | Catch-all single file — well-organized by `#[test]` fn name; not re-audited here per batch instructions |

**Production LOC:** 2054 + 521 + 411 + 625 + 232 + 284 + 126 + 80 = **4333 LOC** (6994 test-only)

---

## Finding 1: (D) — SessionTable submodule split is code-motion, not responsibility decomposition — #4421 DUP, new detail only

**Severity:** Low (modularity debt, not bug)  
**Confidence:** High  
**Refactor class:** Modularity — incomplete decomposition  
**Dedup:** #4421 already filed SessionTable god-struct (27 fields claimed, 6 responsibilities). This finding adds ONLY the new observation that the #2005 mechanical split does not constitute true responsibility separation.

### Evidence

`mod.rs` declares 7 submodules as `mod install`, `mod lookup`, `mod expire` etc. All attach `impl SessionTable { ... }` blocks. But every submodule accesses `SessionTable` private fields directly:

```rust
// install.rs — touches 7 distinct private fields of SessionTable
self.entries.insert(record);
self.key_to_handle.insert(key.clone(), handle);
self.index_forward_nat_key(&key, handle, decision, &metadata);
self.push_to_wheel(&key, now_ns);
self.session_limit_inc(key.src_ip, key.dst_ip);
self.push_delta(...);
```

```rust
// lookup.rs — mutates SessionEntry fields under &mut self.entries borrow,
// then calls self.push_to_wheel (in expire.rs) and self.propagate_tcp_state_to_companion (in mod.rs)
let record = self.entries.get_mut(handle as usize)?;
record.entry.last_seen_ns = now_ns;
record.entry.closing = true;
```

This works because in Rust a child module (`mod install;` inside `mod session`) inherits access to the parent's private fields via `super::*`. There is no trait boundary, no encapsulation, no compile-time isolation. A change to `SessionTable.nat_reverse_index`'s type (`HashMap` → `SmallVec` bucket in #4399/#4438) required touching `mod.rs` (type aliases), `install.rs` (insert path), `lookup.rs` (validate-on-lookup walk), and `expire.rs` (indirectly via `remove_entry` in mod.rs) simultaneously — four files for one field-type change, which is the same coupling as a single 2054-LOC file.

### Why this is not a new (B)/(C)

The mechanical split (#2005) was an intentional staging step — "pure code-motion, byte-for-byte identical bodies" is documented in every submodule header. The project plan calls it P2 of a multi-phase extraction. Filing it as a fresh god-struct issue would be a duplicate of #4421.

### What genuine decomposition would look like (for #4421's fix)

True extraction requires **field grouping + accessor encapsulation**:

| Proposed group | Fields | Responsibility |
|---|---|---|
| `SessionStore` | `entries: Slab<SessionRecord>`, `key_to_handle: SeededKeyMap<u32>` | canonical session storage |
| `NatIndexes` | `nat_reverse_index`, `forward_wire_index`, `reverse_translated_index`, `nat_reverse_key_collisions` | NAT secondary lookup (1:N multimap buckets — #4399/#4438 invariant holder) |
| `HaState` | `owner_rg_sessions`, `deltas`, `delta_loss_pending`, `delta_drops`, `delta_drained`, `epoch_counter` | HA sync (open/close deltas, owner-RG sets, loss-of-sync latch) |
| `IpLimitState` | `session_limit_active`, `session_limit_src_counts`, `session_limit_dst_counts` | per-IP session-limit counters (#2134/#3122/#4377) |
| `ExpiryState` | `wheel`, `last_pop_stats`, `last_gc_ns` | timer-wheel GC |
| `TimeoutConfig` | `timeouts`, `opening_overrides` | forwarding timeout policy |
| `CapacityState` | `max_sessions`, `expired`, `create_drops`, `admission_refused`, `install_partial` | capacity / admission telemetry |

Any extraction MUST preserve:
- **#4399 P5 / #4438**: `NatIndexes` 1:N bucket `SmallVec<[u32; 2]>` append-not-displace invariant — a colliding install APPENDS, removal removes only the handle — lookup validates each bucket entry. Single-value regression reintroduces session hijack.
- **Per-IP limit counting**: `session_limit_inc`/`dec` counted-class predicate (`!is_reverse && !origin.is_transient_local_seed()`, origin-agnostic since #3122), OFF->ON rebuild (#4377), decrement as sole sink in `remove_entry`.
- **`no_index_points_at` debug assert**: eager-cleanup invariant — no secondary index holds a freed handle.
- **Wheel lazy-delete discriminator**: `wheel_tick` vs `scheduled_tick`.

Hot-path preservation: `SessionStore` + `NatIndexes` stay on the same cache-line-touch path as today (one hash probe + one slab dereference per packet). Extracting to a sub-struct adds one level of field access (`self.store.entries` vs `self.entries`) — monomorphized by the compiler to identical codegen (field offset changes only). No pointer indirection (no `Box`).

---

## Finding 2: (C) — SessionEntry hot/cold fusion + SessionMetadata Arc clone per packet — thermal inefficiency, not a monolith per se

**Severity:** Medium (perf, not correctness)  
**Confidence:** High  
**Refactor class:** Performance — per-packet atomic on cloned metadata  
**Dedup:** #4421 mentions SessionEntry hot/cold fusion and "Arc metadata.clone() per packet cost" as part of the god-struct. This finding quantifies the CURRENT Arc re-introduction and proposes a hot/cold split that does NOT add pointer-chase overhead.

### Evidence

`SessionMetadata` in `entry.rs` carries:

```rust
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: u16,        // hot (timeout override lookup)
    pub(crate) egress_zone: u16,         // cold (logging/gRPC export only)
    pub(crate) owner_rg_id: i32,         // cold (HA ownership, not per-packet)
    pub(crate) fabric_ingress: bool,     // cold (HA standby gate only)
    pub(crate) is_reverse: bool,         // HOT — checked every packet
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>, // cold
    pub(crate) log_session_init: bool,   // cold
    pub(crate) log_session_close: bool,  // cold
    pub(crate) policy_id: u32,           // cold (telemetry)
    pub(crate) inactivity_timeout_ns: Option<u64>, // warm (timeout selection on refresh)
    pub(crate) policy_counter_idx: u32,  // cold (fallback path)
    pub(crate) policy_counter: Option<Arc<PolicyRuleCounter>>, // HOT — incremented every packet on fast path
}
```

Comment at `entry.rs:16-22` documents #919: zone names were changed from `Arc<str>` to `u16` IDs to eliminate "the `LOCK XADD` atomic on every `metadata.clone()`". But `policy_counter: Option<Arc<PolicyRuleCounter>>` re-introduces exactly that:

In `lookup.rs:lookup_with_origin` (hot path — every packet that hits a session):

```rust
(
    SessionLookup {
        decision: entry.decision,
        metadata: entry.metadata.clone(), // <-- Arc::clone does LOCK XADD
    },
    entry.origin,
)
```

`SessionMetadata::clone()` clones the `Option<Arc<_>>`, which is an atomic refcount bump. Same in `find_forward_nat_match`, `find_forward_wire_match_with_origin`, `entry_with_origin`, `iter_with_origin`.

**Hot/cold field inventory of SessionEntry** (16 fields, `mod.rs:343-459`):

```
HOT (per-packet read/write):
  decision              — NAT transform for reverse lookup
  entry.metadata.*      — is_reverse, policy_counter, ingress_zone
  last_seen_ns          — re-stamped every lookup hit
  expires_after_ns      — read every touch, written on state transition
  closing, reset        — TCP close state, checked every TCP packet
  established           — half-open guard, checked every TCP-SYN/SYN-ACK
  wheel_tick            — read on every wheel push (throttle compare)
  counters              — per-packet via account_packet (fwd/rev bytes/pkts)
  observed_tos / tcp_flags — per-packet via account_packet

COLD (GC / HA / telemetry / install-only):
  origin                — HA sync classification, tested only at promotion/demote
  install_epoch         — delta ordering, not on forwarding path
  created_ns            — close-delta harvest only
  seen_rg_epoch         — HA self-heal edge detection (GC 1Hz path)
  first_held_ns         — standby hold ceiling (GC 1Hz path)
```

`SessionEntry` is 16 fields with no `#[repr(C)]` / cache-line split. Hot fields and cold fields share the same cache line(s) — a write to `seen_rg_epoch` or `first_held_ns` on the GC path (or a read of `origin`/`owner_rg_id` in the standby gate) pulls the same cache line that the next packet's lookup will need for `decision`/`metadata`/`last_seen_ns`.

`SessionRecord` = `SessionKey` + `SessionEntry`. `SessionKey` itself is `addr_family: u8 + protocol: u8 + src_ip: IpAddr (variable size — 16 bytes for V6 + discriminant) + dst_ip + src_port + dst_port` — roughly 40-56 bytes depending on IpAddr discriminant. + 16-field `SessionEntry` — total slab record likely 200+ bytes, spanning multiple cache lines.

### Proposed decomposition (preserves no-pointer-chase invariant)

Split `SessionEntry` inline (no `Box`, no added indirection — same slab allocation, same number of cache lines fetched for hot fields today, but hot fields packed contiguously at offset 0):

```rust
// Hot — fits in 2 cache lines, touched every packet
struct SessionHot {
    decision: SessionDecision,        // 32-40 bytes (NatDecision + ForwardingResolution)
    is_reverse: bool,                 // 1 byte (hoisted from SessionMetadata)
    policy_counter: Option<Arc<PolicyRuleCounter>>, // see note below
    last_seen_ns: u64,               // 8
    expires_after_ns: u64,           // 8
    closing: bool,                   // 1
    reset: bool,                     // 1
    established: bool,               // 1
    wheel_tick: u64,                 // 8
    counters: SessionCounters,       // 32 (4×u64)
    observed_tos: u8,               // 1
    observed_tcp_flags: u8,         // 1
}

// Cold — instal / GC / HA only
struct SessionCold {
    metadata_rest: SessionMetadataCold, // egress_zone, owner_rg_id, fabric_ingress, nat64_reverse, log flags, policy_id, inactivity_timeout_ns, policy_counter_idx
    ingress_zone: u16,              // needed for timeout override — borderline warm
    origin: SessionOrigin,
    install_epoch: u64,
    created_ns: u64,
    seen_rg_epoch: u32,
    first_held_ns: u64,
}

struct SessionEntry {
    hot: SessionHot,
    cold: SessionCold,
}
```

**Policy counter Arc elimination (strongest win):** The per-rule `PolicyRuleCounter` hit count is incremented via `Arc` shared ownership because `PolicyState::rules` re-hands the same `Arc` for a surviving rule_id across snapshot rebuilds. Alternative: store `*const PolicyRuleCounter` (raw pointer, stable-address via `PolicyCounterStore` pinning) + `policy_counter_idx` for validation, avoiding the atomic on every `metadata.clone()`. Or: replace the `metadata.clone()` in `lookup_with_origin` with a non-cloning return — return `(&SessionDecision, &SessionMetadata)` / `(&SessionHot, &SessionCold)` borrows and let the caller copy only the fields it needs. `SessionLookup { decision, metadata }` clones the entire `SessionMetadata` today to return an owned value; the caller (`poll_descriptor` / `account_packet`) only needs `decision.nat` + `metadata.is_reverse` + `policy_counter` for the common path. Returning a borrow would eliminate the `Arc` clone entirely on the hot path.

**Do NOT:** Replace `Arc<PolicyRuleCounter>` with `Box<PolicyRuleCounter>` (adds a pointer chase per packet — worse than current). The win is eliminating the clone, not adding indirection.

### Hot-path preservation

- `SessionEntry` today lives in a `slab::Slab<SessionRecord>` — a contiguous `Vec`-backed store indexed by `u32`. Splitting `SessionEntry` into `SessionHot`/`SessionCold` sub-structs within the same slab record is a layout reordering, not an allocation change. The compiler's struct-field-offset lowering makes `entry.hot.last_seen_ns` a single `mov` with a different immediate offset. No new pointer chase, no added cache miss on the hot path — fewer, because cold fields no longer share the first 64 bytes with hot fields.
- `Arc::clone` elimination: removing the `metadata.clone()` → replacing with borrowing or raw-pointer counter avoids `LOCK XADD` (~20-40ns on contended x86). At 23 Gbit/s / 64-byte packets = ~45M pps across 6 workers = ~7.5M pps/worker, every per-packet atomic matters.
- Benchmark gate: `cargo bench -- session` (if criterion exists) or `cargo test -- session --nocapture` timing delta. Measure `lookup_with_origin` micro-bench before/after — expect ≥ 10ns reduction from Arc elimination alone.

### Tests / gate

- `make test` (includes `userspace-dp` cargo suite — session unit tests, NAT collision tests, HA standby-gate tests, timer-wheel tests).
- `make cluster-deploy && make test-failover` — session sync during failover must preserve per-RG ownership, standby HOLD/SELF-HEAL, and per-IP limit counting (which rides the same slab).
- Criterion bench: `session::lookup_with_origin` hot loop, `session::account_packet` hot loop — compare `Arc` clone vs borrow.

---

## Finding 3: (D) — Well-decomposed leaf modules — negative finding (no action needed)

**Severity:** None — negative confirmation  
**Confidence:** High  
**Refactor class:** None — clean code confirmed

### Evidence

Three leaf modules are exemplary decompositions and should be used as the template for future SessionTable extraction:

**`key.rs` (232 LOC):** Six pure functions (`forward_wire_key`, `translated_session_key`, `reverse_wire_key`, `reverse_canonical_key`, `reverse_session_key`, `reply_matches_forward_session`) with no `SessionTable` coupling. NAT64 address-family / ICMP protocol mapping is centralized here — one source of truth for the forward↔reverse key duality. #4074 ICMP identifier symmetric-field handling is documented and consistent across all six functions. Re-exported at `pub(crate)` via `pub(crate) use key::*` keeps crate surface stable.

**`wheel.rs` (80 LOC):** 256-bucket × 1s-tick wheel, `WHEEL_MASK` power-of-two trick with compile-time assert, `target_tick_for` / `bucket_for_tick` pure helpers, `FAR_FUTURE_OFFSET` long-timeout re-bucket. Zero table coupling — `SessionWheel` is a data container, `SessionTable` drives it. Matches `mod.rs`-level `SESSION_GC_INTERVAL_NS` via `WHEEL_TICK_NS = SESSION_GC_INTERVAL_NS` binding (Copilot review fix — cadence cannot silently diverge).

**`ctx.rs` (126 LOC):** `SessionInstall` (owned key) + `SessionUpdate` (borrowed key) + `ExpireHaContext` (closures over HA predicates). Resolves #1357's 7-field positional cluster drift hazard. Control flags (`allow_replace_local`, `ha_activation`) correctly stay positional — not embedded in the payload struct — so callers do not populate fields the callee overwrites.

These three modules total ~438 LOC of clean, independently-testable code with zero `SessionTable` private-field coupling. They demonstrate the target pattern: data-type extraction + pure-function grouping with `pub(crate)` / `pub(super)` visibility discipline.

---

## Summary of all findings

| # | Severity | Class | Module | Summary | Action |
|---|----------|-------|--------|---------|--------|
| 1 | Low (D) | Dedup | `mod.rs` + `install.rs`/`lookup.rs`/`expire.rs` | Submodule split is pure code-motion — all 3 submodules still access all 25 private fields via child-module `super::*` visibility; true responsibility grouping (7 groups identified) not yet achieved | Feed into existing #4421 — do not open new issue |
| 2 | Medium (C) | Perf / hot-cold | `mod.rs:SessionEntry`, `entry.rs:SessionMetadata` | `SessionEntry` 16 fields hot/cold fused; `SessionMetadata.policy_counter: Option<Arc<_>>` re-introduces #919's `LOCK XADD` per-packet via `metadata.clone()` in `lookup_with_origin` hot path; propose inline hot/cold split (no Box) + Arc-clone elimination via borrow / raw-pointer counter pinning | Open new issue — "session: eliminate per-packet Arc clone + hot/cold split" — targeted, measurable, staged |
| 3 | None (D) | Negative | `key.rs`, `wheel.rs`, `ctx.rs` | Leaf modules are exemplary — pure functions, zero table coupling, compile-time guards, doc'd invariants | No action — use as template |

---

## Labels

- `modularity` (finding 1 — dedup)
- `perf` `session` `hot-path` (finding 2)
- `no-action` (finding 3)

---

## Dedup note

- **#4421 — SessionTable god-struct (27 fields, 6 responsibilities), SessionEntry hot/cold fusion — ALREADY FILED.** Finding 1 in this report does NOT re-file it — it adds the observation that the #2005 mechanical submodule split (code-motion, byte-for-byte identical bodies, child-module `super::*` private-field access) does not constitute true responsibility decomposition, and enumerates the concrete 7-group field map that a genuine fix requires. Do not open a new god-struct issue from this report.
- **#4409 — overlaps SessionTable** — checked; this report's focus is the `userspace-dp/src/session/*.rs` directory only, not the broader `SessionTable` usage outside `session/`.
- **#4399 P5 — NAT reverse-index single-value→multi-value (correctness)** — related but different (correctness bug, not refactor). This report preserves the #4399/#4438 1:N `SmallVec<[u32; 2]>` bucket invariant as a hard constraint on any proposed decomposition (see Hot-path preservation sections). No re-report.

---

## Verification performed

- [x] Read `session/mod.rs` (2054 LOC), `session/entry.rs` (284), `session/key.rs` (232), `session/ctx.rs` (126), `session/wheel.rs` (80), `session/install.rs` (521), `session/lookup.rs` (411), `session/expire.rs` (625) — 8 files, 4333 prod LOC (6994 test-only)
- [x] Read `docs/engineering-style.md` — Hot-path discipline (no per-packet alloc, atomics, compile-time guards), Modularity discipline (no monolithic files >2000 LOC prod, no god functions >100 lines / >8 params)
- [x] Counted `SessionTable` fields: **25** (issue claimed 27 — close; earlier version likely had 2 additional fields or counted type aliases)
- [x] Counted `SessionEntry` fields: **16** (`decision`, `metadata`, `origin`, `install_epoch`, `last_seen_ns`, `created_ns`, `expires_after_ns`, `closing`, `reset`, `established`, `wheel_tick`, `seen_rg_epoch`, `first_held_ns`, `counters`, `observed_tos`, `observed_tcp_flags`)
- [x] Counted `SessionMetadata` fields: **12** including `policy_counter: Option<Arc<PolicyRuleCounter>>` (re-introduces #919 Arc overhead)
- [x] Confirmed `SessionTable` 7 responsibility groups (mapped explicitly in Finding 1 table)
- [x] Verified submodule access pattern: all of `install.rs`, `lookup.rs`, `expire.rs` use `super::*` / child-module privilege to access private `SessionTable` fields directly — not encapsulated
- [x] Verified `metadata.clone()` in `lookup.rs:lookup_with_origin` hot path causes `Arc::clone` → `LOCK XADD`
- [x] Verified no `#[repr(C)]` / `#[repr(align)]` / cache-line padding on `SessionEntry` or `SessionRecord`
- [x] Verified `key.rs`, `wheel.rs`, `ctx.rs` have zero `SessionTable` coupling and carry appropriate compile-time guards


---

## Findings from a1e (/ps-review-039-a1e.md)

## Finding 1 — ForwardingState God-Struct (65 Fields, No `#[repr]`) — (C) Performance-Positive

**Severity:** Medium
**Confidence:** High
**Refactor class:** (C) PERFORMANCE-POSITIVE — SoA hot-cold split; also (B) mechanical
**Guardrails:** Keep `ForwardingState::clone()` cheap for ArcSwap; cold fields still need `Default`.
**Verification:** `cargo test -p userspace-dp --lib forwarding_build::tests forwarding::tests` + `cargo test -p userspace-dp --lib` for FIB/NAT regressions; `make test-deploy && iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` for throughput regression check.

### Evidence

`ForwardingState` is defined at `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/types/forwarding.rs:14` with:

```rust
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingState {
    // 65 fields — counted via grep "pub(in crate::afxdp)" in struct range
```

Actual field count: **65** (not 55 as originally estimated in #4421 — field count grew via #3769, #3182, #3527, #3618, etc.). No `#[repr(C)]` or `#[repr(Rust)]` — uses default Rust layout (compiler chooses field order, may reorder for packing but still intermixes hot+cold).

Field categorization:

| Category | Count | Fields | Hot-path? |
|----------|-------|--------|-----------|
| Local-delivery | 10 | `local_v4/v6`, `local_tables_v4/v6`, `local_nat_any_table_v4/v6`, `configured_iface_v4/v6`, `interface_nat_v4/v6` | Hot (every packet local-delivery check) |
| FIB / connected | 6 | `connected_v4/v6`, `routes_v4/v6`, `neighbors`, `ingress_logical_ifindex` | Hot (every forwarded packet) |
| Tunnel / GRE / WG | 6 | `tunnel_endpoints`, `tunnel_endpoint_by_ifindex`, `gre_decap_index`, `wg_engines`, `has_wg_tunnels`, `tunnel_interfaces` | Hot (encap decap every tunnel packet; bool gate for non-tunnel) |
| Zone / interface meta | 7 | `ifindex_to_name`, `ifindex_to_config_name`, `ifindex_to_routing_instance`, `ifindex_to_zone_id`, `zone_name_to_id`, `zone_id_to_name`, `egress` | Warm-hot (zone-id lookup every packet; name maps cold) |
| Host-inbound / TCP-RST | 4 | `zone_host_inbound`, `ifindex_host_inbound`, `zone_tcp_rst`, `reject_buckets` | Hot-miss path only (local-delivery admit, policy-deny reject) |
| NAT | 4 | `source_nat_rules`, `static_nat`, `dnat_table`, `nat64`, `nptv6` (5 actual) | Hot (per-flow NAT match on session miss) |
| Policy / filter / screen | 6 | `policy`, `filter_state`, `screen_profiles`, `screen_missing_profiles`, `syn_cookie_master_key`, `cold_path_slot_map` | Hot (policy eval; screen check; sampled-latency path) |
| Fabric / HA | 2 | `fabrics`, `fabric_skips` | Warm (fabric redirect check, #3773 skip tracking) |
| CoS / mirror | 4 | `cos`, `tx_selection_enabled_v4/v6`, `mirror_configs` | Warm (CoS classification; tx-selection gates) |
| Misc / tuning | 8 | `allow_dns_reply`, `allow_embedded_icmp`, `alg_disable_flags`, `app_catalog`, `session_timeouts`, `session_opening_overrides`, `gre_acceleration`, `power_mode_disable`, `tcp_mss_*` (4), `cold_path_sample_mask`, `pending_neigh_timeout_ns` | Mostly cold (config truth, thresholds) |

Hot FIB lookup functions in `forwarding/mod.rs` touch: `local_v4/v6`, `local_tables_v4/v6`, `routes_v4/v6`, `connected_v4/v6`, `neighbors`, `ifindex_to_zone_id`, `ifindex_to_routing_instance`, `tunnel_endpoints`, `gre_decap_index`, `source_nat_rules`/`static_nat`/`dnat_table` (indirectly via `match_source_nat_for_flow*` helpers which read `ForwardingState`). These are interleaved in memory with cold config-truth fields like `filter_state`, `cos`, `ifindex_to_name` (String maps), etc.

### Why it matters

1. **dcache pressure**: every packet loads `ForwardingState` (behind `Arc`). With 65 fields spanning multiple cache lines, hot fields may be evicted by cold field accesses in the same struct. A 65-field struct with `FastMap<String, Vec<RouteEntryV4>>` values means `Arc<ForwardingState>` clone touches cold String keys too (refcount bumps).
2. **Build-time coupling**: `forwarding_build/mod.rs` writes all 65 fields sequentially in `build_forwarding_state_with_policy_counters_and_previous` (~300 LOC orchestrator). Adding a field requires touching the single builder function.
3. **Testing**: `forwarding/tests.rs` 4632 LOC tests all aspects of ForwardingState construction via one `build_forwarding_state` helper — no per-subsystem test seams.

### Proposed decomposition

Split into hot (immutable, read-only, dcache-friendly) vs cold (config metadata, diagnostics):

```text
// New module: userspace-dp/src/afxdp/types/forwarding_hot.rs
pub(in crate::afxdp) struct ForwardingFib {
    // Hot FIB — tightly packed, read every packet
    pub local_v4: FastSet<Ipv4Addr>,
    pub local_v6: FastSet<Ipv6Addr>,
    pub local_tables_v4: FastMap<Ipv4Addr, FastSet<String>>,
    pub local_tables_v6: FastMap<Ipv6Addr, FastSet<String>>,
    pub local_nat_any_table_v4: FastSet<Ipv4Addr>,
    pub local_nat_any_table_v6: FastSet<Ipv6Addr>,
    pub connected_v4: Vec<ConnectedRouteV4>,
    pub connected_v6: Vec<ConnectedRouteV6>,
    pub routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    pub routes_v6: FastMap<String, Vec<RouteEntryV6>>,
    pub gre_decap_index: FastMap<(i32, IpAddr, IpAddr), Vec<u16>>,
    pub has_wg_tunnels: bool,            // bool gate — 1 byte, keep with FIB
    pub neighbors: FastMap<(i32, IpAddr), NeighborEntry>,
    pub ifindex_to_zone_id: FastMap<i32, u16>,
    pub ifindex_to_routing_instance: FastMap<i32, String>,
    pub zone_name_to_id: FastMap<String, u16>, // warm-hot, needed for PBR
}

pub(in crate::afxdp) struct ForwardingState {
    pub fib: Arc<ForwardingFib>,               // hot — one Arc, one cache line for gate
    // Cold / semi-hot — remain inline, accessed on miss / admit / periodic
    pub zone_host_inbound: ...,
    pub source_nat_rules: ...,
    // ... rest unchanged
}
```

Alternative (simpler incremental step, lower risk): keep single struct but add a `#[repr(C)]` + field-reorder pass putting all hot fields first so they occupy contiguous cache lines. The compiler currently uses default layout which *may* reorder but is not guaranteed to pack hot fields together.

Seam: `ForwardingState` is `ArcSwap`-published to workers. Splitting `fib: Arc<ForwardingFib>` means workers can hold `Arc<ForwardingFib>` directly for the hot loop and `Arc<ForwardingState>` for cold-path calls — or keep one `Arc<ForwardingState>` with `fib` inline (simpler, still dcache benefit from field ordering).

### Hot-path preservation

- ForwardingState is `ArcSwap`-stored; workers deref via `Arc`. The Arc clone per tick stays cheap. Splitting does not add indirection on the hot path if `fib` is `Arc`-wrapped separately — workers that only need FIB can hold `Arc<ForwardingFib>`.
- Hot `lookup_forwarding_resolution_inner_ecmp` (192 LOC, every packet) reads `local_v4/v6`, `local_tables_*`, `routes_*`, `connected_*`, `neighbors` — must not add a branch or extra load. Field-reorder alone preserves this; `Arc<ForwardingFib>` adds one pointer chase (one load) vs inline fields — measure with `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` (≥23 Gb/s invariant).
- Keep `#[inline]` on `owns_configured_ip`, `zone_tcp_rst_enabled`, `reject_bucket` — all currently `#[inline]`.

### Fix direction

1. Add `#[repr(C)]` and hot-field-first ordering as immediate zero-risk step (no API change).
2. In a follow-up, extract `ForwardingFib` as separate `Arc` so cold fields (filter_state, cos, ifindex_to_name strings) don't share cache lines with hot FIB maps.
3. Verify with `cargo test -p userspace-dp` (both Go and Rust legs) before and after; throughput check on loss cluster.

---

## Finding 2 — neighbor.rs Monolith (2036 LOC, 4+ Responsibilities) — (B) Mechanical + (C) Cold-Path GC

**Severity:** Medium (at threshold per engineering-style.md — 2036 LOC > 2000 soft limit, touches hot-path neighbor lookup via `ForwardingState.neighbors`)
**Confidence:** High
**Refactor class:** (B) — three clean seams exist; (C) GC/warmer is cold-path extractable
**Guardrails:** `neigh_monitor_thread` uses raw netlink fd + epoll; keep fd ownership clear after move. `trigger_kernel_arp_probe` called from worker hot-path — don't add allocation there.
**Verification:** `cargo test -p userspace-dp --lib neighbor` (all neighbor unit tests including `nth_allowed_cpu_*`, `dump_batch_*`, `neigh_monitor_rcvbuf_*`, `data_path_learn_installs_stale_not_reachable_4475`); `RUST_LOG=xpf=debug` observe `neighbor_warmer_loop` still logs; cluster throughput spot-check (neighbor path not hot but regression can stall resolution).

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/neighbor.rs` — 2036 LOC

Responsibilities (4 distinct):

| Responsibility | Key fns | Lines | Coupling |
|---------------|---------|-------|----------|
| ARP/ND probe + ICMP packet craft | `trigger_kernel_arp_probe` (134), `build_icmp4_echo`, `build_icmp6_echo`, `build_solicit_sockaddr_in6`, `select_probe_socket` | ~300 | Called from `neighbor_warmer_loop` + tests |
| Kernel netlink neighbor management | `build_newneigh_request`, `add_kernel_neighbor`, `update_dynamic_neighbor`, `remove_dynamic_neighbor`, `parse_neighbor_msg`, `request_neighbor_dump`, `process_dump_batch`, `initial_neighbor_dump` | ~400 | Netlink protocol encoding; called from monitor thread + shared_ops |
| Neighbor monitor thread + dump | `neigh_monitor_thread` (272 — largest fn), `set_neigh_monitor_rcvbuf`, `dump_establishes_baseline`, `monotonic_timestamp_to_datetime` | ~400 | Runs as dedicated OS thread; owns netlink monitor socket |
| CPU affinity / pinning + test helpers | `nth_allowed_cpu`, `pin_current_thread`, `parse_mac`, `format_mac`, `neighbor_state_usable_str` | ~200 | Utility; used by `neigh_monitor_thread` for CPU assignment |
| Tests | `data_path_learn_installs_stale_not_reachable_4475`, `build_newneigh_request_encodes_requested_state`, `dump_batch_*`, `nth_allowed_cpu_*`, `neigh_monitor_rcvbuf_*`, `select_probe_socket` tests | ~700 | Inline `#[cfg(test)]` |

Largest functions (from python analysis):
- `neigh_monitor_thread` — 272 lines (netlink monitor event loop + dump sequencing + epoch tracking)
- `trigger_kernel_arp_probe` — 134 lines (interface name resolution, socket selection, ICMP craft, send)
- `neighbor_warmer_loop` — 120 lines (warm-item queue consumer, epoch gate, gen1 baseline)

**`neighbor_resolver.rs` (1512 LOC) and `neighbor_dispatch.rs` (1399 LOC): are they clean splits?**

- `neighbor_resolver.rs`: defines `NeighborResolver`, `ResolveItem`, `ResolverCounters`, `GetOutcome`, `ResolveAction`, `RateLimitDecision`. Owns a dedicated resolver thread (`neighbor_resolver_loop` 639..). Has its own netlink socket for `RTM_GETNEIGH` (synchronous per-key kernel query). Rate-limits via `RESOLVER_PER_KEY_RATE_LIMIT_NS`, `RESOLVER_ENQUEUE_THROTTLE_NS`. **Coupling:** `use super::*` — shares `NeighborEntry`, `ForwardingState`, `ConfigSnapshot` types. Enqueue path called from worker via `resolver_enqueue_throttle` fast-path. Returns `ResolveAction` to the coordinator for `ForwardingState.neighbors` update.
- `neighbor_dispatch.rs`: worker-side pending-neighbor queue (`pending_neigh: FastMap<(i32,IpAddr), PendingNeighPacket>`), per-key single-packet admission (`pending_neigh_admission`), retry with exponential probe schedule (`PROBE_SCHEDULE_NS`, `probe_due`), dynamic neighbor learning (`learn_dynamic_neighbor`, `learn_dynamic_neighbor_from_packet`), flow-key extraction for buffered packets. **Coupling:** `use super::*`; calls `neg_neigh::neg_neigh_active`, `neighbor_latency::neigh_latency_bucket_index`, `forwarding_build::PENDING_NEIGH_TIMEOUT_FAST_NS`. Owns `NegNeighCache` negative-cache lifecycle.

Assessment of splits:

| Criterion | Resolver | Dispatch |
|-----------|----------|----------|
| Has own thread/socket? | Yes — owns `RTM_GETNEIGH` fd + resolver loop thread | No — worker-owned, no new threads |
| Owned state? | Yes — `pending_dwell_hist`, `resolver_counters`, per-key throttle map, epoch | Yes — `pending_neigh` map, `neg_neigh_cache`, `resolver_enqueue_throttle` |
| Clean API boundary? | Partial — `ResolveItem` in, `ResolveAction`/`GetOutcome` out, but shares `NeighborEntry` | Weak — calls into 4+ sibling modules, hands `PendingNeighPacket` back to worker loop via closure capture |

Both files represent genuine concern splits (resolver = proactive kernel re-query; dispatch = worker-side buffering + learning). However they are not yet fully decoupled — they rely on `use super::*` and share `NeighborEntry`/`PeerAddr` identity types. Further cleanup would mean extracting shared types (`NeighborEntry`, `NeighborMsgEffect`, `GetOutcome`, `ResolveAction`, `PendingNeighPacket`) into a `neighbor_types.rs` or `types/neighbor.rs`.

### Proposed decomposition

**Step 1 (B — mechanical, no behavior change):**

```text
userspace-dp/src/afxdp/neighbor/
  mod.rs                  — re-exports + NeighborMsgEffect + NeighborStateClass helpers
  probe.rs                — trigger_kernel_arp_probe + build_icmp4_echo + build_icmp6_echo
                          + build_solicit_sockaddr_in6 + select_probe_socket
  kernel.rs               — build_newneigh_request + add_kernel_neighbor + update/remove_dynamic_neighbor
                          + parse_neighbor_msg + request_neighbor_dump + process_dump_batch
                          + initial_neighbor_dump + RTM_/NLM_/NUD_ constants
  monitor.rs              — neigh_monitor_thread + set_neigh_monitor_rcvbuf + nth_allowed_cpu
                          + pin_current_thread + monotonic_timestamp_to_datetime
  warmer.rs               — neighbor_warmer_loop + ProbeSockKind + WarmItem
  resolver.rs             — (existing neighbor_resolver.rs moved in, 1512 LOC)
  dispatch.rs             — (existing neighbor_dispatch.rs moved in, 1399 LOC)
  neighbor_types.rs       — (optional) NeighborEntry, NeighborMsgEffect, GetOutcome, ResolveAction,
                            RateLimitDecision, PendingNeighPacket, LearnedNeighborKey — shared leaf types
```

Existing `neighbor.rs` becomes `neighbor/mod.rs` (thin re-export). `neighbor_resolver.rs` / `neighbor_dispatch.rs` move under `neighbor/` directory — `git mv` preserves history. Tests move with their owning files (per-file `mod tests` blocks are the project pattern per engineering-style.md).

**Step 2 (C — cold-path GC extraction, optional):**

GC / stale-entry pruning of `pending_neigh` + `neg_neigh_cache` (currently in `worker/loop_body/mod.rs::reap_expired_sessions` + `neighbor_dispatch.rs`'s timeout handling) is cold-path (1s tick). Safe to extract into `neighbor/gc.rs` with a `GcCtx { now_ns, timeout_ns }` arg, called from worker tick — no per-packet cost.

### Hot-path preservation

- `trigger_kernel_arp_probe` is on the resolver hot-path (called per unresolved next-hop) — must not add allocation. Currently crafts `sockaddr_in6` on stack, sends via raw socket. After move to `neighbor/probe.rs` no change in call chain.
- `learn_dynamic_neighbor_from_packet` is called per received ARP/ND packet (RX path) — must not add branch. After move, same `#[inline]` / `pub(super)` visibility preserved.
- `pending_neigh_admission` is checked per forwarded packet that misses a neighbor entry — must remain `#[inline]` and not add allocation. Currently is a pure function `fn(pending_map_len, key) -> PendingNeighAdmission` with no map mutation in the fast check.
- `neighbors: FastMap<(i32, IpAddr), NeighborEntry>` remains in `ForwardingState.fib` — hot lookup unchanged.

### Fix direction

1. `git mv userspace-dp/src/afxdp/neighbor.rs userspace-dp/src/afxdp/neighbor/mod.rs`
2. Extract `probe.rs`, `kernel.rs`, `monitor.rs`, `warmer.rs` from current `neighbor/mod.rs` — mechanical, no signature changes.
3. `git mv neighbor_resolver.rs neighbor/resolver.rs` + `git mv neighbor_dispatch.rs neighbor/dispatch.rs` under the new `neighbor/` directory. Update `mod.rs` re-exports.
4. (Optional) Extract shared types to `neighbor/types.rs` to break `use super::*` cycles — only if step 3 reveals a clean dependency edge.
5. Verify: `cargo test -p userspace-dp --lib neighbor` then full `cargo test`.

---

## Finding 3 — forwarding_build/ Already Well-Decomposed — (D) Negative

**Severity:** Info
**Confidence:** High
**Refactor class:** (D) NEGATIVE — do not refactor further.

### Evidence

`forwarding_build/` was decomposed in #1342 from a single 1162-LOC `forwarding_build.rs` into 7 sibling files with clear ownership:

| File | LOC | Responsibility | Clean seam? |
|------|-----|---------------|-------------|
| `mod.rs` | 687 | Orchestrator — linear chain of sub-builder calls + late-stage NAT local-delivery pass + `build_screen_profiles` | Yes — no branching logic, reads top-to-bottom |
| `fib.rs` | 483 | `sort_connected`, `populate_routes`, `sort_routes`, `populate_neighbors`, `populate_fabrics`, route-target resolution | Yes |
| `interfaces.rs` | 340 | `populate_interfaces` (returns `IfaceIndex`), `populate_egress`, `pick_interface_v4/v6` | Yes |
| `cos.rs` | 850 | `build_cos_classifier_tables`, `build_cos_iface_config`, orchestrator `build_cos_state` | Yes — internal 3-way split noted in comment |
| `tunnels.rs` | 302 | `populate_tunnel_endpoints`, `tunnel_mode_kind`, `TunnelKind` | Yes |
| `zones.rs` | 142 | `populate_zones`, `reject_duplicate_zone_ids` | Yes |
| `wg.rs` | 127 | `populate_wg_engines` — WG engine reuse (TAI64N preservation) | Yes |
| `validated.rs` | 161 | `VlanId`/`TunnelTtl`/`QueueId` checked narrowing newtypes (#2410) | Yes |

Orchestrator (`mod.rs:200..450`) is a straight-line sequence:
`populate_zones → populate_tunnel_endpoints → populate_wg_engines → populate_interfaces → populate_egress → sort_connected → populate_routes → sort_routes → populate_neighbors → populate_fabrics → parse_policy_state → parse_source_nat → static_nat → dnat → nat64 → nptv6 → screen_profiles → ... → filter_state → cos → tx_selection flags → late-stage static-NAT/DNAT local-delivery append`

Late-stage passes (`local_v*` NAT append) *must* stay after every other writer of `local_v*` — comment at mod.rs top explains why. This ordering constraint prevents further arbitrary splitting without introducing a two-phase build.

The only soft spot is `cos.rs` at 850 LOC — but it already documents its own internal 3-way split (`build_cos_classifier_tables` + `build_cos_iface_config` + orchestrator) and a separate split would only add file churn for no readability gain (functions within `cos.rs` share `CosBuildCtx` locals).

### Why it matters (as negative)

A reviewer unfamiliar with the #1342 history might propose "split forwarding_build more." This is wrong — the module is at the right granularity. Over-splitting would scatter the ordering invariants (late-stage NAT must be last) and make the orchestrator harder to audit. No action needed.

---

## Finding 4 — forwarding/mod.rs 2822 LOC, 50+ Free Functions, No Impl — (B) Mechanical Extraction — Secondary

**Severity:** Low-Medium
**Confidence:** High
**Refactor class:** (B) — file exceeds 2000 LOC soft limit; responsibilities are separable.
**Guardrails:** `lookup_forwarding_resolution_inner_ecmp` + `lookup_forwarding_resolution_v4_inner` + `v6_inner` are hot-path — must stay `#[inline]` or `#[inline(always)]` after move. `ForwardingResolution` is `pub(crate)` — after move, new files must be in `forwarding/` so `pub(super)` visibility from new submodules reaches `forwarding/mod.rs`.
**Verification:** `cargo test -p userspace-dp --lib forwarding`; `make test-deploy` + zone-to-zone ping + basic ECMP test if available.

### Evidence

`userspace-dp/src/afxdp/forwarding/mod.rs` — 2822 LOC, 68 free functions (`grep "fn " | wc -l` equivalent), no `impl ForwardingState` block (methods live in `types/forwarding.rs`).

Function responsibilities (grouped):

| Group | Count | Largest | LOC range |
|-------|-------|---------|-----------|
| FIB / route lookup | 11 | `lookup_forwarding_resolution_v4_inner` (192), `lookup_forwarding_resolution_inner_ecmp` (192), `lookup_forwarding_resolution_v6_inner` (184), `ingress_route_table_override` (122) | 10–192 |
| NAT / interface-local | 8 | `interface_nat_local_resolution` (46), `match_source_nat_for_flow_result_at` (47), `parse_neighbor_entries` (50), `should_cache_local_delivery_session_on_miss` (55), `install_helper_local_session_on_miss` (62) | 12–62 |
| Fabric / HA / VRRP | 10 | `cluster_peer_return_fast_path` (105), `build_fabric_link_or_skip` (67), `prefer_local_forward_candidate_for_fabric_ingress` (44), `resolve_fabric_redirect*`, `enforce_ha_resolution*` | 15–105 |
| Tunnel / WG / MSS | 6 | `tunnel_outer_mtu` (48), `tunnel_tcp_mss` (47), `native_gre_inner_mtu`, `native_gre_tcp_mss`, `select_tcp_mss`, `effective_tcp_mss` | 15–48 |
| ECMP / hash | 6 | `choose_v4_route`, `choose_v6_route`, `ecmp_hash_*` (4 variants) | 8–43 |
| Helpers | 10+ | `canonical_route_table` (65), `classify_metadata`, `zone_pair_for_flow*`, `allow_unsolicited_dns_reply`, `owner_rg_for_flow`, `is_icmp_echo_request`, `is_ipsec_traffic`, `classify_ipsec_admission` | 5–65 |

Largest functions exceed 100 LOC threshold per engineering-style.md ("god functions" rule) — specifically `lookup_forwarding_resolution_v4_inner` (192), `lookup_forwarding_resolution_inner_ecmp` (192), `lookup_forwarding_resolution_v6_inner` (184), `ingress_route_table_override` (122), `cluster_peer_return_fast_path` (105) all qualify.

### Proposed decomposition

```text
userspace-dp/src/afxdp/forwarding/
  mod.rs              — DEFAULT_V4/V6_TABLE, MAX_NEXT_TABLE_DEPTH, LOCAL_DELIVERY_IFINDEX0, re-exports
  lookup.rs           — lookup_forwarding_resolution_*, lookup_forwarding_resolution_inner_ecmp,
                        lookup_forwarding_resolution_v4_inner, lookup_forwarding_resolution_v6_inner,
                        lookup_forwarding_for_ip, lookup_neighbor_entry, no_route_resolution,
                        ingress_route_table_override, choose_v4_route, choose_v6_route, ecmp_hash_*
  nat_local.rs        — interface_nat_local_resolution*, ingress_interface_local_resolution*,
                        should_cache_local_delivery_session_on_miss, install_helper_local_session_on_miss,
                        should_block_tunnel_interface_nat_session_miss, nat_scope_ctx_for_flow,
                        match_source_nat_for_flow*
  fabric_ha.rs        — build_fabric_link_or_skip, resolve_fabric_redirect*, resolve_fabric_links_from_snapshots,
                        resolve_zone_encoded_fabric_redirect*, redirect_via_fabric_if_needed,
                        prefer_local_forward_candidate_for_fabric_ingress, cluster_peer_return_fast_path,
                        enforce_ha_resolution*, ingress_is_fabric*, demoted/activated_owner_rgs,
                        cached_flow_decision_valid, finalize_new_flow_ha_resolution, owner_rg_for_flow*
  tunnel_gre.rs       — resolve_tunnel_outer, resolve_tunnel_forwarding_resolution, outer_neighbor_ifindex,
                        native_gre_inner_mtu, native_gre_tcp_mss, tunnel_outer_mtu, tunnel_tcp_mss,
                        select_tcp_mss, effective_tcp_mss, is_ipsec_traffic, classify_ipsec_admission
  host_inbound.rs     — (existing, 817 LOC) — already extracted
  tests.rs            — (existing, 4632 LOC)
```

This is follow-on work after (or alongside) Finding 1 — if `ForwardingState` is split into `ForwardingFib` + cold fields, the `lookup.rs` extraction is easier because `ForwardingFib` methods move naturally with `lookup.rs`.

### Hot-path preservation

- `lookup_forwarding_resolution_v4_inner` / `v6_inner` / `inner_ecmp` are called on every forwarded packet's session-miss path — keep `#[inline(always)]` or at least `#[inline]` after move. The hot-path is session-miss + flow-cache-miss → FIB lookup → NAT → zone/filter. A cross-module call without `#[inline]` adds a call instruction + register spill (measurable at 23+ Gb/s).
- `ecmp_hash_*` are `#[inline]` — preserve.
- `ForwardingState` arg threading: if `ForwardingFib` is extracted (Finding 1), `lookup.rs` takes `&ForwardingFib` not `&ForwardingState` — tighter borrow, better alias analysis, but verify `#[inline]` still applies across crate boundary (`pub(in crate::afxdp)` — same crate, so inlining is possible).

---

## Summary Table

| # | Location | Size | Issue | Class | Priority |
|---|----------|------|-------|-------|----------|
| 1 | `types/forwarding.rs:14` ForwardingState (65 fields) | 1054 LOC file, struct spans ~200 LOC | God-struct: hot FIB + cold config + NAT + filter + CoS interleaved in memory; no `#[repr]` | (C) hot-cold SoA split + (B) mechanical | High (perf + maintainability) |
| 2 | `neighbor.rs` | 2036 LOC | 4 responsibilities (probe, netlink-mgmt, monitor-thread, CPU-pinning) + 2 sibling files already split but still `use super::*` coupled | (B) mechanical directory split | Medium (at threshold, growing) |
| 3 | `forwarding_build/` | 8134 total (incl tests), 8 non-test files | Already well-decomposed in #1342; no further split needed | (D) NEGATIVE | None |
| 4 | `forwarding/mod.rs` | 2822 LOC, 68 fns, 5 over 100 LOC | 5 god-functions + mixed FIB/NAT/fabric/tunnel responsibilities | (B) mechanical file split | Medium (after #1) |

## Cross-Cutting Notes

### Hot-path preservation across all findings

| Path | Frequency | Must not |
|------|-----------|----------|
| `ForwardingState` FIB lookup (`lookup_forwarding_resolution_*_inner`) | Every session-miss packet (fast-path miss rate ~0.1% at steady-state, but burst on flow table churn) | Add branch, extra indirection, or non-inlined call |
| `ForwardingState.local_v*` + `local_tables_*` check | Every packet (pre-FIB local-delivery shortcut) | Add allocation or second hash lookup |
| `neighbors` map read | Every forwarded packet (egress resolution) | Add locking or `Arc` refcount bump per packet |
| `pending_neigh_admission` | Every packet to unresolved next-hop | Add allocation |
| `learn_dynamic_neighbor_from_packet` | Every ARP reply / NDP NA RX | Add branch in hot check |
| `trigger_kernel_arp_probe` | Per new unresolved next-hop (cold) | Add String allocation (already has one — iface name) |
| Worker tick (`worker_loop`) | ~1/s telemetry + ~1/s session GC | Add per-packet cost (tick is fine to touch more fields) |

### `worker/mod.rs` + `loop_body/mod.rs` — (D) Negative for this batch

`worker/mod.rs` (1625 LOC) has been heavily decomposed via #959 (11 sub-modules: `telemetry`, `scratch`, `cos_state`, `tx_counters`, `bpf_maps`, `timers`, `tx_pipeline`, `bind_meta`, `flow_cache_state`, `xsk_rings`, `cos`, `lifecycle`). `BindingWorker` struct holds 20+ fields but most are wrapped in named sub-structs. Remaining monolith smell is the struct field count, but each field has a distinct `Worker*` wrapper — further splitting would only add another level of indirection. `loop_body/mod.rs` (1776 LOC) was extracted in #1326 from `worker/mod.rs` and is the natural home for tick + GC + telemetry publish. Session reap (`reap_expired_sessions`, `count_local_session_expiries`, 80 + 40 lines) could move to its own file but is tightly coupled to `WorkerFlowCacheState`. Not a priority for this batch — mark as (D) for A1e.

### Dedup vs Other Audits

- **#4421 ForwardingState (55 fields)** — same struct; field count has grown to 65. This audit supersedes #4421's count (55 → 65) and adds hot/cold categorization + SoA proposal. If #4421 proposed a different split, align with that work — do not create a second competing split.
- **neighbor.rs (1901 LOC in prior audit)** — grown to 2036 LOC (netlink monitor additions, warmer). Prior audit may have noted `neighbor_resolver`/`neighbor_dispatch` as already extracted; this audit confirms they are genuine concern splits but still `use super::*` coupled to `neighbor.rs` with no shared-types leaf.
- **nat64.rs** — separate module, not in scope for this batch except via `ForwardingState.nat64` field. No dedup conflict.
- **worker/mod.rs and loop_body/mod.rs** — separate audit batch (likely A1f or A2). This audit marks them as (D) negative for A1e (forwarding/neighbor focus).

### Overall file-shape recommendation for A1e batch

```
Before:
  types/forwarding.rs        1054  (65-field god-struct + helpers)
  forwarding/mod.rs          2822  (68 free fns, 5 god-fns)
  forwarding/host_inbound.rs  817  (already OK)
  forwarding_build/mod.rs     687  (orchestrator — OK)
  forwarding_build/*.rs       2333  (7 files — OK)
  neighbor.rs                2036  (4 responsibilities + tests)
  neighbor_resolver.rs       1512  (resolver thread — genuine split)
  neighbor_dispatch.rs       1399  (pending-neighbor dispatch — genuine split)

After (proposed):
  types/
    forwarding.rs            ~400  (ForwardingState thin wrapper: fib: Arc<ForwardingFib> + cold fields)
    forwarding_hot.rs        ~300  (ForwardingFib: hot FIB-only, #[repr(C)], hot-fields-first)
    forwarding_types.rs      ~350  (ConnectedRouteV*, RouteEntryV*, TunnelEndpoint, NeighborEntry, etc.)
  forwarding/
    mod.rs                   ~150  (constants + re-exports)
    lookup.rs                ~900  (FIB lookup, route selection, ECMP)
    nat_local.rs             ~500  (NAT/interface-local session-miss handling)
    fabric_ha.rs              ~600  (fabric redirect, HA resolution, VRRP)
    tunnel_gre.rs            ~400  (tunnel outer MTU/MSS, GRE MTU)
    host_inbound.rs           817  (unchanged)
  forwarding_build/                 (unchanged — already clean)
  neighbor/
    mod.rs                    ~80  (re-exports + NeighborMsgEffect)
    types.rs                 ~150  (shared leaf types: NeighborEntry, GetOutcome, etc.)
    probe.rs                 ~350  (ARP/ND probe, ICMP craft)
    kernel.rs                ~500  (netlink neighbor mgmt, dump, parse)
    monitor.rs               ~400  (neigh_monitor_thread, CPU pinning)
    warmer.rs                ~200  (neighbor_warmer_loop)
    resolver.rs              1512  (moved from neighbor_resolver.rs)
    dispatch.rs              1399  (moved from neighbor_dispatch.rs)
    gc.rs                     ~100  (optional: pending_neigh + neg_neigh GC — cold tick)
```

### Labels

`refactor`, `modularity`, `god-struct`, `dcache`, `forwarding`, `neighbor`, `hot-path`, `performance-positive`, `mechanical-extraction`, `C-hot-cold-split`, `B-file-split`, `D-negative`

---

*Audit: 039 A1e — Forwarding / ForwardingState / neighbor / NAT resolution. Base: f7014695. Repo: /home/ps/git/avacado-xpf.*


---

## Findings from a1f (/ps-review-039-a1f.md)

## File-size / shape inventory (LOC via wc, prod est, responsibilities, hot-path)

| File | Total LOC | Prod LOC* | Test LOC | # fns | Largest fn | Resp count | Hot? | One-line read |
|------|-----------|-----------|----------|-------|------------|------------|------|----------------|
| screen/mod.rs | 1540 | ~1540 | 0 (tests in tests.rs) | 41 | `check_packet_with_zone_id_opts` 374 L | 7 | YES per-packet | ScreenState + 16-check orchestrator + SYN-flood aggregate/per-dst/per-src/alarm + SYN-cookie + ICMP/UDP flood + scan delegation + missing-profile WARN |
| screen/scan.rs | 1213 | ~592 | ~621 | 16 prod / 25 test | `ScanCore::check` 61 L prod; `slow_scan_survives_cleanup_beyond_...` 61 L test | 1 (generic) + 2 thin wrappers | COLD (new-flow only) | Generic ScanCore<T> + PortScanTracker + IpSweepTracker + bounded eviction + pressure alarm |
| afxdp/frame/inspect.rs | 1813 | ~1813 | 0 (inspect_tests.rs separate) | 44 | `parse_session_flow_from_bytes` 141 L | 6 | YES per-packet (meta fast-path + fallback) | L2 VLAN parse + L3 declared-end + IPv6 EH walker ×5 + fragment predicates ×6 + flow-port parse + ICMP ident gate + TermMatchExtra ×3 + SessionFlow parse ×4 + fabric ingress + metadata parse |
| afxdp/frame/mod.rs | 1710 | ~1710 | 0 (tests.rs separate) | 27 | `verify_built_frame_checksums` 192 L (debug-only) / `rewrite_apply_v4` ~133 L prod | 6 | YES per-packet (rewrite + NAT) | In-place VLAN descriptor trick + NAT v4/v6 + port/ICMP-id rewrite + enforce_expected_ports + restore L4 tuple + NAT64 + inject + DSCP + checksum-verify |
| afxdp/frame/wg.rs | 1561 | ~604 | ~957 | 12 prod / 26 test | `wg_encap_frame` 253 L prod | 2 (MTU guard + encap) | YES per-packet (WG transit) | WG outer-MTU physical egress resolution + WG encap (encrypt-in-place) + per-peer LPM |
| afxdp/types/runtime.rs | 503 | 503 | 0 | 13 | `WorkerContext` struct (not fn) / `MirrorTargetMap::insert` 20 L | 5 | NO (plumbing) | WorkerHandle + Tunnel entry structs (GRE/WG lifecycle) + BindingPlan + SharedUmem + HA lease + Debug counters + WorkerContext/TelemetryContext |

\*Prod LOC estimated by stripping `mod *_tests { … }` / `mod tests { … }` blocks. Single-line `#[cfg(test)]` re-exports counted as prod (1-2 L).

### Test-heavy vs prod-heavy

- **Test-heavy (LOC inflated, not a monolith finding):** `screen/scan.rs` (51 % test), `afxdp/frame/wg.rs` (61 % test). Prod 592 L / 604 L respectively, both under modularity threshold. Tests are valuable (fail-on-revert bounds documented in scan.rs header, WG outer-MTU/source byte-identity tests). Do not count toward monolith ranking.
- **Prod-heavy (real monolith candidates):** `screen/mod.rs` (100 % prod in this file, tests live in screen/tests.rs 5395 L), `frame/inspect.rs` (100 % prod, tests in inspect_tests.rs 517 L), `frame/mod.rs` (100 % prod, tests in tests.rs 8290 L). These are the files whose LOC is genuine production logic.

---

## Comparison to prior refactor issues (#4404–#4409, #4421)

| Prior issue | Module | Overlap with A1f? |
|-------------|--------|-------------------|
| #4404–#4409 generic monolith sweep | unspecified, listed examples: policy.rs, SessionTable, ForwardingState | No. SessionTable lives in `session/mod.rs`, ForwardingState in `types/forwarding.rs`. Neither in A1f scope. |
| #4421 monolith list | policy.rs, nat64.rs, neighbor.rs, SnapshotIntegrityError, SessionTable, ForwardingState, flowexport, firewall-filter, rules.go | **No overlap.** Explicitly lists `policy.rs, nat64.rs, neighbor.rs, SnapshotIntegrityError, SessionTable, ForwardingState, flowexport, firewall-filter, rules.go — not screen/frame`. This report is first to audit `screen/mod.rs` 16-check fusion and `frame/inspect.rs` 1813 L. |
| scan.rs / wg.rs test-heavy pattern | — | No prior finding calls out scan.rs 1213 L or wg.rs 1561 L test inflation; new inventory documents it as non-issue. |

**Dedup verdict:** No finding below duplicates a prior issue. Findings 1–4 are new.

---

## Findings

### Finding 1 — screen/mod.rs: `check_packet_with_zone_id_opts` is a 374-line god-function fusing 5 SYN-flood sub-systems

- **Title:** `ScreenState::check_packet_with_zone_id_opts` fuses 5 SYN-flood enforcement phases + flood + SYN-cookie + fabric skip into one function
- **Severity:** Medium (readability, review-cost, incremental rebuild under threshold but trending upward)
- **Confidence:** High
- **Refactor class:** (B) REQUIRES GUARDRAILS — hot path (per-packet every packet screened), but split is safe via `#[inline(always)]` helpers

**Evidence (file:line, LOC, quote):**

- `userspace-dp/src/screen/mod.rs:777-1150` — 374 LOC function (`check_packet_with_zone_id_opts`):
  ```rust
  pub fn check_packet_with_zone_id_opts(
      &mut self,
      zone: &str,
      zone_id: u16,
      pkt: &ScreenPacketInfo,
      now_ns: u64,
      now_secs: u64,
      skip_rate_flood: bool,
  ) -> ScreenVerdict {
      let Some(profile) = self.profiles.get(zone) else { ... };
      // --- Stateless checks ---
      if let Some(reason) = stateless::check_land(profile, pkt) { ... }
      if let Some(reason) = stateless::check_tcp_flag_screens(profile, pkt) { ... }
      if let Some(reason) = stateless::check_ping_of_death(profile, pkt) { ... }
      ...
      if skip_rate_flood { return ScreenVerdict::Pass; }
      // ICMP flood — per-dest + aggregate
      if icmp_flood_threshold > 0 && ... { self.icmp_flood_drop(...) }
      // UDP flood — per-dest (ip+port) + aggregate
      // SYN flood: count TCP SYN (without ACK) per zone.
      if syn_flood_threshold > 0 && pkt.protocol == PROTO_TCP {
          let tf = pkt.tcp_flags;
          if is_initial_syn(tf) {
              let profile_gen = self.syn_cookie_profile_gen(zone);
              let syn_cookie_validated = syn_cookie && self.syn_cookie_validated.take_valid(...);
              // (1) Aggregate dual-threshold in a SINGLE window advance
              let (over_attack, over_alarm) = self.syn_counters.get_mut(zone).map(|c| c.increment_and_classify(...));
              // (2) per-DESTINATION cap — PRIMARY, before aggregate early-return
              if syn_dst_threshold > 0 && sketch.increment(&pkt.dst_ip, ...) { return Drop }
              // (3) aggregate over-attack verdict — SYN-cookie challenge or TokenBucket drop
              if syn_cookie { if over_attack { ... mint_isn ... return SynCookieChallenge } }
              else if bucket.admit_is_over(...) { return Drop }
              // Alarm-threshold crossed but below attack
              if syn_alarm_threshold > 0 && over_alarm && !over_attack { ... }
              // (4) per-SOURCE cap — SECONDARY, skipped while cookie-active
              if syn_src_threshold > 0 && !cookie_active && sketch.increment(&pkt.src_ip, ...) { return Drop }
          }
      }
  ```
- Same file `check_flowless_screens_opts:1170-1256` 104 L duplicates missing-profile / stateless / ICMP-flood / UDP-flood / fabric-skip logic (near-copy with `addrs_known` guard).
- `ScreenState` struct `mod.rs:162-289` 127 L struct with 22 fields fusing 7 responsibilities:
  ```rust
  pub(crate) struct ScreenState {
      profiles: FxHashMap<String, ScreenProfile>,
      icmp_counters: FxHashMap<String, TokenBucket>,
      udp_counters: FxHashMap<String, TokenBucket>,
      syn_counters: FxHashMap<String, RateCounter>,
      syn_off_attack_buckets: FxHashMap<String, TokenBucket>,
      icmp_dst_sketch: FxHashMap<String, SynRateSketch>,
      udp_dst_sketch: FxHashMap<String, SynRateSketch>,
      syn_cookie_active_until_secs: FxHashMap<String, u64>,
      syn_cookie_standby_ack_counters: FxHashMap<String, TokenBucket>,
      syn_cookie_codec: Option<SynCookieCodec>,
      syn_cookie_validated: SynCookieValidatedCache,
      syn_cookie_profile_gen: FxHashMap<String, u64>,
      // ... + scan/sweep trackers + missing-profile maps + alarm maps
  }
  ```

**Responsibility count:** 7 fused in one struct, 5 enforcement phases in one fn (icmp_flood, udp_flood, syn aggregate, syn per-dst, syn per-src, syn alarm, syn-cookie mint). Stateless checks are already extracted to `stateless.rs` (263 L) — good. Rate checks `icmp_flood_drop` / `udp_flood_drop` are helper fns (34 L / 48 L) — good. But SYN-flood sub-thresholds (#3315, #4112 F19 enforcement order) all live inline in the 374 L fn.

**Prod LOC:** 1540 total, all prod (tests external). Largest fn 374 L. Well under 2000 LOC modularity threshold today, but trending toward it; the SYN-flood block alone is 180 L of the 374 L and has changed 8 times (comments reference #3315, #3607, #4112 F18/F19, #4155, #2446, #3032). Next feature addition will push file over threshold per engineering-style "Refactor with new features, not after."

**Proposed decomposition (new modules + what moves + seam):**

- `screen/syn_flood.rs` — new file, ~220 L:
  - `fn syn_flood_check(state: &mut ScreenState, zone, zone_id, pkt, now_ns, now_secs, syn_profile_slice) -> Option<ScreenVerdict>` — extracts lines 922-1079.
  - `fn syn_flood_profile_slice` helper to copy the 6 scalar thresholds out of profile (current lines 854-869) so borrow discipline preserved.
  - Keeps `syn_flood_dst_drops`/`src_drops` counter bumps inside this module (co-located with increment sites).
  - Re-uses existing `SynRateSketch`, `RateCounter`, `TokenBucket`, `SynCookieCodec`, `SynCookieValidatedCache` — no new types.
- `screen/flood.rs` (optional, mechanical) — `icmp_flood_drop` / `udp_flood_drop` move from mod.rs (currently 82 L combined) into dedicated file so mod.rs orchestrator only holds dispatch.
- `screen/missing_profile.rs` — `missing_profile_refs`, `missing_profile_warn_counters`, `maybe_warn_missing_profile`, `update_missing_profiles` (currently ~70 L including constants). Cold path, easy win.
- Result: `mod.rs` shrinks from 1540 → ~900 L (struct def + update_profiles + flowless + scan delegation + SYN-cookie ACK validation + public seams). Orchestrator `check_packet_with_zone_id_opts` becomes:
  ```rust
  stateless::run_all(profile, pkt)?;  // already extracted
  if skip_rate_flood { return Pass; }
  if let Some(v) = flood::icmp_udp_checks(self, zone, pkt, ...) { return v; }
  if let Some(v) = syn_flood::check(self, zone, zone_id, pkt, ...) { return v; }
  ```

**Hot-path preservation analysis (which apply + how to verify):**

- **Inlining:** `syn_flood_check` must be `#[inline(always)]` and take `&mut ScreenState` (not boxed). LLVM cross-module inlining in same crate is free for `pub(crate)` fns; verify via `cargo rustc -- --emit=llvm-ir | grep check_packet_with_zone_id_opts` shows no `call syn_flood_check` (inlined). Prior art: `stateless::check_*` are `#[inline]` and verified inlined per file comment "Hot-path discipline: every helper is #[inline]".
- **Alloc:** No new alloc — existing FxHashMap lookups stay same. `syn_flood_profile_slice` is 6 scalars on stack.
- **Dispatch:** No new trait object; enum `ScreenVerdict` dispatch unchanged.
- **Branch prediction:** Splitting into `#[inline]` helpers does not add branches; early-return pattern identical. SYN-flood threshold zero check `syn_flood_threshold > 0` stays at caller (same as today) so non-SYN packet pays one predictable branch and skips entire sub-module.
- **Layout:** `ScreenState` remains one struct in mod.rs, fields not moved; only methods extracted. No layout change.
- **Lock:** None (worker-owned, single-threaded). The `FxHashMap::get_mut` borrow pattern preserved — helper takes `&mut ScreenState` but does not hold `self.profiles` borrow across calls (scalars copied before call, same as today lines 854-869).

**Tests+gate:**

- Existing: `cargo test -p userspace-dp screen` (includes `scan_tests`, `syn_flood` alarm/dst/src attribution tests `syn_flood_dst_drops`, `syn_flood_src_drops`, `syn_flood_alarm_events`). Must stay green.
- `make test` (Go + Rust suite) — dataplane regression fails whole `make test` per CLAUDE.md.
- Deploy validation: `make test-deploy` ping + iperf before/after; screen logic is per-packet drop so iperf baseline should not shift (≥ 23 Gbit/s, no regression).
- New gate: `cargo asm --lib screen::ScreenState::check_packet_with_zone_id_opts` diff before/after must show only symbol-name shift (no extra `call`).

**Why it matters:** The 374 L function is the #1 reviewer bottleneck for SYN-flood changes. 8 of the last 12 screen bug-fixes touched this function (#3315 sub-thresholds, #3607 token-bucket migration, #4112 per-dst primary, #4155 fabric skip, #2446 profile gen, #3032 epoch cache, #3082 missing-profile, #4567 fragment fold). Each fix risked regressing an unrelated SYN-flood phase because phases share mutable `&mut self` and `profile` borrow. The 2013→2026 comment archaeology inside this one function (lines 903-921 doc block 18 lines explaining enforcement order) proves the function has become a spec document, not code.

**Fix direction (ordered PRs):**

1. PR A1f-1a (mechanical): Extract `missing_profile.rs` (cold path, no hot-path risk, trivial review).
2. PR A1f-1b (mechanical): Extract `flood.rs` (`icmp_flood_drop` + `udp_flood_drop`) — helpers already isolated, just file move.
3. PR A1f-1c (guardrailed): Extract `syn_flood.rs` — 180 L SYN block, needs inline verification + `cargo test screen` + deploy check. Keep `#[inline(always)]`, verify inlining, run full screen test suite.

**Labels:** `refactor`, `screen`, `hot-path`, `modularity`, `B-requires-guardrails`

**Dedup note:** No prior finding covers screen/mod.rs 16-check fusion or SYN-flood god-function. #4421 lists 8 Go/Rust modules — none is screen/. A1f is first audit of this file.

---

### Finding 2 — afxdp/frame/inspect.rs: IPv6 extension-header walker duplicated 5× (1813 L, 6 responsibilities)

- **Title:** IPv6 extension-header chain walk duplicated across 5 functions with diverging EH-type sets, plus 3× `term_match_extra` and 4× `SessionFlow` parsers sharing near-identical fragment/declared-end guards
- **Severity:** Medium (correctness drift risk; #4517 / #4435 fixes had to touch 5 sites; next EH-type addition will miss one)
- **Confidence:** High
- **Refactor class:** (B) REQUIRES GUARDRAILS — hot path (per-packet L4 offset, fragment classification, session flow). Walker must stay branchless/alloc-free and `#[inline(always)]`.
- **Project rule violated (if refactor NOT done):** Engineering-style "One source of truth for every formula" + "No monolithic files" (1813 L, approaching 2000 threshold).

**Evidence (file:line, LOC, quote 5-10 lines showing seam):**

- `frame/inspect.rs:72-132` `frame_l4_offset` — 61 L IPv6 walker:
  ```rust
  pub(in crate::afxdp) fn frame_l4_offset(frame: &[u8], addr_family: u8) -> Option<usize> {
      let l3 = frame_l3_offset(frame)?;
      ...
      let mut protocol = *frame.get(l3 + 6)?;
      let mut offset = l3 + 40;
      for _ in 0..MAX_IPV6_EXT_HEADERS {
          match protocol {
              0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => { let opt = frame.get(offset..offset+2)?; protocol = opt[0]; offset = offset.checked_add((usize::from(opt[1])+1)*8)?; ... }
              51 => { ... (len+2)*4 ... }
              44 => { let frag = frame.get(offset..offset+8)?; protocol = frag[0]; offset+=8; ... }
              59 => return None, _ => return Some(offset),
          }
      } None
  }
  ```
- `inspect.rs:192-260` `packet_rel_l4_offset_and_protocol` — 68 L near-identical walker (same `0|43|60|135|139|140|253|254`, `51`, `44`, `59`, `MAX_IPV6_EXT_HEADERS`, returns `(offset, protocol)` instead of `offset`).
- `inspect.rs:461-590` `term_match_extra_from_frame` 69 L + `term_match_extra_from_frame_fwd` 50 L + `term_match_extra_from_meta` 30 L — 3 variants of firewall-filter match-input builder, each duplicating non-first-fragment + icmp-truncation guards.
- `inspect.rs:1264-1402` `parse_session_flow_from_bytes` 141 L + `parse_session_flow_from_frame` ~60 L + `parse_ipv4_session_flow_from_frame` 70 L + `parse_session_flow_from_meta` 30 L — 4 SessionFlow parsers, each duplicating `frame_is_non_first_fragment` / `meta_icmp_identifier_bearing` / `metadata_tuple_complete` / `declared_end` / `parse_flow_ports` guards.

Walker divergence history proves risk:
- #4517 fix (add Mobility/HIP/Shim6/253/254 to generic EH set) had to touch `frame_l4_offset`, `packet_rel_l4_offset`, `packet_rel_l4_offset_and_protocol`, `ipv6_is_non_first_fragment`, `ipv6_is_any_fragment` — 5 sites. Miss one = IDS evasion (`HOP → MOBILITY → FRAGMENT → TCP` stops at MOBILITY, `is_fragment` stays false, SYN-flood/ teardrop miss).
- #4435 raised `MAX_IPV6_EXT_HEADERS` bound from 6 to 8, exposed as `pub(crate)` so `crate::nat64` shares it. Needed a crate-wide grep to find all private walkers.
- Comments in inspect.rs:1-8, :15-31, :33-54, :55-67 are duplicated EH-type tables (same 8-line `0|43|60|135|...` set repeated 4 times with copy-pasted doc comments). Next EH type (e.g., experimental 253/254 already added once) will require N-site edit.

**Prod LOC:** 1813 L, 44 fns. Second-largest file in A1f batch. Already split from frame/mod.rs per #988 (phase 2), but grown back to 1813 L via successive fixes.

**Proposed decomposition (new modules + what moves + seam):**

- `frame/inspect/` directory (replace single file):
  - `frame/inspect/mod.rs` — `pub(crate) const MAX_IPV6_EXT_HEADERS`, re-exports, `frame_l3_offset` (L2 VLAN), `declared_l3_end` / `ipv4_declared_l3_end` / `ipv6_declared_l3_end`, `try_parse_metadata`, `decode_frame_summary` (~400 L total).
  - `frame/inspect/ext.rs` — **single** EH walker: `#[inline(always)] fn walk_ipv6_ext_headers(packet: &[u8], start_offset: usize, initial_protocol: u8, max: usize) -> Option<(usize, u8, Option<FragmentInfo>)>` returning final l4 offset, protocol, optional fragment info. All 5 call sites become thin wrappers: `frame_l4_offset` → `walk(...).map(|(off,_,_)| off)`, `packet_rel_l4_offset_and_protocol` → `walk(...)`. The EH-type match arm `0|43|60|135|139|140|253|254`, `51`, `44`, `59` lives in exactly one place. Next EH addition = one edit.
  - `frame/inspect/frag.rs` — `ipv4_is_non_first_fragment`, `ipv6_is_non_first_fragment`, `ipv4_is_any_fragment`, `ipv6_is_any_fragment`, `is_non_first_fragment`, `is_any_fragment` (6 fns, ~150 L). Reuses `walk_ipv6_ext_headers` for IPv6 arms instead of duplicating walker again.
  - `frame/inspect/flow.rs` — `parse_session_flow_from_bytes`, `parse_session_flow_from_frame`, `parse_ipv4_session_flow_from_frame`, `parse_session_flow_from_meta`, `l3_session_flow_from_meta`, `parse_flow_ports`, `icmp_identifier_bearing`, `meta_icmp_identifier_bearing`, `parse_packet_destination_from_frame`, `parse_zone_encoded_fabric_ingress` (~500 L). Shared helpers `declared_end`, `frame_l4_offset` imported from mod.rs.
  - `frame/inspect/filter.rs` — `term_match_extra_from_frame`, `term_match_extra_from_frame_fwd`, `term_match_extra_from_meta` (3 variants, ~150 L), `source_is_invalid_for_icmp_error`, `dest_is_multicast_or_broadcast`, `dest_is_directed_broadcast`, `src_is_directed_broadcast`, `l2_dst_is_group_or_broadcast`, `neighbor_ip_is_learnable` (~200 L).

Result: `inspect/mod.rs` ~400 L, each sub-file 150-500 L, walker in one place, no file over 600 L. Existing `frame/inspect_tests.rs` split into `inspect/ext_tests.rs`, `inspect/flow_tests.rs` etc. per modularity discipline.

**Hot-path preservation analysis:**

- **Inlining:** Walker `walk_ipv6_ext_headers` must be `#[inline(always)]`. Current 5 walkers are already `#[inline]` or `#[inline]`-adjacent fns called from per-packet `parse_session_flow_from_bytes` / `frame_l4_offset` (both on TX hot path). Splitting into separate module does not inhibit inlining — same crate, `pub(crate)`, `#[inline(always)]`. Verify via `cargo asm afxdp::frame::inspect::frame_l4_offset` shows no `call walk_ipv6_ext_headers`.
- **Alloc:** Zero — walker operates on `&[u8]` slices, no Vec/Box. New `FragmentInfo` is 2×u8 stack struct.
- **Branch prediction:** EH walker is cold for 99 % packets (no EH). First iteration `match protocol { 6|17|... => return Some(offset) }` is predictable not-taken for typical TCP/UDP. Extracting to shared walker does not add branches; removes 4 duplicate branch tables from I-cache (improves I-cache pressure — C-PERFORMANCE-POSITIVE).
- **Locality:** New files in same `frame/inspect/` directory, same crate, same codegen unit (`--codegen-units=1` in release). No cross-crate call.
- **Dispatch:** No dynamic dispatch; enum `SessionFlow` / `TermMatchExtra` remain stack.

**Tests+gate:**

- `cargo test -p userspace-dp frame::inspect` + `frame::inspect_tests` (517 L) must stay green. Property tests in `frame::prop_tests` (no-panic / parse bounds) must stay green.
- Existing `MAX_IPV6_EXT_HEADERS` 8-way EH-type parity is pinned by `#4517` regression test (Mobility → Fragment → TCP chain). Must add new test: walker returns same result for all 5 wrapper fns on same frame with Mobility/HIP/Shim6.
- Gate: `cargo asm` diff on `parse_session_flow_from_bytes` — no extra `call` after split.

**Why it matters:** 5 duplicate EH walkers is a proven drift surface — #4517 had to fix 5 sites, #2292 had to fix 2 sites (6→8 bound), #4435 had to expose constant crate-wide. Next IANA EH-type (or bug in AH length math `(len+2)*4` vs `(len+1)*8`) will again require N-site edit and will be missed. The EH-type set is a security invariant (IDS evasion if walker stops early — `HOP → MOBILITY → FRAGMENT → TCP(SYN)` must reach TCP). Centralizing to one walker is the only defensible posture.

**Fix direction (ordered PRs):**

1. PR A1f-2a (mechanical, safe): Create `frame/inspect/ext.rs` with single walker, rewire 5 call sites to thin wrappers, no behavior change. Verify `cargo test` + `cargo asm` inlining.
2. PR A1f-2b (mechanical): Create `frame/inspect/frag.rs` extracting 6 fragment predicates, reusing new walker.
3. PR A1f-2c (mechanical): Create `frame/inspect/flow.rs` + `filter.rs` splitting SessionFlow / TermMatchExtra builders. Keep `mod.rs` re-exports so external `use frame::inspect::*` paths unchanged.

**Labels:** `refactor`, `frame`, `ipv6`, `eh-walker`, `modularity`, `B-requires-guardrails`

**Dedup note:** No prior finding calls out IPv6 EH walker duplication or inspect.rs 1813 L monolith. Prior frame refactors (#988 phase 2, #989 TCP split, #1046 TSO, #1352 build/rewrite, #1440 headers) are referenced in file headers as completed steps; this finding is the next step (EH walker unification).

---

### Finding 3 — afxdp/frame/mod.rs: NAT rewrite + VLAN descriptor trick + verify + inject + NAT64 fused (1710 L)

- **Title:** `frame/mod.rs` fuses in-place VLAN descriptor-shift, NAT v4/v6, port/ICMP-id rewrite, NAT64, injected-packet build, and checksum-verify into one file
- **Severity:** Low-Medium (readability, incremental build, but already partially decomposed)
- **Confidence:** High
- **Refactor class:** (A) MECHANICAL/SAFE — all candidates are cold or non-hot helper fns, already marked `#[inline]` or called from cold paths (inject, NAT64, verify is debug-only)

**Evidence:**

- `frame/mod.rs:1-1710` — file header `use super::*; mod byte_writes; mod checksum; mod generated; mod headers; mod inspect; mod tcp; mod wg; mod tcp_segmentation; mod build; mod rewrite;` — 9 sub-modules already extracted, yet mod.rs itself still 1710 L (largest in batch).
- `mod.rs:439-596` — `RewritePrep`, `RewriteEthParams`, `descriptor_view_in_same_umem_frame`, `classify_in_place_l2_rewrite`, `rewrite_prepare_eth_from_parts`, `rewrite_prepare_eth` — 157 L VLAN descriptor-shift logic (retrying TX offset to avoid VLAN push/pop memmove via AF_XDP descriptor view). Single responsibility: avoid 1500-byte `memmove` on common cross-NIC VLAN-transition path. Could live in `frame/rewrite/vlan.rs`.
- `mod.rs:598-720` — `rewrite_apply_v4`, `rewrite_apply_v6` — 122 L NAT+TTL+checksum per-family wrappers, each computing `non_first_fragment`, `repaired_ports`, `apply_nat_*`, TTL decr, `adjust_ipv4_header_checksum`, `enforce_expected_ports`. Share `non_first_fragment` threading pattern with `frame/inspect.rs` fragment predicates.
- `mod.rs:851-937` — `apply_nat_ipv4` 87 L, `apply_nat_ipv6` 215 L, `apply_nat_port_rewrite` 64 L, `apply_nat_icmp_identifier_rewrite` 44 L, `adjust_l4_checksum_port` 28 L — 438 L NAT subsystem (5 fns). Already cohesive but co-located with VLAN/rewrite-prep/verify/inject.
- `mod.rs:228-328` — `build_nat64_forwarded_frame` + `apply_nat64_port_translation` — 100 L NAT64 translator (address family changes size, always copy path). Could live in `frame/nat64.rs` alongside `crate::nat64` module.
- `mod.rs:206-226` / `1391-1507` — `build_injected_packet`, `build_injected_ipv4`, `build_injected_ipv6` — ~140 L test-packet injection (cold path, `InjectPacketRequest`).
- `mod.rs:1519-1698` — `verify_built_frame_checksums` 192 L — debug-only (`#[cfg(feature="debug-log")]` + runtime `cfg!(feature="debug-log")` check), TLs `CSUM_VERIFY_COUNT`, `CSUM_BAD_*` statics, `eprintln!` on mismatch. Should be `frame/debug.rs` or `frame/verify.rs` gated behind feature.
- `mod.rs:413-437` — `RewritePrep` struct + `RewriteEthParams` struct — VLAN+NAT rewrite context structs, could be in `frame/rewrite/prep.rs`.

**Responsibility count:** 6 (VLAN descriptor-shift, NAT v4/v6, port/ICMP-id rewrite, NAT64 transcode, inject, debug-verify). File already decomposed 9 ways but remaining 1710 L is the "kitchen sink" of rewrite-leaf helpers that should live in `frame/rewrite/` or dedicated files.

**Proposed decomposition:**

- `frame/rewrite/prep.rs` — `RewritePrep`, `RewriteEthParams`, `descriptor_view_in_same_umem_frame`, `classify_in_place_l2_rewrite`, `rewrite_prepare_eth_from_parts`, `rewrite_prepare_eth` (VLAN descriptor-shift, 160 L).
- `frame/nat.rs` — `apply_nat_ipv4`, `apply_nat_ipv6`, `apply_nat_port_rewrite`, `apply_nat_icmp_identifier_rewrite`, `adjust_l4_checksum_port` (NAT subsystem, 438 L). Already `pub(in crate::afxdp::frame)` / `pub(super)` with clear boundaries; move verbatim, re-export via `pub use nat::*` in mod.rs.
- `frame/nat64_fwd.rs` (or `frame/build/nat64.rs`) — `build_nat64_forwarded_frame`, `apply_nat64_port_translation` (NAT64 copy-path builder, 100 L).
- `frame/inject.rs` — `build_injected_packet`, `build_injected_ipv4`, `build_injected_ipv6` (cold inject path, 140 L).
- `frame/verify.rs` — `verify_built_frame_checksums`, `CSUM_VERIFIED_TOTAL`, `CSUM_BAD_*`, `IP_LEN_MISMATCH_LOG` (debug-only, 192 L, `#[cfg(feature="debug-log")]`).
- Result: `mod.rs` shrinks from 1710 → ~300 L (re-exports + `build_forwarded_frame_from_frame` wrapper + `rewrite_forwarded_frame_in_place` orchestrator + `v6_rel_l4_offset` + `apply_dscp_rewrite_to_frame`).

**Hot-path preservation:**

- **Inlining:** `apply_nat_ipv4`/`apply_nat_ipv6` are already called from `rewrite_apply_v4`/`rewrite_apply_v6` which are `#[inline]`. Moving to `frame/nat.rs` same crate preserves inlining (LLVM cross-module inlining within same crate is free). `apply_nat_port_rewrite` / `apply_nat_icmp_identifier_rewrite` are `#[inline(always)]` — must keep attribute after move.
- **Alloc:** Zero new alloc — all operate on `&mut [u8]` in-place. No Vec/Box introduced.
- **Dispatch/layout:** No layout change, no new trait objects. Function signatures unchanged.
- **Lock:** None.
- **Verify:** `cargo test frame` must stay green; `cargo asm afxdp::frame::rewrite_apply_v4` diff must show same inline expansions (no new `call` to `apply_nat_ipv4`).

**Tests+gate:**

- `cargo test -p userspace-dp frame` (includes `frame::tests` 8290 L, `frame::tcp_tests`, `frame::checksum`, `frame::headers_tests`, `frame::prop_tests`).
- NAT64 end-to-end: `crate::nat64::build_nat64_*` tests already cover address translation; this move only relocates the caller wrapper.
- Inject path: cold, exercised by `inject_test_packet` integration test (if any) + unit tests.

**Why it matters:** File is 1710 L but 80 % of it is stable leaf helpers that have not changed in 6 months except for bug-fixes that had to wade through unrelated verify/inject/NAT64 code. Example: #1852 (non-first-fragment NAT gate) touched `apply_nat_ipv4`/`apply_nat_ipv6` but reviewer had to read past 192 L `verify_built_frame_checksums` + 140 L inject builders + 100 L NAT64 to find the 10 L diff. Splitting reduces review cost and incremental rebuild time (`frame/mod.rs` currently recompiles on any rewrite-leaf edit, invalidating all 9 sub-modules that depend on it via `use super::*`).

**Fix direction (ordered PRs):**

1. PR A1f-3a (A): Extract `frame/verify.rs` (debug-only, zero risk).
2. PR A1f-3b (A): Extract `frame/inject.rs` (cold path, zero hot-path risk).
3. PR A1f-3c (A): Extract `frame/nat.rs` (NAT subsystem, needs inlining verification).
4. PR A1f-3d (A): Extract `frame/rewrite/prep.rs` (VLAN descriptor-shift, needs careful `InPlaceL2Rewrite` enum move).
5. PR A1f-3e (A): Extract NAT64 forwarder to `frame/nat64_fwd.rs`.

**Labels:** `refactor`, `frame`, `nat`, `vlan`, `modularity`, `A-mechanical-safe`

**Dedup note:** Prior frame decomposition PRs (#988 inspect, #989 tcp, #1046 tcp_segmentation, #1352 build/rewrite, #1440 headers) are completed and referenced in file header; this finding is the next tranche (NAT + VLAN + verify + inject + NAT64). Does not overlap #4421 (which lists nat64.rs — the `crate::nat64` translator, not `frame/mod.rs` NAT helpers).

---

### Finding 4 — Negative findings: scan.rs, wg.rs, runtime.rs are NOT monoliths

- **Title:** (D) DO-NOT-SPLIT — `screen/scan.rs`, `afxdp/frame/wg.rs`, `afxdp/types/runtime.rs` are well-decomposed or test-heavy; splitting would hurt
- **Severity:** N/A (informational)
- **Confidence:** High
- **Refactor class:** (D) DO-NOT-SPLIT

**Evidence:**

**`screen/scan.rs` — 1213 L total, 592 L prod — NOT a monolith:**

- Structure `scan.rs:1-238` module doc (98 L explaining bounds, eviction, cleanup, fail-closed posture — valuable, not bloat).
- `ScanCore<T>` generic `scan.rs:216-480` 264 L single source of truth for bounded windowed-unique tracker — comment at line 209-214 explicitly calls out "one source of truth" discipline:
  ```rust
  /// Shared bounded windowed-unique tracker core (#2209/#2227/#2234). Both
  /// the port-scan (`T = u16`) and IP-sweep (`T = IpAddr`) trackers are thin
  /// `T`-specialised wrappers over this single implementation so the bound /
  /// eviction / pressure logic exists in exactly ONE place (engineering-style
  /// "one source of truth" — the pre-#2234 free functions duplicated the
  /// formula across the two trackers).
  ```
- `PortScanTracker` `scan.rs:484-535` 51 L thin wrapper, `IpSweepTracker` `scan.rs:538-590` 52 L thin wrapper — total 103 L for both, zero duplication.
- `scan.rs:592-1213` 621 L test module `mod scan_tests` — 18 tests including fail-on-revert tests (`slow_scanner_survives_decoy_flood_eviction`, `fresh_scanner_tracked_and_detected_after_saturation`, `slow_scan_survives_cleanup_beyond_five_min_cap`) that pin the 4 evasion fixes (#2234 bounded eviction, #4418 least-suspicious, #4379 window-aware cleanup, #4114 fixed-count). These tests are co-located per project pattern ("per-file mod tests blocks are the project pattern; see tx/ and cos/ layouts").
- Prod 592 L under 2000 threshold, single responsibility (bounded windowed-unique tracker), already generic. Splitting `ScanCore` from its wrappers would add file indirection for 103 L wrappers with no benefit.

**`afxdp/frame/wg.rs` — 1561 L total, 604 L prod — NOT a monolith (test-heavy):**

- Prod `wg.rs:1-604` 604 L: 6 small helpers (`pad_to_16` 4 L, `wg_encapped_size` 6 L, `outer_physical_egress_ifindex` 45 L, `outer_physical_egress_mtu` 15 L, `wg_peer_outer_dst` 42 L, `wg_endpoint_physical_outer_mtu` 22 L) + `wg_encap_frame` 253 L + 2 checksum fns (20 L + 6 L) + re-exports. Well under threshold.
- Tests `wg.rs:604-1561` 957 L — 15 tests including `outer_mtu_uses_physical_egress_not_tunnel_logical`, `outer_source_uses_physical_egress_not_tunnel_logical`, `wg_encap_in_place_matches_separate_buffer`, `wg_encap_frame_resolves_outer_route_once_v4` (#3992 dedup), `udp6_checksum_matches_scalar_reference` (AVX2 vs scalar parity). These tests are valuable per-file `mod tests` blocks (have to access `pub(super)` helpers like `outer_physical_egress_ifindex`, `OUTER_ROUTE_RESOLVE_COUNT` that are crate-privileged). Splitting tests to separate file would require widening visibility of `outer_physical_egress_ifindex` from `pub(super)` to `pub(crate)` (exposing internal MTU helper to whole crate) — worse encapsulation.
- `#3992` dedup (single FIB LPM per packet) is already done — `wg_encap_frame` resolves outer route once and threads `physical_egress_ifindex` + `egress` row through MTU guard and source lookup. No leftover duplication.
- Splitting prod 604 L into `wg/mtu.rs` + `wg/encap.rs` would create 2 files of 200 L / 350 L with tight coupling (both need `outer_physical_egress_ifindex`, `established_initiator_engine` fixture). Not worth it today. Revisit if WG multi-peer MTU selection grows past 1000 L prod.

**`afxdp/types/runtime.rs` — 503 L — NOT a monolith:**

- 503 L total, 13 type definitions, largest struct `WorkerContext` 38 fields but it's a parameter-cluster struct (all `&'a` references) for `poll_binding_process_descriptor` — tracked as #961 (parameter smell, not scope of A1f). File is pure relocation per header comment (Issue 68.4) — types extracted from `afxdp/types/mod.rs` into dedicated file. Already decomposed; splitting further (e.g., `WorkerHandle` into `worker.rs`, `BindingPlan` into `binding.rs`) would create 5 files of ~100 L each with circular imports (all need `super::*` for `ForwardingState`, `SessionFlow`, etc.).
- Responsibilities: WorkerHandle + tunnel handles (GRE/WG lifecycle) + HAGroupRuntime + BindingPlan + SharedUmem + ValidationState + ResolutionDebug + LearnedNeighborKey + WorkerCommand + DebugPollCounters + WorkerContext/TelemetryContext + MirrorTargetMap. 5 responsibilities but total 503 L — well under threshold. Engineering-style says "By the time it hits ~3,000 LOC the next change to that file should split it" — this file is 503 L, 1/6 of threshold.
- `WorkerContext` 16-field struct is the standing example `poll_binding_process_descriptor` 15-param smell (#961) — but that's a function signature issue in `afxdp.rs`, not a file-size issue in `runtime.rs`. Tracked separately.

**Why DO-NOT-SPLIT:** Splitting a 592 L / 604 L / 503 L file that is already well-decomposed (generic core + thin wrappers, prod/test separation, single-responsibility per helper) adds file indirection, widens visibility (private → pub(crate)), and increases reviewer cognitive load (must chase 3 files instead of 1) for zero LOC reduction on hot path. The project's modularity discipline is "No monolithic files" (~2000 LOC threshold) — these files are 1/3 of threshold. For test-heavy files, the LOC count is misleading; prod LOC is the correct signal.

**Labels:** `no-action`, `scan`, `wg`, `runtime`, `D-do-not-split`

---

## Summary ranking by (size × resp-count × hot-path proximity)

| Rank | File | Prod LOC | Resp | Hot? | Score* | Verdict |
|------|------|----------|------|------|--------|---------|
| 1 | screen/mod.rs | 1540 | 7 | YES (per-packet) | 1540×7×3=32340 | (B) Split SYN-flood + flood + missing-profile |
| 2 | frame/inspect.rs | 1813 | 6 | YES (per-packet L4) | 1813×6×3=32634 | (B) Unify EH walker + split flow/filter/frag |
| 3 | frame/mod.rs | 1710 | 6 | YES (per-packet rewrite) | 1710×6×3=30780 | (A) Extract NAT + VLAN + verify + inject (mechanical) |
| 4 | screen/scan.rs | 592 | 1 | NO (new-flow only) | 592×1×1=592 | (D) DO-NOT-SPLIT — already generic, test-heavy |
| 5 | frame/wg.rs | 604 | 2 | YES | 604×2×3=3624 | (D) DO-NOT-SPLIT — 61% test, prod 604 L clean |
| 6 | types/runtime.rs | 503 | 5 | NO | 503×5×1=2515 | (D) DO-NOT-SPLIT — plumbing, well under threshold |

\*Score = prod_loc × resp_count × hot_weight (1=cold, 2=warm, 3=per-packet hot). Used only for ranking; not a hard metric.

Hot-path weight: screen/mod.rs + inspect.rs + frame/mod.rs + wg.rs are per-packet (every packet screened / parsed / rewritten / possibly WG-encapped). scan.rs is session-miss only (cold). runtime.rs is control-plane / bind-time.

---

## Cross-cutting notes

- **Frame inspection hot: parse must stay tight, no new alloc.** All three inspect/mod/wg findings preserve this: walker unification is `#[inline(always)]` + `&[u8]`-only, NAT extraction keeps `&mut [u8]` in-place, WG encap in-place encrypt already avoids intermediate Vec (post-#2792). No new Box/Vec/Arc introduced by any proposed split.
- **Screen sub-thresholds (#3315) config vs enforcement.** Config lives in `ScreenProfile` (packet.rs, 100 L) — 6 SYN-flood thresholds (`syn_flood_threshold`, `syn_flood_dst_threshold`, `syn_flood_src_threshold`, `syn_flood_alarm_threshold`, `syn_flood_dst_threshold`-`src_threshold`, `alarm_without_drop`). Enforcement lives in `check_packet_with_zone_id_opts` (374 L). The split proposed in Finding 1 keeps config in packet.rs and moves enforcement to syn_flood.rs — clean separation, no new config type needed.
- **Screen checks are per-packet but independent (SYN-flood doesn't depend on ICMP-flood).** Splitting by attack type into separate modules via enum+match would be (C) PERFORMANCE-POSITIVE if devirtualized (current code already uses early-return `if threshold==0` to skip disabled checks, which is branch-predictor friendly). The proposed `syn_flood.rs` extraction does not introduce vtable; it's still `if syn_flood_threshold>0 { syn_flood::check(...) }` — same branch, same predictor behavior.
- **No new alloc on hot path.** All splits keep caller-provided buffers (`&mut [u8]`, `&mut ScreenState`) and avoid returning owned collections.


---

## Findings from a1g (/ps-review-039-a1g.md)

## Finding 1 — wg_control.rs 2280 LOC monolith: socket lifecycle + control loop + handshake machine + ECN + poll fused

**Title:** coordinator/wg_control.rs mixes 5 responsibilities in one 2280 LOC file
**Severity:** Medium
**Confidence:** High
**Refactor class:** (A) MECHANICAL / SAFE — cold path, no hot-path inlining risk
**Evidence:**
```
/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/coordinator/wg_control.rs 2280 LOC
  structs: HandshakeAttempt, WgRecv, CmsgBuf
  enums: InboundOutcome, AttemptTrigger, PollWait
  fns: 49 including:
    wg_control_loop / run_wg_control_loop (315 LOC) — main loop
    dispatch_inbound (211 LOC) — WG type dispatch
    encap_and_send, send_keepalive, pace_keepalive_skip — egress/keepalive
    start_attempt, drive_attempt_machine, drive_initiation — handshake SM
    bind_wg_socket, bind_dual_stack_v6, wg_send_to, set_recv_tos_options,
      wg_recvmsg (39 LOC), parse_outer_ecn_from_cmsg, sockaddr_storage_to_socketaddr — socket/ECN
    wg_poll_wait, poll_timeout_ms, monotonic_nanos — poll/timing
```
File crosses the 2000 LOC monolith threshold (engineering-style.md §Modularity: “~2,000 LOC … is a smell, by ~3,000 the next change MUST split”). Two functions exceed 200 LOC (315, 211). Responsibilities are independently testable (socket bind/EADDRINUSE, ECN cmsg parsing, handshake attempt window, poll fatal handling) but currently coupled through a single `impl` block and shared `encap_buf`/`decap_buf` locals.

**Proposed decomposition:**
```
coordinator/wg_control/
  mod.rs              — wg_control_loop entry, HandshakeAttempt, InboundOutcome, constants
  loop.rs             — run_wg_control_loop (poll + burst + timer arm)
  dispatch.rs         — dispatch_inbound + encap_and_send + send_keepalive + pace_keepalive_skip
  handshake.rs        — start_attempt + drive_attempt_machine + drive_initiation
  socket.rs           — bind_wg_socket, bind_dual_stack_v6, wg_send_to, set_recv_tos_options,
                       wg_recvmsg, parse_outer_ecn_from_cmsg, sockaddr_storage_to_socketaddr,
                       CmsgBuf, WgRecv
  poll.rs             — wg_poll_wait, poll_timeout_ms
```
All moves are pure code-motion; `run_wg_control_loop` already takes `&WgEngine`, `&UdpSocket`, `File`, `&AtomicBool` — no new trait bounds. `socket.rs` is `#[cfg(unix)]` isolated, easy to unit-test without a TUN device (existing tests already mock via pipe).

**Hot-path preservation:** N/A — this is the per-tunnel control thread (WG_POLL_CAP_MS 100ms, WG_TIMER_TICK_NS 1s, WG_RX_BURST 64). No HFT constraints. The only per-packet work (decap ECN combine, inner_dst_ip lookup) is dominated by crypto (Noise AEAD) and TUN write, not by dispatch overhead. Split does not change codegen of `dispatch_inbound` match (still monomorphized, still `#[inline]` where it matters).

**Tests+gate:** Existing `wg_control::tests` (poll_loop_stop_joins_promptly, poll_loop_wakes_on_socket_readiness, poll_loop_exits_on_tun_teardown, attempt_give_up_ignores_same_pass, canonicalize_endpoint_*, wg_send_to_*, sockaddr_storage_to_socketaddr_*) remain green. No new tests required for mechanical move. Validate with `cargo test -p xpf-userspace-dp wg_control` and `make test-rust`.

**Why it matters:** 2280 LOC file is already over threshold. Next WG feature (VRF bind, PSK rotation, link-local scope) will push it past 3000. The handshake attempt machine (`HandshakeAttempt` + timers + T7/T8) is the most bug-prone area (see #1888, #2961) and is currently interleaved with ECN cmsg parsing and socket bind fallback — reviewers must read 2280 LOC to audit a timer fix. Splitting isolates the ECN/security-critical cmsg alignment code (CmsgBuf `#[repr(C,align(8))]`) into its own reviewable unit.

**Fix direction:** Mechanical split in one PR before next WG feature. No behavior change. Keep `wg_control.rs` as `mod.rs` re-exporting for `cargo test` compatibility, or delete and fix two `use` sites (`tunnel_supervision.rs`, `coordinator/mod.rs`).

**Labels:** modularity, wg, cold-path, mechanical-split
**Dedup note:** Distinct from #4404 SnapshotIntegrityError (Go), #4405 flowexport, #4406 firewall-filter, #4407 event-engine, #4408-#4409 Go services. No prior Rust wg_control mod split filed. Prior Go WG work (#1432, #1888) is feature, not refactor.

---

## Finding 2 — server/helpers.rs 1292 LOC dumping ground: status + session-sync + binding-plan + hash + VLAN + file-IO

**Title:** server/helpers.rs is a 20-function dumping ground with 6 unrelated responsibilities
**Severity:** Low (cold path) / Medium (reviewability)
**Confidence:** High
**Refactor class:** (A) MECHANICAL / SAFE
**Evidence:**
```
/home/ps/git/avacado-xpf/userspace-dp/src/server/helpers.rs 1292 LOC
  fns:
    refresh_status (311 LOC) — 80+ status field assignments, Prometheus counters
    forwarding_unsupported_error — trivial
    build_synced_session_key / build_nat64_reverse_rebuild / build_synced_session_entry (192 LOC) — HA session-sync
    parse_session_sync_mac — MAC parsing
    reconcile_status_bindings / should_run_afxdp / same_plan_apply_needs_binding_reconcile / set_bindings_forwarding_armed — lifecycle
    wait_for_binding_settle / bindings_settled / same_binding_plan / snapshot_binding_plan_key — settle/hash
    hash_update / update_json_encoded / update_canonical_json_hash / canonical_json_key / write_canonical_json — JSON hashing
    include_userspace_binding_interface / vlan_child_parent_netdev / snapshot_has_parent_candidate / plan_key_rx_queues / replan_queues / replan_bindings_from_candidates / summarize_queues — VLAN+binding plan
    linux_ifname / effective_rx_queues / rx_queue_count — sysfs
    write_state — file persist
```
Header itself says “Daemon-loop helpers extracted from main.rs (Issue 69.1). 20 helper fns called by both main::run() and server::handlers::handle_stream. Pure relocation. Bodies byte-for-byte identical.” — i.e. acknowledged dumping ground pending further split. `refresh_status` alone is 311 LOC with 6 sections (WG liveness, neighbor telemetry, CoS, session, flow, event_stream, fabric-skips) each independently meaningful.

**Proposed decomposition:**
```
server/helpers/
  mod.rs              — re-exports
  status.rs           — refresh_status (or further into status/{mod,neighbor,cos,session,wg}.rs)
  session_sync.rs     — build_synced_session_key, build_synced_session_entry, build_nat64_reverse_rebuild, parse_session_sync_mac
  binding_plan.rs     — include_userspace_binding_interface, vlan_child_parent_netdev, snapshot_has_parent_candidate, plan_key_rx_queues, replan_queues, replan_bindings_from_candidates, summarize_queues, linux_ifname, effective_rx_queues, rx_queue_count + RX_QUEUE_COUNT_OVERRIDE test seam
  hash.rs             — snapshot_binding_plan_key, same_binding_plan, update_snapshot_binding_plan_key, hash_update, update_json_encoded, update_canonical_json_hash, canonical_json_key, write_canonical_json
  lifecycle.rs        — reconcile_status_bindings, should_run_afxdp, same_plan_apply_needs_binding_reconcile, set_bindings_forwarding_armed, wait_for_binding_settle, bindings_settled, write_state
```

**Hot-path preservation:** N/A — cold path (daemon loop: 1/s status refresh, config apply). No inlining or alloc constraints. The only performance-sensitive call is `refresh_status` (1/s) which aggregates atomics via Relaxed loads — splitting files does not change codegen.

**Tests+gate:** Existing helpers tests (`replan_queues_binds_vlan_unit_on_parent_netdev`, `snapshot_allowlist_test.go` parity) must remain green. No new tests for mechanical move.

**Why it matters:** Dumping ground makes “small PR adds one helper” pattern silently grow the file (currently 1292 LOC, will be >1500 after next status field). Reviewers cannot tell if a change to `refresh_status` (status) affects `replan_queues` (binding plan). The file already has a `// Pure relocation` header inviting further split — this is the intended next step of #69.

**Fix direction:** Mechanical split in one PR. Keep `helpers.rs` as `mod.rs` re-exporting for backward compat, or update `use server::helpers::*` in `main.rs`/`handlers.rs` to `use server::helpers::{status::*, session_sync::*, binding_plan::*}`.

**Labels:** modularity, dumping-ground, cold-path, mechanical-split
**Dedup note:** Not in #4404-#4409 (those are Go services, flowexport, firewall-filter). No prior Rust server/helpers split filed. Issue #69.1 was the first extraction; this is the follow-up.

---

## Finding 3 — event_stream/mod.rs 1693 LOC: transport + sequencing + clock + emission fused (borderline)

**Title:** event_stream/mod.rs mixes IO thread, producer sequencing, clock conversion, and RT_FLOW emission
**Severity:** Low (cold path, under threshold for mandatory split, but approaching)
**Confidence:** Medium
**Refactor class:** (A) MECHANICAL / SAFE if split, but (D) DO-NOT-SPLIT also defensible today
**Evidence:**
```
event_stream/mod.rs 1693 LOC
  clock/time helpers (4 fns, ~120 LOC):
    read_mono_and_wall_clocks, monotonic_ns_to_unix_ns,
    monotonic_ns_to_unix_secs_subnanos, mono_ns_to_wall_clock_unix_ns
  shared state (EventStreamShared, EventStreamStats, EventStreamSender, EventStreamWorkerHandle) ~200 LOC
  sequencing (producer_seq_lock, next_seq, rollback_seq, send_sequenced, send_lossless_encoded, send_frame_lossless) ~180 LOC
  emission (encode_delta_frame, push_delta, push_delta_lossless, emit_session_close_rt_flow 108 LOC, emit_session_create_rt_flow 50 LOC) ~250 LOC
  IO thread (io_thread_main, try_connect, replay_buffered, write_all_backpressured, run_connected_loop, process_control_frames, handle_drain_request, drain_remaining, drain_channel_into_write_buf, push_replay_frame, evict_replay_frame, pop_replay_frame, release_*) ~700 LOC
```
File is 1693 LOC (under 2000 but over 1500 threshold for multi-responsibility). Largest functions are 158 LOC (handle_drain_request), 125 LOC (process_control_frames), 111 LOC (run_connected_loop) — none exceed 200 LOC individually. The file’s responsibilities are distinct but tightly coupled through `EventStreamShared` (the IO thread reads `shared.next_seq`, `shared.paused`, `shared.session_evicted_while_paused`; the producer writes them). Extracting IO thread to `io.rs` would require widening 5 `pub(super)` fields to `pub(crate)` — mechanical but creates cross-file coupling.

The existing decomposition already separates concerns into sibling files:
- `codec.rs` — pure wire encoding (no I/O, no atomics, stack `[u8;256]` only)
- `producer.rs` — rate limiting + queue budget (DataplaneEventRateLimiter, DataplaneEventQueueBudget, 466 LOC)
- `mod.rs` — sequencing + transport + emission

This is a reasonable 3-way split. Further splitting mod.rs would create 4-5 files for a single 1693 LOC module.

**Proposed decomposition (if pursued):**
```
event_stream/
  mod.rs      — EventStreamSender/WorkerHandle, EventStreamShared, public API (push_delta, try_emit)
  io.rs       — io_thread_main, try_connect, replay_buffered, write_all_backpressured, run_connected_loop, process_control_frames, handle_drain_request, drain_* helpers, push_replay_frame, evict_replay_frame
  time.rs     — read_mono_and_wall_clocks, monotonic_ns_to_unix_ns*, mono_ns_to_wall_clock_unix_ns (plus NS_PER_SEC const)
```
Keep `emit_session_close_rt_flow` / `emit_session_create_rt_flow` in `mod.rs` (they are the primary worker API). Move clock helpers to `time.rs` — they are pure functions with no `EventStreamShared` dependency, trivial to test in isolation.

**Hot-path preservation / cold-path analysis:** This is cold path. `push_delta` is called on session open/close (per-flow, not per-packet), `try_emit_dataplane_event_at` is called on policy-deny/screen-drop/filter-log (per-drop, rate-limited to ~100/s via producer.rs). `try_send` is non-blocking (bounded mpsc, drop-newest with counter). The IO thread is a dedicated thread (not on AF_XDP poll). Splitting does not affect hot-path inlining. The only hot-path adjacent code is `mono_ns_to_wall_clock_unix_ns` which does two `clock_gettime` syscalls — already documented as acceptable (“one anchored clock read per emit is acceptable; correctness (a real decision timestamp) is preferred over saving the read”).

**Tests+gate:** Existing `event_stream::tests`, `codec_tests`, `producer_tests` must remain green. Time helpers have no direct tests today — extracting them to `time.rs` would be a good opportunity to add unit tests for `monotonic_ns_to_unix_ns` edge cases (0, saturating_sub, future skew clamp).

**Why it matters (if fixed):** Not urgent. File is 1693 LOC, 307 LOC under the 2000 mandatory-split threshold. The IO thread logic (replay gap → FullResync, pause poisoning, drain fence) is the most bug-prone area (8 fixes referenced: #2381, #2382, #2874, #2875, #2876, #2877, #2879, #2959) and would benefit from being in its own file for focused review. But the current layout is not yet a monolith.

**Fix direction:** OPTIONAL. If split, do time.rs first (zero coupling, trivial), then io.rs if file grows past 2000. Otherwise, leave as-is and revisit when adding next event kind.

**Labels:** modularity, event-stream, cold-path, optional-split
**Dedup note:** Distinct from #4407 event-engine (Go), #4421 SnapshotIntegrityError. No prior Rust event_stream split filed beyond the existing codec/producer separation (which was already done).

---

## Finding 4 — wg/engine.rs 1805 LOC + wg/cookie.rs 1435 LOC: single-responsibility WG protocol — DO NOT SPLIT (negative)

**Title:** wg/engine.rs and wg/cookie.rs are large but cohesive — single-responsibility WireGuard protocol — do NOT split
**Severity:** N/A (negative — correctly NOT split)
**Confidence:** High
**Refactor class:** (D) DO-NOT-SPLIT
**Evidence:**
```
// engine.rs 1805 LOC — single responsibility: WireGuard data-plane engine
//   - WgEngine (local_private_key, local_public_key, table: ArcSwap<PeerTable>, sessions_by_local_index, pending, cookie, counters)
//   - PeerTable (peers: Vec<PeerEntry>, peer_index_by_pubkey, allowed_ips: AllowedIps) — atomic snapshot
//   - Hot path: try_encap (via encap_inner 174 LOC), try_decap (223 LOC) — NO allocations, MaybeUninit stack scratch, Arc clone + release lock
//   - Cold path: reconcile_peers, install_session, build_initiator/responder_handshake
//   - Timer queries: peer_has_confirmed_session, peer_for_dest, etc.
//   File is 1805 LOC <2000 threshold, 9 structs/4 enums all WG-domain, 2 functions >200 (try_decap 223, encap_inner 174)

// cookie.rs 1435 LOC — single responsibility: WG DoS mitigation (whitepaper §5.4.7)
//   - CookieChecker (responder): secret rotation, load gate, reply budget, per-source bucket, MAC2 verify, cookie-reply build/encrypt
//   - InitiatorCookie (initiator): last_mac1 tracking, cookie decrypt, MAC2 stamping
//   Two structs, one protocol feature (cookie), shared crypto primitives (keyed_blake2s_128, cookie_encryption_key)
//   File is 1435 LOC <1500 threshold (just over but tests included), production ~900 LOC
```

Both files are under the 2000 LOC mandatory-split threshold. They each have a single conceptual responsibility (WG engine, WG cookie). Splitting engine into `encap.rs`/`decap.rs`/`peer_table.rs`/`reconcile.rs` would create 4 files with tight coupling through `WgEngine`'s `ArcSwap<PeerTable>` and `RwLock<FxHashMap<u32, Arc<WgSession>>>` — every split would require widening `pub(in crate::afxdp::wg)` visibility and passing `&WgEngine` or `&ArcSwap` across files, increasing review burden without reducing complexity.

**Hot-path preservation analysis (HFT-grade):**

- `try_encap` (encap_inner): Hot path for transit WG egress (frame/wg.rs calls engine.try_encap per inner packet). Current code:
  - No allocations: `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` on stack (4080+16=4096), avoids 4096-byte zero-init via raw pointer writes. Correct: LLVM cannot elide `[0u8; N]` zero-init because snow reads trailing pad bytes.
  - No locks held across crypto: `peer_arc` clones `Arc<Peer>` via `ArcSwap::load_full` (atomic, no lock), `peer.current.read().unwrap().clone()` releases `RwLock` before `session.next_tx_counter()` and `snow.write_message`. Verified in file header comment.
  - Branchless-ish: `pad_to_16` is `(n+15)&!15` (single AND), bound checks before counter consume (so Err does not advance nonce).
  - Inlining: `encap_inner` is not `#[inline]` but is called via `try_encap` which is `pub(crate)` and likely inlined by LTO (codegen-units 16, LTO off per crate, but same crate so intra-crate inlining occurs). Splitting into `encap.rs` would keep it in same crate (`mod encap`) — no codegen change. However, extracting to separate crate or `pub` boundary would lose inlining.

- `try_decap`: Hot path for WG ingress (wg_control thread, not AF_XDP hot path but still per-packet for WG). Current code:
  - Takes `sessions_by_local_index.read()` (RwLock read) — single-contended only if multiple WG tunnels share a worker (unlikely; one control thread per tunnel). Contention bounded.
  - Pre-AEAD replay check (`definitely_out_of_window`) with lock held to avoid AEAD cost on replay flood — correct tradeoff (mutex per-session, effectively SPSC because demux is single-worker per session).
  - Post-AEAD `check_and_update` with zero-then-write on Err (prevents plaintext leak).
  - AllowedIPs gate after AEAD (spec §5.4.6) — correct ordering.
  - Splitting into `decap.rs` would not change any of these properties — same crate, same `RwLock`, same ArcSwap.

- `CookieChecker`: Not hot path (classify_initiation called per inbound initiation only, slow path). Contains `Mutex<SecretState>`, `Mutex<LoadState>`, `Mutex<BudgetState>`, `Mutex<SourceTable>` — all `std::sync::Mutex`, not cross-core hot. The file’s `#[inline]` on `macs_equal` and `endpoint_cookie_bytes` is appropriate. No inlining risk from split.

**Layout/locality:** `WgEngine` struct is 10 fields, fits in 2 cache lines (ArcSwap 8B, RwLock 56B, AtomicBool/AtomicU64, counters). Hot path `try_encap` touches `table` (ArcSwap load) + `sessions` is not touched (encap uses peer.current, not demux map). Hot path `try_decap` touches `sessions_by_local_index` (RwLock read) + `table` (for AllowedIPs). Both are cache-resident (engine is `Arc<WgEngine>`, shared across workers). Splitting file does not change struct layout.

**Why NOT to split:** Further decomposition would increase cross-file visibility widening (currently `pub(in crate::afxdp::wg)` for `local_public_key`, `tai64n_clock`, `pending`, `reconcile_lock`, `sessions_by_local_index`, `cookie`, `cookie_gen`) without reducing LOC below threshold or improving reviewability. The wg/ directory already has 15 files (allowed_ips, cookie, counters, dscp, engine, framing, handshake, handshake_session, mod, mss, peer, session, tai64n, timers, tests) — adding `engine_encap.rs`/`engine_decap.rs`/`engine_reconcile.rs` would make the directory harder to navigate. The file is 195 LOC under the 2000 threshold and shrinking is not required.

**Labels:** modularity, wg, hot-path, do-not-split, negative
**Dedup note:** No prior WG engine split filed. #1432 S2a, #1888 S5, #4094 cookie are feature work, not refactor.

---

## Finding 5 — types/cos.rs 1786 LOC, types/forwarding.rs 1054 LOC, protocol/binding.rs 1168 LOC, cold_path_hist.rs 1866 LOC (prod 950), shared_cos_lease/*, event_emit.rs 1492, coordinator/status.rs 1195: cohesive — DO NOT SPLIT (negatives)

**Title:** Remaining large type/status/emit/hist files are cohesive single-responsibility modules — do NOT split
**Severity:** N/A (negatives — correctly NOT split)
**Confidence:** High
**Refactor class:** (D) DO-NOT-SPLIT (all 7 files)
**Evidence:**

| File | LOC | Responsibility | Why cohesive |
|------|-----|----------------|--------------|
| types/cos.rs 1786 | 25 structs, 3 enums | CoS type definitions | Pure types, no logic (except FlowRrRing methods, CoSQueueSojourn::record, FlowFairState::new_boxed). Header says “Pure relocation. 28 items / ~700 LOC …”. All CoS: shaper, queue, flow-fair, fast-path, runtime, telemetry, sojourn, timer wheel. Splitting into cos_config.rs/cos_runtime.rs/cos_flow_fair.rs would create 3 files with circular `CoSQueueConfig` ↔ `CoSQueueRuntime` ↔ `FlowFairState` dependencies. |
| types/forwarding.rs 1054 | 18 structs, 2 enums | Forwarding/routing types | ForwardingState (30+ fields) + route/neighbor/tunnel/fabric/EgressInterface + WorkerBindingLookup. All forwarding-plane config snapshot. Single ArcSwap publish. |
| protocol/binding.rs 1168 | 7 structs | Wire DTOs for status | BindingStatus, BindingCountersSnapshot, WorkerRuntimeStatus, HAGroupStatus, QueueStatus, ExceptionStatus, SessionDeltaInfo + u64_is_zero helpers. All status wire format, no logic. |
| cold_path_hist.rs 1866 (prod ~950) | 3 structs, 1 enum | Cold-path histogram primitives | bucket_index_for_ns_48 (hot, inline), ColdPathSlotMap (cold, build), WorkerColdPathAtomics/Counters (publish/snapshot seqlock), probe/calibrate (cold). Header documents scope clearly. Tests are 914 LOC (49% of file). Prod <1000 LOC. |
| shared_cos_lease/lease.rs 1460 + epoch.rs 565 + vtime.rs 238 + backlog.rs 210 + rotate_epoch_v8.rs + publish_equal_flow_epoch_v8.rs | 4+7 structs | Shared CoS lease token bucket + v8 fair-share | Already decomposed into 6 files (lease.rs, epoch.rs, vtime.rs, backlog.rs, rotate_epoch_v8.rs, publish_equal_flow_epoch_v8.rs + mod.rs). lease.rs 1460 LOC is one piece (token bucket + v8 acquire). Further split would require widening `pub(super)` to `pub(crate)` for config/state/v8 fields. |
| event_emit.rs 1492 (prod ~600) | 0 structs, 1 enum | Dataplane event emission | 8 emit functions (policy_deny, host_inbound_deny, screen_drop, screen_alarm, filter_log) + helpers (resolve_app_id, screen_parse_error_info). All same pattern: build DataplaneEventPayload → try_emit. Single responsibility: RT_FLOW event emission. Tests 892 LOC (60% of file). |
| coordinator/status.rs 1195 | 0 structs (impl Coordinator) | Status surface | 40+ `pub fn` all `&self` → snapshot/sum of coordinator state for gRPC/HTTP. No mutation (except drain_session_deltas). Single responsibility: status reporting. Header says “Operator-status surface split out of coordinator/mod.rs to keep gRPC / HTTP status methods in one place.” |

**Hot-path preservation (where applicable):**

- **cold_path_hist.rs hot functions** (`bucket_index_for_ns_48`, `zone_pair_packed_key`, `lookup_slot`, `sample_tsc_start/end`, `record_sample`): All `#[inline]`, branchless or single-predicate. `bucket_index_for_ns_48` is documented as branchless within each band (one `if ns < 512` selects linear vs exponential). `record_sample` does `buckets[slot][b].saturating_add(1)` + `sum_ns` + `samples` + first_key collision detect — all O(1), no alloc, no lock (worker-local). Called at sampling rate (1-in-256 default, `sample_mask = 0xff`), not per-packet. Inlining is preserved by `#[inline]` regardless of which file defines them — splitting would not change codegen because all are `pub(in crate::afxdp)` and intra-crate.

  The file also contains `WorkerColdPathAtomics` (`#[repr(C, align(64))]`, 64-byte aligned, seqlock publish) and `WorkerColdPathCounters` (`#[repr(C)]`, hot fields in cacheline 0 [0..63] per offset_of tests). The `#[repr(C)]` is load-bearing for cacheline isolation — splitting into separate files would keep the structs together (they must stay co-located) or risk breaking the documented layout. Current layout is correct and pinned by tests (`worker_cold_path_counters_hot_fields_fit_in_cacheline_0`, `worker_cold_path_atomics_hot_fields_at_top`).

- **types/cos.rs FlowRrRing**: `push_back`, `pop_front`, `push_front` are `#[inline]`, use mask-based wrap (`& COS_FLOW_FAIR_BUCKET_MASK`) not modulo — deterministic codegen, no division. `remove` is O(len) linear scan + shift — documented as “typically 2-16 on iperf3, 4096 worst case”. All methods avoid alloc (fixed `[u16; 4096]` backing). `FlowFairState::new_boxed` uses `Box::new_uninit` + raw pointer writes to avoid 352 KB stack temporary — documented SAFETY contract, verified by `new_boxed_matches_new_field_for_field` test + `cargo +nightly miri`. Splitting file would not change any of this.

- **shared_cos_lease/lease.rs acquire_v8_with_cause (278 LOC)**: Hot path for CoS exact queue (per worker, per 200µs epoch). Contains three phases: primary (bounded by my_fair_share + class_cap), surplus (bypass-grace), equal-flow cap. Uses `compare_exchange_weak` loops, tag-checked CAS, `PackedEpochGrant::pack/unpack`. Single function is long (278 LOC) but is a single algorithm (acquire) with three phases that share `still_needed`, `total_granted`, `shortfall` — splitting into `acquire_primary`/`acquire_surplus` would require passing 6+ parameters or a context struct, adding indirection without reducing complexity. The `#[inline]` on helpers (`try_bump_outstanding`, `worker_grant_bump`, `tag_checked_rollback`, `record_equal_flow_active_sample`) is appropriate; LTO is off (codegen-units 16) so cross-file inlining is lost if helpers move to separate files — keeping them in same file preserves intra-crate inlining.

- **event_emit.rs**: `emit_*_event` functions are `#[inline]`, build `DataplaneEventPayload` on stack (no alloc), call `try_emit_dataplane_event_at` (non-blocking, rate-limited). Correct per engineering-style hot-path discipline: no `Vec::push`, no `Box::new` per packet. Splitting file would not affect inlining (all `#[inline]`).

**Why NOT to split:**

- All 7 files are under 2000 LOC (or prod <1000 after excluding tests). They each have a single conceptual responsibility (CoS types, forwarding types, wire DTOs, histogram primitives, lease token bucket, event emission, status surface). Further decomposition would increase file count and cross-file `pub(super)` → `pub(crate)` widening without measurably improving reviewability. The prior decomposition work (#68.1 CoS types extraction, #1229 v6 fair-share module split, #1619 cold_path_hist extraction, #2158 lease split) already brought these files down from larger monoliths — they are at the right granularity today.

- `types/cos.rs` specifically: proposes 25 CoS-related structs. Splitting into `cos/config.rs`, `cos/runtime.rs`, `cos/flow_fair.rs`, `cos/telemetry.rs` would create 4 files with tight coupling (`CoSQueueConfig` → `CoSQueueRuntime` → `FlowFairState` → `VMinQueueState` chain). The current single file lets a reviewer see the full CoS type hierarchy in one place, which is valuable when adding a new queue field (must update config → runtime → telemetry → status overlay).

**Labels:** modularity, do-not-split, negative, types, telemetry
**Dedup note:** Distinct from #4404 SnapshotIntegrityError (Go), #4405 flowexport (Go), #4406 firewall-filter (Rust, separate module), #4408-#4409 Go services. No prior Rust types/cos.rs, cold_path_hist, shared_cos_lease split filed as monolith. Prior splits (#68.1, #1229, #1619, #2158) were the correct granularity — these are the outputs of those splits, not new monoliths.

---

## Summary / recommended action order

| Priority | File | Action | LOC | Class | Risk |
|----------|------|--------|-----|-------|------|
| 1 | coordinator/wg_control.rs 2280 | Split into 5 files (socket, loop, dispatch, handshake, poll) | -~1800 from monolith | (A) mechanical | Low (cold path, existing tests) |
| 2 | server/helpers.rs 1292 | Split into 5 files (status, session_sync, binding_plan, hash, lifecycle) | -~800 from dumping ground | (A) mechanical | Low (cold path, pure fns) |
| 3 | event_stream/mod.rs 1693 | Optional: time.rs + io.rs extraction | -~300 if done | (A) mechanical / (D) defer | Low |
| — | wg/engine.rs 1805 | DO NOT SPLIT | — | (D) | — |
| — | wg/cookie.rs 1435 | DO NOT SPLIT | — | (D) | — |
| — | types/cos.rs 1786 | DO NOT SPLIT | — | (D) | — |
| — | types/forwarding.rs 1054 | DO NOT SPLIT | — | (D) | — |
| — | protocol/binding.rs 1168 | DO NOT SPLIT | — | (D) | — |
| — | cold_path_hist.rs 1866 (prod 950) | DO NOT SPLIT | — | (D) | — |
| — | shared_cos_lease/* (6 files) | DO NOT SPLIT further | — | (D) | — |
| — | event_emit.rs 1492 (prod 600) | DO NOT SPLIT | — | (D) | — |
| — | coordinator/status.rs 1195 | DO NOT SPLIT | — | (D) | — |

**Total mechanical debt:** 2 files over 2000 LOC or dumping-ground (wg_control.rs, helpers.rs) = ~3500 LOC to decompose. 1 optional (event_stream/mod.rs). 10 files correctly NOT split (negatives).

**Hot-path invariants preserved:** All hot-path files (engine.rs encap/decap, cold_path_hist bucket/record, cos FlowRrRing, lease acquire_v8, codec encoding, event_emit try_emit) use stack-only / MaybeUninit / fixed arrays / mask-not-modulo / `#[inline]` / no per-packet alloc / `compare_exchange_weak` seqlock discipline. No split proposed touches hot-path inlining or layout. Proposed splits are cold-path only (wg_control, helpers, event_stream io/time).

**Dedup vs prior audits:** Checked #4404 SnapshotIntegrityError (Go, 616-LOC dumping ground — different module), #4405 flowexport, #4406 firewall-filter, #4407 event-engine (Go), #4408-#4409 Go services, #4421 cold_path_hist? — no overlap. Prior Rust splits (#68.1 types, #1229 v6 lease, #1619 cold_path, #2158 lease) are the correct granularity and their outputs are NOT re-reported as monoliths here.


---

## Findings from a2 (/ps-review-039-a2.md)

## File-size / shape inventory (base f7014695)

| File | LOC | Prod/Test | Responsibilities | Largest fn |
|------|-----|-----------|------------------|------------|
| `userspace-dp/src/nat/allocator.rs` | 1416 | prod | 5 structs (PortAllocator, PortAllocatorShared, AddressOccupancy, PortAllocatorLiveState, LiveAllocation) + PersistentLease + DeterministicV4 + GC + recycle + deterministic reverse | `allocate_translation` 100 LOC, `allocate_translation_locked` 114 LOC |
| `userspace-dp/src/nat/source.rs` | 1389 | prod | SourceNatRule (20+ fields) + 6 type defs + pool expansion + rule parsing + scope/l4/prefix matching + match driver + 6 release/reserve wrappers + 3 NAT64 wrappers + deterministic path | `match_source_nat_result_for_tuple` 336 LOC (line 996-1330) |
| `userspace-dp/src/nat/destination.rs` | 1088 | prod | DnatTable exact+wildcard+PROTO_ANY+prefix-LPM, DnatEntry, DnatPrefixSlot, scope/source/l4 gates, off-exemption, local-address registration | `lookup_with_counter_scoped` ~110 LOC |
| `userspace-dp/src/nat/static_nat.rs` | 793 | prod | StaticNatTable exact+block, StaticNatBlock, SourceConstraint, scope gates, port-mapped coexistence | `from_snapshots` ~110 LOC |
| `userspace-dp/src/nat/mod.rs` | 297 | prod | NatDecision, NatRuleCounter, NatCounterStore, NatScopeCtx, re-exports | — |
| `userspace-dp/src/nat/status.rs` | 40 | prod | Thin snapshot aggregation | — |
| `userspace-dp/src/nat/tests_pool.rs` | 3828 | test | 79 tests pool/persistent/allocator/HA-reserve | — |
| `userspace-dp/src/nat/tests_destination.rs` | 1654 | test | 41 tests DNAT | — |
| `userspace-dp/src/nat/tests_static.rs` | 1109 | test | 31 tests static | — |
| `userspace-dp/src/nat/tests_l4_match.rs` | 815 | test | 17 tests L4/app | — |
| `userspace-dp/src/nat/tests_scope.rs` | 607 | test | 17 tests scope/interface/RI | — |
| `userspace-dp/src/nat/tests_source.rs` | 570 | test | 16 tests source parsing | — |
| `userspace-dp/src/nat/tests_counter.rs` | 357 | test | 6 tests counter | — |
| `userspace-dp/src/nat/tests_dnat_proto.rs` | 348 | test | 10 tests proto | — |
| **nat prod total** | **5023** | | | |
| **nat test total** | **9288** | | | |
| `userspace-dp/src/nat64.rs` | 2527 | prod | Nat64State, Nat64Prefix, forward/reverse translate, EH walk, frag, ICMP-embed | `translate_v6_to_v4` ~200 LOC |
| `userspace-dp/src/nptv6.rs` | 431 | prod | Nptv6State, prefix translate, checksum adjust | — |
| `userspace-dp/src/nat64_tests.rs` | 3984 | test | | |
| `userspace-dp/src/nptv6_tests.rs` | 790 | test | | |
| `pkg/config/compiler_nat.go` | 2529 | prod | ~37 funcs: 5 NAT types compile + 4 validators + 8 helpers + deterministic | `compileNATSource` ~500 LOC, `validateNPTv6Strict` ~200 LOC |
| `userspace-xdp/src/lib.rs` | 1541 | prod | No NAT classification logic (DNAT maps only) | — |

---

## Finding A2-1: nat/allocator.rs — PortAllocatorShared god-struct: hot bitmap + cold persistent-leases/GC/stats fused

**Severity:** Medium
**Confidence:** High
**Refactor class:** (C) PERFORMANCE-POSITIVE (with foot-gun)

**Evidence:**

`PortAllocator` is thin, but its shared state is monolithic:

```rust
// allocator.rs:458
struct PortAllocatorShared {
    counters: Vec<AtomicU32>,          // cold: addr-only try_next_port
    addr_counter_v4: AtomicU32,         // cold: round-robin
    addr_counter_v6: AtomicU32,
    occupancy: Vec<AddressOccupancy>,  // HOT: bitmap + cursor, every new flow
    live: Mutex<PortAllocatorLiveState>, // cold: flow map + persistent leases
    allocations_total: AtomicU64,      // cold: stats
    reuses_total: AtomicU64,
    exhaustion_total: AtomicU64,
    max_tracked_flows: usize,          // config
}
```

```rust
// allocator.rs:284
struct AddressOccupancy {
    words: Vec<AtomicU64>,    // HOT: CAS claim
    cursor: AtomicU32,        // HOT: fetch_add cursor
    recycle: Mutex<VecDeque<u16>>, // semi-hot: FIFO
    port_low: u16,
    range: u32,
}
```

```rust
// allocator.rs:258
pub(super) struct PortAllocatorLiveState {
    live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
    persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
    lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
    lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>>,
    gc_counter: u32,
}
```

No `#[repr]`, no cache-line separation. Hot fields (`occupancy.words`, `occupancy.cursor`) share cache lines with cold atomics (`allocations_total`, `addr_counter_*`) via `PortAllocatorShared`. The comment on line 1-22 itself notes Phase 2 hash-sharding is deferred because Phase 1 single-mutex was the bottleneck — but the hot/cold fusion remains.

Count: 5 cold responsibilities (stats, GC, persistent-lease lifecycle, two expiration indexes, addr round-robin) + 1 hot (bitmap claim) + 1 semi-hot (recycle). Largest method `allocate_translation` 100 LOC (`reserve_flow` is hot-path, every new flow per #4388/#4399).

**Proposed decomposition:**

```
allocator/
  mod.rs              // PortAllocator pub surface, PortAllocatorSnapshot
  hot_bitmap.rs       // AddressOccupancy — words, cursor, claim_offset/free_offset/claim/reserve, #[repr(align(64))]
  live_state.rs       // PortAllocatorLiveState — live_by_flow, persistent_by_source, expiration indexes, gc_counter
  persistent.rs       // PersistentLease, PersistentSourceKey, reuse_existing_lease_locked, gc_expired_*
  deterministic.rs    // DeterministicV4, deterministic_indices_v4, reverse_deterministic_v4, allocate_deterministic_v4
  stats.rs            // allocations_total/reuses_total/exhaustion_total snapshot helpers
```

Keep `PortAllocatorShared` but split physically:

- `hot: Box<[HotAddress]>` where `HotAddress` is `#[repr(align(64))]` containing only `words`, `cursor` (and maybe `port_low/range` if needed for offset_of). This reduces cache footprint for `allocate_translation` non-persistent fast path (line 718-769) which currently touches `self.shared.occupancy[abs].claim()` then `self.shared.live.lock()` — the lock is cold but `occupancy` itself is hot.
- Cold stays behind Arc: `live`, stats, round-robin counters.

Critical: do NOT add a pointer chase between hot bitmap lookup and claim. Current `self.shared.occupancy[abs].claim()` is one deref (`Arc` -> `Vec` -> `AddressOccupancy`). Splitting must keep `occupancy` in same allocation as PortAllocator or in a sibling `Arc` with same indirection depth. Adding a second `Arc<HotState>` would add one more indirection on hot path — measurable.

**Hot-path preservation:**

- `reserve_flow` (#4388) and `allocate_translation` non-persistent hot path run every new flow, must stay zero-alloc, no Vec alloc, no lock on claim. The split must preserve:
  - `AddressOccupancy::claim` remains `&self` with only `AtomicU64` CAS + `AtomicU32` cursor + one `Mutex<VecDeque>` only when cursor exhausted (recycle phase). No new allocation in claim.
  - `reserve_flow` CAS path (`occupancy[addr_index].reserve(port)`) stays lock-free.
  - `live_by_flow` insert stays under existing tiny mutex, not expanded.
  - Per engineering-style.md: pre-size Vecs, never allocate per-packet. The `retained: Vec<u16>` in `claim()` already allocates lazily only on collision — acceptable cold.

Guardrail: run `benches/snat_allocator.rs` (results in `docs/research/2852-portalloc/`). Pre-#2852 single mutex negative-scales 2.87M→0.62M allocs/sec M=1→8. Phase 1 is 1.4-1.6x at M=6/8. Any hot/cold split must not regress below Phase 1.

**Tests+gate:**

- `cargo test -p userspace-dp nat::tests_pool` (79 tests) — covers port-less, ICMP id==0, no-translation, subnet expansion, persistent 3-way, expiry index invariant, pressure GC, shared-pool exhaustion, reserve_flow collision.
- `cargo test -p userspace-dp --lib` for allocator white-box (`debug_is_port_occupied`, `debug_recycled_ports`, etc.)
- `cargo bench -p userspace-dp snat_allocator` — verify no regression vs 2852 baseline.

**Why it matters:** PortAllocator is on the hot path for every new flow (pool-mode SNAT + NAT64 via `allocate_nat64_pool_port`). The current `PortAllocatorShared` mixes hot atomics (bitmap words, cursor) with cold atomics (stats counters, round-robin address counters) on the same cache line. Under 6-8 worker contention this causes false-sharing invalidations on every atomic increment (stats bump at line 765-768) even when workers are claiming distinct pool addresses. Splitting hot bitmap into its own cache-line-aligned struct reduces coherence traffic — but only if done without adding indirection.

**Fix direction:** Introduce `#[repr(align(64))]` `HotOccupancy` for the bitmap+cursor. Move stats/counters to separate `ColdStats`. Keep `occupancy: Vec<HotOccupancy>` flat, not `Vec<Arc<...>>`. Document cache-line reasoning in comment (like existing #2852 comment). No behavior change.

**Labels:** perf, nat, allocator, hot-path, refactor

**Dedup note:** Overlaps #4409 "nat/allocator.rs PortAllocator god-struct (926 LOC)" — this is the same file, now 1416 LOC (+490 LOC from deterministic + persistent refinements). #4409 was filed as open refactor. This finding is a refined, measurement-gated decomposition proposal with explicit hot/cold classification and `#[repr(align)]` guardrail. Not a duplicate — enriches #4409 with performance-positive split analysis.

---

## Finding A2-2: nat/source.rs — match_source_nat_result_for_tuple 336 LOC god-function + 6 responsibilities in one file

**Severity:** Medium
**Confidence:** High
**Refactor class:** (B) STRUCTURAL (moderate risk)

**Evidence:**

```rust
// source.rs:996 (336 LOC, >3x the 100-LOC god-function threshold)
pub(crate) fn match_source_nat_result_for_tuple(
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
    now_ns: u64,
    non_first_fragment: bool,
    icmp_identifier_present: bool,
    matched_counter: &mut Option<Arc<NatRuleCounter>>,
) -> SourceNatLookup {
    // responsibilities in one function:
    // 1. zone/scope match (via rule.matches)
    // 2. off/interface-mode early-return
    // 3. pool_mode + pool_failure gate
    // 4. non-first-fragment gate (#1852)
    // 5. ICMP query vs port-less vs tuple-unknown vs no-translation classification (#3111/#4074/#4088/#3906)
    // 6. v4 vs v6 pool selection + deterministic vs round-robin vs persistent dispatch
```

File `source.rs` totals 1389 LOC with responsibilities:
- Type defs: `SourceNatFailure`, `SourceNatFailureReason` (8 variants), `SourceNatFlowKey`, `PersistentNatPermit`, `SourceNatAppTerm`, `SourceNatRule` (20+ fields), `SourceNatPoolAllocatorKey`
- Pool expansion: `expand_pool_address` (50 LOC)
- Rule parsing: `parse_source_nat_rules_with_previous` (189 LOC) + `parse_match_prefix`
- Match helpers: `scope_matches`, `l4_matches`, `matches`, `nets_match_v4/v6`, `port_in_ranges`
- Allocation driver: `match_source_nat_result_for_tuple` 336 LOC (largest), `match_source_nat_result` 30 LOC, `match_source_nat` 15 LOC
- Release/rollback/reserve: 6 fns `release_source_nat_allocation`, `rollback_source_nat_allocation`, `release_source_nat_allocation_with_mode`, `reserve_synced_source_nat_allocation`, plus 3 NAT64 wrappers
- Deterministic glue already in allocator.rs

13-param function `match_source_nat_result_for_tuple` has 4 nested `match src_ip` arms each duplicating the address-only vs PAT pattern (v4 deterministic, v4 PAT, v6 PAT, wrong-family). The deterministic block (lines 1152-1206) is 55 LOC inline; the port-less gate (lines 1131-1142) is 12 LOC with 3 boolean flags.

**Proposed decomposition:**

```
nat/source/
  mod.rs              // re-exports, SourceNatRule, SourceNatFlowKey, SourceNatFailure
  types.rs            // PersistentNatPermit, SourceNatAppTerm, SourceNatPoolAllocatorKey, SourceNatFlowKey::persistent_source_key
  parse.rs            // parse_source_nat_rules_with_previous, expand_pool_address, parse_match_prefix, source_nat_runtime_compatible (cold, config-time)
  match_rules.rs      // scope_matches, l4_matches, matches, nets_match_*, port_in_ranges (pure predicates)
  match_driver.rs     // match_source_nat_result_for_tuple split:
                      //   classify_l4_mode(protocol, icmp_id_present, no_translation) -> L4Mode enum
                      //   pick_pool_translation(rule, flow, src_ip, family, mode, now_ns) -> Result<TranslatedTuple>
                      //   match_source_nat_result_for_tuple — thin orchestrator (<80 LOC) calling above
  release.rs          // release_source_nat_allocation*, rollback_*, reserve_synced_*
  nat64_glue.rs       // allocate_nat64_pool_port, release_nat64_pool_port, reserve_nat64_pool_port
```

Key split: `match_source_nat_result_for_tuple` →

- `fn classify_l4_mode(protocol: u8, icmp_id_present: bool, no_translation: bool) -> L4Mode { PortLess | AddressOnly { tuple_unknown: bool } | NoTranslation | Pat { icmp_query: bool } }` — pure, no alloc, testable.
- `fn allocate_pool_v4(rule, flow, src_v4, mode, now_ns) -> Result<NatDecision>` — extracts lines 1143-1262 (v4 deterministic + PAT)
- `fn allocate_pool_v6(rule, flow, src_ip, mode, now_ns) -> Result<NatDecision>` — v6 path

This keeps the hot path (called on every new flow miss) tight while making the ICMP/port-less/no-translation interaction testable in isolation.

**Hot-path preservation:**

- `match_source_nat_result_for_tuple` is cold-path (session-miss, first packet of flow) — not per-packet hot, but still high-frequency under SYN flood (100k flows/sec). Must stay zero-alloc: no `Vec` clone, no `String` alloc. Current code is already zero-alloc (iterates `rules` slice, borrows). Split helpers must remain `#[inline]` and take `&SourceNatRule`, not owned.
- `classify_l4_mode` is branchless arithmetic on `protocol` + 2 bools — inlineable.
- No new `Arc` clone on hot path beyond existing `hit_counter.clone()` (already there).

**Tests+gate:**

- `cargo test -p userspace-dp nat::tests_source` (16 tests) + `nat::tests_pool` (79) + `nat::tests_l4_match` (17) + `nat::tests_scope` (17)
- New unit tests: `classify_l4_mode` truth table — protocol 0, 6, 17, 1/58 (ICMP), GRE/ESP (47/50), with/without `icmp_identifier_present`, with/without `no_translation` — 12 cases.

**Why it matters:** The 336-LOC function spans 6 distinct concerns with 3 boolean flags (`port_less`, `tuple_unknown`, `address_only`) plus an `icmp_query` bool, then branches into 4 pool-family arms. The #3906 `no_translation` addition and #4074/#4088 ICMP gate were both layered onto the same function, increasing the risk of a future "add one more flag" regression (the #3111 GRE/ESP corruption was exactly this class — a new protocol added without updating the narrow `protocol == 0` gate). Extracting `classify_l4_mode` as a pure function with exhaustive enum makes the next protocol addition a compile-time match-arm, not a boolean-flag hunt.

**Fix direction:** First PR: extract `classify_l4_mode` + `port_in_ranges`/`nets_match_*` into `match_rules.rs` (pure code-motion, no behavior change). Second PR: extract `allocate_pool_v4`/`v6` from the large match driver. Keep each PR <200 LOC net new logic.

**Labels:** refactor, nat, complexity, god-function

**Dedup note:** Overlaps #4409 "nat/source.rs (1,190 LOC)" — now 1389 LOC (+199). #4409 flagged the file size; this finding pins the specific 336-LOC function and proposes a concrete enum-based decomposition. Complements #4409.

---

## Finding A2-3: pkg/config/compiler_nat.go 2529 LOC — 5 NAT types + 4 validators + helpers fused

**Severity:** Low (code health, not perf)
**Confidence:** High
**Refactor class:** (A) MECHANICAL — pure file split, no logic change

**Evidence:**

37 functions in one file:

- NAT type compilers: `compileNATSource` (500 LOC), `compileNATDestination` (~200 LOC), `compileNATStatic` (~200 LOC), `compileNAT64` (20 LOC), proxy-ARP in `compileNAT` (50 LOC), `compileNAT` dispatcher (120 LOC)
- Validators (strict-vs-lenient): `validateNATHostMaskStrict` (120 LOC), `validateNPTv6Strict` (200 LOC), `validateNAT64PrefixStrict` (60 LOC), `validatePoolUtilizationAlarm` (25 LOC), `validateStaticNATThenTargetStrict` (35 LOC)
- Helpers: `natAddrFamily`, `natCIDRIPPart`, `isHostMaskAddress`, `natStaticPrefixInfo`, `isStaticBlockPair`, `isNAT64PoolHostAddress`, `nptv6PrefixHasHostBits`, `parseZoneList`, `parseNATMatchScopes`, `collectNATScopes`, `applyNATFromScope`, `applyNATToScope`, `applyStaticNATFromScope`, `appendPoolAddresses`, `expandAddressRange`, `parseSourcePoolPortRange`, `applyDeterministicKeys/Children/Host`, `parseDNATPoolAddress`, `parseDNATPortList`, `appendDNATPortRange`, `staticNATMappedPortFromKeys`, `staticNATRoutingInstanceFromKeys`, `resolveStaticNATThenPrefixName(s)`, `defaultPoolAlarmClearThreshold`

The file mixes:

1. AST parsing (hierarchical vs flat-set dual shape — `parseNATMatchScopes`, `parseZoneList`, bracket-list handling)
2. Semantic validation (host-mask, NPTv6 overlap, NAT64 /96, pool alarm, static then-target)
3. Typed-config building (`compileNATSource` etc.)

The comment at line 831 documents the dup-block accumulation fix (#3915) — but the same file also carries unrelated NPTv6 host-bits validation (#2380) and proxy-ARP range expansion. Changing one NAT type requires reading the entire 2529 LOC file.

**Proposed decomposition:**

```
pkg/config/
  compiler_nat.go              // ~80 LOC: compileNAT dispatcher + forEachChild loops
  compiler_nat_source.go       // compileNATSource, appendPoolAddresses, expandAddressRange, parseSourcePoolPortRange, applyDeterministic*, parseZoneList, parseNATMatchScopes, collectNATScopes, applyNATFromScope/ToScope
  compiler_nat_destination.go  // compileNATDestination, parseDNATPoolAddress, parseDNATPortList, appendDNATPortRange
  compiler_nat_static.go       // compileNATStatic, staticNATMappedPortFromKeys, staticNATRoutingInstanceFromKeys, resolveStaticNATThen*, validateStaticNATThenTargetStrict, applyStaticNATFromScope
  compiler_nat_nat64.go        // compileNAT64, isNAT64PoolHostAddress, validateNAT64PrefixStrict
  compiler_nat_validate.go     // validateNATHostMaskStrict, validateNPTv6Strict, validateNAT64PrefixStrict, validatePoolUtilizationAlarm, defaultPoolAlarmClearThreshold, nptv6PrefixHasHostBits
  compiler_nat_helpers.go      // natAddrFamily, natCIDRIPPart, isHostMaskAddress, natStaticPrefixInfo, isStaticBlockPair (shared pure predicates)
```

Each file <600 LOC. No new dependencies, no circular imports (all in `package config`). Pure code-motion: `git mv` + `//go:build` unchanged.

**Hot-path preservation:** N/A — this is compile-time (commit, load, peer-sync), not per-packet. No hot-path concern.

**Tests+gate:**

- `go test ./pkg/config -run TestCompileNAT -count=1`
- `go test ./pkg/config -run TestValidateNAT -count=1`
- `make selftest` — exercises dist roundtrip, validate.py helpers

**Why it matters:** At 2529 LOC this file exceeds the 2000-LOC mod file smell (engineering-style.md: "A .rs file that crosses ~2,000 LOC ... is a smell. Apply same rule to .go"). It is approaching the 3000-LOC "next change should split before adding new logic" threshold. Recent changes (#4290 prefix-name, #4292 routing-instance, #3915 dup-block, #3864 deterministic accumulate) all landed in this single file, increasing merge conflicts. The `validate*Strict` validators are independent of the `compile*` builders — they can be reviewed/tested in isolation.

**Fix direction:** Mechanical split PR: create 6 new files, move functions verbatim, keep `compiler_nat.go` as dispatcher. No behavior change. Second PR (optional): extract `natAddrFamily`/`natCIDRIPPart` into `pkg/config/nat_helpers.go` if reused elsewhere (check via `grep -r natAddrFamily`).

**Labels:** refactor, config, mechanical, file-split

**Dedup note:** Partial overlap with #4056 "NAT compile/validate 5-file-scattered" (open). #4056 describes the problem; this finding proposes concrete file names and function assignments. Also overlaps #4421 "modularity backlog" which lists compiler_nat.go as candidate. Not a duplicate — provides actionable split plan.

---

## Finding A2-4 (D) NEGATIVE — nat/destination.rs is cohesive, not monolithic

**Severity:** N/A
**Confidence:** High
**Refactor class:** (D) NO-OP — do not split

**Evidence:**

`destination.rs` is 1088 LOC with one responsibility: DNAT table. Internal structure:

- `DnatKey` / `DnatValue` / `DnatEntry` / `DnatPrefixSlot` / `DnatProtoPortKey` — all DNAT domain types
- `DnatTable` with 2 maps: `entries: FxHashMap<DnatKey, Vec<DnatEntry>>` (exact) + `prefix_entries: FxHashMap<DnatProtoPortKey, Vec<DnatPrefixSlot>>` (LPM)
- 3-tier lookup: exact `(proto,dst,port)` → wildcard-port `(proto,dst,0)` → `PROTO_ANY` → prefix LPM
- Helpers: `match_entries`, `match_prefix_lpm`, `match_prefix_slots`, `insert_entry`, `insert_prefix_slot`, `destination_ips`, `destination_ips_scoped`, `port_in_ranges`, `host_count_v4/v6`

All helpers serve the single DNAT lookup. No unrelated concerns (no allocator, no pool expansion, no address-book resolution). The 1088 LOC is well under the 2000-LOC monolith threshold. The largest function `lookup_with_counter_scoped` is ~110 LOC, under the 100-LOC god-function threshold (marginally over, but cohesive). The file grew via legitimate feature additions (#3164 prefix LPM, #2394 source-scoped, #3096 interface/RI scope, #3437 ICMP type/code, #3844 off exemption, #3449 dst-port range) — each added a field to `DnatEntry` + a clause in `insert_*` dedup key + a gate in `l4_extra_matches`/`source_matches`/`scope_ok`. This is the expected growth for a lookup table, not a god-struct.

Test coverage: `tests_destination.rs` (41 tests), `tests_dnat_proto.rs` (10), `tests_l4_match.rs` (17, shared with SNAT), `tests_scope.rs` (17) — all exercise DNAT paths.

**Why no split:** Splitting `DnatTable` into `exact.rs` + `prefix.rs` would create two files that always change together (adding a new match field requires updating both dedup keys and both match gates). The current single-file layout localizes the dedup invariant (insert checks same fields as match gates) — splitting would risk drift (the #704 bug class).

**Dedup note:** No open issue proposes splitting destination.rs. #4421 mentions it as part of broader "NAT modules" but does not claim it is monolithic.

---

## Finding A2-5 (D) NEGATIVE — nat/tests already split per #4409, no further action

**Severity:** N/A
**Confidence:** High
**Refactor class:** (D) NO-OP — do not split

**Evidence:**

The original `nat/tests.rs` was 8685 LOC dumping ground (claimed in #4409). It has been split (commit #4409):

```
tests_pool.rs         3828 LOC  79 tests  pool/persistent/allocator/HA-reserve
tests_destination.rs  1654 LOC  41 tests  DNAT
tests_static.rs       1109 LOC  31 tests  static
tests_l4_match.rs      815 LOC  17 tests  L4/app/src-port/ICMP-type
tests_scope.rs         607 LOC  17 tests  interface/RI/zone scope
tests_source.rs        570 LOC  16 tests  source parsing/fail-closed
tests_dnat_proto.rs    348 LOC  10 tests  GRE/ICMP/HOPOPT wildcard
tests_counter.rs       357 LOC   6 tests  counter store/ids/clear
```

Plus `nat64_tests.rs` (3984 LOC) and `nptv6_tests.rs` (790 LOC) separate.

Each file is <4000 LOC, each maps to one NAT concern. `tests_pool.rs` is the largest at 3828 LOC / 79 tests — it covers 5 sub-concerns (port-less, ICMP query-id, no-translation, subnet expansion, persistent NAT) but all are pool-mode SNAT allocation paths that share the same `PortAllocator` setup helpers (`make_pool_rule`, `make_allocator`). Splitting `tests_pool.rs` further would duplicate setup code without improving locality.

**Dedup note:** Directly closes the `nat/tests.rs dumping ground` part of #4409. No further split needed.

---

## Summary of classifications

| Finding | File(s) | LOC prod | Class | Action |
|---------|---------|----------|-------|--------|
| A2-1 | `nat/allocator.rs` (1416) — PortAllocatorShared hot/cold fused | 1416 | (C) PERFORMANCE-POSITIVE (with foot-gun) | Split hot bitmap into `#[repr(align(64))]` struct, keep cold behind Mutex/Arc. Must not add pointer chase. Gate with `benches/snat_allocator.rs`. |
| A2-2 | `nat/source.rs` (1389) — `match_source_nat_result_for_tuple` 336 LOC + 6 responsibilities | 1389 | (B) STRUCTURAL | Extract `classify_l4_mode` enum + `allocate_pool_v4/v6` helpers. Two PRs: pure predicate extraction, then allocation-driver split. |
| A2-3 | `pkg/config/compiler_nat.go` (2529) — 5 NAT types + 4 validators + helpers fused ~37 funcs | 2529 | (A) MECHANICAL | 6-file split, pure code-motion, no behavior change. No hot-path. |
| A2-4 | `nat/destination.rs` (1088) | 1088 | (D) NEGATIVE | Cohesive DNAT lookup, under threshold, do not split |
| A2-5 | `nat/tests_*.rs` (9288 test LOC, 8 files) | — | (D) NEGATIVE | Already split per #4409, each <4000 LOC, no further action |

## Cross-cutting notes

### nat64.rs / nptv6.rs

- `nat64.rs` 2527 LOC: NAT64 forward+reverse, EH walk, frag, ICMP-embed. Responsibilities: `Nat64State` (prefix matching, pool selection, allocator reuse), `Nat64Prefix`, `translate_v6_to_v4`/`translate_v4_to_v6`, `ipv6_l4_offset_and_protocol` (EH walk), `ipv6_fragment_header`, `translate_embedded_*`, `reserve_synced_nat64_allocation`. This is cohesive — all NAT64 translation. The EH walk helpers (`ipv6_l4_offset_and_protocol`, `ipv6_is_non_first_fragment`, `ipv6_fragment_header`) are 3 small fns that could be extracted to `nat64/ipv6_ext.rs` but 2527 LOC is just over the 2000-LOC smell. Propose deferred: if next NAT64 feature adds ~200 LOC, split then (per engineering-style "refactor with new features, not after").

- `nptv6.rs` 431 LOC: small, single responsibility, no action.

- `userspace-xdp/src/lib.rs` 1541 LOC: shim, not NAT. No NAT-related classification — only DNAT map definitions (`DnatKeyV4/V6`) mirrored from `bpf/headers/xpf_maps.h`. No finding.

### Hot-path overall

- `reserve_flow` (allocator.rs:1206) + `nat_reverse_index` (session/mod.rs, not in batch but referenced) are per-new-flow. Current code is zero-alloc, lock-free bitmap CAS. Any allocator split must preserve this.
- `match_source_nat_result_for_tuple` is cold-path (session-miss) but high-frequency under SYN flood — must stay zero-alloc, no `Vec` clone.
- `DnatTable::lookup_with_counter_scoped` is cold-path (session-miss) — not hot, no cache-line concern.

### Verification matrix

| Finding | Unit tests | Bench/gate | Integration |
|---------|------------|------------|-------------|
| A2-1 | `cargo test -p userspace-dp nat::tests_pool` (79) | `cargo bench snat_allocator` — must not regress vs 2852 baseline 1.4-1.6x | `make cluster-deploy` + iperf3 23+ Gbit/s |
| A2-2 | `cargo test nat::tests_source/pool/l4_match/scope` (129) | None (cold path) | `make test-deploy` + NAT pool exhaustion test |
| A2-3 | `go test ./pkg/config -run TestCompileNAT` | `make selftest` | `make test-deploy` + config commit with dup-block (#3915) |
| A2-4 | (D) negative — existing tests unchanged | — | — |
| A2-5 | (D) negative — existing tests unchanged | — | — |


---

## Findings from a3 (/ps-review-039-a3.md)

## File-size / shape inventory

| File | LOC | funcs | types | Largest func (LOC) | Responsibilities (est.) |
|------|-----|-------|-------|--------------------|------------------------|
| `compiler_validate_warn.go` | 3330 | 35 | 0 | `ValidateConfig` 1559 | ~12 (NAT alarms, deterministic NAT, zone/parity, address-book, screen, policy log, junos-host, filter, DDNS, routing, CoS, DHCP relay, sampling, host-inbound) |
| `compiler_nat.go` | 2529 | 37 | 1 | `compileNATSource` ~500 (pool+alarm+deterministic+rule expansion) | 4+7 helpers (helpers/predicates, 4 strict gates, 4 compile entry points, 10+ parse/expand helpers) |
| `compiler.go` | 2110 | 8 | 1 (`compileOpts` with 70+ bool fields) | `CompileConfigLenient` ~100 (opts literal), `compileConfigWithOpts` ~75, `compileConfigForNodeWithOpts` ~60 | 3 (strict/lenient entry points, `compileOpts` god-struct definition, `compileExpanded` orchestrator now thin after #4406) |
| `compiler_system.go` | 1881 | 27 | 0 | `compileSystem` 536, `compileChassis` 300 | 8+ (system leaf parsing, DDNS catalog, dataplane-typed dispatch, userspace tunables, syslog host/file/user, SNMP community/trap-group/v3, login RBAC, chassis/cluster/RG, schedulers, archival, MUEM artifact, advisory warnings) |
| `compiler_services.go` | 1821 | 27 | 0 | `compileDHCPRelay` 149, `compileDHCPLocalServer` 126, `compileRPM` 122, `compileSamplingFamily` 121 | ~10 (RPM probe/test validation×5, DHCP local-server, DHCP DDNS, DHCP expired-leases, dynamic-address, services dispatch, ip-monitoring/overlay, flow-monitoring, forwarding-options sampling/port-mirroring, DHCP relay, event-options, bridge-domains) |
| `compiler_validate_strict_filter.go` | 1660 | 28 | 0 | `validateFilterAddressExceptStrict` ~140, `validateFilterFromMatchStrict` ~120 | 1 domain (firewall filter) but 15+ independent gates |
| `compiler_uniformgates.go` | 1659 | 1 | 0 | `runUniformGates` 1659 | 1 (orchestrator) but ~75 distinct validation gates inlined sequentially |
| `types_system.go` | 1544 | 15 | 64 | `mapJunosPermissions` ~70 | 7+ (SystemConfig, UserspaceConfig, SNMP/MIB, Login RBAC, DHCP server/lease, Services/RPM/IP-monitoring, Flow/Sampling, Firewall/Policer/Filter — firewall types do not belong in "system") |
| `compiler_interfaces.go` | 1279 | 14 | 0 | `compileInterfaces` 535, `parseVRRPGroups` 237 | 5 (interface/VLAN/MTU/speed/encap/LAG/RETH/fabric, tunnel, WireGuard multi-peer, VRRP groups+AST validation+track shape, MSS selection, per-iface DDNS binding) |
| `compiler_routing.go` | 1226 | (not in top-9) | — | — | — |
| `compiler_firewall.go` | 1206 | — | — | — | — |
| `compiler_class_of_service.go` | 1205 | — | — | — | — |
| `compiler_protocols.go` | 1180 | — | — | — | — |
| `types_security.go` | 1202 | — | — | — | — |
| `schema_security.go` | 1255 | — | — | schema only | — |
| `schema_system.go` | 1021 | — | — | schema only | — |

Post-#4405 / #4406 splits already landed:
`compiler_validate_strict.go` (478 LOC remainder) + 10 per-domain files (`_application.go`, `_chassis.go`, `_cos.go`, `_ipsec.go`, `_nat.go`, `_observability.go`, `_policy.go`, `_routing.go`, `_screen.go`, `_vrrp.go`, `_zones.go`, `_filter.go`) = former 6997 LOC god-file decomposed.  
`compiler.go` `compileExpanded` decomposed into `compiler_prewalk.go`, `compiler_dispatch.go`, `compiler_derivations.go`, `compiler_earlystrict.go`, `compiler_uniformgates.go`, `compiler_tailgates.go` — `compileExpanded` now 7 calls.

---

## Finding 1 — `compiler_validate_warn.go` 3330 LOC — warning monolith (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE — cold path, pure file-move

**Evidence:**

- 3330 LOC, 35 funcs, 0 types. Single largest func `ValidateConfig` 1559 LOC (47% of file), branches across 12+ config domains.
- Function list spans unrelated subsystems: `deterministicIPv4Enforced`, `sortedPoolNames`, `ValidateConfig`, `validateHostInboundMulticastWarnings`, `validateDHCPRelayParityWarnings`, `validateInterfaceParityWarnings`, `validateDefaultPolicyLogWarnings`, `validatePolicyLogInertOnDenyWarnings`, `junosHostPolicySourceScoped`, `validateJunosHostDirectDeliveryWarnings`, `validateFilterLossPriorityWarnings`, `validateFirewallInterfaceSpecificWarnings`, `validateLo0FilterKernelMirrorWarnings`, `validateFilterNoCatchAllWarnings`, `validateDDNSBackendWarnings`, `validateSurfaceADDNSWarnings`, `validateRoutingRuleWindowWarnings`, `validateRibGroupLeakWarnings`, `validateCoSOversubscriptionWarnings`, `classOfServiceClassifierQueueWarnings`, …

Quote — `ValidateConfig` mixes login auth, zone bookkeeping, app port validation, policy zone refs, NAT zone refs, screen refs, host-inbound full-admit, address-book CIDR, all in one function:

```go
func ValidateConfig(cfg *Config) []string {
    var warnings []string
    if cfg.Services.ApplicationIdentification {
        warnings = append(warnings,
            "services application-identification is enabled, but xpf "+
                "AppID is port+protocol catalog matching only — no L7 "+
                "DPI / signature engine. ...")
    }
    if userspaceSynCookieProtectionActive(cfg) &&
        (cfg.System.RootAuthentication == nil ||
            cfg.System.RootAuthentication.EncryptedPassword == "") {
        warnings = append(warnings,
            "active userspace-dp SYN-cookie screen profiles require "+
                "system root-authentication encrypted-password material ...")
    }
    if cfg.System.Login != nil {
        for _, u := range cfg.System.Login.Users {
            ...
        }
    }
    // Collect valid zone names
    zones := make(map[string]bool)
    ...
    // Validate policies ... NAT zone references ...
    // Validate screen references in zones ...
    // #3226: `system-services all` / `any-service` is a packet-wide ...
    fullAdmitAdvice := func(where string, svcs []string) {
```

Seam: `ValidateConfig` does (a) operator-facing advice generation, (b) cross-reference resolution (`zones`, `addrs` map builds), and (c) per-domain semantic checks — three responsibilities in one 1559-line function.

**Proposed decomposition:**

```
compiler_validate_warn.go              (keep ValidateConfig skeleton, ~80 LOC dispatch)
compiler_validate_warn_nat.go          (deterministicIPv4Enforced, sortedPoolNames, NAT alarm helpers)
compiler_validate_warn_security.go     (policy log, default-policy, junos-host, zone/screen, host-inbound full-admit)
compiler_validate_warn_forwarding.go   (firewall filter CoS/warn, lo0 mirror, interface parity, DHCP relay parity)
compiler_validate_warn_ddns.go         (validateDDNSBackendWarnings, ddns* helpers, validateSurfaceADDNSWarnings)
compiler_validate_warn_routing.go      (validateRoutingRuleWindowWarnings, validateRibGroupLeakWarnings)
compiler_validate_warn_cos.go          (validateCoSOversubscriptionWarnings, classOfServiceClassifierQueueWarnings, schedulerHasEffectiveWindow, firewallFilterHasCatchAllTerminator …)
```

Each new file: `package config`, takes `*Config`, returns `[]string`, no new imports. Helpers `hasFamily`, `anySamplingDirectionConfigured`, `firewallFilterHasCatchAllTerminator`, etc. travel with their domain.

**Shared private types / consts:** None — all helpers are pure `func(cfg *Config) []string` or tiny predicates. No package-private type shared across domains.

**Hot-path preservation:** (A) SAFE — `ValidateConfig` is called only from `runTailGates` (P7), which runs on `CompileConfig` / commit path. Not reachable from per-packet path. Mechanical file-move, no logic change.

**Tests + gate:** `go test ./pkg/config -run TestValidate` — byte-identical warnings. Verify sorted top-level decl-NAME set unchanged per #4144: `go list -f '{{.GoFiles}}' | xargs grep -h '^func ' | sort` before/after identical.

**Why it matters:** 3330 LOC file with 35 functions is the single largest remaining warning monolith after #4405. Every NAT / security / CoS / DDNS fix touches this file → merge conflicts. Reviewers must scroll past unrelated domain code.

**Fix direction:**

1. PR1: Extract `compiler_validate_warn_nat.go` + `compiler_validate_warn_security.go` (largest two slices, ~1200 LOC moved, no behavior change).
2. PR2: Extract remaining domains (`_forwarding.go`, `_ddns.go`, `_routing.go`, `_cos.go`), thin `ValidateConfig` to a dispatch table.

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 2 — `compiler_system.go` 1881 LOC — system god-compiler (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE

**Evidence:**

- 1881 LOC, 27 funcs, 0 types. Largest: `compileSystem` 536 LOC, `compileChassis` 300 LOC, `compileUserspaceDataplane` 127, `compileSNMP` 131.
- Single `compileSystem` switch handles 15+ top-level `system` children, each invoking a distinct subsystem compiler:

```go
func compileSystem(node *Node, sys *SystemConfig, cfg *Config, opts compileOpts) error {
    dpType, err := compileSystemDataplaneType(node)
    ...
    for _, child := range node.Children {
        switch child.Name() {
        case "host-name":
            if len(child.Keys) >= 2 { sys.HostName = child.Keys[1] }
        case "domain-search":
            sys.DomainSearch = append(sys.DomainSearch, firewallMatchValues(child)...)
        case "login":
            sys.Login = &LoginConfig{}
            for _, classInst := range namedInstances(child.FindChildren("class")) {
                lc := &LoginClass{Name: classInst.name}
                ...
                lc.MappedPermissions, _ = mapJunosPermissions(lc.Permissions)
            }
        case "archival":
            sys.Archival = &ArchivalConfig{ ArchiveDir: "/var/lib/xpf/archive", ... }
            ...
        case "syslog":
            sys.Syslog = &SystemSyslogConfig{}
            for _, slInst := range namedInstances(child.FindChildren("host")) {
                host := &SyslogHostConfig{Address: slInst.name}
                ...
            }
        case "dataplane":
            ...
        }
    }
    svcNode := node.FindChild("services")
    snmpNode := node.FindChild("snmp")
    ...
}
```

Seam crossed: leaf parsing (`host-name` / `domain-search` / `name-server`), RBAC class mapping, DDNS provider catalog, archival SCP site parsing, DHCP server binding, SSH hardening, syslog host/file/user FD logic, SNMP community/trap-group/v3, chassis RG/interface-monitor/ip-monitoring, scheduler/day-window, shared-UMEM artifact JSON read + normalize — all in one file.

Responsibility count: at least 8 (system leaf, login, DDNS, SNMP, chassis/cluster, schedulers, syslog, userspace dataplane tunables + shared-UMEM, archival, advisory generators).

**Proposed decomposition:**

```
compiler_system.go                     (keep compileSystem dispatch ~80 LOC + compileSystemDataplaneType)
compiler_system_login.go               (compileSystem login block, LoginClass mapping, loginClassAdvisoryWarnings, loginClassPermName, sshHardeningAdvisoryWarnings)
compiler_system_ddns.go                (ddnsProviderStringProps, compileDDNSServices, ddnsServicesScalar, parseDurationSeconds, compileDDNSProvider)
compiler_system_syslog.go              (syslogFacilitySeverity, syslog host/file/user parse from compileSystem)
compiler_system_snmp.go                (compileSNMP, compileSNMPv3, parseSNMPv3UserKeys, snmpInertKnobWarnings)
compiler_system_chassis.go             (compileChassis, compileSchedulers, schedulerWindowFromNode, validateBackupRouterDst, schedulerWeekdays)
compiler_system_userspace.go           (compileUserspaceDataplane, compileSharedUMEMConfig, readSharedUMEMPhase0Artifact, normalize*Artifact*, userspaceRetiredKnobWarnings, hasDNSProxyChild, systemInertKnobWarnings)
```

**Shared private types / consts to carry:**

- `sharedUMEMPhase0ArtifactMaxBytes` const → moves with `compiler_system_userspace.go`.
- `ddnsProviderStringProps` var → moves with `compiler_system_ddns.go`.
- `schedulerWeekdays` map → moves with `compiler_system_chassis.go`.
- `compileSystem` calls `firewallMatchValues`, `nodeVal`, `namedInstances` (global helpers in `compiler_*.go`) — remain accessible via same package.

**Hot-path preservation:** (A) SAFE — all `compileSystem*` functions run once per commit (cold path). Not reachable from per-packet path.

**Tests + gate:** `go test ./pkg/config -run TestCompileSystem` / `TestSNMP` / `TestChassis`. Decl-NAME set unchanged.

**Why it matters:** 1881 LOC with 536-LOC `compileSystem` + 300-LOC `compileChassis` is the second-largest compiler after `compiler_nat.go`. Every syslog / SNMP / login / chassis / DDNS change collides here. Splitting by subsystem aligns files with `docs/config-schema.md` aspect boundaries (`system`, `system login`, `system services`, `system syslog`, `system snmp`, `chassis`).

**Fix direction:**

1. PR1: Extract `compiler_system_login.go` + `compiler_system_snmp.go` (well-bounded, no shared state).
2. PR2: Extract `compiler_system_chassis.go` + `compiler_system_ddns.go` + `compiler_system_userspace.go`.

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 3 — `compiler_services.go` 1821 LOC — services god-compiler (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE

**Evidence:**

- 1821 LOC, 27 funcs, 0 types.
- Mixes 5 RPM validators, 3 DHCP compilers, dynamic-address, IP-monitoring, flow-monitoring, forwarding-options/Sampling/Port-mirroring, DHCP-relay, event-options, bridge-domains:

```
func parseRPMPositiveInt(...) ...
func validateRPMTest(...) ...
func validateRPMSourceAddressStrict(...) ...  // 63 LOC
func validateRPMLinkLocalZoneStrict(...) ...  // 53 LOC
func validateRPMHTTPGetSchemeStrict(...) ...
func validateRPMRoutingInstanceStrict(...) ...
func validateRPMProbePinsStrict(...) ...
func compileDHCPLocalServer(...) ...          // 126 LOC
func mergeDHCPDynamicDNS(...) ...
func compileDHCPDynamicDNS(...) ...           // 98 LOC
func compileDHCPExpiredLeases(...) ...
func compileDynamicAddress(...) ...
func compileServices(...) ...                 // 26 LOC dispatch
func compileIPMonitoring(...) ...
func compilePreferredRoutes(...) ...
func validateIPMonitoringStrict(...) ...      // 85 LOC
func compileRPM(...) ...                      // 122 LOC
func compileFlowMonitoring(...) ...
func compileForwardingOptions(...) ...
func compilePortMirroring(...) ...            // 73 LOC
func compileSampling(...) ...
func compileSamplingFamily(...) ...           // 121 LOC — also parses flow-server version/template/src-addr
func compileDHCPRelay(...) ...                // 149 LOC
func compileEventOptions(...) ...             // 93 LOC
func compileBridgeDomains(...) ...
```

Seam crossed in a single file:

```go
// RPM test validation (icmp/tcp/http) lives next to:
func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig, isV6 bool) error {
// ... 126 LOC of DHCP pool/range/subnet/router/DNS/lease/domain/static-bindings ...

// 600 lines later:
func compileSamplingFamily(node *Node) *SamplingFamily {
// ... flow-server version9/version-ipfix/template/source-address/inline-jflow parsing ...
    for _, child := range node.Children {
        switch child.Name() {
        case "flow-server":
            // per-collector version + template + source-address
        case "source-address":
        case "inline-jflow":
        }
    }
}
```

Parsing (DHCP lease-time int), validation (RPM source-address family match), and rendering-prep (SamplingFamily flow-server version binding) all fused via file proximity.

**Proposed decomposition:**

```
compiler_services.go               (keep compileServices dispatch ~30 LOC)
compiler_services_rpm.go           (parseRPMPositiveInt, parseRPMRootPositiveInt, validateRPMTest, validateRPMSourceAddressStrict, validateRPMLinkLocalZoneStrict, validateRPMHTTPGetSchemeStrict, validateRPMRoutingInstanceStrict, validateRPMProbePinsStrict, compileRPM)
compiler_services_dhcp.go          (compileDHCPLocalServer, compileDHCPExpiredLeases, compileDHCPRelay, compileDHCPDynamicDNS, mergeDHCPDynamicDNS, compileDynamicAddress)
compiler_services_ip_monitoring.go (compileIPMonitoring, compilePreferredRoutes, validateIPMonitoringStrict, resolveIPMonitoringInterfaceNextHop)
compiler_services_flow.go          (compileFlowMonitoring, compileForwardingOptions, compileSampling, compileSamplingFamily, compilePortMirroring)
compiler_services_event.go         (compileEventOptions, compileBridgeDomains)
```

**Shared private types / consts:** `supportedRPMProbeTypes` map moves with `_rpm.go`. No cross-domain private const otherwise.

**Hot-path preservation:** (A) SAFE — all `compile*` / `validate*` run on commit path only.

**Tests + gate:** `go test ./pkg/config -run 'TestRPM|TestDHCP|TestSampling|TestFlow'`. Decl-NAME set unchanged.

**Why it matters:** 1821 LOC services file forces every RPM / DHCP / flow / sampling change through same file. Recent DHCP and RPM changes already collide frequently (`git log --oneline --grep=dhcp --grep=rpm` shows interleaved edits).

**Fix direction:**

1. PR1: Extract `compiler_services_rpm.go` (self-contained, 5 validators + `compileRPM`).
2. PR2: Extract `compiler_services_dhcp.go` + `compiler_services_flow.go`.
3. PR3: Extract remaining `_ip_monitoring.go`, `_event.go`.

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 4 — `compiler_nat.go` 2529 LOC — helper predicates + strict gates + compilation fused (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE (with private-helper carry noted)

**Evidence:**

- 2529 LOC, 37 funcs, 1 type (`natMatchScope`). Four distinct concerns in one file:

  1. **Helper predicates** (family/mask classification, used by both compile and validation):
     `natAddrFamily`, `natCIDRIPPart`, `isHostMaskAddress`, `natStaticPrefixInfo`, `isStaticBlockPair`, `isNAT64PoolHostAddress`, `nptv6PrefixHasHostBits` — 160 LOC, no validation, pure parsing.

  2. **Strict validation gates** (commit-time hard-reject, lenient-warn on load):
     `validatePoolUtilizationAlarm`, `validateNATHostMaskStrict` (213 LOC), `validateNPTv6Strict` (234 LOC), `validateNAT64PrefixStrict` (70 LOC), plus `defaultPoolAlarmClearThreshold` / `defaultPoolAlarmHysteresis`.

  3. **Compile dispatch + scope parsing:**
     `compileNAT`, `compileNAT64`, `parseZoneList`, `parseNATMatchScopes`, `collectNATScopes`, `applyNATFromScope`, `applyNATToScope`, `applyStaticNATFromScope`.

  4. **Pool / rule compilation:**
     `appendPoolAddresses`, `expandAddressRange`, `parseSourcePoolPortRange`, `applyDeterministicKeys/Children/Host`, `compileNATSource`, `compileNATDestination`, `compileNATStatic` (each 200-500 LOC).

  Largest func `compileNATSource` ~500 LOC covers pool `address` bracket-list expansion, `port range` Junos-vs-legacy shape, deterministic CGNAT accumulate, persistent-NAT, port-overloading-factor, routing-instance, pool-utilization-alarm defaulting, deterministic capacity check, NAT rule-set from/to scope expansion, match `source-address`/`source-address-name`/`destination-address`/port/application, `then source-nat` interface/pool/off.

Quote — validation gate living in compilation file:

```go
// validateNATHostMaskStrict is the #2173 strict-vs-lenient gate that
// rejects a static-NAT match/prefix or a NAT64 source-pool address whose
// mask is not a host route (/32 for v4, /128 for v6; a bare address is a
// host too). #2132 made the Rust dataplane TOLERATE the canonical host
// mask, and PR #2167 then hardened the Rust parser to REJECT a non-host
// mask — so today a misconfigured /24 static-NAT match or pool address is
// SILENTLY DROPPED at the dataplane (the rule is parsed-out, never
// installed) with no operator feedback. This commit-time check surfaces
// the misconfiguration at `commit`/`commit check` instead.
func validateNATHostMaskStrict(cfg *Config, lenient bool) ([]string, error) {
    if cfg == nil {
        return nil, nil
    }
    var warnings []string
    emitSuffix := func(msg, suffix string) error {
        if lenient {
            warnings = append(warnings, msg+suffix)
            return nil
        }
        return fmt.Errorf("%s", msg)
    }
```

This gate is called from `runUniformGates` (P6b), not from `compileNAT*`. It belongs with the other strict gates, not with pool address expansion.

Quote — helper predicate reused by 3+ call sites across validation + compilation:

```go
func natAddrFamily(ipPart string) string {
    if net.ParseIP(ipPart) == nil {
        return ""
    }
    if strings.IndexByte(ipPart, ':') >= 0 {
        return "v6"
    }
    return "v4"
}
```

Used in `validateNATHostMaskStrict`, `validateBackupRouterDst` (in `compiler_system.go`), `validateNPTv6Strict`, `validateNAT64PrefixStrict`, and `(indirectly) compile-time pool checks`. Same-package reuse across `compiler_nat.go` + `compiler_system.go` + `compiler_validate_strict_nat.go` means splitting must keep this helper visible.

**Proposed decomposition:**

```
compiler_nat.go                    (keep compileNAT, compileNAT64, compileNATSource, compileNATDestination,
                                   compileNATStatic, parseZoneList, parseNATMatchScopes, collectNATScopes,
                                   applyNAT*Scope, appendPoolAddresses, expandAddressRange,
                                   parseSourcePoolPortRange, applyDeterministic*, ~1500 LOC)
compiler_nat_helpers.go             (natAddrFamily, natCIDRIPPart, isHostMaskAddress, natStaticPrefixInfo,
                                   isStaticBlockPair, isNAT64PoolHostAddress, nptv6PrefixHasHostBits,
                                   defaultPoolAlarmClearThreshold, defaultPoolAlarmHysteresis)
compiler_validate_strict_nat.go    (already exists 702 LOC — MOVE validatePoolUtilizationAlarm,
                                   validateNATHostMaskStrict, validateNPTv6Strict, validateNAT64PrefixStrict
                                   FROM compiler_nat.go into this file, so all NAT strict gates live together)
```

Note: `compiler_validate_strict_nat.go` already exists but does NOT contain these 4 gates — they still live in `compiler_nat.go`. The `natAddrFamily` / `isHostMaskAddress` helpers are used by both `compiler_nat.go` (compile-time pool validation) and the strict gates, so they belong in a shared `compiler_nat_helpers.go` (or unexported helpers in `pkg/config/nat_helpers.go`).

**Shared private types / consts — subtlety:**

- `defaultPoolAlarmHysteresis` const, `natScopeKinds` var / `natMatchScope` type must be carried with whichever file keeps the scope helpers.
- `natAddrFamily` is also called from `compiler_system.go:validateBackupRouterDst` — if helpers move to `compiler_nat_helpers.go`, that file must stay in `package config` (same package) so `compiler_system.go` still sees it; no import change needed.
- If `isHostMaskAddress` moves, verify `compiler_nat.go:pool.Address` check (`compileNATSource` static-NAT pool host check) still compiles — it uses the same helper.

**Hot-path preservation:** (A) SAFE — NAT helpers + validation + compilation all run on commit path only (cold). No per-packet function calls this code. Pure file move.

**Tests + gate:** `go test ./pkg/config -run 'TestNAT|TestNPTv6|TestNAT64|TestPool'`. Decl-NAME set must stay identical per #4144 discipline (`go list -f '{{.GoFiles}}'` sorted func/method names before vs after).

**Why it matters:** 2529 LOC file with 37 functions mixing 3 concerns is the single largest compiler file after `compiler_validate_warn.go`. NAT changes (pool, deterministic, NPTv6, NAT64) all collide here, and the inline validation gates duplicate the responsibility already owned by `compiler_validate_strict_nat.go`.

**Fix direction:**

1. PR1: Create `compiler_nat_helpers.go` moving 7 helper predicates + 1 const (no behavior change, `go build` passes).
2. PR2: Move `validatePoolUtilizationAlarm`, `validateNATHostMaskStrict`, `validateNPTv6Strict`, `validateNAT64PrefixStrict` into existing `compiler_validate_strict_nat.go` (now all NAT strict gates co-located).

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 5 — `compiler_uniformgates.go` 1659 LOC + `compiler_validate_strict_filter.go` 1660 LOC — genuinely cohesive, do NOT split (D)

**Severity:** Low (negative finding)  
**Confidence:** High  
**Refactor class:** (D) DO-NOT-SPLIT

### `compiler_uniformgates.go` — single-func orchestrator preserving order invariants

**Why it is cohesive:**

- After #4406 step 4, this file is **exactly one function** `runUniformGates` (1659 LOC) — a linear sequence of ~75 `validate*Strict` calls, each with identical shape:

```go
if err := validateClassOfServiceSchedulerMapRefsStrict(cfg.ClassOfService); err != nil {
    if opts.lenientSchedulerMapRef {
        cfg.Warnings = append(cfg.Warnings,
            fmt.Sprintf("class-of-service scheduler-map reference (downgraded to warning on tolerant path): %v", err))
    } else {
        return err
    }
}
// ... 70+ more gates, same pattern, order is invariant #6/#7 ...
```

- File header explicitly documents invariants #6 (strict path first-error wins) and #7 (tolerant path warning order). These are **observable** via `compile_golden_4406_test.go`. Splitting this orchestrator across files would break the contiguous-order guarantee and require cross-file ordering discipline.

- Each gate is already per-domain in its own `compiler_validate_strict_*.go` file; this file is the **single ordered call-site**, not the gate implementations.

**Verdict:** Keep as single file. Future work should NOT extract per-domain gate groups into separate orchestrator files.

### `compiler_validate_strict_filter.go` — single-domain strict validation

**Why it is cohesive:**

- 1660 LOC, 28 funcs, all strictly firewall-filter domain: `validateFirewallPolicerReferencesStrict`, `validateFirewallPrefixListReferencesStrict`, `validateFirewallRoutingInstanceReferencesStrict`, `validateFirewallFilterReferencesStrict`, `validateFilterProtocolsStrict`, `validateFilterCrossFieldStrict`, `validateFilterActionsStrict`, `validateFilterMatchValuesStrict`, `validateFilterFlexMatchStrict`, `validateFilterPortExceptStrict`, `validateFilterAddressExceptStrict`, `validateFilterAddressLiteralsStrict`, `validateFilterFromMatchStrict`, `validateFilterRoutingInstanceConflictStrict`, `validateFilterTerminalConflictStrict`, `validateFilterDSCPStrict`, plus helpers `filterDSCPResolvable`, `filterProtocolResolvable`, `protocolIsPortBearing`, etc.

- This file IS the per-domain split result of #4405 for the filter domain. Further splitting by individual gate would produce 15+ files each 80-150 LOC with shared helpers (`filterProtocolResolvable`, `protocolIsPortBearing`, `filterDSCPResolvable`, `classifyFilterAddrFamily`), increasing file count without reducing cognitive load.

- Companion `compiler_validate_strict_test.go` pattern (drift guards like `TestFilterProtocolResolvableMatchesProtocolNumber`) expects these helpers co-located.

**Verdict:** Keep as single file. Do NOT further split by gate.

### `types_system.go` 1544 LOC — borderline, but keep for now (D with reservation)

- 64 type definitions. While it mixes SystemConfig, UserspaceConfig, SNMP, Login, DHCP server, Services/RPM, FlowMonitoring, Sampling, **and** Firewall/Policer/Filter (firewall types logically belong in `types_security.go` or `types_firewall.go`), splitting Go type definitions across files is high-blast-radius (every `pkg/config` consumer + `pkg/dataplane/userspace` snapshot builder imports these types).

- The types are cohesive in the sense of "all types compiled by `compiler_system.go` + `compiler_services.go`" — a historical accident, but moving `FirewallConfig` / `PolicerConfig` / `FirewallFilter` to `types_firewall.go` would touch 20+ files and is not a mechanical rename.

- Recommendation: file a tracking issue for `types_system.go` firewall-type extraction, but do NOT block current modularity work on it. Low priority relative to compiler splits.

**Hot-path preservation:** N/A — negative findings, no change proposed.

**Dedup note:** `compiler_validate_strict_filter.go` was already per-domain split in #4405; `compiler_uniformgates.go` was created in #4406 step 4. Do not re-report these as "large monoliths needing split" — they ARE the split result, intentionally kept coarse at the domain/orchestrator level.

---

## Summary of proposed PR sequence (A findings only)

| Order | File(s) created | Source | LOC moved | Risk |
|-------|----------------|--------|-----------|------|
| 1 | `compiler_nat_helpers.go` | `compiler_nat.go` helpers (7 funcs + 1 const) | ~200 | Very low — pure helper move |
| 2 | (move) into `compiler_validate_strict_nat.go` | `compiler_nat.go` 4 strict gates | ~600 | Low — same package, same call site (`runUniformGates`) |
| 3 | `compiler_validate_warn_nat.go` + `_security.go` | `compiler_validate_warn.go` | ~800 | Low — pure warning func move |
| 4 | `compiler_system_login.go` + `_snmp.go` | `compiler_system.go` | ~450 | Low — well-bounded |
| 5 | `compiler_system_chassis.go` + `_ddns.go` + `_userspace.go` | `compiler_system.go` | ~900 | Medium — carries consts/vars |
| 6 | `compiler_services_rpm.go` | `compiler_services.go` 8 funcs | ~350 | Low |
| 7 | `compiler_services_dhcp.go` + `_flow.go` + `_ip_monitoring.go` | `compiler_services.go` | ~800 | Medium |

Each PR: `go build ./... && go test ./pkg/config -run ...` + decl-NAME set check per #4144. No logic change, no new dependencies.

---

## Dedup checklist

- [x] #4405 `compiler_validate_strict.go` 6997 LOC → CLOSED (now 478 + 11 per-domain files). Do NOT re-report.
- [x] #4421 `compiler_security.go` / `firewall-filter` / `rules.go` — separate issue, not re-reported here (filter strict is reported only as D-negative, not as A-split).
- [x] #4406 `compileExpanded` god-orchestrator → CLOSED (`compiler_prewalk.go`, `compiler_dispatch.go`, `compiler_derivations.go`, `compiler_earlystrict.go`, `compiler_uniformgates.go`, `compiler_tailgates.go`). `compiler_uniformgates.go` single-func orchestrator reported as D-negative.

---

## Hot-path preservation statement for all A findings

Go config compilers are **cold path** — `CompileConfig` / `CompileConfigLenient` / `CompileConfigForNode{,Lenient}` run once per operator commit, once per `Store.Load` (boot), and once per HA peer-sync. They are NOT called from `userspace-dp` per-packet path, VRRP advert loop, or HA heartbeat. All proposed splits are pure file moves with no logic change, same package (`package config`), same function signatures, same initialization order. Byte-identical behavior verified by `go build` + `go test ./pkg/config` passing and sorted top-level decl-NAME set unchanged.

One subtlety: `natAddrFamily` / `isHostMaskAddress` / `natCIDRIPPart` helpers are used across `compiler_nat.go`, `compiler_validate_strict_nat.go`, and `compiler_system.go:validateBackupRouterDst`. If extracted to `compiler_nat_helpers.go`, they must stay in `package config` so all existing call sites compile without import changes. Similarly, `schedulerWeekdays`, `ddnsProviderStringProps`, `sharedUMEMPhase0ArtifactMaxBytes`, `supportedRPMProbeTypes` must travel with their domain file.

---

## Labels for new issues

`refactor`, `modularity`, `pkg/config`, `A-mechanical` (findings 1-4), `D-do-not-split` (finding 5)

---

*Generated by modularity audit 039 (A3) against f70146951. Mechanical-split findings follow #4144 decl-NAME discipline.*


---

## Findings from a4 (/ps-review-039-a4.md)

## File-size / shape inventory

| File | LOC | Threshold | #func / #type | Smell |
|------|-----|-----------|---------------|-------|
| `pkg/config/compiler_validate_warn.go` | 3330 | >3000 CRITICAL | 35 funcs | Monolith — 35 warn validators in one file; strict counterpart already split per-domain |
| `pkg/dataplane/userspace/protocol.go` | 2979 | ~3000 CRITICAL | 72 type defs, 1 func | Wire-format fusion — ControlRequest + ConfigSnapshot (~20 snapshot subtypes) + ProcessStatus (~40 status subtypes) + ControlResponse + event-stream constants in one file |
| `pkg/vrrp/instance.go` | 2417 | >2000 | 52 funcs / 3 types | State-machine + RX + TX + GARP + advert-interval + preempt-hold + VIP management — single coherent SM but large |
| `pkg/daemon/daemon_run.go` | 2329 | >2000 | 9 funcs | Lifecycle bootstrap + naming + run-loop + exit — large but already decomposed per #4407 |
| `pkg/frr/policy_render.go` | 1938 | ~2000 | ~ | Slightly over; not inspected this batch |
| `pkg/daemon/daemon_apply.go` | 1935 | ~2000 | 20 funcs | applyConfigLocked ~1148 LOC — god-function; already filed #4407 |
| `pkg/api/metrics_descriptors.go` | 1896 | ~2000 | 279 NewDesc | Prometheus descriptor monolith — all subsystems in one file |
| `pkg/routing/tunnel.go` | 1877 | ~2000 | 3 types + ~30 funcs | Tunnel lifecycle + keepalive + WG MTU + VRF + address reconcile — 5 distinct responsibilities |
| `pkg/cluster/sync_conn.go` | 1858 | ~2000 | ~52 funcs | HA sync connection — gen-guard + fabric dial + bulk + sweep + delete-journal + config-sync + failover + barrier + liveness |
| `pkg/api/metrics_userspace.go` | 1819 | ~ | | Userspace metrics emitter — paired with descriptors |
| `pkg/dataplane/userspace/maps_sync.go` | 1763 | ~ | | Userspace map sync — focused, NOT a monolith (see D) |
| `pkg/dataplane/compiler.go` | 1733 | ~ | | Top-level compiler dispatch |
| `pkg/snmp/agent.go` | 1519 | ~ | | SNMP agent — focused |
| `pkg/daemon/daemon_ha.go` | 1511 | ~ | | HA chassis integration |
| `pkg/daemon/daemon_nft.go` | 1432 | ~ | | nftables host-inbound |
| `pkg/dataplane/userspace/manager_ha.go` | 1425 | ~ | | HA manager glue |
| `pkg/cli/cli_request.go` | 1328 | ~ | | Remote CLI request dispatch |
| `pkg/daemon/daemon_system.go` | 1310 | ~ | | System reconcile |

Total non-test Go in inspected dirs: ~244k LOC (`pkg/dataplane/userspace` + `pkg/daemon` + `pkg/cluster` + `pkg/routing` + `pkg/vrrp` + `pkg/api` + `pkg/config/compiler_*`). Batch top-5 already at 3330+2979+2417+2329+1938 = 13k LOC in 5 files.

---

## F-039-01: `protocol.go` 2979 LOC — wire-format monolith (12 domains fused)

- **Severity**: Medium (reviewability / merge-conflict / `mod touched` churn)
- **Confidence**: HIGH — mechanical
- **Refactor class**: **(A) MECHANICAL / SAFE** — cold path (config-apply + HA sync), pure code-motion

### Evidence

72 `type X struct` in one file, spanning 12 independent wire domains:

```go
// pkg/dataplane/userspace/protocol.go — all in one file:

type ControlRequest struct {        // control RPC envelope
    Type               string
    Snapshot           *ConfigSnapshot
    Forwarding         *ForwardingControlRequest
    HAState            *HAStateUpdateRequest
    Queue              *QueueControlRequest
    Binding            *BindingControlRequest
    Packet             *InjectPacketRequest
    SessionSync        *SessionSyncRequest
    SessionDeltas      *SessionDeltaDrainRequest
    SessionExport      *SessionExportRequest
    ...
}

type ConfigSnapshot struct {        // 30+ fields, 20+ snapshot subtypes
    Version         int
    Generation      uint64
    Zones           []ZoneSnapshot
    Interfaces      []InterfaceSnapshot
    Fabrics         []FabricSnapshot
    TunnelEndpoints []TunnelEndpointSnapshot
    Neighbors       []NeighborSnapshot
    Routes          []RouteSnapshot
    Policies        []PolicyRuleSnapshot
    SourceNAT       []SourceNATRuleSnapshot
    StaticNAT       []StaticNATRuleSnapshot
    DestinationNAT  []DestinationNATRuleSnapshot
    NAT64           []NAT64RuleSnapshot
    Screens         []ScreenProfileSnapshot
    Filters         []FirewallFilterSnapshot
    // ... + ClassOfService, FlowExport, AddressBooks, AppCatalog, ...
}

type ProcessStatus struct {         // ~150 fields, 40+ status subtypes
    PID                              int
    LastSnapshotRejectReasons        []string
    ZoneIDCollisions                 []string
    WorkerRuntime                    []WorkerRuntimeStatus
    CoSInterfaces                    []CoSInterfaceStatus
    PolicyRuleCounters               []PolicyRuleCounterStatus
    NATRuleCounters                  []NATRuleCounterStatus
    FilterTermCounters               []FirewallFilterTermCounterStatus
    SourceNATPools                   []SourceNATPoolStatus
    // ... + HAGroups, Fabrics, Queues, Bindings, PerBinding, FlowWorkerMap, WgTunnels, ...
}

type PolicyRuleSnapshot struct { ... }
type SourceNATRuleSnapshot struct { ... }  // 20+ fields
type StaticNATRuleSnapshot struct { ... }
type DestinationNATRuleSnapshot struct { ... } // 15+ fields inc MatchDestinationPorts, MatchSourcePorts, MatchICMPType
type BindingStatus struct { ... }              // 80+ fields — TX, CoS, mirror, flow-cache
type CoSQueueStatus struct { ... }             // 40+ fields — waterfill, admission, sojourn
type WorkerRuntimeStatus struct { ... }
type WgTunnelStatus struct { ... }
type SessionSyncRequest struct { ... }
type SessionDeltaInfo struct { ... }
// + 40 more
```

Responsibility count: ConfigSnapshot build (Go→Rust wire), ProcessStatus report (Rust→Go wire), ControlRequest/Response envelope, SessionSync wire, HA wire, CoS/QoS wire, NAT wire (4 flavors), Filter wire, Policy wire, Tunnel/WG wire, Factory/neighbor/route wire, Event-stream wire constants (8 more types below).

`wc -l` 2979, `grep -c "^type" ` 72. Compare `userspace-dp` Rust side: `protocol/snapshot.rs`, `protocol/control.rs`, `protocol/cos.rs`, `protocol/binding.rs`, `protocol/status.rs` are already split — Go side did not follow.

### Proposed decomposition

```
pkg/dataplane/userspace/
  protocol.go              // 200 LOC: const ProtocolVersion, ControlRequest, ControlResponse only
  protocol_snapshot.go     // ConfigSnapshot envelope (Version, Generation, Summary, Capabilities, MapPins)
  protocol_snapshot_nat.go // SourceNATRuleSnapshot, StaticNATRuleSnapshot, DestinationNATRuleSnapshot, NAT64RuleSnapshot, Nptv6RuleSnapshot, NatPortRangeWire, NatAppTermWire
  protocol_snapshot_policy.go // PolicyRuleSnapshot, PolicyApplicationSnapshot, AppCatalogEntrySnapshot, AddressBookSnapshot
  protocol_snapshot_filter.go // FirewallFilterSnapshot, FirewallTermSnapshot, FlexMatchSnapshot, PolicerSnapshot, ThreeColorPolicerSnapshot
  protocol_snapshot_network.go // ZoneSnapshot, InterfaceSnapshot, FabricSnapshot, TunnelEndpointSnapshot, TunnelWgPeerWire, RouteSnapshot, NeighborSnapshot, FlowSnapshot, ClassOfServiceSnapshot (+ CoS subtypes)
  protocol_snapshot_screen.go // ScreenProfileSnapshot, ScreenMissingProfileRef
  protocol_status.go       // ProcessStatus envelope + MarshalJSON/UnmarshalJSON (Must stay together — legacy alias)
  protocol_status_binding.go // BindingStatus, BindingCountersSnapshot, QueueStatus, Binding sub-types
  protocol_status_cos.go   // CoSInterfaceStatus, CoSQueueStatus, CoSActiveFlowCountStatus
  protocol_status_worker.go // WorkerRuntimeStatus, HAGroupStatus, SlowPathStatus
  protocol_status_counters.go // PolicyRuleCounterStatus, NATRuleCounterStatus, FirewallFilterTermCounterStatus, SourceNATPoolStatus, WgTunnelStatus, WgPeerStatus
  protocol_hasync.go       // SessionSyncRequest, SessionDeltaInfo, HAStateUpdateRequest, QueueControlRequest, BindingControlRequest, ForwardingControlRequest
  protocol_eventstream.go  // EventFrameHeaderSize, EventType*, SessionEventFlag* constants (already at bottom of current file, lines 2924-2979 — trivial extract)
  wire_uint8list.go        // already exists — WireUint8List stays
```

Each file <500 LOC. All `json` tags unchanged. `go vet` + `go test ./pkg/dataplane/userspace -run TestProtocol` byte-identical — JSON wire is stable (field names unchanged, only file location moves).

### Hot-path preservation

Cold path — protocol.go is used only on `ApplyConfig` (commit) and `PollStatus` (1/s). NOT per-packet hot. Split is (A) pure code-motion.

### Tests+gate

- `go test ./pkg/dataplane/userspace -run TestProtocol -count=1` — existing `protocol_test.go` (1914 LOC) and `protocol_null_collections_2214_test.go` must pass
- `go test ./pkg/dataplane/userspace -run TestSnapshot -count=1`
- `make build` — byte-identical `xpfd` binary (wire format unchanged)

### Why it matters

- Merge conflicts: 12 domains → any CoS change conflicts with any NAT change
- Reviewability: reviewer must load 2979 LOC to review a 10-line NAT field addition
- `engineering-style.md` "No monolithic files — ~2k LOC is a smell, ~3k LOC must split before adding logic"

### Fix direction

Mechanical file split, `package userspace` unchanged. Keep `ProcessStatus.MarshalJSON` + `UnmarshalJSON` together in `protocol_status.go` (they are a pair). No behavior change. File-level PR #4669 (manager_test.go split) shows precedent.

### Labels

`refactor`, `modularity`, `tech-debt`, `cold-path`, `mechanical`

### Dedup note

Not filed before. No prior issue for `protocol.go` split (GH search `protocol.go monolith` returns 0). Distinct from #4404-#4406 (Rust poll_descriptor) and #4407-#4409 (daemon god-struct / NAT).

---

## F-039-02: `sync_conn.go` 1858 LOC — HA sync connection monolith (8 responsibilities fused)

- **Severity**: HIGH (correctness risk — generation-guard ordering #2995/#2170/#2221/#2198 is subtle, single-file makes it hard to review)
- **Confidence**: MEDIUM — split is safe but must preserve lock ordering and single-active-fabric invariant
- **Refactor class**: **(A) MECHANICAL with ORDERING CONSTRAINTS** — cold path (HA sync is 1/s sweep + on-demand, NOT per-packet hot), but generation-guard state machine must stay atomic

### Evidence

All HA sync connection logic in one file (`pkg/cluster/sync_conn.go`):

```go
// pkg/cluster/sync_conn.go — 1858 LOC, ~52 funcs:

// 1. Generation-guard state machine (#2170/#2221/#2198/#2995) — 200+ lines:
func putGenBounded[K comparable](m map[K]uint64, key K, gen uint64) bool { ... }
func (s *SessionSync) nextInstallGen() uint64 { ... }
func (s *SessionSync) stampInstallGenV4(key dataplane.SessionKey, val *dataplane.SessionValue) { ... }
func (s *SessionSync) stampInstallGenV6(...) { ... }
func (s *SessionSync) takeDeleteGenV4(key dataplane.SessionKey) uint64 { ... } // #2221 fresh delete gen
func (s *SessionSync) takeDeleteGenV6(...) uint64 { ... }
func (s *SessionSync) installGenGuardV4(key dataplane.SessionKey, incoming uint64) (record uint64, apply bool) { ... }
func (s *SessionSync) installGenGuardV6(...) (...) { ... }
func (s *SessionSync) recordInstalledGenV4(...) { ... }
func (s *SessionSync) recordInstalledGenV6(...) { ... }
func (s *SessionSync) deleteGenGuardV4(key dataplane.SessionKey, deleteGen uint64) bool { ... }
func (s *SessionSync) deleteGenGuardV6(...) bool { ... }
func (s *SessionSync) resetRecvGen() { ... } // #2198 F2 bulk re-prime

// 2. Session apply (depends on gen-guard):
func (s *SessionSync) installClusterSyncedV4(...) { ... }
func (s *SessionSync) installClusterSyncedV6(...) { ... }
func (s *SessionSync) deleteClusterSyncedV4(...) { ... }
func (s *SessionSync) deleteClusterSyncedV6(...) { ... }

// 3. Fabric dial + active-conn selection:
func shouldInitiateFabricDial(localAddr, peerAddr string) bool { ... }
func (s *SessionSync) activeConnLocked() net.Conn { ... }
func (s *SessionSync) getActiveConn() net.Conn { ... }
func connRemoteAddrString(conn net.Conn) (remote string) { ... }
func connLocalAddrString(conn net.Conn) (local string) { ... }
func configureSessionSyncConn(conn net.Conn) { ... }

// 4. Connection lifecycle (listener, dialer, reconnect, disconnect):
func (s *SessionSync) handleNewConnection(ctx context.Context, fabricIdx int, conn net.Conn) { ... } // ~80 LOC, cold-start bulk decision
func (s *SessionSync) Start(ctx context.Context) error { ... }
func (s *SessionSync) Stop() { ... }
func (s *SessionSync) StartSyncSweep(ctx context.Context) { ... }
func (s *SessionSync) acceptLoop(ctx context.Context, ln net.Listener, fabricIdx int) { ... }
func (s *SessionSync) fabricConnectLoop(ctx context.Context, fabricIdx int, peerAddr string) { ... }
func (s *SessionSync) sendLoop(ctx context.Context) { ... }
func (s *SessionSync) receiveLoop(ctx context.Context, conn net.Conn) { ... }
func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) { ... } // ~350 LOC, 20+ msg types
func (s *SessionSync) handleDisconnect(conn net.Conn) { ... } // ~140 LOC, bulk re-drive #4090/#4360

// 5. Incremental sweep + backpressure:
func (s *SessionSync) sweepIntervals() (...) { ... }
func sweepIntervalsForDataPlane(dp any) (...) { ... }
func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool { ... }
func (s *SessionSync) syncSweep() int { ... } // ~110 LOC, ForEachV4+ForEachV6+journal flush
func (s *SessionSync) PauseIncrementalSync(reason string) { ... }
func (s *SessionSync) ResumeIncrementalSync(reason string) { ... }
func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool { ... }

// 6. Delete journal (bounded ring, rejournalTail, flush):
func (s *SessionSync) QueueSessionV4(...) { ... }
func (s *SessionSync) QueueSessionV6(...) { ... }
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) { ... }
func (s *SessionSync) QueueDeleteV6(...) { ... }
func (s *SessionSync) journalDelete(msg []byte) { ... }
func (s *SessionSync) flushDeleteJournal() { ... }
func (s *SessionSync) rejournalTail(tail [][]byte) { ... }

// 7. Config sync (monotonic config gen #3931/#4151):
func (s *SessionSync) nextConfigGen() uint64 { ... }
func (s *SessionSync) QueueConfig(configText string) { ... }
func (s *SessionSync) shouldApplyConfigGen(gen uint64) bool { ... }
func (s *SessionSync) recordAppliedConfigGen(gen uint64) { ... }
func (s *SessionSync) configApplyLoop(ctx context.Context) { ... }

// 8. Liveness keepalive + clock sync:
func (s *SessionSync) SendLivenessKeepalive() { ... }
func (s *SessionSync) sendClockSync(conn net.Conn) { ... }
```

`sync.go` (shared types) adds another ~800 LOC with `SessionSync` struct definition (30+ fields), `SyncStats`, `TransferReadinessSnapshot`, failover types, sweep profiler iface. Total `sync*.go` = ~2658 LOC in 2 files for what is 8 subsystems.

Responsibility boundaries:
- Gen-guard (stamp/take/guard/record/reset) — pure state machine, no I/O
- Fabric connection (dial/listen/activeConn) — net.Conn lifecycle
- Bulk sync (doBulkSync → sendBulkMarkers → BulkStart/End, reconcileStaleSessions, resetRecvGen)
- Sweep (ForEach + queueMessage + backpressure)
- Delete journal (journalDelete / flush / rejournalTail)
- Config sync (nextConfigGen / QueueConfig / configApplyLoop / shouldApply/record)
- Failover/barrier/clock (handleMessage 20 branches, handleDisconnect bulk re-drive)
- Liveness (SendLivenessKeepalive, sendClockSync, receiveLoop heartbeat)

### Proposed decomposition

```
pkg/cluster/
  sync.go              // SessionSync struct, SyncStats, constructor, Setters (keep — ~300 LOC)
  sync_conn.go         // Connection lifecycle only: Start, Stop, handleNewConnection, acceptLoop, fabricConnectLoop, sendLoop, receiveLoop, handleDisconnect, activeConnLocked, getActiveConn, shouldInitiateFabricDial, configureSessionSyncConn, connRemote/LocalAddrString (~600 LOC)
  sync_gen_guard.go    // Generation-guard state machine: putGenBounded, nextInstallGen, stampInstallGenV4/V6, takeDeleteGenV4/V6, installGenGuardV4/V6, recordInstalledGenV4/V6, deleteGenGuardV4/V6, resetRecvGen, installClusterSyncedV4/V6, deleteClusterSyncedV4/V6, noteHelperMirrorResult — the #2170/#2221/#2198/#2995 family + genGuardMapCap const (pure logic, no I/O) (~350 LOC)
  sync_sweep.go        // Sweep + backpressure: StartSyncSweep, sweepIntervals, sweepIntervalsForDataPlane, ShouldSyncZone, syncSweep, PauseIncrementalSync, ResumeIncrementalSync, queueMessage (~250 LOC)
  sync_delete_journal.go // Delete journal: QueueSessionV4/V6, QueueDeleteV4/V6, journalDelete, flushDeleteJournal, rejournalTail, deleteJournalDefaultCap (~200 LOC)
  sync_config.go       // Config sync: nextConfigGen, QueueConfig, shouldApplyConfigGen, recordAppliedConfigGen, configApplyLoop, configApplyItem (~120 LOC)
  sync_message.go      // Wire dispatch: handleMessage (split by msg type group), sendClockSync, SendLivenessKeepalive (~400 LOC)
  sync_protocol.go     // Already exists — encode/decode helpers (keep)
  sync_bulk.go         // Already exists — doBulkSync, sendBulkMarkers, reconcileStaleSessions, snapshotZoneOwnership (keep)
  sync_failover.go     // Already exists — failover request/ack/commit (keep)
  sync_auth.go         // Already exists (keep)
  sync_state.go        // Already exists (keep)
```

Key invariant to preserve: the comment at `sync_conn.go:304-320` (`Non-atomicity note #2198 F3`) — "apply sequence does NOT hold recvGenMu across whole sequence; safe because receiver apply path for given peer is single-threaded (one receiveLoop goroutine over single ACTIVE fabric)". Split must NOT introduce a new mutex or change lock ordering. The gen-guard map mutations (`genSentMu`, `recvGenMu`) stay in `sync_gen_guard.go` with identical signatures.

### Hot-path preservation

Cold path — HA sync runs at 1s active / 10s idle sweep cadence, not per-packet. `handleMessage` runs on receiveLoop (one goroutine per fabric), not on dataplane hot path. Split must preserve generation-guard ordering (e.g., `stampInstallGen` before `queueMessage`, `takeDeleteGen` draws fresh `nextInstallGen` before evict, delete tombstone before install guard). No per-packet hop added.

### Tests+gate

- `go test ./pkg/cluster -run TestGenGuard -count=1` — existing `sync_gen_guard_test.go` (must pass)
- `go test ./pkg/cluster -run TestSync -count=1` — `sync_test.go` (4717 LOC) + `sync_conn` sweep/journal tests
- `make test-failover` — cluster failover timing (gen-guard regression would surface as stale-delete / stale-RETAIN)
- Byte-identical `go build`: `go vet ./pkg/cluster`

### Why it matters

- Generation-guard is the most subtle state machine in the repo (#2170 stale-delete, #2221 stale-RETAIN, #2198 bulk reset, #2995 ordering, #4151 config M-2). Reviewing a gen-guard fix currently requires loading 1858 LOC of unrelated fabric-dial / sweep / delete-journal code.
- `handleMessage` 350 LOC with 20+ branches shares file with gen-guard — a sweep change can silently break a bulk-reset invariant.
- `handleDisconnect` bulk re-drive (#4090/#4360) holds `s.mu` while spawning goroutine that re-locks `s.mu` via `getActiveConn` inside `doBulkSync` — deadlock risk is invisible when the whole file is one unit.

### Fix direction

Mechanical split per responsibility, `package cluster` unchanged, `SessionSync` struct stays in `sync.go` (single source of truth), each new file takes methods operating on `*SessionSync` with identical receivers. Preserve `// Must hold mu` / `// Must hold recvGenMu` comments and `#2198 F3` non-atomicity note as file header. PR should be pure code-motion (no logic change), verified by `git diff --stat` showing only file moves.

### Labels

`refactor`, `modularity`, `ha`, `gen-guard`, `cold-path`, `mechanical`, `ordering-sensitive`

### Dedup note

Not filed before. GH search `sync_conn gen-guard split` returns 0. Distinct from #4407 daemon god-struct. Related to ongoing #4090/#4360 re-drive fixes which touch this file — split makes those reviews safer.

---

## F-039-03: `tunnel.go` 1877 LOC — tunnel lifecycle + keepalive + WireGuard + MTU + VRF (5 responsibilities)

- **Severity**: Medium
- **Confidence**: HIGH — cold path (tunnel create on commit, keepalive tick 1s+)
- **Refactor class**: **(A) MECHANICAL / SAFE**

### Evidence

```go
// pkg/routing/tunnel.go — 1877 LOC:

// Responsibility 1: Tunnel manager struct + reconcile maps (GRE/IPIP/Anchor/WG ownership)
type tunnelManager struct {
    ops       linkOps
    vrfBinder vrfBinder
    prober    tunnelProber
    mu         sync.Mutex
    tunnels    []string
    keepalives map[string]*keepaliveRunner
    linkGen    map[string]*atomic.Uint64
    ownedNames map[string]bool
    appliedAddrs map[string]map[string]bool
    appliedRI  map[string]string
    wgConfigured map[string]bool
}

// Responsibility 2: GRE/IPIP lifecycle + legacy tunnel match + anchor TUN
func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error { ... } // ~190 LOC
func anchorReusable(link netlink.Link) bool { ... }
func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) { ... } // ~130 LOC
func (t *tunnelManager) applyKernelTunnelLocked(tc *config.TunnelConfig) { ... } // ~160 LOC
func buildKernelTunnelLink(tc *config.TunnelConfig, ...) netlink.Link { ... }
func legacyTunnelMatches(existing, desired netlink.Link) bool { ... }

// Responsibility 3: WireGuard TUN + MTU derivation
const wgOverheadV4 = 60 // 20+8+16+16
const wgOverheadV6 = 80
const wgDefaultOuterMTU = 1500
const wgEngineMaxInnerMTU = 4096
func wgTunMTUForEndpoint(tc *config.TunnelConfig) int { ... } // ~40 LOC
func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error { ... } // ~100 LOC

// Responsibility 4: Keepalive ICMP probe + generation guard + lifecycle
type KeepaliveState struct { mu sync.Mutex; Up bool; Failures int; Unknown bool; UnknownKind UnsupportedKind; ... }
type keepaliveRunner struct { cancel context.CancelFunc; state *KeepaliveState; done chan struct{}; remote string; source string; linkGen *atomic.Uint64; ... }
func (t *tunnelManager) keepaliveProber() tunnelProber { ... }
func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, ...) { ... }
func (t *tunnelManager) stopKeepaliveLocked(name string) { ... }
func (t *tunnelManager) stopAllKeepalivesLocked() { ... }
func (t *tunnelManager) keepaliveLoop(ctx context.Context, done chan struct{}, ...) { ... }
func (t *tunnelManager) keepaliveTick(tunnelName string, state *KeepaliveState, ...) { ... } // ~90 LOC, §6 Axis D commit-after-success
func nextSeq(state *KeepaliveState) int { ... }
func keepaliveProbeDeadline(intervalSec int) time.Duration { ... }

// Responsibility 5: VRF binding + address reconcile (reconcile-in-place #1884)
func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) { ... } // ~80 LOC
func (t *tunnelManager) observeListClaimLocked(tc *config.TunnelConfig, link netlink.Link) { ... }
func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool { ... } // ~100 LOC
func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) (map[string]bool, bool) { ... } // ~40 LOC
func (t *tunnelManager) finishTunnelLocked(tc *config.TunnelConfig, link netlink.Link, skipUp bool, kind string) { ... }
func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState { ... }
func (t *tunnelManager) GetStatus() ([]TunnelStatus, error) { ... }
func (t *tunnelManager) Clear() error { ... }
func (t *tunnelManager) clearLocked() error { ... }
```

5 distinct responsibilities in one file. `tunnelManager` holds 8 maps + 3 interfaces, all guarded by one `mu` but with different lock disciplines (`keepaliveTick` never takes `t.mu` — AGY r5). The keepalive state machine (§6 Axis D commit-after-success: classify → intent → LinkByName → gen.Load() → LinkSetUp/Down → commit Up) is interleaved with tunnel creation — reviewer cannot verify the keepalive invariant without loading GRE/IPIP creation.

### Proposed decomposition

```
pkg/routing/
  tunnel.go              // tunnelManager struct + Apply + Clear + clearLocked + GetStatus + GetKeepaliveState + ensureReconcileStateLocked + linkGenForLocked + bumpLinkGenLocked + linkOps/vrfBinder interfaces + errWGIncompatibleLinkRetained (~300 LOC)
  tunnel_gre.go          // applyKernelTunnelLocked + buildKernelTunnelLink + legacyTunnelMatches + ipEqual + applyAnchorLocked + reconcileAnchorMTULocked + anchorReusable + finishTunnelLocked (~400 LOC)
  tunnel_wireguard.go    // applyWireguardTunLocked + wgTunMTUForEndpoint + wgOverheadV4/V6 + wgDefaultOuterMTU + wgEngineMaxInnerMTU + closeTuntapFiles (~250 LOC)
  tunnel_keepalive.go    // KeepaliveState, keepaliveRunner, keepaliveRunner.matches, keepaliveProber, startKeepalive, stopKeepaliveLocked, stopAllKeepalivesLocked, keepaliveLoop, keepaliveTick, nextSeq, keepaliveProbeDeadline, clearUnknownLocked, markUnknownLocked, classifyErrnoString (~500 LOC)
  tunnel_reconcile.go    // reconcileLinkAddrsLocked, pruneAppliedAddrsLocked, reconcileVRFClaimLocked, observeListClaimLocked, stopAll, TunnelStatus (~350 LOC)
  tunnel_prober.go       // tunnelProber interface + icmpProber + UnsupportedKind + ProbeResult (already small, but separate for testability)
```

Each file <500 LOC. No new mutexes. `tunnelManager.mu` stays in `tunnel.go`. `keepaliveTick` lock-free discipline preserved (never takes `t.mu`). `closeTuntapFiles` stays with wireguard (its only caller).

### Hot-path preservation

Cold path — tunnel creation runs on `applyConfigLocked` (commit), keepalive tick runs at `Keepalive` interval (seconds, 1/s+). NOT per-packet hot. Split is (A) mechanical, no hot-path change.

### Tests+gate

- `go test ./pkg/routing -run TestTunnel -count=1` — existing `routing_test.go` + `tunnel_reconcile_test.go` (1649 LOC)
- `go test ./pkg/routing -run TestKeepalive -count=1`
- `go vet ./pkg/routing`

### Why it matters

- `tunnel.go` is the highest-churn file in `pkg/routing` — every GRE/WG/keepalive/VRF fix touches it (git log: #1884 reconcile-in-place, #1918 hold-on-unknown, #1919 WG prune, #4071 keepalive on anchor, #2457 MTU clamp, #2300 MTU model). Monolith makes each review load 1877 LOC.
- Keepalive §6 Axis D invariant (commit-after-success: "classify + commit counters → compute intent → LinkByName → gen.Load → LinkSet → commit Up") is documented across 50+ lines of comments but interleaved with GRE creation — hard to verify in review.

### Fix direction

Mechanical file split, `package routing` unchanged. Keep `tunnelManager` struct in `tunnel.go`. Each new file's functions keep `(t *tunnelManager)` receiver. Preserve all `#1884`/`#1918`/`#1919`/`#4071` comments verbatim (they are load-bearing for reviewers).

### Labels

`refactor`, `modularity`, `tunnel`, `keepalive`, `wireguard`, `cold-path`, `mechanical`

### Dedup note

Not filed before. GH search `tunnel.go keepalive split` returns 0. Distinct from #4421 (flowexport monolithic) and #4408-#4409 (NAT). `pkg/routing/rules.go` 3-domains (nextTable/ribGroup/pbrManager) was noted in #4421 but is a different file.

---

## F-039-04: `compiler_validate_warn.go` 3330 LOC — warn validators monolith (strict already split)

- **Severity**: Medium (reviewability — warn and strict should be symmetric)
- **Confidence**: HIGH — mechanical per-domain split, proven pattern
- **Refactor class**: **(A) MECHANICAL / SAFE** — cold path (commit-time validation), pure code-motion, `ValidateConfig` is additive (`[]string` warnings, no error)

### Evidence

```go
// pkg/config/compiler_validate_warn.go — 3330 LOC, 35 funcs:

func ValidateConfig(cfg *Config) []string { // ~1600 LOC — top-level orchestrator + inline policy/interface/app validation
    var warnings []string
    // 50-200 LOC each: zones, addrs, apps, policies (FromZone/ToZone, address refs, port specs, protocols),
    // timers, screens, NAT, firewall, routing, scheduler, CoS, DDNS, etc.
    warnings = append(warnings, validateHostInboundMulticastWarnings(cfg)...)
    warnings = append(warnings, validateDHCPRelayParityWarnings(cfg)...)
    warnings = append(warnings, validateInterfaceParityWarnings(cfg)...)
    warnings = append(warnings, validateDefaultPolicyLogWarnings(cfg)...)
    // ... 15 more
    return warnings
}

// 34 helper validators — each is a self-contained per-domain warning:
func validateHostInboundMulticastWarnings(cfg *Config) []string { ... }   // ~50 LOC
func validateDHCPRelayParityWarnings(cfg *Config) []string { ... }        // ~40 LOC
func validateInterfaceParityWarnings(cfg *Config) []string { ... }        // ~60 LOC
func validateDefaultPolicyLogWarnings(cfg *Config) []string { ... }
func validatePolicyLogInertOnDenyWarnings(cfg *Config) []string { ... }
func validateJunosHostDirectDeliveryWarnings(cfg *Config) []string { ... }
func validatePreIDDefaultPolicyLogWarnings(cfg *Config) []string { ... }
func validateFilterLossPriorityWarnings(cfg *Config) []string { ... }
func validateFirewallInterfaceSpecificWarnings(cfg *Config) []string { ... }
func validateLo0FilterKernelMirrorWarnings(cfg *Config) []string { ... }
func validateFilterNoCatchAllWarnings(cfg *Config) []string { ... }
func validateDDNSBackendWarnings(cfg *Config) []string { ... }          // ~260 LOC
func validateSurfaceADDNSWarnings(cfg *Config) []string { ... }          // ~300 LOC
func validateRoutingRuleWindowWarnings(cfg *Config) []string { ... }
func validateRibGroupLeakWarnings(cfg *Config) []string { ... }
func validateCoSOversubscriptionWarnings(cos *ClassOfServiceConfig) []string { ... }
func classOfServiceClassifierQueueWarnings(cos *ClassOfServiceConfig, ...) []string { ... }
func anySamplingDirectionConfigured(cfg *Config) bool { ... }
```

Meanwhile, `compiler_validate_strict*.go` is already split:

```
pkg/config/compiler_validate_strict.go              // 200 LOC — top-level strict orchestrator
pkg/config/compiler_validate_strict_application.go  // per-domain
pkg/config/compiler_validate_strict_chassis.go
pkg/config/compiler_validate_strict_cos.go
pkg/config/compiler_validate_strict_filter.go       // 1660 LOC (the largest strict domain — already split once)
pkg/config/compiler_validate_strict_ipsec.go
pkg/config/compiler_validate_strict_nat.go
pkg/config/compiler_validate_strict_observability.go
pkg/config/compiler_validate_strict_policy.go
pkg/config/compiler_validate_strict_routing.go
pkg/config/compiler_validate_strict_screen.go
pkg/config/compiler_validate_strict_vrrp.go
pkg/config/compiler_validate_strict_zones.go
pkg/config/compiler_validate_vrf_overlap.go
pkg/config/compiler_validate_wireguard.go
```

`compiler_validate_strict` shows the proven mechanical split — 12 files, each per-domain, each <900 LOC. `compiler_validate_warn.go` at 3330 LOC is the only file that did NOT follow this pattern. It contains the same per-domain structure (each `validateXWarnings` is independent) but was never split.

### Proposed decomposition

```
pkg/config/
  compiler_validate_warn.go              // ValidateConfig top-level + inline policy/interface/app (keep ~800 LOC — the main orchestrator that calls 15 validators)
  compiler_validate_warn_hostinbound.go  // validateHostInboundMulticastWarnings + validateJunosHostDirectDeliveryWarnings + junosHostPolicySourceScoped + junosHostPolicyStricterThanCoarseGate + validatePreIDDefaultPolicyLogWarnings (~300 LOC)
  compiler_validate_warn_filter.go       // validateFilterLossPriorityWarnings + validateFirewallInterfaceSpecificWarnings + validateLo0FilterKernelMirrorWarnings + validateFilterNoCatchAllWarnings + schedulerHasEffectiveWindow + firewallFilterHasCatchAllTerminator + firewallTermIsTerminatingAction + firewallTermFromUnconstrained (~350 LOC)
  compiler_validate_warn_ddns.go         // validateDDNSBackendWarnings + ddnsUpdateServerParseable + ddnsTSIGAlgorithmSupported + ddnsKnownDyndns2Provider + ddnsDyndns2ServerValid + ddnsCheckIPURLValid + ddnsGenericURLTemplateValid + ddnsAllowlistMalformedTokens + validateSurfaceADDNSWarnings (~400 LOC)
  compiler_validate_warn_routing.go      // validateRoutingRuleWindowWarnings + validateRibGroupLeakWarnings + validateCoSOversubscriptionWarnings + classOfServiceClassifierQueueWarnings + hasFamily + anySamplingDirectionConfigured (~250 LOC)
  compiler_validate_warn_parity.go       // validateDHCPRelayParityWarnings + validateInterfaceParityWarnings + validateDefaultPolicyLogWarnings + validatePolicyLogInertOnDenyWarnings (~300 LOC)
```

Each file <500 LOC. `ValidateConfig` stays in `compiler_validate_warn.go`, imports the helpers (all `package config`, same dir, no import change). Existing `compiler_validate_warn_nil_3494_test.go` keeps passing.

### Hot-path preservation

Cold path — `ValidateConfig` runs on `Commit()` (commit-time, seconds apart). NOT per-packet hot. Split is (A) pure code-motion, byte-identical warnings slice.

### Tests+gate

- `go test ./pkg/config -run TestValidateConfig -count=1`
- `go test ./pkg/config -run TestValidateWarn -count=1` (if exists) + `TestValidateWarn_Nil_3494`
- `go vet ./pkg/config`
- Verify warnings output identical: compare `ValidateConfig(cfg)` before/after split for a corpus of test configs

### Why it matters

- `compiler_validate_warn.go` is the largest file in `pkg/config` (3330 LOC) and the only one that violates the per-domain split pattern the strict validators already established. Every new warning (DDNS #2780, surface-A #4407, CoS #1614, filter #2321) lands in this one file → merge conflicts + reviewer must load 3330 LOC for a 20-line warning.
- `engineering-style.md` "No monolithic files — ~2k LOC is a smell, ~3k must split before adding logic" — this file is 3330 LOC and still growing (last 3 months: +~400 LOC for surface-A DDNS warnings).

### Fix direction

Mechanical file split mirroring `compiler_validate_strict*.go` domain boundaries. `package config` unchanged. Functions stay identical (copy-paste to new files, delete from original). No behavior change. PR should be `go fmt` clean, `git diff --stat` shows file moves only.

### Labels

`refactor`, `modularity`, `validation`, `config`, `cold-path`, `mechanical`, `strict-parity`

### Dedup note

Not filed before. GH search `compiler_validate_warn split` returns 0. Distinct from #4421 which notes `compiler_security.go` but not `compiler_validate_warn.go`. The strict split (`compiler_validate_strict_*.go`) is complete and is the template for this fix.

---

## F-039-05: `metrics_descriptors.go` 1896 LOC — Prometheus descriptor monolith

- **Severity**: Low-Medium (reviewability / merge conflicts, NOT correctness)
- **Confidence**: HIGH — mechanical, no logic
- **Refactor class**: **(A) MECHANICAL / SAFE** — cold path (metrics_descriptors is only `newCollector` construction, `prometheus.NewDesc` calls; scrape path reads already-constructed descriptors)

### Evidence

```go
// pkg/api/metrics_descriptors.go — 1896 LOC, 279 prometheus.NewDesc calls:

func newCollector(srv *Server) *xpfCollector {
    return &xpfCollector{
        srv: srv,
        packetsTotal: prometheus.NewDesc(
            "xpf_packets_total",
            "Total packets processed.",
            []string{"direction"}, nil,
        ),
        dropsTotal: prometheus.NewDesc(
            "xpf_drops_total",
            "Packets dropped by enforcement (policy deny, screen/IDS, ...)",
            nil, nil,
        ),
        counterReadErrorsTotal: prometheus.NewDesc(...),
        sessionsCreatedTotal: prometheus.NewDesc(...),
        sessionsClosedTotal: prometheus.NewDesc(...),
        screenDropsTotal: prometheus.NewDesc(...),
        screenDropsByReasonTotal: prometheus.NewDesc(...),
        policyDeniesTotal: prometheus.NewDesc(...),
        natAllocFailsTotal: prometheus.NewDesc(...),
        nat64XlateTotal: prometheus.NewDesc(...),
        hostInboundDeny: prometheus.NewDesc(...),
        hostInboundKernelDenies: prometheus.NewDesc(...),
        hostInboundAddresslessZones: prometheus.NewDesc(...),
        hostInboundAddresslessIface: prometheus.NewDesc(...),
        hostInboundAmbiguousAddrs: prometheus.NewDesc(...),
        tcEgressPacketsTotal: prometheus.NewDesc(...),
        syncookieTotal: prometheus.NewDesc(...),
        flowCacheTotal: prometheus.NewDesc(...),
        ifacePacketsTotal: prometheus.NewDesc(...),
        ifaceBytesTotal: prometheus.NewDesc(...),
        // ... + 260 more NewDesc calls:
        // userspace_* (session table, NAT collisions, WireGuard, GRE decap, CoS admission, flow cache, event stream),
        // binding_* (active flow count, TX completions, VMin throttles),
        // cos_* (admission drops, drain, equal-flow, flow-fair, waterfill, sojourn),
        // worker_* (cold path buckets, samples, sum_ns, alias, layout version),
        // fairness_* (Cstruct, active workers, active flows, CoV, equal-flow target/observed/capped/suppressed),
        // daemon_* (uptime, RSS), config_persist_degraded, etc.
    }
}
```

279 `prometheus.NewDesc` in one function. Categories by prefix (from `grep NewDesc | sed ... | sort`):

- Global datapath (15): `xpf_packets_total`, `xpf_drops_total`, `xpf_counter_read_errors_total`, `xpf_sessions_created_total`, `xpf_sessions_closed_total`, `xpf_screen_drops_*`, `xpf_policy_denies_total`, `xpf_nat_alloc_failures_total`, `xpf_nat64_*`, `xpf_host_inbound_*`, `xpf_tc_egress_*`, `xpf_syncookie_*`, `xpf_flow_cache_*`, `xpf_iface_*`
- Userspace dataplane (40+): `xpf_userspace_session_table_*`, `xpf_userspace_nat_reverse_key_*`, `xpf_userspace_session_create_drops`, `xpf_userspace_gre_decap_*`, `xpf_userspace_wg_decap_*`, `xpf_userspace_time_exceeded_*`, `xpf_userspace_packet_too_big_*`, `xpf_userspace_reject_*`, `xpf_userspace_flow_cache_*`, `xpf_userspace_event_stream_*`
- CoS / scheduler (25+): `xpf_cos_admission_*`, `xpf_cos_drain_*`, `xpf_cos_equal_flow_*`, `xpf_cos_flow_fair_*`, `xpf_cos_lease_*`, `xpf_cos_owner_pps`, `xpf_cos_waterfill_*`, `xpf_cos_sojourn_*`
- Worker / cold-path (20+): `xpf_worker_dead`, `xpf_worker_cold_path_*` (8 variants + v3)
- Binding (10): `xpf_binding_active_flow_count`, `xpf_binding_flow_cache_capacity`, `xpf_binding_tx_*`, `xpf_binding_v_min_*`
- Fairness / flow table (15): `xpf_fairness_cstruct`, `xpf_fairness_active_*`, `xpf_fairness_observed_cov`, `xpf_fairness_equal_flow_*`
- System / daemon (5): `xpf_daemon_uptime`, `xpf_daemon_mem_rss`, `xpf_config_persist_degraded`

Every new feature (CoS #706/#718, WireGuard #1432, cold-path #1635, fairness #941, binding #878, etc.) adds 2-8 descriptors to this one file — linear growth (279 → will be 300+ by next quarter).

### Proposed decomposition

`metrics_descriptors.go` defines `newCollector` returning `*xpfCollector`. The `xpfCollector` struct is defined elsewhere (likely `metrics.go` or `metrics_counters.go`). The descriptors are stored as fields. The split strategy: keep struct definition in one place, split descriptor construction via helper functions:

```
pkg/api/
  metrics_descriptors.go              // newCollector top-level (calls helpers, ~100 LOC) + global datapath descriptors (packets, drops, counter_read_errors, sessions, screen, policy, nat, host-inbound, tc, syncookie, flow-cache, iface) — the stable core
  metrics_descriptors_userspace.go    // newCollectorUserspace — userspace dataplane descriptors (session table, NAT, WireGuard, GRE, ECN, reject, flow-cache, event-stream, neighbor, session publish) (~400 LOC)
  metrics_descriptors_cos.go          // newCollectorCoS — CoS/queue descriptors (admission, drain, equal-flow, flow-fair, lease, owner, waterfill, sojourn) (~300 LOC)
  metrics_descriptors_binding.go      // newCollectorBinding — binding-scoped descriptors (active flow count, TX, VMin) (~150 LOC)
  metrics_descriptors_worker.go       // newCollectorWorker — worker + cold-path descriptors (worker_dead, cold_path_bucket/samples/sum_ns/alias/layout, v3) (~250 LOC)
  metrics_descriptors_fairness.go     // newCollectorFairness — fairness harness descriptors (Cstruct, active workers/flows, CoV, equal-flow target/observed/capped/suppressed) (~250 LOC)
  metrics_descriptors_system.go       // newCollectorSystem — daemon/system descriptors (uptime, RSS, config_persist_degraded) (~50 LOC)
```

Alternative (simpler): keep `newCollector` in one file, extract only descriptor literals to helper funcs returning `*prometheus.Desc` per subsystem. This avoids struct-field reordering and keeps `xpfCollector` field init in one call site.

Simpler decomposition (no helper funcs, just file split on struct literal comments):

```
pkg/api/
  metrics_descriptors_global.go    // packetsTotal, dropsTotal, counterReadErrorsTotal, sessions*, screen*, policyDeniesTotal, nat*, hostInbound*, tc*, syncookie, flowCache, iface* — stable core
  metrics_descriptors_userspace.go // userspace* — session table, NAT, WG, GRE, reject, flow-cache, event-stream
  metrics_descriptors_cos.go       // cos*, binding*, fairness equal-flow
  metrics_descriptors_worker.go    // worker*, cold_path*
  metrics_descriptors_fairness.go  // fairness* (harness)
  metrics_descriptors_system.go    // daemon*, config_persist_degraded
```

Each file <500 LOC. All fields of `xpfCollector` are init in the same function — need a single `newCollector` that calls per-file helpers OR the struct literal is split across files via a builder pattern. The cleanest: `newCollector` in `metrics_descriptors.go` calls `c.initGlobalDescriptors()`, `c.initUserspaceDescriptors()`, etc., where each `init*` is in its own file and operates on `*xpfCollector` receiver.

### Hot-path preservation

Cold path — `newCollector` runs once at daemon start (in `NewServer`). `prometheus.NewDesc` is pure allocation (no I/O, no syscalls). Prometheus scrape path (`Collect` method) reads already-constructed descriptors — it does NOT call `newCollector`. Split is (A) mechanical, no hot-path change. Scrape frequency is <10/s (Prometheus default 15s), not per-packet.

### Tests+gate

- `go test ./pkg/api -run TestMetricsDescriptors -count=1` — existing `metrics_descriptor_coverage_test.go` (726 LOC) verifies every `*Desc` field is non-nil after `newCollector`
- `go test ./pkg/api -run TestMetrics -count=1` — existing `metrics_test.go` (2432 LOC) + `metrics_scoped_global_3286_test.go` + `metrics_cold_path_test.go`
- `go vet ./pkg/api`
- After split, run `go test ./pkg/api -run TestMetricsDescriptorCoverage` to verify no descriptor dropped

### Why it matters

- `metrics_descriptors.go` is the #1 merge-conflict file in `pkg/api` — every CoS/scheduler/NAT/WG/cold-path/fairness feature adds descriptors here. Last 3 months: +~40 descriptors (CoS waterfill, sojourn, equal-flow, WG decap ECN, cold-path v3, binding VMin).
- Reviewer must load 1896 LOC to review a 4-line descriptor addition.
- `metrics_userspace.go` (1819 LOC, the emitter) is already a separate file — descriptors and emitters are split by design, but descriptors themselves are not split by subsystem.

### Fix direction

Extract per-subsystem descriptor construction to helper methods on `*xpfCollector` in new files. Keep `newCollector` top-level in `metrics_descriptors.go` as a 20-line orchestrator:

```go
func newCollector(srv *Server) *xpfCollector {
    c := &xpfCollector{srv: srv}
    c.initGlobalDescriptors()
    c.initUserspaceDescriptors()
    c.initCoSDescriptors()
    c.initBindingDescriptors()
    c.initWorkerDescriptors()
    c.initFairnessDescriptors()
    c.initSystemDescriptors()
    return c
}
```

Each `init*` is in its own file. No logic change, no new allocations, no new types. Pure code-motion.

### Labels

`refactor`, `modularity`, `metrics`, `prometheus`, `cold-path`, `mechanical`, `low-risk`

### Dedup note

Not filed before. GH search `metrics_descriptors split` returns 0. Distinct from #4404-#4406 (Rust) and #4407 (daemon god-struct). `metrics_userspace.go` (1819 LOC, the emitter) is a different file — this filing is for the descriptor side.

---

## (D) Negatives — not monoliths or intentionally not split

### D-01: `maps_sync.go` 1763 LOC — focused, NOT a monolith (D)

`pkg/dataplane/userspace/maps_sync.go` is 1763 LOC but has single responsibility: userspace map sync (programBootstrapMapsLocked, syncUserspaceClassifierMapsLocked, syncIngressIfaceMapLocked, syncLocalAddressMapsLocked, applyHelperStatusLocked, etc.). It is NOT a fusion of unrelated domains. The 1763 LOC is justified by the number of BPF maps (9 maps: ctrl, bindings, heartbeat, xsk, local_v4, local_v6, sessions, conntrack_v4, conntrack_v6, dnat_table, trace, plus CPU map) and the per-map sync logic. Splitting by map would create 9 files of ~150 LOC each with no independent review value — the maps are synced atomically under `programBootstrapMapsLocked` and share `userspaceCtrlValue` / `userspaceBindingKey` types.

**Verdict**: (D) — single responsibility, not a split candidate. Keep as-is.

### D-02: `vrrp/instance.go` 2417 LOC — single coherent VRRP state machine (D, with caveat)

`pkg/vrrp/instance.go` is 2417 LOC, above the 2000-LOC smell threshold. It contains 52 funcs: VRRP state machine (StateInitialize/Backup/Master, stepBackup, run), RX (receiver, receiverIPv6, receiverAfPacket, parseAfPacketIPv4/IPv6, walkIPv6ExtHeaders), TX (sendAdvert, sendPacket, sendPacketIPv6, becomeMaster, becomeBackup), GARP (sendGARP, etc.), advert interval (advertInterval, effectiveAdvertInterval, masterDownInterval, preemptHoldDuration), preempt-hold (armPreemptHold, disarmPreemptHold, preemptingLiveLowerMaster, heldMasterIsStale), VIP (addVIPs, removeVIPs, vipAddrSet, resolveLocalIPv4), and helpers (interfaceAddrs, getLocalIP, setLocalIP, etc.).

All 52 funcs operate on `*vrrpInstance` and are part of one RFC 5798 VRRPv3 state machine. The file is large because VRRP has many sub-protocols (IPv4 RX via AF_PACKET + IPv6 RX via raw socket + IPv6 NODAD + track-interface + preempt-hold + sync-hold + GARP burst + owner-preempt + learned-advert-interval + priority-0 abdication + gratuitous ARP probe target). Splitting RX/TX/GARP into separate files would break the state machine's single-goroutine invariant (run-loop goroutine owns all timers + mu) and make it harder to verify `stepBackup`'s preempt-hold timing.

The file was split once already: `track.go` (track-interface), `packet.go` (VRRP packet encode/decode), `addrwatch.go` (address watch), `vrrp.go` (VRRP constants). The remaining `instance.go` is the state-machine core.

**Verdict**: (D) — single coherent responsibility (VRRP state machine), intentionally kept together. If it grows past ~2800 LOC, consider extracting `instance_rx.go` (receiver + parseAfPacket + walkIPv6ExtHeaders) and `instance_garp.go` (sendGARP + garpEpoch/garpDampened), but NOT in this batch. The 2417 LOC is justifiable given the VRRP RFC complexity.

### D-03: `daemon_run.go` 2329 LOC + `daemon_apply.go` 1935 LOC — already filed #4407 (D for this report)

`pkg/daemon/daemon.go` (763 LOC) defines `type Daemon struct` with 150+ fields. `daemon_run.go` (2329 LOC) defines `Run()` (~1690 LOC, ordering-sensitive lifecycle) + `buildRuntimeDataPlane` + `collectAppliedTunnels` + `namingParamsFromConfig` + `applyStartupNamingForConfig` + `maybeReapplyConfigArrivalNaming` + `runBootstrapExitStartup` + `inferIPv6StaticNextHopInterfaces` + `runHAShutdownUpdate` + `enableForwarding`. `daemon_apply.go` (1935 LOC) defines `applyConfigLocked` (~1148 LOC god-function) + `applyTailReconciles` + `commitAndApply` + `commitConfirmedAndApply` + `executeConfirmedRollback` + `reconcileDHCPRelay` + `reconcileLLDP` + etc.

Already filed as #4407 (Daemon god-struct, 150+ fields, ~3500 LOC) + daemon_apply.go applyConfigLocked (1148 LOC) — tracked as increment 1..5 (surfaceAState grouping #4407 inc 5 merged). This report does NOT re-file it.

**Verdict**: (D) — already tracked, do not double-file.

---

## Cross-cutting notes

### Hot-path preservation summary

| File | Path is hot? | Split safe? | Reasoning |
|------|-------------|-------------|-----------|
| `protocol.go` | NO — cold (config-apply + status poll 1/s) | (A) SAFE | Wire format never on per-packet path. Byte-identical JSON after split. |
| `sync_conn.go` | NO — cold (1s sweep + on-demand HA sync) | (A) but ORDERING-SENSITIVE | Generation-guard state machine must preserve stamp→queue→take ordering. Single-active-fabric invariant must be preserved (activeConnLocked prefers conn0, never both). |
| `tunnel.go` | NO — cold (commit + keepalive 1s+) | (A) SAFE | Tunnel create on commit, keepalive tick at seconds. NOT per-packet. |
| `compiler_validate_warn.go` | NO — cold (commit-time) | (A) SAFE | Warn validators are pure functions `func(cfg *Config) []string`, no state, no I/O. |
| `metrics_descriptors.go` | NO — cold (daemon start + Prometheus scrape 1/15s) | (A) SAFE | `newCollector` runs once at startup. Scrape reads already-constructed descriptors. |
| `vrrp/instance.go` | NO — NOT per-packet (30ms RETH advert, 100ms master-down) | (D) KEEP — single SM | VRRP is timer-driven, not per-packet. But splitting the SM would hurt correctness review. |
| `maps_sync.go` | NO — cold (config-apply + helper status poll) | (D) KEEP — single domain | Map sync is one cohesive operation under one mu. |

No hot-path allocations added by any proposed split. All splits are cold-path code-motion.

### Classification legend

- **(A) MECHANICAL / SAFE**: Cold path, pure code-motion, `go build` / `go test` byte-identical, no ordering change, no new types, no new mutexes, no hot-path change. Safe to land without feature flag.
- **(B) MECHANICAL with ORDERING CONSTRAINTS**: Cold path, pure code-motion, but must preserve a documented ordering invariant (gen-guard, bulk re-drive, fabric preference). Reviewer must verify the invariant comment is preserved.
- **(C) NEEDS REFACTOR DESIGN**: Hot path or requires new abstraction (interface, channel, state machine enum) before split. Not used in this report — all A4 files are cold path.
- **(D) NEGATIVE / NOT A MONOLITH**: File is large but has single coherent responsibility, or already filed, or intentionally kept together for correctness.

### Tests + gate for all findings

```bash
go vet ./pkg/config ./pkg/dataplane/userspace ./pkg/cluster ./pkg/routing ./pkg/vrrp ./pkg/api ./pkg/daemon
go test ./pkg/config -run TestValidate -count=1
go test ./pkg/dataplane/userspace -run TestProtocol -count=1
go test ./pkg/dataplane/userspace -run TestSnapshot -count=1
go test ./pkg/cluster -run TestGenGuard -count=1
go test ./pkg/cluster -run TestSync -count=1
go test ./pkg/routing -count=1
go test ./pkg/api -run TestMetricsDescriptorCoverage -count=1
go test ./pkg/api -run TestMetrics -count=1
# Cluster integration (for sync_conn.go):
make test-failover   # 0 / very low packet loss across failover/failback
make test-ha-crash   # multi-cycle crash recovery
```

Byte-identical check: `go build -o /tmp/xpfd.before ./cmd/xpfd && <split> && go build -o /tmp/xpfd.after ./cmd/xpfd && cmp /tmp/xpfd.before /tmp/xpfd.after` — should be identical for pure code-motion (A) findings. For (B) ordering-sensitive, run `go test -race ./pkg/cluster -count=10` to detect ordering regressions.

### Why splitting matters (engineering-style.md)

> "No monolithic files. A `.rs` file that crosses ~2,000 LOC of production code (excluding `mod tests`) is a smell. By the time it hits ~3,000 LOC the next change to that file should split it before adding new logic. Apply the same rule to test files."
>
> "One responsibility per module. A module that mixes admission policy with byte-mutation, or memory mapping with ring management, will get sliced apart eventually — do it on the way in."

All 5 findings violate the 2k/3k LOC rule and the one-responsibility rule. `compiler_validate_warn.go` (3330 LOC) is the largest file in `pkg/config`; `protocol.go` (2979 LOC) is the largest production file in `pkg/dataplane/userspace`; `sync_conn.go` (1858 LOC) is the second-largest in `pkg/cluster`; `tunnel.go` (1877 LOC) is the largest in `pkg/routing`; `metrics_descriptors.go` (1896 LOC) is the largest descriptor file in `pkg/api`.

### Fix direction (priority order)

1. **F-039-01 `protocol.go`** — highest value, lowest risk (pure type defs, no logic, no mutexes, no goroutines, no ordering). Mechanical file split, 1 PR.
2. **F-039-04 `compiler_validate_warn.go`** — proven pattern (strict already split), pure functions, no state. Mechanical file split, 1 PR.
3. **F-039-05 `metrics_descriptors.go`** — pure `NewDesc` calls, no logic, trivial helper extraction. Mechanical, 1 PR.
4. **F-039-03 `tunnel.go`** — 5 responsibilities, but each is well-bounded (GRE vs WG vs keepalive vs VRF vs address). Mechanical file split, 1 PR.
5. **F-039-02 `sync_conn.go`** — highest correctness risk (gen-guard ordering, bulk re-drive, fabric preference). Requires careful review of lock ordering + single-active-fabric invariant. Mechanical but must preserve `#2198 F3` / `#2221` / `#2995` comments. 1 PR, with `go test -race -count=10`.

Suggested PR order: `protocol.go` → `compiler_validate_warn.go` → `metrics_descriptors.go` → `tunnel.go` → `sync_conn.go` (easiest → hardest). Each PR should be pure code-motion (`git diff` shows only file moves + func relocations, no logic change). Land one at a time, verify `go vet` + `go test` green before next.

### Dedup

- **#4407 Daemon god-struct (150+ fields, ~3500 LOC) + daemon_apply.go applyConfigLocked (1148 LOC)** — ALREADY FILED, tracked as increment 1..5. This report marks `daemon_run.go` + `daemon_apply.go` as D-03 (do not double-file).
- **#4421 flowexport monolithic, firewall-filter validation, pkg/routing/rules.go 3 domains, Surface-A DDNS, event-engine, compiler_security.go** — ALREADY FILED / different batch. This report does NOT re-file `rules.go` (nextTable/ribGroup/pbrManager) or `flowexport` or `compiler_security.go`.
- **#4404-#4406 poll_descriptor / Rust monoliths** — different batch (Rust, not Go). Not re-filed.
- **#4408-#4409 NAT allocation / persistent-lease** — different batch (NAT dataplane, not wire/format/tunnel). Not re-filed.
- No prior issue for `protocol.go` split, `sync_conn.go` gen-guard split, `tunnel.go` keepalive split, `compiler_validate_warn.go` warn-split, or `metrics_descriptors.go` descriptor split (verified via `gh issue list --search` for each file name + `monolithic` + `split` + `refactor`).

### Labels for new issues

- `refactor`, `modularity`, `tech-debt`, `cold-path`, `mechanical` (all 5)
- Plus per-finding: `ha` / `gen-guard` (F-039-02), `tunnel` / `keepalive` / `wireguard` (F-039-03), `validation` / `config` (F-039-04), `metrics` / `prometheus` (F-039-05), `wire-format` / `protocol` (F-039-01)



---

## Findings from draft (/ps-review-039-draft.md)

## File-size / shape inventory — the module checklist

### Top Rust non-test production files (by LOC)

| File | LOC (wc -l) | Prod LOC | Largest fn | Responsibilities | Threshold |
|------|------------|----------|-----------|----------------|-----------|
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 6042 | ~4900 | poll_binding_process_descriptor 4724 | 15+ (stages 1-11, flow-cache, session-hit, session-miss, flowless, host-local, NAT pre-routing, filter, route, screen, policy, SNAT, install, telemetry, HA, debug-log) | >5000 CRITICAL — GOD-FUNCTION |
| `userspace-dp/src/afxdp/poll_stages.rs` | 3527 | ~971 prod | stage_screen_check 304 | 9 stage fns, pure code-motion extraction from poll_descriptor | Well-decomposed (D) |
| `userspace-dp/src/afxdp/forwarding/mod.rs` | 2822 | ~2822 | lookup_forwarding_resolution_inner_ecmp 192 | 68 free fns, 5 god-fns >100 LOC — FIB/NAT/fabric/tunnel fused but modular | ~3000 (B) |
| `userspace-dp/src/afxdp/coordinator/wg_control.rs` | 2280 | ~2280 | ~315, ~211 | 5 resp (socket lifecycle + control loop + handshake SM + ECN cmsg + poll) | >2000 (A) |
| `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` | 2174 | ~414 | enqueue_reject_reply 199 | TCP RST/ICMP unreach build, TX-budget, rate-limit, VLAN fix, output-filter, counters | Well-extracted cold (D) |
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | 2058 | ~2058 | select_exact_cos_guarantee_queue_waterfill 432 | Waterfill + epoch refill + clamping + Phase-1 ascend + Phase-2 descend + WRAP | >2000 (B) |
| `userspace-dp/src/session/mod.rs` | 2054 | ~2054 | — | SessionTable 25 fields (7 resp), SessionEntry 16 fields | >2000 (B god-struct) |
| `userspace-dp/src/afxdp/neighbor.rs` | 2036 | ~2036 | neigh_monitor_thread 272 | 4 resp (probe craft, netlink mgmt, monitor thread, warmer) | ~2000 (B) |
| `userspace-dp/src/afxdp/cold_path_hist.rs` | 1866 | ~950 prod | — | Histogram collection (cold path) | <2000 (D) |
| `userspace-dp/src/afxdp/frame/inspect.rs` | 1813 | ~1813 | parse_session_flow_from_bytes 141 | L2 parse, L3 parse, VLAN, IP options, 5× IPv6 EH walker duplication | ~2000 (B) |
| `userspace-dp/src/afxdp/wg/engine.rs` | 1805 | ~1805 | try_encap/try_decap on hot path | WG protocol — single resp, under threshold | (D) cohesive |
| `userspace-dp/src/afxdp/types/cos.rs` | 1786 | ~1786 | — | CoSInterfaceRuntime 28 fields (5 lifecycles), FlowFairState boxed | ~2000 (B) |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | 1776 | ~1776 | — | Worker loop body | Under threshold |
| `userspace-dp/src/afxdp/frame/mod.rs` | 1710 | ~1710 | verify_built_frame_checksums 192 debug-only | 6-resp kitchen sink: VLAN shift, NAT v4/v6, port rewrite, NAT64, inject, debug-verify | ~2000 (A) |
| `userspace-dp/src/event_stream/mod.rs` | 1693 | ~1693 | IO thread 700 | Transport + sequencing + clock + RT_FLOW | ~1700 (A if, D defer) |
| `userspace-dp/src/afxdp/worker/mod.rs` | 1625 | ~1625 | — | Worker lifecycle | Under |
| `userspace-dp/src/afxdp/frame/wg.rs` | 1561 | ~604 prod / 957 test | wg_encap_frame 253 | WG encap — test-heavy, prod clean | (D) |
| `userspace-xdp/src/lib.rs` | 1541 | ~1541 | classify_xxx GRE-inner byte-order | XDP shim | (D) |
| `userspace-dp/src/screen/mod.rs` | 1540 | ~1540 | check_packet_with_zone_id_opts 374 | 16 screen checks, 5 SYN-flood phases + ICMP/UDP flood + stateless | ~1500 (B) |
| `userspace-dp/src/afxdp/neighbor_resolver.rs` | 1512 | ~1512 | — | Neighbor netlink + rate-limit | (B) part of neighbor monolith |
| `userspace-dp/src/afxdp/event_emit.rs` | 1492 | ~1492 | — | Event emission (cold) | Under |
| `userspace-dp/src/afxdp/tx/dispatch/mod.rs` | 1486 | ~1486 | enqueue_pending_forwards 1048 | TX drain god-func: Phase 8 + PTB + seg + fabric + prebuilt + owned + live | ~1500 (B) |
| `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs` | 1460 | ~1460 | legacy lease + v8 fair-share | Legacy + v8 split pending | ~1500 (A) |
| `userspace-dp/src/nat/allocator.rs` | 1416 | ~1416 | allocate_translation_locked 114 | PortAllocatorShared: hot bitmap + cold persistent/GC/stats | ~1500 (C perf-positive) |
| `userspace-dp/src/afxdp/neighbor_dispatch.rs` | 1399 | ~1399 | — | pending_neigh + neg_neigh + dynamic-learn | (B) neighbor split |
| `userspace-dp/src/nat/source.rs` | 1389 | ~1389 | match_source_nat_result_for_tuple 336 | SNAT rule parsing + L4 match + scope + pool alloc driver — 6 resp | ~1500 (B) |
| `userspace-dp/src/afxdp/umem/mod.rs` | 1345 | ~1345 | — | UMEM lifecycle | (D) |
| `userspace-dp/src/afxdp/tx/cos_classify.rs` | 1335 | ~1335 | — | TX-selection + BA reclassify + LP + enqueue + demote + admission | ~1500 (B) |
| `userspace-dp/src/screen/scan.rs` | 1213 | ~592 prod / 621 test | ScanCore::check 61 | Generic ScanCore + thin wrappers, one-source-of-truth per #2234 | (D) clean |
| `userspace-dp/src/afxdp/poll_descriptor/filter.rs` | 1201 | ~640 | evaluate_non_pbr_input_filter 70 | Cold filter extraction | (D) clean split |
| `userspace-dp/src/protocol/binding.rs` | 1168 | ~1168 | — | Binding array construction | (A) mechanical if needed |
| `userspace-dp/src/event_stream/codec.rs` | 1165 | ~1165 | — | Event codec | Companion to mod.rs |
| `userspace-dp/src/afxdp/shared_ops.rs` | 1131 | ~1131 | — | Shared session ops | Under |
| `userspace-dp/src/nat/destination.rs` | 1088 | ~1088 | lookup_with_counter_scoped ~110 | DNAT exact+wildcard+PROTO_ANY+prefix-LPM | (D) cohesive |
| `userspace-dp/src/afxdp/cos/tx_completion.rs` | 1080 | ~1080 | — | 3 resp: completion drain + fill refill + RX/TX wake | Minor (C)/(D) |
| `userspace-dp/src/nat64.rs` | 2527 | ~2527 | translate_v6_to_v4 ~200 | NAT64 forward/reverse/EH/frag/ICMP-embed | ~2500 (defer, next feature) |

### Top Go non-test non-gen production files (by LOC)

| File | LOC | #func/#type | Smell | Action |
|------|-----|------------|-------|--------|
| `pkg/config/compiler_validate_warn.go` | 3330 | 35 funcs | Warn validators monolith, strict already split | (A) split per-domain |
| `pkg/dataplane/userspace/protocol.go` | 2979 | 72 types, 1 func | Wire-format 12 domains | (A) 12 files by domain |
| `pkg/config/compiler_nat.go` | 2529 | 37 funcs | 5 NAT types + 4 validators + 8 helpers | (A) 6 files + move validators |
| `pkg/vrrp/instance.go` | 2417 | 52 funcs/3 types | VRRP SM: state + RX + TX + GARP + VIP | (D) single coherent SM |
| `pkg/daemon/daemon_run.go` | 2329 | 9 funcs | Bootstrap + naming + run-loop + exit | (D) already #4407 |
| `pkg/config/compiler.go` | 2110 | — | 3-phase fusion (parse→validate→compile) | (A) extract phases |
| `cmd/cli/show.go` | 2100 | — | CLI show commands — not inspected | — |
| `pkg/ddns/surface_a.go` | 1957 | — | DDNS state machine (#4421 backlog) | Listed in #4421 |
| `pkg/frr/policy_render.go` | 1938 | — | FRR rendering — slightly over | Minor |
| `pkg/daemon/daemon_apply.go` | 1935 | 20 funcs | applyConfigLocked god-function 1148 | Already #4407 |
| `pkg/api/metrics_descriptors.go` | 1896 | 279 NewDesc | Prometheus descriptor monolith | (A) helper methods |
| `pkg/routing/tunnel.go` | 1877 | 3 types ~30 funcs | Tunnel lifecycle + keepalive + WG + MTU + VRF | (A) 5 responsibilities |
| `pkg/cluster/sync_conn.go` | 1858 | ~52 funcs | HA sync connection: gen-guard + fabric + bulk + sweep + delete + config + failover + barrier | (B) ordering-sensitive |
| `pkg/api/metrics_userspace.go` | 1819 | — | Userspace metrics emitter | Companion to descriptors |
| `pkg/dataplane/userspace/maps_sync.go` | 1763 | — | BPF map sync | (D) single resp |
| `pkg/dataplane/compiler.go` | 1733 | — | Compiler dispatch | (D) |
| `pkg/config/compiler_validate_strict_filter.go` | 1660 | — | Single-domain filter | (D) already per-domain split |
| `pkg/config/compiler_uniformgates.go` | 1659 | — | Uniformgates orchestrator | (D) #4406 split result |
| `pkg/grpcapi/server_diag.go` | 1602 | — | gRPC diag | Under |
| `pkg/cmdtree/tree.go` | 1548 | — | Command tree | (D) |
| `pkg/dhcprelay/relay.go` | 1545 | — | DHCP relay | Focused |
| `pkg/config/types_system.go` | 1544 | 64 type defs | System+SNMP+Login+DHCP+Services+Firewall types | (D) defer, touches 20+ consumers |

Total non-test Go in `pkg/`: ~250k LOC. Top 5 files: 3330+2979+2529+2417+2329 = 13.6k LOC in 5 files.

---

## Rankings — the monolith checklist (size × resp-count × hot-path proximity)

Ranked by (size × responsibility count × hot-path factor), hot = 3×, warm = 2×, cold = 1×:

| Rank | File | Size | Resp | Hot | Score | Notes |
|------|------|------|------|-----|-------|-------|
| 1 | poll_descriptor/mod.rs poll_binding_process_descriptor | 4724 fn | 15+ | HOT 3× | 4724×15×3=212580 | #1 monolith, #4404, per-packet |
| 2 | tx/dispatch/mod.rs enqueue_pending_forwards | 1048 fn | 8+ | HOT 3× | 1048×8×3=25152 | #4408, TX drain |
| 3 | cos/queue_service/mod.rs waterfill | 432 fn | 7 | WARM 2× | 432×7×2=6048 | #4408, TX sched |
| 4 | session/mod.rs SessionTable | 2054 file | 7 | HOT 3× | 2054×7×3=43134 | #4421, every packet lookup |
| 5 | SessionEntry | 284 but 16 fields | 2 | HOT 3× | Arc clone per packet | RPC clone cost |
| 6 | afxdp/forwarding/mod.rs | 2822 | 5 | HOT 3× | ForwardingState 65 fields | FIB lookup hot |
| 7 | ForwardingState (types/forwarding.rs) | 1054 struct | 65 fields | HOT 3× | Hot-cold field fusion | dcache waste |
| 8 | PortAllocatorShared | 800 struct | 5 | HOT 3× | Hot bitmap + cold stats/GC | Cache-line |
| 9 | nat/source.rs match_source_nat_result | 336 fn | 6 | HOT 3× | L4 classify + pool alloc | Per new-flow |
| 10 | screen/mod.rs check_packet | 374 fn | 7 | HOT 3× | 5 SYN-flood phases + flood+stateless | IDS |
| 11 | frame/inspect.rs 5× EH walker dup | 1813 | 5 | HOT 3× | Parse every packet | Code dup |
| 12 | frame/mod.rs kitchen sink | 1710 | 6 | HOT 3× | VLAN+NAT+port+prep+NAT64+verify | TX path |
| 13 | compiler_validate_warn.go | 3330 | ~12 | COLD 1× | 35 funcs, ~12 resp | Mechanical |
| 14 | protocol.go wire-format | 2979 | 12 | COLD 1× | 72 types | Mechanical |
| 15 | sync_conn.go | 1858 | 8 | COLD 1× | Gen-guard ordering | Sensitive |
| 16 | neighbor.rs | 2036 | 4 | COLD 1× | ARP/ND + netlink + monitor | GC |
| 17 | wg/engine.rs | 1805 | 1 | HOT 3× | WG encap/decap | Cohesive (D) |
| 18 | types/cos.rs CoSInterfaceRuntime | 1786 | 5 | WARM 2× | 28 fields, 3 unused WIRE-ONLY | Field split |
| 19 | compiler_nat.go | 2529 | 3 | COLD 1× | 5 NAT types + validators + helpers | Mechanical |
| 20 | tunnel.go | 1877 | 5 | COLD 1× | Tunnel + keepalive + WG MTU + VRF | Mechanical |

---

## File-by-file inspection log



---

---

## Coverage & verification summary

**Files reviewed / total:** Top ~60 largest files inspected from 250k LOC Go + 142k LOC Rust prod (excluding vendored/generated/target/tests).
Top-inventory files covered: all 10 batch areas, 60+ largest files, all top-Rust-non-test (>1000 LOC) and top-Go-non-test-non-gen (>1000 LOC).

**Findings per area:**
- A1a (poll_descriptor): 3 findings (1 B-component update to #4404 with new measurement + 2 D-negatives: poll_stages.rs + reject_reply/filter already extracted)
- A1b (TX dispatch): 5 findings (2 B-component: dispatch god-func remnant Phase 8 + tx/cos_classify 7-resp, 1 D tx/transmit already clean, 2 minor D/C: tx/rings mixed disciplines + tx/drain leftover)
- A1c (CoS): 3 findings (1 B: CoSInterfaceRuntime 28-field god-struct, 1 D waterfill already filed #4408, 1 D shared_cos_lease cluster well-split)
- A1d (Session table): 3 findings (1 D-file-split-as-code-motion not true decomposition, 1 C SessionEntry hot/cold Arc clone per packet, 1 D leaf modules clean) — overlaps #4421/#4422 but adds field-level hot/cold inventory
- A1e (Forwarding/neighbor): 4 findings (1 C ForwardingState 65-field god-struct perf-positive, 1 B neighbor.rs 4-resp monolith, 1 B forwarding/mod.rs 2822 LOC 5 god-fns, 1 D forwarding_build already clean 8 files)
- A1f (Screen/frame/filter): 4 findings (1 B screen/mod.rs 16-checks SYN-flood god-func, 1 B frame/inspect.rs EH walker dup, 1 A frame/mod.rs 6-resp kitchen sink, 1 D scan+wg+runtime already clean)
- A1g (Remaining Rust infra): 5 findings (2 A: wg_control 2280 monolith + server/helpers dumping ground, 1 optional event_stream, 3 D negatives: wg/engine, types/cos, etc.)
- A2 (NAT): 5 findings (1 C nat/allocator PortAllocatorShared perf-positive, 1 B nat/source god-function, 1 A compiler_nat.go 6-file motion, 2 D negatives: nat/dest + nat/tests already split)
- A3 (Go config compilers): 5 findings (4 A: compiler_validate_warn, compiler_system, compiler_services, compiler_nat helpers/validators; 1 D: compiler_uniformgates + types already well-split)
- A4 (Go dataplane+daemon+cluster+routing): 5 findings (5 A: protocol.go wire-format 12 domains, sync_conn.go HA gen-guard ordering, tunnel.go 5-resp, compiler_validate_warn.go 35 funcs, metrics_descriptors.go 279 NewDesc; plus 3 D-negatives: maps_sync, vrrp/instance single SM, daemon god-struct already #4407)

**Classification totals (actual new findings only, excluding already-filed #4404-#4421):**
- (A) MECHANICAL / SAFE (cold path, pure code-motion, no hot-path risk): ~14
- (B) REQUIRES GUARDRAILS (hot/warm path, safe only if guardrails met): ~8
- (C) PERFORMANCE-POSITIVE (hot/cold cache win / lock narrowing / single-writer): ~4
- (D) DO-NOT-SPLIT (genuinely cohesive / already well-decomposed / threshold not exceeded): ~11
- Total findings across batches: 41 (mix of new + enriched + D-negatives)

**Verification approach per class:**
- (A) Mechanical: `go build ./...` + `cargo build -p userspace-dp` + `go test ./...` + `cargo test -p userspace-dp` byte-identical (sorted decl-NAME set unchanged per #4144 discipline), incremental-build timing improvement
- (B) Hot-path guardrails: `cargo asm` / `objdump -d` disassembly diff (no new alloc/call on hot path), `perf stat` cache-miss/branch-miss counters, criterion bench delta, `size` on object, + existing behavioral gates (`make test`, `test-failover`, CoS smoke/fairness)
- (C) Performance-positive: same as (B) + explicit measurement showing improvement (cache-miss reduction, build-time improvement, branch-predictor win)
- (D) Negative: no change needed, documenting why

---

## Suggested issue split — sequenced so each PR is small, independently reviewable, behind existing gates

### Phase 1: Go mechanical splits (safe, driveable-now, largest ROI for build-time + reviewability)

1. **compiler_validate_warn.go 3330 → 5 per-domain files** — (A) mechanical. Largest Go file.
   - `compiler_validate_warn_nat.go`: validateNAT warnings
   - `compiler_validate_warn_security.go`: policy/zone/screen
   - `compiler_validate_warn_forwarding.go`: routing/tunnel/VRF/interface
   - `compiler_validate_warn_ddns.go`: DDNS/dhcp-server
   - `compiler_validate_warn_routing.go`: BGP/CoS/multicast/misc
   - Gate: `go build ./...` + `go test ./pkg/config/...` green, decl-NAME set identical.
   - Labels: `refactor`, `go`, `config`

2. **protocol.go 2979 → 12 domain files** — (A) mechanical, 72 types across 12 wire domains.
   - `protocol/control.go` (ControlRequest/Response), `protocol/snapshot.go` (ConfigSnapshot+~20 subtypes),
     `protocol/status.go` (ProcessStatus+~40 subtypes), `protocol/binding.go` (already exists Rust side),
     `protocol/cos.go`, `protocol/nat.go`, `protocol/policy.go`, `protocol/filter.go`, `protocol/ha.go`,
     `protocol/session_sync.go`, `protocol/eventstream.go`, `protocol/docs.go` (constants)
   - Gate: `go build ./...` + `cargo test -p userspace-dp` (Rust protocol/tests.rs decodes Go JSON).
   - Labels: `refactor`, `go`, `dataplane`, `protocol`

3. **compiler_system.go 1881 + compiler_services.go 1821 → per-domain files** — (A) mechanical.
   - `compiler_system_login.go` + `_snmp.go` + `_chassis.go` + `_ddns.go` + `_userspace.go`
   - `compiler_services_rpm.go` + `_dhcp.go` + `_flow.go` + `_ip_monitoring.go` + `_event.go`
   - Labels: `refactor`, `go`, `config`

4. **compiler_nat.go 2529 → 3-4 files + move strict gates** — (A) mechanical with subtlety.
   - `compiler_nat_helpers.go` (natAddrFamily etc. shared helpers — note: used in 3 files),
     move `validateNATHostMaskStrict` + `validateNPTv6Strict` to `compiler_validate_strict_nat.go`
   - Gate: `go build ./...` + `go test ./pkg/config/...`.
   - Labels: `refactor`, `go`, `nat`, `config`

5. **metrics_descriptors.go 1896 → helper methods** — (A) mechanical.
   - `initGlobalDescriptors`, `initUserspaceDescriptors`, `initCoSDescriptors`, `initBindingDescriptors`,
     `initWorkerDescriptors`, `initFairnessDescriptors`, `initSystemDescriptors` — `newCollector` becomes 20-line orchestrator.
   - Gate: `go test ./pkg/api/...`.
   - Labels: `refactor`, `go`, `metrics`

### Phase 2: Rust mechanical splits (safe, cold path or same-crate boundary)

6. **wg_control.rs 2280 → wg_control/{socket,loop,dispatch,handshake,poll}.rs** — (A) mechanical, cold (100ms poll).
   - Labels: `refactor`, `rust`, `wg`

7. **server/helpers.rs 1292 → helpers/{status,session_sync,binding_plan,hash,lifecycle}.rs** — (A) mechanical.
   - File header says "Pure relocation pending further split."

8. **frame/mod.rs 1710 → frame/{nat,prep/inject,verify,nat64_fwd}.rs** — (A) mechanical.
   - 9 prior extractions already done (#988/#989/#1046/#1352/#1440), this is the final 6-resp kitchen sink cleanup.

9. **event_stream/mod.rs 1693 → transport+sequencing+clock split** — (A) mechanical, optional.
   - Defer if count is low; easy win when next feature touches event_stream.

### Phase 3: Go ordering-sensitive / Rust hot-path-adjacent (requires /triple-review)

10. **sync_conn.go 1858 → sync_conn/{gen_guard,fabric,state_machine,batch}.go** — (B) ordering-sensitive.
    - Gen-guard stamp→queue→take, bulk reset, fabric preference (#2198/#2221/#2995, #4090/#4360).
    - Requires preserving generation-guard state machine comments + single-active-fabric invariant.
    - Gate: `go test ./pkg/cluster/...` + `test-failover` smoke.
    - Labels: `refactor`, `go`, `ha`, `hot-path-adjacent`

11. **tunnel.go 1877 → tunnel/{lifecycle,keepalive,wg_mtu,vrf,address}.rs equivalents** — (A/B) mixed.
    - Keepalive Axis D commit-after-success lock-free is the sensitive part.

### Phase 4: Rust hot-path (requires /triple-review, disassembly + bench gates)

12. **PortAllocatorShared hot/cold split** — (C) performance-positive. Cache-line win: hot bitmap+CAS vs cold stats/GC/persistent-leases.
    - Guard: `benches/snat_allocator.rs` must not regress, `#[repr(align(64))]` cache-line pad, no new pointer chase.
    - Verification: criterion bench delta, `perf stat` LLC-load-miss before/after, `cargo test -p userspace-dp`.
    - Labels: `refactor`, `rust`, `nat`, `hot-path`, `x-hpc`

13. **nat/source.rs match_source_nat_result_for_tuple 336 LOC → classify_l4_mode() enum + allocate_pool_v4/v6** — (B) hot-path.
    - Gate: `cargo test -p userspace-dp -- nat`, session sync during failover.

14. **ForwardingState 65-field god-struct → hot FIB vs cold config** — (C) performance-positive.
    - Immediate: `#[repr(C)]` + hot-field-first reorder (zero-risk).
    - Then: `ForwardingFib(Arc)` SoA split — workers hold hot FIB separately from cold config.
    - Gate: `cargo test -p userspace-dp` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200 ≥23Gb/s, no regression`.

15. **SessionTable + SessionEntry hot/cold field separation** — (C) performance-positive + (D) field map for true 7-group decomposition.
    - SessionEntry Arc clone per packet — 10ns+ win expected at ~7.5M pps/worker via SessionHot/SessionCold inline split.
    - Gate: `lookup_with_origin` micro-bench, `cargo test`, `test-failover`.
    - Labels: `refactor`, `rust`, `session`, `hot-path`, `x-hpc`

16. **neighbor.rs 2036 → neighbor/{probe,kernel,monitor,warmer}.rs + gc.rs** — (B).
    - GC path cold, probe craft must preserve `trigger_kernel_arp_probe` allocation-freedom.

17. **screen/mod.rs SYN-flood god-function → screen/{syn_flood,flood,missing_profile}.rs** — (B).
    - Keep `#[inline(always)]` for hot-path preservation.

18. **frame/inspect.rs EH walker dedup → inspect/{ext,frag,flow,filter}.rs** — (B).
    - Single `walk_ipv6_ext_headers` shared impl, 5× call sites.

### Phase 5: Hardest hot-path god-functions (requires deep /triple-review, NOT driveable-now)

19. **poll_descriptor/mod.rs poll_binding_process_descriptor 4724 LOC + poll_stages.rs + reject_reply + filter** — (B) requires guardrails.
    - Already filed #4404 (reported 1368 LOC, now 4724 — growth). This audit provides new measurement + decomposition angles.
    - 6 incremental PRs ordered by risk: flowless A → telemetry cold outline C → NAT pre-routing B → host-local dedup B → session install B → hit/miss split B with PacketCtx.
    - Guardrails: single-recycle invariant (39 push sites), Junos order 3× duplication, no alloc, inlining, `FORCE_OVERSIZED`/`FORCE_TUPLE_MISMATCH` gates.
    - Do NOT attempt without disassembly baseline + `flowless_local_delivery_tests` + `inplace_randomized_sequence`.
    - Labels: `refactor`, `rust`, `hot-path`, `x-hpc`

20. **tx/dispatch/mod.rs enqueue_pending_forwards 1048 + tx/cos_classify.rs 7-resp + CoS waterfill** — (B)/(C).
    - tx/dispatch: `dispatch/forward_build.rs` (Phase 8 cascade), `tcp_seg.rs`, `fabric.rs` + single-recycle + direct-TX + fabric triple repetition.
    - Already filed #4408. New detail: Phase 8 + direct-TX + fabric breakdown + exact coupling count.
    - Labels: `refactor`, `rust`, `tx`, `hot-path`, `x-hpc`

---

## Negative results (D — do-not-split, genuinely cohesive)

### D-01: poll_stages.rs — well-decomposed (9 stage fns, all #[inline], 304 LOC largest)
Already extracted stages; splitting would duplicate VLAN logical-ifindex logic that caused #2145/#3022 bugs.

### D-02: reject_reply.rs + filter.rs — correctly extracted cold-path modules
Both #[cold] #[inline(never)], exemplary inline policy (cheap guards #[inline], heavy bodies cold). 5-stage pipeline must stay linear for #3656 H11/H12 ordering; Junos order must stay atomic (#3485).

### D-03: tx/transmit/*.rs — CLEAN SEPARATION, textbook (#1354)
6-phase split (rewrite/verify/finalise/write/stage) is exemplary. No further action.

### D-04: tx/rings.rs — mixed ring disciplines — minor, defer

### D-05: tx/drain/mod.rs — orchestrator clean at 35 LOC, leftover CoS ingest 235 LOC → `cos_leftover.rs`/`cos_ingest.rs` only if team anticipates churn.

### D-06: CoS waterfill — already #4408, new angle (f64 fraction calc 37 LOC extraction)

### D-07: shared_cos_lease cluster (backlog+vtime well-split), CoSInterfaceRuntime well-decomposed post-#1035

### D-08: session leaf modules — key.rs (pure NAT key transforms), wheel.rs (power-of-two), ctx.rs (#1357), entry.rs type extraction — all exemplary.

### D-09: forwarding_build/ — well-decomposed (#1342, 8 files, linear chain, documented ordering invariant), cos.rs 850 LOC has 3-way split

### D-10: forwarding/mod.rs well-decomposed scaffolding — no action (from a1e), but D-01 65-field god-struct still applies to types/forwarding.rs

### D-11: nat/destination.rs — cohesive single-resp DNAT table, under threshold

### D-12: nat/tests — already split per #4409 (was 8685 single file), largest 3828

### D-13: wg/engine.rs + wg/cookie.rs — single-responsibility WG protocol

### D-14: types/cos.rs, types/forwarding.rs, protocol/binding.rs — cohesive single-responsibility

### D-15: event_stream/mod.rs — defer, borderline but cohesive transport+sequencing+clock

### D-16: compiler_uniformgates.go — single-func orchestrator, already #4406 step 4 split result

### D-17: compiler_validate_strict_filter.go — single-domain, already #4405 per-domain split result

### D-18: compiler_interfaces.go, types_system.go — genuinely cohesive or touches 20+ consumers

### D-19: maps_sync.go, vrrp/instance.go — cohesive single-responsibility (vrrp is one RFC 5798 SM)

### D-20: daemon_run.go/daemon_apply.go — already #4407

---

## Labels for all findings

Common: `refactor`, `hot-path` (for B/C on per-packet), `x-hpc` (cache-line/layout/atomics), `cold-path` (A mechanical), `monolith`, `god-struct`, `god-function`

Per-finding: `go-config`, `rust-dataplane`, `nat`, `session`, `forwarding`, `neighbor`, `screen`, `frame`, `wg`, `event-stream`, `protocol`, `sync`, `tunnel`, `metrics`, `cos`, `tx`, `coS-queue`

---

## Verification matrix

| Finding class | Inlining | Alloc | Dispatch | Layout | Locality | Lock scope | Verification |
|--------------|----------|-------|----------|--------|----------|------------|-------------|
| (A) Mechanical | Free (same crate TU, or Go same package) | N/A (cold path, config time) | N/A | N/A | N/A | N/A — must not widen | go build/test, cargo build/test, decl-NAME set identical, incremental-build timing |
| (B) Hot-path guardrails | Require #[inline] after move, same crate free OR explicit #[inline] on new module boundary, confirm via cargo asm / objdump -d diff | No Box/Vec/String/clone on per-packet path | No trait objects on hot, prefer enum+match devirtualized | Carry const _: () = assert!(size_of/align_of...) | Keep hot fields in one cache line, cold fields separated | Narrow critical section, preserve concurrency invariants (single-writer-per-worker, per-CPU, lock-free/seqlock, atomic ordering) | cargo asm / objdump -d disassembly diff + perf stat cache-miss/branch-miss + criterion bench + size on .o + make test + test-failover + CoS smoke |
| (C) Perf-positive | Same as (B) | Same as (B) + must measure improvement | Same as (B) | Same as (B) + explicit SoA / AoS→SoA proof | Must measure: perf stat LLC-load-miss reduction, or build-time improvement, or branch-miss reduction | Lock-scope narrowing that reduces contention | Same as (B) + explicit perf measurement showing win (cache-miss reduction, build-time, bench delta) |
| (D) Do-not-split | N/A — no change | N/A | N/A | N/A — layout already correct | N/A — already tight | N/A — already correct scope | No change, documenting why |

---

*Base commit: f70146951583823a5ace87b0b11a2e58f46e8db9*
*Generated: 2026-07-08T15:54:39.945501+00:00*
*Output: /tmp/ps-review-039.md (this file)*

