# xpf firewall refactor audit — ps-review-039-a1a — per-packet orchestrator (poll_descriptor + poll_stages)

Base commit: f70146951583823a5ace87b0b11a2e58f46e8db9 (2026-07-07)
Output path: /tmp/ps-review-039-a1a.md
Batch: A1a — per-packet orchestrator (poll_descriptor + poll_stages)
Reviewer: ps / claude-spark

Prior reviews read for dedup:
- /tmp/ps-review-010.md (RUST-HOT — poll_descriptor god-function 1368 LOC, 15+ resp)
- /tmp/ps-review-011.md (Go control plane + Rust NAT/filter — out of scope)
- /tmp/ps-review-012.md (RUST-COLD)
- grep /tmp/ps-review-*.md for poll_descriptor, poll_stages, filter.rs, reject_reply

Dedup suppression summary:
- #4404: poll_descriptor/mod.rs god-function — ALREADY FILED. This review does NOT re-file the same finding; it adds new measurement (4724 LOC vs 1368 at #4404 time), mutable-locals coupling count (11), single-recycle proof burden (39 push sites), and flowless/Junos-order duplication — angles #4404 lacked.
- #4421 ForwardingState god-struct / SessionEntry / SessionTable — different files, not re-reported.

---

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
