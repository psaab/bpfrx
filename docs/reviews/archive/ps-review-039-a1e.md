# 039 — A1e Forwarding / ForwardingState / Neighbor / NAT Resolution

## File-Size / Shape Inventory

| File | LOC | Role |
|------|-----|------|
| `userspace-dp/src/afxdp/types/forwarding.rs` | 1054 | ForwardingState (65 fields) + supporting types |
| `userspace-dp/src/afxdp/forwarding/mod.rs` | 2822 | 50+ free-fn: FIB lookup, NAT matching, HA resolution, PBR, fabric, MSS |
| `userspace-dp/src/afxdp/forwarding/host_inbound.rs` | 817 | Host-inbound admit classification |
| `userspace-dp/src/afxdp/forwarding/tests.rs` | 4632 | Forwarding tests |
| `userspace-dp/src/afxdp/forwarding_build/mod.rs` | 687 | Build orchestrator — linear chain of sub-builder calls |
| `userspace-dp/src/afxdp/forwarding_build/fib.rs` | 483 | FIB / connected-route / neighbor / fabric population |
| `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` | 340 | Interface + egress population |
| `userspace-dp/src/afxdp/forwarding_build/cos.rs` | 850 | CoS classifier + iface-config build |
| `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` | 302 | Tunnel endpoint hydration |
| `userspace-dp/src/afxdp/forwarding_build/zones.rs` | 142 | Zone / host-inbound / tcp-rst population |
| `userspace-dp/src/afxdp/forwarding_build/wg.rs` | 127 | WireGuard engine reuse/new |
| `userspace-dp/src/afxdp/forwarding_build/validated.rs` | 161 | #2410 checked narrowing newtypes |
| `userspace-dp/src/afxdp/forwarding_build/tests.rs` | 5042 | Build tests |
| `userspace-dp/src/afxdp/neighbor.rs` | 2036 | Netlink monitor, dump, warmer, probe, kernel-neighbor install |
| `userspace-dp/src/afxdp/neighbor_resolver.rs` | 1512 | Background resolver thread — netlink GET per next-hop |
| `userspace-dp/src/afxdp/neighbor_dispatch.rs` | 1399 | Worker-side pending-neighbor + dynamic-learn |
| `userspace-dp/src/afxdp/worker/mod.rs` | 1625 | BindingWorker lifecycle (11 sub-modules already extracted via #959) |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | 1776 | worker_loop — tick, telemetry publish, session reap |

**Crate-wide largest files** (`userspace-dp/src/afxdp/*.rs`, non-test):
`poll_stages.rs` 3527, `flow_cache_tests.rs` 2836, `neighbor.rs` 2036, `cold_path_hist.rs` 1866, `neighbor_resolver.rs` 1512, `event_emit.rs` 1492, `neighbor_dispatch.rs` 1399.

---

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
