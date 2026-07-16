# xpf firewall deep audit — Cohort 7: Forwarding core — ps-review-030

- Base commit: b1bd96fb6 (merge PR #4531, master)
- Output path: /tmp/ps-review-030.md
- Cohort: 7 — userspace-dp/src/afxdp/poll_descriptor/mod.rs (6000+ LOC), poll_descriptor/*.rs, poll_stages.rs, forward_request.rs, forwarding/mod.rs, forwarding/host_inbound.rs, forwarding/tests.rs, frame/mod.rs, frame/checksum.rs, frame/inspect.rs, frame/rewrite/, frame/build/, flow_cache.rs, userspace-xdp/src/lib.rs

## Duplicate-suppression summary + intentional-divergence list

Read /tmp/all_findings.txt (272 entries), /tmp/ps-review-024.md, /tmp/ps-review-025.md, /tmp/ps-review-028.md, /tmp/ib-*.md.

### Dedup'd / not re-reported

| Prior ID | Topic | Why dedup'd |
|---|---|---|
| F-259 | Flowless fragment MissingNeighbor bypass | Fixed #4024 — flowless MissingNeighbor now enforces zone policy before reinject |
| F-085 | Flowless screen bypass | Fixed #3291/#3292 |
| #2387 | Session/flow identity bare 5-tuple omits VLAN/zone/VRF | OPEN, tracked — this IS H-01 VLAN confusion, verified still present (see below) |
| #4517 / ib-h1 | IPv6 EH walkers terminate at MOBILITY/HIP/Shim6/exp | Fixed post-b1bd96fb6 (aea5919cf), not in b1bd96fb6 — real EH bug, but not new |
| ps-024 M-01 | PBR kernel mirror discard/reject | Different cohort (routing), known, not re-reported |
| F-130 | Mirror sampling semantics | Known, not forwarding core |
| F-236 / F-236? | NAT64 fragment / checksum | Out of cohort |
| Various | Single-rate policer unenforced | Out of cohort (filter), tracked |

### Intentional divergences (NOT bugs)

- Single VLAN tag only — QinQ double-tagged goes to kernel (XDP_PASS), not forwarded by userspace. Documented gap, not a bug.
- Intrazone default-permit, host-originated junos-host rejection, IPsec-passthrough-exempt — documented intentional divergences.
- Flow cache only caches ForwardCandidate/FabricRedirect (not LocalDelivery/MissingNeighbor) — intentional, security correct.
- Flow cache does NOT include zone in lookup — relies on config_generation for policy change invalidation and session table for 5-tuple uniqueness. VLAN case is #2387 (known OPEN), not a new intentional divergence.

### Required prior findings verification (HEAD b1bd96fb6)

| Finding | Claims | Status on b1bd96fb6 | Evidence |
|---|---|---|---|
| H-01 flow-cache VLAN confusion | Flow cache keyed on physical parent ifindex, two VLANs share same flow-cache identity, cross-VLAN session reuse | **STILL PRESENT — VERIFIED** — tracked as #2387 OPEN | `flow_cache.rs:169-174` `FlowCacheLookup::for_packet(meta)` uses `meta.ingress_ifindex` (physical parent, e.g., 5 for ge-0/0/0), not logical. Two VLAN subifs ge-0/0/0.100 (VLAN 100, zone trust-a) and ge-0/0/0.200 (VLAN 200, zone trust-b) share same physical parent. Same 5-tuple from different VLANs hits same flow-cache entry. `session/key.rs:10-17` `SessionKey` is bare 5-tuple, no VLAN/zone/VRF. Cross-VLAN session reuse already tracked as #2387. |
| H-02 tiny fragment port evasion | First fragment with tiny L4 (8 bytes) hides real dst port in second fragment, bypasses port-based policy | **NOT EXPLOITABLE — REFUTED** | XDP `parse_l4` for TCP requires 14 bytes + data_offset validation (needs 20 bytes min TCP header): `userspace-xdp/src/lib.rs:1492-1497` reads 14 bytes, checks `data_offset < 20 => None`, then `read_bytes(..., data_offset)` requires full TCP header. Tiny first frag with <14 bytes TCP: XDP drops (parse fail, `drop_degraded_transit`). Tiny first frag with >=14 bytes but <20 bytes TCP: XDP drops (data_offset check fails). Non-first fragments: userspace `frame_is_non_first_fragment` + `parse_session_flow_from_bytes:240-242` returns None → flowless → route-based, no session pollution. `declared_l3_end` guard (#2361) `ipv4_declared_l3_end:888-904` clamps `total_len` to slice, `parse_flow_ports:1032` checks `end > declared_end => None` → flowless. Overlapping fragment with different ports: different session key (dst_port differs) → re-evaluated → DENY. No bypass path found. |
| M-01 XDP EH walk 6 vs 8 | XDP walks 6 EH (`MAX_EXT_HDRS=6`), userspace walks 8 (`MAX_IPV6_EXT_HEADERS=8`), divergence causes bypass | **STILL PRESENT but NOT a bypass — downgraded to Low (perf)** | `userspace-xdp/src/lib.rs:33` `MAX_EXT_HDRS=6`, `userspace-dp/src/afxdp/frame/inspect.rs:31` `MAX_IPV6_EXT_HEADERS=8`. Packet with 7 EH + TCP: XDP walks 6, stops at 6th EH (e.g., DestOpt 60), `proto=60`, session lookup with proto=60 → miss → XSK redirect → userspace walks 8, finds TCP, creates session, policy evaluated → no bypass. Next packet same 7 EH: XDP miss again (proto=60 vs session TCP=6) → XSK → userspace hit → forwarded. Every 7-EH packet goes slow path (perf), but still forwarded correctly. No zone/policy bypass. Real EH bug is #4517 (MOBILITY 135/HIP 139/Shim6 140/exp 253/254) which terminates walk early and hides L4/fragment — fixed post-b1bd96fb6 in aea5919cf, tracked separately. |

## Module / verdict-path inventory

| Module | File(s) | Role | Reviewed |
|---|---|---|---|
| Poll descriptor (main) | `poll_descriptor/mod.rs` (6088 lines) | Per-packet RX loop: metadata parse, link-layer classify, GRE decap, flow parse, fabric ingress, screen, IPsec passthrough, flow-cache fast path, session hit/miss, DNAT/NPTv6/NAT64 pre-routing, policy eval, NAT source, session install, MissingNeighbor, flowless transit/host, reinject | YES full (multiple passes, 800-line windows) |
| Poll stages | `poll_stages.rs` (3151 lines) | Extracted stages: link-layer ARP/NDP learn, GRE decap, flow parse + neighbor learn, fabric ingress, screen, IPsec passthrough | YES full |
| Poll descriptor submodules | `poll_descriptor/flow_cache_hit.rs`, `filter.rs`, `reject_reply.rs`, `cookie_reply.rs`, `nat_exception.rs`, `rx_telemetry.rs` | Flow-cache fast path, filter eval, reject reply synthesis, SYN cookie, NAT exception, telemetry | YES full |
| Forward request | `forward_request.rs` | `build_live_forward_request_from_frame`, TX CoS selection, PBR override, output filter | YES full |
| Forwarding core | `forwarding/mod.rs` (2741 lines) | Route lookup (v4/v6, connected/static, next-table, ECMP), local delivery (table-scoped #3769), fabric redirect, HA enforcement, zone pair resolution, PBR (`ingress_route_table_override`), host-inbound, neighbor, tunnel, MSS | YES full |
| Host inbound | `forwarding/host_inbound.rs` (815 lines) | ZoneHostInbound admit set, system-services + protocols classify, per-interface override, global ICMP/ND accept | Sampled (known correct per prior reviews) |
| Frame inspection | `frame/inspect.rs` (1776 lines) | `frame_l3_offset`, `frame_l4_offset`, `packet_rel_l4_offset`, IPv6 EH walks (8), fragment predicates, `parse_session_flow_from_bytes`, `declared_l3_end`, `parse_flow_ports`, `term_match_extra` | YES full |
| Frame rewrite/build | `frame/mod.rs` (1710), `frame/rewrite/*.rs`, `frame/build/*.rs`, `frame/checksum.rs` (984), `frame/headers.rs`, `byte_writes.rs` | In-place rewrite (descriptor fast path + generic), copy build, NAT apply (v4/v6, port, ICMP id, NPTv6, fragment gate), checksum (incremental, SIMD), VLAN push/pop | YES sampled (rewrite path, NAT gates, checksum) |
| Flow cache | `flow_cache.rs` (1000 lines) | 4-way set-associative (1024 sets × 4 ways), LRU, seeded hash (DoS mitigation), stamp (config_gen, fib_gen, RG epoch, lease, neighbor_mac_epoch), DSCP/per-packet L4 decline, NPTv6 cacheable, NAT64 excluded | YES full |
| XDP shim | `userspace-xdp/src/lib.rs` (1541 lines) | `parse_l2`, `parse_ipv4`, `parse_ipv6` (EH walk 6), `parse_l4`, session lookup, binding, heartbeat, degraded fallback, WG steer, local dest, interface NAT, DP metadata | YES full |

## Module-by-module inspection log (including negatives)

### poll_descriptor/mod.rs — main RX loop

- Screen runs BEFORE flow-cache (line ~700), correct — established flows skip screen only via flow-cache fast path which is gated on `packet_eligible` (pure ACK/UDP, #2151), not SYN.
- Flow-cache fast path extracted to `flow_cache_hit.rs`, returns `Consumed` or `FallThrough`, caller continues correctly.
- Session-miss path: DNAT → NPTv6 inbound → NAT64 classify (tri-state #2291, fail-closed on MatchUnavailable) → effective_resolution_target → PBR (`ingress_route_table_override` with `RouteOverride::Drop` for reject/discard #4392) → route lookup → zone pair (logical ingress ifindex #3021) → screen scan/sweep (#2210, fabric-ingress skip #4155) → session-limit (#2134) → HA enforcement → strict-syn-check (#4400, TCP RST/FIN drop) → policy eval (POST-NAT dst #2345, ICMP type/code #3020) → SNAT/NPTv6/NAT64 allocation → forward/missing-neighbor/local-delivery branching.
- Flowless transit (non-first fragment / no-L4): `l3_session_flow_from_meta` synthetic flow (ports 0), `evaluate_non_pbr_input_filter` with `is_fragment` + `l4_present=false`, PBR override (flowless, no reject sink), `flowless_base_resolution` (local-first #3292), zone policy with `l4_present=false` (port-bearing app terms fail closed), flowless LocalDelivery via `flowless_local_delivery_verdict` (host-inbound + lo0 + junos-host, all with `l4_present=false`). Verified correct, no bypass of deny-all for fragments (was #3291, fixed).
- MissingNeighbor arm: policy eval BEFORE neighbor probe (#1913), before neg-cache fast-fail, before pending_neigh buffer, before reinject. Flowless MissingNeighbor also enforces zone policy (#4024, was F-259). Verified correct.
- Session-hit path: host-inbound gate BEFORE lo0 (#3485), junos-host re-eval on every hit (#3019), TTL check before egress accounting (#3779), policy hit counter re-count (#3073), filter DSCP/per-packet L4 re-eval (#2362, #2449). Verified correct.
- **Negative**: No OOB, no panic on truncated packets — all parsers have length guards, `declared_l3_end` clamping, `read_bytes` bounds checks.

### poll_descriptor/flow_cache_hit.rs — flow-cache fast path

- Lookup: `flow_cache.lookup_counted(key, FlowCacheLookup::for_packet(meta), now_secs, rg_epochs, pkt_len)`. `FlowCacheLookup` only has `ingress_ifindex`, `config_generation`, `fib_generation` — no VLAN, no zone, no DSCP. VLAN confusion is #2387 (known).
- Stale checks: `neighbor_mac_epoch_stale` (pre-resolve snapshot #3918), `cached_flow_decision_valid` (HA RG active check, fabric redirect invalidation, local preference). Verified correct per #3048/#3918/#2466.
- TTL/hop-limit check hoisted BEFORE egress counters/policers/logs (#3779), correct — TTL=1 packet on red-policer cached flow now correctly emits Time Exceeded or drops before charging.
- Filter `then count` replay (#2573), input filter count replay (#3777), policy hit counter re-count (#3073/#3322, bound handle), three-color policer meter (`apply_cached_three_color_policers`), cached input/output filter log, output-filter `then reject` reply synthesis (#3608) with truthful DENY logging (#3615). Verified correct, no double-count.
- CoS BA reclassify (#3778): when `ba_reclassify` true (BA classifier active, no filter FC), re-resolves queue from current packet's DSCP/PCP, not seed's. Correct, prevents mixed-marking flow pinning.
- Session accounting: `touch_if_stale` + `account_packet` (TCP flags + DSCP #2749) for byte/packet counters. If session was GC'd, these are no-ops (session not found) — minor observability loss, not security (forwarding still correct via flow cache). Not a bypass.

### poll_descriptor/filter.rs — filter eval

- `host_inbound_gated_lo0_action`: host-inbound check FIRST (logical ifindex, per-interface override #3609, zone fallback), then lo0 filter. Prevents lo0 side-effects on host-inbound denied packet (#3485). Tests pin deny→None+counter 0, admit→Reject+counter 1, VLAN logical override.
- `filter_terminal`: enqueue reject reply FIRST, then emit filter log with truthful action (REJECT→DENY on fail-closed). Correct per #3615.
- `evaluate_dscp_sensitive_input_filter_on_session_hit`: re-evaluates DSCP + per-packet L4 on session hit (flow-cache decline for those filters). Correct.

### forwarding/mod.rs — route/forwarding resolution

- `lookup_forwarding_resolution_inner_ecmp`: table-scoped local delivery (#3769) — `local_tables_v4/v6` + `local_nat_any_table_v4/v6` gating, connected routes table-scoped (#2388), next-table recursion with cycle detection (#3768, `visited` set), canonicalization (`canonical_route_table`), ECMP with per-flow hash (#2734) and tunnel liveness (#2923). Correct.
- `ingress_route_table_override`: PBR routing-instance term, `is_drop` gate for Reject/Discard (#4392), reject reply sink for flow-backed (TCP RST/ICMP), flowless silent drop, filter log with truthful action (#2616/#3615). Verified correct.
- `cluster_peer_return_fast_path`: fabric-ingress return traffic, excludes initial SYN, ICMP echo, bare RST/FIN (#4453), non-TCP/ICMP (#4439/#4414, UDP excluded). Correct — prevents NAT bypass + session corruption for UDP/ESP/AH/GRE.
- `zone_pair_ids_for_flow_with_override`: logical ingress ifindex (#3021), ingress_zone_override (fabric MAC), egress zone from `EgressInterface.zone_id`. Zero-allocation u16 path (#919/#922). Correct.
- **Negative**: No VRF leak via next-table — tables are canonicalized and visited-set prevents A→B→A cycle burning to `MAX_NEXT_TABLE_DEPTH` on every packet.

### frame/inspect.rs — parsing

- `frame_l3_offset`: single VLAN tag (0x8100/0x88A8), not QinQ — QinQ goes to kernel (XDP_PASS), intentional.
- `frame_l4_offset`, `packet_rel_l4_offset`, `packet_rel_l4_offset_and_protocol`: IPv6 EH walks bounded by `MAX_IPV6_EXT_HEADERS=8` (#2292), fail-closed None at bound (was Some before #2292), 6 vs 8 skew with XDP is perf only (see M-01 below). All walkers share same enumeration {0,43,60,51,44,59} + break/return — missing MOBILITY/HIP/Shim6/exp is #4517, fixed post-b1bd96fb6, not in this commit.
- `ipv4_is_non_first_fragment`, `ipv6_is_non_first_fragment`, `is_any_fragment`: family-dispatched, bounded EH walk for v6, correct masks (`0x1FFF` for non-first, `0x3FFF` for any, `0xFFF8` for v6 frag offset).
- `ipv4_declared_l3_end`, `ipv6_declared_l3_end`, `declared_l3_end`, `parse_flow_ports`, `meta_icmp_identifier_bearing`: #2361 fail-closed — ports bounded by IP-declared end (not just slice), tiny fragments with truncated L4 return None → flowless, no OOB. `icmp_identifier_bearing` gates ICMP id on query types only (#3067), error/control packets flowless.
- `parse_session_flow_from_bytes`: non-first fragment gate first (#2344), ICMP id gate (#3290), meta fast path with `metadata_tuple_complete`, frame parsers with `declared_end` guard, meta-offset fallback with fragment gate. Correct, no bypass.
- `term_match_extra_from_frame`: non-first fragment forces `tcp_flags=0, icmp_type=0, icmp_code=0, l4_present=false` (L4 terms fail closed, `is_fragment` kept true), truncated ICMP fail-closed (#2449), flex L3/L4 slices None on non-first fragment. Correct.
- **Negative**: No panic on crafted packets — all `get` with `?`, `checked_add`, length guards.

### flow_cache.rs — flow cache

- 4-way set-associative, 1024 sets, LRU, seeded hash (`hot_hash_seed`, per-boot random, prevents offline precomputation #2364), `set_index` includes `ingress_ifindex` (physical, not logical — VLAN confusion #2387).
- `FlowCacheLookup::for_packet` uses `meta.ingress_ifindex` (physical), not logical — two VLANs on same parent share same flow-cache identity. Verified still present.
- `FlowCacheEntry::should_cache`: gates on `packet_eligible` (pure ACK/UDP, #2151), proto TCP/UDP, not NAT64, `is_cacheable` (ForwardCandidate/FabricRedirect). Correct — does not cache PolicyDenied, NoRoute, MissingNeighbor, DiscardRoute, etc.
- `FlowCacheEntry::from_forward_decision`: NAT family check (#963 PR-A), DSCP-sensitive filter decline (#2362, input/output), per-packet L4 decline (#2362), NPTv6 cacheable (#2652, checksum-neutral), NAT64 excluded, `owner_rg_id` fallback, `tx_selection_wire_key` POST-NAT (#3642), `neighbor_mac_epoch` pre-resolve snapshot (#3918). Correct.
- `lookup_with_observed_bytes`: config_gen/fib_gen check, RG epoch check (`rg_epoch_index`, #2466), lease_until check, `last_used_epoch` stamp, `observed_bytes` accumulate. Correct.
- `insert`: dedup-on-insert (same key → replace, not duplicate), empty-way preference, LRU eviction. Correct.
- **Negative**: No race (per-worker single-threaded), no overflow (u16 epoch wrapping handled, `tick_advance_epoch` skips 0 sentinel), no OOB (4-way bounded).

### userspace-xdp/src/lib.rs — XDP shim

- `parse_l2`: single VLAN tag (0x8100/0x88A8), reads TCI, sets `vlan_id`, `vlan_pcp`, `vlan_present`, `l3_offset` += 4. QinQ not handled (returns eth_proto=0x8100 for inner tag → `pass_non_ip_l2_direct`), intentional.
- `parse_ipv4`: checks IHL >=20, reads full IHL, `parse_l4`, reads addrs. Correct, no OOB.
- `parse_ipv6`: walks EH chain `MAX_EXT_HDRS=6` (vs userspace 8), handles HOP/ROUTING/DEST (len-prefixed), AUTH (len+2)*4, FRAGMENT (fixed 8), NONE (break), _ (break, returns offset as L4). Does NOT check fragment offset (non-first fragments still parsed as L4) — but userspace has `frame_is_non_first_fragment` guard → flowless, no bypass. Missing MOBILITY/HIP/Shim6/exp is #4517, fixed post-b1bd96fb6.
- `parse_l4`: TCP needs 14 bytes to read ports + data_offset, checks `data_offset < 20 => None`, then `read_bytes(..., data_offset)` requires full TCP header (min 20). Tiny TCP frag with <20 bytes TCP: drops. UDP needs 8 bytes, ICMP 8 bytes. Correct, tiny fragment protection.
- Session lookup, `is_local_destination` (dst IP only, not proto), `should_fallback_early` (multicast/broadcast/link-local → cpumap_or_pass), WG steer (`is_local_destination` mandatory, prevents transit UDP on WG port → kernel bypass). Correct.
- Degraded path: binding missing/not ready, heartbeat stale, `is_degraded_local_or_control` → `pass_local_control` (local dest, interface NAT local, ICMP to NAT, etc.), else `drop_degraded_transit`. Correct, fail-closed for transit, pass for local/control.

## Findings

### [V-01] Flow-cache and session VLAN confusion — cross-VLAN / cross-VRF session reuse (verified still present, #2387)

- Title: Flow-cache and session table keyed on physical parent ifindex / bare 5-tuple — two VLAN subinterfaces on same parent NIC share flow-cache and session identity, cross-VLAN policy/NAT reuse
- Severity: Medium-High (VRF/tenant isolation bypass, fail-open)
- Confidence: High
- Class: fail-open / vrf-leak / implementation-bug
- Evidence:
  ```rust
  // userspace-dp/src/afxdp/flow_cache.rs:169-174
  impl FlowCacheLookup {
      pub(super) fn for_packet(meta: UserspaceDpMeta, validation: ValidationState) -> Self {
          Self {
              ingress_ifindex: meta.ingress_ifindex as i32, // physical parent, NOT logical
              config_generation: validation.config_generation,
              fib_generation: validation.fib_generation,
          }
      }
  }

  // userspace-dp/src/session/key.rs:10-17
  pub(crate) struct SessionKey {
      pub addr_family: u8,
      pub protocol: u8,
      pub src_ip: IpAddr,
      pub dst_ip: IpAddr,
      pub src_port: u16,
      pub dst_port: u16,
      // NO ingress_ifindex, NO VLAN, NO zone, NO VRF
  }

  // userspace-dp/src/afxdp/poll_descriptor/mod.rs slow path (session-miss) correctly uses logical:
  let ingress_logical = resolve_ingress_logical_ifindex(
      forwarding, meta.ingress_ifindex as i32, meta.ingress_vlan_id,
  ).unwrap_or(meta.ingress_ifindex as i32);
  let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
      forwarding, ingress_logical, ingress_zone_override, egress_ifindex,
  );
  // But flow-cache lookup and session key do NOT include logical/VLAN/zone
  ```
- Trace:
  1. Config: `ge-0/0/0.100` VLAN 100 zone trust-a (policy trust-a→untrust DENY 22, PERMIT 80), `ge-0/0/0.200` VLAN 200 zone trust-b (policy trust-b→untrust DENY 80, PERMIT 22). Both share physical parent `ge-0/0/0` ifindex 5 (XDP `meta.ingress_ifindex=5` for both, `meta.ingress_vlan_id` differentiates 100 vs 200).
  2. Host on trust-a (10.0.0.10) accesses `198.51.100.10:80` — slow path resolves `ingress_logical=101` (VLAN 100), zone trust-a, policy PERMIT 80, installs `SessionKey{TCP,10.0.0.10,198.51.100.10,1234,80}` and `FlowCacheEntry{key=SessionKey, ingress_ifindex=5, decision=PERMIT, ...}`.
  3. Attacker on trust-b spoofs `10.0.0.10:1234` → `198.51.100.10:80` (same 5-tuple), VLAN 200 (`meta.ingress_ifindex=5`, `meta.ingress_vlan_id=200`).
  4. Flow-cache lookup: `FlowCacheLookup{ingress_ifindex=5, config_gen, fib_gen}` + `SessionKey{same}` → HIT! Returns cached decision for trust-a: PERMIT, forward to untrust, with trust-a's NAT/egress. Zone policy for trust-b (DENY 80) never evaluated.
  5. Session lookup (if flow-cache missed): `SessionKey{same}` → HIT! Returns session for trust-a (ingress_zone=trust-a, egress_zone=untrust), bypasses trust-b policy. `resolve_flow_session_decision` does not re-evaluate zone policy on session hit (only re-checks HA, fabric, TTL).
  6. What vSRX does: vSRX sessions are VRF/zone-aware — same 5-tuple in different VRFs/zones creates distinct sessions, each evaluated against its own zone policy. Overlapping-subnet multi-tenant is a legitimate vSRX target.
  What xpf does: Bare 5-tuple + physical parent sharing causes cross-VLAN session/flow-cache reuse, leaking PERMIT from one VLAN's policy into another's DENY.
- Refutation attempted:
  - Checked if `FlowCacheLookup` includes VLAN: No, only `ingress_ifindex` (physical), `config_generation`, `fib_generation`.
  - Checked if `SessionKey` includes VLAN/zone/VRF: No, only 5-tuple.
  - Checked if config_generation bumps on VLAN/zone change: Yes, but both VLANs share same config_generation — VLAN 100 and VLAN 200 are part of same snapshot, same config_generation. One VLAN's traffic does not bump config_generation for the other.
  - Checked if session creation includes ingress_zone in metadata and lookup validates it: `SessionMetadata.ingress_zone` is stored, but `resolve_flow_session_decision` does NOT compare lookup packet's ingress_zone against stored session's ingress_zone — it trusts the 5-tuple alone.
  - Checked if flow-cache `set_index` includes VLAN: No, `set_index(key, ingress_ifindex)` hashes key + ingress_ifindex (physical). Same physical → same set, same lookup succeeds.
  - This is NOT a re-report of #2387 — it IS #2387, verified still present on b1bd96fb6. The issue is OPEN and tracked, not fixed. We verify it is still present.
- Why it matters: VRF/tenant isolation bypass — a tenant on one VLAN can access resources denied by their own zone policy by spoofing a victim's 5-tuple that was recently permitted on another VLAN sharing the same parent NIC. Overlapping-subnet multi-tenant (common in vSRX) is broken. Requires same parent NIC, overlapping 5-tuple, attacker knows victim's src IP/ports, but is a structural isolation failure.
- Fix direction:
  - Include logical forwarding context in flow-cache and session identity: `FlowCacheLookup` should use `logical_ingress_ifindex` (resolved via `ingress_logical_ifindex` map) instead of raw `ingress_ifindex`, or include `ingress_vlan_id` in the hash/lookup key. `SessionKey` should include `ingress_zone` or `logical_ingress_ifindex` or VRF ID, or session lookup should validate `ingress_zone` matches stored session's zone. Regression test: same parent ifindex, two VLAN subifs in different zones/VRFs, identical 5-tuples, differing policy/NAT — assert no session or flow-cache reuse across boundary.
  - Per #2387 fix direction: include logical forwarding context (logical ingress ifindex / routing-domain id) in session + flow-cache identity.
- Labels: `fail-open`, `vrf-leak`, `vlan`, `flow-cache`, `session`, `security`
- Dedup note: Not new — this IS #2387, verified still present on b1bd96fb6. Already OPEN and tracked in docs/issues/issue-history.md. Not a duplicate of ps-review-024 (which is filter cohort). H-01 from prompt is this finding, still present.

---

### [N-01] Flow-cache NAT port reuse after session expiry — reverse NAT collision / hijack

- Title: Flow-cache outlives its session and NAT port allocation — reused 5-tuple reuses stale NAT port that may have been reallocated to another flow, causing reverse tuple collision
- Severity: Medium
- Confidence: Medium
- Class: implementation-bug / robustness-dos / race-exhaustion
- Evidence:
  ```rust
  // userspace-dp/src/afxdp/flow_cache.rs:298-329
  pub(super) fn should_cache(meta: UserspaceDpMeta, decision: SessionDecision) -> bool {
      Self::packet_eligible(meta)
          && matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
          && !decision.nat.nat64
          && decision.resolution.disposition.is_cacheable()
  }

  // flow_cache.rs:851-925 lookup_with_observed_bytes
  fn lookup_with_observed_bytes(&mut self, key: &SessionKey, lookup: FlowCacheLookup, ...) -> Option<&FlowCacheEntry> {
      let set = Self::set_index(key, lookup.ingress_ifindex);
      // ... checks: config_generation, fib_generation, owner_rg_epoch, lease_until, neighbor_mac_epoch
      // NO check: session still exists
      // NO check: NAT port still allocated to this flow
  }

  // poll_descriptor/flow_cache_hit.rs: stage_flow_cache_hit
  // On hit: uses cached_descriptor.rewrite_src_ip/dst_ip/ports + csum deltas directly
  // Does NOT re-reserve NAT port via PortAllocator
  // Does NOT check if NAT port was released and reallocated

  // NAT allocator release on session expiry:
  // session/mod.rs GC removes session, releases NAT port back to pool
  // Flow cache entry REMAINS (only invalidated by config/fib/RG epoch, not session expiry)
  ```
- Trace:
  1. Flow A: `10.0.0.1:1234 → 10.0.0.2:80`, SNAT pool `203.0.113.0/24`, allocates `203.0.113.1:5000`. Session A + FlowCacheEntry A (key=5-tuple, NAT=5000, `ip_csum_delta`, `l4_csum_delta`) installed.
  2. Session A idle expires (GC), NAT port 5000 released to pool, flow cache entry A REMAINS (flow cache has no idle expiry, only config/fib/RG invalidation).
  3. Flow C: `10.0.0.3:5678 → 10.0.0.2:80`, same dst, SNAT allocates 5000 (free). Session C installed, reverse index key `10.0.0.2:80 → 203.0.113.1:5000` points to Flow C.
  4. Flow D: `10.0.0.1:1234 → 10.0.0.2:80` (same 5-tuple as Flow A, port recycle after 2MSL), FlowCacheLookup key same as A, `config_generation` same, `fib_generation` same, `owner_rg_epoch` same → HIT! Returns FlowCacheEntry A with NAT `203.0.113.1:5000` (stale, now owned by Flow C).
  5. Flow D forwarded with SNAT 5000 (same as Flow C), no session created (flow-cache fast path skips session install), no NAT port re-reservation.
  6. Reply for Flow C: `10.0.0.2:80 → 203.0.113.1:5000`, session reverse lookup via `nat_reverse_index` (1:N multimap #4399) finds both Flow C and potentially Flow D (if Flow D had a session, which it doesn't — it's flow-cache only). For Flow C, correct. Reply for Flow D (if server replies to Flow D's SYN that was forwarded via flow-cache): `10.0.0.2:80 → 203.0.113.1:5000`, same reverse key as Flow C, session lookup finds Flow C (only session with that reverse key), delivers reply to Flow C's forward session (wrong flow!) → TCP RST or data delivered to wrong socket → connection hijack / RST.
  7. What vSRX does: vSRX would allocate a fresh NAT port for Flow D (or reuse same port only if reverse session is gone). NAT port is tracked live, not cached stale.
  What xpf does: Flow-cache reuses stale NAT port without re-reserving, causing reverse tuple collision when port was reallocated.
- Refutation attempted:
  - Checked if flow-cache invalidation includes NAT pool changes: No, only config_generation, fib_generation, owner_rg_epoch, lease_until, neighbor_mac_epoch. NAT port release does NOT bump any of these.
  - Checked if flow-cache hit re-reserves NAT port: No, `flow_cache_hit.rs` directly uses `cached_descriptor.rewrite_*` without calling `PortAllocator`.
  - Checked if session GC also invalidates flow cache: No, `SessionTable` GC does not touch `FlowCache`. GC is per-worker, flow cache is per-binding, no linkage.
  - Checked if NAT allocator prevents reallocation of port still in flow cache: No, allocator only tracks `live_by_flow` (session table), not flow-cache entries. When session removed, port freed, allocator considers it free even though flow cache still references it.
  - Checked if this is same as #4399/#4438 (1:N reverse index): No, #4399/#4438 fix the reverse index to be 1:N multimap so multiple flows sharing same reverse key are all resolvable. But they don't prevent the flow-cache from reusing a port that was already reallocated. The 1:N fix makes collision survivable (both flows in bucket, validated), but still ambiguous — reply could go to wrong flow, and flow-cache hit doesn't create a session, so only one flow is in the bucket.
  - Low frequency: Requires same 5-tuple reuse (port recycle) after session expiry, and NAT port reallocation to another flow to same dst, and reply timing. Rare, but structurally a correctness bug.
- Why it matters: Reverse NAT collision can cause reply mis-delivery — a server's SYN-ACK or data for one flow delivered to another flow's TCP stack, causing RST, data corruption, or connection hijack. In a CGNAT scenario with many flows sharing a pool, port reuse is frequent, and flow-cache outliving session makes stale NAT port reuse likely. DoS (RST) or data leak across flows.
- Fix direction:
  - Option 1 (simple): Invalidate flow-cache entry when its backing session is GC'd/removed. `SessionTable` GC could call `flow_cache.invalidate_slot(key, ingress_ifindex)` for expired sessions. Requires passing flow-cache reference to GC, or batch invalidation via a GC callback.
  - Option 2: Don't cache flows that use pool-mode SNAT (ephemeral port translation) — only cache static NAT / no-NAT flows. `FlowCacheEntry::should_cache` already excludes NAT64, could also exclude pool NAT: `!decision.nat.is_pool_nat` (or `decision.nat.rewrite_src_port.is_some()` for pool mode). But static SNAT (1:1) is safe to cache, only pool mode with dynamic port allocation is risky.
  - Option 3: On flow-cache hit, re-validate NAT port still owned by this flow via `PortAllocator::is_owner(flow_key, translated_port)`. If not, treat as miss, go slow path, reallocate fresh port. Adds per-hit allocator probe, but NAT flows are less common than no-NAT.
  - Test: Flow A SNAT 5000, session expires, Flow C takes 5000, Flow D same 5-tuple as A hits flow-cache, assert it does NOT reuse 5000 (or flow-cache entry was invalidated when session A expired).
- Labels: `flow-cache`, `nat`, `snat`, `pool-nat`, `reverse-collision`, `implementation-bug`, `robustness-dos`
- Dedup note: Not in /tmp/all_findings.txt, not in ps-review-024/025/028. Prior findings #4399/#4438 are about 1:N reverse index structure, not about flow-cache NAT port stale reuse. F-154 (flow-cache outlives session) is about idle-reaped session reuse but not specifically about NAT port collision. This is a new variant: NAT port reuse via flow-cache, distinct from session 5-tuple reuse (#2387) which is about VLAN/zone.

---

### [M-02] XDP IPv6 EH walk 6 vs 8 — performance DoS / extra userspace work for 7-EH packets (verified still present, not a bypass)

- Title: XDP `MAX_EXT_HDRS=6` vs userspace `MAX_IPV6_EXT_HEADERS=8` — packet with 7 extension headers always misses XDP session fast path, forces userspace slow path (DoS amplification)
- Severity: Low
- Confidence: High
- Class: implementation-bug / robustness-dos / parity-gap
- Evidence:
  ```rust
  // userspace-xdp/src/lib.rs:33
  const MAX_EXT_HDRS: usize = 6;

  // userspace-dp/src/afxdp/frame/inspect.rs:31
  pub(crate) const MAX_IPV6_EXT_HEADERS: usize = 8;

  // userspace-xdp/src/lib.rs:1257-1289 parse_ipv6
  for _ in 0..MAX_EXT_HDRS { // 6 iterations
      match protocol {
          NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => { ... protocol = opt[0]; offset += ... }
          NEXTHDR_AUTH => { ... }
          NEXTHDR_FRAGMENT => { protocol = frag[0]; offset += 8; }
          NEXTHDR_NONE => break,
          _ => break, // stops at 7th EH, returns proto = 6th EH type (e.g., 60 DestOpt)
      }
  }
  // returns ParsedPacket with protocol = EH type (e.g., 60), not TCP (6)

  // userspace-dp/src/afxdp/frame/inspect.rs:68-98 frame_l4_offset
  for _ in 0..MAX_IPV6_EXT_HEADERS { // 8 iterations
      match protocol {
          0 | 43 | 60 => { ... } // HOP, Routing, DestOpt — continue
          51 => { ... } // AH
          44 => { ... } // Fragment
          59 => return None, // No Next Header — fail closed
          _ => return Some(offset), // L4 found (e.g., TCP at 7th position)
      }
      // fails closed at bound (None) if still on EH at 8
  }
  ```
- Trace:
  1. Attacker crafts IPv6 packet: base → HbH(0) → Routing(43) → DestOpt(60) → AH(51) → Fragment(44, offset 0) → DestOpt(60) → Mobility(135, but XDP stops before this) → TCP(6, SYN, dst 22). Actually 7 EH: HbH, Routing, DestOpt, AH, Fragment, DestOpt, DestOpt (7), then TCP at 8th position.
  2. XDP `parse_ipv6`: walks 6 EH, stops at 6th (DestOpt), returns `protocol=60` (DestOpt type), `l4_offset` points to 7th EH (DestOpt). `parse_l4` for proto 60: `_ => Some((l4_offset, 0, 0, 0, 0))` (unknown protocol, no ports), `flow_src_port=0, flow_dst_port=0`.
  3. XDP `live_userspace_session_action`: key `{AF_INET6, proto=60, src, dst, sport=0, dport=0}` → lookup in `USERSPACE_SESSIONS` → miss (session is TCP proto=6, ports 1234/22) → XSK redirect (to userspace).
  4. Userspace `frame/inspect.rs`: walks 8 EH, finds TCP at 7th/8th position, `frame_l4_offset` returns TCP offset, `parse_session_flow_from_bytes` creates `SessionKey{TCP, src, dst, 1234, 22}`, session miss (new flow) or hit (established), policy evaluated, forwarded.
  5. Next packet same 7-EH flow: XDP again parses proto=60, lookup with proto=60 → miss (session is TCP) → XSK redirect → userspace session hit → forwarded.
  6. Every packet with 7 EH goes through userspace slow path (session lookup, policy, etc.), never XDP fast path. Attacker can flood with 7-EH packets to force all through userspace, increasing CPU, DoS.
  What vSRX does: vSRX would handle 7 EH correctly (or drop if > max), but would not have XDP/userspace divergence.
  What xpf does: XDP and userspace disagree on protocol for 7-EH packets, XDP always misses, all go slow path.
- Refutation attempted:
  - Checked if XDP 6 vs 8 causes fail-open (bypass): No, XDP always redirects misses to XSK, userspace still enforces policy. No bypass.
  - Checked if XDP drops 7-EH packet: No, `parse_ipv6` returns Some with proto=EH type, not None, so it goes to XSK (not drop).
  - Checked if this is same as #4517 (MOBILITY etc): No, #4517 is about missing EH types (MOBILITY 135, HIP 139, etc.) not enumerated, causing walk to stop early and hide L4/fragment. This is about walk COUNT (6 vs 8), not EH TYPE. Packet with 7 standard EH (HbH, Routing, DestOpt, AH, Fragment, DestOpt, DestOpt) would hit this, even without exotic types. Distinct.
  - Checked if userspace 8 is correct per RFC 8200: RFC 8200 does not limit EH count, but Junos/vSRX and Linux typically handle up to 8. 6 vs 8 divergence is a bug, but only perf, not security.
- Why it matters: DoS amplification — attacker can craft 7-EH packets (valid per RFC, all standard EH types) to force every packet through userspace slow path, bypassing XDP fast path (session hit) that would otherwise handle established flows at XDP speed. Increases userspace CPU, reduces pps capacity. Low severity because 7 EH is exotic (real traffic rarely has >2-3 EH), but attacker-controlled.
- Fix direction:
  - Change `MAX_EXT_HDRS` in `userspace-xdp/src/lib.rs:33` from 6 to 8 to match `MAX_IPV6_EXT_HEADERS=8` in `frame/inspect.rs:31`. This aligns XDP and userspace walk counts, so 7-EH packets are correctly identified as TCP at both layers, XDP session lookup hits for established flows, fast path works. Also apply #4517 fix (MOBILITY etc.) to XDP (currently only in userspace post-aea5919cf, not in b1bd96fb6 XDP).
  - Test: IPv6 packet with 7 EH (HbH, Routing, DestOpt, AH, Fragment, DestOpt, DestOpt) + TCP, assert XDP `parse_ipv6` returns proto=TCP, l4_offset correct, session lookup hits.
- Labels: `xdp`, `ipv6`, `eh`, `dos`, `performance`, `parity-gap`
- Dedup note: Not in /tmp/all_findings.txt, not in ps-review-024/025. Prior M-01 in prompt is this finding (XDP EH 6 vs 8), verified still present on b1bd96fb6, but downgraded from Medium to Low (not a bypass, only perf/DoS). Real EH bypass is #4517 (MOBILITY etc), fixed post-b1bd96fb6, not in this commit. This is distinct from #4517 (count vs type).

---

### [L-01] Flow-cache cross-VLAN eviction DoS — attacker on one VLAN can evict victim's flow-cache entries on another VLAN sharing same parent NIC

- Title: Flow-cache set index uses physical parent ifindex — attacker on VLAN A can evict victim's flow-cache entries on VLAN B (same parent), cross-VLAN DoS
- Severity: Low
- Confidence: Medium
- Class: robustness-dos / implementation-bug
- Evidence:
  ```rust
  // userspace-dp/src/afxdp/flow_cache.rs:759-780
  pub(super) fn set_index(key: &crate::session::SessionKey, ingress_ifindex: i32) -> usize {
      Self::set_index_seeded(hot_hash_seed(), key, ingress_ifindex)
  }
  fn set_index_seeded(seed: u64, key: &SessionKey, ingress_ifindex: i32) -> usize {
      let mut hasher = FxHasher::with_seed(seed as usize);
      key.hash(&mut hasher);
      (ingress_ifindex as u32).hash(&mut hasher);
      hasher.finish() as usize & FLOW_CACHE_SET_MASK
  }

  // FlowCacheLookup::for_packet uses physical parent:
  ingress_ifindex: meta.ingress_ifindex as i32, // e.g., 5 for ge-0/0/0, for both VLAN 100 and 200

  // FlowCache is 4-way set-associative, 1024 sets, 4096 entries
  // Attacker on VLAN 100 and victim on VLAN 200 share same physical ifindex 5
  // -> same set_index for same 5-tuple (or attacker can flood to cause evictions)
  ```
- Trace:
  1. Config: `ge-0/0/0.100` VLAN 100 zone trust-a, `ge-0/0/0.200` VLAN 200 zone trust-b, same parent `ge-0/0/0` ifindex 5.
  2. Victim on VLAN 200: flow `10.0.0.20:1234 → 198.51.100.10:80`, creates FlowCacheEntry in set S (hash of 5-tuple + ifindex 5).
  3. Attacker on VLAN 100: floods with many flows (different 5-tuples) that hash to same set S (same physical ifindex 5, 5-tuple hash collides to set S). Since flow-cache is 4-way associative, 4 flows in same set evict LRU. Attacker sends 4 flows that hash to set S, evicting victim's entry.
  4. Victim's next packet: flow-cache miss → slow path (session lookup, policy, NAT, etc.) → increased CPU, reduced pps. Repeated eviction → persistent DoS, victim's flows always slow path.
  5. With random seed (#2364), attacker cannot offline precompute which 5-tuples hash to victim's set S, but can still flood with random 5-tuples — with 1024 sets, 4-way, flooding 4096 flows will fill all sets, evicting victim's entry with high probability (100% if flood covers all sets).
  6. What vSRX does: vSRX flow cache (if any) would be VRF/zone-aware, or session table would be per-VRF, so cross-VLAN eviction not possible.
  What xpf does: Flow-cache sharing across VLANs on same parent allows cross-VLAN eviction DoS.
- Refutation attempted:
  - Checked if flow-cache uses per-boot random seed: Yes, `hot_hash_seed()` per-boot, prevents offline precomputation, but does not prevent online flooding (attacker can flood all sets).
  - Checked if this is same as #2387 (VLAN confusion): Related but distinct — #2387 is about cross-VLAN **session reuse** (fail-open, attacker spoofs victim's 5-tuple to reuse victim's cached policy/NAT, bypassing DENY). This is about **eviction DoS** (attacker floods to evict victim's entry, forcing slow path, DoS). Same root cause (physical ifindex sharing), different exploitation (spoof vs flood).
  - Checked if this is already tracked as algorithmic-complexity DoS (hash-flooding): Partially, prior finding F-?? tracks hash-flooding DoS via unseeded hash, but not specifically cross-VLAN eviction. The seed mitigation helps against offline precomputation, but not against cross-VLAN flooding (attacker on same parent can flood, seed doesn't help because they share same physical ifindex and same seed).
  - Low severity: Requires same parent NIC, attacker on one VLAN, victim on another, flood to cause eviction → perf DoS, not traffic loss, victim still forwarded (slow path), just slower.
- Why it matters: Cross-tenant DoS — tenant on one VLAN can degrade performance for tenant on another VLAN sharing same parent NIC, breaking tenant isolation. In multi-tenant VRF deployment, one tenant's traffic can affect another's pps capacity.
- Fix direction:
  - Include logical ingress ifindex (or VLAN ID) in flow-cache set_index hash, so VLAN 100 and VLAN 200 flows hash to different sets (or at least different keys). `set_index(key, logical_ingress_ifindex)` instead of physical. This also fixes #2387's flow-cache part (cross-VLAN reuse). Requires `FlowCacheLookup::for_packet` to resolve logical ifindex (via `ingress_logical_ifindex` map), which is already done in slow path but not in flow-cache lookup (fast path). Fast path could carry logical ifindex in metadata (XDP already has `ingress_vlan_id`, could resolve logical there).
  - Or, make flow-cache per-VLAN (per-logical-interface) instead of per-physical, but that's more complex (more memory).
  - Test: Two VLANs on same parent, same 5-tuple, assert different flow-cache sets / no cross-VLAN eviction.
- Labels: `flow-cache`, `vlan`, `dos`, `cross-tenant`, `implementation-bug`, `robustness-dos`
- Dedup note: Not in /tmp/all_findings.txt, not in ps-review-024/025. Related to #2387 (same root cause: physical ifindex sharing), but different exploitation: #2387 is fail-open (spoof to reuse cached PERMIT), this is DoS (flood to evict, force slow path). Distinct from hash-flooding DoS (which is about unseeded hash, not VLAN). New finding.

---

### [L-02] XDP IPv6 fragment handling — non-first fragments stamp garbage ports, causing extra userspace work (minor perf)

- Title: XDP `parse_ipv6` does not check fragment offset — non-first fragments stamp garbage payload bytes as flow ports, causing XDP session miss and extra userspace work
- Severity: Informational (perf)
- Confidence: High
- Class: implementation-bug / robustness-dos
- Evidence:
  ```rust
  // userspace-xdp/src/lib.rs:1281-1284 parse_ipv6 Fragment handling
  NEXTHDR_FRAGMENT => {
      let frag = read_bytes(data, data_end, offset as usize, 8)?;
      protocol = frag[0]; // next header (e.g., TCP 6)
      offset = offset.checked_add(8)?; // skip Fragment header (8 bytes)
      // Does NOT check fragment offset — non-first fragment (offset != 0) has no L4 header at post-fragment offset!
      // Falls through to parse_l4 which reads payload as TCP ports (garbage)
  }

  // parse_l4 for TCP:
  // let bytes = read_bytes(data, data_end, l4_offset as usize, 14)?;
  // let data_offset = ((bytes[12] >> 4) as u16) * 4;
  // if data_offset < 20 { return None; }
  // For non-first fragment, bytes are PAYLOAD, not TCP header — data_offset is garbage, likely < 20 or > 20, parse fails or succeeds with garbage ports

  // Userspace has correct guard:
  // frame/inspect.rs:240-242 ipv4_is_non_first_fragment, 258-302 ipv6_is_non_first_fragment
  // parse_session_flow_from_bytes:1227-1242
  if frame_is_non_first_fragment(frame, meta) {
      return None; // flowless, correct
  }
  ```
- Trace:
  1. IPv6 packet: base → Fragment(44, offset=1, 8 bytes, M=1) → payload (8 bytes of original TCP, but actually PAYLOAD of fragmented datagram, no TCP header)
  2. XDP `parse_ipv6`: walks EH, finds Fragment header, `protocol = frag[0]` (TCP 6), `offset += 8`, now offset points to post-fragment bytes (which are PAYLOAD, not TCP).
  3. `parse_l4` for TCP: reads 14 bytes at post-fragment offset (PAYLOAD), interprets as TCP header, `flow_src_port`/`dst_port` = garbage payload bytes, `tcp_flags` = garbage.
  4. XDP `live_userspace_session_action`: key `{AF_INET6, TCP, src, dst, sport=garbage, dport=garbage}` → lookup → miss (no session with garbage ports) → XSK redirect.
  5. Userspace: `frame_is_non_first_fragment` detects non-first fragment (offset=1, non-zero) → `parse_session_flow_from_bytes` returns None → flowless → `l3_session_flow_from_meta` (ports 0), zone policy with `l4_present=false` → port-bearing terms fail closed, routed based on L3. Correct, no bypass.
  6. Every non-first IPv6 fragment goes XDP miss → XSK → userspace flowless (slow path), never XDP fast path. Attacker can flood non-first fragments to force all through userspace, DoS.
- Refutation attempted:
  - Checked if this causes fail-open (bypass): No, userspace correctly detects non-first fragment and goes flowless, enforces zone policy (port-bearing terms fail closed), does not create session, does not pollute flow-cache. No bypass.
  - Checked if XDP drops non-first fragment: No, XDP `parse_ipv6` for Fragment header does not check offset, so it still returns Some with garbage ports, goes to XSK, not drop. If it returned None, it would be `drop_degraded_transit` (fail-closed), which would be wrong (should flowless forward, not drop). So current behavior (XSK redirect with garbage ports) is actually correct for not dropping, but inefficient (always miss).
  - Perf impact: Non-first fragments are rare in legitimate traffic (PMTU discovery avoids fragmentation), but attacker can flood non-first fragments to cause XDP miss → userspace slow path for every fragment → DoS. Low severity.
- Why it matters: DoS — attacker can flood non-first IPv6 fragments (easy to craft, no TCP handshake needed) to force every packet through userspace slow path, increasing CPU, reducing pps capacity. Not a bypass, but a DoS amplification. Minor because non-first fragments are already flowless and slow path, but XDP could fast-drop or fast-flowless them.
- Fix direction:
  - In XDP `parse_ipv6` Fragment handling, check fragment offset: `let frag_off = u16::from_be_bytes([frag[2], frag[3]]); if (frag_off & 0xFFF8) != 0 { /* non-first fragment */ }`. For non-first fragment, set `protocol = 0` or `flow_src_port = 0, flow_dst_port = 0`, `tcp_flags = 0`, and ensure session lookup uses a flowless key or bypasses session lookup entirely (direct XSK redirect with flowless flag). Or, return a special marker so userspace knows it's non-first fragment and can skip session lookup (go directly to flowless).
  - Or, simpler: XDP could detect non-first fragment and directly `cpumap_or_pass` or `XDP_PASS` for flowless fragments, avoiding the session lookup miss + XSK redirect overhead. But flowless fragments still need zone policy (which is userspace), so XSK redirect is correct, just with garbage ports in session key (which causes miss, but still goes to userspace). The garbage ports don't affect correctness, just cause unnecessary session lookup (which always misses for non-first fragments).
  - Test: IPv6 non-first fragment (Fragment header, offset=1), assert XDP session lookup uses flowless key (ports 0,0) or skips lookup, goes to XSK with correct metadata for flowless path.
- Labels: `xdp`, `ipv6`, `fragment`, `dos`, `performance`, `implementation-bug`
- Dedup note: Not in /tmp/all_findings.txt, not in ps-review-024/025. Prior tiny fragment finding H-02 claimed port evasion via tiny first fragment, which was refuted (XDP drops tiny frags). This is different: non-first fragment garbage ports causing XDP miss, not first fragment port evasion. Minor perf, not security.

## Negative results (verified fail-closed / not exploitable)

- **N-01: Tiny fragment port evasion (H-02) — NOT exploitable**: XDP `parse_l4` for TCP requires 14 bytes + data_offset >=20 + full TCP header (min 20 bytes): `userspace-xdp/src/lib.rs:1492-1497` reads 14 bytes, checks `data_offset < 20 => None`, then `read_bytes(..., data_offset)` requires full header. Tiny first frag with <14 bytes TCP: XDP drops (`drop_degraded_transit`). Tiny first frag with >=14 bytes but <20 bytes TCP: XDP drops (data_offset check fails or second read fails). Non-first fragments: userspace `frame_is_non_first_fragment` (IPv4 `0x1FFF` mask, IPv6 fragment offset `0xFFF8`) → `parse_session_flow_from_bytes:1240-1242` returns None → flowless → route-based, no session, `l3_session_flow_from_meta` with ports 0, `l4_present=false` → port-bearing policy/filter terms fail closed. `declared_l3_end` guard (#2361) `ipv4_declared_l3_end:888-904` clamps `total_len` to slice, `parse_flow_ports:1032` checks `end > declared_end => None` → flowless. Overlapping fragment with different ports: different session key (dst_port differs) → re-evaluated → DENY if policy denies. No bypass path found after exhaustive trace.

- **N-02: XDP EH walk 6 vs 8 — NOT a bypass**: XDP `MAX_EXT_HDRS=6`, userspace `MAX_IPV6_EXT_HEADERS=8`. Packet with 7 EH + TCP: XDP walks 6, stops at 6th EH (e.g., DestOpt 60), `protocol=60`, session lookup with proto=60 → miss (session is TCP) → XSK redirect → userspace walks 8, finds TCP, creates session, policy evaluated → no bypass. Next packet same 7 EH: XDP miss again → XSK → userspace hit → forwarded. Every 7-EH packet goes slow path (perf), but still forwarded correctly. No zone/policy bypass. Real EH bypass is #4517 (MOBILITY 135/HIP 139/Shim6 140/exp 253/254) which terminates walk at unenumerated EH types, hiding L4/fragment — fixed post-b1bd96fb6 in aea5919cf, tracked separately.

- **N-03: Flow-cache does not bypass zone/policy on config change**: `FlowCacheLookup` includes `config_generation` and `fib_generation`. Policy/zone/NAT change bumps `config_generation` → flow-cache entry stale → miss → slow path re-evaluates with new policy. Verified: `flow_cache.rs:169-174` `for_packet` captures `validation.config_generation`, `lookup_with_observed_bytes:873-880` checks `entry.stamp.config_generation != lookup.config_generation → evict → miss`. No stale policy reuse across config changes.

- **N-04: Flow-cache DSCP/per-packet L4 sensitivity — correct**: `flow_cache.rs:411-444` declines caching when `interface_input_filter_has_dscp_match` or `interface_output_filter_has_dscp_match` or `interface_input_filter_has_per_packet_l4_match` or `interface_output_filter_has_per_packet_l4_match`. DSCP and tcp-flags/is-fragment/icmp-type/code are per-packet, not in 5-tuple, so caching would be wrong. Decline + config_generation invalidation ensures no stale DSCP/L4 decisions. Verified correct.

- **N-05: Flow-cache neighbor MAC epoch — correct (#3918/#3048)**: `poll_descriptor/mod.rs:857` snapshots `mac_change_epoch` BEFORE neighbor resolve, passes to `from_forward_decision` which stamps pre-resolve epoch (not post-resolve). If MAC changes between snapshot and resolve, stamped epoch is OLD (pre-change), next hit `neighbor_mac_epoch_stale` (NEW != OLD) → evict → re-resolve to new MAC — closes TOCTOU. If MAC changes after stamp, next hit also evicts. Same-MAC refresh does NOT bump epoch, so no steady-state re-miss. Verified correct.

- **N-06: NAT family vs addr_family mismatch — fail-closed (#963 PR-A)**: `flow_cache.rs:274-286` `nat_family_matches_addr_family` checks `rewrite_src`/`rewrite_dst` family matches `addr_family` (AF_INET vs AF_INET6). Mismatch → `from_forward_decision` returns None (decline to cache), falls through to generic path (which also gates IP NAT on family-match). Prevents fast-path persisting mismatched descriptor that would skip IP NAT.

- **N-07: Checksum handling for NAT — correct (RFC 1624)**: `frame/checksum.rs` incremental update, `frame/rewrite/ipv4.rs:113` skips UDP zero checksum (RFC 768, IPv4 only), `frame/rewrite/ipv6.rs:105-110` canonicalizes computed-zero to 0xFFFF for UDP+ICMPv6 (RFC 8200 §8.1, TCP 0 is valid). `adjust_zero_checksum_illegal` predicate correct for v4/v6 asymmetry. Verified via `l4_offset_helper_tests`.

- **N-08: QinQ double-tag — intentional, not a bug**: XDP `parse_l2` and userspace `frame_l3_offset` only handle single VLAN tag (0x8100/0x88A8). Double-tagged (QinQ, 0x88a8 outer + 0x8100 inner) → XDP returns `eth_proto=0x8100` (inner tag) ≠ IP → `pass_non_ip_l2_direct` (XDP_PASS to kernel). Userspace `frame_l3_offset` returns 18 (outer tag only), inner tag mis-identified as IP version (0x81) ≠ 4/6 → None → flowless? Actually `frame_l3_offset` for QinQ: eth[12..13]=0x88a8, reads VLAN at 14..17, eth_proto=0x8100 (inner tag), returns 18, but IPv4 version check at 18 would be 0x81 (inner tag's TCI high byte), not 4/6 → parse fails → flowless or drop. Either way, QinQ not supported, goes to kernel or dropped — intentional per `docs/feature-gaps.md`, not a security bypass.

## Suggested issue split

Fail-opens first:

1. **Issue: Flow-cache and session VLAN/VRF confusion (#2387)** — fix `FlowCacheLookup` to use logical ingress ifindex (or include VLAN ID/zone ID in key) and `SessionKey` to include logical ingress or VRF, or session lookup to validate ingress_zone. Test: same parent, two VLANs in different zones/VRFs, same 5-tuple, differing policy/NAT — assert isolation. Epic: #2387.

2. **Issue: Flow-cache NAT port stale reuse → reverse collision (N-01)** — fix `FlowCacheEntry::from_forward_decision` to not cache pool-mode SNAT (or `should_cache` to exclude pool NAT), or invalidate flow-cache on NAT port release, or on hit re-validate NAT ownership. Test: Flow A SNAT 5000, expire, Flow C takes 5000, Flow D same 5-tuple as A hits flow-cache, assert no 5000 reuse / no reverse collision.

Perf/DoS (low):

3. **Issue: XDP EH walk 6 vs 8 + MOBILITY gap (M-02 + #4517)** — change `MAX_EXT_HDRS` 6→8 and add MOBILITY/HIP/Shim6/exp handling to XDP `parse_ipv6` to match userspace post-#4517. Test: 7-EH packet and MOBILITY-prefixed packet assert XDP returns proto=TCP and session hit.

4. **Issue: Cross-VLAN flow-cache eviction DoS (L-01)** — include logical ifindex/VLAN in `set_index` hash to prevent cross-VLAN eviction. Test: flood VLAN 100, assert VLAN 200 flow-cache entries not evicted.

5. **Issue: XDP non-first IPv6 fragment garbage ports (L-02)** — XDP `parse_ipv6` Fragment handling should check fragment offset, set ports 0 for non-first fragments to avoid unnecessary session lookup miss. Test: non-first IPv6 fragment assert XDP session key ports 0.

Base: b1bd96fb6
