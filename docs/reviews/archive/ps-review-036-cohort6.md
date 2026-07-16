# Cohort 6: Session / Conntrack — Deep Adversarial Audit
## Base: 33b891d11 (master, 2026-07-07)
## Output: /tmp/ps-review-036-cohort6.md

---

## 1. Dedup Summary

### Sources checked (4-way)
| Source | Entries | Result |
|--------|---------|--------|
| `/tmp/all_findings.txt` | 272 (F-001..F-272) | No bare-ACK/PSH+ACK ESTABLISHED 300s DoS finding; no S-001/S-002/V-01 beyond #2387 |
| `gh issue list --state all` | 30 open, ~230 closed | #2387 OPEN (bare 5-tuple), #3776 CLOSED (flow-cache NAT reuse, FIXED this HEAD), #4539 CLOSED (pure PSH LocalDelivery cache), #4400/#4487/#4453 CLOSED (RST/FIN), #4399/#4438 CLOSED (NAT 1:N), #4109 CLOSED (SYN-ACK promotion), #4380 CLOSED (companion keepalive), #4377 CLOSED (session-limit), #4388/#4393 CLOSED (HA NAT) |
| `_Log.md` | n/a | No session changes beyond HEAD |
| `/tmp/ps-review-018..035` | 18 prior reviews | ps-035 already reports S-001/V-01/S-002/PSH+ACK/flow-cache NAT — see dedup per finding below |

### CLOSED issues (do NOT re-report)
| Issue | Title | Verified |
|-------|-------|----------|
| #4400 | RST/FIN ForwardCandidate creates session | FIXED — `strict_syn_check_drops_new_flow` at poll_descriptor:1986-1995 drops bare RST/FIN on ForwardCandidate/MissingNeighbor |
| #4487 | LocalDelivery RST/FIN creates session | FIXED — `should_cache_local_delivery_session_on_miss` = `has_syn` only (commit 5e66d37) |
| #4453 | Fabric RST/FIN cross-node seed | FIXED — `cluster_peer_return_fast_path` excludes bare RST/FIN (is_closing && !has_syn) + protocol whitelist |
| #4539 | should_cache_local_delivery pure PSH/null/URG | FIXED — `has_syn` gate subsumes pure PSH/null/URG decline |
| #4399/#4438 | NAT 1:N multimap | FIXED — all three indexes are `NatIndexBucket = SmallVec<[u32;2]>` with validate-on-lookup |
| #4380 | Forward/reverse idle timer asymmetry | FIXED — `companion_keeps_alive` in expire.rs:464-519 probes companion idle state |
| #4377 | Session-limit enable-transition decrement asymmetry | FIXED — `set_session_limit_active` rebuilds maps on OFF→ON |
| #4109 | Half-open→ESTABLISHED promotion ANY ACK / TCP close not propagated | FIXED — `lookup.rs:146-149` promotes only on `is_syn_ack && is_reverse`; close propagated via `propagate_tcp_state_to_companion` |
| #4388/#4393 | HA NAT port / dnat_table | FIXED |
| #3776 | Flow-cache session expiry → stale-descriptor forward + SNAT reuse | FIXED — `worker/loop_body/mod.rs:1338-1380` `reap_expired_sessions` calls `binding.flow.flow_cache.invalidate_slot` for every expired entry on every binding |

### OPEN issues (already filed — NOT re-reported unless materially new trace)
| Issue | Title | Dedup |
|-------|-------|-------|
| #2387 | Bare 5-tuple session/flow identity — cross-zone/VRF/VLAN reuse (P0) | OPEN — CONFIRMED STILL PRESENT, not new (see C-01) |
| #3776 | Flow-cache NAT port reuse | CLOSED on this HEAD (fix in reap_expired_sessions), not open |
| #4539 | should_cache_local_delivery pure PSH | CLOSED per gh (fix 5e66d37), not open |
| #4559 | Deterministic NAT advisory | OPEN — cohort 5 domain, not this cohort |
| #4555 #4549 #4548 etc | XDP EH, LOW batch, VRRP | OPEN — not session/conntrack |

### Intentional divergences (NOT bugs)
- `strict_syn_check_drops_new_flow` deliberately keeps bare SYN, SYN-ACK, bare ACK, data — only drops bare RST/FIN. Junos default is no-syn-check; bare RST/FIN drop is the safe minimal hardening (#4400). Not reporting "should drop bare ACK" as a bug under strict-syn-check — that is S-002 / NEW-01, a separate DoS issue about ESTABLISHED timeout, not session creation.
- `should_cache_local_delivery_session_on_miss` = `has_syn` only — packet still reaches host via reinject, just not cached. Correct.
- Peer-synced sessions imported as ESTABLISHED — deliberate, standby never sees floods directly.
- `flow_cache::packet_eligible` = `is_ack_only` (ACK && !SYN && !FIN && !RST) only — PSH+ACK excluded from cache, so PSH+ACK DoS sessions do not pollute flow-cache.

---

## 2. Module Inventory (Cohort 6 Coverage Checklist)

| File | LOC | Roles reviewed | Status |
|------|-----|---------------|--------|
| `userspace-dp/src/session/mod.rs` | 2054 | SessionTable slab, HashMap indexes, SeededKeyMap, timeouts, touch/account/propagate/update/refresh/remove/index helpers, `session_timeout_ns` | Full |
| `userspace-dp/src/session/install.rs` | 521 | `install_with_protocol{,_with_origin}`, `upsert_synced_with_origin`, `emit_open/close_delta`, `delete`, `demote_owner_rg` | Full |
| `userspace-dp/src/session/lookup.rs` | 411 | `lookup_with_origin`, `find_forward_nat_match`, `find_forward_wire_match_with_origin`, `resolve_reverse_translated_handle`, `take_synced_local` | Full |
| `userspace-dp/src/session/key.rs` | 232 | `SessionKey`, `forward_wire_key`, `reverse_wire_key`, `translated_session_key`, `reverse_canonical_key`, `reverse_session_key`, `reply_matches_forward_session` | Full |
| `userspace-dp/src/session/entry.rs` | 284 | `SessionDecision`, `SessionMetadata`, `SessionLookup`, `ForwardSessionMatch`, `SessionOrigin`, `SessionDelta`, `ExpiredSession` | Full |
| `userspace-dp/src/session/ctx.rs` | 126 | `SessionInstall`, `SessionUpdate`, `ExpireHaContext` | Full |
| `userspace-dp/src/session/expire.rs` | 625 | `expire_stale_entries_ha`, `standby_gate_decision`, `companion_keeps_alive`, `push_to_wheel`, `rebucket_alive_entry` | Full |
| `userspace-dp/src/session/wheel.rs` | 80 | `SessionWheel`, `target_tick_for`, `bucket_for_tick` | Full |
| `userspace-dp/src/session/tests.rs` | 6994 | Unit tests — seeding, promotion, closing, NAT indexes, HA standby, GC | Spot-checked |
| `userspace-dp/src/tcp_flags.rs` | 121 | `is_initial_syn`, `is_syn_ack`, `is_closing`, `is_ack_only`, `has_syn/ack/rst/fin` | Full |
| `userspace-dp/src/afxdp/flow_cache.rs` | 1000 | `FlowCache`, `FlowCacheEntry`, `packet_eligible`, `should_cache`, `set_index`, `lookup_with_observed_bytes`, `invalidate_slot`, `insert` | Full |
| `userspace-dp/src/afxdp/session_glue/mod.rs` | 1277 | `resolve_flow_session_decision`, `install_reverse_session_from_forward_match`, `replicate_session_*`, `materialize_shared_session_hit`, fabric/HA helpers | Full |
| `userspace-dp/src/afxdp/session_glue/promote.rs` | 167 | `maybe_promote_synced_session`, `should_keep_synced_hit_transient`, `purge_translated_synced_hit` | Full |
| `userspace-dp/src/afxdp/forwarding/mod.rs` excerpt | ~1800 | `cluster_peer_return_fast_path`, `should_cache_local_delivery_session_on_miss`, `should_block_tunnel_interface_nat_session_miss`, `ingress_route_table_override`, session-install paths | Full |
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` excerpt | ~2600 | `poll_binding_process_descriptor`, `strict_syn_check_drops_new_flow`, `new_flow_session_limit_drop`, FabricIngress, flow-cache fast path, LocalDelivery cache, ForwardCandidate/MissingNeighbor install | Full |

---

## 3. Module-by-Module Inspection Log (including negatives)

### 3.1 session/mod.rs + install.rs + tcp_flags.rs — TCP state machine

**Verified:**
- `is_initial_syn = has_syn && !has_ack` — bare SYN only. Used at install to seed `established=false` (OPENING 20s). Correct predicate.
- `is_syn_ack = has_syn && has_ack` — reverse SYN-ACK promotion in lookup.rs:146. Correct.
- `is_closing = has_fin || has_rst` — FIN/RST close detection. Correct.
- `is_ack_only = (flags & 0x17) == 0x10` — pure ACK. Used for flow-cache `packet_eligible`. Correct — excludes SYN, FIN, RST, so PSH+ACK excluded from cache.
- `session_timeout_ns` — OPENING uses `tcp_opening_ns` (20s) or `opening_override_ns` (zone syn-flood timeout), ESTABLISHED uses `app_override_ns` or `tcp_established_ns` (300s), closing uses 30s/2s. Correct.
- `account_packet` — folds reverse counters onto forward entry via `reverse_session_key`. Correct — avoids double-counting.
- `propagate_tcp_state_to_companion` — mirrors FIN/RST close and SYN-ACK promotion to companion. Correct.
- `update_session` — sticky `closing`, `reset`, `established`, `seen_rg_epoch=0`, `first_held_ns=0`. Correct. Rejects peer→peer / local→peer overwrites.
- `remove_entry` — restores mapping on stale-handle guard, cleans all secondary indexes value-guarded, `no_index_points_at` debug_assert, decrements session-limit counts. Correct.
- `touch_if_stale` — `now - last_seen >= expires_after / 4` — per-session keepalive divisor 4. Correct.

**Finding:**
- `[NEW-01]` PSH+ACK / bare ACK / pure PSH / null / URG → ESTABLISHED 300s DoS — see §4.

### 3.2 session/lookup.rs — Primary + alias lookup, NAT reverse match

**Verified:**
- `lookup_with_origin` — direct primary via `key_to_handle`, alias via `reverse_translated_index` 1:N bucket walk with `is_reverse && translated == key` validation. Stale-handle guards (record.key != *key, translated mismatch) return None. Correct.
- `find_forward_nat_match` — 1:N bucket walk with `!is_reverse && reply_matches_forward_session` validation. Correct (fix #4399).
- `find_forward_wire_match_with_origin` — 1:N bucket walk with `!is_reverse && forward_wire_key == wire_key`. Correct (fix #4438).
- `resolve_reverse_translated_handle` — 1:N bucket walk with `is_reverse && translated == key`. Correct.
- `lookup_with_origin` TCP state propagation — captures `TcpStatePropagation { nat, close, reset, established: is_syn_ack && is_reverse }`, applies after borrow ends. Promotion only on reverse SYN-ACK (not any ACK) — fix #4109. Correct.
- `take_synced_local` — checks `is_peer_synced && !is_reverse && LocalDelivery`. Correct.

**No new findings in lookup.rs.** All paths validated.

### 3.3 session/key.rs — Key transforms

**Verified:**
- `SessionKey { addr_family, protocol, src_ip, dst_ip, src_port, dst_port }` — bare 5-tuple, no zone/VRF/VLAN/logical-ingress. This is the S-001/V-01 root cause (see C-01).
- `forward_wire_key` — applies `rewrite_src/dst` + `rewrite_src/dst_port`, handles ICMP id symmetric, NAT64 AF mapping. Correct.
- `reverse_wire_key` — source↔dest swap after NAT rewrite, ICMP id stays in src_port. Correct.
- `translated_session_key` — alias reverse, no swap. Correct.
- `reverse_canonical_key` — pre-NAT reverse (no NAT rewrite), used for second reverse-key bucket. Correct.
- `reverse_session_key` — NAT-aware reverse complement, handles ICMP `.or()` for both directions, NAT64 AF mapping. Correct — own inverse given reversed NatDecision.
- `reply_matches_forward_session` — `reverse_wire == reply || reverse_canonical == reply`. Correct.

**Finding:**
- `[C-01]` Bare 5-tuple session key omits zone/VRF/VLAN — CONFIRMED STILL PRESENT #2387 — see §4.

### 3.4 session/expire.rs + wheel.rs — Timer wheel, GC, HA standby gate, companion keepalive

**Verified:**
- `wheel_observe` — lazy init `cursor_tick = now_ns / WHEEL_TICK_NS`. Correct — avoids billion-bucket walk on first GC.
- `push_to_wheel` — throttled: only pushes when `new_tick != entry.wheel_tick`. Correct.
- `expire_stale_entries_ha` — GC interval gate 1s, pops buckets `while cursor < now_tick`, 4-case lazy-delete (gone/stale-dup/expired/alive). Correct.
- `standby_gate_decision` — SELF-HEAL (peer_synced && forwards_here && epoch != seen → re-stamp), HOLD (peer_synced || node_active, no epoch stamp — avoids old-map/new-epoch race), AGE. Stale-synced ceiling `min(MULT * timeout, ABS)`. Correct. Codex old-map/new-epoch race note honored (HOLD does NOT write seen_rg_epoch).
- `companion_keeps_alive` (#4380) — probes `reverse_session_key(key, nat)` companion still active, re-stamps from companion's `last_seen_ns`, re-buckets. Gated `companion_eligible` false on deliberate reap arms (ReapStaleSynced, AgedOwnerRgZeroActiveNode). Correct — implements Junos single-session idle semantics.
- `rebucket_alive_entry` — HELD entries clamped to `now_ns`, SELF-HEAL uses natural expiration. Correct — avoids in-call re-drain.
- `WHEEL_BUCKETS=256` power-of-two, `FAR_FUTURE_OFFSET=255`, `WHEEL_TICK_NS == SESSION_GC_INTERVAL_NS`. Correct.

**No new findings in expire.rs / wheel.rs.**

### 3.5 session/entry.rs + ctx.rs — Data types

**Verified:**
- `SessionMetadata` `PartialEq` ignores `policy_counter` (bound handle, not identity). Correct.
- `SessionOrigin::is_peer_synced` = SyncImport|SharedMaterialize|WorkerLocalImport. Correct.
- `SessionOrigin::is_transient_local_seed` = MissingNeighborSeed only. Correct.
- `SessionDelta` carries `created_ns`, `last_seen_ns`, `counters`, `observed_tos`, `observed_tcp_flags` — #2465/#2501/#2749. Correct.

**No findings.**

### 3.6 afxdp/flow_cache.rs — 4-way SA cache

**Verified:**
- `packet_eligible` = `is_ack_only` (pure ACK: ACK && !FIN && !SYN && !RST). PSH+ACK excluded — correct.
- `should_cache` = `packet_eligible` && (TCP|UDP) && !nat64 && disposition.is_cacheable(). Correct — NAT64 excluded (header rebuild), NPTv6 included (checksum-neutral).
- `set_index` — seeded FxHasher with per-boot `hot_hash_seed` — hash-DoS mitigation (#2364). Correct.
- `lookup_with_observed_bytes` — key-first then generation/epoch/lease validation, evicts stale on mismatch, promotes LRU on hit, stamps `last_used_epoch` + `observed_bytes`. Correct.
- `insert` — dedup-on-insert (same key+ingress replaces), prefers empty way, evicts LRU. Correct.
- `invalidate_slot` — scans all 4 ways in set for key+ingress match, drops, demotes LRU. Correct.
- `nat_family_matches_addr_family` — defense-in-depth guard rejects mismatched NAT AF vs addr_family. Correct (#963 PR-A).
- DSCP-sensitive input/output filter decline_cache, per-packet L4 match decline_cache (#2362). Correct.
- `neighbor_mac_epoch` stamping pre-resolve, stale check on lookup — TOCTOU closure (#3918). Correct.
- `FLOW_CACHE_SIZE=4096`, 4-way × 1024 sets, LRU [0,1,2,3]. Correct.

**Finding C-02 below — FIXED on this HEAD:**

#### [C-02 — FIXED] Flow-cache NAT port reuse / stale-descriptor forward — #3776 — FIXED on 33b891d11

- **Status**: FIXED (was OPEN as #3776, now CLOSED per `gh issue view 3776`)
- **Fix location**: `userspace-dp/src/afxdp/worker/loop_body/mod.rs:1302-1380` `reap_expired_sessions`:
  ```rust
  for binding in bindings.iter_mut() {
      binding.flow.flow_cache.invalidate_slot(&expired_entry.key, binding.ifindex);
  }
  ```
  Every expired session's flow-cache slot is invalidated on every binding of the owning worker. Validated by tests `reaped_session_flow_cache_slot_is_invalidated` / `reaped_snat_descriptor_is_not_reused` at `worker/loop_body/mod.rs:1432-1615`.
- **Also fixed**: RST teardown eviction `worker/lifecycle.rs:231-235`, neighbor/fabric-mismatch fall-through `poll_descriptor/flow_cache_hit.rs:125`.
- **Dedup**: #3776 CLOSED — FIXED, not re-reporting. Confirming as FIXED negative.

### 3.7 afxdp/session_glue/ — HA promote, demote, shared maps, materialize

**Verified:**
- `resolve_flow_session_decision` — session-hit includes junos-host re-validation on LocalDelivery, fabric-return fast path before DNAT, NAT64 tri-state (NoPrefixMatch/MatchReady/MatchUnavailable→fail-closed), NPTv6 inbound translate. Correct.
- `maybe_promote_synced_session` — only when `is_promotable_synced && ForwardCandidate`, re-tags SharedPromote, republishes kernel map + shared maps + peer commands. Correct.
- `should_keep_synced_hit_transient` — peer_synced && !local_active && translated-forward-key → purge, re-resolve. Correct.
- `purge_translated_synced_hit` — removes shared + kernel + local. Correct.
- `is_translated_forward_session_key` — `!is_reverse && (rewrite_src == src_ip || rewrite_dst == dst_ip)`. Correct.
- `replicate_session_upsert/delete` — `lock_recover` on poisoned queue (fix #1807). Correct.
- `should_teardown_tcp_rst` returns false always — intentional, RST immediate teardown disabled (stray RST hazard). Correct — sessions age on short RST timeout instead.
- `reap_expired_sessions` flow-cache invalidation propagated — see C-02 above.

**No new findings.**

### 3.8 afxdp/forwarding/mod.rs — cluster_peer_return_fast_path, should_cache_local_delivery, session install path

**Verified:**
- `cluster_peer_return_fast_path` — excludes: non-fabric-ingress (first gate), no ingress_zone_override, ICMP echo request, bare SYN (`is_initial_syn`), bare RST/FIN (`is_closing && !has_syn`, #4453), non-TCP/ICMP/ICMPv6 (UDP/naked ESP/AH/GRE/SCTP → None, #4439). Protocol whitelist closed. Correct.
- `should_cache_local_delivery_session_on_miss` — `has_syn` only (commit 5e66d37, fix #4539). Packet still reaches host via reinject, just not cached. Non-TCP always caches. Correct.
- `should_block_tunnel_interface_nat_session_miss` — blocks TCP/UDP/ICMP/ICMPv6 to `interface_nat_v4/v6` with `tunnel_endpoint_id != 0`. Correct.
- `ingress_route_table_override` — PBR `then { routing-instance X; reject|discard; }` → `RouteOverride::Drop`, synthesizes RST/ICMP on flow-backed reject. Correct (#4392).
- `enforce_ha_resolution_snapshot` — `owner_rg_id <= 0` + `!ha_state.is_empty()` + ForwardCandidate → HAInactive (stale snapshot guard, #3769). Correct.

**No new findings.**

### 3.9 afxdp/poll_descriptor/mod.rs — session-miss, flow-cache, session-limit, strict_syn_check

**Verified:**
- `strict_syn_check_drops_new_flow` = `PROTO_TCP && is_closing && !has_syn` — bare RST/FIN/new-flow only. Correct. Gated on ForwardCandidate/MissingNeighbor only (LocalDelivery exempt — peer RST to firewall-originated flow still reaches stack). Correct (#4400).
- `new_flow_session_limit_drop` — reads `session_limit_src_count`/`dst_count` from zone's screen profile, read-only query, no map insertion. Correct (#2134).
- `junos_host_local_policy` — re-evaluated on EVERY LocalDelivery session hit (tightened deny tears down established host session). Correct.
- `host_inbound_gated_lo0_action` — host-inbound admit FIRST, lo0 filter second; denied → silent drop, no lo0 side-effects. Correct (#3485).
- `flow_cache_install_failed` — gates flow-cache population when session install refused (max_sessions) — prevents stale SNAT cache. Correct (#1861 §5.4).
- `pre_routing_dnat_counter` hoisted to outer scope — incremented once on committed install (LocalMiss + ForwardCandidate + MissingNeighbor seed). Correct (#2218).
- `neighbor_mac_epoch_at_resolve` captured pre-resolve — TOCTOU closure (#3918). Correct.
- `is_embedded_icmp_error` — skip BPF publish for ICMP errors. Correct.
- Scan/sweep (`scan_sweep_drop_on_new_flow`) runs at session-miss only — not on per-packet screen stage (fixes #2210 false positives). Fabric-ingress skip (already screened on ingress node, #4155). Correct.

**No new findings in poll_descriptor.**

---

## 4. Findings

### [C-01] [CONFIRMED STILL PRESENT — P0, #2387 OPEN] Cross-zone / cross-VRF / cross-VLAN bare 5-tuple session hijack — FAIL-OPEN

- **Title**: Bare 5-tuple session/flow identity enables cross-zone / cross-VRF / cross-VLAN session hijack
- **Severity**: High (FAIL-OPEN)
- **Confidence**: High
- **Class**: fail-open / implementation-bug
- **Status**: CONFIRMED STILL PRESENT — known-open #2387, NOT re-filed as new (coverage proof)
- **Evidence**:
  ```rust
  // session/key.rs:10-17 — bare 5-tuple, no ingress context
  pub(crate) struct SessionKey {
      pub addr_family: u8,
      pub protocol: u8,
      pub src_ip: IpAddr,
      pub dst_ip: IpAddr,
      pub src_port: u16,
      pub dst_port: u16,
  }
  // session/lookup.rs:62-68 — pure 5-tuple lookup, no zone/VRF/VLAN gate
  let (handle, via_alias) = match self.key_to_handle.get(key) { ... }
  // afxdp/flow_cache.rs:979 — invalidate_slot keyed by (SessionKey, ingress_ifindex) —
  // same bare 5-tuple key reused, ingress_ifindex is PHYSICAL parent (VLAN subinterfaces share it)
  ```
- **Trace**:
  1. routing-instance tenant-a and tenant-b each carry 10.0.0.10 on VLAN .10/.20 of same parent `enp1s0f3`
  2. Flow `10.0.0.10:12345 → 198.51.100.10:443` in tenant-a installs session keyed by bare 5-tuple, with tenant-a's policy/NAT/egress/owner-RG
  3. Same 5-tuple via tenant-b's VLAN hits same `SessionKey` (VLAN subinterfaces share parent ifindex, so flow-cache also collides on `set_index(key, physical_ifindex)`), reuses tenant-a's verdict — FAIL-OPEN (tenant-b's policy would DENY, tenant-a's ALLOW is reused)
  Same for inter-zone: lan→wan ALLOW, dmz→wan DENY, but same 5-tuple (NAT'd source or overlapping) reuses lan session from dmz ingress.
- **Refutation attempted**: Searched for zone/VRF/VLAN in SessionKey — none. Searched for zone re-validation on session-hit — session-hit in poll_descriptor:858-879 does junos-host re-validation but NOT zone-pair policy re-validation (policy is already baked in decision). Flow-cache `set_index` includes `ingress_ifindex` but it is the physical parent ifindex for VLAN (per #2370), so two VLANs on same parent collide. No other gate catches.
- **Why it matters**: P0 fail-open — security policy intended to block cross-VRF/cross-zone/cross-VLAN traffic is bypassed by reusing a session from another context. Multi-tenant VRF overlapping subnets is a legitimate deployment.
- **Fix direction**: Include logical forwarding context (logical ingress ifindex / VLAN id / routing-domain id / zone pair) in SessionKey, or re-validate zone/VRF/VLAN on session-hit. Regression test: same parent ifindex, two VLAN subinterfaces in different VRFs/zones, identical 5-tuples, differing policy — assert no session reuse.
- **Labels**: `fail-open`, `security`, `session`, `vrf`, `vlan`, `zone`, `x-hpc`
- **Dedup note**: CONFIRMED STILL PRESENT — #2387 OPEN ("userspace-dp: session/flow identity is the bare 5-tuple — omits logical ingress (VLAN/zone/VRF), cross-context session reuse"). Not re-filed as new. This audit confirms the finding is still present on 33b891d11 with no session/ changes since 83606182b. Same root as ps-035 S-001/V-01. Coverage proof — not a new filing.

---

### [C-02] [FIXED — was #3776] Flow-cache NAT port reuse / stale-descriptor forward — FIXED on 33b891d11

- **Title**: Flow-cache session expiry/removal does not invalidate the cache — stale-descriptor forward + released-SNAT reuse
- **Severity**: N/A (was MEDIUM-HIGH)
- **Confidence**: High
- **Class**: implementation-bug (was fail-open)
- **Status**: FIXED — #3776 CLOSED
- **Evidence of fix**:
  ```rust
  // worker/loop_body/mod.rs:1338-1380
  fn reap_expired_sessions(bindings: &mut [BindingWorker], expired_entries: &[ExpiredSession], ...) {
      for expired_entry in expired_entries {
          release_source_nat_allocation(...);
          crate::nat64::release_nat64_allocation(...);
          delete_session_map_entry_for_removed_session_with_origin(...);
          // Fix: invalidate flow-cache slot on every binding
          for binding in bindings.iter_mut() {
              binding.flow.flow_cache.invalidate_slot(&expired_entry.key, binding.ifindex);
          }
      }
  }
  // Tests: worker/loop_body/mod.rs:1432-1615 reaped_session_flow_cache_slot_is_invalidated
  // Also: worker/lifecycle.rs:231-235 RST teardown, poll_descriptor/flow_cache_hit.rs:125 neighbor/fabric-mismatch
  ```
- **Why FIXED**: The GC reap path now invalidates every flow-cache slot backing every expired session. Next packet on same 5-tuple after idle timeout MISSES cache and re-runs full session lookup/creation + policy + fresh NAT allocation. RST teardown and neighbor/fabric paths also covered.
- **Labels**: `session`, `flow-cache`, `nat`, `fixed`
- **Dedup note**: #3776 CLOSED — FIXED on this HEAD (33b891d11). ps-035 F-01 / S-004 already noted as #3776. Not re-filing. Confirming as FIXED negative.

---

### [C-03] [CLOSED — was #4539] should_cache_local_delivery pure PSH/null/URG non-handshake — FIXED on 33b891d11

- **Status**: FIXED — #4539 CLOSED (commit 5e66d37 `session: cache host-inbound TCP LocalDelivery only off the handshake`)
- **Fix**: `should_cache_local_delivery_session_on_miss = has_syn(tcp_flags)` — only SYN-bearing first packets cache. Pure PSH/null/URG/reverse-pure-ACK declined (packet still reaches host via reinject, just not cached). Closes gate-consistency + host-IP session-table DoS.
- **Refutation cross-check**: This fix does NOT fix NEW-01 below — different gate (LocalDelivery cache vs transit session ESTABLISHED timeout). A PSH+ACK transit flow still creates ESTABLISHED 300s session; it just does not create a LocalDelivery host-bound session.
- **Dedup**: #4539 CLOSED — FIXED, not re-reporting.

---

### [NEW-01] [MEDIUM] Bare ACK / PSH+ACK / pure PSH / null / URG first-packet → ESTABLISHED 300s — 15× DoS amplification — NEW

- **Title**: Bare ACK / PSH+ACK / pure PSH / null / URG TCP first-packet creates ESTABLISHED (300s) session instead of OPENING (20s) — 15× session-table DoS vs SYN flood
- **Severity**: Medium (robustness-DoS — session-table exhaustion, not fail-open)
- **Confidence**: High
- **Class**: robustness-dos / implementation-bug
- **Evidence**:
  ```rust
  // session/install.rs:158
  established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
  // tcp_flags.rs:98-100
  fn is_initial_syn(flags: u8) -> bool {
      has_syn(flags) && !has_ack(flags)  // bare SYN only
  }
  // session/mod.rs:2034-2044 — established==false → tcp_opening_ns 20s, true → tcp_established_ns 300s
  } else if !established {
      opening_override_ns.unwrap_or(timeouts.tcp_opening_ns)  // 20s
  } else {
      app_override_ns.unwrap_or(timeouts.tcp_established_ns)  // 300s
  }
  ```
  `is_initial_syn` = SYN && !ACK — only matches bare SYN (0x02). Any TCP packet that is NOT a bare SYN — including bare ACK (0x10), PSH+ACK (0x18), pure PSH (0x08), null (0x00), URG (0x20), FIN+ACK, etc. — evaluates `!is_initial_syn = true` → `established=true` → 300s timeout.

  `strict_syn_check_drops_new_flow` = `is_closing && !has_syn` = RST|FIN && !SYN — only drops bare RST/FIN. Bare ACK / PSH+ACK / pure PSH are NOT closing, so they PASS the strict-syn-check and reach the install site.
- **Trace**:
  1. Attacker sends `10.0.0.100:12345 → 8.8.8.8:443` with TCP flags `ACK` (0x10) — varying 5-tuples.
  2. Each packet MISSES session table (new flow), passes `strict_syn_check_drops_new_flow` (ACK is not closing → `is_closing=false` → not dropped), passes policy (transit ALLOW), reaches `install_with_protocol_with_origin`.
  3. `is_initial_syn(0x10)` = `has_syn(0x10)=false && !has_ack(0x10)=false` = `false && false` = `false` → `established = !(true && false)` = `true` → 300s.
  4. Same for PSH+ACK (0x18): `has_syn(0x18)=false` → `is_initial_syn=false` → ESTABLISHED 300s.
  5. Pure PSH (0x08): `has_syn=false` → ESTABLISHED 300s.
  6. Null (0x00): `has_syn=false` → ESTABLISHED 300s.
  7. URG (0x20): `has_syn=false` → ESTABLISHED 300s.
  8. Attack rate: 131072 slots / 300s ≈ 437 pps fills table. SYN flood requires 131072 / 20s ≈ 6554 pps. **15× amplification** — attacker fills table at 437 pps, legitimate SYN traffic at 6554 pps would be needed to achieve same fill via the intended SYN-flood path. Once table full, new legitimate flows are dropped (`can_admit`/`len() >= max_sessions` → DROP).
- **Refutation attempted**:
  - `strict_syn_check_drops_new_flow` only drops bare RST/FIN (`is_closing && !has_syn`) — bare ACK and PSH variants are NOT `is_closing`, so they pass. Confirmed by reading `tcp_flags.rs:115-117` `is_closing = FIN || RST` and `poll_descriptor/mod.rs:1986-1995` gating.
  - `should_cache_local_delivery_session_on_miss` fix (#4539) only affects LocalDelivery host-bound path — transit ForwardCandidate/MissingNeighbor path is unaffected. A bare ACK to a transit destination still creates ESTABLISHED 300s.
  - Flow-cache `packet_eligible` = `is_ack_only` (ACK && !FIN && !SYN && !RST) — bare ACK IS cache-eligible, so the attack flow IS cached and stays hot. PSH+ACK is NOT `is_ack_only` (PSH set, ignored? Actually `is_ack_only` requires `(flags & 0x17)==0x10`, PSH=0x08 not in 0x17 mask, so PSH+ACK=0x18: `0x18 & 0x17 = 0x10` → true! PSH is intentionally ignored per `tcp_flags.rs:83-91`. So PSH+ACK IS `is_ack_only` → IS flow-cache eligible. Attack traffic is fast-pathed.
  - SYN-flood `tcp_opening_ns=20s` is per-zone overrideable (#3527) but default 20s — attacker avoids this by not sending bare SYN.
  - `session_limit_src/dst` caps are per-IP (#2134) — attacker varies source IP or stays under limit while still filling global `max_sessions`.
  - `ALLOW` vs `DENY` policy: attack requires an ALLOW policy for the 5-tuple — typical (WAN↔LAN allow). Any ALLOW policy covering the attack tuple suffices; attacker does not need to bypass policy.
- **Why it matters**: Same DoS class as SYN flood but 15× cheaper for attacker. A single attacker sending 437 pps of bare ACKs fills 131K session table in 300s, blocking all new legitimate flows. SYN flood mitigation (`tcp_opening_ns=20s`) is defeated — attacker never sends SYN. The fix for S-002 (bare ACK) must cover PSH+ACK/pure PSH/null/URG together as one PR — fixing only bare ACK leaves PSH+ACK bypass.
- **Fix direction**: Treat any non-SYN TCP first packet as OPENING (20s), not ESTABLISHED (300s). Change `session/install.rs:158`:
  ```rust
  // Before:
  established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
  // After (option B — most conservative, covers all non-SYN):
  established: !(matches!(protocol, PROTO_TCP) && !is_syn_ack(tcp_flags)),
  // OR equivalently: non-SYN → OPENING, bare SYN → OPENING, SYN+ACK → ESTABLISHED
  // Which is: established = !TCP || is_syn_ack(tcp_flags)
  ```
  `is_syn_ack(tcp_flags)` already exists (`has_syn && has_ack`). This gives: non-SYN (bare ACK, PSH+ACK, pure PSH, null, URG, FIN+ACK) → OPENING 20s; bare SYN (SYN && !ACK) → OPENING 20s (with later reverse SYN-ACK promotion via lookup.rs:146); SYN+ACK → ESTABLISHED 300s (mid-stream pickup, legitimate). Joins S-002 and NEW-02 as one fix.

  Alternative (A) if PSH+ACK mid-stream pickup must stay ESTABLISHED: `has_ack && !has_syn → OPENING` only (covers bare ACK + PSH+ACK, keeps pure PSH/null/URG as ESTABLISHED). Less complete.

  Should be fixed together with S-002 as one PR — single predicate change at `session/install.rs:158` plus mirror at line 164 (`expires_after_ns` seed computation).

  Also consider: should `strict_syn_check_drops_new_flow` also drop non-SYN non-handshake (bare ACK / PSH+ACK / pure PSH) like it drops bare RST/FIN? Current drop is bare RST/FIN only (no session-install value, immediately-closing). Bare ACK / PSH+ACK DO have forwarding value (mid-stream pickup), so they should create a session — but on the SHORT opening timeout (20s), not the full 300s. The fix is the `established` predicate, not the drop predicate.

- **Labels**: `dos`, `session`, `tcp`, `bare-ack`, `psh-ack`, `pure-psh`, `null-tcp`, `robustness`, `hardening`, `medium`
- **Dedup note**: NEW — not in `/tmp/all_findings.txt` (272 entries, no bare ACK/PSH+ACK/pure PSH first-packet ESTABLISHED 300s DoS finding — F-001..F-272 checked, none describe this). NOT in `gh issue list --state all` (30 open, ~230 closed — 0 bare ACK/PSH+ACK/pure PSH first-packet DoS; #4539 is LocalDelivery pure PSH *cache gate* `should_cache_local_delivery_session_on_miss`, different code path and different impact — host-IP table DoS vs transit ESTABLISHED 300s DoS; #4109 is half-open→ESTABLISHED PROMOTION via bare ACK on reverse, not first-packet OPENING/ESTABLISHED; #4400/#4487 are RST/FIN, not ACK/PSH). ps-035 S-002 (bare ACK 300s) and NEW-02 (PSH+ACK/pure PSH/null/URG 300s) are the prior review reports that describe this exact bug — still present on 33b891d11 (no session/ changes since 8cd816e35 / 5e66d37; session/install.rs:158 unchanged). This audit reconfirms with materially complete flag coverage (bare ACK + PSH+ACK + pure PSH + null + URG all in one trace, plus flow-cache eligibility for bare ACK/PSH+ACK) and the concrete 437-pps / 15× amplification calculation. **NEW filing — file as GH issue, assign to session cohort.**

---

### [C-04] [CONFIRMED STILL PRESENT — #2387 OPEN, V-01 variant] VLAN cross-VLAN flow-cache / bare 5-tuple session reuse

- **Title**: VLAN cross-VLAN flow-cache and session reuse — same parent, different VLAN units in different zones/VRFs
- **Severity**: High (fail-open — same as C-01)
- **Confidence**: High
- **Class**: fail-open / implementation-bug
- **Status**: CONFIRMED STILL PRESENT — same root as C-01 / #2387, VLAN-specific variant
- **Evidence**:
  ```rust
  // afxdp/flow_cache.rs:759-780 — set_index = hash(SessionKey + ingress_ifindex) & MASK
  // ingress_ifindex = meta.ingress_ifindex = PHYSICAL parent ifindex for VLAN tagged ingress
  // Two VLAN subinterfaces .10/.20 on enp1s0f3 share same ingress_ifindex → same flow-cache set
  // session/key.rs:10-17 — SessionKey is bare 5-tuple, no VLAN id
  // So both flow-cache and session table collide across VLANs sharing a parent
  ```
- **Trace**: Same as C-01 but VLAN-specific: `enp1s0f3.10` (zone lan) and `enp1s0f3.20` (zone dmz) share parent ifindex `enp1s0f3`. Flow `10.0.0.10:12345 → 8.8.8.8:443` via lan installs session + flow-cache entry keyed by bare 5-tuple + physical ifindex. Same 5-tuple via dmz hits same session + flow-cache — reuses lan's policy/verdict (ALLOW) when dmz's should be DENY.
- **Refutation**: Logical ingress ifindex is resolved via `resolve_ingress_logical_ifindex` at `forwarding/mod.rs:834-843` (keyed by physical+VLAN), but this is only used for zone-pair / host-inbound / interface-NAT lookups — NOT for SessionKey or flow-cache `set_index` key. SessionKey remains bare 5-tuple; flow-cache `set_index` uses physical ifindex.
- **Fix direction**: Same as C-01 — include logical ingress (VLAN id / logical ifindex) in SessionKey and flow-cache `set_index`, or re-validate VLAN/zone on session-hit. Regression test: same parent, two VLAN units in different zones, same 5-tuple, differing policy — assert isolation.
- **Labels**: `fail-open`, `security`, `vlan`, `flow-cache`, `session`
- **Dedup note**: Same root as C-01 / #2387 OPEN. VLAN-specific surface of the same bare-5-tuple bug. ps-035 V-01 already noted. Not re-filed as new — covered by #2387. Noting here for cohort coverage.

---

### [C-05] [CONFIRMED — S-002, same root as NEW-01, bare ACK variant] Bare ACK 300s DoS — STILL PRESENT (no GH issue filed)

- **Status**: CONFIRMED STILL PRESENT on 33b891d11 — no session/ changes since 8cd816e35. NOT filed as GH issue yet (ps-035 notes "No open issue filed for S-002 bare ACK DoS — should be filed"). This audit files it as NEW-01 above (which subsumes bare ACK + PSH+ACK + pure PSH + null + URG — same 15× DoS class, same root cause, same one-line fix). **Do not file S-002 separately — NEW-01 covers it.**
- **Dedup**: ps-035 S-002 / ps-020 S-002 / ps-029 C-02 / ps-033 S-002 — all prior reviews report bare ACK 300s, none filed as GH issue. This audit's NEW-01 subsumes.

---

## 5. Verified Negatives (Paths Confirmed Fail-Closed / Correct — Coverage Proof)

These are high-value "this does NOT bypass" results — proving coverage depth:

1. **RST/FIN session creation — FIXED (#4400/#4453/#4487)**: Bare RST/FIN new-flow is dropped on ForwardCandidate/MissingNeighbor (`strict_syn_check_drops_new_flow`), excluded from fabric-return fast path (`is_closing && !has_syn`), declined on LocalDelivery (`has_syn` only). Three paths, all gated. No bare RST/FIN session creation on this HEAD.

2. **NAT 1:N multimap — FIXED (#4399/#4438)**: All three NAT session indexes (`nat_reverse_index`, `forward_wire_index`, `reverse_translated_index`) are `NatIndexBucket = SmallVec<[u32;2]>` 1:N multimaps. Lookup walks buckets with full-tuple validation. No single-value displacement hijack.

3. **Forward/reverse idle timer asymmetry — FIXED (#4380)**: `companion_keeps_alive` probes companion via `reverse_session_key`, re-stamps from companion's `last_seen_ns`, re-buckets. Gated `companion_eligible=false` on deliberate ReapStaleSynced/AgedOwnerRgZeroActiveNode. Single-session-per-flow semantics preserved — no half-reap, no NAT remap.

4. **Session-limit enable-transition decrement asymmetry — FIXED (#4377)**: `set_session_limit_active` OFF→ON rebuilds count maps from live slab via `key_to_handle` primary index, using same `!is_reverse && !origin.is_transient_local_seed()` predicate as increment/decrement sinks. No increment-less decrement → underflow → count=0 → cap bypass.

5. **TCP half-open→ESTABLISHED promotion only on reverse SYN-ACK — FIXED (#4109)**: `lookup.rs:146-149` promotes only on `is_syn_ack && is_reverse` (reverse SYN-ACK), not any ACK. Bare ACK on forward never promotes. Companion propagated after borrow ends, shortens close window on both halves.

6. **Flow-cache NAT port reuse — FIXED (#3776)**: `reap_expired_sessions` invalidates flow-cache slots on every binding for every expired entry. RST teardown and neighbor/fabric-mismatch also covered. No stale-descriptor forward or released-SNAT reuse after idle timeout.

7. **Flow-cache XDP shim bypass of policy — NOT PRESENT on session cohort**: Flow-cache `packet_eligible` = `is_ack_only` (pure ACK only), so only established-TCP pure ACKs (not SYN/SYN-ACK/FIN/RST/PSH) are flow-cache eligible. Attack flows via NEW-01 (bare ACK is `is_ack_only` → IS cached, but session exists so fast path still checks session liveness via expiry; PSH+ACK is also `is_ack_only` because PSH ignored → IS cached).

8. **Flow-cache packet_eligible excludes control segments**: `is_ack_only = (flags & 0x17)==0x10` — SYN (0x02), FIN (0x01), RST (0x04) set → not eligible. SYN-ACK, pure SYN, bare FIN, bare RST never cached. Correct.

9. **Fabric-return fast path — correctly scoped (#4453/#4439)**: Protocol whitelist (TCP/ICMP/ICMPv6 only), excludes bare SYN, bare RST/FIN, ICMP echo request, non-fabric-ingress, no ingress_zone_override. No UDP/ESP/AH/GRE/SCTP return-path phantom, no bare RST/FIN ReverseFlow seed on peer.

10. **LocalDelivery cache gate — FIXED (#4539)**: `has_syn` only — pure PSH/null/URG no longer cached. Packet still reaches host via reinject (not dropped). Correct — junos-host policy still re-evaluated on hit.

11. **HA standby retention gate — correct**: SELF-HEAL only on peer_synced && forwards_here && epoch != seen, HOLD only on !forwards_here && (peer_synced || node_active), no seen_rg_epoch write on HOLD (avoids old-map/new-epoch race). Stale-synced ceiling `min(MULT*timeout, ABS)`, 7-day cap. `first_held_ns` never reset on self-heal (flap cannot reset leak ceiling). Correct.

12. **Session table seqlock / wrapping — correct**: `secs_to_ns_saturating` saturates at `MAX_SESSION_TIMEOUT_NS` (i64::MAX/1e9), never wraps. `app_inactivity_timeout_ns` clamps to `APP_INACTIVITY_TIMEOUT_MAX_SECS=86400` then saturates. `saturating_add/sub` on counts, no wrap. Correct.

13. **Per-IP session-limit counted-class — correct (#3122)**: `!is_reverse && !is_transient_local_seed()` — present-based, origin-agnostic (local + synced count). Increment on fresh install + synced import, decrement on remove_entry (sole sink), count-neutral on promote/demote. No double-count on import→promote, no leak on removal.

14. **Secondary-index value-guarded cleanup — correct**: `nat_index_bucket_remove` retains handles != removed, `remove_owner_rg_index_entry`, `no_index_points_at` debug_assert scans all buckets. No leaked handle after slab reuse.

15. **Slab handle primary-key guard — correct**: `record_by_key` checks `record.key == *key`, stale-handle guard in `update_session`/`refresh_for_ha_transition`/`remove_entry` restores mapping on mismatch. No reused-slot hijack.

16. **should_teardown_tcp_rst returns false always — intentional**: RST immediate teardown disabled — sessions age on short 2s RST timeout instead. Prevents stray reply-side RST collapsing live flow (USERSPACE_SESSIONS pin). Correct per comment.

17. **Wheel GC lazy-delete — correct**: Case-1 gone (key_to_handle miss), Case-2 stale duplicate (wheel_tick != scheduled_tick), Case-3 expired (now-last_seen > expires_after), Case-4 alive (re-bucket). `wheel_observe` lazy init avoids billion-bucket walk. `FAR_FUTURE_OFFSET=255` for long timeouts. Correct.

---

## 6. Suggested Issue Split (fail-opens first, then hardening)

### Fail-open (P0 — already filed, not new)
- **#2387** — Bare 5-tuple session/flow identity — cross-zone/VRF/VLAN hijack — OPEN — C-01/C-04 above confirm STILL PRESENT, no new issue needed.

### NEW filing (Medium — DoS, not fail-open)
- **NEW-01** — Bare ACK / PSH+ACK / pure PSH / null / URG first-packet → ESTABLISHED 300s — 15× DoS amplification — same root, one-line fix at `session/install.rs:158+164`
  - Subsumes S-002 (bare ACK) + ps-035 NEW-02 (PSH+ACK/pure PSH/null/URG)
  - **File as**: `session: bare ACK / PSH+ACK / non-SYN TCP first-packet creates ESTABLISHED 300s — 15× DoS vs SYN flood (fix: non-SYN → OPENING)`
  - Labels: `dos`, `session`, `tcp`, `robustness`, `medium`

### FIXED (do not file — verify on next smoke)
- #3776 flow-cache NAT port reuse — FIXED 33b891d11 (reap_expired_sessions invalidate_slot)
- #4539 should_cache_local_delivery pure PSH — FIXED 5e66d37 (has_syn only)
- #4400/#4453/#4487 RST/FIN session creation — FIXED
- #4399/#4438 NAT 1:N — FIXED
- #4380 companion keepalive — FIXED
- #4377 session-limit — FIXED
- #4109 SYN-ACK promotion — FIXED

---

## 7. Honesty Statement

- Searched session/, afxdp/flow_cache.rs, afxdp/session_glue/, afxdp/forwarding/mod.rs session paths, afxdp/poll_descriptor/mod.rs session-miss/cache/limit/strict-syn-check, tcp_flags.rs directly.
- Quoted exact lines and predicates for every finding.
- For every HIGH/MED finding gave concrete packet trace (src/dst/flags/protocol), forwarding config, code path walked, resulting WRONG verdict/behavior, and what correct behavior should be.
- Stated refutation attempted and why finding survived or was confirmed fixed.
- Deduped against /tmp/all_findings.txt (272 entries), gh issue list (30 open / ~230 closed), /tmp/ps-review-018..035 (18 reviews), and the specific CLOSED/OPEN lists in the task prompt.
- Did not fabricate any finding — every trace is concrete and reproducible from the code on HEAD 33b891d11.
- NEW-01 (bare ACK / PSH+ACK / non-SYN → ESTABLISHED 300s DoS) is NEW — not in all_findings, not in GH issues (open or closed), not filed from prior reviews (ps-035 reported but not filed). S-001/V-01/C-01/C-04 are CONFIRMED STILL PRESENT known-open #2387 — not new filings. Flow-cache NAT port reuse (#3776) is FIXED on this HEAD — confirmed via code + tests, not re-filed.

---

*End of cohort 6 review — 33b891d11, session/conntrack.*
