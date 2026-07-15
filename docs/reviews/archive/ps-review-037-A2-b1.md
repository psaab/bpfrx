# A2 Review — NAT / NAT64 / NPTv6 — d4506d4450e2
**Reviewer:** A2 (Rust dataplane — NAT/NAT64/NPTv6)  
**Base:** d4506d4450e2  
**Date:** 2026-07-07

## Scope
- `userspace-dp/src/nat/{mod.rs,allocator.rs,source.rs,destination.rs,static_nat.rs}`
- `userspace-dp/src/nat64.rs` (2332 LOC)
- `userspace-dp/src/nptv6.rs` (431 LOC)
- `pkg/config/compiler_nat.go`, `pkg/config/compiler_validate_warn.go:760-787`, `pkg/dataplane/userspace/nat*.go`

---

## F-01 — CONFIRMED OPEN #4559 — Deterministic CGNAT advisory only, no enforcement

**Severity:** MED (CGNAT lawful-intercept/audit invariant violated)  
**Confidence:** HIGH — direct code + warning text  
**Evidence:**
- `pkg/config/compiler_validate_warn.go:760-787` — explicit WARNING:
  ```go
  // #4559 (ps-034 M-01): deterministic CGNAT `port deterministic block-size...
  // ...was NEVER ported to the userspace dataplane...
  // ...SILENTLY falls back to round-robin / sticky SNAT
  warnings = append(warnings, fmt.Sprintf(
      "security nat source pool %s: `port deterministic block-size` is "+
      "accepted but NOT enforced by the userspace dataplane "+
      ...
  ```
- `userspace-dp/src/nat/source.rs:277-284` — `SourceNatRule` has no deterministic fields, `PortAllocator` has no block logic
- `userspace-dp/src/nat/allocator.rs:206-225` — `PortAllocator::new` only takes `num_addresses, port_low, port_high`, no block_size/host
- `pkg/dataplane/compiler_nat.go` still compiles deterministic (dead after #1373, retained for eBPF) but userspace path ignores

**Trace:** Operator configures `port deterministic block-size 2016 host address 100.64.0.0/25` → Go parses into `pool.Deterministic` → `ValidateConfig` emits WARNING (visible in `commit` output) → snapshot builder `nat_source.go` does not copy `Deterministic` into `SourceNATRuleSnapshot` → Rust `parse_source_nat_rules` builds round-robin `PortAllocator` → subscriber→fixed-block mapping not enforced.

**Refutation attempt:** Checked if any other path enforces deterministic. `grep -r deterministic userspace-dp/` only shows schema/test. No `block_size`, `host address` in Rust. Confirmed advisory is the sole mitigation.

**HPC:** Not performance; compliance/legal. CGNAT deployments requiring deterministic logging will silently lack per-subscriber block identity, breaking lawful-intercept without per-flow logs.

**Fix:** Implement block-allocator in `userspace-dp/src/nat/allocator.rs` (or new `deterministic.rs`) keyed by subscriber prefix, or hard-reject deterministic pools at commit (fail-closed) until implemented. Current WARNING satisfies "advisory visible" requirement of #4559 but enforcement missing — confirm OPEN #4559 remains.

**Labels:** `deterministic-nat`, `cgnat`, `compliance`, `#4559`  
**Dedup:** Confirms OPEN #4559 (MED→LOW-MED per dedup, but enforcement still missing). Do NOT close.

---

## F-02 — NEW — NAT64 non-first IPv6 fragment leaks port + session (port-exhaustion via fragment)

**Severity:** HIGH (pool exhaustion, DoS)  
**Confidence:** HIGH  
**Evidence:**
- `userspace-dp/src/nat64.rs:1155-1158` — translator correctly drops non-first frag:
  ```rust
  if ipv6_is_non_first_fragment(packet) {
      return None;
  }
  ```
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2623-2647` — **allocates before translating, no frag guard:**
  ```rust
  let nat64_info = if let Some((prefix_idx, dst_v4, orig_dst_v6)) = nat64_match {
      match worker_ctx.forwarding.nat64.allocate_source(...) // ← no non_first check
  ```
- `userspace-dp/src/nat/source.rs:1044-1049` — SNAT correctly gates (contrast):
  ```rust
  if non_first_fragment {
      return SourceNatLookup::Unavailable(... NonFirstFragment)
  }
  ```
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2610-2622` — only SNAT computes `snat_non_first_fragment`, NAT64 path does not.

**Trace:**
1. Attacker sends IPv6 packet with Fragment Header, offset !=0, dst = `64:ff9b::8.8.8.8`, varied src port/addr.
2. `classify_ipv6_dest` → `MatchReady` (prefix matches, pool non-empty).
3. Policy permits (default allow or permissive rule).
4. `allocate_source` → `PortAllocator::allocate_translation` claims `(snat_v4, port)` (stateful, unique).
5. Session install succeeds (`forward_metadata.nat64_reverse = Some(...)`), port reserved.
6. Later TX: `build_nat64_v6_to_v4_frame` → `write_v6_to_v4_into` → `ipv6_is_non_first_fragment` → `None` → packet dropped, but session + port held until idle timeout (default 300s).
7. Repeat with 64512 distinct 5-tuples (1024-65535) → single-pool NAT64 exhaustion. Legitimate v6 clients get `nat64_pool_exhausted` drops.

**Refutation attempt:** Could session install fail because `is_non_first_fragment` checked earlier? No — fragment check only in translator, not in `poll_descriptor` admit path. Could `flow.forward_key` be flowless for fragments? No — frag header still has next proto, parser builds flow. Even if flowless, `allocate_source` still called with `src_port` from flow (payload garbage reinterpreted as ports) — still allocates.

**HPC:** Stateful port leak per malicious fragment; 64512 ports × 1 pool IP = trivial exhaustion from single host. No rate limit on NAT64 allocation distinct from SNAT flood gate (#4567).

**Why it matters:** Breaks N-01 negative (task says "NAT64 non-first fragment: no port leak (N-01 negative)" — we prove leak exists for NAT64, though SNAT is safe). Allows unauthenticated WAN→NAT64-pool DoS.

**Fix:** Mirror SNAT guard: compute `nat64_non_first_fragment` from `meta.l3_offset` + `ipv6_is_non_first_fragment` (or reuse `is_non_first_fragment`) before `allocate_source`; on true, drop + `nat64_non_first_fragment` counter, no allocation, no session. Alternatively, make `allocate_source` check and return `NonFirstFragment` like SNAT.

**Labels:** `nat64`, `fragment`, `port-exhaustion`, `DoS`, `fail-closed`  
**Dedup:** Distinct from OPEN #2562 (frag cache for translation) and OPEN #4569 (non-first frag DENY+permit-any). #2562 is about translating legit fragments; this is about allocation leak on dropped fragments.

---

## F-03 — CONFIRMED OPEN #4512/#4565 — NAT64 HA reverse-translation missing (reply blackhole after failover)

**Severity:** MED (HA failover breaks existing NAT64 sessions)  
**Confidence:** HIGH  
**Evidence:**
- `userspace-dp/src/nat64.rs:153-159`:
  ```rust
  //! Scope: this closes the port-COLLISION harm. Reverse-TRANSLATION ...
  //! still needs `Nat64ReverseInfo` — `orig_src_v6` / `orig_dst_v6`, which are NOT
  //! reconstructible from `NatDecision` — to ride the sync payload; that is a
  //! separate wire-field follow-up (`ha.rs` sets `nat64_reverse: None`).
  ```
- `userspace-dp/src/afxdp/ha.rs:792` — `nat64_reverse: None` on synced entry
- `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:94-108` — reserves port (good) but does not restore `Nat64ReverseInfo`
- `userspace-dp/src/afxdp/frame/mod.rs:274-277` — reverse requires `nat64_reverse`:
  ```rust
  let info = nat64_reverse?; // None → drop
  ```

**Trace:** Active NAT64 forward flow (v6 client → v4 server) installs `Nat64ReverseInfo{orig_src_v6, orig_dst_v6}`. HA sync message carries `NatDecision` (rewrite_src=v4 pool, rewrite_dst=v4 server, rewrite_src_port) but `nat64_reverse=None`. Standby reserves port (#4512 fix) so no collision, but on failover, reverse v4→v6 reply arrives: `build_nat64_forwarded_frame` needs `info.orig_src_v6`/`orig_dst_v6` to rebuild v6 addrs → `None` → `None` → packet dropped (blackhole). Existing sessions break; new sessions work post-failover.

**Refutation:** Could reverse be reconstructed from flow key? No — flow key src is v6 client (good) but dst is synthetic v6 (`64:ff9b::server`), not `orig_dst_v6` (which is same as synthetic? Actually `orig_dst_v6` = synthetic dst, `orig_src_v6` = client. Reverse needs both, but `NatDecision` only has v4 addrs. `orig_src_v6` not derivable from `rewrite_src` (v4 pool). So must be synced.

**Fix:** Add `nat64_reverse: Option<Nat64ReverseInfo>` to HA wire format (like `SessionMetadata`), sync on upsert, restore in `handle_upsert_synced`. Tracked as OPEN #4565 (and #4512 scope note).

**Dedup:** Confirms OPEN #4512 (port-reservation done, reverse-missing remains) / #4565. Do not re-file.

---

## F-04 — NEGATIVE — NAT64 pool exhaustion fail-closed (N-02) holds

**Confidence:** HIGH  
- `userspace-dp/src/nat64.rs:577-589` — `allocate_source` returns `Err(AllocatorExhausted)` when prefix idx invalid or `PortAllocator` empty/exhausted.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2659-2676` — `Err(reason)` → `record_nat64_source_failure(reason)` → `continue` (drop, no session, no translation). No fallback to IPv6 routing.
- `userspace-dp/src/nat64.rs:523-539` — `classify_ipv6_dest` → `MatchUnavailable` on empty pool → drop + `nat64_no_source_pool`.
- Counter split #4520 ensures `AllocatorExhausted` → `nat64_pool_exhausted`, config empty → `nat64_no_source_pool`.

No fail-open. Correct.

---

## F-05 — NEGATIVE — SNAT non-first fragment no port leak (N-01 SNAT) holds, NAT64 does not

**Confidence:** HIGH  
- `userspace-dp/src/nat/source.rs:1044-1049` — SNAT pool-mode returns `Unavailable(NonFirstFragment)` before `allocate_translation`.
- `userspace-dp/src/nat/tests_pool.rs:3094-3159` — test `pool_snat_non_first_fragment_refused_no_allocation` proves no allocation on non-first, allocation on first.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2610-2622` — `snat_non_first_fragment` computed via `is_non_first_fragment` and passed to `source_nat_decision_for_flow`.

SNAT safe. NAT64 leaks (F-02).

---

## F-06 — NEGATIVE — PortAllocator integer safety, overflow, truncation

**Confidence:** MED  
- `allocator.rs:302-309` — `range = port_high - port_low +1` as u32, `val % range` < range, `port_low + (val%range) as u16 <= port_high <=65535`, no overflow (checked: port_low=1, port_high=65535, range=65535, val%range max 65534, sum max 65535).
- `allocator.rs:502-509` — `next_offset` (u32) < range (u32), `port_low + next_offset as u16` safe.
- `source.rs:425-474` — `expand_pool_address` v4: `1u64 << host_bits` where host_bits=32-len, len 0..32, shift 0..32, 1<<32=4294967296 fits u64, >cap ⇒ reject. v6: guard `host_bits >=64` before shift, avoids UB.
- `sticky_pool_index` uses `FxHasher` with fixed seed, `% pool_len`, safe.

No truncation/overflow findings.

---

## F-07 — NEGATIVE — NPTv6 host-bits (#4519) and self-overlap (#4339) fixed

**Confidence:** HIGH  
- `nptv6.rs:163-201` — `parse_prefix` returns `None` if `words[prefix_words..].iter().any(|&w| w!=0)` — fails closed on host bits, no mask-and-accept. `try_from_snapshots` then rejects whole snapshot (fail-closed), preserving previous state. Matches Go `validateNPTv6Strict` host-bits check.
- `nptv6.rs:269-289`, `414-426` — `find_overlap` + `sameRule` skip:
  ```rust
  let sameRule = |prev: seenPrefix| prev.ruleSetName == rs.Name && prev.ruleName == rule.Name
  // ...
  if sameRule(prev) { continue }
  ```
  Single NPTv6 rule with multiple `from` scopes (zone/interface) expands to multiple `StaticNATRuleSet` entries sharing same `(ruleSetName, ruleName)` — previously flagged as self-overlap, now correctly skipped. Overlapping distinct rules still rejected.

Confirmed fixed.

---

## F-08 — LOW — SNAT synthetic `protocol==0` path `try_next_port` bypasses owner tracking (minor accounting / potential shadow)

**Severity:** LOW  
**Confidence:** MED  
**Evidence:**
- `nat/source.rs:896-945` — `match_source_nat` (synthetic wrapper) calls `match_source_nat_result` with `protocol=0, src_port=0, dst_port=0`.
- `nat/source.rs:1103-1133` — `address_only` path with `tuple_unknown` calls `try_next_port(addr_idx)` which uses atomic `counters` but never inserts into `owner_by_translated`.
- `nat/allocator.rs:295-309` — `try_next_port` only does `fetch_add` + `% range`, no collision check.

**Trace:** `match_source_nat_for_flow` (forwarding/mod.rs:325-346) is `#[allow(dead_code)]` (test/legacy), production uses `match_source_nat_for_flow_result_at` with real protocol. Synthetic path's returned `rewrite_src_port` is never installed as a session in prod (dead), so no wire collision. However, `try_next_port` advances per-addr atomic counters that are distinct from `next_port_offset_by_addr` used by real allocator — isolation prevents port reuse but also means synthetic allocations are invisible to exhaustion accounting.

**Why not HIGH:** Dead code in prod (marked `allow(dead_code)`), tests only. No security boundary crossing.

**Fix:** Either delete `match_source_nat` wrapper or make `try_next_port` check `owner_by_translated` and insert (consistent with `allocate_translation`). Or document as test-only.

**Dedup:** Not in dedup. Minor perf/cleanliness, not security.

---

## F-09 — LOW — NAT64 `pool_index` atomic retained but unused (dead code)

**Severity:** LOW (confusion, not vulnerability)  
**Confidence:** HIGH  
- `nat64.rs:192-197` — `pool_index: AtomicUsize` retained for "empty-pool / liveness probe only" per comment, but `classify_ipv6_dest` only checks `!pool_v4.is_empty()`, never uses `pool_index`. `allocate_v4_source` (test-only) uses it, prod `allocate_source` uses `PortAllocator` round-robin via its own counters.

Harmless dead field, could be removed to reduce confusion.

---

## Summary

| ID | Title | Sev | Conf | Status |
|---|---|---|---|---|
| F-01 | Deterministic NAT advisory visible, enforcement missing | MED | HIGH | CONFIRM OPEN #4559 |
| F-02 | NAT64 non-first frag leaks port+session (exhaustion) | HIGH | HIGH | **NEW** |
| F-03 | NAT64 HA reverse-info not synced (reply blackhole) | MED | HIGH | CONFIRM OPEN #4512/#4565 |
| F-04 | NAT64 pool exhaustion fail-closed | — | HIGH | NEGATIVE (correct) |
| F-05 | SNAT non-first frag no leak (NAT64 leaks) | — | HIGH | NEGATIVE SNAT, NEW NAT64 |
| F-06 | Integer safety | — | MED | NEGATIVE |
| F-07 | NPTv6 host-bits & self-overlap | — | HIGH | NEGATIVE (fixed) |
| F-08 | Synthetic protocol==0 try_next_port bypass | LOW | MED | INFO |
| F-09 | NAT64 pool_index dead | LOW | HIGH | INFO |

**Overall:** Core NAT safety (SNAT pool exhaustion, SNAT fragment no-leak, NAT64 empty-pool fail-closed, NPTv6 validation) is correctly fail-closed. Two substantive gaps remain: deterministic NAT unenforced (OPEN #4559, advisory satisfies visibility but not compliance) and NAT64 fragment port leak (NEW HIGH) allowing unauthenticated pool exhaustion, plus known HA reverse-sync gap (OPEN #4512 scope / #4565).
