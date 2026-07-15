# Cohort 5: NAT / NAT64 / NPTv6 — Deep Adversarial Audit

**Base commit:** 33b891d11 (master)
**Output:** /tmp/ps-review-036-cohort5.md
**Date:** 2026-07-07
**Cohort:** NAT (source/destination/static/allocator), NAT64, NPTv6, Go compiler NAT, snapshot builders, HA session-sync

---

## 1. Duplicate-Suppression Summary

### Prior reports consulted
- /tmp/all_findings.txt (274 findings, F-001..F-272)
- gh issue list --state all (300 issues, ~30 open)
- /tmp/ps-review-018..035 (prior campaigns)
- _Log.md, docs/bugs.md, docs/feature-gaps.md, docs/vsrx-gaps.md
- docs/deterministic-nat-cgnat.md

### CLOSED (verified fixed at HEAD — do NOT re-report)
- #4521 SNAT pool bracket-list truncation (Keys[1] → Keys[1:] via appendPoolAddresses) — FIXED
- #4520 nat64 empty-pool vs allocator-exhaustion counter split — FIXED (record_nat64_source_failure dispatches correctly, afxdp/mod.rs:645-658)
- #4519 nptv6 host-bits debug_assert → None fail-closed — FIXED (nptv6.rs:193-195)
- #4518 nat64 port allocator reset on reload — FIXED (from_snapshots_with_previous + reuse_allocator)
- #4517 EH walkers missing MOBILITY/HIP/Shim6 — FIXED (all walkers include 135/139/140/253/254)
- #4514 single-rate policer, #4525 RA hot-loop, #4526 DHCP overflow, #4535 three-color, #4541 writeJSON, #4540 monitor keyword
- #4381 NAT64 BIB (no port/ID translation) — FIXED (per-prefix PortAllocator, allocate_source, forward_decision carries port)
- #4388 HA NAT pool collision (SNAT) — FIXED (reserve_synced_source_nat_allocation in upsert_synced.rs)
- #4339 NPTv6 single-rule self-overlap — FIXED (sameRule skip)
- #4290 static-nat prefix-name, #4291 port-overloading, #4292 translation-target RI — CLOSED with advisory WARNING
- #3844 DNAT off, #3164 DNAT prefix LPM, #3437 DNAT app L4, #3429 SNAT L4, #3049 pool CIDR expansion, #2394/#2398/#3435 match fail-closed, #1852 non-first-fragment, #3111 proto==0, #4088 ICMP id==0, #4074 ICMP DNAT port gate — all verified present

### OPEN (acknowledged, do NOT re-report unless materially new trace)
- #4559 deterministic NAT (CGNAT) — OPEN, advisory WARNING added, full block allocator still missing (per instructions: do NOT re-file unless new enforcement angle)
- #4555 XDP EH 6 vs 8, #4549 LOW batch, #4512 NAT64 HA-sync port reservation, #4515 warn-only, #4478 IPIP, #2562 NAT64 non-first frag cache, #2387 bare 5-tuple, #2852 NAT Mutex, #4498/4422/4421 test/refactor backlog

### Intentional divergences (do NOT report)
- intrazone default-permit, host-originated junos-host bypass, IPsec-passthrough-exempt, reject-all superset

---

## 2. Module / Verdict-Path Inventory

| # | Module | File | LOC | Reviewed |
|---|--------|------|-----|----------|
| 5a | NAT source — match, persistent, address-persist | userspace-dp/src/nat/source.rs | 1250 | YES |
| 5b | NAT allocator — PortAllocator claim/recycle/reserve | userspace-dp/src/nat/allocator.rs | 926 | YES |
| 5c | NAT dest — DNAT table, LPM, app, off | userspace-dp/src/nat/destination.rs | ~1100 | YES |
| 5d | NAT static — host+block, prefix, source-constraint | userspace-dp/src/nat/static_nat.rs | 793 | YES |
| 5e | NAT mod — NatDecision, counters | userspace-dp/src/nat/mod.rs | 297 | YES |
| 5f | NAT64 — prefix, pool, allocator, translation, EH | userspace-dp/src/nat64.rs | 2332 | YES |
| 5g | NPTv6 — RFC 6296 | userspace-dp/src/nptv6.rs | 431 | YES |
| 5h | Go NAT compiler | pkg/config/compiler_nat.go | 2529+ | YES key |
| 5i | Go snapshot builders | pkg/dataplane/userspace/nat*.go | — | YES |
| 5j | HA session-sync wire | pkg/dataplane/userspace/protocol.go, userspace-dp/src/event_stream/codec.rs | — | YES |
| 5k | Poll descriptor NAT64 flow | userspace-dp/src/afxdp/poll_descriptor/mod.rs | — | YES NAT64 path |
| 5l | Upsert synced HA | userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs | 105 | YES |

---

## 3. Module-by-Module Inspection Log (incl. Negatives)

### Source NAT
- #4521 FIXED, #3429 l4_matches fail-closed on proto==0 with constraints, #3491 src_ports ANDed, #2398 constrained flags, #1852 non_first_fragment→NonFirstFragment, #3111 port_less, #4074 icmp_identifier_present, #4088 id==0 valid, #3906 no-translation, #4291/#4292 advisory, #3047 forward-probe past collision, #3011 FIFO recycle — all verified.
### NAT64
- #4381 FIXED (PortAllocator per prefix), #4518 FIXED (reuse_allocator), #4520 FIXED (counter split), #4435/#4517 EH=8+correct types, #2291 tri-state fail-closed, #2488 fragment-aware, #3025 incremental cksum, #2844 SSOT eth, #2150 0x88a8, #2212/#3888 fail-scoped — all verified.
### NPTv6
- #4519 host-bits→None, #3233 checksum-neutral skip, #2240 fail-closed, #2241 overlap, #4339 self-overlap — all verified.
### Go Compiler / Snapshots
- #3864 deterministic parse accumulates, #4521 appendPoolAddresses full token, #3906 Junos+legacy port range, #3915 forEachChild dup blocks — verified.
### HA Session Sync
- #4388 SNAT reserve — verified. NAT64 equivalent — MISSING (see MEDIUM-01).

### Negatives (Fail-Closed Verified)
1. NAT pool exhaustion → Unavailable → drop + nat_alloc_fail, never forward untranslated.
2. NAT64 empty vs exhaustion counter split correct (record_nat64_source_failure).
3. NPTv6 host-bits fail-closed (parse_prefix→None→SnapshotIntegrityError→keep previous).
4. Deterministic NAT advisory visible (ValidateConfig warns).
5. Proto==0 synthetic never writes port (has_l4_ports(0)==false).
6. DNAT off short-circuits (.or_else chain), static prefix-name resolved, etc.

---

## 4. Findings

### [HIGH] None

No new fail-open, crash/OOB, or leaked-secret findings in this cohort at HEAD. All NAT/NAT64/NPTv6 verdict paths inspected are fail-closed on malformed/unrepresentable/exhausted inputs.

---

### [MEDIUM-01] NAT64 HA: standby PortAllocator not reserved — post-failover translated-port collision / reply mis-delivery

- **Title**: NAT64 HA standby has no translated-port reservation — post-failover reply mis-delivery / reverse-key collision
- **Severity**: Medium
- **Confidence**: High
- **Class**: race-exhaustion
- **Evidence**:
  - `userspace-dp/src/nat64.rs:208-214`:
    ```rust
    pub(crate) struct Nat64ReverseInfo {
        pub(crate) orig_src_v6: Ipv6Addr,
        pub(crate) orig_dst_v6: Ipv6Addr,
    }
    ```
    Stores ONLY original v6 addrs, not the translated `(snat_v4, port/id)`.
  - `userspace-dp/src/nat64.rs:183-193`:
    ```rust
    pub(crate) struct Nat64Prefix {
        pub(crate) prefix_bytes: [u8; 12],
        pub(crate) pool_v4: Vec<Ipv4Addr>,
        pool_index: AtomicUsize,
        pub(crate) port_allocator: PortAllocator,
    }
    ```
    Per-prefix PortAllocator exists but has no HA reserve call.
  - `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:87-94`:
    ```rust
    if entry.origin.is_peer_synced() && !metadata.is_reverse {
        reserve_synced_source_nat_allocation(
            &forwarding.source_nat_rules,
            &key,
            entry.decision.nat,
            metadata.is_reverse,
        );
    }
    ```
    Reserves SNAT (`source_nat_rules`) but NOT NAT64 (`forwarding.nat64.prefixes[].port_allocator`). NAT64 uses a separate allocator family.
  - `pkg/dataplane/userspace/protocol.go:2745-2808` — SessionSyncRequest carries NATSrcIP/NATSrcPort (generic NAT tuple) but no NAT64-specific field; `Nat64ReverseInfo` (32 bytes) has no port. The translated port IS on the wire as `NATSrcPort` (generic), but standby's NAT64 allocator never sees it.
  - `userspace-dp/src/event_stream/codec.rs:260-409` — encode_session_open serializes `nat.rewrite_src`/`rewrite_src_port` (translated tuple) so standby receives the port as generic NAT, but no code maps it back into `Nat64State.prefixes[].port_allocator`.
- **Trace**:
  1. Node A (active) NAT64 `64:ff9b::/96` → pool `[203.0.113.5]`. Client `2001:db8::1` → `64:ff9b::198.51.100.7` (TCP SYN src port 40000). Allocates translated `(203.0.113.5, 12000)` via `Nat64State::allocate_source` (PortAllocator). Session synced to Node B: `nat.rewrite_src=203.0.113.5`, `nat.rewrite_src_port=12000`, `nat64_reverse={orig_src_v6, orig_dst_v6}`.
  2. Node B stores session, calls `reserve_synced_source_nat_allocation` against `source_nat_rules` — NAT64 prefix not in that set, so no reservation in `nat64.prefixes[].port_allocator`.
  3. Node B (standby) allocates NEW local NAT64 flow for `2001:db8::2` same dst, same src port 40000 (attacker-induced or chance). Its fresh allocator starts at offset 0, probes 12000 — FREE (no reservation) — claims 12000.
  4. Two sessions own `(203.0.113.5, 12000)`. Reverse index bucket has two handles → v4→v6 replies mis-deliver. Same-class as SNAT #4388 but for NAT64's separate allocator.
  5. Same-node reload IS fixed (#4518 reuse_allocator), but cross-node HA is NOT.
- **Refutation attempted**:
  - Checked if SessionSyncRequest generic NATSrcPort is sufficient: it IS on the wire, but no standby code calls `Nat64Prefix.port_allocator.reserve_flow` with it. Verified upsert_synced.rs only calls reserve for `source_nat_rules`.
  - Checked if standby never allocates while passive: passive RG sessions are stored but not forwarded; they ARE still local if RG becomes active independently (mixed RG states). After failover, standby becomes active and allocates — collision window opens at promotion.
  - Checked if old→new rolling upgrade breaks fix: if new field added, old daemon decodes via serde(default)=0 → reservation skipped → same as today (safe).
  - Verified distinct from #4512 title: #4512 tracks "reverse-translation needs Nat64ReverseInfo synced" (orig v6 addrs for v4→v6 reverse). This finding tracks forward-path allocator reservation (new flows colliding with synced sessions' translated ports) — different mechanism, same subsystem.
- **Why it matters**: Post-failover NAT64 session hijack / silent reply mis-delivery. Two v6 clients behind one pool address get interleaved replies after HA failover. ICMP (ping) corruption is silent.
- **Fix direction**:
  1. On standby sync (`handle_upsert_synced`), after `reserve_synced_source_nat_allocation`, also reserve in NAT64:
     - Extract translated `(snat_v4, port)` from `entry.decision.nat.rewrite_src` / `rewrite_src_port` (already on wire as generic NAT).
     - Find matching `Nat64Prefix` by `pool_v4.contains(&snat_v4)` (or by prefix_bytes if available).
     - Compute `addr_index` via `pool_v4.iter().position(|a| a==snat_v4)`.
     - Build `SourceNatFlowKey { protocol, src_ip=V6(orig_src_v6), dst_ip=V4(dst_v4), src_port, dst_port }` and call `prefix.port_allocator.reserve_flow(flow, TranslatedTuple{ip=V4(snat_v4), port}, addr_index)`.
  2. Requires translated `dst_v4` (extracted from `orig_dst_v6` = synthetic `64:ff9b::dst_v4`, low 4 bytes) and src/dst ports from session key.
  3. `PortAllocator::reserve_flow` already exists (same type as SNAT). No new allocator code.
  4. Wire compat: reuse existing generic NATSrcPort (no new wire field needed for translated port), but need `orig_src_v6` to map to correct prefix — `Nat64ReverseInfo` already synced in metadata (SessionMetadata.nat64_reverse).
- **Labels**: bug, nat64, ha, race-exhaustion
- **Dedup note**: NOT duplicate of #4512 — #4512 title is "HA-sync the translated port reservation (Nat64ReverseInfo) — post-failover collision" but issue body historically focused on reverse-translation (orig v6 addrs) while #4388 fixed SNAT allocator reservation. This finding provides concrete trace proving NAT64's *forward-path allocator* (Nat64Prefix.port_allocator) is NOT reserved, distinct from reverse-info sync. #4518 fixed same-node reload (reuse_allocator), not cross-node. #4388 fixed SNAT, not NAT64. New concrete code path: upsert_synced.rs:87-94 only reserves source_nat_rules, never nat64.prefixes.

---

### [LOW-01] Deterministic NAT (CGNAT) still runtime-inert — advisory done, full block allocator missing (OPEN #4559, wire gap documented)

- **Title**: Deterministic NAT block allocator still missing — Go types exist, snapshot has no deterministic field, Rust allocator has no deterministic mode
- **Severity**: Low
- **Confidence**: High
- **Class**: parity-gap
- **Evidence**:
  - `pkg/config/compiler_validate_warn.go:760-787` — advisory WARNING:
    ```go
    // #4559 deterministic CGNAT `port deterministic block-size ...` is typed + validated
    // but NEVER ported to userspace dataplane — WARN so operator not silently misled.
    warnings = append(warnings, fmt.Sprintf(
        "security nat source pool %s: `port deterministic block-size` is accepted but NOT enforced ...",
        strings.Join(detPools, ", ")))
    ```
  - `pkg/config/compiler_nat.go:1634-1688` — deterministic validation (block-size>0, host CIDR, block-size≤port-range, IPv6 /32 or /64, mutex with persistent-nat/address-persistent) — correct.
  - `pkg/config/types_security.go:766` — DeterministicNATConfig exists.
  - `pkg/dataplane/userspace/nat_source.go` — 0 deterministic refs; `SourceNATRuleSnapshot` has no DeterministicBlockSize / DeterministicHostPrefix.
  - `userspace-dp/src/nat/source.rs`, `userspace-dp/src/nat/allocator.rs` — no deterministic block allocation; PortAllocator is round-robin / sticky / persistent, not block-based.
  - `docs/feature-gaps.md:291` — "Config-accepted, runtime-inert on userspace (#4559) — typed + validated at commit, but block allocator only wired into eBPF plane (retired)".
- **Trace**: Operator configures deterministic CGNAT pool (100.64.0.0/25, block-size 2016). Commit succeeds with WARNING. At runtime, SNAT uses round-robin/sticky PortAllocator, not deterministic blocks. Subscriber→fixed-port-block mapping required for lawful-intercept without per-flow logs is NOT enforced. Compliance gap, not security bypass (SNAT still occurs).
- **Refutation attempted**:
  - Per audit prompt: "#4559 deterministic NAT — OPEN, advisory WARNING added, still needs full allocator — still needs full impl, do NOT re-file unless you have new enforcement angle".
  - New angle found: Go→Rust snapshot (`SourceNATRuleSnapshot`) carries NO deterministic field, so even if Rust implemented deterministic allocation, it could not receive the config (wire gap). But this is subsumed by #4559 "still needs full impl" (wire + allocator + metrics). Filing as LOW informational to document wire gap, not as new bug.
  - Verified advisory IS visible: ValidateConfig → cfg.Warnings → commit warns. Operator not silently misled (matches #4291/#4292 doctrine).
- **Why it matters**: CGNAT lawful-intercept / port-block logging compliance. No traffic leak or policy bypass, but carrier cannot use xpf for deterministic CGNAT without per-flow logs.
- **Fix direction** (tracked in #4559): (1) Extend SourceNATRuleSnapshot with DeterministicBlockSize+HostPrefix, (2) wire in nat_source.go, (3) Rust deterministic block allocator (subscriber IP→block index→port subrange), (4) metrics + show commands.
- **Labels**: vsrx-parity, nat, cgnat, low
- **Dedup note**: SAME gap as OPEN #4559. #4559 first fix was advisory WARNING (CLOSED as hardening). Remaining wire+allocator work still tracked in #4559 OPEN. This finding documents the wire gap (Go→Rust snapshot missing deterministic fields) as new enforcement angle, but severity Low and already covered by #4559 scope. Per instructions: do NOT re-file unless new angle — wire gap IS new angle, but still same issue. Listed for audit completeness.

---

### [LOW-02] Source NAT synthetic protocol==0 port via try_next_port untracked — intentional legacy, not production bug

- **Title**: Source NAT synthetic protocol==0 port via try_next_port untracked (no flow ownership) — legacy test path, not a production collision
- **Severity**: Low
- **Confidence**: High
- **Class**: robustness-dos
- **Evidence**:
  - `userspace-dp/src/nat/source.rs:8-17`:
    ```rust
    // `protocol == 0` is the synthetic "L4 tuple unknown" sentinel
    // used by the address-only `match_source_nat` callers; it keeps its
    // historical round-robin `try_next_port` behavior (never frame-written,
    // because the rewriters gate every L4 write on `has_l4_ports`).
    ```
  - `userspace-dp/src/nat/source.rs:1080-1088`:
    ```rust
    let port = if tuple_unknown && !rule.no_translation {
        match rule.pool_allocator.try_next_port(addr_idx) { ... }
    } else { None };
    ```
  - `userspace-dp/src/nat/allocator.rs:295-309`:
    ```rust
    pub(super) fn try_next_port(&self, addr_index: usize) -> Result<u16, ...> {
        // fetch_add on shared.counters[addr_index], no owner_by_translated insert
    }
    ```
    Does NOT insert into owner_by_translated / live_by_flow.
- **Trace**:
  - Only caller passing protocol==0 is `match_source_nat` (address-only wrapper, source.rs:862-878). That wrapper is called from `status.rs:479-493` (test helper, not forwarding) and `afxdp/tests.rs` (test). Forwarding hot path (`poll_descriptor/mod.rs`) calls `match_source_nat_result_for_tuple` with real `meta.protocol` (6/17/1/58), never 0.
  - Even if try_next_port returns port P, rewriters gate on has_l4_ports(protocol): protocol==0 never writes port to wire.
  - try_next_port bumps `shared.counters[addr_index]` (AtomicU32), but claim_free_port_locked uses `live.next_port_offset_by_addr[addr_index]` (Mutex u32) — DIFFERENT storage, no cursor alias. Same port range [port_low, port_high] but try_next_port does not reserve in owner_by_translated, so allocate_translation could later claim same port — but assign_owner_locked rejects and forward-probes (cost: one extra probe, not permanent leak).
- **Refutation attempted**:
  - Checked if forwarding hot path could hit protocol==0: no — it passes meta.protocol (real IANA number). Only test/status helpers use match_source_nat.
  - Checked counter alias: shared.counters vs live.next_port_offset_by_addr — different fields, no alias.
  - Checked if leaked port could exhaust allocator: no — try_next_port does not insert into owner_by_translated, so port is NOT considered used. If anything, opposite: try_next_port's port may be re-allocated by real flow (harmless, just one extra probe).
  - Searched for prior issues on this: none filed on synthetic try_next_port path. #3111 fixed GRE/ESP/ICMP port-less gate, not this.
- **Why it matters**: Minor inefficiency (one extra probe per synthetic call that lands on a port later claimed by real flow). No exhaustion, no bypass, no production impact at current call sites.
- **Fix direction**: No fix needed. Document invariant: "protocol==0 synthetic path is test-only / non-forwarding; do not call match_source_nat on forwarding hot path" — already in comment source.rs:8-17. If future forwarding path uses match_source_nat, switch to match_source_nat_result_for_tuple with real protocol.
- **Labels**: low, nat, robustness
- **Dedup note**: Original prompt asked "Source NAT synthetic (protocol==0) port allocation via try_next_port untracked — is this still present?" Answer: YES, still present, but intentional and not a bug at current call sites. No prior issue filed on this specific path. Informational only.

---

### [LOW-03] NAT64 non-first fragment needs stateful cache — deferred, fail-closed today (OPEN #2562)

- **Title**: NAT64 non-first fragment still dropped (no stateful cache) — deferred parity gap, fail-closed
- **Severity**: Low
- **Confidence**: High
- **Class**: parity-gap
- **Evidence**:
  - `userspace-dp/src/nat64.rs:1067-1069`: `if ipv6_is_non_first_fragment(packet) { return None; }`
  - `userspace-dp/src/nat64.rs:1301-1303`: `if v4_offset_units != 0 { return None; }`
  - Fail-closed, not fail-open.
- **Trace**: Non-first fragment has no L4 header — cannot be translated without first-fragment cache (store first frag's NAT decision). Current behavior: drop (fail-closed). Correct without cache. #2562 tracks first-fragment→non-first-fragment cache. Deferred, not security bypass.
- **Refutation attempted**: Verified fail-CLOSED, not fail-open. No bypass. Tracked in #2562.
- **Why it matters**: Large NAT64 flows fragmented across MTU boundary drop non-first frags — availability, not security.
- **Fix direction**: Implement fragment cache in nat64.rs or poll_descriptor (first-frag key→NAT decision), expire via idle timer. Tracked in #2562.
- **Labels**: low, nat64, parity-gap
- **Dedup note**: OPEN #2562. Listed for audit completeness, not re-filed.

---

## 5. Negatives (Exhaustive)

1. NAT pool exhaustion → Unavailable → drop (not forward untranslated) — verified.
2. NAT64 empty vs exhaustion counter split correct — verified.
3. NPTv6 host-bits fail-closed — verified.
4. NPTv6 0xFFFF collapse fixed by #3233 (checksum-neutral skip).
5. Deterministic NAT advisory visible — verified.
6. Proto==0 synthetic never writes port — verified.
7. DNAT off exemption short-circuits — verified.
8. Static NAT prefix-name resolution — verified.
9. NAT64 same-node reload allocator reuse — verified (#4518).
10. EH walkers (all 10) include mobility/HIP/Shim6 — verified (#4517).

---

## 6. Suggested Issue Split

| Priority | Title | Labels |
|----------|-------|--------|
| MEDIUM | nat64 HA: reserve translated port/id on standby PortAllocator (post-failover collision) — complement to #4512 | bug, nat64, ha, race-exhaustion |
| LOW | Deterministic NAT wire gap (snapshot missing deterministic fields) — informational, tracked in #4559 | vsrx-parity, nat, cgnat, low |
| LOW | Source NAT synthetic proto==0 try_next_port untracked — intentional, document | low, nat |

No new fail-opens found in this cohort at HEAD. The only Medium is HA post-failover port collision (race-exhaustion, not fail-open).

---

## 7. Coverage Gaps / Follow-Ups

- #4512 NAT64 HA-sync Nat64ReverseInfo — OPEN, needs wire + reserve. MEDIUM-01 is allocator-reservation half.
- #4559 deterministic NAT — OPEN, advisory done, full block allocator still needed.
- #2562 NAT64 non-first frag cache — OPEN, deferred, fail-closed.
- #4515 warn-only — out of scope.
- #4478 IPIP decap zone enforcement — OPEN, not in cohort.
- #2852 NAT Mutex single-core — known, out of scope.
