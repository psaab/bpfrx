# Cohort 6: Session / conntrack — deep adversarial audit — ps-review-029

## 1. Base commit reviewed

```
Repo: /home/ps/git/avacado-xpf
Branch: master
Commit: b1bd96fb68de40d6fc357e63d9717f7ad75241fa (merge PR #4531 from psaab/fix/4526-dhcp-timer-overflow, same as ps-review-020 base c2ee227c4)
Date: 2026-07-07
Cohort: 6 — userspace-dp/src/session/{mod,lookup,gc,install,index,expire,key,entry,ctx,wheel}, userspace-dp/src/afxdp/session_glue/{mod,promote,commands}, userspace-dp/src/afxdp/forwarding/mod.rs (session install, strict SYN check, LocalDelivery cache), userspace-dp/src/tcp_flags.rs, userspace-dp/src/afxdp/poll_descriptor (+ flow_cache)
```

## 2. Output path

`/tmp/ps-review-029.md`

## 3. Duplicate-suppression summary

Read `/tmp/all_findings.txt` (272 entries), `/tmp/ps-review-020.md` (cohort 6, base c2ee227c4), `/tmp/ps-review-018.md`-025.md.

### Prior session findings — confirmation (not re-reported as new, but required by task)

| ID | Topic | Status on b1bd96fb6 | Dedup |
|----|-------|---------------------|-------|
| S-001 | Cross-zone / cross-VRF session hijack via bare 5-tuple SessionKey | **STILL PRESENT** — SessionKey `{addr_family, protocol, src_ip, dst_ip, src_port, dst_port}` has no zone/VRF discriminator; session hit at `poll_descriptor/mod.rs:859-879` does no zone re-validation for transit ForwardCandidate. Only flow-cache is zone-aware (ingress_ifindex in set_index). Flow-cache MISS → session-table HIT = cross-zone reuse. | Already filed ps-review-020 S-001. VERIFIED still present — see §6 C-01. Not re-reported as NEW. |
| S-002 | Bare TCP ACK as first packet → ESTABLISHED (300s) session — DoS amplification vs SYN flood | **STILL PRESENT** — `session/install.rs:158` `established = !(TCP && is_initial_syn)` → bare ACK (ACK=0x10, no SYN) = `established=true` = 300s. Only `is_initial_syn` (SYN && !ACK) triggers OPENING (20s). Bare ACK flood needs 436 pps sustained vs 6553 pps for SYN flood — 15× more efficient DoS. | Already filed ps-review-020 S-002. VERIFIED still present — see §6 C-02. Not re-reported as NEW. |
| P6 RST/FIN creates session | Fixed #4400/#4453/#4487 | **VERIFIED FIXED** on b1bd96fb6. Three sub-paths: ForwardCandidate (#4400 strict_syn_check), LocalDelivery (#4487 should_cache decline), fabric (#4453 cluster_peer_return skip). All use same `is_closing && !has_syn` predicate. Tests pin. | Not re-reported. |
| P7 fabric NAT skip | Fixed #4414/#4439 | **VERIFIED FIXED**. Protocol allowlist TCP\|ICMP\|ICMPv6 only in `cluster_peer_return_fast_path`. UDP/ESP/AH fall through to RG owner forward (NAT applied). | Not re-reported. |
| S-004 per-worker session-limit bypass | Asked to verify — NEW concept | Reviewed below — the per-worker multiplier (`N × configured`, #2186) is **documented and intentional**, not a bypass. The session-limit is a per-worker dataplane mechanism, not a global cap. Docs explicitly say "Size the configured value as a per-worker ceiling." This is a design invariant, not a bug. See §6 N-01. | Not a new finding (intentional divergence). |
| S-005 spoofed reverse SYN-ACK | Asked to verify — NEW concept | Reviewed below — `promote_from_reverse = is_tcp && is_syn_ack(tcp_flags) && metadata.is_reverse`. A reverse SYN-ACK promotion requires `is_reverse` (the session entry's direction flag). An attacker injects a FORWARD (not reverse) SYN-ACK — would NOT have `is_reverse=true` on the forward entry, so no promotion. Reverse path requires attacker to control reverse direction (server side or L2 to server network). This is the F16 fix. See §6 N-02. | Not a new finding (F16 fix is correct). |

### Intentional divergences (NOT bugs, not re-reported)
- **Intrazone default-permit** — intentional, documented.
- **Per-worker session-limit multiplier (#2186)** — intentional, documented in `docs/feature-gaps.md`: "effective admitted cap ≈ N × configured, Size the configured value as a per-worker ceiling." The per-worker SessionTable is single-writer, no cross-worker sharing. Global cap would require cross-worker atomics (violates #1855 contract).
- **Mid-stream pickup (non-SYN first packet → ESTABLISHED)** — intentional for asymmetric routing, but bare ACK (no data) should arguably be shorter (see S-002 residual, already filed).
- **Host-originated junos-host, IPsec-passthrough-exempt, reject-all superset** — known intentional divergences, not reported.

## 4. Module / verdict-path inventory (coverage checklist)

| Module | File(s) | Role | Reviewed |
|--------|---------|------|----------|
| SessionKey / NAT transforms | `session/key.rs` | Bare 5-tuple key, NAT wire/canonical/reverse transforms, ICMP QID handling (#4074) | YES full |
| SessionTable core | `session/mod.rs` (2054 lines) | Table definition, SessionEntry, SeededKeyMap, seeded hash (#2364), 1:N NAT indexes (#4399/#4438), in-place refresh (#1752), companion promotion (#4109), session-limit counts (#2134/#3122/#4377) | YES full |
| SessionTable lookup | `session/lookup.rs` (411) | Primary + alias lookup, 1:N bucket walks, TCP state (close/RST/promotion), stale-index guard | YES full |
| SessionTable install | `session/install.rs` (521) | New-flow install, synced import, cap check, established seed, per-IP count | YES full |
| SessionTable expire/GC | `session/expire.rs` (625), `session/wheel.rs` | Timer-wheel GC, standby retention (SELF-HEAL/HOLD/AGE), companion keepalive (#4380), HA gates (#2120) | YES full |
| SessionTable NAT indexes | `session/mod.rs:1920-2050` | `nat_index_bucket_push` dedup/collision, `nat_index_bucket_remove` per-handle, SmallVec N=2 | YES full |
| TCP flags | `tcp_flags.rs` (121) | Flag constants + predicates (`is_initial_syn`, `is_syn_ack`, `is_closing`, `is_ack_only`, etc.) | YES full |
| Forwarding / LocalDelivery cache | `afxdp/forwarding/mod.rs:1741-1980` | `should_cache_local_delivery_session_on_miss` (P6b L3 fix), `should_block_tunnel_interface_nat`, `lookup_forwarding_resolution_*`, zone/VRF local-delivery (#3769/#3151) | YES full |
| Session glue / HA | `afxdp/session_glue/mod.rs` (1277), `promote.rs`, `commands/*` | `resolve_flow_session_decision`, `maybe_promote_synced_session`, `purge_translated_synced_hit`, fabric redirect, `should_teardown_tcp_rst` (returns false) | YES full |
| Poll descriptor / session-miss | `afxdp/poll_descriptor/mod.rs` (6088 lines, session-relevant sections) | `strict_syn_check_drops_new_flow` (#4400), `new_flow_session_limit_drop` (#2134), flow-cache ↔ session-miss orchestration, host-inbound + junos-host gates on LocalDelivery | YES session sections |
| Flow cache | `afxdp/flow_cache.rs` | `packet_eligible`, `should_cache`, fast-path accounting, TTL-before-egress (#3779) | YES relevant |
| Fabric return fast path | `afxdp/forwarding/mod.rs:713-816` | `cluster_peer_return_fast_path` (P6 fabric + P7 NAT skip) | YES full |
| Session limits | `session/mod.rs:776-863` + `install.rs:214-221` + `lookup` + `poll_descriptor:560-582` | `session_limit_active`, `set_session_limit_active` OFF→ON back-count (#4377), `session_limit_inc/dec`, `session_limit_src/dst_counts`, enforcement | YES full |

## 5. Module-by-module inspection log (including negatives)

### 5.1 SessionKey — PASS (with known S-001 residual: zone/VRF bare 5-tuple)

`SessionKey` at `session/key.rs:10-17`:
```rust
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}
```
Bare 5-tuple + family, no zone/VRF/ingress discriminator. NAT transforms (`forward_wire_key`, `reverse_wire_key`, `translated_session_key`, `reverse_session_key`, `reverse_canonical_key`) are pure SessionKey × NatDecision → SessionKey, verified correct including ICMP Query Identifier handling (#4074). NAT index bucket 1:N multimap mitigation (#4399/#4438) is correct — `nat_index_bucket_push` dedup, `nat_index_bucket_remove` per-handle, collision counter.

**Residual**: bare 5-tuple key enables cross-zone/VRF session reuse (S-001, already filed, §6 C-01).

### 5.2 Session install — PASS (with S-002 residual)

`install_with_protocol_with_origin` at `session/install.rs:113-248`:
- Cap check `len() >= max_sessions` → `create_drops` → false (fail-closed)
- `established` seed: `!(TCP && is_initial_syn)` — bare SYN → OPENING (false), everything else → ESTABLISHED (true). This is the S-002 residual (bare ACK → ESTABLISHED 300s, not OPENING 20s). Correct per design intent (mid-stream pickup) but suboptimal for DoS.
- Timeout selection via `session_timeout_ns` → `opening_override_for(ingress_zone)` for OPENING branch (#3527), per-app override for ESTABLISHED (#3227), closing/RST short windows (#3046/#3489)
- Counted-class `!is_reverse && !is_transient_local_seed()` → `session_limit_inc` — correct, origin-agnostic per #3122
- Delta emit gated on `counted && !is_peer_synced()` — no echo loop

`upsert_synced_with_origin` at `session/install.rs:275-403`: imported as `established=true` (not re-derived as OPENING — correct, standby doesn't apply half-open window, relies on primary's Close delta). Per-IP count includes synced sessions (#3122). Correct.

`can_admit(needed)` preflight — conservative, guarantees post-preflight install infallibility. Correct.

### 5.3 Session lookup / TCP state machine — PASS (S-002 is install-time, not lookup-time)

`lookup_with_origin` at `session/lookup.rs:48-213` — verified:
- Primary + alias (reverse_translated_index 1:N bucket walk + validate) — correct
- `do_close = TCP && is_closing(tcp_flags)` → `closing=true`, `reset |= has_rst` (sticky) — correct
- **F16 fix verified**: `promote_from_reverse = TCP && is_syn_ack(flags) && is_reverse` — only reverse SYN-ACK promotes, not forward ACK, not bare reverse ACK. Tests `forward_ack_without_reverse_synack_stays_opening` + `reverse_bare_ack_does_not_promote_opening` pin this. Verified.
- `session_timeout_ns(established=…)` re-selection on every lookup — correct
- `propagate_tcp_state_to_companion` (#4109 F17) — close + established mirrored — correct
- Stale-index guard — correct

`find_forward_nat_match` / `find_forward_wire_match_with_origin` / `resolve_reverse_translated_handle` — 1:N bucket walks with validate-on-lookup — correct per #4399/#4438.

### 5.4 Session expire / GC — PASS

`expire_stale_entries_ha` at `session/expire.rs:121-412`:
- Wheel cursor drain, lazy-delete, idle expiry, re-bucket — correct
- Standby gate: SELF-HEAL → HOLD → ReapStaleSynced → AgedOwnerRgZero → Age — correct per #2120
- **#4380 companion keepalive** — `reverse_session_key(key, nat)` recovers companion, probes `now - last_seen <= expires_after`, re-stamps idle half from companion's real `last_seen_ns` — correct. Gated to owner-side Age only. Verified functional.

`session_timeout_ns` at `session/mod.rs:2014-2050`: closing (RST 2s / FIN 30s) → OPENING (zone override or global 20s) → ESTABLISHED (app override or global 300s) → UDP/ICMP/OTHER. Correct precedence. Negative: none.

### 5.5 Session in-place refresh — PASS

`update_session` at `session/mod.rs:1170-1399`: `closing |=`, `reset |=`, `established |= is_syn_ack && is_reverse` (all sticky). Secondary-index reindex gated on `nat/is_reverse/owner_rg_id`. HA promote count-neutral. Correct.

`remove_entry` at `session/mod.rs:1616-1689`: primary-key guard, stale-handle guard, secondary-index cleanup (value-guarded), per-IP decrement. Sole removal sink. Correct.

`refresh_for_ha_transition` — always updates, resets `first_held_ns=0, seen_rg_epoch=0`. Correct.

### 5.6 NAT indexes — PASS

`nat_index_bucket_push` / `nat_index_bucket_remove` — dedup, collision counter, per-handle removal. `SmallVec<[u32;2]>` N=2 free (same size as N=1). Correct. Verified fixed (#4399/#4438).

### 5.7 TCP flags — PASS (one LOW new finding: PSH check missing, see M-01)

`tcp_flags.rs:1-121` — canonical SSOT, correct bit values per RFC 9293 §3.1. Predicates correct. Verified.

New finding: PSH alone can skirt certain DoS paths — not a bypass, but hardening gap. See M-01.

### 5.8 Poll descriptor / session-miss — PASS (verified fixed)

`strict_syn_check_drops_new_flow` at `poll_descriptor/mod.rs:614-618`:
```rust
fn strict_syn_check_drops_new_flow(protocol: u8, tcp_flags: u8) -> bool {
    matches!(protocol, PROTO_TCP) && is_closing(tcp_flags) && !has_syn(tcp_flags)
}
```
Applied at `poll_descriptor/mod.rs:1986-1995` — only ForwardCandidate/MissingNeighbor (transit), LocalDelivery exempt (correct). Verified fixed. `new_flow_session_limit_drop` read-only, no phantom entries (#2128). Correct.

### 5.9 Flow cache — PASS

`packet_eligible` — `TCP && is_ack_only || UDP` — only pure-ACK TCP + UDP cacheable. `should_cache` folds `packet_eligible` (#2363) — SYN/SYN-ACK/FIN/RST never seed cache. PSH+ACK data segments cacheable (correct). NAT64 excluded, NPTv6 included. Correct.

### 5.10 Fabric return fast path — PASS (P6 fabric + P7 NAT skip verified fixed)

`cluster_peer_return_fast_path` at `forwarding/mod.rs:713-816` — fabric ingress check → zone override → ICMP echo request exclude → bare SYN exclude → bare RST/FIN exclude (#4453) → protocol allowlist TCP|ICMP|ICMPv6 only (#4414/#4439) → FIB lookup → zone resolution → reverse seed. All exclusions present. Correct.

### 5.11 Session glue / HA — PASS

`resolve_flow_session_decision` — primary session lookup → NAT reverse match → reverse session install (`created`/`install_failed` #1861). `maybe_promote_synced_session` — only promotable + ForwardCandidate. `should_teardown_tcp_rst` returns false (intentional — RST teardown via timeout). `should_keep_synced_hit_transient` — peer-synced + not locally active + translated-forward-key → purge (correct).

### 5.12 Forwarding / LocalDelivery cache — PASS (verified fixed)

`should_cache_local_delivery_session_on_miss` at `forwarding/mod.rs:1741-1789`: Non-TCP → true, TCP + `ACK && !SYN` → false (bare ACK, #2151), TCP + `is_closing && !has_syn` (bare RST/FIN) → false (P6b, #4487). Otherwise → true. Subsumes #2151. Correct.

---

## 6. Findings

CONFIRMED prior findings (S-001, S-002 — STILL PRESENT, not new):

### [C-01] S-001 CONFIRMED: Cross-zone / cross-VRF session hijack via bare 5-tuple SessionKey — policy bypass (FAIL-OPEN) — STILL PRESENT on b1bd96fb6

- **Title**: SessionKey has no zone/VRF discriminator — a packet from zone C reuses a zone A→B session and bypasses zone C's policy — STILL PRESENT
- **Severity**: High (fail-open)
- **Confidence**: High
- **Class**: fail-open / implementation-bug
- **Evidence** (fresh, b1bd96fb6):

  `userspace-dp/src/session/key.rs:10-17` — SessionKey is bare 5-tuple + family (no zone/VRF):
  ```rust
  pub(crate) struct SessionKey {
      pub addr_family: u8,
      pub protocol: u8,
      pub src_ip: IpAddr,
      pub dst_ip: IpAddr,
      pub src_port: u16,
      pub dst_port: u16,
  }
  ```

  `userspace-dp/src/afxdp/poll_descriptor/mod.rs:859-879` — session hit path does NO zone re-validation for transit ForwardCandidate:
  ```rust
  let Some(resolved) = resolve_flow_session_decision(
      sessions, ..., flow, now_ns, now_secs, meta.protocol, meta.tcp_flags, ...
  ) {
      telemetry.counters.session_hits += 1;
      // ... host-inbound re-check (LocalDelivery only), junos-host re-check (LocalDelivery only), TTL check
      // NO zone/VRF re-validation for transit ForwardCandidate
  ```

  `userspace-dp/src/session/lookup.rs:62-68` — lookup by bare 5-tuple only:
  ```rust
  let (handle, via_alias) = match self.key_to_handle.get(key) {
      Some(h) => (*h, false),
      None => match self.resolve_reverse_translated_handle(key) { ... }
  };
  ```

  `userspace-dp/src/afxdp/flow_cache.rs:759-780` — flow cache IS zone-aware (includes `ingress_ifindex` in set index), but session table is not. Flow-cache miss → session-table hit with bare 5-tuple = cross-zone reuse. Same VRF overlapping 10.0.0.0/24 case identical.

- **Trace** (concrete, b1bd96fb6):

  Config: Two zones, `untrust` (reth0.0, 10.0.0.0/24) and `dmz` (reth1.0, 192.168.1.0/24). Policy: `from-zone untrust to-zone trust then permit` (allows 10.0.0.5:1234 → 8.8.8.8:443). Policy: `from-zone dmz to-zone trust then deny` (blocks dmz→internet). Same VRF or overlapping VRFs.

  Attack:
  1. Legit client in untrust: SYN `10.0.0.5:1234 → 8.8.8.8:443`, TCP. Creates session `SessionKey{AF_INET, TCP, 10.0.0.5, 8.8.8.8, 1234, 443}` with decision `ForwardCandidate, permit`.
  2. Attacker in dmz (or spoofing from dmz ifindex): sends `10.0.0.5:1234 → 8.8.8.8:443`, same 5-tuple (spoofed src_ip+port). Packet arrives on dmz ingress ifindex.
  3. Flow cache: `set_index({10.0.0.5, 8.8.8.8, ...}, dmz_ifindex)` → MISS (different ingress_ifindex from untrust's cached entry).
  4. Session table: `key_to_handle.get({AF_INET, TCP, 10.0.0.5, 8.8.8.8, 1234, 443})` → HIT (bare 5-tuple, same key). Returns untrust→trust permit session.
  5. Session hit path: no zone re-validation for ForwardCandidate transit. Packet forwarded with untrust's permit decision, bypassing dmz→trust DENY.

  What vSRX does: Junos session table is zone-aware — sessions keyed by zone-pair or validated against ingress zone on hit. Cross-zone reuse impossible.

  VRF variant: Two routing-instances vrf-a and vrf-b both with 10.0.0.0/24 and 8.8.8.8/32 reachable. Session in vrf-a table (same 5-tuple) reused for vrf-b traffic, crossing VRF isolation.

- **Refutation attempted**:
  - Checked if `SessionMetadata.ingress_zone` is validated on session hit: NO — stamped at install, read for telemetry/logging, never compared against current packet's ingress zone on hit.
  - Checked if flow-cache zone isolation prevents: flow cache includes `ingress_ifindex` in set_index, but flow-cache MISS falls through to zone-unaware session table.
  - Checked if `resolve_flow_session_decision` / `lookup_session_across_scopes` validates zone: NO — pure 5-tuple lookup.
  - Checked if interface-level filtering prevents cross-zone spoofing: zones map to ifindices, but attacker with L2 access or VLAN misconfig can inject with spoofed src_ip. In reth/VLAN deployment where untrust+dmz share physical port, trivially reachable.
  - Checked if already tracked: YES — ps-review-020 S-001 already files this. NOT new.

- **Why it matters**: FAIL-OPEN. A DENY in zone C bypassed by PERMIT session in zone A with same 5-tuple. Operator configures `from-zone dmz to-zone trust then deny`, expects block, but existing untrust→trust session with same 5-tuple lets dmz traffic through. VRF isolation similarly violated.

- **Fix direction**: Include zone/VRF discriminator in SessionKey, or validate `ingress_zone` on session hit and re-evaluate policy on mismatch. Option B preferred (cheaper): on session hit, compare `resolved.metadata.ingress_zone` against current packet's `from_zone_id`, on mismatch treat as session MISS and re-evaluate policy. VRF: similarly include routing-instance or table ID.

- **Labels**: `fail-open`, `security`, `session`, `zone`, `vrf`, `policy-bypass`
- **Dedup note**: STILL PRESENT on b1bd96fb6, verified fresh. Already filed as ps-review-020 S-001. NOT a new finding — included here as required confirmation per task ("VERIFY if still present, do NOT re-report if already filed, but CONFIRM with evidence"). This is S-001 confirmation, not S-001 re-report.

---

### [C-02] S-002 CONFIRMED: Bare TCP ACK as first packet creates ESTABLISHED (300s) session — DoS amplification vs SYN flood — STILL PRESENT on b1bd96fb6

- **Title**: Bare ACK (ACK=0x10, no SYN) as first observed packet creates ESTABLISHED session with 300s timeout — STILL PRESENT
- **Severity**: Medium (robustness-dos)
- **Confidence**: High
- **Class**: robustness-dos / implementation-bug
- **Evidence** (fresh, b1bd96fb6):

  `userspace-dp/src/session/install.rs:152-158`:
  ```rust
  // #3152: a TCP session created by a bare SYN (SYN set, ACK clear) starts OPENING
  // (`established=false`); every other first packet (non-TCP, or a TCP mid-stream
  // pickup such as a SYN-ACK or data segment) starts ESTABLISHED
  established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
  ```

  `userspace-dp/src/tcp_flags.rs:92-100`:
  ```rust
  pub(crate) fn is_initial_syn(flags: u8) -> bool {
      has_syn(flags) && !has_ack(flags)
  }
  ```
  Bare ACK (0x10): `has_syn(0x10)` = false → `is_initial_syn(0x10)` = false → `established=true` → ESTABLISHED 300s.

  `userspace-dp/src/session/mod.rs:2014-2050` `session_timeout_ns`:
  ```rust
  } else if !established {
      opening_override_ns.unwrap_or(timeouts.tcp_opening_ns) // 20s
  } else {
      app_override_ns.unwrap_or(timeouts.tcp_established_ns) // 300s
  ```

- **Trace** (concrete, b1bd96fb6):

  Config: Default zone, no `limit-session` (common). `max_sessions = 131072` per worker, 6 workers = 786k total.

  SYN flood (mitigated by #3152): bare SYN (SYN=0x02) → `is_initial_syn(true)` → `established=false` → OPENING 20s → reaps fast. Sustained to keep full: 131072/20 = 6553 pps.

  Bare ACK flood (NOT mitigated): bare ACK (ACK=0x10) → `is_initial_syn(false)` → `established=true` → ESTABLISHED 300s. Sustained to keep full: 131072/300 = 436 pps. 15× fewer packets than SYN flood for same DoS.

  What vSRX does: Junos `tcp-initial-timeout` applies to any half-open / unverified session. Bare ACK first packet gets shorter timeout.

- **Refutation attempted**:
  - `strict_syn_check_drops_new_flow`: NO — catches `is_closing && !has_syn` (RST/FIN without SYN). Bare ACK (ACK=0x10) not closing, passes.
  - `should_cache_local_delivery_session_on_miss`: PARTIALLY — LocalDelivery bare ACK → false (no cache, #2151). Transit ForwardCandidate bare ACK → still creates session.
  - `flow_cache::packet_eligible`: NO — `is_ack_only(0x10)` = true, so bare ACK IS flow-cache eligible AND creates sessions.
  - Mid-stream pickup intentional? YES partially — comment says "SYN-ACK or data segment starts ESTABLISHED". But bare ACK (no data, just 0x10) ≠ data segment.
  - Any test pins bare-ACK first-packet? NO.

- **Why it matters**: Bare ACK flood (436 pps sustained) fills session table 15× more efficiently than SYN flood that #3152 mitigated. `limit-session source-ip-based` caps per-IP but opt-in.

- **Fix direction**: (A) Bare ACK (ACK=0x10, no payload) as first packet → OPENING (20s), not ESTABLISHED (300s). Promote on data or reverse traffic. (B) Shorter mid-stream pickup timeout (60s) for non-SYN first packet. (C) Document as intentional and recommend `limit-session`.

- **Labels**: `robustness-dos`, `session`, `tcp`, `vsrx-parity`
- **Dedup note**: STILL PRESENT on b1bd96fb6, verified fresh. Already filed as ps-review-020 S-002. NOT a new finding — included here as required confirmation per task. This is S-002 confirmation.

---

CONFIRMED fixed (P6, P7):

### [C-03] P6 RST/FIN creates session — VERIFIED FIXED on b1bd96fb6 (all three sub-paths)

- **Title**: P6 RST/FIN session creation — FIXED (no new finding)
- **Severity**: N/A (verification)
- **Confidence**: High
- **Class**: N/A
- **Evidence**:
  - P6a ForwardCandidate: `poll_descriptor/mod.rs:1986-1995` `strict_syn_check_drops_new_flow(TCP, FIN|RST without SYN)` drops before install. `session/install.rs:158` `is_initial_syn` gate only applies to SYN; RST/FIN caught by strict check. Test `bare_rst_fin_on_miss_installs_no_session` (#4400) pins.
  - P6b LocalDelivery: `forwarding/mod.rs:1760-1789` `should_cache_local_delivery_session_on_miss` returns false for `is_closing && !has_syn` (same predicate), packet still reinjected to kernel. Test `local_delivery_bare_rst_fin_does_not_cache_session` (#4487) pins.
  - P6 fabric: `forwarding/mod.rs:734-755` `cluster_peer_return_fast_path` returns None for bare RST/FIN, falls through to peer's normal forward (whose own #4400 guard drops). Test pins.
  - All three arms use same `is_closing(flags) && !has_syn(flags)`. Consistent. Fixed.

### [C-04] P7 fabric NAT skip — VERIFIED FIXED on b1bd96fb6

- **Title**: P7 fabric NAT skip — FIXED (no new finding)
- **Evidence**: `forwarding/mod.rs:775-777` `cluster_peer_return_fast_path` protocol allowlist `TCP|ICMP|ICMPv6` only — UDP (#4439), ESP/AH/GRE/SCTP (#4414) refused, fall through to RG owner's forward where source-NAT applied.

---

CONFIRMED not-bugs (S-004, S-005 — asked to verify, NOT new findings):

### [N-01] S-004 per-worker session-limit multiplier — INTENTIONAL, NOT a bypass

- **Title**: Per-worker session-limit multiplier (N × configured) — documented intentional divergence, not a bypass
- **Severity**: Info
- **Confidence**: High
- **Class**: N/A — negative result (intentional design)
- **Evidence**:
  `docs/feature-gaps.md:315`:
  ```
  **Per-worker cap (#2186):** the count is maintained per-worker (per RX queue), so with RSS the effective admitted cap is `N × configured` where N = number of RX queues/workers — consistent with the rest of the per-worker dataplane, NOT a global cap. Size the configured value as a per-worker ceiling.
  ```
  `userspace-dp/src/session/mod.rs:776-863` `set_session_limit_active`, `session_limit_inc/dec` — per-worker SessionTable, single-writer, no cross-worker sharing. Global cap would require cross-worker atomics / locks, violating #1855 single-writer contract. All per-worker dataplane state has same multiplier (session-limit, NAT port alloc, etc.) — consistent design.

  Enforcement: `poll_descriptor/mod.rs:560-582` `new_flow_session_limit_drop` — reads `session_limit_src_count`/`dst_count` read-only (no phantom, #2128), fires once per new flow before install. Correct per-worker enforcement.

- **Why not a bug**: The per-worker multiplier is documented and intentional. Sizing `limit-session source-ip-based 100` on a 6-worker system yields effective 600, which the operator must account for. This is not a bypass — an attacker cannot exceed `N × configured` per IP across the cluster without controlling RSS distribution. If attacker controls RSS (e.g., can steer flows to specific queues via src_port hashing), they could theoretically concentrate on one worker, but then they obey that worker's limit (configured N). The multiplier is a sizing issue, not a bypass.

- **Dedup note**: Not in all_findings.txt as a bypass. Docs explicitly call out #2186 as intentional. This is a negative result for S-004 claim.

### [N-02] S-005 spoofed reverse SYN-ACK — NOT exploitable, F16 fix is correct

- **Title**: Spoofed reverse SYN-ACK promotion — NOT exploitable on b1bd96fb6 (F16 fix correct)
- **Severity**: Info
- **Confidence**: High
- **Class**: N/A — negative result (verified fail-closed)
- **Evidence**:
  `userspace-dp/src/session/lookup.rs:129-149` (F16 fix):
  ```rust
  let promote_from_reverse = is_tcp && is_syn_ack(tcp_flags) && entry.metadata.is_reverse;
  if promote_from_reverse {
      entry.established = true;
  }
  ```
  `userspace-dp/src/session/mod.rs:1299-1300` (update_session mirrors):
  ```rust
  record.entry.established |=
      matches!(protocol, PROTO_TCP) && is_syn_ack(tcp_flags) && metadata.is_reverse;
  ```

  Promotion requires BOTH `is_syn_ack(flags)` (SYN=0x02 && ACK=0x10) AND `is_reverse` (the matched session entry's direction flag = true). An attacker injects a FORWARD SYN-ACK (not reverse):
  - Forward entry: `is_reverse=false` → `promote_from_reverse=false` → NO promotion (stays OPENING 20s).
  - Reverse entry: to hit reverse entry, attacker must send a packet matching the REVERSE 5-tuple (server→client direction: dst_ip=attacker? No — reverse entry is keyed `server_ip:server_port → client_ip:client_port`). Attacker in untrust cannot easily spoof server's IP+port as source without controlling reverse path.
  - Bare reverse ACK (ACK=0x10, no SYN): `is_syn_ack(0x10)` = false (needs SYN) → NO promotion. Test `reverse_bare_ack_does_not_promote_opening` pins.

- **Why not exploitable**: The F16 predicate `is_syn_ack && is_reverse` is correct — only a genuine reverse SYN-ACK (server→client) promotes. Forward SYN-ACK never promotes (stays OPENING). Bare reverse ACK never promotes. An off-path attacker cannot inject reverse traffic without controlling the reverse path (server side or L2). If attacker controls reverse path, they already have a stronger position (can inject any traffic). This is not a new bypass.

- **Dedup note**: F16 fix verified in ps-review-020 §5.9. No new finding for S-005.

---

NEW findings (not in ps-review-020, not in ps-review-024/025, not in all_findings.txt):

### [M-01] TCP PSH-only data (PSH=0x08, no ACK) as first packet → OPENING (20s) timeout, but also not caught by strict-syn-check or LocalDelivery bare-ACK gate — allows pure-PSH flood via 300s ESTABLISHED if combined with ACK

- **Title**: TCP PSH-ACK (PSH+ACK=0x18) as first packet → ESTABLISHED 300s — same class as bare ACK DoS, plus pure PSH (PSH=0x08) edge case inconsistent
- **Severity**: Medium (robustness-dos, related to S-002 class)
- **Confidence**: High
- **Class**: robustness-dos / implementation-bug
- **Evidence**:

  `userspace-dp/src/session/install.rs:158`:
  ```rust
  established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
  ```
  `is_initial_syn(0x18)` = `has_syn(0x18) && !has_ack(0x18)` = `false && false` = false → `established=true` → ESTABLISHED 300s.

  `userspace-dp/src/tcp_flags.rs:88-91`:
  ```rust
  pub(crate) fn is_ack_only(flags: u8) -> bool {
      (flags & TCP_FLAGS_CTRL_MASK) == TCP_ACK
  }
  ```
  `TCP_FLAGS_CTRL_MASK = FIN|SYN|RST|ACK = 0x17`. `is_ack_only(0x18)` = `(0x18 & 0x17) == 0x10` → `0x10 != 0x10` → false (PSH+ACK not pure-ACK). But `is_ack_only(0x10)` = true → bare ACK IS flow-cache eligible (S-002). PSH+ACK (0x18) is NOT flow-cache eligible via `packet_eligible`, but still creates ESTABLISHED session via install path.

  `userspace-dp/src/afxdp/poll_descriptor/mod.rs:614-618` `strict_syn_check_drops_new_flow`:
  ```rust
  fn strict_syn_check_drops_new_flow(protocol: u8, tcp_flags: u8) -> bool {
      matches!(protocol, PROTO_TCP) && is_closing(tcp_flags) && !has_syn(tcp_flags)
  }
  ```
  PSH+ACK (0x18): `is_closing(0x18)` = `FIN|RST` = false → NOT dropped by strict-syn-check. Correct (PSH is not closing), but still creates ESTABLISHED session.

  `userspace-dp/src/afxdp/forwarding/mod.rs:1754-1758` `should_cache_local_delivery_session_on_miss`:
  ```rust
  if has_ack(tcp_flags) && !has_syn(tcp_flags) {
      return false; // bare ESTABLISHED ACK, no SYN — don't cache bare ACK
  }
  ```
  PSH+ACK (0x18): `has_ack(0x18) && !has_syn(0x18)` = true → false (don't cache for LocalDelivery). So LocalDelivery PSH+ACK is safe (no session cached, packet reinjected). But transit PSH+ACK still creates ESTABLISHED 300s session.

- **Trace**:

  Config: Same as S-002 (no limit-session). Attacker sends PSH+ACK (0x18) with data payload (or empty) as first packet from distinct (src_ip, src_port). Each: `is_initial_syn(0x18)` = false → `established=true` → 300s. Sustained to keep table full: same 436 pps as bare ACK. PSH+ACK with data looks like "mid-stream data segment" (the comment's intended ESTABLISHED case), but without a prior SYN it is unverified.

  What vSRX does: Junos `tcp-initial-timeout` would apply to any unverified half-open regardless of PSH. A PSH+ACK first packet without prior SYN is still half-open.

  Pure PSH (PSH=0x08, no ACK, no SYN): `is_initial_syn(0x08)` = `has_syn(0x08) && !has_ack(0x08)` = `false && true` = false → `established=true` → 300s! This is even more anomalous — pure PSH as first packet creating ESTABLISHED. And `strict_syn_check_drops_new_flow(0x08)` = `is_closing(0x08)` = false → not dropped. `should_cache_local_delivery_session_on_miss(0x08)`: `has_ack(0x08) && !has_syn(0x08)` = false → true (would cache LocalDelivery PSH — questionable but low impact since PSH-only is rare).

- **Refutation attempted**:
  - Checked if PSH+ACK with data is legitimate mid-stream pickup (asymmetric routing): YES, partially — the comment says "a TCP mid-stream pickup such as a SYN-ACK or data segment starts ESTABLISHED". PSH+ACK with data IS a data segment (data-bearing ACK), legitimate for mid-stream pickup. But bare PSH+ACK with no data (empty PSH+ACK) is not data — still gets 300s.
  - Checked if flow-cache `packet_eligible(PSH+ACK)` = `is_ack_only(0x18)` = false → NOT cacheable → PSH+ACK always goes slow-path → every PSH+ACK packet pays session lookup + GC overhead, but still gets 300s session. Not cacheable ≠ not session-creatable.
  - Checked if this is same root cause as S-002: YES, same `!(TCP && is_initial_syn)` gate — bare ACK and PSH+ACK both bypass OPENING via same predicate. The fix for S-002 (bare ACK → OPENING) should also handle PSH+ACK without data.
  - Checked all_findings.txt: no finding describes PSH-only or PSH+ACK first-packet ESTABLISHED DoS. S-002 is bare ACK only. This extends S-002 to PSH-bearing variants.

- **Why it matters**: Same DoS amplification class as S-002 (15× more efficient than SYN flood) but via PSH+ACK or pure PSH instead of bare ACK. An attacker blocked by a filter on bare ACK (ACK-only) could switch to PSH+ACK or pure PSH and get same 300s ESTABLISHED session. Pure PSH (0x08) as first packet is particularly anomalous — no ACK, no SYN, just PSH, yet gets ESTABLISHED 300s.

- **Fix direction**:
  - Same as S-002: any non-SYN first packet that has no data payload and no SYN-ACK should start OPENING (20s), not ESTABLISHED (300s). Distinguish data-bearing (with payload) PSH+ACK (legitimate mid-stream pickup, 300s OK) from empty PSH+ACK / bare ACK / pure PSH (unverified, 20s).
  - Minimal fix: `is_initial_syn` → `is_initial_syn_or_non_data_first_packet` — if first packet is TCP and not SYN and has no payload (pkt_len == headers), use OPENING. Requires pkt_len at install site (already available via `meta.pkt_len` in poll_descriptor).
  - Simpler: any TCP first packet that is not SYN-ACK and not data-bearing starts OPENING. `is_initial_syn` OR "first-packet bare ACK / pure PSH / empty PSH+ACK" → OPENING.
  - Add tests: install with PSH+ACK first packet (empty), assert OPENING (20s). Install with PSH+ACK + data, assert ESTABLISHED (300s, mid-stream pickup). Install with pure PSH (0x08), assert OPENING.

- **Labels**: `robustness-dos`, `session`, `tcp`, `vsrx-parity`, `s-002-extension`
- **Dedup note**: Not in /tmp/all_findings.txt. ps-review-020 S-002 covers bare ACK (0x10) only. This extends to PSH+ACK (0x18) empty and pure PSH (0x08) — same `is_initial_syn`-only gate, different flag combinations, same root cause but distinct attack vectors. The LocalDelivery gate (`ACK && !SYN`) also misses pure PSH (0x08 has no ACK). Not a duplicate — new flag combinations, same gate.

---

### [M-02] `should_cache_local_delivery_session_on_miss` allows pure PSH (PSH=0x08, no ACK, no SYN) to cache LocalDelivery session — inconsistent with bare-ACK decline and P6b RST/FIN decline

- **Title**: Pure PSH (0x08) caches LocalDelivery session — should be declined like bare ACK and RST/FIN
- **Severity**: Low (hardening / DoS surface)
- **Confidence**: High
- **Class**: implementation-bug / robustness-dos
- **Evidence**:

  `userspace-dp/src/afxdp/forwarding/mod.rs:1741-1789` `should_cache_local_delivery_session_on_miss`:
  ```rust
  pub(super) fn should_cache_local_delivery_session_on_miss(
      state: &ForwardingState,
      resolution_target: IpAddr,
      resolution: ForwardingResolution,
      protocol: u8,
      tcp_flags: u8,
  ) -> bool {
      if resolution.disposition != ForwardingDisposition::LocalDelivery {
          return false;
      }
      if !matches!(protocol, PROTO_TCP) {
          return true;
      }
      // #2151: prior inline `(tcp_flags & ACK) != 0 && (tcp_flags & SYN) == 0`
      // — do not cache a local-delivery session off a bare/established ACK
      if has_ack(tcp_flags) && !has_syn(tcp_flags) {
          return false;
      }
      // P6b: a bare TCP RST/FIN that MISSES must not seed a firewall-local session
      if is_closing(tcp_flags) && !has_syn(tcp_flags) {
          return false;
      }
      let _ = state;
      let _ = resolution_target;
      true
  }
  ```

  Pure PSH (0x08): `has_ack(0x08)` = false → first gate (ACK && !SYN) = false → passes. `is_closing(0x08)` = `FIN(0x01)|RST(0x04)` = false → second gate = false → passes. Returns true — caches LocalDelivery session for pure PSH.

  Compare:
  - Bare ACK (0x10): `has_ack && !has_syn` = true → false (don't cache) — correct per #2151.
  - Bare RST (0x04): `is_closing && !has_syn` = true → false (don't cache) — correct per #4487.
  - Pure PSH (0x08): both gates false → true (cache) — inconsistent.

- **Trace**:

  Config: Firewall with interface 10.0.0.1/24 in trust zone. Attacker on untrust sends TCP PSH=0x08 (no ACK, no SYN) to 10.0.0.1:22 (SSH). Packet is LocalDelivery (to-self). Session-miss → `should_cache_local_delivery_session_on_miss(TCP, 0x08)` = true → caches LocalDelivery session `{AF_INET, TCP, attacker_ip, 10.0.0.1, attacker_port, 22}` as ESTABLISHED 300s (via install path's `!(TCP && is_initial_syn)` — `is_initial_syn(0x08)` = false).

  Next packet: attacker sends TCP SYN to 10.0.0.1:22 from same src_ip:src_port (real SYN for SSH). Session hit — same 5-tuple already exists (PSH-seeded), but with `closing=false, established=true`. The new SYN would be evaluated against the existing session, not re-evaluated by host-inbound / junos-host gates (LocalDelivery session hit skips those gates on hit path). The SYN reuses the PSH-seeded session's permit, potentially bypassing a `to-zone junos-host deny tcp/22` that was added after the PSH seed.

  However, this is LOW severity because:
  - Pure PSH (0x08, no ACK) to a firewall IP is rare and anomalous — legitimate clients never send pure PSH as first packet.
  - The host-inbound gate runs on session HIT for LocalDelivery (it does re-check junos-host on every hit, see `poll_descriptor/mod.rs` host-inbound/junos-host re-eval on hit).
  - Practical exploitation requires precise timing and same 5-tuple control.

- **Refutation attempted**:
  - Checked if LocalDelivery session hit re-evaluates host-inbound / junos-host: YES — `poll_descriptor/mod.rs` session-hit LocalDelivery path DOES re-check host-inbound and junos-host on every hit (junos-host mandatory teardown re-check). So policy-skip is NOT exploitable via this path on b1bd96fb6. Verified.
  - Checked if this is same as S-002/S-003: different — this is LocalDelivery cache (host-bound), not transit. The transit S-002 is DoS via 300s ESTABLISHED; this is LocalDelivery session-table churn via pure PSH.
  - Checked if any test pins pure PSH LocalDelivery behavior: NO — tests cover bare ACK (decline), bare RST/FIN (decline), SYN (cache), SYN-ACK (cache), but not pure PSH.
  - This is LOW — the real risk is table churn (DoS) and inconsistent gating, not policy bypass.

- **Why it matters**: Inconsistent gating — pure PSH should be declined like bare ACK and RST/FIN for consistency. An attacker could use pure PSH (0x08) to churn LocalDelivery session table when bare ACK is blocked by a filter. The 300s ESTABLISHED timeout for pure PSH first packet (M-01) compounds this — each PSH seeds a 300s session.

- **Fix direction**:
  - Add `has_ack` check to the first gate OR add a catch-all "non-SYN first packet without ACK should not cache LocalDelivery" gate. Simplest: `if !has_syn(tcp_flags) && tcp_flags != 0` → false (no non-SYN TCP first packet should cache LocalDelivery except SYN-ACK which has SYN). Or explicitly: add `if tcp_flags == TCP_PSH` → false.
  - Or, more conservatively: any TCP first packet that is not SYN or SYN-ACK should not cache LocalDelivery (matches #2151 intent — only cache off handshake).
  - Add test: `should_cache_local_delivery_session_on_miss(TCP, 0x08)` → false.

- **Labels**: `hardening`, `session`, `local-delivery`, `tcp`, `dos`, `inconsistency`
- **Dedup note**: Not in /tmp/all_findings.txt. Not in ps-review-020. P6b (#4487) fixed RST/FIN decline, #2151 fixed bare ACK decline, but pure PSH (0x08) was never considered. This is a new flag combination not covered by either gate.

---

### [L-01] `established` is `bool` on SessionEntry but install-time `is_initial_syn` gate loses information about whether first packet was SYN-ACK (mid-stream pickup) vs pure data ACK — both start ESTABLISHED but have different handshake semantics

- **Title**: SessionEntry `established` bool conflates "SYN-ACK first packet" (mid-stream pickup, legitimate) with "bare ACK first packet" (unverified, should be shorter timeout) — both are `established=true`
- **Severity**: Low (hardening / vsrx-parity / observability)
- **Confidence**: Medium
- **Class**: implementation-bug / parity-gap / observability-lie
- **Evidence**:

  `userspace-dp/src/session/mod.rs:362-387`:
  ```rust
  established: bool,
  /// ... Set `true` once a handshake-completing segment is observed ...
  /// Initialised `true` for every non-TCP session and for any TCP session
  /// whose creating packet is NOT a bare SYN ...
  ```

  `userspace-dp/src/session/install.rs:158`:
  ```rust
  established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
  ```
  This is binary: either OPENING (bare SYN) or ESTABLISHED (everything else). There is no "MID_STREAM_PICKUP" state. Both SYN-ACK first packet (legitimate asymmetric routing, server-side SYN-ACK seen first) and bare ACK first packet (unverified, no handshake observed) become `established=true` with same 300s timeout, same telemetry, same `show security flow session` display.

  `userspace-dp/src/session/lookup.rs:146-149`:
  ```rust
  let promote_from_reverse = is_tcp && is_syn_ack(tcp_flags) && entry.metadata.is_reverse;
  ```
  Promotion requires reverse SYN-ACK — but if first packet was SYN-ACK forward (is_syn_ack but !is_reverse), it was already ESTABLISHED at install, never went through OPENING → ESTABLISHED promotion.

- **Trace**:

  Config: Asymmetric routing (common in dual-homed / ECMP / anycast). Flow: client SYN → server SYN-ACK → client ACK. xpf sees only the server's SYN-ACK (SYN+ACK=0x12) as first packet (client SYN went via different path). `is_initial_syn(0x12)` = `has_syn(0x12) && !has_ack(0x12)` = `true && false` = false → `established=true` → 300s. Correct — mid-stream pickup should be 300s.

  Attacker: sends bare ACK (0x10) as first packet from spoofed src. `is_initial_syn(0x10)` = false → `established=true` → 300s. Same 300s as legitimate mid-stream pickup, but no handshake proof.

  Both cases are `established=true`, indistinguishable in session table, telemetry, and `show` output. An operator investigating a DoS sees 131k "ESTABLISHED" sessions that look identical to legitimate mid-stream pickups.

- **Refutation attempted**:
  - Is this same as S-002? Partially — S-002 is the DoS aspect (bare ACK → 300s). This is the observability / state-conflation aspect: even if bare ACK DoS is mitigated (e.g., by shortening bare ACK timeout), the `established` bool still conflates two semantically different cases (verified handshake vs unverified mid-stream pickup).
  - Checked if any telemetry distinguishes SYN-ACK first packet from bare ACK first packet: NO — both are `established=true`, same timeout (`tcp_established_ns` 300s), same `observed_tcp_flags` accumulation (both seed with first packet's flags).
  - Checked if vSRX distinguishes: YES — Junos has `tcp-initial-timeout` for unverified / half-open sessions vs full `inactivity-timeout` for verified established. Bare ACK first packet would be "unverified" on vSRX.

- **Why it matters**: LOW severity — hardening / observability / DoS. The conflation makes bare ACK DoS harder to detect (looks like legitimate mid-stream pickup) and prevents targeted mitigation (cannot shorten bare ACK timeout without also shortening legitimate SYN-ACK mid-stream pickup timeout).

- **Fix direction**:
  - Introduce tri-state `TcpHandshakeState { Opening, Established, MidStreamPickup }` or at least `MidStreamPickup` bool separate from `established`. Bare ACK / pure PSH / empty PSH+ACK first packet → `Opening` (20s). SYN-ACK first packet / data-bearing ACK first packet → `MidStreamPickup` (e.g., 60s or 300s, operator-configurable). Real 3-way handshake (SYN → reverse SYN-ACK → forward ACK) → `Established` (300s).
  - Or, simpler: any non-SYN first packet that is not SYN-ACK starts with a shorter "unverified" timeout (e.g., 60s), not the full 300s. Only SYN-ACK first packet and verified handshake get 300s.
  - Add observability: `show security flow session` should distinguish "OPENING / ESTABLISHED / MID-STREAM-PICKUP" in the session state column.

- **Labels**: `hardening`, `session`, `tcp`, `observability`, `vsrx-parity`, `s-002-related`
- **Dedup note**: Not in /tmp/all_findings.txt. Extends S-002 (DoS) to observability / state-model gap. S-002 is the DoS timeout issue; this is the state-conflation issue that makes S-002 harder to detect and fix without regressing mid-stream pickup.

---

## 7. Negative results (verified fail-closed / not exploitable on b1bd96fb6)

### N-01: S-004 per-worker session-limit bypass — NOT a bypass (intentional)

- **Path**: `session/mod.rs:776-863` per-worker SessionTable, `session/install.rs:214-221` per-IP count, `poll_descriptor/mod.rs:560-582` enforcement. `docs/feature-gaps.md:315` documents "Per-worker cap (#2186): effective cap ≈ N × configured, Size configured value as per-worker ceiling."
- **Verification**: The per-worker multiplier is a documented intentional divergence from vSRX global cap. Global cap would require cross-worker atomics, violating #1855 single-writer contract. All per-worker dataplane state has same multiplier — consistent. Not a bypass — attacker cannot exceed `N × configured` per IP without controlling RSS distribution. If attacker controls RSS, they obey that worker's limit.
- **Attack attempted**: Attacker with 1000 src IPs, each with limit 100, on 6-worker system — effective 600 per IP, 600k total, but still bounded. Not unbounded bypass.

### N-02: S-005 spoofed reverse SYN-ACK — NOT exploitable (F16 fix correct)

- **Path**: `session/lookup.rs:146-149` `promote_from_reverse = is_tcp && is_syn_ack(flags) && is_reverse`. Promotion requires BOTH SYN+ACK AND reverse direction. Forward SYN-ACK → `is_reverse=false` → no promotion (stays OPENING 20s). Bare reverse ACK → `is_syn_ack(ACK=0x10)` = false → no promotion. Tests pin.
- **Verification**: Off-path attacker cannot inject reverse traffic without controlling reverse path. If attacker controls reverse path, they already have stronger position. F16 fix is correct.
- **Attack attempted**: Attacker sends forward SYN-ACK (SYN+ACK, !reverse) → no promotion. Attacker spoofs reverse bare ACK → `is_syn_ack` false → no promotion. Both blocked.

### N-03: Cross-worker session-table race — NOT exploitable (per-worker single-writer)

- **Path**: `session/mod.rs:1616-1689` `remove_entry` + `install.rs:140-248` install are per-worker, single-writer (&mut self), no cross-worker sharing for the primary index. Cross-worker sync via `SharedSessionRefs` (shared session maps) + worker commands (MPSC), not direct table mutation.
- **Verification**: No TOCTOU between `can_admit` preflight and `install_with_protocol_with_origin` — both under `&mut self`, single-threaded per worker. The `can_admit` → install path is atomic from the worker's perspective. Correct per #1855.

### N-04: NAT index 1:N collision — VERIFIED FIXED (no session hijack / mis-delivery)

- **Path**: `session/mod.rs:1936-1984` `nat_index_bucket_push` dedup / `nat_index_bucket_remove` per-handle, `SmallVec<[u32;2]>` N=2. `session/lookup.rs:215-314` bucket walks with validate-on-lookup. Fixed #4399/#4438.
- **Verification**: Single-value map displacement bug is gone. Two sessions colliding on same reverse / forward-wire / translated key both kept, lookup validates full tuple. No hijack.

### N-05: TCP `closing` / `reset` / `established` — STICKY, VERIFIED

- **Path**: `session/lookup.rs:123-148` `closing=true`, `reset |= has_rst`, `established |= is_syn_ack && is_reverse` — all sticky, never cleared. `session/mod.rs:1275-1300` `update_session` mirrors: `closing |=`, `reset |=`, `established |=`. #3489 + #3046 + #4109 F16. Correct.

### N-06: Bare SYN → OPENING (20s), not ESTABLISHED — VERIFIED

- **Path**: `session/install.rs:158` `is_initial_syn` gate + `session/tests.rs:1582-1680` `forward_ack_without_reverse_synack_stays_opening` + `reverse_bare_ack_does_not_promote_opening`. SYN flood bounded at 20s. Correct.

### N-07: Flow-cache TCP state — VERIFIED PASS

- **Path**: `flow_cache.rs:290-295` `packet_eligible` excludes FIN/RST/SYN (only pure-ACK + UDP cacheable). `should_cache` folds `packet_eligible` (#2363). Close-state segments always slow-path. Correct.

---

## 8. Suggested issue split

### P0 (fail-open, ship-blocker — CONFIRMED still present, not new)
1. **[C-01] S-001 CONFIRMED**: Cross-zone / cross-VRF session hijack via bare 5-tuple — include zone/VRF in SessionKey or validate ingress_zone on hit — VERIFIED STILL PRESENT on b1bd96fb6 (already filed ps-review-020 S-001)

### P1 (DoS hardening — CONFIRMED still present + new extension)
2. **[C-02] S-002 CONFIRMED**: Bare ACK first-packet ESTABLISHED (300s) DoS amplification — use OPENING (20s) for bare-ACK first packet — VERIFIED STILL PRESENT (already filed ps-review-020 S-002)
3. **[M-01] NEW**: PSH+ACK (0x18) empty and pure PSH (0x08) first-packet ESTABLISHED (300s) — same class as bare ACK DoS, different flag combinations — 15× amplification, bypasses bare-ACK-only filter

### P2 (hardening / fix gaps)
4. **[M-02] NEW**: Pure PSH (0x08) caches LocalDelivery session — inconsistent with bare-ACK decline and P6b RST/FIN decline — should be declined
5. **[L-01] NEW**: `established` bool conflates SYN-ACK mid-stream pickup (legitimate) with bare ACK / pure PSH first packet (unverified) — observability lie + prevents targeted DoS mitigation

### P3 (verified fixed / not-bugs — no action)
6. **[C-03] P6 VERIFIED FIXED**: RST/FIN creates session — all three sub-paths fixed on b1bd96fb6
7. **[C-04] P7 VERIFIED FIXED**: Fabric NAT skip — fixed on b1bd96fb6
8. **[N-01] S-004 NOT A BUG**: Per-worker session-limit multiplier — intentional, documented (#2186)
9. **[N-02] S-005 NOT EXPLOITABLE**: Spoofed reverse SYN-ACK — NOT exploitable (F16 fix correct)

---

*End of Cohort 6 audit — ps-review-029 — 2026-07-07 — master b1bd96fb6 (same as ps-review-020 base c2ee227c4)*
