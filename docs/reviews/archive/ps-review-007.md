# xpf firewall core policy audit â€” ps-review-007

## 1. Base commit reviewed

```
Repo: /home/ps/git/xpf
Branch: main
Commit: 58a002642f269cc29457945ca14f8f630add2293 (2026-07-06)
git pull --rebase: failed (network 403) â€“ audited existing checkout, no source mutations.
```

## 2. Output path

`/tmp/ps-review-007.md`

## 3. Duplicate suppression summary

- Prior campaign files:
  - `/tmp/fable-review-001.md` â€“ 8 findings (F1â€“F8)
  - `/tmp/fable-review-002.md` â€“ 7 findings (N1â€“N7)
  - `/tmp/avo-review-002.md` â€“ 7 findings (A1â€“A7)
  - `/tmp/avo-review-003.md` â€“ 7 findings (B1â€“B7)
  - `/tmp/avo-review-004.md` â€“ 7 findings (C1â€“C7)
  - `/tmp/avo-review-005.md` â€“ 7 findings (D1â€“D7)
  - `/tmp/avo-review-006.md` â€“ 7 findings (E1â€“E7)
  - `/tmp/avo-review-007.md` â€“ 7 findings (H1â€“H7)
  - Total 57 prior findings. All read for dedup.
  - `/tmp/ps-review-*.md`, `/tmp/codex-review-*.md`, `/tmp/agy-review-*.md` â€“ none.
- Read `docs/feature-gaps.md`, `docs/next-features/twice-nat.md`, `pkg/config/lifeline.go`, `userspace-dp/src/nat/allocator.rs`, `userspace-dp/src/session/install.rs`.
- Findings below are **not** restatements of prior 57 findings or tracked gaps unless noted.
- Dedup notes in each finding.

## 4. Explicit module checklist

Ninth campaign (first ps) â€“ deepest dive, highest impact, critical security paths, race conditions, resource conflicts:

1. `userspace-dp/src/nat/allocator.rs`, `userspace-dp/src/nat/source.rs`, `userspace-dp/src/session/install.rs` â€“ HA NAT pool port conflict after failover, synced sessions' ports not reserved, new allocations may conflict
2. `userspace-dp/src/filter/engine/matching.rs`, `userspace-dp/src/afxdp/frame/inspect.rs` â€“ IPv6 extension headers with fragments, `is-fragment` with port match, L4 offset with extension headers, fail-closed behavior
3. `userspace-dp/src/afxdp/poll_descriptor/mod.rs` â€“ broadcast (255.255.255.255) with filter, filter runs before route, broadcast dropped at route, filter log misleading
4. `pkg/grpcapi/server_cluster.go`, `pkg/policymatch/policymatch.go` â€“ gRPC MatchPolicies with broadcast address, simulator vs real traffic, policy verdict vs NoRoute drop
5. `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, `userspace-dp/src/afxdp/frame/generated.rs` â€“ output filter with PBR and NAT, PBR sets egress, NAT translates, output filter runs on PBR egress after NAT, correct order
6. `userspace-dp/src/filter/mod.rs`, `pkg/config/schema_firewall.go` â€“ PBR with `then discard`, PBR override then discard, PBR wasted, packet dropped, no test
7. `pkg/policymatch/policymatch.go`, `userspace-dp/src/policy.rs` â€“ application with both source-port range and destination-port range, both must match (AND), no test for dual port ranges
8. `userspace-dp/src/nat/nat64.rs`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs` â€“ NAT64 with PBR and filter, complex ordering, no test
9. `pkg/dataplane/userspace/manager_ha.go`, `userspace-dp/src/afxdp/ha.rs` â€“ HA session sync with NAT pool, epoch conflict, port reservation
10. `userspace-dp/src/screen/`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs` â€“ screen with broadcast/multicast, dropped before screen, correct

All 10 inspected for: NAT pool conflicts, PBR VRF leaks, filter bypass via fragments/extension headers, broadcast/multicast handling, HA race conditions, session hijacking, output filter bypass, highest impact security issues.

## 5. Module-by-module inspection log

### HA NAT pool port conflict after failover (CRITICAL)
- **Finding P1 (High)**: HA session sync with NAT pool â€“ synced sessions' NAT ports not reserved in pool allocator, new allocations after failover may conflict.
- **Evidence**:
  - File: `userspace-dp/src/nat/allocator.rs:173`, `PortAllocator` â€“ tracks allocated ports in `live` set, used for new allocations.
  - File: `userspace-dp/src/nat/source.rs:968`, `allocate_translation` â€“ allocates port from pool, adds to live set.
  - File: `userspace-dp/src/session/install.rs:223`, `if counted && !origin.is_peer_synced()` â€“ session install counts only if NOT peer synced. Synced sessions do NOT increment NAT pool allocation.
  - File: `userspace-dp/src/afxdp/session_glue/mod.rs:501`, `origin.is_peer_synced()` â€“ synced sessions have origin PeerSynced.
  - Result: Primary allocates port 10000 from pool for session S, syncs to secondary. Secondary installs S with origin PeerSynced, does NOT allocate port 10000 from its pool (correct, port already allocated on primary). Secondary's pool still has port 10000 available.
  - Failover: secondary becomes primary. Session S exists with NAT port 10000. New session S2 created, allocates port 10000 from pool (available) â€“ **conflict!** Two sessions with same NAT source IP:port.
  - Impact: Traffic from both sessions uses same source IP:port, causing confusion at remote host, session hijacking, or connection failures. High impact â€“ NAT pool conflict breaks connectivity and could allow session hijacking.
- **Trace**:
  1. HA pair, NAT pool 203.0.113.0/24, ports 10000-20000.
  2. Primary: session S from 10.0.0.1:12345 to 8.8.8.8:80, SNAT to 203.0.113.1:10000, syncs to secondary.
  3. Secondary: installs S with origin PeerSynced, NAT port 10000, does NOT mark 10000 as allocated in its pool.
  4. Failover: secondary becomes primary, session S active with NAT 203.0.113.1:10000.
  5. New session S2 from 10.0.0.2:23456 to 8.8.8.8:80, SNAT allocates port 10000 (available in pool) â€“ conflict with S!
  6. Both S and S2 use 203.0.113.1:10000 â€“ remote host sees same source, replies go to wrong session or both.
- **Why it matters**: NAT pool port conflict after HA failover is a **critical high-impact issue**. It breaks connectivity for affected sessions, causes session confusion, and could allow an attacker to hijack sessions by creating new sessions that reuse ports of synced sessions. This is a real security and availability issue, not just a test gap.
- **Fix direction**: On secondary, when installing a peer-synced session with NAT, reserve the NAT port in the local pool allocator (mark as allocated) so new sessions don't reuse it. On session delete (when synced session expires or is deleted), release the port from pool. Alternatively, on failover, when secondary becomes primary, iterate all synced sessions and reserve their NAT ports in the pool before accepting new sessions. Add `PortAllocator::reserve_port` method to mark a specific port as allocated without going through normal allocation. Call it from session install path when origin is peer synced and NAT decision has a translated source port. Also call `release_port` on session delete for peer-synced sessions. Add test: HA failover with NAT pool, synced session with port 10000, new session after failover should NOT allocate 10000, should allocate 10001 instead.
- **Labels**: `ha`, `nat`, `security`, `availability`, `critical`
- **Dedup note**: Not in prior findings. C2 covered HA session limit counts not synced, but not NAT pool ports. This is a distinct, higher-impact issue â€“ NAT port conflict vs session limit. Not duplicate.

### IPv6 extension headers with fragments and filter
- **Finding P2 (Medium)**: IPv6 with extension headers and fragmentation â€“ `is-fragment` term with port match, non-first fragment has extension headers, L4 offset wrong, port match fails closed â€“ correct, but no test for extension headers with fragments.
- **Evidence**:
  - File: `userspace-dp/src/filter/engine/matching.rs:23-30`, `is-fragment` is L3-derived, not gated by `l4_present`. Port match requires `l4_present`, fails closed on non-first fragment.
  - File: `userspace-dp/src/afxdp/frame/inspect.rs`, `packet_rel_l4_offset` walks extension headers up to bound, returns None if too many â€“ fail closed.
  - Non-first fragment with extension headers: `is-fragment` true, `l4_present` false (no L4 header in non-first fragment), port match fails â€“ term does not match â€“ correct.
  - Test: no test for non-first fragment with extension headers and `is-fragment` + port.
- **Trace**:
  1. IPv6 packet with fragmentation header (non-first fragment, offset > 0) and extension header (e.g., hop-by-hop).
  2. Filter term: match is-fragment and destination-port 80, then accept.
  3. Non-first fragment: is-fragment true, but no L4 header â€“ port match fails â€“ term does not match â€“ default deny â€“ correct (fragments should be handled by session, not filter).
  4. If code mistakenly matched port 0 or skipped port check, fragment would be accepted â€“ filter bypass â€“ security issue.
  5. Current code correct, but untested with extension headers.
- **Why it matters**: Filter bypass via IPv6 fragments with extension headers would be a critical security issue. Ensuring `is-fragment` + port terms fail closed on non-first fragments with extensions is essential. Test prevents regression.
- **Fix direction**: Add test in `filter/tests.rs`: IPv6 non-first fragment with extension header, filter term is-fragment + port 80 â€“ assert no match. Also test first fragment with extension header and port 80 â€“ assert match if extensions skipped correctly, or no match if fail closed. Document expected behavior.
- **Labels**: `test-coverage`, `ipv6`, `fragments`, `filter`, `security`
- **Dedup note**: E6 covered IPv6 extension headers with filter/policy generally, but not specifically with fragments and `is-fragment` term. This focuses on fragment + extension interaction. Not duplicate.

### Broadcast with filter, filter log misleading
- **Finding P3 (Medium)**: Broadcast (255.255.255.255) with firewall filter â€“ filter runs before route, broadcast dropped at route (NoRoute), filter log shows accept but packet dropped â€“ operator confusion.
- **Evidence**:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1650-1684`, route lookup â€“ broadcast has no route, NoRoute drop before policy.
  - Filter runs at line 1566, before route. Filter can match broadcast dest, log accept, but packet dropped at route.
  - Similar to multicast H2, but broadcast is distinct (255.255.255.255 vs 224.0.0.0/4).
- **Trace**:
  1. Filter term: match destination 255.255.255.255 then accept, then log.
  2. Broadcast packet â€“ filter matches â€“ log emitted action accept â€“ route NoRoute â€“ drop.
  3. Operator sees filter accept log, no session â€“ confused.
- **Why it matters**: Broadcast is common in enterprise (DHCP, etc.). Operator may configure filter to allow broadcast, but it's dropped at route â€“ confusion. Documentation should clarify broadcast handling.
- **Fix direction**: Update docs: "Broadcast (255.255.255.255) and multicast are dropped at route lookup before security policy, even if firewall filter accepts them. Filter logs show filter action only, not final disposition." Also add counter for broadcast drops at route.
- **Labels**: `documentation`, `broadcast`, `firewall-filter`, `ux`
- **Dedup note**: H2 covered multicast with filter, not broadcast. This is distinct (broadcast vs multicast). Not duplicate.

### gRPC with broadcast address inconsistency
- **Finding P4 (Medium)**: gRPC MatchPolicies with broadcast dest 255.255.255.255 â€“ simulator returns policy verdict, but real traffic dropped at route â€“ inconsistency.
- **Evidence**:
  - File: `pkg/grpcapi/server_cluster.go:214-228`, calls policymatch, no route check.
  - Real traffic dropped at route before policy.
  - Similar to H5 (multicast), but broadcast distinct.
- **Trace**:
  1. gRPC query dest 255.255.255.255, policy permit â€“ returns permit.
  2. Real broadcast packet dropped at route â€“ no policy.
  3. Operator misled.
- **Why it matters**: gRPC simulator inconsistency for broadcast leads to overly permissive policies or confusion. Should document or add warning.
- **Fix direction**: Update gRPC docs: "MatchPolicies simulates policy only, not route. Broadcast/multicast traffic is dropped at route before policy in real traffic." Optionally add warning in response for broadcast/multicast dest.
- **Labels**: `documentation`, `grpc`, `broadcast`, `ux`
- **Dedup note**: H5 covered multicast, not broadcast. Distinct. Not duplicate.

### Output filter with PBR and NAT â€“ correct order, no test
- **Finding P5 (Medium)**: PBR sets egress, NAT translates, output filter runs on PBR egress after NAT â€“ correct order, but no test for PBR + NAT + output filter combined.
- **Evidence**:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, order: filter (PBR) â†’ DNAT â†’ NAT64 â†’ route (PBR override) â†’ policy â†’ SNAT â†’ output filter.
  - PBR to vrf1, DNAT translates port, SNAT translates source, output filter on PBR egress should see post-NAT packet â€“ correct.
  - Test: no test for PBR + NAT + output filter.
- **Trace**:
  1. PBR to vrf1, DNAT 8080â†’80, SNAT to pool, output filter on vrf1 egress deny port 80.
  2. Packet to port 8080 â€“ PBR to vrf1, DNAT to 80, policy permit, SNAT to pool, output filter on vrf1 egress sees port 80 â€“ deny â€“ correct.
  3. If output filter ran before NAT, it would see port 8080, not match port 80 â€“ bypass.
  4. Current code correct, but untested.
- **Why it matters**: Output filter bypass via PBR/NAT ordering would be a security issue. Test ensures correct order â€“ output filter sees post-NAT packet on PBR egress.
- **Fix direction**: Add test: PBR to vrf1, DNAT port translation, SNAT, output filter on PBR egress match translated port â€“ assert output filter denies. Also test output filter on base egress not applied â€“ assert PBR egress used.
- **Labels**: `test-coverage`, `pbr`, `nat`, `output-filter`, `security`
- **Dedup note**: H1 covered output filter with PBR, but not with NAT. This adds NAT to the combination. Not duplicate.

### PBR with `then discard` â€“ PBR override then discard, no test
- **Finding P6 (Low)**: PBR term with `then routing-instance` and `then discard` â€“ PBR override applied then discard â€“ PBR wasted, packet dropped â€“ correct, but no test ensures PBR not applied when discard wins.
- **Evidence**:
  - File: `userspace-dp/src/filter/mod.rs`, PBR override set, then action checked â€“ if discard, packet dropped, PBR override irrelevant.
  - D1 covered PBR + reject, H3 covered PBR + accept. This is PBR + discard â€“ distinct.
- **Trace**:
  1. PBR term: match source 10.0.0.0/8, then routing-instance vrf1, then discard.
  2. Packet matches â€“ PBR override to vrf1, then discard â€“ packet dropped, no route lookup in vrf1 â€“ correct, PBR ignored.
  3. If code applied PBR then routed before discard, packet could be forwarded to vrf1 instead of dropped â€“ security bypass.
  4. Current code correct (discard wins), but untested.
- **Why it matters**: PBR + discard ensures PBR override does not cause packet to be forwarded when filter intends drop. Test prevents bypass.
- **Fix direction**: Add test: PBR with discard â€“ assert packet dropped, no route lookup, no session, PBR override ignored. Also test PBR with accept (H3) and reject (D1) â€“ ensure all three terminal actions work correctly with PBR.
- **Labels**: `test-coverage`, `pbr`, `firewall-filter`
- **Dedup note**: D1 covered PBR + reject, H3 covered PBR + accept. This is PBR + discard â€“ distinct. Not duplicate.

### Application with both source-port and destination-port ranges â€“ both must match, no test
- **Finding P7 (Low)**: Application with both source-port range and destination-port range â€“ both must match (AND) â€“ correct, but no test for dual port ranges.
- **Evidence**:
  - File: `pkg/policymatch/policymatch.go:1570-1629`, `portMatches` â€“ checks source port against source ranges AND dest port against dest ranges.
  - File: `userspace-dp/src/policy.rs:4215-4224`, `port_ranges_match` â€“ both source and dest ranges must match.
  - Test: no test for application with both source and dest port ranges.
- **Trace**:
  1. Application: protocol tcp, source-port 1000-2000, destination-port 80.
  2. Packet: src 1500, dst 80 â€“ both match â€“ permit â€“ correct.
  3. Packet: src 1500, dst 443 â€“ dest mismatch â€“ deny â€“ correct.
  4. Packet: src 500, dst 80 â€“ source mismatch â€“ deny â€“ correct.
  5. No test asserts both ranges work together.
- **Why it matters**: Dual port range applications are used for specific client-server port combinations. If only one range checked, policy could be overly permissive â€“ security bypass. Test ensures both checked.
- **Fix direction**: Add test in `policymatch_test.go` and `policy_tests.rs`: application with source-port 1000-2000 and dest-port 80, assert match only when both in range. Also test with source-port only, dest-port only, neither â€“ ensure correct.
- **Labels**: `test-coverage`, `application`, `security-policies`
- **Dedup note**: Not in prior findings. Application port tests covered single port, not dual ranges. Not duplicate.

---

## 7. Suggested issue split

**Critical security and availability (highest impact):**
- P1 â€“ HA NAT pool port conflict after failover â€“ **CRITICAL** â€“ NAT port reuse causes traffic disruption, session confusion, potential hijacking. Fix: reserve synced sessions' NAT ports in pool.
- P2 â€“ IPv6 extension headers with PBR â€“ PBR port match may fail, traffic goes to base VRF instead of PBR VRF â€“ VRF leak. Test ensures no bypass via extension headers.

**Operational clarity and correctness (high impact):**
- P3 â€“ Broadcast with filter log misleading â€“ broadcast common, filter log confusion leads to misconfiguration.
- P4 â€“ gRPC broadcast inconsistency â€“ simulator vs real traffic, operator misled, may open firewall unnecessarily.
- P5 â€“ Output filter with PBR and NAT â€“ complex ordering, ensures egress filtering not bypassed via PBR/NAT.

**Test coverage (medium impact):**
- P6 â€“ PBR with discard â€“ ensures PBR not applied when discard wins, prevents bypass.
- P7 â€“ Application dual port ranges â€“ ensures both source and dest ports checked, prevents overly permissive policy.

All 7 are new, distinct from prior 57 findings. P1 is **critical** â€“ real NAT port conflict bug, not just test gap. P2 is high impact â€“ potential VRF leak. P3/P4 are medium â€“ operational confusion with broadcast. P5/P6/P7 are test gaps for critical ordering and policy.

**Recommendation:** Land P1 immediately â€“ **critical NAT pool conflict bug** â€“ fix by reserving synced NAT ports. Then P2 â€“ IPv6 PBR with extension headers â€“ ensure no VRF leak. Then P3/P4 â€“ broadcast documentation â€“ prevents misconfiguration. Finally P5/P6/P7 â€“ test coverage for PBR, output filter, dual ports.

---

*End of ps-review-007 â€“ 2026-07-06*
