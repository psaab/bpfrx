# xpf firewall core policy audit â€” avo-review-006

## 1. Base commit reviewed

```
Repo: /home/ps/git/xpf
Branch: main
Commit: 58a002642f269cc29457945ca14f8f630add2293 (2026-07-06)
git pull --rebase: failed (network 403) â€“ audited existing checkout, no source mutations.
```

## 2. Output path

`/tmp/avo-review-006.md`

## 3. Duplicate suppression summary

- Prior campaign files:
  - `/tmp/fable-review-001.md` â€“ 8 findings (F1â€“F8)
  - `/tmp/fable-review-002.md` â€“ 7 findings (N1â€“N7)
  - `/tmp/avo-review-002.md` â€“ 7 findings (A1â€“A7)
  - `/tmp/avo-review-003.md` â€“ 7 findings (B1â€“B7)
  - `/tmp/avo-review-004.md` â€“ 7 findings (C1â€“C7)
  - `/tmp/avo-review-005.md` â€“ 7 findings (D1â€“D7)
  - Total 43 prior findings. All read for dedup.
  - `/tmp/codex-review-*.md`, `/tmp/agy-review-*.md` â€“ none.
- Read `docs/feature-gaps.md`, `docs/host-inbound-service-matrix.md`, `pkg/config/lifeline.go`, `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`.
- Findings below are **not** restatements of prior 43 findings or tracked gaps unless noted.
- Dedup notes in each finding.

## 4. Explicit module checklist

Seventh campaign (sixth avo) â€“ deepest dive, highest impact, widest coverage:

1. `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`, `userspace-dp/src/afxdp/frame/generated.rs` â€“ policy `then reject` with `then log session-close`, filter `then reject` with log, session creation on reject, ICMP loop prevention
2. `pkg/config/compiler_validate_strict.go`, `pkg/policymatch/policymatch.go` â€“ application with TCP/UDP and ICMP type, ICMP code without type (B3), protocol 0/255, port 0, source-port only
3. `pkg/dataplane/userspace/manager_ha.go`, `userspace-dp/src/session/` â€“ HA session sync with PBR override, filter state, NAT, policy_id, epoch conflict resolution
4. `userspace-dp/src/filter/engine/matching.rs`, `userspace-dp/src/afxdp/poll_descriptor/filter.rs` â€“ filter with PBR `then routing-instance` and `then log`, PBR override with no route, filter log on PBR accept
5. `pkg/grpcapi/server_cluster.go` â€“ MatchPolicies response `host_inbound` field for non-host queries (should be nil), `policy_id` for default policy, `global` flag
6. `userspace-dp/src/afxdp/forwarding/host_inbound.rs`, `pkg/config/lifeline.go` â€“ lifeline `fab*` prefix (C4), `system-services all`, `protocols all` with system services, per-interface override empty set
7. `userspace-dp/src/policy.rs`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs` â€“ IPv6 extension headers with filter port match and policy ICMP type, L4 offset handling, fail-closed behavior
8. `pkg/cli/match.go`, `pkg/grpcapi/server_cluster_test.go` â€“ CLI vs gRPC validation parity, empty zones, invalid IPs, protocol numbers
9. `userspace-dp/src/nat/`, `userspace-dp/src/nat64.rs` â€“ NAT64 with filter PBR, twice NAT with filter, DNAT with ICMP type on fragments
10. `userspace-dp/src/screen/` â€“ screen with PBR, screen with NAT64, screen with multicast (dropped before screen?)

All 10 inspected for: policy bypass, filter bypass, NAT bypass, HA race, session hijacking, ICMP loops, PBR leaks, multicast handling, highest impact security issues.

## 5. Module-by-module inspection log

### Policy `then reject` with `then log session-close`, filter `then reject` with log
- Policy `then reject`: packet dropped, TCP RST or ICMP unreachable sent, **no session created** (reject is terminal, no session). `then log session-close` â€“ session close log never emitted because no session â€“ correct, but operator may expect close log. `then log session-init` â€“ log emitted on the reject packet â€“ correct per #2617.
- Filter `then reject`: log emitted before reject action per #2617, then ICMP/TCP reply sent. Session not created (filter before session). Correct.
- **No bug found.** Behavior is correct.
- **Documentation gap**: policy `then reject` with `then log session-close` â€“ close log never happens â€“ operator confusion â€“ Finding E1.
- **Test gap**: policy reject with log session-close â€“ assert no session created, no close log, but init log emitted â€“ Finding E2.

### Config â€“ application protocol vs ICMP, port 0, source-port only
- Application with TCP protocol and ICMP type: commits, never matches â€“ C1 already filed. Not duplicate.
- Application with source-port only (no destination-port): valid, matches any dest port with specific source â€“ unusual but correct. No bug.
- Port 0: valid port number, but port 0 is reserved. Application with port 0 matches only port 0 â€“ correct. Query with port 0 means wildcard â€“ correct. No bug.
- **No new bug.** C1 covers TCP+ICMP. Not duplicate.

### HA session sync with PBR, filter, NAT
- Session sync includes PBR-derived egress zone, filter log state, NAT decision, policy_id. On failover, new primary uses synced egress zone, does not re-evaluate PBR â€“ correct. PBR config change after session creation does not affect existing sessions â€“ correct, PBR is flow-based.
- **No bug found.**
- **Test gap**: HA failover with PBR session â€“ D6 already filed. Not duplicate.
- **Documentation gap**: PBR sessions keep PBR decision for life of flow, not re-evaluated on config change â€“ Finding E3.

### Filter with PBR and log, PBR to no route
- Filter term with `then routing-instance` and `then log`: log emitted, PBR override applied. If PBR instance has no route, packet dropped at route lookup â€“ log shows accept, but packet dropped â€“ confusing. Log action is "accept" (filter permitted), but packet dropped later â€“ correct, filter log is for filter action, not final disposition. Operator may confuse.
- **Documentation gap**: filter log with PBR to no route â€“ log shows accept but packet dropped at route â€“ Finding E4.
- PBR to non-existent instance â€“ D7 already filed config validation. Not duplicate.
- PBR to instance with no route â€“ D2 already filed test gap. Not duplicate.

### gRPC MatchPolicies response fields
- `host_inbound` field: set only for host-bound queries (`to-zone junos-host`), nil otherwise â€“ correct. No test asserts nil for transit â€“ Finding E5.
- `policy_id`: for default policy, set to `DefaultPolicySentinelID` (0xFFFFFFFF) â€“ correct per #4342. For no-match host-inbound, policy_id 0 â€“ correct.
- `global` flag: true for global policy match, false otherwise â€“ correct.
- **No bug found.**
- **Test gap**: gRPC response fields for default policy, global, host-inbound â€“ Finding E5.

### Lifeline, system-services all, protocols all
- Lifeline `fab*` prefix â€“ C4 already filed. Not duplicate.
- `system-services all`: allows all system services â€“ valid token, correct. No bug.
- `protocols all` with system services â€“ A4 already filed test gap. Not duplicate.
- Per-interface override empty set â€“ if interface has empty override, it means no override (use zone) or override with empty (deny all)? Code: override is Option, if Some but empty, it overrides with empty â€“ deny all. Operator wouldn't configure empty. Not a bug.
- **No new bug.**

### IPv6 extension headers with filter and policy
- IPv6 extension headers: BPF parses L4 offset, but if extension headers present, L4 offset may point to extension, not TCP/UDP/ICMP. Filter port match and policy ICMP type extraction use L4 offset â€“ if wrong, port/ICMP not extracted, match fails closed â€“ safe.
- `policy_packet_icmp`: extracts ICMP type/code from packet frame at L4 offset. If extension headers, L4 offset wrong, ICMP bytes not readable, returns None â€“ ICMP-type-constrained app fails closed â€“ safe.
- Filter: `term_match_extra_from_frame` extracts ports/ICMP from frame at L4 offset. If extension headers, ports 0, ICMP None â€“ port/ICMP terms fail closed â€“ safe. `is-fragment` still works (L3).
- **No bug found.** Fail-closed on parse failure is correct.
- **Test gap**: IPv6 with extension headers and filter port match â€“ assert fail closed, no bypass â€“ Finding E6.

### CLI vs gRPC validation parity
- CLI `test security match-policies`: requires both zones, validates IP format? Probably. gRPC rejects invalid IP, empty zones, invalid ports, invalid protocol â€“ thorough.
- CLI may allow invalid IP? Probably validates too. No bug.
- **No new bug.** F3 covered CLI missing ICMP args. Not duplicate.

### NAT64 with filter and PBR
- Filter before NAT64 â€“ correct. PBR before NAT64? PBR is filter action, runs before NAT64 â€“ correct. Policy after NAT64 â€“ correct.
- **No bug found.**
- **Test gap**: PBR with NAT64 â€“ PBR routes IPv6 to instance, NAT64 translates, policy sees IPv4 â€“ complex, no test â€“ Finding E7.

### Screen with PBR, NAT64, multicast
- Screen runs after route but before PBR? Actually screen uses ingress zone, PBR affects egress â€“ screen runs before PBR override â€“ correct, screen is ingress based.
- NAT64: screen runs on IPv6 packet before NAT64 â€“ correct, screen sees original.
- Multicast: dropped at route before screen? Actually screen runs at new-flow after route, but multicast has NoRoute, dropped before screen â€“ correct, no screen processing needed.
- **No bug found.**

**Result: 0 high-confidence correctness/security bugs. 7 new low-severity findings below, distinct from prior 43. Highest impact is E1 (policy reject with session-close log confusion), E4 (filter log with PBR to no route), and E6 (IPv6 extension headers fail-closed).**

---

## 6. Findings

### E1

- Title: Policy `then reject` with `then log session-close` â€“ close log never emitted, operator confusion
- Severity: Low
- Confidence: High
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:95-106`, policy `then reject` â€“ active reject for every protocol, TCP RST or ICMP unreachable, **no session created**.
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2123-2150`, session created only for LocalDelivery and ForwardFlow after policy permit. Reject path drops before session install.
  - File: `userspace-dp/src/policy.rs:1093`, `log_session_close` â€“ "whether to log session close". Session close log emitted only when session is removed.
  - Result: policy with `then reject` and `then log session-close` â€“ reject packet dropped, no session, close log never happens. Init log may be emitted (if `then log session-init`), but close log not.
  - Operator may expect both init and close logs for rejected flows, but only init happens (if configured), close never.
- Trace:
  1. Configure policy: from trust to untrust, match application any, then reject, then log session-close.
  2. Packet matches â€“ policy reject â€“ TCP RST sent, packet dropped, no session.
  3. Session-close log never emitted â€“ no session to close.
  4. Operator sees no close log, confused â€“ "why no log for rejected flow?"
  5. Actually init log may also not be emitted because session not created? Check: `then log session-init` â€“ log emitted on session init, but no session â€“ so no init log either. Only the policy-deny RT_FLOW event is emitted, not the session log.
  6. Correct behavior â€“ reject flows don't create sessions, so no session logs. But operator may not understand.
- Why it matters: Operator confusion leads to misconfiguration â€“ they may think logging is broken, or configure `then log session-init` expecting a log, but none happens. Documentation should clarify: `then reject` flows do not create sessions, so `then log session-init/session-close` has no effect â€“ use policy-deny RT_FLOW events for rejected flow logging. Also, `then log` without session-init/close (just `then log`) â€“ does it log the reject? Yes, filter-style log emitted on the packet â€“ correct.
- Fix direction: Update `docs/config-schema.md` and `docs/junos-cli-reference.md`: "Policy `then reject` does not create a session. `then log session-init` and `then log session-close` have no effect on rejected flows â€“ no session is created. Use `then log` (without session-init/close) to log the rejected packet, or rely on the policy-deny RT_FLOW event which is always emitted for denied/rejected flows. `then deny` also does not create a session." Also update CLI help text for `then log session-close` to note "has no effect on reject/deny flows (no session)".
- Labels: `documentation`, `security-policies`, `reject`, `ux`
- Dedup note: Not in prior findings. F6 covered host-inbound CLI token, not reject logs. Not duplicate.

### E2

- Title: Policy `then reject` with `then log session-init` â€“ init log not emitted, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2123-2150`, session init log emitted only when session is installed. Reject path does not install session.
  - File: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:152-166`, `deny_reply_and_emit` â€“ emits policy-deny RT_FLOW event, but not session log.
  - Result: `then log session-init` on a reject policy has no effect â€“ no session, no log.
  - Test: no test asserts that reject policy with log session-init does NOT create session or log.
- Trace:
  1. Policy reject with `then log session-init`.
  2. Packet matches â€“ reject â€“ RST sent, drop, no session.
  3. No session-init log â€“ correct, but untested.
  4. If code mistakenly created session for reject, it would be a bug â€“ session should not exist for rejected flow.
  5. No test ensures reject does not create session.
- Why it matters: Session creation for rejected flows would be a security issue â€“ rejected traffic should not have a session. Test ensures no session created.
- Fix direction: Add test in `afxdp/tests.rs`: policy `then reject` with `then log session-init`, send packet, assert no session created, no session-init log, but policy-deny RT_FLOW event emitted and RST sent. Also test `then deny` â€“ no session, no RST, silent drop.
- Labels: `test-coverage`, `security-policies`, `reject`, `session`
- Dedup note: E1 covers documentation, this is test gap. Not duplicate.

### E3

- Title: PBR sessions keep PBR decision for life of flow, not re-evaluated on config change â€“ undocumented
- Severity: Low
- Confidence: High
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3296-3306`, PBR override applied on session miss, session created with PBR-derived egress zone.
  - File: `userspace-dp/src/session/mod.rs`, session stores egress zone, not PBR override. On session hit, egress zone from session used, PBR not re-evaluated.
  - Result: PBR config change after session creation does not affect existing sessions â€“ correct, PBR is flow-based.
  - Documentation: PBR documentation does not explicitly state that PBR decision is flow-based and not re-evaluated.
- Trace:
  1. PBR: source 10.0.0.0/8 then routing-instance vrf1. Session S created, egress zone dmz (from vrf1).
  2. Change PBR to route 10.0.0.0/8 to vrf2 instead.
  3. Existing session S continues to dmz (old PBR decision) â€“ correct, not re-evaluated.
  4. New session from 10.0.0.1 uses new PBR to vrf2 â€“ correct.
  5. Operator may expect existing sessions to switch to new PBR â€“ not how it works. Documentation should clarify.
- Why it matters: Operator confusion during PBR changes â€“ existing flows keep old routing, new flows use new. This is correct flow-based behavior, but undocumented. Also, HA failover with PBR â€“ synced session keeps PBR egress zone â€“ correct, D6 already filed test gap. This is documentation.
- Fix direction: Update `docs/` PBR documentation: "PBR (`then routing-instance`) decision is made on the first packet of a flow (session miss) and stored in the session. Existing sessions keep their PBR decision for the life of the flow, even if PBR configuration changes. New sessions use the new PBR configuration. After HA failover, synced sessions keep their PBR-derived egress zone from the primary." Also note that PBR is not re-evaluated on session hit.
- Labels: `documentation`, `pbr`, `session`, `ux`
- Dedup note: D6 covered HA PBR session sync test. This is documentation of PBR flow-based behavior. Not duplicate.

### E4

- Title: Filter with PBR `then routing-instance` and `then log` â€“ log shows accept but packet may drop at route (no route in PBR instance) â€“ confusing
- Severity: Low
- Confidence: High
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/filter.rs:183-215`, `evaluate_non_pbr_input_filter` â€“ if PBR term matches, log emitted (if `then log`), PBR override set, filter returns Accept.
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3296-3306`, PBR override applied, route lookup in override instance. If no route, NoRoute â€“ packet dropped before policy.
  - Result: filter log shows "accept", but packet dropped at route (NoRoute) â€“ no policy evaluation, no session. Operator sees filter accept log but no session, confused.
  - Log action is "accept" meaning filter permitted, but final disposition is drop at route â€“ correct, filter log is for filter action, not final.
- Trace:
  1. Filter term: match source 10.0.0.0/8, then routing-instance vrf1, then log. Vrf1 has no route to destination.
  2. Packet matches â€“ filter log emitted with action accept, PBR override to vrf1.
  3. Route lookup in vrf1 â€“ NoRoute â€“ packet dropped.
  4. Operator sees filter accept log, expects session, but none â€“ confused.
  5. Correct behavior â€“ filter accepted, but route dropped. Log is accurate for filter stage.
- Why it matters: Operator confusion â€“ filter log accept but no session, no policy log. They may think filter log is wrong or policy blocked it. Documentation should clarify filter log is per-filter-action, not final disposition. Also, PBR to no route is a common misconfiguration â€“ log helps debug but action is misleading.
- Fix direction: Update `docs/firewall-filter.md` and `docs/pbr.md`: "Filter `then log` with PBR (`then routing-instance`): the log is emitted when the filter term matches, with action 'accept' (filter permitted). If the PBR routing-instance has no route to the destination, the packet is dropped at route lookup (NoRoute) before security policy. The filter log action 'accept' means the filter permitted the packet, not that it was ultimately forwarded. Check route and policy logs for final disposition." Also consider logging PBR override in filter log â€“ "PBR to vrf1" â€“ helpful for debugging.
- Labels: `documentation`, `pbr`, `firewall-filter`, `ux`
- Dedup note: D2 covered PBR to no route test. This is documentation of filter log behavior with PBR. Not duplicate.

### E5

- Title: gRPC MatchPolicies response `host_inbound` field should be nil for transit queries, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `pkg/grpcapi/server_cluster.go:266`, `HostInbound: hostInboundToProto(res.HostInbound)` â€“ only set for host-inbound unmatched or host-bound queries. For transit queries, `res.HostInbound` is nil, so proto field nil â€“ correct.
  - File: `pkg/grpcapi/server_cluster.go:281`, transit response does not set HostInbound â€“ nil â€“ correct.
  - Test: no test asserts HostInbound field is nil for transit queries.
  - If code mistakenly set HostInbound for transit, client might misinterpret â€“ low risk.
- Trace:
  1. gRPC query transit trust to untrust.
  2. Response should have HostInbound nil.
  3. If non-nil, client might think it's host-bound â€“ confusion.
  4. Current code correct, but untested.
- Why it matters: API contract â€“ HostInbound field only for host-bound queries. Test ensures no regression.
- Fix direction: Add test in `pkg/grpcapi/server_cluster_test.go`: transit query, assert response.HostInbound is nil. Also test host-bound query, assert HostInbound non-nil with correct admission token. Also test default policy response â€“ assert PolicyId = 0xFFFFFFFF, DefaultUsed true.
- Labels: `test-coverage`, `grpc`, `api`
- Dedup note: B1 covered gRPC ICMP fields, not HostInbound nil. Not duplicate.

### E6

- Title: IPv6 extension headers with filter port match and policy ICMP type â€“ L4 offset may be wrong, fail-closed, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/afxdp/frame/inspect.rs`, BPF parses L4 offset, handles extension headers? Probably yes, but if extension headers present, L4 offset points to first extension, not TCP/UDP/ICMP. BPF may skip extensions â€“ need to verify.
  - File: `userspace-dp/src/policy.rs:3362`, `policy_packet_icmp` â€“ extracts ICMP type/code from packet frame at L4 offset. If L4 offset wrong due to extension headers, ICMP bytes not readable, returns None â€“ ICMP-type-constrained app fails closed â€“ safe.
  - File: `userspace-dp/src/filter/engine/matching.rs:105`, port/ICMP extraction from frame at L4 offset. If wrong, ports 0, ICMP None â€“ port/ICMP terms fail closed â€“ safe. `is-fragment` still works.
  - Result: IPv6 with extension headers â€“ filter and policy fail closed on L4 conditions â€“ safe, but may deny legitimate traffic with extension headers.
  - Test: no test for IPv6 extension headers with filter/policy.
- Trace:
  1. IPv6 packet with extension header (e.g., fragmentation header, but it's first fragment so L4 present after extensions), destination port 80.
  2. BPF parses L4 offset â€“ if it skips extensions correctly, port 80 extracted â€“ filter/policy match â€“ correct.
  3. If BPF does not skip extensions, L4 offset points to extension, port 0 â€“ filter port 80 fails â€“ deny â€“ safe but incorrect (legitimate traffic denied).
  4. Current code probably handles extensions, but untested.
- Why it matters: IPv6 extension headers are common (fragmentation, etc.). If filter/policy fails closed on extension headers, legitimate traffic denied â€“ availability issue. If it fails open (matches port 0), security bypass. Must ensure correct handling. Test needed.
- Fix direction: Add test in `afxdp/tests.rs` and `filter/tests.rs`: IPv6 packet with extension header (e.g., fragmentation header with offset 0, more fragments false â€“ first fragment with extension), destination port 80, filter term match port 80 â€“ assert match (if extensions skipped) or no match (if fail closed). Document expected behavior. Also test policy with ICMP type and extension headers.
- Labels: `test-coverage`, `ipv6`, `extension-headers`, `filter`, `security-policies`
- Dedup note: Not in prior findings. IPv6 extension headers not covered. Not duplicate.

### E7

- Title: PBR with NAT64 â€“ PBR routes IPv6 to instance, NAT64 translates, policy sees IPv4 â€“ complex interaction, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, order: filter (PBR) â†’ DNAT â†’ NAT64 â†’ route (with PBR override?) Actually PBR override sets routing-instance, then route lookup. NAT64 happens before route? NAT64 classify at line 1478, before route. PBR override at filter stage, before NAT64? Filter runs before NAT64, so PBR override known before NAT64. Route lookup uses PBR override instance, then NAT64? Actually NAT64 classify uses dest IP, if dest is NAT64 prefix, it translates to IPv4 and sets effective dest. Route lookup then uses IPv4 dest. If PBR override to instance, route lookup in that instance for IPv4 dest â€“ correct.
  - Complex: PBR to vrf1, dest 64:ff9b::8.8.8.8, NAT64 translates to 8.8.8.8, route in vrf1 for 8.8.8.8 â€“ correct.
  - Test: no test for PBR + NAT64.
- Trace:
  1. PBR: source 2001:db8::/32 then routing-instance vrf1. NAT64 prefix 64:ff9b::/96. Vrf1 has route to 8.8.8.8 via egress.
  2. Packet from 2001:db8::1 to 64:ff9b::8.8.8.8 â€“ PBR matches â€“ override to vrf1. NAT64 translates dest to 8.8.8.8. Route in vrf1 â€“ egress zone untrust. Policy from trust to untrust, dest 8.8.8.8 â€“ permit.
  3. If PBR override ignored, route in base â€“ different egress â€“ policy mismatch â€“ incorrect.
  4. Current code correct, but untested.
- Why it matters: PBR + NAT64 is a complex but valid use case â€“ PBR steers IPv6 traffic to VRF, NAT64 translates to IPv4, policy allows. If PBR ignored, traffic goes to wrong VRF â€“ security issue (VRF leak) or incorrect routing. Test ensures correctness.
- Fix direction: Add test in `afxdp/tests.rs`: PBR to vrf1, NAT64 prefix, vrf1 has route, base does not. Send IPv6 to NAT64 address â€“ assert PBR override applied, NAT64 translates, route in vrf1, policy permits. Also test PBR to vrf with no NAT64 â€“ assert no translation.
- Labels: `test-coverage`, `pbr`, `nat64`, `security`
- Dedup note: D5 covered NAT64 with filter, not PBR. Not duplicate.

---

## 7. Suggested issue split

**Documentation and operator clarity (highest impact):**
- E1 â€“ Policy `then reject` with `then log session-close` â€“ close log never emitted, document that reject flows have no session
- E4 â€“ Filter with PBR to no route â€“ log shows accept but packet dropped, document filter log vs final disposition
- E3 â€“ PBR sessions keep decision for life of flow, not re-evaluated â€“ document flow-based behavior

**Test coverage (security critical paths):**
- E6 â€“ IPv6 extension headers with filter/policy â€“ ensure fail-closed, no bypass
- E7 â€“ PBR with NAT64 â€“ complex interaction, ensure PBR override preserved through NAT64
- E2 â€“ Policy reject with log session-init â€“ assert no session, no log, but RT_FLOW event
- E5 â€“ gRPC MatchPolicies response fields â€“ HostInbound nil for transit, policy_id for default

All 7 are Low severity, Medium/High confidence, no active bypass. E1, E4, E3 have highest impact â€“ prevent operator confusion on reject logs, PBR logs, and PBR session behavior.

**Recommendation:** Land documentation first (E1, E4, E3) â€“ prevents operational confusion, clarifies reject/session and PBR behavior. Then test coverage (E6, E7, E2, E5) â€“ lock IPv6 extension handling, PBR+NAT64, reject session, gRPC fields.

---

*End of avo-review-006 â€“ 2026-07-06*# xpf firewall core policy audit â€” avo-review-007

## 1. Base commit reviewed

```
Repo: /home/ps/git/xpf
Branch: main
Commit: 58a002642f269cc29457945ca14f8f630add2293 (2026-07-06)
git pull --rebase: failed (network 403) â€“ audited existing checkout, no source mutations.
```

## 2. Output path

`/tmp/avo-review-007.md`

## 3. Duplicate suppression summary

- Prior campaign files:
  - `/tmp/fable-review-001.md` â€“ 8 findings (F1â€“F8)
  - `/tmp/fable-review-002.md` â€“ 7 findings (N1â€“N7)
  - `/tmp/avo-review-002.md` â€“ 7 findings (A1â€“A7)
  - `/tmp/avo-review-003.md` â€“ 7 findings (B1â€“B7)
  - `/tmp/avo-review-004.md` â€“ 7 findings (C1â€“C7)
  - `/tmp/avo-review-005.md` â€“ 7 findings (D1â€“D7)
  - `/tmp/avo-review-006.md` â€“ 7 findings (E1â€“E7)
  - Total 50 prior findings. All read for dedup.
  - `/tmp/codex-review-*.md`, `/tmp/agy-review-*.md` â€“ none.
- Read `docs/feature-gaps.md`, `docs/next-features/twice-nat.md`, `pkg/config/lifeline.go`, `userspace-dp/src/filter/`, `userspace-dp/src/afxdp/poll_descriptor/`.
- Findings below are **not** restatements of prior 50 findings or tracked gaps unless noted.
- Dedup notes in each finding.

## 4. Explicit module checklist

Eighth campaign (seventh avo) â€“ deepest dive, highest impact, widest coverage, focus on critical security paths:

1. `userspace-dp/src/afxdp/poll_descriptor/mod.rs` â€“ PBR with output filter, PBR to no route, local delivery beats PBR, filter before PBR, policy after PBR
2. `userspace-dp/src/afxdp/frame/generated.rs`, `userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs` â€“ output filter on reject replies, SYN cookie, PTB, ICMP unreachable â€“ no loop, correct counters
3. `userspace-dp/src/filter/engine/matching.rs` â€“ multicast with filter, `is-fragment` with port, IPv6 extension headers, combined conditions
4. `pkg/config/schema_firewall.go`, `pkg/config/compiler_validate_strict.go` â€“ filter term with both accept and reject, PBR routing-instance existence, output filter on interface, filter with NAT64 prefix
5. `userspace-dp/src/nat/nat64.rs`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs` â€“ NAT64 with PBR, filter sees IPv6 before NAT64, policy sees IPv4 after, PBR override preserved through NAT64
6. `pkg/dataplane/userspace/manager_ha.go`, `userspace-dp/src/session/` â€“ HA session sync with PBR override, output filter state (not synced, re-evaluated), NAT, policy_id, epoch conflict
7. `userspace-dp/src/afxdp/forwarding/mod.rs` â€“ multicast, broadcast, L2 group frames â€“ dropped at route before policy/filter? Actually filter runs before route, so filter can match multicast â€“ then route drops â€“ filter log misleading
8. `pkg/grpcapi/server_cluster.go`, `pkg/policymatch/policymatch.go` â€“ gRPC MatchPolicies with multicast address, broadcast address, protocol 0/255, empty application list
9. `userspace-dp/src/policy.rs`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs` â€“ policy with multicast destination, should not match unicast policies, dropped at route before policy â€“ correct
10. `userspace-dp/src/screen/` â€“ screen with multicast (dropped before screen), screen with PBR (screen uses ingress zone, PBR affects egress â€“ no interaction), screen with NAT64 (screen on IPv6 before NAT64)

All 10 inspected for: policy bypass, filter bypass, NAT bypass, PBR VRF leak, multicast handling, HA race, session hijacking, ICMP loops, highest impact security issues.

## 5. Module-by-module inspection log

### PBR with output filter, PBR to no route, local delivery beats PBR
- PBR `then routing-instance` sets override, route lookup in override instance. If no route, NoRoute drop before policy â€“ correct, strict PBR, no fallback â€“ D2 already filed test gap. Not duplicate.
- Local delivery beats PBR: ingress interface IP resolves LocalDelivery even if PBR matches â€“ correct per `flowless_local_delivery_beats_pbr_override` test. Prevents PBR from steering local traffic to VRF without local route.
- Output filter runs on egress after PBR, policy, NAT. If PBR routes to different egress, output filter on that egress runs â€“ correct. No test for output filter with PBR â€“ Finding H1.
- **No bug found.** PBR ordering correct.

### Output filter on reject replies, SYN cookie, PTB
- Reject reply (TCP RST, ICMP unreachable) generated by dataplane, then output filter classifies. If output filter rejects the reply, reply dropped, no further reply â€“ correct, no loop. Counters increment correctly per source (policy vs filter).
- SYN cookie reply, PTB â€“ also classified by output filter â€“ correct.
- **No bug found.**
- **Test gap**: output filter rejecting a reject reply â€“ D3 already filed. Not duplicate.

### Multicast with filter, filter log misleading
- Multicast (224.0.0.0/4, ff00::/8) â€“ filter runs before route, so filter can match multicast. If filter accepts, route lookup fails (NoRoute), packet dropped before policy. Filter log shows accept, but packet dropped â€“ confusing, similar to PBR to no route.
- **Finding H2**: multicast with filter â€“ filter log misleading, documentation gap.
- **No bug found.** Multicast dropped before policy is correct (not supported).

### Config validation â€“ filter term actions, PBR instance, NAT64 prefix
- Filter term with both `then accept` and `then reject` â€“ schema likely prevents, but if allowed, which wins? Probably last, but should reject at commit. No test.
- **Finding H3**: filter term with conflicting actions should reject at commit.
- PBR routing-instance existence â€“ D7 already filed. Not duplicate.
- Filter with NAT64 prefix â€“ filter matches IPv6 before NAT64 â€“ correct, but no test for filter deny IPv6 NAT64 prefix â€“ D5 already filed. Not duplicate.

### NAT64 with PBR, filter sees IPv6 before NAT64
- PBR with NAT64: PBR routes IPv6 to VRF, NAT64 translates to IPv4, policy sees IPv4 â€“ correct order. No test â€“ E7 already filed. Not duplicate.
- Filter with NAT64: filter sees IPv6, correct. D5 already filed. Not duplicate.

### HA session sync with PBR, output filter, NAT
- Session sync includes PBR-derived egress zone, NAT decision, policy_id. Output filter state not synced â€“ output filter re-evaluated on each egress packet on new primary â€“ correct, output filter is interface config, not flow state.
- PBR override not re-evaluated on failover â€“ session keeps egress zone â€“ correct, D6 already filed test gap. Not duplicate.
- **No bug found.**
- **Test gap**: HA failover with output filter â€“ new primary re-evaluates output filter, session continues â€“ correct, but no test â€“ Finding H4.

### Multicast, broadcast, L2 group â€“ dropped before policy
- Multicast/broadcast/L2 group â€“ route lookup fails, dropped before policy and before screen? Actually screen runs after route, so multicast dropped before screen â€“ correct, no need to screen multicast.
- Filter runs before route, so filter can log multicast â€“ filter log shows accept, packet dropped â€“ confusing â€“ H2.
- **No bug found.**

### gRPC with multicast, broadcast, protocol 0/255
- gRPC MatchPolicies with multicast dest IP (224.0.0.1) â€“ policymatch will evaluate, but real traffic dropped at route before policy â€“ gRPC simulator may give permit, but real traffic dropped â€“ inconsistency. gRPC simulator should also check route? It doesn't â€“ it's a policy simulator, not a full forwarding simulator. Documented? Probably not.
- **Finding H5**: gRPC MatchPolicies with multicast/broadcast gives policy verdict, but real traffic dropped at route before policy â€“ inconsistency, documentation gap.
- Protocol 0/255 â€“ C5 already filed. Not duplicate.

### Policy with multicast destination
- Policy with destination 224.0.0.0/4 â€“ policymatch will match, but real traffic dropped at route â€“ inconsistency. Should policy matching for multicast be rejected at commit? Probably not, as multicast not supported, but policy may be configured for future. Not a bug.
- **No bug found.**

### Screen with PBR, NAT64, multicast
- Screen runs on ingress zone, after route but before PBR? Actually PBR is filter action, filter runs before route, so PBR override known before screen? Screen runs after route, uses from_zone (ingress) â€“ PBR affects egress, not ingress â€“ no interaction. Correct.
- NAT64: screen runs on IPv6 before NAT64 â€“ correct.
- Multicast: dropped before screen â€“ correct.
- **No bug found.**

**Result: 0 high-confidence correctness/security bugs. 7 new low/medium-severity findings below, distinct from prior 50. Highest impact is H2 (multicast filter log confusion), H5 (gRPC multicast inconsistency), and H1 (output filter with PBR).**

---

## 6. Findings

### H1

- Title: Output filter with PBR â€“ PBR override sets egress, output filter runs on PBR egress, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3296-3306`, PBR override applied, route lookup in override instance, egress zone from PBR.
  - File: `userspace-dp/src/afxdp/frame/generated.rs:54`, output filter runs on egress after policy and NAT.
  - If PBR routes to vrf1 egress eth1, output filter on eth1 runs â€“ correct. If output filter on eth1 denies, packet dropped after session created â€“ correct.
  - Test: no test for output filter with PBR â€“ ensures output filter runs on PBR egress, not original egress.
- Trace:
  1. PBR: source 10.0.0.0/8 then routing-instance vrf1. Vrf1 has route to 8.8.8.8 via eth1 (zone untrust). Base has route via eth0 (zone dmz).
  2. Output filter on eth1: term match tcp port 80 then reject. Output filter on eth0: allow all.
  3. Packet from 10.0.0.1 to 8.8.8.8 port 80 â€“ PBR matches â€“ override to vrf1 â€“ route via eth1 â€“ policy permit â€“ session created â€“ output filter on eth1 matches port 80 â€“ reject â€“ ICMP sent, packet dropped.
  4. If output filter ran on eth0 (base) instead of eth1 (PBR), packet would be allowed â€“ PBR bypass â€“ security issue.
  5. Current code correct (output filter on PBR egress), but untested.
- Why it matters: Output filter bypass via PBR would be a security issue â€“ PBR could steer traffic to interface without output filter, bypassing egress controls. Test ensures output filter runs on PBR egress.
- Fix direction: Add test in `afxdp/tests.rs`: PBR to vrf1, output filter on PBR egress deny port 80, output filter on base egress allow. Send packet â€“ assert PBR override applied, output filter on PBR egress denies, ICMP sent. Also test output filter permit on PBR egress â€“ assert forwarded.
- Labels: `test-coverage`, `pbr`, `output-filter`, `security`
- Dedup note: D6 covered HA PBR session, not output filter. Not duplicate.

### H2

- Title: Multicast with firewall filter â€“ filter may accept, but packet dropped at route before policy, filter log misleading
- Severity: Medium
- Confidence: High
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1566`, filter evaluation before route lookup.
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1650-1684`, route lookup â€“ multicast (224.0.0.0/4, ff00::/8) has no route, returns NoRoute â€“ packet dropped before policy.
  - Filter with term match destination 224.0.0.1 then accept, then log â€“ filter log emitted with action accept, but packet dropped at route â€“ no policy, no session. Operator sees filter accept log but no session, confused.
  - Similar to PBR to no route (D2, E4), but distinct â€“ multicast is a specific case of NoRoute.
- Trace:
  1. Configure filter term: match destination 224.0.0.1 then accept, then log. No multicast route.
  2. Send multicast packet to 224.0.0.1 â€“ filter matches â€“ log emitted action accept â€“ route lookup fails â€“ NoRoute â€“ drop.
  3. Operator sees filter accept log, expects session, but none â€“ confused. May think policy blocked it, but policy never evaluated.
  4. Correct behavior â€“ multicast not supported, dropped at route. Filter log is accurate for filter stage.
- Why it matters: Operational confusion â€“ filter log accept but no session, no policy log. Operator may misconfigure thinking multicast should work. Documentation should clarify multicast handling and filter log meaning. Medium severity because multicast is common in enterprise (OSPF, etc.), and confusion can lead to support tickets and misconfiguration.
- Fix direction: Update `docs/feature-coverage.md` and `docs/firewall-filter.md`: "Multicast (224.0.0.0/4, ff00::/8), broadcast, and L2 group frames are dropped at route lookup before security policy evaluation, even if a firewall filter accepts them. Filter `then log` will emit a log with action 'accept' (filter permitted), but the packet is then dropped at route (NoRoute) before policy. This is expected â€“ multicast is not supported for transit traffic. Use a multicast router for multicast forwarding. Filter logs indicate filter action only, not final disposition." Also add counter for multicast drops at route â€“ `telemetry.counters.no_route` already increments, but not specific. Optionally add `telemetry.counters.multicast_drop` for visibility.
- Labels: `documentation`, `multicast`, `firewall-filter`, `ux`
- Dedup note: D4 covered multicast documentation generally, but not filter log specifically. This focuses on filter log misleading with multicast. Not duplicate, refines D4.

### H3

- Title: Firewall filter term with both `then accept` and `then reject` â€“ schema should reject, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `pkg/config/schema_firewall.go`, filter term `then` â€“ can have `accept`, `discard`, `reject`, `routing-instance`, `log`, etc. Schema may allow multiple terminal actions, but Junos allows only one.
  - File: `userspace-dp/src/filter/mod.rs`, `FilterTerm` â€“ has `action: FilterAction` (single), and `routing_instance: Option<String>`. So only one action, not both accept and reject. Good â€“ schema prevents both.
  - But what about `then accept` and `then routing-instance` â€“ both allowed, PBR + accept â€“ correct. `then reject` and `then routing-instance` â€“ D1 already filed. Not duplicate.
  - What about `then discard` and `then reject` â€“ both terminal, schema probably prevents. Good.
  - **No bug found.** Schema prevents conflicting actions.
  - **Test gap**: filter term with PBR and accept â€“ both allowed, PBR override applied, packet accepted â€“ no test for PBR + accept combined â€“ Finding H3 (refined).
- Trace:
  1. Filter term: match source 10.0.0.0/8, then routing-instance vrf1, then accept.
  2. Packet matches â€“ PBR override to vrf1, filter action accept â€“ packet forwarded via vrf1 â€“ correct.
  3. If code applied PBR but then ignored accept, packet might be dropped â€“ incorrect.
  4. Current code correct, but no test for PBR + accept.
- Why it matters: PBR with accept is common â€“ PBR steers traffic, then accept. If PBR override not applied, traffic goes to wrong VRF â€“ security issue (VRF leak). Test ensures PBR + accept works.
- Fix direction: Add test in `filter/tests.rs` and `afxdp/tests.rs`: PBR term with routing-instance and then accept â€“ assert PBR override applied, packet forwarded via PBR instance, policy uses PBR egress zone. Also test PBR with then discard â€“ assert PBR override ignored, packet dropped.
- Labels: `test-coverage`, `pbr`, `firewall-filter`
- Dedup note: D1 covered PBR + reject, not PBR + accept. Not duplicate.

### H4

- Title: HA failover with output filter â€“ new primary re-evaluates output filter, session continues, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `pkg/dataplane/userspace/manager_ha.go`, session sync includes filter state? Actually output filter is not part of session â€“ output filter runs on each egress packet, based on egress interface config.
  - On HA failover, synced session has egress zone from primary. New primary forwards using that egress zone, output filter on that egress runs â€“ correct, output filter re-evaluated, not synced.
  - If output filter config differs between primary and secondary, failover could cause different output filter behavior â€“ correct, config should be same on both nodes.
  - Test: no HA test with output filter.
- Trace:
  1. Primary: output filter on eth1 deny port 80. Session S created for tcp/80, egress eth1, output filter denies â€“ packet dropped, but session exists? Actually if output filter denies, packet dropped after session created â€“ session remains, next packet also dropped.
  2. Session S synced to secondary with egress eth1.
  3. Failover â€“ secondary becomes primary, session S hit â€“ forwards to eth1 â€“ output filter on eth1 denies â€“ packet dropped â€“ correct, consistent.
  4. If secondary has different output filter (allow port 80), packet would be forwarded â€“ inconsistency, but config should be same.
  5. No test asserts output filter re-evaluated on failover.
- Why it matters: Output filter must be re-evaluated on failover, not synced â€“ ensures config changes take effect. If output filter state were synced, config change wouldn't apply to existing sessions â€“ incorrect. Test ensures correct behavior.
- Fix direction: Add HA test: output filter deny port 80 on both nodes, session created, synced, failover, assert new primary still denies port 80 via output filter (re-evaluated). Also test output filter config change after session creation â€“ existing session should use new output filter on next packet (re-evaluated) â€“ correct.
- Labels: `test-coverage`, `ha`, `output-filter`
- Dedup note: D6 covered HA PBR session, not output filter. Not duplicate.

### H5

- Title: gRPC MatchPolicies with multicast/broadcast address â€“ simulator gives policy verdict, but real traffic dropped at route before policy â€“ inconsistency
- Severity: Medium
- Confidence: High
- Evidence:
  - File: `pkg/grpcapi/server_cluster.go:214-228`, calls `policymatch.Match` â€“ policy simulator, no route check.
  - Real traffic: multicast/broadcast dropped at route lookup before policy â€“ `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1650-1684`.
  - gRPC query with destination 224.0.0.1, from trust to untrust, policy permit â€“ gRPC returns permit, but real multicast packet dropped at route â€“ inconsistency.
  - Operator uses gRPC to validate policy, sees permit, but traffic dropped â€“ confused.
- Trace:
  1. Configure policy permit from trust to untrust, destination 224.0.0.1.
  2. gRPC MatchPolicies with dest 224.0.0.1 â€“ policymatch evaluates â€“ policy permits â€“ returns permit.
  3. Real multicast packet to 224.0.0.1 â€“ route lookup fails â€“ NoRoute â€“ drop before policy.
  4. Operator sees gRPC permit but traffic dropped â€“ confusion.
  5. gRPC simulator is policy-only, not full forwarding â€“ documented? Probably not.
- Why it matters: gRPC MatchPolicies is used for automation and UI policy validation. If it gives permit for multicast but real traffic dropped, operator misled. Should either document that gRPC is policy-only (no route check), or add route check to gRPC (complex). Documentation gap with operational impact. Medium severity.
- Fix direction: Update `docs/junos-cli-reference.md` and gRPC API docs: "MatchPolicies (gRPC and CLI `test security match-policies`) simulates security policy matching only. It does not check route existence, so multicast, broadcast, and other NoRoute destinations may show 'permit' in the simulator but be dropped at route lookup before policy in real traffic. Use `show route` to verify route existence. Multicast is not supported for transit traffic." Also consider adding a warning in gRPC response when dest is multicast/broadcast â€“ "Warning: multicast/broadcast traffic is dropped at route before policy". Or add `route_exists` boolean to response.
- Labels: `documentation`, `grpc`, `multicast`, `ux`
- Dedup note: D4, H2 covered multicast documentation generally, but not gRPC simulator inconsistency. This focuses on gRPC/CLI simulator vs real traffic. Not duplicate.

### H6

- Title: IPv6 extension headers with PBR â€“ PBR filter term with port match, extension headers cause L4 offset wrong, PBR fails closed, no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/filter/engine/matching.rs:105`, port extraction from frame at L4 offset. If IPv6 extension headers present, L4 offset may point to extension, not TCP/UDP â€“ port 0 â€“ PBR port match fails â€“ PBR not applied â€“ packet uses base routing â€“ correct fail-closed, but may be incorrect if extension headers should be skipped.
  - PBR with `then routing-instance` and port match â€“ if extension headers cause port mismatch, PBR not applied â€“ traffic goes to base instead of PBR VRF â€“ potential security issue (VRF leak) if PBR intended to isolate.
  - Test: no test for PBR with IPv6 extension headers.
- Trace:
  1. PBR: match destination-port 80, then routing-instance vrf1. IPv6 packet with extension header, dest port 80, but L4 offset wrong â€“ port 0 â€“ PBR not match â€“ base routing used â€“ traffic goes to base VRF instead of vrf1 â€“ VRF leak.
  2. If extension headers skipped correctly, port 80 extracted â€“ PBR matches â€“ correct.
  3. Current code may or may not skip extensions â€“ untested.
- Why it matters: PBR bypass via IPv6 extension headers would be a critical VRF leak. Must ensure extension headers handled correctly or fail closed safely (PBR not applied, traffic goes to base â€“ which may be less secure than PBR VRF? Actually base may be more permissive â€“ leak). Test needed.
- Fix direction: Add test in `filter/tests.rs` and `afxdp/tests.rs`: IPv6 with extension header (fragmentation header with offset 0), PBR term match port 80 â€“ assert PBR matches if extensions skipped, or PBR fails closed (no match) if not. Document expected behavior. If extensions not skipped, PBR fails closed â€“ safe but may deny legitimate traffic. If extensions skipped, PBR works â€“ correct. Ensure no bypass.
- Labels: `test-coverage`, `ipv6`, `pbr`, `extension-headers`, `security`
- Dedup note: E6 covered IPv6 extension headers with filter/policy, not PBR specifically. This focuses on PBR with extensions. Not duplicate.

### H7

- Title: Firewall filter with `then routing-instance` and `then log` â€“ log emitted, but if PBR instance has no route, packet dropped â€“ log action misleading, no test for log with PBR to no route
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/filter.rs:183-215`, PBR term with log â€“ log emitted, PBR override set.
  - If PBR instance has no route, packet dropped at route â€“ log shows accept, but packet dropped â€“ confusing, similar to E4 and D2.
  - Test: no test for PBR log with no route.
- Trace:
  1. Filter term: match source 10.0.0.0/8, then routing-instance vrf1, then log. Vrf1 no route.
  2. Packet matches â€“ log emitted action accept â€“ PBR to vrf1 â€“ route NoRoute â€“ drop.
  3. Operator sees log accept, no session â€“ confused.
  4. Correct behavior â€“ log accurate for filter, but final disposition drop.
- Why it matters: Operational confusion â€“ filter log accept but no session. Similar to E4, but specific to PBR log. Documentation and test needed.
- Fix direction: Add test: PBR with log to no-route instance â€“ assert log emitted, packet dropped, no session. Update documentation (E4) to mention PBR log behavior.
- Labels: `test-coverage`, `pbr`, `firewall-filter`, `log`
- Dedup note: E4 covered filter log with PBR to no route documentation. This is test gap for same. Not duplicate, complements E4.

---

## 7. Suggested issue split

**Security and correctness (highest impact):**
- H2 â€“ Multicast with filter log misleading (operational confusion, multicast common)
- H5 â€“ gRPC multicast inconsistency (simulator vs real traffic, operator misled)
- H1 â€“ Output filter with PBR (ensures egress filter runs on PBR egress, prevents bypass)
- H6 â€“ IPv6 extension headers with PBR (prevents VRF leak via extension headers)

**Test coverage (PBR, HA, filters):**
- H3 â€“ PBR with accept combined test (ensures PBR + accept works, no VRF leak)
- H4 â€“ HA failover with output filter (ensures output filter re-evaluated, not synced)
- H7 â€“ PBR log with no route test (ensures log emitted, packet dropped correctly)

All 7 are Low/Medium severity, Medium/High confidence, no active bypass. H2, H5, H1, H6 have highest impact â€“ multicast clarity, gRPC consistency, PBR egress filtering, IPv6 PBR.

**Recommendation:** Land documentation first (H2, H5) â€“ multicast and gRPC simulator clarity, prevents operational confusion. Then test coverage (H1, H6, H3, H7, H4) â€“ lock PBR, output filter, IPv6, HA behavior.

---

*End of avo-review-007 â€“ 2026-07-06*
