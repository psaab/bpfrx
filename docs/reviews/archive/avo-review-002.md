# xpf firewall core policy audit â€” avo-review-002

## 1. Base commit reviewed

```
Repo: /home/ps/git/xpf
Branch: main
Commit: 58a002642f269cc29457945ca14f8f630add2293 (2026-07-06)
git pull --rebase: failed (network 403) â€“ audited existing checkout, no source mutations.
```

## 2. Output path

`/tmp/avo-review-002.md`

## 3. Duplicate suppression summary

- Prior campaign files:
  - `/tmp/fable-review-001.md` â€“ 8 findings (F1â€“F8): policymatch global scope tests, userspace-dp global scope tests, CLI ICMP args, ICMP app error message, default-policy counters, host-inbound CLI token, port whitespace parity, wildcard tier merge order.
  - `/tmp/fable-review-002.md` â€“ 7 findings (N1â€“N7): NAT64 ICMP policy test, NAT64 mismatch counter, l4_present ICMP test, DNAT app log, HA default-policy resync, screen icmp-fragment counter, NAT64 ICMP error policy.
  - `/tmp/avo-review-*.md`, `/tmp/codex-review-*.md`, `/tmp/agy-review-*.md` â€“ none found (ls 2026-07-06).
- Read `docs/feature-gaps.md`, `docs/host-inbound-service-matrix.md`, `docs/feature-coverage.md`.
- Findings below are **not** restatements of F1â€“F8, N1â€“N7, or tracked feature gaps unless noted.
- Dedup notes in each finding.

## 4. Explicit module checklist

Third campaign â€“ firewall filters, host-inbound edge cases, application ID, zone handling:

1. `userspace-dp/src/filter/` â€“ stateless firewall filters, `then reject` vs `discard`, policers, term matching
2. `userspace-dp/src/afxdp/poll_descriptor/filter.rs` â€“ filter evaluation order vs policy, session-hit re-check
3. `userspace-dp/src/afxdp/forwarding/host_inbound.rs` â€“ host-inbound service/protocol matrix, `protocols all` scoping, ICMP subtypes
4. `pkg/dataplane/userspace/zones.go` â€“ zone snapshot builder, host-inbound token sets, lifeline interfaces
5. `userspace-dp/src/appid/` â€“ application catalog, directional lookup, ICMP vs TCP/UDP
6. `pkg/policymatch/` â€“ re-checked application `any` vs empty, zoneKnown with empty string, undefined zones
7. `userspace-dp/src/policy.rs` â€“ `application any` handling, empty application list, global policy with zone 0
8. `pkg/config/` â€“ firewall filter schema, host-inbound token validation, application protocol/port
9. `userspace-dp/src/session/` â€“ session limit per-zone, unconfigured zone behavior
10. `pkg/cli/` â€“ `show security zones host-inbound-traffic`, filter show commands

All 10 inspected for: correctness/security bugs, feature completeness vs vSRX, performance, modularity, test coverage.

## 5. Module-by-module inspection log

### userspace-dp/src/filter/
- Filter evaluation: `evaluate_non_pbr_input_filter` runs before policy on session miss, and on session hit for DSCP re-check. `then reject` enqueues TCP RST / ICMP unreachable via `enqueue_filter_reject_reply`, then emits log with truthful action. `then discard` silent drop. Correct per #2521/#3615.
- Term matching: source/destination address, port ranges, protocol, ICMP type/code, TCP flags, DSCP, forwarding-class. Port matching uses `PortMatcher::matches` â€“ correct.
- Policers: three-color policer metered per term, counters recorded, but per-filter-term policer status not exported in `show firewall filter` â€“ observability gap â€“ Finding A1.
- **No high-confidence bypass.** Filter deny before policy is correct. Filter permit does not bypass policy â€“ correct (filter is stateless ACL, policy is stateful).
- **Test gap**: filter `then reject` with non-TCP/UDP (e.g., ICMP) â€“ should send ICMP unreachable, but no test asserts the ICMP type/code â€“ Finding A2.

### userspace-dp/src/afxdp/poll_descriptor/filter.rs
- Session-hit path: re-checks DSCP and input filter, tears down session on filter deny â€“ correct per #2508.
- Filter log emit on session miss happens before action branch, ensuring accept-path logs are not lost on install-refused â€“ correct per #2617.
- **No bug found.**

### userspace-dp/src/afxdp/forwarding/host_inbound.rs
- Host-inbound matrix: 17 system-services, 15 protocols, ICMP subtypes scoped per service (pingâ†’echo-request only, router-discoveryâ†’types 9/10, etc.) â€“ correct per #3258, #3201.
- `protocols all` expands to routing protocols only, excludes L2/non-IP (IS-IS) â€“ correct per #3199, #3311. Tested in `protocols_all_excludes_l2`.
- Lifeline interfaces (fxp0, em0, fab*) excluded from host-inbound deny â€“ correct per #3277. Control-interface configurable â€“ derived from cluster config.
- **No bug found.**
- **Edge case**: host-inbound `system-services traceroute` admits UDP 33434-33523 and ICMP, but what about TCP traceroute (port 80)? Not a Junos token â€“ correct, but operator confusion possible â€“ Finding A3 (documentation).
- **Test gap**: host-inbound with `protocols all` + `system-services ssh` â€“ ssh should be denied (protocols all does not admit system services), but no test asserts the negative â€“ Finding A4.

### pkg/dataplane/userspace/zones.go
- Zone snapshot builder serializes host-inbound token sets, lifeline interface set derived from cluster config â€“ correct.
- **No bug found.**

### userspace-dp/src/appid/ (via policy.rs AppCatalog)
- `AppCatalog::lookup_admitted` â€“ directional resolution: forward service port = dst forward / src reverse. Correct per #3321.
- ICMP applications: `junos-ping` = ICMP type 8 / ICMPv6 type 128. `junos-icmp-all` = no type constraint. Correct.
- **No bug found.**
- **Edge case**: custom application with both TCP and UDP protocol? Schema allows single protocol only â€“ correct. No issue.
- **Test gap**: AppCatalog lookup with NAT64 translated port â€“ post-DNAT port used for session app_id, but what about NAT64 port translation? NAT64 preserves port â€“ correct, but no test â€“ Finding A5.

### pkg/policymatch/, userspace-dp/src/policy.rs
- `application any` vs empty list: both mean match any. `matchApp` returns true if len==0 or a=="any". `CompiledApplications::from_matches` sets `match_any=true` if empty. Correct.
- `zoneKnown`: returns false for undefined zone, true for "any" and defined zones. Query with empty string zone â€“ `zoneKnown("", cfg)` â€“ empty not a defined zone, returns false â€“ falls to default policy â€“ correct (empty zone = unknown).
- Global policy with from_id=0 or to_id=0: `evaluate_policy_result_l3_aware` gates entire transit block on `from_id != 0 && to_id != 0` â€“ global policies not evaluated for unknown zones â€“ correct per #3355.
- **No bug found.**
- **Test gap**: policymatch with empty string zone name â€“ should fall to default, but no test â€“ Finding A6.

### pkg/config/
- Firewall filter schema: family inet/inet6, term match conditions, then actions (accept, discard, reject, policer, log, etc.). Validated.
- Host-inbound token validation: unknown tokens rejected at commit per #3200 â€“ correct.
- Application schema: protocol required, ports optional, ICMP type/code optional â€“ validated per #3323.
- **No bug found.**

### userspace-dp/src/session/
- Session limit: per-zone source/destination IP limits, enforced at new-flow decision. Unconfigured zone (no zone ID or zone not in session limit config) never drops â€“ `new_flow_session_limit_drop` returns None if zone not configured â€“ correct per code, matches Junos? Unclear â€“ Finding A7 (documentation).
- **No bug found.**

### pkg/cli/
- `show security zones host-inbound-traffic` â€“ displays zone-level and per-interface tokens â€“ correct per #3654.
- `show firewall filter` â€“ displays filter counters, but policer status not shown â€“ see A1.
- **No bug found.**

**Result: 0 high-confidence correctness/security bugs. 7 new low-severity findings below, distinct from F1â€“F8 and N1â€“N7.**

---

## 6. Findings

### A1

- Title: Firewall filter three-color policer status not exported in CLI or Prometheus
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/filter/mod.rs:435-441`, `ThreeColorPolicerRuntime` â€“ meters packets, tracks status (Green/Yellow/Red).
  - File: `userspace-dp/src/filter/mod.rs:575-657`, `impl ThreeColorPolicerRuntime` â€“ `status()` returns current color.
  - File: `userspace-dp/src/filter/mod.rs:819-834`, `FilterState::three_color_policer_statuses()` â€“ returns statuses, used internally.
  - CLI: `pkg/cli/` â€“ `show firewall filter` displays term counters, but grep `three_color|policer` in pkg/cli â†’ no hits. Policer status not shown.
  - Prometheus: `grep -rn "three_color\|policer" userspace-dp/src/server/metrics.rs` â€“ no hits. No `xpf_filter_policer_status` metric.
- Trace:
  1. Configure firewall filter with three-color policer on term.
  2. Traffic metered, status changes Greenâ†’Yellowâ†’Red based on rates.
  3. Operator runs `show firewall filter` â€“ sees packet/byte counters per term, but not current policer color.
  4. Prometheus has no policer status â€“ dashboards blind to policer state.
  5. Troubleshooting policer drops requires guessing from counter rates, not current status.
- Why it matters: Three-color policers are used for rate limiting and DDoS protection. Operators need to see current color (Green/Yellow/Red) to understand if policer is currently dropping or marking. Without visibility, they cannot tune CIR/PIR effectively.
- Fix direction: Export policer status via `FilterState::three_color_policer_statuses()` in gRPC `ShowFirewallFilter` response. Add CLI output: `Policer: green/yellow/red` per term. Add Prometheus gauge `xpf_filter_policer_status{filter="...", term="...", color="green|yellow|red"} 1`. Update `docs/firewall-filter.md`.
- Labels: `observability`, `firewall-filter`, `policer`, `ux`
- Dedup note: F1â€“F8 covered policy counters, not filter policers. N1â€“N7 covered NAT64, not filters. Not in feature-gaps.md (policers are implemented). Not duplicate.

### A2

- Title: Firewall filter `then reject` with ICMP â€“ ICMP unreachable type/code not tested
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`, `enqueue_filter_reject_reply` â€“ for non-TCP, sends ICMP unreachable (type 3) with code based on filter action.
  - File: `userspace-dp/src/afxdp/poll_descriptor/filter.rs`, `filter_terminal` â€“ calls `enqueue_filter_reject_reply` for `FilterAction::Reject`, then emits log.
  - Test: `grep -rn "enqueue_filter_reject_reply\|filter.*reject.*icmp" userspace-dp/src --include="*.rs" | head -20` â€“ 3 hits, all in non-test code. No test asserts ICMP unreachable type/code for filter reject.
  - Existing tests: `poll_descriptor_policy_deny_path_emits_rt_flow_event` tests policy reject (TCP RST), not filter reject with ICMP.
- Trace:
  1. Configure firewall filter term match protocol icmp, then reject.
  2. ICMP echo request matches filter â€“ `enqueue_filter_reject_reply` sends ICMP unreachable (type 3, code 1 = host unreachable? Or code 13 = communication administratively prohibited?).
  3. Which code is used? Code inspects `reject_reply.rs:45-67` â€“ for filter reject, uses code 13 (administratively prohibited) â€“ correct per Junos?
  4. No test asserts the ICMP type/code â€“ regression could send wrong code or no reply.
- Why it matters: Filter `then reject` should send ICMP unreachable with appropriate code so sender knows it's administratively prohibited, not just silent drop. Wrong ICMP code confuses troubleshooting. Test coverage ensures correct behavior.
- Fix direction: Add test in `afxdp/tests.rs`: filter with `then reject`, send ICMP, assert reply is ICMP type 3 code 13, and RT_FLOW event action=REJECT. Also test with TCP â€“ assert TCP RST. Also test with UDP â€“ assert ICMP unreachable.
- Labels: `test-coverage`, `firewall-filter`, `icmp`, `reject`
- Dedup note: F1â€“F8 did not cover filter reject. N1â€“N7 covered NAT64 ICMP, not filter. Not duplicate.

### A3

- Title: Host-inbound `system-services traceroute` documentation â€“ TCP traceroute not admitted
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `userspace-dp/src/afxdp/forwarding/host_inbound.rs:412-428`, traceroute service admits UDP 33434-33523 and ICMP (type 11 time exceeded, type 3 code 3 port unreachable), but NOT TCP.
  - Junos `system-services traceroute` â€“ documentation says it admits UDP traceroute probes and ICMP responses, but some operators use TCP traceroute (e.g., `traceroute -T -p 80`). Those TCP SYN packets to port 80 would NOT be admitted by `traceroute` service â€“ operator must also allow `http` or custom port.
  - Docs: `docs/host-inbound-service-matrix.md` â€“ lists traceroute UDP ports and ICMP, but does not explicitly state "TCP not included".
- Trace:
  1. Operator configures `host-inbound-traffic system-services traceroute` expecting TCP traceroute to work.
  2. TCP SYN to port 80 arrives â€“ host-inbound gate checks traceroute service â€“ TCP 80 not in UDP 33434-33523 range, not ICMP â€“ deny.
  3. Operator confused â€“ traceroute fails, but UDP traceroute works.
  4. Documentation does not explicitly say TCP excluded.
- Why it matters: Operator confusion leads to support tickets and misconfiguration. Explicit documentation prevents it. No code bug â€“ behavior is correct per Junos, just unclear.
- Fix direction: Update `docs/host-inbound-service-matrix.md` traceroute row: "Admits UDP 33434-33523 and ICMP time-exceeded/port-unreachable. TCP traceroute (e.g., port 80) is NOT admitted â€“ allow the specific TCP service (http, etc.) separately." Also add CLI help text for `traceroute` service.
- Labels: `documentation`, `host-inbound`, `traceroute`, `ux`
- Dedup note: Not in F1â€“F8, N1â€“N7. Not a code bug, just docs. Not duplicate.

### A4

- Title: Host-inbound `protocols all` with `system-services ssh` â€“ ssh should be denied but no negative test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `userspace-dp/src/afxdp/forwarding/host_inbound.rs:308`, "`protocols all` admits only the routing-protocol set (#3199) â€” it does NOT admit system services."
  - File: `userspace-dp/src/afxdp/forwarding_build/tests.rs:1707-1757`, `build_forwarding_state_protocols_all_admits_routing_not_system_services` â€“ tests that `protocols all` admits OSPF, BGP, VRRP, RIP, and NOT ssh. Good positive/negative test.
  - But what about zone with BOTH `protocols all` AND `system-services ssh`? Should admit both routing protocols AND ssh. Is there a test? Grep â€“ no test for combined protocols all + system-services.
  - Also, what about `protocols all` with `system-services ssh` but ssh denied by mistake? The test above covers protocols all alone, not combined.
- Trace:
  1. Configure zone with `host-inbound-traffic protocols all` and `system-services ssh`.
  2. OSPF packet (proto 89) â€“ admitted by protocols all â€“ correct.
  3. SSH packet (tcp/22) â€“ admitted by system-services ssh â€“ correct.
  4. HTTP packet (tcp/80) â€“ NOT admitted by either â€“ deny â€“ correct.
  5. No test asserts combined behavior â€“ regression in combined token set could break.
- Why it matters: Operators commonly combine `protocols all` (for routing) with specific system services (ssh, ping) for management. The combined token set must work correctly. Test coverage ensures no regression.
- Fix direction: Add test in `forwarding_build/tests.rs`: zone with `protocols all` + `system-services ssh ping`, assert OSPF/BGP/VRRP/RIP admitted, ssh/ping admitted, http denied. Also test that `protocols all` alone does NOT admit ssh (already covered, but keep).
- Labels: `test-coverage`, `host-inbound`, `protocols-all`
- Dedup note: F1â€“F8 did not cover host-inbound. N1â€“N7 did not. Existing test covers protocols all alone, not combined. Not duplicate.

### A5

- Title: AppCatalog lookup with NAT64 translated port â€“ no test for port preservation
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `userspace-dp/src/policy.rs:2121-2138`, `lookup_admitted` â€“ directional resolution, uses dst port for forward, src port for reverse.
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2226-2229`, app_id resolved using `flow.forward_key.dst_port` (post-DNAT, post-NAT64?).
  - NAT64 preserves port (IPv6 port â†’ IPv4 port same number) â€“ correct per RFC 6146.
  - But what if NAT64 port translation were added in future? AppCatalog lookup uses post-translation port â€“ correct for session, but is there a test? Grep `nat64.*app|app.*nat64` â€“ no hits.
- Trace:
  1. v6 client sends TCP to [64:ff9b::8.8.8.8]:80, NAT64 translates to 8.8.8.8:80 (port preserved).
  2. Session app_id resolved via `lookup_admitted(tcp, src_port, 80)` â€“ matches junos-http â€“ correct.
  3. If NAT64 ever did port translation (not currently), app_id would use translated port â€“ correct.
  4. No test asserts NAT64 + application matching â€“ regression risk if NAT64 changes.
- Why it matters: Application identification for NAT64 flows is important for logging and policy (though policy uses pre-NAT64? Actually policy uses post-translation dest, so app matching should use post-translation port). Test ensures correctness.
- Fix direction: Add test in `afxdp/tests.rs` or `policy_tests.rs`: NAT64 flow with TCP 80, assert session app_id = junos-http. Also test with custom app on non-standard port.
- Labels: `test-coverage`, `nat64`, `appid`
- Dedup note: N1 covered NAT64 ICMP policy, not app_id. Not duplicate.

### A6

- Title: policymatch with empty string zone name falls to default but no test
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `pkg/policymatch/policymatch.go:1006-1017`, `zoneKnown` â€“ returns false if zone name not in cfg.Security.Zones.
  - File: `pkg/policymatch/policymatch.go:757-759`, if !zoneKnown(from) or !zoneKnown(to) â†’ default policy.
  - Empty string "" is not a defined zone â€“ zoneKnown returns false â€“ falls to default â€“ correct.
  - Test: grep `zoneKnown|empty.*zone|""` in policymatch_test.go â€“ no test for empty string zone.
  - What about query with FromZone="" and ToZone="trust"? Should fall to default, not match any zone-pair or global with empty scope? Global with empty scope matches any, but zoneKnown check happens before global tier, so empty zone falls to default before global â€“ correct per #3355 (unknown zone = no zone, ineligible for global).
- Trace:
  1. Query `Match(cfg, Query{FromZone:"", ToZone:"trust", ...})`.
  2. `zoneKnown("", cfg)` â†’ false (empty not defined).
  3. Returns default policy â€“ correct, empty zone is unknown.
  4. No test asserts this â€“ if zoneKnown mistakenly returned true for empty, query could match global or wildcard â€“ security bypass.
- Why it matters: Empty zone name could occur from misconfiguration or API misuse. Falling to default deny is safe. Test ensures the safe behavior.
- Fix direction: Add test in `policymatch_test.go`: query with empty FromZone, empty ToZone, both empty â€“ assert default policy used, not zone-pair or global. Also test with FromZone="any" (explicit any) vs "" (empty) â€“ "any" is a wildcard, "" is unknown â€“ different behavior.
- Labels: `test-coverage`, `security-policies`, `zone-handling`
- Dedup note: F1 covered global scope tests, not empty zones. Not duplicate.

### A7

- Title: Session limit â€“ unconfigured zone never drops â€“ intentional but undocumented
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1819-1827`, `new_flow_session_limit_drop` â€“ calls `worker_ctx.forwarding.session_limit_src_count` etc., which return 0 if zone not in session limit map.
  - File: `userspace-dp/src/session/mod.rs:712-718`, `session_limit_src_count` â€“ returns 0 if zone not configured.
  - Result: unconfigured zone (no session limit configured) never drops on session limit â€“ correct per code, but is it intended? Junos session limit is per-zone, if not configured, no limit â€“ correct.
  - However, what about a zone that IS configured for session limit, but the specific source IP is not in the map yet â€“ count is 0, under limit â€“ correct.
  - Documentation: `docs/` â€“ grep "session limit" â€“ `docs/feature-coverage.md` mentions "per-source / per-destination session limiting" but not the unconfigured zone behavior.
  - Test: `new_flow_session_limit_tests::unconfigured_zone_never_drops` â€“ exists! Good, behavior is tested and intentional.
- Trace:
  1. Zone "trust" not configured for session limit.
  2. New flow from trust â€“ `session_limit_src_count("trust", ip)` â†’ 0 (not in map).
  3. Under limit â€“ permit â€“ correct, no limit configured.
  4. Test exists, but documentation does not explicitly state "unconfigured zone = no limit".
- Why it matters: Operators might expect a default session limit for all zones, but unconfigured means unlimited. Documentation clarity prevents confusion. No code bug.
- Fix direction: Update `docs/feature-coverage.md` session limit section: "Per-zone source/destination session limits. Zones not configured for session limiting have no limit (unlimited). Use `show security flow session summary` to view per-zone counts." Also add to `docs/config-schema.md`.
- Labels: `documentation`, `session-limit`, `ux`
- Dedup note: Not in F1â€“F8, N1â€“N7. Test exists, just docs. Not duplicate.

---

## 7. Suggested issue split

**Test coverage:**
- A2 â€“ Firewall filter `then reject` ICMP type/code test
- A4 â€“ Host-inbound `protocols all` + system-services combined test
- A5 â€“ AppCatalog lookup with NAT64 translated port test
- A6 â€“ policymatch empty string zone name test

**Observability / UX:**
- A1 â€“ Firewall filter three-color policer status export (CLI + Prometheus)
- A3 â€“ Host-inbound traceroute documentation (TCP not admitted)
- A7 â€“ Session limit unconfigured zone documentation

All 7 are Low severity, Medium/Low confidence, no active bypass. They complement prior campaigns which covered policy matching, NAT64, and core firewall behavior.

**Recommendation:** Land test-coverage issues first (A2, A4, A5, A6) â€“ they lock filter reject, host-inbound combined tokens, NAT64 app_id, and zone handling. Then observability/docs (A1, A3, A7).

---

*End of avo-review-002 â€“ 2026-07-06*
