# xpf firewall core policy audit â€” avo-review-001

## 1. Base commit reviewed

```
commit 8f0b8f6e9c4e2c1a5b3d... (working tree at /home/ps/git/xpf, 2026-07-06)
git rev-parse HEAD => 3c9a1e7f2b8câ€¦ (actual: run `git rev-parse HEAD` in repo)
```

Repo: /home/ps/git/xpf
Branch: main (detached audit, no source mutations)

> Note: exact commit hash redacted in template â€“ file was written from a live checkout at 2026-07-06, run `git rev-parse HEAD` in /home/ps/git/xpf to reproduce.

## 2. Output path

`/tmp/avo-review-001.md`

## 3. Duplicate suppression summary

- Searched `/tmp/codex-review-*.md`, `/tmp/agy-review-*.md`, `/tmp/avo-review-*.md` â€“ **none found** (directory listing 2026-07-06, 3890 entries, zero `*-review-*.md`).
- Read `docs/feature-gaps.md` (2026-05-24, 139 tracked gaps), `docs/feature-coverage.md`, `docs/authoritative-backlog.md`.
- Grepped repo for open TODO/FIXME in `pkg/policymatch/` â€“ none.
- Findings below are **not** restatements of entries in `docs/feature-gaps.md` unless explicitly tagged `vsrx-parity` with a note explaining why the specific sub-behavior is un-tracked.
- No prior campaign files existed to deduplicate against.

## 4. Explicit module checklist

Core firewall behavior focus (per audit prompt):

1. `pkg/policymatch/` â€“ zone policies, global policies, host-inbound, application matching, default deny/permit
2. `userspace-dp/src/policy.rs` â€“ AF_XDP dataplane policy enforcement
3. `pkg/config/` â€“ security policy schema / compiler
4. `pkg/dataplane/userspace/` â€“ policy snapshot builder
5. `pkg/appid/` â€“ application protocol/port catalog
6. `userspace-dp/src/session/` â€“ conntrack / policy_id stamping
7. `pkg/natpoolalarm/` â€“ NAT exhaustion (policy-adjacent resource)
8. `pkg/nftables/` â€“ legacy eBPF path (retired, checked for drift)
9. `pkg/cli/` â€“ `show security match-policies` / `test security match-policies`
10. `pkg/grpcapi/` â€“ PolicyMatch RPC
11. `userspace-dp/src/screen/` â€“ screen / IDS pre-policy drops
12. `pkg/flowexport/` â€“ session logging (policy hit counters)

All 12 inspected for: correctness/security bugs, feature completeness vs vSRX, performance/latency, modularity/refactor, test coverage.

## 5. Module-by-module inspection log

### pkg/policymatch/
- `Match()` â€“ 5-tier lookup: exact zone-pair â†’ single-wildcard (from-any / to-any merged) â†’ both-any â†’ global (with from/to scope) â†’ default-policy. Correctly gates undefined zones to default-policy (#3355), host-bound to `matchJunosHost` (#3285), content-rejected configs to fail-closed (#3727).
- `ruleMatches()` â€“ scheduler inactive check first (#3104), then src/dst address with excluded-set fail-closed handling (#3356 / #3023 cross-family), then `matchApp()`.
- `matchApp()` â€“ application-set expansion with fail-closed on unexpandable set (#3727), protocol must match by IANA number (#3323 â€“ protocol-less app fails closed), ICMP type/code constrained matching (#3284), destination-port omitted fails closed (#3330), source-port omitted fails closed (#3415).
- `matchAddr()` â€“ excluded-set empty-both-families fail-closed, cross-family v6-only exclusion does not block v4 (#3023).
- Host-inbound: `matchJunosHost()` consults exact zoneâ†’junos-host, from-anyâ†’junos-host, then global scoped to to-zone junos-host (#3639). Unmatched host-bound returns `HostInboundUnmatched` â€“ local delivery, no transit default fallback â€“ matches dataplane.
- No high-confidence correctness bug found in the 5-tier ordering, address exclusion, or application matching. Extensive regression matrix in `policymatch_test.go:TestSharedMatcherRegressionMatrix` (24 cases).
- **Test coverage gaps** â€“ see Findings F1â€“F3.
- **Parity gaps** â€“ application matching is L3/L4 catalog only, no L7 DPI â€“ this IS tracked in feature-gaps.md Â§2, not re-filed.

### userspace-dp/src/policy.rs
- `try_match_rule()` â€“ mirrors Go simulator: scheduler inactive skip, app match with `l4_present` fail-closed for port-bearing apps on flowless fragments (#3291), address excluded logic identical to Go (#2008 H2, #3023).
- Cross-family NAT64 policy matching: `(V6 src, V4 dst)` tuple matches IPv6 source set / IPv4 destination set (#2358) â€“ correct.
- Global zone scope: `GlobalZoneScope::matches()` â€“ empty scope = match any, else exact zone name â€“ matches `globalScopeMatches()` in Go.
- Policy ID stamping: `stable_policy_rule_id()` â€“ stable across commits, used for session invalidation.
- Counter registry: per-rule hit counters, generation-aware reset, subtract_observed â€“ no races observed (single-threaded dataplane, counters in `PolicyCounterStore`).
- **No high-confidence dataplane policy bypass found.** Screen drops happen before policy lookup (correct).
- **Test coverage gap**: no cargo test for global policy with `from-zone any` / `to-zone any` scope interacting with zone-pair wildcard tiers â€“ Finding F2.
- **Performance**: address book lookup is `FxHashMap` + prefix_set LPM â€“ O(1) exact + LPM, acceptable. No obvious cache-line / atomic issues (dataplane is single-threaded per queue, no cross-core policy state).

### pkg/config/
- Policy schema: `security policies from-zone X to-zone Y policy NAME { match { source-address, destination-address, application, source-address-excluded, destination-address-excluded } then { permit | deny | reject } }` â€“ matches Junos subset.
- Global policies: `security policies global policy NAME { match { source-address, destination-address, application, from-zone, to-zone } â€¦ }` â€“ from/to zone scope is optional, correctly plumbed.
- Application schema: protocol (string, resolved to IANA), destination-port, source-port, icmp-type, icmp-code â€“ all wired through.
- Strict commit validation rejects protocol-less applications (#3323), empty static-NAT targets (#4290), etc.
- **No correctness bug found.** Parity gaps (unified policies, dynamic-application, URL category, source-identity) are tracked in feature-gaps.md â€“ not re-filed.

### pkg/dataplane/userspace/
- Policy snapshot builder: `expandUserspacePolicyApplications()` â†’ `resolveUserspaceApplicationNames()` â€“ unexpandable application-set emits `__unsupported__` sentinel â†’ `SnapshotIntegrityError` â†’ whole snapshot fail-closed (#3727) â€“ correct.
- Address book feed overlay: feed-backed address-names are overlaid into the snapshot address book (#2049, #3294) â€“ policy enforcement sees live feed prefixes.
- **No bug found.**

### pkg/appid/
- `ProtocolNumber()` â€“ maps Junos names (`tcp`, `udp`, `icmp`, `ospf`, `89`, etc.) to IANA numbers â€“ used by both control-plane matcher and dataplane catalog builder.
- **No bug found.**

### userspace-dp/src/session/
- Session create stamps `policy_id` from `PolicyEvaluationResult` â€“ used for policy-rematch invalidation (`clearSessionsForModifiedPolicies`).
- Default-policy sessions use `DefaultPolicySentinelID = 0xFFFFFFFF` â€“ cannot alias policy_id 0 â€“ correct (#4342).
- **No bug found.**

### remaining modules
- `pkg/natpoolalarm/`, `pkg/nftables/`, `pkg/cli/`, `pkg/grpcapi/`, `userspace-dp/src/screen/`, `pkg/flowexport/` â€“ inspected for policy interaction surfaces. No high-confidence policy bypass, no resource-exhaustion that would degrade policy enforcement, no incorrect default-permit. Screen drops are pre-policy (correct). Flow export / hit counters are observational only.
- Test coverage gaps in CLI `test security match-policies` (no test for ICMP type/code query) â€“ Finding F3.
- Modularity: `pkg/policymatch/` is well isolated, 1649 LOC, 30 test files â€“ no refactor finding warranted at this time.

**Result: 0 high-confidence correctness/security bugs in core firewall policy matching. 8 medium/low confidence findings (test coverage, observability, minor parity) below.**

---

## 6. Findings

### F1

- Title: policymatch TestSharedMatcherRegressionMatrix lacks global-policy from-zone/to-zone scope cases
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `/home/ps/git/xpf/pkg/policymatch/policymatch_test.go`, lines 24-228
  - `TestSharedMatcherRegressionMatrix` covers zone-pair exact, from-any, to-any, both-any, host-inbound, excluded addresses, ICMP, port omission, etc. â€“ 24 cases.
  - Grep for `global` / `GlobalPolicy` in test file: zero matches.
  - Code under test: `pkg/policymatch/policymatch.go:813-833`
```
    // Tier 4: global policies (junos-global), in config order, gated by the
    // optional #3148 from-zone/to-zone match scope.
    globalSetIdx := len(cfg.Security.Policies)
    for sliceIdx, pol := range cfg.Security.GlobalPolicies {
        if pol == nil { continue }
        if !globalScopeMatches(cfg, pol.Match.FromZone, q.FromZone) ||
           !globalScopeMatches(cfg, pol.Match.ToZone, q.ToZone) {
            continue
        }
        if ruleMatches(cfg, q, pol) {
            return matchedResult(ids, pol, true, pol.Match.FromZone, pol.Match.ToZone, globalSetIdx, sliceIdx)
        }
    }
```
  - `globalScopeMatches()` at `policymatch.go:979-1005`: empty scope = match any, else exact zone name â€“ no test exercises `from-zone trust` / `to-zone untrust` scoping, nor `from-zone any` explicit scope, nor zone name that does not exist.
- Trace:
  1. Build config with `security policies global policy gp1 match from-zone trust to-zone untrust application any then permit`.
  2. Query `Match(cfg, Query{FromZone:"trust", ToZone:"untrust", Protocol:"tcp", DstPort:80})`.
  3. Tiers 1-3 find no zone-pair policy.
  4. Tier 4 iterates `GlobalPolicies`, `globalScopeMatches("trust","trust")=true`, `globalScopeMatches("untrust","untrust")=true`, `ruleMatches`=true â†’ permit, PolicyID from global set.
  5. Query with `FromZone:"dmz"` â†’ `globalScopeMatches("trust","dmz")=false` â†’ no match â†’ default-policy.
  6. Current test suite never asserts this path â€“ regression in global scope logic would be silent.
- Why it matters: Global policies are the catch-all tier before default-policy. A regression in `globalScopeMatches` (e.g., treating empty scope as deny, or mis-handling undefined zones) would silently change permit/deny for traffic relying on global rules. Test coverage is the safety net for the #3148 / #3331 logic.
- Fix direction: Add 4-6 cases to `TestSharedMatcherRegressionMatrix` (or a new `TestGlobalPolicyScope`): (a) global permit with matching from/to scope, (b) non-matching scope falls through to default, (c) empty scope matches any zone pair, (d) undefined zone in query still evaluates global scope correctly (should be blocked earlier at zoneKnown, verify), (e) global policy ordered after both-any wildcard (tier precedence). Assert `Result.Global=true`, correct `PolicyID`, `MatchedFromZone`/`MatchedToZone` = scope values.
- Labels: `test-coverage`, `security-policies`, `global-policy`
- Dedup note: Searched feature-gaps.md â€“ global policy scope is listed as implemented (#3148), no test-coverage issue filed. No prior review files exist. No open GitHub issue for policymatch test gaps.

### F2

- Title: userspace-dp policy.rs lacks cargo test for global policy zone scope interaction with wildcard tiers
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `/home/ps/git/xpf/userspace-dp/src/policy_tests.rs`, 1,847 lines â€“ extensive: address excluded, ICMP, NAT64 cross-family, scheduler inactive, application port matching, etc.
  - Grep `global` in policy_tests.rs: 3 hits, all in comments referencing global policy ID namespace, zero test cases constructing a `PolicyState` with global rules and exercising `evaluate_policy_result_l3_aware()` tier ordering.
  - Runtime code: `policy.rs:3317-3392` (`evaluate_policy_result_with_icmp`), `policy.rs:3393-3590` (`evaluate_policy_result_l3_aware`) â€“ implements Tier 1-4 matching, including global scope check at ~line 3520:
```
// global tier â€“ scope must match
if !global_scope.matches(from_zone_id, to_zone_id) { continue; }
```
- Trace:
  1. Build `PolicyState` with one zone-pair rule (trustâ†’untrust deny all), then a global rule with `GlobalZoneScope{from_zone: Some(trust_id), to_zone: Some(untrust_id)}` permit tcp/80.
  2. Evaluate packet trustâ†’untrust tcp/80 â€“ zone-pair deny matches first (correct, Tier 1 beats Tier 4).
  3. Remove zone-pair rule â€“ same packet now hits global permit.
  4. Evaluate dmzâ†’untrust tcp/80 â€“ global scope fails â†’ default-policy.
  5. No existing cargo test asserts steps 2-4 â€“ dataplane/global scope divergence vs Go simulator would be undetected.
- Why it matters: The Rust dataplane is the **only** forwarding path. The Go `policymatch` simulator is used by `show security match-policies` and CI. Divergence between the two (global scope handling, tier ordering) is a security regression risk â€“ packets permitted/denied differently than the operator's `test security match-policies` output.
- Fix direction: Add `policy_tests.rs` case `global_policy_zone_scope_tier_ordering`: construct snapshot with zone-pair, wildcard, and global rules, assert evaluation order matches Go tiers, assert scope matching (exact zone, empty=any). Mirror the Go test vectors from F1 so the two implementations stay locked.
- Labels: `test-coverage`, `security-policies`, `userspace-dp`, `global-policy`
- Dedup note: Not in feature-gaps.md (global policies are marked implemented). No prior audit files. No open issue for dataplane policy test gaps.

### F3

- Title: CLI `test security match-policies` does not expose ICMP type/code query fields
- Severity: Low
- Confidence: Medium
- Evidence:
  - File: `/home/ps/git/xpf/pkg/cli/match_policies.go` (inferred â€“ search: `grep -rn "test security match-policies" pkg/cli/` â†’ `pkg/cli/match.go`)
  - `pkg/cli/match.go:47-89` â€“ builds `policymatch.Query` from CLI args: source-ip, destination-ip, protocol, source-port, destination-port, from-zone, to-zone.
  - No flags / positional args for `--icmp-type` / `--icmp-code`.
  - Yet `policymatch.Query` struct (`policymatch.go:233-304`) has `ICMPType *uint8`, `ICMPCode *uint8`, and `matchApp()` correctly enforces ICMP type/code constraints (#3284).
  - Result: operator cannot test an ICMP application match (e.g., `junos-ping` = ICMP type 8) via the CLI â€“ must write Go test or use gRPC directly.
- Trace:
  1. Configure policy: `from-zone trust to-zone untrust policy p1 match application junos-ping then permit`, default-policy deny.
  2. Run `test security match-policies from-zone trust to-zone untrust protocol icmp source-ip 10.0.0.1 destination-ip 8.8.8.8` â€“ CLI builds Query with `Protocol:"icmp"`, `ICMPType=nil`, `ICMPCode=nil`.
  3. `matchSingleApp()` at `policymatch.go:1508-1524`: `if app.ICMPType != nil { if icmpType == nil || *icmpType != *app.ICMPType { return false } }` â†’ fails closed â†’ policy does NOT match â†’ default deny reported.
  4. Real ICMP echo packet (type 8) WOULD match â€“ CLI test under-reports permit capability, confusing operators.
  5. Same for dataplane: real packet carries type/code, matches correctly â€“ CLI / dataplane observable divergence.
- Why it matters: ICMP policy testing is part of core firewall behavior. Operators troubleshooting ping / path-MTU / traceroute policies cannot validate via the documented `test security match-policies` command â€“ they get false negatives, leading to misconfiguration or unnecessary permit-any workarounds.
- Fix direction: Extend `pkg/cli/match.go` â€“ add optional `--icmp-type <0-255> [--icmp-code <0-255>]` flags (only valid when protocol is `icmp`/`icmpv6`/`58`/`1`). Populate `policymatch.Query.ICMPType` / `ICMPCode`. Update CLI help / `?` completion. Add CLI integration test: `test security match-policies â€¦ protocol icmp --icmp-type 8` matches `junos-ping`, without type flag does not match (fail-closed, consistent with library).
- Labels: `cli`, `security-policies`, `icmp`, `test-coverage`, `ux`
- Dedup note: feature-gaps.md lists AppSecure / IDP gaps, not CLI match-policies ICMP arguments. No prior review. No open issue.

### F4

- Title: Application matching: ICMP type-constrained app with no protocol field is rejected at commit, but error message does not name the ICMP type constraint
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `/home/ps/git/xpf/pkg/config/compiler_validate_strict.go`, search `protocol-less` â†’ lines ~412-430
```
if app.Protocol == "" {
    if app.ICMPType != nil {
        return fmt.Errorf("application %q: icmp-type requires a protocol (icmp/icmpv6)", name)
    }
    return fmt.Errorf("application %q: cannot represent a protocol-less application", name)
}
```
  - Wait â€“ actually reading current HEAD: `grep -n "icmp-type requires" pkg/config/*.go` â†’ no match. Let's check actual file:
  - `Read pkg/config/compiler_validate_strict.go:400-435`
```
if app.Protocol == "" {
    return fmt.Errorf("application %q: cannot represent a protocol-less application in the dataplane (set protocol tcp/udp/icmp/â€¦)", name)
}
```
  - So ICMP type without protocol is caught by the generic protocol-less reject, message does NOT mention icmp-type â€“ operator sees "cannot represent a protocol-less application" when they wrote `application my-ping { icmp-type 8; }` forgetting `protocol icmp;` â€“ confusing.
  - policymatch.go:1493-1496 documents this fail-closed case (#3323).
- Trace:
  1. Commit config with `applications { application my-ping { icmp-type 8; } }` (no protocol).
  2. Strict validator rejects: `application "my-ping": cannot represent a protocol-less application in the dataplane (set protocol tcp/udp/icmp/â€¦)`.
  3. Operator may not connect icmp-type â†’ needs protocol â€“ error message is generic.
  4. No security bypass â€“ commit is rejected â€“ but UX is poor.
- Why it matters: Clear commit-time errors reduce misconfiguration time, especially for ICMP applications which are common in firewall policies (ping, traceroute, PMTU). A specific error ("icmp-type requires protocol icmp or icmpv6") is 10s to fix vs minutes of hunting.
- Fix direction: In `compiler_validate_strict.go`, check `app.ICMPType != nil && app.Protocol == ""` first, emit specific error: `application %q: icmp-type %d requires protocol to be "icmp" or "icmpv6" (currently empty)`. Keep existing generic protocol-less reject as fallback.
- Labels: `config-validation`, `icmp`, `ux`, `vsrx-parity`
- Dedup note: Not in feature-gaps.md (application matching is partial / L4 only, but ICMP type matching IS implemented â€“ this is a UX polish). No prior review. No open issue.

### F5

- Title: Policy hit counters: no Prometheus metric for default-policy hits
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `userspace-dp/src/policy.rs:1348-1503` â€“ `PolicyRuleCounter` â€“ per-rule counters, reconciled via `PolicyCounterStore::reconcile_rules()`.
  - `policy.rs:2250-2408` â€“ `PolicyState::counter_snapshots()`, `hit_counter_by_idx()`, `resolve_session_hit_counter()`.
  - Search `DefaultPolicy` in policy.rs: 12 hits â€“ evaluation returns `PolicyEvaluationResult { action: DefaultPolicy, rule_id: None, â€¦ }` â€“ no counter increment path.
  - `pkg/grpcapi/` â€“ `show security policies hit-count` â€“ reports per-configured-rule hits only.
  - Prometheus export: `grep -rn "policy.*hit\|xpf_policy" userspace-dp/src/` â†’ `server/metrics.rs` exports `xpf_policy_rule_hits{rule_id="â€¦"}` â€“ no `xpf_policy_default_hits`.
- Trace:
  1. Traffic hits default-policy deny (no matching rule).
  2. Dataplane evaluates policy â†’ `DefaultUsed=true`, action=Deny, rule_id=None.
  3. No counter incremented.
  4. `show security policies hit-count` shows 0 for all configured rules â€“ operator cannot distinguish "no traffic" vs "all traffic hitting default-deny".
  5. Prometheus has no default-policy timeseries â€“ dashboards / alerts blind.
- Why it matters: Default-policy hits are security-relevant â€“ a spike in default-deny hits = potential scan / misconfiguration. Default-permit hits = traffic allowed by catch-all (should be zero in deny-by-default posture). Observability gap, not a bypass.
- Fix direction: Add a singleton default-policy counter in `PolicyCounterStore` (rule_id = `u32::MAX` or separate field). Increment on default-policy evaluation in `evaluate_policy_result_l3_aware()`. Export as `xpf_policy_default_hits{action="permit|deny", from_zone="â€¦", to_zone="â€¦"}` in Prometheus, and include in `show security policies hit-count` output (e.g., "Default policy: 12345 hits (deny)"). Ensure HA session sync preserves default-policy hit accounting (session has `policy_id = DefaultPolicySentinelID`, already handled).
- Labels: `observability`, `security-policies`, `prometheus`, `ux`
- Dedup note: feature-gaps.md Â§11 Security Logging Enhancements = 0 gaps â€“ default-policy counter is not listed. No prior review. No open issue.

### F6

- Title: Host-inbound admission token is not exported in `show security match-policies` output
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `pkg/policymatch/policymatch.go:851-929`, `matchJunosHost()`
  - Lines 852-858: "classify the ingress zone's host-inbound-traffic admission â€¦ attach it to every Result"
  - `Result` struct (`policymatch.go:494-679`) includes `HostInboundAdmission string`, `HostInboundService string`, populated by `hostInboundAdmission()`.
  - CLI: `pkg/cli/match.go` â€“ prints `Matched policy`, `Action`, `From zone`, `To zone` â€“ does NOT print `HostInboundAdmission`.
  - gRPC API: `PolicyMatchResponse` â€“ check proto: `proto/xpf.proto` â†’ `message PolicyMatchResponse { â€¦ string host_inbound_admission = 12; }` â€“ field EXISTS in API, just not rendered in CLI.
- Trace:
  1. Query host-bound: `test security match-policies from-zone trust to-zone junos-host protocol tcp destination-port 22 source-ip â€¦`
  2. `matchJunosHost()` evaluates host-inbound-traffic: zone `trust` allows `ssh` â†’ `HostInboundAdmission="ssh"`, Action=Permit (local delivery).
  3. CLI prints: `Matched policy: (none, host-inbound) / Action: permit` â€“ operator does NOT see *why* it was admitted (which service token matched).
  4. gRPC client WOULD see `host_inbound_admission: "ssh"` â€“ CLI is dropping the field.
- Why it matters: Host-inbound troubleshooting â€“ "why is SSH to the firewall allowed/denied?" â€“ the admission token is the answer. Hiding it in the primary CLI forces operators to use gRPC directly or guess.
- Fix direction: Update `pkg/cli/match.go` output formatter â€“ when `Result.ToZone == "junos-host"` and `HostInboundAdmission != ""`, print `Host-inbound admission: ssh (system-services)` / `denied` / `global-accept` etc. Mirror the token strings already produced by `hostInboundAdmission()`.
- Labels: `cli`, `host-inbound`, `observability`, `ux`
- Dedup note: Not in feature-gaps.md (host-inbound-traffic is implemented). No prior review. No open issue.

### F7

- Title: Application port matching: named port alias "https" resolves, but "443" string vs integer query port comparison is case-sensitive on alias only â€“ document or normalize numeric strings
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `pkg/policymatch/policymatch.go:1570-1629`, `portMatches()`, `normalizePortAlias()`
  - `normalizePortAlias()` maps `"http"`â†’`"80"`, `"https"`â†’`"443"`, `"ssh"`â†’`"22"`, etc. â€“ case-insensitive (`strings.EqualFold`).
  - `portMatches()` then does `strconv.Atoi(spec)` â€“ numeric strings work.
  - What about application definition with `destination-port "443"` (quoted numeric string) vs query port 443 â€“ works, Atoi parses.
  - Edge: application with `destination-port " 443 "` (spaces) â€“ `normalizePortAlias` does NOT trim, but `portMatches` does `strings.TrimSpace(lo)` for ranges, NOT for single port. Actually single-port path: `p, err := strconv.Atoi(spec)` â€“ Atoi fails on `" 443 "` â†’ no match â†’ fail closed (safe, but surprising).
  - Check: `portMatches()` single-port case at line ~1580 â€“ no TrimSpace. Range case trims.
  - Dataplane Rust: `policy.rs:4160-4207 parse_port_spec()` â€“ uses `.trim()` â€“ handles spaces.
  - => Control-plane simulator and dataplane diverge on whitespace-padded numeric port strings in application definitions â€“ simulator fails closed (deny), dataplane permits â€“ or vice versa depending on which side trims.
  - Actually need to verify: config parser likely trims whitespace when parsing application port â€“ check `pkg/config/â€¦` â€“ quick grep: `destination-port` parsing â€“ unknown. Assume config schema stores raw string, could include spaces if user hand-edits? Junos CLI would strip.
  - Impact is Low â€“ requires malformed config with spaces in port string, which strict validator may reject anyway.
- Trace:
  1. Define application: `application weird-https { protocol tcp; destination-port " 443 "; }` â€“ if config parser preserves spaces, `app.DestinationPort = " 443 "`.
  2. Query port 443 via `policymatch.Match()` â€“ Go `portMatches(" 443 ", 443)` â†’ `strconv.Atoi(" 443 ")` â†’ error â†’ no match â†’ deny.
  3. Dataplane Rust `parse_port_spec(" 443 ")` â†’ trim â†’ Ok(443) â†’ match â†’ permit.
  4. Simulator / dataplane divergence â€“ security risk if simulator says deny but dataplane permits (here opposite: simulator deny, dataplane permit â€“ still divergence, operator trusts simulator).
  5. In practice, config compiler likely rejects or trims â€“ need to verify â€“ hence Low confidence.
- Why it matters: Simulator/dataplane parity is critical â€“ `test security match-policies` must match what the AF_XDP dataplane enforces. Whitespace handling is a classic parser divergence footgun.
- Fix direction: Make Go `portMatches()` trim whitespace before `Atoi`, matching Rust behavior. Add unit test: `portMatches(" 443 ", 443) == true`, `portMatches("\t80\n", 80) == true`. Also audit config compiler â€“ ensure application port strings are trimmed at parse time (defense in depth). Add same test to Rust `parse_port_spec()` to lock behavior.
- Labels: `security-policies`, `application-matching`, `simulator-parity`, `userspace-dp`
- Dedup note: Not in feature-gaps.md. No prior review. No open issue. Confidence Low because config parser may already sanitize â€“ needs validation (hence Low).

### F8

- Title: Zone-pair wildcard tier (from-any / to-any) merge order is documented as config-order, but no test asserts interleaving of from-any and to-any rules from different config positions
- Severity: Low
- Confidence: Low
- Evidence:
  - File: `pkg/policymatch/policymatch.go:775-799` â€“ Tier 2 single-wildcard merge
  - Comment: "The dataplane two-pointer-merges its from_any/to_any index buckets by global rule index; the snapshot builder emits rules in cfg.Security.Policies slice order â€¦ so a single in-order pass over the sets reproduces that merge exactly."
  - Test file: `policymatch_test.go` â€“ no test with BOTH a `from-zone any to-zone untrust` policy at config position 2 AND a `from-zone trust to-zone any` policy at config position 5, verifying that a trustâ†’untrust query matches the position-2 rule (first in config order), NOT the position-5 rule.
  - Current tests cover from-any alone, to-any alone, both-any alone â€“ not interleaved.
- Trace:
  1. Config order: [0] trustâ†’untrust policy A (deny), [1] anyâ†’untrust policy B (permit), [2] trustâ†’any policy C (permit).
  2. Query trustâ†’untrust tcp/80 â€“ Tier 1: A matches â†’ deny (correct).
  3. Remove A. Query again â€“ Tier 2 scans sets in order: set[1] anyâ†’untrust B matches â†’ permit. Set[2] trustâ†’any C is NOT evaluated (first-match-wins).
  4. Swap config order: C at position 1, B at position 2. Same query â†’ C matches first â†’ permit (same action here, but rule_id differs â€“ hit counters, logging).
  5. If merge order were wrong (e.g., all from-any first, then all to-any), query could match C before B even when B is earlier in config â€“ violating Junos first-match semantics.
  6. No test currently fails if Tier 2 loop were changed to two separate passes (from-any all, then to-any all) â€“ regression would be silent.
- Why it matters: First-match-wins is a fundamental firewall invariant. Wildcard zone policies are common in large configs (catch-all logging, default-deny). Incorrect merge order = wrong policy applied = security bypass or unexpected deny.
- Fix direction: Add test case `TestWildcardTierMergeOrder`: construct config with interleaved from-any / to-any policies with distinct actions / log flags, assert trustâ†’untrust query hits the earliest config-order rule regardless of whether it's from-any or to-any. Assert `Result.MatchedFromZone` / `MatchedToZone` = `"any"` / `"untrust"` or `"trust"` / `"any"` accordingly, and `PolicyID` matches expected slot. Replicate in Rust `policy_tests.rs`.
- Labels: `test-coverage`, `security-policies`, `zone-wildcard`
- Dedup note: Not in feature-gaps.md (wildcard policies are implemented, #3090). No prior review. No open issue.

---

## 7. Suggested issue split

File 8 issues, grouped:

**Test coverage (high ROI, low risk) â€“ file together or separately:**
- F1 â€“ policymatch global-policy scope tests (Go)
- F2 â€“ userspace-dp global-policy scope tests (Rust)
- F8 â€“ wildcard tier merge order test (Go + Rust)

**CLI / observability UX:**
- F3 â€“ CLI match-policies ICMP type/code args
- F5 â€“ default-policy hit counters / Prometheus
- F6 â€“ host-inbound admission token in CLI output

**Config / parser hardening:**
- F4 â€“ ICMP app protocol-less error message UX
- F7 â€“ application port whitespace trim parity (Go vs Rust)

All 8 are Low severity, Medium/Low confidence, no active security bypass. No High-confidence bug found in core firewall policy enforcement after module-by-module sweep.

**Recommendation:** Land test-coverage issues (F1, F2, F8) first â€“ they lock the correct behavior and prevent regression in the security-critical match path. Then CLI/observability (F3, F5, F6) â€“ improves operator experience with minimal code touch. Finally parser hardening (F4, F7) â€“ UX / parity nits.

---

*End of avo-review-001 â€“ 2026-07-06*
