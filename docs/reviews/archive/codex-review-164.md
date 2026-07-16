# Codex quota audit 164 - vSRX firewall policy core

Base checkout: `/home/ps/git/codex-bpfrx`  
Base commit: `04fa690cd`  
Pull result: `git pull --rebase` reported `Already up to date.`  
Output path: `/tmp/codex-review-164.md`  
Quota: at least 20 non-duplicate findings, with medium and low confidence included.

## Duplicate Suppression

Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` before inspecting. Suppressed exact repeats from:

- `/tmp/codex-review-128.md`: host-inbound parser/selector/addressless issues, ESP/AH global accept, ident-reset, host-inbound union/parser duplication.
- `/tmp/codex-review-131.md`: broad vSRX firewall policy, `junos-host`, default policy, simulator, parser/compiler surfaces.
- `/tmp/codex-review-132.md`: addressless host-inbound observability, mixed-zone/family visibility, policy diagnostic selector/transport issues.
- `/tmp/codex-review-152.md`: Rust policy snapshot integrity issues for malformed literals, duplicate IDs, invalid ICMP fields, timeout range, large O(N) scans, and policy module split.
- `/tmp/codex-review-162.md`: userspace flow-cache hit path ordering, liveness, CoS BA reclassify, VLAN key, TTL/filter replay.
- `/tmp/codex-review-163.md`: AppID attribution, scheduler republish stale enforcement, policy hit-count clear race, wildcard/global histogram slots, default-policy counter/log display gaps.
- Repo issue docs under `docs/pr/1373-retire-ebpf-dataplane/`, `docs/feature-gaps.md`, and `docs/authoritative-backlog.md`, including documented loss-priority inertness, policy-rematch extensive, policy scheduler non-goals, and family-any fixes already closed.

I did not call `gh`; this pass used repo docs and local `/tmp` audit files for suppression.

## Module Checklist

1. `userspace-dp/src/policy.rs` - cold-path policy evaluation, default-policy sentinel, scheduler inactive handling, global scopes.
2. `pkg/dataplane/userspace/policies.go` - policy ID allocation, snapshot builder, scheduler inactive bits, stable keys.
3. `pkg/daemon/daemon_policy_invalidate.go` - deleted-policy and modified-policy session clearing.
4. `pkg/config/compiler_security_policy.go` and `schema_security.go` - global policy syntax, scheduler-name, policy-rematch compile surface.
5. `pkg/dataplane/userspace/policycounters.go` - single and bulk counter readers.
6. CLI/gRPC/REST policy surfaces - `cli_show_security.go`, `server_show_policies_text.go`, `server_show_zones.go`, `api/security.go`.
7. `pkg/config/compiler_firewall.go` - family-any firewall filters and prefix-list handling.
8. `pkg/dataplane/userspace/filters.go` - prefix-list lowering semantics.
9. `pkg/nftables/host_inbound_counters.go` and `pkg/daemon/daemon_nft.go` - host-inbound kernel deny counters.
10. Rust filter engine and flow-cache hit code - checked for duplicates from reports 152/162; no new non-duplicate issue counted here.
11. Docs/plans for vSRX parity - checked to avoid known feature-gap duplicates.
12. Tests around the above - checked for direct coverage gaps where runtime bugs were found.

Modules with no new finding: Rust snapshot integrity checks in `policy.rs` now cover the failures from report 152; userspace flow-cache hit policy/filter replay issues from report 162 appear fixed; host-inbound enforcement itself stays fail-closed in the reviewed paths, with only observability collisions noted below.

## High Confidence Findings

### C164-H01 - Default-policy action/log changes do not invalidate live default-permit sessions

Impact: High security/observability. Confidence: high.

Evidence:

- Rust stamps implicit default-policy sessions with the reserved sentinel, not a configured policy ID:
  - `userspace-dp/src/policy.rs:3555-3583`
  - snippet: `policy_id: DEFAULT_POLICY_SENTINEL_ID` and `policy_counter_idx: DEFAULT_POLICY_COUNTER_IDX`.
- The Go sentinel contract is `0xFFFFFFFF`:
  - `pkg/dataplane/types.go:420-438`
- Commit-time invalidation only diffs configured policies from `PolicyIDsByStableKey`:
  - `pkg/dataplane/userspace/policies.go:254-259`
  - `pkg/daemon/daemon_policy_invalidate.go:63-82`
  - `pkg/daemon/daemon_policy_invalidate.go:286-317`

Runtime trace:

1. Config has no matching zone-pair/global policy and `security policies default-policy permit-all`.
2. A TCP flow misses every configured rule, gets `PolicyEvaluationResult.policy_id = DEFAULT_POLICY_SENTINEL_ID`, and installs as default-permit.
3. Operator commits `default-policy deny-all` or changes `default-policy-log`.
4. `deletedPolicyRuntimeIDs` and `changedPolicyRuntimeIDs` only inspect configured policy stable keys. The implicit default-policy sentinel is never inserted into either clear set.
5. Existing default-permit sessions keep forwarding until idle timeout with old log intent, even though new no-match flows are denied/logged according to the new default-policy.

Why this is not a duplicate: prior reports covered default-policy counter/log display. This is runtime invalidation of already installed default-permit sessions.

Suggested issue label: `bug`, `security`, `vsrx-parity`.

### C164-H02 - Policy ID 0, the first configured policy, is deliberately skipped by deletion and rematch clearing

Impact: High for tightened/deleted first permit policies. Confidence: high.

Evidence:

- First configured rule can have ID 0:
  - `pkg/dataplane/userspace/policies.go:194-196`
  - snippet: `return s.PolicySetID*dataplane.MaxRulesPerPolicy + s.RuleIndex`
- Deletion clear explicitly skips ID 0:
  - `pkg/daemon/daemon_policy_invalidate.go:23-43`
  - `pkg/daemon/daemon_policy_invalidate.go:69-73`
- Modified-policy rematch also skips ID 0:
  - `pkg/daemon/daemon_policy_invalidate.go:276-299`

Runtime trace:

1. First configured policy in the first policy set is `trust->untrust allow-web`; its runtime policy ID is 0.
2. A flow is admitted under this policy and the session stores policy ID 0.
3. Operator deletes `allow-web`, renames it, or changes it to deny/narrower match with `policy-rematch` enabled.
4. The deletion and modified-policy invalidation passes skip ID 0 to avoid sweeping legacy non-policy sessions.
5. The exact policy that was removed/tightened remains forwarding until idle timeout.

The code comment calls this a fail-safe under-clear, but for the first configured permit policy this is a security semantic gap. A safer design is to stop overloading 0: reserve policy ID 0 permanently, shift configured rule IDs by one, or tag session origin so non-security zero sessions are not swept.

Suggested issue label: `bug`, `security`, `vsrx-parity`.

### C164-H03 - Policy-rematch ignores scheduler binding changes even though scheduler inactive is an enforcement predicate

Impact: High for scheduled firewall policy correctness. Confidence: high.

Evidence:

- Snapshot builder stamps scheduler state into runtime rules:
  - `pkg/dataplane/userspace/policies.go:432-449`
  - snippet: `SchedulerName: schedulerName`, `Inactive: policyRuleInactive(schedulerName, activeState)`.
- Scheduler missing/inactive is explicitly fail-closed:
  - `pkg/dataplane/userspace/policies.go:1295-1317`
  - snippet: `return !ok || !active`.
- Rust drops inactive rules before matching:
  - `userspace-dp/src/policy.rs:3798-3800`
  - snippet: `if rule.inactive { return None; }`.
- Rematch diff intentionally ignores `scheduler-name`:
  - `pkg/daemon/daemon_policy_invalidate.go:320-328`
  - snippet: `scheduler-name` listed under ignored non-verdict attributes.

Runtime trace:

1. A permit policy is active because it has no scheduler or an active scheduler.
2. A long-lived flow is admitted and cached under that policy.
3. Operator commits a scheduler binding that makes the policy inactive, or changes the scheduler name from active to inactive, with `policy-rematch` enabled.
4. New flows skip the inactive rule because Rust checks `rule.inactive`.
5. Existing sessions admitted under the old active state are not cleared because `policyMatchOrActionChanged` ignores scheduler-name.
6. The appliance continues forwarding traffic through a policy that is now inactive for new lookups.

This is distinct from the prior scheduler republish stale-enforcement finding in report 163: this one is the config-diff/rematch path ignoring scheduler binding changes.

Suggested issue label: `bug`, `security`, `vsrx-parity`.

### C164-H04 - Family-any firewall filters still allow single-family prefix-list under-block

Impact: High for IPv6 under-block when operators use `family any` with IPv4-only prefix lists. Confidence: high.

Evidence:

- The family-any validator rejects literal `source-address`, `destination-address`, `icmp-type`, and `icmp-code`, but explicitly does not flag prefix-lists:
  - `pkg/config/compiler_firewall.go:428-448`
  - snippet: `source-prefix-list / destination-prefix-list reference NAMED prefix-lists that may legitimately mix v4 and v6 prefixes, so they are also not flagged here.`
- Family-any dual-compiles into both IPv4 and IPv6 pools:
  - `pkg/config/compiler_firewall.go:454-465`
- Prefix-list references are compiled into filter term scope:
  - `pkg/config/compiler_firewall.go:644-652`
- Prefix-list lowering keeps a constrained match even when the resolved set is empty:
  - `pkg/dataplane/userspace/filters.go:312-329`
  - `pkg/dataplane/userspace/filters.go:426-430`
  - `pkg/dataplane/userspace/filters.go:503-507`

Runtime trace:

1. A hierarchical or peer-synced `family any` filter has `from source-prefix-list v4-blocks` and `then discard`.
2. `v4-blocks` contains only IPv4 prefixes.
3. The validator permits the shape because a named prefix-list may be mixed-family in general.
4. The filter is installed in both inet and inet6 pools.
5. The IPv6 arm has a constrained source match but no IPv6 prefixes, so IPv6 packets match nothing and fall through to implicit accept.
6. Operator intended one family-any discard policy; IPv6 is under-blocked.

The existing literal-address gate fixed the same class for direct address literals. Prefix-lists need either a commit-time family-content check under `family any` or a split that rejects single-family prefix-lists unless both families are represented.

Suggested issue label: `bug`, `security`, `vsrx-parity`.

### C164-H05 - Text and zone policy counter surfaces still use per-policy reads despite the bulk reader

Impact: Medium/high latency under large policy sets. Confidence: high.

Evidence:

- The userspace manager documents the old per-policy pattern as O(P*(P+C)) under `m.mu`:
  - `pkg/dataplane/userspace/policycounters.go:174-203`
  - snippet: "The pre-#3965 pattern ... was O(P*(P+C)) AND held the policy mutex".
- The CLI hit-count surface still loops `ReadPolicyCounters` per rule:
  - `pkg/cli/cli_show_security.go:78-85`
  - `pkg/cli/cli_show_security.go:116-123`
  - `pkg/cli/cli_show_security.go:155-161`
- gRPC policy text does the same:
  - `pkg/grpcapi/server_show_policies_text.go:144-152`
  - `pkg/grpcapi/server_show_policies_text.go:193-201`
  - `pkg/grpcapi/server_show_policies_text.go:232-239`
- gRPC zone policy inventory also does the same:
  - `pkg/grpcapi/server_show_zones.go:216-224`
  - `pkg/grpcapi/server_show_zones.go:288-296`
  - `pkg/grpcapi/server_show_zones.go:333-339`

Runtime trace:

1. A firewall has thousands of policies and policy stats enabled.
2. An operator or automation calls `show security policies hit-count`, gRPC text, or zone inventory.
3. Each rendered rule calls `ReadPolicyCounters`.
4. Each call rebuilds the rule-counter index and rescans config under `m.mu` per the manager comment.
5. The call path can stall concurrent apply/session-management work and produces much worse tail latency than the REST/Prometheus bulk path.

Suggested issue label: `performance`, `observability`, `refactor`.

## Medium Confidence Findings

### C164-M01 - Single-policy counter reads still add retired eBPF shim counters while bulk reads intentionally do not

Impact: Medium observability inconsistency after eBPF retirement. Confidence: medium.

Evidence:

- `ReadPolicyCounters` adds `m.bpfShim.ReadPolicyCounters(policyID)` before reading helper status:
  - `pkg/dataplane/userspace/policycounters.go:129-163`
- Bulk reads intentionally skip the retired eBPF counter array:
  - `pkg/dataplane/userspace/policycounters.go:199-202`
  - snippet: "retired-eBPF bpfShim policy_counters array is intentionally NOT consulted".
- REST/Prometheus use the bulk helper for normal rows:
  - `pkg/api/security.go:154-162`
- Several text surfaces still use single-policy reads, as listed in C164-H05.

Runtime trace:

1. A node has stale pinned legacy `policy_counters` state or a shim implementation that returns non-zero values.
2. CLI/gRPC text surfaces call `ReadPolicyCounters` and add stale bpfShim values to helper-published counts.
3. REST/Prometheus rows using `ReadAllPolicyCounters` do not add those values.
4. Operators see different counts for the same policy depending on surface.

Suggested issue label: `bug`, `observability`, `ebpf-retirement`.

### C164-M02 - REST structured default-policy row bypasses the bulk reader even when configured rows use it

Impact: Medium performance/consistency. Confidence: medium.

Evidence:

- REST builds a bulk reader:
  - `pkg/api/security.go:154-162`
  - snippet: `readPolicy = dpuserspace.NewPolicyCounterReader(...)`
- The default-policy synthetic row still calls direct `ReadPolicyCounters`:
  - `pkg/api/security.go:368-374`
- Direct reads can include bpfShim totals and the O(P+C) locked work from C164-M01/H05:
  - `pkg/dataplane/userspace/policycounters.go:129-163`

Runtime trace:

1. `/api/v1/security/policies` builds a bulk snapshot for configured rows.
2. It reaches the default-policy row.
3. Instead of using the bulk closure for `DefaultPolicySentinelID`, it calls the single-policy method.
4. The default row can be counted through a different source/lock path than the rest of the response.

Suggested issue label: `bug`, `observability`.

### C164-M03 - Scoped global policies model only one from-zone and one to-zone

Impact: Medium vSRX parity/config scalability. Confidence: medium.

Evidence:

- Schema allows one `from-zone` and one `to-zone`, no `multi: true`:
  - `pkg/config/schema_security.go:259-276`
- Compiler reads only the second key or the first child:
  - `pkg/config/compiler_security_policy.go:240-257`
- Rust runtime scope type is exactly `Any` or one `Zone(u16)`:
  - `userspace-dp/src/policy.rs:1121-1130`
  - `userspace-dp/src/policy.rs:1158-1173`
- Runtime match tests one scope per side:
  - `userspace-dp/src/policy.rs:3515-3530`

Runtime trace:

1. Operator wants a vSRX-style global emergency deny scoped to multiple ingress zones and one egress zone.
2. xpf cannot represent a set of scoped global zones in one policy.
3. The operator must duplicate policies per zone, increasing rule count and cold-path scan cost.
4. Duplicated global policies also make hit-count/log attribution less ergonomic than a single scoped global rule.

Suggested issue label: `feature`, `vsrx-parity`, `refactor`.

### C164-M04 - Policy-rematch extensive is still not implemented, but the current code/comments are now internally inconsistent

Impact: Medium correctness/documentation risk. Confidence: medium.

Evidence:

- Compiler comment still says xpf performs no session invalidation on commit:
  - `pkg/config/compiler_security_policy.go:55-62`
- Invalidation code now implements deletion and modified-policy clear but explicitly excludes extensive referenced-object changes:
  - `pkg/daemon/daemon_policy_invalidate.go:120-137`

Runtime trace:

1. Operator enables `policy-rematch extensive`.
2. Address-book or application object changes while the policy text is unchanged.
3. `changedPolicyRuntimeIDs` compares only policy match/action text, not referenced object resolved content.
4. Existing sessions admitted by unchanged policy text keep forwarding with old object semantics.
5. Code comments in the compiler still overstate that no invalidation exists at all, which can mislead future maintainers and review agents.

This is partially documented in feature-gap docs; the new issue is the stale comment plus the current rematch surface needing a precise "basic implemented, extensive not implemented" invariant.

Suggested issue label: `docs`, `bug`, `vsrx-parity`.

### C164-M05 - Host-inbound deny counters intentionally merge exotic zone names

Impact: Medium security observability/forensics. Confidence: medium.

Evidence:

- The counter name sanitizer acknowledges lossy collisions:
  - `pkg/nftables/host_inbound_counters.go:51-63`
  - snippet: `"a:b" and "a+b" COLLIDE onto one counter object`.
- Counter names are generated from sanitized zone label and length:
  - `pkg/nftables/host_inbound_counters.go:64-67`
- Parser returns the sanitized token as the zone label:
  - `pkg/nftables/host_inbound_counters.go:98-115`

Runtime trace:

1. Two committed zones differ only by characters outside `[A-Za-z0-9_.-]`.
2. Host-inbound kernel-drop rules are enforced per zone/address, so forwarding remains safe.
3. The nft counter object name collides.
4. Prometheus/CLI host-inbound deny counts cannot attribute drops to the original zone.

This is an acknowledged tradeoff, but for a security appliance the audit/forensic label should be reversible. Add a short hash suffix while preserving a readable prefix.

Suggested issue label: `observability`, `security-hardening`.

### C164-M06 - Family-any prefix-list behavior lacks direct tests for single-family named lists

Impact: Medium test gap backing C164-H04. Confidence: medium.

Evidence:

- Existing family-any tests cover direct source-address and ICMP type rejection, plus family-agnostic protocol:
  - `pkg/config/compiler_firewall_family_any_match_4296_test.go` found by local search.
- The validator explicitly excludes prefix-list leaves from the family-specific map:
  - `pkg/config/compiler_firewall.go:441-448`
- Prefix-list lowering keeps a constrained empty-family match:
  - `pkg/dataplane/userspace/filters.go:426-430`

Runtime trace:

1. Regression tests can pass while the prefix-list variant of the family-any under-block remains live.
2. A future reviewer sees the literal-address fix and assumes all family-specific address scopes are handled.
3. Named prefix-list is the common operational shape, so the untested case is likely to matter.

Suggested issue label: `test`, `security`.

### C164-M07 - Policy counter bulk-reader migration is incomplete across display surfaces

Impact: Medium performance/test architecture. Confidence: medium.

Evidence:

- `NewPolicyCounterReader` exists specifically to replace looping `ReadPolicyCounters`:
  - `pkg/dataplane/userspace/policycounters.go:260-292`
- REST uses it:
  - `pkg/api/security.go:154-162`
- CLI/gRPC text and zone inventory still call `ReadPolicyCounters` directly:
  - `pkg/cli/cli_show_security.go:81`
  - `pkg/grpcapi/server_show_policies_text.go:147`
  - `pkg/grpcapi/server_show_zones.go:218`

Runtime trace:

1. Performance fix lands for one scrape/inventory path.
2. Other operator-facing paths keep the old algorithm.
3. Load testing only Prometheus/REST misses the CLI/gRPC tail-latency path.

This overlaps C164-H05 as a separate issue split: H05 is the direct performance bug, M07 is the missing architectural/test guard to force every surface through the same reader.

Suggested issue label: `test`, `refactor`, `performance`.

### C164-M08 - Scheduler policy docs still state existing sessions continue until a future rematch feature

Impact: Medium operator/documentation drift. Confidence: medium.

Evidence:

- Scheduler plan says flow-cache hits keep forwarding unless a separate policy-rematch feature is implemented:
  - `docs/pr/1373-retire-ebpf-dataplane/plan-1378-policy-schedulers.md:65-69`
- Same plan says existing sessions continue until policy-rematch is explicitly configured in a later feature:
  - `docs/pr/1373-retire-ebpf-dataplane/plan-1378-policy-schedulers.md:104-109`
- Code now has a policy-rematch implementation, but it ignores scheduler-name per C164-H03.

Runtime trace:

1. Operator or reviewer reads the plan and believes scheduler/rematch integration is intentionally deferred.
2. Code now partially implements rematch, but scheduler semantics are not included.
3. There is no crisp doc telling whether scheduled-policy session clearing is in scope now or still deferred.

Suggested issue label: `docs`, `vsrx-parity`.

## Low Confidence / Triage Findings

### C164-L01 - Reserve policy ID 0 rather than documenting under-clear forever

Impact: High if accepted, but design confidence is low because migration/HA compatibility needs planning. Shift configured policy IDs by one or add a session-origin discriminator so non-policy zero sessions are not conflated with first policy sessions.

### C164-L02 - Add a live loss-cluster smoke for default-policy permit-to-deny transitions

Unit tests can prove the invalidation set, but the security invariant is packet-visible: default-permit flow should die or re-evaluate immediately after `default-policy deny-all`.

### C164-L03 - Add a live loss-cluster smoke for scheduled policy active-to-inactive transitions

The packet-path test should pin that new sessions deny and existing sessions behave according to the documented rematch contract.

### C164-L04 - Global policy scoped-zone parity issue should be filed as `vsrx-parity`

Per the audit instruction, any global multi-zone/global-list parity issue should explicitly carry a `vsrx-parity` label rather than being buried as generic refactor.

### C164-L05 - Family-any prefix-list parity issue should be filed as `vsrx-parity`

The bug is security-relevant, but the operator-facing feature shape is also vSRX/Junos parity: `family any` with named prefix-list must not silently under-block one family.

### C164-L06 - Split `daemon_policy_invalidate.go` into a small package with table-driven invariants

Current invalidation logic is subtle enough to deserve `policyinvalidate/{ids.go,diff.go,clear.go}` plus explicit tests for sentinel, ID zero, scheduler, default policy, and referenced object changes.

### C164-L07 - Make policy counter display surfaces share one reader interface

Instead of each API surface deciding between direct/bulk, expose a `PolicyCounterReader` created once per request and make direct `ReadPolicyCounters` inaccessible to show paths except through a legacy adapter.

### C164-L08 - Add a static canary that forbids new show surfaces from calling `ReadPolicyCounters` in a per-rule loop

This would have caught CLI/gRPC text and zone inventory remaining on the old O(P*(P+C)) pattern.

### C164-L09 - Add a benchmark for policy hit-count show with 10k rules and 10k helper counters

Performance regressions here are control-plane tail-latency bugs. Benchmark both REST/Prometheus and CLI/gRPC text.

### C164-L10 - Host-inbound deny counter names should include a short hash suffix for exotic names

Keep the readable sanitized prefix, but add a stable hash of the original zone to avoid `a:b`/`a+b` merges while preserving nft-safe identifiers.

### C164-L11 - Document the exact policy-rematch support matrix in `README.md` or `feature-gaps.md`

The matrix should distinguish deleted-policy default clear, modified policy with knob, default-policy changes, scheduler changes, and extensive referenced-object changes.

### C164-L12 - Add tests for global policy `from-zone`/`to-zone` list rejection or future support

If lists are unsupported, tests should assert strict rejection with an actionable error. If supported later, the runtime type should become a small zone-set rather than duplicating policy rows.

### C164-L13 - Add an API consistency test comparing REST, gRPC, CLI, and Prometheus policy counters

The test should inject helper counters and stale bpfShim counters and assert all surfaces report the same values, including the default-policy row.

### C164-L14 - Move default-policy invalidation into the same runtime-id framework as configured policies

Treat the implicit default-policy as a first-class runtime policy identity in invalidation logic, with its own stable key and reason code, rather than special casing it only in counters/log display.

### C164-L15 - Add a structured "original zone name" side table for host-inbound metrics

If nft counter object names must stay sanitized, publish original zone/family labels from Go-side config rather than reverse-parsing sanitized counter names as source of truth.

## Suggested Issue Split

1. `bug/security/vsrx-parity`: Clear or re-evaluate default-policy sentinel sessions when default-policy action/log changes.
2. `bug/security`: Remove the policy ID 0 under-clear by reserving ID 0 or tagging session origin.
3. `bug/security/vsrx-parity`: Include scheduler-name/active-state changes in policy-rematch invalidation.
4. `bug/security/vsrx-parity`: Reject or faithfully split family-any filters with single-family prefix-lists.
5. `performance/refactor`: Route all policy counter display surfaces through the bulk reader.
6. `bug/observability/ebpf-retirement`: Remove stale bpfShim additions from userspace `ReadPolicyCounters` or isolate them to explicit legacy-only paths.
7. `feature/vsrx-parity`: Support or explicitly reject multi-zone scoped global policies.
8. `observability/security-hardening`: Make host-inbound deny counter labels collision-resistant.
9. `docs`: Publish exact policy-rematch support matrix and update stale comments/plans.
10. `test`: Add live smoke and consistency tests for default-policy, scheduler, family-any prefix-list, and cross-surface counters.

