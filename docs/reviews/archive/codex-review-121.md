# Codex Review Audit 121

## Metadata

- Agent: codex
- Output: `/tmp/codex-review-121.md`
- Repo: `/home/ps/git/codex-bpfrx`
- Command run: `git pull --rebase`
- Pull result: fast-forwarded from `9419bbc2c59e3eda4f6f258a30d1d4e62d32d9a9` to `a2c524281ded9695bc6f15fbaabd9a3b6a57f2ff`
- Worktree status after pull: clean, `master...origin/master`
- Review focus: vSRX core firewall behavior, especially zone policies, admit/deny correctness, feature completeness, operator surfaces, counters, tests, and modularity.

## Duplicate Suppression Inputs

I read prior local review files and repo issue/docs material before selecting findings:

- `/tmp/codex-review-001.md`
- `/tmp/codex-review-002.md`
- `/tmp/agy-review-001.md`
- `/tmp/agy-review-002.md`
- `/tmp/agy-review-121.md`
- `docs/issues/issue-history.md`
- `docs/issues/pr-history.md`
- `docs/feature-gaps.md`
- `docs/config-schema.md`
- `docs/junos-cli-reference.md`
- `docs/userspace-dataplane-architecture.md`
- `pkg/config/README.md`

Suppressed as already covered: host-inbound junos-host gaps, output-filter reject divergence, generated-reply VLAN classification, IPsec/host-inbound bypass classes, AppID gaps, flowless fragment gaps, screen rate/GC items, dynamic-address feed validation, operator matcher historical gap #3042, and the already-documented feature gaps for dynamic-applications, URL categories, source-identity, UTM/IDP, and policy rematch.

Important non-duplicate decision: issue #3042 was a closed operator-simulator divergence from the runtime. The main finding below is different: the Rust runtime itself appears to lack vSRX/Junos intrazone default-permit semantics.

## Module Checklist

1. Rust policy runtime: `userspace-dp/src/policy.rs`
   - Inspected exact, wildcard, both-any, global, and default tiers.
   - Findings: H01, H03, M03, M04, M08, M09, M10.

2. Go policy simulator and operator surfaces: `pkg/policymatch/policymatch.go`
   - Inspected result model, unknown-zone handling, default handling, global fallback, and host-inbound branch.
   - Findings: H02, M07, M11.

3. Config schema/compiler: `pkg/config/schema_security.go`, `pkg/config/compiler_security.go`, `pkg/config/compiler_policy_then.go`
   - Inspected policy/default-policy schema area and policy terminal action handling.
   - Negative result: terminal-action/reject issues are already in issue history. New finding is documentation/schema semantics around intrazone default.
   - Findings: M01, L01, L05.

4. Userspace snapshot/policy builder: `pkg/dataplane/userspace/policies.go`
   - Inspected runtime policy ID walker and configured-policy snapshot emission.
   - Findings: M05, M10, L10.

5. Documentation and architecture: `docs/junos-cli-reference.md`, `docs/userspace-dataplane-architecture.md`, `docs/feature-gaps.md`
   - Inspected Junos reference sample, runtime tier description, and listed gaps.
   - Findings: H01, M01, M02, M13, L11, L12.

6. Rust tests: `userspace-dp/src/policy_tests.rs`, `userspace-dp/src/afxdp/tests.rs`
   - Inspected wildcard/default-policy tests and searched for intrazone/same-zone coverage.
   - Findings: M06, L06, L07, L08, L09.

7. Go tests: `pkg/policymatch/*_test.go`, CLI/gRPC policy-related tests via search.
   - Inspected scoped-global zone-local tests and default-policy tests.
   - Findings: M07, M12.

8. Host-inbound.
   - Negative result: heavily covered by prior reports and recent fixes; no new non-duplicate issue selected this round.

9. Zone-local address books and scoped global policy.
   - Negative result: current tests cover scoped global zone-local resolution. No new non-duplicate issue selected.

10. Policy scheduler.
    - Negative result: current matcher and runtime carry scheduler inactive state and existing drift issues are closed.

11. Firewall filter/reject generated replies.
    - Negative result: existing reports and issues already cover reject/action parity and generated reply paths.

12. Screen.
    - Negative result: outside this round's firewall zone-policy focus; prior screen findings already cover rate/GC issues.

## High Confidence Findings

### H01 - vSRX intrazone default-permit is missing from the Rust runtime

- Severity: High
- Confidence: High
- Labels: `bug`, `security`, `vsrx-parity`, `firewall`, `userspace-dataplane`

Evidence:

```text
docs/junos-cli-reference.md:213-218
213 Default policy: deny-all
214 Default policy log Profile ID: 0
215 Pre ID default policy: permit-all
216 Default HTTP Mux policy: permit-all
217 From zone: trust, To zone: trust
218   Policy: default-permit, State: enabled, Index: 4, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
```

```rust
userspace-dp/src/policy.rs:2604-2631
pub(crate) fn evaluate_policy_result_l3_aware(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    ...
) -> PolicyEvaluationResult {
    if from_id != 0 && to_id != 0 {
        let key = zone_pair_key(from_id, to_id);
        if let Some(indices) = state.zone_pair_index.get(&key) {
```

```rust
userspace-dp/src/policy.rs:2726-2768
        for &idx in &state.global_indices {
            let rule = &state.rules[idx];
            if !rule.global_from_zone.matches(from_id) || !rule.global_to_zone.matches(to_id) {
                continue;
            }
            ...
        }
    }
    state.default_counter.add(packet_len);
    PolicyEvaluationResult {
        action: state.default_action,
```

Runtime trace:

1. Packet enters and exits interfaces in the same configured security zone, e.g. `trust -> trust`.
2. No explicit `from-zone trust to-zone trust` policy matches.
3. Runtime tries exact, wildcard, both-any, global, then falls through.
4. Fall-through returns the single configured `default_action`.
5. With default `deny-all`, same-zone transit is denied, while the repo's Junos reference shows a `trust -> trust` `default-permit` row.

Why it matters:

This is a core security appliance behavior mismatch. A vSRX-style deployment expects intra-zone traffic to be permitted by the zone's implicit `default-permit` unless explicitly overridden. XPF appears to apply the interzone `default-policy` instead. That can blackhole same-zone traffic and force operators to create explicit same-zone permit policies that should not be needed.

Fix direction:

Add an explicit intrazone default tier to the runtime policy evaluator. The policy order must be specified and tested: exact same-zone rules still win, then wildcard/global semantics need a deliberate Junos-compatible decision, then intrinsic intrazone `default-permit` should apply for known same-zone pairs before the interzone default-policy. Add packet-level and policy-unit tests.

### H02 - `MatchPolicies` mirrors the missing intrazone default-permit behavior

- Severity: High
- Confidence: High
- Labels: `bug`, `operator-diagnostics`, `vsrx-parity`, `firewall`

Evidence:

```go
pkg/policymatch/policymatch.go:237-247
type Result struct {
    // Matched is true when a concrete zone-pair or global policy matched. When
    // false the verdict is the configured default-policy (see DefaultUsed).
    Matched bool
    ...
    // DefaultUsed is true when no policy matched and Action is the configured
    // default-policy.
    DefaultUsed bool
```

```go
pkg/policymatch/policymatch.go:421-444
// Tier 4: global policies (junos-global), in config order, gated by the
// optional #3148 from-zone/to-zone match scope.
for sliceIdx, pol := range cfg.Security.GlobalPolicies {
    ...
}

// Tier 5: configured default-policy (NOT a hard-coded deny).
return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
```

Runtime trace:

1. Operator asks the simulator for `from-zone trust to-zone trust`.
2. No explicit same-zone policy matches.
3. The simulator reports `DefaultUsed` and returns `cfg.Security.DefaultPolicy`.
4. If the runtime is fixed without the simulator, the diagnostic will again lie. If both remain as-is, the operator gets a consistent but vSRX-incompatible denial.

Why it matters:

The tool that tells operators "why was this packet allowed or denied" would confirm the wrong behavior. This is not the old #3042 simulator gap; #3042 was about operator surfaces diverging from runtime. This one is about both simulator and runtime lacking the same vSRX intrazone concept.

Fix direction:

Extend `policymatch.Result` with an explicit default kind, e.g. `DefaultKindInterzone`, `DefaultKindIntrazone`, `DefaultKindHostUnmatched`. Update CLI/REST/gRPC rendering and tests to show `default-permit` for intrazone misses.

### H03 - Intrazone default traffic would be counted and logged as `default-policy`, not `default-permit`

- Severity: High
- Confidence: High
- Labels: `bug`, `observability`, `vsrx-parity`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs:1736-1747
/// #3363: reserved hit counter for the IMPLICIT default-policy verdict
/// (the result returned when a flow matches no configured zone-pair,
/// wildcard, or `junos-global` policy).
pub(crate) default_counter: Arc<PolicyRuleCounter>,
```

```rust
userspace-dp/src/policy.rs:2760-2793
state.default_counter.add(packet_len);
PolicyEvaluationResult {
    action: state.default_action,
    policy_id: DEFAULT_POLICY_SENTINEL_ID,
    ...
    policy_counter_idx: DEFAULT_POLICY_COUNTER_IDX,
}
```

Runtime trace:

1. Same-zone traffic misses explicit policies.
2. The runtime uses the default-policy counter and `DEFAULT_POLICY_SENTINEL_ID`.
3. Operator surfaces report default-policy hits, not the vSRX-style same-zone `default-permit` row shown in `docs/junos-cli-reference.md`.

Why it matters:

Even if admission is fixed, accounting can remain wrong. Operators need to distinguish "same-zone implicit permit" from "interzone default-policy permit/deny." Conflation weakens audits and can hide whether same-zone traffic is relying on implicit vSRX behavior.

Fix direction:

Add a separate intrazone default identity: policy ID/sentinel, counter, label, and session-log policy name. Keep interzone default-policy counters separate.

## Medium Confidence Findings

### M01 - Config/docs state "default deny matches Junos" but omit Junos intrazone default-permit

- Severity: Medium
- Confidence: Medium
- Labels: `docs`, `config`, `vsrx-parity`, `firewall`

Evidence:

```text
docs/junos-cli-reference.md:213-218
Default policy: deny-all
...
From zone: trust, To zone: trust
  Policy: default-permit, State: enabled, Index: 4
```

```text
docs/userspace-dataplane-architecture.md:610-613
exact (from,to)  ->  single-wildcard (from-any union to-any, merged in config order)
                 ->  both-any  ->  junos-global  ->  default policy
```

Runtime trace:

The architecture says every miss ends at default-policy, while the Junos reference has an additional same-zone implicit policy row.

Why it matters:

The docs encode the wrong mental model for future changes. Engineers will keep adding tests around the five-tier model and miss same-zone behavior.

Fix direction:

Document intrazone semantics explicitly in schema docs, architecture docs, and CLI reference. If XPF intentionally diverges, document it as a security-mode divergence and label it clearly.

### M02 - Architecture tier diagram has no slot where intrazone policy can be inserted safely

- Severity: Medium
- Confidence: Medium
- Labels: `architecture`, `firewall`, `vsrx-parity`

Evidence:

```text
docs/userspace-dataplane-architecture.md:610-613
exact (from,to)  ->  single-wildcard (from-any union to-any, merged in config order)
                 ->  both-any  ->  junos-global  ->  default policy
```

Runtime trace:

The runtime implementation follows this diagram: exact/wildcard/both-any/global/default. There is no documented answer for whether same-zone implicit permit is before or after wildcard/global policy.

Why it matters:

A future patch could "fix" intrazone behavior in the wrong tier. For example, adding same-zone permit before exact policy would break explicit deny overrides; adding it after global could let broad global denies override intrazone default in a way that may or may not match Junos intent.

Fix direction:

Write the intended precedence first. At minimum: exact same-zone policies must override the implicit default. Then confirm Junos behavior for wildcard and global policies against same-zone traffic and encode that in tests.

### M03 - `PolicyState` has only one default action, so it cannot represent context-specific defaults

- Severity: Medium
- Confidence: Medium
- Labels: `refactor`, `firewall`, `vsrx-parity`

Evidence:

```rust
userspace-dp/src/policy.rs:1701-1724
pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    pub(crate) rules: Vec<PolicyRule>,
    zone_pair_index: FxHashMap<ZonePairKey, Vec<usize>>,
    from_any_index: FxHashMap<u16, Vec<usize>>,
    to_any_index: FxHashMap<u16, Vec<usize>>,
    both_any_indices: Vec<usize>,
```

```rust
userspace-dp/src/policy.rs:1774-1788
impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
```

Runtime trace:

Known interzone miss and known intrazone miss both end at `state.default_action`.

Why it matters:

The data model itself encourages a single global default. vSRX-like behavior needs at least "interzone configured default-policy" and "intrazone implicit default-permit" as separate concepts.

Fix direction:

Replace the single `default_action` field with a small defaults struct, e.g. `PolicyDefaults { interzone_action, intrazone_action, ... }`, and make the evaluator return a typed default verdict.

### M04 - `PolicyEvaluationResult` can only report the default-policy sentinel, not an intrazone default

- Severity: Medium
- Confidence: Medium
- Labels: `refactor`, `observability`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs:2767-2775
PolicyEvaluationResult {
    action: state.default_action,
    // #3057: the implicit default policy carries a reserved sentinel ID,
    // NOT 0.
    policy_id: DEFAULT_POLICY_SENTINEL_ID,
```

Runtime trace:

Any non-matching same-zone session would be stamped with the same sentinel as an interzone default-policy hit.

Why it matters:

Session logs and show commands cannot produce the vSRX-style `default-permit` identity unless the result type can distinguish it.

Fix direction:

Add an enum for result source: `NamedPolicy`, `GlobalPolicy`, `DefaultInterzone`, `DefaultIntrazone`, `HostInboundUnmatched`. Use it for counters, logs, and display.

### M05 - Runtime policy ID walker emits configured policies only; no synthetic default-permit slot

- Severity: Medium
- Confidence: Medium
- Labels: `observability`, `show-command`, `vsrx-parity`

Evidence:

```go
pkg/dataplane/userspace/policies.go:243-252
func walkPolicyRuleSlots(cfg *config.Config, fn func(slot policyRuleSlot) error) error {
    if cfg == nil {
        return nil
    }
    policySetID := uint32(0)
    for _, zpp := range cfg.Security.Policies {
        if zpp == nil {
            policySetID++
            continue
        }
```

```go
pkg/dataplane/userspace/policies.go:278-295
globalRuleIndex := uint32(0)
for sliceIdx, pol := range cfg.Security.GlobalPolicies {
    ...
    if err := fn(policyRuleSlot{
        PolicySetID: policySetID,
        RuleIndex:   globalRuleIndex,
        ...
        FromZone:    "junos-global",
```

Runtime trace:

The ID namespace can enumerate configured zone-pair and global policies. It cannot enumerate a synthetic `trust -> trust default-permit` row unless another layer invents it.

Why it matters:

The Junos reference surface shows `From zone: trust, To zone: trust Policy: default-permit`. XPF show surfaces are unlikely to render that row consistently without a first-class synthetic policy slot or separate default-row model.

Fix direction:

Do not overload configured policy IDs. Add a dedicated synthetic-default row model for show/counter surfaces, or a reserved ID range for implicit defaults.

### M06 - Rust policy tests do not pin same-zone default-permit

- Severity: Medium
- Confidence: Medium
- Labels: `tests`, `firewall`, `vsrx-parity`

Evidence:

```text
rg -n "intrazone|intra-zone|same-zone|default-permit" userspace-dp/src pkg docs
userspace-dp/src/policy_tests.rs:1290: // the same zone-pair must reject the WHOLE snapshot...
userspace-dp/src/policy_tests.rs:4798: // Unresolvable match to-zone...
docs/junos-cli-reference.md:218: Policy: default-permit...
```

Runtime trace:

The test corpus has wildcard/default-policy tests but no same-zone no-policy assertion that would fail on the current fall-through-to-default-policy implementation.

Why it matters:

This is exactly the kind of vSRX parity behavior that regresses invisibly. The existing tests can all pass while same-zone traffic is denied.

Fix direction:

Add a Rust policy test: two interfaces/zones with `from_id == to_id`, no explicit policy, default-policy deny-all, expect `PolicyAction::Permit` and an intrazone default identity.

### M07 - Go `policymatch` tests do not pin same-zone simulator behavior

- Severity: Medium
- Confidence: Medium
- Labels: `tests`, `operator-diagnostics`, `firewall`

Evidence:

```go
pkg/policymatch/policymatch.go:365-366
if !zoneKnown(cfg, q.FromZone) || !zoneKnown(cfg, q.ToZone) {
    return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
}
```

```go
pkg/policymatch/policymatch.go:443-444
// Tier 5: configured default-policy (NOT a hard-coded deny).
return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
```

Runtime trace:

A same-zone query with known zones walks the normal tiers and returns the configured default-policy on miss.

Why it matters:

REST/gRPC/CLI policy-match diagnostics become a regression trap. A runtime fix can land while operator surfaces keep saying deny.

Fix direction:

Add simulator tests for `trust -> trust` with no policy and default-policy deny-all. Expected: `DefaultKindIntrazone`, action permit, policy name/rendering `default-permit`.

### M08 - Wildcard/global precedence for same-zone traffic is unspecified

- Severity: Medium
- Confidence: Medium
- Labels: `design`, `firewall`, `vsrx-parity`

Evidence:

```rust
userspace-dp/src/policy.rs:2652-2666
// #3090: wildcard-zone tiers, in Junos most-specific-first precedence
// AFTER the exact zone pair and BEFORE global/default.
...
//  Tier 2 - both-any: `from-zone any to-zone any` in config order.
```

Runtime trace:

Same-zone traffic today goes through wildcard and global tiers before default. If an intrinsic same-zone permit is introduced, the code does not say whether a broad `from-zone any to-zone any deny` should override it.

Why it matters:

This is a security semantics fork. Getting the order wrong either over-permits same-zone traffic despite explicit broad denies or over-denies traffic that Junos would permit.

Fix direction:

Build a vSRX behavior matrix before coding: exact same-zone policy, single wildcard, both-any, unconstrained global, scoped global, and final intrazone default.

### M09 - `default-policy-log` semantics are undefined for implicit intrazone permit

- Severity: Medium
- Confidence: Medium
- Labels: `logging`, `firewall`, `vsrx-parity`

Evidence:

```rust
userspace-dp/src/policy.rs:1748-1756
/// #3534: RT_FLOW session-log selection for the IMPLICIT default-policy
/// verdict (`security policies default-policy-log session-init|
/// session-close`). Stamped onto the default-verdict
/// [`PolicyEvaluationResult`] so a default-PERMIT session carries the flags
```

Runtime trace:

Current default logging is tied to the interzone `default-policy`. If same-zone default-permit becomes separate, it is unclear whether `default-policy-log` should log same-zone intrinsic permits.

Why it matters:

Operators rely on RT_FLOW logs for security audits. Conflating intrazone default-permit with interzone default-policy can create noisy logs or missing logs depending on the configured default-policy-log.

Fix direction:

Define and test logging semantics for intrazone default-permit. If Junos logs it as a policy row, model that row separately from interzone default-policy-log.

### M10 - Default counter store reserves one default counter only

- Severity: Medium
- Confidence: Medium
- Labels: `observability`, `performance`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs:1759-1764
/// #3395: O(1) re-resolution map from a rule's stable `rule_id`
/// (`stable_policy_rule_id`, or `DEFAULT_POLICY_COUNTER_RULE_ID` for the
/// implicit default policy) to its CURRENT positional `policy_id`
```

```rust
userspace-dp/src/policy.rs:1999-2004
// #3363: persistent reserved counter for the implicit default-policy
// verdict.
default_counter: counter_store.rule_hit_counter(DEFAULT_POLICY_COUNTER_RULE_ID),
```

Runtime trace:

The counter store has a stable handle for one implicit default. Intrazone default-permit would need another stable handle or it will be mixed with interzone default-policy hits.

Why it matters:

If same-zone traffic is high volume, it can swamp default-policy counters and hide real interzone default denies.

Fix direction:

Add `DEFAULT_INTRAZONE_COUNTER_RULE_ID` or equivalent and ensure established-session fast path re-counts against the intrazone handle.

### M11 - Show-policy rendering lacks an obvious source for vSRX `default-permit` rows

- Severity: Medium
- Confidence: Medium
- Labels: `cli`, `grpc`, `rest`, `vsrx-parity`

Evidence:

```text
docs/junos-cli-reference.md:217-218
From zone: trust, To zone: trust
  Policy: default-permit, State: enabled, Index: 4
```

```go
pkg/dataplane/userspace/policies.go:229-243
// walkPolicyRuleSlots invokes fn for every configured policy in config order,
// assigning each policy its slot in the runtime policy-ID namespace.
func walkPolicyRuleSlots(cfg *config.Config, fn func(slot policyRuleSlot) error) error {
```

Runtime trace:

The walker only knows configured policies. A Junos-compatible `show security policies` row for same-zone default-permit must be synthesized somewhere else.

Why it matters:

Even if packet forwarding is fixed, operators comparing against vSRX will still see a missing policy row and will not know why same-zone traffic is allowed.

Fix direction:

Add a show-policy synthetic-row layer that emits one default-permit row per zone or per same-zone pair as intended by the vSRX-compatible UX.

### M12 - Existing policy test matrices focus interzone/wildcard, not same-zone

- Severity: Medium
- Confidence: Medium
- Labels: `tests`, `firewall`, `vsrx-parity`

Evidence:

```text
userspace-dp/src/policy_tests.rs has wildcard tests such as:
from_zone_any_matches_across_ingress_zones
to_zone_any_matches_across_egress_zones
both_any_matches_every_pair
```

Runtime trace:

The matrix exercises cross-zone wildcard behavior. It does not appear to assert `from_id == to_id` behavior with default-policy deny-all.

Why it matters:

Same-zone policy behavior is a core firewall primitive. Without a first-class matrix, wildcard/global fixes can accidentally change intrazone semantics.

Fix direction:

Add a same-zone dimension to the policy matrix: no explicit policy, explicit permit, explicit deny, wildcard deny, wildcard permit, global deny, global permit.

### M13 - `docs/feature-gaps.md` does not list intrazone default-permit as a vSRX parity gap

- Severity: Medium
- Confidence: Medium
- Labels: `docs`, `vsrx-parity`, `tracking`

Evidence:

```text
docs/feature-gaps.md was read for duplicate suppression. It lists many security-policy gaps such as dynamic applications, URL categories, source identity, application services, UTM/IDP, and policy rematch, but I did not find an intrazone/default-permit row.
```

Runtime trace:

The gap is not visible in the parity planning doc, so it can be missed while feature parity is tracked.

Why it matters:

This is not a niche feature. Same-zone implicit permit is visible in the repo's own vSRX-style CLI reference.

Fix direction:

Add a feature gap or issue labeled `vsrx-parity` for intrazone default-permit unless the implementation is fixed immediately.

## Low Confidence / Triage Findings

### L01 - If fail-closed same-zone behavior is intentional, it needs an explicit security-mode knob

- Severity: Low
- Confidence: Low
- Labels: `design`, `security`, `vsrx-parity`

Evidence:

```text
docs/junos-cli-reference.md:217-218
From zone: trust, To zone: trust
  Policy: default-permit
```

```rust
userspace-dp/src/policy.rs:2767-2768
PolicyEvaluationResult {
    action: state.default_action,
```

Runtime trace:

Current behavior is stricter than vSRX for same-zone misses. That could be intentional, but the docs call this a vSRX/Junos reference.

Why it matters:

Silent divergence makes migrations risky. Operators may not realize same-zone traffic is denied until production traffic breaks.

Fix direction:

Either implement vSRX-compatible intrazone permit or add an explicit `strict-same-zone-default-deny` mode with migration docs.

### L02 - Policy default logic should live in a `policy/defaults` module

- Severity: Low
- Confidence: Low
- Labels: `refactor`, `modularity`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs contains PolicyState, parsing, evaluation, counters, default-policy logging, wildcard tiering, and result identity in one large module.
```

Runtime trace:

The intrazone gap spans parser defaults, runtime evaluation, counters, logs, and operator displays. That cross-cutting behavior is currently spread across a large file and Go mirror.

Why it matters:

Default behavior is security-critical and easy to regress when represented as scattered sentinel constants and booleans.

Fix direction:

Extract default decision/counter/log identity into `userspace-dp/src/policy/defaults.rs` or similar, then expose one SSOT to runtime and tests.

### L03 - `policymatch.Result.DefaultUsed` is overloaded

- Severity: Low
- Confidence: Low
- Labels: `refactor`, `operator-diagnostics`

Evidence:

```go
pkg/policymatch/policymatch.go:245-247
// DefaultUsed is true when no policy matched and Action is the configured
// default-policy.
DefaultUsed bool
```

Runtime trace:

Future same-zone default-permit cannot be represented by this boolean without lying that it is the configured default-policy.

Why it matters:

Boolean result types are cheap initially but expensive once the domain has multiple defaults.

Fix direction:

Replace `DefaultUsed bool` with a typed enum and keep backward-compatible rendering at the edge.

### L04 - Prometheus/API labels should include default scope

- Severity: Low
- Confidence: Low
- Labels: `observability`, `api`, `metrics`

Evidence:

```rust
userspace-dp/src/policy.rs:1743-1746
// Persisted in the `PolicyCounterStore` under [`DEFAULT_POLICY_COUNTER_RULE_ID`]
// ... reported as that rule id in [`PolicyState::counter_snapshots`].
```

Runtime trace:

One default rule ID means metrics cannot distinguish interzone default-policy from intrazone default-permit.

Why it matters:

Metrics consumers cannot write alerts for "unexpected interzone default denies" if same-zone traffic shares the series.

Fix direction:

Expose `default_scope="interzone|intrazone"` or separate rule IDs.

### L05 - `default-policy-log` docs should say whether they are interzone-only

- Severity: Low
- Confidence: Low
- Labels: `docs`, `logging`

Evidence:

```rust
userspace-dp/src/policy.rs:1748-1752
/// #3534: RT_FLOW session-log selection for the IMPLICIT default-policy
/// verdict (`security policies default-policy-log session-init|
/// session-close`).
```

Runtime trace:

If same-zone default-permit becomes separate, default-policy-log may or may not apply. Current comments do not distinguish.

Why it matters:

Operators will not know whether enabling default-policy-log should log same-zone default-permit sessions.

Fix direction:

Document and test the intended relationship.

### L06 - HA/session sync needs coverage for intrazone default-permit sessions

- Severity: Low
- Confidence: Low
- Labels: `tests`, `ha`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs:2787-2793
inactivity_timeout: None,
policy_counter_idx: DEFAULT_POLICY_COUNTER_IDX,
```

Runtime trace:

Default-permit sessions bind to default policy metadata. Intrazone default sessions would need correct metadata through HA/state sync and re-resolution.

Why it matters:

Failover bugs often hide in metadata, not first-packet verdicts. A same-zone session admitted by an intrinsic default must survive RG failover and continue counting/logging against the right default identity.

Fix direction:

Add HA/session-sync tests once intrazone default-permit exists.

### L07 - Need packet-level smoke for same-zone traffic

- Severity: Low
- Confidence: Low
- Labels: `tests`, `smoke`, `vsrx-parity`

Evidence:

```text
No same-zone default-permit packet-level test was found during this audit. Searches found same-zone mostly in screen internals and host-inbound per-interface tests, not transit policy default-permit.
```

Runtime trace:

Unit tests can prove evaluator behavior, but the end-to-end classifier still must map two interfaces to the same zone and forward.

Why it matters:

The bug is user-visible only when interface-to-zone mapping and route output produce `from_zone == to_zone`.

Fix direction:

Add an integration smoke: two dataplane interfaces in `trust`, no trust->trust policy, default-policy deny-all, assert TCP/ICMP forward succeeds; add explicit trust->trust deny as a negative case.

### L08 - Need explicit deny override test for same-zone traffic

- Severity: Low
- Confidence: Low
- Labels: `tests`, `security`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs:2631-2649
if let Some(indices) = state.zone_pair_index.get(&key) {
    for &idx in indices {
        if let Some(mut result) = try_match_rule(...) {
            result.policy_counter_idx = (idx as u32).saturating_add(1);
            return result;
        }
```

Runtime trace:

Exact same-zone policy should override any intrinsic same-zone default.

Why it matters:

Implementing intrazone permit must not create an unconditional same-zone bypass.

Fix direction:

Add `from-zone trust to-zone trust policy deny-web` and assert matching packets are denied before the default-permit tier.

### L09 - Need broad wildcard/global same-zone precedence tests

- Severity: Low
- Confidence: Low
- Labels: `tests`, `design`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs:2667-2726
let from_any = state.from_any_index.get(&to_id)...
let to_any = state.to_any_index.get(&from_id)...
...
for &idx in &state.both_any_indices {
```

Runtime trace:

Same-zone traffic today can match wildcard and global policies before default-policy. With intrazone default-permit, the desired relationship must be pinned.

Why it matters:

The worst failure mode is a broad `any any permit` or `any any deny` unexpectedly overriding same-zone semantics after a refactor.

Fix direction:

Add same-zone cases for from-any, to-any, both-any, unconstrained global, and scoped global.

### L10 - Avoid O(N^2) synthetic same-zone policy materialization

- Severity: Low
- Confidence: Low
- Labels: `performance`, `refactor`, `firewall`

Evidence:

```rust
userspace-dp/src/policy.rs:2664-2666
// Each tier is a single FxHashMap O(1) lookup ... no N x N materialization.
```

Runtime trace:

If default-permit rows are added by materializing every same-zone pair in the policy index, zone count growth could add cold-start and memory overhead.

Why it matters:

The forwarding path is latency-sensitive. The current design intentionally avoids N x N policy expansion.

Fix direction:

Implement intrazone default as a branch on `from_id == to_id` after the chosen explicit-policy tiers, not as synthetic runtime rules in the hot index.

### L11 - The Junos CLI reference sample should be tied to executable tests

- Severity: Low
- Confidence: Low
- Labels: `docs`, `tests`, `vsrx-parity`

Evidence:

```text
docs/junos-cli-reference.md:210-218 documents `show security policies` with `trust -> trust default-permit`, but no direct test appears to assert that XPF can render or enforce that row.
```

Runtime trace:

Reference docs can drift from code unless backed by a fixture.

Why it matters:

This audit found exactly that kind of drift: docs say one thing, runtime tiers imply another.

Fix direction:

Add a golden test or doc validation fixture for the `show security policies` sample.

### L12 - Any issue opened for this should be labeled `vsrx-parity`

- Severity: Low
- Confidence: Low
- Labels: `tracking`, `vsrx-parity`

Evidence:

```text
User instruction for this campaign: report that feature parity issues should be labeled as such in git.
```

Runtime trace:

This is a feature-parity issue against the repo's own Junos/vSRX reference behavior.

Why it matters:

Without a parity label, it may get lost among generic refactors.

Fix direction:

Open a focused issue titled along the lines of: "security policies: implement vSRX intrazone default-permit semantics and observability", labeled `vsrx-parity`, `firewall`, `security`.

## Quota Summary

- High confidence findings: 3
- Medium confidence findings: 13
- Low confidence findings: 12
- Total candidates: 28

These are not 28 independent root bugs. They are 28 non-duplicate issue candidates and validation/refactor surfaces around one high-confidence root: XPF appears to lack vSRX/Junos intrazone default-permit semantics in the runtime, diagnostics, counters, docs, and tests.

## Recommended Issue Split

1. `security policies: implement vSRX intrazone default-permit in userspace dataplane`
   - Covers H01, M02, M03, M08, L01, L08, L09, L10.

2. `policy diagnostics: expose intrazone default-permit distinctly from default-policy`
   - Covers H02, M04, M07, L03.

3. `policy counters/logs: add separate intrazone default-permit identity`
   - Covers H03, M09, M10, L04, L05, L06.

4. `show security policies: render vSRX default-permit rows for same-zone policy`
   - Covers M05, M11, L11.

5. `tests: add same-zone policy parity matrix and packet smoke`
   - Covers M06, M12, L07, L08, L09.

6. `docs: document intrazone default-permit parity or intentional divergence`
   - Covers M01, M13, L01, L12.
