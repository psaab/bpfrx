# Codex Review 152 - Core Firewall Policy Snapshot Integrity Campaign

## 1. Base Commit Reviewed

- Base commit: `acee6f6f7ca4`
- `git pull --rebase`: already up to date.
- Output path: `/tmp/codex-review-152.md`
- Focus: core firewall behavior: zone policies, global policies, host-inbound, application matching, default deny/permit behavior, and "denied packets stay denied / allowed packets stay allowed."

## 2. Duplicate Suppression Summary

Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` for duplicate suppression. Suppressed:

- `codex-review-131.md`: host-inbound bracket/flat-list tail drops, strict-validation bypasses, default-policy-log parser holes, nil-zone host-inbound admit-all, runtime policy ID display gaps.
- `codex-review-132.md`: host-inbound addressless observability, mixed-zone/family visibility, policy diagnostic selector/transport issues.
- `codex-review-133.md`: Rust firewall-filter DSCP/port/address/fallback-table boundary issues.
- `agy-review-132..152.md`: repeated session-map global mutex, cache-line alignment, and O(N) NAT prefix/block remap findings.
- `_Log.md` / docs: existing host-inbound token matrix, global `junos-host`, default-policy-log, application validation, policy `then`/`match` fail-closed, and RuntimePolicyIDs issues.

The findings below intentionally avoid those themes. The new material is concentrated on the Rust policy snapshot boundary and identity invariants.

## 3. Explicit Module Checklist

| Module / feature | Inspected | Result |
|---|---:|---|
| `userspace-dp/src/policy.rs` snapshot parser | yes | New malformed v3/address-book and app semantic integrity gaps |
| `userspace-dp/src/policy.rs` application matcher | yes | New ICMP type/code direct-snapshot gaps |
| `userspace-dp/src/policy.rs` address-book dense table | yes | New malformed/family-mismatch direct-snapshot gaps |
| `userspace-dp/src/policy.rs` exact/wildcard/global evaluator | yes | Negative result: current precedence tests are strong; no new precedence bug counted |
| `userspace-dp/src/policy.rs` `junos-host` evaluator | yes | Negative result: #3639 exact/wildcard/global host tests cover current shape |
| `userspace-dp/src/policy.rs` counters/rule identity | yes | New duplicate `rule_id` and `policy_id` integrity gaps |
| `pkg/dataplane/userspace/policies.go` snapshot builder | yes | Normal Go path emits sentinels; direct/mixed-version Rust boundary still weaker |
| `pkg/dataplane/userspace/capabilities.go` app expansion | yes | Parser drift risk: Go/Rust tables duplicated by hand |
| `pkg/config/compiler_applications.go` and strict validator | yes | Go rejects ordinary config for several Rust gaps; severity scoped to corrupt/direct/mixed-version snapshots |
| `userspace-dp/src/policy_tests.rs` | yes | New direct-boundary test gaps |
| Docs / feature-gaps / logs | yes | Existing vSRX AppID/host-inbound gaps suppressed as duplicates |

## 4. Verification Performed

Temporary Rust tests were appended, run, and then removed. They asserted the current bad behavior, so passing proves these states are accepted today:

```text
cargo test -p xpf-userspace-dp codex_audit_ -- --nocapture
running 4 tests
... malformed_v3_literal_drops_deny_rule_under_default_permit ... ok
... malformed_address_book_prefix_drops_deny_rule_under_default_permit ... ok
... icmp_code_without_type_matches_all_icmp ... ok
... non_icmp_term_with_icmp_type_never_denies_tcp ... ok
```

Final checkout was restored clean after removing the temporary tests.

## 5. Module-by-Module Inspection Log

- Rust snapshot parser: found malformed v3 literals and address-book prefixes still silently collapse to `MatchNone`, despite comments saying v3 is covered by the sentinel.
- Rust app matcher: found semantic ICMP field combinations accepted at the helper boundary even though Go strict validation rejects normal configs.
- Exact/wildcard/global policy evaluation: inspected `evaluate_policy_result_l3_aware`; exact, wildcard, both-any, global, default-policy ordering has explicit tests and no new bug found.
- `junos-host`: inspected host exact, wildcard, global `match to-zone junos-host`; current tests cover the main precedence and arming cases.
- Counters/identity: found no duplicate identity guard for `rule_id` or `policy_id`.
- Go builder/validator: normal config path often rejects these states, but the Rust helper boundary remains inconsistent with other fail-closed snapshot-integrity families.
- Performance/modularity: the policy evaluator remains rule-scan based and `policy.rs` is still a 3.4k LOC mixed parser/evaluator/counter module.

## 6. High Confidence Findings

### H01 - Malformed v3 policy literals are silently dropped, letting a deny rule no-op under default-permit

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `security`, `policy`, `snapshot-integrity`, `userspace-dataplane`
- Evidence:

```rust
userspace-dp/src/policy.rs:2107-2119
let (source_literal_v4, source_literal_v6) = if source_is_v3_shaped {
    parse_v3_literal_set(&snap.source_literals)
} else {
    let (v4, v6, malformed) = parse_legacy_address_set(&snap.source_addresses);
...
let (destination_literal_v4, destination_literal_v6) = if destination_is_v3_shaped {
    parse_v3_literal_set(&snap.destination_literals)
```

```rust
userspace-dp/src/policy.rs:2485-2500
for tok in literals {
    match tok.as_str() {
        "any" => { any_v4 = true; any_v6 = true; }
        "any4" | "any-ipv4" => any_v4 = true,
        "any6" | "any-ipv6" => any_v6 = true,
        "" => {}
        s => parse_literal_cidr_into(s, &mut v4, &mut v6),
    }
}
```

```rust
userspace-dp/src/policy.rs:2537-2550
match prefix.parse::<IpNet>() {
    Ok(IpNet::V4(net)) => out_v4.push(PrefixV4::from_net(net)),
    Ok(IpNet::V6(net)) => out_v6.push(PrefixV6::from_net(net)),
    Err(_) => {
        if let Ok(ip) = prefix.parse::<Ipv4Addr>() { ... }
        else if let Ok(ip) = prefix.parse::<Ipv6Addr>() { ... }
    }
}
```

- Runtime trace:
  1. Snapshot has `source_literals=["10.0.0.999"]`, `action="deny"`, `default_policy="permit"`.
  2. `source_is_v3_shaped` is true, so the legacy malformed-literal detector is bypassed.
  3. `parse_literal_cidr_into` cannot parse the token and pushes no prefix, returning no error.
  4. The source side becomes empty/MatchNone.
  5. `try_match_rule` sees no source match; the deny rule does not apply.
  6. Evaluation falls through to default permit. Temporary test reproduced this and passed.
- Why it matters: This is the v3 sibling of the legacy fail-open class already fixed in #3367. A malformed direct/mixed-version snapshot can turn an intended deny into a pass.
- Suggested fix: Make `parse_v3_literal_set` return malformed-token detail and reject the whole snapshot with a v3-specific integrity error unless the token is an accepted placeholder/sentinel.

### H02 - Malformed `AddressBookSnapshot` prefixes are silently dropped, making book-backed deny rules no-op

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `security`, `policy`, `address-book`, `snapshot-integrity`
- Evidence:

```rust
userspace-dp/src/policy.rs:2079-2089
let mut v4: Vec<PrefixV4> = Vec::with_capacity(snap.prefixes_v4.len());
let mut v6: Vec<PrefixV6> = Vec::with_capacity(snap.prefixes_v6.len());
for s in &snap.prefixes_v4 {
    parse_literal_cidr_into(s, &mut v4, &mut v6);
}
for s in &snap.prefixes_v6 {
    parse_literal_cidr_into(s, &mut v4, &mut v6);
}
let entry = BookEntry {
```

`parse_literal_cidr_into` drops malformed strings without returning a boolean or error, as shown in H01.

- Runtime trace:
  1. Snapshot has address book ID 42 with `prefixes_v4=["10.0.0.999"]`.
  2. Deny rule references `source_book_ids=[42]`, destination any, default-policy permit.
  3. Parser accepts the book ID and builds a dense book row with both families MatchNone.
  4. The deny rule's source side never matches.
  5. Evaluation falls through to default permit. Temporary test reproduced this and passed.
- Why it matters: Address books are the normal way operators express security boundaries. A corrupt/mixed-version book row should fail closed like duplicate/unknown IDs do, not narrow to nothing.
- Suggested fix: Parse book rows with family-aware `Result`, reject malformed prefixes, and include book ID/name plus offending token in the integrity error.

### H03 - Rust comments claim v3 literals are sentinel-protected, but arbitrary malformed v3 tokens are not rejected

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `docs`, `snapshot-integrity`, `policy`
- Evidence:

```rust
userspace-dp/src/policy.rs:52-55
/// the common "empty -> MatchAny" legacy path ... 
/// The v3-shaped
/// literal path already fails closed via the `__unsupported_address__` sentinel
/// (`UnrepresentableAddress`, #3261); this is the analogous backstop for the
/// legacy field, which carries raw literals with no sentinel.
```

But the v3 parser accepts any non-sentinel string and calls the non-reporting `parse_literal_cidr_into` (`policy.rs:2485-2500`).

- Runtime trace:
  1. Go normally emits `__unsupported_address__` for known unrepresentable config.
  2. A direct/mixed-version/corrupt helper snapshot can carry `source_literals=["not-an-address"]` without the sentinel.
  3. Rust treats it as v3-shaped and does not run the legacy malformed detector.
  4. The malformed token is silently dropped.
- Why it matters: The code comment documents an invariant reviewers will trust, but the implementation only protects the exact sentinel token. This is how the H01 fail-open survives.
- Suggested fix: Update implementation, not just comment: reject arbitrary malformed v3 literals.

### H04 - `icmp_code` without `icmp_type` is accepted by Rust and matches all ICMP

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `security`, `policy`, `icmp`, `vsrx-parity`
- Evidence:

```rust
userspace-dp/src/protocol/security.rs:476-479
#[serde(rename = "icmp_type", default, skip_serializing_if = "Option::is_none")]
pub icmp_type: Option<u8>,
#[serde(rename = "icmp_code", default, skip_serializing_if = "Option::is_none")]
pub icmp_code: Option<u8>,
```

```rust
userspace-dp/src/policy.rs:1380-1388
if app.icmp_type.is_some() {
    entry.icmp_constraints.push((
        order,
        app.icmp_type.expect("icmp_type is Some"),
        app.icmp_code,
        app.inactivity_timeout,
    ));
} else if app.source_ports.is_empty()
```

With `icmp_code=Some(3)` and `icmp_type=None`, the term falls through to the empty-port range path, which is protocol-only match-all for ICMP.

- Runtime trace:
  1. Snapshot term has protocol `icmp`, `icmp_type=null`, `icmp_code=3`, action permit, default deny.
  2. `parse_applications` carries both optional fields through.
  3. `from_matches` ignores `icmp_code` because only `icmp_type.is_some()` enters `icmp_constraints`.
  4. Empty source/destination ports create a protocol-only range term.
  5. ICMP echo-request type 8/code 0 and destination-unreachable type 3/code 1 both match. Temporary test reproduced this and passed.
- Why it matters: Go strict validation rejects this at commit, but the Rust boundary accepts it. A mixed-version or hand-built snapshot can broaden an intended narrow ICMP rule into all-ICMP.
- Suggested fix: In Rust snapshot parsing, reject `icmp_code.is_some() && icmp_type.is_none()` before compiling apps.

### H05 - Non-ICMP application terms with `icmp_type` become never-match terms, so deny rules fail open under default permit

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `security`, `policy`, `icmp`, `snapshot-integrity`
- Evidence:

```rust
userspace-dp/src/policy.rs:3339-3347
out.push(ApplicationMatch {
    protocol,
    source_ports,
    destination_ports,
    icmp_type: term.icmp_type,
    icmp_code: term.icmp_code,
    inactivity_timeout: term.inactivity_timeout.filter(|&t| t > 0),
});
```

```rust
userspace-dp/src/policy.rs:1496-1509
if !terms.icmp_constraints.is_empty() {
    if let Some((ptype, pcode)) = packet_icmp {
        if let Some(&(order, _, _, timeout)) = terms.icmp_constraints.iter().find(
            |&&(_, ctype, ccode, _)| ctype == ptype && ccode.map_or(true, |c| c == pcode),
        ) {
```

- Runtime trace:
  1. Snapshot term has protocol `tcp`, destination-port `80`, `icmp_type=8`, action deny, default permit.
  2. Rust accepts it and routes the term to `icmp_constraints` under protocol TCP.
  3. TCP packets pass `packet_icmp=None`.
  4. The ICMP-constrained TCP term never matches.
  5. The deny rule does not apply; default permit admits TCP/80. Temporary test reproduced this and passed.
- Why it matters: Go strict validation rejects normal configs, but Rust should not install a semantically impossible term. For a deny rule this is a security fail-open under default permit/later permit.
- Suggested fix: Reject any `icmp_type`/`icmp_code` on non-ICMP/non-ICMPv6 protocol in Rust.

### H06 - Duplicate `rule_id` values are accepted and corrupt counters plus policy re-resolution

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `observability`, `policy`, `rt-flow`, `snapshot-integrity`
- Evidence:

```rust
userspace-dp/src/policy.rs:1146-1156
fn rule_hit_counter(&self, rule_id: &str) -> Arc<PolicyRuleCounter> {
    let mut counters = self.counters.lock().expect("policy counter store poisoned");
    if let Some(counter) = counters.get(rule_id) {
        return counter.clone();
    }
    let counter = Arc::new(PolicyRuleCounter::with_rule_id(rule_id));
    counters.insert(rule_id.to_string(), counter.clone());
```

```rust
userspace-dp/src/policy.rs:2393-2397
state.rule_id_to_policy_id.reserve(state.rules.len() + 1);
for rule in &state.rules {
    state
        .rule_id_to_policy_id
        .insert(rule.rule_id.clone(), rule.policy_id);
}
```

- Runtime trace:
  1. Snapshot contains two different rules with identical non-empty `rule_id`.
  2. Both rules receive the same `Arc<PolicyRuleCounter>` from `PolicyCounterStore`.
  3. `counter_snapshots()` emits two rows with the same rule ID and same shared totals.
  4. `rule_id_to_policy_id.insert` overwrites the first rule's policy ID with the second.
  5. Existing sessions admitted by the first rule can re-resolve to the second rule's policy ID.
- Why it matters: This breaks auditability for RT_FLOW, session display, and hit counters. In a security appliance, wrong policy attribution is materially dangerous during incident response.
- Suggested fix: Reject duplicate `stable_policy_rule_id(snap)` during `parse_policy_state_with_counters`, just like duplicate address-book IDs are rejected.

## 7. Medium Confidence Findings

### M01 - Duplicate `policy_id` values are accepted, allowing RT_FLOW/session identity aliasing

- Severity: MEDIUM
- Confidence: Medium
- Labels: `bug`, `policy`, `rt-flow`, `observability`
- Evidence:

```rust
userspace-dp/src/protocol/security.rs:1100-1103
type PolicyRuleSnapshot struct {
    RuleID        string `json:"rule_id,omitempty"`
    PolicyID      uint32 `json:"policy_id,omitempty"`
```

```rust
userspace-dp/src/policy.rs:2239-2242
let rule = PolicyRule {
    rule_id: rule_id.clone(),
    policy_id: snap.policy_id,
```

```rust
userspace-dp/src/policy.rs:3213-3218
if src_ok && dst_ok {
    rule.hit_counter.add(packet_len);
    Some(PolicyEvaluationResult {
        action: rule.action,
        policy_id: rule.policy_id,
```

- Runtime trace:
  1. Snapshot has two live rules with `policy_id=17`.
  2. The parser accepts both; no uniqueness or range check exists.
  3. Matching either rule emits `policy_id=17`.
  4. Go display/log surfaces cannot distinguish which rule actually matched if only policy ID is present.
- Why it matters: `policy_id` is explicitly the RT_FLOW/session/display join key in docs. Duplicate IDs destroy that contract.
- Suggested fix: Reject duplicate non-sentinel policy IDs within a snapshot and add a direct Rust test.

### M02 - Address-book `prefixes_v4` / `prefixes_v6` family fields are not enforced

- Severity: MEDIUM
- Confidence: Medium
- Labels: `bug`, `address-book`, `ipv6`, `snapshot-integrity`
- Evidence:

```rust
userspace-dp/src/policy.rs:2079-2086
let mut v4: Vec<PrefixV4> = Vec::with_capacity(snap.prefixes_v4.len());
let mut v6: Vec<PrefixV6> = Vec::with_capacity(snap.prefixes_v6.len());
for s in &snap.prefixes_v4 {
    parse_literal_cidr_into(s, &mut v4, &mut v6);
}
for s in &snap.prefixes_v6 {
    parse_literal_cidr_into(s, &mut v4, &mut v6);
}
```

- Runtime trace:
  1. A corrupt/mixed snapshot puts `2001:db8::/32` in `prefixes_v4`.
  2. Rust parses it as IPv6 and pushes into `v6`.
  3. The family-specific wire field is ignored.
- Why it matters: The wire contract names family-specific arrays. Ignoring family lets malformed producer output still enforce, but not as the producer declared. That is bad for HA/mixed-version debugging.
- Suggested fix: Parse each list with family-specific parser and reject wrong-family tokens.

### M03 - Direct Rust app parser accepts per-application idle timeouts above the Go/vSRX cap

- Severity: MEDIUM
- Confidence: Medium
- Labels: `bug`, `session-gc`, `policy`, `snapshot-integrity`
- Evidence:

```rust
userspace-dp/src/protocol/security.rs:492-497
#[serde(
    rename = "inactivity_timeout",
    default,
    skip_serializing_if = "Option::is_none"
)]
pub inactivity_timeout: Option<u32>,
```

```rust
userspace-dp/src/policy.rs:3347-3351
// A 0 seconds value collapses to None (use-global) so the override
// is only set when the operator configured a positive timeout.
inactivity_timeout: term.inactivity_timeout.filter(|&t| t > 0),
```

Go caps application timeouts at 86400 seconds:

```go
pkg/config/compiler_applications.go:21-24
const (
    appTimeoutMin = 0
    appTimeoutMax = 86400
)
```

- Runtime trace:
  1. Direct snapshot carries `inactivity_timeout=4294967295`.
  2. Rust accepts it as `Some(4294967295)`.
  3. A matching session is stamped with an effectively never-expiring idle timeout.
- Why it matters: Session GC behavior can diverge materially from commit-time constraints, increasing state retention under attack or config corruption.
- Suggested fix: Enforce the same upper bound in Rust or make the bound a shared generated protocol constant.

### M04 - Rust application parser still duplicates Go protocol/service grammar by hand

- Severity: MEDIUM
- Confidence: Medium
- Labels: `refactor`, `policy`, `application`, `modularity`
- Evidence:

```go
pkg/dataplane/userspace/capabilities.go:448-459
// userspacePortSpecRepresentable reports whether a policy application port spec
// parses the way the Rust dataplane's parse_port_spec does (#2124). It must stay
// in lock-step with userspace-dp/src/policy.rs::parse_port_spec...
func userspacePortSpecRepresentable(spec string) bool {
```

```rust
userspace-dp/src/policy.rs:3395-3415
fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() { return Some(Vec::new()); }
    let normalized = match spec {
        "http" => "80",
        "https" => "443",
        ...
        "syslog" => "514",
        other => other,
    };
```

- Runtime trace:
  1. A future service alias is added to Go but not Rust.
  2. Go accepts and publishes the snapshot.
  3. Rust drops the term and rejects the snapshot or narrows behavior depending on the shape.
- Why it matters: This boundary has already had multiple drift fixes. It should not depend on duplicated literal tables in two languages.
- Suggested fix: Generate protocol and service alias tables from one source into Go and Rust, with a cross-language canary.

### M05 - Global policy evaluation scans every global rule for every first packet

- Severity: MEDIUM
- Confidence: Medium
- Labels: `performance`, `latency`, `policy`, `userspace-dataplane`
- Evidence:

```rust
userspace-dp/src/policy.rs:2789-2805
for &idx in &state.global_indices {
    let rule = &state.rules[idx];
    if !rule.global_from_zone.matches(from_id) || !rule.global_to_zone.matches(to_id) {
        continue;
    }
    if let Some(mut result) = try_match_rule(
        rule,
```

- Runtime trace:
  1. A cold first packet enters a defined zone pair.
  2. Exact/wildcard tiers miss.
  3. Every global rule is scanned, even if most have scoped `match from-zone/to-zone` that cannot apply.
  4. Each candidate may also run application and address matching.
- Why it matters: First-packet latency is security dataplane latency. Large global policy sets can add avoidable branch/cache pressure.
- Suggested fix: Build scoped global indices by `(from_id,to_id)` / wildcard scope, while preserving global config order for matching lists.

### M06 - Zone-pair policy evaluation remains an O(number of rules in bucket) first-packet scan

- Severity: MEDIUM
- Confidence: Medium
- Labels: `performance`, `policy`, `latency`
- Evidence:

```rust
userspace-dp/src/policy.rs:2693-2712
let key = zone_pair_key(from_id, to_id);
if let Some(indices) = state.zone_pair_index.get(&key) {
    for &idx in indices {
        if let Some(mut result) = try_match_rule(
            &state.rules[idx],
            state,
            src_ip,
```

- Runtime trace:
  1. First packet for a flow performs a zone-pair lookup.
  2. It linearly probes rules in config order until a match.
  3. Rules with protocol/port/address constraints all pay branch and prefix-test cost before the match.
- Why it matters: Junos/SRX policy sets can be large. A router/firewall aiming for low-latency AF_XDP should avoid avoidable O(N) first-packet scans where indexes can preserve ordering by candidate sets.
- Suggested fix: Add optional compiled candidate indexes by protocol, destination port class, and address-book family while retaining ordered final resolution.

### M07 - Address-book lookups repeat per rule instead of compiling merged per-rule prefix sets

- Severity: MEDIUM
- Confidence: Medium
- Labels: `performance`, `address-book`, `policy`
- Evidence:

```rust
userspace-dp/src/policy.rs:3105-3110
rule.source_v4_match_any
    || rule.source_literal_v4.contains(src)
    || rule
        .source_book_idxs
        .iter()
        .any(|&i| state.books[i as usize].v4.contains(src))
```

- Runtime trace:
  1. A rule references several books.
  2. Every first-packet evaluation iterates every referenced book.
  3. Each book performs its own prefix-set lookup.
- Why it matters: Address-book-heavy enterprise policies make this hot on cold-path admission. It is also harder to reason about family-empty/excluded behavior across literals plus books.
- Suggested fix: At snapshot parse time, compile each rule's effective source/destination prefix set as literals union cited books, plus explicit provenance for display.

### M08 - Rust direct-boundary tests do not cover Go-rejected ICMP semantic combinations

- Severity: MEDIUM
- Confidence: Medium
- Labels: `tests`, `policy`, `icmp`, `snapshot-integrity`
- Evidence:

Existing ICMP tests cover valid constrained/unconstrained behavior:

```rust
userspace-dp/src/policy_tests.rs:3876-3888
fn junos_ping_matches_echo_request_only() {
    let state = parse_policy_state(
        "deny",
        &[icmp_app_rule("junos-ping", "icmp", Some(8))],
...
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 0, 0), PolicyAction::Deny);
```

There is no test for `icmp_code=Some(_) && icmp_type=None`, or `protocol=tcp && icmp_type=Some(_)`.

- Runtime trace:
  1. These combinations are rejected by Go strict validation.
  2. The Rust parser is the helper-boundary backstop for corrupt/mixed snapshots.
  3. Without tests, the backstop accepts them.
- Why it matters: This is exactly the class of mixed-version/security-boundary bug earlier PRs repeatedly missed.
- Suggested fix: Add Rust integrity tests expecting `SnapshotIntegrityError` for both combinations.

### M09 - Rust direct-boundary tests cover malformed v3 literals only through the excluded-address path

- Severity: MEDIUM
- Confidence: Medium
- Labels: `tests`, `policy`, `address-book`, `snapshot-integrity`
- Evidence:

```rust
userspace-dp/src/policy_tests.rs:2840-2850
// #2008 fail-open hardening: an `*-excluded` side whose configured
// address set is unexpectedly EMPTY ...
#[test]
fn test_empty_excluded_source_fails_closed_v4() {
    // source_literals=["totally-bogus"] drops to nothing → MatchNone →
```

- Runtime trace:
  1. The existing test proves empty excluded sets do not invert to match-all.
  2. It does not prove ordinary deny rules reject malformed v3 literals.
  3. Temporary test showed ordinary deny + default permit still passes traffic.
- Why it matters: The excluded-path regression test can give false confidence that v3 literal malformed handling is fully hardened.
- Suggested fix: Add non-excluded malformed v3 literal tests that expect parser rejection, not just match-none behavior.

## 8. Low Confidence / Triage Findings

### L01 - `policy.rs` is still too broad for production security review

- Severity: LOW
- Confidence: Low
- Labels: `refactor`, `modularity`, `policy`
- Evidence: `wc -l` shows `userspace-dp/src/policy.rs` is 3459 LOC and owns snapshot parsing, app compilation, address parsing, indexes, evaluation, counters, default-policy, and `junos-host`.
- Trace: A reviewer checking one invariant must reason across parsing (`parse_policy_state_with_counters`), app compilation (`CompiledApplications`), address parsing, and evaluation. H01-H05 are examples of invariant gaps hidden across those regions.
- Suggested fix: Split into `policy/{snapshot.rs,address.rs,applications.rs,index.rs,evaluate.rs,counters.rs,tests/...}`.

### L02 - `policy_tests.rs` is a 5680-line catch-all instead of feature-scoped test modules

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `refactor`, `modularity`
- Evidence: `wc -l userspace-dp/src/policy_tests.rs` => 5680 lines.
- Trace: Direct-boundary malformed literals, ICMP semantics, host/global precedence, counters, and app timeout tests all share one file. Missing cases are harder to see.
- Suggested fix: Split into `policy/tests/{address_books.rs,applications.rs,identity.rs,junos_host.rs,global.rs,counters.rs}`.

### L03 - Add a policy snapshot integrity fuzz target

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `fuzzing`, `security`
- Evidence: The parser accepts structured JSON snapshots and has many hand-written invariants but no apparent fuzz corpus for malformed cross-field combinations.
- Trace: H01-H05 all arise from legal JSON fields in semantically illegal combinations.
- Suggested fix: Add proptest/fuzz cases generating `PolicyRuleSnapshot`, `AddressBookSnapshot`, and `PolicyApplicationSnapshot`, asserting either parse rejection or no fail-open under default permit.

### L04 - Snapshot integrity errors should distinguish bad protocol, bad port, bad ICMP semantic, and bad address literal

- Severity: LOW
- Confidence: Low
- Labels: `observability`, `policy`, `operator-ux`
- Evidence:

```rust
userspace-dp/src/policy.rs:401-404
Self::UnrepresentableApplicationProtocol { rule_id } => write!(
    f,
    "rule {:?} has an unrepresentable application term (unparseable protocol or port) ..."
```

- Trace: The parser currently has one app error bucket for protocol/port parse failures and no ICMP semantic error bucket.
- Suggested fix: Add precise integrity variants with offending application name/token.

### L05 - Address-book integrity errors should include book name and offending prefix

- Severity: LOW
- Confidence: Low
- Labels: `observability`, `address-book`, `operator-ux`
- Evidence: Existing address-book integrity errors only cover id zero/duplicate and unknown ID, not prefix content (`policy.rs:2070-2086`).
- Trace: Once H02 is fixed, operators need actionable error text naming the bad book row and token.
- Suggested fix: Add `MalformedAddressBookPrefix { id, name, prefix, expected_family }`.

### L06 - Family-specific address-book arrays should have a source-of-truth invariant test

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `address-book`, `ipv6`
- Evidence: Both `prefixes_v4` and `prefixes_v6` are parsed by the same family-agnostic function.
- Trace: A test should fail if an IPv6 token in `prefixes_v4` is accepted or vice versa.
- Suggested fix: Add direct Rust tests and a Go snapshot-builder canary.

### L07 - Per-rule effective prefix compilation would simplify excluded-address correctness

- Severity: LOW
- Confidence: Low
- Labels: `refactor`, `policy`, `address-book`
- Evidence: `try_match_rule` manually recomputes literal/book/excluded logic separately for v4, v6, and NAT64 mixed-family arms (`policy.rs:3095-3208`).
- Trace: Any future tweak must update three arms, plus empty-family semantics.
- Suggested fix: Compile `EffectiveAddressMatch` per side/family with methods `matches_v4`, `matches_v6`, `matches_nat64_dst_v4`.

### L08 - The Go/Rust app grammar should have a generated parity fixture, not comments saying "lock-step"

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `codegen`, `policy`, `application`
- Evidence: Go comment at `capabilities.go:448-459` explicitly depends on Rust `parse_port_spec`.
- Trace: Comments do not fail CI when a table changes in one language.
- Suggested fix: Generate both tables or add a source-level canary that diffs the alias/protocol sets.

### L09 - Global-policy scoped index can preserve order without scanning unrelated globals

- Severity: LOW
- Confidence: Low
- Labels: `performance`, `policy`
- Evidence: Current `global_indices` is a single vector (`policy.rs:2789-2805`).
- Trace: A scoped global `from trust to untrust` and another scoped global `from dmz to wan` are both scanned for a trust->untrust flow.
- Suggested fix: Store scoped-global candidate lists keyed by concrete/wildcard scope, then merge ordered candidate lists.

### L10 - Policy parser/evaluator should expose helper-boundary rejection metrics

- Severity: LOW
- Confidence: Low
- Labels: `observability`, `snapshot-integrity`, `metrics`
- Evidence: SnapshotIntegrityError returns errors but the inspected policy parser does not itself publish per-reason counters.
- Trace: A mixed-version cluster repeatedly publishing malformed policy snapshots may only show apply failure logs, not a counter by reason.
- Suggested fix: Add status counters for policy snapshot integrity rejects by reason.

### L11 - vSRX parity issues from this report should be labeled explicitly

- Severity: LOW
- Confidence: Low
- Labels: `issue-hygiene`, `vsrx-parity`
- Evidence: H04/H05 concern Junos/vSRX ICMP application semantics; M05/M06 concern scale expected of SRX-like policy tables.
- Trace: Without `vsrx-parity`, these can be triaged as generic cleanup even though they affect operator expectations.
- Suggested fix: Apply `vsrx-parity` to ICMP app semantics and large policy-scale follow-ups.

### L12 - Add a mixed-version snapshot acceptance matrix for policy schema v3 fields

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `ha-sync`, `compatibility`, `policy`
- Evidence: v3 fields (`source_book_ids`, `source_literals`, `application_terms`, ICMP fields, `inactivity_timeout`) are all additive/defaulted.
- Trace: The Go normal path can be safe while direct/mixed-version fields produce fail-open behavior.
- Suggested fix: Add tests for old-Go/new-Rust, new-Go/old-Rust, corrupt direct snapshot, and HA peer-sync snapshots.

### L13 - `parse_literal_cidr_into` should not be reused for both permissive and strict contexts

- Severity: LOW
- Confidence: Low
- Labels: `refactor`, `snapshot-integrity`, `address-book`
- Evidence: The same non-reporting helper is used by v3 literals and address-book rows (`policy.rs:2081-2085`, `2499`).
- Trace: Some contexts need permissive best-effort behavior; policy security boundaries need fail-closed errors.
- Suggested fix: Split into `try_parse_literal_cidr` and context-specific callers.

### L14 - Policy identity uniqueness should be validated before allocating counters

- Severity: LOW
- Confidence: Low
- Labels: `refactor`, `policy`, `counters`
- Evidence: `parse_policy_state_with_counters` allocates counters per rule during the main parse loop (`policy.rs:2289`) before duplicate `rule_id` can be detected because no duplicate check exists.
- Trace: If duplicate detection is added late, the store may have observed transient counters for a rejected snapshot.
- Suggested fix: Preflight all rule identities and policy IDs before building `PolicyRule` entries.

### L15 - Add explicit negative-result tests for exact/wildcard/global policy precedence with malformed skipped rules

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `policy`
- Evidence: Precedence tests exist, but malformed direct snapshots can remove a rule from consideration without parse rejection.
- Trace: A malformed deny in exact tier plus a later global permit should be rejected at parse, not fall through by precedence.
- Suggested fix: Add tests combining malformed v3/app terms with exact-vs-global fallthrough.

## 9. Suggested Issue Split

1. `bug(policy): reject malformed v3 literals and address-book prefixes at Rust snapshot boundary` - H01, H02, H03, M09, L05, L06, L13.
2. `bug(policy-app): reject invalid ICMP application field combinations in Rust snapshot parser` - H04, H05, M08.
3. `bug(policy): reject duplicate rule_id and policy_id values in userspace policy snapshots` - H06, M01, L14.
4. `bug(session-gc): cap Rust per-application inactivity_timeout to Go/vSRX bounds` - M03.
5. `refactor(policy): split Rust policy parser/evaluator/counter modules and scoped tests` - L01, L02, L07.
6. `perf(policy): index scoped global and zone-pair candidates for cold-path admission` - M05, M06, M07, L09.
7. `test(policy): add policy snapshot fuzz/mixed-version matrix` - L03, L12, L15.
8. `codegen(policy-app): generate Go/Rust protocol and service alias grammar from one source` - M04, L08.
