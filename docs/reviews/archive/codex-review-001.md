# Codex Review Audit 001 - Core Firewall / vSRX Parity

## 1. Base Commit Reviewed

- Repository: `/home/ps/git/codex-bpfrx`
- Base commit: `9419bbc2c59e`
- Pull status: `git pull --rebase` returned `Already up to date.`
- Output path: `/tmp/codex-review-001.md`

## 2. Duplicate Suppression Summary

- Prior `/tmp/codex-review*.md` / `/tmp/agy-review*.md`: none present in this environment, so output number is `001`.
- Local issue/docs read for suppression:
  - `docs/issues/issue-history.md`
  - `docs/issues/pr-history.md`
  - `docs/feature-gaps.md`
  - `docs/feature-coverage.md`
  - `docs/userspace-dataplane-gaps.md`
  - `docs/config-schema.md`
  - `docs/junos-cli-reference.md`
  - relevant module READMEs under `userspace-dp/src/`
- Explicitly suppressed as already tracked:
  - `system-services all` / `any-service` full-packet admission (#3226).
  - Flowless LocalDelivery bypass as filed in #3292; current code appears to contain a fix, so this report flags stale tracking separately instead of duplicating the original runtime bug.
  - Positional `policy_id` attribution (#3395).
  - Host-inbound unknown/typo tokens, per-zone no-stanza default deny, BFD multihop, IS-IS token acceptance, ICMP subtype parity, host-inbound counters, nft apply/delete failures, and lo0 ordering issues already closed in the #3070/#3200/#3311/#3326/#3361/#3405/#3485 family.

## 3. Explicit Module Checklist

1. Host-inbound classifier: `userspace-dp/src/afxdp/forwarding/host_inbound.rs`
2. LocalDelivery poll path: `userspace-dp/src/afxdp/poll_descriptor/{mod.rs,filter.rs}`
3. `to-zone junos-host` policy evaluator: `userspace-dp/src/policy.rs`
4. Global policy strict validation: `pkg/config/compiler_validate_strict.go`
5. Output firewall filter / generated reply path: `userspace-dp/src/filter/README.md`, `userspace-dp/src/afxdp/tx/cos_classify.rs`
6. Screen rate limiting: `userspace-dp/src/screen/rate.rs`, `userspace-dp/src/screen/tests.rs`
7. AppID catalog and fallback display: `userspace-dp/src/policy.rs`, `pkg/appid/runtime.go`, `pkg/appid/README.md`
8. Snapshot/build plumbing: `userspace-dp/src/protocol/snapshot.rs`, `userspace-dp/src/afxdp/forwarding_build/*.rs`
9. RT_FLOW / dataplane event surfaces: `userspace-dp/src/event_stream/mod.rs`, poll descriptor emit sites
10. Documentation / feature parity surfaces: `docs/junos-cli-reference.md`, `docs/feature-gaps.md`, `docs/config-schema.md`

## 4. Module-by-Module Inspection Log

### 4.1 Host-Inbound Classifier

- Correctness/security: Found fail-open behavior for unknown/global zone ids and a likely VLAN logical-ifindex miss for per-interface overrides.
- vSRX completeness: `from-zone junos-host` egress self-traffic and implicit `junos-host` default-deny remain incomplete.
- Performance/latency: Classifier itself is cheap hash lookups; no hot-loop allocation found.
- Modularity/refactor: `host_inbound_gated_lo0_action` mines raw `UserspaceDpMeta` instead of accepting resolved logical ingress context.
- Test coverage: No visible VLAN-subinterface per-interface override LocalDelivery test; current direct helper tests use default raw meta.

### 4.2 LocalDelivery Poll Path

- Correctness/security: Host-inbound denied packets are counted but do not emit tuple-rich RT_FLOW-style events.
- vSRX completeness: Host-originated traffic is outside this path; only host-bound self-traffic is enforced.
- Performance/latency: LocalDelivery gates are cold relative to transit; no new hot-path issue beyond duplicate checks already documented.
- Modularity/refactor: Session-hit, session-miss, and flowless branches each perform similar accounting/drop sequences.
- Test coverage: Several direct helper tests exist; integration coverage around logical interfaces and host-bound policy matrix remains thin.

### 4.3 Junos-Host Policy Evaluator

- Correctness/security: Match-driven lifeline semantics intentionally skip implicit default-deny and broad wildcard/global tiers on the host path.
- vSRX completeness: `from-zone junos-host`, host-path global policy context, and configured-pair default-deny are parity gaps.
- Performance/latency: Indexed exact/wildcard rule lookup is bounded by matching bucket length; no immediate hot-path regression.
- Modularity/refactor: Host-path policy evaluation is separate from transit evaluation, which is safer but now has a semantic matrix that needs explicit tests.
- Test coverage: Existing unit tests cover parts of #3019/#3292, but not host-originated or global host contexts.

### 4.4 Output Filter / Generated Replies

- Correctness/security: Input/lo0 filter `reject` is active, but output-filter `reject` still becomes silent drop on TX/CoS.
- vSRX completeness: Output filter reject parity is still incomplete.
- Performance/latency: Generated-reply classification is cold; TX cached classification is hot and currently lacks enough context to synthesize replies.
- Modularity/refactor: Reply synthesis is descriptor-centric and not reusable from cached TX selection.
- Test coverage: No active-reply TX output-filter reject test because feature is explicitly missing.

### 4.5 Screen Rate Limiter

- Correctness/security: The two-bucket implementation blocks boundary bursts but over-throttles steady senders at exactly threshold/sec.
- vSRX completeness: Junos threshold semantics normally mean sustained threshold rate should not need a full idle second to recover.
- Performance/latency: Integer-only and allocation-free; no lock contention. The correctness problem is timing semantics, not cost.
- Modularity/refactor: A small monotonic subsecond sliding estimator or token bucket would be a cleaner primitive than whole-second bucket carry.
- Test coverage: Boundary-burst test exists; sustained-threshold test is missing.

### 4.6 AppID Catalog / Runtime Display

- Correctness/security: Enabled AppID chooses lowest `app_id` on overlap; disabled fallback chooses specificity first. This can change operator-visible app labels.
- vSRX completeness: Full L7 AppID/signature system is documented missing and not duplicated here.
- Performance/latency: Protocol-only/range/source-constrained entries are linearly scanned per cold session resolution.
- Modularity/refactor: Go fallback and Rust enabled matching have divergent precedence rules.
- Test coverage: Overlap tests pin lowest-ID behavior, but no parity test asserts whether enabled vs disabled should agree on specificity.

### 4.7 Event / Observability

- Correctness/security: Host-inbound denies increment counters but lack tuple/action events; debug counter `policy_deny` also includes non-policy host-inbound drops.
- vSRX completeness: Operational investigation is weaker than SRX-style logs for control-plane protection denies.
- Performance/latency: Event emission is best-effort and cold; no new backpressure bug found in this pass.
- Modularity/refactor: Host-inbound deny should have a typed event kind instead of piggybacking policy-deny debug stats.
- Test coverage: Counter tests exist; tuple-rich host-inbound event coverage does not.

## 5. High Confidence Findings

### H01 - `from-zone junos-host` host-originated policy is accepted/indexed but not enforced

- Severity: High
- Confidence: High
- Evidence:

`userspace-dp/src/policy.rs:2828-2838`

```rust
/// Crucially there is NO implicit default-deny here: an unmatched host-bound
/// flow falls through to today's behavior (local delivery proceeds). This is
/// the deliberate lifeline guarantee — configuring some junos-host policy
/// cannot silently brick management/host traffic that does not match a deny
/// rule. The stricter Junos "configured zone-pair implies default-deny"
/// posture is intentionally deferred (see docs/junos-cli-reference.md).
///
/// `from-zone junos-host` (host-ORIGINATED) rules are indexed by the same name
/// resolution but are NOT consulted here: locally-generated traffic does not
/// traverse the ingress LocalDelivery path. That direction is a documented
/// follow-up.
```

`docs/junos-cli-reference.md:493-497`

```text
  - **Scope:** `to-zone junos-host` (host-INBOUND) is enforced.
    `from-zone junos-host` (host-ORIGINATED / locally-generated traffic) rules
    are accepted and indexed but NOT yet consulted — locally-generated traffic
    does not traverse the ingress LocalDelivery path; that direction is a
    documented follow-up.
```

- Runtime trace:
  1. Operator configures `security policies from-zone junos-host to-zone untrust policy block-host-egress then deny`.
  2. The rule commits and is indexed by the same reserved `junos-host` zone-name mapping.
  3. Locally generated traffic leaves via host/egress generation paths, not ingress `LocalDelivery`.
  4. `evaluate_junos_host_policy*` only evaluates host-bound `to-zone junos-host` traffic.
  5. The host-originated deny never fires; traffic is controlled only by other planes.
- Why it matters: vSRX has a self-zone policy model in both directions. A router/firewall must be able to constrain daemon-originated traffic to untrusted zones.
- Suggested fix direction: Add a host-originated egress policy hook for locally generated frames/host-stack egress, reuse the reserved `JUNOS_HOST_ZONE_ID`, and add deny/reject/log/counter tests for host egress.
- Suggested labels: `bug`, `security`, `firewall-policy`, `vsrx-parity`, `host-originated`

### H02 - Screen `RateCounter` over-throttles sustained threshold traffic until an idle second occurs

- Severity: High
- Confidence: High
- Evidence:

`userspace-dp/src/screen/rate.rs:23-34`

```rust
//! Two adjacent 1-second buckets are retained: the count for the current
//! second (`count`) and the count for the immediately preceding second
//! (`prev_count`). An event is admitted only when
//! `prev_count + count <= threshold`. Because the previous second's tally
//! still contributes for the whole of the current second, a sender that
//! exhausts the budget just before a boundary cannot immediately spend a
//! fresh budget just after it — the trailing 1-second sum stays bounded by
//! `threshold` regardless of where the boundary falls.
//!
//! The semantic of the operator-configured threshold is preserved: a
//! sustained sender is still admitted at ~`threshold` events per second.
```

`userspace-dp/src/screen/rate.rs:73-83`

```rust
/// Increment and return true if admitting this event would exceed the
/// threshold over the trailing 1-second sliding window.
///
/// The event is always counted (so a sustained over-limit sender keeps
/// the window saturated), mirroring the original fixed-window
/// behaviour where the offending packet incremented the counter.
pub(super) fn increment(&mut self, now_secs: u64, threshold: u32) -> bool {
    self.advance(now_secs);
    self.count = self.count.saturating_add(1);
    self.prev_count.saturating_add(self.count) > threshold
}
```

- Runtime trace:
  1. Threshold is 100 events/sec.
  2. Sender emits exactly 100 events in second `N`; all pass, `count=100`.
  3. First event in second `N+1` calls `advance`, setting `prev_count=100`, then increments `count=1`.
  4. `prev_count + count = 101`, so the first event in the next second drops even though the sender is at exactly threshold/sec.
  5. Dropped events are still counted, so a busy sender can keep the next bucket saturated until an entirely idle second passes.
- Why it matters: Flood screens and standby SYN-cookie ACK validation can suppress legitimate traffic at the documented configured threshold. This is a correctness/security tradeoff, not just a tuning issue.
- Suggested fix direction: Replace the whole-second carry model with a weighted sliding window using subsecond monotonic time, or a token bucket with burst size equal to threshold and explicit refill rate. Add sustained-threshold and over-threshold recovery tests.
- Suggested labels: `bug`, `screen`, `rate-limit`, `security`, `performance`

### H03 - TX output firewall-filter `then reject` still silently drops instead of active reject

- Severity: Medium
- Confidence: High
- Evidence:

`userspace-dp/src/filter/README.md:759-763`

```text
**Scope:** output-firewall-filter `then reject` realized on the
TX/CoS path (`tx/cos_classify.rs`) still collapses `Reject` to a
silent drop. That site lacks the descriptor/packet context the
reflected-reply synthesis needs, so wiring it would be a divergent
path — tracked as a follow-up, not part of #2521.
```

`userspace-dp/src/afxdp/tx/cos_classify.rs:227-234`

```rust
CachedTxSelectionDescriptor {
    queue_id,
    dscp_rewrite: effective_dscp_rewrite,
    drop: output_result.action != crate::filter::FilterAction::Accept,
    filter_counters,
    three_color_policers,
    filter_log,
}
```

- Runtime trace:
  1. Operator attaches an output firewall filter with a terminal `then reject`.
  2. A transit packet reaches the cached TX/CoS classifier.
  3. The output filter returns `FilterAction::Reject`.
  4. TX code collapses every non-`Accept` action to `drop: true`.
  5. No TCP RST or ICMP/ICMPv6 unreachable is generated; remote endpoint sees timeout, not reject.
- Why it matters: vSRX `reject` behavior is operator-visible and used for policy diagnostics. Input/lo0 reject parity is fixed, but egress reject remains incomplete.
- Suggested fix direction: Carry enough descriptor/frame context into the TX reject decision to call shared reject synthesis, or explicitly split an issue/contract saying output reject is unsupported and commit-warn it.
- Suggested labels: `bug`, `firewall-filter`, `vsrx-parity`, `reject-action`

### H04 - Per-interface host-inbound override likely misses VLAN logical interfaces on AF_XDP LocalDelivery

- Severity: High
- Confidence: High
- Evidence:

`userspace-dp/src/afxdp/forwarding_build/interfaces.rs:93-107`

```rust
// #3362: per-interface host-inbound OVERRIDE. When the control plane
// marked this interface host-inbound-configured, classify its EFFECTIVE
// (zone ∪ interface) token set and key it by ifindex so the
// local-delivery admit path prefers it over the from-zone's set.
if iface.host_inbound_configured {
    state.ifindex_host_inbound.insert(
        iface.ifindex,
        crate::afxdp::forwarding::zone_host_inbound_from_tokens(
```

`userspace-dp/src/afxdp/poll_descriptor/filter.rs:448-455`

```rust
// Host-inbound gate FIRST — a denied packet is a fail-closed silent drop
// with NO lo0 side-effects (#3485). #3362: keyed by ingress interface so a
// per-interface host-inbound override governs the check where one exists,
// falling back to the from-zone set otherwise.
if !crate::afxdp::forwarding::host_inbound_admits_iface(
    forwarding,
    meta.ingress_ifindex as i32,
    host_inbound_zone,
```

`userspace-dp/src/afxdp/poll_descriptor/filter.rs:100-105`

```rust
let ingress_ifindex = resolve_ingress_logical_ifindex(
    forwarding,
    meta.ingress_ifindex as i32,
    meta.ingress_vlan_id,
)
.unwrap_or(meta.ingress_ifindex as i32);
```

- Runtime trace:
  1. Zone contains a VLAN subinterface such as `reth1.100`.
  2. Operator configures per-interface host-inbound override on `reth1.100`.
  3. Snapshot builder keys `ifindex_host_inbound` by `iface.ifindex` for the logical interface.
  4. LocalDelivery host-inbound gate probes `ifindex_host_inbound` with raw `meta.ingress_ifindex` from the XSK physical parent.
  5. The lookup misses and falls back to zone-level host-inbound, ignoring the per-interface override.
- Why it matters: Per-interface host-inbound is specifically a vSRX parity feature for exposing management/control protocols on one interface inside a zone. On VLAN-heavy deployments this can under-permit or over-permit the control plane.
- Suggested fix direction: Resolve logical ingress ifindex once before host-inbound/lo0 policy gates and pass it explicitly into `host_inbound_gated_lo0_action`; add VLAN subinterface regression tests.
- Suggested labels: `bug`, `host-inbound`, `vlan`, `vsrx-parity`, `security`

### H05 - Unknown/global host-inbound zone id is still admit-all

- Severity: Medium
- Confidence: High
- Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:472-483`

```rust
match state.zone_host_inbound.get(&ingress_zone_id) {
    // #3405: every configured security zone is in the table (the Go control
    // plane marks them all `host_inbound_configured`), so `None` is now only
    // a genuinely unknown / global ingress zone (e.g. id 0, no resolved
    // security zone). Such traffic keeps the admit default — narrowing it is
    // out of scope for the configured-zone default-deny fix and risks
    // breaking ND / control delivery on the global context.
    None => true,
```

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:567-572`

```rust
// A genuinely unknown / global ingress zone (id not in the table) keeps
// the admit default — #3405 is scoped to configured zones only.
assert!(
    host_inbound_admits(&state, 999, TCP, 22, false, 0),
    "unknown/global zone (absent from table) keeps the admit default",
);
```

- Runtime trace:
  1. A LocalDelivery packet enters with an unresolved, global, or stale zone id.
  2. The Rust host-inbound table has no entry for that id.
  3. `None => true` admits the packet before checking service/protocol tokens.
  4. Management/control-plane service reaches the host unless later lo0/security policy blocks it.
- Why it matters: The configured-zone default-deny fix is strong, but unresolved-zone admission is still fail-open. Security appliances usually prefer explicit lifeline exceptions, not unknown-zone permit.
- Suggested fix direction: Replace `None => true` with a narrow allowlist for lifeline/global control protocols and count every unknown-zone admission/drop separately; at minimum make it configurable and visible.
- Suggested labels: `security`, `host-inbound`, `fail-open`, `vsrx-parity`

### H06 - Host-inbound denies are counted but not tuple-rich logged

- Severity: Medium
- Confidence: High
- Evidence:

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:850-878`

```rust
None => {
    // Host-inbound denied: silent drop, tear down
    // the established host-bound session.
    delete_terminal_filtered_session(
        sessions,
        binding.bpf_maps.session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
```

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:868-876`

```rust
telemetry.dbg.local += 1;
telemetry.dbg.policy_deny += 1;
// #3326: account the host-inbound deny so
// `GlobalCtrHostInboundDeny` (REST/Prometheus/
// `show security flow statistics`) reflects the
// drop. `touched` must be set so the batch is
// flushed into BindingLiveState.
telemetry.counters.touched = true;
telemetry.counters.host_inbound_denied_packets += 1;
```

- Runtime trace:
  1. Packet to firewall-local SSH arrives on a zone that does not admit SSH.
  2. Host-inbound gate returns `None`.
  3. Poll loop increments aggregate host-inbound deny counters and recycles the descriptor.
  4. No `emit_policy_deny_event` / host-inbound event is emitted with source IP, destination IP, protocol, service, and ingress zone.
- Why it matters: Operators can see that host-inbound denies happened, but not who hit which control-plane service. That is weak incident response for a firewall/router.
- Suggested fix direction: Add a `HostInboundDeny` dataplane event kind with tuple, service/protocol, ingress zone/interface, and reason; rate-limit by zone/source like other dataplane events.
- Suggested labels: `observability`, `security`, `host-inbound`, `vsrx-parity`

## 6. Medium Confidence Findings

### M01 - `to-zone any` / both-any / global policy tiers are deliberately skipped for host-bound traffic

- Severity: Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/policy.rs:2909-2918`

```rust
// #3090: a `from-zone any to-zone junos-host` wildcard governs host-bound
// traffic from EVERY ingress zone. It MUST be consulted here — once the
// #3018 interim commit reject is lifted such a rule commits, and leaving it
// unindexed on the host path would re-introduce the exact silent fail-open
// #3018 closed. `to-zone any` / `from-zone any to-zone any` are deliberately
// NOT pulled into the host path: the junos-host gate stays conservative and
// strictly match-driven (no implicit default-deny — see this function's doc
// comment), mirroring the existing rule that global policies are not applied
```

- Runtime trace:
  1. Operator has broad policy such as `from-zone trust to-zone any then deny` or a global deny intended as a catch-all.
  2. Packet targets a firewall-local IP in `trust`.
  3. Host-inbound admits the service.
  4. Host policy evaluator checks exact `to-zone junos-host` and `from-zone any to-zone junos-host` only.
  5. Broad `to-zone any`/global deny is ignored; packet reaches host.
- Why it matters: This may surprise vSRX operators who treat broad policies as covering self-traffic unless explicitly separated.
- Suggested fix direction: Decide whether to implement Junos global/self traffic parity or add commit/display warnings when broad policies do not cover host-bound traffic.
- Suggested labels: `firewall-policy`, `vsrx-parity`, `security`, `docs`

### M02 - No implicit default-deny for configured `junos-host` zone pairs

- Severity: Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/policy.rs:2820-2833`

```rust
/// CONSERVATIVE / FAIL-SAFE semantics, by design (#3019 brief): enforcement is
/// strictly MATCH-DRIVEN. Returns:
///   - `None` when no `junos-host` policy is configured at all
///     (`has_junos_host_rules == false`), when the ingress zone is unknown
///     (id 0, mirroring the #3110 unzoned guard), or when no `junos-host` rule
///     MATCHES the flow.
///   - `Some(result)` only when a `to-zone junos-host` rule MATCHES.
///
/// Crucially there is NO implicit default-deny here: an unmatched host-bound
/// flow falls through to today's behavior (local delivery proceeds).
```

- Runtime trace:
  1. Operator adds one `from-zone untrust to-zone junos-host` deny rule for SNMP.
  2. Host-inbound admits SSH on that zone.
  3. SSH does not match the SNMP deny rule.
  4. Evaluator returns `None`.
  5. SSH reaches the host instead of hitting configured-pair default deny.
- Why it matters: This is safer for upgrades but weaker than vSRX configured-zone-pair semantics.
- Suggested fix direction: Add a guarded `strict-junos-host-policy-default-deny` mode, or move toward vSRX parity with lifeline exceptions plus explicit migration warnings.
- Suggested labels: `vsrx-parity`, `firewall-policy`, `security`

### M03 - Global policy `junos-host` context is rejected instead of supported

- Severity: Medium
- Confidence: Medium
- Evidence:

`pkg/config/compiler_validate_strict.go:2715-2733`

```go
// The reserved self-traffic zone `junos-host` cannot be honored as a
// global-policy from/to-zone match context: the userspace dataplane
// does NOT evaluate a zone-scoped global policy on the host-bound
// (LocalDelivery) path, so a `match from-zone junos-host` / `to-zone
// junos-host` global would commit but silently never match (a
// commit-vs-dataplane divergence on a security leaf). Reject it at
// commit so the two layers agree; real junos-host global-zone-context
// support is a follow-up.
```

- Runtime trace:
  1. Operator tries to express a global self-traffic rule scoped to `junos-host`.
  2. Strict validation rejects it.
  3. Operator must duplicate policy under each zone-specific `to-zone junos-host` pair.
  4. A missed zone becomes a management-plane hole.
- Why it matters: Rejection is fail-closed, but feature parity and operational ergonomics are incomplete.
- Suggested fix direction: Add global self-traffic scope support in the host-bound evaluator, with explicit precedence relative to exact and wildcard host policy tiers.
- Suggested labels: `feature`, `vsrx-parity`, `firewall-policy`

### M04 - AppID enabled overlap precedence diverges from disabled fallback specificity

- Severity: Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/policy.rs:1627-1648`

```rust
let exact = bucket.exact_dst.get(&service_port).copied();
// Scan entries (ranges / source-constrained / protocol-only). Catalog
// order = ascending id.
let in_range = |low: u16, high: u16, p: u16| -> bool {
    // (0,0) means "no constraint".
    (low == 0 && high == 0) || (p >= low && p <= high)
};
let mut scan_hit: Option<u16> = None;
```

`userspace-dp/src/policy.rs:1646-1648`

```rust
match (exact, scan_hit) {
    (Some(a), Some(b)) => a.min(b),
    (Some(a), None) | (None, Some(a)) => a,
```

`pkg/appid/runtime.go:136-158`

```go
func resolveTupleFallback(proto uint8, srcPort, dstPort uint16, cfg *config.Config) string {
    if cfg != nil {
        // #2578: cfg.Applications.Applications is a Go map; iterating it and
        // returning the first match is non-deterministic. When BOTH a
        // port-constrained app (e.g. tcp/8443) and a protocol-only app (tcp)
        // match the same session, the more-specific port-based app must win,
        // deterministically.
```

- Runtime trace:
  1. Config defines `aaa-tcp` as protocol-only TCP and `zzz-https-special` as TCP/443.
  2. With AppID enabled, Rust catalog assigns ids by sorted name and chooses the lowest id on overlap.
  3. Flow TCP/443 can be stamped as broad `aaa-tcp`.
  4. With AppID disabled, display fallback would prefer the port-constrained app.
  5. The same tuple changes displayed/logged application name based on AppID knob semantics.
- Why it matters: This is log/forensic correctness and operator trust. A more-specific application should usually beat a protocol-wide label.
- Suggested fix direction: Define one precedence rule for application labeling, preferably specificity first then deterministic name/id tie-break, and share tests across Go fallback and Rust catalog.
- Suggested labels: `appid`, `observability`, `security`, `test-gap`

### M05 - AppID catalog scan list is O(number of ranged/source/protocol-only apps) per cold lookup

- Severity: Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/policy.rs:1522-1542`

```rust
/// grouped by protocol, with exact single-destination-port entries in an O(1)
/// map and everything else (ranges, port-0/"protocol-only" entries) in a
/// per-protocol scan list. On overlap the first matching entry wins, which is
/// the lowest `app_id` because the Go builder emits entries in sorted-name /
/// ascending-id order; deterministic and stable across reloads.
#[derive(Clone, Debug, Default)]
pub(crate) struct AppCatalog {
    by_protocol: FxHashMap<u8, AppProtoEntries>,
}
```

`userspace-dp/src/policy.rs:1634-1644`

```rust
let mut scan_hit: Option<u16> = None;
for s in &bucket.scan {
    // Destination constraint is matched against the service slot and
    // the source constraint against the client slot — directional, no
    // cross-slot probing.
    let dst_ok = in_range(s.dst_low, s.dst_high, service_port);
    let src_ok = in_range(s.src_low, s.src_high, client_port);
    if dst_ok && src_ok {
```

- Runtime trace:
  1. Deployment enables AppID and defines many protocol-only/ranged/source-constrained apps under TCP/UDP.
  2. Every new session calls `AppCatalog::lookup_directional`.
  3. Exact single-destination-port hits are O(1), but everything else scans the full protocol bucket until a match.
  4. Cold session creation and deny/log paths pay linear work under large catalogs.
- Why it matters: This is not a packet-hit path, but high connection-rate routers/firewalls can be cold-path bound under scan-heavy AppID configs.
- Suggested fix direction: Split protocol-only, exact-dst, dst-range interval index, and src-constrained sub-indexes. Add microbenchmarks with 1k/10k catalog entries.
- Suggested labels: `performance`, `appid`, `latency`, `modularity`

### M06 - AppID `app_id` is not synced over HA session wire, so failover can relabel sessions after catalog drift

- Severity: Medium
- Confidence: Medium
- Evidence:

`docs/services-application-identification.md:70-77`

```text
   and dst slot so the forward and reverse conntrack entries
   resolve to the same `app_id`. **Note**: only the local
   session-owner stamps `app_id` in the conntrack map (the same
   property as `alg_type`); an HA-synced session on the standby
   peer is not mirrored into the conntrack map, and a session
   re-created locally after failover is re-stamped from the
   catalog (the catalog is shipped to both nodes), so `app_id`
   is re-derived rather than carried on the session-sync wire.
```

- Runtime trace:
  1. Node A owns a session and stamps app id `42`.
  2. Config/catalog changes or reload ordering creates a temporary catalog skew before failover.
  3. Session sync does not carry app id.
  4. Node B recreates or reports the session by re-deriving app id from its current catalog.
  5. RT_FLOW/session display can show a different application label for the same surviving flow.
- Why it matters: HA failover should preserve forensic identity when possible; app labels drive incident response and policy analysis.
- Suggested fix direction: Carry `app_id` in the HA session wire format or include catalog generation/epoch and assert both nodes agree before re-stamping.
- Suggested labels: `ha`, `appid`, `observability`, `vsrx-parity`

### M07 - Host-inbound deny branches increment `dbg.policy_deny`, conflating policy and host-inbound drops

- Severity: Low-Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1736-1747`

```rust
None => {
    // Host-inbound denied: silent drop, never
    // cached.
    telemetry.dbg.local += 1;
    telemetry.dbg.policy_deny += 1;
    telemetry.counters.touched = true;
    // #3326: account the host-inbound deny so
    // `GlobalCtrHostInboundDeny` reflects the drop
```

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3117-3124`

```rust
FlowlessLocalVerdict::HostInboundDeny => {
    telemetry.dbg.local += 1;
    telemetry.dbg.policy_deny += 1;
    telemetry.counters.touched = true;
    // #3326: account the host-inbound deny so
    // `GlobalCtrHostInboundDeny` reflects the drop.
    telemetry.counters.host_inbound_denied_packets += 1;
```

- Runtime trace:
  1. Host-inbound denies a packet before security policy evaluation.
  2. Code increments `host_inbound_denied_packets`.
  3. The same branch also increments debug `policy_deny`.
  4. Internal debug totals mix two different controls.
- Why it matters: Debug counters are used during dataplane investigations. Conflating host-inbound and policy denies can send engineers down the wrong path.
- Suggested fix direction: Add `dbg.host_inbound_deny` and leave `dbg.policy_deny` to real policy/default-policy denies.
- Suggested labels: `observability`, `debugging`, `host-inbound`

### M08 - Flowless LocalDelivery open issue #3292 appears stale against current code

- Severity: Medium
- Confidence: Medium
- Evidence:

`docs/issues/issue-history.md:51733-51742`

```text
## #3292 — userspace-dp: flowless LocalDelivery bypasses host-inbound, lo0 filter, and to-zone junos-host policy [OPEN]

## Summary

Recent work added host-inbound admission, the lo0 filter, and `to-zone
junos-host` policy to **flow-backed** LocalDelivery. The **flowless**
LocalDelivery arm bypasses all three. A host-bound flowless packet (e.g. a
non-first fragment addressed to a firewall interface IP, or any no-L4
LocalDelivery packet) is reinjected to the host without host-inbound admission,
```

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3078-3106`

```rust
// (4) #3292: flowless LocalDelivery (host-bound) enforcement.
//     A host-bound flowless packet (a non-first fragment / no-
//     L4 packet addressed to a firewall interface IP) MUST pass
//     the same gates the flow-backed LocalDelivery arm applies:
//     host-inbound admission, the lo0 host-bound filter, and
//     `to-zone junos-host` policy.
if final_resolution.disposition == ForwardingDisposition::LocalDelivery
    && let Some(l3_flow) = l3_ctx.as_ref()
{
```

- Runtime trace:
  1. Backlog says flowless LocalDelivery still bypasses host-inbound/lo0/junos-host.
  2. Current code comments and branch show flowless LocalDelivery calling `flowless_local_delivery_verdict`.
  3. That helper calls `host_inbound_gated_lo0_action` and `junos_host_policy_deny_action`.
  4. The open issue no longer appears to describe current master.
- Why it matters: Stale open security issues waste review effort and can hide the true residual gaps such as VLAN logical-ifindex handling.
- Suggested fix direction: Close #3292 if current tests prove fixed, or rewrite it to the remaining verified residual.
- Suggested labels: `issue-hygiene`, `host-inbound`, `security`

### M09 - No sustained-threshold screen rate test

- Severity: Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/screen/tests.rs:1838-1871`

```rust
fn icmp_flood_sliding_window_blocks_boundary_burst_then_recovers() {
    // #2937: the rate counter is a two-bucket sliding window, NOT a fixed
    // wall-second window. After the budget is exhausted in second 100, the
    // immediately following second (101) must NOT hand out a fresh full
    // budget — the previous second's tally still counts for the whole of
    // second 101. A full empty second must elapse before the budget frees.
    let mut profile = ScreenProfile::default();
```

- Runtime trace:
  1. Existing test intentionally exhausts and exceeds threshold in one second.
  2. It asserts the next second still drops.
  3. It does not test exactly-threshold traffic across many seconds.
  4. Therefore H02 can survive while boundary-burst tests pass.
- Why it matters: Tests pin the anti-burst property but not the operator threshold contract.
- Suggested fix direction: Add tests for exactly N events/sec over several seconds and N+1 events/sec recovery behavior.
- Suggested labels: `test-gap`, `screen`, `rate-limit`

### M10 - No VLAN LocalDelivery regression test for per-interface host-inbound override

- Severity: Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/afxdp/poll_descriptor/filter.rs:572-600`

```rust
/// A host-inbound-DENIED packet must return `None` (caller drops silently,
/// no reject reply / no session teardown) AND must NOT evaluate the lo0
/// filter — its counter stays 0. Reverting the reorder (lo0 first) bumps the
/// counter to 1 on the denied packet, turning this RED.
#[test]
fn host_inbound_deny_skips_lo0_side_effects() {
    let fw = forwarding_with_lo0_reject();
```

`userspace-dp/src/afxdp/poll_descriptor/filter.rs:538-548`

```rust
fn tcp_443_flow_and_meta() -> (SessionFlow, UserspaceDpMeta) {
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let meta = UserspaceDpMeta {
        protocol: PROTO_TCP,
        addr_family: libc::AF_INET as u8,
```

- Runtime trace:
  1. Current direct helper tests use default `UserspaceDpMeta`; they do not set VLAN id or parent/logical ifindex mapping.
  2. H04 depends on exactly that logical-vs-physical distinction.
  3. Test coverage can pass while VLAN per-interface overrides miss at runtime.
- Why it matters: The per-interface feature is most useful on logical units and RETH/VLAN layouts.
- Suggested fix direction: Build a forwarding state with parent ifindex plus VLAN logical mapping, set an interface override on the logical ifindex, then assert LocalDelivery uses the override.
- Suggested labels: `test-gap`, `host-inbound`, `vlan`, `vsrx-parity`

### M11 - Output-filter reject is documented as follow-up but no issue-history entry was found

- Severity: Medium
- Confidence: Medium
- Evidence:

`docs/feature-gaps.md:435-444`

```text
Filter `then reject` is now an **active** reject on the input and lo0
(host-bound) paths (#2521): it synthesizes a TCP RST (TCP) or ICMP/ICMPv6
admin-prohibited unreachable (otherwise) using the SAME machinery as policy
reject (`poll_descriptor/reject_reply.rs`), runs the generated reply through
#2238 output-filter/CoS/DSCP classification, and counts it on
`filter_reject_sent`. `then discard` stays a silent drop. Previously filter
reject collapsed to a silent drop (fail-closed parity gap). REMAINING GAP:
output-firewall-filter `then reject` realized on the TX/CoS path still
collapses to a silent drop
```

- Runtime trace:
  1. Docs say output-filter reject is tracked as a #2521 follow-up.
  2. `docs/issues/issue-history.md` has #2521 closed but no dedicated open entry for the TX residual in the local grep pass.
  3. The runtime gap remains in H03.
  4. Without a real issue, it is easy to lose during parity planning.
- Why it matters: This is an unclosed behavior gap in a security action.
- Suggested fix direction: File a dedicated issue for TX output-filter active reject or update an existing issue if one exists outside local docs.
- Suggested labels: `issue-tracking`, `firewall-filter`, `vsrx-parity`

### M12 - Host-inbound IPv6 Redirect is globally admitted; needs explicit hardening decision

- Severity: Medium
- Confidence: Medium
- Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:411-416`

```rust
///   2. IPv6 Neighbor Discovery (#3201/#3240) — RS (133), RA (134), NS (135),
///      NA (136), Redirect (137). ND is core L3 operation, accepted globally by
///      the nft chain (never a per-service exposure). Admitting it here is what
///      lets the per-zone `router-discovery` token carry NOTHING on v6 while
///      still matching nft — i.e. v6 RS/RA reach the host via this global ND
///      accept on any host-inbound-configured zone, exactly as nft does.
```

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:436-440`

```rust
// ICMPv6 errors: destination-unreachable (1), packet-too-big (2,
// PMTUD), time-exceeded (3), parameter-problem (4); PLUS the ND set:
// RS (133), RA (134), NS (135), NA (136), Redirect (137).
58 => matches!(icmp_type, 1 | 2 | 3 | 4 | 133 | 134 | 135 | 136 | 137),
```

- Runtime trace:
  1. Zone has host-inbound configured without router-discovery/ping.
  2. ICMPv6 Redirect to a firewall-local address arrives.
  3. Global accept fires before zone lookup.
  4. Redirect reaches host stack regardless of service/protocol posture.
- Why it matters: Redirects are often disabled/treated carefully on routers. The current behavior mirrors nft, but the security stance should be explicit and validated against kernel sysctls.
- Suggested fix direction: Decide whether Redirect belongs in global accept or should be gated; add tests/documentation for kernel sysctl posture and operator visibility.
- Suggested labels: `security-hardening`, `ipv6`, `host-inbound`, `vsrx-parity`

## 7. Low Confidence Findings

### L01 - Refactor LocalDelivery gate inputs into a resolved `HostInboundContext`

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/afxdp/poll_descriptor/filter.rs:435-447`

```rust
pub(super) fn host_inbound_gated_lo0_action(
    forwarding: &ForwardingState,
    host_inbound_zone: u16,
    dst_port: u16,
    is_v6: bool,
    icmp_first_l4_byte: u8,
    extra: TermMatchExtra<'_>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
```

- Runtime trace:
  1. Callers already resolve zone/logical context in different places.
  2. Helper receives raw `meta` and reinterprets the ingress interface internally.
  3. This enabled H04's logical-vs-physical ambiguity.
- Why it matters: Security gates should receive explicit resolved context, not reconstruct it from packet metadata after earlier stages resolved it differently.
- Suggested fix direction: Introduce `host_inbound::Context { raw_ifindex, logical_ifindex, zone_id, vlan_id }` and pass it through all LocalDelivery branches.
- Suggested labels: `refactor`, `modularity`, `host-inbound`

### L02 - Split host-bound policy semantics into a documented matrix and canary tests

- Severity: Low
- Confidence: Low
- Evidence:

`docs/issues/issue-history.md:51510-51518`

```text
## Runtime host-bound semantics (userspace-dp/src/policy.rs)

`evaluate_junos_host_policy` (policy.rs:1915-2007) returns `Some` ONLY when an
exact `from-zone <ingress> to-zone junos-host` rule or a `from-zone any to-zone
junos-host` rule matches. There is NO implicit junos-host default-deny, and
`to-zone any` / `from-zone any to-zone any` / global policies are explicitly
NOT applied to host-bound local delivery
```

- Runtime trace:
  1. Host-bound policy has different semantics from transit policy.
  2. The differences are spread across issue history, code comments, and CLI docs.
  3. New reviewers repeatedly rediscover and re-question the same behavior.
- Why it matters: The host/self traffic policy plane is security-sensitive; ambiguity causes regressions and duplicated review work.
- Suggested fix direction: Create a table-driven test matrix for exact, from-any, to-any, both-any, global, default, no-match, and unknown zone cases.
- Suggested labels: `test-gap`, `docs`, `firewall-policy`, `vsrx-parity`

### L03 - AppID enabled overlap policy should be made an explicit product decision

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/policy_tests.rs:3641-3652`

```rust
// Overlapping entries: first/lowest app_id wins, deterministically (the Go
// builder emits ascending ids in sorted-name order).
#[test]
fn app_catalog_overlap_lowest_id_wins() {
    // Two apps both claiming tcp/80 — exact-port path.
    let cat = AppCatalog::from_snapshot(&[cat_entry(5, 6, 80, 80), cat_entry(11, 6, 80, 80)]);
    assert_eq!(cat.lookup_forward(6, 40000, 80), 5);

    // Range vs exact overlap — lowest id still wins.
```

- Runtime trace:
  1. Tests intentionally pin lowest-id behavior.
  2. Fallback documentation intentionally pins specificity behavior.
  3. The mismatch may be acceptable, but it should be a documented product choice.
- Why it matters: Application labels are operator-facing security evidence.
- Suggested fix direction: Add a design note: AppID enabled precedence = lowest id or specificity; align tests/docs/runtime accordingly.
- Suggested labels: `appid`, `docs`, `product-decision`

### L04 - Host-inbound deny should be modeled as a first-class dataplane event kind

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/event_stream/mod.rs:122-137`

```rust
/// These events fire on drops / denies / log-matched packets (NOT per normal
/// packet), so one anchored clock read per emit is acceptable; correctness
/// (a real decision timestamp) is preferred over saving the read.
pub(crate) fn mono_ns_to_wall_clock_unix_ns(mono_ns: u64) -> u64 {
    let (now_mono_ns, now_unix_ns) = read_mono_and_wall_clocks();
    monotonic_ns_to_unix_ns(mono_ns, now_mono_ns, now_unix_ns)
}
```

- Runtime trace:
  1. Event stream already supports drop/deny/log events as cold-path records.
  2. Host-inbound denies are security drops but only counters today.
  3. A typed event would preserve operator observability without hot-path cost.
- Why it matters: Control-plane protection should be auditable at the same quality as transit policy denies.
- Suggested fix direction: Add `DataplaneEventKind::HostInboundDeny` and consume it in Go logging/API surfaces.
- Suggested labels: `observability`, `host-inbound`, `security`

### L05 - Output-filter reject needs a reusable reply-synthesis interface independent of descriptor ownership

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/afxdp/tx/cos_classify.rs:24-31`

```rust
/// #2238: classification verdict for a LOCALLY-GENERATED reply frame,
/// derived from the reply's OWN egress 5-tuple + egress interface (not the
/// triggering inbound packet's tuple). `drop == true` means an output
/// firewall filter terminal `discard`/`reject` (or a three-color policer)
/// on the egress interface dropped the reply, OR the generated bytes could
/// not be parsed (fail-CLOSED, §6.2). On `parse_error == true` the caller
/// MUST attribute the drop on a dedicated parse-error counter
```

- Runtime trace:
  1. Existing reject synthesis is built around inbound descriptor/frame context.
  2. TX output classification only returns a cached descriptor.
  3. `Reject` has no way to request an active reply from this layer.
- Why it matters: This structural split is why H03 remains incomplete.
- Suggested fix direction: Define a small `RejectRequest` with original tuple, ingress/egress context, packet length, and frame slice where available; let TX ask a common generator to synthesize or fail closed.
- Suggested labels: `refactor`, `firewall-filter`, `reject-action`

### L06 - `host-inbound` issue history and docs still carry conflicting default-admit/default-deny language

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/protocol/snapshot.rs:393-398`

```rust
/// #3070: whether the zone declared a `host-inbound-traffic` stanza. When
/// false the dataplane preserves admit-all for host-bound (local-delivery)
/// traffic on this zone; when true it default-denies host-bound traffic
/// whose system-service / protocol is not in the sets below (Junos
/// host-inbound posture). serde(default) keeps wire parity with an older Go
/// control plane that omits the field (#1961).
```

`docs/junos-cli-reference.md:291-299`

```text
  - **Default-deny posture (#3405):** EVERY configured security zone denies
    host-bound traffic by default (Junos/vSRX parity). A zone with interfaces
    but NO `host-inbound-traffic` stanza is treated exactly like an empty
    `host-inbound-traffic { }` stanza — it admits nothing, so SSH / HTTP / SNMP
    / routing protocols to a firewall-local interface IP in that zone are
    DROPPED unless the operator adds the matching `system-services` /
```

- Runtime trace:
  1. Snapshot struct comment still describes `host_inbound_configured=false` as admit-all for that zone.
  2. CLI reference says every configured zone denies by default after #3405.
  3. Readers may not know whether false still occurs for configured zones or only old-wire/global cases.
- Why it matters: Stale comments in security posture code cause future regressions.
- Suggested fix direction: Update snapshot comments to explain current Go emits every configured zone into the table and false is compatibility/old-wire/global-only.
- Suggested labels: `docs`, `host-inbound`, `security`

### L07 - Host-inbound IS-IS support is accepted-but-not-enforced at IP gate; needs explicit CLNS/LLC posture issue if parity is required

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:369-380`

```rust
// #3311: IS-IS rides OSI/CLNP directly over L2 (LLC-encapsulated, NOT
// IP), so it cannot be expressed in this IP-keyed admit model (proto
// number / TCP-UDP port / ICMP type). It is a recognized-but-no-op
// host-inbound token (Go SSOT: config.HostInboundL2Protocols; Rust
// mirror: HOST_INBOUND_L2_PROTOCOLS): the kernel delivers IS-IS PDUs to
// FRR's isisd via an LLC packet socket, outside the IP host-inbound
// filter (and the AF_XDP local-delivery path only ever classifies IP
// packets). This explicit arm is DOCUMENTARY
```

- Runtime trace:
  1. Operator configures `host-inbound-traffic protocols isis`.
  2. Commit accepts the token.
  3. IP host-inbound classifier no-ops it.
  4. Kernel/FRR receives IS-IS via packet socket outside this gate.
- Why it matters: This is documented and likely intentional, but vSRX parity around L2 control-plane policing remains incomplete.
- Suggested fix direction: If IS-IS control-plane filtering is required, add a separate CLNS/LLC nft or AF_PACKET admission path and tests; otherwise label as explicitly unsupported.
- Suggested labels: `vsrx-parity`, `routing`, `host-inbound`, `feature-gap`

### L08 - Global ICMP/ND host-inbound accepts need per-type counters for audit

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:397-416`

```rust
/// #3171/#3201/#3240: ICMP/ICMPv6 subtypes that the host-inbound layer admits
/// UNCONDITIONALLY — regardless of which services/protocols the ingress zone
/// lists — so the userspace LocalDelivery classifier matches the kernel
/// host-inbound chain's GLOBAL accepts at the top of the chain
/// (`pkg/daemon/daemon_nft.go` `buildHostInboundFilterPayload`):
/// `icmp type { destination-unreachable, time-exceeded, parameter-problem }`
/// and `icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 }`.
```

- Runtime trace:
  1. Packet matches global PMTUD/ND accept.
  2. Admission happens before zone lookup.
  3. No per-type/per-zone accept counter distinguishes PMTUD from ND/Redirect traffic.
- Why it matters: Global bypasses are correct for liveness but should be observable, especially during IPv6 control-plane abuse.
- Suggested fix direction: Add lightweight counters for global accept categories: ICMPv4 error, ICMPv6 error, ND, redirect.
- Suggested labels: `observability`, `ipv6`, `host-inbound`

### L09 - AppID protocol-only/range index could be a module directory, not more growth inside `policy.rs`

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/policy.rs:1515-1530`

```rust
/// #2008 M5: the L3/L4 application-identification catalog. Resolves a session's
/// 5-tuple to the numeric `app_id` the dataplane stamps on the conntrack
/// session so `show security flow session` reports a real application name. The
/// `app_id` values are assigned on the Go side (`appid.BuildCatalog`) in
/// lock-step with `CompileResult.AppNames`, which the show path consumes — so a
/// stamped id round-trips to the correct name.
///
/// This is the read-the-id sibling of [`CompiledApplications`]
```

- Runtime trace:
  1. Policy evaluation, address matching, app terms, junos-host, counters, and AppID catalog all live in `policy.rs`.
  2. AppID matching has separate performance and semantic requirements.
  3. Future L7/AppTrack work will add more AppID code if not split.
- Why it matters: The user's modularity requirement is directory modules (`appid/*.rs`), not larger feature files.
- Suggested fix direction: Move AppID catalog to `userspace-dp/src/appid/{catalog.rs,index.rs,tests.rs}` with policy importing a small lookup trait.
- Suggested labels: `refactor`, `modularity`, `appid`, `performance`

### L10 - Screen rate limiter should expose its approximation in operator docs

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/screen/rate.rs:4-8`

```rust
//! The limiter is a two-bucket **sliding-window counter** keyed on a
//! 1-second granularity clock (`now_secs`). It bounds the admitted event
//! rate across any rolling 1-second interval, not just within a fixed
//! calendar second.
```

- Runtime trace:
  1. Operator configures a screen threshold expecting nominal per-second behavior.
  2. Implementation is a coarse two-bucket approximation.
  3. Boundary and recovery behavior differ from a true sliding window/token bucket.
- Why it matters: Security tuning depends on knowing whether thresholds are exact, burst tolerant, or conservative.
- Suggested fix direction: Document exact semantics in user-facing screen docs and add CLI/API descriptions for over-throttle behavior until H02 is fixed.
- Suggested labels: `docs`, `screen`, `rate-limit`

### L11 - Host-bound default-policy behavior differs from simulator history and needs a current conformance test

- Severity: Low
- Confidence: Low
- Evidence:

`docs/issues/issue-history.md:51512-51518`

```text
`evaluate_junos_host_policy` (policy.rs:1915-2007) returns `Some` ONLY when an
exact `from-zone <ingress> to-zone junos-host` rule or a `from-zone any to-zone
junos-host` rule matches. There is NO implicit junos-host default-deny, and
`to-zone any` / `from-zone any to-zone any` / global policies are explicitly
NOT applied to host-bound local delivery (comment at policy.rs:1982-1987).
Host-inbound service admission runs first; an unmatched host-bound flow falls
```

- Runtime trace:
  1. Runtime host-bound policy intentionally skips default/global tiers.
  2. Historical issue text says simulator used transit precedence for host-bound queries.
  3. If simulator/API still drifts, operators can receive misleading match-policy results.
- Why it matters: Control-plane firewall policy must be explainable before commit and during audits.
- Suggested fix direction: Add a golden test comparing CLI/API policy-match output to Rust host-bound runtime matrix.
- Suggested labels: `test-gap`, `cli`, `firewall-policy`, `vsrx-parity`

### L12 - Default lifeline behavior should be encoded as data, not comments in security branches

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/policy.rs:2828-2833`

```rust
/// Crucially there is NO implicit default-deny here: an unmatched host-bound
/// flow falls through to today's behavior (local delivery proceeds). This is
/// the deliberate lifeline guarantee — configuring some junos-host policy
/// cannot silently brick management/host traffic that does not match a deny
/// rule. The stricter Junos "configured zone-pair implies default-deny"
/// posture is intentionally deferred (see docs/junos-cli-reference.md).
```

- Runtime trace:
  1. Lifeline guarantee is a security behavior encoded by comments and fallback `None`.
  2. Multiple security features now carry their own lifeline exceptions.
  3. Future refactors can accidentally widen lifeline scope or shrink it.
- Why it matters: Production router/firewall fail-safe posture should be explicit and auditable.
- Suggested fix direction: Model lifeline interfaces/zones/policies as explicit snapshot data and generate an audit table showing which traffic bypasses default-deny and why.
- Suggested labels: `refactor`, `security`, `host-inbound`, `modularity`

### L13 - AppID missing L7 features should be labeled `vsrx-parity` on issues, not only documented in feature table

- Severity: Low
- Confidence: Low
- Evidence:

`docs/feature-gaps.md:73-83`

```text
| **Application Identification (AppID)** | `services application-identification` | L7 DPI engine using signatures, heuristics, pattern matching. Identifies 4000+ apps regardless of port/protocol. Foundation for all AppSecure features. | High | Partial — L3/L4 catalog classification only; L7 DPI / signature engine is **not implemented**. The userspace dataplane stamps the matched catalog `app_id` on each session (#2008 M5) so `show security flow session` reports the real application; with the knob enabled, a session matching no catalog entry resolves to `UNKNOWN` (honest) instead of a built-in port guess. Full contract: [docs/services-application-identification.md](services-application-identification.md); operator-facing status: `show services application-identification status`. (#653) |
| **Application Tracking (AppTrack)** | `security application-tracking` | Log and report on applications traversing the device. Generates AppTrack log messages per session with app name, bytes, duration. | Medium | Missing |
| **Application Firewall (AppFW)** | `security application-firewall ...` | (Legacy, replaced by unified policies) Policy enforcement based on detected app identity | Medium | Missing |
```

- Runtime trace:
  1. Feature table documents AppSecure gaps.
  2. If GitHub issues are not labeled `vsrx-parity`, parity planning and filtering are weaker.
  3. Review campaigns may rediscover table rows instead of tracking implementation state.
- Why it matters: The user explicitly wants feature parity issues labeled as such.
- Suggested fix direction: Audit AppSecure-related issues and ensure `vsrx-parity`, `appid`, and feature-specific labels are applied.
- Suggested labels: `issue-hygiene`, `vsrx-parity`, `appid`

### L14 - `RateCounter` uses `u32` saturating counters; saturation is fail-closed but opaque

- Severity: Low
- Confidence: Low
- Evidence:

`userspace-dp/src/screen/rate.rs:37-48`

```rust
//! The hot path is allocation-free and integer-only (two `u32` adds and a
//! compare per event).

/// Sliding-window rate counter over two adjacent 1-second buckets.
#[derive(Debug, Clone, Default)]
pub(super) struct RateCounter {
    /// Events counted in the current 1-second bucket.
    pub(super) count: u32,
    /// Events counted in the immediately preceding 1-second bucket.
```

`userspace-dp/src/screen/rate.rs:79-82`

```rust
pub(super) fn increment(&mut self, now_secs: u64, threshold: u32) -> bool {
    self.advance(now_secs);
    self.count = self.count.saturating_add(1);
    self.prev_count.saturating_add(self.count) > threshold
}
```

- Runtime trace:
  1. Extreme flood drives `count` to `u32::MAX`.
  2. Saturating add preserves fail-closed over-limit state.
  3. There is no explicit counter/metric for saturation.
  4. Operators cannot distinguish normal over-threshold from numeric saturation.
- Why it matters: Saturation can be a signal of severe attack or clock/update bug.
- Suggested fix direction: Add a rare saturation counter or debug trace and a unit test.
- Suggested labels: `screen`, `observability`, `hpc-invariant`

## 8. Negative Results / Non-Findings

- IS-IS token acceptance itself is not re-filed as the old hard-reject bug: #3311 is closed and current code explicitly accepts it as a documented L2 no-op.
- The `system-services all` and `any-service` full-packet semantics were not re-reported because #3226 is open.
- Flowless LocalDelivery bypass was not re-reported as originally filed because current code routes flowless LocalDelivery through `flowless_local_delivery_verdict`; the remaining concern is stale issue state and logical-interface details.
- Positional policy id was not re-reported because #3395 is open and current comments show an O(1) stable re-resolution design in progress/current code.
- The full L7 AppID/AppSecure suite is not re-reported as one giant new issue because it is already in `docs/feature-gaps.md`; only narrower semantics/performance/test issues are listed.

## 9. HPC / Low-Level Invariant Notes

- Atomic wrapping: No new high-confidence wraparound bug found. `RateCounter` uses saturating `u32`, which is fail-closed but under-instrumented (L14).
- Lock contention: No new lock contention bug found in the inspected hot paths. The relevant latency risk is AppID scan-list linear lookup on cold session creation (M05).
- Cache line alignment: Not enough evidence in this pass for a concrete false-sharing issue; no finding filed.
- Endianness: No new endian mismatch found in inspected firewall/host-inbound/AppID paths.
- Cold vs hot path: Generated reply classification is intentionally cold; output-filter reject remains incomplete because the hot cached TX path lacks reply context (H03/L05).

## 10. Suggested Issue Split

1. `from-zone junos-host` host-originated policy enforcement (H01).
2. Screen `RateCounter` sustained-threshold over-throttle and tests (H02, M09, L10, L14).
3. Output firewall-filter TX `then reject` active reply support and tracking (H03, M11, L05).
4. VLAN/logical-interface per-interface host-inbound LocalDelivery fix and test (H04, M10, L01).
5. Unknown/global host-inbound zone posture and observability (H05, L08).
6. Host-inbound deny tuple-rich event and debug-counter split (H06, M07, L04).
7. Host-bound policy parity roadmap: implicit default-deny, wildcard/global tiers, global `junos-host` context (M01, M02, M03, L02, L11, L12).
8. AppID precedence/performance/HA labeling package (M04, M05, M06, L03, L09).
9. IPv6 ND/Redirect global accept hardening and per-type counters (M12, L08).
10. Issue-hygiene pass: stale #3292 and `vsrx-parity` labels on feature-parity issues (M08, L13).
