# Codex review 163 - vSRX firewall policy execution audit

Base commit: `4cc1b9085`
Output path: `/tmp/codex-review-163.md`
Campaign mode: quota campaign, not a best-findings pass.

## Duplicate Suppression

Read prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, `docs/issues/issue-history.md`, and `docs/issues/pr-history.md` for overlapping firewall policy work. I intentionally did not re-report:

- Host-inbound default-deny / `junos-host` display and broad `to-zone any` host-bound behavior from older reviews.
- The already-fixed policy verdict bug where `junos-ping`/`junos-pingv6` matched every ICMP type (#3020/#3194).
- The already-fixed wildcard-zone enforcement work (`from-zone any`, `to-zone any`, both-any) and scoped-global enforcement work (#3018/#3148).
- The previously reported direct snapshot integrity holes around duplicate `rule_id`/`policy_id`, bad ICMP fields, malformed addresses, and scheduler inventory display.
- The already-fixed AppID directionality, DNAT post-translation AppID, app-id space, and source-port catalog issues.

This report focuses on residual runtime execution and observability mismatches: policy verdict vs AppID attribution, counter clear races, scheduler state freshness, cold-path histogram coverage, and module/test gaps around those surfaces.

## Module Checklist

1. `userspace-dp/src/policy.rs` - application matcher, zone/global tiers, hit counters, default policy, junos-host policy.
2. `userspace-dp/src/protocol/security.rs` - policy/application/catalog wire structs.
3. `userspace-dp/src/afxdp/poll_descriptor/mod.rs` - transit, flowless, MissingNeighbor, and histogram policy call sites.
4. `userspace-dp/src/afxdp/event_emit.rs` - RT_FLOW policy-deny/filter/session AppID attribution.
5. `pkg/appid/catalog.go` and `pkg/appid/runtime.go` - catalog build/tie-break/show semantics.
6. `pkg/dataplane/userspace/flow.go` and `protocol.go` - AppCatalog wire projection.
7. `pkg/config/compiler_applications.go` - ICMP application lowering and custom app grammar.
8. `pkg/dataplane/userspace/manager.go` - scheduled-policy snapshot republish.
9. `pkg/daemon/daemon_scheduler.go` - scheduler callback path and error propagation.
10. `userspace-dp/src/afxdp/forwarding_build/mod.rs` and `cold_path_hist.rs` - zone-pair histogram map build/record.
11. `userspace-dp/src/session/entry.rs`, `server/helpers.rs`, `protocol/control.rs` - synced policy metadata import.
12. Policy tests and docs - coverage confirmation.

## Inspection Log

- Policy matcher: inspected `CompiledApplications`, `try_match_rule`, exact/wildcard/global order, default-policy counter, and `junos-host` evaluator. Negative result: exact/wildcard/global verdict precedence now matches the documented tiers; I found no new direct allow/deny bypass in the main transit evaluator.
- AppID catalog: inspected Go catalog build, Rust catalog wire mirror, Rust lookup, and RT_FLOW emitters. Findings: AppID attribution still cannot represent ICMP type/code or the actual matched policy term.
- Counter path: inspected `PolicyRuleCounter::reset`, coalesced worker batches, direct tests, and clear handler plumbing. Finding: the generation bump ordering can lose post-clear hits under a real interleaving not covered by tests.
- Scheduler path: inspected daemon scheduler publish callback and userspace manager republish. Finding: scheduler changes are fire-and-forget and full-snapshot based; failures leave stale enforcement.
- Histogram path: inspected slot-map construction from `configured_zone_pairs` and record call sites. Finding: wildcard/global-only deployments are uninstrumented.
- HA/session sync: inspected current policy metadata fields. Negative result: the old "policy id is zero on synced sessions" is closed by `policy_id`, `policy_counter_idx`, and `inactivity_timeout` fields. Residual below is narrower: the sync import still cannot bind a stable local counter Arc.

## High Confidence Findings

### H1. ICMP AppID attribution still ignores ICMP type/code, so non-echo ICMP can log as `junos-ping`

Labels: `bug`, `security-observability`, `appid`, `icmp`, `vsrx-parity`

Evidence:

```text
userspace-dp/src/protocol/security.rs:500-523
AppCatalogEntry has app_id, protocol, dst_port_low/high, src_port_low/high.
It has no icmp_type or icmp_code fields.

pkg/appid/catalog.go:157-166
ProtocolNumber maps "junos-ping" to protocol 1 and "junos-pingv6" to 58.

pkg/dataplane/userspace/flow.go:155-164
buildAppCatalogSnapshot copies only AppID/protocol/port bounds into the wire row.

userspace-dp/src/afxdp/event_emit.rs:123-134
resolve_policy_deny_app_id resolves a deny record from protocol/src/dst port only.
```

Runtime trace:

1. Configure `services application-identification` and a policy that references `junos-ping`; policy matching itself is now echo-request-only because `PolicyApplicationSnapshot` carries `icmp_type`.
2. The AppID catalog row for `junos-ping` still becomes `(protocol=1, ports=0/0)`.
3. An ICMP timestamp packet or destination-unreachable packet fails the `junos-ping` policy match and falls to default deny.
4. The deny event calls `resolve_policy_deny_app_id`, which probes only protocol and ports.
5. The RT_FLOW policy-deny record can carry the `junos-ping` app_id for a packet that explicitly did not match `junos-ping`.

Why it matters: firewall audit logs should explain the verdict. Here the verdict engine and the log application engine use different semantic models. This is especially bad for ICMP because `junos-ping` is a security-sensitive allow/deny shorthand.

Suggested fix: add optional `icmp_type`/`icmp_code` to `AppCatalogEntrySnapshot` and Rust `AppCatalogEntry`, include them in catalog matching, and add tests for echo, timestamp, unreachable, and ICMPv6 RA/NS/NA cases. Until the wire changes, force ICMP type-constrained apps to resolve UNKNOWN rather than a misleading app id.

### H2. Session/RT_FLOW AppID can disagree with the policy application term that admitted the flow

Labels: `bug`, `appid`, `policy`, `observability`, `vsrx-parity`

Evidence:

```text
userspace-dp/src/policy.rs:1476-1492
CompiledApplications::matches returns only the matched term's optional timeout.

userspace-dp/src/policy.rs:1522-1563
The actual policy matcher chooses the lowest config-order matching term.

userspace-dp/src/policy.rs:1678-1755
AppCatalog::lookup_directional chooses by specificity tier and then lowest app_id.

pkg/appid/catalog.go:48-58, 76-82
app_id values are assigned in sorted-name order, not in per-policy application order.
```

Runtime trace:

1. Define two user applications with the same L3/L4 match, for example two TCP/443 aliases with different names and different inactivity-timeout values.
2. Put the later alphabetic app first in a policy application list so the policy matcher admits the flow using that first term and its timeout.
3. On session creation, AppID is re-resolved from the global catalog, not returned from `CompiledApplications::matches`.
4. The catalog chooses the lower `app_id`, which is the alphabetically earlier application.
5. The session and RT_FLOW records name a different application than the one whose policy term and timeout admitted the flow.

Why it matters: operators use AppID, policy name, and timeout together for incident reconstruction. Splitting "matched app term" from "display app id" makes those records internally inconsistent.

Suggested fix: have `CompiledApplications::matches` return a matched application identity along with timeout, and stamp that identity on the session/log path when the match came from policy evaluation. Keep the global catalog as a fallback for `application any` / non-policy surfaces.

### H3. `clear security policies hit-count` can lose post-clear hits because `reset()` bumps the generation before zeroing counters

Labels: `bug`, `counters`, `concurrency`, `policy`, `hpc-correctness`

Evidence:

```text
userspace-dp/src/policy.rs:1137-1144
fn reset(&self) {
    self.generation.fetch_add(1, Ordering::Relaxed);
    self.packets.store(0, Ordering::Relaxed);
    self.bytes.store(0, Ordering::Relaxed);
}

userspace-dp/src/policy.rs:1289-1315
record_policy_hit_counter reads counter.generation(), captures a pending batch,
and later flushes it if the generation still matches.
```

Runtime trace:

1. Control plane calls clear; `reset()` increments generation from `G` to `G+1`.
2. Before `packets.store(0)` runs, a worker records a legitimate post-clear packet and captures generation `G+1`.
3. The worker reaches the flush threshold or batch end and `add_batch`s the packet into the shared atomic because its generation matches.
4. `reset()` resumes and stores `packets=0`, wiping the post-clear hit.

Why it matters: policy hit counters are audit evidence. A clear should remove pre-clear hits; it must not erase traffic that arrived after the clear boundary.

Suggested fix: make clear a two-phase epoch or a locked/seqlocked reset that establishes an ordering boundary visible to workers. At minimum, add a production-style interleaving test; the current tests drive `flush_pending_policy_hit_record` directly and do not cover this race.

### H4. Scheduled-policy state changes are fire-and-forget; failed userspace republish leaves stale enforcement

Labels: `bug`, `scheduler`, `policy`, `fail-closed`, `vsrx-parity`

Evidence:

```text
pkg/daemon/daemon_scheduler.go:120-139
publishPolicyScheduleState acquires applySem and calls updatePolicyScheduleStateLocked.

pkg/daemon/daemon_scheduler.go:151-163
updatePolicyScheduleStateLocked calls updater.UpdatePolicyScheduleState(...) with no error return.

pkg/dataplane/userspace/manager.go:794-826
UpdatePolicyScheduleState can log and return on policy build, address-book build,
disarm, or apply_snapshot failure.
```

Runtime trace:

1. A scheduler window closes and `activeState["workhours"]` flips false.
2. The daemon callback calls `UpdatePolicyScheduleState`.
3. Userspace snapshot republish fails, for example helper apply_snapshot errors or policy/address-book rebuild fails.
4. The method logs and returns; the daemon receives no error and records no retry-needed state.
5. The old helper snapshot remains live with the old `inactive` bits. A scheduled permit can remain active after its time window closed.

Why it matters: scheduled firewall policy is enforcement, not display. A stale allow-after-window is a security failure. vSRX behavior is deterministic around time gates; xpf should either publish the new state or fail closed/alert/retry.

Suggested fix: change `UpdatePolicyScheduleState` to return an error/result, add a daemon retry/metric/alarm, and define the fail-closed behavior for scheduled permits when a scheduler-only republish fails.

### H5. Wildcard/global-only policy deployments have no cold-path histogram slot

Labels: `observability`, `perf`, `policy`, `cold-path`, `vsrx-parity`

Evidence:

```text
userspace-dp/src/policy.rs:2029-2047
configured_zone_pairs() builds the histogram slot set only from zone_pair_index.

userspace-dp/src/policy.rs:2415-2465
Wildcard policies live in from_any_index, to_any_index, and both_any_indices.

userspace-dp/src/policy.rs:2955-2986
Global policies are evaluated for concrete from/to zone ids.

userspace-dp/src/afxdp/forwarding_build/mod.rs:333-338
ColdPathSlotMap is built from state.policy.configured_zone_pairs().

userspace-dp/src/afxdp/poll_descriptor/mod.rs:2267-2282
Recording is skipped when lookup_slot misses.
```

Runtime trace:

1. Configure only `from-zone any to-zone untrust` and/or `security policies global` rules.
2. Traffic from `trust` to `untrust` is correctly evaluated by the wildcard/global tier.
3. The cold-path slot map was built only from exact `zone_pair_index` entries, so `(trust, untrust)` has no slot.
4. `lookup_slot` returns `None` and the latency sample is silently skipped.

Why it matters: a common vSRX-style catch-all policy design becomes invisible to the cold-path latency instrumentation that is supposed to prove first-packet policy health.

Suggested fix: build histogram candidate pairs from concrete zone table cross-products constrained by wildcard/global policy scopes, or add a separate wildcard/global bucket family. Add a test with no exact zone-pair policies.

## Medium Confidence Findings

### M1. AppID ICMP type/code fix is a wire-contract issue, not just a builder bug

Labels: `design`, `appid`, `wire-protocol`, `icmp`

Evidence: both Go and Rust wire structs contain only protocol and ports (`pkg/dataplane/userspace/protocol.go:1083-1098`, `userspace-dp/src/protocol/security.rs:500-523`). This means a correct fix for H1 cannot be localized to `pkg/appid/catalog.go`; the snapshot protocol needs additive fields and compatibility tests.

Suggested fix: create a small AppID wire vNext plan with `icmp_type`, `icmp_code`, and tests proving older helpers fail honest UNKNOWN instead of false labels.

### M2. Policy matcher returns timeout but not match reason, blocking precise logs, counters, and diagnostics

Labels: `refactor`, `policy`, `observability`

Evidence: `CompiledApplications::matches` returns `Option<Option<u32>>` (`userspace-dp/src/policy.rs:1504-1511`), and `try_match_rule` propagates only `inactivity_timeout` (`userspace-dp/src/policy.rs:3236-3242`). The matched application name/id, term index, and miss reason are discarded.

Impact: H2 is one symptom. The same shape prevents `request security test policy` and RT_FLOW from saying whether an app, source, destination, scheduler, or ICMP-type predicate selected the verdict.

Suggested fix: return a compact `ApplicationMatchResult { timeout, app_id/name/term_index }` and carry miss reasons in debug/test builds.

### M3. Address checks run after application matching, making address-miss traffic pay expensive application scans

Labels: `perf`, `policy`, `cold-path`, `hpc`

Evidence: `try_match_rule` first calls `rule.compiled_apps.matches(...)` (`userspace-dp/src/policy.rs:3236-3242`) and only then evaluates source/destination address sets (`userspace-dp/src/policy.rs:3261-3365`).

Trace:

1. A rule has a large application set and a narrow source address set.
2. A scan from an address outside the source set arrives.
3. The rule still runs the application matcher before failing the cheap address predicate.

Suggested fix: split the evaluator into cheap prefilters and expensive app/address-book paths. For most rules, source/destination literal/book checks can reject before app range scans.

### M4. Scheduler-only updates invalidate the whole forwarding generation

Labels: `perf`, `scheduler`, `flow-cache`, `latency`

Evidence: `UpdatePolicyScheduleState` increments `m.generation` and publishes a whole `apply_snapshot` (`pkg/dataplane/userspace/manager.go:777-830`). Flow-cache validation keys include config generation in prior code paths, so a pure scheduler bit flip can flush otherwise valid cache entries and force new-flow cold-path work.

Impact: a frequent policy schedule boundary on a large router can cause avoidable first-packet latency and CPU spikes unrelated to routes/NAT/CoS.

Suggested fix: make scheduler inactive state a small policy-generation subresource or a side-band update with a policy epoch, not a full forwarding generation when only inactive bits change.

### M5. Scheduler-only republish sends a full snapshot over the helper control channel

Labels: `perf`, `scheduler`, `control-plane`, `modularity`

Evidence: the scheduler path clones the last snapshot, rebuilds policies/address books, filters neighbors, and sends `ControlRequest{Type: "apply_snapshot"}` (`pkg/dataplane/userspace/manager.go:777-826`).

Impact: the cost of a time-of-day policy flip scales with the entire config size, not with the number of scheduled policies. This is not HFT-grade control-plane design for large policy tables.

Suggested fix: define a `set_policy_inactive_bitmap` or `set_policy_scheduler_state` control request carrying only rule IDs and inactive bits.

### M6. Default-policy counter collapses unzoned traffic and ordinary policy misses into one row

Labels: `observability`, `policy`, `default-policy`, `vsrx-parity`

Evidence: unknown-zone traffic jumps straight to the default branch (`userspace-dp/src/policy.rs:2846-2858`), and every no-match/default path increments the same `state.default_counter` (`userspace-dp/src/policy.rs:2989-2995`).

Impact: `show security policies hit-count` can tell that default policy was hit, but not whether the hits are unzoned-interface leakage, exact zone-pair miss, wildcard miss, or global miss. Those are operationally different root causes.

Suggested fix: add structured default-policy subcounters by reason and from/to zone id, while keeping the existing aggregate for compatibility.

### M7. Default-policy logging cannot be scoped by zone pair

Labels: `feature-gap`, `policy`, `logging`, `vsrx-parity`

Evidence: the implicit default branch emits one sentinel policy id and global default log flags (`userspace-dp/src/policy.rs:2996-3023`). There is no per-zone-pair default row or per-zone default log decision.

Impact: operators often need "trust to untrust default deny" vs "dmz to trust default deny" as separate audit streams. Current logs require reconstructing zones from each event rather than configuring/reporting a zone-specific default.

Suggested fix: support generated per-zone default rows in display/counters/log rendering, even if enforcement remains one default action.

### M8. Peer-synced sessions still cannot bind a stable local counter Arc on import

Labels: `ha`, `policy-counters`, `observability`

Evidence: sync import now carries `policy_counter_idx`, but `server/helpers.rs:488-497` still sets `policy_counter: None`. `PolicyState::resolve_session_hit_counter` falls back to positional lookup when the bound handle is absent (`userspace-dp/src/policy.rs:1959-1970`).

Confidence note: HA requires identical config at sync time, so this is not a normal failover bug. The residual appears when a session is synced, then the receiving node's policy table is reordered before it forwards/promotes that session.

Suggested fix: on sync import, resolve `policy_counter_idx` to a local Arc immediately when the snapshot generation matches. Longer term, carry stable `rule_id` on the sync wire.

### M9. Flowless fragment policy behavior is correct by code comments but incomplete as vSRX feature parity

Labels: `feature-gap`, `fragments`, `policy`, `vsrx-parity`

Evidence: flowless non-first fragments call `evaluate_policy_result_l3_aware` with ports zero and `l4_present=false` (`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3173-3187`). Protocol-only and `application any` terms can still match, while port-bearing terms fail closed.

Concern: vSRX policy behavior for fragments often has explicit fragment handling and screen interactions. This implementation has local semantics, but I did not find a feature surface that lets operators choose "drop all non-first fragments unless fragment reassembly/state exists" per zone/policy.

Suggested fix: document fragment policy parity and add a configurable fragment policy/screen mode if vSRX supports it in the target feature set.

### M10. AppID catalog tie-break remains alphabetic within a specificity tier

Labels: `appid`, `observability`, `vsrx-parity`

Evidence: `AppCatalog::lookup_directional` takes the minimum app id within a tier (`userspace-dp/src/policy.rs:1740-1755`), and app ids are sorted-name order (`pkg/appid/catalog.go:48-58`).

Confidence note: prior work intentionally aligned enabled AppID with disabled fallback. The remaining gap is vSRX/DPI parity: alphabetic name is not a domain-specific specificity or signature priority model.

Suggested fix: introduce explicit application priority/order metadata and keep alphabetic tie-break only as the final deterministic fallback.

## Low Confidence / Triage Findings

### L1. No direct test for ICMP AppID type/code attribution

Labels: `test-gap`, `appid`, `icmp`

I found tests proving policy ICMP type enforcement and TCP/UDP AppID attribution, but not an end-to-end case where `junos-ping` policy deny/session logging refuses to label non-echo ICMP as ping. Add tests around H1 before touching the wire.

### L2. Counter clear tests bypass the production thread-local coalescer

Labels: `test-gap`, `counters`, `concurrency`

The #3448 tests directly construct `PendingPolicyHitRecord` because the thread-local coalescer is disabled under `cfg(test)` (`userspace-dp/src/policy_tests.rs:5750-5865`). That misses the actual race in H3. Add a test-only hook or loom-style model for reset/record/flush interleavings.

### L3. No histogram test for wildcard/global-only policy configs

Labels: `test-gap`, `cold-path`, `policy`

Existing cold-path histogram tests cover direct zone-pair slot building. Add a fixture with only `from-zone any to-zone X`, only both-any, and only scoped/unscoped global policies, then assert the expected observability behavior.

### L4. Scheduler republish failures are log-only, with no metric or alarm

Labels: `observability`, `scheduler`, `operations`

H4 is worse than observability, but even the log-only path is insufficient. I did not find a counter for failed scheduler snapshot republish, stale scheduler state age, or pending scheduler retry.

### L5. Policy/default counters should expose reason dimensions without changing the existing aggregate

Labels: `observability`, `policy`, `metrics`

This is the metrics sibling of M6/M7. Add Prometheus labels or separate rows for `default_reason={unknown_zone,no_match}` and exact from/to zone ids.

### L6. `policy.rs` is carrying too many separable subsystems

Labels: `refactor`, `modularity`, `rust`

`policy.rs` contains zone-id sentinels, application matching, AppID catalog, address-book matching, scheduler inactive handling, policy counters, default policy, and junos-host evaluation. This is hard to audit. A modular layout should look like `policy/{apps.rs,catalog.rs,counters.rs,zone_index.rs,eval.rs,host.rs}` rather than one feature file.

### L7. `poll_descriptor/mod.rs` still owns too much policy orchestration

Labels: `refactor`, `modularity`, `rust`, `hot-path`

Policy call sites, histogram sample timing, policy deny event emission, flowless logic, and MissingNeighbor policy evaluation are still interleaved in the giant poll descriptor. The previous cold-path extraction helped, but policy enforcement would be easier to reason about in `poll_descriptor/policy_gate.rs` with small typed inputs/outputs.

### L8. Host-bound and transit policy share matcher internals but not one explicit tier engine

Labels: `refactor`, `policy`, `junos-host`

Transit and junos-host evaluation both call `try_match_rule`, but tier traversal is hand-coded separately. That is how host-bound/global/wildcard parity holes have repeatedly appeared in older reports. Extract a shared tier engine parameterized by eligible tiers.

### L9. AppID and policy application matching duplicate overlapping semantics

Labels: `refactor`, `appid`, `policy`

`CompiledApplications` and `AppCatalog` both implement protocol/port/range matching but with different return values and tie-breaks. H1/H2 are symptoms. Consider one match core that can return either verdict metadata or catalog identity.

### L10. Scheduled policy should have a feature-specific runtime state object

Labels: `refactor`, `scheduler`, `policy`

Scheduler state currently rides whole-snapshot rebuilds and a daemon callback. A `policy/scheduler_state` object with epoch, desired active map, applied active map, stale age, last error, and retry policy would make correctness inspectable.

### L11. Default-policy behavior is not modeled as a first-class policy row in Rust

Labels: `refactor`, `default-policy`, `policy`

The default policy is hand-built in the evaluation tail rather than represented as a synthetic rule in the same rule model. This keeps producing special cases: sentinel id, separate counter, separate log flags, no scope. Consider making it an explicit generated rule per scope.

### L12. The current report found no new direct exact-zone allow/deny bypass

Labels: `negative-result`, `policy`

I inspected exact zone-pair, single-wildcard, both-any, scoped-global, default, and junos-host traversal. Within the current model, I did not find a new core exact-zone verdict bug where packets that should be denied by an exact policy are allowed, or packets permitted by an exact policy are denied. The findings above are residual correctness/observability/performance gaps around that core.

## Suggested Split

1. `bug(appid): carry ICMP type/code in AppCatalog and fail honest UNKNOWN for old helpers` - H1, M1, L1.
2. `bug(policy): stamp matched application identity from policy evaluation` - H2, M2, L9.
3. `bug(policy-counters): make hit-count clear linearizable with post-clear traffic` - H3, L2.
4. `bug(scheduler): make policy scheduler republish return errors, retry, and alert on stale enforcement` - H4, L4, L10.
5. `perf(policy): cover wildcard/global policies in cold-path histogram slots` - H5, L3.
6. `perf(policy): separate cheap address prefilters from expensive application scans` - M3.
7. `perf(scheduler): publish scheduler inactive bitmap instead of full snapshots` - M4, M5.
8. `observability(policy): split default-policy counters/log rows by reason and zone pair` - M6, M7, L5, L11.
9. `ha(policy): bind synced policy_counter_idx to stable local rule counter where possible` - M8.
10. `refactor(rust-policy): split policy.rs and poll_descriptor policy gates into modules` - L6, L7, L8, L9.

