# Codex Review 162 - Userspace Flow-Cache Hit Path Audit

Base commit: `ddf9f5870`
Output path: `/tmp/codex-review-162.md`
Reviewer: codex
Scope: Rust userspace dataplane flow-cache hit path, session liveness, filter accounting, CoS classification, TTL ordering, DSCP rewrite, and VLAN/keying interactions.

## Duplicate Suppression Summary

I read prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, `docs/issues/issue-history.md`, `docs/issues/pr-history.md`, `userspace-dp/src/FEATURES.md`, `userspace-dp/src/afxdp/README.md`, and relevant per-module README files.

Important duplicate/residual decisions:

- Prior issue history already covers raw-parent VLAN flow-cache keying around `issue-history.md:37528`; I do not count VLAN flow-cache key aliasing as a fresh high-confidence finding here.
- Prior issue #2220 says the flow-cache entry outliving its session was fixed by per-session keepalive. The current code still allows a cache hit after the real session is gone, so I treat this as an incomplete closure/regression of #2220, not a duplicate.
- Prior PR #2573 covers cached output/tx filter counter replay. It does not cover plain input filter `then count` replay; that is counted here.
- Prior reports cover generated reply output CoS/DSCP issues; this report is about transit cached-flow hit behavior.

## Module Checklist

1. `afxdp/flow_cache.rs` admission, keying, hit validation, debug counters.
2. `afxdp/poll_descriptor/flow_cache_hit.rs` cached-hit execution order.
3. `session/mod.rs` touch/accounting liveness semantics.
4. `afxdp/worker/loop_body/mod.rs` session expiry and slow-path TTL order.
5. `afxdp/forwarding/mod.rs` cached decision validation.
6. `afxdp/tx/cos_classify.rs` cached vs live CoS selection.
7. `filter/compiler.rs` input/output filter cache-sensitive flags.
8. `poll_descriptor/filter.rs` input filter log/counter replay.
9. `afxdp/frame/mod.rs` and TX transmit rewrite DSCP behavior.
10. `tcp_flags.rs` cache eligibility for ACK-only TCP.
11. `afxdp/types/mod.rs` per-packet metadata available to keys/classifiers.
12. `docs/issues/*` and prior `/tmp` reports for duplicate suppression.

## Inspection Log

### 1. Flow cache admission/keying

Correctness/security: `FlowCacheEntry::from_forward_decision` declines DSCP-sensitive input/output filters and per-packet L4 filter terms (`flow_cache.rs:367-412`), but the cache entry still captures CoS DSCP/PCP classifier output and a descriptor keyed only by tuple plus raw ingress ifindex.

vSRX completeness: vSRX-style CoS classifiers are per packet. Cached first-packet DSCP/PCP class reuse is not acceptable for mixed-marking flows.

Performance/latency: the current design is fast but conflates per-flow and per-packet classifiers; performance needs a cacheability gate or key expansion, not replay of mutable packet state.

Modularity/refactor: admission policy and cached CoS state are split across `flow_cache.rs` and `tx/cos_classify.rs`, making cache-sensitivity drift likely.

Test gaps: no tests were found for same tuple with changed DSCP, changed PCP, or expired session on cache hit.

### 2. Cached-hit execution order

Correctness/security: `stage_flow_cache_hit` replays counters/policers/logs at `flow_cache_hit.rs:133-184`, then refreshes/account sessions at `:195-211`, and only then checks TTL/hop-limit at `:217-240`.

vSRX completeness: router TTL behavior should produce Time Exceeded before egress policy side effects for packets that never egress.

Performance/latency: false policer charges and logs pollute fast-path counters and can create misleading operational tuning.

Modularity/refactor: cached hit is doing policy counters, filter counters, policing, TTL, session accounting, mirror, and TX scheduling in one stage. A `CachedFlowPipeline` with ordered phases would make invariants testable.

Test gaps: no test asserts cached TTL-expired packet bypasses egress policers/logs/counters.

### 3. Session liveness and expiry

Correctness/security: session expiry deletes session/BPF state at `worker/loop_body/mod.rs:713-744`; no flow-cache invalidation is performed there. Cached hit validation calls no session-table liveness API.

vSRX completeness: a stateful firewall must not forward established-session traffic after the session is gone.

Performance/latency: doing a full session lookup on every hit may be too expensive, but expiry-driven invalidation or a session-generation stamp is cheap.

Modularity/refactor: session lifecycle and flow-cache lifecycle are not connected by a single owner/event API.

Test gaps: no test proves session expiry invalidates or misses the corresponding flow cache entry.

### 4. Cached vs live CoS selection

Correctness/security: live CoS selection checks `tx_selection_enabled_v4/v6` at `cos_classify.rs:301-310`; cached CoS selection does not have the same family gate at `:93-235`.

vSRX completeness: CoS behavior must be symmetric across first packet, session-hit slow path, and cache hit.

Performance/latency: duplicated live/cached evaluators increase long-term drift risk in hot-path class selection.

Modularity/refactor: one evaluator should take a side-effect mode: live-counted, cache-seed, or cache-replay.

Test gaps: no direct parity test across live and cached CoS selection for family enable flags.

### 5. Input/output filter replay

Correctness/security: output/tx filter counters are replayed via `cached_descriptor.tx_selection.filter_counters` (`flow_cache_hit.rs:133-140`). Plain input filter counters are not captured by `CachedInputFilterLog` (`poll_descriptor/filter.rs:247-250`, `:286-294`) and are not replayed.

vSRX completeness: firewall filter `then count` on input is operator-visible policy evidence; it must count the full cacheable flow, not just the cache seed packet.

Performance/latency: a compact input replay descriptor can avoid full filter evaluation.

Modularity/refactor: input replay should mirror output replay as a structured `CachedInputFilterReplay`, not just an optional log.

Test gaps: no test for input-only count terms under cache hits.

### 6. DSCP rewrite/transmit

Correctness/security: `apply_dscp_rewrite_to_frame` returns `None` when the frame cannot be parsed or is truncated (`frame/mod.rs:149-183`), but prepared and local TX callers ignore it (`tx/transmit/rewrite.rs:60`, `tx/transmit/mod.rs:110-111`).

vSRX completeness: a configured rewrite contract should be observable: rewrite applied, counted failure, or packet dropped.

Performance/latency: failing closed on rewrite parse failure is cold/exception path; no steady-state cost.

Modularity/refactor: DSCP rewrite should return a typed result consumed by both local and prepared TX paths.

Test gaps: no truncated-frame test asserts a counter/drop when a configured rewrite cannot be applied.

### 7. TCP ACK-only eligibility

Correctness/security: the code treats ACK with ECN CWR/ECE set as ACK-only because `is_ack_only` masks only FIN/SYN/RST/ACK (`tcp_flags.rs:83-90`). The comment documents PSH/URG only.

vSRX completeness: ECN bits often carry congestion semantics. If any future screen, accounting, or filter needs them, cache eligibility will be too permissive.

Performance/latency: preserving current fast path is fine if explicitly documented and tested.

Modularity/refactor: cache eligibility should be a named policy object with tests for every flag bit.

Test gaps: no table test for PSH/URG/ECE/CWR cache eligibility.

### 8. VLAN metadata/keying

Correctness/security: code has rich VLAN metadata (`types/mod.rs:105-109`, `:143-147`) and many logical-ifindex fixes. Prior issue history already reports raw-parent VLAN cache keying, so I did not count a new primary finding.

vSRX completeness: same physical port with multiple VLAN units must preserve zone/policy/CoS isolation.

Performance/latency: adding logical ingress or VLAN id to cache key is a low-cost hash input.

Modularity/refactor: all ingress consumers should take a `LogicalIngress` newtype, not raw `(ifindex, vlan)` pairs.

Test gaps: continue to require same tuple across two VLAN units tests for cache, zone, filter, screen, and CoS.

## High Confidence Findings

### H1 - Cache hits can forward after the owning session has expired

Evidence:

- Cache lookup validates only key/generations/RG lease in `flow_cache.rs:805-857`.
- Cached decision validation in `forwarding/mod.rs:675-733` checks HA/fabric/neighbor policy, not session liveness.
- `touch_if_stale` returns on a missing session at `session/mod.rs:865-877`.
- `account_packet` returns on a missing session at `session/mod.rs:924-943`.

Runtime trace:

1. A TCP/UDP flow is permitted and a flow-cache descriptor is inserted.
2. The real session later expires, is cleared, or is removed by lifecycle code.
3. A subsequent packet with the same tuple hits `lookup_counted`.
4. Config/fib/RG/neighbor checks pass.
5. `touch_if_stale` and `account_packet` both miss and return silently.
6. The cached descriptor still rewrites/transmits the packet.

Impact: stateful firewall fail-open. A session table delete no longer guarantees forwarding stops.

Suggested issue labels: `bug`, `security`, `userspace-dataplane`, `flow-cache`.

### H2 - Session expiry deletes BPF/session state but never invalidates the flow cache

Evidence:

- Expiry loop: `sessions.expire_stale_entries_ha(...)` at `worker/loop_body/mod.rs:713`.
- For each expired entry, code releases SNAT and deletes session map entries at `:727-744`.
- There is no call to `flow_cache.invalidate_slot`, which exists at `flow_cache.rs:933-949`.

Runtime trace:

1. A low-rate flow is cacheable and has an active flow-cache entry.
2. Expiry reaps the session and deletes BPF redirect/conntrack state.
3. The flow-cache slot remains.
4. The next packet bypasses slow-path policy/session install and uses stale TX/NAT metadata.

Impact: the explicit expiry path is the easiest repro for H1.

Suggested issue labels: `bug`, `security`, `userspace-dataplane`, `flow-cache`.

### H3 - Plain input filter `then count` is under-counted on cache hits

Evidence:

- Cold input filter evaluation counts through `evaluate_interface_filter_non_routing_counted` at `poll_descriptor/filter.rs:229-242`.
- Cache seed calls only `evaluate_non_pbr_input_filter_log_only` at `poll_descriptor/mod.rs:3700-3706`.
- That helper returns `CachedInputFilterLog` only; no counter IDs are captured (`poll_descriptor/filter.rs:256-295`).
- Cache hits replay only `cached_descriptor.tx_selection.filter_counters` (`flow_cache_hit.rs:133-140`).
- Compiler marks input count terms, but `has_counter_terms` does not make input filters part of cached tx-selection replay (`filter/compiler.rs:138-165`).

Runtime trace:

1. Interface input filter has `then count accept` and no forwarding-class or DSCP rewrite.
2. First packet counts and seeds the cache.
3. Cache seed stores optional input log but no input counter handles.
4. Later packets hit the cache and replay output/tx counters only.
5. Input counter reports first packet only.

Impact: firewall observability and vSRX parity gap for input filters.

Suggested issue labels: `bug`, `vsrx-parity`, `firewall`, `userspace-dataplane`.

### H4 - CoS DSCP classifier queue selection is frozen by the first cached packet

Evidence:

- Cache key excludes DSCP; admission comment says this at `flow_cache.rs:367-371`.
- Cached CoS descriptor resolves queue from `meta.dscp` at `cos_classify.rs:218-221`.
- Cache hit uses cached queue ID at `flow_cache_hit.rs:185` and TX request construction later consumes that descriptor.

Runtime trace:

1. CoS interface maps DSCP EF to a voice queue and DSCP 0 to default.
2. First packet in a UDP flow has DSCP 0, so the flow cache records default queue.
3. Later same tuple packet has DSCP 46.
4. The cache key matches and does not include DSCP.
5. Packet is sent on default queue even though live CoS would choose voice.

Impact: QoS correctness failure for mixed-marking flows.

Suggested issue labels: `bug`, `vsrx-parity`, `cos`, `userspace-dataplane`.

### H5 - CoS IEEE 802.1p PCP classifier queue selection is frozen by the first cached packet

Evidence:

- Per-packet metadata includes `ingress_pcp` and `ingress_vlan_present` (`types/mod.rs:105-109`, `:143-147`).
- Cached CoS descriptor resolves queue from PCP/VLAN-present at `cos_classify.rs:218-227`.
- Cache key hashes only session key plus ingress ifindex (`flow_cache.rs:723-733`), not PCP or VLAN-present.

Runtime trace:

1. A CoS interface maps PCP 5 to a priority queue.
2. First packet in a cacheable flow is untagged or PCP 0.
3. Later same tuple arrives with priority tag/PCP 5.
4. Cache hit reuses the first packet queue.

Impact: 802.1p CoS parity is per-flow instead of per-packet.

Suggested issue labels: `bug`, `vsrx-parity`, `cos`, `vlan`.

### H6 - Cached path can drop TTL-expired packets via output filter/policer before Time Exceeded

Evidence:

- Cached hit applies three-color policers at `flow_cache_hit.rs:158-162`.
- It drops on cached output/filter/policer result at `:181-184`.
- TTL/Time Exceeded construction is later at `:217-240`.
- Slow session-hit path checks TTL before continuing to forwarding (`poll_descriptor/mod.rs:1076-1105`).
- Slow session-miss path checks TTL and rolls back NAT before enqueueing (`poll_descriptor/mod.rs:2411-2435`).

Runtime trace:

1. Cached flow receives a packet with TTL 1.
2. Cached output policer is red or cached terminal output filter says drop.
3. `stage_flow_cache_hit` recycles the packet before `build_local_time_exceeded_request`.
4. A slow path packet with the same TTL would generate ICMP Time Exceeded.

Impact: traceroute/control-plane correctness drift and egress policy side effects on a packet that should not egress.

Suggested issue labels: `bug`, `router-core`, `userspace-dataplane`, `firewall`.

### H7 - Cached path charges output/filter counters and emits logs before TTL rejection

Evidence:

- Output/tx counters replay at `flow_cache_hit.rs:133-140`.
- Input/output cached logs emit at `:163-180`.
- TTL check is later at `:217-240`.

Runtime trace:

1. TTL 1 packet hits an existing cache entry.
2. Output filter counter is incremented and log event is emitted.
3. TTL check then builds Time Exceeded and does not forward the original packet.

Impact: counters/logs claim output-filter matched forwarded traffic that never egressed.

Suggested issue labels: `bug`, `observability`, `firewall`, `userspace-dataplane`.

### H8 - Flow-cache observed bytes and active-flow telemetry count packets before TTL outcome

Evidence:

- `lookup_counted` adds `packet_len` to `observed_bytes` and stamps active epoch immediately on hit (`flow_cache.rs:858-874`).
- TTL may later convert the packet into a local ICMP response (`flow_cache_hit.rs:217-240`).
- Debug output reports `observed_bytes` and queue active counts from cache entry fields (`flow_cache.rs:625-678`).

Runtime trace:

1. A cache entry is hot.
2. A burst of TTL 1 packets hits the entry.
3. `observed_bytes` and active stamp are incremented before TE handling.
4. Active-flow bytes and queue counts include packets not forwarded by that flow.

Impact: misleading active-flow and CoS queue debug telemetry.

Suggested issue labels: `bug`, `observability`, `userspace-dataplane`.

## Medium Confidence Findings

### M1 - Cached CoS selection omits the live `tx_selection_enabled_v4/v6` family gate

Evidence:

- Live path derives family and exits when disabled at `cos_classify.rs:301-310`.
- Cached path starts with interface/filter checks but has no equivalent family gate at `:93-131`.

Runtime trace:

1. A future or test forwarding state has CoS interface/filter maps but `tx_selection_enabled_v4` false.
2. Live path returns default selection.
3. Cached seed path still evaluates filters/classifiers and stamps queue/drop/rewrite.

Impact: direct live-vs-cached semantic drift; production builder may currently mask this, but the helper itself is inconsistent.

Suggested issue labels: `bug`, `cos`, `test-gap`, `userspace-dataplane`.

### M2 - RG lease expiry check likely accepts a cached owner for the exact expiry second

Evidence:

- Lease check invalidates only when `now_secs > owner_rg_lease_until` (`flow_cache.rs:849-857`).

Runtime trace:

1. Cache entry stamps lease deadline second `T`.
2. Packet arrives at `now_secs == T`.
3. Cache hit is accepted, even though a lease deadline usually means valid until less than or equal to `T`.

Impact: possible one-second HA stale-owner forwarding window. Needs confirmation against the HA lease contract.

Suggested issue labels: `ha`, `flow-cache`, `needs-validation`.

### M3 - DSCP rewrite failure is silent on prepared TX

Evidence:

- Rewriter returns `None` when L3 parse fails or packet is too short (`frame/mod.rs:149-183`).
- Prepared TX ignores the result at `tx/transmit/rewrite.rs:60`.

Runtime trace:

1. Policy or CoS selects DSCP rewrite.
2. Frame slice is present but malformed/truncated enough for the rewriter to return `None`.
3. TX proceeds without the rewrite and without a counter.

Impact: configured rewrite can silently not happen. The malformed frame case may be rare, but silent failure is poor for a router/security appliance.

Suggested issue labels: `bug`, `cos`, `observability`.

### M4 - DSCP rewrite failure is silent on local TX

Evidence:

- Local TX ignores `apply_dscp_rewrite_to_frame` at `tx/transmit/mod.rs:110-111`.

Runtime trace:

1. Locally generated packet receives a DSCP rewrite request.
2. Parser returns `None`.
3. Packet transmits without rewrite and with no failure counter.

Impact: generated replies can diverge from CoS rewrite policy without visibility.

Suggested issue labels: `bug`, `cos`, `generated-replies`.

### M5 - `is_ack_only` documentation omits ECE/CWR cache eligibility

Evidence:

- Comment says PSH and URG are intentionally ignored (`tcp_flags.rs:83-86`).
- Implementation masks only `TCP_FLAGS_CTRL_MASK`, so ECE/CWR are also ignored (`:89-90`).

Runtime trace:

1. ACK+ECE or ACK+CWR packet arrives.
2. `is_ack_only` returns true.
3. Flow-cache admission can treat it as a pure ACK even though ECN control bits varied per packet.

Impact: likely acceptable if intentional, but the invariant is incomplete and untested.

Suggested issue labels: `docs`, `test-gap`, `tcp`.

### M6 - Cached input log replay has no counter ownership policy

Evidence:

- Full input evaluator has a detailed `NonRoutingCountPolicy` for PBR/routing interaction at `poll_descriptor/filter.rs:204-228`.
- Cache seed uses `evaluate_non_pbr_input_filter_log_only`, which bypasses counter policy entirely (`:256-295`).

Runtime trace:

1. Input filter has both routing-affecting and count/log terms.
2. Seed packet uses the complex counted evaluator.
3. Cache hits use only a stored log object and never re-run the counter ownership rule.

Impact: once input counter replay is added, it must preserve the PBR count policy or it will reintroduce double-count/undercount bugs.

Suggested issue labels: `firewall`, `refactor`, `test-gap`.

### M7 - Cached output filter replay stores first-packet log match only

Evidence:

- Cached descriptor stores `filter_log` from `resolve_cached_cos_tx_selection` (`cos_classify.rs:170-174`, `:231-235`).
- Cache entry declines DSCP/per-packet L4 match terms, but future match types or dynamic filter metadata could vary outside the 5-tuple.

Runtime trace:

1. A filter term logs based on currently non-cache-sensitive fields.
2. Future term type is added but not wired into cache sensitivity.
3. Cached first-packet log match is replayed for non-matching later packets.

Impact: medium-confidence future drift. The current code has some guards, but the pattern is fragile.

Suggested issue labels: `refactor`, `firewall`, `flow-cache`.

### M8 - Flow-cache debug CoS active counts are queue-stale when classifier inputs vary

Evidence:

- Active debug counts by `entry.descriptor.tx_selection.queue_id` (`flow_cache.rs:653-657`).
- Queue was selected from first packet DSCP/PCP at `cos_classify.rs:218-227`.

Runtime trace:

1. A cached flow alternates DSCP 0 and DSCP EF.
2. Actual expected queue changes per packet.
3. Debug active flow count stays on the first cached queue.

Impact: queue utilization debugging can mislead operators even after forwarding path is fixed.

Suggested issue labels: `observability`, `cos`, `flow-cache`.

### M9 - Cache seed comment still claims NPTv6 is skipped

Evidence:

- `poll_descriptor/mod.rs:3679-3682` says "Skip NAT64/NPTv6".
- `flow_cache.rs:461-465` says NPTv6 is cacheable and carries `nptv6`.

Runtime trace:

1. Developer audits cacheability from the seed comment.
2. They conclude NPTv6 is not cached.
3. Actual code caches NPTv6, so future fixes/tests may be scoped incorrectly.

Impact: documentation drift in hot-path invariants.

Suggested issue labels: `docs`, `userspace-dataplane`.

### M10 - Cache invalidation API is single-key only, making session lifecycle integration easy to miss

Evidence:

- Only observed invalidator is `invalidate_slot(key, ingress_ifindex)` (`flow_cache.rs:933-949`).
- Expiry loop iterates expired session entries but does not have a lifecycle hook that knows all associated cache keys (`worker/loop_body/mod.rs:727-744`).

Runtime trace:

1. A session is removed for expiry, operator clear, HA demotion, or future FIN/RST teardown.
2. Each removal site must remember to call a narrow flow-cache API.
3. At least expiry currently does not.

Impact: design smell with direct correctness fallout. A session-removal event bus or generation invalidation would be safer.

Suggested issue labels: `refactor`, `flow-cache`, `session`.

## Low Confidence / Triage Findings

### L1 - Flow cache needs a session-generation stamp

Current generation stamps cover config/fib/RG (`flow_cache.rs:826-857`) but not session table epoch. A monotonically incremented session lifecycle generation would turn H1/H2 into a cheap hot-path compare.

Labels: `refactor`, `performance`, `flow-cache`.

### L2 - Cached and live TX-selection evaluators should be one engine

`resolve_cached_cos_tx_selection` and `resolve_cos_tx_selection_internal` duplicate family, filter, classifier, and action logic (`cos_classify.rs:93-235`, `:283-515`). A side-effect strategy parameter would reduce drift.

Labels: `refactor`, `cos`, `performance`.

### L3 - Input filter cache replay should be a structured bundle

`CachedInputFilterLog` is too narrow for a firewall fast path. A bundle with counters, log, policers, and ownership policy would match the output side.

Labels: `refactor`, `firewall`.

### L4 - TTL handling should be a phase before egress side effects in every path

Current cached path embeds TTL after counters/policers/logs. A common `pre_egress_l3_checks` phase shared by session-hit, session-miss, and cache-hit would make Time Exceeded ordering testable.

Labels: `router-core`, `refactor`.

### L5 - Cache eligibility should list every per-packet field that is not in the key

The code guards DSCP and some L4 terms, but cached CoS uses DSCP/PCP anyway. A declarative `CacheSensitivity` manifest should cover DSCP, PCP, ECN bits, TTL, fragment state, TCP flags, ICMP type/code, VLAN, and future metadata.

Labels: `refactor`, `flow-cache`.

### L6 - No negative test proving cache misses after session clear/expiry

Add direct unit tests or an integration harness where a session is expired, BPF maps are deleted, and the next packet must go slow-path or drop, not cached TX.

Labels: `test-gap`, `security`.

### L7 - No test for input filter count replay on cached flow

Existing counter tests appear focused on cached TX-selection/output filter counter replay. Add input-only `then count accept` with a cacheable UDP flow and assert N packets move the counter by N.

Labels: `test-gap`, `firewall`, `vsrx-parity`.

### L8 - No DSCP classifier cache-sensitivity test

Add same 5-tuple UDP packets with DSCP 0 then EF and assert the second packet either misses cache or selects the EF queue.

Labels: `test-gap`, `cos`, `vsrx-parity`.

### L9 - No PCP classifier cache-sensitivity test

Add same 5-tuple traffic with priority-tag/PCP variation and assert queue selection follows PCP per packet.

Labels: `test-gap`, `cos`, `vlan`.

### L10 - No test for cached TTL-expired packet with output policer/drop

Construct an existing cache entry with output policer red or terminal drop, then send TTL 1. Expected: Time Exceeded handling wins and output counters/policer/logs do not claim egress of original packet.

Labels: `test-gap`, `router-core`, `firewall`.

### L11 - `observed_bytes` needs a forwarded-bytes vs seen-bytes distinction

`lookup_counted` uses packet length before final outcome. That may be acceptable as "cache-hit seen bytes", but the debug name reads like forwarded flow bytes.

Labels: `observability`, `flow-cache`.

### L12 - ACK-only eligibility needs explicit ECN policy

If ECE/CWR are intentionally ignored for cache, document and test it. If not, add them to per-packet L4 sensitivity.

Labels: `tcp`, `docs`, `test-gap`.

## Suggested Split

1. P0: Session/flow-cache lifecycle correctness.
   - Add a session-liveness generation or expiry-driven invalidation.
   - Make `touch_if_stale`/`account_packet` miss visible to cache-hit code or assert impossible.
   - Tests: cache hit after expiry/clear must miss or drop.

2. P1: Cache-sensitive CoS.
   - Decline cache when egress CoS DSCP/PCP classifier can vary per packet, or include the relevant classifier inputs in the cache key.
   - Add DSCP and PCP same-tuple tests.

3. P1: TTL ordering on cache hit.
   - Move Time Exceeded gate before egress counters, policers, logs, and drops.
   - Add cached TTL 1 with output policer/drop/log test.

4. P1: Input filter counter replay.
   - Replace `CachedInputFilterLog` with a replay bundle.
   - Preserve `NonRoutingCountPolicy`.
   - Add input-only count cache-hit tests.

5. P2: TX selection and rewrite hardening.
   - Unify cached/live TX-selection evaluation.
   - Add family-gate parity tests.
   - Count or fail closed on DSCP rewrite parse failure.
   - Fix NPTv6 cacheability comment drift.

