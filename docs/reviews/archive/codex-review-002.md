# Codex quota review 002 - firewall and zone-policy core audit

Source instruction: `/home/ps/git/agy-do-review-audit.txt`

Repository: `/home/ps/git/codex-bpfrx`

Start state:
- `git pull --rebase`: already up to date.
- `git status --short --branch`: clean `master...origin/master`.
- Existing review reports read for duplicate suppression:
  - `/tmp/codex-review-001.md`
  - `/tmp/agy-review-002.md`
- Output numbering: `/tmp/agy-review-002.md` exists, `/tmp/codex-review-002.md` did not exist, so this report uses `002`.

Focus for this round:
- Core vSRX/SRX firewall behavior.
- Zone policy allow/deny/reject behavior.
- Host-inbound control-plane admission.
- Firewall-filter interaction with generated reject replies.
- Rust userspace dataplane correctness, not just Go control-plane checks.

## Duplicate suppression

I did not count these as new findings because they were already in prior `/tmp` reports or repo issue history/docs:

- `codex-review-001` H01/M01/M02/M03: `junos-host`, global policies, and host-originated policy gaps.
- `codex-review-001` H03: output firewall-filter `then reject` still silently drops for normal forwarded packets.
- `codex-review-001` H04/H05/M12: VLAN logical-ifindex host-inbound overrides, unknown/global host-inbound zone admit, and ICMPv6 Redirect global admit.
- `codex-review-001` M04/M05/M06: AppID overlap/scan/HA-sync concerns.
- `codex-review-001` M07/H06: host-inbound deny counters/log richness.
- `agy-review-002` 01-04: conntrack GC data race, static NAT shadowing, signed port split, and dynamic-address leniency.
- Repo history/docs already track: `#3226`, `#3291`, `#3292`, `#3310`, `#3395`, `#3491`, `#3527`, `#3534`, `#3546`, fragment/reassembly gaps, IDP/UTM/SSL gaps, advanced AppID gaps, policy rematch gaps, and security-flow strict-syn/aggressive-aging config-only gaps.

## Module checklist

Inspected modules/features:

1. `userspace-dp/src/policy.rs`
   - Result: no new high-confidence policy matcher bug found after suppressing known AppID and junos-host issues. The matcher has explicit cross-family, application, address, and port fail-closed handling.
2. `userspace-dp/src/policy_tests.rs`
   - Result: policy default/unknown-zone/wildcard coverage is much better than older reports imply. Not counted as a new finding.
3. `userspace-dp/src/afxdp/poll_descriptor/mod.rs`
   - Result: new high-confidence reject logging/order issue, plus debug-log hardcoding smell.
4. `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`
   - Result: generated reject reply gates are good for safety, but callers do not use the boolean to keep logs semantically true.
5. `userspace-dp/src/afxdp/event_emit.rs`
   - Result: event action mapping assumes reject replies hit the wire; that assumption is false under budget, rate, parse, or output-filter suppression.
6. `userspace-dp/src/afxdp/poll_descriptor/filter.rs`
   - Result: lo0/filter log emission has the same pre-reply-success ordering class.
7. `userspace-dp/src/afxdp/forwarding/host_inbound.rs`
   - Result: no new default-deny bug beyond prior reports, but several medium/low feature-completeness issues remain around IPsec, ident-reset, traceroute, SIP, and no-op service tokens.
8. `userspace-dp/src/afxdp/poll_stages.rs`
   - Result: IPsec passthrough is intentionally before ordinary local-delivery enforcement; this is an explicit design tradeoff that deserves an issue if strict vSRX host-inbound parity is required.
9. `userspace-dp/src/afxdp/icmp_ratelimit.rs`
   - Result: limiter is lock-free and sound at the atomic level, but global-per-reason scoping has multi-zone operational side effects.
10. `userspace-dp/src/filter/engine/matching.rs`
    - Result: fragment-safe L4 matching is already documented and tested; no new fragment fail-open counted.
11. `userspace-dp/src/filter/mod.rs`
    - Result: the `FilterAction::Reject` contract is stricter than the caller behavior.
12. `docs/feature-gaps.md`, `docs/issues/pr-history.md`, `docs/vsrx-gaps.md`
    - Result: many possible findings are already documented; not counted.

This report reaches the requested 20 candidate findings by including medium and low confidence candidates. Only H01 should be filed without more validation; medium/low items need triage or reproducer work.

## High confidence findings

### H01 - Policy `then reject` RT_FLOW can report REJECT even when no RST/ICMP reject was sent

Severity: High

Confidence: High

Labels: `bug`, `firewall`, `observability`, `userspace-dataplane`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2795`

```rust
2795 } else {
2796     emit_policy_deny_event(
2797         worker_ctx.event_stream,
...
2813         policy_result.policy_id,
2814         policy_result.action,
...
2827     );
...
2857     enqueue_deny_reply(
2858         &mut binding.tx_pipeline,
...
2865         matches!(policy_result.action, PolicyAction::Reject),
2866         from_zone_id,
2867     );
```

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:161`

```rust
161 if !syn_cookie_reply_budget_available(tx_pipeline) {
162     counters.touched = true;
163     counters.policy_reject_reply_budget_drops += 1;
164     return false;
165 }
...
179 if !allow_generated_error(GeneratedErrorReason::Reject) {
180     counters.touched = true;
181     return false;
182 }
```

`userspace-dp/src/afxdp/event_emit.rs:423`

```rust
423 #[inline]
424 fn policy_action_to_rt_flow(action: PolicyAction) -> u8 {
425     match action {
426         PolicyAction::Permit => RT_FLOW_ACTION_PERMIT,
427         PolicyAction::Deny => RT_FLOW_ACTION_DENY,
...
435         PolicyAction::Reject => RT_FLOW_ACTION_REJECT,
436     }
437 }
```

Runtime trace:

1. A packet matches a security policy term with `then reject`.
2. `poll_descriptor` emits `RT_FLOW_ACTION_REJECT` immediately using `policy_result.action`.
3. Only after the event is emitted, `enqueue_deny_reply` attempts to synthesize the RST/ICMP reply.
4. The reply can fail closed because the TX-frame budget is exhausted, the reject token bucket is empty, the frame cannot be parsed/built, or an output filter drops the generated reply.
5. The packet is silently dropped, but the event stream still says REJECT.

Why it matters:

For a security appliance, RT_FLOW logs are forensic ground truth. This can make an operator believe active rejects were sent when the dataplane actually fail-closed to silent drops under flood, rate-limit, output-filter, or malformed-packet conditions. It also contradicts the reject path's own comment that it "never logs a reject that did not happen."

Fix direction:

Defer `emit_policy_deny_event` until after `enqueue_deny_reply` returns, or add a distinct event action/reason for `reject-suppressed`. For `PolicyAction::Reject`, map to REJECT only when a reply was actually enqueued; otherwise map to DENY plus suppression metadata. Add tests for rate-limited reject and output-filter-dropped generated reply.

## Medium confidence findings

### M01 - Firewall-filter/lo0 `then reject` logs can report REJECT even when the generated reply was suppressed

Severity: Medium

Confidence: High for behavior, Medium for desired wire/log semantics

Labels: `bug`, `firewall-filter`, `lo0`, `observability`, `userspace-dataplane`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/filter.rs:346`

```rust
346 /// Evaluate the lo0 (host-bound) firewall filter and emit any matched filter
347 /// log. Returns the matched terminal `FilterAction` (#2521): the caller maps
348 /// `Accept` -> deliver, `Discard` -> silent drop, `Reject` -> silent drop PLUS a
349 /// synthesized active reply (TCP RST / ICMP unreachable).
...
380 if let Some(log_match) = result.log_match {
381     emit_filter_log_event(
...
394         log_match.action,
395         FilterLogSource::Lo0,
...
399     );
400 }
401 result.action
```

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1755`

```rust
1755 if lo0_action != crate::filter::FilterAction::Accept {
1756     // #2521: lo0 `then reject` synthesizes an active
1757     // reply (TCP RST / ICMP unreachable); `discard`
1758     // stays a silent drop.
1759     if lo0_action == crate::filter::FilterAction::Reject {
1760         enqueue_filter_reject_reply(
...
1768         );
1769     }
```

Runtime trace:

1. A host-bound packet passes host-inbound and hits a lo0 firewall-filter term with `then reject log`.
2. `apply_lo0_filter_action` emits the filter log before the caller tries to enqueue the generated reject reply.
3. `enqueue_filter_reject_reply` can return false for budget, rate-limit, parse, or output-filter suppression.
4. The event has already reported filter action REJECT, while the wire behavior was silent drop.

Why it matters:

The same forensic mismatch as H01 exists for lo0 and interface filters. This is especially confusing for control-plane protection: logs imply active rejection, but a scanner may observe drops.

Fix direction:

Split filter-log action from requested action, or defer filter log emission for `Reject` until the caller knows whether the generated reply was enqueued. Add a suppression field/counter for reject-requested-but-not-sent.

### M02 - IPsec/IKE passthrough bypasses host-inbound token enforcement in the AF_XDP local-delivery path

Severity: Medium

Confidence: Medium; the code documents this as intentional, but it is a strict vSRX parity/security-policy question

Labels: `feature-gap`, `firewall`, `host-inbound`, `ipsec`, `userspace-dataplane`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/poll_stages.rs:665`

```rust
665 /// Stage 11 - IPsec passthrough.
666 ///
667 /// ESP (proto 50) and IKE (UDP 500/4500) must transit the kernel
668 /// XFRM subsystem. On a match, this stage builds a synthetic
669 /// `SessionDecision` with `LocalDelivery` disposition and
670 /// reinjects the packet via the slow-path TUN device,
...
685 if !is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
686     return StageOutcome::Continue(());
687 }
```

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:138`

```rust
138 // `ipsec` is the Junos system-service that permits host-terminated
139 // IPsec. It opens IKE (udp 500 / NAT-T 4500); the raw ESP/AH data plane
140 // is handled by the kernel XFRM stack / stage_ipsec_passthrough_check
141 // before host-inbound enforcement, so `ipsec` is effectively a superset
142 // of `ike`.
143 "ike" | "ipsec" => {
144     hi.udp_ports.insert(500);
145     hi.udp_ports.insert(4500);
146 }
```

Runtime trace:

1. A packet to UDP/500, UDP/4500, ESP, or AH reaches the userspace poll loop.
2. `stage_ipsec_passthrough_check` recognizes it before ordinary local-delivery host-inbound admission.
3. The packet is reinjected to the kernel XFRM path.
4. The per-zone host-inbound service set cannot deny that traffic in this path.

Why it matters:

On SRX/vSRX, `host-inbound-traffic system-services ike/ipsec` is a policy surface operators expect to control. Here the userspace path treats these as a kernel-passthrough exception. That may be pragmatic for strongSwan/XFRM, but it should be explicit in docs and tests because "no ike/ipsec in host-inbound" does not necessarily mean "block IKE/IPsec to the firewall" on this path.

Fix direction:

Either route IKE/ESP/AH through a host-inbound gate before passthrough, or document the exception as a deliberate userspace dataplane semantic and add an end-to-end test for the disabled-host-inbound case.

### M03 - `ident-reset` still drops rather than actively resetting on the AF_XDP secondary path

Severity: Medium

Confidence: Medium; behavior is directly documented, but it remains incomplete vSRX parity

Labels: `feature-gap`, `host-inbound`, `ident-reset`, `userspace-dataplane`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:160`

```rust
160 // #3310: Junos `system-services ident-reset` does NOT permit the ident
161 // (auth/TCP-113) service - it actively RESETS inbound ident probes.
...
166 // pkg/daemon/daemon_nft.go). This AF_XDP local-delivery classifier is
167 // the SECONDARY edge-case path (reached only by DNAT/static-NAT-to-113,
168 // an edge of an edge). It must NOT admit 113 - so this arm contributes
169 // NOTHING to the admit set, and `admits()` returns false for TCP/113,
170 // dropping the rare AF_XDP-reached ident packet (a documented
171 // divergence from the kernel reset; strictly better than the prior plain
172 // admit).
173 "ident-reset" => {}
```

Runtime trace:

1. A packet reaches AF_XDP local delivery on TCP/113 via a non-primary path such as DNAT/static-NAT-to-113.
2. `ident-reset` contributes no admit entry.
3. `host_inbound_admits` returns false.
4. The poll loop silently drops instead of generating the Junos-style TCP RST.

Why it matters:

This is a narrow edge path, but the operator configured `ident-reset` specifically to avoid hanging probes. Silent drop changes scanner/client behavior and leaves a residual feature-completeness gap.

Fix direction:

Add a distinct host-inbound verdict for "reset" instead of flattening host-inbound to boolean admit/deny, then reuse the generated TCP RST path for this service.

### M04 - Locally generated reject replies are never mirror-cloned

Severity: Medium

Confidence: Medium; depends on whether interface mirroring is intended for locally generated control replies

Labels: `observability`, `firewall`, `mirror`, `userspace-dataplane`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:196`

```rust
196 // #2238: classify the GENERATED reply (TCP RST or ICMP/ICMPv6
197 // unreachable) by its OWN egress 5-tuple + egress interface - the
198 // reflected reply egresses on the interface it arrived on,
...
233 tx_pipeline.pending_tx_local.push_back(TxRequest {
234     bytes,
...
239     egress_ifindex: ingress_ifindex,
240     cos_queue_id: verdict.cos_queue_id,
241     dscp_rewrite: verdict.dscp_rewrite,
242     mirror_clone: false,
243     enqueue_ns: 0,
244 });
```

Runtime trace:

1. A policy/filter `reject` synthesizes a local RST/ICMP reply.
2. Output filter, CoS queue, and DSCP rewrite are applied through `classify_generated_reply`.
3. `TxRequest` hard-codes `mirror_clone: false`.
4. A configured analyzer/mirror path sees the trigger packet but not the generated reject reply.

Why it matters:

For firewall forensics, a mirror/analyzer session that misses locally generated RST/ICMP rejects can misrepresent what the device actually sent. This is especially relevant when debugging policy rejects, PMTUD, and scanner behavior.

Fix direction:

Decide whether locally generated replies should honor egress mirror/analyzer policy. If yes, thread mirror selection through `classify_generated_reply` or a sibling helper and add tests for policy reject and lo0 filter reject with mirror enabled.

### M05 - One global reject token bucket lets one zone starve active rejects for every other zone

Severity: Medium

Confidence: Medium

Labels: `dos`, `firewall`, `rate-limit`, `userspace-dataplane`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/icmp_ratelimit.rs:20`

```rust
20 // This adds the missing limiter, modelled on Linux's ICMP rate limiting
21 // (`net.ipv4.icmp_msgs_per_sec` - a GLOBAL per-host burst, default 1000/s -
22 // plus `net.ipv4.icmp_ratelimit`). We use the simple, bounded-state half of
23 // that model: a GLOBAL-per-reason token bucket (no per-source / per-destination
24 // map, so there is no attacker-driven map growth). Each reason has its own
25 // bucket so a TTL-exceeded flood cannot starve the PTB or reject reasons
```

`userspace-dp/src/afxdp/icmp_ratelimit.rs:163`

```rust
163 static TIME_EXCEEDED_BUCKET: TokenBucket = TokenBucket::new();
164 static PACKET_TOO_BIG_BUCKET: TokenBucket = TokenBucket::new();
165 static REJECT_BUCKET: TokenBucket = TokenBucket::new();
...
183 pub(in crate::afxdp) fn allow_generated_error(reason: GeneratedErrorReason) -> bool {
184     allow_generated_error_at(reason, monotonic_nanos(), DEFAULT_RATE_PER_SEC, DEFAULT_BURST)
185 }
```

Runtime trace:

1. Zone A receives a rejected-flow flood and consumes the global `Reject` bucket.
2. Legitimate policy rejects in Zone B happen at the same time.
3. Zone B's rejects fail closed to silent drops even though Zone B is not under attack.

Why it matters:

The Linux global model avoids map growth, but a multi-zone firewall is not just a Linux host. One untrusted zone can suppress active reject semantics and troubleshooting signals for other zones.

Fix direction:

Consider per-zone, per-RG, or per-worker buckets with bounded cardinality, or document the global behavior and expose zone-attributed suppression counters.

### M06 - Host-inbound `traceroute` only admits UDP 33434-33523

Severity: Medium

Confidence: Medium

Labels: `feature-gap`, `host-inbound`, `traceroute`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:199`

```rust
199 "traceroute" => {
200     // UDP probes land in the 33434..33523 range; admit it as a small
201     // explicit set (kept short to avoid bloating the per-zone set).
202     for p in 33434u16..=33523 {
203         hi.udp_ports.insert(p);
204     }
205 }
```

Runtime trace:

1. Operator enables `host-inbound-traffic system-services traceroute`.
2. Classic UDP traceroute probes to high UDP ports are admitted.
3. ICMP-based traceroute, TCP-based traceroute, or platform variants are not admitted by this token.

Why it matters:

Operators tend to treat "traceroute" as a diagnostic service, not one specific UDP implementation. vSRX/Junos environments often see ICMP/TCP traceroute variants from troubleshooting tools.

Fix direction:

Confirm Junos `system-services traceroute` exact semantics. If broader than UDP high ports, add service definitions and tests. If intentionally UDP-only, document it in the CLI/reference docs.

### M07 - Host-inbound `sip` omits SIP over TLS on TCP/5061

Severity: Medium

Confidence: Medium-low

Labels: `feature-gap`, `host-inbound`, `sip`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:180`

```rust
180 "sip" => {
181     hi.udp_ports.insert(5060);
182     hi.tcp_ports.insert(5060);
183 }
```

Runtime trace:

1. Operator enables `host-inbound-traffic system-services sip`.
2. UDP/TCP 5060 are admitted.
3. SIP over TLS on TCP/5061 remains denied.

Why it matters:

If the Junos service token covers secure SIP, xpf's service is narrower than expected. If it does not, the code is correct and the docs should make the port set explicit.

Fix direction:

Verify Junos service definition. If 5061 is expected, add it with a parity test. If not, document that TLS SIP requires an explicit custom service/policy.

### M08 - Host-inbound `tftp` only admits UDP/69 and has no dynamic data-port handling

Severity: Medium

Confidence: Medium-low

Labels: `feature-gap`, `host-inbound`, `tftp`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:147`

```rust
147 "tftp" => {
148     hi.udp_ports.insert(69);
149 }
```

Runtime trace:

1. Operator enables host-inbound TFTP.
2. The initial RRQ/WRQ to UDP/69 is admitted.
3. Follow-up TFTP transfer traffic uses ephemeral UDP ports and depends on host stack/conntrack behavior outside this service definition.

Why it matters:

TFTP is not a single-port steady-state protocol. For a firewall appliance, "service tftp" without an ALG/helper or explicit dynamic pinhole is at best partial.

Fix direction:

Verify how vSRX models host-bound TFTP. Either document that only the control port is opened, or add an explicit helper/pinhole story for host-bound TFTP.

### M09 - The `FilterAction::Reject` contract is stricter than current callers satisfy

Severity: Medium

Confidence: High for code contract mismatch, Medium for required behavior

Labels: `bug`, `firewall-filter`, `observability`, `userspace-dataplane`

Evidence:

`userspace-dp/src/filter/mod.rs:40`

```rust
40 /// Result of evaluating a filter term.
41 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
42 pub(crate) enum FilterAction {
...
47     /// Request reject behavior.
48     ///
49     /// Callers that cannot synthesize the reject packet must fail closed as a
50     /// silent drop and must not log that an ICMP/RST reject was generated.
51     Reject,
52 }
```

Runtime trace:

1. Filter evaluation returns `FilterAction::Reject`.
2. The filter log is emitted with action reject before reply generation.
3. Generated reply synthesis can fail closed.
4. The caller has logged a reject even though the enum contract says it must not.

Why it matters:

This is an invariant mismatch inside the codebase. Future refactors will read the enum contract and assume callers enforce it, but current lo0 and input-filter call sites do not.

Fix direction:

Turn `Reject` into a two-step outcome: requested action vs realized wire action. Add a test that forces `enqueue_filter_reject_reply` to return false and asserts no reject log is emitted, or that the log action is downgraded.

### M10 - Tests cover reject suppression counters but not event-stream truthfulness

Severity: Medium

Confidence: High

Labels: `test-gap`, `firewall`, `observability`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:648`

```rust
648 /// `Reject` rate-limited counter MUST advance - even though the TX-frame
...
690 assert!(!sent, "reject reply must fail-closed when rate-limited");
693     "no reject must be counted as sent under rate limit"
697     "no RST may be enqueued under rate limit"
701     "the rate-limited drop must bump the observable Reject counter"
```

Runtime trace:

1. Unit tests directly call the enqueue helper.
2. They assert no TX frame and no sent counter under rate limit.
3. They do not exercise the poll-loop event path that emits RT_FLOW/filter logs before the enqueue helper returns.

Why it matters:

The helper tests pass while H01/M01 remain live. The missing integration point is the caller ordering, not the helper itself.

Fix direction:

Add poll-loop tests that force generated-reply suppression and inspect event-stream action, counters, and TX queue length together.

### M11 - No end-to-end test proves output-filter-dropped generated rejects are logged differently from wire-successful rejects

Severity: Medium

Confidence: High

Labels: `test-gap`, `firewall-filter`, `observability`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:221`

```rust
221 let verdict = classify_generated_reply(forwarding, classify_ifindex, &bytes, now_ns);
222 if verdict.drop {
223     counters.touched = true;
224     if verdict.parse_error {
225         counters.generated_reply_classify_parse_errors += 1;
226     } else {
227         counters.policy_reject_output_filter_drops += 1;
228     }
229     // Fail-closed to the silent drop the caller already performs.
230     return false;
231 }
```

Runtime trace:

1. Generated reject reply is successfully built.
2. Egress output filter drops the generated reply.
3. Counter records `policy_reject_output_filter_drops`.
4. The event/log path has already reported reject unless caller ordering changes.

Why it matters:

This is the highest-risk branch for H01 because it is an operator-configured policy interaction, not just a flood/rate-limit edge.

Fix direction:

Add an end-to-end test with policy `then reject` plus egress output filter `then discard` on the reflected reply. Assert action/log semantics and counters.

### M12 - No end-to-end test pins host-inbound disabled plus IPsec passthrough behavior

Severity: Medium

Confidence: Medium

Labels: `test-gap`, `host-inbound`, `ipsec`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/poll_stages.rs:665`

```rust
665 /// Stage 11 - IPsec passthrough.
...
685 if !is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
686     return StageOutcome::Continue(());
687 }
...
702 maybe_reinject_slow_path_from_frame(
703     &worker_ctx.ident,
704     binding_live,
705     worker_ctx.slow_path,
```

Runtime trace:

1. Zone host-inbound omits `ike`/`ipsec`.
2. Packet is UDP/500, UDP/4500, ESP, or AH.
3. IPsec passthrough stage reinjects before ordinary host-inbound denial.

Why it matters:

If this is intentional, tests should pin it so reviewers do not keep treating it as a bug. If it is not intentional, the test should fail and drive a fix.

Fix direction:

Add a local-delivery/slow-path test for each IPsec class with host-inbound absent, and name the expected behavior explicitly.

### M13 - No AF_XDP regression test pins `ident-reset` as reset vs drop on the secondary path

Severity: Medium

Confidence: Medium

Labels: `test-gap`, `host-inbound`, `ident-reset`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:160`

```rust
160 // #3310: Junos `system-services ident-reset` does NOT permit the ident
161 // (auth/TCP-113) service - it actively RESETS inbound ident probes.
...
169 // NOTHING to the admit set, and `admits()` returns false for TCP/113,
170 // dropping the rare AF_XDP-reached ident packet (a documented
171 // divergence from the kernel reset; strictly better than the prior plain
172 // admit).
```

Runtime trace:

1. Secondary AF_XDP local-delivery path is reached for TCP/113.
2. Current expected behavior is documented as silent drop.
3. There is no test forcing a future decision to either preserve that divergence or upgrade to RST.

Why it matters:

Closed issue history says this was a documented compromise. Without a pinning test, the edge path can silently regress back to permit or stay divergent forever.

Fix direction:

Add a red/green test for the AF_XDP secondary path. If the desired final behavior is reset, mark the current drop as an expected-failing parity gap issue.

## Low confidence findings and triage candidates

### L01 - `debug-log` has hard-coded lab trust-flow classification that can flood logs for any 10/8 source

Severity: Low

Confidence: High for behavior, Low for production impact because it is feature-gated

Labels: `observability`, `performance`, `debug`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1499`

```rust
1499 let is_trust_flow = meta.ingress_ifindex == 5
1500     || from_zone == "lan"
1501     || matches!(flow.src_ip, IpAddr::V4(ip) if ip.octets()[0] == 10);
...
1618 if cfg!(feature = "debug-log") {
1619     if telemetry.dbg.session_miss <= 10 || is_trust_flow {
1620         eprintln!(
```

Why it matters:

In a debug build, any 10/8 source can bypass the first-10 throttle and produce high-volume stderr logs. This is not a release-path data-plane bug, but it is a poor operational/debug invariant.

Fix direction:

Move debug selectors to a runtime config or remove lab-specific `ifindex == 5` and 10/8 assumptions.

### L02 - IPv6 `router-discovery` host-inbound token is effectively no-op because RS/RA are globally admitted

Severity: Low

Confidence: Medium

Labels: `host-inbound`, `config-ux`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:397`

```rust
397 /// #3171/#3201/#3240: ICMP/ICMPv6 subtypes that the host-inbound layer admits
398 /// UNCONDITIONALLY - regardless of which services/protocols the ingress zone
399 /// lists - so the userspace LocalDelivery classifier matches the kernel
...
411 ///   2. IPv6 Neighbor Discovery (#3201/#3240) - RS (133), RA (134), NS (135),
412 ///      NA (136), Redirect (137).
...
414 ///      lets the per-zone `router-discovery` token carry NOTHING on v6
```

Why it matters:

Operators can configure or remove `router-discovery` expecting it to affect IPv6 RS/RA, but the token is not load-bearing for v6. That may be the right kernel-parity choice, but it is a CLI/documentation trap.

Fix direction:

Document that IPv6 ND/RS/RA are globally admitted independent of `router-discovery`, or add a stricter mode if vSRX parity requires per-zone control.

### L03 - `ipsec` host-inbound token is semantically an alias of `ike`, not a full IPsec admission control

Severity: Low

Confidence: Medium

Labels: `host-inbound`, `ipsec`, `config-ux`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:138`

```rust
138 // `ipsec` is the Junos system-service that permits host-terminated
139 // IPsec. It opens IKE (udp 500 / NAT-T 4500); the raw ESP/AH data plane
140 // is handled by the kernel XFRM stack / stage_ipsec_passthrough_check
141 // before host-inbound enforcement, so `ipsec` is effectively a superset
142 // of `ike`. Aliased to keep parity with the nft mirror + the #3200 SSOT.
143 "ike" | "ipsec" => {
```

Why it matters:

CLI users see two service names but get nearly identical port behavior in this classifier. Raw ESP/AH behavior is controlled elsewhere.

Fix direction:

Update operator docs and command reference to say `ipsec` maps to IKE/NAT-T in host-inbound, while raw ESP/AH follows the XFRM passthrough exception.

### L04 - Generated reject reply counters are named as policy counters even when the source is a firewall filter

Severity: Low

Confidence: High

Labels: `observability`, `firewall-filter`, `counters`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:23`

```rust
23 /// Which `reject` source a synthesized reply is attributed to. Selects the
24 /// per-source counters so a policy `then reject` and a firewall-filter `then
25 /// reject` are independently observable, while both flow through the SAME
...
65 /// (`filter_reject_sent` vs `policy_reject_sent`). Budget, output-filter, and
66 /// parse-error drops share policy reject's counters and its fail-closed
67 /// behavior
```

Why it matters:

Success counters distinguish policy vs filter reject, but budget/output-filter/parse drops collapse under policy-named counters. That makes firewall-filter troubleshooting less precise.

Fix direction:

Split suppression counters by `RejectReplySource` or rename them as generated-reject counters instead of policy-specific counters.

### L05 - `policy_reject_reply_budget_drops` includes filter-reject drops

Severity: Low

Confidence: High

Labels: `observability`, `firewall-filter`, `counters`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:161`

```rust
161 if !syn_cookie_reply_budget_available(tx_pipeline) {
162     counters.touched = true;
163     counters.policy_reject_reply_budget_drops += 1;
164     return false;
165 }
```

Why it matters:

This is the budget-drop sibling of L04. A lo0 or input firewall-filter reject flood can appear as policy reject budget pressure.

Fix direction:

Use source-specific budget-drop counters or a source label in status/exported metrics.

### L06 - `policy_reject_output_filter_drops` includes filter-reject output-filter drops

Severity: Low

Confidence: High

Labels: `observability`, `firewall-filter`, `counters`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:221`

```rust
221 let verdict = classify_generated_reply(forwarding, classify_ifindex, &bytes, now_ns);
222 if verdict.drop {
223     counters.touched = true;
224     if verdict.parse_error {
225         counters.generated_reply_classify_parse_errors += 1;
226     } else {
227         counters.policy_reject_output_filter_drops += 1;
228     }
```

Why it matters:

Operators cannot tell whether policy-reject or firewall-filter-reject replies are being blocked by output policy.

Fix direction:

Split by source or rename to source-neutral `generated_reject_output_filter_drops`.

### L07 - Host-inbound service definitions are hand-coded in Rust instead of generated from the Go SSOT/nft model

Severity: Low

Confidence: Medium

Labels: `refactor`, `host-inbound`, `modularity`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:120`

```rust
120 "dhcp" | "bootp" => {
121     hi.udp_ports_v4.insert(67);
122     hi.udp_ports_v4.insert(68);
123 }
...
180 "sip" => {
181     hi.udp_ports.insert(5060);
182     hi.tcp_ports.insert(5060);
183 }
...
211 // Unknown / unmapped service token: ignore (fail-closed).
212 _ => {}
```

Why it matters:

The project has repeatedly needed parity tests between Go config, nft, and Rust classifier behavior. A generated service table would be less error-prone than parallel switches.

Fix direction:

Move service definitions into a generated data table consumed by Rust and nft emission, or generate Rust from the Go SSOT.

### L08 - `poll_descriptor/mod.rs` still centralizes too much security flow logic in one very large loop

Severity: Low

Confidence: High

Labels: `refactor`, `performance`, `maintainability`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:1728`

```rust
1728 meta,
1729 ),
1730 worker_ctx.event_stream,
1731 flow,
1732 meta,
1733 ingress_zone_override,
...
1755 if lo0_action != crate::filter::FilterAction::Accept {
1756     // #2521: lo0 `then reject` synthesizes an active
```

Why it matters:

The staged extractions are helpful, but core screen, host-inbound, lo0, policy, reject, NAT, HA, PBR, and TX behavior still interact in one massive control-flow surface. The H01/M01 ordering bug is exactly the kind of issue caused by side effects living far apart in one loop.

Fix direction:

Continue splitting into feature directories, not `feature_foo.rs`: for example `poll_descriptor/reject/`, `poll_descriptor/local_delivery/`, and `poll_descriptor/policy/` with typed outcomes that carry side-effect ordering.

### L09 - There is no explicit vSRX-style zone-policy matrix test for allow/deny/reject/default across transit and junos-host paths

Severity: Low

Confidence: Medium

Labels: `test-gap`, `firewall`, `zone-policy`, `vsrx-parity`

Evidence:

`userspace-dp/src/policy_tests.rs` has many targeted regressions, but the audit did not find a single matrix fixture that covers:

```text
from-zone A to-zone B permit
from-zone A to-zone B deny
from-zone A to-zone B reject
implicit default policy
to-zone junos-host
host-inbound gate before lo0
flow-cache hit after policy/log changes
```

Why it matters:

The individual regressions are strong, but a router/firewall needs a compact behavioral matrix that future contributors can run and read as the contract.

Fix direction:

Add a table-driven Rust integration test module under `userspace-dp/src/afxdp/policy_matrix_tests.rs` or `policy/matrix/`, plus a Go control-plane compile fixture.

### L10 - No test ties generated-reject output-filter classification to mirror/CoS/DSCP together

Severity: Low

Confidence: Medium

Labels: `test-gap`, `cos`, `firewall-filter`, `mirror`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:233`

```rust
233 tx_pipeline.pending_tx_local.push_back(TxRequest {
234     bytes,
...
239     egress_ifindex: ingress_ifindex,
240     cos_queue_id: verdict.cos_queue_id,
241     dscp_rewrite: verdict.dscp_rewrite,
242     mirror_clone: false,
243     enqueue_ns: 0,
244 });
```

Why it matters:

The code improved output-filter/CoS/DSCP classification for generated replies, but mirror behavior is hard-coded false and not asserted as a deliberate invariant.

Fix direction:

Add a generated-reply classification test that asserts all TX metadata fields, including whether mirror is intentionally false.

### L11 - Host-inbound `system-services` coverage lacks an operator-visible port matrix

Severity: Low

Confidence: Medium

Labels: `docs`, `host-inbound`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:120`

```rust
120 "dhcp" | "bootp" => {
121     hi.udp_ports_v4.insert(67);
122     hi.udp_ports_v4.insert(68);
123 }
...
199 "traceroute" => {
200     // UDP probes land in the 33434..33523 range
```

Why it matters:

When a service token has narrowed semantics (`traceroute`, `sip`, `ipsec`, `router-discovery`), operators need an authoritative matrix of what ports/protocols are actually opened.

Fix direction:

Generate or document a host-inbound service table in `docs/junos-cli-reference.md` or a dedicated host-inbound reference.

### L12 - No failure-mode test proves rate-limited generated rejects are distinguishable from policy silent drops in telemetry

Severity: Low

Confidence: Medium

Labels: `test-gap`, `observability`, `rate-limit`

Evidence:

`userspace-dp/src/afxdp/icmp_ratelimit.rs:204`

```rust
204 /// Observable per-reason count of generated error replies dropped because the
205 /// reason's token bucket was empty. Surfaced via the coordinator status
206 /// (`*_rate_limited_total`).
207 pub(in crate::afxdp) fn rate_limited_count(reason: GeneratedErrorReason) -> u64 {
208     bucket_for(reason).rate_limited.load(Ordering::Relaxed)
209 }
```

Why it matters:

Counters exist, but the end-to-end event/counter contract is not obvious: a rejected packet under rate limit should be distinguishable from an explicit `then deny`.

Fix direction:

Add an integration test that compares `then deny`, `then reject` with successful reply, and `then reject` with token bucket empty.

### L13 - Host-inbound global ICMP/ND accepts should be documented as a security posture exception, not just implementation parity

Severity: Low

Confidence: Medium

Labels: `docs`, `host-inbound`, `ipv6`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:397`

```rust
397 /// #3171/#3201/#3240: ICMP/ICMPv6 subtypes that the host-inbound layer admits
398 /// UNCONDITIONALLY - regardless of which services/protocols the ingress zone
399 /// lists - so the userspace LocalDelivery classifier matches the kernel
400 /// host-inbound chain's GLOBAL accepts
...
431 fn is_icmp_host_inbound_global_accept(protocol: u8, icmp_type: u8) -> bool {
```

Why it matters:

This overlaps prior redirect concerns, so I am not counting redirect itself as new. The broader documentation issue remains: global control-message admits are a security posture choice operators should see outside code comments.

Fix direction:

Add a docs section listing unconditional host-inbound accepts and why each exists.

### L14 - `host_inbound_admits` returns true for unknown/global zone id, but the operational distinction is buried in comments

Severity: Low

Confidence: Medium; prior report covered the behavior as a bug candidate, this is only the documentation/operator clarity angle

Labels: `docs`, `host-inbound`, `observability`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:472`

```rust
472 match state.zone_host_inbound.get(&ingress_zone_id) {
473     // #3405: every configured security zone is in the table
...
475     // a genuinely unknown / global ingress zone (e.g. id 0, no resolved
476     // security zone). Such traffic keeps the admit default
...
479     None => true,
```

Why it matters:

Prior review already flagged the security behavior. The remaining non-duplicate point is operator visibility: unknown/global-zone local delivery should be observable so it does not look like normal zone admission.

Fix direction:

Add a counter or debug event for host-inbound admits through the unknown/global-zone default.

### L15 - IPsec passthrough emits a synthetic `LocalDelivery` decision with zeroed ifindexes

Severity: Low

Confidence: Low

Labels: `ipsec`, `observability`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/poll_stages.rs:688`

```rust
688 let ipsec_decision = SessionDecision {
689     resolution: ForwardingResolution {
690         disposition: ForwardingDisposition::LocalDelivery,
691         local_ifindex: 0,
692         egress_ifindex: 0,
693         tx_ifindex: 0,
694         tunnel_endpoint_id: 0,
```

Why it matters:

If slow-path exception telemetry or debug output uses this synthetic decision, it may lose the real local interface context for IPsec packets.

Fix direction:

Audit `maybe_reinject_slow_path_from_frame` consumers and either carry the ingress/local interface or assert that zero is intentionally ignored.

### L16 - `traceroute` host-inbound port range is duplicated as code rather than a named constant

Severity: Low

Confidence: High

Labels: `refactor`, `host-inbound`, `modularity`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:199`

```rust
199 "traceroute" => {
200     // UDP probes land in the 33434..33523 range; admit it as a small
201     // explicit set (kept short to avoid bloating the per-zone set).
202     for p in 33434u16..=33523 {
203         hi.udp_ports.insert(p);
204     }
205 }
```

Why it matters:

Magic protocol ranges embedded in the classifier are easy to drift from documentation/tests and hard to compare against vSRX service definitions.

Fix direction:

Move service ranges into named constants or generated service metadata.

### L17 - Host-inbound protocol/service matching stores many per-zone port sets instead of compact generated bitmaps

Severity: Low

Confidence: Low

Labels: `performance`, `host-inbound`, `userspace-dataplane`

Evidence:

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:120`

```rust
120 "dhcp" | "bootp" => {
121     hi.udp_ports_v4.insert(67);
122     hi.udp_ports_v4.insert(68);
...
180 "sip" => {
181     hi.udp_ports.insert(5060);
182     hi.tcp_ports.insert(5060);
```

Why it matters:

This is probably fine at current scale, but hot-path host-inbound admission could use compact fixed bitmaps or generated sorted slices instead of many hash/set lookups per zone.

Fix direction:

Benchmark host-inbound admission under many zones/services. If it appears in profiles, move to bitmaps for 0-65535 ports or compressed interval tables.

### L18 - Generated reject reply classification is tied to reflected ingress rather than a first-class local-output policy pipeline

Severity: Low

Confidence: Low

Labels: `architecture`, `firewall`, `userspace-dataplane`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:196`

```rust
196 // #2238: classify the GENERATED reply (TCP RST or ICMP/ICMPv6
197 // unreachable) by its OWN egress 5-tuple + egress interface - the
198 // reflected reply egresses on the interface it arrived on, so
199 // `ingress_ifindex` IS the egress.
...
239 egress_ifindex: ingress_ifindex,
```

Why it matters:

Reflecting rejects back out the ingress interface is sane for many firewall replies, but it is not the same abstraction as a full local-output route/policy pipeline. As local-generated traffic grows, one-off reflected-reply paths may drift from policy, mirror, and telemetry semantics.

Fix direction:

Define a local-output packet pipeline abstraction for generated replies and exceptions, then have reject/PTB/time-exceeded/cookie replies share it.

### L19 - The audit did not find a single generated document that maps every vSRX host-inbound token to Go, nft, and Rust behavior

Severity: Low

Confidence: Medium

Labels: `docs`, `host-inbound`, `vsrx-parity`, `test-gap`

Evidence:

The Rust classifier itself is the most precise map found during this pass:

```rust
"ike" | "ipsec" => { udp 500, 4500 }
"ident-reset" => {}
"sip" => { udp 5060, tcp 5060 }
"traceroute" => { udp 33434..33523 }
"gre" => { ip protocol 47 }
```

Why it matters:

For vSRX parity, host-inbound service semantics need to be reviewable without reading Rust and nft generation code. This would have caught several of the medium/low items above earlier.

Fix direction:

Generate a markdown table from the same service metadata used by code/tests, and label deviations from vSRX explicitly.

### L20 - Security-flow tests should include quota-style negative matrix for "denied means denied" on every packet path

Severity: Low

Confidence: Medium

Labels: `test-gap`, `firewall`, `zone-policy`, `userspace-dataplane`, `vsrx-parity`

Evidence:

The key packet paths inspected this round were:

```text
session miss transit
session hit transit
local delivery miss
local delivery hit
flowless non-first fragment
generated reject reply
IPsec passthrough
```

Why it matters:

The codebase has many specific regressions, but the strongest safety net for a firewall is a negative matrix that proves packets expected to be denied are denied across every path, not just one hot path.

Fix direction:

Build a reusable matrix harness with per-path packet builders and assertions for TX, recycle/drop, counters, RT_FLOW action, filter logs, and generated replies.

## Negative results from inspected modules

- `policy.rs`: no new directly evidenced matcher fail-open after suppressing known AppID and junos-host/global-policy issues.
- `filter/engine/matching.rs`: fragment handling looked intentionally fail-closed and is already heavily documented/tested. I did not count fragment bypasses because `#3291` and the current docs already cover the remaining reassembly/association gap.
- `screen` path in this focused pass: no new issue counted beyond the prior rate-counter over-throttle and documented strict-syn/aggressive-aging gaps.
- `source/destination NAT` was not the focus of this firewall round, and recent issue history already covers the obvious application/port matcher holes.

## Suggested filing order

1. H01 plus M01/M09/M10/M11 as one concrete issue: "Reject logs/events must reflect realized wire behavior after generated-reply suppression gates."
2. M02/M12: "Decide and pin IPsec passthrough vs host-inbound enforcement semantics."
3. M03/M13: "Close or explicitly pin AF_XDP ident-reset secondary-path divergence."
4. M04/L10/L18: "Define local-generated reply output policy, mirror, and telemetry contract."
5. M06/M07/M08/L11/L19: "Generate and document host-inbound service token semantics vs vSRX."
6. M05/L12: "Assess global generated-error rate limiter scoping for multi-zone firewalls."
7. L08/L20: "Continue modularizing poll descriptor and add security-flow negative matrix."

