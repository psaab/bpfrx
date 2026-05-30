**Verdict: PLAN-NEEDS-MAJOR**

Not PLAN-KILL: the small4+24g result is a real defect signal. But v2 is not PLAN-READY because the load-bearing §3.B mechanism is not supported by the selector code.

**Findings**

1. **MAJOR: §3.B’s “owner-local eligible quantum_sum” is false in code.**

Plan claims: “`pass1 = quantum_sum × 0.7` is computed over the OWNER's local eligible queue set” and 3g/6g “fall past the per-worker `pass1` boundary” ([plan.md](/home/ps/git/bpfrx/docs/research/1614-simul-load-diagnosis/plan.md:174)).

Counter-evidence: refill sums `root.exact_queues_by_rate_ascending` directly, with no nonempty/runnable/owner filter:

> `for &qi in &root.exact_queues_by_rate_ascending { quantum_sum = quantum_sum.saturating_add(...) }`

([queue_service/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs:793))

That vector is built from all configured exact guaranteed queues:

> `.filter(|&idx| config.queues[idx].exact && config.queues[idx].guarantee_enabled)`

([builders.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/builders.rs:81))

So the reconciliation with #1630-r4 is wrong as written. The denominator remains configured/global per worker runtime, not “owner local eligible.” With small4+24g quanta, 100m+1g+3g+6g should fit well inside `0.7 × quantum_sum`; the observed 3g/6g shortfall cannot be explained by “falling past the Phase-1 boundary.”

2. **MAJOR: v8 lease/shared-exact is not ruled out; it is in the hot path for 3g/6g/24g.**

Plan demotes cross-worker coordination because “3g/6g are single-owner here” ([plan.md](/home/ps/git/bpfrx/docs/research/1614-simul-load-diagnosis/plan.md:247)). Code says queues at or above 2.5 Gbps use shared service:

> `queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES`

([worker/cos/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/cos/mod.rs:168))

And exact queues get v8 leases:

> `SharedCoSQueueLease::new_v8_with_rate_mode(...)`

([coordinator/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs:1399))

That keeps v8 lease behavior, shared queue lease acquisition, and root/FCFS ordering alive as competing causes. The black-box A/B does not isolate them from Phase-1 budget accounting.

3. **MAJOR: #1628 counters cannot validate the per-worker split the plan relies on.**

The plan’s own load-bearing mechanism is per-worker, but the exposed counters are aggregated. Queue rows say counters are:

> “Summed across worker instances”

([queue_row.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/cos/queue_row.rs:246))

Interface waterfill fields are explicitly “THIS WORKER’s view” internally but exported as summed/min aggregates ([types/cos.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/types/cos.rs:420), [protocol/cos.rs](/home/ps/git/bpfrx/userspace-dp/src/protocol/cos.rs:163)). That means the current telemetry can show “phase1-dominated” but cannot prove “worker A’s pass1 budget was consumed by co-hosted small+large queues.”

4. **MAJOR: Phase-2 exclusion is approximate, not the crisp waterfill invariant the plan assumes.**

The selector comment admits:

> “honored_mask is empty on this call”

and then:

> “We approximate by walking descending”

([queue_service/mod.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs:960))

So Path A’s “honor every eligible class before Phase-2 relegation” must first confront that the current implementation does not persist an exact honored set across calls. The plan treats this as a clean Phase-1/Phase-2 budget boundary; the code does not.

5. **Claim 1 is only narrowly sound.**

The 18g=14.25G A/B does refute v1’s “one worker hard-capped at ~4G” claim. But because high-rate queues are routed through shared-exact/v8 machinery, it does not prove the remaining behavior is not lease/root-pool ordering. Use it only to kill the 4G owner-funnel story.

6. **§3.A is plausible but overstated.**

`park_root=0` supports “not the root token bucket.” The ~22-24G aggregate ceiling is credible. But “No CoS change raises this; it is the denominator every class divides” ([plan.md](/home/ps/git/bpfrx/docs/research/1614-simul-load-diagnosis/plan.md:155)) is too absolute while small4+24g only reaches 18.2G and the selector/lease interactions above are unresolved.

Per-flow CoV PLAN-KILL is fine by precedent. The plan becomes PLAN-READY after §3.B is rewritten as an unresolved defect hypothesis, with required per-worker/pass1/lease instrumentation before choosing Path A.

Codex session ID: 019e795f-9da1-78e3-b3fc-876add5f73e8
Resume in Codex: codex resume 019e795f-9da1-78e3-b3fc-876add5f73e8
