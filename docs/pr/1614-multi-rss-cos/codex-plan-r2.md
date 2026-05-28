# Codex hostile plan review r2 - #1614 v4

Reviewer: Codex (hostile scheduler / AF_XDP / CoS plan reviewer)

Target: `docs/pr/1614-multi-rss-cos/plan.md` v4, base commit `10cfa2128`.

Verdict: **NEEDS-MAJOR**

This is not PLAN-READY. The new A1.1 two-phase allocator is internally coherent for the requested `guarantee_fraction` walks and fixes the v3 F4 double-counting bug. However, v4 still contains two blocking design defects:

1. The default `guarantee_fraction = 0.0` path is claimed to preserve current behavior bit-for-bit, but the written algorithm still replaces the legacy round-robin selector with a new Phase-2 allocation path.
2. The CoDel retransmission target is asserted, not proven. The plan says 5 ms sojourn should reduce 1500-2000 retransmits/class/30s to <=100, but provides no math, simulation, or pre-implementation evidence strong enough to accept that as PLAN-READY.

PLAN-KILL is not warranted. B3 remains killed, B1 remains blocked, and the R8 phase-0 sequencing is structurally sufficient. A v5 can become plan-ready by adding an explicit legacy bypass for `fraction=0.0`, tightening A2 priority-low coupling, and turning the CoDel retrans target into either evidence or an explicit experimental gate with fallback.

## Finding 1: A1.1 fraction walks are coherent

Quoted plan evidence:

> `guarantee_fraction = root.config.pass1_guarantee_fraction  // 0.0..1.0`
>
> `pass1_budget = (cap * guarantee_fraction).floor()`
>
> `# Phase 2: proportional residual across ALL queues NOT fully honored.`
>
> `This includes the partial-honor queue from Phase 1`
>
> `pass2_budget = cap - (pass1_budget - remaining_pass1)`

Using the v4 fixture model (`cap = 18 G`; exact rates 100m, 1g, 3g, 6g, 9g, 12g, 15g, 18g, 21g, 24g; clamped Phase-2 quantums 2.5, 25, 75, 150, 225, 300, 375, 450, 512, 512 KB), each requested fraction terminates and sums coherently.

### `guarantee_fraction = 0.0`

Phase 1 budget is 0. No queue enters `honor_set`. Phase 2 receives the whole 18 G and distributes across all exact queues by quantum.

Approximate simplified-quantum allocation:

| Class | Total |
|---|---:|
| 100m | 17 Mbps |
| 1g | 171 Mbps |
| 3g | 514 Mbps |
| 6g | 1.03 G |
| 9g | 1.54 G |
| 12g | 2.06 G |
| 15g | 2.57 G |
| 18g | 3.08 G |
| 21g | 3.51 G |
| 24g | 3.51 G |
| Sum | 18 G |

That is a coherent proportional allocation. It is not bit-for-bit legacy behavior; see Finding 2.

### `guarantee_fraction = 0.4`

Phase 1 budget is 7.2 G. It fully honors 100m, 1g, and 3g, then partially honors 6g with the remaining 3.1 G. Phase 2 receives 10.8 G across `{6g, 9g, 12g, 15g, 18g, 21g, 24g}`.

| Class | Phase 1 | Phase 2 | Total |
|---|---:|---:|---:|
| 100m | 0.10 G | 0 | 0.10 G |
| 1g | 1.00 G | 0 | 1.00 G |
| 3g | 3.00 G | 0 | 3.00 G |
| 6g | 3.10 G | 0.64 G | 3.74 G |
| 9g | 0 | 0.96 G | 0.96 G |
| 12g | 0 | 1.28 G | 1.28 G |
| 15g | 0 | 1.61 G | 1.61 G |
| 18g | 0 | 1.93 G | 1.93 G |
| 21g | 0 | 2.19 G | 2.19 G |
| 24g | 0 | 2.19 G | 2.19 G |
| Sum | 7.20 G | 10.80 G | 18.00 G |

This matches v4's own walk.

### `guarantee_fraction = 0.7`

Phase 1 budget is 12.6 G. It fully honors 100m, 1g, 3g, and 6g, then partially honors 9g with the remaining 2.5 G. Phase 2 receives 5.4 G across `{9g, 12g, 15g, 18g, 21g, 24g}`.

| Class | Phase 1 | Phase 2 | Total |
|---|---:|---:|---:|
| 100m | 0.10 G | 0 | 0.10 G |
| 1g | 1.00 G | 0 | 1.00 G |
| 3g | 3.00 G | 0 | 3.00 G |
| 6g | 6.00 G | 0 | 6.00 G |
| 9g | 2.50 G | 0.51 G | 3.01 G |
| 12g | 0 | 0.68 G | 0.68 G |
| 15g | 0 | 0.85 G | 0.85 G |
| 18g | 0 | 1.02 G | 1.02 G |
| 21g | 0 | 1.16 G | 1.16 G |
| 24g | 0 | 1.16 G | 1.16 G |
| Sum | 12.60 G | 5.40 G | 18.00 G |

This also matches v4's predicted distribution.

### `guarantee_fraction = 1.0`

Phase 1 budget is 18 G. It fully honors 100m, 1g, 3g, and 6g, then partially honors 9g with the remaining 7.9 G. Phase 2 budget is 0.

| Class | Total |
|---|---:|
| 100m | 0.10 G |
| 1g | 1.00 G |
| 3g | 3.00 G |
| 6g | 6.00 G |
| 9g | 7.90 G |
| 12g | 0 |
| 15g | 0 |
| 18g | 0 |
| 21g | 0 |
| 24g | 0 |
| Sum | 18.00 G |

This is severe starvation for large classes, but it is coherent as an explicit operator-selected strict setting. The plan should spell out that `1.0` means 12g-24g can receive zero in this fixture; the current wording says "large classes share only the remaining 0-9% of cap", which understates the zero-share case.

## Finding 2: `fraction=0.0` is not bit-for-bit legacy behavior

This is the main blocker.

Quoted v4 claim:

> `default 0.0 (which makes Phase 1 a no-op and the algorithm collapses to current proportional behaviour for backward compatibility).`

v4 repeats the stronger claim:

> `For operators who want NO regression, guarantee_fraction = 0 preserves current behaviour bit-for-bit.`

and:

> `Default 0.0 preserves current behaviour bit-for-bit.`

The written algorithm does not do that. It changes the selection mechanism even when Phase 1 is disabled:

> `root.exact_queues_by_rate_ascending: Vec<usize>` is precomputed and sorted by ascending rate.
>
> `for queue_idx NOT in honor_set: alloc[queue_idx] += pass2_budget * Q_i / unhonored_total_quantum`

The current code is a mutable round-robin selector, not a per-pass static allocator:

```rust
let start = root.exact_guarantee_rr % queue_count;
for offset in 0..queue_count {
    let queue_idx = (start + offset) % queue_count;
```

and on selection:

```rust
root.exact_guarantee_rr = (start + offset + 1) % queue_count;
let secondary_budget = queue
    .hot
    .tokens
    .min(cos_guarantee_quantum_bytes(queue))
    .max(head_len);
```

So the implementation-equivalence statement is false. Even if long-window aggregate throughput is close, `fraction=0.0` as written can change queue ordering, batch shape, cursor state, per-pass budget, telemetry timing, park/wakeup behavior, and any tests that depend on exact RR progression.

Required v5 change: specify an explicit branch:

```text
if pass1_guarantee_fraction == 0.0 and priority_low_min_share == 0 and codel_target_ns == legacy_default:
    call the existing select_exact_cos_guarantee_queue_with_lease_telemetry path unchanged
else:
    run the new A1/A2/A3 path
```

The exact condition can be refined, but the key invariant is non-negotiable: the default path must execute the legacy selector, not a logically similar allocator.

## Finding 3: A1.4 is stateless across drain passes

This is acceptable.

Quoted v4 evidence:

> `The algorithm is stateless across drain passes (no guarantee-debt accumulation).`
>
> `Each pass independently computes phase 1 + phase 2 over root.tokens`
>
> `debt is BOUNDED per pass by pass1_budget, not accumulated across passes.`

That closes Codex r1 finding #2. There is no cross-pass guarantee-debt ledger in the written algorithm, so sustained 109/18 oversubscription cannot create an ever-growing "Pass 1 must drain debt before Pass 2" condition.

Residual issue: the document says "debt" but the algorithm is really a per-pass allocation budget, not debt accounting. Rename this in v5 to avoid implementors accidentally adding state.

## Finding 4: Phase-0 R8 sequencing is structurally sufficient

This is acceptable.

Quoted v4 evidence:

> `Phase 0 (run BEFORE any A1 implementation): R8 reverse-simul sanity check.`
>
> `MUST run gate 8 first and confirm reverse-simul aggregate >= 22 G before writing A1 code.`
>
> `If reverse-simul caps at ~18 G the firewall isn't the bottleneck and the entire plan is invalidated.`

The acceptance gate also requires:

> `simultaneous all-11-class reverse-direction run, same process count, same -P 12, same 30 s duration`
>
> `generator CPU saturation metrics (mpstat -P ALL 1 30 inside loss:cluster-userspace-host)`

This closes SMR r2 S8. One cleanup remains: the smoke matrix lists reverse-simul as "NEW Pass D" after push Pass C. v5 should make it unambiguously "Phase 0 / Pass 0" in the schedule and harness section too, not just in §4 and R3.

## Finding 5: CoDel 5 ms retransmission claim is not verified

This is the second blocker.

Quoted v4 evidence:

> `Tail-drops at 100% buffer cause the retransmit storm.`
>
> `When the oldest packet in a queue has been queued for >=5 ms (RFC 8290 default), drop it (or mark CE if ECT).`
>
> `Expected retrans reduction: 1500-2000 -> <=100 per class per 30 s.`

The mechanism is plausible; the acceptance claim is not proven. v4 does not provide:

- a queueing calculation showing that a 5 ms target on this fixture bounds drops to <=100/class/30s;
- a simulation;
- prior smoke evidence from this codebase with equivalent rates, buffers, RTT, and 12-stream iperf3 load;
- a fallback if 5 ms CoDel protects latency but still exceeds the retrans gate.

The plan's own checklist asks:

> `Does A3 (CoDel 5ms sojourn-time) achieve retrans <= 100 per class per 30 s? Show math or simulation.`

v4 does not show either. The current text is an assertion. That is not enough for PLAN-READY because acceptance criterion 3 is hard-gated on the outcome:

> `Aggregate retrans <= 100 per class per 30 s under simul (BOTH modes; today: 1500-2000).`

Required v5 change: either add convincing math/simulation/evidence, or explicitly treat A3 as an experimental gate with a rollback/tuning path (`codel-target`, interval behavior, ECN-only fallback, or disabled default if retrans/CoV fail).

## Finding 6: B3 remains killed; B1 remains blocked

This is acceptable.

Quoted v4 evidence for B1:

> `B1 (first-SYN class-affinity via hardware flow steering): BLOCKED.`
>
> `XSKMAP redirect-to-queue at runtime violates xsk_rcv_check.`
>
> `Mechanism must use ethtool ntuple or driver-supported flow steering at first-SYN. Requires lab verification`

Quoted v4 evidence for B3:

> `B3 (RSS reprogramming): KILLED per AGY+Codex DOA on #840 resurrection.`

This preserves the r1 kill-chain conclusions.

## Additional correctness notes

### Priority-low is still coupled too tightly to Pass 1

v4 says:

> `priority-low queue is admitted to Pass 1 set alongside exact-guarantee queues with R_eff = priority_low_min_share_bytes.`

This is risky. If `guarantee_fraction = 0.0`, the Pass-1 budget is 0, so a priority-low "min share" coupled only to Pass 1 cannot be guaranteed. If `guarantee_fraction > 0`, priority-low consumes the exact small-class Pass-1 budget. The minimum share should be reserved before A1 runs, then A1 should operate on the remaining exact-class cap.

This does not change the verdict because Finding 2 already forces a v5 algorithm rewrite, but it should be fixed in the same revision.

### The current-scheduler quantum sum in §3 is numerically inconsistent

v4 says:

> `Sum of quantums = 2400 KB. With 18 G ceiling, predicted T_i = 18 x Q_i / 2400`

But the table immediately above sums to `2.5 + 25 + 75 + 150 + 225 + 300 + 375 + 450 + 512 + 512 = 2626.5 KB` using v4's rounded units, or 2,651,076 bytes using the actual 524,288-byte clamp. This affects the displayed `fraction=0.0` proportional numbers and should be corrected. The A1.1 fraction walks for 0.4 and 0.7 use the smaller unhonored-set sums correctly.

## Required v5 changes

1. Add an explicit default-path bypass so `guarantee_fraction = 0.0` executes the legacy exact RR selector unchanged. Do not claim bit-for-bit preservation for a rewritten allocator.
2. Decouple priority-low min-share from the A1 Pass-1 budget. Reserve the min-share before A1 or define an equally strong independent guarantee.
3. Add math, simulation, or empirical evidence for the CoDel `1500-2000 -> <=100/class/30s` claim, or document it as an experimental gate with fallback tuning.
4. Correct the §3 quantum sum and the `fraction=0.0` predicted distribution.
5. Move reverse-simul from smoke "Pass D" wording to explicit Phase-0/Pass-0 wording everywhere the sequence is described.

Final verdict: **NEEDS-MAJOR**.
