# Codex hostile plan review - #1614 Multi-RSS Multi-Core CoS r1

Reviewer: Codex (hostile network/scheduler/AF_XDP/Junos CoS plan reviewer)

Verdict: **NEEDS-MAJOR**

This is not PLAN-READY. Axis A1 is probably directionally useful, but the plan's current math, acceptance gates, generator control, ECN/AQM design, and Axis B kill-chain table are not production-grade. PLAN-KILL is not warranted for the whole workstream because a narrower Axis-A-only v2 can be made reviewable.

## 1. Scheduler reading: rate-proportional via quantum; equivalent to pro-rata only in the unclamped saturated case

The code path is `userspace-dp/src/afxdp/cos/queue_service/mod.rs::select_exact_cos_guarantee_queue_with_lease_telemetry`.

Quoted code evidence:

```rust
let start = root.exact_guarantee_rr % queue_count;
for offset in 0..queue_count {
    let queue_idx = (start + offset) % queue_count;
```

```rust
root.exact_guarantee_rr = (start + offset + 1) % queue_count;
let secondary_budget = queue
    .hot
    .tokens
    .min(cos_guarantee_quantum_bytes(queue))
    .max(head_len);
```

The selection cursor is round-robin. It advances by one selected queue. The per-visit budget is not equal; it is bounded by `cos_guarantee_quantum_bytes(queue)`.

Quoted code evidence for the quantum:

```rust
let bytes_for_visit = ((queue.transmit_rate_bytes() as u128) * (COS_GUARANTEE_VISIT_NS as u128)
    / 1_000_000_000u128) as u64;
bytes_for_visit.clamp(
    COS_GUARANTEE_QUANTUM_MIN_BYTES,
    COS_GUARANTEE_QUANTUM_MAX_BYTES,
)
```

The constants are:

```rust
pub(in crate::afxdp) const COS_GUARANTEE_VISIT_NS: u64 = 200_000;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MIN_BYTES: u64 = 1500;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 512 * 1024;
```

So the scheduler is **rate-proportional-via-quantum**. In a saturated, work-conserving, unclamped steady state this collapses mathematically to pro-rata-by-rate:

```text
T_i = visits_per_sec * Q_i
sum(T_i) = C = visits_per_sec * sum(Q_j)
T_i = C * Q_i / sum(Q_j)
Q_i = R_i * 200 us, if unclamped
T_i = C * R_i / sum(R_j)
```

The plan's "pro-rata-by-shape" conclusion is therefore only conditionally correct. It omits the actual mechanism and the clamp. The clamp matters at the high end:

```text
Q_i = rate_gbps * 25,000 bytes
21 G: 525,000 B -> clamped to 524,288 B
24 G: 600,000 B -> clamped to 524,288 B
```

Predicted current exact-class distribution from the real quantum formula at an 18 G ceiling:

| Class | Shape | Quantum bytes | Predicted Gbps |
|---|---:|---:|---:|
| iperf-100m | 0.1 G | 2,500 | 0.017 |
| iperf-1g | 1 G | 25,000 | 0.170 |
| iperf-3g | 3 G | 75,000 | 0.509 |
| iperf-6g | 6 G | 150,000 | 1.018 |
| iperf-9g | 9 G | 225,000 | 1.528 |
| iperf-12g | 12 G | 300,000 | 2.037 |
| iperf-15g | 15 G | 375,000 | 2.546 |
| iperf-18g | 18 G | 450,000 | 3.055 |
| iperf-21g | 21 G | 524,288 | 3.560 |
| iperf-24g | 24 G | 524,288 | 3.560 |

That matches the shape of the observed data well enough to validate the mechanism, and it explains why 21 G and 24 G converge.

## 2. Pass-1/Pass-2 proposal is underspecified and may not do what the plan claims

The plan says Pass 1 must drain a class's accrued guarantee debt before giving any visit to a higher-rate class, and Pass 2 runs only after Pass 1 has no runnable queue with positive guarantee debt.

That is not a stable oversubscription algorithm as written. With exact rates summing to 109.1 G and a ceiling of 18 G, aggregate guarantee debt grows faster than service. There may never be a moment where every runnable exact queue has zero positive guarantee debt. A literal implementation can collapse into Pass 1 only, with Pass 2 starved indefinitely.

If the configured queue order is the fixture order and Pass 1 is interpreted literally, a one-second 18 G service budget can produce this pathological "small-first until tokens run out" distribution:

| Class | Shape | Literal Pass-1 prediction |
|---|---:|---:|
| iperf-100m | 0.1 G | 0.1 G |
| iperf-1g | 1 G | 1.0 G |
| iperf-3g | 3 G | 3.0 G |
| iperf-6g | 6 G | 6.0 G |
| iperf-9g | 9 G | 7.9 G |
| iperf-12g | 12 G | 0 G |
| iperf-15g | 15 G | 0 G |
| iperf-18g | 18 G | 0 G |
| iperf-21g | 21 G | 0 G |
| iperf-24g | 24 G | 0 G |

If instead I charitably infer the intended policy as "honor 100m/1g/3g/6g first, then distribute residual exact capacity among larger classes pro-rata", the 18 G exact budget prediction is:

| Class | Shape | Charitable Pass-1+Pass-2 prediction |
|---|---:|---:|
| iperf-100m | 0.1 G | 0.100 G |
| iperf-1g | 1 G | 1.000 G |
| iperf-3g | 3 G | 3.000 G |
| iperf-6g | 6 G | 6.000 G |
| iperf-9g | 9 G | 0.718 G |
| iperf-12g | 12 G | 0.958 G |
| iperf-15g | 15 G | 1.197 G |
| iperf-18g | 18 G | 1.436 G |
| iperf-21g | 21 G | 1.676 G |
| iperf-24g | 24 G | 1.915 G |

If priority-low receives 5% of an 18 G cluster ceiling first, exact capacity drops to 17.1 G and the large-class numbers fall further:

| Class | Shape | With 0.9 G priority-low floor |
|---|---:|---:|
| iperf-100m | 0.1 G | 0.100 G |
| iperf-1g | 1 G | 1.000 G |
| iperf-3g | 3 G | 3.000 G |
| iperf-6g | 6 G | 6.000 G |
| iperf-9g | 9 G | 0.636 G |
| iperf-12g | 12 G | 0.848 G |
| iperf-15g | 15 G | 1.061 G |
| iperf-18g | 18 G | 1.273 G |
| iperf-21g | 21 G | 1.485 G |
| iperf-24g | 24 G | 1.697 G |

That charitable policy protects small classes but fails the plan's current acceptance criterion 1 for the large classes. The literal policy is worse. Plan v2 must specify the allocation algorithm, epoch definition, cursor behavior, and proof that Pass 2 can run under oversubscription.

## 3. Acceptance criterion 1 is already satisfied by the baseline and conflicts with the intended small-class guarantee goal

Criterion 1 is:

```text
each exact class hits >= shape OR >= 90% of pro-rata-by-rate, whichever is smaller
```

With `C = 18 G` and exact shape sum `109.1 G`, the target is:

```text
target_i = min(shape_i, 0.9 * 18 * shape_i / 109.1)
         = 0.14849 * shape_i
```

Every exact class in the baseline table already clears this target:

| Class | Shape | 90% pro-rata target | Observed |
|---|---:|---:|---:|
| iperf-100m | 0.1 G | 0.015 G | 0.020 G |
| iperf-1g | 1 G | 0.148 G | 0.210 G |
| iperf-3g | 3 G | 0.445 G | 0.770 G |
| iperf-6g | 6 G | 0.891 G | 1.430 G |
| iperf-9g | 9 G | 1.336 G | 2.320 G |
| iperf-12g | 12 G | 1.782 G | 2.840 G |
| iperf-15g | 15 G | 2.227 G | 2.770 G |
| iperf-18g | 18 G | 2.673 G | 2.830 G |
| iperf-21g | 21 G | 3.118 G | 3.220 G |
| iperf-24g | 24 G | 3.564 G | 3.620 G |

This gate does not test the plan's stated primary fix. If the actual desired semantic is "100M and 1G must hit their configured exact rates before larger classes receive surplus", the criterion must say that directly. As written, criterion 1 lets the current scheduler pass.

## 4. R8 generator bottleneck is plausible and blocking

SMR's generator-bottleneck concern is valid enough to block plan readiness. The fixture launches 11 iperf3 clients, each with `-P 12`, inside a 16-CPU virtio container. That is either 11 heavy sender processes on older single-threaded iperf3 behavior or potentially 132 stream workers on newer threaded iperf3 builds. Either way, it is very plausible to bind on generator CPU, virtio TX, TCP segmentation/checksum work, or retransmit recovery before proving a firewall scheduler ceiling.

The plan's reverse-direction statement does not close R8. It says reverse/no-filter reaches 22-23 G, but the needed control is simultaneous all-11-class reverse with the same process count, same `-P`, same duration, and generator CPU/softirq counters. Receiver-side reverse traffic is not the same CPU workload as sender-side push traffic.

Plan v2 must include:

- iperf3 version inside `loss:cluster-userspace-host`.
- simultaneous all-11 reverse aggregate on the same fixture.
- generator per-CPU utilization, softirq, retransmits, and sender-side CPU saturation during push and reverse.
- a rule for invalidating the baseline if reverse-simul also caps near push.

## 5. ECN/WRED A3 is not justified and may regress existing admission behavior

The existing code already has ECN marking at one third of the relevant cap:

```rust
pub(in crate::afxdp) const COS_ECN_MARK_THRESHOLD_NUM: u64 = 1;
pub(in crate::afxdp) const COS_ECN_MARK_THRESHOLD_DEN: u64 = 3;
```

The admission path also documents that this applies to both aggregate and per-flow thresholds, and that moving the threshold is tuning against live telemetry:

```rust
queue.hot.queued_bytes > buffer_limit x NUM/DEN
```

```rust
ff.flow_bucket_bytes[flow_bucket] > share_cap x NUM/DEN
```

The plan's proposed 75%-100% WRED ramp moves signaling later than the current 33% threshold without a latency or RTT proof. With 12 streams per class and a 5-7 ms post-shaper RTT already documented in code comments, late RED-style marking is not enough evidence to promise retransmits <= 100/class/30s. SMR's CoDel/PIE objection is sustained: v2 must either keep/justify an earlier threshold with math and smoke evidence, or switch to a time/sojourn based AQM design.

## 6. Kill-chain table is not sound

Axis A1/A2 are local scheduler changes and do not violate the closed no-mid-flight-resteering chain.

B1 is not sound as written. The repo's XDP shim currently encodes the AF_XDP queue-binding invariant directly:

```rust
/*
 * AF_XDP delivery is queue-bound. XDP may only redirect to a socket bound
 * to the packet's actual RX queue. Hashing to a different userspace queue
 * here silently strands packets between redirect intent and ring delivery.
 *
 * Keep the XDP handoff on the ingress queue and let userspace do any
 * higher-level work redistribution after the packet is received.
 */
rx_queue_index % queue_count
```

So the plan's "B1 uses redirect-to-queue at FIRST-SYN only" does not by itself respect #937. First-SYN is not a magic exception to `xsk_rcv_check`; redirecting an XDP frame to an XSK bound to a different RX queue is still invalid. B1 is only potentially viable if it programs hardware/new-flow placement before packet delivery, not if it calls XSKMAP redirect to a non-ingress queue.

B3 is also unsound. The existing RSS indirection implementation explicitly treats RSS reshaping as startup/reconcile host tuning:

```go
// Runs at daemon startup (and on reconcile for worker-count changes),
// before the dataplane binds any AF_XDP socket on startup.
```

Dynamic RSS table edits for "persistent class skew" cannot be scoped to "new connections only" by destination-port range using a normal NIC indirection table. Changing hash-bucket-to-queue mapping moves any existing flow whose hash lands in an edited bucket. That resurrects #840/#937 failure mode. B3 should be removed from v2 unless the author can prove a hardware flow-steering mechanism that matches only new SYNs and leaves established flows' RX queue unchanged.

## Required v2 changes

1. Rewrite the scheduler diagnosis as rate-proportional-via-quantum, with the unclamped pro-rata equivalence and the 512 KiB clamp.
2. Specify a real oversubscription allocation algorithm. Do not rely on "Pass 2 runs after all debt is gone" when total exact debt grows faster than service.
3. Replace acceptance criterion 1 with gates that actually test the desired exact semantics, or admit that criterion 1 is a baseline-pass gate and not an Axis A proof.
4. Close R8 before implementation with simultaneous reverse/control runs and generator CPU evidence.
5. Redesign A3 around existing 33% ECN behavior, earlier/rate-aware WRED, or CoDel/PIE-style sojourn time; 75%-100% WRED is not accepted without empirical proof.
6. Delete or redesign B1/B3 so the closed kill chain (#1215 #837 #937 #1238 #840 #1243) is respected without relying on mid-flight or cross-RX-queue steering.

Final verdict: **NEEDS-MAJOR**.
