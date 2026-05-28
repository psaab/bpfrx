# AGY Adversarial Plan Review — #1614 Multi-RSS Multi-Core CoS

**Reviewer:** AGY (Adversarial Plan Reviewer — HPC Networking, AF_XDP Zero-Copy Queue Physics, Scheduler Theory, CPU Microarchitecture, Junos CoS Contract)
**Target Branch:** `refactor/1614-multi-rss-cos`
**Target Plan:** `docs/pr/1614-multi-rss-cos/plan.md`
**Verdict:** **NEEDS-MAJOR**

---

## Executive Summary

This independent adversarial review challenges the implementation direction of the proposed Class of Service (CoS) scheduler refactor. Based on a rigorous mathematical walk of the `queue_service` code, microarchitectural analysis of virtualized packet generation, and audit of the AF_XDP kernel zero-copy constraints, we return a verdict of **NEEDS-MAJOR**. 

While the core direction of Axis A1 (a two-pass strict-guarantee then surplus scheduler) is correct and necessary to resolve small-class starvation, both the plan and the prior Claude SMR review suffer from major mathematical and physical blind spots:
1. **Mathematical Equivalence of Pro-Rata and Rate-Proportional:** SMR's claim (F1) that the scheduler is "rate-proportional-via-quantum" and *not* "pro-rata-by-shape" is mathematically a distinction without a difference in a saturated, work-conserving system. Under steady-state saturation, both models yield the exact same throughput distribution: $T_i = C_{\text{ceiling}} \times \frac{R_i}{\sum R_j}$.
2. **Quantum Clamping Blind Spot:** Both reviews missed that the shaper quantum `cos_guarantee_quantum_bytes` is clamped to a maximum of 512 KB (`COS_GUARANTEE_QUANTUM_MAX_BYTES`). At rates $\ge 21$ Gbps, this clamp becomes active, explaining why the rate-proportionality breaks down at the high end.
3. **ECN WRED Regression (A3):** The proposed 75%–100% WRED ramp is a severe regression from the existing codebase's 33.3% ECN marking threshold. Under Gbps speeds and a 5–7 ms cluster RTT, a 75% threshold leaves only 8 ms of buffer headroom, which is insufficient for multi-stream TCP congestion windows to react before catastrophic tail-drops occur.
4. **Axis B Resurrection of Closed PLAN-KILLs:** The deferred Axis B mechanisms (B1 and B3) are fundamentally flawed and auto-DOA. Reprogramming the NIC RSS indirection table (B3) will re-hash packets of existing long-lived connections, instantly violating the kernel `xsk_rcv_check` constraint on other workers and dropping traffic, resurrecting the killed #840 and #937 paths.

---

## Detailed Findings & Critical Questions

### A. §3 Scheduler Reading & Mathematical Verification

The plan's diagnosis in §3 characterizes the current scheduler as "approximately pro-rata-by-shape," while SMR's F1 claims it is "rate-proportional-via-quantum" and that the plan's diagnosis is wrong.

#### Code Walk & Mathematical Proof
In `userspace-dp/src/afxdp/cos/queue_service/mod.rs` (`select_exact_cos_guarantee_queue_with_lease_telemetry` L590-719), the round-robin selection cursor `exact_guarantee_rr` rotates through runnable exact queues. In a saturated steady state where all exact queues are backlogged:
1. Each runnable queue is visited exactly once per round-robin cycle of length $N$.
2. On visit, queue $i$ drains up to $Q_i = \text{cos\_guarantee\_quantum\_bytes}(queue_i)$ bytes.
3. Let $V$ be the number of round-robin cycles executed per second. The steady-state throughput of queue $i$ is:
   $$T_i = V \times Q_i$$
4. Since the aggregate throughput is constrained by the push ceiling $C_{\text{ceiling}}$:
   $$\sum_{j} T_j = C_{\text{ceiling}} \implies V \sum_{j} Q_j = C_{\text{ceiling}} \implies V = \frac{C_{\text{ceiling}}}{\sum_{j} Q_j}$$
5. Substituting $V$ back:
   $$T_i = C_{\text{ceiling}} \times \frac{Q_i}{\sum_{j} Q_j}$$
6. For rates where the quantum scales linearly without clamping:
   $$Q_i = R_i \times \frac{\text{COS\_GUARANTEE\_VISIT\_NS}}{10^9}$$
7. Since the visit interval constant cancels out:
   $$T_i = C_{\text{ceiling}} \times \frac{R_i}{\sum_{j} R_j}$$

This is the **exact mathematical definition of pro-rata-by-shape WFQ**. SMR's assertion in F1 is wrong; the plan's diagnosis of "approximately pro-rata-by-shape" is mathematically correct because the rate-proportional quantum naturally implements it.

#### The Clamping Factor (What Both Missed)
In `userspace-dp/src/afxdp/tx/drain/mod.rs` (L563):
`pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 512 * 1024;`

At a configured rate $R_i$, the quantum is:
`bytes_for_visit` = $R_i \times 200,000 / 10^9 = R_i / 5000$.
- For `iperf-21g` ($21 \times 10^9$ bps): $Q_{21G} = 525,000$ B $\implies$ Clamped to **524,288 B**.
- For `iperf-24g` ($24 \times 10^9$ bps): $Q_{24G} = 600,000$ B $\implies$ Clamped to **524,288 B**.

This explains why `iperf-21g` and `iperf-24g` achieve almost identical throughput in the baseline (3.22 G and 3.62 G, respectively). The rate-proportionality collapses at the high end because of this hard 512 KB clamp.

---

### B. §10 R8 Generator-Bottleneck Analysis

SMR's F2 suggests that the firewall may be innocent and the 18–20 G limit is purely a generator CPU bottleneck inside the 16-CPU virtio container.

#### Quantitative Physics Check
1. **Container Core Count vs. Senders:** 11 `iperf3` senders with `-P 12` represents 132 active TCP sockets. `iperf3` is single-threaded; thus, the 11 processes can consume at most 11 of the 16 available cores.
2. **Reverse Direction Proof:** The plan notes that reverse-direction traffic (generator as receiver) easily reaches **22–23 Gbps** under identical conditions.
3. **Firewall Drop-Induced CPU Overhead:** In the push direction, the firewall drops packets due to oversubscription (1500–2000 retransmits per 30s). When TCP packets are dropped, the sender's CPU overhead spikes dramatically due to timer interrupts, fast retransmit processing, and congestion control calculations.
4. **Conclusion:** SMR is wrong to declare the firewall innocent. The generator's CPU is indeed saturated in the push direction, but this saturation is **caused by the firewall's severe packet drops**. The TCP retransmission storm collapses the generator's efficiency. Lowering retransmits via better scheduler queue physics and ECN (Axis A) will reduce generator CPU load and allow throughput to recover.

---

### C. Plan A2 Priority-Low Min-Share Defensibility

The plan proposes a configurable starvation-prevention floor of `5% of root.shaping_rate_bytes`.
- **Defensible?** Yes, completely. A strict exact-rate guarantee scheduler under oversubscription will allocate 100% of tokens in Pass 1, leaving 0% for `priority-low` (starvation). A 5% floor (1.25 Gbps on the 25G fixture) ensures that control plane traffic, SSH management, DNS, and ARP do not freeze during dataplane saturation.
- Keeping this fully configurable via the Junos knob `priority-low-min-share` prevents it from being an arbitrary hardcoded value.

---

### D. Plan A3 ECN WRED 75%–100% Ramp Analysis

The plan proposes a WRED ramp marking packets from 75% to 100% of buffer size to drop retransmits from 1500–2000 to $\le 100$.

#### RTT Feedback Loop Math
1. **Buffer Drain Latency:** For a 4MB buffer (e.g., `scheduler-1g` L28) at 1 Gbps:
   $$\text{Drain Time} = \frac{4 \times 10^6 \text{ B}}{125 \times 10^6 \text{ B/s}} = 32 \text{ ms}$$
2. **Headroom Window:** A 75%–100% ramp starts marking at 3MB. The headroom before hard drop is 1MB.
   $$\text{Headroom Time} = \frac{1 \times 10^6 \text{ B}}{125 \times 10^6 \text{ B/s}} = 8 \text{ ms}$$
3. **Feedback RTT:** The cluster post-shaper RTT is **5–7 ms**.
4. **The Collision:** When the queue reaches the 75% marking threshold, CE marks are stamped. The sender does not receive these marks and adjust its cwnd until 1 RTT later (5–7 ms). In that time, the 1MB headroom (8 ms) will be almost fully exhausted by the high-concurrency (12 streams) senders. A tiny burst will push the queue past 100% into hard tail-drops.
5. **WRED Regression:** The existing codebase (`userspace-dp/src/afxdp/cos/admission.rs` L77-78) already sets the ECN marking threshold to **33.3%** (`COS_ECN_MARK_THRESHOLD_NUM = 1 / DEN = 3`).
   Raising this threshold to 75% is a major regression that delays signaling, making it impossible to satisfy Acceptance Criterion 4 (retrans $\le 100$).
6. **Verdict:** **NEEDS-MAJOR**. The WRED ramp must start much earlier (e.g., linear ramp from 25% to 75%) or utilize a rate-aware delay threshold.

---

### E. Plan §8 Kill-Chain Table Audit

We audited the closed PLAN-KILLs (#1215, #837, #937, #1238, #840, #1243) against the plan:

| Mechanism | Closed Issue | Physical/Kernel Constraint | Verdict on Plan |
|---|---|---|---|
| **A1/A2** | #1215, #1238 | Mid-flight flow re-steering | **CLEARED**. Operates entirely inside the local queue context. |
| **B1 (First-SYN)** | #937 | Kernel `xsk_rcv_check` enforces `xs->queue_id == rxq->queue_index` | **SUSPECT**. If NIC RSS hashes a subsequent packet to a different queue, enqueuing it sideways will trigger a kernel drop. |
| **B3 (RSS Reprogram)** | #840 | NIC RSS indirection table changes re-hash existing flows mid-flight | **PLAN-KILL / DEAD ON ARRIVAL**. Reprogramming the RSS table entry will instantly cause existing flows matching that entry to steer to a new worker, violating `xsk_rcv_check` and dropping active connections. |

Axis B3 resurrects the exact structural failure that killed #840. While Axis B is deferred, the architectural premise is wrong and must be re-planned.

---

### F. Plan §7 Acceptance Criterion 1 vs. 18-G Ceiling

Acceptance Criterion 1 demands: $\text{throughput}_i \ge \min(\text{shape}_i, 0.9 \times \text{pro-rata}_i)$.
- **Math Per Class:** With $C_{\text{ceiling}} = 18$ G and sum of shapes = 109.1 G, the $90\%$ pro-rata target is:
  $$\text{Target}_i = 0.9 \times 18 \times \frac{R_i}{109.1} \approx 0.1485 \times R_i$$
- Since $14.85\%$ is well below the configured rate, every class's target is its pro-rata share.
- In the baseline data (§3), every single class already hits this target:
  - 100m: Target = 14.8 Mbps. Achieved = 20 Mbps.
  - 1g: Target = 148.5 Mbps. Achieved = 210 Mbps.
  - 24g: Target = 3.56 Gbps. Achieved = 3.62 Gbps.
- **Conclusion:** **Criterion 1 is already satisfied by the baseline code**. The primary purpose of Axis A is not Criterion 1, but rather preserving absolute guarantees for small classes under oversubscription (e.g., 100m getting 100 Mbps, not 20 Mbps). The plan must clarify this distinction.

---

### G. Plan §9 Invariants Audit

- **Generation-Counter Atomicity (B3):** **UNACHIEVABLE**. NIC RSS hardware updates cannot be synchronized with active packet processing without dropping packets. Any flow re-hashed mid-flight dies. B3 must be killed.

---

### H. What Both Missed

1. **Clamping Limits:** Neither review identified that `COS_GUARANTEE_QUANTUM_MAX_BYTES` (512 KB) limits the rate-proportionality of the scheduler above 21 Gbps.
2. **ECN Threshold Regression:** Both missed that raising ECN marking to 75% is a step backward from the current 33% threshold.
3. **Cstruct Contract Resilience:** Both missed that the `Cstruct` contract (Gate 2) naturally handles RSS skew by scaling the target CoV, making broad cross-worker re-steering unnecessary for fairness validation.

---

## Action Plan for Plan v2

To move this plan to `PLAN-READY`, the author must update the document to address the following:
1. **Redesign A3 (ECN):** Drop the 75%–100% ramp. Instead, implement a linear ramp starting at **30% of the buffer limit** (or flow share cap) up to **75%**, leaving the final 25% as pure drop headroom to accommodate RTT feedback latency.
2. **Kill Axis B3:** Explicitly remove the dynamic RSS indirection table rebalancing (B3) from the Axis B roadmap to respect the closed #840 kill-chain.
3. **Address Quantum Clamping:** Document the 512 KB quantum clamping constraint in §3 and explain how it shapes high-rate queue distribution.
4. **Re-align Acceptance Criteria:** Explicitly state that Axis A's primary goal is protecting the small-class guarantees (e.g., 100m getting 100M, 1g getting 1G) rather than meeting the pro-rata target, which the baseline already does.

---

**Verdict:** **NEEDS-MAJOR** (Axis A conditionally mergeable if ECN thresholds are corrected; Axis B requires structural deletion of B3).
