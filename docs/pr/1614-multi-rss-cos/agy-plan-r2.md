# AGY Adversarial Plan Review Round 2 — #1614 CoS Scheduler

**Reviewer:** AGY (Adversarial Plan Reviewer — HPC Networking, AF_XDP Zero-Copy Queue Physics, Scheduler Theory, CPU Microarchitecture, Junos CoS Contract)
**Target Branch:** `refactor/1614-multi-rss-cos`
**Target Plan:** `docs/pr/1614-multi-rss-cos/plan.md` (v4)
**Verdict:** **NEEDS-MAJOR**

---

## Executive Summary

We have performed a rigorous adversarial review of the **Plan v4** proposal for #1614. While Plan v4 is a substantial improvement over v3 and successfully resolves SMR r2's fatal algorithm inconsistency (F4) by formulating a clean two-phase deficit-bounded waterfill allocator, it introduces **two major structural flaws** and **one substantive network physics risk** that prevent it from being `PLAN-READY`:

1. **Proportional Mode Divergence (Major):** Running the A1.1 allocator on the default `fraction = 0.0` mode is *not* bit-for-bit identical to the current scheduler. It alters the selection loop from a dynamic round-robin cursor to a fixed sorted rate-ascending order, causing severe starvation/unfairness between equal-rate classes. It also dynamically scales the visit budget by `cap / sum(Q_j)` instead of using the static quantum `Q_i`.
2. **Priority-Low Min-Share Coupling (Major):** Admitting the priority-low min-share (A2) to the Pass 1 set coupling-starves it under the default `fraction = 0.0` mode (Pass 1 budget is 0), and eats into the exact-guarantee Pass 1 budget when `fraction > 0.0`.
3. **CoDel AQM vs. CoV Contract Collision (Substantive):** The 5ms sojourn time AQM (A3) is extremely close to the 5–7 ms feedback loop RTT. Shortening this sojourn target introduces high drop randomness on transient bursts, causing TCP congestion windows to oscillate wildly and elevating the per-flow CoV, risking violation of the #1217 contract.

All mechanical details of the wire-protocol paths have been verified against the source code to eliminate configuration-time ambiguity. The 512KB quantum clamp behavior remains physically defensible.

---

## Detailed Findings & Critical Questions

### A. §4 A1.1 Algorithm Walk and Regression Evaluation
We walked the proposed A1.1 two-phase algorithm at fractions $0.0$, $0.4$, $0.7$, and $1.0$ under the $109/18$ oversubscription fixture (aggregate capacity $C = 18\text{ G}$):

*   **Fraction = 0.0:** Phase 1 budget is 0. All exact queues are unhonored. Phase 2 budget is $18\text{ G}$, distributed pro-rata by quantum: $18\text{ G} \times Q_i / \sum Q_j$. Drains align with current proportional shares (100m: 19M, 1g: 188M, 9g: 1.69G, 24g: 3.84G).
*   **Fraction = 0.4:** Phase 1 budget is $7.2\text{ G}$. Drains 100m ($0.1\text{ G}$), 1g ($1.0\text{ G}$), 3g ($3.0\text{ G}$) fully, and partially honors 6g ($3.1\text{ G}$). Phase 2 budget is $10.8\text{ G}$ distributed across the unhonored set $\{6\text{g}, 9\text{g}, \dots, 24\text{g}\}$. Sum of final allocations is exactly $18.0\text{ G}$.
*   **Fraction = 0.7:** Phase 1 budget is $12.6\text{ G}$. Honors 100m ($0.1\text{ G}$), 1g ($1.0\text{ G}$), 3g ($3.0\text{ G}$), 6g ($6.0\text{ G}$) fully, and partially honors 9g ($2.5\text{ G}$). Phase 2 budget of $5.4\text{ G}$ is distributed across $\{9\text{g}, 12\text{g}, \dots, 24\text{g}\}$. This yields the plan's exact predicted distribution (9g: 3.01G, 12g: 0.68G, 24g: 1.16G).
*   **Fraction = 1.0:** Phase 1 budget is $18.0\text{ G}$. Honors 100m ($0.1\text{ G}$), 1g ($1.0\text{ G}$), 3g ($3.0\text{ G}$), 6g ($6.0\text{ G}$) fully, and partially honors 9g ($7.9\text{ G}$). Phase 2 budget is $0\text{ G}$. The large classes ($12\text{g} \dots 24\text{g}$) receive **exactly 0 G** (complete starvation).

#### Are the large-class regressions acceptable?
Under `guarantee-rate 0.7`, the large classes ($12\text{g} \dots 24\text{g}$) drop from $\approx 2.8\text{--}3.6\text{ G}$ to $0.68\text{--}1.16\text{ G}$ (a $\approx 64\text{--}76\%$ reduction).
**Verdict: Yes, highly acceptable.**
1.  **Opt-in safety:** This is an explicit, non-default policy configured via `oversubscription-policy guarantee-rate <fraction>`.
2.  **No upgrade surprise:** The default `proportional` mode preserves original behavior without regressions.
3.  **Operator safety:** The validator in `pkg/config/cos.go` explicitly warns the operator about the exact large-class throughput reduction if the policy is active.

---

### B. Proportional Mode Bit-for-Bit Equivalence
> **Critical Question:** *Is the algorithm at fraction = 0.0 bit-for-bit identical to the current scheduler, or does it subtly perturb?*

**Verdict: Subtly but severely perturbs; NOT bit-for-bit identical.**

If the A1.1 allocator is executed for all values of `pass1_guarantee_fraction`, the following deviations occur:
1.  **Starvation of Equal-Rate Queues:** The current scheduler uses a round-robin cursor `exact_guarantee_rr` (`queue_service/mod.rs:600-602`) that advances per selection. The A1.1 allocator instead iterates over a *fixed* ascending order `root.exact_queues_by_rate_ascending`. If there are multiple exact queues with the same configured rate (e.g., two `3g` classes), the queue that appears first in the precomputed sorted vector will *always* be preferred, starving the second queue during saturation.
2.  **Budget Scaling Perturbation:** The current scheduler select-drains exactly $Q_i = \text{quantum}_i$. Under A1.1, the budget allocated per visit is scaled dynamically to $\text{cap} \times Q_i / \sum Q_{\text{unhonored}}$, which alters the size of the drain quantum depending on token fullness and active queue counts.

**Required Structural Fix:** The scheduler must **explicitly branch**. If `oversubscription-policy` is `proportional` (or `fraction == 0.0`), the scheduler must bypass the A1 allocator code entirely and execute the legacy `select_exact_cos_guarantee_queue_with_lease_telemetry` round-robin selection block.

---

### C. Gate-8 Phase 0 Sequencing
> **Critical Question:** *Is gate-8 Phase 0 sequencing the right structural fix?*

**Verdict: Yes, completely correct.**

If the `loss:cluster-userspace-host` 16-CPU virtio container is physically bound by generator CPU interrupts, softirqs, or virtio-NET segmentation during push runs, implementing a two-phase allocator will not raise the aggregate firewall throughput above 18 G. Moving the R8 sanity check (parallel 11-stream reverse direction run, aggregate $\ge 22\text{ G}$) to **Phase 0 (blocking, before A1 implementation)** is a vital defensive gate that prevents wasted implementation hours on a bottlenecked generator test-bed.

---

### D. CoDel Sojourn vs. Per-Flow CoV Contract (#1217)
> **Critical Question:** *Does CoDel @ 5ms affect the per-flow CoV gate on saturated runs?*

**Verdict: Yes, a 5ms target risks violating the #1217 CoV contract.**

#### Network Physics Proof:
1.  **Feedback Loop RTT:** The cluster post-shaper feedback RTT is documented as **5–7 ms**.
2.  **Signal Lag:** When CoDel drops or marks a packet at the dequeue gate, it takes at least 1 RTT ($5\text{--}7\text{ ms}$) for the TCP sender to receive the signal (ACK/SACK or CE-ECE flag) and shrink its congestion window.
3.  **Drop Oscillations:** Since the CoDel sojourn target ($5\text{ ms}$) is *less than or equal to* the feedback loop RTT, the sender cannot react before subsequent packets are dequeued. The dequeue gate will trigger continuous, highly random drops across parallel streams of the same class.
4.  **CoV Elevation:** Wildly fluctuating congestion windows across parallel flows will artificially raise the short-term throughput variance between parallel streams, elevating the per-flow Coefficient of Variation (CoV) and breaching the \#1217 limit (Acceptance Criterion 4: $\le \text{Cstruct} + 0.05$).

**Required Structural Fix:** Add an explicit risk statement and tuning advice in `docs/cos-traffic-shaping.md`. The default `codel-target` should scale with the RTT or class transmit rate:
$$\text{codel-target} = \max(5\text{ms}, 1.5 \times \text{RTT})$$

---

### E. Priority-Low Min-Share Orthogonality
> **Critical Question:** *Should fraction (Pass 1 budget) explicitly subtract priority-low min-share, or is min-share orthogonal?*

**Verdict: They must be orthogonal; Pass 1 coupling is a defect.**

If the priority-low min-share ($5\%$) is admitted directly to the Pass 1 set alongside exact queues:
1.  **Starvation in Proportional Mode:** When `fraction = 0.0`, the Pass 1 budget is 0, completely starving the priority-low min-share despite its explicit configuration.
2.  **Budget Dilution:** When `fraction > 0.0`, the priority-low queue eats $1.25\text{ G}$ of the exact-guarantee Pass 1 budget, diluting the protection of small exact classes.

**Required Structural Fix:** The priority-low min-share must be calculated **before** the A1 allocator runs. The scheduler should subtract the priority-low min-share from the overall pass capacity `cap`:
$$\text{cap}_{\text{eff}} = \text{cap} - \text{priority\_low\_min\_share\_bytes}$$
The A1 two-phase waterfill allocator should then execute on $\text{cap}_{\text{eff}}$. This ensures control-plane survivability is guaranteed under *all* oversubscription policies, including `proportional`.

---

### F. The 512KB Quantum Clamp Defensibility
> **Critical Question:** *Is the flattening of 21g and 24g classes in Phase 2 acceptable?*

**Verdict: Yes, completely acceptable and physically necessary.**

1.  **Microarchitectural Protection:** The $512\text{ KB}$ maximum clamp (`COS_GUARANTEE_QUANTUM_MAX_BYTES`) is a hard physical guard preventing any single saturated queue from holding the scheduler worker thread for too long in a single pass, which would destroy latency and jitter guarantees for all other interfaces.
2.  **Oversubscribed Context:** Since the aggregate exact rate ($109\text{ G}$) vastly exceeds the pipe ($18\text{ G}$), these ultra-high classes are in the residual best-effort phase. The plan v4 correctly documents and incorporates the clamp into the Phase 2 mathematical walk, establishing parity with observed baseline behavior.

---

### G. Mechanical Wire-Protocol Verification

We audited the codebase and confirmed the exact struct paths to eliminate configuration-time ambiguity in §4 A2:

*   **Rust Configuration Snapshot:** `InterfaceSnapshot` in `userspace-dp/src/protocol/snapshot.rs` L38.
*   **Go Configuration Snapshot:** `InterfaceSnapshot` in `pkg/dataplane/userspace/protocol.go` L118.
*   **Rust Telemetry Status:** `CoSInterfaceStatus` in `userspace-dp/src/protocol/cos.rs` L131.
*   **Go Telemetry Status:** `CoSInterfaceStatus` in `pkg/dataplane/userspace/protocol.go` L649.

---

## Action Plan for Plan v5

To move this plan to `PLAN-READY`, the author must update the document to address the following:

1.  **Add Proportional Mode Bypass:** Explicitly specify that if `oversubscription-policy` is `proportional` (or `fraction == 0.0`), the scheduler skips the new waterfill logic and runs the legacy round-robin selection block.
2.  **De-couple Priority-Low Min-Share:** Modify §4 A2 to calculate and subtract the priority-low min-share from `cap` *prior* to executing the A1 waterfill allocator.
3.  **Scale CoDel Target:** Address the CoV contract collision by setting `codel-target = max(5ms, 1.5 * RTT)` and documenting the tuning guidelines in §9.
4.  **Incorporate Wire-Protocol Struct Paths:** Replace the "confirm at implementation time" placeholders with the verified Go/Rust file paths and struct names.

---

**Verdict:** **NEEDS-MAJOR** (The Axis A implementation is conditionally mergeable once these algorithm and design fixes are incorporated in v5).
