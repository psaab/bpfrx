# AGY Adversarial Plan Review Round 3 — #1614 CoS Scheduler

**Reviewer:** AGY (Adversarial Plan Reviewer — HPC Networking, AF_XDP Zero-Copy Queue Physics, Scheduler Theory, CPU Microarchitecture, Junos CoS Contract)  
**Target Branch:** `refactor/1614-multi-rss-cos`  
**Target Plan:** `docs/pr/1614-multi-rss-cos/plan.md` (v5, SHA `f742b3ff3`)  
**Verdict:** **NEEDS-MINOR (PLAN-READY conditional on three mechanical fixes)**

---

## Executive Summary

We have performed a rigorous, hostile round-3 adversarial review of **Plan v5**. 

We congratulate the team on the successful completion of the **Phase 0 R8 reverse-simul check**, which passed on 2026-05-27 (22.72 G aggregate reverse throughput, generator CPU 20-58% idle, confirming the firewall as the bottleneck). This empirical grounding validates the foundational assumptions of the scheduler rewrite.

Plan v5 successfully closes our three round-2 findings by introducing an explicit proportional mode bypass (§4 A1.1), moving priority-low min-share subtraction before A1 (§4 A2), scaling the CoDel target via the RTT-aware formula (§4 A3), and reframing CoDel as an experimental gate with documented fallback paths.

However, our hostile walk-through of the v5 text has uncovered **three new mechanical design flaws** (one in the early-branch bypass, one in Rust safety, and one mathematical flaw in the waterfill algorithm):

1. **Priority-Low Min-Share Bypassed in Proportional Mode (Major Gap):** The early-return branch for proportional mode skips the subtraction of the priority-low min-share. If an operator selects `Proportional` but configures a non-zero `priority-low-min-share`, the min-share is ignored, leading to priority-low starvation.
2. **Rust Unsigned Underflow/Panic Risk:** Direct subtraction in `cap_eff = root.tokens - priority_low_min_share_pass` will trigger unsigned underflows and panic (in debug) or corrupt token counts (in release) during transient token depletion.
3. **Phase 2 Quantum-Violation Bug (Mathematical Proof):** The waterfill allocator's claim that Phase 2 shares never exceed a queue's quantum is mathematically incorrect. The partially honored queue participates in Phase 2 with its *full* quantum weight rather than its *remaining* quantum weight, allowing its total allocation to exceed its configured per-pass quantum.

The plan is extremely close to implementation. These three findings are purely mechanical and can be closed via rapid text revisions. Once these are folded into a final plan, the design is **PLAN-READY**.

---

## Detailed Findings & Critical Questions

### A. Resolution of the Three r2 Findings

We audited the v5 text against our r2 findings:

1. **Proportional Mode Divergence (Closed):** §4 A1.1 now starts with an explicit check on `oversubscription_policy == Proportional OR guarantee_fraction == 0.0`. It immediately returns `select_exact_cos_guarantee_queue_with_lease_telemetry`, preserving the legacy round-robin selection cursor, cursor advancement, and visit budget. Wording is tight and leaves no gap.
2. **Priority-Low Min-Share Orthogonality (Closed):** The priority-low min-share is subtracted before A1 runs, and the Go/Rust wire-protocol snap structures are correctly defined at their exact codebase files.
3. **CoDel AQM vs. CoV Contract Collision (Closed):** The plan now sets `codel-target = max(5ms, 1.5 * measured_RTT)` and documents this rule in `docs/cos-traffic-shaping.md`. CoDel is correctly categorized as an experimental gate with clear Disposition Tiers (Optimal, Sub-optimal but acceptable, Revert/Rollback). This satisfies network-physics rigor.

---

### B. Proportional Mode Bypass & Priority-Low Subtraction Interaction
> **Critical Question:** *Does the explicit branch interact correctly with the cap_eff subtraction order? Specifically: in proportional mode (which bypasses A1), is priority-low min-share still honored?*

**Verdict: No, it is completely bypassed and ignored in proportional mode.**

#### The Gap:
Under §4 A1.1, the branch is implemented as:
```rust
if root.config.oversubscription_policy == Proportional
   OR root.config.guarantee_fraction == 0.0:
    // BIT-FOR-BIT IDENTICAL to current scheduler.
    return select_exact_cos_guarantee_queue_with_lease_telemetry(root, ...)
```
Because this is an early return at the very top of the function, the subsequent block that subtracts `priority_low_min_share_pass` and updates `cap_eff` is **never executed**.

If an operator deploys the default `Proportional` mode but configures `priority-low-min-share = 5%`, the exact queues will consume 100% of the tokens in the legacy round-robin selector, leaving zero tokens for Phase 3 (surplus) and starving priority-low. This violates the core design promise that priority-low min-share is orthogonal to the oversubscription policy choice.

#### The Fix:
The early-branch logic must conditionally subtract and restore the reserved tokens if the min-share is non-zero, maintaining legacy RR for exact queues while honoring the min-share:
```rust
if root.config.oversubscription_policy == Proportional
   OR root.config.guarantee_fraction == 0.0:
    if root.config.priority_low_min_share_bytes == 0:
        // BIT-FOR-BIT IDENTICAL to legacy scheduler.
        return select_exact_cos_guarantee_queue_with_lease_telemetry(root, ...)
    else:
        // Proportional mode WITH priority-low min-share:
        // Subtract min-share first, run legacy selection, then restore for Phase 3.
        let priority_low_min_share_pass = priority_low_min_share_bytes * elapsed_ns / 1e9;
        root.tokens = root.tokens.saturating_sub(priority_low_min_share_pass);
        
        let res = select_exact_cos_guarantee_queue_with_lease_telemetry(root, ...);
        
        root.tokens += priority_low_min_share_pass;
        return res;
```

---

### C. CoDel Network-Physics Rigor
> **Critical Question:** *Does the CoDel experimental-gate disposition satisfy network-physics rigor?*

**Verdict: Yes, completely.**

By scaling the `codel-target` to $\max(5\text{ms}, 1.5 \times \text{RTT})$, the shaper delay allows a TCP sender to receive and process the congestion signal (ACK/SACK or ECE flag) before subsequent packets from the same flow are dropped at the dequeue gate. This prevents drops from becoming highly random/uncorrelated and preserves the per-flow CoV contract ($\le \text{Cstruct} + 0.05$).

Treating A3 as an experimental gate with an explicit rollback path (falling back to `codel-target 0` if smoke sweeps demonstrate wild oscillation or a breach of the CoV contract) is highly professional and protects the production dataplane from unexpected AQM instability.

---

### D. Numerics Consistency in §3
> **Critical Question:** *Are the §3 numerics consistent now?*

**Verdict: Yes, completely consistent.**

The sum of quantums has been corrected to **2626.5 KB**, folding in the Codex r2 arithmetic correction. All predicted values in the table now align perfectly:
$$\text{Predicted } T_i = 18\text{ Gbps} \times Q_i / 2626.5\text{ KB}$$
For example:
*   `100m`: $18 \times 2.5 / 2626.5 = 17.1\text{ Mbps}$ (matches $17\text{ Mbps}$)
*   `1g`: $18 \times 25 / 2626.5 = 171.3\text{ Mbps}$ (matches $171\text{ Mbps}$)
*   `9g`: $18 \times 225 / 2626.5 = 1.541\text{ Gbps}$ (matches $1.54\text{ G}$)
*   `24g`: $18 \times 512 / 2626.5 = 3.508\text{ Gbps}$ (matches $3.51\text{ G}$)

The prediction column sums to exactly $17.992\text{ Gbps} \approx 18\text{ Gbps}$. The numerical foundation is mathematically bulletproof.

---

### E. NEW Findings Introduced in v5

We identified two new substantive findings that must be addressed:

#### Finding E1: Rust Unsigned Underflow/Panic Risk in Token Subtraction
In §4 A2, the plan specifies:
```rust
priority_low_min_share_pass = priority_low_min_share_bytes × elapsed_ns / 1e9
cap_eff = root.tokens - priority_low_min_share_pass
```
*   **The Risk:** During transient token depletion or under heavy shaper rate limits, the token count `root.tokens` can be smaller than `priority_low_min_share_pass`. Because these are unsigned integer types (`u64`/`usize` in Rust), this subtraction will trigger an unsigned underflow.
*   **The Impact:** In Rust, an unsigned underflow causes a panic in debug mode (crashing the dataplane thread) and an integer wrapping overflow in release mode (corrupting token budgets to massive values).
*   **The Fix:** Use saturating subtraction explicitly in the plan:
    ```rust
    let cap_eff = root.tokens.saturating_sub(priority_low_min_share_pass);
    ```

#### Finding E2: Waterfill Allocator Phase 2 Quantum-Violation Bug
In §4 A1.1, Phase 2 states:
> `# No rate cap — Phase 2 share never exceeds the queue's per-pass quantum because pass2_budget ≤ pass2_quantum_sum in oversubscribed regime.`

*   **The Proof of Failure:** This claim is mathematically incorrect because the queue partially honored in Phase 1 (let's call it $p$) participates in Phase 2 with its *full* quantum $Q_p$ as its weight in the numerator, rather than its *remaining* quantum weight ($Q_p - \text{Phase1\_alloc}$).
*   **Mathematical Walk:**
    *   Consider 2 exact queues: $Q_1 = 10\text{ bytes}, Q_2 = 10\text{ bytes}$.
    *   Let capacity $C = 15\text{ bytes}$, and `guarantee_fraction = 0.5`.
    *   Pass 1 budget = $15 \times 0.5 = 7.5\text{ bytes}$.
    *   **Phase 1:** Queue 1 is evaluated. It needs $10\text{ bytes}$. Since $7.5 < 10$, it is partially honored with $7.5\text{ bytes}$. `honor_set = {}` (empty, since Queue 1 was not fully honored). Phase 1 ends.
    *   **Phase 2:** Budget = $15 - 7.5 = 7.5\text{ bytes}$.
    *   Unhonored queues: Queue 1 and Queue 2. Total unhonored quantum = $Q_1 + Q_2 = 20\text{ bytes}$.
    *   Phase 2 allocation for Queue 1 = $7.5 \times 10 / 20 = 3.75\text{ bytes}$.
    *   Phase 2 allocation for Queue 2 = $7.5 \times 10 / 20 = 3.75\text{ bytes}$.
    *   **Total Allocations:**
        *   Queue 1 = $7.5\text{ (Phase 1)} + 3.75\text{ (Phase 2)} = 11.25\text{ bytes}$.
        *   Queue 2 = $3.75\text{ bytes}$.
    *   Queue 1 receives **11.25 bytes**, which **exceeds its configured per-pass quantum of 10 bytes**!
*   **The Fix:** In Phase 2, the weight for any partially honored queue $p$ must be its remaining quantum ($Q_p - \text{alloc\_p\_phase1}$), and the denominator `unhonored_total_quantum` must be the sum of these remaining weights. 
    *   *Recalculated walk with correct weights:*
        *   Remaining weights: Queue 1 = $10 - 7.5 = 2.5$; Queue 2 = $10$. Total weight = $12.5$.
        *   Phase 2 alloc Queue 1 = $7.5 \times 2.5 / 12.5 = 1.5\text{ bytes}$.
        *   Phase 2 alloc Queue 2 = $7.5 \times 10 / 12.5 = 6.0\text{ bytes}$.
        *   Total Queue 1 = $7.5 + 1.5 = 9.0\text{ bytes} \le Q_1$ (Correct).
        *   Total Queue 2 = $6.0\text{ bytes} \le Q_2$ (Correct).

---

## Required Plan v5 Changes (NEEDS-MINOR)

To transition this plan to **PLAN-READY**, the implementer must update `plan.md` to incorporate the following three minor mechanical edits:

1.  **Correct the Early Proportional Mode Bypass:** Rewrite the §4 A1.1 bypass branch to handle `priority_low_min_share` subtraction and restoration if it is non-zero (as shown in §B).
2.  **Add Rust Saturating Subtraction Guard:** Update the §4 A2 subtraction step to explicitly specify Rust `saturating_sub` protection to eliminate the overflow/panic risk (as shown in §E1).
3.  **Fix the Waterfill Phase 2 Weighting:** Update the §4 A1.1 algorithm text to state that the partially honored queue participates in Phase 2 using its *remaining* quantum weight ($Q_i - \text{alloc}_i$), and update `unhonored_total_quantum` to sum the *remaining* weights of the unhonored set (as shown in §E2).

---

## Verdict

**NEEDS-MINOR**  
*(Plan is PLAN-READY as soon as these three mechanical algorithm and logic fixes are updated in the text. No further review cycles are required; the team is cleared to implement immediately once these edits are saved.)*
