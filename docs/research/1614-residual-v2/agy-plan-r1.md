I will start by listing the contents of the `docs/research` directory to locate the plan files and raw measurements for the residual issue #1614.
I will list the contents of the target directory inside the `.claude/worktrees/1614-research-v2` worktree.
I will view the main plan file `plan.md` to understand the proposed resolution of issue #1614 and the supporting data.
I will read the supporting document `claude-smr-plan-r1.md` next to see if there is previous reviewer input or context that I should take into account.
I will view the SSOT contract document `docs/fairness-regimes.md` to see the definitions of starvation and fairness regimes, specifically the section 'Reading divided-ceiling as starvation is a misread'.
I will search for the phrase "divided-ceiling" in `docs/fairness-regimes.md` to find the exact section mentioned in the user's request.
I will view the contents of `docs/fairness-regimes.md` from line 1020 to 1110 to read the "Reading divided-ceiling as starvation is a misread" section.
I will list the contents of the raw measurement directory `docs/research/1614-residual-v2/raw/` to understand what runs were captured and analyze their data.
I will list the contents of one of the raw measurement run directories to see the structure of the JSON and metric files collected.
I will run a git command to inspect the changes introduced in commit `2e6e0041f` (#1743) to verify the three hunks described in the plan.
I will run a command to see the full list of files modified and the commit message of `2e6e0041f`.
I will run a git command to view the diff for `queue_service/mod.rs` in commit `2e6e0041f` to see how Hunks A, B, and C were implemented.
I will view the `select_exact_cos_guarantee_queue_waterfill` function in `userspace-dp/src/afxdp/cos/queue_service/mod.rs` to review the entire logic of the waterfill scheduler.
I will view lines 1050 to 1250 of `queue_service/mod.rs` to see how Phase 2 selection and budget wrap-around are implemented.
I will search for "guarantee-rate" and "fraction" in `docs/fairness-regimes.md` to identify all contract clauses governing these terms.
I will view lines 980 to 1020 of `docs/fairness-regimes.md` to understand the definitions of guarantee-rate and its oversubscription policies.
I will search for `cos_guarantee_quantum_bytes` in the codebase to understand how queue quantums are calculated.
I will view lines 1735 to 1765 of `queue_service/mod.rs` to see the quantum calculation logic.
I will search for the definition of `COS_GUARANTEE_QUANTUM_MIN_BYTES` and `COS_GUARANTEE_QUANTUM_MAX_BYTES` to see what constraints are applied to the quantums.
I will search for the definition of `COS_GUARANTEE_QUANTUM_MAX_BYTES` to see what is its upper limit.
I will search for `share_exhausted` and `AcquireV8ShortfallCause` in the codebase to understand what these counters measure and how they relate to the lease layer.
I will search for `AcquireV8ShortfallCause` to find where the shortfall reasons are defined and incremented.
I will search for `Shortfall` case-insensitively in the codebase.
I will run `git status` in the `1614-research-v2` worktree directory to check if there are any modified or untracked files specific to this worktree.
I will check the git history in the `1614-research-v2` worktree to see the latest commits on the `research/1614-residual-v2` branch.
I will run `git show --stat 5f95f7d33` to see what changes were made in the commit that introduced this plan.
# Hostile Adversarial Review: Close-to-Contract Proposal for #1614

## Verdict: PLAN-KILL

---

### Adjudication 1: Reading A is Ratified, but the Starvation Test is Violated (KILL Point 1)

**Reading A** (the ratified SSOT starvation test) is the only legally binding basis for closing the issue. The product contract in [fairness-regimes.md](file:///home/ps/git/bpfrx/docs/fairness-regimes.md) explicitly defines the starvation guarantee $G_i$ for a class $i$ at lines 1040-1041:
> "A guaranteed class `i` (guarantee `G_i = R_i × guarantee-rate fraction`)..."

Furthermore, at lines 1095-1097, [fairness-regimes.md](file:///home/ps/git/bpfrx/docs/fairness-regimes.md) explicitly states that the full-shape expectation (**Reading B**) is not a binding gate under multi-class contention:
> "The ≥95% guarantee for 3g/6g under multi-class contention is a CONFIRMED-but-mechanism-UNRESOLVED defect tracked in **#1692**; it is not asserted here until that issue resolves."

Therefore, Reading A is the correct basis for evaluation. 

**However, the close is KILLED because the decisive cell data violates Reading A.**
In the decisive cell `small4 + 24g` (reported in [plan.md:65](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L65)), the `6g` class in rep `r3` achieves **69.2%** of shape. 
- The configured shape $R_{6g} = 6.0\text{ G}$.
- The contract guarantee $G_{6g} = 6.0\text{ G} \times 0.7 = 4.2\text{ G}$ (70.0% of shape).
- In `r3`, the achieved rate is $4.152\text{ G}$, which is strictly less than the guarantee of $4.2\text{ G}$ ($4.152 < 4.200$).

This triggers **Condition 1** (`actual_i < G_i` is true) from [fairness-regimes.md:1043](file:///home/ps/git/bpfrx/docs/fairness-regimes.md#L1043). Since the $24g$ class receives bandwidth ($11.95\text{ G} > 0$, satisfying **Condition 2**), and the sum of guarantees fits under the ceiling ($\sum G_k = 7.07\text{ G} < 19.34\text{ G}$, satisfying **Condition 3**), **all three starvation criteria are satisfied**. 

Waving this off as "within noise" is unacceptable in a strict QoS validation. The code mathematically starved the $6g$ class in rep `r3`.

---

### Adjudication 2: The Measurement Program is Unsound (KILL Point 2)

1. **Statistically Inadequate Repetitions:** Network performance testing under high-speed AF_XDP (25G line rate) is highly sensitive to packet pacing, CPU scheduling jitter, and RSS distribution. Running only 3 repetitions for the decisive cell and 2 repetitions for controls is insufficient to rule out transient failures. The fact that `r3` violated the starvation contract while `r1` and `r2` barely passed confirms that the sample size is too small to build confidence.
2. **Invalid UDP Saturation Control:** The UDP perturbation experiment ([plan.md:120-130](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L120-L130)) was designed to rule out TCP-pacing-collapse as a driver of starvation. However, due to generator limitations (iperf3 UDP capped at ~2.9 G per process), the $24g$ aggressor only generated 2.9 G of load. This represents an 8-fold reduction in aggressor traffic compared to the TCP run (~11.9 G). Consequently, the UDP runs **did not test the classes under saturated aggressor conditions**. The assertion that "no TCP-pacing-collapse artifact is hiding starvation" is invalid because the perturbation failed to recreate the saturation pressure.

---

### Adjudication 3: Unsound Attribution without Pre-#1743 A/B Deploy (KILL Point 3)

The plan attributes the improvement in the $3g/6g$ classes from ~52% to ~72% solely to the changes in commit `2e6e0041f` (#1743). However, because master was deployed fresh this session, and other changes (such as FQ-CoDel dequeue AQM work and NAT changes) were merged around the same time, this attribution is purely correlational. To prove that `#1743` healed the defect, a rollback A/B test (deploying `2e6e0041f^` and re-running the decisive cell in the same session) is required. Skipping this test to save a 1-hour cluster run is an unacceptable engineering shortcut.

---

### Adjudication 4: Follow-up is Not Differentiated from Killed #1692 (KILL Point 4)

The proposed follow-up issue is not sufficiently differentiated from the plan-killed `#1692`. The plan admits in [plan.md:208-213](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L208-L213):
> "...per-worker (not per-class) resolution means the lease-layer split between honored-class and Phase-2-class service is still not directly observable — the same observability wall that killed #1692..."

If the follow-up faces the exact same observability wall, it will be unable to diagnose the root cause of the realization gap. It will inevitably slide back into proposing passive/active lease-layer instrumentation, resurrecting the exact path that killed `#1692`.

---

### Architectural Finding: Hunk B "Phantom Charge" & Lockout Livelock (KILL Point 5)

Our code audit of [select_exact_cos_guarantee_queue_waterfill](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L800) reveals a major architectural bug introduced by Hunk B of `#1743`. 

At [queue_service/mod.rs:1032-1033](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L1032-L1033):
```rust
let phase1_cost = cos_guarantee_quantum_bytes(queue).max(head_len);
let send_budget = queue.hot.tokens.min(cos_guarantee_visit_cap_bytes()).max(head_len);
```

1. **Phantom Charge:** When a queue is visited during Phase 1, the selector subtracts `phase1_cost` (the full rate-scaled quantum, e.g., 75,000 bytes for the $3g$ class) from `waterfill_pass1_remaining_bytes`. However, if the queue's token bucket is low (e.g. 1,500 bytes because the worker loop runs fast and visits it before tokens accumulate), the drain budget `send_budget` is clamped to 1,500 bytes. The queue only sends 1,500 bytes on the wire, but the Phase-1 budget is charged for the full 75,000 bytes. This creates a **phantom charge** that drains the Phase-1 budget without sending data.
2. **Lockout Livelock:** Because the queue was selected, it is marked as honored in `waterfill_honored_epoch_bits` (line 1063). This **locks out** the queue from both Phase 1 and Phase 2 for the rest of the 200 µs epoch. The queue continues to accumulate tokens during the remaining portion of the epoch, but it is prohibited from sending packets.
3. **Aggressor Enrichment:** The phantom charges prematurely deplete the Phase-1 budget. Once the budget hits zero, the allocator switches to Phase 2, which skips all "honored" queues (even if they only sent 1 packet). The un-honored $24g$ aggressor queue then consumes the remaining root tokens in Phase 2.

This explains the ~16-19 pt realization gap. It is a logical scheduling defect caused by early lockout and phantom charging, not an unrecoverable "physical ceiling limit." Under aggressor pressure, tokens are depleted, maximizing the occurrence of phantom charges and forcing early lockouts on the $3g/6g$ classes.

---

### Summary of Actions Required
To make this plan ready:
1. **Fix the Hunk B Phantom Charge:** Update the selector to charge the Phase-1 budget only for the bytes actually sent (or restore credit for unsent bytes), and allow queues that were locked out early to reclaim service in Phase 2 if their token buckets refill.
2. **Perform the pre-#1743 master A/B deployment** to confirm causal attribution.
3. **Fix the UDP generator limit** (e.g. by fixing the 620x iperf servers or splitting ports) and run a valid 24 G UDP saturation control.
4. **Increase the repetition count** to at least 5-10 runs for all cell configurations to establish statistical validity.
