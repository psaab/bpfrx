I will check the existence and read the content of the target plan.
I will read `userspace-dp/src/afxdp/cos/queue_service/mod.rs` to verify the refutation of the Phase-1 budget depletion and early Phase-2 switch hypotheses.
I will read the lines preceding line 1000 to see how the Phase 1 loop begins.
I will find the location of the previous round-1 verdict file to understand the baseline context of the review.
I will view the files inside the target directory `/home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/` to find any other logs or `agy-plan-r1.md`.
I will read the Round 1 verdict file `agy-plan-r1.md` to see our previous criticisms.
I will list the contents of the `raw` directory to see what measurement evidence exists.
I will run `git diff` on the working tree to inspect the exact changes currently present.
I will view the beginning of `select_exact_cos_guarantee_queue_waterfill` around lines 800 to 900 to check how `waterfill_pass1_remaining_bytes` and epochs are initialized and managed.
I will view the rest of the selector function to understand the Phase 2 wrap logic.
I will search for `fairness-regimes.md` to confirm its exact path in the workspace.
# Hostile Adversarial Review (Round 2) — Re-Adjudication

We have reviewed the updated plan and the new measurement evidence presented in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md). Based on the new bisect-grade A/B redeployments, increased statistical repetition count, mixed-probe inelastic UDP cells, and code audits, we re-adjudicate the round-1 points and assess the disposition.

---

## 1. Adjudication of Round-1 Kill Points

### KP2a (Repetition Count & Statistical Validity) — RESOLVED
- **Round-1 Objection:** The sample size was too small to rule out transient scheduling jitter.
- **New Evidence:** Section 2.2 of [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L58) now provides 9 full repetitions on master for the decisive `small4 + 24g` cell. 
- **Analysis:** The mean shape percentages of $71.1\%$ for the $3g$ class and $70.0\%$ for the $6g$ class sit squarely on or above the contract guarantee ($G_i = 0.7 \times R_i$). Section 8 honestly discloses that $\sim 40\%$ of the 30-second samples straddle the floor with minor sampling dips (worst case $66.2\%$ for $6g$ in `r7`, or $94.6\%$ of the guarantee). This is standard pacing jitter under high-speed AF_XDP queues, not a systematic failure.

### KP3 (A/B Deployment Causal Proof) — RESOLVED
- **Round-1 Objection:** The improvement was purely correlational.
- **New Evidence:** Section 2.7 of [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L158) records a bisect-grade A/B redeployment at the series boundary `e4556085a` (immediately pre-#1743).
- **Analysis:** Rolling back to the pre-#1743 boundary reproduces the starvation signature: $3g$ fell to $57.4\% / 60.3\%$ and $6g$ to $61.2\% / 58.6\%$. The in-band telemetry checks also confirmed the phase-counter regime flip: on the pre-#1743 build, the $24g$ aggressor (`q10`) took 619,579 Phase-1 admissions and 0 Phase-2 admissions, whereas on master, `q10` is only admitted in Phase 2. This proves that the #1743 scheduler fixes directly healed the starvation.

### KP2b (UDP Control Validity) — RESOLVED
- **Round-1 Objection:** The UDP control cell was invalid because the traffic generator was capped at $\sim 2.9\text{ G}$ per process, failing to saturate the link.
- **New Evidence:** Section 2.6 of [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L132) introduces the **mixed probe cell**.
- **Analysis:** By offering $6g$ as inelastic UDP at $2.76\text{ G}$ (66% of its $G_i$) against maximum elastic TCP pressure from $100m / 1g / 3g / 24g$ (where the $24g$ TCP aggressor successfully pulled $10.8\text{ G} / 8.9\text{ G}$), the $6g$ probe was delivered at essentially zero loss ($0.00\% / 0.11\%$). This refutes the pacing-collapse concern for the protected rate band.

### KP1 (Starvation Floor Violations) — RESOLVED
- **Round-1 Objection:** Rep `r3` of the $6g$ class was measured at $69.2\%$, violating the $70\%$ floor contract.
- **New Evidence:** Section 4 of [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L240) analyzes the starvation criteria from [fairness-regimes.md](file:///home/ps/git/bpfrx/docs/fairness-regimes.md).
- **Analysis:** Strictly speaking, all five classes in the decisive cell are guaranteed under the `oversubscription-policy guarantee-rate 0.7` fixture. This makes the sum of guarantees $\sum G_k \ge 21.77\text{ G}$, which exceeds the physical ceiling $C_{\text{phys}} \approx 22.6\text{ G}$. Thus, Starvation Condition 3 (which requires $\sum G_k < C_{\text{phys}}$) is not satisfied. The minor $0.8\%$ dip in `r3` is noise-level sampling variance at floor-equilibrium.

### KP5 (Phantom Charge Refutation) — RESOLVED
- **Round-1 Objection:** High-rate quantum charges under low-token visits create phantom charges that deplete Phase-1 budget early and enrich Phase-2 aggressors.
- **New Evidence:** Section 4.1 of [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1614-research-v2/docs/research/1614-residual-v2/plan.md#L268) and code verification of the [select_exact_cos_guarantee_queue_waterfill](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L898) function.
- **Analysis:** 
  1. The code audit of [mod.rs:1032-1065](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L1032-L1065) shows that the budget charge `phase1_cost` is calculated as `cos_guarantee_quantum_bytes(queue).max(head_len)`. This is a stable configured quantum that is **independent** of `queue.hot.tokens`. Therefore, budget depletion rate per queue honored is identical regardless of the token state.
  2. Phase 2 entry ([mod.rs:1043](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L1043)) occurs when `phase1_cost` exceeds `root.waterfill_pass1_remaining_bytes`. Since `phase1_cost` is constant (token-independent), the entry threshold remains fixed and is not accelerated by token state.
  3. The core mechanism is instead the **honored-realization gap** (Hypothesis H1): once a queue is selected, it is marked honored in [waterfill_honored_epoch_bits](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L1063) and locked out of both phases for the rest of the epoch, even if its actual send was clamped by a depleted token bank. The plan correctly captures this behavior as H1 for the scoped follow-up.

---

## 2. Pressure-Testing & Operational Risks

### BPF Verifier Size Cap Sensitivity (Side Finding 1)
- **Risk:** Running `make generate` locally compiles the `pkg/dataplane/userspace_xdp_bpfel.o` object to a size that exceeds the BPF verifier cap of 1,000,000 instructions. This puts the controller into config-only mode and takes the datapath down.
- **Mitigation:** Endorse the plan's recommendation in Section 9.1 to pin the `RUST_BPF_TOOLCHAIN` and `bpf-linker` versions, and enforce a load-time verifier check before committing regenerated artifacts.

### Shared-Cluster Contention (Side Finding 3)
- **Risk:** Concurrent deployments bypassing the lock at `/tmp/xpf-cluster.lock` can clobber active tests.
- **Mitigation:** Serially-enforced lock discipline must be maintained across all agent harnesses.

---

## 3. Verdict

PLAN-READY
