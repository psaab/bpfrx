I will list the current permission grants to verify my access.
I will view the plan document in the worktree directory to inspect the proposed plan (v2).
I will view the Rust source file `userspace-dp/src/afxdp/cos/queue_ops/push.rs` between lines 10 and 65 to analyze the single-flow FIFO and per-flow promotion behavior.
I will view the `userspace-dp/src/afxdp/cos/admission.rs` file to inspect how the `!flow_fair()` arms are implemented and see when ECN and flow-fair clamps are active.
I will read the next section of `userspace-dp/src/afxdp/cos/admission.rs` to check the other `!flow_fair()` arm.
I will search for the definition of the `flow_fair` method on `CoSQueueRuntime` to see what it returns.
I will view `userspace-dp/src/afxdp/types/cos.rs` around line 612 to see the implementation of the `flow_fair` method.
I will view `pkg/config/types_cos.go` around lines 80-110 to see the defaults and code comments about RTT and CoDel defaults.
I will view `userspace-dp/src/afxdp/protocol/cos.rs` around line 113 to confirm the default configuration values and their contract comments.
I will search the Rust codebase for `codel` to locate where CoDel parameters are configured or references to the protocol/cos.rs file might be.
I will search for `protocol.rs` or any files defining `CoSSchedulerSnapshot` in the codebase.
I will view `userspace-dp/src/protocol/cos.rs` around lines 100 to 125 to check the comments on the defaults.
I will list the directory `docs/research/1828-wan-sq/` in the worktree to see if there are other files related to the plan.
I will read `agy-plan-r1.md` (our round-1 review) to verify the details of the round-1 findings and resolutions.
I will view the beginning of `userspace-dp/src/afxdp/cos/admission.rs` to see the entry point and how queue limit and ECN checks are applied.
I will search for `cos_queue_accepts_prepared` and `cos_queue_accepts_local` inside `userspace-dp/src/afxdp/cos/admission.rs` to see the entry point functions for admission control.
I will search for all functions defined in `userspace-dp/src/afxdp/cos/admission.rs`.
I will view `userspace-dp/src/afxdp/cos/admission.rs` from lines 270 to 330.
PLAN-READY

### Round 1 Findings Verification
* **Finding (2) [Empirical validation check with active flow telemetry]:** **RESOLVED.** Plan v2 (§6 Deliverable 1 validation run, §10 Deliverable 1 test plan, and §12 Q5) explicitly mandates verifying `xpf_userspace_cos_active_flow_count > 1` on the synthetic queue under `-P 12` load to confirm lazy promotion.
* **Finding (3) [Post-expansion AST validation gate for commit check rules]:** **RESOLVED.** Plan v2 (§6 Deliverable 2 commit-check preamble, §10 Deliverable 2 test plan, and §12 Q1) explicitly specifies that the validation rules checking `smart-queueing` and `scheduler-map` collisions are evaluated on the post-group-expansion AST, preventing bypasses via `apply-groups`.
* **Finding (4) [WAN RTT mismatch in CoDel defaults]:** **RESOLVED.** Plan v2 (§6 Deliverable 2 defaults paragraph and §12 Q7) leaves scheduler-level defaults unfrozen to inherit live-validated values (referencing the baseline contract at [types_cos.go:90-96](file:///home/ps/git/bpfrx/pkg/config/types_cos.go#L90-L96)), and specifies cookbook guidance instructing operators to scale `codel-interval` appropriately on high-latency WAN links.

### Fold Verification and Nuance Check
* **§3 Row (b) Nuance Wording:** **VERIFIED CORRECT.** Checked against the Rust implementation:
  * In [push.rs:19-56](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/queue_ops/push.rs#L19-L56), `maybe_promote_best_effort` uses the cheap FIFO front key comparison and does not promote until a second distinct flow arrives.
  * In [admission.rs:222-224](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/admission.rs#L222-L224), `cos_flow_aware_buffer_limit` bypasses the per-flow share limits and the 5 ms clamp if `!queue.flow_fair()`.
  * In [admission.rs:346-352](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/cos/admission.rs#L346-L352), `apply_cos_admission_ecn_policy` defaults to the `aggregate_above` threshold rather than `flow_above` if `!queue.flow_fair()`.
  The wording matches the code behavior precisely and introduces no new errors.
* **§12 Resolutions Block Fidelity:** **VERIFIED CORRECT.** All 7 round-1 questions correspond perfectly to the previous answers and findings.

### New Findings
* **None.** No new design risks, rollback issues, or syntax compile errors were identified in the v2 plan.
