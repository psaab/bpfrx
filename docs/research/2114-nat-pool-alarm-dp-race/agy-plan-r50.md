# AGY adversarial plan-review — round 50 (plan v50 @ 2ca8da070)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY-WITH-NITS (0 MAJOR, 1 MINOR — the §9/acceptance re-activation copy omitted the two-node + complete-predicate clauses, IS Codex fold-2's PARTIAL; folds 4 FOLDED / 1 PARTIAL; 2 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

Wait, let's look at line 2092 where v50 revision history starts or grep for v50 related sections. Let's do grep search for `H2` or `5.1` or `r49` or `apply-health` in `plan.md`.
Let's read around line 2092 to see the full v50 entry in revision history.
Let's carefully review the user prompt, instructions, rules, and questions.

The prompt tasks us with:
"Adversarial PLAN review (round 50, CONVERGENCE round) of a research plan-of-action doc for GitHub issue #2114 in the xpf repo...
Read-only — do NOT edit any files. This is a PLAN review, NOT a code review — no production code exists for plan items; verify the plan's claims ABOUT the code by reading the referenced source.

Plan doc: docs/research/2114-nat-pool-alarm-dp-race/plan.md in the worktree...
Read work item H2's runbook, the §5.1 pkg/daemon + pkg/cluster inventory entries, the formal acceptance copy, and §9's JOIN-COHERENCE leg in full. In round 49 you returned NEEDS-REVISION... v50 folds all of those findings. Your r50 job: verify the v50 folds below, attack the v50 delta, and confirm the structure."

Let's read all the required sections in `plan.md` first, as well as check code files in the repo to verify claims about real code.

Let's find the line numbers for:
- Work item H2's runbook
- §5.1 pkg/daemon + pkg/cluster inventory entries
- Formal acceptance copy
- §9's JOIN-COHERENCE leg in full

Let's grep in `plan.md` for these sections.
(A) Fold verification:
1. FOLDED — [daemon_apply.go:49-86,141-355](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go#L49-L86); [`plan.md:5598-5613,7094-7104`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5598-L5613). Central state `applyFailureCount` + `lastApplyOK` exists in §5.1, `applyConfigLocked` is verified as the single full-apply entry point, and §9 legs `h2a` and `h2b` cover the sticky-failure and parked-mid-apply regressions.
2. PARTIAL — [`plan.md:4712-4726,7027-7034`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4712-L4726). The §4.7 runbook copy (`plan.md:4712-4726`) carries the full 2-node re-activation requirement with each commit's success and full health predicate, but §9's copy (`plan.md:7027-7034`) omitted "ON BOTH NODES, each commit's own success required" and "followed by the COMPLETE predicate again", specifying only a pre-quiesce digest check.
3. FOLDED — [daemon_ha_sync.go:336-370,447-465](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go#L336-L370); [election.go:172-193](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/election.go#L172-L193); [daemon_run.go:157-177,393-398](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L157-L177); [`plan.md:4585-4614,6933-6951`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4585-L4614). Election-aware choreography and precedence reconciliation are stated in both copies.
4. FOLDED — [`plan.md:4358-4367,6866-6872`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4358-L4367). Both runbook and acceptance copies carry the re-baseline rule and the termination clause.
5. FOLDED — [`plan.md:4204-4212,6814-6818`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4204-L4212). Both copies explicitly state the re-capture rule covering both pre-quiesce and fence-time baselines.

(B) Fresh attacks:
- Load-override-on-resulting-authority timing: FAILED (If the post-stability push fires first with $T_{old}$, both nodes temporarily hold $T_{old}$, but the final post-restart predicate compares active digests against the off-node captured intended digest $T_{new}$, failing the check until the operator re-drives `load override` + `commit` on the authority).
- `lastApplyOK=false-at-entry` vs boot apply: FAILED (A process before boot apply completion reads `lastApplyOK == false`, correctly failing the predicate as intended until boot apply completes with a nil return and sets `lastApplyOK` to `true`).

(C) New findings:
- MINOR: [`plan.md:7027-7034`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7027-L7034). §9's re-activation copy is incomplete compared to the runbook copy at [`plan.md:4712-4726`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4712-L4726). It omits the "ON BOTH NODES, each commit's own success required" clause and the re-verification of the full health/apply predicate (persist-health aggregate, `ActiveApplied`, apply-failure/last-outcome terms on both nodes), leaving §9 specifying only a single-node pre-quiesce digest check for re-activation.

(D) Structure confirmation:
Confirmed: the §4.7 2-unit split structure stands, and AGY's r28 (A) dissent remains recorded ([`plan.md:5579-5586`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5579-L5586)).

(E) Verdict line:
PLAN-READY-WITH-NITS
