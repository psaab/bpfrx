# Codex hostile plan-review r5 (#5275) — VERDICT: PLAN-NEEDS-MAJOR (viable; 5/8 contracts closed, 5 blocking + 2 holes remain)

Reviewed plan.md @ r6. Final synthesis (file-read dumps stripped):


[3mCompleted the plan, prior-review, and firsthand source audit. The requested mechanisms are all present textually, but cross-contract contradictions and two previously raised lifecycle/publication contracts remain unresolved at design level.[0m
  [32m✓[0m Read r6, prior reviews, and cited source firsthand
  [32m✓[0m Verify the eight round-4 contracts against source and each other
  [32m✓[0m Audit apparent closures and new correctness holes
  [36m→[0m Deliver the hostile design-level verdict
[3mThe review is complete. r6 is architecturally viable and substantially improved, but four cross-contract design choices remain unresolved, so it is not yet safe to hand to implementation.[0m
  [32m✓[0m Read r6, prior reviews, and cited source firsthand
  [32m✓[0m Verify the eight round-4 contracts against source and each other
  [32m✓[0m Audit apparent closures and new correctness holes
  [32m✓[0m Deliver the hostile design-level verdict
[35m[3mcodex[0m[0m
r6 is architecturally viable and materially better, but it is still not an executable security contract. All eight requested mechanisms appear textually; several do not compose safely.

| # | Assessment |
|---|---|
| 1 | Composed hold and standalone daemon state are correctly specified. |
| 2 | Withdrawal inventory and held-RG0 read-only are specified, but the recovery path contradicts read-only. |
| 3 | §5 defines the right proof, but §9 performs attachment-affecting mutations after that proof. |
| 4 | Bridge/flowtable containment is correct; “hold clears last” is not reflected by the actual sequence. |
| 5 | Alias-safe facade and teardown retention are present, but the facade is not specified as sealed while pending. |
| 6 | Weight-zero and heartbeat-only lifecycle are sound choices, but yield is not tied to the composed hold. |
| 7 | The three routes and six stages are present, but candidate-generation isolation is undefined. |
| 8 | The PR boundaries are honest in intent, but PR1 depends textually on §9 machinery deferred to PR3. |

The blocking findings are:

1. Final proof is followed by proof-invalidating mutations. Section 5 correctly requires proof after the final link-cycle/reapply/rebind ([plan.md:136](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:136)). Section 9 instead proves at step 4, then publishes networkd and VRF changes at step 5 ([plan.md:215](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:215)). In the source, networkd is followed by RETH link cycling and AF_XDP rebind/reapply ([daemon_apply_dataplane.go:219](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:219), [daemon_apply_dataplane.go:386](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:386)). The plan must distinguish preliminary attachment proof from one final post-mutation proof, with addresses, FRR, services, barrier removal, and ownership release after that final proof.

2. RG0 read-only makes the promised HA fix-forward path impossible. Sections 3 and 8 require read-only throughout `armFailed` while allowing persistence of a corrected configuration ([plan.md:82](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:82), [plan.md:193](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:193)). The actual gate rejects user mutation and commit; only internal HA sync bypasses it ([store_lock.go:9](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store_lock.go:9)). Section 4 excludes config sync before proof. A failed clustered node can therefore neither accept a local correction nor receive the primary’s correction. The plan must choose a non-authoritative recovery store, narrowly scoped inbound authoritative sync, or standalone-only persistence. `pkg/configstore` must consequently enter the blast radius.

3. The prior publisher-TOCTOU finding is only apparently closed. Section 9 promises to abort all candidate publication while retaining the old armed generation ([plan.md:220](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:220)), but the source promotes and persists the candidate before apply ([daemon_apply_commit.go:225](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:225)). Independent DDNS, RA, and VIP reconcilers subsequently read `ActiveConfig`, so they can publish the supposedly aborted candidate. The contract must select delayed promotion, rollback, or a durable applied/published-generation view consumed by every publisher. Merely aborting the current apply stack is insufficient.

4. Release and lifecycle ownership remain ambiguous. Section 5 clears `dataplaneUnproven` before `startTakeoverMachinery`, while §9 calls that function the `armPending → armed` release path ([plan.md:146](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:146), [plan.md:223](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:223)). Clearing a hold can synchronously re-elect, so it is not actually the final ownership-enabling action if lifecycle preparation still follows. Define one atomic release owner and the full post-proof lifecycle inventory.

5. The facade is not sealed during `armPending`. Section 7 revokes it only “on arm failure” ([plan.md:179](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:179)). Management captures the backend and exposes forwarding, queue, and binding mutators ([server_diag_system_action.go:396](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/grpcapi/server_diag_system_action.go:396)); those calls do not traverse the apply gate. The facade must start sealed, permit arming only through a private capability, open at the final release, and revoke stickily against concurrent calls.

Two additional correctness holes need explicit treatment:

- Weight-zero must remain active whenever `effectiveHold` is true, not merely while `dataplaneUnproven` is true. Otherwise dataplane proof can restore normal advertised weight while `kernelTrialUnpromoted` still prevents local ownership, recreating both-secondary.
- A failed withdrawal scrub has no safe branch. Withholding explicit yield does not prevent peer timeout promotion, while the plan acknowledges that the transit barrier cannot suppress stale VIP/Kea/FRR ownership. Require a proved-down/service-fenced fallback before peer takeover is safe.

The bridge/flowtable barrier, proof ingredients, heartbeat wire compatibility, teardown retention, and nominal three-PR division are genuinely closed. Minor cleanup remains—“peer owns every RG” should mean every mutually configured and eligible RG, and §8’s PR1 gate cannot require the §9 transaction that only lands in PR3—but those are not the reason for the verdict.

This remains a viable architecture, not a plan-kill. However, proof ordering, configuration authority, generation visibility, and release ownership require explicit design choices before `/engineer`; they are not line-level implementation details.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
289,835
r6 is architecturally viable and materially better, but it is still not an executable security contract. All eight requested mechanisms appear textually; several do not compose safely.

| # | Assessment |
|---|---|
| 1 | Composed hold and standalone daemon state are correctly specified. |
| 2 | Withdrawal inventory and held-RG0 read-only are specified, but the recovery path contradicts read-only. |
| 3 | §5 defines the right proof, but §9 performs attachment-affecting mutations after that proof. |
| 4 | Bridge/flowtable containment is correct; “hold clears last” is not reflected by the actual sequence. |
| 5 | Alias-safe facade and teardown retention are present, but the facade is not specified as sealed while pending. |
| 6 | Weight-zero and heartbeat-only lifecycle are sound choices, but yield is not tied to the composed hold. |
| 7 | The three routes and six stages are present, but candidate-generation isolation is undefined. |
| 8 | The PR boundaries are honest in intent, but PR1 depends textually on §9 machinery deferred to PR3. |

The blocking findings are:

1. Final proof is followed by proof-invalidating mutations. Section 5 correctly requires proof after the final link-cycle/reapply/rebind ([plan.md:136](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:136)). Section 9 instead proves at step 4, then publishes networkd and VRF changes at step 5 ([plan.md:215](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:215)). In the source, networkd is followed by RETH link cycling and AF_XDP rebind/reapply ([daemon_apply_dataplane.go:219](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:219), [daemon_apply_dataplane.go:386](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:386)). The plan must distinguish preliminary attachment proof from one final post-mutation proof, with addresses, FRR, services, barrier removal, and ownership release after that final proof.

2. RG0 read-only makes the promised HA fix-forward path impossible. Sections 3 and 8 require read-only throughout `armFailed` while allowing persistence of a corrected configuration ([plan.md:82](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:82), [plan.md:193](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:193)). The actual gate rejects user mutation and commit; only internal HA sync bypasses it ([store_lock.go:9](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store_lock.go:9)). Section 4 excludes config sync before proof. A failed clustered node can therefore neither accept a local correction nor receive the primary’s correction. The plan must choose a non-authoritative recovery store, narrowly scoped inbound authoritative sync, or standalone-only persistence. `pkg/configstore` must consequently enter the blast radius.

3. The prior publisher-TOCTOU finding is only apparently closed. Section 9 promises to abort all candidate publication while retaining the old armed generation ([plan.md:220](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:220)), but the source promotes and persists the candidate before apply ([daemon_apply_commit.go:225](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:225)). Independent DDNS, RA, and VIP reconcilers subsequently read `ActiveConfig`, so they can publish the supposedly aborted candidate. The contract must select delayed promotion, rollback, or a durable applied/published-generation view consumed by every publisher. Merely aborting the current apply stack is insufficient.

4. Release and lifecycle ownership remain ambiguous. Section 5 clears `dataplaneUnproven` before `startTakeoverMachinery`, while §9 calls that function the `armPending → armed` release path ([plan.md:146](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:146), [plan.md:223](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:223)). Clearing a hold can synchronously re-elect, so it is not actually the final ownership-enabling action if lifecycle preparation still follows. Define one atomic release owner and the full post-proof lifecycle inventory.

5. The facade is not sealed during `armPending`. Section 7 revokes it only “on arm failure” ([plan.md:179](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:179)). Management captures the backend and exposes forwarding, queue, and binding mutators ([server_diag_system_action.go:396](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/grpcapi/server_diag_system_action.go:396)); those calls do not traverse the apply gate. The facade must start sealed, permit arming only through a private capability, open at the final release, and revoke stickily against concurrent calls.

Two additional correctness holes need explicit treatment:

- Weight-zero must remain active whenever `effectiveHold` is true, not merely while `dataplaneUnproven` is true. Otherwise dataplane proof can restore normal advertised weight while `kernelTrialUnpromoted` still prevents local ownership, recreating both-secondary.
- A failed withdrawal scrub has no safe branch. Withholding explicit yield does not prevent peer timeout promotion, while the plan acknowledges that the transit barrier cannot suppress stale VIP/Kea/FRR ownership. Require a proved-down/service-fenced fallback before peer takeover is safe.

The bridge/flowtable barrier, proof ingredients, heartbeat wire compatibility, teardown retention, and nominal three-PR division are genuinely closed. Minor cleanup remains—“peer owns every RG” should mean every mutually configured and eligible RG, and §8’s PR1 gate cannot require the §9 transaction that only lands in PR3—but those are not the reason for the verdict.

This remains a viable architecture, not a plan-kill. However, proof ordering, configuration authority, generation visibility, and release ownership require explicit design choices before `/engineer`; they are not line-level implementation details.

VERDICT: PLAN-NEEDS-MAJOR
