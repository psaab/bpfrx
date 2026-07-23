# Codex hostile plan-review r9 (#5275) — VERDICT: PLAN-NEEDS-MAJOR (D1-D4 + D5(b) + facade all confirmed; ONE fix: gate crash-restart first-yield on verified scrub)

Reviewed plan.md @ r10. Final synthesis (file-read dumps stripped):

  [32m✓[0m Read r10 D5, the §5 facade-OPEN fix, and relevant surrounding invariants
  [32m✓[0m Trace all cited HA/VIP/heartbeat mechanisms in shipped source
  [32m✓[0m Compare r10 against rounds 1–8 and independently stress-test crash/live paths
  [36m→[0m Synthesize hostile review and issue the exact final verdict
[1mcollab:[0m Wait
[3mThe review is complete. r10 fixes the live interlock and facade omission, but the crash-path first-zero ordering admits a source-backed new dual-owner window, so the central “no worse” contract is not yet true.[0m
  [32m✓[0m Read r10 D5, the §5 facade-OPEN fix, and relevant surrounding invariants
  [32m✓[0m Trace all cited HA/VIP/heartbeat mechanisms in shipped source
  [32m✓[0m Compare r10 against rounds 1–8 and independently stress-test crash/live paths
  [32m✓[0m Synthesize hostile review and issue the exact final verdict
[2mcontext compacted[0m
[35m[3mcodex[0m[0m
r10 is still not approvable. The STONITH tradeoff is legitimate, but D5(a)’s central “no worse than an existing xpfd crash” claim is false for one valid execution.

The shipped mechanisms do support part of D5:

- NODAD state can survive daemon restart, and direct ownership is reconciled every HA tick ([daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:891)).
- `surfaceStaleVIP` performs five delayed retries, but it explicitly permits the VIP to remain after exhaustion until another transition ([instance_vip.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance_vip.go:90)). That is a bounded retry budget—not bounded convergence or guaranteed self-healing.
- Peer promotion and GARP are real, but GARP only influences neighbor caches; it neither removes the old address nor fences the old DHCP service.
- Therefore, when xpfd remains dead and its peer’s ordinary timeout expires, guaranteeing zero overlap does require an independent host-fencing mechanism. Asking the human to accept that existing window or require STONITH is a valid operational decision.

But r10 introduces an additional overlap:

1. Configure a long, valid heartbeat timeout; the schema places no relevant finite upper bound on the threshold ([schema_chassis.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/config/schema_chassis.go:74)).
2. The preferred primary crashes and restarts before that timeout. Today, the surviving peer has not promoted. Restart configuration immediately runs local election, allowing the preferred node to resume as the sole owner ([group_state.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/group_state.go:125), [daemon_run_bringup.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_bringup.go:161)).
3. Under r10, the held restart publishes weight zero while its inherited VIP/Kea state may still exist. Receipt of that heartbeat immediately invokes election ([heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:293)); zero peer weight promotes the receiver ([election.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:138)).
4. D5(c) explicitly scopes verified-withdraw-before-yield away from this crash path ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:504)). The zero heartbeat can therefore create dual VIP and dual DHCP ownership before asynchronous cleanup succeeds.

That window is caused by #5275 accelerating peer takeover; the corresponding current fast-restart execution need not have any dual ownership. The STONITH tradeoff does not excuse it.

The correction is straightforward but contract-critical: gate the restarted process’s first weight-zero publication on verified VIP/stable-link-local removal and Kea stop, or remain sender-silent until the peer has already promoted through the pre-existing failure detector. If restart scrubbing fails, #5275 must not accelerate takeover. This preserves the accepted existing crash hazard without promising impossible zero-window fencing. Sections 3/12 and D5(c) must also be made consistent.

D5(b)’s live path is sound: provided `fencing` is sticky and prevents VIP re-addition or queued Kea restart, publishing zero only after verified address removal and Kea shutdown prevents dual VIP/DHCP. FRR convergence behind the barrier is an availability/ECMP concern, not the same ownership-safety defect. The §5 facade-OPEN ordering fix is also correct.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
257,912
r10 is still not approvable. The STONITH tradeoff is legitimate, but D5(a)’s central “no worse than an existing xpfd crash” claim is false for one valid execution.

The shipped mechanisms do support part of D5:

- NODAD state can survive daemon restart, and direct ownership is reconciled every HA tick ([daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:891)).
- `surfaceStaleVIP` performs five delayed retries, but it explicitly permits the VIP to remain after exhaustion until another transition ([instance_vip.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance_vip.go:90)). That is a bounded retry budget—not bounded convergence or guaranteed self-healing.
- Peer promotion and GARP are real, but GARP only influences neighbor caches; it neither removes the old address nor fences the old DHCP service.
- Therefore, when xpfd remains dead and its peer’s ordinary timeout expires, guaranteeing zero overlap does require an independent host-fencing mechanism. Asking the human to accept that existing window or require STONITH is a valid operational decision.

But r10 introduces an additional overlap:

1. Configure a long, valid heartbeat timeout; the schema places no relevant finite upper bound on the threshold ([schema_chassis.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/config/schema_chassis.go:74)).
2. The preferred primary crashes and restarts before that timeout. Today, the surviving peer has not promoted. Restart configuration immediately runs local election, allowing the preferred node to resume as the sole owner ([group_state.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/group_state.go:125), [daemon_run_bringup.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_bringup.go:161)).
3. Under r10, the held restart publishes weight zero while its inherited VIP/Kea state may still exist. Receipt of that heartbeat immediately invokes election ([heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:293)); zero peer weight promotes the receiver ([election.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:138)).
4. D5(c) explicitly scopes verified-withdraw-before-yield away from this crash path ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:504)). The zero heartbeat can therefore create dual VIP and dual DHCP ownership before asynchronous cleanup succeeds.

That window is caused by #5275 accelerating peer takeover; the corresponding current fast-restart execution need not have any dual ownership. The STONITH tradeoff does not excuse it.

The correction is straightforward but contract-critical: gate the restarted process’s first weight-zero publication on verified VIP/stable-link-local removal and Kea stop, or remain sender-silent until the peer has already promoted through the pre-existing failure detector. If restart scrubbing fails, #5275 must not accelerate takeover. This preserves the accepted existing crash hazard without promising impossible zero-window fencing. Sections 3/12 and D5(c) must also be made consistent.

D5(b)’s live path is sound: provided `fencing` is sticky and prevents VIP re-addition or queued Kea restart, publishing zero only after verified address removal and Kea shutdown prevents dual VIP/DHCP. FRR convergence behind the barrier is an availability/ECMP concern, not the same ownership-safety defect. The §5 facade-OPEN ordering fix is also correct.

VERDICT: PLAN-NEEDS-MAJOR
