# Codex hostile plan-review r10 (#5275) — VERDICT: PLAN-NEEDS-MAJOR (crash fix SOUND; scope sender-silent to crash-only; live keeps incumbent until scrub; 2 doc-consistency fixes)

Reviewed plan.md @ r11. Final synthesis (file-read dumps stripped):

  [32m✓[0m Inspect r11, prior r1–r9 reviews, and repository state
  [32m✓[0m Trace unified yield-gate safety across crash-restart and live re-arm paths
  [32m✓[0m Verify §3, §12, D5(c), and cited source claims firsthand
  [32m✓[0m Perform hostile residual-risk audit and issue exact verdict
[35m[3mcodex[0m[0m
r11 closes the exact round-9 crash-restart overlap, but it is not approvable: the unified failure rule creates a new live-path safety defect.

For crash restart, D5(a)’s first-zero gate is sound: verified VIP/stable-link-local removal and Kea stop precede weight-zero, while failure remains silent instead of triggering immediate zero-weight election ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:487), [election.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:152)). That closes r9’s accelerated-takeover defect.

But sender-silent-on-failure is unsafe for live re-arm:

1. A running primary loses dataplane verification.
2. Its scrub fails, so VIP/Kea may remain.
3. D5(c) makes it sender-silent ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:510)).
4. Silence creates peer staleness; timeout elects the peer Primary before optional fencing ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:910), [heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:404)).
5. The peer can activate VIP/Kea while the still-running old owner retains them.

Unlike crash restart, this staleness episode is caused by #5275 silencing a previously healthy sender. Therefore the D5 sign-off claim that #5275 never accelerates takeover into unscrubbed state is false for path (b).

The correction is to scope sender-silent failure fallback to crash restart. Live `fencing` must remain pre-hold and retain an incumbent-heartbeat/takeover interlock until scrub succeeds; only then atomically enter `effectiveHold`/`armFailed` and publish zero. Otherwise, silence requires a separately verified service/host fence.

The requested sections are also inconsistent: §12 still requires proved-down/service-fenced fallback and FRR removal before yield, whereas §3/D5(c) prescribe sender-silent timeout fallback and asynchronous FRR ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:390)). Additionally, §3’s “orderly shutdown scrubs” is overbroad: shutdown source does not stop Kea or clear persisted FRR ([daemon_run_shutdown.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_shutdown.go:124)).

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
155,021
r11 closes the exact round-9 crash-restart overlap, but it is not approvable: the unified failure rule creates a new live-path safety defect.

For crash restart, D5(a)’s first-zero gate is sound: verified VIP/stable-link-local removal and Kea stop precede weight-zero, while failure remains silent instead of triggering immediate zero-weight election ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:487), [election.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:152)). That closes r9’s accelerated-takeover defect.

But sender-silent-on-failure is unsafe for live re-arm:

1. A running primary loses dataplane verification.
2. Its scrub fails, so VIP/Kea may remain.
3. D5(c) makes it sender-silent ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:510)).
4. Silence creates peer staleness; timeout elects the peer Primary before optional fencing ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:910), [heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:404)).
5. The peer can activate VIP/Kea while the still-running old owner retains them.

Unlike crash restart, this staleness episode is caused by #5275 silencing a previously healthy sender. Therefore the D5 sign-off claim that #5275 never accelerates takeover into unscrubbed state is false for path (b).

The correction is to scope sender-silent failure fallback to crash restart. Live `fencing` must remain pre-hold and retain an incumbent-heartbeat/takeover interlock until scrub succeeds; only then atomically enter `effectiveHold`/`armFailed` and publish zero. Otherwise, silence requires a separately verified service/host fence.

The requested sections are also inconsistent: §12 still requires proved-down/service-fenced fallback and FRR removal before yield, whereas §3/D5(c) prescribe sender-silent timeout fallback and asynchronous FRR ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:390)). Additionally, §3’s “orderly shutdown scrubs” is overbroad: shutdown source does not stop Kea or clear persisted FRR ([daemon_run_shutdown.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_shutdown.go:124)).

VERDICT: PLAN-NEEDS-MAJOR
