# Codex hostile plan-review r11 (#5275) — VERDICT: PLAN-NEEDS-MINOR (no safety defect remains; 2 wording fixes)

Reviewed plan.md @ r12. Final synthesis (file-read dumps stripped):


[2m2026-07-23T08:58:04.163858Z[0m [31mERROR[0m [2mcodex_core::tools::router[0m[2m:[0m [3merror[0m[2m=[0mtimeout_ms must be at least 10000
[35m[3mcodex[0m[0m
The hostile stress test converged on the same result from three independent angles: the mechanism is safe, and the cited shutdown/election premises are accurate. I did find one stale r11 sentence in the D5 human-sign-off summary—and one adjacent “pre-hold” terminology slip—that prevent a clean ready verdict even though neither requires redesign.
[3mSafety and source audits agree: the path-specific mechanism closes the live dual-ownership defect and preserves only the accepted crash timeout tradeoff. Two localized wording contradictions remain in §13-D5, so the calibrated result is PLAN-NEEDS-MINOR.[0m
  [32m✓[0m Read r12 sections, citations, and prior review conclusions
  [32m✓[0m Verify relevant source claims firsthand
  [32m✓[0m Stress-test live re-arm and crash-restart state transitions
  [32m✓[0m Check §3/§12/§13-D5 consistency and issue final verdict
[35m[3mcodex[0m[0m
r12 closes the round-10 safety defect. The live path preserves heartbeat/takeover interlock until verified scrub success, while the barrier blackholes transit; the crash path retains only the accepted pre-existing timeout window. Source also confirms the §3 shutdown correction.

Two localized wording defects remain:

- [D5 human sign-off](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:541) still universally says a failed scrub becomes sender-silent, contradicting the live-path rule. Path-scope that sentence.
- [D5(c)](/home/ps/git/bpfrx/.claude/worktrees/5275-arm-failclosed/plan.md:528) calls live fencing “pre-hold,” then says “holds-but-cannot-scrub.” Replace that with “remains in fencing/pre-hold with the scrub incomplete.”

These require no redesign. I found no remaining genuine safety defect or false source claim, and the dead-node timeout-versus-STONITH tradeoff is correctly left for human sign-off.

VERDICT: PLAN-NEEDS-MINOR
[2mtokens used[0m
168,878
r12 closes the round-10 safety defect. The live path preserves heartbeat/takeover interlock until verified scrub success, while the barrier blackholes transit; the crash path retains only the accepted pre-existing timeout window. Source also confirms the §3 shutdown correction.

Two localized wording defects remain:

- [D5 human sign-off](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:541) still universally says a failed scrub becomes sender-silent, contradicting the live-path rule. Path-scope that sentence.
- [D5(c)](/home/ps/git/bpfrx/.claude/worktrees/5275-arm-failclosed/plan.md:528) calls live fencing “pre-hold,” then says “holds-but-cannot-scrub.” Replace that with “remains in fencing/pre-hold with the scrub incomplete.”

These require no redesign. I found no remaining genuine safety defect or false source claim, and the dead-node timeout-versus-STONITH tradeoff is correctly left for human sign-off.

VERDICT: PLAN-NEEDS-MINOR
