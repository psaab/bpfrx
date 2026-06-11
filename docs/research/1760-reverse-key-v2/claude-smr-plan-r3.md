# Claude SMR hostile plan review — #1760 stage-2 revisit, round 3

**Verdict on v3→v4: PLAN-READY.**

Hostile checks performed on the round-3 inputs before accepting:

- **Codex r3's single finding** (scope the coverage claim; document the
  LocalMiss primary-tuple shadow separately) is correct and is the same
  surface my SMR r2 F1 flagged; v4 folds it into §2.3 with both reviewers'
  positions recorded (Codex: tuple-shadowing risk worth a note; AGY:
  disjoint in practice). The disagreement between them is about an
  out-of-scope adjacent observation, not about the plan's watch — both
  verdicts stand on the same §2.3 coverage map.
- **AGY r3's PLAN-READY** is quote-grounded this round (key.rs reverse-key
  shapes, upsert_synced immutability of `entry.key`/`nat`, promote key
  retention, cluster_peer_return_fast_path being is_reverse=true →
  reverse_translated_index). I verified its cluster_peer_return claim:
  poll_descriptor:479 installs `SessionOrigin::ReverseFlow` with
  `is_reverse: true` metadata — outside `nat_reverse_index`. Its W-lite
  preference (W5 not justified for diagnostic telemetry) matches Codex
  r3's "honesty does not require W5 in the same PR".
- **No reviewer regression**: round-3 verdicts rest on facts settled in
  rounds 1-2 (§1.7, §1.8); nothing in v4 reopens them.

Convergence state: AGY PLAN-READY (r3), Claude SMR PLAN-READY (this doc),
Codex PLAN-NEEDS-MINOR with its only finding applied in v4 — a
confirmation pass on the v4 diff is dispatched to close the loop.

The converged recommendation is the document itself: **W-lite
(W1+W2+W3′+W4) if a multi-host/production deployment is plausible; Path K
(close as accepted-risk) if the posture is lab-only.** Stage-2 structural
fix (A1/A2) stays shelved; its design-of-record now includes the
commit-order-inversion requirement.
