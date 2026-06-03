# Claude SMR r2 — #1752 plan v3 @ decbf7a91

**Verdict: PLAN-READY.**

v3 closes every r1 blocking finding from Codex + AGY:
- Path B safety: ALL HA-node strongSwan/xfrm experiments removed; non-invasive
  stack trace only; config A/B standalone-VM-only and discouraged. (Codex#1,
  AGY safety Q resolved.)
- Crypto DEK causality: Finding 3 now states the mechanism is unproven, the DEK
  pool is generic mlx5 machinery used by kTLS AND IPsec offload, and the trace
  precedes any config theory. (Codex#2 resolved.)
- CoS value claim: anchored on ~19% CPU; 7.4 Gb/s explicitly gross sender thpt,
  goodput TBD, with the "crypto present != constant across packet rates" caveat.
  (Codex#3 resolved.)
- Driver RX: "No (inherent)" -> "Partly" with the concrete lever list. (Codex#4
  resolved.)
- Path A: gated to a sub-profile + concrete sub-cost + no-code-kill exit.
  (Codex#5 resolved.)
- AGY's session-churn finding is now Path E, code-verified
  (update_session:803 remove_entry+restore_entry per packet), with a
  differential-test gate and an index-update-only-on-change design note.

Recommended outcome: pursue **Path E (session in-place mutation, ~4.5%, lowest
risk) as the first /engineer**, with **Path B (non-invasive crypto trace)** in
parallel as diagnostics. Defer Path A behind its own gated /research; C/D are
operator/doc decisions. This is the honest, lowest-risk ordering and it does not
overclaim the CoS Gb/s prize.

Pending Codex + AGY r2 concurrence to declare convergence.
