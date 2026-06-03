# Claude SMR r1 — #1752 remaining-paths plan (v1→v2)

**My v1 was wrong on 3 of 4 paths; AGY + live verification corrected them.**
This is the SMR-soft-pass failure mode the methodology guards against — I framed
B as a clean KILL, C as operator-only, E-followup as defer, all without enough
evidence. Recording it.

- **Path B:** v1 claimed KILL (inherent driver, no lever). Codex: don't overclaim
  / re-symbolize first. AGY: it's the TX-wake sendto path, recoverable. Verified:
  crypto DEK kprobe = 0 calls (artifact confirmed) BUT xsk_sendmsg ~110K/s +
  sendto ~108K/s + mlx5e_xsk_wakeup ~15.5K/s — a real, software-recoverable cost.
  v2 re-scopes B (not kill). **Lesson: "inherent driver cost" was an assumption,
  not a measurement; the kprobe both killed the crypto claim AND found the real
  cost.**
- **Path C:** v1 said "no code lever, operator only." AGY: workers are already
  pinned (verified neighbor.rs:737); pin Go to core 0. v2 re-scopes C to a real
  tradeoff A/B.
- **Path E-followup:** v1 defer; AGY's correctness argument (re-assert
  structurally necessary under transient port reuse) → v2 KILL. Sound.
- **Path A:** v1 defer-to-own-research stands; v2 enriches with AGY's verified
  sub-levers. Correct.

**Verdict on v2: PLAN-READY-pending-Codex/AGY-r2.** v2's honesty bar is right:
B and C are re-scoped as *research with explicit no-net-win KILL exits* (latency
tradeoff for B, lost-worker-core tradeoff for C), not promised wins. The only
thing I'd still flag: don't let B's re-scope over-promise — Open-Q 1/2 must be
answered (what fraction of the bucket is the wake path; is 50µs already optimal)
in B's own research before any code. v2 states this.
