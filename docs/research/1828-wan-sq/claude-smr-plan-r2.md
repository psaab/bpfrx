# Claude SMR hostile plan review — round 2 (plan v2 @ 8ac561e05)

Verdict: **PLAN-READY.**

Delta verification of the v2 folds:

- **Codex r1 #1 (HIGH) resolved soundly.** The new §3 row (b) nuance and
  §6 D1 item 2 wording match the source: lazy promotion fires only on a
  second distinct flow (`queue_ops/push.rs:43-56`), and the
  "aggregate ECN is the correct signal for one flow" clause is the
  engine's own documented rationale (`cos/admission.rs:301-303`: "the
  aggregate IS the right signal — there's no per-flow isolation"). No
  overcorrection: the claim still correctly says fairness is
  zero-config *under contention*, which is the case SQM exists for.
- **Codex r1 #2 resolved** — per-egress budget caveat in both §3 row and
  D1 item 3; no global-download-root claim remains.
- **Codex r1 #3 = AGY r1 #4 resolved** — defaults unfrozen; the
  inherit-from-Phase-2 rule + cookbook guidance (target ≥1.5× post-shaper
  RTT, interval ≥ max(100 ms, baseline RTT)) quotes the in-tree contract
  (`types_cos.go:90-96`, `protocol/cos.rs:113-117`) verbatim in
  substance.
- **Codex r1 #4 resolved** — §8 invariant 5 now names the interval source
  as the single permitted engine-path delta; consistent with §6 D2's
  honest-accounting paragraph (no internal contradiction remains).
- **AGY r1 #3 resolved** — post-group-expansion evaluation is normative in
  the commit-check preamble AND pinned by a §10 test case (direct
  `smart-queueing` + apply-groups-inherited `scheduler-map` must error).
- **§12 resolutions block** faithful to both reviewers' round-1 answers;
  Q5/Q7 dispositions match what was actually said.

No new findings. The plan's recommendation (Option C primary now +
Option B rider gated on #1829 Phase 2 merging; A rejected; D fenced out)
stands unchallenged across all three reviewers.
