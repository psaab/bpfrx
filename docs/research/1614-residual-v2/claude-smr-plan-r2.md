# Claude SMR hostile plan-review — #1614 residual v2, round 2 (plan v2)

Stance unchanged: hostile domain SMR. Round 2 adjudicates the r1
3-way split (SMR PLAN-READY-conditional / Codex PLAN-NEEDS-MINOR /
AGY PLAN-KILL) against the NEW evidence gathered for v2.

## Adjudication of the r1 split

### AGY KP1 (6g r3 below floor → starvation)
Substance partially upheld, conclusion rejected. The 9-rep extension
(§2.2) confirms the substance: 6g mean 70.03% sits exactly ON the
floor and ~4/9 samples dip below (worst 66.2% = 94.6% of `G_i`). But
AGY's formal starvation claim required misapplying the SSOT: it summed
`Σ G_k` over the small classes only (7.07 G), excluding 24g's 16.8 G
guarantee — the SSOT text says "over the *guaranteed* classes" and 24g
is exact/guaranteed, so condition 3 strictly FAILS
(23.87 G > C_phys ≈ 22.6 G); condition 2 also has no satisfying class
(no unguaranteed class is in the cell). I verified the SSOT's own
worked example applies the test just as loosely — the plan now
discloses BOTH applications (§4 honesty notes) and rests on the
unambiguous condition 1 evaluated on means, plus the explicit §8
floor-straddling risk disclosure. That is the defensible adjudication.

### AGY KP2a (rep count)
Upheld and RESOLVED: 9 reps on the decisive cell; means/extrema
reported; conclusions sit 10-19 pts outside the ±2-4 pt band.

### AGY KP2b (UDP control invalid — no saturated aggressor)
REFUTED as stated: AGY analyzed only the all-UDP cell and missed the
mixed probe cell (§2.6), where the 24g TCP aggressor pulled 10.8/8.9 G
— saturated elastic pressure — while the inelastic 6g probe was
delivered at 0.00%/0.11% loss. Codex r1 independently verified this
from the raw JSON. The plan now states the real limitation precisely
(probe covers only the band below 2.76 G).

### AGY KP3 (attribution requires A/B)
Upheld and RESOLVED: §2.7 bisect-grade A/B at the series boundary
(`e4556085a` vs master), in-band version checks before/after each
cell, one continuous lock hold. Result: 3g 57.4/60.3% and 6g
61.2/58.6% pre-#1743 vs 71.1/70.0% master means; 24g over-take +2 G
pre; phase-counter regime flip (q10: 619 K Phase-1 admissions, 0
phase2, 0 breaks pre-#1743 vs Phase-2-only on master). I checked the
counter trace myself in raw/AB2-pre1743-r1-*/: the Hunk-A signature is
unmistakable. Attribution is no longer correlational. Codex r1 m2
(series-not-single-commit wording) folded — attribution is to the
#1744 merge boundary.

### AGY KP4 (follow-up = #1692 redux)
REJECTED with the v2 strengthening: the follow-up now carries a
code-located mechanism hypothesis (§4.1) + a demonstrated ACTIVE
toolkit (competitor add/remove, inelastic probes, build A/B) + a KILL
exit. #1692 was killed for passive-counter undecidability; none of the
follow-up's program is passive-counter inference.

### AGY KP5 (phantom charge + lockout livelock)
Split verdict, verified line-by-line against
`userspace-dp/src/afxdp/cos/queue_service/mod.rs`:
- REAL: stable-quantum charge (:1048) vs token-clamped send
  (:1049-1053); once-per-epoch honored-bit exclusion from both phases
  (:938, :1078-1079, :1126-1133). The realized-service-bounded-by-
  token-bank-at-visit mechanism is genuine and is now follow-up H1.
- REFUTED: "phantom charges prematurely deplete the budget" — the
  charge is token-independent, so depletion is identical in all token
  states (by design); "early Phase-2 switch enriches the aggressor" —
  Phase-2 entry is determined by the next ascending quantum vs
  remaining budget (:1059-1068), token-independent; on this fixture
  24g ALWAYS breaks the budget.
- REJECTED as round-action: AGY's demanded fix ("charge only actual
  bytes sent") is literally the pre-#1743 Hunk-B bug the §2.7 A/B
  proves harmful. A safe fix needs design work (epoch-remainder
  re-eligibility or guarantee-aware lease shares) — follow-up scope.

### Codex r1 m1/m3 (wording over-claims)
Folded: §2.2 "not materially below guarantee" framing + per-rep floor
table; §2.4 condition-3 "not conservatively provable".

## Fresh hostile checks on v2

1. **A/B confound — was the pre-#1743 deploy actually exercised by the
   counters?** Verified: AB2 r1 delta shows waterfill_epochs +812 K
   and q1-q4,q10 phase1 admissions with NO undergrant metric names
   (those counters post-date the build) — consistent with the old
   build, inconsistent with a stale-new-build artifact. Version string
   checked before AND after each cell. PASS.
2. **Could the foreign-deploy collision have contaminated the master
   9-rep set?** r1-r3 ran before any foreign deploy (counters from the
   pinned build); r4-r9 counter snapshots show the #1847 metric set +
   shaped waterfill activity and are statistically indistinguishable
   from r1-r3 (3g 69.1-74.3 across all nine); the foreign build
   `g68a95b60b` was observed ONLY after r9, and the restore-sanity
   cell on the re-pinned build reproduces the same numbers (3g 69.8,
   6g 71.2). Contamination would have to leave the distribution
   unchanged to hide — not credible. PASS.
3. **Is "close + follow-up" disposition-shopping?** The follow-up is
   not a softer #1614: it has a narrower claim (realization gap above
   the floor), a concrete hypothesis, a KILL exit, and a regression
   baseline. Keeping #1614 open instead would retain an umbrella whose
   defining measurement no longer reproduces. PASS.
4. **Side-finding 2 escalation check**: the shim-verifier landmine is
   a REQUIRED filing at disposition (unchanged from r1 F2).

## Verdict

**PLAN-READY** (round 2) — the disposition (Path 1: close #1614
healed-to-contract with floor-straddling disclosed; file scoped
follow-up with H1 + KILL exit; close #1693 overtaken; file shim
side-issue) is evidence-complete. Convergence requires Codex
ratification of v2 and an AGY round-2 verdict; if AGY re-KILLs, its
findings must again be adjudicated on quoted evidence, not deferred
to.
