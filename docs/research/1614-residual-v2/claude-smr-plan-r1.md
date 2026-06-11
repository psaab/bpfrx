# Claude SMR hostile plan-review — #1614 residual v2, round 1

Reviewer stance: domain SMR (CoS scheduling semantics), CPU/arch, SW
design. Hostile by charter — the burden is on the plan to survive.

## Worked adversarial checks performed

1. **Self-refutation of the plan's own first draft.** The v1 draft as
   initially written adjudicated healed purely on `G_i = 0.7 × R_i`
   ("3g at 103% of guarantee → healed"). I attacked it with the
   plan-v5 prediction table (small classes "full" under guarantee-rate
   0.7) and the live observation that 100m/1g deliver 90-94% ≫ 70% —
   proving `fraction` scales the AGGREGATE Phase-1 budget, not a
   per-class clamp. The per-class-0.7 reading alone was WRONG as a
   sole basis. This forced the `small4-alone` control cell (§2.3) and
   the dual-reading §4 now in the doc. The current revision carries
   both readings honestly; the close rests on Reading A being the
   RATIFIED contract (`docs/fairness-regimes.md` starvation test) while
   Reading B's residual is surfaced with numbers, not buried. PASS,
   with the explicit caveat that reviewers Q1 must ratify that choice.

2. **Is the SSOT starvation test even applicable to the decisive
   cell?** Hostile reading of condition 2 ("unguaranteed classes ARE
   getting bandwidth"): in `small4+24g` ALL five classes are exact
   (guaranteed); strictly there are no unguaranteed classes, so even
   the May-28 capture fails condition 2 read literally — yet the SSOT
   itself asserts the May-28 cell "satisfies all three" (it treats the
   honored-last 24g as the unguaranteed-treatment class). The SSOT
   text is internally loose here. This does NOT rescue a starvation
   claim today (condition 1 independently fails), but the plan should
   not over-lean on a 3-condition test whose own author applied it
   loosely. The §4 framing survives because it uses condition 1
   (below-`G_i`), which is unambiguous. PASS with note.

3. **Noise-band check on "6g ≥ G_i".** 6g r3 = 4.15 G vs G_i =
   4.20 G — 98.8%, i.e. condition 1 is TECHNICALLY true in 1 of 3
   reps. The plan calls this "within the ±2 pt band". Verified: 3-rep
   spread 69.2-71.1% (±1 pt around 70.4%); May-28 was 51% — 19 pts
   away. The 0.8-pt dip is an order of magnitude inside the historical
   defect and inside run-to-run noise. Accepting "at guarantee" is
   sound; a literalist could demand more reps. NON-BLOCKING.

4. **Could the healed numbers be a measurement artifact?**
   (feedback_runnable_repro_before_measurement_claim): metric
   validated against independent drain-byte counters (§2.5) — q3/q4
   drain deltas reproduce iperf3 within wire overhead; CoS fixture
   verified live post-apply (apply script asserts shaper binding);
   3 reps tight. The May-28 comparison is apples-to-apples (same
   fixture file, same client/target, same 12×30 s, same direction).
   One real difference: master deployed fresh this session vs whatever
   ambient state existed May-28 — but the prior research also ran on
   freshly-pinned masters. PASS.

5. **Attribution rigor.** #1743's three hunks are the only merged
   change whose mechanism PREDICTS (a) below-`G_i` delivery while
   "honored", (b) `phase2_admit = 0` in May vs phase2 == budget_breaks
   now, and (c) recovery without per-flow placement changes. #1745 is
   default-OFF (verified in fixture — no COS_EQUAL_FLOW), #1763 shipped
   with a byte-identical differential proof, #1841 is
   allocation-hygiene. Residual risk: some OTHER merged change between
   May-28 and now (e.g. #1782 neighbor work, #1829 sojourn) could
   contribute; none touches the waterfill/lease split. The plan
   correctly downgrades attribution to "correlational, A/B optional"
   (Q2). I judge the A/B NOT required for a close-healed disposition —
   the close stands on "does not reproduce on master" regardless of
   WHICH commit healed it; attribution is explanatory color. PASS.

6. **Does the residual (Reading B) deserve to block the close?**
   Steel-manning keep-open: the gap is 16-19 pts on 3g/6g, the
   original §3.B text said "under-protecting mid classes", and one
   could argue the residual IS §3.B at reduced magnitude. Against:
   (a) the §3.B defect was DEFINED by its measured signature
   (below-`G_i`, ~52%, level with unguaranteed treatment, phase2
   dead) — that signature is gone; (b) the residual's recoverability
   is unproven (mix-specific `C_phys` unknown — the plan is honest
   that 21.1 G feasibility is extrapolated from other mixes); (c)
   keeping a 2-month umbrella open for a possibly-physical 16-pt gap
   invites exactly the #1211 failure mode. The scoped-follow-up
   compromise is the engineering-correct disposition PROVIDED the
   follow-up files with the KILL exit included. PASS conditional on
   that.

7. **#1693 close recommendation.** Checked: #1693 was deferred
   "pending causal attribution" — attribution landed on Phase-1
   accounting (#1743), not placement. The per-worker share_exhausted
   skew (3-4×) is placement-adjacent evidence but harms no guarantee
   today. Closing #1693 as overtaken while the follow-up carries the
   skew observation is clean. PASS.

8. **Side-finding 1 (shim verifier) scope check.** It is real (both
   nodes config-only; restored-`.o` redeploy fixed it), reproducible,
   and NOT CoS — correctly quarantined as a side issue, and it MUST be
   filed (a `make generate` on any dev box currently produces a
   cluster-killing artifact). The plan recommends filing; I require it
   as part of the disposition actions, not optional. UPGRADED to
   required.

## Findings

- **F1 (resolved in current revision)**: sole-Reading-A adjudication —
  self-caught, control cell added, §4 rewritten. Verify reviewers see
  the dual framing (they do — Q1).
- **F2 (required action)**: file the shim-toolchain side issue at
  disposition time (see check 8).
- **F3 (note)**: SSOT condition-2 looseness (check 2) — recommend the
  follow-up issue (or the close comment) quote condition 1 only.
- **F4 (non-blocking)**: 6g r3 98.8%-of-G literalism (check 3) —
  covered by noise band; no action.

## Verdict

**PLAN-READY** (round 1) — conditional on: Path 1 disposition includes
(a) the follow-up issue with explicit PLAN-KILL exit, (b) the shim
side issue actually filed, (c) Q1 ratified by both external reviewers
(if either insists Reading B blocks the close, iterate — do not
override 2-1).
