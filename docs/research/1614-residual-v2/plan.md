# #1614 residual §3.B — re-baseline + perturbative attribution (research v2)

- **Revision:** v2 (round 2 — Codex r1 minors folded; AGY r1 KILL points adjudicated with new measurements §2.7-§2.8 and code audit §4.1)
- **Date:** 2026-06-10
- **Branch:** `research/1614-residual-v2`
- **Mode:** /research — no production code; measurement evidence is the section of record (§2)
- **Measured target:** loss userspace cluster, master @ `aa6fa6fc8` (pinned: deployed this session to both nodes; in-band `show chassis cluster status` version checks), fixture `test/incus/cos-iperf-config.set` (shaping-rate 25g, `oversubscription-policy guarantee-rate 0.7`, equal-flow default-OFF)

## 1. Problem statement

#1614 stayed open for exactly one residual: **§3.B — guarantee-rate
small-first under-protecting mid classes.** On 2026-05-28 the decisive
cell (`small4 + 24g`, TCP, 12 streams/class) delivered 3g at **54%**
and 6g at **51%** of shape while 100m/1g were honored (94%) and the
aggregate (18.2 G) left several G of the ~22-24 G push ceiling `C_phys`
unused. All classes were Phase-1-admitted, so the relegation was inside
the serially-coupled lease→selector→drain stack. #1692 (passive
counters) was PLAN-KILLED — passive per-(class,worker) counters cannot
disambiguate those layers; the 2026-05-30 disposition mandated
**active/perturbative experiments** (open-loop UDP, controlled toggles)
before any mechanism.

This round re-baselines on current master first, because the fairness
engine changed substantially after the May-28 capture: **#1743**
(waterfill shaped-budget anchor + stable honor charge + time refresh,
merged 2026-06-01 as PR #1744, merge `a93bb22da`), #1745 (equal-flow,
default-OFF), #1763 (fused MQFQ dequeue), #1841 (V8 rotation scratch),
plus new instrumentation #1846 (sojourn/occupancy) and #1847
(`AcquireV8ShortfallCause` undergrant cause counters).

## 2. Measurement evidence (section of record)

All cells: loss cluster, push direction, client
`loss:cluster-userspace-host`, target 172.16.80.200, 12 streams/class,
30 s, `flock`-serialized, one cell at a time. Raw artifacts (iperf3
JSON + full before/after `/metrics` snapshots) under
`docs/research/1614-residual-v2/raw/`; runner archived alongside.
Achieved = `sum_received` (landed bytes). Metric validation: per-class
drain-byte counters (§2.5) independently reproduce the iperf3 numbers
within wire-overhead margin, in EVERY rep.

### 2.1 Solo per-class re-baseline (one class at a time, TCP)

| Class | Shape | Achieved | %shape | CoV | retr |
|-------|-------|----------|--------|-----|------|
| 100m | 0.1 G | 0.10 G | 95.2% | 0.3% | 0 |
| 1g | 1.0 G | 0.95 G | 95.3% | 0.0% | 0 |
| 3g | 3.0 G | 2.82 G | 94.0% | 1.7% | 0 |
| 6g | 6.0 G | 5.63 G | 93.8% | 1.1% | 0 |
| 9g | 9.0 G | 8.36 G | 92.9% | 1.4% | 0 |
| 12g | 12.0 G | 10.87 G | 90.6% | 5.4% | 0 |
| uncapped | — | **22.60 G** | — | 37.9% | 0 |

Solo health matches the historical 90-95% band. The solo-uncapped run
pins **today's `C_phys ≈ 22.6 G`** (same band as #1578/#1691; #1691
also recorded multi-class push aggregates of 21.6-24.96 G).

### 2.2 Decisive §3.B cell: `small4 + 24g` (TCP, **9 reps** on master)

Per-rep %-of-shape (r1-r9; ART dirs in raw/):

| Class | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | **mean [min-max]** | May-28 |
|-------|----|----|----|----|----|----|----|----|----|--------------------|--------|
| 100m | 94.1 | 93.8 | 93.6 | 94.8 | 94.2 | 94.7 | 94.6 | 94.0 | 94.1 | **94.2 [93.6-94.8]** | 94 |
| 1g | 90.5 | 86.0 | 91.0 | 88.6 | 90.2 | 88.4 | 88.2 | 84.8 | 88.2 | **88.4 [84.8-91.0]** | 94 |
| **3g** | 72.3 | 73.6 | 74.3 | 69.9 | 70.1 | 70.3 | 70.7 | 69.7 | 69.1 | **71.1 [69.1-74.3]** | **54** |
| **6g** | 71.0 | 71.1 | 69.2 | 70.5 | 68.6 | 69.0 | 66.2 | 72.6 | 72.1 | **70.0 [66.2-72.6]** | **51** |
| 24g | 49.5 | 48.1 | 49.8 | 50.2 | 47.9 | 51.0 | 49.6 | 48.1 | 47.6 | **49.1 [47.6-51.0]** | ~52 |

Aggregate 18.7-19.5 G across reps.

**Floor characterization** (vs `G_i = 0.7 × R_i`, the SSOT starvation
floor): 3g mean 71.1% — at/above the 70% floor in 6/9 reps, dips to
69.1% worst-case (98.7% of `G_i`); 6g mean 70.0% — at/above in 5/9,
dips to 66.2% worst-case (94.6% of `G_i`). The system **equilibrates AT
the floor** with a ±2-4 pt sampling band that straddles it; it is not
materially below guarantee in any rep, and the means sit on the floor.
Contrast May-28: 3g 77% of `G_i`, 6g 73% of `G_i` — 16-19 pts of shape
below floor, in every capture. The May-28 §3.B signature — 3g/6g level
with the unguaranteed-treatment 24g at ~52% — is gone: they now sit
20+ pts above 24g.

### 2.3 Control: small4 ALONE (TCP, 2 reps)

3g 91.5/87.5%, 6g 91.1/88.7% (sum 9.2/9.0 G) — near solo parity.
Comparing §2.2 vs §2.3: adding the single 24g competitor costs 3g/6g
**~16-19 pts** (≈ 0.5 G + 1.2 G) while costing 100m/1g almost nothing.
The residual phenomenon (§4) is competition-induced, not
4-way-concurrency physics.

### 2.4 The issue's matrix cell: all-6 simul (5201-5206, TCP, 2 reps)

| Class | Shape | G_i = 0.7×R | r1 | r2 |
|-------|-------|-----|-----|-----|
| 100m | 0.1 G | 0.07 G | 94.0% | 93.5% |
| 1g | 1.0 G | 0.70 G | 90.2% | 91.1% |
| 3g | 3.0 G | 2.10 G | 72.1% | 68.9% |
| 6g | 6.0 G | 4.20 G | 71.3% | 69.7% |
| 9g | 9.0 G | 6.30 G | 60.6% | 57.2% |
| 12g | 12.0 G | 8.40 G | 50.0% | 44.8% |
| **Sum** | 31.1 G | **21.77 G** | 18.89 G | 17.78 G |

`Σ G_k = 21.77 G ≥ achieved aggregate (17.8-18.9 G)`, and the achieved
aggregate is only a lower bound on `C_phys` — so SSOT starvation
condition 3 is **not conservatively provable** for this cell (Codex r1
m3 wording); the 9g/12g shortfall reads as divided-ceiling per
`docs/fairness-regimes.md`, not scheduler starvation. Ordering is
monotone small-first with no inversion: no class sits below the levels
of a LARGER class.

### 2.5 Phase/lease attribution counters (decisive cell, every rep)

Per-run `/metrics` deltas (RG0-primary node; CoS runtime location
verified per-cell via nonzero deltas):

- `waterfill_phase1_admissions_total`: q1-q4 (the four small classes)
  only — all Phase-1 admitted.
- `waterfill_phase2_admissions_total`: **q10 (24g) only**, and its
  count equals `phase1_budget_breaks_total` exactly (r2: 658,707 ==
  658,707) — 24g admits ONLY after the Phase-1 budget breaks. Compare
  the pre-#1743 A/B counter trace in §2.7.
- `drain_guarantee_sent_bytes_total` per queue independently confirms
  the iperf3 numbers (r2: q3 ≈ 8.69 GB ≈ 2.3 Gbps wire; q4 ≈ 16.8 GB
  ≈ 4.5 Gbps; q10 ≈ 45.4 GB ≈ 12.1 Gbps).
- #1847 undergrant causes: `share_exhausted` dominates (1.4-1.9 M/run;
  class_cap 13-20 K, seqlock_give_up 4-5 K, epoch_rotated ~0.6 K,
  cap_zero = outstanding_cap = 0) — the v8-lease per-epoch share is
  the binding constraint at saturation. Per-worker skew ~3-4× (r1:
  535 K vs 114 K) reflects RSS flow placement (counters are per-worker,
  not per-class — the #1692 kill rationale still applies to them).

### 2.6 Perturbative open-loop UDP (break TCP pacing collapse)

**All-UDP cell** (small4+24g, offered 110% of shape, 1400 B datagrams,
2 reps): 100m 95.7/93.6%, 1g 94.7/94.0%, **3g 88.1/85.5%** (loss
10-13% ≈ the over-offer shaped off). With inelastic demand the small
classes deliver AT or ABOVE their TCP numbers — no TCP-pacing-collapse
artifact is hiding starvation. **Invalid rows:** the 6g and 24g
senders could not source the offered load (iperf3 UDP at MTU 1500 caps
≈ 2.9 G per process; the 620x alternate-port servers are
version-incompatible, so demand cannot be split). Those rows measure
the generator and are excluded per
`feedback_runnable_repro_before_measurement_claim`. Note this cell
doubles as an aggressor-demand-removal perturbation: with 24g's demand
generator-capped at ~2.9 G, 3g rose to 85-88% — consistent with §2.3.

**Mixed probe cell** (6g as inelastic UDP at 2.76 G offered — 66% of
its `G_i` — vs elastic TCP competition from 100m/1g/3g/24g, 2 reps):
6g delivered **2.76 G at 0.00%/0.11% loss** while the 24g TCP
aggressor pulled 10.8/8.9 G. This is the saturated-aggressor inelastic
control AGY r1 asked for (its KP2b looked only at the all-UDP cell):
an inelastic mid-class stream below its guarantee is delivered
essentially lossless under maximum elastic pressure. Limitation: the
generator caps the probe at 66% of `G_i`, so this proves protection of
the band BELOW 2.76 G only; the floor region 2.76-4.2 G is covered by
the TCP reps (§2.2), not by an inelastic probe.

### 2.7 Bisect-grade A/B: pre-#1743 redeploy (same day, same fixture)

Deployed `e4556085a` (= master immediately before the #1743 merge
`a93bb22da`) to BOTH nodes; in-band software-version check printed
`...g e4556085a` immediately before AND after the cells; CoS fixture
re-applied and verified. Two decisive cells:

| Class | pre-#1743 r1 | pre-#1743 r2 | master mean (§2.2) | Δ (master − pre) |
|-------|------|------|------|------|
| 100m | 93.5% | 93.6% | 94.2% | +0.6 |
| 1g | 78.7% | 72.7% | 88.4% | **+12.7** |
| **3g** | **57.4%** | **60.3%** | **71.1%** | **+12.2** |
| **6g** | **61.2%** | **58.6%** | **70.0%** | **+10.1** |
| 24g | 57.1% (13.70 G) | 58.0% (13.91 G) | 49.1% (≈11.8 G) | −8.4 |

Counter trace on pre-#1743 (r1): q10 (24g) took **619,579 PHASE-1
admissions** — more than any small class — with **zero**
`phase2_admissions` and **zero** `phase1_budget_breaks`: exactly the
#1743 Hunk-A signature ("Phase 1 honored every class incl. the
largest; Phase 2 never fired") that the May-28 diagnosis observed as
`phase2_admit ≈ 0`. On master the same cell shows q10 admitted ONLY in
Phase 2 (§2.5).

This upgrades the heal attribution from correlational to
**A/B-proven**: same day, same cluster, same fixture, same harness —
the #1743 series boundary flips 3g/6g from 9-13 pts below the floor
(57-61%) to at-the-floor (70-71%), flips 1g +12.7 pts, removes 24g's
~2 G over-take, and flips the phase-counter regime. (The pre-#1743
absolute values are a few pts above the May-28 capture's 54/51% — two
different masters 3 days apart; the signature, not the exact level, is
the reproduced object.)

A first A/B attempt was invalidated by a shared-cluster collision (a
foreign build `g68a95b60b` was deployed over the A/B build mid-cell by
another agent not holding `/tmp/xpf-cluster.lock`, wiping CoS — the
cells showed 100m at 41× shape, i.e. unshaped). Those artifacts are
kept in raw/ marked `AB-pre1743-*` (invalid); the valid retry is
`AB2-pre1743-*` with in-band version checks inside one continuous lock
hold. Post-A/B the cluster was restored to the research branch build
(`5f95f7d33` = `aa6fa6fc8` + docs-only) + CoS, and a sanity cell
(`restore-sanity`) reproduced the master baseline (3g 69.8%, 6g 71.2%).

### 2.8 Noise discipline

Decisive cell: 9 reps on master, 2 on pre-#1743, 1 restore-sanity.
Run-to-run band ±2-4 pts; the A/B separation (10-13 pts) and the
May-28 recovery (17-19 pts) sit far outside it.

## 3. What healed the May-28 defect (A/B-proven)

The May-28 §3.B signature was: Phase-1-admitted small/mid classes
delivered ~52% — below even `0.7 × R_i` — level with the
unguaranteed-treatment class, with `phase2_admit ≈ 0`. **The #1743
series** (PR #1744, merge `a93bb22da`; main commit `2e6e0041f` plus
review-round commits `fcbdf1f04`/`b2fb8028b`/`14ac9b08e` — attribution
is to the series boundary, per Codex r1 m2) fixed three coupled
Phase-1 accounting defects that jointly produce exactly that
signature:

- **Hunk A** — the Phase-1 budget used `quantum_sum × fraction` (~4×
  what the root shaper delivers per epoch on this fixture: 1,855,753 B
  vs 437,500 B), so Phase 1 nominally honored EVERY class including
  24g and Phase 2 never fired — confirmed live by the §2.7 pre-#1743
  counter trace (q10 619 K Phase-1 admissions, 0 phase2, 0 breaks).
  Now anchored to `shaping_rate × visit_ns × fraction`.
- **Hunk B** — the honor charge was clamped to the depleted v8-lease
  token bank, collapsing to one frame under saturation: a queue was
  marked "fully honored" while consuming almost nothing, and Phase 2
  then **skipped** it (the #1732 persistent honored set made this
  sticky). "Honored on paper, starved on the wire, ineligible for
  residual."
- **Hunk C** — pass1 froze under saturation (Phase-2 selections do not
  decrement it, no time refresh), so small classes stopped being
  honored across epochs.

#1745/#1763/#1841 are fairness-adjacent but behavior-preserving
(equal-flow default-OFF in this fixture; fused dequeue proven
byte-identical; rotation scratch is allocation hygiene); the A/B
boundary test makes the series attribution direct evidence rather than
elimination reasoning.

## 4. The residual: honored-realization gap — readings and mechanism candidate

What remains is NOT the May-28 defect. Precise framing:

**Reading A — ratified SSOT starvation floor**
(`docs/fairness-regimes.md`: starved iff `actual_i < G_i = R_i ×
fraction` AND unguaranteed classes get bandwidth AND `Σ G_k <
C_phys`): 3g/6g means sit ON the floor (71.1% / 70.0% vs 70%); no rep
is materially below (worst 94.6% of `G_i`); and conditions 2-3 are not
satisfiable for this cell read strictly (all five classes are
guaranteed; `Σ G_k = 23.87 G > C_phys ≈ 22.6 G`). Two honesty notes:
(a) the SSOT's own worked application of the test to the May-28 cell
was loose on conditions 2-3 (it treated honored-last 24g as the
"unguaranteed" bandwidth recipient); (b) AGY r1 closed that loophole
by summing `G_k` over the small classes only (7.07 G) — not the SSOT
text, but a defensible strictness. Under EITHER application, the
present data shows floor-equilibrium with sampling dips ≤ 3.8 pts —
not the pre-#1743 systematic 9-13 pt deficit. Condition 1 is the
unambiguous discriminator and it now fails on the means.

**Reading B — design-intent full honor** (#1614 plan-v5 prediction
table: small classes whose cumulative `R_i` fits in `fraction × cap`
deliver **full shape**; the fraction scales the AGGREGATE Phase-1
budget — confirmed live by 100m/1g at 88-94% ≫ 70%): Phase-1 honors
3g/6g at full quantum (75/150 KB per 200 µs epoch ⇒ 3/6 Gbps nominal),
but they REALIZE only ~71/70% under aggressor pressure vs ~88-92% with
the aggressor absent (§2.3) — a **~16-19 pt realization gap** on
honored bytes, monotone in `R_i`.

### 4.1 Code-grounded mechanism candidate (adjudicating AGY r1 KP5)

AGY r1's code audit of `select_exact_cos_guarantee_queue_waterfill`
(`userspace-dp/src/afxdp/cos/queue_service/mod.rs`) claimed a "phantom
charge + lockout livelock" defect. Adjudication against the code:

- **Real (verified):** the Phase-1 charge is the STABLE quantum
  (`phase1_cost = cos_guarantee_quantum_bytes(queue).max(head_len)`,
  mod.rs:1048) while the actual per-visit send is token-clamped
  (`send_budget = queue.hot.tokens.min(visit_cap).max(head_len)`,
  mod.rs:1049-1053). A queue picked with a low token bank is marked
  honored (mod.rs:1078-1079) having been authorized to send far less
  than its quantum, and the honored bit excludes it from BOTH phases
  for the rest of the epoch (mod.rs:938, :1126-1133). So per epoch, an
  honored queue's service is bounded by its token bank at visit time —
  if the v8 lease under-fuels the bank, realized < honored. This is
  the leading candidate for the §2.3 gap, and it coheres with the
  #1847 `share_exhausted` dominance (§2.5): under competition the
  shared lease rations the token top-ups.
- **Wrong in AGY's account:** (a) "phantom charges prematurely deplete
  the Phase-1 budget" — false: `phase1_cost` is charged at the full
  quantum REGARDLESS of token state, so budget depletion is identical
  whether the queue sends 1 frame or its whole quantum; the depletion
  schedule is by design, not an error amplifier. (b) "the allocator
  switches early to Phase 2, enriching the aggressor" — Phase-2 entry
  happens when the next ascending quantum exceeds the remaining budget
  (mod.rs:1059-1068); on this fixture 24g's 600 KB quantum always
  breaks the 437.5 KB budget — entry timing is token-independent.
- **Design context AGY omitted:** charging actual-sent bytes is
  precisely the pre-#1743 Hunk-B bug (trivially-passed gate → marked
  honored → Phase-2 skip → `phase2_admit = 0`), proven harmful by the
  §2.7 A/B. Any fix for the realization gap must NOT regress that:
  candidates include carrying the unsent honor remainder within the
  epoch (re-eligibility with remaining quantum) or making the lease
  share guarantee-aware — mechanism design belongs to the follow-up,
  not this research round.

Whether the gap is RECOVERABLE is still unproven: lifting 3g/6g to
their small4-alone levels while 24g keeps ~11.9 G totals ≈ 21.1 G,
inside the 21.6-24.96 G multi-class aggregates #1691 recorded — but
`C_phys` for THIS 5-class shaped mix is not directly measurable
without an unshaped variant of the same mix. The follow-up inherits
exactly this question with a falsifiable program.

## 5. Disposition paths

- **Path 1 — CLOSE #1614 as healed-to-contract + file one scoped
  follow-up (recommended).** The §3.B defect as measured (below-floor
  starvation, Phase-2 never firing) is healed by the #1743 series —
  now A/B-PROVEN (§2.7) — and verified by 9-rep decisive cells, phase
  counters, and inelastic-demand perturbation. Per the ratified SSOT
  floor there is no starvation on master (floor-equilibrium, means on
  the floor). File ONE tightly-scoped follow-up for the §4 Reading-B
  residual, carrying: the §2 harness + cells as the regression
  baseline, the §4.1 mechanism candidate (honored-once-per-epoch ×
  token-clamped send × lease under-fueling) as hypothesis H1, the
  open "recoverable headroom vs mix-specific `C_phys`" question, and
  an explicit PLAN-KILL exit if an unshaped-mix ceiling measurement
  shows no recoverable headroom. Differentiation from killed #1692:
  ACTIVE program (competitor add/remove A/B, inelastic probes, build
  A/Bs — all demonstrated this round) PLUS a concrete code-located
  mechanism hypothesis — not passive counter interpretation.
  - **#1693 (placement, DEFERRED)**: recommend closing as overtaken —
    the May-28 §3.B cause is attributed to pre-#1743 Phase-1
    accounting, not placement; the per-worker share_exhausted skew
    observation is carried as context in the follow-up.
- **Path 2 — keep #1614 open for a Reading-B mechanism fix now.**
  Rejected: the residual is within the ratified floor contract, its
  recoverability is unproven (risk of #1211 fix-for-nonexistent-
  problem), and #1614 as umbrella carries too much dead scope to be a
  clean tracker for the narrow residual.
- **Path 3 — instrument gap.** Not needed for the close; the follow-up
  inherits the per-class lease-share observability question and can
  decide instrument-vs-measure there.
- **Path 4 — PLAN-KILL.** N/A — the mandated active-experiment program
  ran and produced a decisive disposition.

## 6. Blast radius

None — no production code changes. Deliverables: this doc, issue
comments, #1614 close + follow-up issue + #1693 disposition note, one
side-finding issue (§9.1).

## 7. Acceptance gates

For the close: the §2 tables are the gates (9-rep decisive cell at
floor-equilibrium, A/B regime flip, SSOT condition-1 negative on
means, phase counters consistent, inelastic probe lossless). Standing
regression guard: `cos-simul-load-smoke.sh` floors +
`cos-gate1-small-four-alone.sh` (both already on master; §2.3 shows
small4-alone ≥ 87.5%, above the gate floors).

## 8. Risks

- **Framing risk**: the dispatch heuristic said "3g/6g ≥ ~85% of shape
  under simul → healed". They sit at 69-74% of shape — but ON the
  ratified 70% floor, and the 85%-of-shape level IS met when the
  aggressor is absent (§2.3: 87-92%) and exceeded pre-floor under
  inelastic demand (§2.6: 3g 85-88%). Reviewers must adjudicate §4
  explicitly rather than pattern-match either number.
- **Floor-straddling optics**: ~40% of 30-s samples dip ≤3.8 pts below
  the floor. If the contract is read as per-sample-strict, the system
  is AT criterion, not above it. The follow-up's mechanism work is
  what would lift the margin; the close documents this explicitly
  rather than hiding it.
- **Single-fraction coverage**: all cells ran guarantee-rate 0.7 (the
  fixture default). #1743's unit tests cover allocator arithmetic at
  other fractions.
- **Shared-cluster contention**: one foreign deploy invalidated an A/B
  attempt mid-session (§2.7); all decisive results carry in-band
  version checks or counter-consistency validation.

## 9. Side findings (not §3.B)

1. **Locally-regenerated userspace-xdp shim fails the kernel-7.0
   verifier.** `make generate` rebuilds
   `pkg/dataplane/userspace_xdp_bpfel.o` with the local Rust nightly +
   bpf-linker; the object from the current local toolchain exceeds the
   1 M-insn verifier cap ("BPF program is too large. Processed 1000001
   insn") on BOTH cluster kernels (7.0.0, 7.0.0-rc7+), putting xpfd
   into config-only mode — this took both nodes' dataplanes down
   during this session until the git-tracked `.o` (md5
   `58405bd24c69…`) was restored and redeployed. The tracked object
   loads fine; `userspace-xdp/` source is unchanged since #1432, so
   this is toolchain-version sensitivity. Follow-up issue to be filed
   at disposition: pin `RUST_BPF_TOOLCHAIN`/bpf-linker versions + add
   a load-time verifier guard before any regenerated artifact lands.
2. **620x alternate-port iperf servers are version-incompatible** with
   the client iperf3 ("received an unknown control message"), blocking
   multi-process per-class UDP demand (caps inelastic offered load at
   ~2.9 G/class at MTU 1500). Worth a test-env fix if open-loop work
   needs more.
3. **Shared-cluster lock discipline**: a deploy bypassing
   `/tmp/xpf-cluster.lock` clobbered a measurement cell (§2.7). The
   serialized-smoke rule exists; deploys from other agents should
   honor the same lock.

## 10. Test/repro plan

Executed (§2). Re-runnable: deploy target build → `apply-cos-config.sh`
→ `run-cell.sh` (archived alongside this doc) for `solo-*`,
`small4p24g-r{1..9}`, `small4-alone-r{1,2}`, `all6-r{1,2}`,
`small4p24g-udp-r{1,2}`, `mix-6gudp-r{1,2}`, `AB2-pre1743-r{1,2}`,
`restore-sanity`.

## 11. Reviewer questions (round 2)

1. Reading A as the close basis, with the §8 floor-straddling
   disclosure: ratify or reject (and if reject, name the superseding
   contract text).
2. A/B attribution (§2.7): now bisect-grade at the series boundary —
   any remaining attribution objection?
3. §4.1 adjudication of the KP5 mechanism: agree the once-per-epoch +
   token-clamp + lease-rationing chain is hypothesis-grade (follow-up
   H1), and that "phantom budget depletion / early Phase-2 switch" is
   refuted as stated?
4. Any objection to closing #1693 as overtaken?
5. Is the follow-up sufficiently differentiated from killed #1692
   (active program + code-located hypothesis + KILL exit)?
