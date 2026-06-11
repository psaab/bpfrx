# #1614 residual §3.B — re-baseline + perturbative attribution (research v2)

- **Revision:** v1 (round 1)
- **Date:** 2026-06-10
- **Branch:** `research/1614-residual-v2`
- **Mode:** /research — no production code; measurement evidence is the section of record (§2)
- **Measured target:** loss userspace cluster, master @ `aa6fa6fc8` (pinned: deployed this session to both nodes; `show chassis cluster status` software version `...gaa6fa6fc8`), fixture `test/incus/cos-iperf-config.set` (shaping-rate 25g, `oversubscription-policy guarantee-rate 0.7`, equal-flow default-OFF)

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
(waterfill shaped-budget anchor + stable honor charge + time refresh),
#1745 (equal-flow, default-OFF), #1763 (fused MQFQ dequeue), #1841 (V8
rotation scratch), plus new instrumentation #1846 (sojourn/occupancy)
and #1847 (`AcquireV8ShortfallCause` undergrant cause counters).

## 2. Measurement evidence (section of record)

All cells: loss cluster, push direction, client
`loss:cluster-userspace-host`, target 172.16.80.200, 12 streams/class,
30 s, `flock`-serialized, one cell at a time. Raw artifacts (iperf3
JSON + full before/after `/metrics` snapshots) under
`/tmp/xpf1614/cells/` on the driving host; runner archived at
`docs/research/1614-residual-v2/run-cell.sh`. Achieved =
`sum_received` (landed bytes). Metric validation: per-class
drain-byte counters (§2.5) independently reproduce the iperf3 numbers
within wire-overhead margin.

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

### 2.2 Decisive §3.B cell: `small4 + 24g` (TCP, 3 reps)

| Class | Shape | r1 | r2 | r3 | May-28 | small4-ALONE (§2.3) |
|-------|-------|-----|-----|-----|--------|---------------------|
| 100m | 0.1 G | 94.1% | 93.8% | 93.6% | 94% | 94.3 / 95.0% |
| 1g | 1.0 G | 90.5% | 86.0% | 91.0% | 94% | 89.9 / 91.5% |
| **3g** | 3.0 G | **72.3%** | **73.6%** | **74.3%** | **54%** | **91.5 / 87.5%** |
| **6g** | 6.0 G | **71.0%** | **71.1%** | **69.2%** | **51%** | **91.1 / 88.7%** |
| 24g | 24.0 G | 49.5% | 48.1% | 49.8% | ~52% | — |
| **Sum** | 34.1 G | 19.30 G | 18.98 G | 19.34 G | 18.2 G | 9.20 / 8.96 G |

Run-to-run band ±2 pts. The May-28 signature — **3g/6g level with the
unguaranteed-treatment 24g at ~52%** — is gone: 3g/6g now sit 20+ pts
above 24g and 18-23 pts above their May-28 values.

### 2.3 Control: small4 ALONE (TCP, 2 reps)

3g 91.5/87.5%, 6g 91.1/88.7% (sum 9.2/9.0 G) — near solo parity.
Comparing §2.2 vs §2.3: adding the single 24g competitor costs 3g/6g
**~16-19 pts** (≈ 0.5 G + 1.2 G) while costing 100m/1g ≈ nothing.
This isolates the residual phenomenon (§4): the reduction is
competition-induced, not 4-way-concurrency physics.

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

`Σ G_k = 21.77 G ≥ achieved aggregate` → SSOT starvation condition 3
fails → the 9g/12g shortfall is divided-ceiling physics per
`docs/fairness-regimes.md`. Ordering is monotone small-first with no
inversion: no class sits below the levels of a LARGER class.

### 2.5 Phase/lease attribution counters (decisive cell, every rep)

Per-run `/metrics` deltas (fw0):

- `waterfill_phase1_admissions_total`: q1-q4 (the four small classes)
  only — all Phase-1 admitted.
- `waterfill_phase2_admissions_total`: **q10 (24g) only**, and its
  count equals `phase1_budget_breaks_total` exactly (r2: 658,707 ==
  658,707) — 24g admits ONLY after the Phase-1 budget breaks. This
  textbook small-first trace was impossible in the May-28 captures
  (`phase2_admit ≈ 0` — Phase 2 never fired; see §3).
- `drain_guarantee_sent_bytes_total` per queue independently confirms
  the iperf3 numbers (r2: q3 ≈ 8.69 GB ≈ 2.3 Gbps wire; q4 ≈ 16.8 GB
  ≈ 4.5 Gbps; q10 ≈ 45.4 GB ≈ 12.1 Gbps).
- #1847 undergrant causes: `share_exhausted` dominates (1.4-1.9 M/run;
  class_cap 13-15 K, seqlock_give_up 4-5 K, epoch_rotated ~0.6 K,
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
`feedback_runnable_repro_before_measurement_claim`.

**Mixed probe cell** (6g as inelastic UDP at 2.76 G offered — 66% of
its G_i — vs elastic TCP competition from 100m/1g/3g/24g, 2 reps): 6g
delivered **2.76 G at 0.00%/0.11% loss** while the 24g TCP aggressor
pulled 10.8/8.9 G. An inelastic mid-class stream below its guarantee
is delivered essentially lossless under maximum elastic pressure.
(Aggregate fell to 16.5/14.5 G — the no-GRO 1400 B UDP component
lowers the mix's delivery ceiling; expected.)

Note also the all-UDP cell doubles as an aggressor-demand-removal
perturbation: with 24g's demand generator-capped at ~2.9 G, 3g rose to
85-88% — consistent with §2.3's finding that 24g's elastic demand is
what pushes 3g/6g down to ~72/70%.

## 3. What healed the May-28 defect

The May-28 §3.B signature was: Phase-1-admitted small/mid classes
delivered ~52% — **below even `0.7 × R_i`**, level with the class
receiving unguaranteed treatment, with `phase2_admit ≈ 0`. **#1743**
(merged 2026-06-03, commit `2e6e0041f`, "anchor CoS waterfill Phase-1
budget to shaped cap + stable honor charge + time refresh") fixed
three coupled Phase-1 accounting defects that jointly produce exactly
that signature:

- **Hunk A** — the Phase-1 budget used `quantum_sum × fraction` (~4×
  what the root shaper can deliver per epoch on this fixture:
  1,855,753 B vs 437,500 B), so Phase 1 nominally honored EVERY class
  including 24g and Phase 2 never fired — matching the May-28
  `phase2_admit ≈ 0` observation. Now anchored to
  `shaping_rate × visit_ns × fraction` (the documented fraction×cap
  contract).
- **Hunk B** — the honor charge was clamped to the depleted v8-lease
  token bank, collapsing to one frame under saturation: a queue was
  marked "fully honored" while consuming almost nothing, and Phase 2
  then **skipped** it (the #1732 persistent honored set made this
  sticky). That is the precise mechanism for "honored on paper,
  starved on the wire, ineligible for residual".
- **Hunk C** — pass1 froze under saturation (Phase-2 selections do not
  decrement it, no time refresh), so small classes stopped being
  honored across epochs.

The §2.5 counter trace shows the post-#1743 regime (smalls Phase-1,
24g exclusively Phase-2-after-budget-break) that none of the May-28
captures could produce. #1745/#1763/#1841 are fairness-adjacent but
behavior-preserving (equal-flow default-OFF; fused dequeue proven
byte-identical; rotation scratch is allocation hygiene), so #1743 is
the attribution. An optional bisect-grade A/B (deploy the pre-#1743
master commit and re-run §2.2 once) would make this airtight at ~1 h
cluster cost — reviewer question Q2.

## 4. The residual: honored-realization gap — and the two contract readings

What remains is NOT the May-28 defect. It needs precise framing
because two contract readings adjudicate it differently:

**Reading A — ratified SSOT starvation test**
(`docs/fairness-regimes.md`: starved iff `actual_i < G_i = R_i ×
fraction` AND unguaranteed classes get bandwidth AND `Σ G_k <
C_phys`): 3g delivers 103-106% of `G_i` and 6g 99-102% across reps —
condition 1 fails → **not starved, within contract**.

**Reading B — design-intent full honor** (the #1614 plan-v5 prediction
table says small classes whose cumulative `R_i` fits in `fraction ×
cap` get **full shape** — "3g → 3.0 G (full), 6g → 6.0 G (full)"; the
fraction scales the AGGREGATE Phase-1 budget, not a per-class clamp —
confirmed live by 100m/1g delivering 90-94% ≫ 70%): Phase-1 honors
3g/6g at full quantum (75/150 KB per 200 µs epoch ⇒ 3/6 Gbps
nominal), but they REALIZE only ~72/70% of shape under aggressor
pressure vs ~88-92% with the aggressor absent (§2.3) — a **~16-19 pt
realization gap** on honored bytes, monotone in `R_i` (100m −0.5 pt,
1g −1 pt, 3g −16 pts, 6g −19 pts vs small4-alone).

Arithmetic feasibility of closing the gap is plausible but NOT proven:
lifting 3g/6g to their small4-alone levels while 24g keeps ~11.9 G
totals ≈ 21.1 G, inside the 21.6-24.96 G multi-class aggregates #1691
recorded — but `C_phys` for THIS specific 5-class shaped mix is not
directly measurable without an unshaped variant of the same mix, so
"recoverable headroom" remains a hypothesis, not a fact. The #1847
`share_exhausted` dominance (§2.5) says the v8-lease epoch share is
where service is rationed; per-worker (not per-class) resolution means
the lease-layer split between honored-class and Phase-2-class service
is still not directly observable — the same observability wall that
killed #1692, now one layer narrower.

Magnitude check against the May-28 baseline: the gap below
small4-alone parity shrank from ~37 pts (54% vs ~91%) to ~17 pts, and
the defect-defining "below `G_i`" component went to zero.

## 5. Disposition paths

- **Path 1 — CLOSE #1614 as healed-to-contract + file one scoped
  follow-up (recommended).** The §3.B defect as measured (below-`G_i`
  starvation, Phase-2 never firing) is healed by #1743 and verified by
  3-rep decisive cells, phase counters, and inelastic-demand
  perturbation. Per the ratified SSOT contract there is no starvation
  on master. File ONE tightly-scoped follow-up for the §4 Reading-B
  residual ("Phase-1-honored mid classes realize ~80% of honored bytes
  under Phase-2 aggressor pressure; ~16-19 pts vs aggressor-absent"),
  carrying: the §2 harness + cells as the regression baseline, the
  open question "is the gap recoverable headroom or mix-specific
  `C_phys`", and an explicit PLAN-KILL exit if an unshaped-mix ceiling
  measurement shows no recoverable headroom. This dodges the #1692
  kill rationale: the follow-up's program is ACTIVE
  (competitor add/remove A/B, inelastic probes — demonstrated this
  round), not passive counters.
  - **#1693 (placement, DEFERRED)**: recommend closing as overtaken —
    the May-28 §3.B cause is attributed to #1743's Phase-1 accounting,
    not placement; the per-worker share_exhausted skew observation can
    be carried as context in the follow-up instead.
- **Path 2 — keep #1614 open for a Reading-B mechanism fix now.**
  Rejected: the residual is within the ratified contract, its
  recoverability is unproven (risk of #1211 fix-for-nonexistent-
  problem), and #1614 as umbrella carries too much dead scope to be a
  clean tracker for the narrow residual.
- **Path 3 — instrument gap.** Not needed for the close; the follow-up
  issue inherits the open observability question (per-class lease
  share attribution) and can decide instrument-vs-measure there.
- **Path 4 — PLAN-KILL.** N/A — the mandated active-experiment program
  ran and produced a decisive disposition.

## 6. Blast radius

None — no production code changes. Deliverables: this doc, issue
comments, #1614 close + follow-up issue + #1693 disposition note, one
side-finding issue (§9.1).

## 7. Acceptance gates

For the close: the §2 tables are the gates (3-rep decisive cell with
3g/6g ≥ `G_i` within noise, SSOT starvation test negative, phase
counters consistent, inelastic probe lossless). Standing regression
guard: `cos-simul-load-smoke.sh` floors + `cos-gate1-small-four-alone.sh`
(both already on master; §2 shows current master passes their intent —
small4-alone ≥ 87.5% ≥ the gate floors).

## 8. Risks

- **Framing risk**: the dispatch heuristic said "3g/6g ≥ ~85% of shape
  under simul → healed". They sit at 69-74% of shape — but ≥ 99% of
  `G_i` (Reading A) and the 85%-of-shape bar is not the ratified
  contract under aggressor pressure (it IS met in small4-alone:
  87-92%). Reviewers must adjudicate §4 explicitly rather than
  pattern-match either number.
- **Single-fraction coverage**: all cells ran guarantee-rate 0.7 (the
  fixture default). The #1743 unit tests cover allocator arithmetic at
  other fractions; live multi-fraction sweep left to the follow-up if
  ever needed.
- **Attribution is correlational**: #1743 is the only merged change
  whose mechanism predicts the healed signature, and the phase-counter
  regime flip matches it; a pre-#1743 redeploy A/B (Q2) is the
  airtight version.

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
   this is toolchain-version sensitivity. Recommend a follow-up issue:
   pin `RUST_BPF_TOOLCHAIN`/bpf-linker versions + add a load-time
   verifier guard to CI before any regenerated artifact lands.
2. **620x alternate-port iperf servers are version-incompatible** with
   the client iperf3 ("received an unknown control message"), blocking
   multi-process per-class UDP demand (caps inelastic offered load at
   ~2.9 G/class at MTU 1500). Worth a test-env fix if open-loop work
   needs more.

## 10. Test/repro plan

Executed (§2). Re-runnable: deploy master → `apply-cos-config.sh` →
`run-cell.sh` (archived alongside this doc) for `solo-*`,
`small4p24g-r{1..3}`, `small4-alone-r{1,2}`, `all6-r{1,2}`,
`small4p24g-udp-r{1,2}`, `mix-6gudp-r{1,2}`.

## 11. Reviewer questions (round 1)

1. Do you accept Reading A (ratified SSOT) as the adjudication basis
   for #1614's close, with Reading B's residual moved to a scoped
   follow-up? If not, which contract text supersedes the SSOT?
2. Does the close require the pre-#1743 redeploy A/B for attribution,
   or is the counter-regime flip + mechanism match sufficient?
3. Any objection to closing #1693 as overtaken (vs folding it into the
   follow-up)?
4. Is the follow-up issue as scoped in Path 1 sufficiently
   differentiated from killed #1692 (active program, narrower layer,
   explicit KILL exit) to be worth filing?
