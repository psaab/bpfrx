# #1614 — Simul-load CoS regression: measurement-first diagnosis

Revision: v3 (Codex r1 + AGY r1 folded; §3.B mechanism reframed as UNRESOLVED)
Branch: research/1614-simul-load-diagnosis
Base: origin/master @ 38e6fec53
Status: PLAN-READY candidate (measurement-first; defect SIGNAL confirmed,
mechanism deferred to /engineer instrumentation; recommends sub-issue split)

> v2 CHANGE LOG: v1 concluded "single exact class hard-capped at one
> worker's ~4 G TX throughput." A follow-up A/B REFUTED this: 18g paired
> only with 1g reached 14.25 Gbps from a SINGLE owner worker (q8/worker 2).
> One worker is NOT the limiter. v2 mechanism: shared ~24 G push ceiling
> divided among N backlogged classes, with guarantee-rate small-first
> protecting only 100m/1g.
>
> v3 CHANGE LOG: Codex r1 (PLAN-NEEDS-MAJOR) proved v2's §3.B mechanism
> ("per-worker owner-local eligible quantum_sum") FALSE — quantum_sum is
> global over all configured exact queues (`builders.rs:80-83`), no
> owner/eligible filter. AGY r1 (PLAN-READY) proposed a Phase-2 epoch
> lock-in mechanism instead; the live `waterfill_epochs` counter (climbing
> ~52K/s) + Phase-1-dominant admits REFUTE that as the active cause too.
> v3 reframes §3.B as a CONFIRMED defect SIGNAL with an UNRESOLVED
> mechanism (v8 lease / shared-exact / root FCFS / per-worker budget still
> in play), deferring candidate-selection to a per-worker-instrumented
> /engineer round — per Codex's explicit ask and the #1630 four-mechanism-
> falsification precedent.

This is a `/research` deliverable. It STOPS at PLAN-READY/PLAN-KILL.
No production source was modified. The diagnosis ran against the
**unmodified production daemon** on `loss:xpf-userspace-fw0` using the
#1628 per-class waterfill counters + the pre-existing DrainShape /
OwnerProfile control-socket telemetry.

---

## 1. Problem statement (as filed)

#1614 reports, under simultaneous 11-class load on the loss userspace
cluster (`cos-iperf-config.set`, `shaping-rate 25g`,
`oversubscription-policy guarantee-rate 0.7`):

- class starvation (each class 15-26% of shape, original capture),
- per-flow CoV jump (7-42%),
- sub-shape utilization,
- priority-low (`iperf-uncapped`) totally starved (0 Gbps, original).

The issue was BLOCKED on instrumentation; #1628 (merged, live on master
as of `ee3d12278`/`#1680`) added the per-class waterfill trace counters
(`phase1_admit`, `phase2_admit`, `eligible_visits`, interface
`epochs`/`phase1_budget_breaks`/`min_epochs_per_worker`). It is now
UNBLOCKED for a measurement-first diagnosis.

Note on prior work this plan does NOT repeat: #1630 already diagnosed and
DISPOSED of the **solo / 4-class** sub-shape behavior — cause-1 (low-rate
grant-bound) was fixed by the three-regime bounded credit carry in
`rotate_epoch_v8.rs` (shipped); cause-2 (mid-rate ~6% residual) was
PLAN-KILLED as TCP-burstiness transport physics and documented in
`docs/fairness-regimes.md`. Those explicitly scoped OUT the 11-class
simul case ("that is #1614"). This plan is that remaining case.

## 2. Measurement (this research, 2026-05-30, master @ 38e6fec53)

All runs: `loss:cluster-userspace-host` → firewall → `172.16.80.200`
(reth0.80 WAN, the shaped output filter direction), push, `-P 12`, 30 s,
production daemon. Per-class counter deltas computed from
`show class-of-service interface reth0.80` pre/post snapshots.

### 2.1 Full 11-class simultaneous push

| class | shape G | recv G | %shape | CoV% | spread | retr | p2-admit% | parkR | parkQΔ |
|------|--------:|-------:|-------:|-----:|-------:|-----:|----------:|------:|-------:|
| 100m | 0.1 | 0.09 | 86 | 8.4 | 1.27 | 68 | 0.0 | 0 | 39k |
| 1g | 1 | 0.63 | 63 | 52.4 | 3.58 | 408 | 0.2 | 0 | 25k |
| 3g | 3 | 1.28 | 43 | 26.6 | 2.32 | 550 | 0.1 | 0 | 199k |
| 6g | 6 | 2.43 | 41 | 26.0 | 2.64 | 1443 | 0.2 | 0 | 198k |
| 9g | 9 | 2.73 | 30 | 55.0 | 4.82 | 1408 | 0.8 | 0 | 145k |
| 12g | 12 | 2.71 | 22 | 47.5 | 4.70 | 1264 | 1.5 | 0 | 162k |
| 15g | 15 | 2.76 | 18 | 69.1 | 6.53 | 2310 | 2.0 | 0 | 134k |
| 18g | 18 | 3.13 | 17 | 38.0 | 5.33 | 1565 | 3.2 | 0 | 151k |
| 21g | 21 | 1.72 | 8 | 59.6 | 4.87 | 1252 | 9.9 | 0 | 105k |
| 24g | 24 | 2.60 | 11 | 54.1 | 5.71 | 1993 | 16.0 | 0 | 132k |
| uncap | — | 4.33 | — | 79.4 | 2044 | 47 | n/a | 0 | 0 |
| **SUM** | 109.1 | **24.96** | | | | | | | |

### 2.2 Per-OWNER-worker decomposition (full 11-class)

Each CoS queue is statically assigned to ONE owner worker
(`build_cos_owner_worker_by_queue_*` in `coordinator/mod.rs:1167+`,
round-robin over the TX binding's workers). 11 exact/best-effort queues +
1 uncapped over 6 workers ⇒ ~2 queues per worker:

| worker | Gbps | classes owned (Gbps each) |
|-------:|-----:|---------------------------|
| 0 | 2.59 | best-effort=0.00, 12g=2.59 |
| 1 | 2.72 | 100m=0.08, 15g=2.64 |
| 2 | 3.72 | 1g=0.60, 18g=3.13 |
| 3 | 2.94 | 3g=1.23, 21g=1.72 |
| 4 | 4.93 | 6g=2.33, 24g=2.60 |
| 5 | 6.94 | 9g=2.61, uncapped=4.33 |
| **TOT** | **23.85** | |

### 2.3 (v1) large-six alone — NOT decisive (see 2.4 refutation)

| class | shape G | recv G | %shape | CoV% | spread |
|------|--------:|-------:|-------:|-----:|-------:|
| 9g | 9 | 3.12 | 35 | 43.9 | 4.98 |
| 12g | 12 | 3.34 | 28 | 26.6 | 2.58 |
| 15g | 15 | 4.08 | 27 | 33.8 | 3.23 |
| 18g | 18 | 3.85 | 21 | 37.2 | 4.74 |
| 21g | 21 | 3.84 | 18 | 39.0 | 6.09 |
| 24g | 24 | 3.82 | 16 | 24.9 | 3.76 |
| uncap | — | 0.00 | — | 66.6 | 8.50 |
| **SUM** | | **22.05** | | | |

With 6 large classes competing, each caps at ~3.1-4.1 Gbps. v1 wrongly
read this as "one-worker ceiling." It is actually "~22 G aggregate / 6
backlogged classes."

### 2.4 DECISIVE A/B set — competitor-count sweep (refutes one-worker ceiling)

All push, -P12. Per-class achievement vs NUMBER of competing backlogged
classes:

| scenario | aggregate G | per-class result |
|----------|------------:|------------------|
| 1g solo | 0.95 | 1g=95% (repeated 95%, 95%) |
| 3g solo | 2.81 | 3g=94% |
| 1g + 18g | 15.2 | 1g=95%, **18g=79% (14.25 G from worker 2 ALONE)** |
| 3g + 24g | 18.1 | 3g=69%, 24g=67% (16.0 G) |
| 3 large (12/18/24g) | 22.6 | 44% / 47% / 37% (5.25/8.40/8.92 G) |
| 6 large (9..24g) | 21.6 | 42/31/29/15/16/15% (3.1-4.3 G each) |
| small4 + 24g | 18.2 | 100m=94, 1g=94, **3g=54, 6g=51**, 24g=52% (12.6 G) |
| full 11-class | 24.96 | §2.1 |

DECISIVE results:
- **18g reaches 14.25 Gbps from a SINGLE owner worker** (q8/worker 2,
  `park_root=0`). One worker is NOT capped at ~4 G. v1's funnel claim is
  dead.
- **3g degrades monotonically with competitor count**: 94% (solo) → 69%
  (1 competitor) → 54% (4 competitors). The deficit is set by HOW MANY
  classes are simultaneously backlogged, not by 3g's owner.
- **guarantee-rate 0.7 small-first protects ONLY 100m and 1g** (both ~94%
  in the small4+24g test). 3g/6g are NOT protected — they equalize with
  the unguaranteed 24g (all ~52%). small4-sum (10.1 G) fits comfortably
  under the ~18 G this scenario achieved, so the small-first contract
  SHOULD have honored 3g/6g fully. It did not.
- **`park_root=0` everywhere; `park_queue` high everywhere.** The 25 G
  root TOKEN bucket never throttles, but the aggregate still pins at
  ~18-24 G — so the limiter is upstream of the root token gate (the
  forwarding/TX push ceiling, #1578) AND the per-class division is set by
  the per-queue v8 lease + selector, not the root token bucket.

## 3. Root-cause attribution (corrected v2, falsification-tested)

The regression has TWO compounding components, separated by the §2.4
sweep:

### 3.A — Aggregate push ceiling ~22-24 G (physics, NOT a CoS bug)

The firewall's push-direction forwarding throughput pins at ~22-24 G
regardless of class count (1g+18g→15 G headroom-bound by demand; 3 large
→22.6 G; 6 large→21.6 G; 11-class→24.96 G with surplus). This equals the
documented push ceiling (Phase-0 reverse sanity 22.72 G; #1578). It is the
firewall's RX→forward→TX capacity, NOT a CoS scheduler defect. `park_root=0`
confirms the 25 G root TOKEN bucket is not the gate — the ceiling is
upstream in the forwarding/TX path. The ~22-24 G aggregate is the
denominator every class divides; no root-token or selector change raises
the AGGREGATE (the small4+24g run reached only 18.2 G, demand-bound below
even this ceiling). Sum of configured exact shapes (109 G) is 4.5× this
ceiling — strict-exact is not simultaneously deliverable, exactly as the
#1614 body's A4 commit-warning notes. CAVEAT (Codex r1): "no CoS change
raises this" is asserted for the AGGREGATE only; the §3.B defect is about
DISTRIBUTION of this aggregate, which a selector/lease fix CAN change.

### 3.B — guarantee-rate small-first under-protects 3g/6g (the actual CoS-side defect)

Given the ~22-24 G ceiling as denominator, the CoS question is: does
`guarantee-rate 0.7` honor small classes FIRST as designed? Measurement
says **only the two smallest (100m, 1g) are protected; 3g/6g are not.**

Decisive evidence (§2.4 small4+24g, all `park_root=0`):
- small4 sum-shape = 10.1 G, scenario achieved 18.2 G aggregate → there
  was ample ceiling to fully honor all four small classes.
- 100m=94%, 1g=94% (honored), but **3g=54%, 6g=51%** — sitting at the
  SAME ~52% as the unguaranteed priority-low 24g. The guarantee-rate
  small-first did NOT lift 3g/6g above the even-split line.
- 3g degrades monotonically with competitor count (solo 94% → +1 comp
  69% → +4 comp 54%), the signature of even-division, not guarantee-honor.
- `phase2_admit` is small for 3g/6g (≤0.2%) — they ARE admitted via the
  guaranteed Phase-1 path, NOT relegated to Phase-2. This is the key
  surprise and it RULES OUT the simple "Phase-2 relegation" story.

### 3.B.1 — the MECHANISM is NOT YET ISOLATED (v3 honesty, per Codex r1 + the telemetry cross-check)

v2 attributed §3.B to a per-worker `pass1 = quantum_sum × 0.7` budget
split over the "owner's local eligible queue set." **This is false in
code** (Codex r1, verified): `quantum_sum` is summed over
`root.exact_queues_by_rate_ascending` with NO nonempty/runnable/owner
filter (`queue_service/mod.rs:793-797`), and that vector is built over ALL
configured exact guaranteed queues at config-apply
(`builders.rs:80-83`). So the per-worker Phase-1 DENOMINATOR is global,
not owner-local-eligible; with small4+24g quanta, 100m+1g+3g+6g fit well
inside `0.7 × quantum_sum`. The v2 reconciliation with #1630-r4 was wrong.

Two further candidate mechanisms were proposed and BOTH are unconfirmed by
the live telemetry:

- **(AGY r1) Phase-2 epoch lock-in:** when Phase-1 breaks with a small
  positive `waterfill_pass1_remaining_bytes` and Phase-2 then returns a
  selection without zeroing it, the refill gate (`== 0` at
  `mod.rs:793`) is never met → worker locked in Phase-2 → epoch never
  rotates. **REFUTED as the active mechanism by the live counters:**
  interface `waterfill_epochs` climbed 7.68M → 9.41M (~52K/s) DURING the
  run — the epoch rotates continuously; and `phase1_admit` is the
  DOMINANT admit path for EVERY class incl 24g (84% Phase-1). A
  permanently-locked-Phase-2 worker would show flat epochs and ~0
  phase1_admit. Neither holds. (AGY's read is a plausible LATENT bug worth
  a separate hardening, but it is not what starves 3g/6g here.)
- **v8 lease / shared-exact (Codex r1):** queues ≥ 2.5 Gbps use
  shared-exact v8 leases (`worker/cos/mod.rs:168`,
  `coordinator/mod.rs:1399`). 3g/6g/9g+ all qualify. The v8 lease
  acquire path + root FCFS pool ordering remain live competing causes
  that the black-box A/Bs cannot separate from Phase-1 budget accounting.

**v3 disposition: §3.B is a CONFIRMED defect SIGNAL (3g/6g under-protected
with ceiling headroom — small4+24g reached only 18.2 G of ~24 G while
3g/6g sat at ~52%), but the MECHANISM is UNRESOLVED.** No fix candidate
may be chosen until direct per-worker instrumentation isolates it. This is
the Codex-mandated reframe and it matches the project's measurement-first
discipline (the #1630 chain falsified four derived mechanisms before
landing on physics).

### 3.C — what is NOT the cause (ruled out by data)

1. **NOT the root shaper** — `park_root=0` everywhere.
2. **NOT a single-owner per-class CPU funnel** (v1's wrong claim) — 18g
   pushed 14.25 G from one worker (§2.4).
3. **NOT a permanent Phase-2 epoch lock-in** (AGY r1 hypothesis) —
   `waterfill_epochs` climbs continuously and Phase-1 is the dominant
   admit path (§3.B.1).
4. **NOT simple Phase-2 relegation** — 3g/6g are Phase-1-admitted
   (phase2_admit ≤0.2%).
5. **STILL OPEN:** v8 lease acquire / shared-exact behavior, root FCFS
   pool ordering, and a per-worker budget interaction not visible in the
   aggregated #1628 counters. The /engineer round must instrument these.
4. **NOT the per-flow CoV** — see §3.2.

### 3.1 Why the SYMPTOM differs from the original #1614 capture

The original capture (2026-05-28) predates cause-1 AND #1626/#1629
activating `guarantee-rate 0.7`:
- 100m 20% → 86%, 1g 21% → 63% (cause-1 + guarantee-rate now protect the
  smallest classes).
- uncapped 0 G → 4.33 G (priority-low now harvests surplus via
  `nonexact_while_exact_backlogged` where workers have headroom).

The residual regression is now precisely §3.B: **mid-rate exact classes
(3g/6g) are not honored to guarantee under multi-class contention even
when the ceiling has room.** This IS a CoS-semantics defect SIGNAL,
fixable in the selector/lease layer — contrary to v1's "not a scheduler
bug" conclusion — but the precise mechanism is UNRESOLVED (§3.B.1) and
must be instrumented before a fix is chosen.

### 3.2 Structural-CoV / #1217 contract check

Per-flow CoV within a class (24-69%) is the documented multinomial /
MQFQ floor (`Cstruct ≈ 53%`, `project_1244_killed`; #1220 found 47% was
BELOW the structural ceiling — no scheduler bug). This component stays
PLAN-KILL by precedent: a fix that does not change per-flow placement
cannot lower it. The #1614 acceptance gate "per-flow CoV ≤ 5/10%" is
structurally unreachable and must be re-scoped — directly the #1211/#1220
lesson. The fixable target is §3.B per-CLASS achievement (which class
hits its guarantee), NOT per-flow CoV within a class.

## 4. Multiple Path Options

The two components (§3.A ceiling = physics; §3.B small-first
under-protection = fixable selector) drive different paths. §3.A and the
per-flow CoV (§3.2) are PLAN-KILL-by-precedent; the live design space is
§3.B.

### Path A — Instrument, then fix the 3g/6g guarantee under-protection

Path A is a `/research`→`/engineer` chain that MUST begin with
instrumentation, NOT a pre-chosen fix (Codex r1 mandate; the v2 mechanism
was code-falsified). The /engineer round's FIRST deliverable is a
throwaway per-worker counter set that isolates which layer starves 3g/6g:

- per-worker (not aggregated) `phase1_admit`/`phase2_admit`/`eligible_visits`
  for 3g/6g/24g and their co-hosting peers — the shipped #1628 counters
  are SUMMED across workers and cannot show the per-worker split (Codex
  r1 finding 3; AGY r1 §5 argues each queue is single-owner so the
  per-class counters ARE per-owner — the /engineer round must resolve this
  disagreement empirically by adding a genuinely per-worker dump);
- v8 lease grant vs consume per epoch for 3g/6g (the
  `cos_queue_lease_acquire_v8_granted_bytes` already exists; pair it with
  drain_sent);
- root FCFS pool acquire ordering / fairness across the co-resident
  backlogged queues.

Only after the layer is named do the candidate fixes apply (each
PLAN-KILL-able):

1. **Eligibility/headroom-gated Phase-1** — if the budget split or the
   `quantum × fraction` heuristic is the cause, gate Phase-1 honoring on
   the achievable per-worker share so mid classes are honored before
   Phase-2 relegation. (Candidate ONLY if instrumentation confirms a
   budget-boundary cause; v2's specific wording was wrong.)
2. **Phase-2 epoch-rotation hardening** (AGY r1's latent-bug candidate) —
   reset `waterfill_pass1_remaining_bytes` to 0 on the Phase-1 break or
   refill when it falls below the min active quantum, so the epoch cannot
   wedge. Worth doing as defensive hardening EVEN IF it is not the active
   #1614 cause (the live counters say it isn't), but must be justified on
   its own merits, not sold as the #1614 fix.
3. **v8 lease / shared-exact fairness** — if instrumentation fingers the
   lease grant or root FCFS ordering, the fix is in that layer (highest
   seqlock risk; fresh adversarial round mandatory).
4. **Re-derive the Phase-1 boundary from configured guarantee RATES** (a
   proper small-first WFQ) rather than `quantum × fraction` — the cleanest
   semantic if the heuristic boundary is confirmed at fault.

- **Risk:** this is genuine CoS-semantics work. It must NOT regress the
  default proportional mode (bit-for-bit per `docs/fairness-regimes.md`)
  and must compose with the shipped cause-1 carry + #1643 fence (disjoint
  layers: meter / publish / selector). It is bounded by the §3.A ceiling
  — Path A makes 3g/6g hit guarantee at the COST of the large classes
  (the residual under oversubscription is irreducible; §3.A). That
  trade-off is the documented `guarantee-rate` contract intent.
- **Expected outcome: viable but mechanism-gated** — this is the one
  fixable component, but it is PLAN-READY-able ONLY after the
  instrumentation step names the layer. If instrumentation shows the
  ~52% is actually the §3.A even-division with no recoverable headroom at
  the per-worker level, Path A could itself PLAN-KILL (do not assume a
  fix exists). The #1614 `guarantee-rate` knob exists to make the
  trade-off operator-selectable, which is the design intent IF a
  mechanism is found.

### Path B — Accept §3.A ceiling + re-scope gates + operator warning (REQUIRED regardless)

Independent of Path A:
1. Document the ~22-24 G push ceiling in `docs/fairness-regimes.md` as
   the per-class denominator (it is #1578's documented forwarding
   ceiling, not a CoS bug). Sum-exact = 109 G is 4.5× it.
2. The A4 commit warning (shipped #1618) already fires on
   `sum_exact > shaping_rate`. Verify it fires for this fixture (it
   should — 109 G > 25 G) and that the message names the ceiling.
3. Re-scope #1614 gates: per-CLASS achievement is the fixable target
   (Path A); per-FLOW CoV ≤ 5/10% is structurally unreachable (§3.2) and
   must be DROPPED or replaced by the #1217 structural-CoV contract
   (`observed_CoV ≤ Cstruct + 0.05`).

- **Expected outcome: the honest framing layer.** Required whether or not
  Path A ships.

### Path C — Rate-aware queue→worker placement (fairness refinement)

Today queue→worker is round-robin by queue index
(`coordinator/mod.rs:1167+`); worker 5 got 9g+uncapped (6.94 G) while
worker 0 got best-effort+12g. Rate-aware placement (spread large classes
to distinct workers, cluster small classes) would even the
per-class-achievement spread. Since §2.4 shows one worker CAN push 14 G,
placement DOES matter (unlike v1's claim). But it is bounded by §3.A and
must be transaction-safe + HA-stable per the #761 KILL (adding a class
must not shift existing slots → misroute on HA peers). Defer to a refinement
sub-issue after Path A.

### Path D — Per-flow CoV within a class

PLAN-KILL by precedent (§3.2; #1220/#1244). Out of scope.

## 5. Recommendation

**Decompose #1614 into sub-issues; Path A (fix 3g/6g guarantee-honor) +
Path B (re-scope + document) are the deliverables. Path C is a deferred
refinement. The per-flow-CoV gate is dropped.**

- **Sub-issue 1 (Path B — RECOMMEND OPEN, do first):** document the
  §3.A push ceiling as the per-class denominator; verify the A4 commit
  warning fires on the 109 G fixture; re-scope #1614 gates (drop the
  per-flow-CoV gate, keep per-class-achievement). Low risk, no hot-path
  change. Unblocks honest gating for Path A.
- **Sub-issue 2 (Path A — RECOMMEND OPEN as an INSTRUMENT-FIRST
  `/research`→`/engineer` chain):** the 3g/6g under-protection is a
  CONFIRMED defect signal (small4+24g achieved 18 G with ~6 G unused
  headroom while 3g/6g sat at ~52%, `park_root=0`, Phase-1-admitted), but
  the MECHANISM is UNRESOLVED (§3.B.1: v2's per-worker-quantum_sum theory
  is code-false; AGY's epoch-lock-in is telemetry-refuted; v8 lease / root
  FCFS still open). The /engineer round MUST land per-worker
  instrumentation FIRST and name the layer before any fix — and must
  accept PLAN-KILL if no recoverable headroom exists per-worker. Fresh
  adversarial plan-review (CoS-semantics, seqlock-adjacent); preserve
  default proportional mode bit-for-bit; compose with cause-1 + #1643.
- **Sub-issue 3 (Path C — DEFER):** rate-aware transaction-safe placement;
  only after Path A, only if per-class-achievement spread still matters.

This is a measurement-first convergence: the regression is (a) the
documented ~22-24 G push-ceiling physics divided among N backlogged
classes [§3.A, not fixable] + (b) a CONFIRMED but MECHANISM-UNRESOLVED
guarantee under-protection of 3g/6g [§3.B, instrument before fixing] +
(c) per-flow CoV [PLAN-KILL by #1220/#1244]. v1's single-owner-funnel
claim was refuted by the §2.4 sweep (18g hit 14 G on one worker); v2's
per-worker-quantum_sum mechanism was refuted by Codex r1 (code) and the
live epoch counter. The honest /research output is the confirmed signal +
the falsified hypotheses + the instrument-first Path A charter, NOT a
pre-chosen scheduler fix — matching the #1630 four-mechanism-falsification
discipline.

## 6. Acceptance criteria (re-scoped, achievable)

- [ ] Path B: §3.A ceiling documented; A4 commit warning verified to fire
      on the 109 G fixture; #1614 per-flow-CoV gate dropped/replaced by
      the #1217 contract.
- [ ] Path A STEP 0 (gating): per-worker instrumentation isolates the
      layer starving 3g/6g (Phase-1 budget vs v8 lease vs root FCFS).
      If no recoverable per-worker headroom exists, Path A PLAN-KILLs.
- [ ] Path A (only if STEP 0 names a fixable layer): under small4+24g
      (the §2.4 falsifier), 3g/6g reach ≥ 90% of shape (today 54/51%)
      WITHOUT 100m/1g losing honor (stay ≥ 90%) and WITHOUT raising
      aggregate above §3.A ceiling. The trade-off (large classes regress)
      is expected and operator-selected via `guarantee-rate`.
- [ ] Path A: default proportional mode unchanged bit-for-bit.
- [ ] `make test-failover` ≤ 60 ms unchanged.
- [ ] No per-CoS-class memory regression.

## 7. Open questions for plan-review

1. **1g at 63% in the full 11-class mix but 95% solo and 94% in
   small4+24g.** Resolved by §2.4: 1g is fine when ≤4 competitors; the
   63% is the full-11-class even-division plus its share of the §3.A
   ceiling. Not a separate bug. (SMR r1 R1 — RESOLVED.)
2. **Which layer starves 3g/6g?** UNRESOLVED — §3.B.1. v2's per-worker
   quantum_sum theory is code-false (Codex r1); AGY's epoch-lock-in is
   telemetry-refuted; v8 lease grant / shared-exact / root FCFS ordering
   remain open. This is the Path A STEP 0 instrumentation deliverable.
   The #1628 counters are per-class SUMMED across workers (Codex r1
   finding 3); AGY r1 §5 counters that each queue is single-owner so the
   per-class counter IS per-owner — this DISAGREEMENT must be resolved
   empirically by a genuinely per-worker dump in the /engineer round.
3. **Does any Path A fix need the §3.A ceiling as a runtime input?** If a
   "fits the achievable share" test is the fix, the ceiling must be
   measured/estimated at runtime, not a config constant — design risk.
4. **uncapped spread = 2044x** (full mix) — priority-low surplus
   concentrates where workers have headroom; structural, flagged not
   targeted.
5. **Is the AGY-identified Phase-2 epoch-rotation wedge a real latent
   bug** worth hardening independently (even though it is not the active
   #1614 cause)? The code path (`mod.rs:793` refill gate `== 0` +
   non-zeroing Phase-2 return) is real; the live counter shows it does not
   wedge HERE, but a different rate/quantum mix might trip it.

## 8. Reproducibility

```bash
# full 11-class push + pre/post per-queue counters
/tmp/diag_capture.sh
# competitor-count sweep (the decisive §2.4 set)
/tmp/diag_large.sh   # 6 large alone
/tmp/diag_1g.sh      # 1g solo, 1g+18g, 1g solo repeat
/tmp/diag_sweep.sh   # 3 large, 6 large
/tmp/diag_gr.sh /tmp/diag_gr2.sh  # small4 + 24g (guarantee-rate small-first test)
/tmp/diag_3g.sh      # 3g solo, 3g+24g
# counters: cli -c "show class-of-service interface reth0.80"
#   DrainShape sent_bytes / park_root / park_queue;
#   Waterfill phase1_admit / phase2_admit / eligible_visits
```

Key artifacts: `/tmp/diag1614_1780151878` (full 11-class),
`/tmp/diag1614_1g_18g_*` (18g=14.25 G one worker — refutes v1),
`/tmp/diag1614_gr2_*` (small4+24g — 3g/6g under-protected). Daemon:
master @ 38e6fec53, deployed 2026-05-30 05:39 UTC, node 0 primary,
`guarantee-rate 0.7`, `shaping-rate 25g`.
