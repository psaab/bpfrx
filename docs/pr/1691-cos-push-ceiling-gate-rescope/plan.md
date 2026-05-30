# #1691 — CoS Path B: document the ~22-24 G push-ceiling division + re-scope #1614 acceptance gates

Status: DRAFT v2 — Codex r1 (PLAN-NEEDS-MAJOR) + AGY r1 (PLAN-NEEDS-MINOR)
+ Claude-SMR r1 (PLAN-NEEDS-MINOR) folded; pending re-review
Branch: refactor/1691-cos-push-ceiling-gate-rescope
Base: origin/master @ 7988d4c25

> v2 CHANGE LOG (folds 3 reviewer rounds — see claude-smr-plan-r1.md,
> reviewer-ids.md):
> - **Codex r1 BLOCKING fix:** v1 narrowed smoke Gate 1 to {100m,1g}
>   asserting ≥95%, justified by the §2.4 small4+24g run (1g=94%). But
>   `cos-simul-load-smoke.sh` runs ALL 11 classes, where 1g=63% and even
>   100m=86% (research §2.1). A ≥95% bar is unsatisfiable for EVERY class
>   under full-11 simul — so v1's narrowed gate STILL failed master with
>   no dataplane change. v2 moves the ≥95% guarantee gate to where the
>   research proves it achievable: the SOLO harness
>   `cos-gate1-small-four-alone.sh` (#1630, untouched). The full-11
>   `cos-simul-load-smoke.sh` Gate 1 becomes a DIVIDED-CEILING REGRESSION
>   FLOOR (catches starvation-to-zero, not the unmet guarantee).
> - **Codex r1 + AGY r1 MAJOR fix:** v1 ungated 3g/6g entirely → a
>   starve-to-0 regression would pass silently. v2 keeps ALL four small
>   classes (5201-5204) in the full-11 Gate 1 against a relaxed
>   per-class regression floor calibrated BELOW today's full-11 values
>   (100m≥60%, 1g≥40%, 3g≥25%, 6g≥25%), with an explicit
>   `reported_ungated`-equivalent note that the ≥95% guarantee is NOT
>   asserted under simul (it lives in the SOLO gate + #1692).
> - **Codex r1 + AGY r1 fix:** the ~22-24 G number is expressed
>   algebraically as `C_phys` (the platform's push RX→TX delivery
>   ceiling), with 22-24 G footnoted as the measured loss-cluster
>   reference value — NOT a universal product constant.
> - **Codex r1 + Claude-SMR r1 fix:** the dropped flat per-flow-CoV gate
>   is named as the concrete artifact — #1614 issue body line 113
>   ("Per-flow CoV ≤ 5% under simultaneous load") — and the parent issue
>   checklist is reconciled (a PR/#1614 comment records the drop). The
>   #1614 body already cites #1217 at line 164, so the body is internally
>   inconsistent; the rescope resolves it.
> - **AGY r1 fix:** the starvation discriminator is given a formal
>   3-condition algebraic definition (actual < guarantee AND unguaranteed
>   classes allocated AND ΣG < C_phys).
> - **Codex r1 fix:** explicitly call out that `cos-gate1-small-four-alone.sh`
>   is the #1630 SOLO gate and is NOT the #1614 simul gate, to avoid
>   conflation.

This is the **Path B "do first"** deliverable spun out of the #1614
simul-load CoS-regression research
(`docs/research/1614-simul-load-diagnosis/plan.md` v3 @ `e672bb821`,
converged 3-of-3 PLAN-READY). It is **DOCS + TEST-GATE rescope ONLY** —
no dataplane mechanism change, no CoS scheduler code touched. The
§3.B guarantee-rate under-protection defect is explicitly OUT of scope
(that is the separate instrument-first sub-issue #1692).

## 1. Issue framing (in my words)

The #1614 research established two separable facts the current gates do
not yet reflect:

- **§3.A — the ~22-24 G aggregate push ceiling is physics, not a CoS
  bug.** The firewall's push-direction RX→forward→TX capacity pins at
  ~22-24 G regardless of class count (`park_root=0` everywhere — the
  25 G root token bucket never throttles; the limiter is the #1578
  forwarding/TX push ceiling, upstream of the root token gate). When N
  classes are *simultaneously backlogged*, that fixed ceiling is
  **divided** among them. Sum of configured exact shapes on the
  `cos-iperf-config.set` fixture is 109 G — 4.5× this ceiling — so
  strict-exact is not simultaneously deliverable. Any acceptance gate
  expecting per-class throughput to sum above the ceiling is
  structurally unsatisfiable.

- **The per-flow-CoV gate is PLAN-KILL by precedent.** Per
  #1220/#1244, observed per-flow CoV within a class (24-69% in the
  simul capture) sits at or below the documented multinomial / MQFQ
  structural floor (`Cstruct ≈ 53%`). A fix that does not change
  per-flow placement cannot lower it; AF_XDP zero-copy queue-binding
  is permanent physics (#840/#1203/#1215/#937 all killed). A flat
  per-flow-CoV ≤ 5/10% gate (as the original #1614 issue body
  proposed) is structurally unreachable.

The work: (1) document the push-ceiling-division behavior so operators
and reviewers stop misreading divided-ceiling as starvation; (2)
re-scope the #1614 acceptance gates — drop any flat per-flow-CoV gate
(replaced by the already-present #1217 `Cstruct + 0.05` structural
contract), and restate the small-class guarantee gate against
divided-ceiling reality so it does not assert §3.B (3g/6g) behavior
that is a confirmed-but-unresolved defect deferred to #1692.

## 2. Honest scope / value framing

The value is **honest gating**, not throughput. Today's gates have two
latent inconsistencies that, left in place, will (a) make a future
#1692 instrumentation PR look like it is "failing" against an
unsatisfiable bar, and (b) re-litigate the per-flow-CoV PLAN-KILL that
#1220/#1244 already settled. There is zero runtime/perf change and zero
hot-path code touched.

*If reviewers conclude the gate-rescope misrepresents the contract — in
particular if dropping/loosening the 3g/6g assertion in Gate 1 lets a
real regression slip through, or if the divided-ceiling framing is
wrong — PLAN-KILL is an acceptable verdict.*

## 3. What's already shipped / the gates as they stand today

Three artifacts carry #1614 acceptance gates. The rescope must keep all
three internally consistent.

### 3.1 `docs/fairness-regimes.md` — the product contract

- **§"Acceptance gates under guarantee-rate mode"** (lines ~1008-1026):
  > "In addition to the structural per-flow CoV gate above
  > (`observed_CoV ≤ Cstruct + 0.05`), guarantee-rate runs assert:
  > 1. **Small-class absolute guarantee** (classes whose cumulative
  >    `R_i` fits under the shaping ceiling): each class hits ≥ 95% of
  >    its configured rate under all-class simul load."
- **Phase 0 sanity note** (lines ~1120-1124): "simul-load reverse
  direction (all 11 classes parallel) reached 22.72 G aggregate … the
  firewall (not the generator) is the bottleneck." This is the ~22-24 G
  ceiling already half-documented — but only as a *reverse sanity
  number*, NOT as the push-direction per-class denominator the research
  §3.A names.
- The structural per-flow CoV gate `observed_CoV ≤ Cstruct + 0.05` is
  ALREADY the contract (lines ~110-117, ~276). There is no flat
  per-flow-CoV ≤ 5/10% gate in the doc — the doc already uses the
  structural form. The rescope here is to make the DROP explicit:
  state plainly that the flat per-flow-CoV gate the original #1614 body
  proposed is dropped, and only the #1217 structural gate applies.

### 3.2 `test/incus/cos-simul-load-smoke.sh` — the executable gate

- **Gate 1** (`gate_1_small_class_guarantees`, lines 167-185) asserts
  ports **5201, 5202, 5203, 5204** (100m, 1g, 3g, 6g) each hit ≥ 95% of
  shape under all-11-class simul load. Comment: "100m, 1g, 3g, 6g all
  fit under 18G; if guarantee-rate mode active, each should hit ≥ 95%."
  - **This is the bug the rescope fixes.** This harness runs ALL 11
    classes in parallel. Under full-11 simul the research §2.1 measured
    **100m=86%, 1g=63%, 3g=43%, 6g=41%** — NOT one of the four hits the
    ≥95% guarantee, because the ~22-24 G ceiling divides among 11
    backlogged classes (§3.A). The ≥95% guarantee is a SOLO / few-
    competitor property (§2.4 small4+24g: 100m=94%, 1g=94%; #1630 SOLO
    A/B: 100m=95.0%, 1g=95.3%). Asserting ≥95% on the full-11 harness is
    unsatisfiable for EVERY one of the four — including 1g — for the
    ceiling-division reason the research §2.1/§3.A documents, NOT a
    fixable bug. (For 3g/6g there is ALSO the separate §3.B
    under-protection defect deferred to #1692; but even 100m/1g cannot
    hit ≥95% under full-11.) Gate 1 as written fails master today.
  - The harness COMPUTES `cov_pct` per class but does NOT gate on it —
    there is no per-flow-CoV pass/fail in the harness code (lines 132,
    140, 156). So the per-flow-CoV "drop" is a doc/charter action, not a
    harness code deletion. The harness change is replacing the ≥95%
    guarantee assertion with a DIVIDED-CEILING REGRESSION FLOOR.
- Gate 2 (`gate_2_priority_low_min_share`) and Gate 3
  (`gate_3_retrans_floor`) are unaffected by this rescope.

### 3.4 `test/incus/cos-gate1-small-four-alone.sh` — the #1630 SOLO gate (NOT touched, but called out)

This separate harness (`#1630 Gate 1`) runs 5201-5204 with NO large-
class competition and asserts each ≥ 95% (`cos-gate1-small-four-alone.sh:2`,
`:63`). That is the SOLO/few-competitor scenario where the ≥95%
guarantee IS achievable and is the correct home for the guarantee gate.
This rescope does NOT touch it. The plan explicitly distinguishes it
from the #1614 full-11 `cos-simul-load-smoke.sh` to avoid conflation
(Codex r1 finding 6): the guarantee gate stays SOLO; the simul harness
gets a regression floor only.

### 3.3 `docs/pr/1614-multi-rss-cos/plan.md` §7 — the historical PR gate list

- §7 criterion 1 lists "100m ≥ 95 Mbps, 1g ≥ 950 Mbps, **3g ≥ 2.85 G,
  6g ≥ 5.7 G**". §7 criterion 4 is "Per-flow CoV ≤ Cstruct + 0.05 per
  #1217, unchanged." This is the implementation PR's own plan and is
  archival; the rescope adds a forward-pointer note (not a rewrite of
  history) recording that the 3g/6g simul gate is superseded by the
  #1614 research and deferred to #1692, and that the per-flow-CoV gate
  is the #1217 structural form (no flat bar). I will NOT rewrite the
  archival plan's body — only append a clearly-dated rescope pointer so
  the live contract (`fairness-regimes.md`) is the SSOT.

## 4. Concrete design (the edits)

### Edit set 1 — push-ceiling-division doc (commit 1)

In `docs/fairness-regimes.md`, expand the CoS oversubscription section
to add a subsection (placed right after the "oversubscription-policy"
intro, before "Acceptance gates"). The ceiling is expressed
algebraically as `C_phys` with 22-24 G footnoted as the measured
loss-cluster reference value (Codex r1 finding 3, AGY r1 Q2):

> **### Aggregate push ceiling `C_phys` is the per-class denominator (#1578/#1614 §3.A)**
>
> Let `C_phys` be the platform's push-direction RX→forward→TX delivery
> ceiling — a hardware property (CPU, memory, PCIe, worker count), NOT
> a CoS scheduler limit. On the standard `loss:` reference cluster
> (6 mlx5 VF RX queues → 6 workers) `C_phys ≈ 22-24 G`, measured
> consistently across 3-large (22.6 G), 6-large (21.6 G), full-11
> (24.96 G) push and the 22.72 G reverse sanity (#1578, #1614 §2). It
> is NOT a universal product constant; a different platform has a
> different `C_phys`.
>
> The denominator every backlogged class divides is `C_phys`, NOT the
> sum of configured `transmit-rate`. On the `cos-iperf-config.set`
> fixture the configured exact-shape sum is **109 G — 4.5× `C_phys`**,
> so strict-exact is not simultaneously deliverable (the A4 commit
> warning, #1618, fires on exactly this `sum_exact > shaping_rate`
> condition). `park_root = 0` everywhere in the #1614 capture, so the
> 25 G root token bucket never throttles — the limiter is upstream of
> the root token gate. When N classes are simultaneously backlogged,
> `C_phys` divides among them; per-class %-of-shape therefore drops as
> N rises. Measured competitor-count sweep (#1614 §2.4): 3g reaches
> 94% solo, 69% with one competitor, 54% with four — the deficit is set
> by HOW MANY classes are backlogged, not by 3g's owner worker. 18g
> pushed 14.25 G from a single owner worker (`park_root=0`), so the
> ceiling is an aggregate property, not a per-worker funnel.
>
> **Reading divided-ceiling as starvation is a misread.** A guaranteed
> class `i` (guarantee `G_i = R_i × guarantee-rate fraction`) is
> **starved** iff ALL THREE hold:
> 1. `actual_i < G_i` (guarantee unmet), AND
> 2. `Σ actual_j > 0` over unguaranteed classes (they ARE getting
>    bandwidth while `i` is short), AND
> 3. `Σ G_k < C_phys` over guaranteed classes (the guaranteed demand
>    fits under the ceiling — there is recoverable headroom).
>
> If `Σ G_k ≥ C_phys`, or all unguaranteed classes are at 0 G while
> `C_phys` is saturated, the shortfall is divided-ceiling physics, NOT
> scheduler starvation. The #1614 §3.B 3g/6g case satisfies all three
> (small4+24g: ΣG=10.1 G < 18.2 G achieved, 24g getting 12.6 G, 3g/6g
> at 54/51%) — that is the genuine defect SIGNAL tracked in #1692.

Also adjust the Phase 0 note (lines ~1120-1124) so it cross-references
this as the push-direction equivalent of the 22.72 G reverse number —
both directions hit the same `C_phys` ≈ 22-24 G physics ceiling.

### Edit set 2 — gate rescope (commit 2)

**`docs/fairness-regimes.md` "Acceptance gates under guarantee-rate
mode":**

1. **Scope the ≥95% small-class guarantee gate to SOLO / few-competitor
   runs, NOT the full-11 simul harness.** Under full-11, the §3.A
   ceiling divides so NO class hits ≥95% (100m=86%, 1g=63%; §2.1) — the
   ≥95% guarantee is achievable only SOLO (`cos-gate1-small-four-alone.sh`,
   #1630: 100m=95.0%, 1g=95.3%) or with few competitors (§2.4
   small4+24g: 100m/1g=94%). State that the full-11 simul harness
   asserts a DIVIDED-CEILING REGRESSION FLOOR instead (below), and that
   the ≥95% guarantee for 3g/6g under multi-class contention is a
   CONFIRMED-but-mechanism-UNRESOLVED defect tracked in #1692.
2. Add an explicit statement that the **flat per-flow-CoV gate is
   DROPPED**: name the concrete artifact — **#1614 issue body line 113,
   "Per-flow CoV ≤ 5% under simultaneous load"**. Per #1220/#1244 the
   per-flow CoV within a class is structural (≈ `Cstruct` ≈ 53% at the
   multinomial(12,6) floor), so the ONLY per-flow fairness gate is the
   #1217 `observed_CoV ≤ Cstruct + 0.05` structural contract already
   stated above. (The #1614 body line 164 already cites #1217 — the
   body is internally inconsistent; this resolves it.)
3. State that per-class %-of-shape gates under simul load are bounded by
   `C_phys` — gates may not assert per-class numbers whose sum exceeds
   `C_phys`.

**`test/incus/cos-simul-load-smoke.sh` Gate 1 — replace the ≥95%
guarantee with a divided-ceiling regression floor:** keep ALL four
small-class ports `(5201, 5202, 5203, 5204)` in
`gate_1_small_class_guarantees` (so a starve-to-zero regression on ANY
of them still trips — Codex r1 finding 2, AGY r1 Q1), but compute each
target as a relaxed per-class regression floor calibrated BELOW today's
full-11 measured value (§2.1: 100m=86%, 1g=63%, 3g=43%, 6g=41%), with
margin for normal variance:

```python
# Divided-ceiling regression floor (NOT the ≥95% guarantee, which is
# SOLO-only — see fairness-regimes.md / #1630 cos-gate1-small-four-alone.sh
# and the #1614 §3.B 3g/6g defect tracked in #1692). Under full-11 simul
# the ~22-24 G C_phys ceiling divides among 11 classes, so 100m=86%,
# 1g=63%, 3g=43%, 6g=41% are EXPECTED (research §2.1). These floors only
# catch a collapse (e.g. starve-to-zero), not the unmet guarantee.
SIMUL_FLOOR_PCT = {5201: 0.60, 5202: 0.40, 5203: 0.25, 5204: 0.25}
...
if r["port"] in SIMUL_FLOOR_PCT:
    target = r["shape_gbps"] * SIMUL_FLOOR_PCT[r["port"]]
```

Rename the gate field to make the semantics unambiguous (e.g.
`gate_1_small_class_divided_ceiling_floor`) OR keep the key and add a
`"semantics": "divided-ceiling regression floor, NOT >=95% guarantee
(SOLO/#1692)"` annotation in the emitted JSON so a `verdict.json`
reader cannot misread it as the guarantee gate. Keep computing and
REPORTING all per-class %-shape. No change to Gate 2 / Gate 3 / reverse
Gate 8.

**`docs/pr/1614-multi-rss-cos/plan.md`:** append a dated "#1614
research rescope (Path B / #1691)" pointer block at the END of the §7
gate list (do NOT rewrite the historical criteria in place) recording:
the ≥95% 3g/6g simul guarantee (§7 crit 1) is SOLO-only; the full-11
simul gate is a divided-ceiling regression floor; 3g/6g simul
under-protection deferred to #1692; the flat per-flow-CoV gate (#1614
body line 113) is dropped, replaced by the #1217 structural form;
per-class simul gates bounded by `C_phys`. SSOT for the live contract
is `fairness-regimes.md`.

**Parent issue reconciliation:** post a comment on #1614 (or note in
the #1691 PR body, cross-linked) recording that body acceptance-line
113 ("Per-flow CoV ≤ 5%") is DROPPED per #1220/#1244 in favor of the
#1217 structural gate, and that the 3g/6g ≥95% simul guarantee is
deferred to #1692. This closes the open question of where the dropped
gate physically lives (Claude-SMR r1 F1).

## 5. Public API preservation

No code API. The smoke harness's `verdict.json` keeps Gate 1's
`classes[]` + `pass` shape; the gated port set stays all four (5201-
5204), only the per-port TARGET changes (≥95% → divided-ceiling floor)
plus an added `semantics` annotation (or a renamed key). Gates 2/3/8
byte-identical. A consumer reading `gate_1_*.pass` still finds it; the
annotation prevents misreading the floor as the guarantee.

## 6. Hidden invariants the change must preserve

- **Gate 1 must still catch a real collapse on ALL FOUR small classes.**
  Keeping 5201-5204 in the gate against a divided-ceiling floor means a
  starve-to-zero (or near-zero) regression on 100m/1g/3g/6g still trips
  (Codex r1 finding 2 / AGY r1 Q1). We are NOT ungating any class — we
  are replacing an unsatisfiable ≥95% guarantee bar (which the full-11
  ceiling-division makes impossible for every class incl 1g) with a
  floor calibrated below today's measured value so only a real
  regression fails.
- **The ≥95% guarantee gate is preserved where it is achievable** — the
  SOLO `cos-gate1-small-four-alone.sh` (#1630) is untouched. The
  guarantee is not weakened; it is asserted in the correct scenario.
- **3g/6g visibility preserved.** The harness keeps computing and
  printing 3g/6g %-shape so the #1692 round can read the numbers; the
  ≥95% guarantee pass/fail (not achievable under simul) is the only
  thing removed, replaced by the floor.
- **#1217 structural CoV contract untouched.** The
  `observed_CoV ≤ Cstruct + 0.05` gate is the surviving per-flow
  fairness gate; we are not weakening it, only naming the flat bar it
  replaces.
- **Proportional-mode bit-for-bit preservation note untouched** — this
  rescope does not touch the default-mode contract.
- **A4 commit warning (#1618) unchanged** — referenced, not modified.

## 7. Risk assessment

| Class | Level | Rationale |
|-------|-------|-----------|
| Behavioral regression | LOW | No code path changed; smoke gate retargeted (not removed). Zero dataplane edit. |
| Lifetime / borrow-checker | N/A | No Rust touched. |
| Performance regression | NONE | No hot-path / control-path code change. Docs + one Python gate-target map + comments. |
| Architectural mismatch (#961/#946-P2) | LOW | This is the research's own recommended Path B "do first"; it documents physics rather than asserting a mechanism. The only mismatch risk is mis-stating the contract — which is the explicit PLAN-KILL criterion. |
| Coverage-loss risk | LOW (was the v1 defect) | v2 keeps ALL FOUR small classes in Gate 1 against a divided-ceiling floor (no class ungated), so a starve-to-zero regression still trips. The floor is calibrated below today's full-11 values; a real collapse fails, normal ceiling-division does not. The ≥95% guarantee stays on the SOLO #1630 gate. |
| Floor-calibration risk | LOW-MED | Floors (60/40/25/25%) are below §2.1 measured values (86/63/43/41%) with ~30% margin; too-tight would flake, too-loose would miss a partial regression. Reviewers should sanity-check the margin against expected run-to-run variance. |

## 8. Test plan

This is control-plane docs + a test-harness gate tuple. No cluster
smoke is required (no dataplane change) — stated explicitly per the
task charter. Gates:

- [ ] `python3 -c "import ast; ast.parse(open('test/incus/cos-simul-load-smoke.sh'...))"` — the embedded Python in the smoke script parses (it is a heredoc'd `python3 - <<PY`; validate by extracting and `python3 -m py_compile`, or run `bash -n` on the script).
- [ ] `bash -n test/incus/cos-simul-load-smoke.sh` — shell syntax clean.
- [ ] Go suite stays green: `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — no Go code touched, but run to confirm no doc-embedded test references broke (the CoS parser commit-warning test `parser_class_of_service_test.go` references the fixture, not the doc).
- [ ] Floor-calibration sanity: each per-port floor (60/40/25/25%) is strictly below the §2.1 measured value (86/63/43/41%) with margin, and the embedded Python applies the floor map correctly (extract heredoc + `python3 -m py_compile`).
- [ ] Internal consistency: the four artifacts (fairness-regimes.md, cos-simul-load-smoke.sh, the #1630 SOLO harness call-out, 1614 plan pointer) agree on (a) the simul Gate 1 being a divided-ceiling floor while ≥95% guarantee is SOLO-only, (b) the per-flow-CoV gate being the #1217 structural form with #1614 body line 113 named as dropped, (c) `C_phys` ≈ 22-24 G as the loss-cluster denominator.
- [ ] `Closes #1691` present in PR body; harness tags stripped from all GitHub-bound text; #1614 parent-issue checklist reconciled (comment or PR-body cross-link).

NO cargo build/test needed (no Rust touched). NO cluster smoke needed
(no dataplane change). State this explicitly in the PR.

## 9. Out of scope (explicitly)

- **§3.B guarantee-rate under-protection of 3g/6g** — the confirmed
  defect with unresolved mechanism. That is #1692 (instrument-first
  `/research`→`/engineer`). NO mechanism change here.
- **Any dataplane / CoS scheduler code** — `queue_service/`,
  `rotate_epoch_v8.rs`, `worker/cos/`, `coordinator/mod.rs` placement —
  all untouched.
- **Path C (rate-aware queue→worker placement)** — deferred refinement.
- **Rewriting the archival #1614 implementation plan body** — only a
  dated forward-pointer is appended.

## 10. Open questions for adversarial review (each invitable to PLAN-KILL)

v2 resolved the round-1 findings (Codex r1 #1/#2 the unsatisfiable gate
+ ungating; AGY r1 Q1 the regression floor; both on `C_phys`; Claude-SMR
r1 F1/F2 on the dropped-gate artifact + verdict annotation; Codex r1 #5
the discriminator formula; Codex r1 #6 the SOLO-gate conflation). Open
for r2:

1. **Are the divided-ceiling floors (60/40/25/25%) calibrated right?**
   They sit below §2.1 (86/63/43/41%) with ~30% margin. Too tight risks
   run-to-run flake on a doc-only smoke; too loose misses a partial
   regression. Is the margin defensible, or should the floor be derived
   as a fraction of the LAST GREEN run instead of a hardcoded constant?
2. **Is `C_phys` the right abstraction**, or does naming a symbol for a
   single measured number over-formalize a hardware artifact? The doc
   footnotes 22-24 G as the loss-cluster value — is that enough scoping?
3. **Does the rescope leave any flat per-flow-CoV gate un-neutralized?**
   v2 names #1614 body line 113 as the dropped artifact. Confirm no
   other harness/doc/issue still asserts a flat per-flow-CoV bar.
4. **Is the starvation 3-condition discriminator operationally
   measurable** from the existing smoke `verdict.json` + control-socket
   counters, or does it require data the operator does not have at
   smoke time (making it a #1692 concern, not a Path B deliverable)?
5. **Should the parent #1614 checklist be edited directly** (it is the
   gate SSOT the task names) or only reconciled via a comment + the
   live `fairness-regimes.md` SSOT? Is appending to the archival #1614
   PR plan the right discipline, or leave it untouched?
