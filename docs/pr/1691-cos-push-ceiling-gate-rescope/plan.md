# #1691 — CoS Path B: document the ~22-24 G push-ceiling division + re-scope #1614 acceptance gates

Status: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude-SMR)
Branch: refactor/1691-cos-push-ceiling-gate-rescope
Base: origin/master @ 7988d4c25

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
  - **This is the bug the rescope fixes.** The research §3.B (and §2.4
    small4+24g) measured 3g/6g at ~54%/51% under simul contention —
    they are NOT honored. That under-protection is a CONFIRMED defect
    with an UNRESOLVED mechanism, deferred to instrument-first #1692.
    Gate 1 as written would FAIL on master today and conflates the
    real (settled) small-class guarantee (100m/1g) with the §3.B defect
    (3g/6g). Asserting a number the production daemon cannot hit, for a
    reason that is a separate open issue, is exactly the unsatisfiable
    bar the research flags.
  - The harness COMPUTES `cov_pct` per class but does NOT gate on it —
    there is no per-flow-CoV pass/fail in the harness code. So the
    per-flow-CoV "drop" is a doc/charter action, not a harness code
    deletion. The harness change is narrowing Gate 1 to the classes the
    contract actually guarantees under simul load.
- Gate 2 (`gate_2_priority_low_min_share`) and Gate 3
  (`gate_3_retrans_floor`) are unaffected by this rescope.

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
to add a subsection (placed right after the
"oversubscription-policy" intro, before "Acceptance gates"):

> **### Aggregate push ceiling is the per-class denominator (#1578/#1614 §3.A)**
>
> The push-direction forwarding throughput of the loss userspace
> cluster pins at **~22-24 G aggregate** regardless of how many CoS
> classes are backlogged (#1578 forwarding/TX ceiling). This is
> RX→forward→TX capacity, NOT a CoS scheduler limit: `park_root = 0`
> everywhere in the #1614 capture, so the 25 G root token bucket never
> throttles — the limiter is upstream of the root token gate.
>
> The denominator every class divides is this ~22-24 G, NOT the sum of
> configured `transmit-rate`. On the `cos-iperf-config.set` fixture the
> configured exact-shape sum is **109 G — 4.5× the delivery ceiling**,
> so strict-exact is not simultaneously deliverable (the A4 commit
> warning, #1618, fires on exactly this `sum_exact > shaping_rate`
> condition). When N classes are simultaneously backlogged, the
> ~22-24 G divides among them; per-class %-of-shape therefore drops as
> N rises. Measured competitor-count sweep (#1614 §2.4): 3g reaches
> 94% solo, 69% with one competitor, 54% with four — the deficit is
> set by HOW MANY classes are backlogged, not by 3g's owner worker.
> 18g pushed 14.25 G from a single owner worker (`park_root=0`), so the
> ceiling is an aggregate property, not a per-worker funnel.
>
> **Reading divided-ceiling as starvation is a misread.** A class at
> 22% of its configured shape under 11-class simul load is consistent
> with the ceiling-division physics; it is a starvation SIGNAL only if
> it falls below its guarantee-rate-protected share with measurable
> aggregate headroom (the #1614 §3.B case, tracked separately in
> #1692).

Also adjust the Phase 0 note (lines ~1120-1124) so it cross-references
this as the push-direction equivalent of the 22.72 G reverse number,
making it clear both directions hit the same ~22-24 G physics ceiling.

### Edit set 2 — gate rescope (commit 2)

**`docs/fairness-regimes.md` "Acceptance gates under guarantee-rate
mode":**

1. Rewrite Gate 1 to scope the small-class absolute guarantee to the
   classes the contract actually honors under simul load — **100m and
   1g** (the two protected by `guarantee-rate 0.7` small-first per the
   #1614 §2.4 small4+24g measurement: 100m=94%, 1g=94%). Add an
   explicit note that 3g/6g under-protection under multi-class
   contention is a CONFIRMED-but-mechanism-UNRESOLVED defect tracked in
   #1692 and is NOT asserted by this gate until that issue resolves —
   with a cross-reference to the divided-ceiling subsection.
2. Add an explicit statement that the **flat per-flow-CoV gate
   (≤ 5/10%) is DROPPED**: per #1220/#1244 the per-flow CoV within a
   class is structural (≈ Cstruct), so the ONLY per-flow fairness gate
   is the #1217 `observed_CoV ≤ Cstruct + 0.05` structural contract
   already stated above. Cite #1220/#1244 by issue number.
3. State that per-class %-of-shape gates are bounded by the §3.A
   ceiling — gates may not assert per-class numbers whose sum exceeds
   ~22-24 G.

**`test/incus/cos-simul-load-smoke.sh` Gate 1:** narrow the
`gate_1_small_class_guarantees` port set from `(5201, 5202, 5203,
5204)` to `(5201, 5202)` (100m, 1g only), and rewrite the comment to
cite the #1614 §3.B / #1692 deferral and the divided-ceiling reason
3g/6g are not gated under simul load. Keep computing and REPORTING
3g/6g %-shape (visibility), just stop gating on them. No change to
Gate 2 / Gate 3 / the reverse Gate 8.

**`docs/pr/1614-multi-rss-cos/plan.md`:** append a dated "#1614
research rescope (Path B / #1691)" pointer block at the END of the §7
gate list (do NOT rewrite the historical criteria in place) recording:
3g/6g simul guarantee deferred to #1692; per-flow-CoV gate is the
#1217 structural form (flat bar dropped); per-class gates bounded by
the §3.A ceiling. SSOT for the live contract is `fairness-regimes.md`.

## 5. Public API preservation

No code API. The smoke harness's `verdict.json` schema is preserved:
`gate_1_small_class_guarantees` keeps its shape (`classes[]` + `pass`)
— only the membership of the gated port set changes. Gates 2/3/8
byte-identical. Any consumer reading the verdict keys still finds them.

## 6. Hidden invariants the change must preserve

- **Gate 1 must still catch a real 100m/1g regression.** Narrowing to
  5201/5202 keeps the two classes whose guarantee IS contractually
  honored (#1614 §2.4) under the ≥95% bar. A regression that drops
  100m or 1g below 95% under simul still fails. We are removing a bar
  the daemon provably cannot meet for a reason that is a separate open
  defect — not removing real coverage.
- **3g/6g visibility preserved.** The harness keeps computing and
  printing 3g/6g %-shape so the #1692 instrument-first round can read
  the numbers; only the pass/fail assertion is removed.
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
| Behavioral regression | LOW | No code path changed; smoke gate narrowed to classes the daemon honors. Zero dataplane edit. |
| Lifetime / borrow-checker | N/A | No Rust touched. |
| Performance regression | NONE | No hot-path / control-path code change. Docs + one Python gate tuple + comments. |
| Architectural mismatch (#961/#946-P2) | LOW | This is the research's own recommended Path B "do first"; it documents physics rather than asserting a mechanism. The only mismatch risk is mis-stating the contract — which is the explicit PLAN-KILL criterion. |
| Coverage-loss risk | MED→reviewed | Narrowing Gate 1 could mask a real 3g/6g improvement/regression. Mitigated: 3g/6g stay reported (not gated), and #1692 owns their gate. Reviewers must confirm this does not hide a regression that today's Gate 1 would catch. |

## 8. Test plan

This is control-plane docs + a test-harness gate tuple. No cluster
smoke is required (no dataplane change) — stated explicitly per the
task charter. Gates:

- [ ] `python3 -c "import ast; ast.parse(open('test/incus/cos-simul-load-smoke.sh'...))"` — the embedded Python in the smoke script parses (it is a heredoc'd `python3 - <<PY`; validate by extracting and `python3 -m py_compile`, or run `bash -n` on the script).
- [ ] `bash -n test/incus/cos-simul-load-smoke.sh` — shell syntax clean.
- [ ] Go suite stays green: `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — no Go code touched, but run to confirm no doc-embedded test references broke (the CoS parser commit-warning test `parser_class_of_service_test.go` references the fixture, not the doc).
- [ ] Internal consistency: the three artifacts (fairness-regimes.md, smoke harness, 1614 plan pointer) agree on (a) which classes Gate 1 covers, (b) the per-flow-CoV gate being the #1217 structural form, (c) the ~22-24 G ceiling as denominator.
- [ ] `Closes #1691` present in PR body; harness tags stripped from all GitHub-bound text.

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

1. **Is narrowing smoke Gate 1 from {100m,1g,3g,6g} to {100m,1g} the
   right move, or does it hide a regression?** The research says 3g/6g
   are a separate confirmed defect (#1692); but is removing the
   pass/fail assertion the correct action, or should the gate instead
   assert a LOWER (divided-ceiling) bar for 3g/6g so a *further*
   regression below ~52% still trips? PLAN-KILL if removing the
   assertion entirely loses necessary regression coverage.
2. **Is the ~22-24 G "physics" framing defensible as a documented
   contract number, or is it a single-cluster artifact** that should
   not be enshrined in `fairness-regimes.md` as a denominator? The
   research measured it on `loss:` only.
3. **Does the doc rescope correctly characterize the per-flow-CoV
   drop?** The doc already uses the #1217 structural form, not a flat
   bar. Is there any remaining flat per-flow-CoV gate anywhere
   (harness, plan, issue body) that this rescope fails to neutralize,
   making the "drop" incomplete?
4. **Is appending a pointer to the archival #1614 plan the right
   discipline**, or should that doc be left entirely alone (SSOT purely
   in fairness-regimes.md)?
5. **Divided-ceiling vs starvation discriminator.** The doc says a
   class is starved "only if it falls below its guarantee-rate-protected
   share with measurable aggregate headroom." Is that discriminator
   precise enough to be useful to an operator, or does it just restate
   #1692's open question? PLAN-KILL if the framing is circular.
