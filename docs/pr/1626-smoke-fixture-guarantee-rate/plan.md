# #1626 — Fix `cos-iperf-config.set` to activate `oversubscription-policy guarantee-rate`

Branch: `fix/1626-smoke-fixture-guarantee-rate`
Base: `origin/master` @ `4ac85e2fd`

## 1. Problem statement

The simul-load smoke harness shipped in PR #1618 (#1614 step-1) reports
per-class equalization (~20%/class). I framed that as evidence the
waterfill scaffold doesn't change distribution. The #1625 PLAN-KILL
quad-review surfaced the real explanation: **the fixture itself
doesn't activate the `guarantee-rate` knob it was supposed to test**.

Concrete bug — `test/incus/cos-iperf-config.set` on master:
```
$ grep -n "oversubscription" test/incus/cos-iperf-config.set
$ # empty — the line that opts the unit into guarantee-rate mode
$ # is missing
```

Without `set class-of-service interfaces reth0 unit 80
oversubscription-policy guarantee-rate <X>`, the compiler defaults to
`proportional` mode (see `pkg/config/compiler_class_of_service.go:339`
+ `pkg/config/compiler.go:1097-1108`). So the entire #1614 step-1
measurement was testing the pre-existing proportional path — same as
master before the wire surface shipped. The waterfill scaffold's
runtime branch never executed under the smoke.

## 2. Scope

**In-scope (small surgical fixture+harness change):**
1. Add one `set` line to `test/incus/cos-iperf-config.set` that
   activates `guarantee-rate 0.7` on `reth0 unit 80` (the unit the
   fixture already targets via `shaping-rate 25g` + `scheduler-map
   bandwidth-limit`).
2. Add a runtime-assertion in `apply-cos-config.sh` (post-apply) that
   verifies the running config actually has `oversubscription-policy
   guarantee-rate` set. Catches future regressions of "fixture forgot
   the knob" + parser drops + dataplane fails to apply.
3. Run the smoke and document the per-class distribution under the
   activated knob in the PR body.

**Out of scope (per issue body + memory):**
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs` Phase-2 lock-in
  bug from #1625 kill — separate issue (file #1627 if needed).
- `shared_cos_lease/rotate_epoch_v8.rs` lease scheduling.
- Any new trace-counter instrumentation — that's #1628's territory.
- Multi-RSS multi-core CoS architecture — #1614 umbrella.
- Adding `oversubscription-policy` rendering to `show class-of-service
  interface` (separate UX issue; we use `show configuration
  class-of-service` or the commit warning for the assertion).

## 3. Honest value framing

- **LOC**: ~2 lines in `cos-iperf-config.set` (the policy line + maybe
  a blank for grouping), ~6-10 lines in `apply-cos-config.sh` for the
  verification step.
- **Runtime code change**: 0 LOC. The wire surface, parser, compiler
  warning, and runtime are unchanged.
- **Diagnostic value**: HIGH. This is the gate that determines
  whether the #1614 step-1 ship is a measurement bug (and the
  algorithm works once the knob is on) OR the algorithm is broken in
  the way #1625 reviewers suspected (Phase-2 lock-in at
  queue_service/mod.rs:889-893; worker_fair_share math). The next-
  priority bug fix (#1627) only makes sense after this fixture fix
  produces a clean before/after measurement.

## 4. Junos syntax — verified

Confirmed against `pkg/config/parser_class_of_service_test.go:936`
(`TestValidateCoSOversubscriptionWarningGuaranteeRate`):
```
set class-of-service interfaces ge-0/0/2 unit 80 oversubscription-policy guarantee-rate 0.7
```

Our fixture uses the RETH form (`reth0` not `ge-0/0/2`), unit 80.
Compiler accepts both interface name forms (`reth0` literal lookup in
`cos.Interfaces`).

**Fraction choice**: 0.7 per the #1614 plan v5 worked example
(`docs/pr/1614-multi-rss-cos/plan.md:300` — `pass1_budget = 0.7 × 18 =
12.6 G`). This matches what the v5 acceptance criteria expects the
distribution to look like, so the smoke harness gate 1 (small classes
≥ 95% of configured rate) is the correct downstream check.

## 5. Where the line goes in the fixture

The existing fixture sets per-interface CoS on `reth0 unit 80`:
```
set class-of-service interfaces reth0 unit 80 scheduler-map bandwidth-limit
set class-of-service interfaces reth0 unit 80 shaping-rate 25g
```
I add the policy line directly after `shaping-rate 25g`:
```
set class-of-service interfaces reth0 unit 80 oversubscription-policy guarantee-rate 0.7
```

This is the same unit/interface tuple the rest of the fixture targets,
and the policy lives on the unit struct (`pkg/config/types.go:556`),
so attaching it here is parser-correct.

## 6. Runtime assertion in `apply-cos-config.sh`

Current Phase 3 verification (lines 167-180) greps `show
class-of-service interface` for `shaper|scheduler|traffic-control-
profile|output.*traffic`. That doesn't catch the missing-knob bug
because the scheduler bindings still show up — the policy lives on a
different (oversubscription) path that the show-interface presenter
doesn't render today.

Two viable assertion points:

A. **Grep `show configuration class-of-service`** — the canonical
   round-trip serialization. The line we just set should appear
   verbatim. Robust because it doesn't depend on any presenter
   surface.

B. **Grep the commit warning output** —
   `pkg/config/compiler.go:1097-1108` emits a one-line warning of the
   form `class-of-service interfaces reth0 unit 80: ... configured
   oversubscription-policy=guarantee-rate 0.7: ...`. But this requires
   capturing the commit transcript; the existing Phase-2 apply uses
   `> "$APPLY_OUT" 2>&1` so the transcript is already on disk.

Choice: **(A) + (B) belt-and-suspenders**. (A) verifies the
config-tree was set (catches parser/CLI bugs). (B) verifies the
compiler accepted it and emitted the warning (catches compiler
regressions). If either fails the apply rolls back per the existing
Phase-3 rollback hook.

The assertion is added as a new Phase-3.5 step after the existing
`shaper|scheduler|traffic-control-profile` grep, so we don't
regress the existing check. Skip the assertion for the `--same-class`
and `--symmetric` fixtures which don't (yet) set guarantee-rate.

## 7. Smoke flow and what we expect to see

After deploy + apply with the fixed fixture:

1. **Pre-condition check** (in the apply script):
   - `show configuration class-of-service` contains `oversubscription-
     policy guarantee-rate 0.7`. PASS expected.
   - Apply transcript contains the
     `oversubscription-policy=guarantee-rate 0.7` compiler warning.
     PASS expected (sum of exact-rates 109g > shaping-rate 25g per
     existing fixture, so the warning ALWAYS fires).

2. **Smoke run**:
   `./test/incus/cos-simul-load-smoke.sh push` →
   capture `verdict.json`. Compare `recv_gbps` per class against the
   broken-baseline measurement from PR #1618 (also ~20%/class).

3. **Two possible outcomes:**
   - **Algorithm works**: distribution shifts. Small classes (100m/1g/
     3g/6g) honoured to ≥ 95% (gate 1 passes). Large classes share
     residual proportionally. iperf-uncapped ≥ 5% of ceiling (gate 2).
     → confirms #1625 kill was correct; no new scheduler mechanism
     needed.
   - **Algorithm still equalizes**: distribution unchanged. Small
     classes still get their proportional ~20% share. → confirms one
     of #1625's other findings (queue_service/mod.rs:889-893 Phase-2
     lock-in OR worker_fair_share math). File #1627 with the
     measurement evidence as the next-priority fix.

The PR body documents WHICHEVER outcome we get. The PR is
"diagnostic-fixture-correctness" not "fix-the-scheduler", so we ship
the fixture fix + measurement regardless of which outcome.

## 8. Test plan

- **Go**: `go test ./pkg/config/...` — should be unaffected; we
  already have `TestValidateCoSOversubscriptionWarningGuaranteeRate`
  exercising the exact line we add.
- **Rust**: `cargo build --release` in `userspace-dp/` — no Rust
  changes; smoke check only.
- **Apply script unit-ish**: run the modified
  `apply-cos-config.sh` against the smoke cluster fw0 and confirm:
  - Existing Phase-3 check still PASSes
  - New Phase-3.5 check PASSes with the fixed fixture
  - New Phase-3.5 check FAILs (and rolls back) if we temporarily
    remove the new line from the fixture (manual sanity)
- **Cluster smoke (loss userspace)**: deploy → apply → run
  `cos-simul-load-smoke.sh push` → capture verdict.json → diff
  per-class achievement vs broken-baseline.

## 9. Risk assessment

- **Rollback risk**: the new Phase-3.5 assertion adds a NEW
  rollback trigger. If the assertion is wrong (false-positive),
  we'd roll back a good config. Mitigation: belt-and-suspenders
  (A+B); only roll back if BOTH fail. A literal `oversubscription-
  policy guarantee-rate 0.7` grep against `show configuration` is
  trivially correct.
- **Fixture compatibility**: adding the line shouldn't break the
  existing fixture for any other consumer. The line is OPT-IN and
  only fires the warning + activates the guarantee-rate branch when
  sum_exact > shaping_rate (already true here).
- **Smoke harness gate drift**: the existing
  `cos-simul-load-smoke.sh` push-direction gates 1+2 were written
  for the guarantee-rate path. Activating the knob ENABLES them to
  pass — not breaks them. If they don't pass, that's diagnostic
  signal not regression.

## 10. Open questions for reviewers

1. **Fraction value** — 0.7 per the v5 worked example, or different
   number? 0.7 keeps small classes fully honoured and gives large
   classes their fair share of residual. Lower (0.4) would be a
   harsher test of the algorithm; higher (0.9) is less interesting.
   Decision: **0.7** — matches plan v5 worked example, harness gate 1
   thresholds, and the warning string the existing parser test
   asserts.
2. **Where to put the assertion** — apply script (entry point) vs
   smoke harness (consumer)? Apply is better: it catches both
   smoke-harness use AND any future use of the fixture by another
   harness (failover, surplus-sharing diagnostic, etc.). Decision:
   **apply script**.
3. **Symmetric/same-class fixtures** — should they also activate
   guarantee-rate? Out of scope for #1626. Those fixtures target
   different test purposes (mirror-flow CoS coherence in #1250,
   same-class echo override in #929). If/when their tests need
   guarantee-rate they'll get their own fixture lines. The Phase-3.5
   assertion gates on the chosen fixture, not all of them.

## 11. Rollout / sequence

- Implement: ~2 line .set + ~10 line apply assertion.
- Build: `go vet ./...` + `go test ./pkg/config/...`.
- Smoke: deploy + apply on loss:xpf-userspace-fw0 + run
  `cos-simul-load-smoke.sh push` (+ optionally reverse). Capture
  verdict.json + per-class table.
- PR: body MUST include before/after per-class table and the verdict.
- Auto-merge gate: 4-of-4 reviewer attestation (Codex + AGY + Copilot
  + Claude SMR) + smoke pass on the loss userspace cluster.
