# #1626 — Fix `cos-iperf-config.set` to activate `oversubscription-policy guarantee-rate`

Branch: `fix/1626-smoke-fixture-guarantee-rate`
Base: `origin/master` @ `4ac85e2fd`

## Revision history

- **v1** — initial plan; PLAN-NEEDS-MAJOR by AGY+Codex+Claude SMR.
  Findings F1-F7 (see `agy-plan-r1.md`, `codex-plan-r1.md`,
  `claude-smr-plan-r1.md`).
- **v2** (this version) — addresses all 7 findings; tightens
  assertion semantics, fixes math, gates by fixture content.

## 1. Problem statement

The simul-load smoke harness shipped in PR #1618 (#1614 step-1)
reports per-class equalization (~20%/class). The #1625 PLAN-KILL
quad-review surfaced the cause: **the fixture itself doesn't activate
the `guarantee-rate` knob it was supposed to test**.

Concrete bug — `test/incus/cos-iperf-config.set` on master:
```
$ grep -n "oversubscription" test/incus/cos-iperf-config.set
$ # empty — the policy line is missing
```

Without `set class-of-service interfaces reth0 unit 80
oversubscription-policy guarantee-rate <X>`, the compiler defaults to
`proportional` (see `pkg/config/compiler_class_of_service.go:339-380`
+ `pkg/config/compiler.go:1097-1108`). The #1614 step-1 smoke was
measuring proportional mode — same as master before the wire surface
shipped. The waterfill branch never executed under smoke.

## 2. Scope

**In-scope:**
1. Add one line to `test/incus/cos-iperf-config.set` that activates
   `guarantee-rate 0.7` on `reth0 unit 80`.
2. Add a Phase-3.5 assertion to `test/incus/apply-cos-config.sh`:
   - Use `show configuration class-of-service | display set` for flat
     form (F1 fix).
   - Gate the assertion on whether the chosen fixture actually
     contains an `oversubscription-policy` line — fail loudly if so
     (F5 fix).
   - Assertion semantics: **the policy line MUST appear** in
     post-commit flat-set output. That's the entire gate (F2/F3/F6
     fix — drop the fragile compiler-warning grep).
3. Run the smoke and document before/after per-class distribution
   in the PR body.

**Out of scope (per issue body + memory):**
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs` Phase-2 lock-in
  bug from #1625 kill — separate issue (file #1627 if needed).
- `shared_cos_lease/rotate_epoch_v8.rs`.
- Trace-counter instrumentation (#1628 territory).
- Multi-RSS multi-core CoS architecture (#1614 umbrella).
- Adding oversubscription-policy rendering to `show class-of-service
  interface` (separate UX issue).

## 3. Honest value framing

- **LOC**: ~1 line in `cos-iperf-config.set`; ~15-25 lines in
  `apply-cos-config.sh` for the gated assertion + helper.
- **Runtime code change**: 0 LOC.
- **Diagnostic value**: HIGH. Determines whether #1614 step-1 was a
  measurement bug (algorithm works once knob is on) OR the algorithm
  is broken (Phase-2 lock-in / worker_fair_share math).

## 4. Junos syntax — verified

`pkg/config/parser_class_of_service_test.go:936`
(`TestValidateCoSOversubscriptionWarningGuaranteeRate`) uses exactly:
```
set class-of-service interfaces ge-0/0/2 unit 80 oversubscription-policy guarantee-rate 0.7
```

Our fixture uses RETH form `reth0`. Interface lookup is by string
key in `cos.Interfaces`; same code path.

## 5. Where the line goes in the fixture

Existing fixture sets per-interface CoS on `reth0 unit 80`:
```
set class-of-service interfaces reth0 unit 80 scheduler-map bandwidth-limit
set class-of-service interfaces reth0 unit 80 shaping-rate 25g
```

We add the policy line directly after `shaping-rate 25g`:
```
set class-of-service interfaces reth0 unit 80 oversubscription-policy guarantee-rate 0.7
```

## 6. Fraction choice (F4 fix — math re-anchored to 25g shaping)

**Fraction**: 0.7. Same numerical choice as v5 plan but the worked
example must be re-anchored to the actual fixture parameters:

- Fixture `shaping-rate = 25g` on `reth0.80` (NOT 18g — that was the
  push-direction ceiling assumption from the v5 plan, not the
  configured shaping-rate).
- `pass1_budget = 0.7 × 25g = 17.5g` (NOT 12.6 G).
- Sum of small-class rates (100m + 1g + 3g + 6g = 10.1 G) fits well
  under 17.5 G → small classes fully honoured in Phase 1.
- Sum of mid-class rates that fit under 17.5 G - 10.1 G = 7.4 G
  residual: depending on order, 9g class might fit partially.

The push-direction ceiling under simul-load is ~18 G (NIC + waterfill
overhead), but the configured shaper allows up to 25 G. The
guarantee-rate algorithm computes budgets against the configured
shaper (25 G), then the actual achieved throughput is bounded by the
NIC + waterfill ceiling. So the Phase-1 budget calculation uses 25 G;
the smoke's observed distribution will be bounded by ~18 G aggregate.

What we expect at smoke time under guarantee-rate 0.7:
- Small classes (100m, 1g, 3g, 6g) all sum to 10.1 G ≪ 17.5 G budget,
  so each should be at or near its configured rate (gate 1: ≥ 95%).
- Large classes (9g+) share residual ≈ (NIC ceiling 18 G - 10.1 G) =
  7.9 G across remaining classes proportionally.

This differs from the v5-plan A1.2 table (which presumed 18 G shaper)
but the qualitative gate-1 outcome is preserved: under
guarantee-rate, small classes are honoured.

## 7. Runtime assertion in `apply-cos-config.sh`

Single-rule assertion (F2/F3/F6 fix — collapse to one durable check):

After Phase 3's existing `show class-of-service interface` grep:

```bash
# Phase 3.5: if the chosen fixture activates a guarantee-rate (or
# other oversubscription-policy) line, the running config MUST round-
# trip with that line present. Gate dynamically on the fixture
# content; do NOT couple to flag names.

FIXTURE_HAS_OVERSUB=0
if grep -qE '^set .*oversubscription-policy' "$CONFIG_FILE"; then
  FIXTURE_HAS_OVERSUB=1
fi

if [[ "$FIXTURE_HAS_OVERSUB" -eq 1 ]]; then
  OVERSUB_OUT=$(mktemp)
  trap "rm -f '$SETS_TMP' '$CHECK_OUT' '$APPLY_OUT' '$VERIFY_OUT' '$OVERSUB_OUT'" EXIT
  incus exec "$TARGET" -- /usr/local/sbin/cli -c \
    "show configuration class-of-service | display set" \
    > "$OVERSUB_OUT" 2>&1 || true

  # Extract the canonical fixture lines that match
  # ^set .*oversubscription-policy and confirm each appears in the
  # running flat-set output. Strict line-match means parser drops,
  # compiler regressions, and applied-but-not-persisted bugs all
  # surface here.
  MISSING=0
  while IFS= read -r want; do
    if ! grep -Fxq "$want" "$OVERSUB_OUT"; then
      echo "error: fixture line missing from running config:" >&2
      echo "  expected: $want" >&2
      MISSING=1
    fi
  done < <(grep -E '^set .*oversubscription-policy' "$CONFIG_FILE")

  if [[ "$MISSING" -ne 0 ]]; then
    echo "error: Phase-3.5 oversubscription-policy verification FAILED" >&2
    echo "rolling forward with 'rollback 1 | commit'..." >&2
    incus exec "$TARGET" -- /usr/local/sbin/cli > /dev/null 2>&1 <<'EOF' || true
configure
rollback 1
commit
exit
quit
EOF
    exit 7
  fi
fi
```

Properties of this design:

- **F1 fix**: uses `| display set` for flat-set form so a literal
  `grep -Fxq` will match.
- **F2/F6 fix**: single failure path — any missing fixture line
  triggers rollback. No two-mode contradiction.
- **F3 fix**: dropped the compiler-warning grep entirely. The
  running config tree is the durable contract.
- **F5 fix**: assertion is dynamically gated on whether
  `$CONFIG_FILE` contains `oversubscription-policy` lines. So
  `--same-class` (no such lines) skips automatically; if a future
  operator adds the knob to symmetric/same-class, the gate fires
  unchanged.
- **No false positives on `--surplus-sharing`**: surplus-sharing
  appends `set ... surplus-sharing` lines after the awk pass, but
  this assertion only looks at `oversubscription-policy` lines —
  surplus-sharing doesn't intersect.

The gate uses `grep -Fxq` (fixed-string exact-line) so whitespace
and partial matches can't false-pass.

## 8. Test plan (F7 fix — explicit + consistent)

- **Go**:
  - `go vet ./pkg/config/...` (consistent with §11)
  - `go test ./pkg/config/...` — should be green unaffected; the
    parser already has
    `TestValidateCoSOversubscriptionWarningGuaranteeRate` covering
    the syntax we add.
- **Rust**: no Rust source changes. `cargo build --release` in
  `userspace-dp/` is a sanity check only — the daemon must accept
  the new snapshot field, which it already does (#1614 step-1
  wire surface).
- **Apply script bench**: manually run
  `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` with
  the v2 fixture; confirm:
  - Existing Phase-3 grep still PASSes.
  - New Phase-3.5 grep PASSes.
  - Temporarily delete the oversubscription line from the fixture
    and confirm the gate FAILs (rollback fires).
- **Cluster smoke** (loss userspace): deploy → apply → run
  `cos-simul-load-smoke.sh push` → diff per-class table against
  PR #1618 broken-baseline.

## 9. Risk

- **Phase-3.5 false-positive**: gated dynamically on fixture
  content with strict exact-line `grep -Fxq`; the only way to
  false-fail is if the running-config flat-set output drifts from
  the fixture line (parser drops, compiler regression, daemon
  apply failure). All three are real bugs we WANT to catch.
- **Rollback safety**: assertion failure triggers the existing
  `rollback 1 | commit` path, same as Phase-3.
- **Fixture compatibility**: assertion is opt-in via fixture
  content, so `--same-class`/`--symmetric` are not affected. If
  `--surplus-sharing` is combined with this fixture, the
  surplus-sharing awk pass appends NEW lines but doesn't remove
  or transform the oversubscription line — the gate still passes
  because the line is still present in `$CONFIG_FILE` and in the
  running config.

## 10. Open questions (now closed by v2)

1. Fraction value → **0.7**, math re-anchored to 25g.
2. Assertion location → **apply-cos-config.sh** (entry point).
3. Symmetric/same-class fixtures → **auto-skipped via content gate**.
4. Compiler warning grep → **dropped** (F3 fix).
5. Rollback semantics → **single failure path** (F2/F6 fix).

## 11. Rollout / sequence

- Implement: 1-line `.set` change + ~25-line apply-script
  assertion.
- Build: `go vet ./pkg/config/... && go test ./pkg/config/...`
  (consistency with §8).
- Smoke: deploy + apply on `loss:xpf-userspace-fw0` + run
  `cos-simul-load-smoke.sh push` (+ optionally reverse). Capture
  `verdict.json` + per-class table.
- PR: body MUST include before/after per-class table.
- Auto-merge gate: 4-of-4 reviewer attestation (Codex + AGY +
  Copilot + Claude SMR) + smoke pass on the loss userspace
  cluster. Use `<!-- AWAITING-BATCH-MERGE -->` per
  `feedback_smoke_every_10_batch`.

## 12. Verified against r1 findings

| Finding | Status | Where |
|---------|--------|-------|
| F1 hierarchical vs flat | FIXED | §7 uses `\| display set` |
| F2 rollback contradiction | FIXED | §7 single failure path |
| F3 warning-string coupling | FIXED | §7 no warning grep |
| F4 18g vs 25g math | FIXED | §6 math re-anchored |
| F5 hard-coded flag skip | FIXED | §7 fixture-content gate |
| F6 belt-and-suspenders | FIXED | same as F2 (single path) |
| F7 go vet vs go test | FIXED | §8/§11 consistent |
