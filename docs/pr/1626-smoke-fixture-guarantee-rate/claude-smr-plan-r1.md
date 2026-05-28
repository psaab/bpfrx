# Claude SMR plan review r1 — #1626

Reviewer profile: domain SMR for Junos CoS config syntax, smoke
harness design, measurement validity, CPU arch / SW design patterns.

## Verdict: PLAN-NEEDS-MAJOR (revised from initial PLAN-READY after AGY+Codex r1)

**Self-correction**: I initially rated PLAN-READY. AGY (5 findings) +
Codex (concur on all 5 + 2 new) both correctly found PLAN-NEEDS-MAJOR
issues I missed:

- F1: `show configuration` default is hierarchical not flat-set. My
  grep assertion would have failed in real use. I claimed it was
  "trivially correct" without verifying CLI output format. Bad call.
- F2: Plan body has BOTH "rolls back if either fails" (§6) and "only
  roll back if both fail" (§9) — direct contradiction I should have
  caught on re-read.
- F4: I cited `0.7 × 18 = 12.6 G` but the fixture's shaping-rate is
  25g; budget is 17.5 G. Math copy-pasted from #1614 v5 worked example
  without re-anchoring to actual fixture parameters.
- F5: Hard-coded flag skip is fragile and couples logic to fixture
  names.
- F6 (Codex new): the "belt-and-suspenders" mitigation is backwards.
  Same root as F2.
- F7 (Codex new): test plan §11 mentions `go vet` but §8 only lists
  `go test`.

I move my verdict to **PLAN-NEEDS-MAJOR concurring with AGY+Codex**.
SMR-plan-r2 will verify v2 addresses all 7 findings.

## Original-r1 verdict (kept for record): PLAN-READY (non-blocking refinements)

## Evidence — what I verified directly

1. **Bug exists on master**.
   `grep oversubscription test/incus/cos-iperf-config.set` returns no
   match. The fixture currently has zero lines that activate the new
   knob. The compiler path at
   `pkg/config/compiler_class_of_service.go:339-380` only sets
   `unit.OversubscriptionPolicy` if the `oversubscription-policy` node
   exists. Absent that node, `unit.OversubscriptionPolicy == ""` which
   the compiler treats as `proportional (default)`
   (`pkg/config/compiler.go:1097`). So PR #1618's smoke was indeed
   measuring proportional mode regardless of the new wire surface.

2. **Junos syntax is correct**.
   `pkg/config/parser_class_of_service_test.go:936` uses precisely
   `set class-of-service interfaces ge-0/0/2 unit 80
   oversubscription-policy guarantee-rate 0.7` and asserts the typed
   config picks it up. The parser FLAT path
   (`compiler_class_of_service.go:340-356`) handles
   `Keys[1]=="guarantee-rate"`, `Keys[2]==<float>` which is exactly
   what `ParseSetCommand` produces from the proposed line. Interface
   name `reth0` vs `ge-0/0/2` is irrelevant — the lookup is by string
   in `cos.Interfaces` map, the policy is keyed off the unit
   sub-struct.

3. **0.7 is the right fraction**.
   `docs/pr/1614-multi-rss-cos/plan.md:300` uses 0.7 as the worked
   example (`pass1_budget = 0.7 × 18 = 12.6 G`). The plan v5
   acceptance criteria gate 1 (small classes ≥ 95%) was sized for 0.7.
   The compiler warning text at
   `pkg/config/compiler.go:1100` is `guarantee-rate %g`, so 0.7 emits
   literal `guarantee-rate 0.7` which Phase-3.5 assertion can grep
   for.

4. **Compiler warning fires unconditionally on this fixture**.
   The fixture sum of exact-class rates is
   100m+1g+3g+6g+9g+12g+15g+18g+21g+24g = 109g (omitting BE +
   uncapped which aren't `exact`). Shaping-rate is 25g. 109g > 25g →
   warning fires unconditionally. The Phase-3.5 (B) check on the
   warning is robust.

5. **Phase-3.5 (A) assertion is robust**.
   `show configuration class-of-service` is a round-trip serialization
   of the active config tree. The fixture line we add will appear
   verbatim in that output (per Junos CLI convention — verified by
   reading `pkg/cli/cli.go:245-246` + `showConfigurationSubPath`).
   Trivially correct as an assertion.

6. **--same-class and --symmetric fixtures aren't broken**.
   The plan correctly notes the assertion is gated on the chosen
   fixture. Inspecting the apply script lines 64-72 (the
   `CONFIG_FILE` selector): the new Phase-3.5 assertion can be guarded
   by `if [[ "$SAME_CLASS" -eq 0 && "$SYMMETRIC" -eq 0 ]]` so the two
   alternate fixtures don't trigger it. The plan's section 6 calls
   this out; the implementer needs to remember to actually gate it.

7. **Smoke harness gates 1+2 are designed for guarantee-rate mode**.
   `cos-simul-load-smoke.sh:179-198` comments say "if guarantee-rate
   mode active, each [small class] should hit ≥ 95% of rate" — gate 1
   pre-supposes the knob is on. Gate 2 is "priority-low ≥ 5% of
   cluster ceiling" — also a guarantee-rate-specific bound. So the
   existing gate logic is the RIGHT downstream check; we don't need
   to change it.

## Issues / refinements

### r1.1 (NIT, non-blocking) — assertion gating must be implementation-explicit

Plan section 6 says "Skip the assertion for the `--same-class` and
`--symmetric` fixtures". Make sure the actual implementation uses a
bash `if` on `$SAME_CLASS`/`$SYMMETRIC` AROUND the new assertion, not
just a comment. Otherwise a future `--same-class` operator would hit
spurious rollback. I'll verify this in code-review r1.

### r1.2 (NIT, non-blocking) — assertion should run BEFORE the existing rollback decision

The existing Phase-3 check (line 187-203) is "if no shaper/scheduler
match → rollback". The new Phase-3.5 must run after Phase-3 passed,
NOT before, to preserve the existing safety net for the broader case.
Plan section 6 says "after the existing grep" — good, just confirm
ordering in the diff.

### r1.3 (MINOR observation, no action required)

The `show class-of-service interface` presenter at
`pkg/dataplane/userspace/cosfmt.go:74-200` does NOT render
oversubscription-policy. That's the right call for #1626 scope —
adding it to the presenter is a separate UX issue. But it means
operators who run `show class-of-service interface` today can't see
the active policy. Worth a follow-up issue (NOT in this PR).

## Cross-cutting considerations

- **HA peer state**: VRRP/RG sync replicates the config — the
  secondary will pick up the same policy line after commit. No HA
  concern.
- **Apply-script atomicity**: the existing two-phase commit-check +
  commit pattern is preserved. The Phase-3.5 verification runs AFTER
  commit succeeded, so a Phase-3.5 failure triggers `rollback 1 |
  commit` per the existing safety net.
- **Smoke serialization**: cluster shared with #1620+#1621, #1623
  Path B. Coordinate via AWAITING-BATCH-MERGE marker if smoke contention.
- **Failure mode if Phase-3.5 catches a regression**: rollback brings
  the cluster back to whatever was committed before. Existing Phase-3
  rollback hook covers this; new assertion just adds a second
  trigger.

## Conclusion

Plan is sound and the scope is honest. The runtime change is zero LOC,
the diagnostic value is high (it determines whether #1614 step-1 was
a real regression or a measurement bug). I will verify the two
implementation NITs (r1.1 gating + r1.2 ordering) at code-review time.

**PLAN-READY** pending Codex + AGY concur.
