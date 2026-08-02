# Codex adversarial plan-review — round 92 (plan v95 @ ddfd4e52203b)

Codex companion task-msbfwx7e-rypblq (session 019fc13c-2caf-7cc0-b128-d2a1b12dbc50). Verdict: PLAN-NEEDS-MINOR (2 documentation-only minors, NO MAJOR — "neither requires an architectural, synchronization, or oracle redesign"): m1 MULTI-ACCESS still does not define the claimed 17/24 partition (Compile's only direct selector is compiler.go:353; seedInterfaceCounter's only selector is loader.go:591 — the transitive interpretation fails because Compile composes with clearNativeXDPFlagsForIfindexes at compiler.go:399 while that helper's selector loader.go:928 sits in the single-selector set; the accurate wording is "15 sites in multi-selector methods plus two single-selector sites composed into multi-access operations"); m2 the normative optional-outcome rule omits the comma-ok early-return shape (the generic rules enumerate only silent/if-ok skip, nil-guard return, and skip-and-continue at :5171/:5182, while the same block correctly recognizes loader.go:700's comma-ok early return — a fourth shape). Fold-free passes: the exact 14+2+1 split matches the code; all four counterexample methods individually fit MULTI-ACCESS (2/2/3/2 selectors, none error-returning); SINGLE-ACCESS-SELECTOR landed everywhere normative; the census exact (130+5=135 = 91+41+3); no further A3/§7/§9 contradiction, oracle gap, G+H+H2 leakage, or PR-1 design regression. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MINOR

Two documentation-only inconsistencies remain. Both are inside PR-1 and block formal `PLAN-READY`; neither requires an architectural, synchronization, or oracle redesign.

1. **MINOR — `MULTI-ACCESS` still does not define the claimed 17/24 partition.**

   The plan says all 17 sites occur in methods with more than one registry access ([plan.md:5203](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5203)), with the remainder forming the single-selector set ([plan.md:5212](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5212)). Under A3’s direct-access semantics ([plan.md:3838](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3838)), two listed sites are counterexamples:

   - `Manager.Compile` has only one direct registry selector, [compiler.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353).
   - `seedInterfaceCounter` contains only [loader.go:591](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:591), despite being placed in the 17-site set at [plan.md:5242](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5242).

   A transitive interpretation cannot rescue it: `Compile` calls `clearNativeXDPFlagsForIfindexes` at [compiler.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:399), while that helper’s selector at [loader.go:928](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:928) remains assigned to the single-selector set.

   Accurate wording would be “15 sites in multi-selector methods plus two single-selector sites composed into multi-access operations,” or another property that genuinely defines the 17-site subset.

2. **MINOR — the normative optional-outcome rule still omits the comma-ok early-return shape.**

   The generic rules enumerate only silent/if-ok skip, nil-guard return, and skip-and-continue ([plan.md:5171](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5171), [plan.md:5182](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5182)). Yet the same block correctly recognizes [loader.go:700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700) as a distinct comma-ok early return. It fits none of the three stated forms. Add that fourth outcome or make the list explicitly non-exhaustive.

Everything else passes:

- The exact `14 + 2 + 1` split and bucket summary match the code.
- All four requested counterexamples individually fit `MULTI-ACCESS`: `DeleteStaleStaticNAT` has 2 selectors, `DeleteStaleNAT64` 2, `ZeroStaleNATPoolConfigs` 3, and `SessionCount` 2; none returns an error.
- `SINGLE-ACCESS-SELECTOR` landed everywhere normative; old names are attributed history.
- Census is exact: `130 m.maps + 5 m.programs = 135`, comprising `91 required + 41 optional + 3 writes`.
- No further A3/§7/§9 contradiction, oracle gap, G+H+H2 leakage, or PR-1 design regression was found.

**Yes: findings 1–2 block `PLAN-READY` for #2114 PR-1 at v95.**

Codex session ID: 019fc13c-2caf-7cc0-b128-d2a1b12dbc50
Resume in Codex: codex resume 019fc13c-2caf-7cc0-b128-d2a1b12dbc50
