# Claude SMR plan-review r2 — #1319 typed-leaf rollout

**Reviewer:** Claude (domain SMR + SW design). Hostile pass, round 2.
**Plan under review:** plan.md v2.1 @ c0f6e5a79.
**Verdict:** PLAN-READY.

## Round-1 defects (D1-D5) — all resolved in v2/v2.1

- **D1 import cycle** — RESOLVED. PR-1 step 0 moves `ValueType` +
  constants + `Placeholder()` to `pkg/config`, aliases back in cmdtree.
  Verified: `pkg/config` does not import `cmdtree`, so the alias direction
  is sound. AGY + Codex independently confirmed.
- **D2 fields-only** — RESOLVED. PR-1 step 1 bans `children` changes and
  mandates a SetPath grouping golden test, guarding `ast_edit.go:196`.
- **D3 drop `temporal`** — RESOLVED. PR-1 step 2 drops uncompiled
  `temporal`, keeps compiled `exact` (verified compiled at
  `compiler_class_of_service.go:498,507`), with a per-modifier table.
- **D4 walker contract** — RESOLVED + extended. The contract table now
  covers args/compoundKey/midKeyword/multi/wildcard/typed-leaf/
  modifier-only/groups.
- **D5 frontend-boundary tests** — RESOLVED. PR-1 step 6 tests
  `cli.completeConfigWithDesc` + gRPC `completeConfigPairs` incl.
  trailing-space.

## Codex r2 finding (multi value-tail) — resolved in v2.1

Codex r2 correctly caught that v2's `multi` row was repeat-only and
missed the `multi && children==nil` value-tail/range continuation
(`ast_edit.go:237-244`; live shape `destination-port 20000 to 20003`).
v2.1 adds an explicit contract row that mirrors SetPath's
sibling-vs-value-tail disambiguation and defines range-tail validation
(`<lo> to <hi>` validates both, `to` is the mid-token). I independently
verified the SetPath rule at `ast_edit.go:237` and the compiler shape at
`compiler_nat.go:682` — the row is accurate. Codex r3 = PLAN-READY.

## Residual notes (non-blocking, for /engineer)

- The walker contract table is now the implementation spec; PR 1 must
  prove it by making the existing `schema_validate_test.go` cases pass
  AND adding a `destination-port`-style range case to lock the new row
  (even though destination-port is not yet a typed leaf, a synthetic
  typed-multi fixture should exercise the value-tail path).
- Per-subsystem PRs (chassis cluster first) inherit the killed Phase-3a
  range research — cite it, don't re-derive.

## Bottom line

Three-way convergence: Claude SMR PLAN-READY + Codex r3 PLAN-READY + AGY
r2 PLAN-READY. Option A, staged PR 1 (move ValueType + generic walker +
schedulers re-home + completion wiring + retire cmdtree overlay) then
per-subsystem typed leaves. No code written; awaiting `/engineer 1319`.
