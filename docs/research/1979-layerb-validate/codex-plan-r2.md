# Codex hostile plan re-review r2 — #1979 Layer B

**Verdict: PLAN-NEEDS-MINOR** (no architectural blocker; both r1 MAJORs resolved)

Reviewed source against `origin/master` at `7c3905c9e`.

## r1 MAJORs — confirmed resolved in v2

- **Hook architecture (#2):** resolved. v2 specifies `validateTCPMSSRanges`
  beside `validateVRRPTrackInterfaceAST` as a COMPILER AST pre-walk in
  `compileExpanded` (compiler.go:260), NOT a `SchemaValidate` hook.
  `SchemaValidateWithDefinitions` still only walks `setSchema`
  (schema_walk.go:70) and `tcp-mss` is still opaque (schema_security.go:221) —
  so the compiler pre-walk is the correct and existing hook point.
- **Parse precedence (#3):** resolved. v2 validates the compiler-SELECTED value
  (child `mss` first if parseable, else flat `Keys[1]`) with a shared selector
  and mixed-shape tests, matching `parseMSSValue` (compiler_interfaces.go:729);
  the four callers are only the `tcp-mss` arms (compiler_security.go:655).
- **Sampling drift (#5):** resolved as an explicit user decision — v2 presents
  `[1,u32max]` vs `[0,u32max]` in Q3 and recommends `[0,u32max]`. Source
  confirms `InputRate 0 = sample all` (types_system.go:569) and Layer A
  normalizes `rate <= 0 → 1` (flow.go:138).
- **#4 flow-server / #6 version-ipfix / #7 completion scope:** resolved — v2
  scopes the grouping flip to bare terminal `flow-server <addr>`, treats
  version-ipfix typing as UX parity (excluded from the Layer-A-agreement test),
  and limits the completeness claim to expanded nodes (`syn-flood-protection-mode`
  called out as pre-existing, out of scope).

## MINOR fixes required (folded into v3)

1. §8 test-plan item 1 said "for EVERY leaf use `SchemaValidate`" — false for
   Tier 3 by design (`tcp-mss` opaque). **Fix (v3):** item 1 now routes Tier-3
   accept/reject through `CompileConfig`/`compileTreeStrict`, reserving
   `SchemaValidate` for the Tier-1/2 typed leaves.
2. §8 item 5 Layer-A agreement invariant ("every value Layer B accepts is left
   unchanged by Layer A") conflicts with the Q3 `[0,u32max]` default (sampling
   `0` accepted but normalized to `1`). **Fix (v3):** reworded to the
   directional "Layer B never rejects a value Layer A accepts", with sampling
   `0 → 1` documented as the explicit normalization exception.

Codex: "No new architectural blocker found. These are doc/test-contract
cleanups, not a reason to kill the plan." With both folded, v3 is PLAN-READY.
