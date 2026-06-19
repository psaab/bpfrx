# Claude SMR — #1979 Layer B plan review, round 2 (re-verify of v2)

**Verdict: PLAN-READY** (conditional on the one open USER DECISION, Q3 — which is
a preference, not a defect).

## r1 gaps — both folded, verified

- **Gap A (Q1 resolution):** v2 §4 + Q1 now state `parseMSSValue` has exactly
  four callers (all the `tcp-mss` switch arms) and no interface/per-unit MSS
  feeds these fields. Confirmed against my own grep. Closed.
- **Gap B (T3 hook + VRRP precedent):** v2 commits Tier 3 to a COMPILER pre-walk
  `validateTCPMSSRanges` in `CompileConfig` (compiler.go:225, the
  `validateVRRPTrackInterfaceAST` precedent), with the `lenient` flag. This is a
  real, existing hook (verified compiler.go:225 + the VRRP wiring) and is the
  right home — NOT a SchemaValidate addition (which would never reach an opaque
  `tcp-mss`). Closed.

## Codex r1 MAJORs — folded correctly (cross-checked)

- **#2 hook:** resolved as above; the plan no longer says "invoked from the
  security-flow walk." Good.
- **#3 parse-precedence:** this was the most important external catch and the
  fold is correct. v2 specifies validating the COMPILER-SELECTED value via
  `parseMSSValue`'s precedence (mss-child-first), ideally by extracting a shared
  `selectMSSToken` so the compiler and validator cannot diverge. I independently
  reproduced the trap: `gre-in 70000 { mss 1360 }` compiles `TCPMSSGreIn=1360`
  (child wins; flat 70000 discarded), so "validate both" would false-reject a
  valid config. The shared-selector design eliminates the divergence risk
  entirely. Strong.

## AGY r1 minors — folded, with one verified downgrade

- Shorthand keys: spelled out fully in §5/§6. Good.
- BPF u32 truncation: I verified AGY's cited cast (compiler.go:1006-1012) routes
  to `SetFlowTimeout`, whose live userspace impl is a NO-OP STUB (loader.go:391).
  Dead path. `[0, MaxDurationSeconds]` is correct for the u64 wire timeouts;
  AGY's `[0,u32max]` would have been WRONG there (Layer-A/B disagreement). v2's
  Q8 captures this as a noted-no-action dead-path. Correct call.

## The strict/lenient split (my v1.2 find) — load-bearing, well-pinned

v2 §5 makes the boot/HA-safety split a first-class constraint: Tiers 1+2 inherit
the lenient downgrade for free (store.go:488); Tier 3 `validateTCPMSSRanges` MUST
take the `lenient` flag or a legacy out-of-range MSS blackout-boots an upgraded
node. The mandatory test (plan item 6) pins both legs. This is exactly the kind
of thing that would have bitten /engineer silently; good that it is explicit.

## The one open item — Q3 (sampling rate), NOT a blocker

Q3 (`[0,u32max]` exact-mirror vs `[1,u32max]` reject-0 UX) is a genuine
preference the user should pick. The plan defaults to `[0,u32max]` (exact Layer-A
agreement), which I endorse — it keeps the §6 "Layer B must not reject what Layer
A accepts" invariant clean, and the only value Layer A would actually have
disabled-via-decode-abort is `>u32max`, which `[0,u32max]` still catches. If the
user wants the stricter UX, `[1,u32max]` is fine with the documented drift note.
Either choice is implementable and consistent; this does not gate PLAN-READY.

## Scope / honesty check

The plan is honest that this is UX-only (Layer A is the safety fix), that
PLAN-KILL / Tier-1-only are legitimate lighter outcomes, and that T3-C (defer
Tier 3) leaves the headline `gre-in 70000` flat typo unvalidated. The
recommended scope (Tiers 1+2 + T3-A) is the right balance: ~7 leaves are pure
declarative schema, and the 1 hard leaf reuses an existing, reviewed AST-validator
pattern with the divergence risk designed out.

## Bottom line

v2 resolves every r1 finding from all three reviewers and adds the boot-safety
split. Design is sound, blast radius is minimized, the hard case is correctly
handled with parse-precedence nailed down, and bounds match Layer A exactly
(except the deliberate Q3 user choice). **PLAN-READY** pending the user's Q3
preference. Re-confirm after Codex r2 + AGY r2 land.
