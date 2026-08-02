# Claude SMR hostile plan-review — round 81 (plan v82 @ `c4005f7c2`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r80 pass
ran the widened-pattern extinction sweep but did not re-derive the
precedence assignment against the tree — Codex r80 then found the
class-2 predicate sweeping the error-outcome fabric methods. Recorded.
This pass re-derives the classification and checks the v82 folds.

## A. Fold verification (r80 findings → v82)

### 1. Codex M1 (class-2 predicate correction) — FOLDED

The precedence now reads: escapes → 4; required side effects → 3;
NEUTRAL missing-map outcome (nil/zero/empty, never an error) → 2;
error-outcome → 1. Verified against the tree: `UpdateFabricFwd`
(maps_fabric.go:18-24) and `UpdateRGActive` (:38) return
missing-map errors, so they land in class 1 under the corrected
predicate, as intended; the class-2 set (`SessionCount`,
`GetMapStats`, the no-op clears, `UpdatePolicyScheduleState`) all have
nil/zero/empty missing-map outcomes. FOLDED.

### 2. Codex M2 (carve-out precision) — FOLDED

"Reject WHENEVER loaded==false (both unarmed states); proceed when
armed" — verified against loader.go:490/:1082 and compiler.go:182
(nil-config check first at :179-181, then the loaded rejection).
FOLDED.

### 3. Codex M3 (per-entry-point ordering) — FOLDED

The clause now distinguishes: direct `Manager.Compile`/`ApplyConfig`
(reject immediately even pre-Store — their first registry-adjacent
step is CompileConfig's check), direct `CompileUserspaceShim`
(cleanups :174/:177 + selector :181, then blocks at the selector
during the hold), production `userspace.Manager.Compile` (blocks at
the outer selector, manager_compile.go:184). The post-Store/pre-unlock
barrier is named. FOLDED.

### 4. Codex M4 (reverse-schedule seam + AST canary) — FOLDED

The reverse schedule is real (ClearGlobalCounters releases m.mu at
:179 before its raw lookup at :181 — verified the unlock-then-lookup
order). The two guards answer it: the lookup-entry seam (the registry
helper gets the test hook at its entry — ONE hook site, not
per-statement modification, so it is implementable without production
surgery beyond the seam pattern already in use) and the AST canary
forbidding direct `m.maps`/`m.programs` access outside the registry
helper + the whole-batch writer (the allowlist is two named functions;
the project already runs AST canaries of exactly this shape).
FOLDED.

### 5. Codex m1/m2 (generation wording + fixture scope; idempotency
weakening + citation) — FOLDED

Both sites now read "live FD-backed objects of an obsolete forwarding
generation"; the fixture scope is pinned (one retained fixture
suffices; a Close-transition assertion proves registry preservation);
"safe/no-op when repeated after successful cleanup" replaces the
unconditional idempotency (verified the aggregation-after-partial-
progress shape in the cleanup bodies); the :181 citation is corrected.
FOLDED.

## B. Fresh attacks on the v82 delta

**Attack 1 (FAILED) — the reverse-schedule seam is unimplementable
without production hooks.** The seam lives at the registry helper's
entry (one test-only hook var — the same synthetic-seam pattern the
plan already uses for the population barriers); the writer's release
is driven between the hybrid's side-effect unlock and its helper
entry by the test coordinator. Implementable. FAILED.

**Attack 2 (FAILED) — the canary allowlist is unenforceable.** The
allowlist is two named functions (the registry helper, the
whole-batch writer in `loadUserspaceShimObjects`); the canary fails
any new direct accessor — the same enforcement shape as the existing
retirement-boundary canary. FAILED.

**Attack 3 (FAILED) — a residual class-1 method lost its error-text
preservation.** The class-1 typed error replaces only fresh-state
missing-map errors; retained-state methods proceed as master (with
master's own error texts); the loaded-check set keeps its own
rejections. No preserved-text case remains. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v82 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — with the now-standard discipline note: the mechanism
has been stable since r76 (uniform registry rule, two-state predicate,
whole-batch publication, four-leg oracle, canary net); r77-r82 were
precision work on the text, and each is verified above against the
tree.
