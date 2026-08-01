# Claude SMR hostile plan-review — round 77 (plan v78 @ `a437f0246`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r76 pass
returned PLAN-READY with two attacks marked FAILED that Codex/AGY proved
REAL the same round — the erratum is on that doc. This pass re-verifies
the v78 fold with the citations shown for every step, and treats my own
earlier misses as the prior: assume the fold is wrong until the mechanism
is shown against the tree.

## A. Fold verification (r76 findings → v78)

### 1. Codex M1 + AGY M1 (uniform registry rule + whole-batch) — FOLDED

The rule as written closes the fatal schedule: classification + handle
selection are one scoped `m.mu` operation (the gate outcome and the
handle copy are atomic — no admit-then-unlocked-lookup gap), and the
population's program assignment plus both insert loops
(`loader_userspace_shim.go:183-190`) publish under ONE `m.mu` hold —
the fresh→retained flip cannot be observed mid-batch. Verified the
all-or-nothing substrate independently: every fallible step in
`loadUserspaceShimObjects` returns BEFORE the insert loops (the pin
loop's error path closes the collection and returns), so no partial
registry exists outside the batch — AGY r76 M2's premise does not exist
on current code, and the whole-batch rule makes the property structural.
FOLDED.

### 2. Codex M2 (L2 narrowing + generation hazard to §10) — FOLDED

Verified the generation hazard's mechanics: bootstrap.go:469-473 calls
`Teardown` (not Close) retaining the Manager; root `Teardown` → `Close`
+ `Cleanup` (:1221-1228); `Cleanup` removes the pin tree;
`loadOrCreatePinnedShimMap` (:602) creates fresh maps when pins are
absent. So the retained-after-Teardown handles reference dead objects
and re-Start builds a new generation — a retained-proceed mutation hits
the obsolete object. The §4 text now claims only fresh-unarmed
admission safety + registry-selection race safety, names the hazard as
master's own racy behavior on the recurrence path, and assigns it to
the follow-up's work item H (the recurrence terminator) via §10. The
narrowed L2 claim is exactly true as written. FOLDED.

### 3. Codex m1/m2/m3 (invariant 12 + pointers; retained overlap leg;
fixture classification redo) — FOLDED

Invariant 12 now reads the two-state form (fresh-gated methods never
touch Start-state; retained methods proceed under the registry rule);
§9 gains `TestManager_ArmedGate_RetainedReStartOverlap` with the
whole-batch hook and every class driven, plus the Detach test's
population actor; the fixture classification is redone correctly
(injected fixtures are retained-unarmed and proceed — the XSK fixture's
:41 injections mean the gate never broke it; only `loaded==true`-
asserting fixtures migrate). FOLDED.

## B. Fresh attacks on the v78 delta

**Attack 1 (FAILED) — the uniform rule deadlocks against the userspace
manager's own m.mu.** Verified the nesting is one-directional:
userspace methods take the userspace `m.mu` and then call shim methods
which take the shim's `m.mu` (e.g. manager_ha.go:245-246 → :258
`m.bpfShim.Map(...)`); the shim never calls up (embedded, no
back-reference); userspace `Load()` delegates WITHOUT holding the outer
lock (manager.go:467 — `return m.bpfShim.LoadUserspaceShim()`), so the
whole-batch hold never nests inside the outer lock. Lock order:
userspace-m.mu outer, shim-m.mu inner, no cycle. FAILED.

**Attack 2 (FAILED) — intra-shim recursion through the locked
helpers.** The two composition cases are covered by earlier folds with
the correct shapes: swapXDPEntryProg's :613 check uses the raw
`xdpEntryProgramLocked()` helper under its scoped section (never the
public getter, which locks); the class-3 hybrids compose through
internal raw helpers (r71 M3). No public-under-lock path remains.
FAILED.

**Attack 3 (FAILED) — the uniform rule contradicts the class-3
scoped-lookup text.** The class-3 mechanism IS the registry helper
(lock the lookup, copy the handle, release before BPF ops); the
uniform rule extends the same helper to every class. The class-1
post-gate lookup and the class-2 proceed lookup now go through it.
Consistent. FAILED.

**Attack 4 (FAILED) — retained-proceed during Teardown's Cleanup
deleting kernel maps.** A retained-proceed library call on a handle
whose kernel object Cleanup just deleted returns EBADF through the
library — an error, never a Go fatal; master's ungated behavior is
identical. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v78 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — with the discipline note that my r76 verdict made the
same claim one revision earlier and was wrong; the difference this time
is that every mechanism is pinned to a verified code shape above (the
one-directional lock order, the all-or-nothing population substrate,
the raw-helper compositions), and the remaining hazards are either
named residuals with owners or the follow-up unit's explicit scope.
