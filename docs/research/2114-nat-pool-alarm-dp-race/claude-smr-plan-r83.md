# Claude SMR hostile plan-review — round 83 (plan v84 @ `a30d67ebc`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r82 nit
(the hold-open placement after the cleanups) was subsumed and CORRECTED
by Codex r82's M2 — I missed that the `:154` selector also precedes the
hold and would deadlock a body-wide reading. Recorded. This pass attacks
the v84 named-publisher design; all line numbers re-verified against the
worktree.

## A. Fold verification (r82 findings → v84)

### 1. Codex M1+M2 (named-publisher design) — FOLDED

Verified the structural facts: `loadUserspaceShimObjects` (:95-103) is
a wrapper (MkdirAll + the Once call); `loadUserspaceShimObjectsOnce`
(:106) carries the real work with the registry writes at :185/:187/:190.
The v84 split (unlocked privileged acquisition + the small locked
publisher carrying the writes AND the Store) answers both MAJORs: the
canary allowlist is now exactly two real functions (the registry helper
+ `publishShimRegistryLocked`), the locked-interval shape check defeats
the Lock→hook→Unlock→access anti-pattern, and the hold can never span
the `:154` selector or the `:155/:158` cleanups (the publisher runs
after them, called from `LoadUserspaceShim`). No deadlock path exists.
FOLDED.

### 2. Codex m1 (hook protocol) — FOLDED

Instance-scoped hooks, one ownership hook armed per test, the
TryLock-inside-the-interval assertion or the before-lock/after-acquire
handshake. FOLDED.

### 3. Codex m2 (privilege split) — FOLDED

Always-on classification/ownership legs (sentinel/absent registries)
plus privileged semantic-mutation legs, with the skip-evidence citation
(maps_session_clear_test.go:14). FOLDED.

### 4. Codex m3-m6 (summary pointers; closure wording; qualification
propagation; inventory fixes) — FOLDED

All verified against the current text: the three summary sites carry
the carve-out pointer; §4.7's closure wording now separates the CLOSED
registry-selection race from the narrowed teardown window (limited to
the loaded-check set); the canceled-context precedence is in §7 and §9;
the canary-set naming and the escape-hatch closure note are in. FOLDED.

## B. Fresh attacks on the v84 delta

**Attack 1 (FAILED) — the publisher's Store changes observable
ordering vs master.** Under v84 the publisher completes the writes and
the Store inside its locked body, before `LoadUserspaceShim` returns;
a caller observing `loaded==true` in that gap sees a complete registry
(the writes precede the Store inside the hold). Master provides the
same guarantee via the Store following the objects call. No ordering
change. FAILED.

**Attack 2 (FAILED) — the publisher nests under the userspace m.mu.**
The userspace `Load()` delegates without holding its own m.mu
(manager.go:467 — verified); the publisher takes only the shim's m.mu;
the one-directional nesting (userspace outer, shim inner) from the r77
verification is undisturbed. FAILED.

**Attack 3 (FAILED) — the acquisition split changes error-path
semantics.** On a pin/acquisition failure the publisher never runs, so
the registry stays untouched — identical to the current shape where
the writes trail the fallible work (:175-195's error paths return
before the insert loops). FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v84 keeps PR-1 self-contained.

## Verdict

**PLAN-READY**. The publisher design is the first canary/hold
specification whose allowlist matches the real writer and whose hold
has no deadlock path; the r68-r82 chain is recorded on each round's
doc.
