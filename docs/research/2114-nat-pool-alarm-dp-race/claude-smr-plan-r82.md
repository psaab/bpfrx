# Claude SMR hostile plan-review — round 82 (plan v83 @ `c3c4cad42`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r81 pass
verified the mechanism semantics of the v82 folds but not their
implementation grade — Codex r81 then pinned the canary and the hold
placement. Recorded. This pass checks the v83 specification for
exactly that class: is every mechanism now named to the function and
place.

## A. Fold verification (r81 findings → v83)

### 1. Codex M1 (canary spec + hold placement) — FOLDED, with nit m1

The canary now has the exactly-named allowlist (the registry helper +
`loadUserspaceShimObjects`), the package-wide scanner, the permitted
shapes, the stale-allowlist self-check, and the synthetic negative
tests; the hold placement is structurally exact (taken in
`LoadUserspaceShim`, spanning the `loadUserspaceShimObjects` call AND
the Store(true) — verified the current code: selector :154, cleanups
:155/:158, objects call :161, Store :163). FOLDED — with m1: the
placement text does not say whether the hold opens before or after the
two legacy cleanups (:155/:158). If it opens at function entry, the
hold extends across filesystem work (os.Remove / pin-dir reads) that
touches no registry state — a needless widening of the critical
section during arm. One clause: the hold opens AFTER the cleanups
(they are filesystem-only) and spans exactly the objects call + the
Store. MINOR.

### 2. Codex M2 (ownership test + seam scoping) — FOLDED

The helper lock-ownership test uses the same hold-and-block assertion
shape as the :632 proof (deterministic — the hook lives inside the
helper's own section); the seam-scoping rule (the synthetic loader
replaces only the privileged syscalls, never the production registry
writes) keeps the publication writes on the production path under the
test's barrier. The two hook sites (the batch seam's and the helper's)
live in different tests — the coordinator drives one seam per leg, so
no two-hook interleave exists. FOLDED.

### 3. Codex m1-m4 (summary pointers, oracle subcases, closure wording,
citations) — FOLDED

All four verified against the current text: the class-1 summary's
carve-out pointer, §6's two qualifications, the oracle subcases
(nil config :179, canceled context apply.go:238, cleanup failures,
the pin removal at manager_compile.go:163, the two-invocation shape),
the closure wording (CLOSES in every state; narrowing applies only to
the teardown window), the :18 citation, the higher-precedence
overbreadth fix. FOLDED.

## B. Fresh attacks on the v83 delta

**Attack 1 (SUCCEEDED as nit m1)** — the hold-open placement, above.

**Attack 2 (FAILED) — an access site escapes the named allowlist.**
The allowlist covers the registry helper and the whole-batch writer;
every other site routes through the helper per the uniform rule
(verified the 135-site census shape from the earlier rounds'
independent greps: 130 `m.maps` + 5 `m.programs`). FAILED.

**Attack 3 (FAILED) — the two-invocation shape is untestable.** The
seam's second barrier (post-Store/pre-unlock) lets the coordinator
invoke once pre-Store (rejects) and again post-Store (blocks at
registry selection) — two invocations, two outcomes, deterministic.
FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (1)

**m1.** Pin the hold's open point: the whole-batch `m.mu` hold opens
AFTER the two legacy cleanups (`loader.go:155/:158` — filesystem-only,
no registry state) and spans exactly the `loadUserspaceShimObjects`
call + the Store(true). One clause in the placement text.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v83 keeps PR-1 self-contained.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the hold-open placement).
A v84 containing only this pin is PLAN-READY by inspection from me.
