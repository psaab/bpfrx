# Claude SMR hostile plan-review — round 84 (plan v85 @ `9f1f3ab69`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r83 pass
verified the publisher design but, like AGY, did not run the escape
analysis — Codex r83 found the container-escape hole. Recorded. This
pass runs the escape analysis first, then the rest.

## A. Fold verification (r83 findings → v85)

### 1. Codex M1 (canary escape closure) — FOLDED

The helper is now exactly named with a non-escaping signature
(`registryLookupLocked(name string) *ebpf.Map` — key in, handle out;
the container never escapes). Verified the shape's sufficiency against
the tree: every production registry access is a keyed lookup
(`m.maps[name]` / `m.programs[name]`) — a repo-wide grep finds NO
`range m.maps` / `range m.programs` site and no non-indexed container
use, so the one-key-in shape serves every current access pattern. The
shape rules (type-aware receiver matching; rejection of container
return/alias/field-assign/closure/argument-pass/post-unlock-indexing;
the alias-escape and unlock-before-access negative fixtures; the
publisher's writes + exactly one in-lock Store(true)) cover the r83
hole. FOLDED.

### 2. Codex m1 (teardown-summary qualifications) — FOLDED

Both sites (the §4 mechanics bullet and invariant 12) now qualify the
entry-Store narrowing as the loaded-check set's admission — Close
retains a nonempty registry, so ordinary methods classify retained and
proceed; what changes at the entry Store is that the loaded-check set
begins rejecting from Close's start (master flips `loaded` only at the
:1217 exit and would let them pass against closing links). FOLDED.

## B. Fresh attacks on the v85 delta

**Attack 1 (FAILED) — a residual escape form.** Slice-of-handles and
long-lived struct-field caching: no production code stores a registry
handle in a long-lived field (the r68-era AGY verification re-confirmed
by this grep pass — callers retrieve per operation). The container
itself is the only escape vector and it is now rejected in every form.
FAILED.

**Attack 2 (FAILED) — the publisher self-deadlocks via the helper.**
The publisher writes directly under its own m.mu hold and never calls
the helper (it is the allowlist's writer half; the helper is for
readers) — no intra-allowlist call exists, so no re-entrancy. FAILED.

**Attack 3 (FAILED) — a wholesale-iteration site exists.** None (the
grep above); if one ever appears, the canary fails the build until it
routes through a named shape. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v85 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the escape analysis that neither AGY nor I ran at r83
is now the canary's explicit rule set, verified against the tree's
actual access shapes (all keyed lookups, no wholesale iteration, no
handle caching).
