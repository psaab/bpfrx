# Claude SMR hostile plan-review — round 75 (plan v76 @ `27c602aab`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r74 pass
returned PLAN-READY on v75 while Codex r74 found the DetachXDP
claim-cleanup regression and the XDP seam's silent-green — my r74 pass
verified the no-map early return but did not trace the retained-claim
path on the re-arm state. Recorded. This pass attacks the v76 fold; all
line numbers re-verified against the worktree.

## A. Fold verification (r74 findings → v76)

### 1. Codex M1 (DetachXDP class-3-like delegation) — FOLDED, with nit m1

Verified the mechanism: `setXDPAttachedFlag`'s body order is the no-map
early return (:699-704), then target discovery (:711) and claim
cleanup (:777-787). On the retained re-arm state (Close clears none of
`xdpLinks`/`m.maps`/`xdpFlagClaims`, :1206) master does NOT early-return
and the cleanup runs — so the no-gate + scoped-lookup shape preserves
master exactly. The scoped `m.mu` lookups cover the `:700`/`:730`
Go-map lookups; the `iface_zone_map` ITERATION (:745-749) and updates
(:816) are library-handle operations on the copied `*ebpf.Map` — the
r71 ruling's exact shape (lock the Go-map lookup, copy the handle,
release before BPF ops). FOLDED — with m1: the claim-cleanup WRITES
(`m.xdpFlagClaims[tk] = claims` / `delete(...)`, :770-790) are plain
Go-map writes, and `xdpFlagClaims` is not named under any lock. Its
writers are applySem-serialized EXCEPT in the RACE-3 window (a
recovered-rollback apply's `SetZone`/cleanup vs the boot attach,
:515). The v76 text must name `xdpFlagClaims` as joining the
`m.mu`-protected set (the `loader.go:49` comment's scope grows again).

### 2. Codex M2 (direct :632 pin) — FOLDED

The seeded-distinct-program direct `swapXDPEntryProg` call defeats all
three silent-green exits (class-1 gate on the public wrapper; `:609`
absent-program; `:613` already-selected) — `:632` executes under the
race detector. FOLDED.

### 3. Codex m1/m2/m3 (labels, fixture, premise) — FOLDED

The trio's only listing is now category G; DetachXDP carries one
manifest label with the delegation target named; the fixture migration
is named; the §10 premise correction preserves the adjudication's
conclusion (verified `manager_ha.go:115` starts the loop pre-failure-
propagation, and every start remains post-`CompileUserspaceShim`-return).
FOLDED.

## B. Fresh attacks on the v76 delta

**Attack 1 (SUCCEEDED as nit m1)** — the `xdpFlagClaims` writes, above.

**Attack 2 (FAILED) — the class-3-like iteration escapes.** Per the r71
ruling shape, the lock covers the Go-map lookup only; the BPF
iteration/updates use the library handle, safe against population.
FAILED.

**Attack 3 (FAILED) — the armed synthetic fixture is unconstructable.**
The fixture test lives in `pkg/dataplane/userspace`; `loaded` is
unexported on the root Manager — a `pkg/dataplane` in-package test
helper (or a testutil export) sets it without running Load. Plain.
FAILED.

**Attack 4 (FAILED) — another unserialized plain field.** The struct
sweep from r73 (attack 2 there) plus this round's `xdpFlagClaims`
catch leaves no third field: `lastCompile`/`lastApply` are
writer-serialized; the rest are named in the partition or §10. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (1)

**m1.** Name `xdpFlagClaims` as joining the `m.mu`-protected set — its
writes (`loader.go:770-790`) run from both the applySem-serialized
apply path and the RACE-3 window's boot-attach overlap; the
`loader.go:49` comment scope grows to match.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v76 keeps PR-1 self-contained.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the `xdpFlagClaims`
lock-set naming). A v77 containing only this pin is PLAN-READY by
inspection from me.
