# Claude SMR hostile plan-review — round 16 (plan v16 @ `0b8e7cc97`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r15's Codex
M1 overturned a premise I had signed off (idempotence); r16 re-verifies
the uniform-rule reformulation end to end with extra skepticism, plus
fresh attacks. All line numbers re-verified (origin/master `ed6999000` +
plan-doc-only branch).

## A. Fold verification (r15 findings → v16)

### 1. Uniform tombstone rule (Codex M1) — FOLDED, and the premise correction re-verified independently

- The premise correction stands on direct evidence: the compile path
  deletes XDP link pins BEFORE compiling so AttachXDP does a fresh
  attach (`manager_compile.go:162-172`, comment: "fresh attach triggers
  mlx5 to initialize XSK buffer pool from fill ring"); the flow cache
  carries `config_generation: u64` (`flow_cache.rs:122-139`); the apply
  path reloads FRR (`daemon_apply_routing.go:203-226`). A replayed
  revert is runtime-churning, full stop. My r15 sign-off was at the
  wrong level of abstraction (config-state); Codex measured at the level
  that matters.
- The uniform rule preserves #5473: the retention paths
  (`store.go:738-760`, `store_commit.go:867-937`,
  `store_persist.go:171-227`) NEVER call `resolveConfirmRemovalLocked`
  pre-durability — the only callers on those paths are the
  durable-success and the finalize (`store_persist.go:414-428`,
  `store_commit.go:631-649`). The tombstone helper lives only in
  `resolveConfirmRemovalLocked`. No pre-durability tombstone site
  exists by construction. FOLDED.

### 2. Failed-SyncApply divergence (Codex M2) — FOLDED

The finalize tombstones before deleting; the crash window
(durable B + lingering binding A) now resolves as Resolved-first drop
at the next recovery instead of a revert of the synced config. The
"no tombstone UNTIL durable" qualifier is stated verbatim in the plan
and x7. FOLDED.

### 3. B-durability precondition (Codex M3) — FOLDED, with one pin (m1)

`WriteConfirm` runs the full fsatomic cycle (`db.go:207-218` —
temp+fsync+rename+dir-fsync via `WriteFileDurable`), so a successful
rewrite establishes durability. The livelock case (B's rewrite keeps
failing) degrades to retaining A's debt — consistent with the
typed-error table (transient → retry; the health-degraded state
surfaces it).
**Nit (m1)**: the B-REWRITE debt is a THIRD debt kind and v16 does not
pin ITS identity discipline. It must be ArmID-keyed to B exactly like
A's removal debt: the rewrite retry re-reads confirm.json and rewrites
ONLY if the current record is still B (`ArmID` match); a later arm C
(whose own write succeeded or carries its own rewrite debt) supersedes
— mismatch → clear. Otherwise the B-rewrite debt reintroduces the same
unkeyed-debt race one level down. One-line pin.

### 4. pendingArmID (Codex M4) — FOLDED

The empty-`ArmID` edge resolves cleanly through the existing table:
recovery of an UNREADABLE record returns early
(`store_persist.go:140-144` — no pending state restored, nothing to
resolve later). A LEGACY record (no `ArmID` field) restores
`pendingArmID = ""`; a resolution keyed on `""` matches the legacy
record's own empty field (`"" == ""` → match → tombstone+delete —
correct), and a new arm B with a real `ArmID` mismatches
(`"" != B.ArmID` → B-durability → clear — correct). No special state
needed. FOLDED.

### 5. Typed errors (Codex m1) — FOLDED

The #5637 gate's errors are constructed at `db.go:226-281` as semantic
validation errors, distinct from IO failures at the same call site;
the terminal-degraded state is election-neutral (verified:
`pkg/cluster/manager.go:321-336` — the cluster's health annotations
"must only annotate health, never demote priority or gate"; the
degraded state surfaces via /health 503 + the #1799 Prometheus gauge
for operators/LBs, NOT the heartbeat/VRRP election). FOLDED.

### 6. Consistency (Codex m2) — FOLDED

H2 intro now covers content-changing paths; §5.1 lists `store.go` +
`store_persist.go`.

## B. Fresh attacks on the v16 delta

**Attack 1 (FAILED) — terminal-degraded vs HA election.** Verified
election-neutral (§A.5). FAILED.

**Attack 2 (SUCCEEDED as nit m1) — the B-rewrite debt's keying.** See
§A.3: third debt kind, identity discipline unpinned. MINOR.

**Attack 3 (FAILED) — stale-drop tombstoning.** The stale-drop's
`resolveConfirmRemovalLocked` call now tombstones a superseded record
first — harmless belt-and-braces (Resolved-first drop covers the crash
window; the hash mismatch already disambiguates). Uniformity beats
special-casing. FAILED.

**Attack 4 (FAILED) — re-arm consistency.** Recovery's re-arm writes no
new record; `pendingArmID` restores from the SAME record the re-armed
timer will fire against (`store_persist.go:231-253`) — identity stays
consistent across the re-arm. FAILED.

## C. Findings

### MAJOR (0)

None. The uniform rule survives re-verification at the runtime-state
level, and the four folds are mechanically consistent with the
configstore code as it exists.

### MINOR (1)

**m1.** Pin the B-rewrite debt's identity discipline: ArmID-keyed to B,
rewrite-on-match, clear-on-mismatch (a later arm C supersedes) — the
same four-state pattern as A's removal debt, one level down.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — a one-line identity pin).
A v17 containing only this pin is PLAN-READY by inspection from me.
