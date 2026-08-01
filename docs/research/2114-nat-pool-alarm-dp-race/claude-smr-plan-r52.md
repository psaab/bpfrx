# Claude SMR hostile plan-review — round 52 (plan v52 @ `5e6483dd0`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r51's SMR
raised the witness clause (folded in v52 — IS Codex M4); r52
re-verifies the v52 folds of Codex's 4M/1m against the real code and
attacks the two contract pins the v52 folds introduced (the
single-owner snapshot's failure-path coverage and the seqlock's
writer side). All line numbers re-verified against the worktree.

## A. Fold verification (r51 findings → v52)

### 1. Codex M1 (single-owner snapshot) — FOLDED, with nit m1

The ownership gap verifies (promotion before the boundary,
`daemon_apply_commit.go:194-246`; stamps after,
`daemon_apply_commit.go:277-286,464-475`;
`store.go:781-809,831-848`). The v52 assignment — the configstore
owns the converged-state snapshot and every promotion/stamp
publishes the same versioned snapshot — is coherent: the daemon
already holds `d.store`, so feeding the apply outcome through a
store method at the boundary introduces no dependency cycle.
FOLDED — but see m1: the failure-path publication method is not
named.

### 2. Codex M2 (seqlock read side) — FOLDED, with nit m2

The stale-green construction verifies (the one-load reader returns
captured green after a descheduled-through failure). The v52 reader
discipline — read version, read snapshot, re-read version, retry on
change — is the correct linearization for a no-applySem read path.
FOLDED — but see m2: the writer side's double-bump is not pinned.

### 3. Codex M3 (pending-XSK feed) — FOLDED

The deferral path verifies (`manager_compile.go:230-257,289-298`
records the desired snapshot and returns nil with publication
deferred; `manager.go:348-357` propagates the nil; the rejection is
logged+retried at `process_status.go:118-131,183-186`). The v52 feed
records NOT-converged until the deferred publication completes and
drives lastOK=false/count++ on its failure. While a retry is
pending the predicate correctly reads not-converged, and a
successful retry flips it converged — the intended recoverable
semantics. FOLDED.

### 4. Codex M4 (interval-bracketed double digest check) — FOLDED

The tick's two failure modes verify (the no-op pass returns before
`QueueConfig`, `daemon_ha_sync.go:478-485`, and
`ConfigsSent.Add(1)` lives only in `QueueConfig`,
`sync_conn_config.go:234-250`; the paused claimant survives the
epoch bump, `daemon_ha_sync.go:51-57,474-489`). The bracket's
termination is airtight: the reconcile loop is a SINGLE goroutine
(`configSyncReconcileLoop`), so at most ONE stale claimant can exist
(a pass that captured before the operator's commit and has not yet
fired); it fires within one interval absent a stuck lock; the
bracket's second read catches the flip; the re-drive's push carries
the newest wire generation; and every subsequent pass captures the
intended text — so at most one re-drive, then convergence, and a
non-converging state after two intervals is the declared stuck-lock
incident. FOLDED.

### 5. Codex m1 (§9 contract legs) — FOLDED

Grep-verified: the stale-snapshot-return, mid-render-entry,
single-owner publication-order, pending-XSK rejection,
paused-outbound-claimant/reconnect/commit/release ordering, and
marker-no-op rejection legs all exist as (h2c)/(h2d)/(h2e). FOLDED.

## B. Fresh attacks on the v52 delta

**Attack 1 (SUCCEEDED as nit m1) — the failure-path publication
method is unnamed.** The configstore owns the snapshot, but a
compile failure BEFORE promotion never touches the store's own
paths — the daemon must publish the failure THROUGH a store method
(the `NoteApplyOutcome`-shaped boundary call) at the central hook.
The v52 text says the fields are "written centrally at the single
full-apply entry" but never names the store-side publication method
every failure class flows through — including the pre-promotion
failures. One clause. MINOR.

**Attack 2 (SUCCEEDED as nit m2) — the seqlock's writer side is not
pinned.** The reader retry on a version change is stated, but the
writer's discipline is not: the version must be bumped on BOTH sides
of the publication (the canonical seqlock: bump odd, publish, bump
even) — a single bump can be missed by a reader whose two version
reads straddle the publication asymmetrically... more precisely,
without the double-bump the reader cannot distinguish an in-flight
publication from a completed one. One clause: the writer bumps the
version BEFORE and AFTER publishing, and the reader retries on an
odd version or a changed version. MINOR.

**Attack 3 (FAILED) — a second stale claimant trails the re-drive.**
The reconcile loop is one goroutine; at most one pass can hold a
pre-commit capture; after it fires and the re-drive lands, every
later pass captures the intended text. No succession of stale
claimants can form. FAILED.

**Attack 4 (FAILED) — the snapshot's failure feed deadlocks the
apply path.** The boundary call publishes under the store's own
lock/version atomics; the apply path already holds no store lock at
the boundary (the promotion released it), so the publication cannot
self-deadlock; the reader side is lock-free. FAILED.

**Attack 5 (FAILED) — the bracket's operator cost.** Two reads
bracketing 30s per re-drive, at most one re-drive — bounded and
operator-paced; the alternative (an unobserved stale claimant) is
the permanent-divergence case the bracket exists to prevent. FAILED.

## C. Findings

### MAJOR (0)

None. All five r51 findings fold on independent verification; the
contract now has an owner, a read discipline, and a bounded join.

### MINOR (2)

**m1.** Name the store-side publication method (the
`NoteApplyOutcome`-shaped boundary call) that every failure class —
including pre-promotion compile failures — flows through, so the
configstore-owned snapshot sees every outcome.

**m2.** Pin the seqlock's writer side: the version is bumped BEFORE
and AFTER the publication (odd-in-flight/even-stable), and the
reader retries on an odd or changed version — a single bump cannot
be distinguished from a completed publication by the two-read
discipline.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the publication-method
name and the writer-side double-bump). A v53 containing only these
two pins is PLAN-READY by inspection from me.
