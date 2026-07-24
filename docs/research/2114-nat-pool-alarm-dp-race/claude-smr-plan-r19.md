# Claude SMR hostile plan-review — round 19 (plan v19 @ `1cd0ad1dd`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r18's SMR
found the routing hole Codex confirmed as M6; r19 re-verifies every v18
fold against the v19 text and attacks the delta fresh — including the
two scenarios (deferred-deadline expiry, re-seed clobber) embedded in
the round prompts. All line numbers re-verified against the worktree.

## A. Fold verification (r18 findings → v19)

### 1. Codex M1 (convergence) — FOLDED

The conditional restatement (strict reduction given quiescence +
eventually-successful I/O; distinct keys + single on-disk slot bound the
live set; health visible; no liveness claim under churn) is honest and
is the correct guarantee for a best-effort background healer. The
`store_lock.go:9-28` premise (mutation gated only by cluster read-only)
verified. FOLDED.

### 2. Codex M2 (same-key ordering) — FOLDED

The rule is stated with both guards: "the retry processes R before W"
AND "a rewrite NEVER runs against a record a removal debt also keys" —
the second is the load-bearing one (it protects even a pass that
evaluates W first; the subsumption check at W's turn suffices, no sort
required, though a sort is belt-and-braces). The hazard walk
(pre-rename tombstone failure → pending-B visible → W_B-first restores
it durably → crash → re-arm of a resolved window,
`store_persist.go:149-165,231-253`) is closed by both guards and the
x16 regression drives it. Absent-for-rewrite after a same-pass delete
is NO-OP-and-clear (the record is gone; nothing to make durable).
FOLDED.

### 3. Codex M3 (seeded orphan) — FOLDED, with nit m1

The rule (every superseding replacement resolves a seeded
Present(record) when no in-memory window pends, at the existing
post-durability finalize points) is correct and the disambiguator is
sound (s.mu serializes; the in-memory-window check separates orphans
from live windows). The CONFIRMED-commit sub-case is the sharp one:
the orphan is resolved at the pre-arm finalize point
(`store_commit.go:437-452`); a PRE-rename arm failure afterwards leaves
no binding record. The rule covers it — but x17 as written drives only
the plain-commit leg. See m1.

### 4. Codex M4 (probe absence barrier) — FOLDED

The ENOENT → `DeleteConfirm` re-drive (no-op unlink + dir fsync,
`db.go:297-315`) before clearing matches the #4864 rationale
(`store.go:152-166`). x18 pins it. FOLDED.

### 5. Codex M5 (continuation kinds) — FOLDED

Both embedded attacks fail on the text: (a) the deferred pending-shaped
record's deadline keeps running and the next boot applies the normal
total order — expired → revert is the #4577-CONTRACT-CORRECT outcome
for a window that lapsed unconfirmed (the operator was loudly warned
via 503 + journal + runbook the whole time; suspending the deadline
would let an unconfirmed config stand, which is worse); (b) the
re-seed reads the CURRENT record under s.mu, so it cannot clobber — a
clean read of a legitimately-armed B re-seeds to B, and the stale
A-keyed debt then mismatch-clears exactly as designed. FOLDED.

### 6. Codex M6 (fail-closed routing) — FOLDED

The sentinel + `classifyLoadError` mapping + confirm.json-named
diagnostic + `bootstrap_test.go:10-36` legs + pinned envelope + the
management posture (Load in phase 1, `daemon_run.go:157-177` — no
fxp0 stranding; deliberate exit unlike `loadCompileFailed`; systemd
re-drives) close my own r18 M1. `classifyLoadError` has exactly one
production caller (`daemon_run_bringup.go:277`). FOLDED.

### 7. Codex M7 (three-field snapshot) — FOLDED

The three-field partition is faithful to today's aggregate
(`persistDegraded || confirmRemoveDegraded`,
`store_persist.go:342-353` + `store.go:152-166`); precedence
terminal > confirm-persist > active-persist; the gauge keeps the OR;
Config-field wiring matches this server's conventions
(`server.go:93-140`); the plumbing test + dual-callback wiring are
pinned. FOLDED.

### 8. Codex m1-m5 — FOLDED

Staged barrier outcome, pinned envelope, probe lifecycle, docs sweep
(the five named surfaces), §6 correction — all present and consistent.

## B. Fresh attacks on the v19 delta

**Attack 1 (FAILED) — seeded-orphan resolution vs a deferred
boot-origin record.** A pending-shaped record deferred by the
boot-origin latch, then an operator plain commit: the seeded-orphan
rule resolves it (tombstone+delete). Correct — the operator's commit
IS the confirmation, matching master's in-memory supersession
(`clearPendingConfirmLocked`). Even an expired deferred record is
correctly resolved by the commit. FAILED.

**Attack 2 (FAILED) — probe re-seed vs concurrent arm.** The probe
runs under s.mu within the retry pass; arms serialize. No race.
FAILED.

**Attack 3 (FAILED) — terminal latch double-count in the snapshot.**
Whether a terminalized debt also reads ConfirmPersistDegraded=true is
unobservable: precedence renders terminal first, and the gauge is the
OR. Coherent either way. FAILED.

**Attack 4 (SUCCEEDED as nit m1) — x17 missing the confirmed-commit
leg.** The sharp sub-case (orphan + confirmed commit + PRE-rename arm
failure) is exactly where skipping the pre-arm resolution leaves a
binding orphan (legacy empty hash or byte-identical content → re-arm
→ revert of the just-committed config). The rule covers it; the test
list must pin it. MINOR.

**Attack 5 (SUCCEEDED as nit m2) — the Load-seeding unreadable branch
elides the class split.** The (c) clause says "unreadable (→ the
terminal latch, taxonomy bullet)" — the taxonomy bullet holds the full
transient→retry→fail-closed vs permanent→latch split, but an
implementer reading (c) alone could latch TRANSIENT seeding-read
errors and skip the fail-closed path. One-line explicit split. MINOR.

## C. Findings

### MAJOR (0)

None. The v19 delta is semantic pins on a design whose architecture has
been stable since r16; every pin verified against the code it names.

### MINOR (2)

**m1.** x17 gains the confirmed-commit leg: absent-DB Load with
Present(A) → commit-confirmed supersession → the orphan is resolved at
the pre-arm finalize; a PRE-rename `writeConfirmState` failure then
leaves NO binding record on disk (recovery cannot re-arm A).

**m2.** The Load-seeding (c) clause's unreadable branch names the class
split explicitly: TRANSIENT → the bounded-retry/fail-closed path;
PERMANENT → the terminal latch (cross-referencing the taxonomy bullet
is not enough — the clause currently reads as "unreadable → latch"
unconditionally).

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — a test-leg addition and a
one-line clarity pin). A v20 containing only these two folds is
PLAN-READY by inspection from me. Split ruling: SPLIT-MOOT if Codex
converges this round; if Codex returns NEEDS-REVISION with new MAJORs
on H2, SPLIT-OK (core d.dp + G + H ships; H2 becomes a follow-up) —
the contested surface has been exclusively H2 for four rounds and the
H-without-H2 interim hazard exists on master today for ALL record
classes.
