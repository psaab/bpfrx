# Claude SMR hostile plan-review — round 36 (plan v36 @ `c0cf0b687`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r35's SMR
raised the mask==0 nit that Codex independently elevated to M1; r36
re-verifies the v36 folds against the real code and attacks the
staged-writer mechanism and the stopped-remediation guidance. All
line numbers re-verified against the worktree.

## A. Fold verification (r35 findings → v36)

### 1. Codex M1 (= SMR r35 m1 — mask==0 precondition) — FOLDED

The precondition is now explicit and coheres with the remediation
taxonomy: any live process-local debt (`ConfirmDebtKindMask ≠ 0`)
FORBIDS the stop (debts die with the process,
`store_persist.go:397-401` — re-verified "process exit simply
abandons it"; the repaired pending-shaped record then
hash-matches into expired-revert or a future re-arm at the next
boot, `store_persist.go:149-165,171-255` — the admitted replay
residual, now with the operator WARNED about the Load-outcome
asymmetry: successful-active Load runs the full total order;
absent/compile-failed Load only seeds an orphan). The live
alternative is correctly named: REMOVAL is the live-safe
remediation for the same corrupt record (the confirmed-absence
barrier is idempotent). FOLDED.

### 2. Codex m1 (staged-writer seam) — FOLDED, with nit m1

The seam is pinned constructibly: `WriteFileDurableStaged(path,
data, perm, preRename func() error)` — the classification
re-verify runs inside the pre-rename hook under the same `s.mu`
hold; a hook error abandons the temp and re-classifies; the
monolithic `WriteFileDurable` is untouched for other callers
(verified its shape at `fsatomic.go:310-355`: `createTemp` in the
same directory, write, fsync, close, unconditional rename). The
post-write read-back alternative is correctly rejected (it sees
only the daemon's own replacement when the operator's write
lands first — the rename is namespace-atomic and the operator's
content is already gone). §5.1 gains the fsatomic entry. FOLDED —
but see m1: "abandons the temp file" is loose wording next to
fsatomic's documented cleanup discipline.

### 3. Codex m2 (three-cause copies) — FOLDED

Grep-verified: no "three causes"/"THREE-cause" copy survives; the
`pkg/api/README.md` description, the `health.go:10-16` header,
and the descriptor/wiring copies all name the causes incl.
`ConfigWriteUnverified`. FOLDED.

## B. Fresh attacks on the v36 delta

**Attack 1 (SUCCEEDED as nit m1) — "abandons the temp file" is
loose against fsatomic's cleanup discipline.** The documented
convention at `fsatomic.go:41-44` (re-verified): "The temp file
is removed on every failure path before rename. After a crash,
leaked `.<base>.tmp-*` temps are possible; writers of
frequently-rewritten files should sweep them (configstore's
NewDB does)" — and the monolithic variant implements it via a
`defer`-driven `os.Remove(tmpName)` on the failure paths
(`fsatomic.go:317-322`). The staged variant inherits the same
discipline by construction (hook error → the defer removes the
temp), stray temps are dot-prefixed and inert to the fixed-path
reads, and `NewDB` sweeps crash-leaked temps at open — but the
plan's "abandons the temp file" reads as leaves-in-place. One
clause fixes it: the hook failure path REMOVES the temp per the
`fsatomic.go:41-44` discipline (the defer-driven cleanup), with
crash-leaked temps swept by `NewDB` at open. MINOR.

**Attack 2 (FAILED) — the mask==0 evaluation race.** A debt can
be raised between the operator's mask check and the stop; the
abandoned debt is exactly the admitted replay residual, and the
runbook's own guidance covers it — the operator repairs,
restarts, and the boot total order classifies whatever stands
(a matching unexpired record enters window recovery, which is
the re-arm the operator was already mediating; an expired one
reverts; a Resolved one drops). The operator cannot make the
outcome worse than the residual the plan has admitted since
r29, and the after-restart health/journal check surfaces it.
FAILED.

**Attack 3 (FAILED) — the staged hook extends the s.mu hold
across fsync.** The hook runs after temp fsync/close, so the
classification re-verify adds no I/O inside the lock beyond the
read the pass already performs; the fsync itself completes
before the hook. The hold-time growth is one file read+compare
per repair write — same class as the loop's existing per-attempt
I/O under `s.mu` (`store_persist.go:402-428`). No new lock-order
or stall hazard. FAILED.

## C. Findings

### MAJOR (0)

None. The r36 major (jointly found by Codex and this reviewer)
folds on independent verification; the staged mechanism is
constructible against the real fsatomic shape.

### MINOR (1)

**m1.** Pin the temp-file fate in the staged variant: a hook
failure REMOVES the temp per the `fsatomic.go:41-44` cleanup
discipline (the defer-driven `os.Remove` on every failure path
before rename), with crash-leaked `.<base>.tmp-*` temps swept by
`NewDB` at open — replacing the loose "abandons the temp file"
wording.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the temp-cleanup
wording pin). A v37 containing only this pin is PLAN-READY by
inspection from me.
