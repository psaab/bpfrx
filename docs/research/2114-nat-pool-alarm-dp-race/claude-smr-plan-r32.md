# Claude SMR hostile plan-review — round 32 (plan v32 @ `28505e6e0`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r31's SMR
returned PLAN-READY; r32 re-verifies the v32 folds of Codex's 2M/3m
against the real code and attacks the WRITE-UNVERIFIED state machine
with fresh interleavings. All line numbers re-verified against the
worktree.

## A. Fold verification (r31 findings → v32)

### 1. Codex M1 (WRITE-UNVERIFIED state machine) — FOLDED

The v31 hole was real and I missed it in my r31 pass: a missing key
file classifies READ-side TRANSIENT (UNVERIFIABLE), so a
latest-failure-class predicate reopens the gate exactly where
`readOrCreateMasterKey`'s auto-create lives
(`crypto.go:457-479` — re-verified: generates AND durably persists
a fresh key on `IsNotExist`). The v32 state machine is closed by
construction: ENTER covers the probe failures (ENOENT/EACCES/
mount-IO) alongside key-class-observed failures and byte-mismatch;
HOLD is the default (every non-positive outcome keeps the state);
EXIT requires POSITIVE validation — same-snapshot key-path read
PLUS decrypt-validation of an on-disk encrypted record — which a
missing/wrong key can never produce. The wrong-K″ interleave holds
(the re-read fails auth); the missing-key case holds (the probe
fails); the auto-create can never fire because every encrypted
write is blocked while the state holds. Fresh-box and
plaintext-only postures never enter (verified the entry conditions
are all observation-based — no records, no failures). FOLDED.

### 2. Codex M2 (non-circular restoration) — FOLDED

The circularity is resolved at the right level: the healing write
is gated by the STATE, not by the debt's own bit, and the state's
exit is the validation that the same pass just performed
(single-snapshot). Operator restores K → key-path read succeeds +
confirm re-read decrypts under K → EXIT → R_A's tombstone→delete
proceeds same-snapshot. Wrong-K″ → HOLD. The other exit — the
sanctioned record removal under the gate — remains available for
genuinely corrupt (not wrong-key) records. FOLDED.

### 3. Codex m1 (early commit refusal) — FOLDED

The post-promotion hole was real: `writeConfirmState` arms AFTER
the active write (`store_commit.go:437-524,530-553`) and the
confirm record's encryption keys off `rec.PrevTree`'s
master-password leaf (`db.go:212-215` → `crypto.go:262-270`), so a
plaintext candidate with an encrypted PrevTree produces an
encrypted confirm record. The early precheck evaluates BOTH leaves
(the candidate's for active.json, the PREV tree's for the confirm
record) and refuses BEFORE any write; the regression pins the
plaintext-candidate/encrypted-PrevTree case. FOLDED.

### 4. Codex m2 (keyClass source unified) — FOLDED

Grep-verified: every schema copy now reads "per `errors.As` OR
explicit assignment at a byte-mismatch clear-time verification".
FOLDED.

### 5. Codex m3 (copy sweeps + x25) — FOLDED

The retry-table reference and the §5.1 inventory say FOUR-LEGGED
with the (w-u) leg; the (x25) WRITE-UNVERIFIED legs are in the
formal §9 list (ENTER/HOLD/EXIT, split-key, restoration,
early-refusal, pass-N/N+1, fresh-box). FOLDED.

## B. Fresh attacks on the v32 delta

**Attack 1 (SUCCEEDED as nit m1) — the irrecoverable-generation
exit is unpinned.** Walk: key file lost → arm auto-creates K′
(pre-existing #1894 behavior) → confirm record under K′ → window
confirms → active.json under K′ → operator restores ORIGINAL K
over K′, clobbering it irrecoverably. Every validation now fails
(the files are K′-encrypted, the installed key is K), the state
HOLDS forever, all encrypted writes blocked, and the sanctioned
single-file removal is ALSO blocked — the (g-err) branch of the
active-side gate withholds the barrier because active.json does
not read under K either. The exit that remains is the BOTH-FILES
removal: the (g-absent) barrier proceeds (it only dir-fsyncs an
already-absent slot), the DB becomes absent/plaintext, the state
machine is vacuous, and the box re-bootstraps — at the cost of
the on-disk config's recoverability (the documented sacrifice,
same as master's clobbered-key outcome). The mechanics are all
present ((g-absent), the deletion warning, the boot re-seed) but
the plan never WALKS this path — an operator reading the
restoration runbook could conclude the box is unrecoverable when
it is recoverable-by-sacrifice. One paragraph fixes it: the
irrecoverable-generation exit is the both-files removal, named
explicitly with its sacrifice warning. MINOR.

**Attack 2 (FAILED) — precheck leaf asymmetry.** The candidate
DROPS master-password while the prev tree had it: the active
write is plaintext, but the confirm record still encrypts via
`rec.PrevTree` (`crypto.go:262-270`). The precheck evaluates BOTH
leaves (candidate's for active.json, prev's for the confirm
record) and refuses. FAILED.

**Attack 3 (FAILED) — second key swap between passes.** K
restored, pass N validates and exits, operator swaps to K″ before
pass N+1's active write. The write-side gate evaluates the
predicate FRESH under `s.mu` at action time (the r27 M1
placement pin — never a cached result): the key-path read yields
K″, the active-side validation of the K-encrypted on-disk
active.json under K″ FAILS → (g-err) → withhold → the state
RE-ENTERS on the key-class observation. No write happens under a
key that cannot read the current on-disk content — the
validate-at-write-time discipline makes every write
self-consistent under arbitrary operator key swapping, with
convergence whenever the operator stops swapping. FAILED.

**Attack 4 (FAILED) — the plaintext DB + lost stale key file.**
A fully-plaintext config DB with a stale missing key file: no
encrypted records exist, so no key-class failure is ever observed,
no encrypted write is ever attempted, and the write-unverified
state is never entered — the stale key file is irrelevant until
the first master-password commit, whose arm write creates a fresh
key (the #1894 design). No over-block. FAILED.

## C. Findings

### MAJOR (0)

None. Both r31 majors fold on independent verification; the state
machine survives every fresh interleave I could construct.

### MINOR (1)

**m1.** Pin the irrecoverable-generation exit explicitly: when the
on-disk records' key generation is irrecoverably lost (every
validation fails, the state holds), the operator's exit is the
BOTH-FILES removal — the (g-absent) barrier proceeds, the DB
returns to the absent/plaintext posture, the box re-bootstraps —
with the explicit sacrifice warning (the on-disk config's
crash-recovery intent is lost, matching master's clobbered-key
outcome).

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the
irrecoverable-generation exit walk). A v33 containing only this
pin is PLAN-READY by inspection from me.
