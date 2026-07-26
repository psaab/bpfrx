# Claude SMR hostile plan-review — round 35 (plan v35 @ `04ac2d9a8`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r34's SMR
returned PLAN-READY; r35 re-verifies the v35 folds of Codex's 3M/1m
against the real code and attacks the remediation-race closures with
fresh interleavings. All line numbers re-verified against the
worktree.

## A. Fold verification (r34 findings → v35)

### 1. Codex M1 (remediations split by race safety) — FOLDED

The race was real: `ReadConfirm` is an ordinary read
(`db.go:242-248`) and the repair write is an unconditional atomic
replacement (`db.go:207-218` + `fsatomic.go:310-366`), so a D
tombstone or (w-u) restore could delete a record the operator
hand-repaired to valid between classification and rename. The
split is the right one and it composes with the doctrine:
REMOVAL is inherently safe live (the probe's confirmed-absence
barrier only re-fsyncs — a removed file cannot be destructively
overwritten); repair-to-valid goes offline (xpfd stopped, boot
classifies); and the in-process re-verify inside the same `s.mu`
hold shrinks the residual window to the fsatomic gap itself, with
the stopped requirement named as the authoritative closure.
FOLDED.

### 2. Codex M2 (state-exit key-identity compare) — FOLDED

The false clear was real: with no persistence debt, the debt-clear
compare never ran, so a post-validation swap to K′ exited the
state, terminated the loop, and turned health green with
undecryptable records. The v35 pin gives the STATE EXIT its own
final key-path re-read and exact-bytes compare against the
validation snapshot — the same discipline the debt clear carries,
generalized — and the x25 state-only second-swap regression pins
it. The after-clean-exit swap case is master's own posture (a key
swap on a healthy system is latent until the next store operation
detects it and re-enters) — no new gap. FOLDED.

### 3. Codex M3 (observability sweep) — FOLDED

Grep-verified: the §5.1 implementation inventory, both formal
test inventories, and the API precedence copy now carry
`ConfigWriteUnverified` in the aggregate formula AND the
WriteUnverified precedence position (ConfirmDebt > WriteUnverified
> ActivePersist). FOLDED.

### 4. Codex m1 (cumulative-summary punctuation) — FOLDED

The §11 sentence now attaches restoration ONLY to the key-class
set and assigns master-key IO the READ-side TRANSIENT retry with
the UNVERIFIABLE message. FOLDED.

## B. Fresh attacks on the v35 delta

**Attack 1 (CONSIDERED-AND-REJECTED) — post-write verification
read-back.** A read-back after the rename could detect an operator
clobber landing between the re-verify and the rename — but the
read-back itself races the same unlocked filesystem (the operator
can write after it), and the tombstone-write's success is already
the plan's signal. The stopped requirement is the authoritative
closure; the read-back buys complexity for a race the
operator-mediation doctrine already assigns to the operator.
REJECTED — not a defect.

**Attack 2 (FAILED) — false-green window WITH debts.** Between a
second swap and the next pass's re-validation, a clear flag could
read green — but the aggregate includes the debt mask, so any
standing debt keeps health at 503; the mask == 0 case is exactly
the state-only one the M2 exit-compare now covers. The
after-clean-exit swap is latent-until-next-operation, identical
to master's posture. FAILED.

**Attack 3 (SUCCEEDED as nit m1) — the stopped-repair branch
inherits the debt-provenance residual without naming it.** The
v35 fold requires repair-to-valid FILESYSTEM remediation with
xpfd stopped "in the same offline/serialized posture as the
BOOT-origin key-restoration branch" — that posture includes the
r30 Codex M2 precondition (`mask == 0` — never stop mid-debt, or
the process-local debts die and a pending-shaped record
hash-matches into re-arm/expired-revert at the next boot,
`store_persist.go:149-165,231-255,397-401`), but only BY
REFERENCE. An operator reading the repair-to-valid branch alone
could stop xpfd with live debts standing and re-enter the
admitted replay residual. One clause fixes it: the stopped
requirement carries the mask == 0 precondition explicitly (any
live process-local debt forces the live/probe-mediated path —
REMOVAL is the live-safe remediation, and removal also resolves
the corrupt-record case the operator was trying to repair).
MINOR.

## C. Findings

### MAJOR (0)

None. All three r34 majors fold on independent verification; the
v35 delta survives the residual attacks.

### MINOR (1)

**m1.** Make the `mask == 0` precondition explicit in the
repair-to-valid stopped-remediation branch (it currently holds
only by reference to the BOOT-origin key-restoration posture) —
any live process-local debt forces the live/probe-mediated path,
and REMOVAL is the live-safe remediation for the same corrupt
record.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the explicit mask ==
0 precondition in the stopped-repair branch). A v36 containing
only this pin is PLAN-READY by inspection from me.
