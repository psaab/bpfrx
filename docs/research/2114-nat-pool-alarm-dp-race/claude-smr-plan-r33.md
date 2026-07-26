# Claude SMR hostile plan-review — round 33 (plan v33 @ `ee4e82ee1`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r32's SMR
signed off with one nit (the irrecoverable-generation exit, folded
into Codex M1b's confirmed-empty exit); r33 re-verifies the v33 folds
of Codex's 2M/2m against the real code and attacks the completed
WRITE-UNVERIFIED machine with fresh interleavings. All line numbers
re-verified against the worktree.

## A. Fold verification (r32 findings → v33)

### 1. Codex M1a (action-scoped continuous EXIT) — FOLDED

The insufficiency was real: a one-shot decrypt-validation of "an"
encrypted record could exit the state while a second on-disk
generation (active.json under K, confirm record under K′) stayed
unreadable. The v33 form is the right one: the state is the
ABSENCE of a current positive validation, and every gated
encrypted write re-performs the fresh same-snapshot validation at
action time, covering BOTH sides' present encrypted generations —
the dual of the r26 laundering guard (a confirm repair must never
outrun an unreadable active config; an active write must never
outrun an unreadable confirm generation). A premature exit is
harmless by construction: the other generation's own action
re-validates and re-blocks. FOLDED.

### 2. Codex M1b + SMR r32 m1 (total + observable EXIT) — FOLDED

The totality gap was real: a decrypt-only exit is unreachable when
no ciphertext remains (final unreadable record sanctioned-removed,
or a never-encrypted DB). The CONFIRMED-EMPTY exit closes it with
the removal's data-loss warning already mandated by the
sanctioned-removal doctrine — and it is exactly the
irrecoverable-generation path: the single-file removal is withheld
by (g-err) (active.json does not read under the installed key
either), so the operator exits through the BOTH-FILES removal →
(g-absent) → absent/plaintext → CONFIRMED-EMPTY, with the explicit
sacrifice warning. The observability clause lands:
`ConfigWriteUnverified` joins the typed snapshot (NON-SECRET,
folded into the aggregate OR, /health message — §6 repertoire at
SIX) and the retry loop actively probes the key path each pass
while the state holds. FOLDED.

### 3. Codex M2 (second-swap leg) — FOLDED

The leg was real: a plaintext-on-disk active side makes the (g-ok)
validation a no-op, so a K″ swap between the exit pass and the
deferred active write would have re-encrypted under K″ while a
K-era confirm record stood. The both-sides validation from (1)
closes it: the write withholds whenever a confirm-side encrypted
generation exists and fails the snapshot's validation — the
plaintext active side no longer exempts it. FOLDED.

### 4. Codex m1/m2 (keyClass copies + message class-split) — FOLDED

Grep-verified: no errors.As-only keyClass copy remains (all read
"errors.As OR explicit byte-mismatch assignment"); the (w-u)/(d-i)
block copies now class-split the missing-key message
(invalid-LENGTH/byte-MISMATCH → RESTORATION; ENOENT/EACCES/
mount-IO → UNVERIFIABLE, no restoration claim) — reconciled with
the normative taxonomy. FOLDED.

## B. Fresh attacks on the v33 delta

**Attack 1 (FAILED) — a new encrypted record appears between the
confirmed-empty proof and the exit.** While the state holds, every
arm path is refused (the early precheck covers interactive commit
confirmed AND the bootstrap import — both are commits at the Store
persistence layer), every active write is blocked (plain commits,
SyncApply, AND the rollback timer's `performAutoRollback` — a
config-DB write like any other), and the repair machinery is
gated by the same state. No writer remains that could create an
encrypted record mid-proof. FAILED.

**Attack 2 (FAILED) — both-sides validation deadlocks or stalls
the retry loop.** The loop already performs filesystem I/O under
`s.mu` per attempt (`store_persist.go:402-428` — the active write
itself); the confirm-side ReadConfirm+decrypt added to a gated
active write is the same class of operation under the same single
lock — no nesting, no new lock order, one extra file read+decrypt
per gated write while encrypted records exist. FAILED.

**Attack 3 (CONSIDERED-AND-CLOSED) — the stay-alive probe's
termination.** The loop's exit condition
(`store_persist.go:402-410`: exits when !persistDegraded &&
!confirmRemoveDegraded) gains writeUnverified as a stay-alive
condition — pinned in the observability clause ("the loop is kept
ALIVE by the outstanding state even with no debt/latch/mask").
Once the probe validates and the state exits, the next evaluation
of the unmodified condition terminates the loop cleanly — one
extra pass of liveness, no leak. CLOSED.

**Attack 4 (FAILED) — the confirmed-empty exit fires with a live
window's record on disk.** The exit requires NO encrypted or
unreadable record to remain; a live window's record is encrypted
(when the prev tree has master-password), so the exit cannot fire
while it stands; and the arm-supersession machinery (m3 pin)
clears D only via the arm's own durable barrier — the exit and
the window lifecycle never overlap destructively. FAILED.

## C. Findings

### MAJOR (0)

None. Both r32 majors fold on independent verification; the
completed state machine survives every fresh interleave I could
construct.

### MINOR (0)

None. My r32 nit is folded into the confirmed-empty exit and its
x25 leg.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR) — with the §4.7 structure: PR-1
ships the `d.dp` accessor core; the G+H+H2 follow-up carries this
document's design as its seed. Equally PLAN-READY as a single PR
if the user prefers AGY's (A) packaging.
