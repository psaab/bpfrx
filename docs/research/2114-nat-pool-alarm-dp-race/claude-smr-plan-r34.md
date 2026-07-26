# Claude SMR hostile plan-review — round 34 (plan v34 @ `0e344b03e`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r33's SMR
returned PLAN-READY; r34 re-verifies the v34 folds of Codex's 3M/2m
against the real code and attacks the completed state machine's
composition with the repair exemptions. All line numbers re-verified
against the worktree.

## A. Fold verification (r33 findings → v34)

### 1. Codex M1 (side-asymmetric validation) — FOLDED

The deadlock was real and my r33 pass missed it: the
content-INDEPENDENT repairs exist precisely for targets that can
NEVER validate (too-new envelope, unsupported PRF, malformed nonce
— the unencrypted envelope header makes them provably unparseable
under any key, `crypto.go:307-356`, re-verified), so an own-target
validation requirement would have bricked the escape hatch and
prevented CONFIRMED-EMPTY from ever firing. The v34 asymmetry is
the right cut: the OPPOSITE side's generations must validate (the
laundering guard's dual), while the own-target is exempt exactly
when its classification is NON-KEY-CLASS PERMANENT — the
classification that makes the overwrite safe. The (w-u)/(d-i)
legs cross-reference the exemption; the walkthrough (too-new
confirm + restored key access → active validates, own-target
exempt, the tombstone proceeds, CONFIRMED-EMPTY can fire after)
is coherent. FOLDED.

### 2. Codex M2 (CONFIRMED-EMPTY proof + priority) — FOLDED

The proof is executable: one fresh under-`s.mu` classification of
BOTH files using ONE key byte snapshot, with the envelope-detected
bit (structural, key-INDEPENDENT — `unmarshalEnvelope` at
`crypto.go:307`) surfaced at both call sites. The
encrypted-or-plaintext classification therefore cannot be fooled
by a mid-scan key swap (it is structural); only the
decrypt-validation uses the key, and its failure withholds (safe
direction). The priority is pinned: CONFIRMED-EMPTY is
authoritative BEFORE the key-probe HOLD (nothing left to
protect), and the under-`s.mu` scan excludes Store-origin arm
interleavings by construction. FOLDED.

### 3. Codex M3 (observability swept) — FOLDED

Grep-verified: every loop-exit copy now keeps the loop alive on
the outstanding state (three copies amended); every exact
schema/aggregate copy carries `ConfigWriteUnverified` (five
copies amended); the precedence list inserts WriteUnverified
between ConfirmDebt and ActivePersist (all renderings). FOLDED.

### 4. Codex m1 (Save lock) — FOLDED

`Save()` takes `s.mu.Lock()` — the mutation of
`ConfigWriteUnverified` and the loop start/retain are
synchronized; the operator/API save path is not hot, so the
upgrade from RLock costs nothing; the x25 inventory gains the
exported-path leg. FOLDED.

### 5. Codex m2 (SyncApply admission) — FOLDED

Promote-in-memory + withhold-persistence is the only composition
consistent with both contracts: #1799 Option B (the in-memory
apply MUST stand — refusing diverges the cluster) and
write-safety (the encrypted disk write is withheld and raises
the active-persist debt, healed current-tree-always per
`store_persist.go:414-420` after the state exits, with the #5473
deferred-removal finalize ordering preserved). FOLDED.

### 6. Fold-partials — FOLDED

The last errors.As-only per-debt definition now reads
"errors.As OR explicit byte-mismatch assignment"; all three
missing-key-file restoration lumps are class-split
(invalid-LENGTH/byte-MISMATCH → restoration; ENOENT/EACCES/
mount-IO → UNVERIFIABLE). FOLDED.

## B. Fresh attacks on the v34 delta

**Attack 1 (FAILED with note) — operator hand-repair races the
exempt overwrite.** An operator replaces a corrupt confirm record
with a valid one between the repair's classify (T0) and its
overwrite (T2). The operator race is outside `s.mu` by nature —
but it is exactly the domain the store-owned-file doctrine
already governs: the confirm slot is STORE-OWNED and the
sanctioned operator paths are removal or repair-to-valid-then-
classify; the runbook's repair path should say the operator
repairs with the retry loop quiesced (or accepts that a landing
tombstone may delete the hand-repaired record — after which the
machinery simply re-classifies). For the (w-u) case the
overwrite installs the LIVE window's authoritative record — the
correct end state regardless. NOTE (not a finding): the runbook
paragraph should name the hand-repair-vs-tombstone race
explicitly. FAILED as a design defect.

**Attack 2 (FAILED) — mid-scan key swap fools the empty proof.**
The empty proof is STRUCTURAL (the envelope is unencrypted JSON
framing — `unmarshalEnvelope` needs no key): a key-path swap
mid-scan cannot flip an encrypted record to "plaintext". The
decrypt-validation is the only key-dependent step and fails
closed (withhold). FAILED.

**Attack 3 (FAILED) — SyncApply withheld write breaks the #5473
retention ordering.** The withheld write raises the active-persist
debt; `confirmResolvePendingPersist` stands; the post-exit heal
re-writes the CURRENT in-memory tree under `s.mu`
(`store_persist.go:414-420` — never a stale capture), and
`clearConfirmResolutionPendingLocked` finalizes the deferred
removal only after the CURRENT replacement is durable — exactly
the r15 failed-SyncApply divergence fix. FAILED.

## C. Findings

### MAJOR (0)

None. All three r33 majors fold on independent verification; the
v34 delta survives every fresh interleave I could construct.

### MINOR (0)

None at the design level. The Attack-1 note (name the
hand-repair-vs-tombstone operator race in the runbook paragraph)
is a one-sentence documentation suggestion inside an already-
governed doctrine, not a defect.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR) — with the §4.7 structure: PR-1
ships the `d.dp` accessor core; the G+H+H2 follow-up carries this
document's design as its seed. Equally PLAN-READY as a single PR
if the user prefers AGY's (A) packaging.
