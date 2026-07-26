# Claude SMR hostile plan-review — round 28 (plan v28 @ `7d772594f`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r27's SMR
signed off with one nit (the plaintext-write over-block, folded into the
v28 no-create primitive); r28 re-verifies the v28 folds of Codex's
4M/2m against the real code and attacks the v28 delta with fresh
interleavings. All line numbers re-verified against the worktree.

## A. Fold verification (r27 findings → v28)

### 1. Codex M1 (executable gate state machine) — FOLDED

The under-specification was real: `readTreeMeta` returns
`(nil, true, nil)` on `os.IsNotExist` (`db.go:323-327` — verified),
so an error-only predicate would have treated a MISSING active.json
as healthy, and a non-nil-tree predicate would have blocked the
sanctioned both-files-removed barrier. The v28 three-way machine
pins exactly the right semantics: (g-ok) PROCEED; (g-absent)
PROCEED only for the barrier (active absence IS the operator's
both-files intent), WITHHOLD everything else — critically, the W
restore withholds under (g-absent), so a live window's
crash-recovery file cannot be clobbered while active is absent
(the window's own resolution drives the state forward: confirm →
active lands → (g-ok); rollback → W stale-clears). Placement is
sound at boot because `Load` holds `s.mu` for its whole body
(`store_persist.go:23-25`, verified) — the gate's consumption of
Load's own `ReadActiveMeta` result cannot go stale mid-Load — and
at runtime the fresh read under `s.mu` at action time is the same
serialization the retry loop already uses
(`store_persist.go:402-428`). (g-err) withholds without
terminalizing for EACCES and corrupt-active alike — consistent
with the no-write-failure-terminalizes doctrine. FOLDED.

### 2. Codex M2 (no-create, single-snapshot writes) — FOLDED

The hole was real: `WriteConfirm` calls `maybeEncryptTreeJSON`
(`db.go:212-215`, verified) which calls `readOrCreateMasterKey`
(`crypto.go:266-268`) whenever the candidate's prev tree carries a
master-password leaf — so every repair write previously reached the
auto-create path (`crypto.go:457-479`, verified: generates a fresh
32-byte key and durably persists it on `IsNotExist`). The v28
primitive sources repair-write keys via `readMasterKey`
(`crypto.go:443-455`, verified: NEVER creates, fails on
missing/invalid) and feeds ONE snapshot under `s.mu` to both the
gate validation and the write — the K→K′ check/write race is closed
by construction. The scoping is right: the no-create primitive
applies to REPAIR writes only; the ordinary arm write keeps
`WriteConfirm`'s create-on-first-use (the documented #1894
fresh-box design). My r27 m1 is folded: the plaintext exemption is
structural (`crypto.go:262-265` returns the body untouched when
`masterPasswordPRF(tree) == ""` — verified), so a plaintext repair
write performs no key access and cannot be over-blocked. FOLDED.

### 3. Codex M3 (D vs undurable replacement) — FOLDED

The scenario verifies against `store.go:714-745`:
`cancelPendingConfirmTimerLocked()` runs BEFORE `writeActive`, and
on write failure `noteActivePersistFailureLocked` +
`confirmResolvePendingPersist = true` keep C's record while
`persistDegraded` stands — exactly the window where v27's D (no W,
`armedArmID == ""`) could have (d-i)-tombstoned the only recovery
intent for the still-on-disk unconfirmed C. The third conjunct
(`persistDegraded == false`) makes D inert for precisely that
window, and the composition with the retry loop is sound: the loop
heals `persistDegraded` FIRST, then
`clearConfirmResolutionPendingLocked` runs the resolution's own
tombstone→delete (`store_persist.go:414-428`), so C's record is
removed by its OWN machinery once the replacement is durable — D's
fresh re-read afterward finds the slot absent/tombstoned and clears
as moot. Over-suppression in the routine case (an active-write
failure unrelated to any window) is safe: D lingers inert while
health is already loudly 503, and proceeds when the active write
heals. FOLDED.

### 4. Codex M4 (typed sentinel sources) — FOLDED

The gap was real: `gcm.Open`'s error is unexported-typed and
`crypto.go:354-356` wraps it as an ordinary error (verified);
`readMasterKey`'s invalid-length error is a plain `fmt.Errorf`
with NO `%w` (`crypto.go:451-453`, verified). The v28 pin
(`ErrMasterKeyAuth` at the gcm.Open wrap, `ErrMasterKeyLength` at
both length gates, both matching
`errors.As(err, &ConfirmRecordKeyClassError)` while preserving
`ConfirmRecordPermanentError`) is constructible: `ReadConfirm`'s
`%w` chain (`db.go:250-252`) passes typed causes through, and
`maybeDecryptTreeJSON`'s "encrypted config but master key
unavailable: %w" wrap (`crypto.go:316-318`) preserves the
IO-vs-length distinction the two-sided classification hinges on.
The x24 boundary set is complete: auth/length → key-class; missing
file/EACCES → transient by construction (no sentinel carried);
PRF/format/nonce/base64 → non-key permanent (unencrypted envelope
header, `crypto.go:28-32,307,323-326,348-353` — key-independent
corruption). `crypto.go` is now in the §5.1 inventory. FOLDED.

### 5. Codex m1/m2 + partials — FOLDED

The `ConfirmDebtKeyClass` bool crosses the Store→API boundary in
the typed snapshot (non-secret, errors.As-derived at debt
raise/retain — never message text) with both /health variants
regression-pinned; the (x22) durable-arm + SyncApply-pre-rename
legs and the (x23)/(x24) matrices are in §9; `grep` confirms zero
remaining "before the next W pass" copies (all now "next
SUCCESSFUL W restore — failed passes do not close the gap"), zero
unannotated "returns the slot to D's (d-i) path" copies, and zero
"any clear validates" remnants. FOLDED.

## B. Fresh attacks on the v28 delta

**Attack 1 (FAILED) — K′-valid key file, plaintext active,
K-encrypted confirm record.** The gate passes (plaintext no-op)
while `ReadConfirm` fails authentication — but the READ-side
key-class rule retains the debt with NO write attempted, and the
no-create primitive does not weaken it (the write is never
reached). The two mechanisms compose: read-classification gates
the ATTEMPT, the primitive constrains the WRITE's key sourcing,
the gate constrains the ACTIVE side. FAILED.

**Attack 2 (FAILED) — (g-absent) clears a debt whose slot held a
live record.** Under (g-absent) only the barrier proceeds; every
write action withholds. An operator who removed both files intends
the confirm state gone; the barrier's unlink is idempotent; and
the automatic machinery's (d-ii) re-drive under (g-absent) targets
an already-absent slot. No path sacrifices a live record the
operator did not already sacrifice by hand. FAILED.

**Attack 3 (FAILED) — the boot gate's ReadActiveMeta result goes
stale before the recovery sequence.** `Load` holds `s.mu` from
entry (`store_persist.go:23-25`); no commit/sync can interleave
between the active read at :26-35 and the recovery steps at
:113-140. The consumed result is fresh by lock construction.
FAILED.

**Attack 4 (FAILED) — key-class at BOOT contradicts runtime
RETAIN.** Boot terminalizes the key-class record into the R-kind
operator-mediated latch (repair = restore ORIGINAL master.key;
remove = sacrifice crash recovery, with the warning) because boot
has no retry loop to pend in — the latch IS the pending state;
the key-class /health variant names the same remediation. Both
fail closed; the surfaces are consistent. FAILED.

## C. Findings

### MAJOR (0)

None. All four r27 majors fold on independent verification; the
v28 delta survives every fresh interleave I could construct.

### MINOR (0)

None. My r27 nit is folded into the no-create primitive's
plaintext exemption.

## D. Split ruling (§11 question 6)

**(B) SPLIT.** The v28 folds are real and the H2 design is now
executable-pinned — but the honest engineering unit is two PRs,
not one. The A-G `d.dp` accessor core (the issue's TITLED defect:
RACE-1/2/3, the atomic cell, the sampler narrowing, the startup
gate) has been triple-stable for ~18 rounds and converts ~244
sites; H2 is a separable pre-existing durability-defect complex in
`pkg/configstore` (typed sentinels, no-create primitive, gate
machine, debt machinery, health plumbing, ~24 regression legs)
that the hostile audit pulled into scope. Bundling them makes one
unreviewable PR; `docs/engineering-style.md` principle 5 (narrow
scope) says split. The r19-recorded analysis holds: H-without-H2
is unsound, so H moves WITH H2. ORDERING: the follow-up may TRAIL
the core's merge — H2's defects are pre-existing on master (the
core introduces no new exposure), so the follow-up sequences them
rather than gating the titled fix. The follow-up issue carries the
v28 H2 design as its research seed and should be the NEXT work
item driven.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR) — with the (B) SPLIT ruling: the
A-G core is the #2114 deliverable; H+H2 move to a named follow-up
issue carrying the v28 design as its seed. If the other two
reviewers rule (A) CONVERGE instead, the v28 full plan is also
PLAN-READY as a single PR from me — the design closes either way;
the split is a scope recommendation, not a correctness gate.
