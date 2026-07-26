# Claude SMR hostile plan-review — round 29 (plan v29 @ `9e6bef427`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r28's SMR
returned PLAN-READY with the (B) split ruling; r29 re-verifies the v29
folds of Codex's 3M/3m + partials against the real code, attacks the
v29 delta (including the three attack questions posed to all
reviewers), and confirms the §4.7 structure. All line numbers
re-verified against the worktree.

## A. Fold verification (r28 findings → v29)

### 1. Codex M1 (complete producer inventory) — FOLDED

The v29 enumeration is complete: (w-a) durable rewrite, (w-b)/(w-c)
restores, R-kind (a) MATCH tombstone (the read-mutate-write helper —
the ONLY read-back tombstone producer), R-kind (c) MISMATCH durable
rewrite, D synthesized tombstone. Every one is a `WriteConfirm`
producer outside the arm path, and `WriteConfirm` encrypts via
`maybeEncryptTreeJSON` → `readOrCreateMasterKey` when the tree has a
master-password leaf (`db.go:207-217`, `crypto.go:262-270,457-479` —
re-verified). The R-kind four-state table now carries the gate note
and the x23 matrix covers the full producer set. The arm path's
create-on-first-use retention is deliberate and scoped (see Attack 3
below). FOLDED.

### 2. Codex M2 (key-path generation) — FOLDED

Both pins are present and sound: (i) offline/serialized remediation
by runbook (restore with xpfd stopped — natural under the systemd
singleton — or the next probe validates the restored key first);
(ii) every debt clear that consumed a key snapshot re-reads the path
at clear time and compares bytes — a mismatch retains. The compare
is EXACT-BYTES, which correctly survives a legitimate same-content
key rewrite (operator restores the SAME key via a new file — bytes
match, clear proceeds); a generation counter would have broken that
case. The both-files operator-provenance assumption is now stated
with its safe-if-wrong argument (the barrier only dir-fsyncs an
already-absent slot — verified the re-drive targets an absent path,
`db.go:297-315`). FOLDED.

### 3. Codex M3 (per-state key-class cause) — FOLDED

The snapshot carries `ConfirmDebtKeyClassMask` (per-debt-kind,
errors.As-derived at the owning debt's raise/retain, cleared only
with that debt) AND `ConfirmRecordKeyClass` (the latch-level cause,
cleared with the latch); the /health variant renders per the
RENDERED LEVEL's cause bit. The coexisting-debts case (R_A + W_B +
R_B) is representable (per-kind bits), and the boot key-class latch
(no debt) now has its own cause field. One accepted nuance (see
Attack 2): the mask renders the MOST SEVERE observed cause per kind
across retains — fail-loud, with the journal carrying per-attempt
exact causes. FOLDED.

### 4-6. Codex m1/m2/m3 — FOLDED

x24 gains the COMBINED plaintext-active / K-encrypted-confirm
scenario asserting ZERO write/delete — and the ordering is now
testable because the read-side key-class rule retains BEFORE any
write is attempted (the no-create primitive is never reached; a
plaintext tombstone performs no key access at all,
`crypto.go:262-265`). The nonce boundary is qualified correctly:
decode/length failures precede AEAD (`crypto.go:328-353` — the
#4793 length guard at :348-353 verified) → non-key-class; a
well-formed tampered nonce reaches `gcm.Open` (:354-356) →
key-class by indistinguishability. The arm-time D clear is pinned
as the arm's own supersession — semantically right: the arm's
overwrite IS the supersession the debt existed to perform, and the
clear rides the arm's own barrier. FOLDED.

### 7. Stale-copy sweep — FOLDED

`grep` over the committed doc: the normative definition, both x14
copies, both x21 copies, and the v-history entry all carry the
per-state causes; no singular `ConfirmDebtKeyClass bool` copy
remains outside annotated history; both (x4e') legs split
NON-KEY-CLASS TERMINAL vs KEY-CLASS RETAIN with the
content-INDEPENDENT exemption; zero "before the next W pass"
remnants; the formal §9 list runs x1-x24. FOLDED.

### 8. §4.7 structure — COHERENT

The core (A1 + writer conversion + snapshot boundaries + reader
conversion + sampler narrowing + canaries) stands alone: it closes
RACE-1/2/3 at the memory-ordering level and touches nothing G/H/H2
owns — no core section depends on the gate, the recovery invariant,
or the debt machinery (the accessor's nil-handling makes the
RACE-3 timer's read safe WITHOUT G's dispatch-ordering fix; G/H/H2
are pre-existing-defect hardening that trails). Codex's ordering
constraint is honored: G moves WITH H+H2, so G-without-H never
ships. The core regresses nothing vs master — every hazard it does
not address stays exactly as exposed as master is today. CONFIRMED.

## B. Fresh attacks on the v29 delta

**Attack 1 (FAILED) — transient failure of the clear-time path
re-read.** The validate→write→re-read→compare→clear sequence under
a transient re-read EACCES retains the debt with the restoration
message — the message over-names the cause (restoration vs
"couldn't verify"), but the debt retains and retries, the next
pass re-validates, and the journal carries the exact per-attempt
error. Fail-loud, self-healing, no correctness hazard. FAILED.

**Attack 2 (CONSIDERED-AND-ACCEPTED) — the mask's rendered cause
across mixed retains.** A debt raised non-key-class then retained
key-class sets the bit (key-class is the more actionable cause);
raised key-class then retained non-key-class KEEPS the bit (cleared
only with the owning debt) — the rendered cause can lag the latest
attempt's class. Accepted: the bit names the most severe cause the
debt has EVER retained against (key restoration remains necessary
for any key-class-observed debt — the record is unreadable under
the current key regardless of a later non-key error), the journal
carries per-attempt exact causes, and the alternative
(last-failure-wins) would FLIP the message away from key-class
while the record is still key-unreadable — strictly worse. FAILED
as a defect; the semantics are the right ones and the plan states
them.

**Attack 3 (FAILED with note) — the ARM path itself auto-creates.**
`writeConfirmState` → `WriteConfirm` → `readOrCreateMasterKey`:
a mid-life key-file loss followed by an encrypted ARM creates K′
and writes the confirm record under it while active.json remains
K-encrypted — the confirm record outruns the active config for the
window's duration. This is PRE-EXISTING #1894 behavior (the
DurableState comment at `crypto.go:471-476` documents
create-on-first-use for ANY encrypted write; master behaves
identically today), not introduced by the plan: the window's
confirm/rollback re-encrypts active under K′ consistently (both
writes read the now-persisted K′), a crash during the window fails
`Load` closed on the K-encrypted active (operator restores K —
same as master), and the repair-side machinery NEVER creates. The
plan names the arm-path retention deliberate ("the documented
#1894 fresh-box design"). NOTE for v30 if Codex wants it: an
honest-residuals sentence walking this exact case would make the
acceptance explicit rather than implicit. Not a finding — a
documentation nit at most.

**Attack 4 (FAILED) — §4.7 core secretly depends on H2.** The
core's RACE-3 fix converts the recovered confirm timer's `d.dp`
READ to the accessor (nil → degrade); the timer's confirm-record
durability is H2's domain and is untouched by the core. No core
test or conversion step references the gate, the latch, the debt
machinery, or the recovery invariant. The split is clean. FAILED.

## C. Findings

### MAJOR (0)

None. All three r28 majors fold on independent verification; the
v29 delta survives every fresh interleave I could construct.

### MINOR (0)

None at the design level. The Attack-3 note (make the arm-path
auto-create residual explicit in the honest-residuals set) is a
one-sentence documentation suggestion, not a defect — the behavior
is pre-existing and the plan already calls the arm-path retention
deliberate.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 as recorded: Codex (B), SMR (B), AGY (A) — 2-of-3 for
the split, AGY's dissent preserved verbatim, the design identical
under either packaging, the user makes the final call. My r28 (B)
ruling stands; Codex's ordering constraint (G with H+H2) is the
right refinement and is honored in the structure.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR) — with the §4.7 structure: PR-1
ships the `d.dp` accessor core; the G+H+H2 follow-up carries this
document's design as its seed. Equally PLAN-READY as a single PR
if the user prefers AGY's (A) packaging — the design closes either
way.
