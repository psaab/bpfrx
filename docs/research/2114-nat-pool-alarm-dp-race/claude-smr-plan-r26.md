# Claude SMR hostile plan-review — round 26 (plan v26 @ `1fda3b3c2`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r25's SMR
signed off with two nits (folded via Codex m1/m2); r26 re-verifies the
v26 folds and attacks the key-class machinery with fresh interleavings.
All line numbers re-verified against the worktree.

## A. Fold verification (r25 findings → v26)

### 1. Codex M1 (key-class laundering) — FOLDED, with nit m1

The laundering scenario is closed: under the key-class rule, a
WriteConfirm under a swapped-but-valid K′ is BLOCKED (the debt
retains; the message names master.key restoration), and any clear
following a key-class failure validates the active side under the
current key — never the confirm slot alone. The plaintext case is a
correct no-op (`maybeDecryptTreeJSON` passes through non-envelope
bodies with no key access, `crypto.go:303-356`, `db.go:37-70`).
FOLDED — but see m1: the key-class list conflates two different
master-key-IO classifications.

### 2. Codex M2 (D suppression) — FOLDED

The kill-shot is closed structurally: with ANY W debt pended, D
never reaches (d-i) at all — the W restore handles every slot
content ((w-u) restore-over-unreadable; (w-a)
make-visible-C-durable). The W-free determination is exhaustive: D
debts arise ONLY from the (ii-b) eager rule (plain commit/SyncApply
with the latch standing — no window armed); every confirmed-commit
outcome either replaces the record (success → (d-iii) clears D) or
creates a W debt (post-rename → (w-a); pre-rename → (w-c) restore)
— no path routes a confirmed-commit failure to D anymore. The
invalid-key kill-shot (encrypted W write blocked,
`crypto.go:262-270` keys off the prev tree's master-password leaf;
plaintext synthesized D succeeds) cannot occur because D never
runs while W pends. FOLDED.

### 3. Codex m1 (R rationale) — FOLDED

The corrected rationale (slot's occupant unprovable under a
permanent read error — a newer LIVE record may stand where R_K's
resolved record used to) is the right one. FOLDED.

### 4. Codex m2 (key-class remediation) — FOLDED

Journal + ORIGINAL master.key restoration + the live-record
deletion warning. FOLDED.

### 5. Codex m3 (exposure window) — FOLDED

Seconds-wide transient, unbounded up to the confirm window's end
under deterministic write failure, no post-crash heal — both copies.
FOLDED.

### 6. Codex m4 (ownership mechanism) — FOLDED

Stated as the operational single-xpfd assumption with enforcement a
follow-up. FOLDED.

### 7. Partial copies — FOLDED

x15 legs split; FirstCommit rationale corrected in both places;
generic message names slot-delete; §5.1 seeding shorthand names the
class split. FOLDED.

## B. Fresh attacks on the v26 delta

**Attack 1 (SUCCEEDED as nit m1) — master-key IO has TWO
classifications and the text pins only one.** The v26 key-class list
("authentication failure, master-key IO, invalid master-key length")
puts master-key IO in the WRITE-blocking set — correct and
load-bearing on the WRITE side, because `readOrCreateMasterKey`
AUTO-CREATES a fresh key on `IsNotExist` and persists it
(`crypto.go:457-479`): a repair write attempted while the key file
is missing would encrypt the confirm record under a NEW key —
exactly the laundering Codex M1 closed. But on the READ side, the
r17 taxonomy classifies master-key IO as TRANSIENT (retain + retry —
a missing mount or EACCES is recoverable), and that classification
is what keeps the (d-i)/(w-u) paths from being entered at all (they
require a PERMANENT read failure). As written, an implementer could
read "master-key IO is key-class permanent" and terminalize it,
contradicting r17. The one-paragraph pin: master-key IO is
READ-side TRANSIENT (retain + retry the read) AND WRITE-side
BLOCKED (a repair write would auto-create a fresh key and launder
the unreadable-active state); the key-class PERMANENT set for
read-side purposes is authentication failure + invalid observed key
length. MINOR.

**Attack 2 (FAILED) — active-side validation over-blocks plaintext
removals.** The active-side read for a plaintext config never
touches the key path (passthrough on non-envelope bodies,
`crypto.go:303-356`). The validation only bites when encryption is
configured. FAILED.

**Attack 3 (FAILED) — confirmed-commit arm success during the latch
leaves D stuck.** The arm's overwrite replaces the record; D's next
re-read classifies (d-iii) READABLE → clear as moot (the live
record is untouched). FAILED.

## C. Findings

### MAJOR (0)

None. The key-class laundering and the D-suppression kill-shot are
closed on independent verification; the W-free determination is
exhaustive; the plaintext paths are no-ops where they should be.

### MINOR (1)

**m1.** Pin master-key IO's two-sided classification explicitly:
READ-side TRANSIENT (retain + retry — r17's classification stands;
the (d-i)/(w-u) paths require a PERMANENT read failure, so a
transient key-IO error never reaches them) and WRITE-side BLOCKED
(`readOrCreateMasterKey` auto-creates and persists a fresh key on
`IsNotExist`, `crypto.go:457-479` — a repair write under it would
launder the unreadable-active state). The key-class PERMANENT set
for read-side purposes is authentication failure + invalid observed
key length.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — a two-sided
classification pin). A v27 containing only this pin is PLAN-READY by
inspection from me.
