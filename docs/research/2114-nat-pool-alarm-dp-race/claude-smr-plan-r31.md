# Claude SMR hostile plan-review — round 31 (plan v31 @ `445cbd2b1`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r30's SMR
signed off with one nit (the barrier choice, folded into Codex m2's
deferred-barrier pin); r31 re-verifies the v31 folds of Codex's 2M/2m
against the real code and attacks the remediation-protocol delta with
fresh interleavings. All line numbers re-verified against the
worktree.

## A. Fold verification (r30 findings → v31)

### 1. Codex M1 (split-key interleave) — FOLDED

The interleave was real: `persistRetryLoop` heals `persistDegraded`
FIRST (`store_persist.go:414-428`, re-verified) and the active
write's encryption consumes the CURRENTLY INSTALLED key
(`crypto.go:262-270` → `readOrCreateMasterKey`, re-verified), so a
wrong-but-valid K″ installed mid-debt would re-encrypt active.json
under K″ and strand the two files on different keys with no
single-key convergence. The v31 rule closes it at the only
sufficient point: WHILE ANY KEY-CLASS FAILURE IS OUTSTANDING, EVERY
ENCRYPTED config-DB write is blocked (the active retry withholds —
the in-memory tree stays the source of truth; new arms/commits are
refused at the persistence layer with a key-remediation error). The
split cannot form because no file is ever re-encrypted under an
unverified key; with K restored, the confirm-side re-reads heal
and the flag clears; with K″ installed, the key-class debts keep
failing and the write stays blocked. The one-pass lag (the gate
evaluates the previous pass's confirm-side state, preserving the
#5473 active-heal → resolution-finalize order) costs one extra
degraded pass after restoration — zero hazard, since the skipped
write is retried and the on-disk state stays coherent throughout
(the temp+rename atomicity of every write). No deadlock: the
operator's restoration (or the sanctioned record removal) is the
only exit from the outstanding state, and both are exactly what
the health message instructs. FOLDED.

### 2. Codex M2 (branch keys on live debt) — FOLDED

The mixed state is real (a confirmed commit during the BOOT latch
can fail its arm pre-rename and create a W debt — the W-creation
rules make no latch exception). The v31 keying is the only correct
one: the abandon hazard lives in the process-local DEBT, not the
latch, so `mask ≠ 0` forces the running/wait branch and only
`mask == 0` permits stopped-restore; the mixed-state regression
pins BOOT latch + live W → running/wait rendered. FOLDED.

### 3. Codex m1 (re-read taxonomy) — FOLDED

The three outcomes are now representable and mutually
distinguished: byte-MISMATCH sets keyClass EXPLICITLY (the key's
identity changed — a comparison outcome but a key-class condition),
invalid-length matches `ErrMasterKeyLength` (already key-class via
the typed source) — both restoration-required; EACCES/ENOENT/
mount-IO → key-state-UNVERIFIABLE under the generic confirm-debt
text with the exact error journaled and NO restoration claim. The
health variant selection (key-class bit set → restoration variant;
clear → generic) covers all three. FOLDED.

### 4. Codex m2 = SMR r30 m1 (barrier choice) — FOLDED

The pin is the durability barrier (dir-fsync, `fsatomic.go:45-79`),
never rename visibility: arm success → D clears with the barrier;
failed barrier (pre- or post-rename) → D survives, suppressed by
the resulting W debt; and the deferred case — post-rename arm
failure, then successful (w-a) — clears D WITH W, since (w-a)'s
durable `WriteConfirm` IS the deferred barrier and the slot
provably holds the durable live record. The chain is consistent
across the m3 pin, the D table, the W table, and both x22a legs.
FOLDED.

### 5. Residual copies — FOLDED

Grep-verified: both x23 matrices name (w-u); both x24 copies carry
the re-read taxonomy; the W table is four-legged at every summary
(the v20-history and §5.1 three-state copies are annotated);
§9's item 1 is untagged (both units) with items 3–5 [CORE]; the
source-comment rewording block points at the FOLLOW-UP unit.
FOLDED.

## B. Fresh attacks on the v31 delta

**Attack 1 (FAILED) — commit refusal bricks a day-0 box.** A key-
class latch requires a prior confirm record, which requires a
prior confirmed commit — so a never-committed box has no latch and
the bootstrap import proceeds. The mixed case (confirm record
exists + active.json absent → Load starts fresh with the latch
standing) refuses the bootstrap import — but that box is mid-
remediation by definition (the latch demands key restoration or
record removal), and after remediation the latch clears and the
import proceeds. Refusing the import is strictly safer than
writing the first active.json under an unverified key. FAILED.

**Attack 2 (FAILED) — W stale-clear orphans D.** Window resolves
while W pends → W stale-clears; the resolution's own finalize
tombstones/deletes the slot record (or defers it with
`confirmResolvePendingPersist` → `persistDegraded` stands → the
third conjunct keeps D inert until the replacement lands). D's
next fresh re-read then resolves mechanically: absent → (d-ii)
re-drive + clear; `Resolved` → finish the delete; readable live →
(d-iii) clear as moot (gated). Every transitional state is covered
by a conjunct; D can never be orphaned beside a finalized slot.
FAILED.

**Attack 3 (FAILED) — the one-pass lag loses a write at shutdown.**
A shutdown between pass N (flag cleared) and pass N+1 (active
write) abandons the retry loop (`store_persist.go:397-401` —
pre-existing accepted behavior): every write is temp+rename atomic,
so on-disk active.json is always a coherent whole (at worst one
config version stale, exactly the #1799 degraded contract, with
health loudly 503 the entire window). No torn or half-written
state is possible. FAILED.

**Attack 4 (FAILED) — the encrypted-write block deadlocks against
persistDegraded.** persistDegraded clears only via the active
write; the active write is blocked while key-class is outstanding;
key-class clears only via confirm-side re-validation (operator-
restored key) or the sanctioned removal. The exit is always an
operator action the health message names — the intended loud
posture, not a deadlock (the system keeps forwarding on the
in-memory config throughout). FAILED.

## C. Findings

### MAJOR (0)

None. Both r30 majors fold on independent verification; the v31
remediation protocol survives every fresh interleave I could
construct — including the bootstrap-brick, orphan-D, shutdown-lag,
and deadlock attacks above.

### MINOR (0)

None. My r30 barrier nit is folded into the m3 pin and both x22a
legs.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR) — with the §4.7 structure: PR-1
ships the `d.dp` accessor core; the G+H+H2 follow-up carries this
document's design as its seed. Equally PLAN-READY as a single PR
if the user prefers AGY's (A) packaging.
