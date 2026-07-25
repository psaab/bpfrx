# Claude SMR hostile plan-review — round 25 (plan v25 @ `3028893aa`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r24's SMR
signed off with two doctrine nits (both subsumed by the v25 Codex
folds); r25 re-verifies the v25 folds and attacks the unified doctrine
with fresh interleavings. All line numbers re-verified against the
worktree.

## A. Fold verification (r24 findings → v25)

### 1. Codex M1 (permanent-error state machine) — FOLDED, with nit m1

The contradiction is gone: terminalization is scoped to
content-DEPENDENT debts (the R-kind read-back tombstone), and the
content-INDEPENDENT debts (W restore, D synthesized tombstone) are
exempt with the provably-superseded justification. The boundary is
CORRECT on a walk the plan does not quite spell out: a
content-dependent debt cannot distinguish a corrupt RESOLVED record
from a corrupt LIVE one (master-key corruption makes a live encrypted
record "permanent unreadable" — and the single slot means the
unreadable record could be either), so it must not auto-act; a
content-independent debt acts only where supersession is provable
WITHOUT reading (a newer durable config landed after the record's
window). The write-failure doctrine (retain + capped backoff +
degraded, never terminalize — a read-only FS loops at 503) is
consistent with every other debt kind, and the invalid-master-key
case (both read and write fail permanently, `crypto.go:443-465`)
correctly loops degraded-and-loud. FOLDED — but the rationale should
name the live-record-hiding case explicitly (m1 below).

### 2. Codex M2 (downgrade oracle) — FOLDED

Verified against the recovery code: `s.active = rec.PrevTree` always
(`store_persist.go:166-172`); the `FirstCommit` branch decides the
POSTURE (`compiled=nil`, `everCommitted=false`, `committed=0` at
`:176-184` → bootstrap handling) vs the else branch (compile
`PrevTree`, `everCommitted=true`, `committed=1`). The corrected
rationale and the posture-asserting regression (serialized
`FirstCommit=false` + `compiled` + `committed=1` + non-bootstrap
boot class, with the `FirstCommit=true` variant landing in
bootstrap handling) are exactly right. FOLDED.

### 3. Codex m1 ((w-u) phase qualification) — FOLDED

Pre-rename → D's (d-i); post-rename → live C visible, W stays owed
((w-a)), D's re-read reaches (d-iii) → clear as moot. Both phase
regressions named. FOLDED.

### 4. Codex m2 (schema consistency) — FOLDED

§5.1 and both x14/x21 copies now carry the exact three-value
breakdown with the aggregate DERIVED. FOLDED.

### 5. Codex m3 = SMR m2 (operator ownership) — FOLDED

The Store-owned-slot pin is present with the sanctioned-remediation
pair (removal, or repair-to-valid-then-classify) and the
classification-not-trust guarantee. FOLDED.

### 6. Codex m4 (residual wording) — FOLDED

The residual now reads as an exposure window (crash must land inside
it) with no post-crash heal. FOLDED.

## B. Fresh attacks on the v25 delta

**Attack 1 (SUCCEEDED as nit m1) — the terminal-vs-exempt rationale
should name the live-record-hiding case.** The v25 text justifies the
boundary as "operator-inspect vs provably-superseded" — true, but the
SHARP reason the R-kind terminal case cannot use the synthesized path
is that the single slot's corrupt record could be a LIVE window's
record made unreadable by key corruption, and the R-kind debt cannot
distinguish that from its own resolved record without reading it.
The (w-u)/(d-i) exemption is safe for the dual reason: their content
is independent of the read AND their precondition (a newer durable
config landed after the record's window) makes the record
provably-stale regardless of what the corrupt bytes were. One-
paragraph sharpening so an implementer does not "optimize" the
R-kind terminal case into the synthesized path. MINOR.

**Attack 2 (SUCCEEDED as nit m2) — the master-key remediation pointer
is missing from the ConfirmDebt message path.** During an
invalid-master-key loop, health renders the generic ConfirmDebt
message ("removal/rewrite not yet durable; retry in progress") while
the actual remediation is `master.key` repair, not anything to
confirm.json. The journal carries the crypto error, but the
operator-facing message/runbook should point at it: when the debt
loop stalls with crypto-class errors, the remediation is
`master.key` repair — one line in the health detail field or the
runbook. MINOR.

**Attack 3 (FAILED) — the (d-i) exemption extended to an R-kind
known-resolved record.** Tempting (a resolved record's tombstone is
content-free), but the slot's content is unverifiable under a
permanent read error — see Attack 1. The terminal latch is correct.
FAILED.

## C. Findings

### MAJOR (0)

None. The v25 doctrine is self-consistent on independent
verification: terminalization scopes to debts that cannot act
without reading, exemptions apply only where action needs no read
AND supersession is provable without one, and write failures never
terminalize anywhere.

### MINOR (2)

**m1.** Sharpen the terminal-vs-exempt rationale with the
live-record-hiding case (a content-dependent debt cannot distinguish
a corrupt resolved record from a corrupt live one on the single
slot; the exemption is safe only because BOTH the content AND the
staleness of the target are read-independent).

**m2.** Point the ConfirmDebt remediation at `master.key` when the
stall is crypto-class (one line in the health detail or the
runbook — the generic "retry in progress" message would otherwise
send the operator at confirm.json).

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — a rationale sharpening
and a remediation pointer). A v26 containing only these pins is
PLAN-READY by inspection from me.
