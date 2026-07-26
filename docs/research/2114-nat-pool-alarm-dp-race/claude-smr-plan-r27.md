# Claude SMR hostile plan-review — round 27 (plan v27 @ `554c61356`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r26's SMR
signed off with one nit (the two-sided master-key-IO pin, folded into
Codex M3); r27 re-verifies the v27 folds of Codex's 3M/1m plus the
five fold-verification PARTIALs, and attacks the v27 delta with fresh
interleavings. All line numbers re-verified against the worktree.

Disclosure: this round's SMR pass reviewed the v27 DRAFT before commit
and caught five residual stale copies from Codex's r26 fold-verification
partials that the draft had missed — the "owner is known" resurrection,
the "seconds-wide next-pass restore" promise, two slot-delete omissions
(§5.1 `pkg/api` inventory + docs-inventory aggregate-cause copy), the
unqualified PERMANENT-class repair-authorizing copies (v24-history
(d-i) half, §11 r22/r23/(w-u) summaries), and the W-only D-suppression
copies (v25 history entry + §11 cumulative summary). Those were
corrected in the committed v27; the verification below is against the
committed doc.

## A. Fold verification (r26 findings → v27)

### 1. Codex M1 (laundering guard generalized) — FOLDED

The absence-path bypass is closed structurally: EVERY W/D repair
action (restore, synthesized tombstone, delete) AND every
confirm-side clear is gated on the ACTIVE side being readable under
the current key. The W three-state table now carries an explicit
every-action gate note that names the (w-c) absent-slot case as the
motivating bypass (`ReadConfirm` returns `(nil, nil)` on IsNotExist
without decrypting — verified `db.go:242-248`: the `os.IsNotExist`
branch returns before `maybeDecryptTreeJSON` is reached). The (d-i)
leg, the § tombstone/delete copies, and the x15 boundary copy all
carry the same gate. The gate is a verified no-op for plaintext
active configs: `maybeDecryptTreeJSON` returns non-envelope bodies
via `if !ok { return data, false, nil }` with NO key access
(`crypto.go:307-314`), so a plaintext `active.json` reads regardless
of key-file state. On validation failure the action is WITHHELD
(retained), never terminalized — consistent with the write-side
doctrine that no write failure terminalizes. FOLDED.

### 2. Codex M2 (D suppression broadened to any live window) — FOLDED

The durable-arm gap is closed: D NEVER acts while any W debt pends
OR `armedArmID != ""`; D acts ONLY when no live window exists. The
in-memory `armedArmID` independently suppresses D even when the arm
was DURABLE (no W debt created) — so a blocked (d-iii) moot-clear can
no longer leave D routable to (d-i) by a later non-key permanent read
error. `grep -n "W-free"` over the committed doc returns ZERO hits;
the normative D block, the v25/v27 history entries, and the §11
cumulative summary all state the broadened condition. Post-restart
liveness is sound: the D-kind debt is process-local (not recreated at
boot), `armedArmID` resets to `""`, and the eager rule's "no live
window" determination re-reads the SLOT (the re-read classification),
not the in-memory flag — a post-restart D cannot be mis-suppressed
because it cannot exist. FOLDED.

### 3. Codex M3 = SMR r26 m1 (mechanical taxonomy) — FOLDED, with nit m1

The taxonomy is now mechanical: `ConfirmRecordKeyClassError`
(authentication failure + invalid observed key length) consumed via
`errors.As`, never string-matched; every repair-permitting copy says
NON-KEY-CLASS-PERMANENT (verified: the remaining bare
`PERMANENT-class` hits are all READ-side boot/latch/fail-closed
copies where terminalizing key-class records into the R-kind
operator-mediated latch is the intended behavior). The two-sided
master-key-IO classification is verified against the code:
`readMasterKey` (`crypto.go:444-455`, decrypt path) NEVER creates
and returns a wrapped IO error on a missing file (READ-side
TRANSIENT — a missing mount/EACCES is recoverable) vs the invalid
length error naming the path (`crypto.go:451-453` — KEY-CLASS
PERMANENT, the observed key's content is wrong); while
`readOrCreateMasterKey` (`crypto.go:457-481`, encrypt path)
AUTO-CREATES and durably persists a fresh 32-byte key on
`IsNotExist` — so a repair WRITE attempted with the key file missing
would encrypt under a NEW key and launder the unreadable-active
state (WRITE-side BLOCKED). The distinction the classification hinges
on (IO vs invalid length) is real at `crypto.go:448-455`. FOLDED —
but see m1 below on the write-block's scope.

### 4. Codex m1 (key remediation representable) — FOLDED

The path is corrected to `<confdir>/.configdb/master.key`:
`masterKeyPath()` = `filepath.Join(db.dir, "master.key")`
(`crypto.go:34-35`) and `db.dir` is the `.configdb` dir
(`store.go:302-305`, `daemon.go:1047-1052`) — NOT
`/etc/xpf/master.key`. The health DETAIL field carries a key-class
indicator from the retained failure's `errors.As` check, so the
operator guidance names ORIGINAL key restoration. FOLDED.

### 5. Fold-verification partials sweep — FOLDED

(Item 3) `grep "owner is known"` survives only as negated/corrected
forms ("never", "not because", "no longer says"). (Item 5) the
arm-persistence residual now states the honest window: seconds-wide
under TRANSIENT failure, UNBOUNDED up to the confirm window's own end
under a deterministic write failure, the W retry has NO success
guarantee and dies with the process (verified
`store_persist.go:397-401`: the retry loop is a plain goroutine
abandoned at process exit — "process exit simply abandons it"), NO
post-crash heal. (Items 4/7) the §5.1 `pkg/api` inventory and the
docs-inventory aggregate-cause copy now name
removal/rewrite/SLOT-DELETE; every repair-authorizing summary table
carries the NON-KEY-CLASS-PERMANENT qualifier. FOLDED.

## B. Fresh attacks on the v27 delta

**Attack 1 (SUCCEEDED as nit m1) — the blanket key-file write-block
over-blocks PLAINTEXT repair writes.** The (w-u) leg and the key-class
block state "ANY missing/unreadable key file BLOCK the write", with
the laundering rationale (`readOrCreateMasterKey` auto-creates). But
`maybeEncryptTreeJSON` returns the body as PLAINTEXT without touching
the key path when the candidate tree carries no master-password leaf
(`crypto.go:262-265`: `prf == "" → return data, nil` —
`readOrCreateMasterKey` is never called). So in the degenerate corner
where BOTH the active config and the candidate are plaintext and the
(stale, unneeded) key file is missing or corrupt, a plaintext W
restore / plaintext synthesized tombstone / slot DELETE — none of
which cryptographically need the key — is retained until the operator
restores a key file the system does not need. The active-validation
gate does NOT rescue the corner: it is a no-op on the plaintext
active side, so the gate passes and the blanket write-block is the
only thing retaining the debt. The fail direction is SAFE (retain +
actionable message; the next `Load` of a plaintext active.json is
unimpeded) and the simplification avoids replicating the
encryption-decision predicate in the gate — but the plan states the
blanket block without acknowledging the plaintext exemption.
Remediation: either scope the write-block to writes that would
actually ENCRYPT (the same `masterPasswordPRF(tree) != ""` predicate
`WriteConfirm` uses — a plaintext repair write provably cannot
auto-create a key) or explicitly pin the over-block as accepted
conservative behavior with the rationale (one uniform rule beats a
replicated predicate; the corner resolves on the next pass once any
operator looks at the 503 message). MINOR.

**Attack 2 (FAILED) — gate evaluation under transient ACTIVE-side
failure terminalizes a healthy confirm slot.** If `active.json` is
momentarily unreadable (EACCES during a rewrite) while a W restore is
attempted, the gate WITHHOLDS the action and retains the debt — the
retry loop re-evaluates next pass; nothing terminalizes on a
withheld action (the no-write-failure-terminalizes doctrine covers
the gate by construction). FAILED.

**Attack 3 (FAILED) — unsupported-PRF / too-new-envelope /
bad-nonce / bad-base64 mis-classified as key-class.** These all live
in the UNENCRYPTED envelope header (`env.Format`/`env.PRF`/
`env.Salt`/`env.Nonce`/`env.Data` — `crypto.go:28-32`,
`unmarshalEnvelope` at `crypto.go:307`, `deriveEncryptionKeyFromSalt`
at `crypto.go:323-326`, the #4793 nonce-length guard at
`crypto.go:348-353`): they are key-INDEPENDENT content corruption,
correctly classified NON-key-class permanent (provably unparseable
under ANY key — the repair write is safe). The key-class subtype
covers exactly the key-DEPENDENT failures: `gcm.Open` authentication
failure (`crypto.go:355-356` — wrong key vs corrupt ciphertext
indistinguishable) and invalid observed key length
(`crypto.go:451-453,460-462`). No gap. FAILED.

**Attack 4 (FAILED) — broadened D suppression starves D's
moot-clear across a long-lived window.** While a window lives, D
cannot even clear itself as moot. But the window is bounded (the
confirm window's own deadline); on resolution the resolution's own
tombstone/deletion subsumes D's target, and D's next re-read
classification (post-`armedArmID = ""`) clears or completes it fresh.
The debt set is keyed and per-pass convergent; a pending D across a
window is the intended semantics, not starvation. FAILED.

**Attack 5 (FAILED) — boot-time key-class terminalization
contradicts the runtime RETAIN rule.** At boot, a key-class corrupt
confirm record terminalizes into the R-kind operator-mediated latch
(repair-or-remove with the deletion warning); at runtime the same
class RETAINS with the restoration message. Both are fail-closed and
both name key restoration; the difference is intentional — boot has
no retry loop to pend a debt in, so the latch IS the pending state.
Consistent. FAILED.

## C. Findings

### MAJOR (0)

None. The generalized laundering guard, the broadened D suppression,
and the mechanical two-sided taxonomy close Codex's r26 majors on
independent verification against the code; the residual partial
copies are swept.

### MINOR (1)

**m1.** Scope or explicitly accept the blanket key-file write-block's
plaintext over-block: `maybeEncryptTreeJSON` never touches the key
path for a master-password-free tree (`crypto.go:262-265`), so a
plaintext W restore / plaintext synthesized tombstone / slot DELETE
cannot auto-create a key and does not need the block. Either
predicate the write-block on the candidate tree's
`masterPasswordPRF(tree) != ""` (the same check `WriteConfirm`
performs) or pin the over-block as accepted conservative behavior
with the one-uniform-rule rationale. Safe-fail either way; the plan
must say which.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the write-block scope
pin). A v28 containing only this pin is PLAN-READY by inspection from
me.
