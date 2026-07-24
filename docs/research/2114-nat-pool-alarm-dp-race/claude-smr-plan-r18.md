# Claude SMR hostile plan-review — round 18 (plan v18 @ `df04e2598`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r17's SMR
converged with Codex on 6 majors; r18 verifies those folds end to end and
attacks the v18 delta with fresh skepticism — including the two points
AGY's r18 PLAN-READY asserted away with factually wrong rationales. All
line numbers re-verified against the worktree (origin/master `ed6999000`
+ plan-doc branch).

## A. Fold verification (r17 findings → v18)

### 1. Codex M1 (replacement-path classification) — FOLDED, mechanism verified

The three replacement paths now classify via
`isPostRenameDurabilityFailure` (`store_commit.go:181` precedent):
PRE-rename → retain per #5473 (no tombstone attempt — the replacement is
invisible, the record is the rollback intent); POST-rename → immediate
tombstone barrier attempt (success proves the replacement durable — the
#5473 witness; failure retains both debts). The commit paths'
already-immediate finalize (`store_commit.go:180-200,437-452`) is
symmetric, so the doctrine is now uniform: a visible replacement is
always followed by a barrier attempt. The no-op-commit-confirmed
pathological case (byte-identical confirm → hash binds after a reverted
post-rename write) is covered by the same branch — the immediate attempt
tombstones the record before any restart window opens. The x7 restatement
(the #5473 tests updated to retention-only-on-barrier-failure) preserves
the #5473 invariant with the tombstone success as the durability witness.
FOLDED.

### 2. Codex M2 (Load seeding) — FOLDED, but see M1 below for the absent-DB routing consequence

`Load` reads confirm.json on every outcome
(`store_persist.go:26-42,81-113` verified as the former gaps) and seeds
Present(ArmID)/Absent/unreadable→latch. The orphan chain now keys the
debt on A (verified: `clearPendingConfirmLocked` early-returns with no
in-memory window, `store_commit.go:678-682`, so without seeding the
phantom-empty debt would durably preserve the orphan). FOLDED.

### 3. Codex M3 (debt set) — FOLDED

The false ≤1+1 bound is deleted; the keyed-set + strict-per-pass
convergence statement is the correct replacement (my r17 walk agrees:
R_A + W_B + R_B coexist transiently; each pass completes own-record
actions or stale-clears; keys are distinct per debt and the single
on-disk slot bounds the live-action set). The arm-path-only rewrite rule
makes "at most one rewrite debt" true (nested arms B then C both failing
post-rename RE-KEY the single debt to C — transition (iii)). FOLDED.

### 4. Codex M4 (terminal machine) — FOLDED, with nit m1

The master-key IO/invalid-length boundary is correctly drawn
(`crypto.go:446-449` vs `:452,:461`); the sentinel requirement is stated
(the zero-deadline/nil-target gates were plain `fmt.Errorf`,
`db.go:271-280`); the `%w` decrypt wrap (`db.go:251-253`) preserves
`errors.As`; the probe-observer keeps the singleton alive and its
shutdown-safety claim intact (`store_persist.go:396-405` — plain
goroutine, short critical sections). FOLDED — but the probe's clean-read
transition is under-specified in a way that can resurrect a resolved
window (nit m1 below).

### 5. Codex M5 (transient boot fail-closed) — NOT-FOLDED, see M1 below

The plan says "`Load` FAILS (fail-closed — systemd `RestartSec=1`
re-drives)". It does not say HOW the bringup path treats that error —
and the default treatment silently proceeds.

### 6. Codex M6 (cause-bearing channel) — FOLDED

The typed `ConfigPersistDegradedState()` snapshot + new functional
option + precedence rule + aggregate gauge is implementable against
`server.go:130-145` and `health.go:65-71` as they exist; the descriptor/
option/wiring comment updates are enumerated (Codex m2's surfaces).
FOLDED.

### 7. Codex m1/m2/m3 (residual, surfaces, terminology) — FOLDED

The residual is restated as replacement-POST ∧ barrier-failure-any-phase
∧ restart; the four metrics/comment surfaces and the SyncApply
source-doc terminology (`store.go:716-717`, `README.md:663-672`) are in
the sweep. FOLDED.

## B. Findings

### MAJOR (1)

**M1 — The fail-closed boot closure is UNROUTED: the default
`classifyLoadError` mapping turns "Load FAILS" into "warn and proceed",
silently re-opening the never-stand hole the fold claims to close.**
Verified: `classifyLoadError` (`bootstrap.go:52-63`) maps ONLY
`ErrConfigDBUnreadable` → `loadFatalUnreadable` (exit Run — fail closed)
and `ErrConfigCompile` → `loadCompileFailed` (bootstrap/lifeline);
EVERY other error → `loadOtherError` — "logged as a warning; the daemon
PROCEEDS" (`bootstrap.go:45-47`), and the bringup switch does exactly
that (`daemon_run_bringup.go:297-298`: `slog.Warn` + fall through).
v18's fold says a transient-exhausted boot confirm-read "FAILS `Load`
(fail-closed …; proceeding is exactly the never-stand violation)" — but
an implementer returning a plain (or even novel-but-unmapped) error from
`Load` lands in `loadOtherError`, the daemon warns and BOOTS ON with the
rollback window lost: the precise outcome the fold exists to prevent,
one indirection later. AGY r18's attack-2 rationale asserts
`loadOtherError` returns a startup error and aborts bringup — factually
wrong; that class proceeds. One-pin fix, but load-bearing: the
exhausted-retry error must be TYPED (a new
`ErrConfirmStateUnreadable` sentinel, or a deliberate
`ErrConfigDBUnreadable` reuse) AND mapped in `classifyLoadError` to the
fail-closed class, with the `loadFatalUnreadable` message adjusted (it
currently points the operator at active.json,
`daemon_run_bringup.go:280-285` — misdirecting for a confirm.json
failure) and a classification regression test added (the x13 leg must
assert the bringup switch ABORTS, not just that `Load` returns error).
The plan must also state the management posture explicitly: unlike
`loadCompileFailed` (which deliberately does NOT exit to preserve
management, `bootstrap.go:41-44`), the confirm-read fail-closed EXITS —
on a device whose only management is in-band through the dataplane, a
persistently failing confirm read strands management until console
intervention; failing closed is still the right posture (the alternative
boots into a possibly-unconfirmed config — the security contract
loses), but the trade must be stated, not discovered.

### MINOR (2)

**m1 — The probe clean-read transition must key on LATCH ORIGIN.** The
latch has two origins: (a) DEBT-origin (a removal/rewrite retry's read
failed permanently — the in-memory resolution already happened,
`confirmGen` bumped at `:717-726`) and (b) BOOT-origin (recovery's read
failed — the window was never restored, no timer, no debt). v18 says a
clean probe read "clears the latch AND re-arms the debt's retry from
the now-readable record" — correct for (a), incomplete for (b). The pin:
DEBT-origin → resume the four-state DEBT retry (match →
tombstone→delete; NEVER re-arm the window — re-arming a resolved window
rolls back a confirmed config, the #4577 second-half violation);
BOOT-origin → re-run the recovery TOTAL ORDER on the now-readable
record (Resolved → drop; GuardedHash → stale-drop; expired → revert;
H → guard; else re-arm — a pending-shaped record legitimately re-arms
ONLY here). AGY r18's attack-3 rationale ("re-arming rec.Deadline and
rec.PrevTree is the intended recovery behavior") is right ONLY for the
boot-origin case — as a blanket statement it is the resolved-window
rollback. Two-sentence pin, both halves load-bearing.

**m2 — The bounded boot-retry budget is unspecified.** "Bounded retry
INSIDE `Load`" needs a concrete envelope (attempt count, backoff, total
budget) pinned in the plan — it trades boot latency against transient
tolerance, and an unpinned budget invites an implementer-invented one.
One line (e.g. a small constant consistent with the store's existing
retry doctrine), plus a note that the budget is boot-path-only and does
NOT apply to the runtime retry loop.

## C. Notes on AGY r18 (PLAN-READY)

AGY's four fresh attacks all FAILED, but two of its rationales are
factually wrong in ways that matter: attack-2 asserts `loadOtherError`
aborts bringup (it proceeds — see M1), and attack-3 asserts a blanket
window re-arm on probe clean-read (right only for the boot-origin latch
— see m1). A PLAN-READY built on wrong rationales for the exact two
mechanisms the round changed is a soft pass; the folds above stand on
the code, not on AGY's reasoning.

## Verdict

**NEEDS-REVISION** (1 MAJOR, 2 MINOR). M1 is a one-pin fix (typed error
+ `classifyLoadError` mapping + message + test + posture note) but is
load-bearing: without it the r17 Codex M5 closure is fictional — the
daemon warns and proceeds. m1 pins the probe re-arm by latch origin; m2
pins the retry budget. Everything else in the v18 delta verified FOLDED
against the code.
