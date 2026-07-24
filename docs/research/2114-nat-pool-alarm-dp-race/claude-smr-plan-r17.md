# Claude SMR hostile plan-review — round 17 (plan v17 @ `3d3b3e8af`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r16's SMR
signed off with one nit; r17 re-attacks the v17 delta (two-field identity,
durability barrier, debt set, taxonomy, health channel) end to end. Every
finding below was independently verified against the worktree code
(origin/master `ed6999000` + plan-doc branch), not adopted on trust.

## A. Fold verification (r16 findings → v17)

### 1. Codex M1 (post-rename finalize durability) — PARTIAL, and the fold re-opened a worse hole (see M1 below)

The barrier claim itself verifies: `activePath`/`confirmPath` share
`db.dir` (`db.go:74-76,195-196`); `WriteFileDurable` is
temp→fsync→rename→dir-fsync (`fsatomic.go:310-369`); the finalize paths
are program-ordered after the active write (`store_commit.go:180-200,
437-452`; `persistRetryLoop` heals the active write BEFORE
`clearConfirmResolutionPendingLocked`, `store_persist.go:414-428`). The
x8 seam EXISTS (`fsatomic.SetAfterRenameSyncDirForTesting`,
`pkg/fsatomic/test_seams.go:9-32`, used by
`postrename_dbboundary_5234_test.go:47,97`) — my implementability attack
FAILED. But see §B M1: the uniform rule's "retain pre-durability" arm
leaves SyncApply (and the two rollback paths) with a single-failure
restart hole that contradicts the plan's own x7 closure claim.

### 2. Codex M2 (two-field identity) — PARTIAL (see M2 below)

The nested-arm counterexample is closed by construction. But `Load`'s
early exits never seed `onDiskArmID` (`store_persist.go:26-42` absent-DB
return, `:81-113` compile-fail return — only the success path reaches
`recoverPendingConfirmLocked` at :113), so "" conflates "never observed"
with the legacy sentinel, and a plain commit does NOT resolve an orphan
record (`clearPendingConfirmLocked` returns early when no in-memory
window is pending, `store_commit.go:678-682`).

### 3. Codex M3 (B-rewrite A/B/C) — PARTIAL; the ≤1+1 bound is false (M3 below)

The four transitions are sound. The bound proof is not: my own walk
(below) independently produced the same three-debt interleaving Codex
found. AGY's r17 PLAN-READY asserts the false bound verbatim in its
attack-2 rationale — a soft pass on exactly the claim SMR exists to
check.

### 4. Codex M4 (terminal taxonomy) — PARTIAL (M4 below)

Per-debt terminal + boot reconstruction are the right shape. Two defects:
master-key IO is misclassified permanent (`crypto.go:443-453` is a plain
`os.ReadFile` — transient-recoverable; only invalid OBSERVED key length
is deterministic), and the remediation transition has NO live observer —
the only production `ReadConfirm` is boot recovery
(`store_persist.go:140`), and the singleton loop exits when neither
degradation flag is set (`store_persist.go:405-412`), so a lone terminal
latch never clears in-process. AGY's attack-4 rationale ("ReadConfirm is
called in persistRetryLoop") misses the loop-exit gap.

### 5. Codex m1 (classification) — FOLDED

Body text is consistent: SyncApply replacement-class only
(`store.go:697-760`); no stale confirm-type-scoped/HA-sync-auto-confirm
text outside revision history. But see Codex m3/SMR fold list: the
SOURCE docs still say "Treat the sync as the confirmation"
(`store.go:716-717`) and the sweep must name them.

### 6. Codex m2 (NAT64 citation) — FOLDED

`flow_cache.rs:385-393` excludes NAT64 (`!decision.nat.nat64`);
eviction-at-lookup at `:992-999`; the `nat64.rs:244-263,528-553` guard
is real.

### 7. Codex m3 (503 policy) — PARTIAL (M6 below)

Election-neutrality verified (`readiness.go:20-24` diagnostic-only;
`election.go:427-432` crash-takeover bypass). The distinct terminal
message is NOT implementable as written: the API channel is
`ConfigPersistDegradedFn func() bool` (`server.go:132-140,338,424`),
surfaced identically to `/health` (`health.go:65-71`) AND the Prometheus
gauge (`metrics.go:951-957`) — no cause-bearing channel exists.

## B. Findings (independently derived; they converge with Codex r17)

### MAJOR

**M1 — Replacement paths retain untombstoned records on POST-rename
failure: a single-failure restart hole that contradicts x7's closure.**
Verified: SyncApply treats EVERY `writeActive` error — including
`*PostRenameSyncError` — as not-durable and defers
(`store.go:738-746`: `noteActivePersistFailureLocked` +
`confirmResolvePendingPersist = true`, NO classification, NO tombstone
attempt). Post-rename means B is NAMESPACE-VISIBLE
(`fsatomic.go:45-55`). A restart before the retry heals loads B +
pending-shaped A; A binds whenever content matches (SyncApply-identical,
byte-identical edit-back, legacy empty hash) → re-arm → the timer
reverts B → the exact #4378-class divergence plan.md:1061-1066 and the
x7 leg claim is closed. The v16/v17 closure assumed the finalize
tombstones — but the finalize only runs AFTER the retry's durable
heal, and the restart can precede it. This is not the admitted
double-failure residual; it needs ONE writeActive failure + one restart.
The same shape exists on the other two replacement paths
(`PromoteRollback` `store_commit.go:917-937`; boot-recovery revert
`store_persist.go:196-227`) — for those, the record's GuardedHash
usually mismatches the reverted tree (stale-drop saves them) EXCEPT the
pathological no-op-commit-confirmed case. Fix: ALL replacement paths
classify the failure with the existing `isPostRenameDurabilityFailure`
check (`store_commit.go:181` precedent): PRE-rename → retain per #5473;
POST-rename → immediately attempt the tombstone barrier
(`resolveConfirmRemovalLocked`): success PROVES the replacement durable
(the barrier), satisfying #5473's precondition; failure retains BOTH
debts. The #5473 tests' retention expectations change accordingly (the
record now survives until the barrier, not until the retry heals —
the invariant "survives until the replacement is durable" is preserved,
with the tombstone success as the durability witness).

**M2 — `onDiskArmID` is never seeded on `Load`'s early-exit paths; ""
conflates never-observed with the legacy sentinel.** Verified:
absent-DB (`store_persist.go:40-42`) and compile-failed (`:81-113`)
returns skip `ReadConfirm` entirely. Codex's chain replays cleanly: an
admitted-replay orphan A (active rename lost, A's record survives) →
bootstrap plain commit does NOT resolve it (no in-memory window,
`store_commit.go:678-682`) → a later B arm fails pre-rename → B's
resolution hits a read error → debt keyed "" → retry reads nonempty A →
"newer mismatch" → DURABLY PRESERVES the orphan it should tombstone.
Fix: `Load` reads confirm.json on EVERY outcome (absent-DB,
compile-failed, success) and seeds the three-state identity
(Present(ArmID) / Absent / unreadable→terminal latch); the "" sentinel
is then only ever a PRESENT legacy record's value. The orphan lifecycle
is documented (cleaned by the next successful boot's stale-drop or the
first keyed resolution targeting it).

**M3 — The "≤1 removal + 1 rewrite" bound is false; the convergence
argument is different.** My independent walk, before reading Codex:
A's resolution leaves removal R_A; B's arm fails post-rename → rewrite
W_B; B's resolution tombstone fails post-rename → removal R_B (the
singleton sleeps outside the lock, `store_persist.go:402-405`, so all
three land inside one sleep). R_A + W_B + R_B coexist. The composition
still CONVERGES (each retry pass completes a debt's own record action
or stale-clears it once the current record is durable — strictly
shrinking), but the plan's hard bound is falsified and must be replaced
by the keyed-set + strict-convergence statement. (Codex M3 same;
AGY asserted the false bound — soft pass noted.)

**M4 — Terminal machine: master-key IO misclassified; no in-process
exit.** Verified: `readMasterKey` is `os.ReadFile` (`crypto.go:446-449`)
— a missing mount/EACCES is transient-recoverable; only invalid
OBSERVED key length (`:452,:461`) is deterministic-permanent. And the
latch-clear transition ("next clean ReadConfirm or confirmed absence")
has no live observer: the only production ReadConfirm is boot recovery;
the singleton exits at `store_persist.go:405-412` when neither
`persistDegraded` nor `confirmRemoveDegraded` is set — a lone terminal
latch keeps neither. Fix: (a) master-key IO → TRANSIENT (retain+retry);
invalid observed key length stays PERMANENT; (b) the terminal latch
keeps the singleton ALIVE in probe-only mode (READ-ONLY ReadConfirm per
pass, no writes): a clean read clears the latch and re-arms the debt's
retry from the now-readable record; a confirmed absence clears the latch
and drops the debt; the loop-exit condition gains "and no terminal
latch".

**M5 — Transient boot `ReadConfirm` failure silently loses the rollback
window for the process's lifetime.** Verified:
`store_persist.go:140-145` logs and returns; `Load` SUCCEEDS; no timer,
no debt, no retry — an unconfirmed active config stands indefinitely.
This is a PRE-EXISTING master #4577 hole ("an unconfirmed config must
NEVER stand", invariant 12) that v17 explicitly preserves
("transient-class keeps master's log-and-return"). The plan must not
enshrine it. Fix: boot recovery retries TRANSIENT read failures with
bounded backoff INSIDE Load (before manager construction); still
failing → `Load` FAILS (fail-closed — systemd `RestartSec=1` re-drives
the boot; the transient error clears). PERMANENT-class boot failures
keep the v17 behavior (proceed + terminal latch + 503 + runbook) —
failing Load forever on a deterministically-corrupt record would brick
the node; the admitted "unconfirmed stands, loudly, until operator
action" for the permanent class is stated, and the bigger hammer
(auto-revert to the last rollback archive on a corrupt record) is
considered and rejected as out of scope.

**M6 — The distinct terminal 503 has no cause-bearing channel.**
Verified: `ConfigPersistDegradedFn func() bool`
(`server.go:139,338,424`) is the only signal; `health.go:65-71` cannot
distinguish causes; the same bool drives the gauge
(`metrics.go:951-957`). Fix: a typed snapshot accessor (e.g.
`ConfigPersistDegradedState() struct{ ActivePersist bool;
ConfirmRecordTerminal bool }` or an enum) wired via a new functional
option; `health.go` selects message by precedence (terminal
confirm-record > active-persist); the gauge stays the aggregate OR.

### MINOR

**m1 (SMR-own) — Retry-side post-rename failures: which debt owns
them?** Rule (b) as written ("a POST-rename failure → the VISIBLE
record's ArmID + a rewrite debt") is universal — mechanically it raises
a rewrite debt for the TOMBSTONE helper's post-rename failure too,
while the linearization bullet says tombstone failure retains the
REMOVAL debt (re-driving tombstone→delete). Both converge safely, but
the text must pin it: the rewrite debt is raised ONLY by the ARM path
(`writeConfirmState`); a post-rename failure of a resolution-side or
retry-side `WriteConfirm` retains the ORIGINATING debt (which re-drives
the same write next pass). One-sentence pin.

**m2 (Codex) — The residual is broader than "both fail post-rename".**
Active POST + tombstone PRE also leaves B visible + A untombstoned
(`fsatomic.go:45-55`); restart before healing observes B+A. Precise
residual: active POST + tombstone failure in ANY phase + restart/power
loss before a successful directory barrier.

**m3 (Codex) — "Wired ONLY to REST health" is false; surfaces
misdescribe.** The same bool drives Prometheus
(`metrics.go:951-957`), and the descriptor
(`metrics_descriptors.go:625-630`), the option comment
(`server.go:132-140`), and the wiring comment
(`daemon_run_servers.go:370-374`) describe only active-config
persistence — false once terminal confirm corruption sets the
aggregate. The sweep must update all four surfaces (and the M6 typed
accessor keeps them honest).

**m4 (Codex) — Source-doc terminology.** `store.go:716-717` ("Treat the
sync as the confirmation") and `pkg/configstore/README.md:663-672`
still teach the confirm-type framing of SyncApply; the §5.5 sweep lists
neither.

## Verdict

**NEEDS-REVISION** (6 MAJOR, 4 MINOR — converging with Codex r17's
6M/3m on independent verification; SMR-own m1 is the retry-side
debt-ownership pin). AGY r17's PLAN-READY accepted the falsified ≤1+1
bound and the observer-less remediation transition — both attacks I
walk independently fail AGY's rationales. The v17 mechanisms are
directionally right (the barrier, the two-field model, per-debt
terminal); the folds needed are the failure-phase classification, the
Load seeding, the corrected convergence statement, the taxonomy
boundary + probe observer, the boot fail-closed hardening, and the
typed health channel.
