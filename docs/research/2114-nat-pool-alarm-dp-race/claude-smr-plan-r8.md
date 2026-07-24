# Claude SMR hostile plan-review — round 8 (plan v8 @ `9c2bc5bbd`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE — verify every
load-bearing claim against worktree code; attack the v8 delta; probe the
boundaries the plan asserts closed. All line numbers verified against the
worktree (origin/master `ed6999000` + plan-doc-only branch).

## A. Verification pass (claims checked against code, all CONFIRMED)

1. **Writer enumeration** — `grep -n 'd\.dp = '` yields exactly 5:
   `daemon_run_bringup.go:448,464,469,497` + `daemon_run_naming.go:234`.
   CONFIRMED.
2. **Executor registration precedes all phases** —
   `d.store.SetRollbackExecutor(d.executeConfirmedRollback)` at
   `daemon_run.go:136`, inside `Run` before `runStartupOrAbort`
   (`daemon_run.go:174`). CONFIRMED.
3. **`executeConfirmedRollback` takes applySem FIRST** —
   `daemon_apply_commit.go:629-631`. CONFIRMED (and the plan's
   gate-before-applySem edit lands exactly before :630).
4. **Pre-existing vrrpMgr nil-deref defect (r5 discovery)** —
   `d.vrrpMgr.UpdateInstances` unconditional at `daemon_apply_tail.go:50`;
   construction at `daemon_run_bringup.go:219` (`d.vrrpMgr =
   vrrp.NewManager()`). A timer fired before phase-3 manager init nil-derefs
   today. CONFIRMED — work item G closes a real master defect.
5. **`runStartupOrAbort` failure paths** — exactly two failure returns
   (`daemon_run.go:828` `return teardown(err)` signal-abort; `:832`
   `return err` plain phase error). The plan's "publish inside
   runStartupOrAbort's failure handling (or its immediate wrapper) so BOTH
   reach it" is realizable; the 5807 harness
   (`startup_signal_5807_test.go:125-140`) drives the signal path directly.
   CONFIRMED.
6. **PHASE 5 tail structure** — `d.startGRPCServer(...)` at
   `daemon_run.go:599` is the LAST statement of PHASE 5; PHASE 6 comment at
   :601. The END-of-PHASE-5 linearization point exists and is unambiguous.
   CONFIRMED.
7. **Two-sided gate feasibility** — `Sampler.Start` primes synchronously
   (`sampler.go:64-66` `s.sample(time.Now())` before `go s.loop(ctx)`);
   `sample()` calls `s.proc.ReadSelfStat()` (`sampler.go:93`) BEFORE any
   `s.dp` touch (:113-125). A blocking fake `ProcReader` therefore parks the
   reader before the conflicting `d.dp` access with no channel between the
   pair. CONFIRMED.
8. **`Build` keys on Status() presence** — `builder.go:117-122` type-asserts
   `dp.(interface{ Status() ... })`. The collapsed single-method daemon
   adapter can never satisfy it. CONFIRMED.
9. **Daemon adapter has exactly one production caller** —
   `forwardingStatusDataplane()` is called only at `daemon_run.go:595`;
   gRPC (`server_show_forwarding.go:65`) and CLI (`cli_show_chassis.go:103`)
   define their OWN `forwardingStatusDataplane` methods on their own types
   reading their own boot-captured `s.dp`/`c.dp`. CONFIRMED — the collapse
   is contained. Zero test references to either daemon adapter type.
10. **`userspaceDataplaneStatus()` dead-after-collapse** — sole caller is
    the adapter's `Status()` method (`daemon_forwarding_status.go:63`).
    CONFIRMED.
11. **Recovery-path structure** — `recoverPendingConfirmLocked`
    (`store_persist.go:136-251`): GuardedHash mismatch → drop + return
    (:159-165); expired-during-downtime → revert-to-prevTree + return
    (:171-227); unexpired → re-arm (:229+). `s.Load()` calls it at :113,
    PHASE 1/2, before `initManagers` (PHASE 3) constructs `d.cluster`
    (`daemon_run_bringup.go:164`) and starts the watcher (:203). CONFIRMED.
12. **RACE-1 watcher chain** — `go d.watchClusterEvents(d.daemonCtx)` at
    `daemon_run_bringup.go:203` precedes the `d.dp = dp` publication at
    :469; the watcher handler reads `d.dp` at `daemon_ha.go:297` with no
    happens-before edge. CONFIRMED.

## B. Attacks mounted and their outcomes

### Attack 1 (MOUNTED, FAILED — plan survives): current-version FirstCommit+cluster record

Probe 3 tried to break the "legacy artifact" framing: can a CURRENT-version
build persist a `FirstCommit=true` record whose active config declares a
cluster? Path attempted: baked-image node, absent DB → `everCommitted=false`
(`store_persist.go:37-42`), config file carries the cluster stanza, first
operator `commit confirmed` → FirstCommit record + cluster config. **Attack
fails at `bootstrapFromFile` (`daemon_apply_commit.go:17-60`): the file
import runs a REAL commit (`d.store.CommitWithDescriptionGen("", gen)` at
:57), and the commit path sets `s.everCommitted = true`
(`store_commit.go:203`).** A file-seeded node therefore has
`everCommitted=true` before any operator commit; the first operator commit
records `FirstCommit=false`. The only remaining current-version path to
`FirstCommit=true` is a truly fresh store (no DB, no file) whose first
commit adds `chassis cluster` — and that is `clusterTopologyCommitPreflight
(false, cluster-cand)` → standalone→cluster → REJECTED
(`daemon_apply_commit.go:558`). Factory-reset clears `everCommitted`
(`store_commit.go:899-907`) but the daemon stops/wipes on reset
(`isResetting()` gate, `daemon_apply_commit.go:634-638`), so the post-reset
commit happens after a reboot with no cluster runtime — preflight rejects
again. The plan's r6 scoping ("current-version records cannot produce the
coexistence") HOLDS. Documented here so the boundary probe is on the
record.

### Attack 2 (MOUNTED, FAILED — plan survives): gate-before-applySem deadlock inversion

If the executor waited on `startupDone` WHILE holding applySem, and any
startup phase needs applySem (the boot apply), startup wedges →
`finishStartup` never fires → executor holds applySem forever. The plan
gates BEFORE `Acquire` (pseudocode at §4 work item G) and the gate test
asserts a second goroutine CAN acquire/release applySem while the executor
is parked — this kills the inversion by construction. The remaining
question — is gate-before-applySem observably correct when the timer fires
POST-linearization? Then `startupDone` is already closed, `<-d.startupDone`
returns immediately, `startupOK` true, executor proceeds to Acquire exactly
as today. Zero behavior change on the steady-state path. CONFIRMED safe.

### Attack 3 (MOUNTED, SUCCEEDED — MAJOR): work item H guard placement regresses #4577 for EXPIRED records

The plan never pins WHERE inside `recoverPendingConfirmLocked` the guard
sits; AGY's r8 verification explicitly describes it as firing "before
reaching deadline expiry (line 171) or timer re-arm (line 231)" — i.e.,
BEFORE the expired-during-downtime branch. That placement is WRONG. For an
EXPIRED `FirstCommit`+cluster record, current master's expired branch
(`store_persist.go:171-227`) reverts `s.active` to the empty prevTree and
clears `everCommitted` AT LOAD — before `initManagers` constructs any
cluster runtime (PHASE 3). The node boots into bootstrap with NO cluster
manager: safe, and it honors #4577's semantics ("the operator never
confirmed, so the unconfirmed config on disk must NOT stand",
`store_persist.go:172-175`). A pre-expiry guard that "keeps the active
config, drops the record" would instead boot the node WITH the unconfirmed
cluster config active — silently standing a config the operator never
confirmed, a #4577 regression introduced by this PR. The ONLY records the
guard needs to intercept are UNEXPIRED ones (the re-arm branch at :229+:
active keeps the cluster config → `d.cluster` constructs at PHASE 3 → the
re-armed timer later rolls into `enterBootstrapMode` with live cluster
comms — the r6 hybrid). Expired records are already safe without the guard
and must keep flowing through the existing revert branch. **Required fold:**
pin the guard to the UNEXPIRED re-arm branch (immediately before
`s.confirmPrevTree = prevTree` at :231), state explicitly that expired
records are untouched because the load-time revert precedes manager
construction, and add a fourth test: EXPIRED `FirstCommit`+cluster record →
existing expired-path revert proceeds unchanged (active reverted to empty
tree, `everCommitted=false`, no guard interference). The plan's test (i)
must also state the record's deadline is UNEXPIRED (a "no re-arm" assertion
is vacuous against an expired record, which never re-arms anyway).

### Attack 4 (MOUNTED, PARTIALLY SUCCEEDED — MINOR): fixture enumeration is not "completed"

The v8 header claims "fixture list completed" and §4 work item G lists six
sites (`rollback_resync_test.go:31`, `bootstrap_rollback_test.go:24`,
`rollback_serialize_test.go:71,150,201,247`). A full grep for
executor-driving `&Daemon{...}` constructions finds EIGHT: the plan MISSES
`bootstrap_rollback_test.go:74` (registers
`s.SetRollbackExecutor(d.executeConfirmedRollback)` at :82 and fires the
timer) and `rollback_resync_test.go:81` (calls
`d.executeConfirmedRollback(gen)` directly at :85). Under the gate, both
tests hang on a nil `startupDone` channel until the go-test timeout. The
compiler does NOT catch this (nil channel compiles fine) — only the test
run does, as a 10-minute wedge. **Required fold:** add the two sites, and
either re-derive the list by grep at /engineer time or drop the "completed"
claim.

### Attack 5 (MOUNTED, PARTIALLY SUCCEEDED — MINOR): collapsed-adapter deletion set not enumerated

§4 says the daemon adapter "collapses to a SINGLE method" but does not
enumerate the two deletions that collapse forces: the
`var _ fwdstatus.DataPlaneAccessor = forwardingStatusDaemonDataPlane{}`
assertion (`daemon_forwarding_status.go:10` — fails to compile against a
CachedStatus-only type; compiler-enforced, but should be named) and the
`forwardingStatusDaemonUserspaceDataPlane` wrapper type (:52-75 — the
plan's own §5.4 table row `:21,24,36,39,97,100` marks the METHODS deleted
but never names the wrapper type). **Required fold:** enumerate both
deletions explicitly; add a negative assertion to the new canary or a unit
test that `fwdstatus.DataPlaneAccessor` is NOT satisfied by the collapsed
type (a plain type-assertion test — the `var _` idiom cannot express
negation).

## C. Findings

### MAJOR (1)

**M1. Work item H guard placement must be pinned to the UNEXPIRED re-arm
branch; pre-expiry placement regresses #4577.** (Attack 3.) Plan §4 work
item H + test (i) as written admit an implementation that keeps an
unconfirmed cluster config whose confirm window already expired during
downtime — the exact "unconfirmed config must NOT stand" semantics #4577
established and the current expired branch implements safely (revert before
manager construction). Fix: guard sits immediately before the re-arm at
`store_persist.go:231`; expired records flow through unchanged; test (i)
specifies an unexpired deadline; add an expired-record test.

### MINOR (2)

**m1. Fixture list incomplete** — add `bootstrap_rollback_test.go:74` and
`rollback_resync_test.go:81` (both drive the executor; both hang on a nil
gate otherwise). (Attack 4.)

**m2. Collapsed-adapter deletion set** — enumerate the
`var _ fwdstatus.DataPlaneAccessor` line (:10) and
`forwardingStatusDaemonUserspaceDataPlane` (:52-75) deletions; add a
negative-satisfaction assertion. (Attack 5.)

## D. What this review did NOT find

- No break in the dpCell/accessor architecture (A1) — it survives eight
  rounds including two independent double-close catches and the
  cross-upgrade counterexample.
- No current-version path to FirstCommit+cluster (Attack 1, failed).
- No deadlock in gate-before-applySem (Attack 2, failed).
- Audit table writer count, executor-registration ordering, sampler seams,
  Build keying, adapter caller set, recovery-path structure — all verified
  accurate (§A).

## Verdict

**NEEDS-REVISION** (1 MAJOR, 2 MINOR). The architecture is sound and one
fold away from READY; M1 is a real semantic-regression trap that AGY's r8
verification explicitly blessed in the wrong placement, which is exactly
the class of miss the SMR pass exists to catch.
