# Claude SMR hostile plan-review — round 9 (plan v9 @ `27c968b45`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r9 is the
convergence round: verify every v9 fold of the r8 findings against worktree
code, attack the v9 delta itself, mount one fresh attack on the surviving
architecture. All line numbers re-verified against the worktree
(origin/master `ed6999000` + plan-doc-only branch — NO production code
exists for the plan items; verification is of the plan's claims ABOUT the
code, not of implemented code).

## A. Fold verification (r8 findings → v9)

### 1. Codex M1 (shutdown-admission fence) — FOLDED, with one nit (m1)

v9 work item G: `stopping atomic.Bool` published by `runShutdownSequence`
BEFORE its applySem drain; executor re-checks `d.stopping.Load()` UNDER
applySem after the gate. Interleaving audit:

- Executor gated when shutdown publishes: after gate release it acquires
  applySem — necessarily after the drain's release (the drain holds it
  first) — and sees `stopping=true`. Abandons. CORRECT.
- Executor acquires applySem BEFORE shutdown's drain: it is inside its
  critical section; the drain waits (bounded,
  `daemon_run_shutdown.go:50-58` `applyCloseoutDrainTimeout`). The drain
  timeout tradeoff is pre-existing and documented at :46-49 — unchanged by
  this plan. CORRECT.
- Executor between gate-release and Acquire when `stopping` publishes:
  the drain serializes; post-drain acquisition observes the flag.
  CORRECT.
- Abort path: `runStartupOrAbort` (`daemon_run.go:822-833`) passes
  `runShutdownSequence` as teardown; the v9 failure-publish ordering
  (BEFORE `teardown(err)`) abandons waiters at the `startupOK` check
  before the fence is even published. Benign either way. CORRECT.
- Fence lifecycle: set-once, never reset — correct for a
  process-terminal state. Both PHASE 6 exits (interactive CLI return,
  daemon-mode `<-ctx.Done()`) funnel into `runShutdownSequence`, so the
  publication point covers every ordinary shutdown. VERIFIED against
  `daemon_run.go:741-756` fall-through structure.

  **Nit (m1)**: the plan pins the fence check and the existing
  `isResetting()` guard (`daemon_apply_commit.go:634-638`) as separate
  checks but never says whether the fence check joins the reset guard or
  precedes it. Order is semantically irrelevant (both abandon), but the
  /engineer pass should not have to choose — one line: "the fence check
  joins the existing `isResetting()` early-return immediately after
  applySem acquisition."

### 2. Codex M2 / Claude SMR M1 (work item H redesign) — FOLDED, with one nit (m2)

v9: revert-at-Load, guard AFTER the GuardedHash-mismatch branch
(`store_persist.go:159-165`) and AFTER the expired branch (:171-227),
before the unexpired re-arm (:229+); reuses the expired branch's
FirstCommit revert body (:177-184 + shared tail) via a factored helper.

- Placement VERIFIED: expired FirstCommit+cluster records keep the
  existing safe behavior (revert at :171-227 before manager construction);
  only UNEXPIRED records hit the guard. The v8 keep-active defect class
  (both the pre-expiry placement and the unexpired keep-active) is dead.
- #4577 honored: the unconfirmed tree is reverted; nothing about the
  guard persists the unconfirmed config. The sacrificed remaining confirm
  window for this narrow class is documented in §4 and invariant 12 —
  honest and justified (re-arm is what produces the hybrid; there is no
  third option that both preserves the window and avoids it).
- End-state parity: the guard's end state (empty active, compiled=nil,
  everCommitted=false, record removed-or-debt, candidate reset) is
  identical to the expired-window recovery — the plan says so and the
  shared helper enforces it. VERIFIED against :177-227.

  **Nit (m2)**: journal/log distinguishability. The expired branch
  journals `"auto_rollback"` with detail "window expired during daemon
  downtime" (:222-227). The guard path must use a DISTINCT journal detail
  and slog message (the trigger is different: window NOT expired; the
  early resolution is the anomaly being recorded). v9 says "journal +
  loud warn" without pinning distinct text — an operator auditing the
  journal must not see a false "expired during downtime" record. One-line
  fold: pin distinct journal detail + slog message for the guard path.

### 3. Codex M3 (permanent invariant + recurrence) — FOLDED

Recurrence chain re-verified link by link: `PromoteRollback` FirstCommit
leg clears `everCommitted` + persists `committed=0`
(`store_commit.go:901-907`); `enterBootstrapMode` teardown list covers
networkd/FRR/dataplane/NAT-monitor, NOT cluster comms
(`bootstrap.go:321-340`+); the next cluster commit-confirmed passes
`clusterTopologyCommitPreflight(d.cluster != nil, cand)`
(`daemon_apply_commit.go:558`) with `firstCommit = !everCommitted = true`
→ fresh nonempty-GuardedHash FirstCommit record (`store_commit.go:542`).
The guard is provenance-blind (`rec.FirstCommit &&
recoveredActiveHasCluster(s.active)` — no GuardedHash condition), so
every recurrence generation dies at its next recovery. TERMINATES.
Test (v) (synthesize post-hybrid state → new record → recovery → guard
fires) covers the chain. FOLDED.

### 4. Codex m1 (panic defer) — FOLDED

Run-scoped `defer d.finishStartup(false)`; `sync.Once` idempotence makes
it a no-op after success. Verified `daemon_run.go:799` (phase call) has
no recover — the defer is a cheap local invariant. FOLDED.

### 5. Codex m2 / Claude SMR m1 (fixtures) — FOLDED

Re-grepped `pkg/daemon/*_test.go` for executor/`runStartupOrAbort`
drivers: `executeConfirmedRollback` direct calls at
`rollback_resync_test.go:48,85`, `rollback_serialize_test.go:104,162,
210,267`; `SetRollbackExecutor` at `bootstrap_rollback_test.go:32,82`,
`rollback_serialize_test.go:208`; `runStartupOrAbort` direct at
`startup_signal_5807_test.go:131` (fixture :118) and the plain-error
test (fixture :157). The v9 list (resync :31,81; bootstrap :24,74;
serialize :71,150,201,247; 5807 :118,157) covers all eight. COMPLETE.
The 5807 fixtures' open-gate initialization kills the `close(nil)` panic
(`close` of a nil channel panics — the `sync.Once` does not save you).
FOLDED.

### 6. Codex m3 / Claude SMR m2 (deletion inventory + §5.1) — FOLDED

`var _` assertion (`daemon_forwarding_status.go:10`),
`forwardingStatusDaemonUserspaceDataPlane` (:52-75),
`userspaceStatusProbe` (:83-87) all enumerated; `userspaceCachedStatusProbe`
retained (still used by `userspaceDataplaneCachedStatus`, :107-115);
§5.1 now lists `pkg/configstore/store_persist.go` for work item H.
Negative-satisfaction test pinned. FOLDED.

### 7. Codex m4 (rationale corrections) — FOLDED

`daemon_apply.go:50-51` verified: applySem held only around the apply.
`daemon_run.go:586-589` (HTTP) before :599 (gRPC) verified. The v9 text
states both correctly. FOLDED.

## B. Fresh attack on the v9 delta (mounted, FAILED — plan survives)

**Target: the guard's `recoveredActiveHasCluster(s.active)` operand.**
Could the guard check the wrong tree? The hybrid arises because the
UNCONFIRMED (active) config declares the cluster — `d.cluster` constructs
from the boot-time ACTIVE config (`daemon_run_bringup.go:164`). Checking
`s.active` is exactly right. The alternative confusion — a record whose
PREV tree declares a cluster — cannot exist for FirstCommit (prevTree is
the empty tree by definition, `store_persist.go:239-240`). Non-FirstCommit
records with cluster active config re-arm normally and roll back to a
prior CLUSTER config (d.cluster already exists; no hybrid). The guard's
operand and condition are precise. Attack fails.

**Target: fence vs fixture zero-values.** The executor fixtures
(closed+OK gate) exercise `executeConfirmedRollback` with
`stopping == false` zero value — no additional fixture init needed. The
fence cannot false-positive in tests. Attack fails.

## C. Findings

### MAJOR (0)

None. The two v9 load-bearing redesigns (fence, revert-at-Load) verify
under every interleaving and chain I could construct, including the two
fresh attacks above.

### MINOR (2)

**m1.** Pin the fence check's position relative to the existing
`isResetting()` early-return (one line; order irrelevant but the plan
should choose).

**m2.** Pin DISTINCT journal detail + slog message for the guard path vs
the expired branch's "window expired during daemon downtime" text
(`store_persist.go:222-227`) — the guard fires on UNEXPIRED records and
the journal must not misrecord the trigger.

Both are one-line plan pins, not design changes.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR). Both nits are textual pins
the /engineer pass applies mechanically; neither changes the design. If
the process demands a literal v10 for two one-line pins, fold them and
ship — I do not need another full round to re-approve a wording change,
and my verdict on a v10 containing ONLY those two pins is PLAN-READY by
inspection.
