# Claude SMR hostile plan-review — round 42 (plan v42 @ `2e0b4df03`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r41's SMR
raised the indicator-freshness nit (folded in v42); r42 re-verifies the
v42 folds of Codex's 4M/1m against the real code and attacks the new
`ConfigSyncOutstanding` counter's own balance semantics. All line
numbers re-verified against the worktree.

## A. Fold verification (r41 findings → v42)

### 1. Codex M1 (gap-free outstanding counter) — FOLDED, with nit m1

The three false-idle windows of the v41 queue-length + gen-fence pair
are real and re-verified: the consumer dequeues BEFORE
`beginConfigApply` publishes the fence (`sync_conn_config.go:325-360` —
the `item := <-s.configApplyCh` receive precedes
`s.beginConfigApply(item.gen)` by two gate branches); a gen==0
legacy/unconditional apply leaves `applyingConfigGen` at 0
(`sync_conn_config.go:289-309` — "the fence stays 0"); and
`resetRecvGen` fires from the bulk-start path
(`sync_conn_read.go:183-195`) with the epoch logic at
`sync_conn_gen.go:340-362`. A generation/epoch-independent counter —
incremented at frame receipt before enqueue
(`sync_conn_read.go:298-324`), decremented only after the apply returns
including the applySem-blocked duration
(`sync_conn_config.go:325-351`, `daemon_apply_commit.go:326-335`) —
closes all three by construction. FOLDED — but see m1: the plan's
increment/decrement wording leaves two counter-BALANCE paths unpinned,
and a leaked increment wedges the drain the fence waits on.

### 2. Codex M2 (fence reorder) — FOLDED

The reorder (peer preflight → STOP THE PEER → local outstanding drain →
full re-check including the counter → stop and repair) closes both
undrained directions. Verified: `QueueConfig` writes directly to the
active connection with no outbound queue and nil-returns when the conn
is gone (`sync_conn_config.go:230-250` — `getActiveConn(); if conn ==
nil { return }`), so a stopped peer means no local→peer write can
initiate or complete; and a stopped peer process sends nothing inbound
over any transport. The debts-only blind spot is real (a
merely-enqueued or applySem-blocked apply raises debt only inside
`SyncApply`, `store.go:687-746`; exit abandons the retry,
`store_persist.go:397-401`) and the re-check's added
`ConfigSyncOutstanding == 0` term covers exactly it. FOLDED.

### 3. Codex M3 (peer full-state read path) — FOLDED

The read path is an intra-plan composition and it is coherent: the
plan's own (x14) TYPED HEALTH CHANNEL work item
(`plan.md:4193-4210`, `plan.md:5430-5445`) wires
`ConfigPersistDegradedState()` — `{ActivePersistDegraded,
ConfirmDebtKindMask (REMOVAL|REWRITE|SLOT_DELETE), ...}` — into
`/health`, and it ships in the SAME follow-up unit (G+H+H2) as H2's
runbook, so the fields exist before the runbook needs them. The real
`/health` handler already carries `config_persist_degraded` today
(`pkg/api/health.go:65-67`), so the pattern is established, not
speculative. The §5.1 `pkg/cluster` inventory entry adds the counter +
mask/persist wiring to the cluster-status RPC. FOLDED.

### 4. Codex M4 (stale acceptance copy) — FOLDED

The formal acceptance copy (`plan.md:5645-5700`) now names the current
fence: preflight includes the counter via the peer's `/health`, the
local drain waits on the counter to ZERO, the re-check includes the
counter — no timer anywhere. I grepped the whole doc for surviving
copies of the old sequence (`ONE full pass` / `capped backoff` /
`capped timer`): the three remaining hits are (a) the v38
revision-HISTORY entry (`plan.md:1385-1386`) and (b) the v41
revision-HISTORY entry (`plan.md:1536`) — both historical records of
superseded designs, preserved as history per the doc's 42-round
convention — and (c) `plan.md:3268`, which describes the real persist
retry loop's own capped backoff (`store_persist.go`), not the fence.
No LIVE restatement of the old fence survives. FOLDED.

### 5. Codex m1 (live-read pin + regression) — FOLDED

The counter is a single atomic read LIVE at check time — the
joint-protection coherence note is answered by construction — and §9's
JOIN-COHERENCE leg is the framed-blocking-apply regression (frame
dequeued, apply blocked on `applySem` via the test seam) asserting the
counter NEVER reads zero until the apply returns, explicitly covering
all three M1 windows. FOLDED.

## B. Fresh attacks on the v42 delta

**Attack 1 (SUCCEEDED as nit m1) — the counter's balance is unpinned,
and a leaked increment wedges the drain.** The plan says "INCREMENTED
at frame receipt (BEFORE enqueue ...)" and "DECREMENTED only AFTER the
apply returns". Two real code paths break that pairing:

- (a) The enqueue is NON-BLOCKING with a drop arm: when the 64-slot
  `configApplyCh` is full, the frame is dropped with an alarm
  (`sync_conn_read.go:321-331` — "config apply queue full, dropping
  config (will re-converge on next push)"). An increment taken BEFORE
  the enqueue attempt leaks +1 on this arm — no apply ever runs for
  the dropped frame — and `outstanding == 0` becomes UNREACHABLE,
  hanging the runbook's LOCAL OUTSTANDING DRAIN forever.
- (b) The consumer has two skip arms that never "apply": a
  stale-generation item is dropped by `shouldApplyConfigGen` with
  `continue` (`sync_conn_config.go:331-336`, `ConfigsStaleIgnored`),
  and an unwired-handler item is skipped the same way
  (`sync_conn_config.go:337-341`). A decrement worded as "only AFTER
  the apply returns" never fires on these arms — another leak.

Both are one-clause precision pins, not a redesign: the increment
belongs ONLY in the successful-enqueue arm (the drop arm and the
nil-channel guard at `sync_conn_read.go:318` do not increment), and
the decrement is DEQUEUE-SCOPED — a `defer` at the top of the
consumer's per-item processing — so the stale-skip, nil-handler-skip,
apply-failure, and panic-unwind paths all balance. MINOR.

**Attack 2 (FAILED) — a peer-LOCAL commit between (2a) and (2b).** A
commit issued on the peer after its clean preflight raises peer debt
the preflight didn't see; the peer stop then abandons it. But this is
exactly the admitted residual (v) and bounded shape (ii) — abandonment
is symmetric and the next boot re-classifies — and the runbook's step
(1) is operator refrain-from-commits discipline across BOTH nodes for
the procedure's duration. No new hole. FAILED.

**Attack 3 (FAILED) — the local drain needs a peer counter re-read
after (2b).** The peer is stopped; its counter dies with its process
and its remaining process-local debts are the admitted abandoned-D
residual. Nothing on the dead peer can change the local join. FAILED.

**Attack 4 (FAILED) — restart-order contradiction.** The fence stops
the peer FIRST (2b) and the local SECOND (4); the post-repair order
starts the LOCAL first (its `Load` classification completes before
cluster comms, `daemon_run.go:157-177,393-398`) and the peer second.
Peer-first stop and local-first start compose — the local boot
classifies its own records with no peer running to interfere; the peer
then boots into a clean re-sync. No contradiction. FAILED.

**Attack 5 (FAILED) — a `QueueConfig` write in flight at the peer
stop.** The write either lands before the peer's process dies (the
peer counted it; the apply either completes or is abandoned with the
process — the bounded residual) or errors into `handleDisconnect`
(`sync_conn_config.go:242-249`). No unbounded state. FAILED.

## C. Findings

### MAJOR (0)

None. All four r41 majors fold on independent verification; the fence
is now a gap-free observable join with a transport-universal barrier, a
full-state exit check, and a designed peer read path.

### MINOR (1)

**m1.** Pin the counter's balance: (a) the increment is taken ONLY in
the successful-enqueue arm of the non-blocking send — the full-queue
drop arm (`sync_conn_read.go:321-331`) and the nil-channel guard do
NOT increment, else a dropped frame leaks +1 and the drain's
`outstanding == 0` becomes unreachable; (b) the decrement is
DEQUEUE-SCOPED (a per-item `defer` in the consumer), so the
stale-generation skip (`sync_conn_config.go:331-336`), the
nil-handler skip (`sync_conn_config.go:337-341`), apply failure, and
panic unwind ALL balance the increment. One sentence in the normative
runbook + one clause in the §5.1 `pkg/cluster` entry; the §9
JOIN-COHERENCE leg already exercises the blocked-apply arm and needs
no change.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the counter-balance pin).
A v43 containing only this pin is PLAN-READY by inspection from me.
