# Claude SMR hostile plan-review — round 51 (plan v51 @ `88772f3f4`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r50's SMR
raised the push-window clause (folded in v51 as part of Codex M3's
reconciler-join); r51 re-verifies the v51 folds of Codex's 4M/1m
against the real code and attacks the two new mechanisms (the snapshot
contract and the reconciler-join observation). All line numbers
re-verified against the worktree.

## A. Fold verification (r50 findings → v51)

### 1. Codex M1 (coherent snapshot contract) — FOLDED

The torn-read construction was verified in r50; the v51 form — ONE
immutable snapshot struct swapped under a single `atomic.Pointer`,
written at the apply boundary, read exactly once by the renderer —
closes it: a read after the failure's swap sees the failure (release/
acquire), a read during the apply sees lastOK==false (the entry swap
precedes the apply body). The residual question I posed — is
ActiveApplied inside the snapshot — is answered by the predicate's
shape: ActiveApplied remains store-locked, but the false-green
direction required the apply-health fields to tear AMONG THEMSELVES
(old lastOK with old count); the snapshot prevents exactly that, and
ActiveApplied's own store lock makes its read atomic. FOLDED.

### 2. Codex M2 (truth at the convergence point) — FOLDED

Both false-green paths verify (`daemon_apply_dataplane.go:390-402,
466-489` with `manager_worker_arm_5134.go:10-21`;
`daemon_run_bringup.go:493-520` with
`daemon_apply_dataplane.go:137-163`), and the v51 rule — lastApplyOK
true only when the dataplane phase actually converged, both named
outcomes recording NOT-converged — moves the truth assignment to the
convergence point. I walked `applyConfigLocked`'s exits
(`daemon_apply.go:141-355`): the deferred-error tail join
(`daemon_apply_tail.go`) is upstream of the wrapper's success mark,
so no full-apply exit reports success with an unconverged dataplane
once the two named feeds record failure. FOLDED.

### 3. Codex M3 (outbound-reconciler join) — FOLDED, with nit m1

The stale-capture construction verifies exactly
(`daemon_ha_sync.go:462-497` captures text and claims the marker
without applySem; the paused pass's `QueueConfig` takes a newer wire
generation, `sync_conn_config.go:222-243`; the receiver accepts
strictly-newer, `sync_conn_config.go:254-272`; the claimed marker
suppresses the later reconcile, `daemon_ha_sync.go:479-484`). The
join's ORDERING is right — the operator's commit push always carries
the newest wire generation, so a re-drive after a stale push
overwrites it. FOLDED — but see m1: the observation mechanism is
not faithful.

### 4. Codex M4 (authority-dependent branches executable) — FOLDED

The read-only gate and its clearing verify (`store.go:346-353`,
`store_lock.go:9-27`, `daemon_ha.go:438-475` — promotion to primary
clears cluster read-only), the manual-failover request exists in the
operational tree (the chassis-cluster request commands), and the
terminal corner (encrypted origin-pinned artifact + no operator text
+ cross-node need) is now named runbook-unrecoverable with the
rebuild path. FOLDED.

### 5. Codex m1 + the acceptance re-activation gap — FOLDED

The acceptance copy now carries `failure-count == 0 AND
last-outcome-success` and the two-node re-activation with the
complete predicate. Grep-verified both. FOLDED.

## B. Fresh attacks on the v51 delta

**Attack 1 (SUCCEEDED as nit m1) — the reconciler-join's witness is
not faithful.** The v51 text observes the pass's completion via "the
`ConfigsSent` tick ... or the marker no-op". Two defects: (i) a
no-op pass never ticks `ConfigsSent` (the no-op return precedes
`QueueConfig`, `daemon_ha_sync.go:478-485`), and the no-op is a
Debug log — not an operator surface — so the operator cannot
distinguish "pass no-oped" from "pass hasn't fired"; (ii) a tick
doesn't say WHICH text was pushed. The faithful witness is the
digest re-read: the reconcile loop wakes at the stability threshold
and every 30s thereafter (`configSyncReconcileLoop`,
`daemon_ha_sync.go` — `periodic = 30 * time.Second`), so the
operator waits until the authority's uptime ≥ stability-gate + one
reconcile interval, then RE-READS BOTH digests; if the peer flipped
to the older text, the stale push landed and the operator's
re-convergence commit overwrites it (newest wire generation wins);
only then does the final predicate run. One clause replacing the
tick/no-op wording. MINOR.

**Attack 2 (FAILED) — a stale snapshot read after a failure.** The
entry swap (lastOK=false) precedes the apply body; the exit swap
(count++/false or true) precedes the return; a predicate read at
operator pace lands after one of the two swaps, and the
release/acquire pairing on the pointer makes the read see the latest
published snapshot. No stale-green window. FAILED.

**Attack 3 (FAILED) — the promotion-for-commit disturbs the fence.**
The manual-failover promotion happens post-restart, after the local
state is already classified (Load before comms); the final predicate
runs after the re-convergence and re-activation, so any disturbance
the promotion introduced is measured by the predicate, not hidden
from it. FAILED.

**Attack 4 (FAILED) — the snapshot boundary vs ActiveApplied.** The
dangerous tear was among the apply-health fields (old lastOK with
old count); the snapshot closes it. ActiveApplied is independently
store-locked but atomically read; a predicate that ANDs the snapshot
with ActiveApplied can miss an apply that starts between the two
reads — and that case reads lastOK=false on the NEXT read because
the entry swap fires at apply entry; the operator-paced predicate
re-reads on any failure. FAILED.

## C. Findings

### MAJOR (0)

None. All five r50 findings fold on independent verification.

### MINOR (1)

**m1.** Replace the reconciler-join's witness: the `ConfigsSent`
tick is insufficient (a no-op pass never ticks — the no-op return
precedes `QueueConfig`, `daemon_ha_sync.go:478-485` — and a tick
doesn't identify which text was pushed). The faithful observation:
wait until the authority's uptime ≥ stability-gate + one reconcile
interval (`periodic = 30s`, `configSyncReconcileLoop`), then re-read
BOTH digests; if the peer flipped to the older text, the stale push
landed and the operator's re-convergence commit overwrites it
(newest wire generation wins); only then the final predicate runs.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the witness clause). A
v52 containing only this pin is PLAN-READY by inspection from me.
