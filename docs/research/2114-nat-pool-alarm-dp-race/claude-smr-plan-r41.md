# Claude SMR hostile plan-review — round 41 (plan v41 @ `4a331d5a6`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r40's SMR
raised the H-branch config-shape nit (folded in v41); r41 re-verifies
the v41 folds of Codex's 2M/1m against the real code and attacks the
observable join's freshness semantics. All line numbers re-verified
against the worktree.

## A. Fold verification (r40 findings → v41)

### 1. Codex M1 (observable join) — FOLDED, with nit m1

The barrier gap was real: the config-sync consumer invokes
`syncAndApply(context.Background())` and can block INDEFINITELY
on `applySem` (`sync_conn_config.go:325-351`,
`daemon_apply_commit.go:326-335` — re-verified), so no capped
pass or timer can drain the queue. The v41 answer is the right
one: expose the queue-depth and apply-in-flight state read-only
on both nodes' status surfaces and wait on the INDICATOR, not a
timer — the operator's drain is an observable join, not a
guess. FOLDED — but see m1: the indicator's read freshness is
not pinned.

### 2. Codex M2 (reverse-direction TOCTOU) — FOLDED

The local drain closes it by construction: queue-empty AND no
apply-in-flight locally means no local→peer push can be in
flight when the peer stops; and a just-landed sync's debts are
raised synchronously at the peer (`store.go:687-717,738-746` —
the promote-then-persist ordering with
`noteActivePersistFailureLocked`), visible on the peer's own
status at preflight time. The peer-side full-state check is
readable exactly when it is needed (the peer runs until step
2c). FOLDED.

### 3. Codex m1 (§11 baseline + down-em0 annotation) — FOLDED

Grep-verified: the verdict request names "the current design";
the retained v39 history entry's `down em0` alternative is
annotated WITHDRAWN with the fabric-fallback citation. FOLDED.

## B. Fresh attacks on the v41 delta

**Attack 1 (SUCCEEDED as nit m1) — the indicator's read
freshness is unpinned.** The v41 text exposes the queue-depth
and apply-in-flight state "read-only" but never says the read is
LIVE (under the cluster mutex at RPC time, not a cached
snapshot). A cached or periodically-refreshed indicator would
reintroduce exactly the staleness the join exists to eliminate —
the operator could drain on a seconds-old queue-depth reading
while a frame lands behind it. The existing status surfaces
(`cluster/status.go:340-356`) read live state under the cluster
mutex, so the natural implementation is live — but the plan must
say so explicitly: the indicator is read LIVE under the cluster
mutex at check time, and the implementation pins a no-cache
regression. MINOR.

**Attack 2 (FAILED) — the peer-side preflight's visibility
window.** The peer's full state is read via the peer's own
status RPC, which exists only while the peer runs — but the
preflight (2b) precedes the peer stop (2c) by construction, so
the read is always available when needed; after the stop, no
peer state is needed (the local full-state re-check and the
stop complete the fence). No contradiction. FAILED.

**Attack 3 (FAILED) — the indicator itself lies during a
lock-free moment.** The queue-depth read under the cluster
mutex is atomic w.r.t. enqueue/dequeue; the apply-in-flight
flag is set/cleared under the same mutex at apply start/end
(`sync_conn_config.go:325-351`). A read showing
empty-and-idle is a true instantaneous join: any frame landing
after it must come from a producer the fence already covers
(commits refrained, peer about to be stopped). FAILED.

## C. Findings

### MAJOR (0)

None. Both r40 majors fold on independent verification; the
fence is now an observable-join protocol with a
transport-universal barrier and a full-state exit check.

### MINOR (1)

**m1.** Pin the indicator's freshness: the queue-depth and
apply-in-flight reads are LIVE under the cluster mutex at RPC
time (never a cached or periodically-refreshed value), with a
no-cache regression — a stale indicator would reintroduce the
exact TOCTOU the join exists to close.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the indicator
freshness pin). A v42 containing only this pin is PLAN-READY by
inspection from me.
