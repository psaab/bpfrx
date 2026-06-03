# Claude-SMR hostile plan review — #1750 r2

Reviewing plan v2 (@ 0bbcd5f41) after the r1 round folded. Hostile.

## Verdict: PLAN-NEEDS-MINOR → converging on the same single defect as Codex+AGY r2

The three r1 MAJORs are closed in v2's prose (atomic-publish reworded → bundle;
cause D keying called out; dead-code §6.3 replaced with the side-table). But r2
surfaces ONE shared defect plus two precision fixes:

### MINOR-1 (shared, Codex+AGY r2) — the `StaleFlowSnapshot` defer is unsafe
The guard as written ("hottest worker has zero candidate rows but bundled
`active_flow_count > 0` → defer") is broken two ways:
- **Dead after bundling:** once count and rows ride one snapshot from the same
  scan (`flow_cache.rs:478-493`), `count > 0 && rows.is_empty()` is impossible
  for a non-truncated snapshot — the check never fires for the case it was meant
  to catch.
- **Livelocks on the filtered case:** if the controller checks the *filtered*
  candidate list (TCP/UDP on the steered ifindex), a worker carrying only
  non-steerable traffic (ICMP, unsteered ports) has `active_flow_count > 0` but
  zero candidates → defers EVERY tick → never installs (AGY's worked example).
**Fix:** make staleness a SNAPSHOT-AGE check (publish timestamp older than
N × publish-interval), bounded to a few ticks, then fall through to a real
terminal skip with a diagnostic. Do NOT gate the defer on count-vs-rows.

### MINOR-2 (Codex r2) — cause D is ALREADY FIXED on the branch; reframe
The current `engineer/1748-ntuple-rebalance` HEAD already joins `live` (slot) →
`identities` (slot→`BindingIdentity{worker_id}`) and keys `WorkerByteRate` by
the real `worker_id` (`rebalance.rs:207-256`, comment "#1748 live BUG (r6)").
So cause D is the parallel patch's work, not an open blocker — the plan should
say "already fixed; re-verify live" rather than "to fix". The deeper
consequence: **after bundling (A) AND the existing keying fix (D), a still-empty
candidate set is necessarily cause C (post-filter loss: ifindex/parse/proto) —
diagnose it directly from the live trace; the StaleFlowSnapshot defer must NOT
paper over a persistent post-filter loss.**

### MINOR-3 (Codex r2) — specify the `flow_worker_map()` API change
The controller currently reads `let (rows, _truncated) = self.flow_worker_map()`
(`rebalance.rs:273`) — rows only, NO count. Path 1 part 1 must explicitly change
`Coordinator::flow_worker_map()` (`status.rs:168`) to surface the bundled
per-binding/per-worker count, and the controller to consume it. The plan said
"bundle the count" but did not name the consumer-API change.

### Precision fix
v2 §6.2 says worker_id is "available on the live state / identities" — it is on
**identities (BindingIdentity)**, NOT `BindingLiveState`. Correct the wording.

## Things v2 got right (keep)
- Atomic bundle (Path 1 part 1) is the correct structural fix for skew (A).
- Side-table deferral acceptable for the homogeneous P12 live gate (both r2
  reviewers agree); Path 2 only if a heterogeneous gate is added.
- Pre-code live trace + live CoV gate as acceptance.

## Required for PLAN-READY (v3)
1. Rewrite the staleness defer as a bounded snapshot-AGE check; never gate on
   count-vs-rows; fall through to a real skip + diagnostic after N ticks.
2. Reframe cause D as already-fixed-on-branch (re-verify live); state that a
   residual empty candidate set is then necessarily cause C and must be
   diagnosed, not deferred.
3. Name the `flow_worker_map()`/`status.rs:168` API change explicitly.
4. Fix "live state / identities" → "identities (BindingIdentity)".
