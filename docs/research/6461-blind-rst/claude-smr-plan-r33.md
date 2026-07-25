# Claude SMR hostile plan-review — round 33 (v9.9.17 @ 3bf46930e)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.17 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.17-as-committed** — one self-found HIGH (the deferral park as written
would stall heartbeats and trip failover), plus placement precision. All
other v9.9.17 mechanisms verified sound against code.

## Finding 1 (HIGH — the deferral park must be message-class-selective)

The future-epoch deferral says "the receiver PARKS that connection's
remaining stream (head-of-line)". Read literally, the park blocks the whole
sync connection — but heartbeats ride the SAME connection
(`syncMsgHeartbeat`/`syncMsgHeartbeatAck` are handled in the same
`handleMessage` dispatcher as session installs,
`pkg/cluster/sync_conn_read.go:284,:296`, with the ack written synchronously
on receive). A routine config-apply lag (the normal sub-second async-apply
window, let alone a #6387 stuck apply) would stall heartbeat-acks, run up
`missedHeartbeats`, and trip a spurious failover — a brand-new availability
hazard introduced by the fold, worse than the bug it fixes. The park MUST be
message-class-selective: SESSION-STATE messages (session installs, deletes,
bulk Start/End/markers — anything that mutates or reconciles session state)
buffer behind the park in arrival order (the FIFO ordering proof is
preserved: buffered deltas keep their stream order, so a delete still can
never bypass a deferred install for the same key); CONTROL messages
(heartbeat/ack, config receipt — which is itself only queued for async
application, `sync_conn_read.go:298`, and is what eventually drains the
park) keep flowing. Bulk markers park with the deltas
(`reconcileStaleSessions` at BulkEnd consumes session state and must not
run against a partially-buffered bulk). Overflow of the bounded buffer →
connection reset → re-bulk (on reconnect the config re-push precedes the
bulk, so the park drains first — progress is guaranteed unless the config
never applies, the operator-visible #6387 case).

## Finding 2 (nit — placement of the three-way epoch gate)

The deferral should be pinned to the same layer as the existing stale gate:
`configEpochStale` is "authoritative here in the Go cluster layer: the
receiver refuses BEFORE forwarding the install to the userspace helper"
(`sync_conn_gen.go:404-412`), and the barrier it reads —
`max(applyingConfigGen, lastAppliedConfigGen)` — already exists with the
correct success-release ordering (`sync_conn_gen.go:415-431`). State the
gate as one coherent three-way at that Go receive point: `epoch < barrier`
→ refuse (existing #5274 semantics); `epoch > barrier` → park (new);
`epoch == barrier` or in-band → process. The helper never sees a
future-epoch install; no helper-side change is needed for the deferral.

## Verified sound this round (my own re-trace)

- **r32-M3 fold**: `rollback_flow` (allocator.rs:1392-1458) is the correct
  teardown for every create-or-retain shape — persistent port-bearing
  (saturating_sub on `active_flows`; port freed only when the fresh lease is
  removed), re-activation rollback restores the PREVIOUS expiry, address-only
  persistent (reverse-identity token removed, no port bit touched),
  non-persistent arms (plain port free honoring the deterministic bit).
- **r32-B2 fold mechanism**: the barrier fields exist and are read with the
  right ordering; the drain condition (`lastAppliedConfigGen >= stamp`) is
  well-defined; reconnect re-push precedes bulk so the park drains.
- **r32-B1 fold**: inventories now agree at all five sites (§5.8 tail, Go
  sidecar, atomic snapshot, shared-map, entry-stamp provenance).
- **Migration gate (AGY Q2 fold)**: the RW-gate answers all three AGY
  traces; the enumeration (now including `rollback_flow` and expiry GC) is
  complete against source.rs/allocator.rs; the drained-snapshot-publish
  removes the lockstep requirement entirely.

## Verdict

**PLAN NO for v9.9.17** — fold Finding 1 (message-class-selective park) and
Finding 2 (three-way gate placement) as v9.9.18. Both are precision clauses
on the deferral mechanism, no redesign. Part A remains converged and
untouched.
