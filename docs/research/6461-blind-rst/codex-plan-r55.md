PLAN NO

1. **BLOCKER — Independent confirmation deadlines can latch opposite protocol classes on the same connection.**

   `plan.md@cd616a909:4038-4050` makes a local timeout permanently latch that endpoint into legacy mode. There is no shared decision/commit exchange. Concrete schedule: A and B both send matching confirmations; B receives A’s just before its deadline and installs as repair-era, while B’s confirmation reaches A just after A’s deadline, so A installs as legacy and ignores the late confirmation. TCP preserves B-confirm-before-B-repair ordering, but cannot reverse A’s completed latch. B then uses repair terminal semantics while A follows legacy `BulkEnd` processing at [sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:205), producing inconsistent reconciliation or a readiness/redrive wedge.

   Retaining the same stream after timeout also requires explicit partial-frame handling: [sync_auth.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:289) can consume part of a frame before timeout, while the normal reader then expects a new header at `sync_conn_read.go:38`.

   Required change: use a shared capability commit—such as a deterministic decision owner plus `CAPABILITY_DECISION/ACK`—and install neither side until committed. Otherwise a timeout must close and retry with bounded backoff; it cannot independently select a class while retaining the connection.

2. **HIGH — Delayed legacy readiness writers can overwrite the activation transaction’s not-ready fence.**

   `plan.md:4053-4062` correctly orders repair-ID creation, obligation arming, not-ready publication, capability exposure, and bulk drive. However, a legacy `BulkEnd` queues `go s.OnBulkSyncReceived()` asynchronously at [sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:246). That callback carries no connection, protocol, or activation generation—its type is simply `func()` at [sync.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go:407).

   Concrete schedule: legacy completion queues callback G1; later repair activation atomically arms its obligation and marks not-ready; delayed G1 then calls `SetSyncReady(true)` at [daemon_ha_sync.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_sync.go:90). The older readiness timer at `:40-47` can do the same. Readiness is a separate boolean under `Manager.m.mu` at [sync_state.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_state.go:13), so the plan’s activation atomicity does not presently fence these writers.

   Required change: use one versioned activation/readiness state. Every callback and timer must carry the connection/protocol generation and set ready only by CAS when that generation remains current and no repair obligation exists.

**Round-54 dispositions**

- **r54-1 — RESOLVED.** I reconstructed both 177-byte inputs and recomputed the HMAC-SHA256 values. They exactly match `48fdf3d1119bce50cf76abd185678c4c9f39701d678c9aead4c864bb907790f3` and `13dff63c649c4e72b2df5e6a7f275fecb335d78363344dbf00464a81d35dd428`. The grammar, fields, bit registry, and role wording are consistent with [sync_auth.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:217).
- **r54-2 — PARTIALLY RESOLVED.** Registration, deadline, admission accounting, and shutdown coverage are fixed; the replacement timeout-latch protocol can still select asymmetric classes.
- **r54-3 — PARTIALLY RESOLVED.** The direct activation ordering is fixed, but finding 2 leaves older asynchronous readiness writers outside its atomicity domain.

Bottom line: the byte-exact authentication contract has converged, and the original untracked-confirmation and pre-arm activation windows are closed. Sign-off remains blocked because local confirmation timeouts can split protocol class and stale completion callbacks can restore readiness while a repair remains outstanding. I found no additional concrete demote-gate, NAT-holder, or family-cleanup trace.
