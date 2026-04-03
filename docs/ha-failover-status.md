# HA Failover Status

Date: 2026-04-03 (updated)

This is the single authoritative document for userspace dataplane HA failover.
It replaces the fragmented state across a dozen prior docs. Read this first;
refer to the others only for implementation-level detail.

## Goal

Failover should be:

1. VRRP moves the virtual MAC
2. New owner sends GARP/NA
3. Traffic continues forwarding through synced sessions

No activation-time repair, no re-resolution, no queue bring-up, no barrier
choreography. Sessions are synced continuously — the standby should already
be able to forward.

## Current Reality

The system is closer to this goal than it has ever been, but it is not there
yet. Here is what is true today:

- Sessions sync continuously via event stream (real-time) + bulk (startup)
- Synced sessions are resolved with local egress on receipt (#326), not at
  activation time
- Flow cache uses epoch-based invalidation (#327) — no transition-time scans
- Demotion is a single `update_ha_state(active=false)` call (#359) — no
  two-phase prepare + demote
- Activation is a single `update_ha_state(active=true)` call (#358) — no
  explicit refresh RPC
- Manual failover uses request/ack/commit protocol (PRs #395-#397) — not
  weight-zero heuristics
- Takeover readiness gates on proven userspace dataplane health (#391)
- Blackhole routes skipped in userspace mode (#354)
- Helper watchdog threshold aligned with sync cadence (#349)
- Reverse companions pre-installed via sync path (#310)
- BPF conntrack entries written for zone/interface display (fab9230c)
- Userspace counters aggregated into BPF global counters (#332)
- Shared sessions indexed by owner RG for O(1) demotion/activation (PRs
  #404-#406) — no full-table scans during failover
- Priority barrier channel for acks (PR #407) — barrier/bulk acks bypass
  session data in send queue
- Planned failover decoupled from bulk sync (PR #407) — barrier ack
  proves peer is current, no bulk-sync gate
- Transfer readiness surfaced separately from takeover readiness (PR #402)

## What Works

Manual failover with `request chassis cluster failover redundancy-group 1
node N` successfully moves RGs between nodes. Sessions are synced, SNAT is
applied on the new owner, traffic continues. Validated with iperf3 4-stream
tests showing 27M SNAT packets on the new owner after failover.

The key fixes that made this work:

| Commit | Fix |
|--------|-----|
| ba1c4304 | Async bulk ack + HA sync throttle — bulk sync completes reliably |
| 7417144e | Re-resolve synced sessions with owner_rg_id=0 |
| 71b80b3d | refresh_for_ha_activation bypasses synced guard — SNAT works |
| a21018f3 | Epoch flow cache, resolve on receipt, owner_rg_id at sender |
| dcc59c67 | Unified synced flag → origin-based collision detection |
| PRs #395-397 | Explicit RG transfer protocol (request/ack/commit) |
| PRs #404-406 | Owner RG indexes — O(1) demotion/activation |
| PR #407 | Priority barrier channel + decouple failover from bulk sync |

## What Was Fixed Recently

### P0: Barrier delivery during bulk sync — FIXED (PR #407)

Barrier acks and bulk acks now route through a dedicated priority channel
(`barrierCh`). The `sendLoop` drains `barrierCh` before `sendCh`, so acks
are never stuck behind bulk session data. Barrier requests still go through
`sendCh` to preserve ordering (the barrier must be after all queued sessions
so the ack proves the peer processed them).

### P2: Manual failover rejected during bulk sync — FIXED (PR #407)

Removed `syncPeerBulkPrimed` and `TransferReadiness` bulk-state checks from
the planned failover path. The barrier ack alone proves the peer is current.
Bulk sync is a startup concern, not a failover concern.

### P3: Split-RG readiness stuck — LIKELY FIXED

Root cause was barrier/bulk ack delivery stuck behind bulk data (P0). With
priority ack channel, acks should deliver promptly. Needs live validation
on split-RG cluster.

## What Still Needs Work

### Inherited translated tuples resolve as HA-inactive (was P1)

After failover, some inherited forward-wire tuples (translated 5-tuples
from SNAT) may resolve as `HAInactive` on the new owner. PRs #404-406
added owner RG indexes to shared session stores, which should improve
the lookup path. Needs live validation to confirm the fix.

**Status:** Likely improved, needs testing.

### Live validation of all fixes

The recent changes (priority barrier channel, owner RG indexes, planned
failover decoupled from bulk sync) have not been validated together with
a live `/failover-test` run. The individual pieces are tested but the
end-to-end flow needs validation.

### Throughput parity on fabric redirect path

When traffic is fabric-redirected (old owner → new owner via fabric link),
throughput is ~7 Gbps vs 15-17 Gbps for direct forwarding. This is a
hardware/topology limitation — fabric redirect adds an extra hop through
the virtio fabric interface. Traffic should converge to direct forwarding
on the new owner quickly.

## Architecture

### Session Sync Flow

```
Active node:
  helper creates session → event stream → daemon → session sync TCP → peer

Standby node:
  session sync TCP → daemon → SetClusterSyncedSessionV4 → helper UpsertSynced
  → resolve with local egress immediately (not at activation)
  → session is forwarding-ready in the helper's session table
```

### Failover Flow (Target)

```
1. CLI: request failover RG1 to node1
2. node0: barrier check (peer has all sessions)
3. node0: update_ha_state(RG1=false) — atomic demotion
   - bump RG epoch (flow cache auto-expires)
   - demote shared sessions
4. node0: VRRP sends priority-0 burst → node1 becomes MASTER
5. node1: VRRP MASTER → addVIPs → GARP/NA
6. node1: update_ha_state(RG1=true) — activation
   - sessions already resolved with local egress (from step above)
   - bump FIB generation
   - traffic starts flowing immediately
```

### Failover Flow (Current)

Steps 1-6 above are now the actual flow. Remaining differences from target:
- Some translated tuples may still resolve as HAInactive (needs validation)
- Neighbor warmup still runs async after activation (harmless — ARP/NDP
  for next-hops, not blocking the forwarding path)

## What Was Eliminated

These mechanisms existed before the simplification work and have been
removed or bypassed:

| Mechanism | Removed in | Why |
|-----------|-----------|-----|
| `FlushFlowCaches` worker command | a21018f3 | Replaced by epoch-based invalidation |
| `refresh_owner_rgs` explicit RPC | 5ac423a3 | Sessions pre-resolved on receipt |
| `prepare_ha_demotion` two-phase | #359 | Demotion is atomic in update_ha_state |
| `SuppressedUntil` lease variant | #359 | No longer needed without prepare step |
| `syncPeerBulkPrimed` hard gate | e42c882e | Replaced by barrier-based readiness |
| Quiescence retry loop | a21018f3 | Single barrier is sufficient |
| Event stream drain/pause/resume | a21018f3 | Barrier proves delivery |
| Kernel session journal flush | a21018f3 | eBPF ctrl is disabled in userspace mode |
| `pendingRGTransitions` map | 5ac423a3 | Replaced by atomic bool |
| Blackhole routes (userspace mode) | 5ac423a3 | XDP shim + rg_active handles this |
| Weight=0 manual failover | PR #395 | Replaced by explicit transfer state |
| `synced: bool` field | dcc59c67 | Replaced by origin-based collision |
| `syncPeerBulkPrimed` failover gate | PR #407 | Barrier ack proves peer is current |
| `TransferReadiness` bulk-state check | PR #407 | Planned failover doesn't depend on bulk |
| Full-table scans on demotion/activation | PRs #404-406 | Owner RG indexes for O(1) lookups |
| `waitForSendQueueDrain` in barrier path | PR #407 | Priority channel for acks |

## Testing

### Automated

```bash
# Hardened RG move under load (the primary validator)
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 240 --parallel 4
```

### Manual CLI test

```bash
# Start traffic
iperf3 -c 172.16.80.200 -P 4 -t 60

# Move RG
cli -c "request chassis cluster failover redundancy-group 1 node 1"

# Verify: SNAT > 0 on new owner, all streams alive
cli -c "show chassis cluster data-plane statistics" | grep SNAT
```

### Pass criteria

- All 4 iperf3 streams survive failover
- Zero zero-throughput intervals
- SNAT packets > 0 on new owner
- Session misses < 1000 on new owner
- RG moves to the requested node

## Remaining Work (Priority Order)

1. **Live validation** — run `/failover-test` with all recent fixes deployed
   to confirm end-to-end failover works with zero stream loss
2. **Validate translated tuple fix** — confirm PRs #404-406 resolved the
   HAInactive resolution for inherited forward-wire entries
3. **Validate split-RG** — confirm priority ack channel fixed split-RG
   readiness convergence
4. **Throughput parity** — hardware/topology limitation, not a software fix

## Superseded Documents

These docs contain historical investigation detail but should not be
read as current truth. This document supersedes all of them:

- `docs/archived/userspace-failover-hardening-plan.md`
- `docs/archived/userspace-failover-next-steps.md`
- `docs/archived/userspace-ha-failover-parity-plan.md`
- `docs/archived/failover-hardening-progress.md`
- `docs/archived/ha-failover-simplification-audit.md`
- `docs/archived/ha-simple-failover-design.md`
- `docs/archived/ha-failover-implementation-plan.md`
- `docs/archived/ha-forwarding-state-inventory.md`
- `docs/archived/userspace-forwarding-and-failover-gap-audit.md`
