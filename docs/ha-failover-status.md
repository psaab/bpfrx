# HA Failover Status

Date: 2026-04-02

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
- Manual failover uses request/ack/commit protocol (PRs #396-#397) — not
  weight-zero heuristics
- Takeover readiness gates on proven userspace dataplane health (#391)
- Blackhole routes skipped in userspace mode (#354)
- Helper watchdog threshold aligned with sync cadence (#349)
- Reverse companions pre-installed via sync path (#310)
- BPF conntrack entries written for zone/interface display (fab9230c)
- Userspace counters aggregated into BPF global counters (#332)

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

## What Does Not Work Yet

### P0: Barrier delivery during bulk sync

The barrier message that fences demotion gets stuck behind bulk session data
in the TCP stream. When the peer is receiving hundreds of sessions via bulk
sync, the barrier waits 60-80 seconds to be delivered. The demotion prep
times out.

**Root cause:** `writeBarrierMessage` used to call `waitForSendQueueDrain`
which blocks until `sendCh` empties. Even after removing the drain wait, the
barrier is written via `writeMu` which the `sendLoop` holds continuously
during bulk writes. The barrier ack from the peer also goes through `sendCh`
on the receiver side, competing with outbound messages.

**Impact:** Manual failover fails with "demotion peer barrier failed:
timed out" when bulk sync is in progress.

**Fix needed:** Either (a) send barriers on a separate TCP connection,
(b) give barriers priority in the write path via a priority channel, or
(c) write barriers directly via the connection with a short deadline
bypassing the sendLoop entirely.

### P1: Inherited translated tuples resolve as HA-inactive

After failover, some inherited forward-wire tuples (translated 5-tuples
from SNAT) resolve as `HAInactive` on the new owner even though the RG is
locally active. This causes the new owner to fabric-redirect traffic back
to the old owner instead of forwarding it locally.

**Root cause:** The shared session store has forward-wire entries keyed by
the post-NAT 5-tuple. When the new owner activates, these entries' owner
RG resolution may not match because the egress interface mapping differs.

**Fix needed:** Ensure forward-wire alias entries are re-resolved alongside
the primary forward session during standby materialization.

### P2: Manual failover rejected during bulk sync

The transfer-readiness check (`userspaceManualFailoverTransferReadinessError`)
rejects failover when the requester is in active bulk receive or has a
pending outbound bulk ack. This is correct for safety but means failover
is unavailable during the 30-120 second bulk sync window after a
reconnect/restart.

**Fix needed:** Either make bulk sync faster (batch session installs to
reduce control socket contention) or allow failover to proceed with a
degraded guarantee (some sessions may not be on the peer yet).

### P3: Split-RG session-sync readiness stuck

In split-RG configurations (RG1 on node0, RG2 on node1), session-sync
readiness can get stuck as "not ready" even after cluster ownership
converges. The bulk sync retry loop exhausts without the peer acking.

**Fix needed:** Investigate why bulk ack delivery fails in split-RG
configurations. May be related to P0 (barrier delivery).

### P4: Throughput parity on fabric redirect path

When traffic is fabric-redirected (old owner → new owner via fabric link),
throughput is ~7 Gbps vs 15-17 Gbps for direct forwarding. This is because
fabric redirect adds an extra hop through the virtio fabric interface.

**Fix needed:** This is a hardware/topology limitation, not a software bug.
Fabric redirect is a transient state during failover — traffic should
quickly converge to direct forwarding on the new owner.

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

Steps 1-6 above, PLUS:
- Barrier delivery may take 60-80s if bulk sync is in progress (P0)
- Some translated tuples may resolve as HAInactive (P1)
- NAPI bootstrap removed from activation (#391) but neighbor warmup
  still runs async (harmless — just ARP/NDP for next-hops)

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

1. **Fix barrier delivery during bulk sync** (P0) — unblocks reliable
   manual failover in all cluster states
2. **Fix inherited translated tuple HA-inactive** (P1) — ensures all
   session types are forwarded correctly after failover
3. **Allow failover during bulk sync** (P2) — removes the 30-120s
   unavailability window after reconnect
4. **Fix split-RG readiness** (P3) — enables active/active testing
5. **Throughput parity** (P4) — hardware/topology, not a software fix

## Superseded Documents

These docs contain historical investigation detail but should not be
read as current truth. This document supersedes all of them:

- `docs/userspace-failover-hardening-plan.md`
- `docs/userspace-failover-next-steps.md`
- `docs/userspace-ha-failover-parity-plan.md`
- `docs/failover-hardening-progress.md`
- `docs/ha-failover-simplification-audit.md`
- `docs/ha-simple-failover-design.md`
- `docs/ha-failover-implementation-plan.md`
- `docs/ha-forwarding-state-inventory.md`
- `docs/userspace-forwarding-and-failover-gap-audit.md`
