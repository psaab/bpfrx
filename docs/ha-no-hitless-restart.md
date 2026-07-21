# HA Mode: No Hitless Restart

Date: 2026-03-01  
Status: Implemented (Sprint #68)  
Tracking issue: https://github.com/psaab/xpf/issues/68

## Summary

In chassis cluster (HA) mode, hitless restart is the wrong default.
If the local daemon is down or wedged, the node should fail closed instead of
continuing to forward with stale in-kernel dataplane state.

## Why

Hitless restart is valuable for standalone upgrades, but HA has different
priorities:

- Deterministic failover and single-owner forwarding.
- Reduced split-brain risk when a node loses control-plane health.
- Clear operational behavior: HA node unhealthy means stop forwarding.

Current code intentionally preserves dataplane state on daemon shutdown:

- `pkg/daemon/daemon.go` keeps control-plane state and calls non-destructive
  dataplane close (`d.dp.Close()`).
- `pkg/dataplane/loader.go` `Close()` keeps pinned links/maps active for reuse.

That is desirable for standalone hitless restart, but risky as the default in
HA.

## Implemented behavior

When `chassis cluster` is enabled:

1. Disable hitless-restart semantics by default.
2. On daemon exit/failure, transition to fail-closed behavior for local
   forwarding ownership state.
3. Preserve current hitless behavior in non-HA standalone mode.
4. Provide an explicit opt-in if operators want hitless behavior in HA.

## Acceptance criteria

- In HA mode, stopping or crashing `xpfd` does not leave stale active
  forwarding on that node.
- Peer failover converges without prolonged dual-active forwarding.
- Standalone mode continues to support hitless restart.

## Standalone <-> cluster transitions require a restart (#5840)

Turning chassis-cluster mode ON or OFF is a topology change, not a live
day-2 reconfiguration. The cluster runtime — the `d.cluster` manager,
its election, the heartbeat/watchdog writer, session/config/DHCP-lease
sync, the event watcher, the VRRP sync hold, and the gRPC fabric
listener — is constructed **exactly once, at process startup**, and only
when the boot-time active config already contains `chassis cluster`
(`pkg/daemon/daemon_run.go` `initManagers` + `startClusterComms`). A
running daemon cannot construct or tear that runtime down from a commit:

- `d.cluster` is a bare, write-once-at-boot pointer read without a
  lifecycle lock from many gRPC/CLI/reconcile call sites, so assigning it
  mid-apply is a data race and exposes a partially-initialized runtime.
- The userspace dataplane arms clustered forwarding semantics
  (`clusterHA=true`, seeded HA groups) from the new config during the
  same apply, before any watchdog writer or election exists — the Rust HA
  gate then treats transit as HA-inactive and drops it persistently.

To avoid silently publishing that half-built hybrid state (no HA plus a
persistent transit outage until restart), a commit that adds or removes
`chassis cluster` on a running daemon is **rejected before any store
promotion or dataplane mutation** (`clusterTopologyCommitPreflight`,
wired into `commitAndApply` / `commitConfirmedAndApply`, and fail-closed
in the peer-sync replay path `syncAndApply`). The operator commits the
topology change with the system offline, or restarts `xpfd` into the new
configuration; the boot path then constructs the correct runtime. Intra-
mode edits (redundancy-group / interface / transport changes on an
already-clustered node, or any standalone-only edit) reconcile live as
before.

First-class live day-2 construction/teardown of the cluster runtime
(the "full supervisor" contract) is tracked as a separate follow-up.

## Acceptance criteria (topology transition, #5840)

- A day-2 commit adding `chassis cluster` on a standalone daemon is
  rejected with a restart-required diagnostic; `d.cluster` stays nil and
  the candidate is not promoted.
- The reverse (removing `chassis cluster` on a clustered daemon) is
  rejected the same way.
- A peer-synced replay encoding the same transition fails closed without
  arming the live dataplane.
- Intra-mode commits (no standalone<->cluster change) are unaffected.
