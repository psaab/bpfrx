# HA Mode: No Hitless Restart

Date: 2026-03-01  
Status: Implemented (Sprint #68)  
Tracking issue: https://github.com/psaab/bpfrx/issues/68

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

- In HA mode, stopping or crashing `bpfrxd` does not leave stale active
  forwarding on that node.
- Peer failover converges without prolonged dual-active forwarding.
- Standalone mode continues to support hitless restart.
