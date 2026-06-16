# #1928 — virtio multi-queue forwarding outage: PLAN-READY

**Status:** PLAN-READY. Root cause CONFIRMED on the venue and fixed in the Go
control plane (a `clusterHA` guard on the startup HA-state publish, plus a
cluster→standalone clear). The bind-flag hypothesis from earlier rounds was a
MISATTRIBUTION (refuted by an isolation experiment — see below). The actual
and sole root cause is a standalone HA-gate bug in the Go control plane.

## Confirmed root cause (the real bug)

On a **standalone** (non-chassis-cluster) firewall, the userspace dataplane
dropped **all transit traffic** with disposition `HAInactive`, both IPv4 and
IPv6. The chain:

1. `rg_active` is a `BPF_MAP_TYPE_ARRAY` with `max_entries = 16`, so the kernel
   ALWAYS exposes all 16 keys (0-15). On standalone every value is 0 (inactive).
2. At snapshot-apply (`pkg/dataplane/userspace/manager.go`, the `Apply` path),
   `refreshHAStateFromMapsLocked()` → `mergeHAStateFromMaps()` iterated that
   array and fabricated **16 inactive HA groups** into `m.haGroups`, regardless
   of cluster config (`seedHAGroupInventoryLocked` correctly no-ops without a
   cluster, but the map-replay path did not).
3. `syncHAStateLocked()` then shipped those 16 groups to the Rust helper
   (`CTRL_REQ: update_ha_state groups=16 forwarding_armed=false` in journald).
4. In the helper, `enforce_ha_resolution_snapshot()`
   (`userspace-dp/src/afxdp/forwarding/mod.rs`) gates every transit
   `ForwardCandidate`: with `owner_rg_id <= 0` (standalone egress ifaces have
   redundancy_group 0) AND `!ha_state.is_empty()` (the 16 phantom groups), it
   rewrites the disposition to `HAInactive` and drops the packet.

The periodic status poll (`process.go`) already guarded the same
`refreshHAStateFromMapsLocked()` behind `if m.clusterHA`. The **startup
snapshot-apply path did not** — that asymmetry is the bug.

## Why earlier rounds misdiagnosed it as a bind-flag issue

The prior session changed `bind_flag_candidates_for_driver` (virtio AUTO →
explicit COPY|NEED_WAKEUP) and observed "v6 6/6". That v6 success was **kernel
return-route forwarding**, not the dataplane (`tx_completions_total` stayed 0).
The "AUTO forwards nothing" observation was the HA gate dropping everything, not
the bind flag. Isolation experiment on the venue (this round): with the
bind-flag change REVERTED to the original `AUTO_BIND_FLAGS=[0]` (verified
`flags=0x0000` in journald) but the HA-gate fix in place, the dataplane forwards
**5000 pps, fwd=5000, snat=1, ha_inact=0**. So the bind-flag change was
unnecessary and was DROPPED — the fix is the Go guard alone.

(Diagnostic note: virtio copy-mode XSK RX delivery is fine under both AUTO and
explicit-COPY binds on this kernel — `rx_xdp_redirects` climbs, the fill ring is
serviced via `maybe_wake_rx`'s `poll(POLLIN)`, and `RAW: rxP`/`frC` advance with
traffic. The earlier "frames never reach userspace" framing conflated the
post-RX HAInactive drop with an RX-delivery failure.)

## Fix

`pkg/dataplane/userspace/manager.go`: guard the startup
`refreshHAStateFromMapsLocked()` + `syncHAStateLocked()` behind `if m.clusterHA`,
matching the pre-existing guard on the periodic status poll. When `!clusterHA`,
no phantom groups are fabricated.

To also cover the cluster→standalone live-reconfig hazard (Codex review Q3:
stale groups a prior clustered apply pushed to the helper would otherwise keep
the gate armed):
- `seedHAGroupInventoryLocked` now CLEARS `m.haGroups` when there is no cluster
  config (was an early return that left stale groups in the manager).
- The non-cluster branch of the startup path calls a new
  `clearHelperHAStateLocked()` that sends an explicit empty `update_ha_state`
  (`groups=0`) so the helper rebuilds an EMPTY `ha_state` and drops any stale
  groups. Verified live: the debug-log helper logged
  `CTRL_REQ: update_ha_state groups=0` on a standalone apply.
- The XSK-startup deferral path (manager.go, `pendingXSKStartup` early return)
  also calls `clearHelperHAStateLocked()` on the non-cluster branch, because the
  deferred-publish resume path (`syncSnapshotLocked`) never syncs HA state
  (Codex review Q1).

Regression tests:
- `TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap` documents the array-map
  phantom-group mechanism the guard protects against.
- `TestSeedHAGroupInventoryLockedClearsGroupsWithoutCluster` covers the
  cluster→standalone group-clear.
- `TestClearHelperHAStateLockedSendsEmptyUpdate` asserts the helper-side clear
  sends `update_ha_state` with a present `ha_state` payload and 0 groups
  (Codex review Q6).

## Validation (venue t1921-fw, 4-queue virtio, clean production build)

- v4 transit LAN→WAN: 5/5, 0% loss.
- v6 transit LAN→WAN: 5/5, 0% loss.
- standalone daemon: the only `update_ha_state` is the `groups=0` clear (was
  `groups=16` of inactive phantom groups arming the gate).
- `ha_inact=0` (was 1346 under load), `sessions` nonzero, `bpf_entries` nonzero.
- `xpf_userspace_binding_tx_completions_total` nonzero across LAN+WAN bindings.
- SNAT proven: wan-host has NO v4 return route to 10.66.1.0/24 yet v4 replies
  returned — only possible via interface SNAT to 10.66.2.1. DBG `NAT:snat=1`.
- Sustained UDP flood: `rx≈tx≈fwd=5000` per second, 0 ha_inact, 0 tx_err.

## mlx5 no-regression rationale

The fix only changes behavior for `clusterHA == false` (standalone). The loss
cluster runs `clusterHA == true`, so the guarded block executes exactly as
before — the fix is a no-op for clustered nodes. `make test-failover` confirms.

## Scope

- One Go guard + one regression test. No Rust helper / shim changes.
- bind.rs is restored to master (the earlier #1928 bind-flag commit is dropped).
