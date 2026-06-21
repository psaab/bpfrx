# pkg/cluster

Chassis-cluster HA state machine. Owns node state (Primary, Secondary,
SecondaryHold, Lost, Disabled), redundancy-group election, readiness
gates, manual failover, and the callbacks that fire session/config/IPsec
sync.

## Entry points

The legacy `cluster.go` (2429 LOC) was split in #1541 into sibling
files inside `package cluster`. Public API is preserved verbatim;
locating any symbol below is now a matter of opening the named file.

- `NodeState`, `RedundancyGroupState`, `ClusterEvent`,
  `RetryablePreFailoverError`, `Manager` (struct + `NewManager` +
  lifecycle: `Start`, `Stop`, `Events`, `Monitor`, `NodeID`,
  `ClusterID`, `SetOnEventDrop`, `sendEvent`) — `manager.go`.
- `electRG`, `runElection`, `electSingleNode`, `EffectivePriority`,
  `SetMonitorWeight`, `recalcWeight` — `election.go`.
- `StartHeartbeat`, `StopHeartbeat`, `RestartHeartbeat`,
  `buildHeartbeat`, `handlePeerHeartbeat`, `handlePeerTimeout`,
  `handlePeerNeverSeen`, `HeartbeatStats`,
  `vrfListenConfig` — `heartbeat_manager.go`.
- `HeartbeatPacket`, `MarshalHeartbeat`,
  `UnmarshalHeartbeat`, sender/receiver goroutine types — `heartbeat.go`.
- Single-RG manual failover and transfer-commit protocol
  (`ManualFailover`, `ForceSecondary`, `ResetFailover`,
  `RequestPeerFailover`, `commitRequestedPeerFailover`,
  `abortRequestedPeerFailover`, `notePeerTransferCommitted`,
  `FinalizePeerTransferOut`, `FenceStatus`), the batch variants
  (`ManualFailoverBatch`, `RequestPeerFailoverBatch`,
  `FinalizePeerTransferOutBatch`, etc.), and all transfer-commit
  state machine `*Locked` helpers
  (`applyPeerTransferOutOverrideLocked`,
  `clearPeerTransferOutOverrideLocked`,
  `restorePeerTransferOutOverrideLocked`,
  `transferCommitGracePeriodLocked`,
  `suppressPeerTimeoutForTransferCommitLocked`,
  `applyTransferCommitOverridesOnPeerStateLocked`) — `failover.go`.
  Co-locating the entire manual-failover locking domain in one
  file keeps the "committed-failover-suppresses-stale-heartbeat"
  invariant answerable by reading one file end-to-end.
- Readiness gate (`SetRGReady`) — `readiness.go`.
- Group-state accessors (`UpdateConfig`, `GroupStates`,
  `DataGroupIDs`, `GroupState`, `IsLocalPrimary`,
  `IsLocalPrimaryAny`, `LocalPriorities`) — `group_state.go`.
- Peer-state accessors (`PeerAlive`, `PeerNodeID`,
  `PeerGroupStates`, software/HA-protocol version,
  `PeerMonitorStatuses`) — `peer_state.go`.
- Sync state (`SetSyncReady`, `IsSyncReady`,
  `SetSyncTransport`, `SyncTransport`, `SetSyncStats`,
  `GetSyncStats`, `IsSyncConnected`) — `sync_state.go`.
- Hooks (`SetPreManualFailoverHook`,
  `SetTransferReadinessFunc`,
  `SetLocalTransferCommitReadyHook`,
  `SetPeerFailoverFunc`, `SetPeerFailoverCommitFunc`,
  `SetPeerFailoverBatchFunc`,
  `SetPeerFailoverCommitBatchFunc`, `SetPeerFenceFunc`,
  `SetPeerTimeoutGuard`) — `hooks.go`.
- Event-history methods (`RecordEvent`, `EventHistoryFor`) —
  `events_log.go`. Underlying types and `EventHistory` ring
  buffer — `events.go`.
- Status formatting (`FormatStatus`, `FormatInformation`,
  `FormatStatistics`, `FormatControlPlaneStatistics`,
  `FormatDataPlaneStatistics`, `FormatDataPlaneInterfaces`,
  `FormatIPMonitoringStatus`, `FormatInterfaces`,
  `InterfaceMonitorInfo`, `RethInfo`, `InterfacesInput`) —
  `status.go`.
- `triggerGARP` (no-op/log hook today — native VRRP owns GARP),
  plus the gratuitous-ARP burst sender — `garp.go`.
- `SessionSync` — `sync.go`, `sync_conn.go`, `sync_bulk.go`, `runtime.go`. HA
  session replication. After #1518, `NewSessionSync`, `NewDualSessionSync`,
  and `SetRuntime` accept the narrow `clusterRuntime` (see `runtime.go`) —
  `Sessions() dataplane.SessionStore` plus `Telemetry() dataplane.Telemetry`.
  Both the legacy `*dataplane.Manager` and the userspace
  `LegacyDataPlaneAdapter` satisfy `clusterRuntime` directly. The deprecated
  `SetDataPlane(dataplane.DataPlane)` setter is retained one release cycle
  for any out-of-tree caller and routes through the same
  `SessionStoreOf`/`TelemetryOf` adapters. The receive, sweep, bulk export,
  and stale-reconcile paths must stay on those runtime-domain interfaces.

The primary consumer of the `Manager.Events()` channel is
`pkg/daemon/daemon_ha.go`, which fans events out (HA sync, status
publish, etc.). `pkg/cluster/reth.go::HandleStateChange` is a
state-handler method, not the event-channel consumer.

## Interface-monitor link-state detection

`Monitor` (`monitor.go`) is the live carrier-detection loop: a 1-second
ticker polls each configured `interface-monitor`, dampens transitions,
and calls `SetMonitorWeight` so a redundancy group is demoted when a
monitored uplink goes down. The whole point of interface-monitoring is to
catch carrier loss (cable pulled / peer link down) and fail over.

Link health is therefore decided from the kernel **operational** state
(`IFLA_OPERSTATE`) via the exported `LinkAttrsUp`, **not** the
administrative `IFF_UP` flag. xpfd admin-ups every managed interface, so
`IFF_UP` is the normal steady state and stays set even after carrier loss
— using it (or OR-ing it in) would report a cable-pulled link as UP and
suppress failover (#2070). The rule is: `OperUp` → up; `OperUnknown` →
fall back to the admin flag (virtual devices and 802.1Q VLAN
sub-interfaces that report no independent carrier state); `OperDown` /
`OperLowerLayerDown` / anything else → down. This mirrors
`pkg/vrrp.linkAttrsUp`, the canonical link-state read used by VRRP
track-interface detection. `pkg/routing/monitor.go` (the display-side
`InterfaceMonitorStatus` path) carries its own identical copy.

`LinkAttrsUp` is exported because the same carrier-aware read is needed
outside the monitor loop:

- `RethController.FormatStatus` (`reth.go`) and the reth-status displays
  for `show chassis cluster interfaces` — both the gRPC/remote-CLI path
  (`pkg/grpcapi`) and the local interactive CLI path (`pkg/cli`) — so a
  cable-pulled-but-admin-up RETH member shows `down`/`Down`, not
  `up`/`Up`, and the two display paths stay in agreement.
- The daemon no-reth-vrrp / private-rg-election VIP-readiness gate
  (`pkg/daemon.checkVIPReadinessForConfig`, #2090) — so a node is not
  judged ready to take over VIPs on an interface whose carrier is down
  (the #2070 hazard, surfacing on the VIP-takeover path).

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`, `pkg/vrrp`.

## Dependencies

`config`, `dataplane`.

## Failover timing (CLAUDE.md authoritative)

- ~60 ms with default 30 ms VRRP advertisements (masterDownInterval ~97 ms).
- Planned shutdown: burst of 3× priority-0 advertisements; peer takes over
  in ~1 ms.
- Failback: ~130 ms (daemon startup + BPF load + sync hold release).
- Heartbeat: 200 ms interval, threshold 5 (1 s detection).
- Event debounce 500 ms before priority updates fire.

## Gotchas

- `Ready` and `TransferReady` are different gates. `Ready` allows VRRP to
  participate in election; `TransferReady` is the stricter gate for
  explicit operator-initiated `request chassis cluster failover`.
- `TakeoverHoldTime` adds extra delay before election when this node would
  immediately preempt. Used to avoid election thrash on simultaneous boot.
- HA delete-sync callbacks fire from the GC loop. They must not block, and
  must log at `slog.Debug` — earlier `slog.Info` flooded at 15 req/s and
  drowned out real diagnostics (per CLAUDE.md logging rules).
- The incremental sync sweep (`sync_conn.go`) re-syncs a session ONLY on
  `val.Created >= threshold` — it deliberately does NOT re-publish an
  established flow on `LastSeen` activity (#270 narrowed this; #131's
  `|| val.LastSeen >= threshold` clause was removed on purpose to keep the
  empty-sweep back-off and avoid >1/s control-socket contention). Standby
  retention of long-lived synced sessions is NOT the sweep's job — it is
  owned by the userspace Rust timer wheel's standby gate (#2120,
  `userspace-dp/src/session/expire.rs`): the standby HOLDS a peer-synced
  session for an RG it does not forward instead of aging it. Do NOT
  "restore the LastSeen re-sync" to fix a failover-retention bug — that
  re-introduces the per-second control-socket hammer #270 removed; the fix
  belongs in the wheel. The sweep narrowing is intentional and must stay.
- Session-sync key-only delete messages use `SessionStore.DeleteWithCompanions*`.
  Bulk stale reconciliation must use the known-value batch delete path through
  `SessionStore.ReconcileClusterBulk`, which deletes with the iterator's
  `(key,value)` snapshot. Reverse-session, DNAT/DNATv6, and persistent-NAT
  side effects are backend-owned; do not add local map cleanup in
  `pkg/cluster`.
- **Install-generation delete guard (#2170)**: every session install and every
  delete carries a per-`(sender,key)` monotonic install generation as a
  length-gated trailing `uint64` (see `docs/sync-protocol.md`). The sender
  (`sync_conn.go`/`sync_bulk.go`) stamps installs from a single boot-seeded
  counter and the matching delete **echoes** the install generation it cancels
  (so the comparison is always same-domain, even across an ownership change).
  The receiver keeps the authoritative per-key stored generation in
  `SessionSync.recvGenV4/V6` (the BPF C struct stays generation-free) and the
  apply layer refuses a delete whose generation is **strictly older** than the
  stored entry (`deleteClusterSynced*`, `DeletesStaleIgnored`) and refuses an
  install that would regress the stored generation (`installClusterSynced*`,
  `InstallsStaleIgnored`). Equality applies; `gen == 0` on either side falls
  back to today's unconditional behavior (rolling-upgrade safe). This stops a
  journaled/deferred delete for a closed flow from killing a same-5-tuple
  replacement that was re-synced with a newer generation. Do NOT reuse the
  synthesized `SessionID` for this — it is non-monotonic
  (`now_seconds<<16|slot`) and collides on same-second/same-slot reuse.
  The generation maps are bounded by `genGuardMapCap` (200000); on overflow
  the map is NEVER cleared (#2198 F1) — an existing key updates in place, a new
  key skip-records (degrades to safe gen-0) and bumps `GenMapOverflow`.
- Dual-active overlap is intentional: primary sets `rg_active=true`
  immediately on becoming master; secondary defers `rg_active=false` until
  it sees the VRRP BACKUP event. Brief overlap, never both inactive.
- `handlePeerTimeout` runs its peer-timeout guard (`peerTimeoutGuardFn`) with
  `m.mu` released, so the receiver read path can run `handlePeerHeartbeat`
  during the call for ANY guard duration (a configured slow guard only widens
  the window). After the guard it re-checks heartbeat STALENESS via
  `peerHeartbeatFreshLocked`, not just `peerAlive` (#2080): a heartbeat that
  lands during the guard window keeps `peerAlive` true but is a fresh
  heartbeat, so the only correct post-guard question is "is the heartbeat
  fresh again?". `peerHeartbeatFreshLocked`
  re-reads the receiver's `lastSeen` against the live monotonic clock (test
  seam: `peerHeartbeatFreshFn`); a fresh heartbeat aborts the peer-lost
  transition and prevents spurious failover churn. A nil receiver / unset seam
  reports not-fresh, so the no-receiver call paths behave exactly as before the
  re-check existed.
