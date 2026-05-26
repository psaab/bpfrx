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
- Session-sync key-only delete messages use `SessionStore.DeleteWithCompanions*`.
  Bulk stale reconciliation must use the known-value batch delete path through
  `SessionStore.ReconcileClusterBulk`, which deletes with the iterator's
  `(key,value)` snapshot. Reverse-session, DNAT/DNATv6, and persistent-NAT
  side effects are backend-owned; do not add local map cleanup in
  `pkg/cluster`.
- Dual-active overlap is intentional: primary sets `rg_active=true`
  immediately on becoming master; secondary defers `rg_active=false` until
  it sees the VRRP BACKUP event. Brief overlap, never both inactive.
