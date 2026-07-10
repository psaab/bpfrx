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
  `UnmarshalHeartbeat`, the #4107 control-channel auth
  (`MarshalHeartbeatAuth`, `heartbeatAuthTrailer`,
  `verifyHeartbeatMAC`, `heartbeatAuthReplay`,
  `heartbeatAuthDecision`), sender/receiver goroutine types —
  `heartbeat.go`. See "Control-channel authentication" below.
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
  plus the gratuitous-ARP / unsolicited-NA burst senders — `garp.go`.
  `SendGratuitousARPBurst` / `SendGratuitousIPv6Burst` send the first
  frame synchronously (error returned to the caller) and the remaining
  follow-up frames at 50ms intervals in a background goroutine. The
  follow-up sends are the failover-convergence reliability mechanism, so
  their send errors are NOT dropped: each failed follow-up frame bumps the
  package-level `burstSendErrors` counter (exported via `BurstSendErrors()`
  for observability) and is logged at Debug; a single Warn fires after the
  burst if any frame failed. The loop never aborts on a transient SEND error
  (#2623). The burst remains non-blocking and the #2081/#2082 epoch +
  dampener storm-control gates live in `pkg/vrrp`, untouched by this.
  The follow-up loop DOES abort cleanly — before any further frame — on
  abdication: `SendGratuitousARPBurstGated` / `SendGratuitousIPv6BurstGated`
  take a `BurstStillValid func() bool` predicate, captured at burst start and
  checked before EVERY follow-up frame; `pkg/vrrp.sendGARP` passes a closure
  that returns true only while the node is still master AND `garpEpoch` is
  unchanged (#2867). When it returns false the loop stops, so a node that
  loses master (or whose burst is superseded by a newer epoch) mid-burst stops
  re-poisoning neighbor caches for VIPs it no longer owns. The original
  `SendGratuitousARPBurst` / `SendGratuitousIPv6Burst` are thin wrappers that
  pass a nil predicate (ungated, run-to-completion) for callers with no
  per-instance epoch/state to gate against (direct-mode re-announce, tests).
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

## Peer-liveness cold-boot grace (#4386)

`heartbeatReceiver.checkTimeout` (`heartbeat.go`) makes both peer-liveness
decisions, and both are gated behind a single cold-boot floor,
`heartbeatStartupGrace` (30s). For that window after a receiver starts, the
local config apply phase — VRF binding, FRR reload, fabric creation, RETH MAC
down/up — can disrupt the control-link UDP receive path for 10-15+ seconds:

- **Seen-then-lost** (`lastSeen != 0`): peer-lost is suppressed entirely inside
  the grace, so a recovering node does not declare a still-live peer dead on
  the first dropped heartbeat. After the grace, staleness (`heartbeatStale`,
  `threshold*interval`) drives `handlePeerTimeout`.
- **Never-seen-at-boot** (`lastSeen == 0`): single-node promotion is held
  behind the SAME floor via `neverSeenConfirmed(sinceStart, grace)`. Deciding a
  peer NEVER EXISTED is different from a peer that WAS seen then went silent —
  on a **simultaneous cold boot** the first heartbeats from a live peer are
  dropped and `lastSeen` stays 0 on BOTH nodes. Promoting at
  `threshold*interval` (~500ms) would then make BOTH claim primary and the RETH
  virtual MAC — a 10-15s split-brain until the link recovers and dual-active
  resolution demotes one. The floor lets a slow-to-appear peer be heard first.

The floor DELAYS the never-seen decision; it never blocks it. A genuinely
absent peer — a single-node deployment, or a peer that will never come up —
still promotes once the grace elapses (`neverSeenConfirmed` returns true at
`sinceStart >= grace`), so there is no permanent no-master. `handlePeerNeverSeen`
sets `peerEverSeen` and runs `electSingleNode`; `election.go` bypasses the
readiness gate when `!peerAlive`, so the surviving node takes over.

## Duplicate node-id (invalid cluster, #4549 F11)

Two chassis sharing a node-id is an invalid cluster: the HA protocol
carries no per-node identity besides the node-id, so election has **no
asymmetric discriminator** to elect a single primary — both nodes run the
identical `electRG` code and compute the identical result. There is no
correct runtime resolution; the only remedy is correcting
`/etc/xpf/node-id` on one chassis.

Two defenses, both fail-safe rather than manufacturing a false winner:

- **Join point (`heartbeatReceiver.recvLoop`, `heartbeat.go`).** On a
  unicast point-to-point control link a node never receives its own
  frame, so a same-cluster heartbeat carrying the local node-id is a
  duplicate-node-id peer, not a loopback. The receiver still discards it
  (it cannot be told apart from a stray loopback, and a duplicate-node-id
  cluster is unresolvable), but calls `NoteDuplicateNodeIDHeartbeat` to
  emit a rate-limited (`>=30s`) `slog.Error` so the operator sees the
  misconfiguration instead of a silent split-brain. Because the frame is
  discarded, `peerAlive`/`peerNodeID` never reflect the duplicate peer, so
  in production both nodes run `electSingleNode` and would otherwise both
  claim PRIMARY — the warning is the operator-facing signal that this is
  happening.

- **Election tie-break (`electRG`, `election.go`).** If a same-node-id
  peer ever does reach election (the direct API / tests, or any future
  path that does not go through `recvLoop`), the dual-active tie, the
  preempt tie, and the initial-state tie all detect
  `m.nodeID == m.peerNodeID` and **fail closed to SECONDARY** (via
  `warnDuplicateNodeIDLocked`). Before the fix the dual-active and preempt
  ties returned "winner stays"/"no change", leaving both symmetric nodes
  PRIMARY (a permanent dual-primary split-brain — duplicate VIP / ARP
  conflict). Yielding both nodes to SECONDARY produces a clean, obvious,
  loudly-logged outage instead of subtle duplicate-address corruption.

## Control-channel authentication (#4107, PR-A)

The cluster heartbeat drives election: `handlePeerHeartbeat` rebuilds
peer redundancy-group state directly from the packet and runs
`runElection()`, so a forged cleartext heartbeat can force the local
node PRIMARY or demote the peer (Weight=0 → local claims PRIMARY;
higher priority → local forced SECONDARY). The heartbeat is UDP on the
shared control VLAN, so any host that can reach the peer's control IP
could inject one.

**Fix (first authed channel).** When a shared PSK is configured
(`set chassis cluster authentication-key <key>` → `config.Secret`
`ClusterConfig.ControlLinkAuthKey`, plumbed into the `Manager` by
`UpdateConfig` and read via `controlLinkAuthKey()`), the sender appends
an HMAC-SHA256 auth trailer to the heartbeat frame and the receiver
rejects a forged/tampered/replayed heartbeat **before** it can refresh
peer liveness (`lastSeen`) or drive election.

- **Wire.** `MarshalHeartbeatAuth` appends a fixed 52-byte trailer
  AFTER the optional version trailer: `magic "XPFA"(4) + session(8) +
  counter(8) + HMAC-SHA256(32)`. The HMAC covers the whole frame plus
  the magic/session/counter (everything but the digest). Because
  `UnmarshalHeartbeat` already ignores bytes past the version section,
  a signed frame stays wire-parseable by a legacy / not-yet-keyed peer
  — the same additive-trailer discipline as the version trailer.
  **Never-unsigned-when-keyed invariant:** `MarshalHeartbeatAuth`
  reserves the 52-byte trailer up front via
  `marshalHeartbeatBody(pkt, heartbeatAuthTrailerSize)`, which truncates
  the best-effort monitor section (never the election-critical header /
  RG groups) to make room. So once a key is configured a heartbeat is
  ALWAYS signed — never silently downgraded to unsigned, which an
  enforcing peer would reject and split the cluster (dual-primary). The
  overflow guard is unreachable at the uint8-bounded RG count and fails
  LOUD (`slog.Error`) rather than emitting cleartext.
- **Anti-replay.** `session` is a random per-sender-process id and
  `counter` a monotonic per-session counter. `heartbeatAuthReplay.admit`
  accepts a strictly increasing counter within a session and RE-ANCHORS
  on a new session id, so a sender restart/reboot (a routine HA event —
  `make test-failover` reboots a node) is never mistaken for a replay.
  Intra-session replays are rejected. Cross-session stale replay is a
  bounded residual (a captured old frame carries stale state that the
  next genuine heartbeat overwrites within one interval); tightening it
  belongs to the follow-up channels.
- **Dual-accept (rolling upgrade), `heartbeatAuthDecision`.** Mirrors
  the #4126 VRRP-checksum dual-accept migration:
  - No local key → accept everything (this node cannot verify; may be
    the not-yet-keyed side of an upgrade). No regression.
  - Local key + auth trailer → enforce: reject a bad HMAC or a replayed
    nonce.
  - Local key + no trailer + peer has NOT yet authenticated → accept
    (the peer has not started signing; key not yet synced).
  - Local key + no trailer + peer HAS authenticated (sticky
    `peerAuthSeen`, set only by a verified frame) → reject: a downgrade
    to cleartext once both nodes are keyed is an attack.

  Enforcement therefore engages only once BOTH nodes carry the key and
  are observed signing — a mixed-version / mid-key-rollout cluster never
  splits.
- **Operator surface (#4484 L-9).** `FormatControlPlaneStatistics`
  (`show chassis cluster control-plane-statistics`) renders an
  `Authentication:` line derived from `controlLinkAuthStatus()`, so an
  operator can tell whether the control link's HMAC auth is actually
  **engaged** (`engaged (peer authenticated; unauthenticated frames
  rejected)` — both nodes keyed and signing) or running in
  **dual-accept** grace (`dual-accept (no control-link key configured)`
  or `dual-accept (key configured; peer not yet authenticated)`). It is
  computed from the SAME two facts the auth gates use —
  `ControlLinkAuthKey` presence + `HeartbeatPeerAuthSeen` — so the line
  tracks the real enforcement decision, and it inspects only `len(key)`
  so the secret is never rendered. Before this line, a control link
  silently degraded to dual-accept (e.g. a peer that stopped signing)
  was invisible.
- **Secret hygiene.** The key is `config.Secret`, redacted on every
  JSON/YAML/`String()` path and masked as `##SECRET-DATA##` in raw-AST
  renders (`authentication-key` is already in `ast_redact.go`'s secret
  set). It is stored as raw bytes on the `Manager`, never logged; the
  auth-reject log line carries only a reason string and the peer node id.

**Scope.** PR-A authenticates the heartbeat/election channel. PR-B (this
work) extends the SAME PSK to the **fabric gRPC listener**
(`pkg/grpcapi/fabric_auth.go`): the `Manager.ControlLinkAuthKey()`
accessor exposes the raw key to `pkg/grpcapi`, which HMAC-authenticates
every peer-proxied RPC with a time-windowed bearer token on top of the
#4122 allowlist (see `docs/architecture.md` "Cluster fabric gRPC
listener" and the F1 half of #4107). The fabric path reuses this
package's dual-accept posture (`fabricAuthDecision` mirrors
`heartbeatAuthDecision`).

The fabric downgrade-guard arms off the heartbeat, not just the fabric
channel. This package exposes `Manager.HeartbeatPeerAuthSeen()` — true
once the receiver accepts a valid authed heartbeat from the peer (the
sticky `heartbeatReceiver.peerAuthSeen`, now an `atomic.Bool` because it
is read cross-goroutine). The gRPC interceptor rejects a tokenless fabric
call when EITHER a prior valid fabric token OR the heartbeat has armed
enforcement. Rationale: nothing periodically dials the fabric listener,
so arming only off an on-demand fabric RPC would leave a window after
EVERY restart of a keyed node — until the next cross-node command — where
any on-segment host could drive tokenless `ClearSessions` / cross-node
failover. Heartbeats flow every ~200ms, so arming off them closes that
window to one interval. Dual-accept is preserved: a not-yet-keyed peer
signs neither channel, so neither source arms during a rolling upgrade.
Two residuals are accepted, not bugs: (1) the ~1-window token replay
horizon (removed only by mTLS with per-node certs, deferred with #4047);
(2) a wall-clock skew > the ±1-window tolerance (~60–90s) fails cross-node
fabric RPCs `Unauthenticated` until corrected — a > 30s inter-node skew is
an operational NTP fault (NTP is already a cluster prerequisite for
heartbeat clock-sync and session-timestamp rebasing).

**Session-sync stream auth (F23, done — `sync_auth.go`).** The
**session-sync stream** frames (`sync.go` / `sync_conn.go` /
`sync_protocol.go`) are now authenticated with the SAME control-link PSK.
The heartbeat's trailing-HMAC does NOT work here: the stream is
length-framed, so a legacy reader would mis-frame an appended HMAC as the
next header. F23 instead uses an auth **capability handshake at connection
setup** that negotiates — BEFORE any session frame flows — whether the
connection is authenticated, then seals every subsequent frame.

- **Handshake (`performSyncHandshake`).** Only a node that holds the PSK
  initiates it. Each keyed side sends a HELLO (`syncMsgAuthHello`, type 27)
  advertising a fresh 32-byte challenge nonce; when BOTH peers are keyed
  each proves possession with `syncMsgAuthProof` (type 28) =
  `HMAC-SHA256(key, tag ‖ peer-nonce)` (mutual challenge-response). Fresh
  per-connection nonces make the proof replay-safe at setup. HELLO/PROOF
  are written CONCURRENTLY with reading the peer's frame so the handshake
  does not deadlock on a fully-synchronous transport (`net.Pipe` in tests /
  a strict write-then-read on two symmetric peers). Types 27/28 sit above
  the legacy set so an old peer ignores them (default receive case).
- **Per-frame seal (`authConn.sealFrame` / `verifyFrame`).** On an
  AUTHENTICATED connection every frame gets an 8-byte per-connection
  monotonic sequence + a 32-byte HMAC keyed by a per-connection key derived
  from the PSK and BOTH handshake nonces (`syncDeriveFrameKey`, canonical
  nonce order so both peers derive the same key). The receiver rejects a bad
  HMAC (forgery/tamper) or a non-increasing sequence (replay/regression) and
  drops the connection. `writeFull` is the single chokepoint that seals (all
  writers hold `s.writeMu`, so sequence order equals wire order);
  `receiveLoop` is the single reader that strips + verifies the trailer.
  Chose a signed per-frame trailer over a bare sequence because a sequence
  without a MAC is forgeable (an on-path attacker just uses seq+1); the MAC
  cost is negligible at realistic session-sync rates.
- **Dual-accept (rolling upgrade).** A node with no key never handshakes
  and is byte-for-byte a legacy peer; a keyed node that sees a
  legacy/unkeyed peer (no HELLO, or `keyed=0`) negotiates
  UNAUTHENTICATED — the stream stays legacy-compatible (no brick). The
  legacy peer's first real frame, consumed by the handshake read, is
  preserved as a `pendingFrame` and processed before the receive loop
  starts. Enforcement engages only once BOTH nodes are keyed and signing.
- **Downgrade-guard (`syncAuthDecision`, mirrors `heartbeatAuthDecision`).**
  Once the peer has authenticated on the sync channel (sticky
  `syncAuthedEver`) OR the heartbeat channel (`HeartbeatPeerAuthSeen`, arms
  within ~200ms of a keyed peer coming up), a later UNAUTHENTICATED
  connection from it is REJECTED — a downgrade to cleartext once both nodes
  are known-keyed is an attack. Consulting the heartbeat closes the window
  after a keyed node restarts before the first sync auth.
- **Wiring.** `SessionSync.SetAuthProvider(*Manager)` (`daemon_ha_sync.go`)
  supplies both `ControlLinkAuthKey()` and `HeartbeatPeerAuthSeen()`. No new
  config leaf — the same `set chassis cluster authentication-key` secret
  authenticates the heartbeat (PR-A), the fabric gRPC (PR-B/#4357), and now
  the session-sync stream. LOW severity (matches Juniper's own
  unauthenticated direct-cable control-link posture); the acute HIGH lever
  (the full-service fabric gRPC surface) was closed by #4357.
- **Failover.** The handshake happens at connect and a reconnect during
  failover re-handshakes; a keyed↔keyed reconnect completes in
  milliseconds. A dropped handshake closes the connection and the
  accept/connect loops retry (~1s) — it never bricks. MUST pass
  `make test-failover` (the path that keeps TCP alive across failover).
- **Accept-loop isolation + short bound (#4370).** The inbound
  `acceptLoop` runs each connection's setup (handshake + wire-up +
  cold-start bulk sync, inside `handleNewConnection`) in a
  per-connection goroutine — a slow or hung handshake on ONE connection
  can no longer stall accepting the NEXT for up to `syncHandshakeTimeout`
  (previously an active control-link peer could serially block accepts).
  The auth gate is unchanged: the connection is not wired into
  `conn0`/`conn1` and no session frame is read from it until
  `performSyncHandshake` succeeds INSIDE the goroutine; a failed
  handshake closes it. The goroutine is `s.wg`-tracked so `Stop()` waits
  for in-flight setup. The outbound `fabricConnectLoop` stays synchronous
  (a dedicated per-fabric dialer that must not redial mid-handling).
  `syncHandshakeTimeout` is **3s** (was 10s): the keyed↔keyed path is
  sub-millisecond, so the bound only covers a hung/absent peer, and a
  shorter bound keeps a stalled handshake goroutine within the 5s `Stop`
  budget.

## IPsec SA sync

Active IKE/child-SA connection names ride the session-sync channel so the
standby can re-initiate the primary's tunnels on takeover:

- **Send** — `syncIPsecSAPeriodic` (`pkg/daemon/daemon_ha.go`) runs on the
  RG0-primary and, every 30s, reads the active set from
  `ipsec.ActiveConnectionNames()` (live `swanctl --list-sas`) and advertises it
  via `SessionSync.QueueIPsecSA` (wire type `syncMsgIPsecSA`,
  `encode/decodeIPsecSAPayload`).
- **Hold** — the standby stores the peer's set wholesale in `peerIPsecSAs`
  (`sync_conn.go` overwrites, not merges), readable via `PeerIPsecSAs()`.
- **Re-initiate on takeover** — `reinitiateIPsecSAs` reads `PeerIPsecSAs()` and
  `InitiateConnection`s each name when this node becomes RG0-primary.
- **Empty-set / tunnel-down handling (#4385)** — a NON-EMPTY set is advertised
  every tick (a heartbeat re-push — the only mechanism that seeds a freshly
  reconnected/restarted standby, so it must keep pushing even when unchanged).
  An EMPTY set is advertised exactly ONCE, on the drop-to-zero transition from a
  previously non-empty set — a tunnel was administratively downed or all its SAs
  were torn down — so the standby CLEARS its stale `peerIPsecSAs` instead of
  resurrecting the tunnel on takeover. A steady empty set, INCLUDING a node that
  never brought an SA up, is never advertised (no empty-heartbeat churn; the
  standby's default set is already empty). The decision is
  `ipsecSASyncAdvertise` (goroutine-local `lastFP` fingerprint, empty string =
  last advertised set was empty / nothing advertised yet). Before #4385 the push
  was guarded by `if len(names) > 0`, so a drop-to-zero was never advertised and
  the standby resurrected the downed tunnel on failover. Mirrors the DHCP
  `maybePushFamily` change-detect precedent below.
- **Reconnect robustness (#4385)** — the one-shot empty push must survive a
  disconnect gap, so two guards back it:
  - **Confirmed-send retry.** `QueueIPsecSA` returns whether the frame reached an
    ACTIVE conn; `ipsecSANextFP` advances `lastFP` ONLY on a confirmed send. An
    empty advertisement that no-ops on a nil/dropped conn (a drop-to-zero landing
    during a reconnect gap) leaves `lastFP` non-empty, so it RETRIES next tick
    instead of being silently marked sent — without this, `lastFP` would advance
    to empty and the empty would never be re-advertised, stranding the standby's
    stale set.
  - **Peer-connect re-advertise.** `OnPeerConnected` nudges `ipsecSANudgeCh`
    (`nudgeIPsecSASync`), and `syncIPsecSAPeriodic` handles it with a FORCED
    advertise (`advertiseIPsecSAOnce(force=true)` -> `ipsecSASyncAdvertise` force
    branch) of the current set, empty or not. A reconnected standby that missed
    the one-shot empty, or a same-process standby that retained its peer set
    across a blip, converges immediately (empty -> clears; non-empty ->
    re-seeds) rather than waiting up to the 30s tick. Mirrors the DHCP
    peer-connect `nudgeDHCPLeaseSync` (#2239 Q7).

  Note: `peerIPsecSAs` is deliberately NOT cleared on disconnect — a real
  primary death (the standby never reconnects) must leave the last-known set in
  place for `reinitiateIPsecSAs` to re-initiate on takeover. Convergence to an
  empty/updated set is driven by the primary re-advertising, not by the standby
  self-clearing.

## DHCP-server lease sync (#2239)

DHCP-server (Kea) leases ride the SAME session-sync channel and follow the
IPsec-SA-sync precedent (`QueueIPsecSA` / `peerIPsecSAs` /
`reinitiateIPsecSAs`), not the Kea native HA hook and not a shared DB. The
mechanism (PATH C of `docs/research/2239-dhcp-ha-lease-sync/plan.md`):

- **Wire** — two additive message types `syncMsgDHCPLeaseV4 = 25` /
  `syncMsgDHCPLeaseV6 = 26` carry a full-set push of the active leases the
  sender serves for a family. `encode/decodeDHCPLeasePayload` (`sync_protocol.go`)
  frame a 4-byte count + length-prefixed, length-GATED per-lease records
  (the #2170 trailing-field discipline: a newer peer's extra fields are
  ignored, a legacy/truncated record zero-fills absent fields, a
  short stream stops at the last complete record). The types are above the
  legacy set so a peer that predates the feature hits the `default` receive
  case and ignores them — no `CurrentHAProtocolVersion` bump (the change is
  additive AND config-knob-gated, so bumping would falsely block session sync
  across a mixed-base pair).
- **Clock invariant** — each lease carries REMAINING LIFETIME, never an
  absolute wall-clock expiry (the channel only syncs a MONOTONIC offset). The
  promoting node re-anchors to its LOCAL clock at seed (`expire = now + remaining`),
  so peer wall-clock skew can never mis-age a synced lease — the structural
  fix for the <60s hazard the Kea native HA hook inherits.
- **Send** — `SessionSync.QueueDHCPLeases(family, leases)` (`sync.go`), driven
  by the RG-MASTER push loop in `pkg/daemon/daemon_dhcp_lease_sync.go`
  (`syncDHCPLeasesPeriodic`): a 30s full-set heartbeat (so a restarted standby
  is never empty) + a 2s on-grant change-detect (push only when the set
  changed, bounding the duplicate-allocation window). Fail-open: a send error
  is logged + counted, never blocks lease granting.
- **Hold** — the BACKUP stores the peer's set in `peerDHCPLeases{4,6}` (the
  `peerIPsecSAs` precedent), accessible via `PeerDHCPLeases{4,6}()`. Its Kea
  stays STOPPED (`clearRethServicesForRG` is UNCHANGED) — VRRP/RG remains the
  sole who-serves arbiter.
- **Seed on takeover** — `pkg/daemon` pre-seeds the held leases into the Kea
  memfile BEFORE Kea start (fully closes the dup-alloc window) AND
  `lease{4,6}-add`s them over the Kea control socket after start (idempotent
  backstop, `RecordDHCPLeasesSeeded`). The Kea read/write side lives in
  `pkg/dhcpserver/lease_sync.go`.
- **Observability** — `SyncStats.DHCPLeases{Sent,Received,Seeded}` surfaced in
  `show chassis cluster statistics` (`status.go`).

Gated end-to-end on `set chassis cluster dhcp-lease-synchronization`
(`config.ClusterConfig.DHCPLeaseSync`); standalone / knob-off renders the Kea
config bit-identical to pre-#2239 (no control-socket, no hook).

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
- **Removing an RG must stop its armed hold timer (#5245).** `SetRGReady`
  arms a per-RG `time.AfterFunc` takeover-hold timer whose closure captures
  the `*RedundancyGroupState` and re-runs election on expiry. `UpdateConfig`'s
  removal loop `Stop()`s and nils `rg.holdTimer` before `delete(m.groups, id)`
  — mirroring the `readiness.go` not-ready clear site and `Stop()`. Without
  this the closure keeps the removed group alive and still fires, running an
  election against removed state. Belt-and-suspenders: the closure also
  re-checks `m.groups[rgID] == rg` after taking `m.mu` (a timer that had
  already fired can race the teardown, since `AfterFunc.Stop()` does not
  cancel an in-flight callback) and no-ops if the group is gone or replaced.
- **`ManualFailover`/`ManualFailoverBatch` release `m.mu` for the pre-failover
  hook — a racing `ResetFailover` must not be clobbered (#5246).** Both take
  `m.mu`, mark `failoverInProgress`, then unlock to run the retryable pre-hook
  (which may sleep up to the retry timeout), re-lock, and write
  `State=SecondaryHold`. A `ResetFailover` in that unlocked window clears the
  failover and re-elects, but the trailing SecondaryHold write would silently
  overwrite it. Fix: a per-RG `failoverGen` counter — `ResetFailover` bumps it;
  the failover path snapshots it before unlocking and abandons its trailing
  write (single-RG returns nil; batch skips that member) if it changed. Keep
  `failoverInProgress` cleaned up on every exit path so a superseded failover
  cannot wedge the next one.
- HA delete-sync callbacks fire from the GC loop. They must not block, and
  must log at `slog.Debug` — earlier `slog.Info` flooded at 15 req/s and
  drowned out real diagnostics (per CLAUDE.md logging rules).
- **`Manager.Start` must NOT hold `m.mu` across the monitor's `Stop()` (#4828).**
  The `Monitor` poll goroutine calls back into `SetMonitorWeight`, which takes
  `m.mu`; `Stop()` joins that goroutine via `wg.Wait()`. Holding `m.mu` while
  waiting for the goroutine to exit is an AB-BA deadlock (any config reload
  racing a monitor state-change permanently freezes the manager). `Start`
  therefore serializes on a dedicated `monStartMu`, takes `m.mu` ONLY to swap
  the `m.monitor` pointer, then runs the old `Stop()` / new `Start()` outside
  `m.mu`. This mirrors the `hbStartMu` discipline `StartHeartbeat` uses for the
  same reason (#4033). Any future method that both takes `m.mu` and joins a
  goroutine that re-enters the manager must follow the same split.
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
- **Install-generation delete guard (#2170, #2221)**: every session install and
  every delete carries a per-`(sender,key)` monotonic install generation as a
  length-gated trailing `uint64` (see `docs/sync-protocol.md`). The sender
  (`sync_conn.go`/`sync_bulk.go`) stamps installs from a single boot-seeded
  counter. A delete draws a **fresh, strictly-greater** generation
  (`takeDeleteGenV4/V6` → `nextInstallGen`) rather than echoing the install's
  stamp, so a delete always out-ranks the install it cancels — this is what makes
  a reordered delete/install pair orderable (#2221). The comparison is always
  same-`(sender,key)`-domain, even across an ownership change.
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
  **#2221 (same-generation reorder residual):** an applied non-zero delete now
  records the delete generation as a **TOMBSTONE** in `recvGenV4/V6` (it does not
  evict). A reordered install of the very session that delete cancelled carries
  the OLDER install generation and is refused by the install guard, so the
  standby converges to the master's state (session GONE) regardless of
  install/delete arrival order; a genuinely newer incarnation (re-stamped by a
  later sweep) carries a higher generation and still installs (last-writer-wins).
  A `gen == 0` (legacy) delete still evicts. The generation maps are bounded by
  `genGuardMapCap` (200000); on overflow the map is NEVER cleared (#2198 F1) — an
  existing key updates in place, a new key skip-records (degrades to safe gen-0)
  and bumps `GenMapOverflow`. The receiver also RESETS `recvGenV4/V6` when the
  peer begins a bulk transfer (`resetRecvGen` from the `syncMsgBulkStart`
  handler, #2198 F2) so a rebooted peer — whose monotonic-seeded counter
  legitimately restarts lower — has its cold-start bulk re-prime accepted instead
  of refused as stale (the stale-RETAIN inverse of #2170), and so a delete
  tombstone never permanently blocks a legitimate cold re-prime. The
  check→Put→record apply sequence is not held under one `recvGenMu` acquisition;
  it is safe because the per-peer receive path is single-threaded over the single
  active fabric (#2198 F3).
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
