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
  (`MarshalHeartbeatAuth`, `marshalHeartbeatAuthEpoch`,
  `heartbeatAuthTrailer`, `verifyHeartbeatMAC`, `heartbeatAuthReplay`,
  `heartbeatAuthState.admitAuthed`, `heartbeatAuthDecision`,
  `Manager.heartbeatNonce`), sender/receiver goroutine types —
  `heartbeat.go`. See "Control-channel authentication" below.
- The #6169 across-reboot boot epoch — wire section constants, the
  key-derived marker (`heartbeatEpochMarker`), the verified-frame reader
  (`heartbeatFrameEpoch`), the plausibility bound (`epochUsableAsFloor`),
  the wall-clock seed published synchronously (`Manager.heartbeatBootEpoch`,
  increasing while the clock advances — not monotonic across a backward step,
  residual 3) with its off-path, RE-RUNNABLE persistence refinement
  (`refineBootEpoch`, `withEpochFileLock`, `Manager.refreshBootEpoch`) and the
  start-time wiring (`Manager.initHeartbeatEpochState`) — `heartbeat_epoch.go`. The downgrade
  latch itself is process-scoped state on `heartbeatAuthState`; there is no
  peer-floor file.
- Single-RG manual failover and transfer-commit protocol
  (`ManualFailover`, `ForceSecondary`, `ResetFailover`,
  `RequestPeerFailover`, `commitRequestedPeerFailover`,
  `abortRequestedPeerFailover`, `notePeerTransferCommitted`,
  `FinalizePeerTransferOut`, `FenceStatus`), the batch variants
  (`ManualFailoverBatch`, `RequestPeerFailoverBatch`,
  `FinalizePeerTransferOutBatch`, etc.), the owner-side
  transfer-out lease (`ArmRemoteTransferOutLease`,
  `ClearRemoteTransferOutLease`,
  `SetRemoteTransferOutLeaseDuration`,
  `clearRemoteTransferOutLeaseLocked`,
  `manualFailoverRestoreWeightLocked`; see "Owner-side
  transfer-out lease" below), and all transfer-commit
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
- `SessionSync` — `sync.go`, `sync_conn.go` (connection lifecycle:
  dial/accept/install/start/stop/disconnect), `sync_conn_gen.go` (session
  generation guards + synced-session apply), `sync_conn_read.go`
  (receive/dispatch), `sync_conn_write.go` (send/queue/delete-journal),
  `sync_conn_sweep.go` (incremental sync sweep), `sync_conn_config.go`
  (config replication), `sync_bulk.go`, `runtime.go`. HA
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

## Session-sync fail-closed authentication (#5078)

The session-sync TCP stream (`sync_auth.go`) authenticates with the SAME
control-link PSK. Until #5078, a node that HAD a key still **dual-accepted** an
unkeyed or legacy peer on first contact: `syncAuthDecision` granted a grace
whenever the sticky downgrade guard (`peerAuthSeen`) had not yet armed.

That grace was not a compatibility affordance, it was an unauthenticated
**active** bypass, and it did not depend on the reflection weakness this issue
also tracks:

- the window is open on **every fresh boot** — "before the guard arms" is
  exactly when a node starts;
- an admitted peer's first frame was executed **before** the connection was
  installed (`handleNewConnection`), and `syncMsgFence` on that path reaches
  `OnFenceReceived`, which disables every routing group;
- the admitted connection then **displaces** the legitimate peer's connection,
  and arming the guard later does not evict it.

So a PSK-less host reaching the fabric could fence the node and hold the peer
slot. Two changes close it:

- **A keyed node requires an authenticated peer.** `syncAuthDecision` no longer
  consults `peerAuthSeen` for the unkeyed-peer branch — it cannot, since the
  whole exposure is the pre-arm window. An unkeyed/legacy peer is rejected.
- **The pre-admission frame mechanism is DELETED, not reordered.** A legacy
  peer's first frame used to be carried out of the handshake as a
  `pendingFrame` and executed BEFORE `installConn` — `syncMsgFence` on that
  path reaches `OnFenceReceived` and disables every routing group, for a peer
  that had proven nothing. Its only producer sat behind the dual-accept grace,
  so once that grace is gone the arm can never accept and the mechanism is
  unreachable. It is removed rather than left dormant: unreachable code that
  mutates cluster state before admission is one edit away from being live
  again. There is now no path by which an unadmitted connection executes
  anything.

**No relaxation knob, deliberately** — but read the rollout constraint below
before concluding that is easy.

An earlier draft shipped a bounded `authentication-migration-window`. It had to
bound a connection's LIFETIME rather than just its admission (an admitted
pass-through stream outlived the deadline and could still fence the node), it
had to stop an admitted peer re-arming it through config-sync, and its
in-memory arming meant a crash loop granted a fresh interval on every restart.
A relaxation needing three guards of its own does not belong inside the fix that
closes the hole, so it was removed.

What remains is the property a security appliance should have: **for a
connection established AFTER keying, a node must possess the key to join a
keyed cluster.**

That qualifier is not pedantry. Verification is gated per-connection on
`ac.authed()`, fixed at handshake time, so a connection established BEFORE the
key was committed stays unauthenticated for its whole lifetime and keeps having
its frames accepted with no HMAC. See "Rolling it onto a live unkeyed cluster"
below for the operator consequence — the restart there is not optional — and
**#6628** for the open residual — it covers any auth-key CHANGE and subsumes
the narrower unkeyed→keyed case. It is PRE-EXISTING, not introduced by #5078.

### Rollout: a secondary whose gate is ARMED cannot be keyed locally

Three earlier revisions of this document got this wrong in three directions —
first claiming an unavoidable deadlock, then claiming the operator can simply
"commit the key locally on each node", then claiming the gate covers every entry
point unconditionally. The mechanism, stated with its precondition:

- `applyRG0OwnershipTransition` calls `store.SetClusterReadOnly(true)` on
  `StateSecondary` / `StateSecondaryHold` (`pkg/daemon/daemon_ha.go`). It is
  driven by an RG0 **transition event** and by nothing else — there is no
  startup arming and no reconcile that re-derives the flag.
- Once armed, `EnterConfigureSession` returns `ErrClusterReadOnly` before doing
  anything else (`pkg/configstore/store_lock.go`), whichever entry point the
  operator used.

So on a secondary whose gate is armed, config mode cannot be opened at all —
this is not "the local commit gets overwritten by sync", and **config-sync is
that node's only writer** (`TestClusterReadOnly_SyncApplyBypassesGate` pins that
the HA-sync ingress path bypasses the gate).

**But arming is not universal, so do not read the heading as unconditional.** A
node that cold-starts, seats as RG0 secondary and never transitions never
reaches that call, and `Store.clusterReadOnly` starts false — so its store is
writable. REST enters a configure session with no RG0 check of its own
(`pkg/api/config.go`), where gRPC guards on `IsLocalPrimary(0)` and the
interactive CLI has its own check. That gap is **#6890**; the dropped-event
variant is **#6889**. Both are OPEN and neither is scheduled — do not read a
fix date into this sentence. The design intent is what this
section describes; treat the gap as a bug to avoid, never as a rollout
procedure.

**Performable procedures:**

1. **At provisioning / console, before the cluster forms.** `clusterReadOnly`
   zero-values to `false`, so each node can be keyed independently before it
   ever seats as secondary. This is the recommended path.
2. **On a live cluster: commit on the PRIMARY while sync is connected.** The
   established connection carries the key to the secondary. This works only
   because committing the key does not restart cluster comms — the auth key is
   deliberately absent from `clusterTransportKey`, pinned by
   `TestAuthKeyChangeDoesNotRestartClusterComms_5078`. Do not add it there; see
   that test for why it would deadlock with no self-recovery. ("Deadlock", not
   "permanent deadlock" — an operator can still break it out of band, by the
   controlled promotion in row 3 or, on a node whose gate was never armed, by
   the #6890 hole. What the hypothetical destroys is the cluster's ability to
   converge on its own.) The step-20 decision
   that must not fire on a key change is pinned separately by
   `TestKeyCommitDoesNotRestartCommsAtTheCallSite_5078` — the struct test alone
   does not cover the call site.

   **Procedure 2 carries the risk it is trying to avoid.** The key reaches the
   secondary asynchronously, so if the session-sync connection drops in the
   window between the primary committing and the secondary applying, you land in
   exactly the keyed-primary / unkeyed-secondary state below — the now-keyed
   primary rejects the unkeyed peer's reconnect, and the key can never be
   delivered. Prefer procedure 1. If you must use procedure 2, confirm sync is
   connected immediately before committing (`show chassis cluster status`) and
   verify the secondary applied the key immediately after; treat a drop in that
   window as requiring the recovery below.

**Recovery: no path is unconditional, and the one you can plan around costs a
controlled outage.** Three earlier revisions of this section got this wrong in
three different directions — one proposed a primary-only rekey and labelled it
UNVERIFIED, the next said no recovery existed at all, the third said exactly one
path works. Each replaced a hedge with an absolute and each was refuted. So the
three candidate paths are stated individually, with their preconditions, rather
than summarised into a verdict:

1. **Primary-only rekey — CLOSED.** "Remove the key on the primary, let the peer
   reconnect unkeyed, config-sync pushes, re-add the key" cannot start: an
   unkeyed `chassis cluster` is what the commit gate rejects, so `delete chassis
   cluster authentication-key; commit` is refused by
   `validateClusterAuthKeyStrict`. This document says the same thing under "Do
   not try to return to dual-accept by clearing the key first". Tracked as
   **#6630**.
2. **Console on the seated secondary — CLOSED only where the gate is actually
   ARMED.** The gate is on the **config store**, not the transport, so *when it
   is armed* `EnterConfigureSession` returns `ErrClusterReadOnly` regardless of
   which entry point the operator used — console, remote CLI, gRPC or REST.
   Arming is not automatic, and that is the whole caveat: `SetClusterReadOnly(true)`
   is reached only from the RG0 **transition** handler, so a node that cold-starts,
   seats as secondary and never transitions still has a **writable** store. On
   such a node this row is OPEN, and REST is the way in — `pkg/api/config.go`
   enters a configure session with no RG0 check of its own, where the interactive
   CLI (`pkg/cli/cli_dispatch.go`) and gRPC (`IsLocalPrimary(0)`) each have one.
   Tracked as **#6890**; the dropped-event variant of the same unarmed-gate
   failure is **#6889**. Do not treat this row as CLOSED on a node whose RG0
   state you have not checked.
3. **Controlled RG0 promotion — the only path you can PLAN for, and it is
   CONDITIONAL.** ("Plan for", not "that works": row 2 is open on an unarmed
   node, so a path exists there too — it is just a bug you must not build a
   procedure on.) Stop `xpfd` on the keyed primary; *if* the secondary wins the
   election, `applyRG0OwnershipTransition(StatePrimary)` calls
   `d.store.SetClusterReadOnly(false)` and the now-primary node accepts a local
   commit of the same key. Restart the old primary and the pair converges keyed.
   Same stop-one-node shape documented above for `configuration-synchronize`.

   **Each "if" is a real precondition, not a formality:**
   - the secondary must be eligible — `election.go` returns early on
     `m.kernelUpgradeHold`, and promotes only when `rg.Weight > 0`. Zero weight
     or an active upgrade hold and no promotion happens at all;
   - the promotion **event must be delivered**. `Manager.sendEvent` is
     non-blocking and drops on a full channel, and the dropped-event fallback
     does not reconcile `Store.ClusterReadOnly` — so the manager can report RG0
     primary while the store stays read-only. Tracked as **#6889**.

   (The unarmed-gate case from row 2 — **#6890** — is *not* a precondition here.
   It does not block promotion; it means the gate you are trying to clear was
   never closed on that node, so the recovery was never needed there. It is
   listed under row 2, where it belongs, rather than padding this list.)

   So do not read this row as a procedure. It is the path you would design
   around; whether it is available on a given cluster at a given moment depends
   on both preconditions above.

So the recovery you can actually plan for is a deliberate cluster failover —
you have turned a config commit into an outage. (A node that happens to fall in
the row-2 unarmed-gate case is writable without any of that, but you cannot
design a procedure around a gap that is merely FILED.) That is why committing
`authentication-key` must never restart cluster comms: the fallback is
CONDITIONAL on everything row 3 lists, and even when available it is one you
would have to schedule. Do not read "a fallback exists" off this sentence —
that is exactly the absolute this section keeps regrowing.
`TestAuthKeyChangeDoesNotRestartClusterComms_5078` and
`TestKeyCommitDoesNotRestartCommsAtTheCallSite_5078` pin the no-restart
behaviour; if either reds, the change under your hand is the one that forces
that outage.

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
- **Wire, boot-epoch section (#6169).** A signed frame optionally carries
  a 16-byte boot-epoch section `marker(8) + epoch(8, little-endian)`
  inserted **BETWEEN the body and the `XPFA` trailer**
  (`marshalHeartbeatAuthEpoch`):

  ```
  [ body … version section ][ marker(8) ][ epoch(8) ][ XPFA(4) session(8) counter(8) HMAC(32) ]
                             \___ #6169 epoch section ___/\_________ #4107 auth trailer _________/
                                                          \_ signed span ends before the digest _/
  ```

  The placement is load-bearing and is **not** interchangeable with
  appending after the trailer. Appending after it (the earlier attempt,
  #6370) moves the `XPFA` magic off `len-52`, so a pre-#6169 receiver reads
  the frame as UNSIGNED — and an enforcing pre-#6169 peer then rejects
  every frame, splitting a keyed cluster mid-upgrade. With the section
  before the trailer, a pre-#6169 receiver still locates the trailer at
  `len-52`, still verifies the MAC over exactly the bytes the new sender
  signed, still decodes an identical packet (the epoch lands past the
  version section, which `UnmarshalHeartbeat` ignores), and simply never
  sees the epoch. Bidirectional compatibility with **no**
  `CurrentHAProtocolVersion` bump.

  `marker = HMAC(PSK, "xpf-ha-boot-epoch-v1")[:8]` is key-derived, NOT a
  fixed ASCII magic. The section is read at a SINGLE FIXED OFFSET back from
  the fixed-size trailer (`len-68` — one index, no search loop), so the bytes
  it lands on are the tail of the version section — a stable, build-specific
  string. A fixed magic could therefore
  be matched by an ordinary body on **every** frame of some build,
  deterministically; and because the receiver LATCHES the high-water epoch,
  a body-derived value read as a uint64 (~7e18, far above a wall-clock
  epoch ~1.8e18) would permanently lock the peer out. A key-derived marker
  is a PRF value no attacker can compute without the PSK, and an archived
  legacy body collides at only ~2⁻⁶⁴. The epoch is read **only** from a
  MAC-verified frame — only a verified frame authorises treating `len-52`
  as the end of the signed body. The tail reserve grows to 68 bytes when a
  marker is emitted, so a maximal frame still fits `maxHeartbeatSize`;
  reserving only 52 lets the frame overrun the receiver's read buffer,
  which truncates it and destroys the MAC.
- **Anti-replay.** `session` is a random per-sender-process id and
  `counter` a monotonic per-session counter. `heartbeatAuthReplay.admit`
  remembers a BOUNDED SET of per-session high-water counters
  (`heartbeatReplaySessions` slots, FIFO eviction). It accepts a strictly
  increasing counter within any KNOWN session and accepts a genuinely
  NEW, never-seen session id, so a sender restart/reboot (a routine HA
  event — `make test-failover` reboots a node) is never mistaken for a
  replay. Intra-session replays are rejected.
  **Retired-session replays are rejected (#5477).** The pre-#5477 tracker
  held exactly ONE `(session, counter)` and RE-ANCHORED on ANY session
  change, so an on-link attacker who recorded authenticated frames from
  two sessions A and B could alternate A→B→A→B indefinitely — each
  switch reset the single watermark and re-admitted the SAME recorded A
  frames, refreshing peer liveness and applying their stale role/priority
  before `handlePeerHeartbeat`. HMAC blocks forging a NEW session but not
  replaying an already-valid byte sequence. Remembering each retired
  session's watermark rejects the return to A (its counter cannot exceed
  the highest the genuine peer ever signed). Session ids are RANDOM
  (unordered), so a strictly-newer test like `fullSetSeqGuard` cannot be
  used — a bounded per-session watermark is the mechanism that separates a
  real reboot (new id) from a replay of a retired session (known id,
  no counter advance). **Bound safety and its honest limit:** the ring
  RAISES the on-link replay attacker's cost — from 2 recorded sessions
  (the pre-#5477 A→B→A loop) to `heartbeatReplaySessions`+1 — but is NOT an
  absolute bar. Eviction is FIFO and is triggered by ANY never-seen session,
  INCLUDING a REPLAYED old frame whose session is not currently in the ring:
  admit() treats it as never-seen, re-records it, and evicts the oldest.
  FIFO always leaves exactly one just-evicted session to replay back in as
  never-seen, so an attacker who captured `heartbeatReplaySessions`+1 (= 65)
  or more distinct sessions can churn the ring by REPLAY ALONE (no
  reboot, no minting) and SUSTAIN the replay indefinitely; with fewer than
  65 recordings every retired-session replay is rejected.
  **The unit is a peer DAEMON INCARNATION — but only since #6169 Stage 0.**
  A session id used to be minted per `heartbeatSender`, so every peer heartbeat
  restart (VRF rebind, HA comms restart) minted a fresh one with no reboot
  involved: the 65 above was 65 recorded heartbeat *sessions*, cheaper to
  harvest than 65 daemon incarnations, routine peer restarts consumed ring
  slots permanently once the ring outlived a local restart, and — worst — those
  extra sessions all shared ONE boot epoch, which the floor cannot separate, so
  the ring stayed churnable *within* an incarnation even under the epoch gate.
  `Manager.heartbeatNonce` now draws the session once per `Manager` and only
  advances the counter (`TestHeartbeatNonceIsIncarnationScoped_6169`), so a
  restart no longer re-anchors and the 65 really is 65 peer boots. The map
  still causes NO
  genuine-peer lockout (an evicted live watermark just makes the peer's next
  frame never-seen → admitted) and cannot grow memory (fixed 64 slots).
  **#6169 closes the ≥65 churn** with the signed boot epoch below; the ring
  is retained and still owns within-incarnation replay and the whole legacy
  (epoch-less) path.
- **Across-incarnation anti-replay — the signed boot epoch (#6169).**
  The ring can only ever be a bounded set because session ids are random and
  unordered. The frame therefore carries a **boot epoch**: a per-daemon-
  incarnation counter that increases across restarts and reboots, giving the
  receiver an order over peer incarnations in O(1) state. It is **not strictly
  increasing in every case** — the persisted term of the seed is bounded, so a
  backward clock step larger than `bootEpochMaxSkew` regresses it even with the
  file intact (residual 3, #6711).
  - **Receiver** (`heartbeatAuthState.admitAuthed`, floor `highEpoch` on the
    `Manager` so it survives a heartbeat restart exactly like the ring):
    `epoch < highEpoch` → REJECT (an incarnation OLDER than the highest one
    accepted — which is a retired one only while the sender's epoch has not
    regressed; see residual 3); `epoch == highEpoch` → fall through to the
    ring, but only for a BOUNDED SET of sessions at that value
    (`highEpochSessions`, `heartbeatEpochSessionsPerEpoch` slots);
    `epoch > highEpoch` → let the ring vet the nonce, then raise the floor and
    rebind it to that session.
    **The floor admits at most `heartbeatEpochSessionsPerEpoch` (2) SESSIONS
    PER EPOCH VALUE**, and bounding that is what makes it bound the ring
    rather than merely order it. Equality must fall through for a bound
    session — a live peer signs every frame of its incarnation with one
    epoch, so refusing equality outright declares a healthy peer dead — and
    must not fall through unbounded, because distinct sessions sharing one
    epoch churn the ring exactly as epochless frames do (measured 1625/1625
    before the binding existed; `epoch == highEpoch` used to fall through
    unconditionally). A refused frame is counted as `EpochSessionCollision`
    and rendered by `show chassis cluster status` as "Epoch session
    collisions".

    **The bound cannot be ONE, and an earlier revision of this document said
    the cost of making it one was "durable only when the clock is frozen AND
    the store never completes".** That is false. `refineBootEpoch` chains to
    `persisted+1`, which is a pure function of the FILE, so a store that
    READS but cannot WRITE — a full or read-only `/var`, with the state file
    holding a value ahead of `now` but inside `bootEpochMaxSkew` after an RTC
    ran fast and NTP corrected it back — hands EVERY successive incarnation
    the identical epoch, on a healthy advancing clock. Refinement is the
    equal-epoch generator there, not the escape from one. With a singleton
    bound the successor incarnation was refused on every heartbeat (measured
    0/40 through `initHeartbeatEpochState` over a write-failing directory),
    which at the shipped 200 ms interval and threshold 5 declares a healthy
    node dead in 1 s and takes its RGs over while it still holds them.

    **What it still costs**, stated as the bound is: a successor beyond the
    second at ONE unchanged epoch value is refused, and refused for its whole
    process lifetime, because `bootEpoch` is set once and re-refinement lands
    on the same `prev+1`. So the honest statement is *durable across every
    restart in a window up to `bootEpochMaxSkew` whenever the persist half
    cannot advance the file*, and the bound buys one restart inside that
    window rather than removing it, and it buys NONE at all against an on-link
    replay attacker: every prior incarnation's frames carry the current floor
    value under a distinct session in this regime, so one replayed archived
    frame fills the second slot and the first genuine successor is refused.
    Raising the bound does not help — an attacker spends `k-1` slots as cheaply
    as one. **Sender-side recovery** needs the wall clock to climb past
    `prev+1` **and** another restart — at most an hour.
    **Receiver-side, only a full `xpfd` restart on the receiving node clears
    it**, and an earlier revision of this document had the reason exactly
    backwards. `highEpoch` and `highEpochSessions` live on the `Manager`, which
    is why a *heartbeat* restart does **not** clear them: `StartHeartbeat`,
    `RestartHeartbeat` on a DHCP-triggered VRF rebind and the HA comms restart
    all preserve `hbAuth` deliberately (#5086/#6642 — a receiver-scoped floor
    would be zeroed by every routine restart and re-admit a replayed retired
    epoch). Only a new `Manager`, i.e. restarting the daemon, resets the floor
    and admits the stranded successor on the raise-from-0 path. That is a
    heavier operation than it sounds, and it is **not** unconditionally
    preferable: a restarted floor is also a *cleared* floor, which one archived
    frame re-raises just as it re-arms a cleared latch (residual 5 below), so
    on a link an attacker is on, restarting can hand the lockout straight back.
    **When
    "Epoch session collisions" climbs alongside a peer that keeps being
    declared dead, check for a non-writable `/var` on the peer first**
    (`df`, and a test write under `/var/lib/xpf`); a clock at or before the
    Unix epoch is the second, degenerate cause. Rebinding on silence instead
    would cover every successor and is declined: waiting out the dead-peer
    interval between captures is free, so it hands the attacker back the
    unbounded churn the bound exists to stop.
    (`TestEqualEpochsCannotChurnTheRing_6669`,
    `TestEqualEpochSuccessorIsAdmitted_6669`,
    `TestFloorRebindsToTheRaisingIncarnation_6669`.)
    **The floor is tested BEFORE the ring is consulted and a rejected frame
    never reaches `ring.admit`.** That ordering is load-bearing: `admit`
    RECORDS a never-seen session as a side effect, so checking the epoch
    after it would let rejected replays keep evicting live watermarks and
    flush the ring — the bypass that failed review in #6370. The floor only
    rises to a value the genuine peer actually signed — but that does **not**
    bound it by the live peer's *current* epoch: if the peer has since
    regressed (residual 3, #6711), one archived frame raises the floor above
    it and locks it out, and re-raises a cleared floor after a restart just as
    it re-arms a cleared latch (residual 5).
  - **Sender** (`bootEpochSeed` published synchronously, then `refineBootEpoch`):
    `max(persisted+1, wall_clock_nanos)`,
    persisted atomically at `/var/lib/xpf/ha-boot-epoch` (the same durable
    state root as SNMPv3 `engineBoots`). The two terms cover the two
    failure modes neither survives alone — a **backward clock step** across
    a reboot is dominated by `persisted+1`, and **lost persisted state**
    (fresh image, wiped `/var/lib`, first boot) is dominated by the wall
    clock. Resolution is NANOSECONDS deliberately: a coarser seed hands two
    incarnations starting in the same interval identical values.
    **The first term is BOUNDED, and the bound is `bootEpochMaxSkew` (one
    hour).** A persisted value further ahead than that is not chained from at
    all (`epochOrderable` in `refineBootEpoch`), so a backward step LARGER
    than an hour is not carried across even with the file perfectly intact —
    see residual 3 and #6711. Read `persisted+1` as covering ordinary RTC
    skew and NTP corrections, not arbitrary clock faults.
  - **The DOWNGRADE LATCH — without it the floor closes almost nothing.**
    The floor only ever sees frames that CARRY an epoch, and an attacker's
    captures are by construction mostly from BEFORE the upgrade, so they
    carry none. A receiver that accepts epochless frames forever never
    consults the floor at all. Measured on the first cut of this change,
    with the floor latched at a live peer's epoch: **975/975 epochless
    replays still admitted.** So once the peer has been seen to emit an
    epoch, an epochless frame from it is REFUSED (`epochSeen` in
    `heartbeatAuthState`). The latch is armed by OBSERVATION, never by local
    build version — that is what keeps a rolling upgrade working.
  - **The latch is PROCESS-SCOPED, and that is the design decision that
    REPLACED durability.** It lives on `Manager.hbAuth` (#5086/#6642), so a
    heartbeat restart, a DHCP-triggered VRF rebind and an HA comms restart all
    PRESERVE it — the routine events. Only a full daemon restart clears it.

    **The cost is bounded by the peer's NEXT GENUINE FRAME — not by wall clock**,
    and that distinction is the whole of it. Measured after a receiver daemon
    restart: **1080/1080 epoch-less captures admitted** inside the window, then
    **0/120** once a genuine frame lands. What the attacker gets is one full
    ascending pass over their captures — about 60 frames across 12 retired
    incarnations — not a single frame. A replayed OLD epoch CAN set the floor low
    (the forward bound constrains only how far AHEAD an epoch may be), but it
    cannot be sustained *while the peer's own epoch is still climbing*: the
    genuine frame then dominates and re-arms the latch.

    **"The genuine frame always dominates" is FALSE as an unqualified claim, and
    this section used to make it.** It holds exactly while the sender is
    monotonic. If the peer's epoch has REGRESSED (residual 3, #6711 — a backward
    clock step larger than `bootEpochMaxSkew`), a replayed archived frame
    carrying the peer's *earlier, higher* epoch raises the floor ABOVE the live
    peer, and the live peer's genuine frames are then refused indefinitely.
    Measured: 0/5 live frames admitted after one archived frame poisoned a fresh
    floor, 0/5 after a sender restart at the same clock, and 0/5 again after a
    receiver restart followed by one re-injected archived frame
    (`TestArchivedEpochPoisonsAFreshFloor_6711`).

    With a LIVE peer that is ~100 ms and the trade is clearly good. With a
    **SILENT** peer the window stays open until the peer returns — and that is
    precisely the scenario the durable floor was justified by, so this residual
    is narrow only in the live-peer case. It is stated that way deliberately: the
    trade was taken with the silent-peer cost known, not overlooked. Measured by
    `TestReceiverRestartWindowIsOneHeartbeat_6169`.

    In exchange, rollback recovery is a PSK rotation plus `systemctl restart
    xpfd` rather than deleting a state file, there is no commit window between
    accepting a frame and durably recording it, the receive path needs no
    cross-process lock, and an in-range-but-wrong epoch cannot lock a peer out
    across reboots. The rotation is not optional garnish — a replayed archived
    epoch frame re-arms the latch against the empty post-restart state, so the
    restart alone is not reliable recovery (residual 5).

    An earlier revision persisted the FLOOR so the latch also survived a daemon
    restart. Review priced that and it was removed: a peer-floor state file
    turns a deliberate ROLLBACK into "delete the right file on the right node
    and restart" — a procedure done under pressure at 3am — opens a crash
    window between accepting a frame and committing the floor, needs
    cross-process locking on the receive path, and lets an in-range-but-wrong
    epoch lock a peer out across reboots.

    **A durable LATCH is not the same object as a durable FLOOR, and the two
    must be priced apart.** The narrowest durable latch is a PSK-scoped boolean
    — `{key fingerprint, epochSeen}` — which persists no epoch, so an in-range
    wrong floor still dies at the next restart, and which resets by
    construction on a PSK rotation. Neither floor cost above applies to it. It
    is still declined, on its own costs: the durable write has to land BEFORE
    the frame is accepted (a crash in between leaves the latch clear across the
    reboot, which is exactly the state a replay wants), so it puts storage on
    the control-channel receive path with no good failure policy — fail-open
    buys nothing over today, fail-closed lets a disk fault refuse a healthy
    peer; it needs the same cross-process lock for the same `SO_REUSEPORT`
    reason; and it makes the NO-ATTACKER rollback strictly worse, since a
    restart would no longer clear the latch and every deliberate downgrade
    would require a PSK rotation across both nodes.

    **The rotation does NOT retire captures made after it, and an earlier
    revision of this section claimed it did.** A PSK rotation retires everything
    an attacker recorded BEFORE it; a frame recorded AFTER it, under the current
    key, still verifies. Measured: rotate K1→K2, let the peer arm the latch
    under K2, roll it back under K2 to a build that signs but emits no epoch,
    record the frames this receiver refuses, then let the peer go silent and
    restart this daemon — **5/5 of those post-rotation captures are admitted**
    against the empty state, and a durable K2-scoped latch would have refused
    them (`TestRotationDoesNotRetirePostRotationCaptures_6669`). The durable
    latch is still declined, but on its own merits:

    - **Where it matters most, its benefit and its worst cost are the same
      configuration.** A signed epoch-less frame under the current key can only
      exist if the peer held that key while running a pre-#6169 build (ALWAYS-
      EMIT means a #6169+ build always carries an epoch) — rollback, replacement
      under the same identity and key, or a partial upgrade. While the peer is
      still on that build a durable latch refuses the captures *and the live
      peer*: that is the no-attacker-rollback cost above, not a separate gain.

    A second bullet used to read **"where the live peer is healthy again, it
    shuts one door with another open beside it"** — the latch can only have
    armed under this key because an epoch-BEARING frame was accepted under it,
    so an on-link attacker holds one of those too, and against empty
    post-restart state an archived epoch-bearing frame is admitted whatever the
    latch says (residual 5). **That argument is wrong**, because the two doors
    cost the attacker different things. Measured against a restarted receiver:
    65 captured epoch-BEARING incarnations admit 325/325 on one ascending pass
    and 0/1625 across five further rounds (the floor climbs with them and the
    per-session watermark closes the rest — the set is spent), while 65
    epoch-LESS incarnations captured under the CURRENT key admit 1625/1625 and
    keep going, because nothing orders them and FIFO eviction hands back a
    never-seen session every round. That is indefinitely sustained forged
    liveness against a silent peer, and a durable PSK-scoped latch refuses all
    of it.

    So the benefit is real and is larger than "captures taken strictly inside a
    rollback": it is every epoch-less capture taken under the current key. It is
    **still declined**, on its own costs — a durable write on the accept path
    with no good failure policy, cross-process locking there, and a strictly
    heavier procedure for every no-attacker rollback — and the residual is
    **accepted**, not closed. The exposure is bounded by the rollback (no
    rollback under the current key, no epoch-less captures to replay) and is
    metered rather than silent (`Heartbeats without epoch:`). Reconsider the
    trade if a rollback under the current key ever becomes routine rather than
    an incident action.

    Rollback recovery is a rotation followed by `systemctl restart xpfd`, both
    operations operators already perform, rather than a hand-edit of state; the
    rotation carries real weight because without it the restart is defeatable by
    one replayed archived frame (residual 5).
  - **ALWAYS-EMIT, and why this mechanism costs no HA availability.** The
    epoch is published SYNCHRONOUSLY from the wall clock with **no file access
    at all**, so every frame carries one from the very first send. Persistence
    is a REFINEMENT that runs on a worker and only ever RAISES the value; its
    single job is surviving a backward clock step.

    This ordering is load-bearing, not tidiness. The latch means a peer REJECTS
    epoch-less frames from a node that has proved it emits them — so if a
    storage fault could stop this node emitting one, the latch would convert a
    disk stall into a **false peer-death**, an availability regression on an HA
    path caused by the fix itself. With emission decoupled from I/O, a hung
    disk, a blocking `flock` and a wedged `fsync` are all survivable, and the
    invariant holds:

    > a keyed heartbeat carries no epoch **iff** the peer runs a pre-#6169 build.

    The residual here is the double fault — storage that never completes AND a
    clock that stepped backwards. **That is the residual of THIS ordering
    property, not of the epoch as a whole**, and an earlier revision let it
    stand as if it were both. A single backward clock step larger than
    `bootEpochMaxSkew` regresses the epoch on its own, with storage perfectly
    healthy and the file intact — see residual 3 and #6711.
  - **The state lock fails CLOSED.** Nothing in xpf enforces a single daemon
    instance — no pidfile, and the gRPC listener sets `SO_REUSEPORT`
    (`pkg/grpcapi/server.go`), so a second `xpfd` does NOT fail on a port
    collision the way it otherwise would. `withEpochFileLock` therefore
    serializes the whole read-modify-write of the boot-epoch file across
    processes. On lock failure it SKIPS the persist rather than running the
    critical section unlocked: a lock whose failure path runs the work anyway
    is not a lock. Skipping is free precisely because emission does not depend
    on it — only backward-clock-step protection is lost.
  - **Plausibility bound — the floor is a ONE-WAY DOOR.** A latched epoch
    rejects everything below it forever, so a bogus far-future value is a
    permanent lockout. Only an epoch below **year 2200**
    (`epochPlausibleMax`) may be latched: a present-day value is ~0.25x that
    bound, `MaxUint64` is ~2.5x it (year 2554). `MaxUint64` is unreachable
    by ordinary operation but IS reachable through a corrupt or hand-edited
    persist file — and `refineBootEpoch` chaining from such a value would emit
    `MaxUint64` on one boot and then REGRESS on the next (`MaxUint64+1`
    overflows, so the wall clock wins), permanently locking this node out of
    a peer that had latched it. It therefore refuses to chain from an
    implausible previous value and rewrites the file with a sane one. The
    bound is deliberately ONE-SIDED and absolute: a low epoch is permissive
    rather than locking, so bounding below would refuse an appliance with a
    dead RTC; and an absolute bound means a receiver whose OWN clock is
    wrong does not start refusing a healthy peer. An implausible epoch still
    is refused outright rather than admitted-and-ignored: a frame the floor
    cannot ORDER would be governed by the bounded ring alone, which is the
    epoch-less bypass in miniature.
  - **Forward bound — the recoverable half.** The absolute bound alone leaves a
    single-fault path: a peer whose clock or persisted state runs far ahead, yet
    still lands before 2200, would latch a floor its own corrected incarnations
    can never climb back above. So an epoch may also be at most
    `bootEpochMaxSkew` (one HOUR, 3.6e12 ns) ahead of the RECEIVER's wall
    clock. The slack IS the worst-case lockout — a bad epoch inside the bound
    is latched, and a repaired peer sits below that floor until its own
    wall-clock seed climbs past it — so an hour is deliberate: a year of slack
    bought nothing over it (the bound only has to exceed real inter-node skew,
    milliseconds under NTP and minutes without it) and cost a year-long
    lockout. Bounding the forward side
    stops the **latch**, which is the unrecoverable half, so a peer that is
    corrected is accepted again the moment it comes back into range.
    There are exactly TWO places this forward bound is applied, and no
    persistent peer-floor store is one of them (there is no such file): the
    receiver's floor RAISE path, and `refineBootEpoch` validating the persisted
    value it would chain from — where it now also validates the successor it
    would actually publish, so a persisted value one below a bound cannot emit
    an epoch exactly on or past it.

    **Precondition on healing, stated exactly.** A persisted epoch written
    under a bad clock heals *only when this node's own clock is credible at the
    moment refinement loads the file*. Below `epochClockSaneFloor` (2020) the
    forward bound is skipped entirely — deliberately, because a dead-RTC node
    booting near 1970 cannot distinguish its own legitimate previous epoch from
    a corrupt future one. Both sit implausibly far "ahead" of a 1970 clock — a
    legitimate 2026 epoch by ~56 years, the corrupt year-2191 fixture this
    branch tests with by ~222 — and the node has no reference that separates
    them, because the forward bound that WOULD discriminate is exactly what is
    skipped. The magnitudes differ; the indistinguishability does not. Rejecting
    would
    discard exactly the value persistence exists to carry across a backward
    clock step. Only the absolute year-2200 band applies there. So on an
    appliance whose RTC is dead and whose xpfd always starts before NTP, a
    wrong-but-below-2200 value is chained from on every boot and never heals;
    refinement runs once per `Manager`, so NTP correcting the clock later does
    not re-validate it. See "Honest residuals" below.

    The forward bound gates the RAISE path only (`epoch > highEpoch`), never
    `epoch == highEpoch`. Re-testing an epoch that has ALREADY been accepted is
    a different question from vetting a new one, and conflating them was a
    defect: a backward wall-clock step beyond the skew made every subsequent
    frame from a healthy, already-latched incarnation fail the bound and be
    rejected BEFORE the monotonic `lastSeen` update, so the peer was declared
    dead in ~500ms and the cluster went dual-master. The relaxation has a
    price and it is worth naming: when the floor already sits beyond the bound,
    an equal-epoch frame from the BOUND session reaches
    `heartbeatAuthReplay.admit` and costs one ascending archive pass. That is
    the whole cost — equality cannot move the floor, so the one-way door is
    untouched, and the session binding above already refuses every other
    session at that value.

    The forward bound is applied ONLY when the receiver's own clock is itself
    credible (`epochClockSaneFloor`, year 2020). An appliance with a dead RTC
    boots near the Unix epoch and syncs NTP seconds later; during that window a
    healthy peer's epoch is ~56 years "ahead", and a naive forward bound would
    make it refuse its peer at exactly the moment cold-boot split-brain is most
    likely — the hazard `heartbeatStartupGrace` already exists for. Below that
    floor only the absolute bound applies, which is permissive, never locking.
    The trade this makes is deliberate: a backward clock step LARGER than the
    skew allowance regresses this node's epoch rather than chaining. It is NOT
    true — an earlier revision of this paragraph said it — that such a value is
    only reachable when this node's own clock was the wrong one at persist
    time, and therefore that nothing is ever locked out. An incarnation running
    at the RIGHT time persists `T` and its peer latches floor `T`; the next
    incarnation starts at `T-2h` (still credible, above year 2020), rejects the
    intact `T` for exceeding `now+1h`, publishes `T-2h`, and is refused by the
    peer. Both branches of the trade are lockouts; the choice is between one
    that is RECOVERABLE and one that never ends, because chaining from an
    out-of-range value strands this node permanently above the range its peer
    will ever accept. Recoverable does NOT mean "a restart on either node" — an
    earlier revision of this paragraph said that, and it is false; see
    "Recovery is narrower than a restart on either node" under residual 3 below
    for what actually clears it. A recoverable lockout
    beats an unrecoverable one — but the residual is real and is tracked as
    #6711, not argued away. Pinned by
    `TestRefinementValidatesThePublishedEpochNotJustThePersistedOne_6169` and
    the `value_beyond_the_forward_bound_is_not_chained_from` subtest.

    `refineBootEpoch` takes its ONE clock sample AFTER `os.ReadFile` returns,
    not before it. Sampling first let a stalled read straddle an NTP correction:
    a dead-RTC boot captured a 1970 instant, the read completed after the clock
    reached the present, and the value was then judged against the stale sample
    — so the credibility gate skipped the forward bound on a node whose clock
    was by then perfectly good, and a corrupt-but-below-2200 successor was
    published. (`TestRefinementSamplesTheClockAfterLoadingPersistedState_6669`.)
  - **Cross-process locking on the boot-epoch file** (the only epoch state file
    — there is no peer-floor file). Nothing in xpf enforces a single daemon
    instance: there is no pidfile, and the gRPC listener sets `SO_REUSEPORT`
    (`pkg/grpcapi/server.go`), so a second `xpfd` does NOT fail on a port
    collision the way it otherwise would. Two overlapping incarnations could
    therefore interleave read-modify-write, and an interleaved one can lose the
    update the other just made. An advisory `flock` on a sidecar file
    (`withEpochFileLock`) serializes the whole read-modify-write, not merely the
    write.

    **It does NOT order incarnations**, and this section used to say it did
    ("publish epochs that are not strictly ordered, which is the one property
    the whole mechanism rests on"). It serializes by lock ACQUISITION, and
    nothing ties that to daemon start or to survivorship — emission deliberately
    precedes the worker that takes the lock. Older incarnation A publishes `a`
    and is delayed; newer B publishes `b > a`, locks first, persists `b`; A locks
    second, reads `b` and raises *itself* to `b+1`. The peer then latches the
    OLDER incarnation and refuses the newer, surviving one. It cannot be closed
    with this file alone — refinement only matters when the persisted value
    exceeds our seed, and "a predecessor wrote it after a backward clock step"
    and "a concurrent newer incarnation wrote it" leave the identical file, so
    separating them needs a lifetime-held liveness lock or a writer identity in
    the file. What IS closed is the unrecoverable half: refinement is re-run on
    every later heartbeat start (`Manager.refreshBootEpoch`), so the stranded
    incarnation climbs back above the file at the next `StartHeartbeat` — a VRF
    rebind or an HA comms restart — instead of staying below the peer's floor
    for the life of the process. Between the mis-ordering and that next start
    this node is refused; there is no periodic re-check. That recovery carries
    two conditions — the raising epoch must have reached the FILE, and the
    other incarnation must be gone — spelled out under residual 7.
    (`TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669`,
    `TestBootEpochRefreshIsIdempotent_6669`,
    `TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669`.)

    **A post-rename durability failure is not a failed write.**
    `fsatomic.WriteFileDurable` reports a directory-fsync failure that happened
    AFTER the rename as a typed `*PostRenameSyncError` (#5185): the new content
    is already VISIBLE — the next read, or a restart, sees it — and only its
    durability across power loss is unknown. Refinement records its persist
    watermark from that value rather than treating the pass as a no-op.
    Treating it as a failed write left the watermark stale, so the next pass
    could not recognise its own value, chained from it, and rewrote `epoch+1`
    — ratcheting the file on EVERY pass for as long as the fsync kept failing.
    (`TestPostRenameSyncKeepsTheWatermark_6669`.)

    **It fails CLOSED — the write is SKIPPED, not run unlocked.** Proceeding
    unlocked does not trade correctness for liveness; it trades a TRANSIENT
    liveness risk for a DURABLE one. A raced read-modify-write can leave a lower
    epoch in the file, that value is read back as `prev` on the next boot, and it
    is exactly the term that matters after a backward clock step — the one case
    persistence exists for. The epoch then produced can sit below the peer's
    latched floor and be refused: the same false-peer-death, one restart later
    and durable. Declining costs only backward-clock-step protection, and only
    until the next resolve succeeds, because the wall-clock epoch is already
    published and on the wire.
  - **Layering with #4107's `peerAuthSeen` — two gates, neither redundant.**
    `peerAuthSeen` latches "the peer proved it holds the PSK" and refuses
    UNSIGNED frames; `epochSeen` latches "the peer proved it runs an
    epoch-capable build" and refuses SIGNED-BUT-EPOCH-LESS ones. A replayed
    pre-upgrade capture is genuinely signed (it came off a keyed cluster), so it
    passes the first gate and is stopped only by the second — which is precisely
    why the epoch latch was needed. An unsigned frame never reaches the epoch
    gate: `heartbeatReceiver.admitFrame` — the single implementation of the
    receive-side gate, called by `readLoop` for every datagram and by the epoch
    fixtures instead of a restated copy — reads the epoch and calls
    `admitAuthed` only when the MAC verified. The one path skipping BOTH is a
    cluster with no key configured at all, where there is no MAC to verify and
    the key-derived marker cannot exist; that is #6624's domain (an unkeyed
    chassis cluster is refused at commit), not the epoch's.

    **The wiring at both ends is bound by an end-to-end test, not by
    inspection.** `TestBootEpochTraversesTheRealSendAndReceivePath_6169` drives
    the real `heartbeatSender` through a real UDP socket into the real
    `readLoop` goroutine and asserts the receiver latched the exact epoch the
    sender published. Before it existed, passing `0` at the send site
    (`marshalHeartbeatAuthEpoch`'s last argument, which produces a byte-identical
    legacy frame) and severing the receiver's epoch read BOTH left `go test
    ./pkg/cluster` fully green — two nodes could run this code, neither latch,
    and the sustained replay stay open under passing CI.
  - **Observability — FIVE counters, and the operator action differs per
    counter.** Without them the residual is invisible: an operator who has
    upgraded both nodes has no way to tell whether the cluster is still
    accepting pre-upgrade-shaped frames, and the documentation would be the
    only defence.

    | `HeartbeatStats` field | rendered as | what a non-zero value means |
    |---|---|---|
    | `EpochlessAdmitted` | `Heartbeats without epoch:` | the exposure meter — frames admitted with no epoch at all |
    | `EpochDowngradeRejected` | `Epoch downgrades rejected:` | the latch refused a peer that had previously signed epochs |
    | `EpochSessionCollision` | `Epoch session collisions:` | too many sessions at one epoch value — usually a peer whose epoch store cannot advance |
    | `EpochOutOfBandRejected` | `Epoch out-of-band rejected:` | the PEER emitted 0 or a post-2200 epoch. A conforming build cannot; check the peer's state file or its build |
    | `EpochAheadOfClockRejected` | `Epoch ahead of our clock:` | a CLOCK fault, usually on a healthy peer — check NTP on both nodes, not for an attacker |

    The last two exist because `heartbeatAuthDecision` cannot tell those arms
    apart: it sees only `nonceFresh == false` and reports every epoch refusal as
    `stale nonce (replay)`. Both arms used to be silent as well as mislabelled,
    so a clock-skew lockout and a corrupt-epoch peer both read as an on-link
    replay attack. `admitAuthed` now returns a reason for each and the receive
    path prefers it over the generic wording. The third silent arm — an epoch
    BELOW the floor — keeps the generic wording deliberately: that one really is
    a replay of a retired incarnation.

    All five are rendered on all three surfaces
    (`FormatInformation`, `FormatStatistics`, `FormatControlPlaneStatistics`)
    and bound there by `TestEveryEpochCounterIsRendered_6669`, which drives each
    counter to a DISTINCT value so a transposed pair of render lines fails
    rather than passing on a label match.

    Every one is RENDERED in the `Control link statistics:` block on all three
    surfaces that print it — `FormatInformation`, `FormatStatistics` and
    `FormatControlPlaneStatistics` — under the labels in the table above. While the peer is not yet signing epochs the
    count carries an inline note naming the action that closes it (rotate the
    control-link PSK); once the latch has armed the note switches to marking the
    count historical, since it is then a record of the migration rather than
    live exposure. A counter populated on an internal struct but rendered
    nowhere would be documentation, not observability, so the guard asserts the
    RENDERED string on each surface rather than the struct field.

    **Not yet a Prometheus series.** The collector (`pkg/api`, `xpfCollector`)
    is dataplane-scoped and has no cluster/heartbeat surface at all, so this
    would mean plumbing the cluster `Manager` into it — a new dependency edge,
    not a one-line addition. Worth doing as its own change; the CLI block is
    what an upgrading operator reads today.
  - **Sender nonce is INCARNATION-scoped** (`Manager.heartbeatNonce`). It
    used to be per-`heartbeatSender`, so every `StartHeartbeat` minted a
    fresh session — and routine events mint them (VRF rebind, comms
    restart). One long-lived daemon could therefore emit more than a ringful
    of sessions under ONE epoch, which the floor cannot separate, leaving
    the ring churnable within an incarnation. One incarnation now emits one
    session with a counter monotonic across heartbeat restarts, so the floor
    leaves an attacker at most one session and the ring rejects it on the
    watermark. Nothing regresses on the receiver: a heartbeat restart keeps
    the session and advances the counter (admitted); a daemon restart builds
    a new `Manager` and draws a fresh session (admitted as never-seen).
  - **What happens on a ROLLBACK — the one legitimate latch trigger.**
    Because a storage fault no longer stops a node emitting an epoch, the
    only way a healthy peer goes epochless after having emitted one is a
    deliberate rollback to a pre-#6169 build (A/B image rollback, #1930).
    That peer IS refused: this node declares it dead and takes over, and the
    rolled-back node cannot see that it is being refused. This is a real,
    deliberate trade — the same one #4107's sticky `peerAuthSeen` already
    makes for the auth trailer. It is bounded and
    operator-visible:
      - a cluster that has never run an epoch-capable build is never latched,
        so a plain rolling upgrade in either direction is unaffected;
      - the rejection logs a rate-limited, actionable warning naming the
        recovery below (`Manager.NoteEpochDowngradeHeartbeat`, once per 30s) —
        there is no state file, so nothing to clear by hand. The generic
        per-frame `heartbeat auth rejected` line is rate-limited on the same
        30s interval (`heartbeatRejectWarnLimiter`) and reports
        `suppressed_since_last`, so the bound does not hide the rate. Before
        #6669 r18 only the actionable line was bounded and the generic one
        fired per frame, so a 10/s epochless stream produced ~10 warnings a
        second — the sentence promised a rate limit the noisy line did not
        have;
      - **recovery, in this order:** rotate the control-link PSK on BOTH nodes,
        *then* `systemctl restart xpfd` on the node that is refusing. The latch
        is process-scoped, so the restart brings it back unlatched and it
        accepts the rolled-back peer again. There is no state file to hand-edit
        and no new CLI surface to learn. Rolling BOTH nodes back needs no
        action beyond that on whichever node had latched.

        **If you already did it in the wrong order, you are not stuck — restart
        once more.** Restarting *before* rotating leaves the latch armed
        THROUGH the rotation: the replay re-arms it after the restart, and the
        subsequent key change cannot un-arm what is already set. Measured, one
        rotate→restart pass recovers; restart→rotate needs a **second** restart
        after the rotation. Nothing else is required, and no state is lost
        either way.

        **The restart alone is not reliable, and the order is the reason.**
        A restart clears the floor, the latch and the ring together, and
        arming the latch needs only an authenticated, orderable, ring-fresh
        epoch frame — so ONE frame an attacker captured while the peer still
        ran an epoch-capable build re-arms it against that empty state
        (`highEpoch` is 0, so nothing is below the floor; an empty ring calls
        its session never-seen). The rolled-back peer is refused again, and one
        replay per restart sustains that indefinitely. Rotating the PSK first
        makes every archived frame fail MAC verification, so it never reaches
        the latch; the key is re-read per frame on both the send and receive
        paths, so rotation itself needs no restart. This is pinned by
        `TestArchivedEpochReplayReArmsLatchAfterRestart_6169` and stated at the
        arming site in `admitAuthed`, which also records why a durable
        latch and a freshness test were both rejected.
  - **Honest residuals**, each measured rather than asserted.
    1. **Receiver restart window — bounded by the peer's next genuine frame, not
       by time.** ~100 ms with a LIVE peer; **open until the peer returns if it is
       SILENT**, which is the case durability existed for. Measured: 1080/1080
       epoch-less captures admitted inside the window, 0/120 after a genuine
       frame lands; the attacker gets one full ascending pass (~60 frames across
       12 retired incarnations). A replayed old epoch can set the floor low but
       cannot sustain it **while the peer's own epoch is still climbing** — the
       genuine frame then dominates. It does NOT dominate if the peer's epoch has
       regressed (residual 3): there a replayed archived frame raises the floor
       above the live peer and holds it out, across receiver restarts, at one
       re-injection each.
       (`TestReceiverRestartWindowIsOneHeartbeat_6169`,
       `TestArchivedEpochPoisonsAFreshFloor_6711`.)
    2. **In-bound clock skew latches a bounded lockout.** A peer epoch ahead of
       us but INSIDE the skew allowance is latched, so a peer later repaired to
       real time sits below that floor. Bounded twice: the slack IS the lockout
       (one hour), so the peer's own wall-clock seed climbs past it unattended;
       and the floor is in memory, so `systemctl restart xpfd` on the refusing
       node clears it immediately — subject to residual 5, since a replayed
       archived frame can re-raise a cleared floor just as it can re-arm a
       cleared latch. With a durable floor this needed deleting a state file,
       which is what made it a MAJOR.
       (`TestInBoundFarFutureEpochLockoutIsBounded_6169`.)
    3. **Sender epoch regression — and it is NOT only a double fault.** Losing
       the persisted epoch AND stepping the clock back below the last emitted
       value in the same reboot regresses the sender's epoch and the peer
       refuses it, with the same restart recovery as a rollback. This
       paragraph used to end "both terms of the seed must fail together", and
       that margin does not hold: a SINGLE backward step larger than
       `bootEpochMaxSkew` (one hour) does it on its own with the persisted file
       perfectly intact, because `refineBootEpoch` declines to chain from a
       value more than an hour ahead of `now`. The peer had latched the earlier,
       correct epoch, so it refuses the restarted node; a later NTP correction
       does NOT repair it, since the epoch is published once per incarnation and
       the file has by then been overwritten with the lower value.

       **Recovery is narrower than "a restart on either node".** Restarting the
       SENDER does not help *while its published reading is still below the
       floor* — the file now holds the *lower* value, so the next incarnation
       re-publishes from the same bad clock (measured: still below the floor).
       The operative condition is the reading, not the clock: a clock that stays
       two hours slow still reads past the floor two real hours later, and a
       restart then publishes a value STRICTLY ABOVE it, which the peer admits
       on the RAISE path and which rebinds the floor to that incarnation.
       The raise path is the one to rely on, and not because equality is shut:
       a frame landing exactly ON the floor is admitted while one of the
       value's `heartbeatEpochSessionsPerEpoch` slots is free, so that door is
       real but finite and does not refill. The raise is the wider of the two
       (a nanosecond past the floor, rather than landing on one exact value)
       and cannot be exhausted
       (`TestPoisonedFloorStillRecoversByRaise_6669`). Restarting the RECEIVER does
       clear the floor, but an attacker holding one archived frame from the
       pre-regression incarnation re-raises it immediately, at one re-injection
       per restart — the same shape as residual 5, and it means the floor can be
       poisoned by a capture rather than only by the sender's own regression.
       Reliable recovery is fixing the clock (then restarting the sender), or a
       PSK rotation before the receiver restart. Tracked as **#6711** — a
       behavioural fix there touches persistence semantics and is deliberately
       out of scope here. (`TestArchivedEpochPoisonsAFreshFloor_6711`.)
    4. **PSK rotation** changes the key-derived marker; the in-memory floor and
       latch are unaffected and stay valid, since a floor is a per-peer counter
       rather than key material.
    5. **A restart does not recover from a rollback while an archived epoch
       frame is being replayed.** Restarting clears the floor, the latch and the
       ring together, and arming needs only an authenticated, orderable,
       ring-fresh epoch frame — so ONE frame captured while the peer still ran
       an epoch-capable build re-arms the latch against that empty state and the
       rolled-back peer is refused again, indefinitely, at one replay per
       restart. The same shape re-raises the floor in residual 2. Recovery is
       PSK rotation on both nodes FIRST, then the restart, which is what the
       rejection warning now says. Scope: a peer that has NEVER emitted an epoch
       cannot be falsely armed this way — there is nothing to capture — so this
       bites on rollback, replacement under the same identity and key, or a
       partial upgrade. Not closed in code: a durable FLOOR re-creates the
       peer-floor file this design deliberately removed; a durable PSK-scoped
       LATCH avoids that but pays a durable write on the accept path, a
       cross-process lock there, and a heavier no-attacker rollback. It is
       **not** declined as redundant: a rotation retires captures taken *before*
       it and nothing else, and a durable latch refuses the epoch-less captures
       taken under the CURRENT key — the ones that sustain forged liveness
       indefinitely (1625/1625 admitted after a restart, against 0/1625 for a
       spent epoch-bearing set). The pricing is above; and
       a freshness test needs a challenge-response or timestamp the wire format
       does not carry (a legitimately long-lived peer's epoch is arbitrarily
       old, so no recency test separates it from an archived one).
       (`TestArchivedEpochReplayReArmsLatchAfterRestart_6169`,
       `TestRollbackRecoveryOrderingIsRotateThenRestart_6169`.)
    6. **A bad persisted epoch heals only if the local clock is credible when
       refinement loads it.** Below `epochClockSaneFloor` the forward bound is
       skipped, so a wrong-but-below-2200 persisted value is chained from rather
       than ignored. On an appliance with a dead RTC whose `xpfd` starts before
       time sync, the FIRST pass of every boot is made against an uncredible
       clock, and a correctly clocked peer then refuses this node's epoch on its
       raise path — asymmetric visibility, not mutual isolation. Refinement is
       re-run at each later heartbeat start (`Manager.refreshBootEpoch`), which
       RE-VALIDATES the file but does **not** heal it — an earlier revision of
       this paragraph said it did, and that was wrong. Refinement persists the
       published epoch, which only ever rises, so once the first pass has chained
       from the corrupt value every later pass writes the same raised value back.
       Nothing lowers the file, and lowering is what healing would mean. On the
       dead-RTC box this residual describes, a restart does not clear it either:
       the first pass of every boot chains again and the value ratchets. No
       complete close exists:
       under a dead RTC a legitimate previous epoch and a corrupt future one are
       indistinguishable (nothing on the node is a trustworthy time reference),
       and healing after the fact would mean LOWERING a published epoch
       mid-incarnation, the one direction the design refuses. A PARTIAL
       narrowing does exist and was declined rather than missed — lowering the
       arbitrary year-2200 horizon would reject a year-2191 value while still
       carrying present-day ones — because the horizon is a hard cliff, not
       spare room: a value at or past it is rejected outright on EVERY frame, so
       lowering it makes a forward clock fault that much more likely to produce
       mutual refusal. That trades a fault whose worst case is asymmetric
       visibility for one whose worst case is dual-master. Reasoned at
       `epochWithinForwardBound`. Operational close: a working RTC, or ordering
       `xpfd` after time synchronization.
       (`TestPersistedEpochHealsOnlyWhenClockCredible_6169`.)
       Refinement's clock sample is taken AFTER the state read returns, so a
       stalled read straddling an NTP correction cannot judge the file against a
       clock that no longer exists
       (`TestRefinementSamplesTheClockAfterLoadingPersistedState_6669`).
    7. **The state lock orders lock acquisition, not incarnations.** Two
       overlapping `xpfd` instances (no pidfile, `SO_REUSEPORT`) can publish in
       one order and reach `withEpochFileLock` in the other: the OLDER one locks
       second, reads the newer one's persisted value, and raises *itself* above
       it. The peer then latches the older incarnation and refuses the newer,
       surviving one. It cannot be closed with this file alone — a predecessor's
       value after a backward clock step and a concurrent newer incarnation's
       value leave the identical file — so a complete fix needs a lifetime-held
       liveness lock, a writer identity in the file, or single-instance
       enforcement for `xpfd`. What IS closed is the unrecoverable half:
       refinement re-runs on every later heartbeat start
       (`Manager.refreshBootEpoch`), so the stranded incarnation climbs back
       above the file at the next `StartHeartbeat` instead of staying below the
       floor for the life of the process. Until that start it is refused, and
       there is no periodic re-check. Tracked as **#6724**.
       (`TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669`,
       `TestBootEpochRefreshIsIdempotent_6669`.)

       **That recovery carries two conditions**, and they do NOT need the same
       missing state — an earlier revision of this paragraph said both were the
       same state as the mis-ordering itself. It re-reads the FILE, so it
       recovers only what the file expresses. First, **the floor-raising epoch
       must have reached the file**: refinement publishes a raise before
       persisting it (deliberately — a node that has read a predecessor's higher
       value must still order itself above it even when it cannot write), so the
       other incarnation can EMIT `b+1` while the file still reads `b`. This
       node then has no signal at all — it wrote `b`, the file says `b` — and
       every restart returns at the idempotence shortcut, leaving it below the
       peer's floor for its whole process lifetime. Second, **the other
       incarnation must be gone**: while both run, each pass raises above the
       other and rewrites the file, so they leapfrog indefinitely, alternately
       stranding each other while the file ratchets.
       (`TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669`.)

       Only the SECOND needs a writer identity in the file or a lifetime-held
       liveness lock, which is where the leapfrog lives. The first needs nothing
       but a **retry trigger**: on a retry A's published value is already `b+1`,
       so `next := prev+1` does not exceed it, nothing ratchets, and the
       `WriteFileDurable` is simply re-attempted — once `b+1` lands, B's next
       refresh reads it and raises to `b+2`. What is missing is only something
       to schedule that retry, which is the "no periodic re-check" half of
       **#6724** and a materially smaller change than a writer identity.

       A refine requested while one is in flight used to be DROPPED, which lost
       exactly this recovery request — the in-flight worker's locked read can
       already be complete, so an update landing behind it is invisible to that
       pass. It is now COALESCED into one follow-up pass, which bounds the extra
       work at one outstanding request rather than an unbounded backlog of
       fsync-ing workers. (`TestOverlappingRefineRequestIsCoalesced_6669`,
       `TestCoalescingDoesNotRatchetOnAHealthyNode_6669`.)

       **The in-flight flag and the pending bit are ONE WORD**
       (`Manager.bootEpochRefine`, claimed and released by CAS on the pair) and
       that is a correctness requirement rather than packing. As two separate
       atomics they could be observed torn: a requester that read "a worker is
       in flight", lost the race while that worker ran all the way out, and only
       then stored the pending bit published it against a worker that no longer
       existed, and nothing in production observes a stranded bit — the operator
       would have seen only a node still below its peer's floor, recovering at
       some later heartbeat start that nothing bounds. On one word the publish is
       conditional on the observation still holding, so a requester whose CAS
       fails takes the idle slot and runs the pass itself. The window was a few
       instructions wide and unreachable by hammering (3000 rounds x 4 concurrent
       `refreshBootEpoch`), so it is driven through two seams.
       (`TestLateRefineRequestIsReclaimed_6669` for a request landing before the
       release, `TestLateRefineRequestCannotBeStranded_6669` for one landing
       after.)

       **`Manager.Stop` joins the worker, with a bound.** The worker may park
       indefinitely in a flock or an fsync, so it outliving `Stop` needs no race
       — one sequential shutdown over a wedged store reaches it — and it would
       then still be storing to `m.bootEpoch` and writing the state file on a
       torn-down manager. `Stop` refuses new workers and waits
       `bootEpochStopJoinBudget` (2 s) for the one already running; the wait is
       bounded because the shutdown path has just sent VRRP priority-0 and must
       not block on a dead disk. A timeout is logged, and leaves behind atomic
       stores and **up to two** `fsatomic` writes: the wedged pass itself, plus
       one coalesced follow-up if a request set the pending bit while it was
       stuck, which the worker serves once it unblocks.

       **The join spawns nothing, and takes no lock.** Writing it as
       `go func() { wg.Wait(); close(done) }()` selected against a timer returns
       only the CALLER — nothing cancels a `WaitGroup.Wait` — so each timed-out
       join left one goroutine parked for as long as the store stayed wedged.
       That is easy to wave through for a single terminal `Stop` and wrong
       across repeated calls, and there are several (`Stop` is public; the tests
       join on every epoch case). The worker publishes its own exit handle
       (`Manager.bootEpochWorker`, an `atomic.Pointer`), so a join is a select
       on a channel somebody else closes and a timeout costs nothing.
       (`TestTimedOutJoinLeavesNoWaiterBehind_6669`.)

       The handle is PUBLISHED under `bootEpochRefineMu`, which is what keeps
       `Stop`'s refuse-then-join ordering airtight, but it is LOADED and CLEARED
       without it — and that is a correctness requirement, not tidiness.
       `bootEpochRefineMu` is held across `claimBootEpochRefine`, hence across
       its `epochRefineAfterLostClaim` seam, where a requester can park
       indefinitely; the join and the worker's own exit are precisely the two
       operations that must make progress regardless. Guarding the handle with
       that mutex deadlocked all three against each other, and a bounded join
       that can block forever is not a bounded join.
       (`TestJoinDoesNotBlockBehindAParkedRequester_6669`.)

       It can also still hold a lock a caller waits on, which an earlier
       revision of this section denied: `withEpochFileLock` holds the state
       file's advisory lock across the whole read-modify-write, so another
       INCARNATION's refine blocks behind a wedged worker until it unwedges.
       Nothing in *this* process does — the refine slot is a CAS word, not a
       lock.

       **The timeout path deliberately does not release that flock.** The
       descriptor is a local on the wedged worker's stack, and dropping the lock
       while that worker is still mid-write would let another incarnation
       interleave with a write in progress — trading a delay for the torn update
       the lock exists to prevent. It does not need releasing: an flock dies
       with the open file description, so the kernel drops it when the process
       exits, SIGKILL included. Under the documented restart recovery (systemd
       `Type=simple`, `TimeoutStopSec=20`) the old unit is reaped before the new
       one starts, so a **restart never contends for this lock**. What can
       contend is two concurrently running incarnations — the SO_REUSEPORT
       overlap this lock was written for — and there the blocked party is the
       other incarnation's refine worker, whose failure is already survivable:
       it declines the persist and keeps the wall-clock epoch already on the
       wire.

  - **`Stop` is not idempotent by construction, only by call topology.** It has
    no `sync.Once` and no early return; a repeat call re-executes the body and
    survives only because it captures `hbSender`/`hbReceiver` under `mu` and
    nils them there, while `Monitor.Stop` is independently idempotent through
    the same idiom. Both `heartbeatSender.stop` and `heartbeatReceiver.stop`
    open with a bare `close(stopCh)`, so a second call without that capture
    panics. The manager is built once per process and stopped once, so the
    repeat is unreachable today — but by topology, not by design, which is why
    `TestSecondStopIsANoOp_6669` asserts it.

       **Three rules for tests in this area**, each of which was a real
       cross-test failure before it was a rule:

       1. `bootEpochReady` **is not a drain.** The worker closes it from inside
          its loop and then still calls `releaseBootEpochRefine`, which reads a
          package-var seam, and may run further coalesced passes. Use
          `awaitFirstRefine`, which waits for the channel AND drains.
       2. **Unpark every seam on the failure path**, from a `t.Cleanup` rather
          than the end of the body. `t.Fatalf` runs `runtime.Goexit` and skips
          the rest of the body, so an assertion that fires while a requester is
          parked inside `claimBootEpochRefine` leaves that goroutine holding
          `bootEpochRefineMu` for the life of the process — and every later test
          that starts or stops a worker then blocks on it, turning one
          assertion into a package-wide `panic: test timed out` naming an
          unrelated test.
       3. **Join a requester goroutine; do not poll the word for it.**
          `waitBootEpochIdle` reads `bootEpochRefine`, and that word reads 0 in
          the window after a worker releases the slot and before an unparked
          requester re-claims it, so a test can return while the requester is
          still inside `startBootEpochRefine` reading `bootEpochPath`.
          `keyedEpochManager`'s cleanup join is no backstop: it joins a
          REGISTERED worker, and a requester that has not claimed yet is not
          one.
  - **No clone/bake requirement** (unlike the SNMPv3 engine-id, `pkg/snmp`).
    Epochs are compared per-PEER, never between the two nodes, so two chassis
    cloned from one image may hold identical persisted boot epochs harmlessly;
    and a baked-in value can only ever raise a node's starting epoch, which the
    never-regress rule already permits.
- **The tracker's LIFETIME is the process, not the heartbeat (#5086).**
  The watermarks and the sticky `peerAuthSeen` flag live in
  `Manager.hbAuth` (`heartbeatAuthState`); a `heartbeatReceiver` holds a
  POINTER to it. This is load-bearing, not a refactor. Every
  `StartHeartbeat` builds a brand-new receiver, and it runs on far more
  than a daemon boot — `RestartHeartbeat` on a DHCP-triggered VRF rebind
  (`daemon_apply_dataplane.go`) and the HA comms (re)start
  (`daemon_ha_sync.go`), both routine. While the tracker was a receiver
  field, each of those DISCARDED every retired-session watermark, so the
  #5477 protection lasted only as long as one UDP socket: after a restart
  an attacker replaying captured frames from a retired session hit an
  EMPTY tracker, every frame looked never-seen, and the whole captured run
  was re-admitted — refreshing peer liveness and applying stale
  role/priority for its full length. Measured on the pre-fix code: a
  10-frame capture from each of two sessions yields 20 admitted frames
  (~4 s of forged liveness at the 200 ms interval, i.e. 4× the ~1 s
  peer-dead window) per heartbeat restart, and a fresh 20 on every
  subsequent restart. A peer that looks alive while dead is the failure
  that matters here: the survivor never takes over. Anchoring the state to
  the `Manager` costs nothing on the failover path (the same integer scan,
  now under a mutex taken ~5×/s) and does not change the memory bound —
  one fixed ring per `Manager` (64 × 16 B = 1 KiB) plus a mutex and an
  atomic, allocated once, never growing with restart count, uptime, or the
  number of peer sessions observed. It also fixes the mirror-image
  hole in `Manager.HeartbeatPeerAuthSeen`, which read the flag off
  `m.hbReceiver`: `StopHeartbeat` nils that field, so every restart
  silently DISARMED the gRPC fabric listener's downgrade-guard for the
  restart window (a VRF-rebind restart retries the bind for up to ~5 s)
  and an unsigned fabric RPC was accepted from a peer already known to
  hold the key. It now reads the process-lifetime state.
  **Narrowed, not closed, by #6169:** the session ring, the boot-epoch floor
  and the downgrade latch are all process state, so a full daemon restart
  starts with all three empty. What #6169 changes is how fast that repairs:
  the peer's next epoch-bearing frame re-establishes the floor above every
  captured older epoch and re-arms the latch, so the exposure is bounded by
  the peer speaking rather than by the ring alone. With a SILENT peer the
  window stays open until it returns — see the boot-epoch residuals above.
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
sticky `peerAuthSeen` in `Manager.hbAuth`, an `atomic.Bool` because it is
read cross-goroutine; it hangs off the Manager rather than the receiver so
a heartbeat restart cannot disarm the guard — #5086). The gRPC interceptor rejects a tokenless fabric
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
- **Dual-accept, UNKEYED SIDE ONLY (as of #5078).** A node with no key never
  handshakes and is byte-for-byte a legacy peer, so an unkeyed node still
  accepts anything. A KEYED node does **not** dual-accept: it rejects a
  legacy/unkeyed peer (no HELLO, or `keyed=0`) outright, with no
  first-contact grace and no migration window — see "Session-sync
  fail-closed authentication (#5078)" above, which supersedes the
  paragraph this bullet used to contain. The `pendingFrame` mechanism that
  carried a legacy peer's first frame out of the handshake is **deleted**,
  not merely bypassed: with no accepting arm left it was unreachable, and
  it executed that frame BEFORE the connection was admitted. Enforcement
  still engages only once BOTH nodes are keyed and signing — and, for an
  ALREADY-ESTABLISHED connection, only after it is re-established, because
  the handshake result is fixed at connect and committing a key does not
  restart cluster comms (#6628, pinned by
  `TestAuthKeyChangeDoesNotRestartClusterComms_5078`; see "Operating the
  control-link PSK" below).
- **No sync-side downgrade-guard (removed in #5078).** There used to be one
  here: once the peer had authenticated on the sync channel (sticky
  `syncAuthedEver`) or the heartbeat channel, a later UNAUTHENTICATED
  connection was rejected. A guard of that shape only matters where an
  unkeyed peer would otherwise be ADMITTED, and on a keyed node none ever
  is, so it became unreachable — `syncPeerAuthSeen` ended with zero callers
  and `syncAuthedEver` write-only — and was deleted along with the
  `HeartbeatPeerAuthSeen()` requirement on `SyncAuthProvider`. The **#4107
  heartbeat downgrade-guard is separate state** (`heartbeatAuthDecision`
  over `heartbeatAuthState.peerAuthenticated`) and is unchanged, as is the
  #4357 fabric guard that arms off it via `Manager.HeartbeatPeerAuthSeen`
  — that method is still exported and still consumed, just no longer by
  this interface.
- **Wiring.** `SessionSync.SetAuthProvider(*Manager)` (`daemon_ha_sync.go`)
  supplies `ControlLinkAuthKey()`. No new
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
- **Atomic install + cold-prime decision (#4962).** Because #4370 made
  `handleNewConnection` per-accept, two same-fabric accepts can race: the
  loser observes the winner's just-installed connection, closes it
  (aborting its in-flight cold-prime bulk), and — under the pre-#4962
  after-unlock `wasDisconnected` read — skipped cold-prime, leaving the
  **surviving** connection un-primed (peer blackholes on the next
  failover). `installConn` now wires the connection into `conn0`/`conn1`
  and computes the cold-prime decision under the **same** `s.mu`
  acquisition, gated on a `needColdPrime` latch (armed on a
  full-disconnect→connect edge, consumed only when a bulk succeeds) so the
  surviving accept **inherits** the outstanding obligation and re-drives
  the bulk. See `docs/session-sync-architecture.md` → "Atomic Install +
  Cold-Prime Decision (#4962)".

## Operating the control-link PSK (#6611)

All three authenticated control channels above — heartbeat (PR-A), fabric
gRPC (#4357) and session sync (#4369) — key off ONE leaf:

```
set chassis cluster authentication-key <key>
```

Each channel deliberately fails **OPEN** when that leaf is absent, which is
what makes a rolling key rollout possible. The cost is that an unkeyed
cluster runs its whole control channel unauthenticated: any host that can
reach the control segment can forge a heartbeat to drive election, call the
allowlisted fabric RPCs (read/clear sessions, cross-node failover), and open
a session-sync connection. Before #6611 every config this repository shipped,
documented and tested was unkeyed, so the enforcing branches were dead code
in practice.

### Where the key is required

`validateClusterAuthKeyStrict`
(`pkg/config/compiler_validate_strict_cluster_auth.go`) rejects a `chassis
cluster` with no key on the **strict** compile path and downgrades to a
`cfg.Warnings` entry on the **tolerant** path (`opts.lenientClusterAuthKey`).
Strict is **not** only the operator commit — it is every caller of
`compileTreeStrict`:

| path | caller | effect of a reject |
|---|---|---|
| operator commit | `Store.Commit` / `CommitCheck` / `CommitConfirmed` | **Inert for traffic.** The active config and the dataplane are untouched; the cluster keeps running while you add the key. |
| **first-boot import** | `daemon.bootstrapFromFile` (`daemon_apply_commit.go`), taken whenever the config DB has no active config (`daemon_run_bringup.go`) | **The node comes up with NO active config** — unattended, no warning. |
| **day-0 validation** | `configstore.CheckText` (`xpfd check-config`) | `xpf-deploy.py` dies; `make_config_drive.py` refuses; the first-boot loader `scripts/image/xpf-day0-config` falls back to the **factory bootstrap**. |
| **autonomous remediation** | `pkg/eventengine` — `store.CommitCheck()` then the daemon's commit closure (`engine.go`) | Every `event-options` `change-configuration` policy **silently fails** until the cluster is keyed. |
| load / peer config-sync | `Store.Load`, `SyncApply` → `compileTreeLenient` | **Warns and boots.** This is the in-place upgrade path. |

So an **in-place upgrade** still boots — that population keeps its
`.configdb` and loads leniently. Note the fourth row applies to exactly
that population: from the moment of upgrade, an unkeyed cluster's
event-driven `change-configuration` remediation stops committing, with no
operator present to see the rejection. "The cluster keeps running" is
true of traffic and the dataplane; it is not true of automation. What is NOT safe is provisioning a node **without** a DB
while the cluster's config is still unkeyed: reimaging or replacing a failed
node, restoring from an archived text config, or building a day-0 drive from
an unkeyed config. A node in that state comes up unconfigured, and a
factory-default node never forms the cluster, so peer config-sync cannot
rescue it. This repository's own `make cluster-deploy` takes that path —
`test/incus/cluster-setup.sh` pushes the text config and then `rm -rf
/etc/xpf/.configdb`.

### Required order

> **Key the RUNNING cluster first. Only then re-provision, reimage, or
> rebuild a day-0 drive.** The reverse order strands the new node.

The keying commit strict-compiles the WHOLE candidate, so on a cluster
whose config has never been strict-validated it can be refused for an
unrelated reason a lenient boot tolerated — a stale typed leaf (#1319), a
node-identity mismatch (#4185), an RA-interval violation (#4525). That is
the same population this gate is aimed at, so expect to fix those first;
the order above is still the right one, it just may not be a single step.

### Generating and distributing the key

Any high-entropy string; 32 bytes of base64 is a good default:

```
openssl rand -base64 32
```

The key must be **identical on both nodes** and must NOT be `${node}`-scoped —
each node signs with it and verifies the peer with the same value, so a
per-node key authenticates nothing and leaves the channel permanently in
dual-accept. Put it in the shared (non-group) `chassis cluster` stanza, as
the reference configs do.

**Provision it out-of-band — do not rely on `configuration-synchronize` to
carry it (#6629).** Config-sync serializes the active config and writes it
over the session-sync stream, which is HMAC-authenticated but **not
encrypted**; during the very first rollout that stream is also still
unauthenticated (see below). Push the key to each node by the same trusted
channel you use for any other secret.

Out-of-band provisioning alone does **not** avoid the exposure. Every
shipped config sets `configuration-synchronize`, and the RG0 primary's
commit calls `pushConfigToPeer`, which sends `Store.ShowActive()` — the RAW
formatted tree, with no `ast_redact.go` pass on that path. So the cleartext
PSK crosses the control segment at step 1 of the rollout below no matter how
you delivered it. To actually avoid it, take config-sync out of the loop for
the duration:

```
delete chassis cluster configuration-synchronize   # see the caveats below
<key both nodes out-of-band, per the rollout below>
set chassis cluster configuration-synchronize      # ONLY once #6629 lands
```

**Two caveats, both load-bearing — read them before running the above.**

*The restore does not restore safely.* An earlier version of this section
claimed the restore commit was safe because it re-synchronises a config both
nodes already hold, so the key is "no longer new information on the wire".
That is wrong: the stream is authenticated but **not encrypted**, and a
passive observer on the control segment reads the cleartext PSK off that
re-sync regardless of whether the peers already know it. Confidentiality is
not a function of who else already has the secret. Until #6629 gives that
path either redaction or transport encryption, **the honest advice is to
leave `configuration-synchronize` off on a keyed cluster** and manage config
on both nodes out-of-band, accepting the operational cost. Restore it only
when #6629 has landed.

*By far the easiest path is to never reach this state.* Provision both
nodes from text with `configuration-synchronize` ABSENT and the key
already set, before the pair carries traffic. Note that the shipped
reference configs (`docs/ha-cluster.conf`, `docs/ha-cluster-userspace.conf`)
DO enable `configuration-synchronize`, and the Incus test harness pushes
them unchanged — so neither is an example of this order; you have to
remove the line from your own config first. On a new build or during a
maintenance window you were taking anyway, this costs nothing.

*On a LIVE pair whose secondary gate is ARMED, the delete cannot be done
without the sync undoing it.* (Everything in this subsection assumes an armed
gate; on the row-2 unarmed node the second delete needs no promotion at all.
That is the #6890 hole, not a supported route — see the Recovery section. This
subsection does not restate the caveat again.)
`configuration-synchronize` is committed from the RG0 primary. Delete it
there and the SECONDARY still has it enabled — so the moment that secondary
is promoted, reconciliation (`daemon_ha.go:444`) sees sync enabled in its
own local config and pushes its COMPLETE active configuration back to the
former primary (`daemon_ha_sync.go:462`), restoring the very line you just
deleted. You cannot simply "delete on both nodes": the second delete
requires a promotion, and the promotion re-adds the first.

There is one safe order you can RELY on for a live pair, and it is a controlled
single-node outage — not a two-command sequence, and NOT a link cut:

```
# 1. On the RG0 primary: delete the line and commit.
delete chassis cluster configuration-synchronize   # commit

# 2. Stop xpfd on that SAME node and leave it down.
systemctl stop xpfd

# 3. Wait for the peer to promote AND for its session-sync to report the
#    peer disconnected. Do not proceed on a timer — wait for the field.
show chassis cluster status          # on the peer: it must be primary, and
#   "Sync link statistics (control-link): Status: Down"   must be present

# 4. On the now-primary peer: delete the line and commit.
delete chassis cluster configuration-synchronize   # commit

# 5. Verify BOTH persistent stores no longer carry it, then restart the
#    stopped node. Sync is absent on both sides, so nothing pushes the
#    line back regardless of which node ends up primary.
systemctl start xpfd
```

Step 2 is what makes this work: with that node's `xpfd` down there is
nobody for the promoted peer's reconciliation to push to, so the deletion
survives the promotion.

Two details worth stating rather than leaving to be discovered. The
restarted node comes back as SECONDARY only in the normal non-preempt
case — with RG0 preemption enabled a returning higher-priority node can
reclaim primary (`election.go`), so expect a failback. It does not matter
for this procedure, because sync is absent on both sides by then, but it
does change what you will see. And the promoted peer may attempt
reconciliation before it has detected the disconnect; that is harmless
here, because config transmission writes directly to the active
connection rather than queueing for replay, the stopped node cannot apply
it, and during teardown it still considers itself RG0 primary and rejects
incoming config.

**Do NOT sever the link instead.** An earlier version of this section
suggested cutting "the session-sync/fabric segment" before promoting.
That is wrong and dangerous. Session and config sync run on the CONTROL
link — the same interface as the heartbeat, port 4785 — and only fall
back to fabric when no control interface is configured
(`daemon_ha_sync.go`). So cutting fabric alone does not stop config sync
in any shipped configuration, and cutting the control segment takes the
heartbeat with it: both nodes stop hearing each other, both declare the
peer dead, and both become primary. That is a dataplane split-brain with
duplicate VIPs, not merely two nodes with independent config authority.
A physical cut also races disconnect detection, so a promotion issued
immediately after it can still find the session established.

Once BOTH nodes have sync disabled, ongoing config management is manual and
paired: treat only the RG0 primary as writable (that is the intent; see the
#6890 caveat above for where the gate is not actually armed), so every change is
a controlled RG0 promotion, an edit, verification on both stores, and a
failback. That
cost is the reason #6629 (redaction or transport encryption for the
config-sync payload) is the real fix, and why this is documented as a
constraint rather than recommended practice.

### Rolling it onto a live unkeyed cluster

**STALE — dual-accept was removed by #5078; the sequence below no longer works
as written.** It is kept for the shape of the problem, not as a procedure. Step 2
asks the operator to commit the key on the *other* node: on an RG0 secondary
whose read-only gate is armed that returns `ErrClusterReadOnly`, and if sync
drops before step 2 the keyed side rejects the unkeyed reconnect outright. See
the "Recovery" discussion above for what is actually available and under which
preconditions. Rewriting this section is tracked as **#6881**.

Dual-accept made the forward direction non-disruptive:

1. Set the key on one node and commit. It now signs; the unkeyed peer has no
   key, so it accepts everything, and the keyed node has not armed
   enforcement yet, so it still accepts the peer's unsigned frames.
2. Set the SAME key on the other node and commit. Both sign, each observes
   the other authenticate, and enforcement arms.
3. **Restart `xpfd` on both nodes**, one at a time, waiting for the cluster
   to re-form in between.

Step 3 is not optional. **Session sync fixes a connection's authentication
state when the TCP connection is established** (`performSyncHandshake` →
`wrapSyncConn`), and committing the key does **not** restart cluster comms —
the restart decision compares only `clusterTransportKey`
(`daemon_apply_tail.go` / `daemon_ha_sync.go`), which does not include the
auth key. So an already-established session-sync stream stays
**unauthenticated indefinitely** after the key is committed: a hostile stream
admitted before the commit keeps injecting frames, and legitimate traffic
stays unsigned until an incidental disconnect or a restart. The heartbeat and
the fabric gRPC listener DO pick the key up immediately (both read the live
key per frame / per RPC); only session sync is connection-scoped. Tracked as
**#6628** — until it is fixed, the restart is the operator's part of the
contract.

Confirm the posture with `show chassis cluster statistics`, whose
`Authentication:` line (`controlLinkAuthStatus`) reads
`engaged (peer authenticated; unauthenticated frames rejected)` once both
nodes are keyed — `dual-accept (...)` means the channel is still
unauthenticated in practice. Note this line reflects the heartbeat/fabric
posture; it does not tell you whether an existing session-sync connection
predates the key.

**Rolling BACK is not symmetric.** `peerAuthSeen` is sticky in memory and
clears only on an **xpfd restart** — since #5086 it lives on the `Manager`,
so restarting the heartbeat (VRF rebind, comms restart) no longer clears it
— so a node that has seen its peer authenticate will
reject that peer's unsigned heartbeats. Returning one node to an unkeyed
config or an older binary while the other stays armed produces the same
split-brain described under rotation.

### Rotation

There is no key-id, no previous/current overlap and no coordinated rekey, so
rotation is a **planned-outage operation, not a rolling one**.

While the two nodes hold different keys, each receives a present-but-invalid
HMAC from the other. `handleFrame` rejects those frames and `continue`s
**without refreshing `lastSeen`** (`heartbeat.go`), so neither node refreshes
peer liveness: after `heartbeat-interval × heartbeat-threshold` — 200 ms × 5 =
**~1 s** at the SHIPPED cluster settings, 100 ms × 5 = **~500 ms** at the code
defaults (`DefaultHeartbeatInterval`) — **both** nodes declare the peer dead and **both**
take over their redundancy groups — dual-master with duplicate VIPs on the
wire for the whole window between the two commits.

Procedure:

1. Take a maintenance window.
2. Commit the new key on both nodes back-to-back, keeping the gap as short as
   possible — that gap is the dual-master window.
3. Restart `xpfd` on both nodes (per #6628 above, and to clear the sticky
   `peerAuthSeen`).

> [!IMPORTANT]
> **Rotate the PSK after upgrading both nodes to a #6169-capable build.** This
> is a REQUIRED post-upgrade step, not a footnote. Every capture an on-link
> sniffer took before the upgrade was signed with the OLD key, so rotation is
> the only thing that retires an attacker's existing archive — no code change
> can retroactively invalidate frames they already hold. The mechanism is
> `verifyHeartbeatMAC(frame, key)`, which uses the LIVE key: after a rotation
> every pre-upgrade capture fails `macOK` and is discarded before it reaches
> any epoch logic at all.
>
> **This step is what makes the accepted restart residual acceptable.** The
> downgrade latch (`epochSeen`) is process-scoped, so a full daemon restart on
> the surviving node clears it. But do NOT read that as "while the genuine peer
> is absent nothing re-arms it" — an earlier revision of this paragraph said
> exactly that and it is false, as residual 5 below records. A single ARCHIVED
> epoch-bearing frame, captured while the peer still ran an epoch-capable build,
> re-arms the latch on its own: after the restart `highEpoch` is 0, so the replay
> passes the absolute band, the forward bound and the empty ring, and arms
> `epochSeen`. One replay per restart holds the rolled-back peer out
> indefinitely.
>
> That is precisely why rotation comes FIRST. Rotation invalidates the archive,
> so there is nothing left to replay into the window. Skipping it leaves the
> residual live, and restarting without rotating leaves the latch armed *through*
> a later rotation — costing a second restart. The residual was not priced as
> "narrow" on the assumption that nobody would skip the rotation.
>
> **How to tell whether you are still exposed:** `show chassis cluster
> information` / `statistics` print `Heartbeats without epoch:` in the
> `Control link statistics:` block. If it is non-zero and still climbing after
> both nodes are upgraded, this node is still accepting epoch-less frames —
> either a node is genuinely on an older build, or someone is replaying
> captures — and the line carries an inline note saying so. Once an accepted
> epoch-bearing frame arms the latch, the inline note flips to "downgrade latch
> armed; count is historical" and the epoch-less count stops climbing.
>
> That note reports the LATCH, not current enforcement, and the wording is
> deliberate. `heartbeatAuthDecision` dual-accepts everything when no local key
> is configured, and `UpdateConfig` clears the live key without resetting
> `hbAuth` — so a cluster that added the key under `commit confirmed`, armed the
> latch, then let the confirmation time out back to an unkeyed config is left
> with the latch armed and epoch-less frames admitted anyway. An armed latch
> therefore means "this node has seen the peer emit an epoch", not "this node is
> refusing epoch-less frames right now".
>
> **The latch only enforces while a PSK is configured, so read it together with
> the `Authentication:` line** in `show chassis cluster control-plane
> statistics`. `engaged (peer authenticated; unauthenticated frames rejected)`
> means the latch is being applied; `dual-accept (no control-link key
> configured)` means it is not, whatever the note says.
>
> `Epoch downgrades rejected:` is a SEPARATE signal and does **not** start
> counting when the latch arms — it stays at 0 until some later epoch-less
> frame actually arrives and is refused, which on a healthy upgraded cluster
> may never happen. Read it as "something is still sending epoch-less frames
> and being turned away" (a peer left behind, a rollback, or a replay), not as
> a confirmation that the latch is armed. The inline note is what reports the
> latch.

Rotation is also the **anti-replay capture-invalidation** step. Every capture
an on-link sniffer took BEFORE the rotation was signed under the old key, so
after a rotation none of it verifies. It does **not** retire a capture taken
after the rotation: that frame was signed with the key still in force and still
verifies (`TestRotationDoesNotRetirePostRotationCaptures_6669`). Rotation is the
recovery step for an existing archive, not a prophylactic against a new one.
The boot-epoch marker is key-derived (`HMAC(PSK, "xpf-ha-boot-epoch-v1")[:8]`),
so it changes with the key automatically — no separate rollout step. The
restart in step 3 also clears each node's in-memory epoch floor and latch; both
re-arm from the peer's next epoch-bearing heartbeat, within one heartbeat
interval.

Do **not** try to "return to dual-accept" by clearing the key first: an
unkeyed `chassis cluster` is exactly what the commit gate rejects, so that
path does not exist. Tracked as **#6630**.

### Key strength

The commit gate is an **emptiness floor, not an entropy floor**: it rejects an
absent or whitespace-only key (whitespace would satisfy the runtime's
`len(key) > 0` test while being no key at all), but a one-character key
passes. Strength is a continuum, so `ClusterAuthKeyStrengthWarnings` reports
it as a **warning** on both paths rather than rejecting — hard-rejecting a
short key would create a new brick class, including via the unattended
`bootstrapFromFile` path, for an operator who already configured
authentication. It warns below `MinAdvisedControlLinkKeyLen` (16 characters)
and when the key looks like one of this repository's published placeholders.

Trimming makes the gate STRICTER than the runtime, not identical to it, and
on the tolerant path that difference is observable: a leniently-loaded
`authentication-key "   "` warns "no authentication-key configured" at boot
while the runtime treats the untrimmed three-space value as a real key, so
`show chassis cluster statistics` can report `engaged` once the peer
authenticates with the same three spaces. Pathological and pre-existing —
noted so the two surfaces are not read as contradicting each other.

### Shipped configs

`docs/ha-cluster.conf`, `docs/ha-cluster-loss.conf`,
`docs/ha-cluster-userspace.conf`, `test/incus/xpf-cluster-fw{0,1}.conf` and
`examples/deploy/ha-pair.conf` all carry a key, so the HA smoke cluster
exercises the ENFORCING branch rather than the `keyConfigured == false`
shortcut. Those values are **published in a public repository**: a config
copied from them satisfies the gate while remaining trivially forgeable by
anyone who has read the repo. They are marked `CHANGE-ME` and trip the
placeholder warning above. Replace them before any real deployment.
`TestShippedClusterConfigsAreKeyed_6611` / `...UseOneKeyPerCluster_6611`
(`pkg/config`) lock the keyed and one-key-per-cluster properties;
`TestBootstrapFromFileRejectsUnkeyedCluster_6611` (`pkg/daemon`) and
`TestCheckTextRejectsUnkeyedCluster_6611` (`pkg/configstore`) pin the two
unattended strict paths.

The `authentication-key` leaf is `config.Secret`-typed and is redacted in the
ordinary show/log/JSON render paths (`ast_redact.go`), so it is not exposed to
routine operator output or diagnostics. That is not an absolute guarantee: a
sufficiently privileged CLI class can still render cleartext configuration,
and config-sync transmits it in the clear (#6629). Keep the authoritative copy
in your own secret store.

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
- **Full-set ordering (#5706)** — because the set is REPLACED wholesale and both
  fabric `receiveLoop`s run concurrently, a full-set reordered across the
  redundant streams could overwrite a newer set with an older one. Each push now
  carries a trailing `(incarnation, seq)` (`appendIPsecFullSetSeq`, which inserts
  a `\n` delimiter before the trailer so an old newline-decoder never fuses the
  trailer onto the last SA name); the receiver admits only a strictly-newer pair
  per stream (`ipsecRecvSeq`, a `fullSetSeqGuard`), strips the delimiter
  (`stripIPsecFullSetDelim`), and drops a stale reorder (`IPsecSAStaleIgnored`).
  The guard is reset on a peer bulk re-prime (`resetRecvGen`) so an OS-rebooted
  peer's fresh set (lower monotonic incarnation) is re-accepted. A legacy peer
  sends no trailer → `(0,0)` → accept-always (mixed-version compat). See
  `docs/sync-protocol.md` "Full-set state-sync ordering (#5706)".
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
  across a mixed-base pair). Each per-lease string field (address, hwaddr,
  clientid, DUID, leasetype, hostname) is `uint16`-length-prefixed, so the
  writer FAILS CLOSED on a field longer than 65535 bytes: `putLeaseString` /
  `encodeOneLease` return an error rather than let `uint16(len)` silently narrow
  and misframe the peer's decode, and `encodeDHCPLeasePayload` DROPS that one
  lease (with a warning; the count stays consistent) so the surviving leases
  still round-trip — a >64 KiB field is defensive-only, real DHCP identifiers
  are far below it (#4892). The wire format is unchanged; the decoder
  (`getLeaseString`) is untouched — the writer just never emits an oversized
  field.
- **Full-set ordering (#5706)** — like IPsec SA sync, each v4/v6 lease push is a
  wholesale REPLACE, so a reorder across the two concurrent fabric `receiveLoop`s
  could regress the held set. `QueueDHCPLeases` appends a per-family
  `(incarnation, seq)` trailer (`appendFullSetSeq`, INDEPENDENT `dhcpV4SeqCounter`
  / `dhcpV6SeqCounter`), and the receiver admits only a strictly-newer pair per
  family (`dhcpV4RecvSeq` / `dhcpV6RecvSeq`), dropping a stale reorder
  (`DHCPLeasesStaleIgnored`). An OLD receiver reads exactly its record count and
  IGNORES the trailer (clean backward compat); a legacy sender's `(0,0)` is
  accept-always. See `docs/sync-protocol.md` "Full-set state-sync ordering
  (#5706)".
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

**Missing local link = down (#5080).** A `LinkByName` failure for a
monitor on the LOCAL FPC slot means the configured member link is absent
(cold boot before the NIC appears, or a delete/recreate between polls).
`pollInterfaceMonitors` feeds that absence through the same dampening
machinery as a carrier-down link — it must NOT be silently skipped.
Skipping fails open: an already-primary node keeps effective weight 255
and stays primary while its data link is missing, blackholing traffic. A
monitor on a PEER's slot (`SlotToNodeID(slot) != NodeID`) is still
skipped — the peer publishes that interface's status over heartbeat.

**Reconcile monitor debt on config change (#5080).** Effective RG weight
must always derive from the COMPLETE current desired monitor set. On
`UpdateConfig` the manager runs `reconcileMonitorDebtsLocked`: it builds
the desired `(rgID, iface)→weight` map from the new config, clears the
installed debt (`monitorWeights` + each RG's `MonitorFails`) for any
monitor that was REMOVED or whose interface CHANGED, re-derives the debt
for a still-failed monitor whose configured weight changed, then
recomputes each affected RG's weight — all before the election runs. In
tandem, `Monitor.UpdateGroups` drops the dampening `ifaceState` for
monitors no longer desired. Without this, `UpdateConfig` only swapped the
desired slice, so a debt installed for a monitor the operator later
removed/changed persisted and stranded a healthy node secondary forever.
`UpdateGroups` deliberately does not call the locking `SetMonitorWeight`
(it runs under the manager lock already held by `UpdateConfig`); the
manager-side clear happens directly in `reconcileMonitorDebtsLocked`.

`reconcileMonitorDebtsLocked` reconciles INTERFACE-monitor debt ONLY.
`monitorWeights` + `MonitorFails` are a SHARED structure that also holds
IP-MONITORING debts (installed by `SetMonitorWeight` from the ip-monitor
path under the per-target `ip:<addr>` name and the aggregate
`ipAggregateMonitorName` = `"ip-monitoring"`). Those ip debts are owned by
the `Monitor`'s `reconcileRGIPDebts`, which drives them to the desired set
on every poll and clears removed ones; a dropped RG is torn down wholesale
at RG removal. Because `reconcileMonitorDebtsLocked` builds `desired` from
`InterfaceMonitors` only, an ip key would always look "no longer desired",
so the removal loop SKIPS every ip key (`isIPMonitorName` — `ip:` prefix or
the aggregate constant). Without that skip, any unrelated config change
wiped a LIVE ip-monitoring debt from `monitorWeights`/`MonitorFails` and
recomputed the RG weight without it — and it did not self-heal (the
Monitor's `ipDebts` still recorded the debt installed, so the next
`reconcileRGIPDebts` poll saw `desired==installed` and no-op'd), so a node
with a dead monitored uplink jumped back to weight 255 and could win
election → blackhole. Fail-open (#5080 fold).

**Purge per-RG IP-monitor state on RG removal (#5990).** The manager clears
a removed RG's `monitorWeights` in `UpdateConfig`'s removal loop, but the
Monitor keeps its OWN per-RG maps: dampened `ipState` (keyed by
`(rgID, address)`), the installed-debt record `ipDebts` (keyed by rgID), and
the `ipThresholdState` mirror. `Monitor.UpdateGroups` now drops every entry
whose RG is no longer in config, alongside the `ifaceState` purge. Without
this, a same-id RG remove/re-add while a monitored target is DOWN left stale
`ipDebts[rg.ID]` behind: on re-add `reconcileRGIPDebts` saw
`desired==installed` by its OWN stale record and fired no `SetMonitorWeight`,
so the debt the manager already cleared was never re-installed — the re-added
RG carried a MISSING ip-monitor debt (weight stuck at 255) until the target
next transitioned (a dampened edge), and could stay primary with a dead
monitored uplink. Fail-open, narrow trigger. Purging `ipState` too means a
re-added RG whose target has since recovered starts from fresh dampening
rather than inheriting a stale down/hold-down state. A KEPT RG whose
ip-monitoring or targets merely changed is NOT purged here —
`reconcileRGIPDebts` owns that reconcile per-poll.

**Purge per-RG GARP count on RG removal (#6027).** `UpdateConfig` writes
`m.garpCounts[rg.ID]` ONLY when the config sets a positive
`gratuitous-arp-count`; the consumers (`pkg/vrrp`, `pkg/daemon`) treat an
absent entry as the default burst (3). The removal loop now
`delete(m.garpCounts, id)` alongside `monitorWeights` and `m.groups`, so a
same-id RG remove/re-add where the re-add omits an explicit count does not
inherit the prior incarnation's stale count — the entry stays absent and the
default applies. This is the third same-id-re-add map-lifecycle gap closed in
this loop, after the #5990 ip-monitor `ipState`/`ipDebts`/`ipThresholdState`
purge. The per-RG cleanup-on-removal maps are: `holdTimer` (stopped, #5245),
`monitorWeights` (interface + re-derivable ip debt), `garpCounts` (#6027), and
the group itself.

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
- **Owner-side transfer-out lease — a requester-side abort must not strand the
  demoted owner (#5079).** `RequestPeerFailover` drives the remote owner through
  `ManualFailover` (SecondaryHold, VRRP resigned) on the ACK, BEFORE the
  requester runs its own post-ACK readiness/commit checks. If a requester-side
  step fails after the ACK, `abortRequestedPeerFailover` rolls back only the
  requester's LOCAL override — it sends no abort frame to the owner, and the
  requester may roll back to a HEALTHY secondary. The pre-existing dual-resign
  guard in `electRG` never rescues this: it clears `ManualFailover` only when the
  PEER is itself resigned (weight 0) or in secondary-hold, not when the requester
  is a healthy secondary — so the owner would sit in secondary-hold forever and
  the cluster is left with NO primary (both secondary). Fix: the owner arms a
  **reqID-bound auto-restore lease** (`ArmRemoteTransferOutLease`) when a REMOTE
  request demotes it; the matching commit clears it (`ClearRemoteTransferOutLease`,
  reqID-bound so a stale commit cannot clear a newer request's lease). If the
  lease expires with no commit — abort, requester crash, or fabric loss — `electRG`
  restores the owner (clears `ManualFailover`, restores monitor-derived weight,
  re-elects). This is receiver-only self-healing: NO new wire frame (the reqID
  already rides the failover request/commit payloads), so no mixed-base
  compatibility concern, and it defends against requester death/partition that an
  abort frame could not. Only a REMOTE transfer-out arms a lease; `ManualFailover`
  / `ManualFailoverBatch` / `ForceSecondary` / `ResetFailover` clear any stale
  entry at their demotion/reset site so a deliberate operator or ISSU hold is
  never auto-restored (`ResetFailover` clears it for map hygiene — its restore is
  already gated on `ManualFailover`, which the reset clears; #6301). The lease
  duration (`SetRemoteTransferOutLeaseDuration`, default
  `DefaultRemoteTransferOutLease` = 30s, floored at 15s) is sized above the
  requester's worst-case post-ACK commit latency (local commit-ready settle +
  commit round-trip) so a legitimate slow commit never trips it. The upstream 20s
  failover-ACK cap (`failoverAckTimeout`, `sync.go`) further bounds this: if the
  owner's actuation barrier delays the applied-ack past 20s the requester times
  out and sends NO commit — the exact stranded case the lease-expiry restore
  handles — so a large `failoverActuateTimeout` cannot delay a real commit past
  the lease. reqID is threaded
  into `OnRemoteFailover`/`OnRemoteFailoverBatch`/`OnRemoteFailoverCommit`/
  `OnRemoteFailoverCommitBatch` (`sync.go`) to arm/clear it.
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
- The incremental sync sweep (`sync_conn_sweep.go`) re-syncs a session ONLY on
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
  (`sync_conn_gen.go`/`sync_bulk.go`) stamps installs from a single boot-seeded
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
- **Config-epoch guard (#5274)**: distinct from the per-key install generation,
  every session install carries a `ConfigEpoch` — the #3931 config-sync
  generation (`configGenCounter`) the sender held when it queued the session
  (`stampInstallGen*`), as a length-gated trailing `uint64` on the session wire
  (`sync_protocol.go`). The receiver (`installClusterSynced*`) refuses an install
  whose epoch is **strictly older** than its `lastAppliedConfigGen`
  (`SessionsStaleConfigIgnored`), because the peer has since committed — and this
  node has applied — a newer config that may DENY the session. This closes the
  immediate-policy-invalidation gap: a session admitted under config A that lands
  after config B's `clearSessionsForDeletedPolicies` sweep is a stale permit the
  standby would otherwise forward under after failover. Both the stamp
  (`configGenCounter`) and the compare (`lastAppliedConfigGen`) are in the SAME
  sender→receiver #3931 namespace, so the comparison is meaningful across nodes.
  `epoch == 0` (legacy peer / local-origin) disables the check (rolling-upgrade
  safe); the reconnect `resetRecvGen` zeroes `lastAppliedConfigGen` so a
  rebooted-peer bulk re-prime is never falsely rejected. **That zeroing is
  serialized against every advance of the mark by `configGenMu` (#5084)** — the
  advance is a load/compare/store and the clear runs on a different goroutine
  (a receive loop, versus `configApplyLoop` for the applied mark and the *other*
  receive loop for the received mark), so a clear could land inside an advance
  and be lost, leaving a pre-reboot generation that refuses every generation the
  reconnected peer can produce. Writers of the three config-generation marks:

  | writer | mark(s) | goroutine | synchronisation |
  |---|---|---|---|
  | `recordAppliedConfigGen` | applied | `configApplyLoop` | `configGenMu` |
  | `recordRecvConfigGen` | received | receive loop (×2) | `configGenMu` |
  | `beginConfigApply` / `endConfigApply` | applying fence | `configApplyLoop` | `configGenMu` |
  | `resetRecvGen` | all three, clear to 0 | receive loop (×2) | `configGenMu` |
  | `initGenState` | all three | `NewSessionSync` | none — pre-`Start`, no goroutines yet |

  Readers stay lock-free (the marks are atomics and `configEpochStale` runs per
  synced session install); a reader racing a writer observes one side of a
  single monotone step, which is the tolerance the marks already had. **The guard is
  Go-cluster-authoritative** — the userspace helper's `config_generation` is a
  *local* commit counter (`Manager.bumpGeneration`) that is not cross-node
  comparable, so the receiver rejects the stale install BEFORE forwarding it to
  the helper, and no config-epoch field or guard is added on the Rust side.
  **Apply-in-progress fence (#6284, item 2):** the bare `epoch <
  lastAppliedConfigGen` compare closes the gap only once the high-water has
  advanced, but the high-water advances AFTER `OnConfigReceived` returns while
  the `clearSessionsForDeletedPolicies` sweep runs INSIDE it — leaving a sub-µs
  window where a racing install is admitted against the stale high-water.
  `configApplyLoop` raises `applyingConfigGen` to the generation it is applying
  BEFORE the apply and lowers it only AFTER the high-water advances (success) or
  the apply fails; `configEpochStale` refuses against `max(applyingConfigGen,
  lastAppliedConfigGen)` (fence read first), so an older-epoch install racing the
  window is refused against the applying generation instead of admitted. The
  guard still covers only the config-authority → peer direction; the reverse
  active/active direction stays a documented fail-OPEN residual on #6284 (item 1,
  needs a bidirectional config-gen namespace #5274 scoped out).
- **RT_FLOW session id (#5212)**: distinct from BOTH the synthesized BPF-ABI
  `SessionID` (`now<<16|slot`, node-local) AND the per-key install generation,
  every session install carries the ORIGINATING node's stable RT_FLOW session id
  (`SessionValue{,V6}.RTFlowSessionID`, the dataplane's
  `SessionTable::alloc_session_id` value) as a length-gated trailing `uint64` on
  the session wire (`sync_protocol.go`, appended after the #5274 `ConfigEpoch`).
  Unlike the guards above this is pure identity carriage — the receiver never
  rejects on it. The peer helper's `upsert_synced_with_origin` ADOPTS the id on
  import (via `SessionSyncRequest.session_id` → `build_synced_session_entry`)
  instead of minting a fresh node-local one, so a session's RT_FLOW
  SESSION_CREATE (origin node) and SESSION_CLOSE (peer, after failover) share one
  correlatable id across HA nodes. `id == 0` (legacy peer / synthesized delta)
  falls back to a fresh local id (rolling-upgrade safe). Full path:
  `docs/sync-protocol.md` "RT_FLOW Session Id (#5212)".
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
