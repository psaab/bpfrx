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
  **The unit is a peer SESSION, not a peer daemon boot.** A session id is
  minted per `heartbeatSender`, so every peer heartbeat restart (VRF rebind,
  HA comms restart) mints a fresh one with no reboot involved. So the 65 above
  is 65 recorded heartbeat sessions — cheaper to harvest than 65 daemon
  incarnations — and routine peer restarts consume ring slots permanently now
  that the ring outlives a local restart. Neither is a regression: before
  #5086 any local heartbeat restart wiped the ring entirely, so this worst
  case is a strict subset of the previous one. A complete fix
  needs a boot-epoch / monotonic-across-reboot counter carried in the frame
  (a wire change) — tracked as a follow-up (#6169). The map still causes NO
  genuine-peer lockout (an evicted live watermark just makes the peer's next
  frame never-seen → admitted) and cannot grow memory (fixed 64 slots).
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
  **Residual, unchanged by #5086:** the state is in memory, so a full
  daemon restart or reboot still starts with an empty tracker and a
  captured run replays once against the restarted node. Closing that
  needs the same signed boot-epoch as the ≥65-recording churn — both are
  #6169. #5086 removes the vectors an attacker can reach without the
  survivor restarting its whole daemon.
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
  `SessionID` (node-local, minted per converted session by
  `nextUserspaceSyncedSessionID` since #6198) AND the per-key install generation,
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
