# HA Failover Status

Date: 2026-05-21 (updated)

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
- Takeover readiness gates on proven userspace dataplane health (#391): the
  control socket + ping, forwarding armed, XSK liveness, session mirror health,
  AND — since #5273 — the local event-stream listener being bound
  (`EventStream.ListenerBound()`). The listener is the primary local
  helper-to-daemon push path feeding the peer-sync pipeline, so a node whose
  `net.Listen` failed to bind is denied takeover readiness rather than silently
  starting in the slower `DrainSessionDeltas` polling fallback. The gate keys on
  the listener being UP, not on the local helper currently being connected;
  transient stream disconnects are covered by polling
- The takeover readiness gate applies on COLD BOOT, not only when the peer is
  alive (#7161). `electSingleNode` previously gated on `m.peerAlive`, so the
  gate was fully enforced on the peer-alive path and fully bypassed on the
  peer-dead path — which is the path both a cold boot and a peer loss take. The
  condition is now `(m.peerAlive || !m.peerEverSeen)`:
  - **peer LOSS** (`peerEverSeen && !peerAlive`) keeps the fail-open. An
    established cluster had a working primary and it died; a survivor that
    refuses takeover is a TOTAL OUTAGE and may be the only node that can
    forward.
  - **cold BOOT** (`!peerEverSeen`) applies the gate. There is no established
    forwarding to preserve, and a not-ready node that promotes forwards nothing
    anyway — it claims the VIPs and the RG while unable to serve them, and
    denies the peer a clean takeover. This is #103 acceptance criterion 1.

  **POLICY CHANGE, declared:** a userspace-configured data RG with no published
  dataplane fail-closes in `checkUserspaceTakeoverReadinessFor`, so on a cold
  boot it now stays SECONDARY where it previously promoted. It forwards nothing
  either way; the difference is that it now says so instead of advertising
  itself primary for traffic it cannot carry.

  The prior in-code rationale ("sync readiness is impossible without a peer")
  was stale and has been replaced rather than narrowed: sync readiness is not a
  term in that conjunction at all. `IsReadyForTakeover` consults local
  interfaces, local VRRP and the local userspace dataplane — all determinable
  with no peer — and `fabricReady` is already forced true when the peer is down.

  **Degraded-promotion fallback** (`DefaultDegradedPromoteTimeout`, 2 min): after
  that much CONTINUOUS not-readiness a single node promotes anyway, with the
  reason surfaced on the election event and `DegradedPromoted` set, so a
  readiness bug can never cost the cluster both nodes. Two properties are
  load-bearing and are pinned by tests:
  - it is gated on NO peer condition — not `peerAlive`, not `peerEverSeen`, not
    sync connectivity. #110 shows the failure mode: `armSyncReadyTimer`'s
    callback bails on `!d.syncPeerConnected`, so its fallback never fires in
    exactly the peer-absent case it was written for. A fallback whose firing
    depends on the condition it compensates for is not a fallback.
  - it is armed at the DECLINE SITE in `electSingleNode`, not in `SetRGReady`. A
    cold-boot RG starts not-ready and may never see a readiness TRANSITION, so
    arming from the transition branch would leave it unarmed in precisely the
    case it exists for.
- Bounded startup promotion hold for `no-reth-vrrp` / `private-rg-election`
  (#7162). RETH VRRP mode has suppressed startup preemption since #466
  (`vrrp.Manager.SetSyncHold`, 30s, armed once at bringup, released by bulk
  session sync or its own timer). These modes had no equivalent —
  `checkNoRethTakeoverReadiness` was VIP ownership and nothing else — so a node
  could promote an RG before bulk sync delivered any conntrack/NAT state and
  every established flow reset on the transition.

  `Daemon.armNoRethSyncHold` (`pkg/daemon/daemon_ha_noreth_hold.go`) is the
  sibling: same 30s bound, armed at the same bringup site, consulted by
  `checkNoRethTakeoverReadiness`, released by bulk sync
  (`bulk-sync-complete`) or its own timer (`timeout-degraded`).

  **It is a bounded HOLD, not a `cluster.IsSyncReady()` conjunct, and the
  difference is the whole of #110.** `syncReady` has no bound while the
  session-sync channel is down (`armSyncReadyTimer` early-returns unless
  `syncPeerConnected`), and the election blocks a not-ready RG whenever the peer
  is alive — so a sync-flag conjunct blocks promotion INDEFINITELY when the peer
  is up on the control link with session sync down, which is exactly the
  degraded-peer case preemption exists for. Two properties keep this one
  bounded, and both are pinned by tests:
  - the timer callback consults NO peer condition — not `syncPeerConnected`, not
    `peerAlive`, not `IsSyncReady()`. A release that depended on the peer would
    be no release at all, because the peer being absent is why the hold is still
    held.
  - it is armed EXACTLY ONCE at bringup and never re-armed on reconnect, which
    keeps it a startup hold rather than a mid-life block.

  Releasing the hold DRIVES a reconcile (`triggerReconcile`). Readiness is
  recomputed per reconcile pass, so without that the RG would sit secondary until
  an unrelated event happened to trigger one — bounded in name only. The RETH
  sibling meets the same obligation with `triggerPreemptNow()`.

  **Deploy-tooling coupling (#7962).** `cluster-deploy`'s post-deploy primary
  reassert waits on this fallback, because on an idle cluster it is the only
  path to convergence: XSK liveness cannot self-prove on a node holding a data
  RG (`shouldAutoProveIdleStandbyXSKLocked` requires `!hasActiveDataRGLocked()`,
  and node0 holds RG1), and nothing is driving traffic. The reassert's budget
  was 30s against a 120s fallback, so it failed **by construction** on a
  restarted idle cluster — and both its passes and its failures were timing
  artifacts, indistinguishable from an HA regression in whatever branch happened
  to deploy next (#7688, #7939).

  The reassert now (a) PRIMES liveness with a little LAN→WAN traffic, which is
  what an operator does by hand and converges the common case in seconds rather
  than waiting out the fallback, and (b) falls back to a budget derived from
  `DefaultDegradedPromoteTimeout` only when priming was impossible — so a
  failing deploy is not routinely slower. `DEPLOY_REASSERT_FALLBACK_BUDGET_S`
  (`test/incus/deploy-lib.sh`) and this constant are coupled by
  `TestDeployReassertBudgetExceedsDegradedFallback7962`, which reads the shell
  default and fails if either side moves such that the budget stops covering the
  fallback.

  Its failure message now distinguishes the two states it used to crush into
  one: *traffic was driven and the dataplane still did not prove liveness* (a
  real signal) versus *traffic could not be driven, so the precondition was
  absent* (not an HA regression).

  Interaction with #7161: on a cold boot the readiness gate now applies, so the
  hold and the gate compose — the node holds secondary for the hold window, then
  promotes when readiness recomputes. The #7161 degraded-promotion fallback
  (2 min) is a strictly longer backstop, so the 30s hold is the binding
  constraint.

  **Observability:** `show chassis cluster information` gains a
  `Startup promotion hold:` block reporting the mode (`reth-vrrp` / `no-reth`),
  whether it is still holding, and how it ended. The RETH hold had recorded
  `bulk-sync-complete` / `timeout-degraded` since #466 and surfaced it NOWHERE,
  so an operator could not distinguish a normal startup from one that promoted
  degraded because sync never arrived — which is precisely the explanation for a
  flow reset after a boot. While the hold is active it also appears in the RG's
  `Takeover ready: no (...)` reasons.
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
- Manual/planned failover refuses a config-stale standby (#5563): transfer
  readiness now also gates on the config-sync generation. A standby that has
  received a newer config generation from the primary than it has successfully
  applied (`PeerConfigGen > AppliedConfigGen` in `TransferReadinessSnapshot`) is
  reported not transfer-ready, so `request chassis cluster failover` will not
  promote it onto a stale policy set (fail-open after a tightening commit,
  false-deny after a loosening one). A legitimate same-generation failover still
  proceeds; the unplanned/crash path is not gated. Surfaced in
  `show chassis cluster status` transfer-readiness reason as "standby config
  stale: applied gen=N behind peer committed gen=M"
- HA configs that use per-pool source NAT `persistent-nat` are not admitted to
  userspace forwarding because persistent-NAT leases are helper-local allocator
  state and are not HA-synchronized (#1449)

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

### Failover command/action grammar — one strict parser (#5810, #5851)

The manual-failover command and its wire action string are validated by a
single, side-effect-free grammar in `pkg/clusterfailover`. Every entry point —
the remote CLI (`cmd/cli/request.go`), the in-process CLI
(`pkg/cli/cli_request_chassis.go`), the gRPC loopback handler
(`pkg/grpcapi/server_diag_system_action.go`), and the fabric-allowlist
interceptor (`pkg/grpcapi/server.go` `parseProxiedFailoverAction`) — routes
through `clusterfailover.ParseCommand` (operator tokens) or
`clusterfailover.ParseAction` (wire string) and acts on the SAME typed
operation. Callers never assemble or partially parse the privileged action
string ad hoc.

The grammar is closed. Exactly four forms are accepted:

| Operation | Command | Wire action |
|-----------|---------|-------------|
| Plain RG failover (untargeted) | `redundancy-group <rg>` | `cluster-failover:<rg>` |
| Targeted RG failover | `redundancy-group <rg> node <0\|1>` | `cluster-failover:<rg>:node<0\|1>` |
| Data failover | `data node <0\|1>` | `cluster-failover-data:node<0\|1>` |
| Reset | `reset redundancy-group <rg>` | `cluster-failover-reset:<rg>` |

`<rg>` is a non-negative decimal group ID; `<0|1>` is a supported chassis node.
Unknown, missing, misspelled, duplicate, signed, whitespace-laden, or trailing
tokens — and an empty `:node` suffix — are rejected with usage/`InvalidArgument`
BEFORE any cluster method or peer dial. This closes the class where a truncated
automation variable or a typo (`redundancy-group 1 nod 0`, `redundancy-group 1
node`, or the gRPC `cluster-failover:1:node`) silently degraded to the broader
untargeted `ManualFailover(<rg>)`, moving ownership in an unintended direction.

The loopback handler and the fabric interceptor now share this parser, so they
can never disagree on which action strings are well-formed. The fabric gate may
still deny a valid but local-only form (plain RG failover, reset) by policy —
only the two node-targeted forms are proxyable — but that denial is a policy
choice, never a divergent parse. Shared accept/reject token-vector tables live
in `pkg/clusterfailover/grammarvectors` and are exercised by all four layers'
tests so the verdicts cannot drift.

## Persistent SNAT Lease Boundary

Synced sessions carry the translated tuple needed for active-flow return
traffic after failover. Per-pool `persistent-nat` leases are different: they
are helper-local allocator state used only for future source-side allocations
after the last live flow releases. The userspace helper does not synchronize or
replay those leases to the peer.

#1449 is closed as an admission boundary rather than partial lease replay. If
a chassis cluster config has any source-NAT rule that references a pool with
`persistent-nat`, userspace forwarding is marked unsupported with:

```
userspace persistent-nat source pool leases are not HA-synchronized
```

That reason is visible in helper status as `Forwarding blocked by: ...` and is
also propagated through takeover readiness. Operators should treat it as an
expected capability gate, not allocator exhaustion. Non-HA persistent pools
still report live-flow, used-port, persistent-lease, allocation, reuse, and
exhaustion counters.

A future change that admits HA persistent-NAT must add full lease sync or
replay, including tuple-conflict handling for live synced sessions and stale
lease cleanup.

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

#### Import refusals and the split-truth rollback (#6785)

The standby's install is transactional (#5305): the daemon snapshots the BPF
session row, writes it, mirrors to the helper, and RESTORES the snapshot if the
mirror fails — so a failed install never leaves a row for a session the helper
does not hold.

The helper can refuse an import for three SEMANTIC reasons, none of which are
faults:

| refusal | reason | issue |
|---|---|---|
| `stale-generation` | the stored entry is NEWER than the incoming one | #2170 |
| `capacity` | the aggregate synced-import entry ceiling is full | #5674 |
| `reserve` | the translated NAT tuple could not be reserved for this import | #6600 |

Before #6785 all three returned `ok = true`, so the daemon recorded a success
and left its BPF row behind — the exact split truth the transactional install
exists to prevent, on the one failure class it could not observe. The helper now
answers `ok = false` with a `synced-import-refused:<reason>` token, and the
existing rollback runs.

**A refusal is NOT a mirror failure, and the two must not be conflated.** A
transport failure means the helper session socket is sick and gates HA
takeover-readiness (#5247). A refusal comes from a HEALTHY helper answering
correctly — the peer sent something stale, or this node is at its own ceiling.
Gating takeover on a refusal would keep a working standby from ever taking over
once a peer oversubscribed it, which is worse than the divergence being fixed.
So a refusal:

- rolls back the local BPF row (no split truth),
- does **not** set the sticky session-mirror-failure flag,
- does **not** count toward the session-sync `Errors` total,
- counts into `Imports refused by helper`, rendered by
  `show chassis cluster information` only when non-zero.

That counter is health **debt**, not an error: the local state is consistent, but
the PEER believes it synced a session this node does not hold, and only the
peer's next full sync closes the gap. A persistently non-zero count means the
peer is oversubscribing this node.

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

### Watchdog heartbeat: map write every tick vs IPC on change/backstop (#2549)

The daemon runs a per-RG watchdog heartbeat (`pkg/daemon/daemon_ha_sync.go`)
on a 500ms ticker, writing a monotonic-seconds timestamp so a SIGKILL'd daemon
goes stale and the peer takes over. That timestamp lands in two places with
**different cadence requirements**, and `UpdateHAWatchdog`
(`pkg/dataplane/userspace/manager_ha.go`) decouples them:

- **Shim BPF `ha_watchdog` map write — EVERY tick (500ms), never throttled.**
  This is the kernel-visible liveness signal the BPF ~2s stale window compares
  against; it must stay fresh every tick. It is a cheap local map update, not a
  socket round-trip.
- **`update_ha_state` socket IPC — throttled.** The full HA-state JSON IPC over
  the shared Rust-helper control socket is the expensive part. Issuing it every
  tick is a 2/s-per-RG control-socket caller — exactly what the CLAUDE.md
  *Control socket contention* rule forbids (">1/s … will starve session installs
  during bulk sync"). It now fires only when:
  1. **An RG `Active` state CHANGES** (failover/failback) — published
     IMMEDIATELY. This is the load-bearing failover-timing path and is NEVER
     throttled. (The authoritative active-change publish is `UpdateRGActive`'s
     own direct `update_ha_state`; the heartbeat path also force-syncs on a
     detected per-RG `Active` delta as defense in depth.)
  2. **As a periodic BACKSTOP** — once the watchdog timestamp has advanced by
     `haWatchdogIPCBackstopSecs` (3s) since the last IPC for that RG, so the
     helper's view is refreshed well within its ~10s stale-lease window.

  Per-RG throttle state (`haWatchdogIPCSynced`, under `m.mu`) records the last
  timestamp/`Active` published per RG; the first heartbeat after startup/seed
  has no baseline and always syncs. The baseline is recorded BEFORE the send so
  a post-send error cannot cause a per-tick resync storm (the next ≤3s backstop
  retries), and `UpdateRGActive` records it too so the heartbeat does not
  redundantly re-fire right after a failover.

**Threshold rationale:** 3s gives a >3x margin under the helper's ~10s
stale-lease and drops the heartbeat's control-socket load from 2/s per RG to at
most ~0.33/s per RG (≈6x reduction), while the kernel-level liveness (the map
write) stays at the full 500ms cadence. Failover/failback timing is unchanged
because state changes bypass the throttle entirely.

**Live-config read every tick (#3917):** the heartbeat loop re-reads the
CURRENT redundancy-group set (`d.currentRedundancyGroups()` →
`d.store.ActiveConfig()`) on each tick rather than the `cc.RedundancyGroups`
snapshot captured when `startClusterComms` first ran. `startClusterComms` is
only restarted on a **transport-field** change (`clusterTransportKey`), so a
redundancy-group added by a day-2 commit would otherwise never receive a
watchdog write — its watchdog would stay stale and the dataplane would refuse
to forward for it. The loop is now gated on a published dataplane alone (no startup
RG-count precondition) so it also picks up the first RG added to a cluster that
booted with none.

### Peer fence reads the live config (#3917)

On a heartbeat timeout the surviving node sends a **fence** over the sync
channel; on receipt `OnFenceReceived` (`pkg/daemon/daemon_ha_sync.go`) must
deactivate `rg_active` for EVERY redundancy-group so the peer can own them
without a dual-active split-brain. The handler
(`d.fenceAllRedundancyGroups`) reads the CURRENT active config via
`d.currentRedundancyGroups()`, NOT the startup `cfg` closure. Before #3917 the
callback iterated the snapshot captured at `startClusterComms` time; because
comms are only restarted on a transport change, a day-2 redundancy-group was
absent from that snapshot and was **never fenced** — leaving it active on this
node while the peer also became active for it (split-brain dual-active, the
exact failure the fence exists to prevent). The handler is nil-safe in
config-only mode (no published dataplane) and when the config has no cluster stanza.

### Observing peer fencing (#72)

`show chassis cluster information` renders a **Peer fencing:** block whenever
`peer-fencing` is configured or a fence has ever fired on this node:

```
Peer fencing:
  Action: disable-rg
  Attempts:
    Aug 21 09:14:02  Fence disable-rg sent to peer
    Aug 21 09:31:47  Fence failed: peer not connected
```

`Action` is the CURRENTLY committed `set chassis cluster peer-fencing` value —
`disabled` when the leaf is absent — which can differ from the action the listed
attempts were recorded under, because the event history outlives a config
change. Each attempt line is one `handlePeerTimeout` fence decision and its
outcome.

### `disable-rg` — best-effort, unacknowledged

`SessionSync.SendFence` (`pkg/cluster/sync_failover.go`) writes `syncMsgFence`
and returns; nothing is sent back. A `sent to peer` line therefore means the
write reached the socket, not that the peer disabled its redundancy groups.
Local takeover is consequently NOT gated on the fence — `handlePeerTimeout`
runs `electSingleNode()` BEFORE it attempts the fence, so a dead peer (fence
unreachable) can never block the survivor from forwarding.

Attempt lines: `Fence disable-rg sent to peer`, `Fence failed: <err>` (the sync
channel was down — the node still takes over on the heartbeat timeout), or
`Fence skipped: sync not available` (no session-sync peer-fence function was
armed).

### `disable-rg-confirmed` — acknowledged, bounded, fail-open (#7147)

`set chassis cluster peer-fencing disable-rg-confirmed` sends a SEQUENCED fence
BEFORE the election and waits, bounded, for the peer to report what it
disabled. `SendFenceAwait` (`pkg/cluster/sync_fence_ack_7147.go`) writes
`syncMsgFence` carrying an 8-byte sequence number; the peer runs its fence and
replies `syncMsgFenceAck` (type 35) carrying that sequence, a status, and the
number of redundancy groups it drove to `rg_active=false` out of the number in
its live config.

**"Fenced" means peer-confirmed, not merely acknowledged.** The ack is written
only after the receiver's `fenceAllRedundancyGroups` has run, and only a
full-success result is reported as confirmed. A peer in config-only mode (no
published dataplane) replies `unavailable` rather than a vacuous success over
an empty RG set.

**The gate never withholds ownership.** Every negative outcome proceeds with the
takeover:

| Situation | Cost | Attempt line |
|---|---|---|
| Peer not connected | none — returns immediately | `Fence unconfirmed, took over anyway: peer not connected` |
| Peer predates #7147 | none — capability not advertised | `Fence unconfirmed, took over anyway: peer does not support fence acknowledgement` |
| Sync channel dropped mid-wait | none — waiter released at once | `Fence unconfirmed, took over anyway: session sync disconnected...` |
| Socket alive, peer silent | up to `FenceConfirmTimeout` (1 s) | `Fence unconfirmed, took over anyway: timed out after 1s...` |
| Peer partly fenced | none | `Fence NOT confirmed (peer disabled only 1/3 redundancy groups), took over anyway` |
| Peer confirmed | one fabric round trip | `Fence confirmed by peer (peer disabled 4/4 redundancy groups)` |

The only row that spends the timeout is one where the TCP socket is still up
but no ack comes back. The ordinary dead-peer takeover costs nothing extra,
because `SendFenceAwait` returns immediately when there is no active
connection — there is nothing to wait for.

A `Confirmations: received N, timed out N, sent to peer N` line accompanies
`Action` whenever the policy is armed or any ack traffic has occurred. Read
`timed out` as "takeovers that proceeded without the guarantee you selected";
it is the only place that number appears, since `Fences sent` counts a
confirmed and an unconfirmed takeover identically.

### What `disable-rg-confirmed` does NOT give you

**It reduces the split-brain window. It does not eliminate it, and the policy
name overclaims slightly — read this section, not the name.**

The residual is a partition in which the sync socket is LIVE BUT BLACKHOLED:
packets are being dropped, TCP has not yet timed out, so the connection is not
nil and the fence is written successfully, but no ack can come back. After
`FenceConfirmTimeout` this node takes over anyway while the peer may still be
alive and still forwarding. That is split-brain, and it is exactly the scenario
a fence exists to prevent.

**This is a deliberate trade, not an oversight.** The alternative — failing
CLOSED, refusing to take over without a confirmation — has the worse failure
mode for an appliance: a partition that never resolves leaves NOBODY
forwarding, and an HA pair that will not fail over has lost the property it
exists for. A bounded delay plus a smaller split-brain window is the trade on
offer here; a guarantee is not.

So an operator selecting this mode is buying:

- **confirmation when confirmation was available** — which is the common case,
  because the ack only has to arrive when the socket is genuinely healthy, and
  there a fabric round trip is milliseconds; and
- **ordering** in that case: this node does not claim the groups until the peer
  says it released them.

They are NOT buying "the peer is always confirmed down before I take over".

### Telling a confirmed fence from a fail-open — the event line is the only way

**The config knob cannot express the difference.** `Action: disable-rg-confirmed`
renders identically whether every takeover was confirmed or every one of them
fell open, so an operator reading only the configured action will assume the
stronger property. The `EventFence` attempt line is the discriminator, and it
is the ONLY one:

| Attempt line | What actually happened |
|---|---|
| `Fence confirmed by peer (peer disabled N/N redundancy groups)` | The guarantee held. The peer acknowledged relinquishing every RG before this node claimed them. |
| `Fence unconfirmed, took over anyway: <reason>` | **No confirmation.** Takeover proceeded regardless. The reason names which path — not connected, peer predates #7147, disconnected mid-wait, or timed out. |
| `Fence NOT confirmed (<detail>), took over anyway` | The peer ANSWERED but reported it had not fully complied (partial, or no dataplane). |

The `Confirmations: received N, timed out N, sent to peer N` line summarises the
same thing in aggregate; `timed out` is the count of takeovers that proceeded
without the guarantee. Neither `Fences sent` nor the configured action
distinguishes them, which is why both surfaces exist.

**Mixed-version clusters are safe and need no coordinated upgrade.** Both wire
changes are additive: `syncMsgFenceAck` is a new type that an old peer skips
via the receive switch's missing `default` arm, and the fence sequence is
trailing data on an existing type whose old receiver reads no payload. A
fence-ack capability bit rides the trailing byte of `syncMsgPeerCapabilities`
(#6650). Neither `SessionSyncWireVersion` nor `CurrentHAProtocolVersion` is
bumped — bumping would push `GateMixedBaseSwap`'s single-point compatibility
window off the peer's version and refuse the rolling upgrade this has to
survive. A mixed pair degrades exactly to `disable-rg` behaviour on both sides.

Do not read this block as the **Install fence:** block that appears above it in
the same output — that one reports the bulk-sync install barrier sequence
(`LastFenceSeq`), an unrelated mechanism.

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
# Hardened RG move under load (the primary validator).
# Keep the run long enough to expose late collapses, move RG1 quickly in both
# directions, and keep all eight stream lines visible during the run.
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=12 CYCLE_INTERVAL=5 \
scripts/userspace-ha-failover-validation.sh --duration 600 --parallel 8
```

```bash
# Reverse-path coverage is also required. The validator currently exercises the
# source-sending path, so run a matching reverse iperf after the forward pass.
iperf3 -c 172.16.80.200 -P 8 -t 600 -R
```

### Manual CLI test

```bash
# Start long-running forward traffic and keep all per-stream lines visible.
iperf3 -c 172.16.80.200 -P 8 -t 600

# Rapidly move RG1 between fw0 and fw1 while traffic is active.
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"

# Verify: SNAT > 0 on the new owner, no stream wedges at 0, and the run
# recovers back to full throughput after each move.
cli -c "show chassis cluster data-plane statistics" | grep SNAT
```

```bash
# Repeat the same RG movement under reverse traffic. This exercises the return
# path ownership and catches failovers that only work when the host is sending.
iperf3 -c 172.16.80.200 -P 8 -t 600 -R

cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
```

### Pass criteria

- All 8 iperf3 streams survive every RG move in both forward and reverse runs
- Zero per-stream zero-throughput intervals in both directions
- Zero aggregate zero-throughput intervals in both directions
- No permanently wedged stream after failback in either direction
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
