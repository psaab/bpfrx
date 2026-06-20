# pkg/vrrp

Native VRRPv3 (RFC 5798) state machine. ~60 ms failover with 30 ms RETH
advertisements, IPv6 support, AF_PACKET RX fallback for VLAN
sub-interfaces, async GARP burst on `becomeMaster`, and sync-hold
preemption control for HA bulk session sync.

This is the package that drives chassis-cluster failover.

## Entry points

- `Manager` — `manager.go`. Owns every `Instance` goroutine, the event
  channel, and sync-hold state.
- `Instance` — `vrrp.go`. Per-RG config: interface, group ID, VIPs,
  priority, preempt, timers.
- `VRRPEvent` — `instance.go`. INIT / BACKUP / MASTER transitions.
- `NewManager()` — `manager.go`.
- `Start(ctx context.Context) error` — `manager.go`. **Returns
  immediately** after wiring `m.cancel`. Per-instance goroutines run
  independently and observe their own `stopCh`, **not** the parent
  context. Stop them via `Stop()`, which closes each instance's
  `stopCh`.
- `Stop()` — `manager.go`.
- `UpdateInstances(desired []*Instance) error` — `manager.go`.
- `ReleaseSyncHold()` — `manager.go`. No-arg; releases hold for all
  instances.
- `ResignRG(rgID int)` — `manager.go`. Forces this node out of master
  for the given redundancy group ID.

## File layout

- `manager.go` — redundancy-group coordinator: `Manager`, instance
  diff/lifecycle, sync-hold, RG force/resign helpers, socket helpers.
- `instance.go` — per-instance state machine, RX receivers, advert
  send, VIP add/remove, GARP/NA.
- `packet.go` — VRRPv3 advert parser/builder + IPv4/IPv6 checksums.
- `track.go` — interface tracking (#1814): the per-instance
  effective-priority primitives (`getPriority`, `setTrackDown`,
  `trackedInterface`) and the manager-side singleton link-watcher /
  poller (`runLinkWatcher`, `runLinkPoller`, `pollTrackedLinks`,
  `applyTrackedLinkState`, `seedTrackState`, `netlinkLinkState`,
  `linkAttrsUp`).
- `vrrp.go` — `Instance` config type plus `CollectInstances` /
  `CollectRethInstances` config extraction.

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

`pkg/config`, `pkg/cluster`.

## Failover timing (CLAUDE.md authoritative)

- ~60 ms with 30 ms RETH advertisements (masterDownInterval ~97 ms).
- Planned shutdown: 3× priority-0 advert burst → peer takeover ~1 ms.
- Heartbeat 200 ms, threshold 5 (1 s detection).
- Async GARP: first pair <1 ms; remaining sent at 50 ms intervals in a
  background goroutine. Critical path stays addVIPs → sendAdvert →
  emitEvent (sync), then `go sendGARP()` (async).
- Event debounce 500 ms before priority updates.
- Sync hold: VRRP starts with `preempt=false`; released after bulk
  session sync (or 10 s timeout). `preemptNowCh` triggers instant
  preemption when sync completes early.
- Sync-hold preempt gate (#2082): the non-force `preemptNowCh` shortcut
  is peer-priority gated. `becomeMaster()` runs on the kick only when the
  node's **effective** priority is **strictly greater** than the last
  observed master's (RFC 5798 §6.4.2 — equal priority does NOT preempt;
  no IP tie-break, that resolves a MASTER-MASTER collision in
  `handleMasterRx`, not preemption). A lower-priority preempt-enabled node
  (e.g. a rejoining cluster Secondary at priority 100) therefore no longer
  transiently becomes a second MASTER on sync-hold release while a
  higher-priority peer is legitimately MASTER. `handleBackupRx` /
  `handleMasterRx` record each non-zero peer advert
  (`lastMasterPriority`/`lastMasterSeen`); priority-0 resignation adverts
  are not recorded (post-resign takeover flows through the ungated
  `masterDownTimer` path). Staleness — no master seen, or last seen older
  than `masterDownInterval` — is treated as "no live master", allowing
  cold-start / silent-master-death takeover. `ForceRGMaster` (force=true,
  cluster-authoritative Secondary→Primary promotion) bypasses the gate
  unchanged, so the ~60 ms failover path is untouched. The gate only
  governs the shortcut: a denied gate never stops `masterDownTimer`, so the
  normal RFC election still promotes the node when the real master dies.

## Interface tracking (#1814)

Single-interface tracking per VRRP group:
`track-interface <if> { priority-cost <n>; }` (nested Junos form) or the
legacy flat sibling `track-priority-cost <n>`; nested wins when both are
present. Multiple `track-interface` statements in one group are rejected
at commit (strict) and first-wins with a warning on the tolerant
load/peer-sync compile paths.

- **Effective priority** — `getPriority()` (`track.go`) returns
  `Priority - TrackPriorityCost` clamped to **[1, 254]** while the
  tracked link is down. Tracking can never fabricate the priority-0
  resignation sentinel (priority 0 passes through unchanged), and
  **priority 255 (address owner) is exempt** — an owner stepping down
  while still holding the address invites duplicate-IP conflicts; the
  compiler warns instead.
- **Link watcher** — ONE singleton goroutine per Manager
  (`runLinkWatcher`, `track.go`), started lazily when an instance
  tracks an interface; latched under the manager mutex so
  `UpdateInstances` churn never spawns a second. Subscribes via
  `netlink.LinkSubscribe` with done-channel cancellation closed from
  `Stop()`; on subscribe failure it degrades to a 1 s poll. Initial
  state is seeded with `netlink.LinkByName` at instance create/update
  (a missing tracked interface counts as down). The tracked-ifname →
  instance mapping is re-read under lock per event.
- **Takeover latency** — a demoted MASTER keeps advertising at the
  lower effective priority; a preempt-enabled backup hearing a LOWER
  advert ignores it and waits for masterDown expiry, so takeover lands
  in ~masterDownInterval (≈97 ms at 30 ms adverts, ≈3.3 s at 1 s
  adverts) per RFC 5798 — no forced abdication.
- **Cluster note** — tracking applies to standalone VRRP instances
  (`CollectInstances`). RETH instances (`CollectRethInstances`) never
  carry track config, and RETH VRRP is suppressed entirely under
  `no-reth-vrrp` / `PrivateRGElection` — no chassis-cluster interaction.
- `CollectInstances` normalizes `TrackInterface` from the Junos name
  (`ge-0/0/1`) to the Linux name (`ge-0-0-1`) so netlink matching works.

## Sockets

- IPv4: per-instance raw socket (proto 112) plus AF_PACKET fallback for
  VLAN sub-interfaces (the kernel's raw IP doesn't reliably receive
  multicast on VLANs).
- IPv6: separate raw socket; hop limit set to 255 per RFC.

## Gotchas

- Use the **non-VIP** primary IP as source on advertisements. Sourcing
  from the VIP would self-filter peer adverts.
- RETH virtual MAC per node: `02:bf:72:CC:RR:NN`. Programmed via link
  DOWN → set MAC → link UP. This bounces all kernel addresses; VIPs are
  re-added by `ReconcileVIPs()` immediately afterwards.
- Bind retry on simultaneous boot avoids losing the master election to
  whichever node booted first.
- Event channel is bounded at 256; backpressure increments an atomic
  counter and triggers a reconciliation callback. Don't switch to an
  unbounded channel — the counter is the early warning that something
  upstream stopped draining.
