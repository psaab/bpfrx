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
  Diffs the running instance set against the desired set. A VIP change
  forces an instance restart, which is done **build-before-teardown**
  (#2156): the replacement's interface is resolved and its socket opened
  (the "proof" step) BEFORE the old instance is stopped and removed. A
  transient member-link failure (carrier flap, mid-rename by networkd)
  therefore leaves the old instance running and advertising its old VIPs
  rather than orphaning the RG out of election. Priority/preempt/track
  changes still update in-place (no restart, no master-down gap).
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
  emitEvent (sync), then `go sendGARP(false)` (async).
- GARP suppression gates: `sendGARP(force)` has two gates — a per-epoch
  dedup (`garpEpoch`/`lastGARPEpoch`, one burst per transition) and a
  500 ms time dampener (`lastGARPTime`/`garpDampened`, storm control for
  rapid flaps). `force=true` bypasses ONLY the dampener (the epoch dedup
  still applies). `becomeMaster` and the periodic path pass `force=false`;
  `ReconcileVIPs` passes `force=true` because the RETH MAC just changed and
  the correction GARP must not be swallowed by a routine burst that fired in
  the prior 500 ms (#2081). The decision lives in the network-free helper
  `garpSendAllowed`, which is unit-tested directly.
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

### Receiver goroutine model

When AF_PACKET opens (`afPacketFD >= 0`), a single `receiverAfPacket()`
goroutine handles both IPv4 and IPv6 (it captures full link-layer frames
and dispatches by EtherType). When AF_PACKET is unavailable, `run()`
falls back to the raw-socket path and starts **two concurrent receiver
goroutines** — `receiver()` (IPv4 raw, proto 112) and, if an IPv6 socket
exists, `receiverIPv6()` (`ip6:112`). Both feed the same per-instance
`rxCh` and, on a full channel, both call `warnRXDrop()`. Every field
they share on that drop path is therefore concurrency-safe: `rxReceived`
and `rxDrops` are `atomic.Uint64`, and `lastDropWarn` (the once-per-10s
warning rate-limiter) is an `atomic.Int64` of Unix nanos updated with
`CompareAndSwap` — only the goroutine that swaps the stale timestamp logs
the warning, so a concurrent drop burst yields one log line per interval
(#2225, mirrors the `lastGARPTime` dampener). A plain `time.Time` here
was an unsynchronized read-modify-write across the two goroutines (a
`go test -race` data race).

### AF_PACKET cBPF filter + IPv6 extension headers (#2155)

The AF_PACKET receiver attaches a cBPF prefilter
(`openAfPacketReceiver`, `manager.go`) so the kernel drops non-VRRP
frames before they reach the per-instance RX goroutine. It handles
untagged and 802.1Q-tagged IPv4/IPv6:

- IPv4 matches base protocol `== 112`; `parseAfPacketIPv4` then
  re-walks IHL + re-checks TTL 255 in Go (so IPv4 options are tolerated).
- IPv6 matches the base **Next-Header** against the set
  `{112 VRRP, 0 Hop-by-Hop, 43 Routing, 60 Dest-Opts}`
  (approach A2). A chained VRRP advert's base Next-Header is the FIRST
  ext-header's type, not 112, and a fixed-offset cBPF cannot walk an
  ext-header chain — so admitting these ext-header types lets any
  conformant advert through while ordinary IPv6 TCP/UDP/ICMPv6/ND stays
  kernel-dropped on a data-bearing RETH VLAN (e.g. `reth0.80`).
  Fragment (44) and AH (51) are deliberately **not** admitted: VRRP is
  never legitimately fragmented (no reassembly) and never IPsec-AH-wrapped
  (it authenticates itself), so such frames stay kernel-dropped instead of
  waking the RX goroutine only for the Go walker to drop them. The cBPF is
  only a volume reducer; authoritative validation is in Go.

`parseAfPacketIPv6` performs a **bounded** IPv6 ext-header walk
(`walkIPv6ExtHeaders`) to locate the real proto-112 payload offset
instead of assuming the old fixed 40-byte base header. Conventions and
explicit drop bounds (deliberate, documented):

- Hop-by-Hop (0) / Routing (43) / Dest-Opts (60) are the only chained
  headers a conformant advert can carry; each is `(HdrExtLen+1)*8` bytes
  (8-byte units) and is walked to the next header.
- Fragment (44) is a **hard drop** — VRRP adverts are never legitimately
  fragmented and the receiver does no reassembly. The cBPF prefilter
  already refuses base Next-Header 44, so the walker's drop is
  defense-in-depth for a Fragment header buried mid-chain.
- AH (51) and any other Next-Header is **dropped** — VRRP is not
  IPsec-AH-wrapped, so AH is not a VRRP carrier. The cBPF likewise
  refuses base Next-Header 51, so an AH-first advert is kernel-dropped
  before the walk runs.
- The walk is capped at 8 iterations and bounds-checks every step
  against the captured length, so a truncated or maliciously long chain
  can neither loop nor read out of bounds — it is simply dropped.

The raw `ip6:112` socket fallback (non-AF_PACKET path) is ext-header-safe
for the common extension headers because the kernel walks the chain and
hands `ReadFrom` the upper-layer payload directly. AH and fragmented
VRRP are out of scope on **both** paths — the cBPF, the Go walker, and the
fallback all agree that only `{112, 0, 43, 60}` carry a VRRP advert.

**Homogeneous-peer expectation:** xpf's own IPv6 sender emits a bare
base header (no ext-headers, hop-limit 255) per RFC 5798, which is the
normal way VRRPv3 IPv6 adverts are sent. The ext-header walk exists only
to interoperate with an unusual non-xpf VRRP speaker that inserts
extension headers; deploy homogeneous xpf peers and this path is never
exercised.

**Deliberately separate from the Rust dataplane walkers (#2150):** this
Go `walkIPv6ExtHeaders` is a parallel, intentionally non-shared
implementation. The Rust AF_XDP dataplane has its OWN canonical IPv6
ext-header walker (`userspace-dp/src/afxdp/frame/inspect.rs::packet_rel_l4_offset_and_protocol`,
#2148) and its own L2 parse contract (see
`userspace-dp/src/afxdp/frame/README.md`, #2150). Code cannot be shared
across the Go/Rust boundary, so any change to the ext-header walk
semantics must be mirrored by hand in both — do NOT assume the Rust
dataplane reuses this Go walker, and do NOT try to consolidate them.

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
- Instance restart on VIP change is **build-before-teardown** (#2156):
  the new socket must open before the old instance is stopped, so the
  old `run()` goroutine and the new one never run concurrently for the
  same key (the proof step opens the socket but does NOT start `run()`;
  only the commit step stops the old, swaps, and starts the new). On a
  build failure no placeholder is added to `m.instances`, so
  `RGVRRPReady` / `States` / `InstanceStates` / `Status` stay truthful.
  Bounded self-recovery comes from the daemon's 2s
  `reconcileRGStateLoop`, which re-drives `reconcileVRRPInstances` →
  `UpdateInstances` every tick; a deferred restart retries (and succeeds)
  once the interface returns, with no operator re-commit. During the
  failure window the RG keeps advertising the OLD VIP set — strictly
  better than dropping out of election; the intended VIPs land on the
  next successful re-drive (~2s).
- The instance-lifecycle seams (`resolveIface`, `openInstanceSocket`,
  `runInstance`, `stopInstance`) and link seams (`linkState`,
  `subscribeLinks`) exist so unit tests exercise the diff/lifecycle logic
  without real netlink, raw sockets, or live goroutines. Production
  defaults are wired in `NewManager`; do not change a seam's production
  default without updating the matching test fakes.
