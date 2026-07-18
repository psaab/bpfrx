# Session Sync Architecture

## Overview

xpf HA clusters synchronize stateful firewall sessions between two nodes so
that a new primary can continue forwarding established flows after an RG move
or peer loss. Session sync rides a custom TCP protocol over the fabric link
(`fab0` / `fab1`).

The current implementation has four distinct pieces:

1. **Bulk sync** — cold transfer of the full owned session set on first
   connection after disconnect and when a different fabric transport becomes
   active.
2. **Incremental sweep** — periodic scan of kernel session maps for new or
   changed sessions.
3. **Userspace deltas** — low-latency event drain from the AF_XDP helper for
   userspace-managed sessions.
4. **Demotion handoff** — before graceful failover the demoting node writes a
   single ordered peer barrier (`WaitForPeerBarrier`) and waits for the ack, so
   demotion does not proceed until the peer has processed every delta already
   queued onto the sync stream.

The older mental model of "bulk once, then background sweep" is incomplete.
Current failover safety depends on sender-side bulk acknowledgement, the
continuous lossless userspace event stream (with gap → full-resync, see #2874),
the demotion peer barrier, and filtered userspace delta replication.

## Session Representation

### BPF Maps

Sessions live in two BPF hash maps:

- `sessions_v4` — IPv4 sessions
- `sessions_v6` — IPv6 sessions

Each logical session has two entries:

- forward entry: `IsReverse = 0`
- reverse entry: `IsReverse = 1`

Only forward entries are sent on the wire. The receiver recreates the reverse
entry locally.

### Session Value

The session value includes state, policy, timestamps, counters, NAT fields,
reverse key, and a cached forwarding result (`FibIfindex`, MACs, VLAN,
generation).

### Userspace Mirror

When the userspace dataplane is active, cluster-synced forward sessions are
installed into both places:

- the kernel/BPF session maps
- the Rust helper session table via the userspace manager RPC path

`SetClusterSyncedSessionV4()` / `SetClusterSyncedSessionV6()` do both. Before
install, they clear the cached FIB result so the receiving node recomputes
node-local forwarding.

Locally-created forward sessions take a parallel path: `SetSessionV4()` /
`SetSessionV6()` install into the kernel/BPF maps, then mirror the forward
entry **and a pre-installed reverse companion** (#310 — so the helper holds the
reverse before RG activation, avoiding activation-time synthesis) to the local
Rust helper over the session control socket. Both requests resolve
egress/zone/tunnel-endpoint metadata from `m.lastSnapshot` and the compile
result. **#5007 invariant: the forward/reverse pair MUST be resolved against
ONE consistent snapshot.** The mirror helpers (`mirrorSessionPairV4` /
`mirrorSessionPairV6`) build BOTH `SessionSyncRequest`s under a single
uninterrupted `m.mu` hold — completing every snapshot read *before* any socket
I/O drops the lock — then transmit both via `syncSessionRequestsLocked`, which
releases `m.mu` for the send. This preserves the deliberate "session installs
must not block snapshot publishes" property while closing the window where a
concurrent `ApplyConfig` (which swaps `m.lastSnapshot` under `m.mu`) could make
the reverse companion resolve against a different snapshot than the forward.

That is only one direction of the userspace integration. Locally-created
userspace sessions do **not** flow back through `SetClusterSyncedSession*`.
They are exported through:

- the continuous userspace event stream (steady state), or its
  `DrainSessionDeltas(...)` fallback poll when the stream is down
- a one-shot `ExportOwnerRGSessions(...)` bulk republish, triggered by an
  event-stream **FullResync** (a #2874 sequence gap or a #2442 delta-ring
  overflow) — **not** by the demotion-prep path

## Wire Protocol

### Transport

Session sync uses TCP over the fabric overlays:

- `fab0` — primary fabric
- `fab1` — optional secondary fabric

When a management VRF (`vrf-mgmt`) is configured, sockets are bound to it with
`SO_BINDTODEVICE`; otherwise they use the default routing table. One
deterministic side initiates per fabric. `TCP_NODELAY` is enabled.

### Header

```
[0:4]   Magic "BPSY"
[4]     Type (uint8)
[5:8]   Reserved
[8:12]  Payload length (uint32, little-endian)
```

### Message Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| 1 | SessionV4 | Primary -> Secondary | Incremental IPv4 add/update |
| 2 | SessionV6 | Primary -> Secondary | Incremental IPv6 add/update |
| 3 | DeleteV4 | Primary -> Secondary | IPv4 delete |
| 4 | DeleteV6 | Primary -> Secondary | IPv6 delete |
| 5 | BulkStart | Primary -> Secondary | Start of bulk transfer |
| 6 | BulkEnd | Primary -> Secondary | End of bulk transfer |
| 7 | Heartbeat | Bidirectional | Keepalive |
| 8 | Config | Primary -> Secondary | Full config text |
| 9 | IPsecSA | Primary -> Secondary | IPsec connection names |
| 10 | Failover | Bidirectional | Remote failover request |
| 11 | Fence | Bidirectional | Peer fencing |
| 12 | ClockSync | Bidirectional | Monotonic clock exchange |
| 13 | Barrier | Primary -> Secondary | Ordered demotion marker |
| 14 | BarrierAck | Secondary -> Primary | Barrier acknowledgement |
| 15 | BulkAck | Secondary -> Primary | Bulk acknowledgement |

## Bulk Sync

### When It Triggers

Bulk sync is started when:

- the first session-sync connection appears after a total disconnect
- a different fabric connection becomes the active transport

On first connection after disconnect, the transport setup order is:

1. flush the delete journal
2. fire `OnPeerConnected`
3. start `BulkSync()`

That order matters because reconnect readiness and retry state are reset before
the new bulk is sent.

### Send Side

`BulkSync()`:

1. allocates a new monotonically increasing epoch
2. sends `BulkStart(epoch)`
3. iterates `sessions_v4` / `sessions_v6`
4. skips reverse entries
5. skips sessions not owned by this node for the ingress zone
6. sends forward entries only
7. records `pendingBulkAckEpoch` (**before** the `BulkEnd` write)
8. sends `BulkEnd(epoch)` and then waits for peer acknowledgement

The sender now treats outbound bulk acknowledgement as first-class state. A
bulk transfer is not considered fully primed until the peer returns `BulkAck`
for the current epoch.

**Record-then-send ordering (#3912).** `pendingBulkAckEpoch` must be stored
*before* the `BulkEnd` marker is written to the wire, not after. `BulkEnd` is
what solicits the peer's `BulkAck`, and the ack is processed on the read
goroutine (`handleMessage`, `syncMsgBulkAck`) independently of the send
goroutine. If the pending epoch were recorded *after* the write, a peer that
acked faster than the send goroutine could record the pending state would have
its ack processed against `pendingBulkAckEpoch == 0` — the ack handler's
`pending != 0` guard drops it — and the send goroutine would then latch a
phantom pending epoch that no future ack ever clears. A latched phantom epoch
permanently blocks manual failover, because the readiness gate waits on an
outbound bulk ack that already arrived. Recording first (mirroring the
#2170/#2198 gen-guard record-then-send discipline) guarantees an early ack can
only ever observe the pending epoch already in place, so it clears it
regardless of arrival timing. On a `BulkEnd` write failure the epoch is reset
to 0 (and `handleDisconnect` also clears it), so a failed send cannot leave the
pending state falsely armed. The same ordering applies to the empty-marker
`sendBulkMarkers` path used after event-stream export.

### Receive Side

On `BulkStart` the receiver:

- snapshots zone ownership for stale-session reconciliation
- resets the per-bulk receive tracking maps
- marks bulk in progress

For each received session it:

1. decodes key/value
2. tracks the forward key in the current bulk receive set
3. rebases timestamps into local monotonic time
4. clears cached FIB resolution
5. installs the forward entry through `SetClusterSyncedSession*`
6. creates and installs the reverse entry locally
7. recreates any SNAT `dnat_table` entry locally

On `BulkEnd` the receiver:

1. verifies the epoch
2. reconciles stale sessions using the frozen ownership snapshot
3. sends `BulkAck(epoch)`
4. fires `OnBulkSyncReceived`

### Stale Session Reconciliation

After a bulk completes, the receiver deletes sessions that are still present
locally but were not refreshed by the peer for zones that the frozen snapshot
says are peer-owned.

Important detail: zones missing from the frozen snapshot are conservatively kept
instead of deleted.

## Sync Readiness and Bulk Priming

This is the biggest place where older descriptions are wrong or incomplete.
There are now two distinct readiness signals:

- `syncBulkPrimed` — we received the peer's current-generation bulk
- `syncPeerBulkPrimed` — the peer acknowledged our current-generation bulk with
  `BulkAck`

They are not the same thing.

### Connection Lifecycle

On peer connect:

- `syncBulkPrimed = false`
- `syncPeerBulkPrimed = false`
- cluster sync readiness is forced false
- a guarded readiness timeout is armed
- a bulk-prime retry loop starts

On bulk receive:

- `syncBulkPrimed = true`
- the readiness timeout is stopped
- VRRP sync hold is released
- cluster sync readiness becomes true

On bulk ack receive:

- `syncPeerBulkPrimed = true`

On disconnect:

- both primed flags are cleared
- cluster sync readiness is forced false
- the readiness timeout is invalidated with a generation guard so a stale timer
  callback cannot flip readiness back to true after disconnect

### Bulk-Prime Retry Loop

After reconnect, the daemon retries `BulkSync()` if the peer never acknowledges
our current-generation bulk.

Important current behavior:

- retries stop once `syncPeerBulkPrimed` becomes true
- retries are deferred while the current bulk is still waiting for `BulkAck`
- retries are also deferred while inbound sync progress is still advancing
- retries stop if the connection is replaced or disconnected

This exists because failover admission now depends on the standby having both
sides of the current-generation baseline, not just having received one bulk.

## Incremental Sweep and Delete Journal

### Background Sweep

A background sweep periodically scans the kernel session maps for forward
entries whose `Created` or `LastSeen` timestamps moved since the previous sweep.
Only sessions owned by the local node for the ingress zone are sent.

The sweep is deliberately separate from userspace deltas. It is still the only
way the kernel conntrack path exports incremental session creation.

### Delete Journal

Delete messages are queued immediately from conntrack GC callbacks. If the peer
is disconnected — **or the peer is connected but `sendCh` is momentarily full
(backpressure)** — the delete is journaled in a bounded ring by
`QueueDeleteV4`/`V6` instead of being sent inline.

The journal is replayed on two triggers:

1. **Reconnect flush** — the next first-post-disconnect connection comes up,
   before `OnPeerConnected` and before the fresh bulk starts
   (`handleNewConnection` → `flushDeleteJournal`).
2. **Connected sweep flush (#3926)** — the periodic sweep (`syncSweep`) calls
   `flushDeleteJournal` on every tick while connected, mirroring the
   install-replay it already performs. This converges a delete that was
   journaled during a connected-but-backpressured moment **without requiring a
   disconnect**. Before #3926 the journal was flushed only on trigger (1), so a
   delete journaled while the link stayed up was never delivered until an
   unrelated disconnect — the standby kept the dead session and made the wrong
   forwarding decision on failover. The delete backpressure sets
   `syncBackfillNeeded`, which holds the sweep at the 1s active cadence, so
   convergence is bounded by one active sweep interval. The re-sent delete
   carries the same encoded #2170/#2221 generation drawn when it was first
   journaled, so a stale journaled delete that replays after a same-key
   replacement was re-synced is still refused by the peer's delete guard.

Replay goes through the ordered send channel (`queueMessage`), so a delete that
is delivered stays ordered behind any session frames already queued in `sendCh`
for the peer. (Note: cold-start bulk sync direct-writes session frames under
`writeMu` rather than via `sendCh`, so flush-vs-bulk wire order is not strictly
guaranteed; flush still completes — enqueueing all deletes — before bulk
starts, and a live session landing after a stale delete is the safe direction.)
If the send queue is full (or the peer disconnects) mid-replay,
`flushDeleteJournal` does **not** drop the un-sent deletes: it re-journals the
un-sent tail at the front of the ring (FIFO-preserving, evicting the oldest on
overflow) so they replay on the next reconnect flush — the same
journal-on-failure contract `QueueDeleteV4`/`V6` use for runtime deletes (#2121
fixed an earlier silent drop here). Genuine loss only occurs at the journal cap
and is counted in `DeletesDropped`; a cap eviction now also arms a full bulk
resync so the standby reconciles the evicted deletes (#5450, see "Delete Journal
Overflow" below).

Because deletes are key-only on the peer (no generation/session-identity guard
yet), a re-journaled delete that replays after a same-key replacement session
has been synced can remove the live replacement. This is a pre-existing
property of the journal (it also applies to `QueueDeleteV4`'s full-queue and
disconnect journaling); #2121 widens it to the flush path as a deliberate
trade-off (bounded retention instead of unrecoverable silent loss). Fully
closing it requires a wire-protocol generation guard on deletes — a tracked
follow-up.

## Userspace Session Integration

### NAT Pool Port Reservation for Synced Sessions (#4388)

When the helper installs a peer-synced session that carries a pool-mode
source-NAT translation, it **reserves** the translated `(pool_addr, port)` in
this node's LOCAL source-NAT allocator. The active node picks the pool port via
`allocate_translation` and syncs the completed NAT decision over the fabric; the
standby imports that pre-computed decision and never runs `allocate_translation`
itself, so without an explicit reservation its allocator has no record that the
port is in use. Post-failover the standby-turned-active would then hand the SAME
`(pool_addr, port)` to a fresh local flow — two sessions colliding on one NAT
source tuple (reply mis-delivery / a session-hijack surface).

- **Reserve site:** `handle_upsert_synced`
  (`afxdp/session_glue/commands/upsert_synced.rs`) calls
  `reserve_synced_source_nat_allocation` (`nat/source.rs`) for every forward,
  peer-synced entry that carries `rewrite_src` + `rewrite_src_port`. It resolves
  the pool address to its allocator index and marks the port owned via
  `PortAllocator::reserve_flow` (`nat/allocator.rs`) — the same
  `owner_by_translated` / `addr_index_by_translated` / `live_by_flow` state a
  normal allocation writes, keyed by the synced session's flow. The sequential
  port cursor (`claim_free_port_locked`) then skips the reserved port, exactly
  as it already skips a live local allocation (#3047 forward-probe).
- **Release site:** the reservation uses the synced flow key, so the standard
  teardown — `release_source_nat_allocation`, already called on GC reap
  (`reap_expired_sessions`), on a peer delete-sync (`handle_delete_synced`), and
  on DSCP-filter purge — frees it with no new delete path. A reverse synced
  entry, an address-only / `port no-translation` decision, or a session with no
  source NAT reserves nothing.
- **Config-drift edge:** if the synced pool address is not a member of any local
  pool (the two nodes' pool config diverged), the reserve is skipped gracefully
  — never a panic, never a reservation on the wrong pool.
- **Idempotent:** re-reserving the same synced flow on a refresh is a no-op; the
  allocator is process-global (`Arc<PortAllocatorShared>`), so the reservation
  is visible to every worker regardless of which one imported the session.

### NAT64 Translated-Port Reservation for Synced Sessions (#4512)

NAT64 (RFC 6146 stateful v6→v4) has the identical exposure. Each `Nat64Prefix`
owns a `PortAllocator` (#4381, the same pool-mode allocator source NAT uses) and
`Nat64State::allocate_source` hands every admitted forward flow a unique
translated `(pool v4, port / ICMP identifier)`. The translated port rides the
synced `NatDecision` on `rewrite_src_port` (no new wire field), but the standby
imports the pre-computed decision without running `allocate_source`, so its NAT64
allocator has no record the port is in use. Post-failover the promoted node could
`allocate_source` the SAME `(snat_v4, port)` for a fresh local flow — two forward
flows on one translated source, so the 1:N reverse (v4→v6) index bucket mis-demuxes
the server's replies (the exact BIB collision #4381 closed for the same-node case).

- **Reserve site:** `handle_upsert_synced` calls
  `crate::nat64::reserve_synced_nat64_allocation` (`nat64.rs`) alongside the
  source-NAT reserve, for every forward, peer-synced entry whose decision is a
  NAT64 translation (`nat.nat64 && rewrite_src == V4 && rewrite_src_port`). It
  reconstructs the flow key EXACTLY as `allocate_source` built it (`dst_ip` is the
  translated v4 destination `nat.rewrite_dst`, not the synthetic v6 key), resolves
  `snat_v4` to its `pool_v4` position (the NAT64 allocator uses `family_offset ==
  0`, so the pool position IS the absolute index), and marks it owned via
  `reserve_nat64_pool_port` → `PortAllocator::reserve_flow`. The `nat.nat64` guard
  keeps the NAT64 and source-NAT reserves disjoint even if a pool address is shared.
- **Release site:** the reservation uses the synced flow key, so the standard
  teardown `release_nat64_allocation` — already called on GC reap
  (`reap_expired_sessions`), on delete-sync (`handle_delete_synced`), and on
  DSCP-filter purge — frees it with no new delete path. A reverse entry or a
  non-NAT64 decision reserves nothing.
- **Config-drift / scope:** a synced pool address not in any local NAT64 pool is
  skipped gracefully (no panic). This closes the port-COLLISION harm only;
  reverse-TRANSLATION of a promoted synced NAT64 session is completed by #4565
  (below), which also ARMS this reserve — see the note there.

### NAT64 Reverse-BIB Sync for Promoted Sessions (#4565)

Closes the reverse-TRANSLATION half of the NAT64 HA story #4512 left open, and is
the change that actually ARMS #4512/#4564's `reserve_synced_nat64_allocation`.

**The gap.** A NAT64 forward flow is keyed on the ORIGINAL IPv6 5-tuple; its
reverse (v4→v6) reply is keyed on the translated `(server_v4 → snat_v4,
translated port)` tuple and translated back to IPv6 using the original v6 src/dst
(`Nat64ReverseInfo`). Pre-#4565, `build_synced_session_entry` (`server/helpers.rs`)
built the standby's synced entry with `nat64: false` (via `..NatDecision::default()`)
and `nat64_reverse: None`, and `build_reverse_session_from_forward_match`
(`afxdp/shared_ops.rs`) hardcoded `nat64_reverse: None`. So a promoted NAT64
session (a) never reached `build_nat64_forwarded_frame` — TX dispatch keys
`is_nat64` off `nat.nat64`; (b) could not translate the v4 reply (the frame
builder hard-requires `nat64_reverse`); and (c) synthesized a WRONG (v6-family)
reverse companion KEY — `reverse_session_key` derives the reply's v4 address
family + `(dst_v4 → snat_v4)` tuple from `nat.nat64` + the v4 NAT addresses, so
without them the server's v4 reply never matched. Because the entry set
`nat64: false`, #4512/#4564's reserve (gated on `nat.nat64`) was ALSO a silent
no-op on the real HA path.

**What must ride the wire (verify-first).** The original v6 src/dst ARE the synced
forward v6 session key (`key.src_ip`/`key.dst_ip` == `orig_src_v6`/`orig_dst_v6`;
a NAT64 forward flow is keyed on the original tuple and `nat64_match` is gated on
no-DNAT/no-NPTv6, `<prefix>/96` only), and `dst_v4` is the RFC 6052 /96-embedded
low 32 bits of the key dst. So the ONE datum the standby cannot reconstruct is
the translated pool source `snat_v4` (chosen by the active node's
`allocate_source`, not embedded in the key). A single tag-matched wire field
carries it (self-signaling — non-empty ⟹ NAT64):

- **Event stream (Rust → Go active):** `FLAG_NAT64` (bit `1<<5`) on the SESSION_OPEN
  frame + a trailing 4-byte `snat_v4` (after the #3301 fields). Decoded to
  `SessionDeltaInfo.Nat64` / `Nat64SnatV4` (`eventstream.go`).
- **Shadow + cluster sync (Go active → Go standby):** stamped onto
  `SessionValueV6.Nat64SnatV4` (`daemon_ha_userspace.go`), a userspace-sync-only
  field carried as a length-gated trailing field in `encodeSessionV6Payload`
  (NOT in the BPF/C conntrack ABI).
- **Control socket (Go standby → Rust standby):** `SessionSyncRequest.nat64_snat_v4`
  (Go+Rust, the `protocol_wire_v1.json` / cross-language contract field).

**Rebuild on the standby.** When `nat64_snat_v4` is non-empty,
`build_synced_session_entry` sets `nat64 = true`, `rewrite_src = snat_v4`,
`rewrite_dst = dst_v4` (the /96 low 32 of the v6 key dst; the translated port
already rides `nat_src_port`), and stamps `metadata.nat64_reverse` (orig v6
src/dst) from the key. `build_reverse_session_from_forward_match` inherits
`nat64_reverse` onto the synthesized reverse companion, and `reverse_session_key`
then derives the correct v4 `(server → snat_v4)` reply tuple. Rolling-upgrade
safe: an old peer omits the field ⇒ not-NAT64 (bit-identical to pre-#4565).

### Reverse-SNAT `dnat_table` Publish for Synced Sessions (#4393)

The `dnat_table` / `dnat_table_v6` BPF maps are the **embedded-ICMP reverse-NAT
steering** maps. When an inbound ICMP error (PMTUD Packet-Too-Big, traceroute
Time-Exceeded) quotes a NATed inner packet whose source is a source-NAT pool
`(addr, port)`, the AF_XDP shim looks that tuple up in `dnat_table` to decide the
packet must be handed to the helper's slow path, where `try_embedded_icmp_nat_match`
reverse-translates the error back to the original pre-NAT client. Without the
`dnat_table` entry the shim passes the error to the kernel (which has no NAT
state) — the client never learns the PMTU, TCP stalls on large packets, and
traceroute breaks.

The active node populates `dnat_table` from the worker poll path
(`poll_descriptor`, `publish_dnat_table_entry`) when it forwards the first SNAT'd
packet of a flow. The standby never forwards that packet — it imports the
pre-computed NAT decision over the fabric — so before #4393 the standby held no
`dnat_table` entry for synced SNAT sessions. Post-failover the standby-turned-active
could not steer the inbound embedded-ICMP error into the helper, so PMTUD
blackholed for exactly the flows that survived the failover.

- **Publish site:** `Coordinator::upsert_synced_session` (`afxdp/ha.rs`) calls
  `publish_dnat_table_entry` for every forward peer-synced entry, immediately
  after the `publish_shared_session` that populates the (also process-global)
  `shared_nat_sessions` reverse-NAT map. `dnat_table` is a **single shared BPF
  map** (opened once, its fds cloned to every worker), so this is a
  once-per-synced-session publish, mirroring the primary's single publish rather
  than a redundant per-worker write. It is **not** gated on
  `synced_entry_allows_local_replace` (unlike the forward session-map publish):
  the `dnat_table` is a passive steering map that must be ready the instant this
  node becomes active, and inbound SNAT-return traffic never reaches the standby,
  so an early entry is inert until failover. A reverse companion carries no
  source rewrite and publishes nothing.
- **Release site:** `Coordinator::delete_synced_session_gen` (`afxdp/ha.rs`)
  calls `delete_dnat_table_entry` alongside the session-map delete, keyed on the
  same `dnat_v4_key_bytes` / `dnat_v6_key_bytes` SSOT the publish used, so the
  delete byte-matches the insert. The maps are non-LRU `HASH`
  (`max_entries = MAX_SESSIONS`, `BPF_F_NO_PREALLOC`); a missing delete leaks one
  slot per removed synced SNAT session. A non-SNAT / reverse entry is a no-op.
- **Observability:** a failed publish from this coordinator path (no per-binding
  `BindingLiveState`) bumps the shared `DNAT_PUBLISH_ERRORS_SHARED` static, which
  `Coordinator::dnat_publish_errors_total()` folds into the existing per-binding
  sum for `xpf_userspace_dnat_publish_errors_total` — so map-pressure reverse-NAT
  loss stays operator-visible on the standby path too (#2244 parity).

### Activation Refresh Recomputes `allow_replace_local` Per Session (#4805)

The forward session-map publish for a peer-synced entry is gated on
`synced_entry_allows_local_replace(ha_state, owner_rg_id, now_secs)`: for a
`LocalDelivery` (host-inbound) session whose owning RG is **not** locally
forwarding-active, it returns `true`, and
`force_live_redirect_for_worker_synced_entry` publishes the userspace
`REDIRECT` entry (policy enforced via fabric-redirect / drop) rather than a
kernel-local `PASS_TO_KERNEL` entry. A standby node must never let a
peer-synced, locally-undelivered session fall through to its own kernel stack.

`WorkerCommand::RefreshOwnerRGS` (dispatched to every worker on any RG
activation) runs a **wider scan** — it re-evaluates every HA-managed worker
session, not just those indexed under the activated RG, because a split-RG
reverse companion owned by RG2 can change local-forward vs fabric-redirect when
RG1 moves. Each touched session is republished. That republish MUST recompute
`allow_replace_local` from the refreshed owner RG against the current HA state,
exactly as the initial-sync path (`handle_upsert_synced`) does —
`collect_refresh_owner_rgs_items` in
`afxdp/session_glue/commands/refresh_owner_rgs.rs` computes it alongside the
refreshed metadata. Hardcoding `false` here (the pre-#4805 bug) flipped an
unrelated, still-standby-owned `LocalDelivery` session from `REDIRECT` to
`PASS_TO_KERNEL` on any routine RG activation elsewhere in the cluster —
delivering host-bound traffic straight to the standby's kernel with no policy
enforcement. Pinned by
`refresh_owner_rgs_standby_local_delivery_forces_live_redirect_4805` and
`refresh_owner_rgs_active_owner_local_delivery_publishes_kernel_local_4805`.

### Event Stream (Primary Path)

The Rust helper pushes session events over a persistent binary-framed Unix
socket (`/run/xpf/userspace-dp-events.sock`). Events (SessionOpen,
SessionClose, SessionUpdate) carry sequence numbers for reliable delivery.
The daemon reads events, applies ownership filtering, and queues them to the
peer sync stream. Ack frames flow back for replay buffer management. Pause and
Resume frames throttle the stream. The DrainRequest / DrainComplete frame pair
is **reserved and currently dormant** — see below.

The daemon owns the listener; `EventStream.Start` binds it (`net.Listen`) before
the helper is spawned so the local helper can dial immediately. This socket is
the primary push channel for post-bootstrap deltas from the helper into the
daemon's peer-sync pipeline. The daemon also polls `DrainSessionDeltas` while
the stream is disconnected (the fallback described below), but a listener bind
failure must not silently make that degraded path the startup baseline. A bind
failure (path too long, `EADDRINUSE`, permission, missing directory) therefore
fail-closes dataplane bring-up: `Start` returns an error,
`ensureProcessLocked` aborts before launching the helper instead of storing a
non-nil-but-dead stream, and takeover readiness is denied.
`Start` first acquires a nonblocking process-lifetime sidecar lock. While it
owns that lock it checks `/proc/net/unix` and removes an existing filesystem
socket only when the kernel table proves there is no live owner. This check is
non-invasive: dialing the old listener would displace its real helper because
the event stream permits one connection. A live or inconclusive owner is never
unlinked. `Close` tears down the listener and accepted connection, removes the
socket only when that `EventStream` owns it, and then releases the lock. This
makes active-owner collisions fail closed rather than detaching the first
daemon's pathname.
`EventStream.ListenerBound()` reports whether the local listener is up and is
distinct from `IsConnected()` (the local helper has dialed in). Takeover
readiness gates on `ListenerBound()`, not `IsConnected()`: transient helper
disconnects are covered by polling, while a listener that never bound is a
failed dependency rather than an accepted degraded startup (#5273). Before
#5273 the `net.Listen` failure was logged and swallowed with a void `Start`, so
the manager kept the dead stream and takeover readiness — which only checked
the control socket, ping, forwarding-arm, and XSK liveness — could advertise a
node without its primary delta stream.

#### DrainRequest fence (#2876, #2920) — RESERVED / DORMANT

> **Status: implemented and hardened, but not wired to any production path.**
> The live graceful-demotion path does **not** call `SendDrainRequest`; it uses
> `SessionSync.WaitForPeerBarrier` plus the continuous lossless event stream
> (see "Graceful Demotion" below). The seq-fenced drain is a strictly *weaker*
> guarantee than the unbounded `ExportOwnerRGSessions` full-resync republish
> that already backstops loss-of-sync (#2874 gap, #2442 overflow), so it is not
> on the failover critical path. The pair is retained — fully tested and
> hardened — for a possible future fenced-drain use; the wire frames
> (`MSG_DRAIN_REQUEST = 7`, `MSG_DRAIN_COMPLETE = 8`) are kept rather than
> deleted to avoid an invasive protocol-version churn. The semantics below
> describe the dormant primitive, **not** a live demotion step.

`EventStream.SendDrainRequest` fences the drain to the last fully-applied
sequence (`lastAppliedSeq`, the *target seq*) and blocks for the helper's
`DrainComplete`. The drain is only reported successful when the
**acked/drained seq has reached the target fence**:

- **Helper side** (`handle_drain_request`, `event_stream/mod.rs`): the drain
  loop tracks whether the target fence was reached. On a timeout below the
  fence (the channel never produced the target seq within the 200 ms deadline)
  the helper **withholds** `DrainComplete` rather than emitting one carrying a
  below-target `replay_buf.back().seq`.
- **Go side** (`SendDrainRequest`, `eventstream.go`): a `DrainComplete` with
  `seq < targetSeq` is rejected as a **hard error**, and a context expiry
  (helper withheld the completion) is likewise an error. Demotion must NOT
  proceed past an unflushed fence.

Before #2876 the Go side returned the first `DrainComplete` seq with no fence
check and the helper emitted `DrainComplete` even on a below-fence timeout, so
were this primitive ever wired into demotion, sessions created after the fence
could be reported drained without reaching the peer. #2876/#2920 hardened the
primitive so that defect cannot ship if it is wired in future. The fence carries no new wire field
(the existing `DrainRequest` target seq and `DrainComplete` seq are reused), so
the protocol is unchanged. Siblings in the same event-stream/drain cluster:
#2882 (drain ignores the target_seq filter), #2877 (blocking writes), #2883
(keepalive) — out of scope here.

When the event stream is disconnected (helper restart, startup race), the
daemon automatically falls back to RPC polling.

### Delta Drain (Fallback Path)

The Go daemon can poll helper-originated session deltas via
`DrainSessionDeltas(...)` as a fallback when the event stream is unavailable.

These deltas are **not** blindly mirrored. Filtering in
`shouldSyncUserspaceDelta()`:

- `local_delivery` disposition is never synced to the peer
- `FabricRedirect` with `!FabricIngress`: always synced even if the local node
  is no longer owner, because the peer needs the forward-wire alias to receive
  redirected traffic. The daemon also synthesizes forward-wire alias session
  keys via `userspaceForwardWireAliasFromDeltaV4/V6` so the new owner can
  materialize the translated forward tuple it will receive over the fabric.
- if the delta carries `OwnerRGID`, ownership is checked with `IsPrimaryForRGFn`
- otherwise the fallback is `ShouldSyncZone(ingressZone)`

The filtering fields on `SessionDeltaInfo` are `FabricRedirect` and
`FabricIngress` (boolean flags), not a single combined field.

### Bulk Owner-RG Export (FullResync republish)

`ExportOwnerRGSessions(rgIDs, 0)` dumps **all** userspace sessions owned by the
primary's RGs. The `max = 0` argument means unbounded (`usize::MAX` helper-side)
— it is an unbounded ground-truth snapshot of the entire conntrack table for the
owned RGs, not a Max-truncated or delta-replay export, so it cannot silently drop
post-snapshot sessions.

This is **not** triggered by demotion prep. Its only live caller is
`handleEventStreamFullResync` → `exportUserspaceOwnerRGSessionsWithConfig`: the
event stream signals a FullResync after a #2874 sequence gap or a #2442
delta-ring overflow (loss-of-sync), and the export republishes the full owned set
from table truth. It is not the same thing as the steady-state delta drain.

The `rgIDs` handed to the export are enumerated from the **configured
redundancy-group set** — `handleEventStreamFullResync` calls
`primaryOwnerRGIDs(cfg)`, which walks `cfg.Chassis.Cluster.RedundancyGroups`
(the same live active config `buildZoneIDs` reads) and keeps every id the node
is `IsLocalPrimary` for. It does **not** iterate a fixed `0..15` range. Junos
redundancy-group ids are not bounded to 15 (the `<group-id>` config slot has no
validator and is parsed via an unbounded `strconv.Atoi`), so the old hardcoded
`for rgID := 0; rgID < 16` loop silently skipped any RG with id >= 16 — its
owned sessions were never re-exported on a FullResync, so the standby never
received them and they were dropped on a failover of that RG (#4028). This
mirrors the live-config enumeration the watchdog/fence paths use
(`currentRedundancyGroups`, #3917).

**The export ack-wait runs OFF the global `ServerState` lock (#2962).** The
helper-side control-socket dispatcher (`server/handlers/mod.rs`) holds a single
`Mutex<ServerState>` across its request `match`, which serializes every control
RPC (status poll, session install, snapshot/FIB bump, HA state update, neighbor
update). The owner-RG export blocks up to 15 s waiting for every worker to ack
the export sequence — so doing that wait under the lock would freeze the whole
control plane for up to 15 s whenever a worker is slow or stalled (exactly the
failover-critical moment). The handler is therefore split into two phases:

- **Locked phase** (`Coordinator::kick_owner_rg_export`): enqueue the
  `ExportOwnerRGSessions` command to every worker, bump `export_seq`, and
  snapshot the lock-free handles the wait needs — the per-worker
  `session_export_ack` atomics (`Arc<AtomicU64>`) and the per-binding delta
  buffers (`Arc<BindingLiveState>`). Returns an `OwnerRgExportWait` immediately.
- **Lock-free phase** (`OwnerRgExportWait::wait_and_collect`): the dispatcher
  drops the `ServerState` lock, then runs the 15 s ack-wait + delta drain on the
  snapshotted `Arc`s. Status is re-derived afterward under a fresh short-lived
  lock acquisition. While one export drains, all other control RPCs proceed.

There is no TOCTOU: the worker SET (`workers.handles` / `workers.live`) is only
mutated by other control-socket handlers, which all hold the same lock, so the
worker set cannot change during the lock-free wait. The worker THREADS only
advance their ack atomics (monotonic seq) and push into their delta buffers —
both `Arc`-shared and lock-free — so the snapshot observes their progress
faithfully. The 15 s deadline and the timeout error are preserved verbatim.

**The all-sessions bulk export push ALSO runs OFF the global `ServerState`
lock (#4054).** The `export_all_sessions` verb
(`Coordinator::snapshot_all_sessions_export` → `AllSessionsExport::push`) is the
coordinator-driven bulk export used on peer connect / FullResync. It iterates the
shared session table and pushes each qualifying local forward session as an Open
delta through the event stream via `push_delta_lossless`, which retries a full
event-stream channel up to a **5 s** per-delta lossless-queue timeout. Pre-#4054
the whole export — the table iteration AND the `push_delta_lossless` serialization
loop — ran inside the dispatcher's `ServerState` `match` arm, i.e. UNDER the global
lock. On a firewall with many sessions, a bulk export against a slow/backpressured
peer stream could hold the lock long enough for the status poll to miss the control
plane's liveness deadline → a false dataplane-failure → a needless helper restart
(which drops all sessions and flaps forwarding) — precisely at failover, the worst
time. The handler is therefore split like the owner-RG path:

- **Locked phase** (`Coordinator::snapshot_all_sessions_export`, dispatcher
  `all_kick`): under the global lock, iterate the session table once under a brief
  `sessions.synced` lock, copy each qualifying session into an Open `SessionDelta`,
  and capture the Arc-cheap event-stream worker handle plus an OWNED clone of the
  zone-name→id map. Returns an `AllSessionsExport` immediately — no push yet.
- **Lock-free phase** (`AllSessionsExport::push`): the dispatcher drops the
  `ServerState` lock, then runs the `push_delta_lossless` loop over the captured
  snapshot. Status is re-derived afterward under a fresh short-lived lock. While
  one bulk export serializes/backpressures, all other control RPCs proceed.

The exported set is a consistent point-in-time snapshot (deltas built under
`sessions.synced`, zone map cloned in the same locked phase), so a session or zone
mutation racing the push is simply not in THIS bulk export — it rides the
incremental delta stream — identical to the pre-#4054 semantics, which already
snapshotted the deltas under `sessions.synced` before serializing (only the GLOBAL
lock scope changes). Event-stream ordering stays governed by `producer_seq_lock`
inside `push_delta_lossless`, not the `ServerState` lock, so releasing the latter
does not affect the lossless seq contract (#2874 / #3878).

**The worker-loop lossless push is time-BOUNDED per drain cycle (#5468).** Every
lossless send `flush_session_deltas` makes — it runs directly on the packet
worker loop — must NOT use the 5 s `LOSSLESS_QUEUE_TIMEOUT`. That timeout equals
`HEARTBEAT_STALE_AFTER` (5 s), so a connected-but-UNREAD peer (a slow/stalled
reader whose lossless channel is full) that blocked the worker for the full 5 s
would stop the loop stamping its per-binding heartbeat; the peer then sees this
node as stale and triggers a **false failover** — the exact defect #5468
describes. The worker loop therefore calls `push_delta_lossless_within` with a
short `WORKER_LOSSLESS_QUEUE_BUDGET` (one fifth of `HEARTBEAT_STALE_AFTER`,
~1 s), leaving ~5× headroom for the rest of the loop iteration plus the
heartbeat map write. On the bounded timeout the delta is **not** dropped: the
same `set_delta_loss` / `take_delta_loss` latch fires and forces a full owner-RG
resync (deliver-or-resync, the #2874 losslessness contract).

The per-call budget alone is **not** sufficient, because the drain region calls
`flush_session_deltas` many times per iteration: the steady-state drain is one
call, but the #2442 loss-of-sync resync and the #2653 command export
(`take_delta_loss` → `chunked_drain_as_you_export!` → `drain_and_flush_all!`,
`worker/loop_body/mod.rs`) call it ONCE PER 256-delta batch across the entire
owned-session set. For K owned sessions that is ~K/256 calls, so at one budget
each an unread peer would still stall the worker ~(K/256) budgets — past K≈1280
(5 batches) that re-crosses `HEARTBEAT_STALE_AFTER` and re-triggers the same
spurious failover **via the resync path**. The bound is therefore an AGGREGATE
one: a per-drain-cycle `worker_lossless_wedged` latch, reset at the top of every
loop iteration and threaded through every `flush_session_deltas` call, caps the
whole cycle at ~one budget total. The first wedged batch waits one budget and
sets the latch; every later call this cycle inherits it and SKIPS the lossless
wait entirely (it never re-attempts a push), while still draining each delta to
its other consumers — the per-binding live RPC buffer, the shared
conntrack/session tables, peer-worker delete replication, and best-effort
RT_FLOW. Every wedged batch still returns out-of-sync, so the loss-of-sync latch
stays set and the resync simply RETRIES next cycle until the consumer drains
(deliver-or-resync, never a silent drop). Net guarantee: the worker loop's total
lossless WAIT per drain cycle is ~1 budget **regardless of the owned-session
count K** — for both the incremental push and the resync/export.

Only the off-worker-loop exporters — `AllSessionsExport::push` (bulk export on
connect, above) and `push_purge_close_deltas` (tunnel-remap purge, below) — keep
the 5 s `LOSSLESS_QUEUE_TIMEOUT` via `push_delta_lossless`; they run off the
packet loop so a long backpressure wait there does not threaten the worker
heartbeat.

### Delta-ring overflow → loss-of-sync resync (#2442)

Each worker buffers session open/close deltas in an in-worker ring
(`SessionTable.deltas`, capped at `MAX_SESSION_DELTAS = 4096`). The worker loop
drains it 256 at a time. Under a churn burst (failover storm, SYN-cookie
admission flood) the ring can fill faster than the drain catches up, and
`push_delta` drops the overflowing delta — an HA-relevant open/close event the
downstream session-sync consumer will never see.

Pre-#2442 this only bumped a `delta_drops` counter, so the peer/session view
silently diverged from the table truth with no consumer-visible "rescan"
contract. The fix turns a drop into an explicit **loss-of-sync** signal:

- `push_delta` latches `delta_loss_pending` the moment it drops (alongside the
  existing `delta_drops` count). It is a single bool, not a count.
- The worker loop reads-and-clears it once per drain cycle via
  `take_delta_loss()`. A `true` result means the incremental stream went lossy.
- On loss the worker re-emits an Open delta for **every owned forward session**
  (the same table-truth set the `ExportOwnerRGSessions` command walks) so the
  consumer re-derives a complete snapshot instead of diverging.

**Drain-as-you-export (bounded against the ring).** A worker can own up to
`DEFAULT_MAX_SESSIONS = 131072` forward sessions — 32× the 4096-slot delta
ring. A naive "drain the backlog, then push all N" would overflow the ring at
delta 4097, drop sessions 4097..N, re-latch the loss, and storm a fresh resync
every cycle (the peer would never receive a complete snapshot, and `delta_drops`
would climb without bound). The resync therefore **interleaves the drain**:

1. drain+flush the existing backlog so the ring starts empty;
2. collect the export candidates once
   (`forward_export_candidates_for_owner_rgs`, the filter half of the export
   walk — it pushes nothing);
3. emit them in chunks of `RESYNC_EXPORT_CHUNK = 2048` (comfortably under the
   4096 cap), and drain+flush each chunk to the peer **before** emitting the
   next.

Because the ring is empty before every chunk and a chunk is smaller than the
cap, `push_delta` never overflows during a resync. The complete snapshot ships
in chunks regardless of session count, and the loss latch is not spuriously
re-armed by the export itself.

**The single-shot `ExportOwnerRGSessions` command path uses the same chunked
drain-as-you-export (#2653).** Pre-#2653 the command handler
(`handle_export_owner_rg_sessions`) called `export_forward_sessions_for_owner_rgs`
inline, pushing the whole owned-session set into the ring in one shot on the
theory that the caller's 15 s export-ack drain would mop it up. But the overflow
happens *inside* the emit, before any drain runs: with >4096 owned sessions the
ring overflowed at delta 4097 and silently dropped sessions 4097..N, so the HA
peer received an INCOMPLETE bulk snapshot on rejoin / RG transition (the
command-path sibling of the #2442 worker-loop overflow). Since
`apply_worker_commands` has no `BindingWorker`/flush access (it cannot drain the
ring to the peer mid-export), the handler now only **records** the requested
owner RGs in `WorkerCommandResults.export_owner_rgs`; the worker loop — which
owns the binding + flush machinery — performs the identical chunked
drain-as-you-export (collect candidates → emit in `RESYNC_EXPORT_CHUNK = 2048`
chunks → drain+flush between chunks) and only advances `session_export_ack` once
the complete export has drained to the peer. The unbounded
`export_forward_sessions_for_owner_rgs` helper is now `#[cfg(test)]`-only (a
candidate-selection fixture); both production paths are bounded.

**Debounce / composition with the sync state machine.** The signal is a single
bool cleared on read, so a burst that drops N deltas before the worker reads it
raises **exactly one** resync (one episode → one trigger); a *genuinely new*
drop after the resync completes re-arms a new episode on a later cycle. The
resync is entirely worker-local — it re-uses the same per-worker delta ring and
`flush_session_deltas` plumbing the steady-state drain already uses, so it needs
**no control-socket round-trip** and cannot deadlock or starve normal
incremental sync (the control-socket contention rules in CLAUDE.md). It runs at
most once per worker poll tick and only when an overflow actually occurred.

### Coordinator tunnel-remap purge records a dropped close delta (#2880)

The **coordinator-side** tunnel-endpoint-id remap purge
(`purge_remapped_tunnel_sessions`, #1873) deletes every session keyed to a
remapped tunnel id and then emits a `Close` delta on the event stream so the Go
shadow conntrack and the HA peer drop the stale entry too. That close delta is
pushed via `push_delta_lossless`. Pre-#2880 the result was discarded with
`let _ =`, so a disconnected / saturated event stream silently dropped the
delta with no diagnostic and no metric.

**This is an error-hygiene / observability fix, NOT a forwarding-correctness
leak fix — the purge is CLEANUP, not the correctness boundary.** Two facts make
a surviving stale entry harmless:

- **It cannot mis-encapsulate.** Re-resolution and the encap builders refuse a
  tunnel id whose owning netdev ifindex differs from the one stored in the
  session's resolution (documented at the call sites,
  `coordinator/snapshot_refresh.rs` and `coordinator/reconcile/snapshot.rs`). A
  stale entry that escapes the purge dead-ends; it never encaps to the wrong
  tunnel.
- **It self-heals.** The standby runs its OWN `purge_remapped_tunnel_sessions`
  when it applies the same config snapshot, and idle GC reaps the entry on its
  inactivity timeout regardless.

A full owner-RG re-export would **not** recover an undelivered close anyway. The
userspace cold-sync delivers sessions as **incremental `Open`s** through the
event stream and then sends **empty** `BulkStart`/`BulkEnd` markers
(`pkg/cluster/sync_bulk.go` `doBulkSync` → `BulkSyncOverride`); the peer's
`reconcileStaleSessions` (`pkg/cluster/sync.go`) short-circuits on an empty bulk
("skipped (empty bulk)"). Re-emitting `Open`s therefore cannot convey a delete —
only a non-empty **bracketed** bulk drives the stale-session prune, which the
event-stream path never produces. A disconnected stream also triggers a fresh
resync on reconnect (#2874) independently.

So the fix is the minimal honest change: stop silently swallowing the
`push_delta_lossless` error. `push_purge_close_deltas` records each undelivered
delta in the event-stream **dropped-frames** metric
(`EventStreamWorkerHandle::record_dropped_frames` → the same `frames_dropped`
counter the lossy `try_send` path uses, surfaced in `EventStreamStats` /
Prometheus) and logs once. It stops on the first failure — a disconnected stream
fails every subsequent push immediately and a saturated one would otherwise burn
one lossless-queue timeout per remaining delta — and counts the undelivered
remainder. The `usize` return of `purge_remapped_tunnel_sessions` is unchanged:
it remains the accurate **local** purge count (callers read it only for
logging); the propagation drop is recorded separately, not conflated.

### Drained deltas reach binding-independent consumers even with no binding (#2669)

The worker loop drains the delta ring **unconditionally** (`drain_deltas`
pops entries off permanently) and then calls `flush_session_deltas` to apply
them. A drain cycle can coincide with an **empty `bindings` slice** — the XSK
sockets are admin-down or unconfigured during a reload/transaction while the
session table is still aging entries out. `flush_session_deltas` does much
more than push into a per-binding queue:

- **binding-INDEPENDENT** (must always run): remove the closed session from
  the shared session / NAT / forward-wire / owner-RG tables, delete the BPF
  conntrack + live-session entries, replicate a `DeleteSynced` command to the
  peer-worker queues (the HA delete-sync path), append to the recent-deltas
  RPC buffer, and emit to the event stream (HA type-2 session-sync delta plus
  the RT_FLOW SESSION_CLOSE/SESSION_CREATE frames).
- **binding-DEPENDENT** (the only step that needs a binding): the per-binding
  RPC fallback push, `BindingLiveState::push_session_delta` — there is no
  interface-local RPC queue to push into when no binding exists.

Pre-#2669 the **entire** flush was gated behind `if let Some(binding) =
bindings.first()`, so when `bindings` was empty the deltas were drained off
the ring and then silently discarded: closed/expired sessions never left the
shared conntrack/session tables, no `DeleteSynced` reached the HA peer, and no
SESSION_CLOSE reached the event stream — a permanent session-state leak and HA
desync. The fix makes `flush_session_deltas` take `live: Option<&BindingLiveState>`
and flush every binding-independent consumer unconditionally, gating **only**
`push_session_delta` on a binding. When no binding exists the worker loop
synthesizes a labels-only `BindingIdentity` (interface `""`, ifindex `-1`) and
falls back to the loop-cached map fds (which are `-1`, making the live
session-map delete a harmless `EBADF` no-op — that live map belongs to the
absent binding; the shared tables, HA replication, and event stream are the
consumers that matter). This is applied at **all three** drain sites (the
#2442 resync `drain_and_flush_all!` macro, the exported-sequences branch, and
the steady-state else branch) via the shared `flush_drained_session_deltas!`
macro. The invariant: **a drained delta MUST be flushed to its
binding-independent consumers — never popped-and-discarded.**

## Clock Synchronization

At connection setup, both sides exchange monotonic timestamps with `ClockSync`.
The receiver computes a local offset and rebases received session timestamps
into the local monotonic clock domain before install.

That keeps session expiry behavior consistent across nodes even though the two
systems have different boot times and independent monotonic clocks.

## Failover Session Handling

### Promotion

When a node becomes primary for an RG:

- synced sessions for newly-owned zones become locally authoritative
- GC delete callbacks become active for those zones
- userspace session state for the newly-owned RG is refreshed or promoted as
  needed for local forwarding
- direct-mode failover also relies on post-transition re-announcements to move
  LAN-side ownership quickly

### Graceful Demotion

Graceful demotion relies on the continuous real-time session sync rather than a
staged quiesce/republish at demotion time: by the time a node demotes, both
nodes already hold full session state from the continuous lossless event stream
(#2874) plus the steady-state bulk-prime. The demotion-prep step therefore does
exactly one synchronization: a single peer barrier proving the peer has
processed every delta already queued onto the sync stream.

Current sequence (`prepareUserspaceRGDemotionWithTimeout()`):

1. Acquire the demotion prep gate (`acquireUserspaceRGDemotionPrep`) — prevents
   duplicate concurrent preps for the same RG. On failure, the gate is released
   via `releaseUserspaceRGDemotionPrep` so retries are not blocked.
2. If the sync transport is absent or disconnected, release the gate and return
   (a reconnect + retry re-runs the barrier check before demotion proceeds).
3. Bulk-sync readiness (`syncPeerBulkPrimed`) is deliberately **not** required
   here — planned failover must not depend on bulk-sync state because both nodes
   already have full session state from continuous real-time sync. The bulk
   retry loop is advanced (`syncPrimeRetryGen`) so it stops flooding the sync TCP
   connection and delaying the barrier ack; it is restarted if the barrier fails.
4. Write a single ordered peer barrier (`WaitForPeerBarrier`) and wait for the
   ack. The barrier shares the same FIFO `sendCh` as all sync messages, so the
   ack proves the peer has processed everything queued ahead of it. The actual
   demotion then happens atomically in `UpdateRGActive(false)`.

Manual failover uses the same demotion-prep path via
`prepareUserspaceManualFailover()`, but wraps failures as
`RetryablePreFailoverError` for transient conditions (previous barrier pending,
peer not quiescent, barrier ack timeout). The cluster state machine can retry
admission on retryable errors instead of proceeding unsafely.

Once the RG is marked standby, each worker processes a
`WorkerCommand::DemoteOwnerRGS` on its packet thread
(`afxdp/session_glue/commands/demote_owner_rgs.rs`, `handle_demote_owner_rgs`):
it walks every session in the demoted owner RG, re-resolves forwarding (the peer
is now the forwarder), re-publishes the kernel session-map entry, and appends
each demoted key — deduplicated — to `cancelled_keys` so the worker loop can drop
any queued flow and delete stale local XSK redirect aliases. The dedup keeps a
companion `FxHashSet` for an O(1) membership test (#5155): `demote_owner_rg`
yields unique keys, so the pre-#5155 linear `cancelled_keys.iter().any(..)` scan
was O(N²) over the growing Vec — ~8.6e9 `SessionKey` comparisons at
`max_sessions` = 131072, all on the packet worker ahead of the heartbeat store,
i.e. a failover-time stall. The set makes the pass O(N); `cancelled_keys` stays a
Vec so the first-occurrence output order the worker loop iterates is preserved.
The dedup is load-bearing, not belt-and-braces: `demote_owner_rg` only flips a
session's origin to `SyncImport` (it does not remove the entry from the owner-RG
bucket), so a repeated `Demote{[rg]}` in the same dispatch stream re-discovers
the same key.

## Implementation Details

### Incremental Sync Pause/Resume

`PauseIncrementalSync(reason)` / `ResumeIncrementalSync(reason)` provide a
depth-counted pause mechanism. Multiple callers can pause independently; the
sweep only resumes when all callers have resumed. The pause stops only the
periodic sweep goroutine without affecting GC delete callbacks or explicit sync
producers. (These helpers — along with `WaitForIdle` and
`WaitForPeerBarriersDrained` — are retained primitives with no current live
caller; the demotion path uses only the single peer barrier described above.)

### Bulk-Prime Retry Loop

After reconnect, `startSessionSyncPrimeRetry()` retries `BulkSync()` at
increasing intervals (10s, 20s, 40s) if the peer never acknowledges our
bulk with `BulkAck`. Retries are deferred while:

- a pending bulk ack is still young (< 35s since BulkEnd was sent)
- inbound sync progress is still advancing (`syncPrimeProgressObserved`)
- the connection was replaced or disconnected

Retries stop once `syncPeerBulkPrimed` becomes true.

### Readiness Timeout Generation Guard

`armSyncReadyTimer()` captures a generation counter when the timer is armed.
The timeout callback checks that the generation is still current AND the sync
transport is still connected before releasing readiness. `stopSyncReadyTimer()`
increments the generation, invalidating any in-flight callback. This prevents
a stale timer from flipping readiness back to true after a disconnect in a
tight race.

### Barrier Ordering

`WaitForPeerBarrier()` enqueues the barrier message onto `sendCh` (the same
buffered channel used by `sendLoop` for all sync messages) rather than writing
directly to the socket. This preserves strict FIFO ordering — the barrier
cannot overtake messages that `sendLoop` has dequeued but not yet written.

## Invariants

1. Only forward entries are sent on the wire.
2. Reverse entries are recreated locally by the receiver.
3. Received sessions always have cached FIB resolution cleared before install.
4. Timestamps are rebased into the receiver's monotonic clock domain.
5. Session ownership filtering happens before incremental sync or userspace
   delta replication.
6. `local_delivery` sessions are helper-local and are not valid HA sync state.
7. Graceful demotion is ordered against the session-sync stream with a single
   ordered peer barrier (no separate quiesce/republish step on the demotion
   path; the seq-fenced DrainRequest/DrainComplete pair is reserved/dormant).

## Revision History

This document has been corrected through multiple passes:

- v1: Basic bulk + sweep description. Missing sender-side ack tracking,
  demotion protocol, userspace delta filtering.
- v2 (PR #264): Added two-readiness-signal model, bulk-prime retry loop,
  explicit demotion-prep sequence, userspace delta filtering details.
- v3: Corrected delta filtering field names (`FabricRedirect` +
  `FabricIngress`, not a combined field). Clarified that `PauseIncrementalSync`
  only pauses the sweep — GC delete callbacks are never suppressed. Added
  manual failover retry admission logic, depth-counted pause mechanism,
  readiness generation guard, barrier ordering via sendCh.
- v4 (current, #2930): Corrected demotion-path doc drift. The live graceful
  demotion path uses only a single `WaitForPeerBarrier` plus the continuous
  lossless event stream — it does **not** run the old staged
  quiesce/export/`PrepareRGDemotion` sequence (that helper does not exist, and
  `WaitForIdle`/`WaitForPeerBarriersDrained`/`PauseIncrementalSync` have no live
  caller). `ExportOwnerRGSessions(_, 0)` is an unbounded ground-truth republish
  triggered by event-stream **FullResync** (#2874 gap / #2442 overflow), not by
  demotion prep. The seq-fenced `DrainRequest`/`DrainComplete` pair (#2876/#2920)
  is documented as **reserved/dormant** — implemented and hardened but not wired
  to any production path.

## Known Limitations

### Sweep Latency

Kernel-originated session creation is still exported by periodic sweep, not by a
real-time event stream. Short-lived sessions can be missed between sweeps.

### No Real-Time BPF Session Event Stream

There is still no cheap real-time BPF event feed for full session state. The
current design intentionally uses periodic sweep for kernel sessions and keeps
the lower-latency userspace delta path scoped to the AF_XDP helper.

### Delete Journal Overflow

The delete journal is bounded (`deleteJournalCap`, default 10000). Extended
disconnects with high churn can push it past the cap, evicting the oldest queued
deletes. Those evicted records are session teardowns the standby still needs;
they are already gone from the primary's local table, so no incremental install
sweep can re-derive them.

**Recovery (#5450):** whenever an eviction actually DROPS records — in either
`journalDelete` (append past cap) or `rejournalTail` (re-journal-on-failure past
cap) — the drop site arms `forceResync` (a single atomic, CAS-armed once per
overflow episode; counted in `DeletesDropped`). `forceResync` is consumed by
whichever runs first:

- the periodic sweep (`syncSweep`) while connected, or
- the next reconnect (`handleNewConnection`, re-read AFTER `flushDeleteJournal`
  so an eviction during that flush is caught) even when the node is already
  primed (`bulkEverCompleted`),

and it sends a full authoritative `doBulkSync`/`BulkSync` snapshot. The peer's
`reconcileStaleSessions` (run at `BulkEnd`) then DELETES any session absent from
the snapshot — precisely the sessions the evicted deletes would have torn down.
On a failed bulk the arm is restored so a later sweep/reconnect retries. Before
#5450 an overflow only self-healed at the next unrelated full bulk reconcile,
which could be far away, so the standby carried ghost sessions (wrong forwarding
+ inflated session count) for a long time. `forceResync` is deliberately kept
distinct from `bulkEverCompleted` (which the daemon reads for VRRP sync-hold
gating) and from `syncBackfillNeeded` (which only re-drives INSTALLS).

### Counter Divergence

Counters are not kept perfectly current by incremental sync. Session state is
more important than exact byte/packet counters for failover.

### Failover Quality Still Depends on Dataplane Behavior

Correct session-sync admission does not guarantee zero-loss failover. The recent
userspace failover work showed that post-admission dataplane behavior can still
collapse if redirected traffic, queue selection, or translated alias handling is
wrong.

## Key Files

| File | Purpose |
|------|---------|
| `pkg/cluster/sync.go` | Wire protocol, bulk sync, barriers, retry state |
| `pkg/cluster/sync_test.go` | Session sync protocol tests |
| `pkg/daemon/daemon.go` | Readiness, retry, userspace delta filtering, demotion prep |
| `pkg/conntrack/gc.go` | GC delete callbacks |
| `pkg/dataplane/types.go` | Session key/value definitions |
| `pkg/dataplane/userspace/manager.go` | Userspace session install, helper RPCs |
| `userspace-dp/src/session.rs` | Rust session table |
| `userspace-dp/src/afxdp/session_glue.rs` | Userspace session promotion / refresh / export |
