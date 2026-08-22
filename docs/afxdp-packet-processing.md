# AF_XDP Userspace Dataplane Packet Processing

> #1373 note: this is the primary packet-processing path for new dataplane
> development and routine validation. References to the legacy BPF pipeline
> below describe explicit fallback/regression boundaries, not the preferred
> implementation target. The retained userspace shim no longer tail-calls into
> `xdp_main_prog` for degraded helper/XSK states. In degraded states it passes
> only proven local/control traffic to the kernel and drops non-local transit.

## 1. Architecture Overview

The userspace dataplane uses AF_XDP with driver-specific bind/runtime modes to
receive and transmit packets through shared UMEM memory regions.  An XDP shim program
(`xdp_userspace_prog` in `userspace-xdp/src/lib.rs`) runs on each ingress
interface and steers matching packets to AF_XDP sockets via an XSKMAP
(`userspace_xsk_map`).

### Packet steering decision (XDP shim)

The shim checks several conditions before redirecting a packet to userspace:

1. `userspace_ctrl` must be enabled with matching metadata version.
2. Ingress ifindex must be in `userspace_ingress_ifaces` map.
3. A binding must exist in `userspace_bindings` for (ifindex, queue_id) and be
   marked `USERSPACE_BINDING_READY`. `queue_id` is the packet's OWN RX queue,
   read once from the XDP context and never transformed on the way to the
   lookup — AF_XDP delivery is queue-bound, so redirecting to a socket bound to
   any other queue is rejected by `xsk_rcv_check()` and the packet dropped
   (#5173). `userspace_bindings` is a flat array indexed by
   `idx = ifindex * BINDING_QUEUES_PER_IFACE + queue_id`, where
   `BINDING_QUEUES_PER_IFACE == 16` (the fixed per-interface stride, defined in
   `userspace-xdp/src/binding_index.rs` alongside the `binding_slot()` mapping
   itself, and mirrored in `pkg/dataplane` `BindingQueuesPerIface` — NOT in
   `bpf/headers`, which only carries `MAX_INTERFACES`). Because the stride is
   fixed, BOTH sides bound the queue dimension:
   - **Write side.** The control plane
     (`pkg/dataplane/userspace/helper_status_apply.go` for the apply path,
     `maps_sync.go` for the watchdog) fails closed on two dimension
     overflows before writing any slot: a `queue_id >= 16` would alias the
     queue-0 slot of the adjacent ifindex (`ifindex*16 + 16 == (ifindex+1)*16`,
     #4894), and an `ifindex >= MAX_INTERFACES` would overflow the array cap
     (#814). The apply path disables `userspace_ctrl` and the watchdog logs and
     skips.
   - **Read side (shim).** `binding_slot()` returns no slot at all for a
     `queue_id >= 16`, so the shim takes its binding-missing path — local and
     control traffic passes, transit takes the explicit degraded drop. This is
     the matching read-side bound, and it is required because `rx_queue_index`
     comes from the hardware and nothing else clamps it.

   Out-of-stride queue IDs are never clamped/moduloed on either side: reducing
   the coordinate back into range would still steer to a wrong slot, which is
   the #5173 defect in another form. A NIC exposing more than 16 RX queues
   therefore requires reducing its channel count (`ethtool -L`) or a
   coordinated stride bump; the helper planner
   (`replan_bindings_from_candidates`) does not cap the queue count, so the
   Go boundary is the enforcement point for what gets published.
4. The binding's heartbeat (written every 250ms by the worker) must not be
   stale (default 5s timeout).
5. ICMP/ICMPv6 is handled by the userspace dataplane or passed to the kernel
   for local/control-plane delivery; the shim no longer tail-calls through
   `userspace_fallback_progs`.
6. Local-destination traffic (matching `userspace_local_v4`/`userspace_local_v6`) passes to kernel.
7. Non-SYN TCP without a live entry in `userspace_sessions` BPF map is dropped
   (not fallen back -- legacy BPF would generate RSTs that kill the real connection).
8. When helper/XSK state is degraded (`ctrl.enabled=0`, missing/not-ready
   binding, stale heartbeat, redirect failure), only the local/control cases
   above may reach the kernel. Transit drops and increments
   `transit_drop` in `degraded_path_counters`.

Packets that pass all checks get a `UserspaceDpMeta` header prepended via
`bpf_xdp_adjust_meta` and are redirected to the AF_XDP socket with
`bpf_redirect_map(&USERSPACE_XSK_MAP, slot)`.

### Per-binding UMEM and rings

Each AF_XDP binding gets its own `WorkerUmem` with independent fill,
completion, RX, and TX rings (`userspace-dp/src/afxdp.rs`).  Frame count is
`2 * ring_entries` (fill) + `reserved_tx_frames` (TX).  Default `ring_entries`
is 1024, configurable via `--ring-entries`.

```
WorkerUmem {
    area: MmapArea,           // mmap'd contiguous UMEM region
    umem: Umem,               // xdpilone UMEM handle
    total_frames: u32,        // fill frames + TX reserve
}
```

### Current runtime mode by driver

Current live behavior on the userspace HA lab is:

1. `mlx5_core` ingress bindings use the UMEM-owner zerocopy path.
2. `virtio_net` fabric bindings use the UMEM-owner copy-mode path with
   `bind_flags=0`.

That split was validated live during the Phase 2 cleanup work.  The failed
`virtio_net` separate-owner probe was removed from the active strategy because
it was not the correct bind contract for this environment.

## 2. The Fill Ring Exhaustion Bug

### Symptoms

Under sustained high throughput (1 Gbps+ TCP), large downloads stall after
partial transfer and the client receives "Connection reset by peer."

### Root cause

The mlx5 driver's AF_XDP RX path requires available frames in the fill ring.
When the userspace poll loop cannot refill frames fast enough, the fill ring
runs dry.  The driver counter `rx_xsk_buff_alloc_err` climbs to 102M+ during
a single transfer.

When no fill ring frames are available, mlx5 falls back to the regular
(non-XSK) NAPI RX path.  These leaked packets bypass AF_XDP entirely and
reach the kernel TCP stack via VLAN sub-interfaces.  The kernel finds no
socket for the SNAT'd IP addresses and emits TCP RSTs to the server, which
tears down the connection.

### Contributing factors

**TX backpressure halts RX processing** (`afxdp.rs:1842-1849`):

```rust
let tx_backlog = binding.pending_tx_local.len() + binding.pending_tx_prepared.len();
if tx_backlog >= binding.max_pending_tx {
    binding.dbg_backpressure += 1;
    let _ = drain_pending_tx(binding, now_ns, shared_recycles);
    return did_work;  // <-- early exit, no fill ring refill
}
```

When `pending_tx_prepared.len() + pending_tx_local.len() >= max_pending_tx`,
the entire RX loop returns early.  This also skips `drain_pending_fill()`,
starving the fill ring of recycled frames during the exact conditions (high
forwarding load) that consume them fastest.

**Copy mode overhead**: Each redirected packet incurs a `memcpy` from kernel
DMA buffer into UMEM, slowing the RX-to-fill-ring recycle loop versus
zero-copy.

**Single-queue processing**: One worker thread handles one (ifindex, queue_id)
pair; all RX, TX, fill ring management, and session lookups are serialized.

### 2a. Bringup fill-ring prime: partial-insert recovery (#2374)

At socket bringup the worker constructor pops every non-reserved UMEM frame
into `initial_fill_frames` and primes the RX fill ring with all of them via
`prime_fill_ring_offsets()` (`userspace-dp/src/afxdp/bind.rs`). Two failure
modes are handled:

- **Total failure** (`inserted == 0` on a non-empty prime): fatal. The socket
  would run with no RX descriptors, so the bind fails closed
  (`fill_prime_is_total_failure`).
- **Partial insert** (`0 < inserted < N`, e.g. a transiently-full ring during
  rebind / shared-UMEM group churn): the prime first retries the un-inserted
  suffix across the NAPI-trigger loop (each `recvmsg`/`poll`/`sendto` lets the
  kernel consume fill entries and free ring slots). Any suffix the ring still
  has not accepted is **returned** (`defer_uninserted_fill_suffix`) and threaded
  back through `open_binding_worker_rings` into the worker's
  `pending_fill_frames` queue. The steady-state `drain_pending_fill()` loop then
  retries exactly those offsets.

Before #2374 the prime errored only on `inserted == 0` and silently accepted a
partial insert: the `(N - inserted)` un-inserted frames were dropped from every
local pool (`pending_fill_frames` started empty), permanently shrinking RX
capacity and starving the fill ring. The recovery mirrors the steady-state
suffix recovery in `tx::rings::drain_pending_fill` (which already pushes a
partial-insert suffix back onto `pending_fill_frames`) so bringup and the
running loop handle a short fill-ring insert identically.

## 3. Current Mitigation: nftables RST Suppression

Since the root cause is kernel-emitted RSTs for SNAT addresses the kernel
doesn't own, the dataplane installs nftables rules to suppress them.

`install_kernel_rst_suppression()` (`afxdp.rs:6499`) creates an
`inet xpf_dp_rst` table with an output chain that drops outgoing TCP RSTs
from all interface-NAT (SNAT) addresses:

```
table inet xpf_dp_rst {
  chain output {
    type filter hook output priority 0; policy accept;
    ip saddr <snat_v4_addr> tcp flags & rst == rst counter drop
    ip6 saddr <snat_v6_addr> tcp flags & rst == rst counter drop
  }
}
```

The rules are:
- Auto-installed when forwarding state is rebuilt from the config snapshot.
- Auto-removed on DP shutdown via `remove_kernel_rst_suppression()` (`afxdp.rs:6603`).

**Validation**: 1m / 100m / 500m / 1g downloads complete at ~107 MB/s through
NAT.  Before the fix, 1g downloads failed 100% of the time.

## 4. Queue And Frame Ownership After Phase 4

Phase 4 of the cleanup plan made the prepared-TX recycle path explicit.

### 4a. Explicit prepared-TX recycle ownership

Prepared TX requests now carry an explicit recycle destination instead of the
older implicit "maybe a slot, maybe a TX frame" model:

```rust
enum PreparedTxRecycle {
    FreeTxFrame,
    FillOnSlot(u32),
}
```

This makes it obvious whether a completed prepared transmit should:

1. return a reserved TX frame to the TX frame pool, or
2. replenish the fill path for a specific ingress slot.

### 4b. Centralized queue merge / drain / restore helpers

Pending local and prepared TX requests are now merged and restored through a
single helper path in `userspace-dp/src/afxdp/tx.rs` instead of open-coded
queue stitching in multiple places.

That cleanup made three things explicit:

1. merge order between local and shared prepared requests
2. when pending requests are restored after backpressure or partial transmit
3. how completion reaping maps offsets back to either TX-frame free or
   fill-ring replenishment

### 4c. What is still left

Phase 4 was about making ownership explicit, not finishing throughput tuning.
The remaining work is now cleaner:

1. measure and optimize sustained forwarding throughput
2. reduce retransmits on the common forward path
3. improve validation so TTL / hop-limit probes do not fail the shell harness
   when they correctly return time-exceeded with a non-zero exit code

## 5. Performance Metrics

| Metric | Value |
|--------|-------|
| Current throughput (1g NAT download) | ~107 MB/s |
| Target | Line rate on mlx5 (10 Gbps+) |
| Copy-mode overhead | 1x `memcpy` per redirected packet |
| Fill ring exhaustion events (pre-fix) | 102M+ (`rx_xsk_buff_alloc_err`) |
| Poll cycle budget | 4 RX batches x 256 packets = 1024 packets/cycle |

**Bottlenecks** (ordered by impact):
1. Common forward-path retransmits and sustained-throughput collapse
2. Queue drain / completion / recycle cost in the mixed copy/zerocopy runtime
3. Single-queue processing (no RSS fan-out)
4. Session table contention (if multi-queue)

**Monitoring**:
- `ethtool -S <iface> | grep xsk` -- driver-level AF_XDP stats (`rx_xsk_buff_alloc_err`, `rx_xsk_packets`, etc.)
- `show chassis cluster data-plane statistics`
- `show chassis cluster data-plane interfaces`
- `dbg_backpressure` counter tracks TX backpressure events per binding

## 6. Debug Instrumentation

**Compile-time feature**: `cargo build --features debug-log`

| Build | Behavior |
|-------|----------|
| Without `debug-log` | Zero-overhead production build. `debug_log!()` compiles to nothing. |
| With `debug-log` | Per-packet TCP flag parsing, RST detection, hex dumps, checksum verification, session dumps, stall detection, ring diagnostics. |

**XDP degraded path counters**: The shim maintains per-reason counters for
retained-shim degraded actions. Go exposes them in status JSON as
`degraded_path_counters`. The pinned BPF map remains
`userspace_fallback_stats` as an internal mixed-version compatibility
exception. The map is a **per-CPU** `u64` array (`#4113`): native XDP runs
one program instance per RX queue on distinct CPUs concurrently, and
`incr_fallback_stat` does a non-atomic load/add/store; a shared array would
lose increments when two CPUs bump the same reason in the same window. Per-CPU
storage makes each increment CPU-local; the Go and helper readers
(`readDegradedPathStatsLocked`, `read_degraded_path_stats`) sum across CPUs.

**Trace map insert is trace-flag gated (`#4113`)**: `record_trace` writes the
`userspace_trace` BPF map (a `bpf_ktime_get_ns` read plus an avalanche key
compute plus a `bpf_map_update_elem`) **only** when the control flag
`USERSPACE_CTRL_FLAG_TRACE` is set. Earlier code force-inserted for the
`EARLY_FILTER` / `BINDING_MISSING` stages even with tracing disabled, which was
reachable by unauthenticated traffic aimed at well-known multicast/broadcast
groups (`should_fallback_early`) or during a transient config-reload unbind —
an attacker-influenceable per-packet map-update on the native-XDP ingress core.
Visibility for those stages is preserved by the per-CPU degraded-path counter,
which the call sites bump independently of the trace insert.

**Binding debug state**: Each `BindingWorker` tracks live ring state
(`debug_pending_fill_frames`, `debug_free_tx_frames`,
`debug_pending_tx_prepared`, `debug_outstanding_tx`) exposed via the
coordinator's status reporting.
