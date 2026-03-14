# AF_XDP Userspace Dataplane Packet Processing

## 1. Architecture Overview

The userspace dataplane uses AF_XDP (copy mode) on mlx5 NICs to receive and
transmit packets through shared UMEM memory regions.  An XDP shim program
(`xdp_userspace_prog` in `userspace-xdp/src/lib.rs`) runs on each ingress
interface and steers matching packets to AF_XDP sockets via an XSKMAP
(`userspace_xsk_map`).

### Packet steering decision (XDP shim)

The shim checks several conditions before redirecting a packet to userspace:

1. `userspace_ctrl` must be enabled with matching metadata version.
2. Ingress ifindex must be in `userspace_ingress_ifaces` map.
3. A binding must exist in `userspace_bindings` for (ifindex, queue_id) and be
   marked `USERSPACE_BINDING_READY`.
4. The binding's heartbeat (written every 250ms by the worker) must not be
   stale (default 5s timeout).
5. ICMP/ICMPv6 falls back to the legacy BPF pipeline via `userspace_fallback_progs` tail call.
6. Local-destination traffic (matching `userspace_local_v4`/`userspace_local_v6`) passes to kernel.
7. Non-SYN TCP without a live entry in `userspace_sessions` BPF map is dropped
   (not fallen back -- legacy BPF would generate RSTs that kill the real connection).

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

### Why copy mode (not zero-copy)

Zero-copy mode on mlx5 permanently leaks UMEM frames when the XDP shim
returns `XDP_PASS`.  The kernel places the UMEM frame into an SKB and never
returns it to the fill ring.  With any XDP_PASS path (ARP, management traffic,
ICMP fallback, local destinations), all 12K+ RX frames drain within seconds of
sustained traffic, producing permanent `rx_xsk_buff_alloc_err`.

In copy mode, `XDP_PASS` operates on kernel DMA buffers.  UMEM frames are only
consumed by `XDP_REDIRECT -> XSK`, and userspace always recycles them.  The
cost is one `memcpy` per redirected packet.

See `TODO(#209)` in `afxdp.rs:55` for the zero-copy restoration plan.

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

## 3. Current Mitigation: nftables RST Suppression

Since the root cause is kernel-emitted RSTs for SNAT addresses the kernel
doesn't own, the dataplane installs nftables rules to suppress them.

`install_kernel_rst_suppression()` (`afxdp.rs:6499`) creates an
`inet bpfrx_dp_rst` table with an output chain that drops outgoing TCP RSTs
from all interface-NAT (SNAT) addresses:

```
table inet bpfrx_dp_rst {
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

## 4. Improvement Plan

### 4a. Fill Ring Management

**Drain fill ring during TX backpressure.**  The backpressure early-exit path
(`afxdp.rs:1849`) returns without calling `drain_pending_fill()`.  Fix: insert
a `drain_pending_fill(binding, now_ns)` call before `return did_work` so
recycled frames reach the fill ring even when TX is congested.

**Increase default `ring_entries`.**  Current default is 1024
(`main.rs:933`).  With `binding_frame_count()` allocating `2 * ring_entries`
fill frames, that gives 2048 fill slots.  Increasing to 4096 or 8192 provides
a larger buffer pool to absorb bursts before exhaustion.

**Adaptive fill ring watermark.**  Monitor `pending_fill_frames.len()` relative
to capacity.  If it drops below 50%, trigger aggressive refill from all
available recycled frames (TX completions, shared recycles) before processing
the next RX batch.

### 4b. TX Completion Optimization

**Eager completion reaping.**  TX completions currently happen once per poll
cycle (`drain_pending_tx` at `afxdp.rs:1836`).  On cross-binding forwarding,
completed TX frames often need to become fill ring frames on the originating
binding.  Reap completions more frequently -- after every RX batch, not just at
poll entry.

**Reduce TX backlog limit.**  `PENDING_TX_LIMIT_MULTIPLIER` is 2
(`afxdp.rs:49`), giving `max_pending_tx = ring_entries * 2`.  Lowering this
activates backpressure earlier, before fill ring starvation reaches critical
levels.  Combined with the fill-ring-during-backpressure fix, earlier
backpressure becomes safe.

### 4c. Zero-Copy Restoration (Long-term, Issue #209)

The fundamental blocker is that `XDP_PASS` in zero-copy mode permanently leaks
UMEM frames.  The solution is to eliminate all `XDP_PASS` paths in the XDP
shim:

| Current XDP_PASS path | Replacement |
|------------------------|-------------|
| ARP | `cpumap` redirect to CPU processing queue |
| Management traffic (local dest) | `cpumap` redirect |
| ICMP fallback | `cpumap` redirect |
| Non-IP ethertype | `cpumap` redirect |
| Unknown/error paths | `cpumap` redirect |

`cpumap` redirect frees the XSK frame immediately while still delivering the
packet to the kernel stack via a new SKB.  This eliminates copy-mode `memcpy`
overhead entirely.

Requires:
- BPF shim changes: replace all `XDP_PASS` returns with `bpf_redirect_map(&CPUMAP, cpu, 0)`.
- A cpumap program entry point for kernel delivery.
- Testing that cpumap redirect does not lose VLAN tags or metadata needed by the legacy pipeline.

### 4d. Poll Loop Optimization

**`NEED_WAKEUP`**: Already enabled (`XDP_BIND_NEED_WAKEUP` in bind flags,
`afxdp.rs:60`).  Reduces unnecessary `sendto()` calls when the kernel doesn't
need waking.

**Idle sleep**: Set to 1us (`IDLE_SLEEP_US`, `afxdp.rs:62`) for fast response
to new packets.  The idle spin count (`IDLE_SPIN_ITERS=256`) avoids the
syscall cost of `nanosleep` for brief gaps.

**Batch sizes**: `RX_BATCH_SIZE=256`, `FILL_BATCH_SIZE=1024`
(`afxdp.rs:45,50`).  Up to `MAX_RX_BATCHES_PER_POLL=4` RX batches per poll
cycle, processing up to 1024 packets before re-checking TX and fill rings.

**Debug logging overhead**: The `debug_log!` macro (`afxdp.rs:34`) is gated
behind a compile-time `debug-log` Cargo feature (`userspace-dp/Cargo.toml:8`).
Without the feature, all per-packet TCP flag parsing, RST detection, hex dumps,
and checksum verification are compiled out -- zero overhead in production.

### 4e. Multi-Queue Scaling

Each AF_XDP binding handles one `(ifindex, queue_id)` pair.  mlx5 supports RSS
across multiple RX queues.  Scaling path:

1. Configure multiple RX queues on the mlx5 interface (`ethtool -L <iface> combined N`).
2. Create N AF_XDP bindings, one per queue, each with its own `WorkerUmem`.
3. Worker threads poll their respective bindings independently.
4. RSS distributes flows across queues; each worker processes a subset of traffic.

The `Coordinator` already supports multiple bindings per worker
(`afxdp.rs:132-150`), and bindings are grouped by `worker_id`.  The main gap
is coordinating session table access across workers (currently a single
`SessionTable` per worker thread).

## 5. Performance Metrics

| Metric | Value |
|--------|-------|
| Current throughput (1g NAT download) | ~107 MB/s |
| Target | Line rate on mlx5 (10 Gbps+) |
| Copy-mode overhead | 1x `memcpy` per redirected packet |
| Fill ring exhaustion events (pre-fix) | 102M+ (`rx_xsk_buff_alloc_err`) |
| Poll cycle budget | 4 RX batches x 256 packets = 1024 packets/cycle |

**Bottlenecks** (ordered by impact):
1. Copy-mode `memcpy` per packet
2. Single-queue processing (no RSS fan-out)
3. Fill ring starvation during TX backpressure
4. Session table contention (if multi-queue)

**Monitoring**:
- `ethtool -S <iface> | grep xsk` -- driver-level AF_XDP stats (`rx_xsk_buff_alloc_err`, `rx_xsk_packets`, etc.)
- Periodic `DBG w{worker_id}:` summary in journal (every 1s, always enabled)
- `dbg_backpressure` counter tracks TX backpressure events per binding

## 6. Debug Instrumentation

**Compile-time feature**: `cargo build --features debug-log`

| Build | Behavior |
|-------|----------|
| Without `debug-log` | Zero-overhead production build. `debug_log!()` compiles to nothing. |
| With `debug-log` | Per-packet TCP flag parsing, RST detection, hex dumps, checksum verification, session dumps, stall detection, ring diagnostics. |

**Periodic summary (always enabled)**: Every 1s (`DBG_REPORT_INTERVAL_NS`,
`afxdp.rs:5716`), each worker logs counters including rx/tx/fwd totals,
session hit/miss/create, NAT counters, RST counts, direction breakdowns,
and ring state.  Format:

```
DBG w0: 1.0s rx=15234 tx=15100 fwd=14900 local=334 sess_hit=14800 sess_miss=100 ...
```

**XDP fallback stats**: The shim maintains per-reason counters in
`userspace_fallback_stats` (array map with `USERSPACE_FALLBACK_REASON_MAX`
entries).  The worker reads and logs these as `DBG w{}: XDP_FALLBACK: ...`.

**Binding debug state**: Each `BindingWorker` tracks live ring state
(`debug_pending_fill_frames`, `debug_free_tx_frames`,
`debug_pending_tx_prepared`, `debug_outstanding_tx`) exposed via the
coordinator's status reporting.
