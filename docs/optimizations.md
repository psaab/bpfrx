# Performance Optimizations

## Implemented

### 1. Disable bpf_printk (`e104112`)
- **Impact:** 55%+ CPU → negligible
- Debug tracing was the #1 CPU consumer

### 2. Reduce per-packet memset/memcpy (`299a536`)
- Only zero fields actually used, not entire scratch struct

### 3. FIB result caching in sessions (`144a3c2`)
- Cache `fwd_ifindex`, `fwd_dmac`, `fwd_smac` in session entries
- Skip `bpf_fib_lookup` on established flows
- Skip cache on TCP SYN (need fresh FIB for new connections)

### 4. Per-CPU NAT port partitioning (`7aa77f0`)
- Eliminate cross-CPU contention on NAT port counters

### 5. Per-interface native XDP (`f9edb92`)
- virtio-net: native XDP + `ndo_xdp_xmit` → `bpf_redirect_map`
- i40e (PCI passthrough PF): native XDP + `ndo_xdp_xmit` → `bpf_redirect_map`
- Historical: iavf (SR-IOV VF) forced generic XDP → `XDP_PASS` for kernel forwarding
- All-or-nothing mode: code tries native on ALL interfaces, falls back to generic if ANY fails
- `redirect_capable` BPF array map tells xdp_forward which mode each interface supports
- **Result:** ~6.8 Gbps → 25+ Gbps

### 6. Disable init_on_alloc (`a0aabfd`)
- **Impact:** Eliminates 20% CPU from `clear_page_erms` page zeroing
- Debian's `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` zeros every allocated page
- Boot param `init_on_alloc=0` in GRUB; set in `test/incus/setup.sh`
- Not runtime tunable — boot-time only

## Perf Profile (virtio-net, init_on_alloc=0, Feb 2026)

During iperf3 trust→untrust through firewall (~12 Gbps BBR, ~6 Gbps CUBIC):
```
 6.7%  xdp_forward_prog      (forwarding stage)
 5.9%  xdp_main_prog         (entry point)
 4.6%  receive_buf           (virtio-net RX)
 4.3%  htab_map_hash         (BPF hash map lookups)
 3.8%  xdp_zone_prog         (zone + conntrack fast-path)
 2.7%  lookup_nulls_elem_raw (hash element traversal)
 2.3%  virtnet_rq_unmap      (virtio RX buffer cleanup)
 2.1%  virtnet_xdp_xmit      (XDP redirect TX)
 1.9%  read_tsc              (conntrack ktime)
 1.8%  virtnet_rq_alloc      (virtio RX buffer alloc)
 1.7%  __htab_map_lookup_elem (hash map lookup wrapper)
```

## Previous Perf Profile (Native XDP, Physical NIC, Feb 2026)

BPF programs total ~10% CPU. Generic XDP infrastructure ~16% (only on iavf interface).
FIB lookup: 0% (cached in session entries).

```
 2.8%  htab_map_hash         (BPF hash map lookups)
 2.7%  xdp_main_prog         (entry point)
 2.5%  read_tsc              (conntrack ktime)
 2.1%  lookup_nulls_elem_raw (hash element traversal)
 2.0%  iavf_xmit_frame       (SR-IOV TX — generic XDP only)
 1.7%  xdp_forward_prog      (forwarding stage)
 1.6%  csum_partial          (TX checksum)
 1.5%  xdp_conntrack_prog    (session lookup)
 1.1%  xdp_zone_prog         (zone + conntrack fast-path)
 1.0%  xdp_nat_prog          (NAT translation)
```

### 7. Host GRUB: init_on_alloc=0 + hardened_usercopy=off + mitigations=off
- **Impact (measured):** 21-25% throughput increase (12.1→14.7 Gbps reverse, 12.2→15.2 Gbps forward, 8×BBR)

### 8. tc mirred bridge bypass (tested, not persisted)
- **Impact (measured):** +6-7% throughput (14.7→15.6 Gbps reverse, 15.2→16.3 Gbps forward, 8×BBR)
- `tc filter add dev <tap> ingress matchall action mirred egress redirect dev <veth>` (and reverse)
- Problem: blanket `matchall` breaks host-routed traffic (WAN, DHCP, ARP to bridge IP)
- Needs selective filter (e.g., match on dst MAC) to avoid redirecting non-peer traffic
- Not persisted — rules are ephemeral and lost on reboot
- Host was running with `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` (31% in `clear_page_erms`),
  `CONFIG_HARDENED_USERCOPY_DEFAULT_ON=y` (18% in `__check_object_size`),
  and full CPU mitigations enabled
- Added to `/etc/default/grub` + `update-grub`; requires reboot

### 9. IPv6 established-flow cache in `xdp_zone` (`perf-ipv6-flow-cache`)
- **Goal:** reduce `sessions_v6` lookup pressure for long-running IPv6 TCP flows
- Added a small per-CPU exact-flow cache for established IPv6 TCP traffic
- Cache is intentionally narrow:
  - IPv6 only
  - TCP ACK/data only
  - no `SYN/FIN/RST`
  - no `NAT64`, `ALG`, or predicted sessions
- Cache entries batch counter / `last_seen` writeback to the real session map
- Invalidates on FIB generation change or RG ownership loss
- Design notes: `docs/next-features/ipv6-session-fast-path.md`

### 10. IPv6 no-extension parse fast path + narrower NAT rewrite (`perf-ipv6-flow-cache`)
- Added a common-case fast return in `parse_ipv6hdr()` when the base IPv6 header directly names the upper-layer protocol
- The generic extension-header walker now runs only when extension headers are actually present
- Reworked `nat_rewrite_v6()` to specialize by protocol and actual NAT direction
- This avoids repeated protocol branches and avoids touching source/destination fields that are not changing for the packet

## Host-Side Perf Profile (from host during iperf through VM, Feb 2026)

Profile captured from the **host** (not VM). No BPF/XDP stacks visible — XDP pipeline
is essentially free from host perspective. Bottleneck is entirely virtualization:

```
67.38%  memcpy (vhost ring copy)     — rep_movs_alternative in handle_tx_copy/handle_rx
59.40%  KVM hypervisor               — vcpu_halt, apic, vmx_sync, lapic
49.61%  checksum (csum_partial)      — TCP/IP checksum (no HW offload on tun/tap)
31.36%  clear_page_erms              — init_on_alloc=1 (FIXED in GRUB)
24.30%  TCP stack                    — iperf3 endpoint processing on containers
23.87%  Linux bridge                 — br_handle_frame for every packet (tap↔veth)
20.30%  flow dissect + hash          — __skb_flow_dissect + siphash for multiqueue
18.09%  HARDENED_USERCOPY            — __check_object_size (FIXED in GRUB)
12.33%  netif backlog                — process_backlog / __netif_receive_skb
11.64%  slab alloc/free              — kmem_cache/slab for skb lifecycle
10.10%  vhost virtqueue ops          — vhost_get_vq_desc_n / vhost_net_buf_peek
 8.46%  skb free                     — consume_skb / skb_release_data
 5.84%  GSO segmentation             — tcp_gso_segment / skb_segment
```
(Percentages sum >100% due to perf report hierarchy duplication)

### Key insight
The Incus bridge networks (xpf-trust, xpf-untrust, etc.) each have only 2 ports
(VM tap + container veth), so the bridge adds ~24% CPU overhead with zero benefit.
Switching to macvtap, routed, or tc-redirect could eliminate this entirely.

## Future Possibilities

### Bridge + veth for iavf
- Bridge iavf with a veth pair; attach XDP to veth end (fully supports native)
- Would eliminate remaining generic XDP overhead on WAN interface
- Pro: no BPF changes. Con: extra bridge hop, network config complexity

### XDP-capable NIC replacement
- ice, i40e, mlx5, ixgbe, bnxt all support native XDP
- Would make all interfaces native, eliminate need for redirect_capable map

### BPF hash map optimization
- `htab_map_hash` is the top BPF-related CPU consumer
- Could explore bloom filter pre-check or session ID optimization
- Diminishing returns — 2.8% is already very low

### Incus bridge bypass for test containers
- Bridges (xpf-trust, etc.) consume ~24% host CPU just for 2-port L2 forwarding
- Options: macvtap NIC type, `tc redirect` hairpin, or routed mode
- Would eliminate `br_handle_frame` + `br_dev_queue_push_xmit` overhead

### Host flow dissect / hash reduction
- `__skb_flow_dissect` + `siphash` consume ~20% on host for multiqueue steering
- Could disable RPS/RFS on tap devices if single-queue is sufficient
- `ethtool -K tapXXX rx-flow-hash off` (if supported)

### Virtio-net checksum offload
- `csum_partial` is 50% of host CPU — host computing checksums for tun/tap path
- Verify guest csum offload is enabled end-to-end
- SR-IOV passthrough (already used for WAN) bypasses this entirely

## Cluster Failover Timing (Implemented, `ff7821c`, updated `ae1a717`)

### Sub-100ms VRRP advertisement interval (`ae1a717`)
- **Impact:** Failover from ~0.8s → **~60ms** (measured 6 lost pings at 10ms interval)
- RETH instances: **30ms interval** (was 250ms, was 1s); configurable via `set chassis cluster reth-advertise-interval <ms>`
- masterDownInterval: 3 × 30ms + 56/256 × 30ms = **~97ms** (was 805ms, was 3.219s)
- **Planned shutdown (priority-0):** burst of 3× priority-0 adverts; peer immediate takeover in ~1ms (was ~55ms skew)
- **Async GARP:** `becomeMaster()` sends advert first (sync), GARP in background goroutine (was blocking ~200ms)
- **Burst GARP:** `SendGratuitousARPBurst()` sends first pair <1ms, remaining at 50ms intervals in background
- `AdvertiseInterval` field in milliseconds internally; wire format in centiseconds per RFC 5798
- Per-RG `GratuitousARPCount` wired through to VRRP instances

### Session sync connect optimization
- **Impact:** Failback sync from 5-10s → 1-2s
- Immediate first dial attempt (was 5s wait before first attempt)
- 1s retry interval (was 5s)

### Event debounce reduction
- **Impact:** VRRP priority update 1.5s faster
- `watchClusterEvents()` debounce: 500ms (was 2s)

### Sync hold timeout reduction
- 10s timeout (was 30s) — safety net if bulk sync never completes

### Heartbeat timer tuning
- 200ms interval, threshold 5 → 1s detection (was 1000ms interval, threshold 3 → 3s)

### systemd RestartSec
- 1s (was 5s) — faster crash recovery restart

### Measured Failover/Failback Times
| Scenario | Original | `ff7821c` | `ae1a717` |
|----------|----------|-----------|-----------|
| Failover (daemon dies → peer takes over) | ~3.2s | ~0.8s | **~60ms** |
| Clean stop (priority-0 → peer skew) | ~219ms | ~55ms | **~1ms** |
| Failback (daemon returns → preempts) | ~5-6s | ~2-3s | **~130ms** |
| Single node reboot → MASTER | N/A | ~6s | ~6s |
| Simultaneous reboot → converge | N/A | ~10s | ~10s |
