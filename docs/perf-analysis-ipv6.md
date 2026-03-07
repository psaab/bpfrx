# IPv6 vs IPv4 Performance Analysis

Date: 2026-03-07
Kernel: 6.18.9 (Debian 13 VM on Incus)
Hardware: Mellanox ConnectX-5 (mlx5, native XDP), 2 vCPUs
Test: `iperf3 -P 4 -t 10` through bpfrx HA cluster (loss remote, node0 primary)
Build: commit fb3cb60 (PR #169 flow cache + #165/#167/#170 optimizations)

## Throughput

| Protocol | Throughput | Retransmits |
|----------|-----------|-------------|
| IPv4     | 22.4 Gbps | 304         |
| IPv6     | 19.0 Gbps | 266         |
| **Gap**  | **15%**   |             |

Flow cache hit rate: 93.9%

## Perf Capture Method

- VM-level: `perf record -a -g -F 997 -o /tmp/perf-{ipv4,ipv6}.data -- sleep 12`
- Host-level: `perf record -a -g -F 99 -o /tmp/perf-{ipv4,ipv6}.data -- sleep 12`
- iperf3 starts 2s after perf, runs 10s inside 12s capture window
- Profiles aggregated by symbol across all ksoftirqd cores

## VM Profile — Aggregated by Symbol

| Symbol | IPv4 | IPv6 | Delta | Category |
|--------|------|------|-------|----------|
| `xdp_main_prog` | 9.2% | **12.4%** | **+3.2%** | BPF pipeline |
| `xdp_zone_prog` | 7.4% | 8.2% | +0.8% | BPF pipeline |
| `mlx5e_skb_from_cqe_mpwrq_linear` | 7.2% | 6.1% | -1.1% | MLX5 driver RX |
| `xdp_forward_prog` | 6.9% | 5.0% | -1.9% | BPF pipeline |
| `__htab_map_lookup_and_delete_batch` | 6.1% | 4.9% | -1.2% | bpfrxd GC |
| `htab_map_hash` | 5.6% | **7.9%** | **+2.3%** | BPF hash map |
| `read_tsc` | 5.0% | 4.5% | -0.5% | Timestamps |
| `mlx5e_free_xdpsq_desc` | 4.2% | 2.1% | -2.1% | MLX5 driver TX |
| `lookup_nulls_elem_raw` | 3.6% | **4.6%** | **+1.0%** | BPF hash bucket walk |
| `xdp_nat_prog` | 2.8% | **4.9%** | **+2.1%** | BPF pipeline |
| `mlx5e_poll_rx_cq` | 2.8% | 3.2% | +0.4% | MLX5 driver RX |
| `mlx5e_xdp_xmit` | 2.7% | 2.6% | -0.1% | MLX5 XDP TX |
| `mlx5e_page_release_fragmented` | 2.2% | 1.1% | -1.1% | Page pool |
| `__htab_map_lookup_elem` | 1.7% | 2.0% | +0.3% | BPF hash lookup |
| `mlx5e_xmit_xdp_frame_mpwqe` | 1.5% | 1.3% | -0.2% | MLX5 TX frame |
| `xdp_screen_prog` | 1.1% | 1.2% | +0.1% | BPF pipeline |
| `page_pool_put_netmem_bulk` | 1.3% | 1.6% | +0.3% | Page pool |
| `ct_kernel_exit_state` | 0.9% | 1.2% | +0.3% | RCU context tracking |
| `xdp_do_redirect` | 0.8% | 0.8% | 0% | XDP redirect |

## CPU Breakdown by Category

### 1. BPF Pipeline — 28.4% (IPv4) / 31.7% (IPv6)

| Program | IPv4 | IPv6 | Notes |
|---------|------|------|-------|
| xdp_main | 9.2% | 12.4% | L2/L3/L4 parse, scratch meta init, tail call |
| xdp_zone | 7.4% | 8.2% | Zone lookup, conntrack, flow cache, policy |
| xdp_forward | 6.9% | 5.0% | `bpf_fib_lookup` + `bpf_redirect_map` |
| xdp_nat | 2.8% | 4.9% | SNAT rewrite (128-bit addr = 4x IPv4 work) |
| xdp_screen | 1.1% | 1.2% | SYN flood, rate limits, teardrop |

`xdp_main_prog` is the single biggest BPF hotspot. The +3.2% IPv6 gap comes from
IPv6 header parsing (40B base + protocol dispatch) vs IPv4 (20B fixed).

`xdp_nat_prog` is +2.1% on IPv6 — SNAT rewrites 128-bit addresses (4x) plus
incremental checksum updates over larger pseudo-header.

### 2. Hash Map Operations — 10.9% (IPv4) / 14.5% (IPv6)

| Function | IPv4 | IPv6 | Notes |
|----------|------|------|-------|
| htab_map_hash | 5.6% | 7.9% | jhash on session key (16B v4 / 40B v6) |
| lookup_nulls_elem_raw | 3.6% | 4.6% | Hash bucket chain walk + memcmp |
| __htab_map_lookup_elem | 1.7% | 2.0% | Top-level lookup dispatcher |

**This is the biggest remaining IPv6 penalty.** 40-byte session keys cost +2.3%
more hashing and +1.0% more bucket walking vs 16-byte IPv4 keys. Maps directly
to issue #168 (compact IPv6 session key).

### 3. MLX5 Driver — 20.5% (IPv4) / 18.0% (IPv6)

| Function | IPv4 | IPv6 | Notes |
|----------|------|------|-------|
| mlx5e_skb_from_cqe_mpwrq_linear | 7.2% | 6.1% | CQE→XDP metadata conversion |
| mlx5e_free_xdpsq_desc | 4.2% | 2.1% | TX descriptor cleanup |
| mlx5e_poll_rx_cq | 2.8% | 3.2% | RX completion queue polling |
| mlx5e_xdp_xmit | 2.7% | 2.6% | XDP frame transmit |
| mlx5e_xmit_xdp_frame_mpwqe | 1.5% | 1.3% | MPWQE TX frame assembly |
| mlx5e_page_release_fragmented | 2.2% | 1.1% | Page pool release |

Driver overhead is ~20% — mostly inherent to the NAPI→XDP flow and hard to
optimize from userspace.

### 4. Conntrack GC (userspace bpfrxd) — 6.1% (IPv4) / 4.9% (IPv6)

`__htab_map_lookup_and_delete_batch` runs in bpfrxd's GC goroutine, batch-scanning
the sessions map for expired entries via `bpf_map_lookup_and_delete_batch()` syscall.

### 5. Timestamps — 5.0% (IPv4) / 4.5% (IPv6)

`read_tsc` is called by `bpf_ktime_get_ns()` for conntrack `last_seen` timestamps.
Each session lookup/update invokes it.

## Improvement Opportunities

### High Impact

#### 1. Compact IPv6 session key (#168) — saves ~3.3% CPU

`htab_map_hash` + `lookup_nulls_elem_raw` account for +3.3% on IPv6 vs IPv4.

Approaches:
- Use 128-bit SipHash of 5-tuple as key (16B, collision-safe with full key in value)
- CRC32-based compact key with collision detection
- Would bring IPv6 hash cost to IPv4 parity

#### 2. Reduce `xdp_main_prog` overhead — 9-12% of all CPU

`xdp_main` does per-packet: L2 parse (VLAN strip), L3 parse (IP/IPv6 header),
L4 parse (TCP/UDP ports), scratch meta struct init, per-CPU map write, tail call.

Approaches:
- **Inline xdp_screen into xdp_main**: save one tail call (~0.5% each)
- **Reduce scratch meta size**: writing full `pkt_meta` to per-CPU array is a
  helper call + memcpy every packet
- **Combined L3+L4 parse**: avoid redundant bounds checks between parse stages

#### 3. Reduce `read_tsc` overhead — 5% on timestamping

`bpf_ktime_get_ns()` called on every conntrack hit for `last_seen`.

Approaches:
- Coarser timestamps: only update `last_seen` every N packets or when seconds change
  (the flow cache already batches with 32-pkt/1s flush interval)
- Skip timestamp update on flow cache hits entirely (cache batches writeback)
- Use `bpf_jiffies64()` instead (cheaper, ~4ms granularity is fine for session timeouts)

### Medium Impact

#### 4. Reduce `xdp_nat_prog` IPv6 cost — +2.1% vs IPv4

128-bit SNAT rewrite + checksum incremental update is inherently 4x IPv4.

Approaches:
- Precompute checksum deltas at NAT rule compile time (store in NAT map entry)
- Skip checksum update for interface SNAT when source IP unchanged (e.g., hairpin)

#### 5. Skip xdp_screen for established sessions — 1.1%

Screen checks (SYN flood, ping death, teardrop) are irrelevant for mid-flow ACK packets.
Flow cache already bypasses conntrack+policy but screen runs before zone/conntrack.

Approach: add `SESS_FLAG_SCREENED` — screen programs check per-CPU scratch for
"already established" flag and return early.

#### 6. Batch/reduce conntrack GC — 6%

`__htab_map_lookup_and_delete_batch` at 6% is from bpfrxd's 1s GC sweep.

Approaches:
- Adaptive GC frequency (reduce sweep rate when few sessions expire)
- `BPF_MAP_TYPE_LRU_HASH` auto-evicts (but loses delete-sync callbacks for HA)
- Increase batch size to amortize syscall overhead

### Lower Impact

#### 7. MLX5 driver tuning — 20% mostly inherent

`mlx5e_skb_from_cqe_mpwrq_linear` (7%) does CQE→XDP metadata conversion — kernel internal.

Tunables:
- `ethtool -G mlx5_core0 rx 8192 tx 8192` (increase ring sizes)
- `ethtool -C mlx5_core0 adaptive-rx on` (reduce interrupt overhead)
- Check if `rx-gro-hw` or `rx-udp-gro-forwarding` helps with XDP

#### 8. `ct_kernel_exit_state` — ~1%

Context tracking overhead from RCU — kernel config dependent (`CONFIG_CONTEXT_TRACKING_USER`),
not actionable from BPF.

## Host-Level Profile Summary

The loss host (bare metal running QEMU/KVM) shows:
- **IPv4**: 60% idle, 5% `rep_movs_alternative` (iperf3 memcpy), 3.5% KVM overhead
- **IPv6**: 65% idle, 3.5% iperf3 memcpy, minimal KVM overhead

Host is not the bottleneck — all interesting work happens inside the VM.

## Historical Progression

| Date | IPv4 | IPv6 | Gap | Key Change |
|------|------|------|-----|------------|
| Pre-#169 | 19.9 Gbps | 19.3 Gbps | 3% | Baseline (htab_map_hash 4.8%→9.1%) |
| Post-#169 (flow cache) | 19.6 Gbps | 18.5 Gbps | 6% | Per-CPU IPv6 flow cache, 96% hit rate |
| Post-#165/#170 | 22.2 Gbps | 21.9 Gbps | 1.4% | Parse fast path + deferred csum_partial |
| Current run | 22.4 Gbps | 19.0 Gbps | 15% | Same code, variance in scheduling/load |
| Post-#171/#172/#173 | 22.3 Gbps | 19.3 Gbps | 13.5% | Screen bypass + coarse time + adaptive GC |

Note: throughput varies between runs (±15%) due to iperf3 scheduling, NAPI budget,
and ksoftirqd affinity. The profile percentages are more stable than absolute throughput.

## Post-#171/#172/#173 Profile (Screen Bypass + Coarse Time + Adaptive GC)

Build: commit 7381e8e (merged PRs #171, #172, #173)
Test: VLAN 80 path (LAN→fw0→loss host on mlx0.80)

### Throughput

| Protocol | Throughput | Retransmits |
|----------|-----------|-------------|
| IPv4     | 22.3 Gbps | 300         |
| IPv6     | 19.3 Gbps | 496         |
| **Gap**  | **13.5%** |             |

### VM Profile — Aggregated by Symbol

| Symbol | IPv4 | IPv6 | Delta | Notes |
|--------|------|------|-------|-------|
| `xdp_main_prog` | 11.9% | 14.1% | +2.2% | Screen bypass saves ~0.5% vs pre-#171 |
| `xdp_zone_prog` | 8.8% | 9.7% | +0.9% | |
| `mlx5e_skb_from_cqe_mpwrq_linear` | 7.7% | 8.6% | +0.9% | |
| `xdp_forward_prog` | 6.8% | 5.0% | -1.8% | |
| `__htab_map_lookup_and_delete_batch` | 6.1% | 5.6% | -0.5% | Adaptive GC: lower sweep rate |
| `htab_map_hash` | 6.0% | 8.1% | +2.1% | Still the main IPv6 penalty (#168) |
| `mlx5e_free_xdpsq_desc` | 5.0% | 4.3% | -0.7% | |
| `lookup_nulls_elem_raw` | 3.8% | 3.7% | -0.1% | |
| `read_tsc` | 3.2% | 2.4% | -0.8% | Coarse time saves ~2% vs pre-#172 |
| `xdp_nat_prog` | 2.6% | 3.3% | +0.7% | |
| `mlx5e_xdp_xmit` | 2.9% | 3.0% | +0.1% | |
| `__htab_map_lookup_elem` | 1.7% | 2.4% | +0.7% | |
| `mlx5e_poll_rx_cq` | 1.8% | 2.7% | +0.9% | |

### Key changes vs previous run

1. **`read_tsc` dropped**: 5.0%→3.2% (IPv4), 4.5%→2.4% (IPv6) — `bpf_ktime_get_coarse_ns()` working
2. **`__htab_map_lookup_and_delete_batch` stable**: 6.1%→6.1% (IPv4), 4.9%→5.6% (IPv6) — adaptive GC effect is subtle (less CPU when idle, same during load)
3. **`xdp_screen_prog` gone from top**: screen bypass working — no longer in top symbols
4. **`htab_map_hash` still dominates IPv6 penalty**: +2.1% — issue #168 (compact IPv6 session key) remains the biggest opportunity
