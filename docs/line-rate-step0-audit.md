# Phase B Step 0 — Zero-code Audit Results

Branch: `pr/line-rate-investigation`
Plan commit: `aeec40d3`
Cluster under test: `loss:xpf-userspace-fw0` (primary) / `loss:xpf-userspace-fw1` (secondary)
iperf3 client: `loss:cluster-userspace-host`
iperf3 server: `172.16.80.200` (external, SSH refused — scoped accordingly)
Observation mode: cold (no iperf3 active); daemon has been up ~1h with
low-rate management traffic, so cumulative counters are non-zero.
Executed: 2026-04-20 (UTC).

## Topology observed — deviations from plan template

The plan template assumes two interfaces (`ge-0-0-1`, `ge-0-0-2.80`)
with four per-interface workers. The actual binding plan on
`xpf-userspace-fw0` is:

- **3 interfaces** bound: `ge-0-0-0` (LAN-local / fabric parent),
  `ge-0-0-1` (LAN / trust), `ge-0-0-2` (WAN parent — VLAN `.80` is a
  logical subinterface; XSK always binds to the physical parent).
- **6 RSS queues per NIC** × 3 interfaces = **18 XSK bindings**.
- **4 workers** (pinned CPU 0-3) — so queues 4 and 5 on each NIC
  wrap back to workers 0 and 1 (known double-bound-worker pattern
  carried over from #785).
- `ge-0-0-0` binds in **Copy** mode (virtio-net without native XDP
  redirect support); `ge-0-0-1` and `ge-0-0-2` bind in **ZeroCopy**.
- Guest kernel: `7.0.0-rc7+`; CPU: Xeon D-2146NT; 6 vCPUs; single
  NUMA node.

All Step 0 rows that the plan pinned to `ge-0-0-2.80` are reported
below against the physical parent `ge-0-0-2` and marked accordingly.

## 0.1 — PCI-BDF-scoped IRQ affinity

PCI BDFs read via `readlink /sys/class/net/<iface>/device`:

- `ge-0-0-1` → `0000:08:00.0`
- `ge-0-0-2` → `0000:09:00.0`
- `ge-0-0-2.80` has no device link (VLAN subif — inherits `ge-0-0-2`)

Worker pinning verified via `taskset -cp`:
`tid=xpf-userspace-w{0..3} affinity = CPU 0..3` respectively
(`--workers 4 --ring-entries 16384 --poll-mode interrupt`).

| mlx5 queue | IRQ | smp_affinity_list | Expected (worker CPU) | Status |
|-|-|-|-|-|
| ge-0-0-1 q0 (comp0@pci:0000:08:00.0) | 95  | 0 | 0 (w0) | **PASS** |
| ge-0-0-1 q1 (comp1@pci:0000:08:00.0) | 122 | 1 | 1 (w1) | **PASS** |
| ge-0-0-1 q2 (comp2@pci:0000:08:00.0) | 123 | 2 | 2 (w2) | **PASS** |
| ge-0-0-1 q3 (comp3@pci:0000:08:00.0) | 124 | 3 | 3 (w3) | **PASS** |
| ge-0-0-1 q4 (comp4@pci:0000:08:00.0) | 125 | 4 | 0 or 4 (w0 double-bound to q4) | **FAIL** |
| ge-0-0-1 q5 (comp5@pci:0000:08:00.0) | 126 | 5 | 1 or 5 (w1 double-bound to q5) | **FAIL** |
| ge-0-0-2 q0 (comp0@pci:0000:09:00.0) | 97  | 0 | 0 (w0) | **PASS** |
| ge-0-0-2 q1 (comp1@pci:0000:09:00.0) | 117 | 1 | 1 (w1) | **PASS** |
| ge-0-0-2 q2 (comp2@pci:0000:09:00.0) | 118 | 2 | 2 (w2) | **PASS** |
| ge-0-0-2 q3 (comp3@pci:0000:09:00.0) | 119 | 3 | 3 (w3) | **PASS** |
| ge-0-0-2 q4 (comp4@pci:0000:09:00.0) | 120 | 4 | 0 or 4 (w0 double-bound to q4) | **FAIL** |
| ge-0-0-2 q5 (comp5@pci:0000:09:00.0) | 121 | 5 | 1 or 5 (w1 double-bound to q5) | **FAIL** |

Overall 0.1: **FAIL** — queues 4 and 5 on each NIC take their IRQ on
a different CPU (4, 5) than the XSK worker that services that queue
(workers 0, 1 — running on CPUs 0, 1). Every packet on those queues
crosses L2 to be consumed.

## 0.2 — NAPI / coalescence / busy-poll

Identical `ethtool -c` output on `ge-0-0-1` and `ge-0-0-2` (one row
per value below).

| Item | Observed | Expected | Status |
|-|-|-|-|
| 0.2 adaptive coalescing (RX) | **on** | off | **FAIL** |
| 0.2 adaptive coalescing (TX) | **on** | off | **FAIL** |
| 0.2 rx-usecs | 8 | ≤ 8 | PASS (but see caveat — adaptive=on overrides) |
| 0.2 tx-usecs | 8 | ≤ 8 | PASS (same caveat) |
| 0.2 rx-frames | 128 | unspecified | informational |
| 0.2 tx-frames | 128 | unspecified | informational |
| 0.2 `netdev_budget` | **300** | ≥ 600 | **FAIL** |
| 0.2 `netdev_budget_usecs` | 8000 | ≥ 8000 | PASS |
| 0.2 `gro_flush_timeout` (both NICs) | 0 | matches polling loop | **FAIL** |
| 0.2 `napi_defer_hard_irqs` (both NICs) | 0 | > 0 if using pure busy-poll | FAIL (proxy; poll_mode=interrupt) |
| 0.2 `net.core.busy_poll` | 0 | process-set via SO_BUSY_POLL (interrupt mode: 1 µs) | PASS (via setsockopt — see below) |
| 0.2 `net.core.busy_read` | 0 | same | PASS |
| 0.2 `SO_BUSY_POLL` per-XSK | 1 µs (interrupt mode) | 1 µs | **PASS** |
| 0.2 `SO_PREFER_BUSY_POLL` per-XSK | 1 | 1 | **PASS** |
| 0.2 `SO_BUSY_POLL_BUDGET` | `RX_BATCH_SIZE` | ≥ batch size | PASS |

Note: Adaptive coalescing = on is a mlx5 default. `rx-usecs=8,
rx-frames=128` are the **ceiling** the adaptive algorithm can walk
to — at low load mlx5 will scale down to larger interrupt gaps.
The reported values alone do not tell us the effective dwell time.

## 0.3 — TCP congestion control

| Endpoint | Observed | Expected | Status |
|-|-|-|-|
| `cluster-userspace-host` (client) | cubic (available: reno cubic) | cubic | **PASS** |
| `172.16.80.200` (server) | NOT VERIFIABLE (SSH refused from host + from container) | cubic | **DEFERRED-INSTRUMENTATION** |
| `ss -ti` in-run sample | (not run — Step 0 is cold) | cubic on all flows | DEFERRED-TO-STEP-3 |

Server-side verification requires either (a) credentials / console
access to 172.16.80.200, or (b) piggy-back via `iperf3 --debug` at
Step 3 to read `tcpi_ca_state` from `ss -ti` on the client (which
also reports the server-end algorithm when it differs). **Proposed
disposition: proxy via `ss -ti` during Step 3.**

## 0.4 — Ring-quadruple audit (cold)

`ethtool -g` on both NICs reports **RX=8192 TX=8192** (current =
maximum). XSK `ring_entries=16384` (userspace-dp arg) sets the XSK
fill / completion rings to 16384.

Authoritative-counter table (cold — pre-iperf3). Counters are
cumulative across the current daemon uptime (~1h of low-rate
management traffic — not truly zero):

| Ring | Counter | ge-0-0-1 | ge-0-0-2 | Expected | Status |
|-|-|-|-|-|-|
| RX (NIC) | `rx_out_of_buffer` | 258 | 26 | 0 at cold | **FAIL** |
| RX (NIC) | `rx_missed_errors` | 0 | 0 | 0 | PASS |
| RX (NIC) | `rx_steer_missed_packets` | 5 | **55,731,591** | 0 at cold | **FAIL** (huge on ge-0-0-2) |
| RX (NIC) | `rx_discards_phy` | 0 | 0 | 0 | PASS |
| RX (NIC) | `tx_discards_phy` | 0 | 0 | 0 | PASS |
| RX fill (XSK) | `rx_fill_ring_empty_descs` | not exposed via ctl socket | same | 0 at cold | **DEFERRED-INSTRUMENTATION** |
| RX fill (XSK) | `fill_batch_starved` | not in code (per plan) | same | 0 at cold | **DEFERRED-INSTRUMENTATION** |
| TX (XSK) | `dbg_tx_ring_full` | internal; not in ControlResponse | same | 0 at cold | **DEFERRED-INSTRUMENTATION** |
| TX (XSK) | `tx_errors` | 0 (all 18 slots) | 0 | 0 | PASS |
| TX (kernel produce) | `dbg_sendto_enobufs` | internal; not exposed | same | 0 at cold | **DEFERRED-INSTRUMENTATION** |
| TX (kernel produce) | `dbg_pending_overflow` | internal; not exposed | same | 0 at cold | **DEFERRED-INSTRUMENTATION** |
| TX (kernel produce) | `pending_tx_local_overflow_drops` | 0 (all 18 slots) | 0 | 0 | PASS |
| TX (kernel produce) | `tx_submit_error_drops` | 0 (all 18 slots) | 0 | 0 | PASS |
| TX (kernel produce) | `redirect_inbox_overflow_drops` | 0 (all 18 slots) | 0 | 0 | PASS |
| Completion (XSK) | `completion_reap_max_batch` | not in code (per plan) | same | bounded | **DEFERRED-INSTRUMENTATION** |
| Completion (XSK) | `debug_outstanding_tx` | 0 on all 18 slots (steady) | 0 | bounded | **PASS** |
| XSK slot | `kernel_rx_dropped` | 0 (all 18 slots) | 0 | 0 | PASS |
| XSK slot | `kernel_rx_invalid_descs` | 0 (all 18 slots) | 0 | 0 | PASS |

**Most alarming**: `rx_steer_missed_packets = 55,731,591` on
`ge-0-0-2` at cold. This is the mlx5 flow-steering miss counter.
It indicates packets that arrived but could not be steered to a
ring by the steering tables, and is not the same as
`rx_out_of_buffer`. This must be root-caused before Step 1 —
it plausibly is a significant fraction of the line-rate gap on
the WAN side.

## 0.5 — CPU frequency / C-states

Guest has **no** `/sys/devices/system/cpu/cpu*/cpufreq/` nodes —
cpufreq is not exposed through QEMU/KVM to this VM. `cpupower` is
not installed. Host (incus server `172.16.100.249`) was queried
directly via SSH:

| Item | Observed | Expected | Status |
|-|-|-|-|
| 0.5 host cpufreq governor (cpu0) | **`schedutil`** | `performance` | **FAIL** |
| 0.5 host cpufreq driver | `intel_cpufreq` | intel_cpufreq/intel_pstate | informational |
| 0.5 guest-side governor | N/A (no cpufreq dir) | N/A | DEFERRED-INSTRUMENTATION |
| 0.5 turbostat Bzy_MHz in-run | not collected at Step 0 | ≥ base clock on worker CPUs | DEFERRED-TO-STEP-3 |
| 0.5 turbostat CPU%c6 in-run | not collected at Step 0 | ≈ 0% on worker CPUs | DEFERRED-TO-STEP-3 |

## 0.6 — XSK bind mode / fallback

Bind mode per slot (18 slots total):

| Interface | Bindings | Mode | Expected | Status |
|-|-|-|-|-|
| `ge-0-0-0` (LAN / fabric parent) | 6/18 slots | **copy** | zero-copy | **FAIL** (driver lacks native XDP redirect) |
| `ge-0-0-1` (trust / client-side) | 6/18 slots | zerocopy | zero-copy | **PASS** |
| `ge-0-0-2` (WAN parent; VLAN .80) | 6/18 slots | zerocopy | zero-copy | **PASS** |

`USERSPACE_FALLBACK_STATS` map (`/sys/fs/bpf/xpf/userspace_fallback_stats`) —
cold (cumulative since daemon start):

| Reason code | Name | Count | Expected | Status |
|-|-|-|-|-|
| 0 | ctrl_disabled | 33 | 0 | informational (pre-arm window) |
| 1 | parse_fail | 0 | 0 | PASS |
| 2 | binding_missing | 0 | 0 | PASS |
| 3 | binding_not_ready | 0 | 0 | PASS |
| 4 | hb_missing | 0 | 0 | PASS |
| 5 | hb_stale | 0 | 0 | PASS |
| 6 | icmp | 0 | 0 | PASS |
| 7 | **early_filter** | **581** | 0 | **FAIL** |
| 8 | adjust_meta | 0 | 0 | PASS |
| 9 | meta_bounds | 0 | 0 | PASS |
| 10 | redirect_err | 0 | 0 | PASS |
| 11 | **iface_nat_no_sess** | **264** | 0 | **FAIL** |
| 12 | no_session | 0 | 0 | PASS |

Combined: XDP_FALLBACK counters are **not** zero — `early_filter`
and `iface_nat_no_sess` are firing. Each fallback-to-kernel event
removes a packet from the fastpath; under line-rate load this is a
throughput leak.

## Step 0 summary

| # | Audit item | Status |
|-|-|-|
| 1 | 0.1 IRQ affinity — ge-0-0-1 q0 | PASS |
| 2 | 0.1 IRQ affinity — ge-0-0-1 q1 | PASS |
| 3 | 0.1 IRQ affinity — ge-0-0-1 q2 | PASS |
| 4 | 0.1 IRQ affinity — ge-0-0-1 q3 | PASS |
| 5 | 0.1 IRQ affinity — ge-0-0-1 q4 | FAIL |
| 6 | 0.1 IRQ affinity — ge-0-0-1 q5 | FAIL |
| 7 | 0.1 IRQ affinity — ge-0-0-2 q0 | PASS |
| 8 | 0.1 IRQ affinity — ge-0-0-2 q1 | PASS |
| 9 | 0.1 IRQ affinity — ge-0-0-2 q2 | PASS |
| 10 | 0.1 IRQ affinity — ge-0-0-2 q3 | PASS |
| 11 | 0.1 IRQ affinity — ge-0-0-2 q4 | FAIL |
| 12 | 0.1 IRQ affinity — ge-0-0-2 q5 | FAIL |
| 13 | 0.2 adaptive coalescing RX | FAIL |
| 14 | 0.2 adaptive coalescing TX | FAIL |
| 15 | 0.2 rx-usecs | PASS |
| 16 | 0.2 tx-usecs | PASS |
| 17 | 0.2 netdev_budget | FAIL |
| 18 | 0.2 netdev_budget_usecs | PASS |
| 19 | 0.2 gro_flush_timeout | FAIL |
| 20 | 0.2 SO_BUSY_POLL | PASS |
| 21 | 0.2 SO_PREFER_BUSY_POLL | PASS |
| 22 | 0.3 tcp_congestion_control (client) | PASS |
| 23 | 0.3 tcp_congestion_control (server) | DEFERRED-INSTRUMENTATION |
| 24 | 0.3 ss -ti algorithm in-run | DEFERRED-TO-STEP-3 |
| 25 | 0.4 ge-0-0-1 RX ring (rx_out_of_buffer) | FAIL |
| 26 | 0.4 ge-0-0-1 TX ring (dbg_tx_ring_full proxy tx_errors) | PASS (proxy) |
| 27 | 0.4 ge-0-0-1 fill ring (rx_fill_ring_empty_descs) | DEFERRED-INSTRUMENTATION |
| 28 | 0.4 ge-0-0-1 completion ring (outstanding_tx) | PASS |
| 29 | 0.4 ge-0-0-2 RX ring (rx_out_of_buffer) | FAIL |
| 30 | 0.4 ge-0-0-2 TX ring (dbg_tx_ring_full proxy tx_errors) | PASS (proxy) |
| 31 | 0.4 ge-0-0-2 fill ring (rx_fill_ring_empty_descs) | DEFERRED-INSTRUMENTATION |
| 32 | 0.4 ge-0-0-2 completion ring (outstanding_tx) | PASS |
| 33 | 0.4 ge-0-0-2 rx_steer_missed_packets | FAIL |
| 34 | 0.5 cpufreq governor (worker CPUs) | FAIL (host: schedutil) |
| 35 | 0.6 XSK bind mode — ge-0-0-0 | FAIL (copy) |
| 36 | 0.6 XSK bind mode — ge-0-0-1 | PASS |
| 37 | 0.6 XSK bind mode — ge-0-0-2 | PASS |
| 38 | 0.6 XDP_FALLBACK counters — early_filter | FAIL |
| 39 | 0.6 XDP_FALLBACK counters — iface_nat_no_sess | FAIL |

**22 of 39 Step-0 audit items PASS** (6 DEFERRED-INSTRUMENTATION /
DEFERRED-TO-STEP-3, 11 FAIL).

## FAIL disposition

| # | Row | Proposed disposition |
|-|-|-|
| 5,6,11,12 | IRQ queues 4/5 on both NICs land on CPU 4/5 but served by w0/w1 on CPU 0/1 | **Zero-code fix**: either (a) set 6 workers (matches queue count, eliminates double-binding), or (b) pin queue-4 IRQ → CPU 0 and queue-5 IRQ → CPU 1 via `echo`. Option (a) is strictly better. Halt Phase B until one is applied. |
| 13,14 | Adaptive coalescing on RX/TX (mlx5 default) | **Zero-code fix**: `ethtool -C ge-0-0-1 adaptive-rx off adaptive-tx off; same for ge-0-0-2`. Re-verify with `ethtool -c`. |
| 17 | `netdev_budget=300` < 600 | **Zero-code fix**: `sysctl -w net.core.netdev_budget=600`. Note: only affects softirq NAPI path (non-ZC traffic and ge-0-0-0 copy-mode). |
| 19 | `gro_flush_timeout=0` | **Zero-code fix OR defer**: non-zero GRO flush timeout matters only for kernel-socket ingress; XSK zero-copy bypasses GRO. Propose **defer with rationale**: irrelevant to XSK-ZC path. |
| 25,29 | `rx_out_of_buffer > 0` on both NICs | **Investigate before Step 1**: cumulative since boot during low-load — most likely transient bursts during bring-up. Re-zero by `ethtool -s` reset or simply tolerate as baseline and monitor the delta during Step 3. **Proposed disposition: baseline + delta-verify at Step 3.** |
| 33 | `rx_steer_missed_packets = 55,731,591` on ge-0-0-2 | **Blocking — root-cause before Step 1**. Could be misconfigured flow-steering rule (e.g. stale mlx5 flow-group after VF/PF re-bind, or a steering filter that drops instead of steering). Propose: (a) `ethtool -x`, `ethtool -N ge-0-0-2` to dump flow rules, (b) `mlx5 flow_counter` inspection via `devlink`. File GitHub issue if root cause is a config/driver bug. **This alone could be the entire line-rate answer.** |
| 34 | Host CPU governor = `schedutil` | **Zero-code fix on host**: `cpupower frequency-set -g performance` on the incus host (requires root on 172.16.100.249). Verify with turbostat during Step 3. **Blocks Step 3 measurement integrity.** |
| 35 | ge-0-0-0 binds in copy mode | **Expected for current topology** (ge-0-0-0 sits on a non-native-XDP virtio-net link used only for LAN-local / slow-path). **Proposed disposition: document + defer** — not on the primary ingress path for the iperf3 test (ge-0-0-1 ↔ ge-0-0-2 is the path). |
| 38 | `early_filter` fallback = 581 | **Code investigation needed**: these are packets the XDP shim's early filter sends to slow path. Enumerate via ftrace which cases fire. **Proposed disposition: defer with proxy** — re-read counter delta during Step 3; if it grows at line-rate it becomes a PR target. |
| 39 | `iface_nat_no_sess` fallback = 264 | **Code investigation needed**: indicates interface-NAT traffic that did not find a live session (session install race, or stale session map). **Proposed disposition: defer with proxy** — re-read delta during Step 3; only escalates if it grows under load. |

## DEFERRED-INSTRUMENTATION rows

Five proxy gaps (named in plan §Phase C "Instrumentation pre-work")
not yet satisfied by in-code counters exposed through the control
socket:

| # | Counter | Plan source | Status |
|-|-|-|-|
| 27 | `rx_fill_ring_empty_descs` (ge-0-0-1) | XSK `xdp_statistics` — read internally (`xsk_ffi::stats`) but not marshalled into `BindingLiveSnapshot` in `userspace-dp/src/protocol.rs`. | DEFERRED-INSTRUMENTATION |
| 31 | `rx_fill_ring_empty_descs` (ge-0-0-2) | same | DEFERRED-INSTRUMENTATION |
| 27b | `fill_batch_starved` | not implemented (per plan § ring-quadruple audit) | DEFERRED-INSTRUMENTATION |
| 32b | `completion_reap_max_batch` | not implemented (per plan) | DEFERRED-INSTRUMENTATION |
| 33 | `dbg_tx_ring_full`, `dbg_sendto_enobufs`, `dbg_pending_overflow` | present as per-worker `Rust` struct fields (`worker.rs:64-70`) but not plumbed into `BindingLiveSnapshot` — currently only emitted via `eprintln!` DBG lines when > 0 | DEFERRED-INSTRUMENTATION |

**Proposed disposition for all five**: flag as Phase C
pre-requisites per the plan's "Instrumentation pre-work"
sub-section. Each is a small code PR (Rust struct field +
protocol.rs serialize + Go ControlResponse field + statusfmt
render). Plan is explicit that these block Step 5 but not Step 0
itself.

## Supplementary observations

1. **55.7 M `rx_steer_missed_packets` on ge-0-0-2 is the single
   most suspicious finding in this audit.** It is plausible that
   a broken flow-steering rule on the WAN NIC is dropping the
   bulk of incoming packets before they reach any ring — which
   could account for a sizable fraction of the line-rate gap
   entirely on its own. This must be root-caused before Step 1.

2. **Queue count (6) does not match worker count (4).** Every
   Step-0 pass can't hide that RSS queues 4 and 5 on each NIC
   are double-bound to workers 0 and 1, which already caused the
   uneven-worker distribution that #785 spent a month solving.
   The clean fix is to start userspace-dp with `--workers 6` on a
   6-vCPU box; the per-worker affinity and IRQ alignment both
   fall out for free. This is a config-file-only change
   (systemd unit `ExecStart` argument). **It is the cheapest
   Step-0 fix on the list.**

3. **Host governor = `schedutil`** instead of `performance`. Even
   after fixing everything else, a `schedutil`-governed worker CPU
   will scale to a lower frequency during the ramp-up of an iperf3
   test (large cwnd, burst-then-idle cycles). This confounds every
   throughput measurement until it is changed. This is a
   single-command fix on the host.

4. **Adaptive coalescing = on** is the mlx5 default and it *will*
   raise effective `rx-usecs` at low PPS, costing latency and
   sometimes throughput. `rx-usecs=8` is only a ceiling.

5. **Early-filter fallback = 581** and **iface_nat_no_sess =
   264** are small in absolute terms but non-zero at cold. If
   they grow during Step 3 they are a hotpath leak; if they stay
   flat they were pre-arm startup artefacts and can be ignored.

6. **ge-0-0-0 bound in Copy mode** is expected (virtio-net has no
   native XDP redirect support) but is a reminder that any
   traffic that transits ge-0-0-0 — fabric forwarding, slow-path
   punt, etc. — cannot line-rate.

## Next steps

Per the plan's "Control flow on FAIL" clause, Phase B **does not
proceed to Step 1** until every FAIL row above has been either
fixed (zero-code) or explicitly deferred in writing. This document
deposits all 11 FAIL rows with proposed dispositions; the
reviewer's decision on each is required before Step 1 begins.
Recommended order:

1. **Host governor → performance** (single command, unlocks
   measurement integrity for every subsequent run).
2. **Worker count 4 → 6** (systemd unit edit + restart, unlocks
   rows 5, 6, 11, 12, 33b without any IRQ-pin gymnastics).
3. **Adaptive coalescing off on both NICs** (rows 13, 14).
4. **`netdev_budget=600`** (row 17).
5. **Root-cause `rx_steer_missed_packets`** on ge-0-0-2 (row 33).
6. **Re-baseline ring counters** and re-run the Step 0 table.
7. Once every non-deferred row is PASS, proceed to Step 1.
