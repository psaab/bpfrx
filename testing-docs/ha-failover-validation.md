# HA Failover Validation -- Loss Userspace Cluster

Date: 2026-03-24

This document records the bugs found, fixes applied, and test procedures
used to validate HA failover on the isolated userspace AF_XDP cluster
running mlx5 ConnectX SR-IOV VFs. It is self-contained: another engineer
can reproduce every result using only the commands and environment
described here.

---

## 1. Summary of Fixes Applied

Ten commits, listed in dependency order. Each commit addresses a distinct
failure mode discovered during HA failover testing on the loss cluster.

| Commit | Summary | Files |
|--------|---------|-------|
| `58e7dd86` | Router flag in NA, ctrl enable timeout, new-flow fabric redirect | `garp.go`, `manager.go`, `afxdp.rs`, `lib.rs` |
| `18068903` | Stale BPF session flush on ctrl enable | `manager.go` |
| `00dc648d` | NAPI bootstrap with varying probes (multi-queue coverage) | `manager.go` |
| `8d4bb7ce` | Standalone AF_XDP XSK rebind test proving two bugs | `test/xsk-repro/` |
| `b95a8dd8` | Avoid link DOWN/UP on RETH MAC change | `linksetup.go`, `garp.go` |
| `e83d4d3a` | XSK liveness gate + auto-swap to eBPF pipeline | `manager.go` |
| `2e237a7e` | Suppress stable link-local EADDRNOTAVAIL log spam | `reconcile.go` |
| `375be885` | Replace xdpilone with libxdp C bridge | `csrc/xsk_bridge.c`, `xsk_ffi.rs`, `bind.rs`, `Cargo.toml`, `build.rs` |
| `807ae01a` | eBPF fabric redirect re-FIB for split-RG failover | `bpf/xdp/xdp_zone.c` |
| `4ddf371f` | Persist XSK liveness failure across config reconciles | `manager.go` |

### 1.1 `58e7dd86` -- Router flag in NA, ctrl enable timeout, new-flow fabric redirect

Three independent fixes in one commit:

1. **Router flag in unsolicited NA (`pkg/cluster/garp.go`).**
   `buildUnsolicitedNA` set the flags byte to `0x20` (Override=1, Router=0).
   Per RFC 4861 section 7.2.5, a host that receives NA with Router=0 removes
   the source from its Default Router List. After VRRP failover the new
   primary sent NA for each VIP -- the connected host deleted its IPv6
   default route and entered a 24-second blackout until the next RA. Fixed
   by setting flags to `0xA0` (Router=1, Override=1).

2. **Ctrl enable hard timeout reset (`pkg/dataplane/userspace/manager.go`).**
   Every link-cycle rebind reset both `neighborsPrewarmed` and `ctrlEnableAt`.
   RETH MAC programming causes repeated rebinds, so the 15-second hard
   timeout restarted on each rebind and ctrl never enabled. Fixed by
   preserving `ctrlEnableAt` across rebinds (only set once, on first
   prewarm when the field is zero).

3. **New-flow fabric redirect (`userspace-dp/src/afxdp.rs`).**
   On the session-miss path, when the egress RG was inactive (HAInactive),
   the fabric redirect used `debug.from_zone` (fragile, sometimes None)
   with no fallback. Fixed to use `from_zone_arc` directly and added
   `.or_else(|| resolve_fabric_redirect(...))` as plain fabric fallback.
   Also added fabric redirect for non-flow (no L4 ports) packets.

### 1.2 `18068903` -- Stale BPF session flush on ctrl enable

During the ctrl-disabled window the eBPF pipeline creates
`PASS_TO_KERNEL` entries in the `userspace_sessions` BPF map. After ctrl
enables, the XDP shim sees these stale entries and bypasses XSK, routing
matching flows through the eBPF pipeline instead of the userspace helper.
Fixed by iterating and deleting all `userspace_sessions` entries on the
ctrl 0-to-1 transition.

### 1.3 `00dc648d` -- NAPI bootstrap with varying probes

On mlx5 zero-copy, the NIC only posts XSK fill ring WQEs during NAPI
poll. One ICMP probe per interface hit the same RX queue (ICMP RSS hashes
on `src, dst, proto` only). Queues without NAPI triggers had empty fill
rings -- `XDP_REDIRECT` succeeded at the BPF level but the NIC silently
dropped the packet. Fixed by sending 30 UDP probes with varying
destination ports (RSS uses 4-tuple for UDP) plus ICMP probes with
varying echo IDs, giving statistical coverage of all RX queues.

### 1.4 `8d4bb7ce` -- Standalone AF_XDP XSK rebind test

Added `test/xsk-repro/` with both xdpilone (Rust) and libbpf (C) minimal
AF_XDP tests. Each loads its own XDP program, creates XSK sockets,
receives packets, does link DOWN/UP, rebinds, and checks receive. This
standalone test proved two bugs in isolation (see section 3).

### 1.5 `b95a8dd8` -- Avoid link DOWN/UP on RETH MAC change

`programRethMAC` now tries setting the MAC while the link is UP first.
If the driver supports `IFF_LIVE_ADDR_CHANGE` (mlx5 does), no link cycle
occurs and AF_XDP sockets are preserved. Falls back to DOWN/UP only if
the live change fails. When no link cycle occurs, VIP reconcile, AF_XDP
rebind, and RA re-burst are all skipped (not needed).

### 1.6 `e83d4d3a` -- XSK liveness gate + auto-swap to eBPF pipeline

Two changes:

1. `ctrl.enabled` is only set to 1 if at least one binding has
   `rx_packets > 0`. Prevents routing transit traffic into a black hole
   when XSK cannot deliver packets.

2. After 30 seconds of XSK bindings being ready but `rx_packets == 0`,
   the manager calls `SwapXDPEntryProg("xdp_main_prog")` to replace the
   XDP shim with the direct eBPF pipeline. This restores full 15+ Gbps
   forwarding with zone/policy/SNAT instead of the broken XDP_PASS
   fallback (~129 Mbps, no SNAT).

### 1.7 `2e237a7e` -- Suppress stable link-local log spam

The reconcile tick removes stable link-locals from inactive RG
interfaces. When the address does not exist, `netlink.AddrDel` returns
`EADDRNOTAVAIL`. This logged a WARN every 2 seconds per interface.
Added `EADDRNOTAVAIL` to the suppressed-error set (alongside `ENOENT`
and `ESRCH`).

### 1.8 `375be885` -- Replace xdpilone with libxdp C bridge

xdpilone 1.2.1 is proven broken on mlx5 ConnectX SR-IOV VFs (standalone
test: libbpf Phase 1 rx=3, xdpilone Phase 1 rx=0). Replaced with a C
FFI bridge to libxdp's xsk helpers (`csrc/xsk_bridge.c`), which use the
same code path the kernel developers test against. New Rust module
`src/xsk_ffi.rs` provides the same type API surface as xdpilone. All
356 Rust tests pass.

### 1.9 `807ae01a` -- eBPF fabric redirect re-FIB for split-RG failover

When fabric-forwarded packets arrived at the receiving node and
`bpf_fib_lookup` returned `BLACKHOLE` or `NO_NEIGH` (because the initial
lookup used the fabric interface's VRF), packets were unconditionally
dropped. This killed all existing TCP sessions during per-RG failover.

Fixed in `bpf/xdp/xdp_zone.c`: when `META_FLAG_FABRIC_FWD` is set and
a session exists, attempt a re-FIB in the main routing table
(`tbid=254`). If the main-table FIB succeeds, resolve and forward
normally. If it also fails (true dual-inactive), drop with
`GLOBAL_CTR_FABRIC_FWD_DROP`.

### 1.10 `4ddf371f` -- Persist XSK liveness failure across config reconciles

The XSK liveness swap to `xdp_main_prog` was being overridden by config
reconciles which re-set `XDPEntryProg` to `xdp_userspace_prog`. Added
`xskLivenessFailed` flag that persists and prevents `Compile` from
switching back to the broken XDP shim. Also added `delta-rx` check:
the liveness gate now compares current `rx_packets` against a snapshot
taken at gate start, so transient initial packets do not mask a
subsequent stall.

---

## 2. Test Environment

### 2.1 Cluster Topology

```
                         Internet / Upstream
                              |
                    172.16.80.0/24 (VLAN 80)
                              |
               mlx0 (mlx5 PF, SR-IOV, 8+ VFs)
                    VF4            VF5
                     |              |
          +----------+---+  +------+---------+
          | bpfrx-       |  | bpfrx-         |
          | userspace-   |  | userspace-     |
          | fw0 (node 0) |  | fw1 (node 1)  |
          | pri: 200     |  | pri: 100       |
          +--+--+--+--+--+  +--+--+--+--+---+
             |  |  |  |        |  |  |  |
  fxp0 -----+  |  |  |        +--|----------- fxp0
  em0 ---------+  |  |        +--||---------- em0
  fab0 -----------+  |        |  |+---------- fab0
  ge-0/0/1 ----------+  WAN  +----- ge-7/0/1
  ge-0/0/2 ----------+  LAN  +----- ge-7/0/2
                 |                   |
                 +-------+  +-------+
                         |  |
      incusbr0                (fxp0, DHCP)
      bpu-hb0                 (em0,  10.99.12.0/30)
      bpu-fab0                (fab0, 10.99.13.0/30)
      mlx1 VF (VLAN 3667)    (LAN,  10.0.61.0/24)

          +---------------------+
          | cluster-userspace-  |
          | host                |
          | eth0: 10.0.61.102   |
          +---------------------+
```

### 2.2 Hardware

| Component | Detail |
|-----------|--------|
| WAN NIC | Mellanox ConnectX (mlx5), SR-IOV VFs, PCI `0000:65:00.4` / `0000:65:00.5` |
| LAN NIC | Mellanox ConnectX (mlx5), SR-IOV VFs, PCI `0000:65:05.4` / `0000:65:05.5`, VLAN 3667 |
| Kernel | 6.18 |
| XDP mode | Native (mlx5 driver-mode XDP) |
| AF_XDP mode | Zero-copy (mlx5 driver support) |

### 2.3 Software

| Component | Detail |
|-----------|--------|
| bpfrxd | Daemon managing BPF pipeline + userspace AF_XDP helper |
| bpfrx-userspace-dp | Rust AF_XDP packet processor (libxdp C bridge) |
| Config | `docs/ha-cluster-userspace.conf` |
| Env | `test/incus/loss-userspace-cluster.env` |
| Deploy script | `test/incus/cluster-setup.sh` |

### 2.4 WAN Targets

| Target | Address |
|--------|---------|
| IPv4 WAN | `172.16.80.200` |
| IPv6 WAN | `2001:559:8585:80::200` |

---

## 3. Bugs Found and Proven

### 3.1 Router Flag Bug (RFC 4861 section 7.2.5)

**Symptom.** After VRRP failover, IPv6 connectivity from
`cluster-userspace-host` dropped to zero for 24 seconds. New TCP
connections failed with "Network is unreachable". iperf3 showed
0 Gbps during the blackout.

**Root cause.** The unsolicited Neighbor Advertisement sent as the IPv6
analog of GARP had flags byte `0x20` (Override=1, Router=0). RFC 4861
section 7.2.5 says: if a host receives NA from a router with Router=0,
it MUST remove that router from the Default Router List. The host
deleted its IPv6 default route and waited until the next Router
Advertisement (~24 seconds) to re-learn it.

**Proof.** On the host, immediately after failover:
```
$ ip -6 route show default
(empty -- default route removed)
```
After the fix (flags `0xA0`, Router=1 + Override=1):
```
$ ip -6 route show default
default via fe80::bf:72ff:fe02:0102 dev eth0 ...
```
The default route survives failover.

**Fix.** `pkg/cluster/garp.go`: changed NA flags byte from `0x20` to
`0xA0`.

### 3.2 xdpilone Broken on mlx5

**Symptom.** AF_XDP userspace helper reported `rx_packets=0` on all
interfaces. All transit traffic fell through to `XDP_PASS` (kernel
forwarding) at ~129 Mbps with no SNAT.

**Root cause.** xdpilone 1.2.1 cannot receive packets on mlx5 ConnectX
SR-IOV VFs. The standalone test (`test/xsk-repro/`) proved this in
isolation:

| Mode | Library | Initial Bind | After Link DOWN/UP |
|------|---------|-------------|-------------------|
| zero-copy | **libbpf** | **rx=3 PASS** | **rx=0 FAIL** |
| zero-copy | xdpilone | rx=0 FAIL | rx=0 FAIL |
| copy | libbpf | rx=0 FAIL | rx=0 FAIL |
| copy | xdpilone | rx=0 FAIL | rx=0 FAIL |

Same NIC, same kernel, same XDP program -- the only variable is the
XSK socket creation library. xdpilone's internal socket setup sequence
is incompatible with the mlx5 driver.

**Fix.** Commit `375be885`: replaced xdpilone with a C FFI bridge to
libxdp's xsk helpers.

### 3.3 mlx5 Zero-Copy Does Not Survive Link DOWN/UP

**Symptom.** Even with libbpf (working initial bind), after
`ip link set <iface> down && ip link set <iface> up`, XSK receive
stops. The NIC increments `rx_xsk_xdp_redirect` (redirect to XSK
attempted) but `rx_xsk_packets` stays flat (XSK never delivers).
`rx_xsk_congst_umr` (UMR congestion counter) is non-zero on the
affected interface.

**Root cause.** Kernel/driver bug: the mlx5 driver does not properly
reinitialize the XSK zero-copy receive path (UMR WQE posting) when the
interface is brought back UP after DOWN.

**Proof.** Standalone test (`test/xsk-repro/libbpf-xsk-test`):
```
Phase 1 (initial bind):  rx=3  PASS
Phase 2 (after DOWN/UP): rx=0  FAIL
```

NIC counters after Phase 2:
```
$ ethtool -S ge-7-0-1 | grep xsk
rx_xsk_xdp_redirect: 147      # redirect attempted
rx_xsk_packets: 0              # never delivered
rx_xsk_congst_umr: 3           # UMR issue
```

**Workaround.** Two-layer defense:
1. `b95a8dd8`: Avoid link DOWN/UP entirely during RETH MAC change
   (live MAC change with `IFF_LIVE_ADDR_CHANGE`).
2. `e83d4d3a` + `4ddf371f`: XSK liveness gate detects rx=0 and
   auto-swaps to `xdp_main_prog` (eBPF pipeline) as fallback.

### 3.4 eBPF Fabric Redirect Drops on Split-RG

**Symptom.** After per-RG failover (e.g., RG2/LAN moves to node1 while
RG0/RG1/WAN stays on node0), existing TCP sessions through the eBPF
pipeline died. New connections also failed.

**Root cause.** Fabric-forwarded packets arrived at the receiving node
and `bpf_fib_lookup` was performed using the fabric interface's context.
The fabric interface lives in the default VRF, but the destination route
lives in a data VRF -- FIB returned `BPF_FIB_LKUP_RET_BLACKHOLE`. The
`xdp_zone.c` BLACKHOLE handler unconditionally dropped, even for fabric
packets that just needed to be re-looked-up in the main table.

**Fix.** `807ae01a`: When `META_FLAG_FABRIC_FWD` is set and a session
exists, attempt a re-FIB in the main routing table (`tbid=254`).

### 3.5 XDP Shim Fallback Tail-Call Failure

**Symptom.** When the XDP shim (`xdp_userspace_prog`) determined a
packet should go through the eBPF pipeline instead of XSK, its
`fallback_to_main()` tail-call silently failed (returned without
redirecting). The packet fell through to `XDP_PASS`, meaning the kernel
handled it without SNAT.

**Root cause.** aya-ebpf's `tail_call!` macro does not reliably work in
the XDP shim context. The tail-call instruction is emitted but the
program array lookup fails silently.

**Workaround.** The XSK liveness gate (`e83d4d3a` + `4ddf371f`) detects
that XSK is broken and replaces `xdp_userspace_prog` with
`xdp_main_prog` directly. This eliminates the shim entirely -- traffic
goes through the full eBPF pipeline (zone, conntrack, policy, NAT,
forward) at 15+ Gbps.

### 3.6 Ctrl Enable Never Fires (Rebind Timeout Reset)

**Symptom.** After deploy, `ctrl.enabled` stayed at 0 indefinitely.
Transit traffic went through `XDP_PASS` (kernel, no SNAT).

**Root cause.** Each RETH MAC programming event triggered a link cycle
which triggered XSK rebind which reset `ctrlEnableAt` back to
`now + 15s`. With multiple RETH interfaces, the rebinds chained and the
15-second window never completed.

**Fix.** `58e7dd86`: `ctrlEnableAt` is set only once (first prewarm,
when the field is zero). Subsequent rebinds do not reset it.

### 3.7 NAPI Queue Starvation on mlx5 Zero-Copy

**Symptom.** Some RX queues showed `rx_packets=0` while others
received traffic. Total throughput was reduced.

**Root cause.** mlx5 zero-copy only posts fill ring WQEs during NAPI
poll. The single ICMP prewarm probe hit one RX queue (ICMP RSS is
3-tuple). Other queues had empty fill rings -- `XDP_REDIRECT` to XSK
succeeded at the BPF level but the NIC silently dropped the packet.

**Fix.** `00dc648d`: Send 30 UDP probes with varying destination ports
(4-tuple RSS) plus ICMP probes with varying echo IDs. Provides
statistical coverage across all RX queues.

### 3.8 Stale Session Entries Poison XDP Shim

**Symptom.** After `ctrl` transitions from 0 to 1, some flows bypassed
XSK and went through the eBPF pipeline.

**Root cause.** During the ctrl-disabled window, the eBPF pipeline
created `PASS_TO_KERNEL` entries in `userspace_sessions`. After ctrl
enabled, the XDP shim found these entries and routed matching flows
through the eBPF path instead of XSK.

**Fix.** `18068903` and `00dc648d`: Flush all `userspace_sessions`
entries on the ctrl 0-to-1 transition.

---

## 4. Test Results

### 4.1 Baseline Throughput (All RGs on Same Node)

Measured from `cluster-userspace-host` through the firewall to
`172.16.80.200` / `2001:559:8585:80::200` with `iperf3 -P 4 -t 10`.

| Protocol | Throughput | Retransmits |
|----------|-----------|-------------|
| IPv4 | 23.5 Gbps | 0 |
| IPv6 | 23.1 Gbps | 0 |

### 4.2 HA Failover During iperf3

Failover scenario: all RGs start on node0, then RG2 (LAN) is manually
failed over to node1 during an active iperf3 session.

**Before fixes (24-second blackout):**

| Time Window | Throughput | Notes |
|------------|-----------|-------|
| 0-8s | 23.1 Gbps | Pre-failover baseline |
| 8-32s | 0 Gbps | Complete blackout |
| 32s+ | Partial recovery | Host re-learns IPv6 route via RA |

- Host lost IPv6 default route (Router flag bug)
- `ctrl.enabled` stuck at 0 (timeout reset bug)
- New connections: "Network is unreachable"

**After fixes (sub-second transition):**

| Time Window | Throughput | Notes |
|------------|-----------|-------|
| 0-8s | 23.1 Gbps | Pre-failover baseline |
| 8-9s | 8.4 Gbps | Transition dip (~1s) |
| 9-25s | 10.0-10.4 Gbps | Split-RG fabric redirect path |

- ZERO seconds at 0 Gbps
- Existing TCP sessions survive failover
- Throughput through fabric redirect: ~10 Gbps (expected: fabric adds
  one extra hop per direction)

### 4.3 Post-Failover Connectivity

| Test | Result |
|------|--------|
| IPv4 ping (5 probes, 2s timeout) | 4-5/5 (cold-start first probe may be lost to ARP) |
| IPv6 ping (5 probes, 2s timeout) | 5/5 |
| IPv4 new TCP (iperf3 short) | 5/5 |
| IPv6 new TCP (iperf3 short) | 5/5 |
| IPv6 default route present | Yes (Router=1 in NA preserves it) |

---

## 5. Test Procedures

### 5.1 Deploy

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

Wait for the XSK liveness check to complete and the eBPF pipeline swap
to occur. This takes 15-45 seconds after deploy depending on the NAPI
prewarm timing.

```bash
# Wait for swap (conservative)
sleep 70
```

### 5.2 Verify XDP Program

After the liveness gate fires, each node should be running
`xdp_main_prog` (not `xdp_userspace_prog`) on data interfaces.

```bash
# Node 0 -- check WAN interface
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- \
  ip link show ge-0-0-2 | grep prog"
# Expected: prog/xdp id <N> ...

# Node 1 -- check LAN interface
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw1 -- \
  ip link show ge-7-0-1 | grep prog"
# Expected: prog/xdp id <N> ...
```

Verify the program is the eBPF pipeline, not the XDP shim:

```bash
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- \
  bpftool prog show | grep -A1 'xdp_main_prog'"
```

### 5.3 Basic Connectivity

```bash
# IPv4
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  ping -c 5 -W 2 172.16.80.200"

# IPv6
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  ping6 -c 5 -W 2 2001:559:8585:80::200"
```

Both must succeed (allow 1 cold-start loss on IPv4).

### 5.4 Throughput Baseline

```bash
# IPv4
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  iperf3 -c 172.16.80.200 -t 10 -P 4"

# IPv6
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  iperf3 -c 2001:559:8585:80::200 -t 10 -P 4"
```

Expected: 20+ Gbps for both protocols when all RGs are on the same
node. If throughput is significantly lower, check which XDP program is
attached (section 5.2) and the ctrl map state (section 7.2).

### 5.5 Failover Test (THE CRITICAL TEST)

This is the primary acceptance gate. It tests that existing TCP sessions
survive a per-RG failover and that new connections work immediately
after.

```bash
# Step 1: Move all RGs to node 0
for rg in 0 1 2; do
  sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- \
    /usr/local/sbin/cli -c \
    'request chassis cluster failover redundancy-group $rg node 0'"
  sleep 1
done
sleep 5

# Step 2: Verify cluster state
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- \
  /usr/local/sbin/cli -c 'show chassis cluster status'"
# All three RGs should show node0 as primary

# Step 3: Start iperf3 in background (25-second run)
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  bash -c 'iperf3 -c 2001:559:8585:80::200 -t 25 -P 4 2>&1'" &
PID=$!

# Step 4: Wait for baseline to establish
sleep 8

# Step 5: Failover RG2 (LAN) to node 1
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- \
  /usr/local/sbin/cli -c \
  'request chassis cluster failover redundancy-group 2 node 1'"

# Step 6: Wait for iperf3 to finish
wait $PID

# Step 7: Test new connections after split-RG
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  ping -c 5 -W 2 172.16.80.200"

sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  ping6 -c 5 -W 2 2001:559:8585:80::200"
```

**Pass criteria:**

| Criterion | Threshold |
|-----------|-----------|
| iperf3 drops to 0 Gbps | NEVER (hard fail) |
| Transition dip duration | < 3 seconds |
| Recovery throughput (fabric path) | > 8 Gbps |
| New IPv4 connections (ping) | >= 4/5 |
| New IPv6 connections (ping) | >= 4/5 |
| IPv6 default route on host after failover | Present |

### 5.6 Failover Test -- IPv4 Variant

Same procedure as 5.5 but using IPv4 iperf3:

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  bash -c 'iperf3 -c 172.16.80.200 -t 25 -P 4 2>&1'" &
```

Pass criteria are the same.

### 5.7 Full Reset and Re-Verify

After failover testing, reset all RGs to node 0 and verify clean
recovery:

```bash
for rg in 0 1 2; do
  sg incus-admin -c "incus exec loss:bpfrx-userspace-fw0 -- \
    /usr/local/sbin/cli -c \
    'request chassis cluster failover redundancy-group $rg node 0'"
  sleep 1
done
sleep 5

# Full connectivity check
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  ping -c 5 -W 2 172.16.80.200"
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  ping6 -c 5 -W 2 2001:559:8585:80::200"
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  iperf3 -c 172.16.80.200 -t 5 -P 4"
```

### 5.8 Standalone XSK Rebind Test

This is the standalone test used to bisect AF_XDP bugs independently
of bpfrxd. Run directly on one of the firewall VMs.

```bash
# SSH into a firewall node
sg incus-admin -c "incus exec loss:bpfrx-userspace-fw1 -- bash"

# In test/xsk-repro/ (must be pre-built and pushed)

# libbpf zero-copy (reference: PASS on initial bind, FAIL after cycle)
./libbpf-xsk-test ge-7-0-1 0 zerocopy

# libbpf copy mode
./libbpf-xsk-test ge-7-0-1 0 copy

# xdpilone (expected to fail on both phases)
./xsk-rebind-test ge-7-0-1 0 \
  --xsk-map-pin /sys/fs/bpf/bpfrx/userspace_xsk_map
```

**How to use for bisection.** If a future kernel update or driver change
is suspected to fix or break XSK behavior:

1. Run `libbpf-xsk-test` in zero-copy mode.
2. If Phase 1 (initial bind) fails: library or driver regression.
3. If Phase 1 passes but Phase 2 (after link cycle) fails: the
   mlx5 UMR reinit bug is still present.
4. If both phases pass: the kernel bug is fixed and the
   `IFF_LIVE_ADDR_CHANGE` workaround (`b95a8dd8`) can be removed.

---

## 6. Known Limitations

### 6.1 XSK Liveness Swap Window

After deploy, the daemon takes 15-45 seconds to detect that XSK is
broken and swap to `xdp_main_prog`. During this window, traffic goes
through kernel fallback (`XDP_PASS`) at reduced throughput and without
SNAT. The window consists of:

1. Binding setup + NAPI prewarm: ~5-10s
2. Liveness check period: up to 30s (configurable)
3. Program swap: < 1s

### 6.2 mlx5 Zero-Copy After Link DOWN/UP

This is an upstream kernel/driver bug. The workaround (live MAC change
via `IFF_LIVE_ADDR_CHANGE`) avoids triggering it during normal
operation. If a future event forces a link cycle (e.g., driver reload,
PCI reset), the XSK liveness gate will detect it and auto-swap to the
eBPF pipeline.

### 6.3 libxdp Dynamic Linking

The xdpilone-to-libxdp migration (`375be885`) links `libxdp.so.1`
dynamically. The target firewall VMs must have libxdp installed. The
deploy script installs it automatically, but manual binary copies must
ensure the library is present.

### 6.4 Split-RG Fabric Throughput

When RGs are split across nodes, traffic traverses the fabric link
(one extra hop per direction). Expected throughput is ~10 Gbps through
fabric, compared to 23+ Gbps with all RGs colocated. This is inherent
to the fabric architecture, not a bug.

### 6.5 aya-ebpf Tail-Call Bug

The XDP shim's `fallback_to_main()` tail-call silently fails in
aya-ebpf. This is worked around by the XSK liveness gate (which
replaces the shim entirely), but the root cause in aya-ebpf has not
been fixed upstream.

---

## 7. Diagnostic Commands

### 7.1 XDP Program Attached

Check which XDP program is attached to each data interface:

```bash
# On firewall VM
ip link show ge-0-0-2 | grep prog
# or
bpftool net list

# Expected after liveness swap:
#   xdp_main_prog (not xdp_userspace_prog)
```

List all loaded XDP programs:

```bash
bpftool prog show | grep -E '(xdp_main|xdp_userspace)'
```

### 7.2 Ctrl Map State

Check whether userspace ctrl is enabled in the BPF map:

```bash
bpftool map dump pinned /sys/fs/bpf/bpfrx/userspace_ctrl
# Key: 0x00 0x00 0x00 0x00
# Value: enabled (1) or disabled (0) as first byte
```

### 7.3 XSK Binding State

The binding status is maintained in a state file by the daemon:

```bash
cat /var/run/bpfrx/xsk-status.json 2>/dev/null || \
  journalctl -u bpfrxd --no-pager | grep -i "xsk\|binding\|liveness"
```

Check the BPF bindings map:

```bash
bpftool map dump pinned /sys/fs/bpf/bpfrx/userspace_bindings
# Non-zero entries indicate active XSK bindings
# All-zero entries after deploy indicate the XSK bind failure
```

### 7.4 NIC XSK Counters

mlx5 exposes per-interface XSK statistics:

```bash
ethtool -S ge-7-0-1 | grep xsk
# Key counters:
#   rx_xsk_xdp_redirect  — XDP redirected to XSK (BPF side)
#   rx_xsk_packets        — XSK actually delivered to userspace
#   rx_xsk_congst_umr     — UMR congestion (indicates driver bug)
#   rx_xsk_drops          — XSK fill ring empty drops
```

If `rx_xsk_xdp_redirect` increments but `rx_xsk_packets` does not,
the mlx5 UMR reinitialization bug (section 3.3) is active.

### 7.5 Fallback Statistics

Check global counters for fabric redirect and fallback:

```bash
# Via CLI
/usr/local/sbin/cli -c 'show security flow statistics'

# Via bpftool -- global counters map
bpftool map dump pinned /sys/fs/bpf/bpfrx/global_counters
# Look for:
#   GLOBAL_CTR_FABRIC_FWD       — packets fabric-redirected
#   GLOBAL_CTR_FABRIC_FWD_DROP  — fabric redirect failed (dual-inactive)
#   GLOBAL_CTR_KERNEL_ROUTE     — packets sent to kernel (XDP_PASS)
```

### 7.6 Session Map Entries

Check active sessions, especially for fabric-forwarded flows:

```bash
# Via CLI
/usr/local/sbin/cli -c 'show security flow session'
/usr/local/sbin/cli -c 'show security flow session destination-prefix 172.16.80.200/32'

# Count sessions
/usr/local/sbin/cli -c 'show security flow session summary'
```

### 7.7 Cluster State

```bash
# RG ownership
/usr/local/sbin/cli -c 'show chassis cluster status'

# Heartbeat
/usr/local/sbin/cli -c 'show chassis cluster statistics'

# Interface status
/usr/local/sbin/cli -c 'show chassis cluster interfaces'
```

### 7.8 Journal Logs (Filtered)

```bash
# XSK liveness gate events
journalctl -u bpfrxd --no-pager | grep -i "liveness\|swap.*xdp\|xsk.*fail"

# Ctrl enable events
journalctl -u bpfrxd --no-pager | grep -i "ctrl.*enable\|ctrl.*disable"

# VRRP transitions
journalctl -u bpfrxd --no-pager | grep -i "vrrp.*master\|vrrp.*backup"

# Fabric redirect
journalctl -u bpfrxd --no-pager | grep -i "fabric"

# NA/GARP
journalctl -u bpfrxd --no-pager | grep -i "garp\|unsolicited.*na"
```

---

## 8. Standalone XSK Reproduction Test

### 8.1 Purpose

`test/xsk-repro/` contains minimal standalone programs that isolate
AF_XDP behavior from the rest of bpfrxd. They prove that XSK bugs are
in the library (xdpilone) or kernel driver (mlx5), not in bpfrx
application code.

### 8.2 Contents

| File | Description |
|------|-------------|
| `libbpf-xsk-test.c` | C program using libbpf xsk helpers directly |
| `xsk-rebind-test.rs` | Rust program using xdpilone |
| `xdp_pass.c` | Minimal XDP program (just returns `XDP_REDIRECT` to XSK map) |
| `Makefile` | Build rules for both tests |

### 8.3 Test Protocol

Each test performs two phases:

1. **Phase 1 (initial bind):** Load XDP program, create UMEM, create
   XSK socket, fill the fill ring, send ICMP probes from outside,
   check `rx_packets` after 3 seconds.

2. **Phase 2 (after link cycle):** Bring interface DOWN, bring UP,
   destroy and recreate XSK socket (re-bind), fill the fill ring,
   send probes again, check `rx_packets` after 3 seconds.

### 8.4 Expected Results by NIC/Driver

| Driver | Zero-Copy Phase 1 | Zero-Copy Phase 2 | Copy Phase 1 | Copy Phase 2 |
|--------|-------------------|-------------------|-------------|-------------|
| mlx5 (ConnectX VF) | PASS (libbpf) | FAIL | FAIL | FAIL |
| i40e (X710 PF) | PASS | PASS | PASS | PASS |
| virtio-net | N/A (no zero-copy) | N/A | PASS | PASS |

### 8.5 Future Use

When a kernel update claims to fix mlx5 XSK zero-copy reinit:

1. Update kernel on a firewall VM.
2. Run `./libbpf-xsk-test ge-7-0-1 0 zerocopy`.
3. If both phases pass, the `IFF_LIVE_ADDR_CHANGE` workaround and XSK
   liveness gate can be made optional.
4. If Phase 2 still fails, the workarounds remain necessary.

---

## 9. Commit Dependency Graph

The fixes have the following logical dependencies (commits higher in
the graph must be applied before commits lower):

```
8d4bb7ce  (standalone test -- proves bugs, no code changes to bpfrxd)
    |
    v
375be885  (replace xdpilone with libxdp -- fixes Bug 3.2)
    |
    v
b95a8dd8  (avoid link DOWN/UP -- mitigates Bug 3.3)
    |
    v
e83d4d3a  (XSK liveness gate -- defense-in-depth for 3.2+3.3+3.5)
    |
    v
4ddf371f  (persist liveness flag -- prevents config reconcile override)

58e7dd86  (Router flag + ctrl timeout + fabric redirect -- independent)
    |
    v
18068903  (stale session flush -- depends on ctrl timeout fix)
    |
    v
00dc648d  (NAPI bootstrap -- extends session flush, adds UDP probes)

807ae01a  (eBPF fabric re-FIB -- independent, BPF-only)

2e237a7e  (log spam -- independent, cosmetic)
```

---

## 10. Validation Checklist

Use this checklist after each deploy to confirm all fixes are working:

- [ ] `xdp_main_prog` attached on both nodes (not `xdp_userspace_prog`)
- [ ] `ctrl.enabled` map shows 0 (ctrl disabled is expected after liveness swap)
- [ ] IPv4 ping to `172.16.80.200`: >= 4/5
- [ ] IPv6 ping to `2001:559:8585:80::200`: 5/5
- [ ] IPv6 default route present on `cluster-userspace-host`
- [ ] IPv4 iperf3 baseline: > 15 Gbps
- [ ] IPv6 iperf3 baseline: > 15 Gbps
- [ ] Failover test: zero seconds at 0 Gbps
- [ ] Failover test: transition dip < 3 seconds
- [ ] Post-failover new IPv4 connections: >= 4/5
- [ ] Post-failover new IPv6 connections: >= 4/5
- [ ] No `EADDRNOTAVAIL` WARN spam in journal
- [ ] `show chassis cluster status` shows expected RG ownership
