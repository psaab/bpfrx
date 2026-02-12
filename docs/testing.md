# Testing & Performance Guide

## Test Environment

### VM Setup (Incus)
```
Host: Debian, kernel 6.18.5+deb14-amd64
VM:   Debian 13, kernel 6.18 (from unstable repo)
      8 vCPU, 4 GB RAM
```

### Network Topology
```
                    +-----------+
                    | Host      |
                    | (Debian)  |
                    +-----+-----+
                          |
              +-----------+-----------+------ ...
              |           |           |
         incusbr0    bpfrx-trust  bpfrx-untrust  bpfrx-dmz  bpfrx-tunnel
         10.0.100.1  10.0.1.1     10.0.2.1       10.0.30.1   10.0.40.1
              |           |           |              |           |
        +-----+-----+----+-----------+--------------+-----------+------+
        |  bpfrx-fw VM                                                 |
        |  enp5s0   (mgmt)     10.0.100.x   — incusbr0 (no default route)|
        |  enp6s0   (trust)    10.0.1.10     — bpfrx-trust zone        |
        |  enp7s0   (untrust)  10.0.2.10     — bpfrx-untrust zone      |
        |  enp8s0   (dmz)      10.0.30.10    — bpfrx-dmz zone          |
        |  enp9s0   (tunnel)   DHCP          — bpfrx-tunnel zone       |
        |  enp10s0f0(internet) SR-IOV PCI    — wan zone (VLAN + DHCP)  |
        +--------------------------------------------------------------+
```

### Interface Details
| Interface | Driver | XDP Mode | Zone | Address |
|-----------|--------|----------|------|---------|
| enp5s0 | virtio_net | none (mgmt) | - | DHCP (UseRoutes=false) |
| enp6s0 | virtio_net | native | trust | 10.0.1.10/24 |
| enp7s0 | virtio_net | native | untrust | 10.0.2.10/24 |
| enp8s0 | virtio_net | native | dmz | 10.0.30.10/24 |
| enp9s0 | virtio_net | native | tunnel | DHCP |
| enp10s0f0 | iavf (SR-IOV) | generic | wan | VLAN 100 + DHCP |

### SR-IOV WAN Interface
- Intel X710 NIC with SR-IOV VFs (enp101s0f0np0 on host)
- VFs have individual IOMMU groups — VFIO PCI passthrough works
- Appears as `enp10s0f0` inside VM (NOT `enp10s0`)
- PCI passthrough via: `incus config device add VM internet pci address=<BDF>`
- iavf driver lacks native XDP support — uses generic mode
- VLAN 100 tagging configured in Junos config, handled by BPF

### Zone Policy Matrix
| From \ To | trust | untrust | dmz | wan |
|-----------|-------|---------|-----|-----|
| trust | - | permit | permit | permit+SNAT |
| untrust | DNAT web only | - | HTTP only | permit+SNAT |
| dmz | - | - | - | permit+SNAT |
| default | deny-all | deny-all | deny-all | deny-all |

---

## Build & Deploy Workflow

```bash
# Full build (BPF codegen + Go binary)
make generate && make build

# Run unit tests (18 parser tests)
make test

# Deploy to Incus VM
make test-deploy    # build -> push -> install -> restart

# Monitor
make test-logs      # journalctl -n 50
make test-journal   # journalctl -f (follow)
make test-status    # instance + service + network info
```

### Permission Issues
If `incus` commands fail: `sg incus-admin -c "make test-deploy"`

### Remote CLI Access
```bash
# Interactive
incus exec bpfrx-fw -- cli

# Non-interactive (pipe commands)
printf 'show security flow session\nexit\n' | incus exec bpfrx-fw -- cli 2>/dev/null

# Via sg if needed
printf 'show ...\nexit\n' | sg incus-admin -c 'incus exec bpfrx-fw -- cli' 2>/dev/null
```

---

## Performance Testing

### Throughput Benchmarks

**iperf3 between host and VM (cross-zone):**
```bash
# Start server on host (listening on untrust network)
iperf3 -s -B 10.0.2.1

# Run from trust-host container or host trust interface
# 4 parallel streams, reverse mode, 30 seconds
iperf3 -c 10.0.2.1 -P 4 -R -t 30

# Or via DMZ network
iperf3 -c 10.0.30.100 -P 4 -R -t 30
```

**Results (Feb 2026):**
| Configuration | Throughput | Notes |
|--------------|-----------|-------|
| All generic XDP | ~6.8 Gbps | baseline, all interfaces SKB mode |
| bpf_printk enabled | ~3 Gbps | 55%+ CPU wasted on trace output |
| Per-interface native XDP | ~25 Gbps | virtio native, iavf generic |
| During hitless restart | ~25 Gbps | zero drop across 3 restarts |

### CPU Profiling

**How to profile:**
```bash
# On VM: record 30 seconds of perf data during iperf3
incus exec bpfrx-fw -- perf record -a -g -F 99 -- sleep 30

# Copy perf.data to host
incus file pull bpfrx-fw/root/perf.data ./perf.data

# Analyze
perf report --no-children --sort=dso,symbol
```

**Perf profile (generic XDP, 4-stream iperf3):**
```
 8.1%  memcpy_orig          (SKB linearization for generic XDP)
 8.1%  memset_orig          (SKB head expansion for generic XDP)
 4.1%  pv_native_safe_halt  (CPU idle)
 3.8%  spin_unlock          (dev_map_generic_redirect)
 3.0%  clear_page_erms      (virtio RX page alloc)
 2.8%  htab_map_hash        (BPF hash map lookups)
 2.7%  xdp_main_prog        (entry point)
 2.5%  read_tsc             (conntrack ktime)
 2.1%  lookup_nulls_elem_raw (hash element traversal)
 2.0%  iavf_xmit_frame      (SR-IOV TX)
 1.7%  xdp_forward_prog     (forwarding stage)
 1.6%  csum_partial         (TX checksum)
 1.5%  xdp_conntrack_prog   (session lookup)
 1.1%  xdp_zone_prog        (zone + FIB lookup)
 1.0%  xdp_nat_prog         (NAT translation)
```

**Key insight:** BPF programs total ~10% CPU. Generic XDP infrastructure adds ~16%. FIB lookup is 0% (cached in session entries after first packet).

### Performance Optimizations Applied (in order)

1. **Disable bpf_printk** (`e104112`): 55%+ CPU → negligible. Always remove debug tracing for production.

2. **Reduce memset/memcpy** (`299a536`): Minimized per-packet metadata clearing. Only zero fields actually used, not entire scratch struct.

3. **FIB result caching** (`144a3c2`): Cache `fwd_ifindex`, `fwd_dmac`, `fwd_smac` in session entries. Skip `bpf_fib_lookup` on established flows. (Skip on TCP SYN to get fresh FIB for new connections.)

4. **Per-CPU NAT port partitioning** (`7aa77f0`): Eliminate cross-CPU contention on NAT port counters.

5. **Per-interface native XDP** (`f9edb92`): virtio-net interfaces use native XDP (driver mode), iavf uses generic. `redirect_capable` map tells xdp_forward which mode each interface supports.

---

## Hitless Restart Testing

### What It Tests
Daemon restart with zero session loss and zero packet loss via BPF map/link pinning.

### Prerequisites
- Stateful maps pinned to `/sys/fs/bpf/bpfrx/`
- XDP/TC links pinned to `/sys/fs/bpf/bpfrx/links/`
- Non-destructive SIGTERM shutdown (no route/DHCP/VRF cleanup)

### Test Procedure
```bash
# 1. Verify clean pinned state
sg incus-admin -c 'incus exec bpfrx-fw -- ls -la /sys/fs/bpf/bpfrx/'
sg incus-admin -c 'incus exec bpfrx-fw -- ls -la /sys/fs/bpf/bpfrx/links/'

# 2. Start long-running iperf3 (from host, cross-zone through firewall)
iperf3 -c 10.0.30.100 -P 4 -R -t 60 &

# 3. While iperf3 is running, restart daemon multiple times
sg incus-admin -c 'incus exec bpfrx-fw -- systemctl restart bpfrxd'
sleep 5
sg incus-admin -c 'incus exec bpfrx-fw -- systemctl restart bpfrxd'
sleep 5
sg incus-admin -c 'incus exec bpfrx-fw -- systemctl restart bpfrxd'

# 4. Verify iperf3 completes without errors
# Expected: consistent throughput, no retries, no stuck streams

# 5. Verify sessions survived
printf 'show security flow session\nexit\n' | \
  sg incus-admin -c 'incus exec bpfrx-fw -- cli' 2>/dev/null
```

### Success Criteria
- iperf3 throughput stays consistent (no drops to zero)
- No "connection reset" or "broken pipe" errors
- Sessions visible in CLI after restart
- No "stuck" parallel streams (all 4 should report similar throughput)

### Verified Results (Feb 2026)
- 3 restarts during 40-second iperf3: 25.3 Gbps average, zero drops
- Sessions survived all restarts
- No stuck streams

### Failure Modes (Before Fixes)
1. **Streams stuck at 0 bps:** Routes removed during shutdown → FIB lookup fails → packets dropped
2. **DHCP addresses lost:** DHCP context cancellation removes IPs → interface has no address
3. **Brief deny-all window:** Programs replaced before policies loaded → default-deny drops everything for ~100ms

### How Pinning Works

**Map pinning:**
```
/sys/fs/bpf/bpfrx/
├── sessions          # IPv4 conntrack (survives restart)
├── sessions_v6       # IPv6 conntrack (survives restart)
├── dnat_table        # Reverse DNAT mappings (survives restart)
├── dnat_table_v6     # IPv6 reverse DNAT (survives restart)
├── nat64_state       # NAT64 session state (survives restart)
└── nat_port_counters # SNAT port tracking (survives restart)
```

**Link pinning:**
```
/sys/fs/bpf/bpfrx/links/
├── xdp_3             # XDP link for ifindex 3 (enp6s0)
├── xdp_4             # XDP link for ifindex 4 (enp7s0)
├── xdp_5             # XDP link for ifindex 5 (enp8s0)
├── xdp_6             # XDP link for ifindex 6 (enp9s0)
├── xdp_7             # XDP link for ifindex 7 (enp10s0f0)
├── tc_3              # TC link for ifindex 3
├── tc_4              # ...
├── tc_5
├── tc_6
└── tc_7
```

**Restart flow:**
1. SIGTERM → close Go FD handles (pinned links/maps stay in kernel)
2. New daemon starts → `loadAllObjects()` reuses pinned maps (sessions preserved)
3. `AttachXDP()` loads pinned link → `link.Update(newProg)` atomically replaces program
4. Config recompiled → all maps repopulated → then program replacement happens
5. Existing sessions continue uninterrupted

**Full teardown:**
```bash
incus exec bpfrx-fw -- bpfrxd cleanup
# Removes /sys/fs/bpf/bpfrx/ recursively + clears FRR routes
```

---

## Debugging Techniques

### BPF Program Verification
```bash
# Check attached BPF programs
incus exec bpfrx-fw -- bpftool net show

# Check pinned maps
incus exec bpfrx-fw -- ls -la /sys/fs/bpf/bpfrx/

# Dump map contents (e.g., sessions)
incus exec bpfrx-fw -- bpftool map dump pinned /sys/fs/bpf/bpfrx/sessions
```

### Session Inspection
```bash
# Via CLI
printf 'show security flow session\nexit\n' | incus exec bpfrx-fw -- cli 2>/dev/null

# Filter by source
printf 'show security flow session source-prefix 10.0.1.0/24\nexit\n' | incus exec bpfrx-fw -- cli 2>/dev/null
```

### Route Verification
```bash
# FRR routes
incus exec bpfrx-fw -- vtysh -c 'show ip route'
incus exec bpfrx-fw -- vtysh -c 'show ipv6 route'

# Kernel routes (should match FRR)
incus exec bpfrx-fw -- ip route show
incus exec bpfrx-fw -- ip -6 route show
```

### XDP Mode Verification
```bash
# Check XDP attachment mode per interface
incus exec bpfrx-fw -- ip link show | grep -A1 xdp

# Or via bpftool
incus exec bpfrx-fw -- bpftool net show
```

### Counter Inspection
```bash
# Global counters via API
incus exec bpfrx-fw -- curl -s http://127.0.0.1:8080/api/stats | jq .

# Prometheus metrics
incus exec bpfrx-fw -- curl -s http://127.0.0.1:8080/metrics | grep bpfrx
```

### Common Issues

**"operation not supported" on XDP attach**
- Interface driver doesn't support native XDP
- Expected for iavf — falls back to generic automatically
- Check logs for `native XDP not supported, using generic mode`

**Session count drops to 0 after cleanup**
- Expected: `bpfrxd cleanup` removes all pinned state
- Restart daemon to recreate fresh state

---

## Network-Specific Notes

### Management Interface (enp5s0)
- `UseRoutes=false` in `/etc/systemd/network/enp5s0.network`
- Prevents DHCP default route from shadowing FRR-managed routes
- Still reachable via 10.0.100.0/24 connected route (for incus access)

### ARP Resolution with XDP
- `arping` uses PF_PACKET raw sockets — doesn't populate kernel ARP with XDP attached
- Use `ping` instead for proactive neighbor resolution
- Daemon runs periodic pings (every 15s) for DNAT pools, static NAT, gateways
- STALE ARP entries work fine with `bpf_fib_lookup` — only truly absent entries fail

### VLAN Handling
- WAN interface (enp10s0f0) uses VLAN 100 — tag pushed/popped in BPF
- Configured via Junos `vlan-tagging` + `unit 100 { vlan-id 100; }`
- `vlan_iface_map` BPF map tracks VLAN ID per logical interface

### IPv6
- DHCPv6 on WAN gets global address (2001:559:.../128)
- IPv6 default route via link-local gateway
- Router Advertisements managed via radvd on LAN interfaces
- NAT64 translation native in BPF (no Tayga/Jool)
