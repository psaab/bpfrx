# HA Cluster Test Plan — Two-VM SR-IOV Setup

## Overview

Two VMs running bpfrxd in chassis cluster (active/passive) mode with:
- **WAN**: SR-IOV VFs from `eno6np1` (i40e, one VF per VM via PCI passthrough, bonded into reth0)
- **LAN**: One bridged network (one interface per VM, bonded into reth1)
- **Heartbeat**: Dedicated bridge for cluster health monitoring (UDP:4784)
- **Fabric**: Dedicated link between VMs for session sync, config sync, IPsec SA sync (TCP)
- **Test host**: Container on LAN for end-to-end traffic validation

## Single-Config Model

Both nodes share **one configuration file** (`docs/ha-cluster.conf`) using the Junos
`groups` / `apply-groups` pattern. Node-specific settings (hostname, cluster node ID,
peer addresses, interface-to-RETH mappings) live inside `groups { node0 { ... } }` and
`groups { node1 { ... } }`. The shared sections (chassis cluster, RETH, security, NAT,
routing) appear at the top level.

At load time, the daemon reads `/etc/bpfrx/node-id` (a plain integer: 0 or 1) and
resolves `apply-groups "${node}"` by substituting `${node}` with `node0` or `node1`.
This merges the node-specific group into the active config, producing a complete
per-node configuration from a single source file.

Config sync "just works" — the primary sends the **unexpanded** config text (with groups
intact) to the secondary. Each node compiles it with its own `${node}` expansion.

### Interface Naming Convention

bpfrx uses vSRX-style interface names:

| vSRX Name | Linux Name | Role |
|-----------|-----------|------|
| `fxp0` | `fxp0` | Management (out-of-band) |
| `fxp1` | `fxp1` | Cluster control (heartbeat) |
| `fab0` | `fab0` | Fabric sync link |
| `ge-0/0/0` | `ge-0-0-0` | Node 0 data interface (LAN, reth1 member) |
| `ge-0/0/1` | `ge-0-0-1` | Node 0 data interface (WAN, reth0 member) |
| `ge-7/0/0` | `ge-7-0-0` | Node 1 data interface (LAN, reth1 member) |
| `ge-7/0/1` | `ge-7-0-1` | Node 1 data interface (WAN, reth0 member) |
| `reth0` | `reth0` | Redundant Ethernet — WAN |
| `reth1` | `reth1` | Redundant Ethernet — LAN |

**Name translation**: Junos `ge-X/Y/Z` uses slashes, but Linux interface names cannot
contain slashes. The daemon translates slashes to hyphens: `ge-0/0/0` → `ge-0-0-0`.
Config files use the Junos form; `.link` files rename kernel interfaces to the Linux form.

## Physical Host

```
Host NIC: eno6np1 (i40e, Intel X710/X722)
  - 32 SR-IOV VFs available (sriov_numvfs=32)
  - VFs passed through as PCI devices (type=pci) to each VM
  - VF0 (0000:b7:06.0) → bpfrx-fw0
  - VF1 (0000:b7:06.1) → bpfrx-fw1
  - VFs use iavf driver inside VMs (generic XDP only)
```

## Network Topology

```
                         Internet / Upstream
                              |
                    +---------+---------+
                    |   eno6np1 (i40e)  |  Host PF
                    |   32 SR-IOV VFs   |
                    +----+--------+-----+
                         |        |
                   VF0 (PCI)  VF1 (PCI)
                         |        |
              +----------+--+  +--+----------+
              |  bpfrx-fw0  |  |  bpfrx-fw1  |
              |  (node 0)   |  |  (node 1)   |
              |  pri: 200   |  |  pri: 100   |
              +--+--+--+--+-+  +-+--+--+--+--+
                 |  |  |  |      |  |  |  |
  fxp0 ---------+  |  |  |      +--|--------  fxp0
  fxp1 ------------+  |  |      +--|---------  fxp1
  fab0 ----------------+  |      |  +--------  fab0
  ge-0/0/0 ---------------+      +-----------  ge-7/0/0
                 |                   |
                 +------+   +-------+
                        |   |
           incusbr0             (fxp0, DHCP)
           bpfrx-heartbeat      (fxp1, 10.99.0.0/30)
           bpfrx-fabric         (fab0, 10.99.1.0/30)
           bpfrx-clan           (reth1: 10.0.60.0/24)

              +------------------+
              |  cluster-lan-    |
              |  host            |
              |  eth0: clan      |  10.0.60.102/24
              +------------------+
```

Each VM has one LAN interface on the same bridge. reth1 floats the VIP to
whichever VM is primary, same as reth0 for WAN.

## Incus Resources

### Networks (all pure L2, no Incus IP management)

| Network | Purpose | Incus Config |
|---------|---------|-------------|
| `incusbr0` | Management (existing, DHCP) | default |
| `bpfrx-heartbeat` | Cluster heartbeat (UDP:4784) | ipv4.address=none, ipv6.address=none |
| `bpfrx-fabric` | Session/config/IPsec sync (TCP) | ipv4.address=none, ipv6.address=none |
| `bpfrx-clan` | LAN segment (reth1 member per VM) | ipv4.address=none, ipv6.address=none |

### Profile: `bpfrx-cluster`

```
CPU:    4 vCPU
Memory: 4 GB
Disk:   20 GB (pool: default)
```

| Device | VM Interface | Renamed To | Network | Purpose |
|--------|-------------|-----------|---------|---------|
| `eth0` | enp5s0 | fxp0 | incusbr0 | Management (DHCP) |
| `eth1` | enp6s0 | fxp1 | bpfrx-heartbeat | Heartbeat / control |
| `eth2` | enp7s0 | fab0 | bpfrx-fabric | Fabric sync |
| `eth3` | enp8s0 | ge-X-0-0 | bpfrx-clan | LAN (reth1 member) |

SR-IOV WAN VF added per-VM as PCI passthrough (becomes `ge-X-0-1`):
```bash
incus config device add $vm wan-vf pci address=0000:b7:06.0  # VF0 for fw0
incus config device add $vm wan-vf pci address=0000:b7:06.1  # VF1 for fw1
```

Where X = 0 for node 0 (`ge-0-0-0`, `ge-0-0-1`) and X = 7 for node 1 (`ge-7-0-0`, `ge-7-0-1`).

### Instances

| Instance | Type | Role |
|----------|------|------|
| `bpfrx-fw0` | VM | Firewall node 0 (primary, priority 200) |
| `bpfrx-fw1` | VM | Firewall node 1 (secondary, priority 100) |
| `cluster-lan-host` | Container | Test traffic source/sink on LAN (eth0 only) |

## Interface Mapping

### Per-VM Interfaces

**Node 0 (bpfrx-fw0):**

| Kernel Name | Renamed To | Config Name | Driver | XDP Mode | Role |
|-------------|-----------|-------------|--------|----------|------|
| enp5s0 | fxp0 | fxp0 | virtio_net | native | Management (DHCP) |
| enp6s0 | fxp1 | fxp1 | virtio_net | native | Heartbeat / control |
| enp7s0 | fab0 | fab0 | virtio_net | native | Fabric sync |
| enp8s0 | ge-0-0-0 | ge-0/0/0 | virtio_net | native | LAN (reth1 member) |
| enp9s0f0 (VF) | ge-0-0-1 | ge-0/0/1 | iavf | generic | WAN (reth0 member) |

**Node 1 (bpfrx-fw1):**

| Kernel Name | Renamed To | Config Name | Driver | XDP Mode | Role |
|-------------|-----------|-------------|--------|----------|------|
| enp5s0 | fxp0 | fxp0 | virtio_net | native | Management (DHCP) |
| enp6s0 | fxp1 | fxp1 | virtio_net | native | Heartbeat / control |
| enp7s0 | fab0 | fab0 | virtio_net | native | Fabric sync |
| enp8s0 | ge-7-0-0 | ge-7/0/0 | virtio_net | native | LAN (reth1 member) |
| enp9s0f0 (VF) | ge-7-0-1 | ge-7/0/1 | iavf | generic | WAN (reth0 member) |

### RETH Bonds

| RETH | Node 0 Member | Node 1 Member | IPv4 VIP | IPv6 VIP | Zone | Purpose |
|------|--------------|--------------|----------|----------|------|---------|
| reth0 | ge-0/0/1 | ge-7/0/1 | 172.16.50.6/24 (VLAN 50) | 2001:559:8585:50::6/64 | wan | WAN uplink |
| reth1 | ge-0/0/0 | ge-7/0/0 | 10.0.60.1/24 | 2001:559:8585:cf01::1/64 | lan | LAN |

## IP Addressing

### Point-to-Point Links

| Link | fw0 | fw1 | Subnet |
|------|-----|-----|--------|
| Heartbeat (fxp1) | 10.99.0.1/30 | 10.99.0.2/30 | 10.99.0.0/30 |
| Fabric (fab0) | 10.99.1.1/30 | 10.99.1.2/30 | 10.99.1.0/30 |

### RETH VIPs (float to primary)

| RETH | IPv4 VIP | IPv6 VIP | Gateway for |
|------|----------|----------|-------------|
| reth0 | 172.16.50.6/24 | 2001:559:8585:50::6/64 | WAN uplink |
| reth1 | 10.0.60.1/24 | 2001:559:8585:cf01::1/64 | cluster-lan-host |

### Test Container

| Interface | Network | IPv4 Address | IPv6 | Gateway |
|-----------|---------|-------------|------|---------|
| eth0 | bpfrx-clan | 10.0.60.102/24 | SLAAC + DHCPv6 | 10.0.60.1 / fe80::... (RA) |

## Cluster Configuration

A single config file (`docs/ha-cluster.conf`) is loaded on both nodes. The
`apply-groups "${node}"` directive selects node-specific overrides at commit time.

Node ID is read from `/etc/bpfrx/node-id` (plain integer: 0 or 1). If this file
does not exist, the daemon runs in standalone (non-cluster) mode.

### Node-Specific Settings (via groups)

| Setting | node0 (fw0) | node1 (fw1) |
|---------|------------|------------|
| host-name | bpfrx-fw0 | bpfrx-fw1 |
| cluster node | 0 | 1 |
| peer-address | 10.99.0.2 | 10.99.0.1 |
| fabric-peer-address | 10.99.1.2 | 10.99.1.1 |
| fxp1 address | 10.99.0.1/30 | 10.99.0.2/30 |
| fab0 address | 10.99.1.1/30 | 10.99.1.2/30 |
| WAN RETH member | ge-0/0/1 | ge-7/0/1 |
| LAN RETH member | ge-0/0/0 | ge-7/0/0 |

### Shared Cluster Settings

```
chassis {
    cluster {
        cluster-id 1;
        reth-count 2;
        heartbeat-interval 1000;
        heartbeat-threshold 3;
        control-interface fxp1;
        fabric-interface fab0;
        configuration-synchronize;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
        }
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
            gratuitous-arp-count 8;
            interface-monitor {
                ge-0/0/1 weight 255;
                ge-7/0/1 weight 255;
            }
        }
        redundancy-group 2 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
            gratuitous-arp-count 8;
            interface-monitor {
                ge-0/0/0 weight 255;
                ge-7/0/0 weight 255;
            }
        }
    }
}
```

- **RG0**: Control plane (cluster management, no interface-monitor)
- **RG1**: reth0/WAN — monitors both nodes' WAN physical interfaces
- **RG2**: reth1/LAN — monitors both nodes' LAN physical interfaces

### Security Zones

| Zone | Interfaces | Allowed Services | Allowed Protocols |
|------|-----------|-----------------|------------------|
| mgmt | fxp0 | ssh, ping, dhcp | — |
| control | fxp1, fab0 | ping | — |
| wan | reth0 | ping | — |
| lan | reth1 | ssh, ping, dhcp, dhcpv6 | router-discovery |

### Policies

| From | To | Action | Notes |
|------|----|--------|-------|
| lan | wan | permit + SNAT | Internet access from LAN |
| wan | lan | deny | Default deny inbound |
| default | * | deny-all | Global default |

### NAT

```
security {
    nat {
        source {
            rule-set lan-to-wan {
                from zone lan;
                to zone wan;
                rule snat {
                    match { source-address 0.0.0.0/0; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}
```

### Routing

```
routing-options {
    static {
        route 0.0.0.0/0 { next-hop 172.16.50.1; }
        route ::/0 { next-hop 2001:559:8585:50::1; }
    }
}
```

### Router Advertisements (reth1)

```
protocols {
    router-advertisement {
        interface reth1 {
            managed-configuration;
            other-stateful-configuration;
            prefix 2001:559:8585:cf01::/64 { on-link; autonomous; }
            dns-server-address 2001:4860:4860::8888;
        }
    }
}
```

Flags: M (managed) tells clients to use DHCPv6 for address, O (other) for DNS/domain,
A (autonomous) allows SLAAC as well. radvd resolves RETH names to physical member
interfaces via `ResolveReth()` + `LinuxIfName()`.

### DHCP Server (on reth1)

```
system {
    services {
        dhcp-local-server {
            group lan-pool {
                interface reth1;
                pool lan-range {
                    subnet 10.0.60.0/24;
                    address-range low 10.0.60.100 high 10.0.60.199;
                    router 10.0.60.1;
                    dns-server 8.8.8.8;
                }
            }
        }
    }
}
```

### DHCPv6 Server (on reth1)

```
system {
    services {
        dhcpv6-local-server {
            group lan6-pool {
                interface reth1;
                pool lan6-range {
                    subnet 2001:559:8585:cf01::/64;
                    address-range low 2001:559:8585:cf01::100 high 2001:559:8585:cf01::1ff;
                    dns-server 2001:4860:4860::8888;
                }
            }
        }
    }
}
```

## Setup Procedure

All setup is automated via `test/incus/cluster-setup.sh`:

```bash
./test/incus/cluster-setup.sh init       # Create networks + profile
./test/incus/cluster-setup.sh create     # Launch both VMs + test container
./test/incus/cluster-setup.sh deploy all # Build bpfrxd, push to both VMs
```

Or via Makefile targets:
```bash
make cluster-init     # Create networks + profile
make cluster-create   # Launch both VMs + test container
make cluster-deploy   # Build + push to both VMs (NODE=0|1 for single)
make cluster-destroy  # Tear down
make cluster-status   # Show status
make cluster-ssh NODE=0|1  # Shell into VM
make cluster-logs NODE=0|1 # Show logs
make cluster-start/stop/restart  # Service lifecycle (NODE=0|1|all)
```

### What `create` does per VM

1. Launch Debian 13 VM with `bpfrx-cluster` profile (4 virtio NICs)
2. Add SR-IOV VF via PCI passthrough (stop VM → add device → restart)
3. Write `.link` files for vSRX-style interface renaming (MAC-based)
4. Install packages: FRR, strongSwan, tcpdump, iperf3, bpftool, ethtool, etc.
5. Upgrade kernel to 6.18+ from Debian unstable
6. Set GRUB: `init_on_alloc=0` for XDP performance
7. Configure sysctl: BPF JIT, IP forwarding, RA disable
8. Write `/etc/bpfrx/node-id` (0 or 1)
9. Reboot for new kernel

### What `deploy` does per VM

1. Build `bpfrxd` and `cli` binaries
2. Stop running service, push binaries to `/usr/local/sbin/`
3. Push unified `docs/ha-cluster.conf` to `/etc/bpfrx/bpfrx.conf`
4. Ensure `/etc/bpfrx/node-id` exists
5. Install and enable systemd service

## Test Cases

### TC-1: Cluster Formation

**Objective:** Verify both nodes form a cluster and elect a primary.

```bash
# On fw0 (expected primary due to priority 200):
printf 'show chassis cluster status\nexit\n' | incus exec bpfrx-fw0 -- cli

# Expected:
#   Node 0: primary   (priority 200, weight 255)
#   Node 1: secondary (priority 100, weight 255)
```

**Pass criteria:**
- fw0 is primary for RG0
- fw1 is secondary for RG0
- Heartbeat state: "up"
- Both RETH interfaces active on fw0

### TC-2: LAN Connectivity Through Cluster (IPv4 + IPv6)

**Objective:** Verify traffic flows from LAN container through the primary firewall to WAN.

```bash
# IPv4 from cluster-lan-host:
incus exec cluster-lan-host -- ping -c 5 172.16.50.1   # WAN gateway (via reth0)
incus exec cluster-lan-host -- ping -c 5 8.8.8.8       # Internet (SNAT via reth0)
incus exec cluster-lan-host -- ping -c 5 10.0.60.1     # reth1 VIP

# IPv6 from cluster-lan-host:
incus exec cluster-lan-host -- ping -c 5 2001:559:8585:cf01::1  # reth1 IPv6 VIP
incus exec cluster-lan-host -- ping -c 5 2001:559:8585:50::6    # reth0 IPv6 VIP (WAN)

# Verify sessions on primary:
printf 'show security flow session\nexit\n' | incus exec bpfrx-fw0 -- cli
```

**Pass criteria:**
- All IPv4 pings succeed
- IPv6 gateway ping (reth1) succeeds
- Sessions visible on fw0 (primary)
- SNAT applied for WAN-bound traffic

### TC-3: Failover — Primary Failure

**Objective:** Verify secondary takes over when primary fails.

```bash
# 1. Start continuous ping from cluster-lan-host
incus exec cluster-lan-host -- ping 8.8.8.8 &

# 2. Stop primary
incus exec bpfrx-fw0 -- systemctl stop bpfrxd

# 3. Wait for failover (heartbeat-threshold * interval = 3s)
sleep 5

# 4. Check cluster status on fw1
printf 'show chassis cluster status\nexit\n' | incus exec bpfrx-fw1 -- cli

# 5. Verify ping continues (may lose 3-5 packets during failover)
```

**Pass criteria:**
- fw1 becomes primary within ~5 seconds
- GARP sent for reth0, reth1 VIPs
- cluster-lan-host traffic resumes after brief interruption
- Sessions synced from fw0 survive on fw1

### TC-4: Failover — Recovery and Preemption

**Objective:** Verify original primary reclaims after recovery (preempt enabled).

```bash
# 1. Restart fw0
incus exec bpfrx-fw0 -- systemctl start bpfrxd

# 2. Wait for preemption (election + hold timer)
sleep 10

# 3. Verify fw0 is primary again
printf 'show chassis cluster status\nexit\n' | incus exec bpfrx-fw0 -- cli
```

**Pass criteria:**
- fw0 reclaims primary role
- Traffic continues without prolonged outage
- Session state synced back

### TC-5: Config Synchronization

**Objective:** Verify config changes on primary replicate to secondary.

```bash
# 1. On fw0 (primary), add a policy:
printf 'configure\nset security policies from-zone lan to-zone wan policy test-sync match source-address any destination-address any application any then permit\ncommit\nexit\nexit\n' | incus exec bpfrx-fw0 -- cli

# 2. On fw1, verify config arrived:
printf 'show configuration security policies from-zone lan to-zone wan | display set\nexit\n' | incus exec bpfrx-fw1 -- cli
```

**Pass criteria:**
- Policy `test-sync` appears on fw1 within seconds
- fw1 shows config as read-only (secondary cannot modify)

### TC-6: Session Synchronization

**Objective:** Verify active sessions are synced to secondary for hitless failover.

```bash
# 1. Create a long-lived session from cluster-lan-host
incus exec cluster-lan-host -- iperf3 -c <wan-target> -t 60 &

# 2. Verify session on fw0
printf 'show security flow session\nexit\n' | incus exec bpfrx-fw0 -- cli

# 3. Verify session is synced to fw1
printf 'show security flow session\nexit\n' | incus exec bpfrx-fw1 -- cli
```

**Pass criteria:**
- Session appears on both fw0 and fw1
- Session on fw1 matches fw0 (IPs, ports, NAT state)

### TC-7: RETH Interface Monitor Failover

**Objective:** Verify failover when a monitored RETH member loses link.

```bash
# Simulate WAN VF failure by detaching the PCI device:
incus config device remove bpfrx-fw0 wan-vf

# Monitor cluster status (reth0 weight should drop to 0):
printf 'show chassis cluster status\nexit\n' | incus exec bpfrx-fw1 -- cli
```

**Pass criteria:**
- fw0 weight drops (reth0 monitor triggers)
- fw1 becomes primary if fw0 weight falls below fw1
- Traffic fails over to fw1's WAN VF

### TC-8: Throughput Under HA

**Objective:** Measure forwarding throughput through the HA cluster.

```bash
# Server on WAN side (or use external target)
# Client on cluster-lan-host:
incus exec cluster-lan-host -- iperf3 -c <target> -P 4 -t 30 -C bbr
```

**Pass criteria:**
- Throughput > 1 Gbps through SNAT (generic XDP on iavf VF is the bottleneck)
- No packet loss during steady state
- Compare with/without HA overhead

### TC-9: DHCP Server on reth1

**Objective:** Verify cluster-lan-host can obtain an address via DHCP from the primary.

```bash
incus exec cluster-lan-host -- dhclient eth0
incus exec cluster-lan-host -- ip addr show eth0
```

**Pass criteria:**
- Lease obtained from 10.0.60.100-199 range
- Gateway set to 10.0.60.1 (reth1 VIP)

### TC-10: Split-Brain Prevention

**Objective:** Verify cluster handles heartbeat network failure gracefully.

```bash
# Disconnect heartbeat by removing device from fw1
incus config device remove bpfrx-fw1 eth1

# Both nodes should detect heartbeat loss
# Node 1 (lower priority) should go secondary-hold
sleep 10
printf 'show chassis cluster status\nexit\n' | incus exec bpfrx-fw0 -- cli
printf 'show chassis cluster status\nexit\n' | incus exec bpfrx-fw1 -- cli
```

**Pass criteria:**
- No dual-primary condition
- Higher-priority node retains primary
- Lower-priority node enters secondary-hold or lost state

### TC-11: IPv6 Router Advertisements and DHCPv6

**Objective:** Verify LAN hosts receive IPv6 configuration via SLAAC and DHCPv6.

```bash
# Verify radvd is running on primary with correct interface name
incus exec bpfrx-fw0 -- systemctl status radvd
incus exec bpfrx-fw0 -- cat /etc/radvd.conf
# Expected: interface name is physical member (ge-0-0-0), NOT "reth1"

# Verify kea-dhcp6 is running on primary
incus exec bpfrx-fw0 -- systemctl status kea-dhcp6-server

# Verify cluster-lan-host got IPv6 via SLAAC/DHCPv6
incus exec cluster-lan-host -- ip -6 addr show eth0
# Expected: global address in 2001:559:8585:cf01::/64

# Verify RA from cluster-lan-host (needs ndisc6 package)
incus exec cluster-lan-host -- rdisc6 eth0
# Expected: Router Advertisement from fe80::... with prefix 2001:559:8585:cf01::/64

# Ping IPv6 gateway
incus exec cluster-lan-host -- ping -c 3 2001:559:8585:cf01::1
```

**Pass criteria:**
- radvd running with physical interface name (not reth1)
- kea-dhcp6-server running
- cluster-lan-host has global IPv6 address
- IPv6 gateway reachable

### TC-12: Hitless Forwarding Failover (IPv4 + IPv6)

**Objective:** Verify transit traffic survives primary restart with minimal disruption.

This tests the `META_FLAG_KERNEL_ROUTE` BPF fallback path: when
`bpf_fib_lookup` returns LOCAL/NOT_FWDED for packets matching existing sessions
(stale FIB cache after restart), the packet routes through conntrack for NAT
reversal and then XDP_PASSes for kernel routing.

```bash
# IPv4 forwarding test through SNAT:
# 1. Start a long ping from LAN to an external host
incus exec cluster-lan-host -- ping -c 30 -i 0.5 172.16.100.247 &

# 2. After ~5 seconds, restart the primary
sleep 5
incus exec bpfrx-fw0 -- systemctl restart bpfrxd

# 3. Wait for ping to complete, check results
# Expected: 28-29/30 received (1-2 packets lost during restart, ~1s disruption)

# IPv6 forwarding test:
incus exec cluster-lan-host -- ping -c 30 -i 0.5 2001:559:8585:cf01::1 &
sleep 5
incus exec bpfrx-fw0 -- systemctl restart bpfrxd
# Expected: similar 1-2 packet loss

# Full failover test (stop primary, secondary takes over):
incus exec cluster-lan-host -- ping -c 60 -i 0.5 10.0.60.1 &
sleep 5
incus exec bpfrx-fw0 -- systemctl stop bpfrxd
# Expected: 3-5 packets lost during VRRP failover (~3.5s)
sleep 15
incus exec bpfrx-fw0 -- systemctl start bpfrxd
# Expected: 3-5 more packets lost during preemption back
```

**Pass criteria:**
- Hitless restart (systemctl restart): <= 2 packets lost
- Full failover (stop primary): <= 5 packets lost
- Traffic auto-recovers after all transitions
- No permanent traffic blackhole

**How it works:**
1. BPF programs pinned at `/sys/fs/bpf/bpfrx/` survive daemon restart
2. Existing sessions preserved in pinned conntrack maps
3. After restart, FIB cache in session entries is stale (`fib_gen` mismatch)
4. `bpf_fib_lookup` may return LOCAL/NOT_FWDED (routes not yet in kernel)
5. `xdp_zone` detects existing session + failed FIB → sets `META_FLAG_KERNEL_ROUTE`
6. `xdp_conntrack` processes session normally (NAT reversal via meta fields)
7. `xdp_forward` sees `META_FLAG_KERNEL_ROUTE` → `XDP_PASS` for kernel routing
8. Kernel forwards the NAT'd packet via its own routing table
9. Once FRR converges (~1-2s), fresh FIB lookups succeed and XDP resumes direct forwarding

## Performance Expectations

| Metric | Expected | Notes |
|--------|----------|-------|
| WAN throughput (per VF) | ~6-8 Gbps | iavf generic XDP, single direction |
| LAN throughput (virtio) | ~12-15 Gbps | virtio_net native XDP |
| Failover time | ~3.5 seconds | Master-down timer (3×advert + skew) |
| Session sync latency | < 2 seconds | Ring buffer real-time + 1s sweep |
| Config sync latency | < 1 second | TCP immediate push on commit |
| IPv4 VIP recovery | < 1 second | Dual GARP + gateway ARP probe |
| IPv6 VIP recovery | < 1 second | Unsolicited NA + NODAD flag |

## Known Issues & Fixes (Post-Implementation)

### ConfigDB Bootstrap Caveat

The daemon stores compiled config in `.configdb/active.json`. On startup it loads
from this DB, NOT from the text `.conf` file. The text config is only read when the
DB is empty (first boot or after deletion).

**If you change `ha-cluster.conf` and redeploy**, the daemon will ignore the new
text file because `active.json` already exists. To force re-bootstrap:

```bash
incus exec bpfrx-fw0 -- rm /etc/bpfrx/.configdb/active.json
incus exec bpfrx-fw1 -- rm /etc/bpfrx/.configdb/active.json
make cluster-deploy  # re-push config + restart
```

Alternatively, use `load override` via CLI to load the new config interactively.

### BPF FIB LOCAL/NOT_FWDED Fix (`b0e7e33`)

**Problem:** After daemon restart or VRRP failover, existing sessions had stale FIB
cache entries. `bpf_fib_lookup` returned LOCAL or NOT_FWDED because FRR routes hadn't
converged yet. These packets fell into the host-inbound path in `xdp_forward` and
were either dropped (by host-inbound policy) or delivered to the kernel stack without
NAT reversal, causing RSTs.

**Fix:** Three-part change:
1. `bpfrx_common.h`: Added `META_FLAG_KERNEL_ROUTE` (1 << 2)
2. `xdp_zone.c`: In the FIB failure else-branch, check if packet matches an existing
   session (sv4/sv6 != NULL). If so, set `META_FLAG_KERNEL_ROUTE` and tail-call to
   conntrack for normal session processing and NAT reversal.
3. `xdp_forward.c`: When `fwd_ifindex == 0` and `META_FLAG_KERNEL_ROUTE` is set,
   bypass host-inbound policy and `XDP_PASS` for kernel routing. This is transit
   traffic that needs kernel forwarding, not host-bound traffic.

**Result:** Hitless restart loses only 1-2 packets (ARP/NDP warmup delay) instead of
permanent traffic blackhole for all existing sessions.

### VRRP Implementation History
1. **Deadlock (`58ad85b`):** Manager write lock held during `stop()` which waited for blocking `recvmsg`. Fix: `SyscallConn().Control()`, `SetReadDeadline(1s)`, close-before-wait
2. **VLAN split-brain (`e018918`):** XDP strips VLAN tags; VRRP bypass didn't restore. Fix: push tag back, use AF_PACKET for VLAN sub-interfaces
3. **Per-interface sockets (`70b107c`):** Shared socket missed VLAN multicast. Fix: per-instance `SO_BINDTODEVICE` + self-sent filtering
4. **AF_PACKET for all (`d951626`):** Raw IP unreliable with generic XDP. Fix: AF_PACKET receiver for ALL instances; skip RETH VIP reconciliation
5. **Upstream GARP (`7bcaee9`):** Some routers ignore gratuitous ARP Reply. Fix: dual ARP format + gateway probe
6. **IPv6 VIP (`d03b29e`):** DAD failure + missing FRR interface + RETH name. Fix: NODAD flag + inline key extraction + RethMap translation
7. **Config sync (`64bc9d5`):** `${node}` unquoted in Format + no reverse-sync. Fix: `QuotedKeyPath()` + `OnPeerConnected` with startup guard

## SR-IOV Notes

- `eno6np1` (i40e) has 32 VFs; this setup uses 2 (VF0+VF1), leaving 30 for other uses
- VFs are passed through as PCI devices (`type=pci`), not `nictype=sriov` (which has hotplug issues)
- VFs use `iavf` driver inside VMs — **no native XDP**, only generic/SKB mode
- `redirect_capable` map in BPF marks VF interfaces as non-redirectable
- VF interfaces fall back to `XDP_PASS` (kernel forwarding) instead of `bpf_redirect_map`
- WAN throughput is lower than LAN (virtio native XDP) due to generic mode overhead
- Spoof checking is ON by default on VFs — may need to be disabled for RETH MAC changes:
  ```bash
  ip link set eno6np1 vf <N> spoofchk off
  ```
