# HA Cluster Test Plan — Two-VM SR-IOV Setup

## Overview

Two VMs running bpfrxd in chassis cluster (active/passive) mode with:
- **WAN**: SR-IOV VFs from `eno6np1` (i40e, one VF per VM, bonded into reth0)
- **LAN**: One bridged network (one interface per VM, bonded into reth1)
- **Heartbeat**: Dedicated bridge for cluster health monitoring (UDP:4784)
- **Fabric**: Dedicated link between VMs for session sync, config sync, IPsec SA sync (TCP)
- **Test host**: Container on LAN for end-to-end traffic validation

## Physical Host

```
Host NIC: eno6np1 (i40e, Intel X710)
  - 32 SR-IOV VFs available (sriov_numvfs=32)
  - VFs use iavf driver inside VMs (generic XDP only)
  - Incus nictype=sriov auto-selects free VFs
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
                      VF0(wan)  VF1(wan)
                         |        |
              +----------+--+  +--+----------+
              |  bpfrx-fw0  |  |  bpfrx-fw1  |
              |  (node 0)   |  |  (node 1)   |
              |  pri: 200   |  |  pri: 100   |
              +--+--+--+--+--+  +--+--+--+--+--+
                 |  |  |  |       |  |  |  |
  mgmt0 --------+  |  |  |       |--|---------  mgmt0
  hb0   -----------+  |  |       +--|------  hb0
  fab0   -------------+  |       |  +-----  fab0
  lan0  -----------------+       +---------  lan0
                 |                  |
                 +------+  +-------+
                        |  |
           incusbr0              (mgmt0, DHCP)
           bpfrx-ha-heartbeat   (hb0, 10.99.0.0/30)
           bpfrx-ha-fabric      (fab0, 10.99.1.0/30)
           bpfrx-ha-lan         (reth1: 10.0.60.0/24)

              +------------------+
              |  ha-lan-host     |
              |  (container)     |
              |  eth1: lan       |  10.0.60.102/24
              +------------------+
```

Each VM has one LAN interface on the same bridge. reth1 floats the VIP to
whichever VM is primary, same as reth0 for WAN.

## Incus Resources

### Networks (all pure L2, no Incus IP management)

| Network | Purpose | Incus Config |
|---------|---------|-------------|
| `incusbr0` | Management (existing, DHCP) | default |
| `bpfrx-ha-heartbeat` | Cluster heartbeat (UDP:4784) | ipv4.address=none, ipv6.address=none |
| `bpfrx-ha-fabric` | Session/config/IPsec sync (TCP) | ipv4.address=none, ipv6.address=none |
| `bpfrx-ha-lan` | LAN segment (reth1 member per VM) | ipv4.address=none, ipv6.address=none |

### Profile: `bpfrx-ha-cluster`

```
CPU:    4 vCPU
Memory: 4 GB
Disk:   20 GB (pool: default)
```

| Device | VM Interface | Network | Purpose |
|--------|-------------|---------|---------|
| `eth0` | enp5s0 | incusbr0 | Management (DHCP) |
| `eth1` | enp6s0 | bpfrx-ha-heartbeat | Heartbeat |
| `eth2` | enp7s0 | bpfrx-ha-fabric | Fabric sync |
| `eth3` | enp8s0 | bpfrx-ha-lan | LAN (reth1 member) |

SR-IOV WAN device added per-VM after launch:
```bash
incus config device add $vm wan-vf nic nictype=sriov parent=eno6np1
```

### Instances

| Instance | Type | Role |
|----------|------|------|
| `bpfrx-fw0` | VM | Firewall node 0 (primary, priority 200) |
| `bpfrx-fw1` | VM | Firewall node 1 (secondary, priority 100) |
| `ha-lan-host` | Container | Test traffic source/sink on LAN |

## Interface Mapping

### Per-VM Interfaces

| Kernel Name | Renamed To | Driver | XDP Mode | Role |
|-------------|-----------|--------|----------|------|
| enp5s0 | mgmt0 | virtio_net | native | Management (DHCP) |
| enp6s0 | hb0 | virtio_net | native | Heartbeat |
| enp7s0 | fab0 | virtio_net | native | Fabric sync |
| enp8s0 | lan0 | virtio_net | native | LAN (reth1 member) |
| enp*s* (VF) | wan-vf | iavf | generic | WAN (reth0 member) |

### RETH Bonds

| RETH | Members | VIP | Zone | Purpose |
|------|---------|-----|------|---------|
| reth0 | wan-vf (per-VM) | 172.16.50.10/24 | wan | WAN uplink |
| reth1 | lan0 (per-VM) | 10.0.60.1/24 | lan | LAN |

## IP Addressing

### Point-to-Point Links

| Link | fw0 | fw1 | Subnet |
|------|-----|-----|--------|
| Heartbeat (hb0) | 10.99.0.1/30 | 10.99.0.2/30 | 10.99.0.0/30 |
| Fabric (fab0) | 10.99.1.1/30 | 10.99.1.2/30 | 10.99.1.0/30 |

### RETH VIPs (float to primary)

| RETH | VIP | Gateway for |
|------|-----|-------------|
| reth0 | 172.16.50.10/24 | WAN uplink |
| reth1 | 10.0.60.1/24 | ha-lan-host |

### Test Container

| Interface | Network | Address | Gateway |
|-----------|---------|---------|---------|
| eth1 | bpfrx-ha-lan | 10.0.60.102/24 | 10.0.60.1 (reth1) |

## Cluster Configuration

### Chassis Cluster (both nodes)

```
chassis {
    cluster {
        cluster-id 1;
        reth-count 2;
        heartbeat-interval 1000;
        heartbeat-threshold 3;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
            interface-monitor {
                reth0 weight 255;
                reth1 weight 128;
            }
        }
    }
}
```

### Node-Specific Config

**fw0 (node 0):**
```
control-interface hb0;
peer-address 10.99.0.2;
fabric-interface fab0;
fabric-peer-address 10.99.1.2;
configuration-synchronize;
```

**fw1 (node 1):**
```
control-interface hb0;
peer-address 10.99.0.1;
fabric-interface fab0;
fabric-peer-address 10.99.1.1;
configuration-synchronize;
```

### Security Zones

| Zone | Interfaces | Allowed Services |
|------|-----------|-----------------|
| mgmt | mgmt0 | ssh, ping, dhcp |
| control | hb0, fab0 | ping |
| wan | reth0 | ping |
| lan | reth1 | ssh, ping, dhcp |

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
                rule snat-masq {
                    match { source-address 0.0.0.0/0; }
                    then { source-nat interface; }
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
        route 0.0.0.0/0 next-hop 172.16.50.1;
    }
}
```

### DHCP Server (on reth1)

```
system {
    services {
        dhcp-local-server {
            group lan-pool {
                interface reth1;
            }
        }
    }
}
access {
    address-assignment {
        pool lan-pool {
            family inet {
                network 10.0.60.0/24;
                range clients {
                    low 10.0.60.100;
                    high 10.0.60.199;
                }
                dhcp-attributes {
                    router 10.0.60.1;
                }
            }
        }
    }
}
```

## Setup Procedure

### 1. Create Networks

```bash
for net in bpfrx-ha-heartbeat bpfrx-ha-fabric bpfrx-ha-lan; do
    incus network create "$net" \
        ipv4.address=none ipv4.nat=false \
        ipv6.address=none ipv6.nat=false
done
```

### 2. Create Profile

```bash
incus profile create bpfrx-ha-cluster
incus profile set bpfrx-ha-cluster limits.cpu=4
incus profile set bpfrx-ha-cluster limits.memory=4GB
incus profile device add bpfrx-ha-cluster root disk pool=default path=/ size=20GB
incus profile device add bpfrx-ha-cluster eth0 nic network=incusbr0 name=enp5s0
incus profile device add bpfrx-ha-cluster eth1 nic network=bpfrx-ha-heartbeat name=enp6s0
incus profile device add bpfrx-ha-cluster eth2 nic network=bpfrx-ha-fabric name=enp7s0
incus profile device add bpfrx-ha-cluster eth3 nic network=bpfrx-ha-lan name=enp8s0
```

### 3. Launch VMs

```bash
for vm in bpfrx-fw0 bpfrx-fw1; do
    incus launch images:debian/13 "$vm" --vm --profile bpfrx-ha-cluster
    incus config device add "$vm" wan-vf nic nictype=sriov parent=eno6np1
done
```

### 4. Provision VMs

On each VM:
- Upgrade kernel to 6.18+ from Debian unstable
- Install: frr, strongswan, iproute2, tcpdump, iperf3, bpftool, radvd
- Set GRUB: `init_on_alloc=0`
- Enable: `net.core.bpf_jit_enable=1`, `net.ipv4.ip_forward=1`, IPv6 forwarding
- Write `.link` files for interface renaming (MAC-based)
- Write `setup.sh` bootstrap for first-boot interface rename

### 5. Launch Test Container

```bash
incus launch images:debian/13 ha-lan-host
incus network attach bpfrx-ha-lan ha-lan-host eth1
```

Configure inside container:
```bash
ip addr add 10.0.60.102/24 dev eth1
ip link set eth1 up
ip route add default via 10.0.60.1
```

### 6. Deploy bpfrxd

```bash
make build && make build-ctl
# Push to each VM:
for vm in bpfrx-fw0 bpfrx-fw1; do
    incus file push bpfrxd "$vm/usr/local/sbin/bpfrxd"
    incus file push cli "$vm/usr/local/sbin/cli"
done
# Push per-node configs, enable service, start
```

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

### TC-2: LAN Connectivity Through Cluster

**Objective:** Verify traffic flows from LAN container through the primary firewall to WAN.

```bash
# From ha-lan-host:
ping -c 5 172.16.50.1      # WAN gateway (via reth0)
ping -c 5 8.8.8.8          # Internet (SNAT via reth0)
ping -c 5 10.0.60.1        # reth1 VIP

# Verify session on primary:
printf 'show security flow session\nexit\n' | incus exec bpfrx-fw0 -- cli
```

**Pass criteria:**
- All pings succeed
- Sessions visible on fw0 (primary)
- SNAT applied for WAN-bound traffic

### TC-3: Failover — Primary Failure

**Objective:** Verify secondary takes over when primary fails.

```bash
# 1. Start continuous ping from ha-lan-host
incus exec ha-lan-host -- ping 8.8.8.8 &

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
- ha-lan-host traffic resumes after brief interruption
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
# 1. Create a long-lived session from ha-lan-host
incus exec ha-lan-host -- iperf3 -c <wan-target> -t 60 &

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
# Simulate WAN VF failure by detaching the SR-IOV device:
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
# Client on ha-lan-host:
incus exec ha-lan-host -- iperf3 -c <target> -P 4 -t 30 -C bbr
```

**Pass criteria:**
- Throughput > 1 Gbps through SNAT (generic XDP on iavf VF is the bottleneck)
- No packet loss during steady state
- Compare with/without HA overhead

### TC-9: DHCP Server on reth1

**Objective:** Verify ha-lan-host can obtain an address via DHCP from the primary.

```bash
incus exec ha-lan-host -- dhclient eth1
incus exec ha-lan-host -- ip addr show eth1
```

**Pass criteria:**
- Lease obtained from 10.0.60.100-199 range
- Gateway set to 10.0.60.1 (reth1 VIP)

### TC-10: Split-Brain Prevention

**Objective:** Verify cluster handles heartbeat network failure gracefully.

```bash
# Disconnect heartbeat bridge (simulates network partition)
incus network detach bpfrx-ha-heartbeat bpfrx-fw1 eth1

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

## Performance Expectations

| Metric | Expected | Notes |
|--------|----------|-------|
| WAN throughput (per VF) | ~6-8 Gbps | iavf generic XDP, single direction |
| LAN throughput (virtio) | ~12-15 Gbps | virtio_net native XDP |
| Failover time | < 5 seconds | 3 missed heartbeats @ 1s interval |
| Session sync latency | < 2 seconds | Ring buffer real-time + 1s sweep |
| Config sync latency | < 1 second | TCP immediate push on commit |

## SR-IOV Notes

- `eno6np1` (i40e) has 32 VFs; this setup uses 2, leaving 30 for other uses
- VFs use `iavf` driver inside VMs — **no native XDP**, only generic/SKB mode
- `redirect_capable` map in BPF marks VF interfaces as non-redirectable
- VF interfaces fall back to `XDP_PASS` (kernel forwarding) instead of `bpf_redirect_map`
- WAN throughput is lower than LAN (virtio native XDP) due to generic mode overhead
- Spoof checking is ON by default on VFs — may need to be disabled for RETH MAC changes:
  ```bash
  ip link set eno6np1 vf <N> spoofchk off
  ```
