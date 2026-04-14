# Consistent RETH MAC Addresses

## Problem

In the HA cluster, RETH interfaces use VRRP on physical member interfaces (no bond devices). Each node has a different physical MAC on its RETH member interface, causing problems during failover:

1. **IPv6 link-local addresses differ** -- EUI-64 link-local (`fe80::...`) is derived from MAC. After failover, the new primary has a different link-local address, breaking neighbor caches on LAN hosts.
2. **Neighbor cache invalidation** -- Clients must update both VIP->MAC and gateway link-local->MAC mappings. Unsolicited NA only covers the VIP.
3. **`bpf_fib_lookup` smac** -- XDP forwarding uses `fib.smac` from the kernel. Different MACs mean forwarded packets have different source MACs after failover.

## Solution

Program a deterministic virtual MAC on RETH physical member interfaces at daemon startup. Both nodes present the same MAC for each RETH, making IPv6 link-local addresses identical and eliminating neighbor cache issues.

## MAC Format

```
02:bf:72:CC:RR:00
```

| Byte | Value | Meaning |
|------|-------|---------|
| 0 | `02` | Locally-administered unicast (U/L bit set) |
| 1 | `bf` | xpf identifier |
| 2 | `72` | ASCII 'r' (bpf**r**x) |
| 3 | `CC` | cluster_id (from config) |
| 4 | `RR` | redundancy_group_id |
| 5 | `00` | Reserved |

Example for cluster_id=1:
- reth0 (RG1): `02:bf:72:01:01:00` -> link-local `fe80::bf:72ff:fe01:100`
- reth1 (RG2): `02:bf:72:01:02:00` -> link-local `fe80::bf:72ff:fe01:200`

## Ordering

1. **`.link` files** (udev/networkd) -- match physical MAC for interface rename (e.g. enp6s0 -> ge-0-0-0)
2. **`networkctl reload`** -- applies the rename
3. **Virtual MAC** -- `netlink.LinkSetHardwareAddr()` programs the deterministic MAC
4. **VRRP `UpdateInstances()`** -- picks up new MAC via `net.InterfaceByName()`
5. **GARP/NA** -- automatically use the kernel MAC (called at send time)
6. **`bpf_fib_lookup`** -- automatically returns new MAC as `fib.smac`

## Reboot Safety

- Bootstrap `.link` files (from `setup.sh`) use the physical MAC for udev rename
- After daemon programs the virtual MAC, the kernel MAC changes
- On next `applyConfig()`, if the kernel MAC is a virtual RETH MAC (`02:bf:72:...`), the compiler skips writing a `.link` file for that interface
- This preserves the bootstrap `.link` file with the physical MAC
- On reboot, udev matches the physical MAC (NIC resets to factory MAC) and renames correctly
- Daemon starts and re-programs the virtual MAC

## Implementation

| File | Function |
|------|----------|
| `pkg/cluster/reth.go` | `RethMAC(clusterID, rgID)` -- returns deterministic MAC |
| `pkg/cluster/reth.go` | `IsVirtualRethMAC(mac)` -- detects virtual RETH pattern |
| `pkg/daemon/daemon.go` | `programRethMAC()` -- sets MAC via netlink (step 2.6 in applyConfig) |
| `pkg/dataplane/compiler.go` | Skips `.link` file when RETH member has virtual MAC |

## Impact

- **XDP forwarding**: `bpf_fib_lookup` automatically returns the virtual MAC as `fib.smac` -- no BPF changes needed
- **GARP/NA**: `net.InterfaceByName()` returns the virtual MAC -- no code changes needed
- **VRRP**: advertisements use the virtual MAC -- neighbor caches stay valid across failover
- **IPv6 link-local**: both nodes derive the same `fe80::bf:72ff:fe01:RR00` -- seamless failover
