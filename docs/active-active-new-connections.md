# Active/Active Per-RG: New Connection Support

## Problem

In active/active HA (per-RG split), **existing** TCP connections survive when
RG1 (WAN) moves to fw1 while RG2 (LAN) stays on fw0. However, **new**
connections fail with "no route to host".

### Root Cause — Two Interacting Failures

#### Forward path (SYN: LAN host → internet via fw0)

On fw0 (LAN active, WAN inactive):
1. SYN arrives on LAN interface (RG2, locally active) — zone lookup succeeds
2. No session exists (new connection) — previous code skipped fabric redirect
3. `bpf_fib_lookup` for internet dst **fails** — RETH VIP removed when RG1
   moved, connected route gone, default route withdrawn by FRR
4. FIB failure handler tries `try_fabric_redirect()` — packet reaches fw1
5. **BUT** on fw1: packet arrives on fabric → zone = "control" (fab0) →
   policy uses control→wan → no matching policy → **DROP**

The receiving node has no way to know the packet's *original* ingress zone.

#### Return path (SYN-ACK: server → LAN host via fw1)

On fw1 (WAN active, LAN inactive):
1. SYN-ACK arrives on WAN (RG1, locally active)
2. No synced session yet (sync sweep is 1s, SYN-ACK arrives in ~50ms)
3. `bpf_fib_lookup` for LAN host — LAN connected route gone, but **default
   route** still exists → routes packet back out WAN → **lost**

## Solution

### Part 1: Zone-Encoded Fabric Redirect (BPF)

Encode the original ingress zone in the source MAC when sending new connections
across fabric.  The source MAC is set to `02:bf:72:fe:00:ZZ` where ZZ is the
zone ID (`FABRIC_ZONE_MAC_MAGIC = 0xfe`).

**Why MAC encoding instead of VLAN tags:** Linux bridges strip 802.1Q VLAN
tags into `skb->vlan_tci` before generic XDP runs, making VLAN-encoded zones
invisible to the BPF program.  MAC-based encoding uses plain Ethernet frames
that traverse bridges without any stripping or filtering issues.

**Sender** (`try_fabric_redirect_with_zone()` in `bpfrx_helpers.h`):
- Set source MAC to `{0x02, 0xbf, 0x72, 0xfe, 0x00, ingress_zone}`
- Set dest MAC to fabric peer, redirect via fabric

**Receiver** (xdp_zone.c zone detection):
- If source MAC matches `02:bf:72:fe:??:ZZ` AND packet arrived on fabric:
  - Override `ingress_zone = h_source[5]`
  - Skip normal zone lookup, continue through full pipeline with correct zone

**Routing table override:** Zone-decoded packets on fabric force
`meta->routing_table = 254` (RT_TABLE_MAIN) because the fabric interface
is in vrf-mgmt, and `bpf_fib_lookup` would otherwise search the wrong table.

**Wire points in xdp_zone.c:**
- Post-FIB RG check: new connections (no session) use zone-encoded redirect
- FIB UNREACHABLE/BLACKHOLE/PROHIBIT: zone-encoded redirect first, then plain
- FIB NO_NEIGH: plain `try_fabric_redirect()` only (route exists, just no ARP)

Existing sessions continue using plain `try_fabric_redirect()` — the peer
has the synced session with zone info.

### Part 2: Return Path — Hairpin Detection

When an RG becomes BACKUP, its RETH VIP is removed and the connected route
disappears. Return traffic for those subnets hits the default route and FIB
routes the packet back out the same interface it arrived on (hairpin).

The existing hairpin detection in xdp_zone.c catches this: when
`fwd_ifindex == ingress_ifindex` for an existing session, it tries
`try_fabric_redirect()` to send the packet to the peer that has the correct
connected route. This works for new connections too, because the SYN creates
a session on the peer, so the SYN-ACK return traffic matches the session and
triggers hairpin detection.

**Note:** Blackhole routes were initially considered but rejected — they
break the `META_FLAG_KERNEL_ROUTE` → `XDP_PASS` fallback path because the
kernel's ip rule evaluation hits the blackhole in the main table before
checking cross-VRF rules.

## Files Modified

| File | Change |
|------|--------|
| `bpf/headers/bpfrx_common.h` | `FABRIC_ZONE_MAC_MAGIC 0xfe` constant |
| `bpf/headers/bpfrx_helpers.h` | `try_fabric_redirect_with_zone()` MAC encoding |
| `bpf/xdp/xdp_zone.c` | Zone-encoded MAC detection + zone-aware redirects |
| `pkg/daemon/daemon.go` | (no changes needed — hairpin detection handles return path) |
| `test/incus/test-active-active.sh` | New-connection test phases (iperf3 + ping) |
| `dpdk_worker/shared_mem.h` | `FABRIC_ZONE_MAC_MAGIC` constant (parity) |
| `dpdk_worker/zone.c` | Zone-encoded MAC detection stub (TODO) |

## Verification

1. `make generate && make build` — BPF + Go compile
2. `make test` — all unit tests pass
3. `make cluster-deploy` — deploy to both VMs
4. `make test-active-active` — new Phases 3b/3c verify new connections
5. `make test-failover` — existing failover tests still pass
