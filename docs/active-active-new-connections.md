# Active/Active Per-RG: New Connection Support

Commit `83c9333`. Builds on AA-1 (`23f1a3d`) which solved existing connections.

## Problem

In active/active HA (per-RG split), **existing** TCP connections survive when
RG1 (WAN) moves to fw1 while RG2 (LAN) stays on fw0 — the AA-1 sprint solved
this with per-RG active state tracking in BPF.

However, **new** connections fail. A fresh `ping` or TCP handshake from the LAN
host cannot reach the internet through the split cluster.

## Topology During Split

```
                    ┌─────────────────┐
                    │   WAN Router    │
                    │  172.16.50.1    │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────┴─────────┐       ┌───────────┴───────────┐
    │      fw0          │       │        fw1            │
    │                   │       │                       │
    │  ge-0-0-1.50      │       │  ge-7-0-1.50          │
    │  (WAN — BACKUP)   │       │  (WAN — MASTER)       │
    │  RG1 inactive     │       │  RG1 active           │
    │                   │ fab0  │                       │
    │  ─────────────────├───────┤─────────────────────  │
    │  10.99.1.1        │       │  10.99.1.2            │
    │  (vrf-mgmt)       │       │  (vrf-mgmt)           │
    │                   │       │                       │
    │  ge-0-0-0         │       │  ge-7-0-0             │
    │  (LAN — MASTER)   │       │  (LAN — BACKUP)       │
    │  RG2 active       │       │  RG2 inactive         │
    └─────────┬─────────┘       └───────────┬───────────┘
              │                             │
              └──────────────┬──────────────┘
                             │
                    ┌────────┴────────┐
                    │  LAN Hosts      │
                    │  10.0.60.0/24   │
                    │  VIP: 10.0.60.1 │
                    └─────────────────┘
```

Key: RG1 (WAN) is on fw1, RG2 (LAN) is on fw0. Traffic from LAN to internet
must cross the fabric link between fw0 and fw1.

## Root Cause Analysis

### Forward path failure (SYN: LAN host → internet via fw0)

On fw0 (LAN active, WAN inactive):

1. SYN arrives on LAN interface (RG2, locally active) — zone lookup succeeds
   (ingress_zone = lan).

2. No session exists (new connection). AA-1 code only fabric-redirected
   **existing sessions** when the egress RG was inactive. New connections fell
   through to FIB lookup.

3. `bpf_fib_lookup` for internet destination (e.g., 172.16.100.200):
   - WAN RETH VIP (172.16.50.6) was removed when RG1 moved to fw1
   - Connected route to 172.16.50.0/24 is gone
   - Next-hop 172.16.50.1 becomes unreachable in FRR's RIB
   - FRR **withdraws the default route** (`default via 172.16.50.1`)
   - Without any default route, FIB returns `BPF_FIB_LKUP_RET_NOT_FWDED` (rc=4)

4. FIB failure handler: the `NOT_FWDED` code path is for locally-destined
   traffic (heartbeat, control plane). It does NOT try fabric redirect — the
   packet falls through to `XDP_PASS` for local delivery. But this is transit
   traffic, not local. It gets dropped by the kernel (no route).

   **Root cause #1:** FIB returns `NOT_FWDED` instead of `BLACKHOLE` because
   there's no blackhole catch-all route when the real default is withdrawn.

5. Even if FIB returned BLACKHOLE and the failure handler fired
   `try_fabric_redirect()`, the peer (fw1) would receive the packet on fab0.
   fab0 is in the "control" security zone. fw1's zone-based policy would use
   **control→wan** (not lan→wan), and there's no matching policy — **DROP**.

   **Root cause #2:** The receiving node uses fab0's zone ("control") instead
   of the original ingress zone ("lan").

### Return path failure (SYN-ACK: server → LAN host via fw1)

On fw1 (WAN active, LAN inactive):

1. SYN-ACK arrives on WAN (RG1, locally active) — zone lookup succeeds.

2. No synced session yet — session sync sweep runs at 1-second intervals, but
   SYN-ACK arrives in ~50ms after the SYN.

3. `bpf_fib_lookup` for LAN host (10.0.60.102):
   - LAN connected route (10.0.60.0/24) is gone because RG2 VIP was removed
   - But the **default route still exists** (fw1's WAN is active, default via
     172.16.50.1 works)
   - FIB returns **SUCCESS** with egress = WAN interface

4. Packet is routed back out the WAN interface (hairpin) → escapes to the
   internet → **lost**.

   **Root cause #3:** No blackhole route for the LAN subnet on fw1, so return
   traffic for LAN destinations matches the default route instead of being
   fabric-redirected.

### SNAT reverse path complication

Even when fabric redirect succeeds for return traffic with existing sessions,
a subtle NAT ordering bug caused failures:

1. SNAT reply arrives at fw1's WAN (dst = SNAT VIP, e.g. 172.16.50.6).

2. **Pre-routing NAT** (`dnat_table` lookup at `xdp_zone.c:289-311`) rewrites
   `meta->dst_ip` from SNAT VIP to original client IP (10.0.60.102). This is
   how SNAT reply matching works — the `dnat_table` entry maps
   `(proto, SNAT_IP, SNAT_port) → (original_client_IP, original_port)`.

   **Critical:** This only rewrites the **meta field**, not the actual packet
   header. The packet still contains dst = SNAT VIP.

3. Session lookup succeeds (using the meta-rewritten original client IP).

4. `bpf_fib_lookup` for 10.0.60.102 hits BLACKHOLE (injected route).

5. **BUG:** The BLACKHOLE handler immediately called `try_fabric_redirect()`.
   The packet is sent to the peer with **unrewritten headers** (dst = SNAT VIP).
   The peer can't reverse the SNAT because the `dnat_table` entry only exists
   on the originating node.

   **Root cause #4:** BLACKHOLE handler must not fabric-redirect when a session
   exists. The packet needs NAT reversal first via the
   conntrack→NAT→forward pipeline.

### VRF routing table mismatch for fabric traffic

`fab0` is in VRF mgmt (routing table 999). VRF mgmt has its own default route
(`default via 10.0.100.1 dev fxp0`). When a packet arrives on fab0 via plain
fabric redirect (`META_FLAG_FABRIC_FWD`):

1. Without a session, the routing table override to 254 (main table) doesn't
   fire — the override is guarded by session presence.

2. `bpf_fib_lookup` uses VRF mgmt table 999, which has a default route.

3. FIB returns **SUCCESS** with egress = `fxp0` (management interface). This is
   the **wrong egress** — the packet should go to a data-plane interface.

4. Additionally, `bpf_fib_lookup` with `BPF_FIB_LOOKUP_TBID` set to 254 (main
   table) **still honors l3mdev rules** when `fib.ifindex` belongs to a VRF.
   The lookup hits the VRF table instead of the requested table.

   **Root cause #5:** Must use a non-VRF `fib.ifindex` for main table lookups.

## Solution: Three-Part Fix

### Part 1: Zone-Encoded Fabric Redirect (BPF)

When a new connection arrives on one node but the egress RG is on the peer,
encode the original ingress zone in the source MAC before fabric redirect.

#### Why MAC encoding, not VLAN tags

Initial implementation used VLAN tags (`FABRIC_ZONE_VLAN_BASE + zone_id`).
This failed because Linux bridges strip 802.1Q VLAN tags into `skb->vlan_tci`
before generic XDP runs. The BPF program never sees the VLAN tag — it's already
been consumed by the bridge layer. MAC-based encoding uses plain Ethernet frames
that traverse bridges without any stripping or filtering issues.

#### Sender: `try_fabric_redirect_with_zone()` (`xpf_helpers.h:1887-1916`)

```c
static __always_inline int
try_fabric_redirect_with_zone(struct xdp_md *ctx, struct pkt_meta *meta)
{
    struct fabric_fwd_info *ff = bpf_map_lookup_elem(&fabric_fwd, &zero);
    if (!ff || ff->ifindex == 0) return -1;
    if (ctx->ingress_ifindex == ff->ifindex) return -1;  /* anti-loop */

    /* Encode ingress zone in source MAC: 02:bf:72:fe:00:ZZ */
    eth->h_source[0] = 0x02;
    eth->h_source[1] = 0xbf;
    eth->h_source[2] = 0x72;
    eth->h_source[3] = FABRIC_ZONE_MAC_MAGIC;  /* 0xfe */
    eth->h_source[4] = 0x00;
    eth->h_source[5] = (__u8)(meta->ingress_zone & 0xff);
    __builtin_memcpy(eth->h_dest, ff->peer_mac, ETH_ALEN);

    return bpf_redirect_map(&tx_ports, ff->ifindex, 0);
}
```

The magic MAC prefix `02:bf:72:fe` uses a locally-administered unicast bit
(`02:` prefix) so it won't collide with real MACs. `FABRIC_ZONE_MAC_MAGIC`
(`0xfe`) in byte[3] distinguishes zone-encoded packets from plain fabric
redirects.

#### Receiver: Zone-encoded MAC detection (`xdp_zone.c:213-240`)

Before the normal zone lookup, xdp_zone checks for the magic MAC prefix:

```c
if (zeth->h_source[0] == 0x02 &&
    zeth->h_source[1] == 0xbf &&
    zeth->h_source[2] == 0x72 &&
    zeth->h_source[3] == FABRIC_ZONE_MAC_MAGIC) {
    if (ff && ctx->ingress_ifindex == ff->ifindex) {
        meta->ingress_zone = zeth->h_source[5];
        meta->routing_table = 254;  /* RT_TABLE_MAIN */
        goto zone_resolved;
    }
}
```

Zone-encoded packets:
- Skip `iface_zone_map` lookup (zone already decoded from MAC)
- Force `routing_table = 254` (main table, not VRF mgmt)
- Go through the **full pipeline** (pre-routing NAT, FIB, conntrack, policy,
  NAT, forward) with the correct ingress zone
- Do NOT set `META_FLAG_FABRIC_FWD` — they're treated as regular ingress traffic
  with an overridden zone

#### Wire points in xdp_zone.c

| Location | Trigger | Action |
|----------|---------|--------|
| RG check (line 651-662) | FIB SUCCESS, egress RG inactive, no session | `try_fabric_redirect_with_zone()` |
| BLACKHOLE handler (line 860-873) | FIB UNREACHABLE/BLACKHOLE/PROHIBIT, no session | `try_fabric_redirect_with_zone()` then plain fallback |

Existing sessions use plain `try_fabric_redirect()` — the peer has the synced
session and knows the zones.

### Part 2: Blackhole Routes for Inactive RG Subnets (Go daemon + FRR)

#### Subnet blackhole routes (`daemon.go:3768-3830`)

When an RG goes BACKUP (VRRP), the daemon injects blackhole routes for each
RETH interface's subnet belonging to that RG:

```go
func (d *Daemon) injectBlackholeRoutes(rgID int) {
    for name, ifc := range cfg.Interfaces.Interfaces {
        if ifc.RedundancyGroup != rgID { continue }
        for _, unit := range ifc.Units {
            for _, addr := range unit.Addresses {
                _, ipNet, _ := net.ParseCIDR(addr)
                rt := netlink.Route{
                    Dst:      ipNet,
                    Type:     unix.RTN_BLACKHOLE,
                    Priority: 4242,
                }
                netlink.RouteAdd(&rt)
            }
        }
    }
}
```

These are kernel routes added directly via netlink (not FRR). Metric 4242
ensures the connected route (metric 0) takes priority when the VIP is present.
Routes are tracked in `d.blackholeRoutes[rgID]` and removed on VRRP MASTER
transition (`removeBlackholeRoutes`).

**Effect on fw1 (WAN active, LAN inactive):**
- `blackhole 10.0.60.0/24 metric 4242` is present
- Return traffic for 10.0.60.102 hits BLACKHOLE instead of the default route
- BPF BLACKHOLE handler triggers fabric redirect to fw0

**Effect on fw0 (LAN active, WAN inactive):**
- `blackhole 172.16.50.0/24 metric 4242` is present
- But fw0 also lost the WAN connected route, so this is belt-and-suspenders

#### FRR blackhole default route (`frr.go:331-339`)

When the WAN VIP moves to the peer and FRR withdraws the real default route
(next-hop unreachable), FIB returns `NOT_FWDED` (no route at all). The
`NOT_FWDED` code path is for locally-destined traffic and does not attempt
fabric redirect.

Fix: in cluster mode, FRR injects a blackhole default route with high
administrative distance (250):

```
ip route 0.0.0.0/0 Null0 250
ipv6 route ::/0 Null0 250
```

The real default route (static AD=5, or DHCP-learned AD=200) always takes
priority when present. When it's withdrawn, the blackhole default catches all
traffic and makes `bpf_fib_lookup` return `BPF_FIB_LKUP_RET_BLACKHOLE` instead
of `NOT_FWDED`. The BLACKHOLE handler then triggers zone-encoded fabric redirect.

### Part 3: BPF Pipeline Fixes

#### BLACKHOLE handler session guard (`xdp_zone.c:843-875`)

When an existing session is found AND FIB returns BLACKHOLE, skip the immediate
fabric redirect. The packet may have had pre-routing NAT applied (`dnat_table`
rewrote `meta->dst_ip` but NOT the packet header). It needs to go through the
full conntrack→NAT→forward pipeline for proper NAT reversal before being
fabric-redirected.

```c
if (rc == BPF_FIB_LKUP_RET_BLACKHOLE || ...) {
    volatile int bh_has_session = 0;
    if (sv4 != NULL) bh_has_session = 1;
    if (sv6 != NULL) bh_has_session = 1;
    if (!bh_has_session) {
        /* New connection: zone-encoded redirect */
        int fab_rc = try_fabric_redirect_with_zone(ctx, meta);
        if (fab_rc >= 0) return fab_rc;
        /* Plain redirect fallback */
        fab_rc = try_fabric_redirect(ctx, meta);
        if (fab_rc >= 0) return fab_rc;
    }
    /* Sessions fall through to conntrack → NAT → forward path */
}
```

After NAT reversal, `xdp_forward` re-checks FIB on the rewritten packet
and does fabric redirect with correct headers (see below).

Uses `volatile int` to prevent the compiler from merging pointer NULL checks
into `|=` on pointer registers, which the BPF verifier rejects.

#### xdp_forward FIB re-check (`xdp_forward.c:42-79`)

After NAT reversal in the `META_FLAG_KERNEL_ROUTE` path, re-check FIB on the
**current packet** (which now has NAT-reversed headers). If FIB returns
BLACKHOLE, the destination subnet belongs to an inactive RG on this node —
fabric-redirect to the peer which has the connected route.

```c
if (meta->meta_flags & META_FLAG_KERNEL_ROUTE) {
    struct bpf_fib_lookup fib = {};
    fib.family = meta->addr_family;
    /* Read addresses from actual packet headers (post-NAT) */
    fib.ipv4_src = iph_kr->saddr;
    fib.ipv4_dst = iph_kr->daddr;
    int kr_rc = bpf_fib_lookup(ctx, &fib, sizeof(fib),
                               BPF_FIB_LOOKUP_OUTPUT);
    if (kr_rc == BPF_FIB_LKUP_RET_BLACKHOLE || ...) {
        int fab_rc = try_fabric_redirect(ctx, meta);
        if (fab_rc >= 0) return fab_rc;
    }
    /* Normal kernel routing fallback */
    return XDP_PASS;
}
```

Uses `BPF_FIB_LOOKUP_OUTPUT` flag (no TBID) so the lookup uses the main table.
Uses plain `try_fabric_redirect()` (not zone-encoded) because the session
already exists on the peer (synced from the node that created it).

#### Two-pass FIB for sessionless FABRIC_FWD (`xdp_zone.c:732-788`)

When a packet arrives on fabric via plain redirect (`META_FLAG_FABRIC_FWD`) and
has no local session (e.g., return traffic not yet synced):

**Problem:** The first FIB lookup used VRF mgmt table 999 (because fab0 is a
VRF member and no session triggered the routing_table=254 override). VRF mgmt
has a default route via management network, so FIB returned SUCCESS with the
wrong egress (management interface instead of data-plane interface).

**Fix:** Re-do FIB in the main table (254) with a non-VRF ifindex:

```c
if (meta->meta_flags & META_FLAG_FABRIC_FWD) {
    struct bpf_fib_lookup fib2 = {};
    fib2.tbid = 254;  /* RT_TABLE_MAIN */
    fib2.ifindex = ff2->fib_ifindex;  /* non-VRF interface */
    /* ... populate src/dst from meta ... */
    int rc2 = bpf_fib_lookup(ctx, &fib2, sizeof(fib2),
                             BPF_FIB_LOOKUP_TBID);
    if (rc2 == BPF_FIB_LKUP_RET_SUCCESS) {
        /* Use result: correct data-plane egress */
        bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
    }
    /* FIB failed: fall through to XDP_PASS for kernel local delivery */
    return XDP_PASS;
}
```

This only fires for FABRIC_FWD (plain redirect) traffic without sessions.
Zone-encoded packets do NOT set FABRIC_FWD — they go through the full pipeline.

Locally-destined fabric traffic (heartbeat, session sync) gets `NOT_FWDED` from
the first FIB lookup (VRF mgmt table) and enters the `else` block, bypassing
this handler entirely.

#### fabric_fwd_info.fib_ifindex (`daemon.go:3556-3576`)

`bpf_fib_lookup` with `BPF_FIB_LOOKUP_TBID` still honors kernel l3mdev rules
when `fib.ifindex` belongs to a VRF. To look up the main table correctly, the
lookup needs a non-VRF interface index.

`populateFabricFwd()` discovers a non-VRF, non-loopback, UP interface and
stores its ifindex in the `fib_ifindex` field of the `fabric_fwd` BPF map.
BPF code uses this for all TBID=254 lookups where the ingress interface
is a VRF member.

#### FABRIC_FWD routing table override (`xdp_zone.c:541-555`)

For FABRIC_FWD traffic with a synced session, override `routing_table` from
VRF mgmt (999) to main (254). This must be **session-guarded** — unconditional
override breaks locally-destined fabric traffic because the main table may have
a default route that intercepts local addresses before `NOT_FWDED` fires.

```c
if (meta->meta_flags & META_FLAG_FABRIC_FWD) {
    if (sv4 != NULL) meta->routing_table = 254;
    if (sv6 != NULL) meta->routing_table = 254;
}
```

### Summary of Two Fabric Redirect Modes

| | Plain redirect | Zone-encoded redirect |
|---|---|---|
| **Helper** | `try_fabric_redirect()` | `try_fabric_redirect_with_zone()` |
| **MAC encoding** | Real local MAC as source | `02:bf:72:fe:00:ZZ` as source |
| **When used** | Existing sessions (peer has synced session) | New connections (peer needs zone info) |
| **Receiver flag** | `META_FLAG_FABRIC_FWD` | No flag (goes through full pipeline) |
| **Routing table** | Session-guarded override to 254 | Unconditional 254 (set in zone detection) |
| **Policy** | Bypassed (peer already validated) | Full evaluation (correct zone from MAC) |

## Packet Flow: New ICMP Ping During Split

```
cluster-lan-host (10.0.60.102) → ping 172.16.100.200

1. Echo request arrives at fw0 ge-0-0-0 (LAN, RG2 active)
   xdp_zone: zone=lan, no session, FIB for 172.16.100.200
   FIB: main table has blackhole default (AD=250) → BLACKHOLE
   BLACKHOLE handler: no session → try_fabric_redirect_with_zone()
   Source MAC = 02:bf:72:fe:00:02 (zone 2 = lan)
   → bpf_redirect_map to fab0 → wire → fw1

2. fw1 fab0 receives packet with magic MAC
   xdp_zone: detect 02:bf:72:fe, ingress_zone=2 (lan), routing_table=254
   Pre-routing NAT: no match
   Session lookup: no session
   FIB for 172.16.100.200 in main table: SUCCESS → ge-7-0-1.50 (WAN)
   Egress RG check: RG1 active on fw1 → proceed normally
   → conntrack → policy (lan→wan: allow) → NAT (SNAT) → forward → WAN

3. Echo reply arrives at fw1 ge-7-0-1.50 (WAN, RG1 active)
   xdp_zone: zone=wan, pre-routing NAT matches dnat_table (SNAT reverse)
   meta->dst_ip rewritten to 10.0.60.102 (original client)
   Session lookup: session found (created in step 2)
   FIB for 10.0.60.102: BLACKHOLE (blackhole 10.0.60.0/24 metric 4242)
   BLACKHOLE handler: session exists → skip fabric redirect
   → conntrack (session hit, NAT reversal) → NAT (rewrite packet headers)
   → forward (meta_flags & KERNEL_ROUTE)

4. xdp_forward on fw1: KERNEL_ROUTE path
   FIB re-check on actual packet (dst=10.0.60.102): BLACKHOLE
   → try_fabric_redirect() → wire → fw0

5. fw0 fab0 receives packet with FABRIC_FWD flag (plain redirect)
   xdp_zone: zone=control (fab0), META_FLAG_FABRIC_FWD set
   No session on fw0 (sync delay)
   FIB in VRF mgmt: SUCCESS (VRF default route → wrong egress)
   FABRIC_FWD handler: second FIB in main table (254)
   10.0.60.102 → SUCCESS → ge-0-0-0 (LAN, connected route)
   → tail-call xdp_forward → MAC rewrite → redirect to LAN

6. Echo reply delivered to cluster-lan-host (10.0.60.102)
```

## Files Modified

| File | Change |
|------|--------|
| `bpf/headers/xpf_common.h` | `META_FLAG_FABRIC_FWD (1<<4)`, `FABRIC_ZONE_MAC_MAGIC 0xfe` |
| `bpf/headers/xpf_helpers.h` | `try_fabric_redirect_with_zone()` — MAC-encoded zone redirect |
| `bpf/headers/xpf_maps.h` | `fabric_fwd_info.fib_ifindex` field for non-VRF FIB lookups |
| `bpf/xdp/xdp_zone.c` | Zone-encoded MAC detection, FABRIC_FWD flag, session-guarded routing_table override, RG check for new connections, BLACKHOLE session guard, two-pass FIB for sessionless FABRIC_FWD |
| `bpf/xdp/xdp_forward.c` | FIB re-check in KERNEL_ROUTE path — detect BLACKHOLE after NAT reversal |
| `pkg/daemon/daemon.go` | `injectBlackholeRoutes()` / `removeBlackholeRoutes()` on VRRP transitions, `fib_ifindex` population in `populateFabricFwd()` |
| `pkg/dataplane/types.go` | `FabricFwdInfo.FIBIfindex` field |
| `pkg/frr/frr.go` | Cluster mode blackhole default route (`ip route 0.0.0.0/0 Null0 250`) |
| `dpdk_worker/shared_mem.h` | `FABRIC_ZONE_MAC_MAGIC` constant (DPDK parity) |
| `dpdk_worker/zone.c` | Zone-encoded MAC detection placeholder (TODO: full DPDK implementation) |
| `test/incus/test-active-active.sh` | Phase 3b (TCP handshake via `/dev/tcp`) + Phase 3c (ICMP ping) during split |

## Key Design Decisions

### MAC encoding vs VLAN tags for zone transport

VLAN tags were the first approach (`FABRIC_ZONE_VLAN_BASE 4080`, VLANs
4080-4095 reserved for zone encoding). This failed in testing because the Linux
bridge connecting the two VMs strips 802.1Q tags into `skb->vlan_tci` before
the generic XDP program runs. The BPF program sees `meta->ingress_vlan_id = 0`
even though the sender pushed a VLAN tag.

MAC encoding is immune to this because Ethernet source/destination addresses are
never stripped or modified by bridges.

### Session guard on BLACKHOLE handler

Without the guard, SNAT return traffic gets fabric-redirected with unrewritten
packet headers. The `dnat_table` pre-routing NAT (xdp_zone.c:289-311) only
rewrites `meta->dst_ip`, not the actual IP header in the packet. NAT reversal
happens later in `xdp_nat`. If we fabric-redirect before NAT reversal, the peer
receives a packet with `dst = SNAT VIP` — it can't reverse the SNAT because the
`dnat_table` entry only exists on the originating node.

### Two-pass FIB vs unconditional routing table override

Unconditional `routing_table = 254` for all FABRIC_FWD traffic was tried first.
This broke locally-destined fabric traffic (heartbeat, session sync) because the
main table may have a default route or blackhole that matches before the kernel
detects the packet is locally destined. With VRF mgmt table, locally-destined
traffic correctly gets `NOT_FWDED`.

The two-pass approach: first FIB in VRF (catches NOT_FWDED for local addresses),
then second FIB in main table for transit traffic that got SUCCESS from VRF's
default route.

### bpf_fib_lookup TBID + VRF interaction

Even with `BPF_FIB_LOOKUP_TBID` flag and explicit `fib.tbid = 254`, the kernel
honors l3mdev rules when `fib.ifindex` belongs to a VRF device. The lookup
effectively ignores TBID and uses the VRF's table. Workaround: use
`fabric_fwd_info.fib_ifindex` (a non-VRF interface) for all TBID=254 lookups
where the natural ingress interface is a VRF member.

### Blackhole route metric (4242)

High metric ensures the connected route (metric 0, present when VIP is active)
always wins. When the VIP is removed and the connected route disappears, the
blackhole route is the only match for the subnet. On VRRP MASTER transition,
the daemon removes the blackhole route before the VIP is re-added, avoiding
any transient conflict.

### FRR blackhole default AD (250)

Must be higher than all real default routes: static (AD=5), DHCP-learned
(AD=200). Lower than nothing (withdrawn = absent). The blackhole default is
always present in cluster mode but never wins against a real default.

## Debugging Methodology

1. **Counter analysis:** `show security flow statistics` revealed host-inbound
   deny counts not increasing during fabric ping failure — packet dropped before
   reaching host-inbound check.

2. **tcpdump at wire level:** Confirmed ICMP echo requests not appearing on
   fw1's fab0 — packets never left fw0.

3. **Routing table inspection:** `ip route get 10.99.1.2` showed packets routed
   via WAN default route instead of fab0 — because fab0 is in VRF mgmt and the
   main table doesn't have the 10.99.1.0/30 route.

4. **bpf_printk tracing:** Added targeted prints in pre-routing NAT and FIB
   result handler to trace per-packet decisions. Discovered FIB returning
   SUCCESS with wrong egress (management interface) for FABRIC_FWD traffic.

5. **VRF routing analysis:** `ip route show table 999` revealed VRF mgmt has
   its own default route, causing FIB to match management-plane routes for
   data-plane traffic arriving on the VRF-member fabric interface.

## Test Coverage

```
make test              → all 22 packages pass
make test-connectivity → 25/25 PASS
make test-failover     → 14/14 PASS (existing sessions survive reboot + failback)
make test-active-active → 14/14 PASS:
  Phase 1:  Start iperf3 -P2 through firewall
  Phase 2:  Failover RG1 (WAN) to fw1 — active/active split
  Phase 3:  Existing iperf3 survives split (fabric forwarding)
  Phase 3b: NEW TCP connection through split cluster (TCP handshake via /dev/tcp)
  Phase 3c: NEW ICMP ping through split cluster
  Phase 4:  Failover RG1 back to fw0 — reunify all RGs
  Phase 5:  Existing iperf3 survives reunification
  Phase 6:  iperf3 completed with >1 Gbps throughput
```

## Bug: Failback Stream Death (rg_active Set Before Routing Ready)

### Symptom

After RG1 (WAN) failover to fw1 then failback to fw0, one of 4 parallel
iperf3 streams permanently drops to 0 bytes/s while the other 3 continue at
~1.7 Gbps. The dead stream shows cwnd collapsed to 1.41 KBytes (1 MSS) and
never recovers.

### Root Cause

The cluster event handler (`watchClusterEvents()`) set `rg_active=true`
**before** the VRRP MASTER event fired. This created a ~30-60ms window where
`rg_active=true` but blackhole routes still existed:

```
T=0ms:    Cluster Primary event → UpdateRGActive(1, true) + BumpFIBGeneration()
T=0-60ms: BLACKHOLE WINDOW — rg_active says "active" but routing broken
T=30-60ms: VRRP MASTER → becomeMaster() → removeBlackholeRoutes()
```

During this window, packets hitting the pre-FIB RG check saw `rg_active=true`
and proceeded to FIB lookup instead of fabric-redirecting. FIB returned
BLACKHOLE (routes not yet removed), so the BLACKHOLE handler sent the packet
through conntrack→NAT→forward. SNAT was applied (src rewritten to VIP), then
xdp_forward's KERNEL_ROUTE path did a re-FIB → BLACKHOLE → `try_fabric_redirect()`
to fw1. But the packet now had SNAT'd headers (src=172.16.50.10) that didn't
match any synced session on fw1 (synced sessions use the original 5-tuple).
The packet was dropped.

### Fix

In the cluster event handler, only set `rg_active=true` when VRRP is **already
MASTER** for that RG (`d.rethMasterState[rgID]` is true). This covers the
initial boot case (SecondaryHold→Primary, where VRRP self-elected before the
cluster formed). When VRRP is BACKUP (the failback case), defer `rg_active=true`
to the VRRP MASTER event handler, which fires **after** `becomeMaster()` has
added the VIP and `removeBlackholeRoutes()` has cleaned up routing. This ensures
packets continue to fabric-redirect (pre-NAT) until routing is fully ready.
Setting `rg_active=false` on Secondary transition remains immediate.

### Why Only One Stream Dies

All 4 streams lose packets during the ~30-60ms window. Most recover because
TCP RTO (~200ms) > window duration. But one stream's congestion window collapses
to 1 MSS, and with 3 other streams at full throughput competing for bandwidth,
the collapsed stream cannot reclaim capacity.

## Bug: SNAT'd Packets Leak to Kernel via KERNEL_ROUTE on Fabric Peer

### Symptom

Rapid repeated failover cycles (fw0→fw1→fw0→fw1...) permanently kill 2+
iperf3 streams. Streams show cwnd collapsed to 1 MSS, 0 bytes on receiver,
"Broken pipe". Single-cycle failovers work fine.

### Root Cause

During failback (e.g. RG1: fw1 → fw0), there's a ~30ms window where **both
nodes** have `rg_active[1]=false`:
- fw0: waiting for VRRP MASTER (deferred by the previous fix)
- fw1: cluster Secondary already set rg_active=false

When a fabric-forwarded packet's egress RG is inactive and anti-loop prevents
fabric redirect back, the code fell through to `META_FLAG_KERNEL_ROUTE`. This
caused SNAT'd packets to leak to the kernel:

1. Packet arrives at fw0 LAN → session found → RG inactive → fabric-redirect to fw1 (pre-NAT, good)
2. On fw1: FABRIC_FWD + session found → FIB for destination → RG inactive →
   try_fabric_redirect → ANTI-LOOP (came from fabric!) → falls through
3. KERNEL_ROUTE path: conntrack → NAT (SNAT applied!) → xdp_forward re-FIB on
   SNAT'd packet → uses fabric VRF context → FIB fails → try_fabric_redirect →
   ANTI-LOOP → XDP_PASS
4. Kernel receives SNAT'd packet in fabric VRF context → can't route → drops or
   forwards via stale route

**TCP damage per cycle:**
- Kernel drop: clean packet loss, TCP retransmits recover (OK in isolation)
- Kernel forward: duplicate data with different timing → duplicate ACKs → TCP
  fast recovery halves cwnd
- Kernel sees SNAT'd dst (local VIP + SNAT port), no socket → TCP RST → "Broken pipe"

Each failover cycle compounds the damage. After several cycles, some streams'
cwnd is permanently collapsed.

### Fix

Drop FABRIC_FWD packets cleanly instead of falling through to KERNEL_ROUTE.
The ~30ms failover window will close and TCP retransmits succeed (200ms RTO >
30ms window).

Three guard points in BPF:

1. **xdp_zone.c — Post-FIB RG check:** When `try_fabric_redirect()` returns -1
   (anti-loop) and `META_FLAG_FABRIC_FWD` is set, `return XDP_DROP` instead of
   setting `META_FLAG_KERNEL_ROUTE`

2. **xdp_zone.c — BLACKHOLE handler:** Before setting `META_FLAG_KERNEL_ROUTE`
   for sessions with BLACKHOLE FIB result, check `META_FLAG_FABRIC_FWD` and drop

3. **xdp_forward.c — KERNEL_ROUTE XDP_PASS fallback:** Belt-and-suspenders
   check before the final `XDP_PASS` in the KERNEL_ROUTE path

Additionally, `BumpFIBGeneration()` is now called on every cluster Primary
transition, not just when `rethMasterState` is true. This prevents sessions
from using stale cached FIB results during transitions.

## Bug: Fabric Transit Auto-Forward Used Wrong FIB Result

### Symptom

New TCP connections and ICMP ping during active/active split (Phase 3b/3c) fail.
SYN-ACKs never reach the LAN client. Sessions on fw1 show SYN_RECV (SYN-ACK
processed by conntrack) but the de-NAT'd packet is lost on fw0.

### Root Cause

The fabric transit auto-forward block (originally at xdp_zone.c line 710) was
intended to fast-path sessionless FABRIC_FWD packets by tail-calling directly
to XDP_PROG_FORWARD after the initial FIB lookup. But this auto-forward used
the **initial FIB result**, which was wrong:

1. Packet arrives on fw0 from fabric (`META_FLAG_FABRIC_FWD` set).
2. No synced session yet (`sv4 == NULL`) — routing_table stays 0 (the
   `routing_table = 254` override at line 624-629 requires a session).
3. Initial FIB lookup uses `fib.ifindex = ctx->ingress_ifindex` (fabric
   interface, in vrf-mgmt) with `fib_flags = 0` (no `BPF_FIB_LOOKUP_TBID`).
4. Kernel uses vrf-mgmt's routing table (not main table).
5. vrf-mgmt has a DHCP-learned default route → FIB returns **SUCCESS** with
   egress = management interface (`fxp0`).
6. Auto-forward fires: `FABRIC_FWD + sv4==NULL → bpf_tail_call(XDP_FORWARD)`.
7. xdp_forward redirects packet to management interface → **lost**.

The correct re-FIB (at line 839) — which uses `BPF_FIB_LOOKUP_TBID` with
table 254 and a non-VRF ifindex — was never reached because the auto-forward
short-circuited it with a tail call.

### Fix

Remove the auto-forward block and let the code fall through to the re-FIB
at line 839, which correctly does a second FIB lookup in the main table (254)
using `fabric_fwd_info.fib_ifindex` (a non-VRF interface). This was already
the code that the auto-forward was supposed to be an optimization of, but the
auto-forward used the wrong (initial) FIB result instead of doing its own
correct lookup.

The packet flow now:
1. Initial FIB returns SUCCESS (vrf-mgmt default route, wrong egress)
2. No auto-forward (removed)
3. Post-FIB RG check: skipped (no session)
4. Hairpin detection: skipped (no session)
5. FIB cache update: skipped (no session)
6. FABRIC_FWD re-FIB in table 254: SUCCESS → correct egress (LAN interface)
7. `bpf_tail_call(XDP_FORWARD)` with correct MAC/ifindex

Added egress zone resolution to both re-FIB blocks (FIB SUCCESS path and
UNREACHABLE handler) for correct zone egress counters.

## Bug: TCP Stream Death from Blind RST→CLOSED in Conntrack

### Symptom

During long-duration high-throughput transfers (iperf3 -P4 -t1200 at ~9 Gbps),
individual TCP streams die one by one over time. Dead streams show:

- cwnd collapsed to 1.41 KBytes (1 MSS)
- RTO escalating exponentially: 204→3264→13056→26112→52224→104448→120000ms
- `bytes_sent` frozen — zero forward progress
- Sessions remain "Established" in `show security flow session` but carry zero traffic
- Drop counter increases at ~6 drops/sec matching retransmit rate of dead streams

Observed stream death times: [5] at t=130s, [7] at t=176s, [11] at t=366s,
[9] at t=435s — each after transferring ~50-200 GB.

### Root Cause

Three interacting bugs in the BPF conntrack TCP state machine:

**1. Blind RST→CLOSED transition** (`xpf_conntrack.h:ct_tcp_update_state`)

```c
if (rst) return SESS_STATE_CLOSED;
```

Any RST packet transitions the session to CLOSED immediately, with no TCP
sequence number validation. At 10 Gbps, the TCP sequence number space wraps
every ~23 seconds. Spurious RSTs are inevitable from:
- Packet corruption (bit flip sets RST flag)
- Out-of-window segment responses from the server
- Middlebox interference

**2. CLOSED state drops all data** (`xdp_conntrack.c:handle_ct_hit_v4:118-131`)

```c
case SESS_STATE_CLOSED:
    if (meta->tcp_flags & 0x04) {  /* RST */
        bpf_tail_call(ctx, &xdp_progs, next_prog);
        return XDP_PASS;
    }
    /* SESSION_CLOSE event, then: */
    return XDP_DROP;  /* Drop ALL non-RST packets */
```

Once a session enters CLOSED, every data packet (SYN, ACK, PSH+ACK) is
silently dropped. Only RST packets are forwarded.

**3. last_seen update prevents GC cleanup**

```c
sess->last_seen = now;  /* Updated BEFORE state check */
```

`last_seen` was updated unconditionally at the top of `handle_ct_hit_v4/v6`,
before any state checks. Client retransmits (which are dropped by the CLOSED
handler) still refresh `last_seen`, preventing the GC sweep from ever expiring
the session. The CLOSED session persists indefinitely.

### Death Spiral

```
Normal traffic at 9 Gbps
    │
    ▼
Spurious RST (1 in ~50 billion packets)
    │
    ▼  ct_tcp_update_state: rst → SESS_STATE_CLOSED
    │
    ▼  handle_ct_hit: CLOSED → XDP_DROP all data
    │
    ▼  Client TCP: no ACKs → RTO doubles each retry
    │    200ms → 400ms → 800ms → ... → 120s (max)
    │
    ▼  Client retransmits hit conntrack → last_seen refreshed
    │    GC never expires session (last_seen always recent)
    │
    ▼  Stream permanently dead
       cwnd = 1 MSS, RTO = 120s, bytes_sent frozen
       Session stuck in CLOSED forever
```

### Why Only at High Throughput

At 10 Gbps with 1500-byte packets, the firewall processes ~830K packets/sec.
TCP sequence space is 2³² = 4.3 billion bytes, wrapping every ~23 seconds at
1.5 Gbps per stream. High packet rates increase the probability of:
- NIC/memory bit flips creating RST flags
- Kernel-generated RSTs for out-of-window segments
- Retransmit/reordering causing endpoint RST responses

At lower throughputs (<1 Gbps), the probability per-stream is negligible and
streams survive for hours.

### Fix

**XDP conntrack** (`xdp_conntrack.c:handle_ct_hit_v4/v6`):

1. Suppress RST→CLOSED for ESTABLISHED sessions. Forward the RST to endpoints
   (they can decide to close), but keep the firewall session ESTABLISHED:

```c
if (new_state == SESS_STATE_CLOSED &&
    sess->state == SESS_STATE_ESTABLISHED) {
    __u32 z = 0;
    struct flow_config *fc =
        bpf_map_lookup_elem(&flow_config_map, &z);
    if (!fc || !(fc->tcp_flags & FLOW_TCP_RST_INVALIDATE))
        new_state = sess->state;
}
```

The `rst-invalidate-session` config flag (`FLOW_TCP_RST_INVALIDATE`) overrides
for users who want strict RST handling — this is the only way RST→CLOSED fires
for ESTABLISHED sessions.

2. Guard `last_seen` with CLOSED check to break the GC bypass:

```c
if (sess->state != SESS_STATE_CLOSED)
    sess->last_seen = now;
```

**TC conntrack** (`tc_conntrack.c:tc_ct_hit_v4/v6`):

Same `last_seen` guard. TC doesn't do TCP state tracking or CLOSED drops, but
the guard prevents egress retransmits from resetting the GC timer.

**DPDK conntrack** (`dpdk_worker/conntrack.c`):

Same pattern at all 4 hit paths (v4 forward, v4 reverse, v6 forward, v6
reverse): suppress RST→CLOSED for ESTABLISHED + guard `last_seen`.

### Design Rationale

**Why suppress instead of sequence validation?** BPF conntrack doesn't track
TCP sequence numbers (would require ~8 more bytes per session entry plus
window tracking logic). Suppressing RST→CLOSED for ESTABLISHED is simple, safe,
and matches real-world firewall behavior — most stateful firewalls don't
immediately kill sessions on RST without sequence validation.

**Why forward the RST?** The RST still reaches both endpoints. If it's a
legitimate RST (endpoint intentionally closed), both sides see it and perform
graceful shutdown. The FIN→FIN_WAIT→TIME_WAIT path handles normal TCP
termination. Only the RST→CLOSED shortcut is blocked.

**Why keep rst-invalidate-session?** Some deployments want strict RST handling
(e.g., active session tear-down for security). The config option preserves this
capability for users who opt in, accepting the stream-death risk.

### Verification

```
make test                → all unit tests pass
make test-active-active  → 14/14 PASS (8 streams, 9.13 Gbps)
make test-failover       → 14/14 PASS (8 streams, 7.77 Gbps)
```

Long-duration test: `iperf3 -P4 -t600` completed at 9.08 Gbps with zero
stream deaths (previously streams died within 200-400 seconds).

## Bug: Dual-Inactive Transition Window During Manual Failover

### Symptom

Rapid repeated failover cycles (fw0→fw1→fw0→fw1...) permanently kill 2+ of 8
iperf3 streams. Dead streams show cwnd collapsed to 1 MSS, RTO escalating to
120s, "Broken pipe". Single-cycle failovers survived, but repeated cycles
compounded damage.

### Root Cause

During manual failover (e.g., RG1: node0 → node1), there was a ~25ms window
where **both** nodes had `rg_active[1]=false`:

```
T=0ms:    node0 receives cluster Secondary event
          → immediately sets rg_active[1]=false
T=0ms:    node1 receives cluster Primary event
          → defers rg_active[1]=true until VRRP MASTER (previous fix)
T=0-25ms: DUAL-INACTIVE WINDOW — both nodes drop RG1 traffic
T=~25ms:  node1 VRRP MASTER fires → sets rg_active[1]=true
```

At ~750K pps per stream × 8 streams, 25ms = ~150K dropped packets. TCP BBR
congestion control interprets this as severe congestion → cwnd collapse → RTO
growth. Healthy streams competing for bandwidth prevent collapsed streams from
ever recovering.

### Additional Contributing Factors

**zone_ct_update RST→CLOSED (primary code path):** The fast-path FIB cache hit
in `xdp_zone.c` (`zone_ct_update_v4/v6`) was the PRIMARY code path for
established sessions. This function updated TCP state including RST→CLOSED but
lacked the `rst-invalidate-session` guard added to `xdp_conntrack.c`. A single
spurious RST during the transition window permanently killed the stream even
after the window closed.

**Fabric txqueuelen drops:** The virtio-net fabric interface has a max 256-entry
TX ring. Under bidirectional active/active load at ~10 Gbps, `bpf_redirect_map`
drops exceeded 1.7%. Increasing `txqueuelen` from 1000 to 10000 eliminates
these drops.

### Fix: Eliminate the Dual-Inactive Window

Replace the traffic-killing dual-inactive gap with a brief benign dual-active
overlap (~5ms where both nodes forward):

**1. Cluster Primary transition (`daemon.go`):**
Set `rg_active=true` immediately + call `removeBlackholeRoutes()`. Don't wait
for VRRP MASTER. The incoming node starts forwarding as soon as it knows it's
primary, even before VRRP has converged. During the brief overlap, both nodes
can forward — this is safe because sessions are synced.

**2. Cluster Secondary transition (`daemon.go`):**
Defer `rg_active=false` if VRRP is still MASTER for that RG
(`rethMasterState[rgID]`). Let the VRRP BACKUP event handle deactivation instead
of immediately setting inactive on Secondary. This prevents the old node from
dropping traffic before the new node is ready.

**3. zone_ct_update RST guard (`xdp_zone.c`):**
Add `rst-invalidate-session` check to `zone_ct_update_v4()` and
`zone_ct_update_v6()` — same guard as `xdp_conntrack.c`. Prevents spurious RSTs
during transition from permanently killing streams.

**4. Fabric txqueuelen (`daemon.go` or setup script):**
Set fabric interface `txqueuelen=10000` to handle burst redirects during
transitions.

### Why Dual-Active Overlap Is Safe

During the ~5ms overlap:
- Both nodes have `rg_active=true` for the transitioning RG
- Both can process packets for that RG
- Synced sessions exist on both nodes
- Worst case: duplicate processing of a few packets (TCP handles duplicates)
- No SNAT mismatch: both nodes have the same SNAT VIP in synced sessions

This is strictly better than the dual-inactive window where ALL packets are
dropped.

### Mixed XDP Mode (Attempted and Reverted)

Per-interface native/generic XDP attachment was attempted to improve fabric
throughput. This failed because TC egress BPF programs interfere with
XDP_PASS'd packets — TC conntrack reverses the SNAT on packets that were
supposed to be forwarded transparently.

## References

- AA-1 sprint: `23f1a3d` — Per-RG active state tracking in BPF
- Fabric cross-chassis forwarding: `docs/fabric-cross-chassis-fwd.md`
- Pre-routing NAT (dnat_table): `xdp_zone.c:284-340`
- Session sync protocol: `docs/sync-protocol.md`
