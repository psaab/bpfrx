# Private RG Mastership Protocol: Replacing VRRP on Data-Plane Interfaces

## Problem Statement

VRRP on RETH interfaces floods every LAN segment with multicast traffic:

- **IPv4:** `224.0.0.18` (protocol 112) every 30ms per RETH member interface
- **IPv6:** `ff02::12` (protocol 112) every 30ms per RETH member interface
- 2 RGs × 2 interfaces (parent + VLAN) = **4 instances × 33 pkt/s = ~132 multicast pkt/s** on each LAN segment

Every host on the segment processes and discards this traffic. Every switch port floods it. This is pure overhead — the cluster already has a private control-plane interconnect (fxp1) that can carry election traffic without touching customer networks.

## Why "Just Turn VRRP Off" Doesn't Work

We tried this (`no-reth-vrrp`). It caused **dual-active** — both nodes simultaneously acted as primary, both added VIPs, both sent GARPs. The bug that exposed this was an inverted boolean (`RethVRRP` defaulting to false), but the underlying architectural problem is real:

**The heartbeat election has a race window.** Both nodes can simultaneously:
1. Lose sight of the peer's heartbeat (network blip, CPU spike, GC pause)
2. Independently elect themselves primary for the same RG
3. Both add VIPs → duplicate packets, MAC table thrashing, session corruption

VRRP prevents this because it's a **distributed consensus protocol**: when both nodes advertise as MASTER on the same VRID, the higher-priority advertisement forces the loser to BACKUP within one advertisement interval (30ms). The heartbeat has no such mechanism — it just exchanges state, each node runs election independently, and there's no tie-breaking feedback loop.

**What VRRP provides that the heartbeat doesn't:**

| Capability | Heartbeat | VRRP |
|-----------|-----------|------|
| Peer liveness detection | Yes (200ms interval) | Yes (30ms interval) |
| Per-RG state exchange | Yes (priority, weight, state) | Yes (VRID, priority) |
| Independent per-node election | Yes | Yes |
| **Dual-active resolution** | **No** — both nodes can independently claim primary | **Yes** — advertisement comparison forces loser to resign |
| **Convergence guarantee** | **No** — relies on heartbeat propagation | **Yes** — one advertisement interval resolves contention |

The dual-active resolution is the critical gap. Without it, any transient loss of the heartbeat link can cause split-brain.

## Proposed Solution: Private RG Mastership Protocol

Run a lightweight per-RG mastership protocol over the **control link** (fxp1) — the same private point-to-point interconnect that already carries the heartbeat. The protocol provides the same dual-active prevention guarantee as VRRP but stays entirely on the control plane.

### Why the Control Link, Not Fabric

The control link (fxp1) is the right place for this:

- **Control-plane function:** RG mastership election is a control-plane decision. The fabric links (fab0/fab1) are data-plane — they carry session sync traffic and cross-chassis packet forwarding. Mixing election traffic into the fabric data path conflates concerns.
- **Already carries heartbeat:** The heartbeat (UDP 4784) already runs on fxp1. The RG mastership protocol is a natural companion — same link, different port (UDP 4785).
- **Independent failure domain:** If the fabric links go down, session sync stops but election can still proceed over the control link. If the control link goes down, the heartbeat already detects this and triggers failover. Coupling election to the control link means a single link failure doesn't silently break both session sync AND election.
- **Simpler topology:** One control link vs. dual fabric links. No need for fab0/fab1 fallback logic in the election protocol.

### Design

```
  ┌──────────┐                                    ┌──────────┐
  │   fw0    │                                    │   fw1    │
  │          │  Heartbeat      (UDP 4784, fxp1)   │          │
  │          ├────────────────────────────────────→│          │
  │          │  RG Mastership  (UDP 4785, fxp1)   │          │
  │          ├────────────────────────────────────→│          │
  │          │←────────────────────────────────────┤          │
  │          │                                    │          │
  │          │  Session sync   (TCP, fab0/fab1)   │          │
  │          ├────────────────────────────────────→│          │
  │          │←────────────────────────────────────┤          │
  └──────────┘                                    └──────────┘

Control link (fxp1): heartbeat + RG mastership (control plane)
Fabric links (fab0/fab1): session sync + cross-chassis forwarding (data plane)
No VRRP multicast on LAN interfaces.
```

### Protocol: Per-RG Mastership Advertisements

A single UDP socket on the control link carries **per-RG mastership advertisements** — functionally equivalent to VRRP advertisements but unicast to the peer on the private control-plane interconnect:

**Wire format:**
```
[0:4]   Magic "BFRG"        (4 bytes)
[4]     Version (1)          (1 byte)
[5]     NodeID               (1 byte)
[6:8]   ClusterID            (2 bytes, LE)
[8]     NumEntries           (1 byte)
[9..]   Per-RG entries (5 bytes each):
          [0]    RGID
          [1:3]  Priority (LE uint16, effective = base × weight/255)
          [3]    State (0=secondary, 1=primary)
          [4]    Epoch (monotonic counter, wraps)
```

**Behavior:**
- Sent every **N ms** (configurable, default 50ms)
- Unicast to peer's control-link address (same address heartbeat uses)
- Port **4785** (adjacent to heartbeat port 4784)
- Carries all RGs in a single compact packet
- Each node runs independently — no request/response, pure advertisement
- Shares the VRF/routing context with heartbeat (`vrfListenConfig`)

### Dual-Active Resolution (The Key Mechanism)

When a node receives a peer advertisement where the peer claims primary for the same RG:

```
if peer.state == PRIMARY && local.state == PRIMARY {
    // Dual-active detected — resolve by priority tie-break
    if peer.effectivePriority > local.effectivePriority {
        // Peer wins — resign locally
        transitionToSecondary(rgID)
    } else if peer.effectivePriority == local.effectivePriority {
        // Tie — lower node ID wins (deterministic)
        if peer.nodeID < local.nodeID {
            transitionToSecondary(rgID)
        }
    }
    // else: we have higher priority, peer should resign
    // (peer runs the same logic on our next advert → converges in 1 round)
}
```

**Convergence guarantee:** Within one advertisement interval, exactly one node resigns. Same guarantee as VRRP, but on the private control link.

### Peer Loss Detection

When advertisements stop arriving (peer died or control link down):

```
masterDownInterval = (3 × advertInterval) + skewTime
skewTime = ((256 - localPriority) × advertInterval) / 256
```

Same formula as VRRP RFC 5798. At 50ms interval, priority 100: masterDown = ~174ms. At 30ms interval: masterDown = ~104ms.

On timeout: feed `PeerLostForRG(rgID)` into the existing cluster election. This provides per-RG loss detection that complements the heartbeat's overall peer-liveness signal.

Note: the heartbeat (200ms × 3 = 600ms) already runs on the same control link, so both will detect a control-link failure. The RG mastership protocol detects it faster due to shorter intervals, while the heartbeat serves as a backstop for overall cluster state.

### Integration Points

**Where it fits in the existing architecture:**

1. **New component:** `pkg/cluster/rg_advert.go` — the per-RG advertisement sender/receiver
2. **Socket:** UDP 4785 on control-link addresses (same local/peer addresses as heartbeat on port 4784)
3. **Startup:** `StartRGAdvert(localAddr, peerAddr, vrfDevice)` — mirrors `StartHeartbeat()` API
4. **Drives:** `rgStateMachine.SetCluster()` on state transitions (same interface as heartbeat election)
5. **Replaces:** VRRP instances for RETH interfaces when `private-rg-election` is enabled
6. **Co-exists with:** Heartbeat (overall liveness), session sync (data sync on fabric), VRRP (standalone non-RETH groups)

**Daemon integration (`pkg/daemon/daemon.go`):**

```
watchClusterEvents():
    case rgAdvertPrimary:
        directAddVIPs(rgID)
        go directSendGARPs(rgID)
        applyRethServicesForRG(rgID)   // RA, DHCP
    case rgAdvertSecondary:
        directRemoveVIPs(rgID)
        clearRethServicesForRG(rgID)
```

Same VIP/GARP/service management as the existing `no-reth-vrrp` direct mode — the difference is that mastership is now resolved by the private protocol instead of relying solely on heartbeat election.

### Per-RG Support

The protocol natively supports multiple RGs because each advertisement carries an array of RG entries. Each RG is independently resolved:

- RG0 can be primary on node0, RG1 primary on node1 (active-active per-RG)
- Manual failover sets weight=0 for the targeted RG → peer sees priority drop → peer takes over
- Interface monitoring reduces weight → priority drops → peer preempts (if enabled)

This is identical to how VRRP handles it (separate VRID per RG), but multiplexed into a single packet.

### Advantages Over VRRP

| | VRRP | Private RG Protocol |
|--|------|-------------------|
| **LAN traffic** | 132 multicast pkt/s per segment | Zero |
| **Link** | Data-plane (every LAN segment) | Control link (fxp1, private point-to-point) |
| **Addressing** | Multicast 224.0.0.18 / ff02::12 | Unicast to peer control-link IP |
| **Sockets** | Per-interface (4+ raw sockets + AF_PACKET) | 1 UDP socket |
| **Dual-active resolution** | Same (priority comparison) | Same (priority comparison) |
| **Detection speed** | ~97ms (30ms × 3 + skew) | ~174ms (50ms × 3 + skew), or ~104ms at 30ms |
| **Per-RG** | Separate VRID per RG, separate socket per interface | All RGs in one packet, one socket |
| **RFC compliance** | RFC 5798 | Proprietary |

### Configuration

```
chassis {
    cluster {
        cluster-id 1;
        private-rg-election;                    /* enable private protocol */
        private-rg-election-interval 50;        /* ms, default 50 */
    }
}
```

When `private-rg-election` is set:
- RETH VRRP instances are **not created** (same as `no-reth-vrrp`)
- RG advertisement sender/receiver starts on control link (same addresses as heartbeat)
- VIPs managed via `directAddVIPs/RemoveVIPs` (existing code)
- GARPs sent via `directSendGARPs` (existing code)
- Standalone VRRP groups (non-RETH, e.g., user-configured VRRPv3) are unaffected

### Failure Scenarios

**Control link failure (fxp1 down):**
- Both heartbeat AND RG advertisements stop simultaneously
- Heartbeat timeout fires → triggers peer-lost election → surviving node takes all RGs
- Both protocols share the same failure domain — single link failure triggers clean failover
- No worse than today: VRRP runs on LAN interfaces, but heartbeat loss on fxp1 already triggers election regardless of VRRP state

**Daemon crash / SIGKILL:**
- BPF watchdog (`ha_watchdog` map) detects daemon death within 2s → `rg_active=false` in BPF
- Peer stops receiving advertisements → masterDown timer → peer takes over
- Same behavior as VRRP daemon crash

**Transient control link blip (brief packet loss):**
- Heartbeat election may briefly race → both claim primary
- **RG mastership protocol resolves this** — next advertisement forces loser to resign
- This is exactly the gap VRRP fills today, now filled by the private protocol on the same link

**Fabric link failure (fab0/fab1 down):**
- Session sync stops, cross-chassis forwarding breaks
- Election is NOT affected — it runs on the control link, not fabric
- Clean separation: data-plane failures don't impact control-plane election

### Implementation Estimate

| Component | Effort |
|-----------|--------|
| `pkg/cluster/rg_advert.go` — protocol, sender, receiver | Core (~300 LOC) |
| `pkg/cluster/cluster.go` — start/stop alongside heartbeat | Moderate (~100 LOC) |
| `pkg/config/` — `private-rg-election` config knob | Small (~20 LOC) |
| `pkg/daemon/daemon.go` — wire up events, skip VRRP | Moderate (~80 LOC, reuse existing direct-mode code) |
| Tests — dual-active resolution, failover, per-RG | Tests (~200 LOC) |

Most of the VIP/GARP/service management code already exists in the `no-reth-vrrp` direct mode. The new work is the advertisement protocol and its integration with the cluster state machine.

### Relationship to `no-reth-vrrp`

`no-reth-vrrp` is the **unsafe** version of this idea — it disables VRRP without adding any replacement election mechanism. The heartbeat alone isn't enough to prevent dual-active.

`private-rg-election` is the **safe** version — it disables VRRP on LAN interfaces but adds a private advertisement protocol on the control link that provides the same dual-active resolution guarantee.

When `private-rg-election` is enabled, `no-reth-vrrp` behavior is implicitly active (no RETH VRRP instances). The two flags should be mutually exclusive in config validation:

```
// Can't use both — private-rg-election supersedes no-reth-vrrp
if cc.NoRethVRRP && cc.PrivateRGElection {
    warning: "private-rg-election implies no-reth-vrrp; remove no-reth-vrrp"
}
```

### Why Not Embed This in the Heartbeat?

The heartbeat already carries per-RG state (priority, weight, state) in every packet. Could we just add dual-active resolution logic to the heartbeat handler?

**No — the heartbeat interval is too slow.** The heartbeat runs at 200ms (configurable but intended for liveness, not election speed). Running it at 30-50ms to match VRRP would be a misuse of the protocol. The heartbeat is a coarse liveness signal; the RG mastership protocol is a fast election protocol. They have different timing requirements and should remain separate:

- **Heartbeat (UDP 4784):** 200ms interval, 3 threshold. Answers: "is the peer alive?"
- **RG Mastership (UDP 4785):** 50ms interval, 3 threshold. Answers: "who owns each RG right now?" and resolves contention.

Both run on the same control link, share the same VRF routing context, and are started/stopped together. But they serve distinct roles with distinct timing.

### Migration Path

1. **Today:** VRRP on LAN interfaces (default, working, proven)
2. **Next:** `private-rg-election` for environments that want zero LAN multicast
3. **Future:** Consider making `private-rg-election` the default once battle-tested
4. **Keep:** VRRP always available as fallback / for interop with third-party VRRP peers
