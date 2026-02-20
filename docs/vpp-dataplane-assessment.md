# VPP Dataplane Assessment for bpfrx

*Date: 2026-02-19*

## Executive Summary

This document assesses the viability of using fd.io VPP (Vector Packet Processing) as
a dataplane for bpfrx, either as a replacement for or complement to the existing XDP
and custom DPDK pipelines. The analysis covers VPP's architecture, feature set,
performance characteristics, integration strategies, VPN/tunnel compatibility, HA
(VRRP), and Linux kernel integration via pseudo-interfaces.

**Conclusion:** VPP is a viable high-performance dataplane but imposes significant
architectural constraints. The most practical path is a **hybrid XDP + VPP** model
where XDP handles early drops (screen/DDoS) and VPP handles stateful processing
(conntrack, policy, NAT) via AF_XDP. However, VPP's lack of zone-based policy
requires a custom C plugin, and its crash-stops-forwarding model sacrifices bpfrx's
hitless restart capability. For bpfrx's current scale (25 Gbps XDP, 15.6 Gbps
virtio-net), the existing architecture is adequate; VPP becomes compelling at 40-100+
Gbps where its vector processing model dominates.

**VPN/Tunnel finding:** The strongest case for VPP is encrypted tunnel acceleration.
VPP's WireGuard plugin achieves 34-204 Gbps (vs kernel's 3-5 Gbps per tunnel) and
its IPsec reaches 1.89 Tbps on 40 cores (vs strongSwan's ~1 Gbps/core). XDP
**cannot** inspect decrypted WireGuard or IPsec traffic -- only TC BPF hooks see the
inner packet after kernel crypto. For plaintext tunnels (GRE, VXLAN, Geneve), XDP
handles everything natively at near line-rate with no VPP needed.

**VRRP/HA finding:** VPP includes a production-grade VRRPv3 plugin (RFC 5798, used by
Netgate TNSR) with real-time async state events via GoVPP API -- eliminating
keepalived's fragile SIGUSR1 polling. However, VPP VRRP only makes sense if VPP is
already the dataplane; it lacks sync groups (bpfrx's cluster election handles
coordinated failover instead), and VIPs live on VPP interfaces requiring explicit
kernel mirroring for FRR and management services.

**Linux integration finding:** VPP's Linux Control Plane (LCP) plugin creates TAP
mirror interfaces in the kernel for each VPP-owned NIC, enabling FRR, SSH, SNMP, and
management services to operate without modification. Bidirectional netlink
synchronization keeps routes, addresses, and neighbor tables consistent between VPP
and the kernel. This is proven in production (IPng Networks: 13 routers, zero LCP
crashes since 2021; Netgate TNSR; Coloclue: 0% packet loss). LCP replaces bpfrx's
current networkd-based interface management but introduces namespace complexity and
a dependency on VPP's "experimental" plugin label.

### Document Sections

| Section | Topic |
|---------|-------|
| 1-3     | VPP architecture, feature gaps, performance comparison |
| 4       | Four integration strategies (full replacement, hybrid, selective, DPDK worker) |
| 5-6     | Go control plane (GoVPP), operational considerations |
| 7-8     | Risk assessment and recommendation |
| 9-10    | WireGuard/VPN performance, tunnel/XDP compatibility matrix |
| 11-12   | WireGuard integration options (A-E), impact on VPP decision |
| 13      | VRRP implementation with VPP (vs keepalived) |
| 14      | Linux CP pseudo-interfaces for FRR/kernel integration |

---

## 1. VPP Architecture Overview

### Vector Processing Model

VPP's core innovation is **batch (vector) packet processing** through a directed graph
of forwarding nodes. Instead of processing each packet through the entire pipeline
(as Linux and bpfrx's XDP tail-call chain do), VPP:

1. Reads the largest available vector of packets from the NIC (typically 256).
2. Pushes the entire vector through one graph node before moving to the next.
3. The first packet warms the instruction cache; subsequent packets hit warm cache.

This is fundamentally different from bpfrx's BPF pipeline where each packet traverses
`main -> screen -> zone -> conntrack -> policy -> nat -> nat64 -> forward` individually.
In VPP, all 256 packets would be processed through "screen" first, then all 256 through
"zone", etc. The I-cache advantage grows with batch size and pipeline depth.

### Threading Model

- One main thread for CLI, control plane, slow-path.
- Multiple worker threads, each pinned to a dedicated CPU core.
- RX queues assigned to workers (round-robin or manual NUMA-aware).
- No inter-thread communication on the fast path.

### Buffer Management

- Contiguous hugepage memory per NUMA node (default 16k buffers, ~40MB).
- Buffers referenced by u32 index (not pointer) -- halves working set.
- Thread-local buffer caches (512 entries, allocation is a check + subtraction + memcpy).
- Prefetching 4 packets ahead to hide memory latency.

### Comparison to bpfrx's Models

| Aspect               | bpfrx (XDP)              | bpfrx (DPDK worker)       | VPP                           |
|-----------------------|--------------------------|---------------------------|-------------------------------|
| Processing model      | Per-packet tail calls    | Single-pass per-packet    | Vector/batch graph dispatch   |
| I-cache behavior      | Re-loads per packet      | Single function, warm     | First packet warms, rest hit  |
| Context/stack         | 512-byte limit           | Full userspace            | Full userspace                |
| Threading             | Per-CPU BPF programs     | Per-lcore polling         | Pinned worker graph replicas  |
| Metadata passing      | Per-CPU scratch map      | Local struct (stack)      | Buffer metadata (extensible)  |
| Crash resilience      | Pinned maps survive      | Process crash = stop      | Process crash = stop          |

---

## 2. VPP Feature Coverage vs bpfrx Requirements

### Features VPP Provides Out of the Box

| Feature               | VPP Maturity | bpfrx Equivalent              | Notes                                      |
|-----------------------|--------------|-------------------------------|--------------------------------------------|
| NAT44-ED              | Production   | xdp_nat.c SNAT/DNAT          | More complete: twice-NAT, load-balanced DNAT, forwarding mode |
| NAT64                 | Production   | xdp_nat64.c                  | Stateful RFC 6146, TCP/UDP/ICMP            |
| NAT66                 | Listed       | --                            | IPv6-to-IPv6 static                       |
| Stateful ACLs         | Production   | xdp_conntrack.c + xdp_policy.c | Per-interface only, 2 TCP states, no zones |
| IPsec (ESP/AH)        | Production   | strongSwan config gen         | Native crypto engines, 31-50 Gbps/core     |
| GRE tunnels           | Production   | pkg/routing GRE               | L2 + L3                                   |
| VxLAN                 | Production   | --                            | L2 overlay                                |
| L2 bridging           | Production   | --                            | MAC learning, VLAN rewrite                 |
| BFD                   | Production   | --                            | Bidirectional Forwarding Detection         |
| LLDP                  | Production   | pkg/lldp                      | Link Layer Discovery Protocol              |
| FIB/LPM routing       | Production   | bpf_fib_lookup / DPDK rte_lpm | Built-in with VRF support                  |
| Linux CP plugin       | Production   | --                            | TAP mirrors for FRR integration            |
| AF_XDP driver         | Experimental | XDP attachment                | Kernel driver coexistence                  |
| TCP MSS clamping      | Built-in     | BPF + TC                      | Inline NAT feature                         |
| IPFIX/Syslog          | Built-in     | pkg/flowexport, pkg/logging   | NAT session logging                        |
| WireGuard             | Development  | --                            | VPN tunnels                                |

### Critical Gaps (Would Require Custom VPP Plugins)

| bpfrx Feature                    | VPP Status        | Effort to Implement             |
|----------------------------------|-------------------|---------------------------------|
| **Zone-based policy model**      | Not available     | ~2000 lines C plugin            |
| **Screen/IDS checks (11 types)** | Not available     | ~1000 lines C plugin            |
| **Application matching**         | Not available     | ~500 lines C plugin             |
| **Address book lookups**         | Not available     | ~300 lines C (use VPP LPM)      |
| **NPTv6 (RFC 6296)**            | Not available     | ~400 lines C plugin             |
| **Structured RT_FLOW syslog**    | Partial (IPFIX)   | ~300 lines C adaptation         |
| **ALG (SIP, FTP, etc.)**        | Not available     | ~500 lines C per protocol       |
| **Multi-term app definitions**   | Not available     | ~200 lines C plugin             |
| **Firewall filters (policer)**   | Classifier exists | ~400 lines C adaptation         |
| **Session aggregation reports**  | Not available     | Go-side via GoVPP stats         |

**Estimated plugin development: 4000-6000 lines of C** for zone-based stateful
firewall with bpfrx feature parity. This is the primary cost of VPP adoption.

---

## 3. Performance Comparison

### Raw Forwarding Throughput

| Workload              | bpfrx (XDP native) | bpfrx (virtio)  | bpfrx (DPDK worker) | VPP (DPDK)      | VPP (AF_XDP)    |
|-----------------------|--------------------|-----------------|----------------------|-----------------|-----------------|
| L3 forwarding         | 25+ Gbps           | 15.6 Gbps       | Not benchmarked      | 100+ Gbps       | ~70-80 Gbps est.|
| Stateful firewall     | ~20 Gbps est.      | ~12 Gbps est.   | Not benchmarked      | ~50+ Gbps est.  | ~40 Gbps est.   |
| IPsec AES-GCM-128     | N/A (strongSwan)   | N/A             | N/A                  | 31-50 Gbps/core | --              |
| NAT44                 | ~20 Gbps est.      | ~12 Gbps est.   | Not benchmarked      | ~40+ Gbps est.  | ~30 Gbps est.   |

*VPP numbers from published benchmarks (Google GCP, Intel, Calico/VPP).*
*bpfrx estimates based on measured forwarding throughput with stateful overhead.*

### Per-Core Efficiency

VPP's vector model yields better per-core throughput for complex pipelines:

- **VPP stateful ACL**: ~11 Mpps / 226 cycles per packet (input direction)
- **VPP stateless ACL**: ~9 Mpps / 273 cycles per packet
- **XDP simple forward**: ~14 Mpps per core (native driver)

VPP's stateful path is actually faster than its stateless path because the flow cache
avoids repeated ACL evaluation -- similar to bpfrx's conntrack fast-path bypassing
policy re-evaluation.

### Where VPP Wins

1. **Deep pipelines**: Vector processing advantage grows with pipeline depth.
   bpfrx's 8-stage XDP chain incurs 8 tail-call transitions per packet; VPP batches
   all packets through each stage.
2. **100G+ NICs**: DPDK PMD + VPP graph = line-rate at 100 Gbps on commodity hardware.
3. **IPsec acceleration**: Native crypto engines (IPSecMB, QAT) integrated into the graph.
4. **Multi-service**: NAT + routing + tunneling + IPsec in a single process.

### Where XDP Wins

1. **Early drops**: Screen/DDoS at driver level before SKB allocation -- zero cost for
   dropped packets. VPP must read packets into buffers before dropping.
2. **Crash resilience**: Pinned BPF maps and links survive daemon restart; VPP crash
   stops all forwarding.
3. **Operational simplicity**: No hugepages, no dedicated cores, no separate process.
4. **Kernel integration**: Works with any driver, visible to ip/tc tools, ARP/ND handled
   by kernel.
5. **Latency**: Single-packet processing has lower per-packet latency than batching
   (important for real-time/voice traffic at low utilization).

---

## 4. Integration Strategies

### Strategy A: VPP as Full Replacement (Not Recommended)

Replace XDP and DPDK worker with VPP as the sole dataplane.

```
NIC -> DPDK PMD -> VPP graph (screen -> zone -> conntrack -> policy -> NAT -> forward)
                                           (all as custom plugins)
```

**Pros:**
- Single dataplane to maintain.
- VPP's vector processing for all stages.
- Built-in NAT44-ED, NAT64, IPsec, tunneling.

**Cons:**
- Loss of hitless restart (VPP crash = forwarding stops).
- 4000-6000 lines of custom C plugins for zone-based firewall.
- Hugepage memory pre-allocation, dedicated CPU cores.
- NICs removed from kernel (DPDK mode) or experimental (AF_XDP mode).
- Complete rewrite of existing BPF C code as VPP graph nodes.
- VPP is a massive dependency (~77% C, 15K+ commits).
- Existing DPDK worker (~70% complete) would be abandoned.

**Effort:** 12-16 weeks for custom plugins + Go control plane adaptation.

### Strategy B: Hybrid XDP + VPP via AF_XDP (Most Viable)

Keep XDP for early-stage processing, hand off to VPP for stateful pipeline.

```
NIC driver
  |
  v
XDP program (screen checks, DDoS drops, zone classification)
  |                              |
  | XDP_DROP (screen violations) | XDP_REDIRECT -> XSKMAP
  v                              v
  dropped                       AF_XDP socket -> VPP
                                  |
                                  v
                                VPP graph (conntrack -> policy -> NAT -> forward)
                                  |
                                  v
                                TX via AF_XDP socket -> NIC
```

**Pros:**
- Keeps XDP's early-drop advantage (screen/DDoS at driver level).
- VPP handles complex stateful processing with better per-core throughput.
- AF_XDP keeps kernel driver loaded (management traffic still works).
- Incremental migration: move one pipeline stage at a time.
- Go control plane uses GoVPP for VPP + cilium/ebpf for XDP maps.

**Cons:**
- AF_XDP is "experimental" in VPP.
- Two dataplanes to operate (XDP + VPP).
- Packet crosses kernel/userspace boundary (AF_XDP overhead vs pure DPDK).
- Session state must be consistent between XDP conntrack and VPP sessions.
- Still need custom VPP plugins for zone policy + app matching.
- AF_XDP MTU limited to PAGE_SIZE - 256 (~3840 bytes on 4K pages).

**Effort:** 10-14 weeks (VPP plugins + GoVPP integration + AF_XDP plumbing).

### Strategy C: VPP for Specific Acceleration (Pragmatic)

Use VPP only for specific high-throughput features, keep XDP as primary dataplane.

```
NIC -> XDP pipeline (full bpfrx processing for most traffic)
                |
                | IPsec / high-throughput NAT flows
                v
              AF_XDP -> VPP (IPsec crypto, NAT44-ED pool, tunnel encap)
                |
                v
              TX back to XDP-attached interface
```

**Pros:**
- Minimal disruption to existing architecture.
- Leverage VPP's IPsec acceleration (31-50 Gbps/core vs strongSwan userspace).
- Keep all existing XDP code, tests, hitless restart.
- VPP only runs when needed (IPsec, high-throughput NAT pools).

**Cons:**
- Packet steering logic in XDP must be robust.
- Two session tables (XDP conntrack + VPP sessions) for IPsec flows.
- Limited benefit if IPsec isn't a primary use case.
- Added operational complexity for narrow benefit.

**Effort:** 6-8 weeks (VPP IPsec + AF_XDP bridge + GoVPP control).

### Strategy D: Complete Custom DPDK Worker (Current Path)

Finish the existing dpdk_worker/ implementation instead of adopting VPP.

```
NIC -> DPDK PMD -> dpdk_worker (single-pass: parse -> screen -> zone ->
                                conntrack -> policy -> NAT -> forward)
```

**Current status:** ~70% complete. All core pipeline stages implemented (parse, zone,
conntrack, policy, NAT44, NAT64, screen, firewall filters, TCP MSS clamping). Missing:
ALG, NPTv6, real-time FRR route sync, RETH bond support.

**Pros:**
- Already 70% done (~3000 lines C + Go CGo bridge).
- Tight Go<->C integration via shared hugepage memory (no serialization).
- Full control over processing pipeline and Junos semantics.
- Minimal external dependency (just DPDK libraries).
- ~6-8 weeks to complete remaining features.

**Cons:**
- Custom code to maintain indefinitely (no community).
- Single-pass model doesn't benefit from VPP's I-cache optimization.
- No built-in IPsec acceleration (still depends on strongSwan).
- Must implement every protocol and feature from scratch.

**Effort to complete:** 6-8 weeks for remaining 30% (ALG, NPTv6, FRR sync).

---

## 5. Go Control Plane Integration

### GoVPP Library

GoVPP (v0.13.0, November 2025) is the official Go toolset for VPP management:

- **Binary API client**: Pure Go, connects via Unix socket (`/run/vpp/api.sock`).
- **Stats client**: Shared-memory reader for VPP counters (zero data-plane overhead).
- **Code generator** (`binapigen`): VPP `.api` files -> Go bindings.
- **Performance**: 250,000+ API requests/second (async mode).
- **Used in production** by Calico/VPP and Ligato.

### Integration Pattern

```
Junos Config -> Parser -> Compiler -> GoVPP API calls -> VPP binary API
                                   -> eBPF map writes  -> XDP pipeline (existing)
```

The compiler already produces typed Go structs. A VPP backend would translate those
structs into GoVPP API calls:

```go
// Example: configure NAT pool
natClient := nat44ed.NewServiceClient(conn)
natClient.Nat44AddDelAddressRange(ctx, &nat44ed.Nat44AddDelAddressRange{
    FirstIPAddress: pool.StartIP,
    LastIPAddress:  pool.EndIP,
    VrfID:         vrfID,
    IsAdd:         true,
})
```

### Stats Collection

VPP exports stats via shared memory -- GoVPP reads counters without impacting the
data plane. This is analogous to bpfrx's per-CPU BPF map counter aggregation:

```go
statsClient, _ := statsclient.NewStatsClient("/run/vpp/stats.sock")
conn, _ := core.ConnectStats(statsClient)
stats, _ := conn.GetInterfaceStats()
```

### Dual-Backend Architecture

If pursuing hybrid (Strategy B/C), the config compiler would emit to both backends:

```go
type DataplaneBackend interface {
    ApplyZones(zones []ZoneConfig) error
    ApplySessions(sessions []SessionEntry) error
    ApplyNATRules(rules []NATRule) error
    ApplyPolicies(policies []PolicyEntry) error
}

type EBPFBackend struct { ... }  // existing cilium/ebpf map writes
type VPPBackend struct { ... }   // GoVPP API calls
type DPDKBackend struct { ... }  // shared memory writes (existing)
```

---

## 6. Operational Considerations

### VPP Deployment Requirements

| Requirement         | VPP (DPDK mode)                      | VPP (AF_XDP mode)          | bpfrx (XDP)             |
|---------------------|--------------------------------------|----------------------------|-------------------------|
| Hugepages           | 1-2 GB per NUMA node                 | Optional (UMEM)            | None                    |
| Dedicated CPU cores | Yes (main + workers)                 | Yes                        | No (per-CPU BPF)        |
| Kernel modules      | vfio-pci or igb_uio                  | None                       | None                    |
| NIC visibility      | Removed from kernel                  | Visible to kernel          | Visible to kernel       |
| Process model       | Separate VPP daemon                  | Separate VPP daemon        | Embedded in bpfrxd      |
| Config files        | /etc/vpp/startup.conf                | /etc/vpp/startup.conf      | /etc/bpfrx/bpfrx.conf   |
| Crash behavior      | Forwarding stops                     | Forwarding stops           | BPF continues (pinned)  |
| Restart             | Full restart, sessions lost          | Full restart               | Hitless (pinned maps)   |
| Memory              | Pre-allocated, fixed                 | Pre-allocated              | Dynamic kernel memory   |
| Binary size         | ~50MB (VPP + plugins)                | ~50MB                      | ~45MB (bpfrxd)          |

### FRR Integration

VPP's Linux CP (Control Plane) plugin creates TAP mirror interfaces in the kernel for
each VPP interface. FRR sees these TAP interfaces and manages routes normally. VPP
learns routes via the linux-cp plugin and populates its FIB.

This is functionally equivalent to bpfrx's current model where FRR manages
`/etc/frr/frr.conf` and the kernel FIB is used by `bpf_fib_lookup()` / DPDK
`rte_lpm`. The key difference is that VPP has its own FIB separate from the kernel --
routes must be synced bidirectionally.

### Monitoring and Debugging

| Capability          | VPP                                  | bpfrx (XDP)                         |
|---------------------|--------------------------------------|-------------------------------------|
| Packet tracing      | `trace add` (graph-node level)       | bpf_printk, ring buffer events      |
| Stats               | Shared-memory counters (GoVPP)       | Per-CPU BPF map aggregation         |
| CLI debugging       | vppctl (rich, graph-aware)           | bpfrxd CLI, bpftool                 |
| Performance profile | VPP event logger, perf               | perf, bpftool prog profile          |
| Live inspection     | `show session table`, `show nat44`   | `show security flow session`        |

---

## 7. Risk Assessment

### High Risks

1. **AF_XDP maturity**: VPP's AF_XDP driver is labeled "experimental". Production
   deployment on this driver carries stability risk. Intel E810 NICs have reported
   issues (VPP stops processing RX traffic).

2. **Custom plugin maintenance**: 4000-6000 lines of C plugins must be maintained
   across VPP version upgrades (quarterly releases). VPP's internal APIs change
   between versions with limited backward compatibility guarantees.

3. **Loss of hitless restart**: VPP crash or restart means forwarding stops entirely.
   bpfrx's pinned BPF maps/links provide zero-downtime restarts -- this is a
   significant operational regression.

4. **Debugging complexity**: VPP's graph dispatch model is powerful but opaque. Custom
   plugin bugs are harder to diagnose than BPF verifier-checked programs. No equivalent
   of the BPF verifier's safety guarantees.

### Medium Risks

5. **Two-system complexity**: Hybrid XDP + VPP means operating two packet processing
   systems with consistent session state, increasing operational burden.

6. **GoVPP version coupling**: GoVPP bindings are generated per VPP version. VPP
   upgrades require regenerating and testing all bindings.

7. **Hugepage management**: Pre-allocated hugepages cannot be resized at runtime.
   Over-provisioning wastes memory; under-provisioning causes buffer exhaustion.

### Low Risks

8. **Community**: VPP has Cisco backing, quarterly releases, and production deployments
   (Netgate TNSR, Calico/VPP). Project is unlikely to be abandoned.

9. **Go integration**: GoVPP v0.13.0 is mature (13 releases, used in production).
   The API is stable and well-documented.

---

## 8. Recommendation

### Short Term (Current): Stay on XDP + Complete DPDK Worker

The existing XDP pipeline at 25+ Gbps with hitless restart, verifier-checked safety,
and zero-dependency operation is well-suited for bpfrx's current deployment targets.
The custom DPDK worker is ~70% complete and represents 6-8 weeks of remaining work for
a purpose-built high-performance path under full project control.

**Action:** Finish dpdk_worker (ALG, NPTv6, FRR sync) as the high-performance tier.

### Medium Term (If 40-100G Required): Evaluate VPP via AF_XDP

If deployment targets move to 40-100 Gbps, evaluate VPP with AF_XDP (Strategy B):

1. Prototype VPP with AF_XDP on a 40G NIC (4-6 weeks).
2. Implement minimal zone-policy plugin (2-4 weeks).
3. Benchmark against XDP and DPDK worker on same hardware.
4. Assess AF_XDP stability on target NIC (i40e, ice, mlx5).
5. Decision gate: if VPP delivers >2x throughput with acceptable stability, proceed
   with full plugin development.

**Prerequisite:** AF_XDP must graduate from "experimental" in VPP, or extensive
stability testing on target hardware must pass.

### Long Term (If Multi-Service Platform): Consider VPP as Primary

If bpfrx evolves toward a multi-service platform (router + firewall + load balancer +
VPN concentrator), VPP's integrated feature set becomes compelling. The investment in
custom plugins would be amortized across multiple services that VPP provides natively.

**Decision criteria:**
- Sustained demand for >100 Gbps throughput.
- Need for native IPsec acceleration (not strongSwan).
- Multi-service platform requirements beyond pure firewall.
- Team capacity for VPP plugin development and maintenance.

### Summary Matrix

| Strategy                    | Throughput  | Effort   | Risk   | Hitless Restart | Recommended For        |
|-----------------------------|-------------|----------|--------|-----------------|------------------------|
| A: VPP full replacement     | 100+ Gbps   | 12-16 wk | High   | No              | Not recommended        |
| B: Hybrid XDP + VPP (AF_XDP)| 40-80 Gbps  | 10-14 wk | Medium | Partial (XDP)   | 40-100G deployments    |
| C: VPP for IPsec only       | 25+ Gbps    | 6-8 wk  | Low    | Yes (XDP stays) | IPsec acceleration     |
| D: Complete DPDK worker     | 40+ Gbps    | 6-8 wk  | Low    | No (DPDK)       | Current path (default) |
| Current: XDP only           | 25+ Gbps    | 0        | None   | Yes             | Current deployments    |

---

## 9. WireGuard and VPN Technologies

### 9.1 VPP WireGuard Plugin

VPP's WireGuard plugin was introduced in VPP 20.09 and has been maintained for ~5.5
years. It is based on wireguard-openbsd and uses VPP's IPIP tunnel infrastructure.

**Features:** Multiple peers per interface, persistent keepalive, endpoint roaming,
integration with VPP's async crypto API (software and hardware engines).

**Production use:** Netgate TNSR terminates thousands of WireGuard VPNs on a single
platform. TNSR 25.10 added FQDN-based peer configuration.

**Known issues:** A February 2025 CSIT bug report describes crashes in hardware
WireGuard tests with "Peer error" on the main thread and "Keypair error" on workers,
suggesting memory corruption in certain configurations with hardware crypto offload.

#### WireGuard Performance: VPP vs Kernel vs Userspace

| Implementation                        | Packet Size | Throughput         |
|---------------------------------------|-------------|--------------------|
| VPP WireGuard + Intel QAT Gen 3       | 1420B       | **204 Gbps**       |
| VPP WireGuard + software (AVX-512)    | 1420B       | **34 Gbps**        |
| VPP WireGuard + QAT (Xeon D-2700)     | --          | **46 Gbps** bidir  |
| VPP WireGuard + software (Xeon D-2700)| --          | **8 Gbps** bidir   |
| VPP WireGuard + software (66B pkts)   | 66B         | **1,799 Mbps**     |
| wireguard-go + GSO/GRO (Tailscale)    | --          | **13 Gbps**        |
| Linux kernel WireGuard (multi-stream)  | --          | **7.89 Gbps**      |
| Linux kernel WireGuard (single stream)| --          | **3-5 Gbps**       |
| Linux kernel WireGuard (66B pkts)     | 66B         | **250 Mbps**       |
| boringtun (Cloudflare, Rust)          | --          | ~kernel parity     |

VPP with QAT offload provides a 5.9x improvement over software-only for large packets.
For small packets (66B), VPP is 7.2x faster than the kernel.

**Tailscale's surprising result:** wireguard-go (Go userspace) beat the kernel on bare
metal by leveraging UDP GSO (kernel v4.18+), TUN GRO (kernel v6.2+), and checksum
offload. No kernel bypass -- just smarter syscall batching. This achieved 13 Gbps.

### 9.2 VPP IPsec vs strongSwan / Kernel XFRM

| Implementation                   | Crypto        | Per-Core Throughput  |
|----------------------------------|---------------|----------------------|
| VPP IPsec (4th Gen Xeon)         | AES-GCM-128   | **~50 Gbps/core**    |
| VPP IPsec (single SA)            | AES-GCM-128   | **31 Gbps**          |
| VPP IPsec (Icelake)              | AES-NI vector | **16 Gbps/core**     |
| Linux kernel XFRM (4th Gen Xeon) | AES-GCM       | **~6 Gbps/core**     |
| Linux kernel XFRM (general)      | AES-GCM-128   | **4.8-5 Gbps/core**  |
| strongSwan (research, 2 cores)   | AES128GCM     | **~2.4 Gbps/core**   |
| strongSwan (commodity)           | AES-GCM+AESNI | **~1 Gbps/core**     |

**VPP-SSwan integration:** strongSwan handles IKE/control plane; VPP handles the data
plane via a plugin that offloads ESP processing. This achieved **1.89 Tbps NDR** on a
single 4th Gen Xeon socket (40 cores) -- the first open-sourced Tbps IPsec solution.

**Kernel XFRM bottleneck:** Decapsulation for a single IPsec SA is always limited to a
single CPU. Multiple CHILD_SAs are needed to utilize multiple cores. This is a
fundamental architectural limit that VPP bypasses entirely.

### 9.3 Other VPN/Tunnel Technologies in VPP

| Technology  | VPP Status         | Performance                                      |
|-------------|--------------------|--------------------------------------------------|
| IPsec       | Mature, production | 1.89 Tbps (40 cores)                             |
| VXLAN       | Mature, production | 47 Gbps NDR (4 cores, 1518B, 1-40K tunnels)      |
| Geneve      | Mature             | Similar to VXLAN                                 |
| SRv6        | Mature, production | CSIT benchmarked, telco-scale deployments        |
| MPLS        | Mature             | Core VPP feature                                 |
| GTP-U       | Production (5G)    | 1.3 Tbps containerized demo (Cisco/Intel)        |
| GRE         | Mature             | Core feature, baseline tunnel performance        |

---

## 10. Tunnel Technologies and XDP Compatibility

### 10.1 The Encryption Boundary: Where XDP Stops

XDP fires at the earliest point in the packet path -- before any kernel crypto
processing. This creates a hard architectural boundary:

| Tunnel Type     | XDP Sees on Physical NIC          | Can XDP Inspect Inner Packet? | Best Hook for Inner Packet                      |
|-----------------|-----------------------------------|-------------------------------|-------------------------------------------------|
| **WireGuard**   | Encrypted UDP payload             | **NO**                        | TC BPF on wg0                                   |
| **IPsec/XFRM**  | Encrypted ESP payload             | **NO**                        | TC BPF after XFRM recirculation, or TC on xfrmi |
| **GRE**         | Full GRE packet (plaintext)       | **YES** (inline parsing)      | XDP on physical NIC                             |
| **VXLAN**       | Full VXLAN packet (plaintext)     | **YES** (inline parsing)      | XDP on physical NIC                             |
| **Geneve**      | Full Geneve packet (plaintext)    | **YES** (inline parsing)      | XDP on physical NIC                             |
| **IPIP/IP6IP6** | Outer IP + inner IP               | **YES** (trivial parsing)     | XDP on physical NIC                             |
| **SRv6**        | IPv6 + SRH + inner                | YES (but wrong hook)          | seg6local End.BPF (separate program type)       |

**Key insight:** Plaintext tunnels (GRE, VXLAN, Geneve, IPIP) can be fully parsed and
firewalled inline in XDP at near line-rate. Encrypted tunnels (WireGuard, IPsec)
require kernel crypto processing, forcing inner-packet inspection into TC BPF hooks
which run after SKB allocation -- losing XDP's performance advantage.

### 10.2 WireGuard + XDP: Fundamental Incompatibility

**XDP cannot natively attach to WireGuard interfaces.** This is an architectural
limitation, not a missing feature:

1. **No link-layer headers:** WireGuard's `wg0` is a Layer 3 (tun-type) interface
   without Ethernet headers. XDP expects Layer 2 frames.
2. **No `ndo_bpf` implementation:** The WireGuard kernel module does not implement
   the netdev operation for native XDP.
3. **`XDP_PASS` breaks things:** Due to the header mismatch, passing packets through
   XDP on wg0 jams the socket code.
4. **Rejected upstream:** Jason Donenfeld (WireGuard author) wrote a patch to add XDP
   support; XDP maintainers rejected it as violating XDP's design assumptions about
   operating on raw frames before SKB allocation.
5. **Cilium explicitly rejects** WireGuard + XDP combinations after discovering
   fundamental incompatibilities.

**What works instead:**
- **TC BPF on wg0:** `BPF_PROG_TYPE_SCHED_CLS` on TC ingress sees fully decrypted
  plaintext packets. This is Fly.io's and Cilium's production approach.
- **XDP on physical NIC (pre-decryption):** Sees encrypted WireGuard UDP packets.
  Useful for rate-limiting and DDoS mitigation on port 51820, but cannot inspect
  inner packet content for firewall policy.

### 10.3 IPsec/XFRM + XDP

On ingress, XDP sees raw ESP packets (protocol 50) before XFRM processing. After
kernel XFRM decryption, the decrypted packet is **recirculated** through TC ingress
on the same interface:

```
Physical NIC → XDP (encrypted ESP) → SKB → TC ingress (1st pass: encrypted)
                                              ↓
                                        XFRM decrypt
                                              ↓
                                        TC ingress (2nd pass: decrypted, recirculated)
```

The TC BPF helper `bpf_skb_get_xfrm_state()` (TC-only, not available in XDP) returns
the SA's reqid, SPI, and remote address, enabling policy decisions based on which
IPsec tunnel a packet arrived through.

**xfrmi interfaces** (XFRM interface, `ip link add ipsec0 type xfrm`) also lack
native XDP support and `ndo_xdp_xmit`. TC BPF on xfrmi is the correct hook point
for inner-packet policy after decryption.

### 10.4 Plaintext Tunnels: XDP-Native at Full Speed

**GRE:** XDP can parse through outer IP + GRE header (4-16 bytes) to access inner
packet headers. Encap/decap via `bpf_xdp_adjust_head()` is a pointer operation (no
memcpy). bpfrx already has `gre_accel` infrastructure and GRE-specific TCP MSS
clamping (`tcp_mss_gre_in`/`tcp_mss_gre_out`).

**VXLAN/Geneve:** XDP can parse through outer Ethernet + IP + UDP + VXLAN/Geneve
header (~50 bytes) to the inner Ethernet frame. Manual byte-level encap/decap works
but the kernel helpers `bpf_skb_set_tunnel_key()` / `bpf_skb_get_tunnel_key()` are
**TC-only, not available in XDP**.

**IPIP:** Trivial -- just an extra IP header. XDP parses through with minimal overhead.

**SRv6:** Has first-class kernel support via `seg6local` End.BPF action
(`BPF_PROG_TYPE_LWT_SEG6LOCAL`), but this is a separate BPF program type from XDP --
not part of the XDP pipeline. Production-ready since kernel 4.18.

**Note:** Linux GRE, VXLAN, and Geneve tunnel devices all lack native XDP support
(`ndo_bpf` and `ndo_xdp_xmit`). The XDP-native approach means parsing these tunnels
**inline on the physical NIC** rather than using kernel tunnel devices.

### 10.5 Performance Hierarchy for XDP-Based Firewalling

**Tier 1 -- XDP-Native, Full Fast Path (inline parsing on physical NIC):**
1. IPIP/IP6IP6 -- simplest encap, trivial parsing, minimal overhead
2. GRE -- slightly more complex header, still fixed-format parsing
3. VXLAN/Geneve -- UDP encap adds one more layer, fully parseable

*Expected: 20-25+ Gbps on native XDP hardware.*

**Tier 2 -- Kernel Tunnel Device + TC BPF (two-stage):**
4. Kernel GRE/VXLAN device + TC BPF on tunnel interface for inner policy

*Expected: 10-15 Gbps (post-SKB allocation).*

**Tier 3 -- Encrypted Tunnels (kernel crypto required):**
5. IPsec with hardware offload (Intel QAT, NIC xfrm_device) + TC BPF
6. IPsec software (AES-NI) + TC BPF recirculation
7. WireGuard (ChaCha20-Poly1305 software) + TC BPF on wg0

*Expected: crypto-bound. WireGuard 3-5 Gbps/core, IPsec software 1-5 Gbps/core,
IPsec hardware offload 10-25+ Gbps.*

**Tier 4 -- Separate BPF Hook:**
8. SRv6 (seg6local End.BPF) -- different program type, ~8% overhead from BPF
   execution in the LWT path

---

## 11. WireGuard Integration Options for bpfrx

### Option A: Kernel WireGuard + TC BPF on wg0 (Recommended Short-Term)

```
Physical NIC (XDP) → encrypted UDP → kernel WireGuard → wg0 (TC BPF) → routing
```

- bpfrxd generates WireGuard configs (same pattern as strongSwan config generation)
- Kernel handles ChaCha20-Poly1305 crypto
- TC BPF program on wg0 applies zone-based firewall policy on decrypted traffic
- XDP on physical NIC handles DDoS/screen on encrypted WireGuard UDP traffic

**Pros:** Simplest integration, production-grade kernel WireGuard, battle-tested.
**Cons:** TC hooks slower than XDP (post-SKB). Two processing paths: XDP on physical,
TC on wg0. Single-core bottleneck per tunnel (~3-5 Gbps).
**Effort:** 4-6 weeks (TC BPF firewall program + wg config generator + zone binding).

### Option B: Kernel WireGuard + XDP on veth Peer

```
Physical NIC (XDP) → kernel WireGuard → wg0 → ip route via veth →
  XDP on veth peer → full firewall pipeline → forward
```

- Kernel WireGuard decrypts; wg0 routes to a veth pair
- XDP pipeline runs on the veth peer interface (native XDP supported since kernel 5.9)
- Full XDP firewall pipeline (screen, zone, conntrack, policy, NAT) on decrypted traffic
- Clean separation: WireGuard handles crypto, bpfrx handles policy

**Pros:** Full XDP pipeline on decrypted traffic. Reuses all existing BPF code.
**Cons:** Extra veth hop adds ~1-2 us latency. Routing rules to steer wg0 through veth.
Still limited by kernel WireGuard throughput.
**Effort:** 3-4 weeks (veth plumbing + routing rules + wg config generator).

### Option C: Userspace WireGuard (boringtun/CNDP) + AF_XDP

```
Physical NIC (XDP) → encrypted UDP → XDP_REDIRECT to AF_XDP socket →
  userspace WireGuard decrypt → inject decrypted packet back via tun/veth →
  XDP firewall pipeline on inner interface
```

- AF_XDP provides kernel-bypass I/O for encrypted packets
- boringtun/GotaTun (Rust) or CNDP (Intel, Rust + AF_XDP) handles crypto in userspace
- Decrypted packets re-enter XDP via a veth pair for full pipeline processing

**Pros:** Keeps XDP pipeline intact. CNDP's AF_XDP WireGuard uses Intel AVX-512.
Higher throughput potential than kernel WireGuard.
**Cons:** Extra packet copy (userspace decrypt → re-inject). More complex architecture.
boringtun/GotaTun less battle-tested. Latency from userspace round-trip.
**Effort:** 6-8 weeks (AF_XDP steering + userspace WG integration + re-injection).

### Option D: VPP WireGuard Plugin (Performance Ceiling)

```
Physical NIC (DPDK) → VPP WireGuard decrypt → VPP forwarding graph → VPP WireGuard encrypt
```

- VPP owns the entire data plane (DPDK or AF_XDP NIC binding)
- WireGuard + NAT + routing + ACL all in VPP's vector processing graph
- Intel QAT offload for ChaCha20-Poly1305 (204 Gbps)

**Pros:** Highest raw performance (34-204 Gbps). Vector processing for multi-tunnel.
**Cons:** Replaces bpfrx's entire BPF pipeline. Requires zone-policy VPP plugin.
VPP WireGuard has known stability issues (CSIT crashes). Loss of hitless restart.
**Effort:** 12-16 weeks (VPP zone-policy plugin + GoVPP integration + WireGuard config).

### Option E: Integrate WireGuard into bpfrx DPDK Worker

```
Physical NIC (DPDK PMD) → dpdk_worker (parse → WG decrypt → screen → zone →
  conntrack → policy → NAT → WG encrypt → forward)
```

- Add ChaCha20-Poly1305 to the existing single-pass DPDK pipeline
- Use DPDK's cryptodev API for hardware offload (QAT, AESNI-MB)
- Full bpfrx feature parity on decrypted traffic within a single pipeline pass

**Pros:** Single-pass processing (lowest latency). Full feature parity. No external
dependencies. Tight Go integration via existing shared memory.
**Cons:** Must implement WireGuard protocol (handshake, key rotation, keepalive) in C.
Crypto library integration. Significant development effort.
**Effort:** 8-12 weeks (WireGuard protocol + cryptodev integration + session management).

### WireGuard Integration Recommendation

| Timeframe   | Recommended Option | Rationale                                            |
|-------------|-------------------|------------------------------------------------------|
| Short-term  | **B** (kernel WG + veth + XDP) | Full XDP pipeline, minimal changes, battle-tested crypto |
| Medium-term | **C** (userspace WG + AF_XDP) | Higher throughput when kernel WG bottlenecks          |
| Long-term   | **E** (DPDK worker integration) | Highest performance under full project control       |
| If VPP adopted | **D** (VPP WireGuard plugin) | Only if VPP is already the primary dataplane        |

---

## 12. Impact on VPP Adoption Decision

### Does VPP Change the Calculus for Encrypted Tunnels?

The tunnel analysis strengthens VPP's case in one specific dimension:

**VPP's strongest advantage is encrypted tunnel throughput.** The gap between kernel
crypto and VPP+QAT is enormous:

| Tunnel Type | Kernel/strongSwan  | VPP (software)   | VPP (QAT)       | Speedup   |
|-------------|--------------------|-------------------|-----------------|-----------|
| WireGuard   | 3-5 Gbps/core      | 8-34 Gbps         | 204 Gbps        | 40-60x    |
| IPsec       | 1-5 Gbps/core      | 16-50 Gbps/core   | 50 Gbps/core    | 10-50x    |

If bpfrx's deployment targets include high-throughput VPN concentration (site-to-site
at 40+ Gbps, or hundreds of remote peers), VPP becomes significantly more attractive.

**However**, for deployments where VPN is one feature among many (the typical firewall
use case), the kernel WireGuard + TC/veth approach at 3-7 Gbps per tunnel is adequate
for the vast majority of site-to-site and remote access scenarios.

### For Plaintext Tunnels, VPP Adds Nothing

GRE, VXLAN, Geneve, and IPIP are all fully handled by XDP inline parsing at near
line-rate. There is no performance reason to adopt VPP for these tunnel types.

### Updated Recommendation

The original recommendation stands with one refinement:

- **Current path (XDP + DPDK worker)** remains optimal for the general firewall case.
- **VPP becomes compelling** specifically when the deployment requires **high-throughput
  VPN concentration** (40+ Gbps encrypted tunnels) or **native IPsec acceleration**
  beyond what kernel XFRM provides.
- **For WireGuard support**, Option B (kernel WG + veth + XDP pipeline) is the pragmatic
  first step. VPP or DPDK integration is only warranted when tunnel throughput exceeds
  kernel WireGuard's ~5 Gbps per-core limit.

---

## 13. VRRP Implementation with VPP

### 13.1 VPP VRRP Plugin Overview

VPP includes a production-grade **VRRPv3 plugin** (RFC 5798) that has been part of VPP
since release 20.05 (~6 years). It is maintained by Netgate and used in their TNSR
commercial router/firewall platform.

**Features:**

| Feature                     | VPP VRRP Plugin      | keepalived (bpfrx current)  |
|-----------------------------|----------------------|-----------------------------|
| VRRPv3 (RFC 5798)           | Yes                  | Yes                         |
| VRRPv2 (RFC 3768)           | No                   | Yes                         |
| IPv4 VIPs                   | Yes                  | Yes                         |
| IPv6 VIPs                   | Yes (link-local src) | Partial (bpfrx doesn't use) |
| Multiple VIPs per instance  | Yes                  | Yes                         |
| Priority / Preemption       | Yes                  | Yes                         |
| Accept mode                 | Yes                  | Yes                         |
| Unicast peers               | Yes                  | Yes                         |
| Interface tracking          | Yes (built-in)       | Yes (script-based)          |
| Virtual MAC (00:00:5e:...)  | Yes                  | Yes                         |
| GARP / Unsolicited NA       | Yes (on transition)  | Yes                         |
| Async state events via API  | Yes (WANT_VRRP_EVENTS) | No (SIGUSR1 dump parse)  |
| Sync groups                 | No                   | Yes                         |
| Notify scripts              | No                   | Yes                         |
| Runtime state query         | API (binary/stats)   | SIGUSR1 → file parse        |

### 13.2 Current bpfrx VRRP Architecture (keepalived)

bpfrx uses keepalived as an external VRRP daemon with a config-generation model:

```
bpfrx config (cluster/reth) → pkg/vrrp/vrrp.go → keepalived.conf → keepalived daemon
                                                                          ↓
                                                                    VRRP advertisements
                                                                    GARP/NA on failover
                                                                    VIP address management
```

**Key design choices:**
- **Bondless RETH:** No bond devices. VRRP runs directly on physical member interfaces
  via `RethToPhysical()` resolution (reth0 → trust0, reth1 → wan0, etc.)
- **VRID = 100 + rgID:** Deterministic VRID assignment per redundancy group.
- **Priority 200 (primary) / 100 (secondary):** Mapped from cluster election state.
- **169.254.RG.NODE/32 base address:** Link-local base on physical members for VRRP.
- **State detection:** SIGUSR1 → keepalived dumps to `/tmp/keepalived.data` → parse
  output for MASTER/BACKUP strings. Fragile and adds ~100ms latency.
- **Config apply:** Write `keepalived.conf`, SIGHUP for reload or fresh start.

**Pain points:**
1. External daemon dependency (separate process, separate lifecycle).
2. State detection is fragile (SIGUSR1 file dump parsing, race conditions).
3. No native event stream — cannot react to VRRP transitions in real-time.
4. Dual heartbeat systems: cluster heartbeat (UDP:4784) + VRRP multicast (224.0.0.18).
5. No IPv6 VRRP currently utilized (keepalived supports it, but bpfrx doesn't generate IPv6 instances).
6. Config apply latency from SIGHUP + file write.

### 13.3 VPP VRRP API (GoVPP Integration)

VPP's VRRP plugin exposes a clean binary API accessible via GoVPP:

```go
// Create a VRRP VR (Virtual Router)
vrrpClient := vrrp.NewServiceClient(conn)
reply, err := vrrpClient.VrrpVrAddDel(ctx, &vrrp.VrrpVrAddDel{
    SwIfIndex: interfaceIndex,  // VPP interface (physical member)
    VrID:      100 + rgID,      // VRID = 100 + redundancy group ID
    Priority:  200,             // 200=primary, 100=secondary
    Interval:  100,             // centiseconds (100 = 1 second)
    IsIPv6:    false,
    NAddrs:    uint8(len(vips)),
    Addrs:     vipAddresses,    // VIP addresses for this VR
    IsAdd:     true,
})

// Start the VR
vrrpClient.VrrpVrStartStop(ctx, &vrrp.VrrpVrStartStop{
    SwIfIndex:  interfaceIndex,
    VrID:       100 + rgID,
    IsIPv6:     false,
    IsStart:    true,
})

// Subscribe to state change events
vrrpClient.WantVrrpVrrpEvents(ctx, &vrrp.WantVrrpVrrpEvents{
    Enable: true,
    PID:    uint32(os.Getpid()),
})
// Events delivered asynchronously via VPP notification channel:
// VrrpVrEvent{SwIfIndex, VrID, NewState: INIT/BACKUP/MASTER}
```

**Key API methods:**
- `VrrpVrAddDel` — create/delete VR instances
- `VrrpVrStartStop` — start/stop VRRP on a VR
- `VrrpVrSetPeers` — configure unicast peers
- `VrrpVrTrackIfAddDel` — add interface tracking (weight-based priority reduction)
- `WantVrrpVrrpEvents` — subscribe to state change notifications
- `VrrpVrDump` — query current VR state

### 13.4 Implementation Approach: VPP VRRP for bpfrx

If VPP is adopted as a dataplane (Strategy B or C), VRRP can be migrated from keepalived
to VPP's native plugin. Here is the implementation approach:

#### Architecture

```
bpfrx config (cluster/reth)
    ↓
pkg/vrrp/vpp.go (new VPP VRRP backend)
    ↓
GoVPP binary API → VPP VRRP plugin
    ↓
VRRP advertisements on physical member interfaces
GARP/NA on MASTER transition
VIP address on VPP interface (not kernel)
    ↓
VrrpVrEvent (async) → bpfrx cluster state machine
```

#### Step 1: VRRP Backend Interface

Abstract the VRRP implementation behind an interface so both keepalived and VPP backends
can coexist:

```go
// pkg/vrrp/backend.go
type Backend interface {
    // Apply creates/updates all VRRP instances from compiled config
    Apply(instances []VRRPInstance) error
    // Stop shuts down all VRRP instances
    Stop() error
    // RuntimeStates returns current MASTER/BACKUP state per instance
    RuntimeStates() (map[string]string, error)
    // Events returns a channel of state change events (nil if unsupported)
    Events() <-chan StateEvent
}

type StateEvent struct {
    VRID      uint8
    Interface string
    NewState  string  // "MASTER", "BACKUP", "INIT"
}
```

The existing keepalived code (`pkg/vrrp/vrrp.go`) becomes `KeepalivedBackend` implementing
this interface. A new `VPPBackend` handles the VPP VRRP API.

#### Step 2: VPP VRRP Instance Mapping

Map bpfrx's RETH/RG model to VPP VR instances:

| bpfrx Concept               | VPP VRRP Mapping                         |
|------------------------------|------------------------------------------|
| Redundancy Group (RG)        | One VR per physical member per RG        |
| RETH interface (reth0)       | VIPs on physical member's VR             |
| VRID = 100 + rgID            | Same (VR ID = 100 + rgID)                |
| Priority 200/100             | Same (mapped from cluster election)      |
| RethToPhysical() resolution  | VPP interface index lookup               |
| 169.254.RG.NODE/32 base addr | VPP interface primary address             |
| Cluster weight → priority    | VrrpVrTrackIfAddDel for interface tracking|

#### Step 3: Event-Driven Failover

Replace the fragile SIGUSR1 polling with VPP's async event stream:

```go
func (v *VPPBackend) watchEvents(ctx context.Context) {
    sub, _ := v.conn.WatchEvent(ctx, (*vrrp.VrrpVrEvent)(nil))
    for {
        select {
        case <-ctx.Done():
            return
        case ev := <-sub.Events():
            vrrpEv := ev.(*vrrp.VrrpVrEvent)
            v.eventCh <- StateEvent{
                VRID:     uint8(vrrpEv.VrID),
                NewState: stateToString(vrrpEv.NewState),
            }
        }
    }
}
```

This eliminates the polling latency and race conditions of SIGUSR1 file parsing,
enabling sub-millisecond VRRP state detection.

#### Step 4: VIP Kernel Mirroring (Required)

**Critical limitation:** VPP's VRRP assigns VIPs to VPP interfaces, NOT kernel
interfaces. This means:

- The kernel routing table won't know about VIPs (FRR can't see them).
- Management traffic (SSH, SNMP) to VIPs won't reach the kernel.
- bpfrx's gRPC/HTTP APIs bound to VIP addresses won't work.

**Solution:** Mirror VIP addresses to kernel interfaces on MASTER transition:

```go
func (v *VPPBackend) onMasterTransition(vrid uint8, iface string, vips []net.IP) {
    link, _ := netlink.LinkByName(iface)
    for _, vip := range vips {
        addr := &netlink.Addr{IPNet: &net.IPNet{IP: vip, Mask: mask}}
        netlink.AddrAdd(link, addr)
    }
}

func (v *VPPBackend) onBackupTransition(vrid uint8, iface string, vips []net.IP) {
    link, _ := netlink.LinkByName(iface)
    for _, vip := range vips {
        addr := &netlink.Addr{IPNet: &net.IPNet{IP: vip, Mask: mask}}
        netlink.AddrDel(link, addr)
    }
}
```

This is similar to what keepalived does natively but must be handled explicitly with VPP.

### 13.5 VPP VRRP vs keepalived: Trade-offs

| Dimension                   | VPP VRRP                              | keepalived                            |
|-----------------------------|---------------------------------------|---------------------------------------|
| **State detection**         | Async API events (sub-ms)             | SIGUSR1 file dump (~100ms, fragile)   |
| **Config application**      | GoVPP API call (instant)              | File write + SIGHUP (10-50ms)         |
| **Process management**      | Built into VPP (no extra process)     | Separate daemon lifecycle             |
| **IPv6 VRRP**               | Native VRRPv3 with link-local src     | Supported but unused by bpfrx         |
| **Interface tracking**      | Native API (weight-based)             | Script-based (exec overhead)          |
| **Sync groups**             | Not supported                         | Supported (failover all RGs together) |
| **Notify scripts**          | Not supported                         | Supported (exec on transition)        |
| **VIP ownership**           | VPP interface (needs kernel mirror)   | Kernel interface (native)             |
| **GARP/NA**                 | Built-in on transition                | Built-in on transition                |
| **Virtual MAC**             | 00:00:5e:00:01:XX (standard)          | 00:00:5e:00:01:XX (standard)          |
| **Maturity**                | Production (Netgate TNSR, ~6 years)   | Production (~20 years)                |
| **Dependency**              | Requires VPP dataplane                | Standalone daemon                     |
| **Standalone operation**    | Only with VPP running                 | Works without any dataplane           |

### 13.6 Sync Group Limitation

VPP's VRRP plugin does **not** support sync groups (coordinated failover of multiple VR
instances). In bpfrx's model, when one redundancy group fails over, all RGs on the same
node should fail over together.

**Workarounds:**
1. **Application-level sync:** On receiving a VPP VRRP event for any VR transitioning to
   BACKUP, programmatically force all other VRs on the same node to BACKUP priority via
   `VrrpVrAddDel` with priority 0. This is the GoVPP equivalent of keepalived's sync groups.
2. **Use bpfrx's existing cluster election:** The cluster state machine already handles
   coordinated failover via heartbeat loss detection. VPP VRRP would only handle the VIP
   advertisement layer, not the election logic. When the cluster decides to fail over,
   it adjusts VPP VRRP priorities accordingly.

Option 2 is the correct approach — bpfrx's cluster election is more sophisticated than
VRRP sync groups (weight-based scoring, IP monitors, manual failover commands), and VPP
VRRP simply becomes the mechanism for advertising VIPs and sending GARP/NA.

### 13.7 VRRP Recommendation

| Scenario                             | Recommended Approach                    |
|--------------------------------------|------------------------------------------|
| **Current (XDP dataplane)**          | Stay with keepalived                     |
| **VPP adopted as dataplane**         | Migrate to VPP VRRP plugin               |
| **Hybrid XDP + VPP**                 | Either — VPP VRRP if VPP owns interfaces |
| **DPDK worker path**                 | Stay with keepalived                     |

**Key insight:** VPP VRRP is only worth adopting **if VPP is already the dataplane**.
The primary benefit is eliminating the external keepalived dependency and gaining
real-time event-driven state detection via GoVPP. If bpfrx stays on XDP or the custom
DPDK worker, keepalived remains the better choice — it's battle-tested, requires no VPP
dependency, and manages VIPs natively in the kernel where FRR and management services
need them.

If VPP is adopted, the migration path is:
1. Implement `VPPBackend` behind the `Backend` interface (~400 lines Go).
2. Map existing RETH/RG instances to VPP VR configurations.
3. Subscribe to `VrrpVrEvent` for real-time state transitions.
4. Add kernel VIP mirroring for FRR and management traffic.
5. Test coordinated failover via cluster election → VPP priority adjustment.

**Effort estimate:** 2-3 weeks (assuming VPP dataplane is already integrated).

---

## 14. VPP Linux Control Plane: Pseudo-Interfaces for FRR Integration

### 14.1 The Problem: VPP Owns the NIC, Linux Can't See It

When VPP takes over a physical NIC (via DPDK or AF_XDP), the interface disappears from
the Linux kernel. FRR, SSH, SNMP, DHCP clients, and any management service that relies
on kernel interfaces cannot see or interact with VPP-managed interfaces. This is the
fundamental tension between kernel-bypass performance and control-plane integration.

VPP's **Linux Control Plane (Linux CP / LCP) plugin** solves this by creating **TAP mirror
interfaces** in the kernel — one shadow TAP per VPP interface. These TAP devices appear
as normal Linux network interfaces, enabling FRR, management services, and monitoring
tools to operate without modification.

### 14.2 Architecture: TAP Mirrors and Interface Pairs

```
                     VPP Dataplane (userspace)
                    ┌─────────────────────────────────────────┐
                    │                                         │
Physical NIC ───────┤  phy_sw_if_index ←── x-connect ──→ TAP sw_if_index
(DPDK/AF_XDP)       │  (fast-path forwarding)       (punt/inject path)
                    └─────────────────────────────────────────┘
                                                          │
                                                    virtio rings
                                                          │
                    ┌─────────────────────────────────────────┐
                    │  Linux Kernel                           │
                    │                                         │
                    │  TAP device (e.g., "e0")                │
                    │    - Same MAC, MTU, link state          │
                    │    - Visible to ip/ethtool/FRR          │
                    │    - Can be in dedicated namespace      │
                    └─────────────────────────────────────────┘
```

Each pairing is an **`lcp_itf_pair`** — a three-way mapping:

| Field               | Description                        | Example                    |
|----------------------|------------------------------------|----------------------------|
| `phy_sw_if_index`    | VPP's index for the physical NIC   | TenGigE3/0/0 = sw_if 1    |
| `host_sw_if_index`   | VPP's index for the TAP device     | tap0 = sw_if 5             |
| `vif_index`          | Linux kernel's ifindex for the TAP | e0 = ifindex 3             |

**Creation:**
```
lcp create TenGigabitEthernet3/0/0 host-if e0
lcp create TenGigabitEthernet3/0/1 host-if e1
lcp create loop0 host-if lo0
```

After creation, `e0` and `e1` appear as normal Linux interfaces with the same MAC, MTU,
and link state as the VPP physical interfaces. FRR, SSH, and SNMP see them as real NICs.

### 14.3 Traffic Split: Fast Path vs Punt Path

The critical performance insight: **transit traffic never touches the TAP**. Only
control-plane and management packets are punted through the TAP mirror:

| Traffic Type              | Path                                      | Performance     |
|---------------------------|-------------------------------------------|-----------------|
| **Transit (forwarded)**   | VPP fast path only — never touches kernel | 100+ Mpps       |
| **Local (to router)**     | VPP punt → TAP → kernel TCP/UDP stack     | TAP throughput  |
| **ARP / ND**              | x-connected bidirectionally via TAP       | Negligible load |
| **OSPF / BGP hellos**     | Punted to TAP → FRR in kernel             | Negligible load |
| **Host-originated**       | kernel → TAP → VPP → physical NIC         | TAP throughput  |

This is architecturally identical to bpfrx's current model where `XDP_PASS` punts
control-plane packets to the kernel while transit traffic stays in the XDP fast path.

### 14.4 Bidirectional Synchronization

Linux CP has two sub-plugins providing bidirectional state sync:

#### VPP → Linux (`lcp-sync`)

Changes made in VPP are propagated to the TAP mirrors:
- **Link state:** `set interface state <if> up/down` → TAP goes up/down
- **MTU:** `set interface mtu packet N <if>` → TAP MTU updates
- **IP addresses:** `set interface ip address <if> <addr>` → address added to TAP
- **MAC addresses:** Copied at creation time (runtime changes not synced — recreate LIP)

#### Linux → VPP (`linux-nl` netlink listener)

The netlink listener captures kernel events and applies them to VPP:
- **`RTM_NEWROUTE`/`RTM_DELROUTE`:** FRR route installations → VPP FIB entries
- **`RTM_NEWADDR`/`RTM_DELADDR`:** IP address changes → VPP interface addresses
- **`RTM_NEWLINK`/`RTM_DELLINK`:** Link state, MTU, MAC changes → VPP interfaces
- **`RTM_NEWNEIGH`/`RTM_DELNEIGH`:** ARP/ND entries → VPP neighbor tables

**Route sync performance:** ~175,000 routes/sec. Full DFZ (870K IPv4 + 133K IPv6)
programs into VPP's FIB in approximately 6 seconds.

**Feedback loop prevention:** When processing a batch of netlink messages, the listener
temporarily disables `lcp-sync` to prevent VPP→Linux→VPP infinite loops.

**Cooperative batching:** Up to 40ms or 8000 messages per batch (configurable), preventing
VPP's main thread from stalling during BGP convergence events.

### 14.5 FRR Integration: The Route Flow

```
FRR (BGPd/OSPFd)                     kernel netlink
    │                                     │
    ├─ learns route from peer             │
    ├─ installs in Zebra RIB              │
    ├─ Zebra programs kernel FIB ────────→│ RTM_NEWROUTE
    │                                     │
    │                              linux-nl listener
    │                                     │
    │                              translates to VPP FIB entry
    │                                     │
    │                              VPP forwards at line rate
```

FRR runs on the TAP interfaces (optionally in a `dataplane` network namespace for
isolation). It sees normal Linux network interfaces and operates without modification.
Routes flow: **FRR → kernel → netlink → VPP FIB**.

**Namespace modes:**
- **Default namespace:** TAPs in the same namespace as the host. Simple but no isolation.
- **Dedicated `dataplane` namespace (production recommended):** TAPs isolated from host
  networking. FRR runs inside the namespace. Management SSH may need a separate daemon
  instance in the namespace.

```
linux-cp {
  default netns dataplane
  lcp-sync
  lcp-auto-subint
}
```

**One-way FIB limitation:** Routes programmed directly in VPP's FIB (via API, not through
Linux) do NOT appear in the kernel routing table. All routing state must flow through Linux.

### 14.6 Sub-Interfaces, VLANs, and Tunnels

#### VLAN Sub-Interfaces

With `lcp-auto-subint` enabled, VPP VLAN sub-interfaces automatically get TAP mirrors:

```
# VPP side
create sub-interfaces TenGigabitEthernet3/0/0 100 dot1q 100 exact-match
# → Automatically creates Linux VLAN device e0.100 under parent TAP e0
```

Also works in reverse — creating a VLAN in Linux triggers VPP sub-interface creation:
```bash
ip link add link e0 name e0.100 type vlan id 100
# → Automatically creates VPP sub-interface with dot1q 100
```

Supports 802.1q, 802.1ad, Q-in-Q, and Q-in-AD. All sub-interfaces require `exact-match`.

#### Tunnel Interfaces

- **GRE/IPIP:** VPP-native tunnel interfaces can be mirrored with `lcp create`
- **IPsec/XFRM:** The `linux-xfrm-nl` plugin monitors kernel XFRM netlink messages and
  mirrors SA/SPD configurations into VPP's IPsec subsystem, enabling strongSwan to manage
  IKE while VPP handles ESP in the fast path

#### Bond/LAG

Bond interfaces get TAP mirrors. Physical members should be added before creating the
LIP (LACP temporarily assigns MAC addresses during member join).

### 14.7 Management Traffic

Packets destined to the router itself (SSH, gRPC, HTTP, SNMP) follow the punt path:

1. Packet arrives on VPP physical interface
2. VPP L3 lookup determines destination is a **local address**
3. Packet punted through TAP to kernel
4. Kernel TCP/UDP stack delivers to application (sshd, bpfrxd, snmpd)
5. Response exits through TAP → VPP → physical NIC

For the `dataplane` namespace model, services must run inside the namespace:
```ini
# /etc/systemd/system/sshd-dataplane.service
[Service]
NetworkNamespacePath=/var/run/netns/dataplane
ExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_config_dataplane
```

**Statistics caveat:** Linux interface counters on the TAP only show punted/host-originated
traffic, not transit traffic. Actual interface statistics require querying VPP directly
(CLI, stats segment, or custom SNMP agent).

### 14.8 Known Limitations and Caveats

| Issue                         | Impact                                        | Workaround                          |
|-------------------------------|-----------------------------------------------|-------------------------------------|
| Plugin labeled "experimental" | No formal API stability guarantees            | Used in production (TNSR, IPng)     |
| Multithreaded crash           | `lcp_arp_phy_node()` NULL buffer              | Fixed in recent VPP; test version   |
| No runtime MAC change sync    | Stale MAC on TAP after VPP MAC change         | Recreate LIP                        |
| No VPP→Linux route sync       | VPP-only routes invisible to kernel           | All routes flow through Linux/FRR   |
| Route delete/add race         | ~225μs window during BGP reconvergence        | Transient; no fix yet               |
| IS-IS punt                    | Ethertype 0x83FE not punted by default        | `lcp ethertype enable 0x83FE`       |
| Netlink buffer overflow       | Silent route sync failures under BGP load     | sysctl rmem_max=67108864            |
| Sub-if MTU clamping           | Cannot exceed parent MTU in Linux             | Expected Linux behavior             |

### 14.9 Production Deployments Using Linux CP + FRR

| Deployer         | Stack                    | Scale                    | Uptime / Status                |
|------------------|--------------------------|--------------------------|-------------------------------|
| **IPng Networks**| VPP + Bird2 + Linux CP   | 13 routers, full DFZ     | Zero LCP crashes since 2021  |
| **Netgate TNSR** | VPP + FRR + Linux CP     | 1-1000 Gbps commercial   | Production (v25.10)           |
| **Coloclue**     | VPP + Bird2 + Linux CP   | Amsterdam IX, eBGP/iBGP  | 0.0% packet loss (was 6.6%)  |
| **VyOS**         | VPP + FRR + Linux CP     | Software router          | Rolling release (2025)        |

IPng Networks achieves ~35 Mpps on a Xeon D-1518 (4 cores), sustaining 18 Gbps over
17 days with zero crashes. Full DFZ (870K+133K routes) installs in ~6 seconds.

### 14.10 Relevance to bpfrx

| Aspect                    | bpfrx (Current)                      | VPP + Linux CP                       |
|---------------------------|--------------------------------------|---------------------------------------|
| **Interface ownership**   | bpfrxd manages real kernel interfaces| VPP owns NICs, TAPs shadow to kernel  |
| **FRR integration**       | Generate `frr.conf`, `systemctl reload`| FRR sees TAP interfaces natively    |
| **Route sync**            | bpfrx writes FRR config → FRR installs| FRR → kernel → netlink → VPP FIB   |
| **Control-plane punt**    | `XDP_PASS` for local packets         | Punt to TAP for local packets         |
| **Address management**    | `.network` files via networkd         | `lcp-sync` copies to TAP             |
| **ARP/ND**                | Kernel handles (XDP_PASS)            | Kernel handles (TAP x-connect)        |
| **DHCP**                  | bpfrx's own DHCP client              | Standard dhclient on TAP              |
| **Management (SSH/gRPC)** | Kernel interfaces directly           | TAP interfaces (maybe in namespace)   |
| **Interface rename**      | `.link` files (MAC→name)             | `host-if` parameter names TAP         |

**Key insight:** If VPP is adopted, the Linux CP plugin replaces bpfrx's current interface
management model (`.link`/`.network` files, networkd). FRR integration becomes simpler
(FRR sees TAPs natively instead of needing managed `frr.conf` generation), but the
operational model shifts to managing a VPP startup config + LIP pairs instead of networkd
files. The `dataplane` namespace model adds complexity for management services but
provides clean isolation.

**For bpfrx's GoVPP integration**, the LIP lifecycle would be managed via:
```go
lcpClient := lcp.NewServiceClient(conn)
// Create interface pair
lcpClient.LcpItfPairAddDelV3(ctx, &lcp.LcpItfPairAddDelV3{
    SwIfIndex:   physicalIfIndex,
    HostIfName:  "trust0",
    HostIfType:  lcp.LCP_API_ITF_HOST_TAP,
    Namespace:   "dataplane",
    IsAdd:       true,
})
```

This is analogous to bpfrx's current `writeNetworkdFiles()` but operates at runtime via
API calls rather than file generation + networkctl reload.

---

## Appendix A: VPP Production Deployments

| Deployer        | Product                  | Scale              | Status              |
|-----------------|--------------------------|--------------------|---------------------|
| Netgate         | TNSR (router/firewall)   | 1-1000 Gbps        | Production (v25.10) |
| Tigera/Calico   | Calico/VPP (K8s CNI)     | 40G encrypted pods | GA (Calico 3.27+)   |
| Cisco           | NFV infrastructure       | Telecom 4G/5G core | Production          |
| Google Cloud    | VPP benchmarks on GCP    | 108 Mpps           | Published benchmarks|
| Intel           | IPsec reference arch     | 1.89 Tbps          | Reference design    |
| VyOS            | VPP dataplane option     | Software router    | Preview (not prod)  |

## Appendix B: Key References

- [fd.io VPP Documentation](https://s3-docs.fd.io/vpp/26.02/)
- [GoVPP Repository](https://github.com/FDio/govpp) (v0.13.0)
- [VPP AF_XDP Driver](https://s3-docs.fd.io/vpp/26.02/developer/devicedrivers/af_xdp.html)
- [VPP NAT44-ED Plugin](https://s3-docs.fd.io/vpp/26.02/developer/plugins/nat44_ed_doc.html)
- [VPP ACL Plugin (Multicore)](https://s3-docs.fd.io/vpp/23.10/developer/plugins/acl_multicore.html)
- [VPP Linux CP Plugin](https://s3-docs.fd.io/vpp/24.10/developer/plugins/lcp.html)
- [Calico/VPP Technical Details](https://docs.tigera.io/calico/latest/reference/vpp/technical-details)
- [100 Mpps with VPP on GCP](https://medium.com/google-cloud/forwarding-over-100-mpps-with-fd-io-vpp-on-x86-62b9447da554)
- [40G Encrypted with Calico/VPP](https://medium.com/fd-io-vpp/getting-to-40g-encrypted-container-networking-with-calico-vpp-on-commodity-hardware-d7144e52659a)
- [Intel IPsec with VPP (1.89 Tbps)](https://builders.intel.com/docs/networkbuilders/fd-io-vpp-sswan-and-linux-cp-integrate-strongswan-with-world-s-first-open-sourced-1-89-tb-ipsec-solution-technology-guide-1686047475.pdf)
- [Netgate TNSR](https://www.netgate.com/tnsr)

### WireGuard and VPN References

- [VPP WireGuard Plugin (v26.02)](https://s3-docs.fd.io/vpp/26.02/developer/plugins/wireguard.html)
- [Intel QAT WireGuard (4th Gen Xeon)](https://builders.intel.com/solutionslibrary/intel-qat-accelerate-wireguard-processing-with-4th-gen-intel-xeon-scalable-processor-technology-guide)
- [Intel AVX-512/QAT WireGuard (Xeon D-2700)](https://builders.intel.com/docs/networkbuilders/intel-avx-512-and-intel-qat-accelerate-wireguard-processing-with-intel-xeon-d-2700-processor-technology-guide-1647024663.pdf)
- [CSIT WireGuard Hardware Test Crashes](https://github.com/FDio/csit/issues/4045)
- [Tailscale 10+ Gbps wireguard-go](https://tailscale.com/blog/more-throughput)
- [Cloudflare boringtun](https://github.com/cloudflare/boringtun)
- [Mullvad GotaTun](https://mullvad.net/en/blog/announcing-gotatun-the-future-of-wireguard-at-mullvad-vpn)
- [Intel CNDP WireGuard (AF_XDP)](https://cndp.io/guide/sample_app_ug/WireGuard.html)
- [LPC 2024: WireGuard Performance](https://lpc.events/event/18/contributions/1968/attachments/1534/3213/LPC24_%20WireGuard_perf.pdf)
- [netdevconf 2024: WireGuard Multi-Tunnel Scaling](https://netdevconf.info/0x18/sessions/talk/achieving-linear-cpu-scaling-in-wireguard-with-an-efficient-multi-tunnel-architecture.html)

### XDP + Tunnel Compatibility References

- [Fly.io: BPF, XDP, Packet Filters and UDP](https://fly.io/blog/bpf-xdp-packet-filters-and-udp/)
- [Cilium WireGuard + XDP Incompatibility](https://github.com/cilium/cilium/issues/25354)
- [Cilium XFRM Reference Guide](https://docs.cilium.io/en/latest/reference-guides/xfrm/index.html)
- [Linux XFRM IPsec Reference Guide (pchaigno)](https://pchaigno.github.io/xfrm/2024/10/30/linux-xfrm-ipsec-reference-guide.html)
- [RHEL 9 IPsec AES-GCM Performance](https://www.redhat.com/en/blog/ipsec-performance-red-hat-enterprise-linux-9-performance-analysis-aes-gcm)
- [strongSwan Multi-Core SA Discussion](https://github.com/strongswan/strongswan/discussions/1089)
- [SRv6 BPF Implementation](https://segment-routing.org/index.php/Implementation/BPF)
- [XDP-MPTM Tunnel Multiplexer](https://github.com/ebpf-networking/xdp-mptm)
- [VPP-SSwan 1.89 Tbps Technology Guide](https://builders.intel.com/solutionslibrary/fd-io-vpp-sswan-and-linux-cp-integrate-strongswan-with-world-s-first-open-sourced-1-89-tb-ipsec-solution-technology-guide)

### Linux CP (Pseudo-Interface) References

- [VPP Linux CP Plugin Documentation (v25.10)](https://s3-docs.fd.io/vpp/25.10/developer/plugins/lcp.html)
- [IPng Networks - VPP Linux CP Part 1 (Interface Pairs)](https://ipng.ch/s/articles/2021/08/12/vpp-linux-cp-part1/)
- [IPng Networks - VPP Linux CP Part 2 (Addresses)](https://ipng.ch/s/articles/2021/08/13/vpp-linux-cp-part2/)
- [IPng Networks - VPP Linux CP Part 3 (VLANs)](https://ipng.ch/s/articles/2021/08/15/vpp-linux-cp-part3/)
- [IPng Networks - VPP Linux CP Part 4 (Netlink Listener)](https://ipng.ch/s/articles/2021/08/25/vpp-linux-cp-part4/)
- [IPng Networks - VPP Linux CP Part 5 (Route Sync)](https://ipng.ch/s/articles/2021/09/02/vpp-linux-cp-part5/)
- [IPng Networks - VPP Linux CP Part 6 (SNMP)](https://ipng.ch/s/articles/2021/09/10/vpp-linux-cp-part6/)
- [IPng Networks - VPP Linux CP Part 7 (Production)](https://ipng.ch/s/articles/2021/09/21/vpp-linux-cp-part7/)
- [Case Study: IPng at Coloclue (Full DFZ, Zero Packet Loss)](https://ipng.ch/s/articles/2024/06/29/case-study-ipng-at-coloclue/)
- [TNSR Linux-cp Configuration Guide](https://docs.netgate.com/tnsr/en/latest/advanced/dataplane-linux-cp.html)
- [VyOS VPP LCP Configuration](https://docs.vyos.io/en/latest/vpp/configuration/dataplane/lcp.html)
- [FRR Wiki - Alternate Forwarding Planes: VPP](https://github.com/FRRouting/frr/wiki/Alternate-forwarding-planes:-VPP)
- [Netgate Blog - Linux CP at LF Networking](https://www.netgate.com/blog/linux-cp-at-lf-networkings-one-summit-in-seattle-washington)
- [VPP XFRM Plugin (IPsec Kernel Integration)](https://haryachyy.wordpress.com/2025/08/28/learning-vpp-xfrm-plugin/)

### VRRP References

- [VPP VRRP Plugin Source](https://github.com/FDio/vpp/tree/master/src/plugins/vrrp)
- [VPP VRRP API Definition](https://github.com/FDio/vpp/blob/master/src/plugins/vrrp/vrrp.api)
- [VPP VRRP CLI Reference](https://s3-docs.fd.io/vpp/26.02/cli-reference/clis/clicmd_src_plugins_vrrp.html)
- [Netgate TNSR VRRP Documentation](https://docs.netgate.com/tnsr/en/latest/config/ha/vrrp.html)
- [RFC 5798 — VRRPv3](https://datatracker.ietf.org/doc/html/rfc5798)
- [keepalived Documentation](https://keepalived.readthedocs.io/en/latest/)
