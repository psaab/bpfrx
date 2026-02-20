# VPP Dataplane Assessment for bpfrx

*Date: 2026-02-19*

## Executive Summary

This document assesses the viability of using fd.io VPP (Vector Packet Processing) as
a dataplane for bpfrx, either as a replacement for or complement to the existing XDP
and custom DPDK pipelines. The analysis covers VPP's architecture, feature set,
performance characteristics, integration strategies, and trade-offs.

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
