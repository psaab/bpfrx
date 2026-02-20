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
