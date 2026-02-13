# DPDK Dataplane for bpfrx — Architecture Plan

## Overview

Add a DPDK-based dataplane as an alternative to the current XDP/TC eBPF pipeline. The existing `pkg/dataplane.Manager` API is already well-abstracted — the daemon, CLI, gRPC, config system, and all subsystems interact through this interface, not through BPF-specific code. A DPDK implementation would swap the packet processing engine while keeping everything else unchanged.

## Why DPDK?

| | XDP/TC (current) | DPDK (proposed) |
|---|---|---|
| **Throughput** | 25+ Gbps native XDP | 40-100+ Gbps with DPDK PMDs |
| **Latency** | ~1-5µs (kernel bypass at NIC driver) | ~0.5-2µs (full kernel bypass, polling) |
| **CPU model** | Kernel interrupt-driven + XDP poll | Poll (dedicated cores) or interrupt-driven (power-aware) |
| **NIC support** | Any NIC with XDP driver | NICs with DPDK PMD (Intel, Mellanox, etc.) |
| **Kernel dependency** | Requires Linux 6.x+ for advanced features | Kernel-independent (hugepages + VFIO) |
| **Debugging** | Limited (bpf_printk, verifier) | Full gdb, profiling, logging |
| **Stack limit** | 512 bytes across call frames | No limit (userspace stack) |
| **Deployment** | Zero-dependency (kernel built-in) | Requires hugepages, DPDK libs, dedicated cores |

**Target use case:** High-throughput deployments (40G/100G NICs) where dedicating CPU cores to packet processing is acceptable. An interrupt-driven mode is also available for power-sensitive deployments.

## Architecture

### Current Architecture (XDP/TC)

```
┌─────────────────────────────────────────────────┐
│                   bpfrxd (Go)                    │
│  ┌──────────┐ ┌──────┐ ┌──────┐ ┌───────────┐  │
│  │ ConfigStore│ │ CLI  │ │ gRPC │ │ REST API  │  │
│  └─────┬────┘ └──┬───┘ └──┬───┘ └─────┬─────┘  │
│        │         │        │            │         │
│  ┌─────▼─────────▼────────▼────────────▼──────┐  │
│  │         dataplane.Manager (eBPF)            │  │
│  │  Load() Compile() SetZone() ReadCounters()  │  │
│  └─────────────────┬──────────────────────────┘  │
│                    │ cilium/ebpf                  │
│                    │ map operations               │
└────────────────────┼─────────────────────────────┘
                     │
    ─────────────────┼───────────────── kernel ─────
                     │
              ┌──────▼──────┐
              │  BPF maps   │  ← shared between Go and BPF programs
              └──────┬──────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
    ┌────▼───┐  ┌────▼───┐  ┌───▼────┐
    │XDP prog│  │XDP prog│  │TC prog │  ← 14 BPF programs
    │(ingress│  │  ...   │  │(egress)│    running in kernel
    └────────┘  └────────┘  └────────┘
         │                       │
    ┌────▼───────────────────────▼────┐
    │           NIC driver            │
    └─────────────────────────────────┘
```

### Proposed Architecture (DPDK)

```
┌─────────────────────────────────────────────────────┐
│                    bpfrxd (Go)                       │
│  ┌──────────┐ ┌──────┐ ┌──────┐ ┌───────────┐      │
│  │ConfigStore│ │ CLI  │ │ gRPC │ │ REST API  │      │
│  └─────┬────┘ └──┬───┘ └──┬───┘ └─────┬─────┘      │
│        │         │        │            │             │
│  ┌─────▼─────────▼────────▼────────────▼──────────┐  │
│  │       dataplane.Manager (interface)             │  │
│  │  Load() Compile() SetZone() ReadCounters()      │  │
│  └───────┬────────────────────────┬───────────────┘  │
│          │                        │                   │
│  ┌───────▼───────┐    ┌──────────▼──────────────┐    │
│  │ eBPF backend  │    │    DPDK backend          │    │
│  │ (current)     │    │  ┌────────────────────┐  │    │
│  │ cilium/ebpf   │    │  │ Go control plane   │  │    │
│  └───────────────┘    │  │ (map mgmt, config) │  │    │
│                       │  └────────┬───────────┘  │    │
│                       │           │ CGo / shared  │    │
│                       │           │ memory / RPC  │    │
│                       │  ┌────────▼───────────┐  │    │
│                       │  │ C/Rust DPDK worker │  │    │
│                       │  │ (packet pipeline)  │  │    │
│                       │  │ - poll-mode driver │  │    │
│                       │  │ - hash tables      │  │    │
│                       │  │ - session tracking │  │    │
│                       │  │ - NAT rewrite      │  │    │
│                       │  │ - forwarding       │  │    │
│                       │  └────────┬───────────┘  │    │
│                       └───────────┼──────────────┘    │
└───────────────────────────────────┼───────────────────┘
                                    │ DPDK PMD
                              ┌─────▼─────┐
                              │    NIC     │  ← VFIO/UIO bypass
                              └───────────┘
```

## Implementation Plan

### Phase 1: Define Manager Interface (Go)

Extract an interface from the current concrete `Manager` struct. All existing callers already use it as a concrete type, so this is a refactoring step.

```go
// pkg/dataplane/dataplane.go

type DataPlane interface {
    // Lifecycle
    Load() error
    IsLoaded() bool
    Close()
    Cleanup() error

    // Interface attachment
    AttachXDP(ifindex int, forceGeneric bool) error
    DetachXDP(ifindex int)
    AttachTC(ifindex int) error
    DetachTC(ifindex int)

    // Compilation
    Compile(cfg *config.Config) error
    LastCompileResult() *CompileResult

    // Zone management
    SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32) error
    SetZoneConfig(zoneID uint16, cfg ZoneConfig) error
    ClearIfaceZoneMap() error
    // ... all other Set/Clear/Read methods from maps.go

    // Session iteration
    IterateSessions(fn func(SessionKey, SessionValue) bool) error
    IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error
    DeleteSession(key SessionKey) error
    DeleteSessionV6(key SessionKeyV6) error
    SessionCount() (int, int)

    // Counters
    ReadPolicyCounters(id uint32) (CounterValue, error)
    ReadZoneCounters(id uint16, dir uint8) (CounterValue, error)
    ReadInterfaceCounters(ifindex uint32) (IfaceCounterValue, error)
    // ... all other counter methods

    // Map diagnostics
    GetMapStats() []MapStat
}
```

**Files to change:**
- `pkg/dataplane/dataplane.go` — New file: interface definition
- `pkg/dataplane/loader.go` — Rename `Manager` to `EBPFManager`, implement `DataPlane`
- `pkg/daemon/daemon.go` — Change `dp *dataplane.Manager` to `dp dataplane.DataPlane`
- `pkg/cli/cli.go` — Same type change
- `pkg/grpcapi/server.go` — Same type change
- `pkg/conntrack/gc.go` — Same type change
- `pkg/api/handlers.go` — Same type change

**Estimated effort:** 1-2 days. Mechanical refactoring, no behavior change.

### Phase 2: DPDK Worker Process (C)

Write the DPDK packet processing pipeline in C (or Rust). This replicates the 14 BPF programs as userspace functions.

```
dpdk_worker/
├── main.c              — EAL init, port setup, lcore launch
├── pipeline.c          — Top-level per-packet dispatch
├── parse.c             — Ethernet/IP/IPv6/TCP/UDP parsing
├── screen.c            — IDS checks (land, syn-flood, etc.)
├── zone.c              — Zone lookup + pre-routing FIB
├── conntrack.c         — Session lookup/create/update
├── policy.c            — Zone-pair policy matching
├── nat.c               — SNAT/DNAT rewrite
├── nat64.c             — IPv6↔IPv4 translation
├── forward.c           — TX port selection + VLAN push
├── filter.c            — Firewall filter evaluation
├── tables.h            — Hash table / array / LPM declarations
├── shared_mem.h        — Shared memory layout for Go↔C communication
└── Makefile            — DPDK build with meson/ninja
```

**Key DPDK APIs used:**
- `rte_eth_rx_burst()` / `rte_eth_tx_burst()` — Packet I/O
- `rte_hash_create()` / `rte_hash_lookup()` — Hash tables (sessions, DNAT, SNAT, zones)
- `rte_lpm_create()` / `rte_lpm_lookup()` — LPM trie (address book)
- `rte_ring` — Inter-core communication
- `rte_mempool` — Packet buffer allocation
- `rte_mbuf` — Packet metadata
- `rte_eal_remote_launch()` — Per-core packet loops

**Data structure mapping (BPF → DPDK):**

| BPF Map Type | DPDK Equivalent |
|---|---|
| HASH | `rte_hash` + secondary value array |
| ARRAY | Direct C array in shared memory |
| LPM_TRIE | `rte_lpm` (v4) / `rte_lpm6` (v6) |
| PERCPU_ARRAY | Per-lcore arrays + aggregation |
| PROG_ARRAY (tail calls) | Function pointer table |
| DEVMAP_HASH | TX port array + `rte_eth_tx_burst()` |
| RINGBUF (events) | `rte_ring` (SPSC) for event export |

**Pipeline structure:**

```c
// Main per-packet function — replaces 14 BPF programs
static inline void
process_packet(struct rte_mbuf *pkt, struct pipeline_ctx *ctx)
{
    struct pkt_meta meta = {0};

    // 1. Parse (replaces xdp_main)
    if (parse_packet(pkt, &meta) < 0)
        goto drop;

    // 2. Ingress filter
    if (evaluate_filter(pkt, &meta, DIRECTION_IN) == ACTION_DROP)
        goto drop;

    // 3. Screen/IDS (replaces xdp_screen)
    if (screen_check(pkt, &meta, ctx->screen_configs) < 0)
        goto drop;

    // 4. Zone lookup (replaces xdp_zone)
    zone_lookup(pkt, &meta, ctx->iface_zone_map, ctx->zone_configs);

    // 5. Conntrack (replaces xdp_conntrack)
    int ct_result = conntrack_lookup(pkt, &meta, ctx->sessions);
    if (ct_result == CT_ESTABLISHED && !meta.needs_nat)
        goto forward;  // Fast path

    // 6. Policy (replaces xdp_policy, only for new/non-established)
    if (ct_result == CT_NEW) {
        if (policy_check(pkt, &meta, ctx) != ACTION_PERMIT)
            goto drop;
        conntrack_create(pkt, &meta, ctx->sessions);
    }

    // 7. NAT (replaces xdp_nat)
    if (meta.needs_nat)
        nat_rewrite(pkt, &meta, ctx);

    // 8. NAT64 (replaces xdp_nat64)
    if (meta.needs_nat64)
        nat64_translate(pkt, &meta, ctx);

forward:
    // 9. Forward (replaces xdp_forward)
    forward_packet(pkt, &meta, ctx);
    return;

drop:
    rte_pktmbuf_free(pkt);
    ctx->counters->drops++;
}
```

**Estimated effort:** 3-4 weeks. This is the bulk of the work — replicating all packet processing logic.

### Phase 3: Go ↔ DPDK Communication

The Go control plane needs to update DPDK data structures (zones, policies, sessions) and read counters/sessions back.

**Option A: Shared Memory (Recommended)**

```
┌──────────────────┐          ┌──────────────────┐
│   Go (bpfrxd)    │          │  DPDK Worker (C)  │
│                  │          │                    │
│  DPDKManager     │◄────────►│  Shared hugepage   │
│  .SetZone()      │  mmap    │  - zone_table[]    │
│  .SetPolicy()    │          │  - policy_rules[]  │
│  .ReadCounters() │          │  - sessions hash   │
│                  │          │  - counters[]      │
│  rte_hash API    │          │                    │
│  (via CGo)       │          │                    │
└──────────────────┘          └──────────────────────┘
```

- Shared hugepage memory holds all tables
- Go uses CGo to call `rte_hash_add_key_data()`, `rte_lpm_add()`, etc.
- Counters are per-lcore arrays; Go sums them
- RCU-like semantics for safe update during packet processing

**Option B: Unix Domain Socket RPC**

- Go sends serialized config updates via UDS
- DPDK worker applies them to local tables
- Simpler but higher latency, more complex protocol

**Option C: DPDK Secondary Process**

- Go runs as DPDK secondary process (shares EAL memory)
- Direct access to all DPDK data structures
- Cleanest integration but requires DPDK EAL in Go process

**Recommendation:** Option A (shared memory via CGo). It keeps the Go process lightweight while giving direct access to DPDK hash tables.

**CGo wrapper layer:**

```go
// pkg/dataplane/dpdk/tables.go

// #cgo CFLAGS: -I/usr/include/dpdk
// #cgo LDFLAGS: -lrte_hash -lrte_lpm -lrte_eal
// #include <rte_hash.h>
// #include <rte_lpm.h>
import "C"

type DPDKManager struct {
    sessionHash  *C.struct_rte_hash
    zoneTable    *C.struct_zone_config  // mmap'd array
    policyHash   *C.struct_rte_hash
    // ... all tables
}

func (m *DPDKManager) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32) error {
    key := C.struct_iface_zone_key{
        ifindex: C.uint32_t(ifindex),
        vlan_id: C.uint16_t(vlanID),
    }
    val := C.struct_iface_zone_val{
        zone_id:       C.uint16_t(zoneID),
        routing_table: C.uint32_t(routingTable),
    }
    rc := C.rte_hash_add_key_data(m.zoneHash, unsafe.Pointer(&key), unsafe.Pointer(&val))
    if rc < 0 {
        return fmt.Errorf("rte_hash_add_key_data: %d", rc)
    }
    return nil
}
```

**Estimated effort:** 2-3 weeks. CGo wrappers for all map operations + shared memory setup.

### Phase 4: Go DPDKManager Implementation

Implement the `DataPlane` interface for DPDK.

```go
// pkg/dataplane/dpdk/manager.go

type DPDKManager struct {
    worker     *exec.Cmd        // DPDK worker process
    shm        *SharedMemory    // mmap'd hugepage region
    eventRing  *Ring            // Events from worker → Go

    // Hash table handles (CGo pointers)
    sessions   *C.struct_rte_hash
    sessionsV6 *C.struct_rte_hash
    zones      *C.struct_rte_hash
    policies   *C.struct_rte_hash
    dnatTable  *C.struct_rte_hash
    snatRules  *C.struct_rte_hash
    addrBookV4 *C.struct_rte_lpm
    addrBookV6 *C.struct_rte_lpm6

    // Array tables (direct mmap'd arrays)
    zoneConfigs    []ZoneConfig
    policyRules    []PolicyRule
    screenConfigs  []ScreenConfig
    flowTimeouts   []uint32
    // ...
}

func (m *DPDKManager) Load() error {
    // 1. Init DPDK EAL (as secondary process or via worker)
    // 2. Allocate hugepage shared memory
    // 3. Create hash tables, LPM tries, arrays
    // 4. Launch DPDK worker process
    // 5. Setup event ring for logging
}

func (m *DPDKManager) Compile(cfg *config.Config) error {
    // Same compilation logic as eBPF (phases 1-10)
    // But targets DPDK hash tables instead of ebpf.Map
    // Can reuse most of compiler.go with a different "map writer" backend
}

func (m *DPDKManager) AttachXDP(ifindex int, forceGeneric bool) error {
    // DPDK equivalent: bind NIC port to PMD
    // Worker starts polling this port
}
```

**Key difference from eBPF Manager:**
- No `cilium/ebpf` dependency
- Uses CGo for DPDK hash/LPM operations
- Worker process manages NIC ports (not kernel XDP attachment)
- Events come via `rte_ring` instead of BPF ring buffer

**Estimated effort:** 2 weeks. Most logic from compiler.go can be shared; only the "write to map" calls change.

### Phase 5: Build System & Configuration

```go
// cmd/bpfrxd/main.go

var dataplaneBackend = flag.String("dataplane", "ebpf",
    "Dataplane backend: ebpf (default) or dpdk")

func main() {
    switch *dataplaneBackend {
    case "ebpf":
        dp = dataplane.NewEBPFManager()
    case "dpdk":
        dp = dpdk.NewDPDKManager(dpdkConfig)
    }
    // ... rest of daemon unchanged
}
```

**DPDK-specific config (in Junos syntax):**

```
system {
    dataplane dpdk {
        cores 2-5;              /* Dedicated polling cores */
        memory 2048;            /* Hugepages in MB */
        ports {
            0000:03:00.0 {      /* PCI address → interface mapping */
                interface trust0;
            }
            0000:03:00.1 {
                interface untrust0;
            }
        }
    }
}
```

**Build integration:**

```makefile
# Makefile additions
build-dpdk:
    cd dpdk_worker && meson build && ninja -C build
    CGO_ENABLED=1 CGO_CFLAGS="-I/usr/include/dpdk" \
    CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lrte_eal -lrte_hash -lrte_lpm" \
    go build -tags dpdk -o bpfrxd ./cmd/bpfrxd

build-ebpf:
    make generate && make build  # Current flow, no DPDK deps
```

**Estimated effort:** 1 week.

## Data Structure Replication Details

### Session Table

BPF: `HASH` with `SessionKey` → `SessionValue` (40 + 120 bytes)

DPDK: `rte_hash` with same key/value layout in hugepage memory

```c
struct rte_hash_parameters session_params = {
    .name = "sessions_v4",
    .entries = 1 << 20,           // 1M sessions
    .key_len = sizeof(struct session_key),
    .hash_func = rte_jhash,       // Jenkins hash (fast)
    .socket_id = SOCKET_ID_ANY,
    .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,  // Lock-free RW
};
```

**Lock-free update:** DPDK `rte_hash` supports RCU-based lock-free readers with `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF`. Worker threads read without locks; Go control plane writes with RCU protection.

### LPM Trie (Address Book)

BPF: `LPM_TRIE` with `(prefixLen, IP)` → `addressID`

DPDK: `rte_lpm` (IPv4) / `rte_lpm6` (IPv6)

```c
struct rte_lpm_config lpm_cfg = {
    .max_rules = 65536,
    .number_tbl8s = 256,
};
struct rte_lpm *addr_book_v4 = rte_lpm_create("addr_v4", SOCKET_ID_ANY, &lpm_cfg);
```

### Counters

BPF: `PERCPU_ARRAY` — kernel maintains per-CPU copies

DPDK: Per-lcore counter arrays — same pattern

```c
// Per-lcore (no locks needed)
struct counter_value policy_counters[MAX_POLICIES] __rte_cache_aligned;

// Aggregation (called from Go via CGo)
void aggregate_counters(uint32_t policy_id, uint64_t *packets, uint64_t *bytes) {
    *packets = *bytes = 0;
    for (unsigned i = 0; i < rte_lcore_count(); i++) {
        *packets += lcore_counters[i].policy_counters[policy_id].packets;
        *bytes += lcore_counters[i].policy_counters[policy_id].bytes;
    }
}
```

## Challenges & Mitigations

### 1. NIC Ownership
**Problem:** DPDK takes exclusive ownership of NIC ports via VFIO/UIO. The kernel loses visibility.
**Mitigation:**
- Management interface (mgmt0) stays in kernel (not bound to DPDK)
- KNI (Kernel NIC Interface) or virtio-user for control plane traffic
- Or use bifurcated driver (mlx5) that shares NIC between kernel and DPDK

### 2. Kernel Routing Integration
**Problem:** FRR manages routes via kernel; DPDK bypasses kernel networking.
**Mitigation:**
- Read FIB from FRR JSON API (already done for `show route detail`)
- Maintain userspace FIB in DPDK (replicate kernel routing table)
- Or use `rte_fib` for longest-prefix-match forwarding
- FRR route changes → notification → update DPDK FIB

### 3. ARP/ND Resolution
**Problem:** Kernel ARP won't work for DPDK-owned interfaces.
**Mitigation:**
- Implement ARP responder in DPDK worker (answer ARP requests)
- Maintain neighbor table in shared memory
- Go control plane can populate static entries
- Or use KNI to punt ARP to kernel

### 4. Host-Inbound Services (SSH, DHCP, DNS)
**Problem:** Traffic destined to the firewall itself needs to reach kernel stack.
**Mitigation:**
- KNI interface: DPDK → kernel for host-inbound
- Or virtio-user pair: DPDK writes to virtio-user → kernel picks up
- Filter in DPDK: if dest_ip == self → punt to kernel via KNI

### 5. VLAN Handling
**Problem:** DPDK doesn't use kernel VLAN sub-interfaces.
**Mitigation:**
- Handle VLAN tag/untag in DPDK pipeline (already done in BPF)
- Map VLAN IDs to logical interfaces in userspace

### 6. Hitless Restart
**Problem:** DPDK process restart loses all NIC state.
**Mitigation:**
- Use hugepage-backed shared memory (survives process restart)
- Session table persists in hugepage
- New DPDK worker re-attaches to existing shared memory
- Brief packet loss during worker restart (unavoidable)
- Or use hot-standby: start new worker before killing old one

### 7. CGo Overhead
**Problem:** CGo calls have ~100ns overhead per call.
**Mitigation:**
- Batch operations: write many map entries in single CGo call
- Counter reads: aggregate in C, return single struct to Go
- Session iteration: C-side filtering, return matching subset
- Config compilation: batch all writes, single CGo "apply" call

## Power Management: Interrupt-Driven Mode

Pure poll-mode DPDK burns 100% CPU on dedicated cores even with zero traffic. This is unacceptable for branch/edge deployments, VMs, or any environment where power efficiency matters. bpfrx supports three RX modes that trade latency for power.

### Three RX Modes

```
system {
    dataplane dpdk {
        rx-mode polling;          /* Default: lowest latency, highest CPU */
        /* rx-mode interrupt; */  /* Lowest power, higher latency */
        /* rx-mode adaptive; */   /* Auto-switch between polling and interrupt */
    }
}
```

| Mode | CPU Usage (idle) | CPU Usage (line rate) | Added Latency | Use Case |
|------|-----------------|----------------------|---------------|----------|
| **polling** | 100% per core | 100% per core | 0 | Data center, 40G/100G |
| **interrupt** | ~0% per core | Scales with load | 5-50µs (interrupt coalescing) | Edge, branch, VM |
| **adaptive** | ~0% idle → 100% busy | 100% at threshold | 0-50µs (dynamic) | General purpose |

### Interrupt-Driven Mode (`rx-mode interrupt`)

Uses DPDK's `rte_eth_dev_rx_intr_*` API to sleep on an epoll fd until the NIC signals new packets.

```c
// dpdk_worker/rx_interrupt.c

static void
rx_loop_interrupt(uint16_t port_id, uint16_t queue_id, struct pipeline_ctx *ctx)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_rx;

    for (;;) {
        nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts, BURST_SIZE);

        if (nb_rx > 0) {
            process_burst(pkts, nb_rx, ctx);
            continue;  // Keep draining without sleeping
        }

        // No packets — arm interrupt and sleep
        rte_eth_dev_rx_intr_enable(port_id, queue_id);

        // epoll_wait on the interrupt fd (blocks until NIC signals)
        struct rte_epoll_event ev;
        rte_epoll_wait(rx_intr_fd, &ev, 1, INTR_TIMEOUT_MS);

        // Disable interrupt before resuming poll (avoid spurious wakeups)
        rte_eth_dev_rx_intr_disable(port_id, queue_id);
    }
}
```

**How it works:**
1. Worker calls `rte_eth_rx_burst()` — if packets available, process them
2. If no packets, enable NIC RX interrupt via `rte_eth_dev_rx_intr_enable()`
3. Sleep on epoll fd — kernel puts core to sleep (C-state)
4. NIC raises interrupt when packets arrive → epoll wakes up
5. Disable interrupt, resume polling burst

**NIC requirements:** The NIC PMD must support `RTE_ETH_DEV_INTR_RMV` / rx interrupt. Most modern NICs do: i40e, ice, ixgbe, mlx5, virtio, ena.

**Interrupt coalescing:** NICs batch interrupts to avoid per-packet overhead. Configure via ethtool before DPDK binding or via PMD-specific devargs:
```
# Before DPDK binding
ethtool -C enp3s0 rx-usecs 50 rx-frames 64

# Or via DPDK devargs
-a 0000:03:00.0,rx_intr_thresh=64
```

### Adaptive Mode (`rx-mode adaptive`)

Dynamically switches between poll and interrupt based on traffic load. This gives poll-mode performance under load and interrupt-mode efficiency at idle.

```c
// dpdk_worker/rx_adaptive.c

#define POLL_IDLE_THRESHOLD   256   // Empty polls before switching to interrupt
#define POLL_RESUME_BURST     32    // Packets in interrupt wakeup to resume polling
#define ADAPTIVE_CHECK_US     100   // Check interval for mode switch

enum rx_state { RX_POLL, RX_INTERRUPT };

static void
rx_loop_adaptive(uint16_t port_id, uint16_t queue_id, struct pipeline_ctx *ctx)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    enum rx_state state = RX_POLL;
    uint32_t idle_polls = 0;

    for (;;) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts, BURST_SIZE);

        if (nb_rx > 0) {
            process_burst(pkts, nb_rx, ctx);
            idle_polls = 0;

            // If we were in interrupt mode and got a big burst, switch to polling
            if (state == RX_INTERRUPT && nb_rx >= POLL_RESUME_BURST) {
                state = RX_POLL;
                ctx->counters->mode_switches++;
            }
            continue;
        }

        // No packets
        idle_polls++;

        if (state == RX_POLL && idle_polls > POLL_IDLE_THRESHOLD) {
            // Switch to interrupt mode — too many empty polls
            state = RX_INTERRUPT;
            ctx->counters->mode_switches++;
        }

        if (state == RX_INTERRUPT) {
            rte_eth_dev_rx_intr_enable(port_id, queue_id);
            struct rte_epoll_event ev;
            rte_epoll_wait(rx_intr_fd, &ev, 1, ADAPTIVE_TIMEOUT_MS);
            rte_eth_dev_rx_intr_disable(port_id, queue_id);
            idle_polls = 0;  // Reset after wakeup
        }
    }
}
```

**Tuning parameters (exposed in config):**

```
system {
    dataplane dpdk {
        rx-mode adaptive {
            idle-threshold 256;     /* Empty polls before sleep (default 256) */
            resume-threshold 32;    /* Burst size to resume polling (default 32) */
            sleep-timeout 100;      /* Max sleep ms in interrupt mode (default 100) */
        }
    }
}
```

### Power States and CPU Frequency

In interrupt mode, the core genuinely sleeps (enters C-state). Combined with CPU frequency scaling:

```c
// dpdk_worker/power.c

#include <rte_power.h>

// Initialize per-lcore power management
void power_init(unsigned lcore_id) {
    rte_power_init(lcore_id);  // Enables freq scaling for this core
}

// Called from adaptive loop when switching to interrupt
void power_scale_down(unsigned lcore_id) {
    rte_power_freq_min(lcore_id);  // Drop to lowest P-state
}

// Called from adaptive loop when switching to polling
void power_scale_up(unsigned lcore_id) {
    rte_power_freq_max(lcore_id);  // Boost to max P-state
}
```

DPDK's `rte_power` library integrates with Linux cpufreq governors (intel_pstate, acpi-cpufreq) to scale frequency per-core. In interrupt mode at idle:
- CPU enters C6 sleep state (~0W per core)
- Frequency drops to minimum P-state
- Wake-up latency: 10-100µs depending on C-state depth

### Hybrid Multi-Core: Mixed Modes

For deployments with asymmetric traffic (e.g., WAN at 10G, LAN at 1G), different cores can run different modes:

```
system {
    dataplane dpdk {
        cores 2-5;
        ports {
            0000:03:00.0 {       /* WAN: 10G, high traffic */
                interface wan0;
                rx-mode polling;
                cores 2-3;
            }
            0000:04:00.0 {       /* LAN: 1G, bursty */
                interface trust0;
                rx-mode adaptive;
                cores 4-5;
            }
        }
    }
}
```

### Power Monitoring

Expose power state in operational commands:

```
show system dataplane power
  Core 2: polling    (freq 3600 MHz, 100% busy)
  Core 3: polling    (freq 3600 MHz, 98% busy)
  Core 4: interrupt  (freq 800 MHz, idle, last wakeup 1.2s ago)
  Core 5: interrupt  (freq 800 MHz, idle, last wakeup 0.8s ago)
  Mode switches (adaptive): 1,247 total
  Average idle ratio: 62%
  Estimated power savings vs pure poll: ~45%
```

### Implementation in Worker

The RX mode is selected at startup and can be changed at runtime via shared memory flag:

```c
// dpdk_worker/main.c

typedef void (*rx_loop_fn)(uint16_t port_id, uint16_t queue_id,
                           struct pipeline_ctx *ctx);

static rx_loop_fn rx_loops[] = {
    [RX_MODE_POLL]      = rx_loop_poll,       // Existing pure poll
    [RX_MODE_INTERRUPT] = rx_loop_interrupt,   // New interrupt-driven
    [RX_MODE_ADAPTIVE]  = rx_loop_adaptive,    // New adaptive
};

// Per-lcore main function
static int
lcore_main(void *arg)
{
    struct lcore_conf *conf = arg;
    rx_loop_fn loop = rx_loops[conf->rx_mode];

    // Power management init (for adaptive/interrupt)
    if (conf->rx_mode != RX_MODE_POLL)
        power_init(rte_lcore_id());

    loop(conf->port_id, conf->queue_id, conf->ctx);
    return 0;
}
```

### Comparison with XDP

| | XDP (current) | DPDK Poll | DPDK Interrupt | DPDK Adaptive |
|---|---|---|---|---|
| **Idle CPU** | ~0% | 100% | ~0% | ~0% |
| **Latency (idle→first pkt)** | ~2µs | 0 (always polling) | 10-50µs | 10-50µs |
| **Latency (sustained)** | ~1-5µs | ~0.5-2µs | ~5-50µs | ~0.5-2µs |
| **Throughput** | 25+ Gbps | 40-100+ Gbps | 10-40 Gbps | 40-100+ Gbps |
| **Power** | Low | High | Very low | Low-medium |
| **Dedicated cores** | No | Yes | Yes (but sleeping) | Yes |

The interrupt and adaptive modes make DPDK viable for the same environments where XDP currently runs — without the 100% CPU penalty. Adaptive mode is the recommended default for most deployments.

## Estimated Timeline

| Phase | Description | Effort | Dependencies |
|-------|-------------|--------|-------------|
| 1 | Extract DataPlane interface | 1-2 days | None |
| 2 | DPDK worker (C packet pipeline) | 3-4 weeks | DPDK dev environment |
| 3 | Go ↔ DPDK shared memory + CGo | 2-3 weeks | Phase 2 |
| 4 | DPDKManager implementation | 2 weeks | Phase 1, 3 |
| 5 | Build system + config | 1 week | Phase 2, 4 |
| 6 | Testing + optimization | 2-3 weeks | All phases |
| **Total** | | **10-14 weeks** | |

## Incremental Approach

Rather than implementing everything at once, the DPDK backend could be brought up incrementally:

1. **Milestone 1: Basic forwarding** — Parse, zone lookup, FIB, forward. No conntrack, no NAT.
2. **Milestone 2: Stateful inspection** — Add conntrack (session create/lookup/expire).
3. **Milestone 3: NAT** — SNAT, DNAT, static NAT.
4. **Milestone 4: Policy** — Zone-pair policies, address book matching.
5. **Milestone 5: Screen/IDS** — DoS protection checks.
6. **Milestone 6: Advanced** — NAT64, firewall filters, ALG, DSCP.

Each milestone can be tested independently against the eBPF baseline.

## File Structure

```
pkg/dataplane/
├── dataplane.go         # DataPlane interface (new)
├── loader.go            # EBPFManager (renamed from Manager)
├── maps.go              # eBPF map operations (unchanged)
├── compiler.go          # Shared compilation logic
├── types.go             # Shared data structures
├── dpdk/
│   ├── manager.go       # DPDKManager implementing DataPlane
│   ├── tables.go        # CGo wrappers for rte_hash/rte_lpm
│   ├── shm.go           # Shared memory management
│   ├── events.go        # Event ring reader
│   └── counters.go      # Counter aggregation

dpdk_worker/
├── main.c               # EAL init, port setup, lcore launch
├── pipeline.c           # Per-packet processing
├── parse.c              # Packet parsing
├── screen.c             # IDS checks
├── zone.c               # Zone lookup
├── conntrack.c          # Session management
├── policy.c             # Policy matching
├── nat.c                # NAT rewrite
├── nat64.c              # NAT64 translation
├── forward.c            # Forwarding
├── filter.c             # Firewall filters
├── rx_poll.c            # Pure poll-mode RX loop
├── rx_interrupt.c       # Interrupt-driven RX loop (epoll + rte_eth_rx_intr)
├── rx_adaptive.c        # Adaptive RX loop (auto-switch poll ↔ interrupt)
├── power.c              # CPU frequency scaling via rte_power
├── tables.h             # Table declarations
├── shared_mem.h         # Shared memory layout
├── counters.h           # Per-lcore counters
└── meson.build          # DPDK build file
```

## Decision Points

1. **Language for worker:** C (native DPDK) vs Rust (safety + performance) vs Go with DPDK bindings (simplicity but GC pauses)
   - **Recommendation:** C for worker, Go for control plane. Matches DPDK ecosystem.

2. **Communication model:** Shared memory vs IPC vs DPDK secondary process
   - **Recommendation:** Shared hugepage memory via CGo. Best performance.

3. **NIC driver model:** VFIO (recommended, IOMMU) vs UIO (legacy, no IOMMU) vs bifurcated (mlx5 only)
   - **Recommendation:** VFIO-PCI. Standard, secure, works with most NICs.

4. **Core allocation:** Static (config) vs dynamic (auto-detect load)
   - **Recommendation:** Static initially. Config specifies which cores for DPDK.

5. **Kernel integration for host traffic:** KNI vs virtio-user vs TAP
   - **Recommendation:** virtio-user. KNI is being deprecated; virtio-user is the modern approach.

6. **Default RX mode:** Polling vs interrupt vs adaptive
   - **Recommendation:** Adaptive as default. Gives poll-mode throughput under load, interrupt-mode efficiency at idle. Pure polling available for latency-critical 100G deployments.
