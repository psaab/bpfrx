# Userspace Dataplane JIT Compiler Design

Date: 2026-03-17
Updated: 2026-03-21

## Current Status

| Phase | Description | Status | Measured Gain |
|-------|-------------|--------|---------------|
| 1 | Flow cache + rewrite descriptors | **PARTIAL** — cache hit skips session/policy/NAT/FIB but still uses generic frame builder; descriptor populated but not applied directly | +35% (13→17.5 Gbps) |
| 2 | Policy decision trees | Not started | — |
| 3 | Address-book trie compilation | Not started | — |
| 4 | Cranelift JIT | Not started | — |
| 5 | Screen function specialization | Not started | — |

**Phase 1 remaining work**: Implement `apply_rewrite_descriptor()` to
bypass the generic `build_live_forward_request_from_frame()` on cache
hit. The descriptor has all the fields (MACs, VLAN, NAT IPs/ports,
precomputed csum deltas) but the hot path doesn't use them yet —
it still calls the full frame builder with its ~8 branches.

**Current throughput**: 21.4 Gbps (IPv6, 8 parallel streams via iperf3,
2026-03-21). Baseline before flow cache was ~13 Gbps.

## Motivation

The userspace AF_XDP dataplane currently interprets every packet through a
generic pipeline: parse metadata, screen, session lookup, policy evaluation,
NAT decision, FIB lookup, frame rewrite. For established flows (>99% of
transit packets), the session-hit path still executes ~15 branches and 3-4
hash map lookups that always produce the same answer.

The eBPF dataplane avoids this with a per-CPU flow cache (`xdp_zone.c`) that
stores the complete forwarding decision (egress ifindex, MACs, NAT flags,
policy ID) and replays it in O(1) for subsequent packets in the same flow.
The userspace dataplane has no equivalent.

A JIT compiler can close this gap by generating specialized machine code for
the common-case packet paths, eliminating branches, hash lookups, and
indirection that the interpreter must execute on every packet.

## What the eBPF pipeline precomputes that userspace doesn't

| Feature | eBPF (compile-time) | Userspace (per-packet) |
|---------|---------------------|----------------------|
| Zone lookup | `iface_zone_map` HASH: O(1) | Same: O(1) HashMap |
| Address matching | LPM trie + membership HASH: O(log N) + O(1) | Linear scan of CIDR list |
| Policy rules | Flat ARRAY indexed by `set_id * MAX + idx` | Linear scan of Vec |
| Application match | HASH by `(proto, port)`: O(1) | Linear scan of application terms |
| Flow cache | Per-CPU 256-slot array: O(1) established hit | None; full session lookup every packet |
| Session lookup | Dual-entry HASH: O(1) forward+reverse | Multi-scope fallthrough with Mutex locks |
| NAT pool alloc | Atomic per-CPU counter | Mutex-protected PortAllocator |
| Frame rewrite | Inline in xdp_nat with incremental csum | Generic function with branch per NAT type |

## Where a JIT wins

### 1. Per-flow compiled fast-path (highest impact)

When a session is created, the JIT compiles a small function that encodes
the complete forwarding decision for that flow:

```
// Generated for flow: 10.0.1.102:55068 -> 172.16.80.200:443 TCP
// Zone: trust -> wan, SNAT to 172.16.80.8, egress ge-0-0-2.80
fn flow_0x7a3b(frame: &mut [u8]) -> TxTarget {
    // Ethernet: fixed MACs + VLAN 80 (12 bytes, no branch)
    write_eth_header(frame, DST_MAC, SRC_MAC, 80, 0x0800);
    // TTL decrement at known offset (no AF_INET/AF_INET6 branch)
    frame[22] -= 1;
    // IP checksum adjust (precomputed delta for TTL-1)
    adjust_csum_16(frame, 24, TTL_DELTA);
    // SNAT: rewrite src IP at offset 26 (precomputed)
    write_u32(frame, 26, 0xac108008); // 172.16.80.8
    // L4 pseudo-header csum adjust (precomputed delta)
    adjust_csum_32(frame, 40, SNAT_CSUM_DELTA);
    TxTarget { ifindex: 12, queue: 3 }
}
```

No branches. No hash lookups. No NAT type dispatch. No zone lookup.
Just straight-line memory writes with precomputed constants.

**Estimated gain**: 3-5x for established-flow throughput. The eBPF flow
cache achieves similar gains; this is the userspace equivalent.

### 2. Policy decision trees (high impact on large rulesets)

Current: linear scan of N rules per zone-pair, checking each rule's
address/port/protocol match sequentially.

JIT: at config compile time, build a binary decision tree for each
(src_zone, dst_zone) pair:

```
// Generated for trust -> wan policy (3 rules)
fn policy_trust_wan(proto: u8, dst_port: u16, src_ip: u32, dst_ip: u32) -> PolicyDecision {
    // Rule 1: permit tcp 80,443 to 0.0.0.0/0
    if proto == 6 && (dst_port == 80 || dst_port == 443) {
        return PolicyDecision::Permit { nat: SNAT_INTERFACE, rule_id: 1 };
    }
    // Rule 2: permit udp 53 to 0.0.0.0/0
    if proto == 17 && dst_port == 53 {
        return PolicyDecision::Permit { nat: SNAT_INTERFACE, rule_id: 2 };
    }
    // Rule 3: deny any
    return PolicyDecision::Deny { rule_id: 3 };
}
```

For policies with address-book references, expand CIDR matches into a
trie or sorted-array binary search at compile time instead of runtime
linear scan:

```
// Generated for address-book "servers" containing 10.0.1.0/24, 10.0.2.0/24
fn match_servers(ip: u32) -> bool {
    let prefix = ip >> 8;
    prefix == 0x0a0001 || prefix == 0x0a0002
}
```

**Estimated gain**: O(1) or O(log N) vs O(N) per miss. Matters most for
firewalls with 50+ rules per zone-pair.

### 3. NAT rule compilation (medium impact)

Current: `match_source_nat_for_flow()` iterates SNAT rule sets, checking
each rule's source/destination address match.

JIT: compile NAT rules into a dispatch table indexed by zone-pair:

```
// Generated SNAT dispatch for trust -> wan
fn snat_trust_wan(src_ip: u32, egress_ifindex: i32) -> Option<NatDecision> {
    // Rule 1: interface mode on egress
    if src_ip & 0xffffff00 == 0x0a000100 { // 10.0.1.0/24
        return Some(NatDecision::interface(egress_ifindex));
    }
    None
}
```

### 4. Screen inlining (low-medium impact)

Current: `check_packet()` evaluates all 11 screen checks for every packet
before session lookup, even when the zone has no screen profile.

JIT: at config compile time, generate a per-zone screen function that only
contains the enabled checks:

```
// Generated for zone "wan" with syn-flood + land-attack enabled
fn screen_wan(meta: &Meta) -> ScreenVerdict {
    // Land attack (always cheap)
    if meta.src_ip == meta.dst_ip { return Drop; }
    // SYN flood (only if TCP SYN)
    if meta.protocol == 6 && meta.tcp_flags & 0x02 != 0 {
        if syn_rate.check_and_increment() > 1000 { return Drop; }
    }
    Pass
}
// Generated for zone "trust" with NO screen profile
fn screen_trust(_meta: &Meta) -> ScreenVerdict { Pass }
```

### 5. Frame rewrite templates (medium impact)

Current: `build_forwarded_frame_into_from_frame()` has branches for:
- IPv4 vs IPv6
- VLAN vs no VLAN
- SNAT vs DNAT vs NAT64 vs no NAT
- TCP vs UDP vs ICMP (checksum handling)
- MSS clamping on/off

JIT: generate specialized rewrite functions per (addr_family, vlan,
nat_type, protocol) tuple. For the common case of IPv4+VLAN+SNAT+TCP,
this eliminates ~8 branches from the frame build path.

## Architecture

```
                    Config Change
                         |
                         v
              ┌─────────────────────┐
              │  Snapshot Compiler   │  (existing: Go manager)
              │  policies, zones,   │
              │  NAT rules, routes  │
              └──────────┬──────────┘
                         |
                         v
              ┌─────────────────────┐
              │  JIT Compiler       │  (NEW: Rust, runs on config apply)
              │                     │
              │  Inputs:            │
              │  - PolicySnapshots  │
              │  - SourceNATSnaps   │
              │  - ZoneSnapshots    │
              │  - ScreenSnapshots  │
              │  - RouteSnapshots   │
              │                     │
              │  Outputs:           │
              │  - Zone-pair policy │
              │    decision fns     │
              │  - NAT dispatch fns │
              │  - Screen fns       │
              │  - Frame rewrite    │
              │    templates        │
              │  - Flow cache       │
              │    code gen         │
              └──────────┬──────────┘
                         |
                         v
              ┌─────────────────────┐
              │  Compiled Pipeline  │  (mmap'd executable pages)
              │                     │
              │  Per-worker:        │
              │  - flow_cache[4096] │
              │    maps 5-tuple ->  │
              │    compiled fn ptr  │
              │                     │
              │  Per-zone-pair:     │
              │  - policy_fn()      │
              │  - snat_fn()        │
              │  - screen_fn()      │
              │                     │
              │  Per-flow (on hit): │
              │  - rewrite_fn()     │
              │    straight-line    │
              │    MAC+IP+port+csum │
              └─────────────────────┘
```

### Flow cache design

Each worker maintains a per-CPU flow cache (similar to eBPF's
`xdp_zone.c` flow cache):

```rust
struct FlowCacheEntry {
    key: SessionKey,          // 5-tuple for validation
    generation: u64,          // config generation (invalidate on change)
    rewrite_fn: fn(&mut [u8]) -> TxTarget,  // JIT-compiled rewrite
    nat_decision: NatDecision,
    egress: ForwardingResolution,
}

struct FlowCache {
    entries: [Option<FlowCacheEntry>; 4096],  // direct-mapped, hash-indexed
}
```

**Hit path** (established TCP, ~95% of packets):
1. Hash 5-tuple → cache index
2. Compare stored key (cache validation)
3. Call `rewrite_fn(frame)` → straight-line rewrite
4. Return TxTarget

**Miss path** (new flow or cache miss):
1. Full pipeline: session lookup → policy → NAT → FIB
2. JIT-compile rewrite function for this flow
3. Insert into flow cache
4. Forward packet

### JIT compilation strategy

**Option A: Cranelift** (recommended)

Use Cranelift as the JIT backend. It's a Rust-native code generator
with good ARM64/x86-64 support and fast compile times (~100us per
function). Already used by Wasmtime and rustc_codegen_cranelift.

```toml
[dependencies]
cranelift = "0.110"
cranelift-jit = "0.110"
cranelift-module = "0.110"
```

Pros:
- Native Rust, no FFI
- Fast compilation (~100us per flow function)
- Good register allocation
- Supports both x86-64 and aarch64

Cons:
- ~5MB binary size increase
- Learning curve for IR construction

**Option B: dynasm-rs** (simpler, x86-64 only)

Use dynasm-rs for direct x86-64 assembly emission. Simpler for the
narrow rewrite-function use case.

```toml
[dependencies]
dynasm = "2.0"
dynasmrt = "2.0"
```

Pros:
- Very fast compile (~10us per function)
- Zero abstraction overhead
- Tiny dependency

Cons:
- x86-64 only (no ARM64)
- Manual register management
- Harder to maintain

**Option C: Interpreted fast-path with template specialization**

No actual JIT — instead, precompute a "rewrite descriptor" at session
creation that encodes the exact byte offsets and values to write:

```rust
struct RewriteDescriptor {
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
    ttl_offset: u16,
    src_ip_offset: u16,
    src_ip_value: [u8; 4],      // or 16 for IPv6
    dst_ip_offset: u16,
    dst_ip_value: [u8; 4],
    l3_csum_offset: u16,
    l3_csum_delta: u16,         // precomputed
    l4_csum_offset: u16,
    l4_csum_delta: u32,         // precomputed from IP+port changes
    src_port_offset: u16,
    src_port_value: u16,
    dst_port_offset: u16,
    dst_port_value: u16,
}
```

Apply with a tight loop of `write_at(frame, offset, value)` calls.
No branches, no lookups, but still interpreted (not native code).

Pros:
- No JIT complexity or dependencies
- Works on all architectures
- Easy to reason about correctness
- Can be implemented incrementally

Cons:
- ~30-50% slower than native JIT (branch predictor still sees the
  dispatch loop)
- Still has function-call overhead per field

**Recommendation: Start with Option C**, measure, then graduate to
Option A (Cranelift) if the interpreted fast-path isn't enough.

**Decision (2026-03-18):** Option C chosen and partially implemented.
The `RewriteDescriptor` struct and `FlowCache` are in place. Initial
measurements show +35% from cache-hit alone (skipping session/policy/
NAT/FIB). The straight-line rewrite from the descriptor is the
remaining Phase 1 work.

## Implementation phases

### Phase 1: Flow cache + rewrite descriptors (Option C) — PARTIALLY COMPLETE

**Status**: Flow cache and RewriteDescriptor struct are implemented.
Cache hit skips session lookup, policy, NAT, and FIB. However, the
hit path still calls `build_live_forward_request_from_frame()` (the
generic frame builder) instead of applying the RewriteDescriptor
directly. The descriptor fields are populated but not used for
straight-line rewriting.

**What's done** (as of `30383e6`, 2026-03-21):
- [x] `RewriteDescriptor` struct defined (`afxdp.rs:187`) with MACs, VLAN,
      NAT IPs/ports, precomputed csum deltas, egress info, validation
- [x] `FlowCache` (4096-entry direct-mapped, `afxdp.rs:231`)
- [x] Flow cache lookup in `poll_binding()` hot path (`afxdp.rs:2824`)
      — TCP ACK-only packets checked before session lookup
- [x] Cache population on ForwardCandidate after full pipeline (`afxdp.rs:4131`)
- [x] Config/FIB generation invalidation on lookup
- [x] Amortized session timestamp touch (every 64 hits)
- [x] Per-worker hit/miss/eviction counters

**What's NOT done** (remaining Phase 1 work):
- [ ] `apply_rewrite_descriptor()` — straight-line frame rewrite using
      the descriptor's precomputed offsets and values. Currently the
      cache-hit path still calls the generic frame builder with ~8
      branches for AF, VLAN, NAT type, protocol, etc.
- [ ] Incremental checksum from precomputed deltas — the descriptor
      has `ip_csum_delta` and `l4_csum_delta` fields but they're not
      applied directly; the generic builder recomputes checksums
- [ ] IPv6 flow cache entries — currently only IPv4 TCP ACK-only

**Measured gain so far**: ~35% throughput improvement (13 → 17.5 Gbps)
from skipping session/policy/NAT/FIB on cache hit. Completing the
descriptor-based rewrite should add another 15-30%.

**Files**:
- `userspace-dp/src/afxdp.rs` — flow cache integration in poll_binding
- `userspace-dp/src/afxdp/frame.rs` — `apply_rewrite_descriptor()` (TODO)
- `userspace-dp/src/afxdp/session_glue.rs` — descriptor construction

**Test criteria**:
- Established-flow throughput improves (measured by perf-compare)
- `flow_cache_hits / total_packets > 0.9` for sustained TCP
- No regression in HA failover tests

**Expected remaining gain**: 15-30% from straight-line descriptor
rewrite (eliminates ~8 branches in frame build path).

### Phase 2: Policy decision trees — NOT STARTED

**Scope**: Compile policies into zone-pair decision functions at
config apply time.

1. In `buildPolicySnapshots()`, generate a decision tree representation
2. Pass decision tree to Rust helper as part of ConfigSnapshot
3. In Rust, compile decision tree into a match cascade
4. On session miss, call zone-pair decision function instead of
   linear policy scan

**Expected gain**: O(1)-O(log N) policy evaluation vs O(N) linear scan.
Significant for rulesets with 20+ rules per zone-pair.

### Phase 3: Address-book trie compilation — NOT STARTED

**Scope**: Replace linear CIDR matching with precomputed tries.

1. At config compile time, build a compact IPv4/IPv6 trie for each
   address-book entry
2. Store tries in the ConfigSnapshot
3. In Rust, deserialize into a flat array trie (cache-friendly)
4. Replace `match_address()` linear scan with trie lookup

### Phase 4: Cranelift JIT for flow rewrite functions — NOT STARTED

**Scope**: Replace rewrite descriptors with native code generation.

1. Add Cranelift dependency
2. At session creation, emit Cranelift IR for the rewrite function
3. Compile to native code (~100us)
4. Store function pointer in flow cache entry
5. On cache hit, call native function directly

**Expected gain**: Additional 30-50% over descriptors for the rewrite
path (eliminates dispatch loop overhead).

### Phase 5: Screen function specialization — NOT STARTED

**Scope**: Generate per-zone screen functions at config apply time.

Only compile the enabled screen checks. Zones with no screen profile
get a no-op function. Zones with only land-attack get a single
comparison.

## Incremental checksum precomputation

The biggest single optimization in the rewrite path is precomputing
checksum deltas at session creation time:

**Current** (per-packet):
```rust
// Recompute full L3 checksum after TTL + src_ip change
let old_csum = read_u16(frame, csum_offset);
let new_csum = fold16(
    !old_csum as u32
    + !old_ttl as u32 + new_ttl as u32
    + !old_src_hi as u32 + new_src_hi as u32
    + !old_src_lo as u32 + new_src_lo as u32
);
```

**Precomputed** (at session creation):
```rust
// At session create time:
let ip_csum_delta = compute_incremental_delta(old_src_ip, new_src_ip);
// Per-packet: just add delta + TTL adjustment
let new_csum = fold16(!old_csum as u32 + ip_csum_delta + 0x0100);
```

The IP checksum delta for SNAT is constant for the lifetime of the
session. Only the TTL decrement adds a per-packet component (and
that's always `+0x0100` for TTL-1).

For L4 (TCP/UDP), the pseudo-header checksum delta from IP changes
is also constant per session. Only payload changes (which we don't
modify) affect the L4 checksum.

## Memory and safety considerations

- Flow cache: 4096 entries * ~128 bytes = 512KB per worker (L2 cache friendly)
- Rewrite descriptors: ~64 bytes each, embedded in flow cache entry
- JIT code (Phase 4): ~256 bytes per function, mmap'd with PROT_EXEC
- Total per-worker overhead: ~1MB (acceptable)

**Safety**: All rewrite functions operate on bounded frame buffers
with length checks at the entry point. The descriptor approach
(Phase 1) is inherently safe — it's just offset+value pairs applied
to a validated frame. Cranelift JIT (Phase 4) generates verified
code through its IR builder, which prevents out-of-bounds access
by construction.

**Config invalidation**: Flow cache entries carry a `generation`
counter. On config change, bump the generation; stale entries are
lazily evicted on next access. No stop-the-world flush needed.

## Measurement plan

All phases measured using:
- `scripts/userspace-perf-compare.sh` for A/B throughput
- `iperf3 -P 4 -t 30` (min 3 runs)
- `perf record` / `perf report` for hot-symbol validation
- Flow cache hit rate counter
- `scripts/userspace-ha-failover-validation.sh` for HA regression
