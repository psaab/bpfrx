# Plan: Split afxdp.rs into Defined Modules

## Problem

`userspace-dp/src/afxdp.rs` is 20,138 lines — the largest file in the codebase. It contains the entire AF_XDP userspace dataplane: coordinator lifecycle, worker threads, the packet processing hot loop, forwarding resolution, BPF map operations, UMEM management, neighbor monitoring, checksum helpers, and 8,775 lines of tests.

Seven submodules already exist in `afxdp/` (bind, frame, gre, icmp, icmp_embed, session_glue, tx — 10,420 lines total), but the parent file is still too large to navigate, reason about, or review diffs in.

## Goal

Split into focused modules with clear responsibilities, minimal cross-dependencies, and no public API changes. Each extraction step is independently compilable and testable.

## Current Layout

```
userspace-dp/src/
  afxdp.rs              20,138 lines  ← the monolith
  afxdp/
    bind.rs                385 lines  (XSK socket binding strategies)
    frame.rs             4,209 lines  (packet frame building/parsing)
    gre.rs                 410 lines  (GRE encap/decap)
    icmp.rs                233 lines  (ICMP generation)
    icmp_embed.rs          761 lines  (embedded ICMP NAT reversal)
    session_glue.rs      3,632 lines  (session table + demotion prepare)
    tx.rs                  790 lines  (TX ring submission)
```

### What's in the 20K-line monolith

| Line Range | ~Lines | Section |
|------------|--------|---------|
| 1-557 | 557 | Imports, constants, FlowCache, RewriteDescriptor, PendingNeighPacket, checksum helpers, DNAT table helpers |
| 558-1992 | 1,435 | `pub struct Coordinator` + `impl Coordinator` — orchestrator lifecycle |
| 1993-2879 | 887 | Worker types: ForwardingState, ForwardingResolution, BindingWorker, WorkerUmem, SessionFlow, WorkerCommand, etc. |
| 2880-5992 | 3,113 | `poll_binding()` — THE hot loop for RX/TX processing per worker |
| 5993-6842 | 850 | `worker_loop()` — worker thread main entry point |
| 6843-7221 | 379 | `local_tunnel_source_loop()` + tunnel helpers |
| 7222-7844 | 623 | Utilities: monotonic_nanos, kernel neighbor probes, VLAN insert, raw frame send, neigh_monitor_thread |
| 7845-8288 | 444 | classify_metadata, build_screen_profiles, `build_forwarding_state()` |
| 8289-9134 | 846 | RST suppression (nftables), NAT local exclusions |
| 9135-10150 | 1,016 | TCP MSS clamping, IcmpTeRateLimiter, forwarding resolution lookup functions |
| 10151-10223 | 73 | `diagnose_raw_ring_state()` |
| 10224-10388 | 165 | XSK/heartbeat BPF map helpers |
| 10389-10715 | 327 | OwnedFd, session map operations (publish/delete/verify/dump) |
| 10716-11362 | 647 | MmapArea (mmap wrapper), BindingLiveState (60+ atomic counters) |
| 11363-20138 | 8,775 | Tests |

## Proposed Module Structure

### 8 new modules in `afxdp/`:

| Module | ~Lines | Responsibility |
|--------|--------|----------------|
| **`types.rs`** | 900 | All shared structs, enums, constants. ForwardingState, ForwardingResolution, ForwardingDisposition, BindingWorker, WorkerUmem types, FlowCache, SessionFlow, HAGroupRuntime, route/neighbor/egress types, protocol constants, FastMap/FastSet aliases. Foundation for everything else. |
| **`forwarding.rs`** | 4,500 | Route resolution and config compilation. `build_forwarding_state()`, `build_screen_profiles()`, `classify_metadata()`, forwarding resolution lookup functions, connected route matching, tunnel resolution, fabric redirect logic. Includes ~3,000 lines of forwarding tests. |
| **`bpf_map.rs`** | 570 | BPF map CRUD operations. XSK slot register/delete, heartbeat touch, session map publish/delete/verify/dump, `read_fallback_stats()`, `diagnose_raw_ring_state()`. Standalone unsafe FFI — clear boundary. |
| **`umem.rs`** | 650 | Memory management. `MmapArea` + Drop, `WorkerUmemInner`, `WorkerUmem`, `WorkerUmemPool`, `BindingLiveState` (60+ atomic counters for per-binding stats), `update_binding_debug_state()`. Leaf types with no internal dependencies. |
| **`neighbor.rs`** | 650 | Neighbor discovery and monitoring. `neigh_monitor_thread()` (background netlink listener), kernel ARP/NDP probe functions, `parse_mac_str()`, `neighbor_state_usable_str()`, `send_raw_frame()`, `insert_vlan_tag()`, `monotonic_nanos()`. Includes ~100 lines of MAC parsing tests. |
| **`checksum.rs`** | 230 | Checksum computation. `compute_ip_csum_delta()`, `compute_l4_csum_delta()`, `ipv4_csum_words()`, `publish_dnat_table_entry()`. Pure functions with no side effects. |
| **`rst.rs`** | 850 | TCP RST suppression via nftables + NAT local exclusions. `install_kernel_rst_suppression()`, `remove_kernel_rst_suppression()` (pub(crate)), `nat_translated_local_exclusions()`. |
| **`tunnel.rs`** | 380 | Local tunnel origination. `local_tunnel_source_loop()`, tunnel TX request building, local tunnel session enqueue/wait, TUN device helpers. |

### What stays in `afxdp.rs` (~11,100 lines):

- Module declarations + `use self::X::*` re-exports
- `pub struct Coordinator` + `impl Coordinator` (~1,435 lines) — orchestrates everything
- `poll_binding()` (~3,113 lines) — the hot loop, touches every module
- `worker_loop()` (~850 lines) — thread entry point
- TCP MSS clamping, IcmpTeRateLimiter (~175 lines)
- ~5,500 lines of tests that exercise poll_binding/frame building

**Result: 20,138 → ~11,100 lines (45% reduction)**

## Re-export Strategy

```rust
// In afxdp.rs — wildcard imports so existing submodules' `use super::*` still works
use self::types::*;
use self::forwarding::*;
use self::bpf_map::*;
use self::umem::*;
use self::neighbor::*;
use self::checksum::*;
use self::rst::*;
use self::tunnel::*;

// Public re-exports for crate visibility (unchanged API)
pub use self::types::{ForwardingDisposition, ForwardingResolution, NeighborEntry, SyncedSessionEntry};
pub(crate) use self::rst::remove_kernel_rst_suppression;
pub use self::neighbor::{neighbor_state_usable_str, parse_mac_str};
```

Existing submodules (frame.rs, session_glue.rs, tx.rs, etc.) use `use super::*` to get items from `afxdp.rs` scope. This continues to work because the wildcard imports pull all new module exports into afxdp.rs scope, making them visible to child modules via `super::*`.

## Dependency Graph

```
afxdp.rs (Coordinator, poll_binding, worker_loop)
  │
  ├── types.rs          ← foundation, no deps on other afxdp modules
  ├── checksum.rs       ← uses types only
  ├── neighbor.rs       ← uses types only
  ├── bpf_map.rs        ← uses types only
  ├── umem.rs           ← uses types only
  ├── rst.rs            ← uses types only
  ├── forwarding.rs     ← uses types (largest extraction)
  ├── tunnel.rs         ← uses types + forwarding + bpf_map (via super::*)
  │
  └── [existing submodules]
      ├── bind.rs           (XSK binding strategies — 385 lines)
      ├── frame.rs          (packet frame building — 4,209 lines)
      ├── gre.rs            (GRE encap/decap — 410 lines)
      ├── icmp.rs           (ICMP generation — 233 lines)
      ├── icmp_embed.rs     (embedded ICMP NAT reversal — 761 lines)
      ├── session_glue.rs   (session table + demotion prepare — 3,632 lines)
      └── tx.rs             (TX ring submission — 790 lines)
```

No circular dependencies. All new modules are leaves except `tunnel.rs` which depends on siblings through `use super::*`.

## Migration Order

Each step is a single commit, independently compilable and testable with `cargo build --release && cargo test`.

| Step | Module | Risk | Rationale |
|------|--------|------|-----------|
| 1 | `types.rs` | Zero | Pure data types with trivial impls. Foundation for every subsequent step. No logic to break. |
| 2 | `checksum.rs` | Zero | Pure functions, no callers outside afxdp. Trivial extraction. |
| 3 | `neighbor.rs` | Low | Self-contained netlink + MAC helpers. Clear boundary: only Coordinator and worker_loop call these. |
| 4 | `bpf_map.rs` | Low | Standalone unsafe FFI for BPF map operations. Used by Coordinator, worker_loop, session_glue. |
| 5 | `umem.rs` | Low | Leaf memory management. MmapArea is self-contained, BindingLiveState is atomic-only. |
| 6 | `rst.rs` | Low | nftables + NAT exclusion code. Only called from build_forwarding_state (install) and main.rs (remove). |
| 7 | `forwarding.rs` | Medium | Largest extraction (~4,500 lines with tests). Forwarding resolution functions form a cohesive unit consuming ForwardingState + route types. `build_forwarding_state()` naturally belongs here. |
| 8 | `tunnel.rs` | Medium | Depends on forwarding + bpf_map functions (accessed via super::*). Must be done after steps 4, 6, 7. |

## Challenges and Solutions

### 1. `debug_log!` macro
Used in `poll_binding()` and `tunnel.rs`. Rust requires macros to be defined before use. **Solution:** Define in `afxdp.rs` before the `mod` declarations. Child modules see it via `super::debug_log!`.

### 2. Shared test fixtures
`forwarding_snapshot()`, `native_gre_snapshot()`, `policy_deny_snapshot()`, etc. are used by multiple test functions. **Solution:** Keep shared fixtures in `afxdp.rs`'s `#[cfg(test)] mod tests` block. Tests in `forwarding.rs` can import them via `use super::tests::forwarding_snapshot`. Alternatively, create a `#[cfg(test)] mod test_fixtures` in `afxdp.rs`.

### 3. `FastMap`/`FastSet` type aliases
Used everywhere as `type FastMap<K,V> = FxHashMap<K,V>`. **Solution:** Move to `types.rs`.

### 4. Cross-module access
`tunnel.rs` needs functions from `forwarding.rs` and `bpf_map.rs`. **Solution:** All modules are children of `afxdp.rs`. `tunnel.rs` uses `use super::*` which pulls in all re-exported items from sibling modules. This is the same pattern existing submodules (frame.rs, session_glue.rs) already use.

### 5. Public API preservation
`main.rs` imports `Coordinator`, `NeighborEntry`, `SyncedSessionEntry`, `ForwardingResolution`, `ForwardingDisposition`, `remove_kernel_rst_suppression`, `parse_mac_str`, `neighbor_state_usable_str`. **Solution:** Explicit `pub use` re-exports in `afxdp.rs` (shown above). Import paths in `main.rs` and `session.rs` are unchanged.

## Final File Layout

```
userspace-dp/src/
  afxdp.rs              ~11,100 lines  (was 20,138 — 45% smaller)
  afxdp/
    types.rs               ~900 lines  ← NEW
    forwarding.rs        ~4,500 lines  ← NEW (incl. ~3K tests)
    bpf_map.rs             ~570 lines  ← NEW
    umem.rs                ~650 lines  ← NEW
    neighbor.rs            ~650 lines  ← NEW
    checksum.rs            ~230 lines  ← NEW
    rst.rs                 ~850 lines  ← NEW
    tunnel.rs              ~380 lines  ← NEW
    bind.rs                  385 lines  (existing)
    frame.rs               4,209 lines  (existing)
    gre.rs                   410 lines  (existing)
    icmp.rs                  233 lines  (existing)
    icmp_embed.rs            761 lines  (existing)
    session_glue.rs        3,632 lines  (existing)
    tx.rs                    790 lines  (existing)
```

Total: 16 submodule files + parent. No single file exceeds ~11K lines. The hot path (`poll_binding`) stays in one place for performance reasoning.

## Verification

After each step:
```bash
cd userspace-dp && cargo build --release && cargo test
```

After all 8 steps:
```bash
make build && cargo test           # unit tests
make cluster-deploy                # integration test on HA cluster
make test-failover                 # failover validation
```
