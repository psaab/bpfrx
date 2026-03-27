# Plan: Split afxdp.rs into Defined Modules

## Problem

`userspace-dp/src/afxdp.rs` is 19,329 lines — the largest file in the codebase. It contains the entire AF_XDP userspace dataplane: coordinator lifecycle, worker threads, the packet processing hot loop, forwarding resolution, BPF map operations, UMEM management, neighbor monitoring, checksum helpers, and 8,400 lines of tests.

Seven submodules already exist in `afxdp/` (bind, frame, gre, icmp, icmp_embed, session_glue, tx — 9,204 lines total), but the parent file is still too large to navigate, reason about, or review diffs in.

## Goal

Split into focused modules with clear responsibilities, minimal cross-dependencies, and no public API changes. Each extraction step is independently compilable and testable.

## Current Layout

```
userspace-dp/src/
  afxdp.rs              19,329 lines  ← the monolith
  afxdp/
    bind.rs                368 lines  (XSK socket binding strategies)
    frame.rs             4,213 lines  (packet frame building/parsing)
    gre.rs                 410 lines  (GRE encap/decap)
    icmp.rs                233 lines  (ICMP generation)
    icmp_embed.rs          753 lines  (embedded ICMP NAT reversal)
    session_glue.rs      2,437 lines  (session table operations)
    tx.rs                  790 lines  (TX ring submission)
```

### What's in the 19K-line monolith

| Line Range | ~Lines | Section |
|------------|--------|---------|
| 1-534 | 534 | Imports, constants, FlowCache, RewriteDescriptor, PendingNeighPacket, checksum helpers, DNAT table helpers |
| 535-1778 | 1,244 | `pub struct Coordinator` + `impl Coordinator` — orchestrator lifecycle |
| 1780-2700 | 922 | Worker types: WorkerHandle, BindingPlan, ForwardingState, ForwardingResolution, BindingWorker, WorkerUmem, SessionFlow, WorkerCommand, etc. |
| 2700-5115 | 2,413 | `poll_binding()` — THE hot loop for RX/TX processing per worker |
| 5115-5778 | 662 | Worker helpers: retry_neigh, build_live_forward, learn_neighbor, flush_session_deltas |
| 5780-6574 | 795 | `worker_loop()` — worker thread main entry point |
| 6576-6955 | 380 | `local_tunnel_source_loop()` + tunnel helpers |
| 6955-7575 | 622 | Utilities: monotonic_nanos, kernel neighbor probes, VLAN insert, raw frame send, neigh_monitor_thread |
| 7577-8020 | 443 | classify_metadata, build_screen_profiles, `build_forwarding_state()` |
| 8021-8206 | 186 | RST suppression (nftables), NAT local exclusions |
| 8207-9753 | 1,547 | Forwarding resolution (~30 functions: route lookup, connected routes, tunnel resolution, fabric redirect) |
| 9755-9957 | 203 | XSK/heartbeat BPF map helpers |
| 9959-10319 | 361 | OwnedFd, session map operations (publish/delete/verify/dump) |
| 10320-10903 | 584 | MmapArea (mmap wrapper), BindingLiveState (60+ atomic counters) |
| 10905-19329 | 8,425 | Tests (156 test functions) |

## Proposed Module Structure

### 8 new modules in `afxdp/`:

| Module | ~Lines | Responsibility |
|--------|--------|----------------|
| **`types.rs`** | 950 | All shared structs, enums, constants. ForwardingState, ForwardingResolution, ForwardingDisposition, BindingWorker, WorkerUmem types, FlowCache, SessionFlow, HAGroupRuntime, route/neighbor/egress types, protocol constants, FastMap/FastSet aliases. Foundation for everything else. |
| **`forwarding.rs`** | 4,600 | Route resolution and config compilation. `build_forwarding_state()`, `build_screen_profiles()`, `classify_metadata()`, all ~30 `lookup_forwarding_resolution*` functions, connected route matching, tunnel resolution, fabric redirect logic. Includes ~3,000 lines of forwarding tests. |
| **`bpf_map.rs`** | 570 | BPF map CRUD operations. XSK slot register/delete, heartbeat touch, session map publish/delete/verify/dump, `read_fallback_stats()`, `diagnose_raw_ring_state()`. Standalone unsafe FFI — clear boundary. |
| **`umem.rs`** | 600 | Memory management. `MmapArea` + Drop, `WorkerUmemInner`, `WorkerUmem`, `WorkerUmemPool`, `BindingLiveState` (60+ atomic counters for per-binding stats), `update_binding_debug_state()`. Leaf types with no internal dependencies. |
| **`neighbor.rs`** | 750 | Neighbor discovery and monitoring. `neigh_monitor_thread()` (background netlink listener), kernel ARP/NDP probe functions, `parse_mac_str()`, `neighbor_state_usable_str()`, `send_raw_frame()`, `insert_vlan_tag()`, `monotonic_nanos()`. Includes ~100 lines of MAC parsing tests. |
| **`checksum.rs`** | 180 | Checksum computation. `compute_ip_csum_delta()`, `compute_l4_csum_delta()`, `ipv4_csum_words()`, `publish_dnat_table_entry()`. 4 pure functions with no side effects. |
| **`rst.rs`** | 190 | TCP RST suppression via nftables. `install_kernel_rst_suppression()`, `remove_kernel_rst_suppression()` (pub(crate)), `nat_translated_local_exclusions()`. Small, well-isolated. |
| **`tunnel.rs`** | 380 | Local tunnel origination. `local_tunnel_source_loop()`, tunnel TX request building, local tunnel session enqueue/wait, TUN device helpers. |

### What stays in `afxdp.rs` (~10,400 lines):

- Module declarations + `use self::X::*` re-exports
- `pub struct Coordinator` + `impl Coordinator` (~1,244 lines) — orchestrates everything
- `poll_binding()` (~2,413 lines) — the hot loop, touches every module
- `worker_loop()` (~795 lines) — thread entry point
- Worker helpers (retry_neigh, build_live_forward, learn_neighbor, flush_session_deltas) (~662 lines)
- TCP MSS clamping, IcmpTeRateLimiter (~130 lines)
- ~5,000 lines of tests that exercise poll_binding/frame building

**Result: 19,329 → 10,400 lines (46% reduction)**

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
  ├── forwarding.rs     ← uses types (largest extraction, ~30 functions)
  ├── tunnel.rs         ← uses types + forwarding + bpf_map (via super::*)
  │
  └── [existing submodules]
      ├── bind.rs           (XSK binding strategies)
      ├── frame.rs          (packet frame building — 4,213 lines)
      ├── gre.rs            (GRE encap/decap)
      ├── icmp.rs           (ICMP generation)
      ├── icmp_embed.rs     (embedded ICMP NAT reversal)
      ├── session_glue.rs   (session table operations — 2,437 lines)
      └── tx.rs             (TX ring submission)
```

No circular dependencies. All new modules are leaves except `tunnel.rs` which depends on siblings through `use super::*`.

## Migration Order

Each step is a single commit, independently compilable and testable with `cargo build --release && cargo test`.

| Step | Module | Risk | Rationale |
|------|--------|------|-----------|
| 1 | `types.rs` | Zero | Pure data types with trivial impls. Foundation for every subsequent step. No logic to break. |
| 2 | `checksum.rs` | Zero | 4 pure functions, no callers outside afxdp. Trivial extraction. |
| 3 | `neighbor.rs` | Low | Self-contained netlink + MAC helpers. Clear boundary: only Coordinator and worker_loop call these. |
| 4 | `bpf_map.rs` | Low | Standalone unsafe FFI for BPF map operations. Used by Coordinator, worker_loop, session_glue. |
| 5 | `umem.rs` | Low | Leaf memory management. MmapArea is self-contained, BindingLiveState is atomic-only. |
| 6 | `rst.rs` | Low | Small nftables code. Only called from build_forwarding_state (install) and main.rs (remove). |
| 7 | `forwarding.rs` | Medium | Largest extraction (~4,600 lines with tests). The ~30 forwarding resolution functions form a cohesive unit consuming ForwardingState + route types. `build_forwarding_state()` naturally belongs here. |
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
  afxdp.rs              ~10,400 lines  (was 19,329 — 46% smaller)
  afxdp/
    types.rs               ~950 lines  ← NEW
    forwarding.rs        ~4,600 lines  ← NEW (incl. 3K tests)
    bpf_map.rs             ~570 lines  ← NEW
    umem.rs                ~600 lines  ← NEW
    neighbor.rs            ~750 lines  ← NEW
    checksum.rs            ~180 lines  ← NEW
    rst.rs                 ~190 lines  ← NEW
    tunnel.rs              ~380 lines  ← NEW
    bind.rs                  368 lines  (existing)
    frame.rs               4,213 lines  (existing)
    gre.rs                   410 lines  (existing)
    icmp.rs                  233 lines  (existing)
    icmp_embed.rs            753 lines  (existing)
    session_glue.rs        2,437 lines  (existing)
    tx.rs                    790 lines  (existing)
```

Total: 16 submodule files + parent. No single file exceeds ~10K lines. The hot path (`poll_binding`) stays in one place for performance reasoning.

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
