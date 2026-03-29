# Plan: Split afxdp.rs into Defined Modules

## Problem

`userspace-dp/src/afxdp.rs` started at 20,138 lines — the largest file in the codebase. It contains the entire AF_XDP userspace dataplane: coordinator lifecycle, worker threads, the packet processing hot loop, forwarding resolution, BPF map operations, UMEM management, neighbor monitoring, checksum helpers, and 8,775 lines of tests.

Seven submodules already exist in `afxdp/` (bind, frame, gre, icmp, icmp_embed, session_glue, tx — 10,420 lines total), but the parent file is still too large to navigate, reason about, or review diffs in.

## Goal

Split into focused modules with clear responsibilities, minimal cross-dependencies, and no public API changes. Each extraction step is independently compilable and testable.

## Current Layout

```
userspace-dp/src/
  afxdp.rs              14,794 lines  ← still the monolith, but production helpers are now split out
  afxdp/
    bind.rs                385 lines  (XSK socket binding strategies)
    bpf_map.rs             577 lines  (BPF map helpers)
    checksum.rs            156 lines  (checksum helpers + DNAT publish)
    frame.rs             4,209 lines  (packet frame building/parsing)
    forwarding.rs        2,145 lines  (forwarding resolution + config compilation)
    gre.rs                 410 lines  (GRE encap/decap)
    icmp.rs                233 lines  (ICMP generation)
    icmp_embed.rs          761 lines  (embedded ICMP NAT reversal)
    neighbor.rs            651 lines  (neighbor dump/monitor/probes)
    rst.rs                 169 lines  (RST suppression helpers)
    session_glue.rs      3,632 lines  (session table + demotion prepare)
    tunnel.rs              360 lines  (local tunnel origination)
    tx.rs                  790 lines  (TX ring submission)
    types.rs               650 lines  (shared dataplane types and forwarding structs)
    umem.rs                632 lines  (UMEM + binding live state)
```

### What's still in the monolith

- `Coordinator` lifecycle and orchestration
- `BindingWorker`, `poll_binding()`, `worker_loop()`, and the hot-path helper cluster that stays tightly coupled to packet processing
- mixed frame/dataplane tests and shared test fixtures
- a small number of packet-processing helpers that are still intentionally colocated with the hot loop

## Current Extraction Status

Implemented and compile-checked:

- `checksum.rs`
- `neighbor.rs`
- `bpf_map.rs`
- `rst.rs`
- `tunnel.rs`
- `umem.rs`
- `types.rs`
  - `FastMap` / `FastSet`
  - `UserspaceDpMeta`
  - `XdpOptions`
  - `PendingNeighPacket`
  - `FlowCache`, `FlowCacheEntry`, `RewriteDescriptor`
  - `BindingIdentity`, `WorkerBindingLookup`
  - `WorkerHandle`, `LocalTunnelSourceHandle`, `BindingPlan`
  - `PacketDisposition`, `ValidationState`
  - `SessionFlow`, `ResolutionDebug`
  - `TxRequest`, `PendingForwardRequest`, `PreparedTxRequest`, `PreparedTxRecycle`
  - `LocalTunnelTxPlan`, `LearnedNeighborKey`
  - `WorkerCommand`, `DebugPollCounters`
  - `ForwardingState`, `ForwardingResolution`, `ForwardingDisposition`
  - `FabricLink`, `HAGroupRuntime`
- `forwarding.rs`
  - `classify_metadata()`
  - `build_screen_profiles()`
  - `build_forwarding_state()`
  - route/neighbor selection helpers
  - HA enforcement helpers
  - fabric redirect selection
  - local-delivery/session-miss forwarding helpers
  - forwarding lookup and tunnel-resolution helpers

What the original plan missed:

- the remaining shared worker/forwarding types were already good candidates for `types.rs` and are now moved
- the production forwarding/config compilation code was the real remaining extraction
- the forwarding-heavy test cluster still lives in `afxdp.rs`; that is now an optional follow-on, not a blocker for the helper-module split

Current reduction:

- `afxdp.rs`: `20,138 -> 14,794`
- reduction so far: about `26.5%`

## Proposed Module Structure

### Implemented modules in `afxdp/`:

| Module | ~Lines | Responsibility |
|--------|--------|----------------|
| **`types.rs`** | 650 | Shared structs, enums, aliases, and dataplane metadata. Includes forwarding/runtime structs that were still pending in the earlier draft. |
| **`forwarding.rs`** | 2,145 | Route resolution and config compilation. `build_forwarding_state()`, `build_screen_profiles()`, `classify_metadata()`, forwarding lookup, tunnel resolution, HA enforcement, and fabric redirect logic. |
| **`bpf_map.rs`** | 750 | BPF map CRUD operations. XSK slot register/delete, heartbeat touch/update helpers, `OwnedFd`, session-map key helpers, publish/delete/verify/dump, `read_fallback_stats()`, `diagnose_raw_ring_state()`. Standalone unsafe FFI — clear boundary. |
| **`umem.rs`** | 700 | Memory management. `MmapArea` + Drop, `WorkerUmemInner`, `WorkerUmem`, `WorkerUmemPool`, `BindingLiveState` (60+ atomic counters for per-binding stats), `update_binding_debug_state()`. Leaf types with no internal dependencies. |
| **`neighbor.rs`** | 950 | Neighbor discovery and monitoring. `neigh_monitor_thread()` (background netlink listener), initial neighbor dump/update helpers, kernel ARP/NDP probe helpers (`trigger_kernel_arp_probe`, `add_kernel_neighbor_probe`, `add_kernel_neighbor`), `parse_mac_str()`, `neighbor_state_usable_str()`, `send_raw_frame()`, `insert_vlan_tag()`, `monotonic_nanos()`, `monotonic_timestamp_to_datetime()`. Includes MAC parsing tests. |
| **`checksum.rs`** | 260 | Checksum computation and DNAT BPF publish helpers. `compute_ip_csum_delta()`, `compute_l4_csum_delta()`, `ipv4_csum_words()`, `publish_dnat_table_entry()`. Pure functions plus the DNAT helper. |
| **`rst.rs`** | 850 | TCP RST suppression via nftables + NAT local exclusions. `install_kernel_rst_suppression()`, `remove_kernel_rst_suppression()` (pub(crate)), `nat_translated_local_exclusions()`. |
| **`tunnel.rs`** | 380 | Local tunnel origination. `local_tunnel_source_loop()`, tunnel TX request building, local tunnel session enqueue/wait, TUN device helpers. |

### What stays in `afxdp.rs` now (~14,800 lines):

- Module declarations + `use self::X::*` re-exports
- `pub struct Coordinator` + `impl Coordinator` — orchestrates everything
- `BindingWorker` and the AF_XDP hot loop (`poll_binding()`)
- `worker_loop()` and the tightly-coupled packet-processing helper cluster
- the mixed test fixture and test body section

The split plan is complete for helper/production code. The remaining bulk is hot-loop code and tests, not misplaced utility modules.

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
| 1 | `types.rs` | Done | Shared worker/forwarding types landed here. |
| 2 | `checksum.rs` | Done | DNAT/checksum helpers extracted. |
| 3 | `neighbor.rs` | Done | Netlink dump/monitor/probe helpers extracted. |
| 4 | `bpf_map.rs` | Done | BPF/session/heartbeat helpers extracted. |
| 5 | `umem.rs` | Done | UMEM and binding live-state extracted. |
| 6 | `rst.rs` | Done | RST suppression helpers extracted. |
| 7 | `forwarding.rs` | Done | Forwarding/config compilation extracted. |
| 8 | `tunnel.rs` | Done | Local tunnel origination extracted. |

Optional follow-on, if we want to reduce `afxdp.rs` further:

- split the forwarding-heavy tests and fixtures into `forwarding.rs`
- split the mixed frame/rewrite tests into `frame.rs`
- only after that consider whether `poll_binding()` itself should be carved up further

## Challenges and Solutions

### 1. `debug_log!` macro
Used in `poll_binding()` and `tunnel.rs`. Rust requires macros to be defined before use. **Solution:** Define in `afxdp.rs` before the `mod` declarations. Child modules see it via `super::debug_log!`.

### 2. Shared test fixtures
`forwarding_snapshot()`, `native_gre_snapshot()`, `policy_deny_snapshot()`, etc. are used by multiple test functions. **Solution:** Keep shared fixtures in `afxdp.rs`'s `#[cfg(test)] mod tests` block. Tests in `forwarding.rs` can import them via `use super::tests::forwarding_snapshot`. Alternatively, create a `#[cfg(test)] mod test_fixtures` in `afxdp.rs`.

### 2a. Helper clusters the original plan missed
The monolith has a few cohesive helper groups that should move with the leaf modules even though they were not called out explicitly in the original summary:

- `types.rs`
  - `UserspaceDpMeta`, `XdpOptions`, `PendingNeighPacket`, `WorkerHandle`, `LocalTunnelSourceHandle`, `BindingPlan`, `ValidationState`, `PacketDisposition`, `BindingIdentity`, `WorkerBindingLookup`, `SessionFlow`, `ResolutionDebug`, `TxRequest`, `PendingForwardRequest`, `PreparedTxRequest`, `PreparedTxRecycle`, `LocalTunnelTxPlan`, `LearnedNeighborKey`, `DebugPollCounters`
- `neighbor.rs`
  - `trigger_kernel_arp_probe()`, `add_kernel_neighbor_probe()`, `add_kernel_neighbor()`, `update_dynamic_neighbor()`, `remove_dynamic_neighbor()`, `parse_neighbor_msg()`, `request_neighbor_dump()`, `initial_neighbor_dump()`
- `bpf_map.rs`
  - `update_heartbeat_slot()`, `delete_xsk_slot()`, `delete_heartbeat_slot()`, `maybe_touch_heartbeat()`, `touch_heartbeat()`, `heartbeat_fresh()`, `UserspaceSessionMapKey`, `session_map_key()`, `publish_session_map_key()`, `publish_live_session_key()`, `publish_kernel_local_session_key()`, `publish_live_session_entry()`, `verify_session_key_in_bpf()`, `count_bpf_session_entries()`, `dump_bpf_session_entries()`, `delete_live_session_key()`, `delete_live_session_entry()`

If these stay in `afxdp.rs`, the file still carries most of the helper sprawl even after the main extractions. That gap is now closed: the helper clusters above are moved, and what remains is the hot path plus tests.

### 3. `FastMap`/`FastSet` type aliases
Used everywhere as `type FastMap<K,V> = FxHashMap<K,V>`. **Solution:** Move to `types.rs`.

### 4. Cross-module access
`tunnel.rs` needs functions from `forwarding.rs` and `bpf_map.rs`. **Solution:** All modules are children of `afxdp.rs`. `tunnel.rs` uses `use super::*` which pulls in all re-exported items from sibling modules. This is the same pattern existing submodules (frame.rs, session_glue.rs) already use.

### 5. Public API preservation
`main.rs` imports `Coordinator`, `NeighborEntry`, `SyncedSessionEntry`, `ForwardingResolution`, `ForwardingDisposition`, `remove_kernel_rst_suppression`, `parse_mac_str`, `neighbor_state_usable_str`. **Solution:** Explicit `pub use` re-exports in `afxdp.rs` (shown above). Import paths in `main.rs` and `session.rs` are unchanged.

## Final File Layout

```
userspace-dp/src/
  afxdp.rs              14,794 lines
  afxdp/
    types.rs               650 lines
    forwarding.rs        2,145 lines
    bpf_map.rs             ~577 lines  ← NEW
    umem.rs                ~632 lines  ← NEW
    neighbor.rs            ~651 lines  ← NEW
    checksum.rs            ~156 lines  ← NEW
    rst.rs                 ~169 lines  ← NEW
    tunnel.rs              ~360 lines  ← NEW
    bind.rs                  385 lines  (existing)
    frame.rs               4,209 lines  (existing)
    gre.rs                   410 lines  (existing)
    icmp.rs                  233 lines  (existing)
    icmp_embed.rs            761 lines  (existing)
    session_glue.rs        3,632 lines  (existing)
    tx.rs                    790 lines  (existing)
```

Total: 16 submodule files + parent. The helper-module split is complete. The remaining large file is large because it still owns the hot path and the mixed test body, not because helper code is stranded there.

## Verification

After each step:
```bash
cd userspace-dp && cargo build --release && cargo test
```

Recommended implementation checkpoints:
```bash
cargo fmt --manifest-path userspace-dp/Cargo.toml --all
cargo test --manifest-path userspace-dp/Cargo.toml --no-run
```

After all 8 steps:
```bash
make build && cargo test           # unit tests
make cluster-deploy                # integration test on HA cluster
make test-failover                 # failover validation
```
