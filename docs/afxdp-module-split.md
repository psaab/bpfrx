# Plan: Split `afxdp.rs` into Defined Modules

## Problem

`userspace-dp/src/afxdp.rs` started at 20,138 lines and mixed together:

- coordinator lifecycle and worker orchestration
- AF_XDP hot-path processing
- forwarding/config compilation
- BPF map helpers
- UMEM helpers
- neighbor dump/monitor/probe helpers
- tunnel and RST helpers
- a very large mixed test body

That made review, navigation, and refactoring unnecessarily expensive.

## Goal

Split the monolith into focused modules with clear responsibility boundaries, no public API churn, and test-equivalent behavior.

## Current Layout

```text
userspace-dp/src/
  afxdp.rs              8,459 lines
  afxdp/
    bind.rs               385 lines
    bpf_map.rs            577 lines
    checksum.rs           156 lines
    forwarding.rs       3,891 lines
    frame.rs            8,175 lines
    gre.rs                410 lines
    icmp.rs               233 lines
    icmp_embed.rs         761 lines
    neighbor.rs           651 lines
    rst.rs                169 lines
    session_glue.rs     3,632 lines
    test_fixtures.rs      662 lines
    tunnel.rs             360 lines
    tx.rs                 790 lines
    types.rs              650 lines
    umem.rs               632 lines
```

## What Was Missing From The Original Plan

The original split plan correctly identified the helper clusters, but it understated two remaining sources of size in `afxdp.rs`:

1. shared forwarding/runtime types that were still entangled with helper code
2. the large forwarding-heavy and frame/rewrite-heavy test clusters

Those are now addressed.

## What Is Done

### Production/helper code extracted

These modules are now real and wired through `afxdp.rs`:

- `types.rs`
  - shared aliases, metadata, forwarding/runtime structs, request/response structs, worker commands
- `forwarding.rs`
  - forwarding/config compilation, HA enforcement, fabric redirect selection, route/neighbor lookup helpers
- `bpf_map.rs`
  - XSK/session/heartbeat/BPF map helpers
- `umem.rs`
  - UMEM ownership, binding live state, debug state updates
- `neighbor.rs`
  - neighbor dump, monitor, probe, and netlink parsing helpers
- `checksum.rs`
  - checksum helpers and DNAT publish helpers
- `rst.rs`
  - kernel RST suppression helpers
- `tunnel.rs`
  - local tunnel origination helpers

### Shared test fixtures extracted

`test_fixtures.rs` now carries the reusable snapshot/build helpers that were previously embedded in the middle of `afxdp.rs` tests.

### Forwarding-heavy tests moved

The forwarding-heavy test cluster now lives in `forwarding.rs`, including:

- metadata classification
- HA/fabric redirect behavior
- inactive-owner resolution
- local-delivery resolution on miss
- policy and route resolution
- neighbor-learning and forwarding-resolution behavior
- TX binding resolution

### Frame/rewrite-heavy tests moved

The frame/rewrite-heavy test cluster now lives in `frame.rs`, including:

- session-flow parsing
- native GRE frame/decap/encap coverage
- rewrite descriptor application
- SNAT/DNAT checksum preservation
- forwarded-frame build/rewrite coverage
- TCP segmentation and authoritative port checks

## What Still Lives In `afxdp.rs`

What remains in `afxdp.rs` is there for structural reasons, not because the split stalled:

- `Coordinator` lifecycle/orchestration
- `BindingWorker`, `poll_binding()`, `worker_loop()`, and the tightly-coupled hot-path helper cluster
- session/coordinator/runtime-heavy tests
- static NAT, ICMP slow-path, and a small set of mixed runtime tests that still rely on monolith-local state

At this point the file is no longer a helper grab-bag. It is primarily the runtime shell around the dataplane.

## Reduction Achieved

- `afxdp.rs`: `20,138 -> 8,459`
- reduction: about `58%`

That is enough to change the file from “largest-file bottleneck” to “runtime entry point plus residual tests”.

## Dependency Shape

```text
afxdp.rs
  ├── types.rs
  ├── checksum.rs
  ├── neighbor.rs
  ├── bpf_map.rs
  ├── umem.rs
  ├── rst.rs
  ├── forwarding.rs
  ├── tunnel.rs
  └── existing focused submodules
      ├── bind.rs
      ├── frame.rs
      ├── gre.rs
      ├── icmp.rs
      ├── icmp_embed.rs
      ├── session_glue.rs
      └── tx.rs
```

The important boundary is now real:

- helper/leaf code lives in submodules
- hot-path orchestration lives in `afxdp.rs`
- forwarding-heavy tests live with forwarding code
- frame/rewrite-heavy tests live with frame code

## Re-export Strategy

The parent file still wildcard-imports the split modules so existing child modules using `use super::*` continue to work.

That preserved internal call sites without forcing a larger import-path rewrite as part of the split.

## Verification

These checks passed after the split work:

```bash
cargo fmt --manifest-path userspace-dp/Cargo.toml --all
cargo test --manifest-path userspace-dp/Cargo.toml --no-run
cargo test --manifest-path userspace-dp/Cargo.toml
```

Current Rust test result:

- `388 passed, 0 failed`

## Remaining Optional Work

The core split plan is complete.

Only follow-on cleanup remains if we want even more reduction:

1. move the remaining session/coordinator-heavy test clusters out of `afxdp.rs`
2. decide whether any hot-path helper groups inside `poll_binding()` should be peeled further without harming locality/readability
3. validate the refactor on the userspace HA cluster as a structure-preserving deployment

Those are cleanup/validation steps, not blockers for the module split itself.
