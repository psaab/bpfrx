# agy-review-171 — Wide Modularity & Refactor Campaign

**Reviewer:** agy (Antigravity 2.0). **Mode:** modularity and refactor campaign per `do-review-refactor-audit.txt`.
**Directive:** audit the codebase for monolithic code, including oversized files, god-functions, god-structs, dumping-ground enums, and mixed responsibilities, with a focus on separating cold config/setup/stats/logging out of the per-packet hot path while preserving line-rate forwarding performance.

---

## 1. Base Commit Reviewed

`34f1c7eccc509ee844d62b01aebae556fba41c41` — "Merge pull request #4416 from psaab/fix/4379-scan-cleanup-window" (tip of `origin/master`). Verified against a clean checkout of `origin/master`.

---

## 2. Output Path

- Primary System Output: `/tmp/agy-review-171.md`
- Artifact Log: `file:///home/ps/.gemini/antigravity-cli/brain/ab5238f0-1350-4e31-9217-9c0cca51a910/agy-review-171.md`

---

## 3. Duplicate-Suppression Summary

To ensure maximum signal value and avoid overlaps, we audited this campaign against all prior campaign reviews in `/tmp/`:
- `fable-review-001.md`, `fable-review-002.md`, and `fable-review-161.md` through `fable-review-171.md` (which focused heavily on day-0 zone policies, application matching, host-inbound lists, and reth drop-ins).
- `avo-review-001.md`, `avo-review-002.md`, and `avo-review-007.md` (which focused on cryptographic security and session isolation).
- `codex-review-001.md`, `codex-review-002.md`, `codex-review-121.md` through `codex-review-164.md` (which focused on NAT prefix mapping, BPF manager, VRRP track interfaces, and tunnel re-mapping).
- `ps-review-007.md` through `ps-review-011.md` (which focused on HA failover, PBR bypass, and initial Rust/Go splits).
- `opus-review-171.md` (which focused on screens, NAT pool collision, and IPsec passthrough).

**New Baseline Sync:**
We verified that several critical refactor and bug-fix proposals from recent campaigns have recently been merged into `master`:
- **Commit #4405** (strict validator split) has successfully decomposed the 7,000 LOC `compiler_validate_strict.go` into domain-specific validator files (policy, NAT, filter, screens, etc.). Finding `AGY-171-10` builds on this by addressing the remaining compile/validate boundaries in `compiler_nat.go`.
- **Commit #4399** (NAT 1:N multimap) has resolved the single-value session collision bug in `nat_reverse_index`. Finding `AGY-171-03` focuses on the remaining architectural splits of `SessionTable` (separating HA/limit/stats), which remain unaddressed.
All findings below are confirmed to be active, outstanding modularity issues on the current `master` branch.

---

## 4. File-Size / Shape Inventory

We ran LOC sweeps across both Rust and Go domains to identify compilation units and structs exceeding modularity thresholds.

| File | LOC | Hot Path? | Responsibilities Fused | Modularity Rank |
| :--- | :--- | :--- | :--- | :--- |
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 5,760 | **YES** | Session hit/miss, NAT pre-routing, policy eval, host-local, install, telemetry, debug logging. | 1 |
| `userspace-dp/src/policy.rs` | 4,224 | **YES** | Policy parsing, CompiledApplications matching, Address Books, AppCatalog, SnapshotIntegrityError. | 2 |
| `userspace-dp/src/afxdp/poll_stages.rs` | 3,024 | **YES** | Pre-flow-cache classification, stage definitions, GRE decap, screen checks. | 3 |
| `userspace-dp/src/afxdp/forwarding/mod.rs` | 2,671 | **YES** | FIB LPM, table scoping, ECMP select, connected routing, tunnel endpoints. | 4 |
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | 2,058 | **YES** | CoS selection, waterfill, lease telemetry, DRR scheduling. | 5 |
| `userspace-dp/src/nat64.rs` | 2,047 | Warm | IPv4↔IPv6 translation, classification, checksum updates, fragment parsing. | 6 |
| `userspace-dp/src/session/mod.rs` | 1,959 | **YES** | Slab storage, NAT demux indexes, timer wheel, per-IP limits, HA delta sync. | 7 |
| `userspace-dp/src/afxdp/neighbor.rs` | 1,901 | Warm | ARP/NDP probing, Netlink socket monitoring, neighbor warmer thread. | 8 |
| `userspace-dp/src/afxdp/wg/engine.rs` | 1,763 | **YES** | WireGuard encap/decap fast path, peer config commit, handshakes. | 9 |
| `userspace-dp/src/afxdp/tx/dispatch/mod.rs` | 1,423 | **YES** | Ethernet rewrite, VLAN tag, NAT, checksum, WG/GRE tunnel, TCP GSO. | 10 |
| `userspace-dp/src/nat/source.rs` | 1,191 | **YES** | SNAT rules parse, scope match, linear pool allocation driver. | 11 |
| `userspace-dp/src/nat/destination.rs` | 1,088 | **YES** | DNAT prefix LPM tables, wildcard matching, scope evaluation. | 12 |
| `userspace-dp/src/filter/engine/eval.rs` | 1,026 | **YES** | Filter evaluations, PBR override, action logs, mirror replication. | 13 |
| `userspace-dp/src/nat/allocator.rs` | 927 | **YES** | PortAllocator, sequential cursors, BTreeSet expirations, FIFO recycle. | 14 |
| `pkg/config/compiler.go` | 4,337 | No | `compileExpanded` god-function, AST pre-walks, section compilation, validators. | 15 |
| `pkg/config/compiler_nat.go` | 2,485 | No | NAT compilation, source/dest/static translation blocks, validation. | 16 |
| `pkg/dataplane/userspace/manager.go` | 1,823 | No | Dataplane Manager, sync connection state, HA watchdogs, BPF maps sync. | 17 |
| `pkg/daemon/daemon_apply.go` | 1,884 | No | `applyConfigLocked` commit/rollback orchestrator, 20 subsystem reconciles. | 18 |

---

## 5. File-by-File Inspection Log

### 1. `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (5,760 LOC)
The absolute monolith of the Rust dataplane. The main entry point, `poll_binding_process_descriptor` (lines 585–5156, ~4,571 LOC), is a classic god-function. It fuses session hit processing, session miss processing, static NAT, DNAT, SNAT, policy verdict integration, firewall filtering, host-local delivery, event logging, and UMEM recycling. It violates the core HPC mandate of modularity and prevents targeted unit testing.

### 2. `userspace-dp/src/policy.rs` (4,224 LOC)
This file fuses three distinct domains: packet matching, config parsing, and telemetry. It also houses the `SnapshotIntegrityError` enum (line 16), which has ballooned to over 600 lines because it serves as the dumping ground for every parser and compiler error across policy, NAT, filter, and screen modules.

### 3. `userspace-dp/src/session/mod.rs` (1,959 LOC)
The `SessionTable` struct (lines 472–589) manages the connection tracking state. It has 27 fields and fuses 6 distinct responsibilities: slab storage, NAT demux indexes, timer wheel, session limit counters, HA delta replication, and stats. It also contains hot-path performance regressions: cloning `SessionMetadata` in `lookup_with_origin` performs an atomic increment on the inner `Arc<PolicyRuleCounter>` per packet.

### 4. `userspace-dp/src/afxdp/forwarding/mod.rs` (2,671 LOC)
Fuses FIB routing, table-scoped local delivery, ECMP next-hop selection, and connected routes. It also contains `ingress_route_table_override` (lines 1521–1642), which is a firewall filter PBR action that should live in the filter module. In the hot path, `canonical_route_table` performs a heap allocation via `DEFAULT_V4_TABLE.to_string()` on every packet when no table override is active.

### 5. `userspace-dp/src/afxdp/tx/dispatch/mod.rs` (1,423 LOC)
The TX counterpart to `poll_descriptor`. The `enqueue_pending_forwards` function (lines 125–1256, ~1,131 LOC) acts as a god-function for packet transmit, fusing Ethernet header rewrites, DSCP, VLAN, NAT, WireGuard/GRE tunnel encapsulation, TCP GSO segmentation, output filtering, and UMEM recycling.

### 6. `userspace-dp/src/afxdp/cos/queue_service/mod.rs` (2,058 LOC)
Contains the Class of Service (CoS) scheduling loop. `select_exact_cos_guarantee_queue_waterfill` (lines 926–1363, ~438 LOC) fuses waterfill pass 1/2 calculations with lease telemetry collection and debugging logs, interleaving cold telemetry overhead directly into the hot CoS fast path.

### 7. Go Control Plane: `compiler.go`, `compiler_nat.go`, `manager.go`, `daemon_apply.go`
Fuses Go-side compilation, AST tree walking, local daemon state management, and transaction reconciliation. `applyConfigLocked` (lines 546–1694) reconciles 20 different subsystems (FRR, IPsec, SNMP, DDNS, etc.) in a single monolithic block.

---

## 6. Findings

### High Confidence

#### AGY-171-01 · God-function `poll_binding_process_descriptor` fuses 15+ packet stages
- **Severity:** Critical (Extreme cognitive load, blocks unit testing, high compilation cost)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — crosses per-packet hot path)
- **Evidence:** `userspace-dp/src/afxdp/poll_descriptor/mod.rs:585-5156`
  ```rust
  pub(super) fn poll_binding_process_descriptor(
      binding: &mut BindingWorker,
      binding_index: usize,
      area: *const MmapArea,
      available: u32,
      sessions: &mut SessionTable,
      screen: &mut ScreenState,
      validation: ValidationState,
      now_ns: u64,
      now_secs: u64,
      ha_startup_grace_until_secs: u64,
      _worker_id: u32,
      conntrack_v4_fd: c_int,
      conntrack_v6_fd: c_int,
      worker_ctx: &WorkerContext,
      telemetry: &mut TelemetryContext,
  ) {
      let mut received = binding.xsk.rx.receive(available);
      // Fuses stage 1-11 pre-cache check, session lookup, hit path (400 LOC),
      // miss path (700 LOC), NAT, policy matching, local delivery, install, BPF.
  ```
- **Proposed Decomposition:**
  Create a subdirectory `userspace-dp/src/afxdp/poll_descriptor/stages/` and extract stages:
  - `session_hit.rs` (`fn stage_session_hit`): Handles hit-path packet accounting, DSCP updates, local delivery checks, TTL decrement, and transmit queuing.
  - `session_miss.rs` (`fn stage_session_miss`): Handles NAT pre-routing lookup, firewall filters, PBR, routing, screen, policy, SNAT, and session install.
  - `nat_pre_routing.rs` (`fn stage_nat_pre_routing`): Groups DNAT, NPTv6, and NAT64 pre-routing evaluations.
  - `host_local.rs`: Handles host-inbound traffic, loopback filters, and `junos-host` policy enforcement.
- **Hot-Path Preservation Analysis:**
  - **Inlining:** Mark all new sub-stage functions as `#[inline(always)]` to ensure LLVM compiles them back into a single flat assembly block, avoiding call/return register spilling.
  - **Zero Allocations:** Pass packet references (`&[u8]`) and the mutable context (`&mut PacketCtx` wrapping mutable local registers) by reference. No heap allocations (`Box`, `Vec`).
  - **Branch Optimization:** Group cold debug logs (`cfg(feature = "debug-log")`) into separate `#[cold] #[inline(never)]` functions to pull them out of the CPU instruction cache (icache) hot branch path.
- **Tests + Gate:**
  - `cargo test --lib afxdp::poll_descriptor` runs unit tests.
  - Integration gate: `make test` and `make test-failover`.
  - Disassembly Gate: `objdump -d target/release/xpf-dp` must match the hot-loop assembly exactly.
- **Why It Matters:** Fusing everything into a 4,500-line loop makes it impossible to write unit tests for isolated stages (e.g. testing DNAT logic without mocking the entire `BindingWorker` and `SessionTable`).
- **Fix Direction:**
  1. Extract `flowless` local delivery helpers to `flowless.rs`.
  2. Outline `debug-log` and telemetry increments to `telemetry_debug.rs` as `#[cold] #[inline(never)]`.
  3. Extract NAT pre-routing into `nat_pre_routing.rs`.
  4. Extract host local policy to `host_local.rs`.
  5. Refactor the rest into `session_hit.rs` and `session_miss.rs` using a shared `PacketCtx` struct to bypass mutable-locals compiler blocks.
- **Labels:** `refactor`, `hot-path`, `poll-descriptor`, `god-function`, `x-hpc`
- **Dedup Note:** Building on #1327 (flow-cache hit extraction). Prior sweeps noted the size but did not trace the mutable-locals mitigation (`PacketCtx`) needed to allow full decomposition.

---

#### AGY-171-02 · `SnapshotIntegrityError` is a cross-domain dumping ground enum (616 LOC)
- **Severity:** High (High coupling, forces policy module to depend on NAT/filter/screen errors)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — cold config path, but error variants are shared with Go)
- **Evidence:** `userspace-dp/src/policy.rs:16-632`
  ```rust
  pub(crate) enum SnapshotIntegrityError {
      DuplicateRuleId { rule_id: String },
      UnrepresentableApplicationProtocol { protocol: String },
      // NAT errors:
      Nptv6UnparseableRule { rule: String },
      // Filter errors:
      UnrepresentableFilterProtocol { protocol: String },
      // ... 30+ variants spanning multiple unrelated domains
  }
  ```
- **Proposed Decomposition:**
  - Move policy error variants to a new enum `PolicySnapshotError` in `userspace-dp/src/policy/snapshot.rs`.
  - Move NAT/NPTv6 error variants to `NatSnapshotError` in `userspace-dp/src/nat/snapshot.rs`.
  - Move Filter error variants to `FilterSnapshotError` in `userspace-dp/src/filter/snapshot.rs`.
  - Re-define `SnapshotIntegrityError` in `userspace-dp/src/lib.rs` (or `snapshot.rs`) as a clean wrapper that delegates to domain-specific error enums via `From` implementations.
- **Hot-Path Preservation Analysis:**
  - **N/A (Cold Path):** This error type is only used during configuration apply / commit checks.
  - **Go Error Parity:** The Go control plane parses error strings produced by `SnapshotIntegrityError`'s `Display` implementation. The new domain-specific error strings must match the old ones byte-for-byte.
- **Tests + Gate:**
  - `cargo test --lib policy`, `cargo test --lib nat` verification.
  - Go gate: `go test ./pkg/dataplane/userspace/...` parses Rust apply errors.
- **Why It Matters:** Adding a simple validation error to the filter compiler requires editing the main firewall policy engine file (`policy.rs`), causing merge conflicts.
- **Fix Direction:**
  1. Extract `PolicySnapshotError` first.
  2. Implement `From<PolicySnapshotError> for SnapshotIntegrityError` to preserve the outer compiler interface.
  3. Repeat incrementally for `NatSnapshotError` and `FilterSnapshotError`.
- **Labels:** `refactor`, `coupling`, `policy`, `parser`, `cold-path`
- **Dedup Note:** Flagged as a monolith in prior campaigns, but specific decomposition via domain-error nesting and string-matching constraints was not detailed.

---

#### AGY-171-03 · `SessionTable` is a 27-field god-struct fusing 6 concerns
- **Severity:** High (L1 dcache pressure, high maintenance overhead)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — connection tracking hot path)
- **Evidence:** `userspace-dp/src/session/mod.rs:472-589`
  ```rust
  pub(crate) struct SessionTable {
      pub(super) entries: Slab<SessionRecord>,
      pub(super) key_to_handle: SeededKeyMap<u32>,
      // NAT indexes:
      pub(super) nat_reverse_index: SeededKeyMap<SmallVec<[u32; 2]>>,
      // HA sync:
      pub(super) deltas: VecDeque<SessionDelta>,
      pub(super) epoch_counter: u64,
      // Limits:
      pub(super) session_limit_active: bool,
      // ... 27 fields
  }
  ```
- **Proposed Decomposition:**
  - **Keep Core Together (D-Class):** Keep `entries`, `key_to_handle`, and the NAT reverse indexes in the core table struct to maintain cache line locality during flow lookup.
  - **Extract HA Replication:** Move all delta queues and sync epochs to a nested `session/ha.rs` module.
  - **Extract IP Limits:** Move `session_limit_src_counts` and limit checks to `session/limit.rs`.
- **Hot-Path Preservation Analysis:**
  - **Eliminate Arc Clone:** Eliminate the hot-path regression where `lookup_with_origin` clones the full `SessionMetadata` (including the inner atomic `Arc<PolicyRuleCounter>`), which causes bus locks (`LOCK XADD`) on every packet. Change the lookup to return indices or non-Arc borrows.
  - **Inlining:** Keep limit checking and index manipulation functions marked `#[inline]` within the `crate::session` boundary.
- **Tests + Gate:**
  - `cargo test -p userspace-dp session::` (191 tests).
  - Integration gate: `make test-failover` to verify HA standby state replication.
- **Why It Matters:** Mixing cold HA sync queues with the hot packet lookup table increases the `SessionTable` memory footprint, causing CPU cache misses at high packet rates.
- **Fix Direction:**
  1. Fix the `metadata.clone()` Arc overhead on packet hit (`lookup.rs`).
  2. Extract limit counting to `session/limit.rs` with `#[inline]` gates.
  3. Extract HA delta queues and standby state machine to `session/ha.rs`.
- **Labels:** `refactor`, `session`, `hot-path`, `performance`, `ha`, `x-hpc`
- **Dedup Note:** Resolves the remaining structure cleanup left over after `#4399` (which made `nat_reverse_index` a multimap but did not split the struct).

---

#### AGY-171-04 · `ForwardingState` fuses hot FIB with cold config; PBR lives in forwarding
- **Severity:** High (Fuses routing instance filters into routing lookup, causing unnecessary imports)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — security table scoping)
- **Evidence:** `userspace-dp/src/afxdp/types/forwarding.rs:14-278` and `userspace-dp/src/afxdp/forwarding/mod.rs:1521-1642`
  ```rust
  // ingress_route_table_override in forwarding/mod.rs:
  pub(crate) fn ingress_route_table_override(
      forwarding: &ForwardingState,
      packet_frame: &[u8],
      meta: UserspaceDpMeta,
  ) -> Option<String> {
      // PBR uses filter state and evaluates rules, which belongs in filter module
  ```
- **Proposed Decomposition:**
  - Move the PBR firewall filter override logic (`ingress_route_table_override`) out of `forwarding/mod.rs` and place it in the `filter` module (`filter/pbr.rs`).
  - Document and group hot fields (routes, local tables, interface maps) first in `ForwardingState` to separate them from cold config fields (fabrics, screens, mirrors).
- **Hot-Path Preservation Analysis:**
  - **Eliminate Heap Allocations:** In `canonical_route_table`, replace the heap-allocating `DEFAULT_V4_TABLE.to_string()` call with a static `&str` reference or an interned token lookup to avoid allocating memory per packet on table misses.
  - **Preserve Security Scoping:** The VRF isolation and table-scoped local delivery checks (`owned_here` and connected-route scopes) must remain in the fast path to prevent route leakage across VRFs.
- **Tests + Gate:**
  - `cargo test -p userspace-dp forwarding` covers table scoping, ECMP, and PBR.
  - Gate: `make test-failover` ensures VRF routing remains correct.
- **Why It Matters:** PBR is fundamentally a firewall filter action (`then routing-instance`). Placing it in the forwarding module couples the FIB routing table with filters, logging, and AppID, and introduces a hot-path heap allocation.
- **Fix Direction:**
  1. Fix the `to_string()` allocation in `canonical_route_table`.
  2. Move `ingress_route_table_override` to `filter/pbr.rs` and update imports.
  3. Reorder `ForwardingState` fields so that hot per-packet tables sit on the first cache lines.
- **Labels:** `refactor`, `forwarding`, `pbr`, `allocation`, `x-hpc`
- **Dedup Note:** Forwarding monoliths and PBR coupling were not flagged in prior campaigns.

---

#### AGY-171-05 · TX drain orchestrator `enqueue_pending_forwards` is 1,131 LOC
- **Severity:** High (High icache footprint, UMEM recycle leakage risk)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — per-packet TX hot path)
- **Evidence:** `userspace-dp/src/afxdp/tx/dispatch/mod.rs:125-1256`
  ```rust
  pub(in crate::afxdp) fn enqueue_pending_forwards(
      binding: &mut BindingWorker,
      area: *const MmapArea,
      sessions: &mut SessionTable,
      now_ns: u64,
      worker_id: u32,
      // Fuses Ethernet rewrite, VLAN tag, NAT, checksum, WG/GRE, TCP GSO, and stats
  ```
- **Proposed Decomposition:**
  Keep `enqueue_pending_forwards` as a clean, high-level dispatcher (<150 LOC) that delegates to specialized inline submodules under `tx/dispatch/`:
  - `phase_build.rs` (`build_plain`, `build_wireguard`, `build_gre`): Performs header rewrites and tunnel encapsulation.
  - `phase_segment.rs`: Houses GSO TCP segmentation.
  - `phase_mirror.rs`: Handles packet mirroring.
  - Outline exception logging and fallback metrics into `#[cold] #[inline(never)]` functions.
- **Hot-Path Preservation Analysis:**
  - **Monomorphization over Dyn Traits:** Encapsulation dispatch must remain a flat `match` on the tunnel ID rather than using a trait object (`Box<dyn Encapsulation>`), which would add virtual table lookup overhead.
  - **Inlining:** Mark packet rewrite builders as `#[inline(always)]`.
  - **UMEM Recycle Invariant:** Ensure every early-return path correctly recycles the UMEM descriptor to prevent memory leaks under stress.
- **Tests + Gate:**
  - `cargo test -p userspace-dp tx::dispatch` runs single-recycle checks using `FORCE_OVERSIZED` fault injections.
  - Integration gate: CoS smoke tests and `make test`.
- **Why It Matters:** Fusing encapsulation, segmentation, and error logging into a single massive function bloats the CPU instruction cache, increasing instruction-level cache misses at 10Gbps line rate.
- **Fix Direction:**
  1. Extract encapsulation building (Phase 8) to `phase_build.rs` as inline functions.
  2. Outline fallback telemetry to cold helpers.
  3. Extract GSO TCP segmentation to `phase_segment.rs`.
  4. Thin `enqueue_pending_forwards` to a flat loop.
- **Labels:** `refactor`, `tx-path`, `tunnel`, `icache`, `x-hpc`
- **Dedup Note:** Confirmed the location of the 1,100+ line TX monolith noted in the engineering standards.

---

#### AGY-171-06 · CoS queue selection `select_exact_cos_guarantee_queue_waterfill` is 438 LOC
- **Severity:** Medium (Fairness auditability, telemetry overhead in fast path)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — CoS scheduling)
- **Evidence:** `userspace-dp/src/afxdp/cos/queue_service/mod.rs:926-1363`
  ```rust
  fn select_exact_cos_guarantee_queue_waterfill(
      runtime: &mut CoSQueueRuntime,
      backlog: &SharedCoSExactBacklog,
      now_ns: u64,
      // Fuses waterfill iterations, refund calculations, and logging
  ```
- **Proposed Decomposition:**
  - Move the waterfill pass 1 and pass 2 calculations to `cos/queue_service/select_waterfill.rs`.
  - Move lease tracking and lease acquisition telemetry to `cos/queue_service/lease.rs`.
  - Outline park logging and reason counters into `#[cold]` helper functions.
- **Hot-Path Preservation Analysis:**
  - **No Allocations:** The waterfill algorithm uses stack-allocated bitmasks and arrays. No heap collections (`Vec`, `HashMap`) can be introduced.
  - **Struct Alignment:** Keep `#[repr(align(64))]` on CoS runtime and backlog structs to prevent CPU bus locking from false sharing.
- **Tests + Gate:**
  - `cargo test -p userspace-dp cos_queue_service`.
  - Gate: `cargo test fairness` to verify scheduling correctness.
- **Why It Matters:** Class of Service scheduling must run within strict nanosecond budgets. Interleaving verbose logging and telemetry calculations inside the waterfill loops degrades scheduler efficiency.
- **Fix Direction:**
  1. Extract waterfill pass logic to `select_waterfill.rs` keeping bitwise operations `#[inline(always)]`.
  2. Move lease state logic to `lease.rs`.
  3. Move parking logs to `#[cold]` helpers.
- **Labels:** `refactor`, `cos`, `scheduler`, `waterfill`, `x-hpc`
- **Dedup Note:** Prior work split drain and submit hooks, but did not address the inner waterfill scheduler function itself.

---

#### AGY-171-09 · `pkg/config/compiler.go:compileExpanded` is 2,435 LOC
- **Severity:** High (High cognitive load, blocks unit testing of AST modifications)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — cold path, but must preserve validation order)
- **Evidence:** `pkg/config/compiler.go:1901-4336`
  ```go
  func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
      // Fuses AST sanitization, typed Config initialization, switch compilation
      // for 10+ sections, and 60+ strict validation calls.
  ```
- **Proposed Decomposition:**
  Decompose `compileExpanded` into semantic phases inside `pkg/config/compile_phases.go`:
  - `runASTPreWalks`: Gathers all AST-level checks and expansions.
  - `newEmptyConfig`: Standardizes empty struct construction.
  - `compileSections`: Dispatches AST parsing to domain compilers.
  - `runStrictValidators`: Groups and dispatches validators (in identical order).
- **Hot-Path Preservation Analysis:**
  - **N/A (Cold Path):** Runs only at commit time.
  - **Error Precedence:** Keep validator execution order identical so that the first check to fail produces the expected error message, matching tests.
- **Tests + Gate:**
  - `go test ./pkg/config/...` runs compiler tests.
- **Why It Matters:** AST tree expansions (e.g. interface ranges) are mixed with schema checks and section builders, making it impossible to unit test a new AST expansion in isolation.
- **Fix Direction:**
  1. Move AST walks to `runASTPreWalks`.
  2. Move config initialization to `newEmptyConfig`.
  3. Move section builders to `compileSections`.
  4. Move validation calls to `runStrictValidators`.
- **Labels:** `refactor`, `compiler`, `config-apply`, `cold-path`
- **Dedup Note:** Go-side compiler structures were not flagged in prior campaigns.

---

#### AGY-171-10 · `pkg/config/compiler_nat.go` is a 2,485 LOC NAT compiler monolith
- **Severity:** High (Blocks modular testing of NAT compile phases, merge conflict magnet)
- **Confidence:** High
- **Refactor Class:** A (Mechanical/Safe — cold path)
- **Evidence:** `pkg/config/compiler_nat.go`
  ```go
  func compileNAT(node *Node, sec *SecurityConfig) error {
      // Fuses compileNATSource (500 LOC), compileNATDestination (220 LOC),
      // compileNATStatic (170 LOC), NPTv6, NAT64, and validation.
  ```
- **Proposed Decomposition:**
  Split by translation family into separate files under `pkg/config/`:
  - `compiler_nat_source.go`: Houses source NAT compilation.
  - `compiler_nat_destination.go`: Houses destination NAT compilation.
  - `compiler_nat_static.go`: Houses static 1:1 NAT compilation.
  - `compiler_nat_validate.go`: Houses helper validation checks.
- **Hot-Path Preservation Analysis:**
  - **N/A (Cold Path):** Runs only at commit time. No fast path impact.
- **Tests + Gate:**
  - `go test ./pkg/config -run TestCompile` to check compiler correctness.
- **Why It Matters:** Fusing source, destination, and static NAT compilation into one file leads to constant merge conflicts when different developers modify unrelated translation rules.
- **Fix Direction:**
  1. Move source NAT compiler functions to `compiler_nat_source.go`.
  2. Move destination NAT compiler to `compiler_nat_destination.go`.
  3. Move static NAT compiler to `compiler_nat_static.go`.
- **Labels:** `refactor`, `compiler`, `nat`, `cold-path`
- **Dedup Note:** Builds on strict validator split (#4405) by cleaning up compilation units.

---

#### AGY-171-11 · `pkg/dataplane/userspace/manager.go` is a 1,823 LOC god-struct
- **Severity:** High (Tight coupling of lifecycle, RPC, and BPF maps)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — state management)
- **Evidence:** `pkg/dataplane/userspace/manager.go:150-294`
  ```go
  type DataplaneManager struct {
      // 60+ fields mixing:
      // - snapshot state (lastSnapshot, routeOverlay)
      // - HA synchronizers (haGroups, watchdog)
      // - BPF counters and map files
      // - neighbor and ARP monitors
  }
  ```
- **Proposed Decomposition:**
  Decompose `DataplaneManager` into nested helper components:
  - `SnapshotManager`: Builds and applies routing/NAT snapshots.
  - `HAController`: Manages election state and watchdogs.
  - `BPFSyncer`: Manages BPF map updates and counter polls.
  - `NeighborWatcher`: Monitors Netlink ARP changes.
  The main manager struct becomes a facade delegating to these sub-components.
- **Hot-Path Preservation Analysis:**
  - **N/A (Cold Path):** Manages control plane configurations only.
- **Tests + Gate:**
  - `go test ./pkg/dataplane/userspace/...` to verify control plane manager.
- **Why It Matters:** Mixing HA watchdog code with BPF maps and Netlink monitors makes the manager highly fragile and difficult to mock during tests.
- **Fix Direction:**
  1. Group BPF counters and move to `BPFSyncer`.
  2. Group HA state and move to `HAController`.
  3. Refactor snapshot compilation to `SnapshotManager`.
- **Labels:** `refactor`, `manager`, `dataplane`, `cold-path`
- **Dedup Note:** Prior work split `manager_ha.go`, but left the core struct and other subsystems combined in `manager.go`.

---

#### AGY-171-12 · Go Daemon struct is a 3,500 LOC god-struct
- **Severity:** High (Extreme cognitive load, locks down system initialization)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — core lifecycle)
- **Evidence:** `pkg/daemon/daemon.go`
  ```go
  type Daemon struct {
      // Fuses config store, cluster sync, gRPC servers, DDNS, DHCP, SNMP,
      // LLDP, IPFIX, routing monitors, and telemetry alerts.
  }
  ```
- **Proposed Decomposition:**
  Extract dedicated daemon subsystem managers:
  - `ConfigReconciler`: Listens for CLI commits and compiles configurations.
  - `ServicesManager`: Coordinates DDNS, DHCP, SNMP, and LLDP lifecycles.
  - `FlowExporter`: Coordinates IPFIX logging.
  The daemon struct retains only service start/stop orchestration.
- **Hot-Path Preservation Analysis:**
  - **N/A (Cold Path):** Controls daemon management threads.
- **Tests + Gate:**
  - `go test ./pkg/daemon/...` runs daemon tests.
- **Why It Matters:** A change to the DHCP server configuration apply path requires editing the global `Daemon` coordinator struct, coupling network services together.
- **Fix Direction:**
  1. Move DDNS and DHCP managers to `ServicesManager`.
  2. Extract IPFIX export logic to `FlowExporter`.
  3. Move commit listeners to `ConfigReconciler`.
- **Labels:** `refactor`, `daemon`, `lifecycle`, `cold-path`
- **Dedup Note:** Go daemon layout has not been refactored in prior campaigns.

---

#### AGY-171-13 · Daemon configuration apply `applyConfigLocked` is a 1,883 LOC monolith
- **Severity:** High (Risk of transaction rollback leaks, hard to audit)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — commit-confirmed rollbacks)
- **Evidence:** `pkg/daemon/daemon_apply.go:546-1694`
  ```go
  func (d *Daemon) applyConfigLocked(ctx context.Context, cfg *config.Config) error {
      // Reconciles SNMP, then interface config, FRR, IPsec, DHCP, DNS,
      // DDNS, LLDP, flow export, scheduler, NAT alarms, and confirmed rollback.
  }
  ```
- **Proposed Decomposition:**
  Decompose `applyConfigLocked` into structured compilation phases utilizing an `ApplyContext` transaction struct:
  - `PhaseCompile`: Validates and compiles AST.
  - `PhaseActuateNetwork`: Reconciles networkd and virtual interfaces.
  - `PhaseReconcileServices`: Reconciles daemon services (DHCP, SNMP, DDNS).
  - `PhaseHACommit`: Confirms standby peer synchronization.
- **Hot-Path Preservation Analysis:**
  - **N/A (Cold Path):** Configuration transaction only.
- **Tests + Gate:**
  - `go test ./pkg/daemon -run TestApply` runs config transaction checks.
- **Why It Matters:** If a service fails to start during configuration apply, the daemon must perform a rollback. Combining all rollbacks into one 1,800-line block makes it difficult to verify that resources are not leaked on failure.
- **Fix Direction:**
  1. Define `ApplyContext` and extract AST compile.
  2. Extract network actuation phase.
  3. Extract service reconciliation hooks.
  4. Extract rollback cleanup functions.
- **Labels:** `refactor`, `daemon`, `transaction`, `cold-path`
- **Dedup Note:** Monolith noted in engineering standards; this defines the specific phase and rollback split.

---

#### AGY-171-14 · SNAT parses, matches, and allocates in one file `nat/source.rs`
- **Severity:** Medium (Fuses hot packet matching with cold config parsing)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — hot new flow path)
- **Evidence:** `userspace-dp/src/nat/source.rs:861-1138`
  ```rust
  pub(crate) fn match_source_nat_result_for_tuple(...) -> SourceNatLookup {
      for rule in rules {
          if !rule.matches(...) { continue; }
          // Fuses linear prefix scan, PortAllocator Mutex lock, and failure log
  ```
- **Proposed Decomposition:**
  Decompose the file into three modules under `userspace-dp/src/nat/`:
  - `snat_rule.rs`: Defines configuration structs and parsing logic (`parse_source_nat_rules_with_previous`).
  - `snat_match.rs`: Hot lookup path (`match_source_nat_result_for_tuple`, `rule.matches`).
  - `snat_alloc.rs`: Cold allocation lifecycle (releases, rollbacks).
- **Hot-Path Preservation Analysis:**
  - **Inlining:** Mark `matches` and `l4_matches` as `#[inline]` to preserve fast path matching speeds.
  - **No Allocations:** The matching driver must remain allocation-free. Failure warnings (`SourceNatFailure::for_rule`) must only perform String clones on cold error branches.
- **Tests + Gate:**
  - `cargo test nat --lib` (runs 232 NAT tests).
- **Why It Matters:** Mixing configuration parsing with packet-matching logic increases the risk of adding slow helper functions or allocations directly into the new-flow fast path.
- **Fix Direction:**
  1. Move parser functions to `snat_rule.rs`.
  2. Move release/rollback lifecycle to `snat_alloc.rs`.
  3. Keep only the matching loop in `snat_match.rs`.
- **Labels:** `refactor`, `nat`, `snat`, `hot-path`, `x-hpc`
- **Dedup Note:** Follows the initial extraction from `nat.rs` but targets the sub-module itself.

---

#### AGY-171-15 · `PortAllocator` fuses hot allocation with cold persistent leases and GC
- **Severity:** Medium (Mutex locking contention, persistent lease tracking complexity)
- **Confidence:** High
- **Refactor Class:** C (Performance-Positive — isolates hot lock states)
- **Evidence:** `userspace-dp/src/nat/allocator.rs:124-185`
  ```rust
  pub(super) struct PortAllocatorLiveState {
      live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
      owner_by_translated: FxHashMap<TranslatedTuple, AllocationOwner>,
      // Cold lease state mixed in:
      pub(super) lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
  }
  ```
- **Proposed Decomposition:**
  - Rename `allocator.rs` to `nat/pool.rs` to reflect that it manages translation pools.
  - Split `PortAllocatorLiveState` into:
    - `LiveStateHot`: Contains active maps, offsets, and FIFO queues.
    - `LiveStateCold`: Contains persistent lease state and `BTreeSet` expirations.
  - Move garbage collection to `pool_gc.rs` and status outputs to `pool_status.rs`.
- **Hot-Path Preservation Analysis:**
  - **Minimize Lock Contention:** The hot allocation path (`allocate_translation`) must acquire the mutex for as short a duration as possible. Isolating GC checks and lease updates to a cold path reduces lock hold times.
  - **Inlining:** Ensure `allocate_translation` is marked `#[inline]`.
- **Tests + Gate:**
  - `cargo test nat --lib` checks allocation bounds and expirations.
- **Why It Matters:** The GC sweep is called directly inside the hot allocation path, forcing every 8th packet to block while scanning the `BTreeSet` under a shared mutex lock.
- **Fix Direction:**
  1. Split `LiveState` into hot and cold sub-structs.
  2. Outline GC functions to `pool_gc.rs` and mark them `#[cold]`.
  3. Move persistent lease handling to `pool_lease.rs`.
- **Labels:** `refactor`, `nat`, `port-allocator`, `mutex`, `performance`, `x-hpc`
- **Dedup Note:** Not flagged in prior campaigns.

---

#### AGY-171-16 · `nat64.rs` fuses IPv6 header translation with prefix classification
- **Severity:** Medium (Fuses per-packet translation with control-plane config checks)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — hot header rewrite)
- **Evidence:** `userspace-dp/src/nat64.rs:749-1100`
  ```rust
  pub(crate) fn write_v6_to_v4_into(...) {
      // Fuses classification (RFC 6052), header translation, ICMP mapping,
      // and checksum recalculation.
  }
  ```
- **Proposed Decomposition:**
  Split `nat64.rs` into a module directory `nat/nat64/`:
  - `mod.rs`: Handles rule classification and prefix checking.
  - `translate.rs`: Handles packet header rewrites (v4↔v6).
  - `icmp.rs`: Handles RFC 7915 ICMP translation.
  - `checksum.rs`: Performs checksum updates.
- **Hot-Path Preservation Analysis:**
  - **Frame Allocation:** NAT64 header changes require rewriting the IP header size (40B ↔ 20B), forcing a frame buffer copy. Ensure this copy releases the original UMEM frame to prevent leaks.
  - **Inlining:** Mark header translation helper functions as `#[inline]`.
- **Tests + Gate:**
  - `cargo test nat64_tests` runs translation checks.
- **Why It Matters:** Mixing RFC 6052 prefix checks with raw frame buffer writes makes the NAT64 engine complex and prone to packet parser buffer overflows.
- **Fix Direction:**
  1. Extract prefix classification to `mod.rs`.
  2. Extract translation methods to `translate.rs`.
  3. Extract ICMP mappings to `icmp.rs`.
- **Labels:** `refactor`, `nat64`, `translation`, `hot-path`, `x-hpc`
- **Dedup Note:** Confirmed the codebase location of the NAT64 monolith.

---

#### AGY-171-19 · `afxdp/neighbor.rs` fuses Netlink socket polling, probing, and CPU pinning
- **Severity:** High (Fuses background Netlink threads with fast path probing)
- **Confidence:** High
- **Refactor Class:** B (Requires Guardrails — unresolved next-hop ARP triggers)
- **Evidence:** `userspace-dp/src/afxdp/neighbor.rs:158-290`
  ```rust
  pub(super) fn trigger_kernel_arp_probe(iface_name: &str, ifindex: i32, target: IpAddr) {
      // Fuses thread-local socket cache lookup, raw socket creation, and ICMP echo.
  ```
- **Proposed Decomposition:**
  Decompose `neighbor.rs` into a directory module `afxdp/neighbor/`:
  - `probe.rs`: Handles raw socket caching and `trigger_kernel_arp_probe` (hot path).
  - `netlink.rs`: Runs the background Netlink event loop to monitor ARP state changes.
  - `warmer.rs`: Runs the periodic ARP warming background thread.
  - `cpu.rs`: Moves generic CPU core pinning helpers to `afxdp/cpu.rs`.
- **Hot-Path Preservation Analysis:**
  - **Allocation-Free Probing:** Probing unresolved next-hops occurs in the packet processing path. Probing must remain allocation-free by utilizing thread-local raw sockets instead of opening new sockets per packet.
  - **Inlining:** Mark `trigger_kernel_arp_probe` as `#[inline]`.
- **Tests + Gate:**
  - `cargo test neighbor::` runs ARP tests.
- **Why It Matters:** Mixing background Netlink thread management with raw packet probing makes the neighbor resolver difficult to test and introduces risks of thread leaks.
- **Fix Direction:**
  1. Move CPU pinning helpers to `cpu.rs`.
  2. Extract Netlink thread loop to `netlink.rs`.
  3. Extract the warming thread loop to `warmer.rs`.
  4. Keep only probing in `probe.rs`.
- **Labels:** `refactor`, `neighbor`, `arp`, `netlink`, `cpu-pinning`, `x-hpc`
- **Dedup Note:** Neighbor monolith was not flagged in prior campaigns.

---

### Medium Confidence

#### AGY-171-07 · `AppCatalog` and directional lookup should be extracted from `policy.rs`
- **Severity:** Medium (Config compilation noise in policy matching engine)
- **Confidence:** Medium
- **Refactor Class:** B (Requires Guardrails — AppID lookup)
- **Evidence:** `userspace-dp/src/policy.rs:1953-2224`
  ```rust
  impl AppCatalog {
      pub(crate) fn from_snapshot(entries: &[crate::AppCatalogEntry]) -> Self { ... }
      pub(crate) fn lookup_directional(...) -> u16 { ... }
  }
  ```
- **Proposed Decomposition:**
  Move `AppCatalog` and AppID catalog management to a dedicated submodule `policy/app_catalog.rs`.
- **Hot-Path Preservation Analysis:**
  - **N/A (Session Install Path):** AppID lookup only runs during session installation (session miss), not on the per-packet hot path.
- **Tests + Gate:**
  - `cargo test --lib policy` verified.
- **Why It Matters:** AppID metadata catalog management is unrelated to firewall zone policy matching but occupies 300 LOC in `policy.rs`, increasing compilation noise.
- **Fix Direction:**
  1. Create `policy/app_catalog.rs` and move `AppCatalog`.
- **Labels:** `refactor`, `policy`, `appid`, `catalog`
- **Dedup Note:** Identified as a separate compilation unit split from `policy.rs`.

---

#### AGY-171-08 · Extract `PolicyCounterStore` and parse phases from `policy.rs`
- **Severity:** Medium (Fuses counter store synchronization with policy compilation)
- **Confidence:** Medium
- **Refactor Class:** B (Requires Guardrails — atomic counters)
- **Evidence:** `userspace-dp/src/policy.rs:1391-1674` and `2519-3041`
  ```rust
  pub(crate) fn parse_policy_state_with_counters(...)
  // Fuses address book validation, rule parsing, and counter creation (500 LOC).
  ```
- **Proposed Decomposition:**
  - Move `PolicyRuleCounter` and thread-local counter flushing to `policy/counter.rs`.
  - Split `parse_policy_state_with_counters` into phase helpers: `build_books`, `parse_rules`, and `link_counters`.
- **Hot-Path Preservation Analysis:**
  - **Atomic Counters:** Counter increments use thread-local batching. Ensure the refactored counter store does not introduce cross-thread locks or global atomic counters.
- **Tests + Gate:**
  - `cargo test --lib policy` checks policy counters.
- **Why It Matters:** Policy parsing is 500 lines of complex validation logic that obscures the actual packet matching implementation.
- **Fix Direction:**
  1. Move counter structs to `policy/counter.rs`.
  2. Extract rules parsing phases into helper functions.
- **Labels:** `refactor`, `policy`, `counters`, `parser`
- **Dedup Note:** Detailed split of policy compilation phases.

---

#### AGY-171-17 · `filter/compiler.rs` parses, validates, and links in one file
- **Severity:** Medium (Fuses parsing with rule validation)
- **Confidence:** Medium
- **Refactor Class:** C (Performance-Positive — cleans compile boundaries)
- **Evidence:** `userspace-dp/src/filter/compiler.rs:425-850`
  ```rust
  fn parse_term(...) -> Result<FilterTerm, SnapshotIntegrityError> {
      // Fuses prefix-set compilation, port range parsing, and action mapping
  ```
- **Proposed Decomposition:**
  Split `filter/compiler.rs` into:
  - `filter/compile/parse.rs`: Parses snapshot terms.
  - `filter/compile/validate.rs`: Validates actions and ranges.
  - `filter/compile/link.rs`: Binds policers and logging.
- **Hot-Path Preservation Analysis:**
  - **N/A (Cold Path):** Runs only at config commit time.
- **Tests + Gate:**
  - `cargo test filter::` checks filter compilation.
- **Why It Matters:** Changing a firewall filter action validator recompiles the entire parser module, increasing incremental compile times.
- **Fix Direction:**
  1. Extract validation logic to `validate.rs`.
  2. Move linking logic to `link.rs`.
- **Labels:** `refactor`, `filter`, `compiler`, `cold-path`
- **Dedup Note:** Not flagged in prior campaigns.

---

#### AGY-171-18 · `filter/engine/eval.rs` fuses output filters, PBR, and log matches
- **Severity:** Medium (Fuses PBR routing instances with filter evaluations)
- **Confidence:** Medium
- **Refactor Class:** C/D (Requires Guardrails — hot lookup path)
- **Evidence:** `userspace-dp/src/filter/engine/eval.rs:30-1026`
  ```rust
  pub(crate) fn evaluate_filter(...) {
      // Fuses standard filters, PBR overrides, and action log events
  }
  ```
- **Proposed Decomposition:**
  Split `filter/engine/eval.rs` into:
  - `filter/engine/eval.rs`: Core evaluation loop.
  - `filter/engine/pbr.rs`: PBR action overrides.
  - `filter/engine/log.rs`: Gathers log matches and event formatting.
- **Hot-Path Preservation Analysis:**
  - **Inlining:** Mark `evaluate_filter` as `#[inline(always)]`.
  - **No Allocations:** Log matching must only set boolean flags; do not format event strings in the fast path.
- **Tests + Gate:**
  - `cargo test filter::` runs evaluation tests.
- **Why It Matters:** PBR actions and log event formatting are distinct from basic permit/deny evaluation, but they are all inlined in the same evaluation file.
- **Fix Direction:**
  1. Move PBR action execution to `pbr.rs`.
  2. Move log event preparation to `log.rs`.
- **Labels:** `refactor`, `filter`, `eval`, `hot-path`, `x-hpc`
- **Dedup Note:** Complements the PBR move from the forwarding module.

---

#### AGY-171-20 · `afxdp/wg/engine.rs` fuses hot encap/decap with cold peer syncs
- **Severity:** Medium (Fuses packet encryption with peer config sync)
- **Confidence:** Medium
- **Refactor Class:** B (Requires Guardrails — packet encryption)
- **Evidence:** `userspace-dp/src/afxdp/wg/engine.rs:1206-1378`
  ```rust
  fn encap_inner(...) {
      // Fuses peer routing, snow crypto write, and peer configuration sync
  ```
- **Proposed Decomposition:**
  - Extract cold peer configuration sync (`reconcile_peers`) and SA installations to `afxdp/wg/control.rs`.
  - Retain `encap_inner` and `try_decap` in `engine.rs` as hot-path operations.
- **Hot-Path Preservation Analysis:**
  - **Zero Copy / Stack Cryptography:** Encryption uses stack-allocated buffers. No heap allocations are allowed in the crypto path.
  - **Lock-Free Peers:** Peer lookups must utilize read locks (`RwLock::read`) or RCU pointer swaps to avoid blocking packet workers.
- **Tests + Gate:**
  - `cargo test wg::` runs encryption tests.
- **Why It Matters:** Peer configuration updates (e.g. adding a new peer) run under the same compilation unit as the packet encryption loops, increasing compile times and risk of lock contention.
- **Fix Direction:**
  1. Move peer reconciler to `control.rs`.
  2. Keep hot encap/decap in `engine.rs`.
- **Labels:** `refactor`, `wireguard`, `encryption`, `x-hpc`
- **Dedup Note:** Complements prior WireGuard refactors.

---

### Low Confidence / Do-not-split (D-Class)

The following components are large, but their responsibilities are structurally unified. Splitting them would introduce indirection, pointer chasing, or register spilling that would violate the dataplane's line-rate performance contract. They are marked **DO NOT SPLIT**.

#### AGY-171-21 · GRE tunnel encap/decap `gre.rs` (961 LOC)
- **Modularity Warning:** **DO NOT SPLIT**.
- **Evidence:** `userspace-dp/src/gre.rs`
- **Reasoning:**
  Although `gre.rs` contains both encapsulation and decapsulation logic, they share core GRE packet parsing helpers, checksum update algorithms, and ECN combining routines. Splitting this file by direction (encap vs decap) would duplicate code or create a shared utility module, adding indirection without any maintainability benefit. It is cohesive and must remain a single module.
- **Labels:** `do-not-split`, `tunnel`, `gre`

#### AGY-171-22 · ScreenState orchestrator `screen/mod.rs` (1,479 LOC)
- **Modularity Warning:** **DO NOT SPLIT**.
- **Evidence:** `userspace-dp/src/screen/mod.rs`
- **Reasoning:**
  `screen/mod.rs` has already been decomposed into sub-files (e.g. `packet.rs`, `rate.rs`, `syncookie.rs`). The central coordinator `check_packet_with_zone_id_opts` coordinates 16 distinct stateless and stateful check predicates. Further splitting would fragment the coordination logic across files, increasing call overhead on session misses without reducing complexity.
- **Labels:** `do-not-split`, `screen`, `security`

#### AGY-171-23 · `BindingWorker` state struct (1,615 LOC)
- **Modularity Warning:** **DO NOT SPLIT**.
- **Evidence:** `userspace-dp/src/afxdp/worker/mod.rs`
- **Reasoning:**
  The `BindingWorker` struct has already been split into logical sub-components (`WorkerXskRings`, `WorkerTxPipeline`, etc.). The remaining struct serves as the single unified allocation holding a worker thread's state. Splitting it further would force worker threads to reference separate allocations via pointers, causing CPU L1/L2 data cache misses and pointer-chasing overhead.
- **Labels:** `do-not-split`, `cache-locality`, `performance`

#### AGY-171-24 · `stage_flow_cache_hit` fast path (457 LOC)
- **Modularity Warning:** **DO NOT SPLIT**.
- **Evidence:** `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs`
- **Reasoning:**
  This function handles the cache hit path, which processes over 90% of packets. It is large because it inlines Ethernet rewriting, TTL decrements, and packet forwarding. Splitting this pipeline into separate functions would degrade compiler inlining, cause register spills, and reduce packet throughput. Modularity must be sacrificed here for performance.
- **Labels:** `do-not-split`, `hot-path`, `flow-cache`, `performance`

#### AGY-171-25 · `evaluate_policy_result_l3_aware` policy matcher (191 LOC)
- **Modularity Warning:** **DO NOT SPLIT**.
- **Evidence:** `userspace-dp/src/policy.rs:3393-3584`
- **Reasoning:**
  This is the core policy matching engine. It is written as a clean, branchless linear scan over compiled rules, using only stack-allocated variables and atomic updates. It does not perform any heap allocations or logging. It is a model of high-performance systems engineering. Any attempt to introduce polymorphic policy matches or split this function would degrade performance.
- **Labels:** `do-not-split`, `hot-path`, `exemplary`

#### AGY-171-26 · `ForwardingResolution` POD struct (9 LOC)
- **Modularity Warning:** **DO NOT SPLIT**.
- **Evidence:** `userspace-dp/src/afxdp/types/forwarding.rs:930-941`
- **Reasoning:**
  A simple Plain-Old-Data (POD) struct that encapsulates forwarding verdicts. It is passed by value and fits entirely within registers. Splitting it into subclasses or adding indirection would prevent the compiler from passing it in CPU registers, increasing stack usage.
- **Labels:** `do-not-split`, `pod`, `performance`

---

## 7. Suggested Issue Split

To safely implement these refactoring proposals, we recommend executing them in three distinct, sequential phases:

### Phase 1 — Mechanical & Performance-Positive Fixes (No Hot-Path Risk)
1. **Fix `canonical_route_table` Allocation (C):** Replace `DEFAULT_V4_TABLE.to_string()` with a static `&str` reference to eliminate heap allocation in the forwarding path.
2. **Fix `SessionTable` Arc Cloning (A):** Change `SessionLookup` to store raw integer indices instead of cloning `SessionMetadata` with its inner `Arc<PolicyRuleCounter>`, eliminating `LOCK XADD` atomic instructions.
3. **Move `SnapshotIntegrityError` (B):** Extract domain-specific error enums (`PolicySnapshotError`, `NatSnapshotError`) and implement `From` conversions to preserve the Go/Rust apply contract.
4. **Extract `flowless` Helpers (A):** Move flowless transit helpers out of `poll_descriptor/mod.rs` into a separate `flowless.rs` module.

### Phase 2 — Subsystem Refactoring (Cold & Session-Miss Paths Only)
5. **Extract Go NAT Compiler (A):** Split `compiler_nat.go` into source, destination, and static NAT compilation units.
6. **Decompose Go `compileExpanded` (B):** Extract AST pre-walks, Config initialization, and strict validation loops into phase helpers.
7. **Extract Go Dataplane Manager (B):** Group HA, BPF syncer, and ARP watchers into helper structs inside `manager.go`.
8. **Extract `AppCatalog` from `policy.rs` (B):** Move catalog and directional lookups to `policy/app_catalog.rs`.
9. **Split `policy.rs` Counters (B):** Extract `PolicyRuleCounter` and rule compilation phases.
10. **Extract SNAT Lifecycle (B):** Split `nat/source.rs` into `snat_rule.rs` (parsing) and `snat_alloc.rs` (releases).
11. **Split `PortAllocator` (C):** Separate hot bitmap tracking from cold GC and persistent lease tracking.
12. **Split NAT64 (B):** Extract NAT64 translations and ICMP mapping into a `nat/nat64/` subdirectory.
13. **Decompose `neighbor.rs` (B):** Split neighbor monitoring and CPU pinning from raw ARP probing.

### Phase 3 — Hot-Path Refactoring (Requires High-Performance Guardrails)
14. **Move PBR Actions to Filter (B):** Move `ingress_route_table_override` out of `forwarding/mod.rs` and place it in the `filter` module.
15. **Split `ForwardingState` (B):** Extract routing table lookup logic into `forwarding/route.rs` and local delivery checks to `forwarding/local.rs`. Keep helpers inlined.
16. **Decompose `enqueue_pending_forwards` (B):** Split the TX drain loop into encapsulation builders (`phase_build.rs`) and TCP segmenters (`phase_segment.rs`). Ensure UMEM single-recycle invariants are pinned by tests.
17. **Decompose `poll_binding_process_descriptor` (B):** Define a `PacketCtx` struct and split the RX loop into `session_hit.rs` and `session_miss.rs` stages. Verify using disassembly checks.
18. **Decompose CoS Selection (B):** Extract waterfill passes to `select_waterfill.rs`. Verify scheduling fairness using CoS smoke tests.
