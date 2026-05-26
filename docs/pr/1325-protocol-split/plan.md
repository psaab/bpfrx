# #1325 Step 1 — Split `userspace-dp/src/protocol.rs` by domain

## Status

DRAFT v3 — folds Codex r2 PLAN-NEEDS-MAJOR (3 blocking) + AGY r2
PLAN-NEEDS-MINOR (4 items, overlapping). Pending r3.

### Codex r2 + AGY r2 fold

1. **`NeighborSnapshot` added to `control.rs` import list.**
   Both r2 reviewers caught it: `ControlRequest.neighbors:
   Option<Vec<NeighborSnapshot>>` at protocol.rs:803 means
   `control.rs` imports `NeighborSnapshot` from `snapshot.rs`.
   Added to v3's dependency enumeration.
2. **Public API count corrected.** v2 said "67 named items"
   (64 structs + 2 consts + 1 fn). Mechanically verified:
   `grep -cE '^pub(\(crate\))?\s+(struct|enum)\s+\w'` gives 66;
   `grep -cE '^pub(\(crate\))?\s+(const|fn)\s+\w'` gives 3
   (CONFIG_SNAPSHOT_PROTOCOL_VERSION, INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
   u64_is_zero). **Total: 69 named items.** v3 uses 69.
3. **Differential wire-format test made fail-closed.** v2 said
   "construct fully-populated instances"; v3 makes this
   mechanically enforced via Rust's exhaustive-struct-literal
   rule:
   - **No `..Default::default()`, no struct-update `..` syntax**
     in `wire_invariant.rs`. Every field is explicitly
     initialized. Adding a new field to any covered struct
     breaks compilation of the wire test, forcing simultaneous
     update of test + fixture.
   - **Recursive population**: `Vec<T>` and `Option<T>` fields
     get at least one non-default `T` constructed exhaustively.
   - Fixture regeneration is gated by env var:
     `XPF_PROTOCOL_WIRE_REGEN=1 cargo test --test wire_invariant`
     overwrites the fixture in-place; default `cargo test --test
     wire_invariant` runs the compare path and fails on any
     byte diff.
   - Fixture path:
     `userspace-dp/tests/fixtures/protocol_wire_v1.json`.
4. **Stale "247 LOC tests" claim corrected to 631 LOC** in
   §"Issue framing" (Codex r2 noted v2's framing section still
   said 247).
5. **`u64_is_zero` directory-tree contradiction fixed.** v3's
   directory tree puts `u64_is_zero` ONLY in `binding.rs`. v2
   mentioned it in both `control.rs` (tree) and `binding.rs`
   (narrative). v3 removes the `control.rs` reference.

DRAFT v2 — folds Codex r1 PLAN-KILL findings (5 blocking, all
mechanical corrections) and AGY r1 PLAN-NEEDS-MINOR findings (4
items, fully overlapping with Codex r1 plus a differential
wire-format test recommendation).

### AGY r1 fold (overlaps + new)

- ✅ Move `u64_is_zero` from `control.rs` to `binding.rs` in the
  directory tree (overlaps Codex r1#4). Resolved in v2 by using
  absolute path `crate::protocol::u64_is_zero` AND keeping the fn
  in `binding.rs` (the path remains valid regardless of submodule
  location, so this is defense-in-depth).
- ✅ Cross-module test imports inside `control.rs` test block
  (overlaps Codex r1#3). Test placement table added above.
- ✅ Drop "comment-header-derived" framing (overlaps Codex r1#5).
- ➕ **NEW from AGY:** Differential wire-format snapshot test.
  Folded into Test plan §below as a new
  `wire_invariant_tests.rs` module that mechanically compares
  serialized output of every wire type against a checked-in
  fixture. This is the airtight defense the v1 plan lacked.

### Disagreement between r1 reviewers

- **Codex r1**: incremental-build claim is false (rustc unit count
  is 1 → 1; any incremental win is speculative).
- **AGY r1**: incremental-build claim is valid (proc-macro
  expansion of `serde_derive` is per-file, so a CoS-only edit
  only re-expands `cos.rs`'s ~11 derives, not 60).
- **v2 resolution**: Both are right at different layers. rustc
  *type-checks* the whole crate as one unit on any change (Codex's
  point), but the `cargo build` proc-macro expansion phase IS
  cached at the file level via the `incremental` codegen DB
  (AGY's point — proc-macro outputs are cached per source file).
  However, both effects are small in absolute terms and would
  require a measurement to claim quantitatively. v2 keeps the
  conservative position: justification is *modularity discipline
  only*; any compile-time win is a bonus, not a claim.

### Codex r1 findings folded into v2

1. **Incremental-build claim withdrawn.** v1 claimed faster
   incremental rebuilds; Codex r1 correctly noted that `rustc`
   compiles the whole `userspace-dp` binary crate as a single
   compilation unit, so splitting one file into seven within the
   same crate does NOT change the rustc-unit count (1 → 1). Any
   incremental win is speculative and would have to be measured.
   v2 removes the rebuild claim and reframes the value as
   modularity discipline + domain ownership only.

2. **Dependency graph corrected.** v1 understated `ProcessStatus`'s
   cross-domain dependencies. `ProcessStatus` lives in `control.rs`
   and references types from *every* other module: `UserspaceCapabilities`
   and `FabricSnapshot` (snapshot), `BindingCountersSnapshot` /
   `BindingStatus` / `HAGroupStatus` / `QueueStatus` /
   `ExceptionStatus` / `SessionDeltaInfo` / `WorkerRuntimeStatus`
   (binding), `FlowWorkerStatus` / `PacketResolution` (resolution),
   `CoSInterfaceStatus` / `CoSActiveFlowCountStatus` (cos),
   `PolicyRuleCounterStatus` / `FirewallFilterTermCounterStatus` /
   `ThreeColorPolicerStatus` (security), `SourceNatPoolStatus`
   (nat), `SlowPathStatus` (control). The graph is still a DAG —
   control.rs depends on every leaf, no leaf depends on control —
   but v2 enumerates this explicitly so the implementor knows the
   `use super::...` import list `control.rs` requires.

3. **Test split made explicit, with cross-domain test placement
   rule.** v1 said tests "split cleanly" and gave a 247 LOC count;
   the actual block is 631 LOC (lines 2412–3042). Several tests
   exercise `ProcessStatus` + a leaf type (`WorkerRuntimeStatus`,
   `SourceNatPoolStatus`). v2 rule: every test lands in the module
   of the *constructor* type at the top of the test (the type
   whose round-trip is being exercised). Tests rooted at
   `ProcessStatus` stay in `control.rs`'s test block and `use
   super::*` for the leaf types via the `mod.rs` re-export glob.

4. **`u64_is_zero` uses absolute path.** Per Codex r1's reading of
   `serde_derive` source, the string passed to
   `#[serde(skip_serializing_if = "...")]` is parsed as
   `syn::ExprPath` and emitted directly into the generated code.
   `crate::protocol::u64_is_zero` is a valid absolute path. v2
   adopts that form, which decouples function location from
   struct location and makes future moves of either symbol safe.

5. **"Comment-header-derived" framing dropped.** `protocol.rs` has
   only two domain headers (`Snapshot schema` at line 13,
   `Control request / response` at line 774). The seven-way cut
   is *semantically* derived from type names + cohesion, not from
   in-file comment headers. v2 says so plainly.

## Issue framing

`userspace-dp/src/protocol.rs` is a single 3042-line flat file
(2411 production LOC + 631 LOC `#[cfg(test)] mod tests`, lines
2412–3042) that
holds the entire serde wire schema for the helper↔daemon control
socket. Today it concentrates ~60 unrelated DTO families (snapshot
config DTOs, control request/response, per-binding status, per-flow
status, NAT/CoS/screen/policy snapshots, session-sync wire shapes)
in one translation unit.

#1325 asks for a domain split following the project's modularity
discipline (file >2000 production LOC triggers refactor on the way
in, per `docs/engineering-style.md`). The issue body lists a target
directory layout with one file per cohesive domain.

This Step 1 ships the pure code-motion split into a
`userspace-dp/src/protocol/mod.rs` directory module + sibling
domain files. Public API (every `pub(crate)` symbol re-exported via
the existing `crate::protocol::*` glob in `main.rs`) stays identical.
Wire format stays byte-identical (no `#[serde(rename)]` touched).

## Honest scope/value framing

- **Cost:** Pure code motion across ~3000 LOC + one `mod.rs` re-export
  block (~70 names). Zero behavioral change, zero hot-path change.
- **Value (compliance):** Removes the largest single-file violation of
  the `>2000 LOC trigger refactor` rule from `docs/engineering-style.md`.
  `protocol.rs` is 3042 LOC; the largest sibling after split is
  `binding.rs` at ~640 LOC (BindingStatus + BindingCountersSnapshot +
  the From impl + the _ASSERT + HAGroupStatus + QueueStatus +
  WorkerRuntimeStatus + ExceptionStatus + SessionDeltaInfo).
- **Value (domain ownership):** Adding a new CoS DTO becomes a
  single-file edit in `protocol/cos.rs`. Adding a new
  session-sync wire shape becomes a single-file edit in
  `protocol/control.rs`. Today every such change loads the whole
  3042-line file into the developer's working window.
- **What this is NOT:**
  - NOT a build-time optimization. `rustc` compiles `userspace-dp`
    as one crate unit; splitting one file into seven inside the
    same crate does not change that count. Any incremental win is
    speculative and would need a measurement to claim.
  - NOT a runtime optimization. Zero packets-per-second gain. Zero
    bytes / cycles / cache lines changed.
  - NOT a wire-format change. Byte-identical JSON pre/post.
- **Perf gain at absolute scale:** Zero. Justification is
  *modularity discipline only*.

*If reviewers conclude the modularity churn is not worth the
git-blame fragmentation, PLAN-KILL is an acceptable verdict.*

## What's already shipped / partially batched

The wider #1373 retirement chain and Wave-1 modularity refactor
backlog have already shipped many smaller decompositions:
`pkg/server-show-split` (#1043), `pkg/cli-split` (#1044c),
`pkg/dataplane/userspace/main.rs` → `server/` (recent), several
`afxdp/worker/*` sub-struct extractions (#959). The protocol-DTO
module has not yet been touched. This PR is independent of all
in-flight retirement work — `protocol.rs` is the only file edited
plus its 5 importer files (all on master).

## Concrete design

### Post-refactor directory tree

```
userspace-dp/src/
├── main.rs                # unchanged: `mod protocol; use protocol::*;`
└── protocol/
    ├── mod.rs             # slim: module decls + `pub(crate) use` re-exports
    ├── snapshot.rs        # ConfigSnapshot, SnapshotSummary, InterfaceSnapshot,
    │                      # InterfaceAddressSnapshot, RouteSnapshot,
    │                      # ZoneSnapshot, FabricSnapshot, TunnelEndpointSnapshot
    │                      # (incl. custom Debug redacting wg_local_privkey_hex),
    │                      # MapPins, UserspaceCapabilities, FlowSnapshot,
    │                      # NeighborSnapshot, MirrorConfigSnapshot
    ├── cos.rs             # ClassOfServiceSnapshot + 6 component snapshots
    │                      # (forwarding-class / dscp-classifier{,-entry} /
    │                      # ieee8021-classifier{,-entry} / dscp-rewrite-rule{,-entry} /
    │                      # scheduler / scheduler-map{,-entry}) + their status
    │                      # twins (CoSInterfaceStatus, CoSQueueStatus,
    │                      # CoSActiveFlowCountStatus)
    ├── nat.rs             # SourceNATRuleSnapshot, StaticNATRuleSnapshot,
    │                      # DestinationNATRuleSnapshot, NAT64RuleSnapshot,
    │                      # Nptv6RuleSnapshot, SourceNatPoolStatus
    ├── security.rs        # ScreenProfileSnapshot, FirewallFilterSnapshot,
    │                      # FirewallTermSnapshot, PolicerSnapshot,
    │                      # ThreeColorPolicerSnapshot, FlowExportSnapshot,
    │                      # PolicyRuleSnapshot, PolicyApplicationSnapshot,
    │                      # PolicyRuleCounterStatus,
    │                      # FirewallFilterTermCounterStatus,
    │                      # ThreeColorPolicerStatus
    ├── control.rs         # CONFIG_SNAPSHOT_PROTOCOL_VERSION (const),
    │                      # INJECT_PACKET_TUPLE_PROTOCOL_VERSION (const),
    │                      # ControlRequest, ControlResponse, ProcessStatus,
    │                      # SlowPathStatus (+ From<slowpath::SlowPathStatus>),
    │                      # ForwardingControlRequest, HAStateUpdateRequest,
    │                      # QueueControlRequest, BindingControlRequest,
    │                      # InjectPacketRequest, SessionSyncRequest,
    │                      # SessionDeltaDrainRequest, SessionExportRequest
    ├── binding.rs         # BindingStatus (huge — ~420 LOC),
    │                      # BindingCountersSnapshot (+ From<&BindingStatus>),
    │                      # QueueStatus, WorkerRuntimeStatus,
    │                      # ExceptionStatus, SessionDeltaInfo, HAGroupStatus,
    │                      # u64_is_zero (skip_serializing_if helper —
    │                      # consumed by HAGroupStatus.lease_until),
    │                      # plus _ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND
    │                      # compile-time invariant
    └── resolution.rs      # PacketResolution, FlowTupleStatus
                           # (+ from_session_key impl), FlowWorkerStatus
```

Test policy: inline `#[cfg(test)] mod tests` (currently 631 LOC,
lines 2412–3042) moves into the module whose types it
exercises, per the v2 cross-domain placement rule (test lands in
the module of the constructor type at the top of the test body).
Cross-domain test imports use absolute `crate::protocol::X`
paths.

### `protocol/mod.rs` shape

```rust
//! Control request/response and snapshot schema types shared between
//! the control socket server (`main.rs`) and the AF_XDP coordinator
//! (`afxdp.rs`).
//!
//! All types are `pub(crate)` so they are visible across the crate
//! without being part of the public API.

mod binding;
mod control;
mod cos;
mod nat;
mod resolution;
mod security;
mod snapshot;

// Re-export every symbol so existing `crate::protocol::X` (and
// `use protocol::*;` in main.rs) callers keep working unchanged.
pub(crate) use binding::*;
pub(crate) use control::*;
pub(crate) use cos::*;
pub(crate) use nat::*;
pub(crate) use resolution::*;
pub(crate) use security::*;
pub(crate) use snapshot::*;
```

`mod.rs` carries only module decls + re-exports. No actual type or
constant lives in `mod.rs`. This satisfies the "no misc dumping
grounds" rule.

### Call-site preservation

The five `use crate::protocol::X` sites in `afxdp/mirror.rs`,
`afxdp/coordinator/tests.rs` (×2), `afxdp/wg/tests.rs`,
`afxdp/coordinator/status.rs`, plus 12 files that reference
`protocol::*` types via path (the `crate::protocol::T` form), all
resolve through `mod.rs`'s glob re-exports. Zero edits at call sites.

`main.rs`'s `use protocol::*;` glob continues to import everything
(including `CONFIG_SNAPSHOT_PROTOCOL_VERSION`,
`INJECT_PACKET_TUPLE_PROTOCOL_VERSION`, and `u64_is_zero`) into the
crate root. The two consts that downstream code reads via
`crate::INJECT_PACKET_TUPLE_PROTOCOL_VERSION` (e.g.
`afxdp/coordinator/tests.rs:7`) keep working because the glob still
publishes them at the crate root.

### Inter-module dependency graph (post-split)

This is the literal `use super::...` import list each submodule
needs. Verified by walking type-field references in
`userspace-dp/src/protocol.rs`:

- **`cos.rs`**: leaf. No `use super::*` needed.
- **`nat.rs`**: leaf. No `use super::*` needed.
- **`security.rs`**: leaf. No `use super::*` needed.
- **`resolution.rs`**: leaf. Uses `crate::session::SessionKey` for
  `FlowTupleStatus::from_session_key` (existing dep, unchanged).
- **`binding.rs`**: leaf in protocol-internal terms (no cross-
  submodule type refs). Uses `crate::slowpath::SlowPathStatus` —
  wait, that's wrong: `SlowPathStatus` lives in `control.rs` per
  the partition. Re-check: `crate::slowpath::SlowPathStatus` is a
  *different* type defined in `crate::slowpath` (a sibling top-
  level module of `protocol`), with a `From` conversion to the
  protocol-layer `SlowPathStatus`. That conversion lives in
  `control.rs` next to the protocol-layer struct it produces.
  So `binding.rs` depends on nothing in sibling protocol modules.
- **`snapshot.rs`**: depends on `cos::ClassOfServiceSnapshot` (one
  field), `nat::{SourceNATRuleSnapshot, StaticNATRuleSnapshot,
  DestinationNATRuleSnapshot, NAT64RuleSnapshot, Nptv6RuleSnapshot}`
  (Vec fields in `ConfigSnapshot`), `security::{ScreenProfileSnapshot,
  FirewallFilterSnapshot, PolicerSnapshot, ThreeColorPolicerSnapshot,
  FlowExportSnapshot, PolicyRuleSnapshot, PolicyApplicationSnapshot}`
  (Vec fields in `ConfigSnapshot`).
- **`control.rs`**: deepest. Depends on:
  - `snapshot::{ConfigSnapshot, UserspaceCapabilities, FabricSnapshot, NeighborSnapshot}`
    (NeighborSnapshot dep added per Codex r2 / AGY r2: see
    `ControlRequest.neighbors: Option<Vec<NeighborSnapshot>>`
    at protocol.rs:803.)
  - `binding::{BindingCountersSnapshot, BindingStatus, HAGroupStatus,
    QueueStatus, ExceptionStatus, SessionDeltaInfo,
    WorkerRuntimeStatus}`
  - `resolution::{FlowWorkerStatus, PacketResolution}`
  - `cos::{CoSInterfaceStatus, CoSActiveFlowCountStatus}`
  - `security::{PolicyRuleCounterStatus,
    FirewallFilterTermCounterStatus, ThreeColorPolicerStatus}`
  - `nat::SourceNatPoolStatus`
  - `crate::slowpath` (existing, for the `From` conversion).

  This list will appear verbatim as `use super::{...};` at the
  top of `protocol/control.rs`. Implementor cross-checks this
  list against the actual `ProcessStatus` / `ControlRequest` /
  `ControlResponse` fields when writing the file.

DAG check: control depends on every leaf + snapshot. Snapshot
depends on cos+nat+security. No leaf depends on control. No
cycle.

### What about the `Debug` impl for `TunnelEndpointSnapshot`?

It lives in `protocol/snapshot.rs` with its struct. It uses only
`std::fmt::Debug` and reads its own fields — no cross-module deps.

### What about the `From<crate::slowpath::SlowPathStatus> for SlowPathStatus` impl?

Stays in `protocol/control.rs` alongside `SlowPathStatus`. Adds
`use crate::slowpath;` at the top of that file.

### What about the `From<&BindingStatus> for BindingCountersSnapshot` impl + the static-Send compile assert?

Stays in `protocol/binding.rs` alongside both involved types. The
`const _ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND` item
moves with `BindingCountersSnapshot`.

### What about the `from_session_key` constructor on `FlowTupleStatus`?

Stays in `protocol/resolution.rs` alongside `FlowTupleStatus`. It
uses `crate::session::SessionKey`; adds `use crate::session;`
at the top.

## Public API preservation

Method-by-method list of preserved symbols (all `pub(crate)` unless
noted):

- Constants: `CONFIG_SNAPSHOT_PROTOCOL_VERSION`,
  `INJECT_PACKET_TUPLE_PROTOCOL_VERSION` (both `pub(crate)`,
  reachable as `crate::CONFIG_SNAPSHOT_PROTOCOL_VERSION` via the
  `use protocol::*;` glob in `main.rs`).
- Free fns: `u64_is_zero`.
- 66 struct types: every type listed in §"Concrete design" above is
  preserved by name, field set, derives, and `#[serde(...)]`
  attributes (only file moves).
- `WorkerRuntimeStatus` keeps its `pub struct` visibility (the only
  fully-public-API type — others are `pub(crate)`).
- 4 inherent / trait impls: `Debug for TunnelEndpointSnapshot`,
  `From<crate::slowpath::SlowPathStatus> for SlowPathStatus`,
  `From<&BindingStatus> for BindingCountersSnapshot`,
  `FlowTupleStatus::from_session_key`.

Verification approach: post-refactor `grep -rE "pub(\(crate\))?\s+
(struct|enum|fn|const)" userspace-dp/src/protocol/` matches the
pre-refactor count from `protocol.rs` exactly (**66 structs + 2 consts
+ 1 fn = 69 named items**; verified by separate
`grep -cE '^pub(\(crate\))?\s+(struct|enum)\s+\w'` (66) and
`grep -cE '^pub(\(crate\))?\s+(const|fn)\s+\w'` (3)).

## Hidden invariants this change must preserve

1. **Wire compatibility.** No `#[serde(rename = "...")]`,
   `#[serde(default)]`, `#[serde(skip_serializing_if = "...")]`, or
   field order touched. Byte-identical JSON on the helper↔daemon
   control socket. Same `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 3` and
   `INJECT_PACKET_TUPLE_PROTOCOL_VERSION = 1`.

2. **`u64_is_zero` accessed via absolute path
   `crate::protocol::u64_is_zero`.** Per `serde_derive` semantics
   (Codex r1 confirmed by reading `serde_derive-1.0.228` source:
   the string passed to `skip_serializing_if` is parsed as
   `syn::ExprPath` and emitted directly into the generated code),
   absolute paths are accepted. v2 picks the absolute form so the
   helper fn and the consuming struct can live in any pair of
   submodules without serde resolution drift. Concrete change in
   `binding.rs`:

   ```rust
   #[serde(rename = "lease_until", default,
           skip_serializing_if = "crate::protocol::u64_is_zero")]
   pub lease_until: u64,
   ```

   `u64_is_zero` itself lives in `binding.rs` next to its only
   current consumer; the absolute-path form means a future caller
   in a different submodule does not require any further code
   change.

3. **`#[allow(clippy::large_enum_variant)]` / lint allows / cfg
   gates** — none on the existing types per grep. The only
   compile-time invariant is `_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND`.

4. **Cyclic dependency hazards.** The new modules form a DAG:
   - `snapshot.rs` depends on: `cos::ClassOfServiceSnapshot`,
     `nat::*`, `security::*` (these all appear as `Vec<...>` fields
     in `ConfigSnapshot`).
   - `binding.rs` depends on: nothing in sibling protocol modules
     (uses only `chrono`, `serde`, `std`). The
     `From<crate::slowpath::SlowPathStatus> for SlowPathStatus`
     conversion lives in `control.rs`, not `binding.rs`.
   - `control.rs` depends on every leaf + snapshot — see the
     enumerated import list in §"Inter-module dependency graph"
     above. `ProcessStatus` lives in `control.rs` (not `binding.rs`
     as v2 erroneously bulleted); `SessionDeltaInfo` lives in
     `binding.rs` and is reached from `control.rs` via
     `use super::binding::SessionDeltaInfo;`.
   - `resolution.rs` depends on: nothing (chrono + std + `crate::session`).
   - `nat.rs`, `security.rs`, `cos.rs`: leaves (no cross-domain refs).

   **No cycles.** `mod.rs` declares modules in any order; Rust
   resolves cross-module `use super::cos::X` independently of decl
   order.

5. **Test isolation, with cross-domain placement rule.**
   Existing `#[cfg(test)] mod tests` is one block at the bottom,
   631 LOC (lines 2412–3042 — corrected from v1's "247 LOC" count
   per Codex r1). v2's rule: **each test lands in the module of
   the constructor type at the top of the test body** (the type
   whose round-trip is being exercised first). Cross-domain test
   placements:

   - `process_status_inject_packet_tuple_protocol_version_roundtrip`
     constructs `ProcessStatus` → `control.rs` test block.
   - `process_status_buffer_capacity_fields_roundtrip` constructs
     `ProcessStatus` (uses `WorkerRuntimeStatus` inline) →
     `control.rs` test block. Cross-module type reached via
     `use crate::protocol::WorkerRuntimeStatus;`.
   - `process_status_source_nat_pool_status_roundtrip` constructs
     `ProcessStatus` (uses `SourceNatPoolStatus` inline) →
     `control.rs` test block. Cross-module type reached via
     `use crate::protocol::SourceNatPoolStatus;`.
   - `source_nat_persistent_fields_roundtrip` constructs
     `SourceNATRuleSnapshot` → `nat.rs` test block.
   - `inject_packet_request_*` tests construct
     `InjectPacketRequest` → `control.rs` test block.
   - `tx_kick_latency_*`, `tx_completion_ring_*`,
     `flow_cache_capacity_*`, BindingStatus / BindingCountersSnapshot
     round-trip tests → `binding.rs` test block.

   All cross-module type references inside tests use absolute
   `crate::protocol::X` form (NOT `super::*`) so the test stays
   readable when a cohort moves between submodules.

6. **No reduction of `pub(crate)` to `pub(super)` or `pub`.** Every
   type stays `pub(crate)` (or `pub` for `WorkerRuntimeStatus`). The
   `mod.rs` re-export uses `pub(crate) use`.

## Risk assessment

| Risk class | Verdict | Reasoning |
|---|---|---|
| Behavioral regression | **LOW** | Pure code motion. Zero runtime code path touched. `cargo test --release` exercises the JSON round-trip surface via `main_tests.rs` (which references both protocol consts) and via the inline tests that move with their domain. |
| Lifetime / borrow-checker | **LOW** | No new lifetimes. Existing `impl From<&BindingStatus> for BindingCountersSnapshot` stays exactly as-is. `_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND` still trips if a borrowed field sneaks in. |
| Performance regression | **NEGLIGIBLE** | This is type-system / module-resolution work. The compiled rlib has identical generated code (serde-derive output unchanged because attribute order is preserved). `rustc` compilation-unit count: 1 → 1 (no change). |
| Architectural mismatch (#946 Phase 2 / #961 dead-end pattern) | **LOW** | Unlike #946 Phase 2 (which required cross-stage batching that the data couldn't support), this is a file-shuffle with the partition derived from type-name cohesion (NOT in-file comment headers — protocol.rs has only two domain headers per Codex r1). The premise — "DTOs concentrated by domain" — is verifiable in 30 seconds by reading the type list. No invented architecture. |
| `u64_is_zero` string-path drift | **LOW (mechanically resolved)** | v2 uses absolute path `crate::protocol::u64_is_zero` in the `#[serde(skip_serializing_if = ...)]` attribute. Per `serde_derive` source: the string is parsed as `syn::ExprPath` and emitted directly. An absolute path resolves regardless of where the function lives within the `protocol` module tree. Backed by a `ha_group_status_lease_until_zero_skipped` round-trip test that asserts the field is omitted when `lease_until == 0` and present when nonzero. |

## Test plan

- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build`
  clean (zero new warnings).
- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release` —
  every existing test still passes. The `protocol` test block
  splits across the 6+1 new modules; aggregate count unchanged.
- 5× flake check on the two highest-coverage protocol tests:
  `process_status_inject_packet_tuple_protocol_version_roundtrip` and
  `process_status_buffer_capacity_fields_roundtrip`.
- New `ha_group_status_lease_until_zero_skipped` test in
  `protocol/binding.rs` that mechanically verifies the
  `u64_is_zero` string-path is wired correctly post-move (encodes
  `HAGroupStatus { lease_until: 0, .. }` and asserts the JSON has
  no `lease_until` key; encodes `lease_until: 99` and asserts it
  appears). This is a regression net for the only non-trivial
  hazard in §"Risk assessment".
- **Differential wire-format invariant (Codex r2 + AGY r2:
  fail-closed).** New integration test at
  `userspace-dp/tests/wire_invariant.rs` (crate-test layer, runs
  via `cargo test --test wire_invariant`). Constructs
  exhaustive, recursively-populated instances of every top-level
  wire type:

  `ConfigSnapshot`, `ControlRequest`, `ControlResponse`,
  `ProcessStatus`, `BindingStatus`, `BindingCountersSnapshot`,
  `ExceptionStatus`, `InjectPacketRequest`, `SessionSyncRequest`,
  `SessionDeltaInfo`, `PacketResolution`, `FlowWorkerStatus`,
  `HAGroupStatus`, `QueueStatus`, `WorkerRuntimeStatus`,
  `CoSInterfaceStatus`, `CoSActiveFlowCountStatus`,
  `SourceNatPoolStatus`, `PolicyRuleCounterStatus`,
  `FirewallFilterTermCounterStatus`, `ThreeColorPolicerStatus`,
  `MirrorConfigSnapshot`, `TunnelEndpointSnapshot`.

  Fail-closed discipline (mechanically enforced):
  - **No `..Default::default()` and no struct-update `..` syntax**
    in the constructors. Every field is explicitly initialized.
    Adding any new field to any covered struct breaks compilation
    of the wire test, forcing simultaneous update of test + fixture.
    Rust's exhaustive-struct-literal rule makes this a compile-
    time gate, not a runtime one.
  - **Recursive population**: every `Vec<T>` carries at least one
    non-default `T` constructed exhaustively; every `Option<T>`
    carries `Some(T { ... })` exhaustively.
  - **Fixture regen gated by env var.** Default
    `cargo test --test wire_invariant` runs the *compare* path
    against the checked-in fixture and fails on any byte diff.
    `XPF_PROTOCOL_WIRE_REGEN=1 cargo test --test wire_invariant`
    overwrites the fixture in-place. Regen is run once on master
    (pre-split) to seed `protocol_wire_v1.json`, then again post-
    split to confirm zero diff. Future wire-evolution PRs add
    `protocol_wire_v2.json` (a new test) rather than overwrite v1.
  - **Fixture path:**
    `userspace-dp/tests/fixtures/protocol_wire_v1.json`. The
    file is committed alongside the wire-test source.
  - **Generation workflow** for the implementor of this PR:
    1. Stash the in-progress split.
    2. Check out master, write `wire_invariant.rs` as the
       compare path against a fixture that does not yet exist,
       then run with `XPF_PROTOCOL_WIRE_REGEN=1` to generate
       it. Commit fixture + test on master baseline.
    3. Pop the stash. Re-run `cargo test --test wire_invariant`
       post-split — must pass byte-for-byte.

  This is the airtight defense against silent wire drift during
  refactor. It is independent of inline round-trip tests and
  exists at the integration-test layer so it survives any
  internal module reshuffling.
- Go suite: `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...`
  — protocol JSON is consumed by the Go control plane; any wire-
  field rename or rename-omission would surface here.
- `grep -F "pub(crate)" userspace-dp/src/protocol/ -r | wc -l` and
  `grep -E "^\s*pub(\(crate\))?\s+(struct|enum|fn|const)"
  userspace-dp/src/protocol/ -r | wc -l` match the pre-refactor
  count from `protocol.rs` (69 named items: 66 structs + 2 consts
  + 1 fn).
- **No per-PR smoke** per the Wave-1 retirement-batch rules: post
  `<!-- AWAITING-BATCH-MERGE -->` after 4-of-4 reviewer attestation;
  the smoke-runner singleton fires smoke every 10 merged PRs.

## Out of scope (explicitly)

- **No wire-format changes.** `#[serde(rename = "...")]`,
  `#[serde(default)]`, field ordering: all preserved byte-for-byte.
- **No reshaping of any struct fields.** Pure file motion. No
  renames, no field additions, no field removals, no derive
  changes.
- **No visibility changes.** Everything stays `pub(crate)` except
  `WorkerRuntimeStatus` which stays `pub`.
- **No switching JSON to a binary format** (that is #1164 / a
  separate ticket — strictly orthogonal).
- **No splitting `BindingStatus` itself.** It is ~420 LOC of a
  single struct definition; splitting that struct is a different
  refactor with wire impact. Step 1 moves it intact.
- **No reordering of struct definitions within a single new
  module.** Definitions stay in their original order to keep
  `git blame` legible per-line.
- **No new public API.** The split adds zero new exports.
- **No documentation reshuffle.** Module-level docstrings live
  in the originating file (e.g. the `pub(crate) struct
  BindingCountersSnapshot` doc block moves with it).

## Open questions for adversarial review

1. ~~**Is the `u64_is_zero` string-path hazard real?**~~ Resolved
   in v2: Codex r1 verified `serde_derive` parses the attribute
   string as `syn::ExprPath` and emits it directly, so absolute
   paths work. v2 uses `crate::protocol::u64_is_zero`.

2. **Is the domain partition stable, or will future field-additions
   force types to migrate?** E.g. `PolicyRuleCounterStatus` lives
   in `security.rs` (policy hit counts); if a future patch unifies
   it with `FirewallFilterTermCounterStatus`, do we end up with a
   `counters.rs`? The plan punts: if a future PR needs that move,
   it does it cleanly post-split, not as part of #1325.

3. **Is splitting `BindingStatus` (~420 LOC for one struct) into a
   smaller surface a better Step 2?** Plan defers: that has wire
   impact (or a non-trivial preservation discipline). Step 1 is
   pure file motion only.

4. **Is the `From<&BindingStatus> for BindingCountersSnapshot`
   conversion the right cohesion break?** Both types live in
   `binding.rs`. Alternative: `BindingCountersSnapshot` lives in
   `binding_counters.rs`. Plan picks "same file" because the
   `_ASSERT` and the `From` impl both reference both types, and
   forcing a `use super::binding::BindingStatus;` in a sibling
   module adds noise without compensating cohesion.

5. **Does the `protocol/` directory layout collide with any other
   build system path?** None found — `userspace-dp` is a single
   crate with no `[lib]` target. The `Cargo.toml` references
   `src/main.rs` only.

6. ~~**Is the per-domain test split clean?**~~ Resolved in v2 with
   explicit per-test placement table (above): cross-domain tests
   land with the constructor type and reach leaf types via
   absolute `crate::protocol::X` paths. The 631 LOC inline test
   block partitions across the 7 new modules per that rule.

7. **Is this the right time?** The Wave-1 modularity backlog is
   active, the file is the largest single-file violation of the
   2000 LOC rule, and the change is zero-risk pure motion. *If
   reviewers want to defer to a later wave, PLAN-KILL is the
   appropriate verdict; this isn't urgent enough to push through
   over an architectural objection.*

## Co-authorship discipline

Every commit on this branch will carry:

```
Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

## Reviewer task-id record

See `docs/pr/1325-protocol-split/reviewer-ids.md` for every Codex
and AGY task-id dispatched against this refactor. Required for
continuations after companion-session loss.
