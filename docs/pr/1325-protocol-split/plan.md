# #1325 Step 1 — Split `userspace-dp/src/protocol.rs` by domain

## Status

DRAFT v1 — pending adversarial plan review

## Issue framing

`userspace-dp/src/protocol.rs` is a single 3042-line flat file
(2073 production LOC + 247 LOC `#[cfg(test)] mod tests`) that
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
- **Value (incremental):** Faster incremental rebuilds when only one
  domain changes. Today every CoS field addition retypechecks the
  entire NAT/screen/policy/control surface; after the split,
  `cargo check` on a CoS-only edit only retypes `protocol/cos.rs`
  and `protocol/mod.rs`. Domain ownership becomes legible.
- **Value (compliance):** Removes the largest single-file violation of
  the `>2000 LOC trigger refactor` rule.
- **Perf gain at absolute scale:** Zero packets-per-second gain. This
  is a developer-velocity / modularity refactor, not a runtime
  optimization. The justification is *modularity discipline*, not
  cycles saved.

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
    │                      # SessionDeltaDrainRequest, SessionExportRequest,
    │                      # u64_is_zero (skip_serializing_if helper)
    ├── binding.rs         # BindingStatus (huge — ~420 LOC),
    │                      # BindingCountersSnapshot (+ From<&BindingStatus>),
    │                      # QueueStatus, WorkerRuntimeStatus,
    │                      # ExceptionStatus, SessionDeltaInfo, HAGroupStatus,
    │                      # plus _ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND
    │                      # compile-time invariant
    └── resolution.rs      # PacketResolution, FlowTupleStatus
                           # (+ from_session_key impl), FlowWorkerStatus
```

Test policy: inline `#[cfg(test)] mod tests` (currently 247 LOC at
the bottom of `protocol.rs`) moves into the module whose types it
exercises. The existing tests cover roughly: ProcessStatus protocol-
version fields (control), BindingCountersSnapshot/BindingStatus
round-trip (binding), and a few PacketResolution / FlowWorkerStatus
defaults (resolution). They split cleanly along the same boundary.

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
- 64 struct types: every type listed in §"Concrete design" above is
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
pre-refactor count from `protocol.rs` exactly (64 structs + 2 consts
+ 1 fn = 67 named items).

## Hidden invariants this change must preserve

1. **Wire compatibility.** No `#[serde(rename = "...")]`,
   `#[serde(default)]`, `#[serde(skip_serializing_if = "...")]`, or
   field order touched. Byte-identical JSON on the helper↔daemon
   control socket. Same `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 3` and
   `INJECT_PACKET_TUPLE_PROTOCOL_VERSION = 1`.

2. **`u64_is_zero` path stays `u64_is_zero` (not
   `binding::u64_is_zero` or `control::u64_is_zero`).** Used as a
   string literal inside `#[serde(skip_serializing_if = "u64_is_zero")]`
   on `HAGroupStatus.lease_until`. serde resolves this name at the
   call-site module's scope, so the function and its caller must
   live in the same module OR the function must be glob-imported.
   **Decision:** Place `u64_is_zero` in `protocol/control.rs`
   (alongside `HAStateUpdateRequest`), but `HAGroupStatus` lives in
   `protocol/binding.rs`. To make serde resolve the path, do one of:
   - Move `u64_is_zero` into `protocol/binding.rs` next to
     `HAGroupStatus`. **(preferred — minimal coupling)**
   - Add `use super::control::u64_is_zero;` to
     `protocol/binding.rs`.

   The plan picks option 1: keep `u64_is_zero` next to its only
   consumer (`HAGroupStatus.lease_until`) in `protocol/binding.rs`,
   and re-export at `mod.rs` for any future cross-domain consumer.

3. **`#[allow(clippy::large_enum_variant)]` / lint allows / cfg
   gates** — none on the existing types per grep. The only
   compile-time invariant is `_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND`.

4. **Cyclic dependency hazards.** The new modules form a DAG:
   - `snapshot.rs` depends on: `cos::ClassOfServiceSnapshot`,
     `nat::*`, `security::*` (these all appear as `Vec<...>` fields
     in `ConfigSnapshot`).
   - `binding.rs` depends on: nothing in sibling protocol modules
     (uses only `chrono`, `serde`, `std`, `crate::slowpath`).
   - `control.rs` depends on: `snapshot::ConfigSnapshot` (one field
     in `ControlRequest`), `binding::ProcessStatus` /
     `binding::SessionDeltaInfo` (in `ControlResponse`).
   - `resolution.rs` depends on: nothing (chrono + std + `crate::session`).
   - `nat.rs`, `security.rs`, `cos.rs`: leaves (no cross-domain refs).

   **No cycles.** `mod.rs` declares modules in any order; Rust
   resolves cross-module `use super::cos::X` independently of decl
   order.

5. **Test isolation.** Existing `#[cfg(test)] mod tests` is one
   block at the bottom. After split, each protocol submodule that
   gains a test gets its own `#[cfg(test)] mod tests`. Tests use
   `use super::*;` to reach the parent module's types. Cross-module
   test types (e.g. a binding test referencing
   `CONFIG_SNAPSHOT_PROTOCOL_VERSION` from `control.rs`) reach them
   via `use crate::protocol::CONFIG_SNAPSHOT_PROTOCOL_VERSION`.

6. **No reduction of `pub(crate)` to `pub(super)` or `pub`.** Every
   type stays `pub(crate)` (or `pub` for `WorkerRuntimeStatus`). The
   `mod.rs` re-export uses `pub(crate) use`.

## Risk assessment

| Risk class | Verdict | Reasoning |
|---|---|---|
| Behavioral regression | **LOW** | Pure code motion. Zero runtime code path touched. `cargo test --release` exercises the JSON round-trip surface via `main_tests.rs` (which references both protocol consts) and via the inline tests that move with their domain. |
| Lifetime / borrow-checker | **LOW** | No new lifetimes. Existing `impl From<&BindingStatus> for BindingCountersSnapshot` stays exactly as-is. `_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND` still trips if a borrowed field sneaks in. |
| Performance regression | **NEGLIGIBLE** | This is type-system / module-resolution work. The compiled rlib has identical generated code (serde-derive output unchanged because attribute order is preserved). |
| Architectural mismatch (#946 Phase 2 / #961 dead-end pattern) | **LOW** | Unlike #946 Phase 2 (which required cross-stage batching that the data couldn't support), this is a file-shuffle with explicit domain boundaries already present as comment headers in the original file. The premise — "DTOs concentrated by domain" — is verifiable in 30 seconds by grepping comment-headers. No invented architecture. |
| `u64_is_zero` string-path drift | **MEDIUM (mitigated)** | If `HAGroupStatus.lease_until` and the `u64_is_zero` fn end up in different files without a `use` import, the serde derive still compiles (it emits a path-relative token tree) but the runtime path resolution fails at first encode/decode. Mitigated by keeping the fn in `protocol/binding.rs` next to `HAGroupStatus`, plus a deliberate round-trip test that encodes `HAGroupStatus` with `lease_until == 0` and asserts the field is omitted from the JSON. |

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
- Go suite: `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...`
  — protocol JSON is consumed by the Go control plane; any wire-
  field rename or rename-omission would surface here.
- `grep -F "pub(crate)" userspace-dp/src/protocol/ -r | wc -l` and
  `grep -E "^\s*pub(\(crate\))?\s+(struct|enum|fn|const)"
  userspace-dp/src/protocol/ -r | wc -l` match the pre-refactor
  count from `protocol.rs` (67 named items).
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

1. **Is the `u64_is_zero` string-path hazard real?** Verify by
   reading the serde-derive expansion strategy. If serde generates
   a path token at the macro invocation site (which is the most
   common reading of the docs), then placing `u64_is_zero` in the
   same module as `HAGroupStatus` is sufficient. If serde instead
   accepts an absolute path (`crate::protocol::u64_is_zero`), the
   plan should specify the absolute-path form in the
   `#[serde(skip_serializing_if = ...)]` attribute. Find the
   correct form before implementation.

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

6. **Is the per-domain test split clean?** Audit the existing 247
   LOC `#[cfg(test)] mod tests`: each test references at most one
   domain's types (verified by `grep`). The split is mechanical.

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
