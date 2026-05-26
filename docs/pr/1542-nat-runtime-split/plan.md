# #1542 — Split userspace NAT runtime into per-concern modules (Wave-2)

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`userspace-dp/src/nat.rs` (1,605 LOC, single file) blends six independent
concerns that share only the common `NatDecision` output type:

1. Source NAT rule parsing + matching
2. Pool-mode `PortAllocator` (live + persistent lease state machine,
   rollback, recycled-port indexes, expiration BTrees)
3. Persistent-NAT lease lifecycle (currently colocated inside the
   allocator)
4. Destination NAT lookup (`DnatTable`)
5. Static 1:1 NAT (`StaticNatTable`)
6. Pool status aggregation (`PortAllocatorSnapshot`,
   `source_nat_pool_statuses`)

Issue #1542 calls for splitting these into a `nat/` directory with one
file per concern, so the allocator's invariants stay local and the
rollback state machine is easier to reason about exhaustively.

## Honest scope/value framing

This is a **modularity refactor**, not a performance refactor. The win
is review surface area, not runtime cycles. Concretely:

- The allocator's locked critical section moves from "everything in
  one 1.6 KLOC file" to "one file under 600 LOC."
- `match_source_nat_result_for_tuple` (162 LOC) gets a dedicated file
  next to rule parsing, so the lookup path is greppable without
  scrolling past allocator internals.
- DNAT and static NAT tables get sibling files; both are ~150 LOC
  table types with no overlap with the allocator.
- Build-time / monomorphisation impact is approximately zero (cargo
  compiles per-crate, not per-file).

**Per-packet allocations: zero new.** This refactor must not introduce
any allocations on the hot path. The hot-path lookup callers are:

- `afxdp/forwarding/mod.rs:148` → `match_source_nat_result_for_tuple`
- `afxdp/coordinator/status.rs:125` → same entry point
- `afxdp/coordinator/status.rs:148` → `release_source_nat_allocation`
- `session/mod.rs:2` and `event_stream/codec_tests.rs:8` → `NatDecision`

All four sites are preserved as `crate::nat::<symbol>` shape via the
`nat/mod.rs` re-exports listed below.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. The justification rests on review
ergonomics + locality of the rollback/release invariants, not throughput.

## What's already shipped / partially split

- `nat_tests.rs` already lives as a sibling file at
  `userspace-dp/src/nat_tests.rs` and is loaded via
  `#[path = "nat_tests.rs"] mod tests;` from `nat.rs`. Tests use
  `use super::*;` and reach into private items
  (e.g. `PortAllocator::release_flow`, `persistent_source_key`).
- `nat64.rs` is already a separate sibling module; this refactor does
  NOT touch it.
- `nptv6.rs` is already separate; not touched.
- The persistent SNAT lease state machine landed earlier and currently
  lives inside `PortAllocator::{allocate_translation, release_flow,
  rollback_flow, gc_expired_locked, release_expired_lease_locked}`.

## Concrete design

### Target layout

```
userspace-dp/src/nat/
  mod.rs              # module roots, re-exports, NatDecision
  source.rs           # rule parsing + matching + lookup result types
  allocator.rs        # PortAllocator + live/persistent state machine
  destination.rs      # DnatTable
  static_nat.rs       # StaticNatTable
  status.rs           # PortAllocatorSnapshot + source_nat_pool_statuses
  tests.rs            # relocated nat_tests.rs (kept as one file)
```

`main.rs` line 12 changes from `mod nat;` to `mod nat;` (unchanged —
Rust resolves `nat` to either `nat.rs` or `nat/mod.rs`). The old
`nat.rs` is deleted; the old `nat_tests.rs` is moved to
`nat/tests.rs` with no content change beyond the `#[path]` attribute
relocation.

### Allocation of items to files (line-by-line)

Line numbers reference `nat.rs` at HEAD of branch base
(`origin/master`, commit `3b1f56a8`):

| Item | Source lines | Destination file |
|------|--------------|------------------|
| `DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS`, `NS_PER_SEC` | 13-14 | `allocator.rs` |
| `MAX_SOURCE_NAT_POOL_TRACKED_FLOWS` | 15 | `allocator.rs` |
| `NatDecision` + `impl` | 18-63 | `mod.rs` |
| `SourceNatLookup`, `SourceNatFailure`, `SourceNatFailureReason` + impls + `source_nat_failure_reason_from_snapshot` | 65-126 | `source.rs` |
| `SourceNatFlowKey` + impl | 128-145 | `source.rs` |
| `PersistentSourceKey`, `TranslatedTuple`, `PoolAddressFamily` + impl | 147-179 | `allocator.rs` |
| `AllocationOwner`, `LiveAllocation`, `PersistentLease` | 181-207 | `allocator.rs` |
| `PortAllocatorLiveState` + impl | 209-231 | `allocator.rs` |
| `GC_PERIOD`, `*_GC_BUDGET` constants | 234-237 | `allocator.rs` |
| `PortAllocatorShared`, `PortAllocator`, `Default`, `impl PortAllocator` | 240-797 | `allocator.rs` |
| `PortAllocatorSnapshot` | 799-807 | `status.rs` |
| `allocator_capacity`, `sticky_pool_index` | 809-841 | `allocator.rs` (private helpers used only by allocator) |
| `SourceNatRule` + two `impl` blocks, `SourceNatPoolAllocatorKey`, `source_nat_runtime_compatible` | 843-1047 | `source.rs` |
| `parse_source_nat_rules{,_with_previous}` | 911-1031 | `source.rs` |
| `release_source_nat_allocation`, `rollback_source_nat_allocation`, `release_source_nat_allocation_with_mode` | 1049-1110 | `source.rs` |
| `source_nat_pool_statuses` | 1112-1137 | `status.rs` |
| `match_source_nat`, `match_source_nat_result`, `match_source_nat_result_for_tuple` | 1139-1331 | `source.rs` |
| `StaticNatEntry`, `StaticNatTable` + impl, `nets_match_v4`, `nets_match_v6` | 1333-1422 | `static_nat.rs` |
| `PROTO_TCP`, `PROTO_UDP`, `DnatKey`, `DnatValue`, `DnatEntry`, `DnatTable` + impl | 1424-1601 | `destination.rs` |
| Test sub-mod attribute | 1603-1605 | `mod.rs` |

The 1,605 lines of nat.rs split roughly as:

- `mod.rs`: ~80 LOC (re-exports + `NatDecision`)
- `source.rs`: ~640 LOC (rules + matching + lookup; densest file)
- `allocator.rs`: ~580 LOC (live + lease state machine)
- `destination.rs`: ~180 LOC (DnatTable)
- `static_nat.rs`: ~95 LOC (StaticNatTable)
- `status.rs`: ~35 LOC (snapshot + status aggregation)

All sibling files stay under the project's ~2,000 LOC modularity gate
and well under the 1,605 LOC pre-split file.

### `mod.rs` shape

```rust
mod allocator;
mod destination;
mod source;
mod static_nat;
mod status;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) use allocator::PortAllocator;
pub(crate) use destination::{DnatKey, DnatTable, DnatValue};
pub(crate) use source::{
    match_source_nat, match_source_nat_result, match_source_nat_result_for_tuple,
    parse_source_nat_rules, parse_source_nat_rules_with_previous,
    release_source_nat_allocation, rollback_source_nat_allocation,
    SourceNatFailure, SourceNatFailureReason, SourceNatFlowKey, SourceNatLookup,
    SourceNatRule,
};
pub(crate) use static_nat::{StaticNatEntry, StaticNatTable};
pub(crate) use status::{source_nat_pool_statuses, PortAllocatorSnapshot};

// NatDecision is the cross-cutting output type used by every NAT
// concern, so it stays at the module root rather than inside source.rs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision { ... }
impl NatDecision { ... }
```

### Cross-module visibility

Each sibling file gets a focused `pub(super)` surface:

- `allocator.rs`: `PortAllocator` is `pub(super)`; `try_next_port`,
  `address_index`, `new`, `Default`, `allocate_translation`,
  `release_flow`, `rollback_flow`, `snapshot` are `pub(super)` because
  `source.rs` needs to drive the allocator from
  `match_source_nat_result_for_tuple` and `release_source_nat_allocation`.
  All `*_locked` helpers, `PortAllocatorLiveState`, `LiveAllocation`,
  `PersistentLease`, `AllocationOwner`, `TranslatedTuple`,
  `PoolAddressFamily`, `PersistentSourceKey`, the GC constants, and the
  capacity/sticky helpers stay private (`pub(self)`/no qualifier) —
  this is the locality win the issue asks for.
- `source.rs`: `SourceNatRule` and all the lookup/parse/release entry
  points are `pub(super)`. `SourceNatPoolAllocatorKey`,
  `source_nat_failure_reason_from_snapshot`,
  `source_nat_runtime_compatible`, and `release_source_nat_allocation_with_mode`
  stay private.
- `destination.rs`: `DnatTable`, `DnatKey`, `DnatValue` are
  `pub(super)`. `DnatEntry`, `match_entries`, `insert_entry`,
  `PROTO_TCP`, `PROTO_UDP` stay private.
- `static_nat.rs`: `StaticNatEntry`, `StaticNatTable` are
  `pub(super)`. `nets_match_v4`, `nets_match_v6` stay private.
- `status.rs`: `PortAllocatorSnapshot` is `pub(super)`;
  `source_nat_pool_statuses` is `pub(super)`. `status.rs` needs to
  call `PortAllocator::snapshot`, so `snapshot` on `PortAllocator`
  stays `pub(super)`.
- Test sub-mod uses `use super::*;` then `use super::allocator::*;`
  etc., or — preferred — pulls in via specific imports from each
  sub-module. (We will fix any breakage as it surfaces.)

### Public re-export surface (verified callers preserved)

External callers continue to write `crate::nat::<symbol>`:

- `event_stream/codec_tests.rs:8` → `crate::nat::NatDecision` ✓
- `session/mod.rs:2` → `crate::nat::NatDecision` ✓
- `main_tests.rs:1192,1238` → `crate::nat::SourceNatLookup::Matched` ✓
- `server/helpers.rs:238,243` → `crate::nat::NatDecision` ✓
- `afxdp/coordinator/status.rs:109,125,145,148` →
  `crate::nat::{source_nat_pool_statuses, SourceNatLookup,
  match_source_nat_result_for_tuple, NatDecision,
  release_source_nat_allocation}` ✓
- `afxdp/mod.rs:5` → `use crate::nat::{...}` block (verified all
  symbols re-exported) ✓
- `afxdp/forwarding/tests.rs:6` → `crate::nat::SourceNatFailureReason` ✓
- `afxdp/forwarding/mod.rs:148` →
  `crate::nat::match_source_nat_result_for_tuple` ✓

**No external caller signature changes.** This is pure code motion at
the call-site boundary.

## Public API preservation

Every `pub(crate)` symbol in the current file is preserved with the
same shape and the same `pub(crate)` visibility at `crate::nat::` —
either by living in `mod.rs` directly (`NatDecision`) or by being
re-exported there. The internal sub-module visibility is tightened
to `pub(super)` to localize the rollback/release/lease invariants.

Specifically preserved:

- `NatDecision { rewrite_src, rewrite_dst, rewrite_src_port,
  rewrite_dst_port, nat64, nptv6 }`, `NatDecision::reverse`,
  `NatDecision::merge`
- `SourceNatLookup::{Matched, Excepted, NoMatch}`
- `SourceNatFailure`, `SourceNatFailureReason` and all variants
- `SourceNatFlowKey { protocol, src_ip, src_port, dst_ip, dst_port }`
- `SourceNatRule` field shape (one struct field is `address_pool:
  Vec<IpAddr>`, etc.) and both `impl` blocks
- `PortAllocator::{new, address_index, try_next_port, Default}` and
  all the private state machine fns kept inside `allocator.rs`
- `PortAllocatorSnapshot { allocations_total, reuses_total,
  exhaustion_total, live_count }`
- `StaticNatEntry`, `StaticNatTable`,
  `StaticNatTable::{from_snapshots, match_dnat, match_snat,
  is_empty, external_ips}`
- `DnatKey`, `DnatValue`, `DnatTable`,
  `DnatTable::{from_snapshots, lookup, is_empty, destination_ips}`
- Free fns: `parse_source_nat_rules`, `parse_source_nat_rules_with_previous`,
  `release_source_nat_allocation`, `rollback_source_nat_allocation`,
  `source_nat_pool_statuses`, `match_source_nat`,
  `match_source_nat_result`, `match_source_nat_result_for_tuple`

## Hidden invariants the change must preserve

1. **Allocator lock scope.** `PortAllocator::shared.live` is a single
   `Mutex<PortAllocatorLiveState>`. Every method that mutates live
   state acquires the mutex once and holds it for the duration of the
   critical section. The refactor MUST NOT split this mutex across
   files in a way that lets a second mutex creep in. Mitigation: the
   mutex and the `PortAllocatorLiveState` struct both live in
   `allocator.rs` and stay private.
2. **Side-effect ordering inside `allocate_translation`.** The function
   does: GC → existing-flow shortcut → max-tracked-flows check →
   persistent-key reuse-or-expire dance → port claim → owner assign →
   activation bookkeeping. This ordering must be preserved bit-for-bit
   (rollback semantics depend on `activation_saw_completion`,
   `activation_previous_expires_at_ns`, and
   `activation_had_previous_lease` being set BEFORE the new lease is
   committed). Pure code motion preserves this.
3. **Atomic counter ordering.** `allocations_total`, `reuses_total`,
   `exhaustion_total`, `addr_counter_v4`, `addr_counter_v6`, and the
   per-pool `counters` Vec use `Ordering::Relaxed`. This is correct
   only because the `live` mutex provides happens-before for the
   user-visible state. Moving the file MUST NOT tempt anyone to relax
   the mutex into a sharded lock — the relaxed atomics would break.
4. **Rollback `activation_*` fields.** The persistent lease has three
   "activation epoch" fields that snapshot pre-update state for
   rollback. The `rollback_flow` path reads them; `allocate_translation`
   writes them. Both stay in `allocator.rs` so the invariant is local.
5. **`MAX_SOURCE_NAT_POOL_TRACKED_FLOWS` bound.** The cap is checked at
   allocation time AND at construction time
   (`allocator_capacity().min(MAX_...)`). Both sites stay in
   `allocator.rs`.
6. **DNAT hit counter semantics.** DNAT does NOT currently maintain
   a per-rule hit counter inside `DnatTable` itself; hit counting is
   done by the caller (`afxdp/coordinator/status.rs` and friends) via
   the same `NatDecision` flow. The refactor preserves this — no new
   counter, no removed counter. (This is what acceptance criterion
   "preserve DNAT hit-counter semantics" reduces to here.)
7. **Static NAT 1:1 bidirectionality.** `match_dnat` and `match_snat`
   are mirror lookups on the same `StaticNatEntry` Vec; both kept
   together in `static_nat.rs`.
8. **NAT64 path is in nat64.rs and untouched.** This refactor does NOT
   move or modify nat64. `NatDecision.nat64` and `nptv6` bits stay on
   the cross-cutting `NatDecision` type in `mod.rs`.
9. **Persistent lease expiration BTrees.** `lease_expirations`
   (global) and `lease_expirations_by_addr` (per-address) must be kept
   in sync — every insert/remove goes through
   `insert_lease_expiration_locked` / `remove_lease_expiration_locked`.
   Both helpers stay in `allocator.rs`.
10. **Recycled-port indexes.** `recycled_ports_by_addr` and
    `next_port_offset_by_addr` are sized at allocator construction to
    `num_addresses` and must stay that length. Index access at
    `addr_index` is a hot path. `PortAllocatorLiveState::new` is the
    sizing invariant; lives in `allocator.rs`.
11. **HA sync portability.** `NatDecision`, `SourceNatFlowKey`,
    `SourceNatFailureReason` are serialized over the HA fabric via
    `event_stream`. Field shape, variant ordering, and `derive` traits
    must be preserved bit-for-bit. Pure code motion preserves derives.
12. **Test reachability of private items.** `nat_tests.rs` uses
    `use super::*;` and reaches into `PortAllocator::release_flow`
    (private) and `SourceNatFlowKey::persistent_source_key` (private).
    After the split, the tests file lives at `nat/tests.rs` and its
    `use super::*;` resolves to `mod.rs` — which does NOT have those
    items. We will replace the broad import with explicit
    `use super::allocator::*; use super::source::*; ...` etc. and
    promote test-touched items to `pub(super)` where needed.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Pure code motion; no logic changes. Mitigated by full `cargo test --release` (952+ tests) + 5x flake on `nat_tests`. |
| Lifetime / borrow-checker | LOW | All moves are between sibling files in the same crate; no lifetime parameter changes. `PoolAddressFamily<'a>` lives in `allocator.rs` next to its only caller. |
| Performance regression | LOW | No new allocations; no new mutexes; no new atomics; no inlining boundary changes that matter (LLVM already inlines across modules in the same crate). Verified by Pass A multi-stream reverse smoke (`-P 12 -t 10 -R` on v4 and v6). |
| Architectural mismatch (#961 / #946-Phase-2) | LOW | Refactor follows the issue exactly. Issue is explicit about the target shape; we are not inventing a structural premise. Risk is "PLAN-KILL because perf gain is too small" — that's an acceptable verdict (issue is modularity-only). |

## Test plan

- [ ] `cargo build --release` clean (no warnings introduced)
- [ ] `cargo test --release` — full userspace-dp suite passes
- [ ] 5x flake on `cargo test --release -p userspace-dp nat` (named
      to all `nat_*` tests via the `nat::tests::` module path)
- [ ] Go suite: `make test` (30 packages) passes
- [ ] **No per-PR smoke per Wave-2 rules.** Marker
      `<!-- AWAITING-BATCH-MERGE -->` placed on the PR; NAT
      correctness validated by the every-10 batch smoke (v4+v6 ×
      push+`-R` × CoS-off+CoS-on per-class).

## Out of scope (explicitly)

- Splitting `nat64.rs` further. It is already a separate file and
  issue #1542 does not ask for it.
- Splitting `nptv6.rs`. Same reason.
- Introducing a new persistent-lease module separate from the
  allocator. Issue says the allocator module "should own all
  translated-tuple ownership, live-flow, persistent-lease,
  expiration-index, rollback, and recycled-port invariants" — so we
  keep persistent leases inside `allocator.rs`, NOT in their own file.
  This is a deliberate read of the issue: bullet point in the body
  groups "pool-mode allocator state" and "persistent NAT lease
  lifecycle" as separate concerns at the description level, but the
  acceptance criterion is explicit that the allocator owns lease
  invariants. We follow the acceptance criterion.
- Changing the `PortAllocator` public API. Acceptance criterion 2
  asks for "small and explicit" surface — the current surface IS
  small (allocate via `match_source_nat_result_for_tuple` →
  `allocate_translation`; release via `release_source_nat_allocation`;
  rollback via `rollback_source_nat_allocation`; status via
  `source_nat_pool_statuses`; reuse-check via
  `source_nat_runtime_compatible`). We do not redesign it.
- Performance changes. No allocation removal, no map sharding, no
  lock-free conversion. This is modularity-only.

## Open questions for adversarial review (PLAN-KILL invitations)

1. **Is the modularity win worth the churn?** `nat.rs` is 1,605 LOC.
   Project gate is ~2,000 LOC and ~100 LOC fns / ~8 params. We are
   under the gate. Is splitting an under-gate file really worth a
   review cycle? PLAN-KILL acceptable.
2. **Should persistent leases be a separate file?** Issue description
   lists them as a separate concern but acceptance criterion folds
   them into the allocator. We picked the acceptance criterion. Is
   the description's reading better — i.e., should we have
   `nat/persistent.rs` even at the cost of a tighter
   `pub(super)`-only API between allocator and persistent? Risk: a
   cross-file API for the lease state machine means the rollback
   `activation_*` fields cross a file boundary, which is exactly
   what we are trying to avoid. We argue NO; reviewers may disagree.
3. **`mod.rs` vs flat siblings.** Could we just write
   `nat_source.rs`, `nat_allocator.rs`, etc. in `userspace-dp/src/`
   as flat siblings — like `nat64.rs` and `nptv6.rs` are today?
   Issue says `nat/mod.rs` explicitly, so we follow the issue. But
   if reviewers think flat-sibling convention is the in-crate norm
   (it largely is for nat64/nptv6/screen/policy/session), this is
   PLAN-NEEDS-MAJOR and we re-shape.
4. **`status.rs` is tiny (~35 LOC). Worth a file?** Could fold into
   `source.rs` (where the rules live that drive it) or into
   `allocator.rs` (which owns the snapshot it reads). Issue lists
   it as its own module; we follow. PLAN-NEEDS-MAJOR if reviewers
   think one-file status is over-fragmentation.
5. **Test file split.** Should we split `nat_tests.rs` (2,704 LOC!)
   into per-module test files at the same time? It's bigger than
   the production file. We chose NOT to split it in v1 because
   that triples the diff and risks losing test coverage in a move.
   But the issue's modularity argument applies to tests too —
   reviewers may demand we split tests in the same PR. PLAN-NEEDS-MAJOR
   if so.
6. **Pure-code-motion claim.** The only non-mechanical change is
   visibility (`pub(crate)` → `pub(super)` inside the new module
   tree). Are there subtle semantic implications of swapping
   `pub(crate)` to `pub(super)` on items that the test sub-module
   reaches through? `pub(super)` on `allocator::PortAllocator` means
   `super` = `nat` = `nat/mod.rs`; `nat/mod.rs` then re-exports as
   `pub(crate)`. From outside the `nat` module the symbol is still
   reachable as `crate::nat::PortAllocator`. From `nat/tests.rs`
   the symbol is reachable as `super::allocator::PortAllocator` or
   `super::PortAllocator` via the re-export. We believe this is
   safe; reviewers should confirm.
7. **Build-time ordering / circular module deps.** `source.rs` needs
   `PortAllocator` (it calls `allocate_translation`,
   `release_flow`, `rollback_flow`). `allocator.rs` needs
   `SourceNatFlowKey` (the allocator's `live_by_flow` map is keyed
   by it; `allocate_translation`'s `flow` parameter is one).
   `SourceNatFlowKey` is a 16-line POD struct + one `fn
   persistent_source_key`. We will place `SourceNatFlowKey` in
   `source.rs` and have `allocator.rs` `use super::source::SourceNatFlowKey`.
   No circular import — Rust modules can `use` each other freely as
   long as type definitions are non-recursive. Reviewers should
   confirm this still compiles.
