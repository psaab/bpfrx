# #1329 — shared_cos_lease.rs hot-fn extract — Plan

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`userspace-dp/src/afxdp/types/shared_cos_lease.rs` is currently 1992
prod LOC (issue body cites 1791; the file has grown since). Two hot
functions are the LOC tentpoles and the modularity-discipline trigger:

- `SharedCoSQueueLease::maybe_rotate_epoch_v8(&self, now_ns: u64)`
  at L1497–L1710 — **214 LOC**, single fn, exceeds the >200 LOC bar
  in `docs/engineering-style.md`.
- `publish_equal_flow_epoch_v8(...)` at L1713–L1854 — **142 LOC**,
  9-param free fn (close to the >8-param smell on the helper).

Both functions form the CoS shared-lease epoch-rotation hot path:
`maybe_rotate_epoch_v8` runs **per scheduler tick on RG-0 primary
when the v8 lease is configured**, and `publish_equal_flow_epoch_v8`
is its conditional branch when `rate_mode == EqualFlowSuppress`.
Atomic memory ordering is correctness-critical (seqlock pattern,
ATOMIC-SWAP `packed_granted`, peer-utilization gate); #1229 v8 and
#1231 v5 both took many review rounds to land.

Wave-3 PR objective: **pure code-motion extract** into a directory
module so the file shrinks and the two hot functions live in
named, individually reviewable submodules. **No algorithm change.
No ordering change. No new allocation. Function bodies are moved
byte-for-byte modulo the visibility/path adjustments that the move
strictly forces.**

If reviewers conclude the perf gain is too small to justify the
churn, **PLAN-KILL is an acceptable verdict.**

## Honest scope/value framing

The "value" here is purely modularity-discipline + future-review
ergonomics:

- File drops from 1992 → ~1640 LOC (`mod.rs`) + ~220 LOC
  (`rotate_epoch_v8.rs`) + ~150 LOC (`publish_equal_flow_epoch_v8.rs`).
- The 214-LOC fn becomes a 220-LOC file the reviewer can read in
  isolation against #1229/#1231 history without 1700 lines of
  surrounding context.
- The 142-LOC 9-param free fn moves to its own file but its
  signature is **preserved unchanged** in this PR. Folding the
  9 params into a context struct is **out of scope** for this
  step (issue body suggests it; mixing it with the move makes the
  diff much harder to verify byte-identical, and the param surface
  is internal to the crate).

There is **no runtime perf claim**. `#[inline]` annotations on
moved fns preserve codegen. Codegen-unit boundary is the same
because both moved fns are still inside the `shared_cos_lease` mod
tree (sibling submodules of `mod.rs`, not separate crates).

Cost: zero allocations introduced, zero atomic-ordering edits,
zero public-API surface change (the `pub(in crate::afxdp) use`
re-export list in `types/mod.rs` is identical pre/post).

## What's already shipped / partially batched

- #1229 Phase 6 v8 — epoch rotation state machine.
- #1231 v5 — ATOMIC-SWAP `packed_granted` (linearization-point fix).
- #1290 round-2 — peer-utilization demand-gate.
- The test file `shared_cos_lease_tests.rs` is already a sibling
  submodule via `#[cfg(test)] #[path = "shared_cos_lease_tests.rs"]
  mod tests;`. The Wave-3 layout move requires re-pointing this
  `#[path]` to `"../shared_cos_lease_tests.rs"` (or moving the
  tests file into the dir alongside `mod.rs`). The plan picks the
  in-dir relocation to keep the tests adjacent to the code they
  cover and the `#[path]` shorter.

## Concrete design

### Target layout (Wave 3 standing rule)

```
userspace-dp/src/afxdp/types/
  shared_cos_lease/
    mod.rs                            ~1640 LOC — everything else
    rotate_epoch_v8.rs                ~220  LOC — maybe_rotate_epoch_v8
    publish_equal_flow_epoch_v8.rs    ~150  LOC — publish_equal_flow_epoch_v8
    shared_cos_lease_tests.rs          1009 LOC — relocated test sibling
```

Delete the flat `shared_cos_lease.rs` and `shared_cos_lease_tests.rs`
files (mechanical move; `git mv` for tests, manual carve for code).

### Move mechanics — `maybe_rotate_epoch_v8`

The function is an **inherent method** on `SharedCoSQueueLease`:

```rust
impl SharedCoSQueueLease {
    fn maybe_rotate_epoch_v8(&self, now_ns: u64) { ... }
}
```

To move it to a sibling file without changing its `&self` shape,
the destination file `rotate_epoch_v8.rs` reopens the same `impl`
block:

```rust
// rotate_epoch_v8.rs
use super::*;
use std::sync::atomic::Ordering;

impl SharedCoSQueueLease {
    #[inline]
    pub(super) fn maybe_rotate_epoch_v8(&self, now_ns: u64) {
        // body byte-identical to L1497–L1710 of master shared_cos_lease.rs.
    }
}
```

- Visibility widens from inherent-private to `pub(super)` because the
  caller chain inside `mod.rs` is now in a parent module. **This is
  the only forced visibility delta.** The call sites of
  `maybe_rotate_epoch_v8` are all within the same crate, all already
  inside `mod.rs`.
- `#[inline]` is **added** to preserve codegen. The original fn is
  inherent-private with one call site (per-tick), so the compiler
  already inlines it in practice; `#[inline]` makes that intent
  explicit across the module boundary.

The body calls `publish_equal_flow_epoch_v8(...)` as a free fn —
that call needs the helper visible to `rotate_epoch_v8.rs`. The
helper file's `pub(super) fn` import path handles that (both
sibling submodules under `shared_cos_lease`).

### Move mechanics — `publish_equal_flow_epoch_v8`

The function is a free fn (not on any impl):

```rust
// publish_equal_flow_epoch_v8.rs
use super::*;
use std::sync::atomic::Ordering;

#[inline]
pub(super) fn publish_equal_flow_epoch_v8(
    v8: &V8State,
    new_tag: u32,
    n_workers: usize,
    active_outside_scratch: bool,
    active_by_worker: &[bool],
    active_flows_by_worker: &[u32],
    demanded_by_worker: &[bool],
    prev_grants: &[u32],
) {
    // body byte-identical to L1713–L1854.
}
```

Visibility widens from file-private to `pub(super)`. **The 9-param
signature is preserved verbatim. Param-pack into a context struct
is OUT OF SCOPE for this PR.**

`#[cold]` is appropriate on the `fail_open` early-return branches
inside the helper body — **but I will NOT add `#[cold]` to the
inner branches in this PR** because that's a behavior-shape change
the move alone shouldn't bundle. The function as a whole is **hot**
(per-tick), so no `#[cold]` on the outer fn either.

### `mod.rs` adjustments

The crate-private `pub(in crate::afxdp) use shared_cos_lease::{...}`
re-export list in `userspace-dp/src/afxdp/types/mod.rs` stays
byte-identical because:

- Items currently re-exported (e.g. `SharedCosLease`, `SharedCoSRootLease`,
  `V8RateMode`, `V8EqualFlowFailOpenReason`, `EPOCH_DURATION_NS`, etc.)
  all live in `mod.rs` of the new dir module, not in the new submodules.
- `maybe_rotate_epoch_v8` and `publish_equal_flow_epoch_v8` are NOT
  in the re-export list (they are internal-only).

The two `mod` declarations inside `mod.rs`:

```rust
mod publish_equal_flow_epoch_v8;
mod rotate_epoch_v8;
```

both private to the `shared_cos_lease` module tree.

### Tests file relocation

```bash
git mv userspace-dp/src/afxdp/types/shared_cos_lease_tests.rs \
       userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs
```

Update the `#[path]` attribute in the new `mod.rs`:

```rust
#[cfg(test)]
#[path = "shared_cos_lease_tests.rs"]   // now resolves to the dir-local file
mod tests;
```

Path becomes shorter, not longer, because `mod.rs` and the
relocated test file are in the same directory. **No test body
edits.**

## Public API preservation

- `SharedCoSQueueLease`, `SharedCoSRootLease`, `SharedCoSExactBacklog`,
  `SharedCoSQueueVtimeFloor`, `PaddedVtimeSlot`, `V8RateMode`,
  `V8EqualFlowFailOpenReason`, `V8EqualFlowSuppressState`,
  `SharedCoSEpochState`, `SharedCoSLeaseConfig`, `SharedCoSLeaseState`,
  `EPOCH_DURATION_NS`, `EQUAL_FLOW_VALID_STREAK_REQUIRED`,
  `EQUAL_FLOW_MIN_WORKER_UTIL_NUM`, `EQUAL_FLOW_MIN_WORKER_UTIL_DEN`,
  `compute_shared_cos_lease_config`, `pack_shared_cos_lease_credits`,
  `unpack_shared_cos_lease_credits`, `shared_cos_lease_acquire`,
  `shared_cos_lease_consume`, `shared_cos_lease_available_cap`,
  `shared_cos_lease_release_unused`, `refill_shared_cos_lease_state`,
  `try_bump_outstanding`, `bump_epoch_event`, `worker_grant_bump`,
  `tag_checked_rollback`.
- All inherent methods on `SharedCoSQueueLease` (including
  `equal_flow_cap_v8`, `v8_equal_flow_fail_open_reason`, etc.):
  signatures unchanged.

## Hidden invariants the change must preserve

1. **Seqlock pattern atomic ordering.** The CAS `seq EVEN→ODD` →
   ATOMIC-SWAP `packed_granted` → … → store(`seq ODD→EVEN`,
   `Release`) sequence is byte-identical to master. No `Ordering`
   constant is changed. No re-ordering of ops within the rotation
   body is permitted.

2. **ATOMIC-SWAP linearization point.** `packed_granted.0.swap(...,
   AcqRel)` at L1531-1535 is the publish point for prev_granted
   per #1231 v5; preserved verbatim.

3. **Per-worker scratch arrays on the stack.**
   `signaled_by_worker[32]`, `demanded_by_worker[32]`,
   `prev_grants[32]`, `active_by_worker[32]`,
   `active_flows_by_worker[32]` are stack-allocated; the move must
   keep them stack-allocated (no boxing, no `Vec`).

4. **No allocations per tick.** `maybe_rotate_epoch_v8` and
   `publish_equal_flow_epoch_v8` both run per-tick when the lease
   is active. Neither must introduce `Box`/`Vec`/`String`/`format!`.

5. **`#[inline]` on hot path** preserves the original codegen
   shape (call-site inlining across the module boundary).

6. **`bypass_grace_rotations_remaining` arm/decay** (#1290 v2) at
   L1652-1675 stays in `maybe_rotate_epoch_v8`. Splitting this
   into sub-helpers within the file would be a code-shape change
   I'm explicitly NOT doing — pure move only.

7. **Test file `#[path]` relocation.** The test file moves into
   the new dir alongside `mod.rs`; `mod tests` declaration moves
   to `mod.rs` (not to either submodule). All 1009 LOC of tests
   pass unchanged because they `use super::*;` and the super for
   `mod tests` is now `shared_cos_lease/mod.rs`, which still has
   all the symbols the tests reach for.

## Risk assessment

| Risk class | Verdict | Reasoning |
|---|---|---|
| Behavioral regression | **LOW** | Pure move; bodies byte-identical; ordering preserved; #[inline] preserves codegen. Test suite (1009 LOC) covers the rotation state machine and unchanged. |
| Lifetime / borrow-checker | **LOW** | `&self`-method and free-fn signatures preserved; `pub(super)` visibility widening is the only change. No new references, no new lifetimes. |
| Performance regression | **LOW** | `#[inline]` explicitly preserves the inlining that was implicit in master. No new allocations. No new atomic ops. No new branches. |
| Architectural mismatch (#946 Phase 2 / #961 pattern) | **LOW** | This is NOT a state-machine redesign. This is NOT a control-flow split (we are moving the fns as opaque units, not splitting them into try_claim/snapshot/publish phases per the issue body's suggestion). The fn-split refactor the issue body sketches **is out of scope here**. |

## Test plan

1. `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build` — clean.
2. `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release` — full cargo suite (952+ tests).
3. **5/5 flake check** on a representative epoch-rotation test from
   `shared_cos_lease_tests.rs` — pick the one that exercises seqlock
   rotation under contention.
4. `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — all 30 Go packages.
5. **Smoke on loss userspace cluster** — deferred to AWAITING-BATCH-MERGE
   per Wave-3 retirement-chain rule. The PR records the build+test
   matrix; one comprehensive batch smoke runs at end of wave.

## Out of scope (explicitly)

- **Param-packing `publish_equal_flow_epoch_v8`'s 9 args into a
  context struct.** Issue body suggests this. NOT in this PR.
  Would require touching the rotation caller too and a separate
  reviewer agreement on the struct shape.
- **Splitting `maybe_rotate_epoch_v8` into try_claim_rotation /
  snapshot_rotation_state / publish_new_epoch.** Issue body
  suggests this. NOT in this PR — that's a control-flow rewrite
  with multiple seqlock-state-aware sub-functions; pure-move
  ergonomics gain is achieved by the file split alone.
- **`#[cold]` annotations on fail_open paths.** Could be added in
  a follow-up; mixing them with the move loses the byte-identical
  diff property.
- **Renaming the `_v8` suffix.** Co-existing v9 is the migration
  pattern per issue body.

## Open questions for adversarial review

1. **Is the directory-module layout the right call vs. flat
   sibling files?** Wave-3 standing rule says directory. Confirm
   this isn't an over-rotation for a 2-fn extract.

2. **Visibility widening to `pub(super)`** — does this leak any
   API surface beyond what `mod.rs` already exposes? Re-export
   list audit above claims it does not; verify.

3. **`#[inline]` correctness** — is adding `#[inline]` across the
   submodule boundary a safe no-op vs. master where the fn was
   inherent-private one-call-site (compiler-decided inline)? Or
   does it risk forcing inlining in a way that bloats `.text` or
   regresses cache?

4. **Test file `#[path]` relocation** — moving the `mod tests`
   declaration from `shared_cos_lease.rs` (deleted) to
   `shared_cos_lease/mod.rs` and shortening `#[path]` from
   `"shared_cos_lease_tests.rs"` to `"shared_cos_lease_tests.rs"`
   (now in the same dir) — any way this masks a stale path that
   used to be load-bearing? rust-analyzer / cargo-test path
   resolution edge case?

5. **Atomic-ordering preservation across module boundary** —
   `std::sync::atomic::Ordering` semantics are not affected by
   which `.rs` file the `load`/`store`/`swap` lives in. Confirm
   that the move cannot accidentally change any happens-before
   edge. (My read: it cannot. Codex/AGY should verify.)

6. **Is the LOC-discipline win worth ANY churn?** 1992 → 1640
   `mod.rs` still trips the Tier-2 file-size boundary. If the
   "win" is small and the file is still big, PLAN-KILL is on
   the table per the standing offer.

7. **Risk that the inherent-impl reopened in `rotate_epoch_v8.rs`
   silently shadows a method.** No — Rust would reject duplicate
   inherent methods. But the reviewer should verify no other
   `fn maybe_rotate_epoch_v8` exists anywhere in the crate.

## Verdict request

PLAN-READY / PLAN-NEEDS-MINOR / PLAN-NEEDS-MAJOR / PLAN-KILL.
PLAN-KILL is the right call if the modularity win is too small
to justify the directory-layout churn, or if any of the
invariants above looks like it could subtly drift under the move.
