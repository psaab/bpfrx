# #1351 — umem/mod.rs: extract snapshot + publish_binding_debug_state

**Status:** DRAFT v3 — addresses Codex round-2 finding on `pub(super)` vs `pub(in crate::afxdp)` and corrects caller audit

## Issue framing

`userspace-dp/src/afxdp/umem/mod.rs` is 1648 LOC. Two functions
account for ~450 LOC of telemetry/observability rendering that
sits next to UMEM frame-management hot-path code:

- `impl BindingLiveState { fn snapshot(&self) -> BindingLiveSnapshot }`
  at `umem/mod.rs:872..1144` — 273 LOC body (issue cites 246; the
  exact span depends on counting style — point stands).
- Free function `publish_binding_debug_state(binding: &mut BindingWorker)`
  at `umem/mod.rs:1403..1607` — 205 LOC body.

`docs/engineering-style.md` flags ">100 LOC" as a refactor cue.
Both are >2x. The decomposition asked for in the issue is pure
file split with optional helper grouping for `snapshot()`.

## Honest scope/value framing

This is **pure code motion** plus a `mod` declaration change.
Zero behavior change, zero perf-relevant code reorganization,
zero data-structure churn. The win is readability: `umem/mod.rs`
drops to ~1.2k LOC and reads as "UMEM lifecycle + BindingLiveState
construction + hot-path push", while telemetry rendering lives in
its own files where reviewers can find it.

Cold-path classification (refined per Codex round-2):

- `snapshot()` runs on operator queries via `coordinator.refresh_bindings`
  (gRPC `show xpf userspace status` and Prometheus scrape, ≤1/s).
  Pure cold.
- `publish_binding_debug_state()` itself runs every ~65ms / 65k
  poll ticks — pure cold. Pure cold.
- BUT: `update_binding_debug_state()` (the wrapper that gates
  `publish_binding_debug_state` behind the 0xFFFF poll mask) is
  CALLED from hot worker/drain paths (`tx/dispatch.rs:925`,
  `tx/drain.rs:248,314`, `tx/rings.rs:69,150`, `worker/lifecycle.rs:113,316`,
  `session_glue/mod.rs:943`). The wrapper's hot cost is one
  `wrapping_add(1)` + mask + branch — already minimal.

This refactor does NOT change the wrapper's hot-call shape:
`advance_debug_state_publish_counter` keeps `&mut WorkerTimers` and
the gate evaluation is unchanged. Moving the wrapper into
`debug_state.rs` does not introduce a function boundary that the
optimizer would not already have crossed (the wrapper was always
in a separate file from its callers; the call is via direct fn
reference, not a vtable). Risk: LOW.

If reviewers conclude that the readability win is too small to
justify the churn or that the slow-path / cold-path classification
is wrong, PLAN-KILL is an acceptable verdict.

## What's already shipped / partially batched

- `umem/mmap.rs`, `umem/profile.rs`, `umem/tests.rs` already exist
  as sibling files — the directory layout pattern is established.
- `umem/profile.rs` already houses `OwnerProfileOwnerWrites` /
  `OwnerProfilePeerWrites` and is re-exported via
  `pub(in crate::afxdp) use mmap::MmapArea;` style from `mod.rs`.
- `umem/tests.rs` is loaded via `#[path = "tests.rs"] mod tests`
  and uses `use super::*;` so any symbol it touches must remain
  visible at the `umem` module root (or be re-exported there).

## Concrete design

### Layout

```
userspace-dp/src/afxdp/umem/
├── mod.rs           // ~1.2k LOC after split — UMEM, BindingLiveState
│                    //   construction + mutators + push_redirect_inbox + free
│                    //   helpers; pub(super) `use` re-exports for moved items
├── snapshot.rs      // NEW: impl BindingLiveState { fn snapshot } + snapshot_hist
├── debug_state.rs   // NEW: publish_binding_debug_state +
│                    //   advance_debug_state_publish_counter +
│                    //   idle_debug_state_publish_due +
│                    //   update_binding_debug_state +
│                    //   update_binding_idle_debug_state +
│                    //   flush_v_min_scratches_into +
│                    //   DEBUG_STATE_PUBLISH_MASK +
│                    //   IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS
├── mmap.rs          // unchanged
├── profile.rs       // unchanged
├── tests.rs         // unchanged (loads via #[path], uses super::*)
```

### `mod.rs` changes

```rust
mod debug_state;
mod mmap;
mod profile;
mod snapshot;

pub(in crate::afxdp) use mmap::MmapArea;
pub(in crate::afxdp) use profile::{OwnerProfileOwnerWrites, OwnerProfilePeerWrites};

// CRITICAL VISIBILITY NOTE (Codex round-2 finding):
//
// `snapshot()` (called from `coordinator/mod.rs:1159`) and
// `update_binding_debug_state` (called from `worker/mod.rs:444`,
// `tx/dispatch.rs:925`, `tx/rings.rs:69,150`, `tx/drain.rs:248,314`,
// `worker/lifecycle.rs:113,154,316`, `session_glue/mod.rs:943`) MUST
// be visible across the `crate::afxdp` sibling-module tree. Today
// they sit in `umem/mod.rs` with `pub(super) fn` — which from
// `mod.rs`'s perspective means visible in `crate::afxdp`.
//
// After the move into `snapshot.rs` / `debug_state.rs`, `pub(super)`
// would mean visible in `crate::afxdp::umem` only. That is too
// narrow. The precedent established by `mmap::MmapArea` and
// `profile::{Owner,Peer}` is `pub(in crate::afxdp)`. The same rule
// applies here.
//
// Also: a `pub(super) use` of a `pub(super)` child triggers E0364
// (documented in `userspace-dp/src/afxdp/tx/mod.rs:38`). The child
// items therefore declare `pub(in crate::afxdp)` directly; `mod.rs`
// only declares `mod snapshot; mod debug_state;` without an
// explicit `use` line (inherent methods reach through the impl
// declaration; free fns are reached via their fully-qualified
// child path or via `use crate::afxdp::umem::debug_state::*` at the
// caller — but the simpler form is `pub(in crate::afxdp) use
// debug_state::{...}` from mod.rs because that matches the
// existing mmap/profile pattern).
//
// Constants are re-exported alongside the free fns because
// `umem/tests.rs` references DEBUG_STATE_PUBLISH_MASK at
// tests.rs:1567,1575 and IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS at
// tests.rs:1541,1550,1555,1558,1610,1625 through `use super::*;`.
pub(in crate::afxdp) use debug_state::{
    advance_debug_state_publish_counter,
    flush_v_min_scratches_into,
    idle_debug_state_publish_due,
    update_binding_debug_state,
    update_binding_idle_debug_state,
    DEBUG_STATE_PUBLISH_MASK,
    IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS,
};
```

`snapshot()` is an inherent method on `BindingLiveState`; placing
`impl BindingLiveState { ... }` in `umem/snapshot.rs` keeps it on
the same type without needing a re-export. The `snapshot_hist`
helper (private, `fn`) follows the method into the new file.

### `snapshot.rs` content

```rust
use super::*;

impl BindingLiveState {
    pub(in crate::afxdp) fn snapshot(&self) -> BindingLiveSnapshot { /* moved verbatim */ }

    #[inline]
    fn snapshot_hist(hist: &[AtomicU64; DRAIN_HIST_BUCKETS]) -> [u64; DRAIN_HIST_BUCKETS] {
        std::array::from_fn(|i| hist[i].load(Ordering::Relaxed))
    }
}
```

Note: today `snapshot()` is declared `pub(super) fn snapshot` in
`umem/mod.rs`. The `super` of `mod.rs` is `crate::afxdp`, so
`pub(super)` there means `pub(in crate::afxdp)`. After the move
into `snapshot.rs`, the same effective visibility is spelled
`pub(in crate::afxdp)`. This is required for the
`coordinator/mod.rs:1159` caller.

Note: `snapshot_hist` is an associated function (no `&self`), but
it's called via `Self::snapshot_hist(...)` from within `snapshot()`.
Moving both into the same `impl` block preserves that call shape.

### `debug_state.rs` content

```rust
use super::*;
use crate::afxdp::worker::WorkerTimers;

pub(in crate::afxdp) const DEBUG_STATE_PUBLISH_MASK: u32 = 0xFFFF;
pub(in crate::afxdp) const IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS: u64 = 65_000_000;

pub(in crate::afxdp) fn advance_debug_state_publish_counter(...) -> bool { /* moved */ }
pub(in crate::afxdp) fn idle_debug_state_publish_due(...) -> bool { /* moved */ }
pub(in crate::afxdp) fn update_binding_debug_state(...) { /* moved */ }
pub(in crate::afxdp) fn update_binding_idle_debug_state(...) { /* moved */ }
fn publish_binding_debug_state(...) { /* moved, stays private to debug_state.rs */ }
pub(in crate::afxdp) fn flush_v_min_scratches_into<'a, I>(...) where I: IntoIterator<...> { /* moved */ }
```

Visibility changes: the originals are package-private (no
`pub(super)`) free fns sitting in `mod.rs`. To call them from
`debug_state.rs` -> still in the same crate -> they need at least
`pub(super)` visibility so the `mod.rs` re-export `pub(super) use
debug_state::...` resolves. Today three of the four already have
`pub(super)`; `advance_debug_state_publish_counter` and
`idle_debug_state_publish_due` are private but called only inside
`mod.rs`. After the move they need `pub(super)` so tests at
`umem::tests` can still call them via `super::*`. **This is a
visibility loosening from `private` to `pub(super)` — not a
behavior change.** Tests reach them today through `super::*` only
because they live in the same module.

### Helper-grouping decision

The issue's "decomposition sketch" mentions optional helper
grouping for `snapshot()` (`load_socket_block`, `load_xsk_block`,
etc.). **I am NOT doing that in this PR.** Rationale:

- Helper grouping changes side-effect ordering perception: a
  reader scans the helpers separately and must trust each
  helper's `Relaxed`-load discipline.
- The snapshot's current shape is one tight 250-LOC struct
  literal where every read uses `Ordering::Relaxed` against a
  single owner. Splitting it into N helper structs adds N small
  intermediate structs that don't make the wire protocol any
  cleaner and might tempt a future PR to "optimize" the struct
  layout.
- Pure code motion is the lowest-risk possible PR. Helper
  grouping is a follow-up if reviewers want it.

Reviewers may push back and insist on the grouping; if both
require it, I'll do it as a second commit on this branch.

## Public API preservation

After this split, every external caller in the table below
continues to compile unchanged.

| Caller | Symbol | Visibility |
| --- | --- | --- |
| `coordinator/mod.rs:1159` | `live.snapshot()` (production hot caller — `refresh_bindings`) | inherent method; `pub(in crate::afxdp)` |
| `coordinator/tests.rs:1086` | `live.snapshot()` | inherent method; `pub(in crate::afxdp)` |
| `worker_runtime_tests.rs:25` | `atomics.snapshot()` | inherent method |
| `tx/rings.rs:18,69,150` | `umem::update_binding_debug_state` | `pub(in crate::afxdp) use` from `mod.rs` |
| `tx/drain.rs:248,314` | `umem::update_binding_debug_state` | same |
| `tx/dispatch.rs:925` | `update_binding_debug_state` (missed in v2 audit) | same |
| `worker/mod.rs:444` | `update_binding_debug_state` (missed in v2 audit) | same |
| `worker/lifecycle.rs:113,154,316` | `update_binding_debug_state` + `update_binding_idle_debug_state` | same |
| `session_glue/mod.rs:943` | `update_binding_debug_state` | same |
| `umem/tests.rs:1316,1377` | `crate::afxdp::umem::flush_v_min_scratches_into` | absolute path resolves through `pub(in crate::afxdp) use` |
| `umem/tests.rs:1541,1550,1555,1558,1567,1575,1610,1625` | constants + `idle_debug_state_publish_due` + `advance_debug_state_publish_counter` + `update_binding_idle_debug_state` | tests use `super::*` -> resolves through re-exports |

NOTE: `slowpath.rs:237,481` cited in v2 was wrong — those are
`SharedStatus::snapshot`, NOT `BindingLiveState::snapshot`. Codex
caught this in round-2.

## Hidden invariants the change must preserve

1. **Side-effect ordering inside `snapshot()`** — every atomic load
   is `Ordering::Relaxed`. Moving the impl block does not reorder
   reads. The note at `umem/mod.rs:1083..1090` documents that
   read-side tearing of owner-profile histograms is acceptable;
   that comment moves with the function.
2. **`snapshot_hist` as `&self`-less associated fn** — call shape
   `Self::snapshot_hist(...)` is preserved by keeping both in the
   same impl block.
3. **`publish_binding_debug_state` as free fn taking `&mut
   BindingWorker`** — it mutates `binding.tx_counters`,
   `binding.flow.flow_cache`, and `binding.cos.cos_interfaces`. The
   four pending counter fields are non-atomic `u64` scratchpads;
   the flush pattern (compare to 0, fetch_add atomic, zero scratch)
   must be byte-identical post-move.
4. **`flush_v_min_scratches_into` already extracted for
   testability** — referenced by `umem/tests.rs:1316,1377`. Its
   absolute path `crate::afxdp::umem::flush_v_min_scratches_into`
   must continue to resolve via re-export.
5. **`DEBUG_STATE_PUBLISH_MASK` and `IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS`** —
   referenced by tests at `tests.rs:1541,1550,1555,1558,1567,1575,1610,1625`
   via `use super::*;`. After the move they MUST gain `pub(super)`
   visibility and be re-exported from `mod.rs` so tests still see
   them at `umem::*` (AGY round-1 finding).
6. **`use super::*;` at top of `tests.rs`** — `super` is the `umem`
   module. After split, any symbol previously visible in `umem::`
   must still be visible there via re-export.

## Risk assessment

| Class | Risk | Mitigation |
| --- | --- | --- |
| Behavioral regression | LOW | Pure code motion: no statements added/removed/reordered. Tests + smoke catch any miss. |
| Lifetime / borrow-checker | LOW | `snapshot()` takes `&self`; `publish_binding_debug_state` takes `&mut BindingWorker`. Same signatures post-move. The `WorkerTimers` import already lives at `mod.rs:2`; moving it into `debug_state.rs` is the only `use`-line addition. |
| Performance regression | LOW | Both fns are cold paths (gRPC query rate / 65ms tick). Inlining decisions: `snapshot_hist` is `#[inline]` today and remains so. The free fns are not `#[inline]` today; no change. |
| Architectural mismatch (#961 / #946 Phase 2) | LOW | This is a file-split refactor, not a data-structure or pipeline change. There is no architectural premise to fail. |

## Test plan

1. `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build`
   clean from a fresh build.
2. `cargo test --release` — full 1000+ suite must pass at the
   same count as master.
3. 5x flake check on `idle_debug_state_publish_due_advances_only_at_interval`
   (one of the umem tests touching the re-exported free fns).
4. `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` —
   Go suite (30 packages).
5. Smoke matrix on `loss:xpf-userspace-fw0/fw1`:
   - Pass A (CoS off): v4+v6 push+reverse + `-P 12 -R` reproducers.
   - Pass B (CoS on): per-class 5201-5206 v4+v6 push+reverse.

## Out of scope (explicitly)

- The helper-grouping decomposition mentioned in the issue
  ("load_socket_block", etc.). Deferred.
- Any change to `BindingLiveSnapshot` wire shape.
- Any change to the set of counters maintained on
  `BindingLiveState`.
- Cacheline layout changes on `BindingLiveState`.
- Renaming `snapshot()` / `publish_binding_debug_state` /
  `update_binding_debug_state`.

## Open questions for adversarial review

1. **Should `snapshot()` move at all?** The 273-LOC struct literal
   is mechanical. Splitting it across files doesn't help reviewers
   trace a specific counter — they `grep` for the counter name
   either way. Counter-argument: it's the same readability win as
   keeping `mod.rs` under the modularity threshold; the engineering-
   style doc explicitly cites >100 LOC as a refactor cue.
2. **Resolved in v3:** visibility model uses `pub(in crate::afxdp)`
   (matching the existing `mmap::MmapArea` / `profile::*`
   precedent), not `pub(super)`. The two private fns plus two
   constants gain `pub(in crate::afxdp)` visibility — same
   effective reach as today's `pub(super) fn` in `mod.rs`. This is
   a no-op visibility change: today they live in `mod.rs` where
   `super = crate::afxdp`, so `pub(super)` there ≡ `pub(in
   crate::afxdp)`. After the move into the child module the
   spelling differs but the effective visibility is identical.
3. **Is the helper-grouping deferral the right call?** Reviewers
   may demand the grouped helpers in the same PR. If they do, the
   estimate is +~50 LOC of intermediate structs and the snapshot
   body shrinks from 273 to ~80 LOC. Worth doing now, or
   follow-up?
4. **Does the re-export pattern (`pub(super) use debug_state::{...}`)
   compose cleanly with `umem/tests.rs`?** `tests.rs` is loaded via
   `#[path]` and uses `use super::*;` — `super` is the `umem`
   module, which exports the symbols. This should work, but the
   adversarial reviewer should walk it explicitly.
5. **Is there a risk of `cargo test` finding a stale `#[cfg(test)]`
   helper that lived in `mod.rs`?** Confirm by reading the
   surrounding `#[cfg(test)]` blocks — `mod.rs` only has the
   `#[path = "tests.rs"] mod tests;` declaration; no other
   `#[cfg(test)]` items live inside it.
6. **Resolved in v2** by AGY round-1: constants MUST be
   `pub(super)` and explicitly re-exported. Plan now codifies the
   re-export list with `DEBUG_STATE_PUBLISH_MASK` and
   `IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS` included.
7. **Architectural-mismatch sanity check:** is there any
   pre-existing PR-in-flight on `umem/mod.rs` that would conflict
   with this split? (e.g., a parallel refactor that touches
   `snapshot()` or `publish_binding_debug_state`.)
