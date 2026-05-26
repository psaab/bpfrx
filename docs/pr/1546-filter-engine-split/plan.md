# #1546 — Split filter engine into responsibility-scoped submodules

**Status:** v2 — addresses Codex r1 NEEDS-MAJOR + AGY r1 NEEDS-MINOR. Pending r2.

### v1 -> v2 changes (round-1 findings addressed)

1. **Rustc/inlining wording softened.** v1 claimed CGU-local inlining;
   reality is `#[inline]` is a hint, CGU partitioning *is* per-source-
   module, and rustc relies on ThinLTO + the inline attribute to fold
   across modules. Wording updated in invariant 6 to reflect this.
2. **Policer atomic-ordering invariant rewritten.**
   `ThreeColorPolicerState::meter()` is `&mut self`, not atomic. The
   shared wrapper `ThreeColorPolicerRuntime::meter()` is `&self` but
   serializes via `Mutex`, with relaxed counters. Invariant 7 rewritten.
3. **`interface_filter_affects_route_lookup` moved to `eval.rs`.**
   Codex correctly identified this as a precheck for
   `evaluate_interface_filter_routing_instance_event_counted` (called
   together from `afxdp/forwarding/mod.rs:929` then `:936`). It is not
   a cache-coherency predicate; it is part of the routing-instance
   evaluation path. Placement table updated below.
4. **Tests move to sibling `*_tests.rs` files.** Both reviewers
   independently flagged that inline `#[cfg(test)] mod tests` violates
   the project's modularity-discipline. The project pattern is
   `userspace-dp/src/afxdp/forwarding_build_tests.rs`-style sibling
   files loaded via `#[cfg(test)] #[path = "..._tests.rs"] mod tests;`.
   Open question 6 resolved in favor of sibling files.

## Issue framing

`userspace-dp/src/filter/engine.rs` is 1247 LOC and mixes 8 distinct
responsibilities behind a single flat module:

1. Raw V4/V6 term matching (`term_matches`, `term_matches_v4`,
   `term_matches_v6`).
2. Input filter evaluation (`evaluate_filter*`, `evaluate_lo0_*`,
   `evaluate_interface_filter*` non-tx-selection forms).
3. Output filter evaluation (`evaluate_interface_output_filter*` non-tx
   forms).
4. TX-selection lookup (`evaluate_filter_ref_tx_selection_*`,
   `evaluate_interface_filter_tx_selection_counted`,
   `evaluate_interface_output_filter_tx_selection_counted`).
5. Cached TX-selection reconstruction
   (`evaluate_filter_ref_tx_selection_cached_*`).
6. Three-color policer runtime application
   (`apply_term_three_color_policer`, `apply_cached_three_color_policers`).
7. DSCP / cache-sensitive comparison helpers
   (`dscp_sensitive_filter_semantics_match`, `filter_term_semantics_match`,
   `three_color_policer_semantics_match`, `input_dscp_filter_family_changed`,
   `input_dscp_filter_families_changed`).
8. Predicate / introspection helpers
   (`interface_filter_affects_tx_selection`,
   `interface_filter_affects_route_lookup`,
   `interface_input_filter_has_dscp_match`,
   `interface_output_filter_needs_tx_eval`,
   `interface_output_filter_has_dscp_match`,
   `filter_state_has_input_three_color_policer`,
   `filter_state_has_input_tx_selection`,
   `filter_state_has_output_tx_selection`).

Issue #1546 asks for the canonical Junos-firewall split: match,
evaluation, TX-selection, cache-sensitive comparison, and policer
runtime. The repo's `pkg/cmdtree/tree.go`-style "single source of
truth" pattern argues for one file per responsibility so a future
field adding a new match dimension (e.g. a TCP-flags bitmap, or the
post-#1431 per-packet match field set) only has to update one module
and its focused tests.

## Honest scope and value framing

This is **pure code motion**. Function bodies move byte-for-byte;
visibility paths shift from `pub(crate) fn` (visible from the rest of
`userspace-dp`) to `pub(super) fn` (visible from `filter/`) plus
`pub(crate) use` re-exports at `filter/mod.rs` so the existing call
sites keep compiling.

The win is review-surface and ownership boundaries. There is no
expected throughput delta, no expected memory delta, no cache-line
movement. The hot path is `term_matches_v{4,6}` followed by either
`evaluate_filter_ref_counted_v{4,6}` or
`evaluate_filter_ref_tx_selection_counted_v{4,6}`; all three call sites
remain in the same crate and the same compilation unit (`engine`
becomes a directory, not a separate crate).

The security argument from the issue body — "cleaner module boundary
makes it harder for a future field to update only one of
input/output/session-hit/cache-rotation paths" — is the actual
motivation. The cache-sensitive helpers historically produced bugs
because the structural-equality predicate
(`dscp_sensitive_filter_semantics_match`) and the rebuild trigger
(`input_dscp_filter_family_changed`) live next to the unrelated
matching code and a contributor can update one without realizing the
other exists. Co-locating them in `cache_sensitive.rs` with their own
test module enforces the coupling at the file level.

> *If reviewers conclude the perf gain is too small to justify the
> churn, PLAN-KILL is an acceptable verdict.* The honest answer is
> that this PR has **zero perf gain**; the value is structural. A
> reviewer arguing "the file is fine at 1247 LOC, the bugs you cite
> were caught by tests not by the module boundary" is making a
> legitimate KILL case.

## What's already shipped / partially batched

- `pkg/filter/` (the older Go-side filter path) is **not** the target.
  Issue body explicitly names `userspace-dp/src/filter/engine.rs`.
- `filter/policer.rs` (566 LOC) is the **standalone three-color policer
  runtime**, distinct from the per-term policer-application helpers
  this PR is splitting out. The new submodule lives at
  `filter/engine/policer.rs` and re-uses the existing
  `ThreeColorPolicerRuntime` and `PacketColor` types from
  `filter/policer.rs` via `use super::*` at the engine module root.
  **Do not rename `filter/policer.rs`** — that would break the
  existing import path `crate::filter::policer::*` used by the
  compiler.
- `filter/compiler.rs` (511 LOC) and `filter/tests.rs` (1919 LOC)
  remain in place. The tests module currently imports private fns
  from `engine` via `use super::engine::*`; after the split the
  same wildcard import via `mod.rs` re-exports keeps them working.
- Pre-existing #1049 P2 structural extraction shipped `engine.rs` as
  a single flat module. This PR is the next step on that thread.

## Concrete design

### Target layout

```
userspace-dp/src/filter/engine.rs         (DELETED)
userspace-dp/src/filter/engine/mod.rs     (NEW — re-export hub, no behavior)
userspace-dp/src/filter/engine/r#match.rs (NEW — term_matches family)
userspace-dp/src/filter/engine/eval.rs    (NEW — filter evaluation,
                                                 input + output, non-tx)
userspace-dp/src/filter/engine/tx_selection.rs   (NEW — tx_selection runtime)
userspace-dp/src/filter/engine/cache_sensitive.rs (NEW — semantics
                                                        comparison + cached
                                                        tx_selection)
userspace-dp/src/filter/engine/policer.rs (NEW — apply_*_three_color_policer
                                                 helpers)
```

The Rust `r#match.rs` raw identifier is the conventional escape for
the `match` keyword. The alternative is `matching.rs`; we will use
**`matching.rs`** for readability (no raw identifier in filenames or
`mod` declarations). Final filename: `filter/engine/matching.rs`.

### Function placement (exhaustive)

**`engine/matching.rs`** (pub(super) — only `engine/*` needs these):
- `term_matches`
- `term_matches_v4`
- `term_matches_v6`

**`engine/eval.rs`** (mix of `pub(super)` and `pub(crate)` re-exported
through `mod.rs`):
- `evaluate_filter` *(pub(crate))*
- `evaluate_filter_counted` *(pub(crate))*
- `evaluate_filter_ref_counted` *(pub(super))*
- `evaluate_filter_ref_counted_v4` *(pub(super))*
- `evaluate_filter_ref_counted_v6` *(pub(super))*
- `evaluate_filter_ref_non_routing_counted` *(pub(super))*
- `evaluate_filter_ref_non_routing_counted_v4` *(pub(super))*
- `evaluate_filter_ref_non_routing_counted_v6` *(pub(super))*
- `evaluate_filter_ref_routing_instance_counted_v4` *(pub(super))*
- `evaluate_filter_ref_routing_instance_counted_v6` *(pub(super))*
- `evaluate_filter_ref_log_match` *(pub(super))*
- `filter_log_match` *(pub(super))*
- `evaluate_lo0_filter` *(pub(crate))*
- `evaluate_lo0_filter_counted` *(pub(crate))*
- `evaluate_lo0_filter_log_match` *(pub(crate))*
- `evaluate_interface_filter` *(pub(crate))*
- `evaluate_interface_filter_counted` *(pub(crate))*
- `evaluate_interface_filter_non_routing_counted` *(pub(crate))*
- `evaluate_interface_filter_log_match` *(pub(crate))*
- `evaluate_interface_filter_routing_instance_counted` *(pub(crate))*
- `evaluate_interface_filter_routing_instance_event_counted` *(pub(crate))*
- `interface_filter_affects_route_lookup` *(pub(crate))* — moved from
  cache_sensitive.rs per Codex r1 #4; this is the precheck paired with
  `evaluate_interface_filter_routing_instance_event_counted`
  (afxdp/forwarding/mod.rs:929 + :936). Not a cache predicate.
- `evaluate_interface_output_filter` *(pub(crate))*
- `evaluate_interface_output_filter_counted` *(pub(crate))*

**`engine/tx_selection.rs`** (pub(crate)):
- `evaluate_filter_ref_tx_selection_counted` *(pub(crate))*
- `evaluate_filter_ref_tx_selection_runtime_counted` *(pub(crate))*
- `evaluate_filter_ref_tx_selection_runtime` *(pub(super))*
- `evaluate_filter_ref_tx_selection_counted_v4` *(pub(super))*
- `evaluate_filter_ref_tx_selection_counted_v6` *(pub(super))*
- `evaluate_interface_filter_tx_selection_counted` *(pub(crate))*
- `evaluate_interface_output_filter_tx_selection_counted` *(pub(crate))*
- `interface_filter_affects_tx_selection` *(pub(crate))*
- `interface_output_filter_needs_tx_eval` *(pub(crate))*
- `filter_state_has_input_tx_selection` *(pub(crate))*
- `filter_state_has_output_tx_selection` *(pub(crate))*

**`engine/cache_sensitive.rs`** (pub(crate)):
- `evaluate_filter_ref_tx_selection_cached` *(pub(crate))*
- `evaluate_filter_ref_tx_selection_cached_v4` *(pub(super))*
- `evaluate_filter_ref_tx_selection_cached_v6` *(pub(super))*
- `three_color_policer_semantics_match` *(pub(super))*
- `filter_term_semantics_match` *(pub(super))*
- `dscp_sensitive_filter_semantics_match` *(pub(super))*
- `input_dscp_filter_family_changed` *(pub(super))*
- `input_dscp_filter_families_changed` *(pub(crate))*
- `interface_input_filter_has_dscp_match` *(pub(crate))*
- `interface_output_filter_has_dscp_match` *(pub(crate))*
(NOTE v2: `interface_filter_affects_route_lookup` moved to eval.rs.)

**`engine/policer.rs`** (engine-internal three-color policer
*application*; NOT the standalone runtime):
- `apply_term_three_color_policer` *(pub(super))*
- `apply_cached_three_color_policers` *(pub(crate))*
- `filter_state_has_input_three_color_policer` *(pub(crate))*

### `engine/mod.rs` structure

```rust
//! Per-packet filter evaluation engine. Split into responsibility-scoped
//! submodules by #1546.

use super::*;  // brings FilterState, Filter, FilterTerm, FilterResult,
               // TxSelectionFilterResult, CachedTxSelectionFilterResult,
               // FilterRoutingInstanceResult, FilterLogMatch,
               // CachedThreeColorPolicers, ThreeColorPolicerRuntime,
               // PacketColor, ThreeColorPolicerAction, record_filter_counter,
               // FilterAction, std::net::*, Arc, etc.

mod matching;
mod eval;
mod tx_selection;
mod cache_sensitive;
mod policer;

// Re-export the same surface engine.rs exposed.
pub(crate) use eval::{
    evaluate_filter, evaluate_filter_counted,
    evaluate_lo0_filter, evaluate_lo0_filter_counted, evaluate_lo0_filter_log_match,
    evaluate_interface_filter, evaluate_interface_filter_counted,
    evaluate_interface_filter_non_routing_counted,
    evaluate_interface_filter_log_match,
    evaluate_interface_filter_routing_instance_counted,
    evaluate_interface_filter_routing_instance_event_counted,
    evaluate_interface_output_filter, evaluate_interface_output_filter_counted,
    interface_filter_affects_route_lookup,
};
pub(crate) use tx_selection::{
    evaluate_filter_ref_tx_selection_counted,
    evaluate_filter_ref_tx_selection_runtime_counted,
    evaluate_interface_filter_tx_selection_counted,
    evaluate_interface_output_filter_tx_selection_counted,
    interface_filter_affects_tx_selection,
    interface_output_filter_needs_tx_eval,
    filter_state_has_input_tx_selection,
    filter_state_has_output_tx_selection,
};
pub(crate) use cache_sensitive::{
    evaluate_filter_ref_tx_selection_cached,
    input_dscp_filter_families_changed,
    interface_input_filter_has_dscp_match,
    interface_output_filter_has_dscp_match,
};
pub(crate) use policer::{
    apply_cached_three_color_policers,
    filter_state_has_input_three_color_policer,
};
```

The shared imports (`use super::*`) bring every type each submodule
needs because `filter/mod.rs` already re-exports the relevant symbols
into the `filter::` namespace. Each submodule then does `use super::*`
inside its own file to inherit them transitively.

### Visibility model

- `pub(super)` for helpers consumed only within `filter/engine/`.
- `pub(crate)` for the surface that `filter/mod.rs` re-exports out to
  the rest of the crate (matches the current `engine.rs` surface).
- The re-export pattern in `mod.rs` is the **only** place
  `pub(crate)` re-export glob is used; submodules each declare their
  own `pub(crate)` items by name so a `cargo +nightly rustdoc` or
  `cargo public-api` invocation in the future would not need to walk
  globs.

## Public API preservation

The following functions are visible to the rest of the crate today
(grep'd from `filter/mod.rs` and the rest of `userspace-dp/src/`):

```
$ grep -rn "filter::engine::" userspace-dp/src/ | grep -v 'filter/engine.rs' | wc -l
```

(Reviewers: verify the grep count remains equal after the split. The
implementation step will produce a `before/after` count and post it
in the PR description.)

Specifically, every `pub(crate) fn` listed in the engine.rs grep
above must remain importable from `crate::filter::*` (because
`filter/mod.rs` does `mod engine; use engine::*;`). The shim done by
the new `engine/mod.rs` preserves exactly that — the re-export list
above is the union of every existing `pub(crate) fn` in engine.rs.

## Hidden invariants the change must preserve

1. **Side-effect ordering.** Each
   `evaluate_filter_ref_*_counted_v{4,6}` function records the
   `term.counter` *after* `term_matches_*` and *before* the result is
   constructed. Splitting matching into its own module changes
   nothing if the call chain is preserved verbatim. **Risk:** if a
   reviewer accidentally inlines `term_matches_v4` into the eval
   module instead of importing it from `matching`, the call graph
   stays identical but the `#[inline(always)]` attribute is still
   required for the per-packet hot path to fold properly. We
   preserve `#[inline(always)]` on all three `term_matches*` fns.
2. **Allocation invariants.** `evaluate_filter_ref_counted_v{4,6}`
   does clone `term.policer_name`, `term.routing_instance`,
   `term.forwarding_class` (the latter is `Arc<str>` — cheap), and
   `term.action` (Copy). These clones existed before this PR and
   stay where they are. No new per-packet allocation is introduced.
3. **HA sync portability.** `apply_term_three_color_policer` and
   `apply_cached_three_color_policers` mutate the
   `ThreeColorPolicerRuntime`'s internal atomic token buckets. The
   ordering of `meter()` calls relative to `record_filter_counter()`
   is preserved (counter recorded, then policer metered). Splitting
   eval / tx_selection / cache_sensitive into separate files does
   not interleave these calls.
4. **Stale-handle hazards.** No handles are introduced. Functions
   take `&FilterState` and `&Filter` references; lifetimes are
   identical across the split.
5. **Lifetime / borrow-checker shape.** The `'a` lifetime on
   `TxSelectionFilterResult<'a>` ties to `&'a Filter` (for the
   `forwarding_class: &'a str` field). Splitting between
   `tx_selection.rs` and `eval.rs` keeps `'a` local to each function
   signature; no cross-module lifetime threading is needed.
6. **L1-i cache locality on the per-packet path.** This is the
   #1545 concern the user surfaced. The hottest call path is:
   - Hot read path:
     `evaluate_filter_ref_tx_selection_counted_v{4,6}`
     → `term_matches_v{4,6}` (inner loop, `#[inline(always)]`)
     → `apply_term_three_color_policer` (`#[inline]`)
     → return `TxSelectionFilterResult`.
   After the split, all four functions live in different files.
   The plan preserves `#[inline]` / `#[inline(always)]` attributes
   verbatim on every moved function.

   **Honest framing of the compiler guarantee (v2 correction):**
   Per the [Rust Reference codegen attributes](https://doc.rust-lang.org/reference/attributes/codegen.html#the-inline-attribute),
   `#[inline]` is a **hint**, not a guarantee. rustc's CGU
   partitioner (per the [rustc dev guide on monomorphization](https://rustc-dev-guide.rust-lang.org/backend/monomorph.html))
   creates CGUs per source-level module, so this split *does*
   change CGU layout. However, by default rustc enables local
   ThinLTO across CGUs in optimized builds (the project builds
   with the default release profile), which lets LLVM fold
   `#[inline]` items across CGU boundaries; `#[inline(always)]`
   is honored across CGUs unconditionally because rustc serializes
   the MIR into the importing CGU. v1's claim that the split was
   "in the same CGU" was wrong; the correct claim is that
   `#[inline(always)]` items are guaranteed inlineable cross-CGU
   and `#[inline]` items are inlineable subject to ThinLTO
   coverage, which the release profile enables.

   **Reviewers: please attack this.** If a reviewer can demonstrate
   a measurable I-cache miss spike from this split (perf
   `instructions:u` / `L1-icache-load-misses:u` on the userspace-dp
   binary's filter hot path), the right action is to either (a)
   collapse `matching.rs` into `eval.rs` and `tx_selection.rs`
   (duplicating the three small functions — they are 25-30 LOC
   each) or (b) PLAN-KILL. AGY r1 explicitly verified no L1-i
   regression risk based on the `#[inline(always)]` attributes
   plus rustc's cross-crate inline serialization.
7. **Policer concurrency invariant (v2 correction).**
   `ThreeColorPolicerState::meter()` is `&mut self` (no atomics).
   The shared wrapper `ThreeColorPolicerRuntime::meter()` is
   `&self` but serializes via a `Mutex<ThreeColorPolicerState>`;
   token-bucket invariants are protected by the Mutex, not by
   atomic compare-exchange. Counter increments after `meter()`
   are relaxed-ordering atomic increments on
   `ThreeColorPolicerCounters`. v1 incorrectly described this as
   atomic compare-exchange ordering. The engine helpers
   (`apply_term_three_color_policer`, `apply_cached_three_color_policers`)
   call `runtime.meter()` once per packet and then act on the
   returned `ThreeColorDecision`; moving them to
   `engine/policer.rs` does not change the lock-acquisition
   pattern, the relaxed counter ordering, or the
   `meter()`-then-counter-record sequence.
   **Reviewers: confirm `filter/policer.rs` is untouched** and
   that the only file declaring a `Mutex<ThreeColorPolicerState>`
   remains `filter/mod.rs`.

## Risk assessment

| Class                                    | Severity | Why |
|------------------------------------------|----------|-----|
| Behavioral regression                    | LOW      | Pure code motion; bodies byte-identical; tests unchanged. |
| Lifetime / borrow-checker                | LOW      | Single `'a` already module-local; submodules inherit `use super::*` only. |
| Performance regression                   | LOW-MED  | Cross-module `#[inline]` is preserved by rustc within a crate; L1-i locality concern flagged in invariant 6 — needs reviewer attack. |
| Architectural mismatch (#961 / #946 P2)  | LOW      | Issue explicitly requests this shape; no novel architecture; structural extraction along a boundary the codebase has been moving toward in #1325, #1326, #1327, #1328, #1342, #1356, #1444. |

## Test plan

- `cargo build` clean on `userspace-dp`.
- `cargo test --release` clean (currently passing on master).
- Targeted filter tests in `filter/tests.rs` — all 1919 lines remain;
  no test edits beyond the import path rewrite if any tests
  imported via `super::engine::*`.
- `cargo test --release -p userspace-dp filter::` (filter scope) ×
  5 to flake-check the most coverage-dense module.
- `cargo test --release` full suite — 952+ tests.
- Go suite: `go test ./...` (30 packages) — should be unaffected,
  this is Rust-only.
- No smoke gating on this PR per the wave-2 rule. Marker:
  `<!-- AWAITING-BATCH-MERGE -->`.

## Out of scope (explicitly)

- **No** rename of `filter/policer.rs` → `filter/policer_runtime.rs`,
  even though the new `engine/policer.rs` is namespace-adjacent.
  Rationale: existing import path stability + the two files have
  clearly distinct doc comments.
- **No** edit to `filter/tests.rs`. It stays at 1919 LOC. Per-module
  tests (per #1546 acceptance criterion 2) live as **sibling
  `*_tests.rs` files** under `filter/engine/`, loaded via
  `#[cfg(test)] #[path = "<name>_tests.rs"] mod tests;` from the
  parent module. This matches the project's modularity-discipline
  pattern (e.g. `userspace-dp/src/afxdp/forwarding_build_tests.rs`,
  `userspace-dp/src/afxdp/bpf_map_tests.rs`,
  `userspace-dp/src/afxdp/flow_cache_tests.rs`). v1's inline
  `#[cfg(test)] mod tests` proposal was rejected by both Codex r1
  and AGY r1 as a modularity-discipline violation. Concretely, the
  initial PR will add an empty sibling test file alongside each new
  module — actual test coverage for the acceptance-criterion-2
  scenarios (add/remove/same-ifindex content change/positional-ID
  stability/policer runtime-shape changes) is in scope; placeholder
  empty files for the other modules are out of scope and added only
  if the acceptance-criteria demand them.
- **No** API surface reduction. Every `pub(crate) fn` in engine.rs
  remains `pub(crate)` after the split.
- **No** change to `filter/compiler.rs` or `filter/mod.rs` data
  structures.
- **No** new match dimensions (the per-packet match fields tracked
  by #1431 stay untouched).

## Open questions for adversarial review

1. **Is the L1-i locality concern real?** Cross-module `#[inline]` is
   preserved by rustc, but is there a measurable hot-path regression
   from co-locating `term_matches_v4` away from
   `evaluate_filter_ref_tx_selection_counted_v4`? **PLAN-KILL is
   valid** if reviewers can show a measurable miss-rate delta on the
   userspace-dp filter hot path.
2. **Is `matching.rs` worth a separate file?** Three functions of
   25-30 LOC each. Combined LOC = ~80 lines. The alternative is
   duplicating them into `eval.rs` and `tx_selection.rs` (since
   only those two callers exist) — but that violates the issue's
   "match" responsibility separation. **PLAN-KILL** if the reviewer
   argues the matching responsibility is too small to justify its
   own module.
3. **Should `apply_cached_three_color_policers` live in
   `engine/policer.rs` or `cache_sensitive.rs`?** The function is
   called only by the cached/snapshot path (`UmemSnapshot` rebuild)
   but operates on the policer runtime. We placed it in
   `engine/policer.rs` because the policer atomic ordering
   invariant (invariant 7) is co-located with all other policer
   `meter()` callsites. **Reviewers: argue for cache_sensitive.rs
   placement** if you think the call-site co-location matters more
   than the runtime-mutation co-location.
4. **`engine.rs` → `engine/mod.rs` collision.** Rust allows both
   `engine.rs` and `engine/` to coexist with conflict, but we are
   deleting `engine.rs` and creating `engine/mod.rs`. Verify the
   git diff shows this as `engine.rs` deleted and the new files
   added under `engine/` — not as a rename, which would obscure
   the function-relocation evidence.
5. **Cache invariants vs DSCP rewrite path.** `interface_output_filter_has_dscp_match`
   reads `filter.has_dscp_match_terms`; that field flows through the
   compiler. Moving the predicate into `cache_sensitive.rs` does
   nothing to the field flow, but **reviewers: confirm
   `cache_sensitive.rs` membership for this fn is correct** — it
   reads a precomputed bool on the filter struct, it does not do
   any DSCP-sensitive comparison itself. Counterargument: this is
   actually a pure predicate, belongs in `eval.rs` or `tx_selection.rs`.
   **Argue this.**
6. **Per-module test placement (v2: RESOLVED).** v1 proposed inline
   `#[cfg(test)] mod tests { ... }` inside each `engine/*.rs`. Both
   reviewers independently flagged that the project's modularity-
   discipline standard uses sibling `*_tests.rs` files loaded via
   `#[cfg(test)] #[path = "..._tests.rs"] mod tests;`. v2 adopts
   the sibling-file pattern. Open for re-review: should this PR
   create empty placeholder sibling files for each of matching,
   eval, tx_selection, policer (which acceptance criterion 2 does
   not explicitly require tests for), or only for cache_sensitive?
   Default: only cache_sensitive, since that is the only module
   with explicit AC-2 test coverage requirements; the others
   continue to be covered by `filter/tests.rs`.
7. **`policer_drop` action ordering.** When both
   `term.dscp_rewrite` and `policer_action.dscp_rewrite` are set,
   `evaluate_filter_ref_tx_selection_counted_v{4,6}` uses
   `policer_action.dscp_rewrite.or(term.dscp_rewrite)` — policer
   wins. The new module split must preserve this exact precedence.
   Reviewers: scan the new tx_selection.rs for any `.or_else` /
   `.unwrap_or` reorder.

## Reviewer task IDs

Recorded in `docs/pr/1546-filter-engine-split/reviewer-ids.md` after
each round.
