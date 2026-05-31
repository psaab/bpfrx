# #1725 — Test coverage for filter/engine evaluation path

**Status:** PLAN-READY v2 — Codex PLAN-NEEDS-MINOR (corrections folded),
AGY PLAN-READY (0 false positives, all 9 gaps genuinely uncovered),
Claude-SMR PLAN-NEEDS-MINOR (same two corrections + fold accessors into
one test). Consensus: proceed.

## v2 corrections from review

- **`FilterAction::Reject` is NOT untested repo-wide** — it is asserted
  in `afxdp/tx/cos_classify_tests.rs` and `afxdp/event_emit.rs`. The
  genuine gap is narrower: no test drives a `reject` term through the
  **plain `evaluate_filter` engine path** to assert the returned
  `FilterResult.action == Reject`. Gap #1 reworded to that.
- **IPv6 input-interface eval was overclaimed** — `interface_filter_assignment`
  defines `filter_input_v6` (tests.rs:1290) but the input eval call uses
  `is_v6=false` (tests.rs:1346). So the v6 `evaluate_interface_filter`
  input path is also uncovered; folded into gap #4.
- **Gap #8 (thin accessors)** — grouped into ONE compact table-driven
  test (`thin_accessor_predicates`), not four boilerplate tests.

## Issue framing

#1725 (promoted from #1663 §3 test-gap rank 1-3) asks for cargo unit
tests covering the firewall filter-engine evaluation path:
`userspace-dp/src/filter/engine/{eval.rs (681), tx_selection.rs (286),
cache_sensitive.rs (200)}`, which carry **0 `cfg(test)` blocks** of
their own. The functions are pure/injectable: build a
`Filter`/`FilterState`, call with a 5-tuple + dscp, assert the
verdict / counter / log-match. No socket/UMEM/thread needed.

This is a **TEST-ONLY** addition. No production code changes.

## Critical first finding — existing coverage is substantial

`userspace-dp/src/filter/tests.rs` (1998 LOC, loaded via
`#[path="tests.rs"]` from `filter/mod.rs`) **already exercises most of
the engine evaluation surface**. Tests live in the parent `filter`
module's `cfg(test)` submodule, so the engine files show 0 local
`cfg(test)` blocks but are NOT uncovered. A blanket "add tests for the
engine" would largely duplicate existing assertions. The scope below is
**narrowed to the genuinely-uncovered functions and behaviors** after a
full read of tests.rs + all three engine files.

### Already covered (do NOT duplicate)

- `evaluate_filter`: accept/discard (`basic_accept_discard`), port-range
  (`port_range_matching`), protocol (`protocol_matching`), src/dst CIDR
  (`source_dest_address_matching`), multi-term first-match
  (`multiple_terms_first_match_wins`), DSCP match (`dscp_match_in_term`),
  DSCP rewrite (`dscp_rewrite_action`, `dscp_rewrite_action_allows_default_zero`).
- `evaluate_lo0_filter`: v4 accept/discard (`lo0_filter_evaluation`).
- `evaluate_interface_filter` / `evaluate_interface_output_filter` /
  `evaluate_interface_output_filter_counted`: v4 + v6
  (`interface_filter_assignment`, `interface_output_filter_counted_records_term_hits`,
  `interface_output_filter_without_count_does_not_record_term_hits`).
- `evaluate_interface_filter_log_match`: filter/term identity + PBR skip
  (`interface_filter_log_match_returns_filter_and_term_identity`,
  `..._skips_pbr_terms_without_double_emit`).
- `evaluate_interface_filter_routing_instance_counted`: override + counter
  (`interface_filter_routing_instance_counted_returns_matching_override`).
- `evaluate_filter_ref_tx_selection_runtime_counted` /
  `evaluate_filter_ref_tx_selection_cached`: extensive three-color policer
  coverage (`three_color_*`, `flow_cache_hits_run_three_color_policer`,
  `cached_three_color_descriptor_dedupes_without_vec_allocation`, etc.).
- `input_dscp_filter_families_changed` (cache_sensitive): 6 tests.
- `interface_filter_affects_route_lookup`,
  `interface_output_filter_needs_tx_eval`,
  `filter_state_has_output_tx_selection`: asserted in passing.

### Genuine gaps (this PR fills these)

1. **`FilterAction::Reject` via the plain `evaluate_filter` path** — the
   reject action (`compiler.rs:373`) is asserted elsewhere
   (`cos_classify_tests.rs`, `event_emit.rs`) but no test drives a
   `reject` term through `evaluate_filter` and asserts the returned
   `FilterResult.action == FilterAction::Reject`.
2. **Missing-filter-key / empty-filter → default Accept** —
   `evaluate_filter` against an absent `filter_key`, and against a filter
   with zero terms, both must return `FilterResult::default()`
   (Accept). Not directly asserted.
3. **Address-family mismatch → default** — `evaluate_filter` /
   `evaluate_filter_ref_tx_selection_*` / `evaluate_filter_ref_tx_selection_cached`
   with a V4 src + V6 dst (the `_ => default` arm) returns default.
   Never tested.
4. **IPv6 baseline evaluate paths** — the v6 `evaluate_filter`
   (`evaluate_filter_ref_counted_v6`), v6 `evaluate_lo0_filter`
   (is_v6=true), and the v6 `evaluate_interface_filter` input path are
   not exercised by a plain (non-tx-selection) evaluate test.
   `interface_filter_assignment` defines `filter_input_v6` but only calls
   the input evaluator with `is_v6=false` (tests.rs:1346).
5. **`evaluate_filter_counted` hit-counter increment (baseline path)** —
   counter increment is tested for the tx-selection/output paths, but the
   plain `evaluate_filter_counted` → `evaluate_filter_ref_counted` counter
   bump (v4 and v6) is not asserted.
6. **`evaluate_interface_filter_non_routing_counted`** — the PBR-reject
   variant: a matching term carrying a non-empty `routing_instance` must
   return `FilterResult::default()` (route-lookup deferred), while a
   non-routing matching term returns its action. Never tested.
7. **tx_selection state-level dispatch wrappers** —
   `evaluate_interface_filter_tx_selection_counted` and
   `evaluate_interface_output_filter_tx_selection_counted` (the
   `FilterState`-keyed wrappers, vs. the already-tested `_ref_` forms),
   including the no-filter → default arm.
8. **tx_selection / cache_sensitive accessor predicates** —
   `interface_filter_affects_tx_selection`,
   `filter_state_has_input_tx_selection`,
   `interface_input_filter_has_dscp_match`,
   `interface_output_filter_has_dscp_match`. Not asserted via these
   accessors.
9. **cached-vs-runtime baseline parity** — for a plain (no-policer) term,
   `evaluate_filter_ref_tx_selection_cached` and
   `evaluate_filter_ref_tx_selection_runtime_counted` must agree on
   action / forwarding_class / dscp_rewrite / log_match. Existing
   three-color tests assert policer runtime behavior but not a clean
   baseline-equivalence assertion against the plain `evaluate_filter`
   verdict.

## Test seam (verified real + non-duplicative)

- Tests are added to `userspace-dp/src/filter/tests.rs` as new `#[test]`
  fns in the existing `cfg(test)` submodule. The three helper builders
  (`make_filter_state`, `make_filter_state_with_three_color`,
  `make_filter_state_with_interfaces`) plus `parse_filter_state`
  directly are reused. All engine entry points are `pub(crate)` and
  reachable via `use super::*` (already in place at tests.rs:6).
- Each new test asserts **observable production behavior** (verdict
  enum value, counter atomic load, log-match identity, default fall-
  through), not internal structure — so a regression in the production
  function fails the test. No test passes against a stubbed/buggy body.
- Builders construct `FirewallFilterSnapshot` / `FirewallTermSnapshot`
  and run them through the real `parse_filter_state*` compiler, so the
  tests exercise the compile→evaluate pipeline end-to-end (same path the
  dataplane uses), not a hand-built `Filter`.

## Public API preservation

No production signatures change. Test-only file edits to tests.rs.

## Hidden invariants the tests must respect

- **First-match-wins**: terms evaluated in order; first matching term's
  action returned. New multi-term tests must order terms to prove this.
- **Implicit default Accept**: no match (or missing filter) →
  `FilterResult::default()` whose `action` is `Accept`. Verify the
  default really is Accept (read `FilterResult::default`).
- **Counter increment is conditional on `has_count`**: only terms with a
  non-empty `count` bump the atomic. The `packet_bytes` argument is the
  byte delta. Tests must set `count` to observe the bump and pass an
  explicit byte count.
- **PBR non-routing variant**: a matching term with non-empty
  `routing_instance` short-circuits to default in
  `evaluate_filter_ref_non_routing_counted` (route lookup wins).
- **AF mismatch is a silent default**, not a panic.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | NONE | test-only, no production edit |
| Lifetime / borrow-checker | LOW | tests build owned state, call by ref; same shape as existing tests |
| Performance regression | NONE | tests not on any hot path |
| Architectural mismatch | NONE | filling a real, verified gap; no rearchitecture |

The only real failure mode is a **vacuous test** (asserts something
trivially true regardless of production correctness). Mitigation:
every test asserts a discriminating value (e.g. Reject vs Accept,
counter == exact byte count, default vs matched action) and the gate
requires the full suite green at HEAD (canary #1723 baseline).

## Test plan / gate

- `cargo build` clean.
- New filter tests pass; full `cargo test --release` suite green.
- 5x flake loop on the new tests (`filter::tests::`).
- Go suite unaffected (no Go change) — spot-run optional.
- **No cluster smoke** — test-only, no datapath change (per issue).

## Out of scope (explicitly)

- `engine/matching.rs` term-match primitives (separate file, has its own
  coverage via the evaluate tests; not in #1725 scope).
- `engine/policer.rs` three-color internals (already covered).
- Any production refactor of the engine modules.

## Open questions for adversarial review (each invitable to PLAN-KILL)

1. Is the gap analysis correct, or does tests.rs already cover one of the
   9 claimed gaps (e.g. is `Reject` asserted somewhere I missed)? If
   ≥7 of 9 are already covered, PLAN-KILL as "already covered".
2. Is gap #9 (cached-vs-runtime baseline parity) meaningfully distinct
   from the existing three-color tests, or is it redundant churn?
3. Is testing the thin accessor predicates (gap #8) worth it, or are they
   so trivial (`set.contains`) that a test is vacuous?
4. Does building state via `parse_filter_state` (vs. hand-built `Filter`)
   risk testing the compiler instead of the evaluator — and is that
   acceptable given the dataplane uses the same path?
5. Is the AF-mismatch case (gap #3) a real reachable production state, or
   dead defensive code not worth a test?
6. Any borrow/lifetime hazard in asserting on `TxSelectionFilterResult`'s
   borrowed `forwarding_class: Option<&str>` across the state's lifetime?
