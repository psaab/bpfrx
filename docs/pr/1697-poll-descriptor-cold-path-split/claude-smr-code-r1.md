# Claude-SMR hostile CODE review — PR #1704 (#1697) round 1

Reviewer seat: domain SMR + CPU arch (I-cache/inlining) + SW design.
Base f96e0e049, Head bd2090a8a.

## Verdict: MERGE-READY

The implementation is faithful pure code-motion plus the per-function
inline policy the plan specified. I verified the load-bearing claims by
diff and by disassembly.

## Pure-code-motion verification

- **cookie_reply.rs**: the logic lines of `syn_cookie_reply_budget_available`
  and `enqueue_syn_cookie_reply` (counter increments, `push_back`,
  `build_syn_cookie_*` calls, budget arithmetic, returns) diff IDENTICAL
  against the pre-move mod.rs region (commit 6c62da09f:247-307). The
  `SynCookieReply` enum, `SYN_COOKIE_REPLY_PENDING_RESERVE` const, and
  the `syn_cookie_reply_tests` (now `mod tests`) moved verbatim.
- **nat_exception.rs**: `source_nat_decision_for_flow` /
  `record_source_nat_failure` bodies moved verbatim; only `#[inline]`
  -> `#[cold] #[inline(never)]` and `pub(super)`.
- **filter.rs**: all helper bodies moved verbatim. The one structural
  change is the `emit_cached_output_filter_log` tail split — verified
  behavior-identical: the `#[inline]` guard wrapper checks
  `tx_selection.filter_log` and on `Some` calls the
  `#[cold] #[inline(never)] emit_cached_output_filter_log_tail` with the
  unwrapped `log_match`; the tail passes the EXACT same 10 args to
  `emit_filter_log_event` as the pre-split body (diff confirmed,
  including `filter_log_egress_zone_id(forwarding,
  cached_decision.resolution.egress_ifindex)` and
  `FilterLogSource::CachedOutput`). No double-eval, no reordering.

## Inline policy verification (the round-1 PLAN-KILL fix)

Confirmed via `nm` + `objdump` on the release binary:

- The three hot/warm wrappers (`emit_cached_input_filter_log`,
  `emit_cached_output_filter_log`,
  `evaluate_dscp_sensitive_input_filter_on_session_hit`) have NO
  standalone symbols — they inlined into their callers.
- In `poll_binding_process_descriptor` (which inlines the
  `#[inline(always)]` `stage_flow_cache_hit`), the cached emitters are
  reached ONLY via a conditional `jne` after a single
  `cmpb $0x3,<Option-disc>` guard (0x1878cc -> 0x188af6 for input,
  0x1879f0 -> 0x188b2e for output). The common no-filter-log case falls
  through with NO call and NO 96-byte `UserspaceDpMeta` copy. **The F1
  per-packet regression is provably absent.**
- The exception leaves (`emit_cached_output_filter_log_tail`,
  `emit_input_filter_log_match`, `record_source_nat_failure`,
  `apply_lo0_filter_action`, `enqueue_syn_cookie_reply`,
  `evaluate_non_pbr_input_filter`) all landed as their own out-of-line
  symbols in the cold region (0x152xxx / 0x20exxx).

## Cross-module wiring / borrow

- `flow_cache_hit.rs` now imports the emitters from `super::filter` —
  correct; build clean.
- `enqueue_syn_cookie_reply` across the module boundary: caller still
  passes disjoint `&mut binding.tx_pipeline` + `telemetry.counters`; no
  borrow regression (compiles).

## Tests

- Full `cargo test --release` passes; moved cookie tests pass 5/5 under
  `afxdp::poll_descriptor::cookie_reply::tests::*`.
- Two Go `bind: invalid argument` failures are a pre-existing sandbox
  unix-socket path-length limitation (reproduce on clean master);
  Rust-only PR, no Go files touched.

No findings. MERGE-READY pending Copilot + the loss-cluster CoS smoke.
