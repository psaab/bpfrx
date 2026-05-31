# Claude-SMR hostile PLAN review — #1697 round 1

Reviewer seat: domain SMR (AF_XDP dataplane) + CPU arch (I-cache /
inlining) + SW design patterns. Hostile by mandate.

Plan: docs/pr/1697-poll-descriptor-cold-path-split/plan.md @ fd471ee3c

## Verdict: PLAN-NEEDS-MINOR

The architecture is sound and is NOT the #946-Phase-2 dead-end — it
moves cold leaf helpers OUT of the hot loop rather than restructuring
the order-coupled loop. The file shrinks ~380 LOC below 2983, which
satisfies the audit objective. But the plan's blanket "all moved
helpers become `#[inline(never)]`" is WRONG for two of them and would
introduce a per-packet regression on the hottest path. Fix the
inline-attribute policy and the plan is ready.

## BLOCKING finding (would be a regression if shipped as written)

**F1 — `emit_cached_input_filter_log` / `emit_cached_output_filter_log`
must NOT be `#[inline(never)]`.** These are called UNCONDITIONALLY on
every flow-cache-hit packet — the hottest path in the dataplane:

```
flow_cache_hit.rs:127:        emit_cached_input_filter_log(
flow_cache_hit.rs:134:        emit_cached_output_filter_log(
```

and `flow_cache_hit::stage_flow_cache_hit` is `#[inline(always)]`
(flow_cache_hit.rs header: "`#[inline(always)]` mandated by the plan").
Both emitters early-return on the common no-filter-log case:

```
mod.rs:339:    let Some(cached_log) = cached_descriptor.input_filter_log else { return; };
mod.rs:362:    let Some(log_match) = cached_descriptor.tx_selection.filter_log else { return; };
```

Today (`#[inline]`) the compiler folds that guard into the inlined fast
path: a single load + branch, **no call** when no filter logging is
configured (the overwhelming common case). `#[inline(never)]` would
emit an **unconditional `call` on every established-flow packet** just
to run a function that immediately returns. That is a textbook
per-packet pessimization on the hottest path — the exact "warm helper
mis-classified as cold" failure the plan's own §11-Q2 flags.

**Required fix:** these two emitters keep `#[inline]` (NOT
`inline(never)`). They may still physically move into `filter.rs` for
file-shrink, but the inline hint must be preserved so the guard inlines
into the fast path. The cold *body* past the guard stays out of the hot
CGU because rustc's hot/cold splitting handles the post-guard tail; the
guard itself must inline. Equivalently, keep the thin guard inline and
mark only an inner `#[cold] #[inline(never)]` emit-tail as never —
but the simplest correct policy is: emitters reachable from the
`#[inline(always)]` fast path stay `#[inline]`.

## SECONDARY finding (per-session-hit-packet, smaller but real)

**F2 — `evaluate_dscp_sensitive_input_filter_on_session_hit` (mod.rs
line 677) runs on every session-HIT packet, not per-flow-once.** Its
cheap guard (`interface_input_filter_has_dscp_match`) is INSIDE the
function (mod.rs:232). With `#[inline(never)]` every session-hit packet
pays an unconditional call to reach that guard, even when no DSCP
filter is configured. This is the slow session-table path (not the
flow-cache fast path), so it is warmer than the true exception helpers
but colder than F1. **Recommend `#[inline]` here too**, OR restructure
so the `has_dscp_match` guard is hoisted to the call site and only the
post-guard body is `#[inline(never)]`. The plan already half-admits
this ("warm-but-guarded"); make the attribute match the classification.

## Helpers that ARE correctly `#[inline(never)]` (no objection)

- `record_source_nat_failure` (SNAT exhaustion exception — true cold)
- `source_nat_decision_for_flow` (per-flow once on session miss)
- `evaluate_non_pbr_input_filter` / `_log_only` (per-flow once on miss)
- `emit_input_filter_log_match` (filter LOG action — exception)
- `apply_lo0_filter_action` (host-bound traffic only)
- `enqueue_syn_cookie_reply` + `syn_cookie_reply_budget_available`
  (DDoS/cookie path)
- `filter_log_ingress_zone_id` / `filter_log_egress_zone_id` (leaf
  helpers of the above; `#[inline(never)]` fine — they are only
  reached from already-cold callers).

For these, `#[cold]` is arguably more honest than `#[inline(never)]`
(it both forbids inlining AND tells LLVM to place the body in the
.text.unlikely section, away from the hot loop — directly serving the
I-cache objective). **Recommend adding `#[cold]` alongside
`#[inline(never)]`** on the true-exception helpers
(`record_source_nat_failure`, `emit_input_filter_log_match`,
`apply_lo0_filter_action`). This strengthens the I-cache claim from
"forced call" (which only stops inlining) to "forced call + cold
section placement" (which actually moves the bytes out of the hot
loop's cache lines).

## Borrow-checker (F6 in plan) — no concern

`enqueue_syn_cookie_reply(&mut binding.tx_pipeline, ..., telemetry.counters)`
already passes disjoint sub-borrows at the call sites (mod.rs:537-545,
781). The cross-module move cannot change borrow analysis because the
body is unchanged and the parameter types are unchanged. Compiles.

## On the cosmetic-file-motion PLAN-KILL trigger (§11-Q5) — survives

This is NOT cosmetic hot-path motion. The 2400-LOC hot fn body stays
put; what moves are leaf helper *functions* with their own symbols,
most genuinely cold. The win is (a) real file-shrink below the audit
line and (b) `#[cold]`/`#[inline(never)]` cold-section placement for
the true-exception helpers. That is a defensible cold-path extraction,
not deck-chair shuffling. KILL is not warranted.

## On LTO re-merge (§11-Q4) — claim must be downgraded, not killed

`#[inline(never)]` is honored by LTO (it is a hard directive, not a
hint), so the bodies will not re-merge. But the *I-cache improvement*
remains unmeasured. The plan correctly frames the win as structural
hygiene, not a throughput number, and offers a `cargo asm` spot-check
as the verification. That is the right bar: do NOT claim a Gbps
number; DO confirm via `cargo asm` that (1) the hot loop emits no new
unconditional per-packet call into the cold modules (catches F1/F2
regressions), and (2) the true-exception helpers land in
`.text.unlikely`.

## Required plan edits before PLAN-READY

1. Change the inline policy: `emit_cached_input_filter_log`,
   `emit_cached_output_filter_log`, and
   `evaluate_dscp_sensitive_input_filter_on_session_hit` keep
   `#[inline]` (NOT `inline(never)`). Update §5 and the §4 table.
2. Add `#[cold]` (alongside `#[inline(never)]`) to the true-exception
   helpers for actual cold-section placement.
3. Strengthen the `cargo asm` test to explicitly assert NO new
   unconditional per-packet call into `filter::emit_cached_*` from the
   flow-cache-hit path (the F1 regression guard).
