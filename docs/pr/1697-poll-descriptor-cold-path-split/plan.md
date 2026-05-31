# #1697 — Extract cold-path/exception helpers out of poll_descriptor/mod.rs

**Status:** DRAFT v2 — revised after round-1 PLAN-KILL (Codex + AGY) +
PLAN-NEEDS-MINOR (Claude-SMR). All three converged on one fixable defect:
v1's blanket `#[inline(never)]` policy was wrong for the guard-wrappers
reachable from the `#[inline(always)]` flow-cache fast path. v2 adopts
the salvage path all three reviewers endorsed: keep the common-case
guard inline; split only the rare/heavy bodies into
`#[cold] #[inline(never)]` callees. Re-dispatched for round 2.

## Round-1 verdicts and how v2 addresses them

- **Codex (task-mpt40s8e-dannse): PLAN-KILL** — *"not killed because
  cold leaf extraction is inherently cosmetic ... killed because the
  plan as written extracts warm/hot guard wrappers and forces calls
  from the flow-cache fast path."* Salvage: keep `emit_cached_*` + DSCP
  guard path inline, split only their rare emit/eval bodies into
  `#[cold] #[inline(never)]`.
- **AGY (adversarial-review-mpt40vtg-n4ss4x): PLAN-KILL** — same F1
  regression (forced per-packet `call` + 96-byte `UserspaceDpMeta`
  by-value copy ×2 on every cache hit). Same salvage path. Also raised
  the "12% file reduction is low value" objection (addressed in §2).
- **Claude-SMR: PLAN-NEEDS-MINOR** — same F1; recommended
  `#[cold]` alongside `#[inline(never)]` for true-exception leaves and a
  `cargo asm` regression guard asserting NO new per-packet call into
  `emit_cached_*`.

**New round-1 finding incorporated (Codex):** flow_cache.rs:285
documents that DSCP-sensitive filters are NOT flow-cached ("DSCP-
sensitive filters must be re-evaluated on every packet"). So for a
config with DSCP-sensitive input filters,
`evaluate_dscp_sensitive_input_filter_on_session_hit` IS the
established-flow per-packet path, not a per-flow-once path. v2 keeps it
`#[inline]` with the cheap `has_dscp_match` guard hoisted/inlined.

## 1. Issue framing

`userspace-dp/src/afxdp/poll_descriptor/mod.rs` is the largest file in
the tree (2983 LOC, confirmed by `docs/refactoring-audit-current.txt`).
It holds the AF_XDP ingress forwarding loop
(`poll_binding_process_descriptor`, lines 440-2817) plus a band of
small `#[inline]` helper functions at the top of the module (lines
42-423) and a `#[cfg(test)]` module at the bottom (2819-2983).

#1327 already converted the flat `poll_descriptor.rs` into a directory
module and lifted the *hot* flow-cache fast path
(`flow_cache_hit::stage_flow_cache_hit`, `#[inline(always)]`) and the
per-descriptor RX telemetry helper (`rx_telemetry`) into siblings.

The issue asks for the **complementary** move: take the COLD exception
machinery — interface-input-filter eval + filter-log emitters,
source-NAT-failure recorders, and the SYN-cookie reply builder/budget
helpers — out of `mod.rs` into `#[inline(never)]` sibling modules so
(a) the file drops below the audit threshold, and (b) the cold
exception bodies stop being eligible for inlining into the hot loop's
codegen unit, keeping the per-packet path L1-i resident.

The issue explicitly forbids batch-restructuring the hot loop itself
(the #946 Phase-2 PLAN-KILL: the loop is order-coupled — flow_cache +
session table + MissingNeighbor are not independently batchable) and
says **PLAN-KILL if the only available split is cosmetic file-motion of
the hot path.**

## 2. Honest scope / value framing

This is pure code-motion of already-factored helper functions plus a
codegen hint change (`#[inline]` → `#[inline(never)]` on the cold
helpers). The win is twofold and modest:

- **Audit/maintainability:** mod.rs drops from 2983 LOC to roughly
  ~2570 LOC (helpers ~380 LOC move out; the `mod`/`use` lines and a
  small amount of shared-type plumbing stay). It remains the largest
  file but is no longer a 3K-line monolith, and the cold surface is
  now independently navigable.
- **L1-i / codegen:** today the helpers are `#[inline]` (a *hint*, not
  `inline(always)`). Under LTO/opt the compiler is free to inline the
  filter-eval / NAT-failure / filter-log bodies into
  `poll_binding_process_descriptor`'s CGU, interleaving cold exception
  code with the hot per-packet path and inflating its I-cache
  footprint. `#[inline(never)]` on genuinely-cold helpers forces a
  `call` edge so the cold bodies live in their own symbols and the hot
  loop body shrinks.

The absolute perf win is **unmeasured and expected to be small** — the
cold helpers already only run on the session-miss slow path or true
exception paths, so they execute at most once per flow (NAT failure /
filter log) or never (steady-state established traffic flows entirely
through `stage_flow_cache_hit`). The justification is structural
hygiene + I-cache discipline, not a throughput number.

**On the round-1 "12% reduction / still a monolith" objection (AGY):**
the objection is fair as a ceiling — `mod.rs` stays the largest file
because the 2400-LOC order-coupled hot fn cannot be split (the #946
Phase-2 verdict, which the issue itself cites). This PR does NOT claim
to de-monolith the hot fn. Its claims are narrower and concrete: (1)
move the file below 2600 LOC, eliminating the worst REFACTOR-tier
offender's 3K-line status and making the cold surface independently
navigable; (2) give the true-exception bodies `#[cold]` section
placement so the hot loop's own bytes are not interleaved with
NAT-failure / filter-log code. If reviewers judge (1)+(2) insufficient
to justify three new files, PLAN-KILL remains acceptable — but the
salvage path all three round-1 reviewers volunteered (keep guards
inline, split rare bodies cold) is exactly what v2 now does, which is
the normal disposition of a "killed-but-salvageable" plan, not a dead
architecture.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** The bar this plan must
clear: the helpers being moved must be genuinely COLD (not on the
established-flow per-packet path), and the move must not change
behavior or perturb the order-coupled hot loop.

## 3. What's already shipped / partially batched

- #1327: directory module + `flow_cache_hit` (`#[inline(always)]`,
  HOT) + `rx_telemetry` siblings. `flow_cache_hit.rs` consumes
  `emit_cached_input_filter_log` / `emit_cached_output_filter_log` from
  `mod.rs` via `use super::*` — this cross-module dependency constrains
  where those two emitters can live (see §5).
- #946 Phase 1: seven per-packet sub-stages already live in
  `afxdp/poll_stages.rs` as `#[inline]` helpers.
- The actual frame builders `build_syn_cookie_syn_ack_frame` /
  `build_syn_cookie_ack_rst_frame` already live in
  `afxdp/frame/tcp.rs` — they are NOT in mod.rs. The issue text
  ("SYN-cookie SYN-ACK/RST frame builders") therefore resolves to the
  *reply-enqueue wrapper* `enqueue_syn_cookie_reply` +
  `syn_cookie_reply_budget_available` + the `SynCookieReply` enum +
  `SYN_COOKIE_REPLY_PENDING_RESERVE`, which is what actually lives in
  mod.rs and calls those builders.

## 4. Hot/cold classification (the load-bearing claim)

Every helper proposed for extraction runs ONLY on a non-established
path. Established/steady-state packets are handled entirely inside
`stage_flow_cache_hit` (the `#[inline(always)]` fast path) and never
reach these helpers. Call-site evidence (mod.rs line numbers):

| Helper | Call sites | Path | Cold? |
|--------|-----------|------|-------|
| `source_nat_decision_for_flow` | 1494,1524,2585,2614 | session-miss SNAT eval | yes (per-flow, once) |
| `record_source_nat_failure` | 1509,1538,2599,2629 | SNAT exhaustion exception | yes (exception only) |
| `evaluate_non_pbr_input_filter` | 952 (+239 internal) | session-miss filter eval | yes (per-flow, once) |
| `evaluate_non_pbr_input_filter_log_only` | 2313 | flow-cache *insert* (miss) | yes (per-flow, once) |
| `evaluate_dscp_sensitive_input_filter_on_session_hit` | 677 | session-hit DSCP re-eval | warm (see risk) |
| `enqueue_syn_cookie_reply` | 537,781 | SYN-cookie challenge | yes (DDoS path) |
| `syn_cookie_reply_budget_available` | 274 (internal) | called by enqueue | yes |
| `emit_input_filter_log_match` | 685,960,1654 (+342) | filter LOG action | yes (exception/log) |
| `emit_cached_input_filter_log` | flow_cache_hit.rs:127 | cached filter LOG | warm (fast-path-adjacent) |
| `emit_cached_output_filter_log` | flow_cache_hit.rs:134 | cached filter LOG | warm (fast-path-adjacent) |
| `apply_lo0_filter_action` | 702,1154 | host-bound lo0 filter | yes (host traffic only) |
| `filter_log_ingress_zone_id` | 167,208,408 (internal) | helper-of-helpers | yes |
| `filter_log_egress_zone_id` | 370 (internal) | helper-of-helpers | yes |
| `source_nat_decision_for_flow`/etc. | — | — | — |

**Three helpers are WARM/HOT, not cold — they must stay `#[inline]`
(round-1 fix; v1 wrongly proposed `#[inline(never)]`):**

- `emit_cached_input_filter_log` / `emit_cached_output_filter_log` are
  invoked UNCONDITIONALLY from inside `stage_flow_cache_hit` (the
  `#[inline(always)]` HOT fast path), at flow_cache_hit.rs:127/134 —
  i.e. on EVERY established-flow packet. They early-return on the
  common no-filter-logging case (mod.rs:339, mod.rs:362). v1's
  `#[inline(never)]` would force two unconditional per-packet `call`s
  plus a 96-byte `UserspaceDpMeta` by-value copy each, just to return
  `None` — a hot-path regression. **v2: keep `#[inline]`; the `None`
  guard inlines into the fast path; the rare non-`None` tail delegates
  to a `#[cold] #[inline(never)]` callee.**

- `evaluate_dscp_sensitive_input_filter_on_session_hit` (line 677) runs
  on EVERY session-HIT packet for a config with DSCP-sensitive input
  filters — because flow_cache.rs:285 documents that DSCP-sensitive
  filters are deliberately NOT flow-cached ("must be re-evaluated on
  every packet"). So for that config class this is the established-flow
  per-packet path. Its `interface_input_filter_has_dscp_match` guard is
  INSIDE the fn (mod.rs:232), so `#[inline(never)]` would force a call
  before the guard. **v2: keep `#[inline]` so the cheap guard inlines;
  the post-guard body calls the cold `evaluate_non_pbr_input_filter`.**

## 5. Concrete design

Create three cold sibling modules under
`userspace-dp/src/afxdp/poll_descriptor/`. **Inline policy is
per-function, NOT blanket `#[inline(never)]`** (round-1 fix): a helper
reachable from the `#[inline(always)]` flow-cache fast path keeps
`#[inline]` so its cheap common-case guard folds into the hot path; the
rare/heavy tail is split into a `#[cold] #[inline(never)]` callee.
True-exception leaves get `#[cold] #[inline(never)]` directly (matching
the repo's existing pattern at `tx/dispatch/slow_path.rs:23`).

1. **`filter.rs`** — interface-input-filter evaluation + filter-log
   emission (the largest cold cluster):
   - `struct NonPbrInputFilterEval` (move from mod.rs:128)
   - `fn filter_log_ingress_zone_id`, `fn filter_log_egress_zone_id`
     — leaf helpers; `#[inline]` (called from both inline and cold
     callers; trivial bodies, let rustc decide).
   - `fn evaluate_non_pbr_input_filter` — `#[cold] #[inline(never)]`
     (session-miss per-flow-once).
   - `fn evaluate_non_pbr_input_filter_log_only` —
     `#[cold] #[inline(never)]` (flow-cache insert, per-flow-once).
   - `fn evaluate_dscp_sensitive_input_filter_on_session_hit` —
     **`#[inline]`** (per-packet on the DSCP-filter config class — see
     round-1 Codex finding / flow_cache.rs:285). The cheap
     `interface_input_filter_has_dscp_match` guard at mod.rs:232 MUST
     stay inline at the front so the common no-DSCP-filter case is a
     branch + early return with no call. The post-guard body calls
     `evaluate_non_pbr_input_filter` which is the cold callee.
   - `fn emit_input_filter_log_match` — `#[cold] #[inline(never)]`
     (filter LOG action, exception).
   - `fn emit_cached_input_filter_log` (called from flow_cache_hit.rs
     HOT path) — **`#[inline]`**. Its `None`-guard at mod.rs:339 must
     fold into the fast path. The non-`None` body delegates to
     `emit_input_filter_log_match` (the cold callee), so the only thing
     inlined into the hot path is the guard + the rare `call`.
   - `fn emit_cached_output_filter_log` (called from flow_cache_hit.rs
     HOT path) — **`#[inline]`**, same shape: `None`-guard at
     mod.rs:362 inlines; the emit tail delegates to a
     `#[cold] #[inline(never)]` inner `emit_cached_output_filter_log_tail`
     (new thin split) so the heavy `emit_filter_log_event` call lives
     out of line.
   - `fn apply_lo0_filter_action` — `#[cold] #[inline(never)]`
     (host-bound lo0 traffic only).
   Visibility `pub(super)` so both `mod.rs` and the sibling
   `flow_cache_hit.rs` can call them via `super::filter::*`.

2. **`nat_exception.rs`** — source-NAT decision + failure recorder:
   - `fn source_nat_decision_for_flow` — `#[cold] #[inline(never)]`
     (session-miss SNAT eval, per-flow-once).
   - `fn record_source_nat_failure` — `#[cold] #[inline(never)]`
     (SNAT exhaustion exception only).
   `pub(super)`.

3. **`cookie_reply.rs`** — SYN-cookie reply enqueue machinery:
   - `const SYN_COOKIE_REPLY_PENDING_RESERVE`
   - `enum SynCookieReply`
   - `fn syn_cookie_reply_budget_available` — `#[inline]` (tiny, called
     only from `enqueue_syn_cookie_reply`, already-cold caller).
   - `fn enqueue_syn_cookie_reply` — `#[cold] #[inline(never)]`
     (SYN-cookie challenge / DDoS path, never on established flows).
   `pub(super)` (enum + fns).

Each module starts with `use super::*;` (same pattern as
`flow_cache_hit.rs` / `rx_telemetry.rs`) to pull `BindingWorker`,
`ForwardingState`, `UserspaceDpMeta`, `SessionFlow`, `TelemetryContext`,
`WorkerContext`, `BatchCounters`, `WorkerTxPipeline`, `TxRequest`, the
`crate::filter::*` re-exports, `record_source_nat_exception`,
`emit_filter_log_event`, `build_syn_cookie_*_frame`, etc. into scope.
`mod.rs` adds `mod filter; mod nat_exception; mod cookie_reply;` and the
corresponding `use` lines; the `#[cfg(test)] mod syn_cookie_reply_tests`
either stays in mod.rs (tests reference `enqueue_syn_cookie_reply` /
`syn_cookie_reply_budget_available` via `use super::cookie_reply::*`) or
moves into `cookie_reply.rs` as an inline `#[cfg(test)] mod tests`. The
latter is cleaner (test colocation per docs/engineering-style.md) — the
plan adopts it: move `syn_cookie_reply_tests` into `cookie_reply.rs`.

This is **pure code motion** of function bodies — byte-for-byte
identical bodies, only the enclosing module and the inline attribute
change (`#[inline]` → `#[inline(never)]`). No call site inside the hot
loop changes except the path prefix (`filter::`, `nat_exception::`,
`cookie_reply::`) brought in via `use`.

## 6. Public API preservation

`poll_binding_process_descriptor` (the only `pub(super)` entry point of
the module) keeps its exact signature. No external (outside
`poll_descriptor/`) caller references any of the moved helpers — they
are all module-private today. `flow_cache_hit.rs` is the only sibling
consumer and it keeps calling `emit_cached_input_filter_log` /
`emit_cached_output_filter_log` (now via `super::filter::`).

## 7. Hidden invariants the change must preserve

- **Side-effect ordering:** `enqueue_syn_cookie_reply` pushes to
  `pending_tx_local`, bumps counters, and the caller then pushes
  `desc.addr` to `scratch_recycle` and `continue`s. Moving the fn does
  not reorder these — the caller still owns the recycle/continue.
- **Counter semantics:** `telemetry.counters.touched = true` and the
  per-disposition increments inside the moved fns must be byte-identical.
- **Allocation rules:** `enqueue_syn_cookie_reply` allocates a `Vec<u8>`
  for the reply frame — this is pre-existing and only on the cookie
  path (cold). No new per-packet allocation is introduced.
- **`#[inline(never)]` must not regress the fast path:** the two
  `emit_cached_*` emitters called from the `#[inline(always)]`
  flow_cache_hit body must stay early-return-guarded so the hot path is
  just `branch + (rare) call`, not a forced call every packet. Verified:
  both early-return on `None` filter-log.
- **Borrow shape:** the moved fns take `&ForwardingState`,
  `&mut TelemetryContext`, `&mut WorkerTxPipeline`, `&WorkerContext`,
  `Option<&SessionFlow>` by reference exactly as today; no lifetime
  change. `enqueue_syn_cookie_reply` takes `&mut WorkerTxPipeline` and
  `&mut BatchCounters` — the caller already splits these borrows at the
  call site (`&mut binding.tx_pipeline`, `telemetry.counters`), so the
  cross-module move does not introduce a new aliasing conflict.
- **HA portability:** none of these helpers touch HA session-sync
  state; the SNAT-failure recorder writes only `recent_exceptions`
  (diagnostics) — unchanged.

## 8. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Pure body code-motion; bodies byte-identical; counters/ordering preserved. |
| Lifetime / borrow-checker | LOW | Same by-ref signatures; caller already splits the `binding`/`telemetry` borrows at each call site. The cross-module move cannot tighten borrows because the bodies are unchanged. |
| Performance regression | MED | `#[inline(never)]` is the deliberate change. Risk is mis-classifying a warm helper as cold and forcing a per-packet call. Mitigated by the §4 classification (established traffic never reaches these) + the `cargo asm` spot-check that the hot loop has no new per-packet `call` edge into the cold modules + the full CoS smoke matrix. |
| Architectural mismatch (#961/#946-P2) | LOW | This does NOT touch the order-coupled hot loop structure. It moves cold leaf helpers OUT, the opposite of the batched-restructure that #946 Phase 2 was killed for. If a reviewer finds the only achievable split is hot-loop file-motion, PLAN-KILL. |

## 9. Test plan

- `cargo build` clean (release).
- `cargo test --release` — full userspace-dp suite passes.
- 5/5 flake check on
  `syn_cookie_reply_enqueues_host_generated_frame_without_transit_policy_metadata`
  and `syn_cookie_reply_budget_preserves_tx_batch_reserve` (the tests
  that move with `cookie_reply.rs`).
- **F1 regression guard (the round-1 KILL trigger) — `cargo asm`
  spot-check:** disassemble `stage_flow_cache_hit` and confirm the
  hot flow-cache-hit path does NOT emit an unconditional per-packet
  `call` into `filter::emit_cached_input_filter_log` /
  `emit_cached_output_filter_log` (i.e. the `None` guard inlined and
  only a *conditional* rare call remains, or no call when no filter log
  is configured). Likewise confirm `evaluate_dscp_..._on_session_hit`'s
  `has_dscp_match` guard inlined into the session-hit path. Conversely,
  confirm the true-exception leaves (`nat_exception::record_source_nat_failure`,
  `filter::emit_input_filter_log_match`, `apply_lo0_filter_action`,
  `cookie_reply::enqueue_syn_cookie_reply`) DID land out of line
  (own symbols, `.text.unlikely` placement under `#[cold]`). This is
  the explicit guard against re-introducing the F1 per-packet
  regression.
- Go suite: `go test ./...` (30 packages) — unaffected, sanity only.
- Deploy on loss userspace cluster; **full CoS smoke matrix**
  (HOT-PATH change): Pass A CoS-disabled (v4+v6 × push+reverse +
  `-P 12 -R` multi-stream reproducer) and Pass B CoS-enabled per-class
  5201-5206 v4+v6 push+reverse — 0 retrans, line-rate on the
  multi-stream reproducers.
- Regenerate `docs/refactoring-audit-current.txt` so `make audit-check`
  stays green; confirm mod.rs LOC dropped.

## 10. Out of scope (explicitly)

- Any change to the hot loop body structure (stages 12+), batching, or
  the flow-cache fast path. Order-coupled per #946 Phase 2.
- Moving `build_syn_cookie_*_frame` — already in `frame/tcp.rs`.
- Further decomposition of `poll_binding_process_descriptor` itself
  (it stays the largest symbol; this PR shrinks the *file*, not the
  hot fn).
- New Prometheus counters or behavioral changes.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is the cold classification correct?** Specifically: does any
   established-flow (flow-cache-hit) packet ever reach
   `evaluate_dscp_sensitive_input_filter_on_session_hit` (line 677) on
   a hot path such that `#[inline(never)]` adds a real per-packet call?
   Walk the session-hit branch and confirm the DSCP-match guard
   short-circuits before the call in the common case.
2. **Do the two `emit_cached_*` emitters belong in a cold module given
   they're called from the `#[inline(always)]` fast path?** Is
   `#[inline(never)]` on them a net win (cold body out of the hot CGU)
   or a net loss (forced call on the logged-filter path)? Is there a
   measurable population of cached-filter-LOG traffic where this
   matters?
3. **Is `#[inline(never)]` the right hint, or would `#[cold]` (which
   also implies `inline(never)` for the optimizer's hot/cold splitting)
   be stronger/more honest for the true-exception helpers
   (`record_source_nat_failure`, `emit_input_filter_log_match`)?**
4. **Does forcing `call` edges into separate modules actually shrink
   the hot loop's I-cache footprint, or does LTO re-merge them anyway?**
   Is the `cargo asm` spot-check sufficient evidence, or is this an
   unverifiable codegen claim that should kill the perf justification?
5. **Is this cosmetic file-motion of the hot path in disguise?** The
   issue's explicit PLAN-KILL trigger. Argue whether moving cold leaf
   helpers out (leaving the 2400-LOC hot fn in mod.rs) is a genuine
   cold-path extraction or just shuffling deck chairs.
6. **Borrow/aliasing:** does moving `enqueue_syn_cookie_reply` across a
   module boundary, where it takes `&mut WorkerTxPipeline` while the
   caller holds `&mut BindingWorker`, compile without a borrow-checker
   regression? (Expected yes — caller already passes
   `&mut binding.tx_pipeline` + `telemetry.counters` as disjoint
   borrows — but confirm.)
