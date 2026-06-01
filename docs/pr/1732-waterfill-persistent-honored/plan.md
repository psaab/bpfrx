# Plan — #1732 CoS GuaranteeRate waterfill: persistent honored set + alloc-free hot path

- **Status**: v3 — round-2 findings folded. Codex r2 PLAN-NEEDS-MAJOR + AGY
  r2 PLAN-NEEDS-MINOR converged on the SAME refinement: the bitset must be
  keyed by ORDINAL position in `exact_queues_by_rate_ascending`, not by
  `queue_idx`, and the cap must be surfaced at build time. Both folded
  (Option A: ordinal keying). Claude-SMR concurs. Pending round-3 review.
- **Status history**: v2 — round-1 Phase-1-skip FATAL folded; v1 — DRAFT.
- **Issue**: #1732 (sub-issue of #1731, item #2 / §4.2 of the ENGINEER-READY plan)
- **Mode**: `/engineer` (= triple-review)
- **Base**: `origin/master` @ `c9e552689`
- **Scope file**: `userspace-dp/src/afxdp/cos/queue_service/mod.rs`
  (`select_exact_cos_guarantee_queue_waterfill`, lines 776–1075)

## 1. Issue framing

The GuaranteeRate waterfill selector has two defects in the hot CoS
shaped-service path:

1. **Per-selection heap allocation.** `mod.rs:816`
   `let sorted_indices: Vec<usize> = root.exact_queues_by_rate_ascending.clone();`
   clones the pre-sorted ascending-rate index vector on **every** call to
   the selector. The selector is invoked once per service selection inside
   the shaped drain loop, so this is a per-packet-batch heap alloc + free on
   the CoS hot path — a direct violation of the project's no-hot-path-alloc
   rule.

2. **No persistent honored set → Phase 2 skew.** `mod.rs:815` declares a
   **local** `honored_mask: u64 = 0` that is reset to 0 on every call. When
   Phase 1 honors a queue it returns immediately (`:954`), so the bit set at
   `:942` is discarded. On a later call, when Phase 1 finally breaks to
   Phase 2 (`:935`), `honored_mask` is empty — it carries no record of the
   queues already honored in *prior* calls this epoch. The Phase-2 skip
   check at `:985` therefore never skips a genuinely-honored queue. The code
   comment at `:960-968` openly admits Phase 2 "approximates" and the
   intended "skip already-honored, distribute residual to larger queues"
   contract degrades — the descending walk re-serves queues that already got
   their Phase-1 guarantee, skewing service away from the intended residual
   distribution (in practice toward the lowest-rate queues, which keep
   winning Phase 1 every epoch while the residual never reliably reaches the
   larger ones).

## 2. Honest scope / value framing

This is a correctness + hot-path-alloc fix, not a throughput headliner.

- **Alloc removed:** one `Vec<usize>` clone (length = exact-queue count,
  typically ≤8, ≤64 by the existing bitmask guard) per selector call. At a
  few-KB allocator cost amortized per service selection, the absolute cycle
  win is modest — but it is a strict per-batch heap alloc on the shaped hot
  path, which the engineering-style rules forbid outright regardless of
  magnitude.
- **Correctness:** the persistent honored set makes Phase-2 residual
  distribution match the documented two-phase waterfill intent across a
  multi-selection epoch instead of "approximating." This changes exact-class
  service *distribution* under oversubscription, which is why the #1217
  structural-CoV gate is mandatory.

*If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* (The alloc-removal alone is defensible
on the no-hot-path-alloc rule; the honored-set correctness fix is the larger
justification.)

## 3. What's already shipped / partially batched

`CoSInterfaceRuntime` (`types/cos.rs:385-449`) already persists the
waterfill epoch state across selector calls:

- `exact_queues_by_rate_ascending: Vec<usize>` (`:406`) — built once at
  `build_cos_interface_runtime`, runtime read-only (the clone source).
- `waterfill_pass1_remaining_bytes: u64` (`:414`) — Phase-1 budget,
  lazily refilled when 0.
- `waterfill_phase2_cursor: usize` (`:419`) — Phase-2 descending cursor.
- `waterfill_epochs: u64` (`:427`) — completed-epoch counter, bumped at the
  lazy Phase-1 refill (`mod.rs:809`).
- `waterfill_phase1_budget_breaks: u64` (`:435`) — telemetry.

The fix is the same incremental-field pattern (FACT-C in the #1731 plan):
add one `u64` bitset field + clear it where `waterfill_epochs` already
bumps. No new allocation surface. The `kind`/`head_len` borrow-split hoist
at `:838-847` is the established pattern for ending the immutable `head`
borrow before the `&mut queue` telemetry writes — the index-cursor rewrite
reuses exactly this discipline.

## 4. Concrete design

### 4.1 New field on `CoSInterfaceRuntime` (`types/cos.rs`)

Add immediately after `waterfill_phase2_cursor` (`:419`):

```rust
/// #1732: persistent Phase-1 honored bitset for the current waterfill
/// epoch. Bit `j` set ⇔ the exact queue at ORDINAL position `j` in
/// `exact_queues_by_rate_ascending` was honored in Phase 1 this epoch.
/// Keyed by ASCENDING-VEC ORDINAL, NOT by `queue_idx` (the root.queues
/// index): both phases iterate this same sorted vec, so ordinal `j`
/// unambiguously identifies one queue, and the bit range is bounded by
/// `exact_queues_by_rate_ascending.len()` (≤64) regardless of how high
/// the underlying `queue_idx` values run — see round-2 finding F3′
/// (the prior `queue_idx`-keyed local mask was silently broken for
/// configs with exact queues at root index ≥64; ordinal keying fixes
/// that root-cause). Previously a function-local `honored_mask` reset
/// to 0 every call, so Phase 2 (entered on a *later* call than the
/// Phase-1 honors) saw an empty mask and could not skip already-honored
/// queues — the documented "approximates" skew — AND Phase 1 had no
/// skip at all so the smallest queue was re-honored every call. Now
/// persisted across selector calls, read by BOTH phases, and CLEARED at
/// the lazy Phase-1 refill (where `waterfill_epochs` bumps), so the
/// ascending Phase-1 walk honors each queue at most once per epoch and
/// the descending Phase-2 walk serves the residual to the larger queues
/// skipping the honored set. Single-writer owner worker, plain `u64`.
pub(in crate::afxdp) waterfill_honored_epoch_bits: u64,
```

Initialize to `0` in `builders.rs` alongside the other waterfill fields
(`:110-113`).

### 4.2 Selector rewrite (`queue_service/mod.rs`)

**(a) Clear the bitset at the epoch refill.** In the
`waterfill_pass1_remaining_bytes == 0` block (`:793-810`), where the epoch
counter bumps, add `root.waterfill_honored_epoch_bits = 0;`. This is the
canonical "new epoch starts" boundary. The exhaustion reset at `:1070-1073`
sets `pass1_remaining = 0`, which forces the refill (and thus the clear) on
the next call — so clearing only at the refill site covers both paths
correctly and avoids a redundant double-clear.

**(b) Remove the clone; iterate by index.** Replace

```rust
let mut honored_mask: u64 = 0;
let sorted_indices: Vec<usize> = root.exact_queues_by_rate_ascending.clone();
for queue_idx in &sorted_indices {
    let queue_idx = *queue_idx;
    let queue = &mut root.queues[queue_idx];
    ...
```

with an index loop over the persistent vec's length, reading each element
through a *scoped* immutable borrow that ends before the `&mut root.queues`
borrow begins (split-borrow discipline, same shape as the existing
`kind`/`head_len` hoist):

```rust
let ascending_len = root.exact_queues_by_rate_ascending.len();
debug_assert!(
    ascending_len <= 64,
    "waterfill honored bitset is u64; >64 exact guarantee queues on one \
     interface is unsupported (ordinal bit range overflow)"
);
for i in 0..ascending_len {
    let queue_idx = root.exact_queues_by_rate_ascending[i];
    let queue = &mut root.queues[queue_idx];
    ...
```

`i` is the ASCENDING-VEC ORDINAL (the bitset key, `i < ascending_len ≤ 64`).
`root.exact_queues_by_rate_ascending[i]` is read and copied into the `Copy`
local `queue_idx` (a `usize`, the root.queues index used for queue access),
ending the immutable borrow of `root` before `&mut root.queues[queue_idx]`
is taken — no overlapping borrow, no alloc. The loop bound `ascending_len`
is captured once (the vec is runtime read-only). Index access uses `[]`,
in-bounds by construction (`i < ascending_len`).

**(c) Phase-1 honor sets the persistent bit (keyed by ORDINAL `i`).** At the
honor site (`:941`), replace `honored_mask |= 1u64 << queue_idx;` with
`root.waterfill_honored_epoch_bits |= 1u64 << i;` (ordinal `i`, no
`queue_idx < 64` guard needed — `i < ascending_len ≤ 64` by the
`debug_assert`; in release if a malformed config somehow exceeds 64, only
ordinals ≥64 go untracked, and the build-time warning in §4.4 surfaces it).
This write happens before the `return`, so the bit persists into the next
call. **Round-2 F3′ fix:** the prior `queue_idx` key meant a queue at root
index ≥64 was never marked even when only 2 exact queues existed (ordinals
0,1); ordinal keying makes the ≤64 bound depend only on the exact-queue
COUNT, which is the quantity actually bounded.

**(c′) Phase-1 ALSO skips already-honored queues (round-1 FATAL fix —
Codex + AGY converged).** This is the load-bearing correctness fix that
plan v1 MISSED. Phase 1 always restarts at the smallest ascending queue
(`:817`) and returns immediately on a honor (`:954`). A persistent bitset
read *only* by Phase 2 does NOT stop the smallest queue from being
re-honored on every selector call within the epoch: each call re-enters
Phase 1, honors the smallest queue (decrementing `pass1_remaining` by its
small `phase1_cost`), and returns — so the smallest queue monopolizes the
entire Phase-1 budget and the larger ascending queues never receive their
one Phase-1 honor before the budget is exhausted. **This is precisely the
"skews to the lowest-rate queue" symptom the issue describes.** Therefore,
at the TOP of the Phase-1 loop body — immediately after computing
`queue_idx`, before the eligibility gate at `:820` — add:

```rust
// #1732: at-most-once Phase-1 honor per epoch. A queue already
// honored this epoch is skipped (by ORDINAL `i`) so the ascending
// walk advances to the next-smallest queue instead of re-honoring
// the smallest one every call (the documented small-rate-ascending
// waterfill intent).
if (root.waterfill_honored_epoch_bits & (1u64 << i)) != 0 {
    continue;
}
```

With this, each Phase-1 honor advances the honored set by one queue; once
every eligible exact queue is honored (or the budget is exhausted mid-walk),
Phase 1 finds nothing to honor and falls through to Phase 2, which serves
the residual to the larger queues (descending) skipping the same honored
set. The bitset is the single source of truth for "honored this epoch,"
read by BOTH phases by ordinal, cleared at the next epoch's refill. This
makes the two-phase ascending-Phase1 / descending-Phase2 algorithm match the
documented waterfill contract (`docs/fairness-regimes.md`).

**(d) Phase-2 reads the persistent bitset.** Phase 2 (`:960-1069`) currently
references the dead local `honored_mask` at `:985`. Replace the Phase-2
length/index references to the cloned `sorted_indices` with
`root.exact_queues_by_rate_ascending` (indexed; the vec is still in scope on
`root`, just not cloned), and replace the `honored_mask` skip-check at `:985`
with `root.waterfill_honored_epoch_bits`:

```rust
// pos_from_end is the ascending-vec ORDINAL of the queue being
// visited in the descending walk — the same key Phase 1 set.
if (root.waterfill_honored_epoch_bits & (1u64 << pos_from_end)) != 0 {
    // skip — already honored in Phase 1 this epoch
}
```

The Phase-2 descending walk reads `root.exact_queues_by_rate_ascending.len()`
and `[pos_from_end]` directly; `pos_from_end` (`= len - 1 - phase2_idx`) is
the ordinal into the ascending vec, so `1u64 << pos_from_end` tests the same
bit Phase 1 set for that queue. Each index read copies a `usize` out before
any `&mut root.queues[..]` borrow, so borrow-split holds. The
`phase2_idx`/`start_phase2`/cursor arithmetic is unchanged. (Because both
`pos_from_end` and `i` are ordinals `< ascending_len ≤ 64`, no `< 64` guard
is needed in Phase 2 either.)

**Borrow-checker note.** The reads of `root.waterfill_honored_epoch_bits`
and `root.exact_queues_by_rate_ascending[..]` in Phase 2 happen *before* the
`let queue = &mut root.queues[queue_idx];` on each iteration, and the bit
read result is a `Copy` `u64`/`usize`. `queues` and the waterfill fields are
disjoint struct fields, but to keep the borrow checker happy across the loop
body the reads are sequenced before the `&mut` borrow on every iteration —
exactly the discipline the existing code already uses for the telemetry
`root` field writes at `:933` and `:944`.

### 4.3 Semantic change (intended) and what does NOT change

**Intended change (the fix):** within an epoch, each exact queue is honored
in Phase 1 **at most once** (via (c′)). Previously the smallest queue was
re-honored on every call until the budget ran out. Now the Phase-1 budget is
distributed across the ascending queues, one honor each, smallest-first —
the documented waterfill behavior. When Phase 1 breaks mid-walk (the next
ascending queue's `phase1_cost` exceeds the remaining budget), Phase 2
serves the residual to the *not-yet-honored* (larger) queues descending,
skipping the honored set, instead of re-serving the small ones. **This is
the exact-class distribution change that mandates the #1217 CoV gate.**

**Empty-epoch boundary (Codex r2 Finding-3 — clarified, benign).** If every
eligible exact queue gets honored in Phase 1 while budget remains, both
phases then skip every queue and the selector returns `None` for that one
call (the existing `:1070-1074` exhaustion path resets `pass1_remaining = 0`),
and the next call refills + clears into a fresh epoch. This is a transient
empty-boundary return, NOT a deadlock and NOT a starvation — it occurs only
when all guarantees are already met. The plan does NOT claim Phase 2 serves
residual when there is no unhonored queue.

**What does NOT change:** the Phase-1 honor ORDER (still ascending,
smallest-first); the budget refill math (`quantum_sum × fraction`); the
per-honor `phase1_cost` decrement; the token/lease gates; parking;
`exact_guarantee_rr` advance; all `waterfill_counters` increment sites; the
Phase-2 descending cursor arithmetic. Only the honored-set source (local →
persistent) and the addition of the Phase-1 skip change behavior.

### 4.4 The 64-queue cap disposition (round-2 finding F3′ — Codex + AGY)

**Round-2 sharpening:** both reviewers proved that a `queue_idx`-keyed
bitset with `debug_assert!(ascending_len <= 64)` is WRONG — a config with
only two exact queues but at root indices 65/66 has `ascending_len == 2`
(passes the assert) yet `1u64 << 65` is undefined-shift / silently
untracked. The cap was the wrong invariant for the wrong key.

**Resolution (Option A — both reviewers' recommended fix): key the bitset by
ORDINAL position `i`/`pos_from_end` in `exact_queues_by_rate_ascending`.**
This decouples the bit range from `queue_idx` entirely:

- The bitset key is now bounded by `ascending_len` (the COUNT of exact
  guarantee-rate queues), which IS the quantity `debug_assert!(ascending_len
  <= 64)` correctly bounds. No `all(qi < 64)` check is needed; the assert is
  now sufficient and correct.
- The prior `queue_idx` key (in both the old local mask AND plan v1/v2) was
  the latent root-cause bug; ordinal keying eliminates it. With ordinal
  keying there is no silent untracked-queue case for any config with ≤64
  exact queues, regardless of how high the root indices run.
- **`debug_assert!(ascending_len <= 64)`** at the selector top (stripped in
  release; fires in test/CI). In a release build a >64-exact-queue config
  would leave ordinals ≥64 untracked — but:
- **In-scope build-time warning (round-2 AGY+Codex required this).** At
  `build_cos_interface_runtime` (control-plane cold path, runs once per
  interface; zero hot-path cost) emit a one-time
  `eprintln!("xpf-userspace-dp: CoS interface ... has {n} exact
  guarantee-rate queues (>64); waterfill honored-set tracking is capped at
  64 — queues beyond 64 may be over-served")` when
  `exact_queues_by_rate_ascending.len() > 64`. This surfaces the limit to
  the operator (journald) without a hot-path branch.
- **Hard config-reject (commit-check) remains OUT OF SCOPE / deferred**,
  mirroring #1731 §4.3's separate scoping of the analogous 32-worker reject
  (#1733). The ordinal-keyed bitset + debug_assert + build-time warning is
  the complete in-scope answer; a Go commit-check reject is a larger,
  separately-testable control-plane change.

## 5. Public API preservation

- `select_exact_cos_guarantee_queue_waterfill` signature unchanged
  (`root`, `queue_fast_path`, `now_ns`, `lease_telemetry`).
- `ExactCoSQueueSelection { queue_idx, secondary_budget, kind }` unchanged.
- `CoSInterfaceRuntime` gains one `u64` field (additive; all construction
  sites updated). No field removed/renamed.
- All telemetry counters (`waterfill_counters.*`, `waterfill_epochs`,
  `waterfill_phase1_budget_breaks`) preserve their increment sites and
  semantics. The new bit-clear is colocated with the existing epoch bump.

## 6. Hidden invariants the change must preserve

- **Epoch lifecycle:** bitset cleared exactly at the Phase-1 refill (epoch
  start), set on each Phase-1 honor, read by Phase 2, never read after the
  next refill. The exhaustion reset (`:1072`) does not clear directly but
  forces a refill-clear next call — verified covers both exit paths.
- **`queue_idx < 64` guard:** preserved at both set (`:941`) and skip
  (`:985`) sites. Queues ≥64 are neither marked nor skipped — identical to
  prior local-mask behavior (conservative: such a queue is serviced in both
  phases, never starved).
- **Borrow-split / lifetime:** index-copy-before-`&mut` discipline holds; no
  new lifetime that the old clone hid. (The clone existed *only* to dodge the
  borrow conflict between iterating `exact_queues_by_rate_ascending` and
  taking `&mut root.queues` — the index loop resolves it without a clone.)
- **Allocation rule:** zero heap alloc in the selector after the change.
- **HA portability:** the new field is per-interface runtime scheduler state
  (like the existing `waterfill_*` cursors), NOT lease/session state synced
  to the HA peer. Confirm `interface_row.rs` aggregation does NOT need it
  (it aggregates `waterfill_epochs`/`budget_breaks` for telemetry SUM/MIN
  only; the honored bitset is transient within-epoch state, not a telemetry
  accumulator). → no `make test-failover` requirement.
- **Side-effect ordering:** lease top-up (`maybe_top_up_cos_queue_lease`),
  parking (`park_cos_queue`), `exact_guarantee_rr` advance, and per-queue
  telemetry writes keep their exact current order and call sites. The fix
  touches only the honored-set source and the index iteration mechanism.

## 7. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | **MED-HIGH** | BOTH phases' distribution genuinely changes (the point): Phase 1 now honors each queue at most once per epoch (was: re-honor smallest every call), and Phase 2 skips the persistent honored set. Bounded by the #1217 CoV gate + the new distribution unit test. Phase-1 honor ORDER (ascending) and the budget math are unchanged. |
| Lifetime / borrow-checker | **LOW** | Index-copy-before-`&mut` is the existing discipline; the clone only ever masked this borrow conflict. Build proves it. |
| Performance regression | **LOW** | Strictly removes an alloc; adds two `u64` field accesses (a bit-or and a masked test) that replace the local-mask ops 1:1. No new per-iteration cost. |
| Architectural mismatch (#961 / #946-P2) | **LOW** | Not an architecture change; an incremental field add + alloc removal on an existing, tested selector. The #1731 plan (3-reviewer PLAN-READY) ranks this the lowest-risk sub-issue. |

## 8. Test plan

- `cargo build` clean (release).
- Full cargo suite (`cargo test --release`).
- 5× flake on the new distribution test + the existing
  `waterfill_*` named tests.
- New distribution test (`queue_service/tests.rs`). **Determinism spec
  (Codex r2 Finding-5):** 3+ exact queues at `transmit_rate_bytes` chosen so
  their computed `cos_guarantee_quantum_bytes` are DISTINCT and NOT all
  clamped to the `COS_GUARANTEE_QUANTUM_MIN_BYTES` floor (i.e. rates high
  enough that `rate × COS_GUARANTEE_VISIT_NS / 1e9` exceeds the min clamp);
  set BOTH `root.tokens` AND every `queue.hot.tokens` abundant (the selector
  gates on root tokens at `:856`/`:1034` and queue tokens at `:879` — both
  must be non-binding so the Phase-1 byte budget is the only gate); fixed
  `now_ns`; no shared lease; `runnable = true`; manually-primed multi-item
  backlog per queue. `fraction` chosen so Phase 1 honors a strict subset of
  the small queues before breaking. Drain a multi-selection sequence (one
  full epoch) and assert the **per-epoch service order across >1 selection**:
  (i) selection N honors the N-th-smallest queue (ascending, at-most-once) —
  the smallest queue is NOT re-honored on selection 2;
  (ii) once Phase 1 breaks, Phase 2 serves a NOT-yet-honored larger queue,
  never a Phase-1-honored one;
  (iii) across the epoch each honored queue is selected in Phase 1 exactly
  once. This is exactly the pin the `:2318` test explicitly declined to make.
  A companion assertion contrasts with the broken-mask behavior (the smallest
  queue would have been selected on every Phase-1 call).
- Go suite (`go test ./...`) — no Go change expected; run for safety.
- **CoS smoke matrix** on `loss:xpf-userspace-fw0/fw1`: v4
  (`172.16.80.200`) + v6 (`2001:559:8585:80::200`) × push/`-R` ×
  CoS-off/CoS-on × per-class ports 5201-5206 (`apply-cos-config.sh` after
  deploy wipes CoS).
- **#1217 structural-CoV gate** (`docs/fairness-regimes.md`):
  `observed_CoV ≤ Cstruct + 0.05`, starved-flow hard-fail, aggregate gate on
  saturated runs — mandatory because exact-class distribution changes.
- `make audit-check` — `queue_service/mod.rs` is WATCH-tier (baseline 1711
  LOC); net delta is a handful of lines (no clone-temp Vec; +bit clear; the
  index loop is the same line count). Regen
  `docs/refactoring-audit-current.txt` if it crosses a tier boundary.
- `make test-failover`: **NOT required** — waterfill honored bitset is
  per-interface within-epoch scheduler state, not HA-synced lease/session
  state (confirmed §6).

## 9. Out of scope (explicitly)

- #1731 items #1 (generalize MQFQ to non-exact), #3 (32-worker cap), #4
  (FQ-CoDel), #5 (now_ns refresh), #6 (bucket telemetry) — separate
  sub-issues. #1733 (equal-flow worker cap) is in flight on a sibling
  worktree.
- A hard config-reject for >64 exact guarantee-rate queues on one interface
  — deferred (§4.4), mirroring #1731 §4.3's separate-sub-issue scoping of
  the analogous 32-worker reject.

**Files this PR touches** (round-1 Codex Finding-2: a non-`Default`
`CoSInterfaceRuntime` field also requires updating explicit struct literals
in the worker CoS tests):

- `userspace-dp/src/afxdp/types/cos.rs` — new field.
- `userspace-dp/src/afxdp/cos/builders.rs` — init `= 0`.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs` — selector rewrite.
- `userspace-dp/src/afxdp/cos/queue_service/tests.rs` — distribution test +
  any local `CoSInterfaceRuntime { .. }` literals.
- `userspace-dp/src/afxdp/worker/cos/tests.rs` — 7 explicit
  `CoSInterfaceRuntime { .. }` literals (Codex cited lines 176, 348, 582,
  866, 1066, 1268, 2347) gain `waterfill_honored_epoch_bits: 0`.
- Any other explicit `CoSInterfaceRuntime { .. }` literal the build surfaces
  (the implementation will grep `CoSInterfaceRuntime {` across the tree and
  update every site; the build is the backstop).
- #1735 (MQFQ generalize) will build on this; keep the field naming and
  epoch-clear placement cohesive with that follow-up (the honored bitset is
  exact-only today; the generalize work may extend the eligible set but does
  not depend on this field's internals).

## 10. Open questions for adversarial review

1. **Is the bit-clear at the refill site the *only* correct clear point?**
   Could a path reset `waterfill_pass1_remaining_bytes` to non-zero without
   going through the refill, leaving stale honored bits into a new epoch?
   (Grep shows the only writes to `pass1_remaining` are the refill `:805`,
   the per-honor decrement `:938`, and the exhaustion reset `:1072` → 0. The
   exhaustion-reset-to-0 forces a refill-clear next call. Confirm no other
   writer.)
2. **Borrow-checker:** does reading `root.exact_queues_by_rate_ascending[i]`
   and `root.waterfill_honored_epoch_bits` then taking
   `&mut root.queues[queue_idx]` in the same loop body actually compile, or
   does NLL choke on the field-disjointness across the loop back-edge,
   forcing the clone back? (Plan asserts it compiles via index-copy-first;
   reviewers should demand the build artifact as proof, not the assertion.)
3. **Distribution-change blast radius:** does correcting Phase-2 to skip
   honored queues *starve* any queue relative to today, or only redistribute
   residual? Could a pathological rate mix (one huge + many tiny) leave the
   huge queue worse off than the broken-mask "re-serve everything"
   behavior? (Argue this is *more* correct per the waterfill contract, but a
   reviewer may find a regime where the broken behavior was accidentally
   fairer — that would be a real finding.)
4. **#1217 CoV:** is there a risk the corrected distribution *fails* the
   structural-CoV gate that the broken approximation happened to pass? If
   the broken Phase 2 was accidentally equalizing service, the fix could
   raise observed CoV. (Smoke must measure; this is invitable to PLAN-KILL
   if the corrected distribution is structurally less fair under the
   contract.)
5. **`exact_guarantee_rr` interaction:** the fix doesn't touch
   `exact_guarantee_rr`, but does the corrected honored-set skip change which
   `queue_idx` lands in `exact_guarantee_rr` at Phase-2 selection in a way
   that affects any *other* consumer of that cursor? (Grep its readers.)
6. **Is a `u64` bitset the right shape, or does the ≤64 cap need to become a
   hard config reject** (like #1731 #3 does for workers) so a >64-exact-queue
   config doesn't silently get queues ≥64 serviced in both phases? (Today's
   local mask had the same silent cap; the fix preserves it. Reviewers may
   argue the cap should be surfaced — but that is arguably out-of-scope
   scope-creep for this isolated fix.)

## 11. Round-1 adversarial review findings (folded into v2)

Three reviewers ran on plan v1 (`b1b3581e`). Codex (PLAN-NEEDS-MAJOR) and
AGY (PLAN-NEEDS-MAJOR) converged independently on the same FATAL gap;
Claude-SMR concurred. All folded:

- **F1 (FATAL — Codex + AGY + Claude-SMR): Phase 1 must also skip honored
  queues.** v1 only had Phase 2 read the persistent set. Because Phase 1
  restarts at the smallest queue and returns on honor, the smallest queue
  would be re-honored every call and monopolize the budget — the exact skew
  the issue reports. v1 would NOT have fixed the headline bug. **Folded:**
  §4.2 (c′) adds the at-most-once Phase-1 skip; the bitset is now the SSOT
  read by both phases. §4.3 documents the (intended) Phase-1 semantic change.
- **F2 (MAJOR — Codex): incomplete file scope.** A non-`Default`
  `CoSInterfaceRuntime` field needs 7 explicit struct-literal updates in
  `worker/cos/tests.rs` (and any others the build surfaces). **Folded:** §9
  file list corrected; implementation greps `CoSInterfaceRuntime {`.
- **F3 (MAJOR — Codex + AGY): the `<64` silent cap becomes load-bearing.**
  **Folded:** §4.4 — disposition is `debug_assert` + doc for the isolated
  fix; hard config-reject deferred to a separate sub-issue (mirroring how
  #1731 §4.3 scopes the analogous 32-worker reject as its own item).
  Reviewers invited to rule whether a one-time build-time warning is
  required in-scope.
- **Borrow-checker (Codex + AGY both): the index-loop compiles under NLL** as
  described (index-copy-before-`&mut`). AGY confirmed by building a patched
  artifact (its edits were review-only scaffolding and have been reverted;
  the worktree is clean — the implementation will be written fresh per this
  plan). Codex confirmed by static read.
- **Distribution / HA (Codex): no huge-queue starvation, no HA-sync need.**
  Phase-2 cursor resets to 0 (largest) at refill; the fix redistributes
  residual rather than starving. The bitset is within-epoch scheduler state,
  not HA-synced (worker aggregation exports only `waterfill_epochs` /
  `waterfill_phase1_budget_breaks`). No `make test-failover`.

**Process note:** AGY wrote a full implementation into the worktree during
its "review." Per project policy (AGY is review-only) those edits were
reverted and the worktree verified clean; the implementation below is
written from this plan, not adopted from AGY.

## 12. Round-2 adversarial review findings (folded into v3)

Round-2 ran on plan v2 (`e94bd0482`). Codex r2 PLAN-NEEDS-MAJOR and AGY r2
PLAN-NEEDS-MINOR converged independently on the SAME refinement:

- **F3′ (Codex MAJOR + AGY MINOR — the decisive one): the bitset keyed by
  `queue_idx` with `debug_assert!(ascending_len <= 64)` is the WRONG
  invariant.** `exact_queues_by_rate_ascending` holds root.queues indices
  from `0..config.queues.len()` (`builders.rs:81`); a config with 2 exact
  queues at root indices 65/66 has `ascending_len == 2` (passes the assert)
  but `1u64 << 65` is an out-of-range shift / silently untracked. **Folded:**
  §4.1 + §4.2 re-key the bitset by ORDINAL position `i`/`pos_from_end` in the
  ascending vec (both reviewers' recommended Option A). The bit range is now
  bounded by the exact-queue COUNT (≤64), which the `debug_assert` correctly
  enforces. No `queue_idx < 64` guard remains.
- **Build-time warning now in scope (Codex + AGY both required it).**
  §4.4 adds a one-time `eprintln!` at `build_cos_interface_runtime`
  (control-plane cold path) when the exact-queue count exceeds 64, so the
  cap is operator-visible in journald even in release. Hard config-reject
  stays deferred (mirrors #1731 §4.3's 32-worker reject scoping).
- **Codex r2 Finding-3 (empty-epoch return): plan text overstated Phase 2.**
  When ALL queues are honored with budget left, Phase 2 has no residual
  target and the selector returns `None` for that call (benign; next call
  refills+clears). **Folded:** §4.3 clarified — no claim that Phase 2 serves
  residual when nothing is unhonored.
- **Codex r2 Finding-5 (test determinism): "unequal rates" is insufficient.**
  `cos_guarantee_quantum_bytes` clamps at the min floor; rates must produce
  DISTINCT unclamped quantums, and `root.tokens` (not just per-queue tokens)
  must be abundant. **Folded:** §8 test spec tightened.
- **Codex r2 confirmed:** the Phase-1-skip fix correctly distributes the
  budget across queues smallest-first one-honor-each (hand-traced
  q_small→q_mid→q_big, no off-by-one); clear-at-refill is still the only
  correct clear point; no stale-bits-into-fresh-budget path.
- **AGY r2 was review-only this round** (no worktree edits; verified clean).

**§9 amendment:** this PR also touches `userspace-dp/src/afxdp/cos/builders.rs`
for the build-time over-64 warning (in addition to the field init).
