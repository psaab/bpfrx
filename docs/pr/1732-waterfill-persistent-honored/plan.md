# Plan — #1732 CoS GuaranteeRate waterfill: persistent honored set + alloc-free hot path

- **Status**: DRAFT v1 — pending adversarial plan review
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
/// #1732: persistent Phase-1 honored bitset for the current
/// waterfill epoch. Bit `q` set ⇔ exact queue index `q` was honored
/// in Phase 1 this epoch. Previously a function-local `honored_mask`
/// that reset to 0 every call, so Phase 2 (entered on a *later* call
/// than the Phase-1 honors) saw an empty mask and could not skip
/// already-honored queues — the documented "approximates" skew. Now
/// persisted across selector calls and CLEARED at the lazy Phase-1
/// refill (where `waterfill_epochs` bumps), so Phase 2's descending
/// residual walk correctly skips queues that already took their
/// Phase-1 guarantee this epoch. Bounded to ≤64 exact queues by the
/// existing `queue_idx < 64` guard at the honor/skip sites; queues at
/// index ≥64 are never marked nor skipped (same conservative behavior
/// as the prior local mask). Single-writer owner worker, plain `u64`.
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
for i in 0..ascending_len {
    let queue_idx = root.exact_queues_by_rate_ascending[i];
    let queue = &mut root.queues[queue_idx];
    ...
```

`root.exact_queues_by_rate_ascending[i]` is read and copied into the `Copy`
local `queue_idx` (a `usize`), ending the immutable borrow of `root` before
`&mut root.queues[queue_idx]` is taken — no overlapping borrow, no alloc.
The loop bound `ascending_len` is captured once (the vec is runtime
read-only, so the length cannot change mid-loop; capturing it also avoids
re-borrowing `root` for `.len()` inside the loop). Index access uses `[]`
which is in-bounds by construction (`i < ascending_len`).

**(c) Phase-1 honor sets the persistent bit.** At the honor site (`:941`),
replace `honored_mask |= 1u64 << queue_idx;` with
`root.waterfill_honored_epoch_bits |= 1u64 << queue_idx;` (still guarded by
`queue_idx < 64`). This write happens before the `return`, so the bit
persists into the next call.

**(d) Phase-2 reads the persistent bitset.** Phase 2 (`:960-1069`) currently
references the dead local `honored_mask` at `:985`. Replace the Phase-2
length/index references to the cloned `sorted_indices` with
`root.exact_queues_by_rate_ascending` (indexed; the vec is still in scope on
`root`, just not cloned), and replace the `honored_mask` skip-check at `:985`
with `root.waterfill_honored_epoch_bits`:

```rust
if queue_idx < 64 && (root.waterfill_honored_epoch_bits & (1u64 << queue_idx)) != 0 {
    // skip — already honored in Phase 1 this epoch
}
```

The Phase-2 descending walk reads `root.exact_queues_by_rate_ascending.len()`
and `[pos_from_end]` directly. As above, each index read copies a `usize`
out before any `&mut root.queues[..]` borrow, so borrow-split holds. The
`phase2_idx`/`start_phase2`/cursor arithmetic is unchanged.

**Borrow-checker note.** The reads of `root.waterfill_honored_epoch_bits`
and `root.exact_queues_by_rate_ascending[..]` in Phase 2 happen *before* the
`let queue = &mut root.queues[queue_idx];` on each iteration, and the bit
read result is a `Copy` `u64`/`usize`. `queues` and the waterfill fields are
disjoint struct fields, but to keep the borrow checker happy across the loop
body the reads are sequenced before the `&mut` borrow on every iteration —
exactly the discipline the existing code already uses for the telemetry
`root` field writes at `:933` and `:944`.

### 4.3 No semantic change to honored-within-a-single-call

In the old code, Phase 1 set the local bit at `:942` and returned at `:954`
on a honor — so the only time Phase 2 ran in the *same* call was after a
Phase-1 break (`:935`) with **zero** honors that call (`honored_mask` still
0). Under the new code, the same single-call path sees
`waterfill_honored_epoch_bits` carrying the honors from *prior* calls this
epoch — which is the entire point and the documented-correct behavior. There
is no call in which the old local mask carried information the new persistent
field doesn't; the persistent field is a strict superset.

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
| Behavioral regression | **MED** | Phase-2 distribution genuinely changes (the point). Bounded by the #1217 CoV gate + a new distribution unit test. Phase-1 honor order unchanged; only the residual walk corrects. |
| Lifetime / borrow-checker | **LOW** | Index-copy-before-`&mut` is the existing discipline; the clone only ever masked this borrow conflict. Build proves it. |
| Performance regression | **LOW** | Strictly removes an alloc; adds two `u64` field accesses (a bit-or and a masked test) that replace the local-mask ops 1:1. No new per-iteration cost. |
| Architectural mismatch (#961 / #946-P2) | **LOW** | Not an architecture change; an incremental field add + alloc removal on an existing, tested selector. The #1731 plan (3-reviewer PLAN-READY) ranks this the lowest-risk sub-issue. |

## 8. Test plan

- `cargo build` clean (release).
- Full cargo suite (`cargo test --release`).
- 5× flake on the new distribution test + the existing
  `waterfill_*` named tests.
- New distribution test (`queue_service/tests.rs`): **3+ exact queues at
  unequal `transmit_rate_bytes`**, abundant per-queue tokens so the only
  gate is the Phase-1 byte budget, `fraction` chosen so Phase 1 honors a
  strict subset (the small queues) and Phase 2 must serve the residual.
  Drain a multi-selection sequence and assert the **per-epoch service order /
  byte distribution across >1 selection** — specifically that:
  (i) the persistent honored set causes Phase 2 to skip the Phase-1-honored
  small queues and reach the larger ones, and
  (ii) the visible per-queue selection counts across one full epoch differ
  from the broken-mask behavior (a queue honored in Phase 1 is NOT re-served
  in Phase 2 of the same epoch). This is exactly the pin the `:2318` test
  explicitly declined to make.
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
  worktree; no file overlap with this change beyond the shared CoS module
  tree (this PR touches only `queue_service/mod.rs`, `types/cos.rs`,
  `builders.rs`, `queue_service/tests.rs`).
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
