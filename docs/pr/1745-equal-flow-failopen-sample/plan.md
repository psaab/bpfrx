# #1745 — equal-flow-enforcement permanent fail-open: sample active-flow demand at acquire-time, not rotation-boundary

Status: v2 — Codex PLAN-NEEDS-MAJOR + AGY PLAN-NEEDS-MINOR + Claude-SMR
PLAN-NEEDS-MAJOR converged; all findings folded in. Q1 (the PLAN-KILL
question) resolved NOT-KILL by both external reviewers with independent
proofs (see "Why acquire-time sampling fixes it").

## Issue framing

With `equal-flow-enforcement` opted in on a high-shape exact scheduler
(scheduler-24g, queue 10) on the 6-worker loss cluster, the v8 equal-flow
equalizer **never enforces**: `equal_flow_enforced=0`,
`equal_flow_fail_open{reason=insufficient_sampled_workers}=1`,
`target_per_flow_bps=0`. Outlier flows (~1.9 Gb/s on lightly-loaded
workers) are never clipped toward the slowest per-flow rate. This is NOT
the #1733 >32-worker scratch-cap path (6 ≪ 32).

## Root cause (verified against code, not just the issue body)

The rotation winner (`rotate_epoch_v8.rs`) builds the publish inputs from
two per-worker arrays it reads/swaps at the rotation instant:

- `active_by_worker[id]` ← instantaneous `worker_active_flow_buckets[id]`
  load (`rotate_epoch_v8.rs:93-97`) — "does this worker have ≥1 active
  flow at the rotation nanosecond."
- `demanded_by_worker[id]` ← swap of `worker_demand_events[id]`
  (`rotate_epoch_v8.rs:89-92, :101`) — "did this worker bump a demand
  event during the just-ended epoch."

`publish_equal_flow_epoch_v8.rs` then, for every `active_by_worker[id]`,
requires `demanded_by_worker[id] && prev_grants[id] > 0` or it bails
`UnsampledActiveWorker` (`:43-47`); and requires `sampled_workers >= 2`
or it bails `InsufficientSampledWorkers` (`:56-61`).

**The bad coupling**: `demanded_by_worker[id]` is only set when the worker
runs `acquire_v8` while active (`mod.rs:1186-1193` — `bump_epoch_event`
on `worker_demand_events[worker_id]`). But exact queues with banked
tokens **skip lease acquisition entirely**: `maybe_top_up_cos_queue_lease`
returns at `token_bucket.rs:201` (`if queue.hot.tokens >= lease_bytes`)
**before** calling `acquire_via_lease` → `acquire_v8`. The exact-queue
bank watermark is `COS_EXACT_QUEUE_LEASE_BANK_BYTES` = 8 frames ≈ 32 KB
(`afxdp/mod.rs:261-263`).

So a worker carrying real traffic but whose per-epoch consumption stays
under the ~32 KB bank does **not** bump demand for that epoch, even though
`worker_active_flow_buckets[id] > 0` (the flow count is sticky and remains
nonzero between acquire calls). At the rotation boundary it shows up as
`active_by_worker=true, demanded=false` → `UnsampledActiveWorker`; with
several such workers the demand count drops below 2 → permanent
`InsufficientSampledWorkers` fail-open.

This is confirmed by the existing unit tests: every passing equal-flow
test seeds demand by explicitly calling `acquire_v8` for each worker each
epoch (`shared_cos_lease_tests.rs:553-564`, `:771-837`). That is exactly
the per-epoch acquire the banked production path skips, which is why the
tests pass green while production fail-opens.

The `suppressed_grant_bytes` / `cap_hit_events` increments are gated on
`equal_flow_enforced` + matching tag + nonzero target
(`mod.rs:1298-1307`), so the symptom is purely the never-enforce
fail-open, not a half-initialised suppression.

## Honest scope/value framing

This is a correctness fix for an opt-in feature
(`equal-flow-enforcement`, default OFF — the committed fixture does not
enable it). Blast radius on the default path is bounded: the v8 lease
code is shared, but the new sampling array and its reads are confined to
the `EqualFlowSuppress` rate mode + acquire-time recording. The win is
that the feature works at all: without it the equalizer is dead code in
every real deployment. If reviewers conclude the fix's mechanism cannot
actually capture banked workers either (see Open Question 1), PLAN-KILL
is an acceptable verdict — that would mean the whole equal-flow design
needs a different sampling source, not a patch.

## Why acquire-time sampling fixes it (the load-bearing argument)

The fix does NOT make banked workers call `acquire_v8`. It changes WHEN
and HOW the active-flow + demand signal is captured:

1. Today demand is a per-epoch boolean reset at rotation. A worker must
   call acquire **during** the epoch to set it; the rotation reads the
   instantaneous flow-bucket separately. The two signals are sampled at
   different times and can disagree.

2. The fix records a **tagged, sticky max active-flow sample** per worker
   *at every active acquire_v8 call* into a new `worker_equal_flow_active_samples`
   array (one `PackedEpochGrant` slot per worker, packed
   `(epoch_tag, max_active_flows_seen)`). Rotation swaps this array (like
   the demand/starvation arrays) and the publisher derives the sample set
   from it: a worker is "sampled" iff `sampled_active_flows[id] > 0 &&
   demanded[id] && prev_grants[id] > 0`.

3. Crucially — **single-epoch sticky-max is provably sufficient** (Q1,
   resolved NOT-KILL by both Codex and AGY independently). Exact queues
   have NO autonomous local token refill: `queue.hot.tokens` is refilled
   ONLY via `acquire_via_lease`→`acquire_v8` (`token_bucket.rs:204-209`),
   and every transmitted byte debits the bucket (`tx_completion.rs:679`).
   The watermark is `lease_bytes().max(BANK).min(buffer_bytes…)`
   (`token_bucket.rs:196-200`) — at most ~512 KB
   (`COS_ROOT_LEASE_MAX_BYTES`, `mod.rs:760`), at least the 8-frame
   ~32 KB bank. So any worker that sends a single packet drops below the
   watermark and is forced to call `acquire_v8` on its next selector
   visit — within the same or the immediately following epoch. Worked:
   even at 1 Mb/s (~25 B/epoch) the bucket falls under the watermark every
   epoch. The ONLY worker that stays banked across a whole epoch is one
   carrying literally zero traffic, and excluding such a worker from the
   sample set is the correct, desired semantics. There is no plausible
   "busy worker stays fully banked across multiple consecutive epochs"
   counterexample — the kill scenario does not exist.

   The sticky-max sample (recorded at any active acquire, surviving the
   single epoch until the rotation swap) replaces the brittle requirement
   that the per-epoch demand boolean AND a separate instantaneous
   flow-bucket read agree at the single rotation nanosecond.

4. The publisher no longer fail-opens merely because some *currently*
   (rotation-instant) active worker had no sample — it only counts the
   sampled set. `active_outside_scratch` (the real >32-worker case) stays
   the hard fail-open.

If a worker genuinely sent zero traffic over a whole epoch it correctly
remains unsampled and excluded — which is the desired semantics
(`NoActiveFlows` / `InsufficientSampledWorkers` still fire for a true
single-flow `-P1` workload, validation gate 2).

## Concrete design

### New V8State field (`mod.rs:~396`, init `~:1068`)

```rust
/// #1745: per-worker tagged max active-flow sample, recorded at
/// acquire_v8 time (when the worker requests lease credit while
/// active). Packed (epoch_tag, max_active_flows_seen_this_epoch).
/// Decouples the equal-flow sample set from the rotation-instant
/// worker_active_flow_buckets read, which missed exact-queue workers
/// running on banked tokens (they skip acquire_v8 at the bank
/// watermark and so do not bump demand every epoch). Swapped at
/// rotation alongside worker_demand_events. Length = max_worker_id + 1.
worker_equal_flow_active_samples: Box<[PackedEpochGrant]>,
```

Init beside `worker_demand_events` in both `new_v8`/`new_v8_with_rate_mode`
(they share the array-build block at `:1050-1071`).

### acquire_v8 recording (`mod.rs:~1186-1193`)

Replace the active-only boolean load with an active-flow load + sticky-max
sample record, gated to `EqualFlowSuppress` so the default path is
byte-unaffected:

```rust
let active_flows = v8
    .worker_active_flow_buckets
    .get(worker_id)
    .map(|a| a.load(Ordering::Relaxed))
    .unwrap_or(0);
let active = active_flows > 0;
if active {
    bump_epoch_event(&v8.worker_demand_events[worker_id], my_tag);
    if v8.rate_mode == V8RateMode::EqualFlowSuppress {
        record_equal_flow_active_sample(
            &v8.worker_equal_flow_active_samples[worker_id],
            my_tag,
            active_flows,
        );
    }
}
```

`record_equal_flow_active_sample` is a new tag-checked max-CAS helper
(sibling of `bump_epoch_event`/`worker_grant_bump`). **It must NEVER
write backwards over a newer epoch** (Codex Finding 1 + AGY Finding 3 —
critical race): an old acquirer holding a stale `my_tag` could otherwise
overwrite the rotation's fresh `(new_tag, 0)` slot with `(my_tag,
active_flows)`, corrupting the new epoch's sample. The race-free shape
(compares `curr_tag` against `my_tag`, aborts on a future tag):

```rust
#[inline]
fn record_equal_flow_active_sample(pg: &PackedEpochGrant, my_tag: u32, active_flows: u32) {
    loop {
        let curr = pg.0.load(Ordering::Acquire);
        let (curr_tag, curr_count) = PackedEpochGrant::unpack(curr);
        // A rotation already advanced the slot to a newer epoch — abort,
        // never write a stale tag backwards. Tags are monotonically
        // increasing per rotation (seq>>1)+1, so `curr_tag > my_tag`
        // unambiguously means "rotation happened after our snapshot".
        if curr_tag > my_tag {
            return;
        }
        let new = if curr_tag == my_tag {
            PackedEpochGrant::pack(my_tag, curr_count.max(active_flows))
        } else {
            // curr_tag < my_tag: first active acquire of this epoch; the
            // slot still carries the prior epoch's value (it has not been
            // swapped yet, or we are the first writer). Install fresh —
            // do NOT carry the stale count forward.
            PackedEpochGrant::pack(my_tag, active_flows)
        };
        if pg
            .0
            .compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}
```

Tag monotonicity: `new_tag = ((seq>>1)+1)` at rotation
(`rotate_epoch_v8.rs:53`); tags only increase, so `curr_tag > my_tag`
safely means "newer epoch." The `EqualFlowSuppress` guard means
`CstructDefault` leases never touch the new array → default path
unchanged.

### rotate_epoch_v8 swap (`rotate_epoch_v8.rs`)

**The new-array swap MUST be gated on `EqualFlowSuppress`** (Codex
Finding 2 + AGY Finding 5): the existing STEP-2 loop (`:83-112`) runs for
ALL v8 rate modes, so adding the swap there unconditionally would impose
a new per-worker `AcqRel` swap per rotation on the `CstructDefault`
default path, breaking byte-equivalence. Instead, do the new swap inside
the existing `if v8.rate_mode == V8RateMode::EqualFlowSuppress` block
(`:123`) that already guards the publish call, in a dedicated loop:

```rust
let mut sampled_active_flows_by_worker = [0u32; MAX_WORKERS_SCRATCH];
if v8.rate_mode == V8RateMode::EqualFlowSuppress {
    for id in 0..v8.worker_equal_flow_active_samples.len() {
        let old_sample = v8.worker_equal_flow_active_samples[id]
            .0
            .swap(new_packed_zero, Ordering::AcqRel);
        let (old_tag, old_count) = PackedEpochGrant::unpack(old_sample);
        if id < n_workers && old_tag == (seq >> 1) as u32 {
            sampled_active_flows_by_worker[id] = old_count;
        }
    }
    publish_equal_flow_epoch_v8(
        v8, new_tag, n_workers, active_outside_scratch,
        &active_by_worker, &sampled_active_flows_by_worker,
        &demanded_by_worker, &prev_grants,
    );
} else {
    v8.equal_flow.disable_for_epoch(new_tag);
}
```

The tag check `old_tag == (seq>>1)` only counts samples from the
just-ended epoch (the slot is reset to `new_packed_zero = pack(new_tag,
0)`, so a slot never written this epoch swaps out as `(prior_tag, …)` and
is correctly excluded as 0).

### publish_equal_flow_epoch_v8 (`publish_equal_flow_epoch_v8.rs`)

Add `sampled_active_flows_by_worker: &[u32]` parameter. Replace the
sample-set derivation. **Per Codex Finding 4, do NOT drop the
active-but-unsampled bail entirely** — that would let a worker which
genuinely participated (demanded or was granted bytes) but whose sample
we missed be silently ignored while two other workers set the class
target. The refined rule, per worker `id` in `0..n_workers`:

- If `!active_by_worker[id]` → skip (not a class participant).
- Else if `sampled_active_flows[id] > 0 && demanded_by_worker[id] &&
  prev_grants[id] > 0` → IN the sample set.
- Else if `demanded_by_worker[id] || prev_grants[id] > 0` → the worker
  DID participate this epoch but we failed to capture a usable sample →
  **fail-open `UnsampledActiveWorker`** (preserve the safety bail for a
  real-but-unsampled participant).
- Else (active flow-bucket nonzero but zero demand AND zero grants AND
  zero sample) → genuinely idle-at-rotation background worker →
  **exclude from the set, do NOT fail-open** (this is the banked-worker
  case the fix targets; such a worker, if it had real traffic, would have
  a sample per the Q1 proof).
- Compute the per-flow target over the sample set:
  `prev_grants[id] / sampled_active_flows[id]`, clip-to-SLOWEST `min`
  (UNCHANGED — see Out-of-scope #1746).
- `max_worker_cap` = `max over sampled set of smoothed *
  sampled_active_flows[id]`.
- Require sample-set size `>= 2` → else `InsufficientSampledWorkers`.
- Keep `active_outside_scratch` → `UnsampledActiveWorker` hard fail-open
  for the real >32-worker case (`:30-34`).
- Keep all downstream guards: `ZeroTarget`, `ArithmeticInvalid`,
  `LowDemandWorker` (util gate — this is the structural protection
  against a stale-high sticky-max over-suppressing after flow teardown,
  per AGY Q2), `NotEnoughValidStreak`, smoothing.

Note the `max_worker_cap`/per-flow math uses `sampled_active_flows[id]`
(the swapped sticky-max), NOT the live `worker_active_flow_buckets`, so
the published cap is internally consistent with the sample that produced
the target.

The acquire-side `equal_flow_cap_v8` (`mod.rs:1606`) is UNCHANGED — it
keeps multiplying the published per-flow target by the live
`worker_active_flow_buckets[worker_id]`.

### Regression test (unit)

1. `equal_flow_forced_insufficient_sampled_workers_leaves_suppression_unchanged`:
   build an `EqualFlowSuppress` lease, drive a single-worker (`-P1`-style)
   epoch so the publisher bails `InsufficientSampledWorkers`, assert
   `suppressed_grant_bytes` and `cap_hit_events` are both unchanged across
   the fail-open epoch (validation gate 3).
2. Positive test: two workers sampled via the new acquire-time sticky-max
   path now reach `enforced=1`. Critically, model the banked path by NOT
   re-bumping the instantaneous demand on the enforcing epoch — assert the
   pre-fix rotation-instant logic would have fail-opened but the
   sticky-max sample carries the worker through.
3. **Sticky-max correctness test**: within one epoch, record a high
   active-flow count then a lower one (flow teardown) for the same
   worker; assert the swapped-out sample is the MAX (not last-write).
4. **Teardown over-suppression guard test** (AGY Q2 / Codex Finding 5):
   drive a worker whose grants fall below the util gate after a sample
   recorded a high flow count; assert the epoch fails open
   `LowDemandWorker` rather than publishing an over-low target.
5. **Tag-backwards race test**: simulate a stale acquirer
   (`record_equal_flow_active_sample` with `my_tag < curr_tag`) and assert
   the slot is NOT overwritten (no backwards tag write).
6. **Default-path byte-equivalence test**: a `CstructDefault` lease must
   leave `worker_equal_flow_active_samples` all-zero after several
   acquire + rotation cycles (no new atomic writes on the default path).

## Public API preservation

- `acquire_v8`, `equal_flow_cap_v8`, `snapshot_epoch_v8`,
  `maybe_rotate_epoch_v8` signatures UNCHANGED.
- `publish_equal_flow_epoch_v8` gains one `&[u32]` parameter (internal
  `pub(super)`, single call site).
- All `v8_equal_flow_*` status accessors UNCHANGED.
- No protocol/wire change; no Go-side change.

## Hidden invariants the change must preserve

- **Seqlock ordering**: the new array is swapped inside the ODD critical
  section like the others; payload-before-tag publish in
  `enforce_epoch`/`fail_open` unchanged.
- **Single-writer-per-slot**: only worker `id` writes
  `worker_equal_flow_active_samples[id]` at acquire; rotation winner is
  the sole swapper. Same discipline as `worker_grants`/`worker_demand_events`.
- **Tag-checked CAS**: cross-epoch records naturally rejected by tag
  mismatch (max-CAS installs new tag on mismatch — must NOT carry a stale
  count forward; it resets to the fresh sample).
- **Default path byte-unaffected**: all new writes/reads gated on
  `V8RateMode::EqualFlowSuppress`. `CstructDefault` acquire records
  nothing.
- **No hot-path allocation**: array allocated once at lease construction;
  acquire-time record is a bounded CAS loop.
- **HA**: the v8 equal-flow epoch state is process-local per-binding and
  rebuilt fresh on the new array sizing; it is NOT serialized over session
  sync (only `worker_active_flow_buckets` is rehydrated via
  `rehydrate_worker_active_count`). The new array is rebuilt on lease
  reconstruction. No wire/sync surface added. `make test-failover` still
  run because the lease code is shared.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression (default path) | LOW | All new state gated on `EqualFlowSuppress`; `CstructDefault` untouched. Verified by grep + the default-mode test. |
| Lifetime / borrow-checker | LOW | One more `Box<[PackedEpochGrant]>` field + one `&[u32]` param. No new borrows across the seqlock. |
| Performance regression | LOW-on-default / LOW | Default path: zero new work. EqualFlow path: one extra Relaxed load + one bounded CAS per active acquire — same class as the existing demand bump right beside it. |
| Architectural mismatch | LOW (was MEDIUM) | Q1 resolved NOT-KILL: exact queues have no autonomous refill, so any byte-sending worker is forced to acquire_v8 within the epoch (Codex + AGY independent proofs). Only zero-traffic workers stay banked, and excluding them is correct. The single-epoch sticky-max sample is provably sufficient. |

## Test plan

- `cargo build` clean (release).
- `cargo test --release` full suite green.
- 5×/5 flake on the most-affected named tests
  (`equal_flow_*`, the new regression test).
- Go suite (`go test ./...`) — no Rust-adjacent breakage expected.
- Deploy to loss userspace cluster.
- **Live validation gate (the proof):**
  1. Enable `equal-flow-enforcement` on scheduler-24g (queue 10), CoS
     loaded + classifier bound; iperf3 `-P12` on port 5210; after warmup
     ASSERT `enforced==1`, `target_per_flow_bps>0`, `max_worker_cap_bytes>0`,
     `fail_open{insufficient_sampled_workers}==0` steady-state, AND
     per-stream CoV drops + ~1.8-1.9G outliers clip toward the published
     target (ground-truth iperf3 per-stream, not #1741 counters).
  2. `-P1` control: `enforced==0`, `target==0`, reason
     `insufficient_sampled_workers`, NO `suppressed_grant_bytes` increase.
  3. Revert equal-flow OFF (committed fixture stays default-off).
  4. Full CoS smoke matrix (Pass A CoS-off + Pass B per-class) v4+v6 ×
     push+reverse; #1217 fairness gate; no aggregate/best-effort
     regression on the equal-flow-OFF default path.
- `make test-failover` (shared lease code).

## Out of scope (explicitly)

- **#1746**: changing the target semantics from clip-to-SLOWEST
  (non-work-conserving) to mean / global-fair-rate. This PR KEEPS
  clip-to-slowest `min` exactly. #1746 is gated on this fix landing.
- Folding `publish_equal_flow_epoch_v8`'s parameter list into a context
  struct (tracked follow-up from PR #1588).
- Any change to the >32-worker scratch cap (#1733).

## Open questions for adversarial review — RESOLVED in round 1

All six resolved by Codex (PLAN-NEEDS-MAJOR) + AGY (PLAN-NEEDS-MINOR) +
Claude-SMR (PLAN-NEEDS-MAJOR), converged into v2 above:

- **Q1 (sufficiency / the kill question): NOT-KILL.** Both external
  reviewers gave independent proofs that exact queues have no autonomous
  refill, so any worker sending ≥1 byte drops below the watermark and is
  forced to `acquire_v8` within the epoch; only a zero-traffic worker
  stays banked and excluding it is correct. No multi-epoch-banked
  counterexample exists.
- **Q2 (sticky-max vs last-write): max is correct;** last-write would
  publish a noisy transient denominator. Stale-high after teardown is
  caught by the `LowDemandWorker` 80% util gate (regression test #4).
- **Q3 (tag race): CRITICAL — fixed.** Helper now aborts on
  `curr_tag > my_tag`, never writes a stale tag backwards.
- **Q4 (dropping the bail): refined, not dropped.** Keep the bail for a
  demanded-or-granted-but-unsampled participant; only exclude truly idle
  workers. `sampled >= 2` retained.
- **Q5 (HA): acceptable.** New array built unconditionally at
  `len = max_worker_id + 1` in lock-step with `worker_grants`; fresh
  process-local telemetry, no rehydration needed.
- **Q6 (default-path byte-equivalence): fixed** by gating the
  rotation-side swap on `EqualFlowSuppress` (not just the acquire-side
  record). Regression test #6 asserts it.

### Original open questions (kept for the record)

1. **Is acquire-time sampling actually sufficient?** At the validation
   shape (24 Gb/s, ~32 KB bank), does every busy worker call `acquire_v8`
   at least once per epoch (or per few epochs, given sticky-max survives
   only ONE epoch because the array is swapped each rotation)? If a worker
   can stay fully banked across multiple consecutive 200 µs epochs at a
   plausible per-worker rate, the sticky-max (single-epoch) sample still
   misses it and the fix is insufficient → PLAN-KILL. Should the sample
   instead persist across N epochs (decay), not reset every rotation?
2. **Sticky-max vs last-write**: is max the right reduction? A worker
   whose flow count drops mid-epoch (flow teardown) would publish a stale
   high count. Does that distort the per-flow target (`prev_grants /
   sampled_active_flows`) — too-low target → over-suppression? Should it
   be last-write or min instead?
3. **Tag-reset semantics on the max-CAS**: on tag mismatch the helper must
   install `(my_tag, active_flows)` fresh, NOT `max(stale, active_flows)`.
   Confirm the helper cannot leak a prior epoch's count via a lost-update
   race between the tag check and the CAS.
4. **Dropping the active-but-unsampled hard bail**: by removing the
   `:43-47` fail-open, can a transient where one worker is sampled and a
   second is `active_by_worker` but unsampled now produce a target derived
   from a non-representative single-worker-ish set that over-clips the
   class? Is `sampled>=2` enough, or does dropping that bail open a new
   under-target hazard?
5. **HA/failover**: the equal-flow epoch state is process-local and
   rebuilt on lease reconstruction. Confirm the new array does not need
   rehydration and that a demote→promote on the new primary cannot leave
   a half-sized array (vs `worker_grants`) — both are built from the same
   `len = max_worker_id + 1`, so they should stay in lock-step; verify.
6. **Default-path byte-equivalence**: confirm by code-walk that a
   `CstructDefault` lease performs literally zero new atomic ops (the
   `EqualFlowSuppress` guard wraps both the record call and the publish
   branch already gates the rotate call).
