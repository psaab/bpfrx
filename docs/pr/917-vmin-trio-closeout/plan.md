# #917 V_min trio — closeout audit (#940 / #941 / #942)

## Status

REV-3 — final shipped state. Plan reflects what's in the merged
diff, not what was originally proposed. Older revisions:

- REV-1 → REV-2 (Codex round-1 plan review, 6 asks): widened Gap 1
  to include the stale `publish` doc + first-enqueue rationale;
  reworded Gap 4 to actually run the existing #940 microbench and
  invoke `scripts/userspace-ha-failover-validation.sh`; aligned
  issue-closure to "PR merges first, then close with cited evidence".
- REV-2 → REV-3 (Codex code-review round-1, MERGE-NEEDS-MAJOR; round-2
  MERGE-NEEDS-MINOR): corrected publish-site count from 5 to 6
  (rollback `slot.publish` at `cos/queue_ops/push.rs:126` was
  missing); weakened the memory-ordering claim from "consistent
  snapshot" wording to "the set of values observed during the scan";
  scrubbed residual references to the deleted `read_v_min` /
  `participating_peer_count` helpers throughout this plan.

## Background

Three open issues describe correctness gaps in the cross-worker V_min
synchronization shipped by PR #939 (#917 Phase 4). Per the issues:

- **#940 (P0)**: V_min publish on speculative pop leaks uncommitted
  vtime to peers — fix by moving publish to TX-ring commit boundary.
- **#941 (P0)**: Bucket-empty vacate, HA-demotion vacate, hard-cap
  escape hatch — three sub-work-items.
- **#942 (P1)**: V_min check missing from Prepared scratch builder.

Audit finding (2026-05-02): the implementation work for all three
issues already shipped via PRs #950 (#940 fix), #952 (#941 work
items A/B/C/D), and #953 (#942 wiring), all merged 2026-04-28. The
issues are STALE — never closed. The architectural refactors
landed since (#1034 P1-P5, #1036, #1037, #1038, #1042, #1098)
relocated the code into `cos/queue_ops/v_min.rs` and
`cos/queue_service/drain.rs` but preserved the algorithm.

This PR is a **closeout audit**, not new implementation. Verify
every acceptance criterion from the original issues against the
current code, fill in the residual gaps, and close the three
issues with cited evidence.

## Audit results

### #940 acceptance criteria

| AC | Status | Evidence |
|----|--------|----------|
| No publish on speculative pop | ✅ PASS | `cos/queue_ops/pop.rs:117-118` comment confirms publish moved out; no `slot.publish` call in `cos_queue_pop_front_inner`. Test: `vmin_pop_snapshot_does_not_publish` (v_min_tests.rs). |
| Publish at TX-ring commit boundary | ✅ PASS | `publish_committed_queue_vtime` defined at `cos/queue_ops/v_min.rs:38`. **6 publish sites total: 4 post-settle + 1 demote-restore + 1 direct rollback.** Indirect via the helper: `cos/queue_service/service.rs:160`, `:310`, `:466`, `:619` (post-settle, each immediately after `settle_*`/`commit`); `tx/cos_classify.rs:641` (after `demote_prepared_cos_queue_to_local` restores the saved `queue_vtime`). Direct `slot.publish`: `cos/queue_ops/push.rs:126` on the `cos_queue_push_front` rollback path, restoring the pre-pop `queue_vtime` so peers don't see the inflated speculative value. Test: `vmin_post_settle_publish_writes_committed_vtime`. |
| Per-pop CPU regression < 1% | ⚠️ NOT VERIFIED | No automated micro-benchmark. PR #950 description likely captured pre/post measurements; not preserved as a regression test. |
| Cluster smoke iperf-c P=12 ≥ 22 Gb/s | ⚠️ STALE | Last evidence at `docs/pr/940-942-vmin-correctness/smoke.md` (post-PR-#953). Re-verify on current master. |
| iperf-b retx = 0 | ⚠️ STALE | Same. Re-verify. |
| No new failures across #785/#913/#917 suites | ✅ PASS | `cargo test --release` = 942 tests passing on the audit branch. |

### #941 acceptance criteria

| AC | Status | Evidence |
|----|--------|----------|
| A: bucket-empty vacate | ✅ PASS | `cos/queue_ops/accounting.rs:81-92`. Test: `vmin_vacate_on_bucket_empty`, `vmin_vacate_only_when_last_bucket_empties`. |
| B: HA-demotion vacate | ✅ PASS | `afxdp/ha.rs:51-55` enqueues `WorkerCommand::VacateAllSharedExactSlots` on RG demotion. Test: `vmin_demote_no_drain_all_leak`. |
| C: hard-cap escape hatch | ✅ PASS | `cos/queue_ops/v_min.rs:171` (`V_MIN_CONSECUTIVE_SKIP_HARD_CAP`) + suspension state in `cos_queue_v_min_consume_suspension` (v_min.rs:83). Test: `vmin_hard_cap_counter_resets_on_success`, `vmin_hard_cap_override_does_not_double_count_throttle`, `vmin_local_hard_cap_suspension_carries_into_prepared_drain`. |
| Symmetric first-enqueue publish | ❌ NOT IMPLEMENTED — see §Gap analysis below | Test `vmin_no_first_enqueue_publish` exists and **asserts the absence of this publish**, indicating an explicit decision to NOT do it. |
| Phantom-participating worker test | ✅ PASS | Implicit in `vmin_vacate_only_when_last_bucket_empties` and the bucket-empty vacate tests. |
| Hard-cap forced continue test | ✅ PASS | `vmin_hard_cap_override_does_not_double_count_throttle`, `vmin_prepared_drain_arms_hard_cap_after_repeated_throttle`. |
| Memory-ordering doc on the slot-iteration helper | ❌ MISSING (now FIXED) | `types/shared_cos_lease.rs:120-138` (the prior `read_v_min` site) had no non-atomic-across-slots semantics doc. The replacement helper `participating_v_min_snapshot` carries the canonical memory-ordering paragraph; the prior helpers (`read_v_min`, `participating_peer_count`) were dead code and have been removed (see Gap 2). |
| #943 telemetry counters | ✅ PASS | PR #1139 merged 2026-05-02 (commit `7438e92e`). Counters `v_min_throttles` + `v_min_throttle_hard_cap_overrides` plumbed through to wire surface. |
| Cluster smoke: mouse-latency ≤ 59.51 ms | ⚠️ STALE | Re-verify. |

### #942 acceptance criteria

| AC | Status | Evidence |
|----|--------|----------|
| Prepared flow-fair drain calls v_min_continue | ✅ PASS | `cos/queue_service/drain.rs:384`. K=8 cadence + suspension carry-over. |
| FIFO Prepared drain documents unreachability | ✅ PASS | `cos/queue_service/drain.rs:238-244`. |
| Synthetic Prepared-path V_min throttle test | ✅ PASS | `vmin_prepared_flow_fair_throttle_and_suspension`, `vmin_prepared_drain_arms_hard_cap_after_repeated_throttle`, `vmin_prepared_drain_unblocks_when_peer_slot_vacates`, `vmin_prepared_no_suspension_burn_when_head_is_local`. |
| No regression on existing Prepared-path tests | ✅ PASS | `cargo test --release`. |
| HA-failover replay smoke | ⚠️ NOT VERIFIED | Out of scope for closeout — would need a dedicated test harness; the existing cluster smoke does not exercise HA-replay storm specifically. |

## Gap analysis

### Gap 1: missing memory-ordering doc + stale `publish` doc + missing first-enqueue rationale

**Three related doc bugs** in the same file (`types/shared_cos_lease.rs`):

1. **Missing memory-ordering doc on the slot-iteration helper**
   (the prior `read_v_min` doc was a one-liner). #941 acceptance
   criterion explicitly required documenting the
   non-atomic-across-slots semantics.

2. **Stale doc on `PaddedVtimeSlot::publish`** (the original lines
   65-67 in the pre-PR doc claimed publish happens on first
   enqueue when the bucket count transitions 0 → ≥1). That claim
   was false: the implementation deliberately omits a first-enqueue
   publish (test `vmin_no_first_enqueue_publish` enforces the
   absence).

3. **Missing rationale for the first-enqueue-publish omission**:
   #941 work item A's "symmetric first-enqueue publish" was DROPPED
   during implementation. The reason wasn't documented anywhere
   that a future reader could find — without the rationale a future
   PR could re-add the (unwanted) publish "to make work item A
   complete".

**Why these matter**:
- (1) is the durable artifact that prevents future "is this a race?"
  litigation.
- (2) was a doc/code mismatch that misled anyone reading the type.
- (3) is the load-bearing piece of context for why the algorithm
  is correct: NOT_PARTICIPATING peers are skipped in the V_min
  reduction (`participating_v_min_snapshot` does
  `if let Some(peer) = slot.read()` — `None` means skip), so a
  freshly-enqueued worker that hasn't yet popped is correctly
  invisible to peer V_min until first commit. There is no
  "stale-low publish" bug because there is no publish.

**What this PR shipped** in `types/shared_cos_lease.rs`:
- Rewrote `PaddedVtimeSlot::publish` doc to drop the false
  first-enqueue clause; lists all 6 publish sites; cites the
  no-first-enqueue test as the enforcement mechanism.
- Replaced the prior `read_v_min` + `participating_peer_count`
  pair (both unused) with a single
  `participating_v_min_snapshot(worker_id) -> (u32, Option<u64>)`
  helper that returns the count + min in one pass.
- Added the memory-ordering paragraph on
  `participating_v_min_snapshot` (per-slot Acquire/Release;
  non-atomic across slots; result is the set of values observed
  during the scan, not a cross-slot atomic snapshot;
  bounded staleness across K-cadence read window).
- Added a module-level invariant doc on `cos/queue_ops/v_min.rs`
  capturing the "NOT_PARTICIPATING → peers skip → no stale-low
  publish" rationale.

### Gap 2: `read_v_min` and `participating_peer_count` are dead code

**Issue**: Both methods on `SharedCoSQueueVtimeFloor` are defined
`pub(in crate::afxdp)` but have **zero call sites**. The actual
slot iteration happens inline at v_min.rs:140-148 in
`cos_queue_v_min_continue`. The inlined version computes both
v_min AND participating count in a single pass — the helper
methods would require two passes.

**Three options**:

A. **Delete the dead helpers.** Pros: removes 30 LOC of unused code;
   the inlined version is the canonical algorithm. Cons: if a future
   caller wants v_min standalone (without the throttle decision),
   it has to re-implement the iteration.

B. **Keep helpers; rewrite `cos_queue_v_min_continue` to call them.**
   Pros: DRY; one canonical iteration. Cons: doubles the iteration
   cost on the hot path (one for v_min, one for participating). Not
   acceptable.

C. **Replace both helpers with a single `slot_snapshot` method that
   returns `(participating, v_min)` in one pass; rewrite
   `cos_queue_v_min_continue` to call it.** Pros: DRY, single-pass,
   centralized memory-ordering doc. Cons: small visibility juggle.

**Proposal: option C.** A single helper named
`participating_v_min_snapshot(&self, worker_id: u32) -> (u32, Option<u64>)`
that returns `(participating_count, Some(v_min) | None)`. Used by
`cos_queue_v_min_continue` for both pieces it currently inlines.
Memory-ordering doc lives on this helper.

### Gap 3: stale cluster-smoke evidence

The smoke gates from #940/#941/#942 acceptance (iperf-c P=12 ≥ 22 Gb/s,
mouse-latency ≤ 59.51 ms baseline) were captured at the time of
PRs #950/#952/#953 in late April. Master has moved 30+ commits since
(architectural refactors). Re-run smoke as part of this closeout PR
to confirm the gates still hold on the post-refactor code.

### Gap 4: #940 micro-benchmark gate + #942 HA-failover smoke

#### #940 micro-benchmark — RUN, don't defer

The #940 microbench DOES exist as `bench_pop_commit_settle_publish`
at `cos/queue_ops/tests.rs:1029` (`#[ignore]`'d, runnable via
`cargo test --release -p xpf-userspace-dp -- bench_pop_commit_settle_publish --nocapture --ignored`).
Codex round-1 caught that I had previously claimed "smoke
substitutes for the microbench" — that was wrong, the bench
exists and we should run it.

**Fix**: this PR runs the bench in --release and records
ns/op + bytes/sec figures in the closeout PR description. No
hard regression-gate (we don't have a baseline number from the
PR-#950 era), but the recorded number becomes the future baseline.

#### #942 HA-failover smoke — RUN if harness viable

The script `scripts/userspace-ha-failover-validation.sh` exists.
This PR invokes it after the main 6-class smoke, captures the
failover/failback timing + V_min counter increments on the
Prepared path, and includes the output in the PR description.

If the harness is not currently runnable (env-specific fixture
issues, missing peer state, etc.), the deferral is documented
honestly with the specific blocker — no hand-waving "out of
scope" claim.

## Proposal

### What this PR does

1. **Fix Gap 1**: rewrite the stale doc on `PaddedVtimeSlot::publish`
   to drop the false first-enqueue-publish claim and document the
   omission rationale. Add the memory-ordering paragraph to the
   replacement helper (`participating_v_min_snapshot` — see Gap 2)
   so the contract lives where the algorithm reads happen, not on
   helpers being deleted. Add a module-level invariant doc on
   `cos/queue_ops/v_min.rs` capturing the publish-only-on-commit
   rule and the no-first-enqueue rationale.

2. **Fix Gap 2 via Option C**: replace the two unused historical
   helpers (named `read_v_min` and `participating_peer_count` in
   pre-PR master) with a single
   `participating_v_min_snapshot(worker_id) -> (u32, Option<u64>)`
   that returns the count + min in one pass. Rewrite
   `cos_queue_v_min_continue` to call it.

3. **Verify Gap 3**: cluster smoke on the loss userspace cluster
   covering all 6 CoS classes; record iperf-c P=12 result and
   iperf-b retx count.

4. **Document Gap 4**: comment block in v_min.rs noting the missing
   micro-benchmark gate as a known limitation.

5. **Close #940, #941, #942** AFTER the closeout PR merges. Each
   close cites the merged PR commit hash + the final smoke evidence
   (per Codex round-1 — issues stay open until the merge is the
   durable artifact).

### What this PR does NOT do

- No algorithm changes. Every behavior preserved byte-for-byte
  (modulo Gap 2's helper consolidation, which is structurally
  identical to the inlined version).
- No new acceptance gates. The closing-the-issues acceptance is
  "code matches what the issue asked for, with cited evidence".
- No HA-failover smoke (#942 last AC). Out of scope; would need a
  dedicated test harness.

## Acceptance gate

- `cargo test --release` — all 942 tests pass + the helper rewrite
  doesn't introduce new failures.
- No new warnings.
- Cluster smoke: 6 CoS classes pass, iperf-c P=12 ≥ 22 Gb/s,
  iperf-b retx = 0.
- Issues #940, #941, #942 closed with the audit summary.

## Risks

1. **Helper consolidation could subtly change behavior**: option C
   replaces two iterations with one. Need to verify the inlined
   version's per-slot decisions match the new helper's return values.
   *Mitigation*: existing 26 V_min tests + smoke gate.

2. **Memory-ordering claim could be subtly wrong**: the doc says
   "Acquire load against Release store, non-atomic across slots".
   If a future caller relies on cross-slot atomicity, the doc is
   load-bearing.
   *Mitigation*: this is exactly what #941's acceptance asked us
   to document, and the algorithm has been in production since
   April. The claim is verified by the working algorithm, not by
   the doc itself.

3. **Smoke regressions on the post-refactor master**: 30+ commits
   between the original PRs and now. If the smoke fails, the
   audit becomes a real refactor PR.
   *Mitigation*: run smoke before declaring closeout complete;
   if it fails, escalate to an actual fix-it PR rather than a
   closeout.
