# Codex Code Review

MERGE NO

## Findings

HIGH

- `userspace-dp/src/afxdp/tx.rs:2758-2762`, `userspace-dp/src/afxdp/worker.rs:1761-1791`, `userspace-dp/src/afxdp/worker.rs:688-703`, `userspace-dp/src/afxdp/tx.rs:5909-5938`, `userspace-dp/src/afxdp/types.rs:1693-1712`, `docs/pr/829-slice-b/plan.md:90`, `docs/pr/829-slice-b/plan.md:521-527`: the only production `mark_binding_idle()` call is the post-drain helper when a queue drains empty. The teardown/reconfigure paths release queue tokens and clear runtimes, but never mark registered frontier slots idle. That leaves a stale non-`u64::MAX` slot behind, and `current_min_frontier()` will keep reducing over it forever. On failover/reconfigure/lease-map swaps, a dead binding can pin `v_min` and make surviving bindings yield against a frontier that will never advance. Fix: before `release_all_cos_queue_leases()`, `reset_binding_cos_runtime()`, and lease-map swaps, walk every exact flow-fair queue with `(frontier_slot, shared_queue_lease)` and call `mark_binding_idle(slot)`.

MED

- `userspace-dp/src/afxdp/coordinator.rs:1919-1938`, `userspace-dp/src/afxdp/worker.rs:1657-1660`, `userspace-dp/src/afxdp/tx.rs:5487-5494`, `userspace-dp/src/afxdp/tx.rs:5572-5588`, `userspace-dp/src/afxdp/types.rs:1215-1218`, `userspace-dp/src/afxdp/tx.rs:15980-15988`: `frontier_slot` is not actually restricted to `shared_exact + flow_fair`. The coordinator builds `SharedCoSQueueLease` for every exact queue, the worker fast path attaches that lease to every exact queue, and promotion registers whenever `queue.flow_fair` is true. Because `promote_cos_queue_flow_fair()` sets `queue.flow_fair = queue.exact`, owner-local exact queues will also register slots, contradicting the type docs and the approved plan's "single-owner exact queues unaffected" contract. Test #22 hides this by using `shared_queue_lease = None`, which is not the production shape. Fix: gate frontier registration/publish on `queue_fast.shared_exact` (or `queue.shared_exact`) in addition to `flow_fair`, and replace test #22 with a production-shaped fixture.

- `docs/pr/829-slice-b/plan.md:209-214`, `docs/pr/829-slice-b/plan.md:390-396`, `userspace-dp/src/afxdp/tx.rs:16100-16160`: test #26 does not pin the invariant the plan says is load-bearing. The plan's bound depends on "at most one binding per lease per poll iteration", but the test only proves that one call to `drain_exact_local_items_to_scratch_flow_fair()` ends in one final publish/idle mark. A future refactor could invoke that helper multiple times in one poll iteration and still pass this test while breaking the fairness bound. Fix: add an integration-style test around `drain_shaped_tx()` / the worker poll loop with two bindings on one lease and assert that only one binding slot can advance per poll iteration.

LOW

- `userspace-dp/src/afxdp/types.rs:1657-1663`: `register_binding()` is fetch-add based, but it is not strictly overflow-safe. `AtomicU32::fetch_add` wraps after `u32::MAX`, so low slot numbers can eventually be reissued. The unreclaimed 64-slot budget will fail much earlier, so this is not the active operational limit, but the precise answer to "overflow-safe?" is still no. Fix: use a saturating CAS loop around `MAX_BINDINGS_PER_LEASE`, or widen the cursor and never reuse low values.

- `userspace-dp/src/afxdp/tx.rs:5506-5510`, `userspace-dp/src/afxdp/tx.rs:5572-5588`: the `promote_cos_queue_flow_fair()` doc comment still says the "current policy" is `flow_fair = queue.exact && !shared_exact`, while the implementation now sets `queue.flow_fair = queue.exact`. Fix: update or delete the stale paragraph so the comment matches the code.

## Verification

- `1a. Yes.` The gate block is inserted at `userspace-dp/src/afxdp/tx.rs:1733-1766`, and `maybe_top_up_cos_queue_lease()` is called after it at `userspace-dp/src/afxdp/tx.rs:1767-1773`.
- `1b. Yes.` `current_min_frontier()` loads the active prefix from `next_slot` at `userspace-dp/src/afxdp/types.rs:1703-1705`, initializes `min` to `u64::MAX` at `userspace-dp/src/afxdp/types.rs:1705`, and only replaces it when `v < min` at `userspace-dp/src/afxdp/types.rs:1706-1710`. Idle slots stay `u64::MAX`, so they never lower the min; if every active slot is idle, the function returns `u64::MAX`.
- `1c. Mixed.` It is fetch-add based at `userspace-dp/src/afxdp/types.rs:1657-1658`, and it safely handles 64-slot exhaustion by returning `None` and bumping `register_overflow` at `userspace-dp/src/afxdp/types.rs:1659-1663`. It is not strictly wrap-safe against `u32` overflow; see LOW finding #1.
- `1d. No.` The code does not limit `frontier_slot` to `shared_exact + flow_fair`. Promotion registers on any `queue.flow_fair` queue with a `shared_queue_lease` at `userspace-dp/src/afxdp/tx.rs:5487-5494`. Every exact queue gets a lease in `userspace-dp/src/afxdp/coordinator.rs:1919-1938`, and every exact queue is made `flow_fair` in `userspace-dp/src/afxdp/tx.rs:5572-5588`.
- `1e. Yes.` Bring-up seeding happens only when `v_min < u64::MAX` at `userspace-dp/src/afxdp/tx.rs:5491-5494`.
- `1f. Yes.` Both drains publish through the shared helper: local at `userspace-dp/src/afxdp/tx.rs:2736-2744` and prepared at `userspace-dp/src/afxdp/tx.rs:2958-2961`.
- `1g. Yes.` The helper calls `mark_binding_idle()` when `cos_queue_is_empty(queue)` is true at `userspace-dp/src/afxdp/tx.rs:2758-2762`.

- `2a. Yes.` The yielding `continue` is inside the gate block at `userspace-dp/src/afxdp/tx.rs:1754-1758`, still before `maybe_top_up_cos_queue_lease()` at `userspace-dp/src/afxdp/tx.rs:1767-1773`.
- `2b. Yes on the reviewed path.` If the gate yields, control exits before top-up and before any queue-token mutation in this selector path; the relevant early exit is `userspace-dp/src/afxdp/tx.rs:1756-1758`. Test #16 also confirms both fields stay unchanged; see below.
- `2c. Yes.` Test #16 snapshots `queue.tokens` before the gate at `userspace-dp/src/afxdp/tx.rs:15801-15805`, then asserts both `lease.test_credits_load()` and `runtime.queues[0].tokens` are unchanged at `userspace-dp/src/afxdp/tx.rs:15811-15819`.

- `3a. Yes.` Test #25 spawns 16 threads at `userspace-dp/src/afxdp/tx.rs:16073-16080`, joins them, sorts the returned slots, and asserts equality with `0..N` at `userspace-dp/src/afxdp/tx.rs:16082-16089`.
- `3b. No cleanup hook found.` The plan says teardown should mark slots idle at `docs/pr/829-slice-b/plan.md:90`. In production code, `mark_binding_idle()` is only reached from the post-drain helper at `userspace-dp/src/afxdp/tx.rs:2758-2762`; teardown paths `reset_binding_cos_runtime()` and `release_all_cos_queue_leases()` do not call it at `userspace-dp/src/afxdp/worker.rs:1761-1791` and `userspace-dp/src/afxdp/tx.rs:5909-5938`. This is the blocker in HIGH finding #1.

- `4a. Yes.` `publish_binding_frontier()` uses `store(..., Ordering::Release)` at `userspace-dp/src/afxdp/types.rs:1677-1680`.
- `4b. Yes.` `current_min_frontier()` uses `load(Ordering::Acquire)` for both `next_slot` and each frontier slot at `userspace-dp/src/afxdp/types.rs:1703-1708`.
- `4c. Yes for ordering.` `register_binding()` uses `fetch_add(Ordering::AcqRel)` at `userspace-dp/src/afxdp/types.rs:1657-1658`.

- `5a. Yes.` The env override is read in `main::run()` at `userspace-dp/src/main.rs:89-117`, before coordinator construction at `userspace-dp/src/main.rs:211-215` and before the first thread spawn at `userspace-dp/src/main.rs:245-251`.
- `5b. Yes.` Parse failures hit the `Err(e)` arm, log a warning, and keep the default at `userspace-dp/src/main.rs:98-114`.

- `6. No, test #26 is not strong enough.` The plan says the bound depends on one binding per lease per poll iteration at `docs/pr/829-slice-b/plan.md:209-214` and `docs/pr/829-slice-b/plan.md:390-396`. The test body explicitly narrows itself to "single publish per drain call" at `userspace-dp/src/afxdp/tx.rs:16108-16119`, so a future refactor that batches multiple drain calls in one poll iteration could still pass.

- `7a. No.` Single-owner exact queues are not completely untouched because the current code can still assign them a `frontier_slot`; see MED finding #1.
- `7b. Yes.` Non-flow-fair shared queues still skip registration because promotion only registers when `queue.flow_fair` is true at `userspace-dp/src/afxdp/tx.rs:5487-5494`. Test #23 drives that shape and asserts `frontier_slot == None` / `next_slot == 0` at `userspace-dp/src/afxdp/tx.rs:16005-16023`.
- `7c. Yes structurally.` The `worker.rs` diff only touches test-module initializers and assertions at `userspace-dp/src/afxdp/worker.rs:2349-3314`; the production worker loop and spawn path stay where they were at `userspace-dp/src/afxdp/worker.rs:433-1502` and `userspace-dp/src/afxdp/coordinator.rs:692-789`.

- `8a. Yes.` `publish_binding_frontier_after_drain()` is a shared helper defined once at `userspace-dp/src/afxdp/tx.rs:2748-2764` and called from both drain functions at `userspace-dp/src/afxdp/tx.rs:2743` and `userspace-dp/src/afxdp/tx.rs:2961`.
- `8b. Mostly yes.` The new public / quasi-public entry points are documented: `set_cos_cross_binding_lag_limit_override()` at `userspace-dp/src/afxdp.rs:249-258`, the new lease helpers at `userspace-dp/src/afxdp/types.rs:1649-1703`, and the override reader at `userspace-dp/src/afxdp/tx.rs:3450-3465`. One stale policy comment remains; see LOW finding #2.
- `8c. No new production unwrap hazard found in the reviewed hunks.` The added production code paths in `userspace-dp/src/main.rs:89-117`, `userspace-dp/src/afxdp.rs:249-259`, `userspace-dp/src/afxdp/types.rs:1657-1712`, and `userspace-dp/src/afxdp/tx.rs:1733-1767`, `2754-2763`, `3450-3469`, `5458-5495` all use `if let` / `Option` handling rather than new `unwrap()` calls. The only material code-quality issue I found is the stale comment in LOW finding #2.

- `9a. Yes for local ParkReason wiring.` The new enum variant is defined at `userspace-dp/src/afxdp/tx.rs:4748-4756`, and `count_park_reason()` increments `queue.drop_counters.cross_binding_lag_parks` at `userspace-dp/src/afxdp/tx.rs:4793-4813`. The counter field itself lives at `userspace-dp/src/afxdp/types.rs:1278-1288`.
- `9b. No visible surfacing.` `CoSQueueStatus` has fields for the older park counters but no `cross_binding_lag_parks` field at `userspace-dp/src/protocol.rs:854-869`, and the worker-side status merger only aggregates the older three counters at `userspace-dp/src/afxdp/worker.rs:2136-2144`. That matches the plan's "no new status fields" scope.

## Targeted Validation

- `cargo test 'afxdp::tx::tests::yield_path_does_not_consume_lease_credits' -- --exact` passed.
- `cargo test 'afxdp::tx::tests::concurrent_registration_returns_unique_slots' -- --exact` passed.
- `cargo test 'afxdp::tx::tests::single_poll_iteration_drains_one_binding_for_lease' -- --exact` passed.
- I did not rerun the full `786`-test suite or `make test-failover` locally.
