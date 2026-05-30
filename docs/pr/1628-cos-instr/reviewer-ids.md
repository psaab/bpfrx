# #1628 reviewer task-id ledger

Per `feedback_codex_session_loss_continuation`: record every Codex/AGY/Gemini
task-id here so a continuation can fetch results by id after session-state loss.

## Plan review (round 1)

| Reviewer | Task ID | Verdict | Notes |
|---|---|---|---|
| Codex | task-mprtl981-wg7p3w | PLAN-NEEDS-MAJOR | r1 plan; 7 findings, borderline KILL |
| AGY | adversarial-review-mprtlgg5-txzcuz | PLAN-NEEDS-MAJOR | r1 plan; convergent w/ Codex |
| Claude SMR | (in-conversation) | PLAN-NEEDS-MAJOR | concur: last_epoch freeze + worker_fair_share gap + semantic pollution |

### r1 convergent fatals (all addressed in plan v2)
1. `*_last_epoch` swap broken: transient-sampling loss + freezes during Phase-2 lock-in (refill at mod.rs:793 never runs when pass1_remaining stays >0). → monotonic `_total`.
2. `worker_fair_share` not diagnosable by waterfill-only counters (lives in v8 lease: shared_cos_lease/mod.rs:407, rotate_epoch_v8.rs:306, acquire_v8:1175). → add 1 narrow v8 counter OR drop the claim. v2: drop the claim, keep scope worker-local.
3. per-interface considered/honored SUMMED across workers hides fragmentation (6×2=12 looks healthy). → per-worker semantics required, not sum.
4. `skipped_not_backlogged` summed → globally-empty vs fragmented-active look identical; noisy. → cut or make per-worker reason-split.
5. semantic pollution: don't add scheduler counters to CoSQueueDropCounters. → new CoSQueueWaterfillCounters struct on CoSQueueTelemetry.
6. Phase-1 honor return is mod.rs:924 not 912.
7. plain u64 correct (build_worker_cos_statuses runs ON the worker thread, published via ArcSwap — no live cross-thread read); fix the rationale wording.
8. phase1_budget_exhausted only fires on first queue crossing boundary; larger queues after it silent (Codex #3).

## Plan review (round 2 — v2 @ 9aa961aac)

| Reviewer | Task ID | Verdict | Notes |
|---|---|---|---|
| Codex | task-mpru36mt-9tyfq5 | PLAN-NEEDS-MAJOR | 2 major (overclaim) + 1 minor (borrow); redesign validated |
| AGY | adversarial-review-mpru3d7g-lmqxlg | PLAN-NEEDS-MAJOR | 4 findings, convergent w/ Codex |
| Claude SMR | (in-conversation) | PLAN-NEEDS-MAJOR | concur; counters correct, framing overclaims |

### r2 convergent findings (all addressed in plan v3)
- F1 borrow shape (Codex-minor + AGY-major): count_waterfill_event(&mut root,..) won't compile while queue=&mut root.queues[idx] is live. → inline queue.telemetry.waterfill_counters.X += 1; root counters via disjoint field borrow.
- F2 summing masks single-worker lock-in (both): summed waterfill_epochs across 6 workers drowns one frozen worker. → add coordinator MIN-aggregation waterfill_min_epochs_per_worker (follows the existing .max() pattern at coordinator/mod.rs:927).
- F3 signature not unique (both): healthy asymmetric/idle load → same phase2>0/phase1=0/epochs-frozen footprint. → reframe as evidence COMBINED with queued_bytes>0 + *_starvation_parks; soften test assertions.
- F4 eligible_visits misses token-parked-but-backlogged queues (AGY): parked → !runnable → skipped at gate → low eligible_visits reads as "idle". → document eligible_visits + existing root/queue_token_starvation_parks pairing distinguishes starved-park from genuinely-idle; do NOT add a counter (parks already exist).
- Confirmed OK by both: dedicated struct placement, monotonic redesign, eligible_visits write location (after eligibility/head, before token gate), cutting skipped_not_backlogged.

## Code review (round 1)

| Reviewer | Task ID | Verdict | Notes |
|---|---|---|---|
| Codex | (pending) | | |
| AGY | (pending) | | |
| Copilot | (pending) | | |
| Claude SMR | (in-conversation) | | |
