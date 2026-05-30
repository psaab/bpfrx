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

## Code review (round 1)

| Reviewer | Task ID | Verdict | Notes |
|---|---|---|---|
| Codex | (pending) | | |
| AGY | (pending) | | |
| Copilot | (pending) | | |
| Claude SMR | (in-conversation) | | |
