# Codex hostile PLAN review — Tier B triage v1

Task ID: task-mossxgbh-x4l5jv
Codex session ID: 019df8d2-65da-7c52-b716-03b62ec5fa70

---

**Overall Verdict: PLAN-NEEDS-MAJOR**

I could not read live GitHub issue bodies/comments: every `gh issue view` call was blocked by the sandbox's network restriction. I reviewed the plan, current `origin/master` at `dab78ef6`, and checked-in design/finding docs. The branch is doc-only over `origin/master`.

**Blocking Finding**

`#837` should not be closed as wontfix on the evidence in the repo. The strongest local source says the opposite: `docs/pr/838-afd-lite/findings.md:142` explicitly says not to retire `#837`, because it preserves the larger redesign context for true cross-binding MQFQ. The `#838` plan also defers cross-binding shared-exact AFD/MQFQ work back to `#837`.

A productive framing exists: keep `#837` open as a parked design/research issue gated on measurement and prerequisites, not as an implementation-ready ticket. The plan's close-as-wontfix recommendation does not survive the repo evidence.

**Major Reframe**

`#917` did ship the functional V_min mechanism, lag throttle, hard cap, and telemetry, but not the literal early "global atomic on `SharedCoSQueueLease` + CAS update" design.

Current master has:

- `queue_vtime_floors` in `cos_state.rs:13`
- per-worker padded atomic slots in `shared_cos_lease.rs:49`
- Release-store publication and min-scan V_min, not CAS-global update: `shared_cos_lease.rs:95`
- lag throttle and hard-cap override in `v_min.rs:142`
- telemetry counters in `protocol.rs:1230`

So `#917` can close as shipped, but the closure must say the original CAS/global-atomic sketch was superseded by the shipped per-worker slot-floor design. As written, the plan overclaims.

`#793` has the same problem. The early Phase 4 design did include global `v_min`, CAS, and empirical lag-threshold tuning: `docs/pr/785-umbrella/perf-fairness-plan.md:235`. `#917` narrowed that into a const-threshold v1 and even notes later configurability separately: `docs/pr/917-mqfq-phase4/plan.md:352`. Close `#793` only as superseded/absorbed by `#917`, not as a literal duplicate whose full original tuning scope landed.

**Per-Issue Verdicts**

| Issue | Verdict | Reason |
|---|---|---|
| `#786` | REFRAME-NEEDED | Closing the research tracker is probably fine, but the rationale must account for `#837` staying open and for `#793/#917` being superseded, not literally implemented as first sketched. |
| `#793` | REFRAME-NEEDED | Duplicate/superseded by `#917` is defensible; "CAS/global atomic/T tuning shipped" is not. |
| `#794` | AGREE | Deferred close is consistent with AFD being optional/pathological-flow work, with no current trigger shown. |
| `#837` | REJECT | Do not close as wontfix. Keep open, parked and gated, as the repo explicitly preserves it for larger cross-binding redesign. |
| `#917` | REFRAME-NEEDED | Functional work shipped, but closure must describe the slot-floor implementation, not claim literal CAS-global V_min. |
| `#936` | AGREE | Keep open. Post-`#917` findings still identify residual RSS-driven fairness gap needing `#936` or `#937`. |
| `#937` | AGREE | Keep open. It is an alternative to `#936`, not a duplicate: redirect/rebalancing attacks aggregate loss differently than service throttling. |

Net: revise the plan before using it to close issues. The main required change is to keep/reframe `#837`; the secondary required change is to stop presenting `#793/#917` as literal CAS-global V_min completion.

---

# Gemini Pro 3 review — failed

Task ID: task-mossxka2-edcu43
Status: rate-limited (4th consecutive Gemini failure today)
