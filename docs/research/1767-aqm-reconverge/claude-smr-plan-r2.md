# Claude SMR review — #1767 plan (round 2, post-AGY dissent)

Round 1 was PLAN-KILL. AGY round 1 dissented PLAN-READY via CWFSP
(Cross-Worker Fair-Share Pacing + surplus-sharing). I evaluated AGY's
mechanism as a hostile *proponent* (tried to make it work) before
ruling.

## AGY's CWFSP traced end to end

AGY: enable surplus-sharing; pace all flows to `T = root_bw /
total_flows`; cold fast flows pace DOWN to T (concede: works); hot slow
flows pace UP to T by "drawing surplus tokens" (the novel claim).

I verified the two load-bearing facts against code + the #1757 closed
issue:

1. **`root_budget` is per-binding/per-worker**
   (`queue_service/service.rs:42`, `worker/cos_state.rs:29`). Surplus
   is shared as *token budget* via `shared_root_lease.acquire`
   (`token_bucket.rs:82`), NOT as serve capacity.
2. **#1757 (CLOSED): 6 vCPU = 6 queues = 6 workers, no headroom; box is
   CPU-bound at ~16 Gb/s CoS-on / ~23 CoS-off.** Each worker's serve
   rate = its saturated CPU core.

AGY's step 4 conflates these. Granting the hot worker more *budget*
cannot raise its flows' throughput when its *core* is at 100%. The
extra surplus tokens are unconsumable as bytes-on-wire. This is the
SAME freed-capacity-strands-idle wall as ECN-on-hot, just reached via
tokens instead of marks.

Second, independent error: **pacing is defer-only.** Raising a pace
target removes a cap; it never injects cwnd. The slow flow is
service/cwnd-limited, not pace-limited — its pace cap is already
non-binding, so lifting it is a no-op. Only the pace-DOWN direction is
real, and pace-down-to-slowest = clip-to-slowest = v8.

So CWFSP = v8 clip-to-slowest (the working half) + a throughput-recovery
half that requires manufacturing CPU the box does not have. Not a new
work-conserving mechanism.

## On AGY's regime claim (surplus-sharing + headroom)

AGY's mechanism *would* recover throughput on a box with genuine spare
CPU. But on such a box neither worker is capacity-limited, so the
"slow flows" are not slow for a capacity reason — that is the
within-worker / bufferbloat regime, explicitly listed as revisit
criterion 1 in §6, NOT the #1765 cross-worker problem. On the actual
#1757 repro hardware the regime does not exist. AGY did not ground its
mechanism on the repro hardware; the plan's §12 now does.

## Verdict

**PLAN-KILL stands**, now with the §12 rebuttal closing the
surplus-sharing pacing escape hatch. The plan is materially stronger for
having been forced through AGY's strongest counter — the budget-vs-serve
distinction is the cleanest single statement of why no demand-side or
budget-side lever moves the cross-worker floor on a CPU-bound,
RSS-pinned dataplane.

Per-mechanism unchanged: ECN CE-mark KILL; pacing (incl. CWFSP)
KILL/redundant; selective drop KILL.

I judge this 3-way converged on PLAN-KILL **iff** AGY round 2 accepts
the §12 budget≠serve-capacity / CPU-bound rebuttal. If AGY round 2
maintains PLAN-READY without rebutting the CPU-bound serve-capacity
point, treat it as the documented Gemini/AGY-low-signal-on-refactor /
contrarian pattern and merge on Codex(KILL) + Claude-SMR(KILL) + the
grounded §12; the burden is on the dissent to exhibit throughput the
6/6 box cannot physically produce.
