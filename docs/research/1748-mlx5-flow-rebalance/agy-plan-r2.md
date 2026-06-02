# AGY adversarial plan-review — #1748 r2

Job: adversarial-review-mpw7hewk-aicdmn
Verdict: **PLAN-NEEDS-WORK (overturn correct, R1-spike gate)**

## Summary

AGY ratifies its own r1 Wall-B overturn (verified again: forward+reverse
replicas pre-installed on all sibling workers; active gate is per-RG not
per-worker; safe landing with single flow-cache miss). Concedes "no code
changes needed, just turn it on" was too strong, and engages R1-R6.

### R1 — NOT floor-bound (the smoking gun)
> "Phase 0 manual experiment validated mechanism: CoV 62.5% -> 3.8% with
> hand-installed rules" (pr-history.md:19247).

Perfect placement is NOT floor-bound by physics; manual balance hits 3.8%
(well under the 20% gate). The #1203 controller's 49-55% was a CONTROLLER
DEFECT, specifically count-blindness:
- #1203 flattened per-queue FLOW COUNT only (pr-history.md:19239), ignoring
  byte-rates. An even-count partition (2,2,2,2,2,2) still has high CoV if one
  flow is a 3 Gb/s elephant and its queue-mate is a mouse.
- Byte-rate-aware candidate selection was DEFERRED to Phase 2 because it added
  a per-packet cache-line write to the worker hot path (pr-history.md:19283).

Beat-the-floor is possible ONLY with byte-rate-aware candidate selection,
which re-opens the deferred hot-path-telemetry-write cost. The R1 manual spike
is the correct cheap gate.

### R2 — reverse-flow asymmetry
ntuple exact-5-tuple is directional. Forward-only re-pin balances push tests;
`-R`/bidirectional needs a second reverse-companion rule -> 2 rules/flow ->
512-flow effective cap + doubled firmware latency.

### R3 — transient window
~1 ms firmware write; split arrival -> reordering/dup-ACK/fast-retransmit +
cold-cache miss on new worker. HA substrate prevents resets, but twitchy
steering degrades aggregate. Hysteresis mandatory; exclude transient window
from steady-state CoV.

### R4 — HA double-homing
Rule must land on matching queue index on BOTH nodes; controller must mirror
every ethtool -N to the standby or a failover steers the flow back to default
RSS (cold-cache + imbalance). Plan lacks an HW-rule replication protocol.

### R5 — rule cap / cost / contention / thrash
~1 ms/rule synchronous (100 rules = 100 ms thread block); ethtool churn
saturates control socket; #840 proved a thrashing rebalancer DEGRADES fairness
(37.7% vs 18.5%). Hysteresis + long dwell + <<1 Hz cadence mandatory.

### R6 — selection policy
Need a stable-flow gate (flow_age>=3s, last_seen<1s) + an oscillation-free
move-selection (flow whose transfer most flattens per-worker byte-rate). Plan
defers the math.

## Convergence path
Run R1 manual spike: under -P12 -p5210, identify {a_i}, manually ethtool -N
the elephants to idle queues to force a 2,2,2,2,2,2 partition, measure 60 s
steady-state CoV. If CoV < 10% (matching Phase-0 3.8%), Path 2 physically
viable on current master -> resolve R2-R6. If CoV > 20% after balanced
placement, placement is floor-bound -> permanent PLAN-KILL.

VERDICT: PLAN-NEEDS-WORK (overturn correct, R1-spike gate)
