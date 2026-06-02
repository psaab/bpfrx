# #1748 R1 spike — established-flow ntuple re-pin: PASS

Recorded 2026-06-02 directly on `loss:xpf-userspace-fw0` (master @ `ecdc16f2e`,
post-#1745, equal-flow-enforcement OFF / clean fixture). This is the R1 gate the
converged research plan (`research-plan.md` §8) required before any controller
code: *does reactive established-flow placement actually beat the per-flow CoV
floor, or did #1203's 49–55% prove it can't?*

## Verdict: PASS (proceed to controller design R2–R6)

Established-flow **mid-flight** exact-5-tuple ntuple re-pin on `ge-0-0-1`
(forward/data direction of a `-P12 -p5210` push) dropped per-flow CoV from
**16.8% → 2.3–4.2%** while **raising** aggregate **16.24 → 17.5–17.8 Gb/s**.

## Method

- Single 70 s `iperf3 -c 172.16.80.200 -P 12 -t 70 -i 5 -p 5210` push (client
  `10.0.61.102` on LAN `ge-0-0-1`/reth1.0 → server on WAN reth0.80).
- Flows established on their natural RSS queues for ~14 s; then **mid-flight**
  enumerated the 13 client sockets (`ss -tn | grep :5210`, 12 data + 1 control)
  and installed 13 exact rules
  `ethtool -N ge-0-0-1 flow-type tcp4 src-ip 10.0.61.102 dst-ip 172.16.80.200
  src-port <p> dst-port 5210 action <i mod 6>` — round-robin across all 6 RX
  queues. No daemon code; manual ethtool only.
- Measured per-stream CoV from `iperf3 -i5` intervals: a pre-re-pin baseline
  interval and three post-re-pin settled intervals.

## Results

| Phase | per-worker `{aᵢ}` on ge-0-0-1 | CoV | aggregate |
|---|---|---:|---:|
| Baseline (natural RSS, t10–15) | `[2,2,1,1,4,2]` | **16.8%** | 16.24 G |
| Post-re-pin (t45–50) | `[2,2,2,2,2,2]` | **2.3%** | 17.74 G |
| Post-re-pin (t55–60) | `[2,2,2,2,2,2]` | **3.8%** | 17.78 G |
| Post-re-pin (t65–70) | `[2,2,2,2,2,2]` | **4.2%** | 17.52 G |

Per-stream rates collapsed from a 1.02–1.73 G spread to 1.36–1.57 G.

## What this resolves

1. **Placement mechanism is NOT floor-bound.** 2.3–4.2% CoV beats #1203's
   49–55% by ~12×. Reproduces #789's manual 3.8% — and crucially does so for
   **established-flow re-pin** (mid-flight), not just connect-time placement.
   The #1203 49–55% was a count-blind controller defect (it flattened flow
   *count* and deferred byte-rate-aware selection), not a physics ceiling.
2. **Aggregate is preserved/improved**, unlike the #1746 cap (which trades
   throughput for fairness). Per-flow exact rules used all 6 queues evenly,
   fixing the #789 experiment's bitmask quirk that idled 3 queues and cost 24%.
   This is the only lever that improves the structural ceiling `Cstruct` rather
   than clipping within it.
3. **Wall B (HA session-strand) stays falsified in practice** — the re-pinned
   flows forwarded correctly on their new workers with no connectivity loss
   (the pre-replicated session substrate, research-plan §0).

## Costs / risks surfaced (controller must address — R2–R6)

- **R3 transient (measured):** the whole-run summary showed **7601 retransmits**
  — the reorder burst from moving all 12 flows simultaneously mid-flight. A
  production controller MUST move flows incrementally with hysteresis (one/few
  per rebalance tick, ≪1 Hz rule churn) to amortize this; bulk re-pin is a
  spike artifact, not the intended operating mode.
- **R2 reverse direction** not exercised (push test; forward-only re-pin
  suffices for the push CoV symptom but `-R`/bidirectional needs reverse rules).
- **R4 HA mirroring, R5 rule-cap/cost/hysteresis, R6 selection policy** remain
  open as designed.

## Cleanup verified

All 13 rules deleted, `ethtool -K ge-0-0-1 ntuple off`, 0 rules remaining.
Cluster returned to clean master fixture (equal-flow OFF).
