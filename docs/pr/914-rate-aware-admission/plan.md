# Plan: #914 — Rate-aware per-flow cap on shared_exact

Issue: #914
Umbrella: #911 (validates against #929 same-class harness)

## 1. Problem

`cos_queue_flow_share_limit` at `tx.rs:4075-4104` disables the
per-flow admission cap on `shared_exact` queues:

```rust
if queue.shared_exact {
    return buffer_limit;  // hole: full buffer to any single flow
}
```

This was deliberate (#785 retrospective Attempt A: enabling the
fixed 24 KB cap on shared_exact regressed iperf-c throughput from
22.3 → 16.3 Gbps because the cap was rate-unaware — multi-Gbps
flows hit the cap and tail-dropped).

But the absence of any cap means a single elephant in a
shared_exact queue can occupy 100% of the queue's buffer,
starving every other flow in the same class. This is the
admission-side companion to #911's MQFQ ordering issue — even
with perfect MQFQ vtime ordering (#913 just shipped), if one
flow has 10 MB queued and others have 24 KB, MQFQ still has to
drain the 10 MB before it can finish that flow's contribution.

## 2. Goal

Re-enable per-flow admission on `shared_exact` queues with a
**rate-aware** cap that scales with the queue's configured
`transmit_rate_bytes` and the prospective distinct-flow count.
The cap should be:

- High enough to fit one BDP at the queue's configured rate (so
  TCP can build cwnd to line rate without tail-drops).
- Low enough to prevent one flow from occupying >> 1/N of the
  buffer when N flows are active.

## 3. Approach

### 3.1 Rate-aware cap formula

Replace the unconditional `return buffer_limit` for shared_exact
with:

```rust
if queue.shared_exact {
    // Rate-aware per-flow cap. Goal: each active flow can hold
    // approximately one BDP worth of bytes at the queue's
    // configured rate, while preventing a single flow from
    // exceeding `1/N + headroom` of the aggregate buffer.
    //
    // BDP at queue rate, ~10ms RTT (typical loss-cluster RTT
    // post-shaper) = transmit_rate_bytes × 0.010.
    // For 25 Gbps queue: 25e9/8 × 0.010 = ~31 MB BDP — way more
    // than the queue's typical buffer_limit, so we cap at
    // `buffer_limit / max(prospective_active, 1)` plus a 2x
    // headroom factor for transient bursts.
    let prospective = cos_queue_prospective_active_flows(queue, flow_bucket).max(1);
    // Per-flow share = aggregate / N, with 2× headroom.
    let fair_share = buffer_limit / prospective;
    // BDP-equivalent floor: each flow gets at least enough buffer
    // for one RTT at queue rate / N flows.
    let bdp_floor_per_flow = bdp_floor_bytes(queue.transmit_rate_bytes, prospective);
    return (fair_share * 2)
        .max(bdp_floor_per_flow)
        .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit);
}
```

Where `bdp_floor_bytes` is a new helper:

```rust
const RTT_TARGET_NS: u64 = 10_000_000; // 10 ms

#[inline]
fn bdp_floor_bytes(transmit_rate_bytes: u64, active_flows: u64) -> u64 {
    // Per-flow BDP at queue's rate / active_flows ≈ rate * RTT / N.
    // rate is bytes/sec; convert to bytes-per-RTT.
    let per_flow_rate = transmit_rate_bytes / active_flows;
    (per_flow_rate * RTT_TARGET_NS) / 1_000_000_000
}
```

### 3.2 What this gives at typical configurations

**(Codex R1 caught arithmetic disagreement: my earlier examples
used unrealistic 1 MB buffer values. Recomputed below using the
actual `cos_flow_aware_buffer_limit` output, which expands the
base buffer by `prospective_active` flows.)**

The `buffer_limit` argument passed to
`cos_queue_flow_share_limit` is the OUTPUT of
`cos_flow_aware_buffer_limit` (`tx.rs:4140-4153`). For
non-`flow_fair` queues it returns `base` immediately; otherwise
it returns

`base.max(prospective_active.saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES))
 .min(delay_cap.max(base))`

where `base = queue.buffer_bytes.max(COS_MIN_BURST_BYTES)` (96 KB
floor) and `delay_cap = transmit_rate_bytes × 5 ms`
(`COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS` = 5 ms, NOT 10 ms — the
per-flow `RTT_TARGET_NS` in this PR is a separate constant).
Shared_exact queues are flow_fair, so the early return is not
in play here.

The cluster CoS config (`test/incus/cos-iperf-config.set`) does
NOT set `buffer-size`, so `queue.buffer_bytes = 0` and `base =
COS_MIN_BURST_BYTES = 96 KB`. The effective `buffer_limit`
therefore grows with prospective flows up to `delay_cap`:

- **iperf-b** (10 Gbps): `delay_cap = 1.25 GB/s × 5 ms = 6.25 MB`.
- **iperf-c** (25 Gbps): `delay_cap = 3.125 GB/s × 5 ms = 15.6 MB`.

Re-running the formula `max(fair_share*2, bdp_floor)
.clamp(MIN, buffer_limit)`. Note the **upper clamp to
`buffer_limit`** is load-bearing at low N: the `bdp_floor` can
exceed `buffer_limit` at low active-flow counts, in which case
the per-flow cap is the buffer_limit itself (i.e. the proposed
formula degenerates to "let one flow have the whole queue" — the
admission-side hole this PR is partially closing only kicks in
once there are enough flows to grow `buffer_limit` past BDP):

For each case, `bdp_floor` uses the formula
`(transmit_rate_bytes / active_flows) × RTT_TARGET_NS / 1e9`
with `RTT_TARGET_NS = 10 ms`:

- **iperf-b, N=8**: per-flow rate = 156 MB/s; bdp_floor = 156
  MB/s × 10 ms = **1.56 MB**. `buffer_limit = max(96 KB, 8 × 24
  KB).min(max(6.25 MB, 96 KB)) = 192 KB`. `fair_share = 192 KB /
  8 = 24 KB`, `fair_share*2 = 48 KB`. `max(48 KB, 1.56 MB) =
  1.56 MB`, clamp to `buffer_limit = 192 KB` → **per-flow cap =
  192 KB** (= buffer_limit; one elephant can still fill the
  queue). At low N the bdp_floor exceeds buffer_limit, so the
  formula degenerates to today's behavior. This regime relies on
  `cos_flow_aware_buffer_limit` itself to grow the buffer.

- **iperf-b, N=128**: per-flow rate = 9.77 MB/s; bdp_floor =
  9.77 MB/s × 10 ms = **97.7 KB**.
  `buffer_limit = max(96 KB, 128 × 24 KB).min(6.25 MB) = 3.07 MB`.
  `fair_share = 3.07 MB / 128 = 24 KB`, `fair_share*2 = 48 KB`.
  `max(48 KB, 97.7 KB) = 97.7 KB`, clamp ≥ 24 KB and ≤ 3.07 MB →
  **per-flow cap = 97.7 KB**. ~3.2% of the buffer per flow;
  cwnd builds to 1 BDP, no tail-drops at line rate.

- **iperf-c, N=12**: per-flow rate = 260 MB/s; bdp_floor = 260
  MB/s × 10 ms = **2.6 MB**. `buffer_limit = max(96 KB, 12 × 24
  KB).min(15.6 MB) = 288 KB`. `fair_share = 288 KB / 12 = 24
  KB`, `fair_share*2 = 48 KB`. `max(48 KB, 2.6 MB) = 2.6 MB`,
  clamp to `buffer_limit = 288 KB` → **per-flow cap = 288 KB**
  (= buffer_limit; same degeneration as iperf-b N=8). The
  pre-existing buffer_limit ceiling is the binding constraint.

- **iperf-c, N=128**: per-flow rate = 24.4 MB/s; bdp_floor =
  24.4 MB/s × 10 ms = **244 KB**. `buffer_limit = 3.07 MB`.
  `fair_share = 24 KB`, `fair_share*2 = 48 KB`. `max(48 KB, 244
  KB) = 244 KB`, clamp ≥ 24 KB and ≤ 3.07 MB → **per-flow cap =
  244 KB**.

The 22.3→16.3 Gbps regression in #785 Attempt A was caused by
the FIXED 24 KB cap that ignored both `transmit_rate_bytes` and
`active_flows`. The rate-aware formula above keeps the cap above
per-flow BDP at moderate-to-high N (the cap actively splits the
buffer), while at low N the cap clamps to `buffer_limit` (no
change vs today). The transition point is where `bdp_floor`
crosses below `buffer_limit`. For iperf-b that occurs at N where
`(1.25 GB/s / N) × 10 ms < N × 24 KB` — i.e. roughly
`N > sqrt(1.25e9 × 0.010 / 24000) ≈ 23` flows. Below ~23 flows
on a 10G shared_exact queue, this PR is a no-op; above, it
divides the buffer.

(If the operator raises `buffer-size` so that `buffer_limit`
grows above per-flow BDP at low N, the formula stops degenerating
and the cap actively splits the buffer. Same-class iperf-b
validation on the loss cluster relies on the N=128 case to show
the cap is doing work; N=8 is the negative control and is
expected to match today's mouse-latency p99.)

### 3.2.1 Numerical-overflow safety (Codex R1)

`bdp_floor_bytes(rate, active)` does
`(rate / active) * RTT_NS / 1e9`. At `rate = 25e9 / 8 = 3.125e9
B/s` and `active = 1`, intermediate `3.125e9 * 10e6 = 3.125e16`
fits in u64. At `rate = 100e9 / 8 = 1.25e10` and `active = 1`,
intermediate `1.25e10 * 10e6 = 1.25e17` fits in u64
(u64::MAX ≈ 1.8e19). For 100G+ deployments with long RTT
(50ms), `1.25e10 * 50e6 = 6.25e17` still fits. Use saturating
multiply as belt-and-suspenders:

```rust
#[inline]
fn bdp_floor_bytes(transmit_rate_bytes: u64, active_flows: u64) -> u64 {
    let per_flow_rate = transmit_rate_bytes / active_flows.max(1);
    per_flow_rate
        .saturating_mul(RTT_TARGET_NS)
        / 1_000_000_000
}
```

### 3.2.2 RTT_TARGET scoping (Codex R1)

`RTT_TARGET_NS = 10_000_000` (10ms) is defensible for the
loss-cluster and similar low-RTT deployments (project memory:
~5-7ms post-shaper RTT on the cluster; 10ms gives 1.5× headroom).

For **WAN-scoped deployments** (50ms+ RTT), the cap is too
tight: at 10G shared_exact / N=8, BDP at 50ms is 7.8 MB. With
no operator buffer-size override the buffer_limit ceiling is
192 KB (per §3.2 above), so the cap clamps to 192 KB which is
~40× below the WAN BDP. TCP cwnd would collapse. Operators
running in WAN mode must raise `buffer-size` AND raise the
`RTT_TARGET_NS` (or this PR's cap) before relying on
shared_exact admission.

Plan: scope this PR to the cluster RTT envelope. Document in
the issue / commit message: `RTT_TARGET_NS` is hardcoded for
cluster-scale RTT; WAN deployments need a separate follow-up
that either makes RTT a queue-config attribute or uses an
adaptive measurement (sketch: track per-queue p99 ack-RTT via
sk_buff timestamping; use that to size BDP). Track as #930
(file at impl time).

### 3.3 Per-flow cap interaction with the active-flow count

The existing `cos_queue_prospective_active_flows()` helper
returns `max(active_count + 1, 1)` for the inserting flow.
Rate-aware cap calls this with the new flow's bucket, so the
denominator is correct.

If `active_flows = 1` (only this flow), the cap effectively
becomes `buffer_limit` (whole buffer) which is the same as
today's behavior. As more flows arrive, the cap shrinks
proportionally — exactly the fairness we want.

### 3.4 Existing aggregate cap at site

`cos_queue_admit()` (the actual admission gate) reads the
returned share cap and tail-drops on overflow. No change needed
to the gate site itself; just the helper.

### 3.5 Configuration knob: NONE in this PR

The 10ms RTT target is hardcoded. Tuning it per-queue is a
follow-up if measurements show different rates need different
targets. Project policy is no new config knobs without a
demonstrated need (per `engineering-style.md`).

## 4. What this is NOT

- Not a change to the dequeue (MQFQ) path — that's #913 (shipped).
- Not a change to non-`shared_exact` queues (already have rate-
  unaware cap; not touching that today).
- Not a fix to #927 (was_empty restore) or #926 (demote
  inflation) — those are documented as preexisting.
- Not a fix to #918 (flow cache) — that's stream A, parallel.

## 5. Files touched

- `userspace-dp/src/afxdp/tx.rs`:
  - `cos_queue_flow_share_limit` — new `shared_exact` branch with
    rate-aware formula.
  - New helper `bdp_floor_bytes`.
  - Add `RTT_TARGET_NS` constant.
- New unit tests:
  - `flow_share_limit_shared_exact_scales_with_rate`
  - `flow_share_limit_shared_exact_caps_at_aggregate_for_single_flow`
  - `flow_share_limit_shared_exact_protects_against_dominant_flow`
  - `flow_share_limit_owner_local_exact_unchanged`

## 6. Test strategy

### 6.1 Unit

`cargo build --release` clean. Unit tests above pass.

### 6.2 Cluster validation

Required: #929 same-class harness deployed.

Run same-class N=8 M=10 + N=128 M=10 at iperf-b. Compare:

- BEFORE #914 (baseline): one elephant can occupy ~entire buffer
  at any N; mice tail-drop or queue behind.
- AFTER #914 (per §3.2): N=8 cap = buffer_limit (192 KB) — same
  as baseline, since `bdp_floor` exceeds `buffer_limit` at low N.
  N=128 cap = 97.7 KB — each flow gets ~3.2% of the buffer; mice
  share the rest.

Expected: mouse p99 drops materially **at N=128 same-class
iperf-b** (the binding case). At N=8, this PR alone is not
expected to move the needle — that case is dominated by
`cos_flow_aware_buffer_limit`'s ceiling. The plan §6.3 of #913
explicitly named #914 as the next candidate if iperf-b
same-class still FAILs after #913.

### 6.3 Throughput sanity

Critical regression check: iperf3 -P 12 -t 60 -p 5203 (iperf-c):

- Pre-#914: ~22 Gbps (per project memory).
- Post-#914: target ≥ 22 Gbps. If <22 Gbps, the rate-aware cap
  is too tight; revisit headroom factor.

### 6.4 Edge cases

- **Single flow** (N=1): `prospective_active = 1`, so
  `buffer_limit = max(96 KB, 24 KB) = 96 KB` (or operator-set
  base). `fair_share = buffer_limit`, `fair_share*2 = 2 ×
  buffer_limit`, `bdp_floor = rate × 10 ms` (typically ≫
  buffer_limit), final clamp to `buffer_limit` → cap =
  buffer_limit. No regression vs current.
- **Low flow count (iperf-b N=8)**: per §3.2, cap = buffer_limit
  = 192 KB. The `bdp_floor` (1.56 MB) exceeds `buffer_limit`, so
  the formula degenerates to "let one flow hold the whole queue"
  — same admission behavior as today. The cap only starts
  splitting the buffer once `bdp_floor` drops below
  `buffer_limit` (around N ≈ 23 flows on a 10 G queue).
- **High flow count (iperf-b N=128)**: per §3.2, `buffer_limit =
  3.07 MB`, `fair_share*2 = 48 KB`, `bdp_floor = 97.7 KB` →
  `max = 97.7 KB`, clamp ≥ MIN_SHARE 24 KB and ≤ buffer_limit →
  cap = 97.7 KB per flow. Fairness preserved; saturation drops
  any flow exceeding its share.

## 7. Risks

- **TCP cwnd collapse if cap is too tight.** This is what #785
  Attempt A hit. Mitigation: rate-aware formula sized to fit
  per-flow BDP at queue rate. RTT target of 10ms is conservative
  for the loss-cluster setup (post-shaper RTT measured at ~5-7
  ms, so 10 ms is 1.5x headroom).
- **Burst tail-drops.** Short bursts that exceed the per-flow
  cap will tail-drop. Mitigated by the 2× fair-share headroom
  AND the BDP-equivalent floor.
- **Hot-path cost.** New cap formula = 1 division + 1 mul + 1
  comparison vs the current 0-cost return. Total ~3 ns. Lookup
  is on admission (per packet), not the throughput-critical
  dequeue. Negligible.
- **Static RTT assumption.** 10 ms hardcoded. If the deployment
  has 50 ms RTT, the cap is too tight. Mitigation: make the cap
  ENABLE be queue-config-conditional in a future PR if observed.

## 8. Acceptance

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Plan reviewed by Gemini (HPC + networking-protocols
      expertise on TCP cwnd / BDP); MERGE YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] Unit tests pass.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Gemini adversarial code review: MERGE YES.
- [ ] Cluster validation: same-class N=128 mouse p99 drops
      materially (the binding case per §3.2); same-class N=8
      mouse p99 ≈ baseline (negative control per §3.2;
      `bdp_floor > buffer_limit` so cap clamps to today's
      behavior); iperf-c throughput ≥ 22 Gbps.
- [ ] PR opened, Copilot review addressed.
- [ ] Merged.
