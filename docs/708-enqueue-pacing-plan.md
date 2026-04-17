# #708 enqueue-side pacing — architect plan

Status: plan. Implementation lands in a follow-up PR against the slice
defined in [§4](#4-narrow-write-scope-for-the-implementor). This is a
docs-only change.

## 1. Problem restatement

The CoS shaper paces the **dequeue** side (root + per-queue token
buckets). Enqueue is unpaced: a TCP cwnd worth of bytes from one sender
can land back-to-back into a single SFQ bucket in one tick, faster than
the ECN marks from the previous tick have propagated back through the
ack clock. Under multi-flow concurrency those microbursts collide in
the buffer and overflow per-flow admission (#705) even when the
steady-state aggregate is well under rate.

Post-#728 baseline on 16-flow / 1 Gbps exact / ECN end-to-end:

| Counter | Value / 30 s |
|---|---|
| Rate ratio (max/min) | 1.24× |
| `flow_share_drops` | 75–156 |
| `buffer_drops` | 0 |
| `ecn_marked` | ~100 k |
| iperf3 retransmits | 114–136 k |
| cwnd steady state | 8–17 KB |

ECN is doing the fairness work. The 1.24× ratio is close to ideal. The
residual `flow_share_drops` are a two-orders-of-magnitude reduction
from pre-#728. Any pacing plan attacks the **residual microbursts that
ECN can't catch in time**, not the fundamental fairness problem. That
scoping matters for §3 — several options in the issue are already
implicitly landed.

## 2. Options at a glance

| Opt | Changes | Size | Risk | Attacks on post-#728 baseline |
|-----|---------|------|------|-------------------------------|
| A   | Per-flow token bucket on enqueue | ~500+ LOC, per-flow state + backpressure | High | Unknown — requires per-flow estimator + defer queue |
| B   | Per-SFQ-bucket token bucket | ~150 LOC, 2–3 files | Med | The residual ~100 share_drops/30s microburst window |
| C   | BQL-style adaptive admission cap | ~400 LOC + feedback loop | High | Aggregate drain-rate skew (none observed today) |
| D   | ECN marking on admission | 0 LOC — **already landed** | — | — |
| E   | Batch+flush redirect coalescing | ~200 LOC in binding hot path | Med | Producer-side latency jitter (overlaps #709) |

Verdicts:

- **A** — honest per-flow pacing is a large surface: per-flow state
  lookup, a per-flow token bucket keyed by the 5-tuple, backpressure
  or a deferred-packet queue with a timer wheel. Too much at once for
  a residual that is already within a factor of 2× of the fairness
  knee.
- **B** — narrowest slice that reuses `flow_bucket_bytes` from #711.
  One new array `flow_bucket_tokens: [u64; COS_FLOW_FAIR_BUCKETS]` +
  one shared `last_refill_ns`. Token refill is the same primitive the
  root/queue shapers already use.
- **C** — introduces a control loop (adjust cap based on drain rate)
  on top of a queue that is already ECN-stable. Negative value for the
  baseline we have.
- **D** — **effectively landed via #727/#728.** ECN marking at
  admission is the current dominant fairness signal (100k marks/30s).
  Treating this as a new scope for #708 is double-counting.
- **E** — overlaps #709 (redirect-hotspot work). Defer to #709's
  decision tree; don't solve the same problem twice.

## 3. Recommendation

**Pick Option B, scoped as a measurement-first single slice.** Land
per-SFQ-bucket token pacing as an admission gate that fires **strictly
after** the ECN marker, with a new `admission_pacing_drops` counter.
If the counter stays near zero under load, we close #708 as
"implemented, dormant on current workload" and move on — the slice has
bought us honest data.

Rationale. The post-#728 baseline shows ECN carrying the fairness
signal (100k marks/30s) against a residual 75–156 flow_share_drops and
114–136 k sender-reported retransmits. Analytical framing on the
retrans-vs-drop gap: Linux TCP increments `RetransSegs` (and by
extension iperf3's `sender.retransmits`) on every fast-retransmit
entry AND on every segment pulled from the retrans queue during
recovery. A single CE mark triggers `tcp_enter_recovery`, which
retransmits the head of the write queue on its way into cwnd-halving.
At 100k CE marks / 30 s, seeing 114–136 k retrans is exactly the shape
we expect from ECN-induced recovery entries, not from 100k wire-loss
events. That means **most of the retrans count is ECN working, not a
signal pacing can fix**. We cannot confidently predict that Option B
will move retrans by more than single-digit percent, and we should say
that up front.

Ordering is the load-bearing choice, and it's the top-of-mind risk:
the pacing gate sits *after* `apply_cos_admission_ecn_policy` in
`enqueue_cos_item`, using the same `flow_bucket` and `buffer_limit`.
For ECT packets the marker runs first; the packet takes the mark and
proceeds through pacing. If pacing tokens are insufficient the packet
drops as `admission_pacing_drops`. The sender sees **both** the CE
mark on the previously-admitted packet and the tail-drop on this one —
consistent signals. If we put pacing *before* the marker, ECN becomes
dead code because pacing rejects the packet the marker would have
marked. Reverse ordering also means non-ECT traffic gets paced at the
same threshold as ECT traffic, which is correct behaviour for a
defensive microburst gate and preserves the marker's "mark only if we
will admit" invariant from #718.

What B does NOT fix:
- Does not reduce the ~100k ECN-induced retrans count meaningfully.
- Does not address CPU-scheduler jitter (#712) or owner-hotspot
  drain-p99 (#709).
- Does not help non-flow-fair queues; `flow_fair=false` returns early
  from the pacing gate, same shape as existing admission.

Expected metric movement (predictions to falsify):
- `flow_share_drops` 75–156/30s → ≤ 30/30s (absorbs microbursts
  before they hit the flow-share cap).
- `admission_pacing_drops` ≥ 50/30s on the same run (otherwise the
  gate is dormant — close as wontfix).
- Rate ratio: no meaningful movement expected (1.24× stays ±0.05).
- iperf3 retransmits: no confident prediction. If the 100k signal is
  overwhelmingly ECN-induced recovery, we expect ≤ 10% movement.
- 5202 shared-queue median latency: ±5%.

If `admission_pacing_drops` lands at zero in the live run, **that is a
valid outcome** — we will have pinned that the residual is not
microburst-driven, closed the hypothesis, and redirected effort to
#709 / #712 via one narrow PR.

## 4. Narrow write scope for the implementor

Exact files. Keep the slice tight.

1. `userspace-dp/src/afxdp/types.rs` — `CoSQueueRuntime` gains:
   - `flow_bucket_tokens: [u64; COS_FLOW_FAIR_BUCKETS]` — per-bucket
     token count in bytes. Inline array, same shape as
     `flow_bucket_bytes`. Initialised to `0` by
     `Default::default()` / construction sites.
   - `flow_bucket_last_refill_ns: u64` — **single shared**
     monotonic ns timestamp across all buckets on the queue. Rationale:
     per-bucket timestamps cost another 8 KB per queue
     (1024 × 8 B) and provide no correctness gain when the refill
     formula is `elapsed_ns × per_bucket_rate` against a shared
     `now_ns`. The only thing per-bucket timestamps buy is avoiding
     shared credit across buckets, which we already avoid via the
     per-bucket `flow_bucket_tokens` cap.
   - `CoSQueueDropCounters` gains:
     `admission_pacing_drops: u64`.
   - Construction sites in `worker.rs` add the initialiser entries.
2. `userspace-dp/src/afxdp/tx.rs`:
   - Add `const COS_FLOW_BUCKET_BURST_NS: u64 = 1_000_000;` — burst
     cap of 1 ms worth of per-bucket rate, matching the order of the
     #717 latency-envelope clamp. One-line justification in a comment
     above the const.
   - New helper
     `refill_cos_flow_bucket_tokens(queue: &mut CoSQueueRuntime,
     flow_bucket: usize, now_ns: u64)` that:
     - Short-circuits if `!queue.flow_fair || queue.transmit_rate_bytes == 0`.
     - Computes `per_bucket_rate = queue.transmit_rate_bytes /
       cos_queue_prospective_active_flows(queue, flow_bucket).max(1)`.
     - Refills `flow_bucket_tokens[flow_bucket]` via the same
       `elapsed_ns × rate / 1e9` u128 math the root/queue shaper uses,
       capped at `per_bucket_rate × COS_FLOW_BUCKET_BURST_NS / 1e9`.
     - Advances the shared `flow_bucket_last_refill_ns` on refill.
   - New helper
     `cos_flow_bucket_pacing_exceeded(queue: &CoSQueueRuntime,
     flow_bucket: usize, item_len: u64) -> bool` — returns
     `flow_bucket_tokens[flow_bucket] < item_len`. Always returns
     `false` when `!queue.flow_fair`.
   - In `enqueue_cos_item` (currently lines ~4197–4230), after
     `apply_cos_admission_ecn_policy`, before the
     `if flow_share_exceeded || buffer_exceeded` branch:
     - Call `refill_cos_flow_bucket_tokens(queue, flow_bucket, now_ns)`.
     - Compute `pacing_exceeded = cos_flow_bucket_pacing_exceeded(queue, flow_bucket, item_len)`.
     - Expand the drop branch: if any of `flow_share_exceeded`,
       `buffer_exceeded`, `pacing_exceeded` is true, attribute to the
       highest-priority reason in order: `flow_share` →
       `pacing` → `buffer`. Rationale: flow_share stays highest-
       priority because that was the #710 ordering rule for
       root-cause attribution. Pacing sits above buffer because
       pacing *is* the root-cause of buffer-side microbursts on
       flow-fair queues.
   - On admit, decrement `flow_bucket_tokens[flow_bucket]` by
     `item_len` via `saturating_sub`.
3. `enqueue_cos_item` signature already takes enough state. `now_ns`
   needs threading into the callee; the existing admission path is
   called at a point where `monotonic_nanos()` has already been
   evaluated in the caller (e.g. `drain_shaped_tx` carries it). If a
   call site does not have `now_ns` in hand, read it once at the top
   of `enqueue_cos_item` and pass down — same pattern
   `maybe_top_up_cos_queue_lease` uses.
4. `userspace-dp/src/protocol.rs` / `CoSInterfaceStatus` — add
   `admission_pacing_drops: u64` alongside the existing
   `admission_flow_share_drops` / `admission_buffer_drops` /
   `admission_ecn_marked` fields.
5. CoS CLI renderer (the same path that emits the `Drops:` line from
   #724) — add ` pacing=<n>` in the existing Drops line. Example:

   ```
   Drops: flow_share=30  pacing=820  buffer=0  ecn_marked=104012
   ```

6. `pkg/api` Prometheus collector — add
   `xpf_cos_admission_pacing_drops_total{ifindex, queue_id}` alongside
   the existing admission counters.
7. `docs/cos-validation-notes.md` — new row in the decision-tree
   table for the `pacing` column, and an "interpreting
   admission_pacing_drops" paragraph mirroring the existing
   `flow_share` / `buffer` / `ecn_marked` prose. This is an
   Architect-owned doc edit landing in the implementor's PR.
8. Tests in `userspace-dp/src/afxdp/tx.rs` tests module:
   - `refill math` — small elapsed_ns at high rate yields expected
     token count (u128 intermediate).
   - `burst cap` — sitting idle across a large elapsed does not
     exceed `per_bucket_rate × COS_FLOW_BUCKET_BURST_NS / 1e9`.
   - `ordering vs ECN` — ECT packet hits CE mark AND proceeds through
     pacing; non-ECT packet hits pacing directly. Assert
     `admission_ecn_marked` bumps on the ECT admission path and
     `admission_pacing_drops` bumps on the pacing-drop path with
     correct ordering (both counters can bump on different packets of
     the same flow; assert by counter deltas, not by interleaving).
   - `non-flow-fair degenerate case` — `flow_fair=false` queue does
     not engage pacing regardless of rate / item_len.
   - Counter-factual pin — a test that reconstructs the
     pre-fix formula (no pacing gate) and asserts
     `flow_share_drops` would have bumped on the test fixture,
     so the gate provably moves drops into the `pacing` column.

## 5. Invariants the implementor must preserve

- **ECN ordering is load-bearing.** The pacing gate must NOT trigger
  before the ECN marker for ECT packets. Ordering in
  `enqueue_cos_item` is: `apply_cos_admission_ecn_policy` →
  `refill_cos_flow_bucket_tokens` → `cos_flow_bucket_pacing_exceeded`
  → drop-reason attribution. The marker's #718 "mark only if
  admitted" invariant stays correct as long as the marker does not
  itself see the pacing decision.
- **No allocations on the hot path.** `flow_bucket_tokens` lives
  inline in `CoSQueueRuntime` alongside `flow_bucket_bytes`. No
  `Vec::push`, no `HashMap::entry`, no `Box::new`.
- **Token refill math is branchless and clock-syscall-free.** Use the
  `now_ns` already passed into `enqueue_cos_item`. No
  `Instant::now()`, no `clock_gettime` fresh read.
- **Single source of truth for per-bucket rate.**
  `per_bucket_rate = queue.transmit_rate_bytes /
  cos_queue_prospective_active_flows(queue, flow_bucket)` — reuse
  the existing `cos_queue_prospective_active_flows` helper so the
  denominator stays in lockstep with `cos_queue_flow_share_limit` and
  `cos_flow_aware_buffer_limit`. #704 was caused by exactly this
  class of duplication drift.
- **Burst cap bound.** `flow_bucket_tokens` is clamped to
  `per_bucket_rate × COS_FLOW_BUCKET_BURST_NS / 1e9`. No "tokens
  accumulate forever while the queue is idle" path.
- **Drop-newest policy.** The dropped packet is the one that failed
  the token check, not the head of the bucket. Document the reasoning
  at the drop site per `engineering-style.md` "drop-newest unless
  specific reason otherwise".
- **Non-flow-fair queues unchanged.** `flow_fair=false` short-circuits
  out of both helpers; best-effort queues and pure-rate-limited
  queues keep identical behaviour.
- **Const-asserts pin shape drift.** `const _: () = assert!
  (COS_FLOW_BUCKET_BURST_NS <= COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS)` so
  the pacing burst cannot exceed the latency-envelope clamp #717 set.
- **Counter attribution priority is fixed.** `flow_share` >
  `pacing` > `buffer`. Do not reorder without a separate PR.
- **No new cross-worker state.** Per-queue runtime is single-writer
  (the owner worker); `u64` fields are sufficient, no atomics.

## 6. Acceptance criteria — validating against the live lab

Methodology anchor: [`cos-validation-notes.md`](cos-validation-notes.md)
§ "How to read admission drop counters live". The implementor PR adds
a new sub-section "Interpreting admission_pacing_drops" mirroring the
existing prose.

Pre-fix baseline (captured on 2026-04-17 post-#728, §1 above):

| Counter | /30 s |
|---|---|
| `flow_share_drops` | ~100 |
| `buffer_drops` | 0 |
| `ecn_marked` | ~100 k |
| iperf3 retransmits | ~120 k |
| Rate ratio | 1.24× |
| cwnd steady state | 8–17 KB |

Post-fix expected (run against the `test/incus/cos-iperf-config.set`
fixture, 16-flow 30 s iperf3 on 5201 per the existing recipe):

1. `admission_pacing_drops` on queue 4 is **≥ 50 / 30 s** on the
   16-flow run. If it lands at zero, the plan says "close #708 as
   implemented-dormant" — that is an acceptable outcome but must be
   reported honestly in the PR body.
2. `flow_share_drops` on queue 4 drops from ~100/30 s to **≤ 30/30 s**
   — pacing absorbs microbursts before they hit the flow-share cap.
3. `buffer_drops` remains at **0**.
4. `ecn_marked` stays within **±20%** of the 100k baseline. A large
   swing either direction means the ordering change is mis-interacting
   with the marker and the invariant in §5 is violated.
5. iperf3 `sender.retransmits` movement is **reported but not
   required to move**. If the PR claims it moved, the body must
   include before/after numbers per `engineering-style.md`. If it does
   not move, say so explicitly — the plan predicted this.
6. Rate ratio (max/min per-flow) remains within **1.0×–1.5×**. No
   regression from the post-#728 1.24× baseline.
7. 5202 (10 Gbps shared-exact) and 5203 (100 Mbps) median latency and
   aggregate throughput within **±5%** of the pre-fix run. Same
   iperf3 invocations.
8. The new CLI column renders under `show class-of-service interface`
   with the correct zero vs. non-zero attribution. Zero on idle
   queues; non-zero on queue 4 during load.
9. Prometheus scrape exposes
   `xpf_cos_admission_pacing_drops_total{ifindex, queue_id}` and
   `promtool check metrics` on the scrape is clean.
10. Unit tests §4 step 8 all pass. The counter-factual pin in
    particular must actually reconstruct the pre-fix formula — a test
    that asserts `0 == 0` before calling into the gate is not a
    regression pin.

Mid-test read command (same shape as existing methodology):

```bash
incus exec loss:cluster-userspace-host -- \
  iperf3 -c 172.16.80.200 -P 16 -t 30 -p 5201 -i 0 >/dev/null 2>&1 &
sleep 10
incus exec loss:xpf-userspace-fw0 -- \
  /usr/local/sbin/cli -c "show class-of-service interface"
wait
```

## 7. Out-of-scope / deferred

Explicitly not in this slice. Each becomes a new issue on merge if
the counter signal points at it.

- **Option A per-flow pacing.** Deferred because per-flow state +
  backpressure is a significant surface. Revisit only if B's counter
  shows ≥ 100k pacing drops/30 s — i.e. per-bucket pacing runs out of
  resolution and per-flow tokens are needed. Follow-up issue title:
  *"userspace-dp: per-flow token-bucket pacing with deferred-admit
  timer wheel"*.
- **Option C BQL-style adaptive admission cap.** Deferred; adds a
  feedback loop on top of an ECN-stable queue. Follow-up issue title:
  *"userspace-dp: drain-rate-adaptive admission cap (BQL analog)"*.
- **Option D ECN marking on admission.** **Not a new scope** — already
  landed via #727 / #728. If we want to tune the mark fraction
  (currently 1/5 of share_cap), that is a separate tuning PR and
  should cite live data from this PR's pacing-drop distribution as
  justification. No follow-up issue.
- **Option E batch/flush redirect coalescing.** Overlaps #709
  owner-drain work. Do not solve twice. Decision deferred to #709's
  Option B / telemetry outcome.
- **Per-bucket `last_refill_ns` array.** Deferred with explicit
  justification: shared `last_refill_ns` + per-bucket tokens is
  correctness-equivalent for the admission gate and saves 8 KB per
  queue. If we later surface per-bucket refill-latency histograms and
  the shared ns becomes a blocker, file
  *"userspace-dp: per-flow-bucket refill timestamp for pacing
  telemetry"*.
- **Pacing on non-flow-fair queues.** Deferred; the plan treats
  non-flow-fair (`flow_fair=false`) queues as degenerate and bypasses
  pacing. If operators configure a `flow_fair=false` queue that needs
  microburst smoothing, the right fix is enabling SFQ on that queue,
  not bolting pacing onto the non-SFQ path.
- **Endpoint-side explanation of the 100k retrans count.** The plan
  calls out analytically that most of the retrans signal is ECN-
  induced recovery, not wire loss. Confirming that empirically
  (server-side gRPC capture of actual wire retransmissions vs.
  iperf3's reported count) is deferred. Follow-up issue title:
  *"cos: disambiguate iperf3 retransmit count — wire loss vs ECN
  recovery entries"*. The capture endpoint was unreachable in the
  architect's window; see §3 for the analytical framing.

## Refs

- #704 umbrella cwnd-collapse symptom
- #705 admission cap interaction (landed via #711 SFQ + #716 flow-aware cap)
- #707 buffer undersizing (closed)
- #709 owner-worker hotspot (companion plan)
- #710 per-queue drop-reason counters (landed — this plan adds one)
- #711 1024-bucket SFQ (landed — this plan reuses its array)
- #712 worker CPU pinning (orthogonal)
- #715/#716/#720/#727/#728 admission + ECN fixes landing in the post-#728 baseline
- #724 surface admission drop counters (landed — this plan follows the render pattern)
- `engineering-style.md` — narrow-scope, honest-framing principles
  driving the "single-option, measurement-first" recommendation
- `cos-validation-notes.md` — validation methodology anchor
