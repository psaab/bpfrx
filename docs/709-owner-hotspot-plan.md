# #709 low-rate owner-worker hotspot — architect plan

Status: plan. Implementation lands in a follow-up PR against the slice
defined in [§4](#4-narrow-write-scope-for-the-implementor).

## 1. Problem restatement

Low-rate exact queues (`shared_exact == false`) elect a single "owner"
worker. All packets the other workers RX for that queue redirect to the
owner via the per-binding MPSC inbox added in #715; the owner's
`drain_shaped_tx` is the only code path that services the queue's SFQ
state. The owner still does its own bound-queue RX + forwarding + NAT on
top of that, so its per-tick budget is ~2× a non-owner's on the hot
queue.

Post-#715/#716/#720/#727/#728 baseline on the 16-flow / 1 Gbps / queue 4
workload: rate ratio 1.28×, 114k retransmits per 30 s, 75
`flow_share_drops` per 30 s, 0 `buffer_drops`, 97k `ecn_marked` per
30 s, cwnd 8–17 KB per flow (ECN-held, no RTO collapse). The
originally-observable symptoms of the hotspot (cwnd bimodality tied
to RSS landing) are almost entirely masked by ECN working. What
remains is jitter-level noise that we cannot currently *attribute* to
the owner hotspot because we lack the telemetry to separate it from
CPU-scheduler jitter (#712), ECN-residual microbursts, or sender-side
noise.

## 2. Options at a glance

| Opt | Changes                           | Size                | Risk   | Attacks                                  |
|-----|-----------------------------------|---------------------|--------|------------------------------------------|
| A   | systemd unit + kernel cmdline     | ≤10 lines, 2 files  | Low    | OS scheduler jitter (not owner fanout)   |
| B   | Work-stealing off-worker drain    | ~400–800 lines Rust | High   | Owner CPU fanout                         |
| C   | NIC-side RSS queue retargeting    | ~200 lines Go + NIC | Med    | RX-side fanout at the hardware           |
| D   | Owner rotation every ~100 ms      | ~200 lines Rust     | Med    | Time-average fanout; cache/thrash cost   |
| E   | Telemetry: owner-drain histogram  | ~150 lines Rust     | Low    | Measures before committing to a fix      |

- **A** is #712 verbatim — treat A as subsumed if we go there. It does
  not touch the owner-fanout pattern, only the jitter that rides on top
  of it.
- **B** is the "honest" structural fix — it dissolves the owner hotspot
  entirely — but it requires a lock-free MPMC over the SFQ cursor and
  dispatch and is a significant correctness surface. Shaper cursor is
  currently single-writer; relaxing that is the real cost.
- **C** needs `ethtool -X` / flow-director plumbing and is NIC-specific;
  loss uses i40e+virtio in mixed mode.
- **D** adds RG-sync cost and cache warmup per rotation.
- **E** is filed at the bottom of #709 itself ("filed separately — the
  telemetry gap"). It has not been written.

## 3. Recommendation

**Pick Option E: close the telemetry gap before committing to a structural
fix.** Implementation slice = add an owner-drain latency histogram +
owner-vs-non-owner pps counter + redirect-acquire distribution to
`BindingLiveState`, surface them through `show class-of-service
interface` and Prometheus.

Rationale. Post-#728 the visible-to-operator evidence of the owner
hotspot is nearly gone: cwnd is ECN-held (not RTO-collapsed),
retransmits are down from ~200k to 114k, `flow_share_drops` is down
from ~190/s to ~2.5/s. The residual per-flow variance (55–91 Mbps on
the owner queue) is as likely to be CPU-scheduler jitter (#712) or
ECN-residual microbursts as it is to be owner-drain slippage. Option B
is the honest structural fix but is a high-risk slice to land against
noise-level symptoms. We don't have the data to claim it would move
any metric ≥10% on the post-#728 live workload, and
`engineering-style.md` is explicit that PRs claiming a metric movement
must present before/after numbers.

What E *does not* fix:
- Does not remove the owner fanout. If telemetry proves owner-drain
  latency is the bottleneck, a follow-up must still pick B/C/D.
- Does not improve current live numbers by itself.
- Does not subsume #712. CPU pinning is orthogonal: #712 addresses
  scheduler jitter regardless of the owner hotspot.

Expected outcome of the E PR: we discover one of three worlds.
(i) Owner-drain p99 is flat relative to non-owner → close #709 as
not-needed, keep #712 for jitter. (ii) Owner-drain p99 has a clear
head-of-line stall signature → land Option B narrowly. (iii) Drain is
fine but redirect-acquire shows contention → pivot to a smaller
producer-side fix. The decision tree is data-first.

## 4. Narrow write scope for the implementor

Exact files. Keep the slice tight.

1. `userspace-dp/src/afxdp/types.rs` (or `umem.rs` near
   `BindingLiveState`) — add three `AtomicU64` fields and a fixed-cap
   histogram. Bucket boundaries as `const` array. No heap allocation.
   - `drain_latency_hist: [AtomicU64; 16]` — buckets in `now_ns`
     deltas across `drain_shaped_tx` calls, powers of two from 1 µs to
     32 ms. Index via `leading_zeros`, branchless.
   - `drain_invocations: AtomicU64`, `drain_noop_invocations: AtomicU64`.
   - `redirect_acquire_hist: [AtomicU64; 16]` — time spent in
     `MpscInbox::push` from caller perspective (sampled — every Nth
     redirect, not every one; see invariants).
   - `pps_owner_vs_peer_running_window: [AtomicU64; 2]` — owner pps and
     sum-of-peer-pps in a ring-counter pair, operator resets on CLI.
2. `userspace-dp/src/afxdp/tx.rs` — two call sites in `drain_shaped_tx`
   wrap timing via `monotonic_nanos()` delta (already cheap, already
   used for `now_ns`). No new `Instant::now()` calls.
3. `userspace-dp/src/afxdp/umem.rs` — wrap `enqueue_tx_owned` with a
   sampled timer (1-in-256; seed from `worker_id` so samples
   interleave). Gated behind a const sample interval so we can disable
   by recompile if the CAS overhead on the sampled path ever bites.
4. `userspace-dp/src/protocol.rs` / gRPC `CoSInterfaceStatus` — surface
   the histogram buckets and the PPS counters per-queue-owner so the
   CLI renderer can display them.
5. `userspace-dp/src/cli` renderer or `cmd/cli` equivalent — extend the
   per-queue `Drops:` line in `show class-of-service interface` to emit
   a new indented `OwnerProfile:` line on queues where owner_worker !=
   255 (i.e. exact queues with a single owner). Format:
   `OwnerProfile: drain_p50=<µs> drain_p99=<µs> redirect_p99=<µs>
    owner_pps=<n> peer_pps=<n>`.
6. `pkg/api` (Prometheus collector) — add matching gauges per-queue.
   One gauge per bucket for each histogram, label by `(ifindex,
   queue_id, bucket_hi_ns)`.
7. `docs/cos-validation-notes.md` — new "Reading the owner-profile
   counters" section describing interpretation and decision tree. This
   is an Architect-owned doc edit in the implementor PR.

## 5. Invariants the implementor must preserve

- The MPSC inbox from #715 stays MPSC. The sampled timer wraps
  `enqueue_tx_owned` externally; it does not add a second consumer or a
  second producer-side atomic beyond the one sample counter.
- No allocations on the hot path. Histograms are
  `[AtomicU64; 16]` inline; PPS counters are two `AtomicU64`s. No
  `Vec::push`, no `HashMap::entry`.
- Histogram bucket selection is branchless: one
  `(ns | 1).leading_zeros()` + one saturating subtract. No bucket-search
  loop.
- Timer sampling in `enqueue_tx_owned` is gated by a power-of-two
  mask on a producer-local counter. Seeded per-worker so samples do not
  all land in lockstep on one slot.
- `drain_shaped_tx` timing must not add a syscall. `monotonic_nanos()`
  in this codebase is `clock_gettime(CLOCK_MONOTONIC)` (VDSO,
  branchless). One call before and one after the whole
  `drain_shaped_tx` invocation — not per queue, not per batch.
- Existing Prepared/Local dispatch in `apply_cos_admission_ecn_policy`
  and in `ingest_cos_pending_tx` is unchanged.
- Per-binding counters live on `BindingLiveState` (owner's binding)
  because that's the Arc the peer workers already hold for the inbox;
  no new cross-worker state.
- Prometheus label cardinality must not explode: one bucket × one
  queue × one owner-worker is bounded by `num_queues × num_interfaces`
  (typically ≤ 64 queues across ≤ 8 interfaces, ≤ 512 series × 16
  buckets = 8192 series). Acceptable; flag it on the PR anyway.
- Const-asserts: `const _: () = assert!(DRAIN_HIST_BUCKETS == 16)` so
  any schema drift breaks the build.

## 6. Acceptance criteria — validating against the live lab

Methodology anchor: [`cos-validation-notes.md`](cos-validation-notes.md)
§ "How to read admission drop counters live" — same methodology, new
section added by the implementor PR.

Run the 16-flow iperf3 on 5201 per the existing recipe. Then:

1. `show class-of-service interface` on queue 4 emits the new
   `OwnerProfile:` line with non-zero `drain_p50`, `drain_p99`,
   `owner_pps`, `peer_pps`. Zeroes on queues 0/5 are acceptable — they
   are idle.
2. Owner vs peer pps ratio on queue 4 is reported and makes physical
   sense (owner does its own RX too; expect owner_pps ≈
   peer_pps_sum × (1 + 1/N) at steady state for N workers).
3. Histogram bucket distribution for drain latency shows enough
   resolution that the decision tree in §3 is actionable: a right-tail
   fatter than one decade above p50 is the "owner is bottleneck"
   signature.
4. `flow_share_drops`, `buffer_drops`, `ecn_marked` on queue 4 do not
   regress from the post-#728 baseline (75 / 0 / 97349 per 30 s, ±20%).
   This PR is telemetry-only; it must not affect the hot path.
5. 5202 (10 G) and 5203 (no-shape) throughput does not regress. Same
   run, same `iperf3 -P 16 -p 5202 -t 30` / `-p 5203 -t 30`
   invocations.
6. Prometheus scrape returns the new series; `promtool check metrics`
   on the scrape output is clean (no type drift, no label churn).

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

Explicitly deferred from this slice. Each becomes an issue on merge if
telemetry points at it.

- **Work-stealing off-owner drain (Option B).** Filed as new issue
  *"userspace-dp: work-stealing exact-queue drain (lock-free SFQ
  cursor)"*. Depends on telemetry from this PR showing drain_p99 is
  bimodal / fat-tailed on queue 4.
- **RSS queue retargeting (Option C).** Filed as new issue
  *"userspace-dp: steer per-queue RX to owner-worker at the NIC"*.
  Hardware-specific; loss uses mixed i40e + virtio.
- **Owner rotation (Option D).** Filed as new issue *"userspace-dp:
  rotate exact-queue owner on a slow timescale"*. Deferred as
  complexity/value unproven.
- **CPU pinning + isolcpus (Option A).** Already tracked in #712.
  This plan does not touch it; pin discipline is orthogonal telemetry
  because scheduler jitter and owner-drain slippage look similar on a
  coarse histogram — that's why we need both together to disambiguate.
- **Redirect-acquire unsampled timing.** Sampling is cheap; full timing
  on every `enqueue_tx_owned` adds a `clock_gettime` per redirected
  packet (~15 ns, ~0.5% at 1 Gbps). Filed as new issue
  *"userspace-dp: optional full-rate redirect-acquire timing behind a
  compile flag"*.

## Refs

- #704 umbrella cwnd-collapse symptom
- #706 redirect mutex (closed by #715)
- #709 owner-worker hotspot (this plan)
- #712 worker CPU pinning + IRQ isolation
- #715/#716/#720/#727/#728 merged admission + ECN fixes that mask the
  visible-to-operator hotspot symptoms
- `engineering-style.md` — narrow-scope, honest-framing principles
  driving the "measure before optimizing" recommendation
- `cos-validation-notes.md` — validation methodology anchor
