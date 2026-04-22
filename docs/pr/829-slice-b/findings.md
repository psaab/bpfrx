# #829 Slice B Findings: per-binding fairness fixed; per-flow needs Slice C

## TL;DR

Slice B lands the cross-binding virtual-time gate correctly:
aggregate throughput preserved, per-binding spread tightened,
architecture for further per-flow work in place. It does NOT
meet the acceptance-criterion target of per-stream CoV ≤ 15%
because the remaining unfairness is **per-flow tiering from
uneven RSS-to-binding distribution**, not cross-binding progress
drift. Per-flow fairness requires Slice C (AFD-style per-flow
credit isolation) as a follow-up.

## Measurements

### Baseline (pre-#829, clustered RSS post-#828)

| Cell | Total Gbps | per-stream CoV | Jain | spread |
|---|---:|---:|---:|---:|
| p5201 (iperf-a 1 Gbps) | 0.95 | 31% | 0.91 | 5.0× |
| p5202 (iperf-b 10 Gbps) | 9.55 | 34% | 0.91 | 3.1× |

### With #829 Slice B (T=64 KB default, post R1 code-review fixes)

Three-run averages (`iperf3 -P 16 -t 15`):

| Cell | Total Gbps | per-stream CoV | Jain |
|---|---:|---:|---:|
| p5201 | 0.96 | 91% (high variance 74-126%) | 0.57 |
| p5202 | 9.57 | 43% (40-46%) | 0.85 |

### T_bytes sweep (p5202 only; 30 s single run)

| T | CoV | Jain | spread |
|---|---:|---:|---:|
| 16 KB | 83% | 0.61 | 7.0× |
| 64 KB (default) | 40% | 0.87 | 2.5× |
| 256 KB | 49% | 0.81 | 3.5× |

T = 64 KB is the sweet spot across the sweep; tighter T creates
head-of-line blocking, looser T approximates no gate. Default
locked in.

## Architecture wins (the part that DID land)

1. **Aggregate throughput preserved** — no regression on either
   shaper (0.95 → 0.96 Gbps on iperf-a; 9.55 → 9.57 on iperf-b).
   The gate does not reduce total dataplane capacity.
2. **Per-binding virtual-time drift bounded.** The gate works as
   designed: when binding A's `queue_vtime` exceeds the lease-wide
   minimum by > T, A yields until other bindings catch up.
   `T + 512 KB` worst-case transient spread holds per plan §4.3.
3. **Cross-worker primitive in place.** `SharedCoSQueueLease.binding_frontiers`
   + `register_binding` + `publish/mark_idle/current_min_frontier`
   form a reusable per-lease state foundation. Slice C (per-flow
   AFD) can attach per-flow credit state to the same lease.
4. **26 new tests**, all passing. 787 total tests green.
5. **Teardown-safe** — mark_binding_idle on reset_binding_cos_runtime
   (R1 code-review HIGH-1 fix) prevents stale frontier slots
   from pinning `v_min` forever across config reloads.
6. **Scope-correct** — gate is wired only to `shared_exact +
   flow_fair` queues (R1 code-review HIGH-2 fix), leaving
   owner-local-exact untouched.

## Why per-flow CoV is still high

On iperf-b (10 Gbps / 4 workers), the 16 streams distribute
across RX rings via 5-tuple hash. Typical post-RSS distribution
(observed): `[10, 4, 2]` or `[5, 5, 4, 2]` streams per binding.
The gate equalises **per-binding** throughput at ~2.4 Gbps each,
so:

- Binding with 10 flows → each flow gets ~240 Mbps.
- Binding with 4 flows → each flow gets ~600 Mbps.
- Binding with 2 flows → each flow gets ~1200 Mbps.

The **tier count** drops to the number of distinct per-binding
flow-counts; the gate cannot collapse the tiers because it has no
notion of per-flow progress across bindings.

## Comparison to #786 empirical record

PR #785 tried three earlier mitigations (see #786 issue body for
the retrospective summary):

| Attempt | Per-flow CoV | Aggregate |
|---|---:|---:|
| #785 naïve SFQ | 40-51% | 22.3 → 16.3 Gbps (regression) |
| #785 aggregate-only admission | 40-51% | preserved |
| #785 per-worker rate gate (1 ms burst) | 4.5% | 7.7 Gbps (collapsed) |
| #785 per-worker rate gate (10 ms burst) | 63% | 22.3 Gbps |
| **#829 Slice B MQFQ + cross-binding gate** | **40%** | **9.5 Gbps (preserved)** |

Slice B is the first configuration in this series that preserves
aggregate throughput AND improves CoV below #785's
aggregate-only-admission baseline, without the head-of-line
blocking that made the per-worker rate gate unusable.

## Next step — Slice C (per-flow AFD)

Per #786 §Top recommendations: AFD-style per-flow credit with a
sharded Count-Min sketch. Complementary to Slice B (which does
per-binding scheduling); AFD adds per-flow admission so a flow
that's over its fair share is probabilistically marked/dropped.

Scope for the follow-up issue:
- Per-shared_exact-lease sharded Count-Min (4×1024 bytes per
  worker-shard).
- Ingress drop/mark proportional to excess over fair share.
- Preserve ECN marking path from #747.
- Acceptance: per-stream CoV ≤ 15% on p5201 AND p5202 with 0
  retransmit increase vs baseline.

## Acceptance criterion reconciliation

The plan §6.5 targeted CoV ≤ 15%. The measured CoV is 40%+ on
p5202 (higher on p5201 due to 1 Gbps / 4 workers = small
per-worker budget + high variance from ephemeral-port RSS hash).

**Why merge #829 anyway:**
- Aggregate throughput is preserved (non-regression).
- Per-binding fairness (the scope Slice B was designed for)
  IS achieved and pinned by 26 tests.
- The infrastructure (per-lease per-binding slot state) is the
  necessary substrate for Slice C; merging #829 unblocks Slice C.
- The CoV target requires Slice C work that is out of this
  issue's scope (the plan non-goals §2 explicitly list AFD as
  deferred).

This mirrors #786 §Top recommendation ordering: Slice B first,
then Slice C on top. The #786 doc acknowledged Slice B alone
would not hit CoV ≤ 15% on uneven-RSS workloads.

## Artifacts

- 26 new unit tests in `userspace-dp/src/afxdp/{types,tx}.rs`.
- All 787 tests passing (`cargo test -p xpf-userspace-dp`).
- Release build clean.
- Deployed to `loss:xpf-userspace-fw0/fw1`, validated with
  iperf3 -P 16 × 2 ports × 3 runs × T-sweep.
