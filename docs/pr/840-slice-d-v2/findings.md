# #840 Slice D v2 — Empirical Negative Finding

## TL;DR

The #840 RSS-rebalance loop **was reverted per #835 §6.5** because
empirical measurement showed it **degrades** cross-binding fairness
in the workers==queues topology with long-lived TCP flows. CoV
nearly doubled vs the no-rebalance baseline. Root cause: the
algorithm thrashes the RSS table because table changes only
affect future hash buckets, not existing flows.

The implementation itself is correct (4 Codex hostile-review rounds
+ Copilot inline review all clean, MERGE YES at Codex R4) and the
signal-source change from #835's frozen `ethtool -S` counters to
xpf-userspace-dp's per-binding `RXPackets` was verified working
(rebalance loop fires, table actually changes). The problem is
the **design assumption** that table change → traffic
redistributes-evenly, which only holds for new flows.

## Test environment

- Cluster: `loss:xpf-userspace-fw0` (RG0 primary), `loss:xpf-userspace-fw1`
- Topology: workers=6, ge-0-0-1/ge-0-0-2 mlx5 ConnectX-5 with 6 RX queues each
- CoS: applied via `test/incus/apply-cos-config.sh` (4 classes, 100 Mb/s / 1 Gb/s / 10 Gb/s / 25 Gb/s shapers)
- Test: `iperf3 -c 172.16.80.200 -P 16 -t 600 -p 5201` (1 Gb/s shaped class, 16 long-lived streams, 10 min)
- Both interfaces: `ethtool -X iface default` before each run (round-robin baseline)

## Result (single 600s run each)

| Metric                      | #840 ENABLED | BASELINE (rebalance off) | Δ        |
|-----------------------------|-------------:|-------------------------:|----------|
| Aggregate Gbps              | 0.954        | 0.954                    | tied     |
| Streams collapsed (≤1Mbps)  | 0/16         | 0/16                     | tied     |
| **CoV (per-stream)**        | **37.7%**    | **18.5%**                | **2.0× worse** |
| Min stream Mbps             | 21.24        | 48.06                    | 2.3× lower with #840 |
| Max stream Mbps             | 99.69        | 79.02                    | 26% higher with #840 |
| Retransmits                 | 3501         | 3791                     | tied     |

PASS gate from #835 §6.4 was "p5201 CoV ≤ 15% on ≥ 8 of 10 runs".
With rebalance enabled we are at **37.7%**, more than 2× over the
threshold. The baseline (no rebalance) achieves **18.5%** —
itself just above the threshold but in the right ballpark.

## Why the algorithm thrashes

Journalctl during the 10-min test shows ~50 rebalance fires (one
per ~10s, the cooldown floor). Sample weight evolution on
ge-0-0-2:

```
[20 20 20 20 20 20]  (initial seed)
[15 27 21 23 15 19]
[15 27 24 23 12 19]
[15 27 27 23  9 19]
[15 27 27 23  9 19] (no change — early-return on weightsEqual)
[15 22 34 18  7 24]
[15 23 34 18  6 24]
[19 23 34 14  6 24]
[27 23 26 14  6 24]
[32 18 26 14  6 24]
[35 18 26 11  6 24]
[37 14 26  9  6 24]
[37 14 26  9 12 23]  (now ring 4 starts getting traffic)
[37 14 20  9 12 30]
[37 14 20  7 12 30]
...
```

The algorithm sees **persistent imbalance** across ticks because
the 16 long-lived TCP streams stay on whatever queue RSS hashed
them to at connect time. Migrating weight TO an idle queue gives
that queue more hash buckets, but no TCP stream picks them up
(streams are already established). The next tick still sees the
same imbalance, fires again, migrates more weight. This cycles
indefinitely.

By contrast, the **baseline** holds at the round-robin default,
which gives a stable hash distribution. With 16 streams hashing
into 6 queues, pigeon-hole gives an uneven 3-4-3-3-2-1 distribution
that's noisy but *stable*, and stable is what TCP wants.

## Algorithm assumption that doesn't hold

#835 plan §3 reasoning: "rebalance the RSS table so future hash
buckets favor cold queues; over time, the table converges and
traffic balances."

This is correct **for new flows**. A connection establishing right
after the table change WILL hash into the new layout. But for
**long-lived flows** (which is exactly the workload Slice D was
supposed to help — sustained iperf-class traffic), the existing
streams stay on their original queue and the algorithm has no
mechanism to move them.

## Why workers==queues makes it worse

In the original #835 target case (workers<queues), `ethtool -X iface weight 1 1 1 1 0 0` (workers=4, queues=6) leaves
queues 4-5 at weight 0. Migrating weight to queues 4-5 IS
beneficial because they were getting nothing before. New flows
hashing there fill them up.

In workers==queues=6, the **default round-robin RSS table is
already equal-weight** — there are no zero-weighted queues to
"activate". The algorithm sees imbalance from hash-collision
clustering (two streams happen to hash to the same queue), and
migrates weight away from the busy queue. But the busy queue is
busy because it has 4 long-lived flows, not because it has too
many hash buckets. Reducing its bucket count doesn't move the 4
flows; it just reduces hashing slack for any new flow that
*also* hashed there. Net effect: no improvement, plus added
churn from constant rewrites.

## Replication

To reproduce on the userspace cluster:

```bash
# 1. Deploy with #840 (e.g. checkout the reverted commit's parent)
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    ./test/incus/cluster-setup.sh deploy all

# 2. Apply CoS
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0

# 3. Reset RSS to round-robin default
incus exec loss:xpf-userspace-fw0 -- ethtool -X ge-0-0-2 default
incus exec loss:xpf-userspace-fw0 -- ethtool -X ge-0-0-1 default

# 4. Run with #840 enabled
incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -P 16 -t 600 -p 5201 -J > p5201-enabled.json

# 5. Disable rebalance, reset table, re-run
incus exec loss:xpf-userspace-fw0 -- bash -c \
    "echo -e 'configure\nset system dataplane userspace rss-indirection disabled\ncommit\nexit' | cli"
incus exec loss:xpf-userspace-fw0 -- ethtool -X ge-0-0-2 default
incus exec loss:xpf-userspace-fw0 -- ethtool -X ge-0-0-1 default
incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -P 16 -t 600 -p 5201 -J > p5201-baseline.json

# 6. Compare per-stream sender bitrate, compute CoV
```

## Revert

Per #835 §6.5 protocol, only the four files this PR touched were
reverted:

```bash
git checkout master -- \
    pkg/daemon/rss_rebalance.go \
    pkg/daemon/rss_rebalance_test.go \
    pkg/daemon/rss_indirection.go \
    pkg/daemon/daemon.go
```

`docs/pr/840-slice-d-v2/` (this directory) is preserved so future
attempts have the empirical baseline.

## Design rework needed before re-introduction

Three follow-on issues filed:

1. **Hysteresis / convergence detection** — algorithm must stop
   firing if recent rebalances haven't improved the imbalance
   metric. Track post-rebalance max/mean, abort if it doesn't
   decrease for K consecutive attempts.

2. **Scope to workers<queues + non-equal initial weight** —
   Slice D's value proposition (move buckets to zero-weighted
   queues) only applies when the initial table actually has
   zero-weighted queues. In workers==queues, the algorithm is
   a no-op at best, harmful at worst (this finding).

3. **Per-flow XDP_REDIRECT alternative** — fundamental
   limitation: long-lived flows don't migrate when the RSS
   table changes. To actually rebalance in-flight traffic, we'd
   need per-flow steering (XDP_REDIRECT to a specific queue
   based on flow hash + load awareness) rather than tuning the
   coarse-grained NIC RSS table. This is a larger design
   change that subsumes Slice D entirely.

## Cross-references

- #835 (closed) — Slice D v1 with `ethtool -S` signal source
- #786 — parent epic (cross-binding fairness)
- #830 (Slice B) — per-binding virtual-time gate (works correctly above this)
- #832 — workers=6 default
- #826 — precedent for per-binding daemon counters (rx_packets atomic)
