# Step 1 Plan Review

Disposition: not ready to run. The plan is strongest where it quotes the post-#804 snapshot surface, and weakest exactly where it tries to turn those counters into verdict math.

## Findings

### 1
**SEVERITY:** HIGH

Threshold X is mathematically wrong for the statistic it actually tests, and Y/Z have no error-rate derivation at all.

`docs/pr/line-rate-investigation/step1-plan.md:246-278` computes a per-worker binomial standard deviation (`0.108`) and then applies it to `max(load_w)-min(load_w)`, which is a different statistic. With 16 flows across 4 workers, shares move in 6.25% steps, so `> 0.15` is really a threshold of `3/16 = 18.75%`; on an ideal multinomial RSS split, `P(max-min >= 3 flows) = 0.78798`, so the classifier would false-positive on about 79% of balanced runs. The doc also gives no false-positive / false-negative derivation for Y or Z beyond narrative hand-waving (`docs/pr/line-rate-investigation/step1-plan.md:256-278`).

Concrete mitigation: derive X on the actual range statistic or use an exact multinomial/binomial test on worker counts, publish FP/FN for X/Y/Z, and define the discrete boundary explicitly. Right now the threshold is cargo cult math.

### 2
**SEVERITY:** HIGH

Skipping `no-cos × reverse` is not “strict duplication”; it throws away the only control for ACK-path CoS interaction.

The skip rationale says reverse traffic is unclassified because the filter exists only on `reth0.80` output (`docs/pr/line-rate-investigation/step1-plan.md:39-52`, `docs/pr/line-rate-investigation/8matrix-findings.md:34-47`). That ignores TCP directionality: in `iperf3 -R`, bulk server→client data exits `ge-0-0-1` unfiltered, but client→server ACKs still leave via `reth0.80` and hit the `destination-port 5201/5202/5203` terms or the best-effort default in `full-cos.set` (`docs/pr/line-rate-investigation/full-cos.set:27-48`). `with-cos × reverse` therefore still exercises CoS on the ACK/control loop, while `no-cos × reverse` does not; skipping those four cells can hide a reverse-only bug where shaped ACK handling or cross-worker ACK distribution throttles bulk goodput.

Concrete mitigation: run all 16 cells, or at minimum add a reverse control that proves ACK-path classification is irrelevant by checking filter counters and reverse-cell deltas under `no-cos`.

### 3
**SEVERITY:** HIGH

The “12 samples = statistical validity” claim is mathematically false for these counters, and the cadence can miss the only transient gauge.

The plan says 12 samples are enough for per-counter mean/stddev and even calls them “48 per-worker observations” (`docs/pr/line-rate-investigation/step1-plan.md:121-131`, `docs/pr/line-rate-investigation/step1-plan.md:421-427`). But the exported fields are a mix of cumulative counters and gauges: the worker debug tick `fetch_add`s the local `dbg_*` counters into live atomics and resets the locals, while `outstanding_tx` is a `store()`d gauge (`userspace-dp/src/afxdp/worker.rs:1361-1403`); `BindingCountersSnapshot` then exposes those mixed semantics directly (`userspace-dp/src/protocol.rs:1330-1420`). Means over serial cumulative samples are not estimators of event totals, 12 snapshots from one run are not 48 independent observations, and 5-second sampling can alias away short-lived `outstanding_tx` spikes.

Concrete mitigation: define analysis on cold→post deltas for cumulative counters, sample gauges at the worker publish cadence or faster, and stop using “N=12” language as if this were an iid sample.

### 4
**SEVERITY:** HIGH

The plan’s load-bearing interpretation of `dbg_cos_queue_overflow` is wrong: it is an admission-drop counter, not a token-starvation/shaper-contention counter.

Appendix A says `dbg_cos_queue_overflow` distinguishes “CoS admission rejecting under shaper token contention” from bound-pending overflow (`docs/pr/line-rate-investigation/step1-plan.md:461-475`). The code says otherwise: the increment happens when enqueue admission rejects because `flow_share_exceeded` or `buffer_exceeded` (`userspace-dp/src/afxdp/tx.rs:5326-5367`, `userspace-dp/src/afxdp/tx.rs:5406-5412`). Token starvation is tracked separately as queue/root starvation parks in `CoSQueueStatus` (`userspace-dp/src/protocol.rs:854-867`; see the park write sites in `userspace-dp/src/afxdp/tx.rs:1500-1517`).

Concrete mitigation: either sample the queue-level token-starvation counters and use those for verdict B, or rename B so it matches the actual signal. The #804 split is real; the semantics the plan assigns to one side of the split are not.

### 5
**SEVERITY:** HIGH

The CoS apply/remove smoke verifies forwarding only; it does not verify that CoS actually changed.

After apply/remove, the only required check is `iperf3 -P 4 -t 5 -p 5203` with zero retransmits (`docs/pr/line-rate-investigation/step1-plan.md:351-367`). That is a terrible discriminator because port 5203 maps to `scheduler-iperf-c transmit-rate 25.0g` on an interface already shaped at `25g` (`docs/pr/line-rate-investigation/full-cos.set:19-20`, `docs/pr/line-rate-investigation/full-cos.set:27-29`, `docs/pr/line-rate-investigation/full-cos.set:40-43`): the smoke can pass whether term 2 is active or the filter is absent entirely. The plan also never waits for runtime reconciliation on the control socket before starting the measured half.

Concrete mitigation: after each transition, verify commit success plus runtime state with `show configuration`, `show class-of-service interface`, and control-socket `cos_interfaces` / `filter_term_counters`, then use a tight-shaper port (5201 or 5202) as the classification sanity check.

### 6
**SEVERITY:** HIGH

The reproducibility claim is false in this branch and false in the cited commit.

The plan says the measurement is driven by committed `test/incus/step1-capture.sh` “added in the same PR” (`docs/pr/line-rate-investigation/step1-plan.md:430-433`). On this branch, `git ls-files test/incus/step1-capture.sh` returns nothing and `rg --files test/incus | rg 'step1-capture\\.sh$'` returns nothing; `git show --name-only 91935061` shows only `docs/pr/line-rate-investigation/step1-plan.md`. That means the repo has a plan and some rough snippets, not the promised executable protocol.

Concrete mitigation: commit the driver script and any parsers in this branch, or delete the reproducibility claim and replace it with exact checked-in commands and exact post-processing logic.

### 7
**SEVERITY:** MEDIUM

The `perf stat --per-thread -p` setup is brittle to the point of likely being wrong.

The plan obtains `WORKER_PIDS` with `pgrep -f 'xpf-userspace-w'` (`docs/pr/line-rate-investigation/step1-plan.md:137-142`), but workers are named `xpf-userspace-worker-{id}` in the Rust thread builder (`userspace-dp/src/afxdp/coordinator.rs:693-695`). `pgrep -f` matches command line, not thread name, so this can easily produce an empty list or the wrong scope; even if corrected, a daemon restart or worker respawn mid-window invalidates the attachment and the plan has no invariant that catches that.

Concrete mitigation: collect TIDs from `ps -eLo pid,tid,comm,args` or `pgrep -w` against the actual thread name, assert exactly four live worker TIDs before capture, and invalidate the cell on any daemon restart.

### 8
**SEVERITY:** MEDIUM

Primary selection is treated as a post-hoc validity check even though the parent plan says the alternate primary is known-bad.

Step 1 hardcodes all commands to `loss:xpf-userspace-fw0` “(primary)” (`docs/pr/line-rate-investigation/step1-plan.md:66-68`) and only checks same-primary pre/post inside a cell (`docs/pr/line-rate-investigation/step1-plan.md:337`, `docs/pr/line-rate-investigation/step1-plan.md:446-447`). But the parent plan explicitly calls out fw1’s pre-existing fab0 bug (`docs/pr/line-rate-investigation/plan.md:650`), so a failover is not just noise; it can strand the measurement on the one node where userspace-dp may not be running.

Concrete mitigation: promote “fw0 is RG0 primary” to a start-of-run invariant, abort immediately on any primary drift, and do not perform CoS transitions or captures during a failover window.

### 9
**SEVERITY:** MEDIUM

The latency probe pinning is undefined in practice, and 100 Hz ICMP is only a coarse tail proxy at 25 Gbps.

The plan says “unused CPU” and then hardcodes CPUs 4 and 5 (`docs/pr/line-rate-investigation/step1-plan.md:161-173`) without proving those CPUs exist or are actually idle on `cluster-userspace-host`. If those cores are busy, the probe measures host scheduling contention, not datapath latency. Also, 60 seconds at 100 Hz yields 6000 samples, so the p99 is based on only 60 tail samples: fine for a coarse regression tripwire, weak for claiming accurate line-rate p99 under microburst conditions.

Concrete mitigation: reserve probe CPUs explicitly, log host CPU occupancy for those cores, and describe ICMP p99 as a coarse regression signal unless the sampling method is strengthened.

### 10
**SEVERITY:** MEDIUM

Run length, time budget, and Step-2 decision semantics are all underspecified exactly where the plan pretends to be deterministic.

Nothing in the doc derives `-t 60` from measured RTT/BDP or from Cubic convergence on the 1 G / 100 M cells (`docs/pr/line-rate-investigation/step1-plan.md:112-115`), so “steady state” is asserted, not demonstrated. At the same time, the budget allows only ~10 minutes of rerun buffer even though §5 allows two reruns per bad cell (`docs/pr/line-rate-investigation/step1-plan.md:341-344`, `docs/pr/line-rate-investigation/step1-plan.md:375-390`), and the classifier never defines “argmax normalized distance from threshold” or what to do with mixed A/B/C cells below the 50% / 75% cutoffs (`docs/pr/line-rate-investigation/step1-plan.md:280-284`, `docs/pr/line-rate-investigation/step1-plan.md:397-412`).

Concrete mitigation: justify 60 seconds with measured RTT/cwnd traces per shaper, add a hard rescope rule tied to remaining cells/time, and define an explicit aggregation tree from per-cell verdicts to Step 2.

## Where The Plan Holds Up

- Verified: the `status` response really does surface a compact `per_binding` array plus the full `bindings[]` view. `refresh_status()` populates `per_binding` from `BindingStatus` on every status refresh (`userspace-dp/src/main.rs:748-807`), `ProcessStatus` exports that field (`userspace-dp/src/protocol.rs:711-720`), `BindingStatus` still carries the claimed load fields such as `rx_packets`, `tx_packets`, `flow_cache_hits`, `flow_cache_misses`, and `redirect_inbox_overflow_drops` (`userspace-dp/src/protocol.rs:1121-1235`), and `BindingCountersSnapshot` contains exactly the post-#804 keys the plan lists (`userspace-dp/src/protocol.rs:1367-1420`). The plan is grounded here.

- Verified: the #804 split between bound-pending overflow and CoS admission overflow is real in code. `dbg_bound_pending_overflow` increments only in `bound_pending_tx_local()` / `bound_pending_tx_prepared()` (`userspace-dp/src/afxdp/tx.rs:154-194`), `dbg_cos_queue_overflow` increments only at the CoS enqueue reject site (`userspace-dp/src/afxdp/tx.rs:5406-5412`), and the worker publish path keeps them separate (`userspace-dp/src/afxdp/worker.rs:1361-1369`). The instrumentation exists; the plan’s interpretation of one counter is the broken part.
