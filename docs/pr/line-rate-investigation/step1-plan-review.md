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

## Round 2 verification

ROUND 2: plan-ready NO
Blockers: capture script speaks the wrong control-socket schema and does not implement the promised end-to-end protocol; Verdict-B thresholds remain underived.

- Prior HIGH #1 / review finding 1: STILL PARTIAL. The X-threshold arithmetic is now numerically consistent: the plan’s rounded `P(max(n_w) ≥ 8) ≈ 0.108` and union FP `≈ 0.133` match exact recomputation for 16 balls / 4 bins (`docs/pr/line-rate-investigation/step1-plan.md:264-287`). But the exact tail probabilities are cited to `scripts/rss_multinomial.py`, not derived in-plan, and that file is not committed (`docs/pr/line-rate-investigation/step1-plan.md:268-270`; `scripts/rss_multinomial.py` not found). Missing `4/4/4/4` is correct, not a defect.
- Prior HIGH #2 / review finding 6: STILL OPEN. `test/incus/step1-capture.sh` exists and has arg checks (`test/incus/step1-capture.sh:1-63`), but its control-socket calls are wrong: it sends `{"request_type":"status"}` although the protocol requires `type` (`userspace-dp/src/protocol.rs:625-627`; decode at `userspace-dp/src/main.rs:357-358`), reads top-level `.per_binding` / `.cos_interfaces`, and uses `.matched_packets`, while the actual wire shape is `.status.*` and `filter_term_counters[].packets` (`userspace-dp/src/main.rs:729-731`; `userspace-dp/src/protocol.rs:735-736,918-930`; `test/incus/step1-capture.sh:116-117,167-169,251-280`). It also defers verdicting to nonexistent `step1-classify.sh` despite the plan claiming the script produces `verdict.txt` (`test/incus/step1-capture.sh:289-290`; `docs/pr/line-rate-investigation/step1-plan.md:672-679`; `step1-classify.sh` not found).
- Prior HIGH #3 / review finding 4: CLOSED. `root_token_starvation_parks` / `queue_token_starvation_parks` exist on `CoSQueueStatus` (`userspace-dp/src/protocol.rs:801-867`), the scheduler records them from the park sites at `tx.rs:1500` / `:1516` via `count_park_reason()` (`userspace-dp/src/afxdp/tx.rs:1500-1517,4415-4428`), and they are exposed on `status.cos_interfaces[].queues[]` (`userspace-dp/src/main.rs:729-731,810-811`; `userspace-dp/src/protocol.rs:733-736,797`).

- MEDIUM: The cited Monte Carlo artifact is still missing (`docs/pr/line-rate-investigation/step1-plan.md:268-270`; `scripts/rss_multinomial.py` not found).
- HIGH: Verdict-B thresholding is still weak. Y’s `1500 / (5Gbps / 16)` term is dimensionally time, then `1.40x` is justified by an uncited empirical ceiling rather than a quantitative FP derivation; Z relies on an uncited “PR #804 dogfooding” baseline asserted only in the plan (`docs/pr/line-rate-investigation/step1-plan.md:354-372,422-429`).
- HIGH: The promised “canonical” capture script does not implement §6 transition handling, so CoS-apply failure and control-socket failure are not robustly handled; primary drift is only checked pre/post (`docs/pr/line-rate-investigation/step1-plan.md:544-600,672-679`; `test/incus/step1-capture.sh:1-290,233-238`).

## Round 3 verification

ROUND 3: plan-ready NO

- #1 CLOSED: `test/incus/step1-rss-multinomial.py` is committed and `python3 test/incus/step1-rss-multinomial.py --seed 42 --trials 1000000` prints `FP_union_max9_or_min0  0.0638`, which matches the plan's rounded `0.064`. Citation: `git ls-files` output=`test/incus/step1-rss-multinomial.py`; ran script, output=`FP_union_max9_or_min0  0.0638`.
- #2 CLOSED: `test/incus/step1-rate-spread-analysis.py` is committed, defaults to exactly the four forward cells `p5201-fwd/p5202-fwd/p5203-fwd/p5204-fwd`, and when run prints `mean across 4 cells: 1.8651`, `stddev: 0.4267`, `Y = mean + 2*stddev: 2.7186`, `Y rounded for plan: 2.72`. Citation: `test/incus/step1-rate-spread-analysis.py:87-90,121-129`; ran script, output=`mean across 4 cells: 1.8651 ... Y rounded for plan: 2.72`.
- #3 STILL PARTIAL: the `A` predicate really does fire at `n_max >= 9` so `9/16 = 56.25%` is detected, but the Monte Carlo only simulates fair RSS under the null and does not test power on that specific overloaded-worker failure mode, so the defense is logically weaker than claimed. Citation: `docs/pr/line-rate-investigation/step1-plan.md:283-295`; `test/incus/step1-rss-multinomial.py:5-7,40-42`.
- #4 STILL PARTIAL: `Y=2.72` is computed from `statistics.stdev()` on only 4 baseline cells, and the committed code/plan contain no confidence interval or bootstrap; the plan itself concedes the `4-cell stddev` is noisy enough that the true FP could be `5–15 %`, which is not a strong defense of a fairness threshold. Citation: `test/incus/step1-rate-spread-analysis.py:121-129`; `docs/pr/line-rate-investigation/step1-plan.md:429-434`.
- #5 CLOSED: the schema fix is real: the request key is JSON `"type"` via `ControlRequest { #[serde(rename = "type")] pub request_type }`, the response envelope is top-level `.status`, and the actual `ProcessStatus` fields are `per_binding`, `cos_interfaces`, and `filter_term_counters`; the capture script now documents and uses that shape. Citation: `userspace-dp/src/protocol.rs:625-627,719-736,980-985`; `test/incus/step1-capture.sh:29-35,119-131,396-418`.
- #6 STILL PARTIAL: the script now gates all three named failure paths in code, but only partially safely: CoS-apply failure halts via `exit 3`, failover mid-run is turned into `SUSPECT`, and sampler socket timeouts become `_error=control_socket_timeout` lines that trip `I6`; however, the CoS-apply halt path has no rollback and can stop after live state has already changed. Citation: `test/incus/step1-capture.sh:106-123,192-223,276-288,322-327,377-389`; `test/incus/apply-cos-config.sh:39-64`.
- #7 STILL PARTIAL: §4 never says that a single false `A` is acceptable even though the verified per-cell FP is `0.0638`, which implies `12 * 0.0638 = 0.7656` expected false `A` verdicts and `P(at least one false A in 12 cells) = 0.5467`; §8 only partially handles this by requiring `A` on `>= 50 %` of cells before Step 2 is driven by `A`. Citation: `docs/pr/line-rate-investigation/step1-plan.md:506-510,725-726`; ran calc, output=`expected_false_A_12_cells=0.7656`, `p_at_least_one_false_A_12_cells=0.5467`.
- #8 NEW FINDING: there is no committed policy to re-derive `Y` when new baseline data arrives and changes the 4-cell spread materially; the doc only says reviewers can rerun the script, not that baseline updates must recompute and re-approve `Y`. Citation: `docs/pr/line-rate-investigation/step1-plan.md:387-410,768-771`.
- #9 NEW FINDING: `exit 3` on CoS-apply failure does not leave the cluster in a cleanly restored state, because `apply-cos-config.sh` commits the destructive deletes first and only then does the strict merge/commit; if phase 2 fails, `step1-capture.sh` halts immediately with no rollback, leaving live state in post-delete `no-cos`. Citation: `test/incus/apply-cos-config.sh:39-64`; `test/incus/step1-capture.sh:200-203,214-215,121-123`.

## Round 4 verification

ROUND 4: plan-ready NO — Verdict B still lacks a healthy-CoS calibration for the `B_park` leg, so a higher-but-healthy shaped CoS regime can still false-trigger the Step-2 MQFQ path.

- 1 CLOSED: `python3 test/incus/step1-rss-multinomial.py --skewed-worker0 0.56` on this branch printed `max>=9 OR min<=0  -> per-cell fire_rate=0.6302` and `N= 8  max>=9 -> 0.9949`, matching `§4.2`'s rounded `0.63` / `0.9949` claims (`docs/pr/line-rate-investigation/step1-plan.md:332-365`; `test/incus/step1-rss-multinomial.py:141-200`).
- 2 CLOSED: `python3 test/incus/step1-rate-spread-analysis.py` printed `Y rounded for plan: 2.72` and `Y 95% CI: [1.8208, 2.8765]`, which rounds to `[1.82, 2.88]` exactly as claimed. Re-runs with seed `42` twice and alternate seeds `1/2/7/99` produced the same CI on this dataset, so the current script output is reproducible across runs (`test/incus/step1-rate-spread-analysis.py:145-200`; `docs/pr/line-rate-investigation/step1-plan.md:669-693`).
- 3 PARTIAL: `apply-cos-config.sh` does implement `commit check` -> `commit` -> post-commit `show class-of-service interface` verification, with `exit 4` / `exit 5` / `exit 6` for check-fail / commit-fail / verify-fail (`test/incus/apply-cos-config.sh:64-86,88-127,129-163`). The rollback sequence is syntactically valid because the CLI accepts `rollback <N>` in config mode and then a separate `commit` (`pkg/cli/cli_dispatch.go:322-330`; `pkg/configstore/store.go:887-910`; `testing-docs/standalone-vm.md:137-142`). But the plan's `rollback 1 | commit` wording is shorthand, not literal CLI syntax, and the plan text names exit `4` and `6` but never explicitly documents the script's `exit 5` path (`docs/pr/line-rate-investigation/step1-plan.md:741-750,941-956`).
- 4 CLOSED: §4.6 now explicitly defines the neighbor relation as `same direction, different ports` and `same port, different CoS state where applicable` (`docs/pr/line-rate-investigation/step1-plan.md:633-649`).
- 5 CLOSED: the "Y=2.72 is already ~97.5th percentile" angle does not hold on the committed data. Exact enumeration of all `4^4 = 256` bootstrap resamples from `p520[1-4]-fwd.json` gave local output `orig_Y=2.718587`, `percentile_le=0.7344`, and `pct_0.975=2.876465`, so the point estimate sits around the 73rd percentile of the bootstrap distribution, not the 97.5th. The CI is still wide, but this specific overfit claim is not supported (`test/incus/step1-rate-spread-analysis.py:155-184`; `docs/pr/line-rate-investigation/step1-plan.md:669-693`).
- 6 NEW FINDING: HIGH. §4.7 only re-derives `Y` when new baseline cells arrive (`docs/pr/line-rate-investigation/step1-plan.md:675-693`). The second leg of Verdict B, `B_park >= 100/s`, is still defended only by narrative and by the structurally-zero `no-cos` case (`docs/pr/line-rate-investigation/step1-plan.md:477-492`), which is not a healthy shaped-CoS baseline. If healthy CoS quantization / Cubic oscillation can raise both rate spread and queue-token parks in shaped cells, the plan can still fire B when it should not, and §8 would then steer Step 2 into MQFQ/shaper work on a false premise (`docs/pr/line-rate-investigation/step1-plan.md:887-889`). This remains a gating hole for the multi-week next-work decision.
- 7 CLOSED: a daemon crash in the gap between phase-1 `commit check` and phase-2 `commit` does not need a config recovery path, because phase 1 exits configure mode and discards the candidate before phase 2 starts. The remote CLI exits config mode on process shutdown (`cmd/cli/main.go:208-210`), `ExitConfigure` RPC tears down the session (`pkg/grpcapi/server_config.go:34-37`), and the store clears `candidate` on exit (`pkg/configstore/store.go:246-263`). A crash in that gap leaves live config at the pre-apply state.
- 8 CLOSED: the `0.8538` probability is the `N=4` case from §4.2 (`docs/pr/line-rate-investigation/step1-plan.md:352-355`), not the 60-minute rescope gate. The actual rescope rule keeps the 8 forward cells (`docs/pr/line-rate-investigation/step1-plan.md:858-864`), and §4.6 refuses to apply the investigation-level A rule below `N_valid = 8` (`docs/pr/line-rate-investigation/step1-plan.md:633-647`). So the plan's gated next-work decision still rests on the `N=8`, `0.9949` case, not `0.8538`.
- 9 NEW FINDING: LOW. §4.6 says `P(≥ 2 of 8 cells fire | fair RSS) = 0.139` (`docs/pr/line-rate-investigation/step1-plan.md:646-648`), but using the same independence assumption the section already uses at `docs/pr/line-rate-investigation/step1-plan.md:620-622` with per-cell `p = 0.0638` gives local calc output `0.0881384187574415`, not `0.139`. That arithmetic bug is conservative rather than flattering, but it should still be corrected.

## Round 5 verification

ROUND 5: plan-ready NO — the with-cos `Z_cos` gating loop is still not cleanly closed before Step 2 action, the `k_B ≥ 3` with-cos rule is still undefended for the targeted failure modes, and §4.2 still contains an internal park-rate arithmetic error.

1. [PASS] "`B_park = Z_nocos = 10 parks / s` on no-cos cells and `B_park = Z_cos = 500 parks / s` on with-cos cells (split derivation below; Z_cos is a calibration-gap placeholder)" and "`Multiplier rule.` In lieu of direct calibration, `Z_cos = 5 × Z_nocos = 500 parks / s`. Rationale:"
2. [PASS] "`single-cell Verdict B firing under `with-cos` is treated as TENTATIVE (reported but not trusted as an investigation-level signal); the §4.6 k ≥ 2 rule is tightened to k ≥ 3 for with-cos Verdict B until the calibration gap closes.`" and "`A single with-cos Verdict B is reported as TENTATIVE in findings.md and does NOT trigger Step 2 AFD work on its own.`"
3. [PASS] "`Step 2 MUST ALSO include a Z_cos re-calibration task (capture park-rate from the healthy shaped baseline, apply mean + 2σ, update the plan) before any AFD fix is merged.`"
4. [PASS] "`P(≥ 2 of 8 cells fire | fair RSS) = 0.0881`" and "`the ≥ 2 threshold amplifies signal-to-noise by ~11× versus the single-cell rule (0.9949 / 0.0881 ≈ 11.3 versus 0.6302 / 0.0638 ≈ 9.9 for single-cell).`" `0.139` NOT FOUND. `~7x` NOT FOUND.
5. [FAIL] "`The 5× multiplier is specifically chosen to be large enough that healthy shaped oscillation (1–3 parks per tick on average across the cell's queues, ~10–30 / s × 10+ queues ≈ 100–300 / s integrated) does NOT exceed it`" is internally inconsistent with "`The shaping tick period is 1 ms ... giving a theoretical upper bound of 1000 parks / s if the queue parks exactly once per tick.`" At `1 ms`, `1–3 parks per tick` is not `~10–30 / s`.
6. [AMBIGUOUS] "`Step 2 is explicitly required to capture park-rate from at least two of the 8 with-cos forward cells on the first complete Step 1 run and re-derive `Z_cos` via mean + 2σ before accepting any Verdict B as final`" and "`If **k_B ≥ 50 %** of valid cells (with `k_B ≥ 2` on no-cos, `k_B ≥ 3` on with-cos per §4.6 calibration-gap tightening): Step 2 is AFD / Phase 5 MQFQ ↔ shaper-interaction work.`" The doc writes a recalibration path, but it assigns the re-derivation to Step 2 and still allows Step 2 work to start from placeholder-threshold `with-cos` B; it does not cleanly say "Step 1's own data produces the real `Z_cos`, then `with-cos` B becomes actionable."
7. [FAIL] "`Verdict B under `with-cos` requires `k_B ≥ 3` out of the 8 with-cos cells`" and "`capture park-rate from at least two of the 8 with-cos forward cells on the first complete Step 1 run`." NOT FOUND: any defense of why the `k_B ≥ 3` threshold is the right trigger for the experiment's targeted failure modes. The text also muddles the matrix by referring to "`8 with-cos forward cells`" even though Step 1 defines 4 with-cos forward cells and 4 with-cos reverse cells.

### Remaining issues

- BLOCKER: The `Z_cos = 500` placeholder still does not have a clean "Step 1 captures the real baseline, then re-derive `Z_cos`, then act on `with-cos` B" loop; §8 still allows Step 2 AFD work to start before that re-derivation completes.
- BLOCKER: The `k_B ≥ 3` with-cos rule is not defended for the failure modes Step 1 is supposed to detect, and the same section misstates the matrix as "`8 with-cos forward cells`".
- LOW: The `1–3 parks per tick` / `~10–30 / s × 10+ queues ≈ 100–300 / s integrated` sentence is arithmetic noise inside the `5×` rationale and should be corrected.

## Round 6 verification

1. PASS: `§8` now states the gate imperatively and unambiguously. The file says: "`No Step 2 AFD work starts — not design, not scoping, not an issue — until Step 2's first sub-task captures park-rate from at least two with-cos forward shaped cells and re-derives Z_cos via mean + 2σ`" and then tightens it again with "`any with-cos Verdict B — even at `k_B ≥ 2 of 4` — is **TENTATIVE** and must NOT trigger AFD / Phase 5 work.`" (`§8`, lines 1076-1088). That is a clear imperative "no Step 2 until..." rule.

2. PASS: `§4.6` now uses the correct 4-cell with-cos matrix and `k_B ≥ 2` threshold. The text says "`Verdict B is only applicable on ... **with-cos forward cells** ... which is **4 cells, not 8**`" and "`Fire the investigation-level with-cos Verdict B iff `k_B ≥ 2` of the 4 with-cos forward shaped cells.`" (`§4.6`, lines 762-779). The probability math is also consistent: "`P(≥ 2 of 4 | independent cells) = 1 − (1−p)^4 − 4·p·(1−p)^3`" and the table gives "`0.10 -> 0.0523`" (`§4.6`, lines 793-806). Substituting `p = 0.10`: `(0.90)^4 = 0.6561`, `4×0.10×(0.90)^3 = 4×0.10×0.7290 = 0.2916`, so `1 − 0.6561 − 0.2916 = 0.0523`. I did not find an active contradictory with-cos aggregation value; the summary-table shorthand "`aggregate with-cos FP 0.052 at `k_B ≥ 2 of 4``" is consistent rounding (`§4.2` table, line 641).

3. PASS: `§4.2`'s parks-per-tick arithmetic is now correct. The file states "`with tick period `T = 1 ms` and a target steady-state per-queue park rate `Z_per_queue ≈ 10–30 / s` ... expected parks per tick per queue = `Z × T = (10–30) × 0.001 = 0.01–0.03``" and then "`Across ~10 active CoS queues for a cell, the aggregated per-tick expectation is `0.1–0.3` parks per tick, and the aggregated per-second rate is `100–300 / s`.`" (`§4.2`, lines 546-553). The arithmetic checks: `10×0.001 = 0.01`, `30×0.001 = 0.03`; multiplying by `~10` queues gives `0.1–0.3` parks/tick, and at `1000` ticks/s that is `100–300 / s`.

4. LOW: two of the three `§9` cross-cell probabilities are fully derivable from stated per-cell rates, but the no-cos B case only gives an upper bound, not an exact per-cell `p_{B0}`. For A, `§9` says "`per-cell FP 0.0638`" and "`P(≥ 1 false A across 8 cells) = 0.4099`" (`lines 1117-1119`); the math is `p_A = 0.0638`, so `P(≥1 of 8) = 1 − (1 − 0.0638)^8 = 1 − 0.9362^8 = 0.409868...`, which rounds to `0.4099`. For B-no-cos, `§9` says "`per-cell FP ≤ 0.05`" and "`P(≥ 1 false B) ≤ 0.1855`" (`lines 1119-1120`); exact `p_{B0}` cannot verify from file — missing, but using the stated ceiling gives `1 − (1 − 0.05)^4 = 1 − 0.95^4 = 1 − 0.81450625 = 0.18549375`, so the file's `≤ 0.1855` is a correct upper bound. For B-with-cos, `§9` says "`per-cell FP assumed 0.10`" and "`P(≥ 1 false B) = 0.3439`" (`lines 1121-1123`); the math is `p_Bc = 0.10`, so `1 − (1 − 0.10)^4 = 1 − 0.90^4 = 1 − 0.6561 = 0.3439`.

5. PASS: the exact `k_B = 1 of 4` tentative case now has an explicit disposition. `§4.6` says "`Single-cell with-cos Verdict B (k_B = 1 of 4) is reported as TENTATIVE in findings.md and does NOT trigger Step 2 AFD work on its own.`" (`lines 834-838`). `§8` reinforces the same action: "`any with-cos Verdict B — even at `k_B ≥ 2 of 4` — is **TENTATIVE** and must NOT trigger AFD / Phase 5 work`" until the Z-cos gate is cleared (`lines 1082-1085`). That is concrete enough to dispose of the below-threshold 1-of-4 case.

6. PASS: the "`≈1.7–5× headroom`" range is quantified in-file, and it is explicitly presented as assumption-driven arithmetic rather than a reference measurement. `§4.2` derives "`aggregated per-second rate is `100–300 / s``" and then says "`Z_cos = 500 / s` threshold sits comfortably above that envelope (≈1.7–5× headroom)`" (`lines 552-555`). The ratio comes directly from the stated envelope: `500/300 ≈ 1.67` and `500/100 = 5`. The source is not measured baseline data; it is the file's own "`order-of-magnitude estimate of healthy oscillation`" (`lines 547-548`). Because `§8` separately blocks any with-cos Step-2 action until Z_cos is re-derived from Step 1 data, this assumed headroom is documented rationale, not the final action gate.

7. BLOCKER: one numeric/policy contradiction remains inside the with-cos Verdict-B math. `§4.2` still says "`If real healthy shaped park rate is near 500 / s ... FP could exceed the ≤ 5 % target band; the k ≥ 3 multi-cell rule absorbs that risk.`" (`lines 573-578`), but `§4.6` rewrites the active rule to "`Fire the investigation-level with-cos Verdict B iff `k_B ≥ 2` of the 4 with-cos forward shaped cells`" and summarizes it again as "`k_B ≥ 2 of 4` (50%). Aggregate FP ≈ 0.052 at p = 0.10.`" (`lines 777-812, 834-842`). That stale "`k ≥ 3`" sentence is not just historical context; it sits in the current threshold derivation and directly contradicts the operative `k_B ≥ 2 of 4` rule.

ROUND 6: plan-ready NO — 1 blocker(s) remain.
