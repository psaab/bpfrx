# Plan Review: #819 Step-2 Discriminator Design

> Date: 2026-04-21
> Reviewer: Codex
> Disposition: hostile/pedantic
> Source 1 note: `gh issue view 819` was unavailable from this sandbox because outbound network is blocked. Findings below rely on the checked-in sources that were readable.

## SEVERITY: HIGH — 1. §3 Option A overclaims what 5-second `sched_switch` counts can discriminate

**Symptom.** §3.1 sells P1 as "cleanly dispositive" for M3, but the proposed reducer does not measure the quantity that matters. It records per-block switch counts, not off-CPU duration. A 50 us preemption inside a 5 s block is `50e-6 / 5 = 1e-5 = 0.001%` duty cycle. On top of that, the two load-bearing cells already have D1 mass in essentially every 5 s block, so the x-axis the plan wants to correlate is nearly flat. This is not a discriminator; it is wishful counting.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:133-145` claims P1 is cheaply dispositive; `docs/pr/819-step2-discriminator-design/plan.md:283-293` reduces the data to per-second switch counts and blockwise correlation; `docs/pr/819-step2-discriminator-design/plan.md:421-443` bases the verdict on 12 five-second points; `test/incus/step1-histogram-classify.py:120-156` confirms the histogram side is exactly 12 non-overlapping 5 s blocks; `docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/hist-blocks.jsonl:1-12` shows p5201-fwd has buckets 3-6 mass in every block at roughly 0.97-1.00; `docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/hist-blocks.jsonl:1-12` shows p5202-fwd is likewise high in every block at roughly 0.79-0.93; `docs/pr/816-step1-rerun/findings.md:125-140` identifies these two shaped-forward cells as the load-bearing D1 evidence.

**Concrete mitigation.** P1 must switch from "switch count by block" to "off-CPU time and max off-CPU gap by block", or else stop claiming `OUT` on M3. If the design insists on correlation, make 1 s bins the primary plan, not an afterthought, and pre-register a minimum detectable off-CPU burden relative to the D1 signal on p5201/p5202.

## SEVERITY: HIGH — 2. §4 matrix cells pretend to have IN/OUT thresholds they do not have

**Symptom.** The matrix is written as if the design already knows what each probe's `IN` and `OUT` data looks like. It does not. Several cells have no named threshold; at least two cannot be named from the currently proposed telemetry.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:215-221` marks the matrix cells; `docs/pr/819-step2-discriminator-design/plan.md:225-240` calls P1 and P3 the most valuable probes; `docs/pr/819-step2-discriminator-design/plan.md:330-371` leaves P2/P3 as sketches; `docs/pr/819-step2-discriminator-design/plan.md:445-449` explicitly says P2/P3 analysis is not filled in yet; `docs/pr/819-step2-discriminator-design/plan.md:475-497` nevertheless uses those probes as decision-tree leaves.

- `M1 / P3 IN`: the plan says "retry-counter + sendto-kick-latency ARE the M1 fingerprint," but nowhere names how much retry activity, how much sendto latency, or what correlation strength is sufficient. That is an unnamed threshold. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:217`, `docs/pr/819-step2-discriminator-design/plan.md:353-371`, `docs/pr/819-step2-discriminator-design/plan.md:475-483`.
- `M1 / P3 OUT`: "retry counter flat; sendto kick latency bounded" is not operational unless "flat" and "bounded" are numeric. They are not. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:479-483`.
- `M2 / P2 IN`: the plan says "`napi_complete_done` cadence is the M2 signature" while also admitting it does not yet know whether the relevant cadence is even visible on the target surface. That is not an `IN / OUT` cell; it is unresolved probe viability. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:218`, `docs/pr/819-step2-discriminator-design/plan.md:346-351`, `docs/pr/819-step2-discriminator-design/plan.md:490-497`.
- `M2 / P2 OUT`: cannot be named at all until the probe surface, queue mapping, and cadence metric are defined. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:340-351`, `docs/pr/819-step2-discriminator-design/plan.md:447-449`.
- `M3 / P1 IN`: a threshold exists (`rho >= 0.6`), but it is borderline and tied to count-only data rather than off-CPU duration. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:432-435`.
- `M3 / P1 OUT`: "worker on-CPU through every D1 gap" cannot be proven from switch counts. That requires off-CPU duration or timestamp-aligned gaps, which the plan does not collect. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:436-443`, `docs/pr/819-step2-discriminator-design/plan.md:464-466`.
- `M4 / P4 IN/OUT`: there are no named exit families, no thresholds, and no read-off rules. The cell is labeled dispositive anyway. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:220`, `docs/pr/819-step2-discriminator-design/plan.md:101-107`, `docs/pr/819-step2-discriminator-design/plan.md:574-579`.
- `M5 / P5 IN/OUT`: there is no burstiness statistic, no threshold, and no matching rule between client-send and server-observed timing. Evidence: `docs/pr/819-step2-discriminator-design/plan.md:221`, `docs/pr/819-step2-discriminator-design/plan.md:108-114`, `docs/pr/819-step2-discriminator-design/plan.md:587-593`.

**Concrete mitigation.** Stop labeling a cell `IN / OUT` until the design doc names the observable, the threshold, and the negative-control condition for that cell. Until then, those cells are `INF` or `UNC`, not dispositive.

## SEVERITY: MEDIUM — 3. §5.1 privilege handling is plausible but unproven on `loss:xpf-userspace-fw0`

**Symptom.** The plan hand-waves perf privilege with "loosen the sysctl for the capture window" but never proves the live VM is compatible with `sched:sched_switch` tracepoint capture. The repo evidence says VM-level `perf record` is normal and runtime sysctl management exists, but it does not say the live `kernel.perf_event_paranoid` already satisfies this probe.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:322-328` gives the privilege requirement and the fallback; `test/incus/setup.sh:270-281` shows the VM setup installs `linux-perf` and manages sysctls at runtime, but does not set `kernel.perf_event_paranoid`; `docs/testing.md:136-142`, `docs/test_env.md:130-132`, and `docs/perf-analysis-ipv6.md:19-22` all assume VM-level `perf record` usage is supported. None of those sources record the actual live paranoid value or `sched:sched_switch` availability on `loss:xpf-userspace-fw0`.

**Concrete mitigation.** Add a preflight gate: record `sysctl kernel.perf_event_paranoid`, `perf list sched:sched_switch`, and a 1 s smoke `perf record -e sched:sched_switch -t "$WORKER_TIDS" -- sleep 1`. State explicitly that runtime sysctl change is the intended path if needed; do not imply VM image rebuild unless the tracepoint or `perf` binary is actually missing.

## SEVERITY: LOW — 4. §5.2 asks the wrong NAPI question for the load-bearing cells

**Symptom.** The plan worries that P2 may be blocked because the guest RX side is `virtio-net`. For the load-bearing shaped-forward cells, that is the wrong topology. The checked-in audit says the hot interfaces are `ge-0-0-1` and `ge-0-0-2` in ZeroCopy; only `ge-0-0-0` is the `virtio-net` copy-mode path.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:336-351` frames the P2 uncertainty around a `virtio-net` guest RX side; `docs/pr/line-rate-investigation/step0-audit.md:18-27` says `ge-0-0-1` and `ge-0-0-2` bind in ZeroCopy while only `ge-0-0-0` is Copy mode on `virtio-net`; `docs/pr/line-rate-investigation/step0-audit.md:253`, `docs/pr/line-rate-investigation/step0-audit.md:313-315` state `ge-0-0-0` is the non-primary `virtio-net` path; `docs/pr/line-rate-investigation/step1-plan.md:772-779` and `docs/pr/line-rate-investigation/step1-plan.md:920-924` identify the with-cos forward cells and the shaped `5201` discriminator traffic as the relevant workload.

**Concrete mitigation.** Rewrite the design-doc-level question. The real open question is which RX queue / CPU / interface on `ge-0-0-1` or `ge-0-0-2` to instrument for p5201-fwd and p5202-fwd, not whether `virtio-net` NAPI exists at all.

## SEVERITY: HIGH — 5. §6 never states whether the plan tolerates per-cell mechanism splits

**Symptom.** The capture protocol re-runs only the two load-bearing cells, but the decision tree acts as if the outcome is one global mechanism verdict. There is no rule for p5201-fwd saying "M1" while p5202-fwd says "M3", or vice versa. "Joint fires are possible" is not enough; that line speaks about multiple mechanisms in general, not about cross-cell disagreement and issue-close criteria.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:116-118` allows joint fires in principle; `docs/pr/819-step2-discriminator-design/plan.md:377-388` reduces capture scope to p5201-fwd and p5202-fwd only; `docs/pr/819-step2-discriminator-design/plan.md:458-497` closes #819 on singular P1/P3/P2 outcomes without a per-cell split branch.

**Concrete mitigation.** Add an explicit global-close rule: #819 can close on a single mechanism only if both load-bearing cells point to the same dominant mechanism. Otherwise the design doc must emit a split-mechanism outcome, keep both cells in the subsequent probe rounds, and describe how #793 Phase 4 scopes heterogeneity instead of pretending it is one thing.

## SEVERITY: HIGH — 6. §7.1 uses a borderline Spearman cutoff without admitting that it is borderline

**Symptom.** The plan sets `rho >= 0.6` as `M3 IN` on `N = 12` points and then quietly adds "or a clearly visible trend". That is exactly how hand-wavy statistics leak back into the doc after the repo already spent multiple rounds burning them out. With only 12 five-second blocks, this cutoff sits right on the significance cliff. The text never acknowledges that and never requires an exact p-value.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:421-443` defines the analysis on 12 block points and sets `rho >= 0.6`, `rho <= 0.3`, and "clearly visible trend"; `test/incus/step1-histogram-classify.py:120-156` confirms the 12-point design; `docs/development-workflow.md:73-78`, `docs/development-workflow.md:91-95` require derived thresholds, not vibes.

**Concrete mitigation.** Acknowledge in the plan that the chosen `rho >= 0.6` threshold is only barely significant at `N = 12`. Then tighten the rule: require exact `spearmanr` p-values, drop "clearly visible trend", and preferably make 1 s blocks the primary analysis if P1 is supposed to carry an `IN / OUT` claim.

## SEVERITY: MEDIUM — 7. §8 omits the real worst-case budget behind P1→P3→P2

**Symptom.** Option A is justified as "cheap per round" and the preamble claims "2-3 plan rounds (shorter than #816)", but the budget table counts only raw capture minutes. The actual worst case is P1 capture + analysis + review, then a P3 implementation issue + capture + analysis + review, then a P2 issue + capture + analysis + review, plus the explicit "rerun P1 at 1 s resolution" branch. That is precisely the kind of budget omission the workflow forbids.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:6-8` claims 2-3 rounds and "shorter than #816"; `docs/pr/819-step2-discriminator-design/plan.md:133-155` argues for Option A on cost grounds; `docs/pr/819-step2-discriminator-design/plan.md:399-405` budgets only capture wall-clock; `docs/pr/819-step2-discriminator-design/plan.md:466-471`, `docs/pr/819-step2-discriminator-design/plan.md:479-497` explicitly create second and third conditional rounds; `docs/development-workflow.md:73-78` requires an execution matrix with budgets; `docs/development-workflow.md:122-123` says 2-4 plan-review rounds are typical even before implementation lag is counted.

**Concrete mitigation.** Add a worst-case end-to-end schedule table for Option A that includes design-doc rounds, follow-up implementation issue latency per probe, capture time, and analysis time. If Option A is still the recommendation after honest budgeting, fine. But write the honest budget down.

## SEVERITY: MEDIUM — 8. §12 overstates what the regime split proves about M4 and M5

**Symptom.** The deferral logic says virtualization jitter or iperf3 burstiness would affect shaped and unshaped cells equally, therefore their prior is low. That is too strong. A workload-conditional mechanism is entirely plausible: MQFQ-imposed idle gaps can create opportunities for hypervisor descheduling or client burst clustering that do not appear on unshaped line-rate cells. Regime split alone does not kill that counterexample.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:580-586` uses equal-impact reasoning to deflate M4; `docs/pr/819-step2-discriminator-design/plan.md:591-593` does the same for M5; `docs/pr/816-step1-rerun/findings.md:125-136` says the load-bearing cells are specifically the shaped-forward cells and ties them to the MQFQ throttle / park signature; `docs/pr/816-step1-rerun/findings.md:144-172` explicitly shows the with-cos forward cells split into shaped vs line-rate operating clusters.

**Concrete mitigation.** Keep M4 and M5 deferred if you want, but weaken the rationale to "low prior, not excluded." Add an un-deferral trigger for workload-conditional behavior, e.g. shaped-only guest off-CPU gaps with no M1/M2 evidence, or a cheap client-side symptom check before declaring those mechanisms uninteresting.

## SEVERITY: HIGH — 9. §5.3's "~200-line Rust change" is not grounded, and it cites the wrong `sendto()` site

**Symptom.** The plan says the retry loop is "around the sendto kick site (line 284)" and that adding a retry counter plus sendto-kick-latency histogram is a "~200-line Rust change on top of the existing sidecar infrastructure." That is wrong in two ways. First, `tx.rs:284` is the RX wake path's `sendto()` after `poll(POLLIN)`, not the TX kick path. Second, the existing sidecar is per-descriptor submit→completion state; a sendto-kick latency histogram is per-kick syscall telemetry with separate wire-format and snapshot plumbing.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:355-363` makes the claim; `userspace-dp/src/afxdp/tx.rs:249-293` shows line 284 is inside `maybe_wake_rx`, with `poll(POLLIN)` for RX wake followed by a TX-completion `sendto()`; `userspace-dp/src/afxdp/tx.rs:6429-6448` shows the actual TX wake / kick path in `maybe_wake_tx`; `docs/pr/812-tx-latency-histogram/plan.md:121-124`, `docs/pr/812-tx-latency-histogram/plan.md:189-205` describe the current sidecar as frame-offset keyed submit/completion telemetry; `docs/pr/812-tx-latency-histogram/plan.md:545-580` and `docs/pr/812-tx-latency-histogram/plan.md:1213-1224` show that a single added histogram already needed protocol, snapshot, coordinator, tests, and bench work; the as-built code spans `userspace-dp/src/protocol.rs:1333-1338`, `userspace-dp/src/afxdp/worker.rs:4240-4247`, `userspace-dp/src/afxdp/umem.rs:237-254`, `userspace-dp/src/afxdp/umem.rs:1931-1941`, and `userspace-dp/src/afxdp/coordinator.rs:1428-1440`.

**Concrete mitigation.** Fix the cited TX kick site to `maybe_wake_tx`, stop using a line-count estimate as a proxy for scope, and replace it with a file-scope change list: hot-path counter location(s), owner snapshot state, wire-format additions, coordinator copy, parser/analysis changes, and tests. Until that is done, the P3 cost argument is ungrounded.

## SEVERITY: LOW — 10. §11's #817 coupling is a conditional replan trigger, not a present blocker

**Symptom.** The "H-STOP-D1" label sounds stronger than the actual coupling. The checked-in evidence says the forward load-bearing cells have enormous margin under Path B, so #817 is parallel work unless it unexpectedly flips a forward-cell sign. That is a low-probability replan trigger, not a reason to pause #819 today.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:556-560` pauses only if #817 flips a load-bearing forward-cell sign; `docs/pr/819-step2-discriminator-design/plan.md:608-617` already describes the coupling as low risk; `docs/pr/816-step1-rerun/findings.md:16-33` says Path B matters when downstream decisions depend on Monte-Carlo precision but also calls D1 risk low; `docs/pr/816-step1-rerun/findings.md:45` says p5201-fwd and p5202-fwd have enormous robustness margin; `docs/pr/816-step1-rerun/findings.md:349-357` says those two cells carry the verdict regardless of the baseline sensitivity cleanup.

**Concrete mitigation.** Optional wording cleanup only: rename H-STOP-D1 to an explicit "replan trigger if Path B flips a forward cell." The logic itself is not the problem.

## SEVERITY: MEDIUM — 11. Missing section: there is no feasibility / preflight gate, and G1-G7 would not catch that

**Symptom.** G1-G7 can all pass while the chosen probes are still unrunnable or attached to the wrong surface. That is a gap in the review contract itself. P1 has privilege uncertainty, P2 has probe-surface uncertainty, and P4 has access uncertainty. None of the current gates require the design doc to prove those probes are executable before using them in the decision tree.

**Evidence.** `docs/pr/819-step2-discriminator-design/plan.md:513-530` defines G1-G7 and does not include a feasibility gate; `docs/pr/819-step2-discriminator-design/plan.md:322-328` leaves P1 dependent on live privilege state; `docs/pr/819-step2-discriminator-design/plan.md:346-351` leaves P2 dependent on unresolved target-surface questions; `docs/pr/819-step2-discriminator-design/plan.md:574-579` leaves P4 contingent on external access.

**Concrete mitigation.** Add a dedicated `Prerequisites / Feasibility` section and a `G8` gate: every probe used as a decision-tree branch must have a one-command smoke test proving tooling availability, capture privileges, target surface, and artifact emission path on the actual cluster.

## Terminal Summary

HIGH findings: 5
MEDIUM findings: 4
LOW findings: 2

ROUND 1: PLAN-READY NO — open HIGH/MEDIUM items: §3 Option-A/P1 granularity math, §4 matrix IN/OUT thresholds, §5.1 perf privilege preflight, §6 per-cell split handling, §7.1 borderline Spearman rule, §8 worst-case serial budget, §12 M4/M5 deferral rationale, §5.3 wrong TX-kick site / ungrounded scope estimate, and the missing feasibility gate.

## Round 1 response

**Architect: Round 2 plan posted at `plan.md`. Disposition per finding:**

### HIGH findings

- **HIGH-1 — §3 / §5.1 P1 granularity math.** **Fixed.** Redesigned P1 post-processing from "switch count per block" to "off-CPU duration histogram on the same 16 log2 buckets as `T_D1`", with a per-block `off_cpu_time_3to6,b` aggregate (buckets 3-6, 4-64 µs). The reducer now pairs `sched_switch` with `sched_stat_runtime` + `sched_wakeup` to extract exact off-CPU durations. Cite: `plan.md` §5.1 "Post-processing — off-CPU duration by log2 bucket (HIGH-1 fix)" and §7.1 read-off rules. The M3 IN/OUT decision is now `ρ(T_D1,b, off_cpu_time_3to6,b)` AND a 1% total-off-CPU-mass floor.
- **HIGH-2 — Matrix IN/OUT thresholds.** **Fixed.** Every IN/OUT cell in §4 now references a named threshold T1-T5 in §4.1. Cells that cannot be named (M4 guest-side-only) labeled UNC. Cite: `plan.md` §4, §4.1.
- **HIGH-3 — Per-cell mechanism split not handled.** **Fixed.** New §6.3 specifies a per-cell branching rule. If p5201-fwd and p5202-fwd diverge at any probe, #819 emits a split-mechanism outcome and may spawn per-cell Phase 4 sub-scope issues. Cite: `plan.md` §6.3, §8.1-8.3.
- **HIGH-4 — Spearman ρ ≥ 0.6 borderline.** **Fixed.** Replaced with **ρ ≥ 0.8** (IN) and **ρ ≤ 0.3** (OUT), explicit inconclusive band. Justification: Monte-Carlo under exchangeable null at N=12 yields P(|ρ|≥0.8) ≈ 0.001 (FP < 0.1%). Inconclusive band routes to a 1-s re-bin (no re-capture). Cite: `plan.md` §7.1.
- **HIGH-5 — Wrong `tx.rs` line for sendto kick.** **Fixed and verified.** Line 284 is `maybe_wake_rx`; actual TX kick is `maybe_wake_tx` at line 6429. P3 instrumentation site corrected; "~200-line" estimate replaced with file-scope change list. Cite: `plan.md` §5.3.

### MEDIUM findings

- **MED-6 — P1 perf privilege preflight.** **Fixed.** §5.1 adds explicit four-command preflight smoke test (sysctl read, tracepoint list, 1-s perf-record smoke, runtime sysctl-change procedure). bpftrace fallback specified.
- **MED-7 — Worst-case serial budget not named.** **Fixed.** New §3.4 honest-budget table enumerates 5 scenarios. Parallel-escape clause in §3.1 #4 and §8.1 caps serial worst case at 2 rounds expected, 3 worst.
- **MED-8 — M4/M5 regime-split deferral not airtight.** **Fixed.** §12 acknowledges workload-conditional counterexample for both. Deferral weakened from "excluded" to "low prior, not excluded." Explicit un-deferral triggers + named residual risk.
- **MED-11 — Missing feasibility gate.** **Fixed.** New G8 in §9 — every decision-tree probe ships a one-command cluster smoke test before implementation issue filed.

### LOW findings

- **LOW-9** — Subsumed by HIGH-5.
- **LOW-10 — H-STOP-D1 too strong.** **Fixed via rename** to RT-1; "Does NOT pause #819" text. Cite §11.

**Disposition:** Round 2 plan addresses all 11 findings. Requesting Round 2 review.

## Round 2 verification

ROUND 2: PLAN-READY NO — HIGH-1, HIGH-2, MED-6, MED-7, MED-8, MED-11; new MEDIUM regression on the budget path

> Date: 2026-04-21
> Reviewer: Codex
> Disposition: hostile/pedantic
> Corrected after file-write confirmation: this section replaces the stale Round 2 verification that was based on an older `plan.md`.

### HIGH-1 — PARTIAL

**Evidence:** The Round 2 plan does switch P1 from raw switch counts to an off-CPU-duration design: M3 is now defined in terms of off-CPU time in buckets 3-6 (`docs/pr/819-step2-discriminator-design/plan.md:85-92`), §5.1 records `sched_switch` + `sched_stat_runtime` + `sched_wakeup` (`docs/pr/819-step2-discriminator-design/plan.md:207-224`), buckets durations into the same 16 log2 buckets as `tx_submit_latency_hist`, and defines the per-block `off_cpu_time_3to6,b` aggregate (`docs/pr/819-step2-discriminator-design/plan.md:226-235`). §7.1 then correlates `T_D1,b` against `off_cpu_time_3to6,b` instead of switch count (`docs/pr/819-step2-discriminator-design/plan.md:336-349`).

**Residual concern:** The reducer logic is still underspecified where it matters most. Step 2 says it pairs a switch-out with the next switch-in **or** `sched_wakeup`, and then treats that delta as "off-CPU duration" (`docs/pr/819-step2-discriminator-design/plan.md:228-229`). `sched_wakeup` is not the same thing as "running again"; it can undercount wake-to-run queue delay. `sched_stat_runtime` is listed in tooling but never given a reducer role. The noise-floor problem is materially improved, but the accounting rule is not yet rigorous enough to call fully resolved.

**Mitigation needed:** Rewrite the reducer contract so `sched_wakeup` is used for classification, not as an alternative interval terminator, and say explicitly what `sched_stat_runtime` contributes.

### HIGH-2 — PARTIAL

**Evidence:** The matrix now references named thresholds T1-T5 (`docs/pr/819-step2-discriminator-design/plan.md:181-203`). §4.1 contains numerical criteria for M1-M5: T3 with `ρ` and 1% duty-cycle floors, T1 with retry-count and latency cutoffs, T2 with p99 cadence cutoffs, T4 with exit-rate and correlation floors, and T5 with inter-send-time p99 plus correlation (`docs/pr/819-step2-discriminator-design/plan.md:193-199`).

**Residual concern:** This is much better, but still not fully machine-testable. T1, T2, T4, and T5 all hinge on "during T_D1-elevated blocks" or after time alignment, yet the plan never defines "T_D1-elevated" numerically and never specifies the alignment rule (`docs/pr/819-step2-discriminator-design/plan.md:196-199`). T1 also punts the middle band with "Calibration band set after first capture" (`docs/pr/819-step2-discriminator-design/plan.md:196`), which means the scriptable classifier is still incomplete.

**Mitigation needed:** Define `T_D1`-elevated blocks quantitatively and state the exact alignment / inconclusive-band rules, not just the IN/OUT extremes.

### HIGH-3 — RESOLVED

**Evidence:** §6.3 now exists and explicitly handles per-cell mechanism splits between p5201-fwd and p5202-fwd (`docs/pr/819-step2-discriminator-design/plan.md:322-333`). It states what happens when verdicts diverge: the IN-cell proceeds to its Phase 4 sub-scope while the OUT-cell continues the probe order, and #819 may spawn separate Phase 4 sub-scope issues (`docs/pr/819-step2-discriminator-design/plan.md:326-331`). §8 also evaluates branches per cell and includes split handling after P1 and P3 (`docs/pr/819-step2-discriminator-design/plan.md:356-378`).

### HIGH-4 — RESOLVED

**Evidence:** §7.1 now uses `ρ ≥ 0.8` for IN, `ρ ≤ 0.3` for OUT, and `0.3 < ρ < 0.8` as the inconclusive band (`docs/pr/819-step2-discriminator-design/plan.md:343-346`). It explicitly acknowledges the `N = 12` Spearman critical value problem, explains why `ρ ≥ 0.8` is safer, and states that the 1-second re-bin raises `N` to 60 with a tighter critical value (`docs/pr/819-step2-discriminator-design/plan.md:348-350`). The inconclusive path routes to a 1-second re-bin from the same `perf.data` (`docs/pr/819-step2-discriminator-design/plan.md:346`, `docs/pr/819-step2-discriminator-design/plan.md:365`).

### HIGH-5 — RESOLVED

**Evidence:** §5.3 now correctly identifies `maybe_wake_tx` at `userspace-dp/src/afxdp/tx.rs:6429` as the TX-kick site and the `sendto` call at line 6439 (`docs/pr/819-step2-discriminator-design/plan.md:279-282`). The repo confirms that site (`userspace-dp/src/afxdp/tx.rs:6429-6439`). The old "~200-line" estimate has been replaced by a file-scope change list covering hot-path code, owner snapshot state, wire format, coordinator copy, parser/analysis additions, and tests (`docs/pr/819-step2-discriminator-design/plan.md:283-290`).

### MED-6 — PARTIAL

**Evidence:** §5.1 now has a real preflight section: it checks `kernel.perf_event_paranoid`, checks the tracepoint exists, runs a 1-second `perf record` smoke, specifies the guest-side runtime sysctl change on `loss:xpf-userspace-fw0`, and includes a `bpftrace` fallback (`docs/pr/819-step2-discriminator-design/plan.md:250-267`).

**Residual concern:** The fix is substantial but not exact. The Architect claimed a four-command smoke; the actual preflight block is three smoke commands plus a separate remediation command (`docs/pr/819-step2-discriminator-design/plan.md:252-265`). That is close, but not what was claimed.

**Mitigation needed:** Either collapse the smoke into the promised four-command structure or stop claiming that exact shape.

### MED-7 — PARTIAL

**Evidence:** §3.4 now exists and contains a five-row end-to-end budget table with elapsed wall-time estimates, not just round counts (`docs/pr/819-step2-discriminator-design/plan.md:165-179`). §3.1 also adds a parallel-escape clause for the P1-inconclusive path (`docs/pr/819-step2-discriminator-design/plan.md:117-140`).

**Residual concern:** The budget story is internally inconsistent. §3.1 says the parallel-escape clause "caps the serial-round worst case at 2, not 3" (`docs/pr/819-step2-discriminator-design/plan.md:133-138`), but §3.4 still includes a three-round serial row for `P1 -> P3 -> P2` (`docs/pr/819-step2-discriminator-design/plan.md:167-178`). The escape clause only helps the P1-inconclusive branch; it does not eliminate the P1-OUT then P3-OUT then P2 serial path.

**Mitigation needed:** Fix the prose in §3.1 so it matches the budget table, or explain exactly which branch is capped at 2 rounds.

### MED-8 — PARTIAL

**Evidence:** §12 now explicitly acknowledges workload-conditional counterexamples for both M4 and M5 instead of claiming the regime split excludes them (`docs/pr/819-step2-discriminator-design/plan.md:413-421`). It also adds un-deferral triggers: for M4, §8.3 firing or P1 showing >1% off-CPU mass with mid-band `ρ`; for M5, §8.3 firing or client-side `ss` buffer burst symptoms correlated with `T_D1,b` (`docs/pr/819-step2-discriminator-design/plan.md:415-416`).

**Residual concern:** The triggers are better, but still uneven. M4's trigger uses `ρ` in `0.6-0.8` (`docs/pr/819-step2-discriminator-design/plan.md:415`), while §7.1 defines the actual inconclusive band as `0.3-0.8` (`docs/pr/819-step2-discriminator-design/plan.md:346`). M5's `ss` trigger is still descriptive rather than fully operationalized; it does not say what specific `ss` fields or thresholds constitute "fill-drain bursts" (`docs/pr/819-step2-discriminator-design/plan.md:416`).

**Mitigation needed:** Align M4's trigger band with §7.1 and make the M5 trigger measurable, not just suggestive.

### MED-11 — PARTIAL

**Evidence:** §9 now contains G8, and it is the right kind of gate: it requires tooling availability, capture privilege, target surface, and artifact emission on `loss:xpf-userspace-fw0` before a probe issue may be filed (`docs/pr/819-step2-discriminator-design/plan.md:383-397`).

**Residual concern:** The gate exists, but the "one-command" promise is still aspirational. The concrete P1 draft in §5.1 is a multi-command sequence, not a single command (`docs/pr/819-step2-discriminator-design/plan.md:250-267`). P2/P3 are still only design-doc requirements, not concrete smoke commands (`docs/pr/819-step2-discriminator-design/plan.md:397`).

**Mitigation needed:** Either soften G8's "one-command" wording or provide actual single-command smoke checks per probe.

### LOW-10 — RESOLVED

**Evidence:** §11 is now retitled `Replan triggers`, uses `RT-1`, and explicitly says the #817 relationship "Does NOT pause #819" absent a forward-cell flip (`docs/pr/819-step2-discriminator-design/plan.md:407-411`).

### Regression

**MEDIUM — The new budget prose overclaims what the parallel-escape clause achieves.**

**Evidence:** §3.1 says the escape clause caps serial worst case at 2 rounds (`docs/pr/819-step2-discriminator-design/plan.md:133-138`), but §3.4 still enumerates a three-round serial `P1 -> P3 -> P2` path (`docs/pr/819-step2-discriminator-design/plan.md:167-178`). That contradiction was introduced by the Round 2 rewrite.

**Mitigation needed:** Reconcile §3.1 with §3.4. Right now the plan says two different things about the worst serial path.

### Terminal count

PARTIAL items: 6
NOT-RESOLVED items: 0
New HIGH/MEDIUM regressions: 1 MEDIUM

## Round 3 verification

ROUND 3: PLAN-READY NO — HIGH-1, HIGH-2, MED-7, MED-8

> Date: 2026-04-21
> Reviewer: Codex
> Disposition: hostile/pedantic
> Basis: current `docs/pr/819-step2-discriminator-design/plan.md` read fresh from disk before writing this section

### HIGH-1 — PARTIAL

**Evidence:** §5.1 now gives the three tracepoints distinct roles: `sched_switch` as the primary off-CPU event, `sched_wakeup` as the off→runnable signal, and `sched_stat_runtime` as a sanity-check-only input (`docs/pr/819-step2-discriminator-design/plan.md:235-242`). It now includes an explicit per-tid/per-block aggregate formula for `off_cpu_durations(tid, b)`, `bucket_idx(d_ns)`, `off_cpu_time_3to6(tid, b)`, and `off_cpu_time_3to6,b` (`docs/pr/819-step2-discriminator-design/plan.md:243-256`), names the voluntary/involuntary classification by `prev_state` (`docs/pr/819-step2-discriminator-design/plan.md:258-259`), and defines the per-block JSON output shape (`docs/pr/819-step2-discriminator-design/plan.md:260-280`).

**Residual concern:** The reducer is much more implementable now, but it still leaves one material mismatch. §5.1's JSON output is block-aggregate only (`buckets`, `sum_3to6`, `voluntary_3to6`, `involuntary_3to6`) (`docs/pr/819-step2-discriminator-design/plan.md:260-280`), while §7.1 step 2 still says "compute `off_cpu_time_3to6,b` per worker TID" from that file (`docs/pr/819-step2-discriminator-design/plan.md:392-396`). That is not possible from the emitted shape without guessing or recomputing from raw `perf-script.txt`.

**Mitigation needed:** Either change §7.1 to consume the aggregated block JSON, or extend the JSON output to carry per-TID entries explicitly.

### HIGH-2 — PARTIAL

**Evidence:** §4.1 now defines "T_D1-elevated blocks" quantitatively as `T_D1,b ≥ percentile(T_D1, 75)` over the 12 blocks, concretely the top 3 blocks, and names the checked-in evidence field path `shape[3]+shape[4]+shape[5]+shape[6]` in `evidence/with-cos/<cell>/hist-blocks.jsonl` (`docs/pr/819-step2-discriminator-design/plan.md:200-208`). T1 and T2 reference "during T_D1-elevated blocks" explicitly (`docs/pr/819-step2-discriminator-design/plan.md:205-206`), and T4 clearly uses the same defined elevated-block notion (`docs/pr/819-step2-discriminator-design/plan.md:207`).

**Residual concern:** This fix closes the missing-top-quartile definition, but the overall machine-testable bar is still not fully met because T1 still contains "Calibration band set after first capture" (`docs/pr/819-step2-discriminator-design/plan.md:205`). That is not a pre-registered scriptable rule; it is a post-hoc calibration escape.

**Mitigation needed:** Replace the calibration-band placeholder with a concrete INCONCLUSIVE band or explicit fixed thresholds.

### MED-6 — RESOLVED

**Evidence:** §5.1 now contains exactly four numbered preflight commands (`docs/pr/819-step2-discriminator-design/plan.md:287-313`). All of them are explicitly run inside the guest via `incus exec loss:xpf-userspace-fw0 -- ...` (`docs/pr/819-step2-discriminator-design/plan.md:289-313`). Step 4 is a real parse check using `perf script -i /tmp/smoke.data | head -5 | grep -q 'sched_switch'`, not just a binary-exists check (`docs/pr/819-step2-discriminator-design/plan.md:308-313`). Guest-side sysctl scope and the `bpftrace` fallback are also explicit (`docs/pr/819-step2-discriminator-design/plan.md:315-321`).

### MED-7 — NOT-RESOLVED

**Evidence:** The contradiction-resolution text is now present and does explicitly name two conditions for row 4: (a) the §8 escape also returns inconclusive and (b) the architect declines the §8.4 pivot (`docs/pr/819-step2-discriminator-design/plan.md:133-145`). But that explanation is still wrong when cross-checked against the actual decision tree: §8.1 says `P1 -> M3 OUT` proceeds to P3 (`docs/pr/819-step2-discriminator-design/plan.md:414-419`), and §8.2 says `P3 -> M1 OUT` proceeds to P2 (`docs/pr/819-step2-discriminator-design/plan.md:421-426`). That ordinary OUT/OUT path already creates the 3-round serial `P1 -> P3 -> P2` branch represented by row 4 in §3.4 (`docs/pr/819-step2-discriminator-design/plan.md:172-186`) without requiring the P1-inconclusive escape path or the §8.4 all-silent leaf.

**Residual concern:** The text that was added to reconcile the contradiction still contradicts the rest of the plan.

**Mitigation needed:** Rewrite §3.1 so it matches the actual §8 branching. The current "both conditions must hold" claim is false.

### MED-8 — PARTIAL

**Evidence:** The M5 un-deferral trigger is now concrete. §12 names the client-side command, the 100 ms sampling cadence for 60 s, the per-sample `Send-Q` and `cwnd` fields, and the numerical fire rule `≥ 5` fill-drain transitions/s with Spearman `ρ ≥ 0.5` after time alignment (`docs/pr/819-step2-discriminator-design/plan.md:476-478`). M4 remains concrete too: §12 still gives explicit observables and thresholds for un-deferral (`docs/pr/819-step2-discriminator-design/plan.md:475-475`).

**Residual concern:** M4 remains concrete, but it is still inconsistent with the actual §7.1 inconclusive band. §12 keeps M4's trigger at `ρ` in `0.6-0.8` (`docs/pr/819-step2-discriminator-design/plan.md:475`), while §7.1 defines inconclusive as `0.3 < ρ < 0.8` (`docs/pr/819-step2-discriminator-design/plan.md:397-400`). So the trigger is concrete but not aligned with the plan's own statistical routing.

**Mitigation needed:** Align the M4 un-deferral band with §7.1 or explain why a narrower `0.6-0.8` sub-band is the intended policy.

### MED-11 — RESOLVED

**Evidence:** G8 now explicitly references all three probes and gives concrete smoke-test drafts for each (`docs/pr/819-step2-discriminator-design/plan.md:446-457`). P2 includes a real 2-second emission check via `bpftrace ... interval:s:2 { exit(); } ... | grep -q "@:"` (`docs/pr/819-step2-discriminator-design/plan.md:448-452`). P3 checks the new wire-format field directly with the control-socket + `jq` pipeline looking for `tx_kick_latency_hist` (`docs/pr/819-step2-discriminator-design/plan.md:453-457`) and also requires one-cycle capture emission (`docs/pr/819-step2-discriminator-design/plan.md:457`).

### Regression

**MEDIUM — The targeted MED-7 rewrite introduced a new false claim about when row 4 is reachable.**

**Evidence:** §3.1 now says the row-4 three-round serial path requires the P1-inconclusive escape to also come back inconclusive and the architect to decline the §8.4 pivot (`docs/pr/819-step2-discriminator-design/plan.md:133-145`). But §§8.1-8.3 independently allow a straightforward `P1 OUT -> P3 OUT -> P2` serial path (`docs/pr/819-step2-discriminator-design/plan.md:414-431`). The contradiction is no longer just missing budgeting; it is now an explicit incorrect statement introduced by the targeted edit.

**LOW — HIGH-1 tightening exposed a file-format / analysis mismatch.**

**Evidence:** §5.1 emits aggregate-per-block JSON only (`docs/pr/819-step2-discriminator-design/plan.md:260-280`), while §7.1 still asks readers to compute per-worker-TID values from that file (`docs/pr/819-step2-discriminator-design/plan.md:392-396`).

### Terminal count

PARTIAL items: 3
NOT-RESOLVED items: 1
New HIGH/MEDIUM regressions: 1 MEDIUM

## Round 4 verification

ROUND 4: PLAN-READY NO — HIGH-1, MED-7

> Date: 2026-04-21
> Reviewer: Codex
> Disposition: hostile/pedantic
> Basis: current `docs/pr/819-step2-discriminator-design/plan.md` read fresh from disk before writing this section

### HIGH-1 — PARTIAL

**Evidence:** §5.1 now fully specifies the reducer roles and aggregate formula: `sched_switch` is primary, `sched_wakeup` closes the off-CPU interval, `sched_stat_runtime` is sanity-check only, and `off_cpu_time_3to6,b` is defined as the cross-worker per-block aggregate (`docs/pr/819-step2-discriminator-design/plan.md:247-266`). §7.1 step 2 no longer asks for per-TID data from the JSON and explicitly notes the raw-event fallback from `perf-script.txt` (`docs/pr/819-step2-discriminator-design/plan.md:404-405`).

**Residual concern:** The JSON/output naming still does not line up cleanly enough to clear the "no guessing" bar. The emitted per-block JSON field is `sum_3to6` (`docs/pr/819-step2-discriminator-design/plan.md:273-279`), but §7.1 step 2 tells the reader to "read `off_cpu_time_3to6,b` directly" from that file (`docs/pr/819-step2-discriminator-design/plan.md:405`). That is the right quantity, but not the field name actually present in the artifact.

**Mitigation needed:** Rename the emitted key to `off_cpu_time_3to6`, or make §7.1 step 2 say `read sum_3to6 (= off_cpu_time_3to6,b)` explicitly.

### HIGH-2 — RESOLVED

**Evidence:** §4.1 now defines `T_D1`-elevated blocks quantitatively as `T_D1,b ≥ percentile(T_D1, 75)` over the 12 captured blocks, concretely the top 3 blocks, and pins the source field path to `evidence/with-cos/<cell>/hist-blocks.jsonl` via `shape[3]+shape[4]+shape[5]+shape[6]` (`docs/pr/819-step2-discriminator-design/plan.md:212-212`). T1 is now fully pre-registered with fixed IN/OUT/INCONCLUSIVE bands and explicitly withdraws the old post-hoc calibration clause (`docs/pr/819-step2-discriminator-design/plan.md:215-215`). T2 and T4 use the same named elevated-block definition consistently (`docs/pr/819-step2-discriminator-design/plan.md:216-217`).

### MED-7 — PARTIAL

**Evidence:** §3.1 now honestly names the plain `P1 OUT -> P3 OUT -> P2` path as a real 3-round serial branch instead of calling it "pathological" (`docs/pr/819-step2-discriminator-design/plan.md:133-155`). §8 remains consistent with that branch: `P1 -> M3 OUT` proceeds to P3, and `P3 -> M1 OUT` proceeds to P2 (`docs/pr/819-step2-discriminator-design/plan.md:424-441`).

**Residual concern:** The rewrite still stops short of the requested clean restatement. §3.1 does not actually enumerate five scenarios `(a)-(e)`; it gives four bullets. Worse, §3.4 still says "Row 4 is avoided by Row 3's escape clause" (`docs/pr/819-step2-discriminator-design/plan.md:192-194`), which is false for the ordinary `P1 OUT -> P3 OUT -> P2` serial path the same plan admits elsewhere (`docs/pr/819-step2-discriminator-design/plan.md:142-145`, `docs/pr/819-step2-discriminator-design/plan.md:433-441`).

**Mitigation needed:** Enumerate the five scenarios explicitly in §3.1 and delete or rewrite the §3.4 claim that Row 3 avoids Row 4.

### MED-8 — RESOLVED

**Evidence:** §12 now makes M4's un-deferral trigger concrete and aligned with the requested policy: trigger only if M3 is firmly OUT at `ρ ≤ 0.3` and P1 still shows `>1%` off-CPU mass in buckets 3-6, with an explicit note that this does **not** fire inside §7.1's `0.3-0.8` M3-inconclusive band (`docs/pr/819-step2-discriminator-design/plan.md:485-485`). M5 remains concrete as well: the client-side `ss -tinm dst 172.16.80.200 sport :5201,5202` command, 100 ms sampling cadence for 60 s, and `Send-Q`/`cwnd` trigger criteria are all still present (`docs/pr/819-step2-discriminator-design/plan.md:486-488`).

### R3-regression — PARTIAL

**Evidence:** The Round 3 format mismatch is materially narrower: §7.1 now consumes the block aggregate and no longer demands per-TID values from the JSON (`docs/pr/819-step2-discriminator-design/plan.md:404-405`). But the artifact still exposes that aggregate as `sum_3to6`, while §7.1 names it as `off_cpu_time_3to6,b` (`docs/pr/819-step2-discriminator-design/plan.md:273-279`, `docs/pr/819-step2-discriminator-design/plan.md:405`).

**Residual concern:** The mismatch is now one field-name hop rather than a whole shape mismatch, but it is still a hop.

**Mitigation needed:** Use one name in both places.

### Regression

No new HIGH/MEDIUM regressions were introduced by these targeted edits. The remaining blockers are the residual HIGH-1/R3 naming mismatch and the still-inaccurate MED-7 budget prose.

### Terminal count

PARTIAL items: 3
NOT-RESOLVED items: 0
New HIGH/MEDIUM regressions: 0

## Round 5 verification

ROUND 5: PLAN-READY YES

> Date: 2026-04-21
> Reviewer: Codex
> Disposition: hostile/pedantic
> Basis: current `docs/pr/819-step2-discriminator-design/plan.md` read fresh from disk before writing this section

### HIGH-1 — RESOLVED

**Evidence:** §5.1 now uses the canonical aggregate name `off_cpu_time_3to6` in the field-alignment note, the per-block JSON schema, and the evidence-layout enumeration (`docs/pr/819-step2-discriminator-design/plan.md:275-299`). §7.1 reads the same quantity by that name at analysis time (`docs/pr/819-step2-discriminator-design/plan.md:413-418`). The old `sum_3to6` token survives only in the historical rename note, not as an active emitted or consumed field (`docs/pr/819-step2-discriminator-design/plan.md:275-275`).

### MED-7 — RESOLVED

**Evidence:** §3.4 now states, in plain English, that Row 4 is the honest 3-round serial budget for `P1 OUT → P3 OUT → P2`, and that Row 3's escape applies only to the P1-INCONCLUSIVE branch (`docs/pr/819-step2-discriminator-design/plan.md:192-203`). That now matches §3.1's own branch description, which separately names the plain serial OUT path and the distinct INCONCLUSIVE escape path (`docs/pr/819-step2-discriminator-design/plan.md:133-155`).

### LOW findings

**LOW — §4.1 still uses symbolic threshold notation instead of the emitted JSON field name.**

**Evidence:** T3 in §4.1 still refers to `off_cpu_time_buckets_3to6_b` / `sum_over_blocks(off_cpu_time_buckets_3to6)` (`docs/pr/819-step2-discriminator-design/plan.md:219-221`), while §5.1/§7.1 pin the actual artifact contract to `off_cpu_time_3to6` (`docs/pr/819-step2-discriminator-design/plan.md:275-299`, `docs/pr/819-step2-discriminator-design/plan.md:413-418`).

**Why this is non-blocking:** A developer no longer has to guess the emitted/read field. The artifact schema and analysis recipe agree; §4.1's notation mismatch is documentation polish, not an implementation gap.

### Regression

No new HIGH/MEDIUM regressions were introduced by these edits. At the Round 5 bar, the plan is implementable as written.

### Terminal count

Blockers (PARTIAL + NOT-RESOLVED): 0
LOW findings: 1
New HIGH/MEDIUM regressions: 0
