# Line-rate investigation plan — adversarial review

1. **SEVERITY: HIGH** The plan can falsely rule out the leading forward-path hypothesis because it looks for AF_XDP TX-ring pressure in the wrong place first.
Explanation: `H-FWD-1` is framed as an AF_XDP TX-ring overrun caused by delayed `sendto()` wakeups or `reap_tx_completions` (`docs/line-rate-investigation-plan.md`, "Hypotheses for the forward-direction gap"), but Step 1 expects NIC `tx_dropped` / ring errors to prove it and only Step 3 vaguely asks for `tx_ring_full_drops or equivalent` (`docs/line-rate-investigation-plan.md`, "Investigation plan"). In the dataplane, the direct evidence is userspace-side: `transmit_local_queue()` and `transmit_prepared_queue()` increment `dbg_tx_ring_full` on zero insert, while `maybe_wake_tx()` separately records `dbg_sendto_enobufs` and other wake failures (`userspace-dp/src/afxdp/tx.rs`), and the worker summary exports those counters every report interval plus operator-facing live counters such as `pending_tx_local_overflow_drops` and `tx_submit_error_drops` (`userspace-dp/src/afxdp/worker.rs`). NIC counters may stay quiet while the userspace ring is thrashing, so the current step order can produce a false negative on the most likely forward-loss theory.
Concrete revision: Promote explicit binding-level userspace counters to Step 1A: capture `dbg_tx_ring_full`, `dbg_sendto_enobufs`, `dbg_pending_overflow`, `tx_errors`, `pending_tx_local_overflow_drops`, `tx_submit_error_drops`, and `outstanding_tx` before treating NIC counters as the primary discriminator for `H-FWD-1`.

2. **SEVERITY: HIGH** The fairness rollback gate is not statistically stable enough for the baseline this repo already documents.
Explanation: The plan treats `> 5 percentage points` as an immediate rollback trigger and anchors the 12-flow gate to the "current ~38 % baseline" (`docs/line-rate-investigation-plan.md`, "Validation at every step" and "Hard stops"). But the D3 validation doc shows the same shipped code at mean CoV `41.4 %` in a fresh matched 5-run and `36.6 %` in an earlier run, with a run range of `19.2-63.2` on the noisier cluster state (`docs/785-d3-validation.md`, "With D3", "Earlier D3 run", and "Interpretation"). That makes a fixed absolute rollback threshold against a frozen `38 %` number vulnerable to both false rollback and false comfort; the document itself says cluster state drift changes the result materially.
Concrete revision: Replace the fixed 12-flow rollback baseline with a matched same-session before/after baseline, and require either two consecutive 5-run regressions or a paired-run criterion before declaring systemic CoV regression. Keep the 5-point rule only as a first alarm, not an automatic final verdict.

3. **SEVERITY: MEDIUM** `H-FWD-3` is not actually testable with the evidence the plan collects.
Explanation: The hypothesis says session-install or early-path contention would appear as retransmits concentrated in the first `1-2 seconds` (`docs/line-rate-investigation-plan.md`, "Hypotheses for the forward-direction gap"), but Steps 1-6 collect only pre/post counters, a one-minute CPU sample, and a direct single-flow control (`docs/line-rate-investigation-plan.md`, "Investigation plan"). There is no interval-level retransmit or throughput capture, and no warm-up/discarded run to separate TCP slow-start noise from steady-state dataplane loss. As written, the plan could "confirm" `H-FWD-3` from elevated session-create counters even if the actual throughput gap is a later steady-state problem.
Concrete revision: Add a pre-code measurement step that records per-interval iperf output for the first 10 seconds and the full 60-second run, plus one discarded warm-up run before the 5 measured runs. Require `H-FWD-3` to show both an early session-create spike and early-window retransmit concentration before it is treated as primary.

4. **SEVERITY: MEDIUM** The hypothesis set is incomplete on two non-code-path controls the current plan itself makes plausible: XDP fallback/bind mode and sender TCP mode.
Explanation: The plan includes a server-side flow-control theory for reverse traffic (`H-REV-4`) but never records congestion-control mode or socket-buffer configuration anywhere in Steps 1-6 (`docs/line-rate-investigation-plan.md`, "Hypotheses for the reverse-direction gap" and "Investigation plan"). Separately, it never mentions XDP fallback, bind mode, or zero-copy vs non-zero-copy, even though `worker.rs` carries `xsk_bind_mode` in `BindingLiveSnapshot`, records the actual bind mode when the socket is opened, and periodically prints `XDP_FALLBACK` stats specifically because they tell operators "WHY packets stop being redirected to XSK" (`userspace-dp/src/afxdp/worker.rs`). Without those controls, the investigation can blame the firewall for a sender-side TCP-mode artifact or for traffic that is no longer consistently staying on the XSK path.
Concrete revision: Add a preflight control row that records client/server TCP congestion control and socket-buffer settings, and add one forward/reverse hypothesis for "XSK path degradation / fallback" with Step 1A capture of `xsk_bind_mode`, `zero_copy`, and `XDP_FALLBACK` stats on every watched binding.

5. **SEVERITY: MEDIUM** `H-REV-3` is underspecified enough that Step 3 cannot cleanly confirm or reject it.
Explanation: The hypothesis points at `scratch_local_tx` / `scratch_prepared_tx` being sized to `TX_BATCH_SIZE = 256` and says Step 3 should look for `scratch-rebuild counters` (`docs/line-rate-investigation-plan.md`, "Hypotheses for the reverse-direction gap" and Step 3). In the reviewed source, those scratch vectors are preallocated once per binding at `TX_BATCH_SIZE`, but I do not see any named "scratch-rebuild" counter in `worker.rs` or `tx.rs`; the files expose restore/release helpers and TX-ring counters instead (`userspace-dp/src/afxdp/worker.rs`, `userspace-dp/src/afxdp/tx.rs`). That means the plan currently names evidence that is not grounded in the reviewed implementation.
Concrete revision: Either remove `H-REV-3` until a concrete observable is named, or restate it as a queue-restore / exact-drain hypothesis tied to existing observables such as TX-ring-full events, overflow drops, queue path selection, and the exact restore helpers used on reverse traffic.

6. **SEVERITY: MEDIUM** The success criteria are internally inconsistent and do not say how many runs must actually hit the target.
Explanation: The problem statement sets a concrete goal of `>= 24 Gbps` both directions and `<= 100 retransmits` over 60 seconds (`docs/line-rate-investigation-plan.md`, "Problem statement"), but the validation gate later relaxes to `SUM >= pre-change, retransmits <= pre-change` and the final phase only says "both directions at line rate" (`docs/line-rate-investigation-plan.md`, "Validation at every step" and "Phasing"). That leaves an escape hatch where a PR can pass the per-commit gate without ever meeting the stated target, and it never says whether one lucky run, the mean of five runs, or all five runs must satisfy the line-rate condition.
Concrete revision: Define success once and reuse it everywhere: for example, "five measured runs per direction after one warm-up; mean SUM >= 24 Gbps, no individual run < 23 Gbps, total retransmits mean <= 100, and no CoV regression on either the 16-flow or 12-flow gates."

7. **SEVERITY: LOW** Rollback and phasing mechanics need sharper boundaries to keep regressions attributable once multiple fixes exist.
Explanation: The plan says "rollback that commit immediately" and separately says rollback commits stay in branch history, while also forcing fully serialized Phases C and D with one PR per issue (`docs/line-rate-investigation-plan.md`, "Validation at every step", "Phasing", and "Risks"). That is directionally safe, but it does not say what happens when a regression is discovered after several commits on the investigation branch, nor does it justify blocking issue filing and PR work on independent findings once Phase B evidence is frozen. The result is avoidable ambiguity in the recovery path and unnecessary serialization after the no-code review phase.
Concrete revision: Keep Phases A and B fully serialized, then require each accepted root cause to branch from a tagged last-known-green commit. Specify that regressions are reverted per offending commit or by resetting the workstream branch to the last green tag, rather than leaving "rollback immediately" as an informal instruction.

## Round 2 verification
ROUND 2: plan-ready NO

### Round-1 HIGH #1
FIXED. The plan now says userspace evidence comes before NIC counters, puts `flow_steer_snapshot` plus `dbg_tx_ring_full`/`dbg_sendto_enobufs`/`dbg_pending_overflow`/`pending_tx_local_overflow_drops`/`tx_submit_error_drops`/`outstanding_tx` in Step 1, and moves NIC counters to Step 2. Plan lines 178-181, 245-268.

### Round-1 HIGH #2
FIXED. Rollback is now a matched 5-run pre/post protocol with mean and stddev calculations, replacing the prior single absolute threshold. Plan lines 384-423.

### Round-1 MEDIUM
FIXED. Step 0.3 records `tcp_congestion_control` on both endpoints, pins one algorithm, and verifies in-run with `ss -ti`. Plan lines 214-223.

### Round-2 #4
FAIL. Step 0.2 records mlx5 coalescence fields, but its gate only fires if "any value is clearly pathological"; it does not require a per-item disposition, so coalescence can be noted without an explicit flag. Plan lines 201-212.

### Round-2 #5
FAIL. The CoV rollback rule is `mean(post-CoV) - mean(pre-CoV) > 2 x stddev(pre-CoV)` with no floor if `stddev(pre-CoV)` is near zero. Plan lines 410-412, 516-519.

### Round-2 #6
FAIL. The latency probe is only `ping -i 0.01 <dst>` or `sockperf` on "the same path"; no interface selection, CPU pinning, or statement about load-test-induced probe jitter is defined. Plan lines 286-290, 395-396, 431-432.

### Round-2 #7
FAIL. Ring-quadruple material is split across Step 0.4 and Step 5, and authoritative overflow evidence is only recoverable by combining Step 1/H-FWD-1 userspace counters such as `dbg_tx_ring_full` and `pending_tx_local_overflow_drops`; there is no single canonical audit section. Plan lines 224-230, 250-255, 261-264, 308-318.
