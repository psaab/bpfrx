# Issue #819 — Step 2 discriminator telemetry design doc

> **Status.** Design doc (the deliverable of #819). Produced after
> `plan.md` reached PLAN-READY YES at Codex Round 5.
>
> **What this doc is.** The doc names probes, specifies wiring
> requirements for each probe, and specifies the capture protocol.
> **It does NOT implement any probes.** Each named probe becomes a
> separate follow-up implementation issue per plan §1.1.
>
> **What this doc is not.** This is not a re-litigation of #816's H2 D1
> verdict (plan RT-3). This is not a Phase 4 scope for #793 — that
> scope is written only after a decisive probe outcome names the
> dominant mechanism (plan §1).
>
> **Cluster.** Userspace cluster only: `loss:xpf-userspace-fw0` /
> `-fw1`. bpfrx forbidden (plan §10).
>
> **Completeness contract.** The design doc is COMPLETE when plan §9
> G1-G8 pass. §Validation gates checklist (below) confirms each gate
> is satisfied by this doc.

## 1. Problem statement and verdict input

Per `docs/pr/816-step1-rerun/findings.md` §1 verdict and §5
concluding verdict:

> "**H2 D1 (XSK submit→DMA latency elevated cross-cell on
> shaped-traffic cells.)** … Per plan §8: *'XSK submit→DMA latency
> elevated cross-cell.' → Scope #793 Phase 4 against in-AF_XDP
> submit-path queueing / per-CPU NAPI drift / sendto kick
> regressions.*"

### 1.1 Load-bearing cells

The H2 D1 verdict is load-bearing on two cells (findings §1.2):

- **p5201-fwd-with-cos** — `stat_D1 ≈ 0.969`, mode = 4.
- **p5202-fwd-with-cos** — `stat_D1 ≈ 0.885`, mode = 5.

Reverse-direction fires (p5201-rev, p5203-rev, `stat_D1 ≈ 0.01-0.02`)
are within-the-gate corroboration, not independently strong. The
design doc re-captures on the forward-with-cos load-bearing pair only
(§Capture protocol).

### 1.2 Candidate mechanisms

Findings §7 enumerates five candidate mechanisms for the elevated
submit→DMA latency. The #816 data does NOT distinguish among them:

1. **M1 — Submit→TX DMA stalls (in-AF_XDP).** AF_XDP submit-path
   queueing internal to the dataplane.
2. **M2 — RX NAPI budget exhaustion leaking into TX scheduling.**
   Cross-CPU softirq / worker coupling.
3. **M3 — Scheduler descheduling the worker between `sendto` and
   reap.** Scheduler jitter on the worker CPU.
4. **M4 — Virtualization jitter.** Nested-hypervisor VM-exit artifacts.
5. **M5 — iperf3 client-side burstiness.** Input waveform shape
   contaminating the downstream signal.

### 1.3 Why discrimination matters — Phase 4 scoping gate

#816 plan §8 mapped H2 D1 to Phase 4 actions: "Scope #793 Phase 4
against in-AF_XDP submit-path queueing / per-CPU NAPI drift / sendto
kick regressions." Those three directions correspond to M1 + M2 + a
sub-case of M1 inside the daemon. M3 / M4 / M5 would each re-scope
#793 Phase 4 entirely (scheduler tuning, VM/host placement,
iperf3 harness replacement respectively). **Phase 4 (#793) scope
cannot be written until the dominant mechanism is named.** #819
scopes the telemetry to name it.

## 2. Mechanism-vs-discriminator matrix (G1)

Cell labels: **IN** / **OUT** / **INF** (informative) / **SIL** (silent) /
**UNC** (uncertain). Every IN/OUT cell has a numerical threshold in
§3. Every mechanism row has at least one IN/OUT cell (G1 satisfied).

| Mechanism | P1: off-CPU duration by bucket | P2: `napi_complete_done` cadence | P3: TX kick latency histogram + retry counter | P4: `perf kvm stat` (L0) | P5: iperf3 client send-time histogram |
|---|---|---|---|---|---|
| **M1 — submit→DMA stall** | INF | INF | **IN/OUT** (T1) | SIL | SIL |
| **M2 — RX NAPI exhaustion** | INF | **IN/OUT** (T2) | INF | SIL | SIL |
| **M3 — scheduler desched** | **IN/OUT** (T3) | INF | SIL | INF | SIL |
| **M4 — virtualization jitter** | INF | SIL | SIL | **IN/OUT (T4) or UNC** | SIL |
| **M5 — iperf3 burstiness** | SIL | SIL | INF | SIL | **IN/OUT** (T5) |

**G1 verification.** Every row has at least one IN/OUT cell: M1→T1,
M2→T2, M3→T3, M4→T4 (or UNC if only guest-side proxies are
available), M5→T5. G1 satisfied.

## 3. Thresholds (G1 named-threshold backing)

### 3.1 Definition: "T_D1-elevated blocks"

A 5-s block `b` is **T_D1-elevated** if its `T_D1,b` value (the
bucket-3-to-6 mass fraction per #816 plan §4.2 /
`step1-histogram-classify.py:159-163`) is in the **top quartile** of
the 12 blocks in the cell's capture:

```
T_D1,b ≥ percentile(T_D1, 75)
```

Concretely: rank the 12 block values, take the top 3 (12 ÷ 4 = 3
rounded). Reference:
`evidence/with-cos/<cell>/hist-blocks.jsonl` lines 1-12, field
`shape[3]+shape[4]+shape[5]+shape[6]`. Used by T1, T2, T4 below for
"during T_D1-elevated blocks" and by T3 for the inconclusive-band
re-bin.

### 3.2 Named thresholds T1-T5

- **T3 — M3 IN via P1.**
  `Spearman(T_D1,b, off_cpu_time_3to6,b) ≥ 0.8` (computed across
  all 12 blocks) **AND** `sum_over_blocks(off_cpu_time_3to6) / 60s ≥
  1%`.
  **T3 OUT.** `ρ ≤ 0.3` OR `total_off_cpu_3to6 / 60s < 1%`.
  **T3 INCONCLUSIVE.** `0.3 < ρ < 0.8`.
  Justification: §Analysis recipe, P1.

- **T1 — M1 IN via P3 (pre-registered, no post-hoc band).**
  `Δ(retry_counter)/block ≥ 1000 events` during T_D1-elevated blocks
  (top 3 blocks per §3.1) **AND** `mean(sendto_kick_latency) ≥ 4 µs`
  (lower edge of bucket 3).
  **T1 OUT.** `Δ(retry_counter)/block < 100 events on every block`
  AND `mean(sendto_kick_latency) < 2 µs across all blocks` (bucket
  ≤ 1, below where D1 lives).
  **T1 INCONCLUSIVE.** Anything between (e.g. retry counter in
  100-1000/block range, or mean kick latency in 2-4 µs band).
  The IN/OUT/INCONCLUSIVE bands are pre-registered fixed thresholds
  — no post-capture calibration.

- **T2 — M2 IN via P2.** p99 inter-`napi_complete_done` interval on
  the RX queue during T_D1-elevated blocks ≥ 100 µs.
  **T2 OUT.** p99 ≤ 10 µs across all blocks AND no correlation with
  `T_D1,b` (ρ ≤ 0.3).

- **T4 — M4 IN via P4.**
  `Δ(KVM_REQ_HALT + KVM_REQ_EVENT)/block` on the worker vCPU shows
  ρ ≥ 0.8 with `T_D1,b` AND exit-count rate ≥ 100/s during elevated
  blocks. Guest-only proxies → UNC.

- **T5 — M5 IN via P5.** client-side inter-send-time p99 ≥ 10 µs on
  the two load-bearing cells AND ρ ≥ 0.8 with `T_D1,b` after
  time-alignment.

**G1-backing verification.** Each IN/OUT matrix cell in §2 references
a named threshold in §3.2. T1, T2, T3, T5 are fully specified
numerical rules. T4 is either numerical (when L0 `perf kvm` is
accessible) or UNC (when only guest-side proxies are available),
matching the matrix cell label. All five thresholds are
pre-registered before their probe's capture.

**Note on §4.1 symbolic notation.** Plan §4.1 T3 uses the symbolic
name `off_cpu_time_buckets_3to6_b` / `sum_over_blocks(off_cpu_time_buckets_3to6)`
for the quantity the P1 artifact emits. The artifact and analysis
recipe both use the canonical field name `off_cpu_time_3to6` (§5.1).
This design doc uses `off_cpu_time_3to6,b` for the per-block value
and `sum_over_blocks(off_cpu_time_3to6)` for the 60-s total;
they are the same quantity, just notation-canonicalized to match the
JSON field.

## 4. Per-probe wiring spec (G2)

Per G2 (plan §9): each probe specifies tooling, capture point, exact
command line, output format, post-processing recipe, and integration
with `step1-capture.sh`.

**Round scope.** This design doc fully specifies **P1, P2, and P3**.
**P4 and P5 are deferred** (§Deferrals) and carry placeholder
wiring summaries only — they fire only on plan §8.3 or §12 trigger.

### 4.1 P1 — sched_switch perf-record reduced to off-CPU duration histogram

**Tooling.** `perf record` with `sched:sched_switch` +
`sched:sched_stat_runtime` + `sched:sched_wakeup` for 60 s on the
worker TIDs.

**Capture point.** `loss:xpf-userspace-fw0`. Worker TIDs from
`test/incus/step1-capture.sh:252` (`WORKER_TIDS`).

**Exact command.**

```
perf record \
  -e sched:sched_switch \
  -e sched:sched_stat_runtime \
  -e sched:sched_wakeup \
  -t "$WORKER_TIDS" \
  --call-graph=fp \
  -o /tmp/sched-switch.perf.data \
  -- sleep 60
```

**Post-processing — off-CPU duration by log2 bucket.**

The reducer consumes the time-ordered `perf script` event stream and
emits a per-block 16-bucket off-CPU duration histogram. The three
tracepoints play distinct roles:

- **`sched_switch`** is the *primary* event. For each `sched_switch
  (prev=TID, prev_state=off)` event timestamped at `t_off`, the TID
  went off-CPU. This event also carries `prev_state` (R/S/D/etc.)
  which feeds the voluntary/involuntary classification.
- **`sched_wakeup`** is the *off→runnable* signal. The next
  `sched_wakeup TID` event timestamped at `t_wake` marks when the
  TID became runnable again. The time delta `t_wake - t_off` is the
  TID's off-CPU duration for that switch pair.
- **`sched_stat_runtime`** is the *sanity check*. It carries
  `runtime` / `vruntime` deltas accumulated while a TID was on-CPU;
  used in the reducer ONLY as a cross-check that on-CPU intervals
  between off-CPU pairs sum to the expected wall-clock minus
  aggregate off-CPU time. A mismatch >1% triggers a sanity-check
  warning in `correlation-report.md` (does not affect verdict). Not
  part of the per-block aggregate formula.

**Aggregate formula.** For each TID `tid` and each 5-s block
`b ∈ 0..=11`:

```
off_cpu_durations(tid, b) := { (t_wake - t_off) :
                                t_off ∈ [b·5s, (b+1)·5s) ,
                                next sched_wakeup(tid) at t_wake }

bucket_idx(d_ns) := bucket index in [0..15] per #812 plan §11 layout

off_cpu_time_3to6(tid, b) := Σ over off_cpu_durations(tid, b) of d
                              if 3 ≤ bucket_idx(d_ns) ≤ 6 else 0

off_cpu_time_3to6,b      := Σ over all worker tids of off_cpu_time_3to6(tid, b)
```

**Field-name canonical form.** The per-block JSON emits the
cell-level aggregate as **`off_cpu_time_3to6`** (same name §Analysis
recipe P1 and §3 thresholds use).

**Voluntary vs involuntary split.** A switch is **voluntary** if
`prev_state ∈ {S, D, I}` (worker went to sleep); **involuntary** if
`prev_state == R` (CFS preempted a runnable task). Bucket each side
separately.

**Per-block output (one JSON line per block):**

```
{ "b": <int 0..11>,
  "buckets": [<u64> × 16],
  "off_cpu_time_3to6": <u64 ns>,
  "voluntary_3to6": <u64 ns>,
  "involuntary_3to6": <u64 ns>,
  "stat_runtime_check": "PASS" | "WARN" }
```

**M3 IN/OUT decision (T3).** Does `off_cpu_time_3to6,b` correlate
with `T_D1,b` at ρ ≥ 0.8, AND total off-CPU mass in buckets 3-6 ≥ 1%
duty cycle? (§3.2 T3.)

**Output layout.**

```
evidence/p<port>-fwd-with-cos/sched-switch/
    perf.data
    perf-script.txt
    off-cpu-hist-by-block.jsonl   # 12 lines: {b, buckets[16], off_cpu_time_3to6, voluntary_3to6, involuntary_3to6, stat_runtime_check}
    correlation-report.md
```

**Per-cell cadence.** One 60-s capture per load-bearing cell.

**Harness integration.** **Sister harness.** New
`test/incus/step2-sched-switch-capture.sh` invokes
`step1-capture.sh` (for the histogram baseline) AND runs
`perf record` concurrently against the same TIDs. The sister harness
MUST re-use `step1-capture.sh`'s existing block boundaries so that
`T_D1,b` and `off_cpu_time_3to6,b` refer to the same 12 wall-clock
5-s windows.

### 4.2 P2 — NAPI cadence (bpftrace on RX napi:* tracepoints)

**Tooling.** `bpftrace` on `tracepoint:napi:napi_complete_done` +
`tracepoint:napi:napi_poll` with inter-call interval histogram.
Fallback: `kprobe:__napi_complete_done` if `napi:*` tracepoints
absent on the guest kernel.

**Capture point.** fw0 VM, kernel-side. The load-bearing cells run
TX on `ge-0-0-1` / `ge-0-0-2` in ZeroCopy per
`docs/pr/line-rate-investigation/step0-audit.md:18-27`. P2 measures
NAPI cadence on the RX queue that pairs with these TX interfaces.

**Design-doc open questions (to be resolved at P2 implementation-issue
filing time):**

- Which RX queue ID on `ge-0-0-1` / `ge-0-0-2` hosts load-bearing
  traffic per cell? The implementation issue must enumerate exact
  queue → CPU mapping per cell before capture.
- Which CPU runs that RX softirq? Shared with the TX worker CPU or
  isolated?
- Does the guest kernel export `napi:*` tracepoints, or must the
  implementation use the `kprobe:__napi_complete_done` fallback?
  G8 P2 smoke test answers this directly.

**Indicative bpftrace script (design-doc draft; implementation issue
will ground queue / CPU mapping):**

```
# step2-napi-cadence-capture.bt (draft)
tracepoint:napi:napi_complete_done /cpu == $RX_CPU/ {
    $now = nsecs;
    $prev = @last[cpu];
    if ($prev > 0) {
        @inter_arrival = hist($now - $prev);
    }
    @last[cpu] = $now;
}
interval:s:60 { exit(); }
```

**Output format.**

```
evidence/p<port>-fwd-with-cos/napi-cadence/
    napi-inter-arrival-hist.txt     # bpftrace hist output
    napi-cadence-by-block.jsonl     # 12 lines: {b, p50_ns, p99_ns, count}
    correlation-report.md
```

**Post-processing.** Bucket the raw inter-arrival stream into the
same 12 5-s wall-clock blocks as `step1-capture.sh`. Compute p50 /
p99 per block. Correlate per-block p99 against `T_D1,b`.

**M2 IN/OUT decision (T2).** Per §3.2 T2: p99 inter-arrival ≥ 100 µs
during T_D1-elevated blocks AND ρ ≥ 0.8 vs `T_D1,b` → IN. p99 ≤ 10 µs
on every block AND ρ ≤ 0.3 → OUT.

**Harness integration.** **Sister harness.** New
`test/incus/step2-napi-cadence-capture.sh` runs `step1-capture.sh`
concurrently with the bpftrace script against the identified RX CPU.

### 4.3 P3 — AF_XDP TX-kick latency + retry counter

**TX kick site (verified).** The TX kick is **`maybe_wake_tx` at
`userspace-dp/src/afxdp/tx.rs:6429`**, with `sendto` syscall at line
6439. (Not `tx.rs:284`, which is `maybe_wake_rx` — the RX wake path's
TX-completion reap.)

**File-scope change list.** (Replaces any earlier line-count estimate.)

- **Hot-path counter + histogram** in `userspace-dp/src/afxdp/tx.rs`
  around `maybe_wake_tx` (line 6429):
  - Capture timestamp pair around `sendto` (lines 6438-6447) into a
    16-bucket histogram identical in shape to `tx_submit_latency_hist`.
  - Increment a per-binding retry counter when the TX kick `sendto`
    returns `EAGAIN` / `EWOULDBLOCK` (line 6453).
- **Owner snapshot state** in `userspace-dp/src/afxdp/worker.rs`,
  mirroring the `tx_submit_latency_hist` projection at
  `worker.rs:4240-4247`.
- **Wire-format additions** in
  `userspace-dp/src/protocol.rs:1320-1343`:
  - `tx_kick_latency_hist: [u64; 16]`
  - `tx_kick_latency_count: u64`
  - `tx_kick_latency_sum_ns: u64`
  - `tx_kick_retry_count: u64`
  Go mirror in `pkg/dataplane/userspace/protocol.go:697,682`.
- **Coordinator copy** in
  `userspace-dp/src/afxdp/coordinator.rs:1428-1440` and clear path at
  `:1530`.
- **Parser / analysis additions** in
  `test/incus/step1-histogram-classify.py` and
  `test/incus/step1-capture.sh` (extract the new histogram + counter
  from the existing JSON snapshot).
- **Tests.** Unit tests for the histogram recording path and
  wire-format round-trip; bench stub mirroring #812's overhead test.

**Capture point.** Same as `tx_submit_latency_hist` today — the
existing `step1-capture.sh` snapshot loop catches the new counters
once the wire format is bumped.

**Output format.**

```
evidence/p<port>-fwd-with-cos/tx-kick/
    flow_steer_samples.jsonl                # augmented — contains new fields per sample
    tx-kick-by-block.jsonl                  # 12 lines: {b, kick_latency_hist[16], kick_latency_mean_ns, retry_count_delta}
    correlation-report.md
```

**Post-processing.** Derive per-block `Δ(retry_count)` from the
snapshot stream (post snapshot minus prior snapshot, per 5-s block).
Compute `mean(sendto_kick_latency)` per block as
`kick_latency_sum_ns / kick_latency_count` (bounded difference
across two adjacent snapshots). Correlate both series against
`T_D1,b`.

**M1 IN/OUT decision (T1).** Per §3.2 T1:
`Δ(retry_counter)/block ≥ 1000` during T_D1-elevated blocks AND
`mean(sendto_kick_latency) ≥ 4 µs` → IN.
`Δ(retry_counter)/block < 100` on every block AND
`mean(sendto_kick_latency) < 2 µs` across all blocks → OUT.
Anything between → INCONCLUSIVE.

**Design-doc-level questions (for the P3 implementation issue):**

- Timestamp source: `clock_gettime(CLOCK_MONOTONIC)` vs the
  already-hot `monotonic_nanos()` reader used by submit-path
  telemetry. Implementation must match #812's overhead budget
  (`docs/pr/812-tx-latency-histogram/plan.md` §3.4).
- Retry-counter semantics: count `EAGAIN` returns only vs inner
  retry-loop iterations? Design doc pre-registers: **count outer
  `sendto` returns that are `EAGAIN` / `EWOULDBLOCK`**. Inner-loop
  iteration counts belong in a separate diagnostic probe; not in P3.
- Overhead re-validation against #812's budget — Issue B's
  acceptance criteria must include a bench run matching #812's
  overhead test methodology.

**Harness integration.** No sister harness for P3 — the daemon-side
counters surface through the existing `step1-capture.sh` flow once
the wire format is bumped. The analysis parser update is the only
harness-side change.

### 4.4 P4 — `perf kvm stat` (deferred; placeholder wiring summary)

Deferred per §Deferrals. Un-deferral trigger: plan §8.3 fires OR
P1 reports >1% off-CPU mass in buckets 3-6 with M3 firmly OUT
(`ρ ≤ 0.3`). Wiring summary for the future implementation issue:

- **Tooling.** `perf kvm stat record` on the L0 hypervisor for the
  vCPU(s) backing the worker TID inside `loss:xpf-userspace-fw0`.
- **Access requirement.** L0 shell access with root / `kvm` group;
  not currently granted to the automation account. Resolving this is
  a prerequisite the P4 implementation issue must address.
- **Guest-only fallback → UNC.** If L0 access is refused,
  `perf stat -e kvm:*` inside the guest returns symptoms only (lost
  cycles between `monotonic_nanos()` reads), which is circumstantial
  and matches the matrix cell label **UNC**.

### 4.5 P5 — iperf3 client send-time histogram (deferred; placeholder wiring summary)

Deferred per §Deferrals. Un-deferral triggers per §Deferrals (M5
workload-conditional trigger or §8.3 fire). Wiring summary:

- **Tooling option A.** Patched iperf3 emitting per-packet
  send-timestamp log. Requires either upstream iperf3 instrumentation
  patch or local fork.
- **Tooling option B.** `tcpdump -w` on the client's egress interface
  + post-processing to extract inter-send gaps. No iperf3 patch
  needed; larger artifact size.
- **Cheap symptom check (pre-P5).** `ss -tinm dst 172.16.80.200
  sport :5201,5202` at 100 ms intervals for 60 s; per §Deferrals,
  fill-drain transitions + Spearman ρ vs `T_D1,b` constitute an
  M5 un-deferral trigger without needing the full P5 wiring.

**G2 verification.** P1, P2, P3 each have tooling, capture point,
exact command, output format, post-processing recipe, and harness
integration named above. P4 and P5 carry placeholder wiring summaries
tied to explicit un-deferral triggers. G2 satisfied for the
in-scope probes; deferred probes document their wiring at
un-deferral time.

## 5. Analysis recipe per probe (G3)

### 5.1 P1 (off-CPU duration) — how to read it

Per block `b ∈ 0..=11`:

1. From `hist-blocks.jsonl`: compute `T_D1,b` (mass fraction in
   buckets 3-6, field path `shape[3]+shape[4]+shape[5]+shape[6]` per
   `step1-histogram-classify.py:159-163`).
2. From `off-cpu-hist-by-block.jsonl`: read `off_cpu_time_3to6,b`
   directly (the reducer already aggregates across worker TIDs per
   §4.1 formula). Per-TID breakdown is NOT in the per-block JSON; if
   needed for diagnostic purposes, recompute from `perf-script.txt`
   raw events.
3. **Scatter-plot** `T_D1,b` (x, 12 points) vs `off_cpu_time_3to6,b`
   (y).
4. Read-off rules (T3, §3.2):
   - **M3 IN.** `ρ ≥ 0.8` AND
     `sum_over_blocks(off_cpu_time_3to6) / 60s ≥ 1%`.
   - **M3 OUT.** `ρ ≤ 0.3` OR
     `sum_over_blocks(off_cpu_time_3to6) / 60s < 1%` (the "OR" matters
     — <0.6 s of off-CPU time over 60 s can't explain D1 mass
     regardless of correlation).
   - **M3 INCONCLUSIVE.** `0.3 < ρ < 0.8`. Re-bin at 1-s blocks
     (60 points) from same `perf.data` (no re-capture). If still
     inconclusive, file P3 in parallel (§Decision tree escape).

**ρ-threshold justification.** N=12, two-sided Spearman critical ρ at
α=0.05 ≈ 0.587. **ρ ≥ 0.8** gives P(|ρ| ≥ 0.8 | null) ≈ 0.001
(Monte-Carlo on 12 independent uniform points), FP < 0.1%. **ρ ≤ 0.3**
OUT keeps an explicit inconclusive band (0.3, 0.8) rather than
pretending the marginal region is conclusive. The 60-point 1-s
re-bin's critical ρ at α=0.05 narrows to ≈ 0.255; analysis tightens
accordingly on re-bin.

**Test-statistic alternative.** If the off-CPU-duration distribution
is strongly zero-inflated, switch to **Mann-Whitney U comparing
per-block `T_D1,b` between top-quartile and bottom-quartile
`off_cpu_time_3to6,b` blocks** (3-block groups at N=12) OR re-capture
at N=48 from a 4-min window. The implementation issue's
`correlation-report.md` carries both test statistics when N=12
Spearman is borderline.

### 5.2 P2 (NAPI cadence) — read-off sketch

Pattern mirrors P1:

1. From `hist-blocks.jsonl`: compute `T_D1,b` as above.
2. From `napi-cadence-by-block.jsonl`: read `p99_ns` per block.
3. **Scatter-plot** `T_D1,b` vs `p99_ns / block`, plus a direct-check
   plot of `p99_ns` during the top-3 T_D1-elevated blocks.
4. Read-off rules (T2, §3.2):
   - **M2 IN.** p99 inter-arrival ≥ 100 µs during T_D1-elevated
     blocks AND `ρ(T_D1,b, p99_ns) ≥ 0.8`.
   - **M2 OUT.** p99 ≤ 10 µs on every block AND `ρ ≤ 0.3`.
   - **M2 INCONCLUSIVE.** Between — spec mirrors P1, route through
     either a 1-s re-bin or Mann-Whitney U on quartile groups.

### 5.3 P3 (TX kick latency + retry counter) — read-off sketch

Pattern mirrors P1 with two series (retry delta + mean kick latency):

1. From `hist-blocks.jsonl`: compute `T_D1,b`.
2. From `tx-kick-by-block.jsonl`: read `retry_count_delta` and
   `kick_latency_mean_ns` per block.
3. Two per-block correlations against `T_D1,b`:
   `ρ(T_D1,b, retry_count_delta)` and
   `ρ(T_D1,b, kick_latency_mean_ns)`.
4. Read-off rules (T1, §3.2):
   - **M1 IN.** Both `retry_count_delta ≥ 1000` during T_D1-elevated
     blocks AND `kick_latency_mean_ns ≥ 4 µs` (bucket 3 lower edge).
   - **M1 OUT.** `retry_count_delta < 100` on every block AND
     `kick_latency_mean_ns < 2 µs` across all blocks.
   - **M1 INCONCLUSIVE.** Anything between (e.g. retries in
     100-1000/block range, or mean kick latency in 2-4 µs band).
     Route per §Decision tree.

**G3 verification.** Every in-scope probe (P1, P2, P3) has a
read-off recipe with explicit IN / OUT / INCONCLUSIVE rules tied to
§3.2 thresholds. G3 satisfied.

## 6. Capture protocol (G5)

**What changes vs #816.**

- **Scope reduction: re-run only two cells.** p5201-fwd-with-cos and
  p5202-fwd-with-cos.
- **NO re-run of the 12-cell matrix.**
- **NO new baseline pools.** The discriminator is intra-cell.
- **Same cluster.** `loss:xpf-userspace-fw0` only.
- **Same CoS config.** Canonical `full-cos.set` from #816.
- **Concurrent-run composition.** Sister harness per probe runs
  `step1-capture.sh` + the probe-side tool concurrently against the
  same TIDs, re-using `step1-capture.sh`'s 12 5-s block boundaries.

### 6.1 Capture-run timing

| Probe | Captures | iperf3 time | Total wall-clock |
|---|---|---|---|
| P1 (off-CPU duration)      | 2 cells × 60 s | 2 min | ~10 min |
| P2 (NAPI cadence)          | 2 cells × 60 s | 2 min | ~15 min |
| P3 (TX-kick + retry)       | 2 cells × 60 s | 2 min | ~10 min after daemon wiring lands |

### 6.2 Negative-control spot-check

Run P1 once on a D1-quiet cell (e.g. `p5203-fwd-no-cos`). If off-CPU
mass in buckets 3-6 there is comparable to the load-bearing cells,
the probe is non-informative. This spot-check result lands in the
P1 implementation issue's acceptance criteria.

### 6.3 Per-cell mechanism split handling

`p5201-fwd-with-cos` (~1 Gbps shaped) vs `p5202-fwd-with-cos`
(~10 Gbps shaped) — 10× load spread. Different dominant mechanisms
per cell are possible.

- **Single-mechanism close.** Both cells agree on a per-probe verdict
  → close on global verdict; one Phase 4 scope.
- **Split verdict at any probe stage.** Verdicts diverge → split-
  mechanism outcome:
  - The IN-cell proceeds to its named Phase 4 sub-scope.
  - The OUT-cell continues through the probe order on its own.
  - #819 may spawn **two separate Phase 4 sub-scope issues**, one per
    cell.
- **Applies recursively at P3 and P2.**

**Worked split-verdict example.**

Suppose P1 returns:

- p5201-fwd-with-cos: `ρ(T_D1,b, off_cpu_time_3to6,b) = 0.87`,
  `sum_over_blocks(off_cpu_time_3to6) / 60s = 2.3%` → **M3 IN**.
- p5202-fwd-with-cos: `ρ = 0.12`,
  `sum_over_blocks(off_cpu_time_3to6) / 60s = 0.4%` → **M3 OUT**.

Split-verdict consequences:

- p5201-fwd-with-cos closes on M3 immediately; a Phase 4 sub-scope
  issue is filed for scheduler-jitter mitigation on the ~1 Gbps
  shaped regime (RT SCHED_FIFO on the worker, `isolcpus=` tuning,
  iperf3 client off worker cores).
- p5202-fwd-with-cos proceeds to P3 (per §Decision tree §7.2).
  Issue B fires with the P3 wiring; its capture run targets
  p5202-fwd-with-cos only. Negative-control P1 on a D1-quiet cell is
  NOT re-run (single-cell scope).
- #819 does not close until p5202-fwd-with-cos reaches a terminal
  verdict — the second cell continues the probe ladder standalone.
- If p5202-fwd-with-cos also lands M3 IN on a re-bin, or M1 IN on
  P3, the corresponding per-cell Phase 4 sub-scope issue is filed
  independently from p5201-fwd-with-cos's.

**G5 verification.** Delta vs #816 is named (scope-reduced re-capture
of two cells, no new baselines, sister harness composition). Split
handling is specified at §6.3 with a worked example. G5 satisfied.

## 7. Decision tree (G4)

Branches evaluated **per cell** (§6.3).

### 7.1 After P1

- **P1 → M3 IN on both cells.** Phase 4 = scheduler-jitter
  mitigation (RT SCHED_FIFO, `isolcpus=`, iperf3 client off worker
  cores). Close #819.
- **P1 → M3 OUT on both cells.** Proceed to P3.
- **P1 → split.** Per §6.3: file sub-scope Phase 4 issue for IN-cell;
  file P3 implementation issue targeting OUT-cell only.
- **P1 → INCONCLUSIVE.** Re-bin at 1-s (no re-capture). If still
  inconclusive, parallel-escape: file P3 in parallel with 1-s re-bin.

### 7.2 After P3 (P1 M3-OUT)

- **P3 → M1 IN on applicable cell(s).** Phase 4 = in-AF_XDP TX-kick
  mitigation (rework `maybe_wake_tx`, batch-submit vs kick
  coalescing).
- **P3 → M1 OUT.** Proceed to P2.
- **P3 → MIXED.** Compound verdict; Phase 4 scope is "M1 + (next
  probe) joint."
- **P3 → split.** Same per-cell branching as §7.1.

### 7.3 After P2 (P1+P3 both OUT on a cell)

- **P2 → M2 IN.** Phase 4 = RX NAPI / TX-worker CPU affinity rework.
- **P2 → M2 OUT.** M1, M2, M3 all ruled out on that cell. P4 / P5
  un-defer.

### 7.4 Pathological — all probes silent

If P1, P2, P3 all SILENT or INCONCLUSIVE on both load-bearing cells:
Option C (composite multi-point latency probe) un-defers OR close
#793 Phase 4 as "below measurement floor." This is a replan decision,
not an automatic fork; see §Deferrals for Option C un-deferral cost.

**G4 verification.** Every branch terminates at either a Phase 4
scope or a named follow-up probe. Per-cell branches are covered
(§6.3). G4 satisfied.

## 8. Deferrals (G6)

- **M4 (virtualization jitter) probe (P4).** Deferred. **Rationale
  (not regime-exclusion).** Low prior for "equally-affects-all-cells"
  jitter because no-cos cells are D1-quiet. **Counterexample
  acknowledged:** workload-conditional M4 (MQFQ-imposed idle gaps
  creating hypervisor descheduling opportunities) is NOT excluded by
  regime split alone. **Un-deferral triggers:** §7.3 fires; OR P1
  reports >1% off-CPU mass in buckets 3-6 with M3 firmly OUT
  (`ρ ≤ 0.3` per §5.1 T3 OUT) — off-CPU time exists but scheduler is
  not the cause, hypervisor descheduling becomes the next suspect.
  The M4 trigger does NOT fire inside §5.1's M3-INCONCLUSIVE 0.3-0.8
  band — that band routes to a P1 re-bin first, not M4 un-deferral.
  **Residual risk accepted:** if workload-conditional M4 is dominant
  and triggers don't fire (M1 swamps M4's signal), we will scope
  #793 against M1 and discover M4 residual post-fix.

- **M5 (iperf3 burstiness) probe (P5).** Deferred. **Same caveat:**
  workload-conditional M5 (iperf3 burst clustering under shaper
  backpressure only) not excluded by regime-split alone.
  **Un-deferral triggers:**
  - §7.3 fires; OR
  - Cheap client-side `ss` symptom check fires. During a load-
    bearing-cell capture window, on the iperf3 client
    (cluster-userspace-host), run
    `ss -tinm dst 172.16.80.200 sport :5201,5202` at 100 ms intervals
    for 60 s. For each sample, record `Send-Q` size and `cwnd`. If
    `Send-Q` shows ≥ 5 transitions between "near-empty" (< 4 KiB)
    and "near-full" (> 0.5 × `wmem_default`) per second on average,
    AND those transitions correlate with `T_D1,b` time-aligned to
    the client's wall clock at Spearman ρ ≥ 0.5, M5 un-defers.
    Rationale: a bursty client should show fill-drain cycles in the
    kernel sendbuf; a steady client shouldn't.

- **Option C (composite multi-point latency probe).** Deferred.
  Un-deferred only if §7.4 fires (all probes silent or inconclusive).
  Scope: four-point per-descriptor stamping (sendto-entry, inside
  AF_XDP, NIC TX-complete, RX-kernel-return), three new histograms,
  wire-format updates, overhead re-validation against #812 §3.4, and
  `step1-capture.sh` harness updates — a full multi-PR workstream.

- **Z_cos stratified re-calibration.** Belongs under #793 / #806.

- **T_D2 minimum-count floor re-spec.** Belongs in the next plan
  re-using D2.

- **Per-baseline-run sanity gate.** #816-class methodology fix.

- **Coupling with Path B (#817).** Low risk on forward cells
  (findings §Reproducibility: "enormous margin"). RT-1 triggers
  replan if forward-cell `stat_D1` sign flips.

**G6 verification.** Each deferred mechanism is named with a risk
statement and explicit un-deferral trigger. G6 satisfied.

## 9. Prerequisites / G8 smoke tests

**Per plan §9 G8.** Every decision-tree probe ships smoke tests
proving (1) tooling availability, (2) capture privileges, (3) target
surface, (4) artifact emission — all four executed inside the guest
on `loss:xpf-userspace-fw0` before the probe's implementation issue
may be filed.

**STATUS: NONE of these smoke tests have been run yet.** They are
pre-conditions for filing the per-probe implementation issues listed
in §Implementation issue queue.

### 9.1 P1 G8 smoke (four-command guest-side sequence)

All four executed inside the GUEST (`loss:xpf-userspace-fw0`), NOT on
the L0 incus host. Sysctl scope is per-namespace; the relevant value
is the guest-kernel one because that's what governs `perf` on guest
TIDs.

1. **Sysctl read (guest):**
   ```
   incus exec loss:xpf-userspace-fw0 -- sysctl kernel.perf_event_paranoid
   ```
   Acceptable: ≤ 1.
2. **Tracepoint surface check (guest):**
   ```
   incus exec loss:xpf-userspace-fw0 -- perf list sched:sched_switch
   incus exec loss:xpf-userspace-fw0 -- perf list sched:sched_stat_runtime
   incus exec loss:xpf-userspace-fw0 -- perf list sched:sched_wakeup
   ```
   All three must be present in `perf list` output.
3. **Privilege smoke (guest):**
   ```
   incus exec loss:xpf-userspace-fw0 -- \
     bash -c 'TID=$(ps -eLo tid,comm | awk "\$2==\"xpf-userspace-w\"{print \$1;exit}"); \
              perf record -e sched:sched_switch -t "$TID" -o /tmp/smoke.data -- sleep 1 && \
              test -s /tmp/smoke.data'
   ```
4. **Artifact-emission verification (guest):**
   ```
   incus exec loss:xpf-userspace-fw0 -- \
     perf script -i /tmp/smoke.data | head -5 | grep -q 'sched_switch'
   ```

If command 1 returns > 1, runtime guest-side change (NOT host):

```
incus exec loss:xpf-userspace-fw0 -- sysctl -w kernel.perf_event_paranoid=1   # window-only, revert after
```

**Fallback:** `bpftrace` on `kprobes:__schedule` inside the guest with
the same reducer pipeline; the implementation issue carries both
specs and G8 smoke decides which ships.

### 9.2 P2 G8 smoke (bpftrace sequence)

1. **Tooling:**
   ```
   incus exec loss:xpf-userspace-fw0 -- which bpftrace
   ```
   Must succeed.
2. **Privilege:**
   ```
   incus exec loss:xpf-userspace-fw0 -- bpftrace -e 'BEGIN { exit(); }'
   ```
   Proves bpftrace can attach inside the guest.
3. **Surface:**
   ```
   incus exec loss:xpf-userspace-fw0 -- bpftrace -l 'tracepoint:napi:napi_complete_done'
   incus exec loss:xpf-userspace-fw0 -- bpftrace -l 'tracepoint:napi:napi_poll'
   ```
   Both tracepoints must exist. If `napi:*` tracepoints absent on the
   guest kernel, fall back to `kprobe:__napi_complete_done`.
4. **Artifact emission:**
   ```
   incus exec loss:xpf-userspace-fw0 -- \
     bash -c 'bpftrace -e "tracepoint:napi:napi_complete_done { @ = count(); } interval:s:2 { exit(); }" 2>/dev/null | grep -q "@:"'
   ```
   Proves the script attaches and emits a non-empty count within 2 s.

### 9.3 P3 G8 smoke (post-daemon-PR verification)

Runs **after** Issue B (P3 implementation issue) lands the new
histogram + counter fields in the wire format.

1. **Tooling:**
   ```
   incus exec loss:xpf-userspace-fw0 -- pidof xpf-userspace-dp
   ```
   Helper running.
2. **Privilege:** none beyond control-socket access (already required
   for `step1-capture.sh`).
3. **Surface:**
   ```
   incus exec loss:xpf-userspace-fw0 -- \
     bash -c 'echo "{\"type\":\"status\"}" | nc -U /run/xpf/userspace-dp.sock | \
              jq -r ".status.per_binding[0] | keys[]" | grep -q tx_kick_latency_hist'
   ```
   New fields surfaced on the wire.
4. **Artifact emission:** one cycle of `step1-capture.sh` produces
   `flow_steer_samples.jsonl` containing the new field on every
   sample.

**G8 verification.** P1, P2, P3 each carry four-command guest-side
smoke sequences. Tooling, privilege, surface, and artifact-emission
are all covered. G8 satisfied as specification; smoke-run artifacts
are produced at implementation-issue-filing time, not in this doc.

## 10. Implementation issue queue

This §is the design doc's actionable output. Implementor consumes
this list to file per-probe implementation issues in dependency
order.

### Issue A — P1: `step2-sched-switch-capture.sh` sister harness

- **Title.** "Wire `step2-sched-switch-capture.sh` sister harness for
  P1 off-CPU duration probe (#819 follow-up)."
- **Files first.** This is the first probe; it unblocks §7.1 branching.
- **Scope.** §4.1 above. Sister harness composes `step1-capture.sh`
  with `perf record` concurrently against worker TIDs; reducer emits
  `off-cpu-hist-by-block.jsonl` per §4.1 schema; analysis produces
  `correlation-report.md` per §5.1 read-off rules.
- **Acceptance criteria.**
  - §9.1 P1 G8 smoke (four-command sequence) runs clean inside
    `loss:xpf-userspace-fw0`.
  - Both load-bearing cells capture one 60-s run each, plus the §6.2
    negative-control run on `p5203-fwd-no-cos`.
  - `correlation-report.md` reports `ρ`, `sum_over_blocks(off_cpu_time_3to6)/60s`,
    voluntary/involuntary split, and a T3 IN/OUT/INCONCLUSIVE verdict
    per cell.
  - Field name `off_cpu_time_3to6` present in emitted JSON (matches
    §4.1 canonical form).
- **Closes #819 if.** P1 → M3 IN on both cells (§7.1).

### Issue B — P3: `tx_kick_latency_hist` + `tx_kick_retry_count` daemon counters

- **Title.** "Wire `tx_kick_latency_hist` + `tx_kick_retry_count`
  daemon counters (#819 P3 follow-up)."
- **Files only after.** Issue A completes with verdict M3 OUT on at
  least one cell, or split (per §7.1).
- **Scope.** §4.3 above. File-scope change list (hot-path counter,
  owner snapshot, wire format, coordinator copy, parser/analysis,
  tests). Implementation matches #812's overhead budget.
- **Acceptance criteria.**
  - Unit tests + wire-format round-trip green.
  - Bench stub mirrors #812's overhead test; overhead within #812's
    budget.
  - §9.3 P3 G8 smoke passes post-merge on `loss:xpf-userspace-fw0`.
  - New fields surface in `flow_steer_samples.jsonl` on every sample
    from `step1-capture.sh`.
  - `step1-histogram-classify.py` parses the new histogram and
    counter into per-block deltas.
- **Closes #819 if.** P3 → M1 IN on applicable cell(s) (§7.2).

### Issue C — P2: `step2-napi-cadence-capture.sh` bpftrace harness

- **Title.** "Wire bpftrace NAPI cadence harness
  `step2-napi-cadence-capture.sh` (#819 P2 follow-up)."
- **Files only after.** Issue A + Issue B complete with verdict OUT
  on at least one cell for both M3 and M1 (per §7.3).
- **Scope.** §4.2 above. Sister harness composes `step1-capture.sh`
  with bpftrace script attached to the identified RX CPU;
  post-processing emits `napi-cadence-by-block.jsonl`; analysis
  reports T2 IN/OUT per cell.
- **Acceptance criteria.**
  - §9.2 P2 G8 smoke (four-command bpftrace sequence) runs clean.
  - RX queue → CPU mapping enumerated for both load-bearing cells
    before capture.
  - Fallback decision (tracepoint vs `kprobe:__napi_complete_done`)
    recorded in the implementation issue.
  - Both load-bearing cells capture one 60-s run each.
  - `correlation-report.md` reports p99 inter-arrival during
    T_D1-elevated blocks and a T2 IN/OUT verdict per cell.
- **Closes #819 if.** P2 → M2 IN (§7.3).

### Issue D — P4: L0 `perf kvm` hypervisor-side probe (deferred)

- **Title.** "L0 `perf kvm` hypervisor-side probe for M4 (#819 P4
  follow-up; deferred per plan §12)."
- **Files only on.** §7.3 firing OR §Deferrals M4 trigger firing
  (P1 reports >1% off-CPU mass in buckets 3-6 with M3 OUT at
  ρ ≤ 0.3).
- **Scope.** §4.4 above (placeholder wiring summary). The
  implementation issue expands the wiring at filing time. L0 shell
  access is a prerequisite.
- **Closes #819 if.** P4 → M4 IN (T4 per §3.2).

### Issue E — P5: client-side `ss` socket-buffer sampling / iperf3 send-time (deferred)

- **Title.** "Client-side `ss` socket-buffer sampling for M5 trigger
  check (#819 P5 follow-up; deferred per plan §12)."
- **Files only on.** §7.3 firing OR §Deferrals M5 symptom-check
  trigger firing (`Send-Q` fill-drain transitions ≥ 5/s with ρ ≥ 0.5
  vs `T_D1,b` time-aligned to client wall clock).
- **Scope.** §4.5 above (placeholder wiring summary). Begins with the
  cheap `ss`-based symptom check; escalates to full iperf3 send-time
  histogram (patched iperf3 OR tcpdump post-processing) only if the
  symptom check fires.
- **Closes #819 if.** P5 → M5 IN (T5 per §3.2).

## 11. Validation gates checklist (G1-G8)

Per plan §9, the design doc is COMPLETE when G1-G8 pass. Each gate is
confirmed below:

- **G1 — Matrix completeness.** §2 matrix: every mechanism row has at
  least one IN/OUT cell. §3.2 names the thresholds (T1-T5) backing
  every IN/OUT cell. **SATISFIED.**
- **G2 — Wiring spec per probe.** §4.1 (P1), §4.2 (P2), §4.3 (P3)
  each specify tooling, capture point, exact command / code-change
  scope, output format, post-processing recipe, harness integration.
  §4.4 (P4) and §4.5 (P5) carry placeholder wiring summaries tied
  to un-deferral triggers. **SATISFIED.**
- **G3 — Analysis recipe per probe.** §5.1 (P1), §5.2 (P2), §5.3 (P3)
  each specify IN / OUT / INCONCLUSIVE read-off rules tied to §3.2
  thresholds. **SATISFIED.**
- **G4 — Decision tree.** §7 terminates at Phase 4 scopes OR named
  follow-up probes. Per-cell branches covered (§6.3 + §7.1-7.3
  "split" cases). **SATISFIED.**
- **G5 — Capture-protocol delta from #816 minimal and named.** §6
  enumerates: two cells only, no matrix re-run, no new baselines,
  sister harness composition, per-cell mechanism split. Worked
  split-verdict example present (§6.3). **SATISFIED.**
- **G6 — Each deferred mechanism named with risk statement.** §8
  covers M4, M5, Option C, Z_cos, T_D2, per-baseline-run sanity
  gate, Path B coupling. Each has un-deferral trigger + residual
  risk statement. **SATISFIED.**
- **G7 — No wiring implementation.** This doc is spec only. No probe
  code, no daemon diffs, no harness scripts emitted here. §10
  Implementation issue queue enumerates follow-up issues that will
  land the code. **SATISFIED.**
- **G8 — Feasibility / preflight smoke tests.** §9.1 (P1), §9.2 (P2),
  §9.3 (P3) each ship four-command guest-side smoke sequences
  covering tooling, privilege, target surface, artifact emission.
  NONE executed yet — they are pre-conditions for filing the §10
  implementation issues. **SATISFIED as specification.**

## 12. Replan triggers

- **RT-1 (Path B forward-cell flip).** If #817 flips `stat_D1` sign
  on p5201-fwd OR p5202-fwd, re-plan. Risk low per findings
  §Reproducibility ("enormous margin"). **Does NOT pause #819** in
  absence of flip — #817 runs in parallel.
- **RT-2 (design doc grows code).** If any round produces a
  `design.md` that lands probe code instead of spec, halt: wrong
  workflow.
- **RT-3 (scope-creep into #816 verdict).** If Codex review drifts
  into "is D1 really what the histogram shows?", halt. D1-vs-D2 is
  #816's question, not #819's.

---

*End of design doc. §10 Implementation issue queue is the
actionable output; §11 G1-G8 checklist is the completeness contract.*
