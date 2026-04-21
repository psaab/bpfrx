# Issue #819 — Architect plan: Step 2 discriminator-telemetry design doc

> **Status.** Architect Round 2. Round 1 Codex review returned 5 HIGH +
> 4 MEDIUM + 2 LOW (PLAN-READY NO); every HIGH and MEDIUM is addressed
> below, either (a) fixed with a named change, or (b) explicitly
> deferred with a risk statement. See
> `docs/pr/819-step2-discriminator-design/codex-plan-review.md` Round
> 1 response (appended after the findings).
>
> **Deliverable.** `docs/pr/819-step2-discriminator-design/design.md`,
> written AFTER this plan is PLAN-READY YES. Follow-up wiring for
> each named probe is a separate implementation issue per probe.
>
> **No code lands under this plan.** No captures run. No cluster
> changes. The plan describes a design doc; the design doc describes
> probes; probes are implementation issues.

## 1. Problem statement

Per `docs/pr/816-step1-rerun/findings.md` §1 (verdict) and §5
(concluding verdict):

> "**H2 D1 (XSK submit→DMA latency elevated cross-cell on
> shaped-traffic cells.)** … Per plan §8: *'XSK submit→DMA latency
> elevated cross-cell.' → Scope #793 Phase 4 against in-AF_XDP
> submit-path queueing / per-CPU NAPI drift / sendto kick
> regressions.*"

The H2 D1 verdict is load-bearing on two cells (findings §1.2):
**p5201-fwd-with-cos** (`stat_D1 ≈ 0.969`, mode=4) and
**p5202-fwd-with-cos** (`stat_D1 ≈ 0.885`, mode=5). Reverse-direction
fires (p5201-rev, p5203-rev, `stat_D1 ≈ 0.01-0.02`) are
within-the-gate corroboration, not independently strong.

Findings §7 enumerates **five candidate mechanisms** for the
elevated submit→DMA latency. The round's data does NOT distinguish
among them:

1. **Submit→TX DMA stalls under no-shaper backpressure** — AF_XDP
   submit-path queueing internal to the dataplane.
2. **RX-side NAPI budget exhaustion leaking into TX scheduling** —
   cross-CPU softirq/worker coupling.
3. **Kernel scheduler descheduling the worker between `sendto` and
   reap** — scheduler jitter on the worker CPU.
4. **Virtualization jitter** — nested-hypervisor VM-exit artifacts.
5. **iperf3 client-side burstiness** — input waveform shape
   contaminating the downstream signal.

**Why discrimination matters.** #816 plan §8 decision tree gave H2
D1 a verdict-to-action mapping: "*Scope #793 Phase 4 against
in-AF_XDP submit-path queueing / per-CPU NAPI drift / sendto kick
regressions.*" Those three named directions correspond to
mechanisms (1) + (2) + a specific sub-case of (1) inside the
daemon. Mechanisms (3), (4), (5) would each re-scope #793 Phase 4
entirely (scheduler tuning, VM/host placement work, iperf3 harness
replacement respectively). **Phase 4 scope cannot be written until
the dominant mechanism is named.** This issue scopes the telemetry
to name it.

### 1.1 What this plan is and isn't

**This plan is the PLAN for a DESIGN DOC, not for code.** The
deliverable of #819 is `design.md`. The design doc names probes,
specifies wiring requirements, and specifies a capture protocol —
it does NOT implement any probes. Each probe named in the approved
design doc becomes a separate follow-up issue for the Implementor.

## 2. Hypotheses — the 5 mechanisms as predictions

Each mechanism is re-stated as a **predicted observable signature**
on probe telemetry. The design doc's job is to pick probes that
distinguish these signatures.

- **M1 — Submit→TX DMA stalls (in-AF_XDP).** Signature: elevated
  `T_D1` correlates with a per-worker counter whose units are
  "retry-loop iterations inside AF_XDP submit path" OR "wall-clock
  µs spent inside `sendto()` before syscall return." Worker is
  on-CPU throughout the gap; the time is spent either spinning on
  a full ring or blocked inside the kernel syscall.
- **M2 — RX NAPI budget exhaustion leaking into TX.** Signature:
  elevated `T_D1` correlates with `napi_complete_done` cadence
  anomalies on the RX queue (long between-drain intervals) AND/OR
  RX-softirq CPU contention with the TX worker CPU. Worker may be
  on-CPU but blocked on cache/softirq contention.
- **M3 — Scheduler descheduling the worker.** Signature: elevated
  `T_D1` correlates with worker-CPU **off-CPU time in buckets 3-6
  (4-64 µs)**, NOT raw switch count. A voluntary/involuntary
  split on the off-CPU intervals is informative: *involuntary*
  points at CFS preemption (another task stole the CPU);
  *voluntary* at the worker going to sleep (e.g. a full-ring
  return path). **See §5.1 for the full off-CPU reducer.**
- **M4 — Virtualization jitter.** Signature: elevated `T_D1`
  correlates with `KVM_REQ_*` exit density (HALT, external
  interrupt, TSC sync) on the vCPU hosting the worker. Needs L0
  `perf kvm` access; guest-side we can only observe *symptoms*
  (CPU "lost cycles" gaps between `monotonic_nanos()` reads),
  which is circumstantial, not dispositive.
- **M5 — iperf3 client burstiness.** Signature: per-packet
  client-side send-time histogram shows bimodal or long-tail
  inter-send gaps on the two load-bearing cells, and/or
  server-side receive-time histogram shows a matching pattern
  that tracks the submit→DMA elevation.

**Joint fires are possible.** These are not mutually exclusive
predictions. §8 decision tree covers compound verdicts; §6.3
covers per-cell mechanism splits (HIGH-3 fix).

## 3. Approach choice — A vs B vs C

Per #819's "Approach options" enumeration:

- **Option A — probes one at a time, ordered by informativeness.**
- **Option B — all five probes in parallel in one capture window.**
- **Option C — composite multi-point latency probe** (sendto-entry,
  inside-AF_XDP, NIC-TX-complete, RX-kernel-return).

### 3.1 Recommendation: **Option A, with a parallel-escape clause.**

**Rationale.**

1. **Cheap per round.** `perf record -e sched:sched_switch` on the
   worker CPU adds zero daemon code and no cluster-config drift.
   Per-cell capture is ~10 min wall-clock, well under any
   maintenance window. (See §6 capture budget table.)
2. **M3 is dispositively discriminable by off-CPU time in buckets
   3-6.** The HIGH-1 redesign (§5.1) replaces raw switch counts
   with off-CPU duration bucketed on the same log2 axis as
   `T_D1`. A clean M3-OUT result narrows the field from 5 → 4
   and promotes P3 to next.
3. **Iteration over parallelism.** Option A amortizes only
   against the probes that are actually needed; Option B spends
   every probe's setup cost up front.
4. **Parallel-escape clause for worst-case budget (MED-7 fix; MED-7 NOT-RESOLVED Round-2 → Round-3 honest restatement).**
   The plain `P1 OUT → P3 OUT → P2` path in §8 reaches **3 design-doc
   rounds** with no additional conditions — Codex Round 3 was right
   that the prior "expected vs pathological" framing misrepresented
   the §8 branching. Restated honestly:
   - **Expected path** (best case): 1 round if P1 IN/OUT decisive
     and either (a) M3 IN closes #819, or (b) M3 OUT routes to P3
     and P3 fires decisively in the same round if P3 wiring has
     already landed. **2 rounds** if P3 wiring lands separately.
   - **Plain serial path:** P1 OUT → P3 OUT → P2 = **3 rounds**.
     This is not "pathological" — it's the natural sequence when
     M1/M2/M3 each rule out cleanly. The §3.4 table row 4 estimate
     (~5-8 weeks wall-time) is the honest ceiling for this case.
   - **§8 INCONCLUSIVE escape** (P1 returns INCONCLUSIVE on first
     pass): file P3 in parallel with a 1-s P1 re-bin. This shaves
     a round in the inconclusive subcase, taking 1-2 rounds
     instead of 2-3.
   - **§8.4 all-silent pivot:** if P1+P3+P2 all silent, optional
     pivot to Option C OR close as "below floor" — does not add
     more probe rounds, but does add Option C's multi-PR cost
     (§3.4 row 5).
   No internal contradiction with §8 branching; the 3-round path
   is real and is named honestly in §3.4 row 4.
5. **Cluster-window politeness.** The userspace cluster is shared.
   Option A slots into existing maintenance windows.

### 3.2 Why NOT Option B

Option B's definitive-in-one-shot appeal rests on the assumption
that the mechanisms are non-interacting and that all five probes
are cheap. Two mechanisms break that assumption:

- **M4 (virtualization jitter) needs hypervisor-side access we may
  not have.** If we don't have L0 shell, M4's probe is blocked
  and Option B can't close on all five anyway.
- **M5 (iperf3 burstiness) needs client-side changes.** Neither a
  patched iperf3 nor a tcpdump+analysis pipeline exists today in
  `test/incus/`.

### 3.3 Why NOT Option C

Option C's multi-point latency probe is the most elegant output
but requires four-point per-descriptor stamping, three new
histograms, wire-format updates, overhead re-validation
(#812 §3.4), and `step1-capture.sh` harness updates. It is a
full multi-PR workstream unjustified as a FIRST step when the
cheap one-probe path may resolve the question. Option C
un-defers at §8.4's "all probes silent" leaf.

### 3.4 Honest worst-case end-to-end budget (MED-7 fix)

| Branch                                 | DD rounds | Impl lag            | Capture (min) | Analysis (min) | Review rounds | Wall-time estimate |
|----------------------------------------|-----------|---------------------|---------------|----------------|---------------|---------------------|
| P1 decisive (M3 IN or OUT → P3 fires)  | 1         | P1: none            | 2×10          | 30             | 2             | ~1-2 weeks          |
| P1 decisive → P3 decisive              | 2         | P3: 1-2 weeks       | 4×10          | 60             | 4             | ~3-5 weeks          |
| P1 inconclusive + parallel P3          | 1 (par.)  | P3: 1-2 weeks       | 4×10          | 60             | 2             | ~2-3 weeks          |
| P1 → P3 → P2 serial (worst)            | 3         | P3+P2: 2-4 weeks    | 6×10          | 90             | 6             | ~5-8 weeks          |
| §8.4 all-silent → Option C pivot       | 4+        | C: multi-PR (#812-class) | N/A      | N/A            | 6+            | ≥8 weeks            |

Option A's expected path is rows 1-2. Row 3 is the parallel-escape
path that fires only on a P1 INCONCLUSIVE outcome. **Row 4 (3-round
serial) is the honest budget when P1 OUT → P3 OUT → P2 each rules
out cleanly** — this is not avoided by Row 3's escape (the escape
applies to the INCONCLUSIVE branch only, per §3.1 #4). Row 5 is the
honest worst case if multiple probes come back silent and Option C
un-defers; at that point the question is whether to close #793 Phase 4
as "below measurement floor" instead of paying for the C workstream.
Row-4 vs Row-3 selection is data-driven: if P1 is decisive Row 3 is
moot; if P1 is inconclusive Row 3 fires; if P1 is decisive but each
subsequent probe rules cleanly, Row 4 is the natural outcome and is
not bypassed.

## 4. Mechanism-vs-discriminator matrix

Cell labels: **IN** / **OUT** / **INF** (informative) / **SIL** (silent) / **UNC** (uncertain). Per HIGH-2, every IN/OUT cell has a numerical threshold (§4.1).

| Mechanism | P1: off-CPU duration by bucket | P2: `napi_complete_done` cadence | P3: TX kick latency histogram + retry counter | P4: `perf kvm stat` (L0) | P5: iperf3 client send-time histogram |
|---|---|---|---|---|---|
| **M1 — submit→DMA stall** | INF | INF | **IN/OUT** (T1) | SIL | SIL |
| **M2 — RX NAPI exhaustion** | INF | **IN/OUT** (T2) | INF | SIL | SIL |
| **M3 — scheduler desched** | **IN/OUT** (T3) | INF | SIL | INF | SIL |
| **M4 — virtualization jitter** | INF | SIL | SIL | **IN/OUT (T4) or UNC** | SIL |
| **M5 — iperf3 burstiness** | SIL | SIL | INF | SIL | **IN/OUT** (T5) |

### 4.1 Thresholds (HIGH-2 fix; HIGH-2 PARTIAL Round-2 spec tightening)

**Definition: "T_D1-elevated blocks".** A 5-s block `b` is "T_D1-elevated" if its `T_D1,b` value (the bucket-3-to-6 mass fraction per #816 plan §4.2 / `step1-histogram-classify.py:159-163`) is in the **top quartile** of the 12 blocks in the cell's capture, i.e. `T_D1,b ≥ percentile(T_D1, 75)`. Concretely: rank the 12 block values, take the top 3 (12 ÷ 4 = 3 rounded). Reference: `evidence/with-cos/<cell>/hist-blocks.jsonl` lines 1-12, field `shape[3]+shape[4]+shape[5]+shape[6]`. Used by T1, T2, T4 below for "during T_D1-elevated blocks" and by T3 for the inconclusive-band re-bin.

- **T3 — M3 IN via P1:** `Spearman(T_D1,b, off_cpu_time_buckets_3to6_b) ≥ 0.8` (computed across all 12 blocks) **AND** `sum_over_blocks(off_cpu_time_buckets_3to6) / 60s ≥ 1%`. **T3 OUT:** `ρ ≤ 0.3` OR `total_off_cpu_3to6 / 60s < 1%`. **T3 INCONCLUSIVE:** `0.3 < ρ < 0.8`. Justification: §7.1.
- **T1 — M1 IN via P3 (HIGH-2 PARTIAL Round-3 — pre-registered, no post-hoc band):** `Δ(retry_counter)/block ≥ 1000 events` during T_D1-elevated blocks (top 3 blocks per §4.1 definition) **AND** `mean(sendto_kick_latency) ≥ 4 µs` (lower edge of bucket 3). **T1 OUT:** `Δ(retry_counter)/block < 100 events on every block` AND `mean(sendto_kick_latency) < 2 µs across all blocks` (bucket ≤ 1, below where D1 lives). **T1 INCONCLUSIVE:** anything between (e.g. retry counter in 100–1000/block range, or mean kick latency in 2–4 µs band). Pre-registered before P3 captures; the "calibration band set after first capture" clause from Round 2 is withdrawn — the IN/OUT/INCONCLUSIVE bands are fixed thresholds.
- **T2 — M2 IN via P2:** p99 inter-`napi_complete_done` interval on the RX queue during T_D1-elevated blocks ≥ 100 µs. **T2 OUT:** p99 ≤ 10 µs across all blocks AND no correlation with T_D1,b (ρ ≤ 0.3).
- **T4 — M4 IN via P4:** `Δ(KVM_REQ_HALT + KVM_REQ_EVENT)/block` on the worker vCPU shows ρ ≥ 0.8 with T_D1,b AND exit-count rate ≥ 100/s during elevated blocks. Guest-only proxies → UNC.
- **T5 — M5 IN via P5:** client-side inter-send-time p99 ≥ 10 µs on the two load-bearing cells AND ρ ≥ 0.8 with T_D1,b after time-alignment.

### 4.2 Matrix validation gate

Every mechanism row has at least one IN/OUT cell (§9 G1). Per HIGH-2 every IN/OUT cell has a named threshold above. Design doc inherits §4.1 verbatim.

## 5. Per-probe wiring spec

### 5.1 P1 — sched_switch perf-record reduced to off-CPU duration histogram (HIGH-1 redesign)

**Tooling.** `perf record` with `sched:sched_switch` + `sched:sched_stat_runtime` + `sched:sched_wakeup` for 60 s on the worker TIDs.

**Capture point.** `loss:xpf-userspace-fw0`. Worker TIDs from `test/incus/step1-capture.sh:252` (`WORKER_TIDS`).

**Exact command (design doc draft).**

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

**Post-processing — off-CPU duration by log2 bucket (HIGH-1 fix; HIGH-1 PARTIAL Round-2 spec tightening).**

The reducer consumes the time-ordered `perf script` event stream and emits a per-block 16-bucket off-CPU duration histogram. The three tracepoints play distinct roles:

- **`sched_switch`** is the *primary* event. For each `sched_switch (prev=TID, prev_state=off)` event timestamped at `t_off`, the TID went off-CPU. This event also carries `prev_state` (R/S/D/etc.) which feeds the voluntary/involuntary classification.
- **`sched_wakeup`** is the *off→runnable* signal. The next `sched_wakeup TID` event timestamped at `t_wake` marks when the TID became runnable again. The time delta `t_wake - t_off` is the TID's off-CPU duration for that switch pair.
- **`sched_stat_runtime`** is the *sanity check*. `sched_stat_runtime` carries `runtime` and `vruntime` deltas accumulated while a TID was on-CPU; it's used in the reducer ONLY as a cross-check that the on-CPU intervals between off-CPU pairs sum to the expected wall-clock minus aggregate off-CPU time. A mismatch >1% triggers a sanity-check warning in `correlation-report.md` (does not affect verdict). It is not part of the per-block aggregate formula.

**Aggregate formula.** For each TID `tid` and each 5-s block `b ∈ 0..=11`:

```
off_cpu_durations(tid, b) := { (t_wake - t_off) :
                                t_off ∈ [b·5s, (b+1)·5s) ,
                                next sched_wakeup(tid) at t_wake }

bucket_idx(d_ns) := bucket index in [0..15] per #812 plan §11 layout

off_cpu_time_3to6(tid, b) := Σ over off_cpu_durations(tid, b) of d
                              if 3 ≤ bucket_idx(d_ns) ≤ 6 else 0

off_cpu_time_3to6,b      := Σ over all worker tids of off_cpu_time_3to6(tid, b)
```

**Field-name canonical form (HIGH-1 PARTIAL Round-4 alignment).** The per-block JSON emits the cell-level aggregate as **`off_cpu_time_3to6`** (the same name §7.1 and §4.1 use for `off_cpu_time_3to6,b`). The earlier shorthand `sum_3to6` from Round 2 is renamed to keep §5.1 emit, §7.1 read, and §4.1 threshold all on one canonical field name.

Voluntary vs involuntary split: a switch is **voluntary** if `prev_state ∈ {S, D, I}` (worker went to sleep); **involuntary** if `prev_state == R` (CFS preempted a runnable task). Bucket each side separately.

**Per-block output (one JSON line per block):**

```
{ "b": <int 0..11>,
  "buckets": [<u64> × 16],
  "off_cpu_time_3to6": <u64 ns>,         # also referenced as `off_cpu_time_3to6,b` in §7.1; same field
  "voluntary_3to6": <u64 ns>,
  "involuntary_3to6": <u64 ns>,
  "stat_runtime_check": "PASS" | "WARN" }
```

**M3 IN/OUT decision (T3).** Does `off_cpu_time_3to6,b` correlate with `T_D1,b` at ρ ≥ 0.8, AND total off-CPU mass in buckets 3-6 ≥ 1% duty cycle?

**Output format.**

```
evidence/p<port>-fwd-with-cos/sched-switch/
    perf.data
    perf-script.txt
    off-cpu-hist-by-block.jsonl   # 12 lines: {b, buckets[16], off_cpu_time_3to6, voluntary_3to6, involuntary_3to6}
    correlation-report.md
```

**Per-cell cadence.** One 60-s capture per load-bearing cell.

**Integration.** **Sister harness.** New `test/incus/step2-sched-switch-capture.sh` invokes `step1-capture.sh` (for the histogram baseline) AND runs `perf record` concurrently against the same TIDs.

**Privilege preflight (MED-6 fix; MED-6 PARTIAL Round-2 host/guest distinction).** §9 G8 requires P1 to ship a **four-command** smoke test, all four executed inside the GUEST (`loss:xpf-userspace-fw0`), NOT on the L0 incus host. Sysctl scope is per-namespace and the relevant value is the guest-kernel one because that's what governs `perf` on guest TIDs:

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
   Confirms the .data is parseable by `perf script` and contains the expected event type.

If command 1 returns > 1, runtime guest-side change (NOT host):

```
incus exec loss:xpf-userspace-fw0 -- sysctl -w kernel.perf_event_paranoid=1   # window-only, revert after
```

(Reversible inside the guest; no host change; no image rebuild.) **Fallback:** `bpftrace` on `kprobes:__schedule` inside the guest with the same reducer pipeline; design doc carries both specs and G8 smoke decides which ships.

### 5.2 P2 — NAPI cadence (sketch)

**Tooling (candidates).** `bpftrace` on `napi_complete_done:entry` + `napi_poll:entry` with inter-call interval histogram; OR perf-record on the same tracepoints.

**Capture point (LOW-4 fix).** fw0 VM, kernel-side. The load-bearing cells run TX on `ge-0-0-1` / `ge-0-0-2` (ZeroCopy per `docs/pr/line-rate-investigation/step0-audit.md:18-27`). Design doc must enumerate exact RX queue / CPU mapping per cell.

**Design-doc-level questions.**
- Which RX queue ID on `ge-0-0-1` / `ge-0-0-2` hosts load-bearing traffic per cell?
- Which CPU runs that RX softirq? Shared with the TX worker CPU?

### 5.3 P3 — AF_XDP TX-kick latency + retry counter (HIGH-5 fix)

**TX kick site correction.** Codex Round 1 finding 9 confirmed: `tx.rs:284` is `maybe_wake_rx` (RX wake path's TX-completion reap), **not** the TX kick. Actual TX kick: **`maybe_wake_tx` at `userspace-dp/src/afxdp/tx.rs:6429`**, with `sendto` syscall at line 6439. P3's instrumentation site is pinned to `maybe_wake_tx`.

**File-scope change list (replaces "~200-line Rust change" estimate).**

- **Hot-path counter + histogram** in `userspace-dp/src/afxdp/tx.rs` around `maybe_wake_tx` (line 6429): increment a per-binding retry counter when the TX kick `sendto` returns EAGAIN/EWOULDBLOCK (line 6453); capture timestamp pair around `sendto` (lines 6438-6447) into a 16-bucket histogram identical in shape to `tx_submit_latency_hist`.
- **Owner snapshot state** in `userspace-dp/src/afxdp/worker.rs` (mirror the `tx_submit_latency_hist` projection at `worker.rs:4240-4247`).
- **Wire-format additions** in `userspace-dp/src/protocol.rs:1320-1343`: add `tx_kick_latency_hist`, `tx_kick_latency_count`, `tx_kick_latency_sum_ns`, `tx_kick_retry_count`. Go mirror in `pkg/dataplane/userspace/protocol.go:697,682`.
- **Coordinator copy** in `userspace-dp/src/afxdp/coordinator.rs:1428-1440` and clear path at `:1530`.
- **Parser/analysis additions** in `test/incus/step1-histogram-classify.py` and `test/incus/step1-capture.sh` (extracts new histogram from existing JSON snapshot).
- **Tests**: unit tests for the histogram recording path and wire-format round-trip; bench stub mirroring #812's overhead test.

**Capture point.** Same as `tx_submit_latency_hist` today — existing `step1-capture.sh` snapshot loop catches new counters once wire format is bumped.

**Design-doc-level questions.**
- Timestamp source: `clock_gettime(CLOCK_MONOTONIC)` vs the already-hot `monotonic_nanos()` reader used by submit-path telemetry?
- Retry-counter semantics: count EAGAIN returns vs inner retry-loop iterations?
- Overhead re-validation against #812's budget.

## 6. Capture protocol

**What changes vs #816.**

- **Scope reduction: re-run only two cells.** p5201-fwd-with-cos and p5202-fwd-with-cos.
- **NO re-run of the 12-cell matrix.**
- **NO new baseline pools.** Discriminator is intra-cell.
- **Same cluster.** `loss:xpf-userspace-fw0` only.
- **Same CoS config.** Canonical `full-cos.set` from #816.
- **Concurrent-run composition.** Sister harness per probe runs `step1-capture.sh` + the probe-side tool concurrently against the same TIDs.

### 6.1 Capture-run timing

| Probe | Captures | iperf3 time | Total wall-clock |
|---|---|---|---|
| P1 (off-CPU duration)      | 2 cells × 60 s | 2 min | ~10 min       |
| P2 (NAPI cadence)          | 2 cells × 60 s | 2 min | ~15 min       |
| P3 (TX-kick + retry)       | 2 cells × 60 s | 2 min | ~10 min after daemon wiring lands |

### 6.2 Negative-control spot-check

Run P1 once on a D1-quiet cell (e.g. `p5203-fwd-no-cos`). If off-CPU mass in buckets 3-6 there is comparable to the load-bearing cells, the probe is non-informative.

### 6.3 Per-cell mechanism split handling (HIGH-3 fix)

p5201-fwd-with-cos (~1 Gbps shaped) vs p5202-fwd-with-cos (~10 Gbps shaped) — 10× spread. Different dominant mechanisms possible.

- **Single-mechanism close.** Both cells agree on a per-probe verdict → close on global verdict; one Phase 4 scope.
- **Split verdict at any probe stage.** Verdicts diverge → split-mechanism outcome:
  - The IN-cell proceeds to its named Phase 4 sub-scope.
  - The OUT-cell continues through the probe order on its own.
  - #819 may spawn **two separate Phase 4 sub-scope issues**, one per cell.
- **Applies recursively at P3 and P2.**
- **Design doc** must include a worked split-verdict example.

## 7. Analysis recipe — per probe

### 7.1 P1 (off-CPU duration) — how to read it

Per block `b ∈ 0..=11`:

1. From `hist-blocks.jsonl`: compute `T_D1,b` (mass fraction in buckets 3-6).
2. From `off-cpu-hist-by-block.jsonl`: read `off_cpu_time_3to6,b` directly (the reducer already aggregates across worker TIDs per §5.1 formula). Per-TID breakdown is NOT in the per-block JSON; if needed for diagnostic purposes, recompute from `perf-script.txt` raw events. (HIGH-1 PARTIAL Round-3 — analysis-recipe shape now matches the reducer output.)
3. **Scatter-plot** `T_D1,b` (x, 12 points) vs `off_cpu_time_3to6,b` (y).
4. Read-off rules (T3, §4.1):
   - **M3 IN:** `ρ ≥ 0.8` AND `sum(off_cpu_time_3to6) / 60s ≥ 1%`.
   - **M3 OUT:** `ρ ≤ 0.3` OR `sum(off_cpu_time_3to6) / 60s < 1%` (the "OR" matters — <0.6s of off-CPU time over 60s can't explain D1 mass regardless of correlation).
   - **M3 INCONCLUSIVE:** `0.3 < ρ < 0.8`. Re-bin at 1-s blocks (60 points) from same `perf.data` (no re-capture). If still inconclusive, file P3 in parallel (§8 escape).

**ρ-threshold justification (HIGH-4 fix).** N=12, two-sided Spearman critical ρ at α=0.05 ≈ 0.587. Round 1's ρ ≥ 0.6 was barely significant. **ρ ≥ 0.8** gives P(|ρ| ≥ 0.8 | null) ≈ 0.001 (Monte-Carlo on 12 independent uniform points), FP < 0.1%. **ρ ≤ 0.3** OUT keeps an explicit inconclusive band (0.3, 0.8) rather than pretending the marginal region is conclusive. The 60-point 1-s re-bin's critical ρ at α=0.05 narrows to ≈ 0.255, design doc tightens accordingly.

**Test-statistic alternative.** If off-CPU-duration distribution is strongly zero-inflated, the design doc may pick **Mann-Whitney U comparing per-block `T_D1,b` between top-quartile and bottom-quartile `off_cpu_time_3to6,b` blocks** (3-block groups at N=12) OR re-capture at N=48 from a 4-min window. Design doc decides; this plan does not.

### 7.2 P2 / P3 — sketch

Design doc fills in. Pattern mirrors P1: per-block correlation between `T_D1,b` and probe-specific signal, with explicit IN / OUT / INCONCLUSIVE read-off rules against §4.1 thresholds.

## 8. Decision tree

Branches evaluated **per cell** (§6.3).

### 8.1 After P1

- **P1 → M3 IN on both cells.** Phase 4 = scheduler-jitter mitigation (RT SCHED_FIFO, `isolcpus=`, iperf3 client off worker cores). Close #819.
- **P1 → M3 OUT on both cells.** Proceed to P3.
- **P1 → split.** Per §6.3: file sub-scope Phase 4 issue for IN-cell; file P3 implementation issue targeting OUT-cell only.
- **P1 → INCONCLUSIVE.** Re-bin at 1-s (no re-capture). If still inconclusive, parallel-escape: file P3 in parallel with 1-s re-bin.

### 8.2 After P3 (P1 M3-OUT)

- **P3 → M1 IN on applicable cell(s).** Phase 4 = in-AF_XDP TX-kick mitigation (rework `maybe_wake_tx`, batch-submit vs kick coalescing).
- **P3 → M1 OUT.** Proceed to P2.
- **P3 → MIXED.** Compound verdict; Phase 4 scope is "M1 + (next probe) joint."
- **P3 split.** Same per-cell branching as §8.1.

### 8.3 After P2 (P1+P3 both OUT on a cell)

- **P2 → M2 IN.** Phase 4 = RX NAPI / TX-worker CPU affinity rework.
- **P2 → M2 OUT.** M1, M2, M3 all ruled out on that cell. P4 / P5 un-defer.

### 8.4 Pathological — all probes silent

If P1, P2, P3 all SILENT or INCONCLUSIVE on both load-bearing cells: Option C un-defers OR close #793 Phase 4 as "below measurement floor."

## 9. Validation gates — for the design doc itself

- **G1 — Matrix completeness.** Every mechanism has at least one IN/OUT cell in §4.
- **G2 — Wiring spec per probe.** Tooling, capture point, exact command/code-change scope, output format, post-processing recipe, harness integration.
- **G3 — Analysis recipe per probe** with IN / OUT / INCONCLUSIVE rules tied to §4.1 thresholds.
- **G4 — Decision tree** terminates at Phase 4 scopes OR named follow-up probes; per-cell branches covered (§6.3).
- **G5 — Capture-protocol delta from #816 minimal and named.**
- **G6 — Each deferred mechanism named with risk statement.**
- **G7 — No wiring implementation.** Probes are follow-up issues.
- **G8 — Feasibility / preflight smoke tests (MED-11 fix; MED-11 PARTIAL Round-2 concretization).** Every decision-tree probe ships smoke tests proving (1) tooling availability, (2) capture privileges, (3) target surface, (4) artifact emission — all four executed inside the guest on `loss:xpf-userspace-fw0` before the probe's implementation issue may be filed.
  - **P1 G8** drafted in §5.1 (four-command sequence above).
  - **P2 G8 draft:**
    1. **Tooling:** `incus exec loss:xpf-userspace-fw0 -- which bpftrace` (must succeed).
    2. **Privilege:** `incus exec loss:xpf-userspace-fw0 -- bpftrace -e 'BEGIN { exit(); }'` (proves bpftrace can attach inside the guest).
    3. **Surface:** `incus exec loss:xpf-userspace-fw0 -- bpftrace -l 'tracepoint:napi:napi_complete_done' && incus exec loss:xpf-userspace-fw0 -- bpftrace -l 'tracepoint:napi:napi_poll'` (both tracepoints exist; if napi:* tracepoints absent on the guest kernel, fall back to `kprobe:__napi_complete_done`).
    4. **Artifact emission:** `incus exec loss:xpf-userspace-fw0 -- bash -c 'bpftrace -e "tracepoint:napi:napi_complete_done { @ = count(); } interval:s:2 { exit(); }" 2>/dev/null | grep -q "@:"'` (proves the script attaches and emits a non-empty count within 2 s).
  - **P3 G8 draft (post-daemon-PR):** after the P3 implementation issue lands the new histogram fields:
    1. **Tooling:** `incus exec loss:xpf-userspace-fw0 -- pidof xpf-userspace-dp` (helper running).
    2. **Privilege:** none beyond control-socket access (already required for `step1-capture.sh`).
    3. **Surface:** `incus exec loss:xpf-userspace-fw0 -- bash -c 'echo "{\"type\":\"status\"}" | nc -U /run/xpf/userspace-dp.sock | jq -r ".status.per_binding[0] | keys[]" | grep -q tx_kick_latency_hist'` (new fields surfaced on the wire).
    4. **Artifact emission:** one cycle of `step1-capture.sh` produces `flow_steer_samples.jsonl` containing the new field on every sample.

## 10. Non-negotiables

- **Userspace cluster only.** `loss:xpf-userspace-fw0` / `-fw1`. bpfrx forbidden.
- **No histogram API widening.** `tx_submit_latency_hist` stays 16 buckets `[AtomicU64; 16]`.
- **P3's new histogram (`tx_kick_latency_hist`) is additive** — alongside existing histogram, not replacement.
- **No per-flow histograms.** #812 deferral.
- **The #816 H2 D1 verdict is not up for re-litigation.**

## 11. Replan triggers

- **RT-1 (Path B forward-cell flip — LOW-10 rename from H-STOP-D1).** If #817 flips `stat_D1` sign on p5201-fwd OR p5202-fwd, re-plan. Risk low per findings §Reproducibility ("enormous margin"). **Does NOT pause #819** in absence of flip — #817 runs in parallel.
- **RT-2 (design doc grows code).** If any round produces a `design.md` that lands probe code instead of spec, halt: wrong workflow.
- **RT-3 (scope-creep into #816 verdict).** If Codex review drifts into "is D1 really what the histogram shows?", halt. D1-vs-D2 is #816's question.

## 12. Deferrals

- **M4 (virtualization jitter) probe (P4).** Deferred. **Rationale (MED-8 caveat):** low prior for "equally-affects-all-cells" jitter because no-cos cells are D1-quiet. **Counterexample:** workload-conditional M4 (MQFQ-imposed idle gaps creating hypervisor descheduling opportunities) is NOT excluded by regime-split alone. **Un-deferral triggers:** §8.3 fires; OR P1 reports >1% off-CPU mass in buckets 3-6 with M3 firmly OUT (`ρ ≤ 0.3` per §7.1 T3 OUT) — off-CPU time exists but scheduler is not the cause, hypervisor descheduling becomes the next suspect. (MED-8 PARTIAL Round-3: trigger band tightened from "0.6-0.8 inconclusive" to "≤ 0.3 OUT" so the M4 trigger does NOT fire inside §7.1's M3-INCONCLUSIVE 0.3-0.8 band — that band routes to a P1 re-bin first, not M4 un-deferral.) **Residual risk accepted:** if workload-conditional M4 is dominant and triggers don't fire (e.g. M1 swamps M4's signal), we will scope #793 against M1 and discover M4 residual post-fix.
- **M5 (iperf3 burstiness) probe (P5).** Deferred. **Same MED-8 caveat:** workload-conditional M5 (iperf3 burst clustering under shaper backpressure only) not excluded by regime-split alone. **Un-deferral triggers (MED-8 PARTIAL Round-2 concretization):**
  - §8.3 fires; OR
  - Cheap client-side `ss` symptom check fires. Specifically: during a load-bearing-cell capture window, on the iperf3 client (cluster-userspace-host), run `ss -tinm dst 172.16.80.200 sport :5201,5202` at 100 ms intervals for 60 s. For each sample, record `Send-Q` size and `cwnd`. If `Send-Q` shows ≥ 5 transitions between "near-empty" (< 4 KiB) and "near-full" (> 0.5 × `wmem_default`) per second on average, AND those transitions correlate with `T_D1,b` time-aligned to the client's wall clock at Spearman ρ ≥ 0.5, M5 un-defers. Rationale: a bursty client should show fill-drain cycles in the kernel sendbuf; a steady client shouldn't.
- **Option C (composite multi-point latency probe).** Deferred. Un-deferred only if §8.4 fires.
- **Z_cos stratified re-calibration.** Belongs under #793 / #806.
- **T_D2 minimum-count floor re-spec.** Belongs in next plan re-using D2.
- **Per-baseline-run sanity gate.** #816-class methodology fix.
- **Coupling with Path B (#817).** Low risk on forward cells; RT-1 triggers replan if forward-cell flip occurs.

## 13. Out of scope

- **Any probe wiring implementation.** Follow-up issues per probe.
- **Re-litigation of the H2 D1 verdict** (RT-3).
- **Phase 4 scope commit from this round** — follows decisive probe outcome.
- **New bucket cuts**, **Prometheus export**, **sub-µs resolution** — #812 deferrals.

## 14. Evidence layout

```
docs/pr/819-step2-discriminator-design/
    plan.md                      # this document
    codex-plan-review.md         # Codex plan-review rounds
    design.md                    # the deliverable (after PLAN-READY YES)
    codex-design-review.md       # Codex design-doc-review rounds
    # NO evidence/ directory — this issue produces a doc only.
```

*End of Architect Round 2. Awaiting Codex hostile plan review.*
