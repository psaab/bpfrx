# Claude SMR plan-review r1 — #1607 cold-path microbench

## Verdict: PLAN-NEEDS-MAJOR

The instrumentation half of the plan (histogram counter + wire +
Prometheus surface) is fine — pure code-motion with the established
`bucket_index_for_ns` pattern, low risk. The **harness design half is
structurally wrong as currently specified**, for a stack of reasons
that compound. I am NOT calling PLAN-KILL because the cold-path
histogram itself is independently useful: even with a flawed harness,
having the counter live in production means anyone running iperf3 in
any future scenario gets cold-path latency on the dashboard. But the
harness has to be re-scoped before we ship the numbers in the Scale
Target section of the JIT design doc, because the wrong numbers there
do worse damage than no numbers (they pin a false ceiling that the
JIT design then optimizes against).

## Findings tied to file:line

### F1 (HARD-FATAL — the cold-path-sample-rate compound problem)

Three issues stack on top of each other:

1. **TCP doesn't exercise cold path per packet.** `iperf3 -P 12 -t 30
   -b 0 -l 64` opens 12 long-lived TCP connections. The first SYN per
   stream hits the cold path; every subsequent packet hits the flow
   cache (`flow_cache_hit::stage_flow_cache_hit` in
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — looked it up at
   the `use flow_cache_hit::{FlowCacheOutcome, stage_flow_cache_hit};`
   import in mod.rs:20). At steady state, 12 streams = **12
   cold-path samples per 30 s run**. The plan's Q3 acknowledges this
   but defers the answer.

2. **Even the optional `--pktgen` escape valve is under-specified.**
   The plan says "iperf3-style UDP with -u" but `iperf3 -u` reuses the
   same 5-tuple per stream — the flow cache still hits after the
   first packet. To force 100 % cold path the generator must
   randomize *the source port per packet*, which iperf3 does not do.
   The plan defers "a small Go/Rust UDP flooder" to round-2, which
   means the harness as-shipped will have a near-zero cold-path
   sample count.

3. **Aggregate samples / 30 s is the wrong unit.** Even if we hit
   100 % cold path with a custom flooder at 5 Mpps/worker, the §4.5
   doc text reports "per-worker Mpps p50" derived from the histogram
   rate. But the histogram only counts cold-path samples; the
   per-worker total Mpps comes from `rx_packets` (warm + cold). The
   table shape conflates two different rate-bases.

→ The harness produces statistically meaningless numbers on its
default mode, and the doc table the harness populates conflates cold
and total throughput. Both must be fixed before this PR is
shippable. **PLAN-NEEDS-MAJOR; consider PLAN-KILL** on the §4.5 table
unless the harness reports cold-path-per-packet-ns + cold-path-only
sample rate as separate quantities from total Mpps.

### F2 (HARD-FATAL — timer overhead vs measurement budget)

Per-call timer overhead: `clock_gettime(CLOCK_MONOTONIC)` via vDSO on
x86 is ~20–25 ns (verified by reading
`userspace-dp/src/afxdp/neighbor.rs:3` — single `clock_gettime` call,
no fallback). Two calls per sample site = **40–50 ns** wrapper
overhead per cold-path eval, plus `bucket_index_for_ns` (one
`leading_zeros` + one branchless arithmetic) at ~2 ns, plus one
non-atomic u64 array store at ~1 ns.

The issue's derivation cites a **270 ns/packet budget** at 64 B
linerate. The wrapper alone is **15–20 % of the budget being
measured**. This is measurement bias, not floor noise. Future
operators looking at `policy_decision_cold_path_ns_sum_total /
samples_total` and getting, say, 320 ns will not know how much of
that is policy + how much is the timer.

The plan's §7 Risk-Performance line says "<1 % overhead because
cold path is 100s of ns minimum". This is wrong:

- At rule-count 10 (linear scan over 10 rules with ~10 inline
  predicates each), cold-path is 50-80 ns. The timer dominates.
- At rule-count 1000 with the new prefix-set Trie (#923) and
  zone-pair indexing, cold-path may still be ~200-400 ns. Timer is
  20 %.
- Only at rule-count 100K+ does cold-path dwarf the timer.

The plan does not specify a clock-gettime empirical baseline subtract.
The plan's Q5 acknowledges this risk but does not commit to a
mitigation.

**Required fix:** the harness MUST measure and report a
`clock_gettime` baseline (e.g., 1 M back-to-back calls in a tight
loop, report median wrapper cost) and the Scale Target table MUST
subtract it before reporting per-packet ns. Without this, the
numbers we ship in the JIT design doc are biased by ~50 ns toward
"linear scan is slower than it really is", which defeats the entire
purpose of the measurement (it pins the JIT budget too tight, making
the JIT case look stronger than it is).

### F3 (NEEDS-MAJOR — bucket-saturation hides the cliff this PR is built to find)

`DRAIN_HIST_BUCKETS = 16` saturates at 2^24 ns = **16.77 ms**.
Cold-path policy eval at 1M rules with linear scan and ~50-100 ns
per rule = **50-100 ms**. That lands in bucket 15 silently, and the
operator looking at "p99 < 16 ms" thinks 1M rules is fine when in
fact every cold-path packet takes 100 ms.

The plan's Q4 acknowledges this and asks whether to widen. The
answer (from a measurement-methodology standpoint) is **yes, widen**:
the entire point of this PR is to inform #1605 JIT planning, and the
JIT plan needs to see the actual tail latency at 100K / 1M rules to
size the budget. Saturating bucket 15 makes the headline reading
useless.

Cost of widening: 8 more `AtomicU64` per worker = 64 bytes per
worker. Already proposing 144 B; total goes to 208 B. Still 4 cache
lines per worker; trivial. Bucket layout extension: bucket 16
upper-bound = 2^25 ns ≈ 33.5 ms; bucket 23 upper-bound = 2^32 ns ≈
4.3 s. 24 buckets covers up to ~4 s which is well past anything we
could ever care about.

**Required fix:** introduce
`POLICY_COLD_PATH_HIST_BUCKETS = 24` as a project-local constant
with a `const _: () = assert!(POLICY_COLD_PATH_HIST_BUCKETS >=
DRAIN_HIST_BUCKETS);` so the wider layout cannot silently shrink
back. Bucket index math: extend `bucket_index_for_ns` with an
`exclusive_max_bucket` parameter or define a sibling
`policy_cold_path_bucket_for_ns(ns)` that clamps to 23 instead of
15. Plan must commit to ONE of these mechanisms.

### F4 (NEEDS-MINOR — CPU isolation discipline is absent)

Walked the cluster setup:
- `test/incus/cluster-setup.sh`: no taskset / cpuset / smp_affinity.
- `test/incus/loss-userspace-cluster.env`: no CPU pinning.
- `test/incus/xpfd.service:19`: comment confirms `CPUAffinity=2 3 4
  5` is **NOT shipped** ("the directive is NOT shipped" — verbatim).
- Workers self-pin via `pin_current_thread` (`neighbor.rs:520`) but
  to any CPU in the inherited mask, which on the loss cluster is
  effectively "all CPUs the VM was scheduled on".

The plan's Q2 ("CPU isolation discipline") needs a real answer:
either (a) the harness ships a CPUAffinity= unit override that pins
workers to a specific core set away from NIC IRQs, OR (b) the
harness records `/proc/interrupts` deltas and flags shared-CPU
collisions in the output, OR (c) the doc text in §4.5 explicitly
disclaims that the numbers are upper bounds that may move with IRQ
steal.

(b) is the cheapest credible answer. (a) is more rigorous but
invasive on the test fixture. (c) is the honest minimum.

### F5 (NEEDS-MINOR — flow-cache hit interaction with cold-path
sampling)

The plan asserts both `evaluate_policy*` call sites in
`poll_descriptor/mod.rs` are cold-path-by-construction. Confirmed:
- mod.rs:1375 — called only after the
  `decision.resolution.disposition == ForwardCandidate` branch,
  which is the session-miss / first-packet-of-flow path.
- mod.rs:2393 — called inside the SYN-ACK / NAT reverse setup, which
  is also session-miss path.

But the broader claim "flow cache hit bypasses policy eval entirely"
in §4 of the plan needs the F1 callout: under TCP, the flow cache hit
rate is ~100 % after the first SYN per stream. The sample count is
correct (cold-path-only); the rate is misleadingly low. This is the
same problem as F1 viewed from the publishing side.

### F6 (NEEDS-MINOR — false-sharing audit of WorkerRuntimeAtomics)

Current `WorkerRuntimeAtomics` is `#[repr(align(64))]` and per the
comment at `worker_runtime.rs:160` is 128 B after the AtomicBool
+ padding. Adding:

- `policy_cold_path_ns_hist: [AtomicU64; 16]` = 128 B (or 192 B at
  POLICY_COLD_PATH_HIST_BUCKETS=24 per F3)
- `policy_cold_path_samples: AtomicU64` = 8 B
- `policy_cold_path_sum_ns: AtomicU64` = 8 B

Total addition: ~144-208 B. Current struct + addition = 272-336 B,
which is 5-6 cache lines per worker. With `#[repr(align(64))]` the
struct rounds to whole cache lines (320 or 384 B). Adjacent workers
in `Vec<WorkerRuntimeAtomics>` still don't false-share because the
align(64) guarantees per-worker boundary. **OK** but the plan should
acknowledge the struct size growth.

### F7 (NEEDS-MINOR — file-zone overlap check vs #1606)

Walked:
- This plan touches: `userspace-dp/src/protocol/binding.rs` (add
  fields to `WorkerRuntimeStatus`), `worker_runtime.rs` (add fields
  to `WorkerRuntimeAtomics` + `WorkerRuntimeCounters`),
  `poll_descriptor/mod.rs` (two call-site timer wrappers),
  `coordinator/status.rs` (mirror new atomics into snapshot),
  `pkg/dataplane/userspace/protocol.go::WorkerRuntimeStatus`,
  `pkg/api/metrics_*.go` (new descriptor + emitter).
- #1606 per the parent prompt touches:
  `userspace-dp/src/protocol/security.rs::AddressBookSnapshot` /
  rule fields, `userspace-dp/src/policy/lpm.rs`,
  `userspace-dp/src/policy/rule.rs`.

`protocol/binding.rs` vs `protocol/security.rs` — distinct files,
distinct structs. `coordinator/status.rs` — the `policy` field on
the ProcessStatus struct may be shared, but each side adds fields
to **distinct sub-structs**. **Confirmed disjoint.** The only
collision point is `pkg/api/metrics_*.go` (both plans add new
metrics there) but that's a flat-file additive change, not a
structural change, so merge conflicts will be mechanical at worst.

### F8 (informational — public-API JSON wire client survey)

Walked: the `/metrics` Prometheus endpoint is consumed by Prometheus
itself; new fields are additive. The control-socket status endpoint
is consumed by `pkg/dataplane/userspace/`, which uses Go's
`encoding/json` with the default unknown-field-allowed behavior. No
external Go consumer rejects unknown fields. **OK**.

## Self-correction note

I went into this review thinking the histogram counter was the risky
part and the harness was a thin shell around iperf3. After working
through F1-F3 the inversion became obvious: the histogram is fine,
the harness as currently specified will produce numbers that mislead
operators and the JIT design doc. The plan's §2 "honest framing"
flags this risk but the §4 design doesn't follow through —
specifically, the §4.5 Scale Target table format does not separate
cold-path-per-call ns from total Mpps, and the warmup phase
described in §4.2 is too short (1 s) to wash out the very-rare-cold-
path TCP regime where 30 s of run yields 12 samples.

## Required changes for PLAN-READY

1. **F1**: harness MUST ship with a real UDP-with-random-source-port
   packet generator (Rust or Go ~50 LOC), not just an iperf3 wrapper.
   The default mode should be the UDP flooder; iperf3-style TCP is
   the "smoke" mode that confirms the counter increments at all.
2. **F2**: harness MUST measure and subtract a `clock_gettime`
   wrapper baseline before reporting per-packet ns. The harness
   output must show three numbers: `wrapper_ns_baseline`,
   `measured_ns_p50_raw`, `measured_ns_p50_corrected`.
3. **F3**: introduce `POLICY_COLD_PATH_HIST_BUCKETS = 24` so the
   tail at 1M rules is visible.
4. **F4**: pick one of (a)/(b)/(c) and bind the harness to it.
5. **Scale Target table** in `docs/userspace-jit-design.md`: drop
   "per-worker Mpps" from the same row as "per-packet ns"; report
   them as two separate tables, one for cold-path-only (sourced from
   the histogram) and one for total throughput (sourced from
   `rx_packets`).
6. Plan §11 version-log: add v2 entry capturing the above.

## Domain-specific checks the plan should pass (status)

| Check | Status |
|-------|--------|
| Hot-path allocation rule (per-packet) | PASS — no allocation, two clock reads + bucket index + non-atomic store on cold path |
| Lock ordering / ArcSwap semantics | N/A — no new locks; no ArcSwap touched |
| HA sync portability | PASS — no HA-touching code modified |
| Numerical / counter overflow | PASS — u64 cumulative, century-scale wrap |
| Verifier / kernel-API constraints | N/A — userspace-only |
| Wire-protocol both-sides | PASS pending implementation — `WorkerRuntimeStatus` mirror in Go is in scope |
| Modularity discipline (file <2000 LOC, fn <100 LOC) | PASS — new code is small |
| Cache-line / false-sharing | PASS — `#[repr(align(64))]` preserved per F6 |
| Smoke v4+v6 × push+rev × CoS-off+on | Pending Step 6 |
