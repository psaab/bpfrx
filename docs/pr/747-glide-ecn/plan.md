---
status: DRAFT v1 — pending adversarial plan review
issue: https://github.com/psaab/xpf/issues/747
phase: Glide-style per-flow rate signal for ECN marking on heterogeneous workloads
---

## 1. Issue framing

`apply_cos_admission_ecn_policy` at
`userspace-dp/src/afxdp/cos/admission.rs:271` currently makes the
ECN CE-mark decision on a **byte-depth** signal:

```rust
let flow_above = queue.flow_bucket_bytes[flow_bucket]
    > share_cap * COS_ECN_MARK_THRESHOLD_NUM / COS_ECN_MARK_THRESHOLD_DEN;
```

On homogeneous elephant traffic (the current 16-flow iperf3 lab
fixture) every flow saturates, so depth correctly identifies the
heaviest offenders. On **heterogeneous workloads** — bulk + mice
sharing one queue — short-lived mice can briefly cross 50 % of
their `share_cap` for one or two packets and get CE-marked. They
back off unnecessarily, paying the same ECN cost as elephants
despite contributing a tiny fraction of the queueing pressure.

#747 proposes a Glide-inspired absolute-rate signal: estimate
per-flow bytes-per-second via EWMA at the bucket and require
the flow to be over a target rate AND over the depth threshold
before CE-marking.

## 2. Honest scope/value framing

This is a **gain on heterogeneous workloads we don't currently
exercise**. The issue explicitly says "this PR cannot land
against the current 16-flow iperf3 fixture because that workload
has no mice". The fixture must be built first or in parallel.

Concrete value: mice in a shared CoS queue with elephants stop
seeing false-positive backoffs. Elephants are unchanged. With
no real heterogeneous workload in the field today (operators
class-segregate mice via `forwarding-class` typically), the
practical user value is real but bounded.

Memory cost: 2 × 1024 × 8 bytes = **16 KB per queue** (one
EWMA-bytes-per-sec array + one last-arrival-ns array of
`COS_FLOW_FAIR_BUCKETS=1024` slots). At ~6 queues × 4 interfaces
× 6 workers, ~2.3 MB total — acceptable.

Hot-path cost: one extra DIV (instantaneous rate computation)
per admitted packet on flow-fair owner-local-exact queues.
~10-30 ns on modern x86 (DIV latency is the gating factor).
The packet-rate budget already absorbs the `cos_queue_flow_share_limit`
clamp (5 ns) — the EWMA adds another ~10 ns. Total admission
cost stays under the per-packet budget that smoke matrix
P=12 -R 22.9 Gbps gates against.

If reviewers conclude (a) the heterogeneous-workload value is
too small to justify the per-packet ALU cost, or (b) the EWMA
gives a noisy signal that breaks more than it fixes, PLAN-KILL is
an acceptable verdict.

## 3. What's already shipped / partially batched

- `apply_cos_admission_ecn_policy` at `admission.rs:271` is the
  single per-packet ECN mark decision site for flow-fair queues.
  Two existing arms: `flow_above` (per-flow depth) for
  `flow_fair && !shared_exact`, `aggregate_above` for the rest.
- `flow_bucket_bytes: [u64; COS_FLOW_FAIR_BUCKETS]` already lives
  on `CoSQueueRuntime` (`types/cos.rs:455`). Updated on each
  bucket enqueue/dequeue. The new arrays mirror this shape.
- `admission_ecn_marked` counter exists; new signal piggybacks
  on the same counter — operators see one ECN-mark line in
  `show class-of-service interface`, not a new column.
- The shared_exact path uses MQFQ virtual-finish-time ordering
  for fairness (#785 Phase 3) and intentionally uses
  `aggregate_above`-only at the ECN site (per the comment at
  `admission.rs:327-333`). #747's rate signal applies ONLY to
  the `flow_fair && !shared_exact` branch — the owner-local-exact
  workload class — leaving shared_exact untouched.

## 4. Concrete design

### 4.1 New runtime state

Add two arrays to `CoSQueueRuntime` in
`userspace-dp/src/afxdp/types/cos.rs`:

```rust
/// #747 Glide signal: EWMA of per-flow-bucket arrival rate in
/// bytes/sec. Updated on each admission alongside
/// `flow_bucket_bytes`. Used by
/// `apply_cos_admission_ecn_policy` to AND-guard the existing
/// depth signal with an absolute-rate signal so mice in
/// heterogeneous workloads stop seeing false-positive CE marks.
///
/// Meaningful only on `flow_fair && !shared_exact` queues
/// (owner-local-exact path). On other queues it is updated
/// but not read.
pub(in crate::afxdp) flow_bucket_rate_bytes_ewma:
    [u64; COS_FLOW_FAIR_BUCKETS],

/// #747 Glide signal: monotonic-clock timestamp of the last
/// packet seen in this bucket (ns since epoch / boot — the
/// existing `now_ns` clock used elsewhere). Drives the dt for
/// the EWMA above.
///
/// Initialised to 0 on queue construction. The first packet
/// sees `dt = now - 0 = now`, which produces an inst_rate
/// near zero. The first ~3 EWMA updates are noisy but the
/// 7/8+1/8 weighting damps them to within 0.1 % of the true
/// rate within ~24 packets.
pub(in crate::afxdp) flow_bucket_last_arrival_ns:
    [u64; COS_FLOW_FAIR_BUCKETS],
```

Memory: 2 × 1024 × 8 = 16 KB per queue.

### 4.2 EWMA update on admission

At the existing `flow_bucket_bytes[bucket] += item_len` site
(in the queue_ops push path — `userspace-dp/src/afxdp/cos/queue_ops/push.rs`
or the equivalent `cos_flow_bucket_bytes_increment` site):

```rust
// #747 Glide: EWMA inst-rate update. Hot path; single DIV.
let dt = now_ns.saturating_sub(queue.flow_bucket_last_arrival_ns[bucket]);
if dt > 0 {
    let inst_rate = item_len.saturating_mul(1_000_000_000) / dt;
    let ewma = queue.flow_bucket_rate_bytes_ewma[bucket];
    // 7/8 old + 1/8 new — TCP-style EWMA. Branchless.
    queue.flow_bucket_rate_bytes_ewma[bucket] =
        (ewma.saturating_mul(7) / 8).saturating_add(inst_rate / 8);
}
queue.flow_bucket_last_arrival_ns[bucket] = now_ns;
```

Compile-time assertions to prevent the weighting from drifting:

```rust
const COS_FLOW_RATE_EWMA_OLD_NUM: u64 = 7;
const COS_FLOW_RATE_EWMA_NEW_NUM: u64 = 1;
const COS_FLOW_RATE_EWMA_DEN: u64 = 8;
const _: () = assert!(
    COS_FLOW_RATE_EWMA_OLD_NUM + COS_FLOW_RATE_EWMA_NEW_NUM
        == COS_FLOW_RATE_EWMA_DEN,
    "EWMA weights must sum to denominator"
);
```

### 4.3 Mark-decision change in `apply_cos_admission_ecn_policy`

Replace the `flow_above` signal in the
`flow_fair && !shared_exact` branch with a conjunction of
rate-above AND depth-above:

```rust
// New: target rate = 2× fair-share rate. Active flow count
// approximates "how thin is the bucket", same denominator the
// existing per-flow share-cap math uses.
let active = cos_queue_prospective_active_flows(queue, flow_bucket).max(1);
let target_bytes_per_sec = queue.transmit_rate_bytes
    .saturating_mul(2) / active;

let rate_above = queue.flow_bucket_rate_bytes_ewma[flow_bucket]
    > target_bytes_per_sec;
let depth_above = queue.flow_bucket_bytes[flow_bucket]
    > flow_ecn_threshold;

let should_mark = if queue.flow_fair && !queue.shared_exact {
    rate_above && depth_above   // #747 — both arms
} else {
    aggregate_above             // unchanged
};
```

Why `2× fair-share`: a flow at fair share that's queueing is
correctly contributing to congestion AT or below baseline.
The 2× cap means mark only flows that are sending faster
than twice their fair share — i.e. the offenders. Same idea
as Glide's `delivered_ce * pacing_rate / delivered > 50 MB/s`
default.

The aggregate-arm path (shared_exact, best-effort) is
**unchanged**. Per `admission.rs:327-333`'s comment, those
queues need the aggregate signal for different reasons
(MQFQ already enforces fairness, so per-flow rate would
double-signal); keeping the aggregate-only behavior preserves
that contract.

### 4.4 Idle-flow staleness handling

When a flow is idle for a long period and resumes, the EWMA's
`last_arrival_ns` is stale. The first packet of the burst
sees a huge `dt`, so inst_rate is tiny — that under-counts
real burst rate. Subsequent packets in the burst see small
dts and large inst_rates that pull the EWMA up correctly
within ~3-8 packets.

This is acceptable for the heterogeneous-mice scenario:
short-lived mice never accumulate enough stale-then-burst
samples to trip the rate-above AND depth-above conjunction.
The depth signal alone won't trip on a brief burst either
(the AND guard means we need BOTH).

We do NOT add an explicit time-decay or reset path. Adding
one would either (a) require a periodic sweeper (separate
hot-path cost) or (b) gate every EWMA read behind a
`dt-since-last-arrival` check (extra branch + load per packet).
The first-packet-undercount is preferable to either.

### 4.5 Code locations to modify

- **`userspace-dp/src/afxdp/types/cos.rs:CoSQueueRuntime`**:
  add the 2 new arrays (~10 LOC + doc comments).
- **`userspace-dp/src/afxdp/cos/builders.rs:build_cos_runtime`**:
  zero-initialise the new arrays.
- **`userspace-dp/src/afxdp/cos/queue_ops/push.rs`** (or wherever
  `flow_bucket_bytes` is incremented on enqueue): EWMA update
  block (~10 LOC).
- **`userspace-dp/src/afxdp/cos/admission.rs`**:
  - Add 3 EWMA constants + compile-time assertion (~6 LOC).
  - Modify `apply_cos_admission_ecn_policy` to compute
    `rate_above` and AND with `flow_above` for the
    `flow_fair && !shared_exact` branch (~6 LOC change).

Total: ~35 LOC excluding tests.

### 4.6 No-op for shared_exact and best-effort

`shared_exact` queues use `aggregate_above` only (per the
`admission.rs:327-333` comment). The new `flow_bucket_rate_bytes_ewma`
field is updated for them too (no branching cost on the update
side), but never read in their mark decision.

`!flow_fair` (legacy best-effort, rate-limited) queues never
enter the per-flow path at all — `cos_queue_flow_share_limit`
returns `buffer_limit` unchanged when `flow_fair` is false, and
the EWMA arrays are populated-but-unused.

This is intentional: keep the change scoped to the workload
where the issue's problem manifests.

## 5. Public API preservation

- `CoSQueueRuntime` gains 2 fixed-size arrays. No struct-size
  guarantees; Rust doesn't pin layout.
- No public-API method signatures change.
- Snapshot/protocol unchanged — the EWMA state is per-runtime,
  not synced to peers.
- Existing CLI counters unchanged. `admission_ecn_marked` still
  represents "marks taken"; the meaning shifts subtly because
  the threshold is stricter, but the counter name and rendering
  stay the same.

## 6. Hidden invariants the change must preserve

- **No hot-path allocation**: the 2 new arrays are inline
  members of `CoSQueueRuntime`, sized at compile time. No new
  allocations on enqueue / dequeue / admission.
- **#728 / #731 ECN ordering**: marker fires strictly before
  pacing-equivalents, not after. The new conjunction does not
  reorder; only narrows.
- **Admission gates count unchanged** (#708 wontfix / #742):
  this is the same single mark decision; signal change only.
- **Branchless rate math**: `saturating_mul` + integer division.
  `inst_rate / 8` and `ewma * 7 / 8` are constant-divisor — LLVM
  generates a multiply-by-magic-number, not a real DIV.
- **The `item_len.saturating_mul(1_000_000_000) / dt` is the
  one real DIV per packet.** `dt` ranges from ~10 ns (back-to-back
  burst) to ~10⁹ ns (1 second idle). Both fit in u64 with
  saturation; no overflow path.
- **Compile-time assertion** that EWMA weighting (7/8 + 1/8)
  matches denominator — catches refactor drift.
- **shared_exact path semantics preserved**: aggregate_above-only
  branch is byte-identical; #784 / #785 Phase 3 fairness contract
  intact.

## 7. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | **MED** | The mark decision changes for `flow_fair && !shared_exact` (owner-local-exact). Today this is the iperf-a 1 Gbps queue. Fewer marks → potentially less congestion control on elephants there. The AND-guard means the fix only fires when BOTH signals say mark; never marks more than today, only fewer. |
| Lifetime / borrow-checker | **LOW** | Plain inline array fields, no lifetimes. |
| Performance regression | **LOW** | One extra DIV per admitted packet. ~10 ns on x86. The smoke matrix P=12 -R 22.9 Gbps gate has ~1 µs per-packet budget; +10 ns is 1 % of that. Not visible. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **LOW** | Same admission gate, different signal. Not a refactor. The new fields parallel `flow_bucket_bytes` exactly — same indexing, same lifecycle, no new abstraction. |
| Heterogeneous-fixture risk | **HIGH** | The acceptance criterion ("mice CE-mark drops by ≥ 50 %, elephant CE-mark within ±10 %") requires a workload the lab doesn't have today. Building the fixture is its own scope. |

## 8. Test plan

- `make generate` clean.
- `cargo build --release` clean.
- `cargo test --release` 974+ pass (post-#915 baseline), plus
  new tests:
  - `userspace-dp/src/afxdp/cos/admission_tests.rs`:
    `apply_cos_admission_ecn_policy_marks_when_rate_and_depth_both_above`
    — set both `flow_bucket_bytes[N] > flow_ecn_threshold` AND
    `flow_bucket_rate_bytes_ewma[N] > target_bytes_per_sec`,
    verify mark fires.
  - `apply_cos_admission_ecn_policy_skips_when_only_depth_above`
    — set `flow_bucket_bytes[N] > flow_ecn_threshold` but
    `flow_bucket_rate_bytes_ewma[N] == 0`, verify NO mark
    (the AND-guard caught the false-positive).
  - `apply_cos_admission_ecn_policy_skips_when_only_rate_above`
    — set rate above but depth below, verify no mark
    (defense-in-depth — a flow with small queueing but high
    instantaneous rate isn't congesting yet).
  - `flow_bucket_ewma_update_initial_packet_pulls_rate_to_inst`
    — first packet on an idle bucket, verify EWMA settles
    toward the inst_rate over a few packets.
  - `flow_bucket_ewma_compile_time_weights_sum_to_denominator`
    — compile-time `const _ : () = assert!(...)` — no runtime
    test needed.
  - Regression: `apply_cos_admission_ecn_policy_shared_exact_path_unchanged`
    — set `queue.shared_exact = true`, verify mark decision
    uses `aggregate_above` only and ignores the new EWMA
    fields.
- 5x flake check on the most-affected named test.
- Go test ./... clean.
- Smoke matrix per `triple-review` SKILL.md Step 6: full
  Pass A + Pass B 30 measurements. Expected: zero throughput
  delta on homogeneous elephant workload (all flows trip both
  rate AND depth thresholds, so behavior matches today's
  depth-only).

### 8.1 Heterogeneous workload smoke (the acceptance gate)

Build `test/incus/test-cos-mixed-workload.sh`:

- 4 long-lived `iperf3 -c 172.16.80.200 -P 4 -t 60 -p 5201`
  elephants (iperf-a 1 Gbps shaped class).
- 100 short-lived TCP echo round-trips per second to
  `172.16.80.200:5201` over the same iperf-a shape (mice
  driver: `bash` loop with `exec 3<>/dev/tcp/...`, ~1 KB
  request per iteration, count + close per iteration).
- 60 s run, capture pre/post `show class-of-service interface
  reth0.80` for `admission_ecn_marked` and queue-bucket bytes
  per worker; bucket-attribute mice CE marks vs elephant CE
  marks via `tcpdump --dscp` on the source side.

Acceptance:
- Mice CE-mark rate drops **≥ 50 %** versus the depth-only
  baseline (re-run with `flow_bucket_rate_bytes_ewma` artificially
  forced to `u64::MAX` so rate_above is always true).
- Elephant CE-mark rate changes by **≤ 10 %**.
- Neither regresses the post-#728 16-flow homogeneous-elephant
  results (CoV ≤ 18.5 % per #905 baseline).

If the heterogeneous fixture cannot be built within scope,
PLAN-KILL is acceptable — the fix is unobservable on
homogeneous traffic.

## 9. Out of scope (explicitly)

- Rate-aware CE-mark threshold for `shared_exact` queues.
  Different fairness model (MQFQ); needs separate analysis.
- Per-flow rate signal exposed via CLI/snapshot. Operators
  don't ask for that today; can be added if useful.
- Time-decay/reset on the EWMA after a long idle. First-packet
  undercount is acceptable (§4.4 rationale); decay would add
  hot-path branching cost.
- DPDK pipeline parity — the DPDK CoS path is not yet ECN-marking
  enabled; #747 fix lives in the userspace-dp Rust path only.
- Glide-style accurate ECN feedback (the L4 / sender-side
  signal #747 references). This plan implements only the
  firewall-side rate estimate that mirrors Glide's *target*
  semantics; the sender-side handshake is unchanged.

## 10. Open questions for adversarial review

1. **Operator value vs ALU cost**: is the heterogeneous-mice
   improvement (which requires a fixture we don't have today)
   worth one extra DIV per admitted packet? PLAN-KILL is
   acceptable if reviewers consider this premature given the
   absence of operator pressure for the heterogeneous-workload
   case.
2. **Default target rate**: 2 × fair-share. Glide's published
   default is `pacing_rate > 50 MB/s`. xpf's analog uses
   `transmit_rate_bytes / active_flow_buckets`. Is 2× the right
   multiplier, or should it be 1.5× / 3×? Need parameter tuning
   data we don't have.
3. **AND-guard vs OR-guard**: plan picks AND (strict — both
   signals must agree to mark). Reviewers may prefer OR
   (lenient — either signal triggers mark). The issue's
   snippet uses AND ("mark only if the flow is BOTH above
   rate target AND above depth threshold"). AND is the
   false-positive-reducing direction; OR would mark more
   aggressively, defeating the fix's purpose. Settled but
   open to pushback.
4. **First-packet undercount**: §4.4 accepts the EWMA having
   bad signal for the first 3-8 packets of a new flow.
   Reviewers may require a different bootstrap (e.g. seed
   `last_arrival_ns` to `now_ns` on first packet so dt=0 →
   skip update). The plan's choice is deliberate (cheaper) but
   discussable.
5. **Heterogeneous workload fixture scope**: building
   `test-cos-mixed-workload.sh` is a non-trivial harness
   investment (mice driver, bucket attribution via tcpdump,
   per-class CE-mark counter rendering). Scope-creep risk.
   Could be a follow-up issue if the code change lands as
   "no-op on homogeneous" by definition.
6. **EWMA staleness interaction with #784 fairness**: the post-#784
   3 winner / 9 loser regression on iperf3 -P 12 was caused by
   ECN marks correlating with cwnd state. If the new rate
   signal correlates differently, could it re-introduce a
   bimodal split under heavy contention? Codex/Gemini should
   walk #784 to confirm.
7. **Test plan §8.1 acceptance threshold reproducibility**:
   "≥ 50 % mice CE drop" is the issue's stated target.
   TCP CE marking has high run-to-run variance. Is one 60 s
   run sufficient, or do we need N reps with statistical
   bounds?
8. **Memory footprint**: 16 KB per queue × 6 queues × 4
   interfaces × 6 workers ≈ 2.3 MB. At what queue / interface
   / worker count does this become concerning? With 100
   workers (hyperscale future), 16 MB. Reviewers may push for
   `Box<[u64; 1024]>` to put the arrays on the heap or for
   smaller bucket count. Plan keeps inline for hot-path
   locality.
