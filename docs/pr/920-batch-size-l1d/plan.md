# Plan: #920 — RX/TX_BATCH_SIZE 256 → 64

Issue: #920
Umbrella: #911 (validates against #929 same-class harness)

## 1. Problem

`RX_BATCH_SIZE` and `TX_BATCH_SIZE` are hardcoded at 256 in
`userspace-dp/src/afxdp.rs:156-159`. A 256-packet batch processes
roughly:

- 256 × 96 bytes packet metadata (`UserspaceDpMeta`) = 24 KB
- 256 × 64-128 bytes packet headers fetched ≈ 16-32 KB
- Plus the bookkeeping inside the RX loop: VecDeque entries, scratch
  vectors, validation cache reads, flow cache lookups.

Total working set per batch easily exceeds 32 KB (typical L1d on
modern Intel/AMD x86_64). When the loop reaches the end of a batch
and starts the next one, the first packets of the previous batch
have already been evicted to L2 — so any per-batch state that the
NEXT batch revisits incurs L2 fetches.

For mouse-latency p99: a mouse packet that arrives late in a batch
waits for all 255 elephant packets ahead of it to be processed
before it gets a turn. At 1500-byte MTU and 25 Gb/s line rate
each packet takes ~480 ns, so 255 packets is ~122 µs of
head-of-line latency for a mouse that arrived second-to-last
in a 256-batch.

## 2. Goal

Quarter both batch sizes from 256 to 64. This:

- Reduces the per-batch working set roughly 4× — from ~32-48 KB
  to ~10-14 KB (64 × 96 B `UserspaceDpMeta` = 6 KB, plus 64 × 64-
  128 B headers = 4-8 KB, plus snapshot stack and scratch
  vectors). The 256-batch case overflows L1d on most x86_64;
  the 64-batch case fits comfortably.
- Reduces worst-case mouse HOL latency by 4× — at 25 Gb/s and
  1500-byte MTU (~480 ns/packet), 255 packets ahead = 122 µs;
  63 packets ahead = 30 µs.
- Costs a small constant in batch-loop overhead (4× more
  iterations) — but each iteration touches an already-warm L1d so
  the per-packet cost goes DOWN.

DPDK's empirical sweet-spot for similar pipelines is 32-64 (per
the issue body). Pick 64 to retain headroom over 32 in case of
sub-batch fragmentation.

## 3. Approach

### 3.1 Constants

```rust
// userspace-dp/src/afxdp.rs
const RX_BATCH_SIZE: u32 = 64;   // was 256
const TX_BATCH_SIZE: usize = 64; // was 256
```

### 3.2 Snapshot-stack capacity ripple

`pop_snapshot_stack` is preallocated to `TX_BATCH_SIZE` capacity
(per #913 plan §3.2 and verified at `tx.rs:cos_queue_pop_front_inner`
debug_assert). Quartering 256→64 reduces the preallocated stack
from ~6 KB to ~1.5 KB at 24 bytes per `CoSQueuePopSnapshot`
(per `types.rs` size note) — strictly improvement for L1d
residency.

The debug_assert that the stack stays within `TX_BATCH_SIZE` still
holds; nothing in the existing code paths inserts more than one
snapshot per pop, so a 64-entry stack is comfortably above the
typical drain depth (which is ≤ TX_BATCH_SIZE per call site clear).

### 3.3 Scratch-vector capacities

`scratch_recycle`, `scratch_forwards`, `scratch_prepared_tx` are
allocated `with_capacity(RX_BATCH_SIZE)` / `with_capacity(TX_BATCH_SIZE)`.
The reduction to 64 just means the initial alloc is smaller; the
Vecs grow if needed. No semantic change.

### 3.4 Batch-loop sites

Primary call sites that act on BATCH_SIZE as a control parameter
(not a capacity hint):

1. `bind.rs:391` — `let budget: c_int = RX_BATCH_SIZE as c_int;`
   passed via `setsockopt(SO_BUSY_POLL_BUDGET)` (NOT
   `xsk_socket__poll`; an earlier R1 misattribution). Sets the
   kernel's NAPI busy-poll budget per `recvmsg`/poll cycle for
   this AF_XDP socket. Reducing it caps the kernel-side per-poll
   work at 64 instead of 256, complementing the userspace caps.

2. `afxdp.rs:449` — `available = raw_avail.min(RX_BATCH_SIZE)`.
   Caps the per-iteration RX descriptor processing.

3. `frame_tx.rs:283`, `:347`, `:793-794` — flush trigger sites
   (Codex R1 was wrong that frame_tx.rs doesn't exist; R2
   corrected). `pending_tx_*.len() >= TX_BATCH_SIZE` triggers a
   TX flush. Lowering 256→64 means flushes fire 4× as often.

4. `tx.rs:563` — TX retry-buffer flush trigger
   (`retry.len() >= TX_BATCH_SIZE` in the per-tick fallback
   transmit path; Gemini R2 caught this site missing from R1's
   enumeration). Same flush semantics as the frame_tx.rs sites.

5. `tx.rs:6201`, `:6370` — `.min(TX_BATCH_SIZE)` per-drain caps
   in the queue drain path. Caps how many items a single drain
   call processes before yielding; not a flush trigger but
   directly affects per-iteration L1d residency.

6. `tx.rs:2524, 2623, 2711, 2815, 3137, 3178` —
   `while scratch_*_tx.len() < TX_BATCH_SIZE` per-drain refill
   caps (Codex R3: these are control caps, not capacity hints —
   they bound how many items a single drain pass produces, which
   directly throttles the per-iteration working set). Lowering
   to 64 means the refill loop runs more often but each pass
   processes less. The behavioral effect is identical to sites
   1-5: more frequent, smaller iterations.

Capacity-hint sites (NOT control parameters; reducing them only
shrinks initial Vec allocations and is harmless or beneficial):

- `worker.rs:349-355, 357, 370` — `Vec::with_capacity(RX/TX_BATCH_SIZE)`
  for scratch vectors.
- `worker.rs:555` — `Vec::with_capacity((RX_BATCH_SIZE as usize)
  .saturating_mul(2))` for the shared-recycles buffer (Codex R3:
  this site was missing from R2's enumeration).
- `tx.rs:324` — `.max(TX_BATCH_SIZE.saturating_mul(2))` capacity
  hint.
- `tx.rs:5592, 13852, 13896, 13951`, `worker.rs:2442, 2582,
  2788, ...` — `pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE)`.
  At 24 bytes per `CoSQueuePopSnapshot` element, reduction lowers
  the initial element-storage allocation from ~6 KB (256 × 24) to
  ~1.5 KB (64 × 24) per stack, plus per-Vec header/allocator
  overhead.

The cumulative effect: more frequent but smaller iterations through
the entire RX→XDP→TX pipeline. The hypothesis: the L1d-resident
per-iteration state amortizes the higher iteration count by a
larger margin.

### 3.5 No new public/private API

The constants are internal to the `afxdp` module. Nothing escapes.

## 4. What this is NOT

- Not a tunable / config knob. Plan R0: keep it a `const` to
  prevent runtime branching in the hot path. Future tunability
  (per the issue's "make configurable") tracked as separate
  follow-up if measurements show benefit at different sizes for
  different workloads.
- Not a change to scheduler / fairness math. MQFQ ordering is
  unchanged; smaller batches just mean ordering decisions fire
  more frequently.
- Not a change to AF_XDP ring sizes (`UMEM_FRAME_COUNT`,
  `XSK_RING_PROD/CONS_DEFAULT_NUM_DESCS`). Those are independent
  resources sized for full-rate buffering.

## 5. Files touched

- `userspace-dp/src/afxdp.rs`: change `RX_BATCH_SIZE` and
  `TX_BATCH_SIZE` consts; add `const_assert!` pins; expand the
  comment block with sizing math + per-poll budget rationale.
- `userspace-dp/src/afxdp/tx.rs`: update `guarantee_phase_*_visit_quantum`
  test to assert the new TX_BATCH_SIZE cap; add new
  `guarantee_phase_quantum_scales_with_rate` test guarding the
  rate-quantum invariant; refresh stale 256-batch comments in
  the drain-cost analysis.
- `userspace-dp/src/afxdp/types.rs`: refresh stale 256 × 24
  comment on the `pop_snapshot_stack` worst-case footprint.
- `userspace-dp/src/main.rs`: cherry-picked unrelated #878
  `BindingCountersSnapshot` test fix (pre-existing build break
  on origin/master) so cargo test can run.
- Cluster-side measurement results will be collected post-merge
  via the #929 same-class harness; not a separate file in this
  PR.

## 6. Test strategy

### 6.1 Build

`cargo build --release` clean. No code logic changes; only
constants. Unit tests unaffected.

### 6.2 Cluster validation

Required: #929 same-class harness deployed.

Run same-class N=128 M=10 matrix at BATCH=256 (rollback) vs
BATCH=64. Hypothesis:

- Mouse p99 drops by 2-4× (proportional to batch reduction).
- Throughput unchanged or slightly improved (cache locality).

If throughput regresses by >5%, the gain doesn't justify; revisit
batch=128 as middle ground.

### 6.3 Throughput sanity

`iperf3 -P 128 -p 5203 -t 30` on iperf-c queue: expect ≥15 Gb/s
unchanged or improved.

### 6.4 Per-iteration cost regression check

`perf stat -e L1-dcache-load-misses,L1-dcache-loads` during a
30-second iperf3 -P 128: expect L1d miss rate to DROP with
BATCH=64 vs BATCH=256.

Optional but informative.

## 7. Risks

- **TX ring under-utilization at low pps.** With BATCH=64, a flush
  fires every 64 packets; if the link is mostly idle (10s of
  Kpps), flushes are very small and add syscall overhead. The
  existing flush logic already triggers on ANY pending tx after
  RX-side processing completes, so empty RX cycles still drain
  pending TX. No regression expected.
- **AF_XDP TX kick cost** (Codex R1, replacing the optimistic
  syscall-cost claim). At 25 Gb/s with 1500-byte packets =
  2.08 Mpps, each batch of 256 means ~8.1k submits/s; each
  batch of 64 means ~32.6k submits/s — so ~24.5k extra kicks/s.
  At 1/3/5 µs per kick, that's ~2.4/7.3/12.2% of one core, or
  ~12/35/59 ns extra per packet. For a 10k-packet burst, the
  extra batch kicks are `ceil(10000/64)-ceil(10000/256) = 117`
  not "150"; at 3 µs/kick that's ~351 µs CPU.
  Trade-off acceptable if mouse p99 improves materially.
  Required telemetry to verify: add to acceptance gate readings
  of `tx_kick_latency_count` / `tx_kick_latency_sum_ns`,
  `tx_kick_retry_count`, `dbg_tx_ring_full`, and
  `tx_ring_full_submit_stalls`.

- **MAX_RX_BATCHES_PER_POLL interaction**: the per-`poll_binding`
  cap is `MAX_RX_BATCHES_PER_POLL × RX_BATCH_SIZE`. With
  RX_BATCH_SIZE=256 and the existing `MAX_RX_BATCHES_PER_POLL=4`,
  per-poll cap is 1024 packets. With RX_BATCH_SIZE=64, per-poll
  cap drops to 256 packets. Verify this is intentional or
  raise `MAX_RX_BATCHES_PER_POLL` to 16 to preserve the 1024
  per-poll budget.
- **Scratch-stack initial allocation churn.** Lowering capacity
  from 256 to 64 means a Vec that pushes >64 items will realloc
  once (to 128) then again (to 256). The MQFQ scratch path has a
  `debug_assert` against this in #913. Verify the assert with the
  new size — if it fires, raise the cap.

## 8. Acceptance

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Plan reviewed by Gemini (HPC + CPU cache-design); MERGE YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Gemini adversarial code review: MERGE YES.
- [ ] Cluster smoke + same-class N=128 M=10 measurement.
- [ ] Throughput sanity ≥15 Gb/s.
- [ ] PR opened, Copilot review addressed.
- [ ] Merged.
