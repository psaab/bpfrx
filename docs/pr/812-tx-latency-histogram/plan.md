# Issue #812 — Architect plan: per-queue TX-lane submit→completion latency histogram

> Phase of `docs/development-workflow.md`: **PLAN PHASE — Architect draft**.
> Status: awaiting Design Reviewer (Codex, hostile). No code written.
> Related: #798 (step1 execution), #806 (Z_cos recalibration follow-up).

## 1. Problem statement

Phase B Step 1 (`docs/pr/line-rate-investigation/step1-findings.md` §4)
returned `D / D-escalate (dominant)` on 10 / 12 cells:

- `k_D = 5` + `k_D-escalate = 5`, combined 83 % (`step1-findings.md:103-104`).
- Zero C firings (`ring_w = 0` on every cell — `step1-findings.md:97-100`).
- B-tentative on a single cell (`step1-findings.md:89-96`).
- A-isolated on a single cell, discounted by §4.6 (`step1-findings.md:77-85`).

Per the step1-plan §8 decision tree at
`docs/pr/line-rate-investigation/step1-plan.md:1100-1102`:

> "If verdict is **D (npbt)** on > 75 % of cells: we exhausted the
> current hypothesis set. Step 2 is the design doc for a new
> hypothesis tier — NOT more measurement."

The named prerequisite for any D-tier subdivision — at
`step1-plan.md:696-698` — is a "per-queue TX-lane-level latency
histogram (not currently exposed)." Current counters
(`BindingCountersSnapshot` at `userspace-dp/src/protocol.rs:1367-1400`,
plus `CoSQueueStatus` park counters at `userspace-dp/src/protocol.rs:
797-889`) expose ring-full, park-rate, and queue depth — NONE of them
discriminate among the §5 D-tier candidates
(`step1-findings.md:131-146`):

| Candidate | What it would reveal | Current counter gap |
|---|---|---|
| D1: XSK TX submit → NIC DMA latency | Queue time inside AF_XDP before DMA. | No submit-ts → completion-ts delta exposed. |
| D2: per-worker reap-lag jitter below the C threshold | `dbg_tx_ring_full = 0` but µs-scale stalls. | `outstanding_tx` is a depth, not a latency. |
| D3: NIC-side send-queue pressure (tx pause / LLFC) | Needs completion-latency tail vs submit rate. | `ethtool -S` not wired into snapshot; we lack a time-series view either way. |
| D4: RX coalescing gap on generic XDP | Orthogonal to TX latency — but a healthy TX histogram RULES OUT D1/D2 and forces the next investigation to D3/D4. | — |

#812 is the instrumentation PR that makes D1/D2/D3 discriminable.
Pure observability — it does not fix anything.

## 2. Scope

### In-scope

- Per-queue-per-worker log-spaced latency histogram of `(ts_completion_reap - ts_submit_commit)` for each UMEM TX descriptor.
- Storage: `[AtomicU64; N_BUCKETS]` on `BindingLiveState`, mirroring the existing `drain_latency_hist` pattern
  (`userspace-dp/src/afxdp/umem.rs:188`).
- Per-frame-offset submit-ns sidecar, pre-allocated once at binding construction (`FastMap<u64, u64>` is NOT acceptable — see §3 sub-heading on sidecar).
- Serialization: extend `BindingCountersSnapshot` (`userspace-dp/src/protocol.rs:1367-1423`) with the histogram + two scalar metadata fields (count, sum-ns), following the PR #804 additive pattern.
- Read path: Go consumer picks up the new field through the existing `flow_steer_snapshot` status poll (the `status` request in `userspace-dp/src/main.rs:371` → `state.status.per_binding` at `main.rs:802-807`).
- Bucket-math unit pins, cross-thread read-side test, serde round-trip test.
- Integration test: iperf3 `-P 16 -t 60 -p 5203` on `loss:xpf-userspace-fw0` cluster, query the snapshot, assert a non-empty histogram.

### Out-of-scope (explicit — do NOT add to this PR)

- Any hot-path SEMANTIC change (no re-order, no new drop rule, no new backpressure gate). Purely additive observability.
- D1' / AFD / Phase 5 MQFQ shaper tuning or TX-ring-size tuning (`step1-plan.md:1069-1099` — ruled out by §4.6 aggregation).
- The symmetric reverse-CoS config question (term 3 on `bandwidth-output` missing `from destination-port 5204` — `step1-findings.md:18-24`). Separate PR.
- Z_cos recalibration itself (sub-task #10 — deferred to a follow-up commit once the histogram lands and park-rate samples can be recaptured).
- NIC-side ethtool time-series (D3 instrumentation — separate follow-up).
- Adding the histogram to Prometheus (separate follow-up; JSON first because the classifier already speaks `flow_steer_samples.jsonl`).

## 3. Design

### 3.1 Measurement points — exact code sites

AF_XDP TX hardware is "fire-and-forget": completions arrive on the
completion ring with only the UMEM frame offset — no timestamp. We
record the submit timestamp in a per-binding sidecar keyed by frame
offset, and compute the delta at reap time.

**Submit-ts sites (6 total — all TX ring commit points).** For each
descriptor about to be inserted, stamp `ts_submit_ns[offset] =
monotonic_nanos()` BEFORE `writer.commit()`. The reference sites in
`userspace-dp/src/afxdp/tx.rs`:

| Call-site function | `writer.commit()` line | `dbg_tx_ring_submitted +=` line |
|---|---|---|
| (unnamed, ~line 1830) | `tx.rs:1855` | `tx.rs:1871` |
| `transmit_prepared_queue` / local variant | `tx.rs:1975` | `tx.rs:1995` |
| MQFQ exact-prepared variant | `tx.rs:2112` | `tx.rs:2127` |
| MQFQ exact-local variant | `tx.rs:2235` | `tx.rs:2256` |
| `transmit_batch` (post-CoS backup) | `tx.rs:5935` | `tx.rs:5947` |
| `transmit_prepared_batch` (continuation) | `tx.rs:6149` | `tx.rs:6160` |

The submit-ts write happens inside the existing
`scratch_local_tx` / `scratch_prepared_tx` loop that already walks the
batch to call `writer.insert(...)`. Specifically: right after the loop
has validated each descriptor's `offset` but before `writer.commit()`.
One `monotonic_nanos()` call per batch (not per-packet) is enough —
we stamp all descriptors in the batch with the same timestamp. See
§3.4 for the overhead derivation.

Only descriptors actually accepted by `writer.insert()` (i.e., index
`< inserted`) get stamped. The retry-unwind path already restores
offsets to `free_tx_frames.push_front(offset)` — those MUST NOT have
their submit-ts recorded.

**Completion-ts site (1 total — the reap loop).** In
`userspace-dp/src/afxdp/tx.rs:3-35` (`reap_tx_completions`):

- After `completed.read()` populates `scratch_completed_offsets`
  (`tx.rs:15-22`), call `monotonic_nanos()` ONCE before the recycle
  loop at `tx.rs:23-26`.
- For each `offset`, look up `ts_submit_ns[offset]`, compute
  `delta_ns = ts_completion_ns - ts_submit_ns`, classify with
  `bucket_index_for_ns(delta_ns)` (already in `umem.rs:162`, reuse
  verbatim), and `fetch_add(1, Relaxed)` on the corresponding bucket
  of the new `tx_submit_latency_hist`.
- Clear the sidecar slot (store 0 or a tombstone — see §3.3).

Descriptors with a missing sidecar entry (e.g., leftover from a
crash restart within the same UMEM) must NOT inflate the histogram.
We use a sentinel value (u64::MAX) in the sidecar to indicate
"unstamped" and skip the bucket increment for that offset.

### 3.2 Bucket spacing + range

**Reuse the existing `bucket_index_for_ns` layout from #709
(`umem.rs:112-166`).** 16 log2-spaced buckets, range
`[0, 2^24) ns = [0, ~16 ms]`:

| Bucket | Range (ns) | Range (µs) |
|---|---|---|
| 0 | [0, 1024) | [0, 1.024) |
| 1 | [1024, 2048) | [1, 2) |
| 2 | [2048, 4096) | [2, 4) |
| ... | `[2^(N+9), 2^(N+10))` | |
| 14 | [2^23, 2^24) | [8.388, 16.777) ms |
| 15 | [2^24, ∞) | ≥ 16.777 ms (saturation) |

**Rationale for this range and this N:**

- At 25 Gbps line rate with 1500-byte frames, one packet = 480 ns on
  the wire. Sub-µs (bucket 0) is the "healthy NIC DMA + single-
  packet completion" regime.
- TX completion typical latency on Linux AF_XDP / virtio is
  low-single-digit µs when the NIC is keeping up, landing in
  buckets 1-3.
- A 100-µs gap (NIC tx-pause, LLFC event, or coalescing stall)
  lands in bucket 7 — distinguishable from the healthy range by a
  wide margin.
- The saturation bucket at 16 ms is far beyond any "normal"
  completion and catches pathological stalls without bloating the
  bucket count.
- 16 buckets × 8 bytes = 128 B per queue-per-worker = 2 cache
  lines, keeping the atomic array within the "telemetry cacheline-
  isolated" pattern #746 established (see `umem.rs:186-263`).
- Reusing the exact bucket layout is a wire-format win: the
  existing Prometheus exporter path for `drain_latency_hist`
  already knows how to unpack 16 log-spaced buckets; extending it
  costs ~1 copy-paste.

We explicitly do NOT use HdrHistogram. HdrHistogram is a `Vec`-
based dynamic structure and would allocate. Fixed-cap atomic array
keeps us allocation-free on the hot path.

Compile-time invariant:

```rust
const _: () = assert!(TX_SUBMIT_LAT_BUCKETS == DRAIN_HIST_BUCKETS);
```

— so a future edit that renumbers the drain histogram at
`umem.rs:128` also catches this wire-contract dependency at build
time.

### 3.3 Sidecar — `ts_submit_ns[frame_offset]`

**Per-binding, per-worker dense array indexed by UMEM frame slot.**

The binding's UMEM has a fixed number of frames (`WorkerUmem::
total_frames` — `umem.rs:56`), and `ring_entries` is bounded
(typical 8192 per `bind.rs:39` comment). The TX ring itself is
bounded by `ring_entries`; outstanding submit-ts sidecar entries
can never exceed `ring_entries`.

Storage shape: `Vec<u64>` of length `total_frames`, allocated once
at `BindingWorker::new`, indexed by `(offset / UMEM_FRAME_SIZE)`.
Sentinel `u64::MAX` = unstamped.

Why not `FastMap<u64, u64>` keyed by offset:
- `FastMap::insert` may allocate on grow → violates hot-path
  allocation rule (§Hot-path coding discipline, `engineering-style.md:51-68`).
- Bucketed hash access = extra indirection, branch on hit/miss.
- A dense array is one load + one store per descriptor.

Memory cost: `8192 frames × 8 B = 64 KiB per worker per binding`.
Acceptable — already well below the per-binding MmapArea UMEM
itself (`8192 × 4096 B = 32 MiB`).

**Single-writer property.** The frame offset is claimed by the
owner worker's `free_tx_frames.pop_front()` and returned via
`recycle_completed_tx_offset` — both inside the single-threaded
owner-worker loop for this binding. Submit and completion for one
offset are the same thread. No atomic needed on the sidecar;
plain `&mut Vec<u64>` store/load.

Thread-safety: the owner worker is the sole writer AND sole reader.
The HISTOGRAM atomics are cross-worker (owner writes on reap,
control-socket thread reads on snapshot) — only the final bucket
`fetch_add` crosses threads.

### 3.4 Overhead budget — derivation, not a guess

**Per-packet additions on the TX submit path (batch-amortized):**

Per batch (up to `TX_BATCH_SIZE = 256` descriptors — `afxdp.rs:152`):

| Op | Cost (ns, x86_64 modern) | Per-batch | Per-packet @ 256/batch |
|---|---|---|---|
| `clock_gettime(MONOTONIC)` VDSO | ~15 ns | 15 ns | 0.06 ns |
| `offset / UMEM_FRAME_SIZE` (u64 shift) | <1 ns | <1 ns | <0.01 ns |
| sidecar store `ts_submit_ns[idx] = now` | 1 ns (L1 write) | 256 ns | 1 ns |
| **Subtotal submit** | | | **~1.1 ns/pkt** |

**Per-packet additions on the TX completion (reap) path:**

Per batch of completions (typically TX_BATCH_SIZE):

| Op | Cost (ns) | Per-batch | Per-packet @ 256/batch |
|---|---|---|---|
| `clock_gettime(MONOTONIC)` VDSO | ~15 ns | 15 ns | 0.06 ns |
| sidecar load + sentinel check | 1 ns | 256 ns | 1 ns |
| `bucket_index_for_ns` (1 clz + max + min — `umem.rs:161-166`) | <2 ns | 512 ns | 2 ns |
| `hist[bucket].fetch_add(1, Relaxed)` | 3-5 ns (uncontended, own cache line) | 768-1280 ns | 3-5 ns |
| **Subtotal reap** | | | **~6-8 ns/pkt** |

**Total per packet: ~7-10 ns.** This is additive — the packet has
already paid for `bucket_index_for_ns` elsewhere (drain histogram,
redirect histogram) so the function is cache-hot.

**Cache-line cost:** one new cache-line touch per packet on the
`tx_submit_latency_hist` atomic (16 buckets = 2 cache lines; a
healthy-traffic run hits ~3 adjacent buckets, so steady-state is
~1 cache line active).

**25 Gbps budget check:**

- 25 Gbps ÷ 12000 bits/packet (~1500 B) ≈ 2.08 Mpps per queue at
  line rate.
- Per-packet budget at P=16 workers: each worker handles ~130
  Kpps. Per-packet CPU time: ~7600 ns total (1 / 130K = 7.7 µs).
- Additive 10 ns ÷ 7600 ns = **0.13 % of per-packet CPU budget.**
- Well under the 1 % hard-stop threshold in §8.

**What we explicitly do NOT do** — and why:

- We do NOT call `monotonic_nanos()` per packet. Batch-amortized
  (1 call per submit commit, 1 call per reap batch).
- We do NOT store per-packet latency. Only the bucket-increment
  survives.
- We do NOT log per-packet. Histograms are read by snapshot, not
  streamed.
- We do NOT use HdrHistogram or any `Vec::push`-based structure.

### 3.5 Serialization — `BindingCountersSnapshot` extension

Extend `userspace-dp/src/protocol.rs:1367-1423` additively:

```rust
// existing fields...

// #812: per-queue TX submit→completion latency histogram. Buckets
// match DRAIN_HIST_BUCKETS layout (see umem.rs:112-128). Absent on
// wire = all-zero (default), preserving pre-#812 consumers.
#[serde(rename = "tx_submit_latency_hist", default)]
pub tx_submit_latency_hist: Vec<u64>,
// count of completions observed since last reset. MUST equal the
// sum of the histogram buckets; used as a consistency check.
#[serde(rename = "tx_submit_latency_count", default)]
pub tx_submit_latency_count: u64,
// running sum of observed deltas in ns. MUST equal
// sum(bucket_idx * bucket_midpoint) within bucket discretization;
// used for mean-latency computation without bucket integration.
#[serde(rename = "tx_submit_latency_sum_ns", default)]
pub tx_submit_latency_sum_ns: u64,
```

And correspondingly in the `From<&BindingStatus>` impl
(`protocol.rs:1406-1423`), plus new fields on `BindingStatus`
(where `drain_latency_hist` already lives at
`userspace-dp/src/protocol.rs:881-883`, same struct).

The `snapshot()` function in `userspace-dp/src/afxdp/umem.rs` at
`:1330-1345` already copies the drain histogram bucket-by-bucket
via `Self::snapshot_hist` (`umem.rs:1352-1354`). Add two more
lines to `BindingLiveSnapshot` construction in the same pattern.

Go consumer side — the snapshot JSON is parsed by existing
step1-capture plumbing (`test/incus/step1-capture.sh` via
`flow_steer_samples.jsonl`). No Go struct change needed for the
plan; the classifier upgrade is Z_cos recalibration follow-up
(§10).

### 3.6 Snapshot semantics — "read = reset" vs "monotonic with delta"

**Decision: monotonic counters, NO reset on snapshot.** Rationale:

- All existing histograms (`drain_latency_hist`,
  `redirect_acquire_hist`) are monotonic.
- Snapshot consumers compute delta by subtracting two successive
  snapshots — the step1-capture script already does this for every
  other counter (`step1-findings.md:81` shows `park_rate` derived
  as delta / 60 s).
- A "reset on snapshot" scheme races with in-flight `fetch_add`s
  (multiple pending completions between read and reset-to-zero
  can be lost).
- If a future operator wants a reset endpoint, it's a separate
  request type in `main.rs:371` (`"reset_tx_latency"` — DEFERRED,
  §12).

Sidecar (`ts_submit_ns`) is NOT snapshot-able — it's worker-local
state and holds in-flight values only.

## 4. Invariants

Non-negotiables that must not drift. Any violation = block merge.

1. **Hot path: no new lock, no new heap allocation, no new syscall per packet.**
   - `clock_gettime` VDSO is NOT a syscall.
   - The sidecar is pre-allocated once at binding construction.
   - The bucket atomic is `fetch_add(1, Relaxed)` — uncontended on the owner's cache line.
   - Reviewer check: `git diff` must show zero `Box::new` / `Vec::with_capacity` / `HashMap::insert` inside the submit or reap hot paths.

2. **Per-packet overhead: ≤ 15 ns CPU, ≤ 1 additional cache-line touch.**
   - Derived in §3.4. Enforced by a Criterion micro-bench (new file `userspace-dp/src/afxdp/tests.rs` — add a bench) that pins the per-packet delta for submit-stamp + reap-bucket.

3. **Histogram monotonic; no reset on snapshot.** §3.6 rationale.
   - Enforced by serde: no reset parameter plumbed.

4. **Thread-safety: single-writer (owner worker), many-readers.**
   - Submit-stamp and reap-bucket-increment are both on the owner worker's thread — the only thread that touches this binding's TX frames.
   - Snapshot reads are `load(Relaxed)` from the control-socket thread — identical pattern to the existing drain-histogram read at `umem.rs:1330-1345`.

5. **Bucket layout is frozen wire contract.**
   - `const _: () = assert!(TX_SUBMIT_LAT_BUCKETS == DRAIN_HIST_BUCKETS)` at module level. A renumber-without-propagation breaks the build.

6. **Sum of buckets == completion count within the measurement window.**
   - Because a single completion drives exactly one `fetch_add(1)` and nothing else touches these atomics.
   - Enforceable with an `#[test]` that drives N synthetic completions and asserts `sum(hist) == tx_submit_latency_count`.

7. **`tx_submit_latency_count` monotonically ≤ `tx_completions`.**
   - A completion with a missing sidecar entry (e.g., pre-#812 frame offset that survived a restart) increments `tx_completions` but NOT the histogram. So `count ≤ tx_completions` is a loose bound used for sanity-checking the classifier output.

## 5. Measurement integrity — how do we know we're measuring what we think?

Three layers of assurance.

### 5.1 Injected synthetic delay (unit test)

Add a test at `userspace-dp/src/afxdp/tests.rs`:

- Construct a `BindingLiveState` and a fake sidecar.
- Stamp submit-ts at `T0`. Inject a manual completion with a
  deterministic `now = T0 + K_ns` for `K_ns ∈ {500, 1500, 10_000,
  100_000, 10_000_000}`.
- Snapshot the histogram; assert the specific bucket predicted by
  `bucket_index_for_ns(K_ns)` has count 1, all others 0.

This is the strongest possible pin — if the bucket arithmetic
shifts, the test fails on exactly the boundary value.

### 5.2 Histogram-sum consistency (property test)

- Drive N random-latency completions through the hot path. Assert
  `sum(buckets) == N`. Invariant 6.

### 5.3 End-to-end live data sanity check

Part of §6 integration test: after iperf3 `-P 16 -t 60`, read the
snapshot. Assert:
- `tx_submit_latency_count > 0` on every worker-queue pair that
  had TX activity (any `tx_packets > 0`).
- The non-empty histogram has NO mass in the saturation bucket 15
  (> 16 ms) in a healthy run — if it does, that's itself a
  D-tier signal (post-merge, not a failure of #812).
- Mean latency derived from `tx_submit_latency_sum_ns /
  tx_submit_latency_count` is in the expected single-digit-µs
  range.

### 5.4 Protection against phantom completions

If a frame offset completes without a submit-stamp (sentinel
`u64::MAX`), we MUST skip the histogram increment — otherwise we'd
record `ts_completion - u64::MAX` wrapping to a tiny positive ns
number that lands in bucket 0 and silently biases the distribution
toward "healthy".

The sentinel-check is part of §5.1's unit-test coverage (one test
case with a deliberately unstamped completion; histogram stays at
zero).

## 6. Test plan

### 6.1 Unit pins (≥ 3 — required by the spec above)

1. **Bucket boundary test.** See §5.1.
2. **Atomic ordering / concurrency.** Spawn two threads: one
   calls `record_tx_submit(offset, now)` on the sidecar; the other
   calls `record_tx_completion(offset, now+K)`. Assert (a) no
   torn read; (b) bucket count increments by exactly 1 for any
   N-completion interleaving.
3. **Serialization round-trip.** Construct a
   `BindingCountersSnapshot` with a non-trivial histogram; JSON-
   encode, JSON-decode; assert field-equality. Also assert that
   a pre-#812 JSON payload (missing the new fields) deserializes
   with zero-valued histogram (serde `default`).

Additional unit pins:

4. **Sentinel skip.** §5.4.
5. **Invariant 6 (sum == count).** §5.2.

### 6.2 Integration test

Run on the `loss:xpf-userspace-fw0` HA cluster primary, per the
Step 1 execution environment (`step1-findings.md:21-22`).

```bash
# Setup: re-apply CoS config per engineering-style.md §Project-specific
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
# Run the instrumented daemon for 60 s at P=16
iperf3 -c 172.16.80.200 -P 16 -t 60 -p 5203
# Snapshot
cli -c "show userspace-dp binding counters" > snap.json
# Assertions (add a helper script — commit together with the PR)
jq '.per_binding[] | select(.tx_packets > 0) |
      {q: .queue_id,
       count: .tx_submit_latency_count,
       non_empty: (.tx_submit_latency_hist | map(. > 0) | any)}' snap.json
# Every worker with TX activity must have non-empty histogram + count > 0.
```

### 6.3 Forwarding smoke — mandatory continuous gate

Per `docs/development-workflow.md:188-202` and
`engineering-style.md:213-222`:

```bash
iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203   # 0 retransmits, before and after
```

If retransmits > 0 on either side: revert (§7).

### 6.4 Regression check — existing pin suite

`cargo test -p xpf-userspace-dp` — all 255 existing Rust tests
must still pass. In particular the `mqfq_*` and `flow_steer_*`
unit tests (admission, bucket math, snapshot serialization) — any
regression is a hard stop (§8).

## 7. Rollback

**Failure-mode enumeration:**

| Failure | Symptom | Catcher | Revert |
|---|---|---|---|
| Incorrect atomic ordering on bucket write | Test #2 fails; histogram sum ≠ count. | `cargo test`. | Revert the PR commit; no prod exposure. |
| Sidecar sentinel miscompare → bucket 0 bias | Mean latency artificially drops; §5.1 fails. | Unit test #4. | Revert. |
| `clock_gettime` panics on an exotic kernel | Daemon panics at startup; forwarding dies. | `make test-deploy` fails smoke. | `systemctl stop xpf-userspace && xpf-userspace cleanup && git revert`. |
| Cache-line ping-pong under cross-binding traffic | P=16 t=60 SUM regresses > 5 %. | Hot-path bench (§8). | Revert. |
| PR #804 wire-contract break | Pre-#812 snapshot consumer (step1-capture.sh running a pinned branch) chokes on new fields. | serde `default` annotations guarantee this does NOT happen — the test in §6.1 item 3 proves the compat. | No revert path needed IF the test passes. |

**Revert mechanics:**
```bash
git revert <commit-sha>
make build && make test-deploy && make cluster-deploy
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
# Forwarding smoke must pass at 0 retransmits.
```

If a revert itself fails (hitless-restart property violated), fall
back to `xpfd cleanup` on each node in sequence. The HA cluster
survives a rolling restart (`MEMORY.md` — "Hitless Restart Patterns").

## 8. Hard stops

Each of these terminates execution immediately; no investigation,
no "let's just merge it and file a follow-up":

1. **Hot-path bench regresses > 5 % on `iperf3 -P 16 -t 60 -p 5203` SUM** (absolute Gbps, pre vs post on the same cluster, same CoS state).
2. **Any forwarding smoke (`-P 4 -t 5`) returns retransmits > 0** after the PR lands.
3. **Any `mqfq_*` or `flow_steer_*` unit test fails.**
4. **Histogram sum ≠ count in an integration run** (indicates a lost bucket update or double-count).
5. **CPU profile shows > 1 % time in `record_tx_submit` + `record_tx_completion` combined** (measured via `perf record -e cpu-clock` during the integration test). Derived budget in §3.4 is 0.13 %; 1 % gives a ~7× safety margin.

## 9. Wall-clock + scope

### Implementation estimate

| Sub-task | Hours |
|---|---|
| `BindingLiveState` field additions + `#[repr(align(64))]` cacheline-isolation (similar to `OwnerProfileOwnerWrites`) | 2 |
| Submit-ts stamping — 6 sites in `tx.rs`, common helper | 2 |
| Reap-side delta + bucket `fetch_add` in `reap_tx_completions` | 1 |
| `BindingCountersSnapshot` + `BindingLiveSnapshot` fields + `From` impl | 1 |
| Coordinator reverse-copy (`coordinator.rs:1404-1427`) | 0.5 |
| Unit tests (5 pins, §6.1) | 3 |
| Integration helper + smoke | 1 |
| Criterion bench for hot-path overhead | 1.5 |
| Plan/code review finding response | 2 |
| **Subtotal** | **14 h** |

### Total story

| Phase | Typical rounds (workflow §Plan-cycle) | Wall-clock |
|---|---|---|
| Plan review (Architect ↔ Design Reviewer) | 2-4 | 1-2 days |
| Code implementation | — | 2 days |
| Code review (Codex + Rust angle) | 2-3 | 2-3 days |
| Merge + forwarding validation | — | 0.5 day |
| **Total** | | **6-8 days** |

### Stack posture

**Ships alone.** No stacking. Rationale:

- #812 is strictly additive observability and does not modify the
  hot-path semantic state that any other in-flight PR would
  depend on.
- #806 (Z_cos recalibration) explicitly waits for #812 to land
  first (§10).
- Stacking it on an unrelated refactor PR (e.g. 807-refactor)
  would entangle the hot-path bench comparison.

## 10. Z_cos recalibration — separate sub-task after merge

**Deferred to follow-up commit, not part of #812's scope.**

Once #812 is merged and running on the HA cluster primary:

1. Re-run the step1-capture script on AT LEAST two with-cos-fwd
   shaped cells (e.g. `p5202-fwd-with-cos` and
   `p5203-fwd-with-cos`).
2. Sample `queue_token_starvation_parks` AND the new
   `tx_submit_latency_hist` on each run.
3. Derive `Z_cos = mean(park_rate) + 2 × stddev(park_rate)` per
   `step1-plan.md:507-524`.
4. Update the §4.2 threshold table in `step1-plan.md` with the
   real number, and amend `step1-findings.md` §5 noting the
   recalibration.
5. Amend the §8 gating loop at `step1-plan.md:1082-1094` —
   specifically the line that reads "the gate is on data
   provenance (Z_cos source), not on fire count" — to mark the
   gate CLOSED.

This is a DOCS-ONLY PR once #812 is in. Wall-clock ~1 day.

## 11. Statistical analysis — what the re-run classifier looks for

After #812 merges, re-running Step 1 with the new histogram
available changes the per-cell dashboard from 10 fields to 26
(adding 16 bucket counts, plus count and sum-ns). The classifier
will look for signature patterns, not just scalar thresholds.

### 11.1 Patterns per verdict

| Verdict | Histogram pattern that indicates it |
|---|---|
| **A** (cross-worker imbalance) | Histogram shape roughly equal across workers; the imbalance is in `rx_packets / tx_packets` counts, not in TX-completion latency. No change to how A is detected — A fires on flow distribution, independent of latency. |
| **B** (MQFQ token starvation) | Mass concentrates in buckets 4-7 (tens of µs) correlated with `queue_token_starvation_parks > 0`. The park-rate spike and the latency-bucket shift SHOULD co-occur. If they don't, the park counter is misleading (classifier HIGH finding for a future revision). |
| **C** (TX-ring full) | Mass shifts to buckets 8+ (hundreds of µs to ms). Completions stall because the ring is full and `sendto` kicks are bounced. Correlated with `dbg_tx_ring_full > 0`. |
| **D1** (XSK submit → DMA latency alone) | Mass in buckets 3-6 (4-128 µs) with NO correlation to park-rate and NO ring-full events. The smoking gun: latency elevated, but everything else clean. |
| **D2** (reap-lag jitter below C) | Bimodal distribution: most completions in buckets 0-2 (healthy) plus a secondary lobe in 6-9 (occasional multi-ms reap lag). The difference between D2 and D1 is the SHAPE — D1 is a shifted mean, D2 is a heavier tail. |
| **D3** (NIC-side backpressure / LLFC) | Saturation mass in bucket 14-15 (≥ 8 ms) that clears when wire-level pressure relaxes. Requires correlating with `ethtool -S tx_pause` time-series (separate follow-up). |
| **D confirmed (no new signal)** | Histogram is tight in buckets 0-2, count × 60s ≈ tx_packets, NO visible tail. The ~2.4 Gbps shortfall observed in `step1-findings.md:95` is not in the TX-completion path → it must be in RX coalescing (D4) or upstream. |

### 11.2 What would make the verdict A/B/C actually FIRE under re-run

- For verdict A: `k_A ≥ 2` across neighboring cells (§4.6
  aggregation rule, `step1-plan.md:1069-1074`). The histogram does
  NOT change the A firing logic, but it can corroborate it by
  showing per-worker histogram divergence.
- For verdict B: `k_B ≥ 2 of 4` with-cos-fwd shaped cells AND the
  Z_cos gate in §10 CLOSED.
- For verdict C: `k_C ≥ 1` — same as before. The new histogram
  can pre-warn for C before `dbg_tx_ring_full` spikes (mass
  drifting to bucket 8+ indicates the TX ring is filling).

### 11.3 False-positive risk of the new signal

Per `step1-plan.md:1134`, no bare "5 %" thresholds. The histogram
adds 16 counters × 12 cells = 192 additional observations per
re-run. If we set a D1 threshold like "mass in bucket 4-6 ≥ 10 %
of count", multiple-testing correction is warranted. The
re-calibration sub-task (§10) MUST include a Bonferroni or
equivalent correction for the 16-bucket multiple comparison before
any D-subdivision verdict fires.

## 12. Deferrals — expected reviewer concerns we deliberately do NOT address in this PR

Listed with rationale so a future reviewer doesn't rediscover them.

1. **Prometheus export of the new histogram.** JSON-only in this
   PR. Step 1 classifier consumes JSON. Prometheus wiring adds a
   separate serde path and risks a cardinality-blowup per
   queue-per-worker. Follow-up issue to be filed as #812a.
2. **Per-flow (per-5-tuple) latency histograms.** Bucket-
   isolating by flow would require a hash in the hot path —
   violates the allocation rule. Aggregate-per-queue is the right
   scope for Step 2.
3. **Histogram reset endpoint.** §3.6 explicit decision.
4. **HdrHistogram / dynamic bucket adaptation.** Incompatible
   with the hot-path allocation rule. Fixed-cap array is the
   Engineering Style commitment (`engineering-style.md:52-57`).
5. **Moving `bucket_index_for_ns` to a shared helper crate.**
   The function already lives in `umem.rs` and is used by three
   callers (drain, redirect-acquire, submit-latency). Extraction
   to a helper module is cleanup, not blocking — it survives the
   "source of truth" rule (`engineering-style.md:17-20`)
   trivially because all three uses WILL NOT drift: they all
   const-assert the same bucket count.
6. **NIC-side `ethtool -S tx_pause` time-series.** Needed for D3
   separation. Separate follow-up (Step 2 D3 spike PR, not #812).
7. **Reverse-direction CoS config fix.** `step1-findings.md:18-24`
   — noted, separate PR to be filed after this one.
8. **Bucket-width asymmetry.** Some reviewers will argue 16 log2
   buckets is too coarse at the low end (everything < 1 µs in
   bucket 0). Rebuttal: the existing drain histogram uses this
   exact layout and has survived 3 revisions of review. Changing
   the layout for #812 would break `bucket_index_for_ns` single-
   source-of-truth.
9. **Online Z_cos recalibration.** Keep the recalibration
   off-line (operator runs step1-capture, updates the plan). An
   online feedback loop in the daemon would couple the
   classifier to the scheduler and expand blast-radius well
   beyond instrumentation scope.
10. **Bucket midpoint for `tx_submit_latency_sum_ns`.** We store
    the exact per-packet delta sum, not a midpoint
    approximation. Discretization-free mean at the cost of one
    extra `fetch_add(delta, Relaxed)` per completion — already
    counted in the §3.4 overhead budget (the 3-5 ns bucket
    fetch_add line).
11. **Interaction with rare hot-path #806 patches.** None — #806
    explicitly depends on #812 landing first. #806 is the
    Z_cos recalibration and any AFD follow-up work; it cannot
    start until the gate in `step1-plan.md:1082-1094` is closed.

---

*End of Architect draft. Awaiting Design Reviewer findings per
`docs/development-workflow.md:85-99`. Reviewer: please flag
HIGH / MEDIUM / LOW with `file:line` citations and concrete
mitigations. Append results to `docs/pr/812-tx-latency-
histogram/plan-review.md`.*
