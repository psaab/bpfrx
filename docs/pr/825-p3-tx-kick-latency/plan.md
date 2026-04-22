# Issue #825 — Architect plan: wire `tx_kick_latency_hist` + `tx_kick_retry_count`

> **Status.** Architect Round 1. Awaiting Codex hostile plan review.
> **Deliverable.** Daemon code change implementing #819 plan §5.3 verbatim.
> Implementor consumes this plan only after PLAN-READY YES.
> **Cluster.** Userspace cluster only: `loss:xpf-userspace-fw0`. bpfrx forbidden.
>
> **What this plan is NOT.** Not a re-litigation of #823's M3 OUT verdict.
> Not Phase 4 scoping. Not the P3 capture run — that is a separate
> follow-up per the Issue A → #823 pattern (§14 Deferrals).

## 1. Problem statement

Per `docs/pr/819-step2-discriminator-design/step2-p1-findings.md` §1 and §6:

> "**M3 OUT on both load-bearing cells.** … M1 (in-AF_XDP submit→TX DMA
> stalls) becomes the highest-prior remaining mechanism. The latency is
> spent *inside* the `sendto` syscall (spinning on a full ring, blocking
> in kernel, or inner AF_XDP queueing) while the worker holds the CPU."

P3 tests M1. #819 design doc §5.3 defines the wiring contract — four new
fields on `BindingCountersSnapshot` plus hot-path instrumentation in
`maybe_wake_tx`. **This plan implements that contract.** The T1 threshold
(#819 §4.1) the P3 capture will apply is `Δ(retry_counter)/block ≥ 1000
AND mean(sendto_kick_latency) ≥ 4 µs` (IN) vs `< 100/block AND < 2 µs` (OUT).

TX kick site pinned: `maybe_wake_tx` at `userspace-dp/src/afxdp/tx.rs:6429`,
sendto at `:6439`, EAGAIN/EWOULDBLOCK handled at `:6452`. Verified against
current HEAD in §3.1.

## 2. Hypotheses

This is an implementation plan, not a measurement plan. The one hypothesis
is tested by the P3 capture follow-up, not by this PR:

- **H1 (tested post-merge by P3 capture).** On p5201-fwd-with-cos and
  p5202-fwd-with-cos, the newly-wired `tx_kick_latency_hist` +
  `tx_kick_retry_count` satisfy T1 IN per #819 §4.1 during T_D1-elevated
  blocks.

This PR's contract is narrower: instrumentation correctness such that the
P3 capture can fairly test H1. Correctness gates are §9.

## 3. Design — per-file spec

### 3.1 Verified context (pre-flight, not a change)

- `tx.rs:6429`: `maybe_wake_tx(binding: &mut BindingWorker, force: bool, now_ns: u64)`. Runs on the owner worker thread (single writer per binding). Has `&mut binding`, so `binding.live.owner_profile_owner` is accessible.
- `tx.rs:6438-6447`: `libc::sendto` syscall.
- `tx.rs:6449-6480`: error classification. `binding.dbg_sendto_eagain` already counts `EAGAIN || EWOULDBLOCK` returns but is NEVER published out of the worker (unlike `dbg_sendto_enobufs` published at `worker.rs:1396-1400`). This plan publishes a parallel atomic that IS surfaced in the snapshot.
- `tx.rs:3-135`: `record_tx_completions_with_stamp` is the precedent for hot-path atomic bucket writes on `OwnerProfileOwnerWrites`; we mirror its shape for `record_kick_latency`.
- `neighbor.rs:3-15`: `monotonic_nanos()` — `clock_gettime(CLOCK_MONOTONIC)`, VDSO fast path (~15 ns on the deploy VM per `docs/pr/812-tx-latency-histogram/plan.md` §3.4a). Returns 0 on syscall failure; sentinel check in `record_kick_latency` mirrors `TX_SIDECAR_UNSTAMPED`.
- `umem.rs:198-202`: `bucket_index_for_ns(ns: u64) -> usize` — reuse verbatim.
- `umem.rs:223-254`: `OwnerProfileOwnerWrites` — cacheline-isolated (`#[repr(align(64))]`) owner-only atomic struct. `tx_submit_latency_hist` / `_count` / `_sum_ns` live here; we add four parallel fields.
- Wire-format today: `BindingStatus` at `protocol.rs:1333-1338` has three `tx_submit_latency_*` fields; `BindingCountersSnapshot` at `:1420-1425` has the same three, projected via `From` at `:1455-1479`. The `'static + Send` assert is at `:1446-1449`.
- Go mirror at `pkg/dataplane/userspace/protocol.go:682-684` (`BindingStatus`) and `:726-728` (`BindingCountersSnapshot`).

### 3.2 `userspace-dp/src/afxdp/umem.rs` — new owner-write atomics

Add four fields to `OwnerProfileOwnerWrites` after `tx_submit_latency_sum_ns`:

```rust
pub(super) tx_kick_latency_hist: [AtomicU64; TX_SUBMIT_LAT_BUCKETS],
pub(super) tx_kick_latency_count: AtomicU64,
pub(super) tx_kick_latency_sum_ns: AtomicU64,
pub(super) tx_kick_retry_count: AtomicU64,
```

Initialize in `OwnerProfileOwnerWrites::new` (currently `umem.rs:335-349`) to zero / `AtomicU64::new(0)` / `std::array::from_fn(|_| AtomicU64::new(0))`.

**Cacheline budget (MED-1 R1 explicit cap-raise).** Current size: 328 B raw / 384 B padded (Codex R1 verified). Adding 16 × u64 histogram + 3 × u64 scalars = +152 B = **480 B raw / 512 B padded**. The 448 B const-assert at `umem.rs:332` WILL fire. Required cap-raise in the same commit:

```rust
// Raise cap to 512 for #825 tx_kick_latency_* fields.
// New total: 480 B raw / 512 B padded. `#[repr(align(64))]` alignment
// invariant unchanged (the separate align assert still holds).
const _ASSERT_OWNER_PROFILE_OWNER_SIZE: () =
    assert!(size_of::<OwnerProfileOwnerWrites>() <= 512);
```

The two assertions are independent: one caps size, one pins alignment. Only the size cap changes; alignment stays at 64 B. The 512 B padded size still fits within ~8 cache lines — standard on x86_64.

Bucket-count reuse: `TX_SUBMIT_LAT_BUCKETS = DRAIN_HIST_BUCKETS = 16` — same const. No new const added; existing `_ASSERT_TX_SUBMIT_BUCKET_COUNT_IS_16` pins the wire contract for both.

Bucket-count reuse: `TX_SUBMIT_LAT_BUCKETS = DRAIN_HIST_BUCKETS = 16` — same const. No new const added; existing `_ASSERT_TX_SUBMIT_BUCKET_COUNT_IS_16` pins the wire contract for both.

### 3.3 `userspace-dp/src/afxdp/tx.rs` — hot-path instrumentation

**Site 1: `maybe_wake_tx` (line 6429).** Rewrite the sendto block:

- Before `libc::sendto` (line 6438): `let kick_start = monotonic_nanos();`
- After sendto returns, before error classification: `let kick_end = monotonic_nanos();`
- `let delta_ns = kick_end.wrapping_sub(kick_start);` — `wrapping_sub` because `monotonic_nanos()` returns 0 on failure; untrapped underflow would explode the bucket index. Sentinel (LOW-3 R1 fix — precedent-matching): skip record when `kick_end < kick_start` (matches `record_tx_completions_with_stamp`'s `ts_completion >= ts_submit` pattern at `tx.rs:113-119`; does NOT use `== 0` checks — monotonic_nanos() failure is already captured by the `wrapping_sub` producing a bogus-large value, which the `<` check catches via the bucket saturation guard).
- Call `record_kick_latency(&binding.live.owner_profile_owner, delta_ns);` after the sentinel check.
- In the `errno == libc::EAGAIN || errno == libc::EWOULDBLOCK` branch (line 6452), also call `binding.live.owner_profile_owner.tx_kick_retry_count.fetch_add(1, Ordering::Relaxed);`. `binding.dbg_sendto_eagain` stays (the worker-local debug-tick log at `worker.rs:1051-1054` continues to work).

**Site 2: new helper `record_kick_latency`.** Near `record_tx_completions_with_stamp` (`tx.rs:94`):

```rust
#[inline]
pub(super) fn record_kick_latency(
    owner: &OwnerProfileOwnerWrites,
    delta_ns: u64,
) {
    let bucket = bucket_index_for_ns(delta_ns);
    owner.tx_kick_latency_hist[bucket].fetch_add(1, Ordering::Relaxed);
    owner.tx_kick_latency_count.fetch_add(1, Ordering::Relaxed);
    owner.tx_kick_latency_sum_ns.fetch_add(delta_ns, Ordering::Relaxed);
}
```

`pub(super) fn` visibility matches `record_tx_completions_with_stamp`. `#[inline]` because called once per TX kick on the hot path. Unit-testable without a full `BindingWorker` fixture.

**Why NOT reuse `now_ns`.** `now_ns` on `maybe_wake_tx`'s signature is caller-cached — stale up to `IDLE_SPIN_ITERS * spin_cost` per #812 §3.1 R1. Kick-latency MUST use two fresh `monotonic_nanos()` calls bracketing sendto, identical reasoning to #812's submit-stamp decision.

### 3.4 `userspace-dp/src/afxdp/worker.rs` — snapshot projection

At `worker.rs:4240-4247`, `BindingLiveSnapshot` carries three `tx_submit_latency_*` fields. Add four parallel:

```rust
pub(crate) tx_kick_latency_hist: [u64; TX_SUBMIT_LAT_BUCKETS],
pub(crate) tx_kick_latency_count: u64,
pub(crate) tx_kick_latency_sum_ns: u64,
pub(crate) tx_kick_retry_count: u64,
```

### 3.5 `userspace-dp/src/afxdp/umem.rs` — `BindingLiveState::snapshot()`

At `umem.rs:1931-1941`, `snapshot()` copies `tx_submit_latency_*` out of `owner_profile_owner`. Add four parallel loads using `Self::snapshot_hist` for the histogram and `.load(Ordering::Relaxed)` for scalars. Ordering per single-writer / bounded-read-skew (#812 §3.6 R2).

### 3.6 `userspace-dp/src/protocol.rs` — wire format additions

**`BindingStatus` (~line 1338).** Add:

```rust
#[serde(rename = "tx_kick_latency_hist", default)]
pub tx_kick_latency_hist: Vec<u64>,
#[serde(rename = "tx_kick_latency_count", default)]
pub tx_kick_latency_count: u64,
#[serde(rename = "tx_kick_latency_sum_ns", default)]
pub tx_kick_latency_sum_ns: u64,
#[serde(rename = "tx_kick_retry_count", default)]
pub tx_kick_retry_count: u64,
```

`default` on each keeps the wire format additive.

**`BindingCountersSnapshot` (~line 1425).** Same four fields, same `#[serde(rename, default)]`. The `'static + Send` const-assert at `:1446` covers the struct as a whole — `Vec<u64>` + `u64` fields satisfy it mechanically.

**`From<&BindingStatus>` impl (~line 1476).** `.clone()` for the histogram, by-value copies for scalars:

```rust
tx_kick_latency_hist: b.tx_kick_latency_hist.clone(),
tx_kick_latency_count: b.tx_kick_latency_count,
tx_kick_latency_sum_ns: b.tx_kick_latency_sum_ns,
tx_kick_retry_count: b.tx_kick_retry_count,
```

### 3.7 `userspace-dp/src/afxdp/coordinator.rs` — per-binding snapshot copy

**Site 1 (lines 1428-1440, copy path).** After existing `tx_submit_latency_*` block:

```rust
binding.tx_kick_latency_hist.resize(snap.tx_kick_latency_hist.len(), 0);
binding.tx_kick_latency_hist.copy_from_slice(&snap.tx_kick_latency_hist);
binding.tx_kick_latency_count = snap.tx_kick_latency_count;
binding.tx_kick_latency_sum_ns = snap.tx_kick_latency_sum_ns;
binding.tx_kick_retry_count = snap.tx_kick_retry_count;
```

**Site 2 (line 1530, clear path).** After existing zero-out:

```rust
binding.tx_kick_latency_hist.clear();
binding.tx_kick_latency_count = 0;
binding.tx_kick_latency_sum_ns = 0;
binding.tx_kick_retry_count = 0;
```

### 3.8 `pkg/dataplane/userspace/protocol.go` — Go mirror

At `:682-684` (`BindingStatus`) and `:726-728` (`BindingCountersSnapshot`), add immediately after existing `TxSubmitLatencySumNs`:

```go
TxKickLatencyHist  []uint64 `json:"tx_kick_latency_hist,omitempty"`
TxKickLatencyCount uint64   `json:"tx_kick_latency_count,omitempty"`
TxKickLatencySumNs uint64   `json:"tx_kick_latency_sum_ns,omitempty"`
TxKickRetryCount   uint64   `json:"tx_kick_retry_count,omitempty"`
```

`omitempty` on all four. JSON keys match Rust's `serde(rename)` verbatim.

### 3.9 Tests

Rust unit pins in `umem.rs` `#[cfg(test)]` (where `OwnerProfileOwnerWrites` lives and `record_tx_completions_with_stamp` tests at `:800-830` are the precedent). **Construct via `BindingLiveState::new()` + `live.owner_profile_owner`** — `OwnerProfileOwnerWrites::new()` is private (LOW-10 R1 fix). This matches the existing working fixture pattern in `umem.rs:923-930, 1496`.

1. **Bucket-mapping pin.** Call `record_kick_latency(&live.owner_profile_owner, delta)` with deltas landing in buckets 0, 3, 6, 14, 15 (boundary + saturation). Verify atomic incremented by 1; count/sum_ns match.
2. **Accumulation pin.** Call N times with fixed delta; assert `count == N`, `sum_ns == N * delta`, `sum(hist buckets) == N`.
3. **Sentinel pin.** Two sub-cases:
   - 3a: `kick_end == kick_start` (delta=0) → records bucket 0.
   - 3b: `kick_end < kick_start` (wrapping_sub produces large value) → skipped per §3.3 guard. Verify via constructing events at the caller site; if fixture cost for a full `BindingWorker` is prohibitive, degrade to a code-review note with the line-cite.
4. **EAGAIN retry-counter pin (HIGH-9 R1 new test).** Construct a minimal fixture that drives `maybe_wake_tx`'s error-classification branch with `errno = EAGAIN` mocked. Verify `tx_kick_retry_count` increments by 1; assert `tx_kick_latency_count` ALSO increments (EAGAIN path records the latency before the error). If full `maybe_wake_tx` fixture is too expensive, the fallback is an integration-level pin: during the deploy smoke (§9 gate 8), assert the field is present AND non-zero after a 60s iperf3 run on p5201-fwd-with-cos (a shaped cell where ring backpressure is guaranteed to produce some EAGAIN returns).
5. **Wire-format round-trip** in `protocol.rs` `#[cfg(test)]`. Construct `BindingStatus` with non-zero four-field values; serde serialize → deserialize → equality. Construct pre-#825 JSON (no new keys); deserialize produces zero/empty. Construct `BindingCountersSnapshot` via `From<&BindingStatus>`; assert propagation.
6. **Cross-thread `'static + Send` skew harness (MED-11 R1 new test, mirrors #812 §620-643).** Spawn a writer thread that calls `record_kick_latency` in a loop; spawn a reader thread that calls `BindingLiveState::snapshot()` in a loop. Assert (a) no data race (cargo test with `-Z sanitizer=thread` on nightly, OR Miri check as a weaker approximation), and (b) K_skew bound holds: `|sum(snap.tx_kick_latency_hist) - snap.tx_kick_latency_count| ≤ K_skew_bound` per §4. This is the "hard precedent" #812 set that #825 must match.
7. **`'static + Send` compile-time assertion.** No test code — the existing const-block at `protocol.rs:1446` catches regressions as build errors.

Go unit: extend `pkg/dataplane/userspace/protocol_test.go` if it exists; otherwise add one round-trip test. Mirror existing `tx_submit_latency_*` test pattern (spot-check at implementation time).

### 3.10 Bench

Criterion bench at `userspace-dp/benches/tx_kick_latency.rs` mirroring `docs/pr/812-tx-latency-histogram/plan.md` §6.1 precedent. Scope: measure per-call overhead of `record_kick_latency` + two `monotonic_nanos()` calls vs a baseline that only calls sendto.

**HIGH-9 R1 bench wiring.** Criterion benches require a `[[bench]]` entry in `userspace-dp/Cargo.toml`. The implementor MUST add:
```toml
[[bench]]
name = "tx_kick_latency"
harness = false
```
plus a `criterion = "..."` dev-dependency if not already present. Without this the `cargo bench` invocation would silently skip the benchmark. #812's bench wiring at `userspace-dp/Cargo.toml:<existing bench>` is the reference.

**Gate (§9 below):** p99 per-call overhead ≤ **60 ns** on `loss:xpf-userspace-fw0` (VDSO-confirmed reference). Number derived in §7 to match the 45 ns per-call cost plus bench-jitter headroom, not the earlier 25 ns that gated only the atomic fast-path.

## 4. Data contract

Field names fixed by #819 §5.3 verbatim:

- `tx_kick_latency_hist` (Vec<u64>, 16 log2 buckets, layout = `tx_submit_latency_hist` = `drain_latency_hist`)
- `tx_kick_latency_count` (u64)
- `tx_kick_latency_sum_ns` (u64)
- `tx_kick_retry_count` (u64)

JSON wire-key convention: `snake_case`, matches `tx_submit_latency_*`. All four carry `omitempty` on Go, `#[serde(default)]` on Rust — additive, backward-compatible.

Doc-comment invariant on `tx_kick_latency_hist`: `sum(tx_kick_latency_hist) ≈ tx_kick_latency_count` with bounded skew `|sum - count| ≤ K_skew`. **K_skew carries over from #812 §3.6 R2 as a conservative upper bound, not a re-derivation** (LOW-7 R1 clarification + R2 refinement): #812's K_skew=3 was derived from 3 Mpps completion rate at 1 µs read window. Kicks occur strictly less frequently than submits (each kick attempts to drain one or more submits), but the precise kick-per-packet rate is unmeasured pre-instrumentation and is workload-dependent (#823 showed worker on-CPU ~100%; wake cadence is gated by `TX_WAKE_MIN_INTERVAL_NS` at `tx.rs:6432-6434` but the effective rate under load is not directly known). Post-instrumentation, `tx_kick_latency_count` becomes the exact measure. Carrying #812's K_skew=3 bound is therefore a **deliberate conservative choice**: the bound that holds for the hotter submit-stamp path trivially holds for the strictly-rarer kick path, regardless of the unmeasured precise rate.

## 5. Retry counter semantics

**`tx_kick_retry_count` counts outer `sendto` returns where `errno ∈ {EAGAIN, EWOULDBLOCK}`.**

Rationale:

- **Semantic match to T1.** T1 (`Δ(retry_counter)/block ≥ 1000`) is a ring-pushback rate. Ring pushed back iff sendto returned EAGAIN; counting outer returns gives 1:1 "kicks the kernel refused."
- **Implementation simplicity.** Existing error branch at `tx.rs:6452` is a single if-branch on `errno`; the fetch_add slots in as one extra instruction. Inner retry-loop iterations would require introducing a loop (there isn't one) or attributing to scheduler retry (undefined).
- **Rejected: count all sendto returns.** Already approximated by `binding.dbg_sendto_calls`; a retry counter equal to total kicks tells you nothing about ring pushback.

Pre-registers the semantic before capture; T1 OUT threshold (`< 100/block`) is sized for EAGAIN-only.

## 6. Timestamp source

**`monotonic_nanos()` from `userspace-dp/src/afxdp/neighbor.rs:3-15`** — same reader `tx_submit_latency_hist` uses.

- VDSO fast-path proven on the deploy VM per `docs/pr/812-tx-latency-histogram/plan.md` §3.4a (`evidence/vdso_probe2.c`). ~15 ns per call. No syscall entry.
- **Consistency with submit-latency histogram.** P3 analysis aligns per-block `retry_count_delta` + `kick_latency_mean_ns` against `T_D1,b`. Same clock = no clock-skew confounder.
- Rejected: `rdtsc`. Requires per-CPU calibration, TSC-invariance detection, CPU-migration handling. Large surface for no win. #812 §3.4a carries the full argument.

Failure: `monotonic_nanos()` returns 0 on syscall failure. Sentinel check in caller skips record when either timestamp is 0.

## 7. Overhead budget

Budget source: `docs/pr/812-tx-latency-histogram/plan.md` §8 — **5% steady-state hard stop, 10% small-batch soft gate.** #825 fits within, leaving headroom for the existing submit-stamp.

Per-kick cost, derived:

| Op | Cost (ns, VDSO confirmed) |
|---|---|
| `monotonic_nanos()` × 2 (bracketing sendto) | ~15 + ~15 = 30 ns |
| `wrapping_sub` + sentinel check | < 1 ns |
| `bucket_index_for_ns` (`umem.rs:198-202`) | < 2 ns |
| `hist[bucket].fetch_add` (uncontended) | 3-5 ns |
| `count.fetch_add` | 3-5 ns |
| `sum_ns.fetch_add` | 3-5 ns |
| **Per kick (non-EAGAIN)** | **~45 ns** |
| EAGAIN: +`retry_count.fetch_add` | +3-5 ns → **~50 ns** |

**Amortization (HIGH-8 R1 honest restatement).** `maybe_wake_tx` is called from multiple sites; amortization rate is workload-dependent. The `TX_WAKE_MIN_INTERVAL_NS` gate at `tx.rs:6432-6434` rate-limits wakes but NOT on a "1 per 1000 packets" basis — the prior claim was unsupported and is withdrawn. Instead:

- **Per-call cost:** ~45 ns (derivation above).
- **Call rate:** varies. Observed #823 p5201-fwd-with-cos captures had worker on-CPU ~100% throughout; kick rate per packet is not directly observable pre-instrumentation. Post-instrumentation, `tx_kick_latency_count` IS the call rate indicator — we'll have exact data after the P3 capture.
- **Worst case:** 1 kick per packet (extreme partial-batch / ring-full-every-insert). At 25 Gbps / 1500 B = 2.08 Mpps = 481 ns/pkt budget, 45 ns / 481 ns = **9.4%** — lands at #812's soft-gate ceiling (same regime; #812 §11.1 notes this is C-verdict territory where the system is already degraded).
- **Expected case:** `TX_WAKE_MIN_INTERVAL_NS` throttles to substantially less than every-packet; a 10× reduction → < 1%.

**Concrete bench gate (§9 gate 4 — HIGH-8 R1 reconciled):** Criterion microbench p99 per-call ≤ **60 ns** on `xpf-userspace-fw0` (VDSO-confirmed). 60 ns accommodates the 45 ns derivation plus ~15 ns headroom for bench jitter and cacheline-contention slack. The earlier 25 ns gate was an error (gated only the atomic fast-path, not the two VDSO `monotonic_nanos()` calls which are the dominant 30 ns) and is withdrawn. Regressions above 60 ns indicate VDSO disable (§10 stop 1) or cacheline contention (§10 stop 3). The 5% steady-state hard-stop from #812 §8 still applies in aggregate on the forwarding path; this microbench gate guards the per-call overhead within that aggregate budget.

## 8. Execution matrix

| Step | File | Change | Validated by |
|---|---|---|---|
| 1 | `umem.rs:223-254` | Add 4 fields to `OwnerProfileOwnerWrites`; init in `::new`. | `cargo build`; size assert holds OR is deliberately raised. |
| 2 | `tx.rs` top (near line 94) | Add `record_kick_latency` helper. | §3.9 tests 1, 2. |
| 3 | `tx.rs:6429` (`maybe_wake_tx`) | Stamp bracketing sendto; call helper; fetch_add on EAGAIN. | End-to-end smoke (§9 gate 5). |
| 4 | `worker.rs:4240-4247` (`BindingLiveSnapshot`) | Add 4 fields. | `cargo build`. |
| 5 | `umem.rs:1931-1941` (`snapshot()`) | Add 4 load lines. | §3.9 test 1 snapshot-read. |
| 6 | `protocol.rs:1333-1338, 1420-1425, 1474-1476` | 4 fields on both structs + `From` impl. | §3.9 test 4; `'static + Send` assert. |
| 7 | `coordinator.rs:1428-1440, :1530` | Copy + clear paths. | `cargo build`. |
| 8 | `pkg/dataplane/userspace/protocol.go:682,697` | Go mirror. | `go build`; round-trip test. |
| 9 | `userspace-dp/benches/tx_kick_latency.rs` | New bench stub (+ `[[bench]]` entry in `userspace-dp/Cargo.toml` per §3.10). | p99 ≤ 60 ns. |

Order 1→2→3→4→5→6→7 driven by Rust type-checking. Step 8 (Go) must land atomically with step 6 so the wire format is consistent in a single merge. Step 9 prepared in parallel, validated last.

## 9. Validation gates

Ordered; each must pass before advancing.

1. **Rust builds green.** `cargo build -p xpf-userspace-dp` + `cargo build --release` + `cargo clippy` clean.
2. **Rust unit tests pass.** All new pins in §3.9 + existing suite green (`cargo test -p xpf-userspace-dp`).
3. **`'static + Send` compile-time assertion holds.** Build failure = regression, blocks merge.
4. **Bench overhead.** Criterion p99 per-call ≤ **60 ns** on `xpf-userspace-fw0` (HIGH-8 R1 reconciled). Document VM CPU in the run log.
5. **Go builds + tests green.** `go build ./...` + `go test ./pkg/dataplane/userspace/...`.
6. **`make generate` stable.** No generated-code drift on Go side.
7. **Deploy to `loss:xpf-userspace-fw0`.** Restart daemon; `iperf3 -P 4 -t 5 -p 5203` shows 0 retransmits.
8. **Status snapshot shape.** `... | jq -r '.status.per_binding[0] | keys[]' | grep -q tx_kick_latency_hist` non-empty. Four new field names present on every `per_binding[]` entry.
9. **Regression: `tx_submit_latency_hist` unchanged in form and behavior.** Snapshot shows `tx_submit_latency_*` fields with same name/type/bucket-count as pre-#825. No change to `bucket_index_for_ns` or `TX_SUBMIT_LAT_BUCKETS`.
10. **#819 §9.3 P3 G8 smoke.** `grep -q tx_kick_latency_hist` after daemon PR lands. Issue #825 cannot close until this passes.

## 10. Hard stops

Terminate immediately on:

1. **Bench p99 > 60 ns.** Indicates VDSO disabled OR cacheline contention; root-cause before proceeding.
2. **`cargo build --release` fails** on size/align const-asserts AND the implementer cannot document the cap-raise (§3.2) with a named argument.
3. **`'static + Send` assertion fails.** Blocks merge unconditionally.
4. **`iperf3 -P 4 -t 5 -p 5203` retrans > 0** on fw0 after deploy. Forwarding regression; revert.
5. **Wire-format round-trip fails on Go side.** JSON tag mismatch; blocks merge.
6. **`tx_submit_latency_*` fields change form or behavior.** Violates #819 non-negotiable. Revert.

## 11. Rollback

**Single commit `git revert`.**

- Wire format additions carry `#[serde(default)]` / `omitempty` — pre-#825 consumer deserializes zeroed; pre-#825 producer's JSON deserializes with zeroed fields.
- No deploy-time migration. Old and new daemons coexist.
- No config-file schema change.
- Reverting atomically removes instrumentation; worker state carries no persisted residue.

Exit criterion during code-phase: any hard stop (§10) that can't be root-caused within one iteration.

## 12. Non-negotiables

- **Userspace cluster only.** `loss:xpf-userspace-fw0` / `-fw1`. bpfrx forbidden.
- **No per-flow histograms.** #812 deferral stands.
- **No new Prometheus exporter.** JSON-only per #819 §10.
- **No change to `tx_submit_latency_hist`** (field name, bucket count, bucket function, publish cadence).
- **No change to the `'static + Send` compile-time guard.** New fields MUST pass mechanically.
- **No repurposing of `binding.dbg_sendto_eagain`.** New counter is additive; the worker-local debug counter stays.
- **#823 M3 OUT verdict is not up for re-litigation** (#819 RT-3).

## 13. Out of scope

- Running P3 captures — follow-up issue per Issue A → #823 pattern.
- `test/incus/step1-histogram-classify.py` extension — defer unless trivial (simple analog of existing block-delta).
- Prometheus export — #812 §12 item 1 deferral stands.
- Per-CPU histogram stratification — #812 §12 item 2.
- `rdtsc` overhead re-validation — named alternative in §6.
- Rationalization of `binding.dbg_sendto_eagain` vs new counter — separate cleanup PR after P3 verdict.

## 14. Deferrals

- **P3 capture runs.** Separate issue after #825 lands; two-cell capture (p5201-fwd-with-cos, p5202-fwd-with-cos), T1 threshold analysis (#819 §4.1), IN/OUT/INCONCLUSIVE verdict. NOT in this PR.
- **Classify.py extension.** Defer unless trivial single-function analog.
- **Prometheus, per-CPU strat, rdtsc, dbg_sendto_eagain cleanup.** All deferred per §13.

## 15. Evidence layout

```
docs/pr/825-p3-tx-kick-latency/
    plan.md                      # this document
    codex-plan-review.md         # Codex plan-review rounds
    codex-code-review.md         # Codex code-review rounds (code phase)
    <second-angle>-review.md     # Rust or systems angle (code phase)
    # NO evidence/ directory — code + wire-format PR. P3 capture
    # follow-up gets its own evidence dir.
```

## 16. Replan triggers

- **RT-1 (wire format incompatibility).** Go round-trip reveals JSON-tag mismatch not reconcilable by Rust rename — field-name contract broken; return to #819.
- **RT-2 (overhead out of budget).** p99 > 60 ns after investigation; candidates `rdtsc`, stamp-sampling, or dropping `sum_ns` (§13).
- **RT-3 (cacheline assert trips, cap-raise indefensible).** Raising `OwnerProfileOwnerWrites` size cap forces realign past acceptable alignment — requires separate owner-writes struct split; halts #825.

*End of Architect Round 1. Awaiting Codex hostile plan review.*
