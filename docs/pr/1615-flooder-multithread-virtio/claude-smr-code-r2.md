# Claude SMR code-review r2 — PR #1617 (#1615 impl, post-r1-fix)

Verdict: **MERGE-READY**.

## R1 findings — verification

| r1 finding | r2 status | Code location |
|------------|-----------|---------------|
| CODEX-code-r1-1 ≡ AGY-impl-r1-1 dangling stack pointer | **FIXED** | wire_msgs moved INSIDE worker_loop after pin (main.rs:1056-1062); spawn closure no longer calls it (main.rs:1295-1300) |
| CODEX-code-r1-2 warmup accounting | **FIXED** | per-worker `warmup_baseline: Arc<AtomicU64>` published at warmup-end (main.rs:1080-1085); subtracted in run_multi_threaded summary path (main.rs:1351-1365) |
| CODEX-code-r1-3 shared deadline | **FIXED** | main computes `start_at, warmup_end, total_deadline` once (main.rs:1228-1231); WorkerCtx carries them; worker honors total_deadline (main.rs:1067); main stores shutdown_flag at deadline (main.rs:1330) |
| AGY-impl-r1-2 unsafe Send justification | **FIXED** | safety comment now distinguishes heap-backed (iovec) from inline (dst_sll) pointer classes; documents the wire_msgs-at-final-location contract (main.rs:582-604) |

All 4 r1 fatal/major findings closed.

## Re-smoke verification

After fix:
- threads=4 aggregate 2.94 M (warmup correctly excluded; was 3.58 M
  inflated)
- per_thread_ratio 1.615 (warning band, below 2.0 hard-fail)
- err_eagain = 0
- BLOCKING gate (≥2.5 Mpps + ratio ≤2.0): **PASS**

The 2.94 M number is now the accurate steady-state. The previous
3.58 M reading included warmup-phase work in the duration-divisor
denominator, inflating the apparent throughput.

## Hostile re-read of r1 fixes

- **Dangling-pointer fix**: wire_msgs() is now called inside
  worker_loop after pin. `worker_loop` takes `mut ctx: WorkerCtx`
  by value; after entering, the TxRing is at its final stack
  location and stays there for the duration of the function. No
  further move occurs. wire_msgs() captures `&self.dst_sll as ...`
  — `self` is `&mut ctx.ring`, so dst_sll is at the address of
  `ctx.ring.dst_sll` on worker_loop's stack frame. Pointer remains
  valid for the entire worker_loop body. **OK.**

- **Warmup baseline race**: worker reads `tx_packets.load(Relaxed)`
  and stores `baseline` in its own `warmup_baseline: AtomicU64`.
  Main reads warmup_baseline in `run_multi_threaded` AFTER all
  workers have joined — so there's no concurrent access. No race.
  **OK.**

- **`warmup_baseline_published` boolean per worker**: ensures the
  baseline is written exactly once per worker even if the worker
  loops many times after warmup_end. Stored as a stack bool, no
  shared state. **OK.**

- **shutdown_flag store at total_deadline**: main does
  `shutdown_flag.store(true, Relaxed)` after the main while-loop
  exits (regardless of whether it exited via deadline OR fatal-error
  break). Workers see the flag on next iteration and exit. Join is
  bounded by `max(worker_remaining_batch_time)` ≈ a few hundred us.
  **OK.**

- **`start_at = Instant::now() + Duration::from_millis(50)`**: a
  50 ms head-start gives all worker threads time to spawn and pin
  before the warmup window opens. With threads=64 (hard cap), spawn
  latency could matter. Currently workers also check `now >=
  total_deadline` and `now >= warmup_end`; they don't gate-wait on
  `start_at`. So the 50 ms is just slack that delays warmup_end +
  total_deadline by 50 ms. **OK** but worth noting: if a tight test
  wants exact timing, the 50 ms is a known startup buffer.

- **Per-worker stat collection after join**: `stats_slots.iter()`
  → snapshot. The `warmup_baseline` is read separately from a
  parallel Vec. Both ordering Relaxed. No race after join. **OK.**

- **Worker exits early from shutdown_flag check before publishing
  warmup_baseline**: if a worker is killed during warmup, its
  `warmup_baseline` stays at 0 (initial value). Then summary
  subtracts 0 from its tx_packets — which is the entire warmup
  phase. The reported tx_packets is therefore over-counted for
  that worker. But this is the failure path; we also surface the
  first_fatal error message, so the summary is not load-bearing in
  that case. Acceptable.

## Outstanding minor notes

None. All 4 r1 findings cleanly addressed.

## Test gap re smoke gate margin

The aggregate dropped from 3.58 M (inflated) to 2.94 M (accurate) —
margin over the 2.5 M gate is 1.18× instead of 1.43×. Still passes
but tighter. The threads=8 row would give better headroom (4.38 M
inflated → ~3.5 M accurate, ~1.4× margin). Acceptable.

## Gate

**MERGE-READY.** All 4 r1 findings fixed; re-smoke passes;
invariants preserved.
