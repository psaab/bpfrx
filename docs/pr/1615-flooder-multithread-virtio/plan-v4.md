# Plan v4 — #1615 cold-path-flooder multi-thread (round-3 fixes)

Supersedes plan-v3.md (small patch). Closes #1615.

R3 reviewer summary:
- Claude-SMR r3: PLAN-READY (3 impl notes already folded)
- AGY r3: NEEDS-MINOR (AGY-r3-1, -r3-2, -r3-3)
- Codex r3: NEEDS-MAJOR (CODEX-r3-1..6) — primarily doc-consistency
  (§7 still has stale text from v2; spawn API needs to be Builder)

## R3 overlap

- CODEX-r3-5 ≡ AGY-r3-1: `std::thread::spawn` panics, must use
  `std::thread::Builder::new().spawn(...)`. Same fix.
- CODEX-r3-3: §7 mitigation list still mentions pre-check probe
  (v3 §3.3 said drop it; need to scrub §7 too).
- CODEX-r3-4: §7 still says "softnet_stat per-CPU" (v3 §3.7 dropped
  it; need to scrub §7 too).
- CODEX-r3-1: per-thread tx_packets ratio doesn't strictly prove
  distinct queues. Accepted as documented limitation.
- CODEX-r3-2: §3.7 says "fail at >1.5 OR fail at >2.0" ambiguously.
  Pick one.
- CODEX-r3-6: unit test must cover both default-reject and
  oversubscribe-accept paths for `--threads > allowed.len()`.
- AGY-r3-2: main thread progress loop must read shutdown_flag every
  tick to short-circuit on worker failure.
- AGY-r3-3: ratio for N=1 should be 1.0 (defined).

All addressable.

## Section patches against plan-v3.md (applied)

### §3.7 — ratio gate, single threshold (CODEX-r3-2)

Replace the ambiguous "fail at >1.5 OR fail at >2.0 with warning"
language with **a single hard threshold and a single warning band**:

> Hard fail criteria for the BLOCKING gate (threads=4):
> - aggregate `avg_pps` < 2_500_000
> - per-thread `tx_packets` max/min ratio > 2.0
>
> Warning band (informational, does NOT fail the gate):
> - per-thread `tx_packets` max/min ratio in (1.5, 2.0]
>
> For N=1, ratio is defined as 1.0 (single-element trivially
> uniform; see AGY-r3-3). For N≥2, ratio = max / max(min, 1).

Single threshold = unambiguous gate decision.

### §3.7 — TX-queue distribution caveat (CODEX-r3-1)

Add this paragraph after the ratio gate:

> **Caveat (CODEX-r3-1)**: per-thread `tx_packets` parity is a
> *necessary* but not *sufficient* condition for distinct mlx5 TX
> queue distribution. If all N threads collide on a single
> TX queue under HARD_TX_LOCK, each thread's blocking-wait time
> rises uniformly and per-thread tx_packets will still be near-equal
> — but aggregate avg_pps will collapse to a single-queue ceiling.
> The aggregate avg_pps ≥ 2.5 Mpps gate catches this collapse;
> the ratio check is a secondary cross-check that catches the
> *opposite* failure mode (one thread starving others). The two
> gates together cover both directions.

This is correct: a 4-on-1 collision would show tx_packets ratio ≈ 1
but aggregate pps ≈ single-queue cap (~870 K). The pps gate catches it.

### §3.9 — `std::thread::Builder::new().spawn(...)` (CODEX-r3-5 / AGY-r3-1)

Replace "fallible `std::thread::spawn`" with:

> Use `std::thread::Builder::new().name(format!("flooder-{}", id))
> .spawn(closure)` which returns `io::Result<JoinHandle<T>>`. On
> `Err`, main thread sets `shutdown_flag.store(true, Relaxed)`,
> joins all already-spawned handles (they observe the flag and
> exit), then returns from main with a non-zero exit code and a
> clear message identifying which thread index failed to spawn.
>
> The free `std::thread::spawn` panics on OS thread-creation
> failure, which would bypass the rollback. Builder is mandatory.

### §3.8 — main thread shutdown_flag check (AGY-r3-2)

Add to the main thread progress loop description:

> The main thread's per-second progress loop checks
> `shutdown_flag.load(Relaxed)` at the top of each iteration. On
> set, the loop breaks immediately, transitions to the join phase,
> and emits the final summary JSON before exiting non-zero. This
> prevents the main thread from emitting empty 1-second progress
> lines after a worker has signaled fatal failure.

### §5.1 — additional unit test (CODEX-r3-6)

Add test:
> `threads_arg_oversubscribe_flag_allows_excess`: with
> `allowed_cpus = [0, 1]` mock and `--threads 4`, assert validator
> *rejects* unless `--allow-oversubscribe` is set. With the flag
> set, validator *accepts* and the mapping wraps via modulo.

### §7 — scrub stale references (CODEX-r3-3, CODEX-r3-4)

Replace the §7 lines that still read:

> "Mitigation: validator pre-checks `pthread_setaffinity_np` works
>  on CPU 0 of `allowed_cpus[0]` from the main thread..."

with:

> "Mitigation: worker thread pin failure is fatal (sets
>  shutdown_flag + first-error slot; main exits non-zero on join).
>  No pre-check from main thread is performed (preserves main
>  affinity for stderr emitter)."

Replace:

> "Mitigation: §5.2 captures `/proc/net/softnet_stat` per-CPU;
>  if one CPU sees > 1.5× others, that's evidence and we PLAN-KILL."

with:

> "Mitigation: §5.2 captures per-thread `tx_packets` from the final
>  summary JSON; ratio max/min > 2.0 hard-fails the gate. Combined
>  with aggregate avg_pps ≥ 2.5 Mpps, this covers both queue-
>  collision and per-thread-starvation failure modes."

## All other sections unchanged

§1, §2, §3.1, §3.2, §3.3, §3.4, §3.5, §3.6, §3.10, §4, §6, §8, §9,
§10, §11 from plan-v3.md (which inherits from plan-v2.md) remain in
force unchanged. §5.2 and §3.7 are updated by this v4 patch.

## R4 deliverable

PLAN-READY targeted from all four reviewer seats. No more rounds
expected; impl-phase notes already folded.

## R3 reviewer task IDs

- Codex r3: task-mpoyqsg3-kz70ue (NEEDS-MAJOR)
- AGY r3: adversarial-review-mpoyqyps-lt2o4w (NEEDS-MINOR)
- Claude SMR r3: claude-smr-plan-r3.md (PLAN-READY)
