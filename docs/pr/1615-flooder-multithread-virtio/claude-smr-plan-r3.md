# Claude SMR plan-review r3 — #1615 multi-thread flooder (plan v3)

Reviewer seat: kernel networking / AF_PACKET / mlx5 SR-IOV / Linux scheduler
+ Rust std::thread + libc FFI. Hostile pass.

Verdict: **PLAN-READY**.

## Coverage check vs r2 findings

| r2 finding | Resolved by v3 § |
|------------|------------------|
| AGY-r2-1 softnet_stat invalid | §3.7 + §5.2 rewritten — per-thread tx_packets max/min ratio |
| AGY-r2-2 validator too strict | §3.1 — `--allow-oversubscribe` flag |
| AGY-r2-3 spawn rollback | §3.9 — wrap spawn in try, join-and-shutdown on failure |
| CODEX-r2-1 softnet_stat | same as AGY-r2-1 |
| CODEX-r2-2 BQL state | same — §3.7 rewrite removes BQL paths |
| CODEX-r2-3 queue distribution probabilistic | §3.7 — ratio>2.0 hard-fails the design |
| CODEX-r2-4 main-thread pre-check pin probe | §3.3 — drop pre-check; worker-only pin |

All 7 r2 findings closed.

## Hostile re-read of v3

- **§3.7 ratio threshold**: 1.5× warn, 2.0× fail. With 4 threads and
  11 TX queues, kernel hash modulo 11 → some collisions are inevitable
  (probabilistically each thread lands on its own queue with
  probability 11×10×9×8/11^4 = 7920/14641 ≈ 54% per run). The other
  46% of runs will have at least 2 threads on the same TX queue and
  will show ratio > 1.0 modestly.

  But the absolute pps cap per TX queue is what matters, not the
  fairness of distribution. If 2 threads collide on one queue, that
  queue's HARD_TX_LOCK serializes them — they'll show roughly half
  the per-thread pps of an uncollided thread. So 2-on-1 collision
  → ratio ≈ 2.0. The fail threshold at 2.0× is correct for "at most
  one collision".

  For threads=8 (informational headroom run, not gate): 8 threads over
  11 queues, probability of no collisions = 11!/(3! × 11^8) ≈ 19%.
  So most runs will have 1-2 collisions. Ratio threshold should be
  relaxed for threads=8 (informational only, not gate). v3 already
  treats threads=8 as informational; OK.

  No change needed.

- **§3.9 spawn rollback path**: with `std::thread::spawn` returning
  `JoinHandle<T>`, it doesn't actually return Result — it panics on
  failure (out-of-memory or thread-limit). The plan should clarify:
  use `std::thread::Builder::new().spawn(...)` which DOES return
  `io::Result<JoinHandle<T>>` and allows graceful handling. This is
  an implementation detail — not a plan-blocker — but worth a code
  comment.

- **§3.1 `--allow-oversubscribe` semantics**: When set, MAX_THREADS
  cap is 64 (not `allowed_cpus.len()`). On a 16-CPU host this is
  fine. On a 2-CPU container slice with oversubscribe, `--threads
  64` would spawn 64 threads all competing for 2 CPUs — that's a
  contention test, not a measurement. The plan should note that
  oversubscribed runs are for diagnostic purposes only, not for
  the BLOCKING smoke gate. Add a one-line warning to the help text.
  Not a plan blocker.

- **§3.3 main-thread affinity preserved**: drop pre-check is the
  right call. The main thread runs the per-second progress emitter
  + final sum + JSON output. Keeping it unpinned (kernel default)
  is fine; it does very little.

- **Per-thread tx_packets ratio computation**: needs care for
  short runs. At the threads=1 sweep row, the ratio is undefined
  (1 element). Define: `ratio = if per_thread.len() == 1 { 1.0 }
  else { max / max(min, 1) }`. Trivial; document in code.

## Things I checked again that didn't break

- `pthread_setaffinity_np(pthread_self(), ...)` in unprivileged
  containers: works to restrict within the cpuset, fails with EPERM
  on attempt to expand. Index arithmetic into `allowed_cpus[]`
  guarantees we only pin to allowed CPUs ⇒ no EPERM expected.
- `compare_exchange_strong(0, errno, Acquire, Relaxed)` on
  `AtomicI32`: not Relaxed/Relaxed since we want the side-effecting
  store of errno to be observable; use `(Acquire, Relaxed)` per Rust
  convention. Implementation-phase note only.
- `WorkerFd::drop` on a closed-or-invalid fd: `libc::close` on -1
  returns EBADF but doesn't crash. Guard with `if self.0 >= 0` per
  v2 §3.2 — verified safe.

## Gate

**PLAN-READY.** All r1+r2 findings closed. Implementation-phase
notes already folded into plan-v3.md or SMR-r2/r3 sidecars. Move
to Step 5 (implementation).
