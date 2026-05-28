# Plan v3 — #1615 cold-path-flooder multi-thread (round-2 fixes)

Supersedes plan-v2.md. Closes #1615.

R2 reviewer summary:
- Claude-SMR r2: PLAN-READY (3 minor follow-ups for impl phase)
- AGY r2: NEEDS-MINOR (AGY-r2-1, AGY-r2-2, AGY-r2-3)
- Codex r2: NEEDS-MAJOR (CODEX-r2-1, -2, -3, -4)

R2 overlap:
- AGY-r2-1 ≡ CODEX-r2-1 + CODEX-r2-2 + SMR-r2-follow-up-1: replace
  `/proc/net/softnet_stat` and BQL-state in §3.7 + §5.2 with per-thread
  `tx_packets` max/min ratio check (≤1.5×). Same fix.
- CODEX-r2-3: TX queue distribution being probabilistic — same fix as above.
- CODEX-r2-4: pre-check `pthread_setaffinity_np` mutates main affinity —
  drop the pre-check entirely; worker pin failure is already fatal.
- AGY-r2-2: hard reject `N > allowed_cpus.len()` blocks oversubscribe
  testing — demote to warning with `--allow-oversubscribe` override.
- AGY-r2-3: rollback on partial thread spawn failure — wrap spawn loop
  with shutdown_flag + join-all-successful-spawns recovery.

This v3 patch is small. Only sections §3.1, §3.3, §3.7, §3.9, §5.2 change.
All other sections in plan-v2.md remain in force unchanged.

## Section diffs (against plan-v2.md)

### §3.1 — `--threads N` flag (revised)

Add CLI flag `--allow-oversubscribe` (bool, default `false`).

Validator behavior:
- If `--threads N` where `N > allowed_cpus.len()`:
  - If `--allow-oversubscribe` is set: emit a warning, proceed.
  - Otherwise: hard reject with a message pointing at the flag.
- `MAX_THREADS` cap stays at `min(64, allowed_cpus.len())` only when
  `--allow-oversubscribe` is not set. With the flag, cap is 64.

Rationale (AGY-r2-2): in a 2-CPU container slice the operator may
explicitly want 4 threads to test lock contention. Default-safe but
not artificially blocked.

### §3.3 — CPU pinning (revised)

Drop the main-thread pre-check from §3.3 (CODEX-r2-4). Pin happens
exclusively inside the worker closure. If pin fails on the worker,
worker sets shutdown_flag + records first-error and exits; main
thread sees the failure on join and exits non-zero.

This preserves main-thread affinity unchanged for the entire run
(important because main thread is the sole stderr progress emitter
per §3.8 — moving it across CPUs would be a confounding variable).

### §3.7 — TX queue distribution validation (rewritten)

The original §3.7 fallback to `/proc/net/softnet_stat` and BQL state
is technically invalid (AGY-r2-1, CODEX-r2-1, CODEX-r2-2):
- `softnet_stat` counts RX softirqs + softirq-driven TX completions,
  not direct-xmit work. PACKET_QDISC_BYPASS direct-xmit runs
  synchronously in the calling thread's context; no TX softirq fires.
- `byte_queue_limits/...` is BQL state, not packet count.

Replaced with: **per-thread tx_packets max/min ratio check from the
PaddedStats atomic snapshots in the final summary JSON**.

Spec:
- The final summary JSON `"per_thread": [...]` contains `tx_packets`,
  `tx_batches`, `err_eagain` per thread.
- The smoke runner computes
  `ratio = max(per_thread[].tx_packets) / max(min(...), 1)`.
- Hard fail if `ratio > 1.5` (or `> 2.0` with a warning gate at 1.5).
- Document threshold rationale: with 4 threads over 11 mlx5 TX queues
  and disjoint 5-tuple per-thread streams, kernel hash distribution
  should keep per-thread tx_packets within 1.5× modulo small RNG/skew.
- If `ratio > 2.0`, that's evidence of queue collision (multiple
  threads' skb-hash modulo 11 colliding on one queue) and the design
  is rejected; v4 needs explicit XPS configuration on the host or
  PACKET_TX_RING (option 3).

CODEX-r2-3 (queue distribution probabilistic, not guaranteed) is
resolved by this check: if the kernel hash happens to collide all
4 threads onto one TX queue, max/min ratio will be 4× and the gate
hard-fails — design rejected. Not a hidden risk; it's now measured.

The smoke runner records the threshold check in the measurements
markdown file and the gate decision is determinate.

### §3.9 — Shutdown plumbing (revised)

Add to the existing shutdown_flag plumbing: **main thread spawn loop
wraps each `std::thread::spawn` in a fallible try block**. If spawn
fails (resource exhaustion, thread count exceeded), main thread
immediately:
1. Sets `shutdown_flag.store(true, Relaxed)`.
2. Joins all already-spawned worker handles (they exit on next
   loop iteration via flag check).
3. Returns from main with a non-zero exit and clear error message
   identifying which thread index failed to spawn.

Resolves AGY-r2-3.

### §5.2 — Smoke gate sweep (revised)

Replace the "/proc/interrupts + /proc/net/softnet_stat snapshots"
checklist item with:

> For each run, capture from the final summary JSON:
> - aggregate `avg_pps`
> - per-thread `tx_packets` array → compute max/min ratio
> - sum `err_eagain`
>
> Pass criteria for the BLOCKING gate (threads=4 row):
> - aggregate `avg_pps` ≥ 2_500_000
> - per-thread max/min ratio ≤ 1.5 (warn at 1.5-2.0; fail at >2.0)
> - sum `err_eagain` < 0.1% of total tx_packets

Optionally (informational, not gating), capture
`/proc/interrupts` filtered to `mlx1` VF MSI-X vectors before+after
to record IRQ CPU placement for the AGY-3 SLUB-locality narrative.
Do not gate on it.

## All other sections unchanged

§1, §2, §3.2, §3.4, §3.5, §3.6, §3.8, §3.10, §4, §6, §7, §8, §9,
§10, §11 from plan-v2.md remain in force unchanged.

## R3 deliverable

PLAN-READY targeted from all four reviewer seats. No more rounds
expected; minor implementation-phase notes from SMR r2 (which were
already on the list) are folded in as comments during coding.

## R2 reviewer task IDs

- Codex r2: task-mpoxxoi2-lcj5po (NEEDS-MAJOR)
- AGY r2: adversarial-review-mpoxxv31-f1ylaj (NEEDS-MINOR)
- Claude SMR r2: claude-smr-plan-r2.md (PLAN-READY)
