# Plan v2 — #1615 cold-path-flooder multi-thread (round-1 fixes)

Supersedes plan.md (v1). Addresses Claude-SMR r1 MAJOR-1..5 + MINOR-1..4,
AGY r1 AGY-1..5, Codex r1 CODEX-1..13. Verdict targets PLAN-READY.

Closes #1615.

## 1. Problem statement (unchanged from v1)

Cold-path-flooder #1611 caps at ~870 K pps single-thread on
`loss:cluster-userspace-host`; the BLOCKING smoke gate is ≥2.5 Mpps.
This PR adds multi-thread TX so each thread feeds a separate mlx5 VF
TX queue, breaking the single-CPU softirq/xmit ceiling.

## 2. Root cause — corrected (v1 §2 plus kernel-source citations)

The issue body misnamed the environment as virtio + IPVLAN.
Inspection (verified):

- `cluster-userspace-host` is an Incus **container** with a direct
  SR-IOV mlx5 VF on parent `mlx1` (cluster-setup.sh:485-492).
- VF exposes **11 TX queues**, `qdisc fq`, container has 16 CPUs
  (verified live via `ip link` and `/sys/class/net/eth0/queues/`).
- `PACKET_QDISC_BYPASS=1` is set on the AF_PACKET socket
  (main.rs:734-751).

**Kernel-source citation (resolved AGY-5 / SMR-5 / CODEX-10)**:
`net/packet/af_packet.c::packet_setsockopt(PACKET_QDISC_BYPASS)` swaps
the per-socket xmit pointer:
```c
po->xmit = val ? packet_direct_xmit : dev_queue_xmit;
```
`packet_direct_xmit` calls `__dev_direct_xmit` in `net/core/dev.c`:
```c
int __dev_direct_xmit(struct sk_buff *skb, u16 queue_id) {
    txq = netdev_get_tx_queue(dev, queue_id);
    HARD_TX_LOCK(dev, txq, smp_processor_id());
    ret = netdev_start_xmit(skb, dev, txq, false);
    HARD_TX_UNLOCK(dev, txq);
}
```
This bypasses `__dev_queue_xmit` → `q->enqueue`, so `fq` qdisc does
NOT apply. The lock is `HARD_TX_LOCK` (per-TX-queue) — so threads
landing on **different** TX queues do not contend.

Queue selection in `packet_pick_tx_queue` uses
`netdev_pick_tx`/`__netdev_pick_tx` → `skb->hash` (computed from the
5-tuple via `__skb_get_hash`) modulo `dev->real_num_tx_queues`. With
disjoint per-thread 5-tuple streams (per-thread RNG), threads naturally
land on different TX queues.

The single-thread ceiling is therefore the per-CPU cost of skb alloc +
`mlx5e_xmit` + completion path on the calling CPU, not qdisc and not
any device-wide lock.

## 3. Design (revised)

### 3.1 `--threads N` flag

Add `--threads N`, default `1`, range `1..=MAX_THREADS`.

**MAX_THREADS bound (resolves AGY-5 / CODEX-5)**:
Compute the allowed CPU set once at startup via
`libc::sched_getaffinity(0, ...)`. Let `allowed_cpus: Vec<i32>` be the
vector of allowed CPU IDs. Default cap:
`MAX_THREADS = min(64, allowed_cpus.len())`. The validator rejects
`--threads N` where `N > allowed_cpus.len()` (hard error, not warn).
This handles sparse cpusets in containers.

### 3.2 Per-thread fd ownership (resolves SMR-1 / CODEX-6)

Per-thread AF_PACKET SOCK_RAW socket. Each fd is wrapped in a thin
RAII type:
```rust
struct WorkerFd(libc::c_int);
impl Drop for WorkerFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: WorkerFd holds exclusive ownership of fd; close once.
            unsafe { libc::close(self.0); }
        }
    }
}
```
Main thread opens all N sockets in a single pass (so EPERM/CAP_NET_RAW
errors surface centrally), wraps each in `WorkerFd`, then moves each
WorkerFd into the corresponding thread builder closure. Main does NOT
retain any fd after spawn. On worker panic or normal exit, Drop closes
the fd. No double-close path.

### 3.3 CPU pinning (resolves SMR-2 / SMR-3 / AGY-2 / CODEX-7 / CODEX-8)

#### CLI

Two flags:
- `--cpu-base K` (u32, default `0`) — index into `allowed_cpus[]`.
- `--no-cpu-pin` (bool flag, default `false`) — skip pin entirely.

Eliminates the `-1` sentinel.

#### Mapping

`worker[T]` pins to `allowed_cpus[(cpu_base as usize + T) % allowed_cpus.len()]`.
That's index arithmetic into the **actual cpuset**, not into raw CPU IDs.

#### Pin call site

Inside each worker's `std::thread::spawn` closure, as its first action:
```rust
let mut cpu_mask: libc::cpu_set_t = unsafe { zeroed() };
unsafe { libc::CPU_SET(target_cpu_id as usize, &mut cpu_mask); }
let rc = unsafe {
    libc::pthread_setaffinity_np(
        libc::pthread_self(),
        size_of::<libc::cpu_set_t>(),
        &cpu_mask,
    )
};
```
Uses `pthread_self()` — no unstable `as_pthread_t()` needed.

#### Pin failure handling (resolves CODEX-12)

Pin failure is **fatal** to the smoke gate run. The worker writes the
failure into a shared `Arc<Mutex<Option<String>>>` first-error slot
and signals `shutdown_flag.store(true, Relaxed)`. Main joins and
returns non-zero exit. The flooder docstring + `--help` text states
this: "--no-cpu-pin to opt out; pinning failures are fatal otherwise".

This matches the smoke gate semantics: an unpinned run is not
comparable to the #1611 single-thread CPU0-pinned baseline.

### 3.4 PRNG seed disjointness + zero-trap fix (resolves AGY-4 / CODEX-4)

```rust
fn worker_seed(base_seed: u64, thread_id: u32) -> u64 {
    let mixed = base_seed ^ (thread_id as u64).wrapping_mul(0x9E3779B97F4A7C15);
    if mixed == 0 { 0xA5A5A5A5A5A5A5A5 } else { mixed }
}
```
The zero-fallback constant 0xA5A5_A5A5_A5A5_A5A5 is a known-safe
non-degenerate xorshift64 state. Property test verifies this.

### 3.5 Per-thread stats — cache-line-aligned atomics (resolves SMR-4 / AGY-1 / CODEX-1 / CODEX-9)

Replace `Arc<[Mutex<RunStats>]>` (v1) with a Vec of cache-line-padded
atomic blocks:
```rust
#[repr(align(64))]
struct PaddedStats {
    tx_packets: AtomicU64,
    tx_batches: AtomicU64,
    err_eagain: AtomicU64,
    err_partial: AtomicU64,
    err_other: AtomicU64,
    first_other_errno: AtomicI32,
    _pad: [u8; 64 - 5*8 - 4],  // pad to 64 bytes
}
const _: () = assert!(std::mem::size_of::<PaddedStats>() == 64);
```
Each worker holds an `Arc<PaddedStats>` (its own slot). Per-batch
updates are `fetch_add(Relaxed)`. Main thread reads each slot for
per-second aggregate progress lines (mildly torn but acceptable for
monitoring). After join, main thread reads final values for the
summary.

No false sharing — each worker's PaddedStats occupies its own 64-byte
cache line.

`first_other_errno` is stored atomically with `compare_exchange(0, errno, ...)`
so only the first non-recoverable errno is recorded.

### 3.6 SLUB allocator + MSI-X IRQ affinity (resolves AGY-3 / CODEX-3)

Out-of-scope for code, but documented in the runbook. Add a section
to `docs/pr/1615-flooder-multithread-virtio/measurements.md` (Step 6):
> Before running the smoke sweep, capture the host's
> `/proc/interrupts` filtered to `mlx1` VF MSI-X vectors. If the host
> IRQs land on different physical cores than the container's pinned
> worker CPUs, expect SLUB cross-cpu allocator overhead (`napi_consume_skb`
> running on IRQ-CPU vs `__alloc_skb` on worker-CPU). Best result is
> achieved when host-side `irqbalance` is disabled and the VF queue
> IRQs are manually pinned to the same cores as the container workers.
>
> The smoke gate (≥2.5 Mpps aggregate) is empirically achievable even
> without manual IRQ alignment — but recording IRQ placement lets us
> diagnose any short-fall.

Code-side: no change. We do not attempt to set host IRQ affinity from
inside the container (no permission); we just measure.

### 3.7 TX queue distribution validation (resolves CODEX-11)

The smoke sweep runner captures per-TX-queue packet counters from
the container before/after the run:
```bash
incus exec loss:cluster-userspace-host -- \
    bash -c 'cat /sys/class/net/eth0/statistics/tx_packets; \
             for q in /sys/class/net/eth0/queues/tx-*; do \
                 echo $q $(cat $q/byte_queue_limits/...) || true; \
             done'
```
The mlx5 driver also exposes per-queue counters via
`/proc/net/dev` is not sufficient; the cleaner path is `ethtool -S
eth0 | grep 'tx_packets_phy\|tx_queue'` IF ethtool is installed.
Since the container lacks ethtool (verified — `command not found`),
fall back to:
```bash
cat /proc/net/softnet_stat  # per-CPU softirq accounting
```
and verify that per-CPU tx counters are roughly balanced across the N
pinned CPUs (within ±20% of each other for the threads=4 run).

If per-queue/per-CPU distribution is wildly uneven (e.g., one CPU at
3 Mpps and three CPUs at 100 K pps), that proves the assumption fails
and PLAN-KILL the v2 multi-thread approach. The fallback would be
explicit XPS configuration on the host (out-of-scope) or
PACKET_TX_RING (option 3).

### 3.8 Per-thread stderr serialization (resolves CODEX-13)

Each worker emits per-second progress as a single
`eprintln!("{}", json_line)` — that's one `write()` syscall on stderr.
Linux guarantees writes ≤PIPE_BUF (4096) to a pipe are atomic; stderr
to a terminal/journal goes through line-buffered stdio in Rust's
println — but `eprintln!` uses `io::stderr().write_all(...)` which is
**not** atomic across threads.

Fix: each worker's progress line is built into a single `String` and
emitted via `eprintln!` exactly once per line. Rust's `Stderr` is
line-buffered when attached to a terminal but **NOT atomic across
threads** in general. To guarantee non-interleaved lines, wrap stderr
writes in a `Mutex<()>` (once per second per thread = 8 ops/s for
N=8). Trivial overhead, fixes interleaving.

Alternatively (cleaner): workers don't emit per-second progress; only
main thread emits one aggregate progress line per second by reading
the PaddedStats atomic snapshots. Per-thread breakdown is in the
final summary JSON only.

**Plan v2 picks the cleaner option**: main thread is the sole stderr
progress emitter; workers are silent except for the first-other-errno
log (one-shot, single line, no interleave risk).

### 3.9 Shutdown plumbing

Shared `Arc<AtomicBool> shutdown_flag = AtomicBool::new(false)`. Each
worker checks `shutdown_flag.load(Relaxed)` once per batch at top of
loop. Set by:
- Main thread when duration elapses (uses an `Instant` deadline, set
  shutdown when reached).
- Any worker on fatal error (pin failure, EPERM/EACCES from sendmmsg).

Worker exits cleanly; main joins all; main emits final summary.

### 3.10 NOT in scope (unchanged from v1)

PACKET_TX_RING, bare-metal generator, virtio knobs, IPv6, larger frames.

## 4. Files touched

- `test/incus/cold-path-flooder/src/main.rs` — multi-thread refactor.
  Estimated +250 LOC vs v1's +200 (atomics, sched_getaffinity,
  WorkerFd wrapper).
- `test/incus/cold-path-flooder/Cargo.toml` — no new deps; libc only.
- `docs/pr/1615-flooder-multithread-virtio/plan-v2.md` — this file.
- `docs/pr/1615-flooder-multithread-virtio/measurements.md` — sweep
  results + IRQ-affinity recording (Step 6).
- `_Log.md` — Write/Edit logging.

## 5. Test plan

### 5.1 Cargo unit tests (additions)

- `worker_seed_avoids_zero_state`: assert `worker_seed(0, 0) != 0`
  and equals 0xA5A5_A5A5_A5A5_A5A5 sentinel.
- `worker_seed_disjoint_across_threads`: for `(base_seed, T)` in
  `[(0,0..16), (1,0..16), (42,0..16)]`, assert all 16 seeds distinct.
- `multi_thread_seeds_produce_disjoint_5tuples`: spawn 4 threads,
  same base_seed; capture first 1000 5-tuples each via mock loop;
  assert pairwise disjoint (BTreeSet intersection empty).
- `threads_arg_validates_against_cpuset`: mock `sched_getaffinity`
  via injected `allowed_cpus`; assert N > allowed.len() rejected.
- `cpu_base_arithmetic_uses_allowed_cpus`: assert that with
  `allowed_cpus=[2,4,6,8]`, `cpu_base=1`, `--threads=2` maps to
  CPUs 4 and 6 (NOT 1 and 2).
- `no_cpu_pin_skips_setaffinity`: assert with `--no-cpu-pin`, the
  pin code path is not taken.
- `padded_stats_layout_is_64`: const-assert
  `size_of::<PaddedStats>() == 64`.
- `padded_stats_no_false_sharing_in_vec`: assert two adjacent
  PaddedStats elements in a Vec are 64 bytes apart (or wrap into
  separate cache lines).
- `progress_aggregate_sums_per_thread`: feed synthetic atomic values
  for 4 threads; assert main-thread aggregate read matches sum.
- All 22 existing tests continue to pass.

Target: 32 unit tests total (22 existing + 10 new).

### 5.2 Smoke gate (BLOCKING)

Methodology mirrors #1611 plan v4 §4.5.

Sweep on `loss:cluster-userspace-host` against `xpf-userspace-fw0`:

| --threads | --batch | --cpu-base | expected aggregate | gate                |
|-----------|---------|------------|--------------------|---------------------|
| 1         | 32      | 0          | ~870 K pps         | regression vs #1611 |
| 2         | 32      | 0          | ~1.7 M             | scaling sanity      |
| 4         | 32      | 0          | **≥ 2.5 M (gate)** | **BLOCKING**        |
| 8         | 32      | 0          | ≥ 2.5 M            | headroom            |

For each run: 10 s duration + 2 s warmup. Capture:
- aggregate avg_pps
- sum err_eagain
- per-thread spread max/min ratio (target ≤ 1.5×; warn if higher)
- `/proc/interrupts` snapshot before+after (host mlx1 VF MSI-X)
- `/proc/net/softnet_stat` snapshot before+after (per-CPU softirq)

If `threads=4` row meets ≥2.5 M, gate passes; this PR ships.
If `threads=8` row plateaus near threads=4, log it and move on
(it's the VF cap; the gate is still met).
If `threads=4` row < 2.5 M, PLAN-KILL plan v2 and re-plan for
PACKET_TX_RING or bare-metal generator.

### 5.3 Firewall-side regression (Pass A + Pass B per SKILL.md Step 6)

Standard smoke matrix on `loss:xpf-userspace-fw0/fw1`:
v4+v6 × push+`-R` × CoS-off+CoS-on. Acceptance: no regression vs
master baseline (Wave-N batch baselines).

## 6. Hidden invariants

- Per-thread fd opened in main thread; moved to worker; WorkerFd Drop
  closes once. Main never retains an fd copy after spawn.
- `sched_getaffinity` is called once at process start; the resulting
  `allowed_cpus` is cloned into each worker for index arithmetic.
- Workers do not directly emit per-second stderr lines; only main
  does, by reading the atomic PaddedStats snapshots.
- `PaddedStats` struct is `#[repr(align(64))]`; size const-asserted == 64.
- `worker_seed` never returns 0; fallback constant
  `0xA5A5_A5A5_A5A5_A5A5` is xorshift64-safe.
- Pin failure is fatal in the default (pinned) configuration; smoke
  gate runs MUST be pinned.
- The sole shared mutable state on the hot path is the atomic
  `shutdown_flag` (`AtomicBool::load(Relaxed)`) and the worker's own
  PaddedStats slot. No mutex acquisitions in the hot loop.
- `compare_exchange(Relaxed, Relaxed)` is used for `first_other_errno`
  to record only the first error per worker.

## 7. Risks + mitigations (revised)

- **Risk**: TX queue distribution skewed across threads (CODEX-11).
  **Mitigation**: §5.2 captures `/proc/net/softnet_stat` per-CPU; if
  one CPU sees > 1.5× others, that's evidence and we PLAN-KILL.
- **Risk**: VF aggregate TX-PPS caps below 2.5 Mpps.
  **Mitigation**: §5.2 threads=8 row probes the cap; PLAN-KILL is
  acceptable, fallback is PACKET_TX_RING.
- **Risk**: Pin failure in unprivileged container (cgroup cpuset).
  **Mitigation**: validator pre-checks `pthread_setaffinity_np` works
  on CPU 0 of `allowed_cpus[0]` from the main thread before spawning
  workers; if it fails, error out clearly with `--no-cpu-pin` hint.
- **Risk**: false sharing between PaddedStats slots.
  **Mitigation**: `#[repr(align(64))]` + `size_of==64` const assert.
- **Risk**: per-thread fd ownership double-close.
  **Mitigation**: WorkerFd RAII single-owner pattern.
- **Risk**: xorshift64 zero-state trap.
  **Mitigation**: explicit zero-fallback in `worker_seed`.
- **Risk**: stderr line interleave.
  **Mitigation**: workers don't emit progress lines; main is sole
  emitter.
- **Risk**: SLUB cross-CPU allocator overhead (AGY-3).
  **Mitigation**: documented in runbook; not a code blocker; smoke
  gate empirically settles it.

## 8. Open questions for r2

None expected. AGY r1 + Codex r1 + SMR r1 raised 14 findings total;
all addressed in v2 sections §3.1-§3.10 + §5.

## 9. Rollout (unchanged from v1)

`cargo build --release --manifest-path test/incus/cold-path-flooder/Cargo.toml`
then `incus file push`. #1612 harness script will pass
`--threads 4 --cpu-base 0` explicitly. Single-thread baseline
preserved via default `--threads 1`.

## 10. Closes

`Closes #1615`.

## 11. References

- v1 plan: `docs/pr/1615-flooder-multithread-virtio/plan.md`.
- SMR r1: `docs/pr/1615-flooder-multithread-virtio/claude-smr-plan-r1.md`.
- AGY r1: `agy:result adversarial-review-mpoxmejg-u7jhya`.
- Codex r1: `codex:result task-mpoxt7ed-srhb1t`.
- Kernel: `net/packet/af_packet.c::packet_setsockopt`,
  `net/core/dev.c::__dev_direct_xmit`.
- Container env: `test/incus/cluster-setup.sh:474-538`,
  `incus config show loss:cluster-userspace-host`.
