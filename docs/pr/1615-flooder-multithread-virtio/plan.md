# Plan v1 — #1615 cold-path-flooder multi-thread + mlx5 VF TX-queue distribution

Closes #1615. Unblocks #1612 Scale Target table population and the
downstream #1609 multi-stage-policy DAG plan-review.

## 1. Problem statement

The cold-path-flooder shipped in #1611 (squash `6c26c40e6`) is correct
but caps at **~870 K pps single-thread** on `loss:cluster-userspace-host`,
regardless of `--batch` (32 / 64 / 256) or `taskset -c 0` CPU pin.
The #1611 plan v4 BLOCKING smoke gate is **≥2.5 Mpps**; that gate
cannot be hit with the current single-thread design.

This blocks #1612 Scale Target measurement table population (needs the
flooder to actually saturate the cold path) which in turn blocks #1609
multi-stage policy DAG v2 plan-review (needs the Scale Target numbers
to size the DAG).

## 2. Root cause — environment correction

The #1615 issue body framed the ceiling as "container's virtio TX
queue / qdisc=fq on IPVLAN". **That framing is wrong.** Inspection of
the live container shows:

- `cluster-userspace-host` is an Incus **container** (not a VM), not
  virtio.
- The container's `eth0` is a **direct SR-IOV VF** on parent `mlx1`
  (line in `test/incus/cluster-setup.sh:485-492`), VLAN 3667:
  ```yaml
  devices.eth0:
    nictype: sriov
    parent: mlx1
    vlan: "3667"
  ```
- `volatile.eth0.host_name: enp101s0f1v2` confirms it's an mlx5 VF
  in the netns of the container (not bridged).
- The VF in-container exposes **11 TX queues** (`/sys/class/net/eth0/queues/tx-{0..10}`).
- The container has **16 CPUs** visible (`nproc`).
- Qdisc on the VF is `fq` — but **`PACKET_QDISC_BYPASS=1`** is set in
  the flooder (verified in `main.rs:734-751`), so qdisc is bypassed
  on the TX path. The fq parent is not load-bearing for this ceiling.

So the ~870 K pps ceiling is **not** virtio queue depth and **not**
qdisc=fq serialization. The single-thread design pegs one CPU at a
per-CPU softirq+mlx5_core xmit ceiling. The mlx5 VF can absorb much
more aggregate pps; we are just under-feeding it with one TX-thread.

### Why multi-thread breaks the ceiling

`sendmmsg` on AF_PACKET SOCK_RAW with `PACKET_QDISC_BYPASS` calls
`packet_direct_xmit` → driver `ndo_start_xmit` directly. The mlx5
driver hashes by `skb_get_queue_mapping()` (set from skb hash of the
5-tuple) to pick a TX queue. With one thread emitting from one socket
with disjoint 5-tuples, the kernel still does:

1. one `__local_bh_disable_ip()` per `sendmmsg` batch on the calling CPU
2. one driver_xmit + completion path per packet, on the calling CPU
3. skb alloc / kfree in the per-CPU slab cache on the calling CPU

The calling CPU saturates around 870 K pps doing the skb alloc + driver
xmit + completion. **Multiple threads on multiple CPUs let each one
drive its own subset of the VF's 11 TX queues independently.**

We expect ~4× when going from 1 to 4 threads (each on its own CPU),
modulo mlx5 VF aggregate TX-PPS cap. 4 threads × 870 K = 3.48 Mpps,
comfortably > 2.5 Mpps gate. If the VF caps at 2 Mpps aggregate this
proves a separate ceiling, in which case PLAN-KILL is acceptable and
the fallback is option 3 (PACKET_TX_RING) or option 1 (bare-metal
generator).

## 3. Design

### 3.1 `--threads N` flag

Add a `--threads N` flag to the flooder (default `1`, range `1..=16`).

Per-thread state:
- Own AF_PACKET SOCK_RAW socket (open + bind per-thread; do **not**
  share fd, because Linux sendmmsg on AF_PACKET takes the socket
  buffer lock; per-thread fd avoids the lock).
- Own `TxRing` (own `slots`, `iovecs`, `msgs` Vec).
- Own xorshift64 PRNG seeded with `base_seed + thread_id`.
- Own `RunStats`.
- Optional CPU pin via `pthread_setaffinity_np` to CPU `cpu_base + thread_id`.

Per-thread loop is identical to the existing single-thread `run_loop`.
The main thread spawns N worker threads via `std::thread::spawn`,
blocks on `join`, sums per-thread `RunStats`, emits the same JSON
summary plus a new top-level `"threads": N` field and a `"per_thread"`
array.

### 3.2 `--cpu-base K` flag

Default `0`. Thread T pins to CPU `(cpu_base + T) % nproc`.

Two reasons we need this rather than always pinning to `0..N-1`:
- The Incus host may have RT/management work on CPU 0; operator might
  want `--cpu-base 1` or `--cpu-base 8` to avoid that.
- HT-siblings: on the loss host CPUs 0/8, 1/9, ... are HT pairs. With
  `--threads 4 --cpu-base 0` we land on 0/1/2/3 (distinct physical
  cores). With `--threads 8 --cpu-base 0` we cover all 8 physical
  cores. Operator can pass `--cpu-base 4` to start from the second
  numa-half if needed.

Default behavior with no `--cpu-base` is unpinned (kernel scheduler
chooses); we document that pin is recommended for reproducible runs.
Actually no — to match the #1611 smoke methodology (CPU0-pinned),
default `--cpu-base 0` makes the smoke deterministic. Operators who
don't want pin pass `--cpu-base -1` (sentinel) to disable.

### 3.3 Per-thread RNG seed disjointness

Per-thread seed = `base_seed XOR (thread_id * 0x9E3779B97F4A7C15)`
(golden-ratio mixing). Each thread's 64-bit xorshift state diverges
within the first call; the resulting 5-tuple streams will be
near-independent (xorshift64 cycle is 2^64-1, so the probability of
any two seeds landing on the same point within a 30-second run is
~30 × 2.5M / 2^64 ≈ 4e-12, negligible).

Property test: spawn 4 threads with same `base_seed=1`; assert the
first 1000 5-tuples generated by each thread are pairwise disjoint.

### 3.4 Aggregate stats output

Existing single-thread JSON summary shape preserved. Three new fields:
- `"threads": N`
- `"avg_pps": <aggregate>`  (sum across threads; this becomes the
  smoke-gate metric)
- `"per_thread": [ { "thread_id": 0, "avg_pps": X, "tx_packets": Y,
  ... }, ... ]`

Per-second progress lines on stderr each thread emits its own JSON
with `"thread_id": T`. A final aggregated line is emitted by the main
thread once per second (sum of last second's per-thread deltas).

### 3.5 NOT in scope

- PACKET_TX_RING / tpacket_v3: deferred again, per AGY r1's #1611
  finding 2. Only revisit if multi-thread doesn't break ceiling.
- Bare-metal generator (run flooder on loss host directly): out of
  scope; that's a methodology change to docs/runbook, not a code
  change.
- Virtio queue tuning: N/A — container is on a direct mlx5 VF.
- Frame size > 64: out of scope; this PR keeps the 64 B floor.
- IPv6: out of scope; #1611 ships v4-only and #1612 measurement table
  is v4-only.

## 4. Files touched

- `test/incus/cold-path-flooder/src/main.rs` — add `--threads`,
  `--cpu-base`, refactor `run_loop` into per-thread, add stats merge.
  Estimated +200 LOC.
- `test/incus/cold-path-flooder/Cargo.toml` — no new deps (use libc
  `pthread_setaffinity_np`); just keep libc.
- `docs/pr/1615-flooder-multithread-virtio/plan.md` — this file.
- `docs/pr/1615-flooder-multithread-virtio/measurements.md` — created
  Step 6 with the threads=1/2/4/8 sweep results.
- `_Log.md` — log the implement-test-PR actions.

No production dataplane code is touched. No userspace-dp, no
userspace-xdp, no pkg/. This is purely the test harness binary.

## 5. Test plan

### 5.1 Cargo unit tests

Add to `test/incus/cold-path-flooder/src/main.rs`:

- `multi_thread_seeds_are_disjoint`: spawn 4 threads with same
  `base_seed`, capture first 1000 5-tuples each, assert pairwise
  disjoint.
- `threads_arg_parses_and_validates`: assert `--threads 0` and
  `--threads 17` rejected, `--threads 1..=16` accepted.
- `cpu_base_arg_parses_and_validates`: assert `--cpu-base -2` rejected,
  `--cpu-base -1` (no-pin sentinel), `--cpu-base 0..=nproc-1` accepted.
- `per_thread_stats_merge_sums`: feed a synthetic Vec<RunStats> with
  known values; assert merged values are correct sums.
- `progress_aggregate_json_emits_threads`: assert the new
  `per_thread` array shape and the `threads` top-level field.
- Existing 22 tests continue to pass.

### 5.2 Smoke gate (BLOCKING)

Run on `loss:cluster-userspace-host` against `xpf-userspace-fw0`
(peer firewall RETH MAC). Methodology mirrors #1611 plan v4 §4.5.

Sweep table:

| --threads | --batch | expected aggregate pps | notes |
|-----------|---------|------------------------|-------|
| 1         | 32      | ~870 K                 | regression check vs #1611 |
| 2         | 32      | ~1.7 M                 | 2× scaling check          |
| 4         | 32      | ≥ 2.5 M (gate)         | **smoke gate**            |
| 8         | 32      | ≥ 2.5 M                | headroom check            |

For each run: 10 s duration + 2 s warmup, `--cpu-base 0`, all other
defaults. Capture aggregate `avg_pps`, sum `err_eagain`, and per-thread
spread (max/min pps ratio; expect ≤ 1.3× imbalance).

### 5.3 Firewall-side regression (Pass A + Pass B per SKILL.md)

The flooder change is on the LAN-side host. It cannot disturb the
firewall, but we still re-deploy the firewall on `loss:xpf-userspace-fw0/fw1`
and run the standard smoke matrix per SKILL.md Step 6:
v4+v6 × push+`-R` × CoS-off+CoS-on. Acceptance: no regression vs the
previous master baseline.

## 6. Open questions for reviewers

1. **Per-thread fd vs shared fd**: I propose per-thread AF_PACKET
   socket. AGY r1 on #1611 finding D recommended cache-line-aligned
   TxSlot; per-thread fd extends that "no false sharing" discipline.
   But a shared fd with N threads doing `sendmmsg` would (a) take the
   socket spinlock, (b) potentially funnel through a single packet
   socket buffer. Is per-thread fd unambiguously the right call? Are
   there observability tradeoffs (separate `/proc/net/packet` entries)?

2. **CPU-pin default**: I propose default `--cpu-base 0` (matches
   #1611 methodology). With 4 threads we land on CPUs 0-3. Is that
   the right default, or should we honor HT topology and pick
   physical-core IDs (0, 2, 4, 6 on a 2-way HT system)? On the loss
   host CPUs 0-7 are physical and 8-15 are HT siblings — so 0..N-1
   is fine for N≤8 but `--cpu-base` lets ops override. Acceptable?

3. **mlx5 VF aggregate TX-PPS cap**: I expect ~4× scaling 1→4
   threads. If the VF caps at, say, 2 Mpps aggregate regardless of
   thread count (queue limits or PCIe BAR write rate), we'd see plateau
   at threads=2. Is there a way to query the VF's max TX-PPS short of
   actually running the sweep? (probably not, hence the empirical
   sweep table in §5.2).

4. **fq qdisc on the VF**: even with `PACKET_QDISC_BYPASS=1`,
   `qdisc fq` is configured on the device. Does QDISC_BYPASS truly
   skip fq, or does fq have an out-of-band path that still applies
   (e.g., per-flow pacing on the device backend)? I read the AF_PACKET
   `packet_direct_xmit` path as fully bypassing qdisc, but the
   reviewer should sanity-check.

5. **Multi-thread vs SO_REUSEPORT**: an alternative is one shared
   listening socket with SO_REUSEPORT, but SO_REUSEPORT is for RX
   demux, not TX dispatch. AF_PACKET TX with SO_REUSEPORT does nothing
   useful AFAIK. Confirm or deny.

6. **Sendmmsg flag `MSG_DONTWAIT`**: should each thread pass
   `MSG_DONTWAIT` to avoid blocking on a full TX queue? Current code
   passes flags=0 and treats EAGAIN as recoverable; with multi-thread
   on a single VF, contention is higher so MSG_DONTWAIT might be
   warranted. Or it might be a no-op given how AF_PACKET handles flags.

7. **Thread-shutdown ordering**: if any thread errors out (e.g.,
   EPERM), the others should stop promptly. Use an `AtomicBool`
   shutdown flag checked at the top of each `run_loop` iteration?
   Or rely on `std::process::exit` from the failed thread? I'll
   implement the AtomicBool path; it's cleaner.

8. **Stats merge race**: per-thread stats are private to the thread
   until join; main thread sums after join. No race. But the
   per-second aggregate progress line needs an atomic snapshot — I
   plan to have each thread publish its current `RunStats` to a shared
   `Arc<[Mutex<RunStats>]>` indexed by thread_id, updated under the
   mutex once per iteration. Is the per-iteration mutex acquisition
   acceptable overhead at ~870 K pps per thread? At batch=32 that's
   ~27 K acquisitions/s/thread — trivial. Acceptable?

9. **Why not async / io_uring**: io_uring would let one thread saturate
   the VF without skb alloc overhead via `sendmsg_zc`. But that's a
   re-architecture, not a fix. Multi-thread is the obvious incremental
   fix; if it doesn't break the ceiling, io_uring + zc is the v3
   redesign and warrants its own issue.

10. **Compile-time invariants**: keep the existing `const _: () = assert!(...)`
    invariants. Add `const _: () = assert!(MAX_THREADS == 16)` and
    `const _: () = assert!(DEFAULT_THREADS == 1)`. Document MAX_THREADS
    rationale (kernel limit on AF_PACKET sockets per process? PID
    limits? Realistically the loss host has 16 CPUs; the cap matches).

## 7. Risk + mitigations

- **Risk**: scaling falls short of 2.5 Mpps gate (e.g., VF caps at
  1.5 Mpps aggregate).
  **Mitigation**: empirical sweep table caught this BEFORE we declare
  PLAN-READY. If sweep shows < 2.5 Mpps at threads=8, this PR
  PLAN-KILLs and we re-plan with PACKET_TX_RING or bare-metal.

- **Risk**: per-thread fds open a syscall surface area we didn't
  exercise in #1611 (e.g., SOCK_RAW open with EPERM mid-run when one
  thread succeeds and another races on rlimits).
  **Mitigation**: open all N sockets in the main thread BEFORE
  spawning any worker; check_iface_up + read_iface_mac done once;
  bind+QDISC_BYPASS done per-socket. Worker threads receive a
  pre-opened fd via the thread builder closure.

- **Risk**: CPU-pin via libc on a worker thread fails on some
  containers (CAP_SYS_NICE may be required for explicit affinity
  setting in unprivileged containers).
  **Mitigation**: treat pin failure as warning, not fatal. Print
  `warning: pthread_setaffinity_np failed (...): continuing without
  pin` and proceed.

- **Risk**: per-thread PRNG seeds collide.
  **Mitigation**: golden-ratio multiplier guarantees distinct
  64-bit seeds for thread_id in 0..16. Property test covers it.

- **Risk**: `--threads 16` exhausts the host's CPUs and starves the
  firewall (which lives on the *same* `loss:` host).
  **Mitigation**: smoke uses `--threads 4` (within 16-CPU budget,
  leaves 12 CPUs for fw0 + fw1 + host). Document this in the runbook.

## 8. Hidden invariants (per SKILL.md Step 2)

- Per-thread fds are opened in the main thread BEFORE thread spawn,
  to centralize EPERM/CAP_NET_RAW errors and avoid mid-run partial-spawn.
- Per-thread PRNG seeds are deterministic from `(base_seed, thread_id)`
  pair — the same `--seed 1 --threads 4` invocation produces the same
  4-stream tuple set across runs (important for diff'ing runs).
- The aggregate JSON summary always has `"threads": N` even when N=1,
  for parser-side simplicity (#1611 consumers can be updated in lock-step).
- Worker threads never call `eprintln!` other than per-second progress
  lines or first-other-errno; no per-batch printing.
- Each worker holds its own `TxRing` (no shared state on hot path);
  Arc<AtomicBool> shutdown flag is read once per batch via `Relaxed`.

## 9. Rollout

This is a test-harness binary. No deploy changes. To use:
1. `make build-cold-path-flooder` (existing target if any; otherwise
   `cargo build --release --manifest-path
   test/incus/cold-path-flooder/Cargo.toml`).
2. `incus file push target/release/cold-path-flooder
    loss:cluster-userspace-host/usr/local/bin/`.
3. Run with `--threads 4 --cpu-base 0` for the BLOCKING smoke gate.

The harness script in #1612 will add `--threads` to its invocation; that
PR comes later. This PR ships only the binary capability.

## 10. Closes

`Closes #1615`.

## 11. References

- #1611 plan v4: `docs/pr/1611-flooder-runner-body/plan-v4.md` (in
  git history, on branch perf/1611-flooder-runner-body).
- AGY r1 finding 2 on #1611 (PACKET_TX_RING deferred).
- AGY r1 finding D on #1611 (cache-line align TxSlot).
- Issue #1612 Scale Target measurement table — the dependent work
  this PR unblocks.
- `test/incus/cluster-setup.sh:474-538` — `create_lan_host()`, which
  proves cluster-userspace-host is an SR-IOV container.
