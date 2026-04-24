# PR: #881 show chassis forwarding — 5s / 1m / 5m CPU windows

## Goal

Replace the cumulative-since-start CPU% on the `Daemon CPU utilization`
and `Worker threads CPU utilization` rows with three Junos-style
sliding windows (5s / 1m / 5m). Cumulative hides current load — a
daemon that burned 100% for 10s three days ago reads ~0% today.
Operators diagnose live load, not lifetime averages.

## History — worker-row semantic change reverted

An earlier iteration of this PR also proposed switching the worker row
from OS thread CPU (`thread_cpu_ns / wall_ns`) to dataplane activity
(`Σactive_ns / Σwall_ns` from #869 telemetry). **Empirical validation
killed that change.** At 25 Gbps iperf3 load on
`loss:xpf-userspace-fw0`, the activity signal read **0%** per worker
while `top` and `thread_cpu/wall` showed ~5-10% per worker. Two
follow-up issues came out of that investigation:

- **#883 (P0)** — iperf3 at 25 Gbps entirely bypasses the userspace
  workers. `ethtool -S ge-0-0-2 | grep rx_xdp_redirect` = **1** over
  20+ minutes. The XDP shim is attached and configured correctly but
  packets take `XDP_PASS` to the kernel stack instead of XSK/CPUMAP
  redirect. Until this lands, workers genuinely see no forwarding
  traffic.
- **#884** — `active_ns` accounting in the worker loop undercounts:
  idle-branch ring-poll CPU (~84s over 1604s) gets bucketed into
  `idle_block_ns` instead of a poll-CPU bucket. Even if workers did
  see traffic, the activity signal would be near-zero because all the
  poll-loop CPU is misclassified.

Both upstream issues defeat `active_ns / wall_ns` as an operator
signal today. Until #883 + #884 land, the honest default is to keep
the worker row on `thread_cpu_ns / wall_ns` — the same semantics #880
shipped. The busy-poll-100% false-positive I was worried about is a
smaller lie than showing 0% at 25 Gbps.

This PR therefore ships the **windows only**, not the worker-row
semantic change. Worker row stays on `thread_cpu_ns / wall_ns` with
the #880 label ("Worker threads CPU utilization"). When #883 and
#884 are resolved, a follow-up PR can swap to activity-based semantics.

## Approach — two signals, three windows

Two rows tell different, complementary stories:

- **Daemon CPU utilization** — `/proc/self/stat` utime+stime. Total
  process CPU as per-core percent; can exceed 100% on multi-core
  (200% = 2 cores). Useful for capacity planning.
- **Worker threads utilization** (note: label drops "CPU" to avoid
  the OS-CPU connotation) — `Σ(active_ns) / Σ(wall_ns) × 100` across
  all workers. A 0-100% time-weighted per-worker-average activity
  fraction. Matches the operator intent of Junos vSRX "Real-time
  threads CPU utilization" — "how loaded is the forwarding plane?"
  — without the busy-poll false-positive of raw OS CPU. On eBPF,
  workers don't exist so this row renders `N/A — eBPF path has no
  worker threads` as in #880.

Each row renders three windows: 5s / 1m / 5m.

### Data flow

```
   ┌───────────────┐  1s tick   ┌─────────────────┐   Build()   ┌──────────────┐
   │  sampler      │──────────▶ │  cpuRing        │ ──────────▶ │  Format()    │
   │  goroutine    │            │  (360 samples)  │             │  3 columns   │
   └───────────────┘            └─────────────────┘             └──────────────┘
```

- **Sampler goroutine** owned by `pkg/fwdstatus`. Launched from the
  daemon at startup via a new `NewSampler(dp, proc)` + `Start(ctx)`.
  Stops on context cancel.
- **Cadence: 1s**. Matches existing #869 `WorkerRuntimeStatus`
  publish cadence.
- **Each sample captures three cumulative monotonic counters**:
  - `wall_ns` — monotonic clock at sample time.
  - `daemon_cpu_ns` — from `/proc/self/stat` (utime+stime, in ticks
    → ns via userHZ=100).
  - `worker_active_ns` — `Σ WorkerRuntimeStatus.active_ns` across all
    workers at sample time. Zero on eBPF path (type assertion fails).
  - `worker_wall_ns` — `Σ WorkerRuntimeStatus.wall_ns` across all
    workers. Used as denominator for the worker row. Zero on eBPF.
- **Ring**: `[360]cpuSample` circular buffer — sized for the longest
  window (5m at 1s = 300) plus a 1m headroom to tolerate: (a) missed
  samples (skipped on /proc read errors) and (b) the fact that
  looking up `newest.wall_ns − 5m` after 300 samples requires the
  ring still hold a sample ≥ 300s old. With a 360-slot ring and 1s
  cadence, the oldest retained sample is ~360s old at steady state,
  comfortably satisfying the 5m window. Mutex around writer + reader.
- **Build() query**: take a `SamplerSnapshot` (see test interface
  below). Pick newest sample and the sample at or before
  (newest.wall − W) for each W in {5s, 1m, 5m}.
  - Daemon %: `(newest.daemon_cpu_ns − then.daemon_cpu_ns) /
    (newest.wall_ns − then.wall_ns) × 100` → per-core %.
  - Worker %: `(newest.worker_active_ns − then.worker_active_ns) /
    (newest.worker_wall_ns − then.worker_wall_ns) × 100`. Because
    each worker's `wall_ns` advances at real time, `Σ wall_ns` over
    N workers and a time interval Δt equals N·Δt, and `Σ active_ns`
    is bounded by `Σ wall_ns`. The ratio is therefore a
    **time-weighted per-worker-average activity fraction in [0, 100]**
    — not a pool aggregate. The row answers "on average, what
    fraction of a worker's time was spent doing useful work in this
    window?".
  - If no sample ≥ W ago, that column is marked invalid and the
    formatter prints `-`.

### Struct changes

```go
// In pkg/fwdstatus/fwdstatus.go

type ForwardingStatus struct {
    // existing fields (State, Heap%, Buffer%, Uptime, ClusterMode)...

    // New: 5s / 1m / 5m columns.  Index with CPUWindow* constants.
    // DaemonCPU = process-wide /proc/self/stat rate.
    // WorkerCPU = Σ(active_ns) / Σ(wall_ns) × 100 — dataplane
    //            activity fraction, not OS thread CPU.
    DaemonCPUWindows      [3]float64
    WorkerCPUWindows      [3]float64
    DaemonCPUWindowValid  [3]bool
    WorkerCPUWindowValid  [3]bool

    // WorkerCPUMode is retained from #880. When it equals
    // CPUModeEBPFNoWorkers, the worker row prints the explicit "N/A
    // — eBPF path has no worker threads" label regardless of
    // WorkerCPUWindowValid — so eBPF's all-invalid state is
    // distinguishable from userspace's "short uptime" state.
    WorkerCPUMode         CPUMode

    // (Removed: DaemonCPUPercent, WorkerCPUPercent — cumulative
    // values are no longer displayed.)
}

const (
    CPUWindow5s = iota
    CPUWindow1m
    CPUWindow5m
)
```

### Formatter changes

`Format()` renders the two CPU rows as:

```
Daemon CPU utilization         4% / 3% / 2%   (5s / 1m / 5m)
Worker threads utilization     42% / 38% / 35% (5s / 1m / 5m)
```

Short uptime renders `-` per invalid column:

```
Daemon CPU utilization         4% / - / -     (5s / 1m / 5m)
```

### Sampling precision and first-tick behavior

- **Window granularity is ±1 sample.** With a 1s cadence and a
  `sample at or before (now − W)` lookup, the 5s column actually
  covers a 5–6s interval. Junos's literal-5s semantics has the same
  ±1s slop. Noted so operators don't chase ghost differences.
- **First-tick off-by-one.** `Start()` takes an initial sample
  before returning so the ring is never empty when Build() runs.
  Subsequent samples arrive at t=1, t=2, … With a sample at t=0
  (prime) and another at t=5, the 5s column becomes valid at t≈5
  (five ticks after prime). For the 1m / 5m columns, the validity
  threshold is ≥ N ticks since prime where N = window_seconds.
  Short-uptime behavior: the validity flag is set purely on "does a
  sample ≥ W old exist in the ring", not on a separate uptime
  clock — this makes the condition self-consistent with what
  Build() actually needs.

### Error handling during sampling

- **`/proc/self/stat` read failure**: the sample is **skipped**
  (ring head does not advance). Skipping ensures counter monotonicity
  across samples — a zero-insert would create a non-monotonic series
  that produces a negative rate on the next Build(). A skip merely
  widens the window's effective time range by 1s, which is benign
  and already tolerated by the ±1s slop above.
- **Worker telemetry read failure** (e.g. `Status()` returns an
  error on userspace-dp): record the sample with `worker_active_ns`
  and `worker_wall_ns` frozen at the previous sample's values.
  Build() therefore reads the rate as zero for that interval, which
  is honest — we didn't observe any worker activity.



- New package file `pkg/fwdstatus/sampler.go`:
  - `type Sampler struct { mu, ring, head, count, dp, proc }` (lifetime tied to the ctx passed to Start; no cancel field)
  - `NewSampler(dp DataPlaneAccessor, proc ProcReader) *Sampler`
  - `(s *Sampler) Start(ctx context.Context)` — primes one sample
    synchronously, then launches the 1s-tick goroutine.
  - `(s *Sampler) Snapshot() SamplerSnapshot` — returns a
    copy-on-read view of the ring for `Build()`.
  - `(s *Sampler) sample()` — one iteration of the loop.
- **Test interface**: `Build()` takes `SamplerSnapshot` directly
  (not `*Sampler`), so tests construct `SamplerSnapshot` literals
  with canned values without touching the Sampler goroutine.
  `SamplerSnapshot` is a small value-type:
  ```go
  type SamplerSnapshot struct {
      Samples []cpuSample    // copied from ring, newest last
      Now     time.Time      // captured when Snapshot() was called
  }
  ```
  Call sites (grpcapi handler, local TTY handler) do
  `Build(dp, proc, startTime, clusterMode, s.sampler.Snapshot())`.
  Zero-value `SamplerSnapshot{}` (empty slice) → all windows
  invalid, preserving behavior when no sampler is plumbed.
- Daemon wiring: new field on `grpcapi.Server` for the `*Sampler`;
  constructed in `pkg/daemon/daemon.go` alongside the existing
  dataplane/gRPC setup, started with the daemon context.

### Thread safety

- `Sampler` holds three fields under `mu`: the ring (`[360]cpuSample`),
  a write index `head` (wraps 0..359), and a monotonic `count` of
  samples ever written (does NOT wrap). `head` is the next write
  slot; `count` tracks population history so rollover doesn't lose
  track of how many samples have actually been taken.
- `Snapshot()` takes `mu`, copies `ring[]` to a fresh slice ordered
  oldest-first (newest last — whichever order Build() expects), sets
  `Now = time.Now()`, releases the lock. If `count < 360`, only the
  first `count` entries are populated — the returned slice is sized
  to `min(count, 360)`. Build reads off-lock.
- Samples are 32 bytes × 360 = 11.5 KB. Copy is cheap.

### Short-uptime handling

A column is valid iff the snapshot contains a sample with
`wall_ns ≤ newest.wall_ns − W`. This is purely a content check, not a
head/count check — Build only needs to know whether a sufficiently-old
sample is present in the copied slice. At boot, with a 1s sampler
cadence and a synchronous prime at `Start()`:

- 5s column: valid once a sample ≥ 5s old is in the ring (≈5s after
  prime).
- 1m column: valid at ≈60s post-prime.
- 5m column: valid at ≈300s post-prime.

Before those thresholds, the corresponding `*WindowValid[i]` stays
`false` and the formatter renders `-`. Ring rollover at count ≥ 360
does not affect this: once the 5m column is valid, it stays valid,
because the oldest retained sample is always ~6m old by construction
(the ring holds 360s of history, comfortably past the 5m lookup).

### Files touched

| File | Change |
|---|---|
| `pkg/fwdstatus/sampler.go` (new) | `Sampler` type, ring, goroutine, `Snapshot`. |
| `pkg/fwdstatus/sampler_test.go` (new) | Fill, rollover, window lookup with exact / approximate / short-uptime cases. |
| `pkg/fwdstatus/fwdstatus.go` | Add `DaemonCPUWindows`/`WorkerCPUWindows` + valid flags to `ForwardingStatus`; remove `DaemonCPUPercent`/`WorkerCPUPercent` (cumulative values) but retain `WorkerCPUMode` for eBPF N/A label distinction. Update `Format()`. |
| `pkg/fwdstatus/builder.go` | Drop the per-call `/proc/self/stat` CPU math. Take a `SamplerSnapshot` (value type); populate windows by computing rates from the snapshot's `Samples` slice. |
| `pkg/fwdstatus/fwdstatus_test.go` | Replace cumulative-CPU tests with window tests. Tests construct `SamplerSnapshot` literals directly — no need to instantiate or drive the Sampler goroutine. |
| `pkg/grpcapi/server.go` + `server_show.go` | Store `*Sampler` on `Server`; call `s.sampler.Snapshot()` and pass the result to `fwdstatus.Build`. |
| `pkg/cli/cli_show_chassis.go` | Accept `*Sampler` (new field on CLI struct) + call `Snapshot()` and pass result to Build. |
| `pkg/cli/cli.go` | Add `*fwdstatus.Sampler` field + setter. |
| `pkg/daemon/daemon.go` | Construct the sampler at startup; pass to gRPC server + CLI. |

### Test strategy

1. **Sampler unit test**: seed with synthetic timestamps, write N
   samples, assert `Snapshot` returns correct ordering, rollover,
   and window lookups for all three windows.
2. **Insufficient-history test**: sampler with 3 samples (3s
   uptime) → 5s and longer windows flagged invalid.
3. **Build + format integration**: fake sampler returns canned
   windows; formatter renders correct three-column output; invalid
   columns render `-`.
4. **Deploy + load test**: on `loss:xpf-userspace-fw0`, run iperf3
   to saturate one core briefly, run `show chassis forwarding`
   during and after. Expect 5s to spike and decay first, 1m to
   track more slowly, 5m to stay low.

### Follow-ups not in this PR

- Exposing windows as Prometheus gauges (separate issue if asked).
- Adding more windows (15m, 1h) — not requested, not doing.

## Alternatives rejected

1. **Keep cumulative + add windowed rows**. Rejected: cumulative is
   not useful information for an operator diagnosing live load; it
   only dilutes the display. If some operator wants it, it can come
   back as a `show chassis forwarding extensive` follow-up.

2. **Per-CLI-invocation two-sample 1s sleep**. Already rejected in
   #877 plan alt 2. Blocks scripts.

3. **Sliding mean via decay instead of ring**. Cheap storage-wise
   (just 3 floats + EMA constants) but loses the ability to
   compute arbitrary windows later and produces a different
   (exponentially decayed) value than what operators expect from
   Junos's "last 5 seconds" literal-average semantics.

## Refs

Closes #881. Builds on #877/#880 (ForwardingStatus + formatter).
