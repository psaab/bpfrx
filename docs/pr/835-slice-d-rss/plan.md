# Issue #835 — Plan: RSS indirection rebalance for cross-binding fairness (#786 Slice D)

> **Status.** Architect R5 (R3 was a clean rewrite; R4 + R5 are
> targeted patches addressing residual Codex findings). Closes:
> R1 (1 CRITICAL + 9 HIGH), R2 (Findings 5/6/8/10), R3 (4 new),
> R4 (3 new), R5 (4 new — snapshot ordering, per-iface epoch
> isolation, test contradiction, stale references).

## 1. Goal

On shared_exact CoS queues under `iperf3 -P 16`, per-stream CoV is
bimodal because RSS lands 16 flows unevenly across 6 bindings
(observed distributions like `[5, 5, 4, 2]`). RSS++ (Barbette et
al., CoNEXT 2019) periodically samples per-RX-ring packet load and
rebalances the NIC indirection weights by moving traffic from the
hottest ring toward the coldest.

**Acceptance** (pre-registered, §6.4):
- p5202 per-stream CoV ≤ 25% on ≥ 8 of 10 consecutive runs.
- p5201 per-stream CoV ≤ 15% on ≥ 8 of 10 runs.
- Aggregate Gbps within ±5% of the #830 + #832 baseline (≥ 0.91 /
  9.08 Gbps).
- 0 retransmit-count regression.
- `make test-failover` passes.
- 33 new unit tests pass; no existing tests regress.

## 2. Non-goals

- Scheduler-side changes in the Rust dataplane.
- Cross-NIC rebalance (one interface's rebalance decision never
  references another interface's state).
- Non-mlx5 drivers — virtio / iavf / i40e explicitly skipped via the
  existing `mlx5Driver` constant (`rss_indirection.go:43`).
- Replacing RSS with custom eBPF-based flow steering.
- Adaptive cadence / thresholds — fixed constants in this PR.
- Ops-surface visibility (new `show` command) — log-only for v1.
- Fallback path to individual-slot writes — weights-only (§4.3).

## 3. Files

### 3.1 New files

- `pkg/daemon/rss_rebalance.go` — rebalance loop, state machine,
  ethtool-parsing helpers, weight computation.
- `pkg/daemon/rss_rebalance_test.go` — 33 unit tests.
- `docs/pr/835-slice-d-rss/plan.md` — this file.
- `docs/pr/835-slice-d-rss/codex-plan-review.md` — review trail.
- `docs/pr/835-slice-d-rss/codex-code-review.md` — review trail.
- `docs/pr/835-slice-d-rss/findings.md` — post-deploy measurement.

### 3.2 Modified files

- `pkg/daemon/rss_indirection.go`
  - Add package-level `rssWriteMu sync.Mutex` guarding every
    ethtool RSS write.
  - Add package-level `rssIndirectionEpoch atomic.Uint64`; bumped
    by the three PUBLIC entry points **after a successful
    write completes**. Marks "the table you read may have
    changed; re-seed your shadow state on the next tick."
    The rebalance loop reads this via `LoadRSSEpoch()` at the
    top of each tick and resets per-iface state on mismatch.
    **Rebalance writes do NOT bump this** (R5 Finding 2 — see
    below).
  - Add package-level `rssConfigGen atomic.Uint64` bumped on
    EVERY invocation of the three public entry points,
    regardless of write success. Marks "RSS config intent
    changed". The rebalance loop snapshots this BEFORE
    computing weights and re-checks AFTER the mutex (resolves
    R4 Finding #3: a failed `applyRSSIndirection` followed by
    a `restoreDefaultRSSIndirection` would otherwise slip past
    an Epoch-only re-check). **Rebalance writes do NOT bump
    this either** (R5 Finding 2): the bumps are control-plane-
    only events; one iface's rebalance success is local state
    and must not invalidate peer ifaces' rebalance state.
  - **R5 Finding 2 — per-iface vs global counters**: both
    `rssIndirectionEpoch` and `rssConfigGen` are GLOBAL
    (per-process), bumped by the three control-plane entry
    points only. They do NOT couple ifaces' rebalance state.
    The rebalance loop's per-iface state machine (currentWeights,
    consecutiveImbalanced, lastRebalanceTime) is purely local;
    a successful rebalance on iface A produces no global counter
    bump, and iface B's state is untouched.
  - **Mutex wrapping — resolves R3 new-issue #2 self-deadlock
    AND R4 Finding #2 kill-switch re-entry**:
    - Split each of the three public entry points into a
      locked shell and an unlocked inner:
      `applyRSSIndirection` (locks + calls
      `applyRSSIndirectionLocked`),
      `reapplyRSSIndirection` (locks + calls
      `reapplyRSSIndirectionLocked`),
      `restoreDefaultRSSIndirection` (locks + calls
      `restoreDefaultRSSIndirectionLocked`).
    - The `...Locked` variants do the actual work under a
      `// PRECONDITION: rssWriteMu.Lock() held` contract. They
      can freely call each other without re-entry — e.g.,
      `applyRSSIndirectionLocked(enabled=false, ...)` calls
      `restoreDefaultRSSIndirectionLocked`.
    - `applyRSSIndirectionOne` is also a `...Locked` contract
      helper (unwrapped; caller holds mutex).
    - The rebalance loop acquires the mutex via
      `rssWriteMuLock()` / `rssWriteMuUnlock()`. All four
      writer paths (boot apply, commit reapply, kill-switch
      restore, rebalance) serialize at the outermost call site
      without re-entry.
  - Add package-level `rssAllowedRef atomic.Pointer[[]string]`
    holding the current `allowed` slice. Updated by
    `applyRSSIndirection` / `reapplyRSSIndirection` on every
    invocation so the rebalance loop reads the live allowlist.
    Resolves R3 new-issue #4 allowlist reload.
  - Add package-level `rssEnabled atomic.Bool`. Set by
    `applyRSSIndirection(enabled, ...)`. Read by the rebalance
    loop.
  - Add package-level `rssWorkers atomic.Int32`. Same pattern.
  - Expose `LoadRSSEpoch() uint64`, `LoadRSSAllowed() []string`,
    `LoadRSSEnabled() bool`, `LoadRSSWorkers() int`,
    `BumpRSSEpoch()`, `RssWriteMuLock() / RssWriteMuUnlock()`
    for the rebalance loop.
- `pkg/daemon/daemon.go`
  - At initial daemon start (line 466-500 region), after the
    first `applyRSSIndirection` invocation, spawn the rebalance
    goroutine exactly once with the daemon root `ctx`.
  - The goroutine's runtime state (enabled / workers / allowed)
    comes from the `rss_indirection.go` atomic variables added
    above, NOT from a copy captured at spawn time. So the loop
    transparently picks up reload-driven allowlist changes,
    worker-count changes, and kill-switch toggles without
    needing to be restarted. Resolves R3 new-issue #4.
  - On shutdown, `ctx` cancellation cleanly stops the goroutine.

### 3.3 Explicitly unchanged

- Rust dataplane.
- BPF / XDP / TC programs.
- Config schema — no new knobs in v1.
- systemd unit / boot sequence — the new goroutine is invisible at
  this layer.

## 4. Algorithm

### 4.0 Pre-plan empirical spike — resolves R1 CRITICAL + HIGH-2

Before committing to this design we ran a spike on the loss
cluster (mlx5 VF, 6 RX rings):

- `iperf3 -c 172.16.80.200 -P 16 -t 20 -p 5202` running.
- At t=7s: `ethtool -X ge-0-0-2 weight 10 20 20 20 20 20`.
- At t=14s: `ethtool -X ge-0-0-2 weight 25 10 20 20 20 20`.

Results:
- Aggregate throughput 9.56 Gbps (matches #830 + #832 baseline
  of 9.57 Gbps — no regression).
- Total retransmits during the 20 s run with two mid-flight
  rewrites: 35 (≈ 0.01% of packets at 10 Gbps, well inside the
  TCP-slow-start noise band).
- `ethtool -x` after each rewrite shows the indirection table
  has shifted to the expected weighted distribution
  (25/115 × 256 = 56 slots for ring 0, etc.).

**Conclusions for the plan**:
- `ethtool -X <iface> weight` works live on mlx5 VF without a
  link bounce or a driver-level reset. The mechanism is pinned
  as weights-only (§4.3, §4.4).
- Mid-traffic rewrites do not disrupt in-flight TCP connections
  in any observable way. The retransmit count is the noise
  floor; a connection-reset event would produce orders of
  magnitude more retransmits.

**Open empirical unknown — not knowable a priori**: does the
rebalance algorithm's iterative convergence actually reach
"balanced" within the 10-run measurement window? The closed-form
analysis in §4.3a gives a 4-iteration worst-case under idealised
linear-rate-response assumptions, but the real rate-response is
a function of 5-tuple hash properties and TCP burstiness.
Pre-registered in §6.4 negative-finding protocol: if the 10-run
measurement shows no convergence OR throughput regression, we
revert and close the PR.

### 4.1 Signal

Per-RX-ring packet counters from `ethtool -S <iface>`:

```
rx0_packets: <u64>
rx0_bytes:   <u64>
rx1_packets: <u64>
...
```

Parsed via a regex on each tick into `map[int]uint64` keyed by
ring index (packet count only; bytes ignored for trigger).

### 4.2 Trigger

Two-condition gate so transient bursts don't churn the table:

1. **Imbalance.** Compute `max_rate / mean_rate` across the
   **rebalance domain** = ring indices `0..ringCount-1` where
   `ringCount = min(workers, queue_count(iface))`. This is also
   the domain of `currentWeights`; trigger, argmin(cold), and
   argmax(hot) all agree on this one domain. Idle rings within
   the domain count toward the mean as 0-delta, so skews like
   `[24, 0, 0, 0, 0, 0]` across 6 domain rings yield mean=4,
   max=24, ratio=6.0 — fires. Rings outside the domain (e.g.
   `queue_count > workers`) are never sampled for the trigger
   and never have their weight adjusted. `TRIGGER = 1.8`;
   derivation in §4.2a. Resolves R3 new-issue #1 and R4 Finding
   #1.
2. **Stability.** Require `STABILITY` consecutive imbalanced
   samples (`STABILITY = 3`) before firing.
3. **Cooldown.** After firing, block further rebalance on this
   iface for `COOLDOWN = 10 s`. Any imbalanced sample during
   cooldown resets to `0` (fresh stability required after
   cooldown expires).

Each tick is `SAMPLE_INTERVAL = 1 s`, so stability fires after
3 s of sustained imbalance and rebalances happen at most every
~13 s per iface.

#### Guards (§4.5 pseudocode implements; tests #26-#28 pin)

- **First sample per iface seeds state only**; no imbalance check
  yet (delta requires a prior sample). Prevents `0/0` at boot.
- **Zero-total-traffic samples (`sum(delta) < minTrafficPerWindow
  = 1000 pkts`) reset `consecutiveImbalanced` to 0.** No signal =
  no action.
- **Samples with managed domain `ringCount < 2` skip the ratio
  check** (can't measure imbalance with a single managed ring).
  Note: **we do NOT skip on `nonZeroRings(delta) < 2`** — an
  idle-ring skew like `[24,0,0,0,0,0]` has only 1 non-zero ring
  but is the most imbalanced case and must fire. R4 Finding #1.
- **Counter non-monotonicity (reset or wrap) is treated as
  zero-delta for this tick** — i.e., `max(0, current - previous)`,
  with the counter replaced by `current` for the next tick.
  Counter resets happen on driver restart / link down-up; very
  rare. The zero-delta branch then disables imbalance counting
  for one tick.
- **Missing counters** (a ring's `rx<N>_packets` line is absent
  from a given `ethtool -S` output): treated as "ring exists but
  saw zero packets this window" — same as zero-delta.

#### 4.2a Trigger derivation

`TRIGGER = 1.8` comes from the standard deviation of multinomial
sampling with `N` flows uniformly distributed across `M` rings.
For `N = 16`, `M = 6`:

- Expected packets per ring: `μ = N/M ≈ 2.67`.
- Std dev per ring: `σ = √(N × (1/M) × (1 − 1/M)) ≈ 1.49`.
- `(μ + 1σ) / μ ≈ 1.56` (expected max/mean spread at 1σ above mean).
- `(μ + 2σ) / μ ≈ 2.12` (at 2σ).

`1.8` sits midway. Below it, the observed imbalance is
within-the-noise-of-uniform-RSS; above, it's meaningfully skewed.
This derivation is order-of-magnitude correct; exact response
depends on the Toeplitz hash's quality and flow packet-size
distribution. §6.1 **pre-flight empirical calibration** validates
the threshold on the test workload and bumps it if needed.

### 4.3 Weight-shift rule (no slot writes)

Each iface carries a `currentWeights []int` vector of length
`ringCount = min(workers, ethtool_queue_count(iface))`. Seeded
to `[DEFAULT_WEIGHT; ringCount]` where `DEFAULT_WEIGHT = 20`.

On trigger:

1. `hot = argmax(rates[0..ringCount])`;
   `cold = argmin(rates[0..ringCount])` across the **full
   rebalance domain** (idle rings eligible as cold — in fact
   idle rings are the BEST cold candidates). Ties broken by
   lowest ring index. R4 Finding #1.
2. `shift = max(1, currentWeights[hot] × MIGRATE_FRACTION)` where
   `MIGRATE_FRACTION = 0.25`.
3. Clamp: `shift = min(shift, currentWeights[hot] - MIN_WEIGHT)`
   where `MIN_WEIGHT = 1`. No ring starved to 0.
4. Update in-memory: `currentWeights[hot] -= shift`;
   `currentWeights[cold] += shift`.
5. Apply via `ethtool -X <iface> weight <w0> <w1> ... <wN>`
   (single invocation; atomic from the NIC's perspective).

### 4.3a Convergence (illustrative, not proof)

Worst-case skew: rates `[10, 1, 1, 1, 1, 1]`, initial weights
`[20, 20, 20, 20, 20, 20]`.

Assumption (acknowledged as not empirically grounded in this
plan, but plausible): rate on each ring is roughly proportional
to that ring's weight when all rings share the same incoming
traffic distribution.

| Iter | Weights before | Shift | Weights after | Projected ratio |
|------|----------------|------:|---------------|----------------:|
| 1 | [20,20,20,20,20,20] | 5 | [15,25,20,20,20,20] | 2.3 |
| 2 | [15,25,20,20,20,20] | 3 | [12,28,20,20,20,20] | 2.0 |
| 3 | [12,28,20,20,20,20] | 3 | [9,31,20,20,20,20] | 1.8 |
| 4 | [9,31,20,20,20,20] | 2 | [7,33,20,20,20,20] | 1.6 (below trigger) |

With `COOLDOWN = 10 s`, convergence ≈ 40 s wall-clock in this
idealised model. If real rate-to-weight response is sub-linear
or the hot-ring identity oscillates (hash-pattern shift), actual
convergence will be slower; §6.4 negative-finding protocol
handles non-convergence.

### 4.4 ethtool invocation

Single path, no fallback:

```
ethtool -X <iface> weight <currentWeights[0]> ... <currentWeights[ringCount-1]>
```

Driver gate: `execer.readDriver(iface) != mlx5Driver` → skip
silently. Uses the existing `mlx5Driver = "mlx5_core"` constant
(`rss_indirection.go:43`).

Failure handling (§4.5 state machine):
- Stderr + exit code captured into the daemon log.
- `consecutiveFailures` advances on each failed attempt.
- On `consecutiveFailures ≥ MAX_FAILURES = 5`, the iface is
  flagged `permanentSkip = true` for the life of this daemon
  run. Restart clears.

### 4.5 State machine

Per iface:

```go
type rebalanceState struct {
    lastSampleCounters    map[int]uint64 // ring → cumulative packets
    lastSampleTime        time.Time
    firstSample           bool           // true until we have a baseline
    currentWeights        []int          // seeded on first rebalance or reset on epoch change
    consecutiveImbalanced int
    lastRebalanceTime     time.Time
    consecutiveFailures   int
    permanentSkip         bool
    lastSeenEpoch         uint64         // last observed rssIndirectionEpoch
}
```

Loop (one goroutine, iterates all allowed interfaces each tick):

```go
for {
    select {
    case <-ctx.Done():
        return
    case <-ticker.C:
    }
    // R8 Finding 1: snapshot ConfigGen FIRST THING in the
    // tick — before any sample reads, weight computations, or
    // config loads. Any control-plane invocation between this
    // snapshot and the under-lock re-check (in the rebalance
    // path below) will be detected and the iteration will
    // abandon. This closes the "reapply with same state but
    // different table" window that R8 flagged.
    tickGenSnapshot := rss_indirection.LoadRSSConfigGen()

    // Pull live config state on every tick — resolves R3
    // new-issue #4 (allowlist changes after startup).
    enabled := rss_indirection.LoadRSSEnabled()
    workers := rss_indirection.LoadRSSWorkers()
    allowed := rss_indirection.LoadRSSAllowed()
    if !enabled || workers <= 1 || len(allowed) == 0 {
        continue // runtime disable or config reload removed all allowed ifaces
    }
    for _, iface := range allowed {
        // Driver gate — reuse existing mlx5Driver constant.
        if execer.readDriver(iface) != mlx5Driver { continue }
        s := stateFor(iface)
        if s.permanentSkip { continue }

        // Reconcile epoch: if boot / commit / kill switch wrote
        // RSS since last tick, reset our state to match.
        curEpoch := rss_indirection.LoadRSSEpoch()
        if curEpoch != s.lastSeenEpoch {
            s.currentWeights         = equalWeights(ringCount(iface))
            s.consecutiveImbalanced  = 0
            s.lastRebalanceTime      = time.Now() // refresh cooldown
            s.firstSample            = true       // invalidate counter baseline
            s.lastSeenEpoch          = curEpoch
        }

        sample, err := readEthtoolS(iface, execer)
        if err != nil { s.consecutiveFailures++; continue }

        if s.firstSample {
            s.lastSampleCounters = sample
            s.lastSampleTime     = time.Now()
            s.firstSample        = false
            continue // no delta yet
        }

        elapsed := time.Since(s.lastSampleTime)
        if elapsed < minElapsed { continue }

        delta := deltaSafeAgainstResets(sample, s.lastSampleCounters)
        s.lastSampleCounters = sample
        s.lastSampleTime     = time.Now()

        if totalPackets(delta) < minTrafficPerWindow {
            s.consecutiveImbalanced = 0
            continue
        }
        // R4 Finding #1: guard on managed ring-count domain, not
        // active-ring count. An idle-ring skew `[24,0,0,0,0,0]`
        // has only 1 active ring but IS the skew we want to fire.
        if len(s.currentWeights) < 2 {
            s.consecutiveImbalanced = 0
            continue
        }

        // R4 Finding #1: max/mean computed across ALL domain
        // rings (zero-filled for idle ones), not just non-zero.
        domain := s.currentWeights // ringCount = len(currentWeights)
        maxR, meanR := maxMeanOverDomain(delta, len(domain))
        if float64(maxR) > meanR*TRIGGER {
            s.consecutiveImbalanced++
        } else {
            s.consecutiveImbalanced = 0
        }

        if s.consecutiveImbalanced < STABILITY { continue }
        if time.Since(s.lastRebalanceTime) < COOLDOWN { continue }

        // R2 F6 + R4 F3 + R5 F1 + R8 F1: use the tick-start
        // ConfigGen snapshot taken at the very top of this
        // iteration. Any control-plane invocation between then
        // and the post-lock re-check below — including a reapply
        // that doesn't change enabled/workers/allowed but DOES
        // overwrite the indirection table — bumps ConfigGen and
        // forces abandon. The snapshot covers the window from
        // BEFORE counter sampling all the way to BEFORE write.
        genBefore := tickGenSnapshot

        // Compute new weights from current state.
        newWeights := computeWeightShift(delta, s.currentWeights)

        rss_indirection.RssWriteMuLock()
        // R7 Finding 1: re-validate that the runtime config we
        // observed at the top of the tick (enabled, workers,
        // allowed-membership for THIS iface) hasn't changed
        // under us BEFORE we issue the write. The pre-snapshot
        // load happens outside the lock; a control-plane apply
        // / disable in the gap between that load and the lock
        // acquisition would otherwise slip through. ConfigGen
        // re-check catches it because every public-entry
        // invocation bumps ConfigGen regardless of write
        // success.
        if rss_indirection.LoadRSSConfigGen() != genBefore {
            rss_indirection.RssWriteMuUnlock()
            // Force the reconcile branch on next tick.
            s.lastSeenEpoch = rss_indirection.LoadRSSEpoch() - 1
            continue
        }
        // Defence in depth: also re-load enabled/workers/allowed
        // under the lock and abandon if any control-plane state
        // changed even if ConfigGen somehow missed it (e.g.
        // a future bug). A failed re-validation aborts cleanly.
        if !rss_indirection.LoadRSSEnabled() ||
           rss_indirection.LoadRSSWorkers() <= 1 ||
           !ifaceInAllowed(iface, rss_indirection.LoadRSSAllowed()) {
            rss_indirection.RssWriteMuUnlock()
            s.lastSeenEpoch = rss_indirection.LoadRSSEpoch() - 1
            continue
        }
        err = applyWeights(iface, newWeights, execer)
        if err == nil {
            // R5 Finding 2: rebalance must NOT bump global Epoch
            // or ConfigGen — those are control-plane signals
            // ("boot/reapply/kill-switch fired") that other
            // ifaces' state machines react to. A successful
            // rebalance on iface A doesn't change iface B's
            // intent, so it must not propagate as a config bump.
            // Per-iface success is tracked via the local
            // s.lastRebalanceTime / s.currentWeights state below.
            s.lastSeenEpoch = rss_indirection.LoadRSSEpoch()
        }
        rss_indirection.RssWriteMuUnlock()

        if err != nil {
            s.consecutiveFailures++
            if s.consecutiveFailures >= MAX_FAILURES {
                slog.Warn("rss rebalance: iface permanently skipped",
                          "iface", iface, "err", err)
                s.permanentSkip = true
            }
            continue
        }
        s.currentWeights        = newWeights
        s.lastRebalanceTime     = time.Now()
        s.consecutiveImbalanced = 0
        s.consecutiveFailures   = 0
        slog.Info("rss rebalance applied",
                  "iface", iface,
                  "weights", newWeights,
                  "delta_pkts", delta)
    }
}
```

#### Why this closes R2 Finding 6

The race is: rebalance computes weights at t0 while holding no
lock; at t1 `reapplyRSSIndirection` runs under the lock; rebalance
waits on the lock; at t2 rebalance acquires the lock with STALE
weights computed from the PRE-reapply distribution; applying them
silently undoes the commit's reconcile.

The ConfigGen snapshot (`genBefore := LoadRSSConfigGen()` taken
BEFORE `computeWeightShift`) + re-check (`if LoadRSSConfigGen()
!= genBefore { abandon }`) post-lock is the abandon-on-config-
change rule that closes Codex R2 Finding 6 + R4 Finding 3 + R5
Finding 1+2. ConfigGen bumps on EVERY public-entry invocation
regardless of write success, so a failed apply followed by a
restore is also caught. Rebalance writes do NOT bump ConfigGen
or Epoch — those are control-plane signals only. Test #26 pins
the bump-during-block case; test #29 pins the bump-without-write
case (R6 second blocker).

### 4.6 Runtime disable + config reload (R1 HIGH-5 closure)

**Runtime disable**: driven by a shared `atomic.Bool` flag
`rssEnabled`. `applyRSSIndirection(enabled=false, ...)` calls
`rssEnabled.Store(false)`. The rebalance loop reads it at the
top of every tick:

```go
if !rssEnabled.Load() || workers <= 1 { continue }
```

Suppression latency: ≤ 1 `SAMPLE_INTERVAL` (1 s) from disable to
the first post-disable tick. No rebalance write can happen after
disable is observed. Kill-switch + daemon-restart is NO LONGER
required — `applyRSSIndirection` already restores defaults via
`restoreDefaultRSSIndirection` (existing behaviour). Withdrawn:
the R2 draft's "config reloads require a daemon restart" claim.

**Config reload** (re-apply path `pkg/daemon/daemon.go:2361-2394`):
unchanged. Its call to `applyRSSIndirection` / its kill-switch
path both bump `rssIndirectionEpoch`. The rebalance loop observes
the bump on its next tick (§4.5) and resets state.

### 4.7 Constants

```go
const (
    SAMPLE_INTERVAL         = time.Second
    minElapsed              = 750 * time.Millisecond // jitter guard
    TRIGGER                 = 1.8                    // §4.2a
    STABILITY               = 3
    COOLDOWN                = 10 * time.Second
    MIGRATE_FRACTION        = 0.25
    DEFAULT_WEIGHT          = 20
    MIN_WEIGHT              = 1
    MAX_FAILURES            = 5
    minTrafficPerWindow     = uint64(1000) // pkts
)
```

## 5. Tests (target 33)

All in `pkg/daemon/rss_rebalance_test.go`. Run via
`go test ./pkg/daemon/... -run RSS`.

### 5.1 Parsing (3)

1. `TestParseEthtoolS_ExtractsPerRingPackets` — canned mlx5
   output (real capture from `ge-0-0-2`) → expected map.
2. `TestParseEthtoolS_IgnoresNonRingCounters` — `rx_errors`,
   `tx_bytes`, etc. filtered.
3. `TestParseEthtoolS_HandlesMissingRings` — only `rx0` and
   `rx3` present → map has only those keys.

### 5.2 Imbalance + stability + cooldown (7)

4. `TestImbalance_UnderTriggerDoesNotFire` — rates `[100, 95,
   98, 92, 97, 99]`, ratio 1.04, no increment.
5. `TestImbalance_OverTriggerFires` — rates
   `[500, 100, ..., 100]`, ratio 2.5, increment.
6. `TestImbalance_ExactlyAtTriggerDoesNotFire` — strict `>`.
6a. `TestImbalance_IdleRingSkewFires` — rates `[24, 0, 0, 0, 0, 0]`;
    mean across ALL 6 rings = 4, ratio 6.0, fires. Pins R3
    new-issue #1: trigger must include idle rings in the mean
    (not just non-zero ones).
7. `TestStability_RequiresConsecutive` — 2 imbalanced + 1
   balanced resets counter.
8. `TestStability_NonConsecutiveResets` — imbalanced samples
   interleaved with zero-traffic samples never accumulate (zero
   traffic resets to 0 per §4.2 guard).
9. `TestCooldown_BlocksWithinWindow`.
10. `TestCooldown_AllowsAfterWindow`.

### 5.3 Weight computation (4)

11. `TestComputeWeightShift_ShiftsHotToCold` — 25% of hot's
    weight moves to cold.
12. `TestComputeWeightShift_NeverDropsBelowMinWeight` — clamp
    to `MIN_WEIGHT = 1`.
13. `TestComputeWeightShift_NoopWhenBalanced` — equal rates in
    → equal weights out.
14. `TestComputeWeightShift_TiebreakByLowestIndex` — two rings
    tied on rate (both cold); pick the lower-index one.

### 5.4 Guards for degenerate samples (R1 HIGH-4 closure) (4)

15. `TestGuard_FirstSampleSeedsOnly` — fresh state; first tick
    reads counters, sets baseline, no imbalance check.
16. `TestGuard_ZeroTotalTrafficResetsImbalance` — after 2
    imbalanced samples, a zero-total sample zeros the counter.
17. `TestGuard_SingleNonZeroRingFiresRatio` (R5 Finding 3
    correction — was previously inverted): 1 ring has high delta,
    5 have zero, all 6 are in the managed domain → max/mean = 6,
    ratio fires. Pins the §4.2 R4-Finding-1 fix that domain
    rings count even when zero. (The OLD test asserted skip;
    that was the wrong semantics.)
18. `TestGuard_CounterResetTreatedAsZeroDelta` — current <
    previous on at least one ring; that ring's delta is 0,
    not negative/wrapped.

### 5.5 Ethtool invocation + failure (3)

19. `TestApplyWeights_InvokesEthtoolXWithExpectedArgs` — stub
    executor; verify exact `ethtool -X <iface> weight ...`
    argv.
20. `TestApplyWeights_StderrExitCodeSurfaced` — stub returns
    exit 1 + stderr "invalid weight"; log carries the stderr
    string; `consecutiveFailures` advances.
21. `TestApplyWeights_PermanentSkipAfterMaxFailures` — 5
    consecutive failures → `permanentSkip=true`; subsequent
    ticks skip this iface silently.

### 5.6 Lifecycle + driver gate (4)

22. `TestLoop_StopsOnContextCancel` — goroutine returns within
    2× sample interval of cancel.
23. `TestLoop_SkipsNonMlx5Iface` — stub driver = "virtio"; no
    ethtool write.
24. `TestLoop_SkipsOnRSSDisabled` — `rssEnabled.Store(false)`
    while loop running; no write on next tick, even if
    imbalanced.
25. `TestLoop_MultiInterfaceStateIsolation` — two ifaces; state
    machine per iface independent (one's failure / skip
    doesn't affect the other).

### 5.7 Concurrency + ConfigGen / Epoch (R2 F6, R4 F3, R5 F1+2, R6 F2)

26. `TestConcurrency_StaleWeightsAbandonedOnConfigGenChange` —
    the core race test. Mock: compute-then-block-on-lock;
    simulate `reapplyRSSIndirection` bumping ConfigGen during
    the block; verify the rebalance iteration ABANDONS its
    stale weights and does not call `applyWeights`. Pins R2
    Finding 6 + R4 Finding 3.
27. `TestConcurrency_EpochBumpResetsCurrentWeights` — state has
    `currentWeights = [10, 30, 20, 20, 20, 20]` +
    `consecutiveImbalanced=3`; external bump the Epoch (e.g.
    boot apply ran); next tick resets to equal weights +
    counter=0 + cooldown refreshed.
28. `TestConcurrency_WorkersGreaterThanRingCount` — `workers=8`,
    `ringCount(iface)=6`; `currentWeights` length = 6.
29. `TestConcurrency_FailedApplyStillBumpsConfigGen` (R6 second
    blocker pin) — mock `applyRSSIndirection` returning an
    error from inside the locked path; verify `ConfigGen`
    advanced anyway. Pins the §3.2 invariant that ConfigGen
    bumps on every public-entry INVOCATION regardless of write
    outcome, distinguishing it from `Epoch` which bumps only on
    SUCCESS. Without this, a failed-apply-then-disable sequence
    could slip past the rebalance loop's stale-write guard.
30. `TestConcurrency_RebalanceWriteDoesNotBumpGlobalCounters`
    (R5 Finding 2 pin) — successful rebalance write on iface A;
    verify `Epoch` and `ConfigGen` are unchanged afterward.
    Confirms the cross-iface isolation invariant.
31. `TestConcurrency_AbandonsWhenControlPlaneFiresBetweenSnapshotAndLock`
    (R7 Finding 1 pin) — drive the loop to the
    snapshot-then-blocked-on-lock state with a stub. While
    blocked, a `reapplyRSSIndirection` invocation runs on
    another goroutine (bumps ConfigGen). When the rebalance
    re-acquires the lock, the post-lock re-check fires and the
    rebalance abandons. Pins the snapshot-vs-lock-acquisition
    window race.
32. `TestLiveReload_AllowlistShrinkTakesEffectNextTick` (R9
    Finding 2 pin a) — initial state has `allowed = [a, b, c]`;
    rebalance loop iterating ticks. External code calls
    `applyRSSIndirection` with `allowed = [a, c]` (b removed).
    Next tick: loop iterates only `[a, c]`; iface `b` state is
    not touched and no ethtool write fires for `b`. Pins the
    "live reload via atomic.Pointer" claim.
33. `TestLiveReload_WorkerCountChangeTakesEffectNextTick` (R9
    Finding 2 pin b) — initial state `workers = 4`,
    `currentWeights = [W, W, W, W]`. External code calls
    `applyRSSIndirection` with `workers = 2`. Next tick after
    the Epoch bump: per-iface state resets, `currentWeights`
    re-seeds to length 2 = `[W, W]`. Pins the worker-count
    reload path.

Test count: **33** (was 31; +2 R9 pins).

## 6. Validation

### 6.1 Pre-flight

Before the 10-run fairness measurement:

1. Confirm loss cluster at post-#832 master.
2. Reapply canonical `cos-iperf-config.set`.
3. **Empirical trigger calibration (R1 HIGH-8)**: record 10
   samples of `ethtool -S ge-0-0-2` at 1 s intervals with
   iperf3 running, but BEFORE deploying the rebalance
   binary. Compute observed `max/mean` ratio each sample.
   If the median observed ratio is already ≥ `TRIGGER`, that
   means RSS hashing alone produces >1.8× variance on this
   workload and the trigger will fire on every sample. Bump
   `TRIGGER` to the 80th-percentile observed ratio + 0.2 (a
   margin above typical spread). Document chosen value in
   `findings.md`.
4. Pre-deploy baseline: 3 iperf3 runs × 2 ports, record CoV.
   Expect ~40% CoV on p5202 per #830 data.

### 6.2 Build + deploy

```bash
make build build-ctl
sg incus-admin -c "BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    ./test/incus/cluster-setup.sh deploy all"
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c \
    'sed -i s/\"4\"/\"6\"/g /etc/xpf/.configdb/active.json; \
     systemctl restart xpfd; sleep 3; \
     rm -f /tmp/cos-iperf-sets.set'"
sg incus-admin -c "test/incus/apply-cos-config.sh loss:xpf-userspace-fw0"
```

### 6.3 10-run measurement

Per port in `{5201, 5202}`, 10 × 15 s runs:

```bash
for i in $(seq 1 10); do
  sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -P 16 -t 15 -p <PORT> -J" \
    > /tmp/p<PORT>-run-$i.json
  sleep 25  # > COOLDOWN so rebalance can react between runs
done
```

Also capture:
- `ethtool -x ge-0-0-2` at start + every 3 runs + end — proves
  the indirection table actually changed.
- `journalctl -u xpfd --since=<ts> | grep 'rss rebalance'` —
  proves the rebalance logic fired.

### 6.4 Acceptance

PASS iff ALL:
- p5202 CoV ≤ 25% on ≥ 8 of 10 runs.
- p5201 CoV ≤ 15% on ≥ 8 of 10 runs.
- Aggregate Gbps ≥ 0.91 (p5201), ≥ 9.08 (p5202) on every run.
- 0 retransmit-count increase vs baseline medians.
- Log shows ≥ 1 `rss rebalance applied` line (else feature was
  inactive and the result is not attributable to #835).
- No `consecutiveFailures ≥ MAX_FAILURES` warnings.
- **`make test-failover` passes** (R9 Finding 1 — the mandatory
  CLAUDE.md requirement is now in the PASS gate, not just §1
  prose. Run after the 10-run measurement completes; failover
  must succeed without RSS-rebalance interference, and the
  rebalance loop on the new primary must seed cleanly via the
  tick-start ConfigGen snapshot path).

### 6.5 Negative-finding protocol

If ANY acceptance condition fails: revert **only** the files
this PR touched (resolves R3 new-issue #3 — no broad
`pkg/daemon/` revert that could discard unrelated daemon work):

```bash
git checkout master -- \
    pkg/daemon/rss_rebalance.go \
    pkg/daemon/rss_rebalance_test.go \
    pkg/daemon/rss_indirection.go \
    pkg/daemon/daemon.go
rm -f docs/pr/835-slice-d-rss/findings.md  # will be rewritten
```

Document result in `findings.md` with the same discipline as
#833 / #834 (reasoning, per-run numbers, what went wrong,
whether it's a fixable parameter issue or an algorithmic
dead-end). Close PR. Do not keep iterating on parameter tuning
trying to rescue a regression.

## 7. Workflow

1. Architect R5 (R3 was the clean rewrite; R4 + R5 were targeted
   patches; this is the current consolidated state).
2. Codex plan review → iterate to PLAN-READY YES (currently in
   round R5 → R6).
3. Implement `rss_rebalance.go` + test file + `rss_indirection.go`
   mutex/epoch/configgen/atomic-state additions + `daemon.go`
   wiring. 33 unit tests. Aim for single commit; split if
   reviewer demands.
4. Two-angle code review (Codex behavioral + Go second-angle).
5. Deploy + calibration (§6.1) + 10-run measurement.
6. Merge or revert per §6.5.

## 8. Risks & pre-registered outs

- **R1 — weights-only path wrong on non-mlx5 NIC**: gated by
  `mlx5Driver` constant; non-mlx5 silently skipped. Follow-up
  PR if another driver ever joins the deployment mix.
- **R2 — mid-traffic rewrite disruption**: spike (§4.0) showed
  35 retransmits across 2 mid-flight rewrites; baseline noise
  floor. If production workload shows worse, revert.
- **R3 — convergence oscillates**: COOLDOWN 10s + STABILITY 3
  + MIGRATE 25% are conservative. §6.5 protocol if
  convergence doesn't land within 10-run window.
- **R4 — TRIGGER too low for this workload**: §6.1 calibration
  bumps it before the 10-run measurement.
- **R5 — epoch race on reconcile / boot vs rebalance**:
  addressed by §4.5 ConfigGen snapshot + re-check; tests #26 + #29 pin.
- **R6 — TEST-ENV hardware drift**: mlx5 VF used here has 6 RX
  rings. Non-mlx5 deployments or different ring counts are
  out-of-scope.
- **R7 — `make test-failover` regression**: rebalance goroutine
  stops cleanly on shutdown; failover re-runs
  `applyRSSIndirection` on the new primary's boot before the
  rebalance loop starts. No cross-node state. Mandatory per
  CLAUDE.md.

## 9. Open questions

- **Q1.** 33 tests adequate? **Draft:** Yes; §5.7 closes the
  R2 Finding 6 gap with a dedicated race test.
- **Q2.** Should `currentWeights` be persisted across daemon
  restarts? **Draft:** No — seed to equal each run. Persistence
  adds a config surface and the cooldown naturally re-converges
  within seconds anyway.
- **Q3.** Should `TRIGGER` / `COOLDOWN` / `MIGRATE_FRACTION` be
  config knobs? **Draft:** No in v1. Hardcoded. A follow-up
  PR can expose them after the defaults prove out.

## 10. R1 + R2 finding map (where each issue is resolved)

| Finding | Severity | Section resolving |
|---------|:--------:|-------------------|
| R1-1 slot-move vs weights-only | CRITICAL | §4.3, §4.4 (weights-only; no fallback) |
| R1-2 in-flight disruption unproven | HIGH | §4.0 empirical spike |
| R1-3 convergence handwaved | HIGH | §4.3a worked 4-iter analysis (explicitly idealised) |
| R1-4 divide-by-zero / NaN | HIGH | §4.2 guards; §5.4 tests #15-#18 |
| R1-5 kill switch / reload regression | HIGH | §4.6 (runtime disable via atomic; no restart needed) |
| R1-6 locking race | HIGH | §3.2 + §4.5 rssWriteMu + epoch; §4.5 abandon-on-epoch; test #26 |
| R1-7 test coverage gaps | HIGH | §5.5 + §5.6 + §5.7 multi-iface + workers>rings + stderr + race |
| R1-8 `1.8` defensibility | HIGH | §4.2a multinomial derivation; §6.1 empirical calibration |
| R1-9 `mlx5` → `mlx5_core` | HIGH | §4.4 uses existing `mlx5Driver` constant |
| R1-10 plan quality / overclaims | HIGH | R3 clean rewrite removes doc-level contradictions |
| R2-6 stale-weights race after lock | HIGH (repeat) | §4.5 ConfigGen snapshot + re-check; tests #26 + #29 |
| R3 new-1 idle-ring skew invisible | HIGH | §4.2 trigger computes max/mean across ALL rings incl. zero |
| R3 new-2 self-deadlock on nested mutex | HIGH | §3.2 mutex wraps ONLY public entry points; `applyRSSIndirectionOne` assumes caller holds lock |
| R3 new-3 revert too broad | HIGH | §6.5 reverts only the 4 files this PR touches |
| R3 new-4 allowlist reload | HIGH | §3.2 atomic `rssAllowedRef/rssEnabled/rssWorkers`; §4.5 reads live on each tick |
| R3 partial R1-F5 reload | HIGH | same as R3 new-4 — atomic live state |
| R3 partial R1-F6 nested mutex | HIGH | same as R3 new-2 — single public wrapper |
| R4 Finding #1 idle-ring guard inconsistency | HIGH | §4.2 guard on `len(currentWeights) < 2` not `nonZeroRings < 2`; §4.3 argmin over full domain incl. idle rings; §4.2 + pseudocode both use same domain `0..ringCount-1` |
| R4 Finding #2 kill-switch nested mutex | HIGH | §3.2 split into public-locked / `...Locked`-unlocked variants; `apply(enabled=false)` calls `restoreDefaultLocked` |
| R4 Finding #3 reload-without-write race | HIGH | §3.2 `rssConfigGen` bumps on every invocation regardless of write success; §4.5 pseudocode re-checks ConfigGen post-lock |
| R5 Finding 1 ConfigGen snapshot order | HIGH | §4.5 snapshot now BEFORE `computeWeightShift` |
| R5 Finding 2 cross-iface coupling via global counters | HIGH | §3.2 explicit: rebalance writes do NOT bump global Epoch/ConfigGen; §4.5 pseudocode dropped the post-write bumps |
| R5 Finding 3 contradictory test #17 | HIGH | §5.4 test #17 inverted: now `FiresRatio` not `SkipsRatio` |
| R5 Finding 4 stale R3/Epoch references | MED | §1 Status updated to R5; §3.2 Epoch/ConfigGen semantics distinguished; §7 workflow updated |
| R6 Finding 1 §4.5/§8/§10 prose still epoch-only | HIGH | §4.5 prose, §8 risk text, §10 row R2-6 all updated to ConfigGen mechanism |
| R6 Finding 2 no test for failed-apply ConfigGen bump | HIGH | §5.7 test #29 (`TestConcurrency_FailedApplyStillBumpsConfigGen`) + #30 (`TestConcurrency_RebalanceWriteDoesNotBumpGlobalCounters`) added |
| R7 Finding 1 snapshot-vs-lock window | HIGH | §4.5 pseudocode adds defence-in-depth re-load of enabled/workers/allowed under the lock; test #31 pins the bump-during-block case |
| R7 Finding 2 test count drift (28 vs 30) | LOW | unified to 31 across §1, §3.1, §5, §5.7, §7, §9 |
| R8 Finding 1 reapply-without-state-change race | HIGH | §4.5 ConfigGen snapshot moved to FIRST line of tick body (covers sample window); pre-existing post-lock re-check still applies |
| R8 Finding 2 test count split (30 vs 31) | LOW | §1 + §9 Q1 both updated to 31 |
| R8 Finding 3 finding-map missing R8 | LOW | this row |
| R9 Finding 1 failover not in PASS gate | HIGH | §6.4 PASS conditions now include `make test-failover passes` |
| R9 Finding 2 live-reload tests missing | HIGH | §5.7 tests #32 (allowlist shrink) + #33 (worker-count change) added |
