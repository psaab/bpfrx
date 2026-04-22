// Copyright 2026 xpf Authors
//
// #835 Slice D — RSS indirection rebalance loop.
//
// Periodically samples per-RX-ring packet counters via `ethtool -S`,
// detects imbalance across the managed ring domain, and rebalances
// the indirection-table weights via `ethtool -X <iface> weight ...`
// when the imbalance persists past a stability window.
//
// Composes with #830 Slice B (per-binding virtual-time gate) — Slice B
// bounds per-binding progress drift; Slice D fixes the upstream RSS
// distribution so per-binding load is even to begin with.
//
// All ethtool RSS writes serialize on rssWriteMu (defined in
// rss_indirection.go). The loop snapshots rssConfigGen at the top of
// each tick and re-checks after acquiring the lock; on mismatch, the
// in-flight rebalance is abandoned (handles boot/reapply/kill-switch
// firing between snapshot and write).
//
// Per-iface state is purely local; rebalance writes do NOT bump the
// global Epoch / ConfigGen counters (those are control-plane signals
// only — a successful rebalance on iface A must not invalidate
// iface B's per-iface state).

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Constants per plan §4.7. Hardcoded in v1; can become config knobs
// in a follow-up after defaults prove out empirically.
const (
	rssRebalanceSampleInterval  = time.Second
	rssRebalanceMinElapsed      = 750 * time.Millisecond
	rssRebalanceTriggerRatio    = 1.8
	rssRebalanceStability       = 3
	rssRebalanceCooldown        = 10 * time.Second
	rssRebalanceMigrateFraction = 0.25
	rssRebalanceDefaultWeight   = 20
	rssRebalanceMinWeight       = 1
	rssRebalanceMaxFailures     = 5
	rssRebalanceMinTrafficPkts  = uint64(1000)
)

// rssRebalanceState tracks per-iface state for the rebalance loop.
type rssRebalanceState struct {
	lastSampleCounters    map[int]uint64
	lastSampleTime        time.Time
	firstSample           bool
	currentWeights        []int
	consecutiveImbalanced int
	lastRebalanceTime     time.Time
	consecutiveFailures   int
	permanentSkip         bool
	lastSeenEpoch         uint64
}

// runRSSRebalanceLoop is the goroutine entry point. It reads the live
// rssEnabled / rssWorkers / rssAllowed atomics on every tick, so
// runtime config changes take effect on the next tick without
// restarting this goroutine.
//
// Stops cleanly on ctx cancellation.
func runRSSRebalanceLoop(ctx context.Context, execer rssExecutor) {
	state := make(map[string]*rssRebalanceState)
	ticker := time.NewTicker(rssRebalanceSampleInterval)
	defer ticker.Stop()
	slog.Info("rss rebalance loop started",
		"sample_interval", rssRebalanceSampleInterval,
		"trigger_ratio", rssRebalanceTriggerRatio,
		"stability_samples", rssRebalanceStability,
		"cooldown", rssRebalanceCooldown,
		"migrate_fraction", rssRebalanceMigrateFraction)
	for {
		select {
		case <-ctx.Done():
			slog.Info("rss rebalance loop stopped")
			return
		case <-ticker.C:
		}
		rebalanceTick(state, execer)
	}
}

// rebalanceTick is a single iteration of the loop body, factored out
// so tests can drive it directly without spawning the goroutine.
func rebalanceTick(state map[string]*rssRebalanceState, execer rssExecutor) {
	// R8 Finding 1: snapshot ConfigGen FIRST THING in the tick body —
	// before any reads of enabled/workers/allowed and before counter
	// sampling. The post-lock re-check below catches any control-plane
	// invocation that happened during the entire tick.
	tickGenSnapshot := LoadRSSConfigGen()

	enabled := LoadRSSEnabled()
	workers := LoadRSSWorkers()
	allowed := LoadRSSAllowed()
	if !enabled || workers <= 1 || len(allowed) == 0 {
		return
	}

	for _, iface := range allowed {
		if iface == "lo" {
			continue
		}
		if execer.readDriver(iface) != mlx5Driver {
			continue
		}
		s, ok := state[iface]
		if !ok {
			// Code-review FA4 (MED): seed currentWeights at first
			// creation time, NOT only on epoch-reset. Otherwise an
			// idempotent boot/reapply that skips the ethtool write
			// (table already matches target) leaves Epoch == 0,
			// our lastSeenEpoch == 0, no reset fires, and
			// currentWeights stays nil → permanently skipped via
			// the len < 2 guard. Seeding here unconditionally fixes
			// that.
			ringCount := computeRingCount(workers, execer.readQueueCount(iface))
			s = &rssRebalanceState{
				firstSample:    true,
				currentWeights: equalWeights(ringCount),
				lastSeenEpoch:  LoadRSSEpoch(),
			}
			state[iface] = s
		}
		if s.permanentSkip {
			continue
		}

		// Reconcile epoch: control-plane wrote since our last tick →
		// re-seed our shadow state to match.
		curEpoch := LoadRSSEpoch()
		expectedRingCount := computeRingCount(workers, execer.readQueueCount(iface))
		// Code-review R2 FA4 (MED, partial fix): also re-seed when
		// the expected ring count differs from our current shadow
		// length. An idempotent control-plane reapply with new
		// rssWorkers (or new queue count) doesn't bump Epoch (the
		// table already matches), so the epoch-only check would
		// miss the resize. Detecting the size mismatch directly
		// catches this case.
		needReseed := curEpoch != s.lastSeenEpoch ||
			len(s.currentWeights) != expectedRingCount
		if needReseed {
			s.currentWeights = equalWeights(expectedRingCount)
			s.consecutiveImbalanced = 0
			s.lastRebalanceTime = time.Now() // refresh cooldown
			s.firstSample = true             // invalidate counter baseline
			s.lastSeenEpoch = curEpoch
		}
		// Code-review R2 FA2: snapshot Epoch RIGHT HERE — after
		// reconcile but before any sample / weight / lock work — so
		// the post-lock Epoch re-check below detects any control-
		// plane apply that completes during our compute / lock-wait
		// window.
		tickEpochSnapshot := curEpoch

		sample, err := readEthtoolS(iface, execer)
		if err != nil {
			s.consecutiveFailures++
			if s.consecutiveFailures >= rssRebalanceMaxFailures {
				slog.Warn("rss rebalance: iface permanently skipped after sample failures",
					"iface", iface, "err", err,
					"failures", s.consecutiveFailures)
				s.permanentSkip = true
			}
			continue
		}

		if s.firstSample {
			s.lastSampleCounters = sample
			s.lastSampleTime = time.Now()
			s.firstSample = false
			continue
		}

		elapsed := time.Since(s.lastSampleTime)
		if elapsed < rssRebalanceMinElapsed {
			continue
		}

		delta := deltaSafeAgainstResets(sample, s.lastSampleCounters)
		s.lastSampleCounters = sample
		s.lastSampleTime = time.Now()

		if totalPackets(delta) < rssRebalanceMinTrafficPkts {
			s.consecutiveImbalanced = 0
			continue
		}

		// Guard on managed-domain count, NOT active-ring count
		// (R4 Finding #1). Idle-ring skews like [24,0,0,0,0,0] have
		// only 1 active ring but ARE the skew we want to fire on.
		if len(s.currentWeights) < 2 {
			s.consecutiveImbalanced = 0
			continue
		}

		domainSize := len(s.currentWeights)
		maxR, meanR := maxMeanOverDomain(delta, domainSize)
		if float64(maxR) > meanR*rssRebalanceTriggerRatio {
			s.consecutiveImbalanced++
		} else {
			s.consecutiveImbalanced = 0
		}

		if s.consecutiveImbalanced < rssRebalanceStability {
			continue
		}
		if time.Since(s.lastRebalanceTime) < rssRebalanceCooldown {
			continue
		}

		// R5 F1 + R8 F1: use the tick-start ConfigGen snapshot. Any
		// control-plane invocation between tick start and the post-
		// lock re-check below bumps ConfigGen and forces abandon.
		genBefore := tickGenSnapshot
		// Code-review R2 FA2: also use the per-iface tick-start
		// Epoch snapshot (taken right after the reconcile branch,
		// before sampling, weights, or anything else). Captures
		// any successful control-plane apply that landed during
		// our compute / lock-wait window.
		epochBefore := tickEpochSnapshot

		newWeights := computeWeightShift(delta, s.currentWeights)

		// Code-review FA5 (LOW): if computeWeightShift returned the
		// unchanged vector (e.g. hot ring already at MIN_WEIGHT and
		// no shift possible, or perfectly balanced), don't bother
		// taking the lock or writing — would just emit a fake "rss
		// rebalance applied" log every cooldown.
		if weightsEqual(newWeights, s.currentWeights) {
			s.consecutiveImbalanced = 0
			s.lastRebalanceTime = time.Now() // back off; revisit after cooldown
			continue
		}

		RssWriteMuLock()
		// Post-lock ConfigGen re-check (R2 F6 + R4 F3 + R5 F1 + R8 F1).
		if LoadRSSConfigGen() != genBefore {
			RssWriteMuUnlock()
			s.lastSeenEpoch = LoadRSSEpoch() - 1 // force reconcile next tick
			continue
		}
		// Code-review R2 FA2: post-lock Epoch re-check. A control-
		// plane apply that completed under the writer's lock between
		// our tick-start snapshot and our lock acquisition has
		// bumped Epoch. Our currentWeights are stale; abandon.
		if LoadRSSEpoch() != epochBefore {
			RssWriteMuUnlock()
			s.lastSeenEpoch = LoadRSSEpoch() - 1 // force reconcile next tick
			continue
		}
		// R7 F1 defence in depth: re-load enabled / workers / allowed
		// under the lock and abandon if any control-plane state changed
		// even in a path that somehow missed ConfigGen.
		if !LoadRSSEnabled() || LoadRSSWorkers() <= 1 ||
			!ifaceInAllowed(iface, LoadRSSAllowed()) {
			RssWriteMuUnlock()
			s.lastSeenEpoch = LoadRSSEpoch() - 1
			continue
		}
		err = applyWeights(iface, newWeights, execer)
		// R5 F2: rebalance writes do NOT bump the global Epoch /
		// ConfigGen — those are control-plane signals only.
		RssWriteMuUnlock()

		if err != nil {
			s.consecutiveFailures++
			if s.consecutiveFailures >= rssRebalanceMaxFailures {
				slog.Warn("rss rebalance: iface permanently skipped after apply failures",
					"iface", iface, "err", err,
					"failures", s.consecutiveFailures)
				s.permanentSkip = true
			}
			continue
		}
		s.currentWeights = newWeights
		s.lastRebalanceTime = time.Now()
		s.consecutiveImbalanced = 0
		s.consecutiveFailures = 0
		slog.Info("rss rebalance applied",
			"iface", iface, "weights", newWeights,
			"delta_pkts", delta)
	}
}

// readEthtoolS invokes `ethtool -S <iface>` and parses the per-RX-ring
// packet counters into a map keyed by ring index.
func readEthtoolS(iface string, execer rssExecutor) (map[int]uint64, error) {
	out, err := execer.runEthtool("-S", iface)
	if err != nil {
		return nil, fmt.Errorf("ethtool -S %s: %w", iface, err)
	}
	return parseEthtoolS(out), nil
}

// parseEthtoolS extracts `rx<N>_packets: <value>` lines from ethtool
// -S output. Returns map[ringIndex]packetCount. Ignores byte counters
// and any non-rx-ring counters (rx_errors, tx_*, etc.).
func parseEthtoolS(out []byte) map[int]uint64 {
	result := make(map[int]uint64)
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Looking for: "rx<N>_packets: <value>"
		if !strings.HasPrefix(line, "rx") {
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := line[:colonIdx]
		val := strings.TrimSpace(line[colonIdx+1:])
		// key format: rx<N>_packets — match exactly that.
		if !strings.HasSuffix(key, "_packets") {
			continue
		}
		ringPart := strings.TrimPrefix(key, "rx")
		ringPart = strings.TrimSuffix(ringPart, "_packets")
		ringIdx, err := strconv.Atoi(ringPart)
		if err != nil {
			continue
		}
		count, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			continue
		}
		result[ringIdx] = count
	}
	return result
}

// deltaSafeAgainstResets computes per-ring deltas. If a counter is
// non-monotonic (current < previous, e.g. from driver restart or
// counter wrap), that ring's delta is treated as 0 for this tick;
// the new value becomes the next baseline.
func deltaSafeAgainstResets(current, previous map[int]uint64) map[int]uint64 {
	delta := make(map[int]uint64, len(current))
	for ring, cur := range current {
		prev, ok := previous[ring]
		if !ok || cur < prev {
			delta[ring] = 0
			continue
		}
		delta[ring] = cur - prev
	}
	return delta
}

// totalPackets sums the per-ring delta values.
func totalPackets(delta map[int]uint64) uint64 {
	var total uint64
	for _, v := range delta {
		total += v
	}
	return total
}

// maxMeanOverDomain computes (max, mean) across the FULL managed
// rebalance domain (ring indices 0..domainSize-1). Idle rings
// (missing from delta map) count as 0 toward the mean. This is the
// R4 Finding #1 semantic: idle-ring skews like [24,0,0,0,0,0] yield
// max=24, mean=4, ratio=6.0 — fires.
func maxMeanOverDomain(delta map[int]uint64, domainSize int) (max uint64, mean float64) {
	if domainSize <= 0 {
		return 0, 0
	}
	var sum uint64
	for ring := 0; ring < domainSize; ring++ {
		v := delta[ring] // 0 if not present
		if v > max {
			max = v
		}
		sum += v
	}
	mean = float64(sum) / float64(domainSize)
	return max, mean
}

// computeWeightShift produces a new currentWeights vector by moving
// MIGRATE_FRACTION of the hottest ring's weight to the coldest ring.
// argmin/argmax are taken across the FULL rebalance domain (idle
// rings eligible as cold). Ties broken by lowest index. Never drops
// any weight below MIN_WEIGHT.
func computeWeightShift(delta map[int]uint64, current []int) []int {
	out := append([]int(nil), current...)
	if len(out) < 2 {
		return out
	}

	// argmax + argmin across domain 0..len(out)-1.
	var hot, cold int = 0, 0
	hotRate := delta[0]
	coldRate := delta[0]
	for ring := 1; ring < len(out); ring++ {
		v := delta[ring]
		if v > hotRate {
			hotRate = v
			hot = ring
		}
		if v < coldRate {
			coldRate = v
			cold = ring
		}
	}
	if hot == cold {
		return out // perfectly balanced
	}

	shift := int(float64(out[hot]) * rssRebalanceMigrateFraction)
	if shift < 1 {
		shift = 1
	}
	maxShift := out[hot] - rssRebalanceMinWeight
	if maxShift < 0 {
		maxShift = 0
	}
	if shift > maxShift {
		shift = maxShift
	}
	if shift == 0 {
		return out // can't shift without starving hot below MIN_WEIGHT
	}
	out[hot] -= shift
	out[cold] += shift
	return out
}

// applyWeights invokes `ethtool -X <iface> weight w0 w1 ... wN`.
// PRECONDITION: rssWriteMu is held by the caller.
func applyWeights(iface string, weights []int, execer rssExecutor) error {
	args := []string{"-X", iface, "weight"}
	for _, w := range weights {
		args = append(args, strconv.Itoa(w))
	}
	out, err := execer.runEthtool(args...)
	if err != nil {
		return fmt.Errorf("ethtool %v failed: %w (output: %s)",
			args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// equalWeights returns a vector of length n filled with the default
// weight value.
func equalWeights(n int) []int {
	if n <= 0 {
		return nil
	}
	out := make([]int, n)
	for i := range out {
		out[i] = rssRebalanceDefaultWeight
	}
	return out
}

// computeRingCount returns the rebalance-domain size = min(workers,
// queue_count). When workers > queue_count, rings beyond queue_count
// don't exist and are not part of the domain.
func computeRingCount(workers, queueCount int) int {
	if workers <= 0 || queueCount <= 0 {
		return 0
	}
	if workers < queueCount {
		return workers
	}
	return queueCount
}

// ifaceInAllowed reports whether iface is in the allowlist.
func ifaceInAllowed(iface string, allowed []string) bool {
	for _, a := range allowed {
		if a == iface {
			return true
		}
	}
	return false
}

// weightsEqual reports whether two weight vectors are element-wise
// equal. Used to skip no-op rebalance writes (FA5).
func weightsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
