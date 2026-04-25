// Copyright 2026 xpf Authors
//
// #840 Slice D v2 — RSS indirection rebalance loop.
//
// Periodically samples per-RX-ring packet counters from the
// xpf-userspace-dp helper's BindingStatus snapshot, detects imbalance
// across the managed ring domain, and rebalances the indirection-
// table weights via `ethtool -X <iface> weight ...` when the imbalance
// persists past a stability window.
//
// History: #835 (closed) implemented the same algorithm against
// `ethtool -S` per-RX-ring counters. Empirical deploy on mlx5 SR-IOV
// VF + AF_XDP zero-copy showed every per-queue ethtool counter frozen
// (driver bypass under zero-copy), so the trigger never fired. #840
// re-introduces the same algorithm with the userspace-dp per-binding
// RX counter as the live signal source. Bindings are 1:1 with RX
// rings, so per-binding RX is per-RX-ring rate.
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

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Constants per #835 plan §4.7. Hardcoded in v1; can become config
// knobs in a follow-up after defaults prove out empirically.
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

// bindingRXReader returns per-RX-ring cumulative RX packet counters
// for iface, keyed by ring index. Bindings are 1:1 with RX rings on
// the AF_XDP zero-copy path, so binding.QueueID is the ring index.
//
// Returns (nil, error) if the userspace dataplane helper is
// unavailable. The rebalance loop treats sample errors as recoverable
// (see rssRebalanceMaxFailures), so transient helper unreachability
// does not permanently disable rebalance for an iface.
type bindingRXReader interface {
	ReadBindingRX(iface string) (map[int]uint64, error)
}

// userspaceBindingRXReader wraps a *dpuserspace.Manager and produces
// per-RX-ring RX-packet snapshots from the helper's Status() reply.
type userspaceBindingRXReader struct {
	mgr *dpuserspace.Manager
}

// ReadBindingRX returns map[ring_index]cumulative_rx_packets for iface.
func (r userspaceBindingRXReader) ReadBindingRX(iface string) (map[int]uint64, error) {
	if r.mgr == nil {
		return nil, fmt.Errorf("userspace dataplane manager not available")
	}
	status, err := r.mgr.Status()
	if err != nil {
		return nil, fmt.Errorf("userspace status: %w", err)
	}
	out := make(map[int]uint64, len(status.Bindings))
	for _, b := range status.Bindings {
		if b.Interface != iface {
			continue
		}
		out[int(b.QueueID)] = b.RXPackets
	}
	return out, nil
}

// rssRebalanceState tracks per-iface state for the rebalance loop.
type rssRebalanceState struct {
	lastSampleCounters    map[int]uint64
	lastSampleTime        time.Time
	firstSample           bool
	currentWeights        []int
	consecutiveImbalanced int
	lastRebalanceTime     time.Time
	// applyFailures tracks ethtool -X errors only. A run of
	// rssRebalanceMaxFailures permanently disables rebalance for
	// this iface — a write that consistently fails is unrecoverable
	// (kernel rejects our weight vector). Reset on successful apply.
	applyFailures int
	// sampleFailures tracks ReadBindingRX errors only — typically
	// the userspace helper being unreachable mid-restart. These are
	// recoverable: we reset to 0 on the first successful sample
	// rather than permanently skipping the iface.
	sampleFailures int
	permanentSkip  bool
	lastSeenEpoch  uint64
	// sampleShapeWarned suppresses repeated logging of sample-vs-
	// expected-domain mismatches (e.g. helper queue_count plan less
	// than sysfs queue count due to cross-iface min). One Warn per
	// mismatch transition.
	sampleShapeWarned bool
}

// runRSSRebalanceLoop is the goroutine entry point. It reads the live
// rssEnabled / rssWorkers / rssAllowed atomics on every tick, so
// runtime config changes take effect on the next tick without
// restarting this goroutine.
//
// reader is nil-safe: if the userspace dataplane is not in use, the
// caller passes a nil reader and the loop sees rssEnabled==false and
// returns immediately each tick.
//
// Stops cleanly on ctx cancellation.
func runRSSRebalanceLoop(ctx context.Context, execer rssExecutor, reader bindingRXReader) {
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
		rebalanceTick(state, execer, reader)
	}
}

// rebalanceTick is a single iteration of the loop body, factored out
// so tests can drive it directly without spawning the goroutine.
func rebalanceTick(state map[string]*rssRebalanceState, execer rssExecutor, reader bindingRXReader) {
	// #835 R8 Finding 1: snapshot ConfigGen FIRST THING in the tick
	// body — before any reads of enabled/workers/allowed and before
	// counter sampling. The post-lock re-check below catches any
	// control-plane invocation that happened during the entire tick.
	tickGenSnapshot := LoadRSSConfigGen()

	enabled := LoadRSSEnabled()
	workers := LoadRSSWorkers()
	allowed := LoadRSSAllowed()
	if !enabled || workers <= 1 || len(allowed) == 0 {
		return
	}
	if reader == nil {
		// No signal source — loop is a no-op. This is the expected
		// state when xpfd is run without a userspace dataplane.
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
			// #835 FA4: seed currentWeights at first creation, NOT
			// only on epoch-reset. An idempotent boot/reapply that
			// skips the ethtool write (table already matches) leaves
			// Epoch == 0; without seeding here, currentWeights stays
			// nil and the iface is permanently skipped via the
			// len < 2 guard.
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
		// #835 R2 FA4: also re-seed when the expected ring count
		// differs from our current shadow length. An idempotent
		// control-plane reapply with new rssWorkers (or new queue
		// count) doesn't bump Epoch (the table already matches), so
		// the epoch-only check would miss the resize. Detecting the
		// size mismatch directly catches this case.
		needReseed := curEpoch != s.lastSeenEpoch ||
			len(s.currentWeights) != expectedRingCount
		if needReseed {
			s.currentWeights = equalWeights(expectedRingCount)
			s.consecutiveImbalanced = 0
			s.lastRebalanceTime = time.Now()
			s.firstSample = true
			s.lastSeenEpoch = curEpoch
		}
		// #835 R2 FA2: snapshot Epoch right here — after reconcile
		// but before any sample / weight / lock work — so the post-
		// lock Epoch re-check below detects any control-plane apply
		// that completes during our compute / lock-wait window.
		tickEpochSnapshot := curEpoch

		sample, err := reader.ReadBindingRX(iface)
		if err != nil {
			// Codex MED 2: sample failures are recoverable (typically
			// helper restart). Track them in their own counter, but
			// do NOT permanentSkip — log periodically and let the
			// next successful sample reset state. Apply failures
			// (ethtool kernel reject) remain permanently fatal via
			// applyFailures.
			s.sampleFailures++
			if s.sampleFailures == 1 || s.sampleFailures%rssRebalanceMaxFailures == 0 {
				slog.Warn("rss rebalance: sample read failed",
					"iface", iface, "err", err,
					"consecutive_failures", s.sampleFailures)
			}
			continue
		}
		// Reset sample failure counter on any successful read.
		s.sampleFailures = 0

		// Codex HIGH 1: defensive guard against helper bindings
		// covering fewer queues than the rebalance domain expects
		// (e.g. cross-iface queue_count min — see
		// userspace-dp/src/main.rs:1148). Without this, queues with
		// no AF_XDP socket look "cold" and the rebalance moves
		// weight toward them, redirecting traffic into the kernel
		// fallback path.
		//
		// expectedRingCount mirrors the indirection-table active
		// width (#785). If sample shape doesn't match (helper
		// covers fewer queues, or sample is empty during a
		// helper-side reconfigure), skip this tick rather than
		// rebalance with a partial domain.
		if len(sample) != expectedRingCount {
			if !s.sampleShapeWarned {
				slog.Warn("rss rebalance: sample shape != expected domain — skipping",
					"iface", iface,
					"sample_count", len(sample),
					"expected_domain", expectedRingCount,
					"workers", workers)
				s.sampleShapeWarned = true
			}
			// Reset baseline so the next matched-shape sample
			// starts a fresh delta window.
			s.firstSample = true
			s.consecutiveImbalanced = 0
			continue
		}
		// Shape matches — clear the warned flag so a future
		// transition to mismatch logs once again.
		s.sampleShapeWarned = false

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
		// (#835 R4 Finding #1). Idle-ring skews like [24,0,0,0,0,0]
		// have only 1 active ring but ARE the skew we want to fire on.
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

		// #835 R5 F1 + R8 F1: use the tick-start ConfigGen snapshot.
		// Any control-plane invocation between tick start and the
		// post-lock re-check below bumps ConfigGen and forces abandon.
		genBefore := tickGenSnapshot
		// #835 R2 FA2: also use the per-iface tick-start Epoch
		// snapshot (taken right after the reconcile branch, before
		// sampling, weights, or anything else). Captures any
		// successful control-plane apply that landed during our
		// compute / lock-wait window.
		epochBefore := tickEpochSnapshot

		newWeights := computeWeightShift(delta, s.currentWeights)

		// #835 FA5: if computeWeightShift returned the unchanged
		// vector (e.g. hot ring already at MIN_WEIGHT and no shift
		// possible, or perfectly balanced), don't bother taking the
		// lock or writing — would just emit a fake "rss rebalance
		// applied" log every cooldown.
		if weightsEqual(newWeights, s.currentWeights) {
			s.consecutiveImbalanced = 0
			s.lastRebalanceTime = time.Now()
			continue
		}

		RssWriteMuLock()
		// Post-lock ConfigGen re-check (#835 R2 F6 + R4 F3 + R5 F1 + R8 F1).
		if LoadRSSConfigGen() != genBefore {
			RssWriteMuUnlock()
			s.lastSeenEpoch = LoadRSSEpoch() - 1
			continue
		}
		// #835 R2 FA2: post-lock Epoch re-check. A control-plane
		// apply that completed under the writer's lock between our
		// tick-start snapshot and our lock acquisition has bumped
		// Epoch. Our currentWeights are stale; abandon.
		if LoadRSSEpoch() != epochBefore {
			RssWriteMuUnlock()
			s.lastSeenEpoch = LoadRSSEpoch() - 1
			continue
		}
		// #835 R7 F1 defence in depth: re-load enabled / workers /
		// allowed under the lock and abandon if any control-plane
		// state changed even in a path that somehow missed ConfigGen.
		if !LoadRSSEnabled() || LoadRSSWorkers() <= 1 ||
			!ifaceInAllowed(iface, LoadRSSAllowed()) {
			RssWriteMuUnlock()
			s.lastSeenEpoch = LoadRSSEpoch() - 1
			continue
		}
		err = applyWeights(iface, newWeights, execer)
		// #835 R5 F2: rebalance writes do NOT bump the global Epoch /
		// ConfigGen — those are control-plane signals only.
		RssWriteMuUnlock()

		if err != nil {
			s.applyFailures++
			if s.applyFailures >= rssRebalanceMaxFailures {
				slog.Warn("rss rebalance: iface permanently skipped after apply failures",
					"iface", iface, "err", err,
					"failures", s.applyFailures)
				s.permanentSkip = true
			}
			continue
		}
		s.currentWeights = newWeights
		s.lastRebalanceTime = time.Now()
		s.consecutiveImbalanced = 0
		s.applyFailures = 0
		slog.Info("rss rebalance applied",
			"iface", iface, "weights", newWeights,
			"delta_pkts", delta)
	}
}

// deltaSafeAgainstResets computes per-ring deltas. If a counter is
// non-monotonic (current < previous, e.g. from helper restart or
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
// #835 R4 Finding #1 semantic: idle-ring skews like [24,0,0,0,0,0]
// yield max=24, mean=4, ratio=6.0 — fires.
func maxMeanOverDomain(delta map[int]uint64, domainSize int) (max uint64, mean float64) {
	if domainSize <= 0 {
		return 0, 0
	}
	var sum uint64
	for ring := 0; ring < domainSize; ring++ {
		v := delta[ring]
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
		return out
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
		return out
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
// equal. Used to skip no-op rebalance writes (#835 FA5).
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
