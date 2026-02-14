// Package conntrack implements connection tracking garbage collection.
package conntrack

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/dataplane"
	"golang.org/x/sys/unix"
)

// GCStats holds statistics from the most recent GC sweep.
type GCStats struct {
	LastSweepTime       time.Time
	LastSweepDuration   time.Duration
	TotalEntries        int
	EstablishedSessions int
	ExpiredDeleted      int
}

// GC performs periodic garbage collection on the session table.
type GC struct {
	dp       dataplane.DataPlane
	interval time.Duration
	mu       sync.RWMutex
	stats    GCStats
}

// NewGC creates a new session garbage collector.
func NewGC(dp dataplane.DataPlane, interval time.Duration) *GC {
	return &GC{dp: dp, interval: interval}
}

// Stats returns a snapshot of the most recent GC sweep statistics.
func (gc *GC) Stats() GCStats {
	gc.mu.RLock()
	defer gc.mu.RUnlock()
	return gc.stats
}

// Run starts the GC loop. It blocks until ctx is cancelled.
func (gc *GC) Run(ctx context.Context) {
	slog.Info("conntrack GC started", "interval", gc.interval)
	ticker := time.NewTicker(gc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("conntrack GC stopped")
			return
		case <-ticker.C:
			gc.sweep()
		}
	}
}

// expiredSession holds session data needed for cleanup.
type expiredSession struct {
	key dataplane.SessionKey
	val dataplane.SessionValue
}

// expiredSessionV6 holds IPv6 session data needed for cleanup.
type expiredSessionV6 struct {
	key dataplane.SessionKeyV6
	val dataplane.SessionValueV6
}

func (gc *GC) sweep() {
	sweepStart := time.Now()
	now := monotonicSeconds()

	var total, established, expired int
	var toDelete []dataplane.SessionKey
	var snatExpired []expiredSession

	// IPv4 sessions
	err := gc.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		total++

		// Only process forward entries to avoid double-counting
		if val.IsReverse != 0 {
			return true
		}

		if val.State == dataplane.SessStateEstablished {
			established++
		}

		// Check expiry
		if val.LastSeen+uint64(val.Timeout) < now {
			expired++
			// Delete both forward and reverse entries
			toDelete = append(toDelete, key)
			toDelete = append(toDelete, val.ReverseKey)

			// Track dynamic SNAT sessions for dnat_table cleanup
			// (skip static NAT -- no dynamic dnat_table entry exists)
			if val.Flags&dataplane.SessFlagSNAT != 0 &&
				val.Flags&dataplane.SessFlagStaticNAT == 0 {
				snatExpired = append(snatExpired, expiredSession{key: key, val: val})
			}
		}
		return true
	})
	if err != nil {
		slog.Error("conntrack GC iteration failed", "err", err)
		return
	}

	for _, key := range toDelete {
		if err := gc.dp.DeleteSession(key); err != nil {
			slog.Debug("conntrack GC delete failed", "err", err)
		}
	}

	// Clean up dynamic dnat_table entries for expired SNAT sessions
	for _, s := range snatExpired {
		dk := dataplane.DNATKey{
			Protocol: s.key.Protocol,
			DstIP:    s.val.NATSrcIP,
			DstPort:  s.val.NATSrcPort,
		}
		if err := gc.dp.DeleteDNATEntry(dk); err != nil {
			slog.Debug("conntrack GC dnat cleanup failed", "err", err)
		}
	}

	// IPv6 sessions
	var toDeleteV6 []dataplane.SessionKeyV6
	var snatExpiredV6 []expiredSessionV6

	err = gc.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		total++

		if val.IsReverse != 0 {
			return true
		}

		if val.State == dataplane.SessStateEstablished {
			established++
		}

		if val.LastSeen+uint64(val.Timeout) < now {
			expired++
			toDeleteV6 = append(toDeleteV6, key)
			toDeleteV6 = append(toDeleteV6, val.ReverseKey)

			if val.Flags&dataplane.SessFlagSNAT != 0 &&
				val.Flags&dataplane.SessFlagStaticNAT == 0 {
				snatExpiredV6 = append(snatExpiredV6, expiredSessionV6{key: key, val: val})
			}
		}
		return true
	})
	if err != nil {
		slog.Error("conntrack GC v6 iteration failed", "err", err)
	}

	for _, key := range toDeleteV6 {
		if err := gc.dp.DeleteSessionV6(key); err != nil {
			slog.Debug("conntrack GC v6 delete failed", "err", err)
		}
	}

	for _, s := range snatExpiredV6 {
		dk := dataplane.DNATKeyV6{
			Protocol: s.key.Protocol,
			DstIP:    s.val.NATSrcIP,
			DstPort:  s.val.NATSrcPort,
		}
		if err := gc.dp.DeleteDNATEntryV6(dk); err != nil {
			slog.Debug("conntrack GC dnat_v6 cleanup failed", "err", err)
		}
	}

	totalSnatCleaned := len(snatExpired) + len(snatExpiredV6)
	if expired > 0 {
		slog.Info("conntrack GC sweep",
			"total_entries", total,
			"established", established,
			"expired_deleted", expired,
			"snat_dnat_cleaned", totalSnatCleaned)
	}

	gc.mu.Lock()
	gc.stats = GCStats{
		LastSweepTime:       sweepStart,
		LastSweepDuration:   time.Since(sweepStart),
		TotalEntries:        total,
		EstablishedSessions: established,
		ExpiredDeleted:      expired,
	}
	gc.mu.Unlock()
}

// monotonicSeconds returns the current monotonic clock in seconds,
// matching BPF's bpf_ktime_get_ns() / 1e9.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}
