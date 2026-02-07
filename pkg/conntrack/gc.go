// Package conntrack implements connection tracking garbage collection.
package conntrack

import (
	"context"
	"log/slog"
	"time"

	"github.com/psviderski/bpfrx/pkg/dataplane"
	"golang.org/x/sys/unix"
)

// GC performs periodic garbage collection on the session table.
type GC struct {
	dp       *dataplane.Manager
	interval time.Duration
}

// NewGC creates a new session garbage collector.
func NewGC(dp *dataplane.Manager, interval time.Duration) *GC {
	return &GC{dp: dp, interval: interval}
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

func (gc *GC) sweep() {
	now := monotonicSeconds()

	var total, established, expired int
	var toDelete []dataplane.SessionKey
	var snatExpired []expiredSession

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

			// Track SNAT sessions for dnat_table cleanup
			if val.Flags&dataplane.SessFlagSNAT != 0 {
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
			DstPort:  s.key.SrcPort,
		}
		if err := gc.dp.DeleteDNATEntry(dk); err != nil {
			slog.Debug("conntrack GC dnat cleanup failed", "err", err)
		}
	}

	if expired > 0 {
		slog.Info("conntrack GC sweep",
			"total_entries", total,
			"established", established,
			"expired_deleted", expired,
			"snat_dnat_cleaned", len(snatExpired))
	}
}

// monotonicSeconds returns the current monotonic clock in seconds,
// matching BPF's bpf_ktime_get_ns() / 1e9.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}
