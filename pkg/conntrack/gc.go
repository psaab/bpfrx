// Package conntrack implements connection tracking garbage collection.
package conntrack

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
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

// MaxSessions is the maximum number of session entries in the BPF map.
// This counts both forward and reverse entries, so the effective session
// count for watermark comparison is total/2.
const MaxSessions = 10_000_000

// GC performs periodic garbage collection on the session table.
type GC struct {
	dp       dataplane.DataPlane
	interval time.Duration
	mu       sync.RWMutex
	stats    GCStats

	OnDeleteV4 func(key dataplane.SessionKey)
	OnDeleteV6 func(key dataplane.SessionKeyV6)

	lastV6Count int // v6 entries found in previous sweep
	sweepCount  int // sweep counter for periodic forced v6 check
	lastTotal   int // total entries (v4+v6) found in previous sweep

	lastSessionCounter uint64 // last seen GLOBAL_CTR_SESSIONS_NEW value
	lastClosedCounter  uint64 // last seen GLOBAL_CTR_SESSIONS_CLOSED value

	// Scratch buffers reused across sweeps to reduce allocation churn.
	toDeleteV4    []dataplane.SessionKey
	snatExpiredV4 []expiredSession
	toDeleteV6    []dataplane.SessionKeyV6
	snatExpiredV6 []expiredSessionV6

	// Aggressive session aging (set via SetAgingConfig).
	agingActive   bool
	earlyAgeout   uint64 // seconds
	highWatermark int    // percent of MaxSessions
	lowWatermark  int    // percent of MaxSessions

	// Per-IP session limiting: when enabled, GC accumulates per-src/dst
	// session counts and pushes them to BPF maps for xdp_screen to check.
	sessionLimitEnabled bool
}

// NewGC creates a new session garbage collector.
func NewGC(dp dataplane.DataPlane, interval time.Duration) *GC {
	return &GC{dp: dp, interval: interval, lastV6Count: -1}
}

// SetAgingConfig updates the aggressive aging parameters.
// earlyAgeout is the shortened timeout in seconds (0 = disabled).
// highWM/lowWM are utilization percentages of MaxSessions (0 = disabled).
func (gc *GC) SetAgingConfig(earlyAgeout, highWM, lowWM int) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.earlyAgeout = uint64(earlyAgeout)
	gc.highWatermark = highWM
	gc.lowWatermark = lowWM
	if highWM == 0 || earlyAgeout == 0 {
		gc.agingActive = false
	}
}

// SetSessionLimitEnabled enables or disables per-IP session counting
// during GC sweeps. When enabled, GC accumulates per-src/dst counts
// and pushes them to BPF maps for xdp_screen session limiting.
func (gc *GC) SetSessionLimitEnabled(enabled bool) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.sessionLimitEnabled = enabled
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
	// Fast path: if no sessions existed on last sweep AND no new sessions
	// have been created since, skip the entire iteration.  This eliminates
	// ~25% CPU from empty-table batch lookups on idle firewalls.
	if gc.lastTotal == 0 {
		newCtr, err1 := gc.dp.ReadGlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := gc.dp.ReadGlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil &&
			newCtr == gc.lastSessionCounter &&
			closedCtr == gc.lastClosedCounter {
			return
		}
		// Counters changed — fall through to full sweep.
		gc.lastSessionCounter = newCtr
		gc.lastClosedCounter = closedCtr
	}

	sweepStart := time.Now()
	now := monotonicSeconds()

	var total, established, expired int
	toDelete := gc.toDeleteV4[:0]
	snatExpired := gc.snatExpiredV4[:0]

	// Per-IP session count accumulators (only used when session limiting is enabled)
	countSessions := gc.sessionLimitEnabled
	var srcCounts, dstCounts map[dataplane.SessionCountKey]uint32
	if countSessions {
		srcCounts = make(map[dataplane.SessionCountKey]uint32, 1024)
		dstCounts = make(map[dataplane.SessionCountKey]uint32, 1024)
	}

	// IPv4 sessions — batch iteration reduces kernel lock contention
	err := gc.dp.BatchIterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		total++

		// Only process forward entries to avoid double-counting
		if val.IsReverse != 0 {
			return true
		}

		if val.State == dataplane.SessStateEstablished {
			established++
		}

		// Check expiry (aggressive aging shortens effective timeout)
		effectiveTimeout := uint64(val.Timeout)
		if gc.agingActive && gc.earlyAgeout > 0 && gc.earlyAgeout < effectiveTimeout {
			effectiveTimeout = gc.earlyAgeout
		}
		if val.LastSeen+effectiveTimeout < now {
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
		} else if countSessions {
			// Count active (non-expired) forward sessions per src/dst IP
			srcKey := dataplane.SessionCountKey{
				IP:     binary.NativeEndian.Uint32(key.SrcIP[:]),
				ZoneID: val.IngressZone,
			}
			dstKey := dataplane.SessionCountKey{
				IP:     binary.NativeEndian.Uint32(key.DstIP[:]),
				ZoneID: val.IngressZone,
			}
			srcCounts[srcKey]++
			dstCounts[dstKey]++
		}
		return true
	})
	if err != nil {
		slog.Error("conntrack GC iteration failed", "err", err)
		return
	}

	// Batch delete in chunks for fewer syscalls and reduced lock contention
	const deleteBatch = 64
	for i := 0; i < len(toDelete); i += deleteBatch {
		end := i + deleteBatch
		if end > len(toDelete) {
			end = len(toDelete)
		}
		gc.dp.BatchDeleteSessions(toDelete[i:end])
	}
	// Fire delete callbacks for forward entries (even indices)
	if gc.OnDeleteV4 != nil {
		for i := 0; i < len(toDelete); i += 2 {
			gc.OnDeleteV4(toDelete[i])
		}
	}

	// Clean up dynamic dnat_table entries for expired SNAT sessions.
	// For persistent NAT pools, save the binding before cleanup.
	pnat := gc.dp.GetPersistentNAT()
	for _, s := range snatExpired {
		// Check if this SNAT session belongs to a persistent NAT pool
		if pnat != nil {
			var natIPBytes [4]byte
			binary.NativeEndian.PutUint32(natIPBytes[:], s.val.NATSrcIP)
			natIP := netip.AddrFrom4(natIPBytes)

			if poolName, poolCfg, ok := pnat.LookupPool(natIP); ok {
				srcIP := netip.AddrFrom4(s.key.SrcIP)
				pnat.Save(&dataplane.PersistentNATBinding{
					SrcIP:               srcIP,
					SrcPort:             s.key.SrcPort,
					NatIP:               natIP,
					NatPort:             s.val.NATSrcPort,
					PoolName:            poolName,
					LastSeen:            time.Now(),
					Timeout:             poolCfg.Timeout,
					PermitAnyRemoteHost: poolCfg.PermitAnyRemoteHost,
				})
			}
		}

		dk := dataplane.DNATKey{
			Protocol: s.key.Protocol,
			DstIP:    s.val.NATSrcIP,
			DstPort:  s.val.NATSrcPort,
		}
		if err := gc.dp.DeleteDNATEntry(dk); err != nil {
			slog.Debug("conntrack GC dnat cleanup failed", "err", err)
		}
	}

	// Save scratch buffers for reuse.
	gc.toDeleteV4 = toDelete
	gc.snatExpiredV4 = snatExpired

	// IPv6 sessions — skip iteration when previous sweep found zero entries,
	// but force a check every 6th sweep (60s at default 10s interval).
	gc.sweepCount++
	toDeleteV6 := gc.toDeleteV6[:0]
	snatExpiredV6 := gc.snatExpiredV6[:0]
	skipV6 := gc.lastV6Count == 0 && gc.sweepCount%6 != 0

	if !skipV6 {
		var v6Count int
		err = gc.dp.BatchIterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			v6Count++
			total++

			if val.IsReverse != 0 {
				return true
			}

			if val.State == dataplane.SessStateEstablished {
				established++
			}

			effectiveTimeout := uint64(val.Timeout)
			if gc.agingActive && gc.earlyAgeout > 0 && gc.earlyAgeout < effectiveTimeout {
				effectiveTimeout = gc.earlyAgeout
			}
			if val.LastSeen+effectiveTimeout < now {
				expired++
				toDeleteV6 = append(toDeleteV6, key)
				toDeleteV6 = append(toDeleteV6, val.ReverseKey)

				if val.Flags&dataplane.SessFlagSNAT != 0 &&
					val.Flags&dataplane.SessFlagStaticNAT == 0 {
					snatExpiredV6 = append(snatExpiredV6, expiredSessionV6{key: key, val: val})
				}
			} else if countSessions {
				// XOR-hash IPv6 addresses to uint32 for session count key
				srcHash := binary.NativeEndian.Uint32(key.SrcIP[0:4]) ^
					binary.NativeEndian.Uint32(key.SrcIP[4:8]) ^
					binary.NativeEndian.Uint32(key.SrcIP[8:12]) ^
					binary.NativeEndian.Uint32(key.SrcIP[12:16])
				dstHash := binary.NativeEndian.Uint32(key.DstIP[0:4]) ^
					binary.NativeEndian.Uint32(key.DstIP[4:8]) ^
					binary.NativeEndian.Uint32(key.DstIP[8:12]) ^
					binary.NativeEndian.Uint32(key.DstIP[12:16])
				srcKey := dataplane.SessionCountKey{
					IP:     srcHash,
					ZoneID: val.IngressZone,
				}
				dstKey := dataplane.SessionCountKey{
					IP:     dstHash,
					ZoneID: val.IngressZone,
				}
				srcCounts[srcKey]++
				dstCounts[dstKey]++
			}
			return true
		})
		if err != nil {
			slog.Error("conntrack GC v6 iteration failed", "err", err)
		}
		gc.lastV6Count = v6Count
	}

	for i := 0; i < len(toDeleteV6); i += deleteBatch {
		end := i + deleteBatch
		if end > len(toDeleteV6) {
			end = len(toDeleteV6)
		}
		gc.dp.BatchDeleteSessionsV6(toDeleteV6[i:end])
	}
	if gc.OnDeleteV6 != nil {
		for i := 0; i < len(toDeleteV6); i += 2 {
			gc.OnDeleteV6(toDeleteV6[i])
		}
	}

	for _, s := range snatExpiredV6 {
		// Check if this SNAT session belongs to a persistent NAT pool
		if pnat != nil {
			natIP := netip.AddrFrom16(s.val.NATSrcIP)
			if poolName, poolCfg, ok := pnat.LookupPool(natIP); ok {
				srcIP := netip.AddrFrom16(s.key.SrcIP)
				pnat.Save(&dataplane.PersistentNATBinding{
					SrcIP:               srcIP,
					SrcPort:             s.key.SrcPort,
					NatIP:               natIP,
					NatPort:             s.val.NATSrcPort,
					PoolName:            poolName,
					LastSeen:            time.Now(),
					Timeout:             poolCfg.Timeout,
					PermitAnyRemoteHost: poolCfg.PermitAnyRemoteHost,
				})
			}
		}

		dk := dataplane.DNATKeyV6{
			Protocol: s.key.Protocol,
			DstIP:    s.val.NATSrcIP,
			DstPort:  s.val.NATSrcPort,
		}
		if err := gc.dp.DeleteDNATEntryV6(dk); err != nil {
			slog.Debug("conntrack GC dnat_v6 cleanup failed", "err", err)
		}
	}

	// Save v6 scratch buffers for reuse.
	gc.toDeleteV6 = toDeleteV6
	gc.snatExpiredV6 = snatExpiredV6

	// Run persistent NAT table GC to expire old bindings
	if pnat != nil {
		if removed := pnat.GC(); removed > 0 {
			slog.Info("persistent NAT GC", "removed", removed)
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

	gc.lastTotal = total

	// Push per-IP session counts to BPF maps for xdp_screen limiting.
	if countSessions {
		for k, c := range srcCounts {
			gc.dp.UpdateSessionCountSrc(k, c)
		}
		for k, c := range dstCounts {
			gc.dp.UpdateSessionCountDst(k, c)
		}
	}

	// Aggressive aging watermark hysteresis.
	// total counts both forward+reverse entries; MaxSessions is the map size
	// which holds both. Compare directly against MaxSessions.
	if gc.highWatermark > 0 && gc.earlyAgeout > 0 {
		pct := total * 100 / MaxSessions
		if !gc.agingActive && pct >= gc.highWatermark {
			gc.agingActive = true
			slog.Info("aggressive session aging activated",
				"utilization_pct", pct, "high_watermark", gc.highWatermark)
		} else if gc.agingActive && pct < gc.lowWatermark {
			gc.agingActive = false
			slog.Info("aggressive session aging deactivated",
				"utilization_pct", pct, "low_watermark", gc.lowWatermark)
		}
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
