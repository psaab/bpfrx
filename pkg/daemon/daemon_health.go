// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// recordCompileFailure tracks a dataplane compile failure and emits an
// escalating log (#758). The first failure remains a single WARN;
// every Nth repeat re-emits at ERROR level so an operator tailing the
// journal sees the degraded state without needing to know the original
// failure text. A success clears the counter via recordCompileSuccess.
func (d *Daemon) recordCompileFailure(err error) {
	d.compileHealthMu.Lock()
	d.compileFailureCount++
	d.compileLastError = err.Error()
	d.compileLastErrorUnixSec = time.Now().Unix()
	count := d.compileFailureCount
	everOk := d.compileEverSucceeded
	d.compileHealthMu.Unlock()

	// First WARN fires on every failure — matches pre-#758 behaviour.
	// Escalate to ERROR on the 5th consecutive failure with no prior
	// success, and again every 10 failures thereafter, so a persistent
	// degraded state stays visible in the log without flooding.
	slog.Warn("failed to compile dataplane", "err", err, "attempt", count, "ever_ok", everOk)
	if !everOk && (count == 5 || (count > 5 && count%10 == 0)) {
		slog.Error("dataplane compile has failed repeatedly; forwarding path is degraded",
			"attempt", count, "err", err)
	}
}

// recordCompileSuccess clears compile failure state. The failure count
// is intentionally preserved as a monotonic "have we ever hit this"
// counter (exported via CompileHealthSnapshot), but the "ever ok" flag
// flips true so /health goes back to healthy.
func (d *Daemon) recordCompileSuccess() {
	d.compileHealthMu.Lock()
	d.compileEverSucceeded = true
	d.compileLastError = ""
	d.compileHealthMu.Unlock()
}

// CompileHealthSnapshot returns the current compile health for /health
// and operator-facing RPCs. Safe to call concurrently.
func (d *Daemon) CompileHealthSnapshot() CompileHealth {
	d.compileHealthMu.Lock()
	defer d.compileHealthMu.Unlock()
	return CompileHealth{
		EverSucceeded:    d.compileEverSucceeded,
		FailureCount:     d.compileFailureCount,
		LastError:        d.compileLastError,
		LastErrorUnixSec: d.compileLastErrorUnixSec,
	}
}

func (d *Daemon) shouldScheduleStandbyNeighborRefresh(now time.Time) bool {
	elapsed := now.Sub(d.startTime).Nanoseconds() + 1
	if elapsed < 1 {
		elapsed = 1
	}
	last := d.lastStandbyNeighborRefresh.Load()
	if last != 0 && elapsed >= last && elapsed-last < int64(standbyNeighborRefreshMinInterval) {
		return false
	}
	return d.lastStandbyNeighborRefresh.CompareAndSwap(last, elapsed)
}

func (d *Daemon) scheduleStandbyNeighborRefresh() {
	if d.cluster == nil || d.dp == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.shouldScheduleStandbyNeighborRefresh(time.Now()) {
		return
	}
	go func(cfg *config.Config) {
		d.resolveNeighborsInner(cfg, false)
		d.maintainClusterNeighborReadiness()
	}(cfg)
}
