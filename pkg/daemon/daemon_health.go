// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// Bootstrap-import outcome constants (#4184). Recorded once at boot by
// recordBootstrapImport and surfaced via /health + an event.
const (
	// bootstrapImportOK: the text config file was imported and committed.
	bootstrapImportOK = "ok"
	// bootstrapImportLoadedDB: an active config was already present in the DB;
	// no file import was attempted (normal steady-state boot).
	bootstrapImportLoadedDB = "loaded-from-db"
	// bootstrapImportNoConfig: no text config file present (factory/fresh
	// boot). Expected — NOT a failure and NOT health-degrading.
	bootstrapImportNoConfig = "no-config"
	// bootstrapImportFailed: a text config file was present but could not be
	// read/parsed/committed (or was rejected by the device-map preflight).
	bootstrapImportFailed = "import-failed"
)

// BootstrapImport is a snapshot of the day-0 / bootstrap config-import
// outcome (#4184). Consumed by /health so a FAILED import is visible beyond
// the single boot-time journald WARN it used to be.
type BootstrapImport struct {
	Status  string // a bootstrapImport* constant ("" if not yet recorded)
	Error   string // detail when Status == bootstrapImportFailed
	UnixSec int64  // when the outcome was recorded
	// Failed is true only for bootstrapImportFailed — a real read/parse/
	// commit/preflight failure. The expected factory no-config state is NOT
	// failed, so a health probe does not flap on a fresh box.
	Failed bool
}

// recordBootstrapImport stores the boot-time config-import outcome and, on a
// real failure, emits an event so the cause is observable beyond journald
// (#4184). Called exactly once during Run after the bootstrap decision.
func (d *Daemon) recordBootstrapImport(status, detail string) {
	d.bootstrapMu.Lock()
	d.bootstrapImportStatus = status
	d.bootstrapImportError = detail
	d.bootstrapImportUnixSec = time.Now().Unix()
	d.bootstrapMu.Unlock()

	if status != bootstrapImportFailed {
		return
	}
	// Emit a durable, in-band event so `monitor`/event-stream subscribers and
	// the ring buffer carry the cause — not just a one-shot journald WARN.
	if d.eventBuf != nil {
		d.eventBuf.Add(logging.EventRecord{
			Time:   time.Now(),
			Type:   "BOOTSTRAP_IMPORT_FAILED",
			Reason: detail,
		})
	}
}

// BootstrapImportSnapshot returns the recorded day-0 / bootstrap import
// outcome for /health and operator-facing surfaces. Safe to call
// concurrently.
func (d *Daemon) BootstrapImportSnapshot() BootstrapImport {
	d.bootstrapMu.Lock()
	defer d.bootstrapMu.Unlock()
	return BootstrapImport{
		Status:  d.bootstrapImportStatus,
		Error:   d.bootstrapImportError,
		UnixSec: d.bootstrapImportUnixSec,
		Failed:  d.bootstrapImportStatus == bootstrapImportFailed,
	}
}

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
	if d.cluster == nil || d.dataplane() == nil {
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
