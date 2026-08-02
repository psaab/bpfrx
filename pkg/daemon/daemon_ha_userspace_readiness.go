package daemon

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type userspaceRuntimeModeReporter interface {
	Mode() dpuserspace.DataplaneMode
}

type userspaceTakeoverReadiness interface {
	TakeoverReady() (bool, []string)
}

func (d *Daemon) tryPrepareUserspaceRGDemotion(rgID int) {
	if err := d.prepareUserspaceRGDemotionWithTimeout(rgID, 5*time.Second); err != nil {
		slog.Warn("userspace: prepare rg demotion failed", "rg", rgID, "err", err)
	}
}

func (d *Daemon) acquireUserspaceRGDemotionPrep(rgID int, hold time.Duration) bool {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	now := time.Now()
	if until, ok := d.userspaceDemotionPrepUntil[rgID]; ok && now.Before(until) {
		return false
	}
	if hold < 10*time.Second {
		hold = 10 * time.Second
	}
	d.userspaceDemotionPrepUntil[rgID] = now.Add(hold)
	return true
}

// releaseUserspaceRGDemotionPrep clears the suppression window so retries
// (e.g. manual failover admission) can re-attempt demotion prep immediately.
func (d *Daemon) releaseUserspaceRGDemotionPrep(rgID int) {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	delete(d.userspaceDemotionPrepUntil, rgID)
}

func (d *Daemon) prepareUserspaceRGDemotion(rgID int) error {
	return d.prepareUserspaceRGDemotionWithTimeout(rgID, 30*time.Second)
}

func wrapUserspaceManualFailoverPrepareError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "previous demotion barrier still pending") ||
		strings.Contains(msg, "session sync not ready before demotion") ||
		strings.Contains(msg, "session sync peer not quiescent before demotion") ||
		strings.Contains(msg, "demotion peer barrier failed") {
		return &cluster.RetryablePreFailoverError{Err: err}
	}
	return err
}

func userspaceManualFailoverTransferReadinessError(state cluster.TransferReadinessSnapshot) error {
	if state.ReadyForManualFailover() {
		return nil
	}
	if reason := state.Reason(); reason != "" {
		return fmt.Errorf("session sync transfer not ready before demotion: %s", reason)
	}
	return nil
}

type userspaceTransferReadinessProvider interface {
	IsConnected() bool
	PeerHealthy() bool
	TransferReadiness() cluster.TransferReadinessSnapshot
}

type userspaceHAProtocolMismatchProvider interface {
	HAProtocolVersionMismatch() (bool, uint16, uint16)
}

func userspaceHAProtocolMismatchReason(provider userspaceHAProtocolMismatchProvider) []string {
	if provider == nil {
		return nil
	}
	if mismatch, local, peer := provider.HAProtocolVersionMismatch(); mismatch {
		return []string{fmt.Sprintf("ha protocol mismatch local=%d peer=%d", local, peer)}
	}
	return nil
}

func computeUserspaceTransferReadiness(sync userspaceTransferReadinessProvider, syncPeerConnected bool) (bool, []string) {
	if !sync.IsConnected() || !sync.PeerHealthy() || !syncPeerConnected {
		return false, []string{"session sync disconnected"}
	}
	state := sync.TransferReadiness()
	if state.ReadyForManualFailover() {
		return true, nil
	}
	if reason := state.Reason(); reason != "" {
		return false, []string{reason}
	}
	return true, nil
}

func (d *Daemon) userspaceTransferReadiness(rgID int) (bool, []string) {
	if d.cluster != nil {
		if reasons := userspaceHAProtocolMismatchReason(d.cluster); len(reasons) > 0 {
			return false, reasons
		}
	}
	ss := d.getSessionSync()
	if ss == nil {
		return false, []string{"session sync disconnected"}
	}
	return computeUserspaceTransferReadiness(ss, d.syncPeerConnected.Load())
}

func (d *Daemon) prepareUserspaceManualFailover(rgID int) error {
	return wrapUserspaceManualFailoverPrepareError(
		d.prepareUserspaceRGDemotionWithTimeout(rgID, 60*time.Second),
	)
}

func (d *Daemon) prepareUserspaceRGDemotionWithTimeout(rgID int, barrierTimeout time.Duration) error {
	if !d.acquireUserspaceRGDemotionPrep(rgID, barrierTimeout) {
		slog.Info("userspace: skipping duplicate rg demotion prepare", "rg", rgID)
		return nil
	}
	success := false
	defer func() {
		if !success {
			d.releaseUserspaceRGDemotionPrep(rgID)
		}
	}()
	// Snapshot the session-sync object once for this demotion attempt (#4958)
	// so the nil/connection checks, the retry-restart defer, and the barrier
	// wait all operate on the same instance instead of re-reading the field a
	// concurrent stopClusterComms could nil mid-flight.
	ss := d.getSessionSync()
	if ss == nil || !ss.IsConnected() {
		// Release suppression window so a reconnect + retry can re-run
		// the barrier check before the actual demotion proceeds.
		d.releaseUserspaceRGDemotionPrep(rgID)
		success = true
		return nil
	}
	// Transfer readiness (bulk sync state) is NOT checked here.
	// The barrier at the end of this function proves the peer has all
	// sessions. Planned failover should not depend on bulk sync state —
	// both nodes have full session state from continuous real-time sync.

	// Stop the bulk sync retry loop — it floods the sync TCP connection
	// with session data, delaying the barrier write/ack by 30+ seconds.
	// Advancing the retry generation causes the goroutine to exit.
	retryGen := d.syncPrimeRetryGen.Add(1)

	// If the barrier fails, restart the retry loop so the peer can still
	// receive its cold-start bootstrap. Only suppress the restart when
	// the barrier succeeds and the demotion completes (success=true).
	defer func() {
		if success {
			return
		}
		if d.syncPeerBulkPrimed.Load() {
			return // peer already primed, no retry needed
		}
		if ss == nil || !ss.IsConnected() {
			return // peer disconnected, retry would be pointless
		}
		if d.syncPrimeRetryGen.Load() != retryGen {
			return // a newer retry generation is already active
		}
		slog.Info("cluster: restarting bulk-prime retry loop after failed demotion prep",
			"retry_gen", retryGen, "rg", rgID)
		d.startSessionSyncPrimeRetry(retryGen)
	}()

	// Single barrier — peer ack means it has processed all queued deltas.
	// The actual demotion happens atomically in UpdateRGActive(false).
	if err := ss.WaitForPeerBarrier(barrierTimeout); err != nil {
		return fmt.Errorf("demotion peer barrier failed: %w", err)
	}

	success = true
	slog.Info("userspace: peer barrier ready for rg demotion", "rg", rgID)
	return nil
}

// userspaceDataplaneActive returns true when the userspace dataplane is
// running in a mode that handles forwarding (not eBPF-only). Callers use
// this to skip eBPF-specific workarounds (blackhole routes) that the
// userspace pipeline doesn't need.
func (d *Daemon) userspaceDataplaneActive() bool {
	if runtime, ok := d.dataplane().(userspaceRuntimeModeReporter); ok {
		return runtime.Mode() != dpuserspace.ModeEBPFOnly
	}
	return false
}

func userspaceRGConfigured(cfg *config.Config, rgID int) bool {
	if cfg == nil || dataplane.EffectiveType(cfg.System.DataplaneType) != dataplane.TypeUserspace || rgID <= 0 {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}

// checkUserspaceTakeoverReadiness returns whether the userspace dataplane
// is ready to take over forwarding for the given RG. Returns (true, nil)
// for non-userspace RGs or when the dataplane is healthy.
func (d *Daemon) checkUserspaceTakeoverReadiness(rgID int) (bool, []string) {
	cfg := d.store.ActiveConfig()
	if !userspaceRGConfigured(cfg, rgID) {
		return true, nil
	}
	// Copilot fix: if the dataplane is unpublished or wrong type but config
	// says userspace, the dataplane isn't ready — don't report takeover-ready.
	// #2114: one snapshot feeds the nil-check and the assertion.
	rt := d.dataplane()
	if rt == nil {
		return false, []string{fmt.Sprintf("userspace dataplane not initialized for RG %d", rgID)}
	}
	ready, ok := rt.(userspaceTakeoverReadiness)
	if !ok {
		return false, []string{fmt.Sprintf("userspace dataplane readiness provider not available for RG %d", rgID)}
	}
	return ready.TakeoverReady()
}
