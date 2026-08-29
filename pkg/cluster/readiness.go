package cluster

import (
	"log/slog"
	"strings"
	"time"
)

// maxConfigSyncReasonLen bounds the stored/rendered config-sync failure reason
// (#6387) so an arbitrary apply error can never blow up the status output.
const maxConfigSyncReasonLen = 200

// SetConfigSyncHealth records the node-global config-sync APPLY health (#6387),
// mirroring SetRGReady's manager-mutation shape. failing=true raises the CF
// config-sync monitor-failure / degraded-health annotation surfaced by
// FormatStatus / FormatInformation; failing=false clears it. The reason is
// bounded/sanitized (sanitizeConfigSyncReason) before storage so an arbitrary
// multi-line apply error is never rendered verbatim (§12.6).
//
// This is DIAGNOSTIC ONLY. It deliberately does NOT touch Weight,
// monitorWeights, readiness, or trigger an election: a config-apply failure is
// node-global and must annotate health without perturbing the failover math.
// Manual failover stays gated solely by ConfigStale(); crash takeover stays
// intentionally ungated. See the Manager.configSyncFailing field comment.
func (m *Manager) SetConfigSyncHealth(failing bool, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configSyncFailing = failing
	if failing {
		m.configSyncFailReason = sanitizeConfigSyncReason(reason)
	} else {
		m.configSyncFailReason = ""
	}
}

// sanitizeConfigSyncReason reduces an apply error to a single bounded status
// line (#6387): it keeps the first line only, collapses internal whitespace,
// and caps the length on a rune boundary. This keeps the operator-facing reason
// useful (it still names the failing sub-step, e.g. the host-inbound nft step)
// while guaranteeing the stored value is never a raw multi-line arbitrary error
// string (§12.6). An empty reason falls back to a generic label.
func sanitizeConfigSyncReason(reason string) string {
	if i := strings.IndexByte(reason, '\n'); i >= 0 {
		reason = reason[:i]
	}
	reason = strings.Join(strings.Fields(reason), " ")
	if reason == "" {
		return "config-sync apply failing"
	}
	if r := []rune(reason); len(r) > maxConfigSyncReasonLen {
		reason = string(r[:maxConfigSyncReasonLen]) + "…"
	}
	return reason
}

// SetRGReady updates the readiness state for a redundancy group.
// When transitioning not-ready → ready, sets ReadySince to now.
// When transitioning ready → not-ready, clears ReadySince and stores reasons.
// After any change, triggers re-election to evaluate the readiness gate.
func (m *Manager) SetRGReady(rgID int, ready bool, reasons []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return
	}

	wasReady := rg.Ready
	rg.Ready = ready

	if ready && !wasReady {
		// Transition: not-ready → ready.
		rg.ReadySince = time.Now()
		rg.ReadinessReasons = nil
		// #7161: the RG is ready, so cancel the degraded fallback and forget the
		// not-ready window. A later decline must start a FRESH continuous window
		// rather than inheriting one that has already been satisfied.
		m.clearDegradedStateLocked(rg)
		slog.Info("cluster: RG readiness: ready", "rg", rgID)

		// Schedule a wakeup at ReadySince + takeoverHoldTime to
		// re-trigger election. Without this, the edge-triggered
		// election at readiness change would check too early (hold
		// time not yet elapsed) and never retry.
		if m.takeoverHoldTime > 0 {
			if rg.holdTimer != nil {
				rg.holdTimer.Stop()
			}
			rg.holdTimer = time.AfterFunc(m.takeoverHoldTime, func() {
				m.mu.Lock()
				defer m.mu.Unlock()
				// The manager was stopped after this timer fired but before
				// it acquired the lock — do not run an election on a
				// quiesced manager (#4716).
				if m.stopped {
					return
				}
				// The RG may have been removed (or replaced) from config
				// while this timer was armed or already parked on m.mu
				// (#5245). UpdateConfig stops+clears the timer on removal,
				// but a timer that had already fired races that teardown;
				// verify this is still the live group before electing so a
				// stale closure cannot run an election against removed state.
				if cur, ok := m.groups[rgID]; !ok || cur != rg {
					return
				}
				if !rg.Ready {
					return
				}
				slog.Info("cluster: hold timer expired, re-evaluating election", "rg", rgID)
				if m.peerAlive {
					m.runElection()
				} else {
					m.electSingleNode()
				}
			})
		}
	} else if !ready && wasReady {
		// Transition: ready → not-ready.
		rg.ReadySince = time.Time{}
		rg.ReadinessReasons = reasons
		if rg.holdTimer != nil {
			rg.holdTimer.Stop()
			rg.holdTimer = nil
		}
		slog.Info("cluster: RG readiness: not ready", "rg", rgID, "reasons", reasons)
	} else if !ready {
		// Still not ready — update reasons.
		rg.ReadinessReasons = reasons
	}

	// Re-evaluate election on readiness change.
	if wasReady != ready {
		if m.peerAlive {
			m.runElection()
		} else {
			m.electSingleNode()
		}
	}
}
