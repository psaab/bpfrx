package cluster

import (
	"log/slog"
	"time"
)

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
