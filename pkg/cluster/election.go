package cluster

import (
	"log/slog"
	"time"
)

// EffectivePriority calculates the effective priority for a node.
// effective = base_priority * (weight / 255)
// Returns an integer value scaled to avoid floating-point issues.
// Higher value = higher priority = more likely to be primary.
func EffectivePriority(basePriority, weight int) int {
	if weight <= 0 {
		return 0
	}
	return basePriority * weight / 255
}

// electionResult is the outcome of a per-RG election.
type electionResult int

const (
	electLocalPrimary  electionResult = iota // local node should be primary
	electLocalSecondary                       // local node should be secondary
	electNoChange                             // no state change needed
)

// elect performs election for a single RG considering peer state.
// It implements the full Junos-style election logic:
//   - If peer is lost, local becomes primary (if weight > 0)
//   - If peer is alive, compare effective priorities
//   - Preempt: higher effective priority wins immediately
//   - Non-preempt: incumbent stays unless weight drops to 0
//   - Split-brain (both primary): lower node ID wins
func (m *Manager) electRG(rg *RedundancyGroupState, peerGroup *PeerGroupState) (electionResult, string) {
	// Skip disabled groups entirely.
	if rg.State == StateDisabled {
		return electNoChange, ""
	}

	// ManualFailover normally blocks election (stays secondary until reset).
	// Exception: if the peer has also resigned (weight 0), both nodes are
	// secondary and neither can serve traffic. Clear ManualFailover and
	// restore weight to allow election, avoiding a dual-secondary deadlock
	// during rapid failover cycles where one node resigns before the
	// previous cycle's ManualFailover flag is cleared.
	//
	// Time guard: only clear after 2s to prevent re-promoting a node that
	// JUST resigned. Without this, the resigned node sees stale peer
	// weight=0 (from a previous cycle) and immediately re-elects itself
	// as primary, defeating the resignation.
	if rg.ManualFailover {
		if peerGroup == nil || peerGroup.Weight > 0 {
			return electNoChange, ""
		}
		if time.Since(rg.ManualFailoverAt) < 2*time.Second {
			return electNoChange, ""
		}
		// Peer weight 0 for >2s — both nodes resigned. Clear
		// ManualFailover and restore weight so election can promote
		// one of them.
		slog.Info("cluster: clearing manual failover (peer also resigned)",
			"rg", rg.GroupID)
		rg.ManualFailover = false
		rg.ManualFailoverAt = time.Time{}
		// Recalculate weight inline (recalcWeight calls runElection
		// which would recurse back to electRG).
		totalLost := 0
		for _, iface := range rg.MonitorFails {
			key := monitorKey{rgID: rg.GroupID, iface: iface}
			totalLost += m.monitorWeights[key]
		}
		rg.Weight = 255 - totalLost
		if rg.Weight < 0 {
			rg.Weight = 0
		}
	}

	localWeight := rg.Weight
	localPriority := rg.LocalPriority

	// No peer info — single-node election.
	if peerGroup == nil {
		if !m.peerAlive {
			// Non-preempt in cluster mode: don't claim primary on fresh
			// boot before hearing from the peer. Wait for heartbeat
			// timeout to confirm peer is truly down.
			if !rg.Preempt && !m.peerEverSeen && rg.State == StateSecondary && m.controlInterface != "" {
				return electNoChange, ""
			}
			// Peer lost (was alive, now timed out) or preempt mode.
			if localWeight > 0 && rg.State != StatePrimary {
				return electLocalPrimary, "Peer lost"
			}
			if localWeight <= 0 && rg.State != StateSecondary {
				return electLocalSecondary, "Local weight 0"
			}
			return electNoChange, ""
		}
		// Peer alive but no group info for this RG — we take primary.
		if localWeight > 0 && rg.State != StatePrimary {
			return electLocalPrimary, "Peer has no RG info"
		}
		return electNoChange, ""
	}

	peerWeight := peerGroup.Weight
	peerPriority := peerGroup.Priority

	localEff := EffectivePriority(localPriority, localWeight)
	peerEff := EffectivePriority(peerPriority, peerWeight)

	// Weight 0 → always secondary.
	if localWeight <= 0 {
		if rg.State != StateSecondary {
			return electLocalSecondary, "Local weight 0"
		}
		return electNoChange, ""
	}

	// Peer weight 0 → we should be primary.
	if peerWeight <= 0 {
		if rg.State != StatePrimary {
			return electLocalPrimary, "Peer weight 0"
		}
		return electNoChange, ""
	}

	// Preempt enabled: higher effective priority wins.
	// This takes priority over split-brain detection since preempt explicitly
	// requests priority-based election.
	if rg.Preempt {
		if localEff > peerEff {
			if rg.State != StatePrimary {
				return electLocalPrimary, "Preempt: higher priority"
			}
		} else if localEff < peerEff {
			if rg.State != StateSecondary {
				return electLocalSecondary, "Preempt: lower priority"
			}
		} else {
			// Tie: lower node ID wins.
			if m.nodeID < m.peerNodeID {
				if rg.State != StatePrimary {
					return electLocalPrimary, "Lower node ID wins tie"
				}
			} else if m.nodeID > m.peerNodeID {
				if rg.State != StateSecondary {
					return electLocalSecondary, "Higher node ID loses tie"
				}
			}
			// Same node ID (shouldn't happen) — no change.
		}
		return electNoChange, ""
	}

	// Non-preempt: incumbent stays unless weight drops to 0.
	// If we are currently secondary and peer is primary, we stay secondary.
	// If we are currently primary, we stay primary (peer can't preempt us).
	// If neither is primary (both secondary, e.g. initial state), use priority.
	if rg.State == StatePrimary {
		return electNoChange, "" // non-preempt: incumbent stays
	}

	if peerGroup.State == StatePrimary {
		// Peer is primary and we're not — stay secondary.
		if rg.State != StateSecondary {
			return electLocalSecondary, "Peer is primary"
		}
		return electNoChange, ""
	}

	// Neither is primary (initial state) — use effective priority to decide.
	if localEff > peerEff {
		return electLocalPrimary, "Higher priority"
	} else if localEff < peerEff {
		if rg.State != StateSecondary {
			return electLocalSecondary, "Lower priority"
		}
	} else {
		// Tie: lower node ID wins.
		if m.nodeID < m.peerNodeID {
			return electLocalPrimary, "Lower node ID wins tie"
		}
		if rg.State != StateSecondary {
			return electLocalSecondary, "Higher node ID loses tie"
		}
	}
	return electNoChange, ""
}

// runElection evaluates all RGs using current peer state and applies transitions.
// Must be called with m.mu held.
func (m *Manager) runElection() {
	for _, rg := range m.groups {
		var peerGroup *PeerGroupState
		if pg, ok := m.peerGroups[rg.GroupID]; ok {
			peerGroup = &pg
		}

		result, reason := m.electRG(rg, peerGroup)
		oldState := rg.State

		switch result {
		case electLocalPrimary:
			rg.State = StatePrimary
		case electLocalSecondary:
			rg.State = StateSecondary
		case electNoChange:
			continue
		}

		if oldState != rg.State {
			// Track failover count for primary→non-primary transitions.
			if oldState == StatePrimary {
				rg.FailoverCount++
			}
			m.sendEvent(rg.GroupID, oldState, rg.State, reason)
		}
	}
}
