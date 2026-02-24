package cluster

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
	// Skip disabled or manually failed-over groups.
	if rg.State == StateDisabled || rg.ManualFailover {
		return electNoChange, ""
	}

	localWeight := rg.Weight
	localPriority := rg.LocalPriority

	// No peer info — single-node election.
	if peerGroup == nil {
		if !m.peerAlive {
			// Peer lost or never seen.
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
