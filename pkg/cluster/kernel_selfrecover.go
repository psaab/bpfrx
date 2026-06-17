package cluster

// Adapter predicates for the #1930 INC-2 kernel-channel bounded local
// self-recovery (pkg/upgrade.KernelSelfRecovery). They are read-only views over
// the RG/peer state plus a reset-all wrapper; the recovery POLICY (lease,
// grace, when to act) lives in pkg/upgrade so this file only exposes the facts.

// LocalDrained reports whether THIS node is in the ForceSecondary-drained state:
// every ENABLED redundancy group is manually-failed-over with weight 0 (i.e. the
// node deliberately yielded all RGs to the peer). A node with no enabled RGs is
// NOT considered drained (there is nothing to recover).
func (m *Manager) LocalDrained() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	enabled := 0
	for _, rg := range m.groups {
		if rg.State == StateDisabled {
			continue
		}
		enabled++
		if !rg.ManualFailover || rg.Weight != 0 {
			return false
		}
	}
	return enabled > 0
}

// PeerHealthyPrimary reports whether the peer is alive AND currently owns at
// least one redundancy group as primary — i.e. a real primary that is carrying
// traffic while this (drained) node could safely rejoin as eligible. Used by
// self-recovery to refuse auto-rejoin during a real dual-down / split.
func (m *Manager) PeerHealthyPrimary() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.peerAlive {
		return false
	}
	for _, pg := range m.peerGroups {
		if pg.State == StatePrimary {
			return true
		}
	}
	return false
}

// ResetAllFailover clears manual failover on every redundancy group (rejoin as
// eligible; the election + VRRP preempt rules then decide primary). Used by the
// kernel self-recovery when an orchestrator crash left this node orphaned-drained.
func (m *Manager) ResetAllFailover() error {
	m.mu.RLock()
	ids := make([]int, 0, len(m.groups))
	for id := range m.groups {
		ids = append(ids, id)
	}
	m.mu.RUnlock()
	for _, id := range ids {
		if err := m.ResetFailover(id); err != nil {
			return err
		}
	}
	return nil
}
