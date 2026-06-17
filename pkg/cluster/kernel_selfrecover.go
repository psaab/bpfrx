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

// SetKernelUpgradeHold holds this node SECONDARY in election unconditionally
// (#1930 INC-2 — a kernel-upgrade candidate boot must not become primary until
// the promotion gate verifies the dataplane). Unlike ManualFailover this is NOT
// auto-cleared for an isolated node, so a candidate that cannot see the peer
// still cannot blackhole traffic by claiming primary (r2 AGY Critical). Set it
// BEFORE Start() on a candidate boot. Idempotent.
func (m *Manager) SetKernelUpgradeHold() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kernelUpgradeHold = true
	// Defense in depth: the daemon sets the hold before the first election, so
	// normally no group is primary yet. But setting the hold only BLOCKS future
	// promotions — it must also DEMOTE any group that is already primary, so the
	// hold is correct regardless of call ordering (r2 AGY Finding 1). Idempotent:
	// a no-op when nothing is primary (the common candidate-boot case).
	for _, rg := range m.groups {
		if rg.State == StatePrimary {
			rg.State = StateSecondary
			m.sendEvent(rg.GroupID, StatePrimary, StateSecondary, "kernel-upgrade hold armed")
		}
	}
}

// KernelUpgradeHeld reports whether the kernel-upgrade election hold is set.
// Used by the daemon's reconcile loop to release the hold against the durable
// promotion marker: the promotion gate runs in a SEPARATE process
// (xpf-kernel-promote.service, After=xpfd) that clears only the on-disk journal
// and writes the marker, so the running daemon must notice the verified
// promotion (marker == running kernel) and release the hold itself.
func (m *Manager) KernelUpgradeHeld() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kernelUpgradeHold
}

// ClearKernelUpgradeHold releases the kernel-upgrade election hold and re-runs
// election so the node can take its normal role. The two real callers are
// (1) the daemon's reconcileKernelUpgradeHold once the promotion marker confirms
// THIS kernel was verified+promoted, and (2) ResetAllFailover (the local
// self-recovery rejoin). NOTE: the orchestrator's gRPC `rejoin` clears manual
// failover PER-RG (Manager.ResetFailover, not ResetAllFailover) and does NOT go
// through here — that is fine, because the orchestrator only issues rejoin after
// status reports promoted==version, by which point the marker-driven reconcile
// has already released the hold. A reverted/failed roll deliberately KEEPS the
// hold (fail-safe); the hold is then dropped by the reboot to known-good, where
// it is never re-set.
func (m *Manager) ClearKernelUpgradeHold() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kernelUpgradeHold {
		m.kernelUpgradeHold = false
		// Re-elect with the same peer-aware dispatch the rest of the manager
		// uses: an isolated cleared node (peerAlive=false) must go through the
		// single-node path to claim primary; runElection alone would not promote
		// it. Both require m.mu held (we hold it).
		if m.peerAlive {
			m.runElection()
		} else {
			m.electSingleNode()
		}
	}
}

// ResetAllFailover clears manual failover on every redundancy group (rejoin as
// eligible; the election + VRRP preempt rules then decide primary). Used by the
// kernel self-recovery when an orchestrator crash left this node orphaned-drained.
// It also clears any kernel-upgrade election hold (the rejoin path).
func (m *Manager) ResetAllFailover() error {
	m.ClearKernelUpgradeHold()
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
