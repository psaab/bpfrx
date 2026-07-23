package cluster

// SetArmFailedHold holds this node SECONDARY unconditionally after a dataplane
// arm/attach failure (#5275). #1960/#1993 fail closed only on a COMPILE failure;
// a successful compile followed by a Start/LoadUserspaceShim failure leaves the
// node with no policy-enforcement dataplane, so it must never become primary /
// own the redundancy groups — the healthy peer owns them.
//
// It both BLOCKS future promotions (the election gate checks armFailedHold, like
// kernelUpgradeHold) and DEMOTES any RG already primary, so the hold is correct
// regardless of call ordering: the daemon sets it AFTER cluster.Start() may have
// already run an isolated single-node election that claimed primary (arm failure
// is only known once setupDataplaneAndInitialConfig / the bootstrap-exit arm has
// run, which is after cluster.Start()). Mirrors SetKernelUpgradeHold. Idempotent.
//
// There is deliberately no runtime clear: d.dp is never rebuilt at runtime, so
// recovery from an arm failure is a daemon restart (a fresh boot re-attempts the
// arm and only leaves this hold unset when the dataplane genuinely armed).
func (m *Manager) SetArmFailedHold() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.armFailedHold = true
	// Demote any group that is already primary (defense in depth for call
	// ordering, exactly like SetKernelUpgradeHold). Idempotent: a no-op when
	// nothing is primary.
	for _, rg := range m.groups {
		if rg.State == StatePrimary {
			rg.State = StateSecondary
			m.sendEvent(rg.GroupID, StatePrimary, StateSecondary, "dataplane arm-failed hold armed")
		}
	}
}

// ArmFailedHeld reports whether the #5275 dataplane-arm-failed election hold is
// set. Used by tests and any reconcile that must know the node is fail-closed.
func (m *Manager) ArmFailedHeld() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.armFailedHold
}
