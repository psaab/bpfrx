package cluster

// SetPreManualFailoverHook registers a callback that runs before ManualFailover
// changes local RG ownership.
func (m *Manager) SetPreManualFailoverHook(fn func(rgID int) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preManualFailoverFn = fn
}

// SetTransferReadinessFunc sets the callback used to report whether a local
// redundancy group is ready for explicit transfer-based manual failover.
func (m *Manager) SetTransferReadinessFunc(fn func(rgID int) (bool, []string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transferReadinessFn = fn
}

// SetLocalTransferCommitReadyHook registers a callback that runs on the
// requesting node after local ownership is committed and before the final
// peer-demotion commit is sent.
func (m *Manager) SetLocalTransferCommitReadyHook(fn func(rgIDs []int) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localTransferCommitReadyFn = fn
}

// SetPeerFailoverFunc sets the callback used to send remote failover requests
// to the peer via the fabric sync connection.
func (m *Manager) SetPeerFailoverFunc(fn func(rgID int) (uint64, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverFn = fn
}

// SetPeerFailoverCommitFunc sets the callback used to send remote
// transfer-commit messages via the fabric sync connection.
func (m *Manager) SetPeerFailoverCommitFunc(fn func(rgID int, reqID uint64) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverCommitFn = fn
}

// SetPeerFailoverBatchFunc sets the callback used to send remote multi-RG
// failover requests to the peer via the fabric sync connection.
func (m *Manager) SetPeerFailoverBatchFunc(fn func(rgIDs []int) (uint64, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverBatchFn = fn
}

// SetPeerFailoverCommitBatchFunc sets the callback used to send the final
// multi-RG transfer-commit message via the fabric sync connection.
func (m *Manager) SetPeerFailoverCommitBatchFunc(fn func(rgIDs []int, reqID uint64) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverCommitBatchFn = fn
}

// SetPeerFenceFunc sets the callback used to send a fence message to the
// peer via the fabric sync connection, telling it to disable all RGs.
func (m *Manager) SetPeerFenceFunc(fn func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFenceFn = fn
}

// SetPeerTimeoutGuard sets a callback that can suppress heartbeat-driven
// peer-loss if another control-plane signal proves the peer is still alive.
func (m *Manager) SetPeerTimeoutGuard(fn func() (bool, string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerTimeoutGuardFn = fn
}
