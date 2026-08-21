package cluster

import "log/slog"

// SyncStatsProvider abstracts access to session sync statistics.
type SyncStatsProvider interface {
	Stats() SyncStatsSnapshot
	IsConnected() bool
}

// SetSyncReady marks session sync as ready (bulk sync received, or the
// readiness timeout released the hold).
//
// It does NOT gate RG promotion, in private-rg-election mode or any other
// (#7102). Say that plainly, because the opposite belief is the one #110 was
// filed to prevent and this comment used to assert it: promotion readiness in
// no-RETH / private-rg-election mode is VIP ownership ALONE
// (checkNoRethTakeoverReadiness -> checkVIPReadiness, pkg/daemon), and the
// readiness conjunction that consumes it — ifReady && takeoverGateReady &&
// fabricReady && userspaceReady, in daemon_ha_userspace_readiness.go — carries
// no sync term. A node in this mode can therefore take over an RG before bulk
// session sync has completed.
//
// The gate DID exist: reconcileRGState set vrrpReady = d.cluster.IsSyncReady()
// in no-RETH mode and reported "session sync not ready" as a takeover blocker,
// until 0781f7a60 (2026-04-05) deleted it. That commit has an empty body, so
// the rationale for the removal is unavailable and would need re-deriving;
// whether the gate SHOULD come back is #110, still open. Do not restore it from
// this comment.
//
// Pinned by TestTakeoverReadinessForRG_NoRethIgnoresClusterSyncReady and
// TestTakeoverReadinessForRG_PrivateRGElectionIgnoresClusterSyncReady_7102
// (pkg/daemon), which drive a reconcile with sync NOT ready and assert the RG
// still reaches Ready with no "session sync not ready" reason.
//
// What the flag IS for: the readiness timeout in pkg/daemon/daemon_ha_sync.go,
// which uses it to decide whether to release its own hold, and two log fields
// on the sync connect/disconnect edges. Those are its only production readers.
// The real preemption suppressor with a similar name is the VRRP sync-hold
// (vrrp.Manager.SetSyncHold / ReleaseSyncHold), which is armed only in RETH
// VRRP mode and is not this flag.
func (m *Manager) SetSyncReady(ready bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.syncReady == ready {
		return
	}
	m.syncReady = ready
	slog.Info("cluster: sync readiness changed", "ready", ready)
}

// IsSyncReady returns true if session sync is ready.
func (m *Manager) IsSyncReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncReady
}

// SetSyncTransport records the active sync transport mode ("fabric" or "control-link").
func (m *Manager) SetSyncTransport(transport string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncTransport = transport
}

// SyncTransport returns the active sync transport mode.
func (m *Manager) SyncTransport() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.syncTransport == "" {
		return "fabric"
	}
	return m.syncTransport
}

// SetSyncStats sets the sync stats provider (called by daemon after sessionSync creation).
func (m *Manager) SetSyncStats(p SyncStatsProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncStats = p
}

// GetSyncStats returns sync stats, or nil if no provider is set.
func (m *Manager) GetSyncStats() *SyncStatsSnapshot {
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return nil
	}
	stats := p.Stats()
	return &stats
}

// IsSyncConnected returns true if the sync peer is connected.
func (m *Manager) IsSyncConnected() bool {
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return false
	}
	return p.IsConnected()
}
