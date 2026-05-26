package cluster

import "log/slog"

// SyncStatsProvider abstracts access to session sync statistics.
type SyncStatsProvider interface {
	Stats() SyncStatsSnapshot
	IsConnected() bool
}

// SetSyncReady marks session sync as ready (bulk sync received or timed out).
// In private-rg-election mode this gates RG promotion via the readiness pipeline.
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
