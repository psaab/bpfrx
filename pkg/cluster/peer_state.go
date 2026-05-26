package cluster

// PeerAlive returns whether the peer node is reachable.
func (m *Manager) PeerAlive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerAlive
}

// PeerNodeID returns the peer's node ID (valid only when PeerAlive is true).
func (m *Manager) PeerNodeID() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerNodeID
}

// PeerGroupStates returns a snapshot of the peer's RG states.
func (m *Manager) PeerGroupStates() map[int]PeerGroupState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make(map[int]PeerGroupState, len(m.peerGroups))
	for k, v := range m.peerGroups {
		cp[k] = v
	}
	return cp
}

// SetSoftwareVersion records the local software version advertised to the peer.
func (m *Manager) SetSoftwareVersion(version string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(version) > maxHeartbeatSoftwareVersionSize {
		version = version[:maxHeartbeatSoftwareVersionSize]
	}
	m.localSoftwareVersion = version
}

// SoftwareVersions returns the currently known local and peer software versions.
func (m *Manager) SoftwareVersions() (local, peer string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localSoftwareVersion, m.peerSoftwareVersion
}

// SetHAProtocolVersion records the local HA compatibility version advertised to
// the peer. Zero falls back to the legacy compatibility version.
func (m *Manager) SetHAProtocolVersion(version uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localHAProtocolVersion = normalizeHAProtocolVersion(version)
}

// HAProtocolVersions returns the currently known local and peer HA protocol versions.
func (m *Manager) HAProtocolVersions() (local, peer uint16) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localHAProtocolVersion, m.peerHAProtocolVersion
}

// HAProtocolVersionMismatch reports whether both sides advertised incompatible
// HA/session-transfer versions. When the peer is absent or has not yet
// advertised a version, mismatch stays false so disconnect/readiness logic can
// report the more accurate transport-state reason.
func (m *Manager) HAProtocolVersionMismatch() (bool, uint16, uint16) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	local := normalizeHAProtocolVersion(m.localHAProtocolVersion)
	if !m.peerAlive || m.peerHAProtocolVersion == 0 {
		return false, local, 0
	}
	peer := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
	return local != peer, local, peer
}

// PeerMonitorStatuses returns the peer's interface monitor states from heartbeat.
// Returns nil if peer is not alive or no monitor data received.
func (m *Manager) PeerMonitorStatuses() []InterfaceMonitorInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.peerMonitors) == 0 {
		return nil
	}
	cp := make([]InterfaceMonitorInfo, len(m.peerMonitors))
	copy(cp, m.peerMonitors)
	return cp
}
