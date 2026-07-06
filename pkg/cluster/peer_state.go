package cluster

// PeerAlive returns whether the peer node is reachable.
func (m *Manager) PeerAlive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerAlive
}

// peerHeartbeatFreshLocked reports whether a peer heartbeat is currently within
// the timeout window (NOT stale). It is the truth source for
// handlePeerTimeout's post-guard re-check. Must be called with m.mu held (it
// reads m.peerHeartbeatFreshFn and m.hbReceiver).
//
// The test seam (m.peerHeartbeatFreshFn) takes precedence so tests can inject a
// fresh/stale heartbeat without a real socket. Otherwise it defers to the live
// receiver. A nil receiver (no heartbeat path wired) reports "not fresh" so the
// peer-lost transition proceeds exactly as before this re-check existed.
func (m *Manager) peerHeartbeatFreshLocked() bool {
	if m.peerHeartbeatFreshFn != nil {
		return m.peerHeartbeatFreshFn()
	}
	if m.hbReceiver != nil {
		return m.hbReceiver.peerHeartbeatFresh()
	}
	return false
}

// HeartbeatPeerAuthSeen reports whether the heartbeat receiver has ever
// accepted a valid HMAC-authenticated heartbeat from the peer (#4107). It is
// the fast-arming signal the gRPC fabric listener reuses to enforce its PSK
// downgrade-guard: heartbeats flow continuously (~200ms), so this arms within
// one interval of a keyed peer coming up — closing the post-restart window
// where nothing had yet dialed the fabric listener on-demand to arm its own
// sticky flag. Returns false when no heartbeat receiver is wired (standalone /
// heartbeat not started) or the peer has not authenticated, so a node with no
// PSK, or a rolling upgrade where the peer is not yet signing, keeps the
// dual-accept grace. Reads m.hbReceiver under the manager lock (it may be
// swapped by RestartHeartbeat); the flag itself is an atomic.
func (m *Manager) HeartbeatPeerAuthSeen() bool {
	m.mu.RLock()
	r := m.hbReceiver
	m.mu.RUnlock()
	if r == nil {
		return false
	}
	return r.peerAuthenticated()
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
