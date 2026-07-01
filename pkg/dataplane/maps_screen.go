package dataplane

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Screen / IDS map accessors.
// Same-package split of maps.go (#1686): screen profile configs, the
// per-source/per-destination session-count limit maps, and the per-zone flood
// counters. The session-count maps are a separate map family co-located here
// by IDS relevance, not because they share storage with screen_configs.

// SetScreenConfig writes a screen profile configuration entry.
func (m *Manager) SetScreenConfig(profileID uint32, cfg ScreenConfig) error {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return fmt.Errorf("screen_configs map not found")
	}
	return zm.Update(profileID, cfg, ebpf.UpdateAny)
}

// ClearScreenConfigs zeroes all screen_configs entries.
func (m *Manager) ClearScreenConfigs() error {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return fmt.Errorf("screen_configs map not found")
	}
	empty := ScreenConfig{}
	for i := uint32(0); i < 64; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// UpdateSessionCountSrc writes a per-source-IP session count entry.
func (m *Manager) UpdateSessionCountSrc(key SessionCountKey, count uint32) error {
	zm, ok := m.maps["session_count_src"]
	if !ok {
		return fmt.Errorf("session_count_src map not found")
	}
	val := SessionCountValue{Count: count}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// UpdateSessionCountDst writes a per-destination-IP session count entry.
func (m *Manager) UpdateSessionCountDst(key SessionCountKey, count uint32) error {
	zm, ok := m.maps["session_count_dst"]
	if !ok {
		return fmt.Errorf("session_count_dst map not found")
	}
	val := SessionCountValue{Count: count}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSessionCounts deletes all entries from the session count maps.
func (m *Manager) ClearSessionCounts() error {
	for _, name := range []string{"session_count_src", "session_count_dst"} {
		zm, ok := m.maps[name]
		if !ok {
			continue
		}
		var key SessionCountKey
		var val []byte
		iter := zm.Iterate()
		var keys []SessionCountKey
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			zm.Delete(k)
		}
	}
	return nil
}

// ReadFloodCounters returns the userspace-reported per-zone flood-event state
// for zoneID.
//
// #3643: like ReadZoneCounters, this keys a Go-side sparse offset map instead
// of indexing the dense flood_counters BPF array (MaxZones entries), so a
// stable-hash zone id >= MaxZones can no longer OOB the bounded Lookup and
// surface as a hard read failure. The userspace helper does not yet populate
// per-zone flood counters (POPULATE deferred, #3643 plan §5A), so the map is
// empty and this reports ErrCounterNotPopulated; surfaces render "not
// available" rather than a misleading 0.
func (m *Manager) ReadFloodCounters(zoneID uint16) (FloodState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fs, ok := m.floodCounterOffsets[zoneID]
	if !ok {
		return FloodState{}, ErrCounterNotPopulated
	}
	return fs, nil
}

// SetFloodCounterOffset records the absolute cumulative per-zone flood-event
// counts reported by the userspace dataplane for zoneID (#3643 POPULATE hook,
// mirroring SetZoneCounterOffset). Once set, ReadFloodCounters returns it (nil
// error) instead of ErrCounterNotPopulated.
func (m *Manager) SetFloodCounterOffset(zoneID uint16, fs FloodState) {
	m.mu.Lock()
	if m.floodCounterOffsets == nil {
		m.floodCounterOffsets = make(map[uint16]FloodState)
	}
	m.floodCounterOffsets[zoneID] = fs
	m.mu.Unlock()
}

// ClearFloodCounterOffsets drops all userspace-reported per-zone flood offsets
// (#3643). Wired into ClearAllCounters.
func (m *Manager) ClearFloodCounterOffsets() {
	m.mu.Lock()
	m.floodCounterOffsets = nil
	m.mu.Unlock()
}
