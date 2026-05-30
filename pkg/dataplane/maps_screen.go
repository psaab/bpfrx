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

// ReadFloodCounters reads the per-CPU flood state for a zone and sums them.
func (m *Manager) ReadFloodCounters(zoneID uint16) (FloodState, error) {
	zm, ok := m.maps["flood_counters"]
	if !ok {
		return FloodState{}, fmt.Errorf("flood_counters map not found")
	}
	var perCPU []FloodState
	if err := zm.Lookup(uint32(zoneID), &perCPU); err != nil {
		return FloodState{}, err
	}
	var total FloodState
	for _, fs := range perCPU {
		total.SynCount += fs.SynCount
		total.ICMPCount += fs.ICMPCount
		total.UDPCount += fs.UDPCount
	}
	return total, nil
}
