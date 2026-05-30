package dataplane

// BPF map utilization stats.
// Same-package split of maps.go (#1686): MapStats + GetMapStats.

// MapStats holds utilization info for a BPF map.
type MapStats struct {
	Name       string
	Type       string
	MaxEntries uint32
	UsedCount  uint32
	KeySize    uint32
	ValueSize  uint32
}

// GetMapStats returns utilization statistics for key BPF maps.
func (m *Manager) GetMapStats() []MapStats {
	// Maps to report on and whether to count entries (only for hash maps)
	reportMaps := []struct {
		name      string
		countable bool // hash maps can be iterated; arrays cannot meaningfully count
	}{
		{"sessions", true},
		{"sessions_v6", true},
		{"zone_configs", false},
		{"policy_rules", false},
		{"address_book_v4", true},
		{"address_book_v6", true},
		{"address_membership", true},
		{"applications", true},
		{"snat_rules", false},
		{"dnat_table", true},
		{"dnat_table_v6", true},
		{"nat_pool_config", false},
		{"screen_profiles", false},
		{"global_counters", false},
		{"policy_counters", false},
		{"filter_rules", true},
	}

	var stats []MapStats
	for _, rm := range reportMaps {
		bm, ok := m.maps[rm.name]
		if !ok || bm == nil {
			continue
		}
		info, err := bm.Info()
		if err != nil {
			continue
		}
		ms := MapStats{
			Name:       rm.name,
			Type:       info.Type.String(),
			MaxEntries: info.MaxEntries,
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
		}

		if rm.countable {
			// Count entries by iterating the map
			var count uint32
			iter := bm.Iterate()
			var key, val []byte
			for iter.Next(&key, &val) {
				count++
			}
			ms.UsedCount = count
		}

		stats = append(stats, ms)
	}
	return stats
}
