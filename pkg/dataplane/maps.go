package dataplane

import (
	"encoding/binary"
	"net"
)

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ipToUint32BE converts a net.IP to a uint32 matching the in-memory layout
// that BPF programs use when copying __be32 fields (e.g. iph->daddr).
// The IP address bytes are stored as-is; on little-endian hosts this means
// the uint32 numeric value differs from the big-endian interpretation, but
// the byte pattern in the BPF map key matches what BPF writes.
func ipToUint32BE(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(ip4)
}

// ipTo16Bytes converts a net.IP to a [16]byte array.
func ipTo16Bytes(ip net.IP) [16]byte {
	var b [16]byte
	copy(b[:], ip.To16())
	return b
}

// --- Hitless restart: delete-stale methods ---
// These methods remove map entries that are no longer present in the new config,
// AFTER new entries have been written. This avoids the clear-then-repopulate
// window where BPF programs see empty maps.

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
